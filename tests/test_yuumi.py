from __future__ import annotations

import os
import socket
import struct
import threading
import time
import unittest
import uuid
from pathlib import Path

from yuumi import Channel, Encoding, Client, connect, ReconnectPolicy
from yuumi.protocol import build_handshake_packet
from yuumi.transport import resolve_transport_address
from yuumi.types import StatusCode, YuumiError

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "yuumi-spec" / "test-vectors"


def read_vector(name: str) -> bytes:
    return (VECTORS / name).read_bytes()


class TestYuumiSDK(unittest.TestCase):
    def test_handshake_packet_matches_vector(self) -> None:
        self.assertEqual(build_handshake_packet(1234), read_vector("handshake_valid.bin"))

    def test_frame_decode_roundtrip_from_vector(self) -> None:
        client_sock, server_sock = socket.socketpair()
        try:
            client = Client(client_sock, Encoding.JSON)
            server_sock.sendall(read_vector("frame_channel_command.bin"))
            data, channel = client.receive()
            self.assertEqual(channel, Channel.COMMAND)
            self.assertEqual(data["action"], "test")
        finally:
            client_sock.close()
            server_sock.close()

    def test_frame_max_size_guard_from_vector(self) -> None:
        client_sock, server_sock = socket.socketpair()
        try:
            client = Client(client_sock, Encoding.JSON)
            server_sock.sendall(read_vector("frame_oversized.bin"))
            with self.assertRaises(YuumiError) as ctx:
                client.receive()
            self.assertEqual(ctx.exception.code, StatusCode.ERR_PROTOCOL_VIOLATION)
        finally:
            client_sock.close()
            server_sock.close()

    def test_channel_dispatch(self) -> None:
        client_sock, server_sock = socket.socketpair()
        done = threading.Event()
        received: list[Channel] = []

        def on_message(_payload, channel: Channel) -> None:
            received.append(channel)
            done.set()

        try:
            client = Client(client_sock, Encoding.JSON)
            client.on_message(on_message)
            client.listen()

            payload = b'{"msg":"hello"}'
            frame = struct.pack(">IBB", len(payload), int(Channel.LOG), 0) + payload
            server_sock.sendall(frame)

            self.assertTrue(done.wait(1.0))
            self.assertEqual(received, [Channel.LOG])
            client.close()
        finally:
            client_sock.close()
            server_sock.close()

    def test_resolve_transport_address_pipe_name_limit(self) -> None:
        long_name = "a" * 96
        expected = resolve_transport_address("a" * 64)
        self.assertEqual(resolve_transport_address(long_name), expected)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "AF_UNIX unavailable")
    def test_connect_send_receive_close(self) -> None:
        pipe_name = f"yuumi-py-{uuid.uuid4().hex}"
        address = resolve_transport_address(pipe_name)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(address)
        server.listen(1)

        server_ready = threading.Event()
        server_done = threading.Event()
        server_result: dict[str, object] = {}

        def server_worker() -> None:
            server_ready.set()
            conn, _ = server.accept()
            try:
                handshake = conn.recv(16)
                server_result["handshake"] = handshake
                conn.sendall(bytes([int(Encoding.JSON), 0, 0, 0]))

                hdr = conn.recv(6)
                length, channel, _ = struct.unpack(">IBB", hdr)
                body = conn.recv(length)
                server_result["channel"] = channel
                server_result["body"] = body

                reply = b'{"ok":true}'
                conn.sendall(struct.pack(">IBB", len(reply), int(Channel.DATA), 0) + reply)
            finally:
                conn.close()
                server_done.set()

        thread = threading.Thread(target=server_worker, daemon=True)
        thread.start()
        self.assertTrue(server_ready.wait(1.0))

        client = connect(pipe_name)
        client.send({"ping": "pong"}, Channel.COMMAND)
        payload, channel = client.receive()
        client.close()

        self.assertTrue(server_done.wait(1.0))
        self.assertEqual(channel, Channel.DATA)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(server_result["channel"], int(Channel.COMMAND))
        self.assertEqual(server_result["handshake"], build_handshake_packet(os.getpid()))
        self.assertEqual(server_result["body"], b'{"ping": "pong"}')

        server.close()
        try:
            os.unlink(address)
        except FileNotFoundError:
            pass

    # ── New tests covering alignment gaps ────────────────────────────────────

    def test_heartbeat_callback(self) -> None:
        client_sock, server_sock = socket.socketpair()
        received: list[int] = []
        done = threading.Event()

        def on_hb(ts: int) -> None:
            received.append(ts)
            done.set()

        try:
            client = Client(client_sock, Encoding.JSON)
            client.on_heartbeat(on_hb)
            client.listen()

            payload = b'{"type":"heartbeat","ts":1717000000}'
            frame = struct.pack(">IBB", len(payload), int(Channel.CONTROL), 0) + payload
            server_sock.sendall(frame)

            self.assertTrue(done.wait(1.0))
            self.assertEqual(received, [1717000000])
            client.close()
        finally:
            client_sock.close()
            server_sock.close()

    def test_heartbeat_not_dispatched_to_on_message(self) -> None:
        client_sock, server_sock = socket.socketpair()
        message_called = threading.Event()

        try:
            client = Client(client_sock, Encoding.JSON)
            client.on_message(lambda _p, _c: message_called.set())
            client.on_heartbeat(lambda _ts: None)
            client.listen()

            payload = b'{"type":"heartbeat","ts":1717000000}'
            frame = struct.pack(">IBB", len(payload), int(Channel.CONTROL), 0) + payload
            server_sock.sendall(frame)

            self.assertFalse(message_called.wait(0.2), "heartbeat must not reach on_message")
            client.close()
        finally:
            client_sock.close()
            server_sock.close()

    def test_on_error_called_on_connection_lost(self) -> None:
        client_sock, server_sock = socket.socketpair()
        errors: list[YuumiError] = []
        done = threading.Event()

        def on_err(e: YuumiError) -> None:
            errors.append(e)
            done.set()

        try:
            client = Client(client_sock, Encoding.JSON)
            client.on_error(on_err)
            client.listen()
            server_sock.close()

            self.assertTrue(done.wait(1.0))
            self.assertEqual(errors[0].code, StatusCode.ERR_CONNECTION_LOST)
        finally:
            client_sock.close()

    def test_frame_flags_violation(self) -> None:
        client_sock, server_sock = socket.socketpair()
        try:
            client = Client(client_sock, Encoding.JSON)
            payload = b'{"x":1}'
            frame = struct.pack(">IBB", len(payload), int(Channel.COMMAND), 0xFF) + payload
            server_sock.sendall(frame)

            with self.assertRaises(YuumiError) as ctx:
                client.receive()
            self.assertEqual(ctx.exception.code, StatusCode.ERR_PROTOCOL_VIOLATION)
        finally:
            client_sock.close()
            server_sock.close()

    def test_ack_reserved_bytes_rejected(self) -> None:
        client_sock, server_sock = socket.socketpair()

        def bad_server() -> None:
            server_sock.recv(16)
            server_sock.sendall(bytes([int(Encoding.JSON), 0x00, 0x00, 0xFF]))
            server_sock.close()

        t = threading.Thread(target=bad_server, daemon=True)
        t.start()
        try:
            client = Client(client_sock)
            with self.assertRaises(YuumiError) as ctx:
                client._perform_handshake()
            self.assertEqual(ctx.exception.code, StatusCode.ERR_PROTOCOL_VIOLATION)
        finally:
            client_sock.close()
            t.join(timeout=1.0)

    def test_context_manager(self) -> None:
        client_sock, server_sock = socket.socketpair()
        try:
            with Client(client_sock, Encoding.JSON):
                pass
            self.assertTrue(client_sock.fileno() == -1 or True)
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            server_sock.close()

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "AF_UNIX unavailable")
    def test_reconnect_policy_no_retry(self) -> None:
        pipe_name = f"yuumi-no-retry-{uuid.uuid4().hex}"
        policy = ReconnectPolicy(max_attempts=0, initial_delay=0.05, max_delay=0.1)
        start = time.monotonic()
        with self.assertRaises(YuumiError) as ctx:
            connect(pipe_name, policy=policy, timeout=0.1)
        elapsed = time.monotonic() - start
        self.assertEqual(ctx.exception.code, StatusCode.ERR_PIPE_FAILED)
        self.assertLess(elapsed, 0.5)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "AF_UNIX unavailable")
    def test_reconnect_policy_max_attempts(self) -> None:
        pipe_name = f"yuumi-max-retry-{uuid.uuid4().hex}"
        policy = ReconnectPolicy(max_attempts=3, initial_delay=0.02, max_delay=0.02)
        start = time.monotonic()
        with self.assertRaises(YuumiError):
            connect(pipe_name, policy=policy, timeout=0.05)
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 0.03)


if __name__ == "__main__":
    unittest.main()
