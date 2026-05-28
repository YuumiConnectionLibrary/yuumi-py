from __future__ import annotations

import os
import socket
import struct
import threading
import unittest
import uuid
from pathlib import Path

from yuumi import Channel, Encoding, Client, connect
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


if __name__ == "__main__":
    unittest.main()
