from __future__ import annotations

import inspect
import json
import os
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest import mock

import msgpack

import yuumi
from yuumi.protocol import FLAG_CORRELATED, build_frame
from yuumi.engine import _Session
from yuumi.transport import SocketStream, TransportClosed, TransportFailure, _connect_for_test

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "yuumi-spec" / "test-vectors"
TOKEN = "0123456789abcdef0123456789abcdef"


def vector(name: str) -> bytes:
    return (VECTORS / name).read_bytes()


def wait_for(predicate, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition was not satisfied before the bounded deadline")


class Peer:
    def __init__(self, address: str) -> None:
        self.stream = _connect_for_test(address)

    def write(self, data: bytes) -> None:
        self.stream.write_all(data)

    def read(self, size: int) -> bytes:
        return self.stream.read_exact(size)

    def handshake(self, encoding_mask: int = 0x03, capabilities: int = 0, pid: int | None = None) -> tuple[bytes, dict]:
        packet = struct.pack(">IIIB", 0x59554D49, 1, os.getpid() if pid is None else pid, encoding_mask) + capabilities.to_bytes(3, "big")
        self.write(packet)
        ack = self.read(4)
        channel, flags, payload = self.read_frame()
        if channel != yuumi.Channel.CONTROL or flags != 0:
            raise AssertionError("session assignment was not the first frame after ACK")
        return ack, json.loads(payload)

    def read_frame(self) -> tuple[yuumi.Channel, int, bytes]:
        length, channel, flags = struct.unpack(">IBB", self.read(6))
        return yuumi.Channel(channel), flags, self.read(length)

    def close(self) -> None:
        self.stream.close()


class EngineConformance(unittest.TestCase):
    def setUp(self) -> None:
        self.name = f"p{uuid.uuid4().hex[:6]}"
        self.engines: list[yuumi.Engine] = []
        self.peers: list[Peer] = []

    def tearDown(self) -> None:
        for peer in self.peers:
            peer.close()
        for engine in self.engines:
            engine.close()

    def config(self, **changes) -> yuumi.EngineConfig:
        base = yuumi.EngineConfig(self.name, TOKEN, heartbeat=yuumi.HeartbeatSettings(disabled=True))
        return replace(base, **changes)

    def open(self, config: yuumi.EngineConfig | None = None) -> yuumi.Engine:
        engine = yuumi.Engine(config or self.config())
        self.engines.append(engine)
        engine.open()
        return engine

    def peer(self, token: str = TOKEN) -> Peer:
        peer = Peer(yuumi.resolve_transport_address(self.name, token))
        self.peers.append(peer)
        return peer

    def established(self, engine=None, **handshake):
        connected = []
        if engine is None:
            engine = self.open()
        engine.on_session_connected(connected.append)
        peer = self.peer()
        ack, control = peer.handshake(**handshake)
        view = wait_for(lambda: connected[0] if connected else None)
        return engine, peer, view, ack, control

    def errors_for_invalid_frame(self, packet: bytes, capabilities: int = 0):
        errors = []
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        engine.on_error(errors.append)
        peer = self.peer()
        peer.handshake(encoding_mask=1, capabilities=capabilities)
        peer.write(packet)
        channel, _, payload = peer.read_frame()
        control = json.loads(payload)
        wait_for(lambda: errors)
        self.assertEqual(channel, yuumi.Channel.CONTROL)
        self.assertEqual(control["type"], "error")
        return errors

    def test_ec_001_invalid_configuration_has_no_endpoint_side_effects(self):
        invalid = [
            self.config(endpoint_name=""), self.config(token="A" * 32), self.config(max_sessions=0),
            self.config(max_sessions=-1), self.config(supported_encodings=()),
            self.config(supported_encodings=(yuumi.Encoding.JSON, yuumi.Encoding.JSON)),
            self.config(supported_encodings=(yuumi.Encoding(4),)), self.config(supported_capabilities=2),
            self.config(expected_pid=-1), self.config(expected_pid=0x100000000),
            self.config(heartbeat=yuumi.HeartbeatSettings(interval=0)),
            self.config(fragmentation=yuumi.FragmentationSettings(timeout=0)),
        ]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(yuumi.EngineError):
                yuumi.Engine(config).open()

    def test_ec_002_canonical_address_and_platform_transport(self):
        address = yuumi.resolve_transport_address(self.name, TOKEN)
        expected = rf"\\.\pipe\yuumi-{self.name}-{TOKEN}" if os.name == "nt" else str(Path(tempfile.gettempdir()) / f"yuumi-{self.name}-{TOKEN}.sock")
        self.assertEqual(address, expected)
        self.open()
        if os.name != "nt":
            self.assertTrue(stat.S_ISSOCK(os.stat(address).st_mode))

    def test_ec_003_address_values_are_not_rewritten(self):
        self.assertIn(f"yuumi-{self.name}-{TOKEN}", yuumi.resolve_transport_address(self.name, TOKEN))
        for name in ("_bad", "a" * 33, "é"):
            with self.assertRaises(ValueError):
                yuumi.resolve_transport_address(name, TOKEN)

    def test_ec_004_defaults_are_protocol_conforming(self):
        config = yuumi.EngineConfig(self.name, TOKEN, heartbeat=yuumi.HeartbeatSettings(disabled=True))
        engine = self.open(config)
        connected = []
        engine.on_session_connected(connected.append)
        peer = self.peer()
        ack, _ = peer.handshake(capabilities=yuumi.CAP_CORRELATION)
        view = wait_for(lambda: connected[0] if connected else None)
        self.assertEqual(ack, bytes([2, 0, 0, 1]))
        self.assertEqual(view.handle.epoch, 0)

    def test_ec_005_open_and_repeated_close_rules(self):
        engine = self.open()
        with self.assertRaises(yuumi.EngineError):
            engine.open()
        closers = [threading.Thread(target=engine.close) for _ in range(2)]
        for closer in closers:
            closer.start()
        for closer in closers:
            closer.join(2.0)
            self.assertFalse(closer.is_alive())
        engine.close()

    def test_ec_006_live_endpoint_is_never_replaced(self):
        first = self.open()
        probe_errors = []
        first.on_error(probe_errors.append)
        second = yuumi.Engine(self.config())
        with self.assertRaises(yuumi.EngineError):
            second.open()
        wait_for(lambda: probe_errors)
        wait_for(lambda: len(first._connections) == 0)
        peer = self.peer()
        self.assertEqual(peer.handshake()[0][0], 2)
        self.assertIsNotNone(first)

    def test_ec_007_closed_endpoint_can_be_recreated(self):
        first = self.open()
        first.close()
        second = self.open()
        self.assertEqual(self.peer().handshake()[0][0], 2)
        self.assertIsNotNone(second)

    def test_ec_008_access_controls_precede_traffic(self):
        self.open()
        address = yuumi.resolve_transport_address(self.name, TOKEN)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(address).st_mode), 0o600)
        self.assertIsNotNone(self.peer())

    def test_ec_009_wrong_token_cannot_reach_handshake(self):
        errors = []
        engine = self.open()
        engine.on_error(errors.append)
        with self.assertRaises((OSError, TransportFailure)):
            Peer(yuumi.resolve_transport_address(self.name, "f" * 32))
        self.assertEqual(errors, [])

    def test_ec_010_orderly_close_releases_sessions(self):
        config = self.config(max_sessions=2)
        engine = self.open(config)
        disconnected = []
        engine.on_session_disconnected(disconnected.append)
        first = self.peer()
        first.handshake()
        self.peer().handshake()
        wait_for(lambda: len(engine._sessions) == 2)
        first.write(vector("frame_fragment_first.bin"))
        engine.close()
        self.assertEqual(len(disconnected), 2)
        self.assertTrue(all(event.reason == yuumi.DisconnectReason.ENGINE_CLOSE for event in disconnected))
        self.open(config).close()

    def test_ec_011_public_api_requires_name_and_token(self):
        parameters = inspect.signature(yuumi.EngineConfig).parameters
        self.assertIn("endpoint_name", parameters)
        self.assertIn("token", parameters)
        self.assertNotIn("address", parameters)

    def test_ec_012_valid_json_handshake_exact_ack(self):
        engine, _, view, ack, control = self.established(self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,), supported_capabilities=0)), encoding_mask=1)
        self.assertEqual(ack, vector("ack_json.bin"))
        self.assertEqual(view.encoding, yuumi.Encoding.JSON)
        self.assertTrue(control["session_id"])

    def test_ec_013_valid_msgpack_handshake_exact_ack(self):
        _, _, view, ack, _ = self.established(self.open(self.config(supported_capabilities=0)))
        self.assertEqual(ack, vector("ack_msgpack.bin"))
        self.assertEqual(view.encoding, yuumi.Encoding.MSGPACK)

    def test_ec_014_short_handshake_is_not_parsed(self):
        errors = []
        engine = self.open()
        engine.on_error(errors.append)
        peer = self.peer()
        peer.write(vector("handshake_valid.bin")[:15])
        peer.close()
        self.assertEqual(wait_for(lambda: errors)[0].phase, yuumi.ErrorPhase.HANDSHAKE_READ)

    def assert_handshake_rejected(self, packet: bytes, status: yuumi.StatusCode, config=None):
        errors = []
        engine = self.open(config)
        engine.on_error(errors.append)
        peer = self.peer()
        peer.write(packet)
        with self.assertRaises(TransportClosed):
            peer.read(1)
        self.assertEqual(wait_for(lambda: errors)[0].status, status)

    def test_ec_015_invalid_magic_no_ack(self):
        self.assert_handshake_rejected(vector("handshake_bad_magic.bin"), yuumi.StatusCode.ERR_MAGIC_MISMATCH)

    def test_ec_016_bad_version_no_ack(self):
        self.assert_handshake_rejected(vector("handshake_bad_version.bin"), yuumi.StatusCode.ERR_VERSION_MISMATCH)

    def test_ec_017_no_encoding_intersection_no_ack(self):
        self.assert_handshake_rejected(vector("handshake_encoding_unsupported.bin"), yuumi.StatusCode.ERR_ENCODING_UNSUPPORTED, self.config(supported_encodings=(yuumi.Encoding.JSON,)))

    def test_ec_018_expected_pid_absence_zero_and_mismatch(self):
        self.established()
        self.name = f"p{uuid.uuid4().hex[:6]}"
        engine = self.open(self.config(expected_pid=0))
        errors = []
        engine.on_error(errors.append)
        peer = self.peer()
        peer.write(struct.pack(">IIIB3s", 0x59554D49, 1, 0, 3, b"\0\0\0"))
        with self.assertRaises(TransportClosed):
            peer.read(1)
        self.assertEqual(wait_for(lambda: errors)[0].status, yuumi.StatusCode.ERR_PID_MISMATCH)

        class DarwinPeerSocket:
            def getsockopt(self, level, option, size):
                self.arguments = (level, option, size)
                return struct.pack("i", 4321)

        native = DarwinPeerSocket()
        with mock.patch("yuumi.transport.sys.platform", "darwin"):
            self.assertEqual(SocketStream(native).peer_pid(), 4321)
        self.assertEqual(native.arguments, (0, 0x002, 4))

    def test_ec_019_preference_and_reserved_encoding_bits(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON, yuumi.Encoding.MSGPACK)))
        self.assertEqual(self.established(engine, encoding_mask=0x83)[3][0], 1)

    def test_ec_020_shared_correlation_is_intersection(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        self.assertEqual(self.established(engine, capabilities=yuumi.CAP_CORRELATION)[3], vector("ack_cap_correlation.bin"))

    def test_ec_021_unshared_capability_establishes_baseline(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,), supported_capabilities=0))
        self.assertEqual(self.established(engine, capabilities=yuumi.CAP_CORRELATION)[3], vector("ack_capabilities_none.bin"))

    def test_ec_022_unknown_capabilities_are_ignored(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        self.assertEqual(self.established(engine, capabilities=0x800001)[3], vector("ack_cap_correlation.bin"))

    def test_ec_023_failed_pre_session_never_connects(self):
        connected = []
        errors = []
        engine = yuumi.Engine(self.config())
        engine.on_session_connected(connected.append)
        engine.on_error(errors.append)
        engine._opened = True

        class FailingSessionWrite:
            def __init__(self):
                self.writes = 0

            def read_exact(self, _):
                return vector("handshake_valid.bin")

            def write_all(self, _):
                self.writes += 1
                if self.writes == 2:
                    raise TransportFailure("injected session assignment failure")

            def peer_pid(self):
                return None

            def close(self):
                pass

        self.assertFalse(engine._handshake(_Session(FailingSessionWrite())))
        self.assertEqual(connected, [])
        self.assertEqual(errors[0].phase, yuumi.ErrorPhase.SESSION_WRITE)

    def test_ec_024_capacity_counts_pre_session(self):
        engine = self.open()
        first = self.peer()
        second = self.peer()
        try:
            second.write(vector("handshake_valid.bin"))
        except (TransportClosed, TransportFailure):
            pass
        else:
            with self.assertRaises((TransportClosed, TransportFailure)):
                second.read(1)
        first.close()
        wait_for(lambda: len(engine._connections) == 0)

    def test_ec_025_n_sessions_are_isolated(self):
        engine = self.open(self.config(max_sessions=2))
        connected = []
        engine.on_session_connected(connected.append)
        self.peer().handshake(encoding_mask=1)
        self.peer().handshake(encoding_mask=2)
        wait_for(lambda: len(connected) == 2)
        self.assertNotEqual(connected[0].handle, connected[1].handle)
        self.assertNotEqual(connected[0].encoding, connected[1].encoding)

    def test_ec_026_negotiated_state_is_session_local(self):
        engine = self.open(self.config(max_sessions=2))
        first = self.established(engine)[1]
        second = self.established(engine)[1]
        wait_for(lambda: len(engine._sessions) == 2)
        sessions = list(engine._sessions.values())
        before = sessions[1].last_activity
        first.write(vector("control_heartbeat.bin"))
        wait_for(lambda: sessions[0].last_activity > before)
        self.assertEqual(sessions[1].last_activity, before)
        second.close()

    def test_ec_027_session_assignment_order_and_uniqueness(self):
        engine = self.open(self.config(max_sessions=2))
        first = self.established(engine)[4]["session_id"]
        second = self.established(engine)[4]["session_id"]
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first.encode("ascii")), 128)

    def test_ec_028_fragment_identifiers_are_session_local(self):
        engine = self.open(self.config(max_sessions=2, supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        first = self.established(engine, encoding_mask=1, capabilities=yuumi.CAP_CORRELATION)[1]
        second = self.established(engine, encoding_mask=1, capabilities=yuumi.CAP_CORRELATION)[1]
        first.write(vector("frame_fragment_first.bin"))
        second.write(vector("frame_fragment_first.bin"))
        first.write(vector("frame_fragment_last.bin"))
        second.write(vector("frame_fragment_last.bin"))
        wait_for(lambda: len(messages) == 2)
        first.write(vector("frame_correlated_request.bin"))
        second.write(vector("frame_correlated_request.bin"))
        wait_for(lambda: len(messages) == 4)
        self.assertEqual([event.correlation_id for event in messages[-2:]], [42, 42])

    def test_ec_029_reconnect_has_new_id_and_epoch(self):
        engine, peer, first, _, _ = self.established()
        peer.close()
        wait_for(lambda: not engine._sessions)
        second = self.established(engine)[2]
        self.assertNotEqual(first.handle.session_id, second.handle.session_id)
        self.assertGreater(second.handle.epoch, first.handle.epoch)

    def test_ec_030_stale_handle_cannot_address_replacement(self):
        engine, peer, first, _, _ = self.established()
        peer.close()
        wait_for(lambda: not engine._sessions)
        self.established(engine)
        with self.assertRaises(yuumi.EngineError):
            engine.send(first.handle, yuumi.Channel.DATA, {"old": True})

    def test_ec_031_event_order_is_stable(self):
        order = []
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        engine.on_session_connected(lambda _: order.append("connected"))
        engine.on_message(lambda _: order.append("message"))
        engine.on_session_disconnected(lambda _: order.append("disconnected"))
        peer = self.peer()
        peer.handshake(encoding_mask=1)
        peer.write(vector("frame_channel_command.bin"))
        wait_for(lambda: "message" in order)
        peer.close()
        wait_for(lambda: "disconnected" in order)
        self.assertEqual(order, ["connected", "message", "disconnected"])

    def test_ec_032_disconnect_is_exact_and_reasoned(self):
        engine, peer, _, _, _ = self.established()
        events = []
        engine.on_session_disconnected(events.append)
        peer.close()
        self.assertEqual(wait_for(lambda: events)[0].reason, yuumi.DisconnectReason.PEER_CLOSE)

    def test_ec_033_protocol_failure_is_session_local(self):
        engine = self.open(self.config(max_sessions=2, supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        first = self.established(engine, encoding_mask=1)[1]
        second = self.established(engine, encoding_mask=1)[1]
        first.write(vector("frame_oversized.bin"))
        first.read_frame()
        second.write(vector("frame_channel_command.bin"))
        self.assertEqual(wait_for(lambda: messages)[0].payload["action"], "test")
        self.assertTrue(engine._opened)

    def test_ec_034_only_complete_application_messages_dispatch(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(vector("control_heartbeat.bin"))
        peer.write(vector("frame_fragment_first.bin"))
        time.sleep(0.05)
        self.assertEqual(messages, [])

    def test_ec_035_json_command_dispatch(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(vector("frame_channel_command.bin"))
        self.assertEqual(wait_for(lambda: messages)[0].payload["action"], "test")

    def test_ec_036_msgpack_command_dispatch(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.MSGPACK,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=2)[1]
        payload = msgpack.packb({"action": "test"}, use_bin_type=True)
        peer.write(build_frame(yuumi.Channel.COMMAND, 0, payload))
        self.assertEqual(wait_for(lambda: messages)[0].payload["action"], "test")

    def test_ec_037_oversized_declared_frame_rejected(self):
        errors = self.errors_for_invalid_frame(vector("frame_oversized.bin"))
        self.assertEqual(errors[0].status, yuumi.StatusCode.ERR_PAYLOAD_TOO_LARGE)

    def test_ec_038_invalid_flags_rejected(self):
        packet = struct.pack(">IBB", 2, 1, 0x80) + b"{}"
        self.assertEqual(self.errors_for_invalid_frame(packet)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_039_unknown_channels_and_directions_rejected(self):
        packet = struct.pack(">IBB", 2, 9, 0) + b"{}"
        self.assertEqual(self.errors_for_invalid_frame(packet)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_040_short_prefix_and_malformed_payload_are_fatal(self):
        packet = struct.pack(">IBB", 3, 1, 1) + b"abc"
        self.assertEqual(self.errors_for_invalid_frame(packet)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_041_uncorrelated_fragments_reassemble_once(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(vector("frame_fragment_first.bin"))
        self.assertEqual(messages, [])
        peer.write(vector("frame_fragment_last.bin"))
        self.assertEqual(wait_for(lambda: messages)[0].payload, "Hello World")

    def test_ec_042_reassembled_size_is_bounded(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        errors = []
        engine.on_error(errors.append)
        peer = self.established(engine, encoding_mask=1)[1]
        first = struct.pack(">IBBII", 4 + 8 * 1024 * 1024, 1, 1, 7, 0)[:-4] + b"a" * (8 * 1024 * 1024)
        peer.write(first)
        second_data = b"b" * (8 * 1024 * 1024 + 1)
        peer.write(build_frame(yuumi.Channel.COMMAND, 3, struct.pack(">I", 7) + second_data))
        self.assertEqual(wait_for(lambda: errors)[0].status, yuumi.StatusCode.ERR_PAYLOAD_TOO_LARGE)

    def test_ec_043_incomplete_fragment_expires(self):
        config = self.config(supported_encodings=(yuumi.Encoding.JSON,), fragmentation=yuumi.FragmentationSettings(timeout=0.05))
        engine = self.open(config)
        errors = []
        engine.on_error(errors.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(vector("frame_fragment_first.bin"))
        self.assertEqual(wait_for(lambda: errors)[0].status, yuumi.StatusCode.ERR_FRAGMENT_TIMEOUT)

    def test_ec_044_fragment_limit_is_per_session(self):
        config = self.config(max_sessions=2, supported_encodings=(yuumi.Encoding.JSON,), fragmentation=yuumi.FragmentationSettings(active_sequence_limit=1))
        engine = self.open(config)
        errors = []
        engine.on_error(errors.append)
        first = self.established(engine, encoding_mask=1)[1]
        second = self.established(engine, encoding_mask=1)[1]
        first.write(vector("frame_fragment_first.bin"))
        second.write(vector("frame_fragment_first.bin"))
        data_fragment = build_frame(yuumi.Channel.DATA, 1, struct.pack(">I", 8) + b"x")
        first.write(data_fragment)
        self.assertEqual(wait_for(lambda: errors)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_045_fragment_consistency_enforced(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        errors = []
        engine.on_error(errors.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(vector("frame_fragment_first.bin"))
        peer.write(build_frame(yuumi.Channel.DATA, 3, struct.pack(">I", 999) + b'"x"'))
        self.assertEqual(wait_for(lambda: errors)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_046_heartbeat_is_json_and_resets_liveness(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.MSGPACK,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=2)[1]
        peer.write(vector("control_heartbeat.bin"))
        time.sleep(0.05)
        self.assertEqual(messages, [])

    def test_ec_047_heartbeat_emission_and_timeout_are_local(self):
        config = self.config(max_sessions=2, heartbeat=yuumi.HeartbeatSettings(interval=0.05, missed_interval_limit=3))
        engine = self.open(config)
        disconnected = []
        engine.on_session_disconnected(disconnected.append)
        active_result = self.established(engine)
        active, active_handle = active_result[1], active_result[2].handle
        silent_result = self.established(engine)
        silent, silent_handle = silent_result[1], silent_result[2].handle
        channel, _, payload = active.read_frame()
        self.assertEqual(channel, yuumi.Channel.CONTROL)
        self.assertEqual(json.loads(payload)["type"], "heartbeat")
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline and not disconnected:
            active.write(vector("control_heartbeat.bin"))
            time.sleep(0.03)
        event = wait_for(lambda: disconnected[0] if disconnected else None)
        self.assertEqual(event.session, silent_handle)
        self.assertEqual(event.reason, yuumi.DisconnectReason.HEARTBEAT_TIMEOUT)
        self.assertIn(active_handle.session_id, engine._sessions)
        silent.close()

    def test_ec_048_ping_receives_same_sequence_pong(self):
        peer = self.established()[1]
        peer.write(vector("control_ping.bin"))
        _, _, payload = peer.read_frame()
        self.assertEqual(json.loads(payload), {"type": "pong", "seq": 1})

    def test_ec_049_fatal_error_frame_precedes_close(self):
        peer = self.established(self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,))), encoding_mask=1)[1]
        peer.write(vector("frame_oversized.bin"))
        _, _, payload = peer.read_frame()
        self.assertEqual(json.loads(payload)["code"], 413)
        with self.assertRaises(TransportClosed):
            peer.read(1)

    def test_ec_050_unknown_control_is_ignored(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=1)[1]
        peer.write(build_frame(yuumi.Channel.CONTROL, 0, b'{"type":"future"}'))
        peer.write(vector("frame_channel_command.bin"))
        self.assertEqual(wait_for(lambda: messages)[0].payload["action"], "test")

    def test_ec_051_malformed_control_is_terminal(self):
        packet = build_frame(yuumi.Channel.CONTROL, 0, b"{")
        self.assertEqual(self.errors_for_invalid_frame(packet)[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_052_correlation_without_negotiation_rejected(self):
        self.assertEqual(self.errors_for_invalid_frame(vector("frame_correlated_not_negotiated.bin"))[0].status, yuumi.StatusCode.ERR_PROTOCOL_VIOLATION)

    def test_ec_053_response_repeats_request_correlation(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        peer = self.established(engine, encoding_mask=1, capabilities=yuumi.CAP_CORRELATION)[1]
        engine.on_message(lambda event: engine.send_correlated(event.session, yuumi.Channel.DATA, event.correlation_id, {"ok": True}))
        peer.write(vector("frame_correlated_request.bin"))
        channel, flags, payload = peer.read_frame()
        self.assertEqual((channel, flags, struct.unpack(">I", payload[:4])[0]), (yuumi.Channel.DATA, FLAG_CORRELATED, 42))

    def test_ec_054_application_error_is_correlated_data(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        peer = self.established(engine, encoding_mask=1, capabilities=yuumi.CAP_CORRELATION)[1]
        engine.on_message(lambda event: engine.send_correlated(event.session, yuumi.Channel.DATA, event.correlation_id, {"error": "bad request"}))
        peer.write(vector("frame_correlated_request.bin"))
        channel, flags, payload = peer.read_frame()
        self.assertEqual((channel, flags, struct.unpack(">I", payload[:4])[0]), (yuumi.Channel.DATA, FLAG_CORRELATED, 42))

    def test_ec_055_fragment_and_correlation_prefix_order(self):
        engine = self.open(self.config(supported_encodings=(yuumi.Encoding.JSON,)))
        messages = []
        engine.on_message(messages.append)
        peer = self.established(engine, encoding_mask=1, capabilities=yuumi.CAP_CORRELATION)[1]
        peer.write(vector("frame_fragment_correlated_first.bin"))
        peer.write(vector("frame_fragment_correlated_last.bin"))
        event = wait_for(lambda: messages)[0]
        self.assertEqual((event.payload, event.correlation_id), ("Hello World", 42))

    def test_ec_056_no_public_engine_request_api(self):
        self.assertNotIn("request", yuumi.Engine.__dict__)
        engine, _, view, _, _ = self.established(capabilities=yuumi.CAP_CORRELATION)
        pending = engine._sessions[view.handle.session_id].pending_correlations
        self.assertTrue(pending.begin(42))
        self.assertFalse(pending.begin(42))
        self.assertTrue(pending.finish(42))
        self.assertTrue(pending.begin(42))

    def test_ec_057_uncorrelated_sends_encode_and_preserve_order(self):
        engine, peer, view, _, _ = self.established()
        engine.send(view.handle, yuumi.Channel.DATA, {"n": 1})
        engine.send(view.handle, yuumi.Channel.DATA, {"n": 2})
        values = []
        for _ in range(2):
            _, flags, payload = peer.read_frame()
            values.append(msgpack.unpackb(payload, raw=False)["n"])
            self.assertEqual(flags, 0)
        self.assertEqual(values, [1, 2])

    def test_ec_058_correlated_send_is_capability_gated(self):
        engine, peer, view, _, _ = self.established(capabilities=yuumi.CAP_CORRELATION)
        engine.send_correlated(view.handle, yuumi.Channel.DATA, 42, {"ok": True})
        _, flags, payload = peer.read_frame()
        self.assertEqual((flags, struct.unpack(">I", payload[:4])[0]), (FLAG_CORRELATED, 42))

    def test_ec_059_application_cannot_forge_control_or_command(self):
        engine, _, view, _, _ = self.established()
        for channel in (yuumi.Channel.CONTROL, yuumi.Channel.COMMAND, 99):
            with self.subTest(channel=channel), self.assertRaises(yuumi.EngineError):
                engine.send(view.handle, channel, {})

    def test_ec_060_invalid_closed_stale_sends_are_isolated(self):
        engine, peer, view, _, _ = self.established()
        peer.close()
        wait_for(lambda: not engine._sessions)
        for handle in (view.handle, yuumi.SessionHandle("absent", 0), yuumi.SessionHandle(view.handle.session_id, view.handle.epoch + 1)):
            with self.assertRaises(yuumi.EngineError):
                engine.send(handle, yuumi.Channel.DATA, {})

    def test_ec_061_serialization_and_size_failures_are_explicit(self):
        engine, _, view, _, _ = self.established()
        with self.assertRaises(yuumi.EngineError):
            engine.send(view.handle, yuumi.Channel.DATA, {object()})
        with self.assertRaises(yuumi.EngineError) as caught:
            engine.send(view.handle, yuumi.Channel.DATA, b"x" * (16 * 1024 * 1024 + 1))
        self.assertEqual(caught.exception.code, yuumi.StatusCode.ERR_PAYLOAD_TOO_LARGE)

    def test_ec_062_transport_write_failure_is_one_error(self):
        engine, _, view, _, _ = self.established()
        errors = []
        engine.on_error(errors.append)
        session = engine._sessions[view.handle.session_id]
        session.stream.write_all = lambda _: (_ for _ in ()).throw(TransportFailure("injected write failure"))
        with self.assertRaises(yuumi.EngineError):
            engine.send(view.handle, yuumi.Channel.DATA, {})
        matching = [item for item in errors if item.session == view.handle]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].phase, yuumi.ErrorPhase.FRAME_WRITE)

    def test_ec_063_error_events_preserve_phase_and_handle(self):
        errors = self.errors_for_invalid_frame(vector("frame_oversized.bin"))
        self.assertEqual(errors[0].phase, yuumi.ErrorPhase.FRAME_DECODE)
        self.assertIsNotNone(errors[0].session)

    def test_ec_064_public_api_is_engine_only_and_documented(self):
        self.assertNotIn("Client", yuumi.__all__)
        self.assertNotIn("connect", yuumi.__all__)
        self.assertIn("Engine", yuumi.__all__)
        self.assertIn("callbacks execute synchronously", yuumi.Engine.__doc__.lower())


if __name__ == "__main__":
    unittest.main()
