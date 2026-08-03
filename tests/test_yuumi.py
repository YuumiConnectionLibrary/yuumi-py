from __future__ import annotations

import inspect
import json
import os
import struct
import threading
import time
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path

import msgpack
import yuumi
from testkit import (
    TOKEN,
    Peer,
    decode_json,
    endpoint,
    establish,
    frame,
    handshake,
    listen,
    vector,
    wait_for,
)
from yuumi.transport import TransportClosed, resolve_transport_address


class EngineConformance(unittest.TestCase):
    def setUp(self) -> None:
        self.config = yuumi.EngineConfig(
            endpoint(),
            TOKEN,
            heartbeat=yuumi.HeartbeatSettings(disabled=True),
        )
        self.engines: list[yuumi.Engine] = []
        self.peers: list[Peer] = []

    def tearDown(self) -> None:
        for peer in self.peers:
            peer.close()
        for engine in self.engines:
            engine.close()

    def engine(self, **changes) -> yuumi.Engine:
        value = yuumi.Engine(replace(self.config, **changes))
        self.engines.append(value)
        return value

    def connected(self, engine: yuumi.Engine | None = None, packet: bytes | None = None):
        engine = engine or self.engine()
        peer, ack, assignment, view = establish(
            engine, engine._source_config, packet
        )
        self.peers.append(peer)
        return engine, peer, ack, assignment, view

    def test_ec_001_configuration_is_frozen_and_validated_before_dial(self):
        invalid = [
            replace(self.config, endpoint_name="bad/name"),
            replace(self.config, token="A" * 32),
            replace(self.config, supported_encodings=()),
            replace(
                self.config,
                supported_encodings=(yuumi.Encoding.JSON, yuumi.Encoding.JSON),
            ),
            replace(self.config, supported_capabilities=2),
            replace(self.config, expected_go_pid=-1),
            replace(self.config, connect_timeout=0),
            replace(self.config, application_queue_capacity=0),
            replace(self.config, heartbeat=yuumi.HeartbeatSettings(interval=0)),
            replace(
                self.config,
                fragmentation=yuumi.FragmentationSettings(timeout=0),
            ),
        ]
        for config in invalid:
            with self.subTest(config=config):
                target = yuumi.Engine(config)
                with self.assertRaises(yuumi.EngineError) as caught:
                    target.connect()
                self.assertEqual(caught.exception.kind, yuumi.ErrorKind.CONFIGURATION)
                self.assertEqual(target.state, yuumi.EngineState.IDLE)
        self.assertEqual(self.config.connect_timeout, 10.0)
        self.assertEqual(self.config.application_queue_capacity, 64)

    def test_ec_002_canonical_address_matches_all_vectors(self):
        data = json.loads(
            (vector("address_derivation.json")).decode("utf-8")
        )
        for item in data["cases"]:
            values = item["input"]
            expected = item["expected"]
            self.assertEqual(
                resolve_transport_address(
                    values["endpoint_name"],
                    values["token"],
                    values["os_temp_dir"],
                    "win32",
                ),
                expected["windows_address"],
            )
            if expected["macos_outcome"] == "accept":
                self.assertEqual(
                    resolve_transport_address(
                        values["endpoint_name"],
                        values["token"],
                        values["os_temp_dir"],
                        "darwin",
                    ),
                    expected["unix_address"],
                )
            else:
                with self.assertRaises(ValueError):
                    resolve_transport_address(
                        values["endpoint_name"],
                        values["token"],
                        values["os_temp_dir"],
                        "darwin",
                    )

    def test_ec_003_engine_is_platform_native_dialer_only(self):
        engine, _, _, _, _ = self.connected()
        self.assertNotIn("open", yuumi.Engine.__dict__)
        self.assertNotIn("listen", yuumi.Engine.__dict__)
        self.assertNotIn("address", engine.__dict__)
        self.assertEqual(engine.state, yuumi.EngineState.CONNECTED)

    def test_ec_004_dial_failure_is_typed_and_creates_no_endpoint(self):
        engine = self.engine(connect_timeout=0.1)
        address = resolve_transport_address(
            self.config.endpoint_name, self.config.token
        )
        with self.assertRaises(yuumi.EngineError) as caught:
            engine.connect()
        self.assertEqual(caught.exception.kind, yuumi.ErrorKind.DIAL)
        self.assertEqual(engine.state, yuumi.EngineState.IDLE)
        if os.name != "nt":
            self.assertFalse(os.path.exists(address))

    def test_ec_005_invalid_handshake_writes_nothing(self):
        for packet, status in (
            (handshake(magic=0), yuumi.StatusCode.ERR_MAGIC_MISMATCH),
            (handshake(version=2), yuumi.StatusCode.ERR_VERSION_MISMATCH),
            (handshake(encodings=0), yuumi.StatusCode.ERR_ENCODING_UNSUPPORTED),
        ):
            with self.subTest(status=status):
                config = replace(self.config, endpoint_name=endpoint())
                engine = yuumi.Engine(config)
                self.engines.append(engine)
                listener = listen(config)
                caught = {}

                def connect():
                    try:
                        engine.connect()
                    except BaseException as exc:
                        caught["error"] = exc

                worker = threading.Thread(target=connect)
                worker.start()
                peer = Peer(listener.accept())
                peer.write(packet)
                with self.assertRaises(TransportClosed):
                    peer.read(1)
                peer.close()
                worker.join(2)
                listener.close()
                self.assertEqual(caught["error"].code, status)

    def test_ec_006_handshake_ack_assignment_and_fragmentation(self):
        engine = self.engine(
            supported_encodings=(yuumi.Encoding.JSON, yuumi.Encoding.MSGPACK)
        )
        _, peer, ack, assignment, view = self.connected(
            engine, handshake(encodings=3, capabilities=0x800001)
        )
        self.assertEqual(ack, vector("ack_cap_correlation.bin"))
        self.assertEqual(assignment[:2], (yuumi.Channel.CONTROL, 0))
        self.assertEqual(decode_json(assignment)["session_id"], view.session_id)
        messages = []
        engine.on_message(messages.append)
        peer.write(vector("frame_fragment_first.bin"))
        peer.write(vector("frame_fragment_last.bin"))
        self.assertEqual(wait_for(lambda: messages)[0].payload, "Hello World")

    def test_ec_007_duplicate_connect_close_and_explicit_reconnect(self):
        engine, peer, _, _, first = self.connected()
        with self.assertRaises(yuumi.EngineError) as caught:
            engine.connect()
        self.assertEqual(caught.exception.kind, yuumi.ErrorKind.STATE)
        engine.close()
        engine.close()
        self.assertEqual(engine.state, yuumi.EngineState.IDLE)
        peer.close()
        replacement = establish(engine, self.config)
        self.peers.append(replacement[0])
        self.assertGreater(replacement[3].epoch, first.epoch)

    def test_ec_008_responder_is_data_correlated_single_use_and_stale(self):
        engine, peer, _, _, first = self.connected(
            packet=handshake(encodings=1, capabilities=1),
            engine=self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
        )
        messages = []
        engine.on_message(messages.append)
        peer.write(vector("frame_correlated_request.bin"))
        event = wait_for(lambda: messages)[0]
        event.responder.respond({"ok": True})
        channel, flags, payload = peer.read_frame()
        self.assertEqual((channel, flags, struct.unpack(">I", payload[:4])[0]), (3, 4, 42))
        with self.assertRaises(yuumi.EngineError) as caught:
            event.responder.respond({"again": True})
        self.assertEqual(caught.exception.kind, yuumi.ErrorKind.STALE_EPOCH)
        peer.close()
        wait_for(lambda: engine.state == yuumi.EngineState.IDLE)
        replacement = establish(engine, self.config, handshake(encodings=1))
        self.peers.append(replacement[0])
        self.assertGreater(replacement[3].epoch, first.epoch)

    def test_ec_009_slow_handler_does_not_block_ping_or_send(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
            handshake(encodings=1),
        )
        started = threading.Event()
        release = threading.Event()

        def handler(_):
            started.set()
            release.wait(1)

        engine.on_message(handler)
        peer.write(vector("frame_channel_command.bin"))
        self.assertTrue(started.wait(1))
        peer.write(vector("control_ping.bin"))
        self.assertEqual(decode_json(peer.read_frame()), {"type": "pong", "seq": 1})
        engine.send(yuumi.Channel.DATA, {"while": "blocked"})
        self.assertEqual(decode_json(peer.read_frame()), {"while": "blocked"})
        release.set()

    def test_ec_010_backpressure_and_callback_exception_are_observable(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(
                supported_encodings=(yuumi.Encoding.JSON,),
                application_queue_capacity=2,
            ),
            handshake(encodings=1),
        )
        wait_for(lambda: engine._session.capacity_used == 0)
        release = threading.Event()
        order = []

        def handler(event):
            order.append(event.payload["n"])
            release.wait(1)

        engine.on_message(handler)
        engine.on_error(lambda event: order.append(event.kind))
        engine.on_session_disconnected(
            lambda event: order.append(event.terminal.reason)
        )
        peer.write(
            b"".join(
                frame(1, 0, json.dumps({"n": n}).encode("utf-8"))
                for n in (1, 2, 3)
            )
        )
        wait_for(lambda: engine.state == yuumi.EngineState.IDLE)
        release.set()
        wait_for(lambda: yuumi.DisconnectReason.BACKPRESSURE in order)
        self.assertEqual(
            order,
            [
                1,
                2,
                yuumi.ErrorKind.BACKPRESSURE,
                yuumi.DisconnectReason.BACKPRESSURE,
            ],
        )

        config = replace(self.config, endpoint_name=endpoint())
        failing = yuumi.Engine(config)
        self.engines.append(failing)
        errors = []
        failing.on_error(errors.append)
        next_peer, _, _, _ = establish(failing, config)
        self.peers.append(next_peer)
        failing.on_message(lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
        next_peer.write(
            frame(1, 0, msgpack.packb({"n": 1}, use_bin_type=True))
        )
        self.assertEqual(
            wait_for(
                lambda: next(
                    (item for item in errors if item.kind == yuumi.ErrorKind.APPLICATION),
                    None,
                )
            ).cause,
            "boom",
        )

    def test_ec_011_protocol_failure_is_framed_before_close(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
            handshake(encodings=1),
        )
        errors = []
        engine.on_error(errors.append)
        peer.write(vector("frame_oversized.bin"))
        control = peer.read_frame()
        self.assertEqual(decode_json(control)["code"], 413)
        with self.assertRaises(TransportClosed):
            peer.read(1)
        self.assertEqual(
            wait_for(lambda: errors)[0].kind, yuumi.ErrorKind.PROTOCOL
        )

    def test_ec_012_heartbeat_disconnect_cleanup_and_public_surface(self):
        engine, peer, _, _, _ = self.connected()
        heartbeats = []
        disconnected = []
        engine.on_heartbeat(heartbeats.append)
        engine.on_session_disconnected(disconnected.append)
        peer.write(vector("control_heartbeat.bin"))
        self.assertTrue(wait_for(lambda: heartbeats))
        peer.close()
        wait_for(lambda: engine.state == yuumi.EngineState.IDLE)
        event = wait_for(lambda: disconnected)[0]
        self.assertEqual(event.terminal.reason, yuumi.DisconnectReason.PEER_CLOSE)
        wait_for(
            lambda: not any(
                thread.name.startswith("yuumi-engine-") and thread.is_alive()
                for thread in threading.enumerate()
            )
        )
        for name in (
            "Client",
            "Runner",
            "open",
            "listen",
            "request",
            "send_correlated",
            "resolve_transport_address",
        ):
            self.assertNotIn(name, yuumi.__all__)
            self.assertNotIn(name, yuumi.Engine.__dict__)
        self.assertIn("explicit daemon", inspect.getdoc(yuumi.Engine))

    def test_ec_013_fragment_timeout_and_malformed_frame_are_observable(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(
                supported_encodings=(yuumi.Encoding.JSON,),
                fragmentation=yuumi.FragmentationSettings(timeout=0.02),
            ),
            handshake(encodings=1),
        )
        errors = []
        engine.on_error(errors.append)
        peer.write(vector("frame_fragment_first.bin"))
        expired = wait_for(
            lambda: next(
                (
                    item
                    for item in errors
                    if item.status == yuumi.StatusCode.ERR_FRAGMENT_TIMEOUT
                ),
                None,
            )
        )
        self.assertEqual(expired.kind, yuumi.ErrorKind.TIMEOUT)

        config = replace(
            self.config,
            endpoint_name=endpoint(),
            supported_encodings=(yuumi.Encoding.JSON,),
        )
        malformed = yuumi.Engine(config)
        self.engines.append(malformed)
        malformed_errors = []
        malformed.on_error(malformed_errors.append)
        next_peer, _, _, _ = establish(
            malformed, config, handshake(encodings=1)
        )
        self.peers.append(next_peer)
        next_peer.write(frame(yuumi.Channel.COMMAND, 0x80, b"{}"))
        next_peer.read_frame()
        self.assertEqual(
            wait_for(lambda: malformed_errors)[0].kind,
            yuumi.ErrorKind.PROTOCOL,
        )

    def test_ec_014_public_sends_are_directional_ordered_and_explicit(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
            handshake(encodings=1),
        )
        engine.send(yuumi.Channel.DATA, {"n": 1})
        engine.send(yuumi.Channel.LOG, {"n": 2})
        first = peer.read_frame()
        second = peer.read_frame()
        self.assertEqual(
            [
                (first[0], decode_json(first)["n"]),
                (second[0], decode_json(second)["n"]),
            ],
            [(yuumi.Channel.DATA, 1), (yuumi.Channel.LOG, 2)],
        )
        with self.assertRaises(yuumi.EngineError) as caught:
            engine.send(yuumi.Channel.COMMAND, {})
        self.assertEqual(caught.exception.kind, yuumi.ErrorKind.PROTOCOL)
        with self.assertRaises(yuumi.EngineError):
            engine.send(yuumi.Channel.DATA, {object()})

    def test_ec_015_heartbeat_emission_and_timeout_are_terminal(self):
        engine, peer, _, _, view = self.connected(
            self.engine(
                heartbeat=yuumi.HeartbeatSettings(
                    interval=0.02, missed_interval_limit=3
                )
            )
        )
        channel, flags, payload = peer.read_frame()
        self.assertEqual((channel, flags), (yuumi.Channel.CONTROL, 0))
        self.assertEqual(json.loads(payload)["type"], "heartbeat")
        wait_for(lambda: engine.state == yuumi.EngineState.IDLE)
        terminal = engine.terminal_result
        self.assertEqual(terminal.reason, yuumi.DisconnectReason.HEARTBEAT_TIMEOUT)
        self.assertEqual(terminal.error.epoch, view.epoch)

    def test_ec_016_close_cancels_an_incomplete_handshake(self):
        engine = self.engine(connect_timeout=5)
        listener = listen(self.config)
        caught = {}

        def connect():
            try:
                engine.connect()
            except BaseException as exc:
                caught["error"] = exc

        worker = threading.Thread(target=connect, name="connect-under-close")
        worker.start()
        peer = Peer(listener.accept())
        wait_for(lambda: engine._candidate)
        engine.close()
        worker.join(2)
        peer.close()
        listener.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(caught["error"].kind, yuumi.ErrorKind.SESSION_CLOSED)
        self.assertEqual(engine.state, yuumi.EngineState.IDLE)

    def test_ec_017_short_handshake_and_pid_policy_fail_without_ack(self):
        for packet, config, status in (
            (
                handshake()[:15],
                replace(self.config, endpoint_name=endpoint()),
                yuumi.StatusCode.ERR_CONNECTION_LOST,
            ),
            (
                handshake(pid=0),
                replace(
                    self.config,
                    endpoint_name=endpoint(),
                    expected_go_pid=os.getpid(),
                ),
                yuumi.StatusCode.ERR_PID_MISMATCH,
            ),
        ):
            with self.subTest(status=status):
                engine = yuumi.Engine(config)
                self.engines.append(engine)
                listener = listen(config)
                caught = {}

                def connect():
                    try:
                        engine.connect()
                    except BaseException as exc:
                        caught["error"] = exc

                worker = threading.Thread(target=connect)
                worker.start()
                peer = Peer(listener.accept())
                peer.write(packet)
                if len(packet) < 16:
                    peer.close()
                with self.assertRaises(TransportClosed):
                    peer.read(1)
                peer.close()
                worker.join(2)
                listener.close()
                self.assertEqual(caught["error"].code, status)

    def test_ec_018_error_kinds_environment_and_manifest_constraints(self):
        self.assertEqual(
            {item.value for item in yuumi.ErrorKind},
            {
                "address_derivation",
                "application",
                "backpressure",
                "capability",
                "configuration",
                "dial",
                "encoding",
                "handshake",
                "internal",
                "protocol",
                "session_closed",
                "stale_epoch",
                "state",
                "timeout",
                "transport",
            },
        )
        self.assertNotIn("config_from_env", yuumi.__all__)
        manifest = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["project"]["dependencies"], ["msgpack>=1.0.7"])
        serialized = json.dumps(manifest).lower()
        self.assertNotIn("pywin32", serialized)
        self.assertNotIn("extension", serialized)


if __name__ == "__main__":
    unittest.main()
