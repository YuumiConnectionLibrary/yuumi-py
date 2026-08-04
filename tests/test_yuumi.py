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
    TEST_TIMEOUT,
    TOKEN,
    Peer,
    decode_json,
    endpoint,
    establish,
    frame,
    handshake,
    open_go_listener,
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

    def _case_configuration(self):
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

    def _case_address(self):
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

    def _case_native_dialer(self):
        engine, _, _, _, _ = self.connected()
        self.assertNotIn("open", yuumi.Engine.__dict__)
        self.assertNotIn("listen", yuumi.Engine.__dict__)
        self.assertNotIn("address", engine.__dict__)
        self.assertEqual(engine.state, yuumi.EngineState.CONNECTED)

    def _case_dial_failure(self):
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

    def _case_invalid_handshake(self):
        for packet, status in (
            (handshake(magic=0), yuumi.StatusCode.ERR_MAGIC_MISMATCH),
            (handshake(version=2), yuumi.StatusCode.ERR_VERSION_MISMATCH),
            (handshake(encodings=0), yuumi.StatusCode.ERR_ENCODING_UNSUPPORTED),
        ):
            with self.subTest(status=status):
                config = replace(self.config, endpoint_name=endpoint())
                engine = yuumi.Engine(config)
                self.engines.append(engine)
                listener = open_go_listener(config)
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

    def _case_establishment_write_failure(self):
        config = replace(self.config, endpoint_name=endpoint())
        engine = yuumi.Engine(config)
        self.engines.append(engine)
        listener = open_go_listener(config)
        caught = {}

        def connect():
            try:
                engine.connect()
            except BaseException as exc:
                caught["error"] = exc

        worker = threading.Thread(
            target=connect,
            name="yuumi-testkit-establishment-failure",
            daemon=False,
        )
        worker.start()
        peer = Peer(listener.accept())
        peer.write(handshake())
        peer.close()
        worker.join(TEST_TIMEOUT)
        listener.close()
        self.assertFalse(worker.is_alive())
        self.assertIn("error", caught)
        self.assertIsNone(engine.session)
        self.assertEqual(engine.state, yuumi.EngineState.IDLE)

    def _case_negotiation_assignment_and_fragmentation(self):
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
        self.assertEqual(
            wait_for(lambda: messages, "EC-013 fragmented message")[0].payload,
            "Hello World",
        )

    def _case_duplicate_connect_close_and_reconnect(self):
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

    def _case_responder_and_replacement_epoch(self):
        engine, peer, _, _, first = self.connected(
            packet=handshake(encodings=1, capabilities=1),
            engine=self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
        )
        messages = []
        engine.on_message(messages.append)
        peer.write(vector("frame_correlated_request.bin"))
        event = wait_for(lambda: messages, "EC-014 correlated responder")[0]
        event.responder.respond({"ok": True})
        channel, flags, payload = peer.read_frame()
        self.assertEqual((channel, flags, struct.unpack(">I", payload[:4])[0]), (3, 4, 42))
        with self.assertRaises(yuumi.EngineError) as caught:
            event.responder.respond({"again": True})
        self.assertEqual(caught.exception.kind, yuumi.ErrorKind.STALE_EPOCH)
        peer.write(vector("frame_correlated_request.bin"))
        stale_responder = wait_for(
            lambda: messages[1].responder if len(messages) > 1 else None,
            "second correlated responder",
        )
        peer.close()
        wait_for(
            lambda: engine.state == yuumi.EngineState.IDLE,
            "old epoch to become idle",
        )
        replacement = establish(engine, self.config, handshake(encodings=1))
        self.peers.append(replacement[0])
        self.assertGreater(replacement[3].epoch, first.epoch)
        with self.assertRaises(yuumi.EngineError) as stale:
            stale_responder.respond({"stale": True})
        self.assertEqual(stale.exception.kind, yuumi.ErrorKind.STALE_EPOCH)

    def _case_slow_handler(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
            handshake(encodings=1),
        )
        started = threading.Event()
        release = threading.Event()

        def handler(_):
            started.set()
            release.wait(TEST_TIMEOUT)

        engine.on_message(handler)
        peer.write(vector("frame_channel_command.bin"))
        self.assertTrue(started.wait(TEST_TIMEOUT))
        peer.write(vector("control_ping.bin"))
        self.assertEqual(decode_json(peer.read_frame()), {"type": "pong", "seq": 1})
        engine.send(yuumi.Channel.DATA, {"while": "blocked"})
        self.assertEqual(decode_json(peer.read_frame()), {"while": "blocked"})
        release.set()

    def _case_backpressure_and_callback_failure(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(
                supported_encodings=(yuumi.Encoding.JSON,),
                application_queue_capacity=2,
            ),
            handshake(encodings=1),
        )
        wait_for(
            lambda: engine._session.capacity_used == 0,
            "EC-018 application queue barrier",
        )
        release = threading.Event()
        order = []

        def handler(event):
            order.append(event.payload["n"])
            release.wait(TEST_TIMEOUT)

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
        wait_for(
            lambda: engine.state == yuumi.EngineState.IDLE,
            "EC-018 terminal idle state",
        )
        release.set()
        wait_for(
            lambda: yuumi.DisconnectReason.BACKPRESSURE in order,
            "EC-018 reserved terminal events",
        )
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
                ),
                "EC-019 application diagnostic",
            ).cause,
            "boom",
        )

    def _case_protocol_failure(self):
        engine, peer, _, _, _ = self.connected(
            self.engine(supported_encodings=(yuumi.Encoding.JSON,)),
            handshake(encodings=1),
        )
        errors = []
        engine.on_error(errors.append)
        peer.write(vector("control_ping.bin"))
        self.assertEqual(decode_json(peer.read_frame()), {"type": "pong", "seq": 1})
        peer.write(vector("frame_oversized.bin"))
        control = peer.read_frame()
        self.assertEqual(decode_json(control)["code"], 413)
        with self.assertRaises(TransportClosed):
            peer.read(1)
        self.assertEqual(
            wait_for(lambda: errors, "EC-016 protocol diagnostic")[0].kind,
            yuumi.ErrorKind.PROTOCOL,
        )

    def _case_disconnect_cleanup_and_public_surface(self):
        engine, peer, _, _, _ = self.connected()
        heartbeats = []
        disconnected = []
        engine.on_heartbeat(heartbeats.append)
        engine.on_session_disconnected(disconnected.append)
        peer.write(vector("control_heartbeat.bin"))
        self.assertTrue(wait_for(lambda: heartbeats, "EC-020 heartbeat event"))
        peer.close()
        wait_for(
            lambda: engine.state == yuumi.EngineState.IDLE,
            "EC-020 disconnect idle state",
        )
        event = wait_for(
            lambda: disconnected,
            "EC-020 disconnect event",
        )[0]
        self.assertEqual(event.terminal.reason, yuumi.DisconnectReason.PEER_CLOSE)
        wait_for(
            lambda: not any(
                thread.name.startswith("yuumi-engine-") and thread.is_alive()
                for thread in threading.enumerate()
            ),
            "EC-025 engine worker cleanup",
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

    def _case_fragment_timeout_and_malformed_frame(self):
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
            ),
            "EC-013 fragment timeout",
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
        malformed_messages = []
        malformed.on_error(malformed_errors.append)
        malformed.on_message(malformed_messages.append)
        next_peer, _, _, _ = establish(
            malformed, config, handshake(encodings=1)
        )
        self.peers.append(next_peer)
        next_peer.write(frame(yuumi.Channel.COMMAND, 0x80, b"{}"))
        next_peer.read_frame()
        self.assertEqual(
            wait_for(
                lambda: malformed_errors,
                "EC-012 malformed frame diagnostic",
            )[0].kind,
            yuumi.ErrorKind.PROTOCOL,
        )
        self.assertEqual(malformed_messages, [])

    def _case_public_sends(self):
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

    def _case_heartbeat_timeout(self):
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
        wait_for(
            lambda: engine.state == yuumi.EngineState.IDLE,
            "EC-025 heartbeat timeout",
        )
        terminal = engine.terminal_result
        self.assertEqual(terminal.reason, yuumi.DisconnectReason.HEARTBEAT_TIMEOUT)
        self.assertEqual(terminal.error.epoch, view.epoch)

    def _case_close_cancels_incomplete_handshake(self):
        engine = self.engine(connect_timeout=5)
        listener = open_go_listener(self.config)
        caught = {}

        def connect():
            try:
                engine.connect()
            except BaseException as exc:
                caught["error"] = exc

        worker = threading.Thread(target=connect, name="connect-under-close")
        worker.start()
        peer = Peer(listener.accept())
        wait_for(lambda: engine._candidate, "EC-025 incomplete handshake candidate")
        engine.close()
        worker.join(TEST_TIMEOUT)
        peer.close()
        listener.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(caught["error"].kind, yuumi.ErrorKind.SESSION_CLOSED)
        self.assertEqual(engine.state, yuumi.EngineState.IDLE)

    def _case_short_handshake_and_pid_policy(self):
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
                listener = open_go_listener(config)
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

    def _case_error_kinds_environment_and_manifest(self):
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

    def test_ec_001_configuration_validation_is_pure_and_snapshot_based(self):
        self._case_configuration()

    def test_ec_002_canonical_address_is_byte_identical(self):
        self._case_address()

    def test_ec_003_every_engine_is_only_a_native_dialer(self):
        self._case_native_dialer()

    def test_ec_004_dial_failures_are_explicit_and_grant_no_ownership(self):
        self._case_dial_failure()

    def test_ec_005_handshake_is_exact_and_invalid_input_writes_nothing(self):
        self._case_invalid_handshake()
        self._case_short_handshake_and_pid_policy()

    def test_ec_006_encoding_and_capability_intersection_are_deterministic(self):
        self._case_negotiation_assignment_and_fragmentation()

    def test_ec_007_ack_and_assignment_establish_in_exact_order(self):
        self._case_negotiation_assignment_and_fragmentation()

    def test_ec_008_establishment_write_failure_creates_no_session(self):
        self._case_establishment_write_failure()

    def test_ec_009_state_machine_rejects_duplicate_connect(self):
        self._case_duplicate_connect_close_and_reconnect()

    def test_ec_010_close_is_idempotent_reconnect_is_explicit(self):
        self._case_duplicate_connect_close_and_reconnect()

    def test_ec_011_frames_and_oversize_bounds_are_exact(self):
        self._case_protocol_failure()

    def test_ec_012_malformed_frames_never_partially_deliver(self):
        self._case_fragment_timeout_and_malformed_frame()

    def test_ec_013_fragmentation_is_bounded_and_epoch_local(self):
        self._case_negotiation_assignment_and_fragmentation()
        self.config = replace(self.config, endpoint_name=endpoint())
        self._case_fragment_timeout_and_malformed_frame()

    def test_ec_014_correlation_preserves_responder_authority(self):
        self._case_responder_and_replacement_epoch()

    def test_ec_015_public_sends_are_directional_ordered_and_await_writes(self):
        self._case_public_sends()

    def test_ec_016_control_and_fatal_ordering_are_exact(self):
        self._case_protocol_failure()

    def test_ec_017_ipc_progresses_independently_of_slow_handlers(self):
        self._case_slow_handler()

    def test_ec_018_backpressure_is_terminal_and_observable(self):
        self._case_backpressure_and_callback_failure()

    def test_ec_019_callback_failures_are_observable(self):
        self._case_backpressure_and_callback_failure()

    def test_ec_020_disconnect_clears_session_state_before_idle(self):
        self._case_disconnect_cleanup_and_public_surface()

    def test_ec_021_replacement_epoch_rejects_stale_work(self):
        self._case_responder_and_replacement_epoch()

    def test_ec_022_every_engine_error_kind_is_distinguishable(self):
        self._case_error_kinds_environment_and_manifest()

    def test_ec_023_public_surface_has_no_listener_client_runner_or_schema_policy(self):
        self._case_disconnect_cleanup_and_public_surface()

    def test_ec_024_environment_adapter_is_configuration_only(self):
        self._case_error_kinds_environment_and_manifest()

    def test_ec_025_cleanup_and_runtime_constraints_hold(self):
        self._case_heartbeat_timeout()
        self.config = replace(self.config, endpoint_name=endpoint())
        self._case_close_cancels_incomplete_handshake()
        self.config = replace(self.config, endpoint_name=endpoint())
        self._case_disconnect_cleanup_and_public_surface()
        self.config = replace(self.config, endpoint_name=endpoint())
        self._case_error_kinds_environment_and_manifest()


if __name__ == "__main__":
    unittest.main()
