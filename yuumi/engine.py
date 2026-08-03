from __future__ import annotations

import inspect
import struct
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from .protocol import (
    FLAG_CORRELATED,
    FLAG_FRAGMENT,
    FLAG_LAST_FRAGMENT,
    KNOWN_FLAGS,
    ProtocolFailure,
    build_control_frame,
    build_frame,
    decode_control,
    decode_payload,
    encode_payload,
)
from .transport import (
    Stream,
    TransportClosed,
    TransportFailure,
    TransportTimeout,
    dial_local,
    resolve_transport_address,
    valid_endpoint_name,
    valid_token,
)
from .types import (
    CAP_CORRELATION,
    IMPLEMENTED_CAPABILITIES,
    MAGIC,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    Channel,
    DisconnectEvent,
    DisconnectReason,
    Encoding,
    EngineConfig,
    EngineError,
    EngineState,
    ErrorInfo,
    ErrorKind,
    ErrorPhase,
    FragmentationSettings,
    HeartbeatEvent,
    HeartbeatSettings,
    MessageEvent,
    SessionView,
    StatusCode,
    TerminalResult,
)

_THREAD_JOIN_TIMEOUT = 2.0

ConnectedHandler = Callable[[SessionView], None]
MessageHandler = Callable[[MessageEvent], None]
HeartbeatHandler = Callable[[HeartbeatEvent], None]
ErrorHandler = Callable[[ErrorInfo], None]
DisconnectedHandler = Callable[[DisconnectEvent], None]


def _error(
    kind: ErrorKind,
    cause: str,
    status: StatusCode | None = None,
    phase: ErrorPhase | None = None,
    epoch: int | None = None,
) -> ErrorInfo:
    return ErrorInfo(kind, cause, status, phase, epoch)


def _engine_error(
    kind: ErrorKind,
    cause: str,
    status: StatusCode | None = None,
    phase: ErrorPhase | None = None,
    epoch: int | None = None,
) -> EngineError:
    return EngineError(_error(kind, cause, status, phase, epoch))


@dataclass
class _Fragment:
    identifier: int
    correlation_id: int | None
    data: bytearray
    deadline: float


@dataclass
class _DispatchItem:
    kind: str
    value: object
    uses_capacity: bool


class _Responder:
    def __init__(self, engine: Engine, epoch: int, correlation_id: int) -> None:
        self._engine = engine
        self._epoch = epoch
        self._correlation_id = correlation_id
        self._used = False
        self._lock = threading.Lock()

    def respond(self, payload: Any) -> None:
        with self._lock:
            if self._used:
                raise _engine_error(
                    ErrorKind.STALE_EPOCH,
                    "responder is single-use",
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    ErrorPhase.APPLICATION_SEND,
                    self._epoch,
                )
            self._used = True
        self._engine._respond(self, payload)

    def invalidate(self) -> None:
        with self._lock:
            self._used = True


class _Session:
    def __init__(self, stream: Stream, view: SessionView, config: EngineConfig) -> None:
        now = time.monotonic()
        self.stream = stream
        self.view = view
        self.config = config
        self.fragments: dict[Channel, _Fragment] = {}
        self.responders: set[_Responder] = set()
        self.last_activity = now
        self.last_heartbeat = now
        self.send_lock = threading.Lock()
        self.data_lock = threading.Lock()
        self.finalize_lock = threading.Lock()
        self.close_requested = threading.Event()
        self.finalized = False
        self.accepting_events = True
        self.terminal = TerminalResult(DisconnectReason.PEER_CLOSE)
        self.events: deque[_DispatchItem] = deque()
        self.event_condition = threading.Condition()
        self.capacity_used = 0
        self.transport_finalized = False
        self.reader_thread: threading.Thread | None = None
        self.dispatch_thread: threading.Thread | None = None
        self.maintenance_thread: threading.Thread | None = None


class Engine:
    """
    Single-session Yuumi engine dialer.

    connect() performs exactly one platform-native dial and handshake attempt.
    Application callbacks run serially on the named dispatcher thread, never on
    the reader or maintenance threads. All owned threads are explicit daemon
    threads and close() wakes and joins them within a bounded deadline.
    """

    def __init__(self, config: EngineConfig) -> None:
        self._source_config = config
        self._state = EngineState.IDLE
        self._state_lock = threading.Lock()
        self._handlers_lock = threading.Lock()
        self._candidate: Stream | None = None
        self._session: _Session | None = None
        self._next_epoch = 0
        self._terminal_result: TerminalResult | None = None
        self._connected_handler: ConnectedHandler | None = None
        self._message_handler: MessageHandler | None = None
        self._heartbeat_handler: HeartbeatHandler | None = None
        self._error_handler: ErrorHandler | None = None
        self._disconnected_handler: DisconnectedHandler | None = None

    @property
    def state(self) -> EngineState:
        with self._state_lock:
            return self._state

    @property
    def session(self) -> SessionView | None:
        with self._state_lock:
            return None if self._session is None else self._session.view

    @property
    def terminal_result(self) -> TerminalResult | None:
        with self._state_lock:
            return self._terminal_result

    def on_session_connected(self, handler: ConnectedHandler | None) -> None:
        with self._handlers_lock:
            self._connected_handler = handler

    def on_message(self, handler: MessageHandler | None) -> None:
        with self._handlers_lock:
            self._message_handler = handler

    def on_heartbeat(self, handler: HeartbeatHandler | None) -> None:
        with self._handlers_lock:
            self._heartbeat_handler = handler

    def on_error(self, handler: ErrorHandler | None) -> None:
        with self._handlers_lock:
            self._error_handler = handler

    def on_session_disconnected(self, handler: DisconnectedHandler | None) -> None:
        with self._handlers_lock:
            self._disconnected_handler = handler

    def connect(self) -> SessionView:
        with self._state_lock:
            if self._state != EngineState.IDLE:
                cause = (
                    "engine is already connecting"
                    if self._state == EngineState.CONNECTING
                    else "engine is already connected or closing"
                )
                raise _engine_error(
                    ErrorKind.STATE,
                    cause,
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    ErrorPhase.DIAL,
                )
        try:
            config = self._snapshot_and_validate_config()
        except EngineError as exc:
            self._emit_pre_session_error(exc.info)
            raise
        try:
            address = resolve_transport_address(config.endpoint_name, config.token)
        except (OSError, ValueError) as exc:
            failure = _engine_error(
                ErrorKind.ADDRESS_DERIVATION,
                str(exc),
                StatusCode.ERR_PIPE_FAILED,
                ErrorPhase.ADDRESS_DERIVATION,
            )
            self._emit_pre_session_error(failure.info)
            raise failure from exc
        with self._state_lock:
            if self._state != EngineState.IDLE:
                raise _engine_error(
                    ErrorKind.STATE,
                    "engine state changed before dial",
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    ErrorPhase.DIAL,
                )
            self._state = EngineState.CONNECTING
            self._terminal_result = None
        deadline = time.monotonic() + config.connect_timeout
        stream: Stream | None = None
        phase = ErrorPhase.DIAL
        try:
            stream = dial_local(address, config.connect_timeout)
            with self._state_lock:
                if self._state != EngineState.CONNECTING:
                    stream.close()
                    raise _engine_error(
                        ErrorKind.SESSION_CLOSED,
                        "connection attempt was closed locally",
                        StatusCode.ERR_CONNECTION_LOST,
                        ErrorPhase.CLOSE,
                    )
                self._candidate = stream
            phase = ErrorPhase.HANDSHAKE_READ
            stream.set_timeout(self._remaining(deadline))
            packet = stream.read_exact(16)
            phase = ErrorPhase.HANDSHAKE_VALIDATE
            magic, version, pid, encoding_mask = struct.unpack(">IIIB", packet[:13])
            client_capabilities = int.from_bytes(packet[13:16], "big")
            if magic != MAGIC:
                raise _engine_error(
                    ErrorKind.HANDSHAKE,
                    "handshake magic is invalid",
                    StatusCode.ERR_MAGIC_MISMATCH,
                    phase,
                )
            if version != PROTOCOL_VERSION:
                raise _engine_error(
                    ErrorKind.HANDSHAKE,
                    "handshake protocol version is incompatible",
                    StatusCode.ERR_VERSION_MISMATCH,
                    phase,
                )
            if config.expected_go_pid is not None:
                peer_pid = stream.peer_pid()
                if pid != config.expected_go_pid or (
                    peer_pid is not None and peer_pid != config.expected_go_pid
                ):
                    raise _engine_error(
                        ErrorKind.HANDSHAKE,
                        "Go PID does not match expected_go_pid",
                        StatusCode.ERR_PID_MISMATCH,
                        phase,
                    )
            selected = next(
                (
                    encoding
                    for encoding in config.supported_encodings
                    if encoding_mask & int(encoding)
                ),
                None,
            )
            if selected is None:
                raise _engine_error(
                    ErrorKind.ENCODING,
                    "no common encoding exists",
                    StatusCode.ERR_ENCODING_UNSUPPORTED,
                    phase,
                )
            capabilities = (
                client_capabilities
                & config.supported_capabilities
                & IMPLEMENTED_CAPABILITIES
            )
            phase = ErrorPhase.ACK_WRITE
            stream.set_timeout(self._remaining(deadline))
            stream.write_all(bytes([int(selected)]) + capabilities.to_bytes(3, "big"))
            session_id = uuid.uuid4().hex
            phase = ErrorPhase.SESSION_WRITE
            stream.set_timeout(self._remaining(deadline))
            stream.write_all(
                build_control_frame({"type": "session", "session_id": session_id})
            )
            stream.set_timeout(None)
            with self._state_lock:
                if self._state != EngineState.CONNECTING:
                    raise _engine_error(
                        ErrorKind.SESSION_CLOSED,
                        "connection attempt was closed locally",
                        StatusCode.ERR_CONNECTION_LOST,
                        ErrorPhase.CLOSE,
                    )
                view = SessionView(
                    session_id,
                    self._next_epoch + 1,
                    selected,
                    capabilities,
                )
                session = _Session(stream, view, config)
                self._next_epoch = view.epoch
                self._candidate = None
                self._session = session
                self._state = EngineState.CONNECTED
            self._start_session(session)
            return view
        except EngineError as exc:
            failure = exc
        except TransportTimeout as exc:
            failure = _engine_error(
                ErrorKind.TIMEOUT,
                str(exc),
                StatusCode.ERR_READ_TIMEOUT,
                phase,
            )
        except (TransportClosed, TransportFailure) as exc:
            with self._state_lock:
                locally_closed = self._state == EngineState.CLOSING
            failure = _engine_error(
                ErrorKind.SESSION_CLOSED if locally_closed else (
                    ErrorKind.DIAL if phase == ErrorPhase.DIAL else ErrorKind.HANDSHAKE
                ),
                "connection attempt was closed locally" if locally_closed else str(exc),
                StatusCode.ERR_CONNECTION_LOST if locally_closed else (
                    StatusCode.ERR_PIPE_FAILED
                    if phase == ErrorPhase.DIAL
                    else StatusCode.ERR_CONNECTION_LOST
                ),
                ErrorPhase.CLOSE if locally_closed else phase,
            )
        except (OSError, ValueError) as exc:
            failure = _engine_error(
                ErrorKind.DIAL if phase == ErrorPhase.DIAL else ErrorKind.HANDSHAKE,
                str(exc),
                StatusCode.ERR_PIPE_FAILED
                if phase == ErrorPhase.DIAL
                else StatusCode.ERR_CONNECTION_LOST,
                phase,
            )
        if stream is not None:
            stream.close()
        with self._state_lock:
            local_close = self._state == EngineState.CLOSING
            if self._candidate is stream:
                self._candidate = None
            self._state = EngineState.IDLE
        if not local_close:
            self._emit_pre_session_error(failure.info)
        raise failure

    def close(self) -> None:
        with self._state_lock:
            if self._state == EngineState.IDLE:
                return
            candidate = self._candidate
            session = self._session
            self._state = EngineState.CLOSING
            if session is not None:
                session.accepting_events = False
                session.close_requested.set()
                self._set_terminal(session, DisconnectReason.LOCAL_CLOSE)
        if candidate is not None:
            candidate.close()
        if session is None:
            return
        session.stream.close()
        deadline = time.monotonic() + _THREAD_JOIN_TIMEOUT
        alive: list[str] = []
        for worker in (
            session.reader_thread,
            session.maintenance_thread,
            session.dispatch_thread,
        ):
            if worker is None or worker is threading.current_thread():
                continue
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                alive.append(worker.name)
        with self._state_lock:
            if self._session is session:
                self._session = None
            self._state = EngineState.IDLE
        if alive:
            raise _engine_error(
                ErrorKind.TIMEOUT,
                f"workers did not stop before close deadline: {', '.join(alive)}",
                StatusCode.ERR_READ_TIMEOUT,
                ErrorPhase.CLOSE,
                session.view.epoch,
            )

    def send(self, channel: Channel, payload: Any) -> None:
        if channel not in (Channel.LOG, Channel.DATA):
            current = self.session
            raise _engine_error(
                ErrorKind.PROTOCOL,
                "engine applications may send only Log or Data",
                StatusCode.ERR_PROTOCOL_VIOLATION,
                ErrorPhase.APPLICATION_SEND,
                current.epoch if current is not None else None,
            )
        session = self._require_session()
        self._send_packet(session, channel, payload)

    def _respond(self, responder: _Responder, payload: Any) -> None:
        with self._state_lock:
            session = self._session
            live = (
                self._state == EngineState.CONNECTED
                and session is not None
                and session.view.epoch == responder._epoch
            )
        if not live or session is None:
            raise _engine_error(
                ErrorKind.STALE_EPOCH,
                "responder belongs to an earlier or closed epoch",
                StatusCode.ERR_CONNECTION_LOST,
                ErrorPhase.APPLICATION_SEND,
                responder._epoch,
            )
        if not session.view.capabilities & CAP_CORRELATION:
            raise _engine_error(
                ErrorKind.CAPABILITY,
                "correlation was not negotiated",
                StatusCode.ERR_PROTOCOL_VIOLATION,
                ErrorPhase.APPLICATION_SEND,
                responder._epoch,
            )
        self._send_packet(
            session, Channel.DATA, payload, correlation_id=responder._correlation_id
        )
        with session.data_lock:
            session.responders.discard(responder)

    def _snapshot_and_validate_config(self) -> EngineConfig:
        source = self._source_config
        try:
            config = EngineConfig(
                source.endpoint_name,
                source.token,
                tuple(source.supported_encodings),
                source.supported_capabilities,
                source.expected_go_pid,
                source.connect_timeout,
                source.application_queue_capacity,
                HeartbeatSettings(
                    source.heartbeat.disabled,
                    source.heartbeat.interval,
                    source.heartbeat.missed_interval_limit,
                ),
                FragmentationSettings(
                    source.fragmentation.timeout,
                    source.fragmentation.active_sequence_limit,
                ),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise _engine_error(
                ErrorKind.CONFIGURATION,
                f"invalid EngineConfig: {exc}",
                StatusCode.ERR_PROTOCOL_VIOLATION,
                ErrorPhase.CONFIGURATION,
            ) from exc
        cause = None
        if not valid_endpoint_name(config.endpoint_name):
            cause = "invalid endpoint_name"
        elif not valid_token(config.token):
            cause = "invalid token"
        elif not config.supported_encodings:
            cause = "supported_encodings must not be empty"
        elif any(
            encoding not in (Encoding.JSON, Encoding.MSGPACK)
            for encoding in config.supported_encodings
        ):
            cause = "supported_encodings contains an unknown value"
        elif len(set(config.supported_encodings)) != len(config.supported_encodings):
            cause = "supported_encodings contains a duplicate"
        elif (
            not isinstance(config.supported_capabilities, int)
            or isinstance(config.supported_capabilities, bool)
            or config.supported_capabilities < 0
            or config.supported_capabilities & ~IMPLEMENTED_CAPABILITIES
        ):
            cause = "supported_capabilities enables an unimplemented bit"
        elif config.expected_go_pid is not None and (
            not isinstance(config.expected_go_pid, int)
            or isinstance(config.expected_go_pid, bool)
            or not 0 <= config.expected_go_pid <= 0xFFFFFFFF
        ):
            cause = "expected_go_pid must be absent or a uint32"
        elif (
            not isinstance(config.connect_timeout, (int, float))
            or isinstance(config.connect_timeout, bool)
            or config.connect_timeout <= 0
        ):
            cause = "connect_timeout must be positive"
        elif (
            not isinstance(config.application_queue_capacity, int)
            or isinstance(config.application_queue_capacity, bool)
            or config.application_queue_capacity <= 0
        ):
            cause = "application_queue_capacity must be a positive integer"
        elif not config.heartbeat.disabled and (
            not isinstance(config.heartbeat.interval, (int, float))
            or isinstance(config.heartbeat.interval, bool)
            or config.heartbeat.interval <= 0
            or not isinstance(config.heartbeat.missed_interval_limit, int)
            or isinstance(config.heartbeat.missed_interval_limit, bool)
            or config.heartbeat.missed_interval_limit <= 0
        ):
            cause = "enabled heartbeat values must be positive"
        elif (
            not isinstance(config.fragmentation.timeout, (int, float))
            or isinstance(config.fragmentation.timeout, bool)
            or config.fragmentation.timeout <= 0
            or not isinstance(config.fragmentation.active_sequence_limit, int)
            or isinstance(config.fragmentation.active_sequence_limit, bool)
            or config.fragmentation.active_sequence_limit <= 0
        ):
            cause = "fragmentation values must be positive"
        if cause is not None:
            raise _engine_error(
                ErrorKind.CONFIGURATION,
                cause,
                StatusCode.ERR_PROTOCOL_VIOLATION,
                ErrorPhase.CONFIGURATION,
            )
        return config

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportTimeout("connect and handshake attempt timed out")
        return remaining

    def _start_session(self, session: _Session) -> None:
        epoch = session.view.epoch
        session.dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            args=(session,),
            name=f"yuumi-engine-dispatch-{epoch}",
            daemon=True,
        )
        session.reader_thread = threading.Thread(
            target=self._read_loop,
            args=(session,),
            name=f"yuumi-engine-reader-{epoch}",
            daemon=True,
        )
        session.maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            args=(session,),
            name=f"yuumi-engine-maintenance-{epoch}",
            daemon=True,
        )
        session.dispatch_thread.start()
        self._enqueue_application(
            session, _DispatchItem("connected", session.view, True)
        )
        session.reader_thread.start()
        session.maintenance_thread.start()

    def _read_loop(self, session: _Session) -> None:
        try:
            while not session.close_requested.is_set():
                header = session.stream.read_exact(6)
                length, raw_channel, flags = struct.unpack(">IBB", header)
                if length > MAX_MESSAGE_SIZE:
                    raise ProtocolFailure(
                        StatusCode.ERR_PAYLOAD_TOO_LARGE,
                        "frame payload exceeds 16 MiB",
                    )
                payload = session.stream.read_exact(length)
                session.last_activity = time.monotonic()
                self._process_frame(session, raw_channel, flags, payload)
        except ProtocolFailure as exc:
            self._protocol_failure(session, exc)
        except TransportClosed:
            pass
        except TransportTimeout as exc:
            if not session.close_requested.is_set():
                self._set_terminal(
                    session,
                    DisconnectReason.TRANSPORT_FAILURE,
                    _error(
                        ErrorKind.TIMEOUT,
                        str(exc),
                        StatusCode.ERR_READ_TIMEOUT,
                        ErrorPhase.FRAME_READ,
                        session.view.epoch,
                    ),
                )
                session.stream.close()
        except TransportFailure as exc:
            if not session.close_requested.is_set():
                self._set_terminal(
                    session,
                    DisconnectReason.TRANSPORT_FAILURE,
                    _error(
                        ErrorKind.TRANSPORT,
                        str(exc),
                        StatusCode.ERR_CONNECTION_LOST,
                        ErrorPhase.FRAME_READ,
                        session.view.epoch,
                    ),
                )
                session.stream.close()
        except Exception as exc:
            if not session.close_requested.is_set():
                self._set_terminal(
                    session,
                    DisconnectReason.TRANSPORT_FAILURE,
                    _error(
                        ErrorKind.INTERNAL,
                        str(exc),
                        StatusCode.ERR_INTERNAL,
                        ErrorPhase.FRAME_DECODE,
                        session.view.epoch,
                    ),
                )
                session.stream.close()
        finally:
            self._finalize(session)

    def _process_frame(
        self, session: _Session, raw_channel: int, flags: int, payload: bytes
    ) -> None:
        try:
            channel = Channel(raw_channel)
        except ValueError as exc:
            raise ProtocolFailure(
                StatusCode.ERR_PROTOCOL_VIOLATION, "frame channel is unknown"
            ) from exc
        if flags & ~KNOWN_FLAGS or (
            flags & FLAG_LAST_FRAGMENT and not flags & FLAG_FRAGMENT
        ):
            raise ProtocolFailure(
                StatusCode.ERR_PROTOCOL_VIOLATION, "frame flags are invalid"
            )
        if channel == Channel.LOG:
            raise ProtocolFailure(
                StatusCode.ERR_PROTOCOL_VIOLATION,
                "Log is not valid Go-to-engine traffic",
            )
        if channel == Channel.CONTROL:
            if flags != 0:
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "Control frames cannot carry application flags",
                )
            self._process_control(session, payload)
            return
        fragmented = bool(flags & FLAG_FRAGMENT)
        correlated = bool(flags & FLAG_CORRELATED)
        if correlated and not session.view.capabilities & CAP_CORRELATION:
            raise ProtocolFailure(
                StatusCode.ERR_PROTOCOL_VIOLATION,
                "correlation was not negotiated",
            )
        offset = 0
        fragment_id = None
        correlation_id = None
        if fragmented:
            if len(payload) < 4:
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "fragment prefix is shorter than four bytes",
                )
            fragment_id = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
        if correlated:
            if len(payload) - offset < 4:
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "correlation prefix is shorter than four bytes",
                )
            correlation_id = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
        data = payload[offset:]
        if fragmented:
            self._process_fragment(
                session, channel, flags, fragment_id, correlation_id, data
            )
            return
        with session.data_lock:
            if channel in session.fragments:
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "fragment sequences cannot be interleaved on one channel",
                    ErrorPhase.FRAGMENTATION,
                )
        self._deliver_message(
            session,
            channel,
            decode_payload(data, session.view.encoding),
            correlation_id,
        )

    def _process_fragment(
        self,
        session: _Session,
        channel: Channel,
        flags: int,
        fragment_id: int,
        correlation_id: int | None,
        data: bytes,
    ) -> None:
        complete = None
        with session.data_lock:
            fragment = session.fragments.get(channel)
            if fragment is None:
                if len(session.fragments) >= session.config.fragmentation.active_sequence_limit:
                    raise ProtocolFailure(
                        StatusCode.ERR_PROTOCOL_VIOLATION,
                        "active fragment-sequence limit exceeded",
                        ErrorPhase.FRAGMENTATION,
                    )
                fragment = _Fragment(
                    fragment_id,
                    correlation_id,
                    bytearray(),
                    time.monotonic() + session.config.fragmentation.timeout,
                )
                session.fragments[channel] = fragment
            elif (
                fragment.identifier != fragment_id
                or fragment.correlation_id != correlation_id
            ):
                session.fragments.pop(channel, None)
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "fragment sequence prefixes changed or interleaved",
                    ErrorPhase.FRAGMENTATION,
                )
            if len(fragment.data) > MAX_MESSAGE_SIZE - len(data):
                session.fragments.pop(channel, None)
                raise ProtocolFailure(
                    StatusCode.ERR_PAYLOAD_TOO_LARGE,
                    "reassembled message exceeds 16 MiB",
                    ErrorPhase.FRAGMENTATION,
                )
            fragment.data.extend(data)
            if flags & FLAG_LAST_FRAGMENT:
                complete = bytes(fragment.data)
                session.fragments.pop(channel, None)
        if complete is not None:
            self._deliver_message(
                session,
                channel,
                decode_payload(complete, session.view.encoding),
                correlation_id,
            )

    def _deliver_message(
        self,
        session: _Session,
        channel: Channel,
        payload: Any,
        correlation_id: int | None,
    ) -> None:
        responder = None
        if correlation_id is not None:
            responder = _Responder(self, session.view.epoch, correlation_id)
            with session.data_lock:
                session.responders.add(responder)
        event = MessageEvent(
            session.view, channel, payload, correlation_id, responder
        )
        self._enqueue_application(session, _DispatchItem("message", event, True))

    def _process_control(self, session: _Session, payload: bytes) -> None:
        value = decode_control(payload)
        control_type = value["type"]
        if control_type == "heartbeat":
            timestamp = value.get("ts")
            if not isinstance(timestamp, int) or isinstance(timestamp, bool):
                timestamp = int(time.time() * 1000)
            self._enqueue_application(
                session,
                _DispatchItem(
                    "heartbeat", HeartbeatEvent(session.view, timestamp), True
                ),
            )
        elif control_type == "ping":
            self._write_control(session, {"type": "pong", "seq": value.get("seq")})
        elif control_type == "error":
            try:
                status = StatusCode(value.get("code"))
            except (TypeError, ValueError) as exc:
                raise ProtocolFailure(
                    StatusCode.ERR_PROTOCOL_VIOLATION,
                    "Control error code is invalid",
                ) from exc
            cause = (
                value["message"]
                if isinstance(value.get("message"), str)
                else "Go peer reported a protocol error"
            )
            self._set_terminal(
                session,
                DisconnectReason.PROTOCOL_FAILURE,
                _error(
                    ErrorKind.PROTOCOL,
                    cause,
                    status,
                    ErrorPhase.FRAME_DECODE,
                    session.view.epoch,
                ),
            )
            session.close_requested.set()
            session.accepting_events = False
            session.stream.close()

    def _maintenance_loop(self, session: _Session) -> None:
        heartbeat = session.config.heartbeat
        period = min(
            0.05,
            session.config.fragmentation.timeout,
            0.05 if heartbeat.disabled else heartbeat.interval,
        )
        period = max(0.001, period)
        while not session.close_requested.wait(period):
            now = time.monotonic()
            expired = 0
            with session.data_lock:
                for channel, fragment in list(session.fragments.items()):
                    if fragment.deadline <= now:
                        session.fragments.pop(channel, None)
                        expired += 1
            for _ in range(expired):
                self._enqueue_application(
                    session,
                    _DispatchItem(
                        "error",
                        _error(
                            ErrorKind.TIMEOUT,
                            "incomplete fragment sequence expired",
                            StatusCode.ERR_FRAGMENT_TIMEOUT,
                            ErrorPhase.FRAGMENTATION,
                            session.view.epoch,
                        ),
                        True,
                    ),
                )
            if heartbeat.disabled:
                continue
            if now - session.last_activity >= (
                heartbeat.interval * heartbeat.missed_interval_limit
            ):
                self._set_terminal(
                    session,
                    DisconnectReason.HEARTBEAT_TIMEOUT,
                    _error(
                        ErrorKind.TIMEOUT,
                        "session heartbeat deadline expired",
                        StatusCode.ERR_READ_TIMEOUT,
                        ErrorPhase.HEARTBEAT,
                        session.view.epoch,
                    ),
                )
                session.close_requested.set()
                session.accepting_events = False
                session.stream.close()
                return
            if now - session.last_heartbeat >= heartbeat.interval:
                session.last_heartbeat = now
                try:
                    self._write_control(
                        session,
                        {"type": "heartbeat", "ts": int(time.time() * 1000)},
                    )
                except EngineError as exc:
                    self._set_terminal(
                        session, DisconnectReason.TRANSPORT_FAILURE, exc.info
                    )
                    session.close_requested.set()
                    session.accepting_events = False
                    session.stream.close()
                    return

    def _require_session(self) -> _Session:
        with self._state_lock:
            session = self._session
            valid = (
                self._state == EngineState.CONNECTED
                and session is not None
                and not session.close_requested.is_set()
                and not session.finalized
            )
        if not valid or session is None:
            raise _engine_error(
                ErrorKind.SESSION_CLOSED,
                "engine has no live session",
                StatusCode.ERR_CONNECTION_LOST,
                ErrorPhase.APPLICATION_SEND,
                None if session is None else session.view.epoch,
            )
        return session

    def _send_packet(
        self,
        session: _Session,
        channel: Channel,
        payload: Any,
        correlation_id: int | None = None,
    ) -> None:
        with self._state_lock:
            live = (
                self._session is session
                and self._state == EngineState.CONNECTED
                and not session.close_requested.is_set()
                and not session.finalized
            )
        if not live:
            raise _engine_error(
                ErrorKind.STALE_EPOCH,
                "operation belongs to an earlier or closed epoch",
                StatusCode.ERR_CONNECTION_LOST,
                ErrorPhase.APPLICATION_SEND,
                session.view.epoch,
            )
        try:
            encoded = encode_payload(payload, session.view.encoding)
            prefix = b"" if correlation_id is None else struct.pack(">I", correlation_id)
            if len(encoded) > MAX_MESSAGE_SIZE - len(prefix):
                raise ProtocolFailure(
                    StatusCode.ERR_PAYLOAD_TOO_LARGE,
                    "encoded frame exceeds 16 MiB",
                    ErrorPhase.APPLICATION_SEND,
                )
            packet = build_frame(
                channel,
                0 if correlation_id is None else FLAG_CORRELATED,
                prefix + encoded,
            )
        except ProtocolFailure as exc:
            raise _engine_error(
                ErrorKind.ENCODING
                if exc.status == StatusCode.ERR_ENCODING_UNSUPPORTED
                else ErrorKind.PROTOCOL,
                exc.cause,
                exc.status,
                exc.phase,
                session.view.epoch,
            ) from exc
        with session.send_lock:
            if session.close_requested.is_set() or session.finalized:
                raise _engine_error(
                    ErrorKind.STALE_EPOCH,
                    "operation belongs to an earlier or closed epoch",
                    StatusCode.ERR_CONNECTION_LOST,
                    ErrorPhase.APPLICATION_SEND,
                    session.view.epoch,
                )
            try:
                session.stream.write_all(packet)
            except (TransportClosed, TransportFailure) as exc:
                failure = _error(
                    ErrorKind.TRANSPORT,
                    str(exc),
                    StatusCode.ERR_WRITE_FAILED,
                    ErrorPhase.FRAME_WRITE,
                    session.view.epoch,
                )
                self._set_terminal(
                    session, DisconnectReason.TRANSPORT_FAILURE, failure
                )
                session.close_requested.set()
                session.accepting_events = False
                session.stream.close()
                raise EngineError(failure) from exc

    def _write_control(self, session: _Session, value: dict[str, Any]) -> None:
        packet = build_control_frame(value)
        with session.send_lock:
            if session.finalized:
                raise _engine_error(
                    ErrorKind.STALE_EPOCH,
                    "operation belongs to an earlier or closed epoch",
                    StatusCode.ERR_CONNECTION_LOST,
                    ErrorPhase.FRAME_WRITE,
                    session.view.epoch,
                )
            try:
                session.stream.write_all(packet)
            except (TransportClosed, TransportFailure) as exc:
                raise _engine_error(
                    ErrorKind.TRANSPORT,
                    str(exc),
                    StatusCode.ERR_WRITE_FAILED,
                    ErrorPhase.FRAME_WRITE,
                    session.view.epoch,
                ) from exc

    def _protocol_failure(
        self, session: _Session, failure: ProtocolFailure
    ) -> None:
        self._set_terminal(
            session,
            DisconnectReason.PROTOCOL_FAILURE,
            _error(
                ErrorKind.PROTOCOL,
                failure.cause,
                failure.status,
                failure.phase,
                session.view.epoch,
            ),
        )
        session.close_requested.set()
        session.accepting_events = False
        try:
            self._write_control(
                session,
                {
                    "type": "error",
                    "code": int(failure.status),
                    "message": failure.cause,
                },
            )
        except EngineError:
            pass
        session.stream.close()

    def _set_terminal(
        self,
        session: _Session,
        reason: DisconnectReason,
        failure: ErrorInfo | None = None,
    ) -> None:
        with session.data_lock:
            if (
                session.terminal.error is not None
                or session.terminal.reason != DisconnectReason.PEER_CLOSE
            ):
                return
            session.terminal = TerminalResult(reason, failure)

    def _enqueue_application(
        self, session: _Session, item: _DispatchItem
    ) -> bool:
        overflow = False
        with session.event_condition:
            if not session.accepting_events or session.finalized:
                return False
            if (
                item.uses_capacity
                and session.capacity_used
                >= session.config.application_queue_capacity
            ):
                session.accepting_events = False
                session.close_requested.set()
                overflow = True
            else:
                session.events.append(item)
                if item.uses_capacity:
                    session.capacity_used += 1
                session.event_condition.notify()
        if overflow:
            self._set_terminal(
                session,
                DisconnectReason.BACKPRESSURE,
                _error(
                    ErrorKind.BACKPRESSURE,
                    "application queue capacity exhausted",
                    StatusCode.ERR_INTERNAL,
                    ErrorPhase.APPLICATION_DISPATCH,
                    session.view.epoch,
                ),
            )
            session.stream.close()
            return False
        return True

    @staticmethod
    def _enqueue_terminal(session: _Session, item: _DispatchItem) -> None:
        with session.event_condition:
            session.events.append(item)
            session.event_condition.notify()

    def _dispatch_loop(self, session: _Session) -> None:
        while True:
            with session.event_condition:
                while not session.events and not session.transport_finalized:
                    session.event_condition.wait()
                if not session.events and session.transport_finalized:
                    return
                item = session.events.popleft()
            try:
                handler = self._handler_for(item.kind)
                if handler is not None:
                    result = handler(item.value)
                    if inspect.isawaitable(result):
                        close = getattr(result, "close", None)
                        if close is not None:
                            close()
                        raise TypeError(
                            "Python Engine callbacks must be synchronous callables"
                        )
            except BaseException as exc:
                if item.kind in ("error", "disconnected"):
                    self._report_uncaught(exc)
                else:
                    self._enqueue_terminal(
                        session,
                        _DispatchItem(
                            "error",
                            _error(
                                ErrorKind.APPLICATION,
                                str(exc),
                                StatusCode.ERR_INTERNAL,
                                ErrorPhase.APPLICATION_DISPATCH,
                                session.view.epoch,
                            ),
                            False,
                        ),
                    )
            finally:
                if item.uses_capacity:
                    with session.event_condition:
                        session.capacity_used -= 1

    def _handler_for(self, kind: str):
        with self._handlers_lock:
            return {
                "connected": self._connected_handler,
                "message": self._message_handler,
                "heartbeat": self._heartbeat_handler,
                "error": self._error_handler,
                "disconnected": self._disconnected_handler,
            }[kind]

    def _emit_pre_session_error(self, failure: ErrorInfo) -> None:
        handler = self._handler_for("error")
        if handler is None:
            return
        try:
            result = handler(failure)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if close is not None:
                    close()
                raise TypeError("Python Engine callbacks must be synchronous callables")
        except BaseException as exc:
            self._report_uncaught(exc)

    @staticmethod
    def _report_uncaught(exc: BaseException) -> None:
        arguments = threading.ExceptHookArgs(
            (type(exc), exc, exc.__traceback__, threading.current_thread())
        )
        threading.excepthook(arguments)

    def _finalize(self, session: _Session) -> None:
        with session.finalize_lock:
            if session.finalized:
                return
            session.finalized = True
            session.accepting_events = False
            session.close_requested.set()
            session.stream.close()
            with session.data_lock:
                session.fragments.clear()
                for responder in session.responders:
                    responder.invalidate()
                session.responders.clear()
            with self._state_lock:
                if self._session is session:
                    self._session = None
                self._terminal_result = session.terminal
                if self._state != EngineState.CLOSING:
                    self._state = EngineState.IDLE
            if session.terminal.error is not None:
                self._enqueue_terminal(
                    session,
                    _DispatchItem("error", session.terminal.error, False),
                )
            self._enqueue_terminal(
                session,
                _DispatchItem(
                    "disconnected",
                    DisconnectEvent(session.view, session.terminal),
                    False,
                ),
            )
            with session.event_condition:
                session.transport_finalized = True
                session.event_condition.notify_all()


"""
The reader parses frames and answers Control traffic, the maintenance worker
owns heartbeat and fragment deadlines, and one dispatcher invokes application
callbacks in order. The bounded queue counts callbacks that are queued or
currently running; two terminal events bypass that capacity so backpressure is
always observable before disconnection. Stream.close unblocks I/O and every
worker observes close_requested before close joins it.
"""
