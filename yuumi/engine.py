from __future__ import annotations

import copy
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
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
    error,
)
from .transport import (
    Stream,
    TransportClosed,
    TransportFailure,
    create_listener,
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
    ErrorCategory,
    ErrorInfo,
    ErrorPhase,
    MessageEvent,
    SessionHandle,
    SessionView,
    StatusCode,
)

ConnectedHandler = Callable[[SessionView], None]
MessageHandler = Callable[[MessageEvent], None]
ErrorHandler = Callable[[ErrorInfo], None]
DisconnectedHandler = Callable[[DisconnectEvent], None]


@dataclass
class _Fragment:
    fragment_id: int
    correlation_id: int | None
    data: bytearray
    deadline: float


class _PendingCorrelations:
    def __init__(self) -> None:
        self._identifiers: set[int] = set()
        self._lock = threading.Lock()

    def begin(self, identifier: int) -> bool:
        with self._lock:
            if identifier in self._identifiers:
                return False
            self._identifiers.add(identifier)
            return True

    def finish(self, identifier: int) -> bool:
        with self._lock:
            if identifier not in self._identifiers:
                return False
            self._identifiers.remove(identifier)
            return True

    def clear(self) -> None:
        with self._lock:
            self._identifiers.clear()


@dataclass(eq=False)
class _Session:
    stream: Stream
    encoding: Encoding = Encoding.MSGPACK
    capabilities: int = 0
    handle: SessionHandle | None = None
    established: bool = False
    close_reason: DisconnectReason = DisconnectReason.PEER_CLOSE
    close_requested: threading.Event = field(default_factory=threading.Event)
    terminal_reported: threading.Event = field(default_factory=threading.Event)
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    event_lock: threading.Lock = field(default_factory=threading.Lock)
    fragment_lock: threading.Lock = field(default_factory=threading.Lock)
    fragments: dict[Channel, _Fragment] = field(default_factory=dict)
    pending_correlations: _PendingCorrelations = field(default_factory=_PendingCorrelations)
    last_activity: float = field(default_factory=time.monotonic)
    last_heartbeat: float = field(default_factory=time.monotonic)


class Engine:
    """Engine-side Yuumi endpoint.

    Callbacks execute synchronously on an explicit daemon session worker, or on
    the maintenance worker for timer events. Events are serialized per session;
    separate sessions may execute concurrently. Sequential same-session sends
    preserve submission order, while concurrent sends follow lock acquisition.
    """

    def __init__(self, config: EngineConfig) -> None:
        self._config = copy.deepcopy(config)
        self._lifecycle_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._handlers_lock = threading.Lock()
        self._workers_lock = threading.Lock()
        self._callback_local = threading.local()
        self._closed_event = threading.Event()
        self._closed_event.set()
        self._opened = False
        self._closing = False
        self._listener = None
        self._address: str | None = None
        self._connections: set[_Session] = set()
        self._sessions: dict[str, _Session] = {}
        self._workers: set[threading.Thread] = set()
        self._accept_thread: threading.Thread | None = None
        self._maintenance_thread: threading.Thread | None = None
        self._next_epoch = 0
        self._connected_handler: ConnectedHandler | None = None
        self._message_handler: MessageHandler | None = None
        self._error_handler: ErrorHandler | None = None
        self._disconnected_handler: DisconnectedHandler | None = None

    def on_session_connected(self, handler: ConnectedHandler | None) -> None:
        with self._handlers_lock:
            self._connected_handler = handler

    def on_message(self, handler: MessageHandler | None) -> None:
        with self._handlers_lock:
            self._message_handler = handler

    def on_error(self, handler: ErrorHandler | None) -> None:
        with self._handlers_lock:
            self._error_handler = handler

    def on_session_disconnected(self, handler: DisconnectedHandler | None) -> None:
        with self._handlers_lock:
            self._disconnected_handler = handler

    def open(self) -> None:
        with self._lifecycle_lock:
            if self._opened or self._closing:
                raise EngineError(error(ErrorCategory.ENDPOINT, StatusCode.ERR_PIPE_FAILED, ErrorPhase.ENDPOINT_OPEN, "engine is already open or changing state"))
            self._validate_config()
            try:
                address = resolve_transport_address(self._config.endpoint_name, self._config.token)
            except ValueError as exc:
                raise EngineError(error(ErrorCategory.CONFIGURATION, StatusCode.ERR_PIPE_FAILED, ErrorPhase.CONFIGURATION, str(exc))) from exc
            listener = create_listener()
            try:
                listener.open(address)
            except TransportFailure as exc:
                raise EngineError(error(ErrorCategory.ENDPOINT, StatusCode.ERR_PIPE_FAILED, ErrorPhase.ENDPOINT_OPEN, str(exc))) from exc
            self._listener = listener
            self._address = address
            self._opened = True
            self._closing = False
            self._closed_event.clear()
            self._accept_thread = threading.Thread(target=self._accept_loop, name="yuumi-engine-accept", daemon=True)
            self._maintenance_thread = threading.Thread(target=self._maintenance_loop, name="yuumi-engine-maintenance", daemon=True)
            self._accept_thread.start()
            self._maintenance_thread.start()

    def close(self) -> None:
        if getattr(self._callback_local, "active", False):
            raise EngineError(error(ErrorCategory.INTERNAL, StatusCode.ERR_INTERNAL, ErrorPhase.CLOSE, "close cannot run synchronously from an Engine callback"))
        with self._lifecycle_lock:
            if not self._opened and not self._closing:
                return
            if self._closing:
                wait_for_close = True
            else:
                wait_for_close = False
                self._closing = True
                self._opened = False
                listener, self._listener = self._listener, None
        if wait_for_close:
            self._closed_event.wait()
            return
        if listener is not None:
            listener.close()
        with self._state_lock:
            active = list(self._connections)
        for session in active:
            self._request_close(session, DisconnectReason.ENGINE_CLOSE)
        current = threading.current_thread()
        for thread in (self._accept_thread, self._maintenance_thread):
            if thread is not None and thread is not current:
                thread.join()
        while True:
            with self._workers_lock:
                workers = [worker for worker in self._workers if worker is not current]
            if not workers:
                break
            for worker in workers:
                worker.join()
            if all(not worker.is_alive() for worker in workers):
                break
        with self._state_lock:
            self._connections.clear()
            self._sessions.clear()
        with self._lifecycle_lock:
            self._closing = False
            self._address = None
            self._accept_thread = None
            self._maintenance_thread = None
            self._closed_event.set()

    def send(self, session: SessionHandle, channel: Channel, payload: Any) -> None:
        self._send(session, channel, payload, None)

    def send_correlated(self, session: SessionHandle, channel: Channel, correlation_id: int, payload: Any) -> None:
        if not isinstance(correlation_id, int) or isinstance(correlation_id, bool) or not 0 <= correlation_id <= 0xFFFFFFFF:
            raise EngineError(error(ErrorCategory.SESSION, StatusCode.ERR_PROTOCOL_VIOLATION, ErrorPhase.APPLICATION_SEND, "correlation_id must be a uint32", session))
        self._send(session, channel, payload, correlation_id)

    def _validate_config(self) -> None:
        config = self._config
        cause = None
        if not valid_endpoint_name(config.endpoint_name):
            cause = "invalid endpoint_name"
        elif not valid_token(config.token):
            cause = "invalid token"
        elif not isinstance(config.max_sessions, int) or isinstance(config.max_sessions, bool) or config.max_sessions <= 0:
            cause = "max_sessions must be an integer greater than zero"
        else:
            try:
                encodings = tuple(config.supported_encodings)
            except TypeError:
                encodings = ()
            if not encodings:
                cause = "supported_encodings must not be empty"
            elif any(encoding not in (Encoding.JSON, Encoding.MSGPACK) for encoding in encodings):
                cause = "supported_encodings contains an unknown value"
            elif len(set(encodings)) != len(encodings):
                cause = "supported_encodings contains a duplicate"
        if cause is None and (not isinstance(config.supported_capabilities, int) or isinstance(config.supported_capabilities, bool) or config.supported_capabilities < 0 or config.supported_capabilities & ~IMPLEMENTED_CAPABILITIES):
            cause = "supported_capabilities enables an unimplemented bit"
        if cause is None and config.expected_pid is not None and (not isinstance(config.expected_pid, int) or isinstance(config.expected_pid, bool) or not 0 <= config.expected_pid <= 0xFFFFFFFF):
            cause = "expected_pid must be absent or a uint32"
        heartbeat = config.heartbeat
        if cause is None and not heartbeat.disabled and (not isinstance(heartbeat.interval, (int, float)) or isinstance(heartbeat.interval, bool) or heartbeat.interval <= 0 or not isinstance(heartbeat.missed_interval_limit, int) or isinstance(heartbeat.missed_interval_limit, bool) or heartbeat.missed_interval_limit <= 0):
            cause = "enabled heartbeat values must be positive"
        fragmentation = config.fragmentation
        if cause is None and (not isinstance(fragmentation.timeout, (int, float)) or isinstance(fragmentation.timeout, bool) or fragmentation.timeout <= 0 or not isinstance(fragmentation.active_sequence_limit, int) or isinstance(fragmentation.active_sequence_limit, bool) or fragmentation.active_sequence_limit <= 0):
            cause = "fragmentation values must be positive"
        if cause is not None:
            raise EngineError(error(ErrorCategory.CONFIGURATION, StatusCode.ERR_PROTOCOL_VIOLATION, ErrorPhase.CONFIGURATION, cause))

    def _accept_loop(self) -> None:
        while self._opened:
            listener = self._listener
            if listener is None:
                return
            try:
                stream = listener.accept()
            except TransportClosed:
                return
            except TransportFailure as exc:
                if self._opened:
                    self._emit_error(error(ErrorCategory.ENDPOINT, StatusCode.ERR_PIPE_FAILED, ErrorPhase.ACCEPT, str(exc)))
                continue
            session = _Session(stream)
            with self._state_lock:
                admitted = len(self._connections) < self._config.max_sessions
                if admitted:
                    self._connections.add(session)
            if not admitted:
                stream.close()
                continue
            worker = threading.Thread(target=self._session_worker, args=(session,), name="yuumi-engine-session", daemon=True)
            with self._workers_lock:
                self._workers.add(worker)
            worker.start()

    def _session_worker(self, session: _Session) -> None:
        try:
            try:
                if not self._handshake(session):
                    return
                self._read_loop(session)
            finally:
                session.stream.close()
                with self._state_lock:
                    self._connections.discard(session)
                    if session.handle is not None:
                        self._sessions.pop(session.handle.session_id, None)
                    session.fragments.clear()
                    session.pending_correlations.clear()
                if session.established and session.handle is not None:
                    self._emit_disconnected(session)
        finally:
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def _handshake(self, session: _Session) -> bool:
        try:
            packet = session.stream.read_exact(16)
        except (TransportClosed, TransportFailure) as exc:
            self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_CONNECTION_LOST, ErrorPhase.HANDSHAKE_READ, str(exc)))
            return False
        magic, version, pid, encoding_mask = struct.unpack(">IIIB", packet[:13])
        client_capabilities = int.from_bytes(packet[13:16], "big")
        if magic != MAGIC:
            self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_MAGIC_MISMATCH, ErrorPhase.HANDSHAKE_VALIDATE, "handshake magic is invalid"))
            return False
        if version != PROTOCOL_VERSION:
            self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_VERSION_MISMATCH, ErrorPhase.HANDSHAKE_VALIDATE, "handshake protocol version is incompatible"))
            return False
        expected_pid = self._config.expected_pid
        if expected_pid is not None:
            try:
                peer_pid = session.stream.peer_pid()
            except TransportFailure as exc:
                self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_PIPE_FAILED, ErrorPhase.HANDSHAKE_VALIDATE, str(exc)))
                return False
            if pid != expected_pid or (peer_pid is not None and peer_pid != expected_pid):
                self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_PID_MISMATCH, ErrorPhase.HANDSHAKE_VALIDATE, "client PID does not match expected_pid"))
                return False
        selected = next((encoding for encoding in self._config.supported_encodings if encoding_mask & int(encoding)), None)
        if selected is None:
            self._emit_error(error(ErrorCategory.HANDSHAKE, StatusCode.ERR_ENCODING_UNSUPPORTED, ErrorPhase.HANDSHAKE_VALIDATE, "no common encoding exists"))
            return False
        capabilities = client_capabilities & self._config.supported_capabilities & IMPLEMENTED_CAPABILITIES
        try:
            session.stream.write_all(bytes([int(selected)]) + capabilities.to_bytes(3, "big"))
        except (TransportClosed, TransportFailure) as exc:
            self._emit_error(error(ErrorCategory.TRANSPORT, StatusCode.ERR_WRITE_FAILED, ErrorPhase.ACK_WRITE, str(exc)))
            return False
        session_id = uuid.uuid4().hex
        try:
            session.stream.write_all(build_control_frame({"type": "session", "session_id": session_id}))
        except (TransportClosed, TransportFailure, ProtocolFailure) as exc:
            self._emit_error(error(ErrorCategory.TRANSPORT, StatusCode.ERR_WRITE_FAILED, ErrorPhase.SESSION_WRITE, str(exc)))
            return False
        with self._state_lock:
            if not self._opened or session.close_requested.is_set():
                return False
            session.handle = SessionHandle(session_id, self._next_epoch)
            self._next_epoch += 1
            session.encoding = selected
            session.capabilities = capabilities
            session.established = True
            session.last_activity = time.monotonic()
            session.last_heartbeat = session.last_activity
            self._sessions[session_id] = session
        self._emit_connected(session)
        return True

    def _read_loop(self, session: _Session) -> None:
        while not session.close_requested.is_set():
            try:
                header = session.stream.read_exact(6)
                length, raw_channel, flags = struct.unpack(">IBB", header)
                if length > MAX_MESSAGE_SIZE:
                    raise ProtocolFailure(StatusCode.ERR_PAYLOAD_TOO_LARGE, "frame payload exceeds 16 MiB")
                payload = session.stream.read_exact(length)
                session.last_activity = time.monotonic()
                self._process_frame(session, raw_channel, flags, payload)
            except ProtocolFailure as exc:
                self._protocol_failure(session, exc.status, exc.cause, exc.phase)
                return
            except TransportClosed:
                return
            except TransportFailure as exc:
                if not session.close_requested.is_set():
                    self._report_terminal(session, error(ErrorCategory.TRANSPORT, StatusCode.ERR_CONNECTION_LOST, ErrorPhase.FRAME_READ, str(exc), session.handle))
                    self._request_close(session, DisconnectReason.TRANSPORT_FAILURE)
                return

    def _process_frame(self, session: _Session, raw_channel: int, flags: int, payload: bytes) -> None:
        try:
            channel = Channel(raw_channel)
        except ValueError as exc:
            raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "frame channel is unknown") from exc
        if flags & ~KNOWN_FLAGS or flags & FLAG_LAST_FRAGMENT and not flags & FLAG_FRAGMENT:
            raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "frame flags are invalid")
        if channel == Channel.LOG:
            raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "Log is not valid client-to-engine traffic")
        if channel == Channel.CONTROL:
            if flags != 0:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "Control frames cannot carry application flags")
            self._process_control(session, payload)
            return
        correlated = bool(flags & FLAG_CORRELATED)
        fragmented = bool(flags & FLAG_FRAGMENT)
        if correlated and not session.capabilities & CAP_CORRELATION:
            raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "correlation was not negotiated")
        offset = 0
        fragment_id = None
        correlation_id = None
        if fragmented:
            if len(payload) < 4:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "fragment prefix is shorter than four bytes")
            fragment_id = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
        if correlated:
            if len(payload) - offset < 4:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "correlation prefix is shorter than four bytes")
            correlation_id = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
        data = payload[offset:]
        if fragmented:
            self._process_fragment(session, channel, flags, fragment_id, correlation_id, data)
            return
        with session.fragment_lock:
            if channel in session.fragments:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "fragment sequences cannot be interleaved on one channel")
        decoded = decode_payload(data, session.encoding)
        self._emit_message(session, MessageEvent(session.handle, channel, decoded, correlation_id))

    def _process_fragment(self, session: _Session, channel: Channel, flags: int, fragment_id: int, correlation_id: int | None, data: bytes) -> None:
        complete = None
        with session.fragment_lock:
            fragment = session.fragments.get(channel)
            if fragment is None:
                if len(session.fragments) >= self._config.fragmentation.active_sequence_limit:
                    raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "active fragment-sequence limit exceeded", ErrorPhase.FRAGMENTATION)
                fragment = _Fragment(fragment_id, correlation_id, bytearray(), time.monotonic() + self._config.fragmentation.timeout)
                session.fragments[channel] = fragment
            elif fragment.fragment_id != fragment_id or fragment.correlation_id != correlation_id:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "fragment sequence prefixes changed or interleaved", ErrorPhase.FRAGMENTATION)
            if len(fragment.data) + len(data) > MAX_MESSAGE_SIZE:
                session.fragments.pop(channel, None)
                raise ProtocolFailure(StatusCode.ERR_PAYLOAD_TOO_LARGE, "reassembled message exceeds 16 MiB", ErrorPhase.FRAGMENTATION)
            fragment.data.extend(data)
            if flags & FLAG_LAST_FRAGMENT:
                complete = bytes(fragment.data)
                session.fragments.pop(channel, None)
        if complete is not None:
            decoded = decode_payload(complete, session.encoding)
            self._emit_message(session, MessageEvent(session.handle, channel, decoded, correlation_id))

    def _process_control(self, session: _Session, payload: bytes) -> None:
        value = decode_control(payload)
        control_type = value["type"]
        if control_type == "ping":
            self._write_control(session, {"type": "pong", "seq": value.get("seq")})
        elif control_type == "error":
            raw_status = value.get("code")
            try:
                status = StatusCode(raw_status)
            except (TypeError, ValueError) as exc:
                raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "Control error code is invalid") from exc
            cause = value.get("message") if isinstance(value.get("message"), str) else "peer reported a protocol error"
            self._report_terminal(session, error(ErrorCategory.PROTOCOL, status, ErrorPhase.FRAME_DECODE, cause, session.handle))
            self._request_close(session, DisconnectReason.PROTOCOL_FAILURE)

    def _maintenance_loop(self) -> None:
        while self._opened:
            time.sleep(0.05)
            now = time.monotonic()
            with self._state_lock:
                sessions = list(self._sessions.values())
            for session in sessions:
                if session.close_requested.is_set():
                    continue
                expired = 0
                with session.fragment_lock:
                    for channel, fragment in list(session.fragments.items()):
                        if fragment.deadline <= now:
                            session.fragments.pop(channel, None)
                            expired += 1
                for _ in range(expired):
                    self._emit_session_error(session, error(ErrorCategory.PROTOCOL, StatusCode.ERR_FRAGMENT_TIMEOUT, ErrorPhase.FRAGMENTATION, "incomplete fragment sequence expired", session.handle))
                heartbeat = self._config.heartbeat
                if heartbeat.disabled:
                    continue
                if now - session.last_activity >= heartbeat.interval * heartbeat.missed_interval_limit:
                    self._report_terminal(session, error(ErrorCategory.TRANSPORT, StatusCode.ERR_READ_TIMEOUT, ErrorPhase.HEARTBEAT, "session heartbeat deadline expired", session.handle))
                    self._request_close(session, DisconnectReason.HEARTBEAT_TIMEOUT)
                elif now - session.last_heartbeat >= heartbeat.interval:
                    try:
                        self._write_control(session, {"type": "heartbeat", "ts": int(time.time() * 1000)})
                        session.last_heartbeat = now
                    except EngineError as exc:
                        self._report_terminal(session, exc.info)
                        self._request_close(session, DisconnectReason.TRANSPORT_FAILURE)

    def _send(self, handle: SessionHandle, channel: Channel, payload: Any, correlation_id: int | None) -> None:
        if channel not in (Channel.LOG, Channel.DATA):
            raise EngineError(error(ErrorCategory.SESSION, StatusCode.ERR_PROTOCOL_VIOLATION, ErrorPhase.APPLICATION_SEND, "engine applications may send only Log or Data", handle))
        with self._state_lock:
            session = self._sessions.get(handle.session_id) if isinstance(handle, SessionHandle) else None
            if session is None or session.handle != handle or session.close_requested.is_set():
                session = None
        if session is None:
            raise EngineError(error(ErrorCategory.SESSION, StatusCode.ERR_CONNECTION_LOST, ErrorPhase.APPLICATION_SEND, "session handle is absent, closed, or stale", handle if isinstance(handle, SessionHandle) else None))
        if correlation_id is not None and not session.capabilities & CAP_CORRELATION:
            raise EngineError(error(ErrorCategory.SESSION, StatusCode.ERR_PROTOCOL_VIOLATION, ErrorPhase.APPLICATION_SEND, "correlation was not negotiated", handle))
        try:
            encoded = encode_payload(payload, session.encoding)
            prefix = struct.pack(">I", correlation_id) if correlation_id is not None else b""
            if len(encoded) > MAX_MESSAGE_SIZE - len(prefix):
                raise ProtocolFailure(StatusCode.ERR_PAYLOAD_TOO_LARGE, "encoded frame exceeds 16 MiB", ErrorPhase.APPLICATION_SEND)
            packet = build_frame(channel, FLAG_CORRELATED if correlation_id is not None else 0, prefix + encoded)
        except ProtocolFailure as exc:
            raise EngineError(error(ErrorCategory.SERIALIZATION, exc.status, exc.phase, exc.cause, handle)) from exc
        self._write_packet(session, packet, ErrorPhase.FRAME_WRITE)

    def _write_control(self, session: _Session, value: dict[str, Any]) -> None:
        self._write_packet(session, build_control_frame(value), ErrorPhase.FRAME_WRITE)

    def _write_packet(self, session: _Session, packet: bytes, phase: ErrorPhase) -> None:
        with session.send_lock:
            if session.close_requested.is_set():
                raise EngineError(error(ErrorCategory.SESSION, StatusCode.ERR_CONNECTION_LOST, phase, "session is closing", session.handle))
            try:
                session.stream.write_all(packet)
            except (TransportClosed, TransportFailure) as exc:
                failure = error(ErrorCategory.TRANSPORT, StatusCode.ERR_WRITE_FAILED, phase, str(exc), session.handle)
                self._report_terminal(session, failure)
                self._request_close(session, DisconnectReason.TRANSPORT_FAILURE)
                raise EngineError(failure) from exc

    def _protocol_failure(self, session: _Session, status: StatusCode, cause: str, phase: ErrorPhase) -> None:
        self._report_terminal(session, error(ErrorCategory.PROTOCOL, status, phase, cause, session.handle))
        try:
            self._write_control(session, {"type": "error", "code": int(status), "message": cause})
        except EngineError:
            pass
        self._request_close(session, DisconnectReason.PROTOCOL_FAILURE)

    def _request_close(self, session: _Session, reason: DisconnectReason) -> None:
        if not session.close_requested.is_set():
            session.close_reason = reason
            session.close_requested.set()
            session.stream.close()

    def _report_terminal(self, session: _Session, failure: ErrorInfo) -> None:
        if not session.terminal_reported.is_set():
            session.terminal_reported.set()
            self._emit_session_error(session, failure)

    def _handler(self, name: str):
        with self._handlers_lock:
            return getattr(self, name)

    def _invoke(self, handler, value) -> None:
        if handler is None:
            return
        self._callback_local.active = True
        try:
            handler(value)
        finally:
            self._callback_local.active = False

    def _emit_connected(self, session: _Session) -> None:
        with session.event_lock:
            self._invoke(self._handler("_connected_handler"), SessionView(session.handle, session.encoding, session.capabilities))

    def _emit_message(self, session: _Session, event: MessageEvent) -> None:
        with session.event_lock:
            self._invoke(self._handler("_message_handler"), event)

    def _emit_error(self, failure: ErrorInfo) -> None:
        self._invoke(self._handler("_error_handler"), failure)

    def _emit_session_error(self, session: _Session, failure: ErrorInfo) -> None:
        with session.event_lock:
            self._emit_error(failure)

    def _emit_disconnected(self, session: _Session) -> None:
        with session.event_lock:
            self._invoke(self._handler("_disconnected_handler"), DisconnectEvent(session.handle, session.close_reason))


"""
Engine callbacks execute synchronously on the session worker that produced the
event; timer-generated errors execute on the maintenance worker. Events for one
session are serialized by a per-session lock, while separate sessions may run
callbacks concurrently. Sequential sends to one session are serialized by its
write lock; concurrent sends follow lock-acquisition order. Every SDK-owned
thread is explicitly daemonized, and close waits for owned workers to finish.
"""
