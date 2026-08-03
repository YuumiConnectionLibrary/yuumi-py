from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
from typing import Any, Protocol

MAGIC = 0x59554D49
PROTOCOL_VERSION = 1
CAP_CORRELATION = 0x000001
IMPLEMENTED_CAPABILITIES = CAP_CORRELATION
MAX_MESSAGE_SIZE = 16 * 1024 * 1024


class Encoding(IntFlag):
    JSON = 0x01
    MSGPACK = 0x02


class Channel(IntEnum):
    CONTROL = 0x00
    COMMAND = 0x01
    LOG = 0x02
    DATA = 0x03


class StatusCode(IntEnum):
    HANDSHAKE_START = 100
    CONNECTING = 101
    OK_CONNECTED = 200
    OK_MESSAGE_RECEIVED = 201
    OK_HEARTBEAT = 202
    ERR_MAGIC_MISMATCH = 400
    ERR_VERSION_MISMATCH = 401
    ERR_PID_MISMATCH = 402
    ERR_PROTOCOL_VIOLATION = 403
    ERR_FRAGMENT_TIMEOUT = 404
    ERR_PAYLOAD_TOO_LARGE = 413
    ERR_ENCODING_UNSUPPORTED = 415
    ERR_PIPE_FAILED = 500
    ERR_READ_TIMEOUT = 501
    ERR_WRITE_FAILED = 502
    ERR_CONNECTION_LOST = 503
    ERR_INTERNAL = 599


class ErrorKind(Enum):
    CONFIGURATION = "configuration"
    ADDRESS_DERIVATION = "address_derivation"
    DIAL = "dial"
    TIMEOUT = "timeout"
    HANDSHAKE = "handshake"
    PROTOCOL = "protocol"
    ENCODING = "encoding"
    CAPABILITY = "capability"
    BACKPRESSURE = "backpressure"
    SESSION_CLOSED = "session_closed"
    STALE_EPOCH = "stale_epoch"
    APPLICATION = "application"
    TRANSPORT = "transport"
    INTERNAL = "internal"
    STATE = "state"


class ErrorPhase(Enum):
    CONFIGURATION = "configuration"
    ADDRESS_DERIVATION = "address_derivation"
    DIAL = "dial"
    HANDSHAKE_READ = "handshake_read"
    HANDSHAKE_VALIDATE = "handshake_validate"
    ACK_WRITE = "ack_write"
    SESSION_WRITE = "session_write"
    FRAME_READ = "frame_read"
    FRAME_DECODE = "frame_decode"
    FRAME_WRITE = "frame_write"
    HEARTBEAT = "heartbeat"
    FRAGMENTATION = "fragmentation"
    APPLICATION_DISPATCH = "application_dispatch"
    APPLICATION_SEND = "application_send"
    CLOSE = "close"


class DisconnectReason(Enum):
    LOCAL_CLOSE = "local_close"
    PEER_CLOSE = "peer_close"
    HEARTBEAT_TIMEOUT = "heartbeat_timeout"
    PROTOCOL_FAILURE = "protocol_failure"
    TRANSPORT_FAILURE = "transport_failure"
    BACKPRESSURE = "backpressure"


class EngineState(Enum):
    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    CLOSING = "closing"


@dataclass(frozen=True)
class SessionView:
    session_id: str
    epoch: int
    encoding: Encoding
    capabilities: int


class Responder(Protocol):
    def respond(self, payload: Any) -> None: ...


@dataclass(frozen=True)
class MessageEvent:
    session: SessionView
    channel: Channel
    payload: Any
    correlation_id: int | None = None
    responder: Responder | None = None


@dataclass(frozen=True)
class HeartbeatEvent:
    session: SessionView
    timestamp: int


@dataclass(frozen=True)
class ErrorInfo:
    kind: ErrorKind
    cause: str
    status: StatusCode | None = None
    phase: ErrorPhase | None = None
    epoch: int | None = None


@dataclass(frozen=True)
class TerminalResult:
    reason: DisconnectReason
    error: ErrorInfo | None = None


@dataclass(frozen=True)
class DisconnectEvent:
    session: SessionView
    terminal: TerminalResult


@dataclass(frozen=True)
class HeartbeatSettings:
    disabled: bool = False
    interval: float = 30.0
    missed_interval_limit: int = 3


@dataclass(frozen=True)
class FragmentationSettings:
    timeout: float = 15.0
    active_sequence_limit: int = 16


@dataclass(frozen=True)
class EngineConfig:
    endpoint_name: str
    token: str
    supported_encodings: tuple[Encoding, ...] = (Encoding.MSGPACK, Encoding.JSON)
    supported_capabilities: int = CAP_CORRELATION
    expected_go_pid: int | None = None
    connect_timeout: float = 10.0
    application_queue_capacity: int = 64
    heartbeat: HeartbeatSettings = field(default_factory=HeartbeatSettings)
    fragmentation: FragmentationSettings = field(default_factory=FragmentationSettings)


class EngineError(Exception):
    def __init__(self, info: ErrorInfo) -> None:
        status = "" if info.status is None else f"[{int(info.status)}]"
        super().__init__(f"[YUUMI_ERR][{info.kind.value}]{status} {info.cause}")
        self.info = info

    @property
    def kind(self) -> ErrorKind:
        return self.info.kind

    @property
    def code(self) -> StatusCode | None:
        return self.info.status
