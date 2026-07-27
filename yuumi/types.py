from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
from typing import Any

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


class ErrorCategory(Enum):
    CONFIGURATION = "configuration"
    ENDPOINT = "endpoint"
    HANDSHAKE = "handshake"
    PROTOCOL = "protocol"
    TRANSPORT = "transport"
    SERIALIZATION = "serialization"
    SESSION = "session"
    INTERNAL = "internal"


class ErrorPhase(Enum):
    CONFIGURATION = "configuration"
    ENDPOINT_PROBE = "endpoint_probe"
    ENDPOINT_OPEN = "endpoint_open"
    ACCEPT = "accept"
    HANDSHAKE_READ = "handshake_read"
    HANDSHAKE_VALIDATE = "handshake_validate"
    ACK_WRITE = "ack_write"
    SESSION_WRITE = "session_write"
    FRAME_READ = "frame_read"
    FRAME_DECODE = "frame_decode"
    FRAME_WRITE = "frame_write"
    HEARTBEAT = "heartbeat"
    FRAGMENTATION = "fragmentation"
    APPLICATION_SEND = "application_send"
    CLOSE = "close"


class DisconnectReason(Enum):
    ENGINE_CLOSE = "engine_close"
    PEER_CLOSE = "peer_close"
    HEARTBEAT_TIMEOUT = "heartbeat_timeout"
    PROTOCOL_FAILURE = "protocol_failure"
    TRANSPORT_FAILURE = "transport_failure"


@dataclass(frozen=True)
class SessionHandle:
    session_id: str
    epoch: int


@dataclass(frozen=True)
class SessionView:
    handle: SessionHandle
    encoding: Encoding
    capabilities: int


@dataclass(frozen=True)
class MessageEvent:
    session: SessionHandle
    channel: Channel
    payload: Any
    correlation_id: int | None = None


@dataclass(frozen=True)
class ErrorInfo:
    category: ErrorCategory
    status: StatusCode
    phase: ErrorPhase
    cause: str
    session: SessionHandle | None = None


@dataclass(frozen=True)
class DisconnectEvent:
    session: SessionHandle
    reason: DisconnectReason


@dataclass
class HeartbeatSettings:
    disabled: bool = False
    interval: float = 30.0
    missed_interval_limit: int = 3


@dataclass
class FragmentationSettings:
    timeout: float = 15.0
    active_sequence_limit: int = 16


@dataclass
class EngineConfig:
    endpoint_name: str
    token: str
    max_sessions: int = 1
    supported_encodings: tuple[Encoding, ...] = (Encoding.MSGPACK, Encoding.JSON)
    supported_capabilities: int = CAP_CORRELATION
    expected_pid: int | None = None
    heartbeat: HeartbeatSettings = field(default_factory=HeartbeatSettings)
    fragmentation: FragmentationSettings = field(default_factory=FragmentationSettings)


class EngineError(Exception):
    def __init__(self, info: ErrorInfo) -> None:
        super().__init__(f"[YUUMI_ERR][{int(info.status)}] {info.cause}")
        self.info = info

    @property
    def code(self) -> StatusCode:
        return self.info.status
