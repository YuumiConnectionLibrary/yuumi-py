from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag

MAGIC = 0x59554D49
PROTOCOL_VERSION = 2
MAX_MESSAGE_SIZE = 16 * 1024 * 1024


class Encoding(IntFlag):
    JSON = 0x01
    MSGPACK = 0x02


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
    ERR_PIPE_FAILED = 500
    ERR_READ_TIMEOUT = 501
    ERR_WRITE_FAILED = 502
    ERR_CONNECTION_LOST = 503
    ERR_INTERNAL = 599


class Channel(IntEnum):
    CONTROL = 0
    COMMAND = 1
    LOG = 2
    DATA = 3


class YuumiError(Exception):
    def __init__(self, code: StatusCode, message: str) -> None:
        super().__init__(f"[YUUMI_ERR][{int(code)}] {message}")
        self.code = code
        self.message = message


@dataclass
class ReconnectPolicy:
    """Exponential-backoff reconnect policy, equivalent to Go ReconnectPolicy."""
    max_attempts: int = 0
    initial_delay: float = 0.1   # seconds
    max_delay: float = 2.0       # seconds
    jitter: float = 0.10         # ±10 % jitter fraction
