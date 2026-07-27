from __future__ import annotations

import json
import struct
from typing import Any

import msgpack

from .types import Channel, Encoding, ErrorCategory, ErrorInfo, ErrorPhase, MAX_MESSAGE_SIZE, StatusCode

FLAG_FRAGMENT = 0x01
FLAG_LAST_FRAGMENT = 0x02
FLAG_CORRELATED = 0x04
KNOWN_FLAGS = FLAG_FRAGMENT | FLAG_LAST_FRAGMENT | FLAG_CORRELATED


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON number {value} is not permitted")


class ProtocolFailure(Exception):
    def __init__(self, status: StatusCode, cause: str, phase: ErrorPhase = ErrorPhase.FRAME_DECODE) -> None:
        super().__init__(cause)
        self.status = status
        self.cause = cause
        self.phase = phase


def error(category: ErrorCategory, status: StatusCode, phase: ErrorPhase, cause: str, session=None) -> ErrorInfo:
    return ErrorInfo(category, status, phase, cause, session)


def encode_payload(value: Any, encoding: Encoding) -> bytes:
    try:
        if encoding == Encoding.MSGPACK:
            return msgpack.packb(value, use_bin_type=True)
        if encoding == Encoding.JSON:
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, f"payload serialization failed: {exc}", ErrorPhase.APPLICATION_SEND) from exc
    raise ProtocolFailure(StatusCode.ERR_ENCODING_UNSUPPORTED, "selected encoding is unsupported", ErrorPhase.APPLICATION_SEND)


def decode_payload(payload: bytes, encoding: Encoding) -> Any:
    try:
        if encoding == Encoding.MSGPACK:
            return msgpack.unpackb(payload, raw=False, strict_map_key=False)
        if encoding == Encoding.JSON:
            return json.loads(payload.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, msgpack.UnpackException, ValueError) as exc:
        raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "application payload cannot be decoded with the negotiated encoding") from exc
    raise ProtocolFailure(StatusCode.ERR_ENCODING_UNSUPPORTED, "selected encoding is unsupported")


def encode_control(value: dict[str, Any]) -> bytes:
    return encode_payload(value, Encoding.JSON)


def decode_control(payload: bytes) -> dict[str, Any]:
    value = decode_payload(payload, Encoding.JSON)
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise ProtocolFailure(StatusCode.ERR_PROTOCOL_VIOLATION, "Control payload must be an object with a string type")
    return value


def build_frame(channel: Channel, flags: int, payload: bytes) -> bytes:
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolFailure(StatusCode.ERR_PAYLOAD_TOO_LARGE, "frame payload exceeds 16 MiB", ErrorPhase.APPLICATION_SEND)
    return struct.pack(">IBB", len(payload), int(channel), flags) + payload


def build_control_frame(value: dict[str, Any]) -> bytes:
    return build_frame(Channel.CONTROL, 0, encode_control(value))
