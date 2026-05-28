from __future__ import annotations

import json
import struct
from typing import Any

import msgpack

from .types import Encoding, MAGIC, PROTOCOL_VERSION


def build_handshake_packet(pid: int, encoding_caps: Encoding = Encoding.JSON | Encoding.MSGPACK) -> bytes:
    return struct.pack(">IIIB3s", MAGIC, PROTOCOL_VERSION, pid & 0xFFFFFFFF, int(encoding_caps), b"\x00\x00\x00")


def encode_payload(data: Any, encoding: Encoding) -> bytes:
    if encoding == Encoding.MSGPACK:
        return msgpack.packb(data, use_bin_type=True)
    return json.dumps(data).encode("utf-8")


def decode_payload(body: bytes, encoding: Encoding) -> dict[str, Any]:
    if encoding == Encoding.MSGPACK:
        decoded = msgpack.unpackb(body, raw=False)
    else:
        decoded = json.loads(body.decode("utf-8"))

    if not isinstance(decoded, dict):
        raise ValueError("Decoded payload must be a JSON/MsgPack object")
    return decoded
