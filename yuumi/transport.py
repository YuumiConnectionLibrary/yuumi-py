from __future__ import annotations

import socket
import tempfile
from pathlib import Path

from .types import StatusCode, YuumiError

MAX_PIPE_NAME_LENGTH = 64


def _truncate_utf8(value: str, limit: int) -> str:
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value
    clipped = raw[:limit]
    while clipped:
        try:
            return clipped.decode("utf-8")
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return ""


def resolve_transport_address(pipe_name: str) -> str:
    safe_name = _truncate_utf8(pipe_name, MAX_PIPE_NAME_LENGTH)
    return str(Path(tempfile.gettempdir()) / f"{safe_name}.sock")


def dial_transport(pipe_name: str, timeout: float = 5.0) -> socket.socket:
    address = resolve_transport_address(pipe_name)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(address)
    except OSError as exc:
        conn.close()
        raise YuumiError(StatusCode.ERR_PIPE_FAILED, f"Dial failed: {exc}") from exc
    return conn
