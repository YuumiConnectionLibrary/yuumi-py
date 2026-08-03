from __future__ import annotations

import hashlib
import os
import re
import socket
import struct
import sys
import tempfile
import threading
from typing import Protocol

_ENDPOINT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}\Z")


class TransportClosed(Exception):
    pass


class TransportFailure(Exception):
    pass


class TransportTimeout(TransportFailure):
    pass


class Stream(Protocol):
    def read_exact(self, size: int) -> bytes: ...
    def write_all(self, data: bytes) -> None: ...
    def close(self) -> None: ...
    def peer_pid(self) -> int | None: ...
    def set_timeout(self, timeout: float | None) -> None: ...


def valid_endpoint_name(value: object) -> bool:
    return isinstance(value, str) and _ENDPOINT_PATTERN.fullmatch(value) is not None


def valid_token(value: object) -> bool:
    return isinstance(value, str) and _TOKEN_PATTERN.fullmatch(value) is not None


def resolve_transport_address(
    endpoint_name: str,
    token: str,
    temp_directory: str | None = None,
    platform_name: str | None = None,
) -> str:
    if not valid_endpoint_name(endpoint_name):
        raise ValueError("endpoint_name must match [A-Za-z0-9][A-Za-z0-9_-]{0,31}")
    if not valid_token(token):
        raise ValueError("token must contain exactly 32 lowercase hexadecimal characters")
    platform_name = platform_name or sys.platform
    if platform_name == "win32":
        return rf"\\.\pipe\yuumi-{endpoint_name}-{token}"
    digest = hashlib.sha256(
        b"yuumi\0" + endpoint_name.encode("utf-8") + b"\0" + token.encode("utf-8")
    ).hexdigest()[:32]
    base = (temp_directory if temp_directory is not None else tempfile.gettempdir()).rstrip("/")
    address = f"{base}/yuumi-{digest}.sock"
    maximum = 103 if platform_name == "darwin" else 107
    if len(os.fsencode(address)) > maximum:
        raise ValueError("canonical Unix socket address exceeds the platform byte bound")
    return address


class SocketStream:
    def __init__(self, value: socket.socket) -> None:
        self._socket: socket.socket | None = value
        self._close_lock = threading.Lock()

    def read_exact(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            with self._close_lock:
                value = self._socket
            if value is None:
                raise TransportClosed(
                    f"connection closed after {len(output)} of {size} bytes"
                )
            try:
                part = value.recv(size - len(output))
            except socket.timeout as exc:
                raise TransportTimeout("transport read timed out") from exc
            except OSError as exc:
                with self._close_lock:
                    if self._socket is None:
                        raise TransportClosed("connection closed") from exc
                raise TransportFailure(str(exc)) from exc
            if not part:
                raise TransportClosed(
                    f"connection closed after {len(output)} of {size} bytes"
                )
            output.extend(part)
        return bytes(output)

    def write_all(self, data: bytes) -> None:
        with self._close_lock:
            value = self._socket
        if value is None:
            raise TransportClosed("connection closed")
        try:
            value.sendall(data)
        except socket.timeout as exc:
            raise TransportTimeout("transport write timed out") from exc
        except OSError as exc:
            with self._close_lock:
                if self._socket is None:
                    raise TransportClosed("connection closed") from exc
            raise TransportFailure(str(exc)) from exc

    def close(self) -> None:
        with self._close_lock:
            value, self._socket = self._socket, None
        if value is None:
            return
        try:
            value.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            value.close()
        except OSError:
            pass

    def peer_pid(self) -> int | None:
        value = self._socket
        if value is None:
            return None
        try:
            if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
                credentials = value.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                return struct.unpack("3i", credentials)[0]
            if sys.platform == "darwin":
                credentials = value.getsockopt(0, 0x002, 4)
                return struct.unpack("i", credentials)[0]
        except OSError as exc:
            raise TransportFailure(f"peer credential query failed: {exc}") from exc
        return None

    def set_timeout(self, timeout: float | None) -> None:
        value = self._socket
        if value is not None:
            value.settimeout(timeout)


def dial_local(address: str, timeout: float) -> Stream:
    if os.name == "nt":
        from ._winpipe import connect_pipe

        return connect_pipe(address, timeout)
    value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    value.settimeout(timeout)
    try:
        value.connect(address)
    except socket.timeout as exc:
        value.close()
        raise TransportTimeout("Unix socket dial timed out") from exc
    except OSError as exc:
        value.close()
        raise TransportFailure(str(exc)) from exc
    return SocketStream(value)


"""
Address derivation is internal because an engine accepts endpoint_name and token,
not arbitrary transport addresses. SocketStream.close shuts down the socket
before closing it so a reader blocked in recv is released for bounded joins.
"""
