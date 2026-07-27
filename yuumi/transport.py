from __future__ import annotations

import errno
import os
import re
import socket
import sys
import tempfile
import threading
from pathlib import Path
from typing import Protocol

_ENDPOINT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}\Z")


class TransportClosed(Exception):
    pass


class TransportFailure(Exception):
    pass


class Stream(Protocol):
    def read_exact(self, size: int) -> bytes: ...
    def write_all(self, data: bytes) -> None: ...
    def close(self) -> None: ...
    def peer_pid(self) -> int | None: ...


class Listener(Protocol):
    def open(self, address: str) -> None: ...
    def accept(self) -> Stream: ...
    def close(self) -> None: ...


def valid_endpoint_name(value: object) -> bool:
    return isinstance(value, str) and _ENDPOINT_PATTERN.fullmatch(value) is not None


def valid_token(value: object) -> bool:
    return isinstance(value, str) and _TOKEN_PATTERN.fullmatch(value) is not None


def resolve_transport_address(endpoint_name: str, token: str) -> str:
    if not valid_endpoint_name(endpoint_name):
        raise ValueError("endpoint_name must match [A-Za-z0-9][A-Za-z0-9_-]{0,31}")
    if not valid_token(token):
        raise ValueError("token must contain exactly 32 lowercase hexadecimal characters")
    stem = f"yuumi-{endpoint_name}-{token}"
    if os.name == "nt":
        return rf"\\.\pipe\{stem}"
    address = str(Path(tempfile.gettempdir()) / f"{stem}.sock")
    limit = 104 if sys.platform == "darwin" else 108
    if len(os.fsencode(address)) >= limit:
        raise ValueError("canonical Unix socket address exceeds the platform bound")
    return address


class SocketStream:
    def __init__(self, value: socket.socket) -> None:
        self._socket = value
        self._close_lock = threading.Lock()

    def read_exact(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            try:
                part = self._socket.recv(size - len(output))
            except OSError as exc:
                raise TransportFailure(str(exc)) from exc
            if not part:
                raise TransportClosed("connection closed")
            output.extend(part)
        return bytes(output)

    def write_all(self, data: bytes) -> None:
        try:
            self._socket.sendall(data)
        except OSError as exc:
            raise TransportFailure(str(exc)) from exc

    def close(self) -> None:
        with self._close_lock:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._socket.close()
            except OSError:
                pass

    def peer_pid(self) -> int | None:
        import struct

        try:
            if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
                credentials = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                return struct.unpack("3i", credentials)[0]
            if sys.platform == "darwin":
                credentials = self._socket.getsockopt(0, 0x002, 4)
                return struct.unpack("i", credentials)[0]
        except OSError as exc:
            raise TransportFailure(f"peer credential query failed: {exc}") from exc
        return None


class UnixListener:
    def __init__(self) -> None:
        self._socket: socket.socket | None = None
        self._address: str | None = None

    def open(self, address: str) -> None:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(address)
        except FileNotFoundError:
            pass
        except ConnectionRefusedError:
            try:
                os.unlink(address)
            except FileNotFoundError:
                pass
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise TransportFailure(f"endpoint probe failed: {exc}") from exc
        else:
            raise TransportFailure("endpoint is already owned by a live listener")
        finally:
            probe.close()

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(address)
            os.chmod(address, 0o600)
            listener.listen()
            listener.settimeout(0.2)
        except OSError as exc:
            listener.close()
            try:
                os.unlink(address)
            except FileNotFoundError:
                pass
            raise TransportFailure(f"endpoint open failed: {exc}") from exc
        self._socket = listener
        self._address = address

    def accept(self) -> SocketStream:
        listener = self._socket
        if listener is None:
            raise TransportClosed("listener is closed")
        while True:
            if self._socket is None:
                raise TransportClosed("listener is closed")
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._socket is None:
                    raise TransportClosed("listener is closed") from exc
                raise TransportFailure(str(exc)) from exc
            return SocketStream(connection)

    def close(self) -> None:
        listener, self._socket = self._socket, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if self._address is not None:
            try:
                os.unlink(self._address)
            except FileNotFoundError:
                pass
            self._address = None


if os.name == "nt":
    from ._winpipe import NamedPipeListener


def create_listener() -> Listener:
    if os.name == "nt":
        return NamedPipeListener()
    return UnixListener()


def _connect_for_test(address: str, timeout: float = 1.0) -> Stream:
    if os.name == "nt":
        from ._winpipe import connect_pipe

        return connect_pipe(address, timeout)
    value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    value.settimeout(timeout)
    value.connect(address)
    value.settimeout(None)
    return SocketStream(value)
