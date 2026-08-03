from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from yuumi.transport import SocketStream, Stream, resolve_transport_address

TOKEN = "0123456789abcdef0123456789abcdef"
ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "yuumi-spec" / "test-vectors"
_sequence = 0


def vector(name: str) -> bytes:
    return (VECTORS / name).read_bytes()


def endpoint() -> str:
    global _sequence
    _sequence += 1
    return f"p{os.getpid():x}{_sequence:x}"


def handshake(
    pid: int | None = None,
    encodings: int = 3,
    capabilities: int = 1,
    magic: int = 0x59554D49,
    version: int = 1,
) -> bytes:
    return (
        struct.pack(
            ">IIIB",
            magic,
            version,
            os.getpid() if pid is None else pid,
            encodings,
        )
        + capabilities.to_bytes(3, "big")
    )


def frame(channel: int, flags: int, payload: bytes) -> bytes:
    return struct.pack(">IBB", len(payload), channel, flags) + payload


class Peer:
    def __init__(self, stream: Stream) -> None:
        self.stream = stream

    def write(self, data: bytes) -> None:
        self.stream.write_all(data)

    def read(self, size: int) -> bytes:
        return self.stream.read_exact(size)

    def read_frame(self) -> tuple[int, int, bytes]:
        length, channel, flags = struct.unpack(">IBB", self.read(6))
        return channel, flags, self.read(length)

    def close(self) -> None:
        self.stream.close()


class UnixTestListener:
    def __init__(self, address: str) -> None:
        self.address = address
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(address)
        self.socket.listen(1)

    def accept(self) -> Stream:
        value, _ = self.socket.accept()
        return SocketStream(value)

    def close(self) -> None:
        self.socket.close()
        try:
            os.unlink(self.address)
        except FileNotFoundError:
            pass


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    from yuumi._winpipe import (
        ERROR_IO_PENDING,
        FILE_FLAG_OVERLAPPED,
        INFINITE,
        INVALID_HANDLE_VALUE,
        OVERLAPPED,
        NamedPipeStream,
        kernel32,
    )

    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    ERROR_PIPE_CONNECTED = 535

    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.ConnectNamedPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL


    class WindowsTestListener:
        def __init__(self, address: str) -> None:
            self.handle = kernel32.CreateNamedPipeW(
                address,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE
                | PIPE_READMODE_BYTE
                | PIPE_WAIT
                | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                None,
            )
            if self.handle == INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())

        def accept(self) -> Stream:
            event = kernel32.CreateEventW(None, True, False, None)
            if not event:
                raise ctypes.WinError(ctypes.get_last_error())
            operation = OVERLAPPED(hEvent=event)
            try:
                connected = kernel32.ConnectNamedPipe(
                    self.handle, ctypes.byref(operation)
                )
                code = 0 if connected else ctypes.get_last_error()
                if code == ERROR_IO_PENDING:
                    kernel32.WaitForSingleObject(event, INFINITE)
                    transferred = wintypes.DWORD()
                    if not kernel32.GetOverlappedResult(
                        self.handle,
                        ctypes.byref(operation),
                        ctypes.byref(transferred),
                        False,
                    ):
                        code = ctypes.get_last_error()
                    else:
                        code = 0
                if code not in (0, ERROR_PIPE_CONNECTED):
                    raise ctypes.WinError(code)
            finally:
                kernel32.CloseHandle(event)
            handle, self.handle = self.handle, INVALID_HANDLE_VALUE
            return NamedPipeStream(handle)

        def close(self) -> None:
            if self.handle != INVALID_HANDLE_VALUE:
                kernel32.CancelIoEx(self.handle, None)
                kernel32.CloseHandle(self.handle)
                self.handle = INVALID_HANDLE_VALUE


def listen(config) -> UnixTestListener:
    address = resolve_transport_address(config.endpoint_name, config.token)
    if os.name == "nt":
        return WindowsTestListener(address)
    return UnixTestListener(address)


def establish(engine, config, packet: bytes | None = None):
    listener = listen(config)
    result = {}

    def run_connect() -> None:
        try:
            result["view"] = engine.connect()
        except BaseException as exc:
            result["error"] = exc

    worker = threading.Thread(
        target=run_connect, name="yuumi-testkit-connect", daemon=False
    )
    worker.start()
    peer = Peer(listener.accept())
    peer.write(packet if packet is not None else handshake())
    ack = peer.read(4)
    assignment = peer.read_frame()
    worker.join(2.0)
    listener.close()
    if worker.is_alive():
        raise AssertionError("engine connect did not finish")
    if "error" in result:
        raise result["error"]
    return peer, ack, assignment, result["view"]


def wait_for(probe, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.005)
    raise AssertionError("condition timed out")


def decode_json(frame_value: tuple[int, int, bytes]):
    return json.loads(frame_value[2])


"""
This module is the private Go-role peer permitted by the Engine API contract.
It owns the UDS or Named Pipe listener only inside tests; nothing here is
packaged or exported by yuumi.
"""
