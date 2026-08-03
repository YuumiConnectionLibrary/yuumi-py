from __future__ import annotations

import ctypes
import threading
import time
from ctypes import wintypes

from .transport import TransportClosed, TransportFailure, TransportTimeout

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_PIPE_BUSY = 231
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_OPERATION_ABORTED = 995
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", wintypes.WPARAM),
        ("InternalHigh", wintypes.WPARAM),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(OVERLAPPED),
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(OVERLAPPED),
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
kernel32.CancelIoEx.restype = wintypes.BOOL
kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.WaitNamedPipeW.restype = wintypes.BOOL
kernel32.GetNamedPipeServerProcessId.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.ULONG),
]
kernel32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
kernel32.CreateEventW.argtypes = [
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.BOOL,
    wintypes.LPCWSTR,
]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(OVERLAPPED),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
kernel32.GetOverlappedResult.restype = wintypes.BOOL


def _windows_error(prefix: str) -> TransportFailure:
    return TransportFailure(f"{prefix}: {ctypes.WinError(ctypes.get_last_error())}")


class NamedPipeStream:
    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._close_lock = threading.Lock()
        self._timeout: float | None = None

    def _operation(
        self,
        function,
        buffer,
        size: int,
        operation_name: str,
    ) -> int:
        with self._close_lock:
            handle = self._handle
        if handle == INVALID_HANDLE_VALUE:
            raise TransportClosed("pipe connection closed")
        event = kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise _windows_error(f"pipe {operation_name} event creation failed")
        operation = OVERLAPPED(hEvent=event)
        transferred = wintypes.DWORD()
        try:
            started = function(handle, buffer, size, None, ctypes.byref(operation))
            code = 0 if started else ctypes.get_last_error()
            if code == ERROR_IO_PENDING:
                timeout_ms = (
                    INFINITE
                    if self._timeout is None
                    else max(1, min(int(self._timeout * 1000), INFINITE - 1))
                )
                result = kernel32.WaitForSingleObject(event, timeout_ms)
                if result == WAIT_TIMEOUT:
                    kernel32.CancelIoEx(handle, ctypes.byref(operation))
                    kernel32.WaitForSingleObject(event, INFINITE)
                    raise TransportTimeout(f"pipe {operation_name} timed out")
                if result != WAIT_OBJECT_0:
                    raise _windows_error(f"pipe {operation_name} wait failed")
                if not kernel32.GetOverlappedResult(
                    handle, ctypes.byref(operation), ctypes.byref(transferred), False
                ):
                    code = ctypes.get_last_error()
                else:
                    code = 0
            elif started:
                if not kernel32.GetOverlappedResult(
                    handle, ctypes.byref(operation), ctypes.byref(transferred), True
                ):
                    code = ctypes.get_last_error()
            if code in (
                ERROR_BROKEN_PIPE,
                ERROR_NO_DATA,
                ERROR_PIPE_NOT_CONNECTED,
                ERROR_OPERATION_ABORTED,
            ):
                raise TransportClosed("pipe connection closed")
            if code:
                ctypes.set_last_error(code)
                raise _windows_error(f"pipe {operation_name} failed")
            return int(transferred.value)
        finally:
            kernel32.CloseHandle(event)

    def read_exact(self, size: int) -> bytes:
        output = bytearray(size)
        offset = 0
        while offset < size:
            target = (ctypes.c_char * (size - offset)).from_buffer(output, offset)
            transferred = self._operation(
                kernel32.ReadFile, target, size - offset, "read"
            )
            if transferred == 0:
                raise TransportClosed(
                    f"pipe closed after {offset} of {size} bytes"
                )
            offset += transferred
        return bytes(output)

    def write_all(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            chunk = ctypes.create_string_buffer(data[offset:])
            transferred = self._operation(
                kernel32.WriteFile, chunk, len(data) - offset, "write"
            )
            if transferred == 0:
                raise TransportFailure("pipe write made no progress")
            offset += transferred

    def close(self) -> None:
        with self._close_lock:
            handle, self._handle = self._handle, INVALID_HANDLE_VALUE
        if handle == INVALID_HANDLE_VALUE:
            return
        kernel32.CancelIoEx(handle, None)
        kernel32.CloseHandle(handle)

    def peer_pid(self) -> int | None:
        with self._close_lock:
            handle = self._handle
        if handle == INVALID_HANDLE_VALUE:
            return None
        pid = wintypes.ULONG()
        if kernel32.GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
            return int(pid.value)
        raise _windows_error("named pipe server PID query failed")

    def set_timeout(self, timeout: float | None) -> None:
        self._timeout = timeout


def connect_pipe(address: str, timeout: float) -> NamedPipeStream:
    deadline = time.monotonic() + timeout
    while True:
        handle = kernel32.CreateFileW(
            address,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        if handle != INVALID_HANDLE_VALUE:
            stream = NamedPipeStream(handle)
            stream.set_timeout(max(0.001, deadline - time.monotonic()))
            return stream
        code = ctypes.get_last_error()
        if code != ERROR_PIPE_BUSY:
            raise _windows_error("named pipe dial failed")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportTimeout("named pipe remained busy until connect timeout")
        wait_ms = max(1, min(int(remaining * 1000), INFINITE - 1))
        if not kernel32.WaitNamedPipeW(address, wait_ms):
            code = ctypes.get_last_error()
            if time.monotonic() >= deadline:
                raise TransportTimeout("named pipe remained busy until connect timeout")
            ctypes.set_last_error(code)
            raise _windows_error("named pipe wait failed")


"""
This module intentionally contains only the Named Pipe client. CreateFileW
performs the dial, overlapped ReadFile and WriteFile provide byte-stream I/O,
and CancelIoEx makes close unblock pending operations. No extension module or
native installation step is required.
"""
