from __future__ import annotations

import ctypes
import threading
import time
from ctypes import wintypes

from .transport import TransportClosed, TransportFailure

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
ERROR_PIPE_BUSY = 231
ERROR_FILE_NOT_FOUND = 2
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_OPERATION_ABORTED = 995
ERROR_IO_PENDING = 997
INFINITE = 0xFFFFFFFF
SDDL_REVISION_1 = 1

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID), ("bInheritHandle", wintypes.BOOL)]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", wintypes.WPARAM),
        ("InternalHigh", wintypes.WPARAM),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


kernel32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES)]
kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.CancelIoEx.restype = wintypes.BOOL
kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.WaitNamedPipeW.restype = wintypes.BOOL
kernel32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
kernel32.GetOverlappedResult.restype = wintypes.BOOL
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL


def _windows_error(prefix: str) -> TransportFailure:
    return TransportFailure(f"{prefix}: {ctypes.WinError(ctypes.get_last_error())}")


class NamedPipeStream:
    def __init__(self, handle: int, server_side: bool) -> None:
        self._handle = handle
        self._server_side = server_side
        self._lock = threading.Lock()

    def read_exact(self, size: int) -> bytes:
        output = bytearray(size)
        offset = 0
        while offset < size:
            transferred = wintypes.DWORD()
            target = (ctypes.c_char * (size - offset)).from_buffer(output, offset)
            event = kernel32.CreateEventW(None, True, False, None)
            if not event:
                raise _windows_error("pipe read event creation failed")
            operation = OVERLAPPED(hEvent=event)
            try:
                started = kernel32.ReadFile(self._handle, target, size - offset, None, ctypes.byref(operation))
                code = 0 if started else ctypes.get_last_error()
                if code == ERROR_IO_PENDING:
                    kernel32.WaitForSingleObject(event, INFINITE)
                    if not kernel32.GetOverlappedResult(self._handle, ctypes.byref(operation), ctypes.byref(transferred), False):
                        code = ctypes.get_last_error()
                    else:
                        code = 0
                elif started:
                    if not kernel32.GetOverlappedResult(self._handle, ctypes.byref(operation), ctypes.byref(transferred), True):
                        code = ctypes.get_last_error()
                if code in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, ERROR_OPERATION_ABORTED):
                    raise TransportClosed("pipe connection closed")
                if code:
                    ctypes.set_last_error(code)
                    raise _windows_error("pipe read failed")
            finally:
                kernel32.CloseHandle(event)
            if transferred.value == 0:
                raise TransportClosed("pipe connection closed")
            offset += transferred.value
        return bytes(output)

    def write_all(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            transferred = wintypes.DWORD()
            chunk = data[offset:]
            event = kernel32.CreateEventW(None, True, False, None)
            if not event:
                raise _windows_error("pipe write event creation failed")
            operation = OVERLAPPED(hEvent=event)
            try:
                started = kernel32.WriteFile(self._handle, chunk, len(chunk), None, ctypes.byref(operation))
                code = 0 if started else ctypes.get_last_error()
                if code == ERROR_IO_PENDING:
                    kernel32.WaitForSingleObject(event, INFINITE)
                    if not kernel32.GetOverlappedResult(self._handle, ctypes.byref(operation), ctypes.byref(transferred), False):
                        code = ctypes.get_last_error()
                    else:
                        code = 0
                elif started:
                    if not kernel32.GetOverlappedResult(self._handle, ctypes.byref(operation), ctypes.byref(transferred), True):
                        code = ctypes.get_last_error()
                if code in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, ERROR_OPERATION_ABORTED):
                    raise TransportClosed("pipe connection closed")
                if code:
                    ctypes.set_last_error(code)
                    raise _windows_error("pipe write failed")
            finally:
                kernel32.CloseHandle(event)
            if transferred.value == 0:
                raise TransportFailure("pipe write made no progress")
            offset += transferred.value

    def close(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, INVALID_HANDLE_VALUE
        if handle == INVALID_HANDLE_VALUE:
            return
        kernel32.CancelIoEx(handle, None)
        kernel32.CloseHandle(handle)

    def peer_pid(self) -> int | None:
        if not self._server_side:
            return None
        pid = wintypes.ULONG()
        if kernel32.GetNamedPipeClientProcessId(self._handle, ctypes.byref(pid)):
            return int(pid.value)
        return None


class NamedPipeListener:
    def __init__(self) -> None:
        self._address: str | None = None
        self._pending = INVALID_HANDLE_VALUE
        self._lock = threading.Lock()
        self._closed = True
        self._security_descriptor = wintypes.LPVOID()

    def _create_instance(self) -> int:
        attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), self._security_descriptor, False)
        handle = kernel32.CreateNamedPipeW(self._address, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, ctypes.byref(attributes))
        if handle == INVALID_HANDLE_VALUE:
            raise _windows_error("named pipe creation failed")
        return handle

    def open(self, address: str) -> None:
        probe = kernel32.CreateFileW(address, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if probe != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(probe)
            raise TransportFailure("endpoint is already owned by a live listener")
        probe_error = ctypes.get_last_error()
        if probe_error == ERROR_PIPE_BUSY:
            raise TransportFailure("endpoint is already owned by a live listener")
        if probe_error != ERROR_FILE_NOT_FOUND:
            raise _windows_error("endpoint probe failed")

        descriptor = wintypes.LPVOID()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;OW)", SDDL_REVISION_1, ctypes.byref(descriptor), None):
            raise _windows_error("named pipe security descriptor creation failed")
        self._security_descriptor = descriptor
        self._address = address
        self._closed = False
        try:
            self._pending = self._create_instance()
        except Exception:
            kernel32.LocalFree(self._security_descriptor)
            self._security_descriptor = wintypes.LPVOID()
            raise

    def accept(self) -> NamedPipeStream:
        with self._lock:
            if self._closed:
                raise TransportClosed("listener is closed")
            handle = self._pending
        event = kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise _windows_error("named pipe accept event creation failed")
        operation = OVERLAPPED(hEvent=event)
        try:
            connected = kernel32.ConnectNamedPipe(handle, ctypes.byref(operation))
            code = 0 if connected else ctypes.get_last_error()
            if code == ERROR_IO_PENDING:
                kernel32.WaitForSingleObject(event, INFINITE)
                transferred = wintypes.DWORD()
                if not kernel32.GetOverlappedResult(handle, ctypes.byref(operation), ctypes.byref(transferred), False):
                    code = ctypes.get_last_error()
                else:
                    code = 0
            if code not in (0, ERROR_PIPE_CONNECTED):
                with self._lock:
                    closed = self._closed
                if closed or code == ERROR_OPERATION_ABORTED:
                    raise TransportClosed("listener is closed")
                ctypes.set_last_error(code)
                raise _windows_error("named pipe accept failed")
        finally:
            kernel32.CloseHandle(event)
        with self._lock:
            if self._closed:
                kernel32.CloseHandle(handle)
                raise TransportClosed("listener is closed")
            self._pending = self._create_instance()
        return NamedPipeStream(handle, True)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            handle, self._pending = self._pending, INVALID_HANDLE_VALUE
        if handle != INVALID_HANDLE_VALUE:
            kernel32.CancelIoEx(handle, None)
            kernel32.CloseHandle(handle)
        if self._security_descriptor:
            kernel32.LocalFree(self._security_descriptor)
            self._security_descriptor = wintypes.LPVOID()


def connect_pipe(address: str, timeout: float = 1.0) -> NamedPipeStream:
    deadline = time.monotonic() + timeout
    while True:
        handle = kernel32.CreateFileW(address, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)
        if handle != INVALID_HANDLE_VALUE:
            return NamedPipeStream(handle, False)
        code = ctypes.get_last_error()
        if code != ERROR_PIPE_BUSY or time.monotonic() >= deadline:
            raise _windows_error("named pipe connection failed")
        remaining = max(1, int((deadline - time.monotonic()) * 1000))
        kernel32.WaitNamedPipeW(address, remaining)
