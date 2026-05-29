from __future__ import annotations

import os
import random
import struct
import threading
import time
from typing import Any, Callable

from .protocol import build_handshake_packet, decode_payload, encode_payload
from .transport import dial_transport
from .types import Channel, Encoding, MAX_MESSAGE_SIZE, ReconnectPolicy, StatusCode, YuumiError

MessageHandler = Callable[[dict[str, Any], Channel], None]
HeartbeatHandler = Callable[[int], None]
ErrorHandler = Callable[["YuumiError"], None]


def _heartbeat_ts(payload: dict[str, Any]) -> int | None:
    if payload.get("type") != "heartbeat":
        return None
    ts = payload.get("ts")
    if ts is None:
        return None
    try:
        return int(ts)
    except (TypeError, ValueError):
        return None


def _backoff_delay(attempt: int, policy: ReconnectPolicy) -> float:
    base = policy.initial_delay * (2.0 ** (attempt - 1))
    base = min(base, policy.max_delay)
    jitter_half = base * policy.jitter
    return max(0.0, base + random.uniform(-jitter_half, jitter_half))


class Client:
    def __init__(self, conn, encoding: Encoding = Encoding.JSON) -> None:
        self._conn = conn
        self._encoding = encoding
        self._running = False
        self._handler: MessageHandler | None = None
        self._heartbeat_handler: HeartbeatHandler | None = None
        self._error_handler: ErrorHandler | None = None
        self._state_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._read_thread: threading.Thread | None = None

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def connect(cls, pipe_name: str, timeout: float = 5.0) -> "Client":
        conn = dial_transport(pipe_name, timeout=timeout)
        client = cls(conn)
        client._perform_handshake()
        return client

    @classmethod
    def connect_with_policy(cls, pipe_name: str, policy: ReconnectPolicy, timeout: float = 5.0) -> "Client":
        if policy.max_attempts <= 0:
            return cls.connect(pipe_name, timeout=timeout)
        last_err: Exception | None = None
        for attempt in range(1, policy.max_attempts + 1):
            try:
                return cls.connect(pipe_name, timeout=timeout)
            except YuumiError as exc:
                last_err = exc
                if attempt < policy.max_attempts:
                    time.sleep(_backoff_delay(attempt, policy))
        raise last_err  # type: ignore[misc]

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def on_message(self, handler: MessageHandler) -> None:
        with self._state_lock:
            self._handler = handler

    def on_heartbeat(self, handler: HeartbeatHandler) -> None:
        with self._state_lock:
            self._heartbeat_handler = handler

    def on_error(self, handler: ErrorHandler) -> None:
        with self._state_lock:
            self._error_handler = handler

    # ── I/O ──────────────────────────────────────────────────────────────────

    def listen(self) -> None:
        with self._state_lock:
            if self._running:
                return
            self._running = True
            self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
            self._read_thread.start()

    def send(self, data: Any, channel: Channel = Channel.COMMAND) -> None:
        payload = encode_payload(data, self._encoding)
        header = struct.pack(">IBB", len(payload), int(channel), 0)
        with self._send_lock:
            try:
                self._conn.sendall(header + payload)
            except OSError as exc:
                raise YuumiError(StatusCode.ERR_WRITE_FAILED, f"Write failure: {exc}") from exc

    def receive(self) -> tuple[dict[str, Any], Channel]:
        header = self._recv_exact(6)
        length, raw_channel, flags = struct.unpack(">IBB", header)
        if flags != 0:
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, f"frame flags must be 0x00, got 0x{flags:02x}")
        if length > MAX_MESSAGE_SIZE:
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, "message too large")
        body = self._recv_exact(length)
        decoded = decode_payload(body, self._encoding)
        return decoded, Channel(raw_channel)

    def close(self) -> None:
        with self._state_lock:
            self._running = False
        try:
            self._conn.shutdown(2)
        except OSError:
            pass
        self._conn.close()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _perform_handshake(self) -> None:
        packet = build_handshake_packet(os.getpid())
        try:
            self._conn.sendall(packet)
        except OSError as exc:
            raise YuumiError(StatusCode.ERR_WRITE_FAILED, f"Handshake write failed: {exc}") from exc

        try:
            ack = self._recv_exact(4)
        except (OSError, EOFError) as exc:
            raise YuumiError(StatusCode.ERR_MAGIC_MISMATCH, f"Handshake ACK not received: {exc}") from exc

        if ack[1] != 0 or ack[2] != 0 or ack[3] != 0:
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, "ACK reserved bytes must be 0x00")

        selected_byte = ack[0]
        if selected_byte not in (int(Encoding.JSON), int(Encoding.MSGPACK)):
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, f"Handshake unknown encoding: 0x{selected_byte:02x}")
        self._encoding = Encoding(selected_byte)

        self._conn.settimeout(None)

    def _recv_exact(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            chunk = self._conn.recv(size - len(out))
            if not chunk:
                raise EOFError("connection closed")
            out.extend(chunk)
        return bytes(out)

    def _notify_error(self, error: YuumiError) -> None:
        with self._state_lock:
            handler = self._error_handler
        if handler is not None:
            handler(error)

    def _read_loop(self) -> None:
        while True:
            with self._state_lock:
                if not self._running:
                    return
            try:
                payload, channel = self.receive()
            except YuumiError as exc:
                self._notify_error(exc)
                return
            except (OSError, EOFError, ValueError):
                self._notify_error(YuumiError(StatusCode.ERR_CONNECTION_LOST, "connection closed"))
                return

            with self._state_lock:
                msg_handler = self._handler
                hb_handler = self._heartbeat_handler

            if channel == Channel.CONTROL:
                ts = _heartbeat_ts(payload)
                if ts is not None:
                    if hb_handler is not None:
                        hb_handler(ts)
                    continue

            if msg_handler is not None:
                msg_handler(payload, channel)


def connect(pipe_name: str, policy: ReconnectPolicy | None = None, timeout: float = 5.0) -> Client:
    if policy is not None and policy.max_attempts > 0:
        return Client.connect_with_policy(pipe_name, policy, timeout=timeout)
    return Client.connect(pipe_name, timeout=timeout)

