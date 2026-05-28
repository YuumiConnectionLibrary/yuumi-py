from __future__ import annotations

import os
import struct
import threading
from typing import Any, Callable

from .protocol import build_handshake_packet, decode_payload, encode_payload
from .transport import dial_transport
from .types import Channel, Encoding, MAX_MESSAGE_SIZE, StatusCode, YuumiError

MessageHandler = Callable[[dict[str, Any], Channel], None]


class Client:
    def __init__(self, conn, encoding: Encoding = Encoding.JSON) -> None:
        self._conn = conn
        self._encoding = encoding
        self._running = False
        self._handler: MessageHandler | None = None
        self._lock = threading.Lock()
        self._read_thread: threading.Thread | None = None

    @classmethod
    def connect(cls, pipe_name: str, timeout: float = 5.0) -> "Client":
        conn = dial_transport(pipe_name, timeout=timeout)
        client = cls(conn)
        client._perform_handshake()
        return client

    def on_message(self, handler: MessageHandler) -> None:
        with self._lock:
            self._handler = handler

    def listen(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
            self._read_thread.start()

    def send(self, data: Any, channel: Channel = Channel.COMMAND) -> None:
        payload = encode_payload(data, self._encoding)
        header = struct.pack(">IBB", len(payload), int(channel), 0)
        try:
            self._conn.sendall(header + payload)
        except OSError as exc:
            raise YuumiError(StatusCode.ERR_WRITE_FAILED, f"Write failure: {exc}") from exc

    def receive(self) -> tuple[dict[str, Any], Channel]:
        header = self._recv_exact(6)
        length, raw_channel, _flags = struct.unpack(">IBB", header)
        if length > MAX_MESSAGE_SIZE:
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, "message too large")
        body = self._recv_exact(length)
        decoded = decode_payload(body, self._encoding)
        return decoded, Channel(raw_channel)

    def close(self) -> None:
        with self._lock:
            self._running = False
        try:
            self._conn.shutdown(2)
        except OSError:
            pass
        self._conn.close()

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

        selected = Encoding(ack[0])
        if selected not in (Encoding.JSON, Encoding.MSGPACK):
            raise YuumiError(StatusCode.ERR_PROTOCOL_VIOLATION, f"Handshake unknown encoding: 0x{int(selected):02x}")
        self._encoding = selected

        self._conn.settimeout(None)

    def _recv_exact(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            chunk = self._conn.recv(size - len(out))
            if not chunk:
                raise EOFError("connection closed")
            out.extend(chunk)
        return bytes(out)

    def _read_loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    return
                handler = self._handler
            try:
                payload, channel = self.receive()
            except (OSError, EOFError, YuumiError, ValueError):
                return
            if handler is not None:
                handler(payload, channel)


def connect(pipe_name: str, timeout: float = 5.0) -> Client:
    return Client.connect(pipe_name, timeout=timeout)
