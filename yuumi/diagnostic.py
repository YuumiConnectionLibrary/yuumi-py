from .types import StatusCode


class Diagnostic:
    """Structured logging utility — mirrors C++ yuumi::Diagnostic."""

    @staticmethod
    def log(code: StatusCode, message: str) -> None:
        print(f"[YUUMI][{int(code)}] {message}")

    @staticmethod
    def error(code: StatusCode, details: str = "") -> None:
        print(f"[YUUMI_ERR][{int(code)}] Error detected. Details: {details}")

    @staticmethod
    def success(message: str) -> None:
        print(f"[YUUMI_SUCCESS] {message}")
