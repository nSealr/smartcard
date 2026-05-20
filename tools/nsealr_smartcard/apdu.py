from __future__ import annotations

from dataclasses import dataclass


def _byte(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer byte")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must fit in one byte")
    return value


def _word(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer word")
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must fit in two bytes")
    return value


def _bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    return bytes(value)


@dataclass(frozen=True)
class CommandAPDU:
    cla: int
    ins: int
    p1: int = 0x00
    p2: int = 0x00
    data: bytes = b""
    le: int | None = None

    def to_bytes(self) -> bytes:
        data = _bytes(self.data, "command APDU data")
        header = bytes([
            _byte(self.cla, "cla"),
            _byte(self.ins, "ins"),
            _byte(self.p1, "p1"),
            _byte(self.p2, "p2"),
        ])
        if len(data) > 255:
            raise ValueError("short APDU data cannot exceed 255 bytes")
        body = b""
        if data:
            body += bytes([len(data)]) + data
        if self.le is not None:
            body += bytes([_byte(self.le, "le")])
        return header + body

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CommandAPDU":
        raw = _bytes(raw, "command APDU")
        if len(raw) < 4:
            raise ValueError("command APDU must contain at least four header bytes")
        cla, ins, p1, p2 = raw[:4]
        rest = raw[4:]
        if not rest:
            return cls(cla, ins, p1, p2)
        lc = rest[0]
        if len(rest) == 1:
            return cls(cla, ins, p1, p2, le=lc)
        if len(rest) < 1 + lc:
            raise ValueError("command APDU data is shorter than Lc")
        data = rest[1 : 1 + lc]
        tail = rest[1 + lc :]
        if len(tail) > 1:
            raise ValueError("short APDU supports at most one Le byte")
        return cls(cla, ins, p1, p2, data, tail[0] if tail else None)


@dataclass(frozen=True)
class ResponseAPDU:
    data: bytes = b""
    status_word: int = 0x9000

    def to_bytes(self) -> bytes:
        data = _bytes(self.data, "response APDU data")
        return data + _word(self.status_word, "status word").to_bytes(2, "big")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResponseAPDU":
        raw = _bytes(raw, "response APDU")
        if len(raw) < 2:
            raise ValueError("response APDU must contain a status word")
        return cls(raw[:-2], int.from_bytes(raw[-2:], "big"))
