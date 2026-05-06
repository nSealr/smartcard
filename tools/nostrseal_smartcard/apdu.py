from __future__ import annotations

from dataclasses import dataclass


def _byte(value: int, name: str) -> int:
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must fit in one byte")
    return value


@dataclass(frozen=True)
class CommandAPDU:
    cla: int
    ins: int
    p1: int = 0x00
    p2: int = 0x00
    data: bytes = b""
    le: int | None = None

    def to_bytes(self) -> bytes:
        header = bytes([
            _byte(self.cla, "cla"),
            _byte(self.ins, "ins"),
            _byte(self.p1, "p1"),
            _byte(self.p2, "p2"),
        ])
        if len(self.data) > 255:
            raise ValueError("short APDU data cannot exceed 255 bytes")
        body = b""
        if self.data:
            body += bytes([len(self.data)]) + self.data
        if self.le is not None:
            body += bytes([_byte(self.le, "le")])
        return header + body

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CommandAPDU":
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
        if not 0 <= self.status_word <= 0xFFFF:
            raise ValueError("status word must fit in two bytes")
        return self.data + self.status_word.to_bytes(2, "big")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResponseAPDU":
        if len(raw) < 2:
            raise ValueError("response APDU must contain a status word")
        return cls(raw[:-2], int.from_bytes(raw[-2:], "big"))
