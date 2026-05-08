from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from .apdu import CommandAPDU, ResponseAPDU


class PcscUnavailableError(RuntimeError):
    """Raised when PC/SC transport prerequisites are not available."""


class PcscConnection(Protocol):
    def connect(self) -> None:
        ...

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        ...


class PcscReader(Protocol):
    def createConnection(self) -> PcscConnection:
        ...


ReadersProvider = Callable[[], Iterable[PcscReader]]


def _require_pcsc_byte(value: int, message: str) -> int:
    if value < 0 or value > 0xFF:
        raise ValueError(message)
    return value


def _pyscard_readers() -> Iterable[PcscReader]:
    try:
        from smartcard.System import readers
    except ImportError as error:
        raise PcscUnavailableError("pyscard is required for PC/SC transport") from error
    return readers()


@dataclass(frozen=True)
class PcscTransport:
    connection: PcscConnection

    @classmethod
    def from_first_reader(cls, readers_provider: ReadersProvider | None = None) -> "PcscTransport":
        provider = readers_provider or _pyscard_readers
        try:
            reader_list = list(provider())
        except ImportError as error:
            raise PcscUnavailableError("pyscard is required for PC/SC transport") from error
        if not reader_list:
            raise PcscUnavailableError("no PC/SC smartcard readers found")

        connection = reader_list[0].createConnection()
        connection.connect()
        return cls(connection)

    def exchange(self, command: CommandAPDU) -> ResponseAPDU:
        data, sw1, sw2 = self.connection.transmit(list(command.to_bytes()))
        response_data = bytes(
            _require_pcsc_byte(byte, "PC/SC response data bytes must fit in one byte")
            for byte in data
        )
        status_word = (
            _require_pcsc_byte(sw1, "PC/SC status bytes must fit in one byte") << 8
        ) | _require_pcsc_byte(sw2, "PC/SC status bytes must fit in one byte")
        return ResponseAPDU(response_data, status_word)
