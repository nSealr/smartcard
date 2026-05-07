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
        return ResponseAPDU(bytes(data), (sw1 << 8) | sw2)
