import json
import unittest
from pathlib import Path

from nostrseal_smartcard.apdu import CommandAPDU, ResponseAPDU
from nostrseal_smartcard.pcsc import PcscTransport, PcscUnavailableError
from nostrseal_smartcard.protocol import (
    INS_GET_PUBLIC_KEY,
    INS_SIGN_EVENT_ID,
    NOSTRSEAL_CLA,
    SW_NO_ERROR,
)
from nostrseal_smartcard.simulator import SmartcardSimulator, verify_schnorr_signature


ROOT = Path(__file__).resolve().parents[1]


def specs_dir() -> Path:
    sibling = ROOT.parent / "specs"
    if sibling.exists():
        return sibling
    return ROOT / "tests/fixtures/specs"


SPECS = specs_dir()
KEY = json.loads((SPECS / "vectors/keys/test-key-1.json").read_text(encoding="utf-8"))
BASIC_VECTOR = json.loads((SPECS / "vectors/events/kind-1-basic.json").read_text(encoding="utf-8"))
GET_PUBLIC_KEY_VECTOR = json.loads((SPECS / "vectors/smartcard/get-public-key.json").read_text(encoding="utf-8"))
SIGN_EVENT_ID_VECTOR = json.loads((SPECS / "vectors/smartcard/sign-event-id-kind-1-basic.json").read_text(encoding="utf-8"))


class FakePcscConnection:
    def __init__(self, response: tuple[list[int], int, int]) -> None:
        self.response = response
        self.connected = False
        self.transmitted: bytes | None = None

    def connect(self) -> None:
        self.connected = True

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        self.transmitted = bytes(command)
        return self.response


class FakePcscReader:
    def __init__(self, connection: FakePcscConnection) -> None:
        self.connection = connection

    def createConnection(self) -> FakePcscConnection:
        return self.connection


class SmartcardProtocolTests(unittest.TestCase):
    def test_short_apdu_encoding_round_trip(self) -> None:
        command = CommandAPDU(NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes.fromhex(SIGN_EVENT_ID_VECTOR["event_id"]))
        encoded = command.to_bytes()

        self.assertEqual(encoded.hex(), SIGN_EVENT_ID_VECTOR["command_hex"])
        self.assertEqual(encoded[:5], bytes([NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, 32]))
        self.assertEqual(CommandAPDU.from_bytes(encoded), command)

    def test_short_apdu_rejects_oversized_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "short APDU data cannot exceed 255 bytes"):
            CommandAPDU(NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes(256)).to_bytes()

    def test_get_public_key_apdu(self) -> None:
        simulator = SmartcardSimulator(KEY["secret_key"])
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        response = simulator.exchange(command)

        self.assertEqual(response.status_word, SW_NO_ERROR)
        self.assertEqual(response.data.hex(), GET_PUBLIC_KEY_VECTOR["response_data_hex"])
        self.assertEqual(response.to_bytes().hex(), GET_PUBLIC_KEY_VECTOR["response_hex"])
        self.assertEqual(ResponseAPDU.from_bytes(response.to_bytes()), response)

    def test_sign_event_id_apdu_returns_valid_schnorr_signature(self) -> None:
        simulator = SmartcardSimulator(KEY["secret_key"])
        command = CommandAPDU.from_bytes(bytes.fromhex(SIGN_EVENT_ID_VECTOR["command_hex"]))
        response = simulator.exchange(command)

        self.assertEqual(response.status_word, SW_NO_ERROR)
        self.assertEqual(f"{response.status_word:04x}", SIGN_EVENT_ID_VECTOR["expected_status_word"])
        self.assertEqual(len(response.data), SIGN_EVENT_ID_VECTOR["expected_data_length"])
        self.assertTrue(
            verify_schnorr_signature(
                SIGN_EVENT_ID_VECTOR["verification_pubkey"],
                SIGN_EVENT_ID_VECTOR["event_id"],
                response.data.hex(),
            )
        )

    def test_pcsc_transport_exchanges_short_apdus_with_connection(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection((
            list(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["response_data_hex"])),
            0x90,
            0x00,
        ))

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])
        response = transport.exchange(command)

        self.assertTrue(connection.connected)
        self.assertEqual(connection.transmitted, command.to_bytes())
        self.assertEqual(response, ResponseAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["response_hex"])))

    def test_pcsc_transport_rejects_out_of_range_response_data_bytes(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(([0x100], 0x90, 0x00))

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC response data bytes must fit in one byte"):
            transport.exchange(command)

    def test_pcsc_transport_rejects_out_of_range_status_bytes(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(([], 0x100, 0x00))

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC status bytes must fit in one byte"):
            transport.exchange(command)

    def test_pcsc_transport_fails_clearly_without_pcsc_provider(self) -> None:
        with self.assertRaisesRegex(PcscUnavailableError, "pyscard"):
            PcscTransport.from_first_reader(lambda: (_ for _ in ()).throw(ImportError("No module named smartcard")))

    def test_pcsc_transport_fails_clearly_without_readers(self) -> None:
        with self.assertRaisesRegex(PcscUnavailableError, "no PC/SC smartcard readers"):
            PcscTransport.from_first_reader(lambda: [])


if __name__ == "__main__":
    unittest.main()
