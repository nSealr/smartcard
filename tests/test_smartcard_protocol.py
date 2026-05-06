import json
import unittest
from pathlib import Path

from nostrseal_smartcard.apdu import CommandAPDU, ResponseAPDU
from nostrseal_smartcard.protocol import (
    INS_GET_PUBLIC_KEY,
    INS_SIGN_EVENT_ID,
    NOSTRSEAL_CLA,
    SW_NO_ERROR,
)
from nostrseal_smartcard.simulator import SmartcardSimulator, verify_schnorr_signature


ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT.parent / "specs"
KEY = json.loads((SPECS / "vectors/keys/test-key-1.json").read_text(encoding="utf-8"))
BASIC_VECTOR = json.loads((SPECS / "vectors/events/kind-1-basic.json").read_text(encoding="utf-8"))


class SmartcardProtocolTests(unittest.TestCase):
    def test_short_apdu_encoding_round_trip(self) -> None:
        command = CommandAPDU(NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes.fromhex(BASIC_VECTOR["event_id"]))
        encoded = command.to_bytes()

        self.assertEqual(encoded[:5], bytes([NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, 32]))
        self.assertEqual(CommandAPDU.from_bytes(encoded), command)

    def test_short_apdu_rejects_oversized_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "short APDU data cannot exceed 255 bytes"):
            CommandAPDU(NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes(256)).to_bytes()

    def test_get_public_key_apdu(self) -> None:
        simulator = SmartcardSimulator(KEY["secret_key"])
        response = simulator.exchange(CommandAPDU(NOSTRSEAL_CLA, INS_GET_PUBLIC_KEY))

        self.assertEqual(response.status_word, SW_NO_ERROR)
        self.assertEqual(response.data.hex(), KEY["public_key"])
        self.assertEqual(ResponseAPDU.from_bytes(response.to_bytes()), response)

    def test_sign_event_id_apdu_returns_valid_schnorr_signature(self) -> None:
        simulator = SmartcardSimulator(KEY["secret_key"])
        response = simulator.exchange(
            CommandAPDU(NOSTRSEAL_CLA, INS_SIGN_EVENT_ID, data=bytes.fromhex(BASIC_VECTOR["event_id"]))
        )

        self.assertEqual(response.status_word, SW_NO_ERROR)
        self.assertEqual(len(response.data), 64)
        self.assertTrue(verify_schnorr_signature(KEY["public_key"], BASIC_VECTOR["event_id"], response.data.hex()))


if __name__ == "__main__":
    unittest.main()
