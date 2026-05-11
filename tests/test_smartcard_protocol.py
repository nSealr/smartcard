import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nostrseal_smartcard.apdu import CommandAPDU, ResponseAPDU
from nostrseal_smartcard import cli as smartcard_cli
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
SMARTCARD_APDU_VECTORS = {
    path.stem: json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((SPECS / "vectors/smartcard").glob("*.json"))
}


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

    def test_simulator_matches_shared_apdu_error_status_vectors(self) -> None:
        simulator = SmartcardSimulator(KEY["secret_key"])
        rejection_vectors = [
            vector
            for vector in SMARTCARD_APDU_VECTORS.values()
            if "expected_status_word" in vector and "response_hex" in vector
        ]
        self.assertGreaterEqual(len(rejection_vectors), 3)

        for vector in rejection_vectors:
            with self.subTest(name=vector["name"]):
                command = CommandAPDU.from_bytes(bytes.fromhex(vector["command_hex"]))
                response = simulator.exchange(command)

                self.assertEqual(f"{response.status_word:04x}", vector["expected_status_word"])
                self.assertEqual(response.to_bytes().hex(), vector["response_hex"])

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

    def test_pcsc_transport_rejects_non_integer_response_data_bytes(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(([1.5], 0x90, 0x00))  # type: ignore[list-item]

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC response data bytes must fit in one byte"):
            transport.exchange(command)

    def test_pcsc_transport_rejects_missing_response_data(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection((None, 0x90, 0x00))  # type: ignore[arg-type]

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC response data must be a byte iterable"):
            transport.exchange(command)

    def test_pcsc_transport_rejects_malformed_transmit_result(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(None)  # type: ignore[arg-type]

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC transmit result must contain data, sw1, and sw2"):
            transport.exchange(command)

    def test_pcsc_transport_rejects_out_of_range_status_bytes(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(([], 0x100, 0x00))

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC status bytes must fit in one byte"):
            transport.exchange(command)

    def test_pcsc_transport_rejects_non_integer_status_bytes(self) -> None:
        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        connection = FakePcscConnection(([], 0x90, 0.5))  # type: ignore[arg-type]

        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(connection)])

        with self.assertRaisesRegex(ValueError, "PC/SC status bytes must fit in one byte"):
            transport.exchange(command)

    def test_pcsc_transport_fails_clearly_without_pcsc_provider(self) -> None:
        with self.assertRaisesRegex(PcscUnavailableError, "pyscard"):
            PcscTransport.from_first_reader(lambda: (_ for _ in ()).throw(ImportError("No module named smartcard")))

    def test_pcsc_transport_fails_clearly_without_readers(self) -> None:
        with self.assertRaisesRegex(PcscUnavailableError, "no PC/SC smartcard readers"):
            PcscTransport.from_first_reader(lambda: [])

    def test_pcsc_transport_fails_clearly_when_reader_provider_fails(self) -> None:
        def broken_provider() -> list[FakePcscReader]:
            raise RuntimeError("native provider missing")

        with self.assertRaisesRegex(PcscUnavailableError, "PC/SC reader provider failed"):
            PcscTransport.from_first_reader(broken_provider)

    def test_pcsc_transport_fails_clearly_when_reader_connection_fails(self) -> None:
        class BrokenReader:
            def createConnection(self) -> FakePcscConnection:
                raise RuntimeError("reader is locked")

        with self.assertRaisesRegex(PcscUnavailableError, "PC/SC reader connection failed"):
            PcscTransport.from_first_reader(lambda: [BrokenReader()])

    def test_pcsc_transport_fails_clearly_when_apdu_exchange_fails(self) -> None:
        class BrokenExchangeConnection:
            def connect(self) -> None:
                pass

            def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
                raise RuntimeError("card removed")

        command = CommandAPDU.from_bytes(bytes.fromhex(GET_PUBLIC_KEY_VECTOR["command_hex"]))
        transport = PcscTransport.from_first_reader(lambda: [FakePcscReader(BrokenExchangeConnection())])

        with self.assertRaisesRegex(PcscUnavailableError, "PC/SC APDU exchange failed"):
            transport.exchange(command)


class SmartcardCliTests(unittest.TestCase):
    def test_cli_sim_get_public_key_writes_apdu_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "public-key.json"

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nostrseal_smartcard",
                    "sim-get-public-key",
                    "--secret-key",
                    KEY["secret_key"],
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=True,
            )

            output = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(output["transport"], "simulator")
            self.assertEqual(output["command_hex"], GET_PUBLIC_KEY_VECTOR["command_hex"])
            self.assertEqual(output["response_hex"], GET_PUBLIC_KEY_VECTOR["response_hex"])
            self.assertEqual(output["status_word"], GET_PUBLIC_KEY_VECTOR["status_word"])
            self.assertEqual(output["public_key"], GET_PUBLIC_KEY_VECTOR["response_data_hex"])

    def test_cli_sim_sign_event_id_writes_apdu_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "signature.json"

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nostrseal_smartcard",
                    "sim-sign-event-id",
                    "--secret-key",
                    KEY["secret_key"],
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=True,
            )

            output = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(output["transport"], "simulator")
            self.assertEqual(output["command_hex"], SIGN_EVENT_ID_VECTOR["command_hex"])
            self.assertEqual(output["status_word"], SIGN_EVENT_ID_VECTOR["expected_status_word"])
            self.assertEqual(output["event_id"], SIGN_EVENT_ID_VECTOR["event_id"])
            self.assertEqual(len(output["signature"]), 128)
            self.assertTrue(
                verify_schnorr_signature(
                    SIGN_EVENT_ID_VECTOR["verification_pubkey"],
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    output["signature"],
                )
            )

    def test_cli_pcsc_get_public_key_fails_cleanly_without_pcsc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "public-key.json"

            with patch(
                "nostrseal_smartcard.cli.PcscTransport.from_first_reader",
                side_effect=PcscUnavailableError("pyscard is required for PC/SC transport"),
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                result = smartcard_cli.main(["pcsc-get-public-key", "--out", str(output_path)])

            self.assertEqual(result, 1)
            self.assertIn("pyscard is required for PC/SC transport", stderr.getvalue())
            self.assertFalse(output_path.exists())


class ProjectToolingTests(unittest.TestCase):
    def test_pyproject_exposes_smartcard_cli_entry_point(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[project.scripts]", pyproject)
        self.assertIn("nseal-smartcard", pyproject)

    def test_makefile_detects_pip_in_tree_build_support(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("PIP_IN_TREE_BUILD", makefile)
        self.assertIn("install --use-feature=in-tree-build --help", makefile)
        self.assertIn("install --disable-pip-version-check $$PIP_IN_TREE_BUILD .", makefile)


if __name__ == "__main__":
    unittest.main()
