import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nsealr_smartcard.apdu import CommandAPDU, ResponseAPDU
from nsealr_smartcard import cli as smartcard_cli
from nsealr_smartcard.pcsc import PcscTransport, PcscUnavailableError
from nsealr_smartcard.protocol import (
    INS_GET_PUBLIC_KEY,
    INS_SIGN_EVENT_ID,
    NSEALR_CLA,
    SW_NO_ERROR,
)
from nsealr_smartcard.simulator import SmartcardSimulator, verify_schnorr_signature


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
APPROVAL_DIGEST = "a09ddd564e439fdd4756da6863156eddcfc50c295af453af1c78c35986c303a5"
SMARTCARD_APDU_VECTORS = {
    path.stem: json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((SPECS / "vectors/smartcard").glob("*.json"))
}
SMARTCARD_ACCOUNT = json.loads(
    (SPECS / "vectors/accounts/smartcard-slot-0.json").read_text(encoding="utf-8")
)
SMARTCARD_POLICY = json.loads(
    (SPECS / "vectors/policies/manual-only-displayless-smartcard.json").read_text(encoding="utf-8")
)
SMARTCARD_ROUTE_SELECTION = json.loads(
    (SPECS / "vectors/route-selections/smartcard-sign-event-slot-0.json").read_text(encoding="utf-8")
)


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
    def test_docs_keep_smartcard_identity_policy_boundary_displayless(self) -> None:
        route = SMARTCARD_ACCOUNT["signer_route"]
        selection = SMARTCARD_ROUTE_SELECTION["selection"]

        self.assertEqual(SMARTCARD_ACCOUNT["signer_route"]["type"], "smartcard")
        self.assertEqual(route["repository"], "smartcard")
        self.assertEqual(route["transport"], "smartcard")
        self.assertEqual(route["custody"], "card_persistent")
        self.assertEqual(route["trusted_review"], "display_less")
        self.assertEqual(route["policy_support"], "manual_only")
        self.assertFalse(SMARTCARD_ACCOUNT["capabilities"]["physical_review"])
        self.assertFalse(SMARTCARD_ACCOUNT["capabilities"]["physical_approval"])
        self.assertFalse(SMARTCARD_ACCOUNT["capabilities"]["persistent_grants"])
        self.assertEqual(SMARTCARD_POLICY["policy_id"], SMARTCARD_ACCOUNT["policy_profile_id"])
        self.assertEqual(SMARTCARD_POLICY["mode"], "manual_only")
        self.assertFalse(SMARTCARD_POLICY["grants_allowed"])
        self.assertEqual(selection["account_id"], SMARTCARD_ACCOUNT["account_id"])
        self.assertEqual(selection["route_type"], route["type"])
        self.assertEqual(selection["repository"], route["repository"])
        self.assertEqual(selection["transport"], route["transport"])
        self.assertEqual(selection["custody"], route["custody"])
        self.assertEqual(selection["trusted_review"], route["trusted_review"])
        self.assertEqual(selection["policy_support"], route["policy_support"])
        self.assertFalse(selection["physical_review"])
        self.assertFalse(selection["physical_approval"])
        self.assertFalse(selection["persistent_grants"])
        self.assertFalse(selection["contains_secret_material"])

        docs = "\n".join(
            [
                (ROOT / "README.md").read_text(encoding="utf-8"),
                (ROOT / "docs/architecture.md").read_text(encoding="utf-8"),
                (ROOT / "docs/roadmap.md").read_text(encoding="utf-8"),
                (ROOT / "docs/testing.md").read_text(encoding="utf-8"),
            ]
        )

        self.assertIn("nsealr-account-descriptor-v0", docs)
        self.assertIn("smartcard-slot-0", docs)
        self.assertIn("smartcard-sign-event-slot-0", docs)
        self.assertIn("policy-manual-only-displayless-smartcard", docs)
        self.assertIn("external review acknowledgement", docs)
        self.assertIn("approval_digest", docs)
        self.assertIn("display-less", docs)
        self.assertIn("manual-only", docs)
        self.assertIn("cannot provide trusted event review by itself", docs.replace("\n", " "))
        self.assertNotIn("provides trusted event review by itself", docs.lower())

    def test_short_apdu_encoding_round_trip(self) -> None:
        command = CommandAPDU(NSEALR_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes.fromhex(SIGN_EVENT_ID_VECTOR["event_id"]))
        encoded = command.to_bytes()

        self.assertEqual(encoded.hex(), SIGN_EVENT_ID_VECTOR["command_hex"])
        self.assertEqual(encoded[:5], bytes([NSEALR_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, 32]))
        self.assertEqual(CommandAPDU.from_bytes(encoded), command)

    def test_short_apdu_rejects_oversized_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "short APDU data cannot exceed 255 bytes"):
            CommandAPDU(NSEALR_CLA, INS_SIGN_EVENT_ID, 0x00, 0x00, bytes(256)).to_bytes()

    def test_short_apdu_rejects_non_integer_header_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "cla must be an integer byte"):
            CommandAPDU(0.5, INS_SIGN_EVENT_ID).to_bytes()  # type: ignore[arg-type]

    def test_short_apdu_rejects_bool_header_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "cla must be an integer byte"):
            CommandAPDU(True, INS_SIGN_EVENT_ID).to_bytes()  # type: ignore[arg-type]

    def test_short_apdu_rejects_non_bytes_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "command APDU data must be bytes"):
            CommandAPDU(NSEALR_CLA, INS_SIGN_EVENT_ID, data=[0x00]).to_bytes()  # type: ignore[arg-type]

    def test_response_apdu_rejects_non_integer_status_words(self) -> None:
        with self.assertRaisesRegex(ValueError, "status word must be an integer word"):
            ResponseAPDU(status_word=True).to_bytes()  # type: ignore[arg-type]

    def test_response_apdu_rejects_non_bytes_payloads(self) -> None:
        with self.assertRaisesRegex(ValueError, "response APDU data must be bytes"):
            ResponseAPDU(data=[0x00]).to_bytes()  # type: ignore[arg-type]

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
                    "nsealr_smartcard",
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

    def test_cli_rejects_existing_output_before_simulator_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "public-key.json"
            output_path.write_text("existing\n", encoding="utf-8")

            with patch("nsealr_smartcard.cli.SmartcardSimulator") as simulator_class, patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as stderr:
                result = smartcard_cli.main([
                    "sim-get-public-key",
                    "--secret-key",
                    KEY["secret_key"],
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("output path already exists", stderr.getvalue())
            self.assertEqual(output_path.read_text(encoding="utf-8"), "existing\n")
            simulator_class.assert_not_called()

    def test_cli_rejects_missing_output_parent_before_simulator_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "missing" / "public-key.json"

            with patch("nsealr_smartcard.cli.SmartcardSimulator") as simulator_class, patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as stderr:
                result = smartcard_cli.main([
                    "sim-get-public-key",
                    "--secret-key",
                    KEY["secret_key"],
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("output parent directory does not exist", stderr.getvalue())
            self.assertFalse(output_path.exists())
            simulator_class.assert_not_called()

    def test_cli_sim_exchange_apdu_matches_shared_fixed_response_vectors(self) -> None:
        fixed_response_vectors = [
            vector
            for vector in SMARTCARD_APDU_VECTORS.values()
            if "command_hex" in vector and "response_hex" in vector
        ]
        self.assertGreaterEqual(len(fixed_response_vectors), 7)

        with tempfile.TemporaryDirectory() as temp_root:
            for vector in fixed_response_vectors:
                with self.subTest(name=vector["name"]):
                    output_path = Path(temp_root) / f"{vector['name']}.json"

                    subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "nsealr_smartcard",
                            "sim-exchange-apdu",
                            "--secret-key",
                            KEY["secret_key"],
                            "--command-hex",
                            vector["command_hex"],
                            "--out",
                            str(output_path),
                        ],
                        cwd=ROOT,
                        check=True,
                    )

                    output = json.loads(output_path.read_text(encoding="utf-8"))
                    expected_status = vector.get("expected_status_word", vector.get("status_word"))
                    self.assertEqual(output["transport"], "simulator")
                    self.assertEqual(output["command_hex"], vector["command_hex"])
                    self.assertEqual(output["response_hex"], vector["response_hex"])
                    self.assertEqual(output["status_word"], expected_status)

    def test_cli_sim_exchange_apdu_rejects_malformed_command_hex_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "apdu.json"

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nsealr_smartcard",
                    "sim-exchange-apdu",
                    "--secret-key",
                    KEY["secret_key"],
                    "--command-hex",
                    "8010000",
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("command hex must be even-length lowercase hex", result.stderr)
            self.assertFalse(output_path.exists())

    def test_cli_sim_sign_event_id_writes_apdu_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "signature.json"

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nsealr_smartcard",
                    "sim-sign-event-id",
                    "--secret-key",
                    KEY["secret_key"],
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    APPROVAL_DIGEST,
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
            self.assertEqual(output["expected_public_key"], GET_PUBLIC_KEY_VECTOR["response_data_hex"])
            self.assertEqual(output["trusted_review"], "external")
            self.assertTrue(output["review_acknowledged"])
            self.assertEqual(output["approval_digest"], APPROVAL_DIGEST)
            self.assertEqual(len(output["signature"]), 128)
            self.assertTrue(output["signature_verified"])
            self.assertTrue(
                verify_schnorr_signature(
                    SIGN_EVENT_ID_VECTOR["verification_pubkey"],
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    output["signature"],
                )
            )

    def test_cli_sim_sign_event_id_rejects_unverifiable_signature_without_output(self) -> None:
        class BadSignatureSimulator:
            def __init__(self, secret_key: str) -> None:
                self.secret_key = secret_key

            def exchange(self, command: CommandAPDU) -> ResponseAPDU:
                return ResponseAPDU(bytes(64), SW_NO_ERROR)

        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "signature.json"

            with patch("nsealr_smartcard.cli.SmartcardSimulator", BadSignatureSimulator), patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as stderr:
                result = smartcard_cli.main([
                    "sim-sign-event-id",
                    "--secret-key",
                    KEY["secret_key"],
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    APPROVAL_DIGEST,
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("SIGN_EVENT_ID signature verification failed", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_cli_sim_sign_event_id_requires_external_review_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "signature.json"

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nsealr_smartcard",
                    "sim-sign-event-id",
                    "--secret-key",
                    KEY["secret_key"],
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--approval-digest",
                    APPROVAL_DIGEST,
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--review-acknowledged", result.stderr)
            self.assertFalse(output_path.exists())

    def test_cli_sim_sign_event_id_rejects_malformed_approval_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "signature.json"

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nsealr_smartcard",
                    "sim-sign-event-id",
                    "--secret-key",
                    KEY["secret_key"],
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    "A" * 64,
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("approval digest must be 32-byte lowercase hex", result.stderr)
            self.assertFalse(output_path.exists())

    def test_cli_pcsc_get_public_key_fails_cleanly_without_pcsc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "public-key.json"

            with patch(
                "nsealr_smartcard.cli.PcscTransport.from_first_reader",
                side_effect=PcscUnavailableError("pyscard is required for PC/SC transport"),
            ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                result = smartcard_cli.main(["pcsc-get-public-key", "--out", str(output_path)])

            self.assertEqual(result, 1)
            self.assertIn("pyscard is required for PC/SC transport", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_cli_rejects_existing_output_before_pcsc_reader_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "public-key.json"
            output_path.write_text("existing\n", encoding="utf-8")

            with patch("nsealr_smartcard.cli.PcscTransport.from_first_reader") as from_first_reader, patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as stderr:
                result = smartcard_cli.main(["pcsc-get-public-key", "--out", str(output_path)])

            self.assertEqual(result, 1)
            self.assertIn("output path already exists", stderr.getvalue())
            self.assertEqual(output_path.read_text(encoding="utf-8"), "existing\n")
            from_first_reader.assert_not_called()

    def test_cli_pcsc_sign_event_id_writes_verified_signature_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "pcsc-signature.json"
            command = CommandAPDU.from_bytes(bytes.fromhex(SIGN_EVENT_ID_VECTOR["command_hex"]))
            simulator_response = SmartcardSimulator(KEY["secret_key"]).exchange(command)
            transport = PcscTransport.from_first_reader(lambda: [
                FakePcscReader(FakePcscConnection((list(simulator_response.data), 0x90, 0x00)))
            ])

            with patch("nsealr_smartcard.cli.PcscTransport.from_first_reader", return_value=transport):
                result = smartcard_cli.main([
                    "pcsc-sign-event-id",
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    APPROVAL_DIGEST,
                    "--expected-public-key",
                    GET_PUBLIC_KEY_VECTOR["response_data_hex"],
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 0)
            output = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(output["transport"], "pcsc")
            self.assertEqual(output["event_id"], SIGN_EVENT_ID_VECTOR["event_id"])
            self.assertEqual(output["expected_public_key"], GET_PUBLIC_KEY_VECTOR["response_data_hex"])
            self.assertEqual(output["approval_digest"], APPROVAL_DIGEST)
            self.assertEqual(output["trusted_review"], "external")
            self.assertTrue(output["review_acknowledged"])
            self.assertTrue(output["signature_verified"])
            self.assertTrue(
                verify_schnorr_signature(
                    GET_PUBLIC_KEY_VECTOR["response_data_hex"],
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    output["signature"],
                )
            )

    def test_cli_pcsc_sign_event_id_requires_expected_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "pcsc-signature.json"

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "nsealr_smartcard",
                    "pcsc-sign-event-id",
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    APPROVAL_DIGEST,
                    "--out",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--expected-public-key", result.stderr)
            self.assertFalse(output_path.exists())

    def test_cli_pcsc_sign_event_id_rejects_unverifiable_signature_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "pcsc-signature.json"
            transport = PcscTransport.from_first_reader(lambda: [
                FakePcscReader(FakePcscConnection((list(bytes(64)), 0x90, 0x00)))
            ])

            with patch("nsealr_smartcard.cli.PcscTransport.from_first_reader", return_value=transport), patch(
                "sys.stderr",
                new_callable=io.StringIO,
            ) as stderr:
                result = smartcard_cli.main([
                    "pcsc-sign-event-id",
                    "--event-id",
                    SIGN_EVENT_ID_VECTOR["event_id"],
                    "--review-acknowledged",
                    "--approval-digest",
                    APPROVAL_DIGEST,
                    "--expected-public-key",
                    GET_PUBLIC_KEY_VECTOR["response_data_hex"],
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("SIGN_EVENT_ID signature verification failed", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_cli_pcsc_exchange_apdu_writes_raw_apdu_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_root:
            output_path = Path(temp_root) / "pcsc-apdu.json"
            transport = PcscTransport.from_first_reader(lambda: [
                FakePcscReader(FakePcscConnection(([], 0x6A, 0x86)))
            ])

            with patch("nsealr_smartcard.cli.PcscTransport.from_first_reader", return_value=transport):
                result = smartcard_cli.main([
                    "pcsc-exchange-apdu",
                    "--command-hex",
                    SMARTCARD_APDU_VECTORS["get-public-key-nonzero-p1"]["command_hex"],
                    "--out",
                    str(output_path),
                ])

            self.assertEqual(result, 0)
            output = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(output["transport"], "pcsc")
            self.assertEqual(output["command_hex"], SMARTCARD_APDU_VECTORS["get-public-key-nonzero-p1"]["command_hex"])
            self.assertEqual(output["response_hex"], SMARTCARD_APDU_VECTORS["get-public-key-nonzero-p1"]["response_hex"])
            self.assertEqual(output["status_word"], SMARTCARD_APDU_VECTORS["get-public-key-nonzero-p1"]["expected_status_word"])


class ProjectToolingTests(unittest.TestCase):
    def test_pyproject_exposes_smartcard_cli_entry_point(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[project.scripts]", pyproject)
        self.assertIn("nsealr-smartcard", pyproject)

    def test_makefile_detects_pip_in_tree_build_support(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("PIP_IN_TREE_BUILD", makefile)
        self.assertIn("install --use-feature=in-tree-build --help", makefile)
        self.assertIn("install --disable-pip-version-check $$PIP_IN_TREE_BUILD .", makefile)


if __name__ == "__main__":
    unittest.main()
