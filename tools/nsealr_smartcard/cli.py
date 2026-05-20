from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .apdu import CommandAPDU, ResponseAPDU
from .pcsc import PcscTransport, PcscUnavailableError
from .protocol import INS_GET_PUBLIC_KEY, INS_SIGN_EVENT_ID, NSEALR_CLA, SW_NO_ERROR
from .simulator import SmartcardSimulator, verify_schnorr_signature, xonly_pubkey_from_secret


def _hex32(value: str, label: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise argparse.ArgumentTypeError(f"{label} must be 32-byte lowercase hex")
    return value


def _secret_key(value: str) -> str:
    return _hex32(value, "secret key")


def _event_id(value: str) -> str:
    return _hex32(value, "event id")


def _approval_digest(value: str) -> str:
    return _hex32(value, "approval digest")


def _public_key(value: str) -> str:
    return _hex32(value, "public key")


def _command_hex(value: str) -> str:
    if len(value) < 8 or len(value) % 2 != 0 or any(char not in "0123456789abcdef" for char in value):
        raise argparse.ArgumentTypeError("command hex must be even-length lowercase hex with at least four APDU header bytes")
    return value


def _prepare_output_path(path: Path) -> None:
    if path.exists():
        raise ValueError(f"output path already exists: {path}")
    parent = path.parent
    if not parent.exists():
        raise ValueError(f"output parent directory does not exist: {parent}")
    if not parent.is_dir():
        raise ValueError(f"output parent path is not a directory: {parent}")


def _write_json(path: Path, value: dict[str, object]) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(payload)
    except FileExistsError:
        raise ValueError(f"output path already exists: {path}") from None
    except FileNotFoundError:
        raise ValueError(f"output parent directory does not exist: {path.parent}") from None
    except IsADirectoryError:
        raise ValueError(f"output path is a directory: {path}") from None


def _status_word(response: ResponseAPDU) -> str:
    return f"{response.status_word:04x}"


def _get_public_key_command() -> CommandAPDU:
    return CommandAPDU(NSEALR_CLA, INS_GET_PUBLIC_KEY)


def _sign_event_id_command(event_id: str) -> CommandAPDU:
    return CommandAPDU(NSEALR_CLA, INS_SIGN_EVENT_ID, data=bytes.fromhex(event_id))


def _command_from_hex(command_hex: str) -> CommandAPDU:
    return CommandAPDU.from_bytes(bytes.fromhex(command_hex))


def _apdu_exchange_report(transport: str, command: CommandAPDU, response: ResponseAPDU) -> dict[str, object]:
    report: dict[str, object] = {
        "transport": transport,
        "command_hex": command.to_bytes().hex(),
        "response_hex": response.to_bytes().hex(),
        "status_word": _status_word(response),
    }
    if response.data:
        report["response_data_hex"] = response.data.hex()
    return report


def _public_key_report(transport: str, command: CommandAPDU, response: ResponseAPDU) -> dict[str, object]:
    report: dict[str, object] = {
        "transport": transport,
        "command_hex": command.to_bytes().hex(),
        "response_hex": response.to_bytes().hex(),
        "status_word": _status_word(response),
    }
    if response.status_word == SW_NO_ERROR:
        report["public_key"] = response.data.hex()
    return report


def _signature_report(
    transport: str,
    command: CommandAPDU,
    response: ResponseAPDU,
    event_id: str,
    approval_digest: str,
    expected_public_key: str,
) -> dict[str, object]:
    report: dict[str, object] = {
        "transport": transport,
        "command_hex": command.to_bytes().hex(),
        "response_hex": response.to_bytes().hex(),
        "status_word": _status_word(response),
        "event_id": event_id,
        "expected_public_key": expected_public_key,
        "trusted_review": "external",
        "review_acknowledged": True,
        "approval_digest": approval_digest,
    }
    if response.status_word == SW_NO_ERROR:
        if len(response.data) != 64:
            raise ValueError("SIGN_EVENT_ID success response must contain a 64-byte Schnorr signature")
        signature = response.data.hex()
        if not verify_schnorr_signature(expected_public_key, event_id, signature):
            raise ValueError("SIGN_EVENT_ID signature verification failed")
        report["signature"] = signature
        report["signature_verified"] = True
    return report


def _sim_get_public_key(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _get_public_key_command()
    response = SmartcardSimulator(args.secret_key).exchange(command)
    _write_json(args.out, _public_key_report("simulator", command, response))


def _sim_sign_event_id(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _sign_event_id_command(args.event_id)
    response = SmartcardSimulator(args.secret_key).exchange(command)
    expected_public_key = xonly_pubkey_from_secret(args.secret_key).hex()
    _write_json(
        args.out,
        _signature_report("simulator", command, response, args.event_id, args.approval_digest, expected_public_key),
    )


def _sim_exchange_apdu(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _command_from_hex(args.command_hex)
    response = SmartcardSimulator(args.secret_key).exchange(command)
    _write_json(args.out, _apdu_exchange_report("simulator", command, response))


def _pcsc_get_public_key(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _get_public_key_command()
    response = PcscTransport.from_first_reader().exchange(command)
    _write_json(args.out, _public_key_report("pcsc", command, response))


def _pcsc_sign_event_id(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _sign_event_id_command(args.event_id)
    response = PcscTransport.from_first_reader().exchange(command)
    _write_json(
        args.out,
        _signature_report("pcsc", command, response, args.event_id, args.approval_digest, args.expected_public_key),
    )


def _pcsc_exchange_apdu(args: argparse.Namespace) -> None:
    _prepare_output_path(args.out)
    command = _command_from_hex(args.command_hex)
    response = PcscTransport.from_first_reader().exchange(command)
    _write_json(args.out, _apdu_exchange_report("pcsc", command, response))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nsealr-smartcard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sim_public_key = subparsers.add_parser("sim-get-public-key", help="Run GET_PUBLIC_KEY against the simulator")
    sim_public_key.add_argument("--secret-key", required=True, type=_secret_key)
    sim_public_key.add_argument("--out", required=True, type=Path)
    sim_public_key.set_defaults(func=_sim_get_public_key)

    sim_sign = subparsers.add_parser("sim-sign-event-id", help="Run SIGN_EVENT_ID against the simulator")
    sim_sign.add_argument("--secret-key", required=True, type=_secret_key)
    sim_sign.add_argument("--event-id", required=True, type=_event_id)
    sim_sign.add_argument(
        "--review-acknowledged",
        action="store_true",
        required=True,
        help="Confirm the event id was produced after external trusted review",
    )
    sim_sign.add_argument(
        "--approval-digest",
        required=True,
        type=_approval_digest,
        help="32-byte lowercase hex digest that binds the external review acknowledgement",
    )
    sim_sign.add_argument("--out", required=True, type=Path)
    sim_sign.set_defaults(func=_sim_sign_event_id)

    sim_exchange = subparsers.add_parser("sim-exchange-apdu", help="Run one raw APDU command against the simulator")
    sim_exchange.add_argument("--secret-key", required=True, type=_secret_key)
    sim_exchange.add_argument("--command-hex", required=True, type=_command_hex)
    sim_exchange.add_argument("--out", required=True, type=Path)
    sim_exchange.set_defaults(func=_sim_exchange_apdu)

    pcsc_public_key = subparsers.add_parser("pcsc-get-public-key", help="Run GET_PUBLIC_KEY against the first PC/SC reader")
    pcsc_public_key.add_argument("--out", required=True, type=Path)
    pcsc_public_key.set_defaults(func=_pcsc_get_public_key)

    pcsc_sign = subparsers.add_parser("pcsc-sign-event-id", help="Run SIGN_EVENT_ID against the first PC/SC reader")
    pcsc_sign.add_argument("--event-id", required=True, type=_event_id)
    pcsc_sign.add_argument(
        "--review-acknowledged",
        action="store_true",
        required=True,
        help="Confirm the event id was produced after external trusted review",
    )
    pcsc_sign.add_argument(
        "--approval-digest",
        required=True,
        type=_approval_digest,
        help="32-byte lowercase hex digest that binds the external review acknowledgement",
    )
    pcsc_sign.add_argument(
        "--expected-public-key",
        required=True,
        type=_public_key,
        help="32-byte lowercase hex x-only public key expected to verify the card signature",
    )
    pcsc_sign.add_argument("--out", required=True, type=Path)
    pcsc_sign.set_defaults(func=_pcsc_sign_event_id)

    pcsc_exchange = subparsers.add_parser("pcsc-exchange-apdu", help="Run one raw APDU command against the first PC/SC reader")
    pcsc_exchange.add_argument("--command-hex", required=True, type=_command_hex)
    pcsc_exchange.add_argument("--out", required=True, type=Path)
    pcsc_exchange.set_defaults(func=_pcsc_exchange_apdu)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, PcscUnavailableError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0
