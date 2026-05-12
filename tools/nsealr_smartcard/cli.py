from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .apdu import CommandAPDU, ResponseAPDU
from .pcsc import PcscTransport, PcscUnavailableError
from .protocol import INS_GET_PUBLIC_KEY, INS_SIGN_EVENT_ID, NSEALR_CLA, SW_NO_ERROR
from .simulator import SmartcardSimulator


def _hex32(value: str, label: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise argparse.ArgumentTypeError(f"{label} must be 32-byte lowercase hex")
    return value


def _secret_key(value: str) -> str:
    return _hex32(value, "secret key")


def _event_id(value: str) -> str:
    return _hex32(value, "event id")


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _status_word(response: ResponseAPDU) -> str:
    return f"{response.status_word:04x}"


def _get_public_key_command() -> CommandAPDU:
    return CommandAPDU(NSEALR_CLA, INS_GET_PUBLIC_KEY)


def _sign_event_id_command(event_id: str) -> CommandAPDU:
    return CommandAPDU(NSEALR_CLA, INS_SIGN_EVENT_ID, data=bytes.fromhex(event_id))


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
) -> dict[str, object]:
    report: dict[str, object] = {
        "transport": transport,
        "command_hex": command.to_bytes().hex(),
        "response_hex": response.to_bytes().hex(),
        "status_word": _status_word(response),
        "event_id": event_id,
    }
    if response.status_word == SW_NO_ERROR:
        report["signature"] = response.data.hex()
    return report


def _sim_get_public_key(args: argparse.Namespace) -> None:
    command = _get_public_key_command()
    response = SmartcardSimulator(args.secret_key).exchange(command)
    _write_json(args.out, _public_key_report("simulator", command, response))


def _sim_sign_event_id(args: argparse.Namespace) -> None:
    command = _sign_event_id_command(args.event_id)
    response = SmartcardSimulator(args.secret_key).exchange(command)
    _write_json(args.out, _signature_report("simulator", command, response, args.event_id))


def _pcsc_get_public_key(args: argparse.Namespace) -> None:
    command = _get_public_key_command()
    response = PcscTransport.from_first_reader().exchange(command)
    _write_json(args.out, _public_key_report("pcsc", command, response))


def _pcsc_sign_event_id(args: argparse.Namespace) -> None:
    command = _sign_event_id_command(args.event_id)
    response = PcscTransport.from_first_reader().exchange(command)
    _write_json(args.out, _signature_report("pcsc", command, response, args.event_id))


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
    sim_sign.add_argument("--out", required=True, type=Path)
    sim_sign.set_defaults(func=_sim_sign_event_id)

    pcsc_public_key = subparsers.add_parser("pcsc-get-public-key", help="Run GET_PUBLIC_KEY against the first PC/SC reader")
    pcsc_public_key.add_argument("--out", required=True, type=Path)
    pcsc_public_key.set_defaults(func=_pcsc_get_public_key)

    pcsc_sign = subparsers.add_parser("pcsc-sign-event-id", help="Run SIGN_EVENT_ID against the first PC/SC reader")
    pcsc_sign.add_argument("--event-id", required=True, type=_event_id)
    pcsc_sign.add_argument("--out", required=True, type=Path)
    pcsc_sign.set_defaults(func=_pcsc_sign_event_id)

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
