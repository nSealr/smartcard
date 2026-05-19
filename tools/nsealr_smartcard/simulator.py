from __future__ import annotations

import re

import secp256k1

from .apdu import CommandAPDU, ResponseAPDU
from .protocol import (
    INS_GET_PUBLIC_KEY,
    INS_SIGN_EVENT_ID,
    NSEALR_CLA,
    SW_CLA_NOT_SUPPORTED,
    SW_INCORRECT_P1P2,
    SW_INS_NOT_SUPPORTED,
    SW_NO_ERROR,
    SW_WRONG_LENGTH,
)

HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{128}$")


def _private_key(secret_key_hex: str) -> secp256k1.PrivateKey:
    if not HEX32_RE.fullmatch(secret_key_hex):
        raise ValueError("secret key must be 32-byte lowercase hex")
    return secp256k1.PrivateKey(bytes.fromhex(secret_key_hex), raw=True)


def xonly_pubkey_from_secret(secret_key_hex: str) -> bytes:
    private_key = _private_key(secret_key_hex)
    out = secp256k1.ffi.new("unsigned char [32]")
    ok = secp256k1.lib.secp256k1_xonly_pubkey_serialize(
        secp256k1.secp256k1_ctx,
        out,
        private_key.pubkey.xonly_pubkey,
    )
    if ok != 1:
        raise RuntimeError("failed to serialize x-only public key")
    return bytes(secp256k1.ffi.buffer(out, 32))


def verify_schnorr_signature(pubkey_hex: str, msg_hex: str, sig_hex: str) -> bool:
    if not HEX32_RE.fullmatch(pubkey_hex) or not HEX32_RE.fullmatch(msg_hex) or not HEX64_RE.fullmatch(sig_hex):
        return False
    xonly_pubkey = secp256k1.ffi.new("secp256k1_xonly_pubkey *")
    parsed = secp256k1.lib.secp256k1_xonly_pubkey_parse(
        secp256k1.secp256k1_ctx,
        xonly_pubkey,
        bytes.fromhex(pubkey_hex),
    )
    if parsed != 1:
        return False
    verified = secp256k1.lib.secp256k1_schnorrsig_verify(
        secp256k1.secp256k1_ctx,
        bytes.fromhex(sig_hex),
        bytes.fromhex(msg_hex),
        32,
        xonly_pubkey,
    )
    return bool(verified)


class SmartcardSimulator:
    def __init__(self, secret_key_hex: str):
        self._secret_key_hex = secret_key_hex
        self._private_key = _private_key(secret_key_hex)

    def exchange(self, command: CommandAPDU) -> ResponseAPDU:
        if command.cla != NSEALR_CLA:
            return ResponseAPDU(status_word=SW_CLA_NOT_SUPPORTED)
        if command.ins == INS_GET_PUBLIC_KEY:
            if command.p1 != 0 or command.p2 != 0:
                return ResponseAPDU(status_word=SW_INCORRECT_P1P2)
            if command.data or command.le is not None:
                return ResponseAPDU(status_word=SW_WRONG_LENGTH)
            return ResponseAPDU(xonly_pubkey_from_secret(self._secret_key_hex), SW_NO_ERROR)
        if command.ins == INS_SIGN_EVENT_ID:
            if command.p1 != 0 or command.p2 != 0:
                return ResponseAPDU(status_word=SW_INCORRECT_P1P2)
            if len(command.data) != 32 or command.le is not None:
                return ResponseAPDU(status_word=SW_WRONG_LENGTH)
            signature = self._private_key.schnorr_sign(command.data, "", raw=True)
            return ResponseAPDU(signature, SW_NO_ERROR)
        return ResponseAPDU(status_word=SW_INS_NOT_SUPPORTED)
