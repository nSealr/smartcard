# NostrSeal Smartcard

JavaCard/NFC/contact smartcard signer work for NostrSeal.

The first goal is compatibility research with Satochip/NostrKey-style cards.
Only after real APDU behavior and test vectors are understood should this
repository host a forked or custom JavaCard applet.

## Planned Capabilities

- Satochip/NostrKey compatibility notes.
- APDU command mapping for Nostr signing.
- PC/SC desktop tools.
- NFC/mobile transport research.
- JavaCard applet experiments.
- Smartcard provisioning and PIN policy notes.

## Current Capabilities

- Python APDU codec for short command and response APDUs.
- NostrSeal proprietary APDU constants for `GET_PUBLIC_KEY` and
  `SIGN_EVENT_ID`.
- secp256k1-backed simulator that returns x-only public keys and signs 32-byte
  Nostr event ids.
- Tests against shared `NostrSeal/specs` event-id fixtures.
- Optional PC/SC transport boundary that exchanges short APDUs through
  `pyscard` when available and fails clearly when PC/SC prerequisites or
  readers are missing. It is tested with fake connections; no real card support
  is claimed yet.

Important trust boundary: the current smartcard model signs a 32-byte event id,
not full event JSON. A display-less card can protect key material, but it cannot
provide trusted event review by itself.

## Initial Layout

- `applet/`: custom or forked JavaCard applet work.
- `tools/`: PC/SC, APDU, and test utilities.
- `docs/`: source review, card profiles, provisioning, and threat notes.

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

## License

New smartcard tooling is released under the MIT License unless a file says
otherwise. Forked or imported applets must preserve their upstream licenses.
