# nSealr Smartcard

JavaCard/NFC/contact smartcard signer work for nSealr.

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
- nSealr proprietary APDU constants for `GET_PUBLIC_KEY` and
  `SIGN_EVENT_ID`.
- secp256k1-backed simulator that returns x-only public keys and signs 32-byte
  Nostr event ids.
- Tests against shared `nSealr/specs` event-id fixtures and APDU
  status-word rejection vectors.
- Optional PC/SC transport boundary that exchanges short APDUs through
  `pyscard` when available and fails clearly when PC/SC prerequisites or
  readers are missing, connection setup fails, or APDU exchange fails. It
  rejects malformed reader responses whose transmit-result shape is invalid,
  whose data is missing, or whose data/status bytes are non-integer values or
  outside the APDU byte range. It is tested with fake connections; no real card
  support is claimed yet.
- `nsealr-smartcard` / `python -m nsealr_smartcard` CLI helpers for simulator
  `GET_PUBLIC_KEY`, `SIGN_EVENT_ID`, and raw APDU exchange reports plus future
  PC/SC `GET_PUBLIC_KEY`, `SIGN_EVENT_ID`, and raw APDU probes. PC/SC commands
  fail clearly when `pyscard` or a reader is unavailable and do not claim
  real-card support.
  `SIGN_EVENT_ID` report commands require explicit
  `--review-acknowledged` and `--approval-digest` flags because the smartcard
  cannot review full event JSON on its own display.
- Identity/policy integration is deliberately narrow: the shared
  `nsealr-account-descriptor-v0` fixture `smartcard-slot-0` now pins a
  display-less, manual-only route bound to
  `policy-manual-only-displayless-smartcard`, with request routing pinned by
  `smartcard-sign-event-slot-0`. Production real-card support is still blocked
  on card slot, PIN, provisioning, export, backup, and real-card APDU
  behavior. The smartcard route must require external review
  acknowledgement and `approval_digest` binding because the card is
  display-less.
  If multiple card slots are supported, each slot public key is its own account
  and policy subject. The card must not be presented as a trusted policy or
  event-review surface by itself.

Important trust boundary: the current smartcard model signs a 32-byte event id,
not full event JSON. A display-less card can protect key material, but it
cannot provide trusted event review by itself.

Feature target and current status are tracked in `nSealr/specs`
`vectors/features/signer-feature-matrix-v0.json`. The smartcard line may omit
device-display features because the card is display-less, but shared features
such as request validation, BIP-340 signing, APDU behavior, external review
acknowledgement, and response verification must follow the shared
`contract_id` when implemented.

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
