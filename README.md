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

## Initial Layout

- `applet/`: custom or forked JavaCard applet work.
- `tools/`: PC/SC, APDU, and test utilities.
- `docs/`: source review, card profiles, provisioning, and threat notes.

## License Plan

Applet work should stay compatible with upstream Satochip licensing if forked.
New tooling should use a copyleft software license unless interoperability
requires a more permissive module.
