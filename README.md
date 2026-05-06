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

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

## License

New smartcard tooling is released under the MIT License unless a file says
otherwise. Forked or imported applets must preserve their upstream licenses.
