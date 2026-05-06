# Architecture

`NostrSeal/smartcard` researches JavaCard, NFC, and contact smartcard signing.

## Responsibilities

- Map APDU behavior for Nostr signing cards.
- Build PC/SC tooling and tests.
- Verify Satochip/NostrKey compatibility.
- Provide a companion adapter boundary.
- Document display-less trust limitations.

## Reference Strategy

Signstr and NostrKey are product references. SatochipApplet and pysatochip are
technical references. License boundaries must be respected before any code reuse.

