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

## Implemented Foundation

- `nostrseal_smartcard.apdu`: short APDU command/response encoding.
- `nostrseal_smartcard.protocol`: NostrSeal CLA/INS/status-word constants.
- `nostrseal_smartcard.simulator`: secp256k1-backed local simulator.
- `nostrseal_smartcard.pcsc`: optional PC/SC transport boundary. It imports
  `pyscard` only when a real PC/SC reader is requested, exchanges short APDUs
  through a connection object, rejects malformed transmit-result shape, missing
  response data, and malformed response data/status bytes that are non-integer
  values or outside the APDU byte range, and returns explicit setup errors when
  `pyscard`, reader enumeration, readers, reader connections, or APDU exchange
  are unavailable.

The first command boundary is deliberately small:

- `GET_PUBLIC_KEY`: returns the active x-only secp256k1 public key.
- `SIGN_EVENT_ID`: signs exactly one 32-byte Nostr event id.

This mirrors what display-less smartcards can realistically do without a trusted
screen. The companion or another trusted review device must still compute and
review the event before sending the digest to the card.

Tests consume APDU vectors from `NostrSeal/specs` so command bytes and response
expectations remain shared across implementations.

The PC/SC boundary is not proof of real-card compatibility. It is the adapter
shape that future Satochip/NostrKey captures and hardware tests should drive
once cards and readers are available.
