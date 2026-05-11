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
- `nostrseal_smartcard.cli`: simulator and PC/SC probe commands for
  `GET_PUBLIC_KEY` and `SIGN_EVENT_ID`. Simulator commands are deterministic
  development tools; PC/SC commands are probe tooling and do not establish
  real-card compatibility by themselves.

The first command boundary is deliberately small:

- `GET_PUBLIC_KEY`: returns the active x-only secp256k1 public key.
- `SIGN_EVENT_ID`: signs exactly one 32-byte Nostr event id.

This mirrors what display-less smartcards can realistically do without a trusted
screen. The companion or another trusted review device must still compute and
review the event before sending the digest to the card.

## Identity And Policy Boundary

The shared `nseal-account-descriptor-v0` smartcard route descriptor is pending.
It must not be added until real card slot behavior, PIN/PUK policy,
provisioning, export policy, and backup/recovery semantics are verified from
sources or hardware captures.

The eventual route can protect a key inside a display-less card, but it must
not claim trusted event review. It must require external review
acknowledgement, bind the event id to an `approval_digest` produced by the
companion or another trusted review device, and clearly report whether a policy
path, manual path, or refusal path produced the APDU request.

Tests consume APDU vectors from `NostrSeal/specs` so command bytes, response
expectations, and deterministic rejection status words remain shared across
implementations.

Feature target and current status live in `NostrSeal/specs`
`vectors/features/signer-feature-matrix-v0.json`. The smartcard repository
must not claim device-display features, but features it does implement, such as
APDUs, external review acknowledgement, BIP-340 signing, and response
verification, must use the shared `contract_id` so behavior stays aligned with
the companion and other signer families.

The PC/SC boundary is not proof of real-card compatibility. It is the adapter
shape that future Satochip/NostrKey captures and hardware tests should drive
once cards and readers are available.
