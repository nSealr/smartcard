# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification, Python unit tests, bytecode
compilation, and isolated `pip check`.

## Implemented Tests

- Short APDU command encode/decode round trip.
- Short APDU oversized payload rejection.
- `GET_PUBLIC_KEY` simulator response.
- `SIGN_EVENT_ID` simulator response with Schnorr verification against shared
  `NostrSeal/specs` fixtures.
- Shared `NostrSeal/specs` APDU vector conformance tests.
- PC/SC transport boundary tests with fake readers/connections and explicit
  unavailable-provider/no-reader errors.
- PC/SC malformed-response tests for out-of-range data and status bytes.
- Single-repo CI falls back to fixture snapshots under `tests/fixtures/specs`
  when the sibling `NostrSeal/specs` checkout is not present. Cross-repo drift
  is still guarded by `NostrSeal/lab` integration checks.

## Required Tests

- APDU fixture tests.
- Real PC/SC reader/card tests when hardware is available.
- pysatochip compatibility checks where available.
- Shared vector signing tests with a real card when hardware is available.
- Simulator fallback when hardware is not available.

Display-less cards must not be represented as trusted event review devices.
