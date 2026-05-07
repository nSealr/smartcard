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

## Required Tests

- APDU fixture tests.
- PC/SC tooling tests.
- pysatochip compatibility checks where available.
- Shared vector signing tests with a real card when hardware is available.
- Simulator fallback when hardware is not available.

Display-less cards must not be represented as trusted event review devices.
