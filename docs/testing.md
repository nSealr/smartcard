# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification, Python unit tests, bytecode
compilation, and isolated `pip check`. Local package setup uses pip's
in-tree build mode when the active pip version still exposes that compatibility
flag; newer pip versions already build in place and leave the flag disabled.

## Implemented Tests

- Short APDU command encode/decode round trip.
- Short APDU oversized payload rejection.
- `GET_PUBLIC_KEY` simulator response.
- `SIGN_EVENT_ID` simulator response with Schnorr verification against shared
  `nSealr/specs` fixtures.
- Shared `nSealr/specs` APDU vector conformance tests, including
  deterministic wrong-length, non-zero P1/P2, unsupported Le, unsupported-CLA,
  and unsupported-INS status-word responses. Rejection-vector discovery is
  directory-driven for every
  smartcard vector that carries both `expected_status_word` and `response_hex`,
  so future APDU rejection fixtures are picked up without a hand-written name
  list.
- CLI simulator report tests for `GET_PUBLIC_KEY`, `SIGN_EVENT_ID`, and raw
  APDU exchange, plus entry-point packaging coverage for `nsealr-smartcard`.
  Raw APDU exchange tests replay every shared smartcard vector that has a fixed
  `response_hex`, including P1/P2 and Le rejection fixtures. `SIGN_EVENT_ID`
  report tests require `--review-acknowledged` and a valid lowercase
  `--approval-digest`, and prove malformed or missing review acknowledgement
  writes no output.
- CLI PC/SC probe test proving the command fails clearly and writes no output
  when `pyscard` or a reader is unavailable.
- CLI PC/SC raw APDU report test with a fake reader, proving the command writes
  command bytes, response bytes, and status words through the same transport
  boundary without claiming real-card compatibility.
- PC/SC transport boundary tests with fake readers/connections and explicit
  unavailable-provider/no-reader/connection setup and APDU exchange errors.
- PC/SC malformed-response tests for malformed transmit-result shape, missing
  data, and non-integer or out-of-range data and status bytes.
- Documentation and fixture boundary tests requiring the shared
  `smartcard-slot-0` account descriptor to stay display-less, manual-only,
  externally reviewed, `approval_digest` bound, and free of persistent grant
  automation before any production identity/policy claim. The same test
  consumes `smartcard-sign-event-slot-0` so route-selection metadata cannot
  drift from the account descriptor.
- Single-repo CI falls back to fixture snapshots under `tests/fixtures/specs`
  when the sibling `nSealr/specs` checkout is not present. Cross-repo drift
  is still guarded by `nSealr/lab` integration checks.

## Required Tests

- Real PC/SC reader/card tests when hardware is available.
- pysatochip compatibility checks where available.
- Shared vector signing tests with a real card when hardware is available.

Display-less cards must not be represented as trusted event review devices.
