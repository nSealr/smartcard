# Roadmap

## Foundation: APDU Protocol Simulator

- Short APDU codec.
- `GET_PUBLIC_KEY` command.
- `SIGN_EVENT_ID` command.
- secp256k1-backed simulator.
- Shared fixture verification.

Status: implemented as the first smartcard protocol foundation.

## M12: Feasibility

- PC/SC tooling.
- Satochip/NostrKey test plan.
- Companion adapter prototype.
- Threat model.

Status: the first optional PC/SC transport boundary is implemented. It wraps a
reader connection, exchanges short APDUs, rejects out-of-range response bytes,
and reports missing `pyscard`, failed reader enumeration, missing readers, or
reader connection setup explicitly. APDU exchange failures are also normalized
to a PC/SC transport error. It is fake-connection tested only; real Satochip,
NostrKey, and reader captures remain pending.

Status note, 2026-05-09: the PC/SC boundary now rejects non-integer response
data and status values with deterministic APDU byte-range errors instead of
leaking provider-specific Python type errors. Real-card compatibility is still
unclaimed.

Status note, 2026-05-09: the PC/SC boundary now rejects missing response data
with a deterministic response-shape error before APDU construction. This keeps
the fake-connection boundary aligned with the companion PC/SC response-shape
hardening and still does not claim real-card compatibility.

Status note, 2026-05-09: the PC/SC boundary now rejects malformed transmit
results with deterministic response-shape errors before reading status bytes or
data. This separates provider exchange failures from malformed provider
responses while remaining fake-connection tested only.

Status note, 2026-05-10: the simulator now consumes shared APDU rejection
vectors from `nSealr/specs` for wrong `SIGN_EVENT_ID` length, unsupported
CLA, and unsupported INS status words. This hardens the display-less APDU
contract without claiming real-card compatibility.

Status note, 2026-05-11: APDU rejection-vector tests now discover every shared
smartcard vector with an `expected_status_word` and fixed `response_hex`
instead of naming individual rejection files.

Status note, 2026-05-10: `nsealr-smartcard` now exposes simulator
`GET_PUBLIC_KEY` and `SIGN_EVENT_ID` report commands plus PC/SC probe commands
for the same APDU operations. The PC/SC path still uses the optional
fake-tested transport boundary and fails clearly when `pyscard` or a reader is
unavailable; this does not claim real-card compatibility.

Status note, 2026-05-11: identity/policy integration remains intentionally
blocked. The `nsealr-account-descriptor-v0` smartcard route descriptor is
pending until card slot, PIN, provisioning, export, backup, and real-card APDU
behavior are source-backed. Any future descriptor must keep the card
display-less, require external review acknowledgement, and bind the signed
event id to an `approval_digest` before companion publication.

## Later

- Native audited adapter.
- Optional custom applet research.
- NFC mobile transport research.
