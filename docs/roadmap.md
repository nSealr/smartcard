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

## Later

- Native audited adapter.
- Optional custom applet research.
- NFC mobile transport research.
