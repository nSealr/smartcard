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
reader connection, exchanges short APDUs, and reports missing `pyscard` or
reader setup explicitly. It is fake-connection tested only; real Satochip,
NostrKey, and reader captures remain pending.

## Later

- Native audited adapter.
- Optional custom applet research.
- NFC mobile transport research.
