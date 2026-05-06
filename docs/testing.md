# Testing

## Current Baseline

```sh
make ci
```

## Required Tests

- APDU fixture tests.
- PC/SC tooling tests.
- pysatochip compatibility checks where available.
- Shared vector signing tests with a real card when hardware is available.
- Simulator fallback when hardware is not available.

Display-less cards must not be represented as trusted event review devices.

