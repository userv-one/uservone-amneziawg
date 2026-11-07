# Improvements over the pinned upstream

## Protocol hardening

- Obfuscation specifications are parsed strictly: unknown text, wrong argument counts, multiple payload fields, non-positive random lengths and invalid data-size widths are rejected.
- Static and generated signature packets are capped at the maximum UDP payload (65,507 bytes), including the combined tag chain.
- Obfuscation decoding validates every source and destination slice, rejects trailing bytes and checks Base64 errors. A regression fuzz target exercises arbitrary packet lengths without panics.
- `Jc` is limited to 128, `Jmax` to 65,507 bytes and `Jmin <= Jmax` is enforced.
- Every `S1-S4` value is checked against the platform packet buffer and its message size. Header protection requires at least 12 nonce bytes in every padding field.
- Candidate junk/header/padding settings are validated before those settings are committed to the device. A rejected update no longer partially changes junk state.
- Cookie replies remain enabled in userv.one profiles.

## Correctness

- `RoutineReadFromTUN` now reframes a packet when a blocked TUN read began with an older transport-padding offset. Previously the first packet after reconfiguration could put `H4` at the old offset and be discarded by the peer as `MessageUnknownType`.
- Fixed-size junk (`Jmin == Jmax`) no longer depends on `fastrandn(0)`; ranged junk includes both endpoints.
- `UintRange.PickOne` handles the full `0-4294967295` range rather than overflowing the range width to zero.
- Windows checksum tests use the protocol number directly instead of a Unix-only constant.

## Customization and operations

- The `profile` package exposes validated `Balanced()` and `LowBandwidth()` presets plus fresh 256-bit header-protection key generation.
- `uservone-awg` renders client/server UAPI without embedding private keys or peer credentials.
- The module path, daemon name, build metadata and container labels identify userv.one without hiding upstream provenance.
- CI covers formatting, tests, vet, builds, race detection and fuzz smoke tests on Linux, Windows and macOS.

## Verification boundary

Unit and loopback integration tests validate the implementation, not a particular production hosting provider or censor. `go vet` is run with `unsafeptr=false` because the upstream Windows RIO ring intentionally converts kernel-owned addresses through `uintptr`; all other vet checks remain enabled. Container builds require a running Docker daemon. External stock-client interoperability should be tested in the target deployment before rollout.
