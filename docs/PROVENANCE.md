# Provenance

## Protocol reference

- Project: `amnezia-vpn/amneziawg-go`
- Source: https://github.com/amnezia-vpn/amneziawg-go
- Commit: `b5928efb6ca19f0153958460c3d141f04abc5c2e`
- Upstream tag at that commit: `v3.1.20260828`
- License: MIT; see the repository root `LICENSE`.

The fork preserves the upstream Git history. The `upstream` remote points to the reference repository; `uservone-core` contains userv.one changes.

## Bundled tools in Docker

- Project: `amnezia-vpn/amneziawg-tools`
- Source: https://github.com/amnezia-vpn/amneziawg-tools
- Commit: `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`
- Tag: `v3.1.20260812`

The tools are built only in the Docker image and are not vendored into this source tree.

## Compatibility policy

Changes must not redefine encrypted fields, packet layouts or Noise/WireGuard behavior. Hardening and profile generation must remain compatible with stock AWG v3 peers using the same shared settings. No claim of DPI or blocking immunity is made.
