# Release and installation

## v0.1.0 assets

Each release contains:

- `uservone-amneziawg-linux-amd64`
- `uservone-amneziawg-linux-arm64`
- `uservone-awg-linux-amd64`
- `uservone-awg-linux-arm64`
- `uservone-amneziawg-v0.1.0-source.zip`
- `buildinfo.json`
- `SHA256SUMS`

`buildinfo.json` records the release tag, exact commit, upstream reference commit, Go version, target platforms and asset names. Both Go binaries are built statically with `CGO_ENABLED=0` and `-trimpath`; `buildinfo.Commit` is set from the release commit.

Verify a downloaded asset before installing:

```sh
sha256sum -c SHA256SUMS
uservone-awg version-json
```

## Compatibility symlink

`awg-quick` expects an `amneziawg-go` executable on `PATH`. Keep `awg` and `awg-quick` untouched and install the fork as follows:

```sh
sudo install -m 0755 uservone-amneziawg-linux-amd64 /usr/local/bin/uservone-amneziawg
sudo install -m 0755 uservone-awg-linux-amd64 /usr/local/bin/uservone-awg
sudo ln -sfn /usr/local/bin/uservone-amneziawg /usr/local/bin/amneziawg-go
```

For rollback, replace the symlink with the stock binary and re-run the existing `awg syncconf` flow. See [MIGRATION.md](MIGRATION.md).

## GHCR image

The tag workflow publishes:

```text
ghcr.io/userv-one/uservone-amneziawg:0.1.0
```

Use the immutable digest from the workflow/package metadata on pilot nodes rather than relying only on the mutable tag. The image contains `awg`, `awg-quick`, the compatibility symlink, and both userv.one binaries. GHCR builds inject the same `Version`/`Commit` ldflags, so `uservone-awg version-json` inside the image matches the release buildinfo.

## Commands

```sh
uservone-awg version-json
uservone-awg check-config /etc/amneziawg/awg0.conf
uservone-awg profile balanced
uservone-awg profile --client low-bandwidth
```

Profiles output UAPI settings only. They never emit private keys, preshared keys, peer public keys, endpoints, AllowedIPs, or `[Interface]`/`[Peer]` sections.
