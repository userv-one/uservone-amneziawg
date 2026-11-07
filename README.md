# uservone-amneziawg

Independent userv.one fork of the Go AmneziaWG userspace implementation. It remains wire-compatible with AmneziaWG v3 and the standard `awg` / `awg-quick` UAPI workflow.

Upstream reference: [`amnezia-vpn/amneziawg-go@b5928efb`](https://github.com/amnezia-vpn/amneziawg-go/commit/b5928efb6ca19f0153958460c3d141f04abc5c2e). See [PROVENANCE.md](docs/PROVENANCE.md).

## What this fork changes

- Rejects malformed obfuscation tags, negative lengths, oversized packets and ambiguous payload layouts.
- Makes obfuscation decoding bounds-safe; malformed Base64 and truncated/trailing data are rejected without panics.
- Validates `Jc/Jmin/Jmax` and `S1-S4` before applying a UAPI update, preventing allocation amplification and packet-buffer overflows.
- Fixes transport packets using a stale padding offset after live reconfiguration. This was reproduced as intermittent Windows ping/pong failure and is now covered by repeated integration tests.
- Preserves fixed-size junk packets and the full `uint32` randomized-header range.
- Adds deterministic `balanced` and `low-bandwidth` profiles with bounded padding, non-overlapping headers and cookies enabled.
- Provides a small management CLI, cross-platform CI, race tests and obfuscation fuzzing.

The complete technical list is in [IMPROVEMENTS.md](docs/IMPROVEMENTS.md).

## Build

Go 1.25 or newer is required.

```sh
make
# Produces:
#   uservone-amneziawg  - userspace daemon
#   uservone-awg        - profile/version CLI
```

Install both binaries and the `amneziawg-go` compatibility symlink:

```sh
sudo make install
```

Docker builds also include `awg` and `awg-quick`, pinned to `amneziawg-tools@ee0f0a9a`.

## Profiles

Generate server-side UAPI (no junk-packet amplification on the server):

```sh
uservone-awg profile balanced > server.awg
sudo awg set awg0 < server.awg
```

Generate the matching client-side settings:

```sh
uservone-awg profile --client balanced > client.awg
sudo awg set awg0 < client.awg
```

Use the **same** `S1-S4`, `H1-H4` and optional header-protection key on both peers. `Jc/Jmin/Jmax` are client-side only.

Header protection is opt-in:

```sh
uservone-awg profile --client --header-protection balanced > client.awg
```

Copy the resulting `header_protection_key` line to the server profile as well. Do not generate a different key on the other peer.

`low-bandwidth` reduces junk and padding overhead:

```sh
uservone-awg profile --client low-bandwidth
```

These profiles change obfuscation parameters, not cryptography or the AWG wire format. They do not provide immunity from DPI, endpoint blocking, active probing or traffic analysis.

## Daemon

Run an interface in the foreground:

```sh
sudo uservone-amneziawg -f awg0
```

Or use the existing userv.one service after installing `awg-quick` and `/etc/amneziawg/awg0.conf`:

```sh
sudo cp packaging/uservawg.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now uservawg.service
```

The daemon remains compatible with existing `/etc/amneziawg/*.conf` files and `uservawg-expiry.timer`; expiry policy stays outside the wire-protocol process.

## Verify

```sh
go test ./...
go vet -unsafeptr=false ./... # Windows RIO uses uintptr by design
go test -race ./...
go test ./device -run '^$' -fuzz FuzzObfChainDeobfuscationNeverPanics -fuzztime 15s
```

## License

MIT, matching upstream. WireGuard and AmneziaWG retain their respective copyright and project identities.
