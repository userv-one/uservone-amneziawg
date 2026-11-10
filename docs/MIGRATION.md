# userv.one platform migration notes

## Scope

Roll out `uservone-amneziawg` **only to explicitly selected pilot AWG nodes**. Do not enable it for all nodes by default. Do not claim compatibility with all stock AmneziaWG/WireGuard clients until a separate interoperability report covers the deployed client versions and profiles.

This repository does not modify platform source files directly. The expected changes in `uservone-platform` are:

| File | Change |
| --- | --- |
| `server/amnezia.js` | Select the userspace binary by a feature flag keyed by `nodeId`; keep `/etc/amneziawg/*.conf` and the existing `awg`, `awg-quick`, `awg syncconf` command shapes. |
| `server/amneziaLocations.js` | Mark pilot locations/nodes and expose the `nodeId` flag input; do not put secrets in location metadata. |
| `syncPilotPeers` | Use the same shared AWG profile on both sides, run `check-config` before `syncconf`, and continue delegating peer expiry to `uservawg-expiry.timer`. |

Suggested flag: `USERVONE_AWG_PILOT_NODE_IDS` as a comma-separated allowlist of exact `nodeId` values. An empty value must select the stock binary.

## Pilot node preflight

```sh
uservone-awg version-json
uservone-awg check-config /etc/amneziawg/awg0.conf
awg-quick strip awg0 > /tmp/awg0.uapi
awg syncconf awg0 /tmp/awg0.uapi
systemctl status uservawg.service uservawg-expiry.timer
```

Keep these paths unchanged:

- `/usr/local/bin/awg`
- `/usr/local/bin/awg-quick`
- `/etc/amneziawg/*.conf`
- `uservawg.service`
- `uservawg-expiry.timer`

`check-config` validates the INI config without creating a TUN device, executing hooks, or printing key values. It accepts base64 and 64-character hex `HeaderProtectionKey` encodings. `syncconf` applies AWG obfuscation fields atomically: a rejected update does not leave the previous `I1-I5`, padding, timings, or flags partially changed. Private key, listen port, fwmark and peer lines keep standard incremental UAPI semantics and are outside that atomic AWG scope.

## Binary selection and compatibility symlink

`awg-quick` invokes the upstream userspace binary name `amneziawg-go`. Install the fork and point that compatibility name at it:

```sh
install -m 0755 uservone-amneziawg /usr/local/bin/uservone-amneziawg
install -m 0755 uservone-awg /usr/local/bin/uservone-awg
ln -sfn /usr/local/bin/uservone-amneziawg /usr/local/bin/amneziawg-go
```

Do not replace `/usr/local/bin/awg` or `/usr/local/bin/awg-quick`; the fork remains UAPI-compatible with them.

## Peer lifecycle

- Add and revoke peers through the existing `awg` UAPI/config path.
- `syncPilotPeers` must not emit private keys, peer credentials, endpoints, or addresses from profile output; profiles generate only shared UAPI settings.
- Peer expiry stays under `uservawg-expiry.timer` and platform state. The core removal path is covered by `TestPeerAddRevokeAndExpiry`.
- An expired peer must disappear from both the peer table and AllowedIPs routing.

## Rollback

For one pilot `nodeId`:

1. Remove the node from the feature-flag allowlist.
2. Point `/usr/local/bin/amneziawg-go` back to the stock binary (or remove the symlink if stock uses the kernel module).
3. Re-run the platform's stock `awg-quick strip` + `awg syncconf` flow with a stock-compatible config.
4. Restart `uservawg.service`, then verify `uservawg-expiry.timer` is still active.
5. Re-check tunnel loopback and peer expiry from the node.

No custom expiry directive is introduced into `/etc/amneziawg/*.conf`; rollback does not require stripping a userv.one-only config key.

## Required evidence before wider rollout

- Green CI on Linux, Windows, macOS, including race, fuzz and tunnel loopback tests.
- GHCR image digest and release `SHA256SUMS` verified on the pilot node.
- A separate stock-client interoperability report.
- Rollback rehearsal on at least one pilot node.
