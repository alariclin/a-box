# A-Box core disaster mirrors

Pinned binaries for offline / upstream-outage recovery live on the GitHub Release:

**`core-mirrors-v171`** → https://github.com/alariclin/a-box/releases/tag/core-mirrors-v171

## Why Releases instead of git LFS

| Asset family | Approx size (amd64+arm64) |
|---|---|
| Xray `v26.7.28` zip | ~40 MiB |
| sing-box `v1.14.2` glibc+musl tarballs | ~120 MiB |
| Hysteria `app/v2.13.0` | ~45 MiB |
| **Total** | **~200 MiB** |

Committing binaries into the git tree would bloat clones. The install script therefore:

1. Tries the **upstream** GitHub Release (XTLS / SagerNet / HyNetworks) with official SHA256 digests.
2. On total failure, falls back to **`alariclin/a-box` Release `core-mirrors-v171`** and verifies against that Release’s `SHA256SUMS`.
3. Never half-overwrites an installed binary; transactional install/upgrade keeps last-good rollback.

Override base URL with env `ABOX_CORE_MIRROR_BASE` if you host your own mirror.

## Pins (v171)

- Xray: `v26.7.28` (Shadowrocket / Mihomo / XHTTP compatibility)
- sing-box: `v1.14.2`
- Hysteria: `app/v2.13.0`

## Files on the Release

See `SHA256SUMS` on the Release for exact names and digests. Typical leaves:

- `Xray-linux-64.zip`, `Xray-linux-arm64-v8a.zip`
- `sing-box-1.14.2-linux-{amd64,arm64}-{glibc,musl}.tar.gz`
- `hysteria-linux-{amd64,arm64}`
