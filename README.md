# A-Box | One-click Linux Network Gateway Toolkit

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

A-Box is a standalone Bash automation toolkit for Linux network gateway deployment and maintenance. It integrates Xray-core, sing-box, official Hysteria 2, protocol configuration export, system tuning, traffic limits, access control, health checks, backup/restore, diagnostics, and SNI preference testing.

> Use only in legal, authorized, and compliant environments. Users are responsible for all operational, legal, and security consequences.

## Safe Quick Start

Download first, inspect or checksum, then run:

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh
sha256sum A-Box.sh
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh
```

Fast pipeline mode is still available:

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

Mirror fallback, only when GitHub raw is unreachable:

```bash
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

Language selection:

```bash
sudo bash A-Box.sh --lang zh
sudo bash A-Box.sh --lang en
```

Read-only checks:

```bash
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh --status
sudo bash A-Box.sh --help
sudo bash A-Box.sh --preflight
sudo bash A-Box.sh --dry-run
```

After first installation, use:

```bash
sb
```

## Core Features

| Module | Description |
|---|---|
| Deployment | Installs dependencies, initializes the runtime environment, deploys and manages Xray-core, sing-box, and official Hysteria 2. |
| Protocol stacks | VLESS-Vision-Reality, VLESS-XHTTP-Reality, Shadowsocks-2022, and Hysteria 2. |
| Default ports | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`; custom ports are validated. |
| SNI policy | Default REALITY SNI is `www.microsoft.com`. Apple/iCloud domains are never used as built-in defaults. Apple/iCloud-like SNI on non-443 ports triggers a warning. |
| Built-in SNI radar | Local full/mini candidate library; no legacy remote SNI script. Scores HTTPS/TLS metrics, TLS 1.3, ALPN, SAN, ASN/topology, and saves records. |
| XHTTP export | Exports XHTTP client parameters using `/xhttp`, `stream-one`, HTTP/2 host, and `smux: false` for compatible clients such as Mihomo. |
| Hysteria 2 | Supports ACME HTTP-01, Cloudflare DNS-01, self-signed certificate pinning, masquerade, optional port hopping, and Salamander obfuscation. |
| Operations | BBR/FQ tuning, TCP KeepAlive, Fail2Ban, logrotate, health probe, Geo data update, monthly traffic cutoff, SS-2022 whitelist, and status reporting. |
| Safeguards | Preflight checks, deployment replacement confirmation, backup before risky actions, redacted diagnostics, and guarded OTA update. |
| Export formats | URI, terminal QR, Clash/Mihomo YAML, sing-box outbound templates, and v2rayN/v2rayNG JSON. |

## Full Menu Reference

| Menu | Function | Use case |
|---:|---|---|
| `1` | Xray VLESS-Vision-Reality | Primary TCP REALITY + Vision path. |
| `2` | Xray VLESS-XHTTP-Reality | High-throughput XHTTP over REALITY path. |
| `3` | Xray Shadowsocks-2022 | TCP/UDP relay or landing inbound; whitelist is recommended. |
| `4` | Official Hysteria 2 | UDP/QUIC/H3 path for mobile or lossy networks. |
| `5` | Xray + Official HY2 all-in-one | Vision + XHTTP + HY2 + SS-2022. |
| `6` | sing-box VLESS-Vision-Reality | Low-memory Vision deployment. |
| `7` | sing-box Shadowsocks-2022 | Low-memory SS-2022 deployment. |
| `8` | sing-box VLESS + SS-2022 | Lightweight two-protocol deployment. |
| `9` | sing-box Hysteria 2 | HY2 implemented by sing-box. |
| `10` | sing-box all-in-one | Vision + HY2 + SS-2022; XHTTP excluded by design. |
| `11` | Toolbox | Benchmark, IP quality, SNI radar, WARP, Swap, backup/restore, diagnostics, dry-run preflight, SNI records. |
| `12` | VPS optimization | BBR/FQ, limits, KeepAlive, Fail2Ban, health probe. |
| `13` | Display node parameters | Links, QR codes, YAML, JSON, outbound templates. |
| `14` | Manual | Full terminal manual. |
| `15` | OTA, Geo & core upgrade | Update A-Box script, update Xray Geo data, or upgrade installed cores without resetting node parameters. |
| `16` | Clean uninstall | Remove managed services, configs, firewall rules, and optional `sb` shortcut. |
| `17` | Delete nodes & reinitialize | Kill orphan processes, clean stale rules, and remove broken configs/services. |
| `18` | Monthly traffic limit | vnStat-based monthly quota; stops services after quota is reached. |
| `19` | SS-2022 whitelist manager | Add/remove frontend IP/CIDR; enforce DROP for non-whitelisted sources. Switching back to whitelist mode removes stale global ACCEPT rules first. |
| `20` | Language settings | Switch Chinese/English UI and save to `/etc/ddr/.lang`. |
| `0` | Exit | Exit the menu. |

## Toolbox Details

| Submenu | Function | Description |
|---:|---|---|
| `1` | System benchmark | Runs `bench.sh` for hardware and download speed testing. |
| `2` | IP quality and route test | Runs Check.Place for IP quality, streaming unlock, and route testing. |
| `3` | Local SNI preference | Runs the full built-in SNI preference library with higher concurrency and deeper verification. |
| `4` | Mini-host local SNI preference | Uses the same candidate library as full mode, but lowers concurrency and verification depth for low-spec hosts. |
| `5` | Cloudflare WARP manager | Downloads and runs a third-party WARP manager. A-Box prints SHA256 and requires strong confirmation before execution. |
| `6` | 2G Swap allocation | Creates `/swapfile` to reduce OOM risk on low-memory hosts. |
| `7` | Backup / Restore | Creates or restores A-Box configuration backups. |
| `8` | Redacted diagnostic bundle | Exports status, ports, versions, logs, firewall snippets, cron entries, and redacted environment data. |
| `9` | Full dry-run preflight check | Runs a non-destructive environment, dependency, network, GitHub, port, service, firewall, and storage check. |
| `10` | SNI preference records | Displays saved full/mini SNI preference results from `/etc/ddr/A-Box-sni-full.tsv` and `/etc/ddr/A-Box-sni-mini.tsv`. |

## Maintenance Safeguards

- Lightweight preflight runs automatically before protocol deployment menus `1`-`10`.
- Menu `15` creates an automatic backup before core upgrade actions without resetting node parameters.
- Menus `16` and `17` ask whether to create a backup before uninstall or environment reset.
- Toolbox submenu `7` provides manual backup and restore.
- Toolbox submenu `8` exports a redacted diagnostic bundle. UUIDs, private keys, passwords, tokens, and client links are masked.
- Toolbox submenu `9` runs a full dry-run preflight report and saves it under `/etc/ddr/preflight/`.
- Toolbox submenu `10` displays the latest saved full/mini SNI preference records.
- Third-party toolbox scripts are not part of A-Box. Before execution, A-Box displays the downloaded script SHA256 and requires exact confirmation `YES-RUN-UNTRUSTED`, unless `ABOX_REMOTE_SHA256_ALLOWLIST` explicitly contains the hash.
- OTA from the `main` branch is guarded by syntax/fingerprint validation plus SHA256 display and `[Y/N]` confirmation. Non-interactive OTA must use `ABOX_OTA_SHA256_ALLOWLIST`.
- GitHub core asset downloads require official release asset SHA256 digest validation. Stable `latest` releases are used by default; prerelease/alpha builds are intentionally not used.

## Recommended Deployment Schemes

| Scenario | Recommended option |
|---|---|
| Balanced production deployment | Menu `5`: Xray + Official HY2 all-in-one. |
| Low-memory lightweight deployment | Menu `10`: sing-box all-in-one. |
| Primary TCP path | Menu `1`: Xray VLESS-Vision-Reality (`443/TCP`). |
| High-throughput desktop backup | Menu `2`: Xray VLESS-XHTTP-Reality (`8443/TCP`). |
| Mobile or lossy network | Menu `4`: Official Hysteria 2 (`443/UDP`). |
| Relay/landing node | Menu `3`: Xray SS-2022 (`2053/TCP+UDP`) + whitelist. |

## SNI Selection Notes

- Run SNI preference on the VPS, not on a local laptop, because REALITY target quality depends mainly on the VPS-to-target path.
- Prefer candidates with `tls13=1`, `san=1`, valid ALPN, and same/near ASN or country when available.
- Avoid API-only, rate-limited, unstable, or abnormal response targets when normal `200` web/document/static-resource targets are available.
- Do not use raw IP addresses as SNI.
- Apple/iCloud-like SNI on non-443 ports is explicitly warned by the script.
- The fallback REALITY SNI is `www.microsoft.com`; Apple/iCloud domains are never used as built-in defaults.
- Use Toolbox `10` to review the saved result after running Toolbox `3` or `4`.

## System Requirements

| Item | Requirement |
|---|---|
| OS | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux. |
| Init system | systemd or OpenRC. |
| CPU | amd64/x86_64, arm64/aarch64. |
| Privilege | root or sudo. |
| Network | Access to system repositories and GitHub Releases. |
| Dependencies | Bash, curl, jq, openssl, iptables, vnStat, and other packages are installed automatically when missing. |

## FAQ

### The script says no interactive TTY is available.
Run it from an interactive terminal. If a pipeline environment fails, download the script first and run `sudo bash A-Box.sh`.

### Deployment failed because a port is occupied.
The script checks for non-A-Box processes using selected ports. Release the port manually or choose a different port.

### Will preflight block reinstalling an already deployed stack?
No. The lightweight preflight used before protocol deployment does not fail just because A-Box-managed services already hold ports. Actual deployment still stops managed services before writing the new stack.

### What is included in backups and diagnostics?
Backups preserve A-Box configuration, service files, scripts, selected firewall/cron state, and related runtime metadata. Diagnostic bundles are redacted for troubleshooting.

### Why does Hysteria 2 ask for up/down bandwidth?
Hysteria 2 uses configured `up` and `down` values as bandwidth control and congestion-control parameters. Set them according to the VPS line capacity.

### ACME certificate application failed.
For HTTP-01, make sure `80/TCP` is reachable and not occupied. For Cloudflare DNS-01, make sure the API token has DNS edit permission for the target zone.

### How should I choose SNI?
Use Toolbox `3` or `4`, then review saved results with Toolbox `10`. Prefer TLS 1.3, SAN match, valid ALPN, and reasonable ASN/topology relationship with the VPS.

## License

Apache License 2.0.
