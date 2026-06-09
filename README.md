# A-Box | One-click Linux Network Gateway Toolkit

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<img width="804" height="867" alt="屏幕快照 2026-06-10 的 02 44 49 上午" src="https://github.com/user-attachments/assets/dfffc937-02e5-4601-9e50-f90616f64cc4" />




**A-Box** is an all-in-one Linux network gateway automation toolkit. It integrates proxy service deployment, system tuning, traffic management, access control, service health checks, client configuration export, network quality testing, maintenance safeguards, and a bilingual terminal UI into one standalone Bash script.

**Credits:** Sincere thanks to Xray-core, sing-box, Hysteria, and related open-source projects for technical inspiration and ecosystem support. A-Box is an independent automation orchestration toolkit.

[![Version](https://img.shields.io/badge/Version-2026.05.07-success.svg?style=flat-square)](https://github.com/alariclin/a-box/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/alariclin/a-box?style=flat-square&color=yellow)](https://github.com/alariclin/a-box/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alariclin/a-box?style=flat-square&color=orange)](https://github.com/alariclin/a-box/network/members)

---

## Compliance & Disclaimer

This project is intended for **network architecture testing, cybersecurity research, and legitimate privacy protection in fully authorized environments**.

1. **Legal compliance:** Do not use this project for any activity that violates the laws or regulations of your country or region.
2. **User responsibility:** Users are fully responsible for all legal, operational, and security consequences caused by misuse or improper operation.
3. **Technical intent:** The routing and encryption technologies involved are designed to improve data transmission security and privacy. Do not use this tool for illegal attacks, unauthorized access, or damage to network infrastructure.
4. **Acceptance:** Downloading, copying, or running this script means you have read, understood, and accepted these terms.

---

## Quick Start

### One-click run: global channel

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

### One-click run: mirror channel

```bash
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

### Specify UI language

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh > A-Box.sh
sudo bash A-Box.sh --lang zh
sudo bash A-Box.sh --lang en
```

### Self-test, status, help, and preflight

```bash
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh --status
sudo bash A-Box.sh --help
sudo bash A-Box.sh --preflight
sudo bash A-Box.sh --dry-run
```

### Console shortcut

After the first run, open the menu at any time with:

```bash
sb
```

---

## Core Features

| Module | Description |
| :--- | :--- |
| One-click deployment | Installs dependencies, initializes the environment, deploys services, and manages Xray-core, sing-box, and official Hysteria 2. |
| Protocol stack | VLESS-Vision-Reality, VLESS-XHTTP-Reality, Shadowsocks-2022, and Hysteria 2. |
| Standard ports | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`; custom ports are validated before deployment. |
| SNI policy | Default REALITY SNI is `www.microsoft.com`. Apple/iCloud-like SNI on non-443 ports triggers a warning and secondary confirmation. Production SNI should be selected with the built-in SNI preference tool. |
| Built-in SNI radar | Local candidate library with full and mini-host modes; no legacy remote SNI script dependency. Scores candidates by HTTPS/TLS metrics, TLS 1.3, ALPN, SAN verification, ASN/topology, and progress reporting. |
| XHTTP export | Exports XHTTP client parameters using `/xhttp`, `stream-one`, HTTP/2 host, and `smux: false` for compatible clients such as Mihomo. |
| Hysteria 2 modes | Supports ACME HTTP-01 and Cloudflare DNS-01 certificate workflows, self-signed certificate pinning, optional masquerade, optional port hopping, and optional Salamander obfuscation. |
| Toolbox | Benchmark, IP quality/streaming/route test, full SNI preference, mini-host SNI preference, Cloudflare WARP manager, 2G Swap, backup/restore, diagnostic bundle, and dry-run preflight. |
| Operations | BBR/FQ tuning, TCP KeepAlive, Fail2Ban, logrotate, health probe, scheduled Geo data update, monthly traffic cutoff, SS-2022 whitelist, `--status`. |
| Maintenance safeguards | Lightweight preflight before protocol deployment; automatic backup before core upgrade; backup prompt before uninstall or environment reset; manual backup/restore; redacted diagnostics. |
| Export formats | URI, terminal QR, Clash/Mihomo YAML, sing-box outbound templates, v2rayN/v2rayNG JSON. |
| Safe deployment | New deployments stop managed services, clean A-Box firewall rules, detect port conflicts, and keep full uninstall/environment reset options available. |

---

## Full Menu Reference

| Menu | Function | Use case |
| :--- | :--- | :--- |
| `1` | Xray VLESS-Vision-Reality | Primary TCP REALITY + Vision path. |
| `2` | Xray VLESS-XHTTP-Reality | High-throughput XHTTP over REALITY path for compatible desktop clients. |
| `3` | Xray Shadowsocks-2022 | TCP/UDP relay or landing inbound; whitelist is recommended. |
| `4` | Official Hysteria 2 (Apernet) | UDP/QUIC/H3 path for mobile or lossy networks. |
| `5` | Xray + Official HY2 all-in-one | Vision + XHTTP + HY2 + SS-2022. |
| `6` | sing-box VLESS-Vision-Reality | Low-memory Vision deployment. |
| `7` | sing-box Shadowsocks-2022 | Low-memory SS-2022 deployment. |
| `8` | sing-box VLESS + SS-2022 | Lightweight two-protocol deployment. |
| `9` | sing-box Hysteria 2 | HY2 implemented by sing-box. |
| `10` | sing-box all-in-one | Vision + HY2 + SS-2022; XHTTP is excluded by design. |
| `11` | Toolbox | Benchmark, IP check, SNI preference, WARP, Swap, backup/restore, diagnostic bundle, dry-run preflight. |
| `12` | VPS one-click optimization | BBR/FQ, file limits, KeepAlive, Fail2Ban, health probe. |
| `13` | Display all node parameters | Show links, QR codes, YAML, JSON, and outbound templates. |
| `14` | Manual | Full terminal manual. |
| `15` | OTA, Geo & core upgrade | Update script, Xray Geo data, or upgrade installed cores without resetting node parameters. |
| `16` | Clean uninstall | Remove managed services, configs, firewall rules, and optional `sb` shortcut. |
| `17` | Delete nodes & reinitialize environment | Kill orphan processes, clean stale rules, and remove broken configs/services. |
| `18` | Monthly traffic limit | vnStat-based monthly quota; stops services after quota is reached. |
| `19` | SS-2022 whitelist manager | Add/remove frontend IP/CIDR and enforce DROP for non-whitelisted sources. |
| `20` | Language settings | Switch Chinese/English UI and save to `/etc/ddr/.lang`. |
| `0` | Exit | Exit the interactive menu. |

---

## Toolbox Details

| Submenu | Function | Description |
| :--- | :--- | :--- |
| `1` | System benchmark | Runs `bench.sh` for hardware and download speed testing. |
| `2` | IP quality and route test | Runs Check.Place for IP quality, streaming unlock, and route testing. |
| `3` | Local SNI preference | Runs the full built-in SNI preference library with higher concurrency and deeper verification. |
| `4` | Mini-host local SNI preference | Uses the same candidate library as full mode, but lowers concurrency and verification depth for low-spec hosts. |
| `5` | Cloudflare WARP manager | Downloads and runs a third-party WARP manager for egress IP masking and streaming unlock scenarios. A-Box prints SHA256 and requires strong confirmation before execution. |
| `6` | 2G Swap allocation | Creates `/swapfile` to reduce OOM risk on low-memory hosts. |
| `7` | Backup / Restore | Creates or restores A-Box configuration backups; excludes nested backups, diagnostics, and preflight reports to avoid recursive archive growth. |
| `8` | Redacted diagnostic bundle | Exports service status, ports, versions, logs, firewall snippets, cron entries, and a redacted environment file. Secrets are masked. |
| `9` | Full dry-run preflight check | Runs a non-destructive environment, dependency, network, GitHub, port, service, firewall, and storage check. |

---

## Maintenance Safeguards

- Lightweight preflight runs automatically before protocol deployment menus `1`-`10`. It checks root/TTY, OS/init support, CPU architecture, required commands, and GitHub API reachability. It does not block on ports already held by A-Box managed services.
- Menu `15` creates an automatic backup before core upgrade actions without resetting node parameters.
- Menus `16` and `17` ask whether to create a backup before uninstall or environment reset.
- Toolbox submenu `7` provides manual backup and restore.
- Toolbox submenu `8` exports a redacted diagnostic bundle. UUIDs, private keys, passwords, tokens, and client links are masked.
- Toolbox submenu `9` runs a full dry-run preflight report and saves it under `/etc/ddr/preflight/`.
- Third-party toolbox scripts are not part of A-Box. Before execution, A-Box displays the downloaded script SHA256 and requires the exact confirmation phrase `YES-RUN-UNTRUSTED`, unless `ABOX_REMOTE_SHA256_ALLOWLIST` explicitly contains the hash.
- OTA from the `main` branch is guarded by syntax/fingerprint validation plus SHA256 display and exact confirmation `YES-UPDATE-MAIN`; set `ABOX_OTA_SHA256_ALLOWLIST` to require a known hash.

---

## Recommended Deployment Schemes

| Scenario | Recommended option |
| :--- | :--- |
| Balanced production deployment | Menu `5`: Xray + Official HY2 all-in-one. |
| Low-memory lightweight deployment | Menu `10`: sing-box all-in-one. |
| Primary TCP path | Menu `1`: Xray VLESS-Vision-Reality (`443/TCP`). |
| High-throughput desktop backup | Menu `2`: Xray VLESS-XHTTP-Reality (`8443/TCP`). |
| Mobile or lossy network | Menu `4`: Official Hysteria 2 (`443/UDP`). |
| Relay/landing node | Menu `3`: Xray SS-2022 (`2053/TCP+UDP`) + whitelist. |

---

## SNI Selection Notes

- Run SNI preference on the VPS, not on your local laptop, because REALITY target quality depends mainly on the VPS-to-target path.
- Prefer candidates with `tls13=1`, `san=1`, valid ALPN, and same/near ASN or country when available.
- Avoid API-only, rate-limited, unstable, or abnormal response targets when normal `200` web/document/static-resource targets are available.
- Do not use raw IP addresses as SNI.
- Apple/iCloud-like SNI on non-443 ports is explicitly warned by the script.
- The fallback REALITY SNI is `www.microsoft.com`; Apple/iCloud domains are never used as built-in defaults.

---

## System Requirements

| Item | Requirement |
| :--- | :--- |
| Operating system | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux. |
| Init system | systemd or OpenRC. |
| CPU | amd64/x86_64, arm64/aarch64. |
| Privilege | root or sudo. |
| Network | Access to system package repositories and GitHub Releases. |
| Dependencies | Bash, curl, jq, openssl, iptables, vnStat and others are installed automatically when missing. |

---

## FAQ

### The script says no interactive TTY is available.
Run it from an interactive terminal. If a pipeline environment fails, download the script first and run `sudo bash A-Box.sh`.

### Deployment failed because a port is occupied.
The script checks for non-A-Box processes using selected ports. Release the port manually or choose a different port during deployment.

### Will preflight block reinstalling an already deployed stack?
No. The lightweight preflight used before protocol deployment does not fail just because A-Box-managed services already hold ports. Actual deployment still stops managed services before writing the new stack.

### What is included in backups and diagnostics?
Backups preserve A-Box configuration, service files, scripts, selected firewall/cron state, and related runtime metadata. Diagnostic bundles are redacted and intended for issue reporting or troubleshooting.

### Why does Hysteria 2 ask for up/down bandwidth?
Hysteria 2 uses the configured `up` and `down` values as bandwidth control and congestion-control parameters. Set them according to the VPS line capacity; overly low values can cap throughput.

### ACME certificate application failed.
For HTTP-01, make sure `80/TCP` is reachable and not occupied. For Cloudflare DNS-01, make sure the API token has DNS edit permission for the target zone.

### How should I choose SNI?
Use Toolbox menu `3` or `4`. Prefer results with TLS 1.3, SAN match, valid ALPN, and reasonable ASN/topology relationship with the VPS.

### Why did services stop after reaching the monthly traffic limit?
Menu `18` can enforce a monthly vnStat quota. Disable or adjust the quota there, then restart services.

---

## Feedback & Contribution

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull requests are welcome.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
