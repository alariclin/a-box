# A-Box | Односкриптовый Linux Toolkit для сетевого шлюза

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

A-Box — автономный Bash-скрипт для развертывания и обслуживания Linux network gateway. Он объединяет Xray-core, sing-box, официальный Hysteria 2, экспорт клиентских конфигураций, системную оптимизацию, лимиты трафика, контроль доступа, health checks, backup/restore, диагностику и локальный SNI preference radar.

> Используйте только в законных, авторизованных и соответствующих правилам средах. Пользователь несет ответственность за правовые, операционные и security-последствия.

## Safe Quick Start

Рекомендуется сначала скачать файл, проверить его и запустить self-test:

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh
sha256sum A-Box.sh
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh
```

Быстрый pipeline-режим:

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

After first installation:

```bash
sb
```

## Core Features

| Module | Description |
|---|---|
| Deployment | Installs dependencies, initializes runtime, deploys and manages Xray-core, sing-box, and official Hysteria 2. |
| Protocol stacks | VLESS-Vision-Reality, VLESS-XHTTP-Reality, Shadowsocks-2022, Hysteria 2. |
| Default ports | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`; custom ports are validated. |
| SNI policy | Default REALITY SNI is `www.microsoft.com`. Apple/iCloud domains are never used as built-in defaults. Apple/iCloud-like SNI on non-443 ports triggers a warning. |
| Built-in SNI radar | Local full/mini candidate library; no legacy remote SNI script. Scores HTTPS/TLS metrics, TLS 1.3, ALPN, SAN, ASN/topology, and saves records. |
| XHTTP export | Exports XHTTP client parameters using `/xhttp`, `stream-one`, HTTP/2 host, and `smux: false` for compatible clients such as Mihomo. |
| Hysteria 2 | Supports ACME HTTP-01, Cloudflare DNS-01, self-signed certificate pinning, masquerade, optional port hopping, and Salamander obfuscation. |
| Operations | BBR/FQ tuning, TCP KeepAlive, Fail2Ban, logrotate, health probe, Geo data update, monthly traffic cutoff, SS-2022 whitelist, and status reporting. |
| Safeguards | Preflight checks, deployment replacement confirmation, backup before risky actions, redacted diagnostics, and guarded OTA update. |

## Full Menu Reference

| Menu | Function | Use case |
|---:|---|---|
| `1` | Xray VLESS-Vision-Reality | Primary TCP REALITY + Vision path. |
| `2` | Xray VLESS-XHTTP-Reality | XHTTP over REALITY path. |
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
| `14` | Manual | Terminal manual. |
| `15` | OTA, Geo & core upgrade | Update A-Box script, Xray Geo data, or installed cores without resetting node parameters. |
| `16` | Clean uninstall | Remove managed services, configs, firewall rules, and optional `sb` shortcut. |
| `17` | Delete nodes & reinitialize | Clean stale processes, rules, broken configs and services. |
| `18` | Monthly traffic limit | vnStat-based monthly quota. |
| `19` | SS-2022 whitelist manager | Add/remove frontend IP/CIDR and enforce DROP. Switching back to whitelist mode removes stale global ACCEPT rules first. |
| `20` | Language settings | Switch Chinese/English UI and save to `/etc/ddr/.lang`. |
| `0` | Exit | Exit the menu. |

## Toolbox Details

| Submenu | Function | Description |
|---:|---|---|
| `1` | System benchmark | Runs `bench.sh`. |
| `2` | IP quality and route test | Runs Check.Place. |
| `3` | Local SNI preference | Full built-in SNI preference library with higher concurrency and deeper verification. |
| `4` | Mini-host local SNI preference | Same candidate library as full mode, but lower concurrency and verification depth. |
| `5` | Cloudflare WARP manager | Downloads a third-party WARP manager; displays SHA256 and requires strong confirmation. |
| `6` | 2G Swap allocation | Creates `/swapfile`. |
| `7` | Backup / Restore | Creates or restores A-Box backups. |
| `8` | Redacted diagnostic bundle | Exports status, ports, versions, logs, firewall snippets, cron entries, and redacted environment data. |
| `9` | Full dry-run preflight check | Non-destructive checks for environment, dependency, network, GitHub, ports, services, firewall, and storage. |
| `10` | SNI preference records | Displays saved results from `/etc/ddr/A-Box-sni-full.tsv` and `/etc/ddr/A-Box-sni-mini.tsv`. |

## Maintenance Safeguards

- Lightweight preflight runs automatically before deployment menus `1`-`10`.
- Menu `15` creates an automatic backup before core upgrade actions.
- Menus `16` and `17` ask whether to create a backup before uninstall or reset.
- Toolbox `7` provides manual backup/restore.
- Toolbox `8` exports redacted diagnostics.
- Toolbox `9` saves full dry-run reports under `/etc/ddr/preflight/`.
- Toolbox `10` displays saved full/mini SNI preference records.
- Third-party toolbox scripts require SHA256 display and exact confirmation `YES-RUN-UNTRUSTED`, unless `ABOX_REMOTE_SHA256_ALLOWLIST` contains the hash.
- OTA from `main` is guarded by syntax/fingerprint validation, SHA256 display, and `[Y/N]` confirmation. Non-interactive OTA must use `ABOX_OTA_SHA256_ALLOWLIST`.
- GitHub core downloads require official release asset SHA256 digest validation. Stable `latest` releases are used by default; prerelease/alpha builds are not used.

## SNI Selection Notes

- Run SNI preference on the VPS, not on a local laptop.
- Prefer `tls13=1`, `san=1`, valid ALPN, and same/near ASN or country when available.
- Avoid API-only, rate-limited, unstable, or abnormal response targets when normal `200` targets are available.
- Do not use raw IP addresses as SNI.
- Apple/iCloud-like SNI on non-443 ports is explicitly warned.
- Fallback REALITY SNI is `www.microsoft.com`; Apple/iCloud domains are never used as built-in defaults.
- Use Toolbox `10` to review saved results after Toolbox `3` or `4`.

## System Requirements

| Item | Requirement |
|---|---|
| OS | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux. |
| Init system | systemd or OpenRC. |
| CPU | amd64/x86_64, arm64/aarch64. |
| Privilege | root or sudo. |
| Network | Access to system repositories and GitHub Releases. |

## License

Apache License 2.0.
