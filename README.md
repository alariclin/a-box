# A-Box

One-click Linux network gateway toolkit.

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img width="804" height="867" alt="A-Box_github" src="https://github.com/user-attachments/assets/4f51a6a1-5d1b-49db-90df-98ffae63d1ca" />
</p>

A-Box is a standalone Bash script for deploying and maintaining Linux network gateway services.

It supports Xray-core, sing-box, official Hysteria 2, VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, Hysteria 2, node export, SNI preference testing, backup and restore, firewall handling, diagnostics, traffic limits, health checks, and core updates.

> Use this project only in legal, authorized, and compliant environments. You are responsible for all legal, operational, and security consequences.

## Compliance and Disclaimer

This project is provided only for network architecture testing, cybersecurity research, system operations automation, and lawful privacy protection in fully authorized environments.

Do not use this project for illegal attacks, unauthorized access, audit evasion, network abuse, infrastructure disruption, or any unlawful activity.

Use it only on servers, networks, and systems that you own, manage, or have explicit permission to operate.

This project is provided "as is", without warranty. By downloading, copying, deploying, or running it, you accept these terms.

## Safe Quick Start

This repository contains the reviewed build `2026-07-28-final-v8-rc2` (`ABOX_BUILD_EPOCH=2026072804`). Use the immutable local/release asset; do not pipe the mutable `main` branch directly into a root shell.

```bash
sha256sum -c install.sh.sha256
sudo bash install.sh --self-test
sudo bash install.sh --preflight
sudo bash install.sh
```

Useful non-interactive commands:

```bash
sudo bash install.sh --status
sudo bash install.sh --start
sudo bash install.sh --stop
sudo bash install.sh --version
```

Backups use manifest v3 plus SHA-256 and host HMAC authentication. The recovery key is **not** placed beside external archives. Export it explicitly to a separate trusted medium:

```bash
sudo bash install.sh --export-backup-key /secure/offline/A-Box-recovery.key
sudo bash install.sh --convert-legacy-backup OLD.tar.gz /root/A-Box-backups
```

Keep the recovery key in a different trust domain from the backup archive. Anyone holding both can authenticate modified archives.

## Main Features

| Area | What it does |
|---|---|
| Deployment | Installs dependencies and deploys Xray-core, sing-box, or official Hysteria 2. |
| Protocols | VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, and Hysteria 2. |
| Default ports | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`. |
| SNI radar | Built-in 4096-candidate SNI test library for REALITY/XHTTP target selection. |
| Exports | URI, QR code, Clash/Mihomo YAML, sing-box outbound templates, and v2rayN/v2rayNG JSON. |
| Firewall safety | Does not automatically disable UFW or firewalld. It tracks A-Box-created firewall rules for cleanup and rollback. |
| Service safety | Avoids global `killall` and checks A-Box service ownership before stopping managed services. |
| Recovery | Backs up and restores configs, service files, core binaries, Xray Geo data, firewall state, cron blocks, and runtime metadata. |
| Maintenance | Supports preflight checks, diagnostics, traffic limits, Fail2Ban, logrotate, health probe, Geo updates, and guarded OTA. |

## Menu

| Menu | Function |
|---:|---|
| `1` | Xray VLESS Vision REALITY |
| `2` | Xray VLESS XHTTP REALITY |
| `3` | Xray Shadowsocks-2022 |
| `4` | Official Hysteria 2 |
| `5` | Xray + Official HY2 all-in-one |
| `6` | sing-box VLESS Vision REALITY |
| `7` | sing-box Shadowsocks-2022 |
| `8` | sing-box VLESS + Shadowsocks-2022 |
| `9` | sing-box Hysteria 2 |
| `10` | sing-box all-in-one |
| `11` | Toolbox |
| `12` | VPS optimization |
| `13` | Show node parameters |
| `14` | Manual |
| `15` | OTA, Geo data, and core upgrade |
| `16` | Clean uninstall |
| `17` | Delete nodes and reinitialize |
| `18` | Monthly traffic limit |
| `19` | SS-2022 whitelist manager |
| `20` | Language settings |
| `0` | Exit |

## Toolbox

| Submenu | Function |
|---:|---|
| `1` | System benchmark |
| `2` | IP quality and route test |
| `3` | Full local SNI preference test |
| `4` | Mini-host local SNI preference test |
| `5` | Cloudflare WARP manager |
| `6` | 2G Swap allocation |
| `7` | Backup and restore |
| `8` | Redacted diagnostic bundle |
| `9` | Full dry-run preflight check |
| `10` | SNI preference records |

## Recommended Deployment

| Scenario | Recommended option |
|---|---|
| Balanced production use | Menu `5`: Xray + Official HY2 all-in-one |
| Low-memory VPS | Menu `10`: sing-box all-in-one |
| Main TCP path | Menu `1`: Xray VLESS Vision REALITY |
| High-throughput TCP backup | Menu `2`: Xray VLESS XHTTP REALITY |
| Mobile or unstable network | Menu `4`: Official Hysteria 2 |
| Relay or landing node | Menu `3`: Xray Shadowsocks-2022 + whitelist |

## SNI Notes

SNI preference testing is mainly for Xray REALITY and XHTTP REALITY.

Run SNI testing on the VPS, not on your local computer. The best target depends on the VPS-to-target network path.

Prefer results with `tls13=1`, `san=1`, valid ALPN, normal HTTP response, and a reasonable ASN or topology relationship with the VPS.

The built-in fallback REALITY SNI is:

```text
www.microsoft.com
```

Apple/iCloud domains are not used as built-in defaults. The script warns if an Apple/iCloud-like SNI is used on a non-443 port.

After running Toolbox `3` or `4`, use Toolbox `10` to view saved SNI records.

## Safety Design

A-Box is designed for production stability:

- It does not automatically disable UFW or firewalld.
- It adds only required A-Box ports when native firewalls are active.
- It tracks A-Box-created native firewall rules for cleanup and rollback.
- It avoids global `killall`.
- It checks A-Box service ownership before stopping managed services.
- It backs up important files before risky operations.
- It restores configs, service files, core binaries, Xray Geo data, firewall state, cron blocks, and runtime metadata.
- It validates GitHub Release asset SHA256 digests for core and Geo downloads.
- It uses stable latest releases by default, not alpha or prerelease builds.
- Third-party toolbox scripts require SHA256 display and exact confirmation unless their hash is explicitly allowlisted.
- OTA from `main` requires syntax/fingerprint validation, SHA256 display, and `[Y/N]` confirmation. Non-interactive OTA requires `ABOX_OTA_SHA256_ALLOWLIST`.

## System Requirements

| Item | Requirement |
|---|---|
| OS | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux |
| Init system | systemd or OpenRC |
| CPU | amd64/x86_64, arm64/aarch64 |
| Privilege | root or sudo |
| Network | Access to system repositories and GitHub Releases |
| Dependencies | Bash, curl, jq, openssl, iptables, vnStat, and other packages are installed automatically when missing |

## FAQ

### The script says no interactive TTY is available.
Run it from an interactive terminal. If pipeline mode fails, download the script first and run `sudo bash install.sh`.

### Deployment failed because a port is occupied.
Release the port manually or choose another port. A-Box checks for non-A-Box processes before deployment.

### Will preflight block reinstalling an existing A-Box stack?
No. The lightweight preflight does not fail only because A-Box-managed services already hold ports. Deployment still stops A-Box-managed services before writing the new stack.

### What is included in backups?
Backups include A-Box configs, service files, scripts, core binaries, Xray Geo data, native firewall state, A-Box cron blocks, selected firewall state, and runtime metadata.

### Why does Hysteria 2 ask for upload and download bandwidth?
Hysteria 2 uses these values for bandwidth and congestion control. Set them according to the VPS line capacity.

### ACME certificate application failed.
For HTTP-01, make sure `80/TCP` is reachable and not occupied. For Cloudflare DNS-01, make sure the API token has DNS edit permission for the target zone.

### How should I choose SNI?
Run Toolbox `3` or `4`, then check Toolbox `10`. Prefer TLS 1.3, SAN match, valid ALPN, normal HTTP response, and reasonable ASN/topology relationship with the VPS.

## Feedback and License

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull Requests are welcome.
- This project is released under the [Apache License 2.0](LICENSE).
