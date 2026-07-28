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

### Global network

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

### Mainland China mirror

```bash
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

The mirror is a third-party acceleration service. If it is unavailable, use the global command. After installation, run `sb` to open the menu.

## Main Features

| Area | Function |
|---|---|
| Core deployment | Xray-core, sing-box, and official Hysteria 2 |
| Protocols | VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, and Hysteria 2 |
| Node export | URI, QR code, Clash/Mihomo YAML, sing-box outbound, and v2rayN/v2rayNG JSON |
| Network tools | SNI testing, IP quality, route testing, WARP, and VPS optimization |
| Operations | Health checks, traffic limits, Fail2Ban, logrotate, Geo updates, and core upgrades |
| Safety | Managed-service ownership checks, firewall rollback, deployment transactions, and guarded OTA |
| Recovery | Backup, restore, legacy-backup conversion, and diagnostic bundles |

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

### Toolbox

| Menu | Function |
|---:|---|
| `1` | System benchmark |
| `2` | IP quality and route test |
| `3` | Full local SNI test |
| `4` | Lightweight local SNI test |
| `5` | Cloudflare WARP manager |
| `6` | Create 2 GB swap |
| `7` | Backup and restore |
| `8` | Redacted diagnostic bundle |
| `9` | Full dry-run preflight |
| `10` | Saved SNI results |

## Usage

| Command | Function |
|---|---|
| `sb` | Open the main menu after installation |
| `sudo bash A-Box.sh --self-test` | Run built-in checks |
| `sudo bash A-Box.sh --preflight` | Check the server before deployment |
| `sudo bash A-Box.sh --status` | Show configuration and service status |
| `sudo bash A-Box.sh --start` | Start the managed stack |
| `sudo bash A-Box.sh --stop` | Stop the managed stack |
| `sudo bash A-Box.sh --version` | Show the build version |

## System Requirements

| Item | Requirement |
|---|---|
| OS | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, or Alpine Linux |
| Init system | systemd or OpenRC |
| CPU | amd64/x86_64 or arm64/aarch64 |
| Privilege | root or sudo |
| Network | Access to system repositories and GitHub Releases |
| Dependencies | Required packages are installed automatically when missing |

## Recommended Use

| Scenario | Recommended option |
|---|---|
| Balanced deployment | Menu `5`: Xray + Official HY2 all-in-one |
| Low-memory VPS | Menu `10`: sing-box all-in-one |
| Primary TCP connection | Menu `1`: Xray VLESS Vision REALITY |
| High-throughput TCP alternative | Menu `2`: Xray VLESS XHTTP REALITY |
| Mobile or unstable network | Menu `4`: Official Hysteria 2 |
| Relay or landing node | Menu `3`: Xray Shadowsocks-2022 with whitelist |

For production use, run `--self-test` and `--preflight` first, keep an independent backup recovery key, and prefer a tagged GitHub Release over an unpinned branch.

## Feedback and License

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull Requests are welcome.
- Released under the [Apache License 2.0](LICENSE).
