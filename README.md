# A-Box

One-click Linux network gateway toolkit.

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img width="804" height="867" alt="A-Box_github" src="https://github.com/user-attachments/assets/4f51a6a1-5d1b-49db-90df-98ffae63d1ca" />
</p>

A-Box is a standalone Bash script for deploying and maintaining Linux network gateway services.

It supports Xray-core, sing-box, the official Hysteria 2 server, VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, client configuration export, SNI testing, backup and restore, firewall management, diagnostics, traffic limits, health checks, and core software upgrades.

> Use this project only in legal, authorized, and compliant environments. You are responsible for all legal, operational, and security consequences.

## Compliance and Disclaimer

This project is intended only for network architecture testing, cybersecurity research, system administration automation, and lawful privacy protection in fully authorized environments.

Do not use it for unlawful attacks, unauthorized access, audit evasion, network abuse, infrastructure disruption, or any other illegal activity.

Use it only on servers, networks, and systems that you own, manage, or have explicit permission to operate.

This project is provided "as is", without warranty. By downloading, copying, deploying, or running it, you accept these terms.

## Safe Quick Start

### Official GitHub source

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

### Fallback mirror for restricted or unreliable GitHub access (third-party)

```bash
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

Use the third-party mirror only when the official GitHub source is unavailable or unreliable. Prefer the official source whenever possible. After installation, run `sb` to open the menu.

## Main Features

| Area | Function |
|---|---|
| Service deployment | Xray-core, sing-box, and the official Hysteria 2 server |
| Protocols | VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, and Hysteria 2 |
| Configuration export | URI, QR code, Clash/Mihomo YAML, sing-box outbound templates, and v2rayN/v2rayNG JSON |
| Network tools | SNI testing, IP quality and route tests, WARP management, and VPS optimization |
| Operations | Health checks, traffic limits, Fail2Ban, logrotate, Geo updates, and core software upgrades |
| Safety | Managed-service ownership checks, firewall rollback, deployment transactions, and guarded OTA |
| Recovery | Backup and restore, legacy-backup conversion, and redacted diagnostic bundles |

## Menu

| Menu | Function |
|---:|---|
| `1` | Xray VLESS Vision REALITY |
| `2` | Xray VLESS XHTTP REALITY |
| `3` | Xray Shadowsocks-2022 |
| `4` | Official Hysteria 2 server |
| `5` | Xray + Official Hysteria 2 bundle |
| `6` | sing-box VLESS Vision REALITY |
| `7` | sing-box Shadowsocks-2022 |
| `8` | sing-box VLESS + Shadowsocks-2022 |
| `9` | sing-box Hysteria 2 |
| `10` | sing-box bundle |
| `11` | Toolbox |
| `12` | VPS optimization |
| `13` | Show client configuration |
| `14` | Help |
| `15` | OTA, Geo data, and core software upgrades |
| `16` | Complete uninstall |
| `17` | Delete configurations and reset the environment |
| `18` | Monthly traffic limit |
| `19` | SS-2022 allowlist manager |
| `20` | Language settings |
| `0` | Exit |

### Toolbox

| Menu | Function |
|---:|---|
| `1` | System benchmark |
| `2` | IP quality and route test |
| `3` | Full local SNI test |
| `4` | Lightweight SNI test for low-resource servers |
| `5` | Cloudflare WARP manager |
| `6` | Create a 2 GB swap file |
| `7` | Backup and restore |
| `8` | Redacted diagnostic bundle |
| `9` | Full read-only preflight check (`dry-run`) |
| `10` | Saved SNI results |

## Usage

| Command | Function |
|---|---|
| `sb` | Open the main menu after installation |
| `sudo bash A-Box.sh --self-test` | Run the built-in checks |
| `sudo bash A-Box.sh --preflight` | Check the server before deployment |
| `sudo bash A-Box.sh --status` | Show configuration and service status |
| `sudo bash A-Box.sh --start` | Start the managed services |
| `sudo bash A-Box.sh --stop` | Stop the managed services |
| `sudo bash A-Box.sh --version` | Show the build version |

## System Requirements

| Item | Requirement |
|---|---|
| OS | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, or Alpine Linux |
| Init system | systemd or OpenRC |
| CPU architecture | amd64/x86_64 or arm64/aarch64 |
| Privileges | root or sudo |
| Network | Access to system package repositories and GitHub Releases |
| Dependencies | Missing required packages are installed automatically |
| Script interface | English or Simplified Chinese |

## Recommended Use

| Scenario | Recommended option |
|---|---|
| Balanced deployment | Menu `5`: Xray + Official Hysteria 2 bundle |
| Low-memory VPS | Menu `10`: sing-box bundle |
| Primary TCP connection | Menu `1`: Xray VLESS Vision REALITY |
| High-throughput TCP alternative | Menu `2`: Xray VLESS XHTTP REALITY |
| Mobile or unstable network | Menu `4`: Official Hysteria 2 server |
| Relay or exit node | Menu `3`: Xray Shadowsocks-2022 with an allowlist |

For production use, run `--self-test` and `--preflight` first, store the backup recovery key separately, and prefer a version-tagged GitHub Release over a mutable branch such as `main`.

Documentation is available in English, Simplified Chinese, Russian, and Persian. The interactive script interface is available in English and Simplified Chinese.

## Feedback and License

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull requests are welcome.
- Released under the [Apache License 2.0](LICENSE).
