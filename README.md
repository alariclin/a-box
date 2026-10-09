# A-Box

One-click Linux network gateway toolkit.

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img width="804" height="867" alt="A-Box_github" src="https://github.com/user-attachments/assets/4f51a6a1-5d1b-49db-90df-98ffae63d1ca" />
</p>

A-Box is a standalone Bash script for deploying and maintaining Linux network gateway services. The script build documented here is `2026-10-10-release-candidate-v170`; its configured default core versions are Xray `v26.7.28` and sing-box `v1.14.2`.

It supports Xray-core, sing-box, the official Hysteria 2 server, VLESS Vision REALITY, VLESS XHTTP REALITY, Shadowsocks-2022, client configuration export, local SNI candidate testing, backup and restore, firewall management, diagnostics, traffic limits, health checks, and core software upgrades.

> Use this project only in legal, authorized, and compliant environments. You are responsible for all legal, operational, and security consequences.

## Compliance and Disclaimer

This project is intended for network architecture testing, cybersecurity research, systems administration automation, and lawful privacy protection in fully authorized environments. Do not use it for unlawful attacks, unauthorized access, audit evasion, network abuse, infrastructure disruption, or any other illegal activity. Use it only on servers, networks, and systems that you own, manage, or have explicit permission to operate.

The project is provided “as is”, without warranty. Review the script and the changes it may make before running it, and keep recoverable backups before maintenance or upgrades.

## Safe Quick Start

### Official GitHub source

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

### Third-party fallback mirror

```bash
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

Use the official GitHub source by default. The mirror is a third-party service, not an official A-Box endpoint. The `main` branch is mutable; for production, prefer a reviewed, version-tagged release and verify its integrity before execution. After installation, enter `sb` to open the menu.

## Main Features

- **Protocol deployment:** Xray VLESS Vision REALITY; Xray VLESS XHTTP REALITY; Xray Shadowsocks-2022; official Hysteria 2; corresponding sing-box Vision, Shadowsocks-2022, and Hysteria 2 options.
- **Combined deployments:** Xray + Hysteria 2 bundle, and a sing-box Vision + Hysteria 2 + Shadowsocks-2022 bundle. The sing-box bundle intentionally does not include XHTTP.
- **Client configuration export:** share links/URIs, QR codes, Clash/Mihomo YAML, sing-box outbound templates, and v2rayN/v2rayNG XHTTP JSON.
- **Operations and diagnostics:** health checks, system/download benchmark, IP quality and route tests, VPS tuning, Fail2Ban/logrotate setup, traffic limits, backup and restore, redacted diagnostic bundles, and preflight checks.
- **SNI candidate workflow:** local full and mini-host candidate tests, saved-result viewer, input validation, bounded file size/row count, duplicate removal, and fallback to a valid local cache or adjacent data file when available.
- **Maintenance:** controlled script OTA with displayed SHA-256 and explicit confirmation, Xray Geo data updates, and core-only upgrades that preserve node parameters.
- **Safety controls:** deployment preflight checks, guarded service ownership/state changes, firewall handling, and rollback paths for supported operations.

The repository ships a curated seed list at [`data/sni-candidates.txt`](data/sni-candidates.txt). SNI entries are only candidates. A listed hostname is **not** a guarantee that it currently works from a particular VPS, supports the required TLS/ALPN/SAN characteristics, or is suitable for a specific REALITY deployment. Verify candidates on the target network before use. The SNI workflow fails closed when it cannot obtain a valid candidate list or fallback copy.

## Main Menu

| No. | Function |
|---:|---|
| `1` | Xray VLESS Vision REALITY |
| `2` | Xray VLESS XHTTP REALITY |
| `3` | Xray Shadowsocks-2022 |
| `4` | Official Hysteria 2 server |
| `5` | Xray + official Hysteria 2 bundle: Vision TCP 443, XHTTP TCP 8443, Hysteria 2 UDP 443, SS-2022 TCP/UDP 2053 |
| `6` | sing-box VLESS Vision REALITY |
| `7` | sing-box Shadowsocks-2022 |
| `8` | sing-box VLESS + Shadowsocks-2022 |
| `9` | sing-box Hysteria 2 |
| `10` | sing-box Vision + Hysteria 2 + Shadowsocks-2022 (no XHTTP) |
| `11` | Toolbox |
| `12` | VPS one-click optimization |
| `13` | Display node parameters and client configurations |
| `14` | Manual |
| `15` | Script OTA, Xray Geo data, and core-only upgrade |
| `16` | Full/partial uninstall |
| `17` | Remove nodes and reset the environment |
| `18` | Monthly traffic limit (vnStat-based; stops managed services when the quota is reached) |
| `19` | SS-2022 IP/CIDR allowlist manager |
| `20` | Switch between Chinese and English script UI |
| `0` | Exit |

### Toolbox

The toolbox includes system and download benchmarks; IP quality, streaming availability, and route tests; full and mini-host local SNI candidate tests; saved SNI results; a Cloudflare WARP manager (which, after confirmation, invokes a third-party script); 2 GB Swap setup; backup and restore; redacted diagnostic export; and a full read-only dry-run preflight check.

## Command-line Usage

The repository file is named `install.sh`. The curl examples below save it as `A-Box.sh`; either filename works if it is this script.

Run commands from the directory containing the script:

| Command | Purpose |
|---|---|
| `sudo bash install.sh --help` | Show command-line help |
| `sudo bash install.sh --lang zh` / `--lang en` | Set the UI language and start the menu |
| `sudo bash install.sh --self-test` | Run built-in regression/self-tests |
| `sudo bash install.sh --preflight` or `--dry-run` | Run the preflight check without deploying a new node |
| `sudo bash install.sh --status` | Show managed configuration and service status |
| `sudo bash install.sh --start` / `--stop` | Start or stop managed services |
| `sudo bash install.sh --version` | Show script build metadata |
| `sudo bash install.sh --export-backup-key /secure/path/A-Box-recovery.key` | Export the recovery key to a protected path |
| `sudo bash install.sh --convert-legacy-backup OLD.tar.gz [OUTPUT_DIR]` | Convert a legacy backup to manifest v3 format |

Protect exported recovery keys and backups. A `--self-test` pass does not replace a target-host preflight, live installation, or client interoperability test.

## System Requirements

The script contains compatibility paths for the following environments; actual compatibility depends on OS release, init system, architecture, dependencies, provider networking, and upstream downloads.

| Item | Requirement |
|---|---|
| OS families | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, or Alpine Linux |
| Init system | systemd or OpenRC |
| CPU architecture | amd64/x86_64 or arm64/aarch64 |
| Privileges | root or sudo |
| Network | Access to system package repositories and required upstream/GitHub release endpoints |
| Script UI | English or Simplified Chinese |

The four README translations do not mean that the interactive script itself supports all four languages; the script UI currently supports English and Simplified Chinese.

## Recommended Production Checklist

1. Review the script and choose a trusted, version-pinned source; do not blindly trust third-party mirrors.
2. Run `--self-test` and `--preflight` on the target VPS before deployment.
3. Confirm provider firewall/security-group rules and client compatibility for the selected protocol and ports.
4. Export and store the recovery key separately; keep a verified backup before destructive maintenance.
5. Verify actual DNS, TLS, ALPN, SNI, reachability, and client behavior from the networks that will use the node. Passing CI alone does not prove that all VPS providers, operating systems, or clients will work.

## Feedback and License

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull requests are welcome.
- Released under the [Apache License 2.0](LICENSE).
