# A-Box | Инструментарий Linux Network Gateway в один шаг

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<img width="1254" height="1254" alt="A-Box_github" src="https://github.com/user-attachments/assets/469f3f77-836c-47c6-a0ed-e24c619c73a7" />



**A-Box** — единый автоматизированный инструментарий для Linux-серверов. Он объединяет развертывание proxy services, system tuning, traffic management, access control, health checks, client configuration export, network quality tests, maintenance safeguards и интерактивный Chinese/English terminal UI в одном Bash-скрипте.

**Благодарности:** Спасибо Xray-core, sing-box, Hysteria и связанным open-source проектам за технические идеи и поддержку экосистемы. A-Box является независимым инструментом automation orchestration.

[![Version](https://img.shields.io/badge/Version-2026.05.07-success.svg?style=flat-square)](https://github.com/alariclin/a-box/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/alariclin/a-box?style=flat-square&color=yellow)](https://github.com/alariclin/a-box/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alariclin/a-box?style=flat-square&color=orange)](https://github.com/alariclin/a-box/network/members)

---

## Соответствие требованиям и отказ от ответственности

Проект предназначен для **тестирования сетевой архитектуры, исследований кибербезопасности и легитимной защиты приватности только в авторизованных средах**.

1. **Соблюдение закона:** не используйте проект для действий, нарушающих законы вашей страны или региона.
2. **Ответственность пользователя:** пользователь несет ответственность за юридические, эксплуатационные и безопасностные последствия неправильного использования.
3. **Техническое назначение:** routing и encryption используются для повышения безопасности и приватности передачи данных. Не используйте инструмент для незаконных атак, unauthorized access или вреда инфраструктуре.
4. **Принятие условий:** загрузка, копирование или запуск означает принятие этих условий.

---

## Быстрый старт

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# Mirror channel
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# Language / checks
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh > A-Box.sh
sudo bash A-Box.sh --lang zh
sudo bash A-Box.sh --lang en
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh --status
sudo bash A-Box.sh --help
sudo bash A-Box.sh --preflight
sudo bash A-Box.sh --dry-run
```

После первого запуска меню открывается командой:

```bash
sb
```

---

## Основные возможности

| Модуль | Описание |
| :--- | :--- |
| One-click deployment | Установка зависимостей, инициализация окружения, deployment services и управление Xray-core, sing-box и official Hysteria 2. |
| Protocol stack | VLESS-Vision-Reality, VLESS-XHTTP-Reality, Shadowsocks-2022, Hysteria 2. |
| Standard ports | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`; custom ports проверяются перед deployment. |
| SNI policy | Default REALITY SNI — `www.microsoft.com`. Apple/iCloud-like SNI на не-443 ports вызывает warning и confirmation. Production SNI выбирается через built-in SNI preference tool. |
| Built-in SNI radar | Local candidate library, full и mini-host modes; no legacy remote SNI script dependency. Scoring по HTTPS/TLS metrics, TLS 1.3, ALPN, SAN, ASN/topology и progress reporting. |
| XHTTP export | Export XHTTP parameters: `/xhttp`, `stream-one`, HTTP/2 host, `smux: false` for compatible clients such as Mihomo. |
| Hysteria 2 modes | ACME HTTP-01, Cloudflare DNS-01, self-signed certificate pinning, optional masquerade, port hopping и Salamander obfuscation. |
| Toolbox | Benchmark, IP quality/streaming/route test, full SNI preference, mini-host SNI preference, WARP manager, 2G Swap, backup/restore, diagnostic bundle, dry-run preflight. |
| Operations | BBR/FQ, TCP KeepAlive, Fail2Ban, logrotate, health probe, scheduled Geo update, monthly traffic cutoff, SS-2022 whitelist, `--status`. |
| Maintenance safeguards | Lightweight preflight before protocol deployment; automatic backup before core upgrade; backup prompt before uninstall/environment reset; manual backup/restore; redacted diagnostics. |

---

## Полное меню

| Меню | Функция | Назначение |
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

## Toolbox

| Подменю | Функция | Описание |
| :--- | :--- | :--- |
| `1` | System benchmark | Runs `bench.sh` for hardware and download speed testing. |
| `2` | IP quality and route test | Runs Check.Place for IP quality, streaming unlock, and route testing. |
| `3` | Local SNI preference | Runs the full built-in SNI preference library with higher concurrency and deeper verification. |
| `4` | Mini-host local SNI preference | Uses the same candidate library as full mode, but lowers concurrency and verification depth for low-spec hosts. |
| `5` | Cloudflare WARP manager | Runs WARP manager for egress IP masking and streaming unlock scenarios. |
| `6` | 2G Swap allocation | Creates `/swapfile` to reduce OOM risk on low-memory hosts. |
| `7` | Backup / Restore | Creates or restores A-Box configuration backups; excludes nested backups, diagnostics, and preflight reports to avoid recursive archive growth. |
| `8` | Redacted diagnostic bundle | Exports service status, ports, versions, logs, firewall snippets, cron entries, and a redacted environment file. Secrets are masked. |
| `9` | Full dry-run preflight check | Runs a non-destructive environment, dependency, network, GitHub, port, service, firewall, and storage check. |

---

## Maintenance Safeguards

- Перед меню `1`-`10` автоматически выполняется lightweight preflight. Он проверяет root/TTY, OS/init, CPU architecture, required commands и GitHub API reachability. Он не блокирует переустановку из-за портов, уже занятых managed services A-Box.
- Меню `15` автоматически создает backup перед core upgrade без сброса node parameters.
- Меню `16` и `17` спрашивают, нужно ли создать backup перед uninstall или environment reset.
- Toolbox `7` выполняет manual backup/restore.
- Toolbox `8` exports redacted diagnostic bundle; UUID, private keys, passwords, tokens и client links masked.
- Toolbox `9` runs full dry-run preflight report and saves it under `/etc/ddr/preflight/`.

---

## SNI Selection Notes

- Запускайте SNI preference на VPS, а не на локальном компьютере; для REALITY важен path VPS -> target.
- Предпочитайте `tls13=1`, `san=1`, valid ALPN и same/near ASN или country.
- Не используйте raw IP as SNI.
- Apple/iCloud-like SNI on non-443 ports is explicitly warned by the script.
- Default REALITY SNI fallback is `www.microsoft.com`; Apple/iCloud domains are not built-in defaults.
- Third-party toolbox scripts are outside A-Box control. A-Box shows the downloaded SHA256 and requires `YES-RUN-UNTRUSTED` before execution. OTA requires SHA256 confirmation with `YES-UPDATE-MAIN` unless an allowlist is configured.
- Hysteria 2 `up`/`down` values are bandwidth/congestion-control parameters; set them according to VPS capacity.

---

## System Requirements

| Item | Requirement |
| :--- | :--- |
| Operating system | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux. |
| Init system | systemd or OpenRC. |
| CPU | amd64/x86_64, arm64/aarch64. |
| Privilege | root or sudo. |
| Network | Access to system package repositories and GitHub Releases. |

---

## FAQ

### Может ли preflight заблокировать переустановку уже развернутого stack?
Нет. Lightweight preflight не падает только из-за портов, занятых managed services A-Box; deployment все равно останавливает old managed services.

### Что входит в backup и diagnostic bundle?
Backup сохраняет A-Box configuration, service files, scripts, selected firewall/cron state и metadata. Diagnostic bundle redacted and intended for issue reporting or troubleshooting.

### Как выбрать лучший SNI?
Используйте Toolbox menu `3` или `4`; предпочитайте TLS 1.3, SAN match, valid ALPN и разумную ASN/topology связь с VPS.

---

## Обратная связь и лицензия

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull requests приветствуются.

Проект распространяется по лицензии [Apache License 2.0](LICENSE).
