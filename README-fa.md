# A-Box | ابزار یک‌مرحله‌ای Linux Network Gateway

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<img width="1254" height="1254" alt="A-Box_github" src="https://github.com/user-attachments/assets/685e3814-304b-4383-975a-666a19f615ff" />



**A-Box** یک ابزار خودکار یکپارچه برای سرورهای Linux است. این ابزار deployment سرویس‌های proxy، system tuning، traffic management، access control، health checks، client configuration export، network quality tests، maintenance safeguards و Chinese/English terminal UI را در یک Bash script مستقل جمع می‌کند.

**قدردانی:** از پروژه‌های Xray-core، sing-box، Hysteria و پروژه‌های متن‌باز مرتبط برای الهام فنی و پشتیبانی اکوسیستم سپاس‌گزاریم. A-Box یک ابزار مستقل automation orchestration است.

[![Version](https://img.shields.io/badge/Version-2026.05.07-success.svg?style=flat-square)](https://github.com/alariclin/a-box/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/alariclin/a-box?style=flat-square&color=yellow)](https://github.com/alariclin/a-box/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alariclin/a-box?style=flat-square&color=orange)](https://github.com/alariclin/a-box/network/members)

---

## انطباق و سلب مسئولیت

این پروژه فقط برای **تست معماری شبکه، پژوهش امنیت سایبری و محافظت قانونی از حریم خصوصی در محیط‌های کاملاً مجاز** طراحی شده است.

1. **رعایت قانون:** از این پروژه برای فعالیت‌های ناقض قانون کشور یا منطقه خود استفاده نکنید.
2. **مسئولیت کاربر:** مسئولیت کامل پیامدهای حقوقی، عملیاتی و امنیتی استفاده نادرست بر عهده کاربر است.
3. **هدف فنی:** routing و encryption برای افزایش امنیت و حریم خصوصی انتقال داده هستند. استفاده برای حمله غیرقانونی، unauthorized access یا آسیب به زیرساخت ممنوع است.
4. **پذیرش شرایط:** دانلود، کپی یا اجرای اسکریپت به معنی پذیرش این شرایط است.

---

## شروع سریع

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

پس از اجرای اول، منو با این دستور باز می‌شود:

```bash
sb
```

---

## قابلیت‌های اصلی

| بخش | توضیح |
| :--- | :--- |
| One-click deployment | نصب وابستگی‌ها، آماده‌سازی محیط، deployment services و مدیریت Xray-core، sing-box و official Hysteria 2. |
| Protocol stack | VLESS-Vision-Reality، VLESS-XHTTP-Reality، Shadowsocks-2022، Hysteria 2. |
| Standard ports | Vision `443/TCP`، XHTTP `8443/TCP`، HY2 `443/UDP`، SS-2022 `2053/TCP+UDP`؛ custom ports پیش از deployment بررسی می‌شوند. |
| SNI policy | Default REALITY SNI برابر `www.microsoft.com` است. Apple/iCloud-like SNI روی non-443 ports هشدار و confirmation می‌گیرد. Production SNI با built-in SNI preference tool انتخاب شود. |
| Built-in SNI radar | Local candidate library با full و mini-host modes؛ بدون legacy remote SNI script dependency. امتیازدهی با HTTPS/TLS metrics، TLS 1.3، ALPN، SAN، ASN/topology و progress reporting. |
| XHTTP export | Export XHTTP parameters شامل `/xhttp`، `stream-one`، HTTP/2 host و `smux: false` برای compatible clients مانند Mihomo. |
| Hysteria 2 modes | ACME HTTP-01، Cloudflare DNS-01، self-signed certificate pinning، optional masquerade، port hopping و Salamander obfuscation. |
| Toolbox | Benchmark، IP quality/streaming/route test، full SNI preference، mini-host SNI preference، WARP manager، 2G Swap، backup/restore، diagnostic bundle، dry-run preflight. |
| Operations | BBR/FQ، TCP KeepAlive، Fail2Ban، logrotate، health probe، scheduled Geo update، monthly traffic cutoff، SS-2022 whitelist، `--status`. |
| Maintenance safeguards | Lightweight preflight پیش از protocol deployment؛ backup خودکار پیش از core upgrade؛ backup prompt پیش از uninstall/environment reset؛ manual backup/restore؛ redacted diagnostics. |

---

## منوی کامل

| منو | عملکرد | کاربرد |
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

| زیرمنو | عملکرد | توضیح |
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

## محافظت‌های عملیاتی

- پیش از منوهای `1` تا `10`، lightweight preflight به‌صورت خودکار اجرا می‌شود. root/TTY، OS/init، CPU architecture، required commands و GitHub API reachability را بررسی می‌کند و اگر پورت‌ها توسط managed services A-Box اشغال باشند، نصب مجدد را اشتباه متوقف نمی‌کند.
- منوی `15` پیش از core upgrade به‌صورت خودکار backup می‌گیرد و node parameters را ریست نمی‌کند.
- منوهای `16` و `17` پیش از uninstall یا environment reset درباره backup سؤال می‌کنند.
- Toolbox `7` manual backup/restore ارائه می‌دهد.
- Toolbox `8` redacted diagnostic bundle خروجی می‌دهد؛ UUID، private keys، passwords، tokens و client links پوشانده می‌شوند.
- Toolbox `9` full dry-run preflight report را اجرا و در `/etc/ddr/preflight/` ذخیره می‌کند.

---

## نکات انتخاب SNI

- SNI preference را روی VPS اجرا کنید نه laptop محلی؛ برای REALITY مسیر VPS -> target مهم است.
- کاندیداهای `tls13=1`، `san=1`، valid ALPN و same/near ASN یا country را ترجیح دهید.
- از raw IP به عنوان SNI استفاده نکنید.
- Apple/iCloud-like SNI روی non-443 ports توسط اسکریپت هشدار داده می‌شود.
- Default REALITY SNI fallback برابر `www.microsoft.com` است؛ Apple/iCloud domains به‌عنوان default داخلی استفاده نمی‌شوند.
- Third-party toolbox scripts خارج از کنترل A-Box هستند. A-Box SHA256 دانلودشده را نشان می‌دهد و پیش از اجرا `YES-RUN-UNTRUSTED` می‌خواهد. OTA نیز با `YES-UPDATE-MAIN` یا allowlist hash محافظت می‌شود.
- Hysteria 2 `up`/`down` bandwidth/congestion-control parameters هستند؛ آنها را مطابق ظرفیت VPS تنظیم کنید.

---

## نیازمندی‌های سیستم

| مورد | نیازمندی |
| :--- | :--- |
| Operating system | Debian 10+، Ubuntu 20.04+، CentOS/RHEL/Rocky/AlmaLinux 8+، Alpine Linux. |
| Init system | systemd یا OpenRC. |
| CPU | amd64/x86_64، arm64/aarch64. |
| Privilege | root یا sudo. |
| Network | دسترسی به system package repositories و GitHub Releases. |

---

## FAQ

### آیا preflight نصب مجدد stack نصب‌شده را متوقف می‌کند؟
خیر. lightweight preflight فقط به دلیل پورت‌های managed services A-Box شکست نمی‌خورد؛ deployment سرویس‌های قدیمی را متوقف می‌کند.

### backup و diagnostic bundle شامل چه چیزهایی هستند؟
Backup شامل A-Box configuration، service files، scripts، selected firewall/cron state و metadata است. Diagnostic bundle redacted است و برای issue reporting یا troubleshooting استفاده می‌شود.

### چگونه بهترین SNI را انتخاب کنم؟
از Toolbox menu `3` یا `4` استفاده کنید؛ TLS 1.3، SAN match، valid ALPN و ASN/topology منطقی با VPS را ترجیح دهید.

---

## بازخورد و مجوز

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull Request پذیرفته می‌شود.

این پروژه تحت مجوز [Apache License 2.0](LICENSE) منتشر شده است.
