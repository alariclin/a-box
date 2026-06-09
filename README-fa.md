# A-Box | ابزار یک‌مرحله‌ای دروازه شبکه لینوکس

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/alariclin/a-box/main/A-Box_github.png" alt="A-Box_github" width="720">
</p>

<p align="center">
  <a href="https://github.com/alariclin/a-box/releases"><img src="https://img.shields.io/badge/Version-2026.05.07-success.svg?style=flat-square" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/alariclin/a-box/stargazers"><img src="https://img.shields.io/github/stars/alariclin/a-box?style=flat-square&color=yellow" alt="GitHub Stars"></a>
  <a href="https://github.com/alariclin/a-box/network/members"><img src="https://img.shields.io/github/forks/alariclin/a-box?style=flat-square&color=orange" alt="GitHub Forks"></a>
</p>

**A-Box** یک ابزار Bash یکپارچه برای خودکارسازی سرورهای لینوکس و دروازه‌های شبکه است.

این ابزار استقرار سرویس‌های پروکسی، تنظیمات سیستم، مدیریت ترافیک، کنترل دسترسی، بررسی سلامت سرویس‌ها، خروجی گرفتن از پیکربندی کلاینت‌ها، آزمایش کیفیت شبکه، محافظت‌های نگه‌داری و رابط تعاملی ترمینال به زبان‌های چینی/انگلیسی را در یک اسکریپت مستقل جمع می‌کند.

**قدردانی:** از پروژه‌های Xray-core، sing-box، Hysteria و پروژه‌های متن‌باز مرتبط برای الهام فنی و پشتیبانی اکوسیستم سپاس‌گزاریم. A-Box یک ابزار مستقل برای خودکارسازی و هماهنگ‌سازی عملیات است.

---

## انطباق و سلب مسئولیت

این پروژه فقط برای **آزمایش معماری شبکه، پژوهش امنیت سایبری و حفاظت قانونی از حریم خصوصی در محیط‌های مجاز** طراحی شده است.

1. **رعایت قانون:** از این پروژه برای فعالیت‌هایی که قوانین کشور یا منطقه شما را نقض می‌کنند استفاده نکنید.
2. **مسئولیت کاربر:** مسئولیت کامل پیامدهای حقوقی، عملیاتی و امنیتی استفاده نادرست بر عهده کاربر است.
3. **هدف فنی:** مسیریابی و رمزنگاری برای افزایش امنیت و حریم خصوصی انتقال داده استفاده می‌شوند. استفاده برای حمله غیرقانونی، دسترسی غیرمجاز یا آسیب به زیرساخت ممنوع است.
4. **پذیرش شرایط:** دانلود، کپی یا اجرای اسکریپت به معنی پذیرش این شرایط است.

---

## شروع سریع

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# کانال آینه؛ فقط وقتی raw.githubusercontent.com در دسترس نیست استفاده شود
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# بررسی‌ها و گزینه‌های زبان
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
| استقرار یک‌مرحله‌ای | نصب وابستگی‌ها، آماده‌سازی محیط، ساخت سرویس‌ها و مدیریت Xray-core، sing-box و Hysteria 2 رسمی. |
| مجموعه پروتکل‌ها | VLESS-Vision-Reality، VLESS-XHTTP-Reality، Shadowsocks-2022 و Hysteria 2. |
| پورت‌های استاندارد | Vision `443/TCP`، XHTTP `8443/TCP`، HY2 `443/UDP`، SS-2022 `2053/TCP+UDP`؛ پورت‌های سفارشی پیش از استقرار بررسی می‌شوند. |
| سیاست SNI | SNI پیش‌فرض REALITY برابر `www.microsoft.com` است. SNIهای شبیه Apple/iCloud روی پورت‌های غیر `443` هشدار و تأیید می‌گیرند. SNI تولیدی باید با ابزار داخلی انتخاب SNI انتخاب شود. |
| رادار داخلی SNI | کتابخانه محلی کاندیداها با حالت full و mini-host؛ بدون وابستگی به اسکریپت SNI قدیمی و راه‌دور. امتیازدهی بر اساس HTTPS/TLS metrics، TLS 1.3، ALPN، SAN، ASN/topology و گزارش پیشرفت انجام می‌شود. |
| خروجی XHTTP | خروجی پارامترهای XHTTP شامل `/xhttp`، `stream-one`، HTTP/2 host و `smux: false` برای کلاینت‌های سازگار مانند Mihomo. |
| حالت‌های Hysteria 2 | ACME HTTP-01، Cloudflare DNS-01، pinning گواهی self-signed، masquerade اختیاری، port hopping و Salamander obfuscation. |
| جعبه‌ابزار | Benchmark، بررسی IP/streaming/route، انتخاب کامل SNI، انتخاب mini-host SNI، WARP، Swap دو گیگابایتی، backup/restore، بسته تشخیصی، dry-run preflight. |
| عملیات | BBR/FQ، TCP KeepAlive، Fail2Ban، logrotate، health probe، به‌روزرسانی زمان‌بندی‌شده Geo، قطع سرویس بر اساس سقف ماهانه ترافیک، whitelist برای SS-2022، `--status`. |
| محافظت‌های نگه‌داری | preflight سبک پیش از استقرار پروتکل؛ backup خودکار پیش از ارتقای core؛ پرسش backup پیش از حذف یا بازنشانی محیط؛ backup/restore دستی؛ diagnostics بدون اطلاعات حساس. |

---

## منوی کامل

| منو | عملکرد | کاربرد |
| :--- | :--- | :--- |
| `1` | Xray VLESS-Vision-Reality | مسیر اصلی TCP با REALITY + Vision. |
| `2` | Xray VLESS-XHTTP-Reality | مسیر پرظرفیت XHTTP over REALITY برای کلاینت‌های دسکتاپ سازگار. |
| `3` | Xray Shadowsocks-2022 | ورودی TCP/UDP relay یا landing؛ استفاده از whitelist توصیه می‌شود. |
| `4` | Official Hysteria 2 (Apernet) | مسیر UDP/QUIC/H3 برای موبایل یا شبکه‌های دارای packet loss. |
| `5` | Xray + Official HY2 all-in-one | Vision + XHTTP + HY2 + SS-2022. |
| `6` | sing-box VLESS-Vision-Reality | استقرار Vision برای سرورهای کم‌حافظه. |
| `7` | sing-box Shadowsocks-2022 | استقرار SS-2022 برای سرورهای کم‌حافظه. |
| `8` | sing-box VLESS + SS-2022 | استقرار سبک دوپروتکلی. |
| `9` | sing-box Hysteria 2 | HY2 پیاده‌سازی‌شده با sing-box. |
| `10` | sing-box all-in-one | Vision + HY2 + SS-2022؛ XHTTP عمداً حذف شده است. |
| `11` | Toolbox | Benchmark، بررسی IP، انتخاب SNI، WARP، Swap، backup/restore، diagnostics، dry-run preflight. |
| `12` | VPS one-click optimization | BBR/FQ، file limits، KeepAlive، Fail2Ban، health probe. |
| `13` | Display all node parameters | نمایش links، QR codes، YAML، JSON و outbound templates. |
| `14` | Manual | راهنمای کامل در ترمینال. |
| `15` | OTA, Geo & core upgrade | به‌روزرسانی اسکریپت، داده‌های Geo برای Xray یا coreهای نصب‌شده بدون ریست کردن پارامترهای نود. |
| `16` | Clean uninstall | حذف سرویس‌های مدیریت‌شده، configs، firewall rules و در صورت انتخاب shortcut `sb`. |
| `17` | Delete nodes & reinitialize environment | حذف فرایندهای باقی‌مانده، قوانین قدیمی و configs/services خراب. |
| `18` | Monthly traffic limit | سهمیه ماهانه بر پایه vnStat؛ پس از رسیدن به سقف، سرویس‌ها متوقف می‌شوند. |
| `19` | SS-2022 whitelist manager | افزودن/حذف frontend IP/CIDR و اعمال DROP برای منابع خارج از whitelist. |
| `20` | Language settings | تغییر UI چینی/انگلیسی و ذخیره در `/etc/ddr/.lang`. |
| `0` | Exit | خروج از منوی تعاملی. |

---

## Toolbox

| زیرمنو | عملکرد | توضیح |
| :--- | :--- | :--- |
| `1` | System benchmark | اجرای `bench.sh` برای آزمایش سخت‌افزار و سرعت دانلود. |
| `2` | IP quality and route test | اجرای Check.Place برای بررسی کیفیت IP، streaming unlock و مسیر شبکه. |
| `3` | Local SNI preference | اجرای انتخاب کامل SNI با موازی‌سازی بیشتر و بررسی عمیق‌تر. |
| `4` | Mini-host local SNI preference | استفاده از همان کتابخانه کاندیداها با موازی‌سازی و عمق کمتر برای VPSهای ضعیف. |
| `5` | Cloudflare WARP manager | اجرای WARP manager برای ماسک کردن IP خروجی و سناریوهای streaming unlock. |
| `6` | 2G Swap allocation | ساخت `/swapfile` برای کاهش ریسک OOM روی سرورهای کم‌حافظه. |
| `7` | Backup / Restore | ساخت یا بازیابی backup پیکربندی A-Box؛ backupهای تو در تو، diagnostics و preflight reports را حذف می‌کند تا archive به‌صورت بازگشتی بزرگ نشود. |
| `8` | Redacted diagnostic bundle | خروجی گرفتن از وضعیت سرویس‌ها، پورت‌ها، نسخه‌ها، لاگ‌ها، firewall snippets، cron entries و environment file بدون اطلاعات حساس. Secrets پوشانده می‌شوند. |
| `9` | Full dry-run preflight check | اجرای بررسی غیرمخرب محیط، وابستگی‌ها، شبکه، GitHub، پورت‌ها، سرویس‌ها، firewall و فضای ذخیره‌سازی. |
| `10` | SNI preference records | نمایش نتایج ذخیره‌شده full/mini SNI از `/etc/ddr/A-Box-sni-full.tsv` و `/etc/ddr/A-Box-sni-mini.tsv`. |

---

## محافظت‌های عملیاتی

- پیش از منوهای `1` تا `10`، lightweight preflight به‌صورت خودکار اجرا می‌شود. root/TTY، OS/init، CPU architecture، required commands و دسترسی به GitHub API را بررسی می‌کند و اگر پورت‌ها توسط سرویس‌های مدیریت‌شده A-Box اشغال باشند، نصب مجدد را بی‌دلیل متوقف نمی‌کند.
- منوی `15` پیش از core upgrade به‌صورت خودکار backup می‌گیرد و پارامترهای نود را ریست نمی‌کند.
- منوی `15` برای OTA، SHA256 اسکریپت دانلودشده را نشان می‌دهد و از تأیید `[Y/N]` استفاده می‌کند.
- منوهای `16` و `17` پیش از uninstall یا environment reset درباره backup سؤال می‌کنند.
- Toolbox `7` قابلیت manual backup/restore دارد.
- Toolbox `8` بسته تشخیصی بدون اطلاعات حساس تولید می‌کند؛ UUID، private keys، passwords، tokens و client links پوشانده می‌شوند.
- Toolbox `9` گزارش کامل dry-run preflight را اجرا و در `/etc/ddr/preflight/` ذخیره می‌کند.
- منوی `19` هنگام برگشت SS-2022 از حالت باز به whitelist، ابتدا ACCEPT ruleهای عمومی قدیمی را پاک می‌کند و سپس whitelist/DROP rules را اعمال می‌کند.

---

## نکات انتخاب SNI

- انتخاب SNI را روی VPS اجرا کنید، نه روی لپ‌تاپ محلی؛ برای REALITY مسیر VPS -> target مهم است.
- کاندیداهای دارای `tls13=1`، `san=1`، ALPN معتبر و ارتباط منطقی ASN/topology با VPS را ترجیح دهید.
- از raw IP به عنوان SNI استفاده نکنید.
- SNIهای شبیه Apple/iCloud روی پورت‌های غیر `443` توسط اسکریپت هشدار می‌گیرند.
- fallback SNI پیش‌فرض REALITY برابر `www.microsoft.com` است؛ Apple/iCloud domains به‌عنوان default داخلی استفاده نمی‌شوند.
- اسکریپت‌های شخص ثالث در Toolbox خارج از کنترل A-Box هستند. A-Box مقدار SHA256 دانلود را نشان می‌دهد و پیش از اجرا `YES-RUN-UNTRUSTED` می‌خواهد.
- مقادیر `up`/`down` در Hysteria 2 پارامترهای پهنای‌باند و congestion control هستند؛ آنها را مطابق ظرفیت واقعی VPS تنظیم کنید.

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

خیر. lightweight preflight فقط به دلیل پورت‌هایی که توسط سرویس‌های مدیریت‌شده A-Box اشغال شده‌اند شکست نمی‌خورد؛ deployment سرویس‌های قدیمی را متوقف می‌کند.

### backup و diagnostic bundle شامل چه چیزهایی هستند؟

Backup شامل پیکربندی A-Box، service files، scripts، وضعیت منتخب firewall/cron و metadata است. Diagnostic bundle بدون اطلاعات حساس تولید می‌شود و برای issue reporting یا troubleshooting کاربرد دارد.

### چگونه بهترین SNI را انتخاب کنم؟

از Toolbox menu `3` یا `4` استفاده کنید؛ TLS 1.3، SAN match، ALPN معتبر و ارتباط منطقی ASN/topology با VPS را ترجیح دهید.

---

## بازخورد و مجوز

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull Request پذیرفته می‌شود.
- این پروژه تحت مجوز [Apache License 2.0](LICENSE) منتشر شده است.
