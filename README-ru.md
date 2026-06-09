# A-Box | Однокомандный инструментарий Linux Network Gateway

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

**A-Box** — единый Bash-инструмент для автоматизации Linux-серверов и сетевых шлюзов.

Он объединяет развертывание прокси-служб, настройку системы, управление трафиком, контроль доступа, проверку состояния служб, экспорт клиентских конфигураций, сетевые тесты, защитные процедуры обслуживания и интерактивный терминальный интерфейс на китайском/английском языке.

**Благодарности:** спасибо проектам Xray-core, sing-box, Hysteria и связанным open-source проектам за технические идеи и поддержку экосистемы. A-Box является независимым инструментом автоматизации и оркестрации.

---

## Соответствие требованиям и отказ от ответственности

Проект предназначен только для **тестирования сетевой архитектуры, исследований кибербезопасности и законной защиты приватности в авторизованных средах**.

1. **Соблюдение закона:** не используйте проект для действий, нарушающих законы вашей страны или региона.
2. **Ответственность пользователя:** пользователь несет полную ответственность за юридические, операционные и безопасностные последствия неправильного использования.
3. **Техническое назначение:** маршрутизация и шифрование используются для повышения безопасности и приватности передачи данных. Запрещено использовать инструмент для незаконных атак, несанкционированного доступа или вреда инфраструктуре.
4. **Принятие условий:** загрузка, копирование или запуск скрипта означает принятие этих условий.

---

## Быстрый старт

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# Зеркальный канал; используйте только если raw.githubusercontent.com недоступен
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash

# Проверки и параметры языка
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
| Развертывание в один шаг | Устанавливает зависимости, инициализирует окружение, создает службы и управляет Xray-core, sing-box и официальной Hysteria 2. |
| Набор протоколов | VLESS-Vision-Reality, VLESS-XHTTP-Reality, Shadowsocks-2022, Hysteria 2. |
| Стандартные порты | Vision `443/TCP`, XHTTP `8443/TCP`, HY2 `443/UDP`, SS-2022 `2053/TCP+UDP`; пользовательские порты проверяются перед развертыванием. |
| Политика SNI | SNI по умолчанию для REALITY — `www.microsoft.com`. Apple/iCloud-подобные SNI на портах не `443` вызывают предупреждение и подтверждение. Рабочий SNI выбирается встроенным инструментом подбора SNI. |
| Встроенный SNI-радар | Локальная библиотека кандидатов, полный режим и mini-host режим; нет зависимости от старого удаленного SNI-скрипта. Оценка учитывает HTTPS/TLS метрики, TLS 1.3, ALPN, SAN, ASN/топологию и прогресс проверки. |
| Экспорт XHTTP | Экспортирует параметры XHTTP: `/xhttp`, `stream-one`, HTTP/2 host, `smux: false` для совместимых клиентов, например Mihomo. |
| Режимы Hysteria 2 | ACME HTTP-01, Cloudflare DNS-01, pinning самоподписанного сертификата, опциональная маскировка, port hopping и Salamander obfuscation. |
| Инструменты | Benchmark, проверка IP/стриминга/маршрута, полный подбор SNI, mini-host подбор SNI, WARP, Swap 2G, backup/restore, диагностический пакет, dry-run preflight. |
| Эксплуатация | BBR/FQ, TCP KeepAlive, Fail2Ban, logrotate, health probe, плановое обновление Geo, месячный лимит трафика, whitelist для SS-2022, `--status`. |
| Защитные процедуры | Легкий preflight перед развертыванием протоколов; автоматический backup перед обновлением core; запрос backup перед удалением или сбросом окружения; ручной backup/restore; обезличенная диагностика. |

---

## Полное меню

| Меню | Функция | Назначение |
| :--- | :--- | :--- |
| `1` | Xray VLESS-Vision-Reality | Основной TCP-путь REALITY + Vision. |
| `2` | Xray VLESS-XHTTP-Reality | Производительный XHTTP over REALITY для совместимых desktop-клиентов. |
| `3` | Xray Shadowsocks-2022 | TCP/UDP relay или landing inbound; рекомендуется whitelist. |
| `4` | Official Hysteria 2 (Apernet) | UDP/QUIC/H3 путь для мобильных или нестабильных сетей. |
| `5` | Xray + Official HY2 all-in-one | Vision + XHTTP + HY2 + SS-2022. |
| `6` | sing-box VLESS-Vision-Reality | Vision-развертывание для малопамятных серверов. |
| `7` | sing-box Shadowsocks-2022 | SS-2022 для малопамятных серверов. |
| `8` | sing-box VLESS + SS-2022 | Легкое двухпротокольное развертывание. |
| `9` | sing-box Hysteria 2 | HY2 на базе sing-box. |
| `10` | sing-box all-in-one | Vision + HY2 + SS-2022; XHTTP намеренно исключен. |
| `11` | Toolbox | Benchmark, IP check, SNI preference, WARP, Swap, backup/restore, diagnostics, dry-run preflight. |
| `12` | VPS one-click optimization | BBR/FQ, file limits, KeepAlive, Fail2Ban, health probe. |
| `13` | Display all node parameters | Показывает ссылки, QR-коды, YAML, JSON и outbound-шаблоны. |
| `14` | Manual | Полное терминальное руководство. |
| `15` | OTA, Geo & core upgrade | Обновление скрипта, Geo-данных Xray или установленных core без сброса параметров узла. |
| `16` | Clean uninstall | Удаляет управляемые службы, конфиги, firewall rules и опционально ярлык `sb`. |
| `17` | Delete nodes & reinitialize environment | Удаляет зависшие процессы, устаревшие правила и поврежденные configs/services. |
| `18` | Monthly traffic limit | Месячная квота на базе vnStat; службы останавливаются после достижения лимита. |
| `19` | SS-2022 whitelist manager | Добавление/удаление frontend IP/CIDR и принудительный DROP для источников вне whitelist. |
| `20` | Language settings | Переключение китайского/английского UI с сохранением в `/etc/ddr/.lang`. |
| `0` | Exit | Выход из интерактивного меню. |

---

## Toolbox

| Подменю | Функция | Описание |
| :--- | :--- | :--- |
| `1` | System benchmark | Запускает `bench.sh` для теста железа и скорости загрузки. |
| `2` | IP quality and route test | Запускает Check.Place для проверки качества IP, streaming unlock и маршрутизации. |
| `3` | Local SNI preference | Запускает полный встроенный подбор SNI с большей параллельностью и глубокой проверкой. |
| `4` | Mini-host local SNI preference | Использует ту же библиотеку кандидатов, но снижает параллельность и глубину проверки для слабых VPS. |
| `5` | Cloudflare WARP manager | Запускает WARP manager для маскирования egress IP и сценариев streaming unlock. |
| `6` | 2G Swap allocation | Создает `/swapfile`, чтобы снизить риск OOM на малопамятных серверах. |
| `7` | Backup / Restore | Создает или восстанавливает backup конфигурации A-Box; исключает вложенные backups, diagnostics и preflight reports. |
| `8` | Redacted diagnostic bundle | Экспортирует состояние служб, порты, версии, логи, firewall snippets, cron entries и обезличенный environment-файл. Секреты маскируются. |
| `9` | Full dry-run preflight check | Запускает неразрушающую проверку окружения, зависимостей, сети, GitHub, портов, служб, firewall и диска. |
| `10` | SNI preference records | Показывает сохраненные результаты full/mini SNI-проверки из `/etc/ddr/A-Box-sni-full.tsv` и `/etc/ddr/A-Box-sni-mini.tsv`. |

---

## Защитные процедуры обслуживания

- Перед меню `1`-`10` автоматически выполняется lightweight preflight. Он проверяет root/TTY, OS/init, CPU architecture, required commands и доступность GitHub API. Он не блокирует переустановку только из-за портов, занятых управляемыми службами A-Box.
- Меню `15` автоматически создает backup перед core upgrade без сброса параметров узла.
- Меню `15` для OTA показывает SHA256 загруженного скрипта и использует подтверждение `[Y/N]`.
- Меню `16` и `17` спрашивают, нужно ли создать backup перед удалением или сбросом окружения.
- Toolbox `7` выполняет ручной backup/restore.
- Toolbox `8` экспортирует обезличенный диагностический пакет; UUID, private keys, passwords, tokens и client links скрываются.
- Toolbox `9` запускает полный dry-run preflight report и сохраняет его в `/etc/ddr/preflight/`.
- Меню `19` при переключении SS-2022 из открытого режима обратно в whitelist очищает старые глобальные ACCEPT rules перед установкой whitelist/DROP правил.

---

## Заметки по выбору SNI

- Запускайте SNI preference на VPS, а не на локальном компьютере; для REALITY важен путь VPS -> target.
- Предпочитайте кандидаты с `tls13=1`, `san=1`, корректным ALPN и разумной ASN/topology связью с VPS.
- Не используйте raw IP как SNI.
- Apple/iCloud-подобные SNI на портах не `443` явно предупреждаются скриптом.
- Fallback SNI по умолчанию для REALITY — `www.microsoft.com`; Apple/iCloud domains не используются как встроенные значения по умолчанию.
- Сторонние toolbox scripts находятся вне контроля A-Box. A-Box показывает SHA256 загруженного файла и требует `YES-RUN-UNTRUSTED` перед выполнением.
- Hysteria 2 `up`/`down` — параметры пропускной способности и congestion control; задавайте их по реальной мощности VPS.

---

## Системные требования

| Параметр | Требование |
| :--- | :--- |
| Operating system | Debian 10+, Ubuntu 20.04+, CentOS/RHEL/Rocky/AlmaLinux 8+, Alpine Linux. |
| Init system | systemd или OpenRC. |
| CPU | amd64/x86_64, arm64/aarch64. |
| Privilege | root или sudo. |
| Network | Доступ к системным репозиториям пакетов и GitHub Releases. |

---

## FAQ

### Может ли preflight заблокировать переустановку уже развернутого stack?

Нет. Lightweight preflight не падает только из-за портов, занятых управляемыми службами A-Box; deployment все равно останавливает старые управляемые службы.

### Что входит в backup и diagnostic bundle?

Backup сохраняет конфигурацию A-Box, service files, scripts, выбранное состояние firewall/cron и metadata. Diagnostic bundle обезличивается и предназначен для issue reporting или troubleshooting.

### Как выбрать лучший SNI?

Используйте Toolbox menu `3` или `4`; предпочитайте TLS 1.3, SAN match, корректный ALPN и разумную ASN/topology связь с VPS.

---

## Обратная связь и лицензия

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- Pull requests приветствуются.
- Проект распространяется по лицензии [Apache License 2.0](LICENSE).
