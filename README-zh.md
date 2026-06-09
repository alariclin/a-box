# A-Box | 一键部署 Linux 网络网关工具箱

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<img width="1254" height="1254" alt="A-Box_github" src="https://github.com/user-attachments/assets/6c436ad1-43cd-4f59-992d-8e2f1e22bce4" />



**A-Box** 是一款面向 Linux 服务器的一体化网络网关自动化工具箱。它把代理服务部署、系统调优、流量管理、访问控制、服务健康检查、客户端配置导出、网络质量测试、运维保护和中英文交互式终端界面集中到一个独立 Bash 脚本中。

**致谢：** 感谢 Xray-core、sing-box、Hysteria 及相关开源项目提供的技术启发与生态支持。A-Box 是独立的自动化编排工具箱。

[![Version](https://img.shields.io/badge/Version-2026.05.07-success.svg?style=flat-square)](https://github.com/alariclin/a-box/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/alariclin/a-box?style=flat-square&color=yellow)](https://github.com/alariclin/a-box/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alariclin/a-box?style=flat-square&color=orange)](https://github.com/alariclin/a-box/network/members)

---

## 合规与免责声明

本项目用于**授权环境下的网络架构测试、网络安全研究与合规隐私保护**。

1. **法律合规性：** 严禁利用本项目从事任何违反所在国家或地区法律法规的活动。
2. **责任界定：** 因用户违反法律法规、不当操作或滥用工具产生的法律、运维和安全风险，由使用者自行承担。
3. **技术属性：** 本项目涉及的路由与加密技术用于提升数据传输安全性与私密性。严禁用于非法攻击、未授权访问或危害网络基础设施安全。
4. **条款接受：** 下载、复制或运行本脚本即视为已阅读、理解并接受本声明。

---

## 快速开始

### 一键运行：全球通道

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

### 一键运行：镜像通道

```bash
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

### 指定界面语言

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh > A-Box.sh
sudo bash A-Box.sh --lang zh
sudo bash A-Box.sh --lang en
```

### 自测、状态、帮助与预检查

```bash
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh --status
sudo bash A-Box.sh --help
sudo bash A-Box.sh --preflight
sudo bash A-Box.sh --dry-run
```

### 安装后快捷入口

首次运行后，可随时用以下命令打开菜单：

```bash
sb
```

---

## 核心能力

| 模块 | 说明 |
| :--- | :--- |
| 一键部署 | 自动安装依赖、初始化环境、部署服务，并管理 Xray-core、sing-box 与官方 Hysteria 2。 |
| 协议栈 | VLESS-Vision-Reality、VLESS-XHTTP-Reality、Shadowsocks-2022、Hysteria 2。 |
| 标准端口 | Vision `443/TCP`，XHTTP `8443/TCP`，HY2 `443/UDP`，SS-2022 `2053/TCP+UDP`；自定义端口会在部署前校验。 |
| SNI 策略 | REALITY 默认 SNI 为 `www.microsoft.com`。非 443 端口使用 Apple/iCloud 类 SNI 会触发风险提示和二次确认。生产环境建议使用内置 SNI 优选结果。 |
| 内置 SNI 雷达 | 本地候选库，包含全量模式和微型主机模式；不依赖旧版远程 SNI 脚本。按 HTTPS/TLS 指标、TLS 1.3、ALPN、SAN、ASN/拓扑评分并显示进度。 |
| XHTTP 导出 | 导出 `/xhttp`、`stream-one`、HTTP/2 host、`smux: false` 等适配 Mihomo 等客户端的 XHTTP 参数。 |
| Hysteria 2 模式 | 支持 ACME HTTP-01、Cloudflare DNS-01 证书流程，自签证书指纹锁定，可选 masquerade、端口跳跃、Salamander 混淆。 |
| 工具箱 | 基准测试、IP 质量/流媒体/路由测试、全量 SNI 优选、微型主机 SNI 优选、Cloudflare WARP 管理、2G Swap、备份/恢复、诊断包、Dry-run 预检查。 |
| 运维能力 | BBR/FQ 调优、TCP KeepAlive、Fail2Ban、logrotate、健康探针、定时 Geo 更新、月流量超额停止、SS-2022 白名单、`--status`。 |
| 运维保护 | 协议部署前自动轻量预检查；核心升级前自动备份；卸载或环境初始化前提示备份；手动备份/恢复；脱敏诊断。 |
| 导出格式 | URI、终端二维码、Clash/Mihomo YAML、sing-box 出站模板、v2rayN/v2rayNG JSON。 |
| 安全部署 | 新部署会停止托管服务、清理 A-Box 防火墙规则、检测端口冲突，并提供完整卸载和环境重置。 |

---

## 完整菜单

| 菜单 | 功能 | 用途 |
| :--- | :--- | :--- |
| `1` | Xray VLESS-Vision-Reality | 主力 TCP REALITY + Vision 通道。 |
| `2` | Xray VLESS-XHTTP-Reality | 面向兼容桌面客户端的高吞吐 XHTTP over REALITY 通道。 |
| `3` | Xray Shadowsocks-2022 | TCP/UDP 回程或落地入站；建议配合白名单。 |
| `4` | 官方 Hysteria 2 (Apernet) | UDP/QUIC/H3 通道，适合移动或丢包链路。 |
| `5` | Xray + 官方 HY2 四合一 | Vision + XHTTP + HY2 + SS-2022。 |
| `6` | sing-box VLESS-Vision-Reality | 低内存 Vision 部署。 |
| `7` | sing-box Shadowsocks-2022 | 低内存 SS-2022 部署。 |
| `8` | sing-box VLESS + SS-2022 | 轻量双协议部署。 |
| `9` | sing-box Hysteria 2 | sing-box 承载 HY2。 |
| `10` | sing-box 三合一 | Vision + HY2 + SS-2022；按设计不含 XHTTP。 |
| `11` | 综合工具箱 | 测速、IP 检测、SNI 优选、WARP、Swap、备份/恢复、诊断包、Dry-run 预检查。 |
| `12` | VPS 一键优化 | BBR/FQ、文件句柄、KeepAlive、Fail2Ban、健康探针。 |
| `13` | 全部节点参数显示 | 查看链接、二维码、YAML、JSON、出站模板。 |
| `14` | 脚本说明书 | 终端完整说明。 |
| `15` | OTA、Geo 与核心升级 | 更新脚本、Xray Geo 数据，或无损升级已安装核心。 |
| `16` | 一键全部清空卸载 | 删除托管服务、配置、防火墙规则和可选 `sb` 快捷入口。 |
| `17` | 删除节点与环境初始化 | 杀残留进程、清理陈旧规则、删除破损配置和服务。 |
| `18` | 每月流量管控限制 | 基于 vnStat 的月流量阈值，达到后停止服务。 |
| `19` | SS-2022 白名单管理 | 添加/删除前置 IP/CIDR，对非白名单来源执行 DROP。 |
| `20` | 语言设置 | 中英文界面切换并保存到 `/etc/ddr/.lang`。 |
| `0` | 退出 | 退出交互菜单。 |

---

## 工具箱子菜单

| 子菜单 | 功能 | 说明 |
| :--- | :--- | :--- |
| `1` | 系统基准测试 | 运行 `bench.sh` 检测硬件和下载速度。 |
| `2` | IP 质量与路由测试 | 运行 Check.Place 检查 IP 质量、流媒体解锁与线路路由。 |
| `3` | 本地 SNI 优选 | 运行内置全量 SNI 候选库，使用更高并发和更深验证。 |
| `4` | 微型主机本地 SNI 优选 | 与全量模式使用同一候选库，但降低并发和验证深度，适合低配主机。 |
| `5` | Cloudflare WARP 管理 | 下载并运行第三方 WARP 管理器，用于出站 IP 伪装和流媒体解锁场景。A-Box 会显示 SHA256，并在执行前要求强确认。 |
| `6` | 2G Swap 划拨 | 创建 `/swapfile`，降低小内存主机 OOM 风险。 |
| `7` | 配置备份 / 恢复 | 创建或恢复 A-Box 配置备份；备份会排除 backups、diagnostics、preflight 目录，避免递归备份膨胀。 |
| `8` | 脱敏诊断包导出 | 导出服务状态、端口、版本、日志、防火墙片段、cron 条目和脱敏环境文件，用于排障。密钥和链接会被遮蔽。 |
| `9` | 完整 Dry-run 预检查 | 执行非破坏性环境、依赖、网络、GitHub、端口、服务、防火墙和磁盘检查。 |

---

## 运维保护说明

- 菜单 `1`-`10` 安装协议前会自动执行轻量 preflight，检查 root/TTY、系统与 init、CPU 架构、关键命令和 GitHub API 可达性。它不会因为旧 A-Box 托管服务占用端口而误阻断重装。
- 菜单 `15` 在核心升级前自动创建一次备份，且不重置节点参数。
- 菜单 `16` 和 `17` 在卸载或环境初始化前会询问是否创建备份。
- 工具箱子菜单 `7` 提供手动配置备份与恢复。
- 工具箱子菜单 `8` 导出脱敏诊断包，UUID、私钥、密码、Token 和客户端链接会被遮蔽。
- 工具箱子菜单 `9` 运行完整 Dry-run 预检查，并把报告保存到 `/etc/ddr/preflight/`。
- 第三方工具箱脚本不属于 A-Box 代码库。执行前，A-Box 会显示下载脚本的 SHA256，并要求输入精确确认短语 `YES-RUN-UNTRUSTED`；也可用 `ABOX_REMOTE_SHA256_ALLOWLIST` 指定允许的哈希。
- OTA 从 `main` 分支下载脚本，除语法/指纹校验外，还会显示 SHA256 并要求输入 `YES-UPDATE-MAIN`；可用 `ABOX_OTA_SHA256_ALLOWLIST` 强制只接受已知哈希。

---

## 推荐部署方案

| 场景 | 推荐 |
| :--- | :--- |
| 均衡生产部署 | 菜单 `5`：Xray + 官方 HY2 四合一。 |
| 低内存轻量部署 | 菜单 `10`：sing-box 三合一。 |
| 主力 TCP 通道 | 菜单 `1`：Xray VLESS-Vision-Reality (`443/TCP`)。 |
| 桌面高吞吐备用 | 菜单 `2`：Xray VLESS-XHTTP-Reality (`8443/TCP`)。 |
| 移动或丢包网络 | 菜单 `4`：官方 Hysteria 2 (`443/UDP`)。 |
| 回程/落地节点 | 菜单 `3`：Xray SS-2022 (`2053/TCP+UDP`) + 白名单。 |

---

## SNI 选择说明

- SNI 优选应在 VPS 上运行，不应以本地电脑延迟作为最终排序依据，因为 REALITY 目标质量主要取决于 VPS 到目标站的链路。
- 优先选择 `tls13=1`、`san=1`、ALPN 有效、ASN 或国家/地区关系合理的候选。
- 有正常 `200` 页面/文档/静态资源候选时，避免优先选择纯 API、限流、异常跳转或不稳定目标。
- 不要使用裸 IP 作为 SNI。
- 非 443 端口使用 Apple/iCloud 类 SNI 会被脚本明确警告。
- REALITY SNI fallback 为 `www.microsoft.com`；Apple/iCloud 域名不会作为内置默认值。

---

## 系统要求

| 项目 | 要求 |
| :--- | :--- |
| 操作系统 | Debian 10+、Ubuntu 20.04+、CentOS/RHEL/Rocky/AlmaLinux 8+、Alpine Linux。 |
| 初始化系统 | systemd 或 OpenRC。 |
| CPU | amd64/x86_64、arm64/aarch64。 |
| 权限 | root 或 sudo。 |
| 网络 | 可访问系统软件源和 GitHub Releases。 |
| 依赖 | Bash、curl、jq、openssl、iptables、vnStat 等，缺失时脚本会自动安装。 |

---

## FAQ

### 脚本提示没有交互式 TTY。
请在可交互终端中运行。如果管道方式失败，先下载脚本再运行 `sudo bash A-Box.sh`。

### 部署失败并提示端口被占用。
脚本会检测非 A-Box 进程占用的新端口。请手动释放端口，或在参数向导中选择其他端口。

### preflight 会不会阻止已安装协议后的重新安装？
不会。安装协议前的轻量 preflight 不会因为 A-Box 自己托管的服务占用端口而失败；真正部署前仍会停止旧的托管服务。

### 备份和诊断包包含什么？
备份保存 A-Box 配置、服务文件、脚本、相关防火墙/cron 状态和运行元数据。诊断包会脱敏，适合提交 issue 或排障。

### Hysteria 2 的 up/down 带宽参数是什么？
Hysteria 2 会把 `up` 和 `down` 作为带宽控制与拥塞控制参数。请按 VPS 真实线路能力设置；过低会限制实际吞吐。

### ACME 证书申请失败。
HTTP-01 需要确认 `80/TCP` 可公网访问且未被占用。Cloudflare DNS-01 需要确认 API Token 有对应域名区域的 DNS 编辑权限。

### 如何选择最佳 SNI？
使用工具箱菜单 `3` 或 `4`。优先选择 TLS 1.3、SAN 匹配、ALPN 有效且与 VPS ASN/拓扑关系合理的结果。

### 达到月流量限制后服务为什么停止？
菜单 `18` 可设置 vnStat 月流量阈值，达到后会停止托管服务。可在该菜单调整或解除限制后重启服务。

---

## 反馈与贡献

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- 欢迎提交 Pull Request。

---

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源许可证。
