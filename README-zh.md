# A-Box | Linux 网络网关一键自动化工具箱

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

A-Box 是一个独立 Bash 脚本，用于 Linux 网络网关部署与维护，集成 Xray-core、sing-box、官方 Hysteria 2、节点参数导出、系统优化、流量限制、访问控制、健康检查、备份恢复、诊断导出和本地 SNI 优选测试。

> 仅限在合法、授权、合规的环境中使用。用户自行承担误用、违规使用或错误操作带来的法律、运维和安全后果。

## 安全快速开始

推荐先下载、校验、自测，再运行：

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh
sha256sum A-Box.sh
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh
```

快速管道模式仍可使用：

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

当 GitHub raw 不可达时，可使用第三方镜像备用通道：

```bash
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

语言选择：

```bash
sudo bash A-Box.sh --lang zh
sudo bash A-Box.sh --lang en
```

只读检查：

```bash
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh --status
sudo bash A-Box.sh --help
sudo bash A-Box.sh --preflight
sudo bash A-Box.sh --dry-run
```

首次运行后可用快捷命令：

```bash
sb
```

## 核心功能

| 模块 | 说明 |
|---|---|
| 一键部署 | 安装依赖、初始化环境、部署并管理 Xray-core、sing-box 和官方 Hysteria 2。 |
| 协议栈 | VLESS-Vision-Reality、VLESS-XHTTP-Reality、Shadowsocks-2022、Hysteria 2。 |
| 默认端口 | Vision `443/TCP`、XHTTP `8443/TCP`、HY2 `443/UDP`、SS-2022 `2053/TCP+UDP`；自定义端口会校验。 |
| SNI 策略 | 默认 REALITY SNI 为 `www.microsoft.com`。Apple/iCloud 域名不会作为内置默认值。非 443 使用 Apple/iCloud 类 SNI 会警告。 |
| 内置 SNI 雷达 | 本地 full/mini 候选库；不依赖旧远程 SNI 脚本；按 HTTPS/TLS、TLS 1.3、ALPN、SAN、ASN/拓扑评分并保存记录。 |
| XHTTP 导出 | 导出 `/xhttp`、`stream-one`、HTTP/2 host、`smux: false`，兼容 Mihomo 等客户端。 |
| Hysteria 2 | 支持 ACME HTTP-01、Cloudflare DNS-01、自签证书 pin、伪装站、可选端口跳跃、Salamander 混淆。 |
| 运维 | BBR/FQ、TCP KeepAlive、Fail2Ban、logrotate、健康探针、Geo 更新、月流量限额、SS-2022 白名单、状态报告。 |
| 安全保护 | 预检查、部署替换确认、危险动作前备份、脱敏诊断、受控 OTA。 |
| 导出格式 | URI、终端二维码、Clash/Mihomo YAML、sing-box outbound 模板、v2rayN/v2rayNG JSON。 |

## 主菜单

| 编号 | 功能 | 用途 |
|---:|---|---|
| `1` | Xray VLESS-Vision-Reality | 主 TCP REALITY + Vision 路径。 |
| `2` | Xray VLESS-XHTTP-Reality | 面向兼容桌面客户端的 XHTTP over REALITY 路径。 |
| `3` | Xray Shadowsocks-2022 | TCP/UDP 中转或落地入口；建议使用白名单。 |
| `4` | 官方 Hysteria 2 | 面向移动网络或高丢包网络的 UDP/QUIC/H3 路径。 |
| `5` | Xray + 官方 HY2 全家桶 | Vision + XHTTP + HY2 + SS-2022。 |
| `6` | sing-box VLESS-Vision-Reality | 低内存 Vision 部署。 |
| `7` | sing-box Shadowsocks-2022 | 低内存 SS-2022 部署。 |
| `8` | sing-box VLESS + SS-2022 | 轻量双协议部署。 |
| `9` | sing-box Hysteria 2 | 由 sing-box 实现 HY2。 |
| `10` | sing-box 全家桶 | Vision + HY2 + SS-2022；按设计不包含 XHTTP。 |
| `11` | 综合工具箱 | Benchmark、IP 质量、SNI 优选、WARP、Swap、备份恢复、诊断、预检查、SNI 记录。 |
| `12` | VPS 一键优化 | BBR/FQ、limits、KeepAlive、Fail2Ban、健康探针。 |
| `13` | 显示全部节点参数 | 链接、二维码、YAML、JSON、outbound 模板。 |
| `14` | 使用说明 | 终端内完整说明。 |
| `15` | OTA、Geo 与核心升级 | 更新 A-Box 脚本、Xray Geo 数据或无损升级核心。 |
| `16` | 完整卸载 | 移除托管服务、配置、防火墙规则和可选 `sb` 快捷入口。 |
| `17` | 删除节点并重置环境 | 清理残留进程、规则、错误配置和服务。 |
| `18` | 月流量限制 | 基于 vnStat 的月流量阈值，达到后停止服务。 |
| `19` | SS-2022 白名单管理 | 添加/删除前置 IP/CIDR；对非白名单来源执行 DROP。切回白名单模式时会先清理旧全局 ACCEPT。 |
| `20` | 语言设置 | 切换中文/英文界面并保存到 `/etc/ddr/.lang`。 |
| `0` | 退出 | 退出菜单。 |

## 工具箱明细

| 编号 | 功能 | 说明 |
|---:|---|---|
| `1` | 系统 benchmark | 运行 `bench.sh`。 |
| `2` | IP 质量和路由测试 | 运行 Check.Place。 |
| `3` | 本地全量 SNI 优选 | 使用完整候选库，更高并发和更深验证。 |
| `4` | 小机器 SNI 优选 | 与全量使用同一候选库，但降低并发和验证深度。 |
| `5` | Cloudflare WARP 管理 | 下载第三方 WARP 管理脚本；显示 SHA256，并要求强确认。 |
| `6` | 2G Swap | 创建 `/swapfile`，降低小内存机器 OOM 风险。 |
| `7` | 备份 / 恢复 | 创建或恢复 A-Box 配置备份。 |
| `8` | 脱敏诊断包 | 导出状态、端口、版本、日志、防火墙、cron、脱敏环境文件。 |
| `9` | 完整 dry-run 预检查 | 非破坏性检查环境、依赖、网络、GitHub、端口、服务、防火墙和存储。 |
| `10` | SNI 优选记录 | 查看 `/etc/ddr/A-Box-sni-full.tsv` 和 `/etc/ddr/A-Box-sni-mini.tsv` 的保存结果。 |

## 维护保护

- 协议部署菜单 `1`-`10` 前会自动运行轻量预检查。
- 菜单 `15` 在核心升级前会自动备份，不重置节点参数。
- 菜单 `16`、`17` 在卸载或环境重置前询问是否备份。
- 工具箱 `7` 提供手动备份/恢复。
- 工具箱 `8` 导出脱敏诊断包，UUID、私钥、密码、token、客户端链接会被遮蔽。
- 工具箱 `9` 生成完整 dry-run 预检查报告并保存到 `/etc/ddr/preflight/`。
- 工具箱 `10` 查看最近保存的 full/mini SNI 优选结果。
- 第三方工具箱脚本不是 A-Box 的组成部分；运行前显示 SHA256，并要求精确输入 `YES-RUN-UNTRUSTED`，除非 `ABOX_REMOTE_SHA256_ALLOWLIST` 已包含该 hash。
- 从 `main` 分支 OTA 更新脚本时，会进行语法/指纹校验，显示 SHA256，并使用 `[Y/N]` 确认。非交互 OTA 必须使用 `ABOX_OTA_SHA256_ALLOWLIST`。
- GitHub 核心资产下载强制校验官方 release asset SHA256 digest。默认仅使用稳定 `latest` release，不使用 prerelease/alpha。

## 推荐部署

| 场景 | 推荐 |
|---|---|
| 均衡生产部署 | 菜单 `5`：Xray + 官方 HY2 全家桶。 |
| 低内存轻量部署 | 菜单 `10`：sing-box 全家桶。 |
| 主 TCP 路径 | 菜单 `1`：Xray VLESS-Vision-Reality (`443/TCP`)。 |
| 桌面高吞吐备用 | 菜单 `2`：Xray VLESS-XHTTP-Reality (`8443/TCP`)。 |
| 移动或丢包网络 | 菜单 `4`：官方 Hysteria 2 (`443/UDP`)。 |
| 中转/落地节点 | 菜单 `3`：Xray SS-2022 (`2053/TCP+UDP`) + 白名单。 |

## SNI 选择说明

- 在 VPS 上运行 SNI 优选，不要在本地电脑运行；REALITY 目标质量主要取决于 VPS 到目标站路径。
- 优先选择 `tls13=1`、`san=1`、ALPN 正常，并与 VPS ASN/国家接近的候选。
- 有正常 `200` 页面/文档/静态资源目标时，避免 API-only、限速、不稳定或响应异常目标。
- 不要把裸 IP 当作 SNI。
- 非 443 使用 Apple/iCloud 类 SNI 会被脚本明确警告。
- 默认 fallback REALITY SNI 是 `www.microsoft.com`；Apple/iCloud 域名不会作为内置默认值。
- 运行工具箱 `3` 或 `4` 后，用工具箱 `10` 查看保存结果。

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 10+、Ubuntu 20.04+、CentOS/RHEL/Rocky/AlmaLinux 8+、Alpine Linux。 |
| Init | systemd 或 OpenRC。 |
| CPU | amd64/x86_64、arm64/aarch64。 |
| 权限 | root 或 sudo。 |
| 网络 | 可访问系统软件源和 GitHub Releases。 |
| 依赖 | Bash、curl、jq、openssl、iptables、vnStat 等，缺失时自动安装。 |

## 许可证

Apache License 2.0。
