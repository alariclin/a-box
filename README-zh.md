# A-Box

Linux 网络网关一键工具箱。

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img width="804" height="867" alt="A-Box_github" src="https://github.com/user-attachments/assets/4f51a6a1-5d1b-49db-90df-98ffae63d1ca" />
</p>

A-Box 是一个独立 Bash 脚本，用于部署和维护 Linux 网络网关服务。

它支持 Xray-core、sing-box、官方 Hysteria 2、VLESS Vision REALITY、VLESS XHTTP REALITY、Shadowsocks-2022、Hysteria 2、节点导出、SNI 优选、备份恢复、防火墙处理、诊断、流量限制、健康检查和核心更新。

> 仅限在合法、授权、合规的环境中使用。用户自行承担所有法律、运维和安全后果。

## 合规与免责声明

本项目仅用于网络架构测试、网络安全研究、系统运维自动化，以及在完全授权环境中的合法隐私保护。

请勿将本项目用于非法攻击、未授权访问、规避审计、网络滥用、破坏基础设施或任何违法活动。

请仅在您拥有、管理或已获得明确授权的服务器、网络和系统中使用。

本项目按“现状”提供，不提供任何担保。下载、复制、部署或运行本项目，即表示您接受这些条款。

## 安全快速开始

推荐方式：

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh
sha256sum A-Box.sh
sudo bash A-Box.sh --self-test
sudo bash A-Box.sh
```

快速管道方式：

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

当 GitHub raw 不可达时，才使用镜像备用通道：

```bash
curl -fsSL https://ghp.ci/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh | sudo bash
```

安装后用下面命令打开菜单：

```bash
sb
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

## 主要功能

| 模块 | 作用 |
|---|---|
| 部署 | 安装依赖，部署 Xray-core、sing-box 或官方 Hysteria 2。 |
| 协议 | VLESS Vision REALITY、VLESS XHTTP REALITY、Shadowsocks-2022、Hysteria 2。 |
| 默认端口 | Vision `443/TCP`、XHTTP `8443/TCP`、HY2 `443/UDP`、SS-2022 `2053/TCP+UDP`。 |
| SNI 雷达 | 内置 4096 个候选的 SNI 测试库，用于 REALITY/XHTTP 目标优选。 |
| 导出 | URI、二维码、Clash/Mihomo YAML、sing-box outbound 模板、v2rayN/v2rayNG JSON。 |
| 防火墙安全 | 不会自动关闭 UFW 或 firewalld；会记录 A-Box 新增的防火墙规则，用于清理和回滚。 |
| 服务安全 | 避免全局 `killall`；停止托管服务前会检查 A-Box 服务归属。 |
| 恢复能力 | 备份并恢复配置、服务文件、核心二进制、Xray Geo 数据、防火墙状态、cron 块和运行元数据。 |
| 运维 | 支持预检查、诊断、流量限制、Fail2Ban、logrotate、健康探针、Geo 更新和受控 OTA。 |

## 主菜单

| 编号 | 功能 |
|---:|---|
| `1` | Xray VLESS Vision REALITY |
| `2` | Xray VLESS XHTTP REALITY |
| `3` | Xray Shadowsocks-2022 |
| `4` | 官方 Hysteria 2 |
| `5` | Xray + 官方 HY2 全家桶 |
| `6` | sing-box VLESS Vision REALITY |
| `7` | sing-box Shadowsocks-2022 |
| `8` | sing-box VLESS + Shadowsocks-2022 |
| `9` | sing-box Hysteria 2 |
| `10` | sing-box 全家桶 |
| `11` | 工具箱 |
| `12` | VPS 优化 |
| `13` | 显示节点参数 |
| `14` | 使用说明 |
| `15` | OTA、Geo 数据和核心升级 |
| `16` | 完整卸载 |
| `17` | 删除节点并重置环境 |
| `18` | 月流量限制 |
| `19` | SS-2022 白名单管理 |
| `20` | 语言设置 |
| `0` | 退出 |

## 工具箱

| 编号 | 功能 |
|---:|---|
| `1` | 系统 benchmark |
| `2` | IP 质量和路由测试 |
| `3` | 本地全量 SNI 优选 |
| `4` | 小机器本地 SNI 优选 |
| `5` | Cloudflare WARP 管理 |
| `6` | 2G Swap |
| `7` | 备份和恢复 |
| `8` | 脱敏诊断包 |
| `9` | 完整 dry-run 预检查 |
| `10` | SNI 优选记录 |

## 推荐部署

| 场景 | 推荐选项 |
|---|---|
| 均衡生产使用 | 菜单 `5`：Xray + 官方 HY2 全家桶 |
| 低内存 VPS | 菜单 `10`：sing-box 全家桶 |
| 主 TCP 路径 | 菜单 `1`：Xray VLESS Vision REALITY |
| 高吞吐 TCP 备用 | 菜单 `2`：Xray VLESS XHTTP REALITY |
| 移动或不稳定网络 | 菜单 `4`：官方 Hysteria 2 |
| 中转或落地节点 | 菜单 `3`：Xray Shadowsocks-2022 + 白名单 |

## SNI 说明

SNI 优选主要用于 Xray REALITY 和 XHTTP REALITY。

请在 VPS 上运行 SNI 测试，不要在本地电脑运行。最佳目标取决于 VPS 到目标站的网络路径。

优先选择 `tls13=1`、`san=1`、ALPN 正常、HTTP 响应正常，并且与 VPS 有合理 ASN 或拓扑关系的结果。

内置 fallback REALITY SNI 是：

```text
www.microsoft.com
```

Apple/iCloud 域名不会作为内置默认值。非 443 端口使用 Apple/iCloud 类 SNI 时，脚本会给出警告。

运行工具箱 `3` 或 `4` 后，可以用工具箱 `10` 查看保存的 SNI 记录。

## 安全设计

A-Box 面向生产稳定性设计：

- 不会自动关闭 UFW 或 firewalld。
- 原生防火墙启用时，只添加 A-Box 所需端口。
- 记录 A-Box 新增的原生防火墙规则，用于清理和回滚。
- 避免全局 `killall`。
- 停止托管服务前会检查 A-Box 服务归属。
- 危险操作前会备份重要文件。
- 可恢复配置、服务文件、核心二进制、Xray Geo 数据、防火墙状态、cron 块和运行元数据。
- 核心和 Geo 下载会校验 GitHub Release asset SHA256 digest。
- 默认使用稳定 latest release，不使用 alpha 或 prerelease 版本。
- 第三方工具脚本会显示 SHA256，并要求精确确认，除非哈希已显式加入 allowlist。
- 从 `main` OTA 需要语法/指纹校验、SHA256 显示和 `[Y/N]` 确认。非交互 OTA 需要 `ABOX_OTA_SHA256_ALLOWLIST`。

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 10+、Ubuntu 20.04+、CentOS/RHEL/Rocky/AlmaLinux 8+、Alpine Linux |
| Init | systemd 或 OpenRC |
| CPU | amd64/x86_64、arm64/aarch64 |
| 权限 | root 或 sudo |
| 网络 | 可访问系统软件源和 GitHub Releases |
| 依赖 | Bash、curl、jq、openssl、iptables、vnStat 等；缺失时自动安装 |

## 常见问题

### 脚本提示没有交互式 TTY。
请从交互式终端运行。如果管道模式失败，先下载脚本，再运行 `sudo bash A-Box.sh`。

### 部署因端口占用失败。
请手动释放端口，或选择其他端口。A-Box 部署前会检查非 A-Box 进程。

### 预检查会阻止重装已部署的 A-Box 协议栈吗？
不会。轻量预检查不会因为 A-Box 托管服务已占用端口而失败。部署时仍会先停止 A-Box 托管服务，再写入新协议栈。

### 备份包含什么？
备份包含 A-Box 配置、服务文件、脚本、核心二进制、Xray Geo 数据、原生防火墙状态、A-Box cron 块、选定防火墙状态和运行元数据。

### Hysteria 2 为什么要求填写上行和下行带宽？
Hysteria 2 使用这些值进行带宽和拥塞控制。请按照 VPS 线路容量填写。

### ACME 证书申请失败。
HTTP-01 模式下，确认 `80/TCP` 可达且未被占用。Cloudflare DNS-01 模式下，确认 API token 对目标 zone 有 DNS 编辑权限。

### 如何选择 SNI？
运行工具箱 `3` 或 `4`，再查看工具箱 `10`。优先选择 TLS 1.3、SAN 命中、ALPN 正常、HTTP 响应正常，并与 VPS ASN/拓扑关系合理的候选。

## 反馈与许可证
- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- 欢迎提交 Pull Request。
- 本项目基于 [Apache License 2.0](LICENSE) 发布。
