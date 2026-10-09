# A-Box

Linux 网络网关一键工具箱。

[English](README.md) | [简体中文](README-zh.md) | [Русский](README-ru.md) | [فارسی](README-fa.md)

<p align="center">
  <img width="804" height="867" alt="A-Box_github" src="https://github.com/user-attachments/assets/4f51a6a1-5d1b-49db-90df-98ffae63d1ca" />
</p>

A-Box 是一个独立 Bash 脚本，用于部署和维护 Linux 网络网关服务。本文档对应的脚本构建版本为 `2026-10-10-release-candidate-v171`，当前脚本配置的默认核心版本为 Xray `v26.7.28`、sing-box `v1.14.2`。

支持 Xray-core、sing-box、官方 Hysteria 2 服务端、VLESS Vision REALITY、VLESS XHTTP REALITY、Shadowsocks-2022、客户端配置导出、本地 SNI 候选测试、备份恢复、防火墙管理、诊断、流量限制、健康检查和核心软件升级；上游失败时回退到仓库 Release `core-mirrors-v171` 灾备资产。

> 仅限在合法、授权、合规的环境中使用。用户自行承担所有法律、运维和安全后果。

## 合规与免责声明

本项目用于网络架构测试、网络安全研究、系统运维自动化，以及在完全授权环境中的合法隐私保护。请勿将本项目用于非法攻击、未授权访问、规避审计、网络滥用、破坏基础设施或任何违法活动。请仅在您拥有、管理或已获得明确授权的服务器、网络和系统中使用。

本项目按“现状”提供，不提供任何担保。执行前请审阅脚本及其可能造成的系统变更；维护或升级前应保留可恢复的备份。

## 安全快速开始

### GitHub 官方源

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

### 第三方备用镜像

```bash
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

默认优先使用 GitHub 官方源。备用镜像属于第三方服务，并非 A-Box 官方端点。`main` 分支内容可能变化；生产环境应优先选择经过审阅、固定版本标签的发布版本，并在执行前验证完整性。安装后输入 `sb` 打开菜单。

## 主要功能

- **协议部署：** Xray VLESS Vision REALITY、Xray VLESS XHTTP REALITY、Xray Shadowsocks-2022、官方 Hysteria 2，以及对应的 sing-box Vision、Shadowsocks-2022 和 Hysteria 2 选项。
- **组合部署：** Xray + Hysteria 2 组合；sing-box Vision + Hysteria 2 + Shadowsocks-2022 组合。sing-box 组合按设计不包含 XHTTP。
- **客户端配置导出：** 分享链接/URI、二维码、Clash/Mihomo YAML、sing-box 出站模板、v2rayN/v2rayNG XHTTP JSON。
- **运维和诊断：** 健康检查、系统/下载测速、IP 质量和路由测试、VPS 系统工具（调优 / IP 偏好 / 本机 DNS / 时区）、Fail2Ban/logrotate、流量限制（含截至当前用量）、备份恢复、脱敏诊断包和预检查。
- **核心灾备镜像：** 固定版本 Xray / sing-box / Hysteria 资产发布于 Release [`core-mirrors-v171`](https://github.com/alariclin/a-box/releases/tag/core-mirrors-v171)；上游失败时脚本自动回退（见 [`mirrors/README.md`](mirrors/README.md)）。
- **SNI 候选工作流：** 本地完整和微型主机候选测试、已保存结果查看器、输入校验、文件大小/行数上限、重复项清理，以及可用时回退到有效本地缓存或同目录数据文件。
- **维护：** 显示 SHA-256 并要求明确确认的脚本 OTA、Xray Geo 数据更新，以及不重置节点参数的核心程序单独升级。
- **安全控制：** 部署前检查、受控服务归属/状态变更、防火墙处理，以及受支持操作的回滚路径。

仓库内置候选种子文件见 [`data/sni-candidates.txt`](data/sni-candidates.txt)。SNI 列表仅是候选项。域名出现在列表中，**不代表它从特定 VPS 当前可用，也不保证符合目标 REALITY 部署所需的 TLS/ALPN/SAN 条件**。使用前必须在目标网络实际验证。无法取得有效列表或有效备用副本时，SNI 工作流会拒绝继续，而不是使用未经验证的数据。

## 主菜单

| 编号 | 功能 |
|---:|---|
| `1` | Xray VLESS Vision REALITY |
| `2` | Xray VLESS XHTTP REALITY |
| `3` | Xray Shadowsocks-2022 |
| `4` | 官方 Hysteria 2 服务端 |
| `5` | Xray + 官方 Hysteria 2 组合：Vision TCP 443、XHTTP TCP 8443、Hysteria 2 UDP 443、SS-2022 TCP/UDP 2053 |
| `6` | sing-box VLESS Vision REALITY |
| `7` | sing-box Shadowsocks-2022 |
| `8` | sing-box VLESS + Shadowsocks-2022 |
| `9` | sing-box Hysteria 2 |
| `10` | sing-box Vision + Hysteria 2 + Shadowsocks-2022（不含 XHTTP） |
| `11` | 综合工具箱 |
| `12` | VPS 系统工具：BBR/FQ 调优（可回滚）、**IP 协议偏好**（仅 IPv4 / 仅 IPv6 / 双栈）、**本机 DNS**（明文 / DoT，可回滚）、**时区**（启发式 + 自定义，可回滚） |
| `13` | 显示节点参数和客户端配置 |
| `14` | 脚本说明书 |
| `15` | 脚本 OTA、Xray Geo 数据和核心单独升级 |
| `16` | 全部/部分卸载 |
| `17` | 删除节点并重置环境 |
| `18` | 每月流量限制（基于 vnStat）。打开菜单先展示**截至当前**本月累计用量，再进入配额管理 |
| `19` | SS-2022 IP/CIDR 白名单管理 |
| `20` | 切换脚本界面的中文/English |
| `0` | 退出 |

### 工具箱

工具箱包含系统性能/下载测速、IP 质量/流媒体可用性/路由测试、完整与微型主机本地 SNI 候选测试、已保存 SNI 结果、Cloudflare WARP 管理器（确认后会调用第三方脚本）、2 GB Swap 创建、备份恢复、脱敏诊断包导出，以及完整的只读 dry-run 预检查。

## 命令行用法

仓库中的脚本文件名为 `install.sh`。下方 curl 示例会保存为 `A-Box.sh`；只要内容是本脚本，两种文件名均可。

在脚本所在目录执行：

| 命令 | 作用 |
|---|---|
| `sudo bash install.sh --help` | 显示命令行帮助 |
| `sudo bash install.sh --lang zh` / `--lang en` | 设置界面语言并启动菜单 |
| `sudo bash install.sh --self-test` | 运行内置回归/自测 |
| `sudo bash install.sh --preflight` 或 `--dry-run` | 运行预检查，不部署新节点 |
| `sudo bash install.sh --status` | 查看托管配置和服务状态 |
| `sudo bash install.sh --start` / `--stop` | 启动/停止托管服务 |
| `sudo bash install.sh --version` | 显示脚本构建元数据 |
| `sudo bash install.sh --export-backup-key /secure/path/A-Box-recovery.key` | 将恢复密钥导出到受保护路径 |
| `sudo bash install.sh --convert-legacy-backup OLD.tar.gz [OUTPUT_DIR]` | 将旧版备份转换为 manifest v3 格式 |

请妥善保护导出的恢复密钥和备份。`--self-test` 通过不能替代目标主机预检查、真实安装或客户端互通测试。

## 系统要求

脚本包含对下列环境的兼容处理；实际兼容性还取决于系统版本、初始化系统、CPU 架构、依赖、服务商网络环境和上游下载可用性。

| 项目 | 要求 |
|---|---|
| 系统系列 | Debian 10+、Ubuntu 20.04+、CentOS/RHEL/Rocky/AlmaLinux 8+ 或 Alpine Linux |
| 初始化系统 | systemd 或 OpenRC |
| CPU 架构 | amd64/x86_64 或 arm64/aarch64 |
| 权限 | root 或 sudo |
| 网络 | 可访问系统软件源和所需上游/GitHub 发布端点 |
| 脚本界面 | English 或简体中文 |

四种语言的 README 不代表脚本交互界面也支持四种语言；脚本界面目前支持 English 和简体中文。

## 生产环境检查清单

1. 审阅脚本并选择可信、固定版本的来源；不要盲目信任第三方镜像。
2. 在目标 VPS 上先运行 `--self-test` 和 `--preflight`。
3. 确认云服务商防火墙/安全组规则，以及所选协议、端口和客户端的兼容性。
4. 将恢复密钥独立保存；执行破坏性维护前保留并验证备份。
5. 从实际使用节点的网络验证 DNS、TLS、ALPN、SNI、连通性和客户端行为。CI 通过本身不能证明所有 VPS 服务商、操作系统和客户端都可正常使用。

## 反馈与许可证

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- 欢迎提交 Pull Request。
- 本项目使用 [Apache License 2.0](LICENSE)。
