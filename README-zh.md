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

### 全球网络

```bash
curl -fsSL https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

### 中国大陆镜像

```bash
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/alariclin/a-box/main/install.sh -o A-Box.sh && sudo bash A-Box.sh
```

镜像为第三方加速服务；镜像不可用时请使用全球网络命令。安装完成后输入 `sb` 打开菜单。

## 主要功能

| 模块 | 功能 |
|---|---|
| 核心部署 | Xray-core、sing-box、官方 Hysteria 2 |
| 协议 | VLESS Vision REALITY、VLESS XHTTP REALITY、Shadowsocks-2022、Hysteria 2 |
| 节点导出 | URI、二维码、Clash/Mihomo YAML、sing-box outbound、v2rayN/v2rayNG JSON |
| 网络工具 | SNI 测试、IP 质量、路由测试、WARP、VPS 优化 |
| 运维 | 健康检查、流量限制、Fail2Ban、logrotate、Geo 更新、核心升级 |
| 安全 | 托管服务归属检查、防火墙回滚、部署事务、受控 OTA |
| 恢复 | 备份恢复、旧备份转换、脱敏诊断包 |

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

### 工具箱

| 编号 | 功能 |
|---:|---|
| `1` | 系统性能测试 |
| `2` | IP 质量和路由测试 |
| `3` | 本地全量 SNI 测试 |
| `4` | 低配置服务器 SNI 测试 |
| `5` | Cloudflare WARP 管理 |
| `6` | 创建 2 GB Swap |
| `7` | 备份和恢复 |
| `8` | 脱敏诊断包 |
| `9` | 完整 dry-run 预检查 |
| `10` | 已保存的 SNI 结果 |

## 使用说明

| 命令 | 功能 |
|---|---|
| `sb` | 安装后打开主菜单 |
| `sudo bash A-Box.sh --self-test` | 运行内置检查 |
| `sudo bash A-Box.sh --preflight` | 部署前检查服务器环境 |
| `sudo bash A-Box.sh --status` | 查看配置和服务状态 |
| `sudo bash A-Box.sh --start` | 启动托管服务 |
| `sudo bash A-Box.sh --stop` | 停止托管服务 |
| `sudo bash A-Box.sh --version` | 查看构建版本 |

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | Debian 10+、Ubuntu 20.04+、CentOS/RHEL/Rocky/AlmaLinux 8+、Alpine Linux |
| 初始化系统 | systemd 或 OpenRC |
| 架构 | amd64/x86_64、arm64/aarch64 |
| 权限 | root 或 sudo |
| 网络 | 可访问系统软件源和 GitHub Releases |
| 依赖 | 缺少的必要软件包会自动安装 |

## 最佳使用方式

| 场景 | 推荐选项 |
|---|---|
| 均衡部署 | 菜单 `5`：Xray + 官方 HY2 全家桶 |
| 低内存 VPS | 菜单 `10`：sing-box 全家桶 |
| 主 TCP 连接 | 菜单 `1`：Xray VLESS Vision REALITY |
| 高吞吐 TCP 备用 | 菜单 `2`：Xray VLESS XHTTP REALITY |
| 移动或不稳定网络 | 菜单 `4`：官方 Hysteria 2 |
| 中转或落地节点 | 菜单 `3`：Xray Shadowsocks-2022 + 白名单 |

生产环境建议先运行 `--self-test` 和 `--preflight`，将备份恢复密钥独立保存，并优先使用带版本标签的 GitHub Release。

## 反馈与许可证

- [GitHub Issues](https://github.com/alariclin/a-box/issues)
- 欢迎提交 Pull Request。
- 本项目使用 [Apache License 2.0](LICENSE)。
