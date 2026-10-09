# 如何把 A-Box 做成全球最好的一键网关工具包

> 无约束愿景文档（v171）。不是路线图承诺清单，而是架构 / UX / 安全 / 运维 / 客户端生态的「理想终局」与可落地优先级。

## 1. 产品定位

A-Box 应成为：**跨发行版、可审计、可回滚、客户端互通优先** 的 Linux 网关一键工具，而不是「堆协议最多」的脚本合集。

全球最佳的衡量标准：

1. **第一次就能装对**（systemd / OpenRC，Debian/Ubuntu/RHEL 系 / Alpine，amd64/arm64）
2. **装坏能回滚**（配置、防火墙、二进制、DNS、时区、调优均有快照）
3. **客户端真正能连**（Shadowrocket / Mihomo / v2rayNG / sing-box 官方客户端互通优先于追最新上游）
4. **运维可观测**（流量截至当前、健康探针、脱敏诊断包、预检）
5. **供应链可信任**（官方 digest、灾备镜像、无静默变砖）

## 2. 架构原则

### 2.1 单脚本 + 外部数据面

- **控制面**：`install.sh` 单一入口，Bash 4.3+，无隐藏远程 `curl | bash` 依赖业务逻辑。
- **数据面**：SNI 候选库、核心灾备资产、文档分仓或 Release 托管，避免把 MB～百 MB 级资产塞进 git 历史。
- **状态面**：`/etc/ddr/` 下分文件持久化（`.env` 部署态、`.ip-pref`、`.dns-*`、`.timezone-*`、防火墙归属、流量配额），权限 600、root 属主、原子写入。

### 2.2 事务与回滚

每个破坏性变更应有：

| 变更 | 快照 | 提交 | 失败 |
|---|---|---|---|
| 部署/换核 | 配置+二进制备份 | 校验通过后切换 | `deployment_transaction_rollback` |
| 核心升级 | 旧二进制 | digest 校验 | `core_upgrade_transaction_rollback` |
| VPS 调优 | sysctl/limits | sysctl -p | `restore_vps_tune` |
| 本机 DNS | resolv + resolved drop-in | 后端重启 | `restore_dns_snapshot` |
| 时区 | localtime/timezone | timedatectl | `.tz-rollback` |
| 流量配额 | 配对状态文件 | 写配额 | 配对回滚 |

**永不半截覆盖**：下载失败保留 last-good；灾备通道也必须 SHA256。

### 2.3 监听与 IP 协议

- 显式 **IPv4-only / IPv6-only / dual**，写入 `wildcard_listen_address`、防火墙、分享链接 IP。
- 默认 dual：有全局 IPv6 且 `bindv6only=0` 时 listen `::`，否则 `0.0.0.0`。
- 仅 IPv6 在无全局地址时拒绝保存，避免部署后不可达。

### 2.4 DNS（主机侧）

分层：

1. **明文 nameserver**（万能，Alpine / 无 resolved）
2. **DoT**（systemd-resolved `DNSOverTLS=yes`）
3. 可选未来：DoH stub（`cloudflared` / `https-dns-proxy`）— 需额外守护进程，默认不装。

原则：**改 DNS 必确认；chattr +i 必二次确认；永远可回滚**。

## 3. UX 原则

1. **菜单深度 ≤ 2**：主菜单 → 子菜单 → 动作；避免 5 层向导。
2. **危险动作二次确认** + 中英双语提示。
3. **打开即有信息**：流量菜单每次展示「截至当前」月累计，而不是空白配额表。
4. **语言包完整**：zh / en / ru / fa 同步菜单文案；新功能不得只写中文。
5. **无 TTY 可脚本化**：`--self-test` / `--preflight` / `--status` / 环境变量覆盖 pins。
6. **失败可读**：die 信息说明「发生了什么 / 是否已回滚 / 下一步」。

## 4. 安全模型

1. **最小权限运行用户**（`abox-xray` 等），能力边界清晰。
2. **防火墙规则归属记账**（UFW / firewalld / nft / iptables），卸载只删自己的规则。
3. **GitHub Release digest 为信任根**；第三方加速镜像仅作传输，digest 失败即拒绝。
4. **SNI 候选不是信任根**：本地探测 + ASN/CDN 惩罚 + 颜色分层；黑名单排除消费巨头与制裁敏感域名。
5. **备份 HMAC**、原子写、禁止不安全 `.env` 权限。
6. **Fail2Ban / logrotate** 可选加固，默认安全基线不依赖它们。

## 5. 运维与可观测

- **流量**：vnStat 月周期「截至当前」+ 配额事务；不做秒级刷新 UI（SSH 菜单不适合）。
- **健康**：socket 探针、服务状态、desired state。
- **诊断包**：脱敏导出（去 UUID/密钥），方便远端协助。
- **预检**：无 PID1 / 无权限时明确 SKIP/FAIL，而不是假成功。
- **矩阵**：CI + 特权 Docker systemd/OpenRC 安装矩阵持续覆盖主流发行版。

## 6. 客户端生态

优先级（由高到低）：

1. **iOS Shadowrocket** VLESS REALITY / SS2022 / HY2
2. **Mihomo / Clash Verge**（loopback DNS、分享 YAML）
3. **v2rayNG / v2rayN**（含 XHTTP JSON）
4. **官方 sing-box 客户端**
5. **Hysteria 官方客户端**

策略：**钉住经实测互通的核心版本**（当前 Xray `v26.7.28` 避开 ML-KEM 门槛），用环境变量允许专家升级，而不是默认追 `latest`。

导出应一键给出：URI、Clash、sing-box JSON、二维码（可选）、分享 IP 随 IP 偏好。

## 7. SNI / REALITY 质量

理想雷达：

1. Stage1：延迟 / HTTP 码 / IP
2. Stage2：TLS1.3 + ALPN + SAN 匹配
3. 评分：同国 ASN 加分、CDN/巨头惩罚、颜色分层 A/R/B/C/D
4. 候选库：教育 / 标准组织 / 企业门户 / 发行版基础设施，**< 12000 行**，CI 正则清洗
5. 永不自动把「探测第一名」静默写入生产 SNI——必须人工确认

## 8. 核心灾备

- Release `core-mirrors-vNNN` 托管 pin 版本多架构资产 + `SHA256SUMS`
- 脚本路径：上游 →（可选加速）→ 同仓灾备 → **保留 last-good**
- 文档写明体积，禁止把大二进制提交进 git 树

## 9. 路线图（无承诺排序）

### P0（已在 v171 落地或应立即保持）

- IP 偏好 / 本机 DNS / 时区 / 流量截至当前 / 核心灾备 / SNI 扩容

### P1（下一里程碑）

- Web 只读状态页（本机 loopback + token）
- 多节点「配置商店」导出（同一服务器多 profile）
- DoH 可选组件（独立 unit，可卸载）
- 客户端二维码与短链（自建，不经第三方）

### P2

- 声明式配置（YAML）与菜单双向同步
- remote syslog / OpenTelemetry 可选导出
- ARM 单板（树莓派等）专项预检与功耗提示

### P3（研究）

- 无 root 用户命名空间试验（多数 VPS 不适用）
- 自动 Canary：部署后对公共探测点做合成监控

## 10. 反模式（明确不做）

1. `curl | bash` 拉第三方「一键」嵌套脚本作为默认路径（WARP 等必须显式确认）
2. 默认开启全局流量劫持 / 透明代理（易毁机）
3. 静默 `chattr +i` / 静默改 DNS
4. 为追星新协议牺牲主流客户端
5. 把 Apple/Google/Netflix/Facebook 等消费巨头当默认 REALITY 目标
6. 在 CI 绿了就宣称「全球可用」——必须以目标网络实测为准

## 11. 成功指标

| 指标 | 目标 |
|---|---|
| 主流发行版 `--self-test` | 100% PASS |
| 特权矩阵端到端安装 | ≥ 12 OS PASS |
| 新功能回滚覆盖率 | 破坏性变更 100% 有快照 |
| Shadowrocket REALITY 互通 | pin 版本下默认可用 |
| 冷启动到可分享链接 | 熟练用户 < 5 分钟 |
| 上游 GitHub 宕机 | 灾备 Release 仍可装核 |

## 12. 结语

「全球最好」不是功能最长，而是：**在最差网络与最杂发行版上，依然可预期、可回滚、可互通**。  
v171 把系统层（IP/DNS/时区）、观测层（流量截至当前）、供应链（灾备镜像）和候选质量（SNI）补齐了一大块；后续应继续围绕 **事务性、客户端真实互通、可审计** 三条主轴迭代。
