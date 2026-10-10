#!/usr/bin/env bash
# ==============================A-Box===============================
# SNI profile: built-in deduplicated maximum REALITY target candidate library; no legacy remote SNI script dependency.
# Hardened build: stricter GitHub digest trust, guarded shortcut persistence, Fail2Ban validation, and Sing-box HY2 ACME semantics.
set -o pipefail
set -u
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    printf 'A-Box requires Bash 4.3 or newer. Current: %s\n' "$BASH_VERSION" >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export LANG=${LANG:-en_US.UTF-8}

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'
BOLD=$'\033[1m'

DEPS_MARKER='/etc/ddr/.deps.v20260725'
SCRIPT_URL='https://raw.githubusercontent.com/alariclin/a-box/main/install.sh'
ABOX_DIR='/etc/ddr'
ABOX_ENV='/etc/ddr/.env'
ABOX_FW_STATE='/etc/ddr/.firewall-native.rules'
ABOX_BACKUP_KEY='/etc/ddr/.backup-hmac.key'
ABOX_CORE_OWNERSHIP='/etc/ddr/.managed-core-files.tsv'
LOCK_FILE='/run/A-Box.lock'
LANG_FILE='/etc/ddr/.lang'
IP_PREF_FILE='/etc/ddr/.ip-pref'
DNS_STATE_FILE='/etc/ddr/.dns-state'
DNS_BACKUP_DIR='/etc/ddr/.dns-backup'
TZ_STATE_FILE='/etc/ddr/.timezone-state'
ABOX_CORE_MIRROR_RELEASE='core-mirrors-v171'
ABOX_CORE_MIRROR_BASE_DEFAULT='https://github.com/alariclin/a-box/releases/download/core-mirrors-v171'
FAST_MODE_FILE='/etc/ddr/.fast-mode'
MIRROR_PREFER_FILE='/etc/ddr/.mirror-prefer'
EXTRA_UUID_FILE='/etc/ddr/.extra-uuids'
SUBSCRIBE_DIR='/etc/ddr/subscribe'
PUBLIC_IP_CACHE='/etc/ddr/.public_ip.cache'
PUBLIC_IP_CACHE_TTL=600
BACKUP_RETENTION_COUNT=${BACKUP_RETENTION_COUNT:-10}
LOCK_FALLBACK_DIR='/run/A-Box.lock.d'
ABOX_LANG='zh'
ABOX_BUILD='2026-10-10-v173-upgrade-candidate'
ABOX_BUILD_EPOCH=20261010173
WALLOS_DEFAULT_VERSION='5.8.3'
WALLOS_DIR='/opt/wallos'
ABOX_TEST_MIRROR_RELEASE='test-tools-mirror-v173'
# Cross-client compatibility pin for Shadowrocket + Mihomo/Clash Verge + sing-box
# with VLESS/REALITY and XHTTP as of 2026-10-08.
# Xray 26.9.8/26.9.9 introduces the newer REALITY ML-KEM ClientHello gate;
# public interoperability reports show breakage with common non-PQ clients.
# Keep 26.7.28 as the compatibility baseline; explicit ABOX_XRAY_VERSION overrides
# remain available for operators who intentionally test a newer build.
ABOX_XRAY_DEFAULT_VERSION='v26.7.28'
# Current sing-box stable release. XHTTP is intentionally Xray-only in A-Box because
# the official sing-box V2Ray transport list does not expose an XHTTP transport.
ABOX_SINGBOX_DEFAULT_VERSION='v1.14.2'
# Candidate library sizing. 0 uses the hard ceiling instead of the historical
# 4096 seed-only boundary; default 8192 keeps generated variants reachable.
ABOX_SNI_DEFAULT_MAX=8192
ABOX_SNI_HARD_MAX=16384
ABOX_SNI_CANDIDATE_URL_DEFAULT='https://raw.githubusercontent.com/alariclin/a-box/main/data/sni-candidates.txt'
ABOX_SNI_CANDIDATE_MAX_BYTES=1048576
ABOX_SNI_CANDIDATE_MAX_ROWS=12000
ABOX_SNI_CANDIDATE_MIN_ROWS=100
ABOX_XRAY_REALITY_MLKEM_MIN_VERSION='v26.9.8'
ABOX_RUNTIME_XRAY_USER='abox-xray'
ABOX_RUNTIME_XRAY_GROUP='abox-xray'
ABOX_RUNTIME_SINGBOX_USER='abox-singbox'
ABOX_RUNTIME_SINGBOX_GROUP='abox-singbox'
ABOX_RUNTIME_HYSTERIA_USER='abox-hysteria'
ABOX_RUNTIME_HYSTERIA_GROUP='abox-hysteria'
ABOX_DESIRED_STATE='/etc/ddr/.desired_state'
ABOX_TRAFFIC_BLOCK_STATE='/etc/ddr/.traffic-block-state'
ABOX_TRAFFIC_PAIR_STATE='/etc/ddr/.traffic-pair-state'
HY2_ACME_OWNER_MARKER='/etc/hysteria/acme/.A-Box-managed'
PUBLIC_IP_CONNECT_TIMEOUT=${PUBLIC_IP_CONNECT_TIMEOUT:-3}
PUBLIC_IP_MAX_TIME=${PUBLIC_IP_MAX_TIME:-6}
ABOX_DEPLOY_TX_ACTIVE=0
ABOX_DEPLOY_TX_TARGETS=''
ABOX_DEPLOY_TX_REASON=''
ABOX_DEPLOY_TX_BACKUP=''
ABOX_DEPLOY_TX_TMP=''
ABOX_DEPLOY_TX_BACKUP_DIR=''
ABOX_DEPLOY_TX_KEY_FILE=''
ABOX_DEPLOY_TX_EPHEMERAL_DIR=''
ABOX_LAST_BACKUP=''
ABOX_RUNTIME_LOCK_MODE=''
ABOX_TX_PREV_TRAP_EXIT=''
ABOX_TX_PREV_TRAP_INT=''
ABOX_TX_PREV_TRAP_TERM=''
ABOX_TX_PREV_TRAP_HUP=''
ABOX_CORE_TX_PREV_TRAP_EXIT=''
ABOX_CORE_TX_PREV_TRAP_INT=''
ABOX_CORE_TX_PREV_TRAP_TERM=''
ABOX_CORE_TX_PREV_TRAP_HUP=''
ABOX_CORE_UPGRADE_TARGETS=''
ABOX_CORE_UPGRADE_TMP=''
ABOX_TRAFFIC_TX_DIR=''

msg() { printf '%s\n' "$*"; }
die() {
    printf '%s\n' "${RED}[!] $*${NC}" >&2
    if [[ -n "${ABOX_DIE_HOOK:-}" ]] && declare -F "$ABOX_DIE_HOOK" >/dev/null 2>&1; then
        "$ABOX_DIE_HOOK" "$*" || true
    fi
    exit 1
}
now_iso() { date '+%Y-%m-%dT%H:%M:%S%z'; }


abox_dir_has_legacy_fingerprint() {
    local dir="${1:-$ABOX_DIR}" count=0 only='' entry base
    [[ -d "$dir" && ! -L "$dir" ]] || return 1
    if [[ -f "$dir/A-Box.sh" && ! -L "$dir/A-Box.sh" ]] &&
       grep -q '==============================A-Box===============================' "$dir/A-Box.sh" 2>/dev/null &&
       grep -q '^main "\$@"' "$dir/A-Box.sh" 2>/dev/null; then
        return 0
    fi
    if [[ -f "$dir/.env" && ! -L "$dir/.env" ]]; then
        if ( load_abox_env "$dir/.env" >/dev/null 2>&1 && [[ "${CORE:-}" =~ ^(xray|singbox|hysteria)$ ]] ); then
            return 0
        fi
    fi
    while IFS= read -r -d '' entry; do
        base=${entry##*/}
        [[ "$base" == '.' || "$base" == '..' ]] && continue
        count=$((count + 1))
        only="$base"
        (( count <= 1 )) || return 1
    done < <(
        shopt -s nullglob dotglob
        for entry in "$dir"/*; do
            [[ -e "$entry" || -L "$entry" ]] || continue
            printf '%s\0' "$entry"
        done
    )
    if (( count == 0 )); then
        return 0
    fi
    if (( count == 1 )) && [[ "$only" == '.lang' && -f "$dir/.lang" && ! -L "$dir/.lang" ]]; then
        grep -Eq '^(zh|en|ru|fa)[[:space:]]*$' "$dir/.lang"
        return
    fi
    return 1
}

path_owned_by_root() {
    local path="$1" uid gid
    [[ -e "$path" && ! -L "$path" ]] || return 1
    uid=$(stat -c %u "$path" 2>/dev/null) || return 1
    gid=$(stat -c %g "$path" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 ]]
}

path_mode_has_no_group_other_write() {
    local path="$1" mode
    mode=$(stat -c %a "$path" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

path_is_mountpoint() {
    local path="$1"
    [[ -e "$path" || -L "$path" ]] || return 1
    if python3 - "$path" <<'PY_EXACT_MOUNT' >/dev/null 2>&1
import os, re, sys

path = os.path.abspath(os.path.normpath(sys.argv[1]))
if os.path.islink(path):
    raise SystemExit(1)
try:
    with open('/proc/self/mountinfo', 'r', encoding='utf-8', errors='strict') as f:
        for line in f:
            fields = line.rstrip('\n').split(' ')
            if len(fields) < 5:
                continue
            raw = fields[4]
            mp = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw)
            mp = os.path.abspath(os.path.normpath(mp))
            if mp == path:
                raise SystemExit(0)
except (OSError, UnicodeError):
    # mountinfo is the authoritative source for Linux mount topology. If it
    # cannot be read, the caller cannot safely prove that the path is not a
    # mountpoint; fail closed rather than falling back to ismount().
    raise SystemExit(0)
raise SystemExit(1)
PY_EXACT_MOUNT
    then
        rc=0
    else
        rc=$?
    fi
    # Only rc=1 is a definitive "not a mountpoint" result. Any other
    # helper failure is treated as a mountpoint so callers fail closed rather
    # than deleting/restoring through an unknown mount boundary.
    case "$rc" in
        0|1) return "$rc" ;;
        *) return 0 ;;
    esac
}

path_tree_has_nested_mountpoint() {
    local path="${1:-}" rc
    [[ -n "$path" && ( -d "$path" || -f "$path" ) && ! -L "$path" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 0
    python3 - "$path" <<'PY_TREE_NESTED_MOUNT'
import os, sys
try:
    target=os.path.realpath(sys.argv[1]).rstrip('/') or '/'
    prefix=target + '/'
    with open('/proc/self/mountinfo','r',encoding='utf-8',errors='strict') as f:
        for raw in f:
            parts=raw.split()
            if len(parts) < 5:
                raise RuntimeError('malformed mountinfo')
            mountpoint=parts[4].replace('\\040',' ').replace('\\011','\\t').replace('\\012','\\n').replace('\\134','\\\\')
            mountpoint=os.path.realpath(mountpoint).rstrip('/') or '/'
            if mountpoint.startswith(prefix):
                raise SystemExit(0)
except SystemExit:
    raise
except Exception:
    raise SystemExit(2)
raise SystemExit(1)
PY_TREE_NESTED_MOUNT
    rc=$?
    case "$rc" in
        0) return 0 ;;
        1) return 1 ;;
        *) return 0 ;;
    esac
}

path_tree_has_mountpoint() {
    local path="$1"
    [[ -e "$path" || -L "$path" ]] || return 1
    if python3 - "$path" <<'PY_TREE_MOUNT' >/dev/null 2>&1
import os, sys

# Linux os.path.ismount() can miss bind mounts when the mount and parent
# reside on the same device. /proc/self/mountinfo is authoritative for the
# current mount namespace and also catches nested bind mounts.
root = os.path.abspath(os.path.normpath(sys.argv[1]))
if os.path.islink(root):
    raise SystemExit(1)

import re
def decode_mountinfo_path(value):
    # Decode each kernel mountinfo octal escape exactly once. Sequential
    # replacement can turn a literal backslash sequence into a different
    # escape and corrupt a legitimate path.
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)

mountpoints = []
try:
    with open('/proc/self/mountinfo', 'r', encoding='utf-8', errors='strict') as f:
        for line in f:
            fields = line.rstrip('\n').split(' ')
            if len(fields) >= 5:
                mp = os.path.abspath(os.path.normpath(decode_mountinfo_path(fields[4])))
                mountpoints.append(mp)
except (OSError, UnicodeError):
    # mountinfo is the authoritative source for Linux mount topology. If it
    # cannot be read, the caller cannot safely prove that the tree is free of
    # mounts; fail closed rather than using weaker ismount()/os.walk() checks.
    raise SystemExit(0)

if root == '/':
    raise SystemExit(0)
for mp in mountpoints:
    if mp == root or mp.startswith(root + os.sep):
        raise SystemExit(0)
raise SystemExit(1)
PY_TREE_MOUNT
    then
        rc=0
    else
        rc=$?
    fi
    # Only rc=1 is a definitive "not a mountpoint" result. Any other
    # helper failure is treated as a mountpoint so destructive/restore paths
    # fail closed instead of crossing an unknown mount boundary.
    case "$rc" in
        0|1) return "$rc" ;;
        *) return 0 ;;
    esac
}

assert_default_abox_parent_chain_trusted() {
    local dir="$1" parent uid gid mode
    [[ "$dir" == '/etc/ddr' ]] || return 0
    for parent in / /etc; do
        [[ -d "$parent" && ! -L "$parent" ]] || die "A-Box 父目录不可信: $parent"
        uid=$(stat -c %u "$parent" 2>/dev/null) || die "无法读取父目录属主: $parent"
        gid=$(stat -c %g "$parent" 2>/dev/null) || die "无法读取父目录属组: $parent"
        mode=$(stat -c %a "$parent" 2>/dev/null) || die "无法读取父目录权限: $parent"
        [[ "$uid" == 0 && "$gid" == 0 ]] || die "A-Box 父目录不是 root:root: $parent"
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) || die "A-Box 父目录可被非 root 写入: $parent"
    done
}

ensure_abox_dir_owned() {
    local dir="${1:-$ABOX_DIR}" owner tmp uid gid mode
    owner="$dir/.A-Box-owner"
    assert_default_abox_parent_chain_trusted "$dir"
    [[ ! -L "$dir" ]] || die "拒绝使用符号链接形式的 A-Box 目录: $dir"
    if [[ -e "$dir" && ! -d "$dir" ]]; then
        die "A-Box 路径不是目录: $dir"
    fi
    if [[ -d "$dir" ]]; then
        path_owned_by_root "$dir" || die "拒绝使用非 root:root 所有的 A-Box 目录: $dir"
        path_mode_has_no_group_other_write "$dir" || die "拒绝使用可被组/其他用户写入的 A-Box 目录: $dir"
        if [[ -f "$owner" && ! -L "$owner" ]] && grep -Fxq 'A-Box managed directory v1' "$owner" 2>/dev/null; then
            path_owned_by_root "$owner" || die "A-Box 目录归属标记不是 root:root: $owner"
            mode=$(stat -c %a "$owner" 2>/dev/null) || die "无法读取 A-Box 目录标记权限: $owner"
            [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || die "A-Box 目录标记权限不安全: $owner"
            chmod 700 "$dir" || die "无法收紧 A-Box 目录权限: $dir"
            chmod 600 "$owner" || die "无法收紧 A-Box 目录标记权限: $owner"
            return 0
        fi
        abox_dir_has_legacy_fingerprint "$dir" || die "拒绝复用未知归属目录: $dir"
    else
        mkdir -p "$dir" || die "无法创建 A-Box 目录: $dir"
    fi
    chown root:root "$dir" || die "无法设置 A-Box 目录属主: $dir"
    chmod 700 "$dir" || die "无法设置 A-Box 目录权限: $dir"
    tmp=$(umask 077; mktemp "$dir/.A-Box-owner.XXXXXX") || die 'A-Box 目录归属标记临时文件创建失败。'
    printf '%s\n' 'A-Box managed directory v1' > "$tmp" || { rm -f "$tmp"; die 'A-Box 目录归属标记写入失败。'; }
    chown root:root "$tmp" || { rm -f "$tmp"; die 'A-Box 目录归属标记属主设置失败。'; }
    chmod 600 "$tmp" || { rm -f "$tmp"; die 'A-Box 目录归属标记权限设置失败。'; }
    mv -f "$tmp" "$owner" || { rm -f "$tmp"; die 'A-Box 目录归属标记提交失败。'; }
    path_owned_by_root "$owner" || die 'A-Box 目录归属标记提交后属主异常。'
}

normalize_lang() {
    case "${1:-}" in
        en|en_US|en-US|english|English) printf 'en' ;;
        ru|ru_RU|ru-RU|russian|Русский) printf 'ru' ;;
        fa|fa_IR|fa-IR|persian|فارسی) printf 'fa' ;;
        zh|zh_CN|zh-CN|cn|CN|中文|'') printf 'zh' ;;
        *) printf 'zh' ;;
    esac
}

tr_msg() {
    local key="$1"
    case "${ABOX_LANG:-zh}:$key" in
        zh:press_return) echo '按回车返回...' ;;
        en:press_return) echo 'Press Enter to return...' ;;
        zh:select_prompt) echo '请选择 / Select' ;;
        en:select_prompt) echo 'Select' ;;
        zh:main_command) echo '请求下发执行代号: ' ;;
        en:main_command) echo 'Input command: ' ;;
        zh:lang_title) echo '语言设置 / Language' ;;
        en:lang_title) echo 'Language Settings / 语言设置' ;;
        ru:lang_title) echo 'Настройки языка' ;;
        fa:lang_title) echo 'تنظیمات زبان' ;;
        zh:lang_saved) echo '语言已保存。' ;;
        en:lang_saved) echo 'Language saved.' ;;
        ru:lang_saved) echo 'Язык сохранён.' ;;
        fa:lang_saved) echo 'زبان ذخیره شد.' ;;
        zh:yes_no_default_no) echo '[Y/N]' ;;
        en:yes_no_default_no) echo '[Y/N]' ;;
        zh:yes_no_default_yes) echo '[Y/N]' ;;
        en:yes_no_default_yes) echo '[Y/N]' ;;
        zh:reality_sni_prompt) echo '   %s 请输入伪装 SNI (端口 %s，回车默认: %s): ' ;;
        en:reality_sni_prompt) echo '   %s Enter camouflage SNI (port %s, default: %s): ' ;;
        zh:bad_sni) echo 'SNI 格式非法: %s' ;;
        en:bad_sni) echo 'Invalid SNI format: %s' ;;
        zh:apple_non443_warn) echo '检测到非 443 端口使用 Apple/iCloud 类 SNI：%s。Xray-core 对 apple/icloud target 与非443端口有风险警告，此组合可能提高 IP 封禁概率。' ;;
        en:apple_non443_warn) echo 'Apple/iCloud-like SNI on non-443 port detected: %s. Xray-core warns about apple/icloud targets and non-443 listening ports; this combination may increase IP blocking risk.' ;;
        zh:reality_non443_warn) echo '[!] REALITY/XHTTP 使用非 443 监听端口 (%s)。Xray 上游将其作为独立风险条件提示；请确认该端口符合你的网络环境。' ;;
        en:reality_non443_warn) echo '[!] REALITY/XHTTP is using a non-443 listen port (%s). Xray treats this as a separate risk condition; confirm that the port is suitable for your network environment.' ;;
        zh:apple_sni_warn) echo '[!] Apple/iCloud 类 target (%s) 被 Xray 上游作为独立风险条件提示；建议改用经过实测的非 Apple/iCloud 目标。' ;;
        en:apple_sni_warn) echo '[!] Apple/iCloud-like target (%s) is flagged by Xray as a separate risk condition; a tested non-Apple/iCloud target is recommended.' ;;
        zh:continue_or_reset) echo '继续使用此 SNI？输入 y 继续，其他任意键重新输入 %s: ' ;;
        en:continue_or_reset) echo 'Continue with this SNI? Type y to continue, anything else to re-enter %s: ' ;;
        zh:port_prompt) echo '   %s 请输入监听端口 (回车默认: %s): ' ;;
        en:port_prompt) echo '   %s Enter listen port (default: %s): ' ;;
        zh:ss_port_prompt) echo '   %s 请输入回程监听端口(TCP/UDP) (回车默认: %s): ' ;;
        en:ss_port_prompt) echo '   %s Enter relay listen port (TCP/UDP, default: %s): ' ;;
        zh:bad_port) echo '端口非法: %s' ;;
        en:bad_port) echo 'Invalid port: %s' ;;
        zh:toolbox_title) echo '综合工具箱 / Toolbox' ;;
        en:toolbox_title) echo 'Toolbox / 综合工具箱' ;;
        zh:confirm_remote) echo '即将下载第三方远程脚本：%s。下载后会显示 SHA256 并要求强确认。继续下载？[Y/N]: ' ;;
        en:confirm_remote) echo 'About to download a third-party remote script: %s. SHA256 will be shown and a strong confirmation will be required. Continue download? [Y/N]: ' ;;
        zh:confirm_local_sni_full) echo '即将运行本地内置全量 SNI 优选库（不执行远程脚本）。确认执行？[Y/N]: ' ;;
        en:confirm_local_sni_full) echo 'About to run the local built-in full SNI preference library (no remote script execution). Continue? [Y/N]: ' ;;
        zh:confirm_local_sni_mini) echo '即将运行本地内置微型主机 SNI 优选库（候选库与全量相同，不执行远程脚本）。确认执行？[Y/N]: ' ;;
        en:confirm_local_sni_mini) echo 'About to run the local built-in mini-host SNI preference library (same candidate library as full, no remote script execution). Continue? [Y/N]: ' ;;
        zh:swap_exists) echo '检测到 /swapfile 已存在，跳过创建。' ;;
        en:swap_exists) echo '/swapfile already exists; creation skipped.' ;;
        zh:swap_done) echo 'Swap 处理完成。' ;;
        en:swap_done) echo 'Swap operation completed.' ;;
        *) echo "$key" ;;
    esac
}

tprintf() {
    local key="$1" fmt placeholder_count=0 i=0 len next
    shift
    fmt=$(tr_msg "$key")
    # Translation strings are internal, but validate their printf grammar before
    # passing them to printf. Only %s and %% are supported, with %% treated as
    # a literal percent and never counted as a placeholder.
    [[ "$fmt" != *\\* ]] || die "非法翻译格式串: ${key}"
    len=${#fmt}
    while (( i < len )); do
        if [[ "${fmt:i:1}" == '%' ]]; then
            (( i + 1 < len )) || die "非法翻译格式串: ${key}"
            next=${fmt:i+1:1}
            case "$next" in
                '%') i=$((i + 2)) ;;
                s) placeholder_count=$((placeholder_count + 1)); i=$((i + 2)) ;;
                *) die "非法翻译格式串: ${key}" ;;
            esac
        else
            i=$((i + 1))
        fi
    done
    (( placeholder_count == $# )) || die "翻译参数数量不匹配: ${key} (${placeholder_count} != $#)"
    printf "$fmt" "$@"
}

proto_label() {
    printf '%b[%s]%b' "${BOLD}${CYAN}" "$1" "${NC}"
}

pause_return() {
    local released=0
    if [[ -t 0 ]]; then
        # Briefly release exclusive flock during idle prompt so cron helpers can run.
        if [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == flock ]] && [[ -e /proc/$$/fd/9 ]]; then
            flock -u 9 2>/dev/null && released=1 || true
        fi
        read -r -p "$(tr_msg press_return)" _ || true
        if (( released == 1 )); then
            flock -n 9 || die '重新获取 A-Box 运行锁失败；可能另有实例已启动。请退出后重试。'
        fi
    fi
}

is_yes() { [[ "${1:-}" =~ ^[Yy]$ ]]; }

confirm_yes_no() {
    local prompt="$1" answer
    read -r -p "$prompt" answer
    is_yes "$answer"
}

detect_lang() {
    if [[ -n "${ABOX_LANG_OVERRIDE:-}" ]]; then
        ABOX_LANG=$(normalize_lang "$ABOX_LANG_OVERRIDE")
    elif [[ -n "${ABOX_LANG:-}" && "${ABOX_LANG:-}" != 'zh' ]]; then
        ABOX_LANG=$(normalize_lang "$ABOX_LANG")
    elif [[ -r "$LANG_FILE" ]]; then
        ABOX_LANG=$(normalize_lang "$(tr -d '[:space:]' < "$LANG_FILE" 2>/dev/null)")
    else
        ABOX_LANG='zh'
    fi
}

save_lang() {
    ensure_abox_dir_owned "$ABOX_DIR"
    write_file_atomically_from_stdin "$LANG_FILE" 600 <<< "${ABOX_LANG:-zh}" || die '语言状态写入失败。'
}

initial_language_select() {
    [[ -f "$LANG_FILE" || -n "${ABOX_LANG_OVERRIDE:-}" ]] && return 0
    local c
    echo 'Language / 语言 / Язык / زبان'
    echo '1. 中文'
    echo '2. English'
    echo '3. Русский'
    echo '4. فارسی'
    read -r -p 'Select [1-4, default 1]: ' c || true
    case "$c" in
        2) ABOX_LANG='en' ;;
        3) ABOX_LANG='ru' ;;
        4) ABOX_LANG='fa' ;;
        *) ABOX_LANG='zh' ;;
    esac
    save_lang
}

language_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}$(tr_msg lang_title)${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}1. 中文${NC}"
    msg "${YELLOW}2. English${NC}"
    msg "${YELLOW}3. Русский${NC}"
    msg "${YELLOW}4. فارسی${NC}"
    msg "${GREEN}0. 返回 / Back${NC}"
    local c
    read -r -p 'Select [0-4]: ' c
    case "$c" in
        1) ABOX_LANG='zh'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        2) ABOX_LANG='en'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        3) ABOX_LANG='ru'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        4) ABOX_LANG='fa'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        *) return 0 ;;
    esac
}

need_interactive_tty() {
    if [[ ! -t 0 ]]; then
        if [[ -r /dev/tty ]]; then
            exec < /dev/tty || die '当前环境无可交互 TTY，无法打开控制终端。'
        else
            die '当前环境无可交互 TTY，无法运行交互式菜单。'
        fi
    fi
}
valid_decimal_upto() {
    local input="${1:-}" max="${2:-}" normalized
    [[ "$input" =~ ^[0-9]+$ ]] || return 1
    [[ "$max" =~ ^[1-9][0-9]*$ ]] || return 1
    normalized="${input#"${input%%[!0]*}"}"
    [[ -n "$normalized" ]] || normalized='0'
    (( ${#normalized} < ${#max} )) && return 0
    (( ${#normalized} > ${#max} )) && return 1
    (( 10#$normalized <= 10#$max ))
}

valid_port() {
    local input="${1:-}" normalized
    valid_decimal_upto "$input" 65535 || return 1
    normalized="${input#"${input%%[!0]*}"}"
    [[ -n "$normalized" ]] || return 1
    (( 10#$normalized >= 1 ))
}

valid_canonical_port() {
    local input="${1:-}"
    valid_port "$input" || return 1
    [[ "$input" == "$((10#$input))" ]]
}

valid_canonical_port_range() {
    local input="${1:-}" start end
    if [[ "$input" =~ ^([0-9]+):([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
    elif [[ "$input" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
    else
        return 1
    fi
    valid_canonical_port "$start" && valid_canonical_port "$end" && (( 10#$start <= 10#$end ))
}

valid_port_range() {
    local input="${1:-}" start end
    if [[ "$input" =~ ^([0-9]+):([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
    elif [[ "$input" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
    else
        return 1
    fi
    valid_port "$start" && valid_port "$end" && (( 10#$start <= 10#$end ))
}

normalize_port_spec() {
    local input="${1:-}" start end
    if valid_port "$input"; then
        printf '%s\n' "$((10#$input))"
        return 0
    fi
    valid_port_range "$input" || return 1
    if [[ "$input" == *:* ]]; then
        start="${input%%:*}"; end="${input##*:}"
    else
        start="${input%%-*}"; end="${input##*-}"
    fi
    printf '%s:%s\n' "$((10#$start))" "$((10#$end))"
}

valid_port_spec() { normalize_port_spec "${1:-}" >/dev/null 2>&1; }

valid_hy2_uri_ports() {
    local input="${1:-}" part
    [[ "$input" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || return 1
    local IFS=,
    local -a _parts=()
    read -r -a _parts <<< "$input"
    ((${#_parts[@]} > 0)) || return 1
    for part in "${_parts[@]}"; do
        if [[ "$part" == *-* ]]; then
            valid_canonical_port_range "$part" || return 1
        else
            valid_canonical_port "$part" || return 1
        fi
    done
}

valid_hy2_clash_ports() {
    local input="${1:-}"
    [[ "$input" =~ ^[0-9]+(-[0-9]+)?$ ]] || return 1
    if [[ "$input" == *-* ]]; then
        valid_canonical_port_range "$input" || return 1
    else
        valid_canonical_port "$input" || return 1
    fi
}

valid_hy2_sb_ports() {
    local input="${1:-}"
    [[ "$input" =~ ^[0-9]+:[0-9]+$ ]] || return 1
    valid_canonical_port_range "$input" || return 1
}

port_spec_for_firewalld() {
    local spec
    spec=$(normalize_port_spec "${1:-}") || return 1
    printf '%s\n' "${spec/:/-}"
}

valid_positive_int() {
    # Keep decimal integers within a range safe for Bash arithmetic on
    # standard 64-bit Linux; callers may still impose a tighter domain limit.
    [[ "${1:-}" =~ ^[1-9][0-9]{0,17}$ ]]
}

valid_traffic_limit_gb() {
    local input="${1:-}"
    [[ "$input" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    (( 10#$input <= 8589934591 ))
}
valid_backup_retention_count() {
    local input="${1:-}"
    [[ "$input" =~ ^[0-9]{1,4}$ ]] || return 1
    (( 10#$input <= 1000 ))
}
valid_hy2_bandwidth_mbps() {
    # Keep the interactive HY2 bandwidth domain identical to the persisted .env validator.
    valid_traffic_limit_gb "${1:-}"
}

valid_domain() {
    local domain="${1:-}"
    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_sni() { valid_domain "$1"; }

valid_single_line_secret() {
    local value="${1:-}" max_len="${2:-512}"
    [[ -n "$value" && ${#value} -le $max_len ]] || return 1
    [[ "$value" != *[[:cntrl:]]* ]]
}

is_apple_like_sni() {
    local sni="${1,,}"
    [[ "$sni" == 'apple.com' || "$sni" == *.apple.com || "$sni" == 'icloud.com' || "$sni" == *.icloud.com ]]
}

default_sni_for_port() {
    # The current default target is intentionally port-independent. Avoid Apple/iCloud
    # targets; use the SNI radar for a separately verified production target.
    printf 'www.microsoft.com'
}

prompt_reality_sni() {
    local label="$1" port="$2" default_sni input answer prompt warned
    default_sni=$(default_sni_for_port "$port")
    while true; do
        prompt=$(tprintf reality_sni_prompt "$label" "$port" "$default_sni")
        read -r -p "$prompt" input || return 1
        input=${input:-$default_sni}
        if ! valid_sni "$input"; then
            printf '%s\n' "${RED}[!] $(tprintf bad_sni "$input")${NC}" >&2
            continue
        fi
        warned=0
        if [[ "$port" != '443' ]]; then
            printf '%s\n' "${YELLOW}$(tprintf reality_non443_warn "$port")${NC}" >&2
            warned=1
        fi
        if is_apple_like_sni "$input"; then
            printf '%s\n' "${YELLOW}$(tprintf apple_sni_warn "$input")${NC}" >&2
            warned=1
        fi
        if [[ "$warned" == 1 ]]; then
            prompt=$(tprintf continue_or_reset "$label")
            read -r -p "$prompt" answer || return 1
            is_yes "$answer" && { printf '%s\n' "$input"; return 0; }
            continue
        fi
        printf '%s\n' "$input"
        return 0
    done
}

valid_url_https() {
    local url="${1:-}" rest host port
    [[ "$url" == https://* ]] || return 1
    [[ "$url" =~ [\"\`\$\\] ]] && return 1
    [[ "$url" =~ [[:space:]] ]] && return 1
    rest="${url#https://}"
    host="${rest%%/*}"
    [[ -n "$host" ]] || return 1
    if [[ "$host" == *:* ]]; then
        # This parser intentionally accepts DNS host[:port] only. Reject
        # multiple/empty colons instead of truncating them into a different
        # hostname+port pair (for example example.com:443:444).
        [[ "$host" =~ ^([^:]+):([0-9]+)$ ]] || return 1
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        valid_port "$port" || return 1
    fi
    valid_domain "$host" || return 1
}

normalize_https_url_input() {
    local input="${1:-}" rest
    input="$(printf '%s' "$input" | tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -n "$input" ]] || return 1
    if [[ "$input" != http://* && "$input" != https://* ]]; then
        input="https://${input}"
    fi
    if [[ "$input" == https://* ]]; then
        rest="${input#https://}"
        [[ "$rest" != */* ]] && input="${input}/"
    fi
    printf '%s\n' "$input"
}

prompt_https_url() {
    local prompt="$1" default_url="$2" input normalized
    while true; do
        read -r -p "$prompt" input || return 1
        input="${input:-$default_url}"
        normalized="$(normalize_https_url_input "$input" 2>/dev/null || true)"
        if [[ -n "$normalized" ]] && valid_url_https "$normalized"; then
            printf '%s\n' "$normalized"
            return 0
        fi
        printf '%s\n' "${RED}[!] HY2 伪装 URL 非法 / Invalid HY2 masquerade URL: ${input}${NC}" >&2
        printf '%s\n' "${YELLOW}    正确示例 / Example: https://www.microsoft.com/${NC}" >&2
    done
}

prompt_port_input() {
    local label="$1" default_port="$2" input prompt
    while true; do
        prompt=$(tprintf port_prompt "$label" "$default_port")
        read -r -p "$prompt" input || return 1
        input="${input:-$default_port}"
        if valid_port "$input"; then
            case "$((10#$input))" in
                22|53|68|123|161|323) printf '%s\n' "${RED}[!] 拒绝使用系统/管理保留端口 $((10#$input))。${NC}" >&2; continue ;;
            esac
            printf '%s\n' "$((10#$input))"
            return 0
        fi
        printf '%s\n' "${RED}[!] $(tprintf bad_port "$input")${NC}" >&2
    done
}

prompt_ss_port_input() {
    local label="$1" default_port="$2" input prompt
    while true; do
        prompt=$(tprintf ss_port_prompt "$label" "$default_port")
        read -r -p "$prompt" input || return 1
        input="${input:-$default_port}"
        if valid_port "$input"; then
            case "$((10#$input))" in
                22|53|68|123|161|323) printf '%s\n' "${RED}[!] 拒绝使用系统/管理保留端口 $((10#$input))。${NC}" >&2; continue ;;
            esac
            printf '%s\n' "$((10#$input))"
            return 0
        fi
        printf '%s\n' "${RED}[!] $(tprintf bad_port "$input")${NC}" >&2
    done
}

prompt_hy2_bandwidth_mbps_input() {
    local prompt="$1" default_value="$2" input
    while true; do
        read -r -p "$prompt" input || return 1
        input="${input:-$default_value}"
        if valid_hy2_bandwidth_mbps "$input"; then
            printf '%s\n' "$input"
            return 0
        fi
        printf '%s\n' "${RED}[!] 请输入正整数 / Enter a positive integer: ${input}${NC}" >&2
    done
}
valid_ipv4_cidr() {
    local input="${1:-}" addr mask n
    addr="${input%/*}"
    mask=''
    if [[ "$input" == */* ]]; then
        mask="${input#*/}"
        [[ -n "$mask" ]] || return 1
    fi
    if [[ -n "$mask" ]]; then
        valid_decimal_upto "$mask" 32 || return 1
        (( 10#$mask > 0 )) || return 1
    fi
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    local -a octets
    read -r -a octets <<< "$addr"
    for n in "${octets[@]}"; do
        valid_decimal_upto "$n" 255 || return 1
        # Keep IPv4 text canonical enough for downstream parsers such as Go's
        # net.ParseIP/net.ParseCIDR, which reject octets with leading zeroes.
        [[ "$n" == "0" || "$n" != 0* ]] || return 1
    done
}

valid_ipv6_cidr() {
    local input="${1:-}" addr mask
    addr="${input%/*}"
    mask=''
    if [[ "$input" == */* ]]; then
        mask="${input#*/}"
        [[ -n "$mask" ]] || return 1
    fi
    if [[ -n "$mask" ]]; then
        valid_decimal_upto "$mask" 128 || return 1
        (( 10#$mask > 0 )) || return 1
    fi
    [[ "$addr" == *:* ]] || return 1
    [[ "$addr" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    [[ "$addr" != *':::'* ]] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$input" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
        return $?
    fi
    return 1
}

valid_ip_address() {
    local input="${1:-}"
    [[ "$input" != */* && -n "$input" ]] || return 1
    valid_ipv4_cidr "$input" || valid_ipv6_cidr "$input"
}

valid_interface_name() {
    local iface="${1:-}"
    # Linux IFNAMSIZ is 16 bytes including the terminating NUL; the usable
    # interface-name limit is therefore 15 characters.
    [[ "$iface" =~ ^[a-zA-Z0-9_.:-]+$ && ${#iface} -le 15 ]]
}

shell_quote() {
    local v=${1:-} q
    q=${v//\\/\\\\}
    q=${q//\"/\\\"}
    q=${q//$'\n'/\\n}
    q=${q//$'\r'/\\r}
    printf '\"%s\"' "$q"
}
json_escape() { jq -Rn --arg v "${1:-}" '$v'; }

clear_abox_env_vars() {
    unset CORE MODE UUID VLESS_SNI VISION_SNI XHTTP_SNI VLESS_PORT XHTTP_PORT HY2_BASE_PORT HY2_DOMAIN HY2_UP HY2_DOWN HY2_MASQ_URL
    unset SS_PORT SS_WHITELIST_IP PUBLIC_KEY PBK SHORT_ID HY2_PASS HY2_OBFS SS_PASS LINK_IP HY2_CERT_SHA256_FP HY2_CERT_PUBKEY_SHA256_B64
    unset HY2_HOP HY2_HOP_IMPL HY2_MONITOR_PORT HY2_ACME_TYPE HY2_ACME_DNS_PROVIDER HY2_ACME_DNS_CF_API_TOKEN
    unset HY2_URI_PORTS HY2_CLASH_PORTS HY2_SB_PORTS HY2_RANGE_START HY2_RANGE_END INGRESS_IF ENABLE_KEEPALIVE
    unset TRAFFIC_LIMIT_GB TRAFFIC_LIMIT_MODE
}

validate_abox_env_semantics() {
    local p value
    [[ "${CORE:-}" =~ ^(xray|singbox|hysteria)$ ]] || return 1
    [[ "${MODE:-}" =~ ^(VISION|XHTTP|SS|ALL|VLESS_SS|HY2)$ ]] || return 1
    case "${CORE}:${MODE}" in
        xray:VISION|xray:XHTTP|xray:SS|xray:ALL|xray:VLESS_SS|singbox:VISION|singbox:SS|singbox:VLESS_SS|singbox:HY2|singbox:ALL|hysteria:HY2) ;;
        *) return 1 ;;
    esac
    for p in VLESS_PORT XHTTP_PORT HY2_BASE_PORT SS_PORT HY2_MONITOR_PORT HY2_RANGE_START HY2_RANGE_END; do
        value=${!p:-}
        [[ -z "$value" ]] || valid_canonical_port "$value" || return 1
    done
    if [[ -n "${HY2_RANGE_START:-}${HY2_RANGE_END:-}" ]]; then
        valid_canonical_port "${HY2_RANGE_START:-}" && valid_canonical_port "${HY2_RANGE_END:-}" || return 1
        (( 10#$HY2_RANGE_START <= 10#$HY2_RANGE_END )) || return 1
    fi
    for p in VLESS_SNI VISION_SNI XHTTP_SNI HY2_DOMAIN; do
        value=${!p:-}
        [[ -z "$value" ]] || valid_domain "$value" || return 1
    done
    for p in HY2_UP HY2_DOWN; do
        value=${!p:-}
        [[ -z "$value" ]] || valid_traffic_limit_gb "$value" || return 1
    done
    [[ -z "${HY2_MASQ_URL:-}" ]] || valid_url_https "$HY2_MASQ_URL" || return 1
    [[ -z "${UUID:-}" || "${UUID:-}" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || return 1
    [[ -z "${SHORT_ID:-}" || "${SHORT_ID:-}" =~ ^[0-9A-Fa-f]{2,32}$ ]] || return 1
    [[ -z "${SHORT_ID:-}" || $(( ${#SHORT_ID} % 2 )) -eq 0 ]] || return 1
    [[ -z "${HY2_CERT_SHA256_FP:-}" || "${HY2_CERT_SHA256_FP:-}" =~ ^[0-9A-Fa-f]{64}$ ]] || return 1
    [[ -z "${LINK_IP:-}" || "${LINK_IP:-}" == N/A ]] || valid_ip_address "$LINK_IP" || return 1
    [[ -z "${HY2_HOP:-}" || "${HY2_HOP:-}" =~ ^(true|false)$ ]] || return 1
    [[ -z "${HY2_HOP_IMPL:-}" || "${HY2_HOP_IMPL:-}" =~ ^(none|manual|official)$ ]] || return 1
    [[ -z "${HY2_ACME_TYPE:-}" || "${HY2_ACME_TYPE:-}" =~ ^(http|dns)$ ]] || return 1
    [[ -z "${ENABLE_KEEPALIVE:-}" || "${ENABLE_KEEPALIVE:-}" =~ ^(true|false)$ ]] || return 1
    [[ -z "${INGRESS_IF:-}" ]] || valid_interface_name "$INGRESS_IF" || return 1
    if [[ -n "${TRAFFIC_LIMIT_GB:-}" ]]; then
        valid_traffic_limit_gb "$TRAFFIC_LIMIT_GB" || return 1
        [[ "${TRAFFIC_LIMIT_MODE:-total}" =~ ^(total|rx|tx)$ ]] || return 1
    else
        [[ -z "${TRAFFIC_LIMIT_MODE:-}" || "${TRAFFIC_LIMIT_MODE:-}" =~ ^(total|rx|tx)$ ]] || return 1
    fi
    if [[ -n "${HY2_URI_PORTS:-}" ]]; then
        valid_hy2_uri_ports "$HY2_URI_PORTS" || return 1
    fi
    if [[ -n "${HY2_CLASH_PORTS:-}" ]]; then
        valid_hy2_clash_ports "$HY2_CLASH_PORTS" || return 1
    fi
    if [[ -n "${HY2_SB_PORTS:-}" ]]; then
        valid_hy2_sb_ports "$HY2_SB_PORTS" || return 1
    fi
}

load_abox_env() {
    local file="${1:-$ABOX_ENV}" parsed key value uid gid mode i
    local -a staged_keys=() staged_values=()
    clear_abox_env_vars
    [[ -r "$file" && -f "$file" && ! -L "$file" ]] || return 1
    uid=$(stat -c %u "$file" 2>/dev/null) || return 1
    gid=$(stat -c %g "$file" 2>/dev/null) || return 1
    mode=$(stat -c %a "$file" 2>/dev/null) || return 1
    [[ "$uid" == '0' && "$gid" == '0' && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    parsed=$(umask 077; mktemp /tmp/A-Box-env.XXXXXX) || return 1
    if ! python3 - "$file" > "$parsed" <<'PY_ABOX_ENV'; then
import os
import shlex
import sys

if os.path.getsize(sys.argv[1]) > 65536:
    raise SystemExit("state file too large")

allowed = {
    "CORE", "MODE", "UUID", "VLESS_SNI", "VISION_SNI", "XHTTP_SNI",
    "VLESS_PORT", "XHTTP_PORT", "HY2_BASE_PORT", "HY2_DOMAIN", "HY2_UP",
    "HY2_DOWN", "HY2_MASQ_URL", "SS_PORT", "PUBLIC_KEY", "SHORT_ID",
    "HY2_PASS", "HY2_OBFS", "SS_PASS", "LINK_IP", "HY2_CERT_SHA256_FP",
    "HY2_CERT_PUBKEY_SHA256_B64", "HY2_HOP", "HY2_HOP_IMPL",
    "HY2_MONITOR_PORT", "HY2_ACME_TYPE", "HY2_ACME_DNS_PROVIDER",
    "HY2_ACME_DNS_CF_API_TOKEN", "HY2_URI_PORTS", "HY2_CLASH_PORTS",
    "HY2_SB_PORTS", "HY2_RANGE_START", "HY2_RANGE_END", "INGRESS_IF",
    "ENABLE_KEEPALIVE", "TRAFFIC_LIMIT_GB", "TRAFFIC_LIMIT_MODE",
}
seen = set()
with open(sys.argv[1], "r", encoding="utf-8", errors="strict") as handle:
    for number, raw_line in enumerate(handle, 1):
        if len(raw_line) > 8192:
            raise SystemExit(f"state line too long at line {number}")
        line = raw_line.rstrip("\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise SystemExit(f"invalid state line {number}")
        key, raw_value = line.split("=", 1)
        if key not in allowed or key in seen:
            raise SystemExit(f"invalid or duplicate state key at line {number}")
        parts = shlex.split(raw_value, posix=True)
        if len(parts) != 1:
            raise SystemExit(f"invalid state value at line {number}")
        value = parts[0]
        if len(value.encode("utf-8")) > 4096:
            raise SystemExit(f"state value too long at line {number}")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise SystemExit(f"invalid control character at line {number}")
        seen.add(key)
        sys.stdout.buffer.write(key.encode("ascii") + b"\0" + value.encode("utf-8") + b"\0")
PY_ABOX_ENV
        rm -f "$parsed"
        clear_abox_env_vars
        return 1
    fi
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
        staged_keys+=("$key")
        staged_values+=("$value")
    done < "$parsed"
    rm -f "$parsed"
    clear_abox_env_vars
    for ((i=0; i<${#staged_keys[@]}; i++)); do
        printf -v "${staged_keys[i]}" '%s' "${staged_values[i]}"
    done
    if ! validate_abox_env_semantics; then
        clear_abox_env_vars
        return 1
    fi
}


load_optional_abox_env_or_die() {
    # A missing .env is valid during first-time setup. An existing but invalid,
    # unsafe, or unreadable .env must never be treated as an empty installation.
    if [[ -e "$ABOX_ENV" || -L "$ABOX_ENV" ]]; then
        load_abox_env "$ABOX_ENV" 2>/dev/null || die '现有 A-Box .env 校验失败或权限不安全；已中止操作。'
    else
        clear_abox_env_vars
    fi
}

rand_alnum() {
    local len="$1" out='' chunk attempt target max_attempts
    valid_positive_int "$len" && (( 10#$len <= 4096 )) || die '随机字符串长度非法。'
    target=$((10#$len))
    # The previous fixed 16 rounds could never produce 4096 alphanumeric chars.
    max_attempts=$(( (target + 255) / 256 + 16 ))
    for ((attempt=0; attempt<max_attempts && ${#out}<target; attempt++)); do
        chunk=$(openssl rand -base64 256 2>/dev/null | tr -dc 'a-zA-Z0-9') || chunk=''
        [[ -n "$chunk" ]] && out+="$chunk"
    done
    (( ${#out} >= target )) || die '加密随机源读取失败。'
    printf '%s\n' "${out:0:target}"
}

generate_robust_uuid() {
    local candidate u variant
    if command -v uuidgen >/dev/null 2>&1; then
        candidate=$(uuidgen 2>/dev/null || true)
        if [[ "$candidate" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$ ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        candidate=$(tr -d '\n\r' < /proc/sys/kernel/random/uuid 2>/dev/null || true)
        if [[ "$candidate" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$ ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    {
        local u variant
        u=$(openssl rand -hex 16 2>/dev/null) || u=''
        [[ ${#u} -eq 32 ]] || die 'UUID 随机源读取失败。'
        case "${u:16:1}" in
            0|1|2|3) variant=8 ;;
            4|5|6|7) variant=9 ;;
            8|9|a|b) variant=a ;;
            *) variant=b ;;
        esac
        printf '%s-%s-4%s-%s%s-%s\n' "${u:0:8}" "${u:8:4}" "${u:13:3}" "$variant" "${u:17:3}" "${u:20:12}"
    }
}

pin_sha256_colon() {
    openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2
}

valid_public_ip() {
    local ip="${1:-}"
    valid_ip_address "$ip" || return 1
    python3 - "$ip" <<'PY_PUBLIC_IP'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if (addr.is_multicast or addr.is_reserved or addr.is_loopback or
    addr.is_link_local or addr.is_unspecified or addr.is_private):
    raise SystemExit(1)
if addr.version == 6 and addr.ipv4_mapped is not None:
    raise SystemExit(1)
if addr.version == 4:
    blocked = (
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('192.0.0.0/24'),
        ipaddress.ip_network('192.88.99.0/24'),
        ipaddress.ip_network('198.18.0.0/15'),
        ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'),
        ipaddress.ip_network('240.0.0.0/4'),
    )
else:
    blocked = (
        ipaddress.ip_network('2001:db8::/32'),
        ipaddress.ip_network('2001:2::/48'),
        ipaddress.ip_network('2001:20::/28'),
        ipaddress.ip_network('64:ff9b::/96'),
    )
if any(addr in network for network in blocked):
    raise SystemExit(1)
if not addr.is_global:
    raise SystemExit(1)
raise SystemExit(0)
PY_PUBLIC_IP
}

get_public_ip_fresh() {
    local ip api pref
    pref=$(read_ip_pref 2>/dev/null || printf 'dual')
    _abox_try_v4() {
        local api ip
        for api in 'https://api.ipify.org' 'https://ifconfig.me/ip' 'https://icanhazip.com'; do
            ip=$(curl -fsS4 --connect-timeout "$PUBLIC_IP_CONNECT_TIMEOUT" -m "$PUBLIC_IP_MAX_TIME" "$api" 2>/dev/null | tr -d '[:space:]')
            if valid_public_ip "$ip"; then
                printf '%s\n' "$ip"
                return 0
            fi
        done
        return 1
    }
    _abox_try_v6() {
        local ip
        ip=$(curl -fsS6 --connect-timeout "$PUBLIC_IP_CONNECT_TIMEOUT" -m "$PUBLIC_IP_MAX_TIME" 'https://api64.ipify.org' 2>/dev/null | tr -d '[:space:]')
        if valid_public_ip "$ip"; then
            printf '%s\n' "$ip"
            return 0
        fi
        return 1
    }
    case "$pref" in
        ipv4)
            _abox_try_v4 && return 0
            ;;
        ipv6)
            _abox_try_v6 && return 0
            ;;
        *)
            _abox_try_v4 && return 0
            _abox_try_v6 && return 0
            ;;
    esac
    printf 'N/A\n'
    return 1
}

cache_public_ip() {
    local ip="$1"
    [[ -n "$ip" && "$ip" != 'N/A' ]] || return 0
    ensure_abox_dir_owned "$ABOX_DIR"
    write_file_atomically_from_stdin "$PUBLIC_IP_CACHE" 600 <<< "$ip" || return 1
}

read_cached_public_ip() {
    local ip now mtime age
    [[ -r "$PUBLIC_IP_CACHE" && -f "$PUBLIC_IP_CACHE" && ! -L "$PUBLIC_IP_CACHE" ]] || return 1
    [[ "$(stat -c %u:%g "$PUBLIC_IP_CACHE" 2>/dev/null || true)" == 0:0 ]] || return 1
    ip=$(head -n 1 "$PUBLIC_IP_CACHE" 2>/dev/null | tr -d '[:space:]')
    if ! valid_public_ip "$ip"; then
        return 1
    fi
    now=$(date +%s)
    mtime=$(stat -c %Y "$PUBLIC_IP_CACHE" 2>/dev/null || echo 0)
    age=$(( now - mtime ))
    (( age >= 0 && age <= PUBLIC_IP_CACHE_TTL )) || return 1
    printf '%s\n' "$ip"
}

get_public_ip() {
    local ip stale age now mtime
    ip=$(read_cached_public_ip 2>/dev/null || true)
    if [[ -n "$ip" ]]; then
        printf '%s\n' "$ip"
        return 0
    fi
    ip=$(get_public_ip_fresh || true)
    if [[ -n "$ip" && "$ip" != 'N/A' ]]; then
        cache_public_ip "$ip"
        printf '%s\n' "$ip"
        return 0
    fi
    # Never silently use an expired address for generated client links.  A
    # stale address can route users to an unrelated host after VPS renumbering.
    if [[ -r "$PUBLIC_IP_CACHE" && -f "$PUBLIC_IP_CACHE" && ! -L "$PUBLIC_IP_CACHE" ]]; then
        stale=$(head -n 1 "$PUBLIC_IP_CACHE" 2>/dev/null | tr -d '[:space:]')
        if valid_public_ip "$stale"; then
            now=$(date +%s)
            mtime=$(stat -c %Y "$PUBLIC_IP_CACHE" 2>/dev/null || echo 0)
            age=$(( now - mtime ))
            printf '[!] Cached public IP is stale (%ss old); refusing to use it.\n' "$age" >&2
        fi
    fi
    printf 'N/A\n'
    return 1
}

refresh_public_ip() {
    local ip
    ip=$(get_public_ip_fresh || true)
    if [[ -n "$ip" && "$ip" != 'N/A' ]]; then
        cache_public_ip "$ip"
        printf '%s\n' "$ip"
        return 0
    fi
    get_public_ip
}
get_active_interface() {
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$iface" ]] && iface=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$iface" ]] && iface=$(ip -o route show to default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$iface" ]] && iface=$(ip -6 -o route show to default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$iface" ]] && iface=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 !~ /^(lo|vir|wl)/ {sub(/@.*/,"",$2); print $2; exit}')
    printf '%s\n' "$iface"
}

verify_domain_points_to_self() {
    local domain="$1" pub_ip="$2" resolved continue_domain
    resolved=$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u)
    [[ -z "$resolved" ]] && die "域名无法解析: $domain"
    if [[ "$pub_ip" != 'N/A' ]] && ! grep -Fxq "$pub_ip" <<< "$resolved"; then
        msg "${YELLOW}[!] 域名已解析，但未发现解析到当前公网 IP: $pub_ip${NC}"
        printf '%s\n\n%s\n' "${YELLOW}解析结果:${NC}" "$resolved"
        read -r -p '仍然继续？[Y/N]: ' continue_domain
        is_yes "$continue_domain" || die '已取消部署。'
    fi
}

openrc_cron_service_name() {
    case "$1" in
        debian|ubuntu) printf '%s\n' cron ;;
        alpine)
            # Prefer an installed alternate cron OpenRC unit. BusyBox ships
            # /etc/init.d/crond by default; apk add cronie/dcron adds a different
            # unit name and must not leave the BusyBox unit as the only target.
            if [[ -x /etc/init.d/cronie ]]; then
                printf '%s\n' cronie
            elif [[ -x /etc/init.d/dcron ]]; then
                printf '%s\n' dcron
            else
                printf '%s\n' crond
            fi
            ;;
        *) printf '%s\n' crond ;;
    esac
}

init_system_environment() {
    release=''
    local -a install_cmd=()
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in
            debian) release='debian'; install_cmd=(apt-get -y install) ;;
            ubuntu) release='ubuntu'; install_cmd=(apt-get -y install) ;;
            alpine) release='alpine'; install_cmd=(apk add) ;;
            centos|rhel|rocky|almalinux|fedora|amzn|ol|oracle) release='centos'; install_cmd=(yum -y install) ;;
        esac
        # ID_LIKE fallback for derivatives (e.g. ID=pop ID_LIKE="ubuntu debian").
        if [[ -z "$release" && -n "${ID_LIKE:-}" ]]; then
            case " ${ID_LIKE} " in
                *' debian '*|*' ubuntu '*) release='debian'; install_cmd=(apt-get -y install) ;;
                *' rhel '*|*' fedora '*|*' centos '*) release='centos'; install_cmd=(yum -y install) ;;
            esac
        fi
    fi
    if [[ -z "$release" ]]; then
        if [[ -f /etc/redhat-release ]] || grep -qiE 'centos|red hat|rocky|almalinux|fedora|amazon|oracle' /proc/version 2>/dev/null; then
            release='centos'; install_cmd=(yum -y install)
        elif grep -qi 'Alpine' /etc/issue /proc/version 2>/dev/null; then
            release='alpine'; install_cmd=(apk add)
        elif grep -qi 'debian' /etc/issue /proc/version 2>/dev/null; then
            release='debian'; install_cmd=(apt-get -y install)
        elif grep -qi 'ubuntu' /etc/issue /proc/version 2>/dev/null; then
            release='ubuntu'; install_cmd=(apt-get -y install)
        fi
    fi
    [[ -z "$release" ]] && die '本脚本不支持当前异构系统。'
    if [[ "$release" == 'centos' ]] && command -v dnf >/dev/null 2>&1; then
        install_cmd=(dnf -y install)
    fi

    if systemd_available; then
        INIT_SYS='systemd'
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYS='openrc'
    else
        die '无法检测到受支持的守护进程初始化系统 (Systemd/OpenRC)。'
    fi

    if [[ ! -f "$DEPS_MARKER" ]]; then
        msg "${YELLOW}[*] 正在同步系统依赖环境 (OS: ${release}, Init: ${INIT_SYS})...${NC}"
        case "$release" in
            debian|ubuntu) apt-get update -y -q >/dev/null 2>&1 ;;
            centos) if command -v dnf >/dev/null 2>&1; then dnf makecache -y -q >/dev/null 2>&1 || true; else yum makecache -y -q >/dev/null 2>&1 || true; fi; "${install_cmd[@]}" epel-release >/dev/null 2>&1 || true ;;
            alpine) apk update -q >/dev/null 2>&1 ;;
        esac
        local deps=()
        case "$release" in
            debian|ubuntu)
                deps=(curl jq openssl bc unzip iptables tar psmisc lsof ca-certificates iproute2 coreutils cron logrotate uuid-runtime python3 util-linux diffutils)
                ;;
            centos)
                # Do not force the full 'curl' RPM when curl-minimal already provides
                # /usr/bin/curl (Rocky/Alma/RHEL 8+/9). Forcing curl conflicts with curl-minimal.
                # diffutils provides cmp(1), required by atomic install / OTA / traffic helpers.
                deps=(jq openssl bc unzip iptables tar psmisc lsof ca-certificates coreutils cronie logrotate util-linux bind-utils iproute epel-release python3 diffutils)
                command -v curl >/dev/null 2>&1 || deps+=(curl)
                ;;
            alpine)
                # Use BusyBox crond (OpenRC unit name: crond). Do not apk-add cronie by
                # default: it lives in community and registers unit 'cronie', which used
                # to disagree with openrc_cron_service_name returning 'crond'.
                # Explicit 'tar' pulls GNU tar so backup fixtures and archives support
                # GNU long options where needed.
                deps=(bash curl jq openssl bc unzip iptables tar psmisc lsof ca-certificates iproute2 coreutils logrotate util-linux bind-tools procps iptables-openrc python3 shadow)
                ;;
        esac
        if [[ "$release" == 'centos' ]] && command -v dnf >/dev/null 2>&1; then
            # --allowerasing covers residual curl <-> curl-minimal swaps if curl is needed.
            dnf -y install --allowerasing "${deps[@]}" >/dev/null 2>&1 || die '基础依赖包安装失败。'
        else
            "${install_cmd[@]}" "${deps[@]}" >/dev/null 2>&1 || die '基础依赖包安装失败。'
        fi
        ensure_abox_dir_owned "$ABOX_DIR"
        install -m 600 /dev/null "$DEPS_MARKER" || die '依赖标记写入失败。'
    fi

    ensure_commands

    reconcile_systemd_unit() {
        local unit="$1"
        systemctl list-unit-files --type=service --no-legend "${unit}.service" 2>/dev/null | awk -v wanted="${unit}.service" '$1 == wanted { found=1 } END { exit !found }' || return 0
        systemctl enable --now "$unit" >/dev/null 2>&1 || die "系统服务 ${unit} 无法启用或启动。"
        systemctl is-active --quiet "$unit" || die "系统服务 ${unit} 未处于 active 状态。"
    }
    reconcile_openrc_service() {
        local unit="$1"
        [[ -x "/etc/init.d/${unit}" ]] || return 0
        rc-update add "$unit" default >/dev/null 2>&1 || die "OpenRC 服务 ${unit} 无法加入 default runlevel。"
        rc-service "$unit" status >/dev/null 2>&1 || rc-service "$unit" start >/dev/null 2>&1 || die "OpenRC 服务 ${unit} 无法启动。"
        rc-service "$unit" status >/dev/null 2>&1 || die "OpenRC 服务 ${unit} 未处于运行状态。"
    }
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        case "$release" in
            debian|ubuntu) reconcile_systemd_unit cron ;;
            centos) reconcile_systemd_unit crond ;;
        esac
        if [[ "$release" == 'centos' ]]; then
            if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
                msg "${YELLOW}[*] firewalld is active; A-Box will add required ports natively and will not disable it.${NC}"
            else
                msg "${YELLOW}[*] firewalld is inactive; A-Box will persist only its own rules through A-Box-firewall.service.${NC}"
            fi
        fi
    else
        local cron_unit
        cron_unit=$(openrc_cron_service_name "$release")
        if [[ "$release" == 'alpine' && "$cron_unit" != 'crond' && -x /etc/init.d/crond ]]; then
            # Avoid dual schedulers after apk add cronie/dcron (Alpine wiki guidance).
            rc-service crond stop >/dev/null 2>&1 || true
            if command -v rc-update >/dev/null 2>&1 && rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])crond([[:space:]]|$)'; then
                rc-update del crond default >/dev/null 2>&1 || true
            fi
        fi
        reconcile_openrc_service "$cron_unit"
    fi

    IPT=$(command -v iptables || echo '/sbin/iptables')
    IPT6=$(command -v ip6tables || echo '/sbin/ip6tables')
}

install_optional_package() {
    local pkg="$1"
    [[ -n "$pkg" ]] || return 1
    case "${release:-}" in
        debian|ubuntu) command -v apt-get >/dev/null 2>&1 && apt-get -y install "$pkg" >/dev/null 2>&1 ;;
        centos) if command -v dnf >/dev/null 2>&1; then dnf -y install --allowerasing "$pkg" >/dev/null 2>&1; elif command -v yum >/dev/null 2>&1; then yum -y install "$pkg" >/dev/null 2>&1; else return 1; fi ;;
        alpine) command -v apk >/dev/null 2>&1 && apk add "$pkg" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

ensure_commands() {
    local missing_pkgs=()
    need_cmd_pkg() {
        local cmd="$1" deb="$2" rpm="$3" apk="$4"
        command -v "$cmd" >/dev/null 2>&1 && return 0
        case "$release" in
            debian|ubuntu) missing_pkgs+=("$deb") ;;
            centos) missing_pkgs+=("$rpm") ;;
            alpine) missing_pkgs+=("$apk") ;;
        esac
    }
    need_cmd_pkg curl curl curl curl
    need_cmd_pkg jq jq jq jq
    need_cmd_pkg openssl openssl openssl openssl
    need_cmd_pkg bc bc bc bc
    need_cmd_pkg unzip unzip unzip unzip
    need_cmd_pkg tar tar tar tar
    need_cmd_pkg iptables iptables iptables iptables
    need_cmd_pkg ss iproute2 iproute iproute2
    need_cmd_pkg lsof lsof lsof lsof
    need_cmd_pkg getent libc-bin glibc-common libc-utils
    need_cmd_pkg flock util-linux util-linux util-linux
    need_cmd_pkg cmp diffutils diffutils diffutils
    need_cmd_pkg crontab cron cronie cronie
    need_cmd_pkg logrotate logrotate logrotate logrotate
    need_cmd_pkg python3 python3 python3 python3
    need_cmd_pkg groupadd passwd shadow-utils shadow
    need_cmd_pkg useradd passwd shadow-utils shadow
    if (( ${#missing_pkgs[@]} > 0 )); then
        local -a unique_pkgs=()
        mapfile -t unique_pkgs < <(printf '%s\n' "${missing_pkgs[@]}" | awk 'NF && !seen[$0]++')
        msg "${YELLOW}[*] 检测到缺失依赖包，正在补装...${NC}"
        if [[ "$release" == 'centos' ]] && command -v dnf >/dev/null 2>&1; then
            dnf -y install --allowerasing "${unique_pkgs[@]}" >/dev/null 2>&1 || die '依赖补装失败。'
        else
            "${install_cmd[@]}" "${unique_pkgs[@]}" >/dev/null 2>&1 || die '依赖补装失败。'
        fi
    fi
    local required=(curl jq openssl bc unzip tar iptables ss lsof crontab logrotate python3 flock cmp)
    local c
    for c in "${required[@]}"; do
        command -v "$c" >/dev/null 2>&1 || die "关键依赖缺失: $c"
    done
    # flock is now guaranteed; upgrade any pre-ensure fallback lock onto LOCK_FILE.
    if [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == fallback ]]; then
        upgrade_runtime_lock_to_flock_if_possible || die '已安装 flock，但无法将 fallback 运行锁升级为 flock；请结束其它 A-Box 实例后重试。'
    fi
}

has_ipv6() {
    local _pref
    _pref=$(read_ip_pref 2>/dev/null || printf 'dual')
    [[ "$_pref" == 'ipv4' ]] && return 1
    ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { found=1 } END { exit !found }' && return 0
    ip -6 route show default 2>/dev/null | awk '/^default/ { found=1 } END { exit !found }' && return 0
    return 1
}

wildcard_listen_address() {
    local bindv6only='0' pref
    pref=$(read_ip_pref 2>/dev/null || printf 'dual')
    case "$pref" in
        ipv4)
            printf '0.0.0.0'
            return 0
            ;;
        ipv6)
            has_ipv6 || die '当前偏好为仅 IPv6，但系统没有可用的全局 IPv6 地址/默认路由。'
            printf '::'
            return 0
            ;;
    esac
    # dual (default): prefer :: when the kernel dual-stacks IPv4-mapped traffic.
    bindv6only=$(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null || printf '0')
    if has_ipv6 && [[ "$bindv6only" == '0' ]]; then
        printf '::'
    else
        # Preserve IPv4 reachability on IPv4-only or v6-only-wildcard hosts.
        printf '0.0.0.0'
    fi
}

ipv6_nat_redirect_usable() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    $IPT6 -w -t nat -L PREROUTING >/dev/null 2>&1 || return 1
}

get_architecture() {
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) XRAY_ARCH='64'; SB_ARCH='amd64'; HY2_ARCH='amd64' ;;
        # armv8l is a 32-bit ARMv8 target, not AArch64; fail closed rather than
        # installing 64-bit arm64/aarch64 binaries into a 32-bit userspace.
        aarch64|arm64) XRAY_ARCH='arm64-v8a'; SB_ARCH='arm64'; HY2_ARCH='arm64' ;;
        *) die "无法识别的底层 CPU 架构: $ARCH" ;;
    esac
}

systemd_available() {
    command -v systemctl >/dev/null 2>&1 || return 1
    [[ -r /proc/1/comm ]] || return 1
    [[ "$(cat /proc/1/comm 2>/dev/null || true)" == 'systemd' ]] || return 1
}

service_active_state_value() {
    local srv="$1" state rc
    if [[ "${INIT_SYS:-}" == systemd ]] && systemd_available; then
        state=$(systemctl show -p ActiveState --value "$srv" 2>/dev/null) || return 1
        case "$state" in
            active) printf '1\n' ;;
            inactive|failed|dead|exited) printf '0\n' ;;
            *) return 1 ;;
        esac
        return 0
    elif [[ "${INIT_SYS:-}" == openrc ]]; then
        command -v rc-service >/dev/null 2>&1 || return 1
        rc-service "$srv" status >/dev/null 2>&1
        rc=$?
        case "$rc" in
            0) printf '1\n' ;;
            3|16|32) printf '0\n' ;;
            *) return 1 ;;
        esac
        return 0
    fi
    return 1
}

service_manager() {
    local action=$1; shift
    local srv
    for srv in "$@"; do
        if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
            case "$action" in
                stop)
                    systemctl stop "$srv" >/dev/null 2>&1 || true
                    [[ "$(service_active_state_value "$srv" 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
                    systemctl disable "$srv" >/dev/null 2>&1 || return 1
                    [[ "$(service_active_state_value "$srv" 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
                    ;;
                start)
                    systemctl daemon-reload >/dev/null 2>&1 || die 'systemd daemon-reload failed.'
                    systemctl enable "$srv" >/dev/null 2>&1 || die "服务 $srv 无法设置为开机启动。"
                    if ! systemctl restart "$srv" >/dev/null 2>&1; then
                        journalctl -u "$srv" --no-pager -n 80 2>/dev/null || true
                        die "服务 $srv 重启命令失败。"
                    fi
                    sleep 2
                    if ! systemctl is-active --quiet "$srv"; then
                        journalctl -u "$srv" --no-pager -n 80 2>/dev/null || true
                        case "$srv" in sing-box|hysteria) clean_nat_rules 2>/dev/null || true; save_firewall_rules 2>/dev/null || true ;; esac
                        die "服务 $srv 拉起失败。"
                    fi
                    record_core_family_ownership "$srv" || die "服务 $srv 已启动，但逐文件归属清单写入失败。"
                    ;;
                *) die "未知服务操作: $action" ;;
            esac
        else
            case "$action" in
                stop)
                    rc-service "$srv" stop >/dev/null 2>&1 || true
                    [[ "$(service_active_state_value "$srv" 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
                    # Not being in default runlevel is success; OpenRC returns non-zero then.
                    if rc-update show default 2>/dev/null | grep -Eq "(^|[[:space:]])${srv}([[:space:]]|$)"; then
                        rc-update del "$srv" default >/dev/null 2>&1 || return 1
                    fi
                    [[ "$(service_active_state_value "$srv" 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
                    ;;
                start)
                    rc-update add "$srv" default >/dev/null 2>&1 || die "服务 $srv 无法加入 OpenRC default runlevel。"
                    rc-service "$srv" restart >/dev/null 2>&1 || die "服务 $srv 的 OpenRC restart 命令失败。"
                    sleep 2
                    if ! rc-service "$srv" status >/dev/null 2>&1; then
                        case "$srv" in sing-box|hysteria) clean_nat_rules 2>/dev/null || true; save_firewall_rules 2>/dev/null || true ;; esac
                        die "服务 $srv 拉起失败。"
                    fi
                    record_core_family_ownership "$srv" || die "服务 $srv 已启动，但逐文件归属清单写入失败。"
                    ;;
                *) die "未知服务操作: $action" ;;
            esac
        fi
    done
}

service_unit_path() {
    local srv="$1"
    case "${INIT_SYS:-}" in
        systemd) printf '/etc/systemd/system/%s.service\n' "$srv" ;;
        openrc) printf '/etc/init.d/%s\n' "$srv" ;;
        *)
            if [[ -e "/etc/systemd/system/${srv}.service" || -L "/etc/systemd/system/${srv}.service" ]]; then
                printf '/etc/systemd/system/%s.service\n' "$srv"
            elif [[ -e "/etc/init.d/${srv}" || -L "/etc/init.d/${srv}" ]]; then
                printf '/etc/init.d/%s\n' "$srv"
            else
                return 1
            fi
            ;;
    esac
}

abox_env_claims_service() {
    local srv="$1"
    [[ -r "$ABOX_ENV" ]] || return 1
    [[ "$(stat -c %U "$ABOX_ENV" 2>/dev/null || true)" == 'root' ]] || return 1
    [[ "$(stat -c %a "$ABOX_ENV" 2>/dev/null || true)" =~ ^[0-6]00$ ]] || return 1
    (
        unset CORE MODE
        load_abox_env "$ABOX_ENV" 2>/dev/null || exit 1
        case "$srv" in
            xray) [[ "${CORE:-}" == 'xray' ]] ;;
            sing-box) [[ "${CORE:-}" == 'singbox' ]] ;;
            hysteria) [[ "${CORE:-}" == 'hysteria' || ( "${CORE:-}" == 'xray' && "${MODE:-}" == *'ALL'* ) ]] ;;
            *) return 1 ;;
        esac
    )
}

service_file_is_abox_managed() {
    local srv="$1" unit=''
    unit=$(service_unit_path "$srv" 2>/dev/null || true)
    [[ -n "$unit" && -f "$unit" && ! -L "$unit" ]] || return 1
    # Destructive ownership decisions require the exact marker.  Names,
    # standard paths, descriptions, or a stale .env file are not proof.
    grep -Fxq '# Managed by A-Box' "$unit"
}


abox_owns_service() {
    local srv="$1" unit=''
    unit=$(service_unit_path "$srv" 2>/dev/null || true)
    # Destructive ownership decisions require a concrete managed unit.  A
    # stale .env file is state, not proof that standard system paths are ours.
    [[ -n "$unit" && ( -e "$unit" || -L "$unit" ) ]] || return 1
    service_file_is_abox_managed "$srv"
}

effective_init_system() {
    if [[ "${INIT_SYS:-}" == systemd || "${INIT_SYS:-}" == openrc ]]; then
        printf '%s\n' "$INIT_SYS"
    elif systemd_available; then
        printf 'systemd\n'
    elif command -v rc-service >/dev/null 2>&1; then
        printf 'openrc\n'
    else
        printf 'unknown\n'
    fi
}

systemd_same_name_unit_path() {
    local srv="$1" path candidate
    if command -v systemctl >/dev/null 2>&1; then
        path=$(systemctl show -p FragmentPath --value "${srv}.service" 2>/dev/null || true)
        if [[ -n "$path" && ( -e "$path" || -L "$path" ) ]]; then printf '%s\n' "$path"; return 0; fi
    fi
    for candidate in "/etc/systemd/system/${srv}.service" "/run/systemd/system/${srv}.service" "/usr/local/lib/systemd/system/${srv}.service" "/usr/lib/systemd/system/${srv}.service" "/lib/systemd/system/${srv}.service"; do
        if [[ -e "$candidate" || -L "$candidate" ]]; then printf '%s\n' "$candidate"; return 0; fi
    done
    return 1
}

same_name_service_unit_path() {
    local srv="$1" init
    init=$(effective_init_system)
    case "$init" in
        systemd) systemd_same_name_unit_path "$srv" ;;
        openrc) [[ -e "/etc/init.d/${srv}" || -L "/etc/init.d/${srv}" ]] && printf '/etc/init.d/%s\n' "$srv" ;;
        *) return 1 ;;
    esac
}

core_family_paths() {
    local init
    init=$(effective_init_system) || return 1
    case "$init" in
        systemd|openrc) ;;
        *) return 1 ;;
    esac
    case "$1" in
        xray)
            printf '%s\n' /usr/local/bin/xray /usr/local/etc/xray /usr/local/share/xray
            case "$init" in systemd) printf '%s\n' /etc/systemd/system/xray.service ;; openrc) printf '%s\n' /etc/init.d/xray /etc/conf.d/xray ;; esac
            ;;
        sing-box)
            printf '%s\n' /usr/local/bin/sing-box /etc/sing-box
            case "$init" in systemd) printf '%s\n' /etc/systemd/system/sing-box.service ;; openrc) printf '%s\n' /etc/init.d/sing-box /etc/conf.d/sing-box ;; esac
            ;;
        hysteria)
            printf '%s\n' /usr/local/bin/hysteria /etc/hysteria
            case "$init" in systemd) printf '%s\n' /etc/systemd/system/hysteria.service ;; openrc) printf '%s\n' /etc/init.d/hysteria /etc/conf.d/hysteria ;; esac
            ;;
        *) return 1 ;;
    esac
}


record_core_family_ownership() {
    local srv="$1" tmp
    local -a owned_roots=()
    abox_owns_service "$srv" || return 1
    ensure_abox_dir_owned "$ABOX_DIR"
    if [[ -e "$ABOX_CORE_OWNERSHIP" || -L "$ABOX_CORE_OWNERSHIP" ]]; then
        [[ -f "$ABOX_CORE_OWNERSHIP" && ! -L "$ABOX_CORE_OWNERSHIP" ]] || return 1
        [[ "$(stat -c %u:%g "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" == 0:0 ]] || return 1
        [[ "$(stat -c %a "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" =~ ^0?600$ ]] || return 1
        [[ "$(stat -c %s "$ABOX_CORE_OWNERSHIP" 2>/dev/null || echo 99999999)" -le 4194304 ]] || return 1
    fi
    local core_paths=''
    core_paths=$(core_family_paths "$srv") || return 1
    if [[ -n "$core_paths" ]]; then
        mapfile -t owned_roots <<< "$core_paths" || return 1
    fi
    local _root
    for _root in "${owned_roots[@]}"; do
        [[ -e "$_root" || -L "$_root" ]] || continue
        path_tree_has_mountpoint "$_root" && return 1
    done
    tmp=$(umask 077; mktemp "$ABOX_DIR/.managed-core-files.XXXXXX") || return 1
    local runtime_uid runtime_gid _u _g
    IFS=$'\t' read -r _u _g < <(abox_runtime_identity "$srv") || { rm -f -- "$tmp"; return 1; }
    runtime_uid=$(id -u "$_u" 2>/dev/null) || { rm -f -- "$tmp"; return 1; }
    runtime_gid=$(getent group "$_g" 2>/dev/null | awk -F: '{print $3}')
    [[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]] || { rm -f -- "$tmp"; return 1; }
    python3 - "$srv" "$ABOX_CORE_OWNERSHIP" "$tmp" "$runtime_uid" "$runtime_gid" "${owned_roots[@]}" <<'PY_CORE_RECORD'
import hashlib, os, stat, sys
srv, old_name, out_name, runtime_uid, runtime_gid, *roots = sys.argv[1:]
runtime_uid=int(runtime_uid)
runtime_gid=int(runtime_gid)
old=[]
try:
    st=os.lstat(old_name)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o077 or st.st_size > 4*1024*1024:
        raise SystemExit(1)
    with open(old_name, 'r', encoding='utf-8') as f:
        for line in f:
            parts=line.rstrip('\n').split('\t')
            if len(parts)!=4 or parts[0] not in {'F','D'} or not parts[2].startswith('/') or '\x00' in line:
                raise SystemExit(1)
            if parts[1] != srv:
                old.append(parts)
except FileNotFoundError:
    pass
except Exception:
    raise SystemExit(1)
entries=[]

def path_is_mountpoint(path):
    path=os.path.abspath(os.path.normpath(path))
    if os.path.islink(path):
        return False
    try:
        with open('/proc/self/mountinfo','r',encoding='utf-8',errors='strict') as mf:
            for line in mf:
                fields=line.rstrip('\n').split(' ')
                if len(fields) < 5:
                    continue
                mp=__import__('re').sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1),8)), fields[4])
                mp=os.path.abspath(os.path.normpath(mp))
                if mp == path:
                    return True
    except (OSError, UnicodeError):
        raise SystemExit(1)
    return False

def add_path(path):
    try: st=os.lstat(path)
    except FileNotFoundError: return
    if path_is_mountpoint(path):
        raise SystemExit(1)
    acme = srv == 'hysteria' and (path == '/etc/hysteria/acme' or path.startswith('/etc/hysteria/acme/'))
    uid_ok = st.st_uid in ({0, runtime_uid} if acme else {0})
    gid_ok = st.st_gid in ({0, runtime_gid})
    group_write_ok = acme and path == '/etc/hysteria/acme' and st.st_uid == 0 and st.st_gid == runtime_gid and stat.S_ISDIR(st.st_mode)
    if not uid_ok or not gid_ok or stat.S_ISLNK(st.st_mode) or (st.st_mode & 0o002) or ((st.st_mode & 0o020) and not group_write_ok):
        raise SystemExit(1)
    if stat.S_ISREG(st.st_mode):
        if st.st_nlink != 1: raise SystemExit(1)
        h=hashlib.sha256()
        with open(path,'rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        entries.append(['F',srv,path,h.hexdigest()])
    elif stat.S_ISDIR(st.st_mode):
        entries.append(['D',srv,path,'-'])
        try:
            names=sorted(os.listdir(path), key=os.fsencode)
        except OSError:
            raise SystemExit(1)
        for name in names:
            add_path(os.path.join(path,name))
    else:
        raise SystemExit(1)
for root in roots: add_path(root)
all_entries=old+entries
seen=set()
with open(out_name,'w',encoding='utf-8',newline='\n') as f:
    for row in sorted(all_entries,key=lambda r:(r[1],os.fsencode(r[2]))):
        key=(row[0],row[1],row[2])
        if key in seen: raise SystemExit(1)
        seen.add(key)
        f.write('\t'.join(row)+'\n')
    f.flush(); os.fsync(f.fileno())
os.chmod(out_name,0o600)
PY_CORE_RECORD
    local rc=$?
    if (( rc != 0 )); then rm -f -- "$tmp"; return 1; fi
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$ABOX_CORE_OWNERSHIP" || { rm -f -- "$tmp"; return 1; }
}

refresh_dynamic_core_subtree_ownership() {
    local srv="$1" target="$2" tmp
    [[ "$srv" =~ ^(xray|sing-box|hysteria)$ ]] || return 1
    [[ "$target" == /etc/hysteria/acme ]] || return 1
    hysteria_acme_owner_marker_valid "$target/.A-Box-managed" || return 1
    path_tree_has_mountpoint "$target" && return 1
    [[ -f "$ABOX_CORE_OWNERSHIP" && ! -L "$ABOX_CORE_OWNERSHIP" ]] || return 1
    [[ "$(stat -c %u:%g "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" == 0:0 ]] || return 1
    [[ "$(stat -c %a "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" =~ ^0?600$ ]] || return 1
    tmp=$(umask 077; mktemp "$ABOX_DIR/.managed-core-files.dynamic.XXXXXX") || return 1
    python3 - "$srv" "$ABOX_CORE_OWNERSHIP" "$target" "$tmp" <<'PY_DYNAMIC_OWNER'
import hashlib, os, stat, sys
srv, manifest, target, out_name = sys.argv[1:]
try:
    import pwd, grp
    runtime_uid = pwd.getpwnam("abox-hysteria").pw_uid
    runtime_gid = grp.getgrnam("abox-hysteria").gr_gid
except KeyError:
    raise SystemExit(1)

def safe_stat(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    acme = srv == 'hysteria' and (path == target or path.startswith(target + '/'))
    uid_ok = st.st_uid in ({0, runtime_uid} if acme else {0})
    gid_ok = st.st_gid in ({0, runtime_gid})
    legacy_root_dir_ok = acme and path == target and st.st_uid == 0 and st.st_gid == 0 and stat.S_ISDIR(st.st_mode) and (st.st_mode & 0o077) == 0
    group_write_ok = acme and path == target and st.st_uid == 0 and st.st_gid == runtime_gid and stat.S_ISDIR(st.st_mode)
    if not uid_ok or not gid_ok or stat.S_ISLNK(st.st_mode) or (st.st_mode & 0o002) or ((st.st_mode & 0o020) and not group_write_ok) or (acme and path == target and not (group_write_ok or legacy_root_dir_ok)):
        raise SystemExit(1)
    return st

target = target.rstrip('/')
rows=[]
with open(manifest, 'r', encoding='utf-8') as f:
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)!=4 or p[0] not in {'F','D'} or p[1] not in {'xray','sing-box','hysteria'} or not p[2].startswith('/') or '\x00' in line:
            raise SystemExit(1)
        rows.append(p)
if len({(r[0],r[1],r[2]) for r in rows}) != len(rows):
    raise SystemExit(1)
# Only refresh the runtime-owned ACME subtree. Static Hysteria files keep their
# original hashes, so a user edit to config.yaml/certs still fails closed.
rows=[r for r in rows if not (r[1]==srv and (r[2]==target or r[2].startswith(target + '/')))]
entries=[]
mountpoints=set()
try:
    with open('/proc/self/mountinfo','r',encoding='utf-8',errors='strict') as mf:
        for line in mf:
            fields=line.rstrip('\n').split(' ')
            if len(fields) < 5:
                continue
            mp=__import__('re').sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1),8)), fields[4])
            mountpoints.add(os.path.abspath(os.path.normpath(mp)))
except (OSError, UnicodeError):
    raise SystemExit(1)

def is_mountpoint(path):
    return os.path.abspath(os.path.normpath(path)) in mountpoints

try:
    st=safe_stat(target)
except FileNotFoundError:
    st=None
if st is not None:
    if not stat.S_ISDIR(st.st_mode) or is_mountpoint(target):
        raise SystemExit(1)
    def add(path):
        st=safe_stat(path)
        if st is None: raise SystemExit(1)
        if stat.S_ISREG(st.st_mode):
            if st.st_nlink != 1: raise SystemExit(1)
            h=hashlib.sha256()
            with open(path,'rb') as f:
                for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
            entries.append(['F',srv,path,h.hexdigest()])
        elif stat.S_ISDIR(st.st_mode):
            if is_mountpoint(path): raise SystemExit(1)
            entries.append(['D',srv,path,'-'])
            for name in sorted(os.listdir(path), key=os.fsencode):
                add(os.path.join(path,name))
        else:
            raise SystemExit(1)
    add(target)
rows.extend(entries)
seen=set()
with open(out_name,'w',encoding='utf-8',newline='\n') as f:
    for row in sorted(rows,key=lambda r:(r[1],os.fsencode(r[2]))):
        key=(row[0],row[1],row[2])
        if key in seen: raise SystemExit(1)
        seen.add(key)
        f.write('\t'.join(row)+'\n')
    f.flush(); os.fsync(f.fileno())
os.chmod(out_name,0o600)
PY_DYNAMIC_OWNER
    local rc=$?
    if (( rc != 0 )); then rm -f -- "$tmp"; return 1; fi
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$ABOX_CORE_OWNERSHIP" || { rm -f -- "$tmp"; return 1; }
}

hysteria_acme_owner_marker_valid() {
    local marker="${1:-$HY2_ACME_OWNER_MARKER}"
    [[ -f "$marker" && ! -L "$marker" ]] || return 1
    path_owned_by_root "$marker" || return 1
    path_mode_has_no_group_other_write "$marker" || return 1
    grep -Fxq 'A-Box managed Hysteria ACME directory v1' "$marker" 2>/dev/null
}

mark_hysteria_acme_dir_managed() {
    local dir="${1:-/etc/hysteria/acme}" marker="${2:-$HY2_ACME_OWNER_MARKER}" tmp
    [[ "$dir" == /etc/hysteria/acme ]] || return 1
    [[ "$marker" == "$dir/.A-Box-managed" ]] || return 1
    [[ -d "$dir" && ! -L "$dir" ]] || return 1
    hysteria_acme_dir_runtime_permissions_valid "$dir" || return 1
    if [[ -e "$marker" || -L "$marker" ]]; then
        hysteria_acme_owner_marker_valid "$marker"
        return
    fi
    tmp=$(umask 077; mktemp "$dir/.A-Box-managed.XXXXXX") || return 1
    printf '%s\n' 'A-Box managed Hysteria ACME directory v1' > "$tmp" || { rm -f "$tmp"; return 1; }
    chown root:root "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$marker" || { rm -f "$tmp"; return 1; }
    hysteria_acme_owner_marker_valid "$marker"
}

hysteria_acme_current_tree_matches_manifest() {
    local manifest="${1:-$ABOX_CORE_OWNERSHIP}" target="${2:-/etc/hysteria/acme}"
    [[ "$target" == /etc/hysteria/acme ]] || return 1
    path_tree_has_mountpoint "$target" && return 1
    [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
    python3 - "$manifest" "$target" <<'PY_ACME_MATCH'
import hashlib, os, stat, sys
manifest, target = sys.argv[1:]
try:
    import pwd, grp
    runtime_uid = pwd.getpwnam("abox-hysteria").pw_uid
    runtime_gid = grp.getgrnam("abox-hysteria").gr_gid
except KeyError:
    raise SystemExit(1)
rows=[]
with open(manifest,'r',encoding='utf-8') as f:
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)!=4 or p[0] not in {'F','D'} or p[1] != 'hysteria' or not p[2].startswith('/') or '\x00' in line:
            continue
        rows.append(p)
recorded={r[2]:(r[0],r[3]) for r in rows if r[2]==target or r[2].startswith(target+'/')}
if recorded.get(target,('', ''))[0] != 'D':
    raise SystemExit(1)
def check(path):
    try: st=os.lstat(path)
    except FileNotFoundError: raise SystemExit(1)
    acme = path == target or path.startswith(target + '/')
    uid_ok = st.st_uid in ({0, runtime_uid} if acme else {0})
    gid_ok = st.st_gid in ({0, runtime_gid})
    legacy_root_dir_ok = acme and path == target and st.st_uid == 0 and st.st_gid == 0 and stat.S_ISDIR(st.st_mode) and (st.st_mode & 0o077) == 0
    group_write_ok = acme and path == target and st.st_uid == 0 and st.st_gid == runtime_gid and stat.S_ISDIR(st.st_mode)
    if not uid_ok or not gid_ok or stat.S_ISLNK(st.st_mode) or (st.st_mode & 0o002) or ((st.st_mode & 0o020) and not group_write_ok) or (acme and path == target and not (group_write_ok or legacy_root_dir_ok)):
        raise SystemExit(1)
    rec=recorded.get(path)
    if rec is None: raise SystemExit(1)
    typ,_=rec
    if stat.S_ISDIR(st.st_mode):
        if typ!='D': raise SystemExit(1)
        for name in sorted(os.listdir(path), key=os.fsencode):
            check(os.path.join(path,name))
    elif stat.S_ISREG(st.st_mode):
        if typ!='F' or st.st_nlink != 1: raise SystemExit(1)
        h=hashlib.sha256()
        with open(path,'rb') as f:
            for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
        if h.hexdigest() != rec[1]: raise SystemExit(1)
    else:
        raise SystemExit(1)
check(target)
# No recorded file below the subtree may disappear from the current tree.
for path,(typ,_) in recorded.items():
    if path==target: continue
    if not os.path.lexists(path): raise SystemExit(1)
raise SystemExit(0)
PY_ACME_MATCH
}

hysteria_acme_dir_runtime_permissions_valid() {
    local dir="${1:-/etc/hysteria/acme}" user group uid gid mode nlink
    [[ "$dir" == /etc/hysteria/acme && -d "$dir" && ! -L "$dir" ]] || return 1
    IFS=$'\t' read -r user group < <(abox_runtime_identity hysteria) || return 1
    uid=$(id -u "$user" 2>/dev/null) || return 1
    gid=$(getent group "$group" 2>/dev/null | awk -F: '{print $3}')
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
    [[ "$(stat -c %u:%g "$dir" 2>/dev/null || true)" == "0:$gid" ]] || return 1
    mode=$(stat -c %a "$dir" 2>/dev/null) || return 1
    nlink=$(stat -c %h "$dir" 2>/dev/null) || return 1
    [[ "$nlink" =~ ^[2-9][0-9]*$ && "$mode" =~ ^0?770$ ]] || return 1
    return 0
}

prepare_hysteria_acme_dir_ownership() {
    local dir=/etc/hysteria/acme marker=$HY2_ACME_OWNER_MARKER user group
    IFS=$'\t' read -r user group < <(abox_runtime_identity hysteria) || return 1
    ensure_abox_runtime_identity hysteria || return 1
    path_parent_chain_safe "$dir/.A-Box-managed" || return 1
    [[ ! -L /etc/hysteria && (! -e /etc/hysteria || -d /etc/hysteria) ]] || return 1
    if [[ -e "$dir" || -L "$dir" ]]; then
        [[ ! -L "$dir" && -d "$dir" ]] || return 1
        if ! hysteria_acme_owner_marker_valid "$marker" && ! hysteria_acme_current_tree_matches_manifest "$ABOX_CORE_OWNERSHIP" "$dir"; then
            return 1
        fi
        chown "root:$group" "$dir" || return 1
        chmod 770 "$dir" || return 1
        hysteria_acme_dir_runtime_permissions_valid "$dir" || return 1
        return 0
    fi
    install -d -o root -g "$group" -m 770 /etc/hysteria "$dir" || return 1
    hysteria_acme_dir_runtime_permissions_valid "$dir" || return 1
    mark_hysteria_acme_dir_managed "$dir" "$marker" || return 1
    return 0
}

remove_recorded_core_family() {
    local srv="$1" runtime_uid runtime_gid
    [[ -f "$ABOX_CORE_OWNERSHIP" && ! -L "$ABOX_CORE_OWNERSHIP" ]] || return 2
    [[ "$(stat -c %u:%g "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" == 0:0 ]] || return 1
    [[ "$(stat -c %a "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" =~ ^0?600$ ]] || return 1
    [[ "$(stat -c %s "$ABOX_CORE_OWNERSHIP" 2>/dev/null || echo 99999999)" -le 4194304 ]] || return 1
    local _u _g
    IFS=$'\t' read -r _u _g < <(abox_runtime_identity "$srv") || return 1
    runtime_uid=$(id -u "$_u" 2>/dev/null) || return 1
    runtime_gid=$(getent group "$_g" 2>/dev/null | awk -F: '{print $3}')
    [[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]] || return 1
    python3 - "$srv" "$ABOX_CORE_OWNERSHIP" "$runtime_uid" "$runtime_gid" <<'PY_CORE_REMOVE'
import hashlib, os, re, stat, sys, tempfile
srv, manifest, runtime_uid, runtime_gid=sys.argv[1:]
runtime_uid=int(runtime_uid)
runtime_gid=int(runtime_gid)
rows=[]; keep=[]; all_rows=[]
with open(manifest,'r',encoding='utf-8') as f:
    for line in f:
        p=line.rstrip('\n').split('\t')
        if len(p)!=4 or p[0] not in {'F','D'} or not p[2].startswith('/') or '\x00' in line:
            raise SystemExit(1)
        all_rows.append(p)
        (rows if p[1]==srv else keep).append(p)
if not rows: raise SystemExit(2)
if len({(r[0],r[1],r[2]) for r in all_rows}) != len(all_rows): raise SystemExit(1)
files={r[2]:r[3] for r in rows if r[0]=='F'}
dirs={r[2] for r in rows if r[0]=='D'}
expected=set(files)|dirs
# Complete fail-closed preflight before deleting anything. Every actual entry
# below a recorded directory must itself be recorded, correctly typed, root
# owned, non-link, non-writable by group/other, and (for files) hash-identical.
for path in sorted(expected, key=os.fsencode):
    try: st=os.lstat(path)
    except FileNotFoundError: continue
    def is_mountpoint(path):
        path = os.path.abspath(os.path.normpath(path))
        if os.path.islink(path):
            return False
        try:
            with open('/proc/self/mountinfo', 'r', encoding='utf-8', errors='strict') as mf:
                for line in mf:
                    fields = line.rstrip('\n').split(' ')
                    if len(fields) < 5:
                        continue
                    mp = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), fields[4])
                    mp = os.path.abspath(os.path.normpath(mp))
                    if mp == path:
                        return True
        except (OSError, UnicodeError):
            # mountinfo is authoritative for this destructive operation.
            # If it cannot be read, the caller cannot prove the path is not
            # mounted; fail closed instead of using the weaker ismount().
            raise SystemExit(4)
        return False
    if is_mountpoint(path):
        raise SystemExit(3)
    acme = srv == 'hysteria' and (path == '/etc/hysteria/acme' or path.startswith('/etc/hysteria/acme/'))
    uid_ok = st.st_uid in ({0} if not acme else {0, runtime_uid})
    gid_ok = st.st_gid in ({0, runtime_gid})
    group_write_ok = acme and path == '/etc/hysteria/acme' and st.st_uid == 0 and st.st_gid == runtime_gid and stat.S_ISDIR(st.st_mode)
    if not uid_ok or not gid_ok or stat.S_ISLNK(st.st_mode) or (st.st_mode & 0o002) or ((st.st_mode & 0o020) and not group_write_ok):
        raise SystemExit(3)
    if path in files:
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1: raise SystemExit(3)
        h=hashlib.sha256()
        try:
            with open(path,'rb') as f:
                for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        except OSError: raise SystemExit(3)
        if h.hexdigest()!=files[path]: raise SystemExit(3)
    else:
        if not stat.S_ISDIR(st.st_mode): raise SystemExit(3)
        try: names=os.listdir(path)
        except OSError: raise SystemExit(3)
        for name in names:
            child=os.path.join(path,name)
            if child not in expected: raise SystemExit(3)
# Only after the complete tree is proven exact may deletion begin.
for path in sorted(files, key=lambda p:(p.count(os.sep),len(p)), reverse=True):
    try: os.unlink(path)
    except FileNotFoundError: pass
    except OSError: raise SystemExit(1)
for path in sorted(dirs, key=lambda p:(p.count(os.sep),len(p)), reverse=True):
    try: os.rmdir(path)
    except FileNotFoundError: pass
    except OSError: raise SystemExit(1)
dirname=os.path.dirname(manifest)
fd,tmp=tempfile.mkstemp(prefix='.managed-core-files.',dir=dirname,text=True)
try:
    with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
        for row in keep: f.write('\t'.join(row)+'\n')
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.chown(tmp,0,0); os.replace(tmp,manifest)
except Exception:
    try: os.unlink(tmp)
    except OSError: pass
    raise
PY_CORE_REMOVE
}

managed_auxiliary_paths() {
    printf '%s\n' \
        /usr/local/bin/sb \
        /etc/logrotate.d/A-Box \
        /etc/fail2ban/filter.d/A-Box.conf \
        /etc/fail2ban/jail.d/A-Box.local \
        /etc/sysctl.d/99-A-Box-tune.conf \
        /etc/security/limits.d/A-Box.conf \
        /etc/modules-load.d/A-Box-bbr.conf \
        /etc/systemd/system/A-Box-firewall.service \
        /etc/init.d/A-Box-firewall
}

auxiliary_content_is_abox_managed() {
    local file="$1" logical_path="$2"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    if [[ "$logical_path" == /usr/local/bin/sb ]]; then
        grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && return 0
        grep -Fq 'exec bash /etc/ddr/A-Box.sh "$@"' "$file" 2>/dev/null || return 1
        grep -Fq 'exec sudo bash /etc/ddr/A-Box.sh "$@"' "$file" 2>/dev/null || return 1
        return 0
    fi
    grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && return 0
    # Path-specific legacy fingerprints allow a one-time migration. New files
    # always carry the exact marker above.
    case "$logical_path" in
        /etc/logrotate.d/A-Box)
            grep -Fq '/var/log/A-Box-*.log' "$file" && grep -Fq 'copytruncate' "$file"
            ;;
        /etc/fail2ban/filter.d/A-Box.conf)
            grep -Fq '[Definition]' "$file" && grep -Fq 'message authentication failed' "$file"
            ;;
        /etc/fail2ban/jail.d/A-Box.local)
            grep -Eq '^\[A-Box-(tcp|udp)\]$' "$file" && grep -Fq 'filter = A-Box' "$file"
            ;;
        /etc/sysctl.d/99-A-Box-tune.conf)
            grep -Eq '^fs\.file-max[[:space:]]*=' "$file" && grep -Eq '^net\.ipv4\.tcp_syncookies[[:space:]]*=' "$file"
            ;;
        /etc/security/limits.d/A-Box.conf)
            grep -Fxq '* soft nofile 1048576' "$file" && grep -Fxq 'root hard nofile 1048576' "$file"
            ;;
        /etc/systemd/system/A-Box-firewall.service|/etc/init.d/A-Box-firewall)
            grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null
            ;;
        /etc/ddr/traffic_monitor.sh)
            grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && grep -Fq 'TRAFFIC_LIMIT_GB' "$file" 2>/dev/null && grep -Fq 'month_bytes()' "$file" 2>/dev/null
            ;;
        /etc/ddr/geo_update.sh)
            grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && grep -Fq 'Geo' "$file" 2>/dev/null && (grep -Fq 'update_geo_ownership' "$file" 2>/dev/null || grep -Fq 'refresh_dynamic_core_subtree_ownership' "$file" 2>/dev/null)
            ;;
        /etc/ddr/socket_probe.sh)
            grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && grep -Fq '/run/A-Box-socket-probe.lock' "$file" 2>/dev/null && grep -Fq 'socket_owned_by_pid' "$file" 2>/dev/null
            ;;
        *) return 1 ;;
    esac
}

auxiliary_path_is_abox_managed() {
    auxiliary_content_is_abox_managed "$1" "$1"
}

assert_abox_auxiliary_safe() {
    local path="$1"
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    auxiliary_path_is_abox_managed "$path" && return 0
    die "拒绝覆盖非 A-Box 辅助文件: $path"
}

remove_owned_auxiliary_path() {
    local path="$1"
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    auxiliary_path_is_abox_managed "$path" || return 0
    path_tree_has_mountpoint "$path" && return 1
    rm -rf -- "$path" || return 1
    [[ ! -e "$path" && ! -L "$path" ]]
}


prune_owned_core_families_except() {
    local allowed=" $* " srv
    for srv in xray sing-box hysteria; do
        [[ "$allowed" == *" $srv "* ]] && continue
        abox_owns_service "$srv" || continue
        stop_abox_service "$srv" || die "无法停止 A-Box 托管服务: $srv"
        remove_owned_core_family "$srv" || die "无法删除 A-Box 托管核心文件: $srv"
    done
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || die '删除 A-Box 托管核心后 systemd daemon-reload 失败。'
    fi
}

list_foreign_core_conflicts() {
    local srv path unit key core_paths=''
    local -A seen=()
    for srv in "$@"; do
        abox_owns_service "$srv" && continue
        unit=$(same_name_service_unit_path "$srv" 2>/dev/null || true)
        if [[ -n "$unit" ]]; then
            key="${srv}|${unit}"
            if [[ -z "${seen[$key]:-}" ]]; then printf '%s|%s\n' "$srv" "$unit"; seen[$key]=1; fi
        fi
        core_paths=$(core_family_paths "$srv") || return 1
        while IFS= read -r path; do
            [[ -e "$path" || -L "$path" ]] || continue
            key="${srv}|${path}"
            [[ -n "${seen[$key]:-}" ]] && continue
            printf '%s|%s\n' "$srv" "$path"
            seen[$key]=1
        done <<< "$core_paths"
    done
}

assert_no_foreign_core_conflicts() {
    local conflicts
    conflicts=$(list_foreign_core_conflicts "$@") || die '无法安全枚举现有核心文件，拒绝继续部署。'
    [[ -z "$conflicts" ]] && return 0
    msg "${RED}[!] Refusing to overwrite non-A-Box core files/services:${NC}"
    while IFS='|' read -r srv path; do [[ -n "$path" ]] && msg "${RED}    ${srv}: ${path}${NC}"; done <<< "$conflicts"
    die '请先迁移或删除上述非 A-Box 安装。A-Box 不会覆盖未知归属的核心、配置或服务文件。'
}

remove_owned_core_family() {
    # $2 force_heal: only explicit callers (menu 17 / full uninstall) may pass 1.
    # Ambient ABOX_HEAL_MISSING_MANIFEST from the environment is never consulted.
    local srv="$1" force_heal="${2:-0}" path rc core_paths=''
    if ! abox_owns_service "$srv"; then
        core_paths=$(core_family_paths "$srv") || return 1
        while IFS= read -r path; do [[ -e "$path" || -L "$path" ]] && msg "${YELLOW}[!] Skip non-A-Box path: ${path}${NC}"; done <<< "$core_paths"
        return 0
    fi
    if [[ "$srv" == hysteria && -d /etc/hysteria/acme && ! -L /etc/hysteria/acme ]]; then
        if hysteria_acme_owner_marker_valid /etc/hysteria/acme/.A-Box-managed || hysteria_acme_current_tree_matches_manifest "$ABOX_CORE_OWNERSHIP" /etc/hysteria/acme; then
            prepare_hysteria_acme_dir_ownership || return 1
            refresh_dynamic_core_subtree_ownership hysteria /etc/hysteria/acme || return 1
        fi
    fi
    remove_recorded_core_family "$srv"; rc=$?
    case "$rc" in
        0) return 0 ;;
        2)
            if [[ "$force_heal" == 1 ]]; then
                msg "${YELLOW}[!] No per-file ownership manifest for ${srv}; performing unit-proven force heal of known core-family paths.${NC}"
                remove_core_family_force "$srv" || return 1
                return 0
            fi
            msg "${YELLOW}[!] No per-file ownership manifest exists for ${srv}; refusing destructive family deletion. Start/restart the managed service once to register exact files.${NC}"
            return 1
            ;;
        3)
            msg "${RED}[!] One or more ${srv} files changed after ownership registration; they were preserved instead of being deleted.${NC}"
            return 1
            ;;
        *) return 1 ;;
    esac
}

remove_all_owned_core_families() {
    # $1 force_heal forwarded to each family (1 = menu 17 / full uninstall only).
    local force_heal="${1:-0}" failed=0
    remove_owned_core_family xray "$force_heal" || failed=1
    remove_owned_core_family sing-box "$force_heal" || failed=1
    remove_owned_core_family hysteria "$force_heal" || failed=1
    (( failed == 0 ))
}


shortcut_is_abox_managed() {
    local path="${1:-/usr/local/bin/sb}"
    auxiliary_content_is_abox_managed "$path" /usr/local/bin/sb
}

assert_abox_shortcut_safe() {
    local path="${1:-/usr/local/bin/sb}"
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    shortcut_is_abox_managed "$path" && return 0
    die "拒绝覆盖非 A-Box 快捷入口: $path"
}

remove_abox_shortcut() {
    local path="${1:-/usr/local/bin/sb}"
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    if shortcut_is_abox_managed "$path"; then
        path_tree_has_mountpoint "$path" && { msg "${RED}[!] Refusing to remove mounted A-Box shortcut: ${path}${NC}"; return 1; }
        rm -f -- "$path"
    else
        msg "${YELLOW}[!] Skip non-A-Box shortcut: ${path}${NC}"
    fi
}

stop_abox_service() {
    local srv="$1"
    if abox_owns_service "$srv"; then
        service_manager stop "$srv"
    else
        msg "${YELLOW}[!] Skip non-A-Box service: ${srv}${NC}"
        return 0
    fi
}

stop_all_managed_services() {
    local failed=0
    stop_abox_service xray || failed=1
    stop_abox_service sing-box || failed=1
    stop_abox_service hysteria || failed=1
    kill_managed_residual_pids >/dev/null 2>&1 || failed=1
    (( failed == 0 ))
}

managed_service_pid() {
    local srv="$1" pid='' pidfile='' exe='' owner mode nlink
    if [[ "${INIT_SYS:-}" == 'systemd' ]] && systemd_available; then
        pid=$(systemctl show -p MainPID --value "$srv" 2>/dev/null || true)
        [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] && printf '%s\n' "$pid"
    elif [[ "${INIT_SYS:-}" == 'openrc' ]]; then
        case "$srv" in
            xray) pidfile=/run/xray.pid; exe=/usr/local/bin/xray ;;
            sing-box) pidfile=/run/sing-box.pid; exe=/usr/local/bin/sing-box ;;
            hysteria) pidfile=/run/hysteria.pid; exe=/usr/local/bin/hysteria ;;
            *) return 1 ;;
        esac
        [[ -f "$pidfile" && ! -L "$pidfile" ]] || return 1
        [[ "$(stat -c %h "$pidfile" 2>/dev/null)" == 1 ]] || return 1
        owner=$(stat -c %u "$pidfile" 2>/dev/null) || return 1
        [[ "$owner" == 0 ]] || return 1
        mode=$(stat -c %a "$pidfile" 2>/dev/null) || return 1
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) || return 1
        pid=$(tr -d '[:space:]' < "$pidfile" 2>/dev/null) || return 1
        [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" -gt 1 ]] || return 1
        pid_exe_matches "$pid" "$exe" || return 1
        printf '%s\n' "$pid"
    fi
}

managed_socket_owner_for_port() {
    local proto="$1" port="$2" srv pid exe flags
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    case "$proto" in tcp) flags='-H -nltp' ;; udp) flags='-H -nlup' ;; *) return 1 ;; esac
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        is_service_running "$srv" || continue
        pid=$(managed_service_pid "$srv" 2>/dev/null || true); pid=${pid%%$'\n'*}
        [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || continue
        case "$srv" in xray) exe=/usr/local/bin/xray ;; sing-box) exe=/usr/local/bin/sing-box ;; hysteria) exe=/usr/local/bin/hysteria ;; esac
        pid_exe_matches "$pid" "$exe" || continue
        # shellcheck disable=SC2086
        if ss $flags 2>/dev/null | awk -v p="$port" -v pid="$pid" '$4 ~ ("[:.]" p "$") && $0 ~ ("pid=" pid "([,)]|$)") {f=1} END{exit(f?0:1)}'; then
            printf '%s\n' "$srv"
            return 0
        fi
    done
    return 1
}

pid_exe_matches() {
    local pid="$1" expect="$2" exe
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    [[ "$exe" == "$expect" ]]
}

kill_managed_residual_pids() {
    local srv pid exe failed=0 i
    local -a pids=() exes=()
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        pid=$(managed_service_pid "$srv" 2>/dev/null || true)
        pid=${pid%%$'\n'*}
        [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" -gt 1 ]] || continue
        case "$srv" in
            xray) exe='/usr/local/bin/xray' ;;
            sing-box) exe='/usr/local/bin/sing-box' ;;
            hysteria) exe='/usr/local/bin/hysteria' ;;
            *) continue ;;
        esac
        pid_exe_matches "$pid" "$exe" || continue
        pids+=("$pid")
        exes+=("$exe")
    done

    (( ${#pids[@]} == 0 )) && return 0

    # Broadcast TERM to the whole managed set before waiting. This avoids the
    # previous serial 1s + optional 1s wait per process.
    for pid in "${pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 1

    # Re-check executable identity before escalating. Numeric PID reuse must
    # never turn an A-Box cleanup into a kill of an unrelated process.
    for i in "${!pids[@]}"; do
        pid="${pids[i]}"
        exe="${exes[i]}"
        if kill -0 "$pid" 2>/dev/null && pid_exe_matches "$pid" "$exe"; then
            kill -KILL "$pid" 2>/dev/null || failed=1
        fi
    done

    # Final fail-closed check: only a still-matching managed executable is a
    # cleanup failure. A reused PID belonging to another process is ignored.
    for i in "${!pids[@]}"; do
        pid="${pids[i]}"
        exe="${exes[i]}"
        if kill -0 "$pid" 2>/dev/null && pid_exe_matches "$pid" "$exe"; then
            failed=1
        fi
    done
    return "$failed"
}

is_service_running() {
    local srv=$1 state
    state=$(service_active_state_value "$srv") || return 1
    [[ "$state" == 1 ]]
}

build_status_str() {
    local status_str='' srv state unknown=0
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        if state=$(service_active_state_value "$srv" 2>/dev/null); then
            case "$state" in
                1)
                    case "$srv" in xray) status_str+="${GREEN}Xray-Core${NC} ";; sing-box) status_str+="${CYAN}Sing-Box${NC} ";; hysteria) status_str+="${GREEN}Hy2(Native)${NC} ";; esac
                    ;;
                0) ;;
                *) unknown=1 ;;
            esac
        else
            unknown=1
        fi
    done
    if [[ -n "$status_str" ]]; then
        (( unknown == 1 )) && status_str+="${YELLOW}State Unknown${NC} "
    elif (( unknown == 1 )); then
        status_str="${YELLOW}Service State Unknown${NC}"
    else
        status_str="${RED}Stack Stopped${NC}"
    fi
    printf '%s' "$status_str"
}

managed_services_active() {
    local srv state unknown=0
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        if state=$(service_active_state_value "$srv" 2>/dev/null); then
            [[ "$state" == '1' ]] && return 0
        else
            unknown=1
        fi
    done
    (( unknown == 0 )) && return 1
    return 2
}

confirm_deployment_replacement() {
    local next_core="$1" next_mode="$2" answer current="none" active_rc=1
    [[ -n "${CORE:-}" || -n "${MODE:-}" ]] && current="${CORE:-unknown}-${MODE:-unknown}"
    if [[ "$current" == 'none' ]]; then
        managed_services_active
        active_rc=$?
        case $active_rc in
            1)
                # No managed services: soft skip in fast/one-click; otherwise no prompt needed either.
                if abox_is_fast || [[ "${ABOX_QUICK_DEPLOY:-0}" == '1' ]]; then
                    msg "${YELLOW}[fast/one-click] fresh host; skip deploy confirm.${NC}"
                fi
                return 0
                ;;
            0|2) : ;;
            *) return 1 ;;
        esac
    fi
    msg "${YELLOW}[!] A-Box will stop managed services before deploying a new stack.${NC}"
    msg "Current config: ${current} | New deployment: ${next_core}-${next_mode}"
    # Critical when replacing existing config/services: never auto-yes in fast mode.
    read -r -p 'Continue deployment? [Y/N]: ' answer
    is_yes "$answer" || die '已取消部署 / Deployment canceled.'
}

service_report_state() {
    local srv="$1" unit state
    if abox_owns_service "$srv"; then
        if state=$(service_active_state_value "$srv" 2>/dev/null); then
            case "$state" in
                1) printf 'active\n' ;;
                0) printf 'inactive\n' ;;
                *) printf 'unknown\n' ;;
            esac
        else
            printf 'unknown\n'
        fi
        return 0
    fi
    unit=$(same_name_service_unit_path "$srv" 2>/dev/null || true)
    if [[ -n "$unit" ]]; then printf 'foreign/unmanaged\n'; else printf 'absent\n'; fi
}

show_status_report() {
    local init='unknown' xray_state sing_state hy2_state shortcut_state='missing' desired='UNINITIALIZED' period='' config_loaded=0
    local _status_lock_held=0
    # Best-effort non-blocking exclusive snapshot lock; proceed unlocked if busy.
    if [[ ${EUID:-0} -eq 0 ]] && command -v flock >/dev/null 2>&1 && [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
        exec 8>>"$LOCK_FILE" 2>/dev/null || true
        # Shared advisory snapshot; does not block writers that hold exclusive fd 9.
        if flock -s -n 8 2>/dev/null; then _status_lock_held=1; fi
    fi
    clear_abox_env_vars
    if load_abox_env "$ABOX_ENV" 2>/dev/null; then config_loaded=1; fi
    if systemd_available; then INIT_SYS='systemd'; init='systemd'; elif command -v rc-service >/dev/null 2>&1; then INIT_SYS='openrc'; init='openrc'; fi
    xray_state=$(service_report_state xray)
    sing_state=$(service_report_state sing-box)
    hy2_state=$(service_report_state hysteria)
    if [[ -e /usr/local/bin/sb || -L /usr/local/bin/sb ]]; then
        if shortcut_is_abox_managed /usr/local/bin/sb; then shortcut_state='managed'; else shortcut_state='foreign/unmanaged'; fi
    fi
    if (( config_loaded == 1 )) || [[ -e "$ABOX_DESIRED_STATE" || -L "$ABOX_DESIRED_STATE" ]] || abox_owns_service xray || abox_owns_service sing-box || abox_owns_service hysteria; then
        desired=$(get_desired_state 2>/dev/null || printf 'invalid')
    fi
    period=$(get_traffic_block_period 2>/dev/null || true)
    cat <<EOF_STATUS
A-Box status
Build: ${ABOX_BUILD} (${ABOX_BUILD_EPOCH})
IP preference: $(read_ip_pref 2>/dev/null || echo dual)
Init: ${init}
Config: CORE=${CORE:-} MODE=${MODE:-}
Desired state: ${desired}${period:+ (traffic period ${period})}
Services: xray=${xray_state} sing-box=${sing_state} hysteria=${hy2_state}
Shortcut: /usr/local/bin/sb=${shortcut_state}
Config file: ${ABOX_ENV}
EOF_STATUS
    if (( _status_lock_held == 1 )); then
        flock -u 8 2>/dev/null || true
        eval "exec 8>&-" 2>/dev/null || true
    fi
}

firewall_snapshot_is_abox_managed() {
    local file="${1:-}"
    firewall_state_file_safe "$file" || return 1
    grep -q '^\*' "$file" || return 1
    grep -q '^COMMIT$' "$file" || return 1
    awk '
      /^\*[^[:space:]]+$/ {next}
      /^COMMIT$/ {next}
      /^-A[[:space:]]/ && /--comment[[:space:]]+"?A-Box-/ {next}
      {exit 1}
    ' "$file"
}

remove_abox_firewall_persistence() {
    local fw_file enabled_state rc_update
    # Complete ownership preflight before any destructive service/file operation.
    for fw_file in "$ABOX_DIR/firewall_restore.sh" "$ABOX_DIR/iptables.v4" "$ABOX_DIR/iptables.v6"; do
        [[ -e "$fw_file" || -L "$fw_file" ]] || continue
        case "$fw_file" in
            "$ABOX_DIR/firewall_restore.sh") auxiliary_content_is_abox_managed "$fw_file" /etc/ddr/firewall_restore.sh || return 1 ;;
            *) firewall_snapshot_is_abox_managed "$fw_file" || return 1 ;;
        esac
    done

    if [[ -e /etc/systemd/system/A-Box-firewall.service || -L /etc/systemd/system/A-Box-firewall.service ]]; then
        [[ -f /etc/systemd/system/A-Box-firewall.service && ! -L /etc/systemd/system/A-Box-firewall.service ]] || return 1
        grep -Fxq '# Managed by A-Box' /etc/systemd/system/A-Box-firewall.service 2>/dev/null || return 1
        systemd_available || return 1
        systemctl disable --now A-Box-firewall.service >/dev/null 2>&1 || return 1
        [[ "$(service_active_state_value A-Box-firewall.service 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
        enabled_state=$(systemctl show -p UnitFileState --value A-Box-firewall.service 2>/dev/null) || return 1
        [[ "$enabled_state" == disabled ]] || return 1
        rm -f -- /etc/systemd/system/A-Box-firewall.service || return 1
        [[ ! -e /etc/systemd/system/A-Box-firewall.service && ! -L /etc/systemd/system/A-Box-firewall.service ]] || return 1
        systemctl daemon-reload >/dev/null 2>&1 || return 1
    fi

    if [[ -e /etc/init.d/A-Box-firewall || -L /etc/init.d/A-Box-firewall ]]; then
        [[ -f /etc/init.d/A-Box-firewall && ! -L /etc/init.d/A-Box-firewall ]] || return 1
        grep -Fxq '# Managed by A-Box' /etc/init.d/A-Box-firewall 2>/dev/null || return 1
        command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 || return 1
        rc-service A-Box-firewall stop >/dev/null 2>&1 || return 1
        [[ "$(service_active_state_value A-Box-firewall 2>/dev/null || printf '%s' unknown)" == 0 ]] || return 1
        if rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])A-Box-firewall([[:space:]]|$)'; then
            rc-update del A-Box-firewall default >/dev/null 2>&1 || return 1
        fi
        rc_update=$(rc-update show default 2>/dev/null) || return 1
        grep -Eq '(^|[[:space:]])A-Box-firewall([[:space:]]|$)' <<< "$rc_update" && return 1
        rm -f -- /etc/init.d/A-Box-firewall || return 1
        [[ ! -e /etc/init.d/A-Box-firewall && ! -L /etc/init.d/A-Box-firewall ]] || return 1
    fi

    # Recovery script and snapshots remain present until all owning services are
    # confirmed inactive and disabled. A failure above leaves them intact.
    rm -f -- "$ABOX_DIR/firewall_restore.sh" "$ABOX_DIR/iptables.v4" "$ABOX_DIR/iptables.v6" || return 1
    [[ ! -e "$ABOX_DIR/firewall_restore.sh" && ! -e "$ABOX_DIR/iptables.v4" && ! -e "$ABOX_DIR/iptables.v6" ]]
}

write_abox_firewall_restore_script() {
    local tmp target="$ABOX_DIR/firewall_restore.sh" uid gid mode
    install -d -m 700 "$ABOX_DIR" || return 1
    if [[ -e "$target" || -L "$target" ]]; then
        [[ -f "$target" && ! -L "$target" ]] || return 1
        uid=$(stat -c %u "$target" 2>/dev/null) || return 1
        gid=$(stat -c %g "$target" 2>/dev/null) || return 1
        mode=$(stat -c %a "$target" 2>/dev/null) || return 1
        [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 8#077) == 0 )) || return 1
        grep -Fxq '# Managed by A-Box' "$target" 2>/dev/null || return 1
    fi
    tmp=$(mktemp "$ABOX_DIR/.firewall_restore.XXXXXX") || return 1
    cat > "$tmp" <<'EOF_ABOX_FW_RESTORE'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
has_ipv6() {
    local _pref
    _pref=$(read_ip_pref 2>/dev/null || printf 'dual')
    [[ "$_pref" == 'ipv4' ]] && return 1
    ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { found=1 } END { exit !found }' && return 0
    ip -6 route show default 2>/dev/null | awk '/^default/ { found=1 } END { exit !found }' && return 0
    return 1
}
clean_chain() {
    local cmd="$1" table="$2" chain="$3" output rule
    local owned_re='--comment "?A-Box-(HY2-HOP|[0-9]+(:[0-9]+)?-(tcp|udp)(-(WL6?|DROP6?))?)"?([[:space:]]|$)'
    local -a argv=()
    if ! command -v "$cmd" >/dev/null 2>&1; then
        [[ "${cmd##*/}" == ip6tables ]] && ! has_ipv6 && return 0
        return 1
    fi
    while :; do
        output=$("$cmd" -w -t "$table" -S "$chain" 2>/dev/null) || return 1
        rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
        [[ -n "$rule" ]] || break
        rule=${rule//\"/}
        read -r -a argv <<< "$rule"
        "$cmd" -w -t "$table" "${argv[@]}" >/dev/null 2>&1 || return 1
    done
}
restore_one() {
    local file="$1" cmd="$2"
    [[ -s "$file" ]] || return 0
    if [[ "${cmd##*/}" == ip6tables-restore ]] && ! has_ipv6; then return 0; fi
    command -v "$cmd" >/dev/null 2>&1 || return 1
    grep -q '^\*' "$file" || return 0
    "$cmd" -w --noflush < "$file" >/dev/null 2>&1 || "$cmd" --noflush < "$file" >/dev/null 2>&1
}
iptables_rule_check() {
    local cmd="$1" rc; shift
    if "$cmd" -w -C "$@" 2>/dev/null; then
        return 0
    else
        rc=$?
    fi
    case "$rc" in
        1) return 1 ;;
        *) return 2 ;;
    esac
}
restore_iptables_saved_snapshot() {
    local restore_cmd="$1" snapshot="$2"
    [[ -s "$snapshot" ]] || return 1
    command -v "$restore_cmd" >/dev/null 2>&1 || return 1
    "$restore_cmd" -w < "$snapshot" >/dev/null 2>&1 || "$restore_cmd" < "$snapshot" >/dev/null 2>&1
}
reorder_one() {
    local cmd="$1" port="$2" proto="$3" wl_suffix="$4" drop_suffix="$5"
    local wl_comment="A-Box-${port}-${proto}-${wl_suffix}" drop_comment="A-Box-${port}-${proto}-${drop_suffix}"
    local wl_re="--comment[[:space:]]+\"?${wl_comment}\"?([[:space:]]|$)" drop_re="--comment[[:space:]]+\"?${drop_comment}\"?([[:space:]]|$)"
    local save_cmd="${cmd}-save" rules_output='' recovery_snapshot='' lock_file=/run/A-Box-firewall-reorder.lock lock_fd=''
    local original_rules_output='' current_rules_output='' current_line line i j n rule_no target_idx del_idx check_rc=0 mutated=0
    local -a rules=() argv=() current_lines=() delete_lines=() delete_target_indices=() delete_rule_numbers=()
    local -a original_target_lines=() original_target_positions=() expected_target_lines=()
    local -a current_target_lines=() current_foreign_lines=() original_foreign_rules=()

    command -v "$cmd" >/dev/null 2>&1 || return 0
    command -v "$save_cmd" >/dev/null 2>&1 || return 1
    if ! "$cmd" -w -S INPUT >/dev/null 2>&1; then
        if [[ "${cmd##*/}" == ip6tables ]] && ! has_ipv6; then return 0; fi
        return 1
    fi
    if iptables_rule_check "$cmd" INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP; then check_rc=0; else check_rc=$?; fi
    case "$check_rc" in 0) ;; 1) return 0 ;; *) return 1 ;; esac

    [[ -d /run && ! -L /run ]] || return 1
    if [[ -e "$lock_file" || -L "$lock_file" ]]; then
        [[ -f "$lock_file" && ! -L "$lock_file" ]] || return 1
        [[ "$(stat -c %u:%g "$lock_file" 2>/dev/null || true)" == 0:0 ]] || return 1
        local lock_mode
        lock_mode=$(stat -c %a "$lock_file" 2>/dev/null) || return 1
        if [[ "$lock_mode" =~ ^[0-7]{3,4}$ ]]; then
            (( (8#$lock_mode & 8#077) == 0 )) || return 1
        else
            return 1
        fi
    else
        (umask 077; set -o noclobber; : > "$lock_file") 2>/dev/null || return 1
    fi
    # Open+flock before chown/chmod so the critical section starts immediately.
    exec {lock_fd}>>"$lock_file" || return 1
    flock -n "$lock_fd" || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; return 1; }
    chown root:root "$lock_file" 2>/dev/null || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; rm -f -- "$lock_file"; return 1; }
    chmod 600 "$lock_file" 2>/dev/null || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; rm -f -- "$lock_file"; return 1; }
    firewall_unlock() {
        # Guard empty lock_fd: `exec >&-` would close stdout.
        if [[ "$lock_fd" =~ ^[0-9]+$ ]]; then
            eval "exec ${lock_fd}>&-" 2>/dev/null || true
        fi
        lock_fd=''
    }

    normalize_managed_rule_line() {
        local line="$1"
        line=${line//\"/}
        line=$(printf '%s\n' "$line" | sed -E 's/^(-A[[:space:]]+INPUT[[:space:]]+-p[[:space:]]+(tcp|udp))[[:space:]]+-m[[:space:]]+\2([[:space:]]|$)/\1\3/')
        printf '%s\n' "$line"
    }
    capture_firewall_views() {
        local item normalized
        current_rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || return 1
        current_target_lines=()
        current_foreign_lines=()
        while IFS= read -r item; do
            [[ "$item" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
            if [[ "$item" =~ $wl_re || "$item" =~ $drop_re ]]; then
                normalized=$(normalize_managed_rule_line "$item") || return 1
                current_target_lines+=("$normalized")
            else
                current_foreign_lines+=("$item")
            fi
        done <<< "$current_rules_output"
    }
    firewall_state_matches_expected() {
        capture_firewall_views || return 1
        [[ "$(printf '%s\n' "${current_target_lines[@]}")" == "$(printf '%s\n' "${expected_target_lines[@]}")" ]] || return 1
        [[ "$(printf '%s\n' "${current_foreign_lines[@]}")" == "$(printf '%s\n' "${original_foreign_rules[@]}")" ]]
    }
    firewall_rollback() {
        local rollback_line
        local -a rollback_lines=() rollback_argv_arr=()
        [[ -n "$recovery_snapshot" && -s "$recovery_snapshot" ]] || return 1
        capture_firewall_views || return 1
        [[ "$(printf '%s\n' "${current_target_lines[@]}")" == "$(printf '%s\n' "${expected_target_lines[@]}")" ]] || {
            printf '%s\n' "A-Box firewall rollback conflict: target rules changed outside this transaction; recovery snapshot preserved at $recovery_snapshot" >&2
            return 2
        }
        [[ "$(printf '%s\n' "${current_foreign_lines[@]}")" == "$(printf '%s\n' "${original_foreign_rules[@]}")" ]] || {
            printf '%s\n' "A-Box firewall rollback conflict: non-A-Box INPUT rules changed outside this transaction; recovery snapshot preserved at $recovery_snapshot" >&2
            return 2
        }
        rollback_lines=("${current_target_lines[@]}")
        for rollback_line in "${rollback_lines[@]}"; do
            rollback_line=${rollback_line//\"/}
            read -r -a rollback_argv_arr <<< "$rollback_line"
            [[ "${rollback_argv_arr[0]:-}" == -A && "${rollback_argv_arr[1]:-}" == INPUT ]] || return 1
            "${cmd}" -w -D INPUT "${rollback_argv_arr[@]:2}" >/dev/null 2>&1 || return 1
        done
        for ((i=${#original_target_lines[@]}-1; i>=0; i--)); do
            rollback_line=${original_target_lines[i]//\"/}
            read -r -a rollback_argv_arr <<< "$rollback_line"
            [[ "${rollback_argv_arr[0]:-}" == -A && "${rollback_argv_arr[1]:-}" == INPUT ]] || return 1
            "${cmd}" -w -I INPUT "${original_target_positions[i]}" "${rollback_argv_arr[@]:2}" >/dev/null 2>&1 || return 1
        done
        capture_firewall_views || return 1
        [[ "$current_rules_output" == "$original_rules_output" ]] || return 1
        rm -f -- "$recovery_snapshot" || return 1
        recovery_snapshot=''
        return 0
    }

    recovery_snapshot=$(mktemp /run/A-Box-firewall-recovery.XXXXXX) || { firewall_unlock; return 1; }
    if ! "$save_cmd" -t filter > "$recovery_snapshot" 2>/dev/null; then
        rm -f -- "$recovery_snapshot"
        firewall_unlock
        return 1
    fi
    original_rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || { rm -f -- "$recovery_snapshot"; firewall_unlock; return 1; }
    capture_firewall_views || { rm -f -- "$recovery_snapshot"; firewall_unlock; return 1; }
    original_target_lines=("${current_target_lines[@]}")
    original_foreign_rules=("${current_foreign_lines[@]}")
    expected_target_lines=("${original_target_lines[@]}")
    for line in "${original_target_lines[@]}"; do
        if [[ "$line" =~ $wl_re ]]; then rules+=("$line"); fi
    done
    rule_no=0
    while IFS= read -r line; do
        [[ "$line" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
        rule_no=$((rule_no + 1))
        if [[ "$line" =~ $wl_re || "$line" =~ $drop_re ]]; then
            original_target_positions+=("$rule_no")
        fi
    done <<< "$original_rules_output"
    n=${#rules[@]}

    for ((i=n-1; i>=0; i--)); do
        local expected_line="${rules[i]}"
        line=${rules[i]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || { firewall_rollback >/dev/null 2>&1 || printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; firewall_unlock; return 1; }
        firewall_state_matches_expected || {
            if (( mutated )); then
                if ! firewall_rollback; then
                    printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2
                fi
            else
                rm -f -- "$recovery_snapshot" || true
            fi
            firewall_unlock
            return 1
        }
        if ! "$cmd" -w -I INPUT 1 "${argv[@]:2}" >/dev/null 2>&1; then
            if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
            firewall_unlock
            return 1
        fi
        mutated=1
        expected_target_lines=("$expected_line" "${expected_target_lines[@]}")
    done
    local expected_drop_line="-A INPUT -p ${proto} --dport ${port} -m comment --comment ${drop_comment} -j DROP"
    firewall_state_matches_expected || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
    if ! "$cmd" -w -I INPUT "$((n + 1))" -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1; then
        if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
        firewall_unlock
        return 1
    fi
    expected_target_lines=("${expected_target_lines[@]:0:n}" "$expected_drop_line" "${expected_target_lines[@]:n}")

    rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
    current_lines=(); mapfile -t current_lines <<< "$rules_output"
    delete_lines=(); delete_target_indices=(); target_idx=0; rule_no=0
    for i in "${!current_lines[@]}"; do
        current_line="${current_lines[i]}"
        [[ "$current_line" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
        rule_no=$((rule_no + 1))
        if [[ "$current_line" =~ $wl_re || "$current_line" =~ $drop_re ]]; then
            if (( target_idx > n )); then
                delete_lines+=("$current_line")
                delete_target_indices+=("$target_idx")
                delete_rule_numbers+=("$rule_no")
            fi
            target_idx=$((target_idx + 1))
        fi
    done
    for ((j=${#delete_lines[@]}-1; j>=0; j--)); do
        firewall_state_matches_expected || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
        line=${delete_lines[j]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
        if ! "$cmd" -w -D INPUT "${delete_rule_numbers[j]}" >/dev/null 2>&1; then
            if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
            firewall_unlock
            return 1
        fi
        del_idx="${delete_target_indices[j]}"
        expected_target_lines=("${expected_target_lines[@]:0:del_idx}" "${expected_target_lines[@]:del_idx+1}")
    done
    if ! firewall_state_matches_expected; then
        if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
        firewall_unlock
        return 1
    fi
    if ! rm -f -- "$recovery_snapshot"; then
        printf '%s\n' "A-Box firewall change completed, but recovery snapshot cleanup failed; snapshot retained at $recovery_snapshot" >&2
        firewall_unlock
        return 1
    fi
    recovery_snapshot=''
    firewall_unlock
    return 0
}

reorder_policy() {
    local cmd="$1" wl_suffix="$2" drop_suffix="$3" line key port proto rules_output=''
    local -A seen=()
    command -v "$cmd" >/dev/null 2>&1 || return 0
    rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || return 1
    while IFS= read -r line; do
        if [[ "$line" =~ --comment[[:space:]]+"?A-Box-([0-9]{1,5})-(tcp|udp)-${drop_suffix}"?([[:space:]]|$) ]]; then
            port="${BASH_REMATCH[1]}"; proto="${BASH_REMATCH[2]}"; key="${port}|${proto}"
            [[ -n "${seen[$key]:-}" ]] && continue
            seen[$key]=1
            reorder_one "$cmd" "$port" "$proto" "$wl_suffix" "$drop_suffix" || return 1
        fi
    done <<< "$rules_output"
}
clean_chain iptables filter INPUT || exit 1
clean_chain iptables nat PREROUTING || exit 1
restore_one /etc/ddr/iptables.v4 iptables-restore || exit 1
reorder_policy iptables WL DROP || exit 1
if has_ipv6; then
    command -v ip6tables >/dev/null 2>&1 || exit 1
    ip6tables -w -S INPUT >/dev/null 2>&1 || exit 1
    clean_chain ip6tables filter INPUT || exit 1
    clean_chain ip6tables nat PREROUTING || exit 1
    restore_one /etc/ddr/iptables.v6 ip6tables-restore || exit 1
    reorder_policy ip6tables WL6 DROP6 || exit 1
elif command -v ip6tables >/dev/null 2>&1 && ip6tables -w -S INPUT >/dev/null 2>&1; then
    clean_chain ip6tables filter INPUT || exit 1
    clean_chain ip6tables nat PREROUTING || exit 1
    restore_one /etc/ddr/iptables.v6 ip6tables-restore || exit 1
    reorder_policy ip6tables WL6 DROP6 || exit 1
fi
EOF_ABOX_FW_RESTORE
    [[ $? -eq 0 ]] || { rm -f "$tmp"; return 1; }
    chmod 700 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$ABOX_DIR/firewall_restore.sh" || { rm -f "$tmp"; return 1; }
}

install_abox_firewall_persistence_service() {
    local tx_dir old_restore=0 old_unit=0 old_unit_path='' old_unit_enabled='' rollback_rc=0
    tx_dir=$(mktemp -d "$ABOX_DIR/.firewall-persist-tx.XXXXXX") || return 1

    if [[ -e "$ABOX_DIR/firewall_restore.sh" || -L "$ABOX_DIR/firewall_restore.sh" ]]; then
        [[ -f "$ABOX_DIR/firewall_restore.sh" && ! -L "$ABOX_DIR/firewall_restore.sh" ]] || { rm -rf -- "$tx_dir"; return 1; }
        path_owned_by_root "$ABOX_DIR/firewall_restore.sh" || { rm -rf -- "$tx_dir"; return 1; }
        path_mode_has_no_group_other_write "$ABOX_DIR/firewall_restore.sh" || { rm -rf -- "$tx_dir"; return 1; }
        grep -Fxq '# Managed by A-Box' "$ABOX_DIR/firewall_restore.sh" 2>/dev/null || { rm -rf -- "$tx_dir"; return 1; }
        cp -a -- "$ABOX_DIR/firewall_restore.sh" "$tx_dir/firewall_restore.sh" || { rm -rf -- "$tx_dir"; return 1; }
        old_restore=1
    fi

    case "${INIT_SYS:-}" in
        systemd)
            old_unit_path=/etc/systemd/system/A-Box-firewall.service
            if [[ -e "$old_unit_path" || -L "$old_unit_path" ]]; then
                assert_abox_auxiliary_safe "$old_unit_path" || { rm -rf -- "$tx_dir"; return 1; }
                cp -a -- "$old_unit_path" "$tx_dir/A-Box-firewall.service" || { rm -rf -- "$tx_dir"; return 1; }
                old_unit=1
                old_unit_enabled=$(service_enabled_state_value A-Box-firewall.service) || { rm -rf -- "$tx_dir"; return 1; }
            fi
            ;;
        openrc)
            old_unit_path=/etc/init.d/A-Box-firewall
            if [[ -e "$old_unit_path" || -L "$old_unit_path" ]]; then
                assert_abox_auxiliary_safe "$old_unit_path" || { rm -rf -- "$tx_dir"; return 1; }
                cp -a -- "$old_unit_path" "$tx_dir/A-Box-firewall" || { rm -rf -- "$tx_dir"; return 1; }
                old_unit=1
                old_unit_enabled=$(service_enabled_state_value A-Box-firewall) || { rm -rf -- "$tx_dir"; return 1; }
            fi
            ;;
        *)
            rm -rf -- "$tx_dir"
            return 1
            ;;
    esac

    firewall_persistence_rollback() {
        local fail=0
        if [[ "$old_restore" == 1 ]]; then
            cp -a -- "$tx_dir/firewall_restore.sh" "$ABOX_DIR/firewall_restore.sh" || fail=1
        else
            rm -f -- "$ABOX_DIR/firewall_restore.sh" || fail=1
        fi
        case "${INIT_SYS:-}" in
            systemd)
                if [[ "$old_unit" == 1 ]]; then
                    cp -a -- "$tx_dir/A-Box-firewall.service" "$old_unit_path" || fail=1
                else
                    systemctl disable A-Box-firewall.service >/dev/null 2>&1 || true
                    rm -f -- "$old_unit_path" || fail=1
                fi
                systemctl daemon-reload >/dev/null 2>&1 || fail=1
                if [[ "$old_unit" == 1 ]]; then
                    case "$old_unit_enabled" in
                        enabled|enabled-runtime|indirect) systemctl enable A-Box-firewall.service >/dev/null 2>&1 || fail=1 ;;
                        *) systemctl disable A-Box-firewall.service >/dev/null 2>&1 || fail=1 ;;
                    esac
                fi
                ;;
            openrc)
                if [[ "$old_unit" == 1 ]]; then
                    cp -a -- "$tx_dir/A-Box-firewall" "$old_unit_path" || fail=1
                else
                    if command -v rc-update >/dev/null 2>&1 && rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])A-Box-firewall([[:space:]]|$)'; then
                        rc-update del A-Box-firewall default >/dev/null 2>&1 || true
                    fi
                    rm -f -- "$old_unit_path" || fail=1
                fi
                if command -v rc-update >/dev/null 2>&1; then
                    if [[ "$old_unit_enabled" == 1 ]]; then
                        rc-update add A-Box-firewall default >/dev/null 2>&1 || true
                    elif rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])A-Box-firewall([[:space:]]|$)'; then
                        rc-update del A-Box-firewall default >/dev/null 2>&1 || true
                    fi
                    if [[ "$(service_enabled_state_value A-Box-firewall 2>/dev/null || printf '%s' unknown)" != "$old_unit_enabled" ]]; then
                        fail=1
                    fi
                else
                    fail=1
                fi
                ;;
        esac
        return "$fail"
    }

    if ! write_abox_firewall_restore_script; then
        firewall_persistence_rollback || rollback_rc=1
        unset -f firewall_persistence_rollback
        rm -rf -- "$tx_dir"
        (( rollback_rc == 0 )) && return 1
        return 1
    fi
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        if ! write_file_atomically_from_stdin /etc/systemd/system/A-Box-firewall.service 644 <<'EOF_ABOX_FW_UNIT'
# Managed by A-Box
[Unit]
Description=A-Box isolated firewall rule restore
After=network-pre.target iptables.service ip6tables.service nftables.service ufw.service firewalld.service
Before=xray.service sing-box.service hysteria.service

[Service]
Type=oneshot
ExecStart=/etc/ddr/firewall_restore.sh
NoNewPrivileges=true
PrivateTmp=true
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_ABOX_FW_UNIT
        then
            firewall_persistence_rollback || rollback_rc=1
            unset -f firewall_persistence_rollback
            rm -rf -- "$tx_dir"
            return 1
        fi
        if ! systemctl daemon-reload >/dev/null 2>&1 || ! systemctl enable A-Box-firewall.service >/dev/null 2>&1; then
            firewall_persistence_rollback || rollback_rc=1
            unset -f firewall_persistence_rollback
            rm -rf -- "$tx_dir"
            return 1
        fi
    else
        if ! write_file_atomically_from_stdin /etc/init.d/A-Box-firewall 755 <<'EOF_ABOX_FW_OPENRC'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box isolated firewall rule restore"
command="/etc/ddr/firewall_restore.sh"
command_background="no"
depend() { need net; after iptables ip6tables nftables ufw firewalld; before xray sing-box hysteria; }
EOF_ABOX_FW_OPENRC
        then
            firewall_persistence_rollback || rollback_rc=1
            unset -f firewall_persistence_rollback
            rm -rf -- "$tx_dir"
            return 1
        fi
        if ! chmod 755 /etc/init.d/A-Box-firewall || ! rc-update add A-Box-firewall default >/dev/null 2>&1; then
            firewall_persistence_rollback || rollback_rc=1
            unset -f firewall_persistence_rollback
            rm -rf -- "$tx_dir"
            return 1
        fi
    fi

    unset -f firewall_persistence_rollback
    rm -rf -- "$tx_dir"
    return 0
}

save_firewall_rules() {
    local tmp4 tmp6 backend target4="$ABOX_DIR/iptables.v4" target6="$ABOX_DIR/iptables.v6"
    local backup4='' backup6='' restore_failed=0
    backend=$(firewall_backend) || return 1
    case "$backend" in
        ufw|firewalld)
            remove_abox_firewall_persistence || return 1
            return 0
            ;;
    esac
    command -v iptables-save >/dev/null 2>&1 || return 1
    install -d -m 700 "$ABOX_DIR" || return 1

    # Refuse unsafe existing persistence files, then snapshot them before the
    # two-file replacement so a later failure cannot leave a mixed v4/v6 state.
    for target in "$target4" "$target6"; do
        if [[ -L "$target" ]]; then return 1; fi
        if [[ -e "$target" ]]; then
            [[ -f "$target" ]] || return 1
            [[ "$(stat -c %h "$target" 2>/dev/null || echo 0)" == 1 ]] || return 1
        fi
    done
    if [[ -f "$target4" ]]; then
        backup4=$(mktemp "$ABOX_DIR/.iptables.v4.rollback.XXXXXX") || return 1
        rm -f -- "$backup4"
        cp -a -- "$target4" "$backup4" || { rm -f -- "$backup4"; return 1; }
    fi
    if [[ -f "$target6" ]]; then
        backup6=$(mktemp "$ABOX_DIR/.iptables.v6.rollback.XXXXXX") || { rm -f -- "$backup4"; return 1; }
        rm -f -- "$backup6"
        cp -a -- "$target6" "$backup6" || { rm -f -- "$backup4" "$backup6"; return 1; }
    fi

    tmp4=$(mktemp "$ABOX_DIR/.iptables.v4.XXXXXX") || { rm -f -- "$backup4" "$backup6"; return 1; }
    tmp6=$(mktemp "$ABOX_DIR/.iptables.v6.XXXXXX") || { rm -f -- "$tmp4" "$backup4" "$backup6"; return 1; }
    iptables-save > "${tmp4}.all" 2>/dev/null || { rm -f "$tmp4" "$tmp6" "${tmp4}.all" "$backup4" "$backup6"; return 1; }
    extract_abox_iptables_rules "${tmp4}.all" all > "$tmp4" || { rm -f "$tmp4" "$tmp6" "${tmp4}.all" "$backup4" "$backup6"; return 1; }
    rm -f "${tmp4}.all"
    if command -v ip6tables-save >/dev/null 2>&1; then
        if ip6tables-save > "${tmp6}.all" 2>/dev/null; then
            extract_abox_iptables_rules "${tmp6}.all" all > "$tmp6" || { rm -f "$tmp4" "$tmp6" "${tmp6}.all" "$backup4" "$backup6"; return 1; }
            rm -f "${tmp6}.all"
        elif ! has_ipv6; then
            # A present userspace binary does not prove that the kernel IPv6
            # firewall backend is enabled. Ignore only a failed v6 query when
            # no global IPv6 address/default route is available.
            rm -f "${tmp6}.all"
            : > "$tmp6"
        else
            rm -f "$tmp4" "$tmp6" "${tmp6}.all" "$backup4" "$backup6"
            return 1
        fi
    else
        if has_ipv6; then
            rm -f -- "$tmp4" "$tmp6" "$backup4" "$backup6"
            return 1
        fi
        : > "$tmp6"
    fi
    chmod 600 "$tmp4" "$tmp6" || { rm -f "$tmp4" "$tmp6" "$backup4" "$backup6"; return 1; }
    if ! grep -q '^\*' "$tmp4" && ! grep -q '^\*' "$tmp6"; then
        rm -f "$tmp4" "$tmp6" "$backup4" "$backup6"
        remove_abox_firewall_persistence || return 1
        return 0
    fi

    if ! mv -f -- "$tmp4" "$target4"; then
        rm -f -- "$tmp4" "$tmp6" "$backup4" "$backup6"
        return 1
    fi
    if ! mv -f -- "$tmp6" "$target6"; then
        if [[ -n "$backup4" ]]; then cp -a -- "$backup4" "$target4" || restore_failed=1; else rm -f -- "$target4" || restore_failed=1; fi
        rm -f -- "$tmp6" "$backup4" "$backup6"
        (( restore_failed == 0 )) || return 1
        return 1
    fi
    if ! install_abox_firewall_persistence_service; then
        if [[ -n "$backup4" ]]; then cp -a -- "$backup4" "$target4" || restore_failed=1; else rm -f -- "$target4" || restore_failed=1; fi
        if [[ -n "$backup6" ]]; then cp -a -- "$backup6" "$target6" || restore_failed=1; else rm -f -- "$target6" || restore_failed=1; fi
        rm -f -- "$backup4" "$backup6"
        (( restore_failed == 0 )) || return 1
        return 1
    fi
    rm -f -- "$backup4" "$backup6"
    return 0
}

warn_ss_whitelist_native_firewall_reload() {
    local backend
    backend=$(firewall_backend)
    [[ "$backend" == 'iptables' ]] && return 0
    msg "${YELLOW}[!] SS-2022 whitelist/DROP rules use iptables/ip6tables. If ${backend} is externally reloaded, reapply whitelist mode from Menu 19.${NC}"
}

ufw_is_active() {
    command -v ufw >/dev/null 2>&1 || return 1
    LC_ALL=C ufw status 2>/dev/null | awk 'tolower($0) ~ /^status:[[:space:]]*active/ { found=1 } END { exit !found }'
}

firewall_backend() {
    if ufw_is_active; then printf 'ufw\n'; elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then printf 'firewalld\n'; else printf 'iptables\n'; fi
}

native_firewall_record_valid() {
    local line="$1" backend spec proto scope zone extra normalized
    IFS='|' read -r backend spec proto scope zone extra <<< "$line"
    [[ -z "$extra" ]] || return 1
    normalized=$(normalize_port_spec "$spec") || return 1
    [[ "$normalized" == "$spec" ]] || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    case "$backend:$scope" in
        ufw:rule) [[ -z "$zone" ]] || return 1 ;;
        firewalld:runtime|firewalld:permanent)
            if [[ -n "$zone" ]]; then
                [[ "$zone" =~ ^[A-Za-z0-9_.:@+-]+$ ]] || return 1
            fi
            ;;
        *) return 1 ;;
    esac
    return 0
}

firewall_state_file_safe() {
    local file="${1:-$ABOX_FW_STATE}" uid gid mode
    [[ -f "$file" && ! -L "$file" ]] || return 1
    uid=$(stat -c %u "$file" 2>/dev/null) || return 1
    gid=$(stat -c %g "$file" 2>/dev/null) || return 1
    mode=$(stat -c %a "$file" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 ))
}

validate_native_firewall_state_file() {
    local file="${1:-$ABOX_FW_STATE}" line
    firewall_state_file_safe "$file" || return 1
    declare -A seen=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -n "$line" ]] || continue
        native_firewall_record_valid "$line" || return 1
        [[ -z "${seen[$line]:-}" ]] || return 1
        seen[$line]=1
    done < "$file"
}

record_native_firewall_rule() {
    local backend="$1" spec proto="$3" scope="${4:-}" record tmp zone=''
    spec=$(normalize_port_spec "$2") || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    case "$backend:$scope" in
        ufw:rule) ;;
        firewalld:runtime|firewalld:permanent)
            zone=$(firewalld_zone_for_abox) || return 1
            ;;
        *) return 1 ;;
    esac
    if [[ -n "$zone" ]]; then
        record="${backend}|${spec}|${proto}|${scope}|${zone}"
    else
        record="${backend}|${spec}|${proto}|${scope}"
    fi
    native_firewall_record_valid "$record" || return 1
    install -d -o root -g root -m 700 "$ABOX_DIR" || return 1
    if [[ -e "$ABOX_FW_STATE" || -L "$ABOX_FW_STATE" ]]; then
        validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    fi
    tmp=$(mktemp "$ABOX_DIR/.firewall-native.XXXXXX") || return 1
    if [[ -f "$ABOX_FW_STATE" ]]; then
        cat "$ABOX_FW_STATE" > "$tmp" || { rm -f -- "$tmp"; return 1; }
    fi
    grep -qxF "$record" "$tmp" 2>/dev/null || printf '%s\n' "$record" >> "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$ABOX_FW_STATE" || { rm -f -- "$tmp"; return 1; }
}

ufw_global_rule_numbers() {
    local spec proto="$2" owned_only="${3:-0}" target output line number body rest expected_comment
    spec=$(normalize_port_spec "$1") || return 2
    [[ "$proto" == tcp || "$proto" == udp ]] || return 2
    target="${spec}/${proto}"
    expected_comment="# A-Box-${spec}-${proto}"
    command -v ufw >/dev/null 2>&1 || return 2
    output=$(LC_ALL=C ufw status numbered 2>/dev/null) || return 2
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\[[[:space:]]*([0-9]+)\][[:space:]]+(.*)$ ]] || continue
        number="${BASH_REMATCH[1]}"
        body="${BASH_REMATCH[2]}"
        if [[ "$body" == "$target"* ]]; then
            rest="${body#"$target"}"
        else
            continue
        fi
        rest="${rest# (v6)}"
        rest="${rest#"${rest%%[![:space:]]*}"}"
        case "$rest" in
            'ALLOW IN '*) rest="${rest#ALLOW IN }" ;;
            'LIMIT IN '*) rest="${rest#LIMIT IN }" ;;
            *) continue ;;
        esac
        rest="${rest#"${rest%%[![:space:]]*}"}"
        [[ "$rest" =~ ^Anywhere([[:space:]]+\(v6\))?([[:space:]]+#.*)?$ ]] || continue
        if [[ "$owned_only" == 1 ]]; then
            [[ "$rest" == *"$expected_comment" ]] || continue
            [[ "${rest##*# }" == "A-Box-${spec}-${proto}" ]] || continue
        fi
        printf '%s\n' "$number"
    done <<< "$output"
}

ufw_rule_state() {
    local numbers rc
    numbers=$(ufw_global_rule_numbers "$1" "$2" 0); rc=$?
    [[ "$rc" == 0 ]] || return "$rc"
    [[ -n "$numbers" ]]
}

ufw_rule_exists() { ufw_rule_state "$1" "$2"; }

ufw_owned_rule_exists() {
    local numbers rc
    numbers=$(ufw_global_rule_numbers "$1" "$2" 1); rc=$?
    [[ "$rc" == 0 ]] || return "$rc"
    [[ -n "$numbers" ]]
}

ufw_delete_owned_rules() {
    local spec proto="$2" numbers
    spec=$(normalize_port_spec "$1") || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    numbers=$(ufw_global_rule_numbers "$spec" "$proto" 1) || return 1
    [[ -n "$numbers" ]] || return 0
    # Delete by the full rule specification rather than mutable display indices.
    # UFW can match the original comment and removes the generic v4/v6 rule pair
    # as one logical rule; a concurrent insertion cannot redirect deletion to a
    # different numbered rule.
    ufw --force delete allow proto "$proto" from any to any port "$spec" comment "A-Box-${spec}-${proto}" >/dev/null 2>&1 || return 1
    ! ufw_owned_rule_exists "$spec" "$proto"
}

firewalld_zone_for_abox() {
    local zone=''
    if [[ -n "${INGRESS_IF:-}" ]] && command -v firewall-cmd >/dev/null 2>&1; then
        zone=$(firewall-cmd --get-zone-of-interface="$INGRESS_IF" 2>/dev/null || true)
        [[ -n "$zone" && "$zone" != 'no zone' ]] && { printf '%s\n' "$zone"; return 0; }
    fi
    zone=$(firewall-cmd --get-default-zone 2>/dev/null || true)
    [[ -n "$zone" && "$zone" != 'no zone' ]] || return 1
    printf '%s\n' "$zone"
}

firewalld_cmd() {
    local zone=''
    zone=$(firewalld_zone_for_abox 2>/dev/null || true)
    if [[ -n "$zone" ]]; then command firewall-cmd --zone="$zone" "$@"; else command firewall-cmd "$@"; fi
}

firewalld_port_state() {
    local spec proto="$2" scope="${3:-runtime}" zone="${4:-}" fw_spec rc
    spec=$(normalize_port_spec "$1") || return 2
    [[ "$proto" == tcp || "$proto" == udp ]] || return 2
    fw_spec=$(port_spec_for_firewalld "$spec") || return 2
    command -v firewall-cmd >/dev/null 2>&1 || return 2
    firewall-cmd --state >/dev/null 2>&1 || return 2
    if [[ -n "$zone" ]]; then
        if [[ "$scope" == permanent ]]; then
            command firewall-cmd --zone="$zone" --permanent --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
        else
            command firewall-cmd --zone="$zone" --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
        fi
    elif [[ "$scope" == permanent ]]; then
        firewalld_cmd --permanent --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
    else
        firewalld_cmd --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
    fi
    rc=$?
    case "$rc" in 0) return 0 ;; 1) return 1 ;; *) return 2 ;; esac
}

remove_native_firewall_rules() {
    [[ ! -e "$ABOX_FW_STATE" && ! -L "$ABOX_FW_STATE" ]] && return 0
    validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    local backend spec proto scope zone extra fw_spec any_failed=0 record_failed tmp
    tmp=$(mktemp "$ABOX_DIR/.firewall-native.remaining.XXXXXX") || return 1
    while IFS='|' read -r backend spec proto scope zone extra; do
        [[ -n "$backend" ]] || continue
        record_failed=0
        case "$backend" in
            ufw)
                if ! command -v ufw >/dev/null 2>&1; then
                    record_failed=1
                elif ! ufw_delete_owned_rules "$spec" "$proto"; then
                    record_failed=1
                fi
                ;;
            firewalld)
                fw_spec=$(port_spec_for_firewalld "$spec" 2>/dev/null || true)
                if [[ -z "$fw_spec" ]] || ! command -v firewall-cmd >/dev/null 2>&1 || ! firewall-cmd --state >/dev/null 2>&1; then
                    record_failed=1
                elif [[ "$scope" == runtime ]]; then
                    if [[ -n "$zone" ]]; then command firewall-cmd --zone="$zone" --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true; else firewalld_cmd --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true; fi
                    firewalld_port_state "$spec" "$proto" runtime "$zone"
                    [[ $? == 1 ]] || record_failed=1
                elif [[ "$scope" == permanent ]]; then
                    if [[ -n "$zone" ]]; then command firewall-cmd --zone="$zone" --permanent --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true; else firewalld_cmd --permanent --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true; fi
                    firewalld_port_state "$spec" "$proto" permanent "$zone"
                    [[ $? == 1 ]] || record_failed=1
                else
                    record_failed=1
                fi
                ;;
            *) record_failed=1 ;;
        esac
        if [[ "$record_failed" == 1 ]]; then
            if [[ -n "$zone" ]]; then
                printf '%s|%s|%s|%s|%s\n' "$backend" "$spec" "$proto" "$scope" "$zone" >> "$tmp"
            else
                printf '%s|%s|%s|%s\n' "$backend" "$spec" "$proto" "$scope" >> "$tmp"
            fi
            any_failed=1
        fi
    done < "$ABOX_FW_STATE"
    chown root:root "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 1; }
    if [[ "$any_failed" == 1 ]]; then
        mv -f -- "$tmp" "$ABOX_FW_STATE" || { rm -f -- "$tmp"; return 1; }
        return 1
    fi
    rm -f -- "$tmp" "$ABOX_FW_STATE"
    return 0
}

forget_native_firewall_rule() {
    local raw_spec="$1" proto="$2" target_backend="$3" spec tmp kept=0 rec_backend rec_spec rec_proto rec_scope rec_zone _rec_extra
    spec=$(normalize_port_spec "$raw_spec") || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    [[ "$target_backend" == ufw || "$target_backend" == firewalld || "$target_backend" == iptables ]] || return 1
    [[ ! -e "$ABOX_FW_STATE" && ! -L "$ABOX_FW_STATE" ]] && return 0
    validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    tmp=$(mktemp "$ABOX_DIR/.firewall-native.forget.XXXXXX") || return 1
    while IFS='|' read -r rec_backend rec_spec rec_proto rec_scope rec_zone _rec_extra; do
        [[ "$rec_backend" == "$target_backend" && "$rec_spec" == "$spec" && "$rec_proto" == "$proto" ]] && continue
        if [[ -n "$rec_zone" ]]; then
            printf '%s|%s|%s|%s|%s\n' "$rec_backend" "$rec_spec" "$rec_proto" "$rec_scope" "$rec_zone" >> "$tmp"
        else
            printf '%s|%s|%s|%s\n' "$rec_backend" "$rec_spec" "$rec_proto" "$rec_scope" >> "$tmp"
        fi
        kept=1
    done < "$ABOX_FW_STATE"
    chown root:root "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 1; }
    if (( kept == 1 )); then
        mv -f -- "$tmp" "$ABOX_FW_STATE" || { rm -f -- "$tmp"; return 1; }
    else
        rm -f -- "$tmp" "$ABOX_FW_STATE" || return 1
    fi
    return 0
}

remove_abox_native_firewall_rule() {
    local raw_spec="$1" proto="$2" spec backend fw_spec failed=0 record
    spec=$(normalize_port_spec "$raw_spec") || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    backend=$(firewall_backend) || return 1
    case "$backend" in
        ufw)
            if [[ -e "$ABOX_FW_STATE" || -L "$ABOX_FW_STATE" ]]; then
                validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
                while IFS='|' read -r _backend _spec _proto _scope _zone _extra; do
                    [[ "$_spec" == "$spec" && "$_proto" == "$proto" && "$_backend" == ufw ]] || continue
                    [[ "$_scope" == rule && -z "$_zone" && -z "$_extra" ]] || return 1
                    ufw_delete_owned_rules "$spec" "$proto" || return 1
                    break
                done < "$ABOX_FW_STATE"
                forget_native_firewall_rule "$spec" "$proto" ufw || return 1
            fi
            return 0
            ;;
        firewalld)
            [[ -e "$ABOX_FW_STATE" || -L "$ABOX_FW_STATE" ]] || return 0
            validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
            fw_spec=$(port_spec_for_firewalld "$spec") || return 1
            while IFS='|' read -r _backend _spec _proto _scope _zone _extra; do
                [[ "$_spec" == "$spec" && "$_proto" == "$proto" && "$_backend" == firewalld ]] || continue
                [[ "$_scope" == runtime || "$_scope" == permanent ]] || return 1
                firewall-cmd --state >/dev/null 2>&1 || return 1
                if [[ "$_scope" == runtime ]]; then
                    if [[ -n "$_zone" ]]; then
                        firewall-cmd --zone="$_zone" --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    else
                        firewalld_cmd --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    fi
                    firewalld_port_state "$spec" "$proto" runtime "$_zone"
                    [[ $? == 1 ]] || failed=1
                else
                    if [[ -n "$_zone" ]]; then
                        firewall-cmd --zone="$_zone" --permanent --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    else
                        firewalld_cmd --permanent --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    fi
                    firewalld_port_state "$spec" "$proto" permanent "$_zone"
                    [[ $? == 1 ]] || failed=1
                fi
            done < "$ABOX_FW_STATE"
            (( failed == 0 )) || return 1
            forget_native_firewall_rule "$spec" "$proto" firewalld || return 1
            ;;
        iptables)
            local comment="A-Box-${spec}-${proto}" cmd check_rc
            for cmd in "$IPT" "$IPT6"; do
                [[ "$cmd" == "$IPT" || -x "$cmd" || -n "$(command -v "$cmd" 2>/dev/null)" ]] || continue
                [[ "$cmd" == "$IPT6" ]] && { command -v ip6tables >/dev/null 2>&1 || continue; "$IPT6" -w -S INPUT >/dev/null 2>&1 || continue; }
                while :; do
                    if iptables_rule_check "$cmd" INPUT -p "$proto" --dport "$spec" -m comment --comment "$comment" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                    case "$check_rc" in
                        0) "$cmd" -w -D INPUT -p "$proto" --dport "$spec" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || return 1 ;;
                        1) break ;;
                        *) return 1 ;;
                    esac
                done
                iptables_rule_check "$cmd" INPUT -p "$proto" --dport "$spec" -m comment --comment "$comment" -j ACCEPT
                [[ $? == 1 ]] || return 1
            done
            ;;
        *) return 1 ;;
    esac
    if [[ -e "$ABOX_FW_STATE" || -L "$ABOX_FW_STATE" ]]; then
        validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    fi
    return 0
}

apply_native_firewall_rules_from_state() {
    [[ ! -e "$ABOX_FW_STATE" && ! -L "$ABOX_FW_STATE" ]] && return 0
    validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    local backend spec proto scope zone extra fw_spec failed=0
    while IFS='|' read -r backend spec proto scope zone extra; do
        [[ -n "$backend" ]] || continue
        case "$backend" in
            ufw)
                if ! command -v ufw >/dev/null 2>&1; then failed=1; continue; fi
                if ufw_owned_rule_exists "$spec" "$proto"; then
                    :
                elif ufw_rule_exists "$spec" "$proto"; then
                    # A foreign equivalent rule must never be adopted as A-Box-owned.
                    failed=1
                    continue
                else
                    ufw allow proto "$proto" from any to any port "$spec" comment "A-Box-${spec}-${proto}" >/dev/null 2>&1 || { failed=1; continue; }
                    ufw_owned_rule_exists "$spec" "$proto" || { failed=1; continue; }
                fi
                ;;
            firewalld)
                fw_spec=$(port_spec_for_firewalld "$spec") || { failed=1; continue; }
                command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 || { failed=1; continue; }
                if [[ "$scope" == runtime ]]; then
                    firewalld_port_state "$spec" "$proto" runtime "$zone"
                    case $? in
                        0) : ;;
                        1) if [[ -n "$zone" ]]; then command firewall-cmd --zone="$zone" --add-port="${fw_spec}/${proto}" >/dev/null 2>&1; else firewalld_cmd --add-port="${fw_spec}/${proto}" >/dev/null 2>&1; fi || { failed=1; continue; } ;;
                        *) failed=1; continue ;;
                    esac
                    firewalld_port_state "$spec" "$proto" runtime "$zone" || failed=1
                elif [[ "$scope" == permanent ]]; then
                    firewalld_port_state "$spec" "$proto" permanent "$zone"
                    case $? in
                        0) : ;;
                        1) if [[ -n "$zone" ]]; then command firewall-cmd --zone="$zone" --permanent --add-port="${fw_spec}/${proto}" >/dev/null 2>&1; else firewalld_cmd --permanent --add-port="${fw_spec}/${proto}" >/dev/null 2>&1; fi || { failed=1; continue; } ;;
                        *) failed=1; continue ;;
                    esac
                    firewalld_port_state "$spec" "$proto" permanent "$zone" || failed=1
                else
                    failed=1
                fi
                ;;
            *) failed=1 ;;
        esac
    done < "$ABOX_FW_STATE"
    (( failed == 0 ))
}

iptables_rule_check() {
    local cmd="$1" rc; shift
    if "$cmd" -w -C "$@" 2>/dev/null; then
        return 0
    else
        rc=$?
    fi
    case "$rc" in
        1) return 1 ;;
        *) return 2 ;;
    esac
}
restore_iptables_saved_snapshot() {
    local restore_cmd="$1" snapshot="$2"
    [[ -s "$snapshot" ]] || return 1
    command -v "$restore_cmd" >/dev/null 2>&1 || return 1
    "$restore_cmd" -w < "$snapshot" >/dev/null 2>&1 || "$restore_cmd" < "$snapshot" >/dev/null 2>&1
}

allowPort() {
    local raw_port="$1" type="${2:-tcp}" backend spec fw_spec runtime=0 permanent=0 added_runtime=0
    spec=$(normalize_port_spec "$raw_port") || die "端口或端口范围非法: $raw_port"
    [[ "$type" == tcp || "$type" == udp ]] || die "协议非法: $type"
    backend=$(firewall_backend)
    case "$backend" in
        ufw)
            if ufw_owned_rule_exists "$spec" "$type"; then
                record_native_firewall_rule ufw "$spec" "$type" rule || die 'UFW 已有托管规则但归属状态记录失败。'
            elif ufw_rule_exists "$spec" "$type"; then
                msg "${YELLOW}[!] ${spec}/${type} 已由非 A-Box UFW 全局规则放行；保留该规则且不声明所有权。${NC}"
            else
                ufw allow proto "$type" from any to any port "$spec" comment "A-Box-${spec}-${type}" >/dev/null 2>&1 || die "UFW 防火墙放行失败或当前 UFW 不支持规则评论: ${spec}/${type}"
                if ! ufw_owned_rule_exists "$spec" "$type"; then
                    ufw_delete_owned_rules "$spec" "$type" >/dev/null 2>&1 || true
                    die "UFW 规则后置归属验证失败: ${spec}/${type}"
                fi
                if ! record_native_firewall_rule ufw "$spec" "$type" rule; then
                    ufw_delete_owned_rules "$spec" "$type" >/dev/null 2>&1 || true
                    die "UFW 规则已添加但归属状态记录失败，已尝试精确回滚: ${spec}/${type}"
                fi
            fi
            return 0
            ;;
        firewalld)
            fw_spec=$(port_spec_for_firewalld "$spec") || die "firewalld 端口范围转换失败: $spec"
            firewalld_port_state "$spec" "$type" runtime
            case $? in 0) runtime=1 ;; 1) runtime=0 ;; *) die 'firewalld runtime 查询失败。' ;; esac
            firewalld_port_state "$spec" "$type" permanent
            case $? in 0) permanent=1 ;; 1) permanent=0 ;; *) die 'firewalld permanent 查询失败。' ;; esac
            if [[ "$runtime" == 0 ]]; then
                firewalld_cmd --add-port="${fw_spec}/${type}" >/dev/null 2>&1 || die "firewalld runtime 放行失败: ${fw_spec}/${type}"
                added_runtime=1
                record_native_firewall_rule firewalld "$spec" "$type" runtime || { firewalld_cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true; die 'firewalld runtime 规则归属记录失败。'; }
            fi
            if [[ "$permanent" == 0 ]]; then
                if ! firewalld_cmd --permanent --add-port="${fw_spec}/${type}" >/dev/null 2>&1; then
                    [[ "$added_runtime" == 1 ]] && firewalld_cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    die "firewalld permanent 放行失败: ${fw_spec}/${type}"
                fi
                if ! record_native_firewall_rule firewalld "$spec" "$type" permanent; then
                    firewalld_cmd --permanent --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    [[ "$added_runtime" == 1 ]] && firewalld_cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    die 'firewalld permanent 规则归属记录失败。'
                fi
            fi
            firewalld_port_state "$spec" "$type" runtime || die 'firewalld runtime 后置验证失败。'
            firewalld_port_state "$spec" "$type" permanent || die 'firewalld permanent 后置验证失败。'
            return 0
            ;;
    esac
    local check_rc=0
    if iptables_rule_check "$IPT" INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
    case "$check_rc" in
        0) ;;
        1) $IPT -w -I INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv4 防火墙放行失败: ${spec}/${type}" ;;
        *) die "无法检查 IPv4 防火墙规则: ${spec}/${type}" ;;
    esac
    if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
        if iptables_rule_check "$IPT6" INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
        case "$check_rc" in
            0) ;;
            1) $IPT6 -w -I INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv6 防火墙放行失败: ${spec}/${type}" ;;
            *) die "无法检查 IPv6 防火墙规则: ${spec}/${type}" ;;
        esac
    fi
}

remove_ss_open_accept_rules() {
    local proto failed=0 comment check_rc
    [[ -n "${SS_PORT:-}" ]] || return 0
    for proto in tcp udp; do
        comment="A-Box-${SS_PORT}-${proto}"
        while :; do
            if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
            case "$check_rc" in
                0) ;;
                1) break ;;
                *) failed=1; break ;;
            esac
            $IPT -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || { failed=1; break; }
        done
        if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
        [[ "$check_rc" == 1 ]] || failed=1
        if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
            while :; do
                if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                case "$check_rc" in
                    0) ;;
                    1) break ;;
                    *) failed=1; break ;;
                esac
                $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || { failed=1; break; }
            done
            if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
            [[ "$check_rc" == 1 ]] || failed=1
        fi
    done
    (( failed == 0 ))
}

reorder_ss_whitelist_rules_one() {
    local cmd="$1" port="$2" proto="$3" wl_suffix="$4" drop_suffix="$5"
    local wl_comment="A-Box-${port}-${proto}-${wl_suffix}" drop_comment="A-Box-${port}-${proto}-${drop_suffix}"
    local wl_re="--comment[[:space:]]+\"?${wl_comment}\"?([[:space:]]|$)" drop_re="--comment[[:space:]]+\"?${drop_comment}\"?([[:space:]]|$)"
    local save_cmd="${cmd}-save" rules_output='' recovery_snapshot='' lock_file=/run/A-Box-firewall-reorder.lock lock_fd=''
    local original_rules_output='' current_rules_output='' current_line line i j n rule_no target_idx del_idx check_rc=0 mutated=0
    local -a rules=() argv=() current_lines=() delete_lines=() delete_target_indices=() delete_rule_numbers=()
    local -a original_target_lines=() original_target_positions=() expected_target_lines=()
    local -a current_target_lines=() current_foreign_lines=() original_foreign_rules=()

    command -v "$cmd" >/dev/null 2>&1 || return 0
    command -v "$save_cmd" >/dev/null 2>&1 || return 1
    if ! "$cmd" -w -S INPUT >/dev/null 2>&1; then
        if [[ "${cmd##*/}" == ip6tables ]] && ! has_ipv6; then return 0; fi
        return 1
    fi
    if iptables_rule_check "$cmd" INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP; then check_rc=0; else check_rc=$?; fi
    case "$check_rc" in 0) ;; 1) return 0 ;; *) return 1 ;; esac

    [[ -d /run && ! -L /run ]] || return 1
    if [[ -e "$lock_file" || -L "$lock_file" ]]; then
        [[ -f "$lock_file" && ! -L "$lock_file" ]] || return 1
        [[ "$(stat -c %u:%g "$lock_file" 2>/dev/null || true)" == 0:0 ]] || return 1
        local lock_mode
        lock_mode=$(stat -c %a "$lock_file" 2>/dev/null) || return 1
        if [[ "$lock_mode" =~ ^[0-7]{3,4}$ ]]; then
            (( (8#$lock_mode & 8#077) == 0 )) || return 1
        else
            return 1
        fi
    else
        (umask 077; set -o noclobber; : > "$lock_file") 2>/dev/null || return 1
    fi
    # Open+flock before chown/chmod so the critical section starts immediately.
    exec {lock_fd}>>"$lock_file" || return 1
    flock -n "$lock_fd" || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; return 1; }
    chown root:root "$lock_file" 2>/dev/null || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; rm -f -- "$lock_file"; return 1; }
    chmod 600 "$lock_file" 2>/dev/null || { [[ "$lock_fd" =~ ^[0-9]+$ ]] && eval "exec ${lock_fd}>&-"; rm -f -- "$lock_file"; return 1; }
    firewall_unlock() {
        # Guard empty lock_fd: `exec >&-` would close stdout.
        if [[ "$lock_fd" =~ ^[0-9]+$ ]]; then
            eval "exec ${lock_fd}>&-" 2>/dev/null || true
        fi
        lock_fd=''
    }

    normalize_managed_rule_line() {
        local line="$1"
        line=${line//\"/}
        line=$(printf '%s\n' "$line" | sed -E 's/^(-A[[:space:]]+INPUT[[:space:]]+-p[[:space:]]+(tcp|udp))[[:space:]]+-m[[:space:]]+\2([[:space:]]|$)/\1\3/')
        printf '%s\n' "$line"
    }
    capture_firewall_views() {
        local item normalized
        current_rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || return 1
        current_target_lines=()
        current_foreign_lines=()
        while IFS= read -r item; do
            [[ "$item" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
            if [[ "$item" =~ $wl_re || "$item" =~ $drop_re ]]; then
                normalized=$(normalize_managed_rule_line "$item") || return 1
                current_target_lines+=("$normalized")
            else
                current_foreign_lines+=("$item")
            fi
        done <<< "$current_rules_output"
    }
    firewall_state_matches_expected() {
        capture_firewall_views || return 1
        [[ "$(printf '%s\n' "${current_target_lines[@]}")" == "$(printf '%s\n' "${expected_target_lines[@]}")" ]] || return 1
        [[ "$(printf '%s\n' "${current_foreign_lines[@]}")" == "$(printf '%s\n' "${original_foreign_rules[@]}")" ]]
    }
    firewall_rollback() {
        local rollback_line
        local -a rollback_lines=() rollback_argv_arr=()
        [[ -n "$recovery_snapshot" && -s "$recovery_snapshot" ]] || return 1
        capture_firewall_views || return 1
        [[ "$(printf '%s\n' "${current_target_lines[@]}")" == "$(printf '%s\n' "${expected_target_lines[@]}")" ]] || {
            printf '%s\n' "A-Box firewall rollback conflict: target rules changed outside this transaction; recovery snapshot preserved at $recovery_snapshot" >&2
            return 2
        }
        [[ "$(printf '%s\n' "${current_foreign_lines[@]}")" == "$(printf '%s\n' "${original_foreign_rules[@]}")" ]] || {
            printf '%s\n' "A-Box firewall rollback conflict: non-A-Box INPUT rules changed outside this transaction; recovery snapshot preserved at $recovery_snapshot" >&2
            return 2
        }
        rollback_lines=("${current_target_lines[@]}")
        for rollback_line in "${rollback_lines[@]}"; do
            rollback_line=${rollback_line//\"/}
            read -r -a rollback_argv_arr <<< "$rollback_line"
            [[ "${rollback_argv_arr[0]:-}" == -A && "${rollback_argv_arr[1]:-}" == INPUT ]] || return 1
            "${cmd}" -w -D INPUT "${rollback_argv_arr[@]:2}" >/dev/null 2>&1 || return 1
        done
        for ((i=${#original_target_lines[@]}-1; i>=0; i--)); do
            rollback_line=${original_target_lines[i]//\"/}
            read -r -a rollback_argv_arr <<< "$rollback_line"
            [[ "${rollback_argv_arr[0]:-}" == -A && "${rollback_argv_arr[1]:-}" == INPUT ]] || return 1
            "${cmd}" -w -I INPUT "${original_target_positions[i]}" "${rollback_argv_arr[@]:2}" >/dev/null 2>&1 || return 1
        done
        capture_firewall_views || return 1
        [[ "$current_rules_output" == "$original_rules_output" ]] || return 1
        rm -f -- "$recovery_snapshot" || return 1
        recovery_snapshot=''
        return 0
    }

    recovery_snapshot=$(mktemp /run/A-Box-firewall-recovery.XXXXXX) || { firewall_unlock; return 1; }
    if ! "$save_cmd" -t filter > "$recovery_snapshot" 2>/dev/null; then
        rm -f -- "$recovery_snapshot"
        firewall_unlock
        return 1
    fi
    original_rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || { rm -f -- "$recovery_snapshot"; firewall_unlock; return 1; }
    capture_firewall_views || { rm -f -- "$recovery_snapshot"; firewall_unlock; return 1; }
    original_target_lines=("${current_target_lines[@]}")
    original_foreign_rules=("${current_foreign_lines[@]}")
    expected_target_lines=("${original_target_lines[@]}")
    for line in "${original_target_lines[@]}"; do
        if [[ "$line" =~ $wl_re ]]; then rules+=("$line"); fi
    done
    rule_no=0
    while IFS= read -r line; do
        [[ "$line" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
        rule_no=$((rule_no + 1))
        if [[ "$line" =~ $wl_re || "$line" =~ $drop_re ]]; then
            original_target_positions+=("$rule_no")
        fi
    done <<< "$original_rules_output"
    n=${#rules[@]}

    for ((i=n-1; i>=0; i--)); do
        local expected_line="${rules[i]}"
        line=${rules[i]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || { firewall_rollback >/dev/null 2>&1 || printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; firewall_unlock; return 1; }
        firewall_state_matches_expected || {
            if (( mutated )); then
                if ! firewall_rollback; then
                    printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2
                fi
            else
                rm -f -- "$recovery_snapshot" || true
            fi
            firewall_unlock
            return 1
        }
        if ! "$cmd" -w -I INPUT 1 "${argv[@]:2}" >/dev/null 2>&1; then
            if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
            firewall_unlock
            return 1
        fi
        mutated=1
        expected_target_lines=("$expected_line" "${expected_target_lines[@]}")
    done
    local expected_drop_line="-A INPUT -p ${proto} --dport ${port} -m comment --comment ${drop_comment} -j DROP"
    firewall_state_matches_expected || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
    if ! "$cmd" -w -I INPUT "$((n + 1))" -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1; then
        if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
        firewall_unlock
        return 1
    fi
    expected_target_lines=("${expected_target_lines[@]:0:n}" "$expected_drop_line" "${expected_target_lines[@]:n}")

    rules_output=$("$cmd" -w -S INPUT 2>/dev/null) || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
    current_lines=(); mapfile -t current_lines <<< "$rules_output"
    delete_lines=(); delete_target_indices=(); target_idx=0; rule_no=0
    for i in "${!current_lines[@]}"; do
        current_line="${current_lines[i]}"
        [[ "$current_line" =~ ^-A[[:space:]]+INPUT[[:space:]] ]] || continue
        rule_no=$((rule_no + 1))
        if [[ "$current_line" =~ $wl_re || "$current_line" =~ $drop_re ]]; then
            if (( target_idx > n )); then
                delete_lines+=("$current_line")
                delete_target_indices+=("$target_idx")
                delete_rule_numbers+=("$rule_no")
            fi
            target_idx=$((target_idx + 1))
        fi
    done
    for ((j=${#delete_lines[@]}-1; j>=0; j--)); do
        firewall_state_matches_expected || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
        line=${delete_lines[j]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || { if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi; firewall_unlock; return 1; }
        if ! "$cmd" -w -D INPUT "${delete_rule_numbers[j]}" >/dev/null 2>&1; then
            if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
            firewall_unlock
            return 1
        fi
        del_idx="${delete_target_indices[j]}"
        expected_target_lines=("${expected_target_lines[@]:0:del_idx}" "${expected_target_lines[@]:del_idx+1}")
    done
    if ! firewall_state_matches_expected; then
        if ! firewall_rollback >/dev/null 2>&1; then printf '%s\n' "A-Box firewall rollback incomplete; recovery snapshot: $recovery_snapshot" >&2; fi
        firewall_unlock
        return 1
    fi
    if ! rm -f -- "$recovery_snapshot"; then
        printf '%s\n' "A-Box firewall change completed, but recovery snapshot cleanup failed; snapshot retained at $recovery_snapshot" >&2
        firewall_unlock
        return 1
    fi
    recovery_snapshot=''
    firewall_unlock
    return 0
}

enforce_ss_whitelist_order() {
    local port="${1:-${SS_PORT:-}}" failed=0 proto
    valid_port "$port" || return 0
    for proto in tcp udp; do
        reorder_ss_whitelist_rules_one "$IPT" "$port" "$proto" WL DROP || failed=1
        if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
            reorder_ss_whitelist_rules_one "$IPT6" "$port" "$proto" WL6 DROP6 || failed=1
        fi
    done
    (( failed == 0 ))
}

clean_nat_rules() {
    local output rule failed=0 owned_re
    local -a argv=()
    owned_re='--comment "?A-Box-HY2-HOP"?([[:space:]]|$)'
    while :; do
        output=$($IPT -w -t nat -S PREROUTING 2>/dev/null) || { failed=1; break; }
        rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
        [[ -n "$rule" ]] || break
        rule=${rule//\"/}
        read -r -a argv <<< "$rule"
        $IPT -w -t nat "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
    done
    if command -v ip6tables >/dev/null 2>&1; then
        if $IPT6 -w -t nat -S PREROUTING >/dev/null 2>&1; then
            while :; do
                output=$($IPT6 -w -t nat -S PREROUTING 2>/dev/null) || { failed=1; break; }
                rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
                [[ -n "$rule" ]] || break
                rule=${rule//\"/}
                read -r -a argv <<< "$rule"
                $IPT6 -w -t nat "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
            done
        elif has_ipv6; then
            failed=1
        fi
    elif has_ipv6; then
        failed=1
    fi
    (( failed == 0 ))
}

clean_input_rules() {
    local output rule failed=0 owned_re
    local -a argv=()
    owned_re='--comment "?A-Box-[0-9]+(:[0-9]+)?-(tcp|udp)(-(WL6?|DROP6?))?"?([[:space:]]|$)'
    remove_native_firewall_rules 2>/dev/null || failed=1
    while :; do
        output=$($IPT -w -S INPUT 2>/dev/null) || { failed=1; break; }
        rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
        [[ -n "$rule" ]] || break
        rule=${rule//\"/}
        read -r -a argv <<< "$rule"
        $IPT -w "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
    done
    if command -v ip6tables >/dev/null 2>&1; then
        if $IPT6 -w -S INPUT >/dev/null 2>&1; then
            while :; do
                output=$($IPT6 -w -S INPUT 2>/dev/null) || { failed=1; break; }
                rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
                [[ -n "$rule" ]] || break
                rule=${rule//\"/}
                read -r -a argv <<< "$rule"
                $IPT6 -w "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
            done
        elif has_ipv6; then
            failed=1
        fi
    elif has_ipv6; then
        failed=1
    fi
    (( failed == 0 ))
}

add_port_pair() {
    local arr_name="$1" proto="$2" port="$3"
    [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] || return 0
    printf -v "$arr_name" '%s%s/%s\n' "${!arr_name}" "$proto" "$port"
}

hy2_http01_enabled() {
    local core="${1:-${CORE_IN:-${CORE:-}}}" mode="${2:-${MODE_IN:-${MODE:-}}}"
    [[ -n "${HY2_DOMAIN:-}" && "${HY2_ACME_TYPE:-http}" == http &&
       ( "$core" == 'hysteria' || ( "$core" == 'xray' && "$mode" == *'ALL'* ) ) ]]
}

selected_port_pairs() {
    local pairs=''
    add_port_pair pairs tcp "${VLESS_PORT:-}"
    add_port_pair pairs tcp "${XHTTP_PORT:-}"
    add_port_pair pairs tcp "${SS_PORT:-}"
    add_port_pair pairs udp "${SS_PORT:-}"
    if hy2_http01_enabled; then
        add_port_pair pairs tcp 80
    fi
    # Native Hysteria official range mode listens on the first range port; the
    # separate base port is only real for non-hopping/manual redirect modes.
    if [[ "${HY2_HOP:-}" != true || "${HY2_HOP_IMPL:-none}" != official ]]; then
        add_port_pair pairs udp "${HY2_BASE_PORT:-}"
    fi
    printf '%s' "$pairs"
}

check_selected_ports_free() {
    msg "${YELLOW}[*] 正在检查新选择端口是否仍被任何进程占用...${NC}"
    local pairs pair proto p holder dup
    pairs=$(selected_port_pairs | awk 'NF')
    dup=$(printf '%s\n' "$pairs" | awk 'NF { seen[$0]++ } END { for (k in seen) if (seen[k] > 1) { print k; break } }')
    [[ -n "$dup" ]] && die "端口冲突：当前配置中存在重复监听组合 ($dup)。"

    if [[ "${HY2_HOP:-}" == 'true' && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
        for pair in $pairs; do
            proto=${pair%/*}; p=${pair#*/}
            if [[ "$proto" == 'udp' ]] && (( 10#$p >= 10#$HY2_RANGE_START && 10#$p <= 10#$HY2_RANGE_END )); then
                die "端口冲突：HY2 基础 UDP 端口 ($p) 不能落在跳跃区间 (${HY2_RANGE_START}-${HY2_RANGE_END}) 内。"
            fi
        done
    fi

    command -v ss >/dev/null 2>&1 || die '系统缺少 ss，无法可靠检查端口占用。'
    for pair in $pairs; do
        proto=${pair%/*}; p=${pair#*/}
        if ! holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null); then
            die "无法检查 ${p}/${proto} 端口占用；ss 查询失败。"
        fi
        holder=$(grep -E "[:.]${p}([[:space:]]|$)" <<< "$holder" || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 新选择端口 ${p}/${proto} 仍被进程占用：${NC}"
        printf '%s\n' "$holder"
        die "请先手动释放端口 ${p}/${proto}。"
    done

    if [[ "${HY2_HOP:-}" == 'true' && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
        local ss_udp_output
        if ! ss_udp_output=$(ss -H -n -l -p -A udp 2>/dev/null); then
            die '无法检查 HY2 UDP 跳跃区间占用；ss 查询失败。'
        fi
        holder=''
        if [[ -n "$ss_udp_output" ]]; then
            while IFS= read -r line; do
                p=$(awk '{print $4}' <<< "$line" | sed -nE 's/.*[:.]([0-9]+)$/\1/p')
                [[ "$p" =~ ^[0-9]+$ ]] || continue
                if (( 10#$p >= 10#$HY2_RANGE_START && 10#$p <= 10#$HY2_RANGE_END )); then
                    holder+="$line"$'\n'
                fi
            done <<< "$ss_udp_output"
        fi
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] HY2 UDP 跳跃区间 ${HY2_RANGE_START}-${HY2_RANGE_END} 仍被进程占用：${NC}"
            printf '%s' "$holder"
            die '请先手动释放 HY2 UDP 跳跃区间内的占用端口。'
        fi
    fi
}

release_ports() {
    msg "${YELLOW}[*] 正在停止 A-Box 托管服务...${NC}"
    stop_all_managed_services || die '无法停止全部 A-Box 托管服务。'
    sleep 1
    local pairs pair proto p holder
    pairs=$(selected_port_pairs | awk 'NF' | sort -u)
    if [[ -z "$pairs" ]]; then
        # Fresh install / empty .env: ports are chosen in the wizard after this
        # step. Occupancy for the newly selected ports is enforced by
        # check_selected_ports_free at the end of pre_install_setup.
        msg "${YELLOW}[*] 当前尚未选定监听端口；端口占用检查将在参数向导完成后执行。${NC}"
        return 0
    fi
    msg "${YELLOW}[*] 正在检查已配置端口占用...${NC}"
    command -v ss >/dev/null 2>&1 || die '系统缺少 ss，无法可靠检查端口占用。'
    for pair in $pairs; do
        proto=${pair%/*}; p=${pair#*/}
        if ! holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null); then
            die "无法检查 ${p}/${proto} 端口占用；ss 查询失败。"
        fi
        holder=$(grep -E "[:.]${p}([[:space:]]|$)" <<< "$holder" || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 端口 ${p}/${proto} 仍被进程占用：${NC}"
        printf '%s\n' "$holder"
        die "请先手动释放端口 ${p}/${proto}。脚本不会自动 kill 非托管进程。"
    done
}


write_if_changed() {
    local target="$1" tmp="$2" mode="${3:-700}"
    if [[ -f "$target" && ! -L "$target" ]] && cmp -s "$tmp" "$target"; then
        rm -f "$tmp"
    else
        install_file_atomically "$tmp" "$target" "$mode" || { rm -f "$tmp"; return 1; }
        rm -f "$tmp"
    fi
}

validate_abox_script_file() {
    local f="$1" context="${2:-script}"
    [[ -s "$f" ]] || { printf '%s\n' "${context} 为空或不存在。" >&2; return 1; }
    bash -n "$f" >/dev/null 2>&1 || { printf '%s\n' "${context} 语法校验失败。" >&2; return 1; }
    grep -q '==============================A-Box===============================' "$f" || { printf '%s\n' "${context} 文本指纹不匹配。" >&2; return 1; }
    grep -q '^main "\$@"' "$f" || { printf '%s\n' "${context} 入口指纹不匹配。" >&2; return 1; }
}


resolve_abox_main_commit_url() {
    local api='https://api.github.com/repos/alariclin/a-box/commits/main' json sha
    json=$(github_api_get "$api") || return 1
    sha=$(jq -r '.sha // empty' <<< "$json" 2>/dev/null)
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf 'https://raw.githubusercontent.com/alariclin/a-box/%s/install.sh\n' "$sha"
}

install_remote_abox_script_guarded() {
    local url="$1" dest="$2" tmp sha resolved_url
    if [[ "$url" == 'https://raw.githubusercontent.com/alariclin/a-box/main/install.sh' ]]; then
        resolved_url=$(resolve_abox_main_commit_url) || die '无法将 A-Box main 分支解析为不可变 commit；已拒绝下载可变源码。'
        url="$resolved_url"
    fi
    tmp=$(umask 077; mktemp /tmp/A-Box-script.XXXXXX.sh) || die '远端脚本临时文件创建失败。'
    curl -fLs --connect-timeout 10 -m 60 "$url" -o "$tmp" || { rm -f -- "$tmp"; die '远端脚本下载失败。'; }
    if ! ( validate_abox_script_file "$tmp" '远端 A-Box 脚本'; validate_ota_version_direction "$tmp" ); then
        rm -f -- "$tmp"
        die '远端 A-Box 脚本校验或版本方向检查失败。'
    fi
    sha=$(sha256sum "$tmp" | awk '{print $1}')
    msg "${YELLOW}[*] Remote script SHA256: ${sha}${NC}"
    confirm_ota_script_hash "$sha" "$url" || { rm -f -- "$tmp"; die '远端脚本安装被取消。'; }
    write_if_changed "$dest" "$tmp" 700 || { rm -f -- "$tmp"; die '远端 A-Box 脚本原子持久化失败。'; }
    rm -f -- "$tmp"
}

setup_shortcut() {
    ensure_abox_dir_owned "$ABOX_DIR" || return 1
    if [[ -f "$0" && -r "$0" && "$0" != 'bash' && "$0" != '-bash' ]]; then
        validate_abox_script_file "$0" '当前 A-Box 脚本' || die '当前 A-Box 脚本校验失败。'
        if [[ -f "$ABOX_DIR/A-Box.sh" ]]; then
            local current_build_epoch remote_build_epoch
            current_build_epoch=$(awk -F= '/^ABOX_BUILD_EPOCH=/{gsub(/[^0-9]/,"",$2); print $2; exit}' "$ABOX_DIR/A-Box.sh" 2>/dev/null || true)
            remote_build_epoch=$(awk -F= '/^ABOX_BUILD_EPOCH=/{gsub(/[^0-9]/,"",$2); print $2; exit}' "$0" 2>/dev/null || true)
            if [[ "$current_build_epoch" =~ ^[0-9]+$ && "$remote_build_epoch" =~ ^[0-9]+$ ]] && (( 10#$remote_build_epoch < 10#$current_build_epoch )); then
                confirm_yes_no '当前本地 A-Box 脚本版本低于已安装版本，确认降级？[Y/N]: ' || die '已拒绝降级 A-Box 脚本。'
            fi
        fi
        if [[ ! -f "$ABOX_DIR/A-Box.sh" ]] || ! cmp -s "$0" "$ABOX_DIR/A-Box.sh"; then
            install_binary_atomically "$0" "$ABOX_DIR/A-Box.sh" || die '持久化当前脚本失败。'
        fi
    elif [[ ! -f "$ABOX_DIR/A-Box.sh" ]]; then
        install_remote_abox_script_guarded "$SCRIPT_URL" "$ABOX_DIR/A-Box.sh"
    fi
    [[ -f "$ABOX_DIR/A-Box.sh" ]] || die '持久化 A-Box 脚本不存在。'
    validate_abox_script_file "$ABOX_DIR/A-Box.sh" '持久化 A-Box 脚本' || die '持久化 A-Box 脚本校验失败。'
    chmod +x "$ABOX_DIR/A-Box.sh" || die 'A-Box 主脚本执行权限设置失败。'

    local shortcut_tmp
    shortcut_tmp=$(umask 077; mktemp /tmp/A-Box-sb.XXXXXX) || die '快捷入口临时文件创建失败。'
    cat > "$shortcut_tmp" <<'EOS' || { rm -f -- "$shortcut_tmp"; die '快捷入口临时文件写入失败。'; }
#!/usr/bin/env bash
# Managed by A-Box
if [[ $EUID -eq 0 ]]; then
    exec bash /etc/ddr/A-Box.sh "$@"
elif command -v sudo >/dev/null 2>&1; then
    exec sudo bash /etc/ddr/A-Box.sh "$@"
else
    echo 'Root privileges required. Please run: su -'
    exit 1
fi
EOS
    chmod 755 "$shortcut_tmp" || { rm -f -- "$shortcut_tmp"; die '快捷入口临时文件权限设置失败。'; }
    if ! assert_abox_shortcut_safe /usr/local/bin/sb; then
        rm -f -- "$shortcut_tmp"
        die '现有 /usr/local/bin/sb 归属/内容不安全，拒绝覆盖。'
    fi
    if [[ ! -f /usr/local/bin/sb ]] || ! cmp -s "$shortcut_tmp" /usr/local/bin/sb; then
        install_binary_atomically "$shortcut_tmp" /usr/local/bin/sb || { rm -f -- "$shortcut_tmp"; die '快捷入口写入失败。'; }
    fi
    rm -f -- "$shortcut_tmp"
}
validate_downloaded_asset() {
    local asset_name="$1" f="${2:-/tmp/$1}" magic=''
    [[ -s "$f" ]] || { printf '%s\n' "下载资产为空: $asset_name" >&2; return 1; }
    case "$asset_name" in
        xray_core.zip)
            unzip -tqq "$f" >/dev/null 2>&1 || { printf '%s\n' 'Xray 压缩包校验失败。' >&2; return 1; }
            ;;
        singbox_core.tar.gz)
            tar -tzf "$f" >/dev/null 2>&1 || { printf '%s\n' 'Sing-box 压缩包校验失败。' >&2; return 1; }
            ;;
        hysteria_core)
            magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n' || true)
            [[ "$magic" == '7f454c46' ]] || { printf '%s\n' 'Hysteria 下载结果不是 ELF 可执行文件。' >&2; return 1; }
            ;;
        *)
            printf '%s\n' "未定义的下载校验规则: $asset_name" >&2
            return 1
            ;;
    esac
}


extract_zip_member_safely() {
    local archive="$1" member="$2" dest="$3"
    [[ -s "$archive" && -n "$member" && -n "$dest" ]] || return 1
    python3 - "$archive" "$member" "$dest" <<'PY_ZIP_EXTRACT'
import os, shutil, stat, sys, zipfile
archive, member, dest = sys.argv[1:]
MAX_FILE = 512 * 1024 * 1024
created = False
try:
    if os.path.lexists(dest): raise ValueError('destination exists')
    with zipfile.ZipFile(archive) as zf:
        matches = [x for x in zf.infolist() if x.filename == member]
        if len(matches) != 1: raise ValueError('member count')
        info = matches[0]
        mode = (info.external_attr >> 16) & 0o170000
        if info.is_dir() or mode == stat.S_IFLNK: raise ValueError('not regular')
        if info.file_size <= 0 or info.file_size > MAX_FILE: raise ValueError('size')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_NOFOLLOW'): flags |= os.O_NOFOLLOW
        fd = os.open(dest, flags, 0o600)
        created = True
        try:
            with zf.open(info, 'r') as src, os.fdopen(fd, 'wb', closefd=False) as out:
                remaining = MAX_FILE + 1
                while True:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk: break
                    out.write(chunk); remaining -= len(chunk)
                    if remaining <= 0: raise ValueError('expanded size')
                out.flush(); os.fsync(out.fileno())
        finally:
            os.close(fd)
except Exception:
    if created:
        try: os.unlink(dest)
        except OSError: pass
    raise SystemExit(1)
PY_ZIP_EXTRACT
}

extract_tar_regular_basename_safely() {
    local archive="$1" basename="$2" dest="$3"
    [[ -s "$archive" && "$basename" =~ ^[A-Za-z0-9._-]+$ && -n "$dest" ]] || return 1
    python3 - "$archive" "$basename" "$dest" <<'PY_TAR_EXTRACT'
import os, posixpath, sys, tarfile
archive, wanted, dest = sys.argv[1:]
MAX_MEMBERS = 10000
MAX_FILE = 512 * 1024 * 1024
created = False
try:
    if os.path.lexists(dest): raise ValueError('destination exists')
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS: raise ValueError('member count')
        matches = []
        for m in members:
            raw = m.name
            if '\x00' in raw or raw.startswith('/'): raise ValueError('path')
            while raw.startswith('./'): raw = raw[2:]
            norm = posixpath.normpath(raw)
            if norm in ('', '.'):
                continue
            if norm == '..' or norm.startswith('../'): raise ValueError('path')
            if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                raise ValueError('special member')
            if not (m.isfile() or m.isdir()): raise ValueError('unknown member')
            if m.isfile() and posixpath.basename(norm) == wanted:
                matches.append(m)
        if len(matches) != 1: raise ValueError('binary member count')
        target = matches[0]
        if target.size <= 0 or target.size > MAX_FILE: raise ValueError('size')
        src = tf.extractfile(target)
        if src is None: raise ValueError('extract')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_NOFOLLOW'): flags |= os.O_NOFOLLOW
        fd = os.open(dest, flags, 0o600)
        created = True
        try:
            with src, os.fdopen(fd, 'wb', closefd=False) as out:
                remaining = MAX_FILE + 1
                while True:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk: break
                    out.write(chunk); remaining -= len(chunk)
                    if remaining <= 0: raise ValueError('expanded size')
                out.flush(); os.fsync(out.fileno())
        finally:
            os.close(fd)
except Exception:
    if created:
        try: os.unlink(dest)
        except OSError: pass
    raise SystemExit(1)
PY_TAR_EXTRACT
}

github_api_get() {
    local url="$1" attempt=1 max_attempts=3 delay=1 rc http_code tmp
    local -a args=(-sS -L --connect-timeout 10 -m 60 -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2026-03-10' -o)
    [[ -n "$url" ]] || return 1
    if [[ "${GITHUB_API_RETRY_DELAY:-1}" =~ ^[0-9]+$ ]]; then
        delay="${GITHUB_API_RETRY_DELAY:-1}"
    elif [[ -n "${GITHUB_API_RETRY_DELAY:-}" ]]; then
        return 1
    fi
    tmp=$(umask 077; mktemp /tmp/A-Box-github-api.XXXXXX) || return 1
    while (( attempt <= max_attempts )); do
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            [[ "${GITHUB_TOKEN}" != *[$'\r\n"\\']* ]] || { rm -f -- "$tmp"; return 1; }
            http_code=$(printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | curl "${args[@]}" "$tmp" -w '%{http_code}' --config - "$url" 2>/dev/null)
            rc=$?
        else
            http_code=$(curl "${args[@]}" "$tmp" -w '%{http_code}' "$url" 2>/dev/null)
            rc=$?
        fi
        if (( rc == 0 )) && [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            cat -- "$tmp"
            rc=$?
            rm -f -- "$tmp"
            return "$rc"
        fi
        if (( rc == 0 )) && [[ "$http_code" =~ ^5[0-9][0-9]$ ]]; then
            :
        elif (( rc == 5 || rc == 6 || rc == 7 || rc == 18 || rc == 28 || rc == 35 || rc == 52 || rc == 56 )); then
            :
        else
            if [[ "$http_code" == 403 && -z "${GITHUB_TOKEN:-}" ]]; then
                printf '%s\n' 'GitHub API 返回 403；共享出口可能触发匿名限流，请设置 GITHUB_TOKEN 后重试。' >&2
            fi
            rm -f -- "$tmp"
            return 1
        fi
        if (( attempt == max_attempts )); then
            break
        fi
        if (( delay > 0 )); then sleep "$delay"; fi
        if (( delay < 30 )); then
            delay=$(( delay * 2 ))
        fi
        attempt=$((attempt + 1))
    done
    rm -f -- "$tmp"
    return 1
}

verify_github_asset_digest() {
    local file="$1" digest="${2:-}" expected actual
    if [[ -z "$digest" || "$digest" == 'null' ]]; then
        printf '%s\n' 'GitHub Release asset 缺少官方 SHA256 digest，拒绝安装。' >&2
        return 1
    fi
    [[ "$digest" == sha256:* ]] || { printf '%s\n' 'GitHub Release digest 不是 sha256 格式。' >&2; return 1; }
    expected="${digest#sha256:}"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || { printf '%s\n' 'GitHub Release digest 格式异常。' >&2; return 1; }
    actual=$(sha256sum "$file" 2>/dev/null | awk '{print $1}') || actual=''
    [[ "${actual,,}" == "${expected,,}" ]] || { printf '%s\n' 'GitHub Release digest 校验失败。' >&2; return 1; }
}

valid_github_download_url() {
    local repo="$1" url="$2" expected_ref="${3:-}" expected_asset="${4:-}"
    local repo_lower="${repo,,}" url_lower="${url,,}"
    [[ "$repo_lower" =~ ^[a-z0-9_.-]+/[a-z0-9_.-]+$ ]] || return 1
    [[ "$url" != *$'\r'* && "$url" != *$'\n'* && "$url" != *$'\t'* ]] || return 1
    if [[ -n "$expected_ref" ]]; then
        [[ "$expected_ref" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
        if [[ -n "$expected_asset" ]]; then
            python3 - "$url" "$repo" "$expected_ref" "$expected_asset" <<'PY_GITHUB_URL'
from urllib.parse import urlsplit
import sys
url, repo, ref, asset = sys.argv[1:]
try:
    u = urlsplit(url)
except ValueError:
    raise SystemExit(1)
if u.scheme != 'https' or u.hostname != 'github.com' or u.username or u.password or u.query or u.fragment:
    raise SystemExit(1)
if u.path != f'/{repo}/releases/download/{ref}/{asset}':
    raise SystemExit(1)
raise SystemExit(0)
PY_GITHUB_URL
            return $?
        fi
        [[ "$url" == "https://github.com/${repo}/releases/download/${expected_ref}/"* ]] || return 1
        local tail="${url#https://github.com/${repo}/releases/download/${expected_ref}/}"
        [[ -n "$tail" && "$tail" != */* && "$tail" != *'?'* && "$tail" != *'#'* && "$tail" != *'..'* && "$tail" != *'\\'* ]] || return 1
    else
        [[ "$url_lower" == "https://github.com/${repo_lower}/releases/download/"* ]] || return 1
        local tail="${url#https://github.com/${repo_lower}/releases/download/}"
        [[ -n "$tail" && "$tail" != *'?'* && "$tail" != *'#'* && "$tail" != *'..'* && "$tail" != *'\\'* ]] || return 1
    fi
}

singbox_asset_regex() {
    if [[ "${release:-}" == 'alpine' ]]; then
        printf '%s\n' "^sing-box-.*-linux-${SB_ARCH}-musl\.tar\.gz$"
    else
        printf '%s\n' "^sing-box-.*-linux-${SB_ARCH}-glibc\.tar\.gz$"
    fi
}

decimal_component_compare() {
    local a="${1:-}" b="${2:-}" LC_ALL=C
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 2
    a="${a#"${a%%[!0]*}"}"; b="${b#"${b%%[!0]*}"}"
    [[ -n "$a" ]] || a='0'
    [[ -n "$b" ]] || b='0'
    if (( ${#a} < ${#b} )); then printf '%s\n' -1; return 0; fi
    if (( ${#a} > ${#b} )); then printf '%s\n' 1; return 0; fi
    if [[ "$a" == "$b" ]]; then printf '%s\n' 0; elif (( 10#$a < 10#$b )); then printf '%s\n' -1; else printf '%s\n' 1; fi
}

xray_version_at_least() {
    local version="${1:-}" min_major="${2:-0}" min_minor="${3:-0}" min_patch="${4:-0}" major minor patch cmp
    version="${version#v}"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
    major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
    cmp=$(decimal_component_compare "$major" "$min_major") || return 2
    (( cmp > 0 )) && return 0; (( cmp < 0 )) && return 1
    cmp=$(decimal_component_compare "$minor" "$min_minor") || return 2
    (( cmp > 0 )) && return 0; (( cmp < 0 )) && return 1
    cmp=$(decimal_component_compare "$patch" "$min_patch") || return 2
    (( cmp >= 0 ))
}

xray_version_compare() {
    local a="${1:-}" b="${2:-}" am aj ap bm bj bp cmp
    a="${a#v}"; b="${b#v}"
    [[ "$a" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
    am="${BASH_REMATCH[1]}"; aj="${BASH_REMATCH[2]}"; ap="${BASH_REMATCH[3]}"
    [[ "$b" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
    bm="${BASH_REMATCH[1]}"; bj="${BASH_REMATCH[2]}"; bp="${BASH_REMATCH[3]}"
    cmp=$(decimal_component_compare "$am" "$bm") || return 2; (( cmp != 0 )) && { printf '%s\n' "$cmp"; return 0; }
    cmp=$(decimal_component_compare "$aj" "$bj") || return 2; (( cmp != 0 )) && { printf '%s\n' "$cmp"; return 0; }
    decimal_component_compare "$ap" "$bp"
}

xray_latest_stable_version() {
    local json tag
    json=$(github_api_get 'https://api.github.com/repos/XTLS/Xray-core/releases?per_page=50') || return 1
    tag=$(jq -r 'first(.[]? | select(.draft == false and .prerelease == false) | .tag_name) // empty' <<< "$json")
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s\n' "$tag"
}

effective_xray_version() {
    printf '%s\n' "${ABOX_XRAY_VERSION:-$ABOX_XRAY_DEFAULT_VERSION}"
}

xray_reality_requires_mlkem() {
    local threshold="${ABOX_XRAY_REALITY_MLKEM_MIN_VERSION#v}" min_major min_minor min_patch
    IFS=. read -r min_major min_minor min_patch <<< "$threshold"
    [[ "$min_major" =~ ^[0-9]+$ && "$min_minor" =~ ^[0-9]+$ && "$min_patch" =~ ^[0-9]+$ ]] || return 2
    xray_version_at_least "$(effective_xray_version)" "$min_major" "$min_minor" "$min_patch"
}

clash_reality_mlkem_enabled() {
    [[ "${CORE:-}" == 'xray' ]] || return 1
    xray_reality_requires_mlkem
}

singbox_asset_json_from_release() {
    local release_json="${1:-}" preferred asset_json
    preferred="$(singbox_asset_regex)"
    # Fail closed on libc selection. A generic linux-ARCH asset is not accepted
    # because it can silently select the wrong libc family and fail after install.
    asset_json=$(jq -c --arg re "$preferred" 'first(.assets[]? | select(.name | test($re)) | {name:.name,url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
    [[ -n "$asset_json" && "$asset_json" != 'null' ]] || return 1
    printf '%s\n' "$asset_json"
}

fetch_github_release() {
    local repo=$1 output_file=$2 dest_file="${3:-}" api_url asset_re release_json asset_json asset_name download_url digest mirror tmp_file tmp_dir release_ref
    case "$repo:$output_file" in
        # Keep new installs on the current iOS/XHTTP compatibility pin.
        # The pin is intentionally not the latest prerelease; explicit overrides remain supported
        # but are treated as compatibility-sensitive.
        XTLS/Xray-core:xray_core.zip) release_ref="${ABOX_XRAY_VERSION:-$ABOX_XRAY_DEFAULT_VERSION}" ;;
        SagerNet/sing-box:singbox_core.tar.gz) release_ref="${ABOX_SINGBOX_VERSION:-$ABOX_SINGBOX_DEFAULT_VERSION}" ;;
        HyNetworks/hysteria:hysteria_core) release_ref="${ABOX_HYSTERIA_APP_VERSION:-app/v2.13.0}" ;;
        *) release_ref='' ;;
    esac
    [[ "$release_ref" =~ ^[A-Za-z0-9._/-]+$ ]] || die '核心版本号非法。'
    api_url="https://api.github.com/repos/${repo}/releases/tags/${release_ref//\//%2F}"
    case "${repo}:${output_file}" in
        XTLS/Xray-core:xray_core.zip) asset_re="^Xray-linux-${XRAY_ARCH//+/\\+}\\.zip$" ;;
        SagerNet/sing-box:singbox_core.tar.gz) asset_re="$(singbox_asset_regex)" ;;
        HyNetworks/hysteria:hysteria_core) asset_re="^hysteria-linux-${HY2_ARCH}$" ;;
        *) die "未定义的资产匹配规则: ${repo}:${output_file}" ;;
    esac
    if [[ "$repo:$output_file" == 'XTLS/Xray-core:xray_core.zip' ]]; then
        if xray_reality_requires_mlkem; then
            msg "${YELLOW}[!] Xray ${release_ref} 使用较新的 REALITY ML-KEM ClientHello 门槛；部分 Shadowrocket / sing-box / Mihomo 旧版本可能无法连接。${NC}"
        else
            rc=$?
            (( rc == 1 )) || die 'Xray 版本号无法解析。'
        fi
    fi
    msg "${YELLOW} -> 正在从 GitHub 获取指定架构/版本资产 [${repo}:${release_ref}]...${NC}"
    probe_core_sources_banner

    # U5: optional mirror-first (still SHA256 verified; never skips digest).
    if abox_prefer_mirror; then
        if [[ -z "$dest_file" ]]; then
            tmp_dir=$(mktemp -d /tmp/A-Box-asset.XXXXXX) || die '核心资产临时目录创建失败。'
            dest_file="$tmp_dir/$output_file"
        else
            mkdir -p "$(dirname "$dest_file")" || die '核心资产目标目录创建失败。'
        fi
        if fetch_abox_mirror_asset "$repo" "$output_file" "$dest_file"; then
            return 0
        fi
        msg "${YELLOW}[!] mirror-first miss; falling back to upstream GitHub...${NC}"
    fi

    release_json=$(github_api_get "$api_url" 2>/dev/null) || release_json=''
    [[ -n "$release_json" ]] || die 'GitHub Release API 请求失败；为保证 digest 信任根，不使用第三方镜像 API。'

    if [[ "$repo:$output_file" == 'SagerNet/sing-box:singbox_core.tar.gz' ]]; then
        asset_json=$(singbox_asset_json_from_release "$release_json") || die '未能解析 sing-box 核心资产下载地址。'
    else
        asset_json=$(jq -c --arg re "$asset_re" 'first(.assets[]? | select(.name | test($re)) | {name:.name,url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
        [[ -n "$asset_json" && "$asset_json" != 'null' ]] || die '未能解析核心资产下载地址。'
    fi
    asset_name=$(jq -r '.name // ""' <<< "$asset_json")
    download_url=$(jq -r '.url' <<< "$asset_json")
    digest=$(jq -r '.digest // ""' <<< "$asset_json")
    [[ -n "$asset_name" ]] || die 'GitHub Release asset name missing.'
    valid_github_download_url "$repo" "$download_url" "$release_ref" "$asset_name" || die 'GitHub Release 下载地址仓库或版本标签不匹配。'
    [[ "$digest" == sha256:* ]] || die 'GitHub Release asset 缺少官方 SHA256 digest，拒绝安装。'
    [[ "${digest#sha256:}" =~ ^[A-Fa-f0-9]{64}$ ]] || die 'GitHub Release digest 格式异常。'

    if [[ -z "$dest_file" ]]; then
        tmp_dir=$(mktemp -d /tmp/A-Box-asset.XXXXXX) || die '核心资产临时目录创建失败。'
        dest_file="$tmp_dir/$output_file"
    else
        mkdir -p "$(dirname "$dest_file")" || die '核心资产目标目录创建失败。'
        # Preserve any existing destination until a fully validated asset is ready.
    fi

    for mirror in '' 'https://ghp.ci/' 'https://mirror.ghproxy.com/'; do
        tmp_file=$(mktemp "${dest_file}.download.XXXXXX") || die '核心资产临时文件创建失败。'
        if curl -fLsS --connect-timeout 10 -m 180 "${mirror}${download_url}" -o "$tmp_file"; then
            if ! validate_downloaded_asset "$output_file" "$tmp_file"; then
                rm -f "$tmp_file"
                if [[ -z "$mirror" ]]; then
                    msg "${YELLOW}[!] GitHub 官方直连下载内容结构校验未通过，正在自动回退尝试备用加速镜像...${NC}"
                    continue
                fi
                msg "${YELLOW}[!] 第三方镜像下载内容结构校验未通过，继续尝试下一通道。${NC}"
                continue
            fi
            if ! verify_github_asset_digest "$tmp_file" "$digest"; then
                rm -f "$tmp_file"
                die 'GitHub Release 核心资产 digest 校验失败；拒绝继续使用任何镜像。'
            fi
            mv -f "$tmp_file" "$dest_file" || { rm -f "$tmp_file"; die '核心资产原子提交失败。'; }
            msg "${GREEN}   核心资产提取成功。${NC}"
            return 0
        fi
        rm -f "$tmp_file"
    done
    # Disaster fallback: same-repo GitHub Release assets (core-mirrors-v171) with checksum file.
    local mirror_base mirror_url mirror_sum expect_sum got_sum asset_leaf
    mirror_base="${ABOX_CORE_MIRROR_BASE:-$ABOX_CORE_MIRROR_BASE_DEFAULT}"
    case "$repo:$output_file" in
        XTLS/Xray-core:xray_core.zip) asset_leaf="Xray-linux-${XRAY_ARCH}.zip" ;;
        SagerNet/sing-box:singbox_core.tar.gz)
            _sb_ver="${ABOX_SINGBOX_VERSION:-$ABOX_SINGBOX_DEFAULT_VERSION}"
            _sb_ver="${_sb_ver#v}"
            if [[ "${release:-}" == 'alpine' ]]; then
                asset_leaf="sing-box-${_sb_ver}-linux-${SB_ARCH}-musl.tar.gz"
            else
                asset_leaf="sing-box-${_sb_ver}-linux-${SB_ARCH}-glibc.tar.gz"
            fi
            ;;
        HyNetworks/hysteria:hysteria_core) asset_leaf="hysteria-linux-${HY2_ARCH}" ;;
        *) asset_leaf='' ;;
    esac
    if [[ -n "$asset_leaf" && -n "$mirror_base" ]]; then
        msg "${YELLOW}[!] 上游 Release 通道失败；尝试 A-Box 灾备镜像 ${mirror_base}/${asset_leaf}${NC}"
        mirror_url="${mirror_base%/}/${asset_leaf}"
        mirror_sum="${mirror_base%/}/SHA256SUMS"
        tmp_file=$(mktemp "${dest_file}.download.XXXXXX") || die '灾备下载临时文件创建失败。'
        if curl -fLsS --connect-timeout 10 -m 180 "$mirror_url" -o "$tmp_file"; then
            if validate_downloaded_asset "$output_file" "$tmp_file"; then
                expect_sum=$(curl -fsS --connect-timeout 8 -m 30 "$mirror_sum" 2>/dev/null | awk -v f="$asset_leaf" '$2==f || $2==("./" f) || $2~(f"$") {print $1; exit}')
                got_sum=$(sha256sum "$tmp_file" | awk '{print $1}')
                if [[ -n "$expect_sum" && "$expect_sum" =~ ^[A-Fa-f0-9]{64}$ && "${got_sum,,}" == "${expect_sum,,}" ]]; then
                    mv -f "$tmp_file" "$dest_file" || { rm -f "$tmp_file"; die '灾备资产原子提交失败。'; }
                    msg "${GREEN}   已从 A-Box 灾备 Release 取得核心资产（SHA256 已校验）。${NC}"
                    return 0
                fi
                msg "${YELLOW}[!] 灾备 SHA256 校验失败或缺少 SHA256SUMS。${NC}"
            fi
        fi
        rm -f "$tmp_file"
    fi
    # Last resort: keep last-good installed binary in place (caller rollback paths).
    die '所有通道（上游 + A-Box 灾备）均无法下载核心资产。请检查网络；已安装的二进制不会被半截覆盖。'
}

fetch_geo_data() {
    local file_name official_url out tmp_out size repo asset release_json asset_json asset_name download_url digest release_ref out_created=0
    file_name="${1:-}"
    official_url="${2:-}"
    out="${3:-}"
    [[ -n "$file_name" && -n "$official_url" ]] || die 'Geo 数据下载参数缺失。'
    [[ "$file_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "Geo 数据文件名非法: $file_name"
    if [[ -z "$out" ]]; then
        out="$(umask 077; mktemp "/tmp/${file_name}.XXXXXX")" || die 'Geo 输出临时文件创建失败。'
        out_created=1
        rm -f -- "$out" || die 'Geo 输出临时文件初始化失败。'
    fi
    [[ ! -L "$out" && ! -d "$out" ]] || die "Geo 输出路径不是普通文件: $out"
    mkdir -p "$(dirname "$out")" || die 'Geo 输出目录创建失败。'
    tmp_out=$(umask 077; mktemp "${out}.download.XXXXXX") || { (( out_created == 1 )) && rm -f -- "$out"; die 'Geo 数据临时文件创建失败。'; }

    if [[ "$official_url" =~ ^https://github.com/([^/]+/[^/]+)/releases/latest/download/([^/?#]+)$ ]]; then
        repo="${BASH_REMATCH[1]}"
        asset="${BASH_REMATCH[2]}"
        release_json=$(github_api_get "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null) || release_json=''
        [[ -n "$release_json" ]] || { rm -f -- "$tmp_out"; die "Geo Release API 请求失败: ${repo}"; }
        asset_json=$(jq -c --arg name "$asset" 'first(.assets[]? | select(.name == $name) | {name:.name,url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
        [[ -n "$asset_json" && "$asset_json" != 'null' ]] || { rm -f -- "$tmp_out"; die "Geo Release asset 未找到: ${asset}"; }
        asset_name=$(jq -r '.name // ""' <<< "$asset_json")
        release_ref=$(jq -r '.tag_name // ""' <<< "$release_json")
        download_url=$(jq -r '.url' <<< "$asset_json")
        digest=$(jq -r '.digest // ""' <<< "$asset_json")
        [[ -n "$asset_name" && -n "$release_ref" ]] || { rm -f -- "$tmp_out"; die 'Geo Release metadata missing asset name or tag.'; }
        valid_github_download_url "$repo" "$download_url" "$release_ref" "$asset_name" || { rm -f -- "$tmp_out"; die 'Geo GitHub Release 下载地址域名/仓库不匹配。'; }
        curl -fLs --connect-timeout 10 -m 90 "$download_url" -o "$tmp_out" || { rm -f -- "$tmp_out"; die "Geo 数据文件 ${file_name} 下载失败。"; }
        if ! verify_github_asset_digest "$tmp_out" "$digest"; then
            rm -f -- "$tmp_out"; (( out_created == 1 )) && rm -f -- "$out"
            die "Geo 数据文件 ${file_name} 官方 digest 校验失败。"
        fi
    else
        rm -f -- "$tmp_out"
        die "Geo 数据 URL 必须是带官方 digest 的 GitHub Release 下载地址；拒绝无 digest 的明文拉取: ${file_name}"
    fi

    size=$(wc -c < "$tmp_out" 2>/dev/null | tr -d ' ')
    [[ -n "$size" && "$size" -gt 500000 ]] || { rm -f -- "$tmp_out"; (( out_created == 1 )) && rm -f -- "$out"; die "Geo 数据文件 ${file_name} 大小异常。"; }
    if head -c 256 "$tmp_out" 2>/dev/null | grep -Eiq '<(html|!doctype)'; then
        rm -f -- "$tmp_out"; (( out_created == 1 )) && rm -f -- "$out"
        die "Geo 数据文件 ${file_name} 看起来是 HTML 错误页。"
    fi
    mv -f -- "$tmp_out" "$out" || { rm -f -- "$tmp_out"; (( out_created == 1 )) && rm -f -- "$out"; die "Geo 数据文件 ${file_name} 原子提交失败。"; }
}

desired_state_valid() { [[ "${1:-}" =~ ^(RUNNING|TRAFFIC_BLOCKED|MANUAL_STOPPED|MAINTENANCE)$ ]]; }
traffic_period_valid() { [[ "${1:-}" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]]; }

# Authoritative traffic state is PAIR ("DESIRED|PERIOD"; PERIOD empty => no block).
# Legacy .desired_state / .traffic-block-state are derived ONLY after pair publish
# succeeds, for older helper readers that have not yet migrated.
read_traffic_pair_fields() {
    local line desired period uid gid mode
    [[ -r "$ABOX_TRAFFIC_PAIR_STATE" && -f "$ABOX_TRAFFIC_PAIR_STATE" && ! -L "$ABOX_TRAFFIC_PAIR_STATE" ]] || return 1
    uid=$(stat -c %u "$ABOX_TRAFFIC_PAIR_STATE" 2>/dev/null) || return 1
    gid=$(stat -c %g "$ABOX_TRAFFIC_PAIR_STATE" 2>/dev/null) || return 1
    mode=$(stat -c %a "$ABOX_TRAFFIC_PAIR_STATE" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    IFS= read -r line < "$ABOX_TRAFFIC_PAIR_STATE" || return 1
    [[ "$line" == *'|'* ]] || return 1
    desired=${line%%|*}
    period=${line#*|}
    desired_state_valid "$desired" || return 1
    if [[ -n "$period" ]]; then
        traffic_period_valid "$period" || return 1
    fi
    printf '%s\n%s\n' "$desired" "$period"
}

commit_traffic_pair_state() {
    local desired="$1" period="${2:-}"
    desired_state_valid "$desired" || return 1
    if [[ -n "$period" ]]; then
        traffic_period_valid "$period" || return 1
    fi
    ensure_abox_dir_owned "$ABOX_DIR" >/dev/null 2>&1 || return 1
    # 1) Atomic pair publish (sole authority for modern readers).
    write_file_atomically_from_stdin "$ABOX_TRAFFIC_PAIR_STATE" 600 <<< "${desired}|${period}" || return 1
    # 2) Derive legacy files only after pair is durable (helpers may still read them).
    write_file_atomically_from_stdin "$ABOX_DESIRED_STATE" 600 <<< "$desired" || return 1
    if [[ -n "$period" ]]; then
        write_file_atomically_from_stdin "$ABOX_TRAFFIC_BLOCK_STATE" 600 <<< "$period" || return 1
    else
        if [[ -e "$ABOX_TRAFFIC_BLOCK_STATE" || -L "$ABOX_TRAFFIC_BLOCK_STATE" ]]; then
            path_tree_has_mountpoint "$ABOX_TRAFFIC_BLOCK_STATE" && return 1
            rm -f -- "$ABOX_TRAFFIC_BLOCK_STATE" || return 1
            [[ ! -e "$ABOX_TRAFFIC_BLOCK_STATE" && ! -L "$ABOX_TRAFFIC_BLOCK_STATE" ]] || return 1
        fi
    fi
}

get_desired_state() {
    local state='RUNNING' uid gid mode pair desired period
    if pair=$(read_traffic_pair_fields); then
        IFS= read -r desired <<< "$pair"
        printf '%s\n' "$desired"
        return 0
    fi
    if [[ -e "$ABOX_DESIRED_STATE" || -L "$ABOX_DESIRED_STATE" ]]; then
        [[ -r "$ABOX_DESIRED_STATE" && -f "$ABOX_DESIRED_STATE" && ! -L "$ABOX_DESIRED_STATE" ]] || return 1
        uid=$(stat -c %u "$ABOX_DESIRED_STATE" 2>/dev/null) || return 1
        gid=$(stat -c %g "$ABOX_DESIRED_STATE" 2>/dev/null) || return 1
        mode=$(stat -c %a "$ABOX_DESIRED_STATE" 2>/dev/null) || return 1
        [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 8#077) == 0 )) || return 1
        IFS= read -r state < "$ABOX_DESIRED_STATE" || return 1
        desired_state_valid "$state" || return 1
    fi
    printf '%s\n' "$state"
}

set_desired_state() {
    local state="$1" period=''
    desired_state_valid "$state" || return 1
    period=$(get_traffic_block_period 2>/dev/null || true)
    commit_traffic_pair_state "$state" "$period"
}

get_traffic_block_period() {
    local period uid gid mode pair desired
    if pair=$(read_traffic_pair_fields); then
        desired=${pair%%$'\n'*}
        period=${pair#*$'\n'}
        [[ -n "$period" ]] || return 1
        printf '%s\n' "$period"
        return 0
    fi
    [[ -r "$ABOX_TRAFFIC_BLOCK_STATE" && -f "$ABOX_TRAFFIC_BLOCK_STATE" && ! -L "$ABOX_TRAFFIC_BLOCK_STATE" ]] || return 1
    uid=$(stat -c %u "$ABOX_TRAFFIC_BLOCK_STATE" 2>/dev/null) || return 1
    gid=$(stat -c %g "$ABOX_TRAFFIC_BLOCK_STATE" 2>/dev/null) || return 1
    mode=$(stat -c %a "$ABOX_TRAFFIC_BLOCK_STATE" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    IFS= read -r period < "$ABOX_TRAFFIC_BLOCK_STATE" || return 1
    traffic_period_valid "$period" || return 1
    printf '%s\n' "$period"
}

set_traffic_block_period() {
    local period="$1" state
    traffic_period_valid "$period" || return 1
    state=$(get_desired_state) || return 1
    commit_traffic_pair_state "$state" "$period"
}

clear_traffic_block_period() {
    local state
    if [[ ! -e "$ABOX_TRAFFIC_BLOCK_STATE" && ! -L "$ABOX_TRAFFIC_BLOCK_STATE" ]] && \
       { ! read_traffic_pair_fields >/dev/null 2>&1 || [[ -z "$(read_traffic_pair_fields | sed -n '2p')" ]]; }; then
        return 0
    fi
    state=$(get_desired_state) || return 1
    commit_traffic_pair_state "$state" ""
}

validate_abox_env_file_for_write() {
    [[ -f "$ABOX_ENV" && ! -L "$ABOX_ENV" ]] || return 1
    path_owned_by_root "$ABOX_ENV" || return 1
    path_mode_has_no_group_other_write "$ABOX_ENV" || return 1
    load_abox_env "$ABOX_ENV" >/dev/null 2>&1 || return 1
}

remove_abox_env_file() {
    [[ ! -e "$ABOX_ENV" && ! -L "$ABOX_ENV" ]] && return 0
    validate_abox_env_file_for_write || return 1
    path_tree_has_mountpoint "$ABOX_ENV" && return 1
    rm -f -- "$ABOX_ENV" || return 1
    [[ ! -e "$ABOX_ENV" && ! -L "$ABOX_ENV" ]]
}

remove_owned_runtime_helper() {
    local path="$1"
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
    auxiliary_content_is_abox_managed "$path" "$path" || return 1
    path_tree_has_mountpoint "$path" && return 1
    rm -f -- "$path" || return 1
    [[ ! -e "$path" && ! -L "$path" ]]
}

update_traffic_state_atomically() {
    local limit="${1:-}" mode="${2:-}" tmp
    validate_abox_env_file_for_write || return 1
    ensure_abox_dir_owned "$ABOX_DIR" >/dev/null 2>&1 || return 1
    tmp=$(mktemp "$ABOX_DIR/.env.A-Box-update.XXXXXX") || return 1
    awk '!/^TRAFFIC_LIMIT_GB=/ && !/^TRAFFIC_LIMIT_MODE=/' "$ABOX_ENV" > "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -n "$limit" ]]; then
        valid_traffic_limit_gb "$limit" || { rm -f "$tmp"; return 1; }
        [[ "$mode" =~ ^(total|rx|tx)$ ]] || { rm -f "$tmp"; return 1; }
        printf 'TRAFFIC_LIMIT_GB=%q\nTRAFFIC_LIMIT_MODE=%q\n' "$limit" "$mode" >> "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ $EUID -eq 0 ]]; then chown root:root "$tmp" || { rm -f "$tmp"; return 1; }; fi
    sync -f "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$ABOX_ENV" || { rm -f "$tmp"; return 1; }
}

reset_protocol_vars() {
    unset UUID VLESS_SNI VISION_SNI XHTTP_SNI VLESS_PORT XHTTP_PORT HY2_BASE_PORT HY2_DOMAIN HY2_UP HY2_DOWN HY2_MASQ_URL
    unset SS_PORT SS_WHITELIST_IP PUBLIC_KEY PBK SHORT_ID HY2_PASS HY2_OBFS SS_PASS
    unset HY2_CERT_SHA256_FP HY2_CERT_PUBKEY_SHA256_B64 HY2_HOP HY2_HOP_IMPL HY2_MONITOR_PORT
    unset HY2_ACME_TYPE HY2_ACME_DNS_PROVIDER HY2_ACME_DNS_CF_API_TOKEN
    unset HY2_URI_PORTS HY2_CLASH_PORTS HY2_SB_PORTS HY2_RANGE_START HY2_RANGE_END ENABLE_KEEPALIVE
}

path_parent_chain_safe() {
    local target="$1" current
    [[ "$target" == /* ]] || return 1
    current=$(dirname -- "$target")
    while :; do
        [[ "$current" == '/' ]] && return 0
        [[ ! -L "$current" ]] || return 1
        if [[ -e "$current" && ! -d "$current" ]]; then
            return 1
        fi
        current=$(dirname -- "$current")
    done
}

write_file_atomically_from_stdin() {
    local dest="$1" mode="${2:-600}" dir tmp
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    [[ ! -e "$dest" && ! -L "$dest" || -f "$dest" ]] || return 1
    [[ ! -L "$dest" && ! -d "$dest" ]] || return 1
    path_parent_chain_safe "$dest" || return 1
    if [[ -e "$dest" || -L "$dest" ]] && path_is_mountpoint "$dest"; then
        return 1
    fi
    dir=$(dirname "$dest")
    if [[ -L "$dir" || ( -e "$dir" && ! -d "$dir" ) ]]; then
        return 1
    fi
    [[ -d "$dir" ]] || mkdir -p "$dir" || return 1
    tmp=$(mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    cat > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod "$mode" "$tmp" || { rm -f -- "$tmp"; return 1; }
    if [[ $EUID -eq 0 ]]; then chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }; fi
    sync -f "$tmp" 2>/dev/null || true
    mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
    sync -f "$dir" 2>/dev/null || true
}

write_env() {
    local env_core="${1:-${CORE:-}}" env_mode="${2:-${MODE:-}}" old_traffic_limit_gb='' old_traffic_limit_mode='' tmp
    [[ -n "$env_core" && -n "$env_mode" ]] || die 'A-Box 状态写入缺少 CORE/MODE，拒绝覆盖现有状态。'
    [[ ! -L "$ABOX_DIR" ]] || die 'A-Box 状态目录是符号链接，拒绝写入。'
    if [[ -e "$ABOX_ENV" ]]; then
        [[ -f "$ABOX_ENV" && ! -L "$ABOX_ENV" ]] || die 'A-Box 状态文件不是安全的普通文件，拒绝覆盖。'
        path_owned_by_root "$ABOX_ENV" || die 'A-Box 状态文件属主不是 root:root，拒绝覆盖。'
        path_mode_has_no_group_other_write "$ABOX_ENV" || die 'A-Box 状态文件权限不安全，拒绝覆盖。'
    fi
    if [[ -f "$ABOX_ENV" && ! -L "$ABOX_ENV" ]]; then
        old_traffic_limit_gb=$(grep '^TRAFFIC_LIMIT_GB=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
        old_traffic_limit_mode=$(grep '^TRAFFIC_LIMIT_MODE=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
        if [[ -z "$old_traffic_limit_gb" ]] || ! valid_traffic_limit_gb "$old_traffic_limit_gb" || [[ "$old_traffic_limit_mode" != total && "$old_traffic_limit_mode" != rx && "$old_traffic_limit_mode" != tx ]]; then
            old_traffic_limit_gb=''
            old_traffic_limit_mode=''
        fi
    fi
    umask 077
    install -d -m 700 "$ABOX_DIR" || die 'A-Box 状态目录创建失败。'
    tmp=$(mktemp "$ABOX_DIR/.env.A-Box-new.XXXXXX") || die 'A-Box 状态临时文件创建失败。'
    {
        printf 'CORE=%s\n' "$(shell_quote "$env_core")"
        printf 'MODE=%s\n' "$(shell_quote "$env_mode")"
        printf 'UUID=%s\n' "$(shell_quote "${UUID:-}")"
        printf 'VLESS_SNI=%s\n' "$(shell_quote "${VLESS_SNI:-}")"
        printf 'VISION_SNI=%s\n' "$(shell_quote "${VISION_SNI:-}")"
        printf 'XHTTP_SNI=%s\n' "$(shell_quote "${XHTTP_SNI:-}")"
        printf 'VLESS_PORT=%s\n' "$(shell_quote "${VLESS_PORT:-}")"
        printf 'XHTTP_PORT=%s\n' "$(shell_quote "${XHTTP_PORT:-}")"
        printf 'HY2_BASE_PORT=%s\n' "$(shell_quote "${HY2_BASE_PORT:-}")"
        printf 'HY2_DOMAIN=%s\n' "$(shell_quote "${HY2_DOMAIN:-}")"
        printf 'HY2_UP=%s\n' "$(shell_quote "${HY2_UP:-}")"
        printf 'HY2_DOWN=%s\n' "$(shell_quote "${HY2_DOWN:-}")"
        printf 'HY2_MASQ_URL=%s\n' "$(shell_quote "${HY2_MASQ_URL:-}")"
        printf 'SS_PORT=%s\n' "$(shell_quote "${SS_PORT:-}")"
        printf 'PUBLIC_KEY=%s\n' "$(shell_quote "${PUBLIC_KEY:-${PBK:-}}")"
        printf 'SHORT_ID=%s\n' "$(shell_quote "${SHORT_ID:-}")"
        printf 'HY2_PASS=%s\n' "$(shell_quote "${HY2_PASS:-}")"
        printf 'HY2_OBFS=%s\n' "$(shell_quote "${HY2_OBFS:-}")"
        printf 'SS_PASS=%s\n' "$(shell_quote "${SS_PASS:-}")"
        printf 'LINK_IP=%s\n' "$(shell_quote "${LINK_IP:-${GLOBAL_PUBLIC_IP:-}}")"
        printf 'HY2_CERT_SHA256_FP=%s\n' "$(shell_quote "${HY2_CERT_SHA256_FP:-}")"
        printf 'HY2_CERT_PUBKEY_SHA256_B64=%s\n' "$(shell_quote "${HY2_CERT_PUBKEY_SHA256_B64:-}")"
        printf 'HY2_HOP=%s\n' "$(shell_quote "${HY2_HOP:-}")"
        printf 'HY2_HOP_IMPL=%s\n' "$(shell_quote "${HY2_HOP_IMPL:-none}")"
        printf 'HY2_MONITOR_PORT=%s\n' "$(shell_quote "${HY2_MONITOR_PORT:-}")"
        printf 'HY2_ACME_TYPE=%s\n' "$(shell_quote "${HY2_ACME_TYPE:-http}")"
        printf 'HY2_ACME_DNS_PROVIDER=%s\n' "$(shell_quote "${HY2_ACME_DNS_PROVIDER:-}")"
        printf 'HY2_ACME_DNS_CF_API_TOKEN=%s\n' "$(shell_quote "${HY2_ACME_DNS_CF_API_TOKEN:-}")"
        printf 'HY2_URI_PORTS=%s\n' "$(shell_quote "${HY2_URI_PORTS:-}")"
        printf 'HY2_CLASH_PORTS=%s\n' "$(shell_quote "${HY2_CLASH_PORTS:-}")"
        printf 'HY2_SB_PORTS=%s\n' "$(shell_quote "${HY2_SB_PORTS:-}")"
        printf 'HY2_RANGE_START=%s\n' "$(shell_quote "${HY2_RANGE_START:-}")"
        printf 'HY2_RANGE_END=%s\n' "$(shell_quote "${HY2_RANGE_END:-}")"
        printf 'INGRESS_IF=%s\n' "$(shell_quote "${INGRESS_IF:-}")"
        printf 'ENABLE_KEEPALIVE=%s\n' "$(shell_quote "${ENABLE_KEEPALIVE:-}")"
        [[ -n "$old_traffic_limit_gb" ]] && printf 'TRAFFIC_LIMIT_GB=%s\n' "$(shell_quote "$old_traffic_limit_gb")"
        [[ -n "$old_traffic_limit_mode" ]] && printf 'TRAFFIC_LIMIT_MODE=%s\n' "$(shell_quote "$old_traffic_limit_mode")"
        :
    } > "$tmp" || { rm -f -- "$tmp"; die 'A-Box 状态写入失败。'; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; die 'A-Box 状态权限设置失败。'; }
    mv -f -- "$tmp" "$ABOX_ENV" || { rm -f -- "$tmp"; die 'A-Box 状态原子提交失败。'; }
}

validate_fail2ban_config_or_die() {
    command -v fail2ban-client >/dev/null 2>&1 || return 0
    local out sample
    if fail2ban-client -h 2>&1 | grep -E -- '(^|[[:space:]])-t([,[:space:]]|$)|--test' >/dev/null; then
        if ! out=$(fail2ban-client -t 2>&1); then
            msg "${YELLOW}[!] Fail2Ban 全局配置校验失败；可能由系统其它 jail 引起，A-Box 不会因此覆盖或删除其它 jail。${NC}"
            printf '%s\n' "$out" >&2
        fi
    else
        if ! out=$(fail2ban-client -d 2>&1); then
            msg "${YELLOW}[!] Fail2Ban 全局配置 dump 失败；可能由系统其它 jail 引起。${NC}"
            printf '%s\n' "$out" >&2
        fi
    fi
    if command -v fail2ban-regex >/dev/null 2>&1 && [[ -r /etc/fail2ban/filter.d/A-Box.conf ]]; then
        sample=$(umask 077; mktemp /tmp/A-Box-f2b-sample.XXXXXX) || die 'Fail2Ban sample creation failed.'
        cat > "$sample" <<'EOF_F2B_SAMPLE' || { rm -f -- "$sample"; die 'Fail2Ban sample write failed.'; }
2026-07-25T10:00:00Z process connection from 203.0.113.7:54321: message authentication failed
2026-07-25T10:00:01Z authentication failed from [2001:db8::7]:443
2026-07-25T10:00:02Z proxy/vless/inbound: invalid request from 198.51.100.9:44321 > proxy/vless/encoding
2026-07-25T10:00:03Z client=198.51.100.8 rejected
EOF_F2B_SAMPLE
        out=$(fail2ban-regex "$sample" /etc/fail2ban/filter.d/A-Box.conf 2>&1) || { rm -f "$sample"; printf '%s\n' "$out" >&2; die 'Fail2Ban 正则测试执行失败。'; }
        rm -f "$sample"
        grep -Eq '^[[:space:]]*[2-9][0-9]*[[:space:]]+total|Failregex:[[:space:]]*[2-9]' <<< "$out" || { printf '%s\n' "$out" >&2; die 'Fail2Ban 过滤器未匹配代表性认证失败日志。'; }
    fi
}

abox_log_files() {
    printf '%s\n' /var/log/A-Box-xray-access.log /var/log/A-Box-xray-error.log /var/log/A-Box-singbox.log /var/log/A-Box-hysteria.log /var/log/A-Box-traffic.log
}

abox_runtime_identity() {
    local family="$1"
    case "$family" in
        xray) printf '%s\t%s\n' "$ABOX_RUNTIME_XRAY_USER" "$ABOX_RUNTIME_XRAY_GROUP" ;;
        sing-box|singbox) printf '%s\t%s\n' "$ABOX_RUNTIME_SINGBOX_USER" "$ABOX_RUNTIME_SINGBOX_GROUP" ;;
        hysteria) printf '%s\t%s\n' "$ABOX_RUNTIME_HYSTERIA_USER" "$ABOX_RUNTIME_HYSTERIA_GROUP" ;;
        *) return 1 ;;
    esac
}

ensure_abox_runtime_identity() {
    local family="$1" user group uid gid shell
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || return 1
    getent group "$group" >/dev/null 2>&1 || {
        if command -v groupadd >/dev/null 2>&1; then
            groupadd --system "$group" >/dev/null 2>&1 || getent group "$group" >/dev/null 2>&1 || return 1
        elif [[ "${release:-}" == 'alpine' ]] && command -v addgroup >/dev/null 2>&1; then
            addgroup -S "$group" >/dev/null 2>&1 || getent group "$group" >/dev/null 2>&1 || return 1
        elif command -v addgroup >/dev/null 2>&1; then
            addgroup --system "$group" >/dev/null 2>&1 || getent group "$group" >/dev/null 2>&1 || return 1
        else
            return 1
        fi
    }
    if ! getent passwd "$user" >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid "$group" "$user" >/dev/null 2>&1 || return 1
        elif [[ "${release:-}" == 'alpine' ]] && command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -s /sbin/nologin -G "$group" "$user" >/dev/null 2>&1 || return 1
        elif command -v adduser >/dev/null 2>&1; then
            adduser --system --no-create-home --home /nonexistent --shell /sbin/nologin --ingroup "$group" "$user" >/dev/null 2>&1 || return 1
        else
            return 1
        fi
    fi
    uid=$(id -u "$user" 2>/dev/null) || return 1
    gid=$(id -g "$user" 2>/dev/null) || return 1
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
    (( uid != 0 && gid != 0 )) || return 1
    shell=$(getent passwd "$user" | awk -F: '{print $7}')
    [[ "$shell" == '/usr/sbin/nologin' || "$shell" == '/sbin/nologin' || "$shell" == '/bin/false' ]] || return 1
}

prepare_abox_runtime_config_dir() {
    local family="$1" dir="$2" user group gid mode nlink
    case "$family:$dir" in
        sing-box:/etc/sing-box|hysteria:/etc/hysteria) ;;
        *) return 1 ;;
    esac
    ensure_abox_runtime_identity "$family" || return 1
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || return 1
    path_parent_chain_safe "$dir/.A-Box-config" || return 1
    [[ ! -L "$dir" && (! -e "$dir" || -d "$dir") ]] || return 1
    install -d -o root -g "$group" -m 750 -- "$dir" || return 1
    gid=$(getent group "$group" 2>/dev/null | awk -F: '{print $3}')
    [[ "$gid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$(stat -c %u:%g "$dir" 2>/dev/null || true)" == "0:$gid" ]] || return 1
    mode=$(stat -c %a "$dir" 2>/dev/null) || return 1
    nlink=$(stat -c %h "$dir" 2>/dev/null) || return 1
    [[ "$nlink" =~ ^[2-9][0-9]*$ && "$mode" =~ ^0?750$ ]] || return 1
}

prepare_abox_runtime_read_file() {
    local path="$1" family="$2" user group
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || return 1
    [[ -f "$path" && ! -L "$path" ]] || return 1
    path_parent_chain_safe "$path" || return 1
    [[ "$(stat -c %u:%g "$path" 2>/dev/null || true)" == 0:* ]] || return 1
    [[ "$(stat -c %h "$path" 2>/dev/null || true)" == 1 ]] || return 1
    chown "root:$group" "$path" || return 1
    chmod 640 "$path" || return 1
}

prepare_abox_runtime_write_file() {
    local path="$1" family="$2" user group
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || return 1
    path_parent_chain_safe "$path" || return 1
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        install -o root -g "$group" -m 660 /dev/null "$path" || return 1
        return 0
    fi
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -c %u:%g "$path" 2>/dev/null || true)" == 0:* ]] || return 1
    [[ "$(stat -c %h "$path" 2>/dev/null || true)" == 1 ]] || return 1
    chown "root:$group" "$path" || return 1
    chmod 660 "$path" || return 1
}

prepare_abox_runtime_permissions() {
    local family="$1"
    ensure_abox_runtime_identity "$family" || return 1
    case "$family" in
        xray)
            prepare_abox_runtime_read_file /usr/local/etc/xray/config.json xray || return 1
            prepare_abox_runtime_write_file /var/log/A-Box-xray-access.log xray || return 1
            prepare_abox_runtime_write_file /var/log/A-Box-xray-error.log xray || return 1
            ;;
        sing-box)
            prepare_abox_runtime_config_dir sing-box /etc/sing-box || return 1
            prepare_abox_runtime_read_file /etc/sing-box/config.json sing-box || return 1
            [[ ! -e /etc/sing-box/hy2.crt ]] || prepare_abox_runtime_read_file /etc/sing-box/hy2.crt sing-box || return 1
            [[ ! -e /etc/sing-box/hy2.key ]] || prepare_abox_runtime_read_file /etc/sing-box/hy2.key sing-box || return 1
            prepare_abox_runtime_write_file /var/log/A-Box-singbox.log sing-box || return 1
            ;;
        hysteria)
            prepare_abox_runtime_config_dir hysteria /etc/hysteria || return 1
            [[ ! -e /etc/hysteria/acme ]] || prepare_hysteria_acme_dir_ownership || return 1
            prepare_abox_runtime_read_file /etc/hysteria/config.yaml hysteria || return 1
            [[ ! -e /etc/hysteria/server.crt ]] || prepare_abox_runtime_read_file /etc/hysteria/server.crt hysteria || return 1
            [[ ! -e /etc/hysteria/server.key ]] || prepare_abox_runtime_read_file /etc/hysteria/server.key hysteria || return 1
            prepare_abox_runtime_write_file /var/log/A-Box-hysteria.log hysteria || return 1
            ;;
        *) return 1 ;;
    esac
}

assert_abox_log_file_safe() {
    local path="$1" uid gid mode nlink
    [[ "$path" == /var/log/A-Box-*.log ]] || return 1
    [[ -d /var/log && ! -L /var/log ]] || return 1
    path_parent_chain_safe "$path" || return 1
    if [[ ! -e "$path" && ! -L "$path" ]]; then return 0; fi
    [[ -f "$path" && ! -L "$path" ]] || return 1
    uid=$(stat -c %u "$path" 2>/dev/null) || return 1
    gid=$(stat -c %g "$path" 2>/dev/null) || return 1
    mode=$(stat -c %a "$path" 2>/dev/null) || return 1
    nlink=$(stat -c %h "$path" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$nlink" == 1 ]] || return 1
    if [[ "$gid" == 0 && "$mode" =~ ^0?600$ ]]; then return 0; fi
    for _group in "$ABOX_RUNTIME_XRAY_GROUP" "$ABOX_RUNTIME_SINGBOX_GROUP" "$ABOX_RUNTIME_HYSTERIA_GROUP"; do
        _gid=$(getent group "$_group" 2>/dev/null | awk -F: '{print $3}')
        [[ -n "$_gid" && "$gid" == "$_gid" && "$mode" =~ ^0?660$ ]] && return 0
    done
    return 1
}

ensure_abox_log_file() {
    local path="$1" family='' user group
    assert_abox_log_file_safe "$path" || die "拒绝覆盖非安全 A-Box 日志文件: $path"
    [[ -e "$path" ]] && return 0
    case "$path" in
        /var/log/A-Box-xray-*.log) family=xray ;;
        /var/log/A-Box-singbox.log) family=sing-box ;;
        /var/log/A-Box-hysteria.log) family=hysteria ;;
        /var/log/A-Box-traffic.log) install -o root -g root -m 600 /dev/null "$path" || die "A-Box 日志文件创建失败: $path"; return 0 ;;
        *) return 1 ;;
    esac
    ensure_abox_runtime_identity "$family" || die "A-Box 运行用户创建失败: $family"
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || die "A-Box 运行用户解析失败: $family"
    install -o root -g "$group" -m 660 /dev/null "$path" || die "A-Box 日志文件创建失败: $path"
}

remove_abox_log_files() {
    local path
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        [[ -e "$path" || -L "$path" ]] || continue
        assert_abox_log_file_safe "$path" || return 1
        path_tree_has_mountpoint "$path" && return 1
        rm -f -- "$path" || return 1
        [[ ! -e "$path" && ! -L "$path" ]] || return 1
    done < <(abox_log_files)
}

setup_active_defense() {
    msg "${YELLOW}[*] 正在挂载私有日志与 Fail2Ban 主动防御矩阵...${NC}"
    while IFS= read -r log_file; do
        [[ -n "$log_file" ]] || continue
        ensure_abox_log_file "$log_file"
    done < <(abox_log_files)
    assert_abox_auxiliary_safe /etc/logrotate.d/A-Box
    write_file_atomically_from_stdin /etc/logrotate.d/A-Box 644 <<'EOF_LOGROTATE' || die 'logrotate 配置原子写入失败。'
# Managed by A-Box
/var/log/A-Box-*.log {
    su root root
    daily
    rotate 2
    size 50M
    missingok
    notifempty
    copytruncate
    compress
    # No "create …": copytruncate keeps the existing inode/ownership so
    # abox-xray / abox-singbox / abox-hysteria (mode 0660 root:group) can keep writing.
}
EOF_LOGROTATE
    if command -v fail2ban-client >/dev/null 2>&1; then
        local tcp_ports='' udp_ports='' jail_tmp='' f2b_action='' f2b_backend='' f2b_tcp_action='' f2b_udp_action=''
        path_parent_chain_safe /etc/fail2ban/filter.d/A-Box.conf || die 'Fail2Ban filter 父目录链不安全，拒绝创建或写入。'
        path_parent_chain_safe /etc/fail2ban/jail.d/A-Box.local || die 'Fail2Ban jail 父目录链不安全，拒绝创建或写入。'
        mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d || die 'Fail2Ban 目录创建失败。'
        assert_abox_auxiliary_safe /etc/fail2ban/filter.d/A-Box.conf
        assert_abox_auxiliary_safe /etc/fail2ban/jail.d/A-Box.local
        jail_tmp=$(mktemp /etc/fail2ban/jail.d/.A-Box.local.A-Box-new.XXXXXX) || die 'Fail2Ban jail 临时文件创建失败。'
        write_file_atomically_from_stdin /etc/fail2ban/filter.d/A-Box.conf 644 <<'EOF_F2B_FILTER' || { rm -f -- "$jail_tmp"; die 'Fail2Ban filter 原子写入失败。'; }
# Managed by A-Box
[Definition]
failregex = ^.*(?:authentication failed|message authentication failed).*?(?:from|client[=:])\s*\[?<HOST>\]?(?::[0-9]+)?(?:\s|:|$).*$
            ^.*(?:from|client[=:])\s*\[?<HOST>\]?(?::[0-9]+)?(?:\s|:).*?(?:authentication failed|message authentication failed).*$
            ^.*invalid request from[[:space:]]+\[?<HOST>\]?(?::[0-9]+)?(?:[[:space:]]|>|:|$).*$
ignoreregex =
EOF_F2B_FILTER
        [[ -n "${VLESS_PORT:-}" ]] && tcp_ports+="${VLESS_PORT},"
        [[ -n "${XHTTP_PORT:-}" ]] && tcp_ports+="${XHTTP_PORT},"
        [[ -n "${SS_PORT:-}" ]] && { tcp_ports+="${SS_PORT},"; udp_ports+="${SS_PORT},"; }
        if [[ "${HY2_HOP:-}" == true && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then udp_ports+="${HY2_RANGE_START}:${HY2_RANGE_END},"; elif [[ -n "${HY2_BASE_PORT:-}" ]]; then udp_ports+="${HY2_BASE_PORT},"; fi
        tcp_ports="${tcp_ports%,}"; udp_ports="${udp_ports%,}"
        if [[ -n "$tcp_ports" || -n "$udp_ports" ]]; then
            f2b_backend=$(firewall_backend) || { rm -f -- "$jail_tmp"; die '无法确定 Fail2Ban 防火墙后端。'; }
            case "$f2b_backend" in
                firewalld) f2b_action='firewallcmd-multiport' ;;
                ufw) f2b_action='ufw' ;;
                iptables) f2b_action='iptables-multiport' ;;
                *) rm -f -- "$jail_tmp"; die "不支持的 Fail2Ban 防火墙后端: $f2b_backend" ;;
            esac
            [[ -r "/etc/fail2ban/action.d/${f2b_action}.conf" ]] || {
                rm -f -- "$jail_tmp"
                die "Fail2Ban action 定义不存在: ${f2b_action}"
            }
            if [[ "$f2b_action" == 'ufw' ]]; then
                # Stock Fail2Ban UFW action blocks the offending source host-wide;
                # do not attach misleading port/protocol arguments to it.
                f2b_tcp_action='ufw[name=A-Box-tcp]'
                f2b_udp_action='ufw[name=A-Box-udp]'
            else
                f2b_tcp_action="${f2b_action}[name=A-Box-tcp, port=\"${tcp_ports}\", protocol=tcp]"
                f2b_udp_action="${f2b_action}[name=A-Box-udp, port=\"${udp_ports}\", protocol=udp]"
            fi
        fi
        printf '%s\n' '# Managed by A-Box' > "$jail_tmp" || { rm -f -- "$jail_tmp"; die 'Fail2Ban jail file initialization failed.'; }
        if [[ -n "$tcp_ports" ]]; then cat >> "$jail_tmp" <<EOF_F2B_TCP
[A-Box-tcp]
enabled = true
ignoreip = 127.0.0.1/8 ::1
port = ${tcp_ports}
filter = A-Box
logpath = /var/log/A-Box-xray-error.log
          /var/log/A-Box-singbox.log
          /var/log/A-Box-hysteria.log
maxretry = 8
findtime = 120
bantime = 3600
action = ${f2b_tcp_action}

EOF_F2B_TCP
        fi
        if [[ -n "$udp_ports" ]]; then cat >> "$jail_tmp" <<EOF_F2B_UDP
[A-Box-udp]
enabled = true
ignoreip = 127.0.0.1/8 ::1
port = ${udp_ports}
filter = A-Box
logpath = /var/log/A-Box-singbox.log
          /var/log/A-Box-hysteria.log
maxretry = 8
findtime = 120
bantime = 3600
action = ${f2b_udp_action}
EOF_F2B_UDP
        fi
        if [[ -n "$tcp_ports" || -n "$udp_ports" ]]; then
            chmod 644 "$jail_tmp" || { rm -f -- "$jail_tmp"; die 'Fail2Ban jail 权限设置失败。'; }
            mv -f -- "$jail_tmp" /etc/fail2ban/jail.d/A-Box.local || { rm -f -- "$jail_tmp"; die 'Fail2Ban jail 原子提交失败。'; }
            validate_fail2ban_config_or_die
            if [[ "${INIT_SYS:-}" == systemd ]]; then
                systemctl restart fail2ban >/dev/null 2>&1 || msg "${YELLOW}[!] Fail2Ban 重启失败；不影响 A-Box 核心服务提交。${NC}"
            else
                rc-service fail2ban restart >/dev/null 2>&1 || msg "${YELLOW}[!] Fail2Ban 重启失败；不影响 A-Box 核心服务提交。${NC}"
            fi
        else
            rm -f -- "$jail_tmp"
            remove_owned_auxiliary_path /etc/fail2ban/jail.d/A-Box.local || die '空的 A-Box Fail2Ban jail 删除失败。'
        fi
    fi
}


hysteria_official_hop_firewall_ok() {
    local start="${1:-${HY2_RANGE_START:-}}" end="${2:-${HY2_RANGE_END:-}}" first="${3:-${HY2_MONITOR_PORT:-${HY2_RANGE_START:-}}}"
    local first_other=''
    [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$first" =~ ^[0-9]+$ ]] || return 1
    (( 10#$start <= 10#$end && 10#$first <= 10#$end )) || return 1
    first_other=$((10#$start + 1))
    if command -v iptables >/dev/null 2>&1; then
        if iptables -w -t nat -S PREROUTING 2>/dev/null | grep -Eq -- "-p udp[[:space:]].*--dport (${start}:${end}|${first_other}:${end}) .*REDIRECT --to-ports ${first}([[:space:]]|$)"; then
            if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
                command -v ip6tables >/dev/null 2>&1 && ip6tables -w -t nat -S PREROUTING 2>/dev/null | grep -Eq -- "-p udp[[:space:]].*--dport (${start}:${end}|${first_other}:${end}) .*REDIRECT --to-ports ${first}([[:space:]]|$)" || return 1
            fi
            return 0
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset 2>/dev/null | grep -Eq -- "udp dport (${start}-${end}|${first_other}-${end}).*redirect to :${first}([[:space:]]|$)" && return 0
    fi
    return 1
}


setup_health_monitor() {
    msg "${YELLOW}[*] 正在注入带锁、连续失败阈值与退避的 L4 健康探针...${NC}"
    install -d -m 700 "$ABOX_DIR" || die '无法创建健康探针目录。'
    write_file_atomically_from_stdin "$ABOX_DIR/socket_probe.sh" 700 <<'EOF_PROBE' || die '健康探针原子写入失败。'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
ENV=/etc/ddr/.env
LOCK=/run/A-Box-socket-probe.lock
STATE=/run/A-Box-socket-probe.fail
DESIRED=/etc/ddr/.desired_state
PAIR_STATE=/etc/ddr/.traffic-pair-state
INIT_SYS_EXPECTED='unknown'
exec 9>>"$LOCK" || exit 0
flock -n 9 || exit 0
RUNTIME_LOCK=/run/A-Box.lock
acquire_abox_runtime_guard() {
    local FALLBACK_DIR=/run/A-Box.lock.d fb_pid fb_start fb_actual mode
    [[ -d /run && ! -L /run ]] || exit 0
    # If a live fallback lock is held by another A-Box process, yield. Helpers
    # must not treat an idle LOCK_FILE flock as free while main owns fallback.
    if [[ -d "$FALLBACK_DIR" && ! -L "$FALLBACK_DIR" && -r "$FALLBACK_DIR/pid" && -r "$FALLBACK_DIR/starttime" ]]; then
        [[ "$(stat -c %u:%g "$FALLBACK_DIR" 2>/dev/null || true)" == 0:0 ]] || exit 0
        mode=$(stat -c %a "$FALLBACK_DIR" 2>/dev/null) || exit 0
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
        (( (8#$mode & 8#077) == 0 )) || exit 0
        IFS= read -r fb_pid < "$FALLBACK_DIR/pid" || exit 0
        IFS= read -r fb_start < "$FALLBACK_DIR/starttime" || exit 0
        if [[ "$fb_pid" =~ ^[0-9]+$ && -d "/proc/$fb_pid" ]]; then
            fb_actual=$(awk '{print $22}' "/proc/${fb_pid}/stat" 2>/dev/null || true)
            [[ -n "$fb_actual" && "$fb_actual" == "$fb_start" ]] && exit 0
        fi
    fi
    # /run is recreated on reboot; recreate the shared lock inode on demand.
    if [[ ! -e "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]]; then
        ( umask 077; set -C; : > "$RUNTIME_LOCK" ) 2>/dev/null || true
    fi
    [[ -f "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]] || exit 0
    [[ "$(stat -c %u:%g "$RUNTIME_LOCK" 2>/dev/null || true)" == 0:0 ]] || exit 0
    mode=$(stat -c %a "$RUNTIME_LOCK" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
    (( (8#$mode & 8#077) == 0 )) || exit 0
    exec 10>>"$RUNTIME_LOCK" || exit 0
    flock -n 10 || exit 0
}
acquire_abox_runtime_guard
load_state() {
    local parsed key value uid gid mode
    [[ -r "$ENV" && -f "$ENV" && ! -L "$ENV" ]] || return 1
    uid=$(stat -c %u "$ENV" 2>/dev/null) || return 1
    gid=$(stat -c %g "$ENV" 2>/dev/null) || return 1
    mode=$(stat -c %a "$ENV" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    parsed=$(umask 077; mktemp /tmp/A-Box-helper-env.XXXXXX) || return 1
    if ! python3 - "$ENV" > "$parsed" <<'PY_HELPER_ENV'; then
import shlex,sys
allowed={"CORE","MODE","VLESS_PORT","XHTTP_PORT","HY2_MONITOR_PORT","HY2_HOP","HY2_HOP_IMPL","HY2_RANGE_START","HY2_RANGE_END","INGRESS_IF","SS_PORT","TRAFFIC_LIMIT_GB","TRAFFIC_LIMIT_MODE"}
seen=set()
with open(sys.argv[1],encoding="utf-8",errors="strict") as h:
    for raw in h:
        line=raw.rstrip("\n")
        if not line or line.lstrip().startswith("#"): continue
        if "=" not in line: raise SystemExit(1)
        key,val=line.split("=",1)
        if key not in allowed: continue
        if key in seen or val.startswith("$'"): raise SystemExit(1)
        parts=shlex.split(val,posix=True)
        if len(parts)!=1 or any(c in parts[0] for c in "\x00\r\n"): raise SystemExit(1)
        seen.add(key)
        sys.stdout.buffer.write(key.encode("ascii")+b"\0"+parts[0].encode("utf-8")+b"\0")
PY_HELPER_ENV
        rm -f "$parsed"
        return 1
    fi
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do printf -v "$key" '%s' "$value"; done < "$parsed"
    rm -f "$parsed"
}
is_systemd() { [[ "$INIT_SYS_EXPECTED" == systemd ]]; }
service_is_abox_managed() {
    local srv="$1" unit
    if is_systemd; then unit="/etc/systemd/system/${srv}.service"; else unit="/etc/init.d/${srv}"; fi
    [[ -f "$unit" && ! -L "$unit" ]] && grep -Fxq '# Managed by A-Box' "$unit" 2>/dev/null
}
expected_exe() { case "$1" in xray) echo /usr/local/bin/xray;; sing-box) echo /usr/local/bin/sing-box;; hysteria) echo /usr/local/bin/hysteria;; *) return 1;; esac; }
service_active_owned() {
    local srv="$1" pid='' exe
    service_is_abox_managed "$srv" || return 1
    if is_systemd; then
        systemctl is-active --quiet "$srv" || return 1
        pid=$(systemctl show -p MainPID --value "$srv" 2>/dev/null || true)
    else
        rc-service "$srv" status >/dev/null 2>&1 || return 1
        [[ -r "/run/${srv}.pid" ]] && pid=$(cat "/run/${srv}.pid" 2>/dev/null || true)
    fi
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
    exe=$(expected_exe "$srv") || return 1
    [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" == "$exe" ]] || return 1
    SERVICE_PID="$pid"
}
socket_owned_by_pid() {
    local proto="$1" port="$2" pid="$3" flags
    command -v ss >/dev/null 2>&1 || return 2
    [[ "$port" =~ ^[0-9]+$ && "$pid" =~ ^[0-9]+$ ]] || return 1
    case "$proto" in tcp) flags='-H -nltp' ;; udp) flags='-H -nlup' ;; *) return 1 ;; esac
    # shellcheck disable=SC2086
    ss $flags 2>/dev/null | awk -v p="$port" -v pid="$pid" '
        $4 ~ ("[:.]" p "$") && $0 ~ ("pid=" pid "([,)]|$)") { found=1 }
        END { exit(found ? 0 : 1) }
    '
}
check_socket_or_fail() {
    local proto="$1" port="$2" pid="$3" srv="$4" rc
    socket_owned_by_pid "$proto" "$port" "$pid"
    rc=$?
    case "$rc" in
        0) return 0 ;;
        1) failed_srv="$srv"; return 0 ;;
        2) exit 0 ;;
        *) exit 0 ;;
    esac
}
restart_owned() {
    local srv="$1"
    service_is_abox_managed "$srv" || return 1
    if is_systemd; then systemctl restart "$srv" >/dev/null 2>&1; else rc-service "$srv" restart >/dev/null 2>&1; fi
}
load_state || exit 0
[[ -n "${CORE:-}" ]] || exit 0
desired=RUNNING
if [[ -r "$PAIR_STATE" && -f "$PAIR_STATE" && ! -L "$PAIR_STATE" ]] && [[ "$(stat -c %u:%g "$PAIR_STATE" 2>/dev/null)" == 0:0 ]]; then
    mode=$(stat -c %a "$PAIR_STATE" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || exit 0
    IFS= read -r _pair < "$PAIR_STATE" || exit 0
    desired=${_pair%%|*}
elif [[ -e "$DESIRED" || -L "$DESIRED" ]]; then
    [[ -r "$DESIRED" && -f "$DESIRED" && ! -L "$DESIRED" ]] || exit 0
    [[ "$(stat -c %u:%g "$DESIRED" 2>/dev/null)" == 0:0 ]] || exit 0
    mode=$(stat -c %a "$DESIRED" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || exit 0
    IFS= read -r desired < "$DESIRED" || exit 0
fi
[[ "$desired" == RUNNING ]] || { rm -f "$STATE"; exit 0; }
IPT=$(command -v iptables || echo /sbin/iptables)
IPT6=$(command -v ip6tables || echo /sbin/ip6tables)
has_ipv6() { local _p; _p=$(read_ip_pref 2>/dev/null || printf dual); [[ "$_p" == ipv4 ]] && return 1; ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { found=1 } END { exit !found }' || ip -6 route show default 2>/dev/null | awk '/^default/ { found=1 } END { exit !found }'; }
ipv6_nat_redirect_usable() { command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -t nat -L PREROUTING >/dev/null 2>&1; }
hysteria_official_hop_firewall_ok() {
    local start="${HY2_RANGE_START:-}" end="${HY2_RANGE_END:-}" first="${HY2_MONITOR_PORT:-${HY2_RANGE_START:-}}" first_other=''
    [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$first" =~ ^[0-9]+$ ]] || return 1
    (( 10#$start <= 10#$end && 10#$first <= 10#$end )) || return 1
    first_other=$((10#$start + 1))
    if command -v iptables >/dev/null 2>&1 && iptables -w -t nat -S PREROUTING 2>/dev/null | grep -Eq -- "-p udp[[:space:]].*--dport (${start}:${end}|${first_other}:${end}) .*REDIRECT --to-ports ${first}([[:space:]]|$)"; then
        if has_ipv6; then
            command -v ip6tables >/dev/null 2>&1 && ip6tables -w -t nat -S PREROUTING 2>/dev/null | grep -Eq -- "-p udp[[:space:]].*--dport (${start}:${end}|${first_other}:${end}) .*REDIRECT --to-ports ${first}([[:space:]]|$)" || return 1
        fi
        return 0
    fi
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset 2>/dev/null | grep -Eq -- "udp dport (${start}-${end}|${first_other}-${end}).*redirect to :${first}([[:space:]]|$)" && return 0
    fi
    return 1
}
case "$CORE" in xray) MAIN_SRV=xray;; singbox) MAIN_SRV=sing-box;; hysteria) MAIN_SRV=hysteria;; *) exit 0;; esac
failed_srv=''
service_active_owned "$MAIN_SRV" || failed_srv="$MAIN_SRV"
MAIN_PID=${SERVICE_PID:-}
HY2_SRV="$MAIN_SRV"; HY2_PID="$MAIN_PID"
if [[ "$CORE" == xray && "$MODE" == *ALL* ]]; then
    if [[ -z "$failed_srv" ]]; then service_active_owned hysteria || failed_srv=hysteria; fi
    HY2_SRV=hysteria; HY2_PID=${SERVICE_PID:-}
fi
if [[ -z "$failed_srv" && "${HY2_HOP:-}" == true && "${HY2_HOP_IMPL:-}" == official && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
    hysteria_official_hop_firewall_ok || failed_srv="$HY2_SRV"
fi
if [[ -z "$failed_srv" && "${HY2_HOP:-}" == true && "${HY2_HOP_IMPL:-}" == manual && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" && -n "${INGRESS_IF:-}" ]]; then
    redirect_port="${HY2_MONITOR_PORT:-${HY2_RANGE_START}}"
    $IPT -w -t nat -C PREROUTING -i "$INGRESS_IF" -p udp --dport "${HY2_RANGE_START}:${HY2_RANGE_END}" -m comment --comment A-Box-HY2-HOP -j REDIRECT --to-ports "$redirect_port" 2>/dev/null || failed_srv="$HY2_SRV"
    if has_ipv6 && ipv6_nat_redirect_usable; then
        $IPT6 -w -t nat -C PREROUTING -i "$INGRESS_IF" -p udp --dport "${HY2_RANGE_START}:${HY2_RANGE_END}" -m comment --comment A-Box-HY2-HOP -j REDIRECT --to-ports "$redirect_port" 2>/dev/null || failed_srv="$HY2_SRV"
    fi
fi
[[ -n "$failed_srv" || -z "${VLESS_PORT:-}" ]] || check_socket_or_fail tcp "$VLESS_PORT" "$MAIN_PID" "$MAIN_SRV"
[[ -n "$failed_srv" || -z "${XHTTP_PORT:-}" ]] || check_socket_or_fail tcp "$XHTTP_PORT" "$MAIN_PID" "$MAIN_SRV"
[[ -n "$failed_srv" || -z "${HY2_MONITOR_PORT:-}" ]] || check_socket_or_fail udp "$HY2_MONITOR_PORT" "$HY2_PID" "$HY2_SRV"
if [[ -z "$failed_srv" && -n "${SS_PORT:-}" ]]; then
    check_socket_or_fail tcp "$SS_PORT" "$MAIN_PID" "$MAIN_SRV"
    [[ -z "$failed_srv" ]] && check_socket_or_fail udp "$SS_PORT" "$MAIN_PID" "$MAIN_SRV"
fi
if [[ -z "$failed_srv" ]]; then rm -f "$STATE"; exit 0; fi
count=0; last=0
[[ -r "$STATE" ]] && read -r count last < "$STATE" || true
[[ "$count" =~ ^[0-9]+$ ]] || count=0
[[ "$last" =~ ^[0-9]+$ ]] || last=0
now=$(date +%s)
count=$((count+1))
printf '%s %s\n' "$count" "$last" > "$STATE"
(( count >= 3 )) || exit 0
(( now - last >= 600 )) || exit 0
if restart_owned "$failed_srv"; then printf '0 %s\n' "$now" > "$STATE"; else printf '%s %s\n' "$count" "$now" > "$STATE"; fi
EOF_PROBE
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='systemd'|" "$ABOX_DIR/socket_probe.sh" || die '健康探针运行环境标记写入失败。'
    else
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='openrc'|" "$ABOX_DIR/socket_probe.sh" || die '健康探针运行环境标记写入失败。'
    fi
    grep -Fxq "INIT_SYS_EXPECTED='${INIT_SYS}'" "$ABOX_DIR/socket_probe.sh" || die '健康探针运行环境标记后置校验失败。' 
    chmod 700 "$ABOX_DIR/socket_probe.sh" || die '健康探针权限设置失败。'
    install_abox_cron_block PROBE '* * * * * /usr/bin/flock -n /run/A-Box-probe-cron.lock /bin/bash /etc/ddr/socket_probe.sh >/dev/null 2>&1'
}

setup_geo_cron() {
    if ! abox_owns_service xray; then
        remove_abox_cron_block GEO || die '无法安全移除 A-Box Geo cron 任务；为避免留下指向不存在脚本的 cron，保留 geo_update.sh 并中止当前操作。'
        remove_owned_runtime_helper "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本删除失败或文件不属于 A-Box。'
        return 0
    fi
    install -d -m 700 "$ABOX_DIR" || die '无法创建 Geo 更新目录。'
    write_file_atomically_from_stdin "$ABOX_DIR/geo_update.sh" 700 <<'EOF_GEO' || die 'Geo 更新脚本原子写入失败。'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
GEO_REPO='Loyalsoldier/v2ray-rules-dat'
DESIRED=/etc/ddr/.desired_state
PAIR_STATE=/etc/ddr/.traffic-pair-state
INIT_SYS_EXPECTED='unknown'
ABOX_CORE_OWNERSHIP=/etc/ddr/.managed-core-files.tsv
exec 9>>/run/A-Box-geo-update.lock || exit 1
flock -n 9 || exit 0
RUNTIME_LOCK=/run/A-Box.lock
acquire_abox_runtime_guard() {
    local FALLBACK_DIR=/run/A-Box.lock.d fb_pid fb_start fb_actual mode
    [[ -d /run && ! -L /run ]] || exit 0
    # If a live fallback lock is held by another A-Box process, yield. Helpers
    # must not treat an idle LOCK_FILE flock as free while main owns fallback.
    if [[ -d "$FALLBACK_DIR" && ! -L "$FALLBACK_DIR" && -r "$FALLBACK_DIR/pid" && -r "$FALLBACK_DIR/starttime" ]]; then
        [[ "$(stat -c %u:%g "$FALLBACK_DIR" 2>/dev/null || true)" == 0:0 ]] || exit 0
        mode=$(stat -c %a "$FALLBACK_DIR" 2>/dev/null) || exit 0
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
        (( (8#$mode & 8#077) == 0 )) || exit 0
        IFS= read -r fb_pid < "$FALLBACK_DIR/pid" || exit 0
        IFS= read -r fb_start < "$FALLBACK_DIR/starttime" || exit 0
        if [[ "$fb_pid" =~ ^[0-9]+$ && -d "/proc/$fb_pid" ]]; then
            fb_actual=$(awk '{print $22}' "/proc/${fb_pid}/stat" 2>/dev/null || true)
            [[ -n "$fb_actual" && "$fb_actual" == "$fb_start" ]] && exit 0
        fi
    fi
    # /run is recreated on reboot; recreate the shared lock inode on demand.
    if [[ ! -e "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]]; then
        ( umask 077; set -C; : > "$RUNTIME_LOCK" ) 2>/dev/null || true
    fi
    [[ -f "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]] || exit 0
    [[ "$(stat -c %u:%g "$RUNTIME_LOCK" 2>/dev/null || true)" == 0:0 ]] || exit 0
    mode=$(stat -c %a "$RUNTIME_LOCK" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
    (( (8#$mode & 8#077) == 0 )) || exit 0
    exec 10>>"$RUNTIME_LOCK" || exit 0
    flock -n 10 || exit 0
}
acquire_abox_runtime_guard
is_systemd() { [[ "$INIT_SYS_EXPECTED" == systemd ]]; }
xray_owned() { local u; if is_systemd; then u=/etc/systemd/system/xray.service; else u=/etc/init.d/xray; fi; [[ -f "$u" && ! -L "$u" ]] && grep -Fxq '# Managed by A-Box' "$u"; }
update_geo_ownership() {
    python3 - "$ABOX_CORE_OWNERSHIP" /usr/local/share/xray/geoip.dat /usr/local/share/xray/geosite.dat <<'PY_GEO_OWNER'
import hashlib, os, stat, sys, tempfile
manifest, *targets = sys.argv[1:]
st = os.lstat(manifest)
if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o077 or st.st_size > 4*1024*1024:
    raise SystemExit(1)
rows = []
with open(manifest, 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 4 or parts[0] not in {'F','D'} or not parts[2].startswith('/') or '\x00' in line:
            raise SystemExit(1)
        rows.append(parts)
if len({(r[0],r[1],r[2]) for r in rows}) != len(rows):
    raise SystemExit(1)
for target in targets:
    st = os.lstat(target)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
        raise SystemExit(1)
    h = hashlib.sha256()
    with open(target, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    matches = [r for r in rows if r[0] == 'F' and r[1] == 'xray' and r[2] == target]
    if len(matches) != 1:
        raise SystemExit(1)
    matches[0][3] = h.hexdigest()
dirname = os.path.dirname(manifest) or '.'
fd, tmp = tempfile.mkstemp(prefix='.managed-core-files.geo.', dir=dirname, text=True)
try:
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
        for row in sorted(rows, key=lambda r: (r[1], os.fsencode(r[2]))):
            f.write('\t'.join(row) + '\n')
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600); os.chown(tmp, 0, 0); os.replace(tmp, manifest)
except Exception:
    try: os.unlink(tmp)
    except OSError: pass
    raise
PY_GEO_OWNER
}
fetch_one() {
    local asset="$1" out="$2" api release_json asset_json url digest expected actual size
    api="https://api.github.com/repos/${GEO_REPO}/releases/latest"
    release_json=$(curl -fLsS --connect-timeout 10 -m 60 -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2026-03-10' "$api") || return 1
    asset_json=$(jq -c --arg name "$asset" 'first(.assets[]? | select(.name == $name) | {name:.name,url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
    [[ -n "$asset_json" && "$asset_json" != null ]] || return 1
    url=$(jq -r '.url' <<< "$asset_json")
    digest=$(jq -r '.digest // ""' <<< "$asset_json")
    [[ "$url" == "https://github.com/${GEO_REPO}/releases/download/"* && "$digest" == sha256:* ]] || return 1
    expected="${digest#sha256:}"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    curl -fLsS --connect-timeout 10 -m 90 "$url" -o "$out" || return 1
    actual=$(sha256sum "$out" | awk '{print $1}')
    [[ "${actual,,}" == "${expected,,}" ]] || return 1
    size=$(wc -c < "$out" 2>/dev/null | tr -d ' ')
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 500000 ]] || return 1
    ! head -c 256 "$out" 2>/dev/null | grep -Eiq '<(html|!doctype)'
}
[[ -d /usr/local/share/xray ]] || exit 0
xray_owned || exit 0
desired=RUNNING
if [[ -r "$PAIR_STATE" && -f "$PAIR_STATE" && ! -L "$PAIR_STATE" ]] && [[ "$(stat -c %u:%g "$PAIR_STATE" 2>/dev/null)" == 0:0 ]]; then
    IFS= read -r _pair < "$PAIR_STATE" || true
    desired=${_pair%%|*}
elif [[ -r "$DESIRED" && -f "$DESIRED" && ! -L "$DESIRED" ]]; then
    IFS= read -r desired < "$DESIRED" || true
fi
[[ "$desired" == RUNNING ]] || exit 0
if is_systemd; then systemctl is-active --quiet xray || exit 0; else rc-service xray status >/dev/null 2>&1 || exit 0; fi
tmpdir=$(umask 077; mktemp -d /tmp/A-Box-geo.XXXXXX) || exit 1
trap 'rm -rf -- "$tmpdir"' EXIT
fetch_one geoip.dat "$tmpdir/geoip.dat" || exit 1
fetch_one geosite.dat "$tmpdir/geosite.dat" || exit 1
old_ip="$tmpdir/geoip.old"
old_site="$tmpdir/geosite.old"
[[ -f /usr/local/share/xray/geoip.dat ]] && cp -a /usr/local/share/xray/geoip.dat "$old_ip"
[[ -f /usr/local/share/xray/geosite.dat ]] && cp -a /usr/local/share/xray/geosite.dat "$old_site"
stage_ip=$(mktemp /usr/local/share/xray/.geoip.A-Box-new.XXXXXX) || exit 1
stage_site=$(mktemp /usr/local/share/xray/.geosite.A-Box-new.XXXXXX) || { rm -f "$stage_ip"; exit 1; }
install -m 644 "$tmpdir/geoip.dat" "$stage_ip" || exit 1
install -m 644 "$tmpdir/geosite.dat" "$stage_site" || exit 1
mv -f "$stage_ip" /usr/local/share/xray/geoip.dat || exit 1
if ! mv -f "$stage_site" /usr/local/share/xray/geosite.dat; then
    [[ -f "$old_ip" ]] && cp -a "$old_ip" /usr/local/share/xray/geoip.dat || rm -f /usr/local/share/xray/geoip.dat
    exit 1
fi
restart_ok=0
if is_systemd; then
    systemctl restart xray >/dev/null 2>&1 && systemctl is-active --quiet xray && restart_ok=1
else
    rc-service xray restart >/dev/null 2>&1 && rc-service xray status >/dev/null 2>&1 && restart_ok=1
fi
if [[ "$restart_ok" != 1 ]]; then
    [[ -f "$old_ip" ]] && cp -a "$old_ip" /usr/local/share/xray/geoip.dat || rm -f /usr/local/share/xray/geoip.dat
    [[ -f "$old_site" ]] && cp -a "$old_site" /usr/local/share/xray/geosite.dat || rm -f /usr/local/share/xray/geosite.dat
    if is_systemd; then systemctl restart xray >/dev/null 2>&1 || true; else rc-service xray restart >/dev/null 2>&1 || true; fi
    exit 1
fi
if ! update_geo_ownership; then
    [[ -f "$old_ip" ]] && cp -a "$old_ip" /usr/local/share/xray/geoip.dat || rm -f /usr/local/share/xray/geoip.dat
    [[ -f "$old_site" ]] && cp -a "$old_site" /usr/local/share/xray/geosite.dat || rm -f /usr/local/share/xray/geosite.dat
    if is_systemd; then systemctl restart xray >/dev/null 2>&1 || true; else rc-service xray restart >/dev/null 2>&1 || true; fi
    exit 1
fi
EOF_GEO
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='systemd'|" "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本运行环境标记写入失败。'
    else
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='openrc'|" "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本运行环境标记写入失败。'
    fi
    grep -Fxq "INIT_SYS_EXPECTED='${INIT_SYS}'" "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本运行环境标记后置校验失败。' 
    chmod 700 "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本权限设置失败。'
    install_abox_cron_block GEO '0 3 * * 1 /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1'
}

pre_install_setup() {
    local CORE_IN=$1 MODE_IN=$2
    reset_protocol_vars
    local DEF_V_PORT=443 DEF_X_PORT=8443 DEF_H_PORT=443 DEF_S_PORT=2053
    local INPUT_H_DOMAIN INPUT_H_HOP INPUT_SS_WL INPUT_KA ip prompt
    local -a ss_whitelist_ips=()
    local HAS_VISION=false HAS_XHTTP=false HAS_HY2=false HAS_SS=false
    local L_VISION L_XHTTP L_HY2 L_SS L_GLOBAL
    L_VISION=$(proto_label 'VLESS-Vision')
    L_XHTTP=$(proto_label 'VLESS-XHTTP')
    L_HY2=$(proto_label 'HY2')
    L_SS=$(proto_label 'SS-2022')
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then L_GLOBAL=$(proto_label 'Global'); else L_GLOBAL=$(proto_label '全局'); fi
    [[ "$MODE_IN" == *'VISION'* || "$MODE_IN" == *'ALL'* || "$MODE_IN" == 'VLESS_SS' ]] && HAS_VISION=true
    [[ "$CORE_IN" == 'xray' && ( "$MODE_IN" == *'XHTTP'* || "$MODE_IN" == *'ALL'* ) ]] && HAS_XHTTP=true
    [[ "$MODE_IN" == *'HY2'* || "$MODE_IN" == *'ALL'* ]] && HAS_HY2=true
    [[ "$MODE_IN" == *'SS'* || "$MODE_IN" == *'ALL'* || "$MODE_IN" == 'VLESS_SS' ]] && HAS_SS=true

    # Xray ALL: Vision TCP 443 + XHTTP TCP 8443 + HY2 UDP 443 + SS-2022 TCP/UDP 2053.
    # Sing-box ALL: Vision TCP 443 + HY2 UDP 443 + SS-2022 TCP/UDP 2053. XHTTP is intentionally excluded.

    INGRESS_IF=$(get_active_interface)
    [[ -z "$INGRESS_IF" ]] && die '无法识别公网入接口。'
    GLOBAL_PUBLIC_IP=$(refresh_public_ip)

    # U1 one-click / quick path: Vision-only defaults, reuse remaining setup (ports/firewall).
    if [[ "${ABOX_QUICK_DEPLOY:-0}" == '1' && "$HAS_VISION" == 'true' && "$HAS_XHTTP" != 'true' && "$HAS_HY2" != 'true' && "$HAS_SS" != 'true' ]]; then
        VLESS_PORT="$DEF_V_PORT"
        VISION_SNI='www.microsoft.com'
        VLESS_SNI="$VISION_SNI"
        ENABLE_KEEPALIVE='false'
        msg "${GREEN}[one-click] Vision REALITY defaults: port=${VLESS_PORT} SNI=${VISION_SNI}${NC}"
        check_selected_ports_free
        allowPort "$VLESS_PORT" tcp
        save_firewall_rules || die 'A-Box 防火墙持久化失败。'
        return 0
    fi

    printf '\n%s\n' "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${BOLD}Parameter Wizard [Engine: $CORE_IN | Mode: $MODE_IN]${NC}"
    else
        msg "${BOLD}参数构造向导 [Engine: $CORE_IN | Mode: $MODE_IN]${NC}"
    fi
    msg "${BLUE}----------------------------------------------------------------------${NC}"

    if [[ "$HAS_VISION" == 'true' ]]; then
        VLESS_PORT=$(prompt_port_input "$L_VISION" "$DEF_V_PORT") || die '监听端口输入已结束 / Port input closed.'
        VISION_SNI=$(prompt_reality_sni "$L_VISION" "$VLESS_PORT") || die 'REALITY SNI 输入已结束 / SNI input closed.'
    fi
    if [[ "$HAS_XHTTP" == 'true' ]]; then
        XHTTP_PORT=$(prompt_port_input "$L_XHTTP" "$DEF_X_PORT") || die 'XHTTP 端口输入已结束 / XHTTP port input closed.'
        XHTTP_SNI=$(prompt_reality_sni "$L_XHTTP" "$XHTTP_PORT") || die 'XHTTP SNI 输入已结束 / XHTTP SNI input closed.'
    fi
    VLESS_SNI=${VISION_SNI:-${XHTTP_SNI:-www.microsoft.com}}

    if [[ "$HAS_HY2" == 'true' ]]; then
        HY2_BASE_PORT=$(prompt_port_input "$L_HY2" "$DEF_H_PORT") || die 'HY2 端口输入已结束 / HY2 port input closed.'

        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            if [[ "$CORE_IN" == 'singbox' ]]; then
                read -r -p "   ${L_HY2} Optional server domain for Sing-box HY2 self-signed certificate/SNI (empty = IP + pinSHA256): " INPUT_H_DOMAIN || die '交互输入已结束 / Interactive input closed.'
            else
                read -r -p "   ${L_HY2} Do you have a domain already resolved to this server? (empty = self-signed certificate): " INPUT_H_DOMAIN || die '交互输入已结束 / Interactive input closed.'
            fi
        else
            if [[ "$CORE_IN" == 'singbox' ]]; then
                read -r -p "   ${L_HY2} 可选填写 Sing-box HY2 自签证书/SNI 域名（留空使用 IP + pinSHA256）: " INPUT_H_DOMAIN || die '交互输入已结束 / Interactive input closed.'
            else
                read -r -p "   ${L_HY2} 是否拥有已解析到本机的域名？(留空使用默认自签证书): " INPUT_H_DOMAIN || die '交互输入已结束 / Interactive input closed.'
            fi
        fi
        HY2_DOMAIN="$INPUT_H_DOMAIN"
        if [[ -n "$HY2_DOMAIN" ]]; then
            valid_domain "$HY2_DOMAIN" || die "域名格式非法 / Invalid domain: $HY2_DOMAIN"
            [[ "${GLOBAL_PUBLIC_IP:-N/A}" != 'N/A' ]] && verify_domain_points_to_self "$HY2_DOMAIN" "$GLOBAL_PUBLIC_IP"
            HY2_ACME_TYPE='http'
            HY2_ACME_DNS_PROVIDER=''
            HY2_ACME_DNS_CF_API_TOKEN=''
            if [[ "$CORE_IN" == 'hysteria' || ( "$CORE_IN" == 'xray' && "$MODE_IN" == *'ALL'* ) ]]; then
                if [[ -n "${ABOX_HY2_ACME_DNS_PROVIDER:-${ABOX_ACME_DNS_PROVIDER:-}}" ]]; then
                    HY2_ACME_TYPE='dns'
                    HY2_ACME_DNS_PROVIDER="${ABOX_HY2_ACME_DNS_PROVIDER:-${ABOX_ACME_DNS_PROVIDER:-}}"
                    HY2_ACME_DNS_CF_API_TOKEN="${ABOX_HY2_ACME_DNS_CF_API_TOKEN:-${ABOX_ACME_DNS_CF_API_TOKEN:-}}"
                else
                    local INPUT_ACME_DNS INPUT_CF_TOKEN
                    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
                        read -r -p "   ${L_HY2} Use Cloudflare DNS-01 ACME instead of HTTP-01? [Y/N]: " INPUT_ACME_DNS || die '交互输入已结束 / Interactive input closed.'
                    else
                        read -r -p "   ${L_HY2} 是否使用 Cloudflare DNS-01 申请证书以避免占用 80 端口？[Y/N]: " INPUT_ACME_DNS || die '交互输入已结束 / Interactive input closed.'
                    fi
                    if is_yes "$INPUT_ACME_DNS"; then
                        HY2_ACME_TYPE='dns'
                        HY2_ACME_DNS_PROVIDER='cloudflare'
                        read -r -s -p "   ${L_HY2} Cloudflare API Token: " INPUT_CF_TOKEN || die '交互输入已结束 / Interactive input closed.'
                        echo
                        HY2_ACME_DNS_CF_API_TOKEN="$INPUT_CF_TOKEN"
                    fi
                fi
                if [[ "${HY2_ACME_TYPE:-http}" == 'dns' ]]; then
                    [[ "${HY2_ACME_DNS_PROVIDER:-}" == 'cloudflare' ]] || die '当前仅内置支持 Cloudflare DNS-01 ACME。'
                    valid_single_line_secret "${HY2_ACME_DNS_CF_API_TOKEN:-}" 512 || die 'Cloudflare DNS-01 ACME Token 为空、过长或包含换行。'
                fi
            fi
        fi

        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            read -r -p "   ${L_HY2} Enable port hopping? [Y/N]: " INPUT_H_HOP || die '交互输入已结束 / Interactive input closed.'
        else
            read -r -p "   ${L_HY2} 是否开启端口跳跃 (单端口被限速环境建议开启)? [Y/N]: " INPUT_H_HOP || die '交互输入已结束 / Interactive input closed.'
        fi
        if is_yes "$INPUT_H_HOP"; then
            HY2_HOP='true'
            HY2_RANGE_START=20000
            HY2_RANGE_END=25000
            if [[ "$CORE_IN" == 'hysteria' || ( "$CORE_IN" == 'xray' && "$MODE_IN" == *'ALL'* ) ]]; then
                HY2_HOP_IMPL='official'
                HY2_URI_PORTS="${HY2_RANGE_START}-${HY2_RANGE_END}"
                HY2_MONITOR_PORT="$HY2_RANGE_START"
            else
                HY2_HOP_IMPL='manual'
                HY2_URI_PORTS="${HY2_BASE_PORT}"
                HY2_MONITOR_PORT="$HY2_BASE_PORT"
                if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
                    command -v ip6tables >/dev/null 2>&1 || die '检测到全局 IPv6，但系统没有 ip6tables；拒绝启用手动 HY2 跳跃。'
                    ip6tables -w -t nat -L PREROUTING >/dev/null 2>&1 || die '检测到全局 IPv6，但 ip6tables nat/PREROUTING 不可用；拒绝启用手动 HY2 跳跃。'
                fi
            fi
            HY2_CLASH_PORTS="${HY2_RANGE_START}-${HY2_RANGE_END}"
            HY2_SB_PORTS="${HY2_RANGE_START}:${HY2_RANGE_END}"
        else
            HY2_HOP='false'
            HY2_HOP_IMPL='none'
            HY2_URI_PORTS="$HY2_BASE_PORT"
            HY2_CLASH_PORTS=''
            HY2_SB_PORTS=''
            HY2_MONITOR_PORT="$HY2_BASE_PORT"
        fi

        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            HY2_DOWN=$(prompt_hy2_bandwidth_mbps_input "   ${L_HY2} Downlink Mbps (default: 1000): " 1000) || die 'HY2 下行速率输入已结束 / HY2 downlink input closed.'
        else
            HY2_DOWN=$(prompt_hy2_bandwidth_mbps_input "   ${L_HY2} 下行速率(Mbps) (回车默认: 1000): " 1000) || die 'HY2 下行速率输入已结束 / HY2 downlink input closed.'
        fi
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            HY2_UP=$(prompt_hy2_bandwidth_mbps_input "   ${L_HY2} Uplink Mbps (default: 100): " 100) || die 'HY2 上行速率输入已结束 / HY2 uplink input closed.'
        else
            HY2_UP=$(prompt_hy2_bandwidth_mbps_input "   ${L_HY2} 上行速率(Mbps) (回车默认: 100): " 100) || die 'HY2 上行速率输入已结束 / HY2 uplink input closed.'
        fi

        local masq_default="https://${VISION_SNI:-${XHTTP_SNI:-www.samsung.com}}/"
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            HY2_MASQ_URL=$(prompt_https_url "   ${L_HY2} Enter HTTP/3 masquerade URL (default: $masq_default): " "$masq_default") || die 'HY2 伪装 URL 输入已结束 / HY2 masquerade URL input closed.'
        else
            HY2_MASQ_URL=$(prompt_https_url "   ${L_HY2} 请输入 HTTP/3 伪装站点 URL (回车默认: $masq_default): " "$masq_default") || die 'HY2 伪装 URL 输入已结束 / HY2 masquerade URL input closed.'
        fi
    fi
    if [[ "$HAS_SS" == 'true' ]]; then
        SS_PORT=$(prompt_ss_port_input "$L_SS" "$DEF_S_PORT") || die 'SS 端口输入已结束 / SS port input closed.'
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            read -r -p "   ${L_SS} Enter frontend whitelist IP/CIDR (empty = open to all, space-separated): " INPUT_SS_WL || die '交互输入已结束 / Interactive input closed.'
        else
            read -r -p "   ${L_SS} 请输入前置机白名单 IP/CIDR (留空全网开放, 多个用空格分隔): " INPUT_SS_WL || die '交互输入已结束 / Interactive input closed.'
        fi
        SS_WHITELIST_IP="$INPUT_SS_WL"
        if [[ -n "$SS_WHITELIST_IP" ]]; then
            read -r -a ss_whitelist_ips <<< "$SS_WHITELIST_IP"
            for ip in "${ss_whitelist_ips[@]}"; do
                if [[ "$ip" == *:* ]]; then
                    valid_ipv6_cidr "$ip" || die "IPv6 白名单地址非法: $ip"
                else
                    valid_ipv4_cidr "$ip" || die "IPv4 白名单地址非法: $ip"
                fi
            done
        fi
    fi

    if abox_is_fast; then
        ENABLE_KEEPALIVE='false'
        msg "${YELLOW}[fast] TCP KeepAlive default off.${NC}"
    else
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            read -r -p "   ${L_GLOBAL} Enable TCP KeepAlive 45s to prevent NAT idle disconnect? [Y/N]: " INPUT_KA || die '交互输入已结束 / Interactive input closed.'
        else
            read -r -p "   ${L_GLOBAL} 是否开启 TCP KeepAlive (45s) 防治 NAT 空闲断连? [Y/N]: " INPUT_KA || die '交互输入已结束 / Interactive input closed.'
        fi
        is_yes "$INPUT_KA" && ENABLE_KEEPALIVE='true' || ENABLE_KEEPALIVE='false'
    fi
    printf '%s\n\n' "${CYAN}======================================================================${NC}"

    check_selected_ports_free
    if [[ "$HAS_HY2" == 'true' ]] && hy2_http01_enabled "$CORE_IN" "$MODE_IN"; then
        if ! holder=$(ss -H -n -l -p -A tcp 2>/dev/null); then
            die '无法检查 80/tcp 端口占用；ss 查询失败。'
        fi
        holder=$(awk '{addr=$4; if (addr ~ /(^|:)80$/) { print; found=1 }} END { if (!found) exit 0 }' <<< "$holder" || true)
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] ACME HTTP-01 需要 80/tcp，但该端口仍被进程占用：${NC}"
            echo "$holder"
            die '请先释放 80/tcp，或改用 Cloudflare DNS-01 ACME 后再部署 HY2 域名证书。'
        fi
    fi

    [[ "$HAS_VISION" == 'true' ]] && allowPort "$VLESS_PORT" tcp
    [[ "$HAS_XHTTP" == 'true' ]] && allowPort "$XHTTP_PORT" tcp
    if [[ "$HAS_HY2" == 'true' ]]; then
        if hy2_http01_enabled "$CORE_IN" "$MODE_IN"; then
            allowPort 80 tcp
        fi
        if [[ "$HY2_HOP" == 'true' ]]; then
            allowPort "${HY2_RANGE_START}:${HY2_RANGE_END}" udp
            [[ "$HY2_HOP_IMPL" == 'manual' ]] && allowPort "$HY2_BASE_PORT" udp
        else
            allowPort "$HY2_BASE_PORT" udp
        fi
    fi
    if [[ "$HAS_SS" == 'true' ]]; then
        if [[ -n "${SS_WHITELIST_IP:-}" && "$(firewall_backend)" != 'iptables' ]]; then
            die '当前防火墙后端不是原生 iptables；SS-2022 源地址白名单仅在 iptables/ip6tables 后端启用，拒绝静默写入不可持久化的白名单规则。'
        fi
        if [[ -n "${SS_WHITELIST_IP:-}" ]]; then
            remove_ss_open_accept_rules || die '旧的 SS 全网 ACCEPT 规则无法完整删除；拒绝启用白名单模式。'
            read -r -a ss_whitelist_ips <<< "$SS_WHITELIST_IP"
            for ip in "${ss_whitelist_ips[@]}"; do
                for proto in tcp udp; do
                    if [[ "$ip" == *:* ]]; then
                        if ! has_ipv6 || ! command -v ip6tables >/dev/null 2>&1 || ! $IPT6 -w -S INPUT >/dev/null 2>&1; then
                            die "IPv6 白名单已配置，但系统没有可用 IPv6 防火墙；拒绝继续以避免白名单被静默丢弃: $ip/$proto"
                        fi
                        if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                            if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                            case "$check_rc" in
                                0) ;;
                                1) $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则写入失败: $ip/$proto" ;;
                                *) die "无法检查防火墙规则。" ;;
                            esac
                        fi
                    else
                        if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                        case "$check_rc" in
                            0) ;;
                            1) $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则写入失败: $ip/$proto" ;;
                            *) die "无法检查防火墙规则。" ;;
                        esac
                    fi
                done
            done
            for proto in tcp udp; do
                if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP; then check_rc=0; else check_rc=$?; fi
                case "$check_rc" in
                    0) ;;
                    1) $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto" ;;
                    *) die "无法检查防火墙规则。" ;;
                esac
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP; then check_rc=0; else check_rc=$?; fi
                    case "$check_rc" in
                        0) ;;
                        1) $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto" ;;
                        *) die "无法检查防火墙规则。" ;;
                    esac
                fi
            done
            enforce_ss_whitelist_order "$SS_PORT" || die 'SS 白名单规则顺序校正失败。'
        else
            allowPort "$SS_PORT" tcp
            allowPort "$SS_PORT" udp
        fi
    fi
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
}

json_sockopt_xray() {
    if [[ "${ENABLE_KEEPALIVE:-}" == 'true' ]]; then
        jq -n '{tcpKeepAliveIdle:45,tcpKeepAliveInterval:45}'
    else
        jq -n 'null'
    fi
}

build_xray_config() {
    local mode="$1" sockopt_json inbounds_json out="${2:-/usr/local/etc/xray/config.json}" tmp_out listen_addr
    listen_addr=$(wildcard_listen_address)
    sockopt_json=$(json_sockopt_xray)
    inbounds_json=$(jq -n \
        --arg mode "$mode" \
        --arg listen_addr "$listen_addr" \
        --arg uuid "$UUID" \
        --arg v_sni "${VISION_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg x_sni "${XHTTP_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg pk "$PK" \
        --arg sid "$SHORT_ID" \
        --argjson vport "${VLESS_PORT:-443}" \
        --argjson xport "${XHTTP_PORT:-8443}" \
        --argjson ssport "${SS_PORT:-2053}" \
        --arg ss_pass "$SS_PASS" \
        --argjson sock "$sockopt_json" '
        def maybe_sock: if $sock == null then {} else {sockopt:$sock} end;
        def vision:
          {
            listen:$listen_addr, port:$vport, protocol:"vless",
            settings:{clients:[{id:$uuid, flow:"xtls-rprx-vision"}], decryption:"none"},
            streamSettings:({network:"tcp", security:"reality", realitySettings:{target:($v_sni + ":443"), serverNames:[$v_sni], privateKey:$pk, shortIds:[$sid], minClientVer:"1.8.2"}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def xhttp:
          {
            listen:$listen_addr, port:$xport, protocol:"vless",
            settings:{clients:[{id:$uuid}], decryption:"none"},
            streamSettings:({network:"xhttp", security:"reality", xhttpSettings:{mode:"auto", path:"/xhttp"}, realitySettings:{target:($x_sni + ":443"), serverNames:[$x_sni], privateKey:$pk, shortIds:[$sid], minClientVer:"1.8.2"}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def ss:
          ({listen:$listen_addr, port:$ssport, protocol:"shadowsocks", settings:{method:"2022-blake3-aes-128-gcm", password:$ss_pass, network:"tcp,udp"}}
           + (if $sock == null then {} else {streamSettings:{sockopt:$sock}} end));
        []
        | if ($mode|contains("VISION")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [vision] else . end
        | if ($mode|contains("XHTTP")) or ($mode|contains("ALL")) then . + [xhttp] else . end
        | if ($mode|contains("SS")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [ss] else . end
    ') || die 'Xray inbounds JSON 构造失败。'
    local out_dir
    out_dir=$(dirname -- "$out")
    [[ ! -L "$out_dir" && ! -L "$out" ]] || die 'Xray 配置路径存在符号链接，拒绝写入。'
    [[ ! -e "$out_dir" || -d "$out_dir" ]] || die 'Xray 配置父路径不是目录，拒绝写入。'
    [[ -d "$out_dir" ]] || install -d -m 755 -- "$out_dir" || die 'Xray 配置目录创建失败。'
    tmp_out=$(mktemp "$out_dir/.A-Box-xray-config.XXXXXX") || die 'Xray 配置临时文件创建失败。'
    umask 077
    jq -n --argjson inbounds "$inbounds_json" '{
        log:{loglevel:"warning", access:"/var/log/A-Box-xray-access.log", error:"/var/log/A-Box-xray-error.log"},
        routing:{domainStrategy:"IPIfNonMatch", rules:[
            {type:"field", protocol:["bittorrent"], outboundTag:"block"},
            {type:"field", domain:["geosite:category-ads-all"], outboundTag:"block"}
        ]},
        inbounds:$inbounds,
        outbounds:[{protocol:"freedom", tag:"direct"}, {protocol:"blackhole", tag:"block"}]
    }' > "$tmp_out" || { rm -f "$tmp_out"; die 'Xray JSON 生成失败。'; }
    chmod 600 "$tmp_out" || { rm -f "$tmp_out"; die 'Xray 配置权限设置失败。'; }
    [[ $EUID -eq 0 ]] && chown root:root "$tmp_out" || true
    mv -f "$tmp_out" "$out" || { rm -f "$tmp_out"; die 'Xray 配置原子提交失败。'; }
}

build_singbox_config() {
    local mode="$1" inbounds_json ka_obj cert_cn='localhost' out="${2:-/etc/sing-box/config.json}" tmp_out listen_addr
    listen_addr=$(wildcard_listen_address)
    [[ -n "${HY2_DOMAIN:-}" ]] && cert_cn="$HY2_DOMAIN"
    if [[ "${ENABLE_KEEPALIVE:-}" == true ]]; then ka_obj='{"tcp_keep_alive":"45s","tcp_keep_alive_interval":"45s"}'; else ka_obj='{}'; fi
    # HY2_UP/HY2_DOWN are client-facing rates. On the server endpoint,
    # server up == client download and server down == client upload, so the
    # values intentionally map to up_mbps=HY2_DOWN and down_mbps=HY2_UP.
    inbounds_json=$(jq -n \
        --arg mode "$mode" --arg uuid "$UUID" --arg listen_addr "$listen_addr" \
        --arg v_sni "${VISION_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg x_sni "${XHTTP_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg pk "$PK" --arg sid "$SHORT_ID" \
        --argjson vport "${VLESS_PORT:-443}" --argjson hy2port "${HY2_BASE_PORT:-443}" --argjson ssport "${SS_PORT:-2053}" \
        --argjson hy2up "${HY2_DOWN:-1000}" --argjson hy2down "${HY2_UP:-100}" \
        --arg hy2pass "${HY2_PASS:-}" --arg hy2obfs "${HY2_OBFS:-}" --arg cert_cn "$cert_cn" \
        --arg masq "${HY2_MASQ_URL:-https://www.samsung.com/}" --arg ss_pass "${SS_PASS:-}" --argjson ka "$ka_obj" '
        def vision:
          ({type:"vless", listen:$listen_addr, listen_port:$vport, tcp_fast_open:true,
            users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
            tls:{enabled:true, server_name:$v_sni, reality:{enabled:true, handshake:{server:$v_sni, server_port:443}, private_key:$pk, short_id:[$sid]}}} + $ka);
        def hy2:
          {type:"hysteria2", listen:$listen_addr, listen_port:$hy2port, up_mbps:$hy2up, down_mbps:$hy2down,
            obfs:{type:"salamander", password:$hy2obfs}, users:[{password:$hy2pass}],
            tls:{enabled:true, server_name:$cert_cn, alpn:["h3"], certificate_path:"/etc/sing-box/hy2.crt", key_path:"/etc/sing-box/hy2.key"}, masquerade:$masq};
        def ss:
          ({type:"shadowsocks", listen:$listen_addr, listen_port:$ssport, tcp_fast_open:true,
            method:"2022-blake3-aes-128-gcm", password:$ss_pass} + $ka);
        []
        | if ($mode|contains("VISION")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [vision] else . end
        | if ($mode|contains("HY2")) or ($mode|contains("ALL")) then . + [hy2] else . end
        | if ($mode|contains("SS")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [ss] else . end') || die 'Sing-box inbounds JSON 构造失败。'
    local out_dir
    out_dir=$(dirname -- "$out")
    [[ ! -L "$out_dir" && ! -L "$out" ]] || die 'Sing-box 配置路径存在符号链接，拒绝写入。'
    [[ ! -e "$out_dir" || -d "$out_dir" ]] || die 'Sing-box 配置父路径不是目录，拒绝写入。'
    if [[ "$out" == /etc/sing-box/config.json ]]; then
        prepare_abox_runtime_config_dir sing-box /etc/sing-box || die 'Sing-box 配置目录权限准备失败。'
    else
        [[ -d "$out_dir" ]] || install -d -m 755 -- "$out_dir" || die 'Sing-box 配置目录创建失败。'
    fi
    tmp_out=$(mktemp "$out_dir/.A-Box-singbox-config.XXXXXX") || die 'Sing-box 配置临时文件创建失败。'
    umask 077
    jq -n --argjson inbounds "$inbounds_json" '{
        log:{level:"warn", output:"/var/log/A-Box-singbox.log"},
        route:{rules:[{network:["tcp"], action:"sniff"},{protocol:"bittorrent", action:"reject"}], auto_detect_interface:true},
        inbounds:$inbounds,
        outbounds:[{type:"direct", tag:"direct"}]
    }' > "$tmp_out" || { rm -f "$tmp_out"; die 'Sing-box JSON 生成失败。'; }
    chmod 600 "$tmp_out" || { rm -f "$tmp_out"; die 'Sing-box 配置权限设置失败。'; }
    [[ $EUID -eq 0 ]] && chown root:root "$tmp_out" || true
    mv -f "$tmp_out" "$out" || { rm -f "$tmp_out"; die 'Sing-box 配置原子提交失败。'; }
}

generate_self_signed_cert_atomically() {
    local key="$1" cert="$2" cn="$3" dir tmp key_tmp cert_tmp pub1 pub2 key_bak='' cert_bak=''
    dir=$(dirname "$key")
    [[ "$dir" == "$(dirname "$cert")" ]] || return 1
    path_parent_chain_safe "$key" || return 1
    path_parent_chain_safe "$cert" || return 1
    case "$dir" in
        /etc/sing-box)
            prepare_abox_runtime_config_dir sing-box /etc/sing-box || return 1
            ;;
        /etc/hysteria)
            prepare_abox_runtime_config_dir hysteria /etc/hysteria || return 1
            ;;
        *)
            install -d -m 700 "$dir" || return 1
            ;;
    esac
    [[ ! -L "$key" && ! -L "$cert" ]] || return 1
    [[ ! -e "$key" || -f "$key" ]] || return 1
    [[ ! -e "$cert" || -f "$cert" ]] || return 1
    tmp=$(mktemp -d "$dir/.A-Box-cert.XXXXXX") || return 1
    key_tmp="$tmp/key.pem"; cert_tmp="$tmp/cert.pem"
    openssl ecparam -genkey -name prime256v1 -out "$key_tmp" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    openssl req -new -x509 -days 3650 -key "$key_tmp" -out "$cert_tmp" -subj "/CN=${cn}" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    openssl x509 -in "$cert_tmp" -noout >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    pub1=$(openssl pkey -in "$key_tmp" -pubout -outform der 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    pub2=$(openssl x509 -in "$cert_tmp" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    [[ -n "$pub1" && "$pub1" == "$pub2" ]] || { rm -rf "$tmp"; return 1; }
    chmod 600 "$key_tmp" "$cert_tmp" || { rm -rf "$tmp"; return 1; }

    if [[ -e "$key" ]]; then key_bak="$tmp/key.old"; cp -a -- "$key" "$key_bak" || { rm -rf "$tmp"; return 1; }; fi
    if [[ -e "$cert" ]]; then cert_bak="$tmp/cert.old"; cp -a -- "$cert" "$cert_bak" || { rm -rf "$tmp"; return 1; }; fi
    mv -f -- "$key_tmp" "$key" || { rm -rf "$tmp"; return 1; }
    if ! mv -f -- "$cert_tmp" "$cert"; then
        if [[ -n "$key_bak" ]]; then cp -a -- "$key_bak" "$key"; else rm -f -- "$key"; fi
        [[ -n "$cert_bak" ]] && cp -a -- "$cert_bak" "$cert"
        rm -rf "$tmp"
        return 1
    fi
    chmod 600 "$key" "$cert" || {
        if [[ -n "$key_bak" ]]; then cp -a -- "$key_bak" "$key"; else rm -f -- "$key"; fi
        if [[ -n "$cert_bak" ]]; then cp -a -- "$cert_bak" "$cert"; else rm -f -- "$cert"; fi
        rm -rf "$tmp"
        return 1
    }
    rm -rf "$tmp"
}

build_hysteria_config() {
    local out="$1" tls_config="$2" listen_spec="$3" tmp pass_yaml obfs_yaml masq_yaml out_dir
    [[ -n "$out" && -n "$listen_spec" ]] || return 1
    [[ "$out" == /etc/hysteria/config.yaml ]] || return 1
    path_parent_chain_safe "$out" || return 1
    out_dir=$(dirname "$out")
    [[ "$out_dir" == /etc/hysteria ]] || return 1
    [[ ! -L "$out_dir" && ! -L "$out" ]] || return 1
    prepare_abox_runtime_config_dir hysteria "$out_dir" || return 1
    pass_yaml=$(json_escape "$HY2_PASS") || return 1
    obfs_yaml=$(json_escape "$HY2_OBFS") || return 1
    masq_yaml=$(json_escape "$HY2_MASQ_URL") || return 1
    tmp=$(mktemp "${out}.tmp.XXXXXX") || return 1
    cat > "$tmp" <<EOF_HY2
listen: ${listen_spec}
${tls_config}
obfs:
  type: salamander
  salamander:
    password: ${obfs_yaml}
auth:
  type: password
  password: ${pass_yaml}
# Server up = server -> client (client download); server down = client -> server (client upload).
bandwidth:
  up: ${HY2_DOWN} mbps
  down: ${HY2_UP} mbps
masquerade:
  type: proxy
  proxy:
    url: ${masq_yaml}
    rewriteHost: true
EOF_HY2
    [[ $? -eq 0 ]] || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$out" || { rm -f -- "$tmp"; return 1; }
    [[ -s "$out" && ! -L "$out" ]]
}

deploy_official_hy2() {
    local IS_SILENT=${1:-NORMAL} TLS_CONFIG HY2_LISTEN cert_cn HY2_CAPS='CAP_NET_BIND_SERVICE' hy2_tmp hy2_bin domain_yaml token_yaml
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        clear; msg "${BOLD}${GREEN}部署官方 Hysteria 2${NC}"
        init_system_environment
        load_optional_abox_env_or_die
        light_preflight_check
        assert_no_foreign_core_conflicts hysteria
        confirm_deployment_replacement hysteria HY2
        begin_deployment_transaction 'official Hysteria 2 deployment' hysteria
        release_ports
        clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
        clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
        save_firewall_rules || die 'A-Box 防火墙持久化失败。'
        pre_install_setup hysteria HY2
        get_architecture
    fi

    hy2_tmp=$(mktemp -d /tmp/A-Box-hysteria.XXXXXX) || die 'Hysteria 临时目录创建失败。'
    ABOX_DEPLOY_TX_TMP="$hy2_tmp"
    hy2_bin="$hy2_tmp/hysteria_core"
    fetch_github_release HyNetworks/hysteria hysteria_core "$hy2_bin"
    chmod 755 "$hy2_bin" || die 'Hysteria staged binary chmod failed.'
    "$hy2_bin" version >/dev/null 2>&1 || die 'Hysteria staged binary execution check failed.'
    install_binary_atomically "$hy2_bin" /usr/local/bin/hysteria || die 'Hysteria binary atomic install failed.'
    rm -rf -- "$hy2_tmp"
    ABOX_DEPLOY_TX_TMP=''
    /usr/local/bin/hysteria version >/dev/null 2>&1 || die 'Hysteria 执行校验失败。'

    HY2_PASS=$(rand_alnum 20)
    HY2_OBFS=$(rand_alnum 16)

    if [[ -n "${HY2_DOMAIN:-}" ]]; then
        prepare_hysteria_acme_dir_ownership || die 'Hysteria ACME 目录已有非 A-Box 内容且无法安全确认归属，拒绝接管。'
        if [[ "${HY2_ACME_TYPE:-http}" == 'dns' ]]; then
            [[ "${HY2_ACME_DNS_PROVIDER:-}" == 'cloudflare' ]] || die '当前仅内置支持 Cloudflare DNS-01 ACME。'
            valid_single_line_secret "${HY2_ACME_DNS_CF_API_TOKEN:-}" 512 || die 'Cloudflare DNS-01 ACME Token 为空、过长或包含换行。'
            domain_yaml=$(json_escape "$HY2_DOMAIN")
            token_yaml=$(json_escape "$HY2_ACME_DNS_CF_API_TOKEN")
            TLS_CONFIG="acme:
  dir: /etc/hysteria/acme
  domains:
    - ${domain_yaml}
  email: $(json_escape "admin@${HY2_DOMAIN}")
  type: dns
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: ${token_yaml}"
        else
            domain_yaml=$(json_escape "$HY2_DOMAIN")
            TLS_CONFIG="acme:
  dir: /etc/hysteria/acme
  domains:
    - ${domain_yaml}
  email: $(json_escape "admin@${HY2_DOMAIN}")
  type: http
  http:
    altPort: 80"
        fi
        HY2_CERT_SHA256_FP=''
        HY2_CERT_PUBKEY_SHA256_B64=''
    else
        generate_self_signed_cert_atomically /etc/hysteria/server.key /etc/hysteria/server.crt localhost || die 'Hysteria 自签证书生成或密钥配对验证失败。'
        HY2_CERT_SHA256_FP=$(pin_sha256_colon /etc/hysteria/server.crt | tr -d ':')
        HY2_CERT_PUBKEY_SHA256_B64=$(openssl x509 -in /etc/hysteria/server.crt -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 | tr -d '\n')
        TLS_CONFIG="tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key"
    fi

    if [[ "${HY2_HOP:-}" == 'true' ]]; then
        HY2_LISTEN=":${HY2_RANGE_START}-${HY2_RANGE_END}"
        HY2_CAPS='CAP_NET_ADMIN CAP_NET_BIND_SERVICE'
    else
        HY2_LISTEN=":${HY2_BASE_PORT}"
    fi
    HY2_RC_CAPS='cap_net_bind_service'
    [[ "${HY2_HOP:-false}" == 'true' ]] && HY2_RC_CAPS='cap_net_admin,cap_net_bind_service'

    build_hysteria_config /etc/hysteria/config.yaml "$TLS_CONFIG" "$HY2_LISTEN" || die 'Hysteria 配置原子生成失败。'

    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        write_file_atomically_from_stdin /etc/systemd/system/hysteria.service 644 <<EOF_SVC || die 'Hysteria systemd unit 原子写入失败。'
# Managed by A-Box
[Unit]
Description=A-Box Hysteria 2 Service
After=network-online.target
Wants=network-online.target

[Service]
User=abox-hysteria
Group=abox-hysteria
CapabilityBoundingSet=${HY2_CAPS}
AmbientCapabilities=${HY2_CAPS}
UMask=0077
ExecStart=/bin/sh -c 'exec /usr/local/bin/hysteria server -c /etc/hysteria/config.yaml >>/var/log/A-Box-hysteria.log 2>&1'
NoNewPrivileges=true
PrivateTmp=true
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        path_parent_chain_safe /etc/conf.d/hysteria || die 'OpenRC conf.d 父链不安全。'
        [[ ! -L /etc/conf.d && (! -e /etc/conf.d || -d /etc/conf.d) ]] || die 'OpenRC conf.d 目录不安全。'
        mkdir -p /etc/conf.d || die 'OpenRC conf.d 目录创建失败。'
        write_file_atomically_from_stdin /etc/conf.d/hysteria 644 <<'EOF_HY2_CONFD' || die 'Hysteria OpenRC conf.d 原子写入失败。'
rc_ulimit="-n 1048576"
EOF_HY2_CONFD
        write_file_atomically_from_stdin /etc/init.d/hysteria 755 <<EOF_SVC || die 'Hysteria OpenRC unit 原子写入失败。'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Hysteria 2 Service"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria/config.yaml"
command_background="yes"
command_user="abox-hysteria:abox-hysteria"
capabilities="${HY2_RC_CAPS}"
umask=077
output_log="/var/log/A-Box-hysteria.log"
error_log="/var/log/A-Box-hysteria.log"
pidfile="/run/hysteria.pid"
depend() { need net; }
EOF_SVC
        chmod +x /etc/init.d/hysteria || die 'Hysteria OpenRC 服务权限设置失败。'
    fi
    prepare_abox_runtime_permissions hysteria || die 'Hysteria 运行时用户/文件权限准备失败。'
    service_manager start hysteria
    if [[ "${HY2_HOP:-false}" == true && "${HY2_HOP_IMPL:-none}" == official ]]; then
        if ! hysteria_official_hop_firewall_ok "$HY2_RANGE_START" "$HY2_RANGE_END" "$HY2_MONITOR_PORT"; then
            msg "${YELLOW}[!] 官方 HY2 端口跳跃防火墙规则未在服务启动后出现；正在重新启动 Hysteria 以触发规则重建。${NC}"
            restart_service_soft hysteria >/dev/null 2>&1 || die '官方 HY2 端口跳跃规则缺失且 Hysteria 重启失败。'
            sleep 1
            hysteria_official_hop_firewall_ok "$HY2_RANGE_START" "$HY2_RANGE_END" "$HY2_MONITOR_PORT" || die '官方 HY2 端口跳跃防火墙规则仍缺失，拒绝提交节点。'
        fi
    fi
    setup_active_defense
    setup_health_monitor
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        write_env hysteria HY2
        set_desired_state RUNNING || die 'Hysteria 服务期望状态提交失败。'
        prune_owned_core_families_except hysteria
        setup_geo_cron
        commit_deployment_transaction
        view_config deploy
    fi
}

install_file_atomically() {
    local src="$1" dest="$2" mode="${3:-600}" staged dir
    [[ -f "$src" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    [[ ! -e "$dest" && ! -L "$dest" || -f "$dest" ]] || return 1
    [[ ! -L "$dest" && ! -d "$dest" ]] || return 1
    path_parent_chain_safe "$dest" || return 1
    if [[ -e "$dest" || -L "$dest" ]] && path_is_mountpoint "$dest"; then
        return 1
    fi
    dir=$(dirname "$dest")
    if [[ -L "$dir" || ( -e "$dir" && ! -d "$dir" ) ]]; then
        return 1
    fi
    [[ -d "$dir" ]] || install -d -m 755 "$dir" || return 1
    staged=$(mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    command install -m "$mode" "$src" "$staged" || { rm -f -- "$staged"; return 1; }
    sync -f "$staged" 2>/dev/null || true
    mv -f -- "$staged" "$dest" || { rm -f -- "$staged"; return 1; }
    sync -f "$dir" 2>/dev/null || true
}

install_binary_atomically() { install_file_atomically "$1" "$2" 755; }

rollback_binary_install() {
    local bin="$1" backup="${2:-}"
    if [[ -n "$backup" && -f "$backup" ]]; then
        install_binary_atomically "$backup" "$bin"
    else
        path_tree_has_mountpoint "$bin" && return 1
        rm -f -- "$bin"
    fi
}

remove_core_family_force() {
    local srv="$1" path failed=0 core_paths=''
    local -a paths=()
    core_paths=$(core_family_paths "$srv") || return 1
    if [[ -n "$core_paths" ]]; then
        mapfile -t paths <<< "$core_paths" || return 1
    fi

    # Complete the safety preflight before deleting any sibling path. A mount
    # or symlink in one target must abort the whole forced cleanup rather than
    # leaving a partially removed core family before backup restoration.
    for path in "${paths[@]}"; do
        [[ -n "$path" ]] || continue
        [[ -e "$path" || -L "$path" ]] || continue
        [[ ! -L "$path" ]] || { failed=1; continue; }
        path_tree_has_mountpoint "$path" && { failed=1; continue; }
    done
    (( failed == 0 )) || return 1

    for path in "${paths[@]}"; do
        [[ -n "$path" ]] || continue
        [[ -e "$path" || -L "$path" ]] || continue
        rm -rf -- "$path" || failed=1
    done
    (( failed == 0 ))
}

restore_saved_trap() {
    local signal="$1" saved="$2"
    trap - "$signal"
    [[ -n "$saved" ]] && eval "$saved"
}

restore_deployment_transaction_traps() {
    restore_saved_trap EXIT "$ABOX_TX_PREV_TRAP_EXIT"
    restore_saved_trap INT "$ABOX_TX_PREV_TRAP_INT"
    restore_saved_trap TERM "$ABOX_TX_PREV_TRAP_TERM"
    restore_saved_trap HUP "$ABOX_TX_PREV_TRAP_HUP"
    ABOX_TX_PREV_TRAP_EXIT=''; ABOX_TX_PREV_TRAP_INT=''; ABOX_TX_PREV_TRAP_TERM=''; ABOX_TX_PREV_TRAP_HUP=''
}

deployment_transaction_signal_abort() {
    local signal="$1" code=1
    case "$signal" in INT) code=130 ;; HUP) code=129 ;; TERM) code=143 ;; esac
    deployment_transaction_rollback "signal ${signal}" || true
    restore_deployment_transaction_traps
    exit "$code"
}

deployment_transaction_exit_abort() {
    local code=$?
    trap - EXIT
    if [[ "${ABOX_DEPLOY_TX_ACTIVE:-0}" == 1 ]]; then deployment_transaction_rollback "unexpected shell exit ${code}" || true; fi
    restore_deployment_transaction_traps
    exit "$code"
}

install_deployment_transaction_traps() {
    ABOX_TX_PREV_TRAP_EXIT=$(trap -p EXIT || true)
    ABOX_TX_PREV_TRAP_INT=$(trap -p INT || true)
    ABOX_TX_PREV_TRAP_TERM=$(trap -p TERM || true)
    ABOX_TX_PREV_TRAP_HUP=$(trap -p HUP || true)
    trap 'deployment_transaction_exit_abort' EXIT
    trap 'deployment_transaction_signal_abort INT' INT
    trap 'deployment_transaction_signal_abort TERM' TERM
    trap 'deployment_transaction_signal_abort HUP' HUP
}

cleanup_ephemeral_deployment_transaction_dir() {
    local dir="${ABOX_DEPLOY_TX_EPHEMERAL_DIR:-}"
    [[ -n "$dir" && "$dir" == /run/A-Box-uninstall-tx.* && "$dir" != /run/ ]] || return 0
    rm -rf -- "$dir" 2>/dev/null || true
    ABOX_DEPLOY_TX_EPHEMERAL_DIR=''
}

deployment_transaction_rollback() {
    [[ "${ABOX_DEPLOY_TX_ACTIVE:-0}" == 1 ]] || return 0
    local targets="${ABOX_DEPLOY_TX_TARGETS:-}" reason="${ABOX_DEPLOY_TX_REASON:-deployment}" backup="${ABOX_DEPLOY_TX_BACKUP:-}" tx_tmp="${ABOX_DEPLOY_TX_TMP:-}" tx_backup_dir="${ABOX_DEPLOY_TX_BACKUP_DIR:-$ABOX_DIR/backups}" tx_key_file="${ABOX_DEPLOY_TX_KEY_FILE:-}" tx_ephemeral_dir="${ABOX_DEPLOY_TX_EPHEMERAL_DIR:-}" srv cleanup_failed=0
    [[ -n "${1:-}" ]] && reason="${reason}; $1"
    # Disable recursive EXIT rollback, but keep the snapshot/context fields until
    # rollback truly completes so an incomplete recovery remains diagnosable.
    ABOX_DEPLOY_TX_ACTIVE=0
    ABOX_DIE_HOOK=''
    msg "${YELLOW}[!] ${reason} failed; restoring the exact pre-operation snapshot.${NC}"

    if ! stop_all_managed_services >/dev/null 2>&1; then
        msg "${RED}[!] Rollback aborted before destructive cleanup: one or more managed services could not be confirmed stopped. Pre-operation backup retained: ${backup:-missing}${NC}" >&2
        return 1
    fi
    clean_nat_rules >/dev/null 2>&1 || cleanup_failed=1
    clean_input_rules >/dev/null 2>&1 || cleanup_failed=1
    remove_native_firewall_rules >/dev/null 2>&1 || cleanup_failed=1
    if (( cleanup_failed != 0 )); then
        msg "${RED}[!] Rollback aborted before removing core files: firewall cleanup could not be verified. Recovery backup retained: ${backup:-missing}${NC}" >&2
        return 1
    fi

    for srv in $targets; do
        if ! remove_core_family_force "$srv"; then
            msg "${RED}[!] Rollback aborted: unable to remove the staged/current ${srv} core family. No backup restore was attempted; recovery backup retained: ${backup:-missing}${NC}" >&2
            return 1
        fi
    done

    if [[ -n "$tx_key_file" ]]; then
        if ! restore_latest_backup_silent "$tx_backup_dir" "$backup" "$tx_key_file"; then
            msg "${RED}[!] Automatic rollback could not restore the exact pre-operation backup: ${backup:-missing}. Recovery context retained.${NC}" >&2
            return 1
        fi
    else
        if ! restore_latest_backup_silent "$tx_backup_dir" "$backup"; then
            msg "${RED}[!] Automatic rollback could not restore the exact pre-operation backup: ${backup:-missing}. Recovery context retained.${NC}" >&2
            return 1
        fi
    fi

    if [[ -n "$tx_tmp" ]]; then
        rm -rf -- "$tx_tmp" || { msg "${RED}[!] Prior state restored, but transaction staging cleanup failed: $tx_tmp${NC}" >&2; return 1; }
    fi
    if [[ -n "$tx_ephemeral_dir" && "$tx_ephemeral_dir" == /run/A-Box-uninstall-tx.* && "$tx_ephemeral_dir" != /run/ ]]; then
        rm -rf -- "$tx_ephemeral_dir" 2>/dev/null || { msg "${RED}[!] Prior state restored, but ephemeral transaction cleanup failed: $tx_ephemeral_dir${NC}" >&2; return 1; }
    fi
    ABOX_DEPLOY_TX_TARGETS=''
    ABOX_DEPLOY_TX_REASON=''
    ABOX_DEPLOY_TX_BACKUP=''
    ABOX_DEPLOY_TX_TMP=''
    ABOX_DEPLOY_TX_BACKUP_DIR=''
    ABOX_DEPLOY_TX_KEY_FILE=''
    ABOX_DEPLOY_TX_EPHEMERAL_DIR=''
    return 0
}

begin_deployment_transaction() {
    local reason="$1"; shift
    [[ "${ABOX_DEPLOY_TX_ACTIVE:-0}" == 1 ]] && die '检测到嵌套部署事务；拒绝静默复用外层事务。'
    ABOX_LAST_BACKUP=''
    local backup_dir="${ABOX_DEPLOY_TX_BACKUP_DIR:-$ABOX_DIR/backups}"
    auto_backup_silent "$reason" "$backup_dir"
    [[ -n "$ABOX_LAST_BACKUP" && -f "$ABOX_LAST_BACKUP" ]] || die '无法确认部署前备份文件。'
    ABOX_DEPLOY_TX_BACKUP_DIR="$backup_dir"
    ABOX_DEPLOY_TX_ACTIVE=1
    ABOX_DEPLOY_TX_REASON="$reason"
    ABOX_DEPLOY_TX_TARGETS="$*"
    ABOX_DEPLOY_TX_BACKUP="$ABOX_LAST_BACKUP"
    ABOX_DIE_HOOK=deployment_transaction_rollback
    install_deployment_transaction_traps
}

commit_deployment_transaction() {
    local tx_ephemeral_dir="${ABOX_DEPLOY_TX_EPHEMERAL_DIR:-}"
    ABOX_DEPLOY_TX_ACTIVE=0
    ABOX_DEPLOY_TX_TARGETS=''
    ABOX_DEPLOY_TX_REASON=''
    ABOX_DEPLOY_TX_BACKUP=''
    ABOX_DEPLOY_TX_TMP=''
    ABOX_DEPLOY_TX_BACKUP_DIR=''
    ABOX_DEPLOY_TX_KEY_FILE=''
    ABOX_DEPLOY_TX_EPHEMERAL_DIR=''
    ABOX_DIE_HOOK=''
    restore_deployment_transaction_traps
    if [[ -n "$tx_ephemeral_dir" && "$tx_ephemeral_dir" == /run/A-Box-uninstall-tx.* && "$tx_ephemeral_dir" != /run/ ]]; then
        rm -rf -- "$tx_ephemeral_dir" 2>/dev/null || true
    fi
}


parse_x25519_keypair_output() {
    local input="${1:-}" line key value private_key='' public_key=''
    [[ -n "$input" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        [[ "$line" == *:* ]] || continue
        key=${line%%:*}
        value=${line#*:}
        key=${key#"${key%%[!$' \t']*}"}; key=${key%"${key##*[!$' \t']}"}
        value=${value#"${value%%[!$' \t']*}"}; value=${value%"${value##*[!$' \t']}"}
        case "${key,,}" in
            privatekey|private\ key)
                [[ -z "$private_key" ]] || continue
                private_key="$value"
                ;;
            password\ \(publickey\)|password\ \(public\ key\)|publickey|public\ key)
                [[ -z "$public_key" ]] || continue
                public_key="$value"
                ;;
            password)
                [[ -n "$public_key" ]] || public_key="$value"
                ;;
        esac
    done <<< "$input"
    [[ -n "$private_key" && -n "$public_key" ]] || return 1
    printf '%s\t%s\n' "$private_key" "$public_key"
}


deploy_xray() {
    local MODE_IN=$1 KEYPAIR
    clear; msg "${BOLD}${GREEN}部署 Xray-core [$MODE_IN]${NC}"
    init_system_environment
    load_optional_abox_env_or_die
    light_preflight_check
    if [[ "$MODE_IN" == *'ALL'* ]]; then assert_no_foreign_core_conflicts xray hysteria; else assert_no_foreign_core_conflicts xray; fi
    confirm_deployment_replacement xray "$MODE_IN"
    if [[ "$MODE_IN" == *'ALL'* ]]; then begin_deployment_transaction "xray ${MODE_IN} deployment" xray hysteria; else begin_deployment_transaction "xray ${MODE_IN} deployment" xray; fi
    release_ports
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    pre_install_setup xray "$MODE_IN"
    get_architecture

    local xray_tmp xray_zip xray_ext geo_tmp
    xray_tmp=$(mktemp -d /tmp/A-Box-xray.XXXXXX) || die 'Xray 临时目录创建失败。'
    ABOX_DEPLOY_TX_TMP="$xray_tmp"
    xray_zip="$xray_tmp/xray_core.zip"
    xray_ext="$xray_tmp/xray_ext"
    mkdir -p "$xray_ext" || die 'Xray extraction directory creation failed.'
    fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
    extract_zip_member_safely "$xray_zip" xray "$xray_ext/xray" || die 'Xray 压缩包安全提取失败。'
    [[ -f "$xray_ext/xray" && ! -L "$xray_ext/xray" ]] || die '安全提取后未找到 xray 主程序。'
    chmod 755 "$xray_ext/xray" || die 'Xray staged binary chmod failed.'
    "$xray_ext/xray" version >/dev/null 2>&1 || die 'Xray staged binary execution check failed.'
    install_binary_atomically "$xray_ext/xray" /usr/local/bin/xray || die 'Xray binary atomic install failed.'
    /usr/local/bin/xray version >/dev/null 2>&1 || die 'Xray 执行校验失败。'
    install -d -m 755 /usr/local/share/xray /usr/local/etc/xray || die 'Xray data/config directory creation failed.'

    geo_tmp="$xray_tmp/geo"
    mkdir -p "$geo_tmp" || die 'Xray Geo 临时目录创建失败。'
    fetch_geo_data geoip.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat' "$geo_tmp/geoip.dat"
    fetch_geo_data geosite.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat' "$geo_tmp/geosite.dat"
    install_file_atomically "$geo_tmp/geoip.dat" /usr/local/share/xray/geoip.dat 644 || die 'geoip.dat 原子安装失败。'
    install_file_atomically "$geo_tmp/geosite.dat" /usr/local/share/xray/geosite.dat 644 || die 'geosite.dat 原子安装失败。'
    rm -rf -- "$xray_tmp"
    ABOX_DEPLOY_TX_TMP=''

    KEYPAIR=$(/usr/local/bin/xray x25519) || die 'Xray REALITY 密钥对生成失败。'
    IFS=$'\t' read -r PK PBK < <(parse_x25519_keypair_output "$KEYPAIR") || die '无法从 Xray x25519 输出解析私钥/公钥。'
    [[ -n "$PK" && -n "$PBK" ]] || die 'Xray REALITY 密钥对为空。'
    UUID=$(generate_robust_uuid)
    SHORT_ID=$(openssl rand -hex 4 | tr -d '\n\r')
    SS_PASS=$(openssl rand -base64 16 | tr -d '\n\r')
    [[ -n "$SS_PASS" ]] || die 'SS-2022 密钥生成失败。'

    build_xray_config "$MODE_IN"
    chmod 600 /usr/local/etc/xray/config.json || die 'Xray config permission hardening failed.'
    jq empty /usr/local/etc/xray/config.json >/dev/null 2>&1 || die 'Xray JSON 格式非法。'
    /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1 || die 'Xray 配置校验失败。'

    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        write_file_atomically_from_stdin /etc/systemd/system/xray.service 644 <<'EOF_SVC' || die 'Xray systemd unit 原子写入失败。'
# Managed by A-Box
[Unit]
Description=A-Box Xray Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=abox-xray
Group=abox-xray
Environment="XRAY_LOCATION_ASSET=/usr/local/share/xray"
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
NoNewPrivileges=true
PrivateTmp=true
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        path_parent_chain_safe /etc/conf.d/xray || die 'OpenRC conf.d 父链不安全。'
        [[ ! -L /etc/conf.d && (! -e /etc/conf.d || -d /etc/conf.d) ]] || die 'OpenRC conf.d 目录不安全。'
        mkdir -p /etc/conf.d || die 'OpenRC conf.d 目录创建失败。'
        write_file_atomically_from_stdin /etc/conf.d/xray 644 <<'EOF_XRAY_CONFD' || die 'Xray OpenRC conf.d 原子写入失败。'
rc_ulimit="-n 1048576"
export XRAY_LOCATION_ASSET="/usr/local/share/xray"
EOF_XRAY_CONFD
        write_file_atomically_from_stdin /etc/init.d/xray 755 <<'EOF_SVC' || die 'Xray OpenRC unit 原子写入失败。'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Xray Service"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background="yes"
command_user="abox-xray:abox-xray"
capabilities="cap_net_bind_service"
pidfile="/run/xray.pid"
depend() { need net; }
EOF_SVC
        chmod +x /etc/init.d/xray || die 'Xray OpenRC 服务权限设置失败。'
    fi
    prepare_abox_runtime_permissions xray || die 'Xray 运行时用户/文件权限准备失败。'
    service_manager start xray
    setup_geo_cron
    setup_active_defense
    setup_health_monitor

    if [[ "$MODE_IN" == *'ALL'* ]]; then
        deploy_official_hy2 SILENT || die 'HY2 deployment failed during Xray ALL.'
    fi
    write_env xray "$MODE_IN"
    set_desired_state RUNNING || die 'Xray 服务期望状态提交失败。'
    if [[ "$MODE_IN" == *ALL* ]]; then prune_owned_core_families_except xray hysteria; else prune_owned_core_families_except xray; fi
    commit_deployment_transaction
    view_config deploy
}

deploy_singbox() {
    local MODE_IN=$1 KEYPAIR SB_PATH cert_cn='localhost' SB_PRE_START='' SB_POST_STOP='' SB_RC_PRE='' SB_RC_POST='' SB_CAPS='CAP_NET_BIND_SERVICE'
    clear; msg "${BOLD}${GREEN}部署 Sing-box 核心 [$MODE_IN]${NC}"
    init_system_environment
    load_optional_abox_env_or_die
    light_preflight_check
    assert_no_foreign_core_conflicts sing-box
    confirm_deployment_replacement singbox "$MODE_IN"
    begin_deployment_transaction "sing-box ${MODE_IN} deployment" sing-box
    release_ports
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    pre_install_setup singbox "$MODE_IN"
    get_architecture

    local sb_tmp sb_tar sb_ext
    sb_tmp=$(mktemp -d /tmp/A-Box-singbox.XXXXXX) || die 'Sing-box 临时目录创建失败。'
    ABOX_DEPLOY_TX_TMP="$sb_tmp"
    sb_tar="$sb_tmp/singbox_core.tar.gz"
    sb_ext="$sb_tmp/extract"
    mkdir -p "$sb_ext" || die 'Sing-box 临时提取目录创建失败。'
    fetch_github_release SagerNet/sing-box singbox_core.tar.gz "$sb_tar"
    SB_PATH="$sb_ext/sing-box"
    extract_tar_regular_basename_safely "$sb_tar" sing-box "$SB_PATH" || die 'Sing-box 压缩包安全提取失败。'
    [[ -f "$SB_PATH" && ! -L "$SB_PATH" ]] || die '安全提取后未找到 sing-box 主程序。'
    chmod 755 "$SB_PATH" || die 'Sing-box staged binary chmod failed.'
    "$SB_PATH" version >/dev/null 2>&1 || die 'Sing-box staged binary execution check failed.'
    install_binary_atomically "$SB_PATH" /usr/local/bin/sing-box || die 'Sing-box binary atomic install failed.'
    rm -rf -- "$sb_tmp"
    ABOX_DEPLOY_TX_TMP=''
    /usr/local/bin/sing-box version >/dev/null 2>&1 || die 'Sing-box 执行校验失败。'

    prepare_abox_runtime_config_dir sing-box /etc/sing-box || die 'Sing-box config directory preparation failed.'
    KEYPAIR=$(/usr/local/bin/sing-box generate reality-keypair)
    PK=$(awk '/Private/{print $NF; found=1; exit} /Password/{fallback=$NF} END{if (!found && fallback != "") print fallback}' <<< "$KEYPAIR")
    PBK=$(awk '/Public/{print $NF; exit}' <<< "$KEYPAIR")
    [[ -n "$PK" && -n "$PBK" ]] || die 'Sing-box REALITY 密钥生成失败。'
    UUID=$(generate_robust_uuid)
    SHORT_ID=$(openssl rand -hex 4 | tr -d '\n\r')
    SS_PASS=$(openssl rand -base64 16 | tr -d '\n\r')
    [[ -n "$SS_PASS" ]] || die 'SS-2022 密钥生成失败。'

    if [[ "$MODE_IN" == *'HY2'* || "$MODE_IN" == *'ALL'* ]]; then
        HY2_PASS=$(rand_alnum 20)
        HY2_OBFS=$(rand_alnum 16)
        [[ -n "${HY2_DOMAIN:-}" ]] && cert_cn="$HY2_DOMAIN"
        generate_self_signed_cert_atomically /etc/sing-box/hy2.key /etc/sing-box/hy2.crt "$cert_cn" || die 'sing-box HY2 自签证书生成或密钥配对验证失败。'
        HY2_CERT_SHA256_FP=$(pin_sha256_colon /etc/sing-box/hy2.crt | tr -d ':')
        HY2_CERT_PUBKEY_SHA256_B64=$(openssl x509 -in /etc/sing-box/hy2.crt -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 | tr -d '\n')
    fi

    build_singbox_config "$MODE_IN"
    chmod 600 /etc/sing-box/config.json || die 'Sing-box config permission hardening failed.'
    jq empty /etc/sing-box/config.json >/dev/null 2>&1 || die 'Sing-box JSON 格式非法。'
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || die 'Sing-box 配置校验失败。'

    if [[ "$MODE_IN" == *'HY2'* || "$MODE_IN" == *'ALL'* ]] && [[ "${HY2_HOP:-}" == 'true' ]]; then
        SB_CAPS='CAP_NET_ADMIN CAP_NET_BIND_SERVICE'
        SB_PRE_START="ExecStartPre=-+/bin/sh -c '$IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'
ExecStartPre=+/bin/sh -c '$IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT'"
        SB_POST_STOP="ExecStopPost=-+/bin/sh -c '$IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
        SB_RC_PRE="start_pre() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true
  $IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT || return 1"
        SB_RC_POST="stop_post() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
        if has_ipv6 && ipv6_nat_redirect_usable; then
            SB_PRE_START+="
ExecStartPre=-+/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'
ExecStartPre=+/bin/sh -c '$IPT6 -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT'"
            SB_POST_STOP+="
ExecStopPost=-+/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
            SB_RC_PRE+="
  $IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true
  $IPT6 -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT || return 1"
            SB_RC_POST+="
  $IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
        fi
        SB_RC_PRE+="
  return 0
}"
        SB_RC_POST+="
  return 0
}"
    fi

    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        write_file_atomically_from_stdin /etc/systemd/system/sing-box.service 644 <<EOF_SVC || die 'sing-box systemd unit 原子写入失败。'
# Managed by A-Box
[Unit]
Description=A-Box Sing-Box Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=abox-singbox
Group=abox-singbox
CapabilityBoundingSet=$SB_CAPS
AmbientCapabilities=$SB_CAPS
$SB_PRE_START
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
$SB_POST_STOP
NoNewPrivileges=true
PrivateTmp=true
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        path_parent_chain_safe /etc/conf.d/sing-box || die 'OpenRC conf.d 父链不安全。'
        [[ ! -L /etc/conf.d && (! -e /etc/conf.d || -d /etc/conf.d) ]] || die 'OpenRC conf.d 目录不安全。'
        mkdir -p /etc/conf.d || die 'OpenRC conf.d 目录创建失败。'
        write_file_atomically_from_stdin /etc/conf.d/sing-box 644 <<'EOF_SB_CONFD' || die 'sing-box OpenRC conf.d 原子写入失败。'
rc_ulimit="-n 1048576"
EOF_SB_CONFD
        write_file_atomically_from_stdin /etc/init.d/sing-box 755 <<EOF_SVC || die 'sing-box OpenRC unit 原子写入失败。'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Sing-Box Service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
command_user="abox-singbox:abox-singbox"
capabilities="cap_net_bind_service"
pidfile="/run/sing-box.pid"
depend() { need net; }
$SB_RC_PRE
$SB_RC_POST
EOF_SVC
        chmod +x /etc/init.d/sing-box || die 'Sing-box OpenRC 服务权限设置失败。'
    fi
    prepare_abox_runtime_permissions sing-box || die 'Sing-box 运行时用户/文件权限准备失败。'
    service_manager start sing-box
    setup_active_defense
    setup_health_monitor
    write_env singbox "$MODE_IN"
    set_desired_state RUNNING || die 'sing-box 服务期望状态提交失败。'
    prune_owned_core_families_except sing-box
    setup_geo_cron
    commit_deployment_transaction
    view_config deploy
}

get_month_total_bytes() {
    local iface="$1" mode="${2:-total}" json rx tx line month_count
    if command -v jq >/dev/null 2>&1 && json=$(vnstat -i "$iface" --json m 1 2>/dev/null); then
        month_count=$(jq -r '(.interfaces[0].traffic.month // .interfaces[0].traffic.months // []) | length' <<< "$json" 2>/dev/null || printf 'x')
        if [[ "$month_count" == '0' ]]; then
            case "$mode" in rx|tx|total) printf '0
'; return 0 ;; *) return 1 ;; esac
        fi
        rx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .rx) // empty' <<< "$json" 2>/dev/null)
        tx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .tx) // empty' <<< "$json" 2>/dev/null)
        if [[ "$rx" =~ ^[0-9]+$ && "$tx" =~ ^[0-9]+$ ]]; then
            case "$mode" in
                rx) printf '%s
' "$rx" ;;
                tx) printf '%s
' "$tx" ;;
                total) python3 - "$rx" "$tx" <<'PY_VNSTAT_TOTAL_MAIN'
import sys
print(int(sys.argv[1]) + int(sys.argv[2]))
PY_VNSTAT_TOTAL_MAIN
                    ;;
                *) return 1 ;;
            esac
            return 0
        fi
    fi
    line=$(vnstat -i "$iface" --oneline b 2>/dev/null) || return 1
    case "$mode" in rx) awk -F';' '{print $9}' <<< "$line" ;; tx) awk -F';' '{print $10}' <<< "$line" ;; total) awk -F';' '{print $11}' <<< "$line" ;; *) return 1 ;; esac
}

bytes_to_gb() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'; }

ensure_vnstat_runtime() {
    if ! command -v vnstat >/dev/null 2>&1; then
        msg "${YELLOW}[*] 未检测到 vnStat；正在按需安装流量统计组件...${NC}"
        install_optional_package vnstat || die 'vnStat 安装失败，无法启用流量限制。'
    fi
    command -v vnstat >/dev/null 2>&1 || die 'vnStat 安装后仍不可用，无法启用流量限制。'
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        if systemctl list-unit-files vnstat.service >/dev/null 2>&1; then
            systemctl enable --now vnstat >/dev/null 2>&1 || die 'vnStat 服务无法启动；未启用流量限制。'
            systemctl is-active --quiet vnstat || die 'vnStat 服务未处于 active 状态；未启用流量限制。'
        elif systemctl list-unit-files vnstatd.service >/dev/null 2>&1; then
            systemctl enable --now vnstatd >/dev/null 2>&1 || die 'vnStat 服务无法启动；未启用流量限制。'
            systemctl is-active --quiet vnstatd || die 'vnStat 服务未处于 active 状态；未启用流量限制。'
        else
            die '系统未提供可识别的 vnStat systemd 服务；无法安全启用流量限制。'
        fi
    elif [[ "${INIT_SYS:-}" == 'openrc' ]]; then
        [[ -x /etc/init.d/vnstatd ]] || die '系统未提供 vnstatd OpenRC 服务；无法安全启用流量限制。'
        rc-update add vnstatd default >/dev/null 2>&1 || die 'vnStat OpenRC 服务无法加入 default runlevel。'
        rc-service vnstatd restart >/dev/null 2>&1 || die 'vnStat OpenRC 服务无法启动；未启用流量限制。'
        rc-service vnstatd status >/dev/null 2>&1 || die 'vnStat OpenRC 服务未处于运行状态；未启用流量限制。'
    else
        die '无法确认 vnStat 运行时环境；未启用流量限制。'
    fi
}

setup_traffic_monitor() {
    ensure_vnstat_runtime
    [[ -z "${ABOX_TRAFFIC_TX_DIR:-}" ]] || capture_traffic_quota_expected_state "$ABOX_TRAFFIC_TX_DIR" || die '流量限制事务状态快照失败。'
    install -d -m 700 "$ABOX_DIR" || die '无法创建流量监控目录。'
    write_file_atomically_from_stdin "$ABOX_DIR/traffic_monitor.sh" 700 <<'EOF_TRAFFIC' || die '流量监控脚本原子写入失败。'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
ENV=/etc/ddr/.env
DESIRED=/etc/ddr/.desired_state
BLOCK_STATE=/etc/ddr/.traffic-block-state
PAIR_STATE=/etc/ddr/.traffic-pair-state
INIT_SYS_EXPECTED='unknown'
exec 9>>/run/A-Box-traffic-monitor.lock || exit 1
flock -n 9 || exit 0
RUNTIME_LOCK=/run/A-Box.lock
acquire_abox_runtime_guard() {
    local FALLBACK_DIR=/run/A-Box.lock.d fb_pid fb_start fb_actual mode
    [[ -d /run && ! -L /run ]] || exit 0
    # If a live fallback lock is held by another A-Box process, yield. Helpers
    # must not treat an idle LOCK_FILE flock as free while main owns fallback.
    if [[ -d "$FALLBACK_DIR" && ! -L "$FALLBACK_DIR" && -r "$FALLBACK_DIR/pid" && -r "$FALLBACK_DIR/starttime" ]]; then
        [[ "$(stat -c %u:%g "$FALLBACK_DIR" 2>/dev/null || true)" == 0:0 ]] || exit 0
        mode=$(stat -c %a "$FALLBACK_DIR" 2>/dev/null) || exit 0
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
        (( (8#$mode & 8#077) == 0 )) || exit 0
        IFS= read -r fb_pid < "$FALLBACK_DIR/pid" || exit 0
        IFS= read -r fb_start < "$FALLBACK_DIR/starttime" || exit 0
        if [[ "$fb_pid" =~ ^[0-9]+$ && -d "/proc/$fb_pid" ]]; then
            fb_actual=$(awk '{print $22}' "/proc/${fb_pid}/stat" 2>/dev/null || true)
            [[ -n "$fb_actual" && "$fb_actual" == "$fb_start" ]] && exit 0
        fi
    fi
    # /run is recreated on reboot; recreate the shared lock inode on demand.
    if [[ ! -e "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]]; then
        ( umask 077; set -C; : > "$RUNTIME_LOCK" ) 2>/dev/null || true
    fi
    [[ -f "$RUNTIME_LOCK" && ! -L "$RUNTIME_LOCK" ]] || exit 0
    [[ "$(stat -c %u:%g "$RUNTIME_LOCK" 2>/dev/null || true)" == 0:0 ]] || exit 0
    mode=$(stat -c %a "$RUNTIME_LOCK" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || exit 0
    (( (8#$mode & 8#077) == 0 )) || exit 0
    exec 10>>"$RUNTIME_LOCK" || exit 0
    flock -n 10 || exit 0
}
acquire_abox_runtime_guard
load_state() {
    local parsed key value uid gid mode
    [[ -r "$ENV" && -f "$ENV" && ! -L "$ENV" ]] || return 1
    uid=$(stat -c %u "$ENV" 2>/dev/null) || return 1
    gid=$(stat -c %g "$ENV" 2>/dev/null) || return 1
    mode=$(stat -c %a "$ENV" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    parsed=$(umask 077; mktemp /tmp/A-Box-helper-env.XXXXXX) || return 1
    if ! python3 - "$ENV" > "$parsed" <<'PY_HELPER_ENV'; then
import shlex
import sys
allowed = {"CORE", "MODE", "VLESS_PORT", "XHTTP_PORT", "HY2_MONITOR_PORT", "HY2_HOP", "HY2_HOP_IMPL", "HY2_RANGE_START", "HY2_RANGE_END", "SS_PORT", "TRAFFIC_LIMIT_GB", "TRAFFIC_LIMIT_MODE", "INGRESS_IF"}
seen = set()
with open(sys.argv[1], encoding="utf-8", errors="strict") as handle:
    for raw in handle:
        line = raw.rstrip("\n")
        if not line or line.lstrip().startswith("#"): continue
        if "=" not in line: raise SystemExit(1)
        key, raw_value = line.split("=", 1)
        if key not in allowed: continue
        if key in seen or raw_value.startswith("$'"): raise SystemExit(1)
        parts = shlex.split(raw_value, posix=True)
        if len(parts) != 1 or any(c in parts[0] for c in "\x00\r\n"): raise SystemExit(1)
        seen.add(key)
        sys.stdout.buffer.write(key.encode("ascii") + b"\0" + parts[0].encode("utf-8") + b"\0")
PY_HELPER_ENV
        rm -f "$parsed"
        return 1
    fi
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do printf -v "$key" '%s' "$value"; done < "$parsed"
    rm -f "$parsed"
}
write_private_line() {
    local dest="$1" value="$2" tmp parent uid gid mode
    case "$dest" in
        "$DESIRED"|"$BLOCK_STATE"|"$PAIR_STATE") ;;
        *) return 1 ;;
    esac
    parent=$(dirname -- "$dest") || return 1
    [[ "$parent" == /etc/ddr && -d "$parent" && ! -L "$parent" ]] || return 1
    uid=$(stat -c %u "$parent" 2>/dev/null) || return 1
    gid=$(stat -c %g "$parent" 2>/dev/null) || return 1
    mode=$(stat -c %a "$parent" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    [[ ! -L "$dest" && ! -d "$dest" ]] || return 1
    tmp=$(umask 077; mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    printf '%s\n' "$value" > "$tmp" && chown root:root "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}
# Atomic desired+period publish: write PAIR first, then derive legacy files.
commit_traffic_pair() {
    local desired="$1" period="${2:-}"
    [[ "$desired" =~ ^(RUNNING|TRAFFIC_BLOCKED|MANUAL_STOPPED|MAINTENANCE)$ ]] || return 1
    if [[ -n "$period" ]]; then
        [[ "$period" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || return 1
    fi
    write_private_line "$PAIR_STATE" "${desired}|${period}" || return 1
    write_private_line "$DESIRED" "$desired" || return 1
    if [[ -n "$period" ]]; then
        write_private_line "$BLOCK_STATE" "$period" || return 1
    else
        rm -f -- "$BLOCK_STATE" || return 1
    fi
}
read_traffic_pair_fields() {
    local line desired period mode
    [[ -r "$PAIR_STATE" && -f "$PAIR_STATE" && ! -L "$PAIR_STATE" ]] || return 1
    [[ "$(stat -c %u:%g "$PAIR_STATE" 2>/dev/null)" == 0:0 ]] || return 1
    mode=$(stat -c %a "$PAIR_STATE" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
    IFS= read -r line < "$PAIR_STATE" || return 1
    [[ "$line" == *'|'* ]] || return 1
    desired=${line%%|*}; period=${line#*|}
    [[ "$desired" =~ ^(RUNNING|TRAFFIC_BLOCKED|MANUAL_STOPPED|MAINTENANCE)$ ]] || return 1
    if [[ -n "$period" ]]; then
        [[ "$period" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || return 1
    fi
    printf '%s\n%s\n' "$desired" "$period"
}
read_desired() {
    local state=RUNNING mode pair desired
    if pair=$(read_traffic_pair_fields); then
        IFS= read -r desired <<< "$pair"
        printf '%s\n' "$desired"
        return 0
    fi
    if [[ -e "$DESIRED" || -L "$DESIRED" ]]; then
        [[ -r "$DESIRED" && -f "$DESIRED" && ! -L "$DESIRED" ]] || return 1
        [[ "$(stat -c %u:%g "$DESIRED" 2>/dev/null)" == 0:0 ]] || return 1
        mode=$(stat -c %a "$DESIRED" 2>/dev/null) || return 1
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
        IFS= read -r state < "$DESIRED" || return 1
    fi
    [[ "$state" =~ ^(RUNNING|TRAFFIC_BLOCKED|MANUAL_STOPPED|MAINTENANCE)$ ]] || return 1
    printf '%s\n' "$state"
}
read_block_period() {
    local period mode pair
    if pair=$(read_traffic_pair_fields); then
        period=${pair#*$'\n'}
        [[ -n "$period" ]] || return 1
        printf '%s\n' "$period"
        return 0
    fi
    [[ -r "$BLOCK_STATE" && -f "$BLOCK_STATE" && ! -L "$BLOCK_STATE" ]] || return 1
    [[ "$(stat -c %u:%g "$BLOCK_STATE" 2>/dev/null)" == 0:0 ]] || return 1
    mode=$(stat -c %a "$BLOCK_STATE" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
    IFS= read -r period < "$BLOCK_STATE" || return 1
    [[ "$period" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || return 1
    printf '%s\n' "$period"
}
month_bytes() {
    local i="$1" mode="${2:-total}" json rx tx line month_count
    if command -v jq >/dev/null 2>&1 && json=$(vnstat -i "$i" --json m 1 2>/dev/null); then
        # A newly initialized vnStat database may have an interface entry but no
        # monthly sample yet. Treat an empty monthly series as 0 for quota purposes.
        # A failed interface/database query still falls through and remains fail-closed.
        month_count=$(jq -r '(.interfaces[0].traffic.month // .interfaces[0].traffic.months // []) | length' <<< "$json" 2>/dev/null || printf 'x')
        if [[ "$month_count" == '0' ]]; then
            case "$mode" in rx|tx|total) printf '0
'; return 0 ;; *) return 1 ;; esac
        fi
        rx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .rx) // empty' <<< "$json" 2>/dev/null)
        tx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .tx) // empty' <<< "$json" 2>/dev/null)
        if [[ "$rx" =~ ^[0-9]+$ && "$tx" =~ ^[0-9]+$ ]]; then
            case "$mode" in
                rx) echo "$rx" ;;
                tx) echo "$tx" ;;
                total) python3 - "$rx" "$tx" <<'PY_VNSTAT_TOTAL_MONITOR'
import sys
print(int(sys.argv[1]) + int(sys.argv[2]))
PY_VNSTAT_TOTAL_MONITOR
                    ;;
                *) return 1 ;;
            esac
            return 0
        fi
    fi
    line=$(vnstat -i "$i" --oneline b 2>/dev/null) || return 1
    case "$mode" in rx) awk -F';' '{print $9}' <<< "$line";; tx) awk -F';' '{print $10}' <<< "$line";; total) awk -F';' '{print $11}' <<< "$line";; *) return 1;; esac
}
is_systemd() { [[ "$INIT_SYS_EXPECTED" == systemd ]]; }
managed_unit_path() {
    case "$1" in
        xray|sing-box|hysteria)
            if is_systemd; then printf '/etc/systemd/system/%s.service\n' "$1"; else printf '/etc/init.d/%s\n' "$1"; fi
            ;;
        *) return 1 ;;
    esac
}
owned() {
    local srv="$1" u
    u=$(managed_unit_path "$srv") || return 1
    [[ -f "$u" && ! -L "$u" ]] && grep -Fxq '# Managed by A-Box' "$u"
}
force_stop_owned_openrc() {
    local srv="$1" pidfile exe pid owner proc_exe
    case "$srv" in
        xray) pidfile=/run/xray.pid; exe=/usr/local/bin/xray ;;
        sing-box) pidfile=/run/sing-box.pid; exe=/usr/local/bin/sing-box ;;
        hysteria) pidfile=/run/hysteria.pid; exe=/usr/local/bin/hysteria ;;
        *) return 1 ;;
    esac
    [[ -f "$pidfile" && ! -L "$pidfile" ]] || return 1
    [[ "$(stat -c %h "$pidfile" 2>/dev/null)" == 1 ]] || return 1
    owner=$(stat -c %u "$pidfile" 2>/dev/null) || return 1
    [[ "$owner" == 0 ]] || return 1
    pid=$(cat -- "$pidfile" 2>/dev/null) || return 1
    [[ "$pid" =~ ^[1-9][0-9]{0,9}$ ]] && (( 10#$pid > 1 )) || return 1
    proc_exe=$(readlink "/proc/${pid}/exe" 2>/dev/null) || return 1
    [[ "$proc_exe" == "$exe" ]] || return 1
    command -v start-stop-daemon >/dev/null 2>&1 || return 1
    # OpenRC's own process helper verifies both the pidfile and executable
    # before signaling. Never fall back to an unqualified kill by PID.
    start-stop-daemon --stop --pidfile "$pidfile" --exec "$exe" --retry TERM/5/KILL/1 >/dev/null 2>&1 || return 1
}

stop_owned() {
    local srv="$1" u rc enabled_state
    u=$(managed_unit_path "$srv") || return 1
    if ! owned "$srv"; then
        # An existing but unmarked unit is outside A-Box ownership and cannot be
        # changed. If the unit file is absent, still query the service manager:
        # a previously loaded unit may remain active after its file was removed.
        [[ ! -e "$u" && ! -L "$u" ]] || return 1
        if is_systemd; then
            local load_state
            load_state=$(systemctl show -p ActiveState --value "$srv" 2>/dev/null) || return 1
            case "$load_state" in inactive|failed|dead|not-found) return 0 ;; *) return 1 ;; esac
        else
            rc-service "$srv" status >/dev/null 2>&1; rc=$?
            case "$rc" in 3|16|32) return 0 ;; *) return 1 ;; esac
        fi
    fi
    if is_systemd; then
        systemctl stop "$srv" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$srv"; then
            # Restart=always can race a failed stop. Disable first, then kill the
            # unit cgroup and re-check actual activity before reporting success.
            systemctl disable "$srv" >/dev/null 2>&1 || return 1
            systemctl kill --kill-who=all --signal=SIGKILL "$srv" >/dev/null 2>&1 || true
            systemctl stop "$srv" >/dev/null 2>&1 || true
        fi
        systemctl is-active --quiet "$srv" && return 1
        systemctl disable "$srv" >/dev/null 2>&1 || return 1
        enabled_state=$(systemctl show -p UnitFileState --value "$srv" 2>/dev/null) || return 1
        [[ "$enabled_state" == disabled ]] || return 1
        return 0
    else
        rc-service "$srv" stop >/dev/null 2>&1 || true
        rc-service "$srv" status >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            # If OpenRC's stop action failed and the service remains active,
            # try its pidfile-aware TERM/KILL escalation only after validating
            # that the pidfile belongs to root and the PID maps to this core.
            force_stop_owned_openrc "$srv" || return 1
            rc-service "$srv" status >/dev/null 2>&1; rc=$?
        fi
        case "$rc" in
            0) return 1 ;;
            3|16|32) : ;;
            *) return 1 ;;
        esac
        if rc-update show default 2>/dev/null | grep -Eq "(^|[[:space:]])${srv}([[:space:]]|$)"; then
            rc-update del "$srv" default >/dev/null 2>&1 || return 1
        fi
        rc-update show default 2>/dev/null | grep -Eq "(^|[[:space:]])${srv}([[:space:]]|$)" && return 1
        rc-service "$srv" status >/dev/null 2>&1; rc=$?
        case "$rc" in
            0) return 1 ;;
            3|16|32) : ;;
            *) return 1 ;;
        esac
    fi
}
start_owned() {
    local srv="$1"
    owned "$srv" || return 0
    if is_systemd; then
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        systemctl enable "$srv" >/dev/null 2>&1 || return 1
        systemctl restart "$srv" >/dev/null 2>&1 || return 1
        systemctl is-active --quiet "$srv"
    else
        rc-update add "$srv" default >/dev/null 2>&1 || return 1
        rc-service "$srv" restart >/dev/null 2>&1 || return 1
        rc-service "$srv" status >/dev/null 2>&1
    fi
}
for_expected_services() {
    case "${CORE:-}" in
        xray)
            "$1" xray || return 1
            if [[ "${MODE:-}" == *ALL* ]]; then "$1" hysteria || return 1; fi
            ;;
        singbox) "$1" sing-box || return 1 ;;
        hysteria) "$1" hysteria || return 1 ;;
        *) return 1 ;;
    esac
}
traffic_error() {
    local log=/var/log/A-Box-traffic.log uid gid mode nlink
    [[ -d /var/log && ! -L /var/log ]] || return 0
    if [[ -L "$log" || -e "$log" && ! -f "$log" ]]; then return 0; fi
    if [[ ! -e "$log" ]]; then
        install -o root -g root -m 600 /dev/null "$log" 2>/dev/null || return 0
    fi
    uid=$(stat -c %u "$log" 2>/dev/null) || return 0
    gid=$(stat -c %g "$log" 2>/dev/null) || return 0
    mode=$(stat -c %a "$log" 2>/dev/null) || return 0
    nlink=$(stat -c %h "$log" 2>/dev/null) || return 0
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^0?600$ && "$nlink" == 1 ]] || return 0
    umask 077
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >> "$log" 2>/dev/null || true
}
current_period=$(date +%Y-%m)
stop_all_owned_services() {
    local srv
    for srv in xray sing-box hysteria; do
        owned "$srv" || continue
        stop_owned "$srv" || return 1
    done
    return 0
}
traffic_fail_closed() {
    local reason="${1:-traffic accounting failed}" failed=0
    traffic_error "$reason; enforcing fail-closed traffic block"
    commit_traffic_pair TRAFFIC_BLOCKED "$current_period" || failed=1
    stop_all_owned_services || failed=1
    return "$failed"
}
state_load_failed=0
load_state || state_load_failed=1
if (( state_load_failed != 0 )); then
    # A missing initial state is harmless during provisioning; an existing but
    # unreadable/invalid persisted state is fail-closed because its traffic
    # limits cannot be trusted to remain enforceable.
    if [[ -e "$ENV" || -L "$ENV" || -e "$DESIRED" || -L "$DESIRED" || -e "$BLOCK_STATE" || -L "$BLOCK_STATE" || -e "$PAIR_STATE" || -L "$PAIR_STATE" ]]; then
        traffic_fail_closed 'persisted traffic state is unreadable or invalid' || traffic_error 'invalid persisted traffic state could not be fail-closed enforced'
        exit 1
    fi
    exit 0
fi
valid_traffic_limit_gb() {
    local input="${1:-}"
    [[ "$input" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    (( 10#$input <= 8589934591 ))
}
valid_backup_retention_count() {
    local input="${1:-}"
    [[ "$input" =~ ^[0-9]{1,4}$ ]] || return 1
    (( 10#$input <= 1000 ))
}
valid_hy2_bandwidth_mbps() {
    # Keep the interactive HY2 bandwidth domain identical to the persisted .env validator.
    valid_traffic_limit_gb "${1:-}"
}
[[ -z "${TRAFFIC_LIMIT_GB:-}" ]] || valid_traffic_limit_gb "$TRAFFIC_LIMIT_GB" || {
    traffic_fail_closed 'persisted traffic limit is invalid' || traffic_error 'invalid persisted traffic limit could not be fail-closed enforced'
    exit 1
}
desired=$(read_desired) || exit 1
blocked_period=$(read_block_period 2>/dev/null || true)
if [[ "$desired" == TRAFFIC_BLOCKED && -z "$blocked_period" ]]; then
    commit_traffic_pair TRAFFIC_BLOCKED "$current_period" || exit 1
    blocked_period="$current_period"
    traffic_error "migrated legacy traffic-blocked state into billing period ${current_period}"
fi
if [[ "$desired" == TRAFFIC_BLOCKED && "$blocked_period" != "$current_period" ]]; then
    commit_traffic_pair MAINTENANCE "$blocked_period" || exit 1
    if ! for_expected_services start_owned; then
        for_expected_services stop_owned >/dev/null 2>&1 || true
        commit_traffic_pair TRAFFIC_BLOCKED "$blocked_period" || true
        traffic_error 'monthly quota period rolled over but at least one owned service could not be started; block remains active'
        exit 1
    fi
    if ! commit_traffic_pair RUNNING ""; then
        for_expected_services stop_owned >/dev/null 2>&1 || true
        commit_traffic_pair TRAFFIC_BLOCKED "$blocked_period" || true
        traffic_error 'monthly quota rollover state commit failed; managed services were stopped and block restored'
        exit 1
    fi
    desired=RUNNING
    traffic_error "monthly quota period rolled over from ${blocked_period} to ${current_period}; managed services resumed"
fi
[[ "$desired" == MANUAL_STOPPED || "$desired" == MAINTENANCE ]] && exit 0
iface="${INGRESS_IF:-}"
if [[ -z "$iface" ]]; then
    traffic_fail_closed 'INGRESS_IF missing; refusing to switch traffic accounting to a newly inferred interface' || traffic_error 'missing ingress interface could not be fail-closed enforced'
    exit 1
fi
# Transient vnStat/metric blips must not flip desired state to TRAFFIC_BLOCKED.
# Only validated over-quota (below) or corrupt persisted policy (above) fail-closed.
used=$(month_bytes "$iface" "${TRAFFIC_LIMIT_MODE:-total}") || { traffic_error 'traffic accounting query failed; leaving prior desired state unchanged'; exit 1; }
limit=$(python3 - "$TRAFFIC_LIMIT_GB" <<'PY_TRAFFIC_LIMIT'
import sys
gb = int(sys.argv[1])
limit = gb * 1024 * 1024 * 1024
if limit > 9223372036854775807:
    raise SystemExit(1)
print(limit)
PY_TRAFFIC_LIMIT
) || { traffic_error 'traffic limit conversion failed; leaving prior desired state unchanged'; exit 1; }
[[ "$used" =~ ^[0-9]+$ && "$limit" =~ ^[0-9]+$ ]] || { traffic_error 'traffic accounting result was invalid; leaving prior desired state unchanged'; exit 1; }
if python3 - "$used" "$limit" <<PY_TRAFFIC_COMPARE
import sys
raise SystemExit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)
PY_TRAFFIC_COMPARE
then
    commit_traffic_pair TRAFFIC_BLOCKED "$current_period" || exit 1
    for_expected_services stop_owned || { traffic_error 'traffic limit reached but at least one owned service could not be stopped'; exit 1; }
elif [[ "$desired" == TRAFFIC_BLOCKED ]]; then
    # Same-period blocks remain fail-closed even if vnStat later reports a lower value.
    for_expected_services stop_owned || { traffic_error 'traffic-blocked state could not be fully enforced'; exit 1; }
fi
EOF_TRAFFIC
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='systemd'|" "$ABOX_DIR/traffic_monitor.sh" || die '流量监控脚本运行环境标记写入失败。'
    else
        sed -i "s|^INIT_SYS_EXPECTED=.*|INIT_SYS_EXPECTED='openrc'|" "$ABOX_DIR/traffic_monitor.sh" || die '流量监控脚本运行环境标记写入失败。'
    fi
    grep -Fxq "INIT_SYS_EXPECTED='${INIT_SYS}'" "$ABOX_DIR/traffic_monitor.sh" || die '流量监控脚本运行环境标记后置校验失败。' 
    chmod 700 "$ABOX_DIR/traffic_monitor.sh" || die '流量监控脚本权限设置失败。'
    [[ -z "${ABOX_TRAFFIC_TX_DIR:-}" ]] || capture_traffic_quota_expected_state "$ABOX_TRAFFIC_TX_DIR" || die '流量限制监控脚本事务快照失败。'
    install_abox_cron_block TRAFFIC '* * * * * /bin/bash /etc/ddr/traffic_monitor.sh >/dev/null 2>&1'
    [[ -z "${ABOX_TRAFFIC_TX_DIR:-}" ]] || capture_traffic_quota_expected_state "$ABOX_TRAFFIC_TX_DIR" || die '流量限制 cron 事务快照失败。'
}

disable_traffic_monitor() {
    remove_abox_cron_block TRAFFIC || return 1
    remove_owned_runtime_helper "$ABOX_DIR/traffic_monitor.sh" || return 1
    clear_traffic_block_period || return 1
}

traffic_snapshot_file_hash() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    sha256sum "$file" 2>/dev/null | awk '{print $1}'
}

capture_traffic_env_state_file() {
    local source_file="$1" out="$2"
    [[ -f "$source_file" && ! -L "$source_file" ]] || return 1
    awk '/^TRAFFIC_LIMIT_(GB|MODE)=/{print}' "$source_file" | LC_ALL=C sort > "$out"
}

capture_traffic_optional_state() {
    local source_file="$1" out="$2" hash
    [[ "$out" == /* || "$out" == */* ]] || return 1
    if [[ -e "$source_file" || -L "$source_file" ]]; then
        [[ -f "$source_file" && ! -L "$source_file" ]] || return 1
        hash=$(traffic_snapshot_file_hash "$source_file") || return 1
        printf 'present|%s\n' "$hash" > "$out"
    else
        printf '%s\n' 'absent' > "$out"
    fi
}

traffic_optional_state_matches_expected() {
    local source_file="$1" expected_file="$2" expected='' actual=''
    [[ -f "$expected_file" && ! -L "$expected_file" ]] || return 1
    IFS= read -r expected < "$expected_file" || return 1
    if [[ "$expected" == absent ]]; then
        [[ ! -e "$source_file" && ! -L "$source_file" ]]
        return $?
    fi
    [[ "$expected" == present\|* ]] || return 1
    [[ -f "$source_file" && ! -L "$source_file" ]] || return 2
    actual=$(traffic_snapshot_file_hash "$source_file" 2>/dev/null || true)
    [[ "$actual" == "${expected#present|}" ]]
}

capture_vnstat_runtime_state() {
    local name='' active enabled
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        if systemctl list-unit-files vnstat.service >/dev/null 2>&1; then
            name=vnstat
        elif systemctl list-unit-files vnstatd.service >/dev/null 2>&1; then
            name=vnstatd
        else
            printf '%s\n' 'absent'
            return 0
        fi
        systemctl is-active --quiet "$name" && active=1 || active=0
        systemctl is-enabled --quiet "$name" && enabled=1 || enabled=0
        printf 'systemd|%s|%s|%s\n' "$name" "$active" "$enabled"
    elif [[ "${INIT_SYS:-}" == openrc ]] && command -v rc-service >/dev/null 2>&1; then
        [[ -x /etc/init.d/vnstatd ]] || { printf '%s\n' 'absent'; return 0; }
        rc-service vnstatd status >/dev/null 2>&1 && active=1 || active=0
        rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])vnstatd([[:space:]]|$)' && enabled=1 || enabled=0
        printf 'openrc|vnstatd|%s|%s\n' "$active" "$enabled"
    else
        return 1
    fi
}

restore_vnstat_runtime_state() {
    local state="$1" kind name active enabled cur_active cur_enabled
    IFS='|' read -r kind name active enabled <<< "$state"
    case "$kind" in
        absent) return 0 ;;
        systemd)
            cur_active=0; cur_enabled=0
            systemctl is-active --quiet "$name" && cur_active=1 || cur_active=0
            systemctl is-enabled --quiet "$name" && cur_enabled=1 || cur_enabled=0
            [[ "$cur_active|$cur_enabled" == '1|1' ]] || return 2
            if [[ "$enabled" == 1 ]]; then systemctl enable "$name" >/dev/null 2>&1 || return 1; else systemctl disable "$name" >/dev/null 2>&1 || return 1; fi
            if [[ "$active" == 1 ]]; then systemctl start "$name" >/dev/null 2>&1 || systemctl restart "$name" >/dev/null 2>&1 || return 1; else systemctl stop "$name" >/dev/null 2>&1 || return 1; fi
            ;;
        openrc)
            cur_active=0; cur_enabled=0
            rc-service "$name" status >/dev/null 2>&1 && cur_active=1 || cur_active=0
            rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])vnstatd([[:space:]]|$)' && cur_enabled=1 || cur_enabled=0
            [[ "$cur_active|$cur_enabled" == '1|1' ]] || return 2
            if [[ "$enabled" == 1 ]]; then rc-update add "$name" default >/dev/null 2>&1 || return 1; elif rc-update show default 2>/dev/null | grep -Eq "(^|[[:space:]])${name}([[:space:]]|$)"; then rc-update del "$name" default >/dev/null 2>&1 || return 1; fi
            if [[ "$active" == 1 ]]; then rc-service "$name" start >/dev/null 2>&1 || rc-service "$name" restart >/dev/null 2>&1 || return 1; else rc-service "$name" stop >/dev/null 2>&1 || return 1; fi
            ;;
        *) return 1 ;;
    esac
    return 0
}

traffic_restore_cron_block() {
    local pre_file="$1" expected_block="$2" current tmp stripped rc=0
    current=$(umask 077; mktemp /tmp/A-Box-traffic-cron-current.XXXXXX) || return 1
    tmp=$(umask 077; mktemp /tmp/A-Box-traffic-cron-restore.XXXXXX) || { rm -f -- "$current"; return 1; }
    if ! read_crontab_to_file "$current"; then rm -f -- "$current" "$tmp"; return 1; fi
    stripped=$(umask 077; mktemp /tmp/A-Box-traffic-cron-stripped.XXXXXX) || { rm -f -- "$current" "$tmp"; return 1; }
    if ! strip_abox_cron_blocks_from_file "$current" "$stripped" TRAFFIC; then rm -f -- "$current" "$tmp" "$stripped"; return 1; fi
    local current_block
    current_block=$(awk 'BEGIN{p=0} $0=="# A-Box TRAFFIC BEGIN"{p=1} p{print} $0=="# A-Box TRAFFIC END"{exit}' "$current")
    if [[ -n "$expected_block" ]]; then
        [[ "$current_block" == "$expected_block" ]] || { rm -f -- "$current" "$tmp" "$stripped"; return 2; }
    else
        [[ -z "$current_block" ]] || { rm -f -- "$current" "$tmp" "$stripped"; return 2; }
    fi
    cat "$stripped" > "$tmp" || { rm -f -- "$current" "$tmp" "$stripped"; return 1; }
    if [[ -s "$pre_file" ]]; then cat "$pre_file" >> "$tmp" || { rm -f -- "$current" "$tmp" "$stripped"; return 1; }; fi
    if commit_crontab_if_unchanged "$current" "$tmp"; then
        rc=0
    else
        rc=$?
    fi
    rm -f -- "$current" "$tmp" "$stripped"
    return "$rc"
}

capture_traffic_quota_expected_state() {
    local tx_dir="$1" current monitor_hash
    [[ -d "$tx_dir" && ! -L "$tx_dir" ]] || return 1
    capture_traffic_env_state_file "$ABOX_ENV" "$tx_dir/post-traffic.env" || return 1
    capture_traffic_optional_state "$ABOX_DESIRED_STATE" "$tx_dir/post.desired" || return 1
    capture_traffic_optional_state "$ABOX_TRAFFIC_BLOCK_STATE" "$tx_dir/post.block" || return 1
    current=$(umask 077; mktemp /tmp/A-Box-traffic-postcron.XXXXXX) || return 1
    read_crontab_to_file "$current" || { rm -f -- "$current"; return 1; }
    awk 'BEGIN{p=0} $0=="# A-Box TRAFFIC BEGIN"{p=1} p{print} $0=="# A-Box TRAFFIC END"{exit}' "$current" > "$tx_dir/post.cron.traffic" || { rm -f -- "$current"; return 1; }
    rm -f -- "$current"
    if [[ -e "$ABOX_DIR/traffic_monitor.sh" || -L "$ABOX_DIR/traffic_monitor.sh" ]]; then
        [[ -f "$ABOX_DIR/traffic_monitor.sh" && ! -L "$ABOX_DIR/traffic_monitor.sh" ]] || return 1
        auxiliary_content_is_abox_managed "$ABOX_DIR/traffic_monitor.sh" /etc/ddr/traffic_monitor.sh || return 1
        monitor_hash=$(traffic_snapshot_file_hash "$ABOX_DIR/traffic_monitor.sh") || return 1
        printf '%s\n' "$monitor_hash" > "$tx_dir/post.monitor.hash" || return 1
    else
        printf '%s\n' none > "$tx_dir/post.monitor.hash"
    fi
    if ! capture_vnstat_runtime_state > "$tx_dir/post.vnstat"; then
        return 1
    fi
}

traffic_quota_transaction_rollback() {
    local tx_dir="$1" rc=0 current_monitor='' expected_monitor='' pre_monitor=0 current_block='' expected_block='' cron_rc vnstat_state='' expected_vnstat='' current_state current_traffic_env current_vnstat
    [[ -d "$tx_dir" && ! -L "$tx_dir" ]] || return 1

    # Establish every expected post-state before changing anything. This prevents
    # rollback from overwriting state changed by another actor after provisioning.
    if [[ -f "$tx_dir/post-traffic.env" ]]; then
        current_traffic_env=$(umask 077; mktemp /tmp/A-Box-traffic-current-env.XXXXXX) || return 1
        if ! capture_traffic_env_state_file "$ABOX_ENV" "$current_traffic_env" || ! cmp -s "$current_traffic_env" "$tx_dir/post-traffic.env"; then
            rm -f -- "$current_traffic_env"
            printf '%s\n' "A-Box traffic rollback conflict: traffic quota environment changed externally; recovery state preserved at $tx_dir" >&2
            return 2
        fi
        rm -f -- "$current_traffic_env"
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected quota environment; recovery state preserved at $tx_dir" >&2
        return 1
    fi
    if [[ -f "$tx_dir/post.desired" ]]; then
        traffic_optional_state_matches_expected "$ABOX_DESIRED_STATE" "$tx_dir/post.desired" || {
            printf '%s\n' "A-Box traffic rollback conflict: desired state changed externally; recovery state preserved at $tx_dir" >&2
            return 2
        }
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected desired state; recovery state preserved at $tx_dir" >&2
        return 1
    fi
    if [[ -f "$tx_dir/post.block" ]]; then
        traffic_optional_state_matches_expected "$ABOX_TRAFFIC_BLOCK_STATE" "$tx_dir/post.block" || {
            printf '%s\n' "A-Box traffic rollback conflict: traffic block state changed externally; recovery state preserved at $tx_dir" >&2
            return 2
        }
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected block state; recovery state preserved at $tx_dir" >&2
        return 1
    fi

    if [[ -f "$tx_dir/post.cron.traffic" ]]; then
        expected_block=$(cat "$tx_dir/post.cron.traffic") || return 1
        current=$(umask 077; mktemp /tmp/A-Box-traffic-current-cron.XXXXXX) || return 1
        if ! read_crontab_to_file "$current"; then rm -f -- "$current"; return 1; fi
        current_block=$(awk 'BEGIN{p=0} $0=="# A-Box TRAFFIC BEGIN"{p=1} p{print} $0=="# A-Box TRAFFIC END"{exit}' "$current")
        rm -f -- "$current"
        [[ "$current_block" == "$expected_block" ]] || {
            printf '%s\n' "A-Box traffic rollback conflict: crontab TRAFFIC block changed externally; recovery state preserved at $tx_dir" >&2
            return 2
        }
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected TRAFFIC cron state; recovery state preserved at $tx_dir" >&2
        return 1
    fi

    if [[ -s "$tx_dir/post.monitor.hash" ]]; then
        IFS= read -r expected_monitor < "$tx_dir/post.monitor.hash" || return 1
        if [[ "$expected_monitor" == none ]]; then
            [[ ! -e "$ABOX_DIR/traffic_monitor.sh" && ! -L "$ABOX_DIR/traffic_monitor.sh" ]] || {
                printf '%s\n' "A-Box traffic rollback conflict: traffic_monitor.sh was created externally; recovery state preserved at $tx_dir" >&2
                return 2
            }
        else
            current_monitor=$(traffic_snapshot_file_hash "$ABOX_DIR/traffic_monitor.sh" 2>/dev/null || true)
            [[ "$current_monitor" == "$expected_monitor" ]] || {
                printf '%s\n' "A-Box traffic rollback conflict: traffic_monitor.sh changed externally; recovery state preserved at $tx_dir" >&2
                return 2
            }
        fi
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected monitor state; recovery state preserved at $tx_dir" >&2
        return 1
    fi

    if [[ -s "$tx_dir/post.vnstat" ]]; then
        IFS= read -r current_vnstat < <(capture_vnstat_runtime_state) || {
            printf '%s\n' "A-Box traffic rollback could not read current vnStat state; recovery state preserved at $tx_dir" >&2
            return 1
        }
        IFS= read -r expected_vnstat < "$tx_dir/post.vnstat" || return 1
        [[ "$current_vnstat" == "$expected_vnstat" ]] || {
            printf '%s\n' "A-Box traffic rollback conflict: vnStat state changed externally; recovery state preserved at $tx_dir" >&2
            return 2
        }
    else
        printf '%s\n' "A-Box traffic rollback could not establish the expected vnStat state; recovery state preserved at $tx_dir" >&2
        return 1
    fi

    # Restore only A-Box-owned traffic state after the complete conflict preflight.
    if [[ -f "$tx_dir/pre-traffic.env" ]]; then
        local envtmp
        envtmp=$(mktemp "$ABOX_DIR/.env.A-Box-traffic-rollback.XXXXXX") || rc=1
        if (( rc == 0 )); then
            awk '!/^TRAFFIC_LIMIT_(GB|MODE)=/' "$ABOX_ENV" > "$envtmp" || rc=1
            cat "$tx_dir/pre-traffic.env" >> "$envtmp" || rc=1
            chmod 600 "$envtmp" || rc=1
            (( rc == 0 )) && mv -f -- "$envtmp" "$ABOX_ENV" || rm -f -- "$envtmp"
        fi
    fi
    if [[ -s "$tx_dir/pre.desired" ]]; then IFS= read -r current_state < "$tx_dir/pre.desired" && write_private_line "$ABOX_DESIRED_STATE" "$current_state" || rc=1; else rm -f -- "$ABOX_DESIRED_STATE" 2>/dev/null || true; fi
    if [[ -s "$tx_dir/pre.block" ]]; then IFS= read -r current_state < "$tx_dir/pre.block" && write_private_line "$ABOX_TRAFFIC_BLOCK_STATE" "$current_state" || rc=1; else rm -f -- "$ABOX_TRAFFIC_BLOCK_STATE" 2>/dev/null || true; fi

    if [[ -f "$tx_dir/pre.cron.traffic" ]]; then
        if traffic_restore_cron_block "$tx_dir/pre.cron.traffic" "$expected_block"; then :; else cron_rc=$?; rc=1; fi
        if (( cron_rc == 2 )); then printf '%s\n' "A-Box traffic rollback conflict: crontab TRAFFIC block changed externally; recovery state preserved at $tx_dir" >&2; fi
    fi

    if [[ -s "$tx_dir/pre.monitor.meta" ]]; then
        IFS='|' read -r pre_monitor _ < "$tx_dir/pre.monitor.meta" || rc=1
        if (( pre_monitor == 1 )); then
            cp -a -- "$tx_dir/traffic_monitor.pre" "$ABOX_DIR/traffic_monitor.sh" || rc=1
        else
            remove_owned_runtime_helper "$ABOX_DIR/traffic_monitor.sh" || rc=1
        fi
    else
        rc=1
    fi

    if [[ -s "$tx_dir/pre.vnstat" ]]; then
        IFS= read -r vnstat_state < "$tx_dir/pre.vnstat" || rc=1
        if [[ -n "$vnstat_state" && "$vnstat_state" != absent ]]; then
            restore_vnstat_runtime_state "$vnstat_state" || { printf '%s\n' "A-Box traffic rollback incomplete: vnStat state restore failed; recovery state preserved at $tx_dir" >&2; rc=1; }
        fi
    else
        rc=1
    fi
    return "$rc"
}

prepare_traffic_quota_transaction() {
    local tx_dir="$1" traffic_env_tmp current
    mkdir -p "$tx_dir" || return 1
    chmod 700 "$tx_dir" || return 1
    traffic_env_tmp="$tx_dir/pre-traffic.env"
    grep -E '^TRAFFIC_LIMIT_(GB|MODE)=' "$ABOX_ENV" > "$traffic_env_tmp" || :
    [[ -f "$ABOX_DESIRED_STATE" ]] && { cp -a -- "$ABOX_DESIRED_STATE" "$tx_dir/pre.desired" || return 1; } || :
    [[ -f "$ABOX_TRAFFIC_BLOCK_STATE" ]] && { cp -a -- "$ABOX_TRAFFIC_BLOCK_STATE" "$tx_dir/pre.block" || return 1; } || :
    current=$(umask 077; mktemp /tmp/A-Box-traffic-precron.XXXXXX) || return 1
    read_crontab_to_file "$current" || { rm -f -- "$current"; return 1; }
    awk 'BEGIN{p=0} $0=="# A-Box TRAFFIC BEGIN"{p=1} p{print} $0=="# A-Box TRAFFIC END"{exit}' "$current" > "$tx_dir/pre.cron.traffic" || { rm -f -- "$current"; return 1; }
    rm -f -- "$current"
    if [[ -e "$ABOX_DIR/traffic_monitor.sh" || -L "$ABOX_DIR/traffic_monitor.sh" ]]; then
        [[ -f "$ABOX_DIR/traffic_monitor.sh" && ! -L "$ABOX_DIR/traffic_monitor.sh" ]] || return 1
        auxiliary_content_is_abox_managed "$ABOX_DIR/traffic_monitor.sh" /etc/ddr/traffic_monitor.sh || return 1
        printf '1|%s\n' "$(traffic_snapshot_file_hash "$ABOX_DIR/traffic_monitor.sh")" > "$tx_dir/pre.monitor.meta" || return 1
        cp -a -- "$ABOX_DIR/traffic_monitor.sh" "$tx_dir/traffic_monitor.pre" || return 1
    else
        printf '%s\n' '0|none' > "$tx_dir/pre.monitor.meta"
    fi
    capture_vnstat_runtime_state > "$tx_dir/pre.vnstat" || return 1
}

finalize_traffic_quota_transaction() {
    local tx_dir="$1"
    capture_traffic_quota_expected_state "$tx_dir"
}


start_services_for_traffic_unblock() {
    local pre_state="$1" changed_pre="$2" changed_expected="$3"
    local services srv before after active enabled op_rc final_state
    services=$(expected_managed_services) || return 1
    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        abox_owns_service "$srv" || return 1
        before=$(managed_service_state_value "$srv" 2>/dev/null) || return 1
        [[ "$before" == "$srv|1|1" ]] && continue
        IFS='|' read -r _ active enabled <<< "$before"
        append_managed_service_state_entry "$pre_state" "$changed_pre" "$srv" || return 1
        if [[ "$active" == 1 ]]; then
            if enable_abox_service_soft "$srv"; then op_rc=0; else op_rc=$?; fi
        else
            if start_abox_service_soft "$srv"; then op_rc=0; else op_rc=$?; fi
        fi
        after=$(managed_service_state_value "$srv" 2>/dev/null || true)
        if [[ -n "$after" ]]; then
            printf '%s\n' "$after" >> "$changed_expected" || return 1
        else
            # Keep the expected post-state explicit; rollback will refuse to
            # mutate if the actual state cannot later be proven to match it.
            printf '%s\n' "$srv|1|1" >> "$changed_expected" || return 1
        fi
        (( op_rc == 0 )) || return 1
        [[ "$after" == "$srv|1|1" ]] || return 1
    done <<< "$services"
    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        final_state=$(managed_service_state_value "$srv" 2>/dev/null) || return 1
        [[ "$final_state" == "$srv|1|1" ]] || return 1
    done <<< "$services"
}

traffic_management_menu() {
    clear
    local INTERFACE limit_gb mode_choice
    load_optional_abox_env_or_die
    INTERFACE="${INGRESS_IF:-$(get_active_interface)}"
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}每月流量管控限制 / Monthly Traffic Management Limit${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${CYAN}[截至当前 / Usage up to now]${NC}"
    msg "${YELLOW}网卡 ${INTERFACE} · 本月累计（非秒级实时；数据来自 vnStat 当前统计周期）${NC}"
    if command -v vnstat >/dev/null 2>&1; then
        # Prefer JSON one-shot for a clear rx/tx/total line when available.
        if command -v jq >/dev/null 2>&1; then
            if json=$(vnstat -i "$INTERFACE" --json m 1 2>/dev/null); then
                python3 - "$json" <<'PY_TRAFFIC_NOW' 2>/dev/null || true
import json,sys
try:
    data=json.loads(sys.argv[1])
    iface=(data.get("interfaces") or [{}])[0]
    traffic=((iface.get("traffic") or {}).get("month") or [{}])[0]
    rx=int(traffic.get("rx",0)); tx=int(traffic.get("tx",0))
    def hum(n):
        for u in ("B","KiB","MiB","GiB","TiB"):
            if n<1024 or u=="TiB":
                return f"{n:.2f} {u}" if u!="B" else f"{n} B"
            n/=1024
        return str(n)
    print(f"  RX={hum(rx)}  TX={hum(tx)}  TOTAL={hum(rx+tx)}")
    y,m=traffic.get("date",{}).get("year"), traffic.get("date",{}).get("month")
    if y and m: print(f"  Period: {y}-{int(m):02d} (month-to-date)")
except Exception:
    pass
PY_TRAFFIC_NOW
            fi
        fi
        # Do not cap the raw output at 8 lines: vnStat headers consume several
        # lines, which previously hid every month after roughly the third row.
        msg "${YELLOW}--- vnStat 月表 ---${NC}"
        vnstat -i "$INTERFACE" -m 2>/dev/null | awk 'NF { print; shown=1 } END { exit !shown }' || msg "${YELLOW}暂无本月统计数据，vnstat 正在收集中。${NC}"
    else
        msg "${YELLOW}[!] vnStat 未安装；打开流量菜单设定上限时会按需安装。${NC}"
    fi
    if [[ -n "${TRAFFIC_LIMIT_GB:-}" ]]; then
        msg "当前设定: ${GREEN}${TRAFFIC_LIMIT_GB} GB${NC} | 模式: ${TRAFFIC_LIMIT_MODE:-total}"
    else
        msg "当前设定: ${RED}未开启${NC}"
    fi
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}1. 设定/修改每月流量上限${NC}"
    msg "${YELLOW}2. 解除流量限制${NC}"
    msg "${GREEN}0. 返回主菜单${NC}"
    read -r -p '请选择 [0-2]: ' tr_choice
    case "$tr_choice" in
        1)
            read -r -p '请输入每月流量上限(GB)，纯数字: ' limit_gb
            valid_traffic_limit_gb "$limit_gb" || { msg "${RED}[!] 流量上限必须是 1-8589934591 GB 的整数。${NC}"; pause_return; return; }
            read -r -p '计量模式 total/rx/tx (回车默认 total): ' mode_choice
            mode_choice=${mode_choice:-total}
            [[ "$mode_choice" =~ ^(total|rx|tx)$ ]] || { msg "${RED}[!] 计量模式无效。${NC}"; pause_return; return; }
            local traffic_tx_dir="" old_die_hook="" traffic_previous_state='' traffic_service_pre='' traffic_service_changed_pre='' traffic_service_changed_expected='' traffic_op_rc=0 traffic_target_state=''
            traffic_previous_state=$(get_desired_state) || die '无法可靠读取当前服务期望状态；未修改流量限制。'
            traffic_tx_dir=$(mktemp -d /run/A-Box-traffic-tx.XXXXXX) || die '无法创建流量状态事务目录。'
            chmod 700 "$traffic_tx_dir" || { rm -rf -- "$traffic_tx_dir"; die '流量状态事务目录权限设置失败。'; }
            prepare_traffic_quota_transaction "$traffic_tx_dir" || { rm -rf -- "$traffic_tx_dir"; die '无法保存流量限制事务前态。'; }
            if [[ "$traffic_previous_state" == TRAFFIC_BLOCKED ]]; then
                traffic_service_pre="$traffic_tx_dir/pre-services.state"
                traffic_service_changed_pre="$traffic_tx_dir/changed-services-pre.state"
                traffic_service_changed_expected="$traffic_tx_dir/changed-services-expected.state"
                capture_managed_service_state "$traffic_service_pre" || { rm -rf -- "$traffic_tx_dir"; die '无法保存解除流量封锁前的服务状态。'; }
                : > "$traffic_service_changed_pre"; : > "$traffic_service_changed_expected"
            fi
            if [[ ${ABOX_DIE_HOOK+x} ]]; then old_die_hook="$ABOX_DIE_HOOK"; fi
            ABOX_TRAFFIC_TX_DIR="$traffic_tx_dir"
            ABOX_DIE_HOOK=traffic_quota_menu_die_rollback
            traffic_quota_menu_die_rollback() {
                local rollback_rc=0 reason="${1:-traffic quota change failed}"
                if [[ -n "$traffic_service_changed_pre" && -s "$traffic_service_changed_pre" ]]; then
                    if [[ -s "$traffic_service_changed_expected" ]]; then
                        restore_managed_service_state "$traffic_service_changed_pre" "$traffic_service_changed_expected" || rollback_rc=1
                    else
                        rollback_rc=1
                    fi
                fi
                traffic_quota_transaction_rollback "$traffic_tx_dir" || rollback_rc=1
                if (( rollback_rc != 0 )); then
                    printf '%s\n' "A-Box traffic quota rollback incomplete/conflicted; recovery state preserved at $traffic_tx_dir" >&2
                else
                    rm -rf -- "$traffic_tx_dir" || rollback_rc=1
                fi
                if (( rollback_rc != 0 )); then
                    printf '%s\n' "A-Box traffic quota/service rollback incomplete; inspect recovery state at $traffic_tx_dir" >&2
                fi
                if [[ -n "$old_die_hook" && "$old_die_hook" != traffic_quota_menu_die_rollback ]] && declare -F "$old_die_hook" >/dev/null 2>&1; then
                    "$old_die_hook" "$reason" || true
                fi
                return "$rollback_rc"
            }
            setup_traffic_monitor
            if update_traffic_state_atomically "$limit_gb" "$mode_choice"; then traffic_op_rc=0; else traffic_op_rc=$?; fi
            capture_traffic_quota_expected_state "$traffic_tx_dir" || die '流量限制更新后无法核验状态；事务已中止。'
            (( traffic_op_rc == 0 )) || die '流量限制状态原子提交失败。'
            if clear_traffic_block_period; then traffic_op_rc=0; else traffic_op_rc=$?; fi
            capture_traffic_quota_expected_state "$traffic_tx_dir" || die '清除旧封锁周期后无法核验状态；事务已中止。'
            (( traffic_op_rc == 0 )) || die '旧流量封锁周期清理失败。'
            case "$traffic_previous_state" in
                TRAFFIC_BLOCKED)
                    start_services_for_traffic_unblock "$traffic_service_pre" "$traffic_service_changed_pre" "$traffic_service_changed_expected" || die '新流量上限已写入，但托管服务无法恢复运行；事务已中止。'
                    traffic_target_state=RUNNING
                    ;;
                RUNNING|MANUAL_STOPPED|MAINTENANCE)
                    traffic_target_state="$traffic_previous_state"
                    ;;
                *) die "未知服务期望状态 ${traffic_previous_state}；拒绝提交流量限制。" ;;
            esac
            if set_desired_state "$traffic_target_state"; then traffic_op_rc=0; else traffic_op_rc=$?; fi
            capture_traffic_quota_expected_state "$traffic_tx_dir" || die '期望状态提交后无法核验事务；已中止。'
            (( traffic_op_rc == 0 )) || die '服务期望状态写入失败。'
            finalize_traffic_quota_transaction "$traffic_tx_dir" || die '流量限制事务提交后校验失败。'
            unset ABOX_DIE_HOOK
            if [[ -n "$old_die_hook" ]]; then ABOX_DIE_HOOK="$old_die_hook"; fi
            ABOX_TRAFFIC_TX_DIR=''
            rm -rf -- "$traffic_tx_dir" || die '流量状态事务清理失败。'
            msg "${GREEN}流量限制已设定为 ${limit_gb} GB，模式 ${mode_choice}。${NC}"
            pause_return
            ;;
        2)
            previous_state=$(get_desired_state) || die '无法可靠读取当前服务期望状态；未解除流量限制。'
            local unblock_tx_dir='' unblock_old_die_hook='' unblock_state_pre='' unblock_changed_pre='' unblock_changed_expected='' unblock_op_rc=0 target_state=''
            unblock_tx_dir=$(mktemp -d /run/A-Box-traffic-unblock.XXXXXX) || die '无法创建流量解除事务目录。'
            chmod 700 "$unblock_tx_dir" || { rm -rf -- "$unblock_tx_dir"; die '流量解除事务目录权限设置失败。'; }
            prepare_traffic_quota_transaction "$unblock_tx_dir" || { rm -rf -- "$unblock_tx_dir"; die '无法保存流量解除事务前态。'; }
            unblock_state_pre="$unblock_tx_dir/pre-services.state"
            unblock_changed_pre="$unblock_tx_dir/changed-services-pre.state"
            unblock_changed_expected="$unblock_tx_dir/changed-services-expected.state"
            capture_managed_service_state "$unblock_state_pre" || { rm -rf -- "$unblock_tx_dir"; die '无法保存流量解除前的服务状态。'; }
            : > "$unblock_changed_pre"; : > "$unblock_changed_expected"
            if [[ ${ABOX_DIE_HOOK+x} ]]; then unblock_old_die_hook="$ABOX_DIE_HOOK"; fi
            ABOX_TRAFFIC_TX_DIR="$unblock_tx_dir"
            ABOX_DIE_HOOK=traffic_unblock_menu_die_rollback
            traffic_unblock_menu_die_rollback() {
                local rollback_rc=0 reason="${1:-traffic unblock failed}"
                if [[ -s "$unblock_changed_pre" ]]; then
                    if [[ -s "$unblock_changed_expected" ]]; then
                        restore_managed_service_state "$unblock_changed_pre" "$unblock_changed_expected" || rollback_rc=1
                    else
                        rollback_rc=1
                    fi
                fi
                traffic_quota_transaction_rollback "$unblock_tx_dir" || rollback_rc=1
                if (( rollback_rc == 0 )); then
                    rm -rf -- "$unblock_tx_dir" || rollback_rc=1
                fi
                if (( rollback_rc != 0 )); then
                    printf '%s\n' "A-Box traffic-unblock rollback incomplete; recovery state preserved at $unblock_tx_dir" >&2
                fi
                if [[ -n "$unblock_old_die_hook" && "$unblock_old_die_hook" != traffic_unblock_menu_die_rollback ]] && declare -F "$unblock_old_die_hook" >/dev/null 2>&1; then
                    "$unblock_old_die_hook" "$reason" || true
                fi
                return "$rollback_rc"
            }

            if update_traffic_state_atomically '' ''; then unblock_op_rc=0; else unblock_op_rc=$?; fi
            capture_traffic_quota_expected_state "$unblock_tx_dir" || die '流量解除时无法验证新状态；事务已中止。'
            (( unblock_op_rc == 0 )) || die '解除流量限制时状态原子提交失败。'
            if remove_abox_cron_block TRAFFIC; then unblock_op_rc=0; else unblock_op_rc=$?; fi
            capture_traffic_quota_expected_state "$unblock_tx_dir" || die '移除流量监控任务后状态核验失败；事务已中止。'
            (( unblock_op_rc == 0 )) || die '移除流量监控任务失败；未提交解除操作。'
            if remove_owned_runtime_helper "$ABOX_DIR/traffic_monitor.sh"; then unblock_op_rc=0; else unblock_op_rc=$?; fi
            capture_traffic_quota_expected_state "$unblock_tx_dir" || die '移除流量监控脚本后状态核验失败；事务已中止。'
            (( unblock_op_rc == 0 )) || die '移除流量监控脚本失败；未提交解除操作。'
            if clear_traffic_block_period; then unblock_op_rc=0; else unblock_op_rc=$?; fi
            capture_traffic_quota_expected_state "$unblock_tx_dir" || die '清除流量封锁周期后状态核验失败；事务已中止。'
            (( unblock_op_rc == 0 )) || die '清除流量封锁周期失败；未提交解除操作。'
            load_abox_env "$ABOX_ENV" || die '流量配置重读失败；未提交解除操作。'
            case "$previous_state" in
                TRAFFIC_BLOCKED)
                    start_services_for_traffic_unblock "$unblock_state_pre" "$unblock_changed_pre" "$unblock_changed_expected" || die '流量封锁解除后有托管服务未能启动/启用并通过状态核验。'
                    target_state=RUNNING
                    ;;
                RUNNING|MANUAL_STOPPED|MAINTENANCE)
                    target_state="$previous_state"
                    ;;
                *) die "未知服务期望状态 ${previous_state}；拒绝解除流量限制。" ;;
            esac
            if set_desired_state "$target_state"; then unblock_op_rc=0; else unblock_op_rc=$?; fi
            capture_traffic_quota_expected_state "$unblock_tx_dir" || die '提交服务期望状态后核验失败；事务已中止。'
            (( unblock_op_rc == 0 )) || die '服务期望状态写入失败。'
            finalize_traffic_quota_transaction "$unblock_tx_dir" || die '流量解除事务最终状态校验失败。'
            unset ABOX_DIE_HOOK
            if [[ -n "$unblock_old_die_hook" ]]; then ABOX_DIE_HOOK="$unblock_old_die_hook"; fi
            ABOX_TRAFFIC_TX_DIR=''
            rm -rf -- "$unblock_tx_dir" || die '流量解除事务清理失败；状态已提交但恢复材料清理失败。'
            msg "${GREEN}流量限制已解除。${NC}"
            pause_return
            ;;
        *) return 0 ;;
    esac
}

remove_ss_source_whitelist_rules() {
    local failed=0 cmd proto line rule
    [[ -n "${SS_PORT:-}" ]] || return 0
    for cmd in "$IPT" "$IPT6"; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        "$cmd" -w -S INPUT >/dev/null 2>&1 || continue
        for proto in tcp udp; do
            while :; do
                line=$("$cmd" -w -S INPUT 2>/dev/null | awk -v p="$proto" -v port="$SS_PORT" '''$0 ~ "^-A INPUT " && $0 ~ ("-p " p) && $0 ~ ("--dport " port) && $0 ~ ("--comment \"?A-Box-" port "-" p "-WL6?\"?($| )") {print; exit}''') || { failed=1; break; }
                [[ -n "$line" ]] || break
                line=${line//\"/}
                rule="${line#-A INPUT }"
                # Word-splitting is intentional: all A-Box comments and source
                # addresses are whitespace-free, and iptables itself tokenizes
                # the normalized -S form.
                "$cmd" -w -D INPUT $rule >/dev/null 2>&1 || { failed=1; break; }
            done
        done
    done
    (( failed == 0 ))
}

manage_ss_whitelist() {
    local check_rc=0
    clear
    local _wl_backend
    _wl_backend=$(firewall_backend)
    [[ "$_wl_backend" == 'iptables' ]] || {
        msg "${RED}[!] SS-2022 源地址白名单仅支持原生 iptables/ip6tables 后端；当前是 ${_wl_backend}。为避免 UFW/firewalld 与 A-Box 双重持久化或规则顺序错误，拒绝修改。${NC}"
        pause_return
        return 1
    }
    load_optional_abox_env_or_die
    [[ -z "${SS_PORT:-}" ]] && { msg "${RED}[!] 未检测到已部署的 SS-2022 服务端口。${NC}"; pause_return; return; }
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}SS-2022 白名单 IP 管理 / SS-2022 Whitelist Manager${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}当前 SS-2022 监听端口: $SS_PORT/TCP+UDP${NC}"
    msg "IPv4 白名单:"
    $IPT -nL INPUT --line-numbers 2>/dev/null | grep -E "(tcp|udp) dpt:$SS_PORT" | grep 'ACCEPT' | awk '{print $5}' | grep -v '0.0.0.0/0' | sort -u || true
    if command -v ip6tables >/dev/null 2>&1 && $IPT6 -nL INPUT >/dev/null 2>&1; then
        msg "IPv6 白名单:"
        $IPT6 -nL INPUT --line-numbers 2>/dev/null | grep -E "(tcp|udp) dpt:$SS_PORT" | grep 'ACCEPT' | awk '{print $5}' | grep -v '::/0' | sort -u || true
    fi
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}1. 新增白名单 IP/CIDR (TCP+UDP)${NC}"
    msg "${YELLOW}2. 移除白名单 IP/CIDR (TCP+UDP)${NC}"
    msg "${YELLOW}3. 开启白名单模式 (TCP+UDP DROP)${NC}"
    msg "${YELLOW}4. 切换为全网开放 (移除 DROP 并放行 TCP+UDP)${NC}"
    msg "${GREEN}0. 返回主菜单${NC}"
    read -r -p '请选择操作 [0-4]: ' wl_choice
    local add_ip del_ip rule found proto
    case "$wl_choice" in
        1)
            read -r -p '请输入要放行的前置机 IP/CIDR: ' add_ip
            [[ -z "$add_ip" ]] && return
            if [[ "$add_ip" == *:* ]]; then
                valid_ipv6_cidr "$add_ip" || { msg "${RED}[!] IPv6 白名单地址非法: $add_ip${NC}"; pause_return; return; }
                has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1 || die '系统无可用 IPv6 防火墙。'
                for proto in tcp udp; do
                    $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$add_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则写入失败: $add_ip/$proto"
                done
            else
                valid_ipv4_cidr "$add_ip" || { msg "${RED}[!] IPv4 白名单地址非法: $add_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$add_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则写入失败: $add_ip/$proto"
                done
            fi
            save_firewall_rules || die 'A-Box 防火墙持久化失败。'
            msg "${GREEN}已添加白名单: $add_ip (TCP+UDP)${NC}"
            pause_return
            ;;
        2)
            read -r -p '请输入要移除的 IP/CIDR: ' del_ip
            [[ -z "$del_ip" ]] && return
            found=0
            if [[ "$del_ip" == *:* ]]; then
                valid_ipv6_cidr "$del_ip" || { msg "${RED}[!] IPv6 白名单地址非法: $del_ip${NC}"; pause_return; return; }
                if ! has_ipv6 || ! command -v ip6tables >/dev/null 2>&1 || ! "$IPT6" -w -S INPUT >/dev/null 2>&1; then
                    msg "${YELLOW}[!] 当前系统没有可用的 IPv6 防火墙，无法移除 IPv6 白名单；IPv4 规则未受影响。${NC}"
                    pause_return
                    return
                fi
                for proto in tcp udp; do
                    while :; do
                        if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                        case "$check_rc" in
                            0) ;;
                            1) break ;;
                            *) die "无法检查 IPv6 白名单规则: $del_ip/$proto" ;;
                        esac
                        $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则删除失败: $del_ip/$proto"
                        found=1
                    done
                done
            else
                valid_ipv4_cidr "$del_ip" || { msg "${RED}[!] IPv4 白名单地址非法: $del_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    while :; do
                        if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT; then check_rc=0; else check_rc=$?; fi
                        case "$check_rc" in
                            0) ;;
                            1) break ;;
                            *) die "无法检查 IPv4 白名单规则: $del_ip/$proto" ;;
                        esac
                        $IPT -w -D INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则删除失败: $del_ip/$proto"
                        found=1
                    done
                done
            fi
            save_firewall_rules || die 'A-Box 防火墙持久化失败。'
            [[ "$found" == 1 ]] && msg "${GREEN}已移除白名单: $del_ip${NC}" || msg "${YELLOW}未找到该白名单规则。${NC}"
            pause_return
            ;;
        3)
            remove_ss_open_accept_rules || die '旧的 SS 全网 ACCEPT 规则无法完整删除；拒绝启用白名单模式。'
            for proto in tcp udp; do
                if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP; then check_rc=0; else check_rc=$?; fi
                case "$check_rc" in
                    0) ;;
                    1) $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto" ;;
                    *) die "无法检查防火墙规则。" ;;
                esac
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP; then check_rc=0; else check_rc=$?; fi
                    case "$check_rc" in
                        0) ;;
                        1) $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto" ;;
                        *) die "无法检查防火墙规则。" ;;
                    esac
                fi
            done
            enforce_ss_whitelist_order "$SS_PORT" || die 'SS 白名单规则顺序校正失败。'
            save_firewall_rules || die 'A-Box 防火墙持久化失败。'
            msg "${GREEN}已开启白名单保护模式 (TCP+UDP)。${NC}"
            pause_return
            ;;
        4)
            remove_ss_source_whitelist_rules || die '旧的 SS-2022 来源白名单规则无法完整删除；拒绝切换为全网开放。'
            for proto in tcp udp; do
                while :; do
                    if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP; then check_rc=0; else check_rc=$?; fi
                    case "$check_rc" in
                        0) ;;
                        1) break ;;
                        *) die "无法检查 IPv4 SS DROP 规则: $proto" ;;
                    esac
                    $IPT -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则删除失败: $proto"
                done
                if iptables_rule_check "$IPT" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP; then check_rc=0; else check_rc=$?; fi
                case "$check_rc" in 1) ;; 0) die "IPv4 SS DROP 规则仍然存在: $proto" ;; *) die "无法验证 IPv4 SS DROP 规则已删除: $proto" ;; esac
                if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    while :; do
                        if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP; then check_rc=0; else check_rc=$?; fi
                        case "$check_rc" in
                            0) ;;
                            1) break ;;
                            *) die "无法检查 IPv6 SS DROP 规则: $proto" ;;
                        esac
                        $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则删除失败: $proto"
                    done
                    if iptables_rule_check "$IPT6" INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP; then check_rc=0; else check_rc=$?; fi
                    case "$check_rc" in 1) ;; 0) die "IPv6 SS DROP 规则仍然存在: $proto" ;; *) die "无法验证 IPv6 SS DROP 规则已删除: $proto" ;; esac
                fi
                allowPort "$SS_PORT" "$proto"
            done
            save_firewall_rules || die 'A-Box 防火墙持久化失败。'
            msg "${GREEN}已切换为全网开放模式 (TCP+UDP)。${NC}"
            pause_return
            ;;
        *) return 0 ;;
    esac
}

do_cleanup() {
    clear; msg "${RED}正在执行清理逻辑...${NC}"
    init_system_environment
    local uninstall_tx_dir='' uninstall_tx_key='' uninstall_tx_value=''
    if [[ "${1:-}" == full ]]; then
        uninstall_tx_dir=$(mktemp -d /run/A-Box-uninstall-tx.XXXXXX) || die '无法创建完全卸载回滚事务目录。'
        chmod 700 "$uninstall_tx_dir" || { rm -rf -- "$uninstall_tx_dir"; die '完全卸载回滚事务目录权限设置失败。'; }
        ABOX_DEPLOY_TX_BACKUP_DIR="$uninstall_tx_dir"
        ABOX_DEPLOY_TX_EPHEMERAL_DIR="$uninstall_tx_dir"
        ABOX_DIE_HOOK='cleanup_ephemeral_deployment_transaction_dir'
    fi
    begin_deployment_transaction 'full A-Box cleanup' xray sing-box hysteria
    if [[ -n "$uninstall_tx_dir" ]]; then
        ensure_backup_auth_key || die '无法建立完全卸载事务恢复密钥。'
        IFS= read -r uninstall_tx_value < "$ABOX_BACKUP_KEY" || die '完全卸载事务恢复密钥读取失败。'
        uninstall_tx_key="$uninstall_tx_dir/recovery.key"
        write_private_sidecar "$uninstall_tx_key" "$uninstall_tx_value" || die '完全卸载事务恢复密钥保存失败。'
        ABOX_DEPLOY_TX_KEY_FILE="$uninstall_tx_key"
    fi
    stop_all_managed_services || die '清理前无法停止全部 A-Box 托管服务。'
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    kill_managed_residual_pids || die 'A-Box 残留进程无法完整停止。'
    remove_all_owned_core_families 1 || die '删除 A-Box 托管核心文件失败。'
    if [[ -d "$ABOX_DIR/tune-backup" ]]; then
        restore_vps_tune 1 >/dev/null 2>&1 || die 'VPS 调优恢复失败；检测到非 A-Box 替换文件或系统写入错误。'
    else
        remove_owned_auxiliary_path /etc/sysctl.d/99-A-Box-tune.conf || die '删除 A-Box sysctl 配置失败。'
        remove_owned_auxiliary_path /etc/security/limits.d/A-Box.conf || die '删除 A-Box limits 配置失败。'
    fi
    remove_all_abox_cron_blocks || die '删除 A-Box cron 任务失败。'
    remove_owned_auxiliary_path /etc/fail2ban/jail.d/A-Box.local || die '删除 A-Box Fail2Ban jail 失败。'
    remove_owned_auxiliary_path /etc/fail2ban/filter.d/A-Box.conf || die '删除 A-Box Fail2Ban filter 失败。'
    remove_owned_auxiliary_path /etc/logrotate.d/A-Box || die '删除 A-Box logrotate 配置失败。'
    remove_abox_log_files || die '删除 A-Box 日志失败；检测到非托管或不安全日志文件。'
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        if systemctl list-unit-files fail2ban.service >/dev/null 2>&1 && systemctl cat fail2ban.service >/dev/null 2>&1; then
            systemctl restart fail2ban >/dev/null 2>&1 || die 'Fail2Ban 重启失败，清理未完成。'
        fi
        systemctl daemon-reload >/dev/null 2>&1 || die '清理后 systemd daemon-reload 失败。'
    elif [[ "${INIT_SYS:-}" == openrc ]] && [[ -x /etc/init.d/fail2ban ]]; then
        rc-service fail2ban restart >/dev/null 2>&1 || die 'Fail2Ban 重启失败，清理未完成。'
    fi
    if [[ "${1:-}" == full ]]; then
        remove_abox_shortcut /usr/local/bin/sb || die 'A-Box 快捷入口删除失败；清理未完成。'
        # Do not destroy ABOX_DIR until managed Swap has been removed successfully.
        # The ownership marker is required for a safe retry when /etc/fstab or swapoff fails.
        if ! remove_abox_swap; then
            msg "${YELLOW}[!] A-Box Swap 未能自动删除；保留 $ABOX_DIR 归属标记以便稍后安全重试。${NC}"
            die 'Swap 清理失败；已停止完全清场以避免遗留无归属状态。'
        fi
        path_tree_has_mountpoint "$ABOX_DIR" && die '检测到 A-Box 数据目录或其子树存在挂载点；拒绝递归删除，以保留挂载内容。'
        # Keep the deployment transaction active until the final data-directory
        # deletion has been confirmed. If rm/race/permission errors occur, the
        # transaction hook must still be able to restore the pre-uninstall backup.
        rm -rf -- "$ABOX_DIR" || die '删除 A-Box 数据目录失败；清理未完成。'
        [[ ! -e "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] || die 'A-Box 数据目录仍然存在；清理未完成。'
        commit_deployment_transaction
        msg "${GREEN}完全清理完成。${NC}"
        exit 0
    fi
    remove_abox_env_file || die '清理 A-Box .env 失败；检测到非托管或不安全状态文件。'
    for runtime_file in "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"; do
        remove_owned_runtime_helper "$runtime_file" || die "清理 A-Box 运行文件失败: $runtime_file"
    done
    remove_sni_candidate_cache || die '清理 A-Box SNI 候选缓存失败或路径不安全。'
    if [[ -f "$DEPS_MARKER" && ! -L "$DEPS_MARKER" ]]; then rm -f -- "$DEPS_MARKER" || die '清理 A-Box 依赖标记失败。'; fi
    setup_shortcut
    commit_deployment_transaction
    remove_abox_swap || msg "${YELLOW}[!] A-Box Swap 未能自动删除；为安全起见保留现状。${NC}"
    msg "${GREEN}代理系统已销毁，保留 A-Box 托管的 sb 入口。${NC}"
    pause_return
}

preflight_reset_ownership() {
    [[ -n "${ABOX_DIR:-}" ]] || return 1
    if [[ -e "$ABOX_ENV" || -L "$ABOX_ENV" ]]; then
        validate_abox_env_file_for_write || return 1
    fi
    local runtime_file srv core_paths path sni_cache="$ABOX_DIR/A-Box-sni-candidates.txt"
    if [[ -e "$sni_cache" || -L "$sni_cache" ]]; then
        [[ -f "$sni_cache" && ! -L "$sni_cache" ]] || return 1
        path_owned_by_root "$sni_cache" || return 1
        path_mode_has_no_group_other_write "$sni_cache" || return 1
        path_tree_has_mountpoint "$sni_cache" && return 1
    fi
    for runtime_file in "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"; do
        [[ ! -e "$runtime_file" && ! -L "$runtime_file" ]] && continue
        auxiliary_content_is_abox_managed "$runtime_file" "$runtime_file" || return 1
        path_tree_has_mountpoint "$runtime_file" && return 1
    done
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        core_paths=$(core_family_paths "$srv") || return 1
        while IFS= read -r path; do
            [[ -e "$path" || -L "$path" ]] || continue
            path_tree_has_mountpoint "$path" && return 1
        done <<< "$core_paths"
    done
    return 0
}

check_virgin_state() {
    if [[ -t 1 ]]; then
        command clear || true
    fi
    init_system_environment || die '初始化系统环境失败。'
    msg "${YELLOW}删除全部节点与环境初始化 / Delete all nodes and perform environment initialization${NC}"
    local confirm_virgin=""
    if [[ -t 0 ]]; then
        read -r -p '确定执行环境深度自愈吗？[Y/N]: ' confirm_virgin || confirm_virgin='N'
    else
        confirm_virgin="${ABOX_YES:-N}"
    fi
    [[ -n "$confirm_virgin" ]] || confirm_virgin='N'
    is_yes "$confirm_virgin" || { msg "${GREEN}操作已取消。${NC}"; pause_return; return 0; }
    : "${ABOX_DIR:?ABOX_DIR 未定义}"
    begin_deployment_transaction 'environment reset' xray sing-box hysteria || die '开启环境重置事务失败。'
    preflight_reset_ownership || die '环境重置预检失败；检测到非托管、挂载或不安全文件，已中止。'
    stop_all_managed_services || die '环境重置前无法停止全部 A-Box 托管服务。'
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    remove_all_abox_cron_blocks || die '删除 A-Box cron 任务失败。'
    # Menu 17 deep self-heal: pass force_heal=1 explicitly (never via environment).
    remove_all_owned_core_families 1 || die '环境重置时删除 A-Box 托管核心文件失败。'
    remove_abox_env_file || die '环境重置时清理 A-Box .env 失败；检测到非托管或不安全状态文件。'
    for runtime_file in "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"; do
        remove_owned_runtime_helper "$runtime_file" || die "环境重置时删除 A-Box 运行文件失败: $runtime_file"
    done
    remove_sni_candidate_cache || die '环境重置时删除 A-Box SNI 缓存失败或路径不安全。'
    if [[ -f "$DEPS_MARKER" && ! -L "$DEPS_MARKER" ]]; then rm -f -- "$DEPS_MARKER" || die '环境重置时删除 A-Box 依赖标记失败。'; fi
    remove_owned_auxiliary_path /etc/fail2ban/jail.d/A-Box.local || die '删除 A-Box Fail2Ban jail 失败。'
    remove_owned_auxiliary_path /etc/fail2ban/filter.d/A-Box.conf || die '删除 A-Box Fail2Ban filter 失败。'
    remove_owned_auxiliary_path /etc/logrotate.d/A-Box || die '删除 A-Box logrotate 配置失败。'
    remove_abox_log_files || die '删除 A-Box 日志失败；检测到非托管或不安全日志文件。'
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        if systemctl list-unit-files fail2ban.service >/dev/null 2>&1 && systemctl cat fail2ban.service >/dev/null 2>&1; then
            systemctl restart fail2ban >/dev/null 2>&1 || die '环境初始化时 Fail2Ban 重启失败。'
        fi
        systemctl daemon-reload >/dev/null 2>&1 || die '环境初始化后的 systemd daemon-reload 失败。'
    elif [[ "${INIT_SYS:-}" == openrc ]] && [[ -x /etc/init.d/fail2ban ]]; then
        rc-service fail2ban restart >/dev/null 2>&1 || die '环境初始化时 Fail2Ban 重启失败。'
    fi
    commit_deployment_transaction
    remove_abox_swap || msg "${YELLOW}[!] A-Box Swap 未能自动删除；为安全起见保留现状。${NC}"
    msg "${GREEN}环境初始化完成；非 A-Box 同名安装未被删除。${NC}"
    pause_return
}

restore_vps_tune() {
    local quiet="${1:-0}" dir="$ABOX_DIR/tune-backup" line key value path failed=0
    local bbr_module_file='/etc/modules-load.d/A-Box-bbr.conf'
    [[ -d "$dir" ]] || { [[ "$quiet" == 1 ]] || msg "${YELLOW}[!] 没有可恢复的 A-Box 调优快照。${NC}"; return 1; }
    path_tree_has_mountpoint "$dir" && { [[ "$quiet" == 1 ]] || msg "${RED}[!] 调优快照目录或其子树存在挂载点，拒绝恢复后删除。${NC}"; return 1; }
    path_parent_chain_safe /etc/sysctl.d/99-A-Box-tune.conf || return 1
    path_parent_chain_safe /etc/security/limits.d/A-Box.conf || return 1
    path_parent_chain_safe "$bbr_module_file" || return 1
    [[ ! -L /etc/sysctl.d && (! -e /etc/sysctl.d || -d /etc/sysctl.d) ]] || return 1
    [[ ! -L /etc/security/limits.d && (! -e /etc/security/limits.d || -d /etc/security/limits.d) ]] || return 1
    [[ ! -L /etc/modules-load.d && (! -e /etc/modules-load.d || -d /etc/modules-load.d) ]] || return 1
    for path in /etc/sysctl.d/99-A-Box-tune.conf /etc/security/limits.d/A-Box.conf "$bbr_module_file"; do
        [[ ! -e "$path" && ! -L "$path" ]] || auxiliary_path_is_abox_managed "$path" || return 1
    done
    if [[ -f "$dir/sysctl.original" ]]; then
        while IFS='=' read -r key value; do [[ -n "$key" ]] || continue; sysctl -w "$key=$value" >/dev/null 2>&1 || failed=1; done < "$dir/sysctl.original"
    fi
    if [[ -f "$dir/sysctl.conf" ]]; then install -d -m 755 /etc/sysctl.d || failed=1; cp -a "$dir/sysctl.conf" /etc/sysctl.d/99-A-Box-tune.conf || failed=1; else rm -f /etc/sysctl.d/99-A-Box-tune.conf || failed=1; fi
    if [[ -f "$dir/limits.conf" ]]; then install -d -m 755 /etc/security/limits.d || failed=1; cp -a "$dir/limits.conf" /etc/security/limits.d/A-Box.conf || failed=1; else rm -f /etc/security/limits.d/A-Box.conf || failed=1; fi
    if [[ -f "$dir/bbr-modules.conf" ]]; then
        install -d -m 755 /etc/modules-load.d || failed=1
        cp -a "$dir/bbr-modules.conf" "$bbr_module_file" || failed=1
    else
        rm -f -- "$bbr_module_file" || failed=1
    fi
    sysctl --system >/dev/null 2>&1 || failed=1
    (( failed == 0 )) || return 1
    path_tree_has_mountpoint "$dir" && return 1
    rm -rf -- "$dir" || return 1
    [[ "$quiet" == 1 ]] || msg "${GREEN}A-Box VPS 调优已恢复。${NC}"
}

apply_vps_tune() {
    local dir="$ABOX_DIR/tune-backup" tmp key value available bbr_loaded=0
    local bbr_module_file='/etc/modules-load.d/A-Box-bbr.conf'
    assert_abox_auxiliary_safe /etc/security/limits.d/A-Box.conf
    assert_abox_auxiliary_safe /etc/sysctl.d/99-A-Box-tune.conf
    assert_abox_auxiliary_safe "$bbr_module_file"
    if [[ -f "$dir/.captured" ]]; then die '检测到尚未恢复的调优快照；请先执行恢复，再重新应用。'; fi
    if [[ -e "$dir" || -L "$dir" ]]; then
        [[ -d "$dir" && ! -L "$dir" ]] || die '调优备份路径不是安全目录。'
        [[ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] || die '检测到未完成的调优快照；请先检查并恢复/清理该快照。'
    fi
    local snapshot_tmp
    snapshot_tmp=$(mktemp -d "$ABOX_DIR/.tune-backup-new.XXXXXX") || die '无法创建调优备份临时目录。'
    if [[ -f /etc/sysctl.d/99-A-Box-tune.conf ]] && ! cp -a /etc/sysctl.d/99-A-Box-tune.conf "$snapshot_tmp/sysctl.conf"; then
        rm -rf -- "$snapshot_tmp"; die '调优 sysctl 原配置备份失败。'
    fi
    if [[ -f /etc/security/limits.d/A-Box.conf ]] && ! cp -a /etc/security/limits.d/A-Box.conf "$snapshot_tmp/limits.conf"; then
        rm -rf -- "$snapshot_tmp"; die '调优 limits 原配置备份失败。'
    fi
    if [[ -f "$bbr_module_file" ]] && ! cp -a "$bbr_module_file" "$snapshot_tmp/bbr-modules.conf"; then
        rm -rf -- "$snapshot_tmp"; die 'BBR 模块自动加载配置备份失败。'
    fi
    : > "$snapshot_tmp/sysctl.original" || { rm -rf -- "$snapshot_tmp"; die '调优 sysctl 原始值快照创建失败。'; }
    for key in fs.file-max fs.inotify.max_user_instances net.ipv4.tcp_syncookies net.ipv4.tcp_fin_timeout net.ipv4.tcp_keepalive_time net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing net.ipv4.tcp_notsent_lowat net.core.netdev_max_backlog net.core.somaxconn net.core.default_qdisc net.ipv4.tcp_congestion_control; do
        value=$(sysctl -n "$key" 2>/dev/null) || continue
        printf '%s=%s\n' "$key" "$value" >> "$snapshot_tmp/sysctl.original" || { rm -rf -- "$snapshot_tmp"; die '调优 sysctl 原始值快照写入失败。'; }
    done
    touch "$snapshot_tmp/.captured" || { rm -rf -- "$snapshot_tmp"; die '调优快照完成标记写入失败。'; }
    if [[ -d "$dir" ]]; then
        rmdir -- "$dir" || { rm -rf -- "$snapshot_tmp"; die '无法原子替换调优备份目录。'; }
    fi
    mv -f -- "$snapshot_tmp" "$dir" || { rm -rf -- "$snapshot_tmp"; die '调优备份快照原子提交失败。'; }
    write_file_atomically_from_stdin /etc/security/limits.d/A-Box.conf 644 <<'EOF_LIMITS' || { restore_vps_tune 1 || true; die 'limits 配置原子写入失败，已恢复原状态。'; }
# Managed by A-Box
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF_LIMITS
    tmp=$(umask 077; mktemp /tmp/A-Box-sysctl.XXXXXX) || { restore_vps_tune 1 || true; die '调优临时文件创建失败，已恢复原状态。'; }
    printf '%s\n' '# Managed by A-Box' > "$tmp" || { rm -f "$tmp"; restore_vps_tune 1 || true; die '调优临时文件初始化失败，已恢复原状态。'; }
    add_sysctl() { sysctl -n "$1" >/dev/null 2>&1 && printf '%s = %s\n' "$1" "$2" >> "$tmp"; }
    add_sysctl fs.file-max 1048576
    add_sysctl fs.inotify.max_user_instances 8192
    add_sysctl net.ipv4.tcp_syncookies 1
    add_sysctl net.ipv4.tcp_fin_timeout 30
    add_sysctl net.ipv4.tcp_max_syn_backlog 8192
    add_sysctl net.ipv4.tcp_fastopen 3
    add_sysctl net.ipv4.tcp_mtu_probing 1
    add_sysctl net.ipv4.tcp_notsent_lowat 16384
    add_sysctl net.core.netdev_max_backlog 250000
    add_sysctl net.core.somaxconn 32768
    if modprobe tcp_bbr >/dev/null 2>&1; then bbr_loaded=1; fi
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if grep -qw bbr <<< "$available"; then
        add_sysctl net.core.default_qdisc fq
        add_sysctl net.ipv4.tcp_congestion_control bbr
        if (( bbr_loaded == 1 )); then
            path_parent_chain_safe "$bbr_module_file" || { rm -f -- "$tmp"; restore_vps_tune 1 || true; die '内核模块自动加载配置父链不安全。'; }
            [[ ! -L /etc/modules-load.d && (! -e /etc/modules-load.d || -d /etc/modules-load.d) ]] || { rm -f -- "$tmp"; restore_vps_tune 1 || true; die '内核模块自动加载目录不安全。'; }
            install -d -m 755 /etc/modules-load.d || { rm -f -- "$tmp"; restore_vps_tune 1 || true; die '无法创建内核模块自动加载目录。'; }
            write_file_atomically_from_stdin "$bbr_module_file" 644 <<'EOF_BBR' || { rm -f -- "$tmp"; restore_vps_tune 1 || true; die 'BBR 内核模块持久加载配置写入失败。'; }
# Managed by A-Box
tcp_bbr
EOF_BBR
        fi
    else
        msg "${YELLOW}[!] 当前内核未提供 BBR，跳过 BBR/FQ 设置。${NC}"
    fi
    install_file_atomically "$tmp" /etc/sysctl.d/99-A-Box-tune.conf 600 || { rm -f "$tmp"; restore_vps_tune 1 || true; die '调优配置原子写入失败。'; }
    rm -f "$tmp"
    if ! sysctl -p /etc/sysctl.d/99-A-Box-tune.conf >/dev/null 2>&1; then restore_vps_tune 1; die 'sysctl 调优应用失败，已恢复原状态。'; fi
    msg "${GREEN}系统调优已应用；未强制启用 IP forwarding，也未修改核心 JSON 配置。${NC}"
}



# --- v172 UX helpers (U1–U5) ---
abox_is_fast() {
    [[ "${ABOX_FAST:-}" =~ ^(1|true|yes|YES|True)$ ]] && return 0
    [[ -r "$FAST_MODE_FILE" && -f "$FAST_MODE_FILE" && ! -L "$FAST_MODE_FILE" ]] || return 1
    [[ "$(tr -d '[:space:]' < "$FAST_MODE_FILE" 2>/dev/null || true)" == '1' ]]
}

read_fast_mode_label() {
    if abox_is_fast; then printf 'fast\n'; else printf 'strict\n'; fi
}

save_fast_mode() {
    local v="${1:-0}"
    [[ "$v" =~ ^(0|1)$ ]] || die '非法快速模式开关。'
    ensure_abox_dir_owned "$ABOX_DIR" || die '无法准备 A-Box 状态目录。'
    write_file_atomically_from_stdin "$FAST_MODE_FILE" 600 <<< "$v" || die '快速模式写入失败。'
}

abox_prefer_mirror() {
    [[ "${ABOX_CORE_MIRROR_PREFER:-}" =~ ^(1|true|yes)$ ]] && return 0
    [[ -r "$MIRROR_PREFER_FILE" && -f "$MIRROR_PREFER_FILE" && ! -L "$MIRROR_PREFER_FILE" ]] || return 1
    [[ "$(tr -d '[:space:]' < "$MIRROR_PREFER_FILE" 2>/dev/null || true)" == '1' ]]
}

save_mirror_prefer() {
    local v="${1:-0}"
    [[ "$v" =~ ^(0|1)$ ]] || die '非法镜像优先开关。'
    ensure_abox_dir_owned "$ABOX_DIR" || die '无法准备 A-Box 状态目录。'
    write_file_atomically_from_stdin "$MIRROR_PREFER_FILE" 600 <<< "$v" || die '镜像优先写入失败。'
}

confirm_soft() {
    # Non-critical confirm: auto-yes in fast mode. Never use for uninstall/digest/destructive wipe.
    local prompt="$1" answer
    if abox_is_fast; then
        msg "${YELLOW}[fast] ${prompt} → Y${NC}"
        return 0
    fi
    read -r -p "$prompt" answer || return 1
    is_yes "$answer"
}

show_core_pin_docs() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}核心兼容钉扎说明 / Core compatibility pins${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "Xray default: ${YELLOW}${ABOX_XRAY_DEFAULT_VERSION}${NC} (Shadowrocket/Mihomo/XHTTP; avoids 26.9.x ML-KEM ClientHello gate)"
    msg "sing-box default: ${YELLOW}${ABOX_SINGBOX_DEFAULT_VERSION}${NC}"
    msg "Hysteria default: ${YELLOW}${ABOX_HYSTERIA_APP_VERSION:-app/v2.13.0}${NC}"
    msg "Override: ABOX_XRAY_VERSION / ABOX_SINGBOX_VERSION / ABOX_HYSTERIA_APP_VERSION"
    msg "Disaster mirror Release: ${YELLOW}${ABOX_CORE_MIRROR_RELEASE}${NC}"
    msg "Download order: upstream GitHub → A-Box core-mirrors → custom ABOX_CORE_MIRROR_BASE"
    msg "Prefer mirror file: ${MIRROR_PREFER_FILE} (or ABOX_CORE_MIRROR_PREFER=1)"
    msg "Mode: ${YELLOW}$(read_fast_mode_label)${NC} (ABOX_FAST=1 or ${FAST_MODE_FILE})"
    pause_return
}

probe_core_sources_banner() {
    local pref='upstream-first'
    abox_prefer_mirror && pref='mirror-first'
    msg "${CYAN}[download sources] order=${pref}: 1) upstream GitHub Release  2) A-Box ${ABOX_CORE_MIRROR_RELEASE}  3) custom ABOX_CORE_MIRROR_BASE=${ABOX_CORE_MIRROR_BASE:-<unset>}${NC}"
}

fetch_abox_mirror_asset() {
    # Try disaster mirror for current repo:output_file; verify SHA256SUMS. Used by prefer-mirror and fallback.
    local repo=$1 output_file=$2 dest_file=$3
    local mirror_base mirror_url mirror_sum expect_sum got_sum asset_leaf tmp_file _sb_ver
    mirror_base="${ABOX_CORE_MIRROR_BASE:-$ABOX_CORE_MIRROR_BASE_DEFAULT}"
    [[ -n "$mirror_base" ]] || return 1
    case "$repo:$output_file" in
        XTLS/Xray-core:xray_core.zip) asset_leaf="Xray-linux-${XRAY_ARCH}.zip" ;;
        SagerNet/sing-box:singbox_core.tar.gz)
            _sb_ver="${ABOX_SINGBOX_VERSION:-$ABOX_SINGBOX_DEFAULT_VERSION}"; _sb_ver="${_sb_ver#v}"
            if [[ "${release:-}" == 'alpine' ]]; then
                asset_leaf="sing-box-${_sb_ver}-linux-${SB_ARCH}-musl.tar.gz"
            else
                asset_leaf="sing-box-${_sb_ver}-linux-${SB_ARCH}-glibc.tar.gz"
            fi
            ;;
        HyNetworks/hysteria:hysteria_core) asset_leaf="hysteria-linux-${HY2_ARCH}" ;;
        *) return 1 ;;
    esac
    mirror_url="${mirror_base%/}/${asset_leaf}"
    mirror_sum="${mirror_base%/}/SHA256SUMS"
    msg "${YELLOW} -> A-Box mirror try: ${mirror_url}${NC}"
    tmp_file=$(mktemp "${dest_file}.download.XXXXXX") || return 1
    if ! curl -fLsS --connect-timeout 10 -m 180 "$mirror_url" -o "$tmp_file"; then
        rm -f "$tmp_file"; return 1
    fi
    if ! validate_downloaded_asset "$output_file" "$tmp_file"; then
        rm -f "$tmp_file"; return 1
    fi
    expect_sum=$(curl -fsS --connect-timeout 8 -m 30 "$mirror_sum" 2>/dev/null | awk -v f="$asset_leaf" '$2==f || $2==("./" f) || $2~(f"$") {print $1; exit}')
    got_sum=$(sha256sum "$tmp_file" | awk '{print $1}')
    if [[ -z "$expect_sum" || ! "$expect_sum" =~ ^[A-Fa-f0-9]{64}$ || "${got_sum,,}" != "${expect_sum,,}" ]]; then
        msg "${YELLOW}[!] mirror SHA256 mismatch or missing SHA256SUMS${NC}"
        rm -f "$tmp_file"; return 1
    fi
    mv -f "$tmp_file" "$dest_file" || { rm -f "$tmp_file"; return 1; }
    msg "${GREEN}   mirror asset OK (SHA256 verified).${NC}"
    return 0
}

one_click_reality_deploy() {
    local eng='1' answer
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}一键 Reality / One-click Vision REALITY${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "Defaults: port ${YELLOW}443${NC}, SNI ${YELLOW}www.microsoft.com${NC}, KeepAlive off"
    msg "Reuses existing deploy stack; menu 1/6 still available for full wizard."
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}1.${NC} Xray Vision REALITY (recommended)"
        msg "${YELLOW}2.${NC} sing-box Vision REALITY"
        msg "${GREEN}0.${NC} Cancel"
        read -r -p 'Select [0-2]: ' eng || return 0
    else
        msg "${YELLOW}1.${NC} Xray Vision REALITY（推荐）"
        msg "${YELLOW}2.${NC} sing-box Vision REALITY"
        msg "${GREEN}0.${NC} 取消"
        read -r -p '请选择 [0-2]: ' eng || return 0
    fi
    case "$eng" in
        1|2) ;;
        *) return 0 ;;
    esac
    if ! confirm_soft 'Deploy one-click Vision REALITY now? [Y/N]: '; then
        msg "${YELLOW}Canceled.${NC}"; pause_return; return 0
    fi
    export ABOX_QUICK_DEPLOY=1
    case "$eng" in
        1) deploy_xray VISION ;;
        2) deploy_singbox VISION ;;
    esac
    unset ABOX_QUICK_DEPLOY
}

ux_mode_menu() {
    clear
    local c
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}体验模式与下载源 / UX mode & download source${NC}"
    msg "Current mode: ${YELLOW}$(read_fast_mode_label)${NC}"
    msg "Prefer mirror: ${YELLOW}$(abox_prefer_mirror && echo on || echo off)${NC}"
    msg "${YELLOW}1. Strict mode (default; all soft confirms)${NC}"
    msg "${YELLOW}2. Fast mode (skip non-critical confirms; NEVER skip digest / uninstall)${NC}"
    msg "${YELLOW}3. Prefer A-Box core-mirrors first${NC}"
    msg "${YELLOW}4. Prefer upstream GitHub first (default)${NC}"
    msg "${YELLOW}5. Show pin / download order docs${NC}"
    msg "${GREEN}0. Back${NC}"
    read -r -p 'Select [0-5]: ' c
    case "$c" in
        1) save_fast_mode 0; msg "${GREEN}Strict mode saved.${NC}"; pause_return ;;
        2) save_fast_mode 1; msg "${GREEN}Fast mode saved (ABOX_FAST=1 also works).${NC}"; pause_return ;;
        3) save_mirror_prefer 1; msg "${GREEN}Mirror-first saved.${NC}"; pause_return ;;
        4) save_mirror_prefer 0; msg "${GREEN}Upstream-first saved.${NC}"; pause_return ;;
        5) show_core_pin_docs ;;
        *) return 0 ;;
    esac
}

list_extra_uuids() {
    [[ -r "$EXTRA_UUID_FILE" && -f "$EXTRA_UUID_FILE" && ! -L "$EXTRA_UUID_FILE" ]] || return 0
    grep -E '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' "$EXTRA_UUID_FILE" 2>/dev/null || true
}

sync_uuids_into_xray_config() {
    local cfg='/usr/local/etc/xray/config.json' tmp primary extras_json
    [[ -f "$cfg" && ! -L "$cfg" ]] || return 1
    primary="${UUID:-}"
    [[ -n "$primary" ]] || return 1
    extras_json=$(list_extra_uuids | jq -R . | jq -s -c 'map(select(length>0))')
    [[ -n "$extras_json" ]] || extras_json='[]'
    tmp=$(mktemp /tmp/A-Box-uuid.XXXXXX) || return 1
    if ! jq --arg p "$primary" --argjson extras "$extras_json" '
        .inbounds |= map(
          if .protocol=="vless" then
            (.settings.clients[0].flow // "") as $flow |
            .settings.clients = (
              [({id:$p} + (if $flow != "" then {flow:$flow} else {} end))]
              + ($extras | map({id:.} + (if $flow != "" then {flow:$flow} else {} end)))
            )
          else . end
        )
      ' "$cfg" > "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    jq empty "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
    if [[ -x /usr/local/bin/xray ]]; then
        XRAY_LOCATION_ASSET=/usr/local/share/xray /usr/local/bin/xray run -test -config "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
    fi
    install_file_atomically "$tmp" "$cfg" 600 || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    return 0
}

export_lightweight_subscription() {
    local CALLER=${1:-manual} F_IP VISION_SNI_E PUBLIC_KEY_E SHORT_ID_E uri_file b64_file clash_file u url
    ensure_abox_dir_owned "$ABOX_DIR" || die 'subscribe dir prepare failed'
    mkdir -p "$SUBSCRIBE_DIR" || die 'subscribe dir create failed'
    chmod 700 "$SUBSCRIBE_DIR" || true
    [[ -f "$ABOX_ENV" ]] || { msg "${RED}No deployment env.${NC}"; pause_return; return 1; }
    load_abox_env "$ABOX_ENV" || die 'env invalid'
    F_IP="${LINK_IP:-}"
    [[ "$F_IP" =~ : ]] && F_IP="[$F_IP]"
    VISION_SNI=${VISION_SNI:-${VLESS_SNI:-}}
    VISION_SNI_E=$(urlencode "$VISION_SNI")
    PUBLIC_KEY_E=$(urlencode "$PUBLIC_KEY")
    SHORT_ID_E=$(urlencode "$SHORT_ID")
    uri_file="$SUBSCRIBE_DIR/uri-list.txt"
    b64_file="$SUBSCRIBE_DIR/subscription.base64"
    : > "$uri_file"
    if [[ "$MODE" == *'VISION'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
        url="vless://$UUID@$F_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$VISION_SNI_E&fp=chrome&pbk=$PUBLIC_KEY_E&sid=$SHORT_ID_E&type=tcp#A-Box-primary"
        printf '%s\n' "$url" >> "$uri_file"
        while IFS= read -r u; do
            [[ -n "$u" ]] || continue
            url="vless://$u@$F_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$VISION_SNI_E&fp=chrome&pbk=$PUBLIC_KEY_E&sid=$SHORT_ID_E&type=tcp#A-Box-$u"
            printf '%s\n' "$url" >> "$uri_file"
        done < <(list_extra_uuids)
    fi
    if command -v base64 >/dev/null 2>&1; then
        base64 -w0 < "$uri_file" > "$b64_file" 2>/dev/null || base64 < "$uri_file" | tr -d '\n' > "$b64_file"
    fi
    clash_file=$(write_clash_yaml 2>/dev/null || true)
    msg "${GREEN}URI list: ${uri_file}${NC}"
    [[ -f "$b64_file" ]] && msg "${GREEN}Base64 subscription: ${b64_file}${NC}"
    [[ -n "${clash_file:-}" ]] && msg "${GREEN}Clash YAML: ${clash_file}${NC}"
    if [[ "$CALLER" != 'quiet' ]]; then
        msg "${YELLOW}Host these files via HTTPS for remote import; this is not a full panel.${NC}"
        pause_return
    fi
}

multi_uuid_menu() {
    clear
    local c nu answer
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}轻量多 UUID / 订阅导出 (U4)${NC}"
    msg "Primary UUID: ${YELLOW}${UUID:-load env first}${NC}"
    msg "Extra UUIDs:"
    list_extra_uuids | sed 's/^/  /' || msg '  (none)'
    msg "${YELLOW}1. Add extra UUID (patch Xray clients if Vision present)${NC}"
    msg "${YELLOW}2. Export URI list + base64 + Clash path${NC}"
    msg "${YELLOW}3. Clear extra UUIDs file (does not rewrite server until next sync/export add)${NC}"
    msg "${GREEN}0. Back${NC}"
    [[ -f "$ABOX_ENV" ]] && load_abox_env "$ABOX_ENV" 2>/dev/null || true
    read -r -p 'Select [0-3]: ' c
    case "$c" in
        1)
            nu=$(generate_robust_uuid)
            ensure_abox_dir_owned "$ABOX_DIR"
            touch "$EXTRA_UUID_FILE"
            chmod 600 "$EXTRA_UUID_FILE"
            printf '%s\n' "$nu" >> "$EXTRA_UUID_FILE"
            msg "${GREEN}Added: $nu${NC}"
            if [[ "${CORE:-}" == 'xray' ]] && [[ -f /usr/local/etc/xray/config.json ]]; then
                if sync_uuids_into_xray_config; then
                    service_manager restart xray 2>/dev/null || service_manager start xray 2>/dev/null || true
                    msg "${GREEN}Xray clients updated.${NC}"
                else
                    msg "${YELLOW}[!] Could not patch Xray config; URI export still lists the UUID for manual merge.${NC}"
                fi
            fi
            export_lightweight_subscription quiet
            pause_return
            ;;
        2) export_lightweight_subscription manual ;;
        3)
            read -r -p 'Clear extra UUID file? [Y/N]: ' answer
            is_yes "$answer" || { pause_return; return 0; }
            rm -f -- "$EXTRA_UUID_FILE"
            msg "${GREEN}Cleared.${NC}"; pause_return
            ;;
        *) return 0 ;;
    esac
}

try_latest_cores_danger() {
    local answer targets=() t latest json
    clear
    msg "${RED}${BOLD}DANGER: 试用上游 latest 核心 / Try upstream latest${NC}"
    msg "Default pins remain ${ABOX_XRAY_DEFAULT_VERSION} / ${ABOX_SINGBOX_DEFAULT_VERSION}."
    msg "This path may break Shadowrocket/Mihomo (e.g. Xray ML-KEM). Failure triggers automatic rollback."
    read -r -p 'Type YES to continue: ' answer
    [[ "$answer" == 'YES' ]] || { msg "${YELLOW}Canceled.${NC}"; pause_return; return 0; }
    init_system_environment
    load_optional_abox_env_or_die
    if abox_owns_service xray && [[ -x /usr/local/bin/xray ]]; then targets+=(xray); fi
    if abox_owns_service sing-box && [[ -x /usr/local/bin/sing-box ]]; then targets+=(singbox); fi
    if abox_owns_service hysteria && [[ -x /usr/local/bin/hysteria ]]; then targets+=(hysteria); fi
    (( ${#targets[@]} > 0 )) || { msg "${YELLOW}No owned cores.${NC}"; pause_return; return 0; }
    begin_core_upgrade_transaction "${targets[@]}"
    for t in "${targets[@]}"; do
        case "$t" in
            xray)
                json=$(github_api_get 'https://api.github.com/repos/XTLS/Xray-core/releases/latest' 2>/dev/null) || json=''
                latest=$(jq -r '.tag_name // empty' <<< "$json")
                [[ -n "$latest" ]] || die '无法解析 Xray latest tag。'
                msg "${YELLOW}Trying Xray ${latest}${NC}"
                ABOX_XRAY_VERSION="$latest" upgrade_xray_core_only
                ;;
            singbox)
                json=$(github_api_get 'https://api.github.com/repos/SagerNet/sing-box/releases/latest' 2>/dev/null) || json=''
                latest=$(jq -r '.tag_name // empty' <<< "$json")
                [[ -n "$latest" ]] || die '无法解析 sing-box latest tag。'
                msg "${YELLOW}Trying sing-box ${latest}${NC}"
                ABOX_SINGBOX_VERSION="$latest" upgrade_singbox_core_only
                ;;
            hysteria)
                # Hysteria uses app/vX tags; keep pin channel unless API gives tag
                json=$(github_api_get 'https://api.github.com/repos/HyNetworks/hysteria/releases/latest' 2>/dev/null) || json=''
                latest=$(jq -r '.tag_name // empty' <<< "$json")
                [[ -n "$latest" ]] || die '无法解析 Hysteria latest tag。'
                msg "${YELLOW}Trying Hysteria ${latest}${NC}"
                ABOX_HYSTERIA_APP_VERSION="$latest" upgrade_hysteria_core_only
                ;;
        esac
    done
    commit_core_upgrade_transaction
    msg "${GREEN}Latest-core attempt finished (transaction committed). Re-test clients.${NC}"
    pause_return
}


valid_ip_pref() {
    [[ "${1:-}" =~ ^(ipv4|ipv6|dual)$ ]]
}

read_ip_pref() {
    local v='dual'
    if [[ -r "$IP_PREF_FILE" && -f "$IP_PREF_FILE" && ! -L "$IP_PREF_FILE" ]]; then
        [[ "$(stat -c %u:%g "$IP_PREF_FILE" 2>/dev/null || true)" == '0:0' ]] || { printf 'dual\n'; return 0; }
        v=$(tr -d '[:space:]' < "$IP_PREF_FILE" 2>/dev/null || true)
    fi
    valid_ip_pref "$v" || v='dual'
    printf '%s\n' "$v"
}

save_ip_pref() {
    local v="${1:-}"
    valid_ip_pref "$v" || die '非法 IP 偏好设置 / Invalid IP preference.'
    ensure_abox_dir_owned "$ABOX_DIR" || die '无法准备 A-Box 状态目录。'
    write_file_atomically_from_stdin "$IP_PREF_FILE" 600 <<< "$v" || die 'IP 偏好写入失败。'
}

ip_preference_menu() {
    clear
    local cur c
    cur=$(read_ip_pref)
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}IP 协议偏好 / IP protocol preference${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "当前 / Current: ${YELLOW}${cur}${NC}"
    msg "${YELLOW}1. 仅 IPv4 (listen 0.0.0.0, prefer IPv4 share links)${NC}"
    msg "${YELLOW}2. 仅 IPv6 (listen ::, prefer IPv6 share links)${NC}"
    msg "${YELLOW}3. 双栈 dual (auto :: when available, else IPv4)${NC}"
    msg "${GREEN}0. 返回${NC}"
    read -r -p 'Select [0-3]: ' c
    case "$c" in
        1) save_ip_pref ipv4; msg "${GREEN}已保存: ipv4${NC}"; pause_return ;;
        2)
            has_ipv6 || { msg "${RED}[!] 系统当前无可用全局 IPv6，拒绝保存仅 IPv6。${NC}"; pause_return; return 1; }
            save_ip_pref ipv6; msg "${GREEN}已保存: ipv6${NC}"; pause_return ;;
        3) save_ip_pref dual; msg "${GREEN}已保存: dual${NC}"; pause_return ;;
        *) return 0 ;;
    esac
    msg "${YELLOW}[*] 新监听偏好对后续部署生效；已运行节点需重新部署或重启核心以应用 listen 地址。${NC}"
}

timezone_for_country() {
    case "${1^^}" in
        CN) printf 'Asia/Shanghai\n' ;;
        HK) printf 'Asia/Hong_Kong\n' ;;
        TW) printf 'Asia/Taipei\n' ;;
        SG) printf 'Asia/Singapore\n' ;;
        JP) printf 'Asia/Tokyo\n' ;;
        KR) printf 'Asia/Seoul\n' ;;
        IN) printf 'Asia/Kolkata\n' ;;
        ID) printf 'Asia/Jakarta\n' ;;
        TH) printf 'Asia/Bangkok\n' ;;
        VN) printf 'Asia/Ho_Chi_Minh\n' ;;
        MY) printf 'Asia/Kuala_Lumpur\n' ;;
        PH) printf 'Asia/Manila\n' ;;
        AU) printf 'Australia/Sydney\n' ;;
        NZ) printf 'Pacific/Auckland\n' ;;
        US) printf 'America/New_York\n' ;;
        CA) printf 'America/Toronto\n' ;;
        BR) printf 'America/Sao_Paulo\n' ;;
        MX) printf 'America/Mexico_City\n' ;;
        GB|UK) printf 'Europe/London\n' ;;
        IE) printf 'Europe/Dublin\n' ;;
        FR) printf 'Europe/Paris\n' ;;
        DE) printf 'Europe/Berlin\n' ;;
        NL) printf 'Europe/Amsterdam\n' ;;
        BE) printf 'Europe/Brussels\n' ;;
        CH) printf 'Europe/Zurich\n' ;;
        AT) printf 'Europe/Vienna\n' ;;
        SE) printf 'Europe/Stockholm\n' ;;
        NO) printf 'Europe/Oslo\n' ;;
        FI) printf 'Europe/Helsinki\n' ;;
        PL) printf 'Europe/Warsaw\n' ;;
        CZ) printf 'Europe/Prague\n' ;;
        ES) printf 'Europe/Madrid\n' ;;
        IT) printf 'Europe/Rome\n' ;;
        PT) printf 'Europe/Lisbon\n' ;;
        RU) printf 'Europe/Moscow\n' ;;
        TR) printf 'Europe/Istanbul\n' ;;
        AE) printf 'Asia/Dubai\n' ;;
        SA) printf 'Asia/Riyadh\n' ;;
        IL) printf 'Asia/Jerusalem\n' ;;
        ZA) printf 'Africa/Johannesburg\n' ;;
        EG) printf 'Africa/Cairo\n' ;;
        NG) printf 'Africa/Lagos\n' ;;
        AR) printf 'America/Argentina/Buenos_Aires\n' ;;
        CL) printf 'America/Santiago\n' ;;
        *) printf '\n' ;;
    esac
}

valid_timezone_name() {
    local tz="${1:-}"
    [[ "$tz" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] || return 1
    [[ -e "/usr/share/zoneinfo/$tz" || -L "/usr/share/zoneinfo/$tz" || -e "/usr/share/zoneinfo/posix/$tz" ]]
}

current_timezone_name() {
    local tz
    if command -v timedatectl >/dev/null 2>&1; then
        tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
        [[ -n "$tz" ]] && { printf '%s\n' "$tz"; return 0; }
    fi
    if [[ -L /etc/localtime ]]; then
        tz=$(readlink /etc/localtime 2>/dev/null || true)
        tz=${tz#*/zoneinfo/}
        [[ -n "$tz" ]] && { printf '%s\n' "$tz"; return 0; }
    fi
    if [[ -r /etc/timezone ]]; then
        tr -d '[:space:]' < /etc/timezone
        return 0
    fi
    printf 'UTC\n'
}

snapshot_timezone_state() {
    local dir="$1" cur
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" || return 1
    cur=$(current_timezone_name)
    printf '%s\n' "$cur" > "$dir/timezone" || return 1
    if [[ -e /etc/localtime ]]; then
        cp -a /etc/localtime "$dir/localtime" 2>/dev/null || true
    fi
    if [[ -f /etc/timezone ]]; then
        cp -a /etc/timezone "$dir/etc-timezone" 2>/dev/null || true
    fi
    return 0
}

restore_timezone_snapshot() {
    local dir="$1" tz
    [[ -d "$dir" ]] || return 1
    tz=$(tr -d '[:space:]' < "$dir/timezone" 2>/dev/null || true)
    if [[ -n "$tz" ]] && valid_timezone_name "$tz"; then
        apply_timezone_name "$tz" || return 1
        return 0
    fi
    if [[ -e "$dir/localtime" ]]; then
        cp -a "$dir/localtime" /etc/localtime || return 1
    fi
    if [[ -f "$dir/etc-timezone" ]]; then
        cp -a "$dir/etc-timezone" /etc/timezone || return 1
    fi
    return 0
}

apply_timezone_name() {
    local tz="$1"
    valid_timezone_name "$tz" || return 1
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-timezone "$tz" || return 1
        return 0
    fi
    # Alpine / BusyBox path
    if [[ -e "/usr/share/zoneinfo/$tz" ]]; then
        ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime || return 1
        printf '%s\n' "$tz" > /etc/timezone || true
        return 0
    fi
    return 1
}

detect_country_for_timezone() {
    local ip body country
    ip=$(get_public_ip 2>/dev/null || true)
    [[ -n "$ip" && "$ip" != 'N/A' ]] || return 1
    body=$(curl -fsS --connect-timeout 3 -m 6 "https://ipinfo.io/${ip}/country" 2>/dev/null | tr -d '[:space:]' || true)
    [[ "$body" =~ ^[A-Za-z]{2}$ ]] || return 1
    printf '%s\n' "${body^^}"
}

timezone_list_entries() {
    if command -v timedatectl >/dev/null 2>&1; then timedatectl list-timezones 2>/dev/null || true
    elif [[ -d /usr/share/zoneinfo ]]; then
        find /usr/share/zoneinfo \( -type f -o -type l \) 2>/dev/null |
            sed 's#^/usr/share/zoneinfo/##' |
            grep -E '^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+.-]+)*$' |
            grep -Ev '^(posix|right|SystemV)/|^(zone|iso3166|tzdata|leap|localtime|posixrules|Factory)$'
    fi
    printf '%s\n' UTC
}

timezone_apply_with_rollback() {
    local target="$1" snap rollback stage
    valid_timezone_name "$target" || { msg "${RED}非法或不存在的时区: $target${NC}"; return 1; }
    snap=$(mktemp -d /etc/ddr/.tz-snap.XXXXXX) || return 1
    chmod 700 "$snap" && snapshot_timezone_state "$snap" || { rm -rf -- "$snap"; msg "${RED}时区快照失败，未修改。${NC}"; return 1; }
    if ! apply_timezone_name "$target"; then
        restore_timezone_snapshot "$snap" || msg "${RED}旧时区恢复失败，请检查系统。${NC}"
        rm -rf -- "$snap"; msg "${RED}时区应用失败，已尝试回滚。${NC}"; return 1
    fi
    rollback='/etc/ddr/.tz-rollback'
    stage=$(mktemp -d /etc/ddr/.tz-rollback-new.XXXXXX) || { restore_timezone_snapshot "$snap" || true; rm -rf -- "$snap"; return 1; }
    cp -a "$snap"/. "$stage"/ && rm -rf -- "$rollback" && mv -- "$stage" "$rollback" || {
        restore_timezone_snapshot "$snap" || true; rm -rf -- "$snap" "$stage"; return 1;
    }
    write_file_atomically_from_stdin "$TZ_STATE_FILE" 600 <<< "applied=$target" || true
    rm -rf -- "$snap"
    msg "${GREEN}时区已设置为 $target；原时区已保存，可回滚。${NC}"
}

timezone_choose_from_list() {
    local query="${1:-}" page=0 step=25 input tz confirm idx start end
    local -a all=() filtered=()
    mapfile -t all < <(timezone_list_entries | awk 'NF && !seen[$0]++' | LC_ALL=C sort -u)
    for tz in "${all[@]}"; do [[ -z "$query" || "${tz,,}" == *"${query,,}"* ]] && filtered+=("$tz"); done
    (( ${#filtered[@]} )) || { msg "${YELLOW}没有匹配时区。${NC}"; return 1; }
    while true; do
        clear; msg "${CYAN}================ IANA 时区列表 / Time zones ================${NC}"
        msg "Current: $(current_timezone_name) | Query: ${query:-ALL} | Total: ${#filtered[@]}"
        start=$((page*step)); end=$((start+step)); ((end>${#filtered[@]})) && end=${#filtered[@]}
        for ((idx=start; idx<end; idx++)); do printf '%4d. %s\n' "$((idx+1))" "${filtered[$idx]}"; done
        read -r -p '输入编号；n/p 翻页；s 搜索；0 返回: ' input || return 0
        case "${input,,}" in
            n|next) ((end<${#filtered[@]})) && page=$((page+1)) ;;
            p|prev) ((page>0)) && page=$((page-1)) ;;
            s|search) read -r -p '时区关键词: ' query || return 0; page=0; filtered=(); for tz in "${all[@]}"; do [[ -z "$query" || "${tz,,}" == *"${query,,}"* ]] && filtered+=("$tz"); done ;;
            0|'') return 0 ;;
            *[!0-9]*) msg "${YELLOW}请输入编号或 n/p/s/0。${NC}"; sleep 1 ;;
            *) ((input>=1 && input<=${#filtered[@]})) || { msg "${YELLOW}编号超出范围。${NC}"; sleep 1; continue; }
               tz="${filtered[$((input-1))]}"; read -r -p "确认设置为 $tz ? [Y/N]: " confirm
               if is_yes "$confirm"; then timezone_apply_with_rollback "$tz"; pause_return; return 0; fi ;;
        esac
    done
}

timezone_locale_ntp_menu() {
    clear
    local c ntp synced now page=0 input start end i target
    local -a locales=()
    now=$(date '+%Y-%m-%d %H:%M:%S %Z (%z)' 2>/dev/null || date)
    ntp='unknown'; synced='unknown'
    if command -v timedatectl >/dev/null 2>&1; then
        ntp=$(timedatectl show -p NTP --value 2>/dev/null || printf unknown)
        synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || printf unknown)
    fi
    msg "${CYAN}================ 时间、时区与地区 / Time & Region ================${NC}"
    msg "当前时间: $now | 时区: $(current_timezone_name) | NTP: $ntp | 已同步: $synced"
    msg "${YELLOW}1. 全部时区编号列表${NC}"
    msg "${YELLOW}2. 搜索时区后按编号选择${NC}"
    msg "${YELLOW}3. 修改系统 Locale（只列出已安装语言包）${NC}"
    msg "${YELLOW}4. 启用 NTP 自动时间同步${NC}"
    msg "${YELLOW}5. 回滚时区修改前快照${NC}"
    msg "${GREEN}0. 返回${NC}"
    read -r -p 'Select [0-5]: ' c
    case "$c" in
        1) timezone_choose_from_list '' ;;
        2) read -r -p '搜索城市/地区/时区: ' input || return 0; timezone_choose_from_list "$input" ;;
        3)
            if command -v localectl >/dev/null 2>&1; then mapfile -t locales < <(localectl list-locales 2>/dev/null | awk 'NF&&!seen[$0]++' | sort -u); fi
            ((${#locales[@]})) || mapfile -t locales < <(locale -a 2>/dev/null | awk 'NF&&!seen[$0]++' | sort -u)
            ((${#locales[@]})) || { msg "${YELLOW}没有可用 Locale；需先安装/生成语言包。${NC}"; pause_return; return 1; }
            while true; do
                clear; msg "${GREEN}可用 Locale（编号选择）${NC}"
                start=$((page*25)); end=$((start+25)); ((end>${#locales[@]})) && end=${#locales[@]}
                for ((i=start;i<end;i++)); do printf '%4d. %s\n' "$((i+1))" "${locales[$i]}"; done
                read -r -p '编号/n/p/0: ' input || return 0
                case "${input,,}" in
                    n) ((end<${#locales[@]})) && page=$((page+1)) ;;
                    p) ((page>0)) && page=$((page-1)) ;;
                    0|'') break ;;
                    *[!0-9]*) msg "${YELLOW}请输入编号/n/p/0。${NC}"; sleep 1 ;;
                    *) ((input>=1&&input<=${#locales[@]})) || continue
                       target="${locales[$((input-1))]}"; read -r -p "确认设置 LANG=$target? [Y/N]: " c
                       is_yes "$c" || continue
                       if command -v localectl >/dev/null 2>&1; then localectl set-locale "LANG=$target"
                       elif command -v update-locale >/dev/null 2>&1; then update-locale "LANG=$target"
                       else msg "${RED}缺少 localectl/update-locale，未修改。${NC}"; fi
                       pause_return; return 0 ;;
                esac
            done
            ;;
        4) if command -v timedatectl >/dev/null 2>&1; then timedatectl set-ntp true && msg "${GREEN}已请求启用 NTP。${NC}" || msg "${RED}启用 NTP 失败。${NC}"; else msg "${YELLOW}本系统没有 timedatectl，请使用发行版对应的 chrony/openntpd 服务。${NC}"; fi; pause_return ;;
        5) if [[ -d /etc/ddr/.tz-rollback ]]; then restore_timezone_snapshot /etc/ddr/.tz-rollback && msg "${GREEN}时区已回滚。${NC}" || msg "${RED}回滚失败。${NC}"; else msg "${YELLOW}无可用时区快照。${NC}"; fi; pause_return ;;
        *) return 0 ;;
    esac
}

timezone_menu() { timezone_locale_ntp_menu; }


dns_backend_detect() {
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        printf 'resolved\n'
    elif command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        printf 'networkmanager\n'
    else
        printf 'resolvconf\n'
    fi
}

snapshot_dns_state() {
    local dir="$1"
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" || return 1
    dns_backend_detect > "$dir/backend" || return 1
    [[ -f /etc/resolv.conf || -L /etc/resolv.conf ]] && cp -a /etc/resolv.conf "$dir/resolv.conf" 2>/dev/null || true
    if [[ -f /etc/systemd/resolved.conf ]]; then cp -a /etc/systemd/resolved.conf "$dir/resolved.conf" || return 1; fi
    if [[ -f /etc/systemd/resolved.conf.d/99-abox-dns.conf ]]; then
        mkdir -p "$dir/resolved.conf.d" || return 1
        cp -a /etc/systemd/resolved.conf.d/99-abox-dns.conf "$dir/resolved.conf.d/99-abox-dns.conf" || return 1
    fi
    if [[ -f /etc/dnscrypt-proxy/dnscrypt-proxy.toml ]]; then
        mkdir -p "$dir/dnscrypt-proxy" || return 1
        cp -a /etc/dnscrypt-proxy/dnscrypt-proxy.toml "$dir/dnscrypt-proxy/dnscrypt-proxy.toml" || return 1
        printf '%s\n' present > "$dir/dnscrypt-config-state"
    else
        printf '%s\n' absent > "$dir/dnscrypt-config-state"
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dnscrypt-proxy 2>/dev/null; then
        printf '%s\n' active > "$dir/dnscrypt-service-state"
    else
        printf '%s\n' inactive > "$dir/dnscrypt-service-state"
    fi
    printf '%s\n' ok > "$dir/COMPLETE" || return 1
}restore_dns_snapshot() {
    local dir="$1" backend config_state svc_state
    [[ -f "$dir/COMPLETE" ]] || return 1
    backend=$(tr -d '[:space:]' < "$dir/backend" 2>/dev/null || true)
    if [[ -e "$dir/resolv.conf" || -L "$dir/resolv.conf" ]]; then cp -a "$dir/resolv.conf" /etc/resolv.conf || return 1; fi
    if [[ -f "$dir/resolved.conf" ]]; then cp -a "$dir/resolved.conf" /etc/systemd/resolved.conf || return 1; fi
    if [[ -f "$dir/resolved.conf.d/99-abox-dns.conf" ]]; then
        mkdir -p /etc/systemd/resolved.conf.d || return 1
        cp -a "$dir/resolved.conf.d/99-abox-dns.conf" /etc/systemd/resolved.conf.d/99-abox-dns.conf || return 1
    else
        rm -f /etc/systemd/resolved.conf.d/99-abox-dns.conf 2>/dev/null || true
    fi
    config_state=$(tr -d '[:space:]' < "$dir/dnscrypt-config-state" 2>/dev/null || true)
    if [[ "$config_state" == present && -f "$dir/dnscrypt-proxy/dnscrypt-proxy.toml" ]]; then
        install -d -m 755 /etc/dnscrypt-proxy || return 1
        cp -a "$dir/dnscrypt-proxy/dnscrypt-proxy.toml" /etc/dnscrypt-proxy/dnscrypt-proxy.toml || return 1
    fi
    if [[ "$backend" == resolved ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart systemd-resolved >/dev/null 2>&1 || return 1
    fi
    if [[ "$backend" == networkmanager ]] && command -v systemctl >/dev/null 2>&1; then systemctl reload NetworkManager >/dev/null 2>&1 || true; fi
    svc_state=$(tr -d '[:space:]' < "$dir/dnscrypt-service-state" 2>/dev/null || true)
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files dnscrypt-proxy.service >/dev/null 2>&1; then
        if [[ "$svc_state" == active ]]; then systemctl restart dnscrypt-proxy >/dev/null 2>&1 || return 1
        else systemctl stop dnscrypt-proxy >/dev/null 2>&1 || true; fi
    fi
    return 0
}apply_host_dns() {
    local mode="$1" v4="$2" v6="$3" backend dropin answer
    # mode: plain | dot
    backend=$(dns_backend_detect)
    msg "检测到 DNS 后端 / backend: ${YELLOW}${backend}${NC}"
    msg "将应用 IPv4 DNS: ${YELLOW}${v4}${NC}  IPv6 DNS: ${YELLOW}${v6:-none}${NC}  模式: ${YELLOW}${mode}${NC}"
    read -r -p '确认修改本机 DNS？可回滚。Confirm host DNS change? [Y/N]: ' answer
    is_yes "$answer" || { msg "${YELLOW}已取消。${NC}"; return 0; }
    # Refuse silent immutable bit games
    if command -v lsattr >/dev/null 2>&1 && lsattr /etc/resolv.conf 2>/dev/null | grep -q 'i'; then
        read -r -p '/etc/resolv.conf 带 immutable(i)。仍要继续并尝试 chattr -i？[Y/N]: ' answer
        is_yes "$answer" || return 0
        chattr -i /etc/resolv.conf 2>/dev/null || die '无法清除 immutable 属性。'
    fi
    rm -rf -- "$DNS_BACKUP_DIR"
    mkdir -p "$DNS_BACKUP_DIR" || die 'DNS 备份目录创建失败。'
    chmod 700 "$DNS_BACKUP_DIR"
    snapshot_dns_state "$DNS_BACKUP_DIR" || die 'DNS 状态快照失败。'
    case "$backend" in
        resolved)
            mkdir -p /etc/systemd/resolved.conf.d || die '无法创建 resolved.conf.d'
            dropin=/etc/systemd/resolved.conf.d/99-abox-dns.conf
            if [[ "$mode" == 'dot' ]]; then
                write_file_atomically_from_stdin "$dropin" 644 <<EOF_DNS || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'DoT drop-in 写入失败。'; }
[Resolve]
DNS=${v4}${v6:+ $v6}
FallbackDNS=
DNSOverTLS=yes
EOF_DNS
            else
                write_file_atomically_from_stdin "$dropin" 644 <<EOF_DNS || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'DNS drop-in 写入失败。'; }
[Resolve]
DNS=${v4}${v6:+ $v6}
FallbackDNS=
DNSOverTLS=no
EOF_DNS
            fi
            systemctl restart systemd-resolved >/dev/null 2>&1 || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'systemd-resolved 重启失败，已回滚。'; }
            ;;
        networkmanager)
            # Apply to active device via nmcli (plaintext DNS; NM DoT varies by version)
            local iface
            iface=$(nmcli -t -f DEVICE,STATE d 2>/dev/null | awk -F: '$2=="connected"{print $1; exit}')
            [[ -n "$iface" ]] || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die '未找到 NetworkManager 活动接口。'; }
            nmcli d modify "$iface" ipv4.ignore-auto-dns yes ipv4.dns "$v4" || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'nmcli IPv4 DNS 失败。'; }
            if [[ -n "$v6" ]]; then
                nmcli d modify "$iface" ipv6.ignore-auto-dns yes ipv6.dns "$v6" || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'nmcli IPv6 DNS 失败。'; }
            fi
            nmcli d reapply "$iface" >/dev/null 2>&1 || nmcli n off && nmcli n on || true
            ;;
        *)
            # Plain resolv.conf for Alpine / generic
            {
                printf '# Managed by A-Box host DNS helper\n'
                printf 'nameserver %s\n' "$v4"
                [[ -n "$v6" ]] && printf 'nameserver %s\n' "$v6"
                printf 'options timeout:2 attempts:3\n'
            } > /etc/resolv.conf || { restore_dns_snapshot "$DNS_BACKUP_DIR"; die 'resolv.conf 写入失败。'; }
            if [[ "$mode" == 'dot' ]]; then
                msg "${YELLOW}[!] 当前后端不支持 systemd-resolved DoT；已写入明文 nameserver。请改用 stubby/unbound 或切换到 systemd-resolved。${NC}"
            fi
            ;;
    esac
    write_file_atomically_from_stdin "$DNS_STATE_FILE" 600 <<< "backend=${backend};mode=${mode};v4=${v4};v6=${v6}" || true
    msg "${GREEN}本机 DNS 已更新。可用菜单回滚。${NC}"
}

dns_menu() {
    clear
    local c mode v4 v6 answer
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}VPS 本机 DNS / Host DNS${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "后端: ${YELLOW}$(dns_backend_detect)${NC}"
    if [[ -r /etc/resolv.conf ]]; then
        msg "${YELLOW}当前 /etc/resolv.conf 摘要:${NC}"
        grep -E '^(nameserver|search|options)' /etc/resolv.conf 2>/dev/null | head -8 || true
    fi
    msg "${YELLOW}1. 明文 DNS（IPv4+可选 IPv6 nameserver）${NC}"
    msg "${YELLOW}2. 隐私 DNS DoT（systemd-resolved DNSOverTLS=yes）${NC}"
    msg "${YELLOW}3. 使用 Cloudflare 1.1.1.1 / 2606:4700:4700::1111${NC}"
    msg "${YELLOW}4. 使用 Quad9 9.9.9.9 / 2620:fe::fe${NC}"
    msg "${YELLOW}5. 回滚到上次 A-Box DNS 变更前${NC}"
    msg "${GREEN}0. 返回${NC}"
    read -r -p 'Select [0-5]: ' c
    case "$c" in
        1)
            read -r -p 'IPv4 DNS (e.g. 1.1.1.1): ' v4
            valid_ipv4_cidr "$v4" && [[ "$v4" != */* ]] || { msg "${RED}非法 IPv4 DNS${NC}"; pause_return; return 1; }
            read -r -p 'IPv6 DNS (可空, e.g. 2606:4700:4700::1111): ' v6
            [[ -z "$v6" ]] || valid_ipv6_cidr "$v6" || { msg "${RED}非法 IPv6 DNS${NC}"; pause_return; return 1; }
            [[ -z "$v6" || "$v6" != */* ]] || { msg "${RED}请填写地址而非 CIDR${NC}"; pause_return; return 1; }
            apply_host_dns plain "$v4" "$v6"
            pause_return
            ;;
        2)
            read -r -p 'DoT resolver IPv4 (e.g. 1.1.1.1): ' v4
            valid_ipv4_cidr "$v4" && [[ "$v4" != */* ]] || { msg "${RED}非法 IPv4${NC}"; pause_return; return 1; }
            read -r -p 'DoT resolver IPv6 (可空): ' v6
            [[ -z "$v6" ]] || { valid_ipv6_cidr "$v6" && [[ "$v6" != */* ]]; } || { msg "${RED}非法 IPv6${NC}"; pause_return; return 1; }
            apply_host_dns dot "$v4" "$v6"
            pause_return
            ;;
        3) apply_host_dns plain '1.1.1.1' '2606:4700:4700::1111'; pause_return ;;
        4) apply_host_dns plain '9.9.9.9' '2620:fe::fe'; pause_return ;;
        5)
            if [[ -f "$DNS_BACKUP_DIR/COMPLETE" ]]; then
                restore_dns_snapshot "$DNS_BACKUP_DIR" && msg "${GREEN}DNS 已回滚。${NC}" || msg "${RED}DNS 回滚失败。${NC}"
            else
                msg "${YELLOW}[!] 无 DNS 回滚快照。${NC}"
            fi
            pause_return
            ;;
        *) return 0 ;;
    esac
}


tune_vps() {
    clear
    msg "$CYAN======================================================================$NC"
    msg "$BOLD$GREEN VPS 一键优化 / VPS one-click optimization $NC"
    msg "$CYAN======================================================================$NC"
    msg "$YELLOW 1. 一键应用可用的 BBR/FQ 与系统调优（可回滚） / Apply BBR/FQ tuning (rollback supported) $NC"
    msg "$YELLOW 2. 恢复调优前状态 / Restore pre-tuning state $NC"
    msg "$GREEN 0. 返回 / Back $NC"
    local c
    read -r -p 'Select [0-2]: ' c
    case "$c" in
        1) apply_vps_tune; pause_return ;;
        2) restore_vps_tune; pause_return ;;
        *) return 0 ;;
    esac
}

sha256_in_allowlist() {
    local sha="${1,,}" allowlist="${2:-}"
    [[ "$sha" =~ ^[a-f0-9]{64}$ && -n "$allowlist" ]] || return 1
    awk -v want="$sha" 'BEGIN {
        found=0
        while ((getline line) > 0) {
            gsub(/[,;[:space:]]+/, "\n", line)
            count=split(line, values, /\n/)
            for (i=1; i<=count; i++) {
                value=tolower(values[i])
                if (value == want) { found=1; exit }
            }
        }
        exit(found ? 0 : 1)
    }' <<< "$allowlist"
}

canonical_path() {
    local input="${1:-}"
    [[ -n "$input" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$input" <<'PY_CANONICAL_PATH'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY_CANONICAL_PATH
}

create_backup_manifest() {
    local tree="${1:-}" output="${2:-}"
    [[ -d "$tree/root" && -d "$tree/meta" && -n "$output" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$tree" "$output" <<'PY_BACKUP_MANIFEST'
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path

base = Path(sys.argv[1]).resolve(strict=True)
out = Path(sys.argv[2])
try:
    out_relative = out.resolve(strict=False).relative_to(base)
except (OSError, ValueError):
    raise SystemExit(1)

entries = []
for top_name in ("root", "meta"):
    top = base / top_name
    if not top.is_dir() or top.is_symlink():
        raise SystemExit(1)
    for current, dirs, files in os.walk(top, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            candidate = current_path / name
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                raise SystemExit(1)
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise SystemExit(1)
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(base)
            if relative == out_relative:
                continue
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                raise SystemExit(1)
            if not stat.S_ISREG(mode):
                raise SystemExit(1)
            entries.append((relative.as_posix(), candidate))

entries.sort(key=lambda item: item[0].encode("utf-8"))
out.parent.mkdir(parents=False, exist_ok=True)
tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", suffix=".tmp", dir=str(out.parent))
tmp = Path(tmp_name)
try:
    with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="\n") as handle:
        for relative, candidate in entries:
            digest = hashlib.sha256()
            with candidate.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            handle.write(f"{digest.hexdigest()}  {relative}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
except Exception:
    try:
        tmp.unlink()
    except OSError:
        pass
    raise SystemExit(1)
PY_BACKUP_MANIFEST
}

confirm_remote_script_hash() {
    local label="$1" url="$2" sha="$3"
    # Refuse without an explicit pin. Interactive confirm alone is not a trust root.
    if [[ -z "${ABOX_REMOTE_SHA256_ALLOWLIST:-}" ]]; then
        msg "${RED}[!] Refusing to run third-party remote script without ABOX_REMOTE_SHA256_ALLOWLIST.${NC}"
        msg "${YELLOW}[*] Set ABOX_REMOTE_SHA256_ALLOWLIST to a comma/space-separated list of expected SHA256 digests, then retry.${NC}"
        msg "${YELLOW}[*] Displayed digest for pinning: ${sha}${NC}"
        return 1
    fi
    if ! sha256_in_allowlist "$sha" "$ABOX_REMOTE_SHA256_ALLOWLIST"; then
        die "Remote script SHA256 is not in ABOX_REMOTE_SHA256_ALLOWLIST: ${label}"
    fi
    msg "${GREEN}[*] Remote script SHA256 matched ABOX_REMOTE_SHA256_ALLOWLIST.${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}[!] This is third-party code outside A-Box control even after digest pin.${NC}"
        msg "${YELLOW}[!] Source: ${url}${NC}"
        confirm_yes_no 'Execute this digest-pinned third-party script? [Y/N]: '
    else
        msg "${YELLOW}[!] 即使摘要已钉扎，仍是 A-Box 无法控制的第三方代码。${NC}"
        msg "${YELLOW}[!] 来源：${url}${NC}"
        confirm_yes_no '确认执行此已钉扎摘要的第三方脚本？[Y/N]: '
    fi
}

run_remote_bash_script() {
    local label="$1" url="$2" tmp sha
    shift 2 || true
    tmp=$(umask 077; mktemp /tmp/A-Box-remote.XXXXXX.sh) || die '远程脚本临时文件创建失败。'
    if ! curl -fLsS --connect-timeout 10 -m 120 "$url" -o "$tmp"; then
        rm -f "$tmp"
        die "远程脚本下载失败: $label"
    fi
    chmod 600 "$tmp"
    sha=$(sha256sum "$tmp" | awk '{print $1}')
    msg "${YELLOW}[*] Remote script: ${label}${NC}"
    msg "${YELLOW}[*] Source: ${url}${NC}"
    msg "${YELLOW}[*] SHA256: ${sha}${NC}"
    bash -n "$tmp" || { rm -f "$tmp"; die "远程脚本语法校验失败: $label"; }
    confirm_remote_script_hash "$label" "$url" "$sha" || { rm -f "$tmp"; msg "${YELLOW}[*] Remote script execution canceled: ${label}${NC}"; return 130; }
    # Third-party code is explicitly opt-in, but must not inherit any exported
    # controller credentials (including secrets unknown to this script). Start
    # from an empty environment and pass only the minimum non-secret runtime context.
    env -i \
        PATH="$PATH" \
        HOME="${HOME:-/root}" \
        LANG="${LANG:-C.UTF-8}" \
        TERM="${TERM:-dumb}" \
        bash "$tmp" "$@"
    local rc=$?
    rm -f "$tmp"
    return "$rc"
}



sni_normalize_candidate_file() {
    local source="${1:-}" output="${2:-}" bytes line domain rows=0
    local -A seen=()
    [[ -n "$source" && -n "$output" && -f "$source" && ! -L "$source" ]] || return 1
    bytes=$(wc -c < "$source" 2>/dev/null | tr -d ' ') || return 1
    [[ "$bytes" =~ ^[0-9]+$ ]] || return 1
    (( bytes > 0 && bytes <= ABOX_SNI_CANDIDATE_MAX_BYTES )) || return 1
    : > "$output" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        domain="${line,,}"
        [[ ${#domain} -le 253 && "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || return 1
        if [[ -z "${seen[$domain]+x}" ]]; then
            seen["$domain"]=1
            rows=$((rows + 1))
            (( rows <= ABOX_SNI_CANDIDATE_MAX_ROWS )) || return 1
            printf '%s\n' "$domain" >> "$output" || return 1
        fi
    done < "$source"
    (( rows >= ABOX_SNI_CANDIDATE_MIN_ROWS && rows <= ABOX_SNI_CANDIDATE_MAX_ROWS ))
}

sni_store_candidate_cache() {
    local source="${1:-}" cache="${ABOX_DIR}/A-Box-sni-candidates.txt"
    [[ $EUID -eq 0 && -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] || return 1
    [[ -f "$source" && ! -L "$source" ]] || return 1
    path_owned_by_root "$ABOX_DIR" || return 1
    path_mode_has_no_group_other_write "$ABOX_DIR" || return 1
    [[ ! -L "$cache" && ( ! -e "$cache" || -f "$cache" ) ]] || return 1
    path_parent_chain_safe "$cache" || return 1
    install_file_atomically "$source" "$cache" 600 || return 1
    path_owned_by_root "$cache" && path_mode_has_no_group_other_write "$cache"
}

sni_load_candidate_seed() {
    local output="${1:-}" override="${ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE:-}"
    local url="${ABOX_SNI_CANDIDATE_URL:-$ABOX_SNI_CANDIDATE_URL_DEFAULT}"
    local downloaded normalized cache local_seed script_dir download_ok=0
    [[ -n "$output" && -f "$output" && ! -L "$output" ]] || return 1
    downloaded=$(umask 077; mktemp /tmp/A-Box-sni-download.XXXXXX) || return 1
    normalized=$(umask 077; mktemp /tmp/A-Box-sni-normalized.XXXXXX) || { rm -f -- "$downloaded"; return 1; }
    cache="${ABOX_DIR}/A-Box-sni-candidates.txt"

    if [[ -n "$override" ]]; then
        if sni_normalize_candidate_file "$override" "$normalized"; then
            cat -- "$normalized" > "$output" || { rm -f -- "$downloaded" "$normalized"; return 1; }
            rm -f -- "$downloaded" "$normalized"
            return 0
        fi
        rm -f -- "$downloaded" "$normalized"
        return 1
    fi

    # This endpoint is data-only. Never execute downloaded content; accept HTTPS only.
    if [[ "$url" == https://* && "$url" != *$'\n'* && "$url" != *$'\r'* ]]; then
        # curl supports the byte ceiling needed here. Do not fall back to wget:
        # wget has no portable hard output-size cap and would defeat this guard.
        if command -v curl >/dev/null 2>&1 && curl -fLsS --connect-timeout 8 --max-time 35 --max-filesize "$ABOX_SNI_CANDIDATE_MAX_BYTES" "$url" -o "$downloaded" 2>/dev/null; then
            download_ok=1
        fi
    fi
    if (( download_ok == 1 )) && sni_normalize_candidate_file "$downloaded" "$normalized"; then
        if cat -- "$normalized" > "$output"; then
            if [[ $EUID -eq 0 && -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]]; then
                if ! sni_store_candidate_cache "$normalized"; then
                    msg "${YELLOW}[!] SNI 数据已下载并通过格式校验，但无法安全更新本地缓存；本次测试将使用临时校验副本。${NC}"
                fi
            fi
            rm -f -- "$downloaded" "$normalized"
            return 0
        fi
    fi

    # Network failure or invalid data: prefer a previously validated local cache.
    if [[ -f "$cache" && ! -L "$cache" ]] && \
        { [[ $EUID -ne 0 ]] || { path_owned_by_root "$cache" && path_mode_has_no_group_other_write "$cache" && path_parent_chain_safe "$cache"; }; } && \
        sni_normalize_candidate_file "$cache" "$normalized"; then
        cat -- "$normalized" > "$output" || { rm -f -- "$downloaded" "$normalized"; return 1; }
        msg "${YELLOW}[!] SNI 数据下载失败或未通过校验；使用上次通过校验的本地缓存。${NC}"
        rm -f -- "$downloaded" "$normalized"
        return 0
    fi

    # Support a source checkout/zip with data/ beside the script (e.g. first CI run).
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || script_dir=''
    local_seed="${script_dir:+$script_dir/data/sni-candidates.txt}"
    if [[ -n "$local_seed" && -f "$local_seed" && ! -L "$local_seed" ]] && sni_normalize_candidate_file "$local_seed" "$normalized"; then
        cat -- "$normalized" > "$output" || { rm -f -- "$downloaded" "$normalized"; return 1; }
        msg "${YELLOW}[!] SNI 在线数据不可用；使用随脚本提供的本地候选文件。${NC}"
        rm -f -- "$downloaded" "$normalized"
        return 0
    fi
    rm -f -- "$downloaded" "$normalized"
    return 1
}

remove_sni_candidate_cache() {
    local cache="${ABOX_DIR}/A-Box-sni-candidates.txt"
    [[ -e "$cache" || -L "$cache" ]] || return 0
    [[ -f "$cache" && ! -L "$cache" ]] || return 1
    path_owned_by_root "$cache" || return 1
    path_mode_has_no_group_other_write "$cache" || return 1
    path_tree_has_mountpoint "$cache" && return 1
    rm -f -- "$cache" || return 1
    [[ ! -e "$cache" && ! -L "$cache" ]]
}

restore_sni_candidate_cache_snapshot() {
    local backup="${1:-}" existed="${2:-0}" cache="${ABOX_DIR}/A-Box-sni-candidates.txt"
    if [[ "$existed" == '1' ]]; then
        [[ -n "$backup" && -f "$backup" && ! -L "$backup" ]] || return 1
        install_file_atomically "$backup" "$cache" 600 || return 1
        path_owned_by_root "$cache" && path_mode_has_no_group_other_write "$cache"
        return $?
    fi
    [[ ! -e "$cache" && ! -L "$cache" ]] && return 0
    remove_sni_candidate_cache
}

sni_resolve_public_ip() {
    local domain="${1:-}" ip any=0 chosen='' resolved=''
    valid_domain "$domain" || return 1
    resolved=$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | awk '!seen[$0]++') || return 1
    [[ -n "$resolved" ]] || return 1
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        any=1
        valid_public_ip "$ip" || return 1
        [[ -n "$chosen" ]] || chosen="$ip"
    done <<< "$resolved"
    (( any == 1 )) && [[ -n "$chosen" ]] || return 1
    printf '%s\n' "$chosen"
}

write_sni_candidate_library() {
    local profile="${1:-full}" out="$2" raw generated tmp append_tmp out_tmp max_count
    [[ -n "$out" ]] || die 'SNI candidate output path missing.'
    path_parent_chain_safe "$out" || die 'SNI candidate output path is unsafe.'
    [[ ! -L "$out" && ( ! -e "$out" || -f "$out" ) ]] || die 'SNI candidate output target is unsafe.'
    raw=$(umask 077; mktemp /tmp/A-Box-sni-lib.XXXXXX) || die 'SNI library temporary file creation failed.'
    generated=$(umask 077; mktemp /tmp/A-Box-sni-lib-generated.XXXXXX) || { rm -f "$raw"; die 'SNI generated library temporary file creation failed.'; }
    tmp=$(umask 077; mktemp /tmp/A-Box-sni-lib-filtered.XXXXXX) || { rm -f "$raw" "$generated"; die 'SNI library filtered temporary file creation failed.'; }

    sni_load_candidate_seed "$raw" || { rm -f -- "$raw" "$generated" "$tmp"; die 'SNI candidate data is unavailable or failed validation; upload data/sni-candidates.txt or restore the validated cache.'; }


    # Generate conservative subdomain variants for strong apexes. Invalid/nonexistent hosts are filtered by TLS probing.
    awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$raw" | \
        sed -E 's#^https?://##; s#/.*$##; s/:443$//; s/[[:space:]]//g' | \
        grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' | \
        awk '!seen[$0]++' > "$generated"

    append_tmp=$(umask 077; mktemp /tmp/A-Box-sni-lib-append.XXXXXX) || { rm -f "$raw" "$generated" "$tmp"; die 'SNI candidate append temporary file creation failed.'; }
    if ! awk -F. 'NF>=2 {
        base=$(NF-1); apex=base "." $NF
        if (base ~ /^(github|cloudflare|microsoft|google|apache|mozilla|docker|kubernetes|linuxfoundation|cncf|python|rust-lang|golang|go|oracle|ibm|redhat|ubuntu|debian|nginx|postgresql|mongodb|elastic|hashicorp|terraform|confluent|fastly|akamai|digitalocean|linode|vultr|hetzner|ovhcloud|scaleway|openai|anthropic|huggingface|pytorch|tensorflow|ietf|w3|rfc-editor|openssl|curl|gnu|kernel|freebsd|openbsd|netbsd|eclipse|jetbrains|npmjs|nodejs|typescriptlang|redis|sqlite|mysql|wikimedia|wikipedia|archive|stackoverflow|stackexchange|nasa|nist|cisa|stanford|mit|berkeley|cambridge|ox|ethz|epfl|unimelb|sydney|unsw|monash|auckland|cloudfront|amazonaws)$/) print apex
    }' "$generated" | awk '!seen[$0]++' | while IFS= read -r apex; do
        for p in www docs doc developer developers api status support blog cdn static assets download downloads registry repo packages pkg files raw resources community help learn training security; do
            printf '%s.%s\n' "$p" "$apex"
        done
        printf '%s\n' "$apex"
    done > "$append_tmp"; then
        rm -f "$raw" "$generated" "$tmp" "$append_tmp"
        die 'SNI candidate variant generation failed.'
    fi
    cat "$append_tmp" >> "$generated" || { rm -f "$raw" "$generated" "$tmp" "$append_tmp"; die 'SNI candidate merge failed.'; }
    rm -f "$append_tmp"

    if ! awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$generated" | \
        sed -E 's#^https?://##; s#/.*$##; s/:443$//; s/[[:space:]]//g' | \
        grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' | \
        grep -Ev '(^|\.)(doubleclick|googlesyndication|googleadservices|facebook|tiktok|tracking|track|ads|analytics|telemetry)\.' | \
        awk '!seen[$0]++' > "$tmp"; then
        rm -f "$raw" "$generated" "$tmp" "$append_tmp"
        die 'SNI candidate filtering failed.'
    fi
    [[ -s "$tmp" ]] || { rm -f "$raw" "$generated" "$tmp" "$append_tmp"; die 'SNI candidate filtering produced an empty library.'; }

    if [[ "$profile" == 'mini' ]]; then
        max_count="${ABOX_SNI_MINI_MAX:-$ABOX_SNI_DEFAULT_MAX}"
    else
        max_count="${ABOX_SNI_FULL_MAX:-$ABOX_SNI_DEFAULT_MAX}"
    fi
    if ! [[ "$max_count" =~ ^[0-9]+$ ]]; then
        max_count="$ABOX_SNI_DEFAULT_MAX"
    fi
    if (( max_count == 0 )); then
        max_count="$ABOX_SNI_HARD_MAX"
    elif (( max_count > ABOX_SNI_HARD_MAX )); then
        max_count="$ABOX_SNI_HARD_MAX"
    fi
    out_tmp=$(mktemp "${out}.A-Box-new.XXXXXX") || { rm -f "$raw" "$generated" "$tmp"; die 'SNI candidate output temporary file creation failed.'; }
    if ! awk -v n="$max_count" 'NR<=n {print}' "$tmp" > "$out_tmp"; then
        rm -f "$raw" "$generated" "$tmp" "$out_tmp"
        die 'SNI candidate output generation failed.'
    fi
    [[ -s "$out_tmp" ]] || { rm -f "$raw" "$generated" "$tmp" "$out_tmp"; die 'SNI candidate output is empty.'; }
    chmod 600 "$out_tmp" || { rm -f "$raw" "$generated" "$tmp" "$out_tmp"; die 'SNI candidate output permissions failed.'; }
    [[ $EUID -eq 0 ]] && chown root:root "$out_tmp" || true
    mv -f -- "$out_tmp" "$out" || { rm -f "$raw" "$generated" "$tmp" "$out_tmp"; die 'SNI candidate atomic commit failed.'; }
    rm -f "$raw" "$generated" "$tmp"
}

sni_domain_penalty() {
    local domain="${1,,}" penalty=0
    case "$domain" in
        www.apple.com|www.icloud.com) penalty=$((penalty + 1800)) ;;
        www.nike.com|www.adidas.com|www.amazon.com|www.google.com|www.youtube.com|www.netflix.com) penalty=$((penalty + 500)) ;;
        *.google.com|*.gstatic.com|*.googleapis.com|*.youtube.com|*.facebook.com|*.instagram.com|*.twitter.com|*.x.com|*.tiktok.com|*.telegram.org|*.whatsapp.com|*.wikipedia.org|*.wikimedia.org|*.openai.com|*.anthropic.com|*.huggingface.co|*.torproject.org|*.nist.gov|*.cisa.gov|*.github.com|*.apple.com|*.icloud.com|apple.com|icloud.com|github.com|*.doubleclick.net|*.googlesyndication.com|*.googleadservices.com) penalty=$((penalty + 2400)) ;;
    esac
    case "$domain" in
        *.microsoft.com|*.bing.com|*.apache.org|*.ietf.org|*.rfc-editor.org|*.w3.org|*.unicode.org|*.icann.org|*.iana.org|*.iso.org|*.itu.int|*.nginx.org|*.openssl.org|*.curl.se|*.kernel.org|*.debian.org|*.ubuntu.com|*.linuxfoundation.org|*.cncf.io|*.cloudflare.com|*.akamai.com|*.fastly.com) penalty=$((penalty - 220)) ;;
        docs.*|developer.*|developers.*|learn.*|support.*|download.*|downloads.*|packages.*|repo.*|registry.*|resources.*|community.*|help.*|security.*|*.mozilla.org|*.confluent.io|*.python.org|*.rust-lang.org|*.nodejs.org|*.postgresql.org|*.sqlite.org|*.eclipse.org|*.gnu.org|*.git-scm.com|*.cmake.org|*.llvm.org|*.mariadb.org|*.mysql.com) penalty=$((penalty - 120)) ;;
        *.samsung.com|*.lenovo.com|*.dell.com|*.intel.com|*.amd.com|*.nvidia.com|*.cisco.com|*.huawei.com|*.ericsson.com|*.nokia.com|*.siemens.com|*.un.org|*.who.int|*.unesco.org|*.cern.ch|*.esa.int|*.mit.edu|*.stanford.edu|*.berkeley.edu|*.cam.ac.uk|*.ox.ac.uk|*.ethz.ch|*.epfl.ch|*.crossref.org|*.orcid.org|*.openstreetmap.org) penalty=$((penalty - 60)) ;;
    esac
    printf '%s\n' "$penalty"
}

asn_lookup_ip() {
    local ip="${1:-}" cache_dir="${2:-}" cache_file body asn country org uid gid mode http_code
    [[ -n "$ip" && "$ip" != 'N/A' ]] || { printf 'asn=unknown\tcountry=unknown\torg=unknown'; return 0; }
    [[ -n "$cache_dir" && -d "$cache_dir" && ! -L "$cache_dir" ]] || return 1
    uid=$(stat -c %u "$cache_dir" 2>/dev/null) || return 1
    gid=$(stat -c %g "$cache_dir" 2>/dev/null) || return 1
    mode=$(stat -c %a "$cache_dir" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^0700$ ]] || return 1
    # Global short-circuit after ipinfo.io rate-limit (429) for this SNI run.
    if [[ -f "$cache_dir/.rate_limited" ]]; then
        printf 'asn=unknown\tcountry=unknown\torg=unknown'
        return 0
    fi
    cache_file="$cache_dir/$(printf '%s' "$ip" | tr -c 'A-Za-z0-9_.:-' '_')"
    if [[ -s "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi
    body=$(curl -sS -w $'\n%{http_code}' --connect-timeout 2 -m 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)
    http_code=${body##*$'\n'}
    body=${body%$'\n'*}
    if [[ "$http_code" == '429' ]]; then
        : > "$cache_dir/.rate_limited" 2>/dev/null || true
        printf 'asn=unknown\tcountry=unknown\torg=unknown'
        return 0
    fi
    if [[ "$http_code" == '200' && -n "$body" ]] && command -v jq >/dev/null 2>&1; then
        org=$(jq -r '.org // "unknown"' <<< "$body" 2>/dev/null | tr '\t\n\r' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
        country=$(jq -r '.country // "unknown"' <<< "$body" 2>/dev/null | tr '\t\n\r' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
        asn=$(sed -nE 's/^(AS[0-9]+).*/\1/p' <<< "$org")
    fi
    [[ -n "$asn" ]] || asn='unknown'
    [[ -n "$country" ]] || country='unknown'
    [[ -n "$org" ]] || org='unknown'
    printf 'asn=%s\tcountry=%s\torg=%s' "$asn" "$country" "$org" | tee "$cache_file" 2>/dev/null || true
}


sni_org_cdn_penalty() {
    local domain="${1,,}" org="${2,,}" penalty=0
    # This is a risk label, not a site-quality bonus. Do not cancel CDN risk
    # with a negative preference for a familiar brand/domain.
    case "$org $domain" in
        *cloudflare*|*cloudfront*|*fastly*|*akamai*|*edgecast*|*stackpath*|*bunny*|*cdn77*) penalty=500 ;;
        *google*|*facebook*|*meta*|*telegram*|*twitter*|*openai*|*anthropic*|*huggingface*|*apple*|*icloud*) penalty=1000 ;;
        *amazon*|*aws*) penalty=220 ;;
        *microsoft*|*verizon*) penalty=180 ;;
    esac
    printf '%s\n' "$penalty"
}

sni_domain_public_dns() {
    sni_resolve_public_ip "${1:-}" >/dev/null
}

sni_raw_score() {
    local app="$1" start="$2" total="$3" penalty="$4"
    # Preserve signed scores. Clamping negative values to 0 made many preferred
    # domains tie at zero and then appear alphabetically instead of by score.
    awk -v app="$app" -v start="$start" -v total="$total" -v p="$penalty" \
        'BEGIN { printf "%d\n", int(app*1000 + start*220 + total*60 + p) }'
}

sni_adjust_score() {
    local score="$1" adjustment="$2"
    # Lower is better; keep ASN/country/CDN adjustments signed and sortable.
    awk -v s="$score" -v a="$adjustment" \
        'BEGIN { printf "%d\n", int(s) + int(a) }'
}

sni_probe_domain() {
    local domain="$1" raw="$2" timeout_s="${3:-6}" metrics code _t_connect t_app t_start t_total http_version remote_ip penalty score target_ip resolve_entry curl_args=()
    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || return 0
    # Resolve once, reject non-public answers, and pin curl to the accepted IP.
    # This avoids mixing validation for one address with a request to another.
    target_ip=$(sni_resolve_public_ip "$domain") || return 0
    if [[ "$target_ip" == *:* ]]; then resolve_entry="${domain}:443:[${target_ip}]"; else resolve_entry="${domain}:443:${target_ip}"; fi
    if [[ "${ABOX_CURL_TLS13_SUPPORTED:-0}" == '1' ]]; then curl_args+=(--tlsv1.3); fi
    if [[ "${ABOX_CURL_HTTP2_SUPPORTED:-0}" == '1' ]]; then curl_args+=(--http2); fi
    metrics=$(curl --noproxy '*' --resolve "$resolve_entry" -sSI "${curl_args[@]}" \
        --connect-timeout "$timeout_s" --max-time "$((timeout_s + 4))" \
        -o /dev/null \
        -w '%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{http_version}\t%{remote_ip}' \
        "https://${domain}/" 2>/dev/null) || return 0
    IFS=$'\t' read -r code _t_connect t_app t_start t_total http_version remote_ip <<< "$metrics"
    [[ "$remote_ip" == "$target_ip" ]] || return 0
    [[ "$t_app" =~ ^[0-9.]+$ ]] || return 0
    awk -v v="$t_app" 'BEGIN{exit !(v>0)}' || return 0
    penalty=$(sni_domain_penalty "$domain")
    [[ "$http_version" == '2' || "$http_version" == '3' ]] || penalty=$((penalty + 350))
    [[ "$code" =~ ^(2|3|4)[0-9][0-9]$ ]] || penalty=$((penalty + 120))
    score=$(sni_raw_score "$t_app" "$t_start" "$t_total" "$penalty")
    printf '%s\t%s\tapp=%ss\tttfb=%ss\ttotal=%ss\thttp=%s\tcode=%s\tip=%s\n' "$score" "$domain" "$t_app" "$t_start" "$t_total" "$http_version" "$code" "$remote_ip" >> "$raw"
}

sni_san_matches_domain() {
    local domain="${1,,}" sanext="${2:-}" name suffix rest
    valid_domain "$domain" || return 1
    # Parse DNS SAN names as values, not as a regular expression assembled
    # from user-controlled domain text. Wildcards match exactly one label.
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        name="${name,,}"
        [[ "$name" == "$domain" ]] && return 0
        case "$name" in
            \*.*)
                suffix="${name#*.}"
                [[ "$domain" == *.* ]] || continue
                rest="${domain#*.}"
                [[ "$rest" == "$suffix" ]] && return 0
                ;;
        esac
    done < <(printf '%s\n' "$sanext" | awk '{ while (match($0, /DNS:[^,[:space:]]+/)) { item=substr($0,RSTART,RLENGTH); sub(/^DNS:/,"",item); print item; $0=substr($0,RSTART+RLENGTH) } }')
    return 1
}

sni_openssl_check() {
    local domain="$1" timeout_s="${2:-5}" target_ip="${3:-}" connect_target out cert sanext alpn='none' tls13=0 san=0
    command -v openssl >/dev/null 2>&1 || { printf 'tls13=unknown\talpn=unknown\tsan=unknown'; return 0; }
    valid_public_ip "$target_ip" || { printf 'tls13=0\talpn=none\tsan=0'; return 0; }
    if [[ "$target_ip" == *:* ]]; then connect_target="[${target_ip}]:443"; else connect_target="${target_ip}:443"; fi
    out=$(printf '' | timeout "$timeout_s" openssl s_client -connect "$connect_target" -servername "$domain" -alpn 'h2,http/1.1' -tls1_3 -showcerts 2>/dev/null | tr -d '\000') || out=''
    if [[ -n "$out" ]]; then
        grep -qiE 'Protocol *: *TLSv1\.3|New, TLSv1\.3' <<< "$out" && tls13=1
        alpn=$(awk -F': ' '/ALPN protocol/{print $2; exit}' <<< "$out")
        [[ -n "$alpn" ]] || alpn='none'
        cert=$(awk 'BEGIN{p=0}/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}' <<< "$out")
        if [[ -n "$cert" ]]; then
            sanext=$(printf '%s\n' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
            sni_san_matches_domain "$domain" "$sanext" && san=1
        fi
    fi
    printf 'tls13=%s\talpn=%s\tsan=%s' "$tls13" "$alpn" "$san"
}

sni_verify_raw_report() {
    local raw_sorted="$1" verified="$2" verify_limit="${3:-240}" timeout_s="${4:-5}" line score domain c3 c4 c5 c6 c7 c8 check tls13 alpn san add adj n=0
    local asn_cache vps_ip vps_meta vps_asn vps_country target_ip target_meta target_asn target_country target_org asn_match same_country cdn_penalty progress_every=20
    : > "$verified"
    asn_cache=$(mktemp -d /tmp/A-Box-asn-cache.XXXXXX) || die 'SNI ASN cache directory creation failed; refusing to use a shared temporary directory.'
    vps_ip=$(get_public_ip 2>/dev/null || true)
    vps_meta=$(asn_lookup_ip "$vps_ip" "$asn_cache")
    vps_asn=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="asn"){print $(i+1); exit}}' <<< "$vps_meta")
    vps_country=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="country"){print $(i+1); exit}}' <<< "$vps_meta")
    [[ -n "$vps_asn" ]] || vps_asn='unknown'
    [[ -n "$vps_country" ]] || vps_country='unknown'
    msg "${YELLOW}[*] Stage 2: OpenSSL verification + ASN/topology scoring. VPS ${vps_ip:-N/A} ${vps_asn}/${vps_country}${NC}"
    while IFS=$'\t' read -r score domain c3 c4 c5 c6 c7 c8; do
        n=$((n + 1))
        (( n > verify_limit )) && break
        if (( n == 1 || n % progress_every == 0 )); then
            printf '\r[*] Stage 2 progress: %d/%d verified' "$n" "$verify_limit" >&2
        fi
        # Extract and validate the stage-1 connected IP before stage-2 TLS.
        # Do not perform a second DNS lookup or invoke OpenSSL with an unset IP.
        target_ip="${c8#ip=}"
        if valid_public_ip "$target_ip"; then
            check=$(sni_openssl_check "$domain" "$timeout_s" "$target_ip")
            tls13=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="tls13"){print $(i+1); exit}}' <<< "$check")
            alpn=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="alpn"){print $(i+1); exit}}' <<< "$check")
            san=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="san"){print $(i+1); exit}}' <<< "$check")
        else
            target_ip='N/A'
            check=$'tls13=0\talpn=none\tsan=0'
            tls13=0
            alpn='none'
            san=0
        fi
        target_meta=$(asn_lookup_ip "$target_ip" "$asn_cache")
        target_asn=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="asn"){print $(i+1); exit}}' <<< "$target_meta")
        target_country=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="country"){print $(i+1); exit}}' <<< "$target_meta")
        target_org=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="org"){print $(i+1); exit}}' <<< "$target_meta")
        [[ -n "$target_asn" ]] || target_asn='unknown'
        [[ -n "$target_country" ]] || target_country='unknown'
        [[ -n "$target_org" ]] || target_org='unknown'
        asn_match=0
        same_country=0
        [[ "$vps_asn" != 'unknown' && "$target_asn" == "$vps_asn" ]] && asn_match=1
        [[ "$vps_country" != 'unknown' && "$target_country" == "$vps_country" ]] && same_country=1
        add=0
        [[ "$tls13" == '1' ]] || add=$((add + 6000))
        [[ "$san" == '1' ]] || add=$((add + 6000))
        [[ "$alpn" == 'h2' ]] || add=$((add + 700))
        cdn_penalty=$(sni_org_cdn_penalty "$domain" "$target_org")
        add=$((add + cdn_penalty))
        [[ "$same_country" == '1' ]] && add=$((add - 250))
        # Strongly prefer a tested target in the VPS's own ASN, but never let
        # topology override hard TLS/SAN checks or erase explicit CDN risk.
        [[ "$asn_match" == '1' ]] && add=$((add - 1500))
        adj=$(sni_adjust_score "$score" "$add")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tasn=%s\tcountry=%s\tasnmatch=%s\tsamecountry=%s\torg=%s\tcdnpenalty=%s\n' \
            "$adj" "$domain" "$c3" "$c4" "$c5" "$c6" "$c7" "$c8" "$check" "$target_asn" "$target_country" "$asn_match" "$same_country" "$target_org" "$cdn_penalty" >> "$verified"
    done < "$raw_sorted"
    printf '\r[*] Stage 2 progress: %d/%d verified\n' "$(( n > verify_limit ? verify_limit : n ))" "$verify_limit" >&2
    LC_ALL=C sort -t $'\t' -k1,1n -k2,2 "$verified" -o "$verified"
    rm -rf "$asn_cache" 2>/dev/null || true
}

sni_report_fit_tier() {
    local tls13="${1#tls13=}" alpn="${2#alpn=}" san="${3#san=}" \
        asn_match="${4#asnmatch=}" same_country="${5#samecountry=}" \
        cdn_penalty="${6#cdnpenalty=}"
    [[ "$cdn_penalty" =~ ^-?[0-9]+$ ]] || cdn_penalty=0
    if [[ "$tls13" != '1' || "$alpn" != 'h2' || "$san" != '1' ]]; then
        printf 'D\n'
    elif (( cdn_penalty >= 300 )); then
        # Keep risky targets visible for analysis, but do not label them a safe fit.
        printf 'R\n'
    elif [[ "$asn_match" == '1' ]]; then
        printf 'A\n'
    elif [[ "$same_country" == '1' ]]; then
        printf 'B\n'
    else
        printf 'C\n'
    fi
}

sni_render_ranked_report() {
    local report_file="${1:-}" requested_limit="${2:-100}" display_dir selected_file
    local row score domain app ttfb total http code ip tls13 alpn san asn country asnmatch samecountry org cdnpenalty tier
    local bucket count color heading rank local_bucket_file
    [[ -s "$report_file" ]] || { msg "${YELLOW}[!] 没有可显示的 SNI 测试记录。${NC}"; return 1; }
    valid_decimal_upto "$requested_limit" 200 || requested_limit=100
    (( 10#$requested_limit >= 1 )) || requested_limit=100
    display_dir=$(mktemp -d /tmp/A-Box-sni-display.XXXXXX) || return 1
    selected_file="$display_dir/selected.tsv"
    head -n "$requested_limit" "$report_file" > "$selected_file" || { rm -rf -- "$display_dir"; return 1; }
    for bucket in A R B C D; do : > "$display_dir/$bucket.tsv"; done
    while IFS= read -r row; do
        IFS=$'\t' read -r score domain app ttfb total http code ip tls13 alpn san asn country asnmatch samecountry org cdnpenalty <<< "$row"
        [[ "$score" =~ ^-?[0-9]+$ && -n "$domain" ]] || continue
        tier=$(sni_report_fit_tier "$tls13" "$alpn" "$san" "$asnmatch" "$samecountry" "$cdnpenalty")
        printf '%s\n' "$row" >> "$display_dir/$tier.tsv"
    done < "$selected_file"
    msg "${CYAN}显示前 ${requested_limit} 条已完成二阶段验证的结果（完整记录保存在 TSV 中）。${NC}"
    for bucket in A R B C D; do
        local_bucket_file="$display_dir/$bucket.tsv"
        count=$(wc -l < "$local_bucket_file" | tr -d ' ')
        (( count > 0 )) || continue
        case "$bucket" in
            A) color="$GREEN"; heading="A级优先｜TLS1.3+H2+SAN合格、同ASN、风险分较低" ;;
            R) color="$YELLOW"; heading="风险复核｜协议检查通过，但CDN/网络风险分较高；同ASN信息仍会显示" ;;
            B) color="$CYAN"; heading="B级良好｜协议检查通过、同国家/地区、风险分较低" ;;
            C) color="$BLUE"; heading="C级可用候选｜协议检查通过，但未匹配同ASN/同地区" ;;
            D) color="$RED"; heading="不合格/需复测｜TLS1.3、ALPN h2或SAN至少一项未通过" ;;
        esac
        msg "${color}[${heading}｜${count} 条]${NC}"
        rank=0
        while IFS= read -r row; do
            IFS=$'\t' read -r score domain app ttfb total http code ip tls13 alpn san asn country asnmatch samecountry org cdnpenalty <<< "$row"
            rank=$((rank + 1))
            printf '%s%3d. [score=%s] %-38s app=%-10s ttfb=%-10s total=%-10s HTTP/%s code=%s %s %s %s ASN=%s country=%s sameASN=%s sameRegion=%s cdnRisk=%s IP=%s%s\n' \
                "$color" "$rank" "$score" "$domain" "${app#app=}" "${ttfb#ttfb=}" "${total#total=}" \
                "${http#http=}" "${code#code=}" "$tls13" "$alpn" "$san" "${asn#asn=}" \
                "${country#country=}" "${asnmatch#asnmatch=}" "${samecountry#samecountry=}" \
                "${cdnpenalty#cdnpenalty=}" "${ip#ip=}" "$NC"
        done < "$local_bucket_file"
    done
    rm -rf -- "$display_dir"
    return 0
}

run_builtin_sni_radar() {
    local profile="${1:-full}" title="${2:-Local SNI preference}" workdir candidates raw raw_sorted report total concurrency timeout_s running=0 domain topn verify_limit processed=0 valid_count=0 progress_every
    workdir=$(mktemp -d /tmp/A-Box-sni-radar.XXXXXX) || die 'SNI radar temporary directory creation failed.'
    candidates="$workdir/candidates.txt"
    raw="$workdir/results.raw.tsv"
    raw_sorted="$workdir/results.raw.sorted.tsv"
    report="$workdir/results.tsv"
    write_sni_candidate_library "$profile" "$candidates"
    if curl --help all 2>/dev/null | grep -F -- '--tlsv1.3' >/dev/null; then
        ABOX_CURL_TLS13_SUPPORTED=1
    else
        ABOX_CURL_TLS13_SUPPORTED=0
    fi
    if curl --help all 2>/dev/null | grep -F -- '--http2' >/dev/null; then
        ABOX_CURL_HTTP2_SUPPORTED=1
    else
        ABOX_CURL_HTTP2_SUPPORTED=0
    fi
    total=$(wc -l < "$candidates" | tr -d ' ')
    if [[ "$profile" == 'mini' ]]; then
        # Mini mode uses the same candidate library as full mode. It reduces concurrency and verification depth only.
        concurrency="${ABOX_SNI_MINI_CONCURRENCY:-8}"
        timeout_s="${ABOX_SNI_MINI_TIMEOUT:-5}"
        topn="${ABOX_SNI_MINI_TOPN:-60}"
        verify_limit="${ABOX_SNI_MINI_VERIFY:-240}"
    else
        concurrency="${ABOX_SNI_FULL_CONCURRENCY:-36}"
        timeout_s="${ABOX_SNI_FULL_TIMEOUT:-6}"
        topn="${ABOX_SNI_FULL_TOPN:-100}"
        verify_limit="${ABOX_SNI_FULL_VERIFY:-120}"
    fi
    valid_decimal_upto "$concurrency" 256 || die 'SNI concurrency must be an integer in 1..256.'
    (( 10#$concurrency >= 1 )) || die 'SNI concurrency must be >= 1.'
    valid_decimal_upto "$timeout_s" 60 || die 'SNI timeout must be an integer in 1..60 seconds.'
    (( 10#$timeout_s >= 1 )) || die 'SNI timeout must be >= 1 second.'
    valid_decimal_upto "$verify_limit" 2048 || die 'SNI verify limit must be an integer in 1..2048.'
    (( 10#$verify_limit >= 1 )) || die 'SNI verify limit must be >= 1.'
    valid_decimal_upto "$topn" 200 || die 'SNI display count must be an integer in 1..200.'
    (( 10#$topn >= 1 )) || die 'SNI display count must be >= 1.'
    progress_every=$(( concurrency * 2 ))
    (( progress_every < 20 )) && progress_every=20
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}${title}${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}[*] Candidate library: ${total} domains | profile=${profile} | concurrency=${concurrency} | deep-check=${verify_limit} | display=${topn}${NC}"
    msg "${YELLOW}[*] Stage 1: HTTPS/TLSv1.3 curl metrics. Stage 2: OpenSSL TLS1.3 + ALPN + SAN + ASN/topology scoring.${NC}"
    msg "${YELLOW}[*] Same-ASN bonus is applied after mandatory TLS/SAN evaluation; high CDN-risk candidates are separated for review.${NC}"
    msg "${YELLOW}[*] Fully internal SNI library; no legacy remote SNI scripts or gist extraction are used.${NC}"
    msg "${YELLOW}[*] Progress is printed after each batch; large libraries can take several minutes on low-end VPS.${NC}"
    : > "$raw"
    while IFS= read -r domain; do
        sni_probe_domain "$domain" "$raw" "$timeout_s" &
        running=$((running + 1))
        processed=$((processed + 1))
        if (( running >= concurrency )); then
            wait
            running=0
            valid_count=$(wc -l < "$raw" 2>/dev/null | tr -d ' ')
            printf '\r[*] Stage 1 progress: %d/%d tested | valid=%s' "$processed" "$total" "${valid_count:-0}" >&2
        elif (( processed % progress_every == 0 )); then
            valid_count=$(wc -l < "$raw" 2>/dev/null | tr -d ' ')
            printf '\r[*] Stage 1 progress: %d/%d queued | valid=%s' "$processed" "$total" "${valid_count:-0}" >&2
        fi
    done < "$candidates"
    wait
    valid_count=$(wc -l < "$raw" 2>/dev/null | tr -d ' ')
    printf '\r[*] Stage 1 progress: %d/%d tested | valid=%s\n' "$processed" "$total" "${valid_count:-0}" >&2
    if [[ ! -s "$raw" ]]; then
        rm -rf "$workdir"
        die 'SNI radar produced no valid HTTPS/TLS results. Check DNS, routing, firewall, curl/OpenSSL support.'
    fi
    LC_ALL=C sort -t $'\t' -k1,1n -k2,2 "$raw" > "$raw_sorted"
    sni_verify_raw_report "$raw_sorted" "$report" "$verify_limit" "$timeout_s"
    if [[ ! -s "$report" ]]; then
        cp -f "$raw_sorted" "$report"
    fi
    ensure_abox_dir_owned "$ABOX_DIR" || die 'SNI record directory is not a trusted A-Box directory; refusing to report a false Saved state.'
    local saved_report="$ABOX_DIR/A-Box-sni-${profile}.tsv"
    install_file_atomically "$report" "$saved_report" 600 || die 'SNI record persistence failed.'
    [[ -s "$saved_report" && ! -L "$saved_report" ]] || die 'SNI record persistence verification failed.'
    path_owned_by_root "$saved_report" || die 'SNI record ownership verification failed.'
    path_mode_has_no_group_other_write "$saved_report" || die 'SNI record permission verification failed.'
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}[ Top SNI Candidates / 优选 SNI 候选 ]${NC}"
    sni_render_ranked_report "$report" "$topn" || msg "${YELLOW}[!] 结果分级显示失败；完整 TSV 仍已保存。${NC}"
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${GREEN}Saved: ${ABOX_DIR}/A-Box-sni-${profile}.tsv${NC}"
    msg "${YELLOW}A/B/C 等级仅表示本 VPS 的探测结果；风险复核和不合格项目不会因低延迟被标为优先推荐。${NC}"
    rm -rf "$workdir"
}

show_sni_preference_records() {
    clear
    local files=() f profile topn="${ABOX_SNI_RECORDS_TOPN:-100}" shown=0 mtime
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${BOLD}${GREEN}SNI Preference Records${NC}"
    else
        msg "${BOLD}${GREEN}SNI 优选记录${NC}"
    fi
    valid_decimal_upto "$topn" 200 || topn=100
    (( 10#$topn >= 1 )) || topn=100
    msg "${CYAN}======================================================================${NC}"
    for f in "$ABOX_DIR/A-Box-sni-full.tsv" "$ABOX_DIR/A-Box-sni-mini.tsv"; do
        [[ -s "$f" ]] && files+=("$f")
    done
    if (( ${#files[@]} == 0 )); then
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            msg "${YELLOW}[!] No SNI preference record found. Run Toolbox option 3 or 4 first.${NC}"
        else
            msg "${YELLOW}[!] 未发现 SNI 优选记录。请先运行工具箱 3 或 4。${NC}"
        fi
        pause_return
        return 0
    fi
    for f in "${files[@]}"; do
        profile="${f##*/A-Box-sni-}"
        profile="${profile%.tsv}"
        mtime=$(date -r "$f" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo 'unknown')
        msg "${BLUE}----------------------------------------------------------------------${NC}"
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            msg "${YELLOW}[${profile}] Saved: ${f} | Updated: ${mtime}${NC}"
        else
            msg "${YELLOW}[${profile}] 保存路径: ${f} | 更新时间: ${mtime}${NC}"
        fi
        sni_render_ranked_report "$f" "$topn" || msg "${YELLOW}[!] 无法读取该记录的分级结果。${NC}"
        shown=1
    done
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    if [[ "$shown" == '1' ]]; then
        msg "${YELLOW}Use only domains with tls13=1 and san=1. Prefer asnmatch=1/samecountry=1 when available.${NC}"
    fi
    pause_return
}

run_local_sni_benchmark() {
    if confirm_yes_no "$(tr_msg confirm_local_sni_full)"; then
        run_builtin_sni_radar 'full' 'Local SNI preference / 本地 SNI 优选'
    fi
    pause_return
}

run_local_sni_mini_benchmark() {
    if confirm_yes_no "$(tr_msg confirm_local_sni_mini)"; then
        run_builtin_sni_radar 'mini' 'Mini host local SNI preference / 微型主机本地 SNI 优选'
    fi
    pause_return
}



run_warp_manager() {
    if confirm_yes_no "$(tprintf confirm_remote 'fscarmen/warp Cloudflare WARP menu')"; then
        run_remote_bash_script 'fscarmen/warp Cloudflare WARP menu' 'https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh'
    fi
    pause_return
}

swapfile_active_state() {
    # Return 0=active, 1=definitely inactive, 2=query failure.
    # A query failure must never be interpreted as inactivity before a
    # destructive swapfile operation.
    local output='' line
    if ! output=$(swapon --show=NAME --noheadings 2>/dev/null); then
        return 2
    fi
    while IFS= read -r line; do
        [[ "$line" == '/swapfile' ]] && return 0
    done <<< "$output"
    return 1
}

rollback_new_swap_activation_only() {
    # Used only before /etc/fstab has been modified. Never edits /etc/fstab.
    # This makes early setup failures independent of the generic rollback path,
    # which may remove A-Box swap entries from fstab.
    swapfile_active_state
    case $? in
        0) swapoff /swapfile >/dev/null 2>&1 || return 1 ;;
        1) ;;
        *) return 1 ;;
    esac
    if [[ -e /swapfile || -L /swapfile ]]; then
        rm -f -- /swapfile || return 1
    fi
    [[ ! -e /swapfile && ! -L /swapfile ]]
}

rollback_abox_new_swap() {
    local fstab_backup="${1:-}" rollback_tmp=''
    if [[ -n "$fstab_backup" && -f "$fstab_backup" && ! -L "$fstab_backup" ]]; then
        if ! cp -a "$fstab_backup" /etc/fstab; then
            msg "${RED}[!] Swap 回滚无法恢复 /etc/fstab；保留现状以避免制造更严重的不一致。${NC}" >&2
            return 1
        fi
    else
        rollback_tmp=$(mktemp /etc/.fstab.A-Box-swap-rollback.XXXXXX) || return 1
        if ! awk '
          $0 == "# A-Box swap BEGIN" {
            if (skip) { print "A-Box swap: nested BEGIN" > "/dev/stderr"; exit 2 }
            skip=1; begin_seen=1; next
          }
          $0 == "# A-Box swap END" {
            if (!skip) { print "A-Box swap: END without BEGIN" > "/dev/stderr"; exit 2 }
            skip=0; end_seen=1; next
          }
          skip {next}
          {print}
          END {
            if (skip || (begin_seen && !end_seen) || (!begin_seen && end_seen)) {
              print "A-Box swap: unbalanced BEGIN/END markers; refusing to rewrite /etc/fstab" > "/dev/stderr"
              exit 2
            }
          }
        ' /etc/fstab > "$rollback_tmp"; then
            rm -f "$rollback_tmp"
            return 1
        fi
        chmod --reference=/etc/fstab "$rollback_tmp" 2>/dev/null || chmod 644 "$rollback_tmp"
        chown --reference=/etc/fstab "$rollback_tmp" 2>/dev/null || true
        mv -f "$rollback_tmp" /etc/fstab || { rm -f "$rollback_tmp"; return 1; }
    fi
    swapfile_active_state
    case $? in
        0) swapoff /swapfile >/dev/null 2>&1 || return 1 ;;
        1) ;;
        *) return 1 ;;
    esac
    rm -f /swapfile "$ABOX_DIR/.swapfile.managed"
    [[ ! -e /swapfile && ! -e "$ABOX_DIR/.swapfile.managed" ]]
}

fstab_path_is_safe() {
    [[ -f /etc/fstab && ! -L /etc/fstab ]] || return 1
    path_owned_by_root /etc/fstab || return 1
    path_mode_has_no_group_other_write /etc/fstab || return 1
}

setup_swap_2g() {
    local fstab_tmp='' fstab_backup='' free_kib=0 created_by_abox=0
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Swap 虚拟内存一键划拨 / Allocate 2G Swap${NC}"
    msg "${CYAN}======================================================================${NC}"
    fstab_path_is_safe || die '/etc/fstab 必须是 root 所有且不可被组/其他用户写入的普通文件，拒绝继续写入。'
    [[ ! -L /swapfile ]] || die '拒绝使用符号链接 /swapfile。'
    if [[ -e /swapfile && ! -f /swapfile ]]; then die '/swapfile 已存在但不是普通文件。'; fi
    if [[ -f /swapfile ]]; then
        [[ "$(stat -c %u:%g /swapfile 2>/dev/null || echo -1:-1)" == 0:0 ]] || die '/swapfile 不是 root:root 所有。'
        [[ "$(stat -c %a /swapfile 2>/dev/null || echo 999)" =~ ^0?600$ ]] || die '/swapfile 已存在但权限不是 0600；A-Box 不会修改非托管 Swap 文件，请先手动收紧权限。'
        msg "${YELLOW}$(tr_msg swap_exists)${NC}"
    else
        free_kib=$(df -Pk / | awk 'NR==2{print $4}')
        [[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -ge 2300000 ]] || die "根文件系统剩余空间不足 2G Swap 安全创建阈值。当前=${free_kib:-unknown}KiB。"
        if ! fallocate -l 2G /swapfile 2>/dev/null; then
            rm -f /swapfile
            dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress || { rm -f /swapfile; die 'Swap 文件创建失败。'; }
        fi
        created_by_abox=1
        chmod 600 /swapfile || { rm -f /swapfile; die 'Swap 文件权限设置失败。'; }
        chown root:root /swapfile || { rm -f /swapfile; die 'Swap 文件属主设置失败。'; }
        mkswap /swapfile >/dev/null || { rm -f /swapfile; die 'mkswap 失败。'; }
    fi
    swapfile_active_state
    case $? in
        0) ;;
        1) swapon /swapfile || { (( created_by_abox == 1 )) && rm -f -- /swapfile; die 'swapon 失败；不会写入 /etc/fstab。'; } ;;
        *) die '无法可靠判断 /swapfile 当前是否已激活；拒绝执行破坏性 Swap 操作。' ;;
    esac
    if (( created_by_abox == 1 )); then
        if ! fstab_backup=$(mktemp /etc/.fstab.A-Box-setup-backup.XXXXXX); then
            if ! rollback_new_swap_activation_only; then
                die '/etc/fstab 备份创建失败且新建 Swap 无法安全关闭；已保留 /swapfile，未修改 /etc/fstab，请立即检查并手动处理。'
            fi
            die '/etc/fstab 备份创建失败；已回滚新建 Swap，且未修改 /etc/fstab。'
        fi
        if ! cp -a /etc/fstab "$fstab_backup"; then
            rm -f -- "$fstab_backup" || true
            if ! rollback_new_swap_activation_only; then
                die '无法创建可靠的 /etc/fstab 备份且新建 Swap 无法安全关闭；已保留 /swapfile，未修改 /etc/fstab。'
            fi
            die '/etc/fstab 备份失败；已回滚新建 Swap，且未修改 /etc/fstab。'
        fi
        if ! grep -qE '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0([[:space:]]|$)' /etc/fstab 2>/dev/null; then
            if ! fstab_tmp=$(mktemp /etc/.fstab.A-Box.XXXXXX); then
                if ! rollback_abox_new_swap "$fstab_backup"; then
                    msg "${RED}[!] Swap 回滚未完成；保留 fstab 备份：${fstab_backup}${NC}" >&2
                    die '/etc/fstab 临时文件创建失败且 Swap 无法安全回滚；已保留恢复材料。'
                fi
                rm -f "$fstab_backup" || true
                die '/etc/fstab 临时文件创建失败；已回滚新建 Swap。'
            fi
            if ! cat /etc/fstab > "$fstab_tmp" || ! printf '%s\n' '# A-Box swap BEGIN' '/swapfile none swap sw 0 0' '# A-Box swap END' >> "$fstab_tmp"; then
                rm -f "$fstab_tmp"
                if ! rollback_abox_new_swap "$fstab_backup"; then
                    msg "${RED}[!] Swap 回滚未完成；保留 fstab 备份：${fstab_backup}${NC}" >&2
                    die '/etc/fstab 写入失败且 Swap 无法安全回滚；已保留恢复材料。'
                fi
                rm -f "$fstab_backup" || true
                die '/etc/fstab 写入失败；已回滚新建 Swap。'
            fi
            chmod --reference=/etc/fstab "$fstab_tmp" 2>/dev/null || chmod 644 "$fstab_tmp"
            chown --reference=/etc/fstab "$fstab_tmp" 2>/dev/null || true
            if ! mv -f "$fstab_tmp" /etc/fstab; then
                rm -f "$fstab_tmp"
                if ! rollback_abox_new_swap "$fstab_backup"; then
                    msg "${RED}[!] Swap 回滚未完成；保留 fstab 备份：${fstab_backup}${NC}" >&2
                    die '/etc/fstab 原子提交失败且 Swap 无法安全回滚；已保留恢复材料。'
                fi
                rm -f "$fstab_backup" || true
                die '/etc/fstab 原子提交失败；已回滚新建 Swap。'
            fi
        fi
        if ! write_file_atomically_from_stdin "$ABOX_DIR/.swapfile.managed" 600 <<'EOF_SWAP_MARK'
A-Box managed swap v1
EOF_SWAP_MARK
        then
            if ! rollback_abox_new_swap "$fstab_backup"; then
                msg "${RED}[!] Swap ownership marker 写入失败，自动回滚未完成；保留 fstab 备份：${fstab_backup}${NC}" >&2
                die 'Swap 归属标记写入失败且自动回滚不完整；已保留恢复材料，请立即检查 /etc/fstab 与 /swapfile。'
            fi
            rm -f "$fstab_backup" || true
            die 'Swap 归属标记写入失败；已完整回滚 A-Box 新建 Swap。'
        fi
        rm -f "$fstab_backup" || die 'Swap 临时备份清理失败；Swap 已部署但安全备份残留，请检查 /etc/.fstab.A-Box-setup-backup.*。'
    elif ! grep -qE '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0([[:space:]]|$)' /etc/fstab 2>/dev/null; then
        msg "${YELLOW}[!] 已存在的 /swapfile 非 A-Box 创建文件；已启用但不修改 /etc/fstab，也不会声明所有权。${NC}"
    fi
    swapon --show || true
    msg "${GREEN}$(tr_msg swap_done)${NC}"
    pause_return
}

remove_abox_swap() {
    [[ -f "$ABOX_DIR/.swapfile.managed" && ! -L "$ABOX_DIR/.swapfile.managed" ]] || return 0
    grep -Fxq 'A-Box managed swap v1' "$ABOX_DIR/.swapfile.managed" 2>/dev/null || return 1
    fstab_path_is_safe || return 1
    local tmp backup swap_active=0 swap_state=1
    if [[ -f /swapfile && ! -L /swapfile ]]; then
        swapfile_active_state
        swap_state=$?
        case "$swap_state" in
            0) swap_active=1 ;;
            1) ;;
            *) return 1 ;;
        esac
    fi
    tmp=$(mktemp /etc/.fstab.A-Box-remove.XXXXXX) || return 1
    backup=$(mktemp /etc/.fstab.A-Box-backup.XXXXXX) || { rm -f "$tmp"; return 1; }
    cp -a /etc/fstab "$backup" || { rm -f "$tmp" "$backup"; return 1; }
    awk '
      $0 == "# A-Box swap BEGIN" {
        if (skip) { print "A-Box swap: nested BEGIN" > "/dev/stderr"; exit 2 }
        skip=1; begin_seen=1; next
      }
      $0 == "# A-Box swap END" {
        if (!skip) { print "A-Box swap: END without BEGIN" > "/dev/stderr"; exit 2 }
        skip=0; end_seen=1; next
      }
      skip {next}
      {print}
      END {
        if (skip || (begin_seen && !end_seen) || (!begin_seen && end_seen)) {
          print "A-Box swap: unbalanced BEGIN/END markers; refusing to rewrite /etc/fstab" > "/dev/stderr"
          exit 2
        }
      }
    ' /etc/fstab > "$tmp" || { rm -f "$tmp" "$backup"; return 1; }
    chmod --reference=/etc/fstab "$tmp" 2>/dev/null || chmod 644 "$tmp"
    chown --reference=/etc/fstab "$tmp" 2>/dev/null || true
    mv -f "$tmp" /etc/fstab || { rm -f "$tmp" "$backup"; return 1; }

    restore_fstab_from_swap_backup() {
        if cp -a "$backup" /etc/fstab; then
            return 0
        fi
        msg "${RED}[!] Swap 清理失败且 /etc/fstab 自动恢复也失败；保留恢复备份：${backup}${NC}" >&2
        return 1
    }

    if (( swap_active == 1 )); then
        if ! swapoff /swapfile; then
            restore_fstab_from_swap_backup || return 1
            rm -f "$backup" || true
            return 1
        fi
    fi
    if [[ -f /swapfile && ! -L /swapfile ]]; then
        if ! rm -f /swapfile; then
            restore_fstab_from_swap_backup || return 1
            msg "${YELLOW}[!] /swapfile 删除失败；已恢复 /etc/fstab，保留现有 Swap 文件与所有权标记。${NC}" >&2
            rm -f "$backup" || true
            return 1
        fi
    fi
    if ! rm -f "$ABOX_DIR/.swapfile.managed"; then
        restore_fstab_from_swap_backup || return 1
        msg "${YELLOW}[!] Swap 所有权标记删除失败；已恢复 /etc/fstab，保留恢复状态。${NC}" >&2
        rm -f "$backup" || true
        return 1
    fi
    rm -f "$backup" || return 1
}

redact_secrets_stream() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - 3<&0 <<'PY_REDACT'
import json
import os
import re
import sys

text = os.fdopen(3, "r", encoding="utf-8", errors="strict").read()
secret = re.compile(
    r"(uuid|private.?key|public.?key|short.?id|fingerprint|password|passwd|token|secret|api.?key|authorization|cookie|ss_pass|hy2_pass|hy2_obfs)",
    re.I,
)
link = re.compile(r"(?i)\b(?:vless|hysteria2|hy2|ss)://\S+")
inline_authorization = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization)\s*[:=]\s*)(?:Bearer\s+\S+|Basic\s+\S+|\S+)"
)
inline_cookie = re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+")
inline_secret_assignment = re.compile(
    r"(?i)([\"']?\b(?:uuid|private.?key|public.?key|short.?id|fingerprint|password|passwd|token|secret|api.?key|ss_pass|hy2_pass|hy2_obfs)\b[\"']?\s*[:=]\s*)([\"']?)[^,;\s}\"']+\2"
)


def redact_text(value):
    value = link.sub("***CLIENT_LINK_REDACTED***", value)
    value = inline_authorization.sub(r"\1***REDACTED***", value)
    value = inline_cookie.sub(r"\1***REDACTED***", value)
    value = inline_secret_assignment.sub(r'\1"***REDACTED***"', value)
    return value


def walk(value):
    if isinstance(value, dict):
        return {
            key: ("***REDACTED***" if secret.search(str(key)) else walk(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [walk(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


try:
    parsed = json.loads(text)
except Exception:
    text = re.sub(
        r"(?im)^(UUID|PUBLIC_KEY|SHORT_ID|HY2_CERT_SHA256_FP|HY2_CERT_PUBKEY_SHA256_B64|SS_PASS|HY2_PASS|HY2_OBFS|HY2_ACME_DNS_CF_API_TOKEN)=.*$",
        r"\1=***REDACTED***",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*)(?:bearer\s+[^\s,;}]+|basic\s+[^\s,;}]+|[^\s,;}]+)",
        r'\1***REDACTED***',
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:cookie|set-cookie)\s*:\s*)[^\r\n]+",
        r'\1***REDACTED***',
        text,
    )
    text = re.sub(
        r"(?i)([\"']?(?:private.?key|public.?key|short.?id|fingerprint|password|passwd|token|secret|api.?key|authorization|cookie)[\"']?\s*[:=]\s*)([\"']?)[^,}\s\"']+\2",
        r'\1"***REDACTED***"',
        text,
    )
    sys.stdout.write(link.sub("***CLIENT_LINK_REDACTED***", text))
else:
    json.dump(walk(parsed), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
PY_REDACT
    else
        sed -E \
            -e 's/(UUID|SS_PASS|HY2_PASS|HY2_OBFS|HY2_ACME_DNS_CF_API_TOKEN|PUBLIC_KEY|SHORT_ID)=.*/\1=***REDACTED***/Ig' \
            -e 's/((Authorization|Proxy-Authorization)[[:space:]]*:[[:space:]]*)(Bearer|Basic)[[:space:]]+[^,;[:space:]}"]+/\1\3 ***REDACTED***/Ig' \
            -e 's/((Authorization|Proxy-Authorization)[[:space:]]*:[[:space:]]*)[^,;[:space:]}"]+/\1***REDACTED***/Ig' \
            -e 's/((Cookie|Set-Cookie)[[:space:]]*:[[:space:]]*)[^,}[:cntrl:]"]+/\1***REDACTED***/Ig' \
            -e 's/^([[:space:]]*(Authorization|Proxy-Authorization)[[:space:]]*:[[:space:]]*).*/\1***REDACTED***/Ig' \
            -e 's/^([[:space:]]*(Cookie|Set-Cookie)[[:space:]]*:[[:space:]]*).*/\1***REDACTED***/Ig' \
            -e 's/([" ]?(PRIVATE_KEY|PUBLIC_KEY|SHORT_ID|HY2_CERT_SHA256_FP|HY2_CERT_PUBKEY_SHA256_B64|privateKey|private_key|publicKey|shortId|fingerprint|password|passwd|token|secret|api[_-]?key|authorization|cookie)[" ]?[[:space:]]*[:=][[:space:]]*[" ]?)[^,}[:space:]["]+/\1***REDACTED***/Ig' \
            -e 's/(vless|hysteria2|hy2|ss):\/\/[^[:space:]]+/***CLIENT_LINK_REDACTED***/Ig'
    fi
}

write_redacted_file() {
    local src="$1" dst="$2"
    [[ -r "$src" ]] || return 0
    mkdir -p "$(dirname "$dst")" || return 1
    redact_secrets_stream < "$src" > "$dst" 2>/dev/null || { rm -f -- "$dst"; return 1; }
    [[ -s "$dst" ]] || { rm -f -- "$dst"; return 1; }
}

validate_abox_cron_file() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    python3 - "$file" <<'PY_ABOX_CRON'
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(encoding='utf-8',errors='strict').splitlines()
allowed={
 'PROBE':'* * * * * /usr/bin/flock -n /run/A-Box-probe-cron.lock /bin/bash /etc/ddr/socket_probe.sh >/dev/null 2>&1',
 'GEO':'0 3 * * 1 /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1',
 'TRAFFIC':'* * * * * /bin/bash /etc/ddr/traffic_monitor.sh >/dev/null 2>&1',
}
i=0; seen=set()
while i < len(lines):
    if not lines[i]: i+=1; continue
    if not (lines[i].startswith('# A-Box ') and lines[i].endswith(' BEGIN')): raise SystemExit(1)
    name=lines[i][8:-6]
    if name not in allowed or name in seen or i+2 >= len(lines): raise SystemExit(1)
    if lines[i+1] != allowed[name] or lines[i+2] != f'# A-Box {name} END': raise SystemExit(1)
    seen.add(name); i+=3
PY_ABOX_CRON
}

collect_abox_cron() {
    local all err extracted
    all=$(umask 077; mktemp /tmp/A-Box-cron-all.XXXXXX) || return 1
    err=$(umask 077; mktemp /tmp/A-Box-cron-err.XXXXXX) || { rm -f "$all"; return 1; }
    extracted=$(umask 077; mktemp /tmp/A-Box-cron-extract.XXXXXX) || { rm -f "$all" "$err"; return 1; }
    if LC_ALL=C crontab -l > "$all" 2> "$err"; then :
    elif grep -Eqi 'no crontab|no crontab for' "$err"; then : > "$all"
    else rm -f "$all" "$err" "$extracted"; return 1
    fi
    awk '
      /^# A-Box (PROBE|GEO|TRAFFIC) BEGIN$/ {inblock=1}
      inblock {print}
      /^# A-Box (PROBE|GEO|TRAFFIC) END$/ {inblock=0}
      END {if (inblock) exit 1}
    ' "$all" > "$extracted" || { rm -f "$all" "$err" "$extracted"; return 1; }
    validate_abox_cron_file "$extracted" || { rm -f "$all" "$err" "$extracted"; return 1; }
    local cat_rc=0
    cat "$extracted" || cat_rc=$?
    rm -f "$all" "$err" "$extracted"
    return "$cat_rc"
}

read_crontab_to_file() {
    local out="$1" err
    [[ -n "$out" ]] || return 1
    err=$(umask 077; mktemp /tmp/A-Box-crontab-error.XXXXXX) || return 1
    if LC_ALL=C crontab -l > "$out" 2> "$err"; then
        rm -f -- "$err"
        return 0
    elif grep -Eqi 'no crontab|no crontab for' "$err"; then
        : > "$out"
        rm -f -- "$err"
        return 0
    fi
    rm -f -- "$err"
    return 1
}

strip_abox_cron_blocks_from_file() {
    local input="$1" output="$2" name="${3:-}"
    [[ -f "$input" && ! -L "$input" && -n "$output" ]] || return 1
    awk -v wanted="$name" '
      BEGIN { skip=0; seen_wanted=0 }
      {
        if (wanted != "" && $0 == "# A-Box " wanted " BEGIN") { skip=1; seen_wanted=seen_wanted+1; next }
        if (wanted != "" && $0 == "# A-Box " wanted " END") { if (!skip) exit 1; skip=0; next }
        if (wanted == "" && $0 ~ /^# A-Box (PROBE|GEO|TRAFFIC) BEGIN$/) { skip=1; next }
        if (wanted == "" && $0 ~ /^# A-Box (PROBE|GEO|TRAFFIC) END$/) { if (!skip) exit 1; skip=0; next }
        if (skip) next
        print
      }
      END { if (skip) exit 1; if (wanted != "" && seen_wanted > 1) exit 1 }
    ' "$input" > "$output" || return 1
}

commit_crontab_if_unchanged() {
    local snapshot="$1" candidate="$2" live rc=0
    [[ -f "$snapshot" && ! -L "$snapshot" && -f "$candidate" && ! -L "$candidate" ]] || return 1
    live=$(mktemp) || return 1
    if ! read_crontab_to_file "$live"; then rm -f -- "$live"; return 1; fi
    if ! cmp -s -- "$snapshot" "$live"; then
        rm -f -- "$live"
        printf '%s\n' 'A-Box cron update aborted: crontab changed concurrently; no overwrite was attempted.' >&2
        return 2
    fi
    rm -f -- "$live"
    crontab "$candidate" >/dev/null 2>&1 || rc=1
    return "$rc"
}

install_abox_cron_block() {
    local name="$1" line="$2" current tmp
    [[ -n "$name" && -n "$line" ]] || return 1
    current=$(mktemp) || die 'crontab 当前内容临时文件创建失败。'
    tmp=$(mktemp) || { rm -f -- "$current"; die 'crontab 临时文件创建失败。'; }
    if ! read_crontab_to_file "$current"; then
        rm -f -- "$current" "$tmp"
        die '无法读取现有 crontab；为避免覆盖用户任务，已中止。'
    fi
    if ! strip_abox_cron_blocks_from_file "$current" "$tmp" "$name"; then
        rm -f -- "$current" "$tmp"
        die "现有 crontab 中的 A-Box ${name} 区块格式异常；为避免破坏计划任务，已中止。"
    fi
    {
        printf '%s\n' "# A-Box ${name} BEGIN"
        printf '%s\n' "$line"
        printf '%s\n' "# A-Box ${name} END"
    } >> "$tmp" || { rm -f -- "$current" "$tmp"; die 'crontab 临时内容写入失败。'; }
    local commit_rc=0
    commit_crontab_if_unchanged "$current" "$tmp" || commit_rc=$?
    if (( commit_rc != 0 )); then
        rm -f -- "$current" "$tmp"
        if (( commit_rc == 2 )); then die 'crontab 在提交前发生并发修改；已中止以保护外部任务。'; fi
        die 'crontab 写入失败；原有 crontab 未被覆盖。'
    fi
    rm -f -- "$current" "$tmp"
}

remove_abox_cron_block() {
    local name="$1" current tmp rc=0
    [[ -n "$name" ]] || return 1
    current=$(mktemp) || die 'crontab 当前内容临时文件创建失败。'
    tmp=$(mktemp) || { rm -f -- "$current"; die 'crontab 临时文件创建失败。'; }
    if ! read_crontab_to_file "$current"; then
        rm -f -- "$current" "$tmp"
        return 1
    fi
    if ! strip_abox_cron_blocks_from_file "$current" "$tmp" "$name"; then
        rm -f -- "$current" "$tmp"
        return 1
    fi
    commit_crontab_if_unchanged "$current" "$tmp" || rc=$?
    rm -f -- "$current" "$tmp"
    return "$rc"
}

remove_all_abox_cron_blocks() {
    local current tmp rc=0
    current=$(mktemp) || die 'crontab 当前内容临时文件创建失败。'
    tmp=$(mktemp) || { rm -f -- "$current"; die 'crontab 临时文件创建失败。'; }
    if ! read_crontab_to_file "$current"; then
        rm -f -- "$current" "$tmp"
        return 1
    fi
    if ! strip_abox_cron_blocks_from_file "$current" "$tmp"; then
        rm -f -- "$current" "$tmp"
        return 1
    fi
    commit_crontab_if_unchanged "$current" "$tmp" || rc=$?
    rm -f -- "$current" "$tmp"
    return "$rc"
}

service_enabled_state_value() {
    local srv="$1" state output rc
    if [[ "${INIT_SYS:-}" == systemd ]] && systemd_available; then
        output=$(systemctl show -p UnitFileState --value "$srv" 2>/dev/null) || return 1
        state="$output"
        case "$state" in
            enabled|enabled-runtime|indirect|disabled) printf '%s\n' "$state" ;;
            *) return 1 ;;
        esac
        return 0
    elif [[ "${INIT_SYS:-}" == openrc ]]; then
        command -v rc-update >/dev/null 2>&1 || return 1
        output=$(rc-update show default 2>/dev/null) || return 1
        if grep -Eq "(^|[[:space:]])${srv//[^a-zA-Z0-9_.@+-]/}([[:space:]]|$)" <<< "$output"; then
            printf '1\n'
        else
            printf '0\n'
        fi
        return 0
    fi
    return 1
}

managed_service_state_value() {
    local srv="$1" active=0 enabled_state enabled=0 output active_state rc
    if [[ "${INIT_SYS:-}" == systemd ]] && systemd_available; then
        output=$(systemctl show -p ActiveState --value "$srv" 2>/dev/null) || return 1
        active_state="$output"
        case "$active_state" in
            active) active=1 ;;
            inactive|failed|dead|exited) active=0 ;;
            *) return 1 ;;
        esac
        enabled_state=$(service_enabled_state_value "$srv") || return 1
        case "$enabled_state" in
            enabled|enabled-runtime|indirect) enabled=1 ;;
            disabled) enabled=0 ;;
            *) return 1 ;;
        esac
    elif [[ "${INIT_SYS:-}" == openrc ]] && command -v rc-service >/dev/null 2>&1; then
        rc-service "$srv" status >/dev/null 2>&1
        rc=$?
        case "$rc" in
            0) active=1 ;;
            3|16|32) active=0 ;;
            *) return 1 ;;
        esac
        enabled_state=$(service_enabled_state_value "$srv") || return 1
        case "$enabled_state" in
            1) enabled=1 ;;
            0) enabled=0 ;;
            *) return 1 ;;
        esac
    else
        return 1
    fi
    printf '%s|%s|%s\n' "$srv" "$active" "$enabled"
}

capture_managed_service_state() {
    local out="$1" srv
    : > "$out" || return 1
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        managed_service_state_value "$srv" >> "$out" || return 1
    done
}


append_managed_service_state_entry() {
    local source="$1" dest="$2" srv="$3" line
    [[ -r "$source" && -f "$source" && ! -L "$source" ]] || return 1
    line=$(awk -F'|' -v target="$srv" '$1 == target {print; found=1; exit} END {if (!found) exit 1}' "$source") || return 1
    printf '%s\n' "$line" >> "$dest"
}

_apply_managed_service_state_file() {
    local state_file="${1:-}" expected_file="${2:-}" line srv active enabled extra seen_srvs="|"
    [[ -r "$state_file" && -f "$state_file" && ! -L "$state_file" ]] || return 1
    [[ "$(stat -c %u:%g "$state_file" 2>/dev/null || true)" == 0:0 ]] || return 1
    local mode
    mode=$(stat -c %a "$state_file" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
    if [[ -n "$expected_file" ]]; then
        validate_services_state_file "$expected_file" || return 1
        [[ "$(stat -c %u:%g "$expected_file" 2>/dev/null || true)" == 0:0 ]] || return 1
        mode=$(stat -c %a "$expected_file" 2>/dev/null) || return 1
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
        [[ "$(awk -F'|' '{print $1}' "$state_file" | sort)" == "$(awk -F'|' '{print $1}' "$expected_file" | sort)" ]] || return 1
    fi

    # Preflight the complete expected post-state before changing any service.
    # A mismatch means another actor changed shared service state; never overwrite
    # that state with an A-Box rollback snapshot.
    if [[ -n "$expected_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            IFS='|' read -r srv _ _ extra <<< "$line"
            [[ -z "${extra:-}" ]] || return 1
            local expected_line current_state
            expected_line="$line"
            current_state=$(managed_service_state_value "$srv") || return 2
            [[ "$current_state" == "$expected_line" ]] || return 2
        done < "$expected_file"
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        IFS='|' read -r srv active enabled extra <<< "$line"
        [[ -z "${extra:-}" ]] || return 1
        case "$srv" in
            xray|sing-box|hysteria) ;;
            *) return 1 ;;
        esac
        [[ "$active" =~ ^[01]$ && "$enabled" =~ ^[01]$ ]] || return 1
        case "$seen_srvs" in *"|$srv|"*) return 1 ;; esac
        seen_srvs+="$srv|"
        abox_owns_service "$srv" || return 1

        if [[ -n "$expected_file" ]]; then
            local expected_state_before
            expected_state_before=$(awk -F'|' -v target="$srv" '$1 == target {print; found=1; exit} END {if (!found) exit 1}' "$expected_file") || return 2
            local current_state_before
            current_state_before=$(managed_service_state_value "$srv") || return 2
            [[ "$current_state_before" == "$expected_state_before" ]] || return 2
        fi

        local restored_state restored_srv restored_active restored_enabled restored_extra
        if [[ "${INIT_SYS:-}" == systemd ]]; then
            systemctl daemon-reload >/dev/null 2>&1 || return 1
            if [[ "$enabled" == 1 ]]; then
                systemctl enable "$srv" >/dev/null 2>&1 || return 1
            else
                systemctl disable "$srv" >/dev/null 2>&1 || return 1
            fi
            if [[ "$active" == 1 ]]; then
                systemctl start "$srv" >/dev/null 2>&1 || systemctl restart "$srv" >/dev/null 2>&1 || return 1
            else
                systemctl stop "$srv" >/dev/null 2>&1 || return 1
            fi
        elif [[ "${INIT_SYS:-}" == openrc ]]; then
            if [[ "$enabled" == 1 ]]; then
                rc-update add "$srv" default >/dev/null 2>&1 || return 1
            else
                if rc-update show default 2>/dev/null | grep -Eq "(^|[[:space:]])${srv}([[:space:]]|$)"; then
                    rc-update del "$srv" default >/dev/null 2>&1 || return 1
                fi
            fi
            if [[ "$active" == 1 ]]; then
                rc-service "$srv" start >/dev/null 2>&1 || rc-service "$srv" restart >/dev/null 2>&1 || return 1
            else
                rc-service "$srv" stop >/dev/null 2>&1 || return 1
            fi
        else
            return 1
        fi
        restored_state=$(managed_service_state_value "$srv") || return 1
        IFS='|' read -r restored_srv restored_active restored_enabled restored_extra <<< "$restored_state"
        [[ -z "${restored_extra:-}" && "$restored_srv" == "$srv" && "$restored_active" == "$active" && "$restored_enabled" == "$enabled" ]] || return 1
    done < "$state_file"
}

restore_managed_service_state() {
    local state_file="${1:-}" expected_file="${2:-}" tx_dir before_file post_file line srv before after rc=0
    [[ -r "$state_file" && -f "$state_file" && ! -L "$state_file" ]] || return 1
    validate_services_state_file "$state_file" || return 1
    tx_dir=$(mktemp -d /run/A-Box-service-restore.XXXXXX) || return 1
    chmod 700 "$tx_dir" || { rm -rf -- "$tx_dir"; return 1; }
    before_file="$tx_dir/before.state"; post_file="$tx_dir/post.state"
    : > "$before_file" || { rm -rf -- "$tx_dir"; return 1; }
    while IFS='|' read -r srv _active _enabled extra; do
        [[ -n "$srv" ]] || continue
        [[ -z "${extra:-}" ]] || { rm -rf -- "$tx_dir"; return 1; }
        before=$(managed_service_state_value "$srv" 2>/dev/null) || { rm -rf -- "$tx_dir"; return 1; }
        printf '%s\n' "$before" >> "$before_file" || { rm -rf -- "$tx_dir"; return 1; }
    done < "$state_file"
    chmod 600 "$before_file" || { rm -rf -- "$tx_dir"; return 1; }

    if _apply_managed_service_state_file "$state_file" "$expected_file"; then
        rm -rf -- "$tx_dir" || return 1
        return 0
    else
        rc=$?
    fi

    # The low-level applier may have changed a prefix of services before a later
    # command failed. Capture the exact observable intermediate state; if any
    # query fails, preserve the recovery snapshot instead of guessing.
    : > "$post_file" || { printf '%s\n' "A-Box service restore failed; recovery state preserved at $tx_dir" >&2; return 1; }
    while IFS='|' read -r srv _active _enabled extra; do
        [[ -n "$srv" ]] || continue
        after=$(managed_service_state_value "$srv" 2>/dev/null) || { printf '%s\n' "A-Box service restore failed; state query unavailable, recovery state preserved at $tx_dir" >&2; return 1; }
        printf '%s\n' "$after" >> "$post_file" || { printf '%s\n' "A-Box service restore failed; recovery state preserved at $tx_dir" >&2; return 1; }
    done < "$state_file"
    chmod 600 "$post_file" || { printf '%s\n' "A-Box service restore failed; recovery state preserved at $tx_dir" >&2; return 1; }
    if cmp -s -- "$before_file" "$post_file"; then
        # No service state changed; avoid needlessly restarting/stopping a stack
        # when the original operation failed before its first effective mutation.
        rm -rf -- "$tx_dir" || return 1
        return "$rc"
    fi

    # Roll back only if the live state still equals the captured intermediate state.
    # _apply_managed_service_state_file performs this precondition check before mutation.
    if ! _apply_managed_service_state_file "$before_file" "$post_file"; then
        printf '%s\n' "A-Box service restore rollback incomplete or conflicted; recovery state preserved at $tx_dir" >&2
        return 1
    fi
    rm -rf -- "$tx_dir" || return 1
    return "$rc"
}

extract_abox_iptables_rules() {
    local snapshot="$1" mode="${2:-all}"
    awk -v mode="$mode" '''
      /^\*/ {table=$0; next} /^COMMIT$/ {next}
      /^-A / {
        base=($0 ~ /--comment "?A-Box-[0-9]+(:[0-9]+)?-(tcp|udp)"?([[:space:]]|$)/)
        wl=($0 ~ /--comment "?A-Box-[0-9]+-(tcp|udp)-WL6?"?([[:space:]]|$)/)
        drop=($0 ~ /--comment "?A-Box-[0-9]+-(tcp|udp)-DROP6?"?([[:space:]]|$)/)
        hop=($0 ~ /--comment "?A-Box-HY2-HOP"?([[:space:]]|$)/)
        owned=(base || wl || drop || hop)
        special=(wl || drop || hop)
        if ((mode=="all" && owned) || special) {
          if (table!=emitted) {if (emitted!="") print "COMMIT"; print table; emitted=table}
          print
        }
      }
      END {if (emitted!="") print "COMMIT"}
    ''' "$snapshot"
}

capture_abox_iptables_snapshot() {
    local out="$1" family="${2:-4}" cmd all
    [[ "$family" == 6 ]] && cmd=ip6tables-save || cmd=iptables-save
    if ! command -v "$cmd" >/dev/null 2>&1; then
        [[ "$family" == 6 ]] && ! has_ipv6 || return 1
        : > "$out"
        return 0
    fi
    all=$(mktemp) || return 1
    if ! "$cmd" > "$all" 2>/dev/null; then
        rm -f "$all"
        if [[ "$family" == 6 ]] && ! has_ipv6; then
            : > "$out"
            return 0
        fi
        return 1
    fi
    extract_abox_iptables_rules "$all" all > "$out" || { rm -f "$all"; return 1; }
    rm -f "$all"
}

restore_abox_iptables_snapshot() {
    local snapshot="$1" family="${2:-4}" mode="${3:-all}" cmd tmp
    [[ "$family" == 6 ]] && ! has_ipv6 && return 0
    [[ -s "$snapshot" ]] || return 0
    [[ "$family" == 6 ]] && cmd=ip6tables-restore || cmd=iptables-restore
    tmp=$(mktemp) || return 1
    extract_abox_iptables_rules "$snapshot" "$mode" > "$tmp" || { rm -f "$tmp"; return 1; }
    if grep -q '^\*' "$tmp"; then
        command -v "$cmd" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
        "$cmd" -w --noflush < "$tmp" >/dev/null 2>&1 || "$cmd" --noflush < "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
    fi
    rm -f "$tmp"
}

backup_sidecar_safe() {
    local file="$1" uid gid mode
    [[ -f "$file" && ! -L "$file" ]] || return 1
    uid=$(stat -c %u "$file" 2>/dev/null) || return 1
    gid=$(stat -c %g "$file" 2>/dev/null) || return 1
    mode=$(stat -c %a "$file" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 ))
}

write_private_sidecar() {
    local dest="$1" value="$2" dir tmp
    [[ "$dest" == /* ]] || return 1
    path_parent_chain_safe "$dest" || return 1
    dir=$(dirname "$dest")
    [[ -d "$dir" && ! -L "$dir" ]] || return 1
    [[ "$(stat -c %u:%g "$dir" 2>/dev/null || true)" == 0:0 ]] || return 1
    path_mode_has_no_group_other_write "$dir" || return 1
    [[ ! -L "$dest" ]] || return 1
    if [[ -e "$dest" ]] && path_is_mountpoint "$dest"; then return 1; fi
    tmp=$(umask 077; mktemp "$dir/.A-Box-sidecar.XXXXXX") || return 1
    printf '%s\n' "$value" > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
}

ensure_backup_auth_key() {
    local key tmp
    if [[ -e "$ABOX_BACKUP_KEY" || -L "$ABOX_BACKUP_KEY" ]]; then
        backup_sidecar_safe "$ABOX_BACKUP_KEY" || return 1
        IFS= read -r key < "$ABOX_BACKUP_KEY" || return 1
        [[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]]
        return
    fi
    ensure_abox_dir_owned "$ABOX_DIR"
    tmp=$(umask 077; mktemp "$ABOX_DIR/.backup-hmac-key.XXXXXX") || return 1
    key=$(openssl rand -hex 32 2>/dev/null) || { rm -f -- "$tmp"; return 1; }
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]] || { rm -f -- "$tmp"; return 1; }
    printf '%s\n' "$key" > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$ABOX_BACKUP_KEY" || { rm -f -- "$tmp"; return 1; }
}

backup_checksum_write() {
    local archive="$1" hash
    [[ -f "$archive" && ! -L "$archive" ]] || return 1
    hash=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')
    [[ "$hash" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    write_private_sidecar "${archive}.sha256" "$hash  $(basename "$archive")"
}

backup_checksum_verify() {
    local archive="$1" sidecar="${2:-${1}.sha256}" expected actual extra
    [[ -f "$archive" && ! -L "$archive" ]] || return 1
    backup_sidecar_safe "$sidecar" || return 2
    read -r expected extra < "$sidecar" || return 1
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    actual=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')
    [[ "${actual,,}" == "${expected,,}" ]]
}

backup_auth_write() {
    local archive="$1" key mac
    ensure_backup_auth_key || return 1
    IFS= read -r key < "$ABOX_BACKUP_KEY" || return 1
    mac=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:${key}" "$archive" 2>/dev/null | awk '{print $NF}')
    [[ "$mac" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    write_private_sidecar "${archive}.hmac" "$mac  $(basename "$archive")"
}

backup_auth_verify() {
    local archive="$1" sidecar="${2:-${1}.hmac}" key expected actual extra
    [[ -f "$archive" && ! -L "$archive" ]] || return 1
    backup_sidecar_safe "$ABOX_BACKUP_KEY" || return 2
    backup_sidecar_safe "$sidecar" || return 2
    IFS= read -r key < "$ABOX_BACKUP_KEY" || return 1
    read -r expected extra < "$sidecar" || return 1
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ && "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    actual=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:${key}" "$archive" 2>/dev/null | awk '{print $NF}')
    [[ "${actual,,}" == "${expected,,}" ]]
}

backup_auth_verify_with_key_file() {
    local archive="$1" sidecar="$2" key_file="$3" key expected actual extra
    [[ -f "$archive" && ! -L "$archive" ]] || return 1
    backup_sidecar_safe "$sidecar" || return 1
    backup_sidecar_safe "$key_file" || return 1
    IFS= read -r key < "$key_file" || return 1
    read -r expected extra < "$sidecar" || return 1
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ && "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    actual=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:${key}" "$archive" 2>/dev/null | awk '{print $NF}')
    [[ "${actual,,}" == "${expected,,}" ]]
}

backup_key_fingerprint() {
    local key_file="$1" key
    backup_sidecar_safe "$key_file" || return 1
    IFS= read -r key < "$key_file" || return 1
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    printf '%s' "${key,,}" | sha256sum | awk '{print $1}'
}

install_recovery_backup_key() {
    local key_file="$1" tmp key
    [[ ! -e "$ABOX_BACKUP_KEY" && ! -L "$ABOX_BACKUP_KEY" ]] || return 1
    backup_sidecar_safe "$key_file" || return 1
    IFS= read -r key < "$key_file" || return 1
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    ensure_abox_dir_owned "$ABOX_DIR"
    tmp=$(umask 077; mktemp "$ABOX_DIR/.backup-hmac-import.XXXXXX") || return 1
    printf '%s\n' "$key" > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$ABOX_BACKUP_KEY" || { rm -f -- "$tmp"; return 1; }
}

prepare_backup_auth_for_manual_restore() {
    local archive="$1" rc fingerprint answer
    local hmac="${archive}.hmac" recovery="${archive}.key"
    # Prefer archive-adjacent sidecar; fall back to separated keys directory.
    if [[ (! -e "$recovery" && ! -L "$recovery") && -f "/root/A-Box-backup-keys/$(basename "$archive").key" ]]; then
        recovery="/root/A-Box-backup-keys/$(basename "$archive").key"
    fi
    if backup_auth_verify "$archive" "$hmac"; then return 0; else rc=$?; fi
    # Never replace an existing trust key automatically. A mismatch may mean
    # the user selected a foreign or malicious backup.
    if [[ -e "$ABOX_BACKUP_KEY" || -L "$ABOX_BACKUP_KEY" ]]; then
        return "$rc"
    fi
    backup_auth_verify_with_key_file "$archive" "$hmac" "$recovery" || return 1
    fingerprint=$(backup_key_fingerprint "$recovery") || return 1
    if [[ -n "${ABOX_BACKUP_KEY_SHA256_ALLOWLIST:-}" ]]; then
        sha256_in_allowlist "$fingerprint" "$ABOX_BACKUP_KEY_SHA256_ALLOWLIST" || return 1
    else
        [[ -t 0 ]] || return 1
        msg "${YELLOW}[!] 此备份需要导入独立保存的恢复密钥。密钥指纹: ${fingerprint}${NC}"
        msg "${YELLOW}[!] 持有归档、HMAC 与恢复密钥的人可以构造受该密钥认证的 root 恢复内容；只应导入你自己保管的密钥。${NC}"
        read -r -p '输入 IMPORT-RECOVERY-KEY 以导入并继续: ' answer
        [[ "$answer" == 'IMPORT-RECOVERY-KEY' ]] || return 130
    fi
    install_recovery_backup_key "$recovery" || return 1
    backup_auth_verify "$archive" "$hmac"
}


export_backup_recovery_key() {
    local dest="${1:-}" key fingerprint
    [[ $EUID -eq 0 ]] || die '导出备份恢复密钥需要 root。'
    [[ -n "$dest" ]] || die '用法: --export-backup-key /path/on/separate-medium/A-Box-recovery.key'
    [[ "$dest" == /* ]] || die '恢复密钥导出路径必须是绝对路径。'
    [[ ! -e "$dest" && ! -L "$dest" ]] || die "拒绝覆盖现有恢复密钥文件: $dest"
    ensure_backup_auth_key || die '无法创建或读取备份认证密钥。'
    IFS= read -r key < "$ABOX_BACKUP_KEY" || die '恢复密钥读取失败。'
    [[ "$key" =~ ^[A-Fa-f0-9]{64}$ ]] || die '恢复密钥格式非法。'
    write_private_sidecar "$dest" "$key" || die '恢复密钥导出失败；目标目录必须为 root 所有且不可被组/其他用户写入。'
    fingerprint=$(backup_key_fingerprint "$dest") || die '恢复密钥指纹计算失败。'
    msg "${GREEN}[*] Recovery key exported:${NC} $dest"
    msg "${GREEN}[*] Key fingerprint (SHA256):${NC} $fingerprint"
    msg "${YELLOW}[!] Store this key separately from backup archives. Anyone holding both can authenticate modified archives.${NC}"
}

validate_legacy_backup_archive() {
    local archive="$1"
    [[ -s "$archive" ]] || return 1
    python3 - "$archive" <<'PY_LEGACY_VALIDATE'
import posixpath, stat, sys, tarfile
fn=sys.argv[1]; max_members=10000; max_file=512*1024*1024; max_total=1024*1024*1024
allowed_prefixes=(
 'root/etc/ddr','root/usr/local/bin/sb','root/usr/local/bin/xray','root/usr/local/bin/sing-box','root/usr/local/bin/hysteria',
 'root/usr/local/etc/xray','root/usr/local/share/xray','root/etc/sing-box','root/etc/hysteria','root/etc/logrotate.d/A-Box',
 'root/etc/fail2ban/filter.d/A-Box.conf','root/etc/fail2ban/jail.d/A-Box.local','root/etc/systemd/system/xray.service',
 'root/etc/systemd/system/sing-box.service','root/etc/systemd/system/hysteria.service','root/etc/init.d/xray','root/etc/init.d/sing-box',
 'root/etc/init.d/hysteria','meta/metadata.txt','meta/cron.abox.txt','meta/iptables.snapshot','meta/ip6tables.snapshot')
def allowed(n):
 if n in {'root','root/etc','root/usr','root/usr/local','root/usr/local/bin','root/usr/local/etc','root/usr/local/share','root/etc/logrotate.d','root/etc/fail2ban','root/etc/fail2ban/filter.d','root/etc/fail2ban/jail.d','root/etc/systemd','root/etc/systemd/system','root/etc/init.d','root/etc/ddr','meta'}: return True
 prefix='root/etc/ddr/'
 if n.startswith(prefix):
  rel=n[len(prefix):]
  if '/' in rel or not rel: return False
  exact={'.env','.firewall-native.rules','.lang','.desired_state','.traffic-block-state','.A-Box-owner','.public_ip.cache','.backup-hmac.key','.runtime.lock','.managed-core-files.tsv','A-Box.sh','socket_probe.sh','geo_update.sh','traffic_monitor.sh','firewall_restore.sh','iptables.v4','iptables.v6','A-Box-sni-full.tsv','A-Box-sni-mini.tsv'}
  return rel in exact or rel.startswith('.deps.v')
 return any(n==x or n.startswith(x+'/') for x in allowed_prefixes if x!='root/etc/ddr')
try: tf=tarfile.open(fn,'r:gz')
except Exception: raise SystemExit(1)
members=tf.getmembers(); seen=set(); total=0
if len(members)>max_members: raise SystemExit(1)
for m in members:
 raw=m.name
 while raw.startswith('./'): raw=raw[2:]
 n=posixpath.normpath(raw)
 if n in ('','.'): continue
 if raw.startswith('/') or n=='..' or n.startswith('../') or not allowed(n): raise SystemExit(1)
 if n in seen and not m.isdir(): raise SystemExit(1)
 seen.add(n)
 if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo() or m.isdev(): raise SystemExit(1)
 if not (m.isfile() or m.isdir()) or m.uid!=0 or m.gid!=0: raise SystemExit(1)
 mode=m.mode & 0o7777
 if mode & 0o7000 or mode & 0o022: raise SystemExit(1)
 if m.isfile():
  if m.size<0 or m.size>max_file: raise SystemExit(1)
  total+=m.size
  if total>max_total: raise SystemExit(1)
if 'root/etc/ddr' not in seen or 'meta/metadata.txt' not in seen: raise SystemExit(1)
if 'meta/manifest.version' in seen: raise SystemExit(1)
PY_LEGACY_VALIDATE
}

convert_legacy_backup_archive() {
    local selected="$1" out_dir="${2:-$(dirname "$1")}" work root out answer unit srv path
    [[ -f "$selected" && ! -L "$selected" ]] || die 'Legacy backup path is invalid.'
    if [[ -f "${selected}.sha256" && ! -L "${selected}.sha256" ]]; then
        backup_checksum_verify "$selected" "${selected}.sha256" || die 'Legacy backup SHA256 verification failed.'
    else
        [[ -t 0 ]] || die 'Legacy backup has no checksum and conversion is non-interactive.'
        confirm_yes_no 'Legacy backup has no trusted checksum. Import anyway? [Y/N]: ' || return 130
    fi
    validate_legacy_backup_archive "$selected" || die 'Legacy backup archive safety validation failed.'
    work=$(mktemp -d /tmp/A-Box-legacy-import.XXXXXX) || die 'Legacy conversion temp directory failed.'
    chmod 700 "$work"
    python3 - "$selected" "$work" <<'PY_LEGACY_EXTRACT'
import os, pathlib, tarfile, sys
src,dst=sys.argv[1:]; base=pathlib.Path(dst).resolve()
with tarfile.open(src,'r:gz') as tf:
 for m in tf.getmembers():
  name=m.name
  while name.startswith('./'): name=name[2:]
  if not name or name=='.': continue
  target=(base/name).resolve()
  if base not in target.parents and target!=base: raise SystemExit(1)
  if m.isdir(): target.mkdir(parents=True,exist_ok=True); os.chmod(target,m.mode & 0o777)
  elif m.isfile():
   target.parent.mkdir(parents=True,exist_ok=True)
   f=tf.extractfile(m)
   if f is None: raise SystemExit(1)
   with open(target,'wb') as out:
    while True:
     chunk=f.read(1024*1024)
     if not chunk: break
     out.write(chunk)
   os.chmod(target,m.mode & 0o777)
  else: raise SystemExit(1)
PY_LEGACY_EXTRACT
    root="$work/root"
    rm -rf -- "$root$ABOX_DIR/backups" "$root$ABOX_DIR/diagnostics" "$root$ABOX_DIR/preflight"
    rm -f -- "$root$ABOX_DIR/A-Box.sh" "$root$ABOX_DIR/.backup-hmac.key" "$root$ABOX_DIR/.runtime.lock" \
        "$root$ABOX_DIR/socket_probe.sh" "$root$ABOX_DIR/geo_update.sh" "$root$ABOX_DIR/traffic_monitor.sh" "$root$ABOX_DIR/firewall_restore.sh" \
        "$root$ABOX_DIR/iptables.v4" "$root$ABOX_DIR/iptables.v6" "$root$ABOX_DIR/.managed-core-files.tsv" "$root$ABOX_DIR/.public_ip.cache"
    find "$root$ABOX_DIR" -maxdepth 1 -type f -name '.deps.v*' -delete 2>/dev/null || true
    install -d -m 700 "$root$ABOX_DIR" "$work/meta" || { rm -rf "$work"; die 'Legacy conversion directory normalization failed.'; }
    printf '%s\n' 'A-Box managed directory v1' > "$root$ABOX_DIR/.A-Box-owner"
    chmod 600 "$root$ABOX_DIR/.A-Box-owner"
    for srv in xray sing-box hysteria; do
        for unit in "$root/etc/systemd/system/${srv}.service" "$root/etc/init.d/${srv}"; do
            [[ -e "$unit" ]] || continue
            [[ -f "$unit" && ! -L "$unit" ]] || { rm -rf "$work"; die "Legacy service member is not a regular file: $unit"; }
            case "$srv" in
                xray) grep -Fq '/usr/local/bin/xray' "$unit" && grep -Fq '/usr/local/etc/xray/config.json' "$unit" || { rm -rf "$work"; die 'Legacy Xray unit fingerprint rejected.'; } ;;
                sing-box) grep -Fq '/usr/local/bin/sing-box' "$unit" && grep -Fq '/etc/sing-box/config.json' "$unit" || { rm -rf "$work"; die 'Legacy sing-box unit fingerprint rejected.'; } ;;
                hysteria) grep -Fq '/usr/local/bin/hysteria' "$unit" && grep -Fq '/etc/hysteria/config.yaml' "$unit" || { rm -rf "$work"; die 'Legacy Hysteria unit fingerprint rejected.'; } ;;
            esac
            if ! grep -Fxq '# Managed by A-Box' "$unit"; then
                if head -n 1 "$unit" | grep -q '^#!'; then sed -i '1a# Managed by A-Box' "$unit"; else sed -i '1i# Managed by A-Box' "$unit"; fi
            fi
        done
    done
    [[ -f "$work/meta/cron.abox.txt" ]] || : > "$work/meta/cron.abox.txt"
    validate_abox_cron_file "$work/meta/cron.abox.txt" || { rm -rf "$work"; die 'Legacy cron block is not compatible with the strict importer.'; }
    [[ -f "$work/meta/iptables.snapshot" ]] || : > "$work/meta/iptables.snapshot"
    [[ -f "$work/meta/ip6tables.snapshot" ]] || : > "$work/meta/ip6tables.snapshot"
    printf 'iptables\n' > "$work/meta/firewall.backend"
    : > "$work/meta/services.state"
    for srv in xray sing-box hysteria; do
        if backup_root_contains_service "$root" "$srv"; then printf '%s|0|0\n' "$srv" >> "$work/meta/services.state"; fi
    done
    { managed_auxiliary_paths; printf '%s\n' \
        /usr/local/bin/xray /usr/local/etc/xray /usr/local/share/xray /etc/systemd/system/xray.service /etc/init.d/xray /etc/conf.d/xray \
        /usr/local/bin/sing-box /etc/sing-box /etc/systemd/system/sing-box.service /etc/init.d/sing-box /etc/conf.d/sing-box \
        /usr/local/bin/hysteria /etc/hysteria /etc/systemd/system/hysteria.service /etc/init.d/hysteria /etc/conf.d/hysteria; } | \
        while IFS= read -r path; do [[ -e "$root$path" ]] && printf '%s\n' "$path"; done | awk 'NF && !seen[$0]++' > "$work/meta/managed-paths.txt"
    local legacy_aux_paths=''
    legacy_aux_paths=$(managed_auxiliary_paths) || { rm -rf "$work"; die 'Legacy auxiliary path enumeration failed.'; }
    while IFS= read -r path; do
        [[ -e "$root$path" ]] || continue
        auxiliary_content_is_abox_managed "$root$path" "$path" || { rm -rf "$work"; die "Legacy auxiliary path fingerprint rejected: $path"; }
        if ! grep -Fxq '# Managed by A-Box' "$root$path" 2>/dev/null; then
            if head -n 1 "$root$path" | grep -q '^#!'; then sed -i '1a# Managed by A-Box' "$root$path"; else sed -i '1i# Managed by A-Box' "$root$path"; fi
        fi
    done <<< "$legacy_aux_paths"
    printf '%s\n' 'A-Box backup manifest v3' > "$work/meta/manifest.version"
    printf '\nConverted by %s from legacy archive: %s\n' "$ABOX_BUILD" "$(basename "$selected")" >> "$work/meta/metadata.txt"
    create_backup_manifest "$work" "$work/meta/manifest.sha256" || { rm -rf "$work"; die 'Converted manifest creation failed.'; }
    install -d -m 700 "$out_dir" || { rm -rf "$work"; die 'Legacy conversion output directory failed.'; }
    out="$out_dir/$(basename "${selected%.tar.gz}")-v3-imported.tar.gz"
    [[ ! -e "$out" && ! -L "$out" ]] || { rm -rf "$work"; die "Converted backup already exists: $out"; }
    tar -C "$work" -czf "$out" root meta || { rm -rf "$work"; rm -f "$out"; die 'Converted backup archive creation failed.'; }
    chmod 600 "$out"
    validate_backup_archive "$out" || { rm -rf "$work"; rm -f "$out"; die 'Converted backup failed v3 structure validation.'; }
    backup_checksum_write "$out" && backup_auth_write "$out" || { rm -rf "$work"; rm -f "$out" "${out}.sha256" "${out}.hmac"; die 'Converted backup authentication failed.'; }
    rm -rf "$work"
    msg "${GREEN}[*] Legacy backup converted safely:${NC} $out"
    msg "${YELLOW}[*] Services are imported as stopped; review configuration before starting them.${NC}"
}


validate_backup_archive() {
    local archive="$1"
    [[ -s "$archive" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    # UID/GID numbers stored in a backup are source-host metadata. The archive
    # is authenticated separately; restore-time ownership is normalized to the
    # target host's dedicated runtime accounts before any service starts.
    python3 - "$archive" <<'PY_VALIDATE'
import posixpath,stat,sys,tarfile
fn=sys.argv[1]
MAX_MEMBERS=10000
MAX_FILE=512*1024*1024
MAX_TOTAL=1024*1024*1024
SB_DIR='root/etc/sing-box'
HY_DIR='root/etc/hysteria'
HY_ACME=HY_DIR + '/acme'
sb_gid=None
hy_uid=None
hy_gid=None
try: tf=tarfile.open(fn,'r:gz')
except Exception: raise SystemExit(1)
seen=set(); total=0
members=tf.getmembers()
if len(members)>MAX_MEMBERS: raise SystemExit(1)
for m in members:
    raw=m.name
    if '\x00' in raw or raw.startswith('/'): raise SystemExit(1)
    while raw.startswith('./'): raw=raw[2:]
    n=posixpath.normpath(raw)
    if n in ('','.'): continue
    if n=='..' or n.startswith('../') or n.split('/',1)[0] not in ('root','meta'): raise SystemExit(1)
    if n in seen and not m.isdir(): raise SystemExit(1)
    seen.add(n)
    # Backup contents are copied regular files/directories only.  Reject all
    # links and special members to avoid re-rooting and extraction ambiguity.
    if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo() or m.isdev(): raise SystemExit(1)
    if not (m.isfile() or m.isdir()): raise SystemExit(1)
    mode=m.mode & 0o7777
    if mode & 0o7000 or mode & 0o002: raise SystemExit(1)
    in_sb = n == SB_DIR or n.startswith(SB_DIR + '/')
    in_hy = n == HY_DIR or n.startswith(HY_DIR + '/')
    in_hy_acme = n == HY_ACME or n.startswith(HY_ACME + '/')
    if in_sb:
        # Sing-box config data may be group-readable by its dedicated runtime
        # service account. Preserve root:root compatibility, but when a non-root
        # group is present it must be internally consistent within this archive.
        if m.uid != 0: raise SystemExit(1)
        if m.gid == 0:
            if mode & 0o077: raise SystemExit(1)
        else:
            if mode & 0o020: raise SystemExit(1)
            if sb_gid is None: sb_gid=m.gid
            elif m.gid != sb_gid: raise SystemExit(1)
        if n == SB_DIR and not ((m.gid != 0 and mode == 0o750) or (m.gid == 0 and (mode & 0o077) == 0)): raise SystemExit(1)
    elif in_hy_acme:
        # Hysteria ACME state is runtime-owned to allow non-root renewal. The
        # source UID/GID are portable metadata, but must remain internally
        # consistent so a modified member cannot introduce an unrelated identity.
        if n == HY_ACME:
            if m.uid != 0 or not m.isdir(): raise SystemExit(1)
            if m.gid != 0:
                if hy_gid is None: hy_gid=m.gid
                elif m.gid != hy_gid: raise SystemExit(1)
                if hy_uid is None: hy_uid=0
            if not ((m.gid != 0 and mode == 0o770) or
                    (m.gid == 0 and (mode & 0o077) == 0)): raise SystemExit(1)
        else:
            if m.gid != 0:
                if hy_gid is None: hy_gid=m.gid
                elif m.gid != hy_gid: raise SystemExit(1)
            if m.uid != 0:
                if hy_uid in (None,0): hy_uid=m.uid
                elif m.uid != hy_uid: raise SystemExit(1)
                if hy_gid in (None,0): hy_gid=m.gid
                elif m.gid != hy_gid: raise SystemExit(1)
            elif m.gid != 0 and hy_uid is None:
                hy_uid=0
            if mode & 0o020: raise SystemExit(1)
    elif in_hy:
        # Hysteria's top-level config tree is group-readable by its dedicated
        # runtime account; source group numbers are portable but must be consistent.
        if m.uid != 0: raise SystemExit(1)
        if m.gid == 0:
            if mode & 0o077: raise SystemExit(1)
        else:
            if mode & 0o020: raise SystemExit(1)
            if hy_gid is None: hy_gid=m.gid
            elif m.gid != hy_gid: raise SystemExit(1)
        if n == HY_DIR and not ((m.gid != 0 and mode == 0o750) or (m.gid == 0 and (mode & 0o077) == 0)): raise SystemExit(1)
    else:
        if m.uid != 0 or m.gid != 0: raise SystemExit(1)
        if mode & 0o020: raise SystemExit(1)
    if m.isfile():
        if m.size < 0 or m.size > MAX_FILE: raise SystemExit(1)
        total += m.size
        if total > MAX_TOTAL: raise SystemExit(1)
required_names={'root/etc/ddr','meta/manifest.version','meta/manifest.sha256','meta/managed-paths.txt','meta/services.state','meta/firewall.backend','meta/iptables.snapshot','meta/ip6tables.snapshot','meta/cron.abox.txt'}
if not required_names.issubset(seen): raise SystemExit(1)
required_root='root/etc/ddr'
if required_root not in seen: raise SystemExit(1)
root_member=next((m for m in members if posixpath.normpath(m.name.lstrip('./'))==required_root),None)
if root_member is None or not root_member.isdir(): raise SystemExit(1)
raise SystemExit(0)
PY_VALIDATE
}

backup_root_contains_service() {
    local root="$1" srv="$2" path
    local -a paths=()
    case "$srv" in
        xray) paths=(
            /usr/local/bin/xray /usr/local/etc/xray /usr/local/share/xray
            /etc/systemd/system/xray.service /etc/init.d/xray /etc/conf.d/xray
        ) ;;
        sing-box) paths=(
            /usr/local/bin/sing-box /etc/sing-box
            /etc/systemd/system/sing-box.service /etc/init.d/sing-box /etc/conf.d/sing-box
        ) ;;
        hysteria) paths=(
            /usr/local/bin/hysteria /etc/hysteria
            /etc/systemd/system/hysteria.service /etc/init.d/hysteria /etc/conf.d/hysteria
        ) ;;
        *) return 2 ;;
    esac
    for path in "${paths[@]}"; do
        [[ -e "$root$path" || -L "$root$path" ]] && return 0
    done
    return 1
}

backup_root_service_init() {
    local root="$1" srv="$2" unit found=''
    for unit in "$root/etc/systemd/system/${srv}.service" "$root/etc/init.d/${srv}"; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        if [[ -n "$found" ]]; then
            return 2
        fi
        case "$unit" in
            "$root/etc/systemd/system/${srv}.service") found=systemd ;;
            "$root/etc/init.d/${srv}") found=openrc ;;
        esac
    done
    [[ -n "$found" ]] || return 1
    printf '%s\n' "$found"
}

validate_backup_core_init_compatibility() {
    local root="$1" srv backup_init current_init contains_rc
    current_init=$(effective_init_system) || return 1
    [[ "$current_init" == systemd || "$current_init" == openrc ]] || return 1
    for srv in xray sing-box hysteria; do
        backup_root_contains_service "$root" "$srv"
        contains_rc=$?
        case "$contains_rc" in
            0) ;;
            1) continue ;;
            *) return 1 ;;
        esac
        backup_root_service_is_managed "$root" "$srv" || return 1
        backup_init=$(backup_root_service_init "$root" "$srv") || return 1
        [[ "$backup_init" == "$current_init" ]] || {
            msg "${RED}[!] Backup for ${srv} uses ${backup_init}, but this VPS uses ${current_init}; refusing restore before any destructive change.${NC}"
            return 1
        }
    done
    return 0
}

backup_root_service_is_managed() {
    local root="$1" srv="$2" unit found=0
    for unit in "$root/etc/systemd/system/${srv}.service" "$root/etc/init.d/${srv}"; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        [[ -f "$unit" && ! -L "$unit" ]] || return 1
        grep -Fxq '# Managed by A-Box' "$unit" 2>/dev/null || return 1
        found=$((found + 1))
    done
    (( found == 1 ))
}

validate_backup_manifest_tree() {
    local work="$1"
    python3 - "$work" <<'PY_BACKUP_MANIFEST'
import hashlib
import os
import re
import sys
from pathlib import Path, PurePosixPath
root=Path(sys.argv[1]).resolve()
manifest=root/'meta'/'manifest.sha256'
if not manifest.is_file() or manifest.is_symlink(): raise SystemExit(1)
entries={}
for raw in manifest.read_text(encoding='utf-8',errors='strict').splitlines():
    m=re.fullmatch(r'([0-9A-Fa-f]{64})  (.+)',raw)
    if not m: raise SystemExit(1)
    digest,name=m.groups()
    pp=PurePosixPath(name)
    if pp.is_absolute() or '..' in pp.parts or not pp.parts or pp.parts[0] not in {'root','meta'}: raise SystemExit(1)
    if name=='meta/manifest.sha256' or name in entries: raise SystemExit(1)
    entries[name]=digest.lower()
actual={}
for base in (root/'root',root/'meta'):
    for path in base.rglob('*'):
        if path.is_symlink(): raise SystemExit(1)
        if path.is_file():
            rel=path.relative_to(root).as_posix()
            if rel=='meta/manifest.sha256': continue
            actual[rel]=path
if set(entries)!=set(actual): raise SystemExit(1)
for name,path in actual.items():
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    if h.hexdigest()!=entries[name]: raise SystemExit(1)
PY_BACKUP_MANIFEST
}

validate_managed_paths_file() {
    local file="$1" allowed_paths='' srv core_paths
    [[ -f "$file" && ! -L "$file" ]] || return 1
    allowed_paths=$(managed_auxiliary_paths) || return 1
    for srv in xray sing-box hysteria; do
        core_paths=$(core_family_paths "$srv") || return 1
        allowed_paths+=$'\n'"$core_paths"
    done
    python3 - "$file" "$allowed_paths" <<'PY_MANAGED_PATHS'
import sys
from pathlib import Path
allowed={x for x in sys.argv[2].splitlines() if x}
lines=[x for x in Path(sys.argv[1]).read_text(encoding='utf-8',errors='strict').splitlines() if x]
if len(lines)!=len(set(lines)) or any(x not in allowed for x in lines): raise SystemExit(1)
PY_MANAGED_PATHS
}

validate_services_state_file() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    awk -F'|' '
      NF==0 {next}
      NF!=3 || $1 !~ /^(xray|sing-box|hysteria)$/ || $2 !~ /^[01]$/ || $3 !~ /^[01]$/ {bad=1; exit}
      seen[$1]++ {bad=1; exit}
      END {exit bad}
    ' "$file"
}

validate_extracted_backup_content() {
    local root="$1" srv path src work
    work=$(dirname "$root")
    [[ -f "$work/meta/manifest.version" && -f "$work/meta/manifest.sha256" ]] || return 1
    grep -Fxq 'A-Box backup manifest v3' "$work/meta/manifest.version" || return 1
    validate_backup_manifest_tree "$work" || return 1
    validate_managed_paths_file "$work/meta/managed-paths.txt" || return 1
    validate_abox_cron_file "$work/meta/cron.abox.txt" || return 1
    grep -Eq '^(iptables|ufw|firewalld)$' "$work/meta/firewall.backend" || return 1
    validate_services_state_file "$work/meta/services.state" || return 1
    [[ -f "$root$ABOX_DIR/.A-Box-owner" && ! -L "$root$ABOX_DIR/.A-Box-owner" ]] || return 1
    grep -Fxq 'A-Box managed directory v1' "$root$ABOX_DIR/.A-Box-owner" 2>/dev/null || return 1
    for srv in xray sing-box hysteria; do
        backup_root_contains_service "$root" "$srv" || continue
        backup_root_service_is_managed "$root" "$srv" || return 1
    done
    local aux_paths=''
    aux_paths=$(managed_auxiliary_paths) || return 1
    while IFS= read -r path; do
        src="$root$path"
        [[ -e "$src" || -L "$src" ]] || continue
        auxiliary_content_is_abox_managed "$src" "$path" || return 1
    done <<< "$aux_paths"
}

assert_restore_target_safe() {
    local root="$1" srv path c=''
    validate_extracted_backup_content "$root" || { msg "${RED}[!] Backup content ownership markers are invalid.${NC}"; return 1; }
    local conflicts=''
    for srv in xray sing-box hysteria; do
        backup_root_contains_service "$root" "$srv" || continue
        conflicts=$(list_foreign_core_conflicts "$srv") || return 1
        c+="$conflicts"$'\n'
    done
    local aux_paths=''
    aux_paths=$(managed_auxiliary_paths) || return 1
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        [[ -e "$root$path" || -L "$root$path" ]] || continue
        [[ ! -e "$path" && ! -L "$path" ]] || auxiliary_path_is_abox_managed "$path" || c+="aux|${path}"$'\n'
    done <<< "$aux_paths"
    [[ -z "${c//$'\n'/}" ]] || { msg "${RED}[!] Restore would overwrite non-A-Box paths:${NC}"; printf '%s' "$c" >&2; return 1; }
}

assert_restore_shortcut_safe() {
    local root="$1"
    [[ -e "$root/usr/local/bin/sb" || -L "$root/usr/local/bin/sb" ]] || return 0
    assert_abox_shortcut_safe /usr/local/bin/sb
}

abox_restore_preserved_name() {
    case "$1" in
        backups|diagnostics|preflight|A-Box.sh|.backup-hmac.key|.runtime.lock|.runtime.lock.d|socket_probe.sh|geo_update.sh|traffic_monitor.sh|firewall_restore.sh|iptables.v4|iptables.v6) return 0 ;;
        *) return 1 ;;
    esac
}

clear_abox_runtime_for_restore() {
    local child base failed=0
    [[ -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] || return 0
    for child in "$ABOX_DIR"/* "$ABOX_DIR"/.[!.]* "$ABOX_DIR"/..?*; do
        [[ -e "$child" || -L "$child" ]] || continue
        base=${child##*/}
        abox_restore_preserved_name "$base" && continue
        path_tree_has_mountpoint "$child" && { msg "${RED}[!] Restore cleanup encountered a mountpoint; aborting before deletion: ${child}${NC}"; return 1; }
    done
    for child in "$ABOX_DIR"/* "$ABOX_DIR"/.[!.]* "$ABOX_DIR"/..?*; do
        [[ -e "$child" || -L "$child" ]] || continue
        base=${child##*/}
        abox_restore_preserved_name "$base" && continue
        rm -rf -- "$child" || failed=1
    done
    (( failed == 0 ))
}

restore_abox_directory() {
    local root="$1" src child base
    src="$root$ABOX_DIR"
    [[ -d "$src" && ! -L "$src" ]] || return 1
    path_parent_chain_safe "$ABOX_DIR" || return 1
    if [[ -e "$ABOX_DIR" || -L "$ABOX_DIR" ]]; then
        [[ -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] || return 1
    else
        install -d -m 700 "$ABOX_DIR" || return 1
    fi
    path_tree_has_mountpoint "$ABOX_DIR" && return 1
    ensure_abox_dir_owned "$ABOX_DIR" || return 1
    for child in "$src"/* "$src"/.[!.]* "$src"/..?*; do
        [[ -e "$child" || -L "$child" ]] || continue
        base=${child##*/}
        abox_restore_preserved_name "$base" && continue
        [[ ! -L "$child" ]] || return 1
        cp -a -- "$child" "$ABOX_DIR/" || return 1
    done
    ensure_abox_dir_owned "$ABOX_DIR" || return 1
}

normalize_restored_runtime_ownership() {
    local family="$1" user group
    IFS=$'\t' read -r user group < <(abox_runtime_identity "$family") || return 1
    ensure_abox_runtime_identity "$family" || return 1
    case "$family" in
        sing-box)
            [[ -d /etc/sing-box && ! -L /etc/sing-box ]] || return 1
            chown -R "root:$group" /etc/sing-box || return 1
            ;;
        hysteria)
            [[ -d /etc/hysteria && ! -L /etc/hysteria ]] || return 1
            chown -R "root:$group" /etc/hysteria || return 1
            if [[ -d /etc/hysteria/acme ]]; then
                [[ ! -L /etc/hysteria/acme ]] || return 1
                chown -R "$user:$group" /etc/hysteria/acme || return 1
                if [[ -f /etc/hysteria/acme/.A-Box-managed ]]; then
                    chown root:root /etc/hysteria/acme/.A-Box-managed || return 1
                    chmod 600 /etc/hysteria/acme/.A-Box-managed || return 1
                fi
                chown "root:$group" /etc/hysteria/acme || return 1
            fi
            ;;
        xray)
            [[ -d /usr/local/etc/xray && ! -L /usr/local/etc/xray ]] || return 1
            chown -R root:root /usr/local/etc/xray || return 1
            ;;
        *) return 1 ;;
    esac
}

regenerate_runtime_assets_after_restore() {
    clear_abox_env_vars
    load_abox_env "$ABOX_ENV" || return 1
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        prepare_abox_runtime_permissions "$srv" || return 1
    done
    setup_shortcut || return 1
    setup_health_monitor || return 1
    setup_geo_cron || return 1
    if valid_traffic_limit_gb "${TRAFFIC_LIMIT_GB:-}"; then
        setup_traffic_monitor || return 1
    else
        disable_traffic_monitor || return 1
    fi
}


restore_tree_path() {
    local root="$1" path="$2" src parent current
    src="$root$path"
    [[ "$path" == /* && "$path" != / ]] || return 1
    parent=$(dirname "$path")
    # Refuse to traverse a symlinked live parent directory.
    current='/'
    IFS='/' read -r -a _parts <<< "${parent#/}"
    for _part in "${_parts[@]}"; do
        [[ -n "$_part" ]] || continue
        current="${current%/}/$_part"
        [[ -L "$current" ]] && return 1
    done
    if [[ "$parent" != "/" ]] && path_is_mountpoint "$parent"; then
        return 1
    fi
    if [[ ! -e "$src" && ! -L "$src" ]]; then
        # Even when the backup has no matching target, the live target may
        # contain nested mounts. Treat the whole target tree as protected so
        # cleanup cannot recurse into an unrelated mounted filesystem.
        path_tree_has_mountpoint "$path" && return 1
        rm -rf -- "$path"
        return 0
    fi
    [[ ! -L "$src" ]] || return 1
    path_tree_has_mountpoint "$path" && return 1
    mkdir -p "$parent" || return 1
    rm -rf -- "$path" || return 1
    cp -a -- "$src" "$parent/" || return 1
    [[ ! -L "$path" ]]
}

restore_shortcut_from_backup() {
    local root="$1" src
    src="$root/usr/local/bin/sb"
    if [[ -e "$src" || -L "$src" ]]; then
        auxiliary_content_is_abox_managed "$src" /usr/local/bin/sb || return 1
        assert_abox_shortcut_safe /usr/local/bin/sb
        restore_tree_path "$root" /usr/local/bin/sb
    else
        remove_abox_shortcut /usr/local/bin/sb
    fi
}

restore_auxiliary_path_from_backup() {
    local root="$1" path="$2" src
    src="$root$path"
    [[ "$path" != /usr/local/bin/sb ]] || { restore_shortcut_from_backup "$root"; return; }
    if [[ -e "$src" || -L "$src" ]]; then
        auxiliary_content_is_abox_managed "$src" "$path" || return 1
        [[ ! -e "$path" && ! -L "$path" ]] || auxiliary_path_is_abox_managed "$path" || return 1
        restore_tree_path "$root" "$path"
    else
        remove_owned_auxiliary_path "$path"
    fi
}

restore_core_family_from_backup() {
    local root="$1" srv="$2" path core_paths='' contains_rc=0 backup_init current_init
    backup_root_contains_service "$root" "$srv"
    contains_rc=$?
    case "$contains_rc" in
        0) ;;
        1) return 0 ;;
        *) return 1 ;;
    esac
    backup_root_service_is_managed "$root" "$srv" || return 1
    backup_init=$(backup_root_service_init "$root" "$srv") || return 1
    current_init=$(effective_init_system) || return 1
    [[ "$backup_init" == "$current_init" ]] || {
        msg "${RED}[!] Backup for ${srv} uses ${backup_init}, but this VPS uses ${current_init}; refusing cross-init restore.${NC}"
        return 1
    }
    core_paths=$(core_family_paths "$srv") || return 1
    [[ -n "$core_paths" ]] || return 1
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        restore_tree_path "$root" "$path" || return 1
    done <<< "$core_paths"
    normalize_restored_runtime_ownership "$srv" || return 1
}


restore_cron_from_file() {
    local f="$1" tmp current err
    [[ -r "$f" && -f "$f" && ! -L "$f" ]] || return 0
    validate_abox_cron_file "$f" || return 1
    tmp=$(umask 077; mktemp /tmp/A-Box-cron-restore.XXXXXX) || return 1
    current=$(umask 077; mktemp /tmp/A-Box-cron-current.XXXXXX) || { rm -f "$tmp"; return 1; }
    err=$(umask 077; mktemp /tmp/A-Box-cron-error.XXXXXX) || { rm -f "$tmp" "$current"; return 1; }
    if LC_ALL=C crontab -l > "$current" 2> "$err"; then :
    elif grep -Eqi 'no crontab|no crontab for' "$err"; then : > "$current"
    else rm -f "$tmp" "$current" "$err"; return 1
    fi
    strip_abox_cron_blocks_from_file "$current" "$tmp" || { rm -f "$tmp" "$current" "$err"; return 1; }
    cat "$f" >> "$tmp" || { rm -f "$tmp" "$current" "$err"; return 1; }
    local rc=0
    commit_crontab_if_unchanged "$current" "$tmp" || rc=$?
    rm -f "$tmp" "$current" "$err"
    return "$rc"
}

backup_current_config() {
    local ts unique backup_dir work root tarball backup_failed=0 backend srv path _abox_links _old_backups
    valid_backup_retention_count "$BACKUP_RETENTION_COUNT" || die 'BACKUP_RETENTION_COUNT 无效；必须是 0-1000 的整数。'
    ts=$(date +%Y%m%d-%H%M%S); unique=$(openssl rand -hex 3 2>/dev/null || printf '%s' "$$")
    backup_dir="${1:-$ABOX_DIR/backups}"
    [[ "$backup_dir" == /* ]] || die 'Backup directory must be an absolute path.'
    path_parent_chain_safe "$backup_dir/.A-Box-backup-destination" || die 'Backup directory parent chain is unsafe.'
    if [[ -e "$backup_dir" || -L "$backup_dir" ]]; then
        [[ -d "$backup_dir" && ! -L "$backup_dir" ]] || die 'Backup directory is not a safe regular directory.'
        path_owned_by_root "$backup_dir" || die 'Backup directory is not root-owned.'
        path_mode_has_no_group_other_write "$backup_dir" || die 'Backup directory permissions are unsafe.'
    fi
    work=$(mktemp -d /tmp/A-Box-backup.XXXXXX) || die 'Backup temp directory creation failed.'
    root="$work/root"; install -d -m 700 "$backup_dir" "$root" "$work/meta" || { rm -rf "$work"; die 'Backup directory creation failed.'; }
    path_owned_by_root "$backup_dir" || { rm -rf "$work"; die 'Backup directory ownership verification failed.'; }
    path_mode_has_no_group_other_write "$backup_dir" || { rm -rf "$work"; die 'Backup directory permissions verification failed.'; }
    local managed_paths='' core_paths=''
    managed_paths=$(managed_auxiliary_paths) || { rm -rf "$work"; die 'Managed path list creation failed.'; }
    for srv in xray sing-box hysteria; do
        core_paths=$(core_family_paths "$srv") || { rm -rf "$work"; die "Core path enumeration failed: $srv"; }
        managed_paths+=$'\n'"$core_paths"
    done
    printf '%s\n' "$managed_paths" | awk 'NF && !seen[$0]++' > "$work/meta/managed-paths.txt" || { rm -rf "$work"; die 'Managed path list write failed.'; }
    msg "${YELLOW}[*] Creating A-Box configuration backup...${NC}"
    backup_copy_path() {
        local src="$1" dst links
        [[ -e "$src" ]] || return 0
        [[ ! -L "$src" ]] || { backup_failed=1; return 1; }
        # A managed path may acquire a nested mount after ownership was recorded.
        # Never let cp -a traverse into an external filesystem/bind mount during backup.
        path_tree_has_mountpoint "$src" && { backup_failed=1; return 1; }
        if [[ -d "$src" ]]; then
            links=$(find "$src" -type l -print 2>/dev/null) || { backup_failed=1; return 1; }
            [[ -z "$links" ]] || { backup_failed=1; return 1; }
        fi
        dst="$root$src"
        mkdir -p "$(dirname "$dst")" || { backup_failed=1; return 1; }
        cp -a -- "$src" "$dst" || backup_failed=1
    }
    if [[ -d "$ABOX_DIR" ]]; then
        # The A-Box data directory itself can live on a separate filesystem, but
        # a nested mount must never be traversed by tar during backup. This also
        # catches same-device bind mounts that --one-file-system cannot detect.
        path_tree_has_nested_mountpoint "$ABOX_DIR" && backup_failed=1
        _abox_links=$(find "$ABOX_DIR" -path "$ABOX_DIR/backups" -prune -o -path "$ABOX_DIR/diagnostics" -prune -o -path "$ABOX_DIR/preflight" -prune -o -type l -print 2>/dev/null) || backup_failed=1
        if [[ -n "${_abox_links:-}" ]]; then
            backup_failed=1
        else
            mkdir -p "$root$ABOX_DIR" || backup_failed=1
            [[ "$backup_failed" == 0 ]] && (cd "$ABOX_DIR" && tar \
                --exclude='./backups' --exclude='./diagnostics' --exclude='./preflight' \
                --exclude='./A-Box.sh' --exclude='./.backup-hmac.key' --exclude='./.runtime.lock' --exclude='./.runtime.lock.d' \
                --exclude='./socket_probe.sh' --exclude='./geo_update.sh' --exclude='./traffic_monitor.sh' \
                --exclude='./firewall_restore.sh' --exclude='./iptables.v4' --exclude='./iptables.v6' \
                -cpf - . | tar -C "$root$ABOX_DIR" -xpf -) || backup_failed=1
        fi
    fi
    shortcut_is_abox_managed /usr/local/bin/sb && backup_copy_path /usr/local/bin/sb
    for srv in xray sing-box hysteria; do
        if abox_owns_service "$srv"; then
            core_paths=$(core_family_paths "$srv") || { rm -rf "$work"; die "Core path enumeration failed during backup: $srv"; }
            while IFS= read -r path; do
                [[ -n "$path" ]] || continue
                backup_copy_path "$path"
            done <<< "$core_paths"
        fi
    done
    local aux_paths=''
    aux_paths=$(managed_auxiliary_paths) || { rm -rf "$work"; die 'Managed auxiliary path enumeration failed during backup.'; }
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        auxiliary_path_is_abox_managed "$path" && backup_copy_path "$path"
    done <<< "$aux_paths"
    { echo 'A-Box backup'; echo "Created: $(now_iso)"; echo "Host: $(hostname 2>/dev/null || true)"; echo "Kernel: $(uname -a 2>/dev/null || true)"; echo "Init: ${INIT_SYS:-unknown}"; echo "Script SHA256: $(sha256sum "$0" 2>/dev/null | awk '{print $1}')"; } > "$work/meta/metadata.txt"
    collect_abox_cron > "$work/meta/cron.abox.txt" 2>/dev/null || backup_failed=1
    capture_managed_service_state "$work/meta/services.state" || backup_failed=1
    backend=$(firewall_backend); printf '%s\n' "$backend" > "$work/meta/firewall.backend"
    capture_abox_iptables_snapshot "$work/meta/iptables.snapshot" 4 || backup_failed=1
    capture_abox_iptables_snapshot "$work/meta/ip6tables.snapshot" 6 || backup_failed=1
    (( backup_failed == 0 )) || { rm -rf "$work"; die 'Backup aborted because an existing A-Box path could not be copied.'; }
    printf '%s\n' 'A-Box backup manifest v3' > "$work/meta/manifest.version"
    create_backup_manifest "$work" "$work/meta/manifest.sha256" || { rm -rf "$work"; die 'Backup manifest creation failed.'; }
    tarball="$backup_dir/A-Box-backup-${ts}-${unique}.tar.gz"
    tar -C "$work" -czf "$tarball" root meta || { rm -rf "$work"; rm -f "$tarball"; die 'Backup tarball creation failed.'; }
    chmod 600 "$tarball"; validate_backup_archive "$tarball" || { rm -rf "$work"; rm -f "$tarball"; die 'Backup archive validation failed.'; }
    backup_checksum_write "$tarball" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256"; die 'Backup SHA256 creation failed.'; }
    backup_auth_write "$tarball" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256" "${tarball}.hmac"; die 'Backup HMAC authentication creation failed.'; }
    local backup_dir_real abox_dir_real
    backup_dir_real=$(canonical_path "$backup_dir") || { rm -rf "$work"; die 'Backup directory canonicalization failed.'; }
    abox_dir_real=$(canonical_path "$ABOX_DIR") || { rm -rf "$work"; die 'A-Box directory canonicalization failed.'; }
    if [[ "$backup_dir_real" != "$abox_dir_real" && "$backup_dir_real" != "$abox_dir_real/"* ]]; then
        # External destinations leave ABOX_DIR (and .backup-hmac.key) behind.
        # Write the recovery key primarily under /root/A-Box-backup-keys/ (mode 700)
        # and also place a discoverable ${tarball}.key sidecar for restore helpers.
        local recovery_key="${tarball}.key" key_value keys_dir='/root/A-Box-backup-keys' separated_key
        separated_key="$keys_dir/$(basename "$tarball").key"
        IFS= read -r key_value < "$ABOX_BACKUP_KEY" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256" "${tarball}.hmac"; die 'External backup recovery key read failed.'; }
        install -d -m 700 -o root -g root -- "$keys_dir" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256" "${tarball}.hmac"; die 'Backup keys directory creation failed.'; }
        if [[ ! -e "$separated_key" && ! -L "$separated_key" ]]; then
            write_private_sidecar "$separated_key" "$key_value" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256" "${tarball}.hmac" "$separated_key"; die 'Separated recovery key write failed.'; }
        fi
        if [[ ! -e "$recovery_key" && ! -L "$recovery_key" ]]; then
            write_private_sidecar "$recovery_key" "$key_value" || { rm -rf "$work"; rm -f "$tarball" "${tarball}.sha256" "${tarball}.hmac" "$recovery_key"; die 'External backup recovery key sidecar write failed.'; }
        fi
        msg "${GREEN}[*] Recovery key (separated):${NC} $separated_key"
        msg "${GREEN}[*] Recovery key (sidecar for restore discovery):${NC} $recovery_key"
        msg "${YELLOW}[!] Prefer keeping the separated key offline via --export-backup-key; anyone with archive+HMAC+key can authenticate modified archives.${NC}"
    fi
    rm -rf "$work"
    ABOX_LAST_BACKUP="$tarball"
    _old_backups=()
    local _old_backups_output=''
    if _old_backups_output=$(python3 - "$backup_dir" "$BACKUP_RETENTION_COUNT" <<'PY_BACKUP_RETENTION'
from pathlib import Path
import sys
root=Path(sys.argv[1]); keep=int(sys.argv[2])
items=[]
for p in root.glob('A-Box-backup-*.tar.gz'):
    try:
        if p.is_file() and not p.is_symlink(): items.append((p.stat().st_mtime_ns, str(p)))
    except OSError: pass
for _, name in sorted(items, reverse=True)[keep:]: print(name)
PY_BACKUP_RETENTION
); then
        [[ -z "$_old_backups_output" ]] || mapfile -t _old_backups <<< "$_old_backups_output"
        for _old in "${_old_backups[@]}"; do [[ "$_old" == "$ABOX_LAST_BACKUP" ]] || rm -f -- "$_old" "${_old}.sha256" "${_old}.hmac" "${_old}.key"; done
    else
        msg "${YELLOW}[!] Backup retention enumeration failed; keeping existing backups unchanged.${NC}"
    fi
    msg "${GREEN}[*] Backup created:${NC} $tarball"
}

auto_backup_prompt() {
    local reason="${1:-operation}" dest="${2:-$ABOX_DIR/backups}" answer
    msg "${YELLOW}[!] Backup recommended before: ${reason}${NC}"
    read -r -p 'Create backup now? [Y/N]: ' answer
    if is_yes "$answer"; then
        backup_current_config "$dest"
    else
        msg "${YELLOW}[*] Backup skipped by user.${NC}"
    fi
}

auto_backup_silent() {
    local reason="${1:-operation}" dest="${2:-$ABOX_DIR/backups}"
    msg "${YELLOW}[*] Auto backup before: ${reason}${NC}"
    backup_current_config "$dest"
}

restore_latest_backup_silent() {
    local backup_dir="${1:-$ABOX_DIR/backups}" selected="${2:-}" key_file="${3:-}" work root backend mode=all srv
    [[ -d "$backup_dir" ]] || return 1
    if [[ -n "$selected" ]]; then
        [[ -f "$selected" && "$(dirname "$selected")" == "$backup_dir" ]] || return 1
    else
        selected=$(find "$backup_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' -print | sort -r | sed -n '1p')
    fi
    [[ -n "$selected" ]] || return 1
    backup_checksum_verify "$selected" "${selected}.sha256" || return 1
    if [[ -n "$key_file" ]]; then
        backup_auth_verify_with_key_file "$selected" "${selected}.hmac" "$key_file" || return 1
    else
        backup_auth_verify "$selected" "${selected}.hmac" || return 1
    fi
    validate_backup_archive "$selected" || return 1
    work=$(mktemp -d /tmp/A-Box-rollback.XXXXXX) || return 1; chmod 700 "$work"
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; return 1; }
    root="$work/root"; assert_restore_target_safe "$root" || { rm -rf "$work"; return 1; }; assert_restore_shortcut_safe "$root" || { rm -rf "$work"; return 1; }; validate_backup_core_init_compatibility "$root" || { rm -rf "$work"; return 1; }
    stop_all_managed_services >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    clean_nat_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    clean_input_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    remove_all_owned_core_families || { rm -rf "$work"; return 1; }
    clear_abox_runtime_for_restore || { rm -rf "$work"; return 1; }
    restore_abox_directory "$root" || { rm -rf "$work"; return 1; }
    for srv in xray sing-box hysteria; do restore_core_family_from_backup "$root" "$srv" || { rm -rf "$work"; return 1; }; done
    local aux_paths=''
    aux_paths=$(managed_auxiliary_paths) || { rm -rf "$work"; return 1; }
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        restore_auxiliary_path_from_backup "$root" "$path" || { rm -rf "$work"; return 1; }
    done <<< "$aux_paths"
    regenerate_runtime_assets_after_restore >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    apply_native_firewall_rules_from_state >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    backend=$(cat "$work/meta/firewall.backend" 2>/dev/null || echo iptables); [[ "$backend" == iptables ]] || mode=special
    restore_abox_iptables_snapshot "$work/meta/iptables.snapshot" 4 "$mode" || { rm -rf "$work"; return 1; }
    restore_abox_iptables_snapshot "$work/meta/ip6tables.snapshot" 6 "$mode" || { rm -rf "$work"; return 1; }
    load_abox_env "$ABOX_ENV" >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    enforce_ss_whitelist_order "${SS_PORT:-}" || { rm -rf "$work"; return 1; }
    save_firewall_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl daemon-reload >/dev/null 2>&1 || { rm -rf "$work"; return 1; }; fi
    restore_managed_service_state "$work/meta/services.state" || { rm -rf "$work"; return 1; }
    rm -rf "$work"; msg "${GREEN}[*] Rollback restored backup:${NC} $selected"
}

restore_from_backup() {
    local backup_dir="$ABOX_DIR/backups" backups i choice selected work root answer backend mode=all srv path targets='' backups_output=''
    if ! backups_output=$(
        for _dir in "$ABOX_DIR/backups" /root/A-Box-backups; do
            [[ -d "$_dir" && ! -L "$_dir" ]] || continue
            find "$_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' -print
        done | sort -ru
    ); then
        msg "${RED}[!] Failed to enumerate A-Box backups; restore was not started.${NC}"
        pause_return
        return
    fi
    backups=()
    [[ -z "$backups_output" ]] || mapfile -t backups <<< "$backups_output"
    (( ${#backups[@]} )) || { msg "${RED}[!] No A-Box backup tarballs found in $ABOX_DIR/backups or /root/A-Box-backups.${NC}"; pause_return; return; }
    clear
    for i in "${!backups[@]}"; do printf '%2d. %s\n' "$((i+1))" "${backups[$i]}"; done
    read -r -p 'Select backup (0 back): ' choice
    [[ "$choice" == 0 ]] && return
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || ! valid_decimal_upto "$choice" "${#backups[@]}"; then
        msg "${RED}[!] Invalid selection.${NC}"
        pause_return
        return
    fi
    selected="${backups[$((10#$choice-1))]}"
    backup_checksum_verify "$selected" "${selected}.sha256" || die 'Backup SHA256 is missing or invalid.'
    prepare_backup_auth_for_manual_restore "$selected" || die 'Backup HMAC/recovery-key authentication failed or was not authorized.'
    validate_backup_archive "$selected" || die 'Backup archive structure/link validation failed.'
    work=$(mktemp -d /tmp/A-Box-restore.XXXXXX) || die 'Restore temp directory creation failed.'
    chmod 700 "$work"
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; die 'Backup extraction failed.'; }
    root="$work/root"
    assert_restore_target_safe "$root" || { rm -rf "$work"; die 'Restore target ownership check failed.'; }
    assert_restore_shortcut_safe "$root" || { rm -rf "$work"; die 'Restore shortcut ownership check failed.'; }
    validate_backup_core_init_compatibility "$root" || { rm -rf "$work"; die 'Backup init system is incompatible with the current VPS; restore was aborted before destructive changes.'; }
    msg "${YELLOW}[!] Restore will replace only A-Box-owned paths and A-Box firewall rules.${NC}"
    read -r -p 'Continue restore? [Y/N]: ' answer
    is_yes "$answer" || { rm -rf "$work"; return; }

    ABOX_LAST_BACKUP=''
    backup_current_config "$backup_dir"
    [[ -n "$ABOX_LAST_BACKUP" && -f "$ABOX_LAST_BACKUP" ]] || { rm -rf "$work"; die 'Pre-restore snapshot creation failed.'; }
    for srv in xray sing-box hysteria; do
        if abox_owns_service "$srv" || backup_root_contains_service "$root" "$srv"; then
            targets+=" ${srv}"
        fi
    done
    ABOX_DEPLOY_TX_ACTIVE=1
    ABOX_DEPLOY_TX_REASON='manual backup restore'
    ABOX_DEPLOY_TX_TARGETS="${targets# }"
    ABOX_DEPLOY_TX_BACKUP="$ABOX_LAST_BACKUP"
    ABOX_DEPLOY_TX_TMP="$work"
    ABOX_DIE_HOOK=deployment_transaction_rollback
    install_deployment_transaction_traps

    stop_all_managed_services || die '恢复前无法停止全部 A-Box 托管服务。'
    clean_nat_rules || die '恢复前无法完整删除 A-Box HY2 NAT 规则。'
    clean_input_rules || die '恢复前无法完整删除 A-Box INPUT/原生防火墙规则。'
    remove_all_owned_core_families || die '恢复前删除当前 A-Box 核心文件失败。'
    clear_abox_runtime_for_restore || die '恢复前清理 A-Box 运行目录失败。'
    restore_abox_directory "$root" || die 'Restore A-Box directory failed.'
    for srv in xray sing-box hysteria; do
        restore_core_family_from_backup "$root" "$srv" || die "Restore failed for core family: $srv"
    done
    local aux_paths=''
    aux_paths=$(managed_auxiliary_paths) || die '无法枚举 A-Box 辅助文件，恢复已中止。'
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        restore_auxiliary_path_from_backup "$root" "$path" || die "Restore failed: $path"
    done <<< "$aux_paths"
    chmod 700 "$ABOX_DIR" 2>/dev/null || die '恢复后的 A-Box 目录权限加固失败。'
    chmod 600 "$ABOX_ENV" 2>/dev/null || die '恢复后的 .env 权限加固失败。'
    regenerate_runtime_assets_after_restore || die 'Regenerate trusted A-Box runtime helpers and cron blocks failed.'
    apply_native_firewall_rules_from_state || die 'Restore native firewall rules failed.'
    backend=$(cat "$work/meta/firewall.backend" 2>/dev/null || echo iptables)
    [[ "$backend" == iptables ]] || mode=special
    restore_abox_iptables_snapshot "$work/meta/iptables.snapshot" 4 "$mode" || die 'IPv4 A-Box firewall restore failed.'
    restore_abox_iptables_snapshot "$work/meta/ip6tables.snapshot" 6 "$mode" || die 'IPv6 A-Box firewall restore failed.'
    load_abox_env "$ABOX_ENV" >/dev/null 2>&1 || die '恢复后的 A-Box 环境文件校验失败。'
    enforce_ss_whitelist_order "${SS_PORT:-}" || die 'Restored SS whitelist order validation failed.'
    save_firewall_rules || die 'Restored A-Box firewall persistence failed.'
    if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl daemon-reload >/dev/null 2>&1 || die 'systemd daemon-reload after restore failed.'; fi
    restore_managed_service_state "$work/meta/services.state" || die 'Restored service state failed validation/startup.'
    for srv in xray sing-box hysteria; do
        if abox_owns_service "$srv"; then
            record_core_family_ownership "$srv" || die "Restored ${srv} ownership manifest update failed; restore was not committed."
        fi
    done
    commit_deployment_transaction
    rm -rf "$work"
    msg "${GREEN}[*] Restore completed.${NC}"
    pause_return
}

backup_restore_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Backup / Restore / 配置备份与恢复${NC}"
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}1. Backup current A-Box configuration${NC}"
        msg "${YELLOW}2. Restore from backup${NC}"
        msg "${YELLOW}3. Export recovery key to a separate medium${NC}"
        msg "${YELLOW}4. Convert a legacy backup to manifest v3${NC}"
        msg "${GREEN}0. Back${NC}"
    else
        msg "${YELLOW}1. 备份当前 A-Box 配置${NC}"
        msg "${YELLOW}2. 从备份恢复${NC}"
        msg "${YELLOW}3. 将恢复密钥导出到独立介质${NC}"
        msg "${YELLOW}4. 将旧版备份安全转换为 manifest v3${NC}"
        msg "${GREEN}0. 返回${NC}"
    fi
    local c
    read -r -p 'Select [0-4]: ' c
    case "$c" in
        1) backup_current_config; pause_return ;;
        2) restore_from_backup ;;
        3)
            local key_dest
            read -r -p 'Absolute path on a separate trusted medium: ' key_dest
            export_backup_recovery_key "$key_dest"; pause_return
            ;;
        4)
            local legacy_path legacy_out
            read -r -p 'Legacy .tar.gz path: ' legacy_path
            read -r -p 'Output directory (default: same directory): ' legacy_out
            convert_legacy_backup_archive "$legacy_path" "${legacy_out:-$(dirname "$legacy_path")}"; pause_return
            ;;
        *) return 0 ;;
    esac
}

write_diagnostic_checksum() {
    local bundle="$1" checksum="$2" tmp dir
    [[ -f "$bundle" && ! -L "$bundle" ]] || return 1
    [[ ! -L "$checksum" && (! -e "$checksum" || -f "$checksum") ]] || return 1
    path_parent_chain_safe "$checksum" || return 1
    dir=$(dirname "$checksum")
    [[ -d "$dir" && ! -L "$dir" ]] || return 1
    tmp=$(mktemp "${checksum}.A-Box-new.XXXXXX") || return 1
    if ! sha256sum "$bundle" > "$tmp" 2>/dev/null; then
        rm -f -- "$tmp"
        return 1
    fi
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    if [[ $EUID -eq 0 ]]; then
        chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
    fi
    mv -f -- "$tmp" "$checksum" || { rm -f -- "$tmp"; return 1; }
    [[ -s "$checksum" && ! -L "$checksum" ]] || return 1
    return 0
}

export_diagnostic_bundle() {
    local ts diag_dir work bundle checksum
    ts=$(date +%Y%m%d-%H%M%S)
    diag_dir="$ABOX_DIR/diagnostics"
    work=$(mktemp -d /tmp/A-Box-diagnostic.XXXXXX) || die 'Diagnostic temp directory creation failed.'
    mkdir -p "$diag_dir" "$work/logs" || { rm -rf -- "$work"; die '诊断目录创建失败。'; }
    chmod 700 "$diag_dir" 2>/dev/null || { rm -rf -- "$work"; die '诊断目录权限设置失败。'; }

    msg "${YELLOW}[*] Collecting diagnostic information with secret redaction...${NC}"
    {
        echo "A-Box diagnostic bundle"
        echo "Created: $(now_iso)"
        echo "Host: $(hostname 2>/dev/null || true)"
        echo "Script: $0"
        echo "Script SHA256: $(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
    } > "$work/summary.txt"

    { uname -a 2>/dev/null; echo; cat /etc/os-release 2>/dev/null || true; echo; command -v systemctl >/dev/null 2>&1 && systemctl --version 2>/dev/null | head -n 3 || true; } > "$work/system.txt"
    { ip addr 2>/dev/null || true; echo; ip route 2>/dev/null || true; echo; ip -6 route 2>/dev/null || true; echo; ss -lntup 2>/dev/null || true; } > "$work/network.txt"
    { show_status_report 2>/dev/null || true; echo; for c in xray sing-box hysteria; do command -v "$c" >/dev/null 2>&1 && "$c" version 2>/dev/null | head -n 5; done; } > "$work/status.txt"
    { iptables -S 2>/dev/null | grep 'A-Box' || true; echo; iptables -t nat -S 2>/dev/null | grep 'A-Box' || true; echo; ip6tables -S 2>/dev/null | grep 'A-Box' || true; echo; ip6tables -t nat -S 2>/dev/null | grep 'A-Box' || true; } > "$work/firewall.txt"
    collect_abox_cron > "$work/cron.txt" 2>/dev/null || true
    if [[ -e "$ABOX_ENV" || -L "$ABOX_ENV" ]]; then
        write_redacted_file "$ABOX_ENV" "$work/env.redacted" || { rm -rf "$work"; die 'Diagnostic secret redaction failed; refusing to create a misleading bundle.'; }
    else
        printf '%s\n' 'A-Box environment file is not present.' > "$work/env.redacted" || { rm -rf "$work"; die 'Diagnostic environment placeholder creation failed.'; }
    fi

    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u xray --no-pager -n 120 2>/dev/null | redact_secrets_stream > "$work/logs/xray.journal.txt" || true
        journalctl -u sing-box --no-pager -n 120 2>/dev/null | redact_secrets_stream > "$work/logs/sing-box.journal.txt" || true
        journalctl -u hysteria --no-pager -n 120 2>/dev/null | redact_secrets_stream > "$work/logs/hysteria.journal.txt" || true
    fi
    for f in /var/log/A-Box-xray-error.log /var/log/A-Box-xray-access.log /var/log/A-Box-singbox.log /var/log/A-Box-hysteria.log; do
        [[ -r "$f" ]] && tail -n 200 "$f" 2>/dev/null | redact_secrets_stream > "$work/logs/$(basename "$f").tail.txt" || true
    done

    bundle="$diag_dir/A-Box-diagnostic-${ts}.tar.gz"
    tar -C "$work" -czf "$bundle" . || { rm -rf "$work"; die 'Diagnostic bundle creation failed.'; }
    chmod 600 "$bundle" 2>/dev/null || { rm -rf "$work"; rm -f "$bundle"; die 'Diagnostic bundle permission hardening failed.'; }
    checksum="${bundle}.sha256"
    write_diagnostic_checksum "$bundle" "$checksum" || { rm -rf "$work"; rm -f "$bundle"; die 'Diagnostic bundle checksum generation failed.'; }
    rm -rf "$work"
    msg "${GREEN}[*] Diagnostic bundle:${NC}" $bundle
    msg "${GREEN}[*] SHA256:${NC}" $checksum
    pause_return
}


default_route_uses_warp() {
    local dev=''
    dev=$(ip -o route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
    [[ "$dev" =~ ^(wg|warp|tun|CloudflareWARP)[0-9A-Za-z_.-]*$ ]]
}


light_preflight_check() {
    local fail=0 warn=0 c
    msg "${YELLOW}[*] Running lightweight preflight check...${NC}"
    [[ $EUID -eq 0 ]] || { msg "${RED}[FAIL] root privilege required${NC}"; fail=$((fail+1)); }
    [[ -t 0 ]] || { msg "${YELLOW}[WARN] no interactive TTY on stdin${NC}"; warn=$((warn+1)); }
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|alpine|fedora|amzn|ol|oracle) msg "${GREEN}[PASS] OS: ${ID:-unknown}${NC}" ;; *) msg "${YELLOW}[WARN] OS may be unsupported: ${ID:-unknown}${NC}"; warn=$((warn+1)) ;; esac
    else
        msg "${YELLOW}[WARN] /etc/os-release not readable${NC}"; warn=$((warn+1))
    fi
    local route_dev warp_confirm=''
    route_dev=$(ip -o route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
    if default_route_uses_warp; then
        msg "${YELLOW}[WARN] 默认公网路由经由 $route_dev；REALITY dest、HY2 伪装和公网 IP 探测可能使用该出口。${NC}"
        if [[ -t 0 ]]; then
            read -r -p '仍要使用当前默认公网路由继续部署吗？[Y/N]: ' warp_confirm || warp_confirm='N'
            is_yes "$warp_confirm" || { msg "${RED}[FAIL] 未确认使用 wg/warp/tun 默认出口。${NC}"; fail=$((fail+1)); }
        else
            msg "${RED}[FAIL] 非交互部署检测到 wg/warp/tun 默认出口；必须显式在交互环境确认后再部署。${NC}"
            fail=$((fail+1))
        fi
    fi
    if systemd_available; then
        msg "${GREEN}[PASS] init: systemd${NC}"
    elif command -v rc-service >/dev/null 2>&1; then
        msg "${GREEN}[PASS] init: OpenRC${NC}"
    else
        msg "${RED}[FAIL] no supported init system detected${NC}"; fail=$((fail+1))
    fi
    case "$(uname -m)" in x86_64|amd64|aarch64|arm64) msg "${GREEN}[PASS] arch: $(uname -m)${NC}" ;; *) msg "${RED}[FAIL] unsupported arch: $(uname -m)${NC}"; fail=$((fail+1)) ;; esac
    for c in bash curl jq openssl unzip tar iptables ss lsof python3 getent flock qrencode fail2ban-client; do
        command -v "$c" >/dev/null 2>&1 || { msg "${YELLOW}[WARN] command missing before dependency sync: $c${NC}"; warn=$((warn+1)); }
    done
    if curl -fsS --connect-timeout 3 -m 6 https://api.github.com >/dev/null 2>&1; then
        msg "${GREEN}[PASS] GitHub API reachable${NC}"
    else
        msg "${YELLOW}[WARN] GitHub API unreachable now; official release metadata/digest cannot be verified and core installation may fail${NC}"; warn=$((warn+1))
    fi
    if (( fail > 0 )); then
        die "Lightweight preflight found blocking failures."
    fi
    msg "${GREEN}[*] Lightweight preflight completed. WARN=${warn}${NC}"
    unset -f pf_pass pf_warn pf_fail 2>/dev/null || true
}

preflight_check() {
    local report_dir report fail=0 warn=0 port proto holder now interactive=1
    local _pf_lock_held=0
    [[ "${1:-}" == '--no-pause' ]] && interactive=0
    if [[ ${EUID:-0} -eq 0 ]] && command -v flock >/dev/null 2>&1 && [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
        exec 8>>"$LOCK_FILE" 2>/dev/null || true
        if flock -s -n 8 2>/dev/null; then _pf_lock_held=1; fi
    fi
    report_dir=$(umask 077; mktemp -d /tmp/A-Box-preflight.XXXXXX) || die 'Preflight report directory creation failed.'
    chmod 700 "$report_dir" || { rm -rf -- "$report_dir"; die 'Preflight report directory permission setup failed.'; }
    report="$report_dir/A-Box-preflight-$(date +%Y%m%d-%H%M%S).txt"

    pf_pass() { printf '[PASS] %s\n' "$*" | tee -a "$report"; }
    pf_warn() { warn=$((warn+1)); printf '[WARN] %s\n' "$*" | tee -a "$report"; }
    pf_fail() { fail=$((fail+1)); printf '[FAIL] %s\n' "$*" | tee -a "$report"; }

    : > "$report"
    echo "A-Box preflight check: $(now_iso)" | tee -a "$report"
    echo "----------------------------------------------------------------------" | tee -a "$report"

    [[ $EUID -eq 0 ]] && pf_pass 'root privilege available' || pf_fail 'not running as root'
    [[ -t 0 ]] && pf_pass 'interactive TTY available' || pf_warn 'no interactive TTY on stdin'
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|alpine|fedora|amzn|ol|oracle) pf_pass "supported OS detected: ${ID:-unknown}" ;; *) pf_warn "OS may be unsupported: ${ID:-unknown}" ;; esac
    else
        pf_warn '/etc/os-release not readable'
    fi
    if systemd_available; then
        INIT_SYS='systemd'
        pf_pass 'systemd detected'
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYS='openrc'
        pf_pass 'OpenRC detected'
    else
        pf_fail 'no supported init system detected'
    fi
    case "$(uname -m)" in x86_64|amd64|aarch64|arm64) pf_pass "supported CPU architecture: $(uname -m)" ;; *) pf_fail "unsupported CPU architecture: $(uname -m)" ;; esac

    for c in bash curl jq openssl bc unzip tar iptables ss lsof vnstat python3 getent flock qrencode fail2ban-client; do
        command -v "$c" >/dev/null 2>&1 && pf_pass "command available: $c" || pf_warn "command missing before dependency sync: $c"
    done

    if curl -fsS --connect-timeout 5 -m 10 https://api.github.com >/dev/null 2>&1; then
        pf_pass 'GitHub API reachable'
    else
        pf_warn 'GitHub API unreachable from this host now; official release metadata/digest cannot be verified and core installation may fail'
    fi

    local preflight_pairs='' env_present=0
    if [[ -e "$ABOX_ENV" || -L "$ABOX_ENV" ]]; then
        env_present=1
        if ! load_abox_env "$ABOX_ENV" >/dev/null 2>&1; then
            pf_fail "A-Box environment state exists but failed trust/parse validation: $ABOX_ENV"
        elif ! validate_abox_env_semantics >/dev/null 2>&1; then
            pf_fail "A-Box environment state failed semantic validation: $ABOX_ENV"
        else
            preflight_pairs=$(selected_port_pairs | awk 'NF' | sort -u) || preflight_pairs=''
        fi
    fi
    if (( env_present == 0 )); then
        preflight_pairs=$'tcp/443\ntcp/8443\ntcp/2053\nudp/2053'
    fi
    if ! command -v ss >/dev/null 2>&1; then
        pf_warn 'ss is unavailable; port occupancy audit skipped'
    else
        local -a preflight_pairs_arr=()
        if [[ -n "$preflight_pairs" ]]; then
            mapfile -t preflight_pairs_arr <<< "$preflight_pairs"
        fi
        for pair in "${preflight_pairs_arr[@]}"; do
            [[ "$pair" =~ ^(tcp|udp)/([0-9]+)$ ]] || continue
            proto=${BASH_REMATCH[1]}
            port=${BASH_REMATCH[2]}
            local preflight_ss_output
            if ! preflight_ss_output=$(ss -H -n -l -p -A "$proto" 2>/dev/null); then
                pf_warn "ss failed for ${proto}; port occupancy audit skipped for ${proto}"
                continue
            fi
            local holder managed_owner
            holder=$(grep -E "[:.]${port}([[:space:]]|$)" <<< "$preflight_ss_output" || true)
            if [[ -n "$holder" ]]; then
                managed_owner=$(managed_socket_owner_for_port "$proto" "$port" 2>/dev/null || true)
                if [[ -n "$managed_owner" ]]; then
                    pf_pass "${port}/${proto} occupied by managed A-Box service: ${managed_owner}"
                else
                    pf_warn "${port}/${proto} occupied by foreign or unresolved process: $(head -n 1 <<< "$holder")"
                fi
            else
                pf_pass "${port}/${proto} available"
            fi
        done
    fi

    managed_services_active
    case $? in
        0) pf_warn 'existing A-Box managed service is active' ;;
        1) pf_pass 'no active A-Box managed service detected' ;;
        2) pf_warn 'A-Box managed service state could not be determined safely' ;;
        *) pf_fail 'A-Box managed service state query failed unexpectedly' ;;
    esac
    if [[ -L "$ABOX_DIR" ]]; then
        pf_fail "A-Box directory is a symbolic link: $ABOX_DIR"
    elif [[ -e "$ABOX_DIR" && ! -d "$ABOX_DIR" ]]; then
        pf_fail "A-Box path is not a directory: $ABOX_DIR"
    elif [[ -d "$ABOX_DIR" ]]; then
        path_owned_by_root "$ABOX_DIR" && path_mode_has_no_group_other_write "$ABOX_DIR" && pf_pass "A-Box directory ownership/mode is safe: $ABOX_DIR" || pf_fail "A-Box directory is not root-owned and protected: $ABOX_DIR"
    else
        [[ -d "$(dirname "$ABOX_DIR")" && ! -L "$(dirname "$ABOX_DIR")" ]] && pf_pass "A-Box directory can be created after runtime ownership checks: $ABOX_DIR" || pf_fail "A-Box directory parent is unavailable or symlinked: $(dirname "$ABOX_DIR")"
    fi

    echo "----------------------------------------------------------------------" | tee -a "$report"
    echo "Summary: FAIL=${fail} WARN=${warn}" | tee -a "$report"
    echo "Report: temporary report generated for this run; cleaned after result." | tee -a "$report"
    if (( fail > 0 )); then
        msg "${RED}[!] Preflight completed with blocking failures.${NC}"
    elif (( warn > 0 )); then
        msg "${YELLOW}[*] Preflight completed with warnings.${NC}"
    else
        msg "${GREEN}[*] Preflight passed.${NC}"
    fi
    if (( _pf_lock_held == 1 )); then
        flock -u 8 2>/dev/null || true
        eval "exec 8>&-" 2>/dev/null || true
        _pf_lock_held=0
    fi
    (( interactive == 1 )) && pause_return
    local preflight_rc=$(( fail > 0 ? 1 : 0 ))
    rm -rf -- "$report_dir" || return 1
    return "$preflight_rc"
}


# Optional Wallos module loader. Core proxy installation remains standalone.
wallos_menu() {
    local module_dir="$ABOX_DIR/modules"
    local module="$ABOX_DIR/modules/wallos.sh"
    local tmp sums asset expected actual
    ensure_abox_dir_owned "$ABOX_DIR" || return 1
    install -d -m 700 "$module_dir" || return 1
    if [[ -f "$module" && ! -L "$module" ]] &&
       grep -Fxq '# A-Box Wallos integration module v173' "$module" 2>/dev/null &&
       bash -n "$module" >/dev/null 2>&1; then
        # shellcheck disable=SC1090
        . "$module"
        wallos_menu_impl
        return $?
    fi
    tmp=$(umask 077; mktemp /tmp/A-Box-Wallos-module.XXXXXX.sh) || return 1
    if ! curl -fLsS --connect-timeout 10 --max-time 45 \
        'https://raw.githubusercontent.com/alariclin/a-box/main/modules/wallos.sh' -o "$tmp"; then
        rm -f -- "$tmp"
        tmp=$(umask 077; mktemp /tmp/A-Box-Wallos-module.XXXXXX.sh) || return 1
        sums=$(umask 077; mktemp /tmp/A-Box-Wallos-sums.XXXXXX) || { rm -f -- "$tmp"; return 1; }
        asset='A-Box-Wallos-module-v173.sh'
        if ! curl -fLsS --connect-timeout 10 --max-time 45 \
            "https://github.com/alariclin/a-box/releases/download/wallos-mirror-v$WALLOS_DEFAULT_VERSION/SHA256SUMS" -o "$sums" ||
           ! curl -fLsS --connect-timeout 10 --max-time 45 \
            "https://github.com/alariclin/a-box/releases/download/wallos-mirror-v$WALLOS_DEFAULT_VERSION/$asset" -o "$tmp" ||
           ! grep -Fq "  $asset" "$sums"; then
            rm -f -- "$tmp" "$sums"
            msg "$RED Wallos 模块主源和灾备源均不可用。/ Wallos module upstream and mirror are unavailable.$NC"
            return 1
        fi
        expected=$(awk -v asset="$asset" '$2 == asset { print $1; exit }' "$sums")
        actual=$(sha256sum "$tmp" | awk '{ print $1 }')
        [[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$expected" == "$actual" ]] || {
            rm -f -- "$tmp" "$sums"
            msg "$RED Wallos 模块灾备校验失败，拒绝加载。/ Wallos module checksum verification failed.$NC"
            return 1
        }
        rm -f -- "$sums"
    fi
    if ! grep -Fxq '# A-Box Wallos integration module v173' "$tmp" ||
       ! grep -Fq 'wallos_menu_impl()' "$tmp" || ! bash -n "$tmp"; then
        rm -f -- "$tmp"
        msg "$RED Wallos 模块结构或 Bash 语法检查失败。/ Wallos module validation failed.$NC"
        return 1
    fi
    install -m 600 "$tmp" "$module" || { rm -f -- "$tmp"; return 1; }
    chown root:root "$module" || { rm -f -- "$tmp" "$module"; return 1; }
    rm -f -- "$tmp"
    # shellcheck disable=SC1090
    . "$module"
    wallos_menu_impl
}

host_network_menu() {
    clear
    msg "$CYAN======================================================================$NC"
    msg "$BOLD$GREEN网络与系统区域设置 / Network and locale settings$NC"
    msg "$CYAN======================================================================$NC"
    msg "$YELLOW 1. IP 协议偏好（IPv4 / IPv6 / 双栈） / IP preference$NC"
    msg "$YELLOW 2. 本机 DNS（明文 / DoT / 自动优选 / DoH） / Host DNS$NC"
    msg "$YELLOW 3. 时区与地区（完整编号选择） / Timezone and locale$NC"
    msg "$YELLOW 4. 快速/严格模式与下载源 / Fast, strict and download source$NC"
    msg "$GREEN 0. 返回 / Back$NC"
    local c
    read -r -p 'Select [0-4]: ' c
    case "$c" in
        1) ip_preference_menu ;;
        2) dns_menu ;;
        3) timezone_menu ;;
        4) ux_mode_menu ;;
        *) return 0 ;;
    esac
}

validate_test_script() {
    local file="$1" size first
    [[ -f "$file" && ! -L "$file" ]] || return 1
    size=$(wc -c < "$file" 2>/dev/null | tr -d ' ') || return 1
    [[ "$size" =~ ^[0-9]+$ ]] && (( size >= 1000 && size <= 10485760 )) || return 1
    IFS= read -r first < "$file" || return 1
    [[ "$first" =~ ^#!.*(bash|env[[:space:]]+bash) ]] || return 1
    if head -n 20 "$file" | grep -Eiq '<!doctype[[:space:]]+html|<html'; then return 1; fi
    bash -n "$file" >/dev/null 2>&1 || return 1
    return 0
}

run_mirrored_test_script() {
    local label="$1" upstream_url="$2" asset="$3"
    shift 3
    local work up_file mirror_file sums manifest expected sha_up sha_mirror selected source='' answer
    work=$(umask 077; mktemp -d /tmp/A-Box-test-tool.XXXXXX) || die '测试脚本临时目录创建失败。'
    chmod 700 "$work" || { rm -rf -- "$work"; return 1; }
    up_file="$work/upstream.sh"
    mirror_file="$work/mirror.sh"
    sums="$work/SHA256SUMS"
    manifest="$work/MIRROR-MANIFEST.txt"
    selected=''

    if curl -fLsS --retry 1 --connect-timeout 10 --max-time 180 "$upstream_url" -o "$up_file" && validate_test_script "$up_file"; then
        sha_up=$(sha256sum "$up_file" | awk '{print $1}')
        msg "$CYAN upstream / 原作者源: $upstream_url$NC"
        msg "$CYAN SHA256: $sha_up$NC"
    else
        rm -f -- "$up_file"
        msg "$YELLOW [!] 原作者源不可用或返回内容校验失败，将尝试 A-Box 固定快照。/ Upstream unavailable or invalid; trying the A-Box snapshot.$NC"
    fi

    if curl -fLsS --connect-timeout 10 --max-time 45 \
        "https://github.com/alariclin/a-box/releases/download/$ABOX_TEST_MIRROR_RELEASE/SHA256SUMS" -o "$sums" &&
       curl -fLsS --connect-timeout 10 --max-time 45 \
        "https://github.com/alariclin/a-box/releases/download/$ABOX_TEST_MIRROR_RELEASE/MIRROR-MANIFEST.txt" -o "$manifest"; then
        expected=$(awk -v asset="$asset" '$2 == asset {print $1; exit}' "$sums")
    else
        expected=''
    fi

    if [[ -s "$up_file" ]] && validate_test_script "$up_file"; then
        sha_up=$(sha256sum "$up_file" | awk '{print $1}')
        if [[ "$expected" =~ ^[a-fA-F0-9]{64}$ && "$sha_up" == "$expected" ]]; then
            selected="$up_file"
            source="upstream (matches A-Box's pinned snapshot)"
        else
            msg "$YELLOW [!] 上游内容与 A-Box 固定摘要不同，可能是新版本，也可能是内容变化。/ Upstream differs from the pinned snapshot.$NC"
            read -r -p '若你信任该上游且要运行尚未进入 A-Box 快照的脚本，请输入大写 YES；否则回车使用灾备快照: ' answer
            if [[ "$answer" == 'YES' ]]; then
                selected="$up_file"
                source='upstream newer/unpinned snapshot (explicitly approved)'
            fi
        fi
    fi

    if [[ -z "$selected" ]]; then
        if ! curl -fLsS --connect-timeout 10 --max-time 180 \
            "https://github.com/alariclin/a-box/releases/download/$ABOX_TEST_MIRROR_RELEASE/$asset" -o "$mirror_file"; then
            rm -rf -- "$work"
            msg "$RED 原作者源不可用且 A-Box 灾备资产无法下载；本次未执行任何脚本。/ Upstream and mirror are unavailable; no script was executed.$NC"
            return 1
        fi
        expected=$(awk -v asset="$asset" '$2 == asset {print $1; exit}' "$sums" 2>/dev/null || true)
        sha_mirror=$(sha256sum "$mirror_file" | awk '{print $1}')
        if [[ ! "$expected" =~ ^[a-fA-F0-9]{64}$ || "$sha_mirror" != "$expected" ]] || ! validate_test_script "$mirror_file"; then
            rm -rf -- "$work"
            msg "$RED A-Box 灾备脚本摘要或 Bash 校验失败，拒绝执行。/ Mirror checksum or Bash validation failed; refusing to run.$NC"
            return 1
        fi
        selected="$mirror_file"
        source="A-Box release snapshot $ABOX_TEST_MIRROR_RELEASE"
    fi

    local chosen_sha
    chosen_sha=$(sha256sum "$selected" | awk '{print $1}')
    msg "$GREEN Test tool / 测试工具: $label$NC"
    msg "$CYAN selected source / 采用来源: $source$NC"
    msg "$CYAN SHA256: $chosen_sha$NC"
    if ! confirm_yes_no "即将执行上面显示的脚本；脚本会访问第三方测试服务，可能消耗流量并收集公开 IP 信息。继续？/ Execute this test script? [Y/N]: "; then
        rm -rf -- "$work"
        return 130
    fi
    chmod 600 "$selected"
    env -i PATH="$PATH" HOME="${HOME:-/root}" LANG="${LANG:-C.UTF-8}" TERM="${TERM:-dumb}" bash "$selected" "$@"
    local rc=$?
    rm -rf -- "$work"
    return "$rc"
}
vps_benchmark_menu() {
    clear
    msg "$CYAN======================================================================$NC"
    msg "$BOLD$GREEN$(tr_msg toolbox_title)$NC"
    msg "$CYAN======================================================================$NC"
    case "$ABOX_LANG" in
        en)
            msg "$YELLOW 1. System benchmark and download speed $NC"
            msg "$YELLOW 2. IP quality, streaming unlock and route test $NC"
            msg "$YELLOW 3. Local SNI preference $NC"
            msg "$YELLOW 4. Mini-host local SNI preference $NC"
            msg "$YELLOW 5. Cloudflare WARP manager $NC"
            msg "$YELLOW 6. Allocate 2G Swap $NC"
            msg "$YELLOW 7. Backup / Restore A-Box configuration $NC"
            msg "$YELLOW 8. Export redacted diagnostic bundle $NC"
            msg "$YELLOW 9. Full dry-run preflight check $NC"
            msg "$YELLOW 10. SNI preference records $NC"
            msg "$YELLOW 11. Multi-UUID / lightweight subscription export $NC"
            msg "$YELLOW 12. Wallos install / update / backup $NC"
            msg "$YELLOW 13. IP / DNS / timezone / locale / download sources $NC"
            msg "$GREEN 0. Back $NC"
            ;;
        ru)
            msg "$YELLOW 1. Тест системы и скорости загрузки $NC"
            msg "$YELLOW 2. Качество IP, стриминг и маршрут $NC"
            msg "$YELLOW 3. Локальный подбор SNI $NC"
            msg "$YELLOW 4. Облегчённый подбор SNI $NC"
            msg "$YELLOW 5. Управление Cloudflare WARP $NC"
            msg "$YELLOW 6. Создать Swap 2 ГБ $NC"
            msg "$YELLOW 7. Резервная копия / восстановление A-Box $NC"
            msg "$YELLOW 8. Диагностический архив без секретов $NC"
            msg "$YELLOW 9. Полная предварительная проверка $NC"
            msg "$YELLOW 10. Записи результатов SNI $NC"
            msg "$YELLOW 11. Несколько UUID / экспорт подписки $NC"
            msg "$YELLOW 12. Wallos: установка / обновление / резервная копия $NC"
            msg "$YELLOW 13. IP / DNS / часовой пояс / локаль / источники загрузки $NC"
            msg "$GREEN 0. Назад $NC"
            ;;
        fa)
            msg "$YELLOW 1. آزمون سیستم و سرعت دانلود $NC"
            msg "$YELLOW 2. کیفیت IP، بازشدن رسانه و مسیر $NC"
            msg "$YELLOW 3. بهینه‌سازی محلی SNI $NC"
            msg "$YELLOW 4. بهینه‌سازی سبک SNI $NC"
            msg "$YELLOW 5. مدیریت Cloudflare WARP $NC"
            msg "$YELLOW 6. ایجاد Swap دو گیگابایتی $NC"
            msg "$YELLOW 7. پشتیبان‌گیری / بازیابی A-Box $NC"
            msg "$YELLOW 8. گزارش تشخیصی بدون اسرار $NC"
            msg "$YELLOW 9. پیش‌آزمایی کامل $NC"
            msg "$YELLOW 10. سوابق نتیجه SNI $NC"
            msg "$YELLOW 11. چند UUID / خروجی اشتراک $NC"
            msg "$YELLOW 12. نصب / به‌روزرسانی / پشتیبان‌گیری Wallos $NC"
            msg "$YELLOW 13. IP / DNS / منطقه زمانی / locale / منبع دانلود $NC"
            msg "$GREEN 0. بازگشت $NC"
            ;;
        *)
            msg "$YELLOW 1. 本机配置和下载测速 $NC"
            msg "$YELLOW 2. IP纯净度、流媒体解锁与回程测试 $NC"
            msg "$YELLOW 3. 本地 SNI 优选 $NC"
            msg "$YELLOW 4. 微型主机本地 SNI 优选 $NC"
            msg "$YELLOW 5. Cloudflare WARP 一键接管 $NC"
            msg "$YELLOW 6. Swap 虚拟内存一键划拨 2G $NC"
            msg "$YELLOW 7. 配置备份 / 恢复 $NC"
            msg "$YELLOW 8. 导出脱敏诊断包 $NC"
            msg "$YELLOW 9. 完整 Dry-run 预检查 $NC"
            msg "$YELLOW 10. SNI 优选记录 $NC"
            msg "$YELLOW 11. 轻量多 UUID / 订阅导出 $NC"
            msg "$YELLOW 12. Wallos 订阅管理（一键安装/升级/备份） $NC"
            msg "$YELLOW 13. IP / DNS / 时区 / 地区 / 下载源设置 $NC"
            msg "$GREEN 0. 返回主菜单 $NC"
            ;;
    esac
    local bench_choice
    read -r -p 'Select [0-13]: ' bench_choice
    case "$bench_choice" in
        1)
            run_mirrored_test_script 'System benchmark and download speed' 'https://bench.sh' 'bench.sh'
            pause_return
            ;;
        2)
            run_mirrored_test_script 'IP quality, streaming unlock and route test' 'https://Check.Place' 'Check.Place.sh' -I
            pause_return
            ;;
        3) run_local_sni_benchmark ;;
        4) run_local_sni_mini_benchmark ;;
        5) run_warp_manager ;;
        6) setup_swap_2g ;;
        7) backup_restore_menu ;;
        8) export_diagnostic_bundle ;;
        9) preflight_check ;;
        10) show_sni_preference_records ;;
        11) multi_uuid_menu ;;
        12) wallos_menu ;;
        13) host_network_menu ;;
        *) return 0 ;;
    esac
}

clean_uninstall_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${RED}深度卸载系统 / Deep Unloading System${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}1. 完全物理清场 (销毁节点、配置、防火墙映射与 sb 入口)${NC}"
    msg "${YELLOW}2. 保留脚本与清场 (销毁节点配置，保留控制台与 sb 入口)${NC}"
    msg "${GREEN}0. 取消并返回${NC}"
    read -r -p '请输入执行代码 [0-2]: ' un_choice
    case "$un_choice" in
        1) auto_backup_prompt 'full uninstall' '/root/A-Box-backups'; do_cleanup full ;;
        2) auto_backup_prompt 'uninstall while keeping script entry' "$ABOX_DIR/backups"; do_cleanup keep ;;
        *) return 0 ;;
    esac
}


urlencode() {
    local raw="${1:-}"
    if command -v jq >/dev/null 2>&1; then
        jq -rn --arg v "$raw" '$v|@uri'
        return $?
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys, urllib.parse; sys.stdout.write(urllib.parse.quote(sys.argv[1], safe=""))' "$raw"
        return $?
    fi
    # Last-resort RFC3986-ish encoder for environments missing jq/python3.
    local i c LC_ALL=C
    for ((i = 0; i < ${#raw}; i++)); do
        c=${raw:i:1}
        case "$c" in
            [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
}

build_ss2022_uri() {
    local host="$1" port="$2" pass="$3"
    # SIP002/SIP022: AEAD-2022 userinfo must not be Base64URL encoded;
    # method and password are percent-encoded as RFC3986 userinfo.
    printf 'ss://%s:%s@%s:%s#A-Box-SS\n' \
        "$(urlencode '2022-blake3-aes-128-gcm')" \
        "$(urlencode "$pass")" \
        "$host" "$port"
}

singbox_hy2_tls_json() {
    if [[ -n "${HY2_DOMAIN:-}" && "${CORE:-}" != 'singbox' ]]; then
        cat <<EOF_TLS
      "tls": {
        "enabled": true,
        "server_name": "${HY2_DOMAIN}"
      }
EOF_TLS
    else
        cat <<EOF_TLS
      "tls": {
        "enabled": true,
        "insecure": true,
        "certificate_public_key_sha256": ["${HY2_CERT_PUBKEY_SHA256_B64:-}"]
      }
EOF_TLS
    fi
}

write_clash_yaml() {
    local out="${CLASH_YAML_PATH:-$ABOX_DIR/A-Box-clash.yaml}" S_IP="$LINK_IP" hy2_name="A-Box-Hy2-Self" tmp_out out_real base_real clash_hop_port
    local hy2_pass_yaml hy2_obfs_yaml ss_pass_yaml clash_mlkem=false clash_mlkem_rc
    if clash_reality_mlkem_enabled; then
        clash_mlkem=true
    else
        clash_mlkem_rc=$?
        (( clash_mlkem_rc == 1 )) || return 1
    fi
    [[ -n "$out" && "$out" == /* ]] || return 1
    [[ -n "${HY2_DOMAIN:-}" ]] && S_IP="$HY2_DOMAIN"
    clash_hop_port="${HY2_BASE_PORT:-443}"
    if [[ "${CORE:-}" != singbox && "${HY2_HOP:-}" == true ]]; then
        if [[ "${HY2_RANGE_START:-}" =~ ^[0-9]+$ ]]; then
            clash_hop_port="$HY2_RANGE_START"
        elif [[ "${HY2_CLASH_PORTS:-}" =~ ^([0-9]+)(-|$) ]]; then
            clash_hop_port="${BASH_REMATCH[1]}"
        fi
    fi
    [[ -n "${HY2_DOMAIN:-}" && "${CORE:-}" != 'singbox' ]] && hy2_name='A-Box-Hy2-ACME'
    ensure_abox_dir_owned "$ABOX_DIR" || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    base_real=$(python3 - "$ABOX_DIR" <<'PY_CLASH_REALPATH'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY_CLASH_REALPATH
) || return 1
    out_real=$(python3 - "$out" <<'PY_CLASH_REALPATH'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY_CLASH_REALPATH
) || return 1
    [[ "$out_real" == "$base_real"/* ]] || return 1
    [[ ! -L "$out" ]] || return 1
    tmp_out=$(mktemp "$base_real/.A-Box-clash-new.XXXXXX") || return 1
    hy2_pass_yaml=$(json_escape "${HY2_PASS:-}") || return 1
    hy2_obfs_yaml=$(json_escape "${HY2_OBFS:-}") || return 1
    ss_pass_yaml=$(json_escape "${SS_PASS:-}") || return 1
    {
        cat <<EOF_CLASH
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  fallback:
    - tls://8.8.4.4
    - tls://1.1.1.1

proxies:
EOF_CLASH
        if [[ "$MODE" == *'VISION'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
            cat <<EOF_CLASH
  - name: "A-Box-VLESS-Vision"
    type: vless
    server: "$LINK_IP"
    port: $VLESS_PORT
    uuid: "$UUID"
    udp: true
    tls: true
    servername: "$VISION_SNI"
    client-fingerprint: chrome
    encryption: ""
    network: tcp
    flow: xtls-rprx-vision
    packet-encoding: xudp
    reality-opts:
      public-key: "$PUBLIC_KEY"
      short-id: "$SHORT_ID"
      support-x25519mlkem768: $clash_mlkem
    smux:
      enabled: false
EOF_CLASH
        fi
        if [[ "$CORE" == 'xray' && ( "$MODE" == *'XHTTP'* || "$MODE" == *'ALL'* ) ]]; then
            cat <<EOF_CLASH
  - name: "A-Box-VLESS-XHTTP"
    type: vless
    server: "$LINK_IP"
    port: $XHTTP_PORT
    uuid: "$UUID"
    udp: true
    tls: true
    servername: "$XHTTP_SNI"
    client-fingerprint: chrome
    encryption: ""
    network: xhttp
    alpn:
      - h2
    reality-opts:
      public-key: "$PUBLIC_KEY"
      short-id: "$SHORT_ID"
      support-x25519mlkem768: $clash_mlkem
    xhttp-opts:
      path: /xhttp
      host: "$XHTTP_SNI"
      mode: stream-one
    smux:
      enabled: false
EOF_CLASH
        fi
        if [[ "$MODE" == *'HY2'* || "$MODE" == *'ALL'* ]]; then
            if [[ -n "${HY2_DOMAIN:-}" && "$CORE" != 'singbox' ]]; then
                if [[ "${HY2_HOP:-}" == 'true' ]]; then
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$HY2_DOMAIN"
    port: $clash_hop_port
    ports: ${HY2_CLASH_PORTS}
    hop-interval: 30
    password: ${hy2_pass_yaml}
    alpn:
      - h3
    sni: "$HY2_DOMAIN"
    obfs: salamander
    obfs-password: ${hy2_obfs_yaml}
EOF_CLASH
                else
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$HY2_DOMAIN"
    port: $HY2_BASE_PORT
    password: ${hy2_pass_yaml}
    alpn:
      - h3
    sni: "$HY2_DOMAIN"
    obfs: salamander
    obfs-password: ${hy2_obfs_yaml}
EOF_CLASH
                fi
            else
                if [[ "${HY2_HOP:-}" == 'true' ]]; then
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$S_IP"
    port: $clash_hop_port
    ports: ${HY2_CLASH_PORTS}
    hop-interval: 30
    password: ${hy2_pass_yaml}
    alpn:
      - h3
    skip-cert-verify: true
    fingerprint: "$HY2_CERT_SHA256_FP"
    obfs: salamander
    obfs-password: ${hy2_obfs_yaml}
EOF_CLASH
                else
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$S_IP"
    port: $HY2_BASE_PORT
    password: ${hy2_pass_yaml}
    alpn:
      - h3
    skip-cert-verify: true
    fingerprint: "$HY2_CERT_SHA256_FP"
    obfs: salamander
    obfs-password: ${hy2_obfs_yaml}
EOF_CLASH
                fi
            fi
        fi
        if [[ "$MODE" == *'SS'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
            cat <<EOF_CLASH
  - name: "A-Box-SS"
    type: ss
    server: "$LINK_IP"
    port: $SS_PORT
    cipher: 2022-blake3-aes-128-gcm
    password: ${ss_pass_yaml}
    udp: true
    smux:
      enabled: false
EOF_CLASH
        fi
        cat <<EOF_CLASH

proxy-groups:
  - name: PROXY
    type: select
    proxies:
EOF_CLASH
        [[ "$MODE" == *'VISION'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]] && echo '      - A-Box-VLESS-Vision'
        [[ "$CORE" == 'xray' && ( "$MODE" == *'XHTTP'* || "$MODE" == *'ALL'* ) ]] && echo '      - A-Box-VLESS-XHTTP'
        [[ "$MODE" == *'HY2'* || "$MODE" == *'ALL'* ]] && echo "      - $hy2_name"
        [[ "$MODE" == *'SS'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]] && echo '      - A-Box-SS'
        cat <<EOF_CLASH
      - DIRECT

rules:
  - MATCH,PROXY
EOF_CLASH
    } > "$tmp_out" || { rm -f -- "$tmp_out"; return 1; }
    chmod 600 "$tmp_out" || { rm -f -- "$tmp_out"; return 1; }
    [[ $EUID -eq 0 ]] && chown root:root "$tmp_out" || true
    mv -f -- "$tmp_out" "$out" || { rm -f -- "$tmp_out"; return 1; }
    chmod 600 "$out" || return 1
    printf '%s\n' "$out"
}

generate_qr() {
    local url=$1
    if command -v qrencode >/dev/null 2>&1; then
        printf '\n%s\n' "${CYAN}================ 扫码导入 / Scan QR Code =================${NC}"
        printf '%s' "$url" | qrencode -s 1 -m 2 -t UTF8
        printf '%s\n\n' "${CYAN}==========================================================${NC}"
    fi
}


build_hy2_uri_endpoint() {
    local raw="${HY2_URI_PORTS:-}" range
    if [[ -z "$raw" ]]; then
        if [[ "${HY2_HOP:-false}" == true && "${HY2_HOP_IMPL:-none}" == manual && "${HY2_BASE_PORT:-}" =~ ^[0-9]+$ && "${HY2_RANGE_START:-}" =~ ^[0-9]+$ && "${HY2_RANGE_END:-}" =~ ^[0-9]+$ ]]; then
            range="${HY2_RANGE_START}-${HY2_RANGE_END}"
            raw="${HY2_BASE_PORT},${range}"
        else
            raw="${HY2_BASE_PORT:-443}"
        fi
    fi
    valid_hy2_uri_ports "$raw" || return 1
    printf '%s\t%s\n' "$raw" ''
}


view_config() {
    local CALLER=${1:-manual}
    clear
    [[ ! -f "$ABOX_ENV" ]] && { msg "${RED}未检测到持久化配置变量。${NC}"; sleep 2; return 0; }
    load_abox_env "$ABOX_ENV" || die 'A-Box 状态文件无效或权限不安全。'
    local refreshed_ip
    refreshed_ip=$(refresh_public_ip || true)
    if [[ -n "$refreshed_ip" && "$refreshed_ip" != 'N/A' && "$refreshed_ip" != "${LINK_IP:-}" ]]; then
        LINK_IP="$refreshed_ip"
        write_env || die '公网 IP 已变化，但持久化更新失败。'
    fi
    VISION_SNI=${VISION_SNI:-${VLESS_SNI:-}}
    XHTTP_SNI=${XHTTP_SNI:-${VLESS_SNI:-}}
    local F_IP="$LINK_IP" S_IP VLESS_URL XHTTP_URL HY2_URL SS_URL CLASH_FILE CLASH_SUB_URL CLASH_SCHEME
    local VISION_SNI_E XHTTP_SNI_E PUBLIC_KEY_E SHORT_ID_E HY2_PASS_E HY2_OBFS_E HY2_DOMAIN_E HY2_PIN_E HY2_URI_PORT HY2_QUERY_PREFIX
    IFS=$'\t' read -r HY2_URI_PORT HY2_QUERY_PREFIX < <(build_hy2_uri_endpoint) || die 'Hysteria2 分享链接端口参数无效。'
    [[ "$LINK_IP" =~ : ]] && F_IP="[$LINK_IP]"
    [[ -z "$LINK_IP" || "$LINK_IP" == 'N/A' ]] && msg "${YELLOW}[!] 未能自动获取公网 IP，分享链接可能不可用。${NC}"
    VISION_SNI_E=$(urlencode "$VISION_SNI")
    XHTTP_SNI_E=$(urlencode "$XHTTP_SNI")
    PUBLIC_KEY_E=$(urlencode "$PUBLIC_KEY")
    SHORT_ID_E=$(urlencode "$SHORT_ID")
    HY2_PASS_E=$(urlencode "$HY2_PASS")
    HY2_OBFS_E=$(urlencode "$HY2_OBFS")
    HY2_DOMAIN_E=$(urlencode "$HY2_DOMAIN")
    HY2_PIN_E=$(urlencode "$HY2_CERT_SHA256_FP")
    msg "${BLUE}======================================================================${NC}"
    msg "${BOLD}${CYAN}全局拓扑网络参数 (${MODE}) / Network Parameters${NC}"
    msg "${BLUE}======================================================================${NC}"
    msg "${BOLD}引擎栈:${NC} $CORE | ${BOLD}模式:${NC} $MODE"
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}[ Shadowrocket / v2rayNG / NekoBox 单节点 URI ]${NC}"
    if [[ "$MODE" == *'VISION'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
        VLESS_URL="vless://$UUID@$F_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$VISION_SNI_E&fp=chrome&pbk=$PUBLIC_KEY_E&sid=$SHORT_ID_E&type=tcp#A-Box-VLESS-Vision"
        msg "${GREEN}${VLESS_URL}${NC}"
        if [[ "$CORE" == 'xray' ]] && xray_reality_requires_mlkem; then
            msg "${YELLOW}当前 Xray $(effective_xray_version) 的 REALITY 服务端涉及较新的兼容门槛；Mihomo 请使用下方完整 YAML。部分 Shadowrocket / sing-box 版本可能无法建立连接。A-Box 默认使用经过当前 iOS + XHTTP/REALITY 兼容性权衡的版本 Xray $ABOX_XRAY_DEFAULT_VERSION（兼容性固定版，非 26.9.x ML-KEM prerelease）；更高 prerelease 版本请显式设置 ABOX_XRAY_VERSION。${NC}"
        fi
        generate_qr "$VLESS_URL"
    fi
    if [[ "$CORE" == 'xray' && ( "$MODE" == *'XHTTP'* || "$MODE" == *'ALL'* ) ]]; then
        XHTTP_URL="vless://$UUID@$F_IP:$XHTTP_PORT?encryption=none&security=reality&sni=$XHTTP_SNI_E&fp=chrome&pbk=$PUBLIC_KEY_E&sid=$SHORT_ID_E&type=xhttp&host=$XHTTP_SNI_E&path=%2Fxhttp&mode=stream-one#A-Box-VLESS-XHTTP"
        msg "${GREEN}${XHTTP_URL}${NC}"
        generate_qr "$XHTTP_URL"
    fi
    if [[ "$MODE" == *'HY2'* || "$MODE" == *'ALL'* ]]; then
        if [[ -n "${HY2_DOMAIN:-}" && "$CORE" != 'singbox' ]]; then
            HY2_URL="hysteria2://$HY2_PASS_E@$HY2_DOMAIN:$HY2_URI_PORT/?${HY2_QUERY_PREFIX}sni=$HY2_DOMAIN_E&obfs=salamander&obfs-password=$HY2_OBFS_E#A-Box-Hy2-ACME"
        else
            S_IP="$F_IP"
            [[ -n "${HY2_DOMAIN:-}" ]] && S_IP="$HY2_DOMAIN"
            HY2_URL="hysteria2://$HY2_PASS_E@$S_IP:$HY2_URI_PORT/?${HY2_QUERY_PREFIX}insecure=1&pinSHA256=$HY2_PIN_E&obfs=salamander&obfs-password=$HY2_OBFS_E#A-Box-Hy2-Self"
        fi
        msg "${GREEN}${HY2_URL}${NC}"
        [[ "${HY2_HOP:-}" == 'true' ]] && msg "${YELLOW}端口跳跃默认间隔 30s；不建议低于 5s。${NC}"
        generate_qr "$HY2_URL"
    fi
    if [[ "$MODE" == *'SS'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
        SS_URL=$(build_ss2022_uri "$F_IP" "$SS_PORT" "$SS_PASS")
        msg "${GREEN}${SS_URL}${NC}"
        generate_qr "$SS_URL"
    fi

    CLASH_FILE=$(write_clash_yaml) || die 'Clash/Mihomo YAML 配置生成失败。'
    CLASH_SUB_URL="${ABOX_CLASH_SUB_URL:-${CLASH_SUB_URL:-}}"
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}[ Clash / Mihomo 完整配置 ]${NC}"
    msg "${GREEN}Local YAML: ${CLASH_FILE}${NC}"
    msg "${YELLOW}Clash/Mihomo 类客户端请导入完整 YAML 或远程订阅 URL；不要扫描上方单条 vless:// / hysteria2:// / ss://。${NC}"
    if [[ -n "$CLASH_SUB_URL" ]]; then
        CLASH_SCHEME="clash://install-config?url=$(urlencode "$CLASH_SUB_URL")"
        msg "${GREEN}Subscription URL: ${CLASH_SUB_URL}${NC}"
        generate_qr "$CLASH_SUB_URL"
        msg "${GREEN}Clash Verge Rev URL Scheme: ${CLASH_SCHEME}${NC}"
        generate_qr "$CLASH_SCHEME"
    else
        msg "${YELLOW}未设置 ABOX_CLASH_SUB_URL。若需要 Clash 扫码导入，请把 ${CLASH_FILE} 发布到 HTTPS 后执行：${NC}"
        msg "${CYAN}ABOX_CLASH_SUB_URL='https://example.com/A-Box-clash.yaml' sb${NC}"
    fi

    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}[ Clash / Mihomo YAML 预览 ]${NC}"
    sed -n '1,220p' "$CLASH_FILE" 2>/dev/null || true

    printf '\n%s\n' "${YELLOW}--- Sing-box 出站示例 ---${NC}"
    if [[ "$MODE" == *'HY2'* || "$MODE" == *'ALL'* ]]; then
        S_IP="$LINK_IP"
        [[ -n "${HY2_DOMAIN:-}" ]] && S_IP="$HY2_DOMAIN"
        if [[ "${HY2_HOP:-}" == 'true' ]]; then
            cat <<EOF_SB
    {
      "type": "hysteria2",
      "server": "$S_IP",
      "server_ports": ["$HY2_SB_PORTS"],
      "hop_interval": "30s",
      "password": "$HY2_PASS",
$(singbox_hy2_tls_json),
      "obfs": {
        "type": "salamander",
        "password": "$HY2_OBFS"
      }
    }
EOF_SB
        else
            cat <<EOF_SB
    {
      "type": "hysteria2",
      "server": "$S_IP",
      "server_port": $HY2_BASE_PORT,
      "password": "$HY2_PASS",
$(singbox_hy2_tls_json),
      "obfs": {
        "type": "salamander",
        "password": "$HY2_OBFS"
      }
    }
EOF_SB
        fi
    fi
    if [[ "$MODE" == *'SS'* || "$MODE" == *'ALL'* || "$MODE" == 'VLESS_SS' ]]; then
        cat <<EOF_SB
    {
      "type": "shadowsocks",
      "server": "$LINK_IP",
      "server_port": $SS_PORT,
      "method": "2022-blake3-aes-128-gcm",
      "password": "$SS_PASS"
    }
EOF_SB
    fi
    if [[ "$CORE" == 'xray' && ( "$MODE" == *'XHTTP'* || "$MODE" == *'ALL'* ) ]]; then
        printf '\n%s\n' "${YELLOW}--- v2rayN / v2rayNG XHTTP JSON ---${NC}"
        cat <<EOF_V2N
{
  "v": "2",
  "ps": "A-Box-VLESS-XHTTP",
  "add": "$LINK_IP",
  "port": "$XHTTP_PORT",
  "id": "$UUID",
  "net": "xhttp",
  "type": "none",
  "path": "/xhttp",
  "mode": "stream-one",
  "tls": "reality",
  "sni": "$XHTTP_SNI",
  "fp": "chrome",
  "pbk": "$PUBLIC_KEY",
  "sid": "$SHORT_ID"
}
EOF_V2N
    fi
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    [[ "$CALLER" == 'deploy' ]] && msg "${GREEN}服务池部署完成。${NC}"
    pause_return
}

show_usage() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}A-Box 脚本全功能说明书 / Full Manual${NC}"
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        cat <<'EOF_USAGE'
[Deployment]
1  Xray VLESS-Vision-Reality
   TCP REALITY + Vision. Best default for long-term stealth. Default REALITY SNI is www.microsoft.com. Use local SNI preference for production; avoid Apple/iCloud-like SNI on non-443 ports.
2  Xray VLESS-XHTTP-Reality
   XHTTP over REALITY. Best high-throughput desktop path with Mihomo v1.19.24+. Recommended: stream-one + h2 + smux disabled. Non-443 SNI should be selected by local SNI preference and manually verified for TLS1.3/H2/SAN; avoid Apple/iCloud on non-443.
3  Xray Shadowsocks-2022
   SS-2022 relay/landing inbound. Default port 2053 TCP/UDP. Best used behind frontend proxies with whitelist.
4  Native Hysteria 2
   UDP/QUIC/H3 acceleration. Use ACME domain cert when available; otherwise self-signed cert with pinSHA256.
5  Xray + Native Hysteria 2 All-in-one
   Vision TCP 443 + XHTTP TCP 8443 + HY2 UDP 443 + SS-2022 TCP/UDP 2053. Balanced speed/fallback deployment.
6  Sing-box VLESS-Vision-Reality
   Low-memory single-core Vision deployment.
7  Sing-box Shadowsocks-2022
   Low-memory SS-2022 relay deployment, default 2053 TCP/UDP.
8  Sing-box VLESS + SS-2022
   Vision main path plus SS-2022 relay path in one sing-box process.
9  Sing-box Hysteria 2
   HY2 in sing-box, best for UDP/QUIC mobile paths.
10 Sing-box All-in-one
   Sing-box Vision + HY2 + SS-2022. No XHTTP by design.

[Operations]
11 Toolbox
   System benchmark/download speed; IP quality/streaming unlock/route test; built-in full SNI preference library; built-in mini-host SNI preference library; SNI preference record viewer; Cloudflare WARP manager; 2G Swap allocation; Backup/Restore; redacted diagnostic bundle export; full dry-run preflight check. Lightweight preflight runs automatically before protocol deployment; backups are offered or created before destructive maintenance/core upgrade actions.
12 VPS One-click Optimization
   BBR/FQ, file descriptor limits, KeepAlive injection, health probe, logrotate/fail2ban defense.
13 Display Node Parameters
   Print URIs, QR codes, Clash/Mihomo YAML, sing-box outbounds, v2rayN/v2rayNG XHTTP JSON.
14 Manual
   This page.
15 OTA, Geo and Core-only Upgrade
   Update A-Box script with Y/N confirmation after SHA256 display, update Xray Loyalsoldier geoip/geosite data, or upgrade installed proxy core binaries without resetting node parameters.
16 Full/Partial Uninstall
   Remove proxy stack, firewall rules, services and optional sb shortcut.
17 Environment Reset
   Kill orphan processes, clean stale firewall rules, remove broken configs and services.
18 Monthly Traffic Limit
   vnStat-based monthly traffic cap; stop services after reaching quota.
19 SS-2022 Whitelist Manager
   Add/remove frontend IP/CIDR whitelist entries. Non-whitelisted sources are dropped when whitelist mode is enabled; switching from open mode removes stale global ACCEPT rules first.
20 Language
   Switch Chinese/English UI and save to /etc/ddr/.lang.
EOF_USAGE
    else
        cat <<'EOF_USAGE'
【部署类】
1  Xray VLESS-Vision-Reality
   TCP REALITY + Vision。长期隐蔽主力。443/TCP 为主力端口；SNI 应使用工具箱本地优选结果并人工确认 TLS1.3/H2/SAN。Apple/iCloud 仅作 443 备用，不建议非443使用。
2  Xray VLESS-XHTTP-Reality
   XHTTP over REALITY。桌面高速优先，需 Mihomo v1.19.24+。推荐 stream-one + h2 + 关闭 smux。非443默认 www.microsoft.com。
3  Xray Shadowsocks-2022
   SS-2022 回程/落地入站。默认 2053 TCP/UDP。最适合公共前置/机场前置后接入，并建议白名单。
4  官方 Hysteria 2
   UDP/QUIC/H3 加速。优先自有域名 ACME 证书；无域名使用自签证书 + pinSHA256。
5  Xray + 官方 Hysteria 2 全协议四合一
   Vision TCP 443 + XHTTP TCP 8443 + HY2 UDP 443 + SS-2022 TCP/UDP 2053。兼顾隐蔽、速度、移动网络与链式回程。
6  Sing-box VLESS-Vision-Reality
   低内存单进程 Vision 部署。
7  Sing-box Shadowsocks-2022
   低内存 SS-2022 回程部署，默认 2053 TCP/UDP。
8  Sing-box VLESS + SS-2022
   Vision 主力 + SS-2022 回程双协议。
9  Sing-box Hysteria 2
   Sing-box 承载 HY2，适合 UDP/QUIC 移动链路。
10 Sing-box 全协议三合一
   Sing-box Vision + HY2 + SS-2022。按设计不包含 XHTTP。

【运维类】
11 综合工具箱
   本机配置/下载测速；IP纯净度/流媒体解锁/回程测试；内置全量SNI优选库；内置微型主机SNI优选库；SNI 优选记录查看；Cloudflare WARP接管；2G Swap划拨；配置备份/恢复；脱敏诊断包导出；完整 Dry-run 预检查。
12 VPS 系统工具 (含 fast/mirror)
21 一键 Reality
   BBR/FQ、文件句柄、KeepAlive、健康探针、logrotate/fail2ban防御。
13 全部节点参数显示
   输出 URI、二维码、Clash/Mihomo YAML、sing-box出站、v2rayN/v2rayNG XHTTP JSON。
14 脚本说明书
   当前页面。
15 脚本 OTA、Xray Geo 与核心无损升级
   更新 A-Box 主脚本（显示 SHA256 后使用 Y/N 确认）、Xray Loyalsoldier geoip/geosite 数据，或仅升级当前已安装协议核心且不重置节点参数。
16 一键全部清空卸载
   删除代理栈、服务、防火墙规则，可选择是否保留 sb 快捷入口。
17 删除全部节点与环境初始化
   杀残留进程、清理陈旧规则、删除破损配置和服务。
18 每月流量管控限制
   基于 vnStat 设置月流量阈值，达到后自动停止服务。
19 SS-2022 白名单 IP 管理
   添加/删除前置机 IP/CIDR，对非白名单来源执行 DROP；从全网开放切回白名单时会先移除旧的全局 ACCEPT 规则。
20 语言设置
   中英文切换，持久化保存至 /etc/ddr/.lang。
EOF_USAGE
    fi
    msg "${CYAN}======================================================================${NC}"
    pause_return
}

extract_abox_build_metadata() {
    local file="$1" build epoch
    build=$(awk -F"'" '/^ABOX_BUILD=/{print $2; exit}' "$file")
    epoch=$(awk -F= '/^ABOX_BUILD_EPOCH=[0-9]+$/{print $2; exit}' "$file")
    [[ -n "$build" && "$epoch" =~ ^[0-9]+$ && ${#epoch} -le 18 ]] || return 1
    printf '%s|%s\n' "$build" "$epoch"
}

validate_ota_version_direction() {
    local file="$1" metadata remote_build remote_epoch
    metadata=$(extract_abox_build_metadata "$file") || { printf '%s\n' 'OTA 脚本缺少可信的 ABOX_BUILD/ABOX_BUILD_EPOCH 元数据。' >&2; return 1; }
    IFS='|' read -r remote_build remote_epoch <<< "$metadata"
    if (( 10#$remote_epoch < 10#$ABOX_BUILD_EPOCH )); then
        [[ "${ABOX_ALLOW_DOWNGRADE:-0}" == 1 ]] || { printf '%s\n' "拒绝 OTA 降级: local=${ABOX_BUILD}(${ABOX_BUILD_EPOCH}) remote=${remote_build}(${remote_epoch})。如确需降级，显式设置 ABOX_ALLOW_DOWNGRADE=1 并配置 SHA256 allowlist。" >&2; return 1; }
        [[ -n "${ABOX_OTA_SHA256_ALLOWLIST:-}" ]] || { printf '%s\n' '允许降级时必须同时设置 ABOX_OTA_SHA256_ALLOWLIST。' >&2; return 1; }
    fi
    OTA_REMOTE_BUILD="$remote_build"
    OTA_REMOTE_EPOCH="$remote_epoch"
}

confirm_ota_script_hash() {
    local sha="$1" url="$2" answer
    if [[ -n "${ABOX_OTA_SHA256_ALLOWLIST:-}" ]]; then
        if sha256_in_allowlist "$sha" "$ABOX_OTA_SHA256_ALLOWLIST"; then
            msg "${GREEN}[*] OTA SHA256 matched ABOX_OTA_SHA256_ALLOWLIST.${NC}"
            return 0
        fi
        printf '%s\n' 'OTA SHA256 is not in ABOX_OTA_SHA256_ALLOWLIST.' >&2
        return 1
    fi
    if [[ "${ABOX_ASSUME_YES_OTA:-}" == '1' ]]; then
        printf '%s\n' 'ABOX_ASSUME_YES_OTA 已禁用；非交互更新必须使用 ABOX_OTA_SHA256_ALLOWLIST。' >&2
        return 1
    fi
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}[!] OTA source is pinned to an immutable Git commit. Syntax/fingerprint and SHA256 display are not a cryptographic publisher signature.${NC}"
        msg "${YELLOW}[!] Source: ${url}${NC}"
        read -r -p 'Install this downloaded A-Box script? [Y/N]: ' answer
    else
        msg "${YELLOW}[!] OTA 已固定到不可变 Git commit。语法/指纹检查与 SHA256 展示仍不是发布者密码学签名。${NC}"
        msg "${YELLOW}[!] 来源：${url}${NC}"
        read -r -p '是否安装此下载的 A-Box 脚本？[Y/N]: ' answer
    fi
    is_yes "$answer"
}

update_script() {
    clear
    local OTA_URL OTA_SNI_URL tmp_update tmp_sni_download tmp_sni_normalized tmp_old_script='' tmp_old_sni_cache=''
    local sni_cache old_cache_exists=0 sha script_restore_ok=1 cache_restore_ok=1
    OTA_URL=$(resolve_abox_main_commit_url) || die '无法将 A-Box main 分支解析为不可变 commit；已拒绝 OTA。'
    [[ "$OTA_URL" =~ ^https://raw\.githubusercontent\.com/alariclin/a-box/[0-9a-f]{40}/install\.sh$ ]] || die 'OTA URL 未指向不可变的 A-Box commit；已拒绝更新。'
    OTA_SNI_URL="${OTA_URL%/install.sh}/data/sni-candidates.txt"
    tmp_update=$(umask 077; mktemp /tmp/A-Box-update.XXXXXX.sh) || die '更新脚本临时文件创建失败。'
    tmp_sni_download=$(umask 077; mktemp /tmp/A-Box-update-sni.XXXXXX) || { rm -f -- "$tmp_update"; die 'SNI 数据更新临时文件创建失败。'; }
    tmp_sni_normalized=$(umask 077; mktemp /tmp/A-Box-update-sni-normalized.XXXXXX) || { rm -f -- "$tmp_update" "$tmp_sni_download"; die 'SNI 数据校验临时文件创建失败。'; }
    msg "${YELLOW}[*] 正在同步固定 commit 的脚本和 SNI 数据...${NC}"
    if ! curl -fLsS --connect-timeout 10 -m 60 "$OTA_URL" -o "$tmp_update"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        msg "${RED}[!] 无法下载更新脚本；当前版本未修改。${NC}"
        pause_return
        return 1
    fi
    sha=$(sha256sum "$tmp_update" | awk '{print $1}')
    msg "${YELLOW}[*] OTA SHA256: ${sha}${NC}"
    if ! validate_abox_script_file "$tmp_update" 'OTA A-Box 脚本' || ! validate_ota_version_direction "$tmp_update"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        msg "${RED}[!] 更新脚本语法、指纹或版本方向校验失败；当前版本未修改。${NC}"
        pause_return
        return 1
    fi
    if ! curl -fLsS --connect-timeout 8 -m 45 --max-filesize "$ABOX_SNI_CANDIDATE_MAX_BYTES" "$OTA_SNI_URL" -o "$tmp_sni_download" 2>/dev/null || ! sni_normalize_candidate_file "$tmp_sni_download" "$tmp_sni_normalized"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        msg "${RED}[!] 同一 commit 的 SNI 数据缺失或校验失败；为避免脚本与数据版本不一致，已取消 OTA。${NC}"
        pause_return
        return 1
    fi
    msg "${YELLOW}[*] OTA remote build: ${OTA_REMOTE_BUILD} (${OTA_REMOTE_EPOCH})${NC}"
    if ! confirm_ota_script_hash "$sha" "$OTA_URL"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        msg "${YELLOW}[*] OTA update canceled; script and SNI cache were not changed.${NC}"
        pause_return
        return 0
    fi

    # Snapshot both current files before changing either one. If a later write
    # or post-write validation fails, restore the old script/cache pair.
    [[ -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] && path_owned_by_root "$ABOX_DIR" && path_mode_has_no_group_other_write "$ABOX_DIR" || {
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        die 'A-Box 数据目录归属或权限校验失败；OTA 未修改本地脚本或缓存。'
    }
    [[ -f "$ABOX_DIR/A-Box.sh" && ! -L "$ABOX_DIR/A-Box.sh" ]] && \
        path_owned_by_root "$ABOX_DIR/A-Box.sh" && path_mode_has_no_group_other_write "$ABOX_DIR/A-Box.sh" && \
        path_parent_chain_safe "$ABOX_DIR/A-Box.sh" || {
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        die '当前 A-Box.sh 不存在或路径不安全；拒绝无法回滚的 OTA。'
    }
    tmp_old_script=$(umask 077; mktemp /tmp/A-Box-update-old-script.XXXXXX.sh) || {
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized"
        die '无法创建 OTA 脚本回滚快照。'
    }
    if ! cp -p -- "$ABOX_DIR/A-Box.sh" "$tmp_old_script"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script"
        die '无法保存当前 A-Box 脚本；OTA 已取消。'
    fi
    sni_cache="$ABOX_DIR/A-Box-sni-candidates.txt"
    if [[ -e "$sni_cache" || -L "$sni_cache" ]]; then
        if [[ ! -f "$sni_cache" || -L "$sni_cache" ]] || ! path_owned_by_root "$sni_cache" || \
            ! path_mode_has_no_group_other_write "$sni_cache" || path_tree_has_mountpoint "$sni_cache"; then
            rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script"
            die '现有 SNI 缓存不安全；OTA 未覆盖此文件。'
        fi
        tmp_old_sni_cache=$(umask 077; mktemp /tmp/A-Box-update-old-sni.XXXXXX) || {
            rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script"
            die '无法创建 SNI 缓存回滚快照。'
        }
        if ! cp -p -- "$sni_cache" "$tmp_old_sni_cache"; then
            rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script" "$tmp_old_sni_cache"
            die '无法保存当前 SNI 缓存；OTA 已取消。'
        fi
        old_cache_exists=1
    fi

    if ! sni_store_candidate_cache "$tmp_sni_normalized"; then
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script" "$tmp_old_sni_cache"
        die '无法安全提交与 OTA 同 commit 的 SNI 数据缓存；脚本未替换。'
    fi
    if ! install_binary_atomically "$tmp_update" "$ABOX_DIR/A-Box.sh"; then
        restore_sni_candidate_cache_snapshot "$tmp_old_sni_cache" "$old_cache_exists" || cache_restore_ok=0
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script" "$tmp_old_sni_cache"
        (( cache_restore_ok == 1 )) && die 'OTA 脚本原子写入失败；旧脚本保留，SNI 缓存已回滚。'
        die 'OTA 脚本原子写入失败，且 SNI 缓存回滚不完整；请保留当前文件并检查 A-Box-sni-candidates.txt。'
    fi
    if ! validate_abox_script_file "$ABOX_DIR/A-Box.sh" '持久化 A-Box 脚本'; then
        rollback_binary_install "$ABOX_DIR/A-Box.sh" "$tmp_old_script" || script_restore_ok=0
        restore_sni_candidate_cache_snapshot "$tmp_old_sni_cache" "$old_cache_exists" || cache_restore_ok=0
        rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script" "$tmp_old_sni_cache"
        if (( script_restore_ok == 1 && cache_restore_ok == 1 )); then
            die 'OTA 持久化校验失败；旧脚本和旧 SNI 缓存已恢复。'
        fi
        die 'OTA 持久化校验失败且回滚不完整；请勿重试，先检查 A-Box.sh 与 SNI 缓存。'
    fi
    rm -f -- "$tmp_update" "$tmp_sni_download" "$tmp_sni_normalized" "$tmp_old_script" "$tmp_old_sni_cache"
    msg "${GREEN}核心代码与同 commit 的 SNI 候选数据库已同步。${NC}"
    sleep 2
    export ABOX_INHERITED_LOCK_MODE="$ABOX_RUNTIME_LOCK_MODE"
    exec "$ABOX_DIR/A-Box.sh"
}

force_update_geo() {
    clear
    init_system_environment
    load_optional_abox_env_or_die
    if ! abox_owns_service xray; then
        msg "${YELLOW}[!] 未检测到 A-Box 托管的 Xray；不会创建或运行 Geo 更新任务。${NC}"
        pause_return
        return 0
    fi
    [[ -x "$ABOX_DIR/geo_update.sh" ]] || setup_geo_cron
    msg "${YELLOW}[*] 正在拉取 Loyalsoldier Geo 资源并执行校验...${NC}"
    if bash "$ABOX_DIR/geo_update.sh"; then
        msg "${GREEN}Xray Geo 资源更新与校验成功。${NC}"
    else
        msg "${RED}[!] Xray Geo 资源下载失败或校验未通过。${NC}"
    fi
    pause_return
}


service_unit_exists() {
    local srv="$1"
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        systemctl list-unit-files "${srv}.service" >/dev/null 2>&1 && return 0
        [[ -f "/etc/systemd/system/${srv}.service" || -f "/lib/systemd/system/${srv}.service" || -f "/usr/lib/systemd/system/${srv}.service" ]] && return 0
    else
        [[ -x "/etc/init.d/${srv}" ]] && return 0
    fi
    return 1
}

restart_service_soft() {
    local srv="$1"
    abox_owns_service "$srv" || return 1
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        systemctl restart "$srv" >/dev/null 2>&1 || return 1
        sleep 2
        systemctl is-active --quiet "$srv" || return 1
        record_core_family_ownership "$srv"
    else
        rc-service "$srv" restart >/dev/null 2>&1 || return 1
        sleep 2
        rc-service "$srv" status >/dev/null 2>&1 || return 1
        record_core_family_ownership "$srv"
    fi
}

enable_abox_service_soft() {
    local srv="$1" state
    abox_owns_service "$srv" || return 1
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        systemctl enable "$srv" >/dev/null 2>&1 || return 1
    elif [[ "${INIT_SYS:-}" == openrc ]]; then
        rc-update add "$srv" default >/dev/null 2>&1 || return 1
    else
        return 1
    fi
    state=$(managed_service_state_value "$srv") || return 1
    [[ "$state" == "$srv|1|1" ]]
}

start_abox_service_soft() {
    local srv="$1"
    abox_owns_service "$srv" || return 1
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        systemctl enable "$srv" >/dev/null 2>&1 || return 1
        systemctl restart "$srv" >/dev/null 2>&1 || return 1
        sleep 2
        systemctl is-active --quiet "$srv" || return 1
        record_core_family_ownership "$srv"
    else
        rc-update add "$srv" default >/dev/null 2>&1 || return 1
        rc-service "$srv" restart >/dev/null 2>&1 || return 1
        sleep 2
        rc-service "$srv" status >/dev/null 2>&1 || return 1
        record_core_family_ownership "$srv"
    fi
}

core_expected_listen_ports() {
    local core="$1" cfg="$2"
    case "$core" in
        xray)
            jq -r '.inbounds[]?.port // empty | if type == "number" then tostring else empty end' "$cfg" 2>/dev/null
            ;;
        singbox)
            jq -r '.inbounds[]?.listen_port // empty | if type == "number" then tostring else empty end' "$cfg" 2>/dev/null
            ;;
        hysteria)
            # Hysteria 2 config uses listen: :PORT (or [::]:PORT).
            awk '
                $1 == "listen:" {
                    v=$0; sub(/^[[:space:]]*listen:[[:space:]]*/, "", v)
                    sub(/^.*:/, "", v); gsub(/[^0-9]/, "", v)
                    if (v != "") print v
                }
            ' "$cfg" 2>/dev/null
            ;;
        *) return 1 ;;
    esac
}

core_ports_listening() {
    local core="$1" cfg="$2" port any=0 line
    while IFS= read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        any=1
        if ! ss -H -lntup 2>/dev/null | awk -v p=":${port}" '$5 ~ p"$" {found=1} END{exit !found}'; then
            msg "${RED}[!] ${core} 端口 ${port} 未处于监听状态。${NC}"
            return 1
        fi
    done < <(core_expected_listen_ports "$core" "$cfg" | awk '!seen[$0]++')
    (( any == 1 ))
}

core_post_upgrade_health_gate() {
    local core="$1" cfg bin
    case "$core" in
        xray)
            cfg='/usr/local/etc/xray/config.json'; bin='/usr/local/bin/xray'
            [[ -x "$bin" && -f "$cfg" ]] || return 1
            XRAY_LOCATION_ASSET=/usr/local/share/xray "$bin" run -test -config "$cfg" >/dev/null 2>&1 || return 1
            ;;
        singbox)
            cfg='/etc/sing-box/config.json'; bin='/usr/local/bin/sing-box'
            [[ -x "$bin" && -f "$cfg" ]] || return 1
            "$bin" check -c "$cfg" >/dev/null 2>&1 || return 1
            ;;
        hysteria)
            cfg='/etc/hysteria/config.yaml'; bin='/usr/local/bin/hysteria'
            [[ -x "$bin" && -f "$cfg" ]] || return 1
            ;;
        *) return 1 ;;
    esac
    is_service_running "$core" || return 1
    core_ports_listening "$core" "$cfg"
}

upgrade_xray_core_only() {
    local was_active=0 active_state='' backup='' tmp xray_zip xray_ext old_ver new_ver
    abox_owns_service xray || die '拒绝升级：xray 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading Xray-core binary only; node parameters will be preserved...${NC}"
    get_architecture
    active_state=$(service_active_state_value xray 2>/dev/null) || die '无法可靠查询 Xray 服务状态；拒绝在状态未知时升级核心。'
    case "$active_state" in 1) was_active=1 ;; 0) was_active=0 ;; *) die 'Xray 服务状态响应无效；拒绝继续升级。' ;; esac
    [[ -x /usr/local/bin/xray ]] && old_ver=$(/usr/local/bin/xray version 2>/dev/null | head -n 1 || true)
    local target_ref current_tag='' cmp=0
    target_ref="$(effective_xray_version)"
    if [[ -z "${ABOX_XRAY_VERSION:-}" && -n "$old_ver" ]]; then
        current_tag=$(grep -oE 'Xray [0-9]+\.[0-9]+\.[0-9]+' <<< "${old_ver:-}" | awk '{print "v"$2}' | head -n 1 || true)
        if [[ -n "$current_tag" ]]; then
            cmp=$(xray_version_compare "$current_tag" "$target_ref") || die '当前 Xray 版本格式无法比较。'
            if (( cmp > 0 )); then
                msg "${YELLOW}[!] 当前 Xray ${current_tag} 高于默认兼容版本 ${target_ref}；为避免自动降级，本次跳过。请显式设置 ABOX_XRAY_VERSION 后再升级。${NC}"
                return 0
            fi
            if (( cmp == 0 )); then
                msg "${GREEN}[OK] 当前 Xray ${current_tag} 已是默认兼容版本，无需替换。${NC}"
                return 0
            fi
        fi
    fi
    tmp=$(mktemp -d /tmp/A-Box-core-xray.XXXXXX) || die 'Xray core upgrade temp directory failed.'
    ABOX_CORE_UPGRADE_TMP="$tmp"
    xray_zip="$tmp/xray_core.zip"; xray_ext="$tmp/xray_ext"; mkdir -p "$xray_ext"
    ABOX_XRAY_VERSION="$target_ref" fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
    extract_zip_member_safely "$xray_zip" xray "$xray_ext/xray" || { rm -rf "$tmp"; die 'Xray core archive safe extraction failed.'; }
    [[ -f "$xray_ext/xray" && ! -L "$xray_ext/xray" ]] || { rm -rf "$tmp"; die 'Xray binary not found after safe extraction.'; }
    chmod 755 "$xray_ext/xray" || { rm -rf "$tmp"; die 'Xray staged binary chmod failed.'; }
    new_ver=$("$xray_ext/xray" version 2>/dev/null | head -n 1 || true)
    [[ -n "$new_ver" ]] || { rm -rf "$tmp"; die 'Xray staged binary execution check failed.'; }
    if [[ -f /usr/local/etc/xray/config.json ]] && ! XRAY_LOCATION_ASSET=/usr/local/share/xray "$xray_ext/xray" run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
        rm -rf "$tmp"; die 'New Xray is incompatible with the current config; installed binary was not changed.'
    fi
    [[ -f /usr/local/bin/xray ]] && { backup="$tmp/xray.backup"; cp -a /usr/local/bin/xray "$backup" || { rm -rf "$tmp"; die 'Xray binary backup failed.'; }; }
    install_binary_atomically "$xray_ext/xray" /usr/local/bin/xray || { rm -rf "$tmp"; die 'Xray binary atomic install failed.'; }
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft xray || ! core_post_upgrade_health_gate xray; then
            msg "${RED}[!] New Xray failed post-upgrade health checks. Rolling back binary...${NC}"
            rollback_binary_install /usr/local/bin/xray "$backup" >/dev/null 2>&1 || true
            restart_service_soft xray >/dev/null 2>&1 || true
            rm -rf "$tmp"; die 'Xray core upgrade rolled back because post-upgrade health checks failed.'
        fi
    fi
    msg "${GREEN}[OK] Xray-core upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf -- "$tmp"
    ABOX_CORE_UPGRADE_TMP=''
}

upgrade_singbox_core_only() {
    local was_active=0 active_state='' backup='' tmp sb_tar sb_ext sb_path old_ver new_ver
    abox_owns_service sing-box || die '拒绝升级：sing-box 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading sing-box binary only; node parameters will be preserved...${NC}"
    get_architecture
    active_state=$(service_active_state_value sing-box 2>/dev/null) || die '无法可靠查询 sing-box 服务状态；拒绝在状态未知时升级核心。'
    case "$active_state" in 1) was_active=1 ;; 0) was_active=0 ;; *) die 'sing-box 服务状态响应无效；拒绝继续升级。' ;; esac
    [[ -x /usr/local/bin/sing-box ]] && old_ver=$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-singbox.XXXXXX) || die 'sing-box core upgrade temp directory failed.'
    ABOX_CORE_UPGRADE_TMP="$tmp"
    sb_tar="$tmp/singbox_core.tar.gz"; sb_ext="$tmp/extract"; mkdir -p "$sb_ext"
    fetch_github_release SagerNet/sing-box singbox_core.tar.gz "$sb_tar"
    sb_path="$sb_ext/sing-box"
    extract_tar_regular_basename_safely "$sb_tar" sing-box "$sb_path" || { rm -rf "$tmp"; die 'sing-box archive safe extraction failed.'; }
    [[ -f "$sb_path" && ! -L "$sb_path" ]] || { rm -rf "$tmp"; die 'sing-box binary not found after safe extraction.'; }
    chmod 755 "$sb_path" || { rm -rf "$tmp"; die 'sing-box staged binary chmod failed.'; }
    new_ver=$("$sb_path" version 2>/dev/null | head -n 1 || true)
    [[ -n "$new_ver" ]] || { rm -rf "$tmp"; die 'sing-box staged binary execution check failed.'; }
    if [[ -f /etc/sing-box/config.json ]] && ! "$sb_path" check -c /etc/sing-box/config.json >/dev/null 2>&1; then
        rm -rf "$tmp"; die 'New sing-box is incompatible with the current config; installed binary was not changed.'
    fi
    [[ -f /usr/local/bin/sing-box ]] && { backup="$tmp/sing-box.backup"; cp -a /usr/local/bin/sing-box "$backup" || { rm -rf "$tmp"; die 'sing-box binary backup failed.'; }; }
    install_binary_atomically "$sb_path" /usr/local/bin/sing-box || { rm -rf "$tmp"; die 'sing-box binary atomic install failed.'; }
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft sing-box || ! core_post_upgrade_health_gate singbox; then
            msg "${RED}[!] New sing-box failed post-upgrade health checks. Rolling back binary...${NC}"
            rollback_binary_install /usr/local/bin/sing-box "$backup" >/dev/null 2>&1 || true
            restart_service_soft sing-box >/dev/null 2>&1 || true
            rm -rf "$tmp"; die 'sing-box core upgrade rolled back because post-upgrade health checks failed.'
        fi
    fi
    msg "${GREEN}[OK] sing-box upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf -- "$tmp"
    ABOX_CORE_UPGRADE_TMP=''
}

upgrade_hysteria_core_only() {
    local was_active=0 active_state='' backup='' tmp hy2_bin old_ver new_ver
    abox_owns_service hysteria || die '拒绝升级：hysteria 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading Hysteria 2 binary only; node parameters will be preserved. Hysteria has no documented standalone config-check command; active services are validated by restart with automatic binary rollback on failure.${NC}"
    get_architecture
    active_state=$(service_active_state_value hysteria 2>/dev/null) || die '无法可靠查询 Hysteria 服务状态；拒绝在状态未知时升级核心。'
    case "$active_state" in 1) was_active=1 ;; 0) was_active=0 ;; *) die 'Hysteria 服务状态响应无效；拒绝继续升级。' ;; esac
    [[ -x /usr/local/bin/hysteria ]] && old_ver=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-hysteria.XXXXXX) || die 'Hysteria core upgrade temp directory failed.'
    ABOX_CORE_UPGRADE_TMP="$tmp"
    hy2_bin="$tmp/hysteria_core"
    fetch_github_release HyNetworks/hysteria hysteria_core "$hy2_bin"
    chmod 755 "$hy2_bin" || { rm -rf "$tmp"; die 'Hysteria staged binary chmod failed.'; }
    new_ver=$("$hy2_bin" version 2>/dev/null | head -n 1 || true)
    [[ -n "$new_ver" ]] || { rm -rf "$tmp"; die 'Hysteria staged binary execution check failed.'; }
    [[ -f /usr/local/bin/hysteria ]] && { backup="$tmp/hysteria.backup"; cp -a /usr/local/bin/hysteria "$backup" || { rm -rf "$tmp"; die 'Hysteria binary backup failed.'; }; }
    install_binary_atomically "$hy2_bin" /usr/local/bin/hysteria || { rm -rf "$tmp"; die 'Hysteria binary atomic install failed.'; }
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft hysteria || ! core_post_upgrade_health_gate hysteria; then
            msg "${RED}[!] New Hysteria failed post-upgrade health checks. Rolling back binary...${NC}"
            rollback_binary_install /usr/local/bin/hysteria "$backup" >/dev/null 2>&1 || true
            restart_service_soft hysteria >/dev/null 2>&1 || true
            rm -rf "$tmp"; die 'Hysteria core upgrade rolled back because post-upgrade health checks failed.'
        fi
    fi
    msg "${GREEN}[OK] Hysteria upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf -- "$tmp"
    ABOX_CORE_UPGRADE_TMP=''
}

restore_core_upgrade_transaction_traps() {
    restore_saved_trap EXIT "$ABOX_CORE_TX_PREV_TRAP_EXIT"
    restore_saved_trap INT "$ABOX_CORE_TX_PREV_TRAP_INT"
    restore_saved_trap TERM "$ABOX_CORE_TX_PREV_TRAP_TERM"
    restore_saved_trap HUP "$ABOX_CORE_TX_PREV_TRAP_HUP"
    ABOX_CORE_TX_PREV_TRAP_EXIT=''; ABOX_CORE_TX_PREV_TRAP_INT=''; ABOX_CORE_TX_PREV_TRAP_TERM=''; ABOX_CORE_TX_PREV_TRAP_HUP=''
}

core_upgrade_transaction_rollback() {
    [[ "${ABOX_CORE_UPGRADE_ACTIVE:-0}" == 1 ]] || return 0
    local backup="${ABOX_CORE_UPGRADE_BACKUP:-}" targets="${ABOX_CORE_UPGRADE_TARGETS:-}" srv core_tmp="${ABOX_CORE_UPGRADE_TMP:-}"
    # Disable recursive EXIT handling but retain backup/target/temp context until
    # the prior snapshot is actually restored and verified.
    ABOX_CORE_UPGRADE_ACTIVE=0
    ABOX_DIE_HOOK=''
    restore_core_upgrade_transaction_traps
    msg "${YELLOW}[!] Core upgrade failed or was interrupted; restoring the exact pre-upgrade snapshot.${NC}"
    if ! stop_all_managed_services >/dev/null 2>&1; then
        msg "${RED}[!] Core-upgrade rollback aborted: one or more managed services could not be confirmed stopped. Backup retained: ${backup:-missing}${NC}" >&2
        return 1
    fi
    for srv in $targets; do
        case "$srv" in singbox) srv='sing-box' ;; esac
        if ! remove_core_family_force "$srv"; then
            msg "${RED}[!] Core-upgrade rollback aborted: unable to remove ${srv} safely. Backup retained: ${backup:-missing}${NC}" >&2
            return 1
        fi
    done
    if ! restore_latest_backup_silent "$ABOX_DIR/backups" "$backup"; then
        msg "${RED}[!] Core upgrade rollback failed: ${backup:-missing}. Recovery context retained.${NC}" >&2
        return 1
    fi
    if [[ -n "$core_tmp" ]]; then
        rm -rf -- "$core_tmp" || { msg "${RED}[!] Prior core state restored, but upgrade staging cleanup failed: $core_tmp${NC}" >&2; return 1; }
    fi
    ABOX_CORE_UPGRADE_BACKUP=''
    ABOX_CORE_UPGRADE_TARGETS=''
    ABOX_CORE_UPGRADE_TMP=''
    return 0
}

core_upgrade_transaction_signal_abort() {
    local sig="$1" code=130
    [[ "$sig" == TERM ]] && code=143
    [[ "$sig" == HUP ]] && code=129
    core_upgrade_transaction_rollback
    exit "$code"
}

core_upgrade_transaction_exit_guard() {
    local rc="$1"
    if [[ "${ABOX_CORE_UPGRADE_ACTIVE:-0}" == 1 ]]; then core_upgrade_transaction_rollback; fi
    return "$rc"
}

install_core_upgrade_transaction_traps() {
    ABOX_CORE_TX_PREV_TRAP_EXIT=$(trap -p EXIT); [[ -n "$ABOX_CORE_TX_PREV_TRAP_EXIT" ]] || ABOX_CORE_TX_PREV_TRAP_EXIT='trap - EXIT'
    ABOX_CORE_TX_PREV_TRAP_INT=$(trap -p INT); [[ -n "$ABOX_CORE_TX_PREV_TRAP_INT" ]] || ABOX_CORE_TX_PREV_TRAP_INT='trap - INT'
    ABOX_CORE_TX_PREV_TRAP_TERM=$(trap -p TERM); [[ -n "$ABOX_CORE_TX_PREV_TRAP_TERM" ]] || ABOX_CORE_TX_PREV_TRAP_TERM='trap - TERM'
    ABOX_CORE_TX_PREV_TRAP_HUP=$(trap -p HUP); [[ -n "$ABOX_CORE_TX_PREV_TRAP_HUP" ]] || ABOX_CORE_TX_PREV_TRAP_HUP='trap - HUP'
    trap 'core_upgrade_transaction_exit_guard "$?"' EXIT
    trap 'core_upgrade_transaction_signal_abort INT' INT
    trap 'core_upgrade_transaction_signal_abort TERM' TERM
    trap 'core_upgrade_transaction_signal_abort HUP' HUP
}

begin_core_upgrade_transaction() {
    ABOX_LAST_BACKUP=''
    auto_backup_silent 'all-core atomic upgrade' "$ABOX_DIR/backups"
    [[ -n "$ABOX_LAST_BACKUP" && -f "$ABOX_LAST_BACKUP" ]] || die '核心升级前精确备份创建失败。'
    ABOX_CORE_UPGRADE_ACTIVE=1
    ABOX_CORE_UPGRADE_BACKUP="$ABOX_LAST_BACKUP"
    ABOX_CORE_UPGRADE_TARGETS="$*"
    ABOX_DIE_HOOK=core_upgrade_transaction_rollback
    install_core_upgrade_transaction_traps
}

commit_core_upgrade_transaction() {
    ABOX_CORE_UPGRADE_ACTIVE=0
    ABOX_CORE_UPGRADE_BACKUP=''
    ABOX_CORE_UPGRADE_TARGETS=''
    ABOX_CORE_UPGRADE_TMP=''
    ABOX_DIE_HOOK=''
    restore_core_upgrade_transaction_traps
}

upgrade_current_cores_only() {
    clear
    init_system_environment
    load_optional_abox_env_or_die
    local targets=() answer t
    if abox_owns_service xray && { [[ -x /usr/local/bin/xray || -f /usr/local/etc/xray/config.json ]] || service_unit_exists xray; }; then targets+=(xray); fi
    if abox_owns_service sing-box && { [[ -x /usr/local/bin/sing-box || -f /etc/sing-box/config.json ]] || service_unit_exists sing-box; }; then targets+=(singbox); fi
    if abox_owns_service hysteria && { [[ -x /usr/local/bin/hysteria || -f /etc/hysteria/config.yaml ]] || service_unit_exists hysteria; }; then targets+=(hysteria); fi
    if (( ${#targets[@]} == 0 )); then
        msg "${YELLOW}[!] No A-Box-owned proxy cores detected; foreign same-name installations are intentionally ignored.${NC}"
        pause_return; return 0
    fi
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Upgrade current installed proxy cores only / 仅升级当前已安装协议核心${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "Detected A-Box-owned cores: ${targets[*]}"
    msg 'Each staged binary is executed and checked against the current config where supported before atomic replacement.'
    read -r -p 'Continue core-only upgrade? [Y/N]: ' answer
    is_yes "$answer" || { msg "${YELLOW}Canceled.${NC}"; pause_return; return 0; }
    begin_core_upgrade_transaction "${targets[@]}"
    for t in "${targets[@]}"; do
        case "$t" in xray) upgrade_xray_core_only ;; singbox) upgrade_singbox_core_only ;; hysteria) upgrade_hysteria_core_only ;; esac
    done
    commit_core_upgrade_transaction
    msg "${GREEN}All detected core-only upgrades completed atomically. Node parameters were preserved.${NC}"
    pause_return
}

ota_and_geo_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${BOLD}${GREEN}OTA, Geo and Core-only Upgrade${NC}"
        msg "${CYAN}======================================================================${NC}"
        msg "${YELLOW}1. Upgrade A-Box script${NC}"
        msg "${YELLOW}2. Update Xray Loyalsoldier Geo resources now${NC}"
        msg "${YELLOW}3. Upgrade current installed proxy cores only; preserve node parameters${NC}"
        msg "${YELLOW}4. Show compatibility pin docs [U3]${NC}"
        msg "${YELLOW}5. DANGER: try upstream latest cores (auto-rollback) [U3]${NC}"
        msg "${GREEN}0. Back${NC}"
        read -r -p 'Select [0-5]: ' ota_choice
    else
        msg "${BOLD}${GREEN}脚本 OTA、Xray Geo 与核心无损升级${NC}"
        msg "${CYAN}======================================================================${NC}"
        msg "${YELLOW}1. 升级 A-Box 核心脚本${NC}"
        msg "${YELLOW}2. 立即拉取并更新 Xray Loyalsoldier Geo 资源${NC}"
        msg "${YELLOW}3. 仅升级当前已安装协议核心，不重置节点参数${NC}"
        msg "${YELLOW}4. 查看兼容钉扎说明 [U3]${NC}"
        msg "${YELLOW}5. 危险：试用上游 latest 核心（失败自动回滚）[U3]${NC}"
        msg "${GREEN}0. 返回主菜单${NC}"
        read -r -p '请选择 [0-5]: ' ota_choice
    fi
    case "$ota_choice" in
        1) update_script ;;
        2) force_update_geo ;;
        3) upgrade_current_cores_only ;;
        4) show_core_pin_docs ;;
        5) try_latest_cores_danger ;;
        *) return 0 ;;
    esac
}


runtime_lock_proc_starttime() {
    local pid="$1"
    awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null
}

open_runtime_flock_fd() {
    local uid gid mode fd_id path_id
    [[ -d "$(dirname "$LOCK_FILE")" && ! -L "$(dirname "$LOCK_FILE")" ]] || return 1
    [[ "$(stat -c %u:%g "$(dirname "$LOCK_FILE")" 2>/dev/null || true)" == 0:0 ]] || return 1
    if [[ -e "$LOCK_FILE" || -L "$LOCK_FILE" ]]; then
        [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || return 1
        uid=$(stat -c %u "$LOCK_FILE" 2>/dev/null) || return 1
        gid=$(stat -c %g "$LOCK_FILE" 2>/dev/null) || return 1
        mode=$(stat -c %a "$LOCK_FILE" 2>/dev/null) || return 1
        [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        # Upgrade compatibility: older A-Box builds created the root-owned
        # regular lock file with the caller's default umask (commonly 0644).
        # Tightening that exact safe legacy case does not replace the inode or
        # bypass flock; an active older process is still detected below.
        if (( (8#$mode & 8#077) != 0 )); then
            chmod 600 "$LOCK_FILE" || return 1
            mode=$(stat -c %a "$LOCK_FILE" 2>/dev/null) || return 1
        fi
        (( (8#$mode & 8#077) == 0 )) || return 1
    else
        ( umask 077; set -o noclobber; : > "$LOCK_FILE" ) 2>/dev/null || return 1
    fi
    exec 9>>"$LOCK_FILE" || return 1
    # Hold the fd before permission hardening so reclaimers cannot swap the inode unseen.
    chown root:root "$LOCK_FILE" || return 1
    chmod 600 "$LOCK_FILE" || return 1
    fd_id=$(stat -Lc '%d:%i' /proc/$$/fd/9 2>/dev/null) || return 1
    path_id=$(stat -Lc '%d:%i' "$LOCK_FILE" 2>/dev/null) || return 1
    [[ "$fd_id" == "$path_id" ]] || return 1
}

validate_inherited_flock_lock() {
    local fd_id path_id
    [[ -e /proc/$$/fd/9 && -e "$LOCK_FILE" ]] || return 1
    fd_id=$(stat -Lc '%d:%i' /proc/$$/fd/9 2>/dev/null) || return 1
    path_id=$(stat -Lc '%d:%i' "$LOCK_FILE" 2>/dev/null) || return 1
    [[ "$fd_id" == "$path_id" ]] || return 1
    flock -n 9 || return 1
}

validate_owned_fallback_runtime_lock() {
    local pid start uid gid mode
    [[ -d "$LOCK_FALLBACK_DIR" && ! -L "$LOCK_FALLBACK_DIR" ]] || return 1
    uid=$(stat -c %u "$LOCK_FALLBACK_DIR" 2>/dev/null) || return 1
    gid=$(stat -c %g "$LOCK_FALLBACK_DIR" 2>/dev/null) || return 1
    mode=$(stat -c %a "$LOCK_FALLBACK_DIR" 2>/dev/null) || return 1
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#077) == 0 )) || return 1
    [[ -f "$LOCK_FALLBACK_DIR/pid" && ! -L "$LOCK_FALLBACK_DIR/pid" && -f "$LOCK_FALLBACK_DIR/starttime" && ! -L "$LOCK_FALLBACK_DIR/starttime" ]] || return 1
    IFS= read -r pid < "$LOCK_FALLBACK_DIR/pid" || return 1
    IFS= read -r start < "$LOCK_FALLBACK_DIR/starttime" || return 1
    [[ "$pid" == "$$" && "$start" == "$(runtime_lock_proc_starttime $$)" ]] || return 1
}

runtime_lock_cleanup() {
    if [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == fallback ]] && validate_owned_fallback_runtime_lock; then
        rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true
        rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true
    fi
}

acquire_fallback_runtime_lock() {
    local existing_pid existing_start actual_start lock_dir_created=0 stale_away=''
    if mkdir -m 700 "$LOCK_FALLBACK_DIR" 2>/dev/null; then
        lock_dir_created=1
        chown root:root "$LOCK_FALLBACK_DIR" || { rmdir "$LOCK_FALLBACK_DIR" 2>/dev/null || true; return 1; }
    else
        if [[ -d "$LOCK_FALLBACK_DIR" && ! -L "$LOCK_FALLBACK_DIR" && -r "$LOCK_FALLBACK_DIR/pid" && -r "$LOCK_FALLBACK_DIR/starttime" ]]; then
            IFS= read -r existing_pid < "$LOCK_FALLBACK_DIR/pid" || existing_pid=''
            IFS= read -r existing_start < "$LOCK_FALLBACK_DIR/starttime" || existing_start=''
            if [[ "$existing_pid" =~ ^[0-9]+$ && -d "/proc/$existing_pid" ]]; then
                actual_start=$(runtime_lock_proc_starttime "$existing_pid" || true)
                [[ -n "$actual_start" && "$actual_start" == "$existing_start" ]] && return 1
            fi
            [[ "$(stat -c %u:%g "$LOCK_FALLBACK_DIR" 2>/dev/null || true)" == 0:0 ]] || return 1
            # Rename-away stale dir as one visible step, then mkdir the canonical name.
            # Avoids the prior rmdir+mkdir TOCTOU window where two reclaimers could both win.
            stale_away="${LOCK_FALLBACK_DIR}.stale.$$.$RANDOM"
            mv -T -- "$LOCK_FALLBACK_DIR" "$stale_away" 2>/dev/null || return 1
            rm -rf -- "$stale_away" 2>/dev/null || true
            mkdir -m 700 "$LOCK_FALLBACK_DIR" 2>/dev/null || return 1
            lock_dir_created=1
            chown root:root "$LOCK_FALLBACK_DIR" || { rmdir "$LOCK_FALLBACK_DIR" 2>/dev/null || true; return 1; }
        else
            return 1
        fi
    fi
    umask 077
    printf '%s\n' "$$" > "$LOCK_FALLBACK_DIR/pid" || { (( lock_dir_created )) && { rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true; rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true; }; return 1; }
    printf '%s\n' "$(runtime_lock_proc_starttime $$)" > "$LOCK_FALLBACK_DIR/starttime" || { (( lock_dir_created )) && { rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true; rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true; }; return 1; }
    chmod 600 "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" || { (( lock_dir_created )) && { rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true; rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true; }; return 1; }
    chown root:root "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" || { (( lock_dir_created )) && { rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true; rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true; }; return 1; }
    ABOX_RUNTIME_LOCK_MODE='fallback'
}


upgrade_runtime_lock_to_flock_if_possible() {
    # After ensure_commands may have installed flock, promote a session that
    # started on LOCK_FALLBACK_DIR onto LOCK_FILE so helpers and main share one object.
    [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == fallback ]] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    open_runtime_flock_fd || return 1
    flock -n 9 || {
        # Another process already holds the flock; keep fallback ownership for cleanup.
        eval "exec 9>&-" 2>/dev/null || true
        return 1
    }
    if validate_owned_fallback_runtime_lock; then
        rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || true
        rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || true
    fi
    ABOX_RUNTIME_LOCK_MODE='flock'
}

acquire_runtime_lock() {
    if [[ "${ABOX_INHERITED_LOCK_MODE:-}" == flock ]]; then
        command -v flock >/dev/null 2>&1 || die '继承的 flock 锁无法验证。'
        validate_inherited_flock_lock || die 'OTA 继承的运行锁无效或 inode 已变化。'
        ABOX_RUNTIME_LOCK_MODE='flock'
    elif [[ "${ABOX_INHERITED_LOCK_MODE:-}" == fallback ]]; then
        validate_owned_fallback_runtime_lock || die 'OTA 继承的 fallback 运行锁无效。'
        ABOX_RUNTIME_LOCK_MODE='fallback'
    elif command -v flock >/dev/null 2>&1; then
        open_runtime_flock_fd || die '运行锁路径不安全或无法打开。'
        flock -n 9 || die '检测到另一个 A-Box 实例正在运行。'
        ABOX_RUNTIME_LOCK_MODE='flock'
    else
        acquire_fallback_runtime_lock || die '检测到另一个 A-Box 实例正在运行，且当前系统缺少 flock。'
    fi
    unset ABOX_INHERITED_LOCK_MODE
    trap 'runtime_lock_cleanup' EXIT
    trap 'runtime_lock_cleanup; exit 129' HUP
    trap 'runtime_lock_cleanup; exit 130' INT
    trap 'runtime_lock_cleanup; exit 143' TERM
}

enter_runtime() {
    if [[ $EUID -ne 0 ]]; then
        if [[ -f "$0" && -r "$0" && "$0" != 'bash' && "$0" != '-bash' ]] && command -v sudo >/dev/null 2>&1; then
            exec sudo bash "$0" "$@"
        fi
        die '非 root 管道/标准输入执行无法自动提权；请使用: curl -fsSL <URL> | sudo bash'
    fi
    # Force-heal is call-stack only; never honor a caller-exported env toggle.
    unset ABOX_HEAL_MISSING_MANIFEST 2>/dev/null || true
    # Die-hooks are installed only by in-script transactions; ignore ambient export.
    unset ABOX_DIE_HOOK 2>/dev/null || true
    need_interactive_tty
    mkdir -p /var/run || die '无法创建 /var/run。'
    ensure_abox_dir_owned "$ABOX_DIR"
    acquire_runtime_lock
    detect_lang
    initial_language_select
}

expected_managed_services() {
    clear_abox_env_vars
    load_abox_env "$ABOX_ENV" || return 1
    case "${CORE:-}" in
        xray) printf 'xray\n'; [[ "${MODE:-}" == *ALL* ]] && printf 'hysteria\n' ;;
        singbox) printf 'sing-box\n' ;;
        hysteria) printf 'hysteria\n' ;;
        *) return 1 ;;
    esac
}

prepare_noninteractive_file_operation() {
    [[ $EUID -eq 0 ]] || die '该操作需要 root。'
    mkdir -p /run || die '无法创建 /run。'
    ensure_abox_dir_owned "$ABOX_DIR"
    acquire_runtime_lock
}

prepare_noninteractive_service_control() {
    [[ $EUID -eq 0 ]] || die '该操作需要 root。'
    mkdir -p /var/run || die '无法创建 /var/run。'
    ensure_abox_dir_owned "$ABOX_DIR"
    acquire_runtime_lock
    if systemd_available; then INIT_SYS='systemd'; elif command -v rc-service >/dev/null 2>&1; then INIT_SYS='openrc'; else die '未检测到 systemd/OpenRC。'; fi
}

manual_stop_managed_stack() {
    local srv failed=0 services previous_state pre_state changed_pre changed_expected tx_dir before after active enabled
    prepare_noninteractive_service_control
    services=$(expected_managed_services) || die '无法读取有效的 A-Box 部署状态。'
    previous_state=$(get_desired_state) || die '无法读取当前 A-Box 期望状态。'
    tx_dir=$(mktemp -d /run/A-Box-service-tx.XXXXXX) || die '无法创建服务状态事务目录。'
    chmod 700 "$tx_dir" || { rm -rf -- "$tx_dir"; die '服务状态事务目录权限设置失败。'; }
    pre_state="$tx_dir/pre.state"; changed_pre="$tx_dir/changed-pre.state"; changed_expected="$tx_dir/changed-expected.state"
    capture_managed_service_state "$pre_state" || { rm -rf -- "$tx_dir"; die '无法保存服务运行/启用状态快照。'; }
    : > "$changed_pre"; : > "$changed_expected"

    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        before=$(managed_service_state_value "$srv" 2>/dev/null) || { failed=1; break; }
        IFS='|' read -r _ active enabled <<< "$before"
        [[ "$active" == 0 && "$enabled" == 0 ]] && continue
        stop_abox_service "$srv" || failed=1
        after=$(managed_service_state_value "$srv" 2>/dev/null || true)
        if [[ -z "$after" ]]; then
            append_managed_service_state_entry "$pre_state" "$changed_pre" "$srv" || failed=1
            printf '%s\n' "$srv|0|0" >> "$changed_expected" || failed=1
        elif [[ "$after" != "$before" ]]; then
            append_managed_service_state_entry "$pre_state" "$changed_pre" "$srv" || failed=1
            printf '%s\n' "$after" >> "$changed_expected" || failed=1
        fi
        [[ "$after" == "$srv|0|0" ]] || failed=1
        (( failed == 0 )) || break
    done <<< "$services"

    service_tx_rollback() {
        [[ ! -s "$changed_pre" ]] && return 0
        [[ -s "$changed_expected" ]] || return 1
        restore_managed_service_state "$changed_pre" "$changed_expected"
    }
    if (( failed != 0 )); then
        if ! service_tx_rollback; then printf '%s\n' "A-Box service rollback incomplete; recovery state preserved at $tx_dir" >&2; else rm -rf -- "$tx_dir"; fi
        die '至少一个托管服务停止/禁用失败；未提交 MANUAL_STOPPED 状态。'
    fi
    set_desired_state MANUAL_STOPPED || {
        if ! service_tx_rollback; then printf '%s\n' "A-Box service rollback incomplete; recovery state preserved at $tx_dir" >&2; else rm -rf -- "$tx_dir"; fi
        die '服务状态提交失败；已尝试恢复原运行/启用状态。'
    }
    rm -rf -- "$tx_dir" || die '服务状态事务清理失败；服务已按预期停止，但未能清理事务材料。'
    printf 'A-Box managed stack stopped; Intent=MANUAL_STOPPED\n'
}

manual_start_managed_stack() {
    local srv failed=0 services previous_state previous_block_period='' block_state_present=0 before after active enabled tx_dir
    prepare_noninteractive_service_control
    services=$(expected_managed_services) || die '无法读取有效的 A-Box 部署状态。'
    previous_state=$(get_desired_state) || die '无法读取当前 A-Box 期望状态。'
    if [[ -e "$ABOX_TRAFFIC_BLOCK_STATE" || -L "$ABOX_TRAFFIC_BLOCK_STATE" ]]; then
        previous_block_period=$(get_traffic_block_period) || die '无法读取当前流量封禁周期状态.'
        block_state_present=1
    fi
    tx_dir=$(mktemp -d /run/A-Box-service-tx.XXXXXX) || die '无法创建服务状态事务目录。'
    chmod 700 "$tx_dir" || { rm -rf -- "$tx_dir"; die '服务状态事务目录权限设置失败。'; }
    local pre_state="$tx_dir/pre.state" changed_pre="$tx_dir/changed-pre.state" changed_expected="$tx_dir/changed-expected.state"
    capture_managed_service_state "$pre_state" || { rm -rf -- "$tx_dir"; die '无法保存服务运行/启用状态快照。'; }
    : > "$changed_pre"; : > "$changed_expected"

    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        abox_owns_service "$srv" || { failed=1; break; }
        before=$(managed_service_state_value "$srv" 2>/dev/null) || { failed=1; break; }
        IFS='|' read -r _ active enabled <<< "$before"
        [[ "$active" == 1 && "$enabled" == 1 ]] && continue
        if [[ "$active" == 1 ]]; then
            enable_abox_service_soft "$srv" || failed=1
        else
            start_abox_service_soft "$srv" || failed=1
        fi
        after=$(managed_service_state_value "$srv" 2>/dev/null || true)
        if [[ -z "$after" ]]; then
            append_managed_service_state_entry "$pre_state" "$changed_pre" "$srv" || failed=1
            printf '%s\n' "$srv|1|1" >> "$changed_expected" || failed=1
        elif [[ "$after" != "$before" ]]; then
            append_managed_service_state_entry "$pre_state" "$changed_pre" "$srv" || failed=1
            printf '%s\n' "$after" >> "$changed_expected" || failed=1
        fi
        [[ "$after" == "$srv|1|1" ]] || failed=1
        (( failed == 0 )) || break
    done <<< "$services"

    service_tx_rollback() {
        [[ ! -s "$changed_pre" ]] && return 0
        [[ -s "$changed_expected" ]] || return 1
        restore_managed_service_state "$changed_pre" "$changed_expected"
    }
    if (( failed == 0 )); then
        clear_traffic_block_period || failed=1
        (( failed != 0 )) || set_desired_state RUNNING || failed=1
    fi
    if (( failed != 0 )); then
        if (( block_state_present == 1 )); then set_traffic_block_period "$previous_block_period" >/dev/null 2>&1 || true; else clear_traffic_block_period >/dev/null 2>&1 || true; fi
        set_desired_state "$previous_state" >/dev/null 2>&1 || true
        if ! service_tx_rollback; then printf '%s\n' "A-Box service rollback incomplete; recovery state preserved at $tx_dir" >&2; else rm -rf -- "$tx_dir"; fi
        die '至少一个托管服务启动/启用或状态提交失败；已尝试回滚本次操作。'
    fi
    rm -rf -- "$tx_dir" || die '服务状态事务清理失败；服务已按预期启动，但未能清理事务材料。'
    printf 'A-Box managed stack started; Intent=RUNNING\n'
}


show_cli_help() {
    cat <<'EOF_HELP'
A-Box
Usage:
  bash install.sh                    启动交互菜单 / Start interactive menu
  bash install.sh --lang zh          设置中文并启动 / Use Chinese UI
  bash install.sh --lang en          Use English UI / 设置英文并启动
  bash install.sh --self-test        运行无副作用静态自测 / Run static self-test
  bash install.sh --status           显示当前配置和服务状态 / Show current status
  bash install.sh --stop             停止托管服务并保持手动停止状态 / Stop managed services
  bash install.sh --start            启动托管服务并恢复运行状态 / Start managed services
  bash install.sh --preflight        运行完整预检查 / Run full dry-run preflight check
  bash install.sh --dry-run          同 --preflight / Alias of --preflight
  bash install.sh --version          显示构建版本 / Show build version
  bash install.sh --export-backup-key /secure/path/A-Box-recovery.key
                                      将恢复密钥导出到独立可信介质
  bash install.sh --convert-legacy-backup OLD.tar.gz [OUTPUT_DIR]
                                      安全转换旧版备份为 manifest v3
  bash install.sh --help             显示命令行帮助 / Show help
EOF_HELP
}

run_self_tests() {
    local tmp failures=0 real_abox_sig='' real_abox_exists=0 selftest_prev_exit_trap selftest_prev_umask selftest_sni_seed='' selftest_script_dir=''
    selftest_prev_umask=$(umask)
    umask 077
    tmp=$(mktemp -d /tmp/A-Box-selftest.XXXXXX) || { umask "$selftest_prev_umask"; exit 1; }
    selftest_prev_exit_trap=$(trap -p EXIT || true)
    # Capture the absolute temp path in the EXIT trap itself. Bash function-local
    # variables may be out of scope when an unexpected exit reaches a trap.
    local selftest_tmp_quoted
    printf -v selftest_tmp_quoted '%q' "$tmp"
    # shellcheck disable=SC2064 # expand the %q-quoted absolute path when the trap is registered
    trap "rm -rf -- $selftest_tmp_quoted" EXIT
    selftest_cleanup() {
        rm -rf -- "$tmp"
        trap - EXIT
        if [[ -n "$selftest_prev_exit_trap" ]]; then
            eval "$selftest_prev_exit_trap" || true
        fi
        umask "$selftest_prev_umask"
        return 0
    }
    selftest_abox_signature() {
        if [[ ! -e /etc/ddr && ! -L /etc/ddr ]]; then
            printf 'ABSENT\n'
            return 0
        fi
        [[ -d /etc/ddr && ! -L /etc/ddr ]] || return 1
        find /etc/ddr -mindepth 1 -maxdepth 1 -xdev -printf '%f\0%y\0%u\0%g\0%m\0%s\0%T@\0' | sort -z | sha256sum | awk '{print $1}'
    }
    if (( EUID == 0 )); then
        if [[ -e /etc/ddr || -L /etc/ddr ]]; then real_abox_exists=1; fi
        real_abox_sig=$(selftest_abox_signature) || { echo 'FAIL: live /etc/ddr baseline signature unavailable'; failures=$((failures + 1)); }
    fi
    assert_ok() { "$@" >/dev/null 2>&1 || { echo "FAIL: $*"; failures=$((failures + 1)); }; }
    assert_bad() { "$@" >/dev/null 2>&1 && { echo "FAIL expected bad: $*"; failures=$((failures + 1)); } || true; }
    selftest_has() { command -v "$1" >/dev/null 2>&1; }
    selftest_note() { printf 'SELF_TEST_NOTE: %s\n' "$*"; }
    # BusyBox tar rejects GNU --owner/--group; prefer GNU flags, else python, else plain tar.
    # Third arg force_root=1 rewrites members to uid/gid 0 (good/bad fixtures). Default preserves
    # on-disk ownership (needed for ACME runtime-owned backup acceptance tests).
    selftest_pack_tar_gz() {
        local src_dir="$1" out="$2" force_root="${3:-0}"
        if tar --help 2>&1 | grep -Fq -- '--owner='; then
            if [[ "$force_root" == '1' ]]; then
                tar -C "$src_dir" --owner=0 --group=0 --numeric-owner -czf "$out" root meta || return 1
            else
                tar -C "$src_dir" --numeric-owner -czf "$out" root meta || return 1
            fi
        elif selftest_has python3; then
            python3 - "$src_dir" "$out" "$force_root" <<'PY_SELFTEST_TAR' || return 1
import os, sys, tarfile
src, out, force_root = sys.argv[1], sys.argv[2], sys.argv[3]
with tarfile.open(out, 'w:gz') as tf:
    for name in ('root', 'meta'):
        path = os.path.join(src, name)
        def filt(m, force=force_root):
            if force == '1':
                m.uid = 0
                m.gid = 0
                m.uname = 'root'
                m.gname = 'root'
            return m
        tf.add(path, arcname=name, filter=filt)
PY_SELFTEST_TAR
        else
            tar -C "$src_dir" -czf "$out" root meta || return 1
        fi
    }

    assert_ok valid_port 1
    assert_ok valid_port 65535
    assert_ok valid_port 00065535
    assert_bad valid_port 0
    assert_bad valid_port 000000
    assert_bad valid_port 65536
    assert_bad valid_port 08x
    assert_bad valid_port 999999999999999999999999999999999999
    assert_ok valid_positive_int 999999999999999999
    assert_bad valid_positive_int 1000000000000000000
    if selftest_has openssl; then
        _rand4096=$(rand_alnum 4096 2>/dev/null) || { echo 'FAIL: rand_alnum maximum length'; failures=$((failures + 1)); }
        [[ ${#_rand4096} -eq 4096 && "$_rand4096" =~ ^[A-Za-z0-9]+$ ]] || { echo 'FAIL: rand_alnum maximum-length output'; failures=$((failures + 1)); }
    else
        selftest_note 'rand_alnum maximum-length test skipped (openssl missing)'
    fi
    assert_ok valid_traffic_limit_gb 8589934591
    assert_bad valid_traffic_limit_gb 8589934592
    assert_bad valid_traffic_limit_gb 999999999999999999
    assert_ok valid_hy2_bandwidth_mbps 8589934591
    assert_bad valid_hy2_bandwidth_mbps 8589934592
    assert_bad valid_hy2_bandwidth_mbps 1000000000000000000
    assert_ok valid_backup_retention_count 0
    assert_ok valid_backup_retention_count 1000
    assert_bad valid_backup_retention_count -1
    assert_bad valid_backup_retention_count abc
    assert_bad valid_backup_retention_count 1001
    assert_bad valid_single_line_secret $'secret\tvalue'
    assert_bad valid_single_line_secret $'secret\nvalue'
    assert_ok valid_single_line_secret 'normal-secret'
    assert_ok valid_interface_name abcdefghijklmno
    assert_bad valid_interface_name abcdefghijklmnop
    assert_ok valid_port_range 20000:25000
    assert_ok valid_port_range 20000-25000
    assert_bad valid_port_range 25000:20000
    assert_ok valid_canonical_port 443
    assert_bad valid_canonical_port 000443
    assert_ok valid_canonical_port_range 20000-25000
    assert_bad valid_canonical_port_range 020000-025000
    assert_ok valid_domain example.com
    assert_bad valid_domain -bad.example.com
    [[ "$(sni_raw_score 0.055769 0.064025 0.064121 -340)" == '-266' ]] || { echo 'FAIL: SNI raw scoring must preserve negative values'; failures=$((failures + 1)); }
    [[ "$(sni_adjust_score -266 -1500)" == '-1766' ]] || { echo 'FAIL: SNI adjusted scoring must preserve signed values'; failures=$((failures + 1)); }
    if ! (
        command() {
            if [[ "${1:-}" == '-v' && "${2:-}" == 'python3' ]]; then return 1; fi
            builtin command "$@"
        }
        _fallback_redacted=$(printf '%s\n' '{"message":"Authorization: Bearer fallback-json-token", "api_key":"fallback-api-secret", "safe":"visible"}' | redact_secrets_stream)
        [[ "$_fallback_redacted" != *fallback-json-token* && "$_fallback_redacted" != *fallback-api-secret* && "$_fallback_redacted" == *visible* ]]
    ); then echo 'FAIL: sed-only diagnostic redaction fallback'; failures=$((failures + 1)); fi
    if ! (
        get_public_ip() { printf '1.1.1.9\n'; }
        asn_lookup_ip() {
            case "${1:-}" in
                1.1.1.9) printf 'asn=AS13335\tcountry=US\torg=Test VPS' ;;
                1.1.1.1) printf 'asn=AS13335\tcountry=US\torg=Test target' ;;
                *) printf 'asn=unknown\tcountry=unknown\torg=unknown' ;;
            esac
        }
        sni_openssl_check() { printf '%s\n' "${3:-EMPTY}" >> "$tmp/sni-openssl-ip-capture"; printf 'tls13=1\talpn=h2\tsan=1'; }
        msg() { :; }
        printf '%s\n' $'00001000\texample.org\tapp=0.04s\tttfb=0.1s\ttotal=0.11s\thttp=2\tcode=200\tip=1.1.1.1' > "$tmp/sni-stage1-valid.tsv"
        sni_verify_raw_report "$tmp/sni-stage1-valid.tsv" "$tmp/sni-stage2-valid.tsv" 1 2 >/dev/null 2>&1
        [[ "$(cat "$tmp/sni-openssl-ip-capture")" == '1.1.1.1' ]]
        grep -Fq 'tls13=1' "$tmp/sni-stage2-valid.tsv"
        printf '%s\n' $'00001000\texample.org\tapp=0.04s\tttfb=0.1s\ttotal=0.11s\thttp=2\tcode=200\tip=127.0.0.1' > "$tmp/sni-stage1-private.tsv"
        rm -f -- "$tmp/sni-openssl-ip-capture"
        sni_verify_raw_report "$tmp/sni-stage1-private.tsv" "$tmp/sni-stage2-private.tsv" 1 2 >/dev/null 2>&1
        [[ ! -e "$tmp/sni-openssl-ip-capture" ]]
        grep -Fq 'tls13=0' "$tmp/sni-stage2-private.tsv"
    ); then echo 'FAIL: SNI stage-2 must pin to validated IP and reject non-public IP'; failures=$((failures + 1)); fi
    assert_ok valid_url_https https://example.com/path
    assert_ok valid_url_https https://example.com:443/path
    assert_bad valid_url_https http://example.com/
    assert_bad valid_url_https 'https://bad example.com/'
    [[ "$(normalize_https_url_input www.microsoft.com)" == 'https://www.microsoft.com/' ]] || { echo 'FAIL: normalize HTTPS URL'; failures=$((failures + 1)); }
    [[ "$(normalize_https_url_input https://www.microsoft.com)" == 'https://www.microsoft.com/' ]] || { echo 'FAIL: normalize HTTPS URL trailing slash'; failures=$((failures + 1)); }
    [[ "$(build_ss2022_uri 203.0.113.10 2053 'abc+/=')" == 'ss://2022-blake3-aes-128-gcm:abc%2B%2F%3D@203.0.113.10:2053#A-Box-SS' ]] || { echo 'FAIL: SS-2022 SIP002/SIP022 URI percent encoding'; failures=$((failures + 1)); }

    selftest_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || selftest_script_dir=''
    if [[ -n "${ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE:-}" && -f "$ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE" && ! -L "$ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE" ]]; then
        selftest_sni_seed="$ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE"
    elif [[ -n "$selftest_script_dir" && -f "$selftest_script_dir/data/sni-candidates.txt" && ! -L "$selftest_script_dir/data/sni-candidates.txt" ]]; then
        selftest_sni_seed="$selftest_script_dir/data/sni-candidates.txt"
    elif [[ -f "$ABOX_DIR/A-Box-sni-candidates.txt" && ! -L "$ABOX_DIR/A-Box-sni-candidates.txt" ]]; then
        selftest_sni_seed="$ABOX_DIR/A-Box-sni-candidates.txt"
    fi
    grep -Fq 'ABOX_SNI_HARD_MAX=16384' "$0" || { echo 'FAIL: SNI hard ceiling missing'; failures=$((failures + 1)); }
    ! sed -n '/^write_sni_candidate_library() {$/,/^sni_domain_penalty() {$/p' "$0" | grep -Fq 'cat > "$raw" <<' || { echo 'FAIL: SNI candidates must live outside install.sh'; failures=$((failures + 1)); }
    grep -Fq 'data/sni-candidates.txt' "$0" || { echo 'FAIL: SNI database URL/path missing'; failures=$((failures + 1)); }
    grep -Fq 'sni_store_candidate_cache' "$0" || { echo 'FAIL: SNI cache synchronization helper missing'; failures=$((failures + 1)); }
    grep -Fq 'remove_sni_candidate_cache' "$0" || { echo 'FAIL: SNI cache uninstall cleanup helper missing'; failures=$((failures + 1)); }
    grep -Fq 'sni_normalize_candidate_file() {' "$0" || { echo 'FAIL: SNI database validator missing'; failures=$((failures + 1)); }
    assert_ok sni_san_matches_domain api.example.org $'X509v3 Subject Alternative Name:\n DNS:api.example.org, DNS:*.other.example'
    assert_ok sni_san_matches_domain api.example.org $'X509v3 Subject Alternative Name:\n DNS:*.example.org'
    assert_bad sni_san_matches_domain deep.api.example.org $'X509v3 Subject Alternative Name:\n DNS:*.example.org'
    assert_bad sni_san_matches_domain api.example.org $'X509v3 Subject Alternative Name:\n DNS:apiXexampleXorg'
    if [[ -n "$selftest_sni_seed" ]]; then
        ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE="$selftest_sni_seed" ABOX_SNI_FULL_MAX=0 write_sni_candidate_library full "$tmp/sni-full.txt"
        sni_count=$(wc -l < "$tmp/sni-full.txt" | tr -d ' ')
        [[ "$sni_count" =~ ^[0-9]+$ && "$sni_count" -ge 2500 ]] || { echo "FAIL: SNI library size < 2500 ($sni_count)"; failures=$((failures + 1)); }
        grep -qx 'www.confluent.io' "$tmp/sni-full.txt" || { echo 'FAIL: SNI library missing www.confluent.io'; failures=$((failures + 1)); }
        grep -qx 'www.apache.org' "$tmp/sni-full.txt" || { echo 'FAIL: SNI library missing www.apache.org'; failures=$((failures + 1)); }
        if grep -Eiq '(^|\.)(google|gstatic|googleapis|googleusercontent|youtube|facebook|instagram|twitter|x|tiktok|telegram|whatsapp|wikipedia|wikimedia|openai|anthropic|huggingface|torproject|apple|icloud|nist|cisa|github)\.' "$tmp/sni-full.txt"; then
            echo 'FAIL: SNI library contains high-risk blocked/sanction-sensitive domains'
            failures=$((failures + 1))
        fi
        printf '%s\n' '# malformed candidate fixture' 'valid.example.org' 'bad host.example.org' > "$tmp/sni-invalid-source.txt"
        if sni_normalize_candidate_file "$tmp/sni-invalid-source.txt" "$tmp/sni-invalid-normalized.txt"; then
            echo 'FAIL: SNI database validator accepted an invalid hostname'; failures=$((failures + 1))
        fi
        ABOX_SNI_CANDIDATE_SOURCE_OVERRIDE="$selftest_sni_seed" ABOX_SNI_MINI_MAX=0 write_sni_candidate_library mini "$tmp/sni-mini.txt"
        mini_count=$(wc -l < "$tmp/sni-mini.txt" | tr -d ' ')
        [[ "$mini_count" =~ ^[0-9]+$ && "$mini_count" -eq "$sni_count" ]] || { echo "FAIL: SNI mini library does not match full library ($mini_count vs $sni_count)"; failures=$((failures + 1)); }
    else
        echo 'SELF_TEST_NOTE: SNI candidate integration test skipped (no adjacent database/cache; network is not used by self-test)' >&2
    fi
    declare -f asn_lookup_ip >/dev/null || { echo 'FAIL: ASN lookup function missing'; failures=$((failures + 1)); }
    declare -f sni_org_cdn_penalty >/dev/null || { echo 'FAIL: ASN/CDN scoring function missing'; failures=$((failures + 1)); }
    [[ "$(tr_msg confirm_local_sni_full)" != *'远程执行第三方脚本'* ]] || { echo 'FAIL: local SNI prompt still says remote third-party'; failures=$((failures + 1)); }
    grep -Fq 'en:reality_non443_warn)' "$0" || { echo 'FAIL: English non-443 SNI warning translation missing'; failures=$((failures + 1)); }
    grep -Fq 'en:apple_sni_warn)' "$0" || { echo 'FAIL: English Apple/iCloud SNI warning translation missing'; failures=$((failures + 1)); }
    declare -F sni_domain_public_dns >/dev/null 2>&1 || { echo 'FAIL: SNI public-DNS guard missing'; failures=$((failures + 1)); }
    grep -Fq 'need_cmd_pkg groupadd passwd shadow-utils shadow' "$0" || { echo 'FAIL: group management dependency mapping missing'; failures=$((failures + 1)); }
    grep -Fq 'need_cmd_pkg useradd passwd shadow-utils shadow' "$0" || { echo 'FAIL: user management dependency mapping missing'; failures=$((failures + 1)); }
    grep -Fq 'addgroup -S "$group"' "$0" || { echo 'FAIL: Alpine BusyBox addgroup fallback missing'; failures=$((failures + 1)); }
    grep -Fq 'adduser -S -D -H -s /sbin/nologin -G "$group" "$user"' "$0" || { echo 'FAIL: Alpine BusyBox adduser fallback missing'; failures=$((failures + 1)); }
    assert_ok valid_ipv4_cidr 192.0.2.1/24
    assert_bad valid_ipv4_cidr 001.002.003.004/24
    assert_bad valid_ip_address 001.002.003.004
    assert_bad valid_ipv4_cidr 999.0.2.1/24
    assert_bad valid_ipv4_cidr 192.0.2.1/999999999999999999999999999
    assert_bad valid_ipv4_cidr 192.0.2.999999999999999999999999/24
    assert_bad valid_ipv4_cidr '192.0.2.1/'
    assert_ok valid_ip_address 192.0.2.1
    assert_bad valid_ip_address 192.0.2.1/24
    if selftest_has python3; then
        getent() { printf '%s\n' '1.1.1.1 STREAM example.com'; }
        assert_ok sni_domain_public_dns example.com
        getent() { printf '%s\n' '10.0.0.1 STREAM example.com'; }
        assert_bad sni_domain_public_dns example.com
        unset -f getent
        assert_ok valid_public_ip 1.1.1.1
        assert_bad valid_public_ip 224.0.0.1
        assert_bad valid_public_ip 239.255.255.255
        assert_bad valid_public_ip 192.88.99.1
        assert_bad valid_public_ip 64:ff9b::8.8.8.8
        assert_bad valid_public_ip ::ffff:8.8.8.8
        assert_ok valid_public_ip 2606:4700:4700::1111
        assert_bad valid_public_ip 10.0.0.1
        assert_bad valid_public_ip 192.168.1.1
        assert_bad valid_public_ip 172.16.0.1
        assert_bad valid_public_ip 100.64.0.1
        assert_bad valid_public_ip 127.0.0.1
        assert_bad valid_public_ip 169.254.1.1
        assert_bad valid_public_ip 198.51.100.1
        assert_bad valid_public_ip fc00::1
        assert_bad valid_public_ip fe80::1
        assert_bad valid_public_ip ::1
        assert_bad valid_public_ip 2001:db8::1
        assert_ok valid_ipv6_cidr 2001:db8::1/64
        assert_bad valid_ipv6_cidr 2001:::1/64
        assert_bad valid_ipv6_cidr 2001:db8::1/999999999999999999999999999
        assert_bad valid_ipv6_cidr '2001:db8::1/'
        assert_bad valid_ipv6_cidr ::/0
        assert_bad valid_ipv6_cidr 2001:db8::/0
        assert_ok valid_ip_address 2001:db8::1
        assert_bad valid_ip_address 2001:db8::1/64
    else
        selftest_note 'public-IP / IPv6 / SNI DNS validator tests skipped (python3 missing)'
    fi
    declare -F backup_current_config >/dev/null 2>&1 || { echo 'FAIL: backup_current_config missing'; failures=$((failures + 1)); }
    declare -F export_diagnostic_bundle >/dev/null 2>&1 || { echo 'FAIL: export_diagnostic_bundle missing'; failures=$((failures + 1)); }
    grep -Fq 'refusing to report a false Saved state' "$0" || { echo 'FAIL: SNI persistence must fail closed'; failures=$((failures + 1)); }
    grep -Fq 'Diagnostic bundle checksum generation failed' "$0" || { echo 'FAIL: diagnostic checksum failures must be blocking'; failures=$((failures + 1)); }
    declare -F write_diagnostic_checksum >/dev/null 2>&1 || { echo 'FAIL: diagnostic checksum helper missing'; failures=$((failures + 1)); }
    declare -F preflight_check >/dev/null 2>&1 || { echo 'FAIL: preflight_check missing'; failures=$((failures + 1)); }
    bash -n "$0" >/dev/null 2>&1 || { echo 'FAIL: installer source must pass bash -n'; failures=$((failures + 1)); }
    declare -F confirm_remote_script_hash >/dev/null 2>&1 || { echo 'FAIL: remote script hash gate missing'; failures=$((failures + 1)); }
    declare -F confirm_ota_script_hash >/dev/null 2>&1 || { echo 'FAIL: OTA hash gate missing'; failures=$((failures + 1)); }
    declare -F validate_ota_version_direction >/dev/null 2>&1 || { echo 'FAIL: OTA anti-downgrade gate missing'; failures=$((failures + 1)); }
    declare -F install_deployment_transaction_traps >/dev/null 2>&1 || { echo 'FAIL: deployment signal traps missing'; failures=$((failures + 1)); }
    declare -F install_core_upgrade_transaction_traps >/dev/null 2>&1 || { echo 'FAIL: core-upgrade signal traps missing'; failures=$((failures + 1)); }
    declare -F convert_legacy_backup_archive >/dev/null 2>&1 || { echo 'FAIL: legacy backup converter missing'; failures=$((failures + 1)); }
    declare -F record_core_family_ownership >/dev/null 2>&1 || { echo 'FAIL: per-file core ownership missing'; failures=$((failures + 1)); }
    declare -F refresh_dynamic_core_subtree_ownership >/dev/null 2>&1 || { echo 'FAIL: dynamic ACME ownership refresh missing'; failures=$((failures + 1)); }
    declare -F prepare_hysteria_acme_dir_ownership >/dev/null 2>&1 || { echo 'FAIL: Hysteria ACME ownership preparation missing'; failures=$((failures + 1)); }
    grep -q 'refresh_dynamic_core_subtree_ownership hysteria /etc/hysteria/acme' "$0" || { echo 'FAIL: Hysteria cleanup does not refresh dynamic ACME ownership'; failures=$((failures + 1)); }
    grep -q 'A-Box managed Hysteria ACME directory v1' "$0" || { echo 'FAIL: Hysteria ACME ownership marker missing'; failures=$((failures + 1)); }
    grep -q 'prepare_hysteria_acme_dir_ownership' "$0" || { echo 'FAIL: Hysteria ACME ownership gate missing'; failures=$((failures + 1)); }
    grep -q 'prepare_hysteria_acme_dir_ownership || return 1' "$0" || { echo 'FAIL: Hysteria cleanup legacy ownership migration gate missing'; failures=$((failures + 1)); }
    declare -F validate_abox_cron_file >/dev/null 2>&1 || { echo 'FAIL: cron semantic validator missing'; failures=$((failures + 1)); }
    _managed_paths_fixture="$tmp/all-managed-paths.txt"
    _saved_init_for_paths="${INIT_SYS:-}"
    INIT_SYS=systemd
    { managed_auxiliary_paths; for _srv in xray sing-box hysteria; do core_family_paths "$_srv" || exit 1; done; } | awk 'NF && !seen[$0]++' > "$_managed_paths_fixture" || { echo 'FAIL: authoritative managed-path enumeration'; failures=$((failures + 1)); }
    if selftest_has python3; then
        validate_managed_paths_file "$_managed_paths_fixture" || { echo 'FAIL: full managed-path set must pass recovery whitelist validation'; failures=$((failures + 1)); }
        grep -Fxq '/etc/modules-load.d/A-Box-bbr.conf' "$_managed_paths_fixture" || { echo 'FAIL: BBR managed path missing from authoritative test set'; failures=$((failures + 1)); }
        printf '%s\n' '/etc/A-Box-selftest-unmanaged-path' >> "$_managed_paths_fixture"
        if validate_managed_paths_file "$_managed_paths_fixture"; then echo 'FAIL: unmanaged recovery path accepted'; failures=$((failures + 1)); fi
    else
        selftest_note 'managed-path whitelist validation skipped (python3 missing)'
        grep -Fxq '/etc/modules-load.d/A-Box-bbr.conf' "$_managed_paths_fixture" || { echo 'FAIL: BBR managed path missing from authoritative test set'; failures=$((failures + 1)); }
    fi
    INIT_SYS="$_saved_init_for_paths"
    unset _saved_init_for_paths
    [[ "$ABOX_BUILD_EPOCH" =~ ^[0-9]+$ ]] || { echo 'FAIL: numeric build epoch missing'; failures=$((failures + 1)); }
    declare -F remove_ss_open_accept_rules >/dev/null 2>&1 || { echo 'FAIL: SS open ACCEPT cleanup missing'; failures=$((failures + 1)); }
    declare -F show_sni_preference_records >/dev/null 2>&1 || { echo 'FAIL: SNI record viewer missing'; failures=$((failures + 1)); }
    declare -F validate_abox_script_file >/dev/null 2>&1 || { echo 'FAIL: local script validation gate missing'; failures=$((failures + 1)); }
    declare -F install_remote_abox_script_guarded >/dev/null 2>&1 || { echo 'FAIL: guarded remote shortcut installer missing'; failures=$((failures + 1)); }
    declare -F validate_fail2ban_config_or_die >/dev/null 2>&1 || { echo 'FAIL: fail2ban validation gate missing'; failures=$((failures + 1)); }
    declare -F ensure_vnstat_runtime >/dev/null 2>&1 || { echo 'FAIL: vnStat runtime gate missing'; failures=$((failures + 1)); }
    declare -F validate_abox_env_file_for_write >/dev/null 2>&1 || { echo 'FAIL: A-Box env ownership validator missing'; failures=$((failures + 1)); }
    declare -F remove_owned_runtime_helper >/dev/null 2>&1 || { echo 'FAIL: runtime helper ownership remover missing'; failures=$((failures + 1)); }
    grep -Fxq '# Managed by A-Box' <(printf '%s\n' '# Managed by A-Box') || { echo 'FAIL: self-test process substitution'; failures=$((failures + 1)); }
    printf '%s\n' '# Managed by A-Box' 'TRAFFIC_LIMIT_GB' 'month_bytes() {}' > "$tmp/traffic_monitor.sh"
    auxiliary_content_is_abox_managed "$tmp/traffic_monitor.sh" /etc/ddr/traffic_monitor.sh || { echo 'FAIL: managed traffic helper ownership'; failures=$((failures + 1)); }
    printf '%s\n' '# foreign' 'TRAFFIC_LIMIT_GB' 'month_bytes() {}' > "$tmp/foreign-traffic.sh"
    ! auxiliary_content_is_abox_managed "$tmp/foreign-traffic.sh" /etc/ddr/traffic_monitor.sh || { echo 'FAIL: foreign traffic helper accepted as managed'; failures=$((failures + 1)); }
    if (( EUID == 0 )); then
        printf '%s\n' '# Managed by A-Box' > "$tmp/A-Box-firewall.service"
        auxiliary_content_is_abox_managed "$tmp/A-Box-firewall.service" /etc/systemd/system/A-Box-firewall.service || { echo 'FAIL: A-Box firewall service ownership marker'; failures=$((failures + 1)); }
        printf '%s\n' '# foreign' > "$tmp/foreign-firewall.service"
        ! auxiliary_content_is_abox_managed "$tmp/foreign-firewall.service" /etc/systemd/system/A-Box-firewall.service || { echo 'FAIL: foreign firewall service accepted as managed'; failures=$((failures + 1)); }
    fi
    grep -Fq 'User=abox-xray' "$0" || { echo 'FAIL: Xray systemd unit must drop root UID'; failures=$((failures + 1)); }
    grep -Fq 'command_user="abox-xray:abox-xray"' "$0" || { echo 'FAIL: Xray OpenRC service must drop root UID'; failures=$((failures + 1)); }
    grep -Fq 'capabilities="${HY2_RC_CAPS}"' "$0" || { echo 'FAIL: Hysteria OpenRC capabilities missing'; failures=$((failures + 1)); }
    grep -Fq 'write_file_atomically_from_stdin /etc/init.d/hysteria 755 <<EOF_SVC' "$0" || { echo 'FAIL: Hysteria OpenRC capabilities heredoc must expand deployment-time value'; failures=$((failures + 1)); }
    [[ "$(grep -Fc 'capabilities="cap_net_bind_service"' "$0")" -ge 2 ]] || { echo 'FAIL: Xray/Sing-box OpenRC capabilities missing'; failures=$((failures + 1)); }
    grep -Fq 'User=abox-singbox' "$0" || { echo 'FAIL: Sing-box systemd unit must drop root UID'; failures=$((failures + 1)); }
    grep -Fq 'command_user="abox-singbox:abox-singbox"' "$0" || { echo 'FAIL: Sing-box OpenRC service must drop root UID'; failures=$((failures + 1)); }
    grep -Fq 'User=abox-hysteria' "$0" || { echo 'FAIL: Hysteria systemd unit must drop root UID'; failures=$((failures + 1)); }
    grep -Fq 'command_user="abox-hysteria:abox-hysteria"' "$0" || { echo 'FAIL: Hysteria OpenRC service must drop root UID'; failures=$((failures + 1)); }
    grep -q 'SagerNet/sing-box:singbox_core.tar.gz) release_ref="${ABOX_SINGBOX_VERSION:-$ABOX_SINGBOX_DEFAULT_VERSION}"' "$0" || { echo 'FAIL: sing-box default stable pin resolver changed'; failures=$((failures + 1)); }
    grep -Fq "ABOX_SINGBOX_DEFAULT_VERSION='v1.14.2'" "$0" || { echo 'FAIL: sing-box stable pin missing'; failures=$((failures + 1)); }
    grep -q 'XTLS/Xray-core:xray_core.zip) release_ref="${ABOX_XRAY_VERSION:-$ABOX_XRAY_DEFAULT_VERSION}"' "$0" || { echo 'FAIL: Xray default pin resolver changed'; failures=$((failures + 1)); }
    [[ "$(effective_xray_version)" == "$ABOX_XRAY_DEFAULT_VERSION" ]] || { echo 'FAIL: effective Xray default version'; failures=$((failures + 1)); }
    ( ABOX_XRAY_VERSION=v26.9.8 xray_reality_requires_mlkem ) || { echo 'FAIL: Xray 26.9.8 must require REALITY ML-KEM'; failures=$((failures + 1)); }
    ( ABOX_XRAY_VERSION=v26.7.28 xray_reality_requires_mlkem ) && { echo 'FAIL: Xray 26.7.28 must not require REALITY ML-KEM'; failures=$((failures + 1)); }
    [[ "$(effective_xray_version)" == "$ABOX_XRAY_DEFAULT_VERSION" ]] || { echo 'FAIL: effective Xray compatibility default'; failures=$((failures + 1)); }
    ( ABOX_XRAY_VERSION=v26.9 xray_reality_requires_mlkem ) >/dev/null 2>&1 && { echo 'FAIL: malformed Xray version accepted'; failures=$((failures + 1)); }
    grep -Fq 'support-x25519mlkem768: $clash_mlkem' "$0" || { echo 'FAIL: Clash REALITY ML-KEM flag must be version-aware'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_HYSTERIA_APP_VERSION:-app/v2.13.0' "$0" || { echo 'FAIL: Hysteria v2.13.0 compatibility pin missing'; failures=$((failures + 1)); }
    grep -Fq "ABOX_XRAY_DEFAULT_VERSION='v26.7.28'" "$0" || { echo 'FAIL: Xray iOS/XHTTP compatibility pin missing'; failures=$((failures + 1)); }

    grep -Fq "ABOX_BUILD='2026-10-10-release-candidate-v172'" "$0" || { echo 'FAIL: build string missing'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_BUILD_EPOCH=20261010172' "$0" || { echo 'FAIL: build epoch missing'; failures=$((failures + 1)); }
    grep -Fq 'IP_PREF_FILE=' "$0" || { echo 'FAIL: IP preference state file missing'; failures=$((failures + 1)); }
    grep -Fq 'ip_preference_menu()' "$0" || { echo 'FAIL: IP preference menu missing'; failures=$((failures + 1)); }
    grep -Fq 'dns_menu()' "$0" || { echo 'FAIL: DNS menu missing'; failures=$((failures + 1)); }
    grep -Fq 'timezone_menu()' "$0" || { echo 'FAIL: timezone menu missing'; failures=$((failures + 1)); }
    grep -Fq 'run_mirrored_test_script()' "$0" || { echo 'FAIL: test mirror fallback missing'; failures=$((failures + 1)); }
    grep -Fq "ABOX_TEST_MIRROR_RELEASE='test-tools-mirror-v173'" "$0" || { echo 'FAIL: test tool mirror release missing'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_CORE_MIRROR_BASE_DEFAULT=' "$0" || { echo 'FAIL: core disaster mirror base missing'; failures=$((failures + 1)); }
    grep -Fq '截至当前 / Usage up to now' "$0" || { echo 'FAIL: traffic up-to-now banner missing'; failures=$((failures + 1)); }
    grep -Fq 'one_click_reality_deploy()' "$0" || { echo 'FAIL: one-click Reality missing'; failures=$((failures + 1)); }
    grep -Fq 'abox_is_fast()' "$0" || { echo 'FAIL: fast mode helper missing'; failures=$((failures + 1)); }
    grep -Fq 'try_latest_cores_danger()' "$0" || { echo 'FAIL: try-latest cores missing'; failures=$((failures + 1)); }
    grep -Fq 'export_lightweight_subscription()' "$0" || { echo 'FAIL: lightweight subscription missing'; failures=$((failures + 1)); }
    grep -Fq 'probe_core_sources_banner()' "$0" || { echo 'FAIL: download source probe missing'; failures=$((failures + 1)); }
    grep -Fq 'fetch_abox_mirror_asset()' "$0" || { echo 'FAIL: mirror asset helper missing'; failures=$((failures + 1)); }

    assert_ok valid_ip_pref ipv4
    assert_ok valid_ip_pref ipv6
    assert_ok valid_ip_pref dual
    assert_bad valid_ip_pref both
    assert_ok valid_timezone_name UTC
    assert_bad valid_timezone_name '../etc/passwd'
    [[ "$(timezone_for_country CN)" == 'Asia/Shanghai' ]] || { echo 'FAIL: CN timezone heuristic'; failures=$((failures + 1)); }
    [[ "$(timezone_for_country US)" == 'America/New_York' ]] || { echo 'FAIL: US timezone heuristic'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_SNI_DEFAULT_MAX=8192' "$0" || { echo 'FAIL: SNI default max missing'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v26.7.28 v26.3.27)" == '1' ]] || { echo 'FAIL: Xray version comparison'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v26.7.28 v26.7.28)" == '0' ]] || { echo 'FAIL: Xray compatibility pin comparison'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v26.3.27 v26.3.27)" == '0' ]] || { echo 'FAIL: Xray equal version comparison'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v26.3.27 v26.7.28)" == '-1' ]] || { echo 'FAIL: Xray reverse version comparison'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v9223372036854775808.0.0 v26.9.8)" == '1' ]] || { echo 'FAIL: Xray huge-version comparison overflow regression'; failures=$((failures + 1)); }
    [[ "$(xray_version_compare v18446744073709551616.0.0 v26.9.8)" == '1' ]] || { echo 'FAIL: Xray extra-large version comparison regression'; failures=$((failures + 1)); }
    grep -Fq "ABOX_XRAY_REALITY_MLKEM_MIN_VERSION='v26.9.8'" "$0" || { echo 'FAIL: Xray REALITY ML-KEM threshold constant missing'; failures=$((failures + 1)); }
    runtime_guard_impl_count=$(grep -Fc '( umask 077; set -C; : > "$RUNTIME_LOCK" )' "$0" || true)
    [[ "$runtime_guard_impl_count" =~ ^[0-9]+$ && "$runtime_guard_impl_count" -ge 3 ]] || { echo 'FAIL: all background helpers must recreate the runtime lock after /run recreation'; failures=$((failures + 1)); }
    runtime_guard_count=$(grep -Fc 'RUNTIME_LOCK=/run/A-Box.lock' "$0" || true)
    [[ "$runtime_guard_count" =~ ^[0-9]+$ && "$runtime_guard_count" -ge 3 ]] || { echo 'FAIL: all background helpers must honor the global A-Box runtime lock'; failures=$((failures + 1)); }
    grep -Fq 'systemctl disable "$srv"' "$0" || { echo 'FAIL: traffic quota stop path must disable systemd autostart'; failures=$((failures + 1)); }
    grep -Fq 'rc-update del "$srv" default' "$0" || { echo 'FAIL: traffic quota stop path must remove OpenRC autostart'; failures=$((failures + 1)); }
    grep -Fq 'start-stop-daemon --stop --pidfile "$pidfile" --exec "$exe" --retry TERM/5/KILL/1' "$0" || { echo 'FAIL: OpenRC stop fallback must bind PID to expected executable'; failures=$((failures + 1)); }
    ( verify_github_asset_digest /dev/null '' ) >/dev/null 2>&1 && { echo 'FAIL: missing GitHub digest must be rejected'; failures=$((failures + 1)); }
    grep -q '\[\[ "\${digest#sha256:}" =~ \^\[A-Fa-f0-9\]{64}\$ \]\]' "$0" || { echo 'FAIL: fetch helper must prevalidate GitHub digest before mirror retry'; failures=$((failures + 1)); }
    ( ABOX_ASSUME_YES_OTA=1 confirm_ota_script_hash 0000000000000000000000000000000000000000000000000000000000000000 https://example.com/script.sh ) >/dev/null 2>&1 && { echo 'FAIL: ABOX_ASSUME_YES_OTA must be rejected without allowlist'; failures=$((failures + 1)); }
    grep -Fq 'env \\
        -u GITHUB_TOKEN' "$0" || { echo 'FAIL: remote third-party scripts must not inherit GITHUB_TOKEN'; failures=$((failures + 1)); }

    [[ "$(normalize_port_spec 020000-025000)" == '20000:25000' ]] || { echo 'FAIL: normalize port range'; failures=$((failures + 1)); }
    HY2_DOMAIN=example.com HY2_ACME_TYPE=http CORE_IN=hysteria MODE_IN=HY2 VLESS_PORT=8443 XHTTP_PORT=9443 SS_PORT=2053 HY2_BASE_PORT=443 HY2_HOP=false HY2_HOP_IMPL=none
    [[ "$(selected_port_pairs | grep -Fx 'tcp/80')" == 'tcp/80' ]] || { echo 'FAIL: Hysteria HTTP-01 must reserve TCP/80'; failures=$((failures + 1)); }
    CORE_IN=singbox MODE_IN=HY2
    [[ "$(selected_port_pairs | grep -Fx 'tcp/80')" != 'tcp/80' ]] || { echo 'FAIL: Sing-box HY2 must not reserve TCP/80'; failures=$((failures + 1)); }
    CORE_IN=xray MODE_IN=ALL HY2_ACME_TYPE=http
    [[ "$(selected_port_pairs | grep -Fx 'tcp/80')" == 'tcp/80' ]] || { echo 'FAIL: Xray ALL HTTP-01 must reserve TCP/80'; failures=$((failures + 1)); }
    HY2_ACME_TYPE=dns
    [[ "$(selected_port_pairs | grep -Fx 'tcp/80')" != 'tcp/80' ]] || { echo 'FAIL: DNS-01 must not reserve TCP/80'; failures=$((failures + 1)); }
    unset HY2_DOMAIN HY2_ACME_TYPE CORE_IN MODE_IN VLESS_PORT XHTTP_PORT SS_PORT HY2_BASE_PORT HY2_HOP HY2_HOP_IMPL
    [[ "$(sni_domain_penalty www.apple.com)" == '1800' ]] || { echo 'FAIL: Apple www SNI penalty'; failures=$((failures + 1)); }
    [[ "$(sni_domain_penalty maps.apple.com)" == '2400' ]] || { echo 'FAIL: Apple subdomain SNI penalty'; failures=$((failures + 1)); }
    [[ "$(sni_domain_penalty apple.com)" == '2400' ]] || { echo 'FAIL: Apple apex SNI penalty'; failures=$((failures + 1)); }
    [[ "$(sni_domain_penalty github.com)" == '2400' ]] || { echo 'FAIL: GitHub apex SNI penalty'; failures=$((failures + 1)); }
    [[ "$(sni_raw_score 0.1 0.1 0.1 -220)" == '-92' ]] || { echo 'FAIL: SNI raw score must preserve negative ranking values'; failures=$((failures + 1)); }
    [[ "$(sni_adjust_score -92 -1500)" == '-1592' ]] || { echo 'FAIL: SNI ASN bonus must preserve negative ranking values'; failures=$((failures + 1)); }
    [[ "$(sni_report_fit_tier tls13=1 alpn=h2 san=1 asnmatch=1 samecountry=1 cdnpenalty=0)" == 'A' ]] || { echo 'FAIL: SNI same-ASN compatible tier'; failures=$((failures + 1)); }
    [[ "$(sni_report_fit_tier tls13=1 alpn=h2 san=1 asnmatch=1 samecountry=1 cdnpenalty=500)" == 'R' ]] || { echo 'FAIL: SNI CDN-risk tier must override green recommendation'; failures=$((failures + 1)); }
    [[ "$(sni_report_fit_tier tls13=1 alpn=h2 san=1 asnmatch=0 samecountry=1 cdnpenalty=0)" == 'B' ]] || { echo 'FAIL: SNI same-country compatible tier'; failures=$((failures + 1)); }
    [[ "$(sni_report_fit_tier tls13=1 alpn=h2 san=1 asnmatch=0 samecountry=0 cdnpenalty=0)" == 'C' ]] || { echo 'FAIL: SNI other-ASN compatible tier'; failures=$((failures + 1)); }
    [[ "$(sni_report_fit_tier tls13=1 alpn=http/1.1 san=1 asnmatch=1 samecountry=1 cdnpenalty=0)" == 'D' ]] || { echo 'FAIL: SNI incompatible ALPN tier'; failures=$((failures + 1)); }
    [[ "$(sni_org_cdn_penalty api.cloudflare.com 'AS13335 Cloudflare, Inc.')" -ge 300 ]] || { echo 'FAIL: Cloudflare first-party target must retain CDN-risk label'; failures=$((failures + 1)); }
    [[ "$(sni_org_cdn_penalty api.fastly.com 'AS54113 Fastly, Inc.')" -ge 300 ]] || { echo 'FAIL: Fastly first-party target must retain CDN-risk label'; failures=$((failures + 1)); }
    ! grep -Fq 'NR <= 8' <(sed -n '/^traffic_management_menu() {$/,/^manage_ss_whitelist()/p' "$0") || { echo 'FAIL: monthly vnStat display must not truncate after 8 raw lines'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_SNI_FULL_TOPN:-100' "$0" || { echo 'FAIL: full SNI result display count default'; failures=$((failures + 1)); }
    ! grep -q '^MAIN_LOCK=/run/A-Box.lock$' "$0" || { echo 'FAIL: helper health probe still depends on interactive main lock'; failures=$((failures + 1)); }
    traffic_writer_body=$(sed -n '/write_private_line() {/,/^read_desired() {/p' "$0") || { echo 'FAIL: traffic helper writer static extraction'; failures=$((failures + 1)); }
    ! grep -q 'path_parent_chain_safe "\$dest"' <<< "$traffic_writer_body" || { echo 'FAIL: traffic helper calls main-only function'; failures=$((failures + 1)); }
    grep -q 'export XRAY_LOCATION_ASSET="/usr/local/share/xray"' "$0" || { echo 'FAIL: OpenRC Xray asset path is not exported'; failures=$((failures + 1)); }
    grep -q '^ABOX_CORE_OWNERSHIP=/etc/ddr/.managed-core-files.tsv$' "$0" || { echo 'FAIL: Geo updater ownership manifest path missing'; failures=$((failures + 1)); }
    grep -q '^update_geo_ownership() {' "$0" || { echo 'FAIL: Geo updater ownership refresh helper missing'; failures=$((failures + 1)); }
    grep -q 'if ! update_geo_ownership; then' "$0" || { echo 'FAIL: Geo updater does not roll back when ownership refresh fails'; failures=$((failures + 1)); }
    grep -q 'write_file_atomically_from_stdin "$ABOX_DIR/.swapfile.managed"' "$0" || { echo 'FAIL: managed swap marker missing'; failures=$((failures + 1)); }
    grep -q 'Authorization: Bearer %s' "$0" || { echo 'FAIL: GitHub bearer token config support missing'; failures=$((failures + 1)); }
    grep -q 'invalid request from' "$0" || { echo 'FAIL: Fail2Ban must cover exact Xray invalid-request scanner logs'; failures=$((failures + 1)); }
    grep -q 'backend=\$(firewall_backend)' "$0" || { echo 'FAIL: firewall backend routing missing'; failures=$((failures + 1)); }
    grep -q '^remove_abox_native_firewall_rule() {' "$0" || { echo 'FAIL: exact owned firewall port removal helper missing'; failures=$((failures + 1)); }
    grep -q '^forget_native_firewall_rule() {' "$0" || { echo 'FAIL: native firewall ownership-state removal helper missing'; failures=$((failures + 1)); }
    _forget_call_prefix='forget_native_firewall_rule'; _ufw_call_suffix=' "$spec" "$proto" ufw'; _fwd_call_suffix=' "$spec" "$proto" firewalld'
    grep -Fq -- "${_forget_call_prefix}${_ufw_call_suffix}" "$0" || { echo 'FAIL: UFW firewall-state removal must preserve backend ownership'; failures=$((failures + 1)); }
    grep -Fq -- "${_forget_call_prefix}${_fwd_call_suffix}" "$0" || { echo 'FAIL: firewalld firewall-state removal must preserve backend ownership'; failures=$((failures + 1)); }
    grep -q '^preflight_reset_ownership() {' "$0" || { echo 'FAIL: reset ownership preflight missing'; failures=$((failures + 1)); }
    grep -Fq 'command clear || true' "$0" || { echo 'FAIL: non-interactive clear guard missing'; failures=$((failures + 1)); }
    grep -Fq 'if [[ -t 0 ]]; then' "$0" || { echo 'FAIL: pause_return TTY guard missing'; failures=$((failures + 1)); }
    _http01_cleanup_call='remove_abox_native_firewall_rule'; _http01_cleanup_args=' 80 tcp'
    ! grep -Fq -- "${_http01_cleanup_call}${_http01_cleanup_args}" "$0" || { echo 'FAIL: HTTP-01 must keep 80/tcp reachable for CertMagic HTTP challenge and renewal'; failures=$((failures + 1)); }
    _hop_udp_regex='-p udp'; _hop_redirect_regex='REDIRECT --to-ports'
    _hop_udp_rule_count=$(grep -F -- "$_hop_udp_regex" "$0" | grep -Fc -- "$_hop_redirect_regex" || true)
    [[ "$_hop_udp_rule_count" -ge 4 ]] || { echo 'FAIL: HY2 official hop iptables checks must require UDP in both verifier copies'; failures=$((failures + 1)); }
    _http01_cleanup_helper='cleanup_http01_port_after_' ; _http01_cleanup_helper+='hy2_start'
    ! grep -Fq -- "$_http01_cleanup_helper" "$0" || { echo 'FAIL: obsolete HTTP-01 post-start cleanup path remains'; failures=$((failures + 1)); }
    grep -Fq 'IPv6 白名单已配置，但系统没有可用 IPv6 防火墙' "$0" || { echo 'FAIL: IPv6 whitelist silent-skip guard missing'; failures=$((failures + 1)); }
    grep -Fq 'if [[ "$current_line" =~ ^-A[[:space:]]+INPUT[[:space:]] ]]; then' "$0" || { echo 'FAIL: firewall rule numbering must skip policy/header lines'; failures=$((failures + 1)); }
    grep -q 'iptables_rule_check() {' "$0" || { echo 'FAIL: standalone firewall restore helper missing'; failures=$((failures + 1)); }
    grep -q 'f2b_action='"'"'firewallcmd-multiport'"'"'' "$0" || { echo 'FAIL: Fail2Ban firewalld action mapping missing'; failures=$((failures + 1)); }
    grep -q 'f2b_action='"'"'ufw'"'"'' "$0" || { echo 'FAIL: Fail2Ban UFW action mapping missing'; failures=$((failures + 1)); }
    grep -q 'bbr_module_file=' "$0" || { echo 'FAIL: BBR module persistence path missing'; failures=$((failures + 1)); }
    grep -q '^    local -a pids=() exes=()' "$0" || { echo 'FAIL: parallel residual PID collection missing'; failures=$((failures + 1)); }
    grep -q 'pid_exe_matches "$pid" "$exe"' "$0" || { echo 'FAIL: PID reuse executable recheck missing'; failures=$((failures + 1)); }
    grep -q 'selftest_abox_signature()' "$0" || { echo 'FAIL: live /etc/ddr side-effect regression guard missing'; failures=$((failures + 1)); }
    grep -q -- '--config -' "$0" || { echo 'FAIL: GitHub token pipe config guard missing'; failures=$((failures + 1)); }
    grep -q '2300000' "$0" || { echo 'FAIL: swap free-space safety check missing'; failures=$((failures + 1)); }
    grep -q 'created_by_abox == 1' "$0" || { echo 'FAIL: swap ownership must only be recorded for A-Box-created swap'; failures=$((failures + 1)); }
    grep -q '^swapfile_active_state() {' "$0" || { echo 'FAIL: Swap activity query must have explicit three-state error handling'; failures=$((failures + 1)); }
    grep -Fq '无法可靠判断 /swapfile 当前是否已激活' "$0" || { echo 'FAIL: Swap activity query failure must fail closed'; failures=$((failures + 1)); }
    swapon() { printf '%s\n' '/swapfile'; }
    [[ "$(swapfile_active_state; echo "$?")" == '0' ]] || { echo 'FAIL: Swap activity query active state'; failures=$((failures + 1)); }
    swapon() { :; }
    [[ "$(swapfile_active_state; echo "$?")" == '1' ]] || { echo 'FAIL: Swap activity query inactive state'; failures=$((failures + 1)); }
    swapon() { return 42; }
    [[ "$(swapfile_active_state; echo "$?")" == '2' ]] || { echo 'FAIL: Swap activity query error state'; failures=$((failures + 1)); }
    unset -f swapon
    grep -q '^fstab_path_is_safe() {' "$0" || { echo 'FAIL: swap fstab trust helper missing'; failures=$((failures + 1)); }
    grep -q 'fstab_path_is_safe || return 1' "$0" || { echo 'FAIL: swap removal must validate trusted fstab before mutation'; failures=$((failures + 1)); }
    grep -q '保留 fstab 备份' "$0" || { echo 'FAIL: Swap rollback must retain fstab recovery material when rollback fails'; failures=$((failures + 1)); }
    grep -q 'Swap 无法安全关闭' "$0" || { echo 'FAIL: Swap setup must not delete an active swapfile when swapoff fails'; failures=$((failures + 1)); }
    grep -q '检测到全局 IPv6' "$0" || { echo 'FAIL: IPv6 manual HY2 hop guard missing'; failures=$((failures + 1)); }
    grep -q "环境初始化时 Fail2Ban 重启失败" "$0" || { echo 'FAIL: environment reset must restart Fail2Ban after removing A-Box jail'; failures=$((failures + 1)); }
    grep -Fq '[[ "$value" != *[[:cntrl:]]* ]]' "$0" || { echo 'FAIL: secret validator must reject control characters'; failures=$((failures + 1)); }
    grep -Fq '[[ "$fmt" != *' "$0" || { echo 'FAIL: translation printf must reject backslash escapes'; failures=$((failures + 1)); }
    ( tr_msg() { printf '%s' 'bad\q %s'; }; tprintf synthetic test ) >/dev/null 2>&1 && { echo 'FAIL: tprintf accepted a backslash escape in a translation'; failures=$((failures + 1)); }
    ( tr_msg() { printf '%s' '%n'; }; tprintf synthetic ) >/dev/null 2>&1 && { echo 'FAIL: tprintf accepted an unsupported printf conversion'; failures=$((failures + 1)); }
    ( tr_msg() { printf '%s' '%s %s'; }; tprintf synthetic only-one ) >/dev/null 2>&1 && { echo 'FAIL: tprintf accepted mismatched placeholder arguments'; failures=$((failures + 1)); }
    grep -q 'command -v ss >/dev/null 2>&1 || return 2' "$0" || { echo 'FAIL: health probe socket checker must distinguish unavailable ss'; failures=$((failures + 1)); }
    grep -q '2) exit 0 ;;' "$0" || { echo 'FAIL: health probe must not restart services when ss is unavailable'; failures=$((failures + 1)); }
    grep -q 'PY_VNSTAT_TOTAL_MAIN' "$0" || { echo 'FAIL: main vnStat total must use exact integer arithmetic'; failures=$((failures + 1)); }
    grep -q 'PY_VNSTAT_TOTAL_MONITOR' "$0" || { echo 'FAIL: traffic monitor vnStat total must use exact integer arithmetic'; failures=$((failures + 1)); }
    grep -q 'PY_TRAFFIC_COMPARE' "$0" || { echo 'FAIL: traffic quota comparison must use exact integer arithmetic'; failures=$((failures + 1)); }
    ! grep -q '^    \[\[ -d /run/systemd/system \]\] && return 0$' "$0" || { echo 'FAIL: systemd detection must not trust /run/systemd/system alone'; failures=$((failures + 1)); }
    cron_guard_in=$(mktemp /tmp/A-Box-selftest-cron-in.XXXXXX) || { echo 'FAIL: cron regression temp creation'; failures=$((failures + 1)); selftest_cleanup; return 1; }
    cron_guard_out=$(mktemp /tmp/A-Box-selftest-cron-out.XXXXXX) || { rm -f "$cron_guard_in"; echo 'FAIL: cron regression temp creation'; failures=$((failures + 1)); selftest_cleanup; return 1; }
    printf '%s\n' '*/5 * * * * /usr/local/bin/user-job /etc/ddr/geo_update.sh --keep-this' '* * * * * /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1' '# A-Box GEO BEGIN' '0 3 * * 1 /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1' '# A-Box GEO END' > "$cron_guard_in"
    strip_abox_cron_blocks_from_file "$cron_guard_in" "$cron_guard_out" GEO || { rm -f "$cron_guard_in" "$cron_guard_out"; echo 'FAIL: cron exact-command cleanup'; failures=$((failures + 1)); }
    grep -Fxq '*/5 * * * * /usr/local/bin/user-job /etc/ddr/geo_update.sh --keep-this' "$cron_guard_out" || { echo 'FAIL: cron cleanup removed a user-owned command containing an A-Box path'; failures=$((failures + 1)); }
    grep -Fxq '* * * * * /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1' "$cron_guard_out" || { echo 'FAIL: unmarked legacy-like GEO cron must be preserved'; failures=$((failures + 1)); }
    ! grep -Fxq '0 3 * * 1 /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1' "$cron_guard_out" || { echo 'FAIL: marked A-Box GEO cron block was not removed'; failures=$((failures + 1)); }
    rm -f "$cron_guard_in" "$cron_guard_out"
    static_body=$(mktemp /tmp/A-Box-selftest-static.XXXXXX) || { echo 'FAIL: self-test static filter temp creation'; failures=$((failures + 1)); selftest_cleanup; return 1; }
    awk '
      /^run_self_tests\(\)/ {skip=1}
      /^main\(\) \{/ {skip=0}
      !skip {print}
    ' "$0" > "$static_body" || { rm -f "$static_body"; echo 'FAIL: self-test static filter'; failures=$((failures + 1)); return 1; }
    grep -Eq 'crontab -l[^\n]*\|.*\|\| true' "$static_body" && { rm -f "$static_body"; echo 'FAIL: crontab read failure must not be swallowed'; failures=$((failures + 1)); return 1; }
    grep -Eq 'remove_abox_cron_block GEO 2>/dev/null \|\| true' "$static_body" && { rm -f "$static_body"; echo 'FAIL: Geo cron removal failure must not be swallowed'; failures=$((failures + 1)); return 1; }
    rm -f "$static_body"
    _devfd_pattern='/dev/''fd/3'; ! grep -q "python3 ${_devfd_pattern}" "$0" || { echo 'FAIL: /dev/fd/3 portability dependency remains'; failures=$((failures + 1)); }
    unset _devfd_pattern
    [[ "$(port_spec_for_firewalld 20000:25000)" == '20000-25000' ]] || { echo 'FAIL: firewalld range conversion'; failures=$((failures + 1)); }
    mkdir -p "$tmp/atomic-dest-dir"
    printf '%s\n' 'payload' > "$tmp/atomic.src2"
    assert_bad install_file_atomically "$tmp/atomic.src2" "$tmp/atomic-dest-dir" 600
    printf '%s\n' 'payload' | (write_file_atomically_from_stdin "$tmp/atomic-dest-dir" 600 >/dev/null 2>&1) && { echo 'FAIL: atomic stdin writer accepted destination directory'; failures=$((failures + 1)); }
    printf '%s\n' '#!/usr/bin/env bash' 'echo /etc/ddr/A-Box.sh' > "$tmp/foreign-shortcut.sh"
    ! auxiliary_content_is_abox_managed "$tmp/foreign-shortcut.sh" /usr/local/bin/sb || { echo 'FAIL: arbitrary shortcut mentioning A-Box path was treated as managed'; failures=$((failures + 1)); }
    printf '%s\n' '#!/usr/bin/env bash' 'exec bash /etc/ddr/A-Box.sh "$@"' 'exec sudo bash /etc/ddr/A-Box.sh "$@"' > "$tmp/legacy-shortcut.sh"
    auxiliary_content_is_abox_managed "$tmp/legacy-shortcut.sh" /usr/local/bin/sb || { echo 'FAIL: valid legacy shortcut fingerprint was rejected'; failures=$((failures + 1)); }
    assert_ok valid_port_spec 20000:25000
    assert_bad valid_port_spec 25000:20000
    _arch_case=$(printf '%s\n' 'armv8l')
    grep -Eq 'aarch64\|arm64\) XRAY_ARCH=.*SB_ARCH=.*HY2_ARCH' "$0" || { echo 'FAIL: AArch64 architecture selector missing'; failures=$((failures + 1)); }
    ! grep -Eq 'armv8\*\)' "$0" || { echo 'FAIL: 32-bit armv8 wildcard must not map to arm64'; failures=$((failures + 1)); }
    unset _arch_case
    for _hy2_uri_case in \
        443 \
        20000-25000 \
        443,8443 \
        443,20000-25000 \
        443,20000-25000,30000-30010 \
        1234,5678,9012 \
        1234,5000-6000,7044,8000-9000; do
        assert_ok valid_hy2_uri_ports "$_hy2_uri_case" || { echo "FAIL: HY2 multi-port validator rejected $_hy2_uri_case"; failures=$((failures + 1)); }
        HY2_URI_PORTS="$_hy2_uri_case"
        HY2_HOP=false
        HY2_HOP_IMPL=none
        if [[ "$(build_hy2_uri_endpoint)" != "$_hy2_uri_case"$'\t' ]]; then
            echo "FAIL: HY2 URI builder mismatch for $_hy2_uri_case"
            failures=$((failures + 1))
        fi
    done
    unset _hy2_uri_case HY2_URI_PORTS HY2_HOP HY2_HOP_IMPL
    assert_bad valid_hy2_uri_ports 443,20000:25000
    assert_bad valid_hy2_uri_ports 443,65535-65536
    assert_ok valid_hy2_clash_ports 20000-25000
    assert_ok valid_hy2_clash_ports 443
    assert_bad valid_hy2_clash_ports 20000:25000
    assert_bad valid_hy2_clash_ports 65535-65536
    assert_ok valid_hy2_sb_ports 20000:25000
    assert_bad valid_hy2_sb_ports 20000-25000
    _x25519_pair=$'PrivateKey: private-test\nPassword (PublicKey): public-test\n'
    [[ "$(parse_x25519_keypair_output "$_x25519_pair")" == $'private-test\tpublic-test' ]] || { echo 'FAIL: Xray x25519 output parser'; failures=$((failures + 1)); }
    _x25519_pair=$'Private key: private-test-2\nPublic key: public-test-2\n'
    [[ "$(parse_x25519_keypair_output "$_x25519_pair")" == $'private-test-2\tpublic-test-2' ]] || { echo 'FAIL: Xray x25519 alternate-label parser'; failures=$((failures + 1)); }
    HY2_URI_PORTS='443,20000-25000'; HY2_HOP=true; HY2_HOP_IMPL=manual
    [[ "$(build_hy2_uri_endpoint)" == $'443,20000-25000\t' ]] || { echo 'FAIL: manual HY2 URI endpoint must serialize documented multi-port address directly'; failures=$((failures + 1)); }
    HY2_URI_PORTS='443'; HY2_HOP=true; HY2_HOP_IMPL=manual; HY2_BASE_PORT=443; HY2_RANGE_START=20000; HY2_RANGE_END=25000
    [[ "$(build_hy2_uri_endpoint)" == $'443\t' ]] || { echo 'FAIL: explicit persisted HY2 URI port must remain canonical'; failures=$((failures + 1)); }
    unset HY2_URI_PORTS
    [[ "$(build_hy2_uri_endpoint)" == $'443,20000-25000\t' ]] || { echo 'FAIL: manual HY2 URI endpoint must derive combined documented multi-port address'; failures=$((failures + 1)); }
    HY2_URI_PORTS='20000-25000'; HY2_HOP=true; HY2_HOP_IMPL=official
    [[ "$(build_hy2_uri_endpoint)" == $'20000-25000\t' ]] || { echo 'FAIL: official HY2 URI endpoint must preserve port range'; failures=$((failures + 1)); }
    unset HY2_URI_PORTS HY2_HOP HY2_HOP_IMPL HY2_RANGE_START HY2_RANGE_END HY2_BASE_PORT
    ( ip() { printf '%s\n' '8.8.8.8 dev wg0 src 192.0.2.2'; }; default_route_uses_warp ) || { echo 'FAIL: overlay default-route detector'; failures=$((failures + 1)); }
    ( ip() { printf '%s\n' '8.8.8.8 dev CloudflareWARP src 192.0.2.2'; }; default_route_uses_warp ) || { echo 'FAIL: CloudflareWARP default-route detector'; failures=$((failures + 1)); }
    ! ( ip() { printf '%s\n' '8.8.8.8 dev eth0 src 192.0.2.2'; }; default_route_uses_warp ) || { echo 'FAIL: ordinary default-route detector false positive'; failures=$((failures + 1)); }
    grep -q '^hysteria_official_hop_firewall_ok() {' "$0" || { echo 'FAIL: official HY2 hop firewall verifier missing'; failures=$((failures + 1)); }
    grep -Fq 'hysteria_official_hop_firewall_ok "$HY2_RANGE_START" "$HY2_RANGE_END" "$HY2_MONITOR_PORT"' "$0" || { echo 'FAIL: official HY2 deployment must verify hop firewall rules after startup'; failures=$((failures + 1)); }
    CORE=singbox MODE=HY2 HY2_BASE_PORT=443 HY2_UP=100 HY2_DOWN=1000 HY2_HOP=false HY2_HOP_IMPL=none
    validate_abox_env_semantics >/dev/null 2>&1 || { echo 'FAIL: valid HY2 bandwidth state'; failures=$((failures + 1)); }
    HY2_UP='not-a-number'
    validate_abox_env_semantics >/dev/null 2>&1 && { echo 'FAIL: invalid HY2 bandwidth state accepted'; failures=$((failures + 1)); }
    unset CORE MODE HY2_BASE_PORT HY2_UP HY2_DOWN HY2_HOP HY2_HOP_IMPL
    if selftest_has python3; then
    assert_ok valid_github_download_url XTLS/Xray-core https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip v26.9.30
    assert_ok valid_github_download_url HyNetworks/hysteria https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64 app/v2.13.0 hysteria-linux-amd64
    assert_bad valid_github_download_url HyNetworks/hysteria https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/../../evil app/v2.13.0 hysteria-linux-amd64
    assert_bad valid_github_download_url HyNetworks/hysteria 'https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64?x=1' app/v2.13.0 hysteria-linux-amd64
    assert_bad valid_github_download_url HyNetworks/hysteria 'https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-arm64' app/v2.13.0 hysteria-linux-amd64
    assert_bad valid_github_download_url XTLS/Xray-core https://github.com/XTLS/Xray-core/releases/download/v26.9.29/Xray-linux-64.zip v26.9.30
    assert_bad valid_github_download_url XTLS/Xray-core https://github.com/SagerNet/sing-box/releases/download/v1.14.1/Xray-linux-64.zip v26.9.30
    else
        selftest_note 'asset-pinned GitHub URL validator suite skipped (python3 missing)'
        assert_ok valid_github_download_url XTLS/Xray-core https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip v26.9.30
    fi

    # Non-GitHub Geo URLs must be refused (digest trust model); old file preserved.
    geo_existing="$tmp/geo-existing.dat"
    printf '%s' 'OLD-GEO-CONTENT' > "$geo_existing"
    if (
        fetch_geo_data geoip.dat https://example.invalid/geo "$geo_existing" >/dev/null 2>&1
    ); then
        echo 'FAIL: insecure non-GitHub Geo URL unexpectedly accepted'
        failures=$((failures + 1))
    fi
    [[ "$(cat "$geo_existing" 2>/dev/null)" == 'OLD-GEO-CONTENT' ]] || { echo 'FAIL: refused Geo update deleted/replaced valid old file'; failures=$((failures + 1)); }

    # GitHub Geo path: digest must fail closed and preserve old content.
    geo_bad_digest="$tmp/geo-bad-digest.dat"
    printf '%s' 'OLD-GEO-CONTENT' > "$geo_bad_digest"
    if (
        github_api_get() {
            printf '%s
' '{"tag_name":"latest","assets":[{"name":"geoip.dat","browser_download_url":"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/latest/geoip.dat","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
        }
        curl() {
            local out=''
            while (($#)); do
                case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
            done
            printf '%s' 'bad-download' > "$out"
            return 0
        }
        fetch_geo_data geoip.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat' "$geo_bad_digest" >/dev/null 2>&1
    ); then
        echo 'FAIL: Geo digest failure unexpectedly succeeded'
        failures=$((failures + 1))
    fi
    [[ "$(cat "$geo_bad_digest" 2>/dev/null)" == 'OLD-GEO-CONTENT' ]] || { echo 'FAIL: failed Geo digest update deleted/replaced valid old file'; failures=$((failures + 1)); }

    # Valid GitHub Geo replacement after digest+size checks.
    geo_success="$tmp/geo-success.dat"
    printf '%s' 'OLD-GEO-CONTENT' > "$geo_success"
    if ! (
        github_api_get() {
            local dig
            dig=$(dd if=/dev/zero bs=600000 count=1 status=none | sha256sum | awk '{print $1}')
            jq -nc --arg dig "$dig" '{tag_name:"latest",assets:[{name:"geosite.dat",browser_download_url:"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/latest/geosite.dat",digest:("sha256:"+$dig)}]}'
        }
        curl() {
            local out=''
            while (($#)); do
                case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
            done
            dd if=/dev/zero of="$out" bs=600000 count=1 status=none
        }
        fetch_geo_data geosite.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat' "$geo_success" >/dev/null 2>&1
    ); then
        echo 'FAIL: valid Geo replacement failed'
        failures=$((failures + 1))
    fi
    [[ "$(stat -c %s "$geo_success" 2>/dev/null || echo 0)" == '600000' ]] || { echo 'FAIL: valid Geo replacement was not atomically committed'; failures=$((failures + 1)); }

    # Core download helper must preserve an existing destination until the replacement
    # has passed structural and digest validation.
    github_existing="$tmp/existing-core.zip"
    printf '%s' 'OLD-CORE' > "$github_existing"
    if (
        github_api_get() {
            printf '%s\n' '{"assets":[{"name":"Xray-linux-64.zip","browser_download_url":"https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
        }
        curl() {
            local out=''
            while (($#)); do
                case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
            done
            printf '%s' 'invalid-archive' > "$out"
            return 0
        }
        XRAY_ARCH=64 ABOX_XRAY_VERSION=v26.9.30 fetch_github_release XTLS/Xray-core xray_core.zip "$github_existing" >/dev/null 2>&1
    ); then
        echo 'FAIL: invalid GitHub asset injection unexpectedly succeeded'
        failures=$((failures + 1))
    fi
    [[ "$(cat "$github_existing" 2>/dev/null)" == 'OLD-CORE' ]] || { echo 'FAIL: failed core download deleted/replaced existing destination'; failures=$((failures + 1)); }
    [[ "$(msg 'literal\nbackslash\ttext')" == $'literal\\nbackslash\\ttext' ]] || { echo 'FAIL: msg must not reinterpret backslash escapes'; failures=$((failures + 1)); }
    [[ "$(msg "${RED}X${NC}")" == $'\033[0;31mX\033[0m' ]] || { echo 'FAIL: ANSI color escapes must remain functional'; failures=$((failures + 1)); }

    if ! (
        _curl_counter="$tmp/github-retry-count"
        printf '0\n' > "$_curl_counter"
        curl() {
            local out=''; while (($#)); do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
            local n; n=$(cat "$_curl_counter"); n=$((n + 1)); printf '%s\n' "$n" > "$_curl_counter"
            printf '%s\n' "retry-${n}" > "$out"
            if (( n == 1 )); then printf '500'; else printf '200'; fi
        }
        export GITHUB_API_RETRY_DELAY=0
        [[ "$(github_api_get https://example.invalid/selftest-retry)" == 'retry-2' && "$(cat "$_curl_counter")" == 2 ]]
    ); then echo 'FAIL: GitHub API must retry transient 5xx once'; failures=$((failures + 1)); fi
    if ! (
        _curl_counter="$tmp/github-403-count"
        printf '0\n' > "$_curl_counter"
        curl() {
            local out=''; while (($#)); do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done
            local n; n=$(cat "$_curl_counter"); n=$((n + 1)); printf '%s\n' "$n" > "$_curl_counter"
            : > "$out"; printf '403'
        }
        unset GITHUB_TOKEN
        export GITHUB_API_RETRY_DELAY=0
        ! github_api_get https://example.invalid/selftest-403 >/dev/null 2>&1 && [[ "$(cat "$_curl_counter")" == 1 ]]
    ); then echo 'FAIL: GitHub API must not retry 403'; failures=$((failures + 1)); fi
    unset GITHUB_API_RETRY_DELAY
    local redacted_json redacted_headers
    redacted_json=$(printf '%s\n' '{"password":"secret","nested":{"token":"abc"},"uri":"vless://abc@host:443"}' | redact_secrets_stream)
    grep -q '\*\*\*REDACTED\*\*\*' <<< "$redacted_json" || { echo 'FAIL: JSON secret redaction'; failures=$((failures + 1)); }
    grep -q '\*\*\*CLIENT_LINK_REDACTED\*\*\*' <<< "$redacted_json" || { echo 'FAIL: client URI redaction'; failures=$((failures + 1)); }
    grep -qE 'secret|vless://abc' <<< "$redacted_json" && { echo 'FAIL: redaction leaked secret'; failures=$((failures + 1)); }
    redacted_json=$(printf '%s\n' '{"public_key":"pub-secret","short_id":"deadbeef","fingerprint":"cafebabe","normal":"visible"}' | redact_secrets_stream)
    [[ "$redacted_json" != *pub-secret* && "$redacted_json" != *deadbeef* && "$redacted_json" != *cafebabe* && "$redacted_json" == *visible* ]] || { echo 'FAIL: diagnostic redaction leaked public key/short id/fingerprint'; failures=$((failures + 1)); }
    redacted_headers=$(printf '%s\n' 'Authorization: Bearer top-secret-token' 'Cookie: sid=top-secret-cookie' 'normal: visible' | redact_secrets_stream)
    [[ "$redacted_headers" != *top-secret-token* && "$redacted_headers" != *top-secret-cookie* && "$redacted_headers" == *visible* ]] || { echo 'FAIL: diagnostic redaction leaked authorization/cookie header values'; failures=$((failures + 1)); }
    grep -q 'visible' <<< "$redacted_headers" || { echo 'FAIL: redaction removed non-secret diagnostic data'; failures=$((failures + 1)); }
    redacted_embedded=$(printf '%s\n' '{"message":"Authorization: Bearer embedded-json-token", "debug":"api_key=embedded-api-secret", "safe":"visible"}' | redact_secrets_stream)
    [[ "$redacted_embedded" != *embedded-json-token* && "$redacted_embedded" != *embedded-api-secret* && "$redacted_embedded" == *visible* ]] || { echo 'FAIL: JSON string-leaf secret redaction'; failures=$((failures + 1)); }

    printf 'new-content
' > "$tmp/atomic.src"
    printf 'old-content
' > "$tmp/atomic.dest"
    assert_ok install_file_atomically "$tmp/atomic.src" "$tmp/atomic.dest" 600
    mkdir -m 750 "$tmp/atomic-parent" || { echo 'FAIL: atomic parent setup'; failures=$((failures + 1)); }
    assert_ok install_file_atomically "$tmp/atomic.src" "$tmp/atomic-parent/kept-mode" 600
    [[ "$(stat -c %a "$tmp/atomic-parent" 2>/dev/null)" == 750 ]] || { echo 'FAIL: install_file_atomically changed an existing parent directory mode'; failures=$((failures + 1)); }
    ln -s "$tmp/atomic-parent" "$tmp/atomic-parent-link"
    assert_bad install_file_atomically "$tmp/atomic.src" "$tmp/atomic-parent-link/dest" 600
    mkdir -p "$tmp/nested-real"
    ln -s "$tmp/nested-real" "$tmp/nested-link"
    assert_bad install_file_atomically "$tmp/atomic.src" "$tmp/nested-link/deeper/dest" 600
    printf '%s\n' 'nested' | (write_file_atomically_from_stdin "$tmp/nested-link/deeper/state" 600 >/dev/null 2>&1) && { echo 'FAIL: atomic stdin writer traversed a nested parent symlink'; failures=$((failures + 1)); }
    mkdir -p "$tmp/sidecar-real/nested"
    ln -s "$tmp/sidecar-real" "$tmp/sidecar-link"
    assert_bad write_private_sidecar "$tmp/sidecar-link/nested/sidecar" 'secret'
    mkdir "$tmp/cert-key-dir"
    assert_bad generate_self_signed_cert_atomically "$tmp/cert-key-dir" "$tmp/cert.crt" localhost
    # Archive extractors must never remove a caller-owned pre-existing destination
    # when rejecting an extraction. This is a regression test for a destructive
    # cleanup bug found during the independent v70/v71 archive audit.
    python3 - "$tmp" <<'PY_SELFTEST_ARCHIVE_CREATE' >/dev/null 2>&1 || { echo 'FAIL: archive regression fixture creation'; failures=$((failures + 1)); }
import io, os, sys, tarfile, zipfile
base=sys.argv[1]
with zipfile.ZipFile(os.path.join(base, 'extract-regress.zip'), 'w') as z:
    z.writestr('target.txt', 'new-content')
with tarfile.open(os.path.join(base, 'extract-regress.tar'), 'w') as t:
    data=b'new-content'
    ti=tarfile.TarInfo('target.txt'); ti.size=len(data)
    t.addfile(ti, io.BytesIO(data))
PY_SELFTEST_ARCHIVE_CREATE
    printf '%s\n' 'preserve-me' > "$tmp/extract-preexisting"
    assert_bad extract_zip_member_safely "$tmp/extract-regress.zip" target.txt "$tmp/extract-preexisting"
    [[ -f "$tmp/extract-preexisting" && "$(cat "$tmp/extract-preexisting")" == 'preserve-me' ]] || { echo 'FAIL: ZIP rejection removed pre-existing destination'; failures=$((failures + 1)); }
    rm -f "$tmp/extract-new"
    assert_ok extract_zip_member_safely "$tmp/extract-regress.zip" target.txt "$tmp/extract-new"
    [[ "$(cat "$tmp/extract-new")" == 'new-content' ]] || { echo 'FAIL: ZIP successful extraction content'; failures=$((failures + 1)); }
    printf '%s\n' 'preserve-me' > "$tmp/extract-preexisting"
    assert_bad extract_tar_regular_basename_safely "$tmp/extract-regress.tar" target.txt "$tmp/extract-preexisting"
    [[ -f "$tmp/extract-preexisting" && "$(cat "$tmp/extract-preexisting")" == 'preserve-me' ]] || { echo 'FAIL: TAR rejection removed pre-existing destination'; failures=$((failures + 1)); }
    if command -v cmp >/dev/null 2>&1; then
        cmp -s "$tmp/atomic.src" "$tmp/atomic.dest" || { echo 'FAIL: atomic file install content'; failures=$((failures + 1)); }
    else
        [[ "$(cat "$tmp/atomic.src" 2>/dev/null)" == "$(cat "$tmp/atomic.dest" 2>/dev/null)" ]] || { echo 'FAIL: atomic file install content'; failures=$((failures + 1)); }
        selftest_note 'cmp missing; used cat equality for atomic install content check'
    fi
    rollback_binary_install "$tmp/atomic.dest" '' >/dev/null 2>&1 || true
    [[ ! -e "$tmp/atomic.dest" ]] || { echo 'FAIL: first-install rollback must remove destination'; failures=$((failures + 1)); }

    mkdir -p "$tmp/archive-good/root/etc/ddr" "$tmp/archive-good/meta"
    printf 'CORE=xray
' > "$tmp/archive-good/root/etc/ddr/.env"
    printf '%s
' 'A-Box backup manifest v3' > "$tmp/archive-good/meta/manifest.version"
    : > "$tmp/archive-good/meta/managed-paths.txt"
    : > "$tmp/archive-good/meta/services.state"
    printf '%s
' iptables > "$tmp/archive-good/meta/firewall.backend"
    : > "$tmp/archive-good/meta/iptables.snapshot"
    : > "$tmp/archive-good/meta/ip6tables.snapshot"
    : > "$tmp/archive-good/meta/cron.abox.txt"
    printf '%s\n' 'sentinel' > "$tmp/archive-good/meta/manifest-sentinel.txt"
    ln -s "$tmp/archive-good/meta/manifest-sentinel.txt" "$tmp/archive-good/meta/manifest.sha256.tmp"
    if create_backup_manifest "$tmp/archive-good" "$tmp/archive-good/meta/manifest.sha256" >/dev/null 2>&1; then
        echo 'FAIL: backup manifest generation accepted a predictable temp-file symlink'
        failures=$((failures + 1))
    fi
    [[ "$(cat "$tmp/archive-good/meta/manifest-sentinel.txt" 2>/dev/null)" == 'sentinel' ]] || { echo 'FAIL: backup manifest generation followed predictable temp-file symlink'; failures=$((failures + 1)); }
    rm -f "$tmp/archive-good/meta/manifest.sha256.tmp"
    if selftest_has python3; then
        assert_ok create_backup_manifest "$tmp/archive-good" "$tmp/archive-good/meta/manifest.sha256"
        selftest_pack_tar_gz "$tmp/archive-good" "$tmp/good.tar.gz" 1 || { echo 'FAIL: good backup fixture tar creation'; failures=$((failures + 1)); }
        assert_ok validate_backup_archive "$tmp/good.tar.gz"
    else
        selftest_note 'backup archive validation skipped (python3 missing)'
    fi
    if (( EUID == 0 )) && id nobody >/dev/null 2>&1 && getent group nogroup >/dev/null 2>&1; then
        old_hy_user="$ABOX_RUNTIME_HYSTERIA_USER"
        old_hy_group="$ABOX_RUNTIME_HYSTERIA_GROUP"
        ABOX_RUNTIME_HYSTERIA_USER=nobody
        ABOX_RUNTIME_HYSTERIA_GROUP=nogroup
        acme_runtime_fixture="$tmp/archive-acme-runtime"
        mkdir -p "$acme_runtime_fixture/root/etc/ddr" "$acme_runtime_fixture/root/etc/hysteria/acme" "$acme_runtime_fixture/meta"
        printf '%s\n' 'CORE=hysteria' > "$acme_runtime_fixture/root/etc/ddr/.env"
        printf '%s\n' 'ACME-CERT' > "$acme_runtime_fixture/root/etc/hysteria/acme/fullchain.pem"
        printf '%s\n' 'A-Box backup manifest v3' > "$acme_runtime_fixture/meta/manifest.version"
        : > "$acme_runtime_fixture/meta/managed-paths.txt"
        : > "$acme_runtime_fixture/meta/services.state"
        printf '%s\n' iptables > "$acme_runtime_fixture/meta/firewall.backend"
        : > "$acme_runtime_fixture/meta/iptables.snapshot"
        : > "$acme_runtime_fixture/meta/ip6tables.snapshot"
        : > "$acme_runtime_fixture/meta/cron.abox.txt"
        chown root:nogroup "$acme_runtime_fixture/root/etc/hysteria" "$acme_runtime_fixture/root/etc/hysteria/acme"
        chmod 750 "$acme_runtime_fixture/root/etc/hysteria"
        chmod 770 "$acme_runtime_fixture/root/etc/hysteria/acme"
        chown nobody:nogroup "$acme_runtime_fixture/root/etc/hysteria/acme/fullchain.pem"
        chmod 600 "$acme_runtime_fixture/root/etc/hysteria/acme/fullchain.pem"
        if selftest_has python3; then
            create_backup_manifest "$acme_runtime_fixture" "$acme_runtime_fixture/meta/manifest.sha256" || { echo 'FAIL: ACME runtime fixture manifest creation'; failures=$((failures + 1)); }
            selftest_pack_tar_gz "$acme_runtime_fixture" "$tmp/acme-runtime-good.tar.gz" || { echo 'FAIL: ACME runtime fixture tar creation'; failures=$((failures + 1)); }
            assert_ok validate_backup_archive "$tmp/acme-runtime-good.tar.gz" || { echo 'FAIL: legal Hysteria ACME runtime-owned backup rejected'; failures=$((failures + 1)); }
            python3 - "$tmp/acme-runtime-good.tar.gz" <<'PY_TAMPER_ACME' >/dev/null 2>&1
import os,sys,tarfile
arc=sys.argv[1]; out=arc+'.bad'
with tarfile.open(arc,'r:gz') as inp, tarfile.open(out,'w:gz') as outfp:
    for m in inp.getmembers():
        if m.name=='root/etc/hysteria/acme/fullchain.pem': m.uid=12345; m.gid=12345
        outfp.addfile(m, inp.extractfile(m) if m.isfile() else None)
os.replace(out,arc)
PY_TAMPER_ACME
            assert_bad validate_backup_archive "$tmp/acme-runtime-good.tar.gz"
        else
            selftest_note 'ACME runtime backup fixture skipped (python3 missing)'
        fi
        ABOX_RUNTIME_HYSTERIA_USER="$old_hy_user"
        ABOX_RUNTIME_HYSTERIA_GROUP="$old_hy_group"
        unset old_hy_user old_hy_group
    fi

    mkdir -p "$tmp/archive-bad/root/etc/ddr" "$tmp/archive-bad/meta"
    ln -s ../../../../etc/shadow "$tmp/archive-bad/root/etc/ddr/escape"
    if selftest_has python3 || tar --help 2>&1 | grep -Fq -- '--owner='; then
        selftest_pack_tar_gz "$tmp/archive-bad" "$tmp/bad.tar.gz" 1 || { echo 'FAIL: bad backup fixture tar creation'; failures=$((failures + 1)); }
        assert_bad validate_backup_archive "$tmp/bad.tar.gz"
    else
        selftest_note 'malicious backup archive rejection skipped (no python3/GNU tar)'
    fi

    cat > "$tmp/iptables.snapshot" <<'EOF_SELFTEST_IPT'
*filter
-A INPUT -p tcp --dport 443 -m comment --comment A-Box-443-tcp -j ACCEPT
-A INPUT -p tcp --dport 22 -m comment --comment Other -j ACCEPT
COMMIT
EOF_SELFTEST_IPT
    extract_abox_iptables_rules "$tmp/iptables.snapshot" all > "$tmp/iptables.abox"
    grep -q 'A-Box-443-tcp' "$tmp/iptables.abox" || { echo 'FAIL: A-Box firewall extraction'; failures=$((failures + 1)); }
    grep -q 'Other' "$tmp/iptables.abox" && { echo 'FAIL: foreign firewall rule extraction'; failures=$((failures + 1)); }

    if [[ $EUID -eq 0 ]]; then
        local saved_abox_env="$ABOX_ENV"
        ABOX_ENV="$tmp/state.env"
        printf '%s
' 'CORE=xray' 'MODE=ALL' 'HY2_MASQ_URL=https://www.example.com/' > "$ABOX_ENV"
        chmod 600 "$ABOX_ENV"
        unset CORE MODE HY2_MASQ_URL
        assert_ok load_abox_env "$ABOX_ENV"
        [[ "${CORE:-}|${MODE:-}|${HY2_MASQ_URL:-}" == 'xray|ALL|https://www.example.com/' ]] || { echo 'FAIL: strict state load'; failures=$((failures + 1)); }
        local selftest_sentinel="$tmp/state-file-command-sentinel"
        printf 'BAD=$(touch %q)\n' "$selftest_sentinel" >> "$ABOX_ENV"
        assert_bad load_abox_env "$ABOX_ENV"
        [[ ! -e "$selftest_sentinel" ]] || { echo 'FAIL: state file command execution'; failures=$((failures + 1)); }
        ABOX_ENV="$saved_abox_env"
    fi

    if (( $EUID == 0 )); then
        local env_tmp="$tmp/write-env"
        mkdir -m 700 "$env_tmp" || { echo 'FAIL: write_env temp directory'; failures=$((failures + 1)); }
        ABOX_ENV="$env_tmp/.env" ABOX_DIR="$env_tmp" LINK_IP=203.0.113.77 GLOBAL_PUBLIC_IP=198.51.100.8 CORE=xray MODE=ALL \
            write_env >/dev/null 2>&1 || { echo 'FAIL: write_env default CORE/MODE path'; failures=$((failures + 1)); }
        load_abox_env "$env_tmp/.env" >/dev/null 2>&1 || { echo 'FAIL: write_env round-trip state load'; failures=$((failures + 1)); }
        [[ "${CORE:-}|${MODE:-}|${LINK_IP:-}" == 'xray|ALL|203.0.113.77' ]] || { echo 'FAIL: write_env no-arg preservation/LINK_IP precedence'; failures=$((failures + 1)); }
        printf '%s\n' MANUAL_STOPPED > "$env_tmp/.desired"
        desired_file="$ABOX_DESIRED_STATE"; ABOX_DESIRED_STATE="$env_tmp/.desired" ABOX_ENV="$env_tmp/.env" ABOX_DIR="$env_tmp" CORE=xray MODE=ALL PUBLIC_KEY=new-public PBK=old-private-derived-public write_env >/dev/null 2>&1 || { echo 'FAIL: write_env state-preservation invocation'; failures=$((failures + 1)); }
        [[ "$(cat "$env_tmp/.desired" 2>/dev/null)" == MANUAL_STOPPED ]] || { echo 'FAIL: write_env must not change desired service state'; failures=$((failures + 1)); }
        ABOX_DESIRED_STATE="$desired_file"
        unset PBK; PUBLIC_KEY=loaded-public ABOX_ENV="$env_tmp/.env" ABOX_DIR="$env_tmp" write_env xray ALL >/dev/null 2>&1 || { echo 'FAIL: write_env persisted-public-key fallback'; failures=$((failures + 1)); }
        grep -Fq 'PUBLIC_KEY="loaded-public"' "$env_tmp/.env" || { echo 'FAIL: write_env used stale PBK instead of loaded PUBLIC_KEY'; failures=$((failures + 1)); }
        ln -s "$env_tmp/.env" "$env_tmp/.env-symlink-target"
        ( ABOX_ENV="$env_tmp/.env-symlink-target" ABOX_DIR="$env_tmp" CORE=xray MODE=ALL write_env >/dev/null 2>&1 ) && { echo 'FAIL: write_env must reject symlink state targets'; failures=$((failures + 1)); }
        [[ -L "$env_tmp/.env-symlink-target" ]] || { echo 'FAIL: write_env symlink rejection must not replace the symlink'; failures=$((failures + 1)); }
    fi

    if ! selftest_has jq; then
        selftest_note 'Xray/sing-box JSON builder tests skipped (jq missing)'
    else
    UUID=00000000-0000-4000-8000-000000000000
    VLESS_SNI=www.example.com
    VISION_SNI=www.microsoft.com
    XHTTP_SNI=www.microsoft.com
    VLESS_PORT=8443
    XHTTP_PORT=9443
    SS_PORT=2053
    HY2_BASE_PORT=443
    HY2_UP=100
    HY2_DOWN=1000
    HY2_PASS=testpass
    HY2_OBFS=testobfs
    HY2_MASQ_URL=https://www.example.com/
    PK=privatekey
    PBK=publickey
    SHORT_ID=abcd1234
    SS_PASS=testsspass
    ENABLE_KEEPALIVE=true

    mkdir -p "$tmp/xray" "$tmp/sing-box"
    printf '%s\n' 'sentinel' > "$tmp/xray/sentinel.txt"
    ln -s "$tmp/xray/sentinel.txt" "$tmp/xray/config.json.tmp.$$"
    build_xray_config ALL "$tmp/xray/config.json"
    [[ "$(cat "$tmp/xray/sentinel.txt" 2>/dev/null)" == 'sentinel' ]] || { echo 'FAIL: Xray config generation followed a predictable temp-file symlink'; failures=$((failures + 1)); }
    [[ -L "$tmp/xray/config.json.tmp.$$" ]] || { echo 'FAIL: Xray config generation touched the predictable temp symlink'; failures=$((failures + 1)); }
    rm -f "$tmp/xray/config.json.tmp.$$"
    jq empty "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: build_xray_config JSON'; failures=$((failures + 1)); }
    [[ "$(stat -c %a "$tmp/xray/config.json" 2>/dev/null)" == '600' ]] || { echo 'FAIL: Xray config permissions must be 0600'; failures=$((failures + 1)); }
    local saved_vision_sni="$VISION_SNI" saved_vless_sni="$VLESS_SNI"
    unset VISION_SNI VLESS_SNI
    build_xray_config VISION "$tmp/xray/default-sni.json"
    jq -e '.inbounds[] | select(.protocol=="vless" and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/default-sni.json" >/dev/null 2>&1 || { echo 'FAIL: default REALITY SNI must be www.microsoft.com'; failures=$((failures + 1)); }
    VISION_SNI="$saved_vision_sni" VLESS_SNI="$saved_vless_sni"
    jq -e '.inbounds[] | select(.protocol=="shadowsocks" and .port==2053 and .settings.network=="tcp,udp")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray SS-2022 2053 tcp,udp'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.protocol=="vless" and .port==8443 and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray Vision SNI split'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.protocol=="vless" and .port==9443 and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray XHTTP SNI split'; failures=$((failures + 1)); }
    jq -e 'all(.inbounds[] | select(.protocol=="vless"); .streamSettings.realitySettings.minClientVer == "1.8.2")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray REALITY minClientVer compatibility guard'; failures=$((failures + 1)); }
    assert_ok valid_github_download_url HyNetworks/hysteria https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64
    assert_bad valid_github_download_url HyNetworks/hysteria https://example.com/HyNetworks/hysteria/releases/download/app/v2.12.2/hysteria-linux-amd64
    printf '%s\n' 'sentinel' > "$tmp/sing-box/sentinel.txt"
    ln -s "$tmp/sing-box/sentinel.txt" "$tmp/sing-box/config.json.tmp.$$"
    build_singbox_config ALL "$tmp/sing-box/config.json"
    [[ "$(cat "$tmp/sing-box/sentinel.txt" 2>/dev/null)" == 'sentinel' ]] || { echo 'FAIL: Sing-box config generation followed a predictable temp-file symlink'; failures=$((failures + 1)); }
    [[ -L "$tmp/sing-box/config.json.tmp.$$" ]] || { echo 'FAIL: Sing-box config generation touched the predictable temp symlink'; failures=$((failures + 1)); }
    rm -f "$tmp/sing-box/config.json.tmp.$$"
    jq empty "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: build_singbox_config JSON'; failures=$((failures + 1)); }
    [[ "$(stat -c %a "$tmp/sing-box/config.json" 2>/dev/null)" == '600' ]] || { echo 'FAIL: Sing-box config permissions must be 0600'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.type=="shadowsocks" and .listen_port==2053 and (.network|not))' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box SS-2022 2053 default network'; failures=$((failures + 1)); }
    jq -e 'all(.inbounds[]; .type != "xhttp")' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box ALL must not include XHTTP'; failures=$((failures + 1)); }
    jq -e '(.route.rules[] | select(.action=="sniff")) and (.route.rules[] | select(.protocol=="bittorrent" and .action=="reject"))' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box sniff/reject route action'; failures=$((failures + 1)); }
    jq -e '.route.rules[0].action=="sniff" and .route.rules[0].network==["tcp"]' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box sniff must remain TCP-only to avoid HY2 UDP sniff coupling'; failures=$((failures + 1)); }
    jq -e 'all(.outbounds[]; .type != "block")' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box legacy block outbound remains'; failures=$((failures + 1)); }
    fi
    # Parent-directory traversal regression for the dedicated runtime user.
    if (( EUID == 0 )) && id nobody >/dev/null 2>&1 && getent group nogroup >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
        runtime_traverse=$(mktemp -d /tmp/A-Box-runtime-traverse.XXXXXX) || { echo 'FAIL: runtime traversal regression temp creation'; failures=$((failures + 1)); }
        chmod 755 "$runtime_traverse"
        mkdir -p "$runtime_traverse/sing-box" "$runtime_traverse/hysteria"
        printf '%s\n' runtime-readable > "$runtime_traverse/sing-box/config.json"
        printf '%s\n' runtime-readable > "$runtime_traverse/hysteria/config.yaml"
        chown root:root "$runtime_traverse/sing-box" "$runtime_traverse/hysteria"
        chmod 700 "$runtime_traverse/sing-box" "$runtime_traverse/hysteria"
        chown root:nogroup "$runtime_traverse/sing-box/config.json" "$runtime_traverse/hysteria/config.yaml"
        chmod 640 "$runtime_traverse/sing-box/config.json" "$runtime_traverse/hysteria/config.yaml"
        runuser -u nobody -- cat "$runtime_traverse/sing-box/config.json" >/dev/null 2>&1 && { echo 'FAIL: 0700 Sing-box parent directory was readable by runtime user'; failures=$((failures + 1)); }
        runuser -u nobody -- cat "$runtime_traverse/hysteria/config.yaml" >/dev/null 2>&1 && { echo 'FAIL: 0700 Hysteria parent directory was readable by runtime user'; failures=$((failures + 1)); }
        chown root:nogroup "$runtime_traverse/sing-box" "$runtime_traverse/hysteria"
        chmod 750 "$runtime_traverse/sing-box" "$runtime_traverse/hysteria"
        runuser -u nobody -- cat "$runtime_traverse/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: 0750 Sing-box parent directory blocked runtime user'; failures=$((failures + 1)); }
        runuser -u nobody -- cat "$runtime_traverse/hysteria/config.yaml" >/dev/null 2>&1 || { echo 'FAIL: 0750 Hysteria parent directory blocked runtime user'; failures=$((failures + 1)); }
    fi
    [[ -n "${runtime_traverse:-}" ]] && rm -rf -- "$runtime_traverse"
    unset runtime_traverse

    if (( EUID == 0 )); then
        local clash_dir="$tmp/abox"
        mkdir -m 700 "$clash_dir" || { echo 'FAIL: self-test A-Box temp directory'; failures=$((failures + 1)); }
        ensure_abox_dir_owned "$clash_dir" || { echo 'FAIL: self-test A-Box temp ownership setup'; failures=$((failures + 1)); }
        ABOX_DIR="$clash_dir" ABOX_ENV="$clash_dir/.env" CORE=xray MODE=ALL PUBLIC_KEY=publickey LINK_IP=203.0.113.10 UUID=11111111-1111-4111-8111-111111111111 VLESS_PORT=443 XHTTP_PORT=8443 SS_PORT=2053 HY2_BASE_PORT=443 VLESS_SNI=www.microsoft.com VISION_SNI=www.microsoft.com XHTTP_SNI=www.microsoft.com HY2_DOMAIN='' HY2_HOP=false HY2_CERT_SHA256_FP=abcdef HY2_CERT_PUBKEY_SHA256_B64=abcdef CLASH_YAML_PATH="$clash_dir/A-Box-clash.yaml" write_clash_yaml >/dev/null 2>&1 || { echo 'FAIL: Clash YAML generation'; failures=$((failures + 1)); }
        [[ "$(stat -c %a "$clash_dir/A-Box-clash.yaml" 2>/dev/null)" == '600' ]] || { echo 'FAIL: Clash YAML permissions must be 0600'; failures=$((failures + 1)); }
        ABOX_DIR="$clash_dir" ABOX_ENV="$clash_dir/.env" CORE=xray MODE=HY2 PUBLIC_KEY=publickey LINK_IP=203.0.113.10 HY2_DOMAIN=hy2.example.com HY2_HOP=true HY2_BASE_PORT=443 HY2_RANGE_START=20000 HY2_RANGE_END=25000 HY2_CLASH_PORTS=20000-25000 HY2_CERT_SHA256_FP=abcdef CLASH_YAML_PATH="$clash_dir/A-Box-clash-hop.yaml" write_clash_yaml >/dev/null 2>&1 || { echo 'FAIL: Clash Hysteria2 hop YAML generation'; failures=$((failures + 1)); }
        grep -q '^    port: 20000$' "$clash_dir/A-Box-clash-hop.yaml" || { echo 'FAIL: official Clash Hysteria2 hop YAML primary port must be first range port'; failures=$((failures + 1)); }
        grep -q '^    ports: 20000-25000$' "$clash_dir/A-Box-clash-hop.yaml" || { echo 'FAIL: Clash Hysteria2 hop YAML ports missing'; failures=$((failures + 1)); }
        grep -q '^proxy-groups:' "$clash_dir/A-Box-clash.yaml" || { echo 'FAIL: Clash YAML proxy-groups'; failures=$((failures + 1)); }
        grep -q '^dns:' "$clash_dir/A-Box-clash.yaml" || { echo 'FAIL: Clash YAML dns'; failures=$((failures + 1)); }
        grep -q '^  listen: 127.0.0.1:1053$' "$clash_dir/A-Box-clash.yaml" || { echo 'FAIL: Clash DNS listener must stay loopback-only'; failures=$((failures + 1)); }
        grep -q 'host: "www.microsoft.com"' "$clash_dir/A-Box-clash.yaml" || { echo 'FAIL: Clash XHTTP host'; failures=$((failures + 1)); }
        [[ "$(grep -Fc 'support-x25519mlkem768: false' "$clash_dir/A-Box-clash.yaml")" -eq 2 ]] || { echo 'FAIL: default Xray REALITY ML-KEM flags must remain disabled'; failures=$((failures + 1)); }
        ABOX_XRAY_VERSION=v26.9.8 ABOX_DIR="$clash_dir" ABOX_ENV="$clash_dir/.env" CORE=xray MODE=ALL PUBLIC_KEY=publickey LINK_IP=203.0.113.10 UUID=11111111-1111-4111-8111-111111111111 VLESS_PORT=443 XHTTP_PORT=8443 SS_PORT=2053 HY2_BASE_PORT=443 VLESS_SNI=www.microsoft.com VISION_SNI=www.microsoft.com XHTTP_SNI=www.microsoft.com HY2_DOMAIN='' HY2_HOP=false HY2_CERT_SHA256_FP=abcdef HY2_CERT_PUBKEY_SHA256_B64=abcdef CLASH_YAML_PATH="$clash_dir/A-Box-clash-mlkem.yaml" write_clash_yaml >/dev/null 2>&1 || { echo 'FAIL: new-Xray Clash YAML generation'; failures=$((failures + 1)); }
        [[ "$(grep -Fc 'support-x25519mlkem768: true' "$clash_dir/A-Box-clash-mlkem.yaml")" -eq 2 ]] || { echo 'FAIL: Xray >= ML-KEM threshold must enable REALITY ML-KEM flags'; failures=$((failures + 1)); }
        grep -Fq '较新的 REALITY ML-KEM ClientHello 门槛' "$0" || { echo 'FAIL: Xray ML-KEM compatibility warning missing'; failures=$((failures + 1)); }
        ABOX_DIR="$clash_dir" CORE=xray MODE=SS LINK_IP=203.0.113.10 SS_PORT=2053 SS_PASS='a"b\c' HY2_PASS='h"p' HY2_OBFS='o\b' CLASH_YAML_PATH="$clash_dir/A-Box-clash-escaped.yaml" write_clash_yaml >/dev/null 2>&1 || { echo 'FAIL: Clash YAML escaped secret generation'; failures=$((failures + 1)); }
        python3 - "$clash_dir/A-Box-clash-escaped.yaml" <<'PY_SELFTEST_YAML' >/dev/null 2>&1 || { echo 'FAIL: Clash YAML secret escaping'; failures=$((failures + 1)); }
import json, sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
values=[]
for line in text.splitlines():
    stripped=line.strip()
    if stripped.startswith('password:'):
        values.append(json.loads(stripped.split(':',1)[1].strip()))
if values != ['a"b\\c']:
    raise SystemExit(1)
PY_SELFTEST_YAML
    else
        echo 'SELF_TEST_NOTE: root-only Clash YAML ownership tests skipped for non-root execution'
    fi
    CORE=xray HY2_DOMAIN=hy2.example.com HY2_CERT_PUBKEY_SHA256_B64='' singbox_hy2_tls_json | grep -q '"server_name": "hy2.example.com"' || { echo 'FAIL: Sing-box HY2 ACME TLS sample'; failures=$((failures + 1)); }
    CORE=singbox HY2_DOMAIN=hy2.example.com HY2_CERT_PUBKEY_SHA256_B64=abcdef singbox_hy2_tls_json | grep -q 'certificate_public_key_sha256' || { echo 'FAIL: Sing-box HY2 self-signed TLS sample'; failures=$((failures + 1)); }
    local _saved_release="${release:-}" _saved_sb_arch="${SB_ARCH:-}" _regex
    SB_ARCH=amd64
    release=alpine
    _regex=$(singbox_asset_regex)
    [[ "$_regex" == '^sing-box-.*-linux-amd64-musl\.tar\.gz$' ]] || { echo 'FAIL: sing-box Alpine musl asset selector'; failures=$((failures + 1)); }
    release=debian
    _regex=$(singbox_asset_regex)
    [[ "$_regex" == '^sing-box-.*-linux-amd64-glibc\.tar\.gz$' ]] || { echo 'FAIL: sing-box glibc asset selector'; failures=$((failures + 1)); }
    _fake_sb_release='{"assets":[{"name":"sing-box-1.14.2-linux-amd64.tar.gz","browser_download_url":"https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
    SB_ARCH=amd64 release=debian
    assert_bad singbox_asset_json_from_release "$_fake_sb_release"
    _fake_sb_release='{"assets":[{"name":"sing-box-1.14.2-linux-amd64-musl.tar.gz","browser_download_url":"https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64-musl.tar.gz","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
    release=debian
    assert_bad singbox_asset_json_from_release "$_fake_sb_release"
    _fake_sb_release='{"assets":[{"name":"sing-box-1.14.2-linux-amd64-glibc.tar.gz","browser_download_url":"https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64-glibc.tar.gz","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
    assert_ok singbox_asset_json_from_release "$_fake_sb_release"
    unset _fake_sb_release
    assert_ok valid_github_download_url XTLS/Xray-core 'https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip' v26.9.30
    assert_bad valid_github_download_url XTLS/Xray-core 'https://github.com/XTLS/Xray-core/releases/download/V26.9.30/Xray-linux-64.zip' v26.9.30
    assert_bad valid_github_download_url XTLS/Xray-core 'https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip' v26.9.30
    assert_bad valid_github_download_url XTLS/Xray-core 'https://github.com/Evil/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip' v26.9.30
    assert_bad valid_url_https 'https://example.com:443:444/'
    assert_bad valid_url_https 'https://example.com::443/'
    [[ "$(openrc_cron_service_name debian)" == 'cron' ]] || { echo 'FAIL: Debian OpenRC cron service name must be cron'; failures=$((failures + 1)); }
    [[ "$(openrc_cron_service_name ubuntu)" == 'cron' ]] || { echo 'FAIL: Ubuntu OpenRC cron service name must be cron'; failures=$((failures + 1)); }
    # Alpine default is BusyBox crond unless cronie/dcron units are present.
    if [[ -x /etc/init.d/cronie ]]; then
        [[ "$(openrc_cron_service_name alpine)" == 'cronie' ]] || { echo 'FAIL: Alpine OpenRC cron service name must prefer cronie when installed'; failures=$((failures + 1)); }
    elif [[ -x /etc/init.d/dcron ]]; then
        [[ "$(openrc_cron_service_name alpine)" == 'dcron' ]] || { echo 'FAIL: Alpine OpenRC cron service name must prefer dcron when installed'; failures=$((failures + 1)); }
    else
        [[ "$(openrc_cron_service_name alpine)" == 'crond' ]] || { echo 'FAIL: Alpine OpenRC cron service name must be crond by default'; failures=$((failures + 1)); }
    fi
    grep -Fq "apk-add cronie by" "$0" || grep -Fq 'Do not apk-add cronie by default' "$0" || { echo 'FAIL: Alpine deps must not force-install cronie by default'; failures=$((failures + 1)); }
    grep -Fq 'curl-minimal' "$0" || { echo 'FAIL: RHEL/Rocky curl-minimal conflict handling missing'; failures=$((failures + 1)); }
    release="$_saved_release"
    SB_ARCH="$_saved_sb_arch"

    grep -q 'traffic_error() {' "$0" || { echo 'FAIL: safe traffic error logger missing'; failures=$((failures + 1)); }
    grep -Fq '非交互部署检测到 wg/warp/tun 默认出口' "$0" || { echo 'FAIL: WARP default-route deployment gate missing'; failures=$((failures + 1)); }
    grep -q 'A-Box-traffic.log' "$0" || { echo 'FAIL: traffic log path missing'; failures=$((failures + 1)); }
    ! grep -Eq 'deps=\([^\n]*\bvnstat\b' "$0" || { echo 'FAIL: vnStat must not be a baseline hard dependency'; failures=$((failures + 1)); }
    ! grep -Eq '^    need_cmd_pkg vnstat ' "$0" || { echo 'FAIL: vnStat must not be an unconditional command dependency'; failures=$((failures + 1)); }
    ! grep -Eq '^    need_cmd_pkg (qrencode|fail2ban-client) ' "$0" || { echo 'FAIL: optional qrencode/Fail2Ban must not be hard dependencies'; failures=$((failures + 1)); }
    grep -Fq 'if ! remove_abox_swap; then' "$0" || { echo 'FAIL: full uninstall must retain ownership marker when swap cleanup fails'; failures=$((failures + 1)); }
    grep -q '^rollback_new_swap_activation_only() {' "$0" || { echo 'FAIL: early Swap rollback must have fstab-independent activation-only helper'; failures=$((failures + 1)); }
    grep -Fq 'fstab 备份失败；已回滚新建 Swap，且未修改 /etc/fstab。' "$0" || { echo 'FAIL: early Swap backup failure must not invoke fstab-modifying rollback'; failures=$((failures + 1)); }
    grep -Fq 'rm -rf -- "$ABOX_DIR" || die' "$0" || { echo 'FAIL: full uninstall must verify A-Box directory removal'; failures=$((failures + 1)); }
    ! grep -Eq 'mapfile -t rules < <\(\"\$cmd\" -w -S INPUT|done < <\(\"\$cmd\" -w -S INPUT' "$0" || { echo 'FAIL: firewall reorder must propagate iptables -S failure'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_DEPLOY_TX_BACKUP_DIR="$uninstall_tx_dir"' "$0" || { echo 'FAIL: full uninstall rollback must use an external transaction backup'; failures=$((failures + 1)); }
    grep -Fq 'backup_auth_verify_with_key_file "$selected" "${selected}.hmac" "$key_file"' "$0" || { echo 'FAIL: rollback external transaction key verification missing'; failures=$((failures + 1)); }
    if (( EUID == 0 )); then
        local post_abox_sig='' post_abox_exists=0
        if [[ -e /etc/ddr || -L /etc/ddr ]]; then post_abox_exists=1; fi
        post_abox_sig=$(selftest_abox_signature) || { echo 'FAIL: live /etc/ddr post-test signature unavailable'; failures=$((failures + 1)); }
        if (( post_abox_exists != real_abox_exists )); then
            echo 'FAIL: --self-test changed /etc/ddr existence state'; failures=$((failures + 1))
        elif [[ "$post_abox_sig" != "$real_abox_sig" ]]; then
            echo 'FAIL: --self-test changed live /etc/ddr directory state'; failures=$((failures + 1))
        fi
    fi
    source_body=$(sed -n '/^run_self_tests() {$/,/^main() {$/!p' "$0") || { echo 'FAIL: static source extraction for regression guards'; failures=$((failures + 1)); }
    ! grep -Fq "asn_cache='/tmp'" <<< "$source_body" || { echo 'FAIL: ASN cache must never fall back to shared /tmp'; failures=$((failures + 1)); }
    ! grep -Eq 'mktemp -d /tmp/A-Box-asn-cache\.XXXXXX.*\|\|[[:space:]]*asn_cache=.*/tmp' <<< "$source_body" || { echo 'FAIL: ASN cache mktemp failure must not fall back to shared /tmp'; failures=$((failures + 1)); }
    ! grep -Fq 'used=$(month_bytes "$iface" "${TRAFFIC_LIMIT_MODE:-total}") || exit 0' <<< "$source_body" || { echo 'FAIL: traffic measurement failure must not fail open'; failures=$((failures + 1)); }
    grep -q '^traffic_fail_closed() {' <<< "$source_body" || { echo 'FAIL: traffic monitor fail-closed enforcement helper missing'; failures=$((failures + 1)); }
    traffic_body=$(sed -n '/write_file_atomically_from_stdin "$ABOX_DIR\/traffic_monitor.sh" 700 <<'"'"'EOF_TRAFFIC'"'"'/,/^EOF_TRAFFIC$/p' "$0") || traffic_body=''
    ! grep -Fq 'load_state || exit 0' <<< "$traffic_body" || { echo 'FAIL: traffic monitor must not silently exit on persisted state load failure'; failures=$((failures + 1)); }
    grep -Fq 'state_load_failed=0' <<< "$traffic_body" || { echo 'FAIL: traffic monitor persisted-state failure handling missing'; failures=$((failures + 1)); }
    grep -Fq 'stop_all_owned_services() {' <<< "$traffic_body" || { echo 'FAIL: traffic monitor fail-closed stop path missing'; failures=$((failures + 1)); }
    grep -Fq 'persisted traffic state is unreadable or invalid' <<< "$traffic_body" || { echo 'FAIL: traffic monitor invalid persisted state must fail closed'; failures=$((failures + 1)); }
    grep -q '^reorder_ss_whitelist_rules_one() {' <<< "$source_body" || { echo 'FAIL: firewall reorder transaction missing'; failures=$((failures + 1)); }
    grep -Fq 'exec {lock_fd}>>"$lock_file"' <<< "$source_body" || { echo 'FAIL: firewall reorder transaction lock missing'; failures=$((failures + 1)); }
    grep -Fq '[[ "$lock_fd" =~ ^[0-9]+$ ]]' <<< "$source_body" || { echo 'FAIL: firewall_unlock must guard empty lock_fd'; failures=$((failures + 1)); }
    grep -Fq 'flock -s -n 8' <<< "$source_body" || { echo 'FAIL: status/preflight must use shared non-blocking flock'; failures=$((failures + 1)); }
    grep -Fq 'umask 077; mktemp /tmp/A-Box-remote.XXXXXX.sh' <<< "$source_body" || { echo 'FAIL: remote script temp must use umask 077'; failures=$((failures + 1)); }
    grep -Fq 'unset ABOX_DIE_HOOK' <<< "$source_body" || { echo 'FAIL: enter_runtime must ignore ambient ABOX_DIE_HOOK'; failures=$((failures + 1)); }

    grep -Fq 'firewall_rollback() {' <<< "$source_body" || { echo 'FAIL: firewall reorder rollback helper missing'; failures=$((failures + 1)); }
    grep -Fq 'recovery snapshot preserved at $recovery_snapshot' <<< "$source_body" || { echo 'FAIL: firewall rollback conflict must preserve recovery snapshot'; failures=$((failures + 1)); }
    grep -Fq '"${cmd}" -w -D INPUT "${rollback_argv_arr[@]:2}"' <<< "$source_body" || { echo 'FAIL: firewall rollback must remove exact owned rules'; failures=$((failures + 1)); }
    grep -Fq 'current_foreign_lines' <<< "$source_body" || { echo 'FAIL: firewall rollback must track foreign INPUT rules'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe "$ABOX_DIR" || return 1' <<< "$source_body" || { echo 'FAIL: rollback restore must validate A-Box parent chain'; failures=$((failures + 1)); }
    grep -Fq 'install -d -m 700 "$ABOX_DIR" || return 1' <<< "$source_body" || { echo 'FAIL: rollback restore must recreate a missing A-Box directory'; failures=$((failures + 1)); }
    grep -Fq 'previous_state=$(get_desired_state)' "$0" || { echo 'FAIL: manual service transitions must snapshot desired state'; failures=$((failures + 1)); }
    grep -Fq 'local pre_state=' "$0" || { echo 'FAIL: manual service transactions must capture pre-state'; failures=$((failures + 1)); }
    grep -Fq 'restore_managed_service_state "$changed_pre" "$changed_expected"' "$0" || { echo 'FAIL: manual service rollback must use expected-state conflict guards'; failures=$((failures + 1)); }
    grep -Fq 'current_state_before=$(managed_service_state_value' "$0" || { echo 'FAIL: service rollback must recheck state before mutation'; failures=$((failures + 1)); }
    grep -Fq 'start_abox_service_soft "$srv"' "$0" || { echo 'FAIL: manual start must use non-fatal service start path'; failures=$((failures + 1)); }
    grep -Fq 'local preflight_rc=$(( fail > 0 ? 1 : 0 ))' "$0" || { echo 'FAIL: preflight must preserve result before cleanup'; failures=$((failures + 1)); }
    grep -Fq 'rm -rf -- "$report_dir" || return 1' "$0" || { echo 'FAIL: preflight report directory cleanup missing'; failures=$((failures + 1)); }
    grep -Fq 'local redacted_json redacted_headers' "$0" || { echo 'FAIL: redaction self-test variables are not separated'; failures=$((failures + 1)); }
    grep -Fq 'target_ref="$(effective_xray_version)"' "$0" || { echo 'FAIL: Xray core-only upgrade must use centralized compatibility version'; failures=$((failures + 1)); }
    grep -q '^core_post_upgrade_health_gate() {' "$0" || { echo 'FAIL: core post-upgrade health gate missing'; failures=$((failures + 1)); }
    grep -Fq 'core_post_upgrade_health_gate xray' "$0" || { echo 'FAIL: Xray post-upgrade health gate not enforced'; failures=$((failures + 1)); }
    grep -Fq 'core_post_upgrade_health_gate singbox' "$0" || { echo 'FAIL: sing-box post-upgrade health gate not enforced'; failures=$((failures + 1)); }
    _traffic_menu=$(sed -n '/^traffic_management_menu() {$/,/^manage_ss_whitelist()/p' "$0") || _traffic_menu=''
    _setup_line=$(grep -n -m1 'setup_traffic_monitor' <<< "$_traffic_menu" | cut -d: -f1 || true)
    _update_line=$(grep -n -m1 'update_traffic_state_atomically "$limit_gb" "$mode_choice"' <<< "$_traffic_menu" | cut -d: -f1 || true)
    [[ "$_setup_line" =~ ^[0-9]+$ && "$_update_line" =~ ^[0-9]+$ && "$_setup_line" -lt "$_update_line" ]] || { echo 'FAIL: quota monitor must be provisioned before quota-state commit'; failures=$((failures + 1)); }
    grep -q '^capture_vnstat_runtime_state() {' "$0" || { echo 'FAIL: traffic transaction vnStat snapshot helper missing'; failures=$((failures + 1)); }
    grep -q '^traffic_restore_cron_block() {' "$0" || { echo 'FAIL: traffic transaction must restore only the A-Box TRAFFIC cron block'; failures=$((failures + 1)); }
    grep -q '^traffic_quota_transaction_rollback() {' "$0" || { echo 'FAIL: traffic quota rollback helper missing'; failures=$((failures + 1)); }
    grep -Fq 'expected_vnstat' "$0" || { echo 'FAIL: traffic rollback must not reuse cron expected-state variable for vnStat'; failures=$((failures + 1)); }
    grep -Fq 'ABOX_DIE_HOOK=traffic_quota_menu_die_rollback' "$0" || { echo 'FAIL: traffic setup/commit failure must trigger transaction rollback'; failures=$((failures + 1)); }
    grep -q '^firewall_snapshot_is_abox_managed() {' <<< "$source_body" || { echo 'FAIL: firewall persistence ownership gate missing'; failures=$((failures + 1)); }
    grep -Fq 'auxiliary_content_is_abox_managed "$fw_file" /etc/ddr/firewall_restore.sh || return 1' <<< "$source_body" || { echo 'FAIL: firewall persistence must preflight ownership before service deletion'; failures=$((failures + 1)); }
    grep -Fq '(( uid != 0 && gid != 0 )) || return 1' <<< "$source_body" || { echo 'FAIL: runtime service identity must never resolve to root UID/GID'; failures=$((failures + 1)); }
    grep -Fq 'prepare_abox_runtime_permissions "$srv" || return 1' <<< "$source_body" || { echo 'FAIL: restore must reapply runtime service permissions before start'; failures=$((failures + 1)); }
    grep -q '^install_optional_package() {' "$0" || { echo 'FAIL: optional package installer missing'; failures=$((failures + 1)); }
    grep -q '^ensure_abox_log_file() {' "$0" || { echo 'FAIL: safe A-Box log file gate missing'; failures=$((failures + 1)); }
    grep -q 'firewalld_zone_for_abox' "$0" || { echo 'FAIL: firewalld zone-aware routing missing'; failures=$((failures + 1)); }
    grep -Fq 'read -r -p "$(tr_msg main_command)" choice || exit 0' "$0" || { echo 'FAIL: main menu must use EOF-safe non-readline input'; failures=$((failures + 1)); }
    grep -q '^prompt_hy2_bandwidth_mbps_input() {' "$0" || { echo 'FAIL: HY2 bandwidth prompt helper missing'; failures=$((failures + 1)); }
    grep -Fq 'valid_traffic_limit_gb "$limit_gb"' "$0" || { echo 'FAIL: traffic-limit prompt must use the persisted traffic-limit validator'; failures=$((failures + 1)); }
    grep -Fq 'read -r -p "$prompt" input || return 1' "$0" || { echo 'FAIL: looped input prompts must return failure on EOF'; failures=$((failures + 1)); }
    grep -Fq 'VLESS_PORT=$(prompt_port_input "$L_VISION" "$DEF_V_PORT") || die' "$0" || { echo 'FAIL: prompt command substitutions must propagate EOF failure'; failures=$((failures + 1)); }
    grep -Fq 'exec < /dev/tty || die' "$0" || { echo 'FAIL: need_interactive_tty must fail fast when opening /dev/tty fails'; failures=$((failures + 1)); }
    if grep -Eq '(^|[[:space:];])read[[:space:]]+-r[[:space:]]+-e(p)?([[:space:]]|$)' "$0" || grep -Eq '(^|[[:space:];])read[[:space:]]+-r[[:space:]]+-e[[:space:]]+-p([[:space:]]|$)' "$0"; then
        echo 'FAIL: interactive reads must not use readline mode because Ctrl-D/EOF can stall on PTY inputs'
        failures=$((failures + 1))
    fi
    if remove_core_family_force __A_BOX_INVALID_CORE_FAMILY__; then
        echo 'FAIL: core path enumeration failure must abort forced cleanup'
        failures=$((failures + 1))
    fi
    grep -Fq 'local -a paths=()' "$0" || { echo 'FAIL: forced core cleanup must preflight all paths before deletion'; failures=$((failures + 1)); }
    grep -Fq 'core_paths=$(core_family_paths "$srv") || return 1' "$0" || { echo 'FAIL: ownership recording must not swallow core path enumeration errors'; failures=$((failures + 1)); }
    grep -q '^backup_root_contains_service() {' "$0" || { echo 'FAIL: backup service path checker missing'; failures=$((failures + 1)); }
    grep -Fq 'core_paths=$(core_family_paths "$srv") || { rm -rf "$work"; die "Core path enumeration failed during backup: $srv"; }' "$0" || { echo 'FAIL: backup core path enumeration must fail closed'; failures=$((failures + 1)); }
    grep -Fq 'def path_is_mountpoint(path):' "$0" || { echo 'FAIL: core ownership recording must use mountinfo-aware mount detection'; failures=$((failures + 1)); }
    grep -Fq 'fail closed instead of using the weaker ismount()' "$0" || { echo 'FAIL: destructive manifest removal must not fall back to weak mount detection'; failures=$((failures + 1)); }
    if sed -n "/^python3 - \"\$srv\" \"\$ABOX_CORE_OWNERSHIP\" <<'PY_CORE_REMOVE'$/,/^PY_CORE_REMOVE$/p" "$0" | grep -Fq 'return os.path.ismount(path)'; then
        echo 'FAIL: destructive manifest removal still contains fail-open mountinfo fallback'
        failures=$((failures + 1))
    fi
    path_tree_has_mountpoint /proc || { echo 'FAIL: mountpoint guard does not detect /proc'; failures=$((failures + 1)); }
    ! path_tree_has_mountpoint "$tmp" || { echo 'FAIL: mountpoint guard falsely reports self-test temp directory'; failures=$((failures + 1)); }
    if command -v python3 >/dev/null 2>&1; then
        _guard_fail_bin="$tmp/.A-Box-failing-python"
        _guard_fail_fixture="$tmp/.guard-target"
        printf '%s\n' '#!/usr/bin/env bash' 'exit 42' > "$_guard_fail_bin" || { echo 'FAIL: mount helper failure-test fixture creation'; failures=$((failures + 1)); }
        chmod 700 "$_guard_fail_bin" || { echo 'FAIL: mount helper failure-test fixture chmod'; failures=$((failures + 1)); }
        ln -sf -- "$_guard_fail_bin" "$tmp/python3" || { echo 'FAIL: mount helper failure-test python shim'; failures=$((failures + 1)); }
        if ! ( PATH="${tmp}:$PATH"; path_tree_has_mountpoint "$tmp" ); then
            echo 'FAIL: path_tree_has_mountpoint must fail closed on helper errors'; failures=$((failures + 1))
        fi
        if ! ( PATH="${tmp}:$PATH"; path_is_mountpoint "$tmp" ); then
            echo 'FAIL: path_is_mountpoint must fail closed on helper errors'; failures=$((failures + 1))
        fi
        mkdir -p "$_guard_fail_fixture" || { echo 'FAIL: mount helper target fixture creation'; failures=$((failures + 1)); }
        if ! ( PATH="${tmp}:$PATH"; core_family_paths() { printf '%s\n' "$_guard_fail_fixture"; }; ! remove_core_family_force xray ); then
            echo 'FAIL: remove_core_family_force did not fail closed on mount-helper error'; failures=$((failures + 1))
        elif [[ ! -d "$_guard_fail_fixture" ]]; then
            echo 'FAIL: remove_core_family_force deleted target after mount-helper error'; failures=$((failures + 1))
        fi
        rm -f -- "$tmp/python3" "$_guard_fail_bin"
        rm -rf -- "$_guard_fail_fixture"
    fi
    grep -q 'os.path.ismount(path)' "$0" || { echo 'FAIL: core ownership record/remove mountpoint guard missing'; failures=$((failures + 1)); }
    grep -q 'Restore cleanup encountered a mountpoint' "$0" || { echo 'FAIL: restore cleanup mountpoint guard missing'; failures=$((failures + 1)); }
    grep -Fq 'path_tree_has_mountpoint "$path" && return 1' "$0" || { echo 'FAIL: source-absent restore must guard the entire target tree for nested mounts'; failures=$((failures + 1)); }
    grep -Fq 'remove_owned_runtime_helper "$ABOX_DIR/geo_update.sh"' "$0" || { echo 'FAIL: Geo helper deletion must be ownership-gated'; failures=$((failures + 1)); }
    grep -q 'validate_backup_core_init_compatibility' "$0" || { echo 'FAIL: restore must preflight backup/current init compatibility before destructive changes'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/fail2ban/filter.d/A-Box.conf' "$0" || { echo 'FAIL: Fail2Ban filter parent chain must be checked before mkdir/write'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/fail2ban/jail.d/A-Box.local' "$0" || { echo 'FAIL: Fail2Ban jail parent chain must be checked before mkdir/write'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/sysctl.d/99-A-Box-tune.conf || return 1' "$0" || { echo 'FAIL: tune restore must check sysctl parent chain before restore'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/security/limits.d/A-Box.conf || return 1' "$0" || { echo 'FAIL: tune restore must check limits parent chain before restore'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/conf.d/hysteria || die' "$0" || { echo 'FAIL: Hysteria OpenRC conf.d parent chain guard missing'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/conf.d/xray || die' "$0" || { echo 'FAIL: Xray OpenRC conf.d parent chain guard missing'; failures=$((failures + 1)); }
    grep -Fq 'path_parent_chain_safe /etc/conf.d/sing-box || die' "$0" || { echo 'FAIL: sing-box OpenRC conf.d parent chain guard missing'; failures=$((failures + 1)); }
    grep -Fq 'aux_paths=$(managed_auxiliary_paths) ||' "$0" || { echo 'FAIL: backup must not swallow managed auxiliary path enumeration errors through process substitution'; failures=$((failures + 1)); }
    grep -Fq 'lock_dir_created=0' "$0" || { echo 'FAIL: fallback runtime lock must track newly created directory for rollback'; failures=$((failures + 1)); }
    if command -v flock >/dev/null 2>&1; then
        (
            _saved_lock_fallback="$LOCK_FALLBACK_DIR"
            LOCK_FALLBACK_DIR="$tmp/.A-Box-fallback-lock-regression"
            chown() { return 42; }
            ! acquire_fallback_runtime_lock
            [[ ! -e "$LOCK_FALLBACK_DIR" && ! -L "$LOCK_FALLBACK_DIR" ]]
        ) || { echo 'FAIL: fallback runtime lock failure must clean newly created lock directory'; failures=$((failures + 1)); }
    fi
    grep -Fq 'Backup init system is incompatible with the current VPS; restore was aborted before destructive changes.' "$0" || { echo 'FAIL: manual restore must abort cross-init backups before destructive changes'; failures=$((failures + 1)); }
    grep -Fq 'service_active_state_value() {' "$0" || { echo 'FAIL: service active-state helper missing'; failures=$((failures + 1)); }
    _svc_test_bin="$tmp/service-state-bin"
    mkdir -m 700 "$_svc_test_bin" || { echo 'FAIL: service-state test directory'; failures=$((failures + 1)); }
    cat > "$_svc_test_bin/systemctl" <<'EOF_SVC_TEST_SYSTEMCTL' || { echo 'FAIL: service-state systemctl fixture'; failures=$((failures + 1)); }
#!/usr/bin/env bash
case "$1 $2 $3 $4" in
  'show -p ActiveState --value')
    [[ "${ABOX_SELFTEST_SERVICE_QUERY_FAIL:-0}" == 1 ]] && exit 42
    printf '%s\n' active
    ;;
  'show -p UnitFileState --value')
    [[ "${ABOX_SELFTEST_SERVICE_QUERY_FAIL:-0}" == 1 ]] && exit 42
    printf '%s\n' enabled
    ;;
  *) exit 0 ;;
esac
EOF_SVC_TEST_SYSTEMCTL
    chmod 700 "$_svc_test_bin/systemctl" || { echo 'FAIL: service-state systemctl fixture chmod'; failures=$((failures + 1)); }
    local _svc_test_saved_path="$PATH" _svc_test_saved_init='' _svc_test_saved_init_set=0
    if [[ ${INIT_SYS+x} ]]; then _svc_test_saved_init="$INIT_SYS"; _svc_test_saved_init_set=1; fi
    PATH="${_svc_test_bin}:$PATH"
    systemd_available() { return 0; }
    INIT_SYS=systemd
    _svc_guard_pre="$tmp/service-guard-pre.state"
    _svc_guard_expected="$tmp/service-guard-expected.state"
    _svc_guard_log="$tmp/service-guard.log"
    printf '%s\n' 'xray|0|0' > "$_svc_guard_pre"
    printf '%s\n' 'xray|1|1' > "$_svc_guard_expected"
    chmod 600 "$_svc_guard_pre" "$_svc_guard_expected"
    if (( EUID == 0 )); then
        chown root:root "$_svc_guard_pre" "$_svc_guard_expected" || { echo 'FAIL: root service-state fixture ownership setup'; failures=$((failures + 1)); }
        _svc_guard_saved_state_fn=$(declare -f managed_service_state_value)
        _svc_guard_saved_owns_fn=$(declare -f abox_owns_service)
        managed_service_state_value() { printf '%s\n' 'xray|1|0'; }
        abox_owns_service() { return 0; }
        : > "$_svc_guard_log"
        if restore_managed_service_state "$_svc_guard_pre" "$_svc_guard_expected" >/dev/null 2>&1; then
            echo 'FAIL: service rollback must reject externally changed state'
            failures=$((failures + 1))
        fi
        eval "$_svc_guard_saved_state_fn"
        eval "$_svc_guard_saved_owns_fn"
    else
        echo 'SELF_TEST_NOTE: root-only service rollback fixture skipped for non-root execution' >&2
    fi
    export ABOX_SELFTEST_SERVICE_QUERY_FAIL=1
    if service_active_state_value xray >/dev/null 2>&1; then
        echo 'FAIL: systemd active-state query error was accepted'
        failures=$((failures + 1))
    fi
    export ABOX_SELFTEST_SERVICE_QUERY_FAIL=0
    [[ "$(service_active_state_value xray 2>/dev/null)" == 1 ]] || { echo 'FAIL: systemd active-state success decode'; failures=$((failures + 1)); }
    PATH="$_svc_test_saved_path"
    if (( _svc_test_saved_init_set )); then INIT_SYS="$_svc_test_saved_init"; else unset INIT_SYS; fi

    cat > "$_svc_test_bin/rc-service" <<'EOF_SVC_TEST_RCSERVICE' || { echo 'FAIL: service-state rc-service fixture'; failures=$((failures + 1)); }
#!/usr/bin/env bash
if [[ "$2" == status ]]; then exit "${ABOX_SELFTEST_RC_STATUS:-3}"; fi
exit 0
EOF_SVC_TEST_RCSERVICE
    cat > "$_svc_test_bin/rc-update" <<'EOF_SVC_TEST_RCUPDATE' || { echo 'FAIL: service-state rc-update fixture'; failures=$((failures + 1)); }
#!/usr/bin/env bash
if [[ "$1" == 'show' && "$2" == 'default' ]]; then
    [[ "${ABOX_SELFTEST_RC_UPDATE_FAIL:-0}" == 1 ]] && exit 42
    printf '%s\n' 'xray | default'
    exit 0
fi
exit 0
EOF_SVC_TEST_RCUPDATE
    chmod 700 "$_svc_test_bin/rc-service" "$_svc_test_bin/rc-update" || { echo 'FAIL: OpenRC service-state fixture chmod'; failures=$((failures + 1)); }
    PATH="${_svc_test_bin}:$PATH"
    INIT_SYS=openrc
    export ABOX_SELFTEST_RC_STATUS=42 ABOX_SELFTEST_RC_UPDATE_FAIL=0
    if service_active_state_value xray >/dev/null 2>&1; then
        echo 'FAIL: OpenRC active-state query error was accepted'
        failures=$((failures + 1))
    fi
    export ABOX_SELFTEST_RC_STATUS=0 ABOX_SELFTEST_RC_UPDATE_FAIL=1
    if service_enabled_state_value xray >/dev/null 2>&1; then
        echo 'FAIL: OpenRC enabled-state query error was accepted'
        failures=$((failures + 1))
    fi
    export ABOX_SELFTEST_RC_STATUS=3 ABOX_SELFTEST_RC_UPDATE_FAIL=0
    [[ "$(service_active_state_value xray 2>/dev/null)" == 0 ]] || { echo 'FAIL: OpenRC stopped-state decode'; failures=$((failures + 1)); }
    PATH="$_svc_test_saved_path"
    if (( _svc_test_saved_init_set )); then INIT_SYS="$_svc_test_saved_init"; else unset INIT_SYS; fi
    unset ABOX_SELFTEST_SERVICE_QUERY_FAIL ABOX_SELFTEST_RC_STATUS ABOX_SELFTEST_RC_UPDATE_FAIL

    _canon_env_tmp="$tmp/.canonical-port-env"
    printf '%s\n' 'CORE=xray' 'MODE=SS' 'SS_PORT="02053"' > "$_canon_env_tmp" || { echo 'FAIL: canonical-port env fixture creation'; failures=$((failures + 1)); }
    chmod 600 "$_canon_env_tmp" || { echo 'FAIL: canonical-port env fixture chmod'; failures=$((failures + 1)); }
    if (( EUID == 0 )); then chown root:root "$_canon_env_tmp" || { echo 'FAIL: canonical-port env fixture ownership'; failures=$((failures + 1)); }; fi
    if load_abox_env "$_canon_env_tmp" >/dev/null 2>&1; then
        echo 'FAIL: persisted .env accepted non-canonical port with leading zero'
        failures=$((failures + 1))
    fi
    declare -F load_optional_abox_env_or_die >/dev/null 2>&1 || { echo 'FAIL: safe optional env loader missing'; failures=$((failures + 1)); }
    if ! ( unset ABOX_DIE_HOOK; ABOX_ENV="$tmp/.env-not-present"; load_optional_abox_env_or_die ); then
        echo 'FAIL: optional env loader rejected a genuinely absent first-install state'
        failures=$((failures + 1))
    fi
    _invalid_env="$tmp/.env-invalid-existing"
    printf '%s\n' 'UNKNOWN_KEY=unexpected' > "$_invalid_env" || { echo 'FAIL: invalid env fixture creation'; failures=$((failures + 1)); }
    chmod 600 "$_invalid_env" || { echo 'FAIL: invalid env fixture chmod'; failures=$((failures + 1)); }
    if ( unset ABOX_DIE_HOOK; ABOX_ENV="$_invalid_env"; load_optional_abox_env_or_die ) >/dev/null 2>&1; then
        echo 'FAIL: optional env loader accepted an existing invalid state file'
        failures=$((failures + 1))
    fi
    if (( failures > 0 )); then
        echo "SELF_TEST_FAILED=$failures"
        selftest_cleanup
        return 1
    fi
    _legacy_preflight_pattern='managed_services_active && pf_warn ' ; _legacy_preflight_pattern="${_legacy_preflight_pattern}existing A-Box managed service is active" ; _legacy_preflight_pattern="${_legacy_preflight_pattern}' || pf_pass"
    if grep -Fq -- "$_legacy_preflight_pattern" "$0"; then
        echo 'FAIL: preflight still collapses unknown managed-service state into inactive'
        failures=$((failures + 1))
    fi

    # Read-only status reporting must distinguish an inactive service from an
    # unqueryable service; query failure is an unknown state, not "stopped".
    _status_owns_orig=$(declare -f abox_owns_service)
    _status_state_orig=$(declare -f service_active_state_value)
    abox_owns_service() { return 0; }
    service_active_state_value() { printf '0\n'; return 0; }
    [[ "$(service_report_state xray)" == 'inactive' ]] || { echo 'FAIL: inactive service status'; failures=$((failures + 1)); }
    service_active_state_value() { return 1; }
    [[ "$(service_report_state xray)" == 'unknown' ]] || { echo 'FAIL: unknown service status'; failures=$((failures + 1)); }
    eval "$_status_owns_orig"
    eval "$_status_state_orig"

    # A mixed active/unknown stack must not collapse to a plain "stopped" UI.
    _status_owns_orig=$(declare -f abox_owns_service)
    _status_state_orig=$(declare -f service_active_state_value)
    abox_owns_service() { [[ "$1" == xray || "$1" == hysteria ]]; }
    service_active_state_value() {
        case "$1" in
            xray) printf '1\n' ;;
            hysteria) return 1 ;;
            *) printf '0\n' ;;
        esac
    }
    [[ "$(build_status_str)" == *'Xray-Core'* && "$(build_status_str)" == *'State Unknown'* ]] || { echo 'FAIL: mixed active/unknown status UI'; failures=$((failures + 1)); }
    eval "$_status_owns_orig"
    eval "$_status_state_orig"

    # A managed-service state query failure must not be treated as "no services"
    # during deployment replacement confirmation.  Unknown state must reach the
    # confirmation path rather than silently auto-approving a destructive change.
    managed_services_active__orig=$(declare -f managed_services_active)
    read__orig=$(declare -f read 2>/dev/null || true)
    die__orig=$(declare -f die)
    managed_services_active() { return 2; }
    read() { answer='N'; return 0; }
    die() { return 99; }
    clear_abox_env_vars
    CORE=''; MODE=''
    if confirm_deployment_replacement xray VISION >/dev/null 2>&1; then
        echo 'FAIL: managed-service state query failure was silently auto-approved'
        failures=$((failures + 1))
    fi
    eval "$managed_services_active__orig"
    eval "$die__orig"
    if [[ -n "$read__orig" ]]; then
        eval "$read__orig"
    else
        unset -f read 2>/dev/null || true
    fi
    if (( failures > 0 )); then
        echo "SELF_TEST_FAILED=$failures"
        selftest_cleanup
        return 1
    fi
    echo 'SELF_TEST_OK'
    selftest_cleanup
    return 0
}

main() {
    case "${1:-}" in
        --version|-V) printf 'A-Box %s (%s)\n' "$ABOX_BUILD" "$ABOX_BUILD_EPOCH"; exit 0 ;;
        --export-backup-key) shift; prepare_noninteractive_file_operation; export_backup_recovery_key "${1:-}"; exit 0 ;;
        --convert-legacy-backup) shift; prepare_noninteractive_file_operation; convert_legacy_backup_archive "${1:-}" "${2:-$(dirname "${1:-.}")}"; exit 0 ;;
        --help|-h) show_cli_help; exit 0 ;;
        --self-test) run_self_tests; exit $? ;;
        --status) show_status_report; exit 0 ;;
        --stop) manual_stop_managed_stack; exit $? ;;
        --start) manual_start_managed_stack; exit $? ;;
        --preflight|--dry-run) detect_lang; preflight_check --no-pause; exit $? ;;
        --lang)
            ABOX_LANG_OVERRIDE="${2:-zh}"
            enter_runtime "$@"
            ABOX_LANG=$(normalize_lang "$ABOX_LANG_OVERRIDE")
            save_lang
            main_loop "$@"
            ;;
        --lang=*)
            ABOX_LANG_OVERRIDE="${1#--lang=}"
            enter_runtime "$@"
            ABOX_LANG=$(normalize_lang "$ABOX_LANG_OVERRIDE")
            save_lang
            main_loop "$@"
            ;;
        '') enter_runtime "$@"; main_loop "$@" ;;
        *) show_cli_help >&2; exit 2 ;;
    esac
}

main_loop() {
    detect_lang
    init_system_environment
    setup_shortcut
    # Safely migrate active, exactly marked v7 installations into the new
    # per-file ownership model. Inactive or ambiguous services are not adopted.
    local _srv _pid _exe
    for _srv in xray sing-box hysteria; do
        abox_owns_service "$_srv" && is_service_running "$_srv" || continue
        _pid=$(managed_service_pid "$_srv" 2>/dev/null || true); _pid=${_pid%%$'\n'*}
        case "$_srv" in xray) _exe=/usr/local/bin/xray ;; sing-box) _exe=/usr/local/bin/sing-box ;; hysteria) _exe=/usr/local/bin/hysteria ;; esac
        if pid_exe_matches "$_pid" "$_exe"; then
            record_core_family_ownership "$_srv" || msg "${YELLOW}[!] Ownership migration for active ${_srv} could not be verified; destructive maintenance will remain blocked until registration succeeds.${NC}" >&2
        fi
    done
    GLOBAL_PUBLIC_IP=$(get_public_ip || true)
    while true; do
        local STATUS_STR='' CUR_MODE='' choice
        STATUS_STR=$(build_status_str)
        load_abox_env "$ABOX_ENV" 2>/dev/null && CUR_MODE="[${CORE}-${MODE}]" || CUR_MODE=''
        clear
        msg "${BLUE}======================================================================${NC}"
        msg "${BOLD}${YELLOW}==================================A-Box===============================${NC}"
        msg "${BLUE}======================================================================${NC}"
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            msg "Gateway: ${YELLOW}$GLOBAL_PUBLIC_IP${NC} | Core: $STATUS_STR $CUR_MODE | Mode: ${YELLOW}$(read_fast_mode_label)${NC}"
            msg "${GREEN}21.${NC} ${BOLD}One-click Vision REALITY${NC} (minimal prompts)  ${YELLOW}[r]${NC}=same"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${YELLOW}[ Xray-core Deployment ]${NC}              ${YELLOW}[ Sing-box Deployment ]${NC}"
            msg "${GREEN}1.${NC} VLESS-Vision-Reality               ${GREEN}6.${NC} VLESS-Vision-Reality"
            msg "${GREEN}2.${NC} VLESS-XHTTP-Reality                ${GREEN}7.${NC} Shadowsocks-2022"
            msg "${GREEN}3.${NC} Shadowsocks-2022                   ${GREEN}8.${NC} VLESS + SS-2022"
            msg "${GREEN}4.${NC} Hysteria 2 (Official)        ${GREEN}9.${NC} Hysteria 2 (Sing-box)"
            msg "${GREEN}5.${NC} All-in-one (Xray+Hy2)             ${GREEN}10.${NC} All-in-one (Sing-box)"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${GREEN}11.${NC} Toolbox"
            msg "${GREEN}12.${NC} VPS One-click Optimization"
            msg "${GREEN}13.${NC} Display All Node Parameters"
            msg "${GREEN}14.${NC} Manual"
            msg "${GREEN}15.${NC} OTA, Geo & Core Upgrade"
            msg "${GREEN}16.${NC} Clean Uninstall"
            msg "${GREEN}17.${NC} Delete Nodes & Reinitialize Environment"
            msg "${GREEN}18.${NC} Monthly Traffic Limit"
            msg "${GREEN}19.${NC} SS-2022 Whitelist Manager"
            msg "${GREEN}20.${NC} Language"
            msg "${GREEN}21.${NC} One-click Vision REALITY"
            msg "${GREEN} 0.${NC} Exit"
            msg "${BLUE}======================================================================${NC}"
            _menu_lock_released=0
            if [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == flock ]] && [[ -e /proc/$$/fd/9 ]]; then
                flock -u 9 2>/dev/null && _menu_lock_released=1 || true
            fi
            read -r -p "$(tr_msg main_command)" choice || exit 0
            if [[ "${_menu_lock_released:-0}" == 1 ]]; then
                flock -n 9 || die '重新获取 A-Box 运行锁失败；可能另有实例已启动。'
            fi
            unset _menu_lock_released
        else
            msg "网关/Gateway: ${YELLOW}$GLOBAL_PUBLIC_IP${NC} | 核心/Core: $STATUS_STR $CUR_MODE | 模式: ${YELLOW}$(read_fast_mode_label)${NC}"
            msg "${GREEN}21.${NC} ${BOLD}一键 Reality${NC}（Vision 默认 SNI，最少提问）  ${YELLOW}[r]${NC}=同"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${YELLOW}[ Xray-core 部署 ]${NC}                    ${YELLOW}[ Sing-box 部署 ]${NC}"
            msg "${GREEN}1.${NC} VLESS-Vision-Reality               ${GREEN}6.${NC} VLESS-Vision-Reality"
            msg "${GREEN}2.${NC} VLESS-XHTTP-Reality                ${GREEN}7.${NC} Shadowsocks-2022"
            msg "${GREEN}3.${NC} Shadowsocks-2022                   ${GREEN}8.${NC} VLESS + SS-2022"
            msg "${GREEN}4.${NC} Hysteria 2 (官方)          ${GREEN}9.${NC} Hysteria 2 (Sing-box)"
            msg "${GREEN}5.${NC} 全协议四合一 (Xray+Hy2)           ${GREEN}10.${NC} 全协议三合一 (Sing-box)"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${GREEN}11.${NC} 综合工具箱"
            msg "${GREEN}12.${NC} VPS 一键优化"
            msg "${GREEN}13.${NC} 全部节点参数显示"
            msg "${GREEN}14.${NC} 脚本说明书"
            msg "${GREEN}15.${NC} 脚本 OTA、Xray Geo 与核心无损升级"
            msg "${GREEN}16.${NC} 一键全部清空卸载"
            msg "${GREEN}17.${NC} 删除全部节点与环境初始化"
            msg "${GREEN}18.${NC} 每月流量管控限制"
            msg "${GREEN}19.${NC} SS-2022 白名单 IP 管理"
            msg "${GREEN}20.${NC} 语言设置 / Language"
            msg "${GREEN}21.${NC} 一键 Reality"
            msg "${GREEN} 0.${NC} 退出脚本"
            msg "${BLUE}======================================================================${NC}"
            _menu_lock_released=0
            if [[ "${ABOX_RUNTIME_LOCK_MODE:-}" == flock ]] && [[ -e /proc/$$/fd/9 ]]; then
                flock -u 9 2>/dev/null && _menu_lock_released=1 || true
            fi
            read -r -p "$(tr_msg main_command)" choice || exit 0
            if [[ "${_menu_lock_released:-0}" == 1 ]]; then
                flock -n 9 || die '重新获取 A-Box 运行锁失败；可能另有实例已启动。'
            fi
            unset _menu_lock_released
        fi
        case "$choice" in
            1) deploy_xray VISION ;;
            2) deploy_xray XHTTP ;;
            3) deploy_xray SS ;;
            4) deploy_official_hy2 NORMAL ;;
            5) deploy_xray ALL ;;
            6) deploy_singbox VISION ;;
            7) deploy_singbox SS ;;
            8) deploy_singbox VLESS_SS ;;
            9) deploy_singbox HY2 ;;
            10) deploy_singbox ALL ;;
            11) vps_benchmark_menu ;;
            12) tune_vps ;;
            13) view_config manual ;;
            14) show_usage ;;
            15) ota_and_geo_menu ;;
            16) clean_uninstall_menu ;;
            17) check_virgin_state ;;
            18) traffic_management_menu ;;
            19) manage_ss_whitelist ;;
            20) language_menu ;;
            21|r|R) one_click_reality_deploy ;;
            0) clear; exit 0 ;;
            *) sleep 1 ;;
        esac
    done
}

main "$@"
