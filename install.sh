#!/usr/bin/env bash
# ==============================A-Box===============================
# SNI profile: built-in deduplicated maximum REALITY target candidate library; no legacy remote SNI script dependency.
# Hardened build: stricter GitHub digest trust, guarded shortcut persistence, Fail2Ban validation, and Sing-box HY2 ACME semantics.
set -o pipefail
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    printf 'A-Box requires Bash 4.3 or newer. Current: %s\n' "$BASH_VERSION" >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
export LANG=${LANG:-en_US.UTF-8}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

DEPS_MARKER='/etc/ddr/.deps.v20260725'
SCRIPT_URL='https://raw.githubusercontent.com/alariclin/a-box/main/install.sh'
ABOX_DIR='/etc/ddr'
ABOX_ENV='/etc/ddr/.env'
ABOX_FW_STATE='/etc/ddr/.firewall-native.rules'
ABOX_BACKUP_KEY='/etc/ddr/.backup-hmac.key'
ABOX_CORE_OWNERSHIP='/etc/ddr/.managed-core-files.tsv'
LOCK_FILE='/run/A-Box.lock'
LANG_FILE='/etc/ddr/.lang'
PUBLIC_IP_CACHE='/etc/ddr/.public_ip.cache'
PUBLIC_IP_CACHE_TTL=600
BACKUP_RETENTION_COUNT=${BACKUP_RETENTION_COUNT:-10}
LOCK_FALLBACK_DIR='/run/A-Box.lock.d'
ABOX_LANG='zh'
ABOX_BUILD='2026-07-29-final-v8-rc4'
ABOX_BUILD_EPOCH=2026072902
ABOX_DESIRED_STATE='/etc/ddr/.desired_state'
ABOX_TRAFFIC_BLOCK_STATE='/etc/ddr/.traffic-block-state'
PUBLIC_IP_CONNECT_TIMEOUT=${PUBLIC_IP_CONNECT_TIMEOUT:-3}
PUBLIC_IP_MAX_TIME=${PUBLIC_IP_MAX_TIME:-6}
ABOX_DEPLOY_TX_ACTIVE=0
ABOX_DEPLOY_TX_TARGETS=''
ABOX_DEPLOY_TX_REASON=''
ABOX_DEPLOY_TX_BACKUP=''
ABOX_DEPLOY_TX_TMP=''
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

msg() { echo -e "$*"; }
die() {
    echo -e "${RED}[!] $*${NC}" >&2
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
        grep -Eq '^(zh|en)[[:space:]]*$' "$dir/.lang"
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
        zh:lang_saved) echo '语言已保存。' ;;
        en:lang_saved) echo 'Language saved.' ;;
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

tprintf() { local key="$1"; shift; printf "$(tr_msg "$key")" "$@"; }

proto_label() {
    printf '%b[%s]%b' "${BOLD}${CYAN}" "$1" "${NC}"
}

pause_return() { read -r -ep "$(tr_msg press_return)" _ || true; }

is_yes() { [[ "${1:-}" =~ ^[Yy]$ ]]; }

confirm_yes_no() {
    local prompt="$1" answer
    read -r -ep "$prompt" answer
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
    echo 'Language / 语言'
    echo '1. 中文'
    echo '2. English'
    read -r -ep 'Select [1-2, default 1]: ' c || true
    case "$c" in 2) ABOX_LANG='en' ;; *) ABOX_LANG='zh' ;; esac
    save_lang
}

language_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}$(tr_msg lang_title)${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}1. 中文${NC}"
    msg "${YELLOW}2. English${NC}"
    msg "${GREEN}0. 返回 / Back${NC}"
    local c
    read -r -ep 'Select [0-2]: ' c
    case "$c" in
        1) ABOX_LANG='zh'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        2) ABOX_LANG='en'; save_lang; msg "${GREEN}$(tr_msg lang_saved)${NC}"; pause_return ;;
        *) return 0 ;;
    esac
}

need_interactive_tty() {
    if [[ ! -t 0 ]]; then
        if [[ -r /dev/tty ]]; then
            exec < /dev/tty
        else
            die '当前环境无可交互 TTY，无法运行交互式菜单。'
        fi
    fi
}
valid_port() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
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

port_spec_for_firewalld() {
    local spec
    spec=$(normalize_port_spec "${1:-}") || return 1
    printf '%s\n' "${spec/:/-}"
}

valid_positive_int() {
    [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

valid_domain() {
    local domain="${1:-}"
    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_sni() { valid_domain "$1"; }

valid_single_line_secret() {
    local value="${1:-}" max_len="${2:-512}"
    [[ -n "$value" && ${#value} -le $max_len && "$value" != *$'\n'* && "$value" != *$'\r'* ]]
}

is_apple_like_sni() {
    local sni="${1,,}"
    [[ "$sni" == 'apple.com' || "$sni" == *.apple.com || "$sni" == 'icloud.com' || "$sni" == *.icloud.com ]]
}

default_sni_for_port() {
    local port="${1:-443}"
    # Avoid Apple/iCloud as a default target. Xray-core emits warnings for apple/icloud
    # targets and for non-443 listeners; use toolbox SNI radar results for production.
    printf 'www.microsoft.com'
}

prompt_reality_sni() {
    local label="$1" port="$2" default_sni input answer prompt warned
    default_sni=$(default_sni_for_port "$port")
    while true; do
        printf -v prompt "$(tr_msg reality_sni_prompt)" "$label" "$port" "$default_sni"
        read -r -ep "$prompt" input
        input=${input:-$default_sni}
        if ! valid_sni "$input"; then
            echo -e "${RED}[!] $(printf "$(tr_msg bad_sni)" "$input")${NC}" >&2
            continue
        fi
        warned=0
        if [[ "$port" != '443' ]]; then
            echo -e "${YELLOW}[!] REALITY/XHTTP 使用非 443 监听端口 (${port})。Xray 上游将其作为独立风险条件提示；请确认该端口符合你的网络环境。${NC}" >&2
            warned=1
        fi
        if is_apple_like_sni "$input"; then
            echo -e "${YELLOW}[!] Apple/iCloud 类 target (${input}) 被 Xray 上游作为独立风险条件提示；建议改用经过实测的非 Apple/iCloud 目标。${NC}" >&2
            warned=1
        fi
        if [[ "$warned" == 1 ]]; then
            printf -v prompt "$(tr_msg continue_or_reset)" "$label"
            read -r -ep "$prompt" answer
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
        port="${host##*:}"
        host="${host%%:*}"
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
        read -r -ep "$prompt" input
        input="${input:-$default_url}"
        normalized="$(normalize_https_url_input "$input" 2>/dev/null || true)"
        if [[ -n "$normalized" ]] && valid_url_https "$normalized"; then
            printf '%s\n' "$normalized"
            return 0
        fi
        echo -e "${RED}[!] HY2 伪装 URL 非法 / Invalid HY2 masquerade URL: ${input}${NC}" >&2
        echo -e "${YELLOW}    正确示例 / Example: https://www.microsoft.com/${NC}" >&2
    done
}

prompt_port_input() {
    local label="$1" default_port="$2" input prompt
    while true; do
        printf -v prompt "$(tr_msg port_prompt)" "$label" "$default_port"
        read -r -ep "$prompt" input
        input="${input:-$default_port}"
        if valid_port "$input"; then
            printf '%s\n' "$input"
            return 0
        fi
        echo -e "${RED}[!] $(printf "$(tr_msg bad_port)" "$input")${NC}" >&2
    done
}

prompt_ss_port_input() {
    local label="$1" default_port="$2" input prompt
    while true; do
        printf -v prompt "$(tr_msg ss_port_prompt)" "$label" "$default_port"
        read -r -ep "$prompt" input
        input="${input:-$default_port}"
        if valid_port "$input"; then
            printf '%s\n' "$input"
            return 0
        fi
        echo -e "${RED}[!] $(printf "$(tr_msg bad_port)" "$input")${NC}" >&2
    done
}

prompt_positive_int_input() {
    local prompt="$1" default_value="$2" input
    while true; do
        read -r -ep "$prompt" input
        input="${input:-$default_value}"
        if valid_positive_int "$input"; then
            printf '%s\n' "$input"
            return 0
        fi
        echo -e "${RED}[!] 请输入正整数 / Enter a positive integer: ${input}${NC}" >&2
    done
}
valid_ipv4_cidr() {
    local input="${1:-}" addr mask n
    addr="${input%/*}"
    mask=''
    [[ "$input" == */* ]] && mask="${input#*/}"
    if [[ -n "$mask" ]]; then
        [[ "$mask" =~ ^[0-9]+$ ]] || return 1
        (( 10#$mask >= 0 && 10#$mask <= 32 )) || return 1
    fi
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    local -a octets
    read -r -a octets <<< "$addr"
    for n in "${octets[@]}"; do
        [[ "$n" =~ ^[0-9]+$ ]] || return 1
        (( 10#$n >= 0 && 10#$n <= 255 )) || return 1
    done
}

valid_ipv6_cidr() {
    local input="${1:-}" addr mask
    addr="${input%/*}"
    mask=''
    [[ "$input" == */* ]] && mask="${input#*/}"
    if [[ -n "$mask" ]]; then
        [[ "$mask" =~ ^[0-9]+$ ]] || return 1
        (( 10#$mask >= 0 && 10#$mask <= 128 )) || return 1
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

shell_quote() { printf '%q' "${1:-}"; }
json_escape() { jq -Rn --arg v "${1:-}" '$v'; }

clear_abox_env_vars() {
    unset CORE MODE UUID VLESS_SNI VISION_SNI XHTTP_SNI VLESS_PORT XHTTP_PORT HY2_BASE_PORT HY2_DOMAIN HY2_UP HY2_DOWN HY2_MASQ_URL
    unset SS_PORT PUBLIC_KEY SHORT_ID HY2_PASS HY2_OBFS SS_PASS LINK_IP HY2_CERT_SHA256_FP HY2_CERT_PUBKEY_SHA256_B64
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
        [[ -z "$value" ]] || valid_port "$value" || return 1
    done
    if [[ -n "${HY2_RANGE_START:-}${HY2_RANGE_END:-}" ]]; then
        valid_port "${HY2_RANGE_START:-}" && valid_port "${HY2_RANGE_END:-}" || return 1
        (( 10#$HY2_RANGE_START <= 10#$HY2_RANGE_END )) || return 1
    fi
    for p in VLESS_SNI VISION_SNI XHTTP_SNI HY2_DOMAIN; do
        value=${!p:-}
        [[ -z "$value" ]] || valid_domain "$value" || return 1
    done
    [[ -z "${HY2_MASQ_URL:-}" ]] || valid_url_https "$HY2_MASQ_URL" || return 1
    [[ -z "${UUID:-}" || "${UUID:-}" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || return 1
    [[ -z "${SHORT_ID:-}" || "${SHORT_ID:-}" =~ ^[0-9A-Fa-f]{2,32}$ ]] || return 1
    [[ -z "${SHORT_ID:-}" || $(( ${#SHORT_ID} % 2 )) -eq 0 ]] || return 1
    [[ -z "${HY2_CERT_SHA256_FP:-}" || "${HY2_CERT_SHA256_FP:-}" =~ ^[0-9A-Fa-f]{64}$ ]] || return 1
    [[ -z "${LINK_IP:-}" || "${LINK_IP:-}" == N/A ]] || valid_ipv4_cidr "$LINK_IP" || valid_ipv6_cidr "$LINK_IP" || return 1
    [[ -z "${HY2_HOP:-}" || "${HY2_HOP:-}" =~ ^(true|false)$ ]] || return 1
    [[ -z "${HY2_HOP_IMPL:-}" || "${HY2_HOP_IMPL:-}" =~ ^(none|manual|official)$ ]] || return 1
    [[ -z "${HY2_ACME_TYPE:-}" || "${HY2_ACME_TYPE:-}" =~ ^(http|dns)$ ]] || return 1
    [[ -z "${ENABLE_KEEPALIVE:-}" || "${ENABLE_KEEPALIVE:-}" =~ ^(true|false)$ ]] || return 1
    [[ -z "${INGRESS_IF:-}" ]] || valid_interface_name "$INGRESS_IF" || return 1
    if [[ -n "${TRAFFIC_LIMIT_GB:-}" ]]; then
        valid_positive_int "$TRAFFIC_LIMIT_GB" || return 1
        [[ "${TRAFFIC_LIMIT_MODE:-total}" =~ ^(total|rx|tx)$ ]] || return 1
    else
        [[ -z "${TRAFFIC_LIMIT_MODE:-}" || "${TRAFFIC_LIMIT_MODE:-}" =~ ^(total|rx|tx)$ ]] || return 1
    fi
    for p in HY2_URI_PORTS HY2_CLASH_PORTS HY2_SB_PORTS; do
        value=${!p:-}
        [[ -z "$value" || "$value" =~ ^[0-9,:-]+$ ]] || return 1
    done
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
    if ! python3 /dev/fd/3 "$file" > "$parsed" 3<<'PY_ABOX_ENV'; then
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
        if raw_value.startswith("$'"):
            raise SystemExit(f"unsupported ANSI-C quoted state value at line {number}")
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

rand_alnum() {
    local len="$1" out='' chunk attempt
    valid_positive_int "$len" && (( 10#$len <= 4096 )) || die '随机字符串长度非法。'
    for ((attempt=0; attempt<16 && ${#out}<10#$len; attempt++)); do
        chunk=$(openssl rand -base64 64 2>/dev/null | tr -dc 'a-zA-Z0-9') || chunk=''
        [[ -n "$chunk" ]] && out+="$chunk"
    done
    (( ${#out} >= 10#$len )) || die '加密随机源读取失败。'
    printf '%s\n' "${out:0:10#$len}"
}

generate_robust_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
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
    fi
}

pin_sha256_colon() {
    openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2
}

get_public_ip_fresh() {
    local ip api
    for api in 'https://api.ipify.org' 'https://ifconfig.me/ip' 'https://icanhazip.com'; do
        ip=$(curl -fsS4 --connect-timeout "$PUBLIC_IP_CONNECT_TIMEOUT" -m "$PUBLIC_IP_MAX_TIME" "$api" 2>/dev/null | tr -d '[:space:]')
        if valid_ipv4_cidr "$ip"; then
            printf '%s\n' "$ip"
            return 0
        fi
    done
    ip=$(curl -fsS6 --connect-timeout "$PUBLIC_IP_CONNECT_TIMEOUT" -m "$PUBLIC_IP_MAX_TIME" 'https://api64.ipify.org' 2>/dev/null | tr -d '[:space:]')
    if valid_ipv6_cidr "$ip"; then
        printf '%s\n' "$ip"
        return 0
    fi
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
    if ! valid_ipv4_cidr "$ip" && ! valid_ipv6_cidr "$ip"; then
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
        if valid_ipv4_cidr "$stale" || valid_ipv6_cidr "$stale"; then
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
    [[ -z "$iface" ]] && iface=$(ip -o route show to default 2>/dev/null | awk '{print $5; exit}')
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
        msg "${YELLOW}解析结果:${NC}\n$resolved"
        read -r -ep '仍然继续？[Y/N]: ' continue_domain
        is_yes "$continue_domain" || die '已取消部署。'
    fi
}

init_system_environment() {
    release=''
    local -a install_cmd=()
    deps_initialized=0
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in
            debian) release='debian'; install_cmd=(apt-get -y install) ;;
            ubuntu) release='ubuntu'; install_cmd=(apt-get -y install) ;;
            alpine) release='alpine'; install_cmd=(apk add) ;;
            centos|rhel|rocky|almalinux) release='centos'; install_cmd=(yum -y install) ;;
        esac
    fi
    if [[ -z "$release" ]]; then
        if [[ -f /etc/redhat-release ]] || grep -qiE 'centos|red hat|rocky|almalinux' /proc/version 2>/dev/null; then
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
                deps=(wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates iproute2 coreutils cron logrotate uuid-runtime fail2ban python3)
                ;;
            centos)
                deps=(wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates coreutils cronie logrotate util-linux bind-utils iproute fail2ban epel-release python3)
                ;;
            alpine)
                deps=(bash wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates iproute2 coreutils cronie logrotate util-linux bind-tools procps fail2ban iptables-openrc python3)
                ;;
        esac
        "${install_cmd[@]}" "${deps[@]}" >/dev/null 2>&1 || die '基础依赖包安装失败。'
        ensure_abox_dir_owned "$ABOX_DIR"
        install -m 600 /dev/null "$DEPS_MARKER" || die '依赖标记写入失败。'
        deps_initialized=1
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
        reconcile_systemd_unit vnstat
        if [[ "$release" == 'centos' ]]; then
            if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
                msg "${YELLOW}[*] firewalld is active; A-Box will add required ports natively and will not disable it.${NC}"
            else
                msg "${YELLOW}[*] firewalld is inactive; A-Box will persist only its own rules through A-Box-firewall.service.${NC}"
            fi
        fi
    else
        reconcile_openrc_service crond
        reconcile_openrc_service vnstatd
    fi

    IPT=$(command -v iptables || echo '/sbin/iptables')
    IPT6=$(command -v ip6tables || echo '/sbin/ip6tables')
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
    need_cmd_pkg wget wget wget wget
    need_cmd_pkg jq jq jq jq
    need_cmd_pkg openssl openssl openssl openssl
    need_cmd_pkg bc bc bc bc
    need_cmd_pkg unzip unzip unzip unzip
    need_cmd_pkg tar tar tar tar
    need_cmd_pkg iptables iptables iptables iptables
    need_cmd_pkg ss iproute2 iproute iproute2
    need_cmd_pkg lsof lsof lsof lsof
    need_cmd_pkg qrencode qrencode qrencode qrencode
    need_cmd_pkg vnstat vnstat vnstat vnstat
    need_cmd_pkg getent libc-bin glibc-common libc-utils
    need_cmd_pkg flock util-linux util-linux util-linux
    need_cmd_pkg fail2ban-client fail2ban fail2ban fail2ban
    need_cmd_pkg crontab cron cronie cronie
    need_cmd_pkg logrotate logrotate logrotate logrotate
    need_cmd_pkg python3 python3 python3 python3
    if (( ${#missing_pkgs[@]} > 0 )); then
        local -a unique_pkgs=()
        mapfile -t unique_pkgs < <(printf '%s\n' "${missing_pkgs[@]}" | awk 'NF && !seen[$0]++')
        msg "${YELLOW}[*] 检测到缺失依赖包，正在补装...${NC}"
        "${install_cmd[@]}" "${unique_pkgs[@]}" >/dev/null 2>&1 || die '依赖补装失败。'
    fi
    local required=(curl jq openssl bc unzip tar iptables ss lsof vnstat crontab logrotate)
    local c
    for c in "${required[@]}"; do
        command -v "$c" >/dev/null 2>&1 || die "关键依赖缺失: $c"
    done
}

has_ipv6() {
    ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { found=1 } END { exit !found }' && return 0
    ip -6 route show default 2>/dev/null | awk '/^default/ { found=1 } END { exit !found }' && return 0
    return 1
}

wildcard_listen_address() {
    local bindv6only='0'
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
        aarch64|arm64|armv8*) XRAY_ARCH='arm64-v8a'; SB_ARCH='arm64'; HY2_ARCH='arm64' ;;
        *) die "无法识别的底层 CPU 架构: $ARCH" ;;
    esac
}

systemd_available() {
    command -v systemctl >/dev/null 2>&1 || return 1
    [[ -d /run/systemd/system ]] && return 0
    [[ "$(cat /proc/1/comm 2>/dev/null || true)" == 'systemd' ]] && return 0
    systemctl is-system-running --quiet >/dev/null 2>&1
}

service_manager() {
    local action=$1; shift
    local srv
    for srv in "$@"; do
        if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
            case "$action" in
                stop)
                    systemctl stop "$srv" >/dev/null 2>&1 || {
                        systemctl is-active --quiet "$srv" && return 1
                    }
                    systemctl disable "$srv" >/dev/null 2>&1 || return 1
                    systemctl is-active --quiet "$srv" && return 1
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
                    rc-service "$srv" stop >/dev/null 2>&1 || {
                        rc-service "$srv" status >/dev/null 2>&1 && return 1
                    }
                    rc-update del "$srv" default >/dev/null 2>&1 || return 1
                    rc-service "$srv" status >/dev/null 2>&1 && return 1
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
    init=$(effective_init_system)
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
    mapfile -t owned_roots < <(core_family_paths "$srv")
    tmp=$(umask 077; mktemp "$ABOX_DIR/.managed-core-files.XXXXXX") || return 1
    python3 - "$srv" "$ABOX_CORE_OWNERSHIP" "$tmp" "${owned_roots[@]}" <<'PY_CORE_RECORD'
import hashlib, os, stat, sys
srv, old_name, out_name, *roots = sys.argv[1:]
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
def add_path(path):
    try: st=os.lstat(path)
    except FileNotFoundError: return
    if st.st_uid != 0 or st.st_gid != 0 or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022:
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

remove_recorded_core_family() {
    local srv="$1"
    [[ -f "$ABOX_CORE_OWNERSHIP" && ! -L "$ABOX_CORE_OWNERSHIP" ]] || return 2
    [[ "$(stat -c %u:%g "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" == 0:0 ]] || return 1
    [[ "$(stat -c %a "$ABOX_CORE_OWNERSHIP" 2>/dev/null || true)" =~ ^0?600$ ]] || return 1
    [[ "$(stat -c %s "$ABOX_CORE_OWNERSHIP" 2>/dev/null || echo 99999999)" -le 4194304 ]] || return 1
    python3 - "$srv" "$ABOX_CORE_OWNERSHIP" <<'PY_CORE_REMOVE'
import hashlib, os, stat, sys, tempfile
srv, manifest=sys.argv[1:]
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
    if st.st_uid!=0 or st.st_gid!=0 or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022:
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
        /etc/systemd/system/A-Box-firewall.service \
        /etc/init.d/A-Box-firewall
}

auxiliary_content_is_abox_managed() {
    local file="$1" logical_path="$2"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    if [[ "$logical_path" == /usr/local/bin/sb ]]; then
        grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null || grep -Fq '/etc/ddr/A-Box.sh' "$file" 2>/dev/null
        return
    fi
    grep -Fxq '# Managed by A-Box' "$file" 2>/dev/null && return 0
    # Path-specific legacy fingerprints allow a one-time migration. New files
    # always carry the exact marker above.
    case "$logical_path" in
        /etc/logrotate.d/A-Box)
            grep -Fq '/var/log/A-Box-*.log' "$file" && grep -Fq 'create 0600 root root' "$file"
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
            return 1
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
    [[ "${INIT_SYS:-}" == systemd ]] && systemctl daemon-reload >/dev/null 2>&1 || true
}

list_foreign_core_conflicts() {
    local srv path unit key
    local -A seen=()
    for srv in "$@"; do
        abox_owns_service "$srv" && continue
        unit=$(same_name_service_unit_path "$srv" 2>/dev/null || true)
        if [[ -n "$unit" ]]; then
            key="${srv}|${unit}"
            if [[ -z "${seen[$key]:-}" ]]; then printf '%s|%s\n' "$srv" "$unit"; seen[$key]=1; fi
        fi
        while IFS= read -r path; do
            [[ -e "$path" || -L "$path" ]] || continue
            key="${srv}|${path}"
            [[ -n "${seen[$key]:-}" ]] && continue
            printf '%s|%s\n' "$srv" "$path"
            seen[$key]=1
        done < <(core_family_paths "$srv")
    done
}

assert_no_foreign_core_conflicts() {
    local conflicts
    conflicts=$(list_foreign_core_conflicts "$@")
    [[ -z "$conflicts" ]] && return 0
    msg "${RED}[!] Refusing to overwrite non-A-Box core files/services:${NC}"
    while IFS='|' read -r srv path; do [[ -n "$path" ]] && msg "${RED}    ${srv}: ${path}${NC}"; done <<< "$conflicts"
    die '请先迁移或删除上述非 A-Box 安装。A-Box 不会覆盖未知归属的核心、配置或服务文件。'
}

remove_owned_core_family() {
    local srv="$1" path rc
    if ! abox_owns_service "$srv"; then
        while IFS= read -r path; do [[ -e "$path" || -L "$path" ]] && msg "${YELLOW}[!] Skip non-A-Box path: ${path}${NC}"; done < <(core_family_paths "$srv")
        return 0
    fi
    remove_recorded_core_family "$srv"; rc=$?
    case "$rc" in
        0) return 0 ;;
        2)
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
    local failed=0
    remove_owned_core_family xray || failed=1
    remove_owned_core_family sing-box || failed=1
    remove_owned_core_family hysteria || failed=1
    (( failed == 0 ))
}

shortcut_is_abox_managed() {
    local path="${1:-/usr/local/bin/sb}"
    [[ -f "$path" && ! -L "$path" ]] || return 1
    grep -Fxq '# Managed by A-Box' "$path" 2>/dev/null || grep -Fq '/etc/ddr/A-Box.sh' "$path" 2>/dev/null
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
    shortcut_is_abox_managed "$path" && rm -f -- "$path" || msg "${YELLOW}[!] Skip non-A-Box shortcut: ${path}${NC}"
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
    local srv="$1" pid=''
    if [[ "${INIT_SYS:-}" == 'systemd' ]] && systemd_available; then
        pid=$(systemctl show -p MainPID --value "$srv" 2>/dev/null || true)
        [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] && printf '%s\n' "$pid"
    elif [[ "${INIT_SYS:-}" == 'openrc' ]]; then
        case "$srv" in xray) [[ -r /run/xray.pid ]] && cat /run/xray.pid ;; sing-box) [[ -r /run/sing-box.pid ]] && cat /run/sing-box.pid ;; hysteria) [[ -r /run/hysteria.pid ]] && cat /run/hysteria.pid ;; esac
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
    local srv pid exe failed=0
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        pid=$(managed_service_pid "$srv" 2>/dev/null || true)
        pid=${pid%%$'
'*}
        [[ -n "$pid" ]] || continue
        case "$srv" in xray) exe='/usr/local/bin/xray' ;; sing-box) exe='/usr/local/bin/sing-box' ;; hysteria) exe='/usr/local/bin/hysteria' ;; esac
        if pid_exe_matches "$pid" "$exe"; then
            kill -TERM "$pid" 2>/dev/null || failed=1
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null || failed=1
                sleep 1
                kill -0 "$pid" 2>/dev/null && failed=1
            fi
        fi
    done
    (( failed == 0 ))
}

is_service_running() {
    local srv=$1
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then systemctl is-active --quiet "$srv"; else rc-service "$srv" status >/dev/null 2>&1; fi
}

build_status_str() {
    local status_str='' srv
    for srv in xray sing-box hysteria; do
        abox_owns_service "$srv" || continue
        is_service_running "$srv" || continue
        case "$srv" in xray) status_str+="${GREEN}Xray-Core${NC} ";; sing-box) status_str+="${CYAN}Sing-Box${NC} ";; hysteria) status_str+="${GREEN}Hy2(Native)${NC} ";; esac
    done
    [[ -z "$status_str" ]] && status_str="${RED}Stack Stopped${NC}"
    printf '%b' "$status_str"
}

managed_services_active() {
    local srv
    for srv in xray sing-box hysteria; do abox_owns_service "$srv" && is_service_running "$srv" && return 0; done
    return 1
}

confirm_deployment_replacement() {
    local next_core="$1" next_mode="$2" answer current="none"
    [[ -n "${CORE:-}" || -n "${MODE:-}" ]] && current="${CORE:-unknown}-${MODE:-unknown}"
    if [[ "$current" == 'none' ]] && ! managed_services_active; then return 0; fi
    msg "${YELLOW}[!] A-Box will stop managed services before deploying a new stack.${NC}"
    msg "Current config: ${current} | New deployment: ${next_core}-${next_mode}"
    read -r -ep 'Continue deployment? [Y/N]: ' answer
    is_yes "$answer" || die '已取消部署 / Deployment canceled.'
}

service_report_state() {
    local srv="$1" unit
    if abox_owns_service "$srv"; then
        if is_service_running "$srv"; then printf 'active\n'; else printf 'inactive\n'; fi
        return 0
    fi
    unit=$(same_name_service_unit_path "$srv" 2>/dev/null || true)
    if [[ -n "$unit" ]]; then printf 'foreign/unmanaged\n'; else printf 'absent\n'; fi
}

show_status_report() {
    local init='unknown' xray_state sing_state hy2_state shortcut_state='missing' desired='UNINITIALIZED' period='' config_loaded=0
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
Init: ${init}
Config: CORE=${CORE:-} MODE=${MODE:-}
Desired state: ${desired}${period:+ (traffic period ${period})}
Services: xray=${xray_state} sing-box=${sing_state} hysteria=${hy2_state}
Shortcut: /usr/local/bin/sb=${shortcut_state}
Config file: ${ABOX_ENV}
EOF_STATUS
}

remove_abox_firewall_persistence() {
    local failed=0
    if [[ -f /etc/systemd/system/A-Box-firewall.service ]] && grep -Fxq '# Managed by A-Box' /etc/systemd/system/A-Box-firewall.service 2>/dev/null; then
        if systemd_available; then
            systemctl disable --now A-Box-firewall.service >/dev/null 2>&1 || { systemctl is-active --quiet A-Box-firewall.service && failed=1; }
        fi
        rm -f /etc/systemd/system/A-Box-firewall.service || failed=1
        [[ ! -e /etc/systemd/system/A-Box-firewall.service && ! -L /etc/systemd/system/A-Box-firewall.service ]] || failed=1
        systemd_available && systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [[ -f /etc/init.d/A-Box-firewall ]] && grep -Fxq '# Managed by A-Box' /etc/init.d/A-Box-firewall 2>/dev/null; then
        if command -v rc-service >/dev/null 2>&1; then
            rc-service A-Box-firewall stop >/dev/null 2>&1 || { rc-service A-Box-firewall status >/dev/null 2>&1 && failed=1; }
            rc-update del A-Box-firewall default >/dev/null 2>&1 || true
        fi
        rm -f /etc/init.d/A-Box-firewall || failed=1
        [[ ! -e /etc/init.d/A-Box-firewall && ! -L /etc/init.d/A-Box-firewall ]] || failed=1
    fi
    rm -f "$ABOX_DIR/firewall_restore.sh" "$ABOX_DIR/iptables.v4" "$ABOX_DIR/iptables.v6" || failed=1
    [[ ! -e "$ABOX_DIR/firewall_restore.sh" && ! -e "$ABOX_DIR/iptables.v4" && ! -e "$ABOX_DIR/iptables.v6" ]] || failed=1
    (( failed == 0 ))
}

write_abox_firewall_restore_script() {
    local tmp
    install -d -m 700 "$ABOX_DIR" || return 1
    tmp=$(mktemp "$ABOX_DIR/.firewall_restore.XXXXXX") || return 1
    cat > "$tmp" <<'EOF_ABOX_FW_RESTORE'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
clean_chain() {
    local cmd="$1" table="$2" chain="$3" output rule
    local owned_re='--comment "?A-Box-(HY2-HOP|[0-9]+(:[0-9]+)?-(tcp|udp)(-(WL6?|DROP6?))?)"?([[:space:]]|$)'
    local -a argv=()
    command -v "$cmd" >/dev/null 2>&1 || return 0
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
    command -v "$cmd" >/dev/null 2>&1 || return 1
    grep -q '^\*' "$file" || return 0
    "$cmd" -w --noflush < "$file" >/dev/null 2>&1 || "$cmd" --noflush < "$file" >/dev/null 2>&1
}
reorder_one() {
    local cmd="$1" port="$2" proto="$3" wl_suffix="$4" drop_suffix="$5" line i
    local wl_comment="A-Box-${port}-${proto}-${wl_suffix}" drop_comment="A-Box-${port}-${proto}-${drop_suffix}"
    local -a rules=() argv=()
    command -v "$cmd" >/dev/null 2>&1 || return 0
    "$cmd" -w -S INPUT >/dev/null 2>&1 || return 0
    "$cmd" -w -C INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP 2>/dev/null || return 0
    mapfile -t rules < <("$cmd" -w -S INPUT 2>/dev/null | grep -E -- "--comment \"?${wl_comment}\"?([[:space:]]|$)")
    while "$cmd" -w -C INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP 2>/dev/null; do
        "$cmd" -w -D INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1 || return 1
    done
    for line in "${rules[@]}"; do
        line=${line//\"/}
        read -r -a argv <<< "${line/-A /-D }"
        "$cmd" -w "${argv[@]}" >/dev/null 2>&1 || return 1
    done
    "$cmd" -w -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1 || return 1
    for ((i=${#rules[@]}-1; i>=0; i--)); do
        line=${rules[i]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || return 1
        "$cmd" -w -I INPUT 1 "${argv[@]:2}" >/dev/null 2>&1 || return 1
    done
}
reorder_policy() {
    local cmd="$1" wl_suffix="$2" drop_suffix="$3" line key port proto
    local -A seen=()
    command -v "$cmd" >/dev/null 2>&1 || return 0
    while IFS= read -r line; do
        if [[ "$line" =~ --comment[[:space:]]+"?A-Box-([0-9]{1,5})-(tcp|udp)-${drop_suffix}"?([[:space:]]|$) ]]; then
            port="${BASH_REMATCH[1]}"; proto="${BASH_REMATCH[2]}"; key="${port}|${proto}"
            [[ -n "${seen[$key]:-}" ]] && continue
            seen[$key]=1
            reorder_one "$cmd" "$port" "$proto" "$wl_suffix" "$drop_suffix" || return 1
        fi
    done < <("$cmd" -w -S INPUT 2>/dev/null)
}
clean_chain iptables filter INPUT || exit 1
clean_chain iptables nat PREROUTING || exit 1
clean_chain ip6tables filter INPUT || exit 1
clean_chain ip6tables nat PREROUTING || exit 1
restore_one /etc/ddr/iptables.v4 iptables-restore || exit 1
restore_one /etc/ddr/iptables.v6 ip6tables-restore || exit 1
reorder_policy iptables WL DROP || exit 1
reorder_policy ip6tables WL6 DROP6 || exit 1
EOF_ABOX_FW_RESTORE
    chmod 700 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$ABOX_DIR/firewall_restore.sh" || { rm -f "$tmp"; return 1; }
}

install_abox_firewall_persistence_service() {
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        assert_abox_auxiliary_safe /etc/systemd/system/A-Box-firewall.service
    elif [[ "${INIT_SYS:-}" == openrc ]]; then
        assert_abox_auxiliary_safe /etc/init.d/A-Box-firewall
    fi
    write_abox_firewall_restore_script || return 1
    if [[ "${INIT_SYS:-}" == systemd ]]; then
        write_file_atomically_from_stdin /etc/systemd/system/A-Box-firewall.service 644 <<'EOF_ABOX_FW_UNIT' || return 1
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
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        systemctl enable A-Box-firewall.service >/dev/null 2>&1 || return 1
    elif [[ "${INIT_SYS:-}" == openrc ]]; then
        write_file_atomically_from_stdin /etc/init.d/A-Box-firewall 755 <<'EOF_ABOX_FW_OPENRC' || return 1
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box isolated firewall rule restore"
command="/etc/ddr/firewall_restore.sh"
command_background="no"
depend() { need net; after iptables ip6tables nftables ufw firewalld; before xray sing-box hysteria; }
EOF_ABOX_FW_OPENRC
        chmod 755 /etc/init.d/A-Box-firewall || return 1
        rc-update add A-Box-firewall default >/dev/null 2>&1 || return 1
    else
        return 1
    fi
}

save_firewall_rules() {
    local tmp4 tmp6
    command -v iptables-save >/dev/null 2>&1 || return 1
    install -d -m 700 "$ABOX_DIR" || return 1
    tmp4=$(mktemp "$ABOX_DIR/.iptables.v4.XXXXXX") || return 1
    tmp6=$(mktemp "$ABOX_DIR/.iptables.v6.XXXXXX") || { rm -f "$tmp4"; return 1; }
    iptables-save > "${tmp4}.all" 2>/dev/null || { rm -f "$tmp4" "$tmp6" "${tmp4}.all"; return 1; }
    extract_abox_iptables_rules "${tmp4}.all" all > "$tmp4" || { rm -f "$tmp4" "$tmp6" "${tmp4}.all"; return 1; }
    rm -f "${tmp4}.all"
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "${tmp6}.all" 2>/dev/null || { rm -f "$tmp4" "$tmp6" "${tmp6}.all"; return 1; }
        extract_abox_iptables_rules "${tmp6}.all" all > "$tmp6" || { rm -f "$tmp4" "$tmp6" "${tmp6}.all"; return 1; }
        rm -f "${tmp6}.all"
    else
        : > "$tmp6"
    fi
    chmod 600 "$tmp4" "$tmp6" || { rm -f "$tmp4" "$tmp6"; return 1; }
    if ! grep -q '^\*' "$tmp4" && ! grep -q '^\*' "$tmp6"; then
        rm -f "$tmp4" "$tmp6"
        remove_abox_firewall_persistence || return 1
        return 0
    fi
    mv -f "$tmp4" "$ABOX_DIR/iptables.v4" || { rm -f "$tmp4" "$tmp6"; return 1; }
    mv -f "$tmp6" "$ABOX_DIR/iptables.v6" || { rm -f "$tmp6"; return 1; }
    install_abox_firewall_persistence_service || return 1
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
    [[ -r /etc/ufw/ufw.conf ]] && grep -Eiq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/ufw/ufw.conf && return 0
    LC_ALL=C ufw status 2>/dev/null | awk 'tolower($0) ~ /^status:[[:space:]]*active/ { found=1 } END { exit !found }'
}

firewall_backend() {
    if ufw_is_active; then printf 'ufw\n'; elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then printf 'firewalld\n'; else printf 'iptables\n'; fi
}

native_firewall_record_valid() {
    local line="$1" backend spec proto scope extra normalized
    IFS='|' read -r backend spec proto scope extra <<< "$line"
    [[ -z "$extra" ]] || return 1
    normalized=$(normalize_port_spec "$spec") || return 1
    [[ "$normalized" == "$spec" ]] || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    case "$backend:$scope" in
        ufw:rule|firewalld:runtime|firewalld:permanent) return 0 ;;
        *) return 1 ;;
    esac
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
    local backend="$1" spec proto="$3" scope="${4:-}" record tmp
    spec=$(normalize_port_spec "$2") || return 1
    [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    case "$backend:$scope" in
        ufw:rule|firewalld:runtime|firewalld:permanent) ;;
        *) return 1 ;;
    esac
    record="${backend}|${spec}|${proto}|${scope}"
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
        rest="${rest#${rest%%[![:space:]]*}}"
        case "$rest" in
            'ALLOW IN '*) rest="${rest#ALLOW IN }" ;;
            'LIMIT IN '*) rest="${rest#LIMIT IN }" ;;
            *) continue ;;
        esac
        rest="${rest#${rest%%[![:space:]]*}}"
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
    local spec proto="$2" numbers number
    spec=$(normalize_port_spec "$1") || return 1
    numbers=$(ufw_global_rule_numbers "$spec" "$proto" 1) || return 1
    [[ -n "$numbers" ]] || return 0
    while IFS= read -r number; do
        [[ "$number" =~ ^[0-9]+$ ]] || return 1
        ufw --force delete "$number" >/dev/null 2>&1 || return 1
    done < <(printf '%s\n' "$numbers" | sort -rn)
    ! ufw_owned_rule_exists "$spec" "$proto"
}

firewalld_port_state() {
    local spec proto="$2" scope="${3:-runtime}" fw_spec rc
    spec=$(normalize_port_spec "$1") || return 2
    [[ "$proto" == tcp || "$proto" == udp ]] || return 2
    fw_spec=$(port_spec_for_firewalld "$spec") || return 2
    command -v firewall-cmd >/dev/null 2>&1 || return 2
    firewall-cmd --state >/dev/null 2>&1 || return 2
    if [[ "$scope" == permanent ]]; then
        firewall-cmd --permanent --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
    else
        firewall-cmd --query-port="${fw_spec}/${proto}" >/dev/null 2>&1
    fi
    rc=$?
    case "$rc" in 0) return 0 ;; 1) return 1 ;; *) return 2 ;; esac
}

remove_native_firewall_rules() {
    [[ ! -e "$ABOX_FW_STATE" && ! -L "$ABOX_FW_STATE" ]] && return 0
    validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    local backend spec proto scope extra fw_spec any_failed=0 record_failed tmp
    tmp=$(mktemp "$ABOX_DIR/.firewall-native.remaining.XXXXXX") || return 1
    while IFS='|' read -r backend spec proto scope extra; do
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
                    firewall-cmd --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    firewalld_port_state "$spec" "$proto" runtime
                    [[ $? == 1 ]] || record_failed=1
                elif [[ "$scope" == permanent ]]; then
                    firewall-cmd --permanent --remove-port="${fw_spec}/${proto}" >/dev/null 2>&1 || true
                    firewalld_port_state "$spec" "$proto" permanent
                    [[ $? == 1 ]] || record_failed=1
                else
                    record_failed=1
                fi
                ;;
            *) record_failed=1 ;;
        esac
        if [[ "$record_failed" == 1 ]]; then
            printf '%s|%s|%s|%s\n' "$backend" "$spec" "$proto" "$scope" >> "$tmp"
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

apply_native_firewall_rules_from_state() {
    [[ ! -e "$ABOX_FW_STATE" && ! -L "$ABOX_FW_STATE" ]] && return 0
    validate_native_firewall_state_file "$ABOX_FW_STATE" || return 1
    local backend spec proto scope extra fw_spec failed=0
    while IFS='|' read -r backend spec proto scope extra; do
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
                    firewalld_port_state "$spec" "$proto" runtime
                    case $? in 0) : ;; 1) firewall-cmd --add-port="${fw_spec}/${proto}" >/dev/null 2>&1 || { failed=1; continue; } ;; *) failed=1; continue ;; esac
                    firewalld_port_state "$spec" "$proto" runtime || failed=1
                elif [[ "$scope" == permanent ]]; then
                    firewalld_port_state "$spec" "$proto" permanent
                    case $? in 0) : ;; 1) firewall-cmd --permanent --add-port="${fw_spec}/${proto}" >/dev/null 2>&1 || { failed=1; continue; } ;; *) failed=1; continue ;; esac
                    firewalld_port_state "$spec" "$proto" permanent || failed=1
                else
                    failed=1
                fi
                ;;
            *) failed=1 ;;
        esac
    done < "$ABOX_FW_STATE"
    (( failed == 0 ))
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
                firewall-cmd --add-port="${fw_spec}/${type}" >/dev/null 2>&1 || die "firewalld runtime 放行失败: ${fw_spec}/${type}"
                added_runtime=1
                record_native_firewall_rule firewalld "$spec" "$type" runtime || { firewall-cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true; die 'firewalld runtime 规则归属记录失败。'; }
            fi
            if [[ "$permanent" == 0 ]]; then
                if ! firewall-cmd --permanent --add-port="${fw_spec}/${type}" >/dev/null 2>&1; then
                    [[ "$added_runtime" == 1 ]] && firewall-cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    die "firewalld permanent 放行失败: ${fw_spec}/${type}"
                fi
                if ! record_native_firewall_rule firewalld "$spec" "$type" permanent; then
                    firewall-cmd --permanent --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    [[ "$added_runtime" == 1 ]] && firewall-cmd --remove-port="${fw_spec}/${type}" >/dev/null 2>&1 || true
                    die 'firewalld permanent 规则归属记录失败。'
                fi
            fi
            firewalld_port_state "$spec" "$type" runtime || die 'firewalld runtime 后置验证失败。'
            firewalld_port_state "$spec" "$type" permanent || die 'firewalld permanent 后置验证失败。'
            return 0
            ;;
    esac
    if ! $IPT -w -C INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT 2>/dev/null; then
        $IPT -w -I INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv4 防火墙放行失败: ${spec}/${type}"
    fi
    if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
        if ! $IPT6 -w -C INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT 2>/dev/null; then
            $IPT6 -w -I INPUT -p "$type" --dport "$spec" -m comment --comment "A-Box-${spec}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv6 防火墙放行失败: ${spec}/${type}"
        fi
    fi
}

remove_ss_open_accept_rules() {
    local proto failed=0 comment
    [[ -n "${SS_PORT:-}" ]] || return 0
    for proto in tcp udp; do
        comment="A-Box-${SS_PORT}-${proto}"
        while $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT 2>/dev/null; do
            $IPT -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || { failed=1; break; }
        done
        $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT 2>/dev/null && failed=1
        if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
            while $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT 2>/dev/null; do
                $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || { failed=1; break; }
            done
            $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "$comment" -j ACCEPT 2>/dev/null && failed=1
        fi
    done
    (( failed == 0 ))
}


reorder_ss_whitelist_rules_one() {
    local cmd="$1" port="$2" proto="$3" wl_suffix="$4" drop_suffix="$5" line
    local wl_comment="A-Box-${port}-${proto}-${wl_suffix}" drop_comment="A-Box-${port}-${proto}-${drop_suffix}"
    local -a rules=() argv=()
    command -v "$cmd" >/dev/null 2>&1 || return 0
    "$cmd" -w -S INPUT >/dev/null 2>&1 || return 0
    "$cmd" -w -C INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP 2>/dev/null || return 0
    mapfile -t rules < <("$cmd" -w -S INPUT 2>/dev/null | grep -E -- "--comment \"?${wl_comment}\"?([[:space:]]|$)")
    while "$cmd" -w -C INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP 2>/dev/null; do
        "$cmd" -w -D INPUT -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1 || return 1
    done
    for line in "${rules[@]}"; do
        line=${line//\"/}
        read -r -a argv <<< "${line/-A /-D }"
        "$cmd" -w "${argv[@]}" >/dev/null 2>&1 || return 1
    done
    "$cmd" -w -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$drop_comment" -j DROP >/dev/null 2>&1 || return 1
    local i
    for ((i=${#rules[@]}-1; i>=0; i--)); do
        line=${rules[i]//\"/}
        read -r -a argv <<< "$line"
        [[ "${argv[0]:-}" == -A && "${argv[1]:-}" == INPUT ]] || return 1
        "$cmd" -w -I INPUT 1 "${argv[@]:2}" >/dev/null 2>&1 || return 1
    done
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
    if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -t nat -S PREROUTING >/dev/null 2>&1; then
        while :; do
            output=$($IPT6 -w -t nat -S PREROUTING 2>/dev/null) || { failed=1; break; }
            rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
            [[ -n "$rule" ]] || break
            rule=${rule//\"/}
            read -r -a argv <<< "$rule"
            $IPT6 -w -t nat "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
        done
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
    if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
        while :; do
            output=$($IPT6 -w -S INPUT 2>/dev/null) || { failed=1; break; }
            rule=$(awk -v re="$owned_re" '$0 ~ re { sub(/^-A /,"-D "); print; exit }' <<< "$output")
            [[ -n "$rule" ]] || break
            rule=${rule//\"/}
            read -r -a argv <<< "$rule"
            $IPT6 -w "${argv[@]}" >/dev/null 2>&1 || { failed=1; break; }
        done
    fi
    (( failed == 0 ))
}

add_port_pair() {
    local arr_name="$1" proto="$2" port="$3"
    [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] || return 0
    printf -v "$arr_name" '%s%s/%s\n' "${!arr_name}" "$proto" "$port"
}

selected_port_pairs() {
    local pairs=''
    add_port_pair pairs tcp "${VLESS_PORT:-}"
    add_port_pair pairs tcp "${XHTTP_PORT:-}"
    add_port_pair pairs tcp "${SS_PORT:-}"
    add_port_pair pairs udp "${SS_PORT:-}"
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
            if [[ "$proto" == 'udp' ]] && (( p >= HY2_RANGE_START && p <= HY2_RANGE_END )); then
                die "端口冲突：HY2 基础 UDP 端口 ($p) 不能落在跳跃区间 (${HY2_RANGE_START}-${HY2_RANGE_END}) 内。"
            fi
        done
    fi

    for pair in $pairs; do
        proto=${pair%/*}; p=${pair#*/}
        holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${p}([[:space:]]|$)" || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 新选择端口 ${p}/${proto} 仍被进程占用：${NC}"
        echo "$holder"
        die "请先手动释放端口 ${p}/${proto}。"
    done

    if [[ "${HY2_HOP:-}" == 'true' && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
        holder=$(ss -H -n -l -p -A udp 2>/dev/null | while read -r line; do
            p=$(awk '{print $4}' <<< "$line" | sed -nE 's/.*[:.]([0-9]+)$/\1/p')
            [[ "$p" =~ ^[0-9]+$ ]] || continue
            if (( p >= HY2_RANGE_START && p <= HY2_RANGE_END )); then
                echo "$line"
            fi
        done || true)
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] HY2 UDP 跳跃区间 ${HY2_RANGE_START}-${HY2_RANGE_END} 仍被进程占用：${NC}"
            echo "$holder"
            die '请先手动释放 HY2 UDP 跳跃区间内的占用端口。'
        fi
    fi
}

release_ports() {
    msg "${YELLOW}[*] 正在停止 A-Box 托管服务并检查端口占用...${NC}"
    stop_all_managed_services || die '无法停止全部 A-Box 托管服务。'
    sleep 1
    local pairs pair proto p holder
    pairs=$(selected_port_pairs | awk 'NF' | sort -u)
    for pair in $pairs; do
        proto=${pair%/*}; p=${pair#*/}
        holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${p}([[:space:]]|$)" || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 端口 ${p}/${proto} 仍被进程占用：${NC}"
        echo "$holder"
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
    [[ -s "$f" ]] || die "${context} 为空或不存在。"
    bash -n "$f" || die "${context} 语法校验失败。"
    grep -q '==============================A-Box===============================' "$f" || die "${context} 文本指纹不匹配。"
    grep -q '^main "\$@"' "$f" || die "${context} 入口指纹不匹配。"
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
    tmp=$(mktemp /tmp/A-Box-script.XXXXXX.sh) || die '远端脚本临时文件创建失败。'
    curl -fLs --connect-timeout 10 -m 60 "$url" -o "$tmp" || { rm -f "$tmp"; die '远端脚本下载失败。'; }
    validate_abox_script_file "$tmp" '远端 A-Box 脚本'
    validate_ota_version_direction "$tmp"
    sha=$(sha256sum "$tmp" | awk '{print $1}')
    msg "${YELLOW}[*] Remote script SHA256: ${sha}${NC}"
    confirm_ota_script_hash "$sha" "$url" || { rm -f "$tmp"; die '远端脚本安装被取消。'; }
    write_if_changed "$dest" "$tmp" 700 || die '远端 A-Box 脚本原子持久化失败。'
}

setup_shortcut() {
    mkdir -p "$ABOX_DIR"
    if [[ "${1:-}" == 'update' ]]; then
        install_remote_abox_script_guarded "$SCRIPT_URL" "$ABOX_DIR/A-Box.sh"
    elif [[ -f "$0" && -r "$0" && "$0" != 'bash' && "$0" != '-bash' ]]; then
        validate_abox_script_file "$0" '当前 A-Box 脚本'
        if [[ ! -f "$ABOX_DIR/A-Box.sh" ]] || ! cmp -s "$0" "$ABOX_DIR/A-Box.sh"; then
            install_binary_atomically "$0" "$ABOX_DIR/A-Box.sh" || die '持久化当前脚本失败。'
        fi
    elif [[ ! -f "$ABOX_DIR/A-Box.sh" ]]; then
        install_remote_abox_script_guarded "$SCRIPT_URL" "$ABOX_DIR/A-Box.sh"
    fi
    [[ -f "$ABOX_DIR/A-Box.sh" ]] || die '持久化 A-Box 脚本不存在。'
    validate_abox_script_file "$ABOX_DIR/A-Box.sh" '持久化 A-Box 脚本'
    chmod +x "$ABOX_DIR/A-Box.sh"

    local shortcut_tmp
    shortcut_tmp=$(mktemp /tmp/A-Box-sb.XXXXXX) || die '快捷入口临时文件创建失败。'
    cat > "$shortcut_tmp" <<'EOS'
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
    chmod 755 "$shortcut_tmp"
    assert_abox_shortcut_safe /usr/local/bin/sb
    if [[ ! -f /usr/local/bin/sb ]] || ! cmp -s "$shortcut_tmp" /usr/local/bin/sb; then
        install_binary_atomically "$shortcut_tmp" /usr/local/bin/sb || die '快捷入口写入失败。'
        rm -f "$shortcut_tmp"
    else
        rm -f "$shortcut_tmp"
        chmod 755 /usr/local/bin/sb 2>/dev/null || true
    fi
}
validate_downloaded_asset() {
    local asset_name="$1" f="${2:-/tmp/$1}"
    [[ -s "$f" ]] || die "下载资产为空: $asset_name"
    case "$asset_name" in
        xray_core.zip) unzip -tqq "$f" >/dev/null 2>&1 || die 'Xray 压缩包校验失败。' ;;
        singbox_core.tar.gz) tar -tzf "$f" >/dev/null 2>&1 || die 'Sing-box 压缩包校验失败。' ;;
        hysteria_core) [[ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')" == '7f454c46' ]] || die 'Hysteria 下载结果不是 ELF 可执行文件。' ;;
        *) die "未定义的下载校验规则: $asset_name" ;;
    esac
}


extract_zip_member_safely() {
    local archive="$1" member="$2" dest="$3"
    [[ -s "$archive" && -n "$member" && -n "$dest" ]] || return 1
    python3 - "$archive" "$member" "$dest" <<'PY_ZIP_EXTRACT'
import os, shutil, stat, sys, zipfile
archive, member, dest = sys.argv[1:]
MAX_FILE = 512 * 1024 * 1024
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
    try: os.unlink(dest)
    except OSError: pass
    raise SystemExit(1)
PY_TAR_EXTRACT
}

github_api_get() {
    local url="$1"
    local -a args=(-fLsS --connect-timeout 10 -m 60 -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2026-03-10')
    [[ -n "${GITHUB_TOKEN:-}" ]] && args+=( -H "Authorization: Bearer ${GITHUB_TOKEN}" )
    curl "${args[@]}" "$url"
}

verify_github_asset_digest() {
    local file="$1" digest="${2:-}" expected actual
    if [[ -z "$digest" || "$digest" == 'null' ]]; then
        die 'GitHub Release asset 缺少官方 SHA256 digest，拒绝安装。'
    fi
    [[ "$digest" == sha256:* ]] || die 'GitHub Release digest 不是 sha256 格式。'
    expected="${digest#sha256:}"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || die 'GitHub Release digest 格式异常。'
    actual=$(sha256sum "$file" | awk '{print $1}')
    [[ "${actual,,}" == "${expected,,}" ]] || die 'GitHub Release digest 校验失败。'
}

valid_github_download_url() {
    local repo="$1" url="$2"
    [[ "$url" == "https://github.com/${repo}/releases/download/"* ]]
}

fetch_github_release() {
    local repo=$1 output_file=$2 dest_file="${3:-}" api_url asset_re release_json asset_json download_url digest mirror tmp_file tmp_dir
    api_url="https://api.github.com/repos/${repo}/releases/latest"
    case "${repo}:${output_file}" in
        XTLS/Xray-core:xray_core.zip) asset_re="^Xray-linux-${XRAY_ARCH//+/\\+}\\.zip$" ;;
        SagerNet/sing-box:singbox_core.tar.gz) asset_re="^sing-box-.*-linux-${SB_ARCH}\\.tar\\.gz$" ;;
        apernet/hysteria:hysteria_core) asset_re="^hysteria-linux-${HY2_ARCH}$" ;;
        *) die "未定义的资产匹配规则: ${repo}:${output_file}" ;;
    esac
    msg "${YELLOW} -> 正在从 GitHub 抓取最新架构版本 [${repo}]...${NC}"

    release_json=$(github_api_get "$api_url" 2>/dev/null) || release_json=''
    [[ -n "$release_json" ]] || die 'GitHub Release API 请求失败；为保证 digest 信任根，不使用第三方镜像 API。'

    asset_json=$(jq -c --arg re "$asset_re" 'first(.assets[]? | select(.name | test($re)) | {url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
    [[ -n "$asset_json" && "$asset_json" != 'null' ]] || die '未能解析核心资产下载地址。'
    download_url=$(jq -r '.url' <<< "$asset_json")
    digest=$(jq -r '.digest // ""' <<< "$asset_json")
    valid_github_download_url "$repo" "$download_url" || die 'GitHub Release 下载地址域名/仓库不匹配。'

    if [[ -z "$dest_file" ]]; then
        tmp_dir=$(mktemp -d /tmp/A-Box-asset.XXXXXX) || die '核心资产临时目录创建失败。'
        dest_file="$tmp_dir/$output_file"
    else
        mkdir -p "$(dirname "$dest_file")"
        rm -f -- "$dest_file"
    fi

    for mirror in '' 'https://ghp.ci/' 'https://mirror.ghproxy.com/'; do
        tmp_file=$(mktemp "${dest_file}.download.XXXXXX") || die '核心资产临时文件创建失败。'
        if curl -fLsS --connect-timeout 10 -m 180 "${mirror}${download_url}" -o "$tmp_file"; then
            if ( validate_downloaded_asset "$output_file" "$tmp_file" && verify_github_asset_digest "$tmp_file" "$digest" ); then
                mv -f "$tmp_file" "$dest_file" || { rm -f "$tmp_file"; die '核心资产原子提交失败。'; }
                FETCHED_ASSET_PATH="$dest_file"
                msg "${GREEN}   核心资产提取成功。${NC}"
                return 0
            fi
            if [[ -z "$mirror" ]]; then rm -f "$tmp_file"; die 'GitHub 官方通道返回的资产校验失败。'; fi
            msg "${YELLOW}[!] 第三方镜像资产校验失败，继续尝试下一通道。${NC}"
        fi
        rm -f "$tmp_file"
    done
    die '所有通道均无法下载核心资产。请检查网络。'
}

fetch_geo_data() {
    local file_name official_url out tmp_out size repo asset release_json asset_json download_url digest
    file_name="${1:-}"
    official_url="${2:-}"
    out="${3:-}"
    [[ -n "$file_name" && -n "$official_url" ]] || die 'Geo 数据下载参数缺失。'
    [[ "$file_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "Geo 数据文件名非法: $file_name"
    [[ -n "$out" ]] || out="$(mktemp "/tmp/${file_name}.XXXXXX")"
    mkdir -p "$(dirname "$out")"
    tmp_out=$(mktemp "${out}.download.XXXXXX") || die 'Geo 数据临时文件创建失败。'

    if [[ "$official_url" =~ ^https://github.com/([^/]+/[^/]+)/releases/latest/download/([^/?#]+)$ ]]; then
        repo="${BASH_REMATCH[1]}"
        asset="${BASH_REMATCH[2]}"
        release_json=$(github_api_get "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null) || release_json=''
        [[ -n "$release_json" ]] || { rm -f -- "$tmp_out"; die "Geo Release API 请求失败: ${repo}"; }
        asset_json=$(jq -c --arg name "$asset" 'first(.assets[]? | select(.name == $name) | {url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
        [[ -n "$asset_json" && "$asset_json" != 'null' ]] || { rm -f -- "$tmp_out"; die "Geo Release asset 未找到: ${asset}"; }
        download_url=$(jq -r '.url' <<< "$asset_json")
        digest=$(jq -r '.digest // ""' <<< "$asset_json")
        valid_github_download_url "$repo" "$download_url" || { rm -f -- "$tmp_out"; die 'Geo GitHub Release 下载地址域名/仓库不匹配。'; }
        curl -fLs --connect-timeout 10 -m 90 "$download_url" -o "$tmp_out" || { rm -f -- "$tmp_out"; die "Geo 数据文件 ${file_name} 下载失败。"; }
        verify_github_asset_digest "$tmp_out" "$digest"
    else
        curl -fLs --connect-timeout 10 -m 90 "$official_url" -o "$tmp_out" || { rm -f -- "$tmp_out"; die "Geo 数据文件 ${file_name} 下载失败。"; }
    fi

    size=$(wc -c < "$tmp_out" 2>/dev/null | tr -d ' ')
    [[ -n "$size" && "$size" -gt 500000 ]] || { rm -f -- "$tmp_out" "$out"; die "Geo 数据文件 ${file_name} 大小异常。"; }
    if head -c 256 "$tmp_out" 2>/dev/null | grep -Eiq '<(html|!doctype)'; then
        rm -f -- "$tmp_out" "$out"
        die "Geo 数据文件 ${file_name} 看起来是 HTML 错误页。"
    fi
    mv -f "$tmp_out" "$out"
    FETCHED_GEO_PATH="$out"
}

desired_state_valid() { [[ "${1:-}" =~ ^(RUNNING|TRAFFIC_BLOCKED|MANUAL_STOPPED|MAINTENANCE)$ ]]; }
get_desired_state() {
    local state='RUNNING' uid gid mode
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
    local state="$1"
    desired_state_valid "$state" || return 1
    ensure_abox_dir_owned "$ABOX_DIR"
    write_file_atomically_from_stdin "$ABOX_DESIRED_STATE" 600 <<< "$state"
}
traffic_period_valid() { [[ "${1:-}" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]]; }
get_traffic_block_period() {
    local period uid gid mode
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
    local period="$1"
    traffic_period_valid "$period" || return 1
    write_file_atomically_from_stdin "$ABOX_TRAFFIC_BLOCK_STATE" 600 <<< "$period"
}
clear_traffic_block_period() { rm -f -- "$ABOX_TRAFFIC_BLOCK_STATE"; }
update_traffic_state_atomically() {
    local limit="${1:-}" mode="${2:-}" tmp
    [[ -f "$ABOX_ENV" && ! -L "$ABOX_ENV" ]] || return 1
    tmp=$(mktemp "$ABOX_DIR/.env.A-Box-update.XXXXXX") || return 1
    awk '!/^TRAFFIC_LIMIT_GB=/ && !/^TRAFFIC_LIMIT_MODE=/' "$ABOX_ENV" > "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -n "$limit" ]]; then
        valid_positive_int "$limit" || { rm -f "$tmp"; return 1; }
        [[ "$mode" =~ ^(total|rx|tx)$ ]] || { rm -f "$tmp"; return 1; }
        printf 'TRAFFIC_LIMIT_GB=%q\nTRAFFIC_LIMIT_MODE=%q\n' "$limit" "$mode" >> "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$ABOX_ENV" || { rm -f "$tmp"; return 1; }
}

reset_protocol_vars() {
    unset UUID VLESS_SNI VISION_SNI XHTTP_SNI VLESS_PORT XHTTP_PORT HY2_BASE_PORT HY2_DOMAIN HY2_UP HY2_DOWN HY2_MASQ_URL
    unset SS_PORT SS_WHITELIST_IP PUBLIC_KEY PBK SHORT_ID HY2_PASS HY2_OBFS SS_PASS
    unset HY2_CERT_SHA256_FP HY2_CERT_PUBKEY_SHA256_B64 HY2_HOP HY2_HOP_IMPL HY2_MONITOR_PORT
    unset HY2_ACME_TYPE HY2_ACME_DNS_PROVIDER HY2_ACME_DNS_CF_API_TOKEN
    unset HY2_URI_PORTS HY2_CLASH_PORTS HY2_SB_PORTS HY2_RANGE_START HY2_RANGE_END ENABLE_KEEPALIVE
}

write_file_atomically_from_stdin() {
    local dest="$1" mode="${2:-600}" dir tmp
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    [[ ! -L "$dest" ]] || return 1
    dir=$(dirname "$dest")
    if [[ ! -d "$dir" ]]; then mkdir -p "$dir" || return 1; fi
    tmp=$(mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    cat > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod "$mode" "$tmp" || { rm -f -- "$tmp"; return 1; }
    if [[ $EUID -eq 0 ]]; then chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }; fi
    sync -f "$tmp" 2>/dev/null || true
    mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
    sync -f "$dir" 2>/dev/null || true
}

write_env() {
    local env_core="$1" env_mode="$2" old_traffic_limit_gb='' old_traffic_limit_mode='' tmp
    if [[ -f "$ABOX_ENV" ]]; then
        old_traffic_limit_gb=$(grep '^TRAFFIC_LIMIT_GB=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
        old_traffic_limit_mode=$(grep '^TRAFFIC_LIMIT_MODE=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
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
        printf 'PUBLIC_KEY=%s\n' "$(shell_quote "${PBK:-}")"
        printf 'SHORT_ID=%s\n' "$(shell_quote "${SHORT_ID:-}")"
        printf 'HY2_PASS=%s\n' "$(shell_quote "${HY2_PASS:-}")"
        printf 'HY2_OBFS=%s\n' "$(shell_quote "${HY2_OBFS:-}")"
        printf 'SS_PASS=%s\n' "$(shell_quote "${SS_PASS:-}")"
        printf 'LINK_IP=%s\n' "$(shell_quote "${GLOBAL_PUBLIC_IP:-}")"
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
    set_desired_state RUNNING || die 'A-Box 服务期望状态提交失败。'
}

validate_fail2ban_config_or_die() {
    command -v fail2ban-client >/dev/null 2>&1 || return 0
    local out sample
    if fail2ban-client -h 2>&1 | grep -E -- '(^|[[:space:]])-t([,[:space:]]|$)|--test' >/dev/null; then
        out=$(fail2ban-client -t 2>&1) || { printf '%s\n' "$out" >&2; die 'Fail2Ban 配置校验失败；已停止部署以避免无效防御配置。'; }
    else
        out=$(fail2ban-client -d 2>&1) || { printf '%s\n' "$out" >&2; die 'Fail2Ban 配置 dump 失败；疑似配置无效，已停止部署。'; }
    fi
    if command -v fail2ban-regex >/dev/null 2>&1 && [[ -r /etc/fail2ban/filter.d/A-Box.conf ]]; then
        sample=$(mktemp /tmp/A-Box-f2b-sample.XXXXXX) || die 'Fail2Ban sample creation failed.'
        cat > "$sample" <<'EOF_F2B_SAMPLE'
2026-07-25T10:00:00Z process connection from 203.0.113.7:54321: message authentication failed
2026-07-25T10:00:01Z authentication failed from [2001:db8::7]:443
2026-07-25T10:00:02Z client=198.51.100.9 rejected
EOF_F2B_SAMPLE
        out=$(fail2ban-regex "$sample" /etc/fail2ban/filter.d/A-Box.conf 2>&1) || { rm -f "$sample"; printf '%s\n' "$out" >&2; die 'Fail2Ban 正则测试执行失败。'; }
        rm -f "$sample"
        grep -Eq '^[[:space:]]*[2-9][0-9]*[[:space:]]+total|Failregex:[[:space:]]*[2-9]' <<< "$out" || { printf '%s\n' "$out" >&2; die 'Fail2Ban 过滤器未匹配代表性认证失败日志。'; }
    fi
}

setup_active_defense() {
    msg "${YELLOW}[*] 正在挂载私有日志与 Fail2Ban 主动防御矩阵...${NC}"
    touch /var/log/A-Box-xray-access.log /var/log/A-Box-xray-error.log /var/log/A-Box-singbox.log /var/log/A-Box-hysteria.log || die 'A-Box 日志文件创建失败。'
    chmod 600 /var/log/A-Box-*.log || die 'A-Box 日志权限设置失败。'
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
    create 0600 root root
}
EOF_LOGROTATE
    if command -v fail2ban-client >/dev/null 2>&1; then
        local tcp_ports='' udp_ports='' jail_tmp
        mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
        assert_abox_auxiliary_safe /etc/fail2ban/filter.d/A-Box.conf
        assert_abox_auxiliary_safe /etc/fail2ban/jail.d/A-Box.local
        jail_tmp=$(mktemp /etc/fail2ban/jail.d/.A-Box.local.A-Box-new.XXXXXX) || die 'Fail2Ban jail 临时文件创建失败。'
        write_file_atomically_from_stdin /etc/fail2ban/filter.d/A-Box.conf 644 <<'EOF_F2B_FILTER' || die 'Fail2Ban filter 原子写入失败。'
# Managed by A-Box
[Definition]
failregex = ^.*(?:authentication failed|message authentication failed|rejected|unauthorized|forbidden|invalid request|bad request).*?(?:from|client[=:])\s*\[?<HOST>\]?(?::[0-9]+)?(?:\s|:|$).*$
            ^.*(?:from|client[=:])\s*\[?<HOST>\]?(?::[0-9]+)?(?:\s|:).*?(?:authentication failed|message authentication failed|rejected|unauthorized|forbidden|invalid request|bad request).*$
ignoreregex =
EOF_F2B_FILTER
        [[ -n "${VLESS_PORT:-}" ]] && tcp_ports+="${VLESS_PORT},"
        [[ -n "${XHTTP_PORT:-}" ]] && tcp_ports+="${XHTTP_PORT},"
        [[ -n "${SS_PORT:-}" ]] && { tcp_ports+="${SS_PORT},"; udp_ports+="${SS_PORT},"; }
        if [[ "${HY2_HOP:-}" == true && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then udp_ports+="${HY2_RANGE_START}:${HY2_RANGE_END},"; elif [[ -n "${HY2_BASE_PORT:-}" ]]; then udp_ports+="${HY2_BASE_PORT},"; fi
        tcp_ports="${tcp_ports%,}"; udp_ports="${udp_ports%,}"
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
action = iptables-multiport[name=A-Box-tcp, port="${tcp_ports}", protocol=tcp]

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
action = iptables-multiport[name=A-Box-udp, port="${udp_ports}", protocol=udp]
EOF_F2B_UDP
        fi
        if [[ -n "$tcp_ports" || -n "$udp_ports" ]]; then
            chmod 644 "$jail_tmp" || { rm -f -- "$jail_tmp"; die 'Fail2Ban jail 权限设置失败。'; }
            mv -f -- "$jail_tmp" /etc/fail2ban/jail.d/A-Box.local || { rm -f -- "$jail_tmp"; die 'Fail2Ban jail 原子提交失败。'; }
            validate_fail2ban_config_or_die
            if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl restart fail2ban >/dev/null 2>&1 || die 'Fail2Ban 重启失败。'; else rc-service fail2ban restart >/dev/null 2>&1 || die 'Fail2Ban 重启失败。'; fi
        else
            rm -f -- "$jail_tmp"
            remove_owned_auxiliary_path /etc/fail2ban/jail.d/A-Box.local || die '空的 A-Box Fail2Ban jail 删除失败。'
        fi
    fi
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
MAIN_LOCK=/etc/ddr/.runtime.lock
exec 8>"$MAIN_LOCK" || exit 0
flock -n 8 || exit 0
exec 9>"$LOCK" || exit 0
flock -n 9 || exit 0
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
    if ! python3 /dev/fd/3 "$ENV" > "$parsed" 3<<'PY_HELPER_ENV'; then
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
is_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
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
    [[ "$port" =~ ^[0-9]+$ && "$pid" =~ ^[0-9]+$ ]] || return 1
    case "$proto" in tcp) flags='-H -nltp' ;; udp) flags='-H -nlup' ;; *) return 1 ;; esac
    # shellcheck disable=SC2086
    ss $flags 2>/dev/null | awk -v p="$port" -v pid="$pid" '
        $4 ~ ("[:.]" p "$") && $0 ~ ("pid=" pid "([,)]|$)") { found=1 }
        END { exit(found ? 0 : 1) }
    '
}
restart_owned() {
    local srv="$1"
    service_is_abox_managed "$srv" || return 1
    if is_systemd; then systemctl restart "$srv" >/dev/null 2>&1; else rc-service "$srv" restart >/dev/null 2>&1; fi
}
load_state || exit 0
[[ -n "${CORE:-}" ]] || exit 0
desired=RUNNING
if [[ -e "$DESIRED" || -L "$DESIRED" ]]; then
    [[ -r "$DESIRED" && -f "$DESIRED" && ! -L "$DESIRED" ]] || exit 0
    [[ "$(stat -c %u:%g "$DESIRED" 2>/dev/null)" == 0:0 ]] || exit 0
    mode=$(stat -c %a "$DESIRED" 2>/dev/null) || exit 0
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || exit 0
    IFS= read -r desired < "$DESIRED" || exit 0
fi
[[ "$desired" == RUNNING ]] || { rm -f "$STATE"; exit 0; }
IPT=$(command -v iptables || echo /sbin/iptables)
IPT6=$(command -v ip6tables || echo /sbin/ip6tables)
has_ipv6() { ip -6 addr show scope global 2>/dev/null | awk '/inet6/ { found=1 } END { exit !found }' || ip -6 route show default 2>/dev/null | awk '/^default/ { found=1 } END { exit !found }'; }
ipv6_nat_redirect_usable() { command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -t nat -L PREROUTING >/dev/null 2>&1; }
case "$CORE" in xray) MAIN_SRV=xray;; singbox) MAIN_SRV=sing-box;; hysteria) MAIN_SRV=hysteria;; *) exit 0;; esac
failed_srv=''
service_active_owned "$MAIN_SRV" || failed_srv="$MAIN_SRV"
MAIN_PID=${SERVICE_PID:-}
HY2_SRV="$MAIN_SRV"; HY2_PID="$MAIN_PID"
if [[ "$CORE" == xray && "$MODE" == *ALL* ]]; then
    if [[ -z "$failed_srv" ]]; then service_active_owned hysteria || failed_srv=hysteria; fi
    HY2_SRV=hysteria; HY2_PID=${SERVICE_PID:-}
fi
if [[ -z "$failed_srv" && "${HY2_HOP:-}" == true && "${HY2_HOP_IMPL:-}" == manual && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" && -n "${INGRESS_IF:-}" ]]; then
    redirect_port="${HY2_MONITOR_PORT:-${HY2_RANGE_START}}"
    $IPT -w -t nat -C PREROUTING -i "$INGRESS_IF" -p udp --dport "${HY2_RANGE_START}:${HY2_RANGE_END}" -m comment --comment A-Box-HY2-HOP -j REDIRECT --to-ports "$redirect_port" 2>/dev/null || failed_srv="$HY2_SRV"
    if has_ipv6 && ipv6_nat_redirect_usable; then
        $IPT6 -w -t nat -C PREROUTING -i "$INGRESS_IF" -p udp --dport "${HY2_RANGE_START}:${HY2_RANGE_END}" -m comment --comment A-Box-HY2-HOP -j REDIRECT --to-ports "$redirect_port" 2>/dev/null || failed_srv="$HY2_SRV"
    fi
fi
[[ -n "$failed_srv" || -z "${VLESS_PORT:-}" ]] || socket_owned_by_pid tcp "$VLESS_PORT" "$MAIN_PID" || failed_srv="$MAIN_SRV"
[[ -n "$failed_srv" || -z "${XHTTP_PORT:-}" ]] || socket_owned_by_pid tcp "$XHTTP_PORT" "$MAIN_PID" || failed_srv="$MAIN_SRV"
[[ -n "$failed_srv" || -z "${HY2_MONITOR_PORT:-}" ]] || socket_owned_by_pid udp "$HY2_MONITOR_PORT" "$HY2_PID" || failed_srv="$HY2_SRV"
[[ -n "$failed_srv" || -z "${SS_PORT:-}" ]] || { socket_owned_by_pid tcp "$SS_PORT" "$MAIN_PID" && socket_owned_by_pid udp "$SS_PORT" "$MAIN_PID"; } || failed_srv="$MAIN_SRV"
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
    chmod 700 "$ABOX_DIR/socket_probe.sh" || die '健康探针权限设置失败。'
    install_abox_cron_block PROBE '* * * * * /usr/bin/flock -n /run/A-Box-probe-cron.lock /bin/bash /etc/ddr/socket_probe.sh >/dev/null 2>&1'
}

setup_geo_cron() {
    if ! abox_owns_service xray; then
        remove_abox_cron_block GEO 2>/dev/null || true
        rm -f "$ABOX_DIR/geo_update.sh"
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
exec 8>/run/A-Box.lock || exit 1
flock -n 8 || exit 0
exec 9>/run/A-Box-geo-update.lock || exit 1
flock -n 9 || exit 0
is_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
xray_owned() { local u; if is_systemd; then u=/etc/systemd/system/xray.service; else u=/etc/init.d/xray; fi; [[ -f "$u" && ! -L "$u" ]] && grep -Fxq '# Managed by A-Box' "$u"; }
fetch_one() {
    local asset="$1" out="$2" api release_json asset_json url digest expected actual size
    api="https://api.github.com/repos/${GEO_REPO}/releases/latest"
    release_json=$(curl -fLsS --connect-timeout 10 -m 60 -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2026-03-10' "$api") || return 1
    asset_json=$(jq -c --arg name "$asset" 'first(.assets[]? | select(.name == $name) | {url:.browser_download_url,digest:(.digest // "")}) // empty' <<< "$release_json")
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
desired=RUNNING; [[ -r "$DESIRED" && -f "$DESIRED" && ! -L "$DESIRED" ]] && IFS= read -r desired < "$DESIRED"
[[ "$desired" == RUNNING ]] || exit 0
if is_systemd; then systemctl is-active --quiet xray || exit 0; else rc-service xray status >/dev/null 2>&1 || exit 0; fi
tmpdir=$(mktemp -d /tmp/A-Box-geo.XXXXXX) || exit 1
trap 'rm -rf "$tmpdir"' EXIT
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
EOF_GEO
    chmod 700 "$ABOX_DIR/geo_update.sh" || die 'Geo 更新脚本权限设置失败。'
    install_abox_cron_block GEO '0 3 * * 1 /usr/bin/flock -n /run/A-Box-geo-cron.lock /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1'
}

pre_install_setup() {
    local CORE_IN=$1 MODE_IN=$2
    reset_protocol_vars
    local DEF_V_PORT=443 DEF_X_PORT=8443 DEF_H_PORT=443 DEF_S_PORT=2053
    local INPUT_V_PORT INPUT_X_PORT INPUT_H_PORT INPUT_H_DOMAIN INPUT_H_HOP INPUT_H_DOWN INPUT_H_UP INPUT_H_MASQ INPUT_S_PORT INPUT_SS_WL INPUT_KA ip prompt
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

    msg "\n${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${BOLD}Parameter Wizard [Engine: $CORE_IN | Mode: $MODE_IN]${NC}"
    else
        msg "${BOLD}参数构造向导 [Engine: $CORE_IN | Mode: $MODE_IN]${NC}"
    fi
    msg "${BLUE}----------------------------------------------------------------------${NC}"

    if [[ "$HAS_VISION" == 'true' ]]; then
        VLESS_PORT=$(prompt_port_input "$L_VISION" "$DEF_V_PORT")
        VISION_SNI=$(prompt_reality_sni "$L_VISION" "$VLESS_PORT")
    fi
    if [[ "$HAS_XHTTP" == 'true' ]]; then
        XHTTP_PORT=$(prompt_port_input "$L_XHTTP" "$DEF_X_PORT")
        XHTTP_SNI=$(prompt_reality_sni "$L_XHTTP" "$XHTTP_PORT")
    fi
    VLESS_SNI=${VISION_SNI:-${XHTTP_SNI:-www.microsoft.com}}

    if [[ "$HAS_HY2" == 'true' ]]; then
        HY2_BASE_PORT=$(prompt_port_input "$L_HY2" "$DEF_H_PORT")

        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            if [[ "$CORE_IN" == 'singbox' ]]; then
                read -r -ep "   ${L_HY2} Optional server domain for Sing-box HY2 self-signed certificate/SNI (empty = IP + pinSHA256): " INPUT_H_DOMAIN
            else
                read -r -ep "   ${L_HY2} Do you have a domain already resolved to this server? (empty = self-signed certificate): " INPUT_H_DOMAIN
            fi
        else
            if [[ "$CORE_IN" == 'singbox' ]]; then
                read -r -ep "   ${L_HY2} 可选填写 Sing-box HY2 自签证书/SNI 域名（留空使用 IP + pinSHA256）: " INPUT_H_DOMAIN
            else
                read -r -ep "   ${L_HY2} 是否拥有已解析到本机的域名？(留空使用默认自签证书): " INPUT_H_DOMAIN
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
                        read -r -ep "   ${L_HY2} Use Cloudflare DNS-01 ACME instead of HTTP-01? [Y/N]: " INPUT_ACME_DNS
                    else
                        read -r -ep "   ${L_HY2} 是否使用 Cloudflare DNS-01 申请证书以避免占用 80 端口？[Y/N]: " INPUT_ACME_DNS
                    fi
                    if is_yes "$INPUT_ACME_DNS"; then
                        HY2_ACME_TYPE='dns'
                        HY2_ACME_DNS_PROVIDER='cloudflare'
                        read -r -sep "   ${L_HY2} Cloudflare API Token: " INPUT_CF_TOKEN; echo
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
            read -r -ep "   ${L_HY2} Enable port hopping? [Y/N]: " INPUT_H_HOP
        else
            read -r -ep "   ${L_HY2} 是否开启端口跳跃 (单端口被限速环境建议开启)? [Y/N]: " INPUT_H_HOP
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
                HY2_URI_PORTS="${HY2_BASE_PORT},${HY2_RANGE_START}-${HY2_RANGE_END}"
                HY2_MONITOR_PORT="$HY2_BASE_PORT"
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
            HY2_DOWN=$(prompt_positive_int_input "   ${L_HY2} Downlink Mbps (default: 1000): " 1000)
        else
            HY2_DOWN=$(prompt_positive_int_input "   ${L_HY2} 下行速率(Mbps) (回车默认: 1000): " 1000)
        fi
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            HY2_UP=$(prompt_positive_int_input "   ${L_HY2} Uplink Mbps (default: 100): " 100)
        else
            HY2_UP=$(prompt_positive_int_input "   ${L_HY2} 上行速率(Mbps) (回车默认: 100): " 100)
        fi

        local masq_default="https://${VISION_SNI:-${XHTTP_SNI:-www.samsung.com}}/"
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            HY2_MASQ_URL=$(prompt_https_url "   ${L_HY2} Enter HTTP/3 masquerade URL (default: $masq_default): " "$masq_default")
        else
            HY2_MASQ_URL=$(prompt_https_url "   ${L_HY2} 请输入 HTTP/3 伪装站点 URL (回车默认: $masq_default): " "$masq_default")
        fi
    fi
    if [[ "$HAS_SS" == 'true' ]]; then
        SS_PORT=$(prompt_ss_port_input "$L_SS" "$DEF_S_PORT")
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            read -r -ep "   ${L_SS} Enter frontend whitelist IP/CIDR (empty = open to all, space-separated): " INPUT_SS_WL
        else
            read -r -ep "   ${L_SS} 请输入前置机白名单 IP/CIDR (留空全网开放, 多个用空格分隔): " INPUT_SS_WL
        fi
        SS_WHITELIST_IP="$INPUT_SS_WL"
        if [[ -n "$SS_WHITELIST_IP" ]]; then
            for ip in $SS_WHITELIST_IP; do
                if [[ "$ip" == *:* ]]; then
                    valid_ipv6_cidr "$ip" || die "IPv6 白名单地址非法: $ip"
                else
                    valid_ipv4_cidr "$ip" || die "IPv4 白名单地址非法: $ip"
                fi
            done
        fi
    fi

    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        read -r -ep "   ${L_GLOBAL} Enable TCP KeepAlive 45s to prevent NAT idle disconnect? [Y/N]: " INPUT_KA
    else
        read -r -ep "   ${L_GLOBAL} 是否开启 TCP KeepAlive (45s) 防治 NAT 空闲断连? [Y/N]: " INPUT_KA
    fi
    is_yes "$INPUT_KA" && ENABLE_KEEPALIVE='true' || ENABLE_KEEPALIVE='false'
    msg "${CYAN}======================================================================${NC}\n"

    check_selected_ports_free
    if [[ "$HAS_HY2" == 'true' && -n "${HY2_DOMAIN:-}" && "${HY2_ACME_TYPE:-http}" == 'http' && ( "$CORE_IN" == 'hysteria' || ( "$CORE_IN" == 'xray' && "$MODE_IN" == *'ALL'* ) ) ]]; then
        holder=$(ss -H -n -l -p -A tcp 2>/dev/null | grep -E '[:.]80\b' || true)
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] ACME HTTP-01 需要 80/tcp，但该端口仍被进程占用：${NC}"
            echo "$holder"
            die '请先释放 80/tcp，或改用 Cloudflare DNS-01 ACME 后再部署 HY2 域名证书。'
        fi
    fi

    [[ "$HAS_VISION" == 'true' ]] && allowPort "$VLESS_PORT" tcp
    [[ "$HAS_XHTTP" == 'true' ]] && allowPort "$XHTTP_PORT" tcp
    if [[ "$HAS_HY2" == 'true' ]]; then
        if [[ -n "$HY2_DOMAIN" && "${HY2_ACME_TYPE:-http}" == 'http' && ( "$CORE_IN" == 'hysteria' || ( "$CORE_IN" == 'xray' && "$MODE_IN" == *'ALL'* ) ) ]]; then
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
        if [[ -n "${SS_WHITELIST_IP:-}" ]]; then
            remove_ss_open_accept_rules || die '旧的 SS 全网 ACCEPT 规则无法完整删除；拒绝启用白名单模式。'
            for ip in $SS_WHITELIST_IP; do
                for proto in tcp udp; do
                    if [[ "$ip" == *:* ]]; then
                        if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                            if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT 2>/dev/null; then
                                $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则写入失败: $ip/$proto"
                            fi
                        fi
                    else
                        if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT 2>/dev/null; then
                            $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则写入失败: $ip/$proto"
                        fi
                    fi
                done
            done
            for proto in tcp udp; do
                if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP 2>/dev/null; then
                    $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto"
                fi
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP 2>/dev/null; then
                        $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto"
                    fi
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
    local mode="$1" sockopt_json inbounds_json out tmp_out listen_addr
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
            streamSettings:({network:"tcp", security:"reality", realitySettings:{target:($v_sni + ":443"), serverNames:[$v_sni], privateKey:$pk, shortIds:[$sid]}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def xhttp:
          {
            listen:$listen_addr, port:$xport, protocol:"vless",
            settings:{clients:[{id:$uuid}], decryption:"none"},
            streamSettings:({network:"xhttp", security:"reality", xhttpSettings:{mode:"auto", path:"/xhttp"}, realitySettings:{target:($x_sni + ":443"), serverNames:[$x_sni], privateKey:$pk, shortIds:[$sid]}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def ss:
          ({listen:$listen_addr, port:$ssport, protocol:"shadowsocks", settings:{method:"2022-blake3-aes-128-gcm", password:$ss_pass, network:"tcp,udp"}}
           + (if $sock == null then {} else {streamSettings:{sockopt:$sock}} end));
        []
        | if ($mode|contains("VISION")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [vision] else . end
        | if ($mode|contains("XHTTP")) or ($mode|contains("ALL")) then . + [xhttp] else . end
        | if ($mode|contains("SS")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [ss] else . end
    ')
    out="${XRAY_CONFIG_PATH:-/usr/local/etc/xray/config.json}"
    tmp_out="${out}.tmp.$$"
    mkdir -p "$(dirname "$out")"
    jq -n --argjson inbounds "$inbounds_json" '{
        log:{loglevel:"warning", access:"/var/log/A-Box-xray-access.log", error:"/var/log/A-Box-xray-error.log"},
        routing:{domainStrategy:"IPIfNonMatch", rules:[
            {type:"field", protocol:["bittorrent"], outboundTag:"block"},
            {type:"field", domain:["geosite:category-ads-all"], outboundTag:"block"}
        ]},
        inbounds:$inbounds,
        outbounds:[{protocol:"freedom", tag:"direct"}, {protocol:"blackhole", tag:"block"}]
    }' > "$tmp_out" || { rm -f "$tmp_out"; die 'Xray JSON 生成失败。'; }
    mv -f "$tmp_out" "$out"
}

build_singbox_config() {
    local mode="$1" inbounds_json ka_obj cert_cn='localhost' out tmp_out listen_addr
    listen_addr=$(wildcard_listen_address)
    [[ -n "${HY2_DOMAIN:-}" ]] && cert_cn="$HY2_DOMAIN"
    if [[ "${ENABLE_KEEPALIVE:-}" == true ]]; then ka_obj='{"tcp_keep_alive":"45s","tcp_keep_alive_interval":"45s"}'; else ka_obj='{}'; fi
    inbounds_json=$(jq -n \
        --arg mode "$mode" --arg uuid "$UUID" --arg listen_addr "$listen_addr" \
        --arg v_sni "${VISION_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg x_sni "${XHTTP_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg pk "$PK" --arg sid "$SHORT_ID" \
        --argjson vport "${VLESS_PORT:-443}" --argjson hy2port "${HY2_BASE_PORT:-443}" --argjson ssport "${SS_PORT:-2053}" \
        --argjson hy2up "${HY2_UP:-100}" --argjson hy2down "${HY2_DOWN:-1000}" \
        --arg hy2pass "${HY2_PASS:-}" --arg hy2obfs "${HY2_OBFS:-}" --arg cert_cn "$cert_cn" \
        --arg masq "${HY2_MASQ_URL:-https://www.samsung.com/}" --arg ss_pass "${SS_PASS:-}" --argjson ka "$ka_obj" '
        def vision:
          ({type:"vless", listen:$listen_addr, listen_port:$vport, tcp_fast_open:true,
            users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
            tls:{enabled:true, server_name:$v_sni, reality:{enabled:true, handshake:{server:$v_sni, server_port:443}, private_key:$pk, short_id:[$sid]}}} + $ka);
        def hy2:
          {type:"hysteria2", listen:$listen_addr, listen_port:$hy2port, up_mbps:$hy2up, down_mbps:$hy2down,
            obfs:{type:"salamander", password:$hy2obfs}, users:[{password:$hy2pass}],
            tls:{enabled:true, server_name:$cert_cn, certificate_path:"/etc/sing-box/hy2.crt", key_path:"/etc/sing-box/hy2.key"}, masquerade:$masq};
        def ss:
          ({type:"shadowsocks", listen:$listen_addr, listen_port:$ssport, tcp_fast_open:true,
            method:"2022-blake3-aes-128-gcm", password:$ss_pass} + $ka);
        []
        | if ($mode|contains("VISION")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [vision] else . end
        | if ($mode|contains("HY2")) or ($mode|contains("ALL")) then . + [hy2] else . end
        | if ($mode|contains("SS")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [ss] else . end')
    out="${SINGBOX_CONFIG_PATH:-/etc/sing-box/config.json}"
    tmp_out="${out}.tmp.$$"
    mkdir -p "$(dirname "$out")"
    jq -n --argjson inbounds "$inbounds_json" '{
        log:{level:"warn", output:"/var/log/A-Box-singbox.log"},
        route:{rules:[{action:"sniff"},{protocol:"bittorrent", action:"reject"}], auto_detect_interface:true},
        inbounds:$inbounds,
        outbounds:[{type:"direct", tag:"direct"}]
    }' > "$tmp_out" || { rm -f "$tmp_out"; die 'Sing-box JSON 生成失败。'; }
    mv -f "$tmp_out" "$out"
}

generate_self_signed_cert_atomically() {
    local key="$1" cert="$2" cn="$3" dir tmp key_tmp cert_tmp pub1 pub2 key_bak='' cert_bak='' committed_key=0
    dir=$(dirname "$key")
    [[ "$dir" == "$(dirname "$cert")" ]] || return 1
    install -d -m 700 "$dir" || return 1
    [[ ! -L "$key" && ! -L "$cert" ]] || return 1
    tmp=$(mktemp -d "$dir/.A-Box-cert.XXXXXX") || return 1
    key_tmp="$tmp/key.pem"; cert_tmp="$tmp/cert.pem"
    openssl ecparam -genkey -name prime256v1 -out "$key_tmp" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    openssl req -new -x509 -days 36500 -key "$key_tmp" -out "$cert_tmp" -subj "/CN=${cn}" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    openssl x509 -in "$cert_tmp" -noout >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    pub1=$(openssl pkey -in "$key_tmp" -pubout -outform der 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    pub2=$(openssl x509 -in "$cert_tmp" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    [[ -n "$pub1" && "$pub1" == "$pub2" ]] || { rm -rf "$tmp"; return 1; }
    chmod 600 "$key_tmp" "$cert_tmp" || { rm -rf "$tmp"; return 1; }

    if [[ -e "$key" ]]; then key_bak="$tmp/key.old"; cp -a -- "$key" "$key_bak" || { rm -rf "$tmp"; return 1; }; fi
    if [[ -e "$cert" ]]; then cert_bak="$tmp/cert.old"; cp -a -- "$cert" "$cert_bak" || { rm -rf "$tmp"; return 1; }; fi
    mv -f -- "$key_tmp" "$key" || { rm -rf "$tmp"; return 1; }
    committed_key=1
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
    local out="$1" tls_config="$2" listen_spec="$3" tmp pass_yaml obfs_yaml masq_yaml
    [[ -n "$out" && -n "$listen_spec" ]] || return 1
    [[ ! -L "$(dirname "$out")" && ! -L "$out" ]] || return 1
    install -d -m 700 "$(dirname "$out")" || return 1
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
bandwidth:
  up: ${HY2_UP} mbps
  down: ${HY2_DOWN} mbps
masquerade:
  type: proxy
  proxy:
    url: ${masq_yaml}
    rewriteHost: true
EOF_HY2
    chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -f -- "$tmp" "$out" || { rm -f -- "$tmp"; return 1; }
    [[ -s "$out" && ! -L "$out" ]]
}

deploy_official_hy2() {
    local IS_SILENT=${1:-NORMAL} TLS_CONFIG HY2_LISTEN cert_cn HY2_CAPS='CAP_NET_BIND_SERVICE' hy2_tmp hy2_bin domain_yaml token_yaml
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        clear; msg "${BOLD}${GREEN}部署官方 Hysteria 2${NC}"
        init_system_environment
        load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
    hy2_bin="$hy2_tmp/hysteria_core"
    fetch_github_release apernet/hysteria hysteria_core "$hy2_bin"
    chmod 755 "$hy2_bin" || die 'Hysteria staged binary chmod failed.'
    "$hy2_bin" version >/dev/null 2>&1 || die 'Hysteria staged binary execution check failed.'
    install_binary_atomically "$hy2_bin" /usr/local/bin/hysteria || die 'Hysteria binary atomic install failed.'
    rm -rf "$hy2_tmp"
    /usr/local/bin/hysteria version >/dev/null 2>&1 || die 'Hysteria 执行校验失败。'

    HY2_PASS=$(rand_alnum 20)
    HY2_OBFS=$(rand_alnum 16)
    mkdir -p /etc/hysteria

    if [[ -n "${HY2_DOMAIN:-}" ]]; then
        if [[ "${HY2_ACME_TYPE:-http}" == 'dns' ]]; then
            [[ "${HY2_ACME_DNS_PROVIDER:-}" == 'cloudflare' ]] || die '当前仅内置支持 Cloudflare DNS-01 ACME。'
            valid_single_line_secret "${HY2_ACME_DNS_CF_API_TOKEN:-}" 512 || die 'Cloudflare DNS-01 ACME Token 为空、过长或包含换行。'
            domain_yaml=$(json_escape "$HY2_DOMAIN")
            token_yaml=$(json_escape "$HY2_ACME_DNS_CF_API_TOKEN")
            TLS_CONFIG="acme:
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

    build_hysteria_config /etc/hysteria/config.yaml "$TLS_CONFIG" "$HY2_LISTEN" || die 'Hysteria 配置原子生成失败。'

    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        write_file_atomically_from_stdin /etc/systemd/system/hysteria.service 644 <<EOF_SVC || die 'Hysteria systemd unit 原子写入失败。'
# Managed by A-Box
[Unit]
Description=A-Box Hysteria 2 Service
After=network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=${HY2_CAPS}
AmbientCapabilities=${HY2_CAPS}
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
        mkdir -p /etc/conf.d
        write_file_atomically_from_stdin /etc/conf.d/hysteria 644 <<'EOF_HY2_CONFD' || die 'Hysteria OpenRC conf.d 原子写入失败。'
rc_ulimit="-n 1048576"
EOF_HY2_CONFD
        write_file_atomically_from_stdin /etc/init.d/hysteria 755 <<'EOF_SVC' || die 'Hysteria OpenRC unit 原子写入失败。'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Hysteria 2 Service"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria/config.yaml"
command_background="yes"
output_log="/var/log/A-Box-hysteria.log"
error_log="/var/log/A-Box-hysteria.log"
pidfile="/run/hysteria.pid"
depend() { need net; }
EOF_SVC
        chmod +x /etc/init.d/hysteria
    fi
    service_manager start hysteria
    setup_active_defense
    setup_health_monitor
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        write_env hysteria HY2
        prune_owned_core_families_except hysteria
        setup_geo_cron
        commit_deployment_transaction
        view_config deploy
    fi
}

install_file_atomically() {
    local src="$1" dest="$2" mode="${3:-600}" staged dir
    [[ -f "$src" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    dir=$(dirname "$dest")
    install -d -m 755 "$dir" || return 1
    staged=$(mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    command install -m "$mode" "$src" "$staged" || { rm -f -- "$staged"; return 1; }
    sync -f "$staged" 2>/dev/null || true
    mv -f -- "$staged" "$dest" || { rm -f -- "$staged"; return 1; }
    sync -f "$dir" 2>/dev/null || true
}

install_binary_atomically() { install_file_atomically "$1" "$2" 755; }

rollback_binary_install() {
    local bin="$1" backup="${2:-}"
    if [[ -n "$backup" && -f "$backup" ]]; then install_binary_atomically "$backup" "$bin"; else rm -f -- "$bin"; fi
}

remove_core_family_force() {
    local srv="$1" path
    while IFS= read -r path; do rm -rf -- "$path"; done < <(core_family_paths "$srv")
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

deployment_transaction_rollback() {
    [[ "${ABOX_DEPLOY_TX_ACTIVE:-0}" == 1 ]] || return 0
    local targets="${ABOX_DEPLOY_TX_TARGETS:-}" reason="${ABOX_DEPLOY_TX_REASON:-deployment}" backup="${ABOX_DEPLOY_TX_BACKUP:-}" tx_tmp="${ABOX_DEPLOY_TX_TMP:-}" srv
    [[ -n "${1:-}" ]] && reason="${reason}; $1"
    ABOX_DEPLOY_TX_ACTIVE=0
    ABOX_DEPLOY_TX_TARGETS=''
    ABOX_DEPLOY_TX_REASON=''
    ABOX_DEPLOY_TX_BACKUP=''
    ABOX_DEPLOY_TX_TMP=''
    ABOX_DIE_HOOK=''
    msg "${YELLOW}[!] ${reason} failed; restoring the exact pre-operation snapshot.${NC}"
    stop_all_managed_services >/dev/null 2>&1 || true
    clean_nat_rules >/dev/null 2>&1 || true
    clean_input_rules >/dev/null 2>&1 || true
    remove_native_firewall_rules >/dev/null 2>&1 || true
    for srv in $targets; do remove_core_family_force "$srv"; done
    restore_latest_backup_silent "$ABOX_DIR/backups" "$backup" || msg "${RED}[!] Automatic rollback could not restore the exact pre-operation backup: ${backup:-missing}${NC}"
    [[ -n "$tx_tmp" ]] && rm -rf -- "$tx_tmp"
}

begin_deployment_transaction() {
    local reason="$1"; shift
    [[ "${ABOX_DEPLOY_TX_ACTIVE:-0}" == 1 ]] && return 0
    ABOX_LAST_BACKUP=''
    auto_backup_silent "$reason" "$ABOX_DIR/backups"
    [[ -n "$ABOX_LAST_BACKUP" && -f "$ABOX_LAST_BACKUP" ]] || die '无法确认部署前备份文件。'
    ABOX_DEPLOY_TX_ACTIVE=1
    ABOX_DEPLOY_TX_REASON="$reason"
    ABOX_DEPLOY_TX_TARGETS="$*"
    ABOX_DEPLOY_TX_BACKUP="$ABOX_LAST_BACKUP"
    ABOX_DIE_HOOK=deployment_transaction_rollback
    install_deployment_transaction_traps
}

commit_deployment_transaction() {
    ABOX_DEPLOY_TX_ACTIVE=0
    ABOX_DEPLOY_TX_TARGETS=''
    ABOX_DEPLOY_TX_REASON=''
    ABOX_DEPLOY_TX_BACKUP=''
    ABOX_DEPLOY_TX_TMP=''
    ABOX_DIE_HOOK=''
    restore_deployment_transaction_traps
}

deploy_xray() {
    local MODE_IN=$1 KEYPAIR PK_LOCAL
    clear; msg "${BOLD}${GREEN}部署 Xray-core [$MODE_IN]${NC}"
    init_system_environment
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
    xray_zip="$xray_tmp/xray_core.zip"
    xray_ext="$xray_tmp/xray_ext"
    mkdir -p "$xray_ext"
    fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
    extract_zip_member_safely "$xray_zip" xray "$xray_ext/xray" || die 'Xray 压缩包安全提取失败。'
    [[ -f "$xray_ext/xray" && ! -L "$xray_ext/xray" ]] || die '安全提取后未找到 xray 主程序。'
    chmod 755 "$xray_ext/xray" || die 'Xray staged binary chmod failed.'
    "$xray_ext/xray" version >/dev/null 2>&1 || die 'Xray staged binary execution check failed.'
    install_binary_atomically "$xray_ext/xray" /usr/local/bin/xray || die 'Xray binary atomic install failed.'
    /usr/local/bin/xray version >/dev/null 2>&1 || die 'Xray 执行校验失败。'
    mkdir -p /usr/local/share/xray /usr/local/etc/xray

    geo_tmp="$xray_tmp/geo"
    mkdir -p "$geo_tmp"
    fetch_geo_data geoip.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat' "$geo_tmp/geoip.dat"
    fetch_geo_data geosite.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat' "$geo_tmp/geosite.dat"
    install_file_atomically "$geo_tmp/geoip.dat" /usr/local/share/xray/geoip.dat 644 || die 'geoip.dat 原子安装失败。'
    install_file_atomically "$geo_tmp/geosite.dat" /usr/local/share/xray/geosite.dat 644 || die 'geosite.dat 原子安装失败。'
    rm -rf "$xray_tmp"

    KEYPAIR=$(/usr/local/bin/xray x25519)
    PK=$(awk '/Private/{print $NF}' <<< "$KEYPAIR")
    PBK=$(awk '/Public/{print $NF}' <<< "$KEYPAIR")
    [[ -n "$PK" && -n "$PBK" ]] || die 'Xray REALITY 密钥生成失败。'
    UUID=$(generate_robust_uuid)
    SHORT_ID=$(openssl rand -hex 4 | tr -d '\n\r')
    SS_PASS=$(openssl rand -base64 16 | tr -d '\n\r')
    [[ -n "$SS_PASS" ]] || die 'SS-2022 密钥生成失败。'

    build_xray_config "$MODE_IN"
    chmod 600 /usr/local/etc/xray/config.json
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
        mkdir -p /etc/conf.d
        write_file_atomically_from_stdin /etc/conf.d/xray 644 <<'EOF_XRAY_CONFD' || die 'Xray OpenRC conf.d 原子写入失败。'
rc_ulimit="-n 1048576"
XRAY_LOCATION_ASSET="/usr/local/share/xray"
EOF_XRAY_CONFD
        write_file_atomically_from_stdin /etc/init.d/xray 755 <<'EOF_SVC' || die 'Xray OpenRC unit 原子写入失败。'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Xray Service"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background="yes"
pidfile="/run/xray.pid"
depend() { need net; }
EOF_SVC
        chmod +x /etc/init.d/xray
    fi
    service_manager start xray
    setup_geo_cron
    setup_active_defense
    setup_health_monitor

    if [[ "$MODE_IN" == *'ALL'* ]]; then
        deploy_official_hy2 SILENT || die 'HY2 deployment failed during Xray ALL.'
    fi
    write_env xray "$MODE_IN"
    if [[ "$MODE_IN" == *ALL* ]]; then prune_owned_core_families_except xray hysteria; else prune_owned_core_families_except xray; fi
    commit_deployment_transaction
    view_config deploy
}

deploy_singbox() {
    local MODE_IN=$1 KEYPAIR SB_PATH cert_cn='localhost' SB_PRE_START='' SB_POST_STOP='' SB_RC_PRE='' SB_RC_POST='' SB_CAPS='CAP_NET_BIND_SERVICE'
    clear; msg "${BOLD}${GREEN}部署 Sing-box 核心 [$MODE_IN]${NC}"
    init_system_environment
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
    sb_tar="$sb_tmp/singbox_core.tar.gz"
    sb_ext="$sb_tmp/extract"
    mkdir -p "$sb_ext"
    fetch_github_release SagerNet/sing-box singbox_core.tar.gz "$sb_tar"
    SB_PATH="$sb_ext/sing-box"
    extract_tar_regular_basename_safely "$sb_tar" sing-box "$SB_PATH" || die 'Sing-box 压缩包安全提取失败。'
    [[ -f "$SB_PATH" && ! -L "$SB_PATH" ]] || die '安全提取后未找到 sing-box 主程序。'
    chmod 755 "$SB_PATH" || die 'Sing-box staged binary chmod failed.'
    "$SB_PATH" version >/dev/null 2>&1 || die 'Sing-box staged binary execution check failed.'
    install_binary_atomically "$SB_PATH" /usr/local/bin/sing-box || die 'Sing-box binary atomic install failed.'
    rm -rf "$sb_tmp"
    /usr/local/bin/sing-box version >/dev/null 2>&1 || die 'Sing-box 执行校验失败。'

    mkdir -p /etc/sing-box
    chmod 700 /etc/sing-box
    KEYPAIR=$(/usr/local/bin/sing-box generate reality-keypair)
    PK=$(awk '/Private/{print $NF}' <<< "$KEYPAIR")
    PBK=$(awk '/Public/{print $NF}' <<< "$KEYPAIR")
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
    chmod 600 /etc/sing-box/config.json
    jq empty /etc/sing-box/config.json >/dev/null 2>&1 || die 'Sing-box JSON 格式非法。'
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || die 'Sing-box 配置校验失败。'

    if [[ "$MODE_IN" == *'HY2'* || "$MODE_IN" == *'ALL'* ]] && [[ "${HY2_HOP:-}" == 'true' ]]; then
        SB_CAPS='CAP_NET_ADMIN CAP_NET_BIND_SERVICE'
        SB_PRE_START="ExecStartPre=-/bin/sh -c '$IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'
ExecStartPre=/bin/sh -c '$IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT'"
        SB_POST_STOP="ExecStopPost=-/bin/sh -c '$IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
        SB_RC_PRE="start_pre() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true
  $IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT || return 1"
        SB_RC_POST="stop_post() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
        if has_ipv6 && ipv6_nat_redirect_usable; then
            SB_PRE_START+="
ExecStartPre=-/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'
ExecStartPre=/bin/sh -c '$IPT6 -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT'"
            SB_POST_STOP+="
ExecStopPost=-/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
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
        mkdir -p /etc/conf.d
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
pidfile="/run/sing-box.pid"
depend() { need net; }
$SB_RC_PRE
$SB_RC_POST
EOF_SVC
        chmod +x /etc/init.d/sing-box
    fi
    service_manager start sing-box
    setup_active_defense
    setup_health_monitor
    write_env singbox "$MODE_IN"
    prune_owned_core_families_except sing-box
    setup_geo_cron
    commit_deployment_transaction
    view_config deploy
}

get_month_total_bytes() {
    local iface="$1" mode="${2:-total}" json rx tx line
    if command -v jq >/dev/null 2>&1 && json=$(vnstat -i "$iface" --json m 1 2>/dev/null); then
        rx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .rx) // empty' <<< "$json" 2>/dev/null)
        tx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .tx) // empty' <<< "$json" 2>/dev/null)
        if [[ "$rx" =~ ^[0-9]+$ && "$tx" =~ ^[0-9]+$ ]]; then
            case "$mode" in rx) printf '%s\n' "$rx" ;; tx) printf '%s\n' "$tx" ;; total) printf '%s\n' "$((rx+tx))" ;; *) return 1 ;; esac
            return 0
        fi
    fi
    line=$(vnstat -i "$iface" --oneline b 2>/dev/null) || return 1
    case "$mode" in rx) awk -F';' '{print $9}' <<< "$line" ;; tx) awk -F';' '{print $10}' <<< "$line" ;; total) awk -F';' '{print $11}' <<< "$line" ;; *) return 1 ;; esac
}

bytes_to_gb() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'; }

setup_traffic_monitor() {
    install -d -m 700 "$ABOX_DIR" || die '无法创建流量监控目录。'
    write_file_atomically_from_stdin "$ABOX_DIR/traffic_monitor.sh" 700 <<'EOF_TRAFFIC' || die '流量监控脚本原子写入失败。'
#!/usr/bin/env bash
# Managed by A-Box
set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
ENV=/etc/ddr/.env
DESIRED=/etc/ddr/.desired_state
BLOCK_STATE=/etc/ddr/.traffic-block-state
exec 8>/run/A-Box.lock || exit 1
flock -n 8 || exit 0
exec 9>/run/A-Box-traffic-monitor.lock || exit 1
flock -n 9 || exit 0
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
    if ! python3 /dev/fd/3 "$ENV" > "$parsed" 3<<'PY_HELPER_ENV'; then
import shlex
import sys
allowed = {"CORE", "MODE", "VLESS_PORT", "XHTTP_PORT", "HY2_MONITOR_PORT", "HY2_HOP", "HY2_HOP_IMPL", "HY2_RANGE_START", "HY2_RANGE_END", "SS_PORT", "TRAFFIC_LIMIT_GB", "TRAFFIC_LIMIT_MODE"}
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
    local dest="$1" value="$2" tmp
    [[ ! -L "$dest" ]] || return 1
    tmp=$(umask 077; mktemp "${dest}.A-Box-new.XXXXXX") || return 1
    printf '%s\n' "$value" > "$tmp" && chown root:root "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}
read_desired() {
    local state=RUNNING mode
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
    local period mode
    [[ -r "$BLOCK_STATE" && -f "$BLOCK_STATE" && ! -L "$BLOCK_STATE" ]] || return 1
    [[ "$(stat -c %u:%g "$BLOCK_STATE" 2>/dev/null)" == 0:0 ]] || return 1
    mode=$(stat -c %a "$BLOCK_STATE" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#077) == 0 )) || return 1
    IFS= read -r period < "$BLOCK_STATE" || return 1
    [[ "$period" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || return 1
    printf '%s\n' "$period"
}
month_bytes() {
    local i="$1" mode="${2:-total}" json rx tx line
    if command -v jq >/dev/null 2>&1 && json=$(vnstat -i "$i" --json m 1 2>/dev/null); then
        rx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .rx) // empty' <<< "$json" 2>/dev/null)
        tx=$(jq -r '([.interfaces[0].traffic.month[]?, .interfaces[0].traffic.months[]?] | last | .tx) // empty' <<< "$json" 2>/dev/null)
        if [[ "$rx" =~ ^[0-9]+$ && "$tx" =~ ^[0-9]+$ ]]; then case "$mode" in rx) echo "$rx";; tx) echo "$tx";; total) echo $((rx+tx));; *) return 1;; esac; return 0; fi
    fi
    line=$(vnstat -i "$i" --oneline b 2>/dev/null) || return 1
    case "$mode" in rx) awk -F';' '{print $9}' <<< "$line";; tx) awk -F';' '{print $10}' <<< "$line";; total) awk -F';' '{print $11}' <<< "$line";; *) return 1;; esac
}
is_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
owned() { local srv="$1" u; if is_systemd; then u="/etc/systemd/system/${srv}.service"; else u="/etc/init.d/${srv}"; fi; [[ -f "$u" && ! -L "$u" ]] && grep -Fxq '# Managed by A-Box' "$u"; }
stop_owned() {
    local srv="$1"
    owned "$srv" || return 0
    if is_systemd; then systemctl stop "$srv" >/dev/null 2>&1 || return 1; systemctl is-active --quiet "$srv" && return 1
    else rc-service "$srv" stop >/dev/null 2>&1 || return 1; rc-service "$srv" status >/dev/null 2>&1 && return 1; fi
}
start_owned() {
    local srv="$1"
    owned "$srv" || return 0
    if is_systemd; then systemctl enable "$srv" >/dev/null 2>&1 || return 1; systemctl restart "$srv" >/dev/null 2>&1 || return 1; systemctl is-active --quiet "$srv"
    else rc-update add "$srv" default >/dev/null 2>&1 || return 1; rc-service "$srv" restart >/dev/null 2>&1 || return 1; rc-service "$srv" status >/dev/null 2>&1; fi
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
traffic_error() { umask 077; printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >> /var/log/A-Box-traffic.log 2>/dev/null || true; }
load_state || exit 0
[[ "${TRAFFIC_LIMIT_GB:-}" =~ ^[1-9][0-9]*$ ]] || exit 0
desired=$(read_desired) || exit 1
current_period=$(date +%Y-%m)
blocked_period=$(read_block_period 2>/dev/null || true)
if [[ "$desired" == TRAFFIC_BLOCKED && -z "$blocked_period" ]]; then
    write_private_line "$BLOCK_STATE" "$current_period" || exit 1
    blocked_period="$current_period"
    traffic_error "migrated legacy traffic-blocked state into billing period ${current_period}"
fi
if [[ "$desired" == TRAFFIC_BLOCKED && "$blocked_period" != "$current_period" ]]; then
    write_private_line "$DESIRED" MAINTENANCE || exit 1
    if ! for_expected_services start_owned; then
        for_expected_services stop_owned >/dev/null 2>&1 || true
        write_private_line "$DESIRED" TRAFFIC_BLOCKED || true
        traffic_error 'monthly quota period rolled over but at least one owned service could not be started; block remains active'
        exit 1
    fi
    if ! write_private_line "$DESIRED" RUNNING || ! rm -f -- "$BLOCK_STATE"; then
        for_expected_services stop_owned >/dev/null 2>&1 || true
        write_private_line "$BLOCK_STATE" "$blocked_period" || true
        write_private_line "$DESIRED" TRAFFIC_BLOCKED || true
        traffic_error 'monthly quota rollover state commit failed; managed services were stopped and block restored'
        exit 1
    fi
    desired=RUNNING
    traffic_error "monthly quota period rolled over from ${blocked_period} to ${current_period}; managed services resumed"
fi
[[ "$desired" == MANUAL_STOPPED || "$desired" == MAINTENANCE ]] && exit 0
iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[[ -n "$iface" ]] || iface=$(ip -o route show to default 2>/dev/null | awk '{print $5; exit}')
[[ -n "$iface" ]] || exit 0
used=$(month_bytes "$iface" "${TRAFFIC_LIMIT_MODE:-total}") || exit 0
limit=$(awk -v g="$TRAFFIC_LIMIT_GB" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
[[ "$used" =~ ^[0-9]+$ && "$limit" =~ ^[0-9]+$ ]] || exit 0
if (( used >= limit )); then
    write_private_line "$BLOCK_STATE" "$current_period" || exit 1
    write_private_line "$DESIRED" TRAFFIC_BLOCKED || exit 1
    for_expected_services stop_owned || { traffic_error 'traffic limit reached but at least one owned service could not be stopped'; exit 1; }
elif [[ "$desired" == TRAFFIC_BLOCKED ]]; then
    # Same-period blocks remain fail-closed even if vnStat later reports a lower value.
    for_expected_services stop_owned || { traffic_error 'traffic-blocked state could not be fully enforced'; exit 1; }
fi
EOF_TRAFFIC
    chmod 700 "$ABOX_DIR/traffic_monitor.sh"
    install_abox_cron_block TRAFFIC '* * * * * /bin/bash /etc/ddr/traffic_monitor.sh >/dev/null 2>&1'
}

disable_traffic_monitor() {
    remove_abox_cron_block TRAFFIC
    rm -f "$ABOX_DIR/traffic_monitor.sh" "$ABOX_TRAFFIC_BLOCK_STATE"
}

traffic_management_menu() {
    clear
    local INTERFACE USED_BYTES USED_GB limit_gb mode_choice
    INTERFACE=$(get_active_interface)
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}每月流量管控限制 / Monthly Traffic Management Limit${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}[网卡 ${INTERFACE} 当前月流量统计]${NC}"
    if command -v vnstat >/dev/null 2>&1; then
        vnstat -i "$INTERFACE" -m 2>/dev/null | awk 'NF && NR <= 8 { print; shown=1 } END { exit !shown }' || msg "${YELLOW}暂无本月统计数据，vnstat 正在收集中。${NC}"
    fi
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
    if [[ -n "${TRAFFIC_LIMIT_GB:-}" ]]; then
        msg "当前设定: ${GREEN}${TRAFFIC_LIMIT_GB} GB${NC} | 模式: ${TRAFFIC_LIMIT_MODE:-total}"
    else
        msg "当前设定: ${RED}未开启${NC}"
    fi
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}1. 设定/修改每月流量上限${NC}"
    msg "${YELLOW}2. 解除流量限制${NC}"
    msg "${GREEN}0. 返回主菜单${NC}"
    read -r -ep '请选择 [0-2]: ' tr_choice
    case "$tr_choice" in
        1)
            read -r -ep '请输入每月流量上限(GB)，纯数字: ' limit_gb
            valid_positive_int "$limit_gb" || { msg "${RED}[!] 输入无效。${NC}"; pause_return; return; }
            read -r -ep '计量模式 total/rx/tx (回车默认 total): ' mode_choice
            mode_choice=${mode_choice:-total}
            [[ "$mode_choice" =~ ^(total|rx|tx)$ ]] || { msg "${RED}[!] 计量模式无效。${NC}"; pause_return; return; }
            update_traffic_state_atomically "$limit_gb" "$mode_choice" || die '流量限制状态原子提交失败。'
            clear_traffic_block_period || die '旧流量封禁周期清理失败。'
            set_desired_state RUNNING || die '服务期望状态写入失败。'
            setup_traffic_monitor
            msg "${GREEN}流量限制已设定为 ${limit_gb} GB，模式 ${mode_choice}。${NC}"
            pause_return
            ;;
        2)
            previous_state=$(get_desired_state 2>/dev/null || printf RUNNING)
            update_traffic_state_atomically '' '' || die '解除流量限制时状态原子提交失败。'
            disable_traffic_monitor
            set_desired_state RUNNING || die '服务期望状态写入失败。'
            load_abox_env "$ABOX_ENV" 2>/dev/null || true
            if [[ "$previous_state" == TRAFFIC_BLOCKED ]]; then
                case "${CORE:-}" in
                    xray) abox_owns_service xray && service_manager start xray ;;
                    singbox) abox_owns_service sing-box && service_manager start sing-box ;;
                    hysteria) abox_owns_service hysteria && service_manager start hysteria ;;
                esac
                [[ "${CORE:-}" == 'xray' && "${MODE:-}" == *'ALL'* ]] && abox_owns_service hysteria && service_manager start hysteria
            fi
            msg "${GREEN}流量限制已解除。${NC}"
            pause_return
            ;;
        *) return 0 ;;
    esac
}

manage_ss_whitelist() {
    clear
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
    read -r -ep '请选择操作 [0-4]: ' wl_choice
    local add_ip del_ip rule found proto
    case "$wl_choice" in
        1)
            read -r -ep '请输入要放行的前置机 IP/CIDR: ' add_ip
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
            read -r -ep '请输入要移除的 IP/CIDR: ' del_ip
            [[ -z "$del_ip" ]] && return
            found=0
            if [[ "$del_ip" == *:* ]]; then
                valid_ipv6_cidr "$del_ip" || { msg "${RED}[!] IPv6 白名单地址非法: $del_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    while $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT 2>/dev/null; do
                        $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则删除失败: $del_ip/$proto"
                        found=1
                    done
                done
            else
                valid_ipv4_cidr "$del_ip" || { msg "${RED}[!] IPv4 白名单地址非法: $del_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    while $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$del_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT 2>/dev/null; do
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
                if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP 2>/dev/null; then
                    $IPT -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto"
                fi
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP 2>/dev/null; then
                        $IPT6 -w -I INPUT 1 -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto"
                    fi
                fi
            done
            enforce_ss_whitelist_order "$SS_PORT" || die 'SS 白名单规则顺序校正失败。'
            save_firewall_rules || die 'A-Box 防火墙持久化失败。'
            msg "${GREEN}已开启白名单保护模式 (TCP+UDP)。${NC}"
            pause_return
            ;;
        4)
            for proto in tcp udp; do
                while $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP 2>/dev/null; do
                    $IPT -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则删除失败: $proto"
                done
                $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP 2>/dev/null && die "IPv4 SS DROP 规则仍然存在: $proto"
                if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    while $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP 2>/dev/null; do
                        $IPT6 -w -D INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则删除失败: $proto"
                    done
                    $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP 2>/dev/null && die "IPv6 SS DROP 规则仍然存在: $proto"
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
    stop_all_managed_services || die '清理前无法停止全部 A-Box 托管服务。'
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    kill_managed_residual_pids || die 'A-Box 残留进程无法完整停止。'
    remove_all_owned_core_families || die '删除 A-Box 托管核心文件失败。'
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
    rm -f /var/log/A-Box-*.log 2>/dev/null || die '删除 A-Box 日志失败。'
    if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl restart fail2ban 2>/dev/null || true; systemctl daemon-reload 2>/dev/null || true; else rc-service fail2ban restart 2>/dev/null || true; fi
    if [[ "${1:-}" == full ]]; then
        remove_abox_shortcut /usr/local/bin/sb
        rm -rf "$ABOX_DIR"
        msg "${GREEN}完全清理完成。${NC}"
        exit 0
    fi
    rm -f "$ABOX_ENV" "$ABOX_DIR"/.deps* "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"
    setup_shortcut
    msg "${GREEN}代理系统已销毁，保留 A-Box 托管的 sb 入口。${NC}"
    pause_return
}

check_virgin_state() {
    clear
    init_system_environment
    msg "${YELLOW}删除全部节点与环境初始化 / Delete all nodes and perform environment initialization${NC}"
    read -r -ep '确定执行环境深度自愈吗？[Y/N]: ' confirm_virgin
    is_yes "$confirm_virgin" || { msg "${GREEN}操作已取消。${NC}"; pause_return; return; }
    auto_backup_prompt 'environment reset' "$ABOX_DIR/backups"
    stop_all_managed_services || die '环境重置前无法停止全部 A-Box 托管服务。'
    clean_nat_rules || die '旧的 A-Box HY2 NAT 规则无法完整删除。'
    clean_input_rules || die '旧的 A-Box INPUT/原生防火墙规则无法完整删除。'
    save_firewall_rules || die 'A-Box 防火墙持久化失败。'
    remove_all_abox_cron_blocks || die '删除 A-Box cron 任务失败。'
    remove_all_owned_core_families || die '环境重置时删除 A-Box 托管核心文件失败。'
    rm -f "$ABOX_ENV" "$ABOX_DIR"/.deps* "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh" || die '环境重置时删除 A-Box 运行文件失败。'
    remove_owned_auxiliary_path /etc/fail2ban/jail.d/A-Box.local || die '删除 A-Box Fail2Ban jail 失败。'
    remove_owned_auxiliary_path /etc/fail2ban/filter.d/A-Box.conf || die '删除 A-Box Fail2Ban filter 失败。'
    remove_owned_auxiliary_path /etc/logrotate.d/A-Box || die '删除 A-Box logrotate 配置失败。'
    rm -f /var/log/A-Box-*.log 2>/dev/null || die '删除 A-Box 日志失败。'
    [[ "${INIT_SYS:-}" == systemd ]] && systemctl daemon-reload 2>/dev/null || true
    msg "${GREEN}环境初始化完成；非 A-Box 同名安装未被删除。${NC}"
    pause_return
}

restore_vps_tune() {
    local quiet="${1:-0}" dir="$ABOX_DIR/tune-backup" line key value path failed=0
    [[ -d "$dir" ]] || { [[ "$quiet" == 1 ]] || msg "${YELLOW}[!] 没有可恢复的 A-Box 调优快照。${NC}"; return 1; }
    for path in /etc/sysctl.d/99-A-Box-tune.conf /etc/security/limits.d/A-Box.conf; do
        [[ ! -e "$path" && ! -L "$path" ]] || auxiliary_path_is_abox_managed "$path" || return 1
    done
    if [[ -f "$dir/sysctl.original" ]]; then
        while IFS='=' read -r key value; do [[ -n "$key" ]] || continue; sysctl -w "$key=$value" >/dev/null 2>&1 || failed=1; done < "$dir/sysctl.original"
    fi
    if [[ -f "$dir/sysctl.conf" ]]; then cp -a "$dir/sysctl.conf" /etc/sysctl.d/99-A-Box-tune.conf || failed=1; else rm -f /etc/sysctl.d/99-A-Box-tune.conf || failed=1; fi
    if [[ -f "$dir/limits.conf" ]]; then cp -a "$dir/limits.conf" /etc/security/limits.d/A-Box.conf || failed=1; else rm -f /etc/security/limits.d/A-Box.conf || failed=1; fi
    sysctl --system >/dev/null 2>&1 || failed=1
    (( failed == 0 )) || return 1
    rm -rf -- "$dir" || return 1
    [[ "$quiet" == 1 ]] || msg "${GREEN}A-Box VPS 调优已恢复。${NC}"
}

apply_vps_tune() {
    local dir="$ABOX_DIR/tune-backup" tmp key value available
    assert_abox_auxiliary_safe /etc/security/limits.d/A-Box.conf
    assert_abox_auxiliary_safe /etc/sysctl.d/99-A-Box-tune.conf
    install -d -m 700 "$dir" || die '无法创建调优备份目录。'
    if [[ -f "$dir/.captured" ]]; then die '检测到尚未恢复的调优快照；请先执行恢复，再重新应用。'; fi
    if [[ ! -f "$dir/.captured" ]]; then
        [[ -f /etc/sysctl.d/99-A-Box-tune.conf ]] && cp -a /etc/sysctl.d/99-A-Box-tune.conf "$dir/sysctl.conf"
        [[ -f /etc/security/limits.d/A-Box.conf ]] && cp -a /etc/security/limits.d/A-Box.conf "$dir/limits.conf"
        : > "$dir/sysctl.original"
        for key in fs.file-max fs.inotify.max_user_instances net.ipv4.tcp_syncookies net.ipv4.tcp_fin_timeout net.ipv4.tcp_keepalive_time net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_max_tw_buckets net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing net.ipv4.tcp_notsent_lowat net.core.netdev_max_backlog net.core.somaxconn net.core.default_qdisc net.ipv4.tcp_congestion_control; do
            value=$(sysctl -n "$key" 2>/dev/null) || continue
            printf '%s=%s\n' "$key" "$value" >> "$dir/sysctl.original"
        done
        touch "$dir/.captured"
    fi
    write_file_atomically_from_stdin /etc/security/limits.d/A-Box.conf 644 <<'EOF_LIMITS' || die 'limits 配置原子写入失败。'
# Managed by A-Box
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF_LIMITS
    tmp=$(mktemp /tmp/A-Box-sysctl.XXXXXX) || die '调优临时文件创建失败。'
    printf '%s\n' '# Managed by A-Box' > "$tmp" || { rm -f "$tmp"; die '调优临时文件初始化失败。'; }
    add_sysctl() { sysctl -n "$1" >/dev/null 2>&1 && printf '%s = %s\n' "$1" "$2" >> "$tmp"; }
    add_sysctl fs.file-max 1048576
    add_sysctl fs.inotify.max_user_instances 8192
    add_sysctl net.ipv4.tcp_syncookies 1
    add_sysctl net.ipv4.tcp_fin_timeout 30
    add_sysctl net.ipv4.tcp_keepalive_time 30
    add_sysctl net.ipv4.tcp_max_syn_backlog 8192
    add_sysctl net.ipv4.tcp_max_tw_buckets 5000
    add_sysctl net.ipv4.tcp_fastopen 3
    add_sysctl net.ipv4.tcp_mtu_probing 1
    add_sysctl net.ipv4.tcp_notsent_lowat 16384
    add_sysctl net.core.netdev_max_backlog 250000
    add_sysctl net.core.somaxconn 32768
    modprobe tcp_bbr >/dev/null 2>&1 || true
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if grep -qw bbr <<< "$available"; then add_sysctl net.core.default_qdisc fq; add_sysctl net.ipv4.tcp_congestion_control bbr; else msg "${YELLOW}[!] 当前内核未提供 BBR，跳过 BBR/FQ 设置。${NC}"; fi
    install_file_atomically "$tmp" /etc/sysctl.d/99-A-Box-tune.conf 600 || { rm -f "$tmp"; die '调优配置原子写入失败。'; }
    rm -f "$tmp"
    if ! sysctl -p /etc/sysctl.d/99-A-Box-tune.conf >/dev/null 2>&1; then restore_vps_tune 1; die 'sysctl 调优应用失败，已恢复原状态。'; fi
    msg "${GREEN}系统调优已应用；未强制启用 IP forwarding，也未修改核心 JSON 配置。${NC}"
}

tune_vps() {
    clear
    msg "${CYAN}VPS 调优 / VPS tuning${NC}"
    msg "${YELLOW}1. 应用可回滚调优${NC}"
    msg "${YELLOW}2. 恢复调优前状态${NC}"
    msg "${GREEN}0. 返回${NC}"
    local c
    read -r -ep 'Select [0-2]: ' c
    case "$c" in 1) apply_vps_tune; pause_return ;; 2) restore_vps_tune; pause_return ;; *) return 0 ;; esac
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
tmp = out.with_name(out.name + ".tmp")
try:
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
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
    local label="$1" url="$2" sha="$3" answer
    if [[ -n "${ABOX_REMOTE_SHA256_ALLOWLIST:-}" ]]; then
        if sha256_in_allowlist "$sha" "$ABOX_REMOTE_SHA256_ALLOWLIST"; then
            msg "${GREEN}[*] Remote script SHA256 matched ABOX_REMOTE_SHA256_ALLOWLIST.${NC}"
            return 0
        fi
        die "Remote script SHA256 is not in ABOX_REMOTE_SHA256_ALLOWLIST: ${label}"
    fi
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}[!] This is third-party code outside A-Box control. Syntax validation is not a trust guarantee.${NC}"
        msg "${YELLOW}[!] Review the source and SHA256 before execution: ${url}${NC}"
        read -r -ep 'Type YES-RUN-UNTRUSTED to execute this remote script: ' answer
    else
        msg "${YELLOW}[!] 这是 A-Box 无法控制的第三方代码。语法校验不等于可信校验。${NC}"
        msg "${YELLOW}[!] 执行前请核对来源与 SHA256：${url}${NC}"
        read -r -ep '输入 YES-RUN-UNTRUSTED 才执行此远程脚本: ' answer
    fi
    [[ "$answer" == 'YES-RUN-UNTRUSTED' ]] || return 130
}

run_remote_bash_script() {
    local label="$1" url="$2" tmp sha
    shift 2 || true
    tmp=$(mktemp /tmp/A-Box-remote.XXXXXX.sh) || die '远程脚本临时文件创建失败。'
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
    bash "$tmp" "$@"
    local rc=$?
    rm -f "$tmp"
    return "$rc"
}



write_sni_candidate_library() {
    local profile="${1:-full}" out="$2" raw generated tmp remote_tmp max_count variant_count
    [[ -n "$out" ]] || die 'SNI candidate output path missing.'
    raw=$(mktemp /tmp/A-Box-sni-lib.XXXXXX) || die 'SNI library temporary file creation failed.'
    generated=$(mktemp /tmp/A-Box-sni-lib-generated.XXXXXX) || { rm -f "$raw"; die 'SNI generated library temporary file creation failed.'; }
    tmp=$(mktemp /tmp/A-Box-sni-lib-filtered.XXXXXX) || { rm -f "$raw" "$generated"; die 'SNI library filtered temporary file creation failed.'; }

    cat > "$raw" <<'EOF_SNI_CANDIDATES'
www.microsoft.com
learn.microsoft.com
docs.microsoft.com
download.microsoft.com
support.microsoft.com
www.bing.com
www.apache.org
downloads.apache.org
www.ietf.org
www.rfc-editor.org
www.w3.org
www.unicode.org
www.icann.org
www.iana.org
www.nginx.org
nginx.org
www.openssl.org
curl.se
www.kernel.org
www.debian.org
www.ubuntu.com
www.python.org
docs.python.org
pypi.org
www.rust-lang.org
crates.io
nodejs.org
www.npmjs.com
www.mozilla.org
developer.mozilla.org
www.postgresql.org
www.sqlite.org
mariadb.org
www.mysql.com
www.cloudflare.com
developers.cloudflare.com
www.akamai.com
www.fastly.com
www.confluent.io
www.linuxfoundation.org
www.cncf.io
www.eclipse.org
www.gnu.org
git-scm.com
cmake.org
llvm.org
www.samsung.com
www.lenovo.com
www.dell.com
www.intel.com
www.amd.com
www.nvidia.com
www.cisco.com
www.huawei.com
www.ericsson.com
www.nokia.com
www.siemens.com
www.sony.com
www.panasonic.com
www.iso.org
www.itu.int
www.un.org
www.who.int
www.unesco.org
www.cern.ch
www.esa.int
www.mit.edu
www.stanford.edu
www.berkeley.edu
www.cam.ac.uk
www.ox.ac.uk
ethz.ch
www.epfl.ch
arxiv.org
www.crossref.org
doi.org
orcid.org
www.openstreetmap.org
microsoft.com
doc.microsoft.com
developer.microsoft.com
developers.microsoft.com
help.microsoft.com
status.microsoft.com
api.microsoft.com
cdn.microsoft.com
static.microsoft.com
assets.microsoft.com
downloads.microsoft.com
files.microsoft.com
resources.microsoft.com
community.microsoft.com
blog.microsoft.com
security.microsoft.com
updates.microsoft.com
packages.microsoft.com
repo.microsoft.com
registry.microsoft.com
pkg.microsoft.com
mirror.microsoft.com
mirrors.microsoft.com
forum.microsoft.com
forums.microsoft.com
manual.microsoft.com
training.microsoft.com
events.microsoft.com
news.microsoft.com
www2.microsoft.com
portal.microsoft.com
service.microsoft.com
services.microsoft.com
bing.com
docs.bing.com
doc.bing.com
developer.bing.com
developers.bing.com
learn.bing.com
support.bing.com
help.bing.com
status.bing.com
api.bing.com
cdn.bing.com
static.bing.com
assets.bing.com
download.bing.com
downloads.bing.com
files.bing.com
resources.bing.com
community.bing.com
blog.bing.com
security.bing.com
updates.bing.com
packages.bing.com
repo.bing.com
registry.bing.com
pkg.bing.com
mirror.bing.com
mirrors.bing.com
forum.bing.com
forums.bing.com
manual.bing.com
training.bing.com
events.bing.com
news.bing.com
www2.bing.com
portal.bing.com
service.bing.com
services.bing.com
office.com
www.office.com
docs.office.com
doc.office.com
developer.office.com
developers.office.com
learn.office.com
support.office.com
help.office.com
status.office.com
api.office.com
cdn.office.com
static.office.com
assets.office.com
download.office.com
downloads.office.com
files.office.com
resources.office.com
community.office.com
blog.office.com
security.office.com
updates.office.com
packages.office.com
repo.office.com
registry.office.com
pkg.office.com
mirror.office.com
mirrors.office.com
forum.office.com
forums.office.com
manual.office.com
training.office.com
events.office.com
news.office.com
www2.office.com
portal.office.com
service.office.com
services.office.com
windows.com
www.windows.com
docs.windows.com
doc.windows.com
developer.windows.com
developers.windows.com
learn.windows.com
support.windows.com
help.windows.com
status.windows.com
api.windows.com
cdn.windows.com
static.windows.com
assets.windows.com
download.windows.com
downloads.windows.com
files.windows.com
resources.windows.com
community.windows.com
blog.windows.com
security.windows.com
updates.windows.com
packages.windows.com
repo.windows.com
registry.windows.com
pkg.windows.com
mirror.windows.com
mirrors.windows.com
forum.windows.com
forums.windows.com
manual.windows.com
training.windows.com
events.windows.com
news.windows.com
www2.windows.com
portal.windows.com
service.windows.com
services.windows.com
azure.com
www.azure.com
docs.azure.com
doc.azure.com
developer.azure.com
developers.azure.com
learn.azure.com
support.azure.com
help.azure.com
status.azure.com
api.azure.com
cdn.azure.com
static.azure.com
assets.azure.com
download.azure.com
downloads.azure.com
files.azure.com
resources.azure.com
community.azure.com
blog.azure.com
security.azure.com
updates.azure.com
packages.azure.com
repo.azure.com
registry.azure.com
pkg.azure.com
mirror.azure.com
mirrors.azure.com
forum.azure.com
forums.azure.com
manual.azure.com
training.azure.com
events.azure.com
news.azure.com
www2.azure.com
portal.azure.com
service.azure.com
services.azure.com
visualstudio.com
www.visualstudio.com
docs.visualstudio.com
doc.visualstudio.com
developer.visualstudio.com
developers.visualstudio.com
learn.visualstudio.com
support.visualstudio.com
help.visualstudio.com
status.visualstudio.com
api.visualstudio.com
cdn.visualstudio.com
static.visualstudio.com
assets.visualstudio.com
download.visualstudio.com
downloads.visualstudio.com
files.visualstudio.com
resources.visualstudio.com
community.visualstudio.com
blog.visualstudio.com
security.visualstudio.com
updates.visualstudio.com
packages.visualstudio.com
repo.visualstudio.com
registry.visualstudio.com
pkg.visualstudio.com
mirror.visualstudio.com
mirrors.visualstudio.com
forum.visualstudio.com
forums.visualstudio.com
manual.visualstudio.com
training.visualstudio.com
events.visualstudio.com
news.visualstudio.com
www2.visualstudio.com
portal.visualstudio.com
service.visualstudio.com
services.visualstudio.com
cloudflare.com
docs.cloudflare.com
doc.cloudflare.com
developer.cloudflare.com
learn.cloudflare.com
support.cloudflare.com
help.cloudflare.com
status.cloudflare.com
api.cloudflare.com
cdn.cloudflare.com
static.cloudflare.com
assets.cloudflare.com
download.cloudflare.com
downloads.cloudflare.com
files.cloudflare.com
resources.cloudflare.com
community.cloudflare.com
blog.cloudflare.com
security.cloudflare.com
updates.cloudflare.com
packages.cloudflare.com
repo.cloudflare.com
registry.cloudflare.com
pkg.cloudflare.com
mirror.cloudflare.com
mirrors.cloudflare.com
forum.cloudflare.com
forums.cloudflare.com
manual.cloudflare.com
training.cloudflare.com
events.cloudflare.com
news.cloudflare.com
www2.cloudflare.com
portal.cloudflare.com
service.cloudflare.com
services.cloudflare.com
akamai.com
docs.akamai.com
doc.akamai.com
developer.akamai.com
developers.akamai.com
learn.akamai.com
support.akamai.com
help.akamai.com
status.akamai.com
api.akamai.com
cdn.akamai.com
static.akamai.com
assets.akamai.com
download.akamai.com
downloads.akamai.com
files.akamai.com
resources.akamai.com
community.akamai.com
blog.akamai.com
security.akamai.com
updates.akamai.com
packages.akamai.com
repo.akamai.com
registry.akamai.com
pkg.akamai.com
mirror.akamai.com
mirrors.akamai.com
forum.akamai.com
forums.akamai.com
manual.akamai.com
training.akamai.com
events.akamai.com
news.akamai.com
www2.akamai.com
portal.akamai.com
service.akamai.com
services.akamai.com
fastly.com
docs.fastly.com
doc.fastly.com
developer.fastly.com
developers.fastly.com
learn.fastly.com
support.fastly.com
help.fastly.com
status.fastly.com
api.fastly.com
cdn.fastly.com
static.fastly.com
assets.fastly.com
download.fastly.com
downloads.fastly.com
files.fastly.com
resources.fastly.com
community.fastly.com
blog.fastly.com
security.fastly.com
updates.fastly.com
packages.fastly.com
repo.fastly.com
registry.fastly.com
pkg.fastly.com
mirror.fastly.com
mirrors.fastly.com
forum.fastly.com
forums.fastly.com
manual.fastly.com
training.fastly.com
events.fastly.com
news.fastly.com
www2.fastly.com
portal.fastly.com
service.fastly.com
services.fastly.com
cdn77.com
www.cdn77.com
docs.cdn77.com
doc.cdn77.com
developer.cdn77.com
developers.cdn77.com
learn.cdn77.com
support.cdn77.com
help.cdn77.com
status.cdn77.com
api.cdn77.com
cdn.cdn77.com
static.cdn77.com
assets.cdn77.com
download.cdn77.com
downloads.cdn77.com
files.cdn77.com
resources.cdn77.com
community.cdn77.com
blog.cdn77.com
security.cdn77.com
updates.cdn77.com
packages.cdn77.com
repo.cdn77.com
registry.cdn77.com
pkg.cdn77.com
mirror.cdn77.com
mirrors.cdn77.com
forum.cdn77.com
forums.cdn77.com
manual.cdn77.com
training.cdn77.com
events.cdn77.com
news.cdn77.com
www2.cdn77.com
portal.cdn77.com
service.cdn77.com
services.cdn77.com
bunny.net
www.bunny.net
docs.bunny.net
doc.bunny.net
developer.bunny.net
developers.bunny.net
learn.bunny.net
support.bunny.net
help.bunny.net
status.bunny.net
api.bunny.net
cdn.bunny.net
static.bunny.net
assets.bunny.net
download.bunny.net
downloads.bunny.net
files.bunny.net
resources.bunny.net
community.bunny.net
blog.bunny.net
security.bunny.net
updates.bunny.net
packages.bunny.net
repo.bunny.net
registry.bunny.net
pkg.bunny.net
mirror.bunny.net
mirrors.bunny.net
forum.bunny.net
forums.bunny.net
manual.bunny.net
training.bunny.net
events.bunny.net
news.bunny.net
www2.bunny.net
portal.bunny.net
service.bunny.net
services.bunny.net
statuspage.io
www.statuspage.io
docs.statuspage.io
doc.statuspage.io
developer.statuspage.io
developers.statuspage.io
learn.statuspage.io
support.statuspage.io
help.statuspage.io
status.statuspage.io
api.statuspage.io
cdn.statuspage.io
static.statuspage.io
assets.statuspage.io
download.statuspage.io
downloads.statuspage.io
files.statuspage.io
resources.statuspage.io
community.statuspage.io
blog.statuspage.io
security.statuspage.io
updates.statuspage.io
packages.statuspage.io
repo.statuspage.io
registry.statuspage.io
pkg.statuspage.io
mirror.statuspage.io
mirrors.statuspage.io
forum.statuspage.io
forums.statuspage.io
manual.statuspage.io
training.statuspage.io
events.statuspage.io
news.statuspage.io
www2.statuspage.io
portal.statuspage.io
service.statuspage.io
services.statuspage.io
ietf.org
docs.ietf.org
doc.ietf.org
developer.ietf.org
developers.ietf.org
learn.ietf.org
support.ietf.org
help.ietf.org
status.ietf.org
api.ietf.org
cdn.ietf.org
static.ietf.org
assets.ietf.org
download.ietf.org
downloads.ietf.org
files.ietf.org
resources.ietf.org
community.ietf.org
blog.ietf.org
security.ietf.org
updates.ietf.org
packages.ietf.org
repo.ietf.org
registry.ietf.org
pkg.ietf.org
mirror.ietf.org
mirrors.ietf.org
forum.ietf.org
forums.ietf.org
manual.ietf.org
training.ietf.org
events.ietf.org
news.ietf.org
www2.ietf.org
portal.ietf.org
service.ietf.org
services.ietf.org
rfc-editor.org
docs.rfc-editor.org
doc.rfc-editor.org
developer.rfc-editor.org
developers.rfc-editor.org
learn.rfc-editor.org
support.rfc-editor.org
help.rfc-editor.org
status.rfc-editor.org
api.rfc-editor.org
cdn.rfc-editor.org
static.rfc-editor.org
assets.rfc-editor.org
download.rfc-editor.org
downloads.rfc-editor.org
files.rfc-editor.org
resources.rfc-editor.org
community.rfc-editor.org
blog.rfc-editor.org
security.rfc-editor.org
updates.rfc-editor.org
packages.rfc-editor.org
repo.rfc-editor.org
registry.rfc-editor.org
pkg.rfc-editor.org
mirror.rfc-editor.org
mirrors.rfc-editor.org
forum.rfc-editor.org
forums.rfc-editor.org
manual.rfc-editor.org
training.rfc-editor.org
events.rfc-editor.org
news.rfc-editor.org
www2.rfc-editor.org
portal.rfc-editor.org
service.rfc-editor.org
services.rfc-editor.org
w3.org
docs.w3.org
doc.w3.org
developer.w3.org
developers.w3.org
learn.w3.org
support.w3.org
help.w3.org
status.w3.org
api.w3.org
cdn.w3.org
static.w3.org
assets.w3.org
download.w3.org
downloads.w3.org
files.w3.org
resources.w3.org
community.w3.org
blog.w3.org
security.w3.org
updates.w3.org
packages.w3.org
repo.w3.org
registry.w3.org
pkg.w3.org
mirror.w3.org
mirrors.w3.org
forum.w3.org
forums.w3.org
manual.w3.org
training.w3.org
events.w3.org
news.w3.org
www2.w3.org
portal.w3.org
service.w3.org
services.w3.org
unicode.org
docs.unicode.org
doc.unicode.org
developer.unicode.org
developers.unicode.org
learn.unicode.org
support.unicode.org
help.unicode.org
status.unicode.org
api.unicode.org
cdn.unicode.org
static.unicode.org
assets.unicode.org
download.unicode.org
downloads.unicode.org
files.unicode.org
resources.unicode.org
community.unicode.org
blog.unicode.org
security.unicode.org
updates.unicode.org
packages.unicode.org
repo.unicode.org
registry.unicode.org
pkg.unicode.org
mirror.unicode.org
mirrors.unicode.org
forum.unicode.org
forums.unicode.org
manual.unicode.org
training.unicode.org
events.unicode.org
news.unicode.org
www2.unicode.org
portal.unicode.org
service.unicode.org
services.unicode.org
icann.org
docs.icann.org
doc.icann.org
developer.icann.org
developers.icann.org
learn.icann.org
support.icann.org
help.icann.org
status.icann.org
api.icann.org
cdn.icann.org
static.icann.org
assets.icann.org
download.icann.org
downloads.icann.org
files.icann.org
resources.icann.org
community.icann.org
blog.icann.org
security.icann.org
updates.icann.org
packages.icann.org
repo.icann.org
registry.icann.org
pkg.icann.org
mirror.icann.org
mirrors.icann.org
forum.icann.org
forums.icann.org
manual.icann.org
training.icann.org
events.icann.org
news.icann.org
www2.icann.org
portal.icann.org
service.icann.org
services.icann.org
iana.org
docs.iana.org
doc.iana.org
developer.iana.org
developers.iana.org
learn.iana.org
support.iana.org
help.iana.org
status.iana.org
api.iana.org
cdn.iana.org
static.iana.org
assets.iana.org
download.iana.org
downloads.iana.org
files.iana.org
resources.iana.org
community.iana.org
blog.iana.org
security.iana.org
updates.iana.org
packages.iana.org
repo.iana.org
registry.iana.org
pkg.iana.org
mirror.iana.org
mirrors.iana.org
forum.iana.org
forums.iana.org
manual.iana.org
training.iana.org
events.iana.org
news.iana.org
www2.iana.org
portal.iana.org
service.iana.org
services.iana.org
iso.org
docs.iso.org
doc.iso.org
developer.iso.org
developers.iso.org
learn.iso.org
support.iso.org
help.iso.org
status.iso.org
api.iso.org
cdn.iso.org
static.iso.org
assets.iso.org
download.iso.org
downloads.iso.org
files.iso.org
resources.iso.org
community.iso.org
blog.iso.org
security.iso.org
updates.iso.org
packages.iso.org
repo.iso.org
registry.iso.org
pkg.iso.org
mirror.iso.org
mirrors.iso.org
forum.iso.org
forums.iso.org
manual.iso.org
training.iso.org
events.iso.org
news.iso.org
www2.iso.org
portal.iso.org
service.iso.org
services.iso.org
itu.int
docs.itu.int
doc.itu.int
developer.itu.int
developers.itu.int
learn.itu.int
support.itu.int
help.itu.int
status.itu.int
api.itu.int
cdn.itu.int
static.itu.int
assets.itu.int
download.itu.int
downloads.itu.int
files.itu.int
resources.itu.int
community.itu.int
blog.itu.int
security.itu.int
updates.itu.int
packages.itu.int
repo.itu.int
registry.itu.int
pkg.itu.int
mirror.itu.int
mirrors.itu.int
forum.itu.int
forums.itu.int
manual.itu.int
training.itu.int
events.itu.int
news.itu.int
www2.itu.int
portal.itu.int
service.itu.int
services.itu.int
un.org
docs.un.org
doc.un.org
developer.un.org
developers.un.org
learn.un.org
support.un.org
help.un.org
status.un.org
api.un.org
cdn.un.org
static.un.org
assets.un.org
download.un.org
downloads.un.org
files.un.org
resources.un.org
community.un.org
blog.un.org
security.un.org
updates.un.org
packages.un.org
repo.un.org
registry.un.org
pkg.un.org
mirror.un.org
mirrors.un.org
forum.un.org
forums.un.org
manual.un.org
training.un.org
events.un.org
news.un.org
www2.un.org
portal.un.org
service.un.org
services.un.org
who.int
docs.who.int
doc.who.int
developer.who.int
developers.who.int
learn.who.int
support.who.int
help.who.int
status.who.int
api.who.int
cdn.who.int
static.who.int
assets.who.int
download.who.int
downloads.who.int
files.who.int
resources.who.int
community.who.int
blog.who.int
security.who.int
updates.who.int
packages.who.int
repo.who.int
registry.who.int
pkg.who.int
mirror.who.int
mirrors.who.int
forum.who.int
forums.who.int
manual.who.int
training.who.int
events.who.int
news.who.int
www2.who.int
portal.who.int
service.who.int
services.who.int
unesco.org
docs.unesco.org
doc.unesco.org
developer.unesco.org
developers.unesco.org
learn.unesco.org
support.unesco.org
help.unesco.org
status.unesco.org
api.unesco.org
cdn.unesco.org
static.unesco.org
assets.unesco.org
download.unesco.org
downloads.unesco.org
files.unesco.org
resources.unesco.org
community.unesco.org
blog.unesco.org
security.unesco.org
updates.unesco.org
packages.unesco.org
repo.unesco.org
registry.unesco.org
pkg.unesco.org
mirror.unesco.org
mirrors.unesco.org
forum.unesco.org
forums.unesco.org
manual.unesco.org
training.unesco.org
events.unesco.org
news.unesco.org
www2.unesco.org
portal.unesco.org
service.unesco.org
services.unesco.org
worldbank.org
www.worldbank.org
docs.worldbank.org
doc.worldbank.org
developer.worldbank.org
developers.worldbank.org
learn.worldbank.org
support.worldbank.org
help.worldbank.org
status.worldbank.org
api.worldbank.org
cdn.worldbank.org
static.worldbank.org
assets.worldbank.org
download.worldbank.org
downloads.worldbank.org
files.worldbank.org
resources.worldbank.org
community.worldbank.org
blog.worldbank.org
security.worldbank.org
updates.worldbank.org
packages.worldbank.org
repo.worldbank.org
registry.worldbank.org
pkg.worldbank.org
mirror.worldbank.org
mirrors.worldbank.org
forum.worldbank.org
forums.worldbank.org
manual.worldbank.org
training.worldbank.org
events.worldbank.org
news.worldbank.org
www2.worldbank.org
portal.worldbank.org
service.worldbank.org
services.worldbank.org
imf.org
www.imf.org
docs.imf.org
doc.imf.org
developer.imf.org
developers.imf.org
learn.imf.org
support.imf.org
help.imf.org
status.imf.org
api.imf.org
cdn.imf.org
static.imf.org
assets.imf.org
download.imf.org
downloads.imf.org
files.imf.org
resources.imf.org
community.imf.org
blog.imf.org
security.imf.org
updates.imf.org
packages.imf.org
repo.imf.org
registry.imf.org
pkg.imf.org
mirror.imf.org
mirrors.imf.org
forum.imf.org
forums.imf.org
manual.imf.org
training.imf.org
events.imf.org
news.imf.org
www2.imf.org
portal.imf.org
service.imf.org
services.imf.org
oecd.org
www.oecd.org
docs.oecd.org
doc.oecd.org
developer.oecd.org
developers.oecd.org
learn.oecd.org
support.oecd.org
help.oecd.org
status.oecd.org
api.oecd.org
cdn.oecd.org
static.oecd.org
assets.oecd.org
download.oecd.org
downloads.oecd.org
files.oecd.org
resources.oecd.org
community.oecd.org
blog.oecd.org
security.oecd.org
updates.oecd.org
packages.oecd.org
repo.oecd.org
registry.oecd.org
pkg.oecd.org
mirror.oecd.org
mirrors.oecd.org
forum.oecd.org
forums.oecd.org
manual.oecd.org
training.oecd.org
events.oecd.org
news.oecd.org
www2.oecd.org
portal.oecd.org
service.oecd.org
services.oecd.org
wto.org
www.wto.org
docs.wto.org
doc.wto.org
developer.wto.org
developers.wto.org
learn.wto.org
support.wto.org
help.wto.org
status.wto.org
api.wto.org
cdn.wto.org
static.wto.org
assets.wto.org
download.wto.org
downloads.wto.org
files.wto.org
resources.wto.org
community.wto.org
blog.wto.org
security.wto.org
updates.wto.org
packages.wto.org
repo.wto.org
registry.wto.org
pkg.wto.org
mirror.wto.org
mirrors.wto.org
forum.wto.org
forums.wto.org
manual.wto.org
training.wto.org
events.wto.org
news.wto.org
www2.wto.org
portal.wto.org
service.wto.org
services.wto.org
cern.ch
docs.cern.ch
doc.cern.ch
developer.cern.ch
developers.cern.ch
learn.cern.ch
support.cern.ch
help.cern.ch
status.cern.ch
api.cern.ch
cdn.cern.ch
static.cern.ch
assets.cern.ch
download.cern.ch
downloads.cern.ch
files.cern.ch
resources.cern.ch
community.cern.ch
blog.cern.ch
security.cern.ch
updates.cern.ch
packages.cern.ch
repo.cern.ch
registry.cern.ch
pkg.cern.ch
mirror.cern.ch
mirrors.cern.ch
forum.cern.ch
forums.cern.ch
manual.cern.ch
training.cern.ch
events.cern.ch
news.cern.ch
www2.cern.ch
portal.cern.ch
service.cern.ch
services.cern.ch
esa.int
docs.esa.int
doc.esa.int
developer.esa.int
developers.esa.int
learn.esa.int
support.esa.int
help.esa.int
status.esa.int
api.esa.int
cdn.esa.int
static.esa.int
assets.esa.int
download.esa.int
downloads.esa.int
files.esa.int
resources.esa.int
community.esa.int
blog.esa.int
security.esa.int
updates.esa.int
packages.esa.int
repo.esa.int
registry.esa.int
pkg.esa.int
mirror.esa.int
mirrors.esa.int
forum.esa.int
forums.esa.int
manual.esa.int
training.esa.int
events.esa.int
news.esa.int
www2.esa.int
portal.esa.int
service.esa.int
services.esa.int
apache.org
docs.apache.org
doc.apache.org
developer.apache.org
developers.apache.org
learn.apache.org
support.apache.org
help.apache.org
status.apache.org
api.apache.org
cdn.apache.org
static.apache.org
assets.apache.org
download.apache.org
files.apache.org
resources.apache.org
community.apache.org
blog.apache.org
security.apache.org
updates.apache.org
packages.apache.org
repo.apache.org
registry.apache.org
pkg.apache.org
mirror.apache.org
mirrors.apache.org
forum.apache.org
forums.apache.org
manual.apache.org
training.apache.org
events.apache.org
news.apache.org
www2.apache.org
portal.apache.org
service.apache.org
services.apache.org
docs.nginx.org
doc.nginx.org
developer.nginx.org
developers.nginx.org
learn.nginx.org
support.nginx.org
help.nginx.org
status.nginx.org
api.nginx.org
cdn.nginx.org
static.nginx.org
assets.nginx.org
download.nginx.org
downloads.nginx.org
files.nginx.org
resources.nginx.org
community.nginx.org
blog.nginx.org
security.nginx.org
updates.nginx.org
packages.nginx.org
repo.nginx.org
registry.nginx.org
pkg.nginx.org
mirror.nginx.org
mirrors.nginx.org
forum.nginx.org
forums.nginx.org
manual.nginx.org
training.nginx.org
events.nginx.org
news.nginx.org
www2.nginx.org
portal.nginx.org
service.nginx.org
services.nginx.org
openssl.org
docs.openssl.org
doc.openssl.org
developer.openssl.org
developers.openssl.org
learn.openssl.org
support.openssl.org
help.openssl.org
status.openssl.org
api.openssl.org
cdn.openssl.org
static.openssl.org
assets.openssl.org
download.openssl.org
downloads.openssl.org
files.openssl.org
resources.openssl.org
community.openssl.org
blog.openssl.org
security.openssl.org
updates.openssl.org
packages.openssl.org
repo.openssl.org
registry.openssl.org
pkg.openssl.org
mirror.openssl.org
mirrors.openssl.org
forum.openssl.org
forums.openssl.org
manual.openssl.org
training.openssl.org
events.openssl.org
news.openssl.org
www2.openssl.org
portal.openssl.org
service.openssl.org
services.openssl.org
www.curl.se
docs.curl.se
doc.curl.se
developer.curl.se
developers.curl.se
learn.curl.se
support.curl.se
help.curl.se
status.curl.se
api.curl.se
cdn.curl.se
static.curl.se
assets.curl.se
download.curl.se
downloads.curl.se
files.curl.se
resources.curl.se
community.curl.se
blog.curl.se
security.curl.se
updates.curl.se
packages.curl.se
repo.curl.se
registry.curl.se
pkg.curl.se
mirror.curl.se
mirrors.curl.se
forum.curl.se
forums.curl.se
manual.curl.se
training.curl.se
events.curl.se
news.curl.se
www2.curl.se
portal.curl.se
service.curl.se
services.curl.se
kernel.org
docs.kernel.org
doc.kernel.org
developer.kernel.org
developers.kernel.org
learn.kernel.org
support.kernel.org
help.kernel.org
status.kernel.org
api.kernel.org
cdn.kernel.org
static.kernel.org
assets.kernel.org
download.kernel.org
downloads.kernel.org
files.kernel.org
resources.kernel.org
community.kernel.org
blog.kernel.org
security.kernel.org
updates.kernel.org
packages.kernel.org
repo.kernel.org
registry.kernel.org
pkg.kernel.org
mirror.kernel.org
mirrors.kernel.org
forum.kernel.org
forums.kernel.org
manual.kernel.org
training.kernel.org
events.kernel.org
news.kernel.org
www2.kernel.org
portal.kernel.org
service.kernel.org
services.kernel.org
linuxfoundation.org
docs.linuxfoundation.org
doc.linuxfoundation.org
developer.linuxfoundation.org
developers.linuxfoundation.org
learn.linuxfoundation.org
support.linuxfoundation.org
help.linuxfoundation.org
status.linuxfoundation.org
api.linuxfoundation.org
cdn.linuxfoundation.org
static.linuxfoundation.org
assets.linuxfoundation.org
download.linuxfoundation.org
downloads.linuxfoundation.org
files.linuxfoundation.org
resources.linuxfoundation.org
community.linuxfoundation.org
blog.linuxfoundation.org
security.linuxfoundation.org
updates.linuxfoundation.org
packages.linuxfoundation.org
repo.linuxfoundation.org
registry.linuxfoundation.org
pkg.linuxfoundation.org
mirror.linuxfoundation.org
mirrors.linuxfoundation.org
forum.linuxfoundation.org
forums.linuxfoundation.org
manual.linuxfoundation.org
training.linuxfoundation.org
events.linuxfoundation.org
news.linuxfoundation.org
www2.linuxfoundation.org
portal.linuxfoundation.org
service.linuxfoundation.org
services.linuxfoundation.org
cncf.io
docs.cncf.io
doc.cncf.io
developer.cncf.io
developers.cncf.io
learn.cncf.io
support.cncf.io
help.cncf.io
status.cncf.io
api.cncf.io
cdn.cncf.io
static.cncf.io
assets.cncf.io
download.cncf.io
downloads.cncf.io
files.cncf.io
resources.cncf.io
community.cncf.io
blog.cncf.io
security.cncf.io
updates.cncf.io
packages.cncf.io
repo.cncf.io
registry.cncf.io
pkg.cncf.io
mirror.cncf.io
mirrors.cncf.io
forum.cncf.io
forums.cncf.io
manual.cncf.io
training.cncf.io
events.cncf.io
news.cncf.io
www2.cncf.io
portal.cncf.io
service.cncf.io
services.cncf.io
eclipse.org
docs.eclipse.org
doc.eclipse.org
developer.eclipse.org
developers.eclipse.org
learn.eclipse.org
support.eclipse.org
help.eclipse.org
status.eclipse.org
api.eclipse.org
cdn.eclipse.org
static.eclipse.org
assets.eclipse.org
download.eclipse.org
downloads.eclipse.org
files.eclipse.org
resources.eclipse.org
community.eclipse.org
blog.eclipse.org
security.eclipse.org
updates.eclipse.org
packages.eclipse.org
repo.eclipse.org
registry.eclipse.org
pkg.eclipse.org
mirror.eclipse.org
mirrors.eclipse.org
forum.eclipse.org
forums.eclipse.org
manual.eclipse.org
training.eclipse.org
events.eclipse.org
news.eclipse.org
www2.eclipse.org
portal.eclipse.org
service.eclipse.org
services.eclipse.org
gnu.org
docs.gnu.org
doc.gnu.org
developer.gnu.org
developers.gnu.org
learn.gnu.org
support.gnu.org
help.gnu.org
status.gnu.org
api.gnu.org
cdn.gnu.org
static.gnu.org
assets.gnu.org
download.gnu.org
downloads.gnu.org
files.gnu.org
resources.gnu.org
community.gnu.org
blog.gnu.org
security.gnu.org
updates.gnu.org
packages.gnu.org
repo.gnu.org
registry.gnu.org
pkg.gnu.org
mirror.gnu.org
mirrors.gnu.org
forum.gnu.org
forums.gnu.org
manual.gnu.org
training.gnu.org
events.gnu.org
news.gnu.org
www2.gnu.org
portal.gnu.org
service.gnu.org
services.gnu.org
fsf.org
www.fsf.org
docs.fsf.org
doc.fsf.org
developer.fsf.org
developers.fsf.org
learn.fsf.org
support.fsf.org
help.fsf.org
status.fsf.org
api.fsf.org
cdn.fsf.org
static.fsf.org
assets.fsf.org
download.fsf.org
downloads.fsf.org
files.fsf.org
resources.fsf.org
community.fsf.org
blog.fsf.org
security.fsf.org
updates.fsf.org
packages.fsf.org
repo.fsf.org
registry.fsf.org
pkg.fsf.org
mirror.fsf.org
mirrors.fsf.org
forum.fsf.org
forums.fsf.org
manual.fsf.org
training.fsf.org
events.fsf.org
news.fsf.org
www2.fsf.org
portal.fsf.org
service.fsf.org
services.fsf.org
www.git-scm.com
docs.git-scm.com
doc.git-scm.com
developer.git-scm.com
developers.git-scm.com
learn.git-scm.com
support.git-scm.com
help.git-scm.com
status.git-scm.com
api.git-scm.com
cdn.git-scm.com
static.git-scm.com
assets.git-scm.com
download.git-scm.com
downloads.git-scm.com
files.git-scm.com
resources.git-scm.com
community.git-scm.com
blog.git-scm.com
security.git-scm.com
updates.git-scm.com
packages.git-scm.com
repo.git-scm.com
registry.git-scm.com
pkg.git-scm.com
mirror.git-scm.com
mirrors.git-scm.com
forum.git-scm.com
forums.git-scm.com
manual.git-scm.com
training.git-scm.com
events.git-scm.com
news.git-scm.com
www2.git-scm.com
portal.git-scm.com
service.git-scm.com
services.git-scm.com
www.cmake.org
docs.cmake.org
doc.cmake.org
developer.cmake.org
developers.cmake.org
learn.cmake.org
support.cmake.org
help.cmake.org
status.cmake.org
api.cmake.org
cdn.cmake.org
static.cmake.org
assets.cmake.org
download.cmake.org
downloads.cmake.org
files.cmake.org
resources.cmake.org
community.cmake.org
blog.cmake.org
security.cmake.org
updates.cmake.org
packages.cmake.org
repo.cmake.org
registry.cmake.org
pkg.cmake.org
mirror.cmake.org
mirrors.cmake.org
forum.cmake.org
forums.cmake.org
manual.cmake.org
training.cmake.org
events.cmake.org
news.cmake.org
www2.cmake.org
portal.cmake.org
service.cmake.org
services.cmake.org
www.llvm.org
docs.llvm.org
doc.llvm.org
developer.llvm.org
developers.llvm.org
learn.llvm.org
support.llvm.org
help.llvm.org
status.llvm.org
api.llvm.org
cdn.llvm.org
static.llvm.org
assets.llvm.org
download.llvm.org
downloads.llvm.org
files.llvm.org
resources.llvm.org
community.llvm.org
blog.llvm.org
security.llvm.org
updates.llvm.org
packages.llvm.org
repo.llvm.org
registry.llvm.org
pkg.llvm.org
mirror.llvm.org
mirrors.llvm.org
forum.llvm.org
forums.llvm.org
manual.llvm.org
training.llvm.org
events.llvm.org
news.llvm.org
www2.llvm.org
portal.llvm.org
service.llvm.org
services.llvm.org
boost.org
www.boost.org
docs.boost.org
doc.boost.org
developer.boost.org
developers.boost.org
learn.boost.org
support.boost.org
help.boost.org
status.boost.org
api.boost.org
cdn.boost.org
static.boost.org
assets.boost.org
download.boost.org
downloads.boost.org
files.boost.org
resources.boost.org
community.boost.org
blog.boost.org
security.boost.org
updates.boost.org
packages.boost.org
repo.boost.org
registry.boost.org
pkg.boost.org
mirror.boost.org
mirrors.boost.org
forum.boost.org
forums.boost.org
manual.boost.org
training.boost.org
events.boost.org
news.boost.org
www2.boost.org
portal.boost.org
service.boost.org
services.boost.org
qt.io
www.qt.io
docs.qt.io
doc.qt.io
developer.qt.io
developers.qt.io
learn.qt.io
support.qt.io
help.qt.io
status.qt.io
api.qt.io
cdn.qt.io
static.qt.io
assets.qt.io
download.qt.io
downloads.qt.io
files.qt.io
resources.qt.io
community.qt.io
blog.qt.io
security.qt.io
updates.qt.io
packages.qt.io
repo.qt.io
registry.qt.io
pkg.qt.io
mirror.qt.io
mirrors.qt.io
forum.qt.io
forums.qt.io
manual.qt.io
training.qt.io
events.qt.io
news.qt.io
www2.qt.io
portal.qt.io
service.qt.io
services.qt.io
kde.org
www.kde.org
docs.kde.org
doc.kde.org
developer.kde.org
developers.kde.org
learn.kde.org
support.kde.org
help.kde.org
status.kde.org
api.kde.org
cdn.kde.org
static.kde.org
assets.kde.org
download.kde.org
downloads.kde.org
files.kde.org
resources.kde.org
community.kde.org
blog.kde.org
security.kde.org
updates.kde.org
packages.kde.org
repo.kde.org
registry.kde.org
pkg.kde.org
mirror.kde.org
mirrors.kde.org
forum.kde.org
forums.kde.org
manual.kde.org
training.kde.org
events.kde.org
news.kde.org
www2.kde.org
portal.kde.org
service.kde.org
services.kde.org
gnome.org
www.gnome.org
docs.gnome.org
doc.gnome.org
developer.gnome.org
developers.gnome.org
learn.gnome.org
support.gnome.org
help.gnome.org
status.gnome.org
api.gnome.org
cdn.gnome.org
static.gnome.org
assets.gnome.org
download.gnome.org
downloads.gnome.org
files.gnome.org
resources.gnome.org
community.gnome.org
blog.gnome.org
security.gnome.org
updates.gnome.org
packages.gnome.org
repo.gnome.org
registry.gnome.org
pkg.gnome.org
mirror.gnome.org
mirrors.gnome.org
forum.gnome.org
forums.gnome.org
manual.gnome.org
training.gnome.org
events.gnome.org
news.gnome.org
www2.gnome.org
portal.gnome.org
service.gnome.org
services.gnome.org
letsencrypt.org
www.letsencrypt.org
docs.letsencrypt.org
doc.letsencrypt.org
developer.letsencrypt.org
developers.letsencrypt.org
learn.letsencrypt.org
support.letsencrypt.org
help.letsencrypt.org
status.letsencrypt.org
api.letsencrypt.org
cdn.letsencrypt.org
static.letsencrypt.org
assets.letsencrypt.org
download.letsencrypt.org
downloads.letsencrypt.org
files.letsencrypt.org
resources.letsencrypt.org
community.letsencrypt.org
blog.letsencrypt.org
security.letsencrypt.org
updates.letsencrypt.org
packages.letsencrypt.org
repo.letsencrypt.org
registry.letsencrypt.org
pkg.letsencrypt.org
mirror.letsencrypt.org
mirrors.letsencrypt.org
forum.letsencrypt.org
forums.letsencrypt.org
manual.letsencrypt.org
training.letsencrypt.org
events.letsencrypt.org
news.letsencrypt.org
www2.letsencrypt.org
portal.letsencrypt.org
service.letsencrypt.org
services.letsencrypt.org
owasp.org
www.owasp.org
docs.owasp.org
doc.owasp.org
developer.owasp.org
developers.owasp.org
learn.owasp.org
support.owasp.org
help.owasp.org
status.owasp.org
api.owasp.org
cdn.owasp.org
static.owasp.org
assets.owasp.org
download.owasp.org
downloads.owasp.org
files.owasp.org
resources.owasp.org
community.owasp.org
blog.owasp.org
security.owasp.org
updates.owasp.org
packages.owasp.org
repo.owasp.org
registry.owasp.org
pkg.owasp.org
mirror.owasp.org
mirrors.owasp.org
forum.owasp.org
forums.owasp.org
manual.owasp.org
training.owasp.org
events.owasp.org
news.owasp.org
www2.owasp.org
portal.owasp.org
service.owasp.org
services.owasp.org
openjsf.org
www.openjsf.org
docs.openjsf.org
doc.openjsf.org
developer.openjsf.org
developers.openjsf.org
learn.openjsf.org
support.openjsf.org
help.openjsf.org
status.openjsf.org
api.openjsf.org
cdn.openjsf.org
static.openjsf.org
assets.openjsf.org
download.openjsf.org
downloads.openjsf.org
files.openjsf.org
resources.openjsf.org
community.openjsf.org
blog.openjsf.org
security.openjsf.org
updates.openjsf.org
packages.openjsf.org
repo.openjsf.org
registry.openjsf.org
pkg.openjsf.org
mirror.openjsf.org
mirrors.openjsf.org
forum.openjsf.org
forums.openjsf.org
manual.openjsf.org
training.openjsf.org
events.openjsf.org
news.openjsf.org
www2.openjsf.org
portal.openjsf.org
service.openjsf.org
services.openjsf.org
opentelemetry.io
www.opentelemetry.io
docs.opentelemetry.io
doc.opentelemetry.io
developer.opentelemetry.io
developers.opentelemetry.io
learn.opentelemetry.io
support.opentelemetry.io
help.opentelemetry.io
status.opentelemetry.io
api.opentelemetry.io
cdn.opentelemetry.io
static.opentelemetry.io
assets.opentelemetry.io
download.opentelemetry.io
downloads.opentelemetry.io
files.opentelemetry.io
resources.opentelemetry.io
community.opentelemetry.io
blog.opentelemetry.io
security.opentelemetry.io
updates.opentelemetry.io
packages.opentelemetry.io
repo.opentelemetry.io
registry.opentelemetry.io
pkg.opentelemetry.io
mirror.opentelemetry.io
mirrors.opentelemetry.io
forum.opentelemetry.io
forums.opentelemetry.io
manual.opentelemetry.io
training.opentelemetry.io
events.opentelemetry.io
news.opentelemetry.io
www2.opentelemetry.io
portal.opentelemetry.io
service.opentelemetry.io
services.opentelemetry.io
prometheus.io
www.prometheus.io
docs.prometheus.io
doc.prometheus.io
developer.prometheus.io
developers.prometheus.io
learn.prometheus.io
support.prometheus.io
help.prometheus.io
status.prometheus.io
api.prometheus.io
cdn.prometheus.io
static.prometheus.io
assets.prometheus.io
download.prometheus.io
downloads.prometheus.io
files.prometheus.io
resources.prometheus.io
community.prometheus.io
blog.prometheus.io
security.prometheus.io
updates.prometheus.io
packages.prometheus.io
repo.prometheus.io
registry.prometheus.io
pkg.prometheus.io
mirror.prometheus.io
mirrors.prometheus.io
forum.prometheus.io
forums.prometheus.io
manual.prometheus.io
training.prometheus.io
events.prometheus.io
news.prometheus.io
www2.prometheus.io
portal.prometheus.io
service.prometheus.io
services.prometheus.io
grafana.com
www.grafana.com
docs.grafana.com
doc.grafana.com
developer.grafana.com
developers.grafana.com
learn.grafana.com
support.grafana.com
help.grafana.com
status.grafana.com
api.grafana.com
cdn.grafana.com
static.grafana.com
assets.grafana.com
download.grafana.com
downloads.grafana.com
files.grafana.com
resources.grafana.com
community.grafana.com
blog.grafana.com
security.grafana.com
updates.grafana.com
packages.grafana.com
repo.grafana.com
registry.grafana.com
pkg.grafana.com
mirror.grafana.com
mirrors.grafana.com
forum.grafana.com
forums.grafana.com
manual.grafana.com
training.grafana.com
events.grafana.com
news.grafana.com
www2.grafana.com
portal.grafana.com
service.grafana.com
services.grafana.com
debian.org
docs.debian.org
doc.debian.org
developer.debian.org
developers.debian.org
learn.debian.org
support.debian.org
help.debian.org
status.debian.org
api.debian.org
cdn.debian.org
static.debian.org
assets.debian.org
download.debian.org
downloads.debian.org
files.debian.org
resources.debian.org
community.debian.org
blog.debian.org
security.debian.org
updates.debian.org
packages.debian.org
repo.debian.org
registry.debian.org
pkg.debian.org
mirror.debian.org
mirrors.debian.org
forum.debian.org
forums.debian.org
manual.debian.org
training.debian.org
events.debian.org
news.debian.org
www2.debian.org
portal.debian.org
service.debian.org
services.debian.org
ubuntu.com
docs.ubuntu.com
doc.ubuntu.com
developer.ubuntu.com
developers.ubuntu.com
learn.ubuntu.com
support.ubuntu.com
help.ubuntu.com
status.ubuntu.com
api.ubuntu.com
cdn.ubuntu.com
static.ubuntu.com
assets.ubuntu.com
download.ubuntu.com
downloads.ubuntu.com
files.ubuntu.com
resources.ubuntu.com
community.ubuntu.com
blog.ubuntu.com
security.ubuntu.com
updates.ubuntu.com
packages.ubuntu.com
repo.ubuntu.com
registry.ubuntu.com
pkg.ubuntu.com
mirror.ubuntu.com
mirrors.ubuntu.com
forum.ubuntu.com
forums.ubuntu.com
manual.ubuntu.com
training.ubuntu.com
events.ubuntu.com
news.ubuntu.com
www2.ubuntu.com
portal.ubuntu.com
service.ubuntu.com
services.ubuntu.com
alpinelinux.org
www.alpinelinux.org
docs.alpinelinux.org
doc.alpinelinux.org
developer.alpinelinux.org
developers.alpinelinux.org
learn.alpinelinux.org
support.alpinelinux.org
help.alpinelinux.org
status.alpinelinux.org
api.alpinelinux.org
cdn.alpinelinux.org
static.alpinelinux.org
assets.alpinelinux.org
download.alpinelinux.org
downloads.alpinelinux.org
files.alpinelinux.org
resources.alpinelinux.org
community.alpinelinux.org
blog.alpinelinux.org
security.alpinelinux.org
updates.alpinelinux.org
packages.alpinelinux.org
repo.alpinelinux.org
registry.alpinelinux.org
pkg.alpinelinux.org
mirror.alpinelinux.org
mirrors.alpinelinux.org
forum.alpinelinux.org
forums.alpinelinux.org
manual.alpinelinux.org
training.alpinelinux.org
events.alpinelinux.org
news.alpinelinux.org
www2.alpinelinux.org
portal.alpinelinux.org
service.alpinelinux.org
services.alpinelinux.org
fedoraproject.org
www.fedoraproject.org
docs.fedoraproject.org
doc.fedoraproject.org
developer.fedoraproject.org
developers.fedoraproject.org
learn.fedoraproject.org
support.fedoraproject.org
help.fedoraproject.org
status.fedoraproject.org
api.fedoraproject.org
cdn.fedoraproject.org
static.fedoraproject.org
assets.fedoraproject.org
download.fedoraproject.org
downloads.fedoraproject.org
files.fedoraproject.org
resources.fedoraproject.org
community.fedoraproject.org
blog.fedoraproject.org
security.fedoraproject.org
updates.fedoraproject.org
packages.fedoraproject.org
repo.fedoraproject.org
registry.fedoraproject.org
pkg.fedoraproject.org
mirror.fedoraproject.org
mirrors.fedoraproject.org
forum.fedoraproject.org
forums.fedoraproject.org
manual.fedoraproject.org
training.fedoraproject.org
events.fedoraproject.org
news.fedoraproject.org
www2.fedoraproject.org
portal.fedoraproject.org
service.fedoraproject.org
services.fedoraproject.org
centos.org
www.centos.org
docs.centos.org
doc.centos.org
developer.centos.org
developers.centos.org
learn.centos.org
support.centos.org
help.centos.org
status.centos.org
api.centos.org
cdn.centos.org
static.centos.org
assets.centos.org
download.centos.org
downloads.centos.org
files.centos.org
resources.centos.org
community.centos.org
blog.centos.org
security.centos.org
updates.centos.org
packages.centos.org
repo.centos.org
registry.centos.org
pkg.centos.org
mirror.centos.org
mirrors.centos.org
forum.centos.org
forums.centos.org
manual.centos.org
training.centos.org
events.centos.org
news.centos.org
www2.centos.org
portal.centos.org
service.centos.org
services.centos.org
rockylinux.org
www.rockylinux.org
docs.rockylinux.org
doc.rockylinux.org
developer.rockylinux.org
developers.rockylinux.org
learn.rockylinux.org
support.rockylinux.org
help.rockylinux.org
status.rockylinux.org
api.rockylinux.org
cdn.rockylinux.org
static.rockylinux.org
assets.rockylinux.org
download.rockylinux.org
downloads.rockylinux.org
files.rockylinux.org
resources.rockylinux.org
community.rockylinux.org
blog.rockylinux.org
security.rockylinux.org
updates.rockylinux.org
packages.rockylinux.org
repo.rockylinux.org
registry.rockylinux.org
pkg.rockylinux.org
mirror.rockylinux.org
mirrors.rockylinux.org
forum.rockylinux.org
forums.rockylinux.org
manual.rockylinux.org
training.rockylinux.org
events.rockylinux.org
news.rockylinux.org
www2.rockylinux.org
portal.rockylinux.org
service.rockylinux.org
services.rockylinux.org
almalinux.org
www.almalinux.org
docs.almalinux.org
doc.almalinux.org
developer.almalinux.org
developers.almalinux.org
learn.almalinux.org
support.almalinux.org
help.almalinux.org
status.almalinux.org
api.almalinux.org
cdn.almalinux.org
static.almalinux.org
assets.almalinux.org
download.almalinux.org
downloads.almalinux.org
files.almalinux.org
resources.almalinux.org
community.almalinux.org
blog.almalinux.org
security.almalinux.org
updates.almalinux.org
packages.almalinux.org
repo.almalinux.org
registry.almalinux.org
pkg.almalinux.org
mirror.almalinux.org
mirrors.almalinux.org
forum.almalinux.org
forums.almalinux.org
manual.almalinux.org
training.almalinux.org
events.almalinux.org
news.almalinux.org
www2.almalinux.org
portal.almalinux.org
service.almalinux.org
services.almalinux.org
archlinux.org
www.archlinux.org
docs.archlinux.org
doc.archlinux.org
developer.archlinux.org
developers.archlinux.org
learn.archlinux.org
support.archlinux.org
help.archlinux.org
status.archlinux.org
api.archlinux.org
cdn.archlinux.org
static.archlinux.org
assets.archlinux.org
download.archlinux.org
downloads.archlinux.org
files.archlinux.org
resources.archlinux.org
community.archlinux.org
blog.archlinux.org
security.archlinux.org
updates.archlinux.org
packages.archlinux.org
repo.archlinux.org
registry.archlinux.org
pkg.archlinux.org
mirror.archlinux.org
mirrors.archlinux.org
forum.archlinux.org
forums.archlinux.org
manual.archlinux.org
training.archlinux.org
events.archlinux.org
news.archlinux.org
www2.archlinux.org
portal.archlinux.org
service.archlinux.org
services.archlinux.org
gentoo.org
www.gentoo.org
docs.gentoo.org
doc.gentoo.org
developer.gentoo.org
developers.gentoo.org
learn.gentoo.org
support.gentoo.org
help.gentoo.org
status.gentoo.org
api.gentoo.org
cdn.gentoo.org
static.gentoo.org
assets.gentoo.org
download.gentoo.org
downloads.gentoo.org
files.gentoo.org
resources.gentoo.org
community.gentoo.org
blog.gentoo.org
security.gentoo.org
updates.gentoo.org
packages.gentoo.org
repo.gentoo.org
registry.gentoo.org
pkg.gentoo.org
mirror.gentoo.org
mirrors.gentoo.org
forum.gentoo.org
forums.gentoo.org
manual.gentoo.org
training.gentoo.org
events.gentoo.org
news.gentoo.org
www2.gentoo.org
portal.gentoo.org
service.gentoo.org
services.gentoo.org
freebsd.org
www.freebsd.org
docs.freebsd.org
doc.freebsd.org
developer.freebsd.org
developers.freebsd.org
learn.freebsd.org
support.freebsd.org
help.freebsd.org
status.freebsd.org
api.freebsd.org
cdn.freebsd.org
static.freebsd.org
assets.freebsd.org
download.freebsd.org
downloads.freebsd.org
files.freebsd.org
resources.freebsd.org
community.freebsd.org
blog.freebsd.org
security.freebsd.org
updates.freebsd.org
packages.freebsd.org
repo.freebsd.org
registry.freebsd.org
pkg.freebsd.org
mirror.freebsd.org
mirrors.freebsd.org
forum.freebsd.org
forums.freebsd.org
manual.freebsd.org
training.freebsd.org
events.freebsd.org
news.freebsd.org
www2.freebsd.org
portal.freebsd.org
service.freebsd.org
services.freebsd.org
openbsd.org
www.openbsd.org
docs.openbsd.org
doc.openbsd.org
developer.openbsd.org
developers.openbsd.org
learn.openbsd.org
support.openbsd.org
help.openbsd.org
status.openbsd.org
api.openbsd.org
cdn.openbsd.org
static.openbsd.org
assets.openbsd.org
download.openbsd.org
downloads.openbsd.org
files.openbsd.org
resources.openbsd.org
community.openbsd.org
blog.openbsd.org
security.openbsd.org
updates.openbsd.org
packages.openbsd.org
repo.openbsd.org
registry.openbsd.org
pkg.openbsd.org
mirror.openbsd.org
mirrors.openbsd.org
forum.openbsd.org
forums.openbsd.org
manual.openbsd.org
training.openbsd.org
events.openbsd.org
news.openbsd.org
www2.openbsd.org
portal.openbsd.org
service.openbsd.org
services.openbsd.org
netbsd.org
www.netbsd.org
docs.netbsd.org
doc.netbsd.org
developer.netbsd.org
developers.netbsd.org
learn.netbsd.org
support.netbsd.org
help.netbsd.org
status.netbsd.org
api.netbsd.org
cdn.netbsd.org
static.netbsd.org
assets.netbsd.org
download.netbsd.org
downloads.netbsd.org
files.netbsd.org
resources.netbsd.org
community.netbsd.org
blog.netbsd.org
security.netbsd.org
updates.netbsd.org
packages.netbsd.org
repo.netbsd.org
registry.netbsd.org
pkg.netbsd.org
mirror.netbsd.org
mirrors.netbsd.org
forum.netbsd.org
forums.netbsd.org
manual.netbsd.org
training.netbsd.org
events.netbsd.org
news.netbsd.org
www2.netbsd.org
portal.netbsd.org
service.netbsd.org
services.netbsd.org
python.org
doc.python.org
developer.python.org
developers.python.org
learn.python.org
support.python.org
help.python.org
status.python.org
api.python.org
cdn.python.org
static.python.org
assets.python.org
download.python.org
downloads.python.org
files.python.org
resources.python.org
community.python.org
blog.python.org
security.python.org
updates.python.org
packages.python.org
repo.python.org
registry.python.org
pkg.python.org
mirror.python.org
mirrors.python.org
forum.python.org
forums.python.org
manual.python.org
training.python.org
events.python.org
news.python.org
www2.python.org
portal.python.org
service.python.org
services.python.org
www.pypi.org
docs.pypi.org
doc.pypi.org
developer.pypi.org
developers.pypi.org
learn.pypi.org
support.pypi.org
help.pypi.org
status.pypi.org
api.pypi.org
cdn.pypi.org
static.pypi.org
assets.pypi.org
download.pypi.org
downloads.pypi.org
files.pypi.org
resources.pypi.org
community.pypi.org
blog.pypi.org
security.pypi.org
updates.pypi.org
packages.pypi.org
repo.pypi.org
registry.pypi.org
pkg.pypi.org
mirror.pypi.org
mirrors.pypi.org
forum.pypi.org
forums.pypi.org
manual.pypi.org
training.pypi.org
events.pypi.org
news.pypi.org
www2.pypi.org
portal.pypi.org
service.pypi.org
services.pypi.org
rust-lang.org
docs.rust-lang.org
doc.rust-lang.org
developer.rust-lang.org
developers.rust-lang.org
learn.rust-lang.org
support.rust-lang.org
help.rust-lang.org
status.rust-lang.org
api.rust-lang.org
cdn.rust-lang.org
static.rust-lang.org
assets.rust-lang.org
download.rust-lang.org
downloads.rust-lang.org
files.rust-lang.org
resources.rust-lang.org
community.rust-lang.org
blog.rust-lang.org
security.rust-lang.org
updates.rust-lang.org
packages.rust-lang.org
repo.rust-lang.org
registry.rust-lang.org
pkg.rust-lang.org
mirror.rust-lang.org
mirrors.rust-lang.org
forum.rust-lang.org
forums.rust-lang.org
manual.rust-lang.org
training.rust-lang.org
events.rust-lang.org
news.rust-lang.org
www2.rust-lang.org
portal.rust-lang.org
service.rust-lang.org
services.rust-lang.org
www.crates.io
docs.crates.io
doc.crates.io
developer.crates.io
developers.crates.io
learn.crates.io
support.crates.io
help.crates.io
status.crates.io
api.crates.io
cdn.crates.io
static.crates.io
assets.crates.io
download.crates.io
downloads.crates.io
files.crates.io
resources.crates.io
community.crates.io
blog.crates.io
security.crates.io
updates.crates.io
packages.crates.io
repo.crates.io
registry.crates.io
pkg.crates.io
mirror.crates.io
mirrors.crates.io
forum.crates.io
forums.crates.io
manual.crates.io
training.crates.io
events.crates.io
news.crates.io
www2.crates.io
portal.crates.io
service.crates.io
services.crates.io
www.nodejs.org
docs.nodejs.org
doc.nodejs.org
developer.nodejs.org
developers.nodejs.org
learn.nodejs.org
support.nodejs.org
help.nodejs.org
status.nodejs.org
api.nodejs.org
cdn.nodejs.org
static.nodejs.org
assets.nodejs.org
download.nodejs.org
downloads.nodejs.org
files.nodejs.org
resources.nodejs.org
community.nodejs.org
blog.nodejs.org
security.nodejs.org
updates.nodejs.org
packages.nodejs.org
repo.nodejs.org
registry.nodejs.org
pkg.nodejs.org
mirror.nodejs.org
mirrors.nodejs.org
forum.nodejs.org
forums.nodejs.org
manual.nodejs.org
training.nodejs.org
events.nodejs.org
news.nodejs.org
www2.nodejs.org
portal.nodejs.org
service.nodejs.org
services.nodejs.org
npmjs.com
docs.npmjs.com
doc.npmjs.com
developer.npmjs.com
developers.npmjs.com
learn.npmjs.com
support.npmjs.com
help.npmjs.com
status.npmjs.com
api.npmjs.com
cdn.npmjs.com
static.npmjs.com
assets.npmjs.com
download.npmjs.com
downloads.npmjs.com
files.npmjs.com
resources.npmjs.com
community.npmjs.com
blog.npmjs.com
security.npmjs.com
updates.npmjs.com
packages.npmjs.com
repo.npmjs.com
registry.npmjs.com
pkg.npmjs.com
mirror.npmjs.com
mirrors.npmjs.com
forum.npmjs.com
forums.npmjs.com
manual.npmjs.com
training.npmjs.com
events.npmjs.com
news.npmjs.com
www2.npmjs.com
portal.npmjs.com
service.npmjs.com
services.npmjs.com
npmjs.org
www.npmjs.org
docs.npmjs.org
doc.npmjs.org
developer.npmjs.org
developers.npmjs.org
learn.npmjs.org
support.npmjs.org
help.npmjs.org
status.npmjs.org
api.npmjs.org
cdn.npmjs.org
static.npmjs.org
assets.npmjs.org
download.npmjs.org
downloads.npmjs.org
files.npmjs.org
resources.npmjs.org
community.npmjs.org
blog.npmjs.org
security.npmjs.org
updates.npmjs.org
packages.npmjs.org
repo.npmjs.org
registry.npmjs.org
pkg.npmjs.org
mirror.npmjs.org
mirrors.npmjs.org
forum.npmjs.org
forums.npmjs.org
manual.npmjs.org
training.npmjs.org
events.npmjs.org
news.npmjs.org
www2.npmjs.org
portal.npmjs.org
service.npmjs.org
services.npmjs.org
php.net
www.php.net
docs.php.net
doc.php.net
developer.php.net
developers.php.net
learn.php.net
support.php.net
help.php.net
status.php.net
api.php.net
cdn.php.net
static.php.net
assets.php.net
download.php.net
downloads.php.net
files.php.net
resources.php.net
community.php.net
blog.php.net
security.php.net
updates.php.net
packages.php.net
repo.php.net
registry.php.net
pkg.php.net
mirror.php.net
mirrors.php.net
forum.php.net
forums.php.net
manual.php.net
training.php.net
events.php.net
news.php.net
www2.php.net
portal.php.net
service.php.net
services.php.net
ruby-lang.org
www.ruby-lang.org
docs.ruby-lang.org
doc.ruby-lang.org
developer.ruby-lang.org
developers.ruby-lang.org
learn.ruby-lang.org
support.ruby-lang.org
help.ruby-lang.org
status.ruby-lang.org
api.ruby-lang.org
cdn.ruby-lang.org
static.ruby-lang.org
assets.ruby-lang.org
download.ruby-lang.org
downloads.ruby-lang.org
files.ruby-lang.org
resources.ruby-lang.org
community.ruby-lang.org
blog.ruby-lang.org
security.ruby-lang.org
updates.ruby-lang.org
packages.ruby-lang.org
repo.ruby-lang.org
registry.ruby-lang.org
pkg.ruby-lang.org
mirror.ruby-lang.org
mirrors.ruby-lang.org
forum.ruby-lang.org
forums.ruby-lang.org
manual.ruby-lang.org
training.ruby-lang.org
events.ruby-lang.org
news.ruby-lang.org
www2.ruby-lang.org
portal.ruby-lang.org
service.ruby-lang.org
services.ruby-lang.org
perl.org
www.perl.org
docs.perl.org
doc.perl.org
developer.perl.org
developers.perl.org
learn.perl.org
support.perl.org
help.perl.org
status.perl.org
api.perl.org
cdn.perl.org
static.perl.org
assets.perl.org
download.perl.org
downloads.perl.org
files.perl.org
resources.perl.org
community.perl.org
blog.perl.org
security.perl.org
updates.perl.org
packages.perl.org
repo.perl.org
registry.perl.org
pkg.perl.org
mirror.perl.org
mirrors.perl.org
forum.perl.org
forums.perl.org
manual.perl.org
training.perl.org
events.perl.org
news.perl.org
www2.perl.org
portal.perl.org
service.perl.org
services.perl.org
lua.org
www.lua.org
docs.lua.org
doc.lua.org
developer.lua.org
developers.lua.org
learn.lua.org
support.lua.org
help.lua.org
status.lua.org
api.lua.org
cdn.lua.org
static.lua.org
assets.lua.org
download.lua.org
downloads.lua.org
files.lua.org
resources.lua.org
community.lua.org
blog.lua.org
security.lua.org
updates.lua.org
packages.lua.org
repo.lua.org
registry.lua.org
pkg.lua.org
mirror.lua.org
mirrors.lua.org
forum.lua.org
forums.lua.org
manual.lua.org
training.lua.org
events.lua.org
news.lua.org
www2.lua.org
portal.lua.org
service.lua.org
services.lua.org
typescriptlang.org
www.typescriptlang.org
docs.typescriptlang.org
doc.typescriptlang.org
developer.typescriptlang.org
developers.typescriptlang.org
learn.typescriptlang.org
support.typescriptlang.org
help.typescriptlang.org
status.typescriptlang.org
api.typescriptlang.org
cdn.typescriptlang.org
static.typescriptlang.org
assets.typescriptlang.org
download.typescriptlang.org
downloads.typescriptlang.org
files.typescriptlang.org
resources.typescriptlang.org
community.typescriptlang.org
blog.typescriptlang.org
security.typescriptlang.org
updates.typescriptlang.org
packages.typescriptlang.org
repo.typescriptlang.org
registry.typescriptlang.org
pkg.typescriptlang.org
mirror.typescriptlang.org
mirrors.typescriptlang.org
forum.typescriptlang.org
forums.typescriptlang.org
manual.typescriptlang.org
training.typescriptlang.org
events.typescriptlang.org
news.typescriptlang.org
www2.typescriptlang.org
portal.typescriptlang.org
service.typescriptlang.org
services.typescriptlang.org
scala-lang.org
www.scala-lang.org
docs.scala-lang.org
doc.scala-lang.org
developer.scala-lang.org
developers.scala-lang.org
learn.scala-lang.org
support.scala-lang.org
help.scala-lang.org
status.scala-lang.org
api.scala-lang.org
cdn.scala-lang.org
static.scala-lang.org
assets.scala-lang.org
download.scala-lang.org
downloads.scala-lang.org
files.scala-lang.org
resources.scala-lang.org
community.scala-lang.org
blog.scala-lang.org
security.scala-lang.org
updates.scala-lang.org
packages.scala-lang.org
repo.scala-lang.org
registry.scala-lang.org
pkg.scala-lang.org
mirror.scala-lang.org
mirrors.scala-lang.org
forum.scala-lang.org
forums.scala-lang.org
manual.scala-lang.org
training.scala-lang.org
events.scala-lang.org
news.scala-lang.org
www2.scala-lang.org
portal.scala-lang.org
service.scala-lang.org
services.scala-lang.org
spring.io
www.spring.io
docs.spring.io
doc.spring.io
developer.spring.io
developers.spring.io
learn.spring.io
support.spring.io
help.spring.io
status.spring.io
api.spring.io
cdn.spring.io
static.spring.io
assets.spring.io
download.spring.io
downloads.spring.io
files.spring.io
resources.spring.io
community.spring.io
blog.spring.io
security.spring.io
updates.spring.io
packages.spring.io
repo.spring.io
registry.spring.io
pkg.spring.io
mirror.spring.io
mirrors.spring.io
forum.spring.io
forums.spring.io
manual.spring.io
training.spring.io
events.spring.io
news.spring.io
www2.spring.io
portal.spring.io
service.spring.io
services.spring.io
gradle.org
www.gradle.org
docs.gradle.org
doc.gradle.org
developer.gradle.org
developers.gradle.org
learn.gradle.org
support.gradle.org
help.gradle.org
status.gradle.org
api.gradle.org
cdn.gradle.org
static.gradle.org
assets.gradle.org
download.gradle.org
downloads.gradle.org
files.gradle.org
resources.gradle.org
community.gradle.org
blog.gradle.org
security.gradle.org
updates.gradle.org
packages.gradle.org
repo.gradle.org
registry.gradle.org
pkg.gradle.org
mirror.gradle.org
mirrors.gradle.org
forum.gradle.org
forums.gradle.org
manual.gradle.org
training.gradle.org
events.gradle.org
news.gradle.org
www2.gradle.org
portal.gradle.org
service.gradle.org
services.gradle.org
postgresql.org
docs.postgresql.org
doc.postgresql.org
developer.postgresql.org
developers.postgresql.org
learn.postgresql.org
support.postgresql.org
help.postgresql.org
status.postgresql.org
api.postgresql.org
cdn.postgresql.org
static.postgresql.org
assets.postgresql.org
download.postgresql.org
downloads.postgresql.org
files.postgresql.org
resources.postgresql.org
community.postgresql.org
blog.postgresql.org
security.postgresql.org
updates.postgresql.org
packages.postgresql.org
repo.postgresql.org
registry.postgresql.org
pkg.postgresql.org
mirror.postgresql.org
mirrors.postgresql.org
forum.postgresql.org
forums.postgresql.org
manual.postgresql.org
training.postgresql.org
events.postgresql.org
news.postgresql.org
www2.postgresql.org
portal.postgresql.org
service.postgresql.org
services.postgresql.org
sqlite.org
docs.sqlite.org
doc.sqlite.org
developer.sqlite.org
developers.sqlite.org
learn.sqlite.org
support.sqlite.org
help.sqlite.org
status.sqlite.org
api.sqlite.org
cdn.sqlite.org
static.sqlite.org
assets.sqlite.org
download.sqlite.org
downloads.sqlite.org
files.sqlite.org
resources.sqlite.org
community.sqlite.org
blog.sqlite.org
security.sqlite.org
updates.sqlite.org
packages.sqlite.org
repo.sqlite.org
registry.sqlite.org
pkg.sqlite.org
mirror.sqlite.org
mirrors.sqlite.org
forum.sqlite.org
forums.sqlite.org
manual.sqlite.org
training.sqlite.org
events.sqlite.org
news.sqlite.org
www2.sqlite.org
portal.sqlite.org
service.sqlite.org
services.sqlite.org
www.mariadb.org
docs.mariadb.org
doc.mariadb.org
developer.mariadb.org
developers.mariadb.org
learn.mariadb.org
support.mariadb.org
help.mariadb.org
status.mariadb.org
api.mariadb.org
cdn.mariadb.org
static.mariadb.org
assets.mariadb.org
download.mariadb.org
downloads.mariadb.org
files.mariadb.org
resources.mariadb.org
community.mariadb.org
blog.mariadb.org
security.mariadb.org
updates.mariadb.org
packages.mariadb.org
repo.mariadb.org
registry.mariadb.org
pkg.mariadb.org
mirror.mariadb.org
mirrors.mariadb.org
forum.mariadb.org
forums.mariadb.org
manual.mariadb.org
training.mariadb.org
events.mariadb.org
news.mariadb.org
www2.mariadb.org
portal.mariadb.org
service.mariadb.org
services.mariadb.org
mysql.com
docs.mysql.com
doc.mysql.com
developer.mysql.com
developers.mysql.com
learn.mysql.com
support.mysql.com
help.mysql.com
status.mysql.com
api.mysql.com
cdn.mysql.com
static.mysql.com
assets.mysql.com
download.mysql.com
downloads.mysql.com
files.mysql.com
resources.mysql.com
community.mysql.com
blog.mysql.com
security.mysql.com
updates.mysql.com
packages.mysql.com
repo.mysql.com
registry.mysql.com
pkg.mysql.com
mirror.mysql.com
mirrors.mysql.com
forum.mysql.com
forums.mysql.com
manual.mysql.com
training.mysql.com
events.mysql.com
news.mysql.com
www2.mysql.com
portal.mysql.com
service.mysql.com
services.mysql.com
redis.io
www.redis.io
docs.redis.io
doc.redis.io
developer.redis.io
developers.redis.io
learn.redis.io
support.redis.io
help.redis.io
status.redis.io
api.redis.io
cdn.redis.io
static.redis.io
assets.redis.io
download.redis.io
downloads.redis.io
files.redis.io
resources.redis.io
community.redis.io
blog.redis.io
security.redis.io
updates.redis.io
packages.redis.io
repo.redis.io
registry.redis.io
pkg.redis.io
mirror.redis.io
mirrors.redis.io
forum.redis.io
forums.redis.io
manual.redis.io
training.redis.io
events.redis.io
news.redis.io
www2.redis.io
portal.redis.io
service.redis.io
services.redis.io
redis.com
www.redis.com
docs.redis.com
doc.redis.com
developer.redis.com
developers.redis.com
learn.redis.com
support.redis.com
help.redis.com
status.redis.com
api.redis.com
cdn.redis.com
static.redis.com
assets.redis.com
download.redis.com
downloads.redis.com
files.redis.com
resources.redis.com
community.redis.com
blog.redis.com
security.redis.com
updates.redis.com
packages.redis.com
repo.redis.com
registry.redis.com
pkg.redis.com
mirror.redis.com
mirrors.redis.com
forum.redis.com
forums.redis.com
manual.redis.com
training.redis.com
events.redis.com
news.redis.com
www2.redis.com
portal.redis.com
service.redis.com
services.redis.com
mongodb.com
www.mongodb.com
docs.mongodb.com
doc.mongodb.com
developer.mongodb.com
developers.mongodb.com
learn.mongodb.com
support.mongodb.com
help.mongodb.com
status.mongodb.com
api.mongodb.com
cdn.mongodb.com
static.mongodb.com
assets.mongodb.com
download.mongodb.com
downloads.mongodb.com
files.mongodb.com
resources.mongodb.com
community.mongodb.com
blog.mongodb.com
security.mongodb.com
updates.mongodb.com
packages.mongodb.com
repo.mongodb.com
registry.mongodb.com
pkg.mongodb.com
mirror.mongodb.com
mirrors.mongodb.com
forum.mongodb.com
forums.mongodb.com
manual.mongodb.com
training.mongodb.com
events.mongodb.com
news.mongodb.com
www2.mongodb.com
portal.mongodb.com
service.mongodb.com
services.mongodb.com
elastic.co
www.elastic.co
docs.elastic.co
doc.elastic.co
developer.elastic.co
developers.elastic.co
learn.elastic.co
support.elastic.co
help.elastic.co
status.elastic.co
api.elastic.co
cdn.elastic.co
static.elastic.co
assets.elastic.co
download.elastic.co
downloads.elastic.co
files.elastic.co
resources.elastic.co
community.elastic.co
blog.elastic.co
security.elastic.co
updates.elastic.co
packages.elastic.co
repo.elastic.co
registry.elastic.co
pkg.elastic.co
mirror.elastic.co
mirrors.elastic.co
forum.elastic.co
forums.elastic.co
manual.elastic.co
training.elastic.co
events.elastic.co
news.elastic.co
www2.elastic.co
portal.elastic.co
service.elastic.co
services.elastic.co
confluent.io
docs.confluent.io
doc.confluent.io
developer.confluent.io
developers.confluent.io
learn.confluent.io
support.confluent.io
help.confluent.io
status.confluent.io
api.confluent.io
cdn.confluent.io
static.confluent.io
assets.confluent.io
download.confluent.io
downloads.confluent.io
files.confluent.io
resources.confluent.io
community.confluent.io
blog.confluent.io
security.confluent.io
updates.confluent.io
packages.confluent.io
repo.confluent.io
registry.confluent.io
pkg.confluent.io
mirror.confluent.io
mirrors.confluent.io
forum.confluent.io
forums.confluent.io
manual.confluent.io
training.confluent.io
events.confluent.io
news.confluent.io
www2.confluent.io
portal.confluent.io
service.confluent.io
services.confluent.io
samsung.com
docs.samsung.com
doc.samsung.com
developer.samsung.com
developers.samsung.com
learn.samsung.com
support.samsung.com
help.samsung.com
status.samsung.com
api.samsung.com
cdn.samsung.com
static.samsung.com
assets.samsung.com
download.samsung.com
downloads.samsung.com
files.samsung.com
resources.samsung.com
community.samsung.com
blog.samsung.com
security.samsung.com
updates.samsung.com
packages.samsung.com
repo.samsung.com
registry.samsung.com
pkg.samsung.com
mirror.samsung.com
mirrors.samsung.com
forum.samsung.com
forums.samsung.com
manual.samsung.com
training.samsung.com
events.samsung.com
news.samsung.com
www2.samsung.com
portal.samsung.com
service.samsung.com
services.samsung.com
lenovo.com
docs.lenovo.com
doc.lenovo.com
developer.lenovo.com
developers.lenovo.com
learn.lenovo.com
support.lenovo.com
help.lenovo.com
status.lenovo.com
api.lenovo.com
cdn.lenovo.com
static.lenovo.com
assets.lenovo.com
download.lenovo.com
downloads.lenovo.com
files.lenovo.com
resources.lenovo.com
community.lenovo.com
blog.lenovo.com
security.lenovo.com
updates.lenovo.com
packages.lenovo.com
repo.lenovo.com
registry.lenovo.com
pkg.lenovo.com
mirror.lenovo.com
mirrors.lenovo.com
forum.lenovo.com
forums.lenovo.com
manual.lenovo.com
training.lenovo.com
events.lenovo.com
news.lenovo.com
www2.lenovo.com
portal.lenovo.com
service.lenovo.com
services.lenovo.com
dell.com
docs.dell.com
doc.dell.com
developer.dell.com
developers.dell.com
learn.dell.com
support.dell.com
help.dell.com
status.dell.com
api.dell.com
cdn.dell.com
static.dell.com
assets.dell.com
download.dell.com
downloads.dell.com
files.dell.com
resources.dell.com
community.dell.com
blog.dell.com
security.dell.com
updates.dell.com
packages.dell.com
repo.dell.com
registry.dell.com
pkg.dell.com
mirror.dell.com
mirrors.dell.com
forum.dell.com
forums.dell.com
manual.dell.com
training.dell.com
events.dell.com
news.dell.com
www2.dell.com
portal.dell.com
service.dell.com
services.dell.com
hp.com
www.hp.com
docs.hp.com
doc.hp.com
developer.hp.com
developers.hp.com
learn.hp.com
support.hp.com
help.hp.com
status.hp.com
api.hp.com
cdn.hp.com
static.hp.com
assets.hp.com
download.hp.com
downloads.hp.com
files.hp.com
resources.hp.com
community.hp.com
blog.hp.com
security.hp.com
updates.hp.com
packages.hp.com
repo.hp.com
registry.hp.com
pkg.hp.com
mirror.hp.com
mirrors.hp.com
forum.hp.com
forums.hp.com
manual.hp.com
training.hp.com
events.hp.com
news.hp.com
www2.hp.com
portal.hp.com
service.hp.com
services.hp.com
intel.com
docs.intel.com
doc.intel.com
developer.intel.com
developers.intel.com
learn.intel.com
support.intel.com
help.intel.com
status.intel.com
api.intel.com
cdn.intel.com
static.intel.com
assets.intel.com
download.intel.com
downloads.intel.com
files.intel.com
resources.intel.com
community.intel.com
blog.intel.com
security.intel.com
updates.intel.com
packages.intel.com
repo.intel.com
registry.intel.com
pkg.intel.com
mirror.intel.com
mirrors.intel.com
forum.intel.com
forums.intel.com
manual.intel.com
training.intel.com
events.intel.com
news.intel.com
www2.intel.com
portal.intel.com
service.intel.com
services.intel.com
amd.com
docs.amd.com
doc.amd.com
developer.amd.com
developers.amd.com
learn.amd.com
support.amd.com
help.amd.com
status.amd.com
api.amd.com
cdn.amd.com
static.amd.com
assets.amd.com
download.amd.com
downloads.amd.com
files.amd.com
resources.amd.com
community.amd.com
blog.amd.com
security.amd.com
updates.amd.com
packages.amd.com
repo.amd.com
registry.amd.com
pkg.amd.com
mirror.amd.com
mirrors.amd.com
forum.amd.com
forums.amd.com
manual.amd.com
training.amd.com
events.amd.com
news.amd.com
www2.amd.com
portal.amd.com
service.amd.com
services.amd.com
nvidia.com
docs.nvidia.com
doc.nvidia.com
developer.nvidia.com
developers.nvidia.com
learn.nvidia.com
support.nvidia.com
help.nvidia.com
status.nvidia.com
api.nvidia.com
cdn.nvidia.com
static.nvidia.com
assets.nvidia.com
download.nvidia.com
downloads.nvidia.com
files.nvidia.com
resources.nvidia.com
community.nvidia.com
blog.nvidia.com
security.nvidia.com
updates.nvidia.com
packages.nvidia.com
repo.nvidia.com
registry.nvidia.com
pkg.nvidia.com
mirror.nvidia.com
mirrors.nvidia.com
forum.nvidia.com
forums.nvidia.com
manual.nvidia.com
training.nvidia.com
events.nvidia.com
news.nvidia.com
www2.nvidia.com
portal.nvidia.com
service.nvidia.com
services.nvidia.com
qualcomm.com
www.qualcomm.com
docs.qualcomm.com
doc.qualcomm.com
developer.qualcomm.com
developers.qualcomm.com
learn.qualcomm.com
support.qualcomm.com
help.qualcomm.com
status.qualcomm.com
api.qualcomm.com
cdn.qualcomm.com
static.qualcomm.com
assets.qualcomm.com
download.qualcomm.com
downloads.qualcomm.com
files.qualcomm.com
resources.qualcomm.com
community.qualcomm.com
blog.qualcomm.com
security.qualcomm.com
updates.qualcomm.com
packages.qualcomm.com
repo.qualcomm.com
registry.qualcomm.com
pkg.qualcomm.com
mirror.qualcomm.com
mirrors.qualcomm.com
forum.qualcomm.com
forums.qualcomm.com
manual.qualcomm.com
training.qualcomm.com
events.qualcomm.com
news.qualcomm.com
www2.qualcomm.com
portal.qualcomm.com
service.qualcomm.com
services.qualcomm.com
arm.com
www.arm.com
docs.arm.com
doc.arm.com
developer.arm.com
developers.arm.com
learn.arm.com
support.arm.com
help.arm.com
status.arm.com
api.arm.com
cdn.arm.com
static.arm.com
assets.arm.com
download.arm.com
downloads.arm.com
files.arm.com
resources.arm.com
community.arm.com
blog.arm.com
security.arm.com
updates.arm.com
packages.arm.com
repo.arm.com
registry.arm.com
pkg.arm.com
mirror.arm.com
mirrors.arm.com
forum.arm.com
forums.arm.com
manual.arm.com
training.arm.com
events.arm.com
news.arm.com
www2.arm.com
portal.arm.com
service.arm.com
services.arm.com
broadcom.com
www.broadcom.com
docs.broadcom.com
doc.broadcom.com
developer.broadcom.com
developers.broadcom.com
learn.broadcom.com
support.broadcom.com
help.broadcom.com
status.broadcom.com
api.broadcom.com
cdn.broadcom.com
static.broadcom.com
assets.broadcom.com
download.broadcom.com
downloads.broadcom.com
files.broadcom.com
resources.broadcom.com
community.broadcom.com
blog.broadcom.com
security.broadcom.com
updates.broadcom.com
packages.broadcom.com
repo.broadcom.com
registry.broadcom.com
pkg.broadcom.com
mirror.broadcom.com
mirrors.broadcom.com
forum.broadcom.com
forums.broadcom.com
manual.broadcom.com
training.broadcom.com
events.broadcom.com
news.broadcom.com
www2.broadcom.com
portal.broadcom.com
service.broadcom.com
services.broadcom.com
cisco.com
docs.cisco.com
doc.cisco.com
developer.cisco.com
developers.cisco.com
learn.cisco.com
support.cisco.com
help.cisco.com
status.cisco.com
api.cisco.com
cdn.cisco.com
static.cisco.com
assets.cisco.com
download.cisco.com
downloads.cisco.com
files.cisco.com
resources.cisco.com
community.cisco.com
blog.cisco.com
security.cisco.com
updates.cisco.com
packages.cisco.com
repo.cisco.com
registry.cisco.com
pkg.cisco.com
mirror.cisco.com
mirrors.cisco.com
forum.cisco.com
forums.cisco.com
manual.cisco.com
training.cisco.com
events.cisco.com
news.cisco.com
www2.cisco.com
portal.cisco.com
service.cisco.com
services.cisco.com
juniper.net
www.juniper.net
docs.juniper.net
doc.juniper.net
developer.juniper.net
developers.juniper.net
learn.juniper.net
support.juniper.net
help.juniper.net
status.juniper.net
api.juniper.net
cdn.juniper.net
static.juniper.net
assets.juniper.net
download.juniper.net
downloads.juniper.net
files.juniper.net
resources.juniper.net
community.juniper.net
blog.juniper.net
security.juniper.net
updates.juniper.net
packages.juniper.net
repo.juniper.net
registry.juniper.net
pkg.juniper.net
mirror.juniper.net
mirrors.juniper.net
forum.juniper.net
forums.juniper.net
manual.juniper.net
training.juniper.net
events.juniper.net
news.juniper.net
www2.juniper.net
portal.juniper.net
service.juniper.net
services.juniper.net
huawei.com
docs.huawei.com
doc.huawei.com
developer.huawei.com
developers.huawei.com
learn.huawei.com
support.huawei.com
help.huawei.com
status.huawei.com
api.huawei.com
cdn.huawei.com
static.huawei.com
assets.huawei.com
download.huawei.com
downloads.huawei.com
files.huawei.com
resources.huawei.com
community.huawei.com
blog.huawei.com
security.huawei.com
updates.huawei.com
packages.huawei.com
repo.huawei.com
registry.huawei.com
pkg.huawei.com
mirror.huawei.com
mirrors.huawei.com
forum.huawei.com
forums.huawei.com
manual.huawei.com
training.huawei.com
events.huawei.com
news.huawei.com
www2.huawei.com
portal.huawei.com
service.huawei.com
services.huawei.com
zte.com
www.zte.com
docs.zte.com
doc.zte.com
developer.zte.com
developers.zte.com
learn.zte.com
support.zte.com
help.zte.com
status.zte.com
api.zte.com
cdn.zte.com
static.zte.com
assets.zte.com
download.zte.com
downloads.zte.com
files.zte.com
resources.zte.com
community.zte.com
blog.zte.com
security.zte.com
updates.zte.com
packages.zte.com
repo.zte.com
registry.zte.com
pkg.zte.com
mirror.zte.com
mirrors.zte.com
forum.zte.com
forums.zte.com
manual.zte.com
training.zte.com
events.zte.com
news.zte.com
www2.zte.com
portal.zte.com
service.zte.com
services.zte.com
ericsson.com
docs.ericsson.com
doc.ericsson.com
developer.ericsson.com
developers.ericsson.com
learn.ericsson.com
support.ericsson.com
help.ericsson.com
status.ericsson.com
api.ericsson.com
cdn.ericsson.com
static.ericsson.com
assets.ericsson.com
download.ericsson.com
downloads.ericsson.com
files.ericsson.com
resources.ericsson.com
community.ericsson.com
blog.ericsson.com
security.ericsson.com
updates.ericsson.com
packages.ericsson.com
repo.ericsson.com
registry.ericsson.com
pkg.ericsson.com
mirror.ericsson.com
mirrors.ericsson.com
forum.ericsson.com
forums.ericsson.com
manual.ericsson.com
training.ericsson.com
events.ericsson.com
news.ericsson.com
www2.ericsson.com
portal.ericsson.com
service.ericsson.com
services.ericsson.com
nokia.com
docs.nokia.com
doc.nokia.com
developer.nokia.com
developers.nokia.com
learn.nokia.com
support.nokia.com
help.nokia.com
status.nokia.com
api.nokia.com
cdn.nokia.com
static.nokia.com
assets.nokia.com
download.nokia.com
downloads.nokia.com
files.nokia.com
resources.nokia.com
community.nokia.com
blog.nokia.com
security.nokia.com
updates.nokia.com
packages.nokia.com
repo.nokia.com
registry.nokia.com
pkg.nokia.com
mirror.nokia.com
mirrors.nokia.com
forum.nokia.com
forums.nokia.com
manual.nokia.com
training.nokia.com
events.nokia.com
news.nokia.com
www2.nokia.com
portal.nokia.com
service.nokia.com
services.nokia.com
siemens.com
docs.siemens.com
doc.siemens.com
developer.siemens.com
developers.siemens.com
learn.siemens.com
support.siemens.com
help.siemens.com
status.siemens.com
api.siemens.com
cdn.siemens.com
static.siemens.com
assets.siemens.com
download.siemens.com
downloads.siemens.com
files.siemens.com
resources.siemens.com
community.siemens.com
blog.siemens.com
security.siemens.com
updates.siemens.com
packages.siemens.com
repo.siemens.com
registry.siemens.com
pkg.siemens.com
mirror.siemens.com
mirrors.siemens.com
forum.siemens.com
forums.siemens.com
manual.siemens.com
training.siemens.com
events.siemens.com
news.siemens.com
www2.siemens.com
portal.siemens.com
service.siemens.com
services.siemens.com
bosch.com
www.bosch.com
docs.bosch.com
doc.bosch.com
developer.bosch.com
developers.bosch.com
learn.bosch.com
support.bosch.com
help.bosch.com
status.bosch.com
api.bosch.com
cdn.bosch.com
static.bosch.com
assets.bosch.com
download.bosch.com
downloads.bosch.com
files.bosch.com
resources.bosch.com
community.bosch.com
blog.bosch.com
security.bosch.com
updates.bosch.com
packages.bosch.com
repo.bosch.com
registry.bosch.com
pkg.bosch.com
mirror.bosch.com
mirrors.bosch.com
forum.bosch.com
forums.bosch.com
manual.bosch.com
training.bosch.com
events.bosch.com
news.bosch.com
www2.bosch.com
portal.bosch.com
service.bosch.com
services.bosch.com
sony.com
docs.sony.com
doc.sony.com
developer.sony.com
developers.sony.com
learn.sony.com
support.sony.com
help.sony.com
status.sony.com
api.sony.com
cdn.sony.com
static.sony.com
assets.sony.com
download.sony.com
downloads.sony.com
files.sony.com
resources.sony.com
community.sony.com
blog.sony.com
security.sony.com
updates.sony.com
packages.sony.com
repo.sony.com
registry.sony.com
pkg.sony.com
mirror.sony.com
mirrors.sony.com
forum.sony.com
forums.sony.com
manual.sony.com
training.sony.com
events.sony.com
news.sony.com
www2.sony.com
portal.sony.com
service.sony.com
services.sony.com
panasonic.com
docs.panasonic.com
doc.panasonic.com
developer.panasonic.com
developers.panasonic.com
learn.panasonic.com
support.panasonic.com
help.panasonic.com
status.panasonic.com
api.panasonic.com
cdn.panasonic.com
static.panasonic.com
assets.panasonic.com
download.panasonic.com
downloads.panasonic.com
files.panasonic.com
resources.panasonic.com
community.panasonic.com
blog.panasonic.com
security.panasonic.com
updates.panasonic.com
packages.panasonic.com
repo.panasonic.com
registry.panasonic.com
pkg.panasonic.com
mirror.panasonic.com
mirrors.panasonic.com
forum.panasonic.com
forums.panasonic.com
manual.panasonic.com
training.panasonic.com
events.panasonic.com
news.panasonic.com
www2.panasonic.com
portal.panasonic.com
service.panasonic.com
services.panasonic.com
canon.com
www.canon.com
docs.canon.com
doc.canon.com
developer.canon.com
developers.canon.com
learn.canon.com
support.canon.com
help.canon.com
status.canon.com
api.canon.com
cdn.canon.com
static.canon.com
assets.canon.com
download.canon.com
downloads.canon.com
files.canon.com
resources.canon.com
community.canon.com
blog.canon.com
security.canon.com
updates.canon.com
packages.canon.com
repo.canon.com
registry.canon.com
pkg.canon.com
mirror.canon.com
mirrors.canon.com
forum.canon.com
forums.canon.com
manual.canon.com
training.canon.com
EOF_SNI_CANDIDATES

    cat >> "$raw" <<'EOF_SNI_PRIORITY'
EOF_SNI_PRIORITY

    # Generate conservative subdomain variants for strong apexes. Invalid/nonexistent hosts are filtered by TLS probing.
    awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$raw" | \
        sed -E 's#^https?://##; s#/.*$##; s/:443$//; s/[[:space:]]//g' | \
        grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' | \
        awk '!seen[$0]++' > "$generated"

    awk -F. 'NF>=2 {
        base=$(NF-1); apex=base "." $NF
        if (base ~ /^(github|cloudflare|microsoft|google|apache|mozilla|docker|kubernetes|linuxfoundation|cncf|python|rust-lang|golang|go|oracle|ibm|redhat|ubuntu|debian|nginx|postgresql|mongodb|elastic|hashicorp|terraform|confluent|fastly|akamai|digitalocean|linode|vultr|hetzner|ovhcloud|scaleway|openai|anthropic|huggingface|pytorch|tensorflow|ietf|w3|rfc-editor|openssl|curl|gnu|kernel|freebsd|openbsd|netbsd|eclipse|jetbrains|npmjs|nodejs|typescriptlang|redis|sqlite|mysql|wikimedia|wikipedia|archive|stackoverflow|stackexchange|nasa|nist|cisa|stanford|mit|berkeley|cambridge|ox|ethz|epfl|unimelb|sydney|unsw|monash|auckland|cloudfront|amazonaws)$/) print apex
    }' "$generated" | awk '!seen[$0]++' | while IFS= read -r apex; do
        for p in www docs doc developer developers api status support blog cdn static assets download downloads registry repo packages pkg files raw resources community help learn training security; do
            printf '%s.%s\n' "$p" "$apex"
        done
        printf '%s\n' "$apex"
    done >> "$generated"

    awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$generated" | \
        sed -E 's#^https?://##; s#/.*$##; s/:443$//; s/[[:space:]]//g' | \
        grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' | \
        grep -Ev '(^|\.)(doubleclick|googlesyndication|googleadservices|facebook|tiktok|tracking|track|ads|analytics|telemetry)\.' | \
        awk '!seen[$0]++' > "$tmp"

    if [[ "$profile" == 'mini' ]]; then
        # Keep the same candidate library semantics as full mode, but cap the default
        # library size to the production-grade high-signal range. Operators can still
        # override this with ABOX_SNI_MINI_MAX when needed.
        max_count="${ABOX_SNI_MINI_MAX:-4096}"
    else
        max_count="${ABOX_SNI_FULL_MAX:-4096}"
    fi
    if ! [[ "$max_count" =~ ^[0-9]+$ ]]; then
        max_count=4096
    fi
    if (( max_count <= 0 || max_count > 4096 )); then
        max_count=4096
    fi
    awk -v n="$max_count" 'NR<=n {print}' "$tmp" > "$out"
    rm -f "$raw" "$generated" "$tmp"
}

sni_domain_penalty() {
    local domain="${1,,}" penalty=0
    case "$domain" in
        *.apple.com|*.icloud.com|www.apple.com|www.icloud.com) penalty=$((penalty + 1800)) ;;
        www.nike.com|www.adidas.com|www.amazon.com|www.google.com|www.youtube.com|www.netflix.com) penalty=$((penalty + 500)) ;;
        *.google.com|*.gstatic.com|*.googleapis.com|*.youtube.com|*.facebook.com|*.instagram.com|*.twitter.com|*.x.com|*.tiktok.com|*.telegram.org|*.whatsapp.com|*.wikipedia.org|*.wikimedia.org|*.openai.com|*.anthropic.com|*.huggingface.co|*.torproject.org|*.nist.gov|*.cisa.gov|*.github.com|*.apple.com|*.icloud.com|*.doubleclick.net|*.googlesyndication.com|*.googleadservices.com) penalty=$((penalty + 2400)) ;;
    esac
    case "$domain" in
        *.microsoft.com|*.bing.com|*.apache.org|*.ietf.org|*.rfc-editor.org|*.w3.org|*.unicode.org|*.icann.org|*.iana.org|*.iso.org|*.itu.int|*.nginx.org|*.openssl.org|*.curl.se|*.kernel.org|*.debian.org|*.ubuntu.com|*.linuxfoundation.org|*.cncf.io|*.cloudflare.com|*.akamai.com|*.fastly.com) penalty=$((penalty - 220)) ;;
        docs.*|developer.*|developers.*|learn.*|support.*|download.*|downloads.*|packages.*|repo.*|registry.*|resources.*|community.*|help.*|security.*|*.mozilla.org|*.confluent.io|*.python.org|*.rust-lang.org|*.nodejs.org|*.postgresql.org|*.sqlite.org|*.eclipse.org|*.gnu.org|*.git-scm.com|*.cmake.org|*.llvm.org|*.mariadb.org|*.mysql.com) penalty=$((penalty - 120)) ;;
        *.samsung.com|*.lenovo.com|*.dell.com|*.intel.com|*.amd.com|*.nvidia.com|*.cisco.com|*.huawei.com|*.ericsson.com|*.nokia.com|*.siemens.com|*.un.org|*.who.int|*.unesco.org|*.cern.ch|*.esa.int|*.mit.edu|*.stanford.edu|*.berkeley.edu|*.cam.ac.uk|*.ox.ac.uk|*.ethz.ch|*.epfl.ch|*.crossref.org|*.orcid.org|*.openstreetmap.org) penalty=$((penalty - 60)) ;;
    esac
    printf '%s\n' "$penalty"
}

asn_lookup_ip() {
    local ip="${1:-}" cache_dir="${2:-/tmp/A-Box-asn-cache}" cache_file body asn country org
    [[ -n "$ip" && "$ip" != 'N/A' ]] || { printf 'asn=unknown\tcountry=unknown\torg=unknown'; return 0; }
    mkdir -p "$cache_dir" 2>/dev/null || true
    cache_file="$cache_dir/$(printf '%s' "$ip" | tr -c 'A-Za-z0-9_.:-' '_')"
    if [[ -s "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi
    body=$(curl -fsS --connect-timeout 2 -m 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)
    if [[ -n "$body" ]] && command -v jq >/dev/null 2>&1; then
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
    case "$org $domain" in
        *google*|*facebook*|*meta*|*telegram*|*twitter*|*openai*|*anthropic*|*huggingface*|*apple*|*icloud*) penalty=$((penalty + 1000)) ;;
        *cloudflare*|*akamai*|*fastly*|*microsoft*|*edgecast*|*verizon*|*stackpath*|*bunny*|*cdn77*) penalty=$((penalty + 120)) ;;
        *cloudfront*|*amazon*|*aws*) penalty=$((penalty + 220)) ;;
    esac
    case "$domain" in
        *.microsoft.com|*.bing.com|*.cloudflare.com|*.fastly.com|*.akamai.com|*.apache.org|*.kernel.org|*.debian.org|*.ubuntu.com|*.ietf.org|*.rfc-editor.org|*.w3.org|*.unicode.org|*.icann.org|*.iana.org|*.nginx.org|*.openssl.org|*.curl.se|*.linuxfoundation.org|*.cncf.io) penalty=$((penalty - 160)) ;;
        *.confluent.io|*.mozilla.org|*.python.org|*.rust-lang.org|*.nodejs.org|*.postgresql.org|*.sqlite.org|*.eclipse.org|*.gnu.org|*.git-scm.com|*.cmake.org|*.llvm.org|*.mariadb.org|*.mysql.com) penalty=$((penalty - 90)) ;;
    esac
    printf '%s\n' "$penalty"
}

sni_probe_domain() {
    local domain="$1" raw="$2" timeout_s="${3:-6}" metrics code t_connect t_app t_start t_total http_version remote_ip penalty score tls_args=()
    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || return 0
    # Fast path: detect curl TLS 1.3 capability once in run_builtin_sni_radar.
    # This preserves probe semantics while avoiding one `curl --help all | grep`
    # subprocess chain per candidate domain on large libraries.
    if [[ "${ABOX_CURL_TLS13_SUPPORTED:-0}" == '1' ]]; then
        tls_args=(--tlsv1.3)
    fi
    metrics=$(curl -sSIL "${tls_args[@]}" --connect-timeout "$timeout_s" --max-time "$((timeout_s + 4))" \
        -o /dev/null \
        -w '%{http_code}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{http_version}\t%{remote_ip}' \
        "https://${domain}/" 2>/dev/null) || return 0
    IFS=$'\t' read -r code t_connect t_app t_start t_total http_version remote_ip <<< "$metrics"
    [[ "$t_app" =~ ^[0-9.]+$ ]] || return 0
    awk -v v="$t_app" 'BEGIN{exit !(v>0)}' || return 0
    penalty=$(sni_domain_penalty "$domain")
    [[ "$http_version" == '2' || "$http_version" == '3' ]] || penalty=$((penalty + 350))
    [[ "$code" =~ ^(2|3|4)[0-9][0-9]$ ]] || penalty=$((penalty + 120))
    score=$(awk -v app="$t_app" -v start="$t_start" -v total="$t_total" -v p="$penalty" 'BEGIN{v=int(app*1000 + start*220 + total*60 + p); if(v<0)v=0; printf "%08d", v}')
    printf '%s\t%s\tapp=%ss\tttfb=%ss\ttotal=%ss\thttp=%s\tcode=%s\tip=%s\n' "$score" "$domain" "$t_app" "$t_start" "$t_total" "$http_version" "$code" "$remote_ip" >> "$raw"
}

sni_openssl_check() {
    local domain="$1" timeout_s="${2:-5}" out cert sanext rest alpn='none' tls13=0 san=0
    command -v openssl >/dev/null 2>&1 || { printf 'tls13=unknown\talpn=unknown\tsan=unknown'; return 0; }
    out=$(printf '' | timeout "$timeout_s" openssl s_client -connect "${domain}:443" -servername "$domain" -alpn 'h2,http/1.1' -tls1_3 -showcerts 2>/dev/null | tr -d '\000') || out=''
    if [[ -n "$out" ]]; then
        grep -qiE 'Protocol *: *TLSv1\.3|New, TLSv1\.3' <<< "$out" && tls13=1
        alpn=$(awk -F': ' '/ALPN protocol/{print $2; exit}' <<< "$out")
        [[ -n "$alpn" ]] || alpn='none'
        cert=$(awk 'BEGIN{p=0}/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}' <<< "$out")
        if [[ -n "$cert" ]]; then
            sanext=$(printf '%s\n' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr '\n' ' ' || true)
            if grep -qi "DNS:${domain}\b" <<< "$sanext"; then
                san=1
            else
                rest="${domain#*.}"
                grep -qi "DNS:\*\.${rest}\b" <<< "$sanext" && san=1
            fi
        fi
    fi
    printf 'tls13=%s\talpn=%s\tsan=%s' "$tls13" "$alpn" "$san"
}

sni_verify_raw_report() {
    local raw_sorted="$1" verified="$2" verify_limit="${3:-240}" timeout_s="${4:-5}" line score domain c3 c4 c5 c6 c7 c8 check tls13 alpn san add adj n=0
    local asn_cache vps_ip vps_meta vps_asn vps_country target_ip target_meta target_asn target_country target_org asn_match same_country cdn_penalty progress_every=20
    : > "$verified"
    asn_cache=$(mktemp -d /tmp/A-Box-asn-cache.XXXXXX) || asn_cache='/tmp'
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
        check=$(sni_openssl_check "$domain" "$timeout_s")
        tls13=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="tls13"){print $(i+1); exit}}' <<< "$check")
        alpn=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="alpn"){print $(i+1); exit}}' <<< "$check")
        san=$(awk -F'\t|=' '{for(i=1;i<=NF;i++) if($i=="san"){print $(i+1); exit}}' <<< "$check")
        target_ip="${c8#ip=}"
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
        [[ "$asn_match" == '1' ]] && add=$((add - 1200))
        adj=$(awk -v s="$score" -v a="$add" 'BEGIN{v=int(s)+int(a); if(v<0)v=0; printf "%08d", v}')
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tasn=%s\tcountry=%s\tasnmatch=%s\tsamecountry=%s\torg=%s\n' \
            "$adj" "$domain" "$c3" "$c4" "$c5" "$c6" "$c7" "$c8" "$check" "$target_asn" "$target_country" "$asn_match" "$same_country" "$target_org" >> "$verified"
    done < "$raw_sorted"
    printf '\r[*] Stage 2 progress: %d/%d verified\n' "$(( n > verify_limit ? verify_limit : n ))" "$verify_limit" >&2
    sort -n "$verified" -o "$verified"
    rm -rf "$asn_cache" 2>/dev/null || true
}

run_builtin_sni_radar() {
    local profile="${1:-full}" title="${2:-Local SNI preference}" workdir candidates raw raw_sorted report total concurrency timeout_s running=0 domain topn verify_limit processed=0 valid_count=0 batch_start progress_every
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
    total=$(wc -l < "$candidates" | tr -d ' ')
    if [[ "$profile" == 'mini' ]]; then
        # Mini mode uses the same candidate library as full mode. It reduces concurrency and verification depth only.
        concurrency="${ABOX_SNI_MINI_CONCURRENCY:-8}"
        timeout_s="${ABOX_SNI_MINI_TIMEOUT:-5}"
        topn=25
        verify_limit="${ABOX_SNI_MINI_VERIFY:-180}"
    else
        concurrency="${ABOX_SNI_FULL_CONCURRENCY:-36}"
        timeout_s="${ABOX_SNI_FULL_TIMEOUT:-6}"
        topn=35
        verify_limit="${ABOX_SNI_FULL_VERIFY:-420}"
    fi
    progress_every=$(( concurrency * 2 ))
    (( progress_every < 20 )) && progress_every=20
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}${title}${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "${YELLOW}[*] Candidate library: ${total} domains | profile=${profile} | concurrency=${concurrency}${NC}"
    msg "${YELLOW}[*] Stage 1: HTTPS/TLSv1.3 curl metrics. Stage 2: OpenSSL TLS1.3 + ALPN + SAN + ASN/topology scoring.${NC}"
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
    sort -n "$raw" > "$raw_sorted"
    sni_verify_raw_report "$raw_sorted" "$report" "$verify_limit" "$timeout_s"
    if [[ ! -s "$report" ]]; then
        cp -f "$raw_sorted" "$report"
    fi
    mkdir -p "$ABOX_DIR" 2>/dev/null || true
    cp -f "$report" "$ABOX_DIR/A-Box-sni-${profile}.tsv" 2>/dev/null || true
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${YELLOW}[ Top SNI Candidates / 优选 SNI 候选 ]${NC}"
    awk -F'\t' -v n="$topn" 'NR<=n {printf "%2d. %-42s %s %s %s %s %s %s %s %s %s\n", NR, $2, $3, $4, $5, $6, $7, $9, $10, $11, $12}' "$report"
    msg "${BLUE}----------------------------------------------------------------------${NC}"
    msg "${GREEN}Saved: ${ABOX_DIR}/A-Box-sni-${profile}.tsv${NC}"
    msg "${YELLOW}Use only domains with tls13=1 and san=1. Prefer asnmatch=1/samecountry=1 when available; avoid blindly using fixed Apple/Nike templates.${NC}"
    rm -rf "$workdir"
}

show_sni_preference_records() {
    clear
    local files=() f profile topn=35 shown=0 mtime
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${BOLD}${GREEN}SNI Preference Records${NC}"
    else
        msg "${BOLD}${GREEN}SNI 优选记录${NC}"
    fi
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
        awk -F'	' -v n="$topn" 'NF>=8 && NR<=n {printf "%2d. %-42s %s %s %s %s %s %s %s %s %s\n", NR, $2, $3, $4, $5, $6, $7, $9, $10, $11, $12}' "$f"
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
    if confirm_yes_no "$(printf "$(tr_msg confirm_remote)" 'fscarmen/warp Cloudflare WARP menu')"; then
        run_remote_bash_script 'fscarmen/warp Cloudflare WARP menu' 'https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh'
    fi
    pause_return
}

setup_swap_2g() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Swap 虚拟内存一键划拨 / Allocate 2G Swap${NC}"
    msg "${CYAN}======================================================================${NC}"
    [[ ! -L /swapfile ]] || die '拒绝使用符号链接 /swapfile。'
    if [[ -e /swapfile && ! -f /swapfile ]]; then
        die '/swapfile 已存在但不是普通文件。'
    fi
    if [[ -f /swapfile ]]; then
        [[ "$(stat -c %u /swapfile 2>/dev/null || echo -1)" == 0 ]] || die '/swapfile 不是 root 所有。'
        chmod 600 /swapfile || die 'Swap 文件权限设置失败。'
        msg "${YELLOW}$(tr_msg swap_exists)${NC}"
    else
        if ! fallocate -l 2G /swapfile 2>/dev/null; then
            rm -f /swapfile
            dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress || die 'Swap 文件创建失败。'
        fi
        chmod 600 /swapfile || die 'Swap 文件权限设置失败。'
        mkswap /swapfile >/dev/null || die 'mkswap 失败。'
    fi
    if ! swapon --show=NAME --noheadings 2>/dev/null | awk '{$1=$1; if ($0 == "/swapfile") found=1} END {exit !found}'; then
        swapon /swapfile || die 'swapon 失败；不会写入 /etc/fstab。'
    fi
    if ! grep -qE '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0([[:space:]]|$)' /etc/fstab 2>/dev/null; then
        fstab_tmp=$(mktemp /etc/.fstab.A-Box.XXXXXX) || die '/etc/fstab 临时文件创建失败。'
        cat /etc/fstab > "$fstab_tmp" || { rm -f "$fstab_tmp"; die '/etc/fstab 读取失败。'; }
        printf '%s\n' '# A-Box swap BEGIN' '/swapfile none swap sw 0 0' '# A-Box swap END' >> "$fstab_tmp" || { rm -f "$fstab_tmp"; die '/etc/fstab 临时写入失败。'; }
        chmod --reference=/etc/fstab "$fstab_tmp" 2>/dev/null || chmod 644 "$fstab_tmp"
        mv -f "$fstab_tmp" /etc/fstab || { rm -f "$fstab_tmp"; die '/etc/fstab 原子提交失败。'; }
    fi
    swapon --show || true
    msg "${GREEN}$(tr_msg swap_done)${NC}"
    pause_return
}

redact_secrets_stream() {
    if command -v python3 >/dev/null 2>&1; then
        python3 /dev/fd/3 3<<'PY_REDACT'
import json
import re
import sys

text = sys.stdin.read()
secret = re.compile(
    r"(uuid|private.?key|password|passwd|token|secret|api.?key|authorization|cookie|ss_pass|hy2_pass|hy2_obfs)",
    re.I,
)
link = re.compile(r"(?i)\b(?:vless|hysteria2|hy2|ss)://\S+")


def walk(value):
    if isinstance(value, dict):
        return {
            key: ("***REDACTED***" if secret.search(str(key)) else walk(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [walk(item) for item in value]
    if isinstance(value, str):
        return link.sub("***CLIENT_LINK_REDACTED***", value)
    return value


try:
    parsed = json.loads(text)
except Exception:
    text = re.sub(
        r"(?im)^(UUID|SS_PASS|HY2_PASS|HY2_OBFS|HY2_ACME_DNS_CF_API_TOKEN)=.*$",
        r"\1=***REDACTED***",
        text,
    )
    text = re.sub(
        r"(?i)([\"']?(?:private.?key|password|passwd|token|secret|api.?key|authorization|cookie)[\"']?\s*[:=]\s*)([\"']?)[^,}\s\"']+\2",
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
            -e 's/(UUID|SS_PASS|HY2_PASS|HY2_OBFS|HY2_ACME_DNS_CF_API_TOKEN)=.*/\1=***REDACTED***/Ig' \
            -e 's/((PRIVATE_KEY|privateKey|private_key|password|passwd|token|secret|api[_-]?key|authorization|cookie)[[:space:]]*[:=][[:space:]]*)[^,}[:space:]]+/\1***REDACTED***/Ig' \
            -e 's/(vless|hysteria2|hy2|ss):\/\/[^[:space:]]+/***CLIENT_LINK_REDACTED***/Ig'
    fi
}

write_redacted_file() {
    local src="$1" dst="$2"
    [[ -r "$src" ]] || return 0
    mkdir -p "$(dirname "$dst")"
    redact_secrets_stream < "$src" > "$dst" 2>/dev/null || true
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
    cat "$extracted"
    rm -f "$all" "$err" "$extracted"
}

install_abox_cron_block() {
    local name="$1" line="$2" tmp
    [[ -n "$name" && -n "$line" ]] || return 1
    tmp=$(mktemp) || die 'crontab 临时文件创建失败。'
    crontab -l 2>/dev/null | sed "/^# A-Box ${name} BEGIN$/,/^# A-Box ${name} END$/d" > "$tmp" || true
    {
        echo "# A-Box ${name} BEGIN"
        echo "$line"
        echo "# A-Box ${name} END"
    } >> "$tmp"
    crontab "$tmp" 2>/dev/null || die 'crontab 写入失败。'
    rm -f "$tmp"
}

remove_abox_cron_block() {
    local name="$1" tmp rc=0
    tmp=$(mktemp) || die 'crontab 临时文件创建失败。'
    crontab -l 2>/dev/null | sed "/^# A-Box ${name} BEGIN$/,/^# A-Box ${name} END$/d" | grep -vE "/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh" > "$tmp" || true
    crontab "$tmp" 2>/dev/null || rc=1
    rm -f "$tmp"
    return "$rc"
}

remove_all_abox_cron_blocks() {
    local tmp rc=0
    tmp=$(mktemp) || die 'crontab 临时文件创建失败。'
    crontab -l 2>/dev/null | sed '/^# A-Box .* BEGIN$/,/^# A-Box .* END$/d' | grep -vE "/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh" > "$tmp" || true
    crontab "$tmp" 2>/dev/null || rc=1
    rm -f "$tmp"
    return "$rc"
}

managed_service_state_value() {
    local srv="$1" active=0 enabled=0
    if [[ "${INIT_SYS:-}" == systemd ]] && systemd_available; then systemctl is-active --quiet "$srv" && active=1; systemctl is-enabled --quiet "$srv" && enabled=1
    elif [[ "${INIT_SYS:-}" == openrc ]] && command -v rc-service >/dev/null 2>&1; then rc-service "$srv" status >/dev/null 2>&1 && active=1; rc-update show default 2>/dev/null | awk -v wanted="$srv" '$1 == wanted { found=1 } END { exit !found }' && enabled=1; fi
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

restore_managed_service_state() {
    local state="$1" srv active enabled failed=0
    [[ -r "$state" ]] || return 0
    local -A seen_services=()
    while IFS='|' read -r srv active enabled; do
        [[ "$srv" =~ ^(xray|sing-box|hysteria)$ && "$active" =~ ^[01]$ && "$enabled" =~ ^[01]$ ]] || { failed=1; continue; }
        [[ -z "${seen_services[$srv]:-}" ]] || { failed=1; continue; }
        seen_services[$srv]=1
        service_file_is_abox_managed "$srv" || { failed=1; continue; }
        if [[ "${INIT_SYS:-}" == systemd ]]; then
            if [[ "$enabled" == 1 ]]; then systemctl enable "$srv" >/dev/null 2>&1 || failed=1; else systemctl disable "$srv" >/dev/null 2>&1 || failed=1; fi
        else
            if [[ "$enabled" == 1 ]]; then rc-update add "$srv" default >/dev/null 2>&1 || failed=1; else rc-update del "$srv" default >/dev/null 2>&1 || failed=1; fi
        fi
        if [[ "$active" == 1 ]]; then
            restart_service_soft "$srv" >/dev/null 2>&1 || failed=1
        elif [[ "${INIT_SYS:-}" == systemd ]]; then
            systemctl stop "$srv" >/dev/null 2>&1 || { systemctl is-active --quiet "$srv" && failed=1; }
            systemctl is-active --quiet "$srv" && failed=1
        else
            rc-service "$srv" stop >/dev/null 2>&1 || { rc-service "$srv" status >/dev/null 2>&1 && failed=1; }
            rc-service "$srv" status >/dev/null 2>&1 && failed=1
        fi
    done < "$state"
    (( failed == 0 ))
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
        [[ "$family" == 6 ]] || return 1
        : > "$out"
        return 0
    fi
    all=$(mktemp) || return 1
    "$cmd" > "$all" 2>/dev/null || { rm -f "$all"; return 1; }
    extract_abox_iptables_rules "$all" all > "$out" || { rm -f "$all"; return 1; }
    rm -f "$all"
}

restore_abox_iptables_snapshot() {
    local snapshot="$1" family="${2:-4}" mode="${3:-all}" cmd tmp
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
    dir=$(dirname "$dest")
    [[ -d "$dir" && ! -L "$dir" ]] || return 1
    [[ "$(stat -c %u:%g "$dir" 2>/dev/null || true)" == 0:0 ]] || return 1
    path_mode_has_no_group_other_write "$dir" || return 1
    [[ ! -L "$dest" ]] || return 1
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
    local archive="$1" hmac="${archive}.hmac" recovery="${archive}.key" rc fingerprint answer
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
        read -r -ep '输入 IMPORT-RECOVERY-KEY 以导入并继续: ' answer
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
        read -r -ep 'Legacy backup has no trusted checksum. Type IMPORT-UNVERIFIED-LEGACY to continue: ' answer
        [[ "$answer" == 'IMPORT-UNVERIFIED-LEGACY' ]] || return 130
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
    while IFS= read -r path; do
        [[ -e "$root$path" ]] || continue
        auxiliary_content_is_abox_managed "$root$path" "$path" || { rm -rf "$work"; die "Legacy auxiliary path fingerprint rejected: $path"; }
        if ! grep -Fxq '# Managed by A-Box' "$root$path" 2>/dev/null; then
            if head -n 1 "$root$path" | grep -q '^#!'; then sed -i '1a# Managed by A-Box' "$root$path"; else sed -i '1i# Managed by A-Box' "$root$path"; fi
        fi
    done < <(managed_auxiliary_paths)
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
    python3 - "$archive" <<'PY_VALIDATE'
import posixpath,stat,sys,tarfile
fn=sys.argv[1]
MAX_MEMBERS=10000
MAX_FILE=512*1024*1024
MAX_TOTAL=1024*1024*1024
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
    if m.uid != 0 or m.gid != 0: raise SystemExit(1)
    mode=m.mode & 0o7777
    if mode & 0o7000 or mode & 0o022: raise SystemExit(1)
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

backup_root_contains_service() { local root="$1" srv="$2" path; while IFS= read -r path; do [[ -e "$root$path" || -L "$root$path" ]] && return 0; done < <(core_family_paths "$srv"); return 1; }

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
    local file="$1"
    [[ -f "$file" && ! -L "$file" ]] || return 1
    python3 - "$file" <<'PY_MANAGED_PATHS'
import sys
from pathlib import Path
allowed={
'/usr/local/bin/sb','/etc/logrotate.d/A-Box','/etc/fail2ban/filter.d/A-Box.conf','/etc/fail2ban/jail.d/A-Box.local',
'/etc/sysctl.d/99-A-Box-tune.conf','/etc/security/limits.d/A-Box.conf','/etc/systemd/system/A-Box-firewall.service','/etc/init.d/A-Box-firewall',
'/usr/local/bin/xray','/usr/local/etc/xray','/usr/local/share/xray','/etc/systemd/system/xray.service','/etc/init.d/xray','/etc/conf.d/xray',
'/usr/local/bin/sing-box','/etc/sing-box','/etc/systemd/system/sing-box.service','/etc/init.d/sing-box','/etc/conf.d/sing-box',
'/usr/local/bin/hysteria','/etc/hysteria','/etc/systemd/system/hysteria.service','/etc/init.d/hysteria','/etc/conf.d/hysteria',
}
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
    while IFS= read -r path; do
        src="$root$path"
        [[ -e "$src" || -L "$src" ]] || continue
        auxiliary_content_is_abox_managed "$src" "$path" || return 1
    done < <(managed_auxiliary_paths)
}

assert_restore_target_safe() {
    local root="$1" srv path c=''
    validate_extracted_backup_content "$root" || { msg "${RED}[!] Backup content ownership markers are invalid.${NC}"; return 1; }
    for srv in xray sing-box hysteria; do
        backup_root_contains_service "$root" "$srv" || continue
        c+="$(list_foreign_core_conflicts "$srv")"$'\n'
    done
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        [[ -e "$root$path" || -L "$root$path" ]] || continue
        [[ ! -e "$path" && ! -L "$path" ]] || auxiliary_path_is_abox_managed "$path" || c+="aux|${path}"$'\n'
    done < <(managed_auxiliary_paths)
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
        rm -rf -- "$child" || failed=1
    done
    (( failed == 0 ))
}

restore_abox_directory() {
    local root="$1" src child base
    src="$root$ABOX_DIR"
    [[ -d "$src" && ! -L "$src" ]] || return 1
    [[ -d "$ABOX_DIR" && ! -L "$ABOX_DIR" ]] || return 1
    ensure_abox_dir_owned "$ABOX_DIR"
    for child in "$src"/* "$src"/.[!.]* "$src"/..?*; do
        [[ -e "$child" || -L "$child" ]] || continue
        base=${child##*/}
        abox_restore_preserved_name "$base" && continue
        [[ ! -L "$child" ]] || return 1
        cp -a -- "$child" "$ABOX_DIR/" || return 1
    done
    ensure_abox_dir_owned "$ABOX_DIR"
}

regenerate_runtime_assets_after_restore() {
    clear_abox_env_vars
    load_abox_env "$ABOX_ENV" || return 1
    setup_shortcut || return 1
    setup_health_monitor || return 1
    setup_geo_cron || return 1
    if valid_positive_int "${TRAFFIC_LIMIT_GB:-}"; then
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
    if [[ ! -e "$src" && ! -L "$src" ]]; then
        rm -rf -- "$path"
        return 0
    fi
    [[ ! -L "$src" ]] || return 1
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
    local root="$1" srv="$2" path
    backup_root_contains_service "$root" "$srv" || return 0
    backup_root_service_is_managed "$root" "$srv" || return 1
    while IFS= read -r path; do
        restore_tree_path "$root" "$path" || return 1
    done < <(core_family_paths "$srv")
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
    sed '/^# A-Box .* BEGIN$/,/^# A-Box .* END$/d' "$current" | grep -vE '/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh' > "$tmp" || true
    cat "$f" >> "$tmp" || { rm -f "$tmp" "$current" "$err"; return 1; }
    crontab "$tmp"
    local rc=$?
    rm -f "$tmp" "$current" "$err"
    return "$rc"
}

backup_current_config() {
    local ts unique backup_dir work root tarball backup_failed=0 backend srv path
    ts=$(date +%Y%m%d-%H%M%S); unique=$(openssl rand -hex 3 2>/dev/null || printf '%s' "$$")
    backup_dir="${1:-$ABOX_DIR/backups}"
    work=$(mktemp -d /tmp/A-Box-backup.XXXXXX) || die 'Backup temp directory creation failed.'
    root="$work/root"; install -d -m 700 "$backup_dir" "$root" "$work/meta" || { rm -rf "$work"; die 'Backup directory creation failed.'; }
    { managed_auxiliary_paths; core_family_paths xray; core_family_paths sing-box; core_family_paths hysteria; } | awk 'NF && !seen[$0]++' > "$work/meta/managed-paths.txt"
    msg "${YELLOW}[*] Creating A-Box configuration backup...${NC}"
    backup_copy_path() {
        local src="$1" dst links
        [[ -e "$src" ]] || return 0
        [[ ! -L "$src" ]] || { backup_failed=1; return 1; }
        if [[ -d "$src" ]]; then
            links=$(find "$src" -type l -print 2>/dev/null) || { backup_failed=1; return 1; }
            [[ -z "$links" ]] || { backup_failed=1; return 1; }
        fi
        dst="$root$src"
        mkdir -p "$(dirname "$dst")"
        cp -a -- "$src" "$dst" || backup_failed=1
    }
    if [[ -d "$ABOX_DIR" ]]; then
        _abox_links=$(find "$ABOX_DIR" -path "$ABOX_DIR/backups" -prune -o -path "$ABOX_DIR/diagnostics" -prune -o -path "$ABOX_DIR/preflight" -prune -o -type l -print 2>/dev/null) || backup_failed=1
        if [[ -n "${_abox_links:-}" ]]; then
            backup_failed=1
        else
            mkdir -p "$root$ABOX_DIR"
            (cd "$ABOX_DIR" && tar \
                --exclude='./backups' --exclude='./diagnostics' --exclude='./preflight' \
                --exclude='./A-Box.sh' --exclude='./.backup-hmac.key' --exclude='./.runtime.lock' --exclude='./.runtime.lock.d' \
                --exclude='./socket_probe.sh' --exclude='./geo_update.sh' --exclude='./traffic_monitor.sh' \
                --exclude='./firewall_restore.sh' --exclude='./iptables.v4' --exclude='./iptables.v6' \
                -cpf - . | tar -C "$root$ABOX_DIR" -xpf -) || backup_failed=1
        fi
    fi
    shortcut_is_abox_managed /usr/local/bin/sb && backup_copy_path /usr/local/bin/sb
    for srv in xray sing-box hysteria; do if abox_owns_service "$srv"; then while IFS= read -r path; do backup_copy_path "$path"; done < <(core_family_paths "$srv"); fi; done
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        auxiliary_path_is_abox_managed "$path" && backup_copy_path "$path"
    done < <(managed_auxiliary_paths)
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
        msg "${YELLOW}[*] External backup created without exporting the authentication key beside it.${NC}"
        msg "${YELLOW}[*] Use --export-backup-key to save the recovery key on a separate trusted medium.${NC}"
    fi
    rm -rf "$work"
    ABOX_LAST_BACKUP="$tarball"
    mapfile -t _old_backups < <(python3 - "$backup_dir" "$BACKUP_RETENTION_COUNT" <<'PY_BACKUP_RETENTION'
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
)
    for _old in "${_old_backups[@]}"; do [[ "$_old" == "$ABOX_LAST_BACKUP" ]] || rm -f -- "$_old" "${_old}.sha256" "${_old}.hmac" "${_old}.key"; done
    msg "${GREEN}[*] Backup created:${NC} $tarball"
}

auto_backup_prompt() {
    local reason="${1:-operation}" dest="${2:-$ABOX_DIR/backups}" answer
    msg "${YELLOW}[!] Backup recommended before: ${reason}${NC}"
    read -r -ep 'Create backup now? [Y/N]: ' answer
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
    local backup_dir="${1:-$ABOX_DIR/backups}" selected="${2:-}" work root backend mode=all srv
    [[ -d "$backup_dir" ]] || return 1
    if [[ -n "$selected" ]]; then
        [[ -f "$selected" && "$(dirname "$selected")" == "$backup_dir" ]] || return 1
    else
        selected=$(find "$backup_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' -print | sort -r | sed -n '1p')
    fi
    [[ -n "$selected" ]] || return 1
    backup_checksum_verify "$selected" "${selected}.sha256" || return 1
    backup_auth_verify "$selected" "${selected}.hmac" || return 1
    validate_backup_archive "$selected" || return 1
    work=$(mktemp -d /tmp/A-Box-rollback.XXXXXX) || return 1; chmod 700 "$work"
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; return 1; }
    root="$work/root"; assert_restore_target_safe "$root" || { rm -rf "$work"; return 1; }; assert_restore_shortcut_safe "$root" || { rm -rf "$work"; return 1; }
    stop_all_managed_services >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    clean_nat_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    clean_input_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    remove_all_owned_core_families || { rm -rf "$work"; return 1; }
    clear_abox_runtime_for_restore || { rm -rf "$work"; return 1; }
    restore_abox_directory "$root" || { rm -rf "$work"; return 1; }
    for srv in xray sing-box hysteria; do restore_core_family_from_backup "$root" "$srv" || { rm -rf "$work"; return 1; }; done
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        restore_auxiliary_path_from_backup "$root" "$path" || { rm -rf "$work"; return 1; }
    done < <(managed_auxiliary_paths)
    regenerate_runtime_assets_after_restore >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    apply_native_firewall_rules_from_state >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    backend=$(cat "$work/meta/firewall.backend" 2>/dev/null || echo iptables); [[ "$backend" == iptables ]] || mode=special
    restore_abox_iptables_snapshot "$work/meta/iptables.snapshot" 4 "$mode" || { rm -rf "$work"; return 1; }
    restore_abox_iptables_snapshot "$work/meta/ip6tables.snapshot" 6 "$mode" || { rm -rf "$work"; return 1; }
    load_abox_env "$ABOX_ENV" >/dev/null 2>&1 || true
    enforce_ss_whitelist_order "${SS_PORT:-}" || { rm -rf "$work"; return 1; }
    save_firewall_rules >/dev/null 2>&1 || { rm -rf "$work"; return 1; }
    if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl daemon-reload >/dev/null 2>&1 || { rm -rf "$work"; return 1; }; fi
    restore_managed_service_state "$work/meta/services.state" || { rm -rf "$work"; return 1; }
    rm -rf "$work"; msg "${GREEN}[*] Rollback restored backup:${NC} $selected"
}

restore_from_backup() {
    local backup_dir="$ABOX_DIR/backups" backups i choice selected work root answer backend mode=all srv path targets=''
    mapfile -t backups < <(
        for _dir in "$ABOX_DIR/backups" /root/A-Box-backups; do
            [[ -d "$_dir" && ! -L "$_dir" ]] || continue
            find "$_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' -print
        done | sort -ru
    )
    (( ${#backups[@]} )) || { msg "${RED}[!] No A-Box backup tarballs found in $ABOX_DIR/backups or /root/A-Box-backups.${NC}"; pause_return; return; }
    clear
    for i in "${!backups[@]}"; do printf '%2d. %s\n' "$((i+1))" "${backups[$i]}"; done
    read -r -ep 'Select backup (0 back): ' choice
    [[ "$choice" == 0 ]] && return
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=${#backups[@]} )) || { msg "${RED}[!] Invalid selection.${NC}"; pause_return; return; }
    selected="${backups[$((choice-1))]}"
    backup_checksum_verify "$selected" "${selected}.sha256" || die 'Backup SHA256 is missing or invalid.'
    prepare_backup_auth_for_manual_restore "$selected" || die 'Backup HMAC/recovery-key authentication failed or was not authorized.'
    validate_backup_archive "$selected" || die 'Backup archive structure/link validation failed.'
    work=$(mktemp -d /tmp/A-Box-restore.XXXXXX) || die 'Restore temp directory creation failed.'
    chmod 700 "$work"
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; die 'Backup extraction failed.'; }
    root="$work/root"
    assert_restore_target_safe "$root" || { rm -rf "$work"; die 'Restore target ownership check failed.'; }
    assert_restore_shortcut_safe "$root" || { rm -rf "$work"; die 'Restore shortcut ownership check failed.'; }
    msg "${YELLOW}[!] Restore will replace only A-Box-owned paths and A-Box firewall rules.${NC}"
    read -r -ep 'Continue restore? [Y/N]: ' answer
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
    while IFS= read -r path; do
        [[ "$path" == /usr/local/bin/sb ]] && continue
        restore_auxiliary_path_from_backup "$root" "$path" || die "Restore failed: $path"
    done < <(managed_auxiliary_paths)
    chmod 700 "$ABOX_DIR" 2>/dev/null || true
    chmod 600 "$ABOX_ENV" 2>/dev/null || true
    regenerate_runtime_assets_after_restore || die 'Regenerate trusted A-Box runtime helpers and cron blocks failed.'
    apply_native_firewall_rules_from_state || die 'Restore native firewall rules failed.'
    backend=$(cat "$work/meta/firewall.backend" 2>/dev/null || echo iptables)
    [[ "$backend" == iptables ]] || mode=special
    restore_abox_iptables_snapshot "$work/meta/iptables.snapshot" 4 "$mode" || die 'IPv4 A-Box firewall restore failed.'
    restore_abox_iptables_snapshot "$work/meta/ip6tables.snapshot" 6 "$mode" || die 'IPv6 A-Box firewall restore failed.'
    load_abox_env "$ABOX_ENV" >/dev/null 2>&1 || true
    enforce_ss_whitelist_order "${SS_PORT:-}" || die 'Restored SS whitelist order validation failed.'
    save_firewall_rules || die 'Restored A-Box firewall persistence failed.'
    if [[ "${INIT_SYS:-}" == systemd ]]; then systemctl daemon-reload >/dev/null 2>&1 || die 'systemd daemon-reload after restore failed.'; fi
    restore_managed_service_state "$work/meta/services.state" || die 'Restored service state failed validation/startup.'
    for srv in xray sing-box hysteria; do abox_owns_service "$srv" && record_core_family_ownership "$srv" || true; done
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
    read -r -ep 'Select [0-4]: ' c
    case "$c" in
        1) backup_current_config; pause_return ;;
        2) restore_from_backup ;;
        3)
            local key_dest
            read -r -ep 'Absolute path on a separate trusted medium: ' key_dest
            export_backup_recovery_key "$key_dest"; pause_return
            ;;
        4)
            local legacy_path legacy_out
            read -r -ep 'Legacy .tar.gz path: ' legacy_path
            read -r -ep 'Output directory (default: same directory): ' legacy_out
            convert_legacy_backup_archive "$legacy_path" "${legacy_out:-$(dirname "$legacy_path")}"; pause_return
            ;;
        *) return 0 ;;
    esac
}

export_diagnostic_bundle() {
    local ts diag_dir work bundle checksum safe_mode
    ts=$(date +%Y%m%d-%H%M%S)
    diag_dir="$ABOX_DIR/diagnostics"
    work=$(mktemp -d /tmp/A-Box-diagnostic.XXXXXX) || die 'Diagnostic temp directory creation failed.'
    mkdir -p "$diag_dir" "$work/logs"
    chmod 700 "$diag_dir" 2>/dev/null || true

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
    write_redacted_file "$ABOX_ENV" "$work/env.redacted"

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
    chmod 600 "$bundle" 2>/dev/null || true
    checksum="${bundle}.sha256"
    sha256sum "$bundle" > "$checksum" 2>/dev/null || true
    chmod 600 "$checksum" 2>/dev/null || true
    rm -rf "$work"
    msg "${GREEN}[*] Diagnostic bundle:${NC} $bundle"
    [[ -f "$checksum" ]] && msg "${GREEN}[*] SHA256:${NC} $checksum"
    pause_return
}

light_preflight_check() {
    local fail=0 warn=0 c
    msg "${YELLOW}[*] Running lightweight preflight check...${NC}"
    [[ $EUID -eq 0 ]] || { msg "${RED}[FAIL] root privilege required${NC}"; fail=$((fail+1)); }
    [[ -t 0 ]] || { msg "${YELLOW}[WARN] no interactive TTY on stdin${NC}"; warn=$((warn+1)); }
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|alpine) msg "${GREEN}[PASS] OS: ${ID:-unknown}${NC}" ;; *) msg "${YELLOW}[WARN] OS may be unsupported: ${ID:-unknown}${NC}"; warn=$((warn+1)) ;; esac
    else
        msg "${YELLOW}[WARN] /etc/os-release not readable${NC}"; warn=$((warn+1))
    fi
    if systemd_available; then
        msg "${GREEN}[PASS] init: systemd${NC}"
    elif command -v rc-service >/dev/null 2>&1; then
        msg "${GREEN}[PASS] init: OpenRC${NC}"
    else
        msg "${RED}[FAIL] no supported init system detected${NC}"; fail=$((fail+1))
    fi
    case "$(uname -m)" in x86_64|amd64|aarch64|arm64|armv8*) msg "${GREEN}[PASS] arch: $(uname -m)${NC}" ;; *) msg "${RED}[FAIL] unsupported arch: $(uname -m)${NC}"; fail=$((fail+1)) ;; esac
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
}

preflight_check() {
    local report_dir report fail=0 warn=0 port proto holder now interactive=1
    [[ "${1:-}" == '--no-pause' ]] && interactive=0
    report_dir=$(umask 077; mktemp -d /tmp/A-Box-preflight.XXXXXX) || die 'Preflight report directory creation failed.'
    chmod 700 "$report_dir" || die 'Preflight report directory permission setup failed.'
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
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|alpine) pf_pass "supported OS detected: ${ID:-unknown}" ;; *) pf_warn "OS may be unsupported: ${ID:-unknown}" ;; esac
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
    case "$(uname -m)" in x86_64|amd64|aarch64|arm64|armv8*) pf_pass "supported CPU architecture: $(uname -m)" ;; *) pf_fail "unsupported CPU architecture: $(uname -m)" ;; esac

    for c in bash curl jq openssl bc unzip tar iptables ss lsof vnstat python3 getent flock qrencode fail2ban-client; do
        command -v "$c" >/dev/null 2>&1 && pf_pass "command available: $c" || pf_warn "command missing before dependency sync: $c"
    done

    if curl -fsS --connect-timeout 5 -m 10 https://api.github.com >/dev/null 2>&1; then
        pf_pass 'GitHub API reachable'
    else
        pf_warn 'GitHub API unreachable from this host now; official release metadata/digest cannot be verified and core installation may fail'
    fi

    load_abox_env "$ABOX_ENV" 2>/dev/null || true
    for proto in tcp udp; do
        for port in 443 8443 2053 ${VLESS_PORT:-} ${XHTTP_PORT:-} ${HY2_BASE_PORT:-} ${SS_PORT:-}; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${port}\b" || true)
            if [[ -n "$holder" ]]; then
                local managed_owner
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
    done

    managed_services_active && pf_warn 'existing A-Box managed service is active' || pf_pass 'no active A-Box managed service detected'
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
    echo "Report: $report" | tee -a "$report"
    if (( fail > 0 )); then
        msg "${RED}[!] Preflight completed with blocking failures.${NC}"
    elif (( warn > 0 )); then
        msg "${YELLOW}[*] Preflight completed with warnings.${NC}"
    else
        msg "${GREEN}[*] Preflight passed.${NC}"
    fi
    (( interactive == 1 )) && pause_return
    return $(( fail > 0 ? 1 : 0 ))
}


vps_benchmark_menu() {
    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}$(tr_msg toolbox_title)${NC}"
    msg "${CYAN}======================================================================${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}1. System benchmark and download speed${NC}"
        msg "${YELLOW}2. IP quality, streaming unlock and route test${NC}"
        msg "${YELLOW}3. Local SNI preference${NC}"
        msg "${YELLOW}4. Mini host local SNI preference${NC}"
        msg "${YELLOW}5. Cloudflare WARP manager (egress IP masking / streaming unlock)${NC}"
        msg "${YELLOW}6. Allocate 2G Swap (prevent OOM crashes)${NC}"
        msg "${YELLOW}7. Backup / Restore A-Box configuration${NC}"
        msg "${YELLOW}8. Export redacted diagnostic bundle${NC}"
        msg "${YELLOW}9. Full dry-run preflight check${NC}"
        msg "${YELLOW}10. SNI preference records${NC}"
        msg "${GREEN}0. Back${NC}"
    else
        msg "${YELLOW}1. 本机配置和下载测速${NC}"
        msg "${YELLOW}2. IP纯净度、流媒体解锁与回程测试${NC}"
        msg "${YELLOW}3. 本地 SNI 优选${NC}"
        msg "${YELLOW}4. 微型主机本地 SNI 优选${NC}"
        msg "${YELLOW}5. Cloudflare WARP 一键接管 (出站 IP 伪装/流媒体解锁)${NC}"
        msg "${YELLOW}6. Swap 虚拟内存一键划拨 2G (防 OOM 宕机)${NC}"
        msg "${YELLOW}7. 配置备份 / 恢复${NC}"
        msg "${YELLOW}8. 导出脱敏诊断包${NC}"
        msg "${YELLOW}9. 完整 Dry-run 预检查${NC}"
        msg "${YELLOW}10. SNI 优选记录${NC}"
        msg "${GREEN}0. 返回主菜单${NC}"
    fi
    local bench_choice
    read -r -ep 'Select [0-10]: ' bench_choice
    case "$bench_choice" in
        1)
            confirm_yes_no "$(printf "$(tr_msg confirm_remote)" 'System benchmark and download speed')" && run_remote_bash_script 'System benchmark and download speed' 'https://bench.sh'
            pause_return
            ;;
        2)
            confirm_yes_no "$(printf "$(tr_msg confirm_remote)" 'IP quality, streaming unlock and route test')" && run_remote_bash_script 'IP quality, streaming unlock and route test' 'https://Check.Place' -I
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
    read -r -ep '请输入执行代码 [0-2]: ' un_choice
    case "$un_choice" in
        1) auto_backup_prompt 'full uninstall' '/root/A-Box-backups'; do_cleanup full ;;
        2) auto_backup_prompt 'uninstall while keeping script entry' "$ABOX_DIR/backups"; do_cleanup keep ;;
        *) return 0 ;;
    esac
}


urlencode() {
    local raw="${1:-}"
    jq -rn --arg v "$raw" '$v|@uri'
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
    local out="${CLASH_YAML_PATH:-$ABOX_DIR/A-Box-clash.yaml}" S_IP="$LINK_IP" hy2_name="A-Box-Hy2-Self"
    [[ -n "${HY2_DOMAIN:-}" ]] && S_IP="$HY2_DOMAIN"
    [[ -n "${HY2_DOMAIN:-}" && "${CORE:-}" != 'singbox' ]] && hy2_name='A-Box-Hy2-ACME'
    mkdir -p "$ABOX_DIR"
    {
        cat <<EOF_CLASH
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true

dns:
  enable: true
  listen: 0.0.0.0:1053
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
    ports: ${HY2_CLASH_PORTS}
    hop-interval: 30
    password: "$HY2_PASS"
    alpn:
      - h3
    sni: "$HY2_DOMAIN"
    obfs: salamander
    obfs-password: "$HY2_OBFS"
EOF_CLASH
                else
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$HY2_DOMAIN"
    port: $HY2_BASE_PORT
    password: "$HY2_PASS"
    alpn:
      - h3
    sni: "$HY2_DOMAIN"
    obfs: salamander
    obfs-password: "$HY2_OBFS"
EOF_CLASH
                fi
            else
                if [[ "${HY2_HOP:-}" == 'true' ]]; then
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$S_IP"
    ports: ${HY2_CLASH_PORTS}
    hop-interval: 30
    password: "$HY2_PASS"
    alpn:
      - h3
    skip-cert-verify: true
    fingerprint: "$HY2_CERT_SHA256_FP"
    obfs: salamander
    obfs-password: "$HY2_OBFS"
EOF_CLASH
                else
                    cat <<EOF_CLASH
  - name: "$hy2_name"
    type: hysteria2
    server: "$S_IP"
    port: $HY2_BASE_PORT
    password: "$HY2_PASS"
    alpn:
      - h3
    skip-cert-verify: true
    fingerprint: "$HY2_CERT_SHA256_FP"
    obfs: salamander
    obfs-password: "$HY2_OBFS"
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
    password: "$SS_PASS"
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
    } > "$out"
    chmod 600 "$out"
    printf '%s\n' "$out"
}

generate_qr() {
    local url=$1
    if command -v qrencode >/dev/null 2>&1; then
        msg "\n${CYAN}================ 扫码导入 / Scan QR Code =================${NC}"
        printf '%s' "$url" | qrencode -s 1 -m 2 -t UTF8
        msg "${CYAN}==========================================================${NC}\n"
    fi
}

view_config() {
    local CALLER=${1:-manual}
    clear
    [[ ! -f "$ABOX_ENV" ]] && { msg "${RED}未检测到持久化配置变量。${NC}"; sleep 2; return 0; }
    load_abox_env "$ABOX_ENV" || die 'A-Box 状态文件无效或权限不安全。'
    VISION_SNI=${VISION_SNI:-${VLESS_SNI:-}}
    XHTTP_SNI=${XHTTP_SNI:-${VLESS_SNI:-}}
    local F_IP="$LINK_IP" S_IP VLESS_URL XHTTP_URL HY2_URL SS_URL CLASH_FILE CLASH_SUB_URL CLASH_SCHEME
    local VISION_SNI_E XHTTP_SNI_E PUBLIC_KEY_E SHORT_ID_E HY2_PASS_E HY2_OBFS_E HY2_DOMAIN_E HY2_PIN_E
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
        generate_qr "$VLESS_URL"
    fi
    if [[ "$CORE" == 'xray' && ( "$MODE" == *'XHTTP'* || "$MODE" == *'ALL'* ) ]]; then
        XHTTP_URL="vless://$UUID@$F_IP:$XHTTP_PORT?encryption=none&security=reality&sni=$XHTTP_SNI_E&fp=chrome&pbk=$PUBLIC_KEY_E&sid=$SHORT_ID_E&type=xhttp&host=$XHTTP_SNI_E&path=%2Fxhttp&mode=stream-one#A-Box-VLESS-XHTTP"
        msg "${GREEN}${XHTTP_URL}${NC}"
        generate_qr "$XHTTP_URL"
    fi
    if [[ "$MODE" == *'HY2'* || "$MODE" == *'ALL'* ]]; then
        if [[ -n "${HY2_DOMAIN:-}" && "$CORE" != 'singbox' ]]; then
            HY2_URL="hysteria2://$HY2_PASS_E@$HY2_DOMAIN:$HY2_URI_PORTS/?sni=$HY2_DOMAIN_E&obfs=salamander&obfs-password=$HY2_OBFS_E#A-Box-Hy2-ACME"
        else
            S_IP="$F_IP"
            [[ -n "${HY2_DOMAIN:-}" ]] && S_IP="$HY2_DOMAIN"
            HY2_URL="hysteria2://$HY2_PASS_E@$S_IP:$HY2_URI_PORTS/?insecure=1&pinSHA256=$HY2_PIN_E&obfs=salamander&obfs-password=$HY2_OBFS_E#A-Box-Hy2-Self"
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

    CLASH_FILE=$(write_clash_yaml)
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

    msg "\n${YELLOW}--- Sing-box 出站示例 ---${NC}"
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
        msg "\n${YELLOW}--- v2rayN / v2rayNG XHTTP JSON ---${NC}"
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
12 VPS 一键优化
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
    metadata=$(extract_abox_build_metadata "$file") || die 'OTA 脚本缺少可信的 ABOX_BUILD/ABOX_BUILD_EPOCH 元数据。'
    IFS='|' read -r remote_build remote_epoch <<< "$metadata"
    if (( 10#$remote_epoch < 10#$ABOX_BUILD_EPOCH )); then
        [[ "${ABOX_ALLOW_DOWNGRADE:-0}" == 1 ]] || die "拒绝 OTA 降级: local=${ABOX_BUILD}(${ABOX_BUILD_EPOCH}) remote=${remote_build}(${remote_epoch})。如确需降级，显式设置 ABOX_ALLOW_DOWNGRADE=1 并配置 SHA256 allowlist。"
        [[ -n "${ABOX_OTA_SHA256_ALLOWLIST:-}" ]] || die '允许降级时必须同时设置 ABOX_OTA_SHA256_ALLOWLIST。'
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
        die "OTA SHA256 is not in ABOX_OTA_SHA256_ALLOWLIST."
    fi
    if [[ "${ABOX_ASSUME_YES_OTA:-}" == '1' ]]; then
        die 'ABOX_ASSUME_YES_OTA 已禁用；非交互更新必须使用 ABOX_OTA_SHA256_ALLOWLIST。'
    fi
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "${YELLOW}[!] OTA source is pinned to an immutable Git commit. Syntax/fingerprint and SHA256 display are not a cryptographic publisher signature.${NC}"
        msg "${YELLOW}[!] Source: ${url}${NC}"
        read -r -ep 'Install this downloaded A-Box script? [Y/N]: ' answer
    else
        msg "${YELLOW}[!] OTA 已固定到不可变 Git commit。语法/指纹检查与 SHA256 展示仍不是发布者密码学签名。${NC}"
        msg "${YELLOW}[!] 来源：${url}${NC}"
        read -r -ep '是否安装此下载的 A-Box 脚本？[Y/N]: ' answer
    fi
    is_yes "$answer" || return 130
}

update_script() {
    clear
    local OTA_URL tmp_update sha
    OTA_URL=$(resolve_abox_main_commit_url) || die '无法将 A-Box main 分支解析为不可变 commit；已拒绝 OTA。'
    tmp_update=$(mktemp /tmp/A-Box-update.XXXXXX.sh) || die '更新脚本临时文件创建失败。'
    msg "${YELLOW}[*] 正在同步固定 commit 的远端源码...${NC}"
    if curl -fLsS --connect-timeout 10 -m 60 "$OTA_URL" -o "$tmp_update"; then
        sha=$(sha256sum "$tmp_update" | awk '{print $1}')
        msg "${YELLOW}[*] OTA SHA256: ${sha}${NC}"
        if validate_abox_script_file "$tmp_update" 'OTA A-Box 脚本'; then
            validate_ota_version_direction "$tmp_update"
            msg "${YELLOW}[*] OTA remote build: ${OTA_REMOTE_BUILD} (${OTA_REMOTE_EPOCH})${NC}"
            confirm_ota_script_hash "$sha" "$OTA_URL" || { rm -f "$tmp_update"; msg "${YELLOW}[*] OTA update canceled.${NC}"; pause_return; return 0; }
            install_binary_atomically "$tmp_update" "$ABOX_DIR/A-Box.sh" || { rm -f "$tmp_update"; die 'OTA 脚本原子写入失败。'; }
            validate_abox_script_file "$ABOX_DIR/A-Box.sh" '持久化 A-Box 脚本'
            rm -f "$tmp_update"
            msg "${GREEN}核心代码热更新完毕。${NC}"
            sleep 2
            export ABOX_INHERITED_LOCK_MODE="$ABOX_RUNTIME_LOCK_MODE"
            exec "$ABOX_DIR/A-Box.sh"
        else
            rm -f "$tmp_update"
            msg "${RED}[!] 更新脚本语法错误或指纹校验失败。${NC}"
        fi
    else
        rm -f "$tmp_update"
        msg "${RED}[!] 无法抵达更新服务器。${NC}"
    fi
    pause_return
}

force_update_geo() {
    clear
    init_system_environment
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
        systemctl daemon-reload >/dev/null 2>&1 || true
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

upgrade_xray_core_only() {
    local was_active=0 backup='' tmp xray_zip xray_ext old_ver new_ver
    abox_owns_service xray || die '拒绝升级：xray 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading Xray-core binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running xray && was_active=1 || true
    [[ -x /usr/local/bin/xray ]] && old_ver=$(/usr/local/bin/xray version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-xray.XXXXXX) || die 'Xray core upgrade temp directory failed.'
    xray_zip="$tmp/xray_core.zip"; xray_ext="$tmp/xray_ext"; mkdir -p "$xray_ext"
    fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
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
    if [[ "$was_active" == '1' ]] && ! restart_service_soft xray; then
        msg "${RED}[!] New Xray failed to restart. Rolling back binary...${NC}"
        rollback_binary_install /usr/local/bin/xray "$backup" >/dev/null 2>&1 || true
        restart_service_soft xray >/dev/null 2>&1 || true
        rm -rf "$tmp"; die 'Xray core upgrade rolled back because service restart failed.'
    fi
    msg "${GREEN}[OK] Xray-core upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

upgrade_singbox_core_only() {
    local was_active=0 backup='' tmp sb_tar sb_ext sb_path old_ver new_ver
    abox_owns_service sing-box || die '拒绝升级：sing-box 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading sing-box binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running sing-box && was_active=1 || true
    [[ -x /usr/local/bin/sing-box ]] && old_ver=$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-singbox.XXXXXX) || die 'sing-box core upgrade temp directory failed.'
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
    if [[ "$was_active" == '1' ]] && ! restart_service_soft sing-box; then
        msg "${RED}[!] New sing-box failed to restart. Rolling back binary...${NC}"
        rollback_binary_install /usr/local/bin/sing-box "$backup" >/dev/null 2>&1 || true
        restart_service_soft sing-box >/dev/null 2>&1 || true
        rm -rf "$tmp"; die 'sing-box core upgrade rolled back because service restart failed.'
    fi
    msg "${GREEN}[OK] sing-box upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

upgrade_hysteria_core_only() {
    local was_active=0 backup='' tmp hy2_bin old_ver new_ver
    abox_owns_service hysteria || die '拒绝升级：hysteria 不是 A-Box 托管服务。'
    msg "${YELLOW}[*] Upgrading Hysteria 2 binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running hysteria && was_active=1 || true
    [[ -x /usr/local/bin/hysteria ]] && old_ver=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-hysteria.XXXXXX) || die 'Hysteria core upgrade temp directory failed.'
    hy2_bin="$tmp/hysteria_core"
    fetch_github_release apernet/hysteria hysteria_core "$hy2_bin"
    chmod 755 "$hy2_bin" || { rm -rf "$tmp"; die 'Hysteria staged binary chmod failed.'; }
    new_ver=$("$hy2_bin" version 2>/dev/null | head -n 1 || true)
    [[ -n "$new_ver" ]] || { rm -rf "$tmp"; die 'Hysteria staged binary execution check failed.'; }
    [[ -f /usr/local/bin/hysteria ]] && { backup="$tmp/hysteria.backup"; cp -a /usr/local/bin/hysteria "$backup" || { rm -rf "$tmp"; die 'Hysteria binary backup failed.'; }; }
    install_binary_atomically "$hy2_bin" /usr/local/bin/hysteria || { rm -rf "$tmp"; die 'Hysteria binary atomic install failed.'; }
    if [[ "$was_active" == '1' ]] && ! restart_service_soft hysteria; then
        msg "${RED}[!] New Hysteria failed to restart. Rolling back binary...${NC}"
        rollback_binary_install /usr/local/bin/hysteria "$backup" >/dev/null 2>&1 || true
        restart_service_soft hysteria >/dev/null 2>&1 || true
        rm -rf "$tmp"; die 'Hysteria core upgrade rolled back because service restart failed.'
    fi
    msg "${GREEN}[OK] Hysteria upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

restore_core_upgrade_transaction_traps() {
    restore_saved_trap EXIT "$ABOX_CORE_TX_PREV_TRAP_EXIT"
    restore_saved_trap INT "$ABOX_CORE_TX_PREV_TRAP_INT"
    restore_saved_trap TERM "$ABOX_CORE_TX_PREV_TRAP_TERM"
    restore_saved_trap HUP "$ABOX_CORE_TX_PREV_TRAP_HUP"
    ABOX_CORE_TX_PREV_TRAP_EXIT=''; ABOX_CORE_TX_PREV_TRAP_INT=''; ABOX_CORE_TX_PREV_TRAP_TERM=''; ABOX_CORE_TX_PREV_TRAP_HUP=''
ABOX_CORE_UPGRADE_TARGETS=''
}

core_upgrade_transaction_rollback() {
    [[ "${ABOX_CORE_UPGRADE_ACTIVE:-0}" == 1 ]] || return 0
    local backup="${ABOX_CORE_UPGRADE_BACKUP:-}" targets="${ABOX_CORE_UPGRADE_TARGETS:-}" srv
    ABOX_CORE_UPGRADE_ACTIVE=0
    ABOX_CORE_UPGRADE_BACKUP=''
    ABOX_CORE_UPGRADE_TARGETS=''
    ABOX_DIE_HOOK=''
    restore_core_upgrade_transaction_traps
    msg "${YELLOW}[!] Core upgrade failed or was interrupted; restoring the exact pre-upgrade snapshot.${NC}"
    stop_all_managed_services >/dev/null 2>&1 || true
    for srv in $targets; do
        case "$srv" in singbox) srv='sing-box' ;; esac
        remove_core_family_force "$srv"
    done
    restore_latest_backup_silent "$ABOX_DIR/backups" "$backup" || msg "${RED}[!] Core upgrade rollback failed: ${backup:-missing}${NC}"
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
    ABOX_DIE_HOOK=''
    restore_core_upgrade_transaction_traps
}

upgrade_current_cores_only() {
    clear
    init_system_environment
    load_abox_env "$ABOX_ENV" 2>/dev/null || true
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
    read -r -ep 'Continue core-only upgrade? [Y/N]: ' answer
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
        msg "${GREEN}0. Back${NC}"
        read -r -ep 'Select [0-3]: ' ota_choice
    else
        msg "${BOLD}${GREEN}脚本 OTA、Xray Geo 与核心无损升级${NC}"
        msg "${CYAN}======================================================================${NC}"
        msg "${YELLOW}1. 升级 A-Box 核心脚本${NC}"
        msg "${YELLOW}2. 立即拉取并更新 Xray Loyalsoldier Geo 资源${NC}"
        msg "${YELLOW}3. 仅升级当前已安装协议核心，不重置节点参数${NC}"
        msg "${GREEN}0. 返回主菜单${NC}"
        read -r -ep '请选择 [0-3]: ' ota_choice
    fi
    case "$ota_choice" in
        1) update_script ;;
        2) force_update_geo ;;
        3) upgrade_current_cores_only ;;
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
        chown root:root "$LOCK_FILE" || return 1
        chmod 600 "$LOCK_FILE" || return 1
    fi
    exec 9>>"$LOCK_FILE" || return 1
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
    local existing_pid existing_start actual_start
    if mkdir -m 700 "$LOCK_FALLBACK_DIR" 2>/dev/null; then
        chown root:root "$LOCK_FALLBACK_DIR" || { rmdir "$LOCK_FALLBACK_DIR"; return 1; }
    else
        if [[ -d "$LOCK_FALLBACK_DIR" && ! -L "$LOCK_FALLBACK_DIR" && -r "$LOCK_FALLBACK_DIR/pid" && -r "$LOCK_FALLBACK_DIR/starttime" ]]; then
            IFS= read -r existing_pid < "$LOCK_FALLBACK_DIR/pid" || existing_pid=''
            IFS= read -r existing_start < "$LOCK_FALLBACK_DIR/starttime" || existing_start=''
            if [[ "$existing_pid" =~ ^[0-9]+$ && -d "/proc/$existing_pid" ]]; then
                actual_start=$(runtime_lock_proc_starttime "$existing_pid" || true)
                [[ -n "$actual_start" && "$actual_start" == "$existing_start" ]] && return 1
            fi
            [[ "$(stat -c %u:%g "$LOCK_FALLBACK_DIR" 2>/dev/null || true)" == 0:0 ]] || return 1
            rm -f -- "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" 2>/dev/null || return 1
            rmdir -- "$LOCK_FALLBACK_DIR" 2>/dev/null || return 1
            mkdir -m 700 "$LOCK_FALLBACK_DIR" || return 1
            chown root:root "$LOCK_FALLBACK_DIR" || return 1
        else
            return 1
        fi
    fi
    umask 077
    printf '%s\n' "$$" > "$LOCK_FALLBACK_DIR/pid" || return 1
    printf '%s\n' "$(runtime_lock_proc_starttime $$)" > "$LOCK_FALLBACK_DIR/starttime" || return 1
    chmod 600 "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" || return 1
    chown root:root "$LOCK_FALLBACK_DIR/pid" "$LOCK_FALLBACK_DIR/starttime" || return 1
    ABOX_RUNTIME_LOCK_MODE='fallback'
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
    local srv failed=0 services
    prepare_noninteractive_service_control
    services=$(expected_managed_services) || die '无法读取有效的 A-Box 部署状态。'
    set_desired_state MANUAL_STOPPED || die '无法写入 MANUAL_STOPPED 状态。'
    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        stop_abox_service "$srv" || failed=1
    done <<< "$services"
    (( failed == 0 )) || die '至少一个托管服务停止失败。'
    printf 'A-Box managed stack stopped; Intent=MANUAL_STOPPED\n'
}

manual_start_managed_stack() {
    local srv failed=0 services
    prepare_noninteractive_service_control
    services=$(expected_managed_services) || die '无法读取有效的 A-Box 部署状态。'
    while IFS= read -r srv; do
        [[ -n "$srv" ]] || continue
        abox_owns_service "$srv" || { failed=1; continue; }
        service_manager start "$srv" || failed=1
    done <<< "$services"
    if (( failed == 0 )); then
        if clear_traffic_block_period && set_desired_state RUNNING; then
            printf 'A-Box managed stack started; Intent=RUNNING\n'
        else
            while IFS= read -r srv; do
                [[ -n "$srv" ]] || continue
                stop_abox_service "$srv" >/dev/null 2>&1 || true
            done <<< "$services"
            set_desired_state MANUAL_STOPPED || true
            die '服务已启动但状态提交失败；已回滚停服并保持 MANUAL_STOPPED。'
        fi
    else
        while IFS= read -r srv; do
            [[ -n "$srv" ]] || continue
            stop_abox_service "$srv" >/dev/null 2>&1 || true
        done <<< "$services"
        set_desired_state MANUAL_STOPPED || true
        die '至少一个托管服务启动失败；已回滚停服并保持 MANUAL_STOPPED。'
    fi
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
    local tmp failures=0
    tmp=$(mktemp -d /tmp/A-Box-selftest.XXXXXX) || exit 1
    trap 'rm -rf "$tmp"' RETURN
    assert_ok() { "$@" >/dev/null 2>&1 || { echo "FAIL: $*"; failures=$((failures + 1)); }; }
    assert_bad() { "$@" >/dev/null 2>&1 && { echo "FAIL expected bad: $*"; failures=$((failures + 1)); } || true; }

    assert_ok valid_port 1
    assert_ok valid_port 65535
    assert_bad valid_port 0
    assert_bad valid_port 65536
    assert_bad valid_port 08x
    assert_ok valid_port_range 20000:25000
    assert_ok valid_port_range 20000-25000
    assert_bad valid_port_range 25000:20000
    assert_ok valid_domain example.com
    assert_bad valid_domain -bad.example.com
    assert_ok valid_url_https https://example.com/path
    assert_ok valid_url_https https://example.com:443/path
    assert_bad valid_url_https http://example.com/
    assert_bad valid_url_https 'https://bad example.com/'
    [[ "$(normalize_https_url_input www.microsoft.com)" == 'https://www.microsoft.com/' ]] || { echo 'FAIL: normalize HTTPS URL'; failures=$((failures + 1)); }
    [[ "$(normalize_https_url_input https://www.microsoft.com)" == 'https://www.microsoft.com/' ]] || { echo 'FAIL: normalize HTTPS URL trailing slash'; failures=$((failures + 1)); }
    [[ "$(build_ss2022_uri 203.0.113.10 2053 'abc+/=')" == 'ss://2022-blake3-aes-128-gcm:abc%2B%2F%3D@203.0.113.10:2053#A-Box-SS' ]] || { echo 'FAIL: SS-2022 SIP002/SIP022 URI percent encoding'; failures=$((failures + 1)); }

    ABOX_SNI_FULL_MAX=0 write_sni_candidate_library full "$tmp/sni-full.txt"
    sni_count=$(wc -l < "$tmp/sni-full.txt" | tr -d ' ')
    [[ "$sni_count" =~ ^[0-9]+$ && "$sni_count" -ge 2500 ]] || { echo "FAIL: SNI library size < 2500 ($sni_count)"; failures=$((failures + 1)); }
    grep -qx 'www.confluent.io' "$tmp/sni-full.txt" || { echo 'FAIL: SNI library missing www.confluent.io'; failures=$((failures + 1)); }
    grep -qx 'www.apache.org' "$tmp/sni-full.txt" || { echo 'FAIL: SNI library missing www.apache.org'; failures=$((failures + 1)); }
    if grep -Eiq '(^|\.)(google|gstatic|googleapis|googleusercontent|youtube|facebook|instagram|twitter|x|tiktok|telegram|whatsapp|wikipedia|wikimedia|openai|anthropic|huggingface|torproject|apple|icloud|nist|cisa|github)\.' "$tmp/sni-full.txt"; then
        echo 'FAIL: SNI library contains high-risk blocked/sanction-sensitive domains'
        failures=$((failures + 1))
    fi
    ABOX_SNI_MINI_MAX=0 write_sni_candidate_library mini "$tmp/sni-mini.txt"
    mini_count=$(wc -l < "$tmp/sni-mini.txt" | tr -d ' ')
    [[ "$mini_count" =~ ^[0-9]+$ && "$mini_count" -eq "$sni_count" ]] || { echo "FAIL: SNI mini library does not match full library ($mini_count vs $sni_count)"; failures=$((failures + 1)); }
    declare -f asn_lookup_ip >/dev/null || { echo 'FAIL: ASN lookup function missing'; failures=$((failures + 1)); }
    declare -f sni_org_cdn_penalty >/dev/null || { echo 'FAIL: ASN/CDN scoring function missing'; failures=$((failures + 1)); }
    [[ "$(tr_msg confirm_local_sni_full)" != *'远程执行第三方脚本'* ]] || { echo 'FAIL: local SNI prompt still says remote third-party'; failures=$((failures + 1)); }
    assert_ok valid_ipv4_cidr 192.0.2.1/24
    assert_bad valid_ipv4_cidr 999.0.2.1/24
    assert_ok valid_ipv6_cidr 2001:db8::1/64
    assert_bad valid_ipv6_cidr 2001:::1/64
    declare -F backup_current_config >/dev/null 2>&1 || { echo 'FAIL: backup_current_config missing'; failures=$((failures + 1)); }
    declare -F export_diagnostic_bundle >/dev/null 2>&1 || { echo 'FAIL: export_diagnostic_bundle missing'; failures=$((failures + 1)); }
    declare -F preflight_check >/dev/null 2>&1 || { echo 'FAIL: preflight_check missing'; failures=$((failures + 1)); }
    declare -F confirm_remote_script_hash >/dev/null 2>&1 || { echo 'FAIL: remote script hash gate missing'; failures=$((failures + 1)); }
    declare -F confirm_ota_script_hash >/dev/null 2>&1 || { echo 'FAIL: OTA hash gate missing'; failures=$((failures + 1)); }
    declare -F validate_ota_version_direction >/dev/null 2>&1 || { echo 'FAIL: OTA anti-downgrade gate missing'; failures=$((failures + 1)); }
    declare -F install_deployment_transaction_traps >/dev/null 2>&1 || { echo 'FAIL: deployment signal traps missing'; failures=$((failures + 1)); }
    declare -F install_core_upgrade_transaction_traps >/dev/null 2>&1 || { echo 'FAIL: core-upgrade signal traps missing'; failures=$((failures + 1)); }
    declare -F convert_legacy_backup_archive >/dev/null 2>&1 || { echo 'FAIL: legacy backup converter missing'; failures=$((failures + 1)); }
    declare -F record_core_family_ownership >/dev/null 2>&1 || { echo 'FAIL: per-file core ownership missing'; failures=$((failures + 1)); }
    declare -F validate_abox_cron_file >/dev/null 2>&1 || { echo 'FAIL: cron semantic validator missing'; failures=$((failures + 1)); }
    [[ "$ABOX_BUILD_EPOCH" =~ ^[0-9]+$ ]] || { echo 'FAIL: numeric build epoch missing'; failures=$((failures + 1)); }
    declare -F remove_ss_open_accept_rules >/dev/null 2>&1 || { echo 'FAIL: SS open ACCEPT cleanup missing'; failures=$((failures + 1)); }
    declare -F show_sni_preference_records >/dev/null 2>&1 || { echo 'FAIL: SNI record viewer missing'; failures=$((failures + 1)); }
    declare -F validate_abox_script_file >/dev/null 2>&1 || { echo 'FAIL: local script validation gate missing'; failures=$((failures + 1)); }
    declare -F install_remote_abox_script_guarded >/dev/null 2>&1 || { echo 'FAIL: guarded remote shortcut installer missing'; failures=$((failures + 1)); }
    declare -F validate_fail2ban_config_or_die >/dev/null 2>&1 || { echo 'FAIL: fail2ban validation gate missing'; failures=$((failures + 1)); }
    ( verify_github_asset_digest /dev/null '' ) >/dev/null 2>&1 && { echo 'FAIL: missing GitHub digest must be rejected'; failures=$((failures + 1)); }
    grep -q "GitHub Release asset digest missing; by"'passed' "$0" && { echo 'FAIL: unsigned GitHub asset bypass must not exist'; failures=$((failures + 1)); }
    ( ABOX_ASSUME_YES_OTA=1 confirm_ota_script_hash 0000000000000000000000000000000000000000000000000000000000000000 https://example.com/script.sh ) >/dev/null 2>&1 && { echo 'FAIL: ABOX_ASSUME_YES_OTA must be rejected without allowlist'; failures=$((failures + 1)); }

    [[ "$(normalize_port_spec 020000-025000)" == '20000:25000' ]] || { echo 'FAIL: normalize port range'; failures=$((failures + 1)); }
    [[ "$(port_spec_for_firewalld 20000:25000)" == '20000-25000' ]] || { echo 'FAIL: firewalld range conversion'; failures=$((failures + 1)); }
    assert_ok valid_port_spec 20000:25000
    assert_bad valid_port_spec 25000:20000

    local redacted
    redacted=$(printf '%s
' '{"password":"secret","nested":{"token":"abc"},"uri":"vless://abc@host:443"}' | redact_secrets_stream)
    grep -q '\*\*\*REDACTED\*\*\*' <<< "$redacted" || { echo 'FAIL: JSON secret redaction'; failures=$((failures + 1)); }
    grep -q '\*\*\*CLIENT_LINK_REDACTED\*\*\*' <<< "$redacted" || { echo 'FAIL: client URI redaction'; failures=$((failures + 1)); }
    grep -qE 'secret|vless://abc' <<< "$redacted" && { echo 'FAIL: redaction leaked secret'; failures=$((failures + 1)); }

    printf 'new-content
' > "$tmp/atomic.src"
    printf 'old-content
' > "$tmp/atomic.dest"
    assert_ok install_file_atomically "$tmp/atomic.src" "$tmp/atomic.dest" 600
    cmp -s "$tmp/atomic.src" "$tmp/atomic.dest" || { echo 'FAIL: atomic file install content'; failures=$((failures + 1)); }
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
    create_backup_manifest "$tmp/archive-good" "$tmp/archive-good/meta/manifest.sha256"
    tar -C "$tmp/archive-good" -czf "$tmp/good.tar.gz" root meta
    assert_ok validate_backup_archive "$tmp/good.tar.gz"
    mkdir -p "$tmp/archive-bad/root/etc/ddr" "$tmp/archive-bad/meta"
    ln -s ../../../../etc/shadow "$tmp/archive-bad/root/etc/ddr/escape"
    tar -C "$tmp/archive-bad" -czf "$tmp/bad.tar.gz" root meta
    assert_bad validate_backup_archive "$tmp/bad.tar.gz"

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
        printf '%s
' 'BAD=$(touch /tmp/A-Box-selftest-owned)' >> "$ABOX_ENV"
        assert_bad load_abox_env "$ABOX_ENV"
        [[ ! -e /tmp/A-Box-selftest-owned ]] || { rm -f /tmp/A-Box-selftest-owned; echo 'FAIL: state file command execution'; failures=$((failures + 1)); }
        ABOX_ENV="$saved_abox_env"
    fi

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
    XRAY_CONFIG_PATH="$tmp/xray/config.json" build_xray_config ALL
    jq empty "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: build_xray_config JSON'; failures=$((failures + 1)); }
    local saved_vision_sni="$VISION_SNI" saved_vless_sni="$VLESS_SNI"
    unset VISION_SNI VLESS_SNI
    XRAY_CONFIG_PATH="$tmp/xray/default-sni.json" build_xray_config VISION
    jq -e '.inbounds[] | select(.protocol=="vless" and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/default-sni.json" >/dev/null 2>&1 || { echo 'FAIL: default REALITY SNI must be www.microsoft.com'; failures=$((failures + 1)); }
    VISION_SNI="$saved_vision_sni" VLESS_SNI="$saved_vless_sni"
    jq -e '.inbounds[] | select(.protocol=="shadowsocks" and .port==2053 and .settings.network=="tcp,udp")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray SS-2022 2053 tcp,udp'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.protocol=="vless" and .port==8443 and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray Vision SNI split'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.protocol=="vless" and .port==9443 and .streamSettings.realitySettings.serverNames[0]=="www.microsoft.com")' "$tmp/xray/config.json" >/dev/null 2>&1 || { echo 'FAIL: Xray XHTTP SNI split'; failures=$((failures + 1)); }
    SINGBOX_CONFIG_PATH="$tmp/sing-box/config.json" build_singbox_config ALL
    jq empty "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: build_singbox_config JSON'; failures=$((failures + 1)); }
    jq -e '.inbounds[] | select(.type=="shadowsocks" and .listen_port==2053 and (.network|not))' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box SS-2022 2053 default network'; failures=$((failures + 1)); }
    jq -e 'all(.inbounds[]; .type != "xhttp")' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box ALL must not include XHTTP'; failures=$((failures + 1)); }
    jq -e '(.route.rules[] | select(.action=="sniff")) and (.route.rules[] | select(.protocol=="bittorrent" and .action=="reject"))' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box sniff/reject route action'; failures=$((failures + 1)); }
    jq -e 'all(.outbounds[]; .type != "block")' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box legacy block outbound remains'; failures=$((failures + 1)); }
    ABOX_DIR="$tmp" ABOX_ENV="$tmp/.env" CORE=xray MODE=ALL PUBLIC_KEY=publickey LINK_IP=203.0.113.10 HY2_DOMAIN= HY2_HOP=false HY2_CERT_SHA256_FP=abcdef HY2_CERT_PUBKEY_SHA256_B64=abcdef CLASH_YAML_PATH="$tmp/A-Box-clash.yaml" write_clash_yaml >/dev/null
    grep -q '^proxy-groups:' "$tmp/A-Box-clash.yaml" || { echo 'FAIL: Clash YAML proxy-groups'; failures=$((failures + 1)); }
    grep -q '^dns:' "$tmp/A-Box-clash.yaml" || { echo 'FAIL: Clash YAML dns'; failures=$((failures + 1)); }
    grep -q 'host: "www.microsoft.com"' "$tmp/A-Box-clash.yaml" || { echo 'FAIL: Clash XHTTP host'; failures=$((failures + 1)); }
    CORE=xray HY2_DOMAIN=hy2.example.com HY2_CERT_PUBKEY_SHA256_B64= singbox_hy2_tls_json | grep -q '"server_name": "hy2.example.com"' || { echo 'FAIL: Sing-box HY2 ACME TLS sample'; failures=$((failures + 1)); }
    CORE=singbox HY2_DOMAIN=hy2.example.com HY2_CERT_PUBKEY_SHA256_B64=abcdef singbox_hy2_tls_json | grep -q 'certificate_public_key_sha256' || { echo 'FAIL: Sing-box HY2 self-signed TLS sample'; failures=$((failures + 1)); }

    if (( failures > 0 )); then
        echo "SELF_TEST_FAILED=$failures"
        return 1
    fi
    echo 'SELF_TEST_OK'
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
        *) enter_runtime "$@"; main_loop "$@" ;;
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
        pid_exe_matches "$_pid" "$_exe" && record_core_family_ownership "$_srv" || true
    done
    GLOBAL_PUBLIC_IP=$(get_public_ip || true)
    while true; do
        local STATUS_STR='' CUR_MODE='' choice
        STATUS_STR=$(build_status_str)
        load_abox_env "$ABOX_ENV" 2>/dev/null && CUR_MODE="[${CORE}-${MODE}]" || CUR_MODE=''
        clear
        msg "${BLUE}======================================================================${NC}"
        msg "${BOLD}${YELLOW}=================================A-Box===============================${NC}"
        msg "${BLUE}======================================================================${NC}"
        if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
            msg "Gateway: ${YELLOW}$GLOBAL_PUBLIC_IP${NC} | Core: $STATUS_STR $CUR_MODE"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${YELLOW}[ Xray-core Deployment ]${NC}              ${YELLOW}[ Sing-box Deployment ]${NC}"
            msg "${GREEN}1.${NC} VLESS-Vision-Reality               ${GREEN}6.${NC} VLESS-Vision-Reality"
            msg "${GREEN}2.${NC} VLESS-XHTTP-Reality                ${GREEN}7.${NC} Shadowsocks-2022"
            msg "${GREEN}3.${NC} Shadowsocks-2022                   ${GREEN}8.${NC} VLESS + SS-2022"
            msg "${GREEN}4.${NC} Hysteria 2 (Native/Apernet)        ${GREEN}9.${NC} Hysteria 2 (Sing-box)"
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
            msg "${GREEN} 0.${NC} Exit"
            msg "${BLUE}======================================================================${NC}"
            read -r -ep "$(tr_msg main_command)" choice
        else
            msg "网关/Gateway: ${YELLOW}$GLOBAL_PUBLIC_IP${NC} | 核心/Core: $STATUS_STR $CUR_MODE"
            msg "${BLUE}----------------------------------------------------------------------${NC}"
            msg "${YELLOW}[ Xray-core 部署 ]${NC}                    ${YELLOW}[ Sing-box 部署 ]${NC}"
            msg "${GREEN}1.${NC} VLESS-Vision-Reality               ${GREEN}6.${NC} VLESS-Vision-Reality"
            msg "${GREEN}2.${NC} VLESS-XHTTP-Reality                ${GREEN}7.${NC} Shadowsocks-2022"
            msg "${GREEN}3.${NC} Shadowsocks-2022                   ${GREEN}8.${NC} VLESS + SS-2022"
            msg "${GREEN}4.${NC} Hysteria 2 (官方/Apernet)          ${GREEN}9.${NC} Hysteria 2 (Sing-box)"
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
            msg "${GREEN} 0.${NC} 退出脚本"
            msg "${BLUE}======================================================================${NC}"
            read -r -ep "$(tr_msg main_command)" choice
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
            0) clear; exit 0 ;;
            *) sleep 1 ;;
        esac
    done
}

main "$@"
