#!/usr/bin/env bash
# ==============================A-Box===============================
# SNI profile: built-in deduplicated maximum REALITY target candidate library; no legacy remote SNI script dependency.
# Hardened build: stricter GitHub digest trust, guarded shortcut persistence, Fail2Ban validation, and Sing-box HY2 ACME semantics.
set -o pipefail
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

DEPS_MARKER='/etc/ddr/.deps.v20260507'
SCRIPT_URL='https://raw.githubusercontent.com/alariclin/a-box/main/install.sh'
ABOX_DIR='/etc/ddr'
ABOX_ENV='/etc/ddr/.env'
ABOX_FW_STATE='/etc/ddr/.firewall-native.rules'
LOCK_FILE='/var/run/A-Box.lock'
LANG_FILE='/etc/ddr/.lang'
PUBLIC_IP_CACHE='/etc/ddr/.public_ip.cache'
PUBLIC_IP_CACHE_TTL=600
ABOX_LANG='zh'

msg() { echo -e "$*"; }
die() {
    echo -e "${RED}[!] $*${NC}" >&2
    if [[ -n "${ABOX_DIE_HOOK:-}" ]] && declare -F "$ABOX_DIE_HOOK" >/dev/null 2>&1; then
        "$ABOX_DIE_HOOK" "$*" || true
    fi
    exit 1
}
now_iso() { date '+%Y-%m-%dT%H:%M:%S%z'; }

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
    mkdir -p "$ABOX_DIR"
    printf '%s\n' "${ABOX_LANG:-zh}" > "$LANG_FILE"
    chmod 600 "$LANG_FILE" 2>/dev/null || true
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

valid_positive_int() {
    [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

valid_domain() {
    local domain="${1:-}"
    [[ ${#domain} -le 253 ]] || return 1
    [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

valid_sni() { valid_domain "$1"; }

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
    local label="$1" port="$2" default_sni input answer prompt
    default_sni=$(default_sni_for_port "$port")
    while true; do
        printf -v prompt "$(tr_msg reality_sni_prompt)" "$label" "$port" "$default_sni"
        read -r -ep "$prompt" input
        input=${input:-$default_sni}
        if ! valid_sni "$input"; then
            echo -e "${RED}[!] $(printf "$(tr_msg bad_sni)" "$input")${NC}" >&2
            continue
        fi
        if [[ "$port" != '443' ]] && is_apple_like_sni "$input"; then
            echo -e "${YELLOW}[!] $(printf "$(tr_msg apple_non443_warn)" "$input")${NC}" >&2
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
    return 0
}

shell_quote() { printf '%q' "${1:-}"; }
json_escape() { jq -Rn --arg v "${1:-}" '$v'; }

rand_alnum() {
    local len="$1" out=''
    while [[ ${#out} -lt "$len" ]]; do
        out+="$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9')"
    done
    printf '%s\n' "${out:0:$len}"
}

generate_robust_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        local u
        u=$(tr -dc 'a-f0-9' < /dev/urandom | fold -w 32 | head -n 1)
        [[ ${#u} -eq 32 ]] || die 'UUID 随机源读取失败。'
        echo "${u:0:8}-${u:8:4}-4${u:13:3}-8${u:17:3}-${u:20:12}"
    fi
}

pin_sha256_colon() {
    openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2
}

get_public_ip_fresh() {
    local ip api
    for api in 'https://api.ipify.org' 'https://ifconfig.me/ip' 'https://icanhazip.com'; do
        ip=$(curl -fsS4 --connect-timeout 1 -m 2 "$api" 2>/dev/null | tr -d '[:space:]')
        if valid_ipv4_cidr "$ip"; then
            printf '%s\n' "$ip"
            return 0
        fi
    done
    ip=$(curl -fsS6 --connect-timeout 1 -m 2 'https://api64.ipify.org' 2>/dev/null | tr -d '[:space:]')
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
    mkdir -p "$ABOX_DIR" 2>/dev/null || true
    printf '%s\n' "$ip" > "$PUBLIC_IP_CACHE" 2>/dev/null || true
    chmod 600 "$PUBLIC_IP_CACHE" 2>/dev/null || true
}

read_cached_public_ip() {
    local ip now mtime age
    [[ -r "$PUBLIC_IP_CACHE" ]] || return 1
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
    local ip
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
    if [[ -r "$PUBLIC_IP_CACHE" ]]; then
        ip=$(head -n 1 "$PUBLIC_IP_CACHE" 2>/dev/null | tr -d '[:space:]')
        if valid_ipv4_cidr "$ip" || valid_ipv6_cidr "$ip"; then
            printf '%s\n' "$ip"
            return 0
        fi
    fi
    printf 'N/A\n'
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
    [[ -z "$iface" ]] && iface=$(ip -o route show to default 2>/dev/null | awk '{print $5; exit}')
    [[ -z "$iface" ]] && iface=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1 | tr -d ' ')
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
    installType=''
    removeType=''
    deps_initialized=0
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in
            debian) release='debian'; installType='apt-get -y install'; removeType='apt-get -y autoremove' ;;
            ubuntu) release='ubuntu'; installType='apt-get -y install'; removeType='apt-get -y autoremove' ;;
            alpine) release='alpine'; installType='apk add'; removeType='apk del' ;;
            centos|rhel|rocky|almalinux|fedora) release='centos'; installType='yum -y install'; removeType='yum -y remove' ;;
        esac
    fi
    if [[ -z "$release" ]]; then
        if [[ -f /etc/redhat-release ]] || grep -qiE 'centos|red hat|rocky|almalinux|fedora' /proc/version 2>/dev/null; then
            release='centos'; installType='yum -y install'; removeType='yum -y remove'
        elif grep -qi 'Alpine' /etc/issue /proc/version 2>/dev/null; then
            release='alpine'; installType='apk add'; removeType='apk del'
        elif grep -qi 'debian' /etc/issue /proc/version 2>/dev/null; then
            release='debian'; installType='apt-get -y install'; removeType='apt-get -y autoremove'
        elif grep -qi 'ubuntu' /etc/issue /proc/version 2>/dev/null; then
            release='ubuntu'; installType='apt-get -y install'; removeType='apt-get -y autoremove'
        fi
    fi
    [[ -z "$release" ]] && die '本脚本不支持当前异构系统。'
    if [[ "$release" == 'centos' ]] && command -v dnf >/dev/null 2>&1; then
        installType='dnf -y install'
        removeType='dnf -y remove'
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
            centos) if command -v dnf >/dev/null 2>&1; then dnf makecache -y -q >/dev/null 2>&1 || true; else yum makecache -y -q >/dev/null 2>&1 || true; fi; ${installType} epel-release >/dev/null 2>&1 || true ;;
            alpine) apk update -q >/dev/null 2>&1 ;;
        esac
        local deps=()
        case "$release" in
            debian|ubuntu)
                deps=(wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates iproute2 coreutils cron uuid-runtime iptables-persistent netfilter-persistent fail2ban python3)
                ;;
            centos)
                deps=(wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates coreutils cronie util-linux bind-utils iproute fail2ban iptables-services epel-release python3)
                ;;
            alpine)
                deps=(bash wget curl jq openssl bc unzip vnstat iptables tar psmisc lsof qrencode ca-certificates iproute2 coreutils util-linux bind-tools procps fail2ban iptables-openrc python3)
                ;;
        esac
        ${installType} "${deps[@]}" >/dev/null 2>&1 || die '基础依赖包安装失败。'
        mkdir -p "$ABOX_DIR" && touch "$DEPS_MARKER"
        deps_initialized=1
    fi

    ensure_commands

    start_unit_if_exists() {
        local unit="$1"
        systemctl list-unit-files "$unit.service" >/dev/null 2>&1 || return 0
        systemctl enable --now "$unit" >/dev/null 2>&1 || true
    }

    if [[ "$deps_initialized" == '1' ]]; then
        if [[ "$INIT_SYS" == 'systemd' ]]; then
            case "$release" in
                debian|ubuntu) start_unit_if_exists cron ;;
                centos) start_unit_if_exists crond ;;
            esac
            start_unit_if_exists vnstat
            if [[ "$release" == 'centos' ]]; then
                if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
                    msg "${YELLOW}[*] firewalld is active; A-Box will add required ports natively and will not disable it.${NC}"
                else
                    systemctl enable --now iptables ip6tables 2>/dev/null || true
                fi
            fi
        else
            rc-update add crond default 2>/dev/null || true
            rc-update add vnstatd default 2>/dev/null || true
            rc-service crond start 2>/dev/null || true
            rc-service vnstatd start 2>/dev/null || true
        fi
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
    need_cmd_pkg python3 python3 python3 python3
    if (( ${#missing_pkgs[@]} > 0 )); then
        local unique_pkgs
        unique_pkgs=$(printf '%s\n' "${missing_pkgs[@]}" | awk 'NF && !seen[$0]++')
        msg "${YELLOW}[*] 检测到缺失依赖包，正在补装...${NC}"
        # shellcheck disable=SC2086
        ${installType} $unique_pkgs >/dev/null 2>&1 || die '依赖补装失败。'
    fi
    local required=(curl jq openssl bc unzip tar iptables ss lsof vnstat)
    local c
    for c in "${required[@]}"; do
        command -v "$c" >/dev/null 2>&1 || die "关键依赖缺失: $c"
    done
}

has_ipv6() {
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && return 0
    ip -6 route show default 2>/dev/null | grep -q '^default' && return 0
    return 1
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
    local srv pid
    for srv in "$@"; do
        if [[ "$INIT_SYS" == 'systemd' ]]; then
            case "$action" in
                stop)
                    systemctl disable --now "$srv" 2>/dev/null || true
                    ;;
                start)
                    systemctl daemon-reload 2>/dev/null || true
                    systemctl enable "$srv" 2>/dev/null || true
                    systemctl restart "$srv" 2>/dev/null || true
                    sleep 2
                    if ! systemctl is-active --quiet "$srv"; then
                        journalctl -u "$srv" --no-pager -n 80 2>/dev/null || true
                        case "$srv" in sing-box|hysteria) clean_nat_rules 2>/dev/null || true; save_firewall_rules 2>/dev/null || true ;; esac
                        die "服务 $srv 拉起失败。"
                    fi
                    ;;
            esac
        else
            case "$action" in
                stop)
                    rc-service "$srv" stop 2>/dev/null || true
                    rc-update del "$srv" default 2>/dev/null || true
                    ;;
                start)
                    rc-update add "$srv" default 2>/dev/null || true
                    rc-service "$srv" restart 2>/dev/null || true
                    sleep 2
                    if ! rc-service "$srv" status >/dev/null 2>&1; then
                        case "$srv" in sing-box|hysteria) clean_nat_rules 2>/dev/null || true; save_firewall_rules 2>/dev/null || true ;; esac
                        die "服务 $srv 拉起失败。"
                    fi
                    ;;
            esac
        fi
    done
}

service_file_is_abox_managed() {
    local srv="$1" unit='' legacy_re=''
    case "${INIT_SYS:-}" in
        systemd)
            unit="/etc/systemd/system/${srv}.service"
            ;;
        openrc)
            unit="/etc/init.d/${srv}"
            ;;
        *) return 1 ;;
    esac
    [[ -f "$unit" ]] || return 1
    grep -Eq 'Managed by A-Box|A-Box' "$unit" && return 0
    # Backward compatibility: older A-Box service files did not contain an
    # explicit marker. Treat a fixed-name unit as managed only when it points
    # to the standard A-Box config paths.
    case "$srv" in
        xray) legacy_re='/usr/local/etc/xray/config\.json' ;;
        sing-box) legacy_re='/etc/sing-box/config\.json' ;;
        hysteria) legacy_re='/etc/hysteria/config\.yaml|A-Box-hysteria\.log' ;;
        *) return 1 ;;
    esac
    [[ -r "$ABOX_ENV" ]] && grep -Eq "$legacy_re" "$unit"
}

stop_abox_service() {
    local srv="$1"
    if service_file_is_abox_managed "$srv"; then
        service_manager stop "$srv" >/dev/null 2>&1 || true
    else
        msg "${YELLOW}[!] Skip non-A-Box service: ${srv}${NC}"
    fi
}

stop_all_managed_services() {
    stop_abox_service xray
    stop_abox_service sing-box
    stop_abox_service hysteria
    kill_managed_residual_pids >/dev/null 2>&1 || true
}
managed_service_pid() {
    local srv="$1" pid=''
    if [[ "${INIT_SYS:-}" == 'systemd' ]] && command -v systemctl >/dev/null 2>&1; then
        pid=$(systemctl show -p MainPID --value "$srv" 2>/dev/null || true)
        [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] && printf '%s\n' "$pid"
    elif [[ "${INIT_SYS:-}" == 'openrc' ]]; then
        case "$srv" in
            xray) [[ -r /run/xray.pid ]] && cat /run/xray.pid ;;
            sing-box) [[ -r /run/sing-box.pid ]] && cat /run/sing-box.pid ;;
            hysteria) [[ -r /run/hysteria.pid ]] && cat /run/hysteria.pid ;;
        esac
    fi
}

pid_exe_matches() {
    local pid="$1" expect="$2" exe
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    [[ "$exe" == "$expect" ]]
}

kill_managed_residual_pids() {
    local srv pid exe
    for srv in xray sing-box hysteria; do
        pid=$(managed_service_pid "$srv" | head -n 1 || true)
        [[ -n "$pid" ]] || continue
        case "$srv" in
            xray) exe='/usr/local/bin/xray' ;;
            sing-box) exe='/usr/local/bin/sing-box' ;;
            hysteria) exe='/usr/local/bin/hysteria' ;;
        esac
        if pid_exe_matches "$pid" "$exe"; then
            kill -TERM "$pid" 2>/dev/null || true
            sleep 1
            kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
        fi
    done
}

is_service_running() {
    local srv=$1
    if [[ "$INIT_SYS" == 'systemd' ]]; then
        systemctl is-active --quiet "$srv"
    else
        rc-service "$srv" status >/dev/null 2>&1
    fi
}


build_status_str() {
    local status_str='' statuses status
    if [[ "${INIT_SYS:-}" == 'systemd' ]] && systemd_available; then
        mapfile -t statuses < <(systemctl is-active xray sing-box hysteria 2>/dev/null || true)
        [[ "${statuses[0]:-}" == 'active' ]] && status_str+="${GREEN}Xray-Core${NC} "
        [[ "${statuses[1]:-}" == 'active' ]] && status_str+="${CYAN}Sing-Box${NC} "
        [[ "${statuses[2]:-}" == 'active' ]] && status_str+="${GREEN}Hy2(Native)${NC} "
    elif [[ "${INIT_SYS:-}" == 'openrc' ]]; then
        rc-service xray status >/dev/null 2>&1 && status_str+="${GREEN}Xray-Core${NC} "
        rc-service sing-box status >/dev/null 2>&1 && status_str+="${CYAN}Sing-Box${NC} "
        rc-service hysteria status >/dev/null 2>&1 && status_str+="${GREEN}Hy2(Native)${NC} "
    fi
    [[ -z "$status_str" ]] && status_str="${RED}Stack Stopped${NC}"
    printf '%b' "$status_str"
}

managed_services_active() {
    is_service_running xray || is_service_running sing-box || is_service_running hysteria
}

confirm_deployment_replacement() {
    local next_core="$1" next_mode="$2" answer current="none"
    [[ -n "${CORE:-}" || -n "${MODE:-}" ]] && current="${CORE:-unknown}-${MODE:-unknown}"
    if [[ "$current" == 'none' ]] && ! managed_services_active; then
        return 0
    fi
    msg "${YELLOW}[!] A-Box will stop managed services before deploying a new stack.${NC}"
    if [[ "${ABOX_LANG:-zh}" == 'en' ]]; then
        msg "Current config: ${current} | New deployment: ${next_core}-${next_mode}"
        msg "This stops/disables xray, sing-box and hysteria managed by A-Box, clears A-Box firewall rules, and overwrites /etc/ddr/.env. Existing binaries/config directories are not fully removed unless using menu 16."
        read -r -ep 'Continue deployment? [Y/N]: ' answer
    else
        msg "当前配置: ${current} | 新部署: ${next_core}-${next_mode}"
        msg '脚本会先停止/禁用 A-Box 托管的 xray、sing-box、hysteria，清理 A-Box 防火墙规则，并覆盖 /etc/ddr/.env。旧核心二进制和配置目录不会被完全删除；彻底删除请用菜单 16。'
        read -r -ep '继续部署？[Y/N]: ' answer
    fi
    is_yes "$answer" || die '已取消部署 / Deployment canceled.'
}

show_status_report() {
    local init='unknown' xray_state='unknown' sing_state='unknown' hy2_state='unknown' shortcut_state='missing'
    [[ -f "$ABOX_ENV" ]] && source "$ABOX_ENV" 2>/dev/null || true
    if systemd_available; then
        init='systemd'
        xray_state=$(systemctl is-active xray 2>/dev/null || true)
        sing_state=$(systemctl is-active sing-box 2>/dev/null || true)
        hy2_state=$(systemctl is-active hysteria 2>/dev/null || true)
    elif command -v rc-service >/dev/null 2>&1; then
        init='openrc'
        rc-service xray status >/dev/null 2>&1 && xray_state='active' || xray_state='inactive'
        rc-service sing-box status >/dev/null 2>&1 && sing_state='active' || sing_state='inactive'
        rc-service hysteria status >/dev/null 2>&1 && hy2_state='active' || hy2_state='inactive'
    fi
    xray_state=${xray_state:-inactive}
    sing_state=${sing_state:-inactive}
    hy2_state=${hy2_state:-inactive}
    [[ -x /usr/local/bin/sb ]] && shortcut_state='executable'
    cat <<EOF_STATUS
A-Box status
Init: ${init}
Config: CORE=${CORE:-} MODE=${MODE:-}
Services: xray=${xray_state} sing-box=${sing_state} hysteria=${hy2_state}
Shortcut: /usr/local/bin/sb=${shortcut_state}
Config file: ${ABOX_ENV}
EOF_STATUS
}

save_firewall_rules() {
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    command -v rc-service >/dev/null 2>&1 && rc-service iptables save >/dev/null 2>&1 || true
    if [[ -d /etc/sysconfig ]]; then
        command -v iptables-save >/dev/null 2>&1 && iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
    fi
}

firewall_backend() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        printf 'ufw\n'
        return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        printf 'firewalld\n'
        return 0
    fi
    printf 'iptables\n'
}

record_native_firewall_rule() {
    local backend="$1" port="$2" proto="$3"
    valid_port "$port" || return 0
    [[ "$proto" == 'tcp' || "$proto" == 'udp' ]] || return 0
    mkdir -p "$ABOX_DIR"
    grep -qxF "${backend}|${port}|${proto}" "$ABOX_FW_STATE" 2>/dev/null || printf '%s|%s|%s\n' "$backend" "$port" "$proto" >> "$ABOX_FW_STATE"
    chmod 600 "$ABOX_FW_STATE" 2>/dev/null || true
}

ufw_rule_exists() {
    local port="$1" proto="$2"
    ufw status 2>/dev/null | grep -Eiq "(^|[[:space:]])${port}/${proto}([[:space:]]|$).*ALLOW"
}

remove_native_firewall_rules() {
    [[ -r "$ABOX_FW_STATE" ]] || return 0
    local backend port proto
    while IFS='|' read -r backend port proto; do
        valid_port "$port" || continue
        [[ "$proto" == 'tcp' || "$proto" == 'udp' ]] || continue
        case "$backend" in
            ufw)
                if command -v ufw >/dev/null 2>&1; then
                    ufw --force delete allow proto "$proto" from any to any port "$port" >/dev/null 2>&1 || ufw --force delete allow "${port}/${proto}" >/dev/null 2>&1 || true
                fi
                ;;
            firewalld)
                if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
                    firewall-cmd --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done < "$ABOX_FW_STATE"
    rm -f "$ABOX_FW_STATE"
}

apply_native_firewall_rules_from_state() {
    [[ -r "$ABOX_FW_STATE" ]] || return 0
    local backend port proto
    while IFS='|' read -r backend port proto; do
        valid_port "$port" || continue
        [[ "$proto" == 'tcp' || "$proto" == 'udp' ]] || continue
        case "$backend" in
            ufw)
                command -v ufw >/dev/null 2>&1 && ufw allow proto "$proto" from any to any port "$port" comment "A-Box-${port}-${proto}" >/dev/null 2>&1 || true
                ;;
            firewalld)
                if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
                    firewall-cmd --add-port="${port}/${proto}" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done < "$ABOX_FW_STATE"
}

allowPort() {
    local port=$1 type=${2:-tcp} backend
    valid_port "$port" || die "端口非法: $port"
    [[ "$type" == 'tcp' || "$type" == 'udp' ]] || die "协议非法: $type"

    backend=$(firewall_backend)
    case "$backend" in
        ufw)
            if ! ufw_rule_exists "$port" "$type"; then
                ufw allow proto "$type" from any to any port "$port" comment "A-Box-${port}-${type}" >/dev/null 2>&1 || ufw allow "${port}/${type}" >/dev/null 2>&1 || die "UFW 防火墙放行失败: ${port}/${type}"
                record_native_firewall_rule ufw "$port" "$type"
            fi
            return 0
            ;;
        firewalld)
            local fw_runtime_exists=0 fw_permanent_exists=0 fw_added_runtime=0
            firewall-cmd --query-port="${port}/${type}" >/dev/null 2>&1 && fw_runtime_exists=1
            firewall-cmd --permanent --query-port="${port}/${type}" >/dev/null 2>&1 && fw_permanent_exists=1
            if [[ "$fw_runtime_exists" == '0' ]]; then
                firewall-cmd --add-port="${port}/${type}" >/dev/null 2>&1 || die "firewalld runtime 放行失败: ${port}/${type}"
                fw_added_runtime=1
            fi
            if [[ "$fw_permanent_exists" == '0' ]]; then
                if ! firewall-cmd --permanent --add-port="${port}/${type}" >/dev/null 2>&1; then
                    [[ "$fw_added_runtime" == '1' && "$fw_runtime_exists" == '0' ]] && firewall-cmd --remove-port="${port}/${type}" >/dev/null 2>&1 || true
                    die "firewalld permanent 放行失败: ${port}/${type}"
                fi
            fi
            if [[ "$fw_runtime_exists" == '0' && "$fw_permanent_exists" == '0' ]]; then
                record_native_firewall_rule firewalld "$port" "$type"
            fi
            return 0
            ;;
    esac

    if ! $IPT -w -C INPUT -p "$type" --dport "$port" -m comment --comment "A-Box-${port}-${type}" -j ACCEPT 2>/dev/null; then
        $IPT -w -I INPUT -p "$type" --dport "$port" -m comment --comment "A-Box-${port}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv4 防火墙放行失败: ${port}/${type}"
    fi
    if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
        if ! $IPT6 -w -C INPUT -p "$type" --dport "$port" -m comment --comment "A-Box-${port}-${type}" -j ACCEPT 2>/dev/null; then
            $IPT6 -w -I INPUT -p "$type" --dport "$port" -m comment --comment "A-Box-${port}-${type}" -j ACCEPT >/dev/null 2>&1 || die "IPv6 防火墙放行失败: ${port}/${type}"
        fi
    fi
}
remove_ss_open_accept_rules() {
    local proto rule
    [[ -n "${SS_PORT:-}" ]] || return 0
    for proto in tcp udp; do
        while $IPT -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}" | grep -F -- '-j ACCEPT' | grep -Ev "A-Box-${SS_PORT}-${proto}-(WL|DROP)" >/dev/null; do
            rule=$($IPT -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}" | grep -F -- '-j ACCEPT' | grep -Ev "A-Box-${SS_PORT}-${proto}-(WL|DROP)" | head -n 1 | sed 's/^-A /-D /')
            [[ -z "$rule" ]] && break
            # shellcheck disable=SC2086
            $IPT -w $rule >/dev/null 2>&1 || break
        done
        if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
            while $IPT6 -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}" | grep -F -- '-j ACCEPT' | grep -Ev "A-Box-${SS_PORT}-${proto}-(WL6|WL|DROP6|DROP)" >/dev/null; do
                rule=$($IPT6 -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}" | grep -F -- '-j ACCEPT' | grep -Ev "A-Box-${SS_PORT}-${proto}-(WL6|WL|DROP6|DROP)" | head -n 1 | sed 's/^-A /-D /')
                [[ -z "$rule" ]] && break
                # shellcheck disable=SC2086
                $IPT6 -w $rule >/dev/null 2>&1 || break
            done
        fi
    done
}

clean_nat_rules() {
    local rule
    while $IPT -w -t nat -S PREROUTING 2>/dev/null | grep -q 'A-Box-HY2-HOP'; do
        rule=$($IPT -w -t nat -S PREROUTING 2>/dev/null | grep 'A-Box-HY2-HOP' | head -n 1 | sed 's/^-A /-D /')
        [[ -z "$rule" ]] && break
        # shellcheck disable=SC2086
        $IPT -w -t nat $rule 2>/dev/null || break
    done
    if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -t nat -S PREROUTING >/dev/null 2>&1; then
        while $IPT6 -w -t nat -S PREROUTING 2>/dev/null | grep -q 'A-Box-HY2-HOP'; do
            rule=$($IPT6 -w -t nat -S PREROUTING 2>/dev/null | grep 'A-Box-HY2-HOP' | head -n 1 | sed 's/^-A /-D /')
            [[ -z "$rule" ]] && break
            # shellcheck disable=SC2086
            $IPT6 -w -t nat $rule 2>/dev/null || break
        done
    fi
}

clean_input_rules() {
    remove_native_firewall_rules 2>/dev/null || true
    local rule
    while $IPT -w -S INPUT 2>/dev/null | grep -q 'A-Box-'; do
        rule=$($IPT -w -S INPUT 2>/dev/null | grep 'A-Box-' | head -n 1 | sed 's/^-A /-D /')
        [[ -z "$rule" ]] && break
        # shellcheck disable=SC2086
        $IPT -w $rule 2>/dev/null || break
    done
    if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
        while $IPT6 -w -S INPUT 2>/dev/null | grep -q 'A-Box-'; do
            rule=$($IPT6 -w -S INPUT 2>/dev/null | grep 'A-Box-' | head -n 1 | sed 's/^-A /-D /')
            [[ -z "$rule" ]] && break
            # shellcheck disable=SC2086
            $IPT6 -w $rule 2>/dev/null || break
        done
    fi
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
    add_port_pair pairs udp "${HY2_BASE_PORT:-}"
    printf '%s' "$pairs"
}

check_selected_ports_free() {
    msg "${YELLOW}[*] 正在检查新选择端口是否被非 A-Box 进程占用...${NC}"
    local pairs pair proto p holder dup
    pairs=$(selected_port_pairs | awk 'NF')
    dup=$(printf '%s\n' "$pairs" | awk 'NF{seen[$0]++} END{for(k in seen) if(seen[k]>1) print k}' | head -n 1)
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
        holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${p}\b" | grep -vE 'xray|sing-box|hysteria' || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 新选择端口 ${p}/${proto} 已被非 A-Box 进程占用：${NC}"
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
        done | grep -vE 'xray|sing-box|hysteria' || true)
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] HY2 UDP 跳跃区间 ${HY2_RANGE_START}-${HY2_RANGE_END} 已被非 A-Box 进程占用：${NC}"
            echo "$holder"
            die '请先手动释放 HY2 UDP 跳跃区间内的占用端口。'
        fi
    fi
}

release_ports() {
    msg "${YELLOW}[*] 正在停止 A-Box 托管服务并检查端口占用...${NC}"
    stop_all_managed_services
    sleep 1
    local pairs pair proto p holder
    pairs=$(selected_port_pairs | awk 'NF' | sort -u)
    for pair in $pairs; do
        proto=${pair%/*}; p=${pair#*/}
        holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${p}\b" | grep -vE 'xray|sing-box|hysteria' || true)
        [[ -z "$holder" ]] && continue
        msg "${RED}[!] 端口 ${p}/${proto} 已被非 A-Box 进程占用：${NC}"
        echo "$holder"
        die "请先手动释放端口 ${p}/${proto}。脚本不会自动 kill 非托管进程。"
    done
}

write_if_changed() {
    local target="$1" tmp="$2"
    if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
        rm -f "$tmp"
    else
        mv -f "$tmp" "$target"
    fi
}

validate_abox_script_file() {
    local f="$1" context="${2:-script}"
    [[ -s "$f" ]] || die "${context} 为空或不存在。"
    bash -n "$f" || die "${context} 语法校验失败。"
    grep -q '==============================A-Box===============================' "$f" || die "${context} 文本指纹不匹配。"
    grep -q '^main "\$@"' "$f" || die "${context} 入口指纹不匹配。"
}

install_remote_abox_script_guarded() {
    local url="$1" dest="$2" tmp sha
    tmp=$(mktemp /tmp/A-Box-script.XXXXXX.sh) || die '远端脚本临时文件创建失败。'
    curl -fLs --connect-timeout 10 -m 60 "$url" -o "$tmp" || { rm -f "$tmp"; die '远端脚本下载失败。'; }
    validate_abox_script_file "$tmp" '远端 A-Box 脚本'
    sha=$(sha256sum "$tmp" | awk '{print $1}')
    msg "${YELLOW}[*] Remote script SHA256: ${sha}${NC}"
    confirm_ota_script_hash "$sha" "$url" || { rm -f "$tmp"; die '远端脚本安装被取消。'; }
    write_if_changed "$dest" "$tmp"
}

setup_shortcut() {
    mkdir -p "$ABOX_DIR"
    if [[ "${1:-}" == 'update' ]]; then
        install_remote_abox_script_guarded "$SCRIPT_URL" "$ABOX_DIR/A-Box.sh"
    elif [[ -f "$0" && -r "$0" && "$0" != 'bash' && "$0" != '-bash' ]]; then
        validate_abox_script_file "$0" '当前 A-Box 脚本'
        if [[ ! -f "$ABOX_DIR/A-Box.sh" ]] || ! cmp -s "$0" "$ABOX_DIR/A-Box.sh"; then
            install -m 755 "$0" "$ABOX_DIR/A-Box.sh" || die '持久化当前脚本失败。'
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
    if [[ ! -f /usr/local/bin/sb ]] || ! cmp -s "$shortcut_tmp" /usr/local/bin/sb; then
        install -m 755 "$shortcut_tmp" /usr/local/bin/sb || die '快捷入口写入失败。'
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

github_api_get() {
    local url="$1"
    curl -fLsS --connect-timeout 10 -m 60 \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$url"
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

    asset_json=$(jq -c --arg re "$asset_re" '.assets[]? | select(.name | test($re)) | {url:.browser_download_url,digest:(.digest // "")}' <<< "$release_json" | head -n 1)
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
            mv -f "$tmp_file" "$dest_file"
            validate_downloaded_asset "$output_file" "$dest_file"
            verify_github_asset_digest "$dest_file" "$digest"
            FETCHED_ASSET_PATH="$dest_file"
            msg "${GREEN}   核心资产提取成功。${NC}"
            return 0
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
        asset_json=$(jq -c --arg name "$asset" '.assets[]? | select(.name == $name) | {url:.browser_download_url,digest:(.digest // "")}' <<< "$release_json" | head -n 1)
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

reset_protocol_vars() {
    unset UUID VLESS_SNI VISION_SNI XHTTP_SNI VLESS_PORT XHTTP_PORT HY2_BASE_PORT HY2_DOMAIN HY2_UP HY2_DOWN HY2_MASQ_URL
    unset SS_PORT SS_WHITELIST_IP PUBLIC_KEY PBK SHORT_ID HY2_PASS HY2_OBFS SS_PASS
    unset HY2_CERT_SHA256_FP HY2_CERT_PUBKEY_SHA256_B64 HY2_HOP HY2_HOP_IMPL HY2_MONITOR_PORT
    unset HY2_ACME_TYPE HY2_ACME_DNS_PROVIDER HY2_ACME_DNS_CF_API_TOKEN
    unset HY2_URI_PORTS HY2_CLASH_PORTS HY2_SB_PORTS HY2_RANGE_START HY2_RANGE_END ENABLE_KEEPALIVE
}

write_env() {
    local env_core="$1" env_mode="$2" old_traffic_limit_gb='' old_traffic_limit_mode=''
    if [[ -f "$ABOX_ENV" ]]; then
        old_traffic_limit_gb=$(grep '^TRAFFIC_LIMIT_GB=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
        old_traffic_limit_mode=$(grep '^TRAFFIC_LIMIT_MODE=' "$ABOX_ENV" | tail -n 1 | cut -d= -f2- | tr -d '"')
    fi
    umask 077
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
    } > "$ABOX_ENV"
    chmod 600 "$ABOX_ENV"
}

validate_fail2ban_config_or_die() {
    command -v fail2ban-client >/dev/null 2>&1 || return 0
    local out
    if fail2ban-client -h 2>&1 | grep -Eq -- '(^|[[:space:]])-t([,[:space:]]|$)|--test'; then
        out=$(fail2ban-client -t 2>&1) || {
            printf '%s\n' "$out" >&2
            die 'Fail2Ban 配置校验失败；已停止部署以避免无效防御配置。'
        }
    else
        out=$(fail2ban-client -d 2>&1) || {
            printf '%s\n' "$out" >&2
            die 'Fail2Ban 配置 dump 失败；疑似配置无效，已停止部署。'
        }
    fi
}

setup_active_defense() {
    msg "${YELLOW}[*] 正在挂载环形缓冲日志与 Fail2Ban 主动防御矩阵...${NC}"
    touch /var/log/A-Box-xray-access.log /var/log/A-Box-xray-error.log /var/log/A-Box-singbox.log /var/log/A-Box-hysteria.log 2>/dev/null || true
    chmod 644 /var/log/A-Box-*.log 2>/dev/null || true
    cat > /etc/logrotate.d/A-Box <<'EOF_LOGROTATE'
/var/log/A-Box-*.log {
    su root root
    daily
    rotate 2
    size 50M
    missingok
    notifempty
    copytruncate
    compress
}
EOF_LOGROTATE
    if command -v fail2ban-client >/dev/null 2>&1; then
        mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
        cat > /etc/fail2ban/filter.d/A-Box.conf <<'EOF_F2B_FILTER'
[Definition]
failregex = ^.*(?:rejected|invalid request|bad request|authentication failed).* from <HOST>[: ].*$
            ^.*<HOST>.*(?:rejected|invalid|unauthorized|forbidden).*$
ignoreregex =
EOF_F2B_FILTER
        local f2b_ports=''
        [[ -n "${VLESS_PORT:-}" ]] && f2b_ports+="${VLESS_PORT},"
        [[ -n "${XHTTP_PORT:-}" ]] && f2b_ports+="${XHTTP_PORT},"
        [[ -n "${HY2_BASE_PORT:-}" ]] && f2b_ports+="${HY2_BASE_PORT},"
        if [[ "${HY2_HOP:-}" == 'true' && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
            f2b_ports+="${HY2_RANGE_START}:${HY2_RANGE_END},"
        fi
        [[ -n "${SS_PORT:-}" ]] && f2b_ports+="${SS_PORT},"
        f2b_ports="${f2b_ports%,}"
        if [[ -z "$f2b_ports" ]]; then
            msg "${YELLOW}[!] 未检测到 A-Box 服务端口，跳过 A-Box Fail2Ban jail。${NC}"
            return 0
        fi
        cat > /etc/fail2ban/jail.d/A-Box.local <<EOF_F2B_JAIL
[A-Box]
enabled = true
ignoreip = 127.0.0.1/8 ::1
port = ${f2b_ports}
filter = A-Box
logpath = /var/log/A-Box-xray-error.log
          /var/log/A-Box-singbox.log
          /var/log/A-Box-hysteria.log
maxretry = 8
findtime = 120
bantime = 3600
action = iptables-multiport[name=A-Box, port="${f2b_ports}", protocol=tcp]
         iptables-multiport[name=A-Box-udp, port="${f2b_ports}", protocol=udp]
EOF_F2B_JAIL
        validate_fail2ban_config_or_die
        if [[ "$INIT_SYS" == 'systemd' ]]; then
            systemctl restart fail2ban 2>/dev/null || die 'Fail2Ban 重启失败。'
        else
            rc-service fail2ban restart 2>/dev/null || die 'Fail2Ban 重启失败。'
        fi
    fi
}

setup_health_monitor() {
    msg "${YELLOW}[*] 正在注入 L4 套接字自愈探针...${NC}"
    mkdir -p "$ABOX_DIR"
    cat > "$ABOX_DIR/socket_probe.sh" <<'EOF_PROBE'
#!/usr/bin/env bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
source /etc/ddr/.env 2>/dev/null || exit 0
[[ -z "${CORE:-}" ]] && exit 0

IPT=$(command -v iptables || echo '/sbin/iptables')
IPT6=$(command -v ip6tables || echo '/sbin/ip6tables')

has_ipv6() {
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && return 0
    ip -6 route show default 2>/dev/null | grep -q '^default' && return 0
    return 1
}

ipv6_nat_redirect_usable() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    $IPT6 -w -t nat -L PREROUTING >/dev/null 2>&1 || return 1
}

get_month_total_bytes() {
    local iface="$1" mode="${2:-total}" line
    line=$(vnstat -i "$iface" --oneline b 2>/dev/null) || return 1
    case "$mode" in
        rx) echo "$line" | awk -F';' '{print $9}' ;;
        tx) echo "$line" | awk -F';' '{print $10}' ;;
        total) echo "$line" | awk -F';' '{print $11}' ;;
        *) return 1 ;;
    esac
}

bytes_to_gb() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'; }

if [[ -n "${TRAFFIC_LIMIT_GB:-}" ]]; then
    INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$INTERFACE" ]] && INTERFACE=$(ip -o route show to default 2>/dev/null | awk '{print $5; exit}')
    [[ -z "$INTERFACE" ]] && INTERFACE=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1 | tr -d ' ')
    USED_BYTES=$(get_month_total_bytes "$INTERFACE" "${TRAFFIC_LIMIT_MODE:-total}") || exit 0
    USED_GB=$(bytes_to_gb "$USED_BYTES")
    if (( $(echo "$USED_GB >= $TRAFFIC_LIMIT_GB" | bc -l) )); then
        exit 0
    fi
fi

check_restart() {
    local srv="$1"
    [[ "$srv" == 'singbox' ]] && srv='sing-box'
    [[ "$srv" == 'xray-core' ]] && srv='xray'
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart "$srv" >/dev/null 2>&1 || true
    else
        rc-service "$srv" restart >/dev/null 2>&1 || true
    fi
}

HY2_SRV="$CORE"
[[ "$CORE" == 'singbox' ]] && HY2_SRV='sing-box'
[[ "$CORE" == 'xray' && "$MODE" == *'ALL'* ]] && HY2_SRV='hysteria'

if [[ "${HY2_HOP:-}" == 'true' && "${HY2_HOP_IMPL:-}" == 'manual' && -n "${HY2_RANGE_START:-}" && -n "${HY2_RANGE_END:-}" ]]; then
    if ! $IPT -w -t nat -S PREROUTING 2>/dev/null | grep -q 'A-Box-HY2-HOP'; then
        check_restart "$HY2_SRV"
        exit 0
    fi
    if has_ipv6 && ipv6_nat_redirect_usable; then
        if ! $IPT6 -w -t nat -S PREROUTING 2>/dev/null | grep -q 'A-Box-HY2-HOP'; then
            check_restart "$HY2_SRV"
            exit 0
        fi
    fi
fi

if [[ -n "${VLESS_PORT:-}" ]] && ! ss -H -nlt 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${VLESS_PORT}$"; then
    check_restart "$CORE"; exit 0
fi
if [[ -n "${XHTTP_PORT:-}" ]] && ! ss -H -nlt 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${XHTTP_PORT}$"; then
    check_restart "$CORE"; exit 0
fi
if [[ -n "${HY2_MONITOR_PORT:-}" ]] && ! ss -H -nlu 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${HY2_MONITOR_PORT}$"; then
    check_restart "$HY2_SRV"; exit 0
fi
if [[ -n "${SS_PORT:-}" ]] && ! ss -H -nlt 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${SS_PORT}$"; then
    check_restart "$CORE"; exit 0
fi
EOF_PROBE
    chmod +x "$ABOX_DIR/socket_probe.sh"
    install_abox_cron_block PROBE '* * * * * /bin/bash /etc/ddr/socket_probe.sh >/dev/null 2>&1'
}

setup_geo_cron() {
    mkdir -p "$ABOX_DIR"
    cat > "$ABOX_DIR/geo_update.sh" <<'EOF_GEO'
#!/usr/bin/env bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
GEO_REPO='Loyalsoldier/v2ray-rules-dat'
fetch_one() {
    local asset="$1" out="$2" api release_json asset_json url digest expected actual size
    rm -f "$out"
    api="https://api.github.com/repos/${GEO_REPO}/releases/latest"
    release_json=$(curl -fLsS --connect-timeout 10 -m 60 \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$api") || return 1
    asset_json=$(jq -c --arg name "$asset" '.assets[]? | select(.name == $name) | {url:.browser_download_url,digest:(.digest // "")}' <<< "$release_json" | head -n 1)
    [[ -n "$asset_json" && "$asset_json" != 'null' ]] || return 1
    url=$(jq -r '.url' <<< "$asset_json")
    digest=$(jq -r '.digest // ""' <<< "$asset_json")
    [[ "$url" == "https://github.com/${GEO_REPO}/releases/download/"* ]] || return 1
    [[ "$digest" == sha256:* ]] || return 1
    expected="${digest#sha256:}"
    [[ "$expected" =~ ^[A-Fa-f0-9]{64}$ ]] || return 1
    curl -fLs --connect-timeout 10 -m 90 "$url" -o "$out" || return 1
    actual=$(sha256sum "$out" | awk '{print $1}')
    [[ "${actual,,}" == "${expected,,}" ]] || return 1
    size=$(wc -c < "$out" 2>/dev/null | tr -d ' ')
    [[ -n "$size" && "$size" -gt 500000 ]] || return 1
    ! head -c 256 "$out" 2>/dev/null | grep -Eiq '<(html|!doctype)'
}

[[ -d '/usr/local/share/xray' ]] || exit 0

tmpdir=$(mktemp -d /tmp/A-Box-geo.XXXXXX) || exit 1
trap 'rm -rf "$tmpdir"' EXIT
fetch_one geoip.dat "$tmpdir/geoip.dat" || exit 1
fetch_one geosite.dat "$tmpdir/geosite.dat" || exit 1

install -m 644 "$tmpdir/geoip.dat" /usr/local/share/xray/geoip.dat
install -m 644 "$tmpdir/geosite.dat" /usr/local/share/xray/geosite.dat
if command -v systemctl >/dev/null 2>&1; then systemctl restart xray 2>/dev/null || true; else rc-service xray restart 2>/dev/null || true; fi
# sing-box GeoIP/Geosite are intentionally not updated here. New sing-box releases removed
# legacy geoip/geosite support; use rule-set based configs when route databases are needed.
EOF_GEO
    chmod +x "$ABOX_DIR/geo_update.sh"
    install_abox_cron_block GEO '0 3 * * 1 /bin/bash /etc/ddr/geo_update.sh >/dev/null 2>&1'
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
                    [[ -n "${HY2_ACME_DNS_CF_API_TOKEN:-}" ]] || die 'Cloudflare DNS-01 ACME 需要 API Token。'
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
        holder=$(ss -H -n -l -p -A tcp 2>/dev/null | grep -E '[:.]80\b' | grep -vE 'xray|sing-box|hysteria' || true)
        if [[ -n "$holder" ]]; then
            msg "${RED}[!] ACME HTTP-01 需要 80/tcp，但该端口已被非 A-Box 进程占用：${NC}"
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
            remove_ss_open_accept_rules
            for ip in $SS_WHITELIST_IP; do
                for proto in tcp udp; do
                    if [[ "$ip" == *:* ]]; then
                        if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                            if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -j ACCEPT 2>/dev/null; then
                                $IPT6 -w -I INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则写入失败: $ip/$proto"
                            fi
                        fi
                    else
                        if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -j ACCEPT 2>/dev/null; then
                            $IPT -w -I INPUT -p "$proto" --dport "$SS_PORT" -s "$ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则写入失败: $ip/$proto"
                        fi
                    fi
                done
            done
            for proto in tcp udp; do
                if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -j DROP 2>/dev/null; then
                    $IPT -w -A INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto"
                fi
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -j DROP 2>/dev/null; then
                        $IPT6 -w -A INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto"
                    fi
                fi
            done
        else
            allowPort "$SS_PORT" tcp
            allowPort "$SS_PORT" udp
        fi
    fi
    save_firewall_rules
}

json_sockopt_xray() {
    if [[ "${ENABLE_KEEPALIVE:-}" == 'true' ]]; then
        jq -n '{tcpKeepAliveIdle:45,tcpKeepAliveInterval:45}'
    else
        jq -n 'null'
    fi
}

build_xray_config() {
    local mode="$1" sockopt_json inbounds_json out tmp_out
    sockopt_json=$(json_sockopt_xray)
    inbounds_json=$(jq -n \
        --arg mode "$mode" \
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
            listen:"::", port:$vport, protocol:"vless",
            settings:{clients:[{id:$uuid, flow:"xtls-rprx-vision"}], decryption:"none"},
            streamSettings:({network:"tcp", security:"reality", realitySettings:{target:($v_sni + ":443"), serverNames:[$v_sni], privateKey:$pk, shortIds:[$sid]}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def xhttp:
          {
            listen:"::", port:$xport, protocol:"vless",
            settings:{clients:[{id:$uuid}], decryption:"none"},
            streamSettings:({network:"xhttp", security:"reality", xhttpSettings:{mode:"auto", path:"/xhttp"}, realitySettings:{target:($x_sni + ":443"), serverNames:[$x_sni], privateKey:$pk, shortIds:[$sid]}} + maybe_sock),
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
          };
        def ss:
          ({listen:"::", port:$ssport, protocol:"shadowsocks", settings:{method:"2022-blake3-aes-128-gcm", password:$ss_pass, network:"tcp,udp"}}
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
    local mode="$1" inbounds_json ka_obj cert_cn='localhost' out tmp_out
    [[ -n "${HY2_DOMAIN:-}" ]] && cert_cn="$HY2_DOMAIN"
    if [[ "${ENABLE_KEEPALIVE:-}" == 'true' ]]; then
        ka_obj='{"tcp_keep_alive":"45s","tcp_keep_alive_interval":"45s"}'
    else
        ka_obj='{}'
    fi
    inbounds_json=$(jq -n \
        --arg mode "$mode" \
        --arg uuid "$UUID" \
        --arg v_sni "${VISION_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg x_sni "${XHTTP_SNI:-${VLESS_SNI:-www.microsoft.com}}" \
        --arg pk "$PK" \
        --arg sid "$SHORT_ID" \
        --argjson vport "${VLESS_PORT:-443}" \
        --argjson hy2port "${HY2_BASE_PORT:-443}" \
        --argjson ssport "${SS_PORT:-2053}" \
        --argjson hy2up "${HY2_UP:-100}" \
        --argjson hy2down "${HY2_DOWN:-1000}" \
        --arg hy2pass "${HY2_PASS:-}" \
        --arg hy2obfs "${HY2_OBFS:-}" \
        --arg cert_cn "$cert_cn" \
        --arg masq "${HY2_MASQ_URL:-https://www.samsung.com/}" \
        --arg ss_pass "${SS_PASS:-}" \
        --argjson ka "$ka_obj" '
        def vision:
          ({
            type:"vless", listen:"::", listen_port:$vport, tcp_fast_open:true,
            users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
            tls:{enabled:true, server_name:$v_sni, reality:{enabled:true, handshake:{server:$v_sni, server_port:443}, private_key:$pk, short_id:[$sid]}}
          } + $ka);
        def hy2:
          {
            type:"hysteria2", listen:"::", listen_port:$hy2port, up_mbps:$hy2up, down_mbps:$hy2down,
            obfs:{type:"salamander", password:$hy2obfs},
            users:[{password:$hy2pass}],
            tls:{enabled:true, server_name:$cert_cn, certificate_path:"/etc/sing-box/hy2.crt", key_path:"/etc/sing-box/hy2.key"},
            masquerade:$masq
          };
        def ss:
          ({
            type:"shadowsocks", listen:"::", listen_port:$ssport, tcp_fast_open:true,
            method:"2022-blake3-aes-128-gcm", password:$ss_pass
          } + $ka);
        []
        | if ($mode|contains("VISION")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [vision] else . end
        | if ($mode|contains("HY2")) or ($mode|contains("ALL")) then . + [hy2] else . end
        | if ($mode|contains("SS")) or ($mode|contains("ALL")) or $mode == "VLESS_SS" then . + [ss] else . end
    ')
    out="${SINGBOX_CONFIG_PATH:-/etc/sing-box/config.json}"
    tmp_out="${out}.tmp.$$"
    mkdir -p "$(dirname "$out")"
    jq -n --argjson inbounds "$inbounds_json" '{
        log:{level:"warn", output:"/var/log/A-Box-singbox.log"},
        route:{rules:[{protocol:"bittorrent", action:"route", outbound:"block"}], auto_detect_interface:true},
        inbounds:$inbounds,
        outbounds:[{type:"direct", tag:"direct"}, {type:"block", tag:"block"}]
    }' > "$tmp_out" || { rm -f "$tmp_out"; die 'Sing-box JSON 生成失败。'; }
    mv -f "$tmp_out" "$out"
}

deploy_official_hy2() {
    local IS_SILENT=${1:-NORMAL} TLS_CONFIG HY2_LISTEN cert_cn HY2_CAPS='CAP_NET_BIND_SERVICE' hy2_tmp hy2_bin
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        clear; msg "${BOLD}${GREEN}部署官方 Hysteria 2${NC}"
        init_system_environment
        source "$ABOX_ENV" 2>/dev/null || true
        light_preflight_check
        confirm_deployment_replacement hysteria HY2
        release_ports
        clean_nat_rules
        clean_input_rules
        save_firewall_rules
        pre_install_setup hysteria HY2
        get_architecture
    fi

    hy2_tmp=$(mktemp -d /tmp/A-Box-hysteria.XXXXXX) || die 'Hysteria 临时目录创建失败。'
    hy2_bin="$hy2_tmp/hysteria_core"
    fetch_github_release apernet/hysteria hysteria_core "$hy2_bin"
    install -m 755 "$hy2_bin" /usr/local/bin/hysteria || die '安装 hysteria 失败。'
    rm -rf "$hy2_tmp"
    /usr/local/bin/hysteria version >/dev/null 2>&1 || die 'Hysteria 执行校验失败。'

    HY2_PASS=$(rand_alnum 20)
    HY2_OBFS=$(rand_alnum 16)
    mkdir -p /etc/hysteria

    if [[ -n "${HY2_DOMAIN:-}" ]]; then
        if [[ "${HY2_ACME_TYPE:-http}" == 'dns' ]]; then
            [[ "${HY2_ACME_DNS_PROVIDER:-}" == 'cloudflare' ]] || die '当前仅内置支持 Cloudflare DNS-01 ACME。'
            [[ -n "${HY2_ACME_DNS_CF_API_TOKEN:-}" ]] || die 'Cloudflare DNS-01 ACME 需要 API Token。'
            TLS_CONFIG="acme:
  domains:
    - ${HY2_DOMAIN}
  email: admin@${HY2_DOMAIN}
  type: dns
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: ${HY2_ACME_DNS_CF_API_TOKEN}"
        else
            TLS_CONFIG="acme:
  domains:
    - ${HY2_DOMAIN}
  email: admin@${HY2_DOMAIN}
  type: http
  http:
    altPort: 80"
        fi
        HY2_CERT_SHA256_FP=''
        HY2_CERT_PUBKEY_SHA256_B64=''
    else
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/server.key 2>/dev/null
        openssl req -new -x509 -days 36500 -key /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj '/CN=localhost' 2>/dev/null
        chmod 600 /etc/hysteria/server.key
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

    cat > /etc/hysteria/config.yaml <<EOF_HY2
listen: ${HY2_LISTEN}
${TLS_CONFIG}
obfs:
  type: salamander
  salamander:
    password: ${HY2_OBFS}
auth:
  type: password
  password: ${HY2_PASS}
bandwidth:
  up: ${HY2_UP} mbps
  down: ${HY2_DOWN} mbps
masquerade:
  type: proxy
  proxy:
    url: ${HY2_MASQ_URL}
    rewriteHost: true
EOF_HY2
    chmod 600 /etc/hysteria/config.yaml

    if [[ "$INIT_SYS" == 'systemd' ]]; then
        cat > /etc/systemd/system/hysteria.service <<EOF_SVC
# Managed by A-Box
[Unit]
Description=A-Box Hysteria 2 Service
After=network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=${HY2_CAPS}
AmbientCapabilities=${HY2_CAPS}
ExecStart=/bin/sh -c 'exec /usr/local/bin/hysteria server -c /etc/hysteria/config.yaml >>/var/log/A-Box-hysteria.log 2>&1'
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        mkdir -p /etc/conf.d
        echo 'rc_ulimit="-n 1048576"' > /etc/conf.d/hysteria
        cat > /etc/init.d/hysteria <<'EOF_SVC'
#!/sbin/openrc-run
# Managed by A-Box
description="A-Box Hysteria 2 Service"
command="/usr/local/bin/hysteria"
command_args="server -c /etc/hysteria/config.yaml >>/var/log/A-Box-hysteria.log 2>&1"
command_background="yes"
pidfile="/run/hysteria.pid"
depend() { need net; }
EOF_SVC
        chmod +x /etc/init.d/hysteria
    fi
    service_manager start hysteria
    setup_geo_cron
    setup_active_defense
    setup_health_monitor
    if [[ "$IS_SILENT" != 'SILENT' ]]; then
        write_env hysteria HY2
        view_config deploy
    fi
}

xray_all_die_rollback() {
    [[ "${ABOX_XRAY_ALL_DEPLOYING:-0}" == '1' ]] || return 0
    ABOX_XRAY_ALL_DEPLOYING=0
    ABOX_DIE_HOOK=''
    msg "${YELLOW}[!] Xray ALL deployment failed; stopping services and rolling back latest auto backup.${NC}"
    stop_all_managed_services >/dev/null 2>&1 || true
    kill_managed_residual_pids >/dev/null 2>&1 || true
    clean_nat_rules >/dev/null 2>&1 || true
    clean_input_rules >/dev/null 2>&1 || true
    save_firewall_rules >/dev/null 2>&1 || true
    restore_latest_backup_silent "$ABOX_DIR/backups" || msg "${YELLOW}[!] Auto rollback could not restore a backup; use menu 7 if a backup is available.${NC}"
}

deploy_xray() {
    local MODE_IN=$1 KEYPAIR PK_LOCAL
    clear; msg "${BOLD}${GREEN}部署 Xray-core [$MODE_IN]${NC}"
    init_system_environment
    source "$ABOX_ENV" 2>/dev/null || true
    light_preflight_check
    confirm_deployment_replacement xray "$MODE_IN"
    if [[ "$MODE_IN" == *'ALL'* ]]; then
        auto_backup_silent 'xray all deployment' "$ABOX_DIR/backups"
        ABOX_XRAY_ALL_DEPLOYING=1
        ABOX_DIE_HOOK='xray_all_die_rollback'
    fi
    release_ports
    clean_nat_rules
    clean_input_rules
    save_firewall_rules
    pre_install_setup xray "$MODE_IN"
    get_architecture

    local xray_tmp xray_zip xray_ext geo_tmp
    xray_tmp=$(mktemp -d /tmp/A-Box-xray.XXXXXX) || die 'Xray 临时目录创建失败。'
    xray_zip="$xray_tmp/xray_core.zip"
    xray_ext="$xray_tmp/xray_ext"
    mkdir -p "$xray_ext"
    fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
    unzip -qo "$xray_zip" -d "$xray_ext" || die 'Xray 压缩包解压失败。'
    [[ -f "$xray_ext/xray" ]] || die '解压后未找到 xray 主程序。'
    install -m 755 "$xray_ext/xray" /usr/local/bin/xray || die '安装 xray 失败。'
    /usr/local/bin/xray version >/dev/null 2>&1 || die 'Xray 执行校验失败。'
    mkdir -p /usr/local/share/xray /usr/local/etc/xray

    geo_tmp="$xray_tmp/geo"
    mkdir -p "$geo_tmp"
    fetch_geo_data geoip.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat' "$geo_tmp/geoip.dat"
    fetch_geo_data geosite.dat 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat' "$geo_tmp/geosite.dat"
    install -m 644 "$geo_tmp/geoip.dat" /usr/local/share/xray/geoip.dat
    install -m 644 "$geo_tmp/geosite.dat" /usr/local/share/xray/geosite.dat
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

    if [[ "$INIT_SYS" == 'systemd' ]]; then
        cat > /etc/systemd/system/xray.service <<'EOF_SVC'
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
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        mkdir -p /etc/conf.d
        echo 'rc_ulimit="-n 1048576"' > /etc/conf.d/xray
        echo 'XRAY_LOCATION_ASSET="/usr/local/share/xray"' >> /etc/conf.d/xray
        cat > /etc/init.d/xray <<'EOF_SVC'
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
        ABOX_XRAY_ALL_DEPLOYING=0
        ABOX_DIE_HOOK=''
    fi
    write_env xray "$MODE_IN"
    view_config deploy
}

deploy_singbox() {
    local MODE_IN=$1 KEYPAIR SB_PATH cert_cn='localhost' SB_PRE_START='' SB_POST_STOP='' SB_RC_PRE='' SB_RC_POST='' SB_CAPS='CAP_NET_BIND_SERVICE'
    clear; msg "${BOLD}${GREEN}部署 Sing-box 核心 [$MODE_IN]${NC}"
    init_system_environment
    source "$ABOX_ENV" 2>/dev/null || true
    light_preflight_check
    confirm_deployment_replacement singbox "$MODE_IN"
    release_ports
    clean_nat_rules
    clean_input_rules
    save_firewall_rules
    pre_install_setup singbox "$MODE_IN"
    get_architecture

    local sb_tmp sb_tar sb_ext
    sb_tmp=$(mktemp -d /tmp/A-Box-singbox.XXXXXX) || die 'Sing-box 临时目录创建失败。'
    sb_tar="$sb_tmp/singbox_core.tar.gz"
    sb_ext="$sb_tmp/extract"
    mkdir -p "$sb_ext"
    fetch_github_release SagerNet/sing-box singbox_core.tar.gz "$sb_tar"
    tar -xzf "$sb_tar" -C "$sb_ext" || die 'Sing-box 压缩包解压失败。'
    SB_PATH=$(find "$sb_ext" -type f -name 'sing-box' | head -n 1)
    [[ -n "$SB_PATH" && -f "$SB_PATH" ]] || die '解压后未找到 sing-box 主程序。'
    install -m 755 "$SB_PATH" /usr/local/bin/sing-box || die '安装 sing-box 失败。'
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
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/hy2.key 2>/dev/null
        openssl req -new -x509 -days 36500 -key /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt -subj "/CN=$cert_cn" 2>/dev/null
        chmod 600 /etc/sing-box/hy2.key
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
ExecStartPre=-/bin/sh -c '$IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
        SB_POST_STOP="ExecStopPost=-/bin/sh -c '$IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
        SB_RC_PRE="start_pre() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true
  $IPT -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
        SB_RC_POST="stop_post() {
  $IPT -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
        if has_ipv6 && ipv6_nat_redirect_usable; then
            SB_PRE_START+="
ExecStartPre=-/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'
ExecStartPre=-/bin/sh -c '$IPT6 -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
            SB_POST_STOP+="
ExecStopPost=-/bin/sh -c '$IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true'"
            SB_RC_PRE+="
  $IPT6 -w -t nat -D PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true
  $IPT6 -w -t nat -A PREROUTING -i $INGRESS_IF -p udp --dport ${HY2_RANGE_START}:${HY2_RANGE_END} -m comment --comment \"A-Box-HY2-HOP\" -j REDIRECT --to-ports $HY2_BASE_PORT 2>/dev/null || true"
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

    if [[ "$INIT_SYS" == 'systemd' ]]; then
        cat > /etc/systemd/system/sing-box.service <<EOF_SVC
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
Restart=always
RestartSec=10
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF_SVC
    else
        mkdir -p /etc/conf.d
        echo 'rc_ulimit="-n 1048576"' > /etc/conf.d/sing-box
        cat > /etc/init.d/sing-box <<EOF_SVC
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
    setup_geo_cron
    setup_active_defense
    setup_health_monitor
    write_env singbox "$MODE_IN"
    view_config deploy
}

get_month_total_bytes() {
    local iface="$1" mode="${2:-total}" line
    line=$(vnstat -i "$iface" --oneline b 2>/dev/null) || return 1
    case "$mode" in
        rx) echo "$line" | awk -F';' '{print $9}' ;;
        tx) echo "$line" | awk -F';' '{print $10}' ;;
        total) echo "$line" | awk -F';' '{print $11}' ;;
        *) return 1 ;;
    esac
}

bytes_to_gb() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'; }

setup_traffic_monitor() {
    mkdir -p "$ABOX_DIR"
    cat > "$ABOX_DIR/traffic_monitor.sh" <<'EOF_TRAFFIC'
#!/usr/bin/env bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
source /etc/ddr/.env 2>/dev/null || exit 0
[[ -z "${TRAFFIC_LIMIT_GB:-}" ]] && exit 0
INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[[ -z "$INTERFACE" ]] && INTERFACE=$(ip -o route show to default 2>/dev/null | awk '{print $5; exit}')
[[ -z "$INTERFACE" ]] && INTERFACE=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1 | tr -d ' ')
get_month_total_bytes() {
    local iface="$1" mode="${2:-total}" line
    line=$(vnstat -i "$iface" --oneline b 2>/dev/null) || return 1
    case "$mode" in
        rx) echo "$line" | awk -F';' '{print $9}' ;;
        tx) echo "$line" | awk -F';' '{print $10}' ;;
        total) echo "$line" | awk -F';' '{print $11}' ;;
        *) return 1 ;;
    esac
}
bytes_to_gb() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'; }
USED_BYTES=$(get_month_total_bytes "$INTERFACE" "${TRAFFIC_LIMIT_MODE:-total}") || exit 0
USED_GB=$(bytes_to_gb "$USED_BYTES")
if (( $(echo "$USED_GB >= $TRAFFIC_LIMIT_GB" | bc -l) )); then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop xray sing-box hysteria 2>/dev/null || true
    else
        rc-service xray stop 2>/dev/null || true
        rc-service sing-box stop 2>/dev/null || true
        rc-service hysteria stop 2>/dev/null || true
    fi
fi
EOF_TRAFFIC
    chmod +x "$ABOX_DIR/traffic_monitor.sh"
    install_abox_cron_block TRAFFIC '* * * * * /bin/bash /etc/ddr/traffic_monitor.sh >/dev/null 2>&1'
}

disable_traffic_monitor() {
    remove_abox_cron_block TRAFFIC
    rm -f "$ABOX_DIR/traffic_monitor.sh"
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
        vnstat -i "$INTERFACE" -m 2>/dev/null | head -n 8 | grep -v '^$' || msg "${YELLOW}暂无本月统计数据，vnstat 正在收集中。${NC}"
    fi
    source "$ABOX_ENV" 2>/dev/null || true
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
            touch "$ABOX_ENV"
            sed -i '/^TRAFFIC_LIMIT_GB=/d;/^TRAFFIC_LIMIT_MODE=/d' "$ABOX_ENV" 2>/dev/null || true
            printf 'TRAFFIC_LIMIT_GB=%q\nTRAFFIC_LIMIT_MODE=%q\n' "$limit_gb" "$mode_choice" >> "$ABOX_ENV"
            chmod 600 "$ABOX_ENV"
            setup_traffic_monitor
            msg "${GREEN}流量限制已设定为 ${limit_gb} GB，模式 ${mode_choice}。${NC}"
            pause_return
            ;;
        2)
            [[ -f "$ABOX_ENV" ]] && sed -i '/^TRAFFIC_LIMIT_GB=/d;/^TRAFFIC_LIMIT_MODE=/d' "$ABOX_ENV" 2>/dev/null || true
            disable_traffic_monitor
            source "$ABOX_ENV" 2>/dev/null || true
            case "${CORE:-}" in
                xray) service_manager start xray ;;
                singbox) service_manager start sing-box ;;
                hysteria) service_manager start hysteria ;;
            esac
            [[ "${CORE:-}" == 'xray' && "${MODE:-}" == *'ALL'* ]] && service_manager start hysteria
            msg "${GREEN}流量限制已解除。${NC}"
            pause_return
            ;;
        *) return 0 ;;
    esac
}

manage_ss_whitelist() {
    clear
    source "$ABOX_ENV" 2>/dev/null || true
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
                    $IPT6 -w -I INPUT -p "$proto" --dport "$SS_PORT" -s "$add_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL6" -j ACCEPT >/dev/null 2>&1 || die "IPv6 白名单规则写入失败: $add_ip/$proto"
                done
            else
                valid_ipv4_cidr "$add_ip" || { msg "${RED}[!] IPv4 白名单地址非法: $add_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    $IPT -w -I INPUT -p "$proto" --dport "$SS_PORT" -s "$add_ip" -m comment --comment "A-Box-${SS_PORT}-${proto}-WL" -j ACCEPT >/dev/null 2>&1 || die "IPv4 白名单规则写入失败: $add_ip/$proto"
                done
            fi
            save_firewall_rules
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
                    while $IPT6 -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}-WL6" | grep -Fq -- "$del_ip"; do
                        rule=$($IPT6 -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}-WL6" | grep -F -- "$del_ip" | head -n 1 | sed 's/^-A /-D /')
                        [[ -z "$rule" ]] && break
                        # shellcheck disable=SC2086
                        $IPT6 -w $rule >/dev/null 2>&1 || die "IPv6 白名单规则删除失败: $del_ip/$proto"
                        found=1
                    done
                done
            else
                valid_ipv4_cidr "$del_ip" || { msg "${RED}[!] IPv4 白名单地址非法: $del_ip${NC}"; pause_return; return; }
                for proto in tcp udp; do
                    while $IPT -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}-WL" | grep -Fq -- "$del_ip"; do
                        rule=$($IPT -w -S INPUT 2>/dev/null | grep -F "A-Box-${SS_PORT}-${proto}-WL" | grep -F -- "$del_ip" | head -n 1 | sed 's/^-A /-D /')
                        [[ -z "$rule" ]] && break
                        # shellcheck disable=SC2086
                        $IPT -w $rule >/dev/null 2>&1 || die "IPv4 白名单规则删除失败: $del_ip/$proto"
                        found=1
                    done
                done
            fi
            save_firewall_rules
            [[ "$found" == 1 ]] && msg "${GREEN}已移除白名单: $del_ip${NC}" || msg "${YELLOW}未找到该白名单规则。${NC}"
            pause_return
            ;;
        3)
            remove_ss_open_accept_rules
            for proto in tcp udp; do
                if ! $IPT -w -C INPUT -p "$proto" --dport "$SS_PORT" -j DROP 2>/dev/null; then
                    $IPT -w -A INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP" -j DROP >/dev/null 2>&1 || die "IPv4 SS DROP 规则写入失败: $proto"
                fi
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    if ! $IPT6 -w -C INPUT -p "$proto" --dport "$SS_PORT" -j DROP 2>/dev/null; then
                        $IPT6 -w -A INPUT -p "$proto" --dport "$SS_PORT" -m comment --comment "A-Box-${SS_PORT}-${proto}-DROP6" -j DROP >/dev/null 2>&1 || die "IPv6 SS DROP 规则写入失败: $proto"
                    fi
                fi
            done
            save_firewall_rules
            msg "${GREEN}已开启白名单保护模式 (TCP+UDP)。${NC}"
            pause_return
            ;;
        4)
            for proto in tcp udp; do
                while $IPT -w -S INPUT 2>/dev/null | grep -q "A-Box-${SS_PORT}-${proto}-DROP"; do
                    rule=$($IPT -w -S INPUT 2>/dev/null | grep "A-Box-${SS_PORT}-${proto}-DROP" | head -n 1 | sed 's/^-A /-D /')
                    [[ -z "$rule" ]] && break
                    # shellcheck disable=SC2086
                    $IPT -w $rule >/dev/null 2>&1 || break
                done
                if command -v ip6tables >/dev/null 2>&1 && $IPT6 -w -S INPUT >/dev/null 2>&1; then
                    while $IPT6 -w -S INPUT 2>/dev/null | grep -q "A-Box-${SS_PORT}-${proto}-DROP6"; do
                        rule=$($IPT6 -w -S INPUT 2>/dev/null | grep "A-Box-${SS_PORT}-${proto}-DROP6" | head -n 1 | sed 's/^-A /-D /')
                        [[ -z "$rule" ]] && break
                        # shellcheck disable=SC2086
                        $IPT6 -w $rule >/dev/null 2>&1 || break
                    done
                fi
                allowPort "$SS_PORT" "$proto"
            done
            save_firewall_rules
            msg "${GREEN}已切换为全网开放模式 (TCP+UDP)。${NC}"
            pause_return
            ;;
        *) return 0 ;;
    esac
}

do_cleanup() {
    clear; msg "${RED}正在执行清理逻辑...${NC}"
    init_system_environment
    stop_all_managed_services
    clean_nat_rules
    clean_input_rules
    save_firewall_rules
    kill_managed_residual_pids
    rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/sing-box /etc/hysteria /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/hysteria
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service /etc/systemd/system/hysteria.service
    rm -f /etc/init.d/xray /etc/init.d/sing-box /etc/init.d/hysteria
    rm -f /etc/sysctl.d/99-A-Box-tune.conf /etc/security/limits.d/A-Box.conf
    sysctl --system >/dev/null 2>&1 || true
    remove_all_abox_cron_blocks
    rm -f /var/log/A-Box-*.log /etc/fail2ban/jail.d/A-Box.local /etc/fail2ban/filter.d/A-Box.conf /etc/logrotate.d/A-Box 2>/dev/null || true
    if [[ "$INIT_SYS" == 'systemd' ]]; then
        systemctl restart fail2ban 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    else
        rc-service fail2ban restart 2>/dev/null || true
    fi
    if [[ "${1:-}" == 'full' ]]; then
        rm -rf "$ABOX_DIR" /usr/local/bin/sb
        msg "${GREEN}完全清理完成。${NC}"
        exit 0
    else
        rm -f "$ABOX_ENV" "$ABOX_DIR"/.deps* "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"
        setup_shortcut
        msg "${GREEN}代理系统已销毁，保留 sb 入口。${NC}"
        pause_return
    fi
}

check_virgin_state() {
    clear
    init_system_environment
    msg "${YELLOW}删除全部节点与环境初始化 / Delete all nodes and perform environment initialization${NC}"
    read -r -ep '确定执行环境深度自愈吗？[Y/N]: ' confirm_virgin
    is_yes "$confirm_virgin" || { msg "${GREEN}操作已取消。${NC}"; pause_return; return; }
    auto_backup_prompt 'environment reset' "$ABOX_DIR/backups"
    stop_all_managed_services
    kill_managed_residual_pids
    clean_nat_rules
    clean_input_rules
    save_firewall_rules
    remove_all_abox_cron_blocks
    rm -f "$ABOX_ENV" "$ABOX_DIR"/.deps* "$ABOX_DIR/traffic_monitor.sh" "$ABOX_DIR/geo_update.sh" "$ABOX_DIR/socket_probe.sh"
    rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/sing-box /etc/hysteria /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/hysteria
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service /etc/systemd/system/hysteria.service /etc/init.d/xray /etc/init.d/sing-box /etc/init.d/hysteria
    rm -f /var/log/A-Box-*.log /etc/fail2ban/jail.d/A-Box.local /etc/fail2ban/filter.d/A-Box.conf /etc/logrotate.d/A-Box 2>/dev/null || true
    [[ "$INIT_SYS" == 'systemd' ]] && systemctl daemon-reload 2>/dev/null || true
    msg "${GREEN}环境初始化完成。${NC}"
    pause_return
}

tune_vps() {
    clear; msg "${CYAN}正在开启底层系统优化 (TCP-BBR & I/O Limit Control)...${NC}"
    cat > /etc/security/limits.d/A-Box.conf <<'EOF_LIMITS'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF_LIMITS
    modprobe tcp_bbr 2>/dev/null || true
    cat > /etc/sysctl.d/99-A-Box-tune.conf <<'EOF_SYSCTL'
fs.file-max = 1048576
fs.inotify.max_user_instances = 8192
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 32768
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF_SYSCTL
    if command -v sysctl >/dev/null 2>&1; then
        if [[ "${release:-}" == 'alpine' ]]; then
            for conf in /etc/sysctl.d/*.conf /etc/sysctl.conf; do [[ -f "$conf" ]] && sysctl -p "$conf" >/dev/null 2>&1 || true; done
        else
            sysctl --system >/dev/null 2>&1 || true
        fi
    fi
    if [[ -f /usr/local/etc/xray/config.json ]] && command -v jq >/dev/null 2>&1; then
        local xray_bak xray_patch
        xray_bak=$(mktemp /tmp/A-Box-xray-config.XXXXXX) || die 'Xray tune 临时备份创建失败。'
        xray_patch=$(mktemp /tmp/A-Box-xray-patch.XXXXXX) || die 'Xray tune 临时补丁创建失败。'
        cp -f /usr/local/etc/xray/config.json "$xray_bak"
        jq '(.inbounds[] | select(.protocol=="vless") | .streamSettings.sockopt) |= {"tcpKeepAliveIdle":30,"tcpKeepAliveInterval":30}' /usr/local/etc/xray/config.json > "$xray_patch" && mv -f "$xray_patch" /usr/local/etc/xray/config.json
        jq empty /usr/local/etc/xray/config.json >/dev/null 2>&1 || { mv -f "$xray_bak" /usr/local/etc/xray/config.json; rm -f "$xray_patch"; die 'Xray tune 后 JSON 非法，已回滚。'; }
        /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1 || { mv -f "$xray_bak" /usr/local/etc/xray/config.json; rm -f "$xray_patch"; die 'Xray tune 后配置校验失败，已回滚。'; }
        rm -f "$xray_bak" "$xray_patch"
        service_manager start xray
    fi
    if [[ -f /etc/sing-box/config.json ]] && command -v jq >/dev/null 2>&1; then
        local sb_bak sb_patch
        sb_bak=$(mktemp /tmp/A-Box-sb-config.XXXXXX) || die 'Sing-box tune 临时备份创建失败。'
        sb_patch=$(mktemp /tmp/A-Box-sb-patch.XXXXXX) || die 'Sing-box tune 临时补丁创建失败。'
        cp -f /etc/sing-box/config.json "$sb_bak"
        jq '(.inbounds[] | select(.type=="vless" or .type=="shadowsocks")) |= . + {"tcp_keep_alive":"30s","tcp_keep_alive_interval":"30s"}' /etc/sing-box/config.json > "$sb_patch" && mv -f "$sb_patch" /etc/sing-box/config.json
        jq empty /etc/sing-box/config.json >/dev/null 2>&1 || { mv -f "$sb_bak" /etc/sing-box/config.json; rm -f "$sb_patch"; die 'Sing-box tune 后 JSON 非法，已回滚。'; }
        /usr/local/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || { mv -f "$sb_bak" /etc/sing-box/config.json; rm -f "$sb_patch"; die 'Sing-box tune 后配置校验失败，已回滚。'; }
        rm -f "$sb_bak" "$sb_patch"
        service_manager start sing-box
    fi
    setup_health_monitor
    setup_active_defense
    msg "${GREEN}系统优化完成。${NC}"
    pause_return
}


sha256_in_allowlist() {
    local sha="$1" allowlist="${2:-}"
    [[ -n "$sha" && -n "$allowlist" ]] || return 1
    tr ',;[:space:]' '\n' <<< "$allowlist" | grep -Eiq "^${sha}$"
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
    if curl --help all 2>/dev/null | grep -q -- '--tlsv1.3'; then
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
    if [[ -f /swapfile ]]; then
        msg "${YELLOW}$(tr_msg swap_exists)${NC}"
    else
        if ! fallocate -l 2G /swapfile 2>/dev/null; then
            dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress || die 'Swap 文件创建失败。'
        fi
        chmod 600 /swapfile || die 'Swap 文件权限设置失败。'
        mkswap /swapfile >/dev/null || die 'mkswap 失败。'
    fi
    swapon /swapfile || die 'swapon 失败；不会写入 /etc/fstab。'
    if ! grep -qE '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0' /etc/fstab 2>/dev/null; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab || die '/etc/fstab 写入失败。'
    fi
    swapon --show || true
    msg "${GREEN}$(tr_msg swap_done)${NC}"
    pause_return
}

redact_secrets_stream() {
    sed -E \
        -e 's/(UUID=).*/\1***REDACTED***/g' \
        -e 's/(SS_PASS=).*/\1***REDACTED***/g' \
        -e 's/(HY2_PASS=).*/\1***REDACTED***/g' \
        -e 's/(HY2_OBFS=).*/\1***REDACTED***/g' \
        -e 's/(HY2_ACME_DNS_CF_API_TOKEN=).*/\1***REDACTED***/g' \
        -e 's/(PRIVATE_KEY|privateKey|private_key|password|passwd|token|secret|api[_-]?key)([=:] ?)[^ ,}\"]+/\1\2***REDACTED***/Ig' \
        -e 's/(vless|hysteria2|hy2|ss):\/\/[^[:space:]]+/***CLIENT_LINK_REDACTED***/Ig'
}

write_redacted_file() {
    local src="$1" dst="$2"
    [[ -r "$src" ]] || return 0
    mkdir -p "$(dirname "$dst")"
    redact_secrets_stream < "$src" > "$dst" 2>/dev/null || true
}

collect_abox_cron() {
    crontab -l 2>/dev/null | grep -E '(/etc/ddr/|A-Box|geo_update|socket_probe)' || true
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
    local name="$1" tmp
    tmp=$(mktemp) || die 'crontab 临时文件创建失败。'
    crontab -l 2>/dev/null | sed "/^# A-Box ${name} BEGIN$/,/^# A-Box ${name} END$/d" | grep -vE "/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh" > "$tmp" || true
    crontab "$tmp" 2>/dev/null || true
    rm -f "$tmp"
}

remove_all_abox_cron_blocks() {
    local tmp
    tmp=$(mktemp) || die 'crontab 临时文件创建失败。'
    crontab -l 2>/dev/null | sed '/^# A-Box .* BEGIN$/,/^# A-Box .* END$/d' | grep -vE "/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh" > "$tmp" || true
    crontab "$tmp" 2>/dev/null || true
    rm -f "$tmp"
}

backup_current_config() {
    local ts backup_dir work root tarball checksum answer
    ts=$(date +%Y%m%d-%H%M%S)
    backup_dir="${1:-$ABOX_DIR/backups}"
    work=$(mktemp -d /tmp/A-Box-backup.XXXXXX) || die 'Backup temp directory creation failed.'
    root="$work/root"
    mkdir -p "$backup_dir" "$root" "$work/meta"
    chmod 700 "$backup_dir" 2>/dev/null || true

    msg "${YELLOW}[*] Creating A-Box configuration backup...${NC}"

    backup_copy_path() {
        local src="$1" dst
        [[ -e "$src" ]] || return 0
        dst="$root${src}"
        mkdir -p "$(dirname "$dst")"
        cp -a "$src" "$dst" 2>/dev/null || true
    }

    backup_copy_abox_dir() {
        # Back up A-Box runtime/config files, but do not recursively include old
        # backups, diagnostics, or preflight reports. Otherwise every backup can
        # grow by embedding previous backup archives.
        [[ -d "$ABOX_DIR" ]] || return 0
        mkdir -p "$root$ABOX_DIR"
        (
            cd "$ABOX_DIR" || exit 0
            tar --exclude='./backups' --exclude='./diagnostics' --exclude='./preflight' -cpf - . 2>/dev/null | tar -C "$root$ABOX_DIR" -xpf - 2>/dev/null
        ) || true
    }

    backup_copy_abox_dir
    backup_copy_path /usr/local/bin/sb
    backup_copy_path /usr/local/bin/xray
    backup_copy_path /usr/local/bin/sing-box
    backup_copy_path /usr/local/bin/hysteria
    backup_copy_path /usr/local/etc/xray
    backup_copy_path /usr/local/share/xray
    backup_copy_path "$ABOX_FW_STATE"
    backup_copy_path /etc/sing-box
    backup_copy_path /etc/hysteria
    backup_copy_path /etc/logrotate.d/A-Box
    backup_copy_path /etc/fail2ban/filter.d/A-Box.conf
    backup_copy_path /etc/fail2ban/jail.d/A-Box.local
    backup_copy_path /etc/systemd/system/xray.service
    backup_copy_path /etc/systemd/system/sing-box.service
    backup_copy_path /etc/systemd/system/hysteria.service
    backup_copy_path /etc/init.d/xray
    backup_copy_path /etc/init.d/sing-box
    backup_copy_path /etc/init.d/hysteria

    {
        echo "A-Box backup"
        echo "Created: $(now_iso)"
        echo "Host: $(hostname 2>/dev/null || true)"
        echo "Kernel: $(uname -a 2>/dev/null || true)"
        echo "Init: ${INIT_SYS:-unknown}"
        echo "Script SHA256: $(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
    } > "$work/meta/metadata.txt"
    collect_abox_cron > "$work/meta/cron.abox.txt" 2>/dev/null || true
    iptables-save > "$work/meta/iptables.snapshot" 2>/dev/null || true
    ip6tables-save > "$work/meta/ip6tables.snapshot" 2>/dev/null || true

    tarball="$backup_dir/A-Box-backup-${ts}.tar.gz"
    tar -C "$work" -czf "$tarball" . || { rm -rf "$work"; die 'Backup tarball creation failed.'; }
    chmod 600 "$tarball" 2>/dev/null || true
    checksum="${tarball}.sha256"
    sha256sum "$tarball" > "$checksum" 2>/dev/null || true
    chmod 600 "$checksum" 2>/dev/null || true
    rm -rf "$work"

    msg "${GREEN}[*] Backup created:${NC} $tarball"
    [[ -f "$checksum" ]] && msg "${GREEN}[*] SHA256:${NC} $checksum"
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
    local backup_dir="${1:-$ABOX_DIR/backups}" selected work root checksum tmp_cron
    [[ -d "$backup_dir" ]] || return 1
    selected=$(find "$backup_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' | sort -r | head -n 1)
    [[ -n "$selected" ]] || return 1
    checksum="${selected}.sha256"
    if [[ -f "$checksum" ]]; then
        sha256sum -c "$checksum" >/dev/null 2>&1 || return 1
    fi
    work=$(mktemp -d /tmp/A-Box-rollback.XXXXXX) || return 1
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; return 1; }
    root="$work/root"

    stop_all_managed_services >/dev/null 2>&1 || true
    kill_managed_residual_pids >/dev/null 2>&1 || true
    remove_native_firewall_rules >/dev/null 2>&1 || true

    rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/sing-box /etc/hysteria
    rm -f /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/hysteria
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service /etc/systemd/system/hysteria.service
    rm -f /etc/init.d/xray /etc/init.d/sing-box /etc/init.d/hysteria

    restore_copy_path_silent() {
        local path="$1"
        [[ -e "$root$path" ]] || return 0
        mkdir -p "$(dirname "$path")"
        cp -a "$root$path" "$(dirname "$path")/" 2>/dev/null || true
    }

    restore_copy_path_silent "$ABOX_DIR"
    restore_copy_path_silent /usr/local/bin/sb
    restore_copy_path_silent /usr/local/bin/xray
    restore_copy_path_silent /usr/local/bin/sing-box
    restore_copy_path_silent /usr/local/bin/hysteria
    restore_copy_path_silent /usr/local/etc/xray
    restore_copy_path_silent /usr/local/share/xray
    restore_copy_path_silent "$ABOX_FW_STATE"
    restore_copy_path_silent /etc/sing-box
    restore_copy_path_silent /etc/hysteria
    restore_copy_path_silent /etc/logrotate.d/A-Box
    restore_copy_path_silent /etc/fail2ban/filter.d/A-Box.conf
    restore_copy_path_silent /etc/fail2ban/jail.d/A-Box.local
    restore_copy_path_silent /etc/systemd/system/xray.service
    restore_copy_path_silent /etc/systemd/system/sing-box.service
    restore_copy_path_silent /etc/systemd/system/hysteria.service
    restore_copy_path_silent /etc/init.d/xray
    restore_copy_path_silent /etc/init.d/sing-box
    restore_copy_path_silent /etc/init.d/hysteria

    if [[ -f "$work/meta/cron.abox.txt" ]]; then
        tmp_cron=$(mktemp) || { rm -rf "$work"; return 1; }
        crontab -l 2>/dev/null | sed '/^# A-Box .* BEGIN$/,/^# A-Box .* END$/d' | grep -vE '/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh' > "$tmp_cron" || true
        cat "$work/meta/cron.abox.txt" >> "$tmp_cron"
        crontab "$tmp_cron" 2>/dev/null || true
        rm -f "$tmp_cron"
    fi

    apply_native_firewall_rules_from_state >/dev/null 2>&1 || true
    [[ "${INIT_SYS:-}" == 'systemd' ]] && systemctl daemon-reload 2>/dev/null || true
    rm -rf "$work"
    msg "${GREEN}[*] Rollback restored latest backup:${NC} $selected"
}

restore_from_backup() {
    local backup_dir backups i choice selected work root checksum answer
    backup_dir="$ABOX_DIR/backups"
    [[ -d "$backup_dir" ]] || { msg "${RED}[!] No backup directory found: $backup_dir${NC}"; pause_return; return 0; }
    mapfile -t backups < <(find "$backup_dir" -maxdepth 1 -type f -name 'A-Box-backup-*.tar.gz' | sort -r)
    (( ${#backups[@]} > 0 )) || { msg "${RED}[!] No A-Box backup tarballs found.${NC}"; pause_return; return 0; }

    clear
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Restore A-Box Backup / 恢复 A-Box 备份${NC}"
    msg "${CYAN}======================================================================${NC}"
    for i in "${!backups[@]}"; do
        printf '%2d. %s\n' "$((i+1))" "${backups[$i]}"
    done
    msg "${GREEN} 0. Back / 返回${NC}"
    read -r -ep 'Select backup: ' choice
    [[ "$choice" == '0' ]] && return 0
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#backups[@]} )) || { msg "${RED}[!] Invalid selection.${NC}"; pause_return; return 0; }
    selected="${backups[$((choice-1))]}"

    checksum="${selected}.sha256"
    if [[ -f "$checksum" ]]; then
        sha256sum -c "$checksum" >/dev/null 2>&1 || die 'Backup SHA256 verification failed.'
    fi

    msg "${YELLOW}[!] Restore will stop managed services and overwrite A-Box configuration files.${NC}"
    read -r -ep 'Continue restore? [Y/N]: ' answer
    is_yes "$answer" || return 0

    backup_current_config
    stop_all_managed_services
    kill_managed_residual_pids >/dev/null 2>&1 || true
    remove_native_firewall_rules >/dev/null 2>&1 || true
    rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/sing-box /etc/hysteria
    rm -f /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/hysteria
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service /etc/systemd/system/hysteria.service
    rm -f /etc/init.d/xray /etc/init.d/sing-box /etc/init.d/hysteria
    work=$(mktemp -d /tmp/A-Box-restore.XXXXXX) || die 'Restore temp directory creation failed.'
    tar -xzf "$selected" -C "$work" || { rm -rf "$work"; die 'Backup extraction failed.'; }
    root="$work/root"

    restore_copy_path() {
        local path="$1"
        [[ -e "$root$path" ]] || return 0
        mkdir -p "$(dirname "$path")"
        cp -a "$root$path" "$(dirname "$path")/" 2>/dev/null || true
    }

    restore_copy_path "$ABOX_DIR"
    restore_copy_path /usr/local/bin/sb
    restore_copy_path /usr/local/bin/xray
    restore_copy_path /usr/local/bin/sing-box
    restore_copy_path /usr/local/bin/hysteria
    restore_copy_path /usr/local/etc/xray
    restore_copy_path /usr/local/share/xray
    restore_copy_path "$ABOX_FW_STATE"
    restore_copy_path /etc/sing-box
    restore_copy_path /etc/hysteria
    restore_copy_path /etc/logrotate.d/A-Box
    restore_copy_path /etc/fail2ban/filter.d/A-Box.conf
    restore_copy_path /etc/fail2ban/jail.d/A-Box.local
    restore_copy_path /etc/systemd/system/xray.service
    restore_copy_path /etc/systemd/system/sing-box.service
    restore_copy_path /etc/systemd/system/hysteria.service
    restore_copy_path /etc/init.d/xray
    restore_copy_path /etc/init.d/sing-box
    restore_copy_path /etc/init.d/hysteria

    [[ -d "$ABOX_DIR" ]] && chmod 700 "$ABOX_DIR" 2>/dev/null || true
    [[ -f "$ABOX_ENV" ]] && chmod 600 "$ABOX_ENV" 2>/dev/null || true
    [[ -x /usr/local/bin/sb ]] && chmod 755 /usr/local/bin/sb 2>/dev/null || true
    [[ -x /usr/local/bin/xray ]] && chmod 755 /usr/local/bin/xray 2>/dev/null || true
    [[ -x /usr/local/bin/sing-box ]] && chmod 755 /usr/local/bin/sing-box 2>/dev/null || true
    [[ -x /usr/local/bin/hysteria ]] && chmod 755 /usr/local/bin/hysteria 2>/dev/null || true

    if [[ -f "$work/meta/cron.abox.txt" ]]; then
        local tmp_cron
        tmp_cron=$(mktemp)
        crontab -l 2>/dev/null | sed '/^# A-Box .* BEGIN$/,/^# A-Box .* END$/d' | grep -vE '/etc/ddr/(traffic_monitor|geo_update|socket_probe)\.sh' > "$tmp_cron" || true
        cat "$work/meta/cron.abox.txt" >> "$tmp_cron"
        crontab "$tmp_cron" 2>/dev/null || true
        rm -f "$tmp_cron"
    fi

    apply_native_firewall_rules_from_state >/dev/null 2>&1 || true
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -rf "$work"
    msg "${GREEN}[*] Restore completed. Use menu 13 to verify parameters, then start/redeploy services if needed.${NC}"
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
        msg "${GREEN}0. Back${NC}"
    else
        msg "${YELLOW}1. 备份当前 A-Box 配置${NC}"
        msg "${YELLOW}2. 从备份恢复${NC}"
        msg "${GREEN}0. 返回${NC}"
    fi
    local c
    read -r -ep 'Select [0-2]: ' c
    case "$c" in
        1) backup_current_config; pause_return ;;
        2) restore_from_backup ;;
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
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|fedora|alpine) msg "${GREEN}[PASS] OS: ${ID:-unknown}${NC}" ;; *) msg "${YELLOW}[WARN] OS may be unsupported: ${ID:-unknown}${NC}"; warn=$((warn+1)) ;; esac
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
    report_dir="$ABOX_DIR/preflight"
    if ! mkdir -p "$report_dir" 2>/dev/null; then
        local requested_report_dir="$report_dir"
        report_dir=$(mktemp -d /tmp/A-Box-preflight.XXXXXX) || die 'Preflight report directory creation failed.'
        msg "${YELLOW}[WARN] Cannot write ${requested_report_dir}; using ${report_dir}${NC}"
    fi
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
        case "${ID:-}" in debian|ubuntu|centos|rhel|rocky|almalinux|fedora|alpine) pf_pass "supported OS detected: ${ID:-unknown}" ;; *) pf_warn "OS may be unsupported: ${ID:-unknown}" ;; esac
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

    source "$ABOX_ENV" 2>/dev/null || true
    for proto in tcp udp; do
        for port in 443 8443 2053 ${VLESS_PORT:-} ${XHTTP_PORT:-} ${HY2_BASE_PORT:-} ${SS_PORT:-}; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            holder=$(ss -H -n -l -p -A "$proto" 2>/dev/null | grep -E "[:.]${port}\b" | grep -vE 'xray|sing-box|hysteria' || true)
            if [[ -n "$holder" ]]; then
                pf_warn "${port}/${proto} occupied by non-A-Box process: $(head -n 1 <<< "$holder")"
            else
                pf_pass "${port}/${proto} not occupied by non-A-Box process"
            fi
        done
    done

    managed_services_active && pf_warn 'existing A-Box managed service is active' || pf_pass 'no active A-Box managed service detected'
    [[ -w "$ABOX_DIR" || ! -e "$ABOX_DIR" ]] && pf_pass "A-Box directory writable or creatable: $ABOX_DIR" || pf_fail "A-Box directory not writable: $ABOX_DIR"

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
    source "$ABOX_ENV"
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
        msg "${YELLOW}[!] OTA source is the main branch. A syntax/fingerprint check is not a cryptographic signature.${NC}"
        msg "${YELLOW}[!] Source: ${url}${NC}"
        read -r -ep 'Install this downloaded A-Box script? [Y/N]: ' answer
    else
        msg "${YELLOW}[!] OTA 来源为 main 分支。语法/指纹检查不是密码学签名。${NC}"
        msg "${YELLOW}[!] 来源：${url}${NC}"
        read -r -ep '是否安装此下载的 A-Box 脚本？[Y/N]: ' answer
    fi
    is_yes "$answer" || return 130
}

update_script() {
    clear
    local OTA_URL='https://raw.githubusercontent.com/alariclin/a-box/main/install.sh' tmp_update sha
    tmp_update=$(mktemp /tmp/A-Box-update.XXXXXX.sh) || die '更新脚本临时文件创建失败。'
    msg "${YELLOW}[*] 正在同步远端源码...${NC}"
    if curl -fLs --connect-timeout 10 "$OTA_URL" -o "$tmp_update"; then
        sha=$(sha256sum "$tmp_update" | awk '{print $1}')
        msg "${YELLOW}[*] OTA SHA256: ${sha}${NC}"
        if validate_abox_script_file "$tmp_update" 'OTA A-Box 脚本'; then
            confirm_ota_script_hash "$sha" "$OTA_URL" || { rm -f "$tmp_update"; msg "${YELLOW}[*] OTA update canceled.${NC}"; pause_return; return 0; }
            install -m 755 "$tmp_update" "$ABOX_DIR/A-Box.sh"
            validate_abox_script_file "$ABOX_DIR/A-Box.sh" '持久化 A-Box 脚本'
            rm -f "$tmp_update"
            msg "${GREEN}核心代码热更新完毕。${NC}"
            sleep 2
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
    if [[ "${INIT_SYS:-}" == 'systemd' ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart "$srv" >/dev/null 2>&1 || return 1
        sleep 2
        systemctl is-active --quiet "$srv"
    else
        rc-service "$srv" restart >/dev/null 2>&1 || return 1
        sleep 2
        rc-service "$srv" status >/dev/null 2>&1
    fi
}

restore_binary_backup() {
    local bin="$1" backup="$2"
    [[ -n "$backup" && -f "$backup" ]] || return 1
    install -m 755 "$backup" "$bin"
}

upgrade_xray_core_only() {
    local was_active=0 backup='' tmp xray_zip xray_ext old_ver new_ver
    msg "${YELLOW}[*] Upgrading Xray-core binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running xray && was_active=1 || true
    [[ -x /usr/local/bin/xray ]] && old_ver=$(/usr/local/bin/xray version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-xray.XXXXXX) || die 'Xray core upgrade temp directory failed.'
    xray_zip="$tmp/xray_core.zip"
    xray_ext="$tmp/xray_ext"
    mkdir -p "$xray_ext"
    fetch_github_release XTLS/Xray-core xray_core.zip "$xray_zip"
    unzip -qo "$xray_zip" -d "$xray_ext" || { rm -rf "$tmp"; die 'Xray core archive extraction failed.'; }
    [[ -f "$xray_ext/xray" ]] || { rm -rf "$tmp"; die 'Xray binary not found after extraction.'; }
    [[ -x /usr/local/bin/xray ]] && { backup="$tmp/xray.backup"; cp -a /usr/local/bin/xray "$backup"; }
    install -m 755 "$xray_ext/xray" /usr/local/bin/xray || { rm -rf "$tmp"; die 'Xray binary install failed.'; }
    new_ver=$(/usr/local/bin/xray version 2>/dev/null | head -n 1 || true)
    if [[ -f /usr/local/etc/xray/config.json ]]; then
        if ! /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
            msg "${RED}[!] New Xray failed current config test. Rolling back binary...${NC}"
            restore_binary_backup /usr/local/bin/xray "$backup" >/dev/null 2>&1 || true
            rm -rf "$tmp"
            die 'Xray core upgrade rolled back because current config is incompatible.'
        fi
    fi
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft xray; then
            msg "${RED}[!] New Xray failed to restart. Rolling back binary...${NC}"
            restore_binary_backup /usr/local/bin/xray "$backup" >/dev/null 2>&1 || true
            restart_service_soft xray >/dev/null 2>&1 || true
            rm -rf "$tmp"
            die 'Xray core upgrade rolled back because service restart failed.'
        fi
    fi
    msg "${GREEN}[OK] Xray-core upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

upgrade_singbox_core_only() {
    local was_active=0 backup='' tmp sb_tar sb_ext sb_path old_ver new_ver
    msg "${YELLOW}[*] Upgrading sing-box binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running sing-box && was_active=1 || true
    [[ -x /usr/local/bin/sing-box ]] && old_ver=$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-singbox.XXXXXX) || die 'sing-box core upgrade temp directory failed.'
    sb_tar="$tmp/singbox_core.tar.gz"
    sb_ext="$tmp/extract"
    mkdir -p "$sb_ext"
    fetch_github_release SagerNet/sing-box singbox_core.tar.gz "$sb_tar"
    tar -xzf "$sb_tar" -C "$sb_ext" || { rm -rf "$tmp"; die 'sing-box archive extraction failed.'; }
    sb_path=$(find "$sb_ext" -type f -name 'sing-box' | head -n 1)
    [[ -n "$sb_path" && -f "$sb_path" ]] || { rm -rf "$tmp"; die 'sing-box binary not found after extraction.'; }
    [[ -x /usr/local/bin/sing-box ]] && { backup="$tmp/sing-box.backup"; cp -a /usr/local/bin/sing-box "$backup"; }
    install -m 755 "$sb_path" /usr/local/bin/sing-box || { rm -rf "$tmp"; die 'sing-box binary install failed.'; }
    new_ver=$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || true)
    if [[ -f /etc/sing-box/config.json ]]; then
        if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then
            msg "${RED}[!] New sing-box failed current config check. Rolling back binary...${NC}"
            restore_binary_backup /usr/local/bin/sing-box "$backup" >/dev/null 2>&1 || true
            rm -rf "$tmp"
            die 'sing-box core upgrade rolled back because current config is incompatible.'
        fi
    fi
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft sing-box; then
            msg "${RED}[!] New sing-box failed to restart. Rolling back binary...${NC}"
            restore_binary_backup /usr/local/bin/sing-box "$backup" >/dev/null 2>&1 || true
            restart_service_soft sing-box >/dev/null 2>&1 || true
            rm -rf "$tmp"
            die 'sing-box core upgrade rolled back because service restart failed.'
        fi
    fi
    msg "${GREEN}[OK] sing-box upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

upgrade_hysteria_core_only() {
    local was_active=0 backup='' tmp hy2_bin old_ver new_ver
    msg "${YELLOW}[*] Upgrading Hysteria 2 binary only; node parameters will be preserved...${NC}"
    get_architecture
    is_service_running hysteria && was_active=1 || true
    [[ -x /usr/local/bin/hysteria ]] && old_ver=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 || true)
    tmp=$(mktemp -d /tmp/A-Box-core-hysteria.XXXXXX) || die 'Hysteria core upgrade temp directory failed.'
    hy2_bin="$tmp/hysteria_core"
    fetch_github_release apernet/hysteria hysteria_core "$hy2_bin"
    [[ -x /usr/local/bin/hysteria ]] && { backup="$tmp/hysteria.backup"; cp -a /usr/local/bin/hysteria "$backup"; }
    install -m 755 "$hy2_bin" /usr/local/bin/hysteria || { rm -rf "$tmp"; die 'Hysteria binary install failed.'; }
    /usr/local/bin/hysteria version >/dev/null 2>&1 || {
        msg "${RED}[!] New Hysteria binary failed execution check. Rolling back binary...${NC}"
        restore_binary_backup /usr/local/bin/hysteria "$backup" >/dev/null 2>&1 || true
        rm -rf "$tmp"
        die 'Hysteria core upgrade rolled back because binary check failed.'
    }
    new_ver=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 || true)
    if [[ "$was_active" == '1' ]]; then
        if ! restart_service_soft hysteria; then
            msg "${RED}[!] New Hysteria failed to restart. Rolling back binary...${NC}"
            restore_binary_backup /usr/local/bin/hysteria "$backup" >/dev/null 2>&1 || true
            restart_service_soft hysteria >/dev/null 2>&1 || true
            rm -rf "$tmp"
            die 'Hysteria core upgrade rolled back because service restart failed.'
        fi
    fi
    msg "${GREEN}[OK] Hysteria upgraded.${NC} ${old_ver:-unknown} -> ${new_ver:-unknown}"
    rm -rf "$tmp"
}

upgrade_current_cores_only() {
    clear
    init_system_environment
    source "$ABOX_ENV" 2>/dev/null || true
    local targets=() answer t
    if [[ -x /usr/local/bin/xray || -f /usr/local/etc/xray/config.json || "${CORE:-}" == 'xray' ]] || service_unit_exists xray; then
        targets+=(xray)
    fi
    if [[ -x /usr/local/bin/sing-box || -f /etc/sing-box/config.json || "${CORE:-}" == 'singbox' ]] || service_unit_exists sing-box; then
        targets+=(singbox)
    fi
    if [[ -x /usr/local/bin/hysteria || -f /etc/hysteria/config.yaml || "${CORE:-}" == 'hysteria' || ( "${CORE:-}" == 'xray' && "${MODE:-}" == *'ALL'* ) ]] || service_unit_exists hysteria; then
        targets+=(hysteria)
    fi
    if (( ${#targets[@]} == 0 )); then
        msg "${YELLOW}[!] No installed A-Box core binaries/configs detected.${NC}"
        pause_return
        return 0
    fi
    msg "${CYAN}======================================================================${NC}"
    msg "${BOLD}${GREEN}Upgrade current installed proxy cores only / 仅升级当前已安装协议核心${NC}"
    msg "${CYAN}======================================================================${NC}"
    msg "Detected cores: ${targets[*]}"
    msg "This preserves /etc/ddr/.env, UUID, Reality keys, ports, passwords and all node parameters."
    msg "It downloads GitHub latest release assets, validates the current config where supported, restarts only active services, and rolls back the binary if validation/restart fails."
    read -r -ep 'Continue core-only upgrade? [Y/N]: ' answer
    is_yes "$answer" || { msg "${YELLOW}Canceled.${NC}"; pause_return; return 0; }
    auto_backup_silent 'core-only upgrade' "$ABOX_DIR/backups"
    for t in "${targets[@]}"; do
        case "$t" in
            xray) upgrade_xray_core_only ;;
            singbox) upgrade_singbox_core_only ;;
            hysteria) upgrade_hysteria_core_only ;;
        esac
    done
    msg "${GREEN}All detected core-only upgrades completed. Node parameters were preserved.${NC}"
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


enter_runtime() {
    if [[ $EUID -ne 0 ]]; then
        if [[ -f "$0" && -r "$0" && "$0" != 'bash' && "$0" != '-bash' ]] && command -v sudo >/dev/null 2>&1; then
            exec sudo bash "$0" "$@"
        fi
        die '非 root 管道/标准输入执行无法自动提权；请使用: curl -fsSL <URL> | sudo bash'
    fi
    need_interactive_tty
    mkdir -p /var/run "$ABOX_DIR"
    detect_lang
    initial_language_select
    exec 9>"$LOCK_FILE"
    if command -v flock >/dev/null 2>&1; then
        flock -n 9 || die '检测到另一个 A-Box 实例正在运行。'
    fi
}

show_cli_help() {
    cat <<'EOF_HELP'
A-Box
Usage:
  bash A-Box.sh                    启动交互菜单 / Start interactive menu
  bash A-Box.sh --lang zh          设置中文并启动 / Use Chinese UI
  bash A-Box.sh --lang en          Use English UI / 设置英文并启动
  bash A-Box.sh --self-test        运行无副作用静态自测 / Run static self-test
  bash A-Box.sh --status           显示当前配置和服务状态 / Show current status
  bash A-Box.sh --preflight        运行完整预检查 / Run full dry-run preflight check
  bash A-Box.sh --dry-run          同 --preflight / Alias of --preflight
  bash A-Box.sh --help             显示命令行帮助 / Show help
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
    declare -F remove_ss_open_accept_rules >/dev/null 2>&1 || { echo 'FAIL: SS open ACCEPT cleanup missing'; failures=$((failures + 1)); }
    declare -F show_sni_preference_records >/dev/null 2>&1 || { echo 'FAIL: SNI record viewer missing'; failures=$((failures + 1)); }
    declare -F validate_abox_script_file >/dev/null 2>&1 || { echo 'FAIL: local script validation gate missing'; failures=$((failures + 1)); }
    declare -F install_remote_abox_script_guarded >/dev/null 2>&1 || { echo 'FAIL: guarded remote shortcut installer missing'; failures=$((failures + 1)); }
    declare -F validate_fail2ban_config_or_die >/dev/null 2>&1 || { echo 'FAIL: fail2ban validation gate missing'; failures=$((failures + 1)); }
    ( verify_github_asset_digest /dev/null '' ) >/dev/null 2>&1 && { echo 'FAIL: missing GitHub digest must be rejected'; failures=$((failures + 1)); }
    grep -q "GitHub Release asset digest missing; by"'passed' "$0" && { echo 'FAIL: unsigned GitHub asset bypass must not exist'; failures=$((failures + 1)); }
    ( ABOX_ASSUME_YES_OTA=1 confirm_ota_script_hash 0000000000000000000000000000000000000000000000000000000000000000 https://example.com/script.sh ) >/dev/null 2>&1 && { echo 'FAIL: ABOX_ASSUME_YES_OTA must be rejected without allowlist'; failures=$((failures + 1)); }

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
    jq -e '.route.rules[] | select(.protocol=="bittorrent" and .action=="route" and .outbound=="block")' "$tmp/sing-box/config.json" >/dev/null 2>&1 || { echo 'FAIL: Sing-box route action'; failures=$((failures + 1)); }
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
        --help|-h) show_cli_help; exit 0 ;;
        --self-test) run_self_tests; exit $? ;;
        --status) show_status_report; exit 0 ;;
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
    GLOBAL_PUBLIC_IP=$(get_public_ip)
    while true; do
        local STATUS_STR='' CUR_MODE='' choice
        STATUS_STR=$(build_status_str)
        source "$ABOX_ENV" 2>/dev/null && CUR_MODE="[${CORE}-${MODE}]" || CUR_MODE=''
        clear
        msg "${BLUE}======================================================================${NC}"
        msg "${BOLD}${YELLOW}==============================A-Box===============================${NC}"
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
            0) clear; rm -f "$LOCK_FILE"; exit 0 ;;
            *) sleep 1 ;;
        esac
    done
}

main "$@"
