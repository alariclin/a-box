#!/usr/bin/env bash
# A-Box Wallos integration module v173
# Upstream project: https://github.com/ellite/Wallos
# Default stable image pin: bellamy/wallos:5.8.3
# This module only manages the optional Wallos application; it does not alter A-Box proxy protocols.

wallos_mod_t() {
    case "$ABOX_LANG:$1" in
        zh:title) printf 'Wallos 订阅管理 / 一键安装与维护\n' ;;
        en:title) printf 'Wallos subscription tracker / install and manage\n' ;;
        ru:title) printf 'Wallos — учёт подписок / установка и управление\n' ;;
        fa:title) printf 'Wallos — مدیریت اشتراک‌ها / نصب و نگهداری\n' ;;
        zh:runtime) printf '未检测到 Docker。是否按当前 Linux 发行版安装 Docker？[Y/N]: ' ;;
        en:runtime) printf 'Docker is missing. Install Docker for this Linux distribution? [Y/N]: ' ;;
        ru:runtime) printf 'Docker не найден. Установить Docker для этой системы? [Y/N]: ' ;;
        fa:runtime) printf 'Docker پیدا نشد. Docker برای این توزیع نصب شود؟ [Y/N]: ' ;;
        zh:public_http) printf 'Wallos 保存个人财务/订阅数据。公网 HTTP 没有 TLS。确认仍要开放公网端口？[Y/N]: ' ;;
        en:public_http) printf 'Wallos stores private subscription/financial data. Public HTTP has no TLS. Expose the port publicly anyway? [Y/N]: ' ;;
        ru:public_http) printf 'Wallos хранит личные финансовые данные. Публичный HTTP не использует TLS. Всё равно открыть порт? [Y/N]: ' ;;
        fa:public_http) printf 'Wallos داده‌های مالی خصوصی را نگه می‌دارد. HTTP عمومی TLS ندارد. پورت عمومی باز شود؟ [Y/N]: ' ;;
        zh:unsupported) printf '当前系统或架构不受安装器支持；没有继续修改。\n' ;;
        en:unsupported) printf 'This OS or architecture is unsupported; no further changes were made.\n' ;;
        ru:unsupported) printf 'Эта ОС или архитектура не поддерживается; изменения не продолжены.\n' ;;
        fa:unsupported) printf 'این سیستم‌عامل یا معماری پشتیبانی نمی‌شود؛ تغییرات ادامه نیافت.\n' ;;
        zh:installed) printf 'Wallos 已启动。首次访问通常会进入初始账户创建页面。\n' ;;
        en:installed) printf 'Wallos is running. The first visit normally opens the initial account creation page.\n' ;;
        ru:installed) printf 'Wallos запущен. При первом посещении обычно открывается создание первой учётной записи.\n' ;;
        fa:installed) printf 'Wallos اجرا شد. نخستین بازدید معمولاً صفحه ساخت حساب اولیه را نشان می‌دهد.\n' ;;
        zh:failed) printf 'Wallos 安装或健康检查失败；已尝试恢复旧容器与数据。\n' ;;
        en:failed) printf 'Wallos installation or health check failed; rollback of the old container and data was attempted.\n' ;;
        ru:failed) printf 'Установка или проверка Wallos не удалась; выполнена попытка отката контейнера и данных.\n' ;;
        fa:failed) printf 'نصب یا بررسی سلامت Wallos شکست خورد؛ تلاش برای بازیابی کانتینر و داده قدیمی انجام شد.\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

wallos_state_value() {
    local key="$1"
    [[ -f "$WALLOS_DIR/.abox-state" && ! -L "$WALLOS_DIR/.abox-state" ]] || return 1
    awk -F= -v k="$key" '$1 == k {sub(/^[^=]*=/, ""); print; exit}' "$WALLOS_DIR/.abox-state"
}

wallos_detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf 'amd64\n' ;;
        aarch64|arm64) printf 'arm64\n' ;;
        armv7l|armv7) printf 'armv7\n' ;;
        *) return 1 ;;
    esac
}

wallos_port_free() {
    local p="$1"
    if command -v ss >/dev/null 2>&1 && ss -H -ltn "sport = :$p" 2>/dev/null | grep -q .; then return 1; fi
    if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Ports}}' 2>/dev/null | grep -Eq "(^|[ ,]):$p->"; then return 1; fi
    return 0
}

wallos_install_runtime() {
    command -v docker >/dev/null 2>&1 && return 0
    confirm_yes_no "$(wallos_mod_t runtime)" || return 1
    [[ -r /etc/os-release ]] || { msg "$(wallos_mod_t unsupported)"; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID" in
        debian|ubuntu)
            apt-get update || return 1
            apt-get install -y docker.io curl ca-certificates || return 1
            if command -v systemctl >/dev/null 2>&1; then systemctl enable --now docker || return 1
            elif command -v service >/dev/null 2>&1; then service docker start || return 1; fi
            ;;
        alpine)
            apk add --no-cache docker curl ca-certificates || return 1
            rc-update add docker default >/dev/null 2>&1 || true
            rc-service docker start || service docker start || return 1
            ;;
        rhel|rocky|almalinux|centos|fedora|ol|amzn)
            if command -v dnf >/dev/null 2>&1; then
                dnf -y install dnf-plugins-core curl ca-certificates || return 1
                if [[ "$ID" == fedora ]]; then
                    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo || return 1
                else
                    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || return 1
                fi
                dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin || return 1
            elif command -v yum >/dev/null 2>&1; then
                yum -y install curl ca-certificates || return 1
                curl -fsSL https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo || return 1
                yum -y install docker-ce docker-ce-cli containerd.io || return 1
            else
                msg "$(wallos_mod_t unsupported)"
                return 1
            fi
            systemctl enable --now docker || return 1
            ;;
        *)
            msg "$(wallos_mod_t unsupported)"
            return 1
            ;;
    esac
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

wallos_pull_or_restore_image() {
    local image="$1" arch_tag="$2" asset tmp
    docker pull "$image" && return 0
    msg "$YELLOW[!] Docker Hub 拉取失败，尝试 A-Box Wallos 灾备 Release。/ Docker Hub pull failed; trying the A-Box disaster-recovery release.$NC"
    asset="Wallos-v$WALLOS_DEFAULT_VERSION-linux-$arch_tag.tar.gz"
    tmp=$(umask 077; mktemp -d /tmp/A-Box-Wallos.XXXXXX) || return 1
    if ! curl -fLsS --connect-timeout 10 --max-time 180 "https://github.com/alariclin/a-box/releases/download/wallos-mirror-v$WALLOS_DEFAULT_VERSION/SHA256SUMS" -o "$tmp/SHA256SUMS"; then
        rm -rf -- "$tmp"; return 1
    fi
    grep -Fq "  $asset" "$tmp/SHA256SUMS" || { rm -rf -- "$tmp"; return 1; }
    if ! curl -fLsS --connect-timeout 10 --max-time 600 "https://github.com/alariclin/a-box/releases/download/wallos-mirror-v$WALLOS_DEFAULT_VERSION/$asset" -o "$tmp/$asset"; then
        rm -rf -- "$tmp"; return 1
    fi
    (cd "$tmp" && grep -F "  $asset" SHA256SUMS > one.sum && sha256sum -c one.sum) || {
        rm -rf -- "$tmp"
        msg "$RED[!] Wallos 灾备镜像 SHA256 校验失败，拒绝加载。/ Mirror checksum failed; refusing to load.$NC"
        return 1
    }
    gzip -dc "$tmp/$asset" | docker load
    local rc=$?
    rm -rf -- "$tmp"
    (( rc == 0 )) && docker image inspect "$image" >/dev/null 2>&1
}

wallos_wait_healthy() {
    local port="$1" i code
    for i in $(seq 1 60); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 "http://127.0.0.1:$port/" 2>/dev/null || true)
        case "$code" in 200|301|302|303|307|308) return 0 ;; esac
        sleep 2
    done
    return 1
}

wallos_create_backup() {
    local stamp="$1" backup="$WALLOS_DIR/backups/wallos-$stamp.tar.gz"
    mkdir -p "$WALLOS_DIR/backups" || return 1
    chmod 700 "$WALLOS_DIR/backups" || return 1
    tar -czf "$backup" -C "$WALLOS_DIR" db logos .abox-state || return 1
    chmod 600 "$backup" || return 1
    find "$WALLOS_DIR/backups" -maxdepth 1 -type f -name 'wallos-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null |
        sort -nr | awk 'NR>5 {$1=""; sub(/^ /,""); print}' |
        while IFS= read -r old; do [[ "$old" == "$backup" ]] || rm -f -- "$old"; done
    printf '%s\n' "$backup"
}

wallos_public_urls() {
    local port="$1" ip4='' ip6=''
    ip4=$(curl -4fsS --connect-timeout 2 --max-time 4 https://api.ipify.org 2>/dev/null || true)
    ip6=$(curl -6fsS --connect-timeout 2 --max-time 4 https://api64.ipify.org 2>/dev/null || true)
    [[ -z "$ip4" ]] || msg "$GREEN Wallos URL / 初始化与登录地址: http://$ip4:$port/ $NC"
    [[ -z "$ip6" ]] || msg "$GREEN IPv6 URL: http://[$ip6]:$port/ $NC"
    if [[ -z "$ip4" && -z "$ip6" ]]; then
        msg "$YELLOW 无法自动检测公网地址，请使用 VPS 公网 IP 或域名访问端口 $port。/ Could not detect public IP; use your VPS address or domain.$NC"
    fi
}

wallos_install_or_update() {
    local arch_tag image port tz old_image old_port old_tz backup='' stamp='' existing=0 code
    (( EUID == 0 )) || { msg "$RED Wallos 安装需要 root。/ Root is required.$NC"; return 1; }
    arch_tag=$(wallos_detect_arch) || { msg "$(wallos_mod_t unsupported)"; return 1; }
    wallos_install_runtime || { msg "$RED Docker 安装/启动失败。/ Docker setup failed.$NC"; return 1; }
    docker info >/dev/null 2>&1 || { msg "$RED Docker daemon 不可用。/ Docker daemon unavailable.$NC"; return 1; }

    if docker container inspect wallos >/dev/null 2>&1; then
        existing=1
        [[ -f "$WALLOS_DIR/.A-Box-managed" ]] || {
            msg "$RED 发现同名 wallos 容器但无 A-Box 归属标记，为避免覆盖其他部署而中止。/ Existing unmanaged container found; refusing takeover.$NC"
            return 1
        }
        old_image=$(docker inspect -f '{{.Config.Image}}' wallos 2>/dev/null || true)
        old_port=$(wallos_state_value PORT 2>/dev/null || true)
        old_tz=$(wallos_state_value TZ 2>/dev/null || true)
        [[ -n "$old_image" && -n "$old_port" && -n "$old_tz" ]] || {
            msg "$RED Wallos 状态文件不完整，拒绝升级。/ Wallos state is incomplete.$NC"; return 1;
        }
        docker stop wallos >/dev/null 2>&1 || return 1
        stamp=$(date -u '+%Y%m%dT%H%M%SZ')
        backup=$(wallos_create_backup "$stamp") || {
            docker start wallos >/dev/null 2>&1 || true
            msg "$RED 升级前备份失败，已中止升级。/ Pre-upgrade backup failed.$NC"; return 1;
        }
        port="$old_port"; tz="$old_tz"
    else
        [[ ! -e "$WALLOS_DIR" || -f "$WALLOS_DIR/.A-Box-managed" ]] || {
            msg "$RED $WALLOS_DIR 已存在且无 A-Box 归属标记，为避免覆盖用户数据而中止。/ Directory is not A-Box-managed.$NC"; return 1;
        }
        mkdir -p "$WALLOS_DIR/db" "$WALLOS_DIR/logos" "$WALLOS_DIR/backups" || return 1
        chmod 750 "$WALLOS_DIR" "$WALLOS_DIR/db" "$WALLOS_DIR/logos" || return 1
        tz=$(current_timezone_name 2>/dev/null || true); [[ -n "$tz" ]] || tz='UTC'
        valid_timezone_name "$tz" || tz='UTC'
        port=8282
        while ! wallos_port_free "$port"; do
            port=$((port + 1))
            (( port <= 8299 )) || { msg "$RED 8282-8299/TCP 均不可用，请释放端口后重试。/ Ports 8282-8299 are occupied.$NC"; return 1; }
        done
    fi

    image="bellamy/wallos:$WALLOS_DEFAULT_VERSION"
    if ! wallos_pull_or_restore_image "$image" "$arch_tag"; then
        if (( existing == 1 )); then docker start wallos >/dev/null 2>&1 || true; fi
        msg "$RED 上游镜像与 A-Box 灾备镜像均不可用。/ Both upstream and A-Box mirror images are unavailable.$NC"
        return 1
    fi

    if (( existing == 1 )); then
        docker rm wallos >/dev/null 2>&1 || { docker start wallos >/dev/null 2>&1 || true; return 1; }
    fi

    if ! confirm_yes_no "$(wallos_mod_t public_http)"; then
        if (( existing == 1 )); then
            docker run -d --name wallos --label com.alariclin.abox.managed=true -v "$WALLOS_DIR/db:/var/www/html/db" -v "$WALLOS_DIR/logos:/var/www/html/images/uploads/logos" -e TZ="$tz" -p "$port:80/tcp" --restart unless-stopped "$old_image" >/dev/null 2>&1 || true
        fi
        msg "$YELLOW 已取消公网 HTTP 暴露。/ Public HTTP exposure cancelled.$NC"; return 0
    fi

    docker run -d --name wallos --label com.alariclin.abox.managed=true \
        -v "$WALLOS_DIR/db:/var/www/html/db" \
        -v "$WALLOS_DIR/logos:/var/www/html/images/uploads/logos" \
        -e TZ="$tz" -p "$port:80/tcp" --restart unless-stopped "$image" >/dev/null
    code=$?
    if (( code != 0 )) || ! wallos_wait_healthy "$port"; then
        docker rm -f wallos >/dev/null 2>&1 || true
        if (( existing == 1 )); then
            rm -rf -- "$WALLOS_DIR/db" "$WALLOS_DIR/logos"
            tar -xzf "$backup" -C "$WALLOS_DIR" || true
            docker run -d --name wallos --label com.alariclin.abox.managed=true \
                -v "$WALLOS_DIR/db:/var/www/html/db" \
                -v "$WALLOS_DIR/logos:/var/www/html/images/uploads/logos" \
                -e TZ="$old_tz" -p "$old_port:80/tcp" --restart unless-stopped "$old_image" >/dev/null 2>&1 || true
        fi
        msg "$(wallos_mod_t failed)"; return 1
    fi

    printf '%s\n' 'A-Box-managed Wallos' > "$WALLOS_DIR/.A-Box-managed"
    printf 'VERSION=%s\nPORT=%s\nTZ=%s\nIMAGE=%s\n' "$WALLOS_DEFAULT_VERSION" "$port" "$tz" "$image" > "$WALLOS_DIR/.abox-state"
    chmod 600 "$WALLOS_DIR/.abox-state" "$WALLOS_DIR/.A-Box-managed"
    msg "$(wallos_mod_t installed)"
    msg "$CYAN Version: $WALLOS_DEFAULT_VERSION | Image: $image | Port: $port | TZ: $tz $NC"
    msg "$YELLOW 首次注册后请立即设置强密码。请确认云安全组放行 TCP $port；建议用 HTTPS 反向代理，不要长期通过明文 HTTP 管理个人财务数据。/ Open TCP $port in your provider firewall and use HTTPS for ongoing access.$NC"
    wallos_public_urls "$port"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
        if confirm_yes_no "检测到 UFW，是否放行 TCP $port？/ Allow TCP $port in UFW? [Y/N]: "; then
            ufw allow "$port/tcp" || msg "$YELLOW UFW 规则添加失败。/ Failed to add UFW rule.$NC"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if confirm_yes_no "检测到 firewalld，是否放行 TCP $port？/ Allow TCP $port in firewalld? [Y/N]: "; then
            firewall-cmd --permanent --add-port="$port/tcp" && firewall-cmd --reload || msg "$YELLOW firewalld 规则添加失败。/ Failed to add firewalld rule.$NC"
        fi
    fi
    [[ -z "$backup" ]] || msg "$GREEN 升级前备份：$backup $NC"
}

wallos_status() {
    local port
    if ! docker container inspect wallos >/dev/null 2>&1; then
        msg "$YELLOW Wallos 容器尚未安装。/ Wallos is not installed.$NC"; return 0
    fi
    docker ps -a --filter name='^/wallos$' --format 'Container: {{.Names}} | Status: {{.Status}} | Image: {{.Image}}'
    port=$(wallos_state_value PORT 2>/dev/null || true)
    [[ -z "$port" ]] && { msg "$YELLOW 状态文件不存在，请检查容器端口映射。/ State file missing.$NC"; return 0; }
    wallos_public_urls "$port"
}

wallos_manual_backup() {
    local stamp
    (( EUID == 0 )) || return 1
    [[ -f "$WALLOS_DIR/.A-Box-managed" ]] || { msg "$YELLOW 未找到 A-Box 管理的 Wallos。/ No A-Box-managed Wallos found.$NC"; return 1; }
    if docker container inspect wallos >/dev/null 2>&1; then docker stop wallos >/dev/null 2>&1 || return 1; fi
    stamp=$(date -u '+%Y%m%dT%H%M%SZ')
    wallos_create_backup "$stamp" || { docker start wallos >/dev/null 2>&1 || true; return 1; }
    if docker container inspect wallos >/dev/null 2>&1; then docker start wallos >/dev/null 2>&1 || true; fi
    msg "$GREEN Wallos 数据备份已完成。/ Wallos data backup created.$NC"
}

wallos_menu_impl() {
    clear
    msg "$CYAN======================================================================$NC"
    msg "$BOLD$GREEN$(wallos_mod_t title)$NC"
    msg "$CYAN======================================================================$NC"
    msg "$YELLOW 1. 一键安装 / 升级 Wallos（上游优先，A-Box 灾备回退） / Install or update$NC"
    msg "$YELLOW 2. 查看状态与访问地址 / Status and URL$NC"
    msg "$YELLOW 3. 备份数据库与上传图片 / Back up database and logos$NC"
    msg "$YELLOW 4. 删除容器但保留数据 / Remove container, keep data$NC"
    msg "$GREEN 0. 返回 / Back$NC"
    local c
    read -r -p 'Select [0-4]: ' c
    case "$c" in
        1) wallos_install_or_update; pause_return ;;
        2) wallos_status; pause_return ;;
        3) wallos_manual_backup; pause_return ;;
        4)
            if [[ -f "$WALLOS_DIR/.A-Box-managed" ]] && confirm_yes_no "确认删除 Wallos 容器但保留 $WALLOS_DIR 下的数据？[Y/N]: "; then
                docker rm -f wallos >/dev/null 2>&1 || true
                msg "$GREEN 容器已删除，数据保留。/ Container removed; data retained.$NC"
            fi
            pause_return ;;
        *) return 0 ;;
    esac
}
