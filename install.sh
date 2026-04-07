#!/bin/bash
#
# install-mtg-ee.sh — Установка MTProto-прокси 9seconds/mtg с ee-секретом и реальным TLS-сертификатом
# Версия: 2.2 (исправлены цвета, генерация секрета, логирование)
#
# Параметры:
#   --show-key   : показать текущий ee-секрет
#   --renew-key  : сгенерировать новый ee-секрет и перезапустить прокси
#

set -uo pipefail

# ================= КОНФИГУРАЦИЯ =================
PROXY_DIR="/opt/mtg-ee-proxy"
CONFIG_FILE="${PROXY_DIR}/config.toml"
COMPOSE_FILE="${PROXY_DIR}/docker-compose.yml"
CERT_DIR="/etc/letsencrypt"
CONTAINER_NAME="mtg-proxy"
IMAGE_TAG="nineseconds/mtg:2"
CRON_FILE="/etc/cron.d/mtg-cert-renew"
LOG_FILE="/var/log/mtg-install.log"
# ===============================================

# Цвета (используются только при выводе в терминал)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Функция для удаления ANSI-кодов (для лог-файла)
strip_colors() { sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g'; }

# Логирование: в терминал с цветами, в файл — без
log_info() { 
    local msg="[INFO] $1"
    echo -e "${GREEN}${msg}${NC}"  # В терминал с цветами
    echo "$msg" | strip_colors >> "$LOG_FILE"  # В файл без цветов
}
log_warn() { 
    local msg="[WARN] $1"
    echo -e "${YELLOW}${msg}${NC}"
    echo "$msg" | strip_colors >> "$LOG_FILE"
}
log_error() { 
    local msg="[ERROR] $1"
    echo -e "${RED}${msg}${NC}" >&2
    echo "$msg" | strip_colors >> "$LOG_FILE"
}

# Вывод без цветов (для финального блока)
echo_plain() { echo "$1"; }
echo_green() { echo -e "${GREEN}${1}${NC}"; }
echo_yellow() { echo -e "${YELLOW}${1}${NC}"; }

# Проверка root
if [[ $EUID -ne 0 ]]; then
    log_error "Скрипт должен запускаться от root. Используйте: sudo $0"
    exit 1
fi

# Инициализация лог-файла
mkdir -p "$(dirname "$LOG_FILE")"
echo "=== Установка запущена: $(date -Iseconds) ===" > "$LOG_FILE"

# ================= УТИЛИТЫ =================

is_package_installed() {
    dpkg -l "$1" &>/dev/null | grep -q "^ii"
}

ensure_package() {
    local package="$1"
    if is_package_installed "$package"; then
        return 0
    fi
    log_warn "Пакет '$package' не установлен. Попытка установки..."
    apt-get update -qq >/dev/null 2>&1 || true
    if apt-get install -y -qq "$package" >/dev/null 2>&1; then
        log_info "✅ Пакет '$package' установлен"
        return 0
    else
        log_error "Не удалось установить пакет '$package'"
        return 1
    fi
}

ensure_command() {
    local cmd="$1"
    local package="${2:-$cmd}"
    if command -v "$cmd" &>/dev/null; then
        return 0
    fi
    ensure_package "$package"
    command -v "$cmd" &>/dev/null
}

install_prerequisites() {
    log_info "📦 Проверка и установка базовых зависимостей..."
    apt-get update -qq >/dev/null 2>&1 || true
    
    # Пакеты без исполняемых файлов (проверка через dpkg)
    for pkg in ca-certificates apt-transport-https gnupg; do
        ensure_package "$pkg" || true
    done
    
    # Утилиты с командами
    ensure_command "curl" "curl" || true
    ensure_command "getent" "libc-bin" || true
    ensure_command "cron" "cron" || true
    ensure_command "openssl" "openssl" || true
    
    log_info "✅ Базовые зависимости проверены"
}

get_public_ip() {
    local ip
    for service in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com" "https://ident.me"; do
        ip=$(curl -s --connect-timeout 5 --max-time 10 "$service" 2>/dev/null | tr -d '\r\n' | head -1)
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

is_valid_public_ip() {
    local ip="$1"
    [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1
    [[ "$ip" =~ ^(127\.|0\.|10\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[0-1][0-9]\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.18\.|198\.19\.|198\.51\.100\.|203\.0\.113\.|22[4-9]\.|23[0-9]\.) ]] && return 1
    return 0
}

is_valid_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

domain_resolves() {
    getent hosts "$1" >/dev/null 2>&1
}

is_cert_valid() {
    local target="$1"
    local cert_path="${CERT_DIR}/live/${target}/fullchain.pem"
    [[ ! -f "$cert_path" ]] && return 1
    if openssl x509 -checkend 2592000 -noout -in "$cert_path" >/dev/null 2>&1; then
        local expiry
        expiry=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
        log_info "✅ Сертификат для '$target' валиден до: $expiry"
        return 0
    fi
    log_warn "⚠️ Сертификат для '$target' истекает менее чем через 30 дней"
    return 1
}

is_docker_installed() {
    command -v docker &>/dev/null && docker info &>/dev/null 2>&1 && \
    (command -v docker-compose &>/dev/null || docker compose version &>/dev/null 2>&1)
}

# ================= ФУНКЦИИ УПРАВЛЕНИЯ =================

show_key() {
    [[ ! -f "$CONFIG_FILE" ]] && { log_error "Файл конфигурации не найден: $CONFIG_FILE"; exit 1; }
    local secret server
    secret=$(grep -E '^secret\s*=' "$CONFIG_FILE" | sed -E 's/secret\s*=\s*"([^"]+)".*/\1/')
    server=$(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo '<не-указан>')
    [[ -z "$secret" ]] && { log_error "Не удалось извлечь секрет"; exit 1; }
    
    echo ""
    echo_green "🔑 Ваш текущий ee-секрет для Telegram:"
    echo "┌─────────────────────────────────────────┐"
    echo "│ $secret"
    echo "└─────────────────────────────────────────┘"
    echo ""
    echo_yellow "Настройки для Telegram:"
    echo_plain "  Тип:    MTProto"
    echo_plain "  Сервер: $server"
    echo_plain "  Порт:   443"
    echo_plain "  Секрет: $secret"
    echo ""
    echo_yellow "💡 Скопируйте секрет целиком (начинается с ee)"
    echo ""
    exit 0
}

renew_key() {
    log_info "🔄 Запуск ротации ee-секрета..."
    [[ ! -f "$CONFIG_FILE" ]] && { log_error "Файл конфигурации не найден: $CONFIG_FILE"; exit 1; }
    
    local server
    server=$(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo "proxy.local")
    
    # Генерация с корректной обработкой вывода
    local raw_output
    raw_output=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$server" 2>&1)
    local new_secret
    new_secret=$(echo "$raw_output" | grep -oE '^ee[0-9a-f]+$' | head -1)
    
    if [[ -z "$new_secret" ]]; then
        # Альтернативный парсинг: берём первую строку, чистим от лишнего
        new_secret=$(echo "$raw_output" | head -1 | tr -cd 'a-f0-9' | sed 's/^/ee/' | head -c 66)
    fi
    
    # Финальная валидация
    if [[ ! "$new_secret" =~ ^ee[0-9a-f]{64}$ ]]; then
        log_error "Не удалось сгенерировать корректный ee-секрет"
        log_error "Получено: '${new_secret}' (длина: ${#new_secret})"
        log_error "Попробуйте вручную: docker run --rm $IMAGE_TAG generate-secret --hex $server"
        exit 1
    fi
    
    sed -i "s/^secret\s*=\s*\"[^\"]*\"/secret = \"$new_secret\"/" "$CONFIG_FILE"
    cd "$PROXY_DIR"
    docker compose restart "$CONTAINER_NAME" >/dev/null 2>&1 || docker restart "$CONTAINER_NAME" >/dev/null 2>&1
    
    log_info "✅ Ключ успешно обновлён!"
    echo ""
    echo_green "🔑 Новый ee-секрет:"
    echo "┌─────────────────────────────────────────┐"
    echo "│ $new_secret"
    echo "└─────────────────────────────────────────┘"
    echo ""
    echo_yellow "⚠️ Обновите настройки во всех клиентах Telegram!"
    echo ""
    exit 0
}

# ================= УСТАНОВКА =================

install_docker() {
    if is_docker_installed; then
        log_info "✅ Docker и Docker Compose уже установлены"
        return 0
    fi
    log_info "📦 Установка Docker..."
    ensure_package "curl" && ensure_package "gnupg" && ensure_package "apt-transport-https" && ensure_package "ca-certificates"
    
    install -m 0755 -d /etc/apt/keyrings 2>/dev/null || true
    curl -fsSL https://download.docker.com/linux/debian/gpg 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
    chmod a+r /etc/apt/keyrings/docker.gpg 2>/dev/null || true
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    systemctl enable --now docker >/dev/null 2>&1 || true
    
    is_docker_installed && { log_info "✅ Docker установлен успешно"; return 0; }
    log_error "Не удалось завершить установку Docker"
    return 1
}

get_certificate() {
    local target="$1"
    local is_ip="$2"
    
    if is_cert_valid "$target"; then
        log_info "✅ Сертификат уже существует и валиден — пропускаем запрос"
        return 0
    fi
    
    log_info "🔐 Запрос реального TLS-сертификата для: $target"
    
    if ! command -v certbot &>/dev/null; then
        log_info "📦 Установка certbot..."
        apt-get install -y -qq certbot >/dev/null 2>&1 || {
            if command -v snap &>/dev/null; then
                snap install core >/dev/null 2>&1 || true
                snap install --classic certbot >/dev/null 2>&1 || true
                ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
            else
                log_error "Не удалось установить certbot"
                return 1
            fi
        }
    fi
    
    local challenge_flag="--standalone --preferred-challenges http"
    log_info "🔄 Запрос сертификата через Let's Encrypt..."
    
    local stopped_services=()
    for svc in nginx apache2 lighttpd caddy; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && stopped_services+=("$svc")
        fi
    done
    
    local cert_success=false
    if [[ "$is_ip" == "true" ]]; then
        certbot certonly $challenge_flag --agree-tos --no-eff-email --email "admin@${target}.local" --ip-addresses "$target" --keep-until-expiring --non-interactive >/dev/null 2>&1 && cert_success=true
    else
        certbot certonly $challenge_flag --agree-tos --no-eff-email --email "admin@$target" -d "$target" --keep-until-expiring --non-interactive >/dev/null 2>&1 && cert_success=true
    fi
    
    for svc in "${stopped_services[@]}"; do systemctl start "$svc" 2>/dev/null || true; done
    
    if [[ "$cert_success" != "true" ]]; then
        log_error "Не удалось получить сертификат через Let's Encrypt"
        return 1
    fi
    
    local cert_path="${CERT_DIR}/live/${target}/fullchain.pem"
    local key_path="${CERT_DIR}/live/${target}/privkey.pem"
    [[ ! -f "$cert_path" || ! -f "$key_path" ]] && { log_error "Сертификат не найден после запроса"; return 1; }
    
    log_info "✅ Сертификат получен: $cert_path"
    return 0
}

setup_autorenew() {
    if [[ -f "$CRON_FILE" ]] && grep -q "certbot renew" "$CRON_FILE" 2>/dev/null; then
        log_info "✅ Задача автообновления уже настроена"
        return 0
    fi
    log_info "⏰ Настройка автообновления сертификатов..."
    cat > "$CRON_FILE" << 'EOF'
# Автообновление TLS-сертификатов для mtg-proxy
0 3 * * * root /usr/bin/certbot renew --quiet --post-hook "docker restart mtg-proxy 2>/dev/null || true"
EOF
    chmod 644 "$CRON_FILE"
    ensure_package "cron"
    systemctl enable --now cron >/dev/null 2>&1 || true
    log_info "✅ Автообновление настроено (ежедневно в 03:00)"
}

generate_config() {
    local target="$1"
    local secret="$2"
    log_info "⚙️ Создание конфигурации..."
    mkdir -p "$PROXY_DIR"
    echo "$target" > "${PROXY_DIR}/.server"
    
    cat > "$CONFIG_FILE" << EOF
# MTProto Proxy Configuration (9seconds/mtg)
# Generated: $(date -Iseconds)

secret = "${secret}"
bind-to = "0.0.0.0:443"

# TLS-сертификаты
tls-certificate = "${CERT_DIR}/live/${target}/fullchain.pem"
tls-private-key = "${CERT_DIR}/live/${target}/privkey.pem"

# Тег для статистики
adtag = "ee-proxy-$(echo "$target" | tr -cd 'a-zA-Z0-9' | head -c 12)"

# Логирование
log-level = "info"
EOF

    cat > "$COMPOSE_FILE" << 'EOF'
version: '3.8'
services:
  mtg-proxy:
    image: nineseconds/mtg:2
    container_name: mtg-proxy
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config.toml:/config.toml:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF
    log_info "✅ Конфигурация создана в $PROXY_DIR"
}

start_proxy() {
    log_info "🚀 Запуск MTProto-прокси..."
    cd "$PROXY_DIR"
    chmod 644 "${CERT_DIR}/live/"*/fullchain.pem 2>/dev/null || true
    chmod 600 "${CERT_DIR}/live/"*/privkey.pem 2>/dev/null || true
    
    local compose_cmd="docker compose"
    $compose_cmd version &>/dev/null || compose_cmd="docker-compose"
    
    $compose_cmd -f "$COMPOSE_FILE" up -d --quiet-pull 2>/dev/null || \
    docker run -d --name "$CONTAINER_NAME" --restart unless-stopped --network host \
        -v "${CONFIG_FILE}:/config.toml:ro" -v "${CERT_DIR}:/etc/letsencrypt:ro" "$IMAGE_TAG" 2>/dev/null
    
    sleep 3
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "✅ Прокси запущен"
        return 0
    else
        log_error "Не удалось запустить контейнер. Проверьте: docker logs $CONTAINER_NAME"
        return 1
    fi
}

# ================= ИНТЕРАКТИВНЫЙ ВЫБОР =================

prompt_target() {
    echo ""
    echo_yellow "🔹 Выберите тип идентификатора для прокси:"
    echo_plain "  1) Использовать домен (например, proxy.example.com)"
    echo_plain "  2) Использовать публичный IP-адрес"
    echo -n "Ваш выбор [1/2]: "
    read -r CHOICE
    
    case "$CHOICE" in
        1)
            echo ""
            echo_yellow "📋 Введите ваш домен:"
            echo -n "> "
            read -r TARGET
            is_valid_domain "$TARGET" || { log_error "Некорректный формат домена"; exit 1; }
            MODE="domain"
            ;;
        2)
            log_info "🔍 Определение публичного IP-адреса..."
            DETECTED_IP=$(get_public_ip)
            if [[ -z "$DETECTED_IP" ]]; then
                log_error "Не удалось автоматически определить внешний IP"
                echo ""
                echo_yellow "📋 Введите ваш публичный IP-адрес вручную:"
                echo -n "> "
                read -r TARGET
            else
                echo ""
                echo_green "✅ Обнаружен внешний IP: ${DETECTED_IP}"
                echo_yellow "📋 Нажмите Enter для использования обнаруженного IP, или введите другой:"
                echo -n "> "
                read -r USER_INPUT
                TARGET="${USER_INPUT:-$DETECTED_IP}"
                log_info "Будет использован: $TARGET"
            fi
            is_valid_public_ip "$TARGET" || { log_error "Некорректный или приватный IP: $TARGET"; exit 1; }
            MODE="ip"
            ;;
        *)
            log_error "Неверный выбор. Перезапустите скрипт."
            exit 1
            ;;
    esac
}

# ================= ОСНОВНАЯ ЛОГИКА =================

if [[ "${1:-}" == "--show-key" ]]; then show_key; fi
if [[ "${1:-}" == "--renew-key" ]]; then renew_key; fi

log_info "🔧 Режим установки: настройка нового MTProto-прокси"
install_prerequisites
prompt_target
install_docker || exit 1

[[ "$MODE" == "domain" ]] && ! domain_resolves "$TARGET" && \
    log_warn "⚠️ Домен '$TARGET' пока не резолвится — это нормально при свежей DNS-записи"

get_certificate "$TARGET" "$([[ "$MODE" == "ip" ]] && echo true || echo false)" || {
    log_error "❌ Не удалось получить реальный TLS-сертификат."
    echo_yellow "Возможные причины:"
    echo_plain "  • Порт 80 закрыт фаерволом или провайдером"
    echo_plain "  • DNS-запись ещё не обновилась (для домена)"
    echo_plain "  • Лимит запросов Let's Encrypt"
    echo ""
    echo_yellow "Проверьте:"
    echo_plain "  • ss -tlnp | grep :80"
    echo_plain "  • Для домена: A-запись должна указывать на $(curl -s ifconfig.me 2>/dev/null || echo 'ваш IP')"
    echo_plain "  • Логи: tail -50 /var/log/letsencrypt/letsencrypt.log"
    exit 1
}

log_info "🔑 Генерация ee-секрета (MTProto 2.0 + Fake TLS)..."
# Генерация с надёжным парсингом
raw_output=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$TARGET" 2>&1)
SECRET=$(echo "$raw_output" | grep -oE '^ee[0-9a-f]{64}$' | head -1)

# Если grep не нашёл — пробуем альтернативный метод
if [[ -z "$SECRET" ]]; then
    # Берём первую строку, оставляем только hex-символы, добавляем ee, обрезаем до 66
    SECRET=$(echo "$raw_output" | head -1 | tr -cd 'a-fA-F0-9' | tr 'A-F' 'a-f' | sed 's/^/ee/' | head -c 66)
fi

if [[ ! "$SECRET" =~ ^ee[0-9a-f]{64}$ ]]; then
    log_error "Не удалось сгенерировать корректный ee-секрет"
    log_error "Получено: '${SECRET}' (длина: ${#SECRET})"
    log_error "Попробуйте вручную: docker run --rm $IMAGE_TAG generate-secret --hex $TARGET"
    log_error "Вывод команды:"
    echo "$raw_output" | strip_colors >> "$LOG_FILE"
    exit 1
fi

generate_config "$TARGET" "$SECRET"
setup_autorenew
start_proxy

# ================= ФИНАЛЬНЫЙ ВЫВОД (без цветов в логах) =================
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  ✅ MTProto-прокси успешно установлен!    ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo_yellow "🔑 Ваш ee-секрет для Telegram:"
echo "┌─────────────────────────────────────────┐"
echo "│ ${SECRET}"
echo "└─────────────────────────────────────────┘"
echo ""
echo_yellow "📱 Настройки для официального Telegram:"
echo_plain "  • Тип прокси: MTProto"
echo_plain "  • Сервер:     ${TARGET}"
echo_plain "  • Порт:       443"
echo_plain "  • Секрет:     ${SECRET}"
echo ""
echo_yellow "🛠️ Управление:"
echo_plain "  • Показать ключ:      $0 --show-key"
echo_plain "  • Ротация ключа:      $0 --renew-key"
echo_plain "  • Просмотр логов:     docker logs -f $CONTAINER_NAME"
echo_plain "  • Перезапуск:         cd $PROXY_DIR && docker compose restart"
echo_plain "  • Лог установки:      tail -f $LOG_FILE"
echo ""
echo_yellow "🔒 Важные заметки:"
echo_plain "  • Сертификат автообновляется ежедневно в 03:00"
echo_plain "  • При обновлении сертификата контейнер перезапускается автоматически"
echo_plain "  • Для максимальной скрытности: используйте только порт 443 и ee-секрет"
echo_plain "  • Рекомендуется менять секрет каждые 30-45 дней: $0 --renew-key"
echo ""
echo_green "🎉 Готово! Подключайтесь в Telegram."
echo ""
