#!/bin/bash
#
# install-mtg-ee.sh — Установка MTProto-прокси 9seconds/mtg с ee-секретом и реальным TLS-сертификатом
# Поддержка: домен ИЛИ публичный IP (Let's Encrypt / ZeroSSL)
# Запуск: от root, Debian 12/13
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
# ===============================================

# Цвета для вывода
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Проверка root
if [[ $EUID -ne 0 ]]; then
    log_error "Скрипт должен запускаться от root. Используйте: sudo $0"
    exit 1
fi

# ================= УТИЛИТЫ =================

# Попытка установить пакет, если команда не найдена
ensure_command() {
    local cmd="$1"
    local package="${2:-$cmd}"
    
    if ! command -v "$cmd" &>/dev/null; then
        log_warn "Команда '$cmd' не найдена. Попытка установки пакета '$package'..."
        apt-get update -qq >/dev/null 2>&1 || true
        if apt-get install -y -qq "$package" >/dev/null 2>&1; then
            log_info "✅ Пакет '$package' установлен"
            return 0
        else
            log_error "Не удалось установить пакет '$package'. Попробуйте вручную: apt install $package"
            return 1
        fi
    fi
    return 0
}

# Установка базовых зависимостей в начале скрипта
install_prerequisites() {
    log_info "📦 Проверка и установка базовых зависимостей..."
    
    # Обновляем кэш пакетов один раз
    apt-get update -qq >/dev/null 2>&1 || true
    
    # Список критичных пакетов
    local packages=("curl" "gnupg" "apt-transport-https" "ca-certificates" "cron" "openssl")
    
    for pkg in "${packages[@]}"; do
        ensure_command "$pkg" "$pkg" || true
    done
    
    # Дополнительно: если не установлен getent (из libc-bin), пробуем установить
    ensure_command "getent" "libc-bin" || true
    
    log_info "✅ Базовые зависимости проверены"
}

# Получение публичного IP через несколько сервисов (fallback)
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

# Валидация IP (публичный, не локальный)
is_valid_public_ip() {
    local ip="$1"
    # Базовая проверка формата
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    # Проверка на приватные/зарезервированные диапазоны
    if [[ "$ip" =~ ^(127\.|0\.|10\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[0-1][0-9]\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.18\.|198\.19\.|198\.51\.100\.|203\.0\.113\.|22[4-9]\.|23[0-9]\.) ]]; then
        return 1
    fi
    return 0
}

# Валидация домена (базовая RFC 1123)
is_valid_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# Проверка, резолвится ли домен (через getent, без dig)
domain_resolves() {
    local domain="$1"
    if getent hosts "$domain" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# ================= ФУНКЦИИ УПРАВЛЕНИЯ =================

show_key() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Файл конфигурации не найден: $CONFIG_FILE"
        exit 1
    fi
    local secret server
    secret=$(grep -E '^secret\s*=' "$CONFIG_FILE" | sed -E 's/secret\s*=\s*"([^"]+)".*/\1/')
    server=$(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo '<не-указан>')
    
    if [[ -z "$secret" ]]; then
        log_error "Не удалось извлечь секрет из конфигурации"
        exit 1
    fi
    echo -e "\n${GREEN}🔑 Ваш текущий ee-секрет для Telegram:${NC}"
    echo "┌─────────────────────────────────────────┐"
    echo "│ $secret"
    echo "└─────────────────────────────────────────┘"
    echo -e "\n${YELLOW}Настройки для Telegram:${NC}"
    echo "  Тип:    MTProto"
    echo "  Сервер: $server"
    echo "  Порт:   443"
    echo "  Секрет: $secret"
    echo -e "\n${YELLOW}💡 Скопируйте секрет целиком (начинается с ee)${NC}\n"
    exit 0
}

renew_key() {
    log_info "🔄 Запуск ротации ee-секрета..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Файл конфигурации не найден: $CONFIG_FILE"
        exit 1
    fi
    
    local server
    server=$(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo "proxy.local")
    
    local new_secret
    new_secret=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$server" 2>/dev/null | tr -d '\r\n')
    
    if [[ ! "$new_secret" =~ ^ee[0-9a-f]{64}$ ]]; then
        log_error "Не удалось сгенерировать корректный ee-секрет"
        exit 1
    fi
    
    sed -i "s/^secret\s*=\s*\"[^\"]*\"/secret = \"$new_secret\"/" "$CONFIG_FILE"
    
    cd "$PROXY_DIR"
    docker compose restart "$CONTAINER_NAME" >/dev/null 2>&1 || docker restart "$CONTAINER_NAME" >/dev/null 2>&1
    
    log_info "✅ Ключ успешно обновлён!"
    echo -e "\n${GREEN}🔑 Новый ee-секрет:${NC}"
    echo "┌─────────────────────────────────────────┐"
    echo "│ $new_secret"
    echo "└─────────────────────────────────────────┘"
    echo -e "\n${YELLOW}⚠️ Обновите настройки во всех клиентах Telegram!${NC}\n"
    exit 0
}

# ================= УСТАНОВКА =================

install_docker() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        log_info "Docker уже установлен"
        return 0
    fi
    
    log_info "📦 Установка Docker..."
    
    # Устанавливаем зависимости через ensure_command
    ensure_command "curl" "curl"
    ensure_command "gpg" "gnupg"
    ensure_command "apt-transport-https" "apt-transport-https"
    
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
    
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    
    systemctl enable --now docker >/dev/null 2>&1 || true
    log_info "✅ Docker установлен"
}

get_certificate() {
    local target="$1"
    local is_ip="$2"
    
    log_info "🔐 Запрос реального TLS-сертификата для: $target"
    
    ensure_command "certbot" "certbot" || {
        # Если certbot не в репозиториях, пробуем установить через snap или pip
        if command -v snap &>/dev/null; then
            snap install core; snap refresh core >/dev/null 2>&1 || true
            snap install --classic certbot >/dev/null 2>&1 || true
            ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
        fi
        if ! command -v certbot &>/dev/null; then
            apt-get install -y -qq python3-certbot >/dev/null 2>&1 || true
        fi
    }
    
    local challenge_flag="--standalone --preferred-challenges http"
    
    log_info "🔄 Запрос сертификата через Let's Encrypt..."
    
    if [[ "$is_ip" == "true" ]]; then
        certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@${target}.local" \
            --ip-addresses "$target" \
            --keep-until-expiring --non-interactive >/dev/null 2>&1 || return 1
    else
        certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@$target" \
            -d "$target" \
            --keep-until-expiring --non-interactive >/dev/null 2>&1 || return 1
    fi
    
    local cert_path="${CERT_DIR}/live/${target}/fullchain.pem"
    local key_path="${CERT_DIR}/live/${target}/privkey.pem"
    
    if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
        log_error "Сертификат не найден после запроса"
        return 1
    fi
    
    log_info "✅ Сертификат получен: $cert_path"
    return 0
}

setup_autorenew() {
    log_info "⏰ Настройка автообновления сертификатов..."
    
    cat > "$CRON_FILE" << 'EOF'
# Автообновление TLS-сертификатов для mtg-proxy
0 3 * * * root /usr/bin/certbot renew --quiet --post-hook "docker restart mtg-proxy 2>/dev/null || true"
EOF
    
    chmod 644 "$CRON_FILE"
    
    ensure_command "cron" "cron"
    systemctl enable --now cron >/dev/null 2>&1 || true
    
    log_info "✅ Автообновление настроено (ежедневно в 03:00)"
}

generate_config() {
    local target="$1"
    local secret="$2"
    
    log_info "⚙️ Создание конфигурации..."
    mkdir -p "$PROXY_DIR"
    
    cat > "$CONFIG_FILE" << EOF
# MTProto Proxy Configuration (9seconds/mtg)
# Generated: $(date -Iseconds)

secret = "${secret}"
bind-to = "0.0.0.0:443"

# TLS-сертификаты (реальные, не самоподписные)
tls-certificate = "${CERT_DIR}/live/${target}/fullchain.pem"
tls-private-key = "${CERT_DIR}/live/${target}/privkey.pem"

# Опционально: тег для статистики
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
    
    if ! docker compose up -d --quiet-pull 2>/dev/null; then
        docker-compose -f "$COMPOSE_FILE" up -d --quiet-pull 2>/dev/null || docker run -d \
            --name "$CONTAINER_NAME" \
            --restart unless-stopped \
            --network host \
            -v "${CONFIG_FILE}:/config.toml:ro" \
            -v "${CERT_DIR}:/etc/letsencrypt:ro" \
            "$IMAGE_TAG"
    fi
    
    sleep 3
    
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "✅ Прокси запущен"
        return 0
    else
        log_error "Не удалось запустить контейнер. Проверьте логи: docker logs $CONTAINER_NAME"
        return 1
    fi
}

# ================= ИНТЕРАКТИВНЫЙ ВЫБОР =================

prompt_target() {
    echo -e "\n${YELLOW}🔹 Выберите тип идентификатора для прокси:${NC}"
    echo "  1) Использовать домен (например, proxy.example.com)"
    echo "  2) Использовать публичный IP-адрес"
    echo -n "Ваш выбор [1/2]: "
    read -r CHOICE
    
    case "$CHOICE" in
        1)
            echo -e "\n${YELLOW}📋 Введите ваш домен:${NC}"
            echo -n "> "
            read -r TARGET
            if ! is_valid_domain "$TARGET"; then
                log_error "Некорректный формат домена"
                exit 1
            fi
            MODE="domain"
            ;;
        2)
            # Автоопределение внешнего IP
            log_info "🔍 Определение публичного IP-адреса..."
            DETECTED_IP=$(get_public_ip)
            
            if [[ -z "$DETECTED_IP" ]]; then
                log_error "Не удалось автоматически определить внешний IP"
                echo -e "\n${YELLOW}📋 Введите ваш публичный IP-адрес вручную:${NC}"
                echo -n "> "
                read -r TARGET
            else
                echo -e "\n${GREEN}✅ Обнаружен внешний IP: ${DETECTED_IP}${NC}"
                echo -e "${YELLOW}📋 Нажмите Enter для использования обнаруженного IP, или введите другой:${NC}"
                echo -n "> "
                read -r USER_INPUT
                if [[ -z "$USER_INPUT" ]]; then
                    TARGET="$DETECTED_IP"
                    log_info "Будет использован обнаруженный IP: $TARGET"
                else
                    TARGET="$USER_INPUT"
                    log_info "Будет использован указанный IP: $TARGET"
                fi
            fi
            
            if ! is_valid_public_ip "$TARGET"; then
                log_error "Некорректный или приватный IP-адрес: $TARGET"
                exit 1
            fi
            MODE="ip"
            ;;
        *)
            log_error "Неверный выбор. Перезапустите скрипт."
            exit 1
            ;;
    esac
}

# ================= ОСНОВНАЯ ЛОГИКА =================

# Обработка параметров
if [[ "${1:-}" == "--show-key" ]]; then
    show_key
elif [[ "${1:-}" == "--renew-key" ]]; then
    renew_key
fi

# Режим установки
log_info "🔧 Режим установки: настройка нового MTProto-прокси"

# 0. Установка базовых зависимостей
install_prerequisites

# 1. Интерактивный выбор: домен или IP
prompt_target

# 2. Установка Docker
install_docker

# 3. (Опционально) Проверка резолвинга для домена — только информативно
if [[ "$MODE" == "domain" ]]; then
    if ! domain_resolves "$TARGET"; then
        log_warn "⚠️ Домен '$TARGET' пока не резолвится. Убедитесь, что A-запись обновилась."
        log_warn "   Это нормально сразу после изменения DNS. Продолжаем установку..."
    fi
fi

# 4. Получение реального сертификата
if ! get_certificate "$TARGET" "$([[ "$MODE" == "ip" ]] && echo true || echo false)"; then
    log_error "❌ Не удалось получить реальный TLS-сертификат."
    echo -e "\n${YELLOW}Возможные причины:${NC}"
    echo "  • Порт 80 закрыт фаерволом или провайдером"
    echo "  • DNS-запись ещё не обновилась (для домена)"
    echo "  • Лимит запросов Let's Encrypt"
    echo -e "\n${YELLOW}Проверьте:${NC}"
    echo "  • ss -tlnp | grep :80  (порт должен быть свободен или слушаться)"
    echo "  • Для домена: A-запись должна указывать на $(curl -s ifconfig.me 2>/dev/null || echo 'ваш IP')"
    echo "  • Повторите запуск через 10-15 минут"
    exit 1
fi

# 5. Генерация ee-секрета
log_info "🔑 Генерация ee-секрета (MTProto 2.0 + Fake TLS)..."
SECRET=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$TARGET" 2>/dev/null | tr -d '\r\n')

if [[ ! "$SECRET" =~ ^ee[0-9a-f]{64}$ ]]; then
    log_error "Не удалось сгенерировать корректный ee-секрет"
    exit 1
fi

# 6. Сохранение домена/IP в конфиг для будущего использования (show-key, renew-key)
mkdir -p "$PROXY_DIR"
echo "server = \"$TARGET\"" >> "$CONFIG_FILE"

# 7. Создание конфигурации и запуск
generate_config "$TARGET" "$SECRET"
setup_autorenew
start_proxy

# 8. Финальный вывод
echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ MTProto-прокси успешно установлен!    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}🔑 Ваш ee-секрет для Telegram:${NC}"
echo "┌─────────────────────────────────────────┐"
echo "│ ${SECRET}"
echo "└─────────────────────────────────────────┘"

echo -e "\n${YELLOW}📱 Настройки для официального Telegram:${NC}"
echo "  • Тип прокси: ${GREEN}MTProto${NC}"
echo "  • Сервер:     ${GREEN}${TARGET}${NC}"
echo "  • Порт:       ${GREEN}443${NC}"
echo "  • Секрет:     ${GREEN}${SECRET}${NC}"

echo -e "\n${YELLOW}🛠️ Управление:${NC}"
echo "  • Показать ключ:      ${GREEN}$0 --show-key${NC}"
echo "  • Ротация ключа:      ${GREEN}$0 --renew-key${NC}"
echo "  • Просмотр логов:     ${GREEN}docker logs -f $CONTAINER_NAME${NC}"
echo "  • Перезапуск:         ${GREEN}cd $PROXY_DIR && docker compose restart${NC}"

echo -e "\n${YELLOW}🔒 Важные заметки:${NC}"
echo "  • Сертификат автообновляется ежедневно в 03:00"
echo "  • При обновлении сертификата контейнер перезапускается автоматически"
echo "  • Для максимальной скрытности: используйте только порт 443 и ee-секрет"
echo "  • Рекомендуется менять секрет каждые 30-45 дней: $0 --renew-key"

echo -e "\n${GREEN}🎉 Готово! Подключайтесь в Telegram.${NC}\n"
