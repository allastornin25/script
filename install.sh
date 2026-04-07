#!/bin/bash
#
# install-mtg-ee.sh — Установка MTProto-прокси 9seconds/mtg с ee-секретом и реальным TLS-сертификатом
# Версия: 2.1 (исправлена проверка пакетов, сертификатов и генерация секрета)
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

# Цвета для вывода
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2; }

# Проверка root
if [[ $EUID -ne 0 ]]; then
    log_error "Скрипт должен запускаться от root. Используйте: sudo $0"
    exit 1
fi

# Инициализация лог-файла
mkdir -p "$(dirname "$LOG_FILE")"
echo "=== Установка запущена: $(date -Iseconds) ===" > "$LOG_FILE"

# ================= УТИЛИТЫ =================

# Проверка, установлен ли пакет через dpkg
is_package_installed() {
    dpkg -l "$1" &>/dev/null | grep -q "^ii"
}

# Установка пакета, если не установлен
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

# Проверка команды (для утилит, которые устанавливают исполняемые файлы)
ensure_command() {
    local cmd="$1"
    local package="${2:-$cmd}"
    
    if command -v "$cmd" &>/dev/null; then
        return 0
    fi
    
    # Пытаемся установить пакет
    ensure_package "$package"
    
    # Проверяем снова
    if command -v "$cmd" &>/dev/null; then
        return 0
    fi
    return 1
}

# Установка базовых зависимостей
install_prerequisites() {
    log_info "📦 Проверка и установка базовых зависимостей..."
    
    # Обновляем кэш пакетов один раз
    apt-get update -qq >/dev/null 2>&1 || true
    
    # Пакеты, которые не устанавливают команды (проверяем через dpkg)
    local config_packages=("ca-certificates" "apt-transport-https" "gnupg")
    for pkg in "${config_packages[@]}"; do
        ensure_package "$pkg" || true
    done
    
    # Утилиты с исполняемыми файлами
    ensure_command "curl" "curl" || true
    ensure_command "getent" "libc-bin" || true
    ensure_command "cron" "cron" || true
    ensure_command "openssl" "openssl" || true
    
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
    [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1
    [[ "$ip" =~ ^(127\.|0\.|10\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[0-1][0-9]\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.18\.|198\.19\.|198\.51\.100\.|203\.0\.113\.|22[4-9]\.|23[0-9]\.) ]] && return 1
    return 0
}

# Валидация домена
is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

# Проверка, резолвится ли домен
domain_resolves() {
    getent hosts "$1" >/dev/null 2>&1
}

# Проверка сертификата: существует и валиден ещё минимум 30 дней
is_cert_valid() {
    local target="$1"
    local cert_path="${CERT_DIR}/live/${target}/fullchain.pem"
    
    # Файл существует?
    [[ ! -f "$cert_path" ]] && return 1
    
    # Валиден ли ещё 30 дней? (2592000 секунд)
    if openssl x509 -checkend 2592000 -noout -in "$cert_path" >/dev/null 2>&1; then
        local expiry
        expiry=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
        log_info "✅ Сертификат для '$target' валиден до: $expiry"
        return 0
    fi
    
    log_warn "⚠️ Сертификат для '$target' истекает менее чем через 30 дней или невалиден"
    return 1
}

# Проверка Docker
is_docker_installed() {
    # Проверяем наличие docker и docker compose
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        # Проверяем, что docker compose тоже доступен
        if command -v docker-compose &>/dev/null || docker compose version &>/dev/null 2>&1; then
            return 0
        fi
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
    
    # Генерируем новый секрет с обработкой вывода
    local new_secret
    new_secret=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$server" 2>/dev/null | tr -d '\r\n\t ' | head -c 66)
    
    # Валидация: ee + 64 hex символа = 66 символов всего
    if [[ ! "$new_secret" =~ ^ee[0-9a-f]{64}$ ]]; then
        log_error "Не удалось сгенерировать корректный ee-секрет (получено: ${new_secret:0:20}...)"
        log_error "Попробуйте вручную: docker run --rm $IMAGE_TAG generate-secret --hex $server"
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
    if is_docker_installed; then
        log_info "✅ Docker и Docker Compose уже установлены"
        return 0
    fi
    
    log_info "📦 Установка Docker..."
    
    # Устанавливаем зависимости
    ensure_package "curl"
    ensure_package "gnupg"
    ensure_package "apt-transport-https"
    ensure_package "ca-certificates"
    
    # Добавляем репозиторий Docker
    install -m 0755 -d /etc/apt/keyrings 2>/dev/null || true
    curl -fsSL https://download.docker.com/linux/debian/gpg 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
    chmod a+r /etc/apt/keyrings/docker.gpg 2>/dev/null || true
    
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    
    systemctl enable --now docker >/dev/null 2>&1 || true
    
    # Проверяем установку
    if is_docker_installed; then
        log_info "✅ Docker установлен успешно"
        return 0
    else
        log_error "Не удалось завершить установку Docker"
        return 1
    fi
}

get_certificate() {
    local target="$1"
    local is_ip="$2"
    
    # Проверяем, есть ли валидный сертификат
    if is_cert_valid "$target"; then
        log_info "✅ Сертификат уже существует и валиден — пропускаем запрос"
        return 0
    fi
    
    log_info "🔐 Запрос реального TLS-сертификата для: $target"
    
    # Устанавливаем certbot если нужно
    if ! command -v certbot &>/dev/null; then
        log_info "📦 Установка certbot..."
        # Пробуем разные методы установки
        if apt-get install -y -qq certbot >/dev/null 2>&1; then
            :
        elif command -v snap &>/dev/null; then
            snap install core >/dev/null 2>&1 || true
            snap install --classic certbot >/dev/null 2>&1 || true
            ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
        else
            log_error "Не удалось установить certbot"
            return 1
        fi
    fi
    
    local challenge_flag="--standalone --preferred-challenges http"
    
    log_info "🔄 Запрос сертификата через Let's Encrypt..."
    
    # Останавливаем возможные веб-серверы на порту 80
    local stopped_services=()
    for svc in nginx apache2 lighttpd caddy; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && stopped_services+=("$svc")
        fi
    done
    
    local cert_success=false
    if [[ "$is_ip" == "true" ]]; then
        certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@${target}.local" \
            --ip-addresses "$target" \
            --keep-until-expiring --non-interactive >/dev/null 2>&1 && cert_success=true
    else
        certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@$target" \
            -d "$target" \
            --keep-until-expiring --non-interactive >/dev/null 2>&1 && cert_success=true
    fi
    
    # Запускаем остановленные сервисы обратно
    for svc in "${stopped_services[@]}"; do
        systemctl start "$svc" 2>/dev/null || true
    done
    
    if [[ "$cert_success" != "true" ]]; then
        log_error "Не удалось получить сертификат через Let's Encrypt"
        return 1
    fi
    
    local cert_path="${CERT_DIR}/live/${target}/fullchain.pem"
    local key_path="${CERT_DIR}/live/${target}/privkey.pem"
    
    if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
        log_error "Сертификат не найден после успешного запроса"
        return 1
    fi
    
    log_info "✅ Сертификат получен: $cert_path"
    return 0
}

setup_autorenew() {
    # Проверяем, есть ли уже задача
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
    
    # Сохраняем server для будущих операций
    echo "# Server identifier" > "${PROXY_DIR}/.server"
    echo "$target" >> "${PROXY_DIR}/.server"
    
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
    
    # Права на сертификаты
    chmod 644 "${CERT_DIR}/live/"*/fullchain.pem 2>/dev/null || true
    chmod 600 "${CERT_DIR}/live/"*/privkey.pem 2>/dev/null || true
    
    # Определяем, какая команда compose доступна
    local compose_cmd="docker compose"
    if ! $compose_cmd version &>/dev/null; then
        compose_cmd="docker-compose"
    fi
    
    if ! $compose_cmd -f "$COMPOSE_FILE" up -d --quiet-pull 2>/dev/null; then
        # Fallback: прямой запуск docker run
        docker run -d \
            --name "$CONTAINER_NAME" \
            --restart unless-stopped \
            --network host \
            -v "${CONFIG_FILE}:/config.toml:ro" \
            -v "${CERT_DIR}:/etc/letsencrypt:ro" \
            "$IMAGE_TAG" 2>/dev/null
    fi
    
    sleep 3
    
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "✅ Прокси запущен"
        return 0
    else
        log_error "Не удалось запустить контейнер"
        log_error "Проверьте логи: docker logs $CONTAINER_NAME"
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
install_docker || exit 1

# 3. Проверка резолвинга для домена (информативно)
if [[ "$MODE" == "domain" ]]; then
    if ! domain_resolves "$TARGET"; then
        log_warn "⚠️ Домен '$TARGET' пока не резолвится — это нормально при свежей DNS-записи"
    fi
fi

# 4. Получение/проверка сертификата
if ! get_certificate "$TARGET" "$([[ "$MODE" == "ip" ]] && echo true || echo false)"; then
    log_error "❌ Не удалось получить реальный TLS-сертификат."
    echo -e "\n${YELLOW}Возможные причины:${NC}"
    echo "  • Порт 80 закрыт фаерволом или провайдером"
    echo "  • DNS-запись ещё не обновилась (для домена)"
    echo "  • Лимит запросов Let's Encrypt"
    echo -e "\n${YELLOW}Проверьте:${NC}"
    echo "  • ss -tlnp | grep :80"
    echo "  • Для домена: A-запись должна указывать на $(curl -s ifconfig.me 2>/dev/null || echo 'ваш IP')"
    echo "  • Логи: tail -50 /var/log/letsencrypt/letsencrypt.log"
    exit 1
fi

# 5. Генерация ee-секрета
log_info "🔑 Генерация ee-секрета (MTProto 2.0 + Fake TLS)..."
SECRET=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$TARGET" 2>/dev/null | tr -d '\r\n\t ' | head -c 66)

# Валидация секрета: ee + ровно 64 hex-символа
if [[ ! "$SECRET" =~ ^ee[0-9a-f]{64}$ ]]; then
    log_error "Не удалось сгенерировать корректный ee-секрет"
    log_error "Получено: '${SECRET}' (длина: ${#SECRET})"
    log_error "Попробуйте вручную и проверьте вывод:"
    log_error "  docker run --rm $IMAGE_TAG generate-secret --hex $TARGET"
    exit 1
fi

# 6. Создание конфигурации и запуск
generate_config "$TARGET" "$SECRET"
setup_autorenew
start_proxy

# 7. Финальный вывод
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
echo "  • Лог установки:      ${GREEN}tail -f $LOG_FILE${NC}"

echo -e "\n${YELLOW}🔒 Важные заметки:${NC}"
echo "  • Сертификат автообновляется ежедневно в 03:00"
echo "  • При обновлении сертификата контейнер перезапускается автоматически"
echo "  • Для максимальной скрытности: используйте только порт 443 и ee-секрет"
echo "  • Рекомендуется менять секрет каждые 30-45 дней: $0 --renew-key"

echo -e "\n${GREEN}🎉 Готово! Подключайтесь в Telegram.${NC}\n"
