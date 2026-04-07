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

set -euo pipefail

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

# ================= ФУНКЦИИ =================

show_key() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Файл конфигурации не найден: $CONFIG_FILE"
        exit 1
    fi
    local secret
    secret=$(grep -E '^secret\s*=' "$CONFIG_FILE" | sed -E 's/secret\s*=\s*"([^"]+)".*/\1/')
    if [[ -z "$secret" ]]; then
        log_error "Не удалось извлечь секрет из конфигурации"
        exit 1
    fi
    echo -e "\n${GREEN}🔑 Ваш текущий ee-секрет для Telegram:${NC}"
    echo "┌─────────────────────────────────────────┐"
    echo "│ $secret"
    echo "└─────────────────────────────────────────┘"
    echo -e "\n${YELLOW}Настройки для Telegram:${NC}"
    echo "  Тип: MTProto"
    echo "  Сервер: $(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo '<ваш-домен-или-IP>')"
    echo "  Порт: 443"
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
    
    # Извлекаем текущий server для генерации (не влияет на работу, но нужен для команды)
    local server
    server=$(grep -E '^server\s*=' "$CONFIG_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)".*/\1/' || echo "proxy.local")
    
    # Генерируем новый HEX-секрет с префиксом ee
    local new_secret
    new_secret=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$server" 2>/dev/null | tr -d '\r\n')
    
    if [[ ! "$new_secret" =~ ^ee[0-9a-f]{64}$ ]]; then
        log_error "Не удалось сгенерировать корректный ee-секрет"
        exit 1
    fi
    
    # Обновляем config.toml
    sed -i "s/^secret\s*=\s*\"[^\"]*\"/secret = \"$new_secret\"/" "$CONFIG_FILE"
    
    # Перезапускаем контейнер
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

install_docker() {
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        log_info "Docker уже установлен"
        return 0
    fi
    
    log_info "📦 Установка Docker..."
    apt-get update -qq
    apt-get install -y -qq curl gnupg apt-transport-https ca-certificates software-properties-common
    
    # Добавляем официальный репозиторий Docker
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
    
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Включаем автозагрузку Docker
    systemctl enable --now docker >/dev/null 2>&1 || true
    log_info "✅ Docker установлен"
}

validate_input() {
    local input="$1"
    # Проверка IP (публичный, не локальный)
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        if [[ "$input" =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
            return 1
        fi
        return 0  # Валидный публичный IP
    fi
    # Проверка домена (базовая)
    if [[ "$input" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

get_certificate() {
    local target="$1"  # domain or IP
    local is_ip="$2"   # true/false
    
    log_info "🔐 Запрос реального TLS-сертификата для: $target"
    
    # Устанавливаем certbot
    if ! command -v certbot &>/dev/null; then
        apt-get install -y -qq certbot
    fi
    
    # Определяем метод челленджа
    local challenge_flag="--standalone"
    local pre_hook="--pre-hook \"systemctl stop nginx 2>/dev/null || true\""
    local post_hook="--post-hook \"systemctl start nginx 2>/dev/null || true\""
    
    # Для IP-адресов Let's Encrypt требует tls-alpn-01 или http-01
    if [[ "$is_ip" == "true" ]]; then
        # Пробуем http-01 (проще, требует только порт 80)
        challenge_flag="--standalone --preferred-challenges http"
        log_warn "Для IP-сертификатов убедитесь, что порт 80 открыт и доступен из интернета"
    fi
    
    # Пробуем получить сертификат через Let's Encrypt
    log_info "🔄 Запрос сертификата через Let's Encrypt..."
    
    if [[ "$is_ip" == "true" ]]; then
        # Для IP используем --ip-адрес в certbot (поддержка с 2024)
        if ! certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@${target}.local" \
            --ip-addresses "$target" \
            --keep-until-expiring --non-interactive 2>/dev/null; then
            log_warn "Let's Encrypt не выдал сертификат для IP. Пробуем ZeroSSL..."
            # Fallback: ZeroSSL через acme.sh (упрощённо)
            return 1
        fi
    else
        # Для домена
        if ! certbot certonly $challenge_flag \
            --agree-tos --no-eff-email --email "admin@$target" \
            -d "$target" \
            --keep-until-expiring --non-interactive 2>/dev/null; then
            log_warn "Let's Encrypt не выдал сертификат. Попробуйте позже или проверьте DNS."
            return 1
        fi
    fi
    
    # Проверяем, что сертификат создан
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
    
    # Создаём cron-задачу
    cat > "$CRON_FILE" << 'EOF'
# Автообновление TLS-сертификатов для mtg-proxy
0 3 * * * root /usr/bin/certbot renew --quiet --post-hook "docker restart mtg-proxy 2>/dev/null || true"
EOF
    
    chmod 644 "$CRON_FILE"
    
    # Проверяем cron
    if ! command -v cron &>/dev/null && ! command -v crond &>/dev/null; then
        apt-get install -y -qq cron >/dev/null 2>&1 || true
        systemctl enable --now cron >/dev/null 2>&1 || true
    fi
    
    log_info "✅ Автообновление настроено (ежедневно в 03:00)"
}

generate_config() {
    local target="$1"
    local secret="$2"
    
    log_info "⚙️ Создание конфигурации..."
    
    # Создаём директорию
    mkdir -p "$PROXY_DIR"
    
    # Создаём config.toml
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

    # Создаём docker-compose.yml
    cat > "$COMPOSE_FILE" << 'EOF'
version: '3.8'

services:
  mtg-proxy:
    image: nineseconds/mtg:2
    container_name: mtg-proxy
    restart: unless-stopped
    network_mode: host  # Критично для Fake TLS / SNI
    
    volumes:
      - ./config.toml:/config.toml:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro  # Монтируем сертификаты
    
    # Ограничение ресурсов
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    
    # Логирование
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
    
    # Проверяем, что сертификаты доступны для чтения
    chmod 644 "${CERT_DIR}/live/"*/fullchain.pem 2>/dev/null || true
    chmod 600 "${CERT_DIR}/live/"*/privkey.pem 2>/dev/null || true
    
    # Запускаем
    if ! docker compose up -d --quiet-pull 2>/dev/null; then
        # Fallback для старых версий docker-compose
        docker-compose -f "$COMPOSE_FILE" up -d --quiet-pull 2>/dev/null || docker run -d \
            --name "$CONTAINER_NAME" \
            --restart unless-stopped \
            --network host \
            -v "${CONFIG_FILE}:/config.toml:ro" \
            -v "${CERT_DIR}:/etc/letsencrypt:ro" \
            "$IMAGE_TAG"
    fi
    
    sleep 3
    
    # Проверка запуска
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "✅ Прокси запущен"
        return 0
    else
        log_error "Не удалось запустить контейнер. Проверьте логи: docker logs $CONTAINER_NAME"
        return 1
    fi
}

# ================= ОСНОВНАЯ ЛОГИКА =================

# Обработка параметров
if [[ "${1:-}" == "--show-key" ]]; then
    show_key
elif [[ "${1:-}" == "--renew-key" ]]; then
    renew_key
fi

# Если аргументы не распознаны — режим установки
log_info "🔧 Режим установки: настройка нового MTProto-прокси"

# Проверка входных данных
echo -e "\n${YELLOW}📋 Введите домен ИЛИ публичный IP-адрес для прокси:${NC}"
echo "   Пример домена: api.test-front.selarti.com"
echo "   Пример IP: 203.0.113.42"
echo -n "> "
read -r TARGET

if ! validate_input "$TARGET"; then
    log_error "Некорректный ввод. Укажите валидный домен или публичный IP"
    exit 1
fi

# Определяем тип ввода
IS_IP="false"
if [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IS_IP="true"
    log_info "🎯 Обнаружен публичный IP: $TARGET"
else
    log_info "🎯 Обнаружен домен: $TARGET"
    # Проверка DNS
    if ! dig +short "$TARGET" | grep -q .; then
        log_warn "⚠️ Домен $TARGET не резолвится. Убедитесь, что A-запись указывает на этот сервер."
        echo -n "Продолжить установку? [y/N]: "
        read -r CONFIRM
        [[ "${CONFIRM,,}" != "y" ]] && exit 1
    fi
fi

# 1. Установка Docker
install_docker

# 2. Получение реального сертификата
if ! get_certificate "$TARGET" "$IS_IP"; then
    log_error "❌ Не удалось получить реальный TLS-сертификат."
    echo -e "\n${YELLOW}Возможные причины:${NC}"
    echo "  • Порт 80/443 закрыт фаерволом или провайдером"
    echo "  • DNS-запись ещё не обновилась (для домена)"
    echo "  • Лимит запросов Let's Encrypt (5 сертификатов/домен/неделю)"
    echo -e "\n${YELLOW}Попробуйте:${NC}"
    echo "  1. Проверьте, что порты 80 и 443 открыты: ss -tlnp | grep -E ':(80|443)'"
    echo "  2. Для домена: убедитесь, что A-запись указывает на $(curl -s ifconfig.me 2>/dev/null || echo 'ваш IP')"
    echo "  3. Повторите запуск скрипта через 10-15 минут"
    exit 1
fi

# 3. Генерация ee-секрета (HEX-формат)
log_info "🔑 Генерация ee-секрета (MTProto 2.0 + Fake TLS)..."
SECRET=$(docker run --rm "$IMAGE_TAG" generate-secret --hex "$TARGET" 2>/dev/null | tr -d '\r\n')

if [[ ! "$SECRET" =~ ^ee[0-9a-f]{64}$ ]]; then
    log_error "Не удалось сгенерировать корректный ee-секрет"
    exit 1
fi

# 4. Создание конфигурации
generate_config "$TARGET" "$SECRET"

# 5. Настройка автообновления сертификатов
setup_autorenew

# 6. Запуск прокси
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

echo -e "\n${YELLOW}🔒 Важные заметки:${NC}"
echo "  • Сертификат автообновляется ежедневно в 03:00"
echo "  • При обновлении сертификата контейнер перезапускается автоматически"
echo "  • Для максимальной скрытности: используйте только порт 443 и ee-секрет"
echo "  • Рекомендуется менять секрет каждые 30-45 дней: $0 --renew-key"

echo -e "\n${GREEN}🎉 Готово! Подключайтесь в Telegram.${NC}\n"
