#!/usr/bin/env bash
# Install a new Monitoring Maxval instance from the private GitHub repository.
#
set -Eeuo pipefail

readonly DEFAULT_REPOSITORY="https://github.com/maxvalrus/monitoring-maxval.git"
readonly DEFAULT_REF="main"
readonly DEFAULT_INSTALL_DIR="/opt/monitoring-maxval"

staging_dir=""

cleanup() {
    [ -n "$staging_dir" ] && rm -rf "$staging_dir"
}
trap cleanup EXIT

fail() {
    printf 'Ошибка: %s\n' "$*" >&2
    exit 1
}

run_root() {
    if [ "${EUID}" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Не найдена команда $1. $2"
}

docker_compose_ready() {
    command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1
}

prompt_value() {
    local prompt="$1"
    local default_value="$2"
    local value
    read -r -p "$prompt [$default_value]: " value
    printf '%s' "${value:-$default_value}"
}

confirm() {
    local prompt="$1"
    local answer
    read -r -p "$prompt [y/N]: " answer
    [[ "$answer" =~ ^([yY]|[yY][eE][sS]|[дД]|[дД][аА])$ ]]
}

confirm_default_yes() {
    local prompt="$1"
    local answer
    read -r -p "$prompt [Y/n]: " answer
    [[ -z "$answer" || "$answer" =~ ^([yY]|[yY][eE][sS]|[дД]|[дД][аА])$ ]]
}

install_host_dependencies() {
    if docker_compose_ready \
        && command -v git >/dev/null 2>&1 \
        && command -v curl >/dev/null 2>&1 \
        && command -v openssl >/dev/null 2>&1; then
        return
    fi

    [ -r /etc/os-release ] || fail 'Поддерживаются Debian, Ubuntu и Linux Mint с apt; ОС определить не удалось.'
    # shellcheck disable=SC1091
    . /etc/os-release
    local docker_distribution
    case "${ID:-}" in
        debian|ubuntu)
            docker_distribution="$ID"
            ;;
        linuxmint)
            docker_distribution='ubuntu'
            ;;
        *) fail "Автоматическая установка пока поддерживает Debian/Ubuntu/Linux Mint, обнаружена: ${PRETTY_NAME:-неизвестная ОС}." ;;
    esac

    printf '%s\n' 'Не найдены все необходимые компоненты хоста.'
    printf '%s\n' 'Будут установлены Git, curl, openssl, Docker Engine и Docker Compose v2 из официального репозитория Docker.'
    confirm_default_yes 'Установить зависимости автоматически?' || fail 'Установка отменена пользователем.'

    local package
    for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
        if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -qx installed; then
            fail "Обнаружен конфликтующий пакет $package. Скрипт не удаляет системные пакеты автоматически. Удалите его вручную или установите Docker Compose v2 отдельно."
        fi
    done

    run_root apt-get update
    run_root apt-get install -y ca-certificates curl git gnupg openssl
    run_root install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${docker_distribution}/gpg" \
        | run_root gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    run_root chmod a+r /etc/apt/keyrings/docker.gpg

    local architecture codename
    architecture="$(dpkg --print-architecture)"
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
    [ -n "$codename" ] || fail 'Не удалось определить codename Debian/Ubuntu.'
    printf '%s\n' \
        "deb [arch=${architecture} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${docker_distribution} ${codename} stable" \
        | run_root tee /etc/apt/sources.list.d/docker.list >/dev/null
    run_root apt-get update
    run_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    run_root systemctl enable --now docker
    run_root docker compose version >/dev/null || fail 'Docker Compose v2 не запустился после установки.'
}

generate_secret() {
    openssl rand -hex "$1"
}

create_env_file() {
    local install_dir="$1"
    local allowed_hosts="$2"
    local database_password secret_key
    database_password="$(generate_secret 32)"
    secret_key="$(generate_secret 48)"

    umask 077
    printf '%s\n' \
        'MONITORING_ENVIRONMENT=production' \
        "MONITORING_DATABASE_URL=postgresql+psycopg://monitoring:${database_password}@db:5432/monitoring" \
        "MONITORING_SECRET_KEY=${secret_key}" \
        "MONITORING_ALLOWED_HOSTS=${allowed_hosts}" \
        'MONITORING_SCHEDULER_ENABLED=true' \
        'MONITORING_SESSION_COOKIE_SECURE=false' \
        'POSTGRES_DB=monitoring' \
        'POSTGRES_USER=monitoring' \
        "POSTGRES_PASSWORD=${database_password}" \
        'POSTGRES_VOLUME_NAME=monitoring-maxval_postgres_data' \
        'BACKUP_VOLUME_NAME=monitoring-maxval_backup_data' > "$install_dir/.env"
    chmod 600 "$install_dir/.env"
}

wait_for_ready() {
    local install_dir="$1"
    local attempt
    for attempt in $(seq 1 60); do
        if curl --fail --silent --show-error http://127.0.0.1:8000/health/ready >/dev/null; then
            return 0
        fi
        sleep 2
    done
    run_root docker compose -f "$install_dir/compose.yaml" logs --tail=120 app db caddy >&2 || true
    fail "Приложение не стало готово за 120 секунд. Журналы показаны выше."
}

main() {
    install_host_dependencies
    require_command git 'Не удалось установить Git.'
    require_command curl 'Не удалось установить curl.'
    require_command openssl 'Не удалось установить openssl.'
    require_command docker 'Не удалось установить Docker Engine.'
    docker compose version >/dev/null 2>&1 || fail 'Не удалось установить Docker Compose v2.'

    printf '%s\n' 'Установка Monitoring Maxval из GitHub.'
    printf '%s\n' 'Будет создана новая установка. Для обновления существующей используйте scripts/update-from-github.sh.'
    local install_dir allowed_hosts owner group
    install_dir="$(prompt_value 'Каталог установки' "$DEFAULT_INSTALL_DIR")"
    [ "${install_dir#/}" != "$install_dir" ] || fail 'Каталог установки должен быть абсолютным путём.'
    [ "$install_dir" != '/' ] || fail 'Корневой каталог нельзя использовать как каталог установки.'
    install_dir="$(readlink -m "$install_dir")"

    if [ -e "$install_dir" ] && [ -n "$(find "$install_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        fail "Каталог $install_dir уже содержит файлы. Для сохранения данных используйте update-from-github.sh."
    fi

    if run_root docker volume inspect monitoring-maxval_postgres_data >/dev/null 2>&1; then
        fail 'Найден существующий PostgreSQL volume monitoring-maxval_postgres_data. Установка остановлена, чтобы не подключить старые данные как новую систему.'
    fi

    allowed_hosts="$(prompt_value 'Разрешённые Host (IP/DNS через запятую; * только для доверенной сети)' '*')"
    [[ "$allowed_hosts" =~ ^[A-Za-z0-9.,:_*_-]+$ ]] || fail 'MONITORING_ALLOWED_HOSTS содержит недопустимые символы.'

    owner="$(id -un)"
    group="$(id -gn)"
    staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/monitoring-maxval-install.XXXXXX")"
    printf '%s\n' 'Скачивание исходного кода…'
    git clone --depth 1 --branch "$DEFAULT_REF" "$DEFAULT_REPOSITORY" "$staging_dir/repository"

    run_root mkdir -p "$(dirname "$install_dir")"
    if [ -d "$install_dir" ]; then
        run_root rmdir "$install_dir"
    fi
    run_root mv "$staging_dir/repository" "$install_dir"
    run_root chown -R "$owner:$group" "$install_dir"
    create_env_file "$install_dir" "$allowed_hosts"
    install -m 600 "$install_dir/caddy/Caddyfile.example" "$install_dir/caddy/Caddyfile"
    mkdir -p "$install_dir/tls"
    chmod 700 "$install_dir/tls"

    printf '%s\n' 'Проверка Docker Compose и запуск контейнеров…'
    (
        cd "$install_dir"
        run_root docker compose config >/dev/null
        run_root docker compose up -d --build
    )
    wait_for_ready "$install_dir"

    if confirm 'Загрузить демонстрационные данные?'; then
        run_root docker compose -f "$install_dir/compose.yaml" exec -T app python scripts/seed_demo.py
    fi

    printf '\n%s\n' 'Monitoring Maxval установлен и готов к работе.'
    printf '%s\n' "Откройте: http://$(hostname -I | awk '{print $1}'):8000/"
    printf '%s\n' 'Первый вход: admin / admin. Сразу смените пароль администратора.'
    printf '%s\n' "Рабочий каталог: $install_dir"
    printf '%s\n' 'GitHub token не сохранён. Для обновления позже будет нужен новый токен Contents: Read.'
}

main "$@"
