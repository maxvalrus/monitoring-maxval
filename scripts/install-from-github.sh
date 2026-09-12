#!/usr/bin/env bash
# Install a new Monitoring Maxval instance from the private GitHub repository.
#
# The script deliberately keeps the GitHub token in memory only.  It never places
# it in the origin URL, .git/config, .env, Docker environment or shell history.

set -Eeuo pipefail

readonly DEFAULT_REPOSITORY="https://github.com/maxvalrus/monitoring-maxval.git"
readonly DEFAULT_REF="main"
readonly DEFAULT_INSTALL_DIR="/opt/monitoring-maxval"

github_token="${MONITORING_GITHUB_TOKEN:-}"
git_askpass=""
staging_dir=""

cleanup() {
    [ -n "$git_askpass" ] && rm -f "$git_askpass"
    [ -n "$staging_dir" ] && rm -rf "$staging_dir"
    unset MONITORING_GITHUB_TOKEN github_token
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

generate_secret() {
    openssl rand -hex "$1"
}

setup_git_auth() {
    if [ -z "$github_token" ]; then
        read -r -s -p "GitHub token (Contents: Read, ввод не отображается): " github_token
        printf '\n'
    fi
    [ -n "$github_token" ] || fail "Для приватного репозитория нужен GitHub token с правом Contents: Read."

    git_askpass="$(mktemp "${TMPDIR:-/tmp}/monitoring-maxval-git-askpass.XXXXXX")"
    chmod 700 "$git_askpass"
    printf '%s\n' '#!/bin/sh' \
        'case "$1" in' \
        '  *Username*) printf "%s" "x-access-token" ;;' \
        '  *) printf "%s" "$MONITORING_GITHUB_TOKEN" ;;' \
        'esac' > "$git_askpass"
    export MONITORING_GITHUB_TOKEN="$github_token"
    export GIT_ASKPASS="$git_askpass"
    export GIT_TERMINAL_PROMPT=0
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
    require_command git 'Установите Git и повторите запуск.'
    require_command curl 'Установите curl и повторите запуск.'
    require_command openssl 'Установите openssl и повторите запуск.'
    require_command docker 'Установите Docker Engine и Docker Compose v2, затем повторите запуск.'
    docker compose version >/dev/null 2>&1 || fail 'Нужен Docker Compose v2 (команда: docker compose).'

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
    setup_git_auth
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
