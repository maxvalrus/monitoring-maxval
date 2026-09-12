#!/usr/bin/env bash
# Safely update an existing Monitoring Maxval installation from GitHub.

set -Eeuo pipefail

readonly DEFAULT_REF="main"

github_token="${MONITORING_GITHUB_TOKEN:-}"
git_askpass=""

cleanup() {
    [ -n "$git_askpass" ] && rm -f "$git_askpass"
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

confirm() {
    local prompt="$1"
    local answer
    read -r -p "$prompt [Y/n]: " answer
    [[ -z "$answer" || "$answer" =~ ^([yY]|[yY][eE][sS]|[дД]|[дД][аА])$ ]]
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

wait_for_ready() {
    local attempt
    for attempt in $(seq 1 60); do
        if curl --fail --silent --show-error http://127.0.0.1:8000/health/ready >/dev/null; then
            return 0
        fi
        sleep 2
    done
    run_root docker compose logs --tail=120 app db caddy >&2 || true
    fail "Приложение не стало готово за 120 секунд. Журналы показаны выше."
}

main() {
    local project_dir
    project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
    cd "$project_dir"

    command -v git >/dev/null 2>&1 || fail 'Не найдена команда git.'
    command -v curl >/dev/null 2>&1 || fail 'Не найдена команда curl.'
    command -v docker >/dev/null 2>&1 || fail 'Не найдена команда docker.'
    docker compose version >/dev/null 2>&1 || fail 'Нужен Docker Compose v2 (команда: docker compose).'
    [ -f .env ] || fail 'Не найден рабочий .env; обновление остановлено.'
    [ -d .git ] || fail 'Это не Git-клон Monitoring Maxval.'

    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        fail 'Есть изменения в отслеживаемых файлах. Сначала закоммитьте или отмените их; update не выполняет reset.'
    fi

    if confirm 'Создать и проверить дамп PostgreSQL перед обновлением?'; then
        run_root ./scripts/backup_database.sh
    fi

    setup_git_auth
    printf '%s\n' 'Получение обновления из GitHub…'
    git fetch --prune origin "$DEFAULT_REF"
    git merge --ff-only "origin/$DEFAULT_REF"

    run_root docker compose config >/dev/null
    run_root docker compose build app tls-manager
    run_root docker compose up -d
    run_root docker compose exec -T app alembic upgrade head
    wait_for_ready

    printf '%s\n' 'Обновление завершено. Рабочие .env, tls/, backups/ и Docker volumes сохранены.'
}

main "$@"
