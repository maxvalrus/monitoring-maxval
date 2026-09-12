#!/usr/bin/env bash
# Remove Monitoring Maxval deliberately. Run from an existing project checkout.

set -Eeuo pipefail

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
    read -r -p "$prompt [y/N]: " answer
    [[ "$answer" =~ ^([yY]|[yY][eE][sS]|[дД]|[дД][аА])$ ]]
}

confirm_phrase() {
    local prompt="$1"
    local expected="$2"
    local answer
    read -r -p "$prompt Введите «$expected»: " answer
    [ "$answer" = "$expected" ]
}

main() {
    local project_dir project_parent
    project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
    project_parent="$(dirname "$project_dir")"

    [ "$project_dir" != / ] || fail 'Нельзя удалить корневой каталог.'
    [ "$project_dir" != "$project_parent" ] || fail 'Не удалось определить безопасный каталог проекта.'
    [ -f "$project_dir/compose.yaml" ] || fail 'Не найден compose.yaml Monitoring Maxval.'
    [ -f "$project_dir/pyproject.toml" ] || fail 'Не найден pyproject.toml Monitoring Maxval.'
    grep -qx 'name: monitoring-maxval' "$project_dir/compose.yaml" \
        || fail 'Каталог не похож на проект Monitoring Maxval.'

    command -v docker >/dev/null 2>&1 || fail 'Не найдена команда docker.'
    docker compose version >/dev/null 2>&1 || fail 'Нужен Docker Compose v2.'

    printf '%s\n' 'Удаление Monitoring Maxval.'
    printf '%s\n' "Каталог проекта: $project_dir"
    printf '%s\n' 'Сначала контейнеры будут остановлены. Данные и TLS не удаляются без отдельных подтверждений.'
    confirm 'Продолжить?' || {
        printf '%s\n' 'Удаление отменено.'
        return 0
    }

    cd "$project_dir"
    if confirm 'Удалить PostgreSQL, резервные копии и служебные Docker volumes без возможности восстановления?'; then
        confirm_phrase 'Это необратимо.' 'DELETE DATA' \
            || fail 'Подтверждение удаления данных не получено.'
        run_root docker compose down --remove-orphans --volumes
        printf '%s\n' 'Контейнеры и Docker volumes Monitoring Maxval удалены.'
    else
        run_root docker compose down --remove-orphans
        printf '%s\n' 'Контейнеры остановлены; PostgreSQL и backup volumes сохранены.'
    fi

    if [ -d "$project_dir/tls" ] && confirm 'Удалить локальный каталог tls/ с сертификатами и private keys?'; then
        confirm_phrase 'Это необратимо.' 'DELETE TLS' \
            || fail 'Подтверждение удаления TLS не получено.'
        run_root rm -rf --one-file-system "$project_dir/tls"
        printf '%s\n' 'Каталог tls/ удалён.'
    else
        printf '%s\n' 'TLS-каталог сохранён.'
    fi

    if confirm "Удалить исходный каталог $project_dir?"; then
        confirm_phrase 'Это необратимо.' 'DELETE PROJECT' \
            || fail 'Подтверждение удаления каталога не получено.'
        cd "$project_parent"
        run_root rm -rf --one-file-system "$project_dir"
        printf '%s\n' 'Исходный каталог Monitoring Maxval удалён.'
    else
        printf '%s\n' "Исходный каталог сохранён: $project_dir"
    fi

    printf '%s\n' 'Удаление завершено.'
}

main "$@"
