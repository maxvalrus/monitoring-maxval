# Установка и эксплуатация Monitoring Maxval 0.8.5 на Linux

Инструкция описывает актуальную рабочую схему. История предыдущих выпусков находится
в `docs/releases/` и `CHANGELOG.md`.

## Требования

- Debian 13 или Ubuntu Server LTS;
- Docker Engine и Docker Compose v2;
- постоянный каталог `/opt/monitoring-maxval`;
- доступ из локальной сети или VPN;
- свободные TCP-порты `8000` и `443`.

Контейнеры:

- `app` — FastAPI и один встроенный планировщик;
- `db` — PostgreSQL 17;
- `caddy` — внешний HTTP/HTTPS reverse proxy;
- `tls-manager` — ограниченное управление TLS без Docker socket.

## Чистая установка

Распакуйте релиз в `/opt/monitoring-maxval`. Готовый релизный `.env` уже содержит
уникальные секреты и предназначен только для новой установки.

```bash
cd /opt/monitoring-maxval
sudo chown -R "$USER":"$USER" /opt/monitoring-maxval
chmod 600 .env
sudo docker compose config --quiet
sudo docker compose up -d --build
```

Проверка:

```bash
sudo docker compose ps
sudo docker compose logs --tail=100 app caddy tls-manager
curl --fail http://127.0.0.1:8000/health/live
curl --fail http://127.0.0.1:8000/health/ready
```

`/health/live` должен сообщить версию `0.8.5`, `/health/ready` — доступность базы.
Интерфейс открывается по адресу `http://IP-СЕРВЕРА:8000/`.

Чистая установка создаёт пользователя `admin` с паролем `admin`. После первого входа
сразу смените пароль. Демонстрационные данные добавляются только при необходимости:

```bash
sudo docker compose exec app python scripts/seed_demo.py
```

## Настройка `.env`

При установке из исходников, а не из релизного ZIP:

```bash
cd /opt/monitoring-maxval
install -m 600 env.example .env
```

Задайте случайные `POSTGRES_PASSWORD` и `MONITORING_SECRET_KEY`. Пароль в
`MONITORING_DATABASE_URL` должен совпадать с `POSTGRES_PASSWORD`.

Важные правила:

- не публиковать `.env` и не добавлять его в репозиторий;
- не менять `MONITORING_SECRET_KEY` после сохранения SMTP-пароля;
- не менять имена постоянных volumes при обновлении;
- разрешать в `MONITORING_ALLOWED_HOSTS` только используемые DNS/IP и внутренние
  health-check hostnames; маска `*` допустима лишь в доверенной сети;
- `MONITORING_SESSION_COOKIE_SECURE=false` сохраняет прямой HTTP-вход, а при HTTPS
  приложение устанавливает Secure-cookie по фактической схеме запроса через Caddy.

SMTP, часовой пояс, HTTPS и PWA Push настраиваются в интерфейсе и не требуют
перезапуска приложения.

## HTTPS

HTTP на `:8000` работает сразу и остаётся доступным, пока отдельный redirect выключен.

В «Настройки → HTTPS» администратор может:

1. загрузить PEM certificate и private key либо создать внутренний CA/TLS-кандидат;
2. дождаться статуса успешной проверки candidate;
3. включить HTTPS и применить конфигурацию;
4. проверить `https://DNS-ИЛИ-IP/`;
5. при необходимости отдельно включить redirect HTTP → HTTPS `307`;
6. отключить redirect или HTTPS без переустановки;
7. откатиться к последней рабочей TLS-паре.

Сертификат должен содержать все используемые DNS/IP в SAN. Private keys находятся в
`tls/`, не записываются в БД и не выдаются браузеру. Для internal CA интерфейс позволяет
скачать только публичный CA и показывает инструкции установки доверия.

Проверка HTTPS и redirect:

```bash
curl -k -sS -o /dev/null -w '%{http_code}\n' https://DNS-ИЛИ-IP/health/ready
curl -sS -D - -o /dev/null http://DNS-ИЛИ-IP:8000/
```

При включённом redirect второй запрос возвращает `307`. HSTS не используется.

Если сертификат истёк или действует не более двух суток, redirect автоматически
отключается в течение часа и не включается вручную до установки безопасной TLS-пары.
Предварительный срок предупреждения настраивается отдельно.

## PWA и Push

PWA и service worker требуют доверенного HTTPS (исключение браузеров — localhost).
После установки сертификата полностью перезапустите браузер или PWA.

Проверить:

- доступность manifest, service worker, иконок 192/512 и apple-touch-icon;
- предложение установки там, где его поддерживает браузер;
- standalone-запуск;
- offline-страницу в светлой и тёмной теме;
- отсутствие старых динамических данных при потере связи;
- включение Push, тестовую отправку и категории пользователя.

На iPhone/iPad Push работает для установленной на домашний экран PWA.

## Резервные копии

В разделе «Настройки → Резервное копирование» доступны:

- `configuration` — площадки, графики, объекты, пользователи и настройки без истории;
- `full` — вся база, включая историю, инциденты, аудит, чат и Push-подписки.

Перед восстановлением проверяются продукт, формат, версия и контрольные суммы.
Конфигурационные и полные бэкапы требуют точного
совпадения версии. `.mxbak` содержит чувствительные данные и должен храниться на
защищённом носителе.

Перед обновлением дополнительно можно сделать проверенный дамп PostgreSQL:

```bash
cd /opt/monitoring-maxval
sudo ./scripts/backup_database.sh
```

## Обновление рабочей установки

1. Создайте и скачайте проверенную резервную копию.
2. Сохраните рабочие `.env`, `tls/` и файлы бэкапов.
3. Замените файлы приложения содержимым нового релиза, но не новым `.env`.
4. Проверьте Compose и соберите образы.
5. Запустите сервисы и примените Alembic.
6. Проверьте версию, HTTP/HTTPS и количество основных записей.

```bash
cd /opt/monitoring-maxval
sudo docker compose config --quiet
sudo docker compose build app tls-manager
sudo docker compose up -d
sudo docker compose exec app alembic upgrade head
sudo docker compose exec app python -c 'import monitoring; print(monitoring.__version__)'
curl --fail http://127.0.0.1:8000/health/ready
```

Для обычного обновления запрещена команда `docker compose down -v`: флаг `-v` удаляет
PostgreSQL и другие постоянные volumes.

## Повседневное обслуживание

```bash
cd /opt/monitoring-maxval
sudo docker compose ps
sudo docker compose logs --tail=200 app
sudo docker compose logs --tail=200 caddy tls-manager
sudo docker compose restart app
```

Остановка без удаления данных:

```bash
sudo docker compose down
sudo docker compose up -d
```

## Типовые проблемы

### `Invalid host header`

Добавьте используемый IP/DNS в `MONITORING_ALLOWED_HOSTS`, затем пересоздайте только
приложение:

```bash
sudo docker compose up -d --force-recreate --no-deps app
```

### HTTPS показывает старый сертификат

Проверьте фактически выдаваемую пару и журналы применения:

```bash
printf '\n' | openssl s_client -connect DNS-ИМЯ:443 -servername DNS-ИМЯ 2>/dev/null \
  | openssl x509 -noout -issuer -dates -ext subjectAltName
sudo docker compose logs --tail=150 tls-manager caddy
```

После успешной активации полностью перезапустите браузер: он может сохранять старое
TLS-соединение.

### `/health/live` работает, `/health/ready` — нет

```bash
sudo docker compose ps
sudo docker compose logs --tail=200 db app
```

### Caddy возвращает `502`

Убедитесь, что `app` имеет состояние `healthy`, затем проверьте его журналы. Не
перенаправляйте Caddy на IP контейнера вручную: используйте Compose-имя `app:8000`.

## Обязательная проверка после установки или обновления

- версия `0.8.5`, Alembic `0036`, healthy-состояние контейнеров;
- вход/выход администратора и наблюдателя;
- главная, площадки, объекты, инциденты, отчёты, настройки, пользователи и аудит;
- плановая и ручная проверка без ложных статусов;
- сохранность площадок, объектов и настроек;
- HTTP; при настроенном TLS — HTTPS, Secure-cookie, redirect `307` и его отключение;
- отсутствие HSTS;
- PWA, offline fallback и Push;
- desktop, планшет, iPhone portrait и landscape;
- отсутствие секретов и private keys в интерфейсе и журналах.
