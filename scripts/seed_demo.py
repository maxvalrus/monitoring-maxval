"""Create harmless demo objects for visual verification of the interface."""

from datetime import UTC, datetime, timedelta

from monitoring.db import SessionLocal
from monitoring.models import (
    ChatMessage,
    CheckResult,
    MonitorTarget,
    PortalMetric,
    Site,
    User,
    UserNotification,
    UserRole,
)
from monitoring.services.auth import hash_password
from monitoring.services.target_checks import sync_target_primary_check

DEMO_PREFIX = "[ДЕМО]"


def add_target(
    site: Site,
    name: str,
    address: str,
    port: int,
    kind: str,
    status: str | None,
    notifications_suppressed: bool = False,
    favorite: bool = False,
    checker_type: str = "tcp",
    comment: str | None = None,
) -> MonitorTarget:
    target = MonitorTarget(
        site=site,
        name=name,
        address=address,
        port=port,
        kind=kind,
        interval_seconds=300,
        checker_type=checker_type,
        comment=comment,
        notifications_suppressed=notifications_suppressed,
        favorite=favorite,
    )
    if status is not None:
        target.results.append(
            CheckResult(
                status=status,
                latency_ms=12.4 if status == "up" else None,
                message=(
                    "Демонстрационный объект доступен"
                    if status == "up"
                    else "Демонстрационная ошибка подключения"
                ),
            )
        )
    return target


def main() -> None:
    with SessionLocal() as session:
        demo_user = session.query(User).filter(User.username == "demo").first()
        if demo_user is None:
            demo_user = User(
                username="demo",
                password_hash=hash_password("demo1234"),
                role=UserRole.VIEWER,
                active=True,
                must_change_default_password=False,
            )
            session.add(demo_user)
            session.flush()

        exists = session.query(Site).filter(Site.name.startswith(DEMO_PREFIX)).first()
        if exists:
            print("Demo data already exists; nothing changed.")
            return

        central = Site(name=f"{DEMO_PREFIX} Центральный офис")
        branch_1 = Site(name=f"{DEMO_PREFIX} Филиал Север — длинное название площадки")
        branch_2 = Site(name=f"{DEMO_PREFIX} Филиал Центр")
        branch_3 = Site(name=f"{DEMO_PREFIX} Филиал Юг")

        add_target(
            central,
            "Сервер приложений",
            "app",
            8000,
            "server",
            "up",
            favorite=True,
            comment="Основной сервер внутренних приложений. Используется для проверки всплывающего комментария.",
        )
        add_target(central, "PostgreSQL", "db", 5432, "server", "up")
        add_target(
            central,
            "Основной сервер бухгалтерии и терминальных подключений",
            "192.0.2.5",
            3389,
            "server",
            "up",
        )
        add_target(
            central,
            "Сетевое хранилище резервных копий",
            "192.0.2.6",
            445,
            "server",
            "down",
        )
        add_target(branch_1, "Маршрутизатор", "192.0.2.10", 8291, "network", "down")
        add_target(
            branch_1,
            "Камера входа",
            "192.0.2.20",
            80,
            "camera",
            None,
            notifications_suppressed=True,
            comment="Камера установлена у главного входа филиала. При диагностике сначала проверить питание PoE и доступность коммутатора видеонаблюдения; затем проверить RTSP-поток и настройки регистратора.",
        )
        add_target(
            branch_1,
            "Камера торгового зала с длинным названием",
            "192.0.2.21/stream1",
            554,
            "camera",
            "up",
            checker_type="rtsp",
        )
        add_target(
            branch_1,
            "Коммутатор системы видеонаблюдения",
            "192.0.2.22",
            22,
            "network",
            "up",
        )
        add_target(branch_2, "Рабочая станция", "192.0.2.30", 3389, "computer", "down")
        add_target(branch_2, "Кассовый компьютер № 1", "192.0.2.31", 3389, "computer", "up")
        add_target(branch_2, "Кассовый компьютер № 2", "192.0.2.32", 3389, "computer", None)
        add_target(branch_3, "Сайт филиала", "example.org", 443, "website", "up")
        add_target(
            branch_3,
            "Резервный канал маршрутизатора",
            "192.0.2.40",
            8291,
            "network",
            "down",
        )

        now = datetime.now(UTC)
        for index in range(24):
            session.add(
                PortalMetric(
                    cpu_percent=18 + (index % 7) * 3,
                    memory_percent=42 + (index % 5),
                    disk_percent=31.5,
                    uptime_seconds=86400 * 12 + index * 3600,
                    bytes_sent=10_000_000 + index * 420_000,
                    bytes_received=22_000_000 + index * 860_000,
                    packets_sent=120_000 + index * 1700,
                    packets_received=210_000 + index * 3100,
                    collected_at=now - timedelta(hours=23 - index),
                )
            )

        session.add_all([central, branch_1, branch_2, branch_3])
        session.flush()
        for site in (central, branch_1, branch_2, branch_3):
            for target in site.targets:
                sync_target_primary_check(session, target)

        admin = session.query(User).filter(User.username == "admin").first()
        if admin is not None:
            incoming = ChatMessage(
                sender_id=demo_user.id,
                recipient_id=admin.id,
                body="Добрый день! Это тестовое сообщение внутреннего чата.",
            )
            outgoing = ChatMessage(
                sender_id=admin.id,
                recipient_id=demo_user.id,
                body="Сообщение получено. Чат работает.",
            )
            session.add_all([incoming, outgoing])
            session.flush()
            session.add(
                UserNotification(
                    user_id=admin.id,
                    kind="chat",
                    title="Сообщение от demo",
                    body=incoming.body,
                    link=f"/chat?user_id={demo_user.id}",
                    source_type="chat_message",
                    source_id=str(incoming.id),
                )
            )

        session.commit()
        print("Demo data created. Chat test user: demo / demo1234")


if __name__ == "__main__":
    main()
