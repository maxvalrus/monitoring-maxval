from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import MonitorTarget, Site, TargetCheck
from monitoring.services.target_transfer import export_targets_csv, import_targets_csv


def test_export_and_import_targets_round_trip() -> None:
    source_engine = create_engine("sqlite://")
    Base.metadata.create_all(source_engine)
    with Session(source_engine) as session:
        session.add(
            MonitorTarget(
                site=Site(name="Филиал Север"),
                name="Камера входа",
                kind="camera",
                checker_type="https",
                address="camera.example.test",
                port=443,
                interval_seconds=300,
                enabled=True,
                notifications_suppressed=True,
                favorite=True,
            )
        )
        session.commit()
        content = export_targets_csv(session).encode("utf-8")

    destination_engine = create_engine("sqlite://")
    Base.metadata.create_all(destination_engine)
    with Session(destination_engine) as session:
        imported = import_targets_csv(session, content)
        session.commit()
        target = session.query(MonitorTarget).one()
        assert imported.created == 1
        assert imported.updated == 0
        assert imported.sites_created == 1
        assert target.site.name == "Филиал Север"
        assert target.checker_type == "https"
        assert target.address == "camera.example.test"
        assert target.notifications_suppressed is True
        assert target.favorite is True
        primary = session.query(TargetCheck).one()
        assert primary.is_primary is True
        assert primary.checker_type == "https"
        assert primary.port == 443

        updated_content = content.replace(b",443,", b",8443,")
        updated = import_targets_csv(session, updated_content)
        session.commit()
        session.refresh(target)
        assert updated.created == 0
        assert updated.updated == 1
        assert target.port == 8443
        session.refresh(primary)
        assert primary.port == 8443


def test_import_rejects_unknown_checker() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    content = (
        "site,name,kind,checker_type,address,comment,port,interval_seconds,enabled,"
        "notifications_suppressed,favorite\n"
        "Филиал,Сервер,server,missing,192.0.2.1,,80,300,true,false,false\n"
    ).encode()
    with Session(engine) as session:
        try:
            import_targets_csv(session, content)
        except ValueError as exc:
            assert "неизвестная проверка" in str(exc)
        else:
            raise AssertionError("unknown checker was accepted")
