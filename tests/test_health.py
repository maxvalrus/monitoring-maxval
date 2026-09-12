from fastapi.testclient import TestClient

from monitoring.main import app


def test_liveness_reports_version() -> None:
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.8.5"}
