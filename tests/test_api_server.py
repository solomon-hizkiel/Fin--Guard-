"""Flask /api/report and /api/health."""

from __future__ import annotations

from api_server import app


def test_health_ok():
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_report_valid_text_returns_scores():
    client = app.test_client()
    response = client.post("/api/report", json={"text": "Need a mule cashout tonight"})
    assert response.status_code == 200
    payload = response.get_json()
    assert "risk_score" in payload
    assert "status" in payload
    assert "category" in payload
    assert payload["status"] in {"Critical", "Suspicious", "Safe"}
    assert isinstance(payload["risk_score"], int)
    assert payload["risk_score"] >= 70
    assert payload["status"] == "Critical"


def test_report_missing_text_returns_400():
    client = app.test_client()
    assert client.post("/api/report", json={}).status_code == 400
    assert client.post("/api/report", json={"text": "   "}).status_code == 400
    assert client.post("/api/report", data="not-json").status_code == 400
