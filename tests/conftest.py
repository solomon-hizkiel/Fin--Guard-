"""Shared fixtures: temp SQLite DB and sample raw messages."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import guardian_core

VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(guardian_core, "DB_PATH", db_path)
    monkeypatch.setattr(guardian_core, "migrate_community_jsonl", lambda: 0)
    guardian_core._ENRICH_CACHE.clear()
    try:
        import report_bot

        report_bot._recent.clear()
    except Exception:
        pass
    guardian_core.init_database()
    yield db_path


@pytest.fixture
def sample_raw_messages():
    now = datetime.now(timezone.utc)
    return {
        "english_risky": {
            "timestamp": now,
            "group": "demo",
            "user_id": "1001",
            "username": "cash_runner",
            "message": "Need a mule to cashout funds tonight.",
        },
        "russian_risky": {
            "timestamp": now,
            "group": "demo",
            "user_id": "1002",
            "username": "obnal_desk",
            "message": "Срочный обнал через дроп, процент обсудим.",
        },
        "wallet": {
            "timestamp": now,
            "group": "demo",
            "user_id": "1003",
            "username": "payee",
            "message": f"Send payment to {VITALIK} today.",
        },
        "safe": {
            "timestamp": now,
            "group": "demo",
            "user_id": "1004",
            "username": "ticketfan",
            "message": "Anyone selling concert tickets for Saturday?",
        },
    }
