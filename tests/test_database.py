"""SQLite detections persistence and query shapes."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pandas as pd

import guardian_core
from guardian_core import (
    CRIME_CATEGORIES,
    fetch_category_counts,
    fetch_detections,
    fetch_offenders,
    persist_flagged,
)


EXPECTED_COLUMNS = {
    "id",
    "user_id",
    "username",
    "message",
    "chat_group",
    "category",
    "risk_score",
    "status",
    "detected_at",
    "source",
    "matched_keywords",
}


def test_init_database_creates_expected_columns(temp_db):
    conn = sqlite3.connect(temp_db)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(detections)")}
    conn.close()
    assert EXPECTED_COLUMNS.issubset(columns)


def test_persist_flagged_skips_safe_records(temp_db):
    now = datetime.now(timezone.utc)
    persist_flagged(
        [
            {
                "timestamp": now,
                "user_id": "1",
                "username": "safe_user",
                "message": "concert tickets",
                "group": "demo",
                "category": "None",
                "risk_score": 0,
                "status": "Safe",
                "platform": "Telegram Intelligence",
                "matched_keywords": "",
            },
            {
                "timestamp": now,
                "user_id": "2",
                "username": "risk_user",
                "message": "Need a mule to cashout",
                "group": "demo",
                "category": "Money mule recruitment",
                "risk_score": 75,
                "status": "Critical",
                "platform": "Telegram Intelligence",
                "matched_keywords": "mule, cashout",
            },
            {
                "timestamp": now,
                "user_id": "3",
                "username": "watch_user",
                "message": "clean cash offer",
                "group": "demo",
                "category": "Illicit cashout",
                "risk_score": 45,
                "status": "Suspicious",
                "platform": "Telegram Intelligence",
                "matched_keywords": "clean cash",
            },
        ]
    )
    conn = sqlite3.connect(temp_db)
    rows = list(conn.execute("SELECT username, status FROM detections"))
    conn.close()
    statuses = {row[1] for row in rows}
    names = {row[0] for row in rows}
    assert "Safe" not in statuses
    assert "safe_user" not in names
    assert "risk_user" in names
    assert "watch_user" in names


def test_fetch_helpers_empty_and_populated_shapes(temp_db):
    empty_detections = fetch_detections()
    empty_offenders = fetch_offenders()
    empty_categories = fetch_category_counts()
    assert isinstance(empty_detections, pd.DataFrame)
    assert empty_detections.empty
    assert isinstance(empty_offenders, pd.DataFrame)
    assert empty_offenders.empty
    assert list(empty_categories.columns) == ["category", "count"]
    assert set(empty_categories["category"]) == set(CRIME_CATEGORIES)
    assert int(empty_categories["count"].sum()) == 0

    persist_flagged(
        [
            {
                "timestamp": datetime.now(timezone.utc),
                "user_id": "u-1",
                "username": "repeat_actor",
                "message": "Need a mule to cashout",
                "group": "alpha",
                "category": "Money mule recruitment",
                "risk_score": 80,
                "status": "Critical",
                "platform": "Telegram Intelligence",
                "matched_keywords": "mule, cashout",
            }
        ]
    )
    detections = fetch_detections()
    offenders = fetch_offenders()
    categories = fetch_category_counts()
    for column in ["timestamp", "platform", "group", "username", "message", "status"]:
        assert column in detections.columns
    assert len(detections) == 1
    assert "user_id" in offenders.columns
    assert "incidents" in offenders.columns
    assert int(offenders.iloc[0]["incidents"]) >= 1
    mule_count = int(
        categories.loc[categories["category"] == "Money mule recruitment", "count"].iloc[0]
    )
    assert mule_count >= 1
    assert guardian_core.DB_PATH == temp_db
