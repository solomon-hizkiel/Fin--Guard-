"""CSV evidence export uses utf-8-sig and round-trips Cyrillic."""

from __future__ import annotations

import pandas as pd


def _export_csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8-sig")


def test_csv_starts_with_utf8_bom():
    frame = pd.DataFrame([{"message": "hello", "status": "Safe"}])
    raw = _export_csv_bytes(frame)
    assert raw.startswith(b"\xef\xbb\xbf")


def test_russian_message_round_trips():
    original = "Срочный обнал через дроп, процент обсудим."
    frame = pd.DataFrame([{"message": original, "status": "Critical"}])
    raw = _export_csv_bytes(frame)
    decoded = raw.decode("utf-8-sig")
    assert original in decoded
    round_trip = pd.read_csv(pd.io.common.BytesIO(raw), encoding="utf-8-sig")
    assert round_trip.loc[0, "message"] == original
