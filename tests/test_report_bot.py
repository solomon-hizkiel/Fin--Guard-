"""Community report bot scoring, logging, and rate limits."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import report_bot


def _update(user_id: int, text: str):
    message = MagicMock()
    message.text = text
    message.caption = None
    message.reply_text = AsyncMock()
    update = MagicMock()
    update.message = message
    update.effective_user = SimpleUser(user_id)
    return update, message


class SimpleUser:
    def __init__(self, user_id: int):
        self.id = user_id


def test_high_risk_message_is_logged(monkeypatch):
    report_bot._recent.clear()
    saved = []

    def fake_persist(records):
        saved.append(records)
        return len(records)

    monkeypatch.setattr(report_bot, "persist_flagged", fake_persist)
    update, message = _update(11, "Need a mule to cashout USDT tonight")
    asyncio.run(report_bot.on_report(update, MagicMock()))
    assert saved
    assert saved[0][0]["status"] in {"Critical", "Suspicious"}
    message.reply_text.assert_awaited()


def test_safe_message_is_not_logged(monkeypatch):
    report_bot._recent.clear()
    saved = []
    monkeypatch.setattr(report_bot, "persist_flagged", lambda records: saved.append(records) or 0)
    update, message = _update(12, "Anyone selling concert tickets for Saturday?")
    asyncio.run(report_bot.on_report(update, MagicMock()))
    assert saved == []
    message.reply_text.assert_awaited()
    assert "No strong risk indicators" in message.reply_text.await_args.args[0]


def test_eleventh_message_from_same_user_is_rate_limited(monkeypatch):
    report_bot._recent.clear()
    saved = []
    monkeypatch.setattr(report_bot, "persist_flagged", lambda records: saved.append(records) or 1)
    last_message = None
    for index in range(11):
        update, last_message = _update(99, "Need a mule to cashout right now")
        asyncio.run(report_bot.on_report(update, MagicMock()))
    assert len(saved) == 10
    assert last_message is not None
    assert "Too many reports" in last_message.reply_text.await_args.args[0]
