"""Telegram login state machine with a mocked Telethon client."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from telethon.errors import (
    PasswordHashInvalidError,
    PhoneCodeInvalidError,
    SessionPasswordNeededError,
)

import app
from app import UI_STRINGS, telegram_step


HASH = "phone-hash-abc"


class FakeTelegramClient:
    def __init__(self):
        self.connected = False
        self.authorized = False
        self.sign_in_calls: list[dict] = []
        self.send_code_calls: list[str] = []
        self.need_password_on_code = True
        self.code_invalid = False
        self.password_invalid = False

    async def connect(self):
        self.connected = True

    async def is_user_authorized(self):
        return self.authorized

    async def send_code_request(self, phone):
        self.send_code_calls.append(phone)
        return SimpleNamespace(phone_code_hash=HASH)

    async def sign_in(self, *args, **kwargs):
        self.sign_in_calls.append(kwargs)
        if kwargs.get("password"):
            if self.password_invalid:
                raise PasswordHashInvalidError(None)
            self.authorized = True
            return
        if kwargs.get("code"):
            if self.code_invalid:
                raise PhoneCodeInvalidError(None)
            if self.need_password_on_code:
                raise SessionPasswordNeededError(None)
            self.authorized = True

    def is_connected(self):
        return self.connected

    async def disconnect(self):
        self.connected = False


def _run(fake: FakeTelegramClient, monkeypatch, **kwargs):
    monkeypatch.setattr(app, "TelegramClient", lambda *a, **k: fake)
    defaults = {
        "api_id": 1,
        "api_hash": "hash",
        "phone": "+447700900000",
        "group": "publicgroup",
        "auth_status": None,
        "login_code": None,
        "twofa_password": None,
        "phone_code_hash": None,
        "scrape": False,
    }
    defaults.update(kwargs)
    return asyncio.run(telegram_step(**defaults))


def test_first_call_returns_needs_code(monkeypatch):
    fake = FakeTelegramClient()
    result = _run(fake, monkeypatch)
    assert result["status"] == "needs_code"
    assert result["phone_code_hash"] == HASH
    assert fake.send_code_calls == ["+447700900000"]


def test_code_then_password_completes_login(monkeypatch):
    fake = FakeTelegramClient()
    first = _run(fake, monkeypatch)
    assert first["status"] == "needs_code"
    hash_value = first["phone_code_hash"]

    second = _run(
        fake,
        monkeypatch,
        auth_status="needs_code",
        login_code="12345",
        phone_code_hash=hash_value,
    )
    assert second["status"] == "needs_password"
    assert fake.sign_in_calls[0]["phone_code_hash"] == hash_value
    assert fake.sign_in_calls[0]["code"] == "12345"

    third = _run(
        fake,
        monkeypatch,
        auth_status="needs_password",
        twofa_password="secret",
        phone_code_hash=hash_value,
    )
    assert third["status"] == "ok"
    assert third["records"] == []
    assert fake.authorized is True


def test_phone_code_invalid_returns_error(monkeypatch):
    fake = FakeTelegramClient()
    fake.code_invalid = True
    result = _run(
        fake,
        monkeypatch,
        auth_status="needs_code",
        login_code="00000",
        phone_code_hash=HASH,
    )
    assert result["status"] == "error"
    assert result.get("message_key") == "err_code_invalid"
    assert UI_STRINGS["en"]["err_code_invalid"]


def test_password_invalid_returns_error(monkeypatch):
    fake = FakeTelegramClient()
    fake.password_invalid = True
    result = _run(
        fake,
        monkeypatch,
        auth_status="needs_password",
        twofa_password="wrong",
    )
    assert result["status"] == "error"
    assert result.get("message_key") == "err_password_wrong"
    assert UI_STRINGS["en"]["err_password_wrong"]
