"""Standalone community-report Telegram bot (Bot API, no Telethon login).

Uses the same score_keywords / status_from_score / analyze_with_gpt functions
as the officer dashboard. Flagged reports are written to fin_guardian.db
so they appear next to scraper detections on the dashboard.

Run:
    python report_bot.py

Token is read from TELEGRAM_BOT_TOKEN, or from a local .env file
(gitignored) so you do not need to export it every session.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from telegram import Update
from telegram.error import Conflict, InvalidToken, NetworkError, TimedOut
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from guardian_core import (
    COMMUNITY_SOURCE,
    SUSPICIOUS_THRESHOLD,
    analyze_with_gpt,
    category_from_keywords,
    init_database,
    persist_flagged,
    score_keywords,
    status_from_score,
)

APP_DIR = Path(__file__).resolve().parent
ENV_PATH = APP_DIR / ".env"
RATE_LIMIT = 10
RATE_WINDOW_SECONDS = 60.0
_RATE_LOCK = threading.Lock()
_recent: dict[int, deque[float]] = defaultdict(deque)

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("report-bot")

START_TEXT = (
    "Forward me a suspicious message and I'll analyze it for "
    "financial-crime risk indicators."
)


def load_local_env() -> None:
    if not ENV_PATH.exists():
        return
    try:
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _bot_token() -> str:
    load_local_env()
    return os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()


def _openai_key() -> str:
    return os.environ.get("OPENAI_API_KEY", "").strip()


def is_rate_limited(user_id: int) -> bool:
    now = time.monotonic()
    with _RATE_LOCK:
        bucket = _recent[user_id]
        while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT:
            return True
        bucket.append(now)
        return False


def extract_text(update: Update) -> str:
    message = update.message or update.effective_message
    if message is None:
        return ""
    return (message.text or message.caption or "").strip()


def save_report(text: str, risk_score: int, status: str, matched: list[str], reporter_id: int) -> int:
    return persist_flagged(
        [
            {
                "timestamp": datetime.now(timezone.utc),
                "message": text,
                "risk_score": risk_score,
                "status": status,
                "category": category_from_keywords(matched),
                "matched_keywords": matched,
                "user_id": str(reporter_id),
                "username": "anonymous",
                "group": "community-bot",
                "platform": COMMUNITY_SOURCE,
            }
        ]
    )


def analyze_text(text: str) -> tuple[int, str, list[str], str]:
    risk_score, matched = score_keywords(text)
    status = status_from_score(risk_score)
    rationale = ""
    api_key = _openai_key()
    if api_key:
        rows, _note = analyze_with_gpt([text], api_key)
        row = rows[0] if rows else {}
        rationale = str(row.get("rationale") or row.get("intent") or "").strip()
    return risk_score, status, matched, rationale


def format_hit(status: str, risk_score: int, matched: list[str]) -> str:
    labels = ", ".join(matched) if matched else "none"
    return (
        f"Risk: {status.upper()} ({risk_score}/100)\n"
        f"Matched: {labels}\n"
        "This has been logged for review."
    )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(START_TEXT)


async def on_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.message or update.effective_message
    if user is None or message is None:
        return
    if is_rate_limited(user.id):
        log.info("Rate-limited user_id=%s", user.id)
        await message.reply_text(
            "Too many reports from this account. Wait a minute and try again."
        )
        return

    text = extract_text(update)
    if not text:
        await message.reply_text(
            "Forward me a suspicious message and I'll analyze it for "
            "financial-crime risk indicators."
        )
        return

    try:
        risk_score, status, matched, _rationale = analyze_text(text)
        if risk_score < SUSPICIOUS_THRESHOLD:
            await message.reply_text("No strong risk indicators found")
            return

        saved = save_report(text, risk_score, status, matched, user.id)
        if not saved:
            await message.reply_text(
                "Flagged, but the database write did not complete."
            )
            return
        await message.reply_text(format_hit(status, risk_score, matched))
    except Exception:
        log.exception("Failed to score or save a community report")
        await message.reply_text(
            "Could not finish that scan. Try again in a moment."
        )


def _configure_event_loop() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def main() -> None:
    _configure_event_loop()
    token = _bot_token()
    if not token:
        print("Set TELEGRAM_BOT_TOKEN in .env before starting report_bot.py")
        sys.exit(1)
    if ":" not in token:
        print("TELEGRAM_BOT_TOKEN does not look like a BotFather token.")
        sys.exit(1)

    init_database()
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(MessageHandler(~filters.COMMAND, on_report))
    log.info("Community report bot writing to fin_guardian.db")
    try:
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
    except InvalidToken:
        print("TELEGRAM_BOT_TOKEN is invalid. Replace it in .env from BotFather.")
        sys.exit(1)
    except Conflict:
        print(
            "Another process is already polling this bot token. "
            "Stop the other python report_bot.py or telegram_bot.py and try again."
        )
        sys.exit(1)
    except (NetworkError, TimedOut) as exc:
        print(f"Cannot reach Telegram. Check your network and try again. ({exc})")
        sys.exit(1)


if __name__ == "__main__":
    main()
