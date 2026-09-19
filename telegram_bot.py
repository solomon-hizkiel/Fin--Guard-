"""Fin-Guardian community report bot.

Users send or forward a message. The bot scores it with the same
keyword + optional GPT-4o logic as the officer dashboard. Critical
and Suspicious hits are written to fin_guardian.db so they appear
under Suspect database and Trends.

Run:
    python setup.py
    python telegram_bot.py

Token is read from TELEGRAM_BOT_TOKEN in .env, FIN_GUARDIAN_BOT_TOKEN,
or telegram_bot_token in .fin_guardian_credentials.json.
The OpenAI key is optional: OPENAI_API_KEY, or openai_key in
.fin_guardian_credentials.json (same file the dashboard uses).
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardian_core import (
    TELEGRAM_BOT_SOURCE,
    init_database,
    persist_flagged,
    score_report,
)

APP_DIR = Path(__file__).resolve().parent
ENV_PATH = APP_DIR / ".env"
CREDENTIALS_FILE = APP_DIR / ".fin_guardian_credentials.json"

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("fin-guardian-bot")

START_TEXT = (
    "Fin-Guardian report bot\n\n"
    "Send or forward a message and I will scan it for money-mule "
    "recruitment, illicit cashout, laundering, and KYC-evasion language.\n\n"
    "If the message is Critical or Suspicious, it is saved to the officer "
    "dashboard.\n\n"
    "This bot only detects and records suspected financial-crime "
    "solicitation. It does not give advice on committing crime."
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


def load_bot_token() -> str:
    load_local_env()
    for key in ("FIN_GUARDIAN_BOT_TOKEN", "TELEGRAM_BOT_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    data = load_credentials()
    return str(data.get("telegram_bot_token") or data.get("bot_token") or "").strip()


def load_openai_key() -> str:
    for key in ("OPENAI_API_KEY", "FIN_GUARDIAN_OPENAI_KEY"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    data = load_credentials()
    return str(data.get("openai_key") or "").strip()


def load_credentials() -> dict[str, Any]:
    if not CREDENTIALS_FILE.exists():
        return {}
    try:
        data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def display_name(user: Any) -> str:
    if user is None:
        return "unknown"
    username = getattr(user, "username", None)
    if username:
        return str(username)
    full = getattr(user, "full_name", None)
    if full:
        return str(full)
    first = getattr(user, "first_name", None)
    last = getattr(user, "last_name", None)
    combined = " ".join(part for part in (first, last) if part)
    return combined or "unknown"


def chat_label(chat: Any) -> str:
    if chat is None:
        return "telegram-bot"
    return (
        getattr(chat, "username", None)
        or getattr(chat, "title", None)
        or "telegram-bot"
    )


def extract_text(message: Any) -> str:
    return (getattr(message, "text", None) or getattr(message, "caption", None) or "").strip()


def suspect_from_message(message: Any) -> tuple[str, str, str]:
    """Prefer the original forwarded sender over the person reporting it."""
    origin = getattr(message, "forward_origin", None)
    if origin is not None:
        origin_name = type(origin).__name__
        if origin_name == "MessageOriginUser":
            user = getattr(origin, "sender_user", None)
            return (
                str(getattr(user, "id", "") or ""),
                display_name(user),
                _forwarded_group(message),
            )
        if origin_name == "MessageOriginHiddenUser":
            return (
                "",
                str(getattr(origin, "sender_user_name", None) or "hidden"),
                _forwarded_group(message),
            )
        if origin_name == "MessageOriginChat":
            chat = getattr(origin, "sender_chat", None)
            return str(getattr(chat, "id", "") or ""), chat_label(chat), chat_label(chat)
        if origin_name == "MessageOriginChannel":
            chat = getattr(origin, "chat", None)
            return str(getattr(chat, "id", "") or ""), chat_label(chat), chat_label(chat)

    forward_from = getattr(message, "forward_from", None)
    if forward_from is not None:
        return (
            str(getattr(forward_from, "id", "") or ""),
            display_name(forward_from),
            _forwarded_group(message),
        )

    forward_chat = getattr(message, "forward_from_chat", None)
    if forward_chat is not None:
        return (
            str(getattr(forward_chat, "id", "") or ""),
            chat_label(forward_chat),
            chat_label(forward_chat),
        )

    hidden = getattr(message, "forward_sender_name", None)
    if hidden:
        return "", str(hidden), _forwarded_group(message)

    reporter = getattr(message, "from_user", None)
    return str(getattr(reporter, "id", "") or ""), display_name(reporter), "telegram-bot"


def _forwarded_group(message: Any) -> str:
    chat = getattr(message, "forward_from_chat", None)
    if chat is not None:
        return chat_label(chat)
    origin = getattr(message, "forward_origin", None)
    if origin is not None:
        nested = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
        if nested is not None:
            return chat_label(nested)
    return "telegram-bot"


def format_reply(record: dict[str, Any], saved: int) -> str:
    status = str(record.get("status") or "Safe")
    score = int(record.get("risk_score") or 0)
    category = str(record.get("category") or "None")
    matched = str(record.get("matched_keywords") or "none")
    rationale = str(record.get("ai_rationale") or "").strip()
    username = str(record.get("username") or "unknown")
    user_id = str(record.get("user_id") or "")

    suspect = html.escape(username)
    if user_id:
        suspect = f"{suspect} ({html.escape(user_id)})"

    lines = [
        f"<b>Scan result:</b> {html.escape(status)}",
        f"<b>Risk score:</b> {score}/100",
        f"<b>Category:</b> {html.escape(category)}",
        f"<b>Suspect:</b> {suspect}",
        f"<b>Keywords:</b> {html.escape(matched)}",
    ]
    if rationale:
        lines.append(f"<b>AI note:</b> {html.escape(rationale)}")

    if status in {"Critical", "Suspicious"} and saved:
        lines.append("")
        lines.append(
            "Saved to the officer dashboard. Open Suspect database or "
            "Trends &amp; analytics and refresh the page."
        )
    elif status in {"Critical", "Suspicious"}:
        lines.append("")
        lines.append("Flagged, but the database write did not complete.")
    else:
        lines.append("")
        lines.append("No financial-crime indicators found. Nothing was saved.")
    return "\n".join(lines)


async def cmd_start(update: Any, context: Any) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(START_TEXT)


async def on_report(update: Any, context: Any) -> None:
    message = update.effective_message
    if message is None:
        return

    text = extract_text(message)
    if not text:
        await message.reply_text(
            "Send or forward a text message (or a photo with a caption) to scan."
        )
        return

    user_id, username, group = suspect_from_message(message)
    openai_key = context.application.bot_data.get("openai_key", "")
    stamp = message.date
    if stamp is not None and stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)

    try:
        await context.bot.send_chat_action(chat_id=message.chat_id, action="typing")
    except Exception:
        pass
    try:
        record = await asyncio.to_thread(
            score_report,
            text,
            user_id=user_id,
            username=username,
            group=group,
            platform=TELEGRAM_BOT_SOURCE,
            openai_key=openai_key,
            timestamp=stamp or datetime.now(timezone.utc),
        )
        saved = await asyncio.to_thread(persist_flagged, [record])
    except Exception:
        log.exception("Failed to score or save a report")
        await message.reply_text(
            "Could not finish that scan. Try again in a moment."
        )
        return

    await message.reply_text(format_reply(record, saved), parse_mode="HTML")


def main() -> None:
    try:
        from telegram.error import Conflict, InvalidToken, NetworkError, TimedOut
        from telegram.ext import Application, CommandHandler, MessageHandler, filters
    except ImportError:
        print("python-telegram-bot is not installed. Run: python setup.py")
        sys.exit(1)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    token = load_bot_token()
    if not token:
        print(
            "Set TELEGRAM_BOT_TOKEN in .env, or FIN_GUARDIAN_BOT_TOKEN, "
            "or add telegram_bot_token to .fin_guardian_credentials.json"
        )
        sys.exit(1)

    init_database()
    openai_key = load_openai_key()
    application = Application.builder().token(token).build()
    application.bot_data["openai_key"] = openai_key
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_start))
    application.add_handler(MessageHandler(~filters.COMMAND, on_report))

    log.info(
        "Fin-Guardian report bot starting (GPT-4o %s)",
        "on" if openai_key else "off — keyword scoring only",
    )
    try:
        application.run_polling(allowed_updates=["message"], drop_pending_updates=True)
    except InvalidToken:
        print("Bot token is invalid. Replace TELEGRAM_BOT_TOKEN in .env from BotFather.")
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
