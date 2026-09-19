"""Shared Fin-Guardian scoring and SQLite persistence.

Used by the Streamlit officer dashboard and the Telegram report bot.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "fin_guardian.db"
_DB_LOCK = threading.Lock()

CRITICAL_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
WALLET_CRITICAL_FLOOR = 85
TELEGRAM_SOURCE = "Telegram Intelligence"
TELEGRAM_BOT_SOURCE = "Telegram Bot Reports"
COMMUNITY_SOURCE = "Community Reports"

ETH_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
ETHERSCAN_URL = "https://api.etherscan.io/api"
_ENRICH_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
_ENRICH_LOCK = threading.Lock()

KEYWORD_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\bclean\s+cash\b", re.IGNORECASE), 45, "clean cash"),
    (re.compile(r"\bno\s+kyc\b", re.IGNORECASE), 30, "no kyc"),
    (re.compile(r"\bcashout\b", re.IGNORECASE), 35, "cashout"),
    (re.compile(r"\bmule\b", re.IGNORECASE), 40, "mule"),
    (re.compile(r"\bwashing\b", re.IGNORECASE), 35, "washing"),
    (re.compile(r"\bобнал\w*", re.IGNORECASE), 45, "обнал"),
    (re.compile(r"\bдроп\w*", re.IGNORECASE), 40, "дроп"),
    (re.compile(r"\bкрипто[\s-]?обмен\w*", re.IGNORECASE), 30, "криптообмен"),
    (re.compile(r"\bпроцент\w*", re.IGNORECASE), 20, "процент"),
    (re.compile(r"\bвывод\w*", re.IGNORECASE), 30, "вывод"),
    (re.compile(r"\bкарт[аыуео]\b", re.IGNORECASE), 15, "карта"),
    (re.compile(r"\bзалив\w*", re.IGNORECASE), 40, "залив"),
    (
        re.compile(r"\bработ[аеуы]\s+для\s+студент\w*", re.IGNORECASE),
        40,
        "работа для студентов",
    ),
]

CRIME_CATEGORIES = (
    "Money mule recruitment",
    "Illicit cashout",
    "Money laundering",
    "KYC evasion",
)
KEYWORD_CATEGORIES = {
    "mule": "Money mule recruitment",
    "дроп": "Money mule recruitment",
    "работа для студентов": "Money mule recruitment",
    "cashout": "Illicit cashout",
    "clean cash": "Illicit cashout",
    "обнал": "Illicit cashout",
    "вывод": "Illicit cashout",
    "залив": "Illicit cashout",
    "карта": "Illicit cashout",
    "washing": "Money laundering",
    "криптообмен": "Money laundering",
    "процент": "Illicit cashout",
    "no kyc": "KYC evasion",
}
CATEGORY_PRIORITY = (
    "Money mule recruitment",
    "Money laundering",
    "Illicit cashout",
    "KYC evasion",
)

GPT_SYSTEM_PROMPT = """You are a financial-crime detection analyst reviewing public Telegram messages.
Messages may be in English or Russian. Treat Russian slang as financial-crime solicitation when it is used that way: обнал (illicit cashout), дроп (money mule), залив (pushing stolen funds onto a card), криптообмен, вывод, карта, процент, работа для студентов.
Classify each message into exactly one category and a risk score.
Do not provide advice on committing crime.

Allowed category values:
- Money mule recruitment
- Illicit cashout
- Money laundering
- KYC evasion
- None

Return JSON with this shape:
{"analyses": [{"index": 0, "risk_score": 0, "category": "None", "rationale": "one sentence"}]}

risk_score is an integer from 0 (benign) to 100 (clear financial-crime solicitation).
"""


def find_eth_wallets(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for address in ETH_ADDRESS_RE.findall(text or ""):
        key = address.lower()
        if key not in seen:
            seen.add(key)
            found.append(address)
    return found


def shorten_eth_address(address: str) -> str:
    if len(address) < 10:
        return address
    return f"{address[:6]}...{address[-4:]}"


def format_wallet_flag(address: str, info: dict[str, Any] | None = None) -> str:
    short = shorten_eth_address(address)
    if not info or not info.get("ok"):
        return f"🔗 {short}"
    count = int(info.get("tx_count") or 0)
    last_active = info.get("last_active")
    if isinstance(last_active, datetime):
        last_text = last_active.astimezone(timezone.utc).strftime("%Y-%m-%d")
        return f"🔗 {short} — {count} txs, last active {last_text}"
    return f"🔗 {short} — {count} txs"


def enrich_eth_wallet(address: str, etherscan_api_key: str) -> dict[str, Any]:
    """Look up an Ethereum address on Etherscan. Never raises."""
    empty: dict[str, Any] = {"tx_count": 0, "last_active": None, "note": "", "ok": False}
    key = (etherscan_api_key or "").strip()
    wallet = (address or "").strip()
    if not key or not ETH_ADDRESS_RE.fullmatch(wallet):
        return empty

    cache_key = (wallet.lower(), key)
    with _ENRICH_LOCK:
        cached = _ENRICH_CACHE.get(cache_key)
    if cached is not None:
        return cached

    try:
        import requests
    except ImportError:
        result = {**empty, "note": "requests is not installed"}
        return result

    try:
        response = requests.get(
            ETHERSCAN_URL,
            params={
                "module": "account",
                "action": "txlist",
                "address": wallet,
                "sort": "desc",
                "apikey": key,
            },
            timeout=8,
        )
        payload = response.json()
    except Exception as exc:
        return {**empty, "note": str(exc)}

    if not isinstance(payload, dict):
        return {**empty, "note": "Unexpected Etherscan response"}

    if str(payload.get("status")) == "0":
        note = str(payload.get("message") or "")
        result = {
            "tx_count": 0,
            "last_active": None,
            "note": note,
            "ok": note.lower().startswith("no transaction"),
        }
        with _ENRICH_LOCK:
            _ENRICH_CACHE[cache_key] = result
        return result

    rows = payload.get("result") or []
    if not isinstance(rows, list):
        return {
            "tx_count": 0,
            "last_active": None,
            "note": str(rows),
            "ok": False,
        }

    last_active = None
    if rows:
        try:
            last_active = datetime.fromtimestamp(
                int(rows[0].get("timeStamp", 0)), tz=timezone.utc
            )
        except (TypeError, ValueError, OSError):
            last_active = None
    result = {
        "tx_count": len(rows),
        "last_active": last_active,
        "note": "",
        "ok": True,
    }
    with _ENRICH_LOCK:
        _ENRICH_CACHE[cache_key] = result
    return result


def apply_wallet_enrichment(records: list[dict[str, Any]], etherscan_api_key: str = "") -> list[dict[str, Any]]:
    """Attach wallet flags. Enrich only when an Etherscan key is present."""
    key = (etherscan_api_key or "").strip()
    for record in records:
        wallets = record.get("wallets") or find_eth_wallets(str(record.get("message") or ""))
        record["wallets"] = wallets
        flags: list[str] = []
        for address in wallets:
            info = enrich_eth_wallet(address, key) if key else None
            if info and not info.get("ok"):
                info = None
            flags.append(format_wallet_flag(address, info))
        record["wallet_flag"] = " · ".join(flags)
    return records


def score_keywords(text: str) -> tuple[int, list[str]]:
    matches: list[str] = []
    score = 0
    for pattern, weight, label in KEYWORD_PATTERNS:
        if pattern.search(text) and label not in matches:
            matches.append(label)
            score += weight
    return min(score, 100), matches


def status_from_score(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "Critical"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def normalize_category(value: Any) -> str:
    text = str(value or "").strip()
    if text in CRIME_CATEGORIES:
        return text
    lowered = text.lower()
    for category in CRIME_CATEGORIES:
        if category.lower() == lowered:
            return category
    aliases = {
        "mule": "Money mule recruitment",
        "drop": "Money mule recruitment",
        "дроп": "Money mule recruitment",
        "cashout": "Illicit cashout",
        "обнал": "Illicit cashout",
        "залив": "Illicit cashout",
        "вывод": "Illicit cashout",
        "laundering": "Money laundering",
        "washing": "Money laundering",
        "криптообмен": "Money laundering",
        "kyc": "KYC evasion",
    }
    for needle, category in aliases.items():
        if needle in lowered:
            return category
    return "None"


def category_from_keywords(matched: list[str]) -> str:
    found = {
        KEYWORD_CATEGORIES[label]
        for label in matched
        if label in KEYWORD_CATEGORIES
    }
    for category in CATEGORY_PRIORITY:
        if category in found:
            return category
    return "None"


def analyze_with_gpt(messages: list[str], api_key: str) -> tuple[list[dict[str, Any]], str | None]:
    if not api_key.strip():
        return [{} for _ in messages], None

    try:
        from openai import OpenAI
    except ImportError:
        return [{} for _ in messages], "OpenAI library is not installed. Keyword scoring only."

    payload = [
        {"index": index, "text": text[:500]}
        for index, text in enumerate(messages)
    ]
    try:
        client = OpenAI(api_key=api_key.strip())
        response = client.chat.completions.create(
            model="gpt-4o",
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": GPT_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps({"messages": payload}, ensure_ascii=False),
                },
            ],
        )
        content = response.choices[0].message.content or "{}"
        parsed = json.loads(content)
        analyses = parsed.get("analyses", [])
        by_index = {
            int(item["index"]): item
            for item in analyses
            if isinstance(item, dict) and "index" in item
        }
        return [by_index.get(index, {}) for index in range(len(messages))], None
    except Exception as exc:
        return [{} for _ in messages], f"GPT-4o analysis skipped: {exc}"


def build_records(
    raw_messages: list[dict[str, Any]],
    openai_key: str,
    default_platform: str = TELEGRAM_SOURCE,
) -> tuple[list[dict[str, Any]], str | None]:
    texts = [item["message"] for item in raw_messages]
    gpt_rows, ai_note = analyze_with_gpt(texts, openai_key)

    records: list[dict[str, Any]] = []
    for item, gpt in zip(raw_messages, gpt_rows):
        keyword_score, matched = score_keywords(item["message"])
        try:
            gpt_score = int(gpt.get("risk_score", keyword_score))
        except (TypeError, ValueError):
            gpt_score = keyword_score
        gpt_score = max(0, min(gpt_score, 100))
        risk_score = max(keyword_score, gpt_score) if openai_key.strip() else keyword_score
        rationale = str(gpt.get("rationale") or gpt.get("intent") or "")
        status = status_from_score(risk_score)
        keyword_category = category_from_keywords(matched)
        gpt_category = normalize_category(gpt.get("category"))
        if openai_key.strip() and gpt_category != "None":
            category = gpt_category
        elif status == "Safe":
            category = "None"
        else:
            category = keyword_category
        wallets = find_eth_wallets(item["message"])
        if wallets:
            risk_score = max(risk_score, WALLET_CRITICAL_FLOOR)
            status = status_from_score(risk_score)
            if category == "None":
                category = keyword_category
        records.append(
            {
                "timestamp": item.get("timestamp") or datetime.now(timezone.utc),
                "group": item.get("group", ""),
                "user_id": item.get("user_id", ""),
                "username": item.get("username", "unknown"),
                "platform": item.get("platform") or default_platform,
                "message": item["message"],
                "risk_score": risk_score,
                "status": status,
                "category": category,
                "matched_keywords": ", ".join(matched),
                "ai_rationale": rationale,
                "wallets": wallets,
                "wallet_flag": " · ".join(format_wallet_flag(address) for address in wallets),
            }
        )
    return records, ai_note


def score_live_record(
    text: str,
    timestamp: datetime | None,
    group: str,
    user_id: str = "",
    username: str = "unknown",
    platform: str = TELEGRAM_SOURCE,
) -> dict[str, Any]:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    elif timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    keyword_score, matched = score_keywords(text)
    wallets = find_eth_wallets(text)
    risk_score = keyword_score
    if wallets:
        risk_score = max(risk_score, WALLET_CRITICAL_FLOOR)
    status = status_from_score(risk_score)
    category = category_from_keywords(matched) if status != "Safe" else "None"
    return {
        "timestamp": timestamp,
        "group": group,
        "user_id": user_id or "",
        "username": username or "unknown",
        "message": text,
        "risk_score": risk_score,
        "status": status,
        "category": category,
        "matched_keywords": ", ".join(matched),
        "ai_rationale": "",
        "platform": platform,
        "wallets": wallets,
        "wallet_flag": " · ".join(format_wallet_flag(address) for address in wallets),
    }


def score_report(
    text: str,
    *,
    user_id: str = "",
    username: str = "unknown",
    group: str = "telegram-bot",
    platform: str = TELEGRAM_BOT_SOURCE,
    openai_key: str = "",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    raw = {
        "timestamp": timestamp or datetime.now(timezone.utc),
        "group": group,
        "user_id": user_id,
        "username": username,
        "platform": platform,
        "message": text,
    }
    records, _note = build_records([raw], openai_key, default_platform=platform)
    return records[0]


def init_database() -> None:
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                username TEXT,
                message TEXT NOT NULL,
                chat_group TEXT,
                category TEXT,
                risk_score INTEGER,
                status TEXT,
                detected_at TEXT NOT NULL,
                source TEXT,
                matched_keywords TEXT
            )
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(detections)")}
        if "source" not in columns:
            conn.execute("ALTER TABLE detections ADD COLUMN source TEXT")
        if "matched_keywords" not in columns:
            conn.execute("ALTER TABLE detections ADD COLUMN matched_keywords TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detections_user ON detections(user_id, username)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source)"
        )
        conn.commit()
        conn.close()
    migrate_community_jsonl()


def persist_flagged(records: list[dict[str, Any]]) -> int:
    flagged = [
        record
        for record in records
        if record.get("status") in {"Critical", "Suspicious"}
    ]
    if not flagged:
        return 0
    rows = []
    for record in flagged:
        stamp = record.get("timestamp") or datetime.now(timezone.utc)
        if isinstance(stamp, datetime):
            stamp_text = stamp.astimezone(timezone.utc).isoformat()
        else:
            stamp_text = str(stamp)
        source = str(
            record.get("source")
            or record.get("platform")
            or TELEGRAM_SOURCE
        )
        matched = record.get("matched_keywords") or ""
        if isinstance(matched, list):
            matched = ", ".join(str(item) for item in matched if item)
        rows.append(
            (
                str(record.get("user_id") or ""),
                str(record.get("username") or "unknown"),
                str(record.get("message") or ""),
                str(record.get("group") or ""),
                normalize_category(record.get("category")),
                int(record.get("risk_score") or 0),
                str(record.get("status") or ""),
                stamp_text,
                source,
                str(matched),
            )
        )
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.executemany(
            """
            INSERT INTO detections (
                user_id, username, message, chat_group, category,
                risk_score, status, detected_at, source, matched_keywords
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        conn.close()
    return len(rows)


def migrate_community_jsonl() -> int:
    """Move leftover community_reports.jsonl rows into fin_guardian.db once."""
    path = APP_DIR / "community_reports.jsonl"
    if not path.exists():
        return 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0
    records: list[dict[str, Any]] = []
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        text = str(item.get("message") or "").strip()
        if not text:
            continue
        matched = item.get("matched_keywords") or []
        if isinstance(matched, str):
            matched_list = [part.strip() for part in matched.split(",") if part.strip()]
        else:
            matched_list = [str(part) for part in matched if part]
        records.append(
            {
                "timestamp": item.get("timestamp") or datetime.now(timezone.utc),
                "message": text,
                "risk_score": int(item.get("risk_score") or 0),
                "status": str(item.get("status") or status_from_score(int(item.get("risk_score") or 0))),
                "category": category_from_keywords(matched_list),
                "matched_keywords": ", ".join(matched_list),
                "user_id": str(item.get("reporter_id") or item.get("user_id") or ""),
                "username": "anonymous",
                "group": "community-bot",
                "platform": COMMUNITY_SOURCE,
            }
        )
    saved = persist_flagged(records) if records else 0
    try:
        path.replace(path.with_suffix(".jsonl.migrated"))
    except OSError:
        pass
    return saved


def fetch_detections() -> pd.DataFrame:
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        frame = pd.read_sql_query(
            """
            SELECT
                detected_at,
                COALESCE(NULLIF(source, ''), ?) AS source,
                chat_group,
                user_id,
                username,
                message,
                category,
                risk_score,
                status,
                COALESCE(matched_keywords, '') AS matched_keywords
            FROM detections
            WHERE status IN ('Critical', 'Suspicious')
            ORDER BY detected_at DESC
            """,
            conn,
            params=(TELEGRAM_SOURCE,),
        )
        conn.close()
    if frame.empty:
        return frame
    return frame.rename(
        columns={"detected_at": "timestamp", "source": "platform", "chat_group": "group"}
    )


def fetch_community_reports() -> list[dict[str, Any]]:
    inbox = fetch_detections()
    if inbox.empty:
        return []
    community = inbox[
        (inbox["platform"].isin({COMMUNITY_SOURCE, TELEGRAM_BOT_SOURCE}))
        | (inbox["group"].isin({"community-bot", "telegram-bot", "community-tip"}))
    ]
    records: list[dict[str, Any]] = []
    for row in community.to_dict(orient="records"):
        stamp = row.get("timestamp")
        if isinstance(stamp, str):
            try:
                stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError:
                stamp = datetime.now(timezone.utc)
        records.append(
            {
                "timestamp": stamp,
                "message": row.get("message") or "",
                "group": row.get("group") or "community-bot",
                "user_id": str(row.get("user_id") or ""),
                "username": str(row.get("username") or "anonymous"),
                "platform": COMMUNITY_SOURCE,
            }
        )
    return records


def fetch_offenders() -> pd.DataFrame:
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        frame = pd.read_sql_query(
            """
            SELECT
                COALESCE(NULLIF(user_id, ''), 'unknown') AS user_id,
                COALESCE(NULLIF(username, ''), 'unknown') AS username,
                COUNT(*) AS incidents,
                COUNT(DISTINCT chat_group) AS groups_count,
                GROUP_CONCAT(DISTINCT chat_group) AS groups,
                MAX(detected_at) AS last_seen
            FROM detections
            WHERE status = 'Critical'
            GROUP BY user_id, username
            ORDER BY incidents DESC, last_seen DESC
            """,
            conn,
        )
        conn.close()
    return frame


def fetch_offender_history(user_id: str, username: str) -> pd.DataFrame:
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        frame = pd.read_sql_query(
            """
            SELECT detected_at, chat_group, category, risk_score, message
            FROM detections
            WHERE status = 'Critical'
              AND COALESCE(NULLIF(user_id, ''), 'unknown') = ?
              AND COALESCE(NULLIF(username, ''), 'unknown') = ?
            ORDER BY detected_at DESC
            """,
            conn,
            params=(user_id, username),
        )
        conn.close()
    return frame


def fetch_category_counts() -> pd.DataFrame:
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        frame = pd.read_sql_query(
            """
            SELECT category, COUNT(*) AS count
            FROM detections
            WHERE status IN ('Critical', 'Suspicious')
              AND category IS NOT NULL
              AND category != 'None'
            GROUP BY category
            """,
            conn,
        )
        conn.close()
    counts = {category: 0 for category in CRIME_CATEGORIES}
    for _, row in frame.iterrows():
        category = normalize_category(row["category"])
        if category in counts:
            counts[category] += int(row["count"])
    return pd.DataFrame(
        {"category": list(counts.keys()), "count": list(counts.values())}
    )


def fetch_hourly_trend() -> pd.DataFrame:
    cutoff = datetime.now(timezone.utc) - pd.Timedelta(hours=24)
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        frame = pd.read_sql_query(
            """
            SELECT detected_at
            FROM detections
            WHERE status IN ('Critical', 'Suspicious')
            """,
            conn,
        )
        conn.close()
    hours = pd.date_range(
        start=cutoff.replace(minute=0, second=0, microsecond=0),
        end=datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0),
        freq="h",
        tz="UTC",
    )
    trend = pd.DataFrame({"hour": hours, "messages": 0})
    if frame.empty:
        return trend
    parsed = pd.to_datetime(frame["detected_at"], utc=True, errors="coerce").dropna()
    parsed = parsed[parsed >= cutoff]
    if parsed.empty:
        return trend
    hourly = (
        parsed.dt.floor("h")
        .value_counts()
        .rename_axis("hour")
        .reset_index(name="messages")
    )
    merged = trend.merge(hourly, on="hour", how="left", suffixes=("", "_new"))
    merged["messages"] = merged["messages_new"].fillna(0).astype(int)
    return merged[["hour", "messages"]]


def _pdf_text(value: Any) -> str:
    text = str(value if value is not None and str(value).strip() != "" else "—")
    return text


def _pdf_utc(value: Any) -> str:
    if isinstance(value, datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if value:
        return str(value)
    return "—"


def lead_report_filename(record: Any) -> str:
    data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    status = str(data.get("status") or "lead").strip().lower() or "lead"
    stamp = data.get("timestamp")
    if isinstance(stamp, datetime):
        when = stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
        stamp_text = when.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%S")
    else:
        stamp_text = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"fin-guardian-lead-{status}-{stamp_text}.pdf"


def generate_report_pdf(record: Any) -> bytes:
    """Build an analyst lead PDF for one detection. Not legal evidence."""
    from fpdf import FPDF

    data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    generated = datetime.now(timezone.utc)
    generated_text = generated.strftime("%Y-%m-%d %H:%M:%S UTC")
    regular_font = str(APP_DIR / "fonts" / "DejaVuSans.ttf")
    bold_font = str(APP_DIR / "fonts" / "DejaVuSans-Bold.ttf")

    class LeadPDF(FPDF):
        def header(self) -> None:
            self.set_font("DejaVu", "B", 13)
            self.set_text_color(30, 41, 59)
            self.cell(
                0,
                8,
                "FIN-GUARDIAN INVESTIGATIVE LEAD REPORT",
                new_x="LMARGIN",
                new_y="NEXT",
                align="C",
            )
            self.set_draw_color(148, 163, 184)
            self.line(12, self.get_y() + 1, 198, self.get_y() + 1)
            self.ln(6)

        def footer(self) -> None:
            self.set_y(-20)
            self.set_draw_color(148, 163, 184)
            self.line(12, self.get_y(), 198, self.get_y())
            self.ln(2)
            self.set_font("DejaVu", "", 7)
            self.set_text_color(100, 116, 139)
            self.multi_cell(
                0,
                3.5,
                _pdf_text(
                    "Generated by Fin-Guardian automated detection system — for internal review only\n"
                    f"Generated: {generated_text}"
                ),
                align="C",
            )

    pdf = LeadPDF()
    pdf.add_font("DejaVu", "", regular_font)
    pdf.add_font("DejaVu", "B", bold_font)
    pdf.set_auto_page_break(auto=True, margin=24)
    pdf.add_page()

    pdf.set_fill_color(255, 251, 235)
    pdf.set_draw_color(217, 119, 6)
    pdf.set_font("DejaVu", "", 9)
    pdf.set_text_color(120, 53, 15)
    pdf.multi_cell(
        0,
        5,
        "This report is an automated investigative lead for analyst review. "
        "It has not been verified by a human investigator.",
        border=1,
        fill=True,
    )
    pdf.ln(6)
    pdf.set_text_color(15, 23, 42)

    fields = [
        ("Report Generated", generated_text),
        ("Source Platform", data.get("platform") or "—"),
        ("Group/Channel", data.get("group") or "—"),
        ("User ID", data.get("user_id") or "—"),
        ("Username", data.get("username") or "—"),
        ("Detection Timestamp", _pdf_utc(data.get("timestamp"))),
        (
            "Risk Score (with status)",
            f"{data.get('risk_score', 0)}/100  ({data.get('status') or '—'})",
        ),
        ("Category", data.get("category") or "—"),
        ("Matched Keywords", data.get("matched_keywords") or "—"),
    ]
    wallet = str(data.get("wallet_flag") or "").strip()
    if wallet:
        fields.append(("Wallet Indicators", wallet))

    for label, value in fields:
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(0, 6, _pdf_text(label), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 10)
        pdf.multi_cell(0, 6, _pdf_text(value))
        pdf.ln(1)

    pdf.ln(3)
    pdf.set_font("DejaVu", "B", 11)
    pdf.cell(0, 8, "Flagged Message", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(148, 163, 184)
    pdf.multi_cell(0, 6, _pdf_text(data.get("message") or "—"), border=1, fill=True)

    return bytes(pdf.output())

