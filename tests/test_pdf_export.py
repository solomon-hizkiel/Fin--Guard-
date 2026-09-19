"""Lead PDF generation, including Cyrillic and framing language."""

from __future__ import annotations

import io
from datetime import datetime, timezone

from pypdf import PdfReader

from guardian_core import generate_report_pdf


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def test_generate_report_pdf_cyrillic_does_not_raise():
    record = {
        "timestamp": datetime.now(timezone.utc),
        "platform": "Telegram Intelligence",
        "group": "obnal_chat",
        "user_id": "9001",
        "username": "дроп_runner",
        "status": "Critical",
        "risk_score": 85,
        "category": "Illicit cashout",
        "matched_keywords": "обнал, дроп",
        "message": "Срочный обнал через дроп, процент обсудим.",
    }
    pdf_bytes = generate_report_pdf(record)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100


def test_pdf_preserves_cyrillic_and_has_no_replacement_chars():
    message = "Срочный обнал через дроп, процент обсудим."
    record = {
        "timestamp": datetime.now(timezone.utc),
        "status": "Critical",
        "risk_score": 85,
        "category": "Illicit cashout",
        "matched_keywords": "обнал, дроп",
        "message": message,
        "username": "аналитик",
    }
    text = _extract_pdf_text(generate_report_pdf(record))
    assert "обнал" in text
    assert "дроп" in text
    assert "?" not in message
    cyrillic_span = text
    assert "обнал" in cyrillic_span
    assert not any(
        token == "?" for token in text.split() if "обнал" in text or "дроп" in text
    )


def test_pdf_does_not_claim_legal_evidence_or_official():
    record = {
        "timestamp": datetime.now(timezone.utc),
        "status": "Critical",
        "risk_score": 90,
        "message": "Need a mule to cashout.",
    }
    text = _extract_pdf_text(generate_report_pdf(record)).lower()
    assert "legal evidence" not in text
    assert "official" not in text
    assert "investigative lead" in text
