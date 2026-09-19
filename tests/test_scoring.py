"""Keyword scoring, status thresholds, and category mapping."""

from __future__ import annotations

import time

from guardian_core import (
    analyze_with_gpt,
    apply_wallet_enrichment,
    build_records,
    category_from_keywords,
    score_keywords,
    status_from_score,
)


def test_english_keywords_score_and_status():
    cases = {
        "cashout tonight": (35, "Safe"),
        "need a mule": (40, "Suspicious"),
        "no kyc cards": (30, "Safe"),
        "washing funds": (35, "Safe"),
        "clean cash offer": (45, "Suspicious"),
    }
    for text, (score, status) in cases.items():
        got_score, matched = score_keywords(text)
        assert got_score == score, text
        assert status_from_score(got_score) == status, text
        assert matched


def test_combined_english_keywords_are_critical():
    score, matched = score_keywords("Need a mule to cashout USDT")
    assert score >= 70
    assert status_from_score(score) == "Critical"
    assert "mule" in matched
    assert "cashout" in matched


def test_russian_keywords_score_and_status():
    cases = {
        "нужен обнал": (45, "Suspicious"),
        "ищем дроп": (40, "Suspicious"),
        "нужен залив": (40, "Suspicious"),
        "вывод средств": (30, "Safe"),
        "работа для студентов вечером": (40, "Suspicious"),
    }
    for text, (score, status) in cases.items():
        got_score, matched = score_keywords(text)
        assert got_score == score, (text, got_score, matched)
        assert status_from_score(got_score) == status, text
        assert matched


def test_no_keywords_is_safe_zero():
    score, matched = score_keywords("Anyone selling concert tickets for Saturday?")
    assert score == 0
    assert matched == []
    assert status_from_score(score) == "Safe"


def test_category_from_keywords_mapping():
    assert category_from_keywords(["mule"]) == "Money mule recruitment"
    assert category_from_keywords(["дроп"]) == "Money mule recruitment"
    assert category_from_keywords(["cashout"]) == "Illicit cashout"
    assert category_from_keywords(["обнал"]) == "Illicit cashout"
    assert category_from_keywords(["залив"]) == "Illicit cashout"
    assert category_from_keywords(["вывод"]) == "Illicit cashout"
    assert category_from_keywords(["washing"]) == "Money laundering"
    assert category_from_keywords(["no kyc"]) == "KYC evasion"
    assert category_from_keywords([]) == "None"


def test_analyze_with_gpt_short_circuits_without_key(monkeypatch):
    constructed = []

    class Boom:
        def __init__(self, *args, **kwargs):
            constructed.append(True)
            raise AssertionError("OpenAI client must not be constructed")

    monkeypatch.setattr("openai.OpenAI", Boom, raising=False)
    rows, note = analyze_with_gpt(["hello"], "")
    assert rows == [{}]
    assert note is None
    assert constructed == []

    records = [{"message": f"hello {i}", "group": "g"} for i in range(50)]
    built, _note = build_records(records, "")
    assert len(built) == 50
    assert constructed == []


def test_profile_keyword_scoring_vs_wallet_enrichment(monkeypatch, capsys):
    records = [
        {
            "message": f"Need a mule cashout batch {i}",
            "group": "g",
            "user_id": str(i),
            "username": "u",
        }
        for i in range(50)
    ]
    start = time.perf_counter()
    built, _note = build_records(records, "")
    keyword_ms = (time.perf_counter() - start) * 1000

    class FakeResponse:
        def json(self):
            return {"status": "1", "result": [{"timeStamp": "1700000000"}]}

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: FakeResponse())
    wallet_records = [
        {
            **row,
            "message": (
                f"Pay 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 batch {i}"
            ),
            "wallets": ["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"],
        }
        for i, row in enumerate(records)
    ]
    start = time.perf_counter()
    apply_wallet_enrichment(wallet_records, "fake-etherscan-key")
    enrich_ms = (time.perf_counter() - start) * 1000
    print(
        f"\nPROFILE build_records(50)={keyword_ms:.1f}ms "
        f"apply_wallet_enrichment(50 mocked)={enrich_ms:.1f}ms"
    )
    assert len(built) == 50
    assert keyword_ms >= 0
    assert enrich_ms >= 0
