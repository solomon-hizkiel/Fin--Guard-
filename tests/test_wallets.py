"""Ethereum address extraction and Etherscan enrichment."""

from __future__ import annotations

from datetime import datetime, timezone

import guardian_core
from guardian_core import (
    build_records,
    enrich_eth_wallet,
    find_eth_wallets,
)

VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def test_find_eth_wallets_extracts_valid_address():
    text = f"Need a mule tonight. Pay {VITALIK} after cashout."
    assert find_eth_wallets(text) == [VITALIK]


def test_find_eth_wallets_rejects_near_misses():
    assert find_eth_wallets("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045") == []
    assert find_eth_wallets("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA9604") == []
    assert find_eth_wallets("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045aa") == []
    assert find_eth_wallets("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045zzz") == []


def test_wallet_in_message_forces_critical(sample_raw_messages):
    records, _note = build_records([sample_raw_messages["wallet"]], "")
    assert len(records) == 1
    assert records[0]["risk_score"] >= 85
    assert records[0]["status"] == "Critical"
    assert VITALIK in records[0]["wallets"]


def test_enrich_eth_wallet_parses_tx_count_and_last_active(monkeypatch):
    guardian_core._ENRICH_CACHE.clear()

    class FakeResponse:
        def json(self):
            return {
                "status": "1",
                "result": [{"timeStamp": "1700000000"}, {"timeStamp": "1690000000"}],
            }

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: FakeResponse())
    info = enrich_eth_wallet(VITALIK, "fake-key")
    assert info["ok"] is True
    assert info["tx_count"] == 2
    assert isinstance(info["last_active"], datetime)
    assert info["last_active"].tzinfo == timezone.utc


def test_enrich_eth_wallet_malformed_response_returns_ok_false(monkeypatch):
    guardian_core._ENRICH_CACHE.clear()

    class BadJson:
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: BadJson())
    info = enrich_eth_wallet(VITALIK, "fake-key")
    assert info["ok"] is False
    assert info["tx_count"] == 0


def test_enrich_eth_wallet_error_status_returns_ok_false(monkeypatch):
    guardian_core._ENRICH_CACHE.clear()

    class FakeResponse:
        def json(self):
            return {"status": "0", "message": "NOTOK", "result": "rate limit"}

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: FakeResponse())
    info = enrich_eth_wallet(VITALIK, "fake-key")
    assert info["ok"] is False
    assert info["tx_count"] == 0


def test_enrich_eth_wallet_non_dict_payload_returns_ok_false(monkeypatch):
    guardian_core._ENRICH_CACHE.clear()

    class FakeResponse:
        def json(self):
            return ["not", "a", "dict"]

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: FakeResponse())
    info = enrich_eth_wallet(VITALIK, "fake-key")
    assert info["ok"] is False
