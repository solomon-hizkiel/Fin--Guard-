"""Local API so the Chrome extension can submit flagged text to Fin-Guardian.

Does not replace the Streamlit dashboard or Telegram bots. Run:

    python setup.py
    python api_server.py
"""

from __future__ import annotations

from flask import Flask, jsonify, request
from flask_cors import CORS

from guardian_core import init_database, persist_flagged, score_report

app = Flask(__name__)
CORS(app)

init_database()


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/report")
def report():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "text is required"}), 400

    text = str(payload.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400

    url = str(payload.get("url") or "").strip()
    _source_page_title = str(payload.get("source_page_title") or "").strip()

    record = score_report(
        text,
        group=url or "browser-extension",
        username="extension-user",
        platform="Browser Extension",
    )
    saved = False
    if record.get("status") in {"Critical", "Suspicious"}:
        persist_flagged([record])
        saved = True

    return jsonify(
        {
            "risk_score": record.get("risk_score"),
            "status": record.get("status"),
            "category": record.get("category"),
            "wallet_flag": record.get("wallet_flag") or "",
            "saved": saved,
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
