"""Fin-Guardian: real-time financial crime detection dashboard.

Scans public Telegram groups for money-mule recruitment and illicit
financial offers. Detection and evidence export only.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import io
import math
import queue
import re
import sqlite3
import struct
import threading
import wave
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from telethon import TelegramClient, events

from guardian_core import (
    COMMUNITY_SOURCE,
    SUSPICIOUS_THRESHOLD,
    TELEGRAM_BOT_SOURCE,
    TELEGRAM_SOURCE,
    analyze_with_gpt,
    apply_wallet_enrichment,
    build_records as core_build_records,
    category_from_keywords,
    enrich_eth_wallet,
    fetch_category_counts,
    fetch_community_reports,
    fetch_detections,
    fetch_hourly_trend,
    fetch_offender_history,
    fetch_offenders,
    generate_report_pdf,
    init_database,
    lead_report_filename,
    normalize_category,
    persist_flagged,
    score_keywords,
    score_live_record,
    status_from_score,
)
from telethon.errors import (
    ApiIdInvalidError,
    AuthKeyDuplicatedError,
    AuthKeyUnregisteredError,
    ChannelPrivateError,
    FloodWaitError,
    PasswordHashInvalidError,
    PhoneCodeEmptyError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    RPCError,
    SecurityError,
    SessionPasswordNeededError,
    UsernameInvalidError,
    UsernameNotOccupiedError,
)

APP_DIR = Path(__file__).resolve().parent
SESSION_PATH = APP_DIR / "fin_guardian"
MESSAGE_LIMIT = 300
SESSION_FILE = SESSION_PATH.with_suffix(".session")
CREDENTIALS_FILE = APP_DIR / ".fin_guardian_credentials.json"
# Caps on-screen live table rows only; monitoring and persist_flagged() are unaffected.
LIVE_RESULT_LIMIT = 1000
ONE_TIME_MODE = "One-time scan"
LIVE_MODE = "Live monitoring"
DATA_SOURCES = (TELEGRAM_SOURCE, COMMUNITY_SOURCE)
CREDENTIAL_FIELDS = (
    "api_id",
    "api_hash",
    "phone",
    "telegram_password",
    "openai_key",
    "etherscan_key",
    "group",
    "live_groups",
)

UI_STRINGS = {
    "en": {
        "language": "Language / Язык",
        "control_center": "Control center",
        "data_source": "Data source",
        "source_telegram": "Telegram Intelligence",
        "source_discord": "Discord Intelligence",
        "source_community": "Community Reports",
        "source_telegram_bot": "Telegram Bot Reports",
        "source_active": "Active source: {source}",
        "credentials_saved_caption": (
            "Keys stay in this browser tab only. Refresh keeps them. "
            "Close the page and you will need to enter API ID, hash, phone, and passwords again."
        ),
        "etherscan_key": "Etherscan API Key",
        "etherscan_help": (
            "Optional. Enriches detected 0x wallets with on-chain activity. "
            "Leave blank to show the address only."
        ),
        "mode": "Mode",
        "one_time_scan": "One-time scan",
        "live_monitoring": "Live monitoring",
        "api_id": "API ID",
        "api_hash": "API hash",
        "phone": "Phone number",
        "telegram_password": "Password",
        "telegram_password_help": "Telegram two-step verification password, if enabled.",
        "openai_key": "OpenAI API key",
        "openai_help": "Optional. Enables GPT-4o intent analysis.",
        "public_groups": "Public groups",
        "public_groups_help": "Monitor several public groups at once. Separate with commas or new lines.",
        "public_group": "Public group",
        "placeholder_group": "@username or t.me/username",
        "placeholder_groups": "@group1\n@group2\nhttps://t.me/group3",
        "login_code": "Telegram login code",
        "login_code_help": "Enter the one-time code Telegram just sent you.",
        "submit_code": "Submit code",
        "submit_password": "Submit password",
        "start_monitoring": "Start monitoring",
        "scan_group": "Scan group",
        "stop_monitoring": "Stop monitoring",
        "stopping_live": "Stopping live monitor",
        "listening_to": "Listening to {groups}…",
        "groups_fallback": "groups",
        "load_samples": "Load sample results",
        "reset_session": "Reset Telegram session",
        "session_cleared": "Telegram login was cleared. Saved API fields were kept.",
        "forget_credentials": "Forget saved credentials",
        "public_groups_only": "Public groups only. Detection and evidence export — not operational advice.",
        "err_need_api": "Enter Telegram API ID, API hash, and phone number.",
        "err_api_id_number": "API ID must be a number.",
        "err_need_group": "Enter a public Telegram group username.",
        "err_need_code": "Enter the login code sent to your Telegram account.",
        "err_need_password": "Enter your Telegram two-step verification password.",
        "err_stop_live_for_scan": (
            "Stop live monitoring before running a one-time scan. "
            "Both cannot share the same Telegram session."
        ),
        "err_live_already": "Live monitoring is already running.",
        "err_at_least_one_group": "Enter at least one public group username.",
        "err_enter_group": "Enter a public group username or t.me link.",
        "err_no_invite": "Private invite links are not supported. Use a public @username.",
        "err_bad_link": "Could not read a public username from that link.",
        "err_password_required": (
            "This Telegram account has two-step verification enabled. "
            "Enter your password in the sidebar and scan again."
        ),
        "err_password_wrong": (
            "The Telegram password is incorrect. "
            "Check your two-step verification password and try again."
        ),
        "err_code_invalid": (
            "That Telegram login code is invalid or expired. Request a new one and try again."
        ),
        "err_login_incomplete": (
            "Could not complete Telegram login. Enter the login code and password, then try again."
        ),
        "err_session_expired": (
            "The saved Telegram session expired and was cleared. Scan again to log in."
        ),
        "err_session_expired_live": (
            "The saved Telegram session expired and was cleared. Log in again with a one-time scan."
        ),
        "err_api_invalid": "API ID or API hash is invalid. Check my.telegram.org.",
        "err_phone_invalid": (
            "That phone number is invalid. Use international format, like +447700900000."
        ),
        "err_flood_wait": "Telegram rate limit. Wait {seconds} seconds and try again.",
        "err_group_private": "That group is private. Fin-Guardian only scans public groups.",
        "err_group_private_live": "One of the groups is private. Live monitoring only supports public groups.",
        "err_group_not_found": "No public Telegram group was found for that username.",
        "err_group_not_found_live": "One of the group usernames could not be found.",
        "err_session_locked": (
            "Telegram session file is locked. Close other Fin-Guardian windows and try again."
        ),
        "err_session_locked_live": (
            "Telegram session file is locked. Stop any other scan and try again."
        ),
        "err_session_conflict": (
            "This Telegram login is already in use in another Fin-Guardian window. "
            "Close extra dashboards, click Reset Telegram session, then log in once."
        ),
        "err_session_conflict_live": (
            "This Telegram login is already in use in another Fin-Guardian window. "
            "Stop live monitoring, close extra dashboards, reset the session, then log in once."
        ),
        "err_telegram_network": (
            "Cannot reach Telegram. Check your internet connection, VPN, or firewall, then try again."
        ),
        "err_telegram_api": "Telegram API error: {exc}",
        "err_login_not_finished": (
            "Telegram login is not finished. Click Start monitoring again, "
            "enter the login code Telegram sends you, then submit."
        ),
        "err_generic": "Unexpected error: {exc}",
        "talking_telegram": "Talking to Telegram…",
        "connecting": "Connecting…",
        "scan_failed": "Scan failed",
        "could_not_scan": "Could not complete the scan: {exc}",
        "login_code_required": "Login code required",
        "login_code_sent": "Telegram sent a login code. Enter it in the sidebar and submit.",
        "password_required": "Password required",
        "enter_2fa": "Now enter your two-step verification password in the sidebar.",
        "scoring_messages": "Scoring messages…",
        "scan_complete": "Scan complete",
        "signing_in": "Signing in to Telegram…",
        "checking_session": "Checking saved Telegram session…",
        "login_failed": "Login failed",
        "could_not_login": "Could not log in: {exc}",
        "login_code_sent_live": (
            "Telegram sent a login code to your app. Type that code in the sidebar and click Submit code."
        ),
        "enter_2fa_live": (
            "Enter your Telegram two-step password in the Password field and click Submit password."
        ),
        "starting_listeners": "Starting live listeners…",
        "live_started": "Logged in. Live monitoring started for {count} public group(s).",
        "lead_pdf_failed": "Could not build the lead report PDF: {exc}",
        "export_lead_pdf": "📄 Export Lead Report (PDF)",
        "export_lead_pdf_status": "📄 Export Lead Report (PDF) · {status}",
        "lead_reports_caption": "Lead reports are automated analyst notes. They are not legal evidence.",
        "expander_lead_reports": "📄 Export lead reports",
        "col_timestamp": "Timestamp",
        "col_message": "Message",
        "col_risk_score": "Risk score",
        "col_status": "Status",
        "col_category": "Category",
        "col_username": "Username",
        "col_wallet": "Wallet",
        "col_lead_report": "Lead report",
        "col_group": "Group",
        "col_source": "Source",
        "col_user_id": "User ID",
        "col_incidents": "Incidents",
        "col_groups": "Groups",
        "col_group_history": "Group history",
        "col_last_seen": "Last seen",
        "metric_listening": "Listening",
        "metric_live_messages": "Live messages",
        "metric_high_risk": "High risk detected",
        "metric_critical_alarms": "Critical alarms",
        "metric_total_scanned": "Total scanned",
        "metric_safe": "Safe messages",
        "monitor_stopped": "stopped",
        "monitor_starting": "starting",
        "monitor_running": "running",
        "monitor_error": "error",
        "risk_alarm": "Risk alarm: critical threat in @{group}. {preview}",
        "critical_threat_detected": "Critical threat detected",
        "watching_live": "Watching {listening}. New messages appear at the top as they are sent.",
        "download_live_evidence": "Download live evidence report",
        "live_ready_hint": (
            "Fill API ID, API hash, phone, and password, then click Start monitoring. "
            "If Telegram asks for a login code, type it in the sidebar and click Submit code. "
            "Your fields are saved on this computer after that."
        ),
        "shared_inbox": "Shared detection inbox",
        "shared_inbox_caption": (
            "Suspicious and critical rows from the Telegram scraper and the report bot, "
            "stored together in fin_guardian.db."
        ),
        "inbox_empty": "No flagged messages in the database yet. Scan a group or send a report to the bot.",
        "enter_credentials_hint": (
            "Enter credentials in the sidebar and scan a public group to load the latest 300 messages."
        ),
        "detection_results": "Detection results",
        "last_messages_from": "Last {limit} messages from @{group} · {when}",
        "just_now": "just now",
        "risk_distribution": "Risk distribution",
        "download_evidence": "Download evidence report",
        "community_reports": "Community reports",
        "community_reports_caption": (
            "Tips from the dashboard and from report_bot.py. "
            "Every flagged report is saved to fin_guardian.db with scraper detections."
        ),
        "reports_loaded": "{count} report(s) loaded from fin_guardian.db.",
        "submit_community_tip": "Submit a community tip",
        "community_tip_placeholder": "Describe a suspected mule, cashout, or no-kyc offer…",
        "score_community_tip": "Score community tip",
        "community_detections": "Community detections",
        "community_detections_caption": (
            "Tips are treated as intelligence reports. "
            "Critical and suspicious tips can export a lead report PDF."
        ),
        "suspect_database": "Suspect database",
        "suspect_database_caption": (
            "Critical detections only. Ranked by how often the same user appears across groups."
        ),
        "no_suspects": (
            "No critical suspects yet. Run a scan, live monitor, or the Telegram report bot."
        ),
        "offender_history": "Offender history",
        "offender_label": "{username} ({user_id}) · {incidents} hits",
        "trends_analytics": "Trends & analytics",
        "trends_caption": "Flagged messages stored in SQLite: critical and suspicious detections.",
        "plotly_missing": "Plotly is not installed. Run python setup.py, then refresh.",
        "crimes_by_category": "Crimes by category",
        "axis_category": "Category",
        "axis_flagged": "Flagged messages",
        "axis_count": "Count",
        "suspicious_activity_24h": "Suspicious activity · last 24 hours",
        "axis_hour": "Hour (UTC)",
        "axis_suspicious_critical": "Suspicious and critical messages",
        "page_title": "Financial crime detection",
        "page_caption": (
            "Real-time dashboard for public Telegram groups. Flags money-mule recruitment "
            "and illegal financial offers for investigator review."
        ),
        "tab_detection": "Detection",
        "tab_suspects": "Suspect database",
        "tab_trends": "Trends & analytics",
        "status_critical": "Critical",
        "status_suspicious": "Suspicious",
        "status_safe": "Safe",
        "cat_mule": "Money mule",
        "cat_cashout": "Cashout",
        "cat_laundering": "Laundering",
        "cat_kyc": "KYC evasion",
        "cat_none": "None",
        "unknown_group": "unknown",
    },
    "ru": {
        "language": "Language / Язык",
        "control_center": "Центр управления",
        "data_source": "Источник данных",
        "source_telegram": "Разведданные Telegram",
        "source_discord": "Разведданные Discord",
        "source_community": "Сообщения сообщества",
        "source_telegram_bot": "Сообщения бота Telegram",
        "source_active": "Активный источник: {source}",
        "credentials_saved_caption": (
            "Ключи остаются только в этой вкладке. Обновление страницы их сохраняет. "
            "Если закрыть страницу, API ID, hash, телефон и пароли нужно ввести снова."
        ),
        "etherscan_key": "Ключ API Etherscan",
        "etherscan_help": (
            "Необязательно. Обогащает обнаруженные кошельки 0x данными ончейн-активности. "
            "Оставьте пустым, чтобы показывать только адрес."
        ),
        "mode": "Режим",
        "one_time_scan": "Однократное сканирование",
        "live_monitoring": "Непрерывный мониторинг",
        "api_id": "API ID",
        "api_hash": "API hash",
        "phone": "Номер телефона",
        "telegram_password": "Пароль",
        "telegram_password_help": "Пароль двухэтапной аутентификации Telegram, если он включён.",
        "openai_key": "Ключ API OpenAI",
        "openai_help": "Необязательно. Включает анализ намерения с помощью GPT-4o.",
        "public_groups": "Открытые группы",
        "public_groups_help": (
            "Мониторинг нескольких открытых групп одновременно. "
            "Разделяйте запятыми или переносами строк."
        ),
        "public_group": "Открытая группа",
        "placeholder_group": "@username или t.me/username",
        "placeholder_groups": "@group1\n@group2\nhttps://t.me/group3",
        "login_code": "Код входа Telegram",
        "login_code_help": "Введите одноразовый код, который Telegram только что отправил.",
        "submit_code": "Отправить код",
        "submit_password": "Отправить пароль",
        "start_monitoring": "Начать мониторинг",
        "scan_group": "Сканировать группу",
        "stop_monitoring": "Остановить мониторинг",
        "stopping_live": "Остановка мониторинга",
        "listening_to": "Прослушивание {groups}…",
        "groups_fallback": "группы",
        "load_samples": "Загрузить примеры",
        "reset_session": "Сбросить сессию Telegram",
        "session_cleared": "Вход в Telegram сброшен. Сохранённые поля API оставлены без изменений.",
        "forget_credentials": "Забыть сохранённые учётные данные",
        "public_groups_only": (
            "Только открытые группы. Выявление и выгрузка доказательств — без операционных рекомендаций."
        ),
        "err_need_api": "Укажите Telegram API ID, API hash и номер телефона.",
        "err_api_id_number": "API ID должен быть числом.",
        "err_need_group": "Укажите имя открытой группы Telegram.",
        "err_need_code": "Введите код входа, отправленный в ваш аккаунт Telegram.",
        "err_need_password": "Введите пароль двухэтапной аутентификации Telegram.",
        "err_stop_live_for_scan": (
            "Остановите непрерывный мониторинг перед однократным сканированием. "
            "Оба режима не могут использовать одну сессию Telegram."
        ),
        "err_live_already": "Непрерывный мониторинг уже запущен.",
        "err_at_least_one_group": "Укажите хотя бы одно имя открытой группы.",
        "err_enter_group": "Укажите имя открытой группы или ссылку t.me.",
        "err_no_invite": "Приватные пригласительные ссылки не поддерживаются. Используйте публичный @username.",
        "err_bad_link": "Не удалось извлечь публичное имя пользователя из этой ссылки.",
        "err_password_required": (
            "У этого аккаунта Telegram включена двухэтапная аутентификация. "
            "Введите пароль в боковой панели и повторите сканирование."
        ),
        "err_password_wrong": (
            "Неверный пароль Telegram. "
            "Проверьте пароль двухэтапной аутентификации и повторите попытку."
        ),
        "err_code_invalid": (
            "Код входа Telegram недействителен или истёк. Запросите новый код и повторите попытку."
        ),
        "err_login_incomplete": (
            "Не удалось завершить вход в Telegram. Введите код и пароль, затем повторите попытку."
        ),
        "err_session_expired": (
            "Сохранённая сессия Telegram истекла и была сброшена. Выполните сканирование, чтобы войти снова."
        ),
        "err_session_expired_live": (
            "Сохранённая сессия Telegram истекла и была сброшена. Войдите снова через однократное сканирование."
        ),
        "err_api_invalid": "Недействительный API ID или API hash. Проверьте данные на my.telegram.org.",
        "err_phone_invalid": (
            "Недействительный номер телефона. Используйте международный формат, например +447700900000."
        ),
        "err_flood_wait": "Лимит запросов Telegram. Подождите {seconds} с и повторите попытку.",
        "err_group_private": "Эта группа закрытая. Fin-Guardian сканирует только открытые группы.",
        "err_group_private_live": (
            "Одна из групп закрытая. Непрерывный мониторинг поддерживает только открытые группы."
        ),
        "err_group_not_found": "Открытая группа Telegram с таким именем не найдена.",
        "err_group_not_found_live": "Одно из имён групп не найдено.",
        "err_session_locked": (
            "Файл сессии Telegram заблокирован. Закройте другие окна Fin-Guardian и повторите попытку."
        ),
        "err_session_locked_live": (
            "Файл сессии Telegram заблокирован. Остановите другое сканирование и повторите попытку."
        ),
        "err_session_conflict": (
            "Этот вход Telegram уже используется в другом окне Fin-Guardian. "
            "Закройте лишние панели, нажмите «Сбросить сессию Telegram» и войдите один раз."
        ),
        "err_session_conflict_live": (
            "Этот вход Telegram уже используется в другом окне Fin-Guardian. "
            "Остановите мониторинг, закройте лишние панели, сбросьте сессию и войдите один раз."
        ),
        "err_telegram_network": (
            "Нет связи с Telegram. Проверьте интернет, VPN или брандмауэр и повторите попытку."
        ),
        "err_telegram_api": "Ошибка API Telegram: {exc}",
        "err_login_not_finished": (
            "Вход в Telegram не завершён. Снова нажмите «Начать мониторинг», "
            "введите код, который отправит Telegram, и подтвердите его."
        ),
        "err_generic": "Непредвиденная ошибка: {exc}",
        "talking_telegram": "Обращение к Telegram…",
        "connecting": "Подключение…",
        "scan_failed": "Сканирование не удалось",
        "could_not_scan": "Не удалось завершить сканирование: {exc}",
        "login_code_required": "Требуется код входа",
        "login_code_sent": "Telegram отправил код входа. Введите его в боковой панели и подтвердите.",
        "password_required": "Требуется пароль",
        "enter_2fa": "Теперь введите пароль двухэтапной аутентификации в боковой панели.",
        "scoring_messages": "Оценка сообщений…",
        "scan_complete": "Сканирование завершено",
        "signing_in": "Вход в Telegram…",
        "checking_session": "Проверка сохранённой сессии Telegram…",
        "login_failed": "Вход не выполнен",
        "could_not_login": "Не удалось войти: {exc}",
        "login_code_sent_live": (
            "Telegram отправил код входа в приложение. Введите его в боковой панели и нажмите «Отправить код»."
        ),
        "enter_2fa_live": (
            "Введите пароль двухэтапной аутентификации Telegram в поле «Пароль» и нажмите «Отправить пароль»."
        ),
        "starting_listeners": "Запуск прослушивания…",
        "live_started": "Вход выполнен. Непрерывный мониторинг запущен для {count} открытых групп.",
        "lead_pdf_failed": "Не удалось сформировать PDF-отчёт по лиду: {exc}",
        "export_lead_pdf": "📄 Выгрузить отчёт по лиду (PDF)",
        "export_lead_pdf_status": "📄 Выгрузить отчёт по лиду (PDF) · {status}",
        "lead_reports_caption": (
            "Отчёты по лидам — автоматические заметки аналитика. Это не юридические доказательства."
        ),
        "expander_lead_reports": "📄 Выгрузка отчётов по лидам",
        "col_timestamp": "Метка времени",
        "col_message": "Сообщение",
        "col_risk_score": "Оценка риска",
        "col_status": "Статус",
        "col_category": "Категория",
        "col_username": "Имя пользователя",
        "col_wallet": "Кошелёк",
        "col_lead_report": "Отчёт по лиду",
        "col_group": "Группа",
        "col_source": "Источник",
        "col_user_id": "ID пользователя",
        "col_incidents": "Инциденты",
        "col_groups": "Группы",
        "col_group_history": "История групп",
        "col_last_seen": "Последняя фиксация",
        "metric_listening": "Прослушивание",
        "metric_live_messages": "Сообщения в реальном времени",
        "metric_high_risk": "Выявлен высокий риск",
        "metric_critical_alarms": "Критические тревоги",
        "metric_total_scanned": "Всего просканировано",
        "metric_safe": "Безопасные сообщения",
        "monitor_stopped": "остановлен",
        "monitor_starting": "запуск",
        "monitor_running": "работает",
        "monitor_error": "ошибка",
        "risk_alarm": "Тревога: критическая угроза в @{group}. {preview}",
        "critical_threat_detected": "Обнаружена критическая угроза",
        "watching_live": "Наблюдение: {listening}. Новые сообщения появляются сверху по мере поступления.",
        "download_live_evidence": "Скачать отчёт доказательств (мониторинг)",
        "live_ready_hint": (
            "Укажите API ID, API hash, телефон и пароль, затем нажмите «Начать мониторинг». "
            "Если Telegram запросит код входа, введите его в боковой панели и нажмите «Отправить код». "
            "После этого поля сохраняются на этом компьютере."
        ),
        "shared_inbox": "Общий журнал детекций",
        "shared_inbox_caption": (
            "Подозрительные и критические записи со скрапера Telegram и бота жалоб, "
            "хранящиеся вместе в fin_guardian.db."
        ),
        "inbox_empty": (
            "В базе пока нет отмеченных сообщений. Просканируйте группу или отправьте сигнал боту."
        ),
        "enter_credentials_hint": (
            "Введите учётные данные в боковой панели и просканируйте открытую группу, "
            "чтобы загрузить последние 300 сообщений."
        ),
        "detection_results": "Результаты выявления",
        "last_messages_from": "Последние {limit} сообщений из @{group} · {when}",
        "just_now": "только что",
        "risk_distribution": "Распределение риска",
        "download_evidence": "Скачать отчёт доказательств",
        "community_reports": "Сообщения сообщества",
        "community_reports_caption": (
            "Сигналы с панели и из report_bot.py. "
            "Каждый отмеченный сигнал сохраняется в fin_guardian.db вместе с детекциями скрапера."
        ),
        "reports_loaded": "Загружено сигналов из fin_guardian.db: {count}.",
        "submit_community_tip": "Отправить сигнал сообщества",
        "community_tip_placeholder": "Опишите предполагаемую вербовку мула, обнал или предложение без KYC…",
        "score_community_tip": "Оценить сигнал сообщества",
        "community_detections": "Детекции сообщества",
        "community_detections_caption": (
            "Сигналы обрабатываются как разведсведения. "
            "По критическим и подозрительным сигналам можно выгрузить PDF-отчёт по лиду."
        ),
        "suspect_database": "База подозреваемых",
        "suspect_database_caption": (
            "Только критические детекции. Ранжирование по частоте появления одного пользователя в группах."
        ),
        "no_suspects": (
            "Критических фигурантов пока нет. Запустите сканирование, мониторинг или бота жалоб Telegram."
        ),
        "offender_history": "История фигуранта",
        "offender_label": "{username} ({user_id}) · {incidents} срабатываний",
        "trends_analytics": "Тренды и аналитика",
        "trends_caption": "Отмеченные сообщения в SQLite: критические и подозрительные детекции.",
        "plotly_missing": "Plotly не установлен. Выполните python setup.py и обновите страницу.",
        "crimes_by_category": "Преступления по категориям",
        "axis_category": "Категория",
        "axis_flagged": "Отмеченные сообщения",
        "axis_count": "Количество",
        "suspicious_activity_24h": "Подозрительная активность · последние 24 часа",
        "axis_hour": "Час (UTC)",
        "axis_suspicious_critical": "Подозрительные и критические сообщения",
        "page_title": "Выявление финансовых преступлений",
        "page_caption": (
            "Оперативная панель по открытым группам Telegram. Фиксирует вербовку денежных мулов "
            "и незаконные финансовые предложения для проверки следователем."
        ),
        "tab_detection": "Детекция",
        "tab_suspects": "База подозреваемых",
        "tab_trends": "Тренды и аналитика",
        "status_critical": "Критический",
        "status_suspicious": "Подозрительный",
        "status_safe": "Безопасный",
        "cat_mule": "Денежный мул",
        "cat_cashout": "Обнал",
        "cat_laundering": "Отмывание",
        "cat_kyc": "Обход KYC",
        "cat_none": "Нет",
        "unknown_group": "неизвестно",
    },
}

LANG_LABELS = {"English": "en", "Русский": "ru"}
LANG_CODES = {"en": "English", "ru": "Русский"}


class UiMessage(ValueError):
    """Raised off the UI thread with a translation key instead of English text."""

    def __init__(self, key: str, **kwargs: Any) -> None:
        self.key = key
        self.kwargs = kwargs
        super().__init__(key)


def ui_lang() -> str:
    lang = st.session_state.get("ui_lang", "en")
    return lang if lang in UI_STRINGS else "en"


def t(key: str, **kwargs: Any) -> str:
    table = UI_STRINGS.get(ui_lang(), UI_STRINGS["en"])
    template = table.get(key) or UI_STRINGS["en"].get(key, key)
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError):
            return template
    return template


def error_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, UiMessage):
        return t(payload.key, **payload.kwargs)
    if isinstance(payload, dict):
        key = payload.get("message_key")
        if key:
            return t(key, **(payload.get("message_args") or {}))
        message = str(payload.get("message") or "")
        if message in UI_STRINGS["en"]:
            return t(message)
        return message
    text = str(payload)
    if text in UI_STRINGS["en"]:
        return t(text)
    return text


def keyed_error(key: str, **kwargs: Any) -> dict[str, Any]:
    return {"status": "error", "message_key": key, "message_args": kwargs}


STATUS_LABELS = {
    "Critical": "🔴 Critical",
    "Suspicious": "🟠 Suspicious",
    "Safe": "🟢 Safe",
}

CATEGORY_LABELS = {
    "Money mule recruitment": "🔴 Money mule",
    "Illicit cashout": "🟠 Cashout",
    "Money laundering": "🟣 Laundering",
    "KYC evasion": "🔵 KYC evasion",
    "None": "⚪ None",
}


def status_labels() -> dict[str, str]:
    return {
        "Critical": f"🔴 {t('status_critical')}",
        "Suspicious": f"🟠 {t('status_suspicious')}",
        "Safe": f"🟢 {t('status_safe')}",
    }


def category_labels() -> dict[str, str]:
    return {
        "Money mule recruitment": f"🔴 {t('cat_mule')}",
        "Illicit cashout": f"🟠 {t('cat_cashout')}",
        "Money laundering": f"🟣 {t('cat_laundering')}",
        "KYC evasion": f"🔵 {t('cat_kyc')}",
        "None": f"⚪ {t('cat_none')}",
    }


def labeled_status(value: Any) -> str:
    text = str(value or "")
    return status_labels().get(text, STATUS_LABELS.get(text, text))


def labeled_category(value: Any) -> str:
    key = normalize_category(value)
    labels = category_labels()
    return labels.get(key, CATEGORY_LABELS.get(key, labels["None"]))


def source_label(source: str) -> str:
    mapping = {
        TELEGRAM_SOURCE: t("source_telegram"),
        COMMUNITY_SOURCE: t("source_community"),
        TELEGRAM_BOT_SOURCE: t("source_telegram_bot"),
        "Discord Intelligence": t("source_discord"),
    }
    return mapping.get(source, source)


def labeled_platform(value: Any) -> str:
    return source_label(str(value or ""))


def select_translated(
    label: str,
    values: list[str],
    format_value,
    state_key: str,
) -> str:
    """Show translated option labels while storing the English value in session state."""
    current = st.session_state.get(state_key, values[0])
    if current not in values:
        current = values[0]
        st.session_state[state_key] = current
    labels = [format_value(item) for item in values]
    selected_label = st.selectbox(
        label,
        labels,
        index=values.index(current),
        key=f"{state_key}__ui_{ui_lang()}",
    )
    chosen = values[labels.index(selected_label)]
    st.session_state[state_key] = chosen
    return chosen


def monitor_status_label(status: str) -> str:
    key = f"monitor_{status}"
    if key in UI_STRINGS["en"]:
        return t(key)
    return status


def status_label(status: str) -> str:
    mapping = {
        "Critical": t("status_critical"),
        "Suspicious": t("status_suspicious"),
        "Safe": t("status_safe"),
    }
    return mapping.get(status, status)



def build_alarm_wav() -> bytes:
    rate = 22050
    duration = 0.55
    n_frames = int(rate * duration)
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        frames = bytearray()
        for index in range(n_frames):
            freq = 880 if index < n_frames // 2 else 1245
            sample = int(0.38 * 32767 * math.sin(2 * math.pi * freq * index / rate))
            frames += struct.pack("<h", sample)
        wav.writeframes(frames)
    return buffer.getvalue()


ALARM_WAV = build_alarm_wav()


def community_sample_records() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": now,
            "group": "community-tip",
            "user_id": "c-301",
            "username": "tipster_north",
            "platform": COMMUNITY_SOURCE,
            "message": "Report: recruiter asking students to be a mule and cashout wages.",
        },
        {
            "timestamp": now,
            "group": "community-tip",
            "user_id": "c-302",
            "username": "bank_watch",
            "platform": COMMUNITY_SOURCE,
            "message": "Anonymous tip about washing / clean cash ads in a local group.",
        },
        {
            "timestamp": now,
            "group": "community-tip",
            "user_id": "c-303",
            "username": "neighbor",
            "platform": COMMUNITY_SOURCE,
            "message": "Someone is selling concert tickets near the station.",
        },
    ]


def load_community_reports() -> list[dict[str, Any]]:
    """Load bot and dashboard tips already stored in fin_guardian.db."""
    return fetch_community_reports()


def parse_groups(value: str) -> list[str]:
    parts = [part for part in re.split(r"[\s,;]+", value.strip()) if part]
    groups: list[str] = []
    for part in parts:
        username = normalize_group(part)
        if username not in groups:
            groups.append(username)
    if not groups:
        raise UiMessage("err_at_least_one_group")
    return groups


class LiveMonitor:
    """Background Telethon listener shared across Streamlit reruns."""

    def __init__(self) -> None:
        self.queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.status = "stopped"
        self.error: Any = None
        self.groups: list[str] = []
        self.alarm_seq = 0
        self.latest_critical: dict[str, Any] | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self.status in {"starting", "running"}

    def start(self, api_id: int, api_hash: str, groups: list[str]) -> str | None:
        with self._lock:
            if self.running:
                return "err_live_already"
            self.stop_event.clear()
            self.status = "starting"
            self.error = None
            self.groups = groups
            self.thread = threading.Thread(
                target=self._thread_main,
                args=(api_id, api_hash, groups),
                daemon=True,
                name="fin-guardian-live",
            )
            self.thread.start()
        return None

    def stop(self) -> None:
        self.stop_event.set()

    def drain(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        while True:
            try:
                items.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return items

    def _thread_main(self, api_id: int, api_hash: str, groups: list[str]) -> None:
        try:
            asyncio.run(self._listen(api_id, api_hash, groups))
        except Exception as exc:
            self.error = {"message_key": "err_generic", "message_args": {"exc": exc}}
            self.status = "error"
        finally:
            if self.status != "error":
                self.status = "stopped"

    async def _listen(self, api_id: int, api_hash: str, groups: list[str]) -> None:
        client = TelegramClient(str(SESSION_PATH), api_id, api_hash)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                self.error = {"message_key": "err_login_not_finished"}
                self.status = "error"
                return

            entities = []
            resolved: list[str] = []
            for username in groups:
                entity = await client.get_entity(username)
                entities.append(entity)
                resolved.append(username)
            self.groups = resolved

            @client.on(events.NewMessage(chats=entities))
            async def on_new_message(event) -> None:
                text = (event.raw_text or "").strip()
                if not text:
                    return
                chat = event.chat
                if chat is None:
                    chat = await event.get_chat()
                group = (
                    getattr(chat, "username", None)
                    or getattr(chat, "title", None)
                    or "unknown"
                )
                sender = await event.get_sender()
                user_id, sender_name = sender_fields(sender)
                if not user_id and event.sender_id:
                    user_id = str(event.sender_id)
                record = score_live_record(
                    text,
                    event.date,
                    str(group),
                    user_id=user_id,
                    username=sender_name,
                )
                self.queue.put(record)
                if record["status"] == "Critical":
                    self.latest_critical = record
                    self.alarm_seq += 1

            self.status = "running"
            watcher = asyncio.create_task(self._wait_for_stop(client))
            await client.run_until_disconnected()
            watcher.cancel()
        except AuthKeyUnregisteredError:
            reset_telegram_session()
            self.error = {"message_key": "err_session_expired_live"}
            self.status = "error"
        except (AuthKeyDuplicatedError, SecurityError):
            reset_telegram_session()
            self.error = {"message_key": "err_session_conflict_live"}
            self.status = "error"
        except (TimeoutError, ConnectionError, ConnectionAbortedError, ConnectionResetError):
            self.error = {"message_key": "err_telegram_network"}
            self.status = "error"
        except OSError as exc:
            if getattr(exc, "winerror", None) in {121, 1231, 1236, 10054}:
                self.error = {"message_key": "err_telegram_network"}
                self.status = "error"
            else:
                raise
        except ChannelPrivateError:
            self.error = {"message_key": "err_group_private_live"}
            self.status = "error"
        except (UsernameNotOccupiedError, UsernameInvalidError):
            self.error = {"message_key": "err_group_not_found_live"}
            self.status = "error"
        except FloodWaitError as exc:
            self.error = {
                "message_key": "err_flood_wait",
                "message_args": {"seconds": exc.seconds},
            }
            self.status = "error"
        except sqlite3.OperationalError:
            self.error = {"message_key": "err_session_locked_live"}
            self.status = "error"
        except RPCError as exc:
            self.error = {
                "message_key": "err_telegram_api",
                "message_args": {"exc": exc},
            }
            self.status = "error"
        except UiMessage as exc:
            self.error = {"message_key": exc.key, "message_args": exc.kwargs}
            self.status = "error"
        except ValueError as exc:
            self.error = {"message_key": "err_generic", "message_args": {"exc": exc}}
            self.status = "error"
        finally:
            if client.is_connected():
                await client.disconnect()

    async def _wait_for_stop(self, client: TelegramClient) -> None:
        while not self.stop_event.is_set():
            await asyncio.sleep(0.25)
        if client.is_connected():
            await client.disconnect()


@st.cache_resource
def get_live_monitor() -> LiveMonitor:
    return LiveMonitor()


def run_async(async_fn, *args, **kwargs):
    """Run a coroutine from Streamlit by isolating Telethon on a fresh event loop."""

    def _runner():
        return asyncio.run(async_fn(*args, **kwargs))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_runner).result()


def reset_telegram_session() -> None:
    for path in (SESSION_FILE, Path(str(SESSION_FILE) + "-journal")):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def sample_records() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": now,
            "group": "demo",
            "user_id": "1001",
            "username": "cash_runner",
            "message": "Need a mule to move funds today, cashout ready, no kyc. Pay 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        },
        {
            "timestamp": now,
            "group": "demo",
            "user_id": "1002",
            "username": "washdesk",
            "message": "Offering clean cash washing through drop accounts.",
        },
        {
            "timestamp": now,
            "group": "demo",
            "user_id": "1003",
            "username": "ticketfan",
            "message": "Anyone selling concert tickets for Saturday?",
        },
    ]


def clear_saved_credentials() -> None:
    try:
        CREDENTIALS_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    for field in CREDENTIAL_FIELDS:
        st.session_state.pop(field, None)
    reset_telegram_session()
    st.session_state.pop("auth_status", None)
    st.session_state.pop("phone_code_hash", None)
    st.session_state.pop("login_code", None)


def apply_credential_defaults() -> None:
    first_visit = "officer_session" not in st.session_state
    st.session_state.officer_session = True
    if first_visit:
        try:
            CREDENTIALS_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        reset_telegram_session()
    for field in CREDENTIAL_FIELDS:
        st.session_state.setdefault(field, "")


def normalize_group(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise UiMessage("err_enter_group")

    if "joinchat" in raw.lower() or "/+" in raw:
        raise UiMessage("err_no_invite")

    if raw.startswith("@"):
        return raw[1:]

    if "t.me" in raw.lower() or raw.lower().startswith("http"):
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        path = parsed.path.strip("/")
        username = path.split("/")[0]
        if not username or username.lower() in {"joinchat", "addstickers"}:
            raise UiMessage("err_bad_link")
        return username

    return raw.lstrip("@")


def sender_fields(entity: Any) -> tuple[str, str]:
    if entity is None:
        return "", "unknown"
    user_id = str(getattr(entity, "id", "") or "")
    username = (
        getattr(entity, "username", None)
        or getattr(entity, "first_name", None)
        or getattr(entity, "title", None)
        or "unknown"
    )
    return user_id, str(username)


def build_records(
    raw_messages: list[dict[str, Any]],
    openai_key: str,
) -> tuple[list[dict[str, Any]], str | None]:
    platform = st.session_state.get("data_source", TELEGRAM_SOURCE)
    if platform not in DATA_SOURCES:
        platform = TELEGRAM_SOURCE
    records, note = core_build_records(
        raw_messages,
        openai_key,
        default_platform=platform,
    )
    apply_wallet_enrichment(records, st.session_state.get("etherscan_key", ""))
    return records, note


async def telegram_step(
    api_id: int,
    api_hash: str,
    phone: str,
    group: str,
    auth_status: str | None,
    login_code: str | None,
    twofa_password: str | None,
    phone_code_hash: str | None,
    scrape: bool = True,
) -> dict[str, Any]:
    """Drive Telegram login one explicit step at a time, then scrape.

    This never calls client.start(), because start() unconditionally
    re-sends a fresh login code every time it's invoked on an
    unauthorized client — which is fatal in Streamlit, since every
    button click creates a brand-new TelegramClient. Instead we track
    exactly which step we're on via session_state and call the
    underlying Telethon methods directly.
    """
    client = TelegramClient(str(SESSION_PATH), api_id, api_hash)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            if auth_status == "needs_password":
                if not twofa_password:
                    return keyed_error("err_password_required")
                try:
                    await client.sign_in(password=twofa_password)
                except PasswordHashInvalidError:
                    return keyed_error("err_password_wrong")
                except SessionPasswordNeededError:
                    return keyed_error("err_password_required")

            elif auth_status == "needs_code" and login_code:
                try:
                    await client.sign_in(
                        phone=phone, code=login_code, phone_code_hash=phone_code_hash
                    )
                except SessionPasswordNeededError:
                    if not twofa_password:
                        return {"status": "needs_password"}
                    try:
                        await client.sign_in(password=twofa_password)
                    except PasswordHashInvalidError:
                        return keyed_error("err_password_wrong")
                except (PhoneCodeInvalidError, PhoneCodeExpiredError, PhoneCodeEmptyError):
                    return keyed_error("err_code_invalid")

            else:
                sent = await client.send_code_request(phone)
                return {"status": "needs_code", "phone_code_hash": sent.phone_code_hash}

        if not await client.is_user_authorized():
            return keyed_error("err_login_incomplete")

        if not scrape:
            return {"status": "ok", "records": [], "group": ""}

        group_name = normalize_group(group)
        entity = await client.get_entity(group_name)
        history = await client.get_messages(entity, limit=MESSAGE_LIMIT)
        records: list[dict[str, Any]] = []
        for message in history:
            text = (getattr(message, "message", None) or "").strip()
            if not text:
                continue
            date = message.date
            if date is not None and date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            sender = message.sender
            if sender is None:
                try:
                    sender = await message.get_sender()
                except Exception:
                    sender = None
            user_id, sender_name = sender_fields(sender)
            if not user_id:
                user_id = str(getattr(message, "sender_id", "") or "")
            records.append(
                {
                    "timestamp": date,
                    "message": text,
                    "group": group_name,
                    "user_id": user_id,
                    "username": sender_name,
                }
            )
        return {"status": "ok", "records": records, "group": group_name}

    except AuthKeyUnregisteredError:
        reset_telegram_session()
        return keyed_error("err_session_expired")
    except (AuthKeyDuplicatedError, SecurityError):
        reset_telegram_session()
        return keyed_error("err_session_conflict")
    except (TimeoutError, ConnectionError, ConnectionAbortedError, ConnectionResetError):
        return keyed_error("err_telegram_network")
    except OSError as exc:
        if getattr(exc, "winerror", None) in {121, 1231, 1236, 10054}:
            return keyed_error("err_telegram_network")
        raise
    except ApiIdInvalidError:
        return keyed_error("err_api_invalid")
    except PhoneNumberInvalidError:
        return keyed_error("err_phone_invalid")
    except FloodWaitError as exc:
        return keyed_error("err_flood_wait", seconds=exc.seconds)
    except ChannelPrivateError:
        return keyed_error("err_group_private")
    except (UsernameNotOccupiedError, UsernameInvalidError):
        return keyed_error("err_group_not_found")
    except SessionPasswordNeededError:
        return keyed_error("err_password_required")
    except PasswordHashInvalidError:
        return keyed_error("err_password_wrong")
    except sqlite3.OperationalError:
        return keyed_error("err_session_locked")
    except RPCError as exc:
        return keyed_error("err_telegram_api", exc=exc)
    except UiMessage as exc:
        return keyed_error(exc.key, **exc.kwargs)
    except ValueError as exc:
        return keyed_error("err_generic", exc=exc)
    finally:
        if client.is_connected():
            await client.disconnect()


def init_state() -> None:
    st.session_state.setdefault("results", [])
    st.session_state.setdefault("auth_status", None)
    st.session_state.setdefault("phone_code_hash", None)
    st.session_state.setdefault("ai_note", None)
    st.session_state.setdefault("scanned_group", "")
    st.session_state.setdefault("last_scan_at", None)
    st.session_state.setdefault("live_results", [])
    st.session_state.setdefault("played_alarm_seq", 0)
    st.session_state.setdefault("data_source", TELEGRAM_SOURCE)
    if st.session_state.get("data_source") not in DATA_SOURCES:
        st.session_state.data_source = TELEGRAM_SOURCE
    st.session_state.setdefault("community_results", None)
    st.session_state.setdefault("ui_lang", "en")
    legacy_mode = st.session_state.get("app_mode")
    if legacy_mode not in {"one_time", "live", None}:
        live_labels = {
            LIVE_MODE,
            UI_STRINGS["en"]["live_monitoring"],
            UI_STRINGS["ru"]["live_monitoring"],
        }
        st.session_state.app_mode = "live" if legacy_mode in live_labels else "one_time"
    apply_credential_defaults()
    init_database()


def results_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    columns = [
        "timestamp",
        "group",
        "user_id",
        "username",
        "message",
        "risk_score",
        "status",
        "category",
        "platform",
        "matched_keywords",
        "ai_rationale",
        "wallet_flag",
    ]
    if not records:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(records)
    for column in columns:
        if column not in frame.columns:
            frame[column] = ""
    return frame[columns]


def display_frame(df: pd.DataFrame, include_group: bool = False) -> pd.DataFrame:
    if df.empty:
        return df
    view = df.copy()
    if "category" not in view.columns:
        view["category"] = "None"
    if "wallet_flag" not in view.columns:
        view["wallet_flag"] = ""
    view["export"] = [
        t("export_lead_pdf") if status in {"Critical", "Suspicious"} else ""
        for status in view["status"]
    ]
    view["status"] = view["status"].map(labeled_status)
    view["category"] = view["category"].map(labeled_category)
    columns = ["timestamp"]
    if include_group and "group" in view.columns:
        columns.append("group")
    if "username" in view.columns:
        columns.append("username")
    columns.extend(
        ["message", "wallet_flag", "risk_score", "category", "status", "export"]
    )
    return view[columns]


def render_sidebar() -> dict[str, Any]:
    monitor = get_live_monitor()
    with st.sidebar:
        current_lang = LANG_CODES.get(st.session_state.get("ui_lang", "en"), "English")
        selected_lang = st.segmented_control(
            t("language"),
            list(LANG_LABELS.keys()),
            default=current_lang,
            key="ui_lang_control",
            persist_state="session",
        )
        st.session_state["ui_lang"] = LANG_LABELS.get(selected_lang, "en")

        st.header(t("control_center"), divider=False)
        data_source = select_translated(
            t("data_source"),
            list(DATA_SOURCES),
            source_label,
            "data_source",
        )
        st.caption(t("credentials_saved_caption"))
        etherscan_key = st.text_input(
            t("etherscan_key"),
            type="password",
            help=t("etherscan_help"),
            key="etherscan_key",
            persist_state="session",
        )

        if data_source != TELEGRAM_SOURCE:
            st.caption(t("source_active", source=source_label(data_source)))
            return {
                "submitted": False,
                "live_mode": False,
                "data_source": data_source,
                "api_id": "",
                "api_hash": "",
                "phone": "",
                "openai_key": st.session_state.get("openai_key", ""),
                "etherscan_key": etherscan_key.strip(),
                "group": "",
                "login_code": "",
                "twofa_password": "",
            }

        mode_values = ["one_time", "live"]
        stored_mode = st.session_state.get("app_mode", "one_time")
        if stored_mode not in mode_values:
            stored_mode = "one_time"
            st.session_state.app_mode = stored_mode
        mode_labels = [t("one_time_scan"), t("live_monitoring")]
        selected_mode = st.segmented_control(
            t("mode"),
            mode_labels,
            default=mode_labels[mode_values.index(stored_mode)],
            required=True,
            key=f"app_mode__ui_{ui_lang()}",
        )
        live_mode = selected_mode == t("live_monitoring")
        st.session_state.app_mode = "live" if live_mode else "one_time"
        needs_code = st.session_state.auth_status == "needs_code"
        needs_password = st.session_state.auth_status == "needs_password"

        with st.form("scan_form", border=False):
            api_id = st.text_input(t("api_id"), key="api_id", persist_state="session")
            api_hash = st.text_input(
                t("api_hash"),
                type="password",
                key="api_hash",
                persist_state="session",
            )
            phone = st.text_input(
                t("phone"),
                placeholder="+447700900000",
                key="phone",
                persist_state="session",
            )
            twofa_password = st.text_input(
                t("telegram_password"),
                type="password",
                help=t("telegram_password_help"),
                key="telegram_password",
                persist_state="session",
            )
            openai_key = st.text_input(
                t("openai_key"),
                type="password",
                help=t("openai_help"),
                key="openai_key",
                persist_state="session",
            )
            if live_mode:
                group = st.text_area(
                    t("public_groups"),
                    placeholder=t("placeholder_groups"),
                    help=t("public_groups_help"),
                    key="live_groups",
                    persist_state="session",
                )
            else:
                group = st.text_input(
                    t("public_group"),
                    placeholder=t("placeholder_group"),
                    key="group",
                    persist_state="session",
                )
            login_code = ""
            if needs_code:
                login_code = st.text_input(
                    t("login_code"),
                    key="login_code",
                    help=t("login_code_help"),
                )

            if needs_code:
                button_label = t("submit_code")
                button_icon = ":material/sms:"
            elif needs_password:
                button_label = t("submit_password")
                button_icon = ":material/lock:"
            elif live_mode:
                button_label = t("start_monitoring")
                button_icon = ":material/sensors:"
            else:
                button_label = t("scan_group")
                button_icon = ":material/search:"

            submitted = st.form_submit_button(
                button_label,
                type="primary",
                icon=button_icon,
            )

        if live_mode and monitor.running:
            if st.button(t("stop_monitoring"), icon=":material/stop:"):
                monitor.stop()
                st.toast(t("stopping_live"), icon=":material/stop:")
            listening = ", ".join(f"@{name}" for name in monitor.groups) or t("groups_fallback")
            st.caption(t("listening_to", groups=listening))

        if st.button(t("load_samples"), icon=":material/science:"):
            records, note = build_records(sample_records(), "")
            st.session_state.results = records
            st.session_state.ai_note = note
            st.session_state.scanned_group = "demo"
            st.session_state.last_scan_at = datetime.now(timezone.utc)
            persist_flagged(records)
            st.rerun()

        if st.button(t("reset_session"), icon=":material/restart_alt:"):
            if monitor.running:
                monitor.stop()
            reset_telegram_session()
            st.session_state.auth_status = None
            st.session_state.phone_code_hash = None
            st.success(t("session_cleared"), icon=":material/check:")

        if st.button(t("forget_credentials"), icon=":material/delete:"):
            clear_saved_credentials()
            st.rerun()

        st.caption(t("public_groups_only"))

    return {
        "submitted": submitted,
        "live_mode": live_mode,
        "data_source": TELEGRAM_SOURCE,
        "api_id": api_id.strip(),
        "api_hash": api_hash.strip(),
        "phone": phone.strip(),
        "openai_key": openai_key.strip(),
        "etherscan_key": etherscan_key.strip(),
        "group": group.strip(),
        "login_code": login_code.strip(),
        "twofa_password": twofa_password.strip(),
    }


def validate_credentials(form: dict[str, Any], require_login_steps: bool = True) -> str | None:
    if not form["api_id"] or not form["api_hash"] or not form["phone"]:
        return t("err_need_api")
    try:
        int(form["api_id"])
    except ValueError:
        return t("err_api_id_number")
    if not form["group"]:
        return t("err_need_group")
    try:
        parse_groups(form["group"])
    except UiMessage as exc:
        return t(exc.key, **exc.kwargs)
    except ValueError as exc:
        return error_text(exc)
    if require_login_steps and st.session_state.auth_status == "needs_code" and not form["login_code"]:
        return t("err_need_code")
    if require_login_steps and st.session_state.auth_status == "needs_password" and not form["twofa_password"]:
        return t("err_need_password")
    return None


def run_scan(form: dict[str, Any]) -> None:
    monitor = get_live_monitor()
    if monitor.running:
        st.error(t("err_stop_live_for_scan"), icon=":material/error:")
        return

    error = validate_credentials(form)
    if error:
        st.error(error, icon=":material/error:")
        return

    with st.status(t("talking_telegram"), expanded=True) as status:
        status.write(t("connecting"))
        try:
            result = run_async(
                telegram_step,
                int(form["api_id"]),
                form["api_hash"],
                form["phone"],
                parse_groups(form["group"])[0],
                st.session_state.auth_status,
                form["login_code"] or None,
                form["twofa_password"] or None,
                st.session_state.phone_code_hash,
            )
        except Exception as exc:
            status.update(label=t("scan_failed"), state="error")
            st.error(t("could_not_scan", exc=exc), icon=":material/error:")
            return

        if result["status"] == "needs_code":
            st.session_state.auth_status = "needs_code"
            st.session_state.phone_code_hash = result.get("phone_code_hash")
            status.update(label=t("login_code_required"), state="complete")
            st.info(t("login_code_sent"), icon=":material/sms:")
            return

        if result["status"] == "needs_password":
            st.session_state.auth_status = "needs_password"
            status.update(label=t("password_required"), state="complete")
            st.info(t("enter_2fa"), icon=":material/lock:")
            return

        if result["status"] == "error":
            status.update(label=t("scan_failed"), state="error")
            st.error(error_text(result), icon=":material/error:")
            return

        st.session_state.auth_status = "authorized"
        st.session_state.phone_code_hash = None
        status.write(t("scoring_messages"))
        records, ai_note = build_records(result.get("records", []), form["openai_key"])
        st.session_state.results = records
        st.session_state.ai_note = ai_note
        st.session_state.scanned_group = result.get("group", form["group"])
        st.session_state.last_scan_at = datetime.now(timezone.utc)
        persist_flagged(records)
        status.update(label=t("scan_complete"), state="complete")
        st.toast(t("scan_complete"), icon=":material/check_circle:")


def start_live_monitor(form: dict[str, Any]) -> None:
    error = validate_credentials(form, require_login_steps=True)
    if error:
        st.error(error, icon=":material/error:")
        return

    try:
        groups = parse_groups(form["group"])
    except UiMessage as exc:
        st.error(t(exc.key, **exc.kwargs), icon=":material/error:")
        return
    except ValueError as exc:
        st.error(error_text(exc), icon=":material/error:")
        return

    monitor = get_live_monitor()
    if monitor.running:
        st.error(t("err_live_already"), icon=":material/error:")
        return

    with st.status(t("signing_in"), expanded=True) as status:
        status.write(t("checking_session"))
        try:
            result = run_async(
                telegram_step,
                int(form["api_id"]),
                form["api_hash"],
                form["phone"],
                groups[0],
                st.session_state.auth_status,
                form["login_code"] or None,
                form["twofa_password"] or None,
                st.session_state.phone_code_hash,
                False,
            )
        except Exception as exc:
            status.update(label=t("login_failed"), state="error")
            st.error(t("could_not_login", exc=exc), icon=":material/error:")
            return

        if result["status"] == "needs_code":
            st.session_state.auth_status = "needs_code"
            st.session_state.phone_code_hash = result.get("phone_code_hash")
            status.update(label=t("login_code_required"), state="complete")
            st.info(t("login_code_sent_live"), icon=":material/sms:")
            return

        if result["status"] == "needs_password":
            st.session_state.auth_status = "needs_password"
            status.update(label=t("password_required"), state="complete")
            st.info(t("enter_2fa_live"), icon=":material/lock:")
            return

        if result["status"] == "error":
            status.update(label=t("login_failed"), state="error")
            st.error(error_text(result), icon=":material/error:")
            return

        st.session_state.auth_status = "authorized"
        st.session_state.phone_code_hash = None
        status.write(t("starting_listeners"))

    start_error = monitor.start(int(form["api_id"]), form["api_hash"], groups)
    if start_error:
        st.error(error_text(start_error), icon=":material/error:")
        return
    st.session_state.played_alarm_seq = monitor.alarm_seq
    st.success(t("live_started", count=len(groups)), icon=":material/sensors:")


def handle_forensic_click(key: str) -> None:
    click = st.session_state.get(key)
    if click is None:
        return
    source = st.session_state.get("forensic_source")
    if source is None or getattr(source, "empty", True):
        return
    index = int(click.row)
    if index < 0 or index >= len(source):
        return
    record = source.iloc[index]
    if str(record.get("status", "")) not in {"Critical", "Suspicious"}:
        return
    try:
        pdf_bytes = generate_report_pdf(record)
    except Exception as exc:
        st.session_state.forensic_error = t("lead_pdf_failed", exc=exc)
        return
    st.session_state.forensic_pdf = pdf_bytes
    st.session_state.forensic_filename = lead_report_filename(record)


def render_forensic_download() -> None:
    error = st.session_state.pop("forensic_error", None)
    if error:
        st.error(error, icon=":material/error:")
    pdf_bytes = st.session_state.get("forensic_pdf")
    if not pdf_bytes:
        return
    st.download_button(
        t("export_lead_pdf"),
        data=pdf_bytes,
        file_name=st.session_state.get(
            "forensic_filename", "fin-guardian-lead-report.pdf"
        ),
        mime="application/pdf",
        icon=":material/picture_as_pdf:",
        key="forensic_pdf_download",
    )


def render_lead_report_downloads(df: pd.DataFrame, key_prefix: str) -> None:
    if df.empty or "status" not in df.columns:
        return
    flagged = df[df["status"].isin(["Critical", "Suspicious"])].reset_index(drop=True)
    if flagged.empty:
        return
    st.caption(t("lead_reports_caption"))
    for index, row in flagged.iterrows():
        try:
            pdf_bytes = generate_report_pdf(row)
        except Exception:
            continue
        preview = str(row.get("message") or "")[:72]
        status = str(row.get("status") or "")
        st.download_button(
            t("export_lead_pdf_status", status=status_label(status)),
            data=pdf_bytes,
            file_name=lead_report_filename(row),
            mime="application/pdf",
            help=preview or None,
            key=f"{key_prefix}-lead-{index}",
        )


def result_table_config(
    include_group: bool = False, export_key: str = "forensic_export"
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "timestamp": st.column_config.DatetimeColumn(
            t("col_timestamp"),
            format="YYYY-MM-DD HH:mm:ss",
        ),
        "message": st.column_config.TextColumn(t("col_message")),
        "risk_score": st.column_config.ProgressColumn(
            t("col_risk_score"),
            min_value=0,
            max_value=100,
            format="%d",
        ),
        "status": st.column_config.TextColumn(t("col_status")),
        "category": st.column_config.TextColumn(t("col_category")),
        "username": st.column_config.TextColumn(t("col_username")),
        "wallet_flag": st.column_config.TextColumn(t("col_wallet")),
        "export": st.column_config.ButtonColumn(
            t("col_lead_report"),
            on_click=handle_forensic_click,
            args=(export_key,),
            key=export_key,
        ),
    }
    if include_group:
        config["group"] = st.column_config.TextColumn(t("col_group"))
    return config


@st.fragment(run_every=1)
def live_feed() -> None:
    monitor = get_live_monitor()
    incoming = monitor.drain()
    if incoming:
        apply_wallet_enrichment(incoming, st.session_state.get("etherscan_key", ""))
        persist_flagged(incoming)
        st.session_state.live_results = (incoming + st.session_state.live_results)[:LIVE_RESULT_LIMIT]

    if monitor.error and monitor.status == "error":
        st.error(error_text(monitor.error), icon=":material/error:")

    df = results_frame(st.session_state.live_results)
    total = int(len(df))
    critical = int((df["status"] == "Critical").sum()) if total else 0
    high_risk = int((df["status"].isin(["Critical", "Suspicious"])).sum()) if total else 0

    with st.container(horizontal=True):
        listening = ", ".join(f"@{name}" for name in monitor.groups) if monitor.groups else "—"
        st.metric(t("metric_listening"), monitor_status_label(monitor.status), border=True)
        st.metric(t("metric_live_messages"), total, border=True)
        st.metric(t("metric_high_risk"), high_risk, border=True)
        st.metric(t("metric_critical_alarms"), critical, border=True)

    if monitor.latest_critical:
        preview = str(monitor.latest_critical.get("message", ""))[:160]
        group = str(monitor.latest_critical.get("group", "unknown") or "unknown")
        group_label = t("unknown_group") if group == "unknown" else group
        st.error(
            t("risk_alarm", group=group_label, preview=preview),
            icon=":material/campaign:",
        )

    if monitor.alarm_seq > st.session_state.played_alarm_seq:
        st.session_state.played_alarm_seq = monitor.alarm_seq
        st.audio(ALARM_WAV, format="audio/wav", autoplay=True)
        st.toast(t("critical_threat_detected"), icon=":material/warning:")

    st.caption(t("watching_live", listening=listening))
    st.session_state.forensic_source = df.reset_index(drop=True)
    st.dataframe(
        display_frame(df, include_group=True),
        hide_index=True,
        height=460,
        column_config=result_table_config(include_group=True, export_key="forensic_export_live"),
    )
    render_forensic_download()

    if not df.empty:
        evidence_cols = [
            col
            for col in [
                "timestamp",
                "group",
                "username",
                "user_id",
                "message",
                "category",
                "risk_score",
                "status",
                "matched_keywords",
            ]
            if col in df.columns
        ]
        evidence = df[evidence_cols].copy()
        csv_bytes = evidence.to_csv(index=False).encode("utf-8-sig")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        st.download_button(
            t("download_live_evidence"),
            data=csv_bytes,
            file_name=f"fin-guardian-live-{stamp}.csv",
            mime="text/csv",
            icon=":material/download:",
            key="live_evidence_download",
        )


def render_live_dashboard() -> None:
    monitor = get_live_monitor()
    st.subheader(t("live_monitoring"))
    if not monitor.running and monitor.status != "error" and not st.session_state.live_results:
        st.info(t("live_ready_hint"), icon=":material/sensors:")
    live_feed()


@st.fragment(run_every=3)
def render_shared_inbox() -> None:
    inbox = fetch_detections()
    st.subheader(t("shared_inbox"))
    st.caption(t("shared_inbox_caption"))
    if inbox.empty:
        st.info(t("inbox_empty"), icon=":material/inbox:")
        return

    view = inbox.copy()
    view["status"] = view["status"].map(labeled_status)
    view["category"] = view["category"].map(labeled_category)
    view["platform"] = view["platform"].map(labeled_platform)
    st.dataframe(
        view[
            [
                "timestamp",
                "platform",
                "group",
                "username",
                "user_id",
                "message",
                "risk_score",
                "category",
                "status",
            ]
        ],
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn(t("col_timestamp")),
            "platform": st.column_config.TextColumn(t("col_source")),
            "group": st.column_config.TextColumn(t("col_group")),
            "username": st.column_config.TextColumn(t("col_username")),
            "user_id": st.column_config.TextColumn(t("col_user_id")),
            "message": st.column_config.TextColumn(t("col_message")),
            "risk_score": st.column_config.ProgressColumn(
                t("col_risk_score"), min_value=0, max_value=100, format="%d"
            ),
            "category": st.column_config.TextColumn(t("col_category")),
            "status": st.column_config.TextColumn(t("col_status")),
        },
    )


def render_metrics(df: pd.DataFrame) -> None:
    total = int(len(df))
    high_risk = int((df["status"].isin(["Critical", "Suspicious"])).sum()) if total else 0
    safe = int((df["status"] == "Safe").sum()) if total else 0

    with st.container(horizontal=True):
        st.metric(t("metric_total_scanned"), total, border=True)
        st.metric(t("metric_high_risk"), high_risk, border=True)
        st.metric(t("metric_safe"), safe, border=True)


def render_results(df: pd.DataFrame) -> None:
    if df.empty:
        st.info(t("enter_credentials_hint"), icon=":material/info:")
        return

    table_col, chart_col = st.columns((2.4, 1))
    with table_col:
        with st.container(border=True):
            st.subheader(t("detection_results"))
            if st.session_state.scanned_group:
                scanned_at = st.session_state.last_scan_at
                when = scanned_at.strftime("%Y-%m-%d %H:%M UTC") if scanned_at else t("just_now")
                st.caption(
                    t(
                        "last_messages_from",
                        limit=MESSAGE_LIMIT,
                        group=st.session_state.scanned_group,
                        when=when,
                    )
                )
            st.session_state.forensic_source = df.reset_index(drop=True)
            st.dataframe(
                display_frame(df),
                hide_index=True,
                column_config=result_table_config(export_key="forensic_export_scan"),
            )
            render_forensic_download()
            with st.expander(t("expander_lead_reports")):
                render_lead_report_downloads(df, "scan")

    with chart_col:
        with st.container(border=True):
            st.subheader(t("risk_distribution"))
            counts = (
                df["status"]
                .value_counts()
                .reindex(["Critical", "Suspicious", "Safe"])
                .fillna(0)
                .astype(int)
                .rename_axis("status")
                .reset_index(name="count")
            )
            counts["status"] = counts["status"].map(status_label)
            counts = counts.rename(
                columns={"status": t("col_status"), "count": t("axis_count")}
            )
            st.bar_chart(counts, x=t("col_status"), y=t("axis_count"))

    evidence_cols = [
        col
        for col in [
            "timestamp",
            "username",
            "user_id",
            "message",
            "category",
            "risk_score",
            "status",
            "matched_keywords",
            "ai_rationale",
            "wallet_flag",
        ]
        if col in df.columns
    ]
    evidence = df[evidence_cols].copy()
    csv_bytes = evidence.to_csv(index=False).encode("utf-8-sig")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    st.download_button(
        t("download_evidence"),
        data=csv_bytes,
        file_name=f"fin-guardian-evidence-{stamp}.csv",
        mime="text/csv",
        icon=":material/download:",
    )

    if st.session_state.ai_note:
        st.caption(st.session_state.ai_note)


def render_scored_source(records: list[dict[str, Any]], heading: str, caption: str, export_key: str) -> None:
    built, note = build_records(records, st.session_state.get("openai_key", ""))
    df = results_frame(built)
    st.subheader(heading)
    st.caption(caption)
    render_metrics(df)
    if df.empty:
        return
    st.session_state.forensic_source = df.reset_index(drop=True)
    st.dataframe(
        display_frame(df, include_group=True),
        hide_index=True,
        column_config=result_table_config(include_group=True, export_key=export_key),
    )
    render_forensic_download()
    with st.expander(t("expander_lead_reports")):
        render_lead_report_downloads(df, export_key)
    if note:
        st.caption(note)


def render_community_reports() -> None:
    st.subheader(t("community_reports"))
    st.caption(t("community_reports_caption"))
    bot_reports = load_community_reports()
    if bot_reports:
        st.caption(t("reports_loaded", count=len(bot_reports)))
    tip = st.text_area(
        t("submit_community_tip"),
        placeholder=t("community_tip_placeholder"),
        key="community_tip",
    )
    if st.button(t("score_community_tip"), icon=":material/flag:", key="score_community_tip") and tip.strip():
        fresh = {
            "timestamp": datetime.now(timezone.utc),
            "group": "community-tip",
            "user_id": "c-live",
            "username": "community",
            "platform": COMMUNITY_SOURCE,
            "message": tip.strip(),
        }
        built, _note = build_records([fresh], st.session_state.get("openai_key", ""))
        persist_flagged(built)
        existing = list(st.session_state.community_results or [])
        st.session_state.community_results = [fresh] + existing
    session_tips = list(st.session_state.get("community_results") or [])
    records = session_tips + list(reversed(bot_reports))
    if not records:
        records = community_sample_records()
    render_scored_source(
        records,
        t("community_detections"),
        t("community_detections_caption"),
        "forensic_export_community",
    )


def render_suspect_database() -> None:
    st.subheader(t("suspect_database"))
    st.caption(t("suspect_database_caption"))
    offenders = fetch_offenders()
    if offenders.empty:
        st.info(t("no_suspects"), icon=":material/person_search:")
        return

    st.dataframe(
        offenders,
        hide_index=True,
        column_config={
            "user_id": st.column_config.TextColumn(t("col_user_id")),
            "username": st.column_config.TextColumn(t("col_username")),
            "incidents": st.column_config.NumberColumn(t("col_incidents")),
            "groups_count": st.column_config.NumberColumn(t("col_groups")),
            "groups": st.column_config.TextColumn(t("col_group_history")),
            "last_seen": st.column_config.TextColumn(t("col_last_seen")),
        },
    )

    labels = [
        t(
            "offender_label",
            username=row.username,
            user_id=row.user_id,
            incidents=int(row.incidents),
        )
        for row in offenders.itertuples(index=False)
    ]
    selected = st.selectbox(t("offender_history"), labels, key="suspect_pick")
    if selected:
        row = offenders.iloc[labels.index(selected)]
        history = fetch_offender_history(str(row["user_id"]), str(row["username"]))
        if "category" in history.columns:
            history["category"] = history["category"].map(labeled_category)
        st.dataframe(
            history,
            hide_index=True,
            column_config={
                "detected_at": st.column_config.TextColumn(t("col_timestamp")),
                "chat_group": st.column_config.TextColumn(t("col_group")),
                "category": st.column_config.TextColumn(t("col_category")),
                "risk_score": st.column_config.ProgressColumn(
                    t("col_risk_score"), min_value=0, max_value=100, format="%d"
                ),
                "message": st.column_config.TextColumn(t("col_message")),
            },
        )


def render_trends_page() -> None:
    try:
        import plotly.express as px
    except ImportError:
        px = None

    st.subheader(t("trends_analytics"))
    st.caption(t("trends_caption"))

    category_df = fetch_category_counts()
    hourly_df = fetch_hourly_trend()

    if px is None:
        st.warning(t("plotly_missing"), icon=":material/warning:")
        category_chart = category_df.rename(
            columns={"category": t("col_category"), "count": t("axis_flagged")}
        )
        hourly_chart = hourly_df.rename(
            columns={"hour": t("axis_hour"), "messages": t("axis_suspicious_critical")}
        )
        st.bar_chart(category_chart, x=t("col_category"), y=t("axis_flagged"))
        st.line_chart(hourly_chart, x=t("axis_hour"), y=t("axis_suspicious_critical"))
        return

    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown(f"**{t('crimes_by_category')}**")
            bar = px.bar(
                category_df,
                x="category",
                y="count",
                color="category",
                color_discrete_map={
                    "Money mule recruitment": "#F87171",
                    "Illicit cashout": "#FB923C",
                    "Money laundering": "#A78BFA",
                    "KYC evasion": "#60A5FA",
                },
            )
            bar.update_layout(
                showlegend=False,
                xaxis_title=t("axis_category"),
                yaxis_title=t("axis_flagged"),
                margin=dict(l=8, r=8, t=8, b=8),
            )
            st.plotly_chart(bar, width="stretch")

    with right:
        with st.container(border=True):
            st.markdown(f"**{t('suspicious_activity_24h')}**")
            line = px.line(
                hourly_df,
                x="hour",
                y="messages",
                markers=True,
            )
            line.update_traces(line_color="#60A5FA")
            line.update_layout(
                xaxis_title=t("axis_hour"),
                yaxis_title=t("axis_suspicious_critical"),
                margin=dict(l=8, r=8, t=8, b=8),
            )
            st.plotly_chart(line, width="stretch")


def main() -> None:
    st.set_page_config(
        page_title="Fin-Guardian",
        page_icon=":material/shield:",
        layout="wide",
    )
    init_state()
    form = render_sidebar()

    st.title(t("page_title"))
    st.caption(t("page_caption"))

    source = form.get("data_source") or st.session_state.get("data_source", TELEGRAM_SOURCE)

    if form["submitted"] and source == TELEGRAM_SOURCE:
        if form["live_mode"]:
            start_live_monitor(form)
        else:
            run_scan(form)

    detection_tab, suspects_tab, trends_tab = st.tabs(
        [
            f":material/shield: {t('tab_detection')}",
            f":material/folder_shared: {t('tab_suspects')}",
            f":material/analytics: {t('tab_trends')}",
        ]
    )
    with detection_tab:
        if source == COMMUNITY_SOURCE:
            render_community_reports()
        elif form["live_mode"]:
            render_live_dashboard()
        else:
            df = results_frame(st.session_state.results)
            render_metrics(df)
            render_results(df)
        render_shared_inbox()
    with suspects_tab:
        render_suspect_database()
    with trends_tab:
        render_trends_page()


if __name__ == "__main__":
    main()