from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import csv
import hashlib
import hmac
import html as html_mod
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
import textwrap
import zipfile
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse, unquote, quote, urlencode

import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse, PlainTextResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image, ImageFilter, ImageDraw
from starlette.middleware.sessions import SessionMiddleware

APP_NAME = "US Cyber Militia / BlindSite"
APP_VERSION = "5.19.6-pdf-report-full-width-timeouts"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "vault.sqlite3"
EVIDENCE_DIR = DATA_DIR / "evidence"
DERIVED_DIR = DATA_DIR / "derived"
SEAL_DIR = DATA_DIR / "seals"
REVIEW_DIR = DATA_DIR / "review_vault"
KEY_FILE = DATA_DIR / "vault.key"
SECRET_FILE = DATA_DIR / "app_secret.key"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg", ".ico", ".avif"}
VIDEO_EXTS = {".mp4", ".m4v", ".webm", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".mpeg", ".mpg", ".m3u8", ".mpd"}
AUDIO_EXTS = {".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac"}
FONT_EXTS = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
CSS_EXTS = {".css"}
MEDIA_POLICIES = ["allow_all", "block_images", "block_images_video", "block_all_media"]
CAPTURE_MODES = ["metadata_only", "safe_summary", "evidence_safe", "full_forensic"]
EDITIONS = ["lockdown", "supervised", "lab"]
BROWSERS = ["chromium", "firefox", "chrome", "msedge", "tor_managed_chromium", "tor_managed_firefox", "torbrowser"]
ARCHIVABLE_BROWSER_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# Standard browser-looking user agents. These are static compatibility/privacy profiles,
# not an anonymity guarantee; network/TLS/browser fingerprints can still differ.
USER_AGENT_PROFILES: dict[str, tuple[str, str]] = {
    "chrome_windows": ("Chrome on Windows 11", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "chrome_mac": ("Chrome on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "chrome_linux": ("Chrome on Linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "edge_windows": ("Edge on Windows 11", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
    "firefox_windows": ("Firefox on Windows 11", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"),
    "firefox_mac": ("Firefox on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0"),
    "safari_mac": ("Safari on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"),
    "ios_safari": ("Safari on iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"),
    "android_chrome": ("Chrome on Android", "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"),
    "ipad_safari": ("Safari on iPad", "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"),
    "firefox_android": ("Firefox on Android", "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0"),
    "tor_browser_windows": ("Tor Browser compatible Firefox on Windows", "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"),
    "tor_browser_linux": ("Tor Browser compatible Firefox on Linux", "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"),
    "forensic_tool": ("BlindSite explicit UA", f"BlindSite/{APP_VERSION} metadata-safe"),
    "custom": ("Custom user agent", ""),
}

BUNDLED_ESCROW_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAscG0PRP92MgUz96g7AQw
3IwP6n7BANUrDJeAt2KToOHru2VslJdnau1UwSNvLvSH54mesrqUwzFN2aMtbtK8
mCJ0Kce25H4kNH7Faav+HplQzE3xG85GrJe3UKqwvWruM2GTALdYFoGdPwhXrFKh
eCefXO++/118PbN6qVliz1knypKDKgxMz6Eu7LVxyiV5la/4UzEpZw1xFlesxudY
dyriu31+0Y7sBDdHs92ThaGSKWaENfPDBtvANVMZM2WFC/jX2Z1/C9f4wb7+s1FH
CGnGGscK1AtpvnHK/YqaFcPqXj7UrAndNynrG2o+ssKO1xdTrvCaKqyk8q7vOiQT
UcQw0I0WMmgUO7r16dHOhph6CjSvx8Sy0X6GeSjWLIxuFUrUVeq0RetqTsEu6z8s
CSoOhou/BDyXHiTkz76uv91KobIAZw/pc0G936ho15GaIqus9FG1cefdCFok/WFc
s4zMFqiOtVDS2yjMPR1azVYpv/o4fPujO5ZxXwelrsNYfeEt7ldGx+NeqcZTYyRU
AX/ylVdwT9xI8H31fQEuemUtSgxNAHCawyBSQL2DXbONevur0xnxTq8MznHy1qlz
YubNBgvNrK9iyGuOcgVSaiXOE5fS/rVMvL2HHO0WPV4zwn0tV+t6owjQOUxxVN3y
jX+9RPguKBS03nI2IId0Vy0CAwEAAQ==
-----END PUBLIC KEY-----
""".strip()

LIVE: dict[str, "LiveBrowserSession"] = {}
LIVE_LOCK = threading.RLock()

PDF_REPORT_DIR = DERIVED_DIR / "reviewer_pdf_reports"
PDF_REPORT_JOBS: dict[str, dict[str, Any]] = {}
PDF_REPORT_LOCK = threading.RLock()
PDF_REPORT_MAX_PAGES = 20
# High-resolution PDF report screenshots. The CSS viewport stays close to the
# reviewer UI size, while device_scale_factor=2 captures sharper text/media.
# The PDF encoder then embeds screenshots at higher quality/DPI to avoid fuzzy
# reports without changing the rendered page layout.
PDF_REPORT_VIEWPORT_WIDTH = 1280
PDF_REPORT_VIEWPORT_HEIGHT = 1600
PDF_REPORT_DEVICE_SCALE_FACTOR = 2
PDF_REPORT_MAX_IMAGE_HEIGHT = 18000
PDF_REPORT_DPI = 144.0
PDF_REPORT_JPEG_QUALITY = 95


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    DERIVED_DIR.mkdir(parents=True, exist_ok=True)
    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def h(value: Any) -> str:
    return html_mod.escape("" if value is None else str(value), quote=True)


def jloads(value: Any, default: Any = None) -> Any:
    if value in (None, ""):
        return {} if default is None else default
    try:
        return json.loads(value)
    except Exception:
        return {} if default is None else default


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def clean_filename(name: str) -> str:
    name = Path(name or "evidence.bin").name
    safe = "".join(c if c.isalnum() or c in "._- " else "_" for c in name).strip(" .")
    return safe[:160] or "evidence.bin"


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise HTTPException(400, "URL is required")
    if not urlparse(url).scheme:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        raise HTTPException(400, "Only http/https URLs are supported")
    return url


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def ensure_secret_file(path: Path, n: int = 32) -> bytes:
    ensure_dirs()
    if not path.exists():
        path.write_bytes(secrets.token_bytes(n))
    return path.read_bytes()


def app_secret() -> str:
    return b64e(ensure_secret_file(SECRET_FILE, 48))


def fernet() -> Fernet:
    ensure_dirs()
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(Fernet.generate_key())
    return Fernet(KEY_FILE.read_bytes())


def encrypt_bytes(data: bytes) -> bytes:
    return fernet().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return fernet().decrypt(data)


def db() -> sqlite3.Connection:
    ensure_dirs()
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con


def execute(sql: str, params: tuple[Any, ...] = ()) -> int:
    with closing(db()) as con:
        cur = con.execute(sql, params)
        con.commit()
        return int(cur.lastrowid or 0)


def fetchone(sql: str, params: tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    with closing(db()) as con:
        return con.execute(sql, params).fetchone()


def fetchall(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    with closing(db()) as con:
        return list(con.execute(sql, params).fetchall())


def rowdict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return "pbkdf2$" + b64e(salt) + "$" + b64e(digest)


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, digest_b64 = stored.split("$", 2)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def set_setting(key: str, value: Any) -> None:
    execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at", (key, str(value), utcnow()))


def get_setting(key: str, default: Any = "") -> str:
    row = fetchone("SELECT value FROM settings WHERE key=?", (key,))
    return str(row["value"]) if row else str(default)


def all_settings() -> dict[str, str]:
    return {r["key"]: r["value"] for r in fetchall("SELECT key,value FROM settings")}


def setting_bool(key: str, default: str = "0") -> bool:
    return truthy(get_setting(key, default))


def split_lines_setting(key: str) -> list[str]:
    raw = get_setting(key, "")
    out = []
    for line in raw.replace(",", "\n").splitlines():
        item = line.strip().lower()
        if item:
            out.append(item)
    return out


def domain_matches(host: str, patterns: list[str]) -> bool:
    host = (host or "").lower().strip(".")
    for pat in patterns:
        pat = pat.lower().strip(".")
        if not pat:
            continue
        if host == pat or host.endswith("." + pat):
            return True
    return False


def master_key_set() -> bool:
    return bool(get_setting("master_key_hash", ""))


def set_master_key(value: str) -> None:
    if len(value or "") < 12:
        raise HTTPException(400, "Master reveal key must be at least 12 characters")
    set_setting("master_key_hash", hash_password(value))


def verify_master_key(value: str) -> bool:
    stored = get_setting("master_key_hash", "")
    return bool(stored and value and check_password(value, stored))


def load_bundled_escrow_public_key() -> str:
    candidate = BASE_DIR / "escrow_public_key.pem"
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")
    return BUNDLED_ESCROW_PUBLIC_KEY_PEM


def load_uscm_escrow_public_key() -> str:
    """Return the embedded USCM escrow public key for Civilian Unknown Master Key mode.

    Civilian Unknown Master Key mode is intentionally not a user-controlled key
    workflow. The civilian collector must not possess/control the private reveal
    key, so this mode uses the embedded USCM escrow public key instead of a
    user-supplied key. Organization-Controlled Key mode remains available for
    organizations that need to control their own keys.
    """
    return BUNDLED_ESCROW_PUBLIC_KEY_PEM


def uscm_escrow_public_fingerprint() -> str:
    return escrow_public_fingerprint(load_uscm_escrow_public_key())


def escrow_public_fingerprint(pem: str) -> str:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # type: ignore[attr-defined]
        return sha256_bytes(der)
    except Exception:
        return ""


def escrow_wrap(pem: str, payload: bytes) -> str:
    key = serialization.load_pem_public_key(pem.encode("utf-8"))
    wrapped = key.encrypt(payload, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # type: ignore[attr-defined]
    return b64e(wrapped)


HARD_SEALED_ENCRYPTED_FLAG = 2
HARD_SEALED_CONTAINER_TYPE = "blindsite_hard_sealed_escrow_object"


def escrow_hard_seal_bytes(public_key_pem: str, payload: bytes, *, meta: dict[str, Any] | None = None) -> bytes:
    """Encrypt bytes so only the escrow private key can recover them.

    This is used for sensitive/original evidence in Civilian Unknown Master Key
    mode. Unlike the normal local vault encryption, no reusable local decrypt key
    is stored on disk for these objects. The payload is encrypted with a random
    per-object Fernet key, and that object key is RSA-wrapped to the escrow
    public key.
    """
    if not public_key_pem or not escrow_public_fingerprint(public_key_pem):
        raise HTTPException(500, "Hard-sealed civilian storage requires a valid escrow public key")
    object_key = Fernet.generate_key()
    encrypted_payload = Fernet(object_key).encrypt(payload).decode("ascii")
    container = {
        "container_type": HARD_SEALED_CONTAINER_TYPE,
        "format_version": 1,
        "algorithm": "Fernet-per-object-key + RSA-OAEP-SHA256-wrapped-object-key",
        "escrow_public_key_fingerprint": escrow_public_fingerprint(public_key_pem),
        "wrapped_object_key": escrow_wrap(public_key_pem, object_key),
        "payload_sha256": sha256_bytes(payload),
        "payload_size": len(payload),
        "encrypted_payload": encrypted_payload,
        "created_at": utcnow(),
        "meta": meta or {},
    }
    return canonical(container).encode("utf-8")


def parse_hard_sealed_container(data: bytes) -> dict[str, Any] | None:
    try:
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict) and obj.get("container_type") == HARD_SEALED_CONTAINER_TYPE:
            return obj
    except Exception:
        return None
    return None


def escrow_hard_unseal_bytes(private_key: Any, sealed_data: bytes) -> bytes:
    container = parse_hard_sealed_container(sealed_data)
    if not container:
        raise HTTPException(400, "Object is not a BlindSite hard-sealed escrow container")
    object_key = escrow_unwrap(private_key, str(container.get("wrapped_object_key") or ""))
    try:
        payload = Fernet(object_key).decrypt(str(container.get("encrypted_payload") or "").encode("ascii"))
    except Exception as exc:
        raise HTTPException(400, f"Could not decrypt hard-sealed object payload: {exc}") from exc
    expected_sha = str(container.get("payload_sha256") or "")
    expected_size = container.get("payload_size")
    if expected_sha and sha256_bytes(payload) != expected_sha:
        raise HTTPException(400, "Hard-sealed object payload hash verification failed")
    if expected_size is not None:
        try:
            if len(payload) != int(expected_size):
                raise HTTPException(400, "Hard-sealed object payload size verification failed")
        except HTTPException:
            raise
        except Exception:
            pass
    return payload


def custody_mode() -> str:
    mode = get_setting("custody_mode", "organization")
    return mode if mode in {"organization", "civilian_unknown_master"} else "organization"


def civilian_unknown_master_mode() -> bool:
    return custody_mode() == "civilian_unknown_master"


def organization_controlled_mode() -> bool:
    return custody_mode() == "organization"


def organization_hard_seal_public_key() -> tuple[str, str]:
    """Return the organization escrow public key used for hard-sealed media.

    This is separate from the local BlindSite vault key and separate from the
    organization master reveal key. When enabled, preserved blocked media is
    sealed to this public key at capture time so the capture installation's
    local vault key cannot decrypt those preserved originals.
    """
    pem = get_setting("organization_hard_seal_public_key_pem", "").strip()
    fp = escrow_public_fingerprint(pem) if pem else ""
    return pem, fp


def organization_hard_seal_media_configured() -> bool:
    pem, fp = organization_hard_seal_public_key()
    return organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0") and bool(pem and fp)


def custody_label() -> str:
    return "Civilian Unknown Master Key" if civilian_unknown_master_mode() else "Organization-Controlled Key"


def init_db() -> None:
    ensure_dirs()
    schema = [
        """CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'investigator', image_policy TEXT NOT NULL DEFAULT 'blur',
            require_master_key INTEGER NOT NULL DEFAULT 1, require_approval INTEGER NOT NULL DEFAULT 1,
            require_webauthn INTEGER NOT NULL DEFAULT 0, webauthn_note TEXT, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS webauthn_credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, credential_id TEXT UNIQUE NOT NULL,
            public_key_pem TEXT NOT NULL, cose_alg INTEGER, sign_count INTEGER NOT NULL DEFAULT 0,
            aaguid TEXT, nickname TEXT, transports_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
            last_used_at TEXT, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)""",
        """CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, mode TEXT NOT NULL DEFAULT 'lockdown',
            compliance_safe INTEGER NOT NULL DEFAULT 1, irreversible_lock INTEGER NOT NULL DEFAULT 0,
            never_materialize_originals INTEGER NOT NULL DEFAULT 1, no_plaintext_export INTEGER NOT NULL DEFAULT 1,
            raw_root_allowed INTEGER NOT NULL DEFAULT 0, default_media_policy TEXT NOT NULL DEFAULT 'block_images_video',
            force_tor INTEGER NOT NULL DEFAULT 0, quarantine_default INTEGER NOT NULL DEFAULT 1,
            sealed_media_preservation_enabled INTEGER NOT NULL DEFAULT 0,
            sealed_media_preserve_images INTEGER NOT NULL DEFAULT 1,
            sealed_media_preserve_video INTEGER NOT NULL DEFAULT 1,
            sealed_media_preserve_audio INTEGER NOT NULL DEFAULT 1,
            sealed_media_preserve_max_bytes INTEGER NOT NULL DEFAULT 52428800,
            created_by TEXT, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS evidence(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, parent_evidence_id INTEGER, kind TEXT NOT NULL,
            source_type TEXT NOT NULL, source_ref TEXT, filename TEXT NOT NULL, mime_type TEXT NOT NULL,
            sha256 TEXT NOT NULL, size INTEGER NOT NULL, object_path TEXT NOT NULL, encrypted INTEGER NOT NULL DEFAULT 1,
            storage_mode TEXT NOT NULL DEFAULT 'original', raw_persisted INTEGER NOT NULL DEFAULT 1,
            meta_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'unviewed', quarantined INTEGER NOT NULL DEFAULT 1,
            lock_direct_original_access INTEGER NOT NULL DEFAULT 0, disable_plaintext_export INTEGER NOT NULL DEFAULT 0,
            never_materialize_blocked_originals INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS derived(
            id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER NOT NULL, kind TEXT NOT NULL, filename TEXT NOT NULL,
            mime_type TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, object_path TEXT NOT NULL,
            encrypted INTEGER NOT NULL DEFAULT 1, meta_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS blocked_media(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, root_evidence_id INTEGER, session_id TEXT,
            page_url TEXT, media_url TEXT NOT NULL, url_sha256 TEXT NOT NULL, resource_type TEXT NOT NULL,
            request_method TEXT, tag_type TEXT, referrer TEXT, policy TEXT NOT NULL, reason TEXT NOT NULL,
            status_code INTEGER, content_type TEXT, content_length TEXT, etag TEXT, last_modified TEXT,
            headers_json TEXT, request_headers_json TEXT, header_sha256 TEXT, content_sha256 TEXT,
            downloaded INTEGER NOT NULL DEFAULT 0, materialized_evidence_id INTEGER, metadata_record_hash TEXT NOT NULL,
            created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
            case_id INTEGER, evidence_id INTEGER, blocked_media_id INTEGER, session_id TEXT,
            investigation_id TEXT NOT NULL DEFAULT 'global',
            details_json TEXT NOT NULL DEFAULT '{}', prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS approvals(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, evidence_id INTEGER, blocked_media_id INTEGER,
            action TEXT NOT NULL, requested_by TEXT NOT NULL, reason TEXT, status TEXT NOT NULL DEFAULT 'pending',
            reviewed_by TEXT, review_reason TEXT, created_at TEXT NOT NULL, reviewed_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS browser_sessions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL, case_id INTEGER, actor TEXT NOT NULL,
            browser_choice TEXT NOT NULL, start_url TEXT NOT NULL, use_tor INTEGER NOT NULL DEFAULT 0,
            media_policy TEXT NOT NULL, headless INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'starting',
            current_url TEXT, created_at TEXT NOT NULL, stopped_at TEXT, meta_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS browser_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, created_at TEXT NOT NULL, event_type TEXT NOT NULL,
            url TEXT, resource_type TEXT, method TEXT, status_code INTEGER, headers_json TEXT, header_sha256 TEXT,
            meta_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS page_captures(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, case_id INTEGER, evidence_id INTEGER NOT NULL,
            page_url TEXT NOT NULL, page_url_sha256 TEXT NOT NULL, title TEXT, capture_mode TEXT NOT NULL,
            raw_persisted INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, meta_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS captured_assets(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, session_id TEXT, root_evidence_id INTEGER,
            resource_evidence_id INTEGER NOT NULL, original_url TEXT NOT NULL, url_sha256 TEXT NOT NULL,
            resource_type TEXT NOT NULL, mime_type TEXT, size INTEGER, sha256 TEXT,
            created_at TEXT NOT NULL, meta_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS seals(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor TEXT NOT NULL,
            audit_head TEXT NOT NULL, storage_hash TEXT NOT NULL, seal_hash TEXT NOT NULL, meta_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS stop_reports(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, evidence_id INTEGER, session_id TEXT, actor TEXT NOT NULL,
            reason TEXT NOT NULL, notes TEXT, created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS reviewer_imports(
            id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, package_sha256 TEXT NOT NULL, package_size INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'imported', imported_by TEXT NOT NULL, created_at TEXT NOT NULL,
            escrow_public_key_fingerprint TEXT, wrapped_storage_key_sha256 TEXT, object_count INTEGER NOT NULL DEFAULT 0,
            recovered_count INTEGER NOT NULL DEFAULT 0, case_name TEXT, case_id_original INTEGER, vault_path TEXT NOT NULL,
            manifest_json TEXT NOT NULL DEFAULT '{}', notes_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS reviewer_objects(
            id INTEGER PRIMARY KEY AUTOINCREMENT, import_id INTEGER NOT NULL, object_class TEXT NOT NULL, original_id INTEGER,
            filename TEXT NOT NULL, mime_type TEXT NOT NULL, kind TEXT NOT NULL, sha256 TEXT, size INTEGER,
            plaintext_path TEXT NOT NULL, zip_path TEXT, source_ref TEXT, page_url TEXT, original_url TEXT,
            root_original_id INTEGER, resource_original_id INTEGER, logical_sha256_expected TEXT, hash_ok INTEGER NOT NULL DEFAULT 1,
            meta_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
            FOREIGN KEY(import_id) REFERENCES reviewer_imports(id) ON DELETE CASCADE)""",
    ]
    with closing(db()) as con:
        for stmt in schema:
            con.execute(stmt)
        # Backward-compatible migrations for databases created by earlier local builds.
        def cols(table: str) -> set[str]:
            try:
                return {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
            except Exception:
                return set()
        def add_col(table: str, col: str, decl: str) -> None:
            if col not in cols(table):
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        add_col("settings", "updated_at", "TEXT NOT NULL DEFAULT ''")
        add_col("audit_events", "investigation_id", "TEXT NOT NULL DEFAULT 'global'")
        add_col("blocked_media", "materialized_evidence_id", "INTEGER")
        add_col("blocked_media", "request_headers_json", "TEXT")
        add_col("blocked_media", "header_sha256", "TEXT")
        add_col("blocked_media", "content_sha256", "TEXT")
        add_col("browser_sessions", "meta_json", "TEXT NOT NULL DEFAULT '{}'")
        add_col("evidence", "storage_mode", "TEXT NOT NULL DEFAULT 'original'")
        add_col("evidence", "raw_persisted", "INTEGER NOT NULL DEFAULT 1")
        add_col("evidence", "lock_direct_original_access", "INTEGER NOT NULL DEFAULT 0")
        add_col("evidence", "disable_plaintext_export", "INTEGER NOT NULL DEFAULT 0")
        add_col("evidence", "never_materialize_blocked_originals", "INTEGER NOT NULL DEFAULT 0")
        add_col("cases", "sealed_media_preservation_enabled", "INTEGER NOT NULL DEFAULT 0")
        add_col("cases", "sealed_media_preserve_images", "INTEGER NOT NULL DEFAULT 1")
        add_col("cases", "sealed_media_preserve_video", "INTEGER NOT NULL DEFAULT 1")
        add_col("cases", "sealed_media_preserve_audio", "INTEGER NOT NULL DEFAULT 1")
        add_col("cases", "sealed_media_preserve_max_bytes", "INTEGER NOT NULL DEFAULT 52428800")
        add_col("cases", "hashtags", "TEXT NOT NULL DEFAULT ''")
        add_col("page_captures", "starred", "INTEGER NOT NULL DEFAULT 0")
        add_col("page_captures", "hashtags", "TEXT NOT NULL DEFAULT ''")
        add_col("evidence", "starred", "INTEGER NOT NULL DEFAULT 0")
        add_col("evidence", "hashtags", "TEXT NOT NULL DEFAULT ''")
        add_col("reviewer_objects", "starred", "INTEGER NOT NULL DEFAULT 0")
        add_col("reviewer_objects", "hashtags", "TEXT NOT NULL DEFAULT ''")
        con.execute("UPDATE settings SET updated_at=? WHERE updated_at='' OR updated_at IS NULL", (utcnow(),))
        con.commit()
    defaults = {
        "setup_required": "1",
        "custody_mode": "organization",
        "escrow_public_key_pem": "",
        "escrow_public_key_fingerprint": "",
        "wrapped_master_key": "",
        "wrapped_storage_key": "",
        "sealed_export_enabled": "1",
        "sealed_export_include_derived": "1",
        "sealed_media_preservation_enabled": "1",
        "sealed_media_preserve_images": "1",
        "sealed_media_preserve_video": "1",
        "sealed_media_preserve_audio": "1",
        "sealed_media_preserve_max_bytes": "52428800",
        "sealed_media_preserve_max_total_bytes": "209715200",
        "sealed_media_preserve_max_items_per_session": "2500",
        "sealed_media_preserve_mime_allowlist": "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream",
        "sealed_media_preserve_fetch_timeout_ms": "3500",
        "sealed_media_preserve_mode": "balanced",
        "sealed_media_preserve_background_timeout_ms": "18000",
        "sealed_media_preserve_flush_before_capture_ms": "0",
        "sealed_media_preserve_max_pending_tasks": "75",
        "sealed_media_preserve_skip_decorative_fast": "1",
        "live_response_logging": "0",
        "live_blocked_event_logging": "0",
        "organization_hard_seal_media_enabled": "0",
        "organization_hard_seal_public_key_pem": "",
        "organization_hard_seal_public_key_fingerprint": "",
        "webauthn_stepup_max_age_seconds": "900",
        "webauthn_require_for_full_reveal": "1",
        "webauthn_require_for_plaintext_export": "1",
        "webauthn_require_for_materialization": "1",
        "webauthn_require_for_sealed_export": "1",
        "webauthn_require_for_exact_page_render": "1",
        "webauthn_require_for_admin_settings": "0",
        "edition": "lockdown",
        "default_case_mode": "lockdown",
        "default_media_policy": "block_images_video",
        "default_capture_mode": "metadata_only",
        "default_encrypt": "1",
        "hard_default_safe_mode": "1",
        "disable_full_reveal_in_lockdown": "1",
        "disable_plaintext_export_in_lockdown": "1",
        "disable_materialization_in_lockdown": "1",
        "require_master_key_full_reveal": "1",
        "require_approval_full_reveal": "1",
        "require_approval_plaintext_export": "1",
        "require_approval_materialization": "1",
        "allow_blur_in_lockdown": "1",
        "live_javascript_enabled": "1",
        "live_headless_default": "0",
        "live_browser_default": "chromium",
        "tor_browser_path": "",
        "tor_executable_path": "",
        "tor_auto_start_from_browser_bundle": "1",
        "tor_browser_force_socks": "1",
        "live_capture_allowed_media_default": "0",
        "max_live_resource_bytes": "10485760",
        "renderer_resource_logging": "1",
        "default_user_agent_profile": "chrome_windows",
        "custom_user_agent": "",
        "tor_host": "127.0.0.1",
        "tor_socks_port": "9050",
        "tor_control_port": "9051",
        "tor_control_password": "",
        "safe_allowlist_domains": "",
        "capture_denylist_domains": "",
        "max_root_read_bytes": "524288",
        "max_text_summary_chars": "20000",
        "max_blocked_records": "1000",
        "head_probe_blocked_media": "1",
        "safe_mode_allow_root_head_only": "1",
        "reject_inline_media_in_safe_mode": "1",
        "auto_open_browser": "1",
        "snapshot_max_media_bytes": "52428800",
        "snapshot_max_media_items": "250",
        "snapshot_max_total_asset_bytes": "209715200",
        "live_download_allowed_media_default": "0",
        "live_auto_capture_default": "0",
        "live_allow_captcha_challenge_media_default": "0",
        "capture_settle_before_save": "1",
        "capture_wait_after_load_ms": "5000",
        "capture_network_idle_timeout_ms": "20000",
        "capture_settle_timeout_ms": "30000",
        "capture_auto_scroll_enabled": "0",
        "capture_auto_scroll_max_steps": "30",
        "capture_auto_scroll_pause_ms": "550",
        "capture_stable_rounds": "3",
        "live_initial_navigation_timeout_ms": "60000",
        "live_auto_capture_delay_ms": "2500",
        "reviewer_enabled": "1",
        "reviewer_default_render_mode": "auto",
        "reviewer_import_unlock_timeout_seconds": "900",
        "pdf_report_navigation_timeout_ms": "60000",
        "pdf_report_domcontentloaded_timeout_ms": "20000",
        "pdf_report_scripts_wait_ms": "12000",
        "pdf_report_safe_wait_ms": "3000",
        "pdf_report_screenshot_timeout_ms": "30000",
        "pdf_report_fallback_timeout_ms": "30000",
        "pdf_report_full_width_capture": "1",
        "pdf_report_max_capture_width": "2400",
        "pdf_report_max_capture_height": "24000",
        "pdf_report_pdf_page_width_px": "1224",
        "pdf_report_pdf_page_height_px": "1584",
        "pdf_report_pdf_margin_px": "36",
        "pdf_report_split_overlap_px": "24",
        "capture_chat_profile_enabled": "1",
        "capture_chat_url_keywords": "chat\nchatroom\nrooms",
        "capture_chat_settle_timeout_ms": "10000",
        "capture_chat_network_idle_timeout_ms": "1200",
        "capture_chat_wait_after_load_ms": "500",
        "capture_chat_auto_scroll_max_steps": "8",
        "live_capture_remote_media_sweep_enabled": "1",
        "live_capture_remote_media_sweep_wait_ms": "3500",
        "live_capture_remote_media_sweep_max_items": "800",
    }
    for k, v in defaults.items():
        if fetchone("SELECT 1 FROM settings WHERE key=?", (k,)) is None:
            set_setting(k, v)
    # Keep Chromium as the default app-managed browser for new/legacy installs.
    # Earlier early-access builds could leave Firefox/Tor-Firefox as the saved default;
    # normalize those legacy defaults back to Chromium without affecting Chrome/Edge/Tor-Browser choices.
    if get_setting("live_browser_default", "chromium") in {"firefox", "tor_managed_firefox", "tor_managed_chromium"}:
        set_setting("live_browser_default", "chromium")

    # Bump legacy defaults only once when the install still uses the old defaults.
    # This preserves custom values after the user changes them in Settings.
    if get_setting("defaults_20260518_capture_tuning_applied", "0") != "1":
        if get_setting("sealed_media_preserve_max_pending_tasks", "75") in {"12", "45"}:
            set_setting("sealed_media_preserve_max_pending_tasks", "75")
        if get_setting("capture_wait_after_load_ms", "5000") == "1500":
            set_setting("capture_wait_after_load_ms", "5000")
        if get_setting("capture_network_idle_timeout_ms", "20000") == "8000":
            set_setting("capture_network_idle_timeout_ms", "20000")
        if get_setting("capture_auto_scroll_enabled", "0") == "1":
            set_setting("capture_auto_scroll_enabled", "0")
        set_setting("defaults_20260518_capture_tuning_applied", "1")
    if get_setting("sealed_media_preserve_max_items_per_session", "2500") == "250":
        set_setting("sealed_media_preserve_max_items_per_session", "2500")
    if get_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream") == "image/\nvideo/\naudio/":
        set_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream")
    if fetchone("SELECT 1 FROM users WHERE username='admin'") is None:
        execute("INSERT INTO users(username,password_hash,role,image_policy,require_master_key,require_approval,created_at) VALUES(?,?,?,?,?,?,?)", ("admin", hash_password("change-me-now"), "admin", "full", 0, 0, utcnow()))
    ensure_secret_file(SECRET_FILE, 48)
    fernet()
    # If an older Civilian Unknown Master Key installation already has
    # sensitive/original evidence stored with the normal local vault key,
    # upgrade it in-place to hard-sealed escrow storage so the local vault key
    # can no longer decrypt those objects.
    try:
        if get_setting("custody_mode", "organization") == "civilian_unknown_master":
            migrate_existing_civilian_sensitive_evidence_to_hard_sealed()
        elif get_setting("custody_mode", "organization") == "organization" and setting_bool("organization_hard_seal_media_enabled", "0"):
            migrate_existing_organization_preserved_media_to_hard_sealed()
    except NameError:
        # Function is defined later; this only matters for unusual import-time
        # calls before the module has finished loading. Normal app startup and
        # CLI paths call init_db after definitions are loaded.
        pass



ZERO_HASH = "0" * 64
APPLICATION_BUILD_IDENTITY_CACHE: dict[str, Any] | None = None
AUDIT_GENERATED_DETAIL_KEYS = {"genesis_hash", "event_hash"}


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    hsh = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            if chunk:
                hsh.update(chunk)
    return hsh.hexdigest()


def git_value(args: list[str]) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=str(BASE_DIR), capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return (r.stdout or "").strip()
    except Exception:
        pass
    return ""


def current_git_commit() -> str:
    for key in ["BLINDSITE_GIT_COMMIT", "APP_GIT_COMMIT", "GIT_COMMIT", "RELEASE_GIT_COMMIT"]:
        val = os.environ.get(key, "").strip()
        if val:
            return val
    val = git_value(["rev-parse", "HEAD"])
    if val:
        return val
    try:
        head = (BASE_DIR / ".git" / "HEAD").read_text(encoding="utf-8", errors="ignore").strip()
        if head.startswith("ref:"):
            ref = head.split(" ", 1)[1].strip()
            ref_path = BASE_DIR / ".git" / ref
            if ref_path.exists():
                return ref_path.read_text(encoding="utf-8", errors="ignore").strip()
        elif head:
            return head
    except Exception:
        pass
    return ""


def current_release_tag() -> str:
    for key in ["BLINDSITE_RELEASE_TAG", "APP_RELEASE_TAG", "RELEASE_TAG", "GITHUB_REF_NAME"]:
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return git_value(["describe", "--tags", "--exact-match"])


def application_build_identity(*, refresh: bool = False) -> dict[str, Any]:
    """Return the current Application Genesis Hash identity for this build.

    Frozen/PyInstaller builds are bound to sys.executable. Source runs are bound
    to this main Python file plus any nearby simple source/build manifest if one
    exists. Hashing failures never block startup; the failure is returned and
    can be recorded in the genesis audit event.
    """
    global APPLICATION_BUILD_IDENTITY_CACHE
    if APPLICATION_BUILD_IDENTITY_CACHE is not None and not refresh:
        return dict(APPLICATION_BUILD_IDENTITY_CACHE)

    frozen = bool(getattr(sys, "frozen", False))
    identity: dict[str, Any] = {
        "feature_name": "Application Genesis Hash",
        "seal_name": "Executable Genesis Seal",
        "app_name": "BlindSite",
        "app_title": APP_NAME,
        "app_version": APP_VERSION,
        "frozen_executable": frozen,
        "build_kind": "frozen_executable" if frozen else "source",
        "executable_path": str(Path(sys.executable).resolve()) if frozen else "",
        "source_path": "" if frozen else str(Path(__file__).resolve()),
        "executable_sha256": "",
        "git_commit": current_git_commit(),
        "release_tag": current_release_tag(),
        "source_component_hashes": [],
        "hash_error": "",
        "warnings": [],
    }

    try:
        if frozen:
            target = Path(sys.executable).resolve()
            identity["executable_sha256"] = sha256_file(target)
        else:
            components: list[dict[str, Any]] = []
            main_path = Path(__file__).resolve()
            components.append({"kind": "main_source", "path": str(main_path), "sha256": sha256_file(main_path)})
            for name in [
                "build_manifest.json", "source_manifest.json", "application_manifest.json",
                "manifest.json", "SHA256SUMS", "RELEASE.txt", "VERSION.txt"
            ]:
                candidate = BASE_DIR / name
                if candidate.exists() and candidate.is_file():
                    try:
                        components.append({"kind": "manifest", "path": str(candidate.resolve()), "sha256": sha256_file(candidate)})
                    except Exception as exc:
                        components.append({"kind": "manifest", "path": str(candidate.resolve()), "sha256": "", "error": str(exc)[:500]})
            identity["source_component_hashes"] = components
            if len(components) == 1:
                identity["executable_sha256"] = components[0].get("sha256", "")
            else:
                identity["executable_sha256"] = sha256_text(canonical(components))
    except Exception as exc:
        identity["hash_error"] = str(exc)[:1000]

    if not identity.get("executable_sha256"):
        identity["warnings"].append("Executable Genesis Seal warning: executable/source hash could not be computed.")
    if not frozen:
        identity["warnings"].append("Executable Genesis Seal warning: source mode was used instead of a frozen/release executable.")
    if not identity.get("git_commit"):
        identity["warnings"].append("Executable Genesis Seal warning: git_commit is missing.")
    if not identity.get("release_tag"):
        identity["warnings"].append("Executable Genesis Seal warning: release_tag is missing.")
    if identity.get("hash_error"):
        identity["warnings"].append("Executable Genesis Seal warning: hash computation failed; see hash_error.")

    APPLICATION_BUILD_IDENTITY_CACHE = dict(identity)
    return identity


def infer_investigation_id(case_id: int | None = None, session_id: str | None = None, details: dict[str, Any] | None = None) -> str:
    details = details or {}
    explicit = str(details.get("investigation_id") or "").strip()
    if explicit:
        return explicit
    if session_id:
        return f"session:{session_id}"
    if case_id is not None:
        return f"case:{int(case_id)}"
    return "global"


def audit_details_for_hash(details: dict[str, Any] | None) -> dict[str, Any]:
    details = dict(details or {})
    for key in AUDIT_GENERATED_DETAIL_KEYS:
        details.pop(key, None)
    return details


def audit_event_hash(*, created_at: str, actor: str, action: str, case_id: int | None, evidence_id: int | None, blocked_media_id: int | None, session_id: str | None, investigation_id: str, details: dict[str, Any], prev_hash: str, include_investigation_id: bool = True) -> str:
    event = {
        "created_at": created_at,
        "actor": actor,
        "action": action,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "blocked_media_id": blocked_media_id,
        "session_id": session_id,
        "details": audit_details_for_hash(details),
        "prev_hash": prev_hash,
    }
    if include_investigation_id:
        event["investigation_id"] = investigation_id
    return sha256_text(canonical(event))


def application_genesis_event_details(*, investigation_id: str, case_id: int | None = None, session_id: str | None = None, created_at: str | None = None) -> dict[str, Any]:
    ident = application_build_identity()
    created_at = created_at or utcnow()
    details = {
        "event_type": "application_genesis",
        "feature_name": "Application Genesis Hash",
        "seal_name": "Executable Genesis Seal",
        "app_name": "BlindSite",
        "app_title": APP_NAME,
        "app_version": APP_VERSION,
        "build_kind": ident.get("build_kind"),
        "frozen_executable": bool(ident.get("frozen_executable")),
        "executable_path": ident.get("executable_path") or "",
        "source_path": ident.get("source_path") or "",
        "executable_sha256": ident.get("executable_sha256") or "",
        "source_component_hashes": ident.get("source_component_hashes") or [],
        "hash_error": ident.get("hash_error") or "",
        "git_commit": ident.get("git_commit") or "",
        "release_tag": ident.get("release_tag") or "",
        "custody_mode": custody_mode(),
        "investigation_id": investigation_id,
        "case_id": case_id,
        "session_id": session_id,
        "created_at": created_at,
        "previous_hash": ZERO_HASH,
        "verification_statement": "This investigation was initialized with BlindSite executable SHA-256: {hash}. Compare this hash against the published GitHub release SHA256SUMS for the claimed release.".format(hash=ident.get("executable_sha256") or "UNAVAILABLE"),
        "warnings": ident.get("warnings") or [],
    }
    return details


def ensure_application_genesis_event(investigation_id: str, *, case_id: int | None = None, session_id: str | None = None, actor: str = "system") -> dict[str, Any]:
    investigation_id = investigation_id or infer_investigation_id(case_id, session_id)
    existing = rowdict(fetchone("SELECT * FROM audit_events WHERE investigation_id=? AND action='application_genesis' ORDER BY id ASC LIMIT 1", (investigation_id,)))
    if existing:
        details = jloads(existing.get("details_json"), {})
        details.setdefault("genesis_hash", existing.get("event_hash"))
        return {"created": False, "event": existing, "details": details}

    prior = rowdict(fetchone("SELECT * FROM audit_events WHERE investigation_id=? ORDER BY id ASC LIMIT 1", (investigation_id,)))
    if prior:
        # Backward compatibility: do not insert a retroactive genesis event after
        # old audit events because that would make the existing chain look broken.
        details = application_genesis_event_details(investigation_id=investigation_id, case_id=case_id, session_id=session_id)
        details.setdefault("warnings", []).append("Application Genesis Hash warning: existing legacy audit events were present before this feature; genesis was not inserted retroactively.")
        return {"created": False, "event": None, "details": details, "legacy_without_genesis": True}

    created_at = utcnow()
    details = application_genesis_event_details(investigation_id=investigation_id, case_id=case_id, session_id=session_id, created_at=created_at)
    event_hash = audit_event_hash(created_at=created_at, actor=actor, action="application_genesis", case_id=case_id, evidence_id=None, blocked_media_id=None, session_id=session_id, investigation_id=investigation_id, details=details, prev_hash=ZERO_HASH)
    details["genesis_hash"] = event_hash
    details["event_hash"] = event_hash
    try:
        execute("""INSERT INTO audit_events(created_at,actor,action,case_id,evidence_id,blocked_media_id,session_id,investigation_id,details_json,prev_hash,event_hash)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (created_at, actor, "application_genesis", case_id, None, None, session_id, investigation_id, json.dumps(details, ensure_ascii=False), ZERO_HASH, event_hash))
        ev = rowdict(fetchone("SELECT * FROM audit_events WHERE investigation_id=? AND action='application_genesis' ORDER BY id ASC LIMIT 1", (investigation_id,))) or {}
        return {"created": True, "event": ev, "details": details}
    except Exception as exc:
        # Do not block startup/session creation. If SQLite insertion itself fails,
        # the caller cannot rely on the audit table, so return a clear failure
        # object for diagnostic surfaces.
        details.setdefault("warnings", []).append(f"Executable Genesis Seal warning: genesis audit event could not be written: {exc}")
        return {"created": False, "event": None, "details": details, "error": str(exc)}


def application_genesis_report(*, case_id: int | None = None, session_id: str | None = None, investigation_id: str | None = None) -> dict[str, Any]:
    investigation_id = investigation_id or infer_investigation_id(case_id, session_id)
    row = rowdict(fetchone("SELECT * FROM audit_events WHERE investigation_id=? AND action='application_genesis' ORDER BY id ASC LIMIT 1", (investigation_id,)))
    warnings: list[str] = []
    if not row:
        warnings.append("Application Genesis Hash warning: audit chain does not start with application_genesis or genesis event is missing.")
        ident = application_build_identity()
        return {
            "present": False,
            "investigation_id": investigation_id,
            "current_application_identity": ident,
            "warnings": warnings + list(ident.get("warnings") or []),
            "verification_statement": "This investigation was initialized with BlindSite executable SHA-256: UNAVAILABLE. Compare this hash against the published GitHub release SHA256SUMS for the claimed release.",
        }
    details = jloads(row.get("details_json"), {})
    executable_sha256 = details.get("executable_sha256") or ""
    warnings.extend(details.get("warnings") or [])
    if not executable_sha256:
        warnings.append("Application Genesis Hash warning: executable hash could not be computed.")
    if details.get("build_kind") == "source" or details.get("source_path"):
        warnings.append("Application Genesis Hash warning: source mode was used instead of frozen/release executable.")
    if not details.get("release_tag"):
        warnings.append("Application Genesis Hash warning: release_tag is missing.")
    if not details.get("git_commit"):
        warnings.append("Application Genesis Hash warning: git_commit is missing.")
    statement = "This investigation was initialized with BlindSite executable SHA-256: {hash}. Compare this hash against the published GitHub release SHA256SUMS for the claimed release.".format(hash=executable_sha256 or "UNAVAILABLE")
    return {
        "present": True,
        "event_id": row.get("id"),
        "investigation_id": investigation_id,
        "event_hash": row.get("event_hash"),
        "genesis_hash": details.get("genesis_hash") or row.get("event_hash"),
        "created_at": row.get("created_at"),
        "app_name": details.get("app_name") or "BlindSite",
        "app_version": details.get("app_version") or APP_VERSION,
        "build_kind": details.get("build_kind") or "",
        "executable_path": details.get("executable_path") or "",
        "source_path": details.get("source_path") or "",
        "executable_sha256": executable_sha256,
        "git_commit": details.get("git_commit") or "",
        "release_tag": details.get("release_tag") or "",
        "custody_mode": details.get("custody_mode") or custody_mode(),
        "verification_statement": statement,
        "warnings": sorted(set(warnings)),
        "details": details,
    }


def log_event(actor: str, action: str, *, case_id: int | None = None, evidence_id: int | None = None, blocked_media_id: int | None = None, session_id: str | None = None, details: dict[str, Any] | None = None) -> str:
    details = dict(details or {})
    investigation_id = infer_investigation_id(case_id, session_id, details)
    details.setdefault("investigation_id", investigation_id)
    if action != "application_genesis" and details.get("event_type") != "application_genesis":
        ensure_application_genesis_event(investigation_id, case_id=case_id, session_id=session_id)
    prev = fetchone("SELECT event_hash FROM audit_events WHERE investigation_id=? ORDER BY id DESC LIMIT 1", (investigation_id,))
    prev_hash = prev["event_hash"] if prev else ZERO_HASH
    created_at = utcnow()
    event_hash = audit_event_hash(created_at=created_at, actor=actor, action=action, case_id=case_id, evidence_id=evidence_id, blocked_media_id=blocked_media_id, session_id=session_id, investigation_id=investigation_id, details=details, prev_hash=prev_hash)
    execute("""INSERT INTO audit_events(created_at,actor,action,case_id,evidence_id,blocked_media_id,session_id,investigation_id,details_json,prev_hash,event_hash)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (created_at, actor, action, case_id, evidence_id, blocked_media_id, session_id, investigation_id, json.dumps(details, ensure_ascii=False), prev_hash, event_hash))
    return event_hash


def verify_audit_chain() -> dict[str, Any]:
    rows = fetchall("SELECT * FROM audit_events ORDER BY investigation_id ASC, id ASC")
    by_inv: dict[str, list[sqlite3.Row]] = {}
    for r in rows:
        inv = str(r["investigation_id"] or "global")
        by_inv.setdefault(inv, []).append(r)
    bad: list[dict[str, Any]] = []
    warnings: list[str] = []
    heads: dict[str, str] = {}
    genesis: dict[str, Any] = {}
    for inv, inv_rows in by_inv.items():
        prev_expected = ""
        first = True
        starts_with_genesis = False
        for r in inv_rows:
            details = jloads(r["details_json"], {})
            is_genesis = r["action"] == "application_genesis" or details.get("event_type") == "application_genesis"
            if first:
                starts_with_genesis = bool(is_genesis and r["prev_hash"] == ZERO_HASH)
                if not starts_with_genesis:
                    warnings.append(f"Audit chain warning: investigation {inv} does not start with application_genesis.")
                    # Preserve backward compatibility for legacy global audit rows.
                    prev_expected = str(r["prev_hash"] or "GENESIS")
                else:
                    prev_expected = ZERO_HASH
                    genesis[inv] = {"id": r["id"], "event_hash": r["event_hash"], "details": details}
                first = False
            if r["prev_hash"] != prev_expected:
                bad.append({"id": r["id"], "investigation_id": inv, "expected_prev": prev_expected, "actual_prev": r["prev_hash"]})
            expected = audit_event_hash(created_at=r["created_at"], actor=r["actor"], action=r["action"], case_id=r["case_id"], evidence_id=r["evidence_id"], blocked_media_id=r["blocked_media_id"], session_id=r["session_id"], investigation_id=inv, details=details, prev_hash=r["prev_hash"])
            legacy_expected = audit_event_hash(created_at=r["created_at"], actor=r["actor"], action=r["action"], case_id=r["case_id"], evidence_id=r["evidence_id"], blocked_media_id=r["blocked_media_id"], session_id=r["session_id"], investigation_id=inv, details=details, prev_hash=r["prev_hash"], include_investigation_id=False)
            if r["event_hash"] not in {expected, legacy_expected}:
                bad.append({"id": r["id"], "investigation_id": inv, "expected": expected, "legacy_expected": legacy_expected, "actual": r["event_hash"]})
            prev_expected = r["event_hash"]
        if inv_rows:
            heads[inv] = inv_rows[-1]["event_hash"]
    global_head = ""
    try:
        last = fetchone("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1")
        global_head = last["event_hash"] if last else ZERO_HASH
    except Exception:
        global_head = ZERO_HASH
    return {"ok": not bad, "count": sum(len(v) for v in by_inv.values()), "head": global_head, "heads_by_investigation": heads, "genesis_by_investigation": genesis, "warnings": warnings[:50], "bad": bad[:20]}


def storage_hash() -> str:
    hsh = hashlib.sha256()
    for root in [EVIDENCE_DIR, DERIVED_DIR]:
        if root.exists():
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    rel = str(p.relative_to(DATA_DIR)).replace("\\", "/")
                    hsh.update(rel.encode())
                    hsh.update(sha256_bytes(p.read_bytes()).encode())
    return hsh.hexdigest()


@asynccontextmanager
async def lifespan(app_obj: FastAPI):
    init_db()
    try:
        if setting_bool("tor_background_prewarm_enabled", "0"):
            tor_prewarm_background("startup")
    except Exception:
        pass
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=app_secret(), same_site="lax", https_only=False)
serializer = URLSafeTimedSerializer(app_secret(), salt="blindsite-view-token")


@app.middleware("http")
async def local_webauthn_canonical_host_middleware(request: Request, call_next):
    # WebAuthn/passkey APIs are strict about secure contexts and RP IDs. BlindSite
    # remains bound to loopback for safety, but browser pages should use
    # http://localhost rather than http://127.0.0.1 to avoid browser
    # SecurityError / "The operation is insecure" during YubiKey enrollment.
    try:
        host = request.url.hostname or ""
        accept = request.headers.get("accept", "")
        if (
            request.method == "GET"
            and request.url.scheme == "http"
            and host.strip().lower().strip("[]") in {"127.0.0.1", "::1", "0.0.0.0"}
            and "text/html" in accept.lower()
        ):
            return RedirectResponse(webauthn_canonical_local_url(request), 303)
    except Exception:
        pass
    return await call_next(request)


def current_user(request: Request) -> dict[str, Any] | None:
    username = request.session.get("username")
    if not username:
        return None
    row = fetchone("SELECT * FROM users WHERE username=?", (username,))
    return dict(row) if row else None


def require_user(request: Request) -> dict[str, Any]:
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Login required")
    return user


def is_admin(user: dict[str, Any]) -> bool:
    return user.get("role") in {"admin", "supervisor"}


def require_admin(request: Request) -> dict[str, Any]:
    u = require_user(request)
    if not is_admin(u):
        raise HTTPException(403, "Admin/supervisor only")
    return u


# ---------------------------------------------------------------------------
# Simple YubiKey / WebAuthn step-up support
# ---------------------------------------------------------------------------
# Browser-native WebAuthn is intentionally implemented as an optional local
# step-up layer. Existing installs keep working. Once a user enrolls a FIDO2
# key, BlindSite can ask for that key before sensitive actions such as login,
# full reveal, plaintext export, materialization, sealed export, and exact
# renderer unlock. Localhost is a valid WebAuthn secure context for testing.

WEBAUTHN_STEPUP_ACTION_LABELS = {
    "login": "sign-in",
    "full_reveal": "full evidence reveal",
    "plaintext_export": "plaintext evidence export",
    "materialize_original": "blocked-media materialization",
    "sealed_export": "sealed evidence export",
    "exact_page_render": "exact local page render",
    "admin_settings": "admin/settings change",
    "reviewer_import_unlock": "LE reviewer case unlock",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    value = (value or "").strip()
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii"))


class _CborReader:
    def __init__(self, data: bytes):
        self.data = data
        self.i = 0

    def read(self, n: int) -> bytes:
        if self.i + n > len(self.data):
            raise ValueError("CBOR truncated")
        out = self.data[self.i:self.i + n]
        self.i += n
        return out

    def read_len(self, add: int) -> int:
        if add < 24:
            return add
        if add == 24:
            return self.read(1)[0]
        if add == 25:
            return int.from_bytes(self.read(2), "big")
        if add == 26:
            return int.from_bytes(self.read(4), "big")
        if add == 27:
            return int.from_bytes(self.read(8), "big")
        raise ValueError("Unsupported indefinite CBOR item")

    def parse(self) -> Any:
        ib = self.read(1)[0]
        major = ib >> 5
        add = ib & 31
        if major == 0:
            return self.read_len(add)
        if major == 1:
            return -1 - self.read_len(add)
        if major == 2:
            return self.read(self.read_len(add))
        if major == 3:
            return self.read(self.read_len(add)).decode("utf-8", errors="replace")
        if major == 4:
            return [self.parse() for _ in range(self.read_len(add))]
        if major == 5:
            return {self.parse(): self.parse() for _ in range(self.read_len(add))}
        if major == 7:
            if add == 20:
                return False
            if add == 21:
                return True
            if add == 22:
                return None
            if add == 23:
                return None
        raise ValueError(f"Unsupported CBOR major={major} add={add}")


def cbor_decode(data: bytes) -> Any:
    return _CborReader(data).parse()


def webauthn_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"


def webauthn_loopback_host(host: str | None) -> bool:
    host = (host or "").strip().lower().strip("[]")
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def webauthn_public_host_for(host: str | None) -> str:
    # Browser WebAuthn is strict about secure contexts and relying-party IDs.
    # For local app use, prefer localhost over raw loopback IPs because some
    # browsers reject ceremonies started from 127.0.0.1/::1 with SecurityError /
    # "The operation is insecure" before the YubiKey prompt can appear.
    return "localhost" if webauthn_loopback_host(host) else (host or "localhost")


def webauthn_public_url_for(host: str | None, port: int | str, path: str = "") -> str:
    public_host = webauthn_public_host_for(host)
    suffix = path if str(path or "").startswith("/") else ("/" + str(path or "")) if path else ""
    return f"http://{public_host}:{int(port)}{suffix}"


def webauthn_canonical_local_url(request: Request) -> str:
    port = request.url.port or DEFAULT_PORT
    path = request.url.path or "/"
    query = ("?" + request.url.query) if request.url.query else ""
    return webauthn_public_url_for("localhost", port, path + query)


def webauthn_canonical_redirect_if_needed(request: Request) -> RedirectResponse | None:
    # If the user opened BlindSite at http://127.0.0.1:8765, most app routes are
    # fine, but WebAuthn may fail in-browser. Redirect WebAuthn ceremonies to
    # http://localhost:8765 before calling navigator.credentials.*.
    host = request.url.hostname or ""
    scheme = request.url.scheme or "http"
    if scheme == "http" and host.strip().lower().strip("[]") in {"127.0.0.1", "::1", "0.0.0.0"}:
        return RedirectResponse(webauthn_canonical_local_url(request), 303)
    return None


def webauthn_rp_id(request: Request) -> str:
    return webauthn_public_host_for(request.url.hostname)


def webauthn_public_key_rp_id(request: Request) -> str:
    """Return the RP ID to explicitly send to navigator.credentials, or ''.

    Local BlindSite normally runs on localhost/loopback over HTTP. Browsers treat
    localhost as a special secure context, but some reject explicit RP IDs on
    loopback origins and throw DOMException/SecurityError: "The operation is
    insecure" before the YubiKey prompt appears. For loopback/local origins we
    therefore omit rp.id/rpId and let the browser use the current origin's RP ID.
    For non-local deployments, BlindSite still sends the current hostname.
    """
    host = (request.url.hostname or "localhost").strip().lower().strip("[]")
    if webauthn_loopback_host(host):
        return ""
    return host or ""


def webauthn_rp_id_candidates(request: Request) -> list[str]:
    """Accept only current-host/local RP hashes during verification."""
    host = (request.url.hostname or "localhost").strip().lower().strip("[]")
    candidates: list[str] = []
    for item in [webauthn_public_key_rp_id(request), host, webauthn_rp_id(request)]:
        if item and item not in candidates:
            candidates.append(item)
    if webauthn_loopback_host(host):
        for item in ["localhost", "127.0.0.1", "::1"]:
            if item not in candidates:
                candidates.append(item)
    return candidates or ["localhost"]


def webauthn_rp_hash_valid(request: Request, rp_hash: bytes) -> bool:
    return any(hashlib.sha256(candidate.encode("utf-8")).digest() == rp_hash for candidate in webauthn_rp_id_candidates(request))


def webauthn_secure_context_hint(request: Request) -> dict[str, Any]:
    host = (request.url.hostname or "localhost").strip().lower().strip("[]")
    scheme = (request.url.scheme or "http").lower()
    loopback = webauthn_loopback_host(host)
    secure_expected = bool(scheme == "https" or loopback)
    warnings: list[str] = []
    if not secure_expected:
        warnings.append("WebAuthn/YubiKey requires HTTPS or localhost/loopback. Open BlindSite through http://localhost on this machine, or use HTTPS for a deployed instance.")
    if scheme == "http" and host in {"127.0.0.1", "::1", "0.0.0.0"}:
        warnings.append("If enrollment says 'The operation is insecure', reopen BlindSite at http://localhost:<port>/webauthn and retry.")
    return {
        "origin": webauthn_origin(request),
        "host": host,
        "scheme": scheme,
        "loopback": loopback,
        "secure_context_expected": secure_expected,
        "explicit_rp_id_sent": webauthn_public_key_rp_id(request) or "",
        "rp_id_candidates": webauthn_rp_id_candidates(request),
        "canonical_local_url": webauthn_canonical_local_url(request) if loopback else "",
        "warnings": warnings,
    }


def webauthn_credential_rows(username: str) -> list[sqlite3.Row]:
    return fetchall("SELECT * FROM webauthn_credentials WHERE username=? ORDER BY id", (username,))


def webauthn_credential_count(username: str) -> int:
    row = fetchone("SELECT count(*) c FROM webauthn_credentials WHERE username=?", (username,))
    return int(row["c"] or 0) if row else 0


def webauthn_user_has_credentials(username: str) -> bool:
    return webauthn_credential_count(username) > 0


def webauthn_public_key_from_cose(cose: dict[Any, Any]) -> tuple[str, int]:
    alg = int(cose.get(3) or 0)
    kty = cose.get(1)
    if kty == 2:  # EC2 / usually ES256 on YubiKey/FIDO2 keys
        crv = cose.get(-1)
        x = cose.get(-2)
        y = cose.get(-3)
        if crv != 1 or not isinstance(x, bytes) or not isinstance(y, bytes):
            raise ValueError("Only P-256 EC2 WebAuthn keys are supported for this enrollment")
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    elif kty == 3:  # RSA
        n = cose.get(-1)
        e = cose.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes):
            raise ValueError("Invalid RSA COSE key")
        pub = rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    else:
        raise ValueError(f"Unsupported WebAuthn COSE key type: {kty!r}")
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return pem, alg


def webauthn_parse_authenticator_data(auth_data: bytes) -> dict[str, Any]:
    if len(auth_data) < 37:
        raise ValueError("Authenticator data is too short")
    rp_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    out: dict[str, Any] = {"rp_id_hash": rp_hash, "flags": flags, "sign_count": sign_count}
    if flags & 0x40:
        if len(auth_data) < 55:
            raise ValueError("Attested credential data is too short")
        aaguid = auth_data[37:53]
        cred_len = int.from_bytes(auth_data[53:55], "big")
        cred_start = 55
        cred_end = cred_start + cred_len
        if len(auth_data) < cred_end:
            raise ValueError("Credential ID is truncated")
        credential_id = auth_data[cred_start:cred_end]
        cose = cbor_decode(auth_data[cred_end:])
        out.update({"aaguid": aaguid, "credential_id": credential_id, "cose_public_key": cose})
    return out


def webauthn_check_client_data(request: Request, encoded: str, expected_type: str, challenge_session_key: str) -> tuple[dict[str, Any], bytes]:
    raw = b64url_decode(encoded)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, f"Invalid WebAuthn client data: {exc}") from exc
    if obj.get("type") != expected_type:
        raise HTTPException(400, f"Unexpected WebAuthn ceremony type: {obj.get('type')!r}")
    expected_challenge = request.session.get(challenge_session_key)
    if not expected_challenge or obj.get("challenge") != expected_challenge:
        raise HTTPException(400, "WebAuthn challenge mismatch or expired challenge")
    origin = str(obj.get("origin") or "")
    expected_origin = webauthn_origin(request)
    if origin != expected_origin:
        host = request.url.hostname or ""
        localhost_ok = host in {"localhost", "127.0.0.1", "::1"} and origin.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]"))
        if not localhost_ok:
            raise HTTPException(400, f"WebAuthn origin mismatch: {origin!r} != {expected_origin!r}")
    return obj, raw


def webauthn_verify_signature(public_key_pem: str, signature: bytes, signed_data: bytes) -> None:
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported WebAuthn public key type")


def webauthn_stepup_max_age() -> int:
    return safe_int(get_setting("webauthn_stepup_max_age_seconds", "900"), 900, min_value=60, max_value=86400)


def webauthn_step_up_valid(request: Request, user: dict[str, Any] | None = None, *, max_age: int | None = None) -> bool:
    user = user or current_user(request)
    if not user:
        return False
    try:
        ts = float(request.session.get("webauthn_verified_at") or 0)
    except Exception:
        return False
    if request.session.get("webauthn_verified_user") != user.get("username"):
        return False
    return bool(ts and time.time() - ts <= float(max_age or webauthn_stepup_max_age()))


def webauthn_action_setting(action: str) -> str:
    return {
        "full_reveal": "webauthn_require_for_full_reveal",
        "plaintext_export": "webauthn_require_for_plaintext_export",
        "materialize_original": "webauthn_require_for_materialization",
        "sealed_export": "webauthn_require_for_sealed_export",
        "exact_page_render": "webauthn_require_for_exact_page_render",
        "admin_settings": "webauthn_require_for_admin_settings",
    }.get(action, "")


def webauthn_action_requires_stepup(user: dict[str, Any], action: str) -> bool:
    """Return True only when this account explicitly opted into YubiKey step-up.

    YubiKey/WebAuthn is optional and additive. It never replaces the master
    reveal key, approvals, custody locks, or existing policy checks. Enrolling a
    key alone does not force prompts; the user must enable the account
    requirement. Per-action settings let an admin narrow where the extra prompt
    appears, but the user-level require_webauthn flag is the on/off switch.
    """
    if action == "reviewer_import_unlock":
        return True
    if not truthy(user.get("require_webauthn")):
        return False
    setting_key = webauthn_action_setting(action)
    if setting_key:
        return setting_bool(setting_key, "1")
    return action in {"login", "step_up", "manual"}


def webauthn_stepup_redirect_if_needed(request: Request, user: dict[str, Any], action: str, return_to: str) -> RedirectResponse | None:
    if not webauthn_action_requires_stepup(user, action):
        return None
    if not webauthn_user_has_credentials(str(user.get("username") or "")):
        raise HTTPException(403, "YubiKey/WebAuthn step-up is required for this account, but no key is enrolled. Open Settings → YubiKey to enroll a key or ask an admin to disable the policy.")
    if webauthn_step_up_valid(request, user):
        return None
    label = WEBAUTHN_STEPUP_ACTION_LABELS.get(action, action.replace("_", " "))
    log_event(user["username"], "YUBIKEY_STEP_UP_REQUIRED", details={"action": action, "label": label, "return_to": return_to})
    return RedirectResponse(f"/webauthn/step-up?action={quote(action)}&return_to={quote(return_to or '/')}", 303)


def webauthn_global_guard_script() -> str:
    """Small global helper that turns annotated forms into browser YubiKey prompts.

    Forms opt in with data-webauthn-action="full_reveal" etc. The server still
    enforces step-up, but this gives the user the simple native browser pop-up
    before the form posts so passwords/master keys are not lost to a redirect.
    """
    return r"""
<script>
(function(){
  if (window.__blindsiteWebAuthnGuardInstalled) return;
  window.__blindsiteWebAuthnGuardInstalled = true;
  function b64ToBuf(s){
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64(buf){
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/g, '');
  }
  function ensureWebAuthnSafeOrigin(){
    const host = (location.hostname || '').toLowerCase();
    if (location.protocol === 'http:' && (host === '127.0.0.1' || host === '::1' || host === '0.0.0.0')) {
      const target = 'http://localhost:' + location.port + location.pathname + location.search + location.hash;
      window.location.replace(target);
      throw new Error('Switching to localhost for YubiKey/WebAuthn. Try again after the page reloads.');
    }
    if (!window.isSecureContext) {
      throw new Error('WebAuthn requires a secure browser context. Use http://localhost for local BlindSite, or HTTPS for deployed instances.');
    }
  }
  async function runStepUp(action){
    ensureWebAuthnSafeOrigin();
    if (!navigator.credentials || !window.PublicKeyCredential) {
      throw new Error('This browser does not expose WebAuthn. Use Chrome/Edge/Firefox on localhost or HTTPS.');
    }
    const r = await fetch('/webauthn/auth/options?action=' + encodeURIComponent(action || 'step_up'), {cache:'no-store'});
    const opts = await r.json();
    if (!opts.ok) throw new Error(opts.error || 'Could not start YubiKey/WebAuthn');
    const pub = opts.publicKey;
    pub.challenge = b64ToBuf(pub.challenge);
    if (pub.allowCredentials) pub.allowCredentials = pub.allowCredentials.map(c => ({...c, id: b64ToBuf(c.id)}));
    const assertion = await navigator.credentials.get({publicKey: pub});
    const payload = {
      mode: 'stepup',
      action: action || '',
      rawId: bufToB64(assertion.rawId),
      id: assertion.id,
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64(assertion.response.clientDataJSON),
        authenticatorData: bufToB64(assertion.response.authenticatorData),
        signature: bufToB64(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64(assertion.response.userHandle) : ''
      }
    };
    const vr = await fetch('/webauthn/auth/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const v = await vr.json();
    if (!v.ok) throw new Error(v.error || 'YubiKey/WebAuthn verification failed');
    return v;
  }
  document.addEventListener('submit', async function(ev){
    const form = ev.target;
    if (!form || !form.dataset || !form.dataset.webauthnAction || form.dataset.webauthnPassed === '1') return;
    const conditional = form.dataset.webauthnIfChecked || '';
    if (conditional) {
      const field = form.querySelector('[name="' + conditional.replace(/"/g, '\"') + '"]');
      if (!field || !field.checked) return;
    }
    ev.preventDefault();
    const action = form.dataset.webauthnAction || 'step_up';
    try {
      const rr = await fetch('/webauthn/required?action=' + encodeURIComponent(action), {cache:'no-store'});
      const req = await rr.json();
      if (!req.required || req.verified) {
        form.dataset.webauthnPassed = '1';
        form.submit();
        return;
      }
      if (!req.has_credentials) throw new Error('This account requires YubiKey/WebAuthn, but no key is enrolled. Open Settings → YubiKey.');
      alert('BlindSite needs your YubiKey/security key before: ' + (req.label || action) + '. Touch the key when your browser asks.');
      await runStepUp(action);
      form.dataset.webauthnPassed = '1';
      form.submit();
    } catch(e) {
      alert('YubiKey/WebAuthn verification failed or was cancelled: ' + (e && e.message ? e.message : e));
    }
  }, true);
})();
</script>
"""


def webauthn_recent_or_redirect(request: Request, user: dict[str, Any], action: str, return_to: str) -> RedirectResponse | None:
    return webauthn_stepup_redirect_if_needed(request, user, action, return_to)


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 401 and str(exc.detail) == "Login required":
        return RedirectResponse("/login", 303)
    body = layout(request, f"Error {exc.status_code}", f"<div class='card danger'><h2>Error {exc.status_code}</h2><p>{h(exc.detail)}</p><p><a href='/'>Back to dashboard</a></p></div>")
    return HTMLResponse(body.body.decode(), status_code=exc.status_code)


def badge(text: Any, cls: str = "") -> str:
    return f"<span class='badge {cls}'>{h(text)}</span>"


def nav(request: Request) -> str:
    u = current_user(request)
    if not u:
        return ""
    setup = "" if get_setting("setup_required", "0") != "1" else "<a href='/setup'>Setup</a>"
    return f"""
    <nav>
      <b>{APP_NAME}</b>
      <a href='/'>Dashboard</a><a href='/cases'>Cases</a><a href='/live'>Live Sessions</a><a href='/captures'>Saved Pages</a><a href='/media'>Media</a><a href='/reviewer'>LE Reviewer</a><a href='/search'>Search</a><a href='/reports'>Reports</a><a href='/approvals'>Approvals</a><a href='/custody'>Custody</a><a href='/settings'>Settings</a>{setup}
      <span class='right'>Signed in as {h(u['username'])} ({h(u['role'])}) <a href='/logout'>Logout</a></span>
    </nav>
    """


def flash(msg: str | None = None) -> str:
    return f"<div class='flash'>{h(msg)}</div>" if msg else ""


def tor_global_status_widget(request: Request) -> str:
    if not current_user(request):
        return ""
    return """<span id='global-tor-status' class='badge warn' title='Tor provider status'>Tor: checking…</span>
      <span id='global-tor-progress-wrap' title='Tor bootstrap progress' style='display:inline-block;width:84px;height:8px;border:1px solid #475569;border-radius:999px;background:#020617;vertical-align:middle;overflow:hidden;margin-left:4px'>
        <span id='global-tor-progress' style='display:block;width:0%;height:100%;background:#0284c7'></span>
      </span>"""


def tor_global_status_script(request: Request) -> str:
    if not current_user(request):
        return ""
    return """<script>
(function(){
  const badge = document.getElementById('global-tor-status');
  const bar = document.getElementById('global-tor-progress');
  const wrap = document.getElementById('global-tor-progress-wrap');
  if (!badge || !bar) return;
  function esc(v){ return String(v || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function clsFor(state){ if (state === 'ready' || state === 'socks_open') return 'badge good'; if (state === 'bootstrapping' || state === 'starting') return 'badge warn'; return 'badge bad'; }
  async function refreshTorStatus(){
    try {
      const r = await fetch('/tor/status', {cache:'no-store'});
      if (!r.ok) return;
      const j = await r.json();
      badge.className = clsFor(j.state);
      badge.textContent = j.label || 'Tor: unknown';
      badge.title = j.message || 'Tor status';
      const pct = (j.percent === null || j.percent === undefined) ? (j.ok ? 100 : 0) : Math.max(0, Math.min(100, Number(j.percent)||0));
      bar.style.width = pct + '%';
      if (wrap) wrap.title = (j.message || '') + (j.percent !== null && j.percent !== undefined ? ' | bootstrap ' + pct + '%' : '');
    } catch(e) {
      badge.className = 'badge bad';
      badge.textContent = 'Tor: status unavailable';
      badge.title = String(e);
      bar.style.width = '0%';
    }
  }
  refreshTorStatus();
  setInterval(refreshTorStatus, 2500);
})();
</script>"""


def layout(request: Request, title: str, body: str) -> HTMLResponse:
    edition = get_setting("edition", "lockdown")
    safe = get_setting("hard_default_safe_mode", "1")
    css = """
    :root{--bg:#0f172a;--panel:#111827;--panel2:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--line:#334155;--accent:#38bdf8;--danger:#ef4444;--warn:#f59e0b;--good:#22c55e}
    *{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#020617,#0f172a 45%,#111827);color:var(--text);font-family:Segoe UI,Roboto,Arial,sans-serif}a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}
    nav{position:sticky;top:0;z-index:10;background:#020617cc;backdrop-filter:blur(8px);border-bottom:1px solid var(--line);padding:12px 18px}nav a{margin-left:14px}.right{float:right}.wrap{max-width:1380px;margin:0 auto;padding:22px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}.card{background:#111827e6;border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0;box-shadow:0 12px 30px #0005}.card h2,.card h3{margin-top:0}.danger{border-color:#7f1d1d!important;background:#2a1015!important}.safe{border-color:#14532d!important}.warn{border-color:#78350f!important}.muted{color:var(--muted)}.small{font-size:.85rem}.mono,code,pre{font-family:Consolas,Menlo,monospace}pre{white-space:pre-wrap;background:#020617;border:1px solid var(--line);border-radius:10px;padding:12px;max-height:520px;overflow:auto}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}th{color:#bae6fd}input,select,textarea{width:100%;padding:10px;border-radius:9px;border:1px solid #475569;background:#020617;color:var(--text);margin:4px 0 10px}textarea{min-height:90px}label{display:block;font-weight:600}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}.row>*{flex:1;min-width:180px}button,.button{display:inline-block;border:0;border-radius:9px;padding:10px 14px;background:#0284c7;color:white;font-weight:700;cursor:pointer;margin:3px}.button.secondary,button.secondary{background:#475569}.button.danger,button.danger{background:#dc2626}.button.warn,button.warn{background:#d97706}.button.good,button.good{background:#16a34a}.badge{display:inline-block;border:1px solid #475569;border-radius:999px;padding:3px 8px;margin:2px;background:#020617;color:#dbeafe;font-size:.8rem}.badge.good{border-color:#15803d;color:#86efac}.badge.bad{border-color:#991b1b;color:#fca5a5}.badge.warn{border-color:#92400e;color:#fcd34d}.badge.info{border-color:#0369a1;color:#7dd3fc}.viewer{min-height:300px;border:2px dashed #475569;border-radius:12px;background:#020617;display:flex;align-items:center;justify-content:center;text-align:center;overflow:auto}.viewer img{max-width:100%;max-height:75vh}.table-scroll{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:10px}.table-scroll table{min-width:980px}.urlcell{min-width:420px;max-width:900px;white-space:normal;word-break:break-all}.hashcell{min-width:320px;word-break:break-all}.media-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}.thumb{background:#020617;border:1px solid var(--line);border-radius:10px;min-height:180px;display:flex;align-items:center;justify-content:center;overflow:hidden}.thumb img{max-width:100%;max-height:240px}.saved-frame,.render-frame{width:100%;height:72vh;border:1px solid var(--line);border-radius:12px;background:#020617}.flash{padding:12px;border:1px solid #0369a1;background:#082f49;border-radius:12px;margin:10px 0}.noprint{}@media print{nav,.noprint,button,.button{display:none!important}body{background:white;color:black}.card{background:white;color:black;border:1px solid #aaa;box-shadow:none}a{color:black}}
    """
    css += """
    .rv-thumb-small{width:74px;height:56px;border:1px solid #334155;border-radius:8px;background:#020617;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative;color:#cbd5e1;font-size:10px}
    .rv-thumb-small img,.rv-thumb-small video{width:100%;height:100%;object-fit:cover;display:block;background:#000}
    .rv-thumb-small .thumb-label{position:absolute;left:2px;bottom:2px;background:rgba(0,0,0,.65);color:#fff;border-radius:4px;padding:1px 3px;font-size:9px}
    .thumb-doc,.thumb-audio{display:flex;flex-direction:column;gap:2px;align-items:center;justify-content:center;text-align:center;font-size:12px;color:#cbd5e1}.thumb-doc span{font-weight:800}.thumb-audio span{font-size:22px}.media-tools{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.media-tools input{max-width:260px}.starbtn{font-size:18px;padding:3px 8px}.tagline{display:flex;gap:5px;align-items:center;flex-wrap:wrap}.compact-input{max-width:220px}
    """
    banner = f"<div class='card {'danger' if edition=='lockdown' else 'warn' if edition=='supervised' else ''}'><b>Custody:</b> {badge(custody_label(),'info')} <b>Edition:</b> {badge(edition,'good' if edition=='lockdown' else 'warn')} <b>Hard default safe mode:</b> {badge(safe,'good' if truthy(safe) else 'warn')} <b>Version:</b> {h(APP_VERSION)} <b>Tor:</b> {tor_global_status_widget(request)}</div>"
    html = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{h(title)} - {APP_NAME}</title><style>{css}</style></head><body>{nav(request)}<main class='wrap'>{banner}<h1>{h(title)}</h1>{body}</main>{webauthn_global_guard_script()}{tor_global_status_script(request)}</body></html>"""
    return HTMLResponse(html)


def case_for(case_id: int | None) -> dict[str, Any] | None:
    if not case_id:
        return None
    return rowdict(fetchone("SELECT * FROM cases WHERE id=?", (case_id,)))


def evidence_for(eid: int) -> dict[str, Any] | None:
    return rowdict(fetchone("SELECT * FROM evidence WHERE id=?", (eid,)))


def meta_of(row: dict[str, Any]) -> dict[str, Any]:
    return jloads(row.get("meta_json"), {})


def edition() -> str:
    val = get_setting("edition", "lockdown")
    return val if val in EDITIONS else "lockdown"


def lockdown() -> bool:
    return edition() == "lockdown"


def case_safe(case: dict[str, Any] | None) -> bool:
    if not case:
        return setting_bool("hard_default_safe_mode", "1")
    return bool(case.get("compliance_safe")) or case.get("mode") == "lockdown" or setting_bool("hard_default_safe_mode", "1") and edition() == "lockdown"


def effective_media_policy(case: dict[str, Any] | None, submitted: str | None = None) -> str:
    policy = submitted or (case.get("default_media_policy") if case else None) or get_setting("default_media_policy", "block_images_video")
    if policy not in MEDIA_POLICIES:
        policy = "block_images_video"
    if case_safe(case) and policy == "allow_all":
        return "block_images_video"
    return policy


def effective_capture_mode(case: dict[str, Any] | None, submitted: str | None = None) -> str:
    mode = submitted or get_setting("default_capture_mode", "metadata_only")
    if mode not in CAPTURE_MODES:
        mode = "metadata_only"
    if case_safe(case) and mode == "full_forensic":
        return "metadata_only" if lockdown() else "safe_summary"
    return mode


def domain_denied(url: str) -> bool:
    return domain_matches(host_of(url), split_lines_setting("capture_denylist_domains"))


def domain_safe_allowed(url: str) -> bool:
    return domain_matches(host_of(url), split_lines_setting("safe_allowlist_domains"))


def selected_user_agent(profile: str | None = None, custom_user_agent: str | None = None) -> str:
    profile = (profile or get_setting("default_user_agent_profile", "chrome_windows") or "chrome_windows").strip()
    if profile == "custom":
        custom = (custom_user_agent if custom_user_agent is not None else get_setting("custom_user_agent", "")).strip()
        if custom:
            return custom[:500]
        profile = "chrome_windows"
    if profile not in USER_AGENT_PROFILES:
        profile = "chrome_windows"
    ua = USER_AGENT_PROFILES[profile][1]
    return ua or USER_AGENT_PROFILES["chrome_windows"][1]


def user_agent_label(profile: str | None) -> str:
    profile = (profile or get_setting("default_user_agent_profile", "chrome_windows") or "chrome_windows").strip()
    return USER_AGENT_PROFILES.get(profile, USER_AGENT_PROFILES["chrome_windows"])[0]


def user_agent_info(profile: str | None = None, custom_user_agent: str | None = None) -> dict[str, Any]:
    profile = (profile or get_setting("default_user_agent_profile", "chrome_windows") or "chrome_windows").strip()
    ua = selected_user_agent(profile, custom_user_agent)
    return {
        "profile": profile if profile in USER_AGENT_PROFILES else "chrome_windows",
        "label": user_agent_label(profile),
        "user_agent": ua,
        "user_agent_sha256": sha256_text(ua),
    }


def ua_select_html(name: str, selected: str | None = None) -> str:
    selected = selected or get_setting("default_user_agent_profile", "chrome_windows")
    return "".join(
        f"<option value='{h(key)}' {'selected' if key == selected else ''}>{h(label)}</option>"
        for key, (label, _ua) in USER_AGENT_PROFILES.items()
    )


def browser_select_html(name: str = "browser_choice", selected: str | None = None) -> str:
    selected = selected or get_setting("live_browser_default", "chromium")
    choices = [
        ("tor_managed_chromium", "One-click managed Tor Session / Chromium"),
        ("tor_managed_firefox", "One-click managed Tor Session / Firefox"),
        ("chromium", "Direct app-managed Chromium"),
        ("firefox", "Direct app-managed Firefox"),
        ("chrome", "Direct installed Chrome"),
        ("msedge", "Direct installed Edge"),
        ("torbrowser", "Installed Tor Browser (experimental)"),
    ]
    return "".join(f"<option value='{h(v)}' {'selected' if selected == v else ''}>{h(label)}</option>" for v, label in choices)


def detect_tor_browser_executable() -> Path | None:
    configured = (get_setting("tor_browser_path", "") or "").strip().strip('"')
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    home = Path.home()
    if os.name == "nt":
        env_candidates = [os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"), os.environ.get("LOCALAPPDATA")]
        for base in [BASE_DIR, home / "Desktop", home / "Downloads", *[Path(x) for x in env_candidates if x]]:
            candidates.append(Path(base) / "Tor Browser" / "Browser" / "firefox.exe")
            candidates.append(Path(base) / "TorBrowser" / "Browser" / "firefox.exe")
    elif sys.platform == "darwin":
        candidates.extend([
            Path("/Applications/Tor Browser.app/Contents/MacOS/firefox"),
            home / "Applications" / "Tor Browser.app" / "Contents" / "MacOS" / "firefox",
        ])
    else:
        candidates.extend([
            BASE_DIR / "tor-browser" / "Browser" / "firefox",
            BASE_DIR / "Tor Browser" / "Browser" / "firefox",
            home / "tor-browser" / "Browser" / "firefox",
            home / "Desktop" / "tor-browser" / "Browser" / "firefox",
            home / "Downloads" / "tor-browser" / "Browser" / "firefox",
        ])
    for c in candidates:
        try:
            if c.exists() and c.is_file():
                return c
        except Exception:
            pass
    return None



def detect_tor_executable() -> Path | None:
    configured = (get_setting("tor_executable_path", "") or "").strip().strip('"')
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    tb = detect_tor_browser_executable()
    if tb:
        browser_dir = tb.parent
        if os.name == "nt":
            candidates.extend([
                browser_dir / "TorBrowser" / "Tor" / "tor.exe",
                browser_dir.parent / "TorBrowser" / "Tor" / "tor.exe",
                browser_dir / "Tor" / "tor.exe",
            ])
        else:
            candidates.extend([
                browser_dir / "TorBrowser" / "Tor" / "tor",
                browser_dir.parent / "TorBrowser" / "Tor" / "tor",
                browser_dir / "Tor" / "tor",
            ])
    home = Path.home()
    if os.name == "nt":
        for base in [BASE_DIR, home / "Desktop", home / "Downloads", Path(os.environ.get("LOCALAPPDATA", home))]:
            candidates.extend([
                Path(base) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
                Path(base) / "TorBrowser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            ])
    else:
        candidates.extend([Path("/usr/bin/tor"), Path("/usr/local/bin/tor"), BASE_DIR / "tor" / "tor"])
    for c in candidates:
        try:
            if c.exists() and c.is_file():
                return c
        except Exception:
            pass
    return None


def socket_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def choose_open_tor_socks_port() -> int | None:
    host = get_setting("tor_host", "127.0.0.1")
    candidates: list[int] = []
    for raw in [get_setting("tor_socks_port", "9050"), "9150", "9050"]:
        try:
            port = int(str(raw).strip())
            if port not in candidates:
                candidates.append(port)
        except Exception:
            pass
    for port in candidates:
        if socket_open(host, port):
            set_setting("tor_socks_port", str(port))
            return port
    return None



def tor_runtime_dir() -> Path:
    d = DATA_DIR / "tor_runtime"
    d.mkdir(parents=True, exist_ok=True)
    return d


def tor_log_path() -> Path:
    return tor_runtime_dir() / "tor_prewarm.log"


def tor_pid_path() -> Path:
    return tor_runtime_dir() / "tor_provider.pid"


def tor_append_runtime_log(message: str) -> None:
    try:
        with open(tor_log_path(), "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"[{utcnow()}] {message}\n")
    except Exception:
        pass


def tor_log_tail(max_chars: int = 5000) -> str:
    try:
        return tor_log_path().read_text(encoding="utf-8", errors="ignore")[-max(200, int(max_chars)):]
    except Exception:
        return ""


def tor_managed_pid() -> int | None:
    try:
        raw = tor_pid_path().read_text(encoding="utf-8", errors="ignore").strip()
        if raw:
            return int(raw)
    except Exception:
        pass
    return None


def process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        if os.name == "nt":
            r = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}"], capture_output=True, text=True, timeout=3)
            return str(pid) in (r.stdout or "")
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def stop_managed_tor(reason: str = "manual") -> dict[str, Any]:
    """Stop the Tor process started by BlindSite, if we know its PID.

    This intentionally avoids killing arbitrary Tor Browser processes that were
    not launched by BlindSite. If SOCKS remains open after this, it is likely an
    external Tor/Tor Browser instance.
    """
    pid = tor_managed_pid()
    host = get_setting("tor_host", "127.0.0.1")
    port = safe_int(get_setting("tor_socks_port", "9050"), 9050)
    result: dict[str, Any] = {"ok": False, "reason": reason, "pid": pid, "message": "no managed Tor PID recorded", "socks_port": port}
    if pid and process_alive(pid):
        try:
            tor_append_runtime_log(f"Stopping managed Tor PID {pid} ({reason})")
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True, timeout=8)
            else:
                os.kill(pid, signal.SIGTERM)
            for _ in range(40):
                if not process_alive(pid):
                    break
                time.sleep(0.1)
            result.update({"ok": True, "message": f"stopped managed Tor PID {pid}", "still_alive": process_alive(pid)})
        except Exception as exc:
            result.update({"ok": False, "message": f"failed to stop managed Tor PID {pid}: {exc}"})
    elif pid:
        result.update({"ok": True, "message": f"managed Tor PID {pid} was already stopped or stale"})
    with contextlib.suppress(Exception):
        tor_pid_path().unlink()
    # Clean common stale lock file only for BlindSite's own DataDirectory.
    with contextlib.suppress(Exception):
        lock = tor_runtime_dir() / "lock"
        if lock.exists() and not socket_open(host, port):
            lock.unlink()
    result["socks_open_after"] = socket_open(host, port)
    result["log_tail"] = tor_log_tail(2500)
    tor_append_runtime_log(f"stop result: {json.dumps({k:v for k,v in result.items() if k != 'log_tail'}, default=str)}")
    return result


def tor_diagnostics() -> dict[str, Any]:
    host = get_setting("tor_host", "127.0.0.1")
    socks_port = safe_int(get_setting("tor_socks_port", "9050"), 9050)
    control_port = safe_int(get_setting("tor_control_port", "9051"), 9051)
    pid = tor_managed_pid()
    boot = tor_bootstrap_status() if socket_open(host, control_port, timeout=0.5) else {"ok": False, "percent": None, "message": "Tor control unavailable"}
    return {
        "host": host,
        "socks_port": socks_port,
        "control_port": control_port,
        "socks_open": socket_open(host, socks_port, timeout=0.5),
        "control_open": socket_open(host, control_port, timeout=0.5),
        "managed_pid": pid,
        "managed_pid_alive": process_alive(pid),
        "bootstrap": boot,
        "log_path": str(tor_log_path()),
        "log_tail": tor_log_tail(3500),
        "prewarm": dict(TOR_PREWARM_STATUS) if 'TOR_PREWARM_STATUS' in globals() else {},
    }

def start_bundled_tor_if_possible() -> tuple[bool, str]:
    tor_exe = detect_tor_executable()
    if not tor_exe:
        tor_append_runtime_log("No bundled/standalone tor executable found")
        return False, "No bundled/standalone tor executable found"
    host = get_setting("tor_host", "127.0.0.1")
    preferred_ports: list[int] = []
    for raw in [get_setting("tor_socks_port", "9050"), "9150", "9050"]:
        try:
            port = int(str(raw).strip())
            if port not in preferred_ports:
                preferred_ports.append(port)
        except Exception:
            pass
    try:
        control_port = int(get_setting("tor_control_port", "9051") or "9051")
    except Exception:
        control_port = 9051
    log_path = tor_log_path()
    pid_path = tor_pid_path()
    last_error = ""
    for port in preferred_ports:
        try:
            if socket_open(host, port):
                set_setting("tor_socks_port", str(port))
                boot = tor_bootstrap_status() if socket_open(host, control_port, timeout=0.75) else {"ok": True, "percent": None, "message": "SOCKS open; control unavailable"}
                pct = boot.get("percent") if boot.get("percent") is not None else "unknown"
                tor_append_runtime_log(f"Tor already listening on {host}:{port}; bootstrap {pct}")
                return True, f"Tor already listening on {host}:{port}; bootstrap {pct}"

            cmd = [
                str(tor_exe),
                "--SocksPort", f"{host}:{port}",
                "--ControlPort", f"{host}:{control_port}",
                "--CookieAuthentication", "0",
                "--DataDirectory", str(tor_runtime_dir()),
                "--Log", f"notice file {log_path}",
            ]
            with open(log_path, "a", encoding="utf-8", errors="ignore") as logf:
                logf.write(f"\n[{utcnow()}] Starting Tor: {' '.join(cmd)}\n")
                proc = subprocess.Popen(cmd, stdout=logf, stderr=logf, cwd=str(tor_exe.parent), creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW") else 0))
            with contextlib.suppress(Exception):
                pid_path.write_text(str(proc.pid), encoding="utf-8")
            opened = False
            for _ in range(140):
                time.sleep(0.25)
                if socket_open(host, port):
                    opened = True
                    break
                if proc.poll() is not None:
                    break
            if opened:
                set_setting("tor_socks_port", str(port))
                boot = tor_bootstrap_status() if socket_open(host, control_port, timeout=0.75) else {"ok": True, "percent": None, "message": "SOCKS open; control unavailable"}
                log_event("system", "TOR_PROVIDER_STARTED", details={"tor_exe": str(tor_exe), "pid": proc.pid, "socks_port": port, "control_port": control_port, "bootstrap": boot, "log_path": str(log_path)})
                pct = boot.get("percent") if boot.get("percent") is not None else "unknown"
                tor_append_runtime_log(f"Started Tor provider PID {proc.pid} on {host}:{port}; bootstrap {pct}")
                return True, f"Started Tor provider PID {proc.pid} on {host}:{port}; bootstrap {pct}; log {log_path}"
            recent_log = tor_log_tail(1200)
            last_error = f"Tor executable launched but SOCKS did not open on {host}:{port}. Recent Tor log: {recent_log or 'no log output'}"
            tor_append_runtime_log(last_error)
        except Exception as exc:
            last_error = str(exc)
            tor_append_runtime_log(f"Tor start attempt failed on port {port}: {last_error}")
    return False, last_error or "Tor executable started but no SOCKS port opened"

def ensure_tor_proxy_ready() -> tuple[bool, str]:
    port = choose_open_tor_socks_port()
    host = get_setting("tor_host", "127.0.0.1")
    ctrl = safe_int(get_setting("tor_control_port", "9051"), 9051)
    if port:
        if socket_open(host, ctrl, timeout=0.75):
            boot = tor_bootstrap_status()
            pct = boot.get("percent")
            if pct is not None and int(pct) < 100:
                return False, f"Tor SOCKS is open on {host}:{port}, but bootstrap is only {pct}%. Wait for prewarm to finish or restart Tor."
        return True, f"Tor SOCKS is open on {host}:{port}"
    if setting_bool("tor_auto_start_from_browser_bundle", "1"):
        ok, msg = start_bundled_tor_if_possible()
        if not ok:
            return ok, msg
        port = choose_open_tor_socks_port()
        if port and socket_open(host, ctrl, timeout=0.75):
            boot = wait_for_tor_bootstrap(90.0)
            pct = boot.get("percent")
            if pct is not None and int(pct) < 100:
                return False, f"Tor started but did not finish bootstrapping within 90s; progress {pct}%. Check Tor diagnostics or restart Tor."
        return ok, msg
    return False, "Tor SOCKS is not open and auto-start is disabled"

def tor_control_command(command: str, *, timeout: float = 6.0) -> dict[str, Any]:
    host = get_setting("tor_host", "127.0.0.1")
    port = int(get_setting("tor_control_port", "9051") or "9051")
    pw = get_setting("tor_control_password", "")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            f = s.makefile("rw", newline="\r\n")
            if pw:
                f.write(f'AUTHENTICATE "{pw}"\r\n')
            else:
                f.write('AUTHENTICATE\r\n')
            f.flush()
            auth = f.readline().strip()
            if not auth.startswith("250"):
                return {"ok": False, "auth": auth, "error": "Tor control authentication failed"}
            f.write(command.strip() + "\r\n")
            f.flush()
            lines: list[str] = []
            while True:
                line = f.readline().strip()
                if not line:
                    break
                lines.append(line)
                if line.startswith("250 ") or line == "250 OK" or line.startswith("552") or line.startswith("5"):
                    break
            f.write('QUIT\r\n')
            f.flush()
            ok = bool(lines and (lines[-1].startswith("250") or lines[0].startswith("250")))
            return {"ok": ok, "auth": auth, "command": command, "lines": lines, "response": "\n".join(lines)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def tor_bootstrap_status() -> dict[str, Any]:
    res = tor_control_command("GETINFO status/bootstrap-phase", timeout=3.0)
    if not res.get("ok"):
        return {"ok": False, "percent": None, "message": res.get("error") or res.get("response") or "control unavailable", "raw": res}
    raw = res.get("response") or ""
    m = re.search(r"PROGRESS=(\d+)", raw)
    pct = int(m.group(1)) if m else None
    return {"ok": True, "percent": pct, "message": raw, "raw": res}


def wait_for_tor_bootstrap(timeout_s: float = 45.0) -> dict[str, Any]:
    deadline = time.time() + max(1.0, timeout_s)
    last: dict[str, Any] = {"ok": False, "percent": None, "message": "not checked"}
    while time.time() < deadline:
        last = tor_bootstrap_status()
        if last.get("ok") and (last.get("percent") is None or int(last.get("percent") or 0) >= 100):
            return last
        time.sleep(1.0)
    return last


def tor_exit_ip(timeout_s: float = 12.0) -> dict[str, Any]:
    port = choose_open_tor_socks_port()
    if not port:
        return {"ok": False, "error": "Tor SOCKS is not open"}
    host = get_setting("tor_host", "127.0.0.1")
    proxy = f"socks5h://{host}:{port}"
    try:
        r = requests.get("https://check.torproject.org/api/ip", proxies={"http": proxy, "https": proxy}, timeout=timeout_s)
        r.raise_for_status()
        data = r.json()
        return {"ok": True, "socks_port": port, "ip": data.get("IP"), "is_tor": data.get("IsTor"), "raw": data}
    except Exception as exc:
        return {"ok": False, "socks_port": port, "error": str(exc)}

TOR_PREWARM_LOCK = threading.Lock()
TOR_PREWARM_STATUS: dict[str, Any] = {"running": False, "ok": False, "message": "not started", "updated_at": "", "reason": "", "socks_port": None, "control_port": None, "exit_ip": None}

def tor_prewarm_background(reason: str = "manual") -> dict[str, Any]:
    """Start/verify Tor in a background thread with live bootstrap diagnostics."""
    with TOR_PREWARM_LOCK:
        if TOR_PREWARM_STATUS.get("running"):
            return dict(TOR_PREWARM_STATUS)
        TOR_PREWARM_STATUS.update({"running": True, "ok": False, "message": f"starting ({reason})", "updated_at": utcnow(), "reason": reason, "started_at": utcnow(), "log_tail": tor_log_tail(2500)})
    tor_append_runtime_log(f"Tor prewarm requested: {reason}")

    def update_status(**kwargs: Any) -> None:
        with TOR_PREWARM_LOCK:
            TOR_PREWARM_STATUS.update(kwargs)
            TOR_PREWARM_STATUS["updated_at"] = utcnow()

    def worker() -> None:
        try:
            ok, msg = ensure_tor_proxy_ready()
            port = choose_open_tor_socks_port()
            host = get_setting("tor_host", "127.0.0.1")
            ctrl = safe_int(get_setting("tor_control_port", "9051"), 9051)
            update_status(ok=False, message=msg, socks_port=port, control_port=ctrl, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
            if not ok and not port:
                update_status(running=False, ok=False, message=msg, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
                log_event("system", "TOR_BACKGROUND_PREWARM_FAILED", details={"message": msg, "reason": reason, "diagnostics": tor_diagnostics()})
                return

            # If control is available, keep the background job alive until Tor reaches 100% or times out.
            timeout_s = 180.0
            deadline = time.time() + timeout_s
            last_boot: dict[str, Any] = {"ok": False, "percent": None, "message": "not checked"}
            while time.time() < deadline:
                if not socket_open(host, port or safe_int(get_setting("tor_socks_port", "9050"), 9050), timeout=0.5):
                    update_status(running=False, ok=False, message="Tor SOCKS closed during prewarm", socks_port=port, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
                    return
                if socket_open(host, ctrl, timeout=0.5):
                    last_boot = tor_bootstrap_status()
                    pct = last_boot.get("percent")
                    msg2 = f"Tor SOCKS open on {host}:{port}; bootstrap {pct if pct is not None else 'unknown'}%"
                    update_status(running=True, ok=bool(pct and int(pct) >= 100), message=msg2, socks_port=port, control_port=ctrl, bootstrap=last_boot, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
                    if pct is not None and int(pct) >= 100:
                        update_status(running=False, ok=True, message=f"Tor ready on {host}:{port}; bootstrap 100%", socks_port=port, control_port=ctrl, bootstrap=last_boot, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
                        log_event("system", "TOR_BACKGROUND_PREWARM_COMPLETED", details={"ok": True, "message": "Tor bootstrap 100%", "reason": reason, "socks_port": port, "bootstrap": last_boot})
                        return
                else:
                    update_status(running=False, ok=True, message=f"Tor SOCKS open on {host}:{port}; control unavailable, cannot read bootstrap", socks_port=port, control_port=ctrl, bootstrap={"ok": False, "message": "control unavailable"}, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
                    log_event("system", "TOR_BACKGROUND_PREWARM_COMPLETED", details={"ok": True, "message": "SOCKS open; control unavailable", "reason": reason, "socks_port": port})
                    return
                time.sleep(1.0)
            pct = last_boot.get("percent")
            message = f"Tor SOCKS open on {host}:{port}, but bootstrap did not reach 100% within {int(timeout_s)}s; last progress {pct if pct is not None else 'unknown'}%"
            update_status(running=False, ok=False, message=message, socks_port=port, control_port=ctrl, bootstrap=last_boot, diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
            log_event("system", "TOR_BACKGROUND_PREWARM_TIMEOUT", details={"message": message, "reason": reason, "socks_port": port, "bootstrap": last_boot})
        except Exception as exc:
            update_status(running=False, ok=False, message=str(exc)[:500], diagnostics=tor_diagnostics(), log_tail=tor_log_tail(3500))
            log_event("system", "TOR_BACKGROUND_PREWARM_FAILED", details={"error": str(exc)[:500], "reason": reason, "diagnostics": tor_diagnostics()})

    threading.Thread(target=worker, name="BlindSiteTorPrewarm", daemon=True).start()
    return dict(TOR_PREWARM_STATUS)


def tor_prewarm_status() -> dict[str, Any]:
    with TOR_PREWARM_LOCK:
        status = dict(TOR_PREWARM_STATUS)
    host = get_setting("tor_host", "127.0.0.1")
    ctrl = safe_int(get_setting("tor_control_port", "9051"), 9051)
    port = choose_open_tor_socks_port()
    if port:
        boot = tor_bootstrap_status() if socket_open(host, ctrl, timeout=0.5) else {"ok": False, "percent": None, "message": "Tor control unavailable"}
        pct = boot.get("percent")
        if pct is not None and int(pct) < 100:
            # Keep reporting bootstrapping instead of pretending the provider is fully ready.
            if not status.get("running"):
                status.update({"ok": False, "running": False})
            status.update({"message": f"Tor SOCKS is open on {host}:{port}; bootstrap {pct}%", "socks_port": port, "bootstrap": boot})
        else:
            status.update({"ok": True, "running": False, "message": f"Tor SOCKS is open on {host}:{port}" + ("; bootstrap 100%" if pct is not None else "; control unavailable"), "socks_port": port, "bootstrap": boot})
    else:
        status.setdefault("message", "Tor SOCKS is closed")
    status["diagnostics"] = tor_diagnostics()
    status["log_tail"] = tor_log_tail(3500)
    return status


def tor_browser_status_html() -> str:
    path = detect_tor_browser_executable()
    tor_exe = detect_tor_executable()
    configured = get_setting("tor_browser_path", "")
    browser_part = f"{badge('Tor Browser found','good')} <span class='mono small'>{h(path)}</span>" if path else f"{badge('Tor Browser path not found','warn')} <span class='small muted'>Configured: {h(configured or 'auto-detect')}</span>"
    tor_part = f"{badge('tor.exe found','good')} <span class='mono small'>{h(tor_exe)}</span>" if tor_exe else badge('tor.exe not found','warn')
    port = choose_open_tor_socks_port()
    port_part = badge(f'Tor SOCKS open:{port}','good') if port else badge('Tor SOCKS closed','warn')
    return browser_part + "<br>" + tor_part + " " + port_part


def classify_resource(url: str, *, mime_type: str | None = None, tag: str | None = None, browser_type: str | None = None) -> str:
    if browser_type:
        rt = browser_type.lower()
        if rt == "media":
            return "media"
        if rt in {"document", "script", "stylesheet", "image", "font", "xhr", "fetch", "websocket", "eventsource", "manifest", "other"}:
            return rt
    tag = (tag or "").lower()
    if tag in {"img", "picture"}:
        return "image"
    if tag in {"video", "source"}:
        return "video"
    if tag == "audio":
        return "audio"
    mt = (mime_type or "").split(";", 1)[0].lower().strip()
    if mt.startswith("image/"):
        return "image"
    if mt.startswith("video/"):
        return "video"
    if mt.startswith("audio/"):
        return "audio"
    if mt in {"application/dash+xml", "application/vnd.apple.mpegurl", "application/x-mpegurl", "application/mp4"}:
        return "video"
    ext = Path(urlparse(url).path.lower()).suffix
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    if ext in AUDIO_EXTS:
        return "audio"
    if ext in FONT_EXTS:
        return "font"
    if ext in CSS_EXTS or mt == "text/css":
        return "stylesheet"
    if mt in {"text/html", "application/xhtml+xml"}:
        return "document"
    return "other"


def policy_blocks_resource(resource_type: str, policy: str) -> bool:
    if policy == "allow_all":
        return False
    if policy == "block_images":
        return resource_type == "image"
    if policy == "block_images_video":
        return resource_type in {"image", "video", "audio", "media"}
    if policy == "block_all_media":
        return resource_type in {"image", "video", "audio", "media", "font"}
    return resource_type in {"image", "video", "audio", "media"}


def live_policy_blocks(browser_resource_type: str, policy: str, url: str = "") -> bool:
    # Critical hang fix: never block document/script/stylesheet/xhr/fetch just because media blocking is on.
    # Exception: some sites load SVG/image files through document/fetch/other request types.
    # In that case the URL extension is still media and should be blocked when image blocking is enabled.
    rt = (browser_resource_type or "").lower()
    if rt == "media":
        logical = "media"
    elif rt in {"image", "font"}:
        logical = rt
    else:
        ext = Path(urlparse(url or "").path.lower()).suffix
        if ext in IMAGE_EXTS:
            logical = "image"
        elif ext in VIDEO_EXTS:
            logical = "video"
        elif ext in AUDIO_EXTS:
            logical = "audio"
        elif ext in FONT_EXTS:
            logical = "font"
        else:
            return False
    return policy_blocks_resource(logical, policy)


CAPTCHA_CHALLENGE_HOST_PATTERNS = [
    "hcaptcha.com", "recaptcha.net", "arkoselabs.com", "funcaptcha.com",
    "geetest.com", "captcha-delivery.com", "challenges.cloudflare.com",
    "captcha", "anti-captcha", "anti_bot", "antibot",
]
CAPTCHA_CHALLENGE_PATH_PATTERNS = [
    "captcha", "recaptcha", "hcaptcha", "funcaptcha", "arkose",
    "challenge", "turnstile", "verification", "verify-human", "security-check",
    "bot-detect", "botdetect", "anti-bot", "antibot", "puzzle",
]
CAPTCHA_CHALLENGE_INLINE_CONTEXT_PATTERNS = [
    # Used only for inline data:image CAPTCHA exceptions. These are context
    # words/classes/field names around the image, not a reason to allow all
    # ordinary images. This keeps the exception narrow enough for civilian/
    # lockdown use while still allowing darknet CAPTCHA images that are embedded
    # as data:image/png;base64 or data:image/webp;base64.
    "captcha", "recaptcha", "hcaptcha", "funcaptcha", "arkose",
    "challenge", "verification", "verify-human", "security-check",
    "bot-detect", "botdetect", "anti-bot", "antibot", "puzzle",
    "robot", "not a robot", "are you not a robot", "human check",
    "human verification", "captchabtn", "ring_id", "captcha answer",
    "captcha expired", "misclick catcher",
]
CAPTCHA_INLINE_ORDINARY_IMAGE_PATTERNS = [
    # Common labels for ordinary site imagery. These prevent broad page-level
    # CAPTCHA wording from allowing unrelated inline logos/avatars.
    "logo", "avatar", "banner", "background", "favicon", "icon",
    "sprite", "decorative", "thumbnail", "profile", "advertisement", " ad ",
]
CAPTCHA_INLINE_STRONG_CONTEXT_PATTERNS = [
    # Strong signals that can appear directly on/near a CAPTCHA image.
    "captcha", "recaptcha", "hcaptcha", "funcaptcha", "arkose",
    "captchabtn", "ring_id", "captcha answer", "captcha expired",
    "misclick catcher", "not a robot", "are you not a robot",
    "human verification", "verify-human", "botdetect", "anti-bot", "antibot",
]


def captcha_challenge_context_candidate(text: str) -> bool:
    hay = (text or "").strip().lower()
    if not hay:
        return False
    return any(pat in hay for pat in CAPTCHA_CHALLENGE_INLINE_CONTEXT_PATTERNS)


def captcha_challenge_inline_data_candidate(src: str, context_text: str = "") -> bool:
    raw = (src or "").strip().lower()
    if not raw.startswith("data:image/"):
        return False
    hay = " " + (context_text or "").strip().lower() + " "
    if not hay.strip():
        return False
    strong_hit = any(pat in hay for pat in CAPTCHA_INLINE_STRONG_CONTEXT_PATTERNS)
    ordinary_hit = any(pat in hay for pat in CAPTCHA_INLINE_ORDINARY_IMAGE_PATTERNS)
    direct_strong_hit = any(pat in hay for pat in [
        "captchabtn", "ring_id", "captcha answer", "alt captcha", "id captcha",
        "class captcha", "human verification", "verify-human", "misclick catcher",
    ])
    # If the context also looks like ordinary site media, broad page-level
    # challenge wording must not turn it into a CAPTCHA exception. Require a
    # direct/structural CAPTCHA signal such as captchabtn, ring_id, or alt captcha.
    if ordinary_hit and not direct_strong_hit:
        return False
    return strong_hit or captcha_challenge_context_candidate(hay)


def captcha_challenge_media_candidate(url: str, browser_resource_type: str = "") -> bool:
    """Return True only for media requests that look like CAPTCHA/challenge assets.

    This is intentionally narrow. It does not turn image loading back on. It
    allows only likely CAPTCHA/challenge images so investigators can complete
    access checks on darknet/high-risk sites while normal images/video/audio
    remain blocked and, when configured, sealed-preserved.
    """
    raw = (url or "").strip()
    if not raw or raw.startswith(("data:", "blob:", "javascript:")):
        return False
    rt = (browser_resource_type or "").lower().strip()
    try:
        p = urlparse(raw)
    except Exception:
        return False
    path = unquote(p.path or "").lower()
    query = unquote(p.query or "").lower()
    host = (p.hostname or "").lower().strip(".")
    ext = Path(path).suffix.lower()
    # Minimal-scope rule: only visual CAPTCHA media is allowed. Documents,
    # scripts, XHR/fetch, stylesheets, and ordinary page media remain governed
    # by the existing policy.
    if rt not in {"image"} and ext not in IMAGE_EXTS:
        return False
    text = " ".join([host, path, query]).lower()
    host_hit = any(pat in host for pat in CAPTCHA_CHALLENGE_HOST_PATTERNS)
    path_hit = any(pat in text for pat in CAPTCHA_CHALLENGE_PATH_PATTERNS)
    # Avoid allowing all generic Google/Gstatic images; require recaptcha/captcha
    # path keywords for those broad hosts.
    if host.endswith(("google.com", "gstatic.com", "googleusercontent.com")):
        return any(pat in text for pat in ["recaptcha", "captcha", "api2/payload"])
    return bool(host_hit or path_hit)


def ext_for_mime(mime_type: str) -> str:
    ext = mimetypes.guess_extension((mime_type or "application/octet-stream").split(";", 1)[0].strip())
    return ext or ".bin"


def kind_for(mime_type: str, filename: str = "") -> str:
    rt = classify_resource(filename, mime_type=mime_type)
    if rt in {"image", "video", "audio", "media"}:
        return rt
    if rt == "stylesheet":
        return "document"
    if rt == "font":
        return "binary"
    if (mime_type or "").startswith("text/") or "json" in (mime_type or "") or "html" in (mime_type or ""):
        return "document"
    return "binary"


SEALED_PRESERVED_STORAGE_MODE = "sealed_preserved_blocked_media"
SEALED_PRESERVED_PAGE_SNAPSHOT_STORAGE_MODE = "sealed_preserved_page_snapshot"


def chat_profile_url(url: str) -> bool:
    """Return True for chat/room style pages that should use faster DOM-stable capture.

    These sites commonly keep background polling/websockets alive forever, so
    capture should not wait on full load/networkidle the way static pages can.
    """
    if not setting_bool("capture_chat_profile_enabled", "1"):
        return False
    text = ((url or "") + " " + host_of(url or "")).lower()
    raw = get_setting("capture_chat_url_keywords", "chat\nchatroom\nrooms")
    keywords = [x.strip().lower() for x in raw.replace(",", "\n").splitlines() if x.strip()]
    return any(k and k in text for k in keywords)


def safe_int(value: Any, default: int, *, min_value: int = 0, max_value: int | None = None) -> int:
    try:
        out = int(str(value).strip())
    except Exception:
        out = default
    if out < min_value:
        out = min_value
    if max_value is not None and out > max_value:
        out = max_value
    return out


def sealed_media_preserve_mode() -> str:
    mode = (get_setting("sealed_media_preserve_mode", "balanced") or "balanced").strip().lower()
    return mode if mode in {"fast", "balanced", "complete"} else "balanced"


def decorative_asset_url(url: str) -> bool:
    """Return True for common low-value decorative assets that should not stall capture.

    The asset can still be logged as a blocked media reference. In fast/balanced
    preservation modes, these should not be allowed to hold a Playwright route open
    for many seconds each.
    """
    path = urlparse(url or "").path.lower()
    name = Path(path).name.lower()
    hay = (path + " " + name).replace("%20", " ")
    terms = [
        "favicon", "logo", "logos", "badge", "rating", "trustpilot", "capterra",
        "g2-rating", "star", "sprite", "icon", "iso-", "soc2", "forrester",
        "contact-us-", "banner-logo", "lufthansa-logo", "youtube-",
    ]
    if any(t in hay for t in terms):
        return True
    ext = Path(path).suffix.lower()
    # SVGs are often logos/icons/badges on marketing pages. They are still
    # preserved in complete mode, but should not be allowed to slow ordinary
    # high-risk/chat captures by default.
    return ext == ".svg" and any(t in hay for t in ["logo", "icon", "badge", "rating", "star", "iso", "soc", "banner"])


def cleaned_preserve_headers(headers: dict[str, Any] | None, *, fallback_user_agent: str = "", referer: str = "") -> dict[str, str]:
    """Sanitize browser request headers before background preservation fetches.

    Some browser/Playwright route logs show values like accept-language: undefined.
    We also remove hop-by-hop / browser-internal headers that can confuse normal
    requests-based fallback downloads.
    """
    out: dict[str, str] = {}
    skip = {"host", "connection", "content-length", "accept-encoding", "range"}
    for k, v in (headers or {}).items():
        lk = str(k).lower().strip()
        if not lk or lk in skip or lk.startswith("sec-"):
            continue
        sv = "" if v is None else str(v)
        if not sv or sv.lower() == "undefined":
            continue
        out[lk] = sv
    out.setdefault("user-agent", fallback_user_agent or selected_user_agent())
    out.setdefault("accept-language", "en-US,en;q=0.9")
    if referer and "referer" not in out:
        out["referer"] = referer
    return out


def preserve_timeout_for(logical: str, url: str, *, background: bool = False) -> int:
    mode = sealed_media_preserve_mode()
    if background:
        default = 18000 if mode != "fast" else 8000
        return max(2000, safe_int(get_setting("sealed_media_preserve_background_timeout_ms", str(default)), default, min_value=1000, max_value=120000))
    if mode == "complete":
        default = 12000
    elif mode == "fast":
        default = 1800 if decorative_asset_url(url) else 2500
    else:
        default = 1200 if decorative_asset_url(url) else 3500
    return max(500, safe_int(get_setting("sealed_media_preserve_fetch_timeout_ms", str(default)), default, min_value=500, max_value=60000))


def sealed_preserved_media_evidence(ev: dict[str, Any] | sqlite3.Row | None) -> bool:
    if not ev:
        return False
    try:
        storage = str(ev["storage_mode"] or "")  # sqlite3.Row compatible
    except Exception:
        storage = str((ev or {}).get("storage_mode") or "")  # type: ignore[union-attr]
    return storage == SEALED_PRESERVED_STORAGE_MODE


def evidence_meta_dict(ev: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any]:
    if not ev:
        return {}
    try:
        raw = ev["meta_json"]  # sqlite3.Row compatible
    except Exception:
        raw = (ev or {}).get("meta_json") if isinstance(ev, dict) else None  # type: ignore[union-attr]
    return jloads(raw, {}) if isinstance(raw, str) else (raw or {})


def hard_sealed_escrow_evidence(ev: dict[str, Any] | sqlite3.Row | None) -> bool:
    if not ev:
        return False
    try:
        encrypted_flag = int(ev["encrypted"] or 0)
    except Exception:
        encrypted_flag = int((ev or {}).get("encrypted") or 0) if isinstance(ev, dict) else 0  # type: ignore[union-attr]
    meta = evidence_meta_dict(ev)
    return (
        encrypted_flag == HARD_SEALED_ENCRYPTED_FLAG
        or bool(meta.get("hard_sealed_civilian_evidence"))
        or bool(meta.get("hard_sealed_organization_media"))
        or bool(meta.get("hard_sealed_escrow_evidence"))
    )


def hard_sealed_civilian_evidence(ev: dict[str, Any] | sqlite3.Row | None) -> bool:
    """True for Civilian Unknown Master Key hard-sealed objects.

    Older civilian hard-sealed rows may only have encrypted flag 2, so if no
    organization hard-seal marker exists we treat flag-2 objects as civilian for
    backward compatibility.
    """
    if not ev:
        return False
    meta = evidence_meta_dict(ev)
    if meta.get("hard_sealed_organization_media") or meta.get("organization_hard_sealed_media_preservation"):
        return False
    if meta.get("hard_sealed_civilian_evidence"):
        return True
    try:
        encrypted_flag = int(ev["encrypted"] or 0)
    except Exception:
        encrypted_flag = int((ev or {}).get("encrypted") or 0) if isinstance(ev, dict) else 0  # type: ignore[union-attr]
    return encrypted_flag == HARD_SEALED_ENCRYPTED_FLAG


def hard_sealed_organization_media_evidence(ev: dict[str, Any] | sqlite3.Row | None) -> bool:
    if not ev:
        return False
    meta = evidence_meta_dict(ev)
    return bool(meta.get("hard_sealed_organization_media") or meta.get("organization_hard_sealed_media_preservation"))


def civilian_hard_seal_required(*, source_type: str, storage_mode: str, kind: str, mime_type: str, raw_persisted: bool, meta: dict[str, Any] | None = None) -> bool:
    """Return True when evidence should not be decryptable by the local civilian install.

    Civilian Unknown Master Key mode still stores safe summaries/metadata with the
    normal local vault key so the collector can manage the case. Sensitive or
    original material is hard-sealed to the USCM escrow public key at capture
    time, so the local vault key cannot decrypt it.
    """
    if not civilian_unknown_master_mode():
        return False
    meta = meta or {}
    st = (storage_mode or "").lower()
    src = (source_type or "").lower()
    k = (kind or "").lower()
    mt = (mime_type or "").lower()
    if meta.get("hard_sealed_civilian_evidence"):
        return True
    if meta.get("sealed_media_preservation"):
        return True
    if st in {SEALED_PRESERVED_STORAGE_MODE, SEALED_PRESERVED_PAGE_SNAPSHOT_STORAGE_MODE}:
        return True
    if src == "sealed_page_snapshot" or meta.get("sealed_page_snapshot"):
        return True
    original_storage_modes = {
        "uploaded_original",
        "allowed_media_original",
        "captured_asset_local",
        "materialized_original",
        "raw_root",
        "live_browser_raw_html",
    }
    original_source_types = {
        "upload",
        "allowed_media_download",
        "captured_asset",
        "live_captured_asset",
        "blocked_media_materialization",
        "sealed_preserved_blocked_media",
    }
    if st in original_storage_modes or src in original_source_types:
        return True
    if raw_persisted and (k in {"image", "video", "audio", "media"} or mt.startswith(("image/", "video/", "audio/"))):
        return True
    return False


def organization_hard_seal_media_required(*, source_type: str, storage_mode: str, kind: str, mime_type: str, raw_persisted: bool, meta: dict[str, Any] | None = None) -> bool:
    """Return True when organization preserved media should be reviewer-key sealed.

    This intentionally applies only to Sealed Media Preservation objects in
    Organization-Controlled Key mode. Normal organization evidence keeps the
    existing local vault encryption/reveal workflow unless this specific
    hard-seal preservation path is used.
    """
    if not organization_controlled_mode():
        return False
    if not setting_bool("organization_hard_seal_media_enabled", "0"):
        return False
    meta = meta or {}
    st = (storage_mode or "").lower()
    src = (source_type or "").lower()
    if meta.get("hard_sealed_organization_media") or meta.get("hard_sealed_escrow_evidence"):
        return True
    if meta.get("sealed_media_preservation") or st == SEALED_PRESERVED_STORAGE_MODE or src == "sealed_preserved_blocked_media":
        return True
    if meta.get("sealed_page_snapshot") or st == SEALED_PRESERVED_PAGE_SNAPSHOT_STORAGE_MODE or src == "sealed_page_snapshot":
        return True
    return False


def sealed_page_snapshot_allowed(case_id: int | None) -> tuple[bool, str]:
    """Whether to save a reviewer-only rendered DOM snapshot for full-page review.

    This is intentionally limited to hard-sealed custody paths so safe-mode local
    users do not gain a local-vault-decryptable copy of the page HTML.
    """
    if civilian_unknown_master_mode():
        return True, "civilian_unknown_master_hard_seal"
    if organization_controlled_mode() and organization_hard_seal_media_configured():
        return True, "organization_hard_sealed_reviewer_key"
    return False, "no hard-sealed page snapshot key configured"


def media_kind_from_resource(*, url: str = "", resource_type: str = "", mime_type: str = "", browser_resource_type: str = "") -> str:
    mt = (mime_type or "").split(";", 1)[0].lower().strip()
    rt = (resource_type or "").lower().strip()
    brt = (browser_resource_type or "").lower().strip()
    if mt.startswith("image/") or rt == "image" or brt == "image":
        return "image"
    if mt.startswith("video/") or rt == "video":
        return "video"
    if mt.startswith("audio/") or rt == "audio":
        return "audio"
    if mt in {"application/dash+xml", "application/vnd.apple.mpegurl", "application/x-mpegurl", "application/mp4", "application/octet-stream"} and ("v.redd.it" in (url or "") or Path(urlparse(url or "").path.lower()).suffix in VIDEO_EXTS):
        return "video"
    ext = Path(urlparse(url or "").path.lower()).suffix
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    if ext in AUDIO_EXTS:
        return "audio"
    if rt == "media" or brt == "media":
        return "media"
    return rt or "other"


def mime_allowed_by_sealed_preservation(mime_type: str, url: str = "") -> bool:
    mt = (mime_type or "").split(";", 1)[0].lower().strip()
    if not mt:
        # Many hidden-service media responses omit Content-Type. Fall back to extension/type checks elsewhere.
        return True
    raw = get_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream")
    patterns = [x.strip().lower() for x in raw.replace(",", "\n").splitlines() if x.strip()]
    if not patterns:
        patterns = ["image/", "video/", "audio/"]
    for pat in patterns:
        if pat.endswith("/") and mt.startswith(pat):
            return True
        if pat.endswith("*") and mt.startswith(pat[:-1]):
            return True
        if mt == pat:
            return True
    return False


def sealed_media_preservation_policy(case: dict[str, Any] | None) -> dict[str, Any]:
    # Available in both custody modes. In Civilian Unknown Master Key mode the
    # local user cannot reveal preserved media. In Organization mode, preserved
    # media may either use the existing local vault/master-key workflow or, if
    # enabled below, hard-seal to an organization escrow public key so the local
    # vault key cannot decrypt it.
    global_enabled = setting_bool("sealed_media_preservation_enabled", "0")
    case_enabled = bool(case and truthy(case.get("sealed_media_preservation_enabled", 0)))
    max_each_global = safe_int(get_setting("sealed_media_preserve_max_bytes", "52428800"), 52428800, min_value=0)
    max_each_case = safe_int((case or {}).get("sealed_media_preserve_max_bytes", max_each_global), max_each_global, min_value=0)
    max_each = min(x for x in [max_each_global, max_each_case] if x > 0) if (max_each_global > 0 or max_each_case > 0) else 0
    org_hard_pem, org_hard_fp = organization_hard_seal_public_key()
    org_hard_enabled = organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0")
    return {
        "enabled": bool(global_enabled and case_enabled),
        "global_enabled": bool(global_enabled),
        "case_enabled": bool(case_enabled),
        "custody_mode": custody_mode(),
        "organization_mode": custody_mode() == "organization",
        "civilian_unknown_master_key_mode": civilian_unknown_master_mode(),
        "organization_hard_seal_media_enabled": bool(org_hard_enabled),
        "organization_hard_seal_media_configured": bool(org_hard_enabled and org_hard_pem and org_hard_fp),
        "organization_hard_seal_public_key_fingerprint": org_hard_fp if org_hard_enabled else "",
        "hard_sealed_storage_for_preserved_media": bool(civilian_unknown_master_mode() or (org_hard_enabled and org_hard_pem and org_hard_fp)),
        "images": setting_bool("sealed_media_preserve_images", "1") and bool((case or {}).get("sealed_media_preserve_images", 1)),
        "video": setting_bool("sealed_media_preserve_video", "1") and bool((case or {}).get("sealed_media_preserve_video", 1)),
        "audio": setting_bool("sealed_media_preserve_audio", "1") and bool((case or {}).get("sealed_media_preserve_audio", 1)),
        "max_each_bytes": max_each,
        "max_total_bytes": safe_int(get_setting("sealed_media_preserve_max_total_bytes", "209715200"), 209715200, min_value=0),
        "max_items_per_session": safe_int(get_setting("sealed_media_preserve_max_items_per_session", "2500"), 2500, min_value=0),
        "mime_allowlist": get_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream"),
    }


def sealed_media_preservation_allowed(case_id: int | None, *, url: str, resource_type: str = "", mime_type: str = "", browser_resource_type: str = "", content_length: int | None = None) -> tuple[bool, str, dict[str, Any]]:
    case = case_for(case_id)
    policy = sealed_media_preservation_policy(case)
    if not policy["enabled"]:
        if not policy["global_enabled"]:
            return False, "sealed media preservation is disabled globally", policy
        return False, "sealed media preservation is disabled for this case", policy
    if policy.get("organization_hard_seal_media_enabled") and not policy.get("organization_hard_seal_media_configured"):
        return False, "organization hard-sealed media preservation is enabled but no valid organization escrow public key is configured", policy
    kind = media_kind_from_resource(url=url, resource_type=resource_type, mime_type=mime_type, browser_resource_type=browser_resource_type)
    if kind == "image" and not policy["images"]:
        return False, "sealed preservation disabled for images", policy
    if kind == "video" and not policy["video"]:
        return False, "sealed preservation disabled for video", policy
    if kind == "audio" and not policy["audio"]:
        return False, "sealed preservation disabled for audio", policy
    if kind == "media" and not (policy["video"] or policy["audio"]):
        return False, "sealed preservation disabled for media", policy
    if kind not in {"image", "video", "audio", "media"}:
        return False, f"resource type {kind!r} is not configured for sealed media preservation", policy
    if mime_type and not mime_allowed_by_sealed_preservation(mime_type, url):
        return False, f"MIME type {mime_type!r} is outside sealed media preservation allowlist", policy
    if content_length is not None and policy["max_each_bytes"] and content_length > policy["max_each_bytes"]:
        return False, f"resource is larger than sealed preservation per-file limit ({content_length} > {policy['max_each_bytes']})", policy
    return True, "sealed media preservation allowed", policy


def filename_for_preserved_media(url: str, mime_type: str, fallback_id: str = "") -> str:
    base = clean_filename(Path(urlparse(url or "").path).name or "")
    if not base:
        base = f"sealed_preserved_media_{fallback_id or uuid.uuid4().hex[:8]}{ext_for_mime(mime_type or 'application/octet-stream')}"
    return base


def persist_sealed_preserved_media(*, actor: str, case_id: int | None, session_id: str | None, root_evidence_id: int | None, page_url: str | None, media_url: str, resource_type: str, mime_type: str, payload: bytes, request_method: str | None = None, referrer: str | None = None, request_headers: dict[str, Any] | None = None, response_headers: dict[str, Any] | None = None, status_code: int | None = None, reason: str = "blocked from local display; encrypted for sealed reviewer handoff", source_engine: str = "live_browser", final_url: str | None = None) -> int:
    mt = (mime_type or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0].strip()
    logical_kind = media_kind_from_resource(url=media_url, resource_type=resource_type, mime_type=mt)
    fname = filename_for_preserved_media(media_url, mt)
    meta = {
        "sealed_media_preservation": True,
        "custody_mode": custody_mode(),
        "civilian_unknown_master_key_mode": civilian_unknown_master_mode(),
        "organization_controlled_key_mode": custody_mode() == "organization",
        "blocked_from_local_display": True,
        "blocked_from_local_civilian_viewing": True,
        "clear_reviewer_required": True,
        "master_key_required_for_local_org_reveal": custody_mode() == "organization" and not organization_hard_seal_media_configured(),
        "organization_hard_seal_media_enabled": organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0"),
        "organization_hard_seal_media_configured": organization_hard_seal_media_configured(),
        "hard_sealed_reviewer_key_required": civilian_unknown_master_mode() or organization_hard_seal_media_configured(),
        "page_url": page_url or "",
        "page_url_sha256": sha256_text(page_url or ""),
        "media_url": media_url,
        "media_final_url": final_url or media_url,
        "media_url_sha256": sha256_text(media_url),
        "media_final_url_sha256": sha256_text(final_url or media_url),
        "url_aliases": sorted(url_aliases(media_url) | url_aliases(final_url or "")),
        "resource_type": logical_kind,
        "request_method": request_method or "GET",
        "referrer_sha256": sha256_text(referrer or ""),
        "request_headers_sha256": header_hash(request_headers),
        "response_headers": dict(response_headers or {}),
        "response_headers_sha256": header_hash(response_headers),
        "status_code": status_code,
        "source_engine": source_engine,
        "preservation_reason": reason,
        "preserved_at": utcnow(),
    }
    eid = persist_evidence(
        case_id=case_id,
        actor=actor,
        kind=logical_kind if logical_kind in {"image", "video", "audio", "media"} else kind_for(mt, fname),
        source_type="sealed_preserved_blocked_media",
        source_ref=media_url,
        filename=fname,
        mime_type=mt,
        payload=payload,
        encrypt=True,
        parent_id=root_evidence_id,
        storage_mode=SEALED_PRESERVED_STORAGE_MODE,
        raw_persisted=True,
        meta=meta,
        quarantined=True,
        lock_original=True,
        disable_plaintext=True,
        never_materialize=True,
    )
    log_event(actor, "SEALED_BLOCKED_MEDIA_PRESERVED", case_id=case_id, evidence_id=eid, session_id=session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical_kind, "size": len(payload), "mime_type": mt, "source_engine": source_engine})
    return eid


def object_path(base: Path, suffix: str = ".bin") -> Path:
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    folder = base / today
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{uuid.uuid4().hex}{suffix}"


def relative(path: Path) -> str:
    return str(path.relative_to(DATA_DIR)).replace("\\", "/")


def data_path(rel: str) -> Path:
    return DATA_DIR / rel


def persist_evidence(*, case_id: int | None, actor: str, kind: str, source_type: str, source_ref: str | None, filename: str, mime_type: str, payload: bytes, encrypt: bool = True, parent_id: int | None = None, storage_mode: str = "original", raw_persisted: bool = True, meta: dict[str, Any] | None = None, quarantined: bool | None = None, lock_original: bool | None = None, disable_plaintext: bool | None = None, never_materialize: bool | None = None) -> int:
    case = case_for(case_id)
    if quarantined is None:
        quarantined = True if not case else bool(case.get("quarantine_default"))
    if lock_original is None:
        lock_original = case_safe(case) or lockdown()
    if disable_plaintext is None:
        disable_plaintext = bool(case and case.get("no_plaintext_export")) or lockdown()
    if never_materialize is None:
        never_materialize = bool(case and case.get("never_materialize_originals")) or lockdown()
    meta = dict(meta or {})
    sha = sha256_bytes(payload)
    civilian_hard_seal = civilian_hard_seal_required(source_type=source_type, storage_mode=storage_mode, kind=kind, mime_type=mime_type, raw_persisted=raw_persisted, meta=meta)
    organization_hard_seal = organization_hard_seal_media_required(source_type=source_type, storage_mode=storage_mode, kind=kind, mime_type=mime_type, raw_persisted=raw_persisted, meta=meta)
    hard_seal = civilian_hard_seal or organization_hard_seal
    if hard_seal:
        if civilian_hard_seal:
            pem = load_uscm_escrow_public_key().strip()
            fp = escrow_public_fingerprint(pem)
            if not pem or not fp:
                raise HTTPException(500, "Civilian Unknown Master Key mode requires the embedded USCM escrow public key for hard-sealed storage")
            meta.update({
                "hard_sealed_civilian_evidence": True,
                "hard_sealed_escrow_evidence": True,
                "hard_sealed_storage_version": 1,
                "hard_sealed_decrypt_with": "USCM escrow private key / cleared reviewer workflow",
                "hard_sealed_local_vault_key_cannot_decrypt": True,
                "escrow_public_key_fingerprint": fp,
                "local_civilian_decrypt_available": False,
            })
            hard_seal_context = "civilian_unknown_master"
        else:
            pem, fp = organization_hard_seal_public_key()
            if not pem or not fp:
                raise HTTPException(500, "Organization hard-sealed media preservation requires a valid organization escrow public key")
            meta.update({
                "hard_sealed_organization_media": True,
                "hard_sealed_escrow_evidence": True,
                "hard_sealed_storage_version": 1,
                "hard_sealed_decrypt_with": "organization escrow private key / cleared reviewer workflow",
                "hard_sealed_local_vault_key_cannot_decrypt": True,
                "escrow_public_key_fingerprint": fp,
                "local_organization_decrypt_available": False,
                "organization_hard_sealed_media_preservation": True,
            })
            hard_seal_context = "organization_hard_sealed_media"
        stored = escrow_hard_seal_bytes(pem, payload, meta={"evidence_sha256": sha, "source_type": source_type, "storage_mode": storage_mode, "filename": clean_filename(filename), "mime_type": mime_type, "hard_seal_context": hard_seal_context})
        encrypted_flag = HARD_SEALED_ENCRYPTED_FLAG
    else:
        stored = encrypt_bytes(payload) if encrypt else payload
        encrypted_flag = 1 if encrypt else 0
    path = object_path(EVIDENCE_DIR, ".fvault")
    path.write_bytes(stored)
    eid = execute("""INSERT INTO evidence(case_id,parent_evidence_id,kind,source_type,source_ref,filename,mime_type,sha256,size,object_path,encrypted,storage_mode,raw_persisted,meta_json,status,quarantined,lock_direct_original_access,disable_plaintext_export,never_materialize_blocked_originals,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (case_id, parent_id, kind, source_type, source_ref or "", clean_filename(filename), mime_type or "application/octet-stream", sha, len(payload), relative(path), encrypted_flag, storage_mode, 1 if raw_persisted else 0, json.dumps(meta or {}, ensure_ascii=False), "unviewed", 1 if quarantined else 0, 1 if lock_original else 0, 1 if disable_plaintext else 0, 1 if never_materialize else 0, utcnow()))
    log_event(actor, "EVIDENCE_STORED", case_id=case_id, evidence_id=eid, details={"kind": kind, "source_type": source_type, "sha256": sha, "storage_mode": storage_mode, "raw_persisted": raw_persisted, "encrypted": encrypted_flag, "hard_sealed_escrow_evidence": hard_seal, "hard_sealed_civilian_evidence": civilian_hard_seal, "hard_sealed_organization_media": organization_hard_seal})
    return eid


def read_evidence(eid: int) -> bytes:
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    data = data_path(ev["object_path"]).read_bytes()
    if hard_sealed_escrow_evidence(ev):
        meta = evidence_meta_dict(ev)
        if meta.get("hard_sealed_organization_media"):
            raise HTTPException(403, "This evidence object is hard-sealed to the organization escrow public key and cannot be decrypted by the local vault key. Use sealed export/reviewer decrypt with the matching escrow private key.")
        raise HTTPException(403, "This evidence object is hard-sealed for Civilian Unknown Master Key custody and cannot be decrypted by the local installation. Use sealed export/reviewer decrypt with the escrow private key.")
    if ev.get("encrypted"):
        try:
            return decrypt_bytes(data)
        except InvalidToken as exc:
            raise HTTPException(500, "Stored evidence cannot be decrypted with current key") from exc
    return data


def migrate_existing_civilian_sensitive_evidence_to_hard_sealed() -> dict[str, Any]:
    """Upgrade older Civilian Unknown Master Key evidence to hard-sealed storage.

    Earlier builds encrypted evidence at rest with the local vault key. That was
    safe from plaintext-at-rest storage, but it still meant the local vault key
    could decrypt sensitive originals outside the UI. In Civilian Unknown Master
    Key mode, sensitive/original objects should instead be encrypted to the USCM
    escrow public key with no local decrypt key. This migration only affects
    objects that the same policy would hard-seal on new captures.
    """
    if not civilian_unknown_master_mode():
        return {"migrated": 0, "skipped": "not civilian_unknown_master"}
    pem = load_uscm_escrow_public_key().strip()
    fp = escrow_public_fingerprint(pem)
    if not pem or not fp:
        return {"migrated": 0, "error": "missing/invalid USCM escrow public key"}
    rows = fetchall("SELECT * FROM evidence ORDER BY id")
    migrated = 0
    failed: list[dict[str, Any]] = []
    for r in rows:
        ev = dict(r)
        if hard_sealed_civilian_evidence(ev):
            continue
        meta = jloads(ev.get("meta_json"), {})
        should = civilian_hard_seal_required(source_type=ev.get("source_type") or "", storage_mode=ev.get("storage_mode") or "", kind=ev.get("kind") or "", mime_type=ev.get("mime_type") or "", raw_persisted=bool(ev.get("raw_persisted")), meta=meta)
        if not should:
            continue
        try:
            path = data_path(ev["object_path"])
            stored = path.read_bytes()
            if int(ev.get("encrypted") or 0) == 1:
                plaintext = decrypt_bytes(stored)
            elif int(ev.get("encrypted") or 0) == 0:
                plaintext = stored
            else:
                continue
            meta.update({
                "hard_sealed_civilian_evidence": True,
                "hard_sealed_storage_version": 1,
                "hard_sealed_migrated_from_local_vault": True,
                "hard_sealed_migrated_at": utcnow(),
                "hard_sealed_decrypt_with": "USCM escrow private key / cleared reviewer workflow",
                "hard_sealed_local_vault_key_cannot_decrypt": True,
                "escrow_public_key_fingerprint": fp,
                "local_civilian_decrypt_available": False,
            })
            hard = escrow_hard_seal_bytes(pem, plaintext, meta={"evidence_id": ev.get("id"), "migrated_from_local_vault": True, "source_type": ev.get("source_type"), "storage_mode": ev.get("storage_mode"), "filename": ev.get("filename"), "mime_type": ev.get("mime_type")})
            path.write_bytes(hard)
            execute("UPDATE evidence SET encrypted=?, meta_json=?, lock_direct_original_access=1, disable_plaintext_export=1, never_materialize_blocked_originals=1 WHERE id=?", (HARD_SEALED_ENCRYPTED_FLAG, json.dumps(meta, ensure_ascii=False), ev["id"]))
            log_event("system", "CIVILIAN_EVIDENCE_HARD_SEALED_MIGRATED", case_id=ev.get("case_id"), evidence_id=ev.get("id"), details={"source_type": ev.get("source_type"), "storage_mode": ev.get("storage_mode"), "sha256": ev.get("sha256"), "escrow_public_key_fingerprint": fp})
            migrated += 1
        except Exception as exc:
            failed.append({"id": ev.get("id"), "error": str(exc)[:500]})
    return {"migrated": migrated, "failed": failed[:20]}


def migrate_existing_organization_preserved_media_to_hard_sealed() -> dict[str, Any]:
    """Upgrade older Organization-mode sealed-preserved media to reviewer-key storage.

    This only touches Sealed Media Preservation objects. Normal organization
    evidence remains on the existing local vault encryption path.
    """
    if not organization_controlled_mode():
        return {"migrated": 0, "skipped": "not organization mode"}
    if not setting_bool("organization_hard_seal_media_enabled", "0"):
        return {"migrated": 0, "skipped": "organization hard-sealed media disabled"}
    pem, fp = organization_hard_seal_public_key()
    if not pem or not fp:
        return {"migrated": 0, "error": "missing/invalid organization hard-seal public key"}
    rows = fetchall("SELECT * FROM evidence WHERE storage_mode=? OR source_type='sealed_preserved_blocked_media' ORDER BY id", (SEALED_PRESERVED_STORAGE_MODE,))
    migrated = 0
    failed: list[dict[str, Any]] = []
    for r in rows:
        ev = dict(r)
        if hard_sealed_escrow_evidence(ev):
            continue
        meta = jloads(ev.get("meta_json"), {})
        should = organization_hard_seal_media_required(source_type=ev.get("source_type") or "", storage_mode=ev.get("storage_mode") or "", kind=ev.get("kind") or "", mime_type=ev.get("mime_type") or "", raw_persisted=bool(ev.get("raw_persisted")), meta=meta)
        if not should:
            continue
        try:
            path = data_path(ev["object_path"])
            stored = path.read_bytes()
            if int(ev.get("encrypted") or 0) == 1:
                plaintext = decrypt_bytes(stored)
            elif int(ev.get("encrypted") or 0) == 0:
                plaintext = stored
            else:
                continue
            meta.update({
                "hard_sealed_organization_media": True,
                "hard_sealed_escrow_evidence": True,
                "hard_sealed_storage_version": 1,
                "hard_sealed_migrated_from_local_vault": True,
                "hard_sealed_migrated_at": utcnow(),
                "hard_sealed_decrypt_with": "organization escrow private key / reviewer workflow",
                "hard_sealed_local_vault_key_cannot_decrypt": True,
                "escrow_public_key_fingerprint": fp,
                "local_organization_decrypt_available": False,
                "organization_hard_sealed_media_preservation": True,
            })
            hard = escrow_hard_seal_bytes(pem, plaintext, meta={"evidence_id": ev.get("id"), "migrated_from_local_vault": True, "source_type": ev.get("source_type"), "storage_mode": ev.get("storage_mode"), "filename": ev.get("filename"), "mime_type": ev.get("mime_type"), "hard_seal_context": "organization_hard_sealed_media"})
            path.write_bytes(hard)
            execute("UPDATE evidence SET encrypted=?, meta_json=?, lock_direct_original_access=1, disable_plaintext_export=1, never_materialize_blocked_originals=1 WHERE id=?", (HARD_SEALED_ENCRYPTED_FLAG, json.dumps(meta, ensure_ascii=False), ev["id"]))
            log_event("system", "ORGANIZATION_PRESERVED_MEDIA_HARD_SEALED_MIGRATED", case_id=ev.get("case_id"), evidence_id=ev.get("id"), details={"source_type": ev.get("source_type"), "storage_mode": ev.get("storage_mode"), "sha256": ev.get("sha256"), "escrow_public_key_fingerprint": fp})
            migrated += 1
        except Exception as exc:
            failed.append({"id": ev.get("id"), "error": str(exc)[:500]})
    return {"migrated": migrated, "failed": failed[:20]}


def update_evidence_meta(eid: int, updates: dict[str, Any]) -> dict[str, Any]:
    """Merge metadata updates into an evidence row without changing original bytes/hash."""
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    meta = jloads(ev.get("meta_json"), {})
    meta.update(updates or {})
    execute("UPDATE evidence SET meta_json=? WHERE id=?", (json.dumps(meta, ensure_ascii=False), eid))
    return meta


def child_evidence_for(parent_id: int, kinds: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    if kinds:
        placeholders = ",".join("?" for _ in kinds)
        rows = fetchall(f"SELECT * FROM evidence WHERE parent_evidence_id=? AND kind IN ({placeholders}) ORDER BY id", (parent_id, *kinds))
    else:
        rows = fetchall("SELECT * FROM evidence WHERE parent_evidence_id=? ORDER BY id", (parent_id,))
    return [dict(r) for r in rows]


def persist_derived(*, evidence_id: int, kind: str, filename: str, mime_type: str, payload: bytes, encrypt: bool = True, meta: dict[str, Any] | None = None) -> int:
    stored = encrypt_bytes(payload) if encrypt else payload
    path = object_path(DERIVED_DIR, ".fvault")
    path.write_bytes(stored)
    did = execute("""INSERT INTO derived(evidence_id,kind,filename,mime_type,sha256,size,object_path,encrypted,meta_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""", (evidence_id, kind, clean_filename(filename), mime_type, sha256_bytes(payload), len(payload), relative(path), 1 if encrypt else 0, json.dumps(meta or {}, ensure_ascii=False), utcnow()))
    ev = evidence_for(evidence_id)
    log_event("system", "DERIVED_ARTIFACT_CREATED", case_id=ev.get("case_id") if ev else None, evidence_id=evidence_id, details={"derived_id": did, "kind": kind})
    return did


def read_derived(did: int) -> tuple[dict[str, Any], bytes]:
    row = rowdict(fetchone("SELECT * FROM derived WHERE id=?", (did,)))
    if not row:
        raise HTTPException(404, "Derived artifact not found")
    data = data_path(row["object_path"]).read_bytes()
    if row.get("encrypted"):
        data = decrypt_bytes(data)
    return row, data


def request_session(use_tor: bool = False, user_agent_profile: str | None = None, custom_user_agent: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": selected_user_agent(user_agent_profile, custom_user_agent),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
    })
    if use_tor:
        host = get_setting("tor_host", "127.0.0.1")
        port = get_setting("tor_socks_port", "9050")
        s.proxies.update({"http": f"socks5h://{host}:{port}", "https": f"socks5h://{host}:{port}"})
    return s


def header_hash(headers: dict[str, Any] | None) -> str:
    return sha256_text(canonical(headers or {}))


def header_get(headers: dict[str, Any] | None, name: str, default: Any = None) -> Any:
    if not headers:
        return default
    lname = name.lower()
    for k, v in headers.items():
        if str(k).lower() == lname:
            return v
    return default


def record_blocked_media(*, actor: str, case_id: int | None, root_evidence_id: int | None = None, session_id: str | None = None, page_url: str | None, media_url: str, resource_type: str, policy: str, reason: str, request_method: str | None = None, tag_type: str | None = None, referrer: str | None = None, response_headers: dict[str, Any] | None = None, request_headers: dict[str, Any] | None = None, status_code: int | None = None, content_type: str | None = None, content_length: str | None = None, downloaded: bool = False, content_sha256: str | None = None, use_tor: bool = False, head_probe: bool | None = None, user_agent_profile: str | None = None, custom_user_agent: str | None = None) -> int:
    if head_probe is None:
        head_probe = setting_bool("head_probe_blocked_media", "1")
    headers = dict(response_headers or {})
    method = request_method or "GET"
    ua_meta = user_agent_info(user_agent_profile, custom_user_agent)
    if head_probe and not headers and media_url.startswith(("http://", "https://")):
        try:
            r = request_session(use_tor, user_agent_profile, custom_user_agent).head(media_url, allow_redirects=True, timeout=10)
            headers = dict(r.headers)
            status_code = r.status_code
            content_type = header_get(headers, "Content-Type") or content_type
            content_length = header_get(headers, "Content-Length") or content_length
            method = "HEAD+blocked-GET"
        except Exception as exc:
            headers = {"head_probe_error": str(exc)[:300]}
    record = {
        "case_id": case_id,
        "root_evidence_id": root_evidence_id,
        "session_id": session_id,
        "page_url_sha256": sha256_text(page_url or ""),
        "media_url_sha256": sha256_text(media_url),
        "resource_type": resource_type,
        "request_method": method,
        "tag_type": tag_type,
        "referrer_sha256": sha256_text(referrer or ""),
        "policy": policy,
        "reason": reason,
        "status_code": status_code,
        "content_type": content_type or header_get(headers, "Content-Type"),
        "content_length": content_length or header_get(headers, "Content-Length"),
        "etag": header_get(headers, "ETag"),
        "last_modified": header_get(headers, "Last-Modified"),
        "header_sha256": header_hash(headers),
        "request_header_sha256": header_hash(request_headers),
        "head_probe_user_agent_profile": ua_meta.get("profile"),
        "head_probe_user_agent_sha256": ua_meta.get("user_agent_sha256"),
        "content_sha256": content_sha256,
        "downloaded": downloaded,
        "created_at": utcnow(),
    }
    metadata_record_hash = sha256_text(canonical(record))
    bid = execute("""INSERT INTO blocked_media(case_id,root_evidence_id,session_id,page_url,media_url,url_sha256,resource_type,request_method,tag_type,referrer,policy,reason,status_code,content_type,content_length,etag,last_modified,headers_json,request_headers_json,header_sha256,content_sha256,downloaded,metadata_record_hash,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (case_id, root_evidence_id, session_id, page_url or "", media_url, record["media_url_sha256"], resource_type, method, tag_type, referrer or "", policy, reason, status_code, record["content_type"], record["content_length"], record["etag"], record["last_modified"], json.dumps(headers, ensure_ascii=False), json.dumps(request_headers or {}, ensure_ascii=False), record["header_sha256"], content_sha256, 1 if downloaded else 0, metadata_record_hash, record["created_at"]))
    log_event(actor, "BLOCKED_MEDIA_RECORDED", case_id=case_id, evidence_id=root_evidence_id, blocked_media_id=bid, session_id=session_id, details={"url_sha256": record["media_url_sha256"], "resource_type": resource_type, "policy": policy, "downloaded": downloaded, "metadata_record_hash": metadata_record_hash})
    return bid



def preserve_blocked_media_via_requests(*, actor: str, case_id: int | None, root_evidence_id: int | None, session_id: str | None, page_url: str, media_url: str, resource_type: str, policy_name: str, tag_type: str | None = None, referrer: str | None = None, use_tor: bool = False, user_agent_profile: str | None = None, custom_user_agent: str | None = None) -> tuple[int | None, int | None, str]:
    """Fetch a blocked media URL into encrypted evidence for sealed handoff only.

    This helper is intentionally separate from normal materialization. It is only
    active in Civilian Unknown Master Key mode when both global and case-level
    Sealed Media Preservation are enabled. It never returns bytes to a viewer.
    """
    if not media_url.startswith(("http://", "https://")):
        return None, None, "sealed preservation skipped: non-network/inline media reference"
    ok, why, pol = sealed_media_preservation_allowed(case_id, url=media_url, resource_type=resource_type)
    if not ok:
        return None, None, why
    try:
        sess = request_session(use_tor, user_agent_profile, custom_user_agent)
        with sess.get(media_url, stream=True, timeout=30, allow_redirects=True) as r:
            headers = dict(r.headers)
            mt = (header_get(headers, "Content-Type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0].strip()
            content_len_raw = header_get(headers, "Content-Length")
            content_len = safe_int(content_len_raw, -1, min_value=-1) if content_len_raw not in (None, "") else None
            ok2, why2, pol = sealed_media_preservation_allowed(case_id, url=media_url, resource_type=resource_type, mime_type=mt, content_length=content_len)
            if not ok2:
                bid = record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_evidence_id, session_id=session_id, page_url=page_url, media_url=media_url, resource_type=resource_type, request_method="GET+sealed-preserve-skip", tag_type=tag_type, referrer=referrer or page_url, policy=policy_name, reason=why2, response_headers=headers, status_code=r.status_code, content_type=mt, content_length=content_len_raw, downloaded=False, use_tor=use_tor, head_probe=False, user_agent_profile=user_agent_profile, custom_user_agent=custom_user_agent)
                return None, bid, why2
            max_each = int(pol.get("max_each_bytes") or 0)
            chunks: list[bytes] = []
            total = 0
            too_large = False
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                total += len(chunk)
                if max_each and total > max_each:
                    too_large = True
                    break
                chunks.append(chunk)
            if too_large:
                bid = record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_evidence_id, session_id=session_id, page_url=page_url, media_url=media_url, resource_type=resource_type, request_method="GET+sealed-preserve-skip", tag_type=tag_type, referrer=referrer or page_url, policy=policy_name, reason=f"sealed preservation skipped: streamed response exceeded per-file limit ({total} > {max_each})", response_headers=headers, status_code=r.status_code, content_type=mt, content_length=str(total), downloaded=False, use_tor=use_tor, head_probe=False, user_agent_profile=user_agent_profile, custom_user_agent=custom_user_agent)
                return None, bid, "sealed preservation skipped: response exceeded per-file limit"
            body = b"".join(chunks)
            if not body:
                bid = record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_evidence_id, session_id=session_id, page_url=page_url, media_url=media_url, resource_type=resource_type, request_method="GET+sealed-preserve-skip", tag_type=tag_type, referrer=referrer or page_url, policy=policy_name, reason="sealed preservation skipped: empty response body", response_headers=headers, status_code=r.status_code, content_type=mt, content_length="0", downloaded=False, use_tor=use_tor, head_probe=False, user_agent_profile=user_agent_profile, custom_user_agent=custom_user_agent)
                return None, bid, "sealed preservation skipped: empty response body"
            logical = media_kind_from_resource(url=media_url, resource_type=resource_type, mime_type=mt)
            final_media_url = str(getattr(r, "url", None) or media_url)
            eid = persist_sealed_preserved_media(actor=actor, case_id=case_id, session_id=session_id, root_evidence_id=root_evidence_id, page_url=page_url, media_url=media_url, resource_type=logical, mime_type=mt, payload=body, request_method="GET+sealed-preserve", referrer=referrer or page_url, response_headers=headers, status_code=r.status_code, reason="blocked from local display; encrypted for sealed reviewer handoff", source_engine="direct_url_capture", final_url=final_media_url)
            if root_evidence_id:
                try:
                    register_captured_asset(actor=actor, case_id=case_id, session_id=session_id, root_evidence_id=root_evidence_id, resource_evidence_id=eid, original_url=media_url, resource_type=logical, mime_type=mt, size=len(body), sha256=sha256_bytes(body), meta={"sealed_preserved_link": True, "final_url": final_media_url, "url_aliases": sorted(url_aliases(media_url) | url_aliases(final_media_url)), "capture_engine": "direct_url_capture"})
                except Exception:
                    pass
            bid = record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_evidence_id, session_id=session_id, page_url=page_url, media_url=media_url, resource_type=logical, request_method="GET+sealed-preserve", tag_type=tag_type, referrer=referrer or page_url, policy=policy_name, reason="blocked from local display; encrypted for sealed reviewer handoff", response_headers=headers, status_code=r.status_code, content_type=mt, content_length=str(len(body)), downloaded=True, content_sha256=sha256_bytes(body), use_tor=use_tor, head_probe=False, user_agent_profile=user_agent_profile, custom_user_agent=custom_user_agent)
            execute("UPDATE blocked_media SET materialized_evidence_id=? WHERE id=?", (eid, bid))
            return eid, bid, "sealed media preserved encrypted for reviewer handoff"
    except Exception as exc:
        bid = record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_evidence_id, session_id=session_id, page_url=page_url, media_url=media_url, resource_type=resource_type, request_method="GET+sealed-preserve-failed", tag_type=tag_type, referrer=referrer or page_url, policy=policy_name, reason=f"sealed preservation failed: {str(exc)[:500]}", use_tor=use_tor, head_probe=True, user_agent_profile=user_agent_profile, custom_user_agent=custom_user_agent)
        log_event(actor, "SEALED_BLOCKED_MEDIA_PRESERVE_FAILED", case_id=case_id, evidence_id=root_evidence_id, blocked_media_id=bid, session_id=session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": resource_type, "error": str(exc)[:500]})
        return None, bid, f"sealed preservation failed: {exc}"


def register_captured_asset(*, actor: str, case_id: int | None, session_id: str | None, root_evidence_id: int | None, resource_evidence_id: int, original_url: str, resource_type: str, mime_type: str | None, size: int | None, sha256: str | None, meta: dict[str, Any] | None = None) -> int:
    aid = execute("""INSERT INTO captured_assets(case_id,session_id,root_evidence_id,resource_evidence_id,original_url,url_sha256,resource_type,mime_type,size,sha256,created_at,meta_json)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (case_id, session_id, root_evidence_id, resource_evidence_id, original_url or "", sha256_text(original_url or ""), resource_type, mime_type or "", size, sha256 or "", utcnow(), pretty(meta or {})))
    log_event(actor, "CAPTURED_ASSET_STORED", case_id=case_id, evidence_id=resource_evidence_id, session_id=session_id, details={"asset_id": aid, "root_evidence_id": root_evidence_id, "url_sha256": sha256_text(original_url or ""), "resource_type": resource_type, "size": size})
    return aid


def link_preserved_media_to_page_capture(*, actor: str, case_id: int | None, session_id: str | None, page_evidence_id: int, page_url: str, html_refs: list[dict[str, Any]] | None = None, dynamic_refs: list[dict[str, Any]] | None = None, limit: int = 800) -> list[int]:
    """Link encrypted preserved blocked-media objects to a saved page capture.

    Live media is preserved before the page evidence row exists, so the preserved
    media initially has only session/page URL metadata. This function runs at
    manual/auto capture time and creates captured_assets rows that let the exact
    renderer and reviewer page viewer place recovered media with the page.
    """
    if not session_id and not page_url:
        return []
    ref_aliases = media_ref_aliases((html_refs or []) + (dynamic_refs or []), page_url)
    page_aliases = url_aliases(page_url)
    clauses = ["e.storage_mode=?", "b.downloaded=1", "b.materialized_evidence_id IS NOT NULL"]
    params: list[Any] = [SEALED_PRESERVED_STORAGE_MODE]
    if session_id:
        clauses.append("b.session_id=?")
        params.append(session_id)
    elif case_id is not None:
        clauses.append("b.case_id=?")
        params.append(case_id)
    params.append(limit)
    rows = fetchall(f"""SELECT b.*, e.filename, e.mime_type, e.kind, e.size, e.sha256, e.meta_json evidence_meta_json
                       FROM blocked_media b JOIN evidence e ON e.id=b.materialized_evidence_id
                       WHERE {' AND '.join(clauses)} ORDER BY b.id DESC LIMIT ?""", tuple(params))
    linked_ids: list[int] = []
    for b in rows:
        try:
            resource_eid = int(b["materialized_evidence_id"])
        except Exception:
            continue
        exists = fetchone("SELECT 1 FROM captured_assets WHERE root_evidence_id=? AND resource_evidence_id=? LIMIT 1", (page_evidence_id, resource_eid))
        if exists:
            continue
        media_aliases = url_aliases(str(b["media_url"] or ""))
        page_match = False
        b_page = str(b["page_url"] or "")
        if page_aliases and url_aliases(b_page) & page_aliases:
            page_match = True
        if ref_aliases and media_aliases & ref_aliases:
            page_match = True
        if session_id and str(b["session_id"] or "") == session_id:
            # Keep a conservative fallback for JS-heavy pages where the DOM no
            # longer exposes a media URL, but the request happened in the same
            # captured browser session and was marked against the current page.
            if not b_page or page_match or (str(b["referrer"] or "") and url_aliases(str(b["referrer"] or "")) & page_aliases):
                page_match = True
        if not page_match:
            continue
        meta = {
            "sealed_preserved_link": True,
            "blocked_media_id": b["id"],
            "blocked_media_metadata_record_hash": b["metadata_record_hash"],
            "page_evidence_id": page_evidence_id,
            "url_aliases": sorted(media_aliases),
            "match_reason": "same page/session media preservation",
        }
        aid = register_captured_asset(actor=actor, case_id=case_id, session_id=session_id, root_evidence_id=page_evidence_id, resource_evidence_id=resource_eid, original_url=str(b["media_url"] or ""), resource_type=str(b["resource_type"] or "media"), mime_type=str(b["content_type"] or b["mime_type"] or ""), size=int(b["size"] or 0), sha256=str(b["content_sha256"] or b["sha256"] or ""), meta=meta)
        linked_ids.append(aid)
    if linked_ids:
        log_event(actor, "SEALED_PRESERVED_MEDIA_LINKED_TO_PAGE", case_id=case_id, evidence_id=page_evidence_id, session_id=session_id, details={"linked_asset_rows": len(linked_ids), "page_url_sha256": sha256_text(page_url or "")})
    return linked_ids


def captured_assets_for_model(ev: dict[str, Any], model: dict[str, Any] | None = None, limit: int = 2000) -> list[sqlite3.Row]:
    model = model or saved_capture_model(ev)
    metadata = model.get("metadata") or {}
    session_id = str(metadata.get("session_id") or "")
    source_url = str(model.get("source_url") or ev.get("source_ref") or "")
    source_aliases = url_aliases(source_url)
    rows: list[sqlite3.Row] = []
    seen_resources: set[int] = set()

    def add_rows(new_rows: list[sqlite3.Row]) -> None:
        for rr in new_rows:
            try:
                rid = int(rr["resource_evidence_id"])
            except Exception:
                continue
            if rid in seen_resources:
                continue
            seen_resources.add(rid)
            rows.append(rr)

    clauses = ["a.root_evidence_id=?"]
    params: list[Any] = [ev["id"]]
    if session_id:
        clauses.append("a.session_id=?")
        params.append(session_id)
    params.append(limit)
    add_rows(fetchall(f"""SELECT a.*, e.filename, e.kind, e.storage_mode, e.object_path, e.encrypted, e.disable_plaintext_export, e.lock_direct_original_access
                       FROM captured_assets a JOIN evidence e ON e.id=a.resource_evidence_id
                       WHERE {' OR '.join(clauses)}
                       ORDER BY a.id DESC LIMIT ?""", tuple(params)))

    # Backward-compatible fallback: direct/full-forensic media children from older builds.
    add_rows(fetchall("""SELECT NULL id, e.case_id, '' session_id, e.parent_evidence_id root_evidence_id, e.id resource_evidence_id,
                             e.source_ref original_url, e.sha256 url_sha256, e.kind resource_type, e.mime_type, e.size, e.sha256, e.created_at, e.meta_json,
                             e.filename, e.kind, e.storage_mode, e.object_path, e.encrypted, e.disable_plaintext_export, e.lock_direct_original_access
                      FROM evidence e WHERE e.parent_evidence_id=? AND e.source_type IN ('allowed_media_download','captured_asset','live_captured_asset','sealed_preserved_blocked_media')
                      ORDER BY e.id DESC LIMIT ?""", (ev["id"], limit)))

    # Fast-route fallback: background sealed-preserved media can finish after
    # page capture, before a captured_assets link exists. Add downloaded
    # blocked-media objects from the same page/session so renderers can place
    # already-preserved media back into the page.
    bm_where = ["b.downloaded=1", "b.materialized_evidence_id IS NOT NULL"]
    bm_params: list[Any] = []
    if ev.get("case_id"):
        bm_where.append("b.case_id=?")
        bm_params.append(ev.get("case_id"))
    if session_id:
        bm_where.append("b.session_id=?")
        bm_params.append(session_id)
    bm_params.append(limit)
    bm_rows = fetchall(f"""SELECT b.id id, b.case_id, b.session_id,
                              COALESCE(b.root_evidence_id, ?) root_evidence_id,
                              b.materialized_evidence_id resource_evidence_id,
                              b.media_url original_url, b.url_sha256 url_sha256,
                              b.resource_type resource_type,
                              COALESCE(NULLIF(b.content_type,''), e.mime_type) mime_type,
                              e.size size, COALESCE(NULLIF(b.content_sha256,''), e.sha256) sha256,
                              b.created_at created_at,
                              json_object('blocked_media_id', b.id, 'page_url', b.page_url, 'referrer', b.referrer, 'url_aliases', json_array(b.media_url)) meta_json,
                              e.filename filename, e.kind kind, e.storage_mode storage_mode, e.object_path object_path, e.encrypted encrypted,
                              e.disable_plaintext_export disable_plaintext_export, e.lock_direct_original_access lock_direct_original_access
                       FROM blocked_media b JOIN evidence e ON e.id=b.materialized_evidence_id
                       WHERE {' AND '.join(bm_where)}
                       ORDER BY b.id DESC LIMIT ?""", tuple([ev["id"]] + bm_params))
    filtered: list[sqlite3.Row] = []
    for br in bm_rows:
        match = False
        try:
            if int(br["root_evidence_id"] or 0) == int(ev["id"]):
                match = True
        except Exception:
            pass
        try:
            meta = jloads(br["meta_json"], {})
            b_page = str(meta.get("page_url") or "")
            ref = str(meta.get("referrer") or "")
            if source_aliases and ((url_aliases(b_page) & source_aliases) or (url_aliases(ref) & source_aliases)):
                match = True
        except Exception:
            pass
        if session_id and not source_aliases:
            match = True
        if match:
            filtered.append(br)
    add_rows(filtered)
    return rows[:limit]

def asset_map_for_model(ev: dict[str, Any], model: dict[str, Any] | None = None) -> dict[str, sqlite3.Row]:
    rows = captured_assets_for_model(ev, model)
    out: dict[str, sqlite3.Row] = {}
    for r in rows:
        aliases = row_url_aliases(r, "original_url")
        # Some fallback rows have the evidence source URL but no captured_assets row.
        aliases.update(row_url_aliases(r, "source_ref"))
        for alias in aliases:
            out.setdefault(alias, r)
    return out


def render_assets_allowed(user: dict[str, Any], ev: dict[str, Any]) -> tuple[bool, str]:
    case = case_for(ev.get("case_id"))
    if case_safe(case):
        return False, "case is compliance-safe; exact local media rendering is disabled"
    if lockdown():
        return False, "global lockdown disables exact local media rendering"
    if not ev.get("raw_persisted"):
        return False, "no raw page bytes were persisted, so exact renderer cannot be built"
    if ev.get("lock_direct_original_access") and user.get("role") not in {"admin", "supervisor"}:
        return False, "page original is locked for this user"
    return True, "exact local saved-asset renderer available"


def absolute_resource_url(source_url: str, value: str) -> str:
    value = (value or "").strip()
    if not value or value.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return value
    return urljoin(source_url or "", value)


def url_aliases(url: str, source_url: str = "") -> set[str]:
    """Return stable aliases for matching recovered media back into pages.

    Modern sites often refer to the same asset with different query strings,
    redirects, srcset widths, or escaped URLs. These aliases are only used for
    local evidence matching; they never permit remote fetching in viewers.
    """
    raw = (url or "").strip()
    if not raw or raw.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return set()
    absu = absolute_resource_url(source_url, raw) if source_url else raw
    out: set[str] = set()
    candidates = {raw, absu, unquote(raw), unquote(absu)}
    for cand in list(candidates):
        cand = (cand or "").strip()
        if not cand:
            continue
        out.add(cand)
        nofrag = cand.split("#", 1)[0]
        out.add(nofrag)
        try:
            p = urlparse(nofrag)
            if p.scheme and p.netloc:
                normalized_netloc = p.netloc.lower()
                normalized_path = unquote(p.path or "")
                base = urlunparse((p.scheme.lower(), normalized_netloc, normalized_path, "", "", ""))
                out.add(base)
                if p.query:
                    out.add(urlunparse((p.scheme.lower(), normalized_netloc, normalized_path, "", p.query, "")))
        except Exception:
            pass
    return {x for x in out if x}


def media_ref_aliases(refs: list[dict[str, Any]], source_url: str = "") -> set[str]:
    out: set[str] = set()
    for ref in refs or []:
        val = str(ref.get("url") or ref.get("src") or ref.get("href") or "")
        out.update(url_aliases(val, source_url))
    return out


def row_url_aliases(row: Any, *fields: str) -> set[str]:
    out: set[str] = set()
    for field in fields:
        try:
            val = row[field]
        except Exception:
            try:
                val = row.get(field)
            except Exception:
                val = None
        out.update(url_aliases(str(val or "")))
    try:
        meta = jloads(row["meta_json"], {})
    except Exception:
        try:
            meta = jloads(row.get("meta_json"), {})
        except Exception:
            meta = {}
    for val in (meta.get("url_aliases") or []):
        out.update(url_aliases(str(val or "")))
    for key in ["media_url", "media_final_url", "original_url", "page_url"]:
        if meta.get(key):
            out.update(url_aliases(str(meta.get(key))))
    return out


def strip_blindsite_live_media_blockers(soup: BeautifulSoup) -> None:
    """Remove BlindSite live-browser visual blockers from captured HTML before rendering.

    The live browser injects pre-paint CSS/JS so blocked images/SVG/canvas/media never
    flash to the investigator. If a rendered DOM snapshot is captured while that style
    exists, the reviewer/case renderer would otherwise keep hiding recovered media.
    This removes only BlindSite-owned blocking artifacts; it does not remove site CSS.
    """
    try:
        for tag in list(soup.find_all(["style", "script"])):
            txt = tag.string or tag.get_text("", strip=False) or ""
            tid = str(tag.get("id") or "")
            data_bs = str(tag.get("data-blindsite") or "")
            if tid == "__blindsite_live_media_block_css" or data_bs == "live-media-block":
                tag.decompose()
                continue
            if "__blindsite_live_media_block_css" in txt or "data-blindsite-media-boot" in txt:
                tag.decompose()
                continue
            if "[data-blindsite" in txt and "background-image:none!important" in txt and "display:none!important" in txt:
                tag.decompose()
                continue
    except Exception:
        pass
    try:
        for el in soup.find_all(True):
            if el.has_attr("data-blindsite-media-boot"):
                del el.attrs["data-blindsite-media-boot"]
    except Exception:
        pass


def rewrite_css_urls(css_text: str, source_url: str, asset_map: dict[str, sqlite3.Row], asset_url_func) -> str:
    def repl(match: re.Match) -> str:
        quote = match.group(1) or ""
        raw = (match.group(2) or "").strip()
        if raw.startswith(("data:", "blob:")):
            return f"url({quote}{raw}{quote})"
        absu = absolute_resource_url(source_url, raw)
        asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
        if asset:
            return f"url({quote}{asset_url_func(asset)}{quote})"
        return "url('')"
    return re.sub(r"url\(\s*(['\"]?)(.*?)(?:\1)\s*\)", repl, css_text or "")


def rewrite_srcset(value: str, source_url: str, asset_map: dict[str, sqlite3.Row], asset_url_func) -> str:
    parts: list[str] = []
    for item in (value or "").split(','):
        item = item.strip()
        if not item:
            continue
        bits = item.split()
        raw = bits[0]
        absu = absolute_resource_url(source_url, raw)
        asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
        if asset:
            bits[0] = asset_url_func(asset)
            parts.append(' '.join(bits))
    return ', '.join(parts)


def rendered_capture_html(ev: dict[str, Any], model: dict[str, Any] | None = None, *, for_export: bool = False, export_asset_prefix: str = "assets") -> str:
    """Build an offline/static page renderer from saved raw HTML and saved assets only.

    The renderer rewrites media/style references to local vault routes or export-relative
    asset files. It removes active code/navigation and enforces a strict CSP so opening a
    saved page cannot call back out to the live web.
    """
    model = model or saved_capture_model(ev)
    source_url = model.get("source_url") or ev.get("source_ref") or ""
    raw_html = model.get("raw_html_source") or ""
    title = model.get("title") or ev.get("filename") or "Saved page"
    asset_map = asset_map_for_model(ev, model)

    def asset_url(asset_row: sqlite3.Row) -> str:
        rid = int(asset_row["resource_evidence_id"])
        fname = clean_filename(str(asset_row["filename"] or f"asset_{rid}.bin"))
        if for_export:
            return f"{export_asset_prefix}/asset_{rid}_{fname}"
        return f"/evidence/{ev['id']}/render-asset/{rid}"

    if not raw_html:
        return saved_capture_frame_html(ev, model, for_export=for_export)

    soup = BeautifulSoup(raw_html, "html.parser")
    strip_blindsite_live_media_blockers(soup)

    # Static forensic renderer: saved bytes only; active execution/navigation disabled.
    for tag in soup.find_all(["script", "iframe", "object", "embed"]):
        placeholder = soup.new_tag("div")
        placeholder["data-ftv-removed"] = tag.name
        placeholder.string = f"[BlindSite removed {tag.name} from static renderer]"
        tag.replace_with(placeholder)

    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv") or "").lower() == "refresh":
            meta.decompose()

    for el in soup.find_all(True):
        for attr in list(el.attrs):
            if attr.lower().startswith("on"):
                del el.attrs[attr]
        if el.name == "a" and el.has_attr("href"):
            original = absolute_resource_url(source_url, str(el.get("href") or ""))
            el["data-original-href"] = original
            el["href"] = "#"
            el["title"] = f"Original link preserved but disabled: {original}"
        if el.name == "form":
            el["data-original-action"] = str(el.get("action") or "")
            el["action"] = "#"
            el["method"] = "get"

    for tag in soup.find_all(["img", "video", "audio", "source"]):
        for attr in ["src", "poster"]:
            if tag.has_attr(attr):
                raw = str(tag.get(attr) or "")
                absu = absolute_resource_url(source_url, raw)
                asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
                if asset:
                    tag[attr] = asset_url(asset)
                    tag[f"data-original-{attr}"] = absu
                    if tag.name in {"video", "audio"}:
                        tag["controls"] = "controls"
                else:
                    tag[f"data-missing-{attr}"] = absu
                    tag[attr] = ""
        if tag.has_attr("srcset"):
            original = str(tag.get("srcset") or "")
            rewritten = rewrite_srcset(original, source_url, asset_map, asset_url)
            tag["data-original-srcset"] = original
            if rewritten:
                tag["srcset"] = rewritten
            else:
                del tag.attrs["srcset"]

    for link in list(soup.find_all("link")):
        rel_val = link.get("rel")
        rel = " ".join(rel_val).lower() if isinstance(rel_val, list) else str(rel_val or "").lower()
        href = str(link.get("href") or "")
        as_attr = str(link.get("as") or "").lower()
        if href and ("stylesheet" in rel or as_attr in {"style", "font"}):
            absu = absolute_resource_url(source_url, href)
            asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
            if asset:
                link["href"] = asset_url(asset)
                link["data-original-href"] = absu
            else:
                link.decompose()
        else:
            link.decompose()

    for el in soup.find_all(style=True):
        el["style"] = rewrite_css_urls(str(el.get("style") or ""), source_url, asset_map, asset_url)
    for style in soup.find_all("style"):
        style.string = rewrite_css_urls(style.string or "", source_url, asset_map, asset_url)

    if soup.html is None:
        html_tag = soup.new_tag("html")
        existing = list(soup.contents)
        for child in existing:
            html_tag.append(child.extract())
        soup.append(html_tag)
    if soup.head is None:
        head = soup.new_tag("head")
        soup.html.insert(0, head)
    if soup.body is None:
        body = soup.new_tag("body")
        soup.html.append(body)

    csp = soup.new_tag("meta")
    csp["http-equiv"] = "Content-Security-Policy"
    csp["content"] = "default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
    soup.head.insert(0, csp)
    style_tag = soup.new_tag("style")
    style_tag.string = "[data-ftv-removed]{display:block;padding:8px;margin:4px;border:1px dashed #64748b;background:#111827;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif}.ftv-banner{position:sticky;top:0;z-index:2147483647;background:#111827;color:#e5e7eb;border-bottom:2px solid #38bdf8;padding:8px 12px;font:14px Segoe UI,Arial,sans-serif}img,video{max-width:100%;height:auto}"
    soup.head.append(style_tag)
    if not soup.title:
        title_tag = soup.new_tag("title")
        title_tag.string = str(title)
        soup.head.append(title_tag)
    banner = soup.new_tag("div")
    banner["class"] = "ftv-banner"
    banner.string = f"BlindSite static renderer — saved local assets only — remote network disabled — evidence #{ev.get('id')} — source: {source_url}"
    if soup.body:
        soup.body.insert(0, banner)
    # Make the renderer self-auditing for complex pages: if a dynamic player fails
    # to place every recovered media object back into the DOM, reviewers still get
    # a local recovered-media shelf inside the rendered page. This does not fetch
    # anything remote; it uses reviewer recovered objects already imported.
    try:
        related_media = reviewer_dedup_media_rows(reviewer_related_objects(import_id, obj, include_session_fallback=True, include_non_media=False, limit=600))
        if related_media:
            shelf = soup.new_tag("details")
            shelf["class"] = "blindsite-recovered-media-shelf"
            shelf["style"] = "margin:16px;padding:10px;border:1px solid #334155;background:#0f172a;color:#e5e7eb;font:14px Segoe UI,Arial,sans-serif;clear:both"
            summary = soup.new_tag("summary")
            summary.string = f"BlindSite recovered media shelf ({len(related_media)} unique objects)"
            shelf.append(summary)
            p = soup.new_tag("p")
            p.string = "Collapsed by default to avoid duplicating the main recovered page. Open this shelf if a site player did not place a recovered object back into the page."
            shelf.append(p)
            grid = soup.new_tag("div")
            grid["style"] = "display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px"
            for media_obj in related_media[:250]:
                mt = (media_obj.get("mime_type") or "application/octet-stream").split(";",1)[0].lower()
                raw = f"/reviewer/imports/{import_id}/objects/{int(media_obj['id'])}/raw"
                card = soup.new_tag("div")
                card["style"] = "border:1px solid #334155;background:#020617;border-radius:10px;padding:8px;overflow:hidden"
                title_el = soup.new_tag("div")
                title_el["style"] = "font-size:12px;color:#cbd5e1;word-break:break-all;margin-bottom:6px"
                title_el.string = str(media_obj.get("filename") or f"object_{media_obj.get('id')}")
                card.append(title_el)
                try:
                    sc = BeautifulSoup(reviewer_star_control_html(import_id, media_obj, return_to=f"/reviewer/imports/{import_id}/pages?page={int(obj.get('id') or 0)}"), "html.parser").find("form")
                    if sc:
                        card.append(sc)
                except Exception:
                    pass
                playback = reviewer_playback_kind(media_obj)
                if playback == "image":
                    el = soup.new_tag("img", src=raw)
                    el["style"] = "max-width:100%;max-height:220px;object-fit:contain;background:#111827"
                    card.append(el)
                elif playback == "video" or mt in {"application/vnd.apple.mpegurl", "application/x-mpegurl", "application/dash+xml", "application/mp4"}:
                    el = soup.new_tag("video", src=raw, controls="controls", preload="metadata")
                    el["style"] = "max-width:100%;max-height:260px;background:#000"
                    card.append(el)
                elif playback == "audio":
                    el = soup.new_tag("audio", src=raw, controls="controls", preload="metadata")
                    el["style"] = "width:100%"
                    card.append(el)
                else:
                    a = soup.new_tag("a", href=raw)
                    a.string = f"Open recovered object #{media_obj.get('id')}"
                    card.append(a)
                reason = soup.new_tag("div")
                reason["style"] = "font-size:11px;color:#94a3b8;word-break:break-word;margin-top:6px"
                reason.string = str(media_obj.get("_reviewer_match_reason") or media_obj.get("source_ref") or media_obj.get("original_url") or "")[:500]
                card.append(reason)
                grid.append(card)
            shelf.append(grid)
            soup.body.append(shelf)
    except Exception:
        pass
    return "<!doctype html>\n" + str(soup)
def extract_media_refs(base_url: str, html_text: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    soup = BeautifulSoup(html_text or "", "html.parser")
    attrs = [("img", "src"), ("img", "srcset"), ("source", "src"), ("source", "srcset"), ("video", "src"), ("video", "poster"), ("audio", "src"), ("iframe", "src"), ("link", "href")]
    for tag, attr in attrs:
        for el in soup.find_all(tag):
            val = el.get(attr)
            if not val:
                continue
            values = []
            if attr == "srcset":
                values = [v.strip().split(" ")[0] for v in val.split(",") if v.strip()]
            else:
                values = [val]
            for v in values:
                inline = v.startswith("data:")
                refs.append({"url": v if inline else urljoin(base_url, v), "tag": tag, "attr": attr, "inline": inline})
    for el in soup.find_all(style=True):
        style = el.get("style", "")
        # simple CSS url(...) detection
        for part in style.split("url(")[1:]:
            raw = part.split(")", 1)[0].strip("'\" ")
            if raw:
                refs.append({"url": raw if raw.startswith("data:") else urljoin(base_url, raw), "tag": "style", "attr": "url", "inline": raw.startswith("data:")})
    return refs


def sanitize_html_summary(base_url: str, html_text: str, limit: int | None = None) -> dict[str, Any]:
    limit = limit or int(get_setting("max_text_summary_chars", "20000") or "20000")
    soup = BeautifulSoup(html_text or "", "html.parser")
    removed: dict[str, int] = {}
    for tag in ["script", "style", "img", "picture", "video", "audio", "source", "canvas", "svg", "iframe", "embed", "object"]:
        els = soup.find_all(tag)
        removed[tag] = len(els)
        for el in els:
            el.decompose()
    for el in soup.find_all(True):
        for attr in list(el.attrs):
            if attr.lower().startswith("on") or attr.lower() in {"src", "srcset", "poster", "style"}:
                del el.attrs[attr]
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    text = soup.get_text("\n", strip=True)[:limit]
    links = []
    for a in soup.find_all("a", href=True)[:200]:
        href = urljoin(base_url, a.get("href"))
        links.append({"text": a.get_text(" ", strip=True)[:140], "url": href, "url_sha256": sha256_text(href)})
    return {"title": title, "text": text, "links": links, "removed_counts": removed, "source_url_sha256": sha256_text(base_url)}


def network_fingerprint(url: str, use_tor: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"host": host_of(url), "use_tor": use_tor}
    if use_tor:
        out["dns_tls_note"] = "Local DNS/TLS probing skipped because Tor/SOCKS mode is enabled."
        return out
    host = host_of(url)
    if not host:
        return out
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        out["addresses"] = sorted({i[4][0] for i in infos})[:20]
    except Exception as exc:
        out["dns_error"] = str(exc)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                out["tls_cert_sha256"] = sha256_bytes(cert) if cert else None
                out["tls_version"] = ssock.version()
    except Exception as exc:
        out["tls_error"] = str(exc)
    return out


def is_page_capture_evidence(ev: dict[str, Any] | None) -> bool:
    if not ev:
        return False
    return (ev.get("source_type") in {"live_browser_capture", "url_capture"}
            or ev.get("storage_mode") in {"live_browser_sanitized_summary", "live_browser_raw_html", "sanitized_summary", "metadata_only", "raw_root"}
            or ev.get("kind") in {"live_browser_summary", "browser_root_html", "root_summary", "metadata"})


def evidence_payload_text(ev: dict[str, Any], limit: int | None = None) -> str:
    data = read_evidence(int(ev["id"]))
    text = data.decode("utf-8", errors="replace")
    if limit is not None and len(text) > limit:
        return text[:limit] + f"\n\n[truncated after {limit} characters]"
    return text


def saved_capture_model(ev: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized safe representation of a saved URL/live-browser capture.

    The viewer never fetches remote resources. It renders only the bytes already saved by
    BlindSite, and for raw HTML it uses a sanitized DOM/text reconstruction by default.
    """
    max_text = int(get_setting("max_text_summary_chars", "20000") or "20000")
    raw = read_evidence(int(ev["id"]))
    text = raw.decode("utf-8", errors="replace")
    parsed: Any = None
    if (ev.get("mime_type") or "").startswith("application/json") or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
    meta: dict[str, Any] = meta_of(ev)
    summary: dict[str, Any] = {}
    source_url = ev.get("source_ref") or ""
    title = ""
    raw_html_source = ""
    payload_kind = "unknown"
    if isinstance(parsed, dict):
        payload_kind = "json_summary"
        meta = parsed.get("live_browser_metadata") or parsed.get("root_metadata") or parsed.get("metadata") or meta
        summary = parsed.get("sanitized_summary") or parsed.get("summary") or {}
        source_url = meta.get("current_url") or meta.get("final_url") or meta.get("requested_url") or ev.get("source_ref") or ""
        title = summary.get("title") or meta.get("title") or ""
        if not summary:
            summary = {"text": pretty(parsed)[:max_text], "links": [], "removed_counts": {}}
    elif "html" in (ev.get("mime_type") or "") or text.lstrip().lower().startswith(("<!doctype", "<html", "<")):
        payload_kind = "raw_html_sanitized_view"
        source_url = ev.get("source_ref") or ""
        summary = sanitize_html_summary(source_url, text, limit=max_text)
        title = summary.get("title") or ""
        raw_html_source = text
        meta = {**meta, "raw_html_saved": bool(ev.get("raw_persisted")), "safe_view_note": "Raw HTML was sanitized for display; original bytes remain in the vault."}
    else:
        payload_kind = "text_or_binary_summary"
        summary = {"title": ev.get("filename") or "Saved capture", "text": text[:max_text], "links": [], "removed_counts": {}}
        title = summary["title"]
    summary.setdefault("links", [])
    summary.setdefault("removed_counts", {})
    summary.setdefault("text", "")
    return {
        "evidence": ev,
        "payload_kind": payload_kind,
        "source_url": source_url,
        "source_url_sha256": sha256_text(source_url or ""),
        "title": title,
        "metadata": meta,
        "summary": summary,
        "raw_html_source": raw_html_source,
    }


def blocked_media_for_capture(ev: dict[str, Any], model: dict[str, Any] | None = None, limit: int = 500) -> list[sqlite3.Row]:
    session_id = ""
    if model:
        session_id = str((model.get("metadata") or {}).get("session_id") or "")
    rows = list(fetchall("SELECT * FROM blocked_media WHERE root_evidence_id=? ORDER BY id DESC LIMIT ?", (ev["id"], limit)))
    if session_id:
        more = fetchall("SELECT * FROM blocked_media WHERE session_id=? AND (root_evidence_id IS NULL OR root_evidence_id<>?) ORDER BY id DESC LIMIT ?", (session_id, ev["id"], limit))
        rows.extend(more)
    return rows[:limit]


def register_page_capture(*, session_id: str | None, case_id: int | None, evidence_id: int, page_url: str, title: str, capture_mode: str, raw_persisted: bool, meta: dict[str, Any] | None = None) -> int:
    pcid = execute("""INSERT INTO page_captures(session_id,case_id,evidence_id,page_url,page_url_sha256,title,capture_mode,raw_persisted,created_at,meta_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""", (session_id, case_id, evidence_id, page_url or "", sha256_text(page_url or ""), title or "", capture_mode, 1 if raw_persisted else 0, utcnow(), pretty(meta or {})))
    return pcid


def page_captures_for_session(session_id: str) -> list[sqlite3.Row]:
    rows = fetchall("""SELECT p.*,e.filename,e.kind,e.mime_type,e.storage_mode,e.sha256,e.created_at evidence_created_at
                       FROM page_captures p JOIN evidence e ON e.id=p.evidence_id
                       WHERE p.session_id=? ORDER BY p.id DESC""", (session_id,))
    if rows:
        return rows
    # Fallback for captures made by older builds before page_captures existed.
    like = f'%"session_id": "{session_id}"%'
    return fetchall("""SELECT NULL id, ? session_id, e.case_id, e.id evidence_id, e.source_ref page_url, '' page_url_sha256,
                             e.filename title, e.storage_mode capture_mode, e.raw_persisted raw_persisted, e.created_at created_at, e.meta_json,
                             e.filename,e.kind,e.mime_type,e.storage_mode,e.sha256,e.created_at evidence_created_at
                      FROM evidence e WHERE e.source_type='live_browser_capture' AND e.meta_json LIKE ? ORDER BY e.id DESC""", (session_id, like))


def page_captures_for_case(case_id: int) -> list[sqlite3.Row]:
    rows = fetchall("""SELECT p.*,e.filename,e.kind,e.mime_type,e.storage_mode,e.sha256,e.created_at evidence_created_at
                       FROM page_captures p JOIN evidence e ON e.id=p.evidence_id
                       WHERE p.case_id=? ORDER BY p.id DESC""", (case_id,))
    if rows:
        return rows
    return fetchall("""SELECT NULL id, '' session_id, e.case_id, e.id evidence_id, e.source_ref page_url, '' page_url_sha256,
                             e.filename title, e.storage_mode capture_mode, e.raw_persisted raw_persisted, e.created_at created_at, e.meta_json,
                             e.filename,e.kind,e.mime_type,e.storage_mode,e.sha256,e.created_at evidence_created_at
                      FROM evidence e WHERE e.case_id=? AND e.source_type IN ('live_browser_capture','url_capture') ORDER BY e.id DESC""", (case_id,))


def saved_capture_frame_html(ev: dict[str, Any], model: dict[str, Any] | None = None, *, for_export: bool = False) -> str:
    model = model or saved_capture_model(ev)
    summary = model.get("summary") or {}
    metadata = model.get("metadata") or {}
    title = model.get("title") or ev.get("filename") or "Saved capture"
    source_url = model.get("source_url") or ev.get("source_ref") or ""
    text_block = str(summary.get("text") or "")
    links = summary.get("links") if isinstance(summary.get("links"), list) else []
    removed = summary.get("removed_counts") if isinstance(summary.get("removed_counts"), dict) else {}
    link_rows = "".join(f"<tr><td>{h((ln.get('text') or '')[:200])}</td><td class='mono'>{h(ln.get('url') or '')}</td><td class='mono'>{h(ln.get('url_sha256') or sha256_text(ln.get('url') or ''))}</td></tr>" for ln in links)
    removed_rows = "".join(f"<tr><td>{h(k)}</td><td>{h(v)}</td></tr>" for k, v in removed.items())
    meta_pre = h(pretty(metadata)[:30000])
    blocked = blocked_media_for_capture(ev, model, 300)
    bm_rows = "".join(f"<tr><td>#{b['id']}</td><td>{h(b['resource_type'])}</td><td>{'downloaded' if b['downloaded'] else 'not downloaded'}</td><td class='mono'>{h(b['media_url'])}</td><td class='mono'>{h(b['url_sha256'])}</td></tr>" for b in blocked)
    export_note = "Exported safe saved-page viewer" if for_export else "Safe saved-page viewer"
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; img-src 'none'; media-src 'none'; script-src 'none'; connect-src 'none'; frame-src 'none'; style-src 'unsafe-inline'">
<title>{h(title)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e5e7eb;margin:0;padding:22px}}a{{color:#38bdf8}}.card{{background:#111827;border:1px solid #334155;border-radius:12px;padding:16px;margin:14px 0}}.muted{{color:#9ca3af}}.mono,pre{{font-family:Consolas,Menlo,monospace}}pre{{white-space:pre-wrap;overflow:auto;background:#020617;border:1px solid #334155;border-radius:10px;padding:12px}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #334155;padding:7px;text-align:left;vertical-align:top}}.scroll{{overflow-x:auto}}.badge{{display:inline-block;border:1px solid #475569;border-radius:99px;padding:3px 8px;margin:2px;background:#020617}}
</style></head><body><h1>{h(title or 'Saved capture')}</h1><div class='card'><b>{h(export_note)}</b><p class='muted'>This page was reconstructed only from data already saved by BlindSite. It does not load remote images, video, scripts, stylesheets, frames, or network resources.</p><p><span class='badge'>Evidence #{h(ev.get('id'))}</span><span class='badge'>storage: {h(ev.get('storage_mode'))}</span><span class='badge'>raw persisted: {h(ev.get('raw_persisted'))}</span></p><p><b>Source URL:</b> <span class='mono'>{h(source_url)}</span></p><p><b>Source URL SHA-256:</b> <span class='mono'>{h(model.get('source_url_sha256'))}</span></p></div><div class='card'><h2>Captured text / sanitized DOM summary</h2><pre>{h(text_block)}</pre></div><div class='card'><h2>Links preserved from page</h2><div class='scroll'><table><tr><th>Text</th><th>URL</th><th>URL SHA-256</th></tr>{link_rows or '<tr><td colspan="3" class="muted">No links in saved summary.</td></tr>'}</table></div></div><div class='card'><h2>Removed or blocked element counts</h2><table><tr><th>Element</th><th>Count</th></tr>{removed_rows or '<tr><td colspan="2" class="muted">No removed-count data.</td></tr>'}</table></div><div class='card'><h2>Blocked media associated with this capture/session</h2><div class='scroll'><table><tr><th>ID</th><th>Type</th><th>State</th><th>URL</th><th>URL SHA-256</th></tr>{bm_rows or '<tr><td colspan="5" class="muted">No blocked media records linked to this capture.</td></tr>'}</table></div></div><div class='card'><h2>Capture metadata</h2><pre>{meta_pre}</pre></div></body></html>"""


def page_capture_rows(case_id: int | None = None, q: str = "", session_id: str | None = None, limit: int = 500, starred: bool = False, hashtag: str = "") -> list[sqlite3.Row]:
    clauses = ["1=1"]
    params: list[Any] = []
    if case_id is not None:
        clauses.append("p.case_id=?")
        params.append(case_id)
    if session_id:
        clauses.append("p.session_id=?")
        params.append(session_id)
    if starred:
        clauses.append("p.starred=1")
    tag = normalize_hashtags(hashtag).split()
    if tag:
        clauses.append("lower(p.hashtags) LIKE ?")
        params.append(f"%{tag[0].lower()}%")
    if q:
        like = f"%{q}%"
        clauses.append("(p.page_url LIKE ? OR p.title LIKE ? OR e.filename LIKE ? OR e.sha256 LIKE ? OR p.hashtags LIKE ?)")
        params.extend([like, like, like, like, like])
    params.append(limit)
    return fetchall(f"""SELECT p.*, e.sha256, e.filename, e.storage_mode, e.raw_persisted, e.mime_type, c.name case_name
                       FROM page_captures p
                       JOIN evidence e ON e.id=p.evidence_id
                       LEFT JOIN cases c ON c.id=p.case_id
                       WHERE {' AND '.join(clauses)}
                       ORDER BY p.starred DESC, p.id DESC LIMIT ?""", tuple(params))


def saved_media_rows(case_id: int | None = None, q: str = "", kind: str = "all", state: str = "all", limit: int = 300, starred: bool = False, hashtag: str = "", exts: str = "") -> list[sqlite3.Row]:
    clauses = ["(lower(e.kind) IN ('image','video','audio','media') OR lower(e.mime_type) LIKE 'image/%' OR lower(e.mime_type) LIKE 'video/%' OR lower(e.mime_type) LIKE 'audio/%' OR e.storage_mode IN ('allowed_media_original','materialized_original','sealed_preserved_blocked_media'))"]
    params: list[Any] = []
    if case_id is not None:
        clauses.append("e.case_id=?")
        params.append(case_id)
    if kind != "all":
        if kind == "image":
            clauses.append("(lower(e.kind)='image' OR lower(e.mime_type) LIKE 'image/%')")
        elif kind == "video":
            clauses.append("(lower(e.kind) IN ('video','media') OR lower(e.mime_type) LIKE 'video/%')")
        elif kind == "audio":
            clauses.append("(lower(e.kind)='audio' OR lower(e.mime_type) LIKE 'audio/%')")
    if state == "materialized":
        clauses.append("e.storage_mode='materialized_original'")
    elif state == "saved":
        clauses.append("e.storage_mode<>'materialized_original'")
    if starred:
        clauses.append("e.starred=1")
    tag = normalize_hashtags(hashtag).split()
    if tag:
        clauses.append("lower(e.hashtags) LIKE ?")
        params.append(f"%{tag[0].lower()}%")
    if q:
        like = f"%{q}%"
        clauses.append("(e.filename LIKE ? OR e.source_ref LIKE ? OR e.sha256 LIKE ? OR e.mime_type LIKE ? OR e.hashtags LIKE ?)")
        params.extend([like, like, like, like, like])
    rows = fetchall(f"""SELECT e.*, c.name case_name FROM evidence e LEFT JOIN cases c ON c.id=e.case_id
                       WHERE {' AND '.join(clauses)} ORDER BY e.starred DESC, e.id DESC LIMIT ?""", tuple(params + [limit]))
    ext_filters = extension_filter_list(exts)
    if ext_filters:
        rows = [r for r in rows if extension_matches(str(r['filename'] or r['source_ref'] or ''), str(r['mime_type'] or ''), ext_filters)]
    return rows

def blocked_media_rows(case_id: int | None = None, q: str = "", kind: str = "all", state: str = "all", limit: int = 300) -> list[sqlite3.Row]:
    clauses = ["1=1"]
    params: list[Any] = []
    if case_id is not None:
        clauses.append("b.case_id=?")
        params.append(case_id)
    if kind != "all":
        if kind == "video":
            clauses.append("b.resource_type IN ('video','media')")
        else:
            clauses.append("b.resource_type=?")
            params.append(kind)
    if state == "blocked":
        clauses.append("b.downloaded=0")
    elif state == "materialized":
        clauses.append("b.downloaded=1")
    if q:
        like = f"%{q}%"
        clauses.append("(b.media_url LIKE ? OR b.url_sha256 LIKE ? OR b.metadata_record_hash LIKE ? OR b.resource_type LIKE ?)")
        params.extend([like, like, like, like])
    params.append(limit)
    return fetchall(f"""SELECT b.*, c.name case_name, e.filename materialized_filename, e.mime_type materialized_mime
                       FROM blocked_media b
                       LEFT JOIN cases c ON c.id=b.case_id
                       LEFT JOIN evidence e ON e.id=b.materialized_evidence_id
                       WHERE {' AND '.join(clauses)} ORDER BY b.id DESC LIMIT ?""", tuple(params))




def normalize_hashtags(text: str) -> str:
    """Normalize free-form hashtag input to a stable space-separated #tag list."""
    raw = str(text or "").replace(",", " ").split()
    tags: list[str] = []
    seen: set[str] = set()
    for token in raw:
        token = token.strip().lower()
        if not token:
            continue
        if not token.startswith("#"):
            token = "#" + token
        token = re.sub(r"[^#a-z0-9._-]+", "", token)
        if token == "#" or len(token) < 2:
            continue
        if token not in seen:
            seen.add(token)
            tags.append(token[:64])
    return " ".join(tags)


def hashtag_badges(text: str) -> str:
    tags = normalize_hashtags(text).split()
    return " ".join(badge(t, "info") for t in tags)


def extension_label_from_url_or_name(value: str, mime_type: str = "") -> str:
    """Human-friendly file type label for media/bulk retry/reviewer tables."""
    raw = (value or "").strip()
    path = urlparse(raw).path if raw.startswith(("http://", "https://")) else raw
    ext = Path(unquote(path)).suffix.lower().strip(".")
    mt = (mime_type or "").split(";", 1)[0].lower()
    if not ext:
        if mt.startswith("image/"):
            ext = mt.split("/", 1)[1]
        elif mt.startswith("video/"):
            ext = mt.split("/", 1)[1]
        elif mt.startswith("audio/"):
            ext = mt.split("/", 1)[1]
        elif "json" in mt:
            ext = "json"
        elif "xml" in mt:
            ext = "xml"
        elif "pdf" in mt:
            ext = "pdf"
        else:
            ext = "bin"
    aliases = {
        "mpegurl": "m3u8", "x-mpegurl": "m3u8", "vnd.apple.mpegurl": "m3u8",
        "dash+xml": "mpd", "svg+xml": "svg", "jpeg": "jpg", "plain": "txt",
    }
    ext = aliases.get(ext, ext)
    return ext[:24]


def extension_filter_list(text: str) -> list[str]:
    vals = []
    for token in re.split(r"[\s,;|]+", text or ""):
        token = token.strip().lower().lstrip(".")
        if token:
            vals.append(token)
    return vals


def extension_matches(value: str, mime_type: str, filters: list[str]) -> bool:
    if not filters:
        return True
    label = extension_label_from_url_or_name(value, mime_type).lower().lstrip(".")
    mt = (mime_type or "").lower()
    return any(f == label or f in mt for f in filters)


def reviewer_object_thumb(import_id: int, obj: dict[str, Any], *, small: bool = True) -> str:
    """Small visual thumbnail for LE recovered-object lists. Uses local recovered objects only."""
    oid = int(obj.get("id") or 0)
    kind = reviewer_playback_kind(obj)
    mt = (obj.get("mime_type") or "").split(";", 1)[0].lower()
    raw = f"/reviewer/imports/{import_id}/objects/{oid}/raw"
    cls = "rv-thumb-small" if small else "rv-thumb"
    label = extension_label_from_url_or_name(str(obj.get("filename") or obj.get("source_ref") or ""), mt).upper()
    if kind == "image":
        return f"<div class='{cls}'><img src='{raw}' loading='lazy' alt='{h(obj.get('filename') or '')}'></div>"
    if kind == "video":
        # A muted metadata preload gives a decent first-frame thumbnail in most browsers without playing audio.
        return f"<div class='{cls}'><video src='{raw}' preload='metadata' muted playsinline></video><span class='thumb-label'>VIDEO {h(label)}</span></div>"
    if kind == "audio":
        return f"<div class='{cls} thumb-audio'><span>♪</span><b>AUDIO</b><small>{h(label)}</small></div>"
    if mt == "application/pdf":
        return f"<div class='{cls} thumb-doc'><span>PDF</span></div>"
    return f"<div class='{cls} thumb-doc'><span>{h(label)}</span></div>"


def evidence_thumb(ev: dict[str, Any], user: dict[str, Any] | None = None, preview: str = "none") -> str:
    mt = (ev.get("mime_type") or "").split(";", 1)[0].lower()
    if preview == "blur" and mt.startswith("image/") and user:
        try:
            ok, why = reveal_allowed(user, ev, "blur")
            if ok:
                tok = signed_token(int(ev["id"]), "blur", user["username"])
                return f"<div class='thumb'><img src='/evidence/{int(ev['id'])}/serve?mode=blur&token={h(tok)}' loading='lazy' alt='blurred preview'></div>"
        except Exception:
            pass
    label = extension_label_from_url_or_name(str(ev.get("filename") or ev.get("source_ref") or ""), mt).upper()
    if mt.startswith("video/"):
        return f"<div class='thumb thumb-doc'><span>VIDEO</span><small>{h(label)}</small></div>"
    if mt.startswith("audio/"):
        return f"<div class='thumb thumb-audio'><span>♪</span><b>AUDIO</b><small>{h(label)}</small></div>"
    if mt.startswith("image/"):
        return "<div class='thumb'><span class='muted'>image evidence</span></div>"
    return f"<div class='thumb thumb-doc'><span>{h(label)}</span></div>"


def blocked_media_session_stats(session_id: str) -> dict[str, int]:
    row = rowdict(fetchone("""SELECT count(*) total,
        sum(CASE WHEN downloaded=1 THEN 1 ELSE 0 END) downloaded_count,
        sum(CASE WHEN downloaded=0 THEN 1 ELSE 0 END) not_downloaded_count,
        sum(CASE WHEN downloaded=0 AND lower(reason) LIKE '%queue full%' THEN 1 ELSE 0 END) queue_full_count,
        sum(CASE WHEN downloaded=0 AND lower(reason) LIKE '%timeout%' THEN 1 ELSE 0 END) timeout_count
        FROM blocked_media WHERE session_id=?""", (session_id,))) or {}
    return {
        "total": int(row.get("total") or 0),
        "downloaded": int(row.get("downloaded_count") or 0),
        "not_downloaded": int(row.get("not_downloaded_count") or 0),
        "queue_full": int(row.get("queue_full_count") or 0),
        "timeouts": int(row.get("timeout_count") or 0),
    }


def blocked_media_session_rows(session_id: str, limit: int = 300) -> list[sqlite3.Row]:
    return fetchall("SELECT * FROM blocked_media WHERE session_id=? ORDER BY id DESC LIMIT ?", (session_id, limit))


def blocked_media_session_file_type_counts(session_id: str, limit: int = 5000) -> dict[str, int]:
    rows = fetchall("SELECT media_url, content_type, resource_type FROM blocked_media WHERE session_id=? ORDER BY id DESC LIMIT ?", (session_id, limit))
    counts: dict[str, int] = {}
    for r in rows:
        ext = extension_label_from_url_or_name(str(r["media_url"] or ""), str(r["content_type"] or ""))
        ext = (ext or str(r["resource_type"] or "other") or "other").lower().strip().lstrip(".")
        if not ext:
            ext = "other"
        counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def render_blocked_media_type_chips(counts: dict[str, int], max_items: int = 36) -> str:
    if not counts:
        return "<p class='small muted'>No file types recorded yet.</p>"
    chips = []
    for ext, count in list(counts.items())[:max_items]:
        chips.append(f"<button type='button' class='secondary small' style='padding:4px 8px' onclick=\"document.getElementById('blockedMediaExtFilter').value='{h(ext)}';filterBlockedMediaRows();\">{h(ext)} <b>{int(count)}</b></button>")
    if len(counts) > max_items:
        chips.append(badge(f"+{len(counts)-max_items} more", "info"))
    return "<div class='tagline' style='gap:6px;margin:8px 0'>" + " ".join(chips) + "</div>"


def render_live_blocked_media_rows(rows: list[sqlite3.Row]) -> str:
    html_rows = []
    for b in rows:
        ext = extension_label_from_url_or_name(str(b['media_url'] or ''), str(b['content_type'] or ''))
        reason_l = str(b['reason'] or '').lower()
        html_rows.append(
            f"<tr class='bm-row' data-ext='{h(ext)}' data-kind='{h(b['resource_type'])}' data-notdownloaded='{1 if not b['downloaded'] else 0}' data-queuefull='{1 if (not b['downloaded'] and 'queue full' in reason_l) else 0}'>"
            f"<td><input type='checkbox' class='bm-check' name='blocked_ids' value='{int(b['id'])}' {'disabled' if b['downloaded'] else ''}></td>"
            f"<td><a href='/blocked/{b['id']}'>#{b['id']}</a></td><td>{h(b['resource_type'])}</td><td>{badge(ext,'info')}</td>"
            f"<td>{badge('downloaded','warn') if b['downloaded'] else badge('not downloaded','good')}</td>"
            f"<td>{h(b['reason'])}</td><td class='urlcell'>{h(b['media_url'])}</td>"
            f"<td class='hashcell'><code>{h(b['url_sha256'])}</code></td></tr>"
        )
    return "".join(html_rows) or '<tr><td colspan="8" class="muted">No blocked media records for this session yet.</td></tr>'

def render_live_blocked_media_stats(stats: dict[str, int]) -> str:
    return f"{badge('total '+str(stats.get('total',0)),'info')} {badge('downloaded '+str(stats.get('downloaded',0)),'warn')} {badge('not downloaded '+str(stats.get('not_downloaded',0)),'good')} {badge('queue full '+str(stats.get('queue_full',0)),'bad' if stats.get('queue_full',0) else 'info')} {badge('timeouts '+str(stats.get('timeouts',0)),'bad' if stats.get('timeouts',0) else 'info')}"


def event_header_hash_html(headers_json: Any, header_sha256: Any) -> str:
    """Return a clear live-event header-hash display.

    Navigation/tab events often have no response headers; older UI still showed
    SHA-256({}) which is 44136fa3... for every such row. That was technically
    accurate but misleading because it looked like different sites shared the
    same captured response headers. Keep the audit data unchanged, but show a
    human-readable empty-header state in the live-session table.
    """
    raw = "" if headers_json is None else str(headers_json).strip()
    parsed = jloads(raw, {}) if raw else {}
    if isinstance(parsed, dict) and parsed:
        return f"<code>{h(header_sha256 or header_hash(parsed))}</code>"
    if raw and raw not in {"{}", "[]", "null", "None"}:
        # Non-empty but unparsable/legacy header text: keep the stored hash visible
        # while making clear the app could not parse a normal header dictionary.
        return f"<code>{h(header_sha256 or '')}</code><br><span class='small muted'>unparsed headers</span>"
    return "<span class='small muted'>No headers captured</span>"

def build_case_saved_pages_index(case_id: int, data: dict[str, Any]) -> str:
    case = data.get("case") or {}
    captures = data.get("page_captures") or []
    rows = []
    for c in captures:
        fname = f"saved_pages/evidence_{c['evidence_id']}.html"
        rows.append(f"<tr><td>#{h(c['evidence_id'])}</td><td><a href='{h(fname)}'>{h(c.get('title') or c.get('filename') or 'Saved page')}</a></td><td>{h(c.get('capture_mode'))}</td><td>{'raw persisted' if c.get('raw_persisted') else 'safe summary / metadata'}</td><td>{h(c.get('created_at'))}</td><td>{h(c.get('page_url'))}</td><td><code>{h(c.get('sha256'))}</code></td></tr>")
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Saved pages - case {h(case.get('id'))}</title><style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;vertical-align:top}}code{{word-break:break-all}}.muted{{color:#666}}</style></head><body><h1>Saved pages for case {h(case.get('name',''))}</h1><p class='muted'>These HTML viewers are reconstructed from what BlindSite saved. They do not fetch remote images, video, scripts, stylesheets, frames, or network resources.</p><table><tr><th>Evidence</th><th>Viewer</th><th>Capture mode</th><th>Raw state</th><th>Captured</th><th>Source URL</th><th>Evidence SHA-256</th></tr>{''.join(rows) or '<tr><td colspan="7">No saved pages.</td></tr>'}</table></body></html>"""


def build_case_media_index(data: dict[str, Any]) -> str:
    case = data.get("case") or {}
    media = data.get("media_evidence") or []
    blocked = data.get("blocked_media") or []
    saved_rows = []
    for e in media:
        saved_rows.append(f"<tr><td>#{h(e.get('id'))}</td><td>{h(e.get('filename'))}</td><td>{h(e.get('kind'))}</td><td>{h(e.get('mime_type'))}</td><td>{h(e.get('storage_mode'))}</td><td><code>{h(e.get('sha256'))}</code></td><td>{h(e.get('source_ref'))}</td></tr>")
    blocked_rows = []
    for b in blocked:
        blocked_rows.append(f"<tr><td>#{h(b.get('id'))}</td><td>{h(b.get('resource_type'))}</td><td>{'downloaded' if b.get('downloaded') else 'not downloaded'}</td><td>{h(b.get('reason'))}</td><td><code>{h(b.get('url_sha256'))}</code></td><td>{h(b.get('media_url'))}</td></tr>")
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Media - case {h(case.get('id'))}</title><style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;vertical-align:top}}code{{word-break:break-all}}.muted{{color:#666}}</style></head><body><h1>Media inventory for case {h(case.get('name',''))}</h1><p class='muted'>Report-only media index. Original media bytes are not included in this export.</p><h2>Saved/materialized media evidence</h2><table><tr><th>Evidence</th><th>Filename</th><th>Kind</th><th>MIME</th><th>Storage</th><th>SHA-256</th><th>Source</th></tr>{''.join(saved_rows) or '<tr><td colspan="7">No saved media evidence.</td></tr>'}</table><h2>Blocked media metadata</h2><table><tr><th>ID</th><th>Type</th><th>State</th><th>Reason</th><th>URL SHA-256</th><th>URL</th></tr>{''.join(blocked_rows) or '<tr><td colspan="6">No blocked media.</td></tr>'}</table></body></html>"""


def application_genesis_html_block(app_genesis: dict[str, Any] | None) -> str:
    g = app_genesis or {}
    warnings = g.get("warnings") or []
    warning_rows = "".join(f"<li>{h(w)}</li>" for w in warnings)
    return f"""<h2>Application Genesis Hash / Executable Genesis Seal</h2>
<div class='warn'>
<p><b>Verification helper:</b> {h(g.get('verification_statement') or 'This investigation was initialized with BlindSite executable SHA-256: UNAVAILABLE. Compare this hash against the published GitHub release SHA256SUMS for the claimed release.')}</p>
<table>
<tr><th>Investigation ID</th><td>{h(g.get('investigation_id') or '')}</td></tr>
<tr><th>Genesis event hash</th><td><code>{h(g.get('genesis_hash') or g.get('event_hash') or '')}</code></td></tr>
<tr><th>Executable/source SHA-256</th><td><code>{h(g.get('executable_sha256') or '')}</code></td></tr>
<tr><th>Build kind</th><td>{h(g.get('build_kind') or '')}</td></tr>
<tr><th>Executable path</th><td>{h(g.get('executable_path') or '')}</td></tr>
<tr><th>Source path</th><td>{h(g.get('source_path') or '')}</td></tr>
<tr><th>Git commit</th><td><code>{h(g.get('git_commit') or '')}</code></td></tr>
<tr><th>Release tag</th><td>{h(g.get('release_tag') or '')}</td></tr>
<tr><th>Custody mode</th><td>{h(g.get('custody_mode') or '')}</td></tr>
</table>
{('<h3>Warnings</h3><ul>' + warning_rows + '</ul>') if warnings else '<p>No Application Genesis Hash warnings recorded.</p>'}
</div>"""


def build_case_report_html(data: dict[str, Any]) -> str:
    case = data.get("case") or {}
    ev_rows = "".join(f"<tr><td>#{h(e.get('id'))}</td><td>{h(e.get('filename'))}</td><td>{h(e.get('kind'))}</td><td>{h(e.get('storage_mode'))}</td><td><code>{h(e.get('sha256'))}</code></td></tr>" for e in data.get("evidence", []))
    page_rows = "".join(f"<tr><td>#{h(c.get('evidence_id'))}</td><td><a href='saved_pages/evidence_{h(c.get('evidence_id'))}.html'>{h(c.get('title') or c.get('filename') or 'Saved page')}</a></td><td>{h(c.get('capture_mode'))}</td><td>{h(c.get('page_url'))}</td></tr>" for c in data.get("page_captures", []))
    blocked_rows = "".join(f"<tr><td>#{h(b.get('id'))}</td><td>{h(b.get('resource_type'))}</td><td>{'downloaded' if b.get('downloaded') else 'not downloaded'}</td><td><code>{h(b.get('metadata_record_hash'))}</code></td><td>{h(b.get('media_url'))}</td></tr>" for b in data.get("blocked_media", []))
    genesis_block = application_genesis_html_block(data.get("application_genesis"))
    audit_warnings = "".join(f"<li>{h(w)}</li>" for w in (data.get("audit_verification", {}).get("warnings") or []))
    audit_warning_block = f"<h3>Audit warnings</h3><ul>{audit_warnings}</ul>" if audit_warnings else ""
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Case report {h(case.get('id'))}</title><style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;vertical-align:top}}code{{word-break:break-all}}.good{{color:green}}.bad{{color:#b91c1c}}.warn{{background:#fff3cd;border:1px solid #d6b656;padding:10px;margin:12px 0}}</style></head><body><h1>BlindSite case report</h1><h2>{h(case.get('name',''))}</h2><p>Generated: {h(data.get('generated_at'))}</p><p>Audit chain: <b class='{'good' if data.get('audit_verification',{}).get('ok') else 'bad'}'>{'verified' if data.get('audit_verification',{}).get('ok') else 'problem detected'}</b></p>{genesis_block}{audit_warning_block}<h2>Saved pages</h2><table><tr><th>Evidence</th><th>Offline viewer</th><th>Capture mode</th><th>Source URL</th></tr>{page_rows or '<tr><td colspan="4">No saved pages.</td></tr>'}</table><h2>Evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>Storage</th><th>SHA-256</th></tr>{ev_rows}</table><h2>Blocked media</h2><table><tr><th>ID</th><th>Type</th><th>State</th><th>Metadata hash</th><th>URL</th></tr>{blocked_rows}</table></body></html>"""


@dataclass
class CaptureOptions:
    use_tor: bool = False
    engine: str = "direct"
    capture_mode: str = "metadata_only"
    media_policy: str = "block_images_video"
    encrypt: bool = True
    download_allowed_media: bool = False
    head_probe_blocked_media: bool = True
    max_root_read_bytes: int = 524288
    max_blocked_records: int = 1000
    user_agent_profile: str = "chrome_windows"
    custom_user_agent: str = ""


def root_body_allowed(case: dict[str, Any] | None, url: str, mode: str) -> tuple[bool, str]:
    if domain_denied(url):
        return False, "host denylisted"
    if mode == "metadata_only":
        return False, "metadata-only mode"
    if case_safe(case):
        if domain_safe_allowed(url) or (case and case.get("raw_root_allowed") and mode != "full_forensic"):
            return True, "safe allowlist/raw-root policy"
        return False, "compliance-safe metadata-first policy"
    if lockdown() and mode == "full_forensic":
        return False, "global lockdown forbids raw root"
    return mode in {"safe_summary", "evidence_safe", "full_forensic"}, "mode permits root read"


def capture_direct(url: str, case_id: int | None, actor: str, options: CaptureOptions) -> dict[str, Any]:
    url = normalize_url(url)
    if domain_denied(url):
        raise HTTPException(403, "URL host is on the capture denylist")
    case = case_for(case_id)
    if case:
        if case.get("force_tor"):
            options.use_tor = True
        options.media_policy = effective_media_policy(case, options.media_policy)
        options.capture_mode = effective_capture_mode(case, options.capture_mode)
        options.download_allowed_media = options.download_allowed_media and not case_safe(case)
    safe = case_safe(case)
    ua_meta = user_agent_info(options.user_agent_profile, options.custom_user_agent)
    sess = request_session(options.use_tor, options.user_agent_profile, options.custom_user_agent)
    started = time.time()
    meta: dict[str, Any] = {"requested_url": url, "requested_url_sha256": sha256_text(url), "engine": "direct", "capture_mode": options.capture_mode, "media_policy": options.media_policy, "safe_mode": safe, "use_tor": options.use_tor, "started_at": utcnow(), "user_agent_profile": ua_meta["profile"], "user_agent_label": ua_meta["label"], "user_agent_sha256": ua_meta["user_agent_sha256"], "user_agent": ua_meta["user_agent"]}
    headers: dict[str, Any] = {}
    status_code = None
    final_url = url
    content_type = "application/json"
    payload: bytes
    raw_persisted = False
    storage_mode = "metadata_only"
    kind = "metadata"
    filename = "root_metadata.json"
    body = b""
    read_allowed, read_reason = root_body_allowed(case, url, options.capture_mode)
    try:
        if not read_allowed:
            # Open stream to get headers/status, then close without reading the body.
            r = sess.get(url, stream=True, timeout=25, allow_redirects=True)
            status_code = r.status_code
            final_url = r.url
            headers = dict(r.headers)
            r.close()
            content_type = (header_get(headers, "Content-Type") or "application/octet-stream").split(";", 1)[0]
            meta.update({"final_url": final_url, "final_url_sha256": sha256_text(final_url), "status_code": status_code, "headers": headers, "headers_sha256": header_hash(headers), "content_type": content_type, "content_length": header_get(headers, "Content-Length"), "root_body_read": False, "root_body_reason": read_reason, "network_fingerprint": network_fingerprint(final_url, options.use_tor), "elapsed_ms": int((time.time() - started) * 1000)})
            payload = pretty(meta).encode("utf-8")
        else:
            with sess.get(url, stream=True, timeout=30, allow_redirects=True) as r:
                status_code = r.status_code
                final_url = r.url
                if domain_denied(final_url):
                    raise HTTPException(403, "Final URL host is on the capture denylist")
                headers = dict(r.headers)
                content_type = (header_get(headers, "Content-Type") or "application/octet-stream").split(";", 1)[0]
                max_read = int(options.max_root_read_bytes or int(get_setting("max_root_read_bytes", "524288")))
                chunks = []
                total = 0
                for chunk in r.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_read and options.capture_mode != "full_forensic":
                        break
                body = b"".join(chunks)
            body_text = body.decode("utf-8", errors="replace") if content_type in {"text/html", "application/xhtml+xml", "text/plain"} or content_type.startswith("text/") else ""
            meta.update({"final_url": final_url, "final_url_sha256": sha256_text(final_url), "status_code": status_code, "headers": headers, "headers_sha256": header_hash(headers), "content_type": content_type, "content_length": header_get(headers, "Content-Length"), "root_body_read": True, "root_body_reason": read_reason, "root_body_bytes_read": len(body), "network_fingerprint": network_fingerprint(final_url, options.use_tor), "elapsed_ms": int((time.time() - started) * 1000)})
            inline_refs = extract_media_refs(final_url, body_text) if body_text else []
            inline_count = sum(1 for r in inline_refs if r.get("inline"))
            if safe and inline_count and setting_bool("reject_inline_media_in_safe_mode", "1"):
                meta["inline_media_rejected"] = True
                meta["inline_media_count"] = inline_count
                payload = pretty({"root_metadata": meta, "sanitized_summary": {"text": "Inline embedded media detected; root text suppressed by safe-mode policy.", "source_url_sha256": sha256_text(final_url)}, "raw_root_persisted": False}).encode("utf-8")
                storage_mode = "sanitized_summary"
                raw_persisted = False
                kind = "root_summary"
                filename = "root_safe_summary.json"
                content_type = "application/json"
            elif options.capture_mode == "full_forensic" and not safe and (case is None or case.get("raw_root_allowed") or edition() == "lab"):
                payload = body
                storage_mode = "raw_root"
                raw_persisted = True
                kind = kind_for(content_type, final_url)
                filename = Path(urlparse(final_url).path).name or "root_response" + ext_for_mime(content_type)
            else:
                summary = sanitize_html_summary(final_url, body_text) if body_text else {"binary_root_not_summarized": True, "content_type": content_type}
                payload = pretty({"root_metadata": meta, "sanitized_summary": summary, "raw_root_persisted": False}).encode("utf-8")
                storage_mode = "sanitized_summary"
                raw_persisted = False
                kind = "root_summary"
                filename = "root_safe_summary.json"
                content_type = "application/json"
    except HTTPException:
        raise
    except Exception as exc:
        meta.update({"error": str(exc), "traceback": traceback.format_exc(limit=4), "elapsed_ms": int((time.time() - started) * 1000)})
        payload = pretty(meta).encode("utf-8")
        content_type = "application/json"
        storage_mode = "capture_error_metadata"
        kind = "metadata"
        filename = "capture_error.json"
    root_id = persist_evidence(case_id=case_id, actor=actor, kind=kind, source_type="url_capture", source_ref=final_url, filename=filename, mime_type=content_type, payload=payload, encrypt=options.encrypt, storage_mode=storage_mode, raw_persisted=raw_persisted, meta=meta)
    try:
        register_page_capture(session_id=None, case_id=case_id, evidence_id=root_id, page_url=final_url, title=filename, capture_mode=storage_mode, raw_persisted=raw_persisted, meta={"engine": "direct", "capture_mode": options.capture_mode, "media_policy": options.media_policy, "use_tor": options.use_tor})
    except Exception:
        pass
    blocked_count = 0
    if body and content_type in {"text/html", "application/xhtml+xml"}:
        refs = extract_media_refs(final_url, body.decode("utf-8", errors="replace"))[: options.max_blocked_records]
        seen: set[str] = set()
        for ref in refs:
            media_url = ref["url"]
            if media_url in seen:
                continue
            seen.add(media_url)
            rtype = classify_resource(media_url, tag=ref.get("tag"))
            inline = bool(ref.get("inline"))
            if inline or policy_blocks_resource(rtype, options.media_policy):
                reason = "inline embedded media detected; no separate network body request" if inline else "blocked by media policy before body download"
                if (not inline) and policy_blocks_resource(rtype, options.media_policy):
                    _preserved_eid, recorded_bid, preserve_note = preserve_blocked_media_via_requests(actor=actor, case_id=case_id, root_evidence_id=root_id, session_id=None, page_url=final_url, media_url=media_url, resource_type=rtype, policy_name=options.media_policy, tag_type=ref.get("tag"), referrer=final_url, use_tor=options.use_tor, user_agent_profile=options.user_agent_profile, custom_user_agent=options.custom_user_agent)
                    if not recorded_bid:
                        record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_id, page_url=final_url, media_url=media_url, resource_type=rtype, tag_type=ref.get("tag"), referrer=final_url, policy=options.media_policy, reason=reason + f"; {preserve_note}", use_tor=options.use_tor, head_probe=options.head_probe_blocked_media, user_agent_profile=options.user_agent_profile, custom_user_agent=options.custom_user_agent)
                else:
                    record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_id, page_url=final_url, media_url=media_url, resource_type=rtype, tag_type=ref.get("tag"), referrer=final_url, policy=options.media_policy, reason=reason, use_tor=options.use_tor, head_probe=False, user_agent_profile=options.user_agent_profile, custom_user_agent=options.custom_user_agent)
                blocked_count += 1
            elif options.download_allowed_media and not safe and options.capture_mode == "full_forensic":
                try:
                    mr = sess.get(media_url, timeout=25)
                    mt = (header_get(dict(mr.headers), "Content-Type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0]
                    fname = Path(urlparse(media_url).path).name or f"media_{blocked_count}{ext_for_mime(mt)}"
                    child = persist_evidence(case_id=case_id, actor=actor, kind=kind_for(mt, fname), source_type="allowed_media_download", source_ref=media_url, filename=fname, mime_type=mt, payload=mr.content, encrypt=options.encrypt, parent_id=root_id, storage_mode="allowed_media_original", raw_persisted=True, meta={"parent_root": root_id, "headers": dict(mr.headers), "capture_engine": "direct"})
                    register_captured_asset(actor=actor, case_id=case_id, session_id=None, root_evidence_id=root_id, resource_evidence_id=child, original_url=media_url, resource_type=rtype, mime_type=mt, size=len(mr.content), sha256=sha256_bytes(mr.content), meta={"capture_engine": "direct", "headers": dict(mr.headers)})
                    record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_id, page_url=final_url, media_url=media_url, resource_type=rtype, tag_type=ref.get("tag"), referrer=final_url, policy=options.media_policy, reason="allowed original media downloaded by full-forensic policy", response_headers=dict(mr.headers), status_code=mr.status_code, content_type=mt, content_length=str(len(mr.content)), downloaded=True, content_sha256=sha256_bytes(mr.content), use_tor=options.use_tor, head_probe=False, user_agent_profile=options.user_agent_profile, custom_user_agent=options.custom_user_agent)
                    execute("UPDATE blocked_media SET materialized_evidence_id=? WHERE id=(SELECT max(id) FROM blocked_media)", (child,))
                except Exception as exc:
                    record_blocked_media(actor=actor, case_id=case_id, root_evidence_id=root_id, page_url=final_url, media_url=media_url, resource_type=rtype, tag_type=ref.get("tag"), referrer=final_url, policy=options.media_policy, reason=f"allowed media download failed: {exc}", use_tor=options.use_tor, head_probe=True, user_agent_profile=options.user_agent_profile, custom_user_agent=options.custom_user_agent)
    log_event(actor, "URL_CAPTURE_COMPLETED", case_id=case_id, evidence_id=root_id, details={"engine": "direct", "blocked_media": blocked_count, "raw_persisted": raw_persisted, "capture_mode": options.capture_mode, "media_policy": options.media_policy, "use_tor": options.use_tor})
    return {"root_evidence_id": root_id, "engine": "direct", "blocked_media": blocked_count, "raw_persisted": raw_persisted}




def looks_like_remote_media_candidate(url: str) -> bool:
    """Return True for URLs worth trying to preserve as remote media during capture.

    This is intentionally broader than Playwright's resource_type because Reddit and
    other dynamic sites often expose media as attributes, manifests, or script-discovered
    URLs rather than normal image/video requests.
    """
    raw = (url or "").strip()
    if not raw or raw.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return False
    try:
        p = urlparse(raw)
    except Exception:
        return False
    if p.scheme not in {"http", "https"} or not p.netloc:
        return False
    host = p.netloc.lower()
    path = p.path.lower()
    ext = Path(path).suffix
    if ext in IMAGE_EXTS or ext in VIDEO_EXTS or ext in AUDIO_EXTS:
        return True
    if any(h in host for h in ["i.redd.it", "preview.redd.it", "v.redd.it", "redditmedia.com", "redd.it", "redgifs.com", "gfycat.com"]):
        return True
    if any(x in path for x in ["/dash", "hls", "playlist", "cmaf", "mp4", "video", "media"]):
        return True
    return False


def response_body_is_xml_or_html_error(url: str, mime_type: str, body: bytes) -> bool:
    """Detect fake media downloads where a .mp4/.webm URL returned XML/HTML error text."""
    path = urlparse(url or "").path.lower()
    mt = (mime_type or "").split(";", 1)[0].lower()
    if path.endswith((".mp4", ".webm", ".mov", ".m4v")) and ("xml" in mt or "html" in mt or mt.startswith("text/")):
        return True
    head = (body or b"")[:512].lstrip().lower()
    if path.endswith((".mp4", ".webm", ".mov", ".m4v")) and head.startswith((b"<?xml", b"<error", b"<html", b"<!doctype")):
        return True
    return False


def normalize_media_response_mime(url: str, mime_type: str) -> str:
    """Normalize CDN MIME oddities for manifests, without accepting XML as video."""
    path = urlparse(url or "").path.lower()
    mt = (mime_type or "").split(";", 1)[0].strip().lower() or "application/octet-stream"
    if path.endswith(".mpd") or "dashplaylist" in path:
        return "application/dash+xml"
    if path.endswith(".m3u8") or "hlsplaylist" in path:
        return "application/vnd.apple.mpegurl"
    if path.endswith((".mp4", ".m4v")) and mt in {"application/octet-stream", "binary/octet-stream"}:
        return "video/mp4"
    return mt


def parse_dash_manifest_media_urls(manifest_url: str, body: bytes) -> list[str]:
    """Extract media BaseURL entries from a DASH MPD manifest.

    This helps avoid guessing Reddit DASH/CMAF variant names. The manifest is XML;
    XML is valid for the manifest, but not valid as a .mp4 video response.
    """
    try:
        text = body.decode("utf-8", errors="replace")
        urls: list[str] = []
        # BaseURL entries are the most useful because Reddit's MPD usually lists
        # the real audio/video object names. Keep the parser simple and dependency-free.
        for m in re.finditer(r"<BaseURL[^>]*>(.*?)</BaseURL>", text, flags=re.I | re.S):
            val = html_mod.unescape(re.sub(r"<[^>]+>", "", m.group(1)).strip())
            if val:
                urls.append(urljoin(manifest_url, val))
        # Some manifests expose SegmentTemplate media attributes.
        for m in re.finditer(r"media=[\"']([^\"']+)[\"']", text, flags=re.I):
            val = html_mod.unescape(m.group(1)).strip()
            if val and "$" not in val:
                urls.append(urljoin(manifest_url, val))
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            if u not in seen and looks_like_remote_media_candidate(u):
                seen.add(u); out.append(u)
        return out[:50]
    except Exception:
        return []


def reddit_video_variants(url: str) -> list[str]:
    """Generate likely full Reddit video URLs from a v.redd.it media URL.

    Reddit often requests tiny byte ranges or CMAF audio/video fragments first.
    If the captured DOM/performance log exposes a v.redd.it ID, these variants
    give the preservation sweep a chance to fetch complete playable assets before
    sealed export, instead of relying on reviewer remote callbacks.
    """
    raw = (url or "").strip()
    try:
        p = urlparse(raw)
    except Exception:
        return []
    if "v.redd.it" not in p.netloc.lower():
        return []
    parts = [x for x in (p.path or "").split("/") if x]
    if not parts:
        return []
    vid = parts[0]
    base = f"https://v.redd.it/{vid}/"
    names = [
        # Fetch manifests first when possible; they list the real media object names.
        "DASHPlaylist.mpd", "HLSPlaylist.m3u8",
        "DASH_1080.mp4", "DASH_720.mp4", "DASH_480.mp4", "DASH_360.mp4", "DASH_240.mp4", "DASH_96.mp4",
        "CMAF_1080.mp4", "CMAF_720.mp4", "CMAF_480.mp4", "CMAF_360.mp4", "CMAF_240.mp4", "CMAF_96.mp4",
        "m2-res_1080p.mp4", "m2-res_720p.mp4", "m2-res_640p.mp4", "m2-res_480p.mp4", "m2-res_360p.mp4",
        "DASH_AUDIO_128.mp4", "DASH_AUDIO_64.mp4", "CMAF_AUDIO_128.mp4", "CMAF_AUDIO_64.mp4",
    ]
    out = [raw]
    out.extend(base + name for name in names)
    # Keep order and remove dupes.
    seen: set[str] = set()
    deduped: list[str] = []
    for u in out:
        if u and u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def expanded_remote_media_candidates(refs: list[dict[str, Any]], source_url: str, limit: int = 800) -> list[dict[str, Any]]:
    """Expand DOM/performance media refs into URLs that should be preserved.

    The output is used only by the live capture side, never by safe viewers.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(url: str, source: str = "media-ref") -> None:
        if not url:
            return
        absu = absolute_resource_url(source_url, str(url))
        if not looks_like_remote_media_candidate(absu):
            return
        variants = reddit_video_variants(absu) or [absu]
        for vu in variants:
            if not looks_like_remote_media_candidate(vu):
                continue
            key = vu.split("#", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            kind = classify_resource(vu)
            # Manifests are video-related; keep them in the video lane so allowlist and policy can accept them.
            if Path(urlparse(vu).path.lower()).suffix in {".m3u8", ".mpd"}:
                kind = "video"
            score = 0
            host = urlparse(vu).netloc.lower()
            path = urlparse(vu).path.lower()
            if any(h in host for h in ["i.redd.it", "preview.redd.it", "v.redd.it", "redditmedia.com", "redd.it"]):
                score += 100
            if kind == "video":
                score += 80
            elif kind == "image":
                score += 50
            elif kind == "audio":
                score += 30
            if any(x in path for x in ["cmaf_audio", "dash_audio"]):
                score -= 10
            if any(x in path for x in ["cmaf_480", "dash_480", "m2-res_640", "m2-res_480", "dash_720", "cmaf_720"]):
                score += 25
            if decorative_asset_url(vu):
                score -= 50
            out.append({"url": vu, "logical": kind, "source": source, "score": score})

    for ref in refs or []:
        if not isinstance(ref, dict):
            continue
        add(str(ref.get("url") or ref.get("src") or ref.get("href") or ""), str(ref.get("tag") or ref.get("source") or "media-ref"))
    out.sort(key=lambda r: int(r.get("score") or 0), reverse=True)
    return out[:max(1, limit)]

class LiveBrowserSession:
    def __init__(self, *, session_id: str, case_id: int | None, actor: str, start_url: str, browser_choice: str, use_tor: bool, media_policy: str, headless: bool, user_agent_profile: str | None = None, custom_user_agent: str | None = None, download_allowed_media: bool = False, auto_capture: bool = False, settle_before_capture: bool = True, sealed_media_preservation_session: bool = True, capture_auto_scroll_session: bool = False, allow_captcha_challenge_media: bool = False):
        self.session_id = session_id
        self.case_id = case_id
        self.actor = actor
        self.start_url = normalize_url(start_url)
        self.browser_choice = browser_choice if browser_choice in BROWSERS else "chromium"
        self.use_tor = True if self.browser_choice in {"torbrowser", "tor_managed_chromium", "tor_managed_firefox"} else use_tor
        self.media_policy = media_policy
        self.headless = False if self.browser_choice == "torbrowser" else headless
        if self.browser_choice == "torbrowser" and (not user_agent_profile or user_agent_profile == "chrome_windows"):
            self.user_agent_profile = "tor_browser_windows" if os.name == "nt" else "tor_browser_linux"
        else:
            self.user_agent_profile = user_agent_profile or get_setting("default_user_agent_profile", "chrome_windows")
        self.custom_user_agent = custom_user_agent or ""
        self.download_allowed_media = bool(download_allowed_media) and not lockdown() and not case_safe(case_for(case_id))
        self.auto_capture = bool(auto_capture)
        self.settle_before_capture = bool(settle_before_capture)
        self.capture_auto_scroll_session = bool(capture_auto_scroll_session)
        self.allow_captcha_challenge_media = bool(allow_captcha_challenge_media)
        self.captcha_challenge_allowed = 0
        self.captcha_challenge_inline_seen: set[str] = set()
        self.sealed_media_preservation_session = bool(sealed_media_preservation_session)
        self.auto_capture_seen: set[str] = set()
        self.auto_capture_lock = threading.RLock()
        self.user_agent_meta = user_agent_info(self.user_agent_profile, self.custom_user_agent)
        self.user_agent = self.user_agent_meta["user_agent"]
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.ready = threading.Event()
        self.stop_flag = threading.Event()
        self.error: str | None = None
        self.page = None
        self.active_page = None
        self.pages: list[Any] = []
        self.tabs_snapshot_lock = threading.RLock()
        self.last_tabs_snapshot: list[dict[str, Any]] = []
        self.last_tabs_snapshot_time = 0.0
        self.context = None
        self.browser = None
        self.current_url = self.start_url
        self.requests = 0
        self.blocked = 0
        self.sealed_preserved = 0
        self.sealed_preserved_bytes = 0
        self.sealed_preserve_skipped = 0
        self.sealed_preserve_timeout_count = 0
        self.sealed_preserve_bg_tasks: set[Any] = set()
        self.sealed_preserve_cancel_requested = threading.Event()
        self.sealed_preserve_cancelled = 0
        self.sealed_preserve_lock = threading.RLock()
        self.deferred_blocked_media: list[dict[str, Any]] = []
        self.deferred_blocked_seen: set[str] = set()
        self.deferred_blocked_lock = threading.RLock()
        self.deferred_blocked_flushed = 0
        self.deferred_blocked_dropped = 0
        self.sealed_media_policy_cache = sealed_media_preservation_policy(case_for(case_id))
        self.preserve_mode = sealed_media_preserve_mode()
        self.preserve_skip_decorative_fast = setting_bool("sealed_media_preserve_skip_decorative_fast", "1")
        self.sealed_preserve_max_pending_tasks = safe_int(get_setting("sealed_media_preserve_max_pending_tasks", "75"), 75, min_value=1, max_value=1000)
        self.deferred_blocked_max = safe_int(get_setting("max_blocked_records", "1000"), 1000, min_value=100, max_value=20000)
        self.log_live_responses = setting_bool("live_response_logging", "0")
        self.log_blocked_browser_events = setting_bool("live_blocked_event_logging", "0")
        self.asset_cache: dict[str, dict[str, Any]] = {}
        self.asset_bytes_total = 0
        self.asset_skipped = 0
        self.asset_lock = threading.RLock()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._thread_main, daemon=True, name=f"live-browser-{self.session_id}")
        self.thread.start()
        self.ready.wait(timeout=20)
        if self.error:
            raise HTTPException(500, self.error)

    def _thread_main(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._run())
        finally:
            try:
                self.loop.close()
            except Exception:
                pass

    async def _run(self) -> None:
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception as exc:
            self.error = "Playwright is not installed or browser binaries are missing. Run: python BlindSite.py --install-browsers"
            execute("UPDATE browser_sessions SET status='error', meta_json=? WHERE session_id=?", (pretty({"error": self.error, "exception": str(exc)}), self.session_id))
            self.ready.set()
            return
        try:
            async with async_playwright() as pw:
                effective_choice = self.browser_choice
                if effective_choice == "tor_managed_chromium":
                    effective_choice = "chromium"
                    self.use_tor = True
                elif effective_choice == "tor_managed_firefox":
                    effective_choice = "firefox"
                    self.use_tor = True
                if effective_choice in {"chrome", "msedge"}:
                    launch_type = pw.chromium
                    kwargs: dict[str, Any] = {"channel": effective_choice, "headless": self.headless}
                elif effective_choice == "firefox":
                    launch_type = pw.firefox
                    kwargs = {"headless": self.headless}
                elif effective_choice == "torbrowser":
                    launch_type = pw.firefox
                    tor_path = detect_tor_browser_executable()
                    if not tor_path:
                        self.error = "Tor Browser executable not found. Set Tor Browser path in Settings, for example C:\\Users\\<you>\\Desktop\\Tor Browser\\Browser\\firefox.exe"
                        execute("UPDATE browser_sessions SET status='error', meta_json=? WHERE session_id=?", (pretty({"error": self.error, "browser_choice": self.browser_choice}), self.session_id))
                        self.ready.set()
                        return
                    kwargs = {"headless": False, "executable_path": str(tor_path)}
                    self.headless = False
                    self.use_tor = True
                else:
                    launch_type = pw.chromium
                    kwargs = {"headless": self.headless}
                if self.use_tor or (self.browser_choice == "torbrowser" and setting_bool("tor_browser_force_socks", "1")):
                    ok, tor_msg = ensure_tor_proxy_ready()
                    if not ok:
                        self.error = "Tor route requested, but Tor was not ready: " + tor_msg
                        execute("UPDATE browser_sessions SET status='error', meta_json=? WHERE session_id=?", (pretty({"error": self.error, "browser_choice": self.browser_choice}), self.session_id))
                        self.ready.set()
                        return
                    kwargs["proxy"] = {"server": f"socks5://{get_setting('tor_host','127.0.0.1')}:{get_setting('tor_socks_port','9050')}"}
                self.browser = await launch_type.launch(**kwargs)
                self.context = await self.browser.new_context(
                    ignore_https_errors=False,
                    java_script_enabled=setting_bool("live_javascript_enabled", "1"),
                    viewport={"width": 1365, "height": 900},
                    user_agent=self.user_agent,
                    bypass_csp=False,
                )
                if self.allow_captcha_challenge_media:
                    try:
                        await self.context.expose_binding("__blindsiteCaptchaChallengeAllowed", self._record_captcha_challenge_allowed_from_browser)
                    except Exception:
                        pass
                # Extra visual block for inline SVG/CSS background/media elements that do not create separate network image requests.
                # Network requests are still handled by the route layer; this prevents inline/data/cached SVG/images from flashing before route aborts land.
                # The short documentElement boot veil is intentionally used only when a media-blocking policy is active.
                visual_selectors: list[str] = []
                css_bits: list[str] = []
                if policy_blocks_resource("image", self.media_policy):
                    captcha_exempt = ":not([data-blindsite-captcha-allow='1'])" if self.allow_captcha_challenge_media else ""
                    visual_selectors.extend([
                        f"img{captcha_exempt}", f"picture{captcha_exempt}", f"svg{captcha_exempt}", f"canvas{captcha_exempt}",
                        f"object[type^='image/']{captcha_exempt}", f"object[data$='.svg' i]{captcha_exempt}", f"object[data*='.svg?' i]{captcha_exempt}", f"object[data*='.svg#' i]{captcha_exempt}",
                        f"embed[type^='image/']{captcha_exempt}", f"embed[src$='.svg' i]{captcha_exempt}", f"embed[src*='.svg?' i]{captcha_exempt}", f"embed[src*='.svg#' i]{captcha_exempt}",
                        f"iframe[src$='.svg' i]{captcha_exempt}", f"iframe[src*='.svg?' i]{captcha_exempt}", f"iframe[src*='.svg#' i]{captcha_exempt}",
                        f"[role='img']{captcha_exempt}",
                    ])
                    if self.allow_captcha_challenge_media:
                        css_bits.append("*:not([data-blindsite-captcha-allow='1']),*:not([data-blindsite-captcha-allow='1'])::before,*:not([data-blindsite-captcha-allow='1'])::after{background-image:none!important;list-style-image:none!important;border-image-source:none!important;-webkit-mask-image:none!important;mask-image:none!important;}")
                    else:
                        css_bits.append("*,*::before,*::after{background-image:none!important;list-style-image:none!important;border-image-source:none!important;-webkit-mask-image:none!important;mask-image:none!important;}")
                if policy_blocks_resource("video", self.media_policy):
                    visual_selectors.append("video")
                if policy_blocks_resource("audio", self.media_policy):
                    visual_selectors.append("audio")
                if visual_selectors:
                    css_bits.insert(0, ",".join(visual_selectors) + "{display:none!important;visibility:hidden!important;opacity:0!important;filter:none!important;background-image:none!important;}")
                    # This selector only applies during the first instant before our block CSS is installed.
                    # It prevents cached/inline images from painting for a frame and is removed immediately after install.
                    css_bits.insert(0, "html[data-blindsite-media-boot='1']{visibility:hidden!important;background:#fff!important;}")
                    css = "\n".join(css_bits)
                    js = """(() => {
  const css = %s;
  const allowCaptchaChallengeMedia = %s;
  const CAPTCHA_HOST_PATTERNS = %s;
  const CAPTCHA_PATH_PATTERNS = %s;
  const STYLE_ID = '__blindsite_live_media_block_css';
  let releasedBoot = false;
  function root(){ return document.documentElement || document.querySelector('html'); }
  const CAPTCHA_CONTEXT_PATTERNS = %s;
  function blindSiteCaptchaTextHit(text){
    text = String(text || '').toLowerCase();
    if (!text) return false;
    return CAPTCHA_PATH_PATTERNS.some(p => text.includes(p)) || CAPTCHA_CONTEXT_PATTERNS.some(p => text.includes(p));
  }
  function blindSiteCaptchaUrl(raw){
    try {
      if (!allowCaptchaChallengeMedia || !raw || typeof raw !== 'string') return false;
      const trimmed = raw.trim();
      if (trimmed.toLowerCase().startsWith('data:image/')) return false;
      const u = new URL(trimmed, location.href);
      const host = (u.hostname || '').toLowerCase();
      const text = (host + ' ' + decodeURIComponent(u.pathname || '') + ' ' + decodeURIComponent(u.search || '')).toLowerCase();
      if ((host.endsWith('google.com') || host.endsWith('gstatic.com') || host.endsWith('googleusercontent.com')) && !(text.includes('recaptcha') || text.includes('captcha') || text.includes('api2/payload'))) return false;
      return CAPTCHA_HOST_PATTERNS.some(p => host.includes(p)) || blindSiteCaptchaTextHit(text);
    } catch(e) { return false; }
  }
  const ORDINARY_INLINE_MEDIA_PATTERNS = ["logo", "avatar", "banner", "background", "favicon", "icon", "sprite", "decorative", "thumbnail", "profile", "advertisement", " ad "];
  function blindSiteHasOrdinaryInlineMediaHint(text){
    text = (' ' + String(text || '').toLowerCase() + ' ');
    if (!text.trim()) return false;
    return ORDINARY_INLINE_MEDIA_PATTERNS.some(p => text.includes(p));
  }
  function blindSiteAttrsText(el, attrs){
    const bits = [];
    if (!el) return '';
    for (const a of attrs) {
      try {
        const v = (a === 'className' ? el.className : el.getAttribute && el.getAttribute(a)) || '';
        if (v && typeof v === 'string') bits.push(v);
      } catch(e) {}
    }
    return bits.join(' ').toLowerCase();
  }
  function blindSiteCaptchaContext(el){
    // Full context is retained for logging/reconstruction only. It must not be
    // the sole reason to allow inline data:image elements because broad page
    // text like "captcha" can contaminate ordinary logo/avatar images.
    const bits = [];
    try {
      let cur = el;
      for (let depth = 0; cur && depth < 5; depth++, cur = cur.parentElement) {
        bits.push(blindSiteAttrsText(cur, ['id','class','className','name','alt','title','aria-label','placeholder','href','action','type','role','value']));
        try { const txt = (cur.innerText || cur.textContent || '').replace(/\\s+/g, ' ').trim(); if (txt) bits.push(txt.slice(0, 500)); } catch(e) {}
      }
      try {
        const form = el.closest && el.closest('form');
        if (form) {
          bits.push(form.getAttribute('action') || '');
          bits.push((form.innerText || form.textContent || '').replace(/\\s+/g, ' ').slice(0, 700));
          for (const input of Array.from(form.querySelectorAll('input,button,label,code,h1,h2,h3,h4,h5,span')).slice(0, 80)) {
            bits.push(blindSiteAttrsText(input, ['name','id','class','placeholder','alt','title','value','type','role']));
            const t = (input.innerText || input.textContent || '').replace(/\\s+/g, ' ').trim();
            if (t) bits.push(t);
          }
        }
      } catch(e) {}
    } catch(e) {}
    return bits.join(' ').toLowerCase();
  }
  function blindSiteInlineElementContext(el){
    // Narrow context used for the inline/base64 allow decision: element attrs
    // plus close clickable/label ancestors only, not the entire body/page.
    const bits = [];
    try {
      bits.push(blindSiteAttrsText(el, ['id','class','className','name','alt','title','aria-label','placeholder','type','role','value']));
      let cur = el ? el.parentElement : null;
      for (let depth = 0; cur && depth < 3; depth++, cur = cur.parentElement) {
        bits.push(blindSiteAttrsText(cur, ['id','class','className','name','title','aria-label','href','action','type','role','value']));
        const tag = (cur.tagName || '').toLowerCase();
        if (['a','button','label','code','span','h1','h2','h3','h4','h5'].includes(tag)) {
          const t = (cur.innerText || cur.textContent || '').replace(/\\s+/g, ' ').trim();
          if (t && t.length <= 300) bits.push(t);
        }
      }
    } catch(e) {}
    return bits.join(' ').toLowerCase();
  }
  function blindSiteInlineFormContext(el){
    const bits = [];
    try {
      const form = el.closest && el.closest('form');
      if (!form) return '';
      bits.push(blindSiteAttrsText(form, ['id','class','className','name','title','aria-label','action','role']));
      const formText = (form.innerText || form.textContent || '').replace(/\\s+/g, ' ').trim();
      if (formText) bits.push(formText.slice(0, 600));
      for (const input of Array.from(form.querySelectorAll('input,button,label,code,h1,h2,h3,h4,h5,span')).slice(0, 80)) {
        bits.push(blindSiteAttrsText(input, ['name','id','class','placeholder','alt','title','value','type','role']));
        const t = (input.innerText || input.textContent || '').replace(/\\s+/g, ' ').trim();
        if (t) bits.push(t.slice(0, 160));
      }
    } catch(e) {}
    return bits.join(' ').toLowerCase();
  }
  function blindSiteInlineFormHasSingleDataImage(el){
    try {
      const form = el.closest && el.closest('form');
      if (!form) return false;
      const dataImages = Array.from(form.querySelectorAll('img,source')).filter(n => String((n.currentSrc || n.getAttribute('src') || '')).trim().toLowerCase().startsWith('data:image/'));
      return dataImages.length === 1 && (dataImages[0] === el || dataImages[0].contains(el) || el.contains(dataImages[0]));
    } catch(e) { return false; }
  }
  function blindSiteCaptchaInlineDataImage(el, src, context){
    try {
      if (!allowCaptchaChallengeMedia || !src || typeof src !== 'string') return false;
      const raw = src.trim().toLowerCase();
      if (!raw.startsWith('data:image/')) return false;
      const direct = blindSiteInlineElementContext(el);
      const formCtx = blindSiteInlineFormContext(el);
      const directHit = blindSiteCaptchaTextHit(direct);
      const formHit = blindSiteCaptchaTextHit(formCtx);
      const ordinaryHint = blindSiteHasOrdinaryInlineMediaHint(direct);
      if (ordinaryHint && !directHit) return false;
      // Direct local CAPTCHA evidence is enough. Form-wide CAPTCHA text is only
      // a fallback when this is the sole inline data image in the form; otherwise
      // a CAPTCHA form could accidentally whitelist ordinary inline logos/avatars.
      return directHit || (formHit && blindSiteInlineFormHasSingleDataImage(el));
    } catch(e) { return false; }
  }
  function blindSiteReportCaptchaAllow(el, src, reason, context){
    try {
      if (el.getAttribute('data-blindsite-captcha-reported') === '1') return;
      el.setAttribute('data-blindsite-captcha-reported', '1');
      const isData = String(src || '').trim().toLowerCase().startsWith('data:image/');
      const payload = {
        page_url: location.href,
        tag: (el.tagName || '').toLowerCase(),
        id: el.getAttribute('id') || '',
        class_name: String(el.getAttribute('class') || ''),
        name: el.getAttribute('name') || '',
        alt: el.getAttribute('alt') || '',
        title: el.getAttribute('title') || '',
        role: el.getAttribute('role') || '',
        reason: reason || 'captcha/challenge image allowed',
        src_kind: isData ? 'inline_data_image' : 'network_or_relative_image',
        src: isData && src.length <= 300000 ? src : '',
        src_prefix: String(src || '').slice(0, 96),
        src_length: String(src || '').length,
        context_text: String(context || '').slice(0, 700)
      };
      if (window.__blindsiteCaptchaChallengeAllowed) window.__blindsiteCaptchaChallengeAllowed(payload).catch(() => {});
    } catch(e) {}
  }
  function blindSiteMarkCaptchaNodes(){
    if (!allowCaptchaChallengeMedia) return;
    try {
      const attrs = ['src','currentSrc','poster','data-src','data-lazy-src','data-original','data-url','data-blindsite-src'];
      const nodes = Array.from(document.querySelectorAll('img,picture,source,svg,canvas,object,embed,iframe,[role="img"],[style]'));
      for (const el of nodes) {
        let matched = false;
        let matchedSrc = '';
        let matchedReason = '';
        const context = blindSiteCaptchaContext(el);
        for (const a of attrs) {
          let v = '';
          try { v = (a === 'currentSrc' ? el.currentSrc : el.getAttribute(a)) || ''; } catch(e) { v = ''; }
          if (blindSiteCaptchaUrl(v)) { matched = true; matchedSrc = v; matchedReason = 'captcha/challenge URL pattern'; break; }
          if (blindSiteCaptchaInlineDataImage(el, v, context)) { matched = true; matchedSrc = v; matchedReason = 'inline data:image CAPTCHA/challenge context'; break; }
        }
        try {
          const ss = el.getAttribute('srcset') || el.getAttribute('data-srcset') || '';
          if (!matched && ss) {
            for (const part of ss.split(',')) {
              const candidate = (part.trim().split(/\\s+/)[0] || '');
              if (blindSiteCaptchaUrl(candidate) || blindSiteCaptchaInlineDataImage(el, candidate, context)) { matched = true; matchedSrc = candidate; matchedReason = 'captcha/challenge srcset/context'; break; }
            }
          }
        } catch(e) {}
        try {
          const style = el.getAttribute('style') || '';
          if (!matched && style) {
            for (const m of style.matchAll(/url\\((['"]?)(.*?)\\1\\)/g)) {
              if (blindSiteCaptchaUrl(m[2]) || blindSiteCaptchaInlineDataImage(el, m[2], context)) { matched = true; matchedSrc = m[2]; matchedReason = 'captcha/challenge CSS-url/context'; break; }
            }
          }
        } catch(e) {}
        if (matched) {
          el.setAttribute('data-blindsite-captcha-allow', '1');
          if (el.parentElement && el.parentElement.tagName && el.parentElement.tagName.toLowerCase() === 'picture') el.parentElement.setAttribute('data-blindsite-captcha-allow', '1');
          blindSiteReportCaptchaAllow(el, matchedSrc, matchedReason, context);
        }
      }
    } catch(e) {}
  }
  function bootVeil(){
    try { const r = root(); if (r && !releasedBoot) r.setAttribute('data-blindsite-media-boot', '1'); } catch(e) {}
  }
  function releaseBoot(){
    try { releasedBoot = true; const r = root(); if (r) r.removeAttribute('data-blindsite-media-boot'); } catch(e) {}
  }
  function applyBlindSiteMediaBlock(){
    try {
      blindSiteMarkCaptchaNodes();
      const r = root();
      if (!r) return false;
      let style = document.getElementById(STYLE_ID);
      if (!style) {
        style = document.createElement('style');
        style.id = STYLE_ID;
        style.type = 'text/css';
        style.setAttribute('data-blindsite', 'live-media-block');
        (document.head || r).appendChild(style);
      }
      if (style.textContent !== css) style.textContent = css;
      return true;
    } catch(e) { return false; }
  }
  function installThenRelease(){
    bootVeil();
    if (applyBlindSiteMediaBlock()) {
      try { requestAnimationFrame(() => setTimeout(releaseBoot, 0)); } catch(e) { setTimeout(releaseBoot, 0); }
    } else {
      setTimeout(installThenRelease, 5);
    }
  }
  installThenRelease();
  document.addEventListener('DOMContentLoaded', () => { applyBlindSiteMediaBlock(); releaseBoot(); }, {once:false});
  try { new MutationObserver(applyBlindSiteMediaBlock).observe(document.documentElement, {childList:true, subtree:true}); } catch(e) {}
  // Some hostile/dynamic pages remove injected styles; keep the block rule installed without doing heavy DOM work.
  let ticks = 0;
  const fastTimer = setInterval(() => { applyBlindSiteMediaBlock(); if (++ticks > 80) clearInterval(fastTimer); }, 25);
  setInterval(applyBlindSiteMediaBlock, 1000);
  setTimeout(releaseBoot, 1500);
})();""" % (json.dumps(css), json.dumps(bool(self.allow_captcha_challenge_media)), json.dumps(CAPTCHA_CHALLENGE_HOST_PATTERNS), json.dumps(CAPTCHA_CHALLENGE_PATH_PATTERNS), json.dumps(CAPTCHA_CHALLENGE_INLINE_CONTEXT_PATTERNS))
                    await self.context.add_init_script(js)
                await self.context.route("**/*", self._route)
                self.context.on("page", self._on_new_page)
                self.page = await self.context.new_page()
                await self._register_page(self.page, reason="initial")
                execute("UPDATE browser_sessions SET status='running' WHERE session_id=?", (self.session_id,))
                log_event(self.actor, "LIVE_SESSION_STARTED", case_id=self.case_id, session_id=self.session_id, details={"browser": self.browser_choice, "use_tor": self.use_tor, "media_policy": self.media_policy, "headless": self.headless, "download_allowed_media": self.download_allowed_media, "sealed_media_preservation": self.sealed_media_policy_cache, "allow_captcha_challenge_media": self.allow_captcha_challenge_media, "user_agent_profile": self.user_agent_meta.get("profile"), "user_agent_sha256": self.user_agent_meta.get("user_agent_sha256")})
                self.ready.set()
                try:
                    await self.page.goto(self.start_url, wait_until="domcontentloaded", timeout=int(get_setting("live_initial_navigation_timeout_ms", "60000") or "60000"))
                except Exception as exc:
                    self.error = str(exc)
                    execute("UPDATE browser_sessions SET meta_json=? WHERE session_id=?", (pretty({"initial_navigation_warning": str(exc)}), self.session_id))
                while not self.stop_flag.is_set():
                    await asyncio.sleep(0.4)
                try:
                    await self._flush_deferred_blocked_media(root_evidence_id=None, page_url=self.current_url)
                except Exception:
                    pass
                try:
                    await self.context.close()
                except Exception:
                    pass
                try:
                    await self.browser.close()
                except Exception:
                    pass
                execute("UPDATE browser_sessions SET status='stopped', stopped_at=? WHERE session_id=?", (utcnow(), self.session_id))
                log_event(self.actor, "LIVE_SESSION_STOPPED", case_id=self.case_id, session_id=self.session_id, details={"requests": self.requests, "blocked": self.blocked, "sealed_preserved": self.sealed_preserved, "sealed_preserved_bytes": self.sealed_preserved_bytes, "sealed_preserve_skipped": self.sealed_preserve_skipped, "current_url": self.current_url, "sealed_preserve_timeouts": self.sealed_preserve_timeout_count, "sealed_preserve_pending": len(self.sealed_preserve_bg_tasks), "captcha_challenge_allowed": self.captcha_challenge_allowed})
        except Exception as exc:
            self.error = str(exc)
            self.ready.set()
            execute("UPDATE browser_sessions SET status='error', meta_json=? WHERE session_id=?", (pretty({"error": str(exc), "traceback": traceback.format_exc(limit=8)}), self.session_id))
            log_event(self.actor, "LIVE_SESSION_ERROR", case_id=self.case_id, session_id=self.session_id, details={"error": str(exc)})

    async def _register_page(self, page, *, reason: str = "") -> None:
        """Track a Playwright tab/page so manual capture can include more than tab #1."""
        if page is None:
            return
        try:
            new_page = page not in self.pages
            if new_page:
                self.pages.append(page)
                page.on("framenavigated", lambda frame, p=page: self._on_frame_nav(p, frame))
                page.on("response", self._on_response)
                try:
                    page.on("close", lambda p=page: self._on_page_close(p))
                except Exception:
                    pass
            self.page = page
            self.active_page = page
            try:
                self.current_url = page.url or self.current_url
                execute("UPDATE browser_sessions SET current_url=? WHERE session_id=?", (self.current_url, self.session_id))
            except Exception:
                pass
            if new_page:
                execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "tab_tracked", getattr(page, "url", "") or "", "document", "GET", None, "{}", header_hash({}), pretty({"reason": reason, "tracked_tabs": len(self.pages)})))
        except Exception:
            pass

    def _on_new_page(self, page) -> None:
        try:
            if self.loop:
                asyncio.run_coroutine_threadsafe(self._register_page(page, reason="new_tab_or_popup"), self.loop)
        except Exception:
            pass

    def _on_page_close(self, page=None) -> None:
        try:
            self.pages = [p for p in self.pages if p != page and not getattr(p, "is_closed", lambda: False)()]
            if self.page == page or self.active_page == page:
                self.page = self.pages[-1] if self.pages else None
                self.active_page = self.page
                try:
                    if self.page is not None:
                        self.current_url = self.page.url or self.current_url
                except Exception:
                    pass
        except Exception:
            pass

    def _live_pages_snapshot(self) -> list[Any]:
        out = []
        candidates = list(self.pages)
        try:
            if self.context is not None:
                for p in list(getattr(self.context, "pages", []) or []):
                    if p not in candidates:
                        candidates.append(p)
        except Exception:
            pass
        if self.page is not None and self.page not in candidates:
            candidates.append(self.page)
        if self.active_page is not None and self.active_page not in candidates:
            candidates.append(self.active_page)
        for p in candidates:
            try:
                if not p.is_closed() and p not in out:
                    out.append(p)
            except Exception:
                pass
        # During active navigation, Playwright can briefly report/throw in a way
        # that makes a poll look like there are zero pages. Do not wipe the
        # tracked page object list on that transient empty read; the tab-status
        # UI also keeps a last-known-good snapshot to prevent blinking.
        if out or not candidates or self.stop_flag.is_set():
            self.pages = out
        return out

    def _cache_asset_response(self, *, url: str, resource_type: str, status_code: int | None, headers: dict[str, Any], body: bytes) -> None:
        if not body:
            return
        try:
            max_items = int(get_setting("snapshot_max_media_items", "250") or "250")
            max_each = int(get_setting("snapshot_max_media_bytes", "52428800") or "52428800")
            max_total = int(get_setting("snapshot_max_total_asset_bytes", "209715200") or "209715200")
        except Exception:
            max_items, max_each, max_total = 250, 52428800, 209715200
        if len(body) > max_each:
            self.asset_skipped += 1
            return
        with self.asset_lock:
            if url in self.asset_cache:
                return
            if len(self.asset_cache) >= max_items or self.asset_bytes_total + len(body) > max_total:
                self.asset_skipped += 1
                return
            mime = (header_get(headers, "Content-Type") or mimetypes.guess_type(url)[0] or "application/octet-stream").split(";", 1)[0].strip()
            fname = clean_filename(Path(urlparse(url).path).name or f"asset_{len(self.asset_cache)+1}{ext_for_mime(mime)}")
            self.asset_cache[url] = {
                "url": url,
                "url_sha256": sha256_text(url),
                "resource_type": classify_resource(url, mime_type=mime, browser_type=resource_type),
                "browser_resource_type": resource_type,
                "status_code": status_code,
                "headers": dict(headers or {}),
                "header_sha256": header_hash(headers),
                "mime_type": mime,
                "filename": fname,
                "sha256": sha256_bytes(body),
                "size": len(body),
                "body": body,
                "captured_at": utcnow(),
            }
            self.asset_bytes_total += len(body)

    async def _capture_allowed_asset_via_route(self, route, request) -> bool:
        if not self.download_allowed_media:
            return False
        if case_safe(case_for(self.case_id)) or lockdown():
            return False
        rt = (request.resource_type or "").lower()
        if rt not in ARCHIVABLE_BROWSER_RESOURCE_TYPES:
            return False
        if live_policy_blocks(rt, self.media_policy, request.url):
            return False
        try:
            response = await route.fetch(timeout=preserve_timeout_for(rt, request.url), headers=cleaned_preserve_headers(dict(request.headers or {}), fallback_user_agent=self.user_agent, referer=self.current_url))
            body = await response.body()
            headers = dict(response.headers or {})
            self._cache_asset_response(url=request.url, resource_type=rt, status_code=getattr(response, "status", None), headers=headers, body=body)
            execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "captured_allowed_asset", request.url, classify_resource(request.url, mime_type=header_get(headers, "Content-Type"), browser_type=rt), request.method, getattr(response, "status", None), json.dumps(headers, ensure_ascii=False), header_hash(headers), pretty({"cached_bytes": len(body), "url_sha256": sha256_text(request.url)})))
            await route.fulfill(response=response)
            return True
        except Exception as exc:
            try:
                execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "allowed_asset_capture_failed", request.url, rt, request.method, None, "{}", header_hash({}), pretty({"error": str(exc)[:500]})))
            except Exception:
                pass
            return False

    def _sealed_preserve_limits_ok(self, pol: dict[str, Any]) -> tuple[bool, str]:
        if pol.get("max_items_per_session") and self.sealed_preserved >= int(pol.get("max_items_per_session") or 0):
            self.sealed_preserve_skipped += 1
            return False, "sealed preservation skipped: per-session item limit reached"
        if pol.get("max_total_bytes") and self.sealed_preserved_bytes >= int(pol.get("max_total_bytes") or 0):
            self.sealed_preserve_skipped += 1
            return False, "sealed preservation skipped: per-session byte limit reached"
        max_pending = safe_int(get_setting("sealed_media_preserve_max_pending_tasks", "75"), 75, min_value=1, max_value=1000)
        if len(self.sealed_preserve_bg_tasks) >= max_pending:
            self.sealed_preserve_skipped += 1
            return False, f"sealed preservation skipped: background queue full ({len(self.sealed_preserve_bg_tasks)} >= {max_pending})"
        return True, "ok"

    def _download_preserved_media_requests(self, media_url: str, headers: dict[str, str], timeout_ms: int, max_each: int) -> dict[str, Any]:
        # Preserve the whole object, not a browser-requested byte range. Reddit and
        # similar video players often request tiny CMAF/Range fragments first; if
        # we store only that partial response, the reviewer sees a small MP4 that
        # cannot play. Strip Range here too so retries of older rows are full fetches.
        headers = dict(headers or {})
        for rk in ["range", "Range"]:
            headers.pop(rk, None)
        sess = request_session(self.use_tor, self.user_agent_profile, self.custom_user_agent)
        sess.headers.clear()
        sess.headers.update(headers)
        timeout_s = max(1.0, float(timeout_ms) / 1000.0)
        started = time.time()
        with sess.get(media_url, stream=True, timeout=(min(8.0, timeout_s), timeout_s), allow_redirects=True) as r:
            response_headers = dict(r.headers or {})
            mt = normalize_media_response_mime(media_url, (header_get(response_headers, "Content-Type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream"))
            content_len_raw = header_get(response_headers, "Content-Length")
            content_len = safe_int(content_len_raw, -1, min_value=-1) if content_len_raw not in (None, "") else None
            ok2, why2, pol2 = sealed_media_preservation_allowed(self.case_id, url=media_url, resource_type=classify_resource(media_url, mime_type=mt), mime_type=mt, content_length=content_len)
            if not ok2:
                return {"ok": False, "reason": why2, "headers": response_headers, "status_code": r.status_code, "mime_type": mt, "content_length": content_len_raw or ""}
            chunks: list[bytes] = []
            total = 0
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if max_each and total > max_each:
                    return {"ok": False, "reason": f"sealed preservation skipped: response exceeded per-file limit ({total} > {max_each})", "headers": response_headers, "status_code": r.status_code, "mime_type": mt, "content_length": str(total)}
            body = b"".join(chunks)
            if body and response_body_is_xml_or_html_error(media_url, mt, body):
                return {"ok": False, "reason": "server returned XML/HTML error instead of playable media", "headers": response_headers, "status_code": r.status_code, "mime_type": mt, "content_length": str(len(body)), "final_url": r.url, "elapsed_ms": int((time.time() - started) * 1000)}
            manifest_urls = parse_dash_manifest_media_urls(r.url or media_url, body) if body and mt == "application/dash+xml" else []
            return {"ok": bool(body), "reason": "ok" if body else "sealed preservation skipped: empty response body", "headers": response_headers, "status_code": r.status_code, "mime_type": mt, "content_length": str(len(body)), "body": body, "final_url": r.url, "elapsed_ms": int((time.time() - started) * 1000), "manifest_media_urls": manifest_urls}

    async def _preserve_blocked_media_background(self, *, blocked_media_id: int, media_url: str, logical: str, method: str, req_headers: dict[str, Any], page_url: str, referrer: str) -> None:
        try:
            ok, why, pol = sealed_media_preservation_allowed(self.case_id, url=media_url, resource_type=logical)
            if not ok:
                execute("UPDATE blocked_media SET reason=? WHERE id=?", (why, blocked_media_id))
                return
            max_each = int(pol.get("max_each_bytes") or 0)
            max_total = int(pol.get("max_total_bytes") or 0)
            if max_total and self.sealed_preserved_bytes >= max_total:
                execute("UPDATE blocked_media SET reason=? WHERE id=?", ("sealed preservation skipped: per-session byte limit reached", blocked_media_id))
                return
            headers = cleaned_preserve_headers(req_headers, fallback_user_agent=self.user_agent, referer=referrer or page_url)
            # Carry browser cookies into the background fetch when available. This improves
            # preservation for authenticated/chat/media pages without keeping the original
            # Playwright route open.
            try:
                if self.context is not None and "cookie" not in headers:
                    cookies = await self.context.cookies([media_url])
                    cookie_header = "; ".join(f"{c.get('name')}={c.get('value')}" for c in cookies if c.get("name"))
                    if cookie_header:
                        headers["cookie"] = cookie_header
            except Exception:
                pass
            timeout_ms = preserve_timeout_for(logical, media_url, background=True)
            result = await asyncio.to_thread(self._download_preserved_media_requests, media_url, headers, timeout_ms, max_each)
            response_headers = dict(result.get("headers") or {})
            mt = str(result.get("mime_type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0].strip()
            status_code = result.get("status_code")
            if not result.get("ok"):
                self.sealed_preserve_skipped += 1
                reason = str(result.get("reason") or "sealed preservation failed/skipped in background")[:500]
                execute("""UPDATE blocked_media SET reason=?, status_code=?, content_type=?, content_length=?, headers_json=?, header_sha256=? WHERE id=?""", (reason, status_code, mt, str(result.get("content_length") or ""), json.dumps(response_headers, ensure_ascii=False), header_hash(response_headers), blocked_media_id))
                log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVE_SKIPPED", case_id=self.case_id, blocked_media_id=blocked_media_id, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical, "reason": reason})
                return
            body = result.get("body") or b""
            if not isinstance(body, bytes) or not body:
                self.sealed_preserve_skipped += 1
                execute("UPDATE blocked_media SET reason=? WHERE id=?", ("sealed preservation skipped: empty response body", blocked_media_id))
                return
            if max_total and self.sealed_preserved_bytes + len(body) > max_total:
                self.sealed_preserve_skipped += 1
                reason = f"sealed preservation skipped: session byte limit would be exceeded ({self.sealed_preserved_bytes + len(body)} > {max_total})"
                execute("UPDATE blocked_media SET reason=?, content_length=? WHERE id=?", (reason, str(len(body)), blocked_media_id))
                return
            logical2 = media_kind_from_resource(url=media_url, resource_type=logical, mime_type=mt, browser_resource_type=logical)
            eid = persist_sealed_preserved_media(actor=self.actor, case_id=self.case_id, session_id=self.session_id, root_evidence_id=None, page_url=page_url, media_url=media_url, resource_type=logical2, mime_type=mt, payload=body, request_method=method + "+sealed-preserve-bg", referrer=referrer or page_url, request_headers=headers, response_headers=response_headers, status_code=status_code, reason="blocked from local display by live browser; background encrypted preservation for sealed reviewer handoff", source_engine="live_browser_background", final_url=str(result.get("final_url") or media_url))
            execute("""UPDATE blocked_media SET downloaded=1, materialized_evidence_id=?, reason=?, status_code=?, content_type=?, content_length=?, headers_json=?, header_sha256=?, content_sha256=? WHERE id=?""", (eid, "blocked from local display by live browser; background encrypted preservation complete", status_code, mt, str(len(body)), json.dumps(response_headers, ensure_ascii=False), header_hash(response_headers), sha256_bytes(body), blocked_media_id))
            self.sealed_preserved += 1
            self.sealed_preserved_bytes += len(body)
            log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVED_BACKGROUND", case_id=self.case_id, evidence_id=eid, blocked_media_id=blocked_media_id, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical2, "size": len(body), "elapsed_ms": result.get("elapsed_ms")})
        except Exception as exc:
            self.sealed_preserve_skipped += 1
            if "timeout" in str(exc).lower():
                self.sealed_preserve_timeout_count += 1
            reason = f"sealed preservation failed in background: {str(exc)[:450]}"
            try:
                execute("UPDATE blocked_media SET reason=? WHERE id=?", (reason, blocked_media_id))
            except Exception:
                pass
            log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVE_FAILED", case_id=self.case_id, blocked_media_id=blocked_media_id, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical, "error": str(exc)[:500]})

    async def _drain_sealed_preservation_tasks(self, max_wait_ms: int | None = None) -> dict[str, Any]:
        tasks = [t for t in list(self.sealed_preserve_bg_tasks) if not t.done()]
        if not tasks:
            return {"pending_before": 0, "pending_after": 0, "waited_ms": 0}
        timeout = max(0.0, float(max_wait_ms if max_wait_ms is not None else safe_int(get_setting("sealed_media_preserve_flush_before_capture_ms", "3000"), 3000, min_value=0)) / 1000.0)
        started = time.time()
        if timeout > 0:
            try:
                await asyncio.wait(tasks, timeout=timeout)
            except Exception:
                pass
        pending_after = len([t for t in list(self.sealed_preserve_bg_tasks) if not t.done()])
        return {"pending_before": len(tasks), "pending_after": pending_after, "waited_ms": int((time.time() - started) * 1000)}

    def _sealed_preserve_allowed_fast(self, *, media_url: str, logical: str, browser_resource_type: str = "") -> tuple[bool, str, dict[str, Any]]:
        """Fast, cached preservation check for the hot Playwright route path.

        This intentionally avoids database/settings reads while a page is loading.
        Full MIME/length validation still happens later in the background worker
        after headers are available.
        """
        pol = self.sealed_media_policy_cache or {}
        if not self.sealed_media_preservation_session:
            return False, "sealed preservation disabled for this live session", pol
        if not pol.get("enabled"):
            return False, "sealed media preservation disabled by policy", pol
        kind = media_kind_from_resource(url=media_url, resource_type=logical, browser_resource_type=browser_resource_type)
        if kind == "image" and not pol.get("images"):
            return False, "sealed preservation disabled for images", pol
        if kind == "video" and not pol.get("video"):
            return False, "sealed preservation disabled for video", pol
        if kind == "audio" and not pol.get("audio"):
            return False, "sealed preservation disabled for audio", pol
        if kind == "media" and not (pol.get("video") or pol.get("audio")):
            return False, "sealed preservation disabled for media", pol
        if kind not in {"image", "video", "audio", "media"}:
            return False, f"resource type {kind!r} is not configured for preservation", pol
        return True, "sealed preservation allowed", pol

    def _defer_blocked_media_record(self, *, media_url: str, logical: str, method: str, req_headers: dict[str, Any], page_url: str, reason: str) -> None:
        """Keep blocked-media metadata in memory so route handling stays fast.

        Records are written in a batch at capture/stop time instead of one SQLite
        write per blocked image while the page is trying to load.
        """
        if not media_url:
            return
        key = sha256_text("|".join([self.session_id, page_url or "", method or "", logical or "", media_url]))
        with self.deferred_blocked_lock:
            if key in self.deferred_blocked_seen:
                return
            if len(self.deferred_blocked_media) >= self.deferred_blocked_max:
                self.deferred_blocked_dropped += 1
                return
            self.deferred_blocked_seen.add(key)
            self.deferred_blocked_media.append({
                "media_url": media_url,
                "logical": logical,
                "method": method or "GET",
                "page_url": page_url or self.current_url,
                "referrer": (req_headers or {}).get("referer") or page_url or self.current_url,
                "request_headers": cleaned_preserve_headers(req_headers or {}, fallback_user_agent=self.user_agent, referer=page_url or self.current_url),
                "reason": reason[:500],
            })

    def _flush_deferred_blocked_media_sync(self, *, root_evidence_id: int | None = None, page_url: str | None = None, limit: int | None = None) -> dict[str, Any]:
        with self.deferred_blocked_lock:
            if not self.deferred_blocked_media:
                return {"flushed": 0, "remaining": 0, "dropped": self.deferred_blocked_dropped}
            take = len(self.deferred_blocked_media) if limit is None else max(0, min(int(limit), len(self.deferred_blocked_media)))
            items = self.deferred_blocked_media[:take]
            self.deferred_blocked_media = self.deferred_blocked_media[take:]
        flushed = 0
        for item in items:
            try:
                record_blocked_media(
                    actor=self.actor,
                    case_id=self.case_id,
                    root_evidence_id=root_evidence_id,
                    session_id=self.session_id,
                    page_url=page_url or item.get("page_url") or self.current_url,
                    media_url=item.get("media_url") or "",
                    resource_type=item.get("logical") or "media",
                    request_method=item.get("method") or "GET",
                    referrer=item.get("referrer") or page_url or self.current_url,
                    policy=self.media_policy,
                    reason=item.get("reason") or "aborted by live browser before body download",
                    request_headers=item.get("request_headers") or {},
                    use_tor=self.use_tor,
                    head_probe=False,
                    user_agent_profile=self.user_agent_profile,
                    custom_user_agent=self.custom_user_agent,
                )
                flushed += 1
            except Exception:
                pass
        with self.sealed_preserve_lock:
            self.deferred_blocked_flushed += flushed
        return {"flushed": flushed, "remaining": len(self.deferred_blocked_media), "dropped": self.deferred_blocked_dropped}

    async def _flush_deferred_blocked_media(self, *, root_evidence_id: int | None = None, page_url: str | None = None, limit: int | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(self._flush_deferred_blocked_media_sync, root_evidence_id=root_evidence_id, page_url=page_url, limit=limit)

    def _preserve_blocked_media_background_sync(self, item: dict[str, Any]) -> dict[str, Any]:
        if self.sealed_preserve_cancel_requested.is_set():
            with self.sealed_preserve_lock:
                self.sealed_preserve_cancelled += 1
            return {"ok": False, "reason": "sealed preservation canceled by user"}
        media_url = item.get("media_url") or ""
        logical = item.get("logical") or "media"
        method = item.get("method") or "GET"
        page_url = item.get("page_url") or self.current_url
        referrer = item.get("referrer") or page_url
        headers = item.get("request_headers") or {}
        root_evidence_id = item.get("root_evidence_id")
        source_engine = item.get("source_engine") or "live_browser_background_fast_route"
        preserve_reason = item.get("preserve_reason") or "blocked from local display by live browser; background encrypted preservation for sealed reviewer handoff"
        try:
            pol = self.sealed_media_policy_cache or {}
            max_each = int(pol.get("max_each_bytes") or 0)
            max_total = int(pol.get("max_total_bytes") or 0)
            with self.sealed_preserve_lock:
                if max_total and self.sealed_preserved_bytes >= max_total:
                    raise RuntimeError("sealed preservation skipped: per-session byte limit reached")
            timeout_ms = preserve_timeout_for(logical, media_url, background=True)
            result = self._download_preserved_media_requests(media_url, headers, timeout_ms, max_each)
            if not result.get("ok"):
                reason = str(result.get("reason") or "sealed preservation failed/skipped in background")[:500]
                bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=root_evidence_id, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical, request_method=method + "+sealed-preserve-bg-failed", referrer=referrer, policy=self.media_policy, reason=reason, request_headers=headers, response_headers=dict(result.get("headers") or {}), status_code=result.get("status_code"), content_type=result.get("mime_type"), content_length=str(result.get("content_length") or ""), downloaded=False, use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
                with self.sealed_preserve_lock:
                    self.sealed_preserve_skipped += 1
                    if "timeout" in reason.lower():
                        self.sealed_preserve_timeout_count += 1
                return {"ok": False, "blocked_media_id": bid, "reason": reason}
            body = result.get("body") or b""
            if not isinstance(body, bytes) or not body:
                raise RuntimeError("sealed preservation skipped: empty response body")
            with self.sealed_preserve_lock:
                if max_total and self.sealed_preserved_bytes + len(body) > max_total:
                    raise RuntimeError(f"sealed preservation skipped: session byte limit would be exceeded ({self.sealed_preserved_bytes + len(body)} > {max_total})")
            response_headers = dict(result.get("headers") or {})
            status_code = result.get("status_code")
            mt = str(result.get("mime_type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0]
            logical2 = media_kind_from_resource(url=media_url, resource_type=logical, mime_type=mt, browser_resource_type=logical)
            eid = persist_sealed_preserved_media(actor=self.actor, case_id=self.case_id, session_id=self.session_id, root_evidence_id=root_evidence_id, page_url=page_url, media_url=media_url, resource_type=logical2, mime_type=mt, payload=body, request_method=method + "+sealed-preserve-bg", referrer=referrer, request_headers=headers, response_headers=response_headers, status_code=status_code, reason=preserve_reason, source_engine=source_engine, final_url=str(result.get("final_url") or media_url))
            bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=root_evidence_id, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical2, request_method=method + "+sealed-preserve-bg", referrer=referrer, policy=self.media_policy, reason=("remote media discovered during capture; encrypted preservation complete" if source_engine == "live_capture_remote_media_sweep" else "blocked from local display by live browser; background encrypted preservation complete"), request_headers=headers, response_headers=response_headers, status_code=status_code, content_type=mt, content_length=str(len(body)), downloaded=True, content_sha256=sha256_bytes(body), use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
            execute("UPDATE blocked_media SET materialized_evidence_id=? WHERE id=?", (eid, bid))
            with self.sealed_preserve_lock:
                self.sealed_preserved += 1
                self.sealed_preserved_bytes += len(body)
            manifest_urls = [str(u) for u in (result.get("manifest_media_urls") or []) if isinstance(u, str)]
            if manifest_urls and self.loop is not None and not self.loop.is_closed():
                def _queue_manifest_children() -> None:
                    queued_children = 0
                    for child_url in manifest_urls[:30]:
                        try:
                            child_kind = classify_resource(child_url)
                            if child_kind == "other":
                                child_kind = "video"
                            self._queue_blocked_preservation_fast(
                                media_url=child_url,
                                logical=child_kind,
                                method="GET+manifest-child",
                                req_headers={"referer": media_url, "accept": "video/*,audio/*,application/octet-stream,*/*;q=0.6"},
                                page_url=page_url,
                                browser_resource_type=child_kind,
                                root_evidence_id=root_evidence_id,
                                source_engine="dash_manifest_child_media",
                                preserve_reason="media URL listed in downloaded DASH/HLS manifest; encrypted preservation for safe local reviewer playback",
                            )
                            queued_children += 1
                        except Exception:
                            pass
                    if queued_children:
                        log_event(self.actor, "DASH_MANIFEST_CHILD_MEDIA_QUEUED", case_id=self.case_id, evidence_id=eid, blocked_media_id=bid, session_id=self.session_id, details={"manifest_url_sha256": sha256_text(media_url), "queued_children": queued_children})
                self.loop.call_soon_threadsafe(_queue_manifest_children)
            log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVED_BACKGROUND", case_id=self.case_id, evidence_id=eid, blocked_media_id=bid, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical2, "size": len(body), "elapsed_ms": result.get("elapsed_ms"), "fast_live_route": True, "source_engine": source_engine, "manifest_child_urls": len(manifest_urls)})
            return {"ok": True, "evidence_id": eid, "blocked_media_id": bid, "size": len(body), "manifest_child_urls": len(manifest_urls)}
        except Exception as exc:
            reason = f"sealed preservation failed in background: {str(exc)[:450]}"
            try:
                bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=root_evidence_id, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical, request_method=method + "+sealed-preserve-bg-error", referrer=referrer, policy=self.media_policy, reason=reason, request_headers=headers, use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
            except Exception:
                bid = None
            with self.sealed_preserve_lock:
                self.sealed_preserve_skipped += 1
                if "timeout" in str(exc).lower():
                    self.sealed_preserve_timeout_count += 1
            log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVE_FAILED", case_id=self.case_id, blocked_media_id=bid, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical, "error": str(exc)[:500], "fast_live_route": True})
            return {"ok": False, "blocked_media_id": bid, "reason": reason}

    async def _preserve_blocked_media_background_fast(self, item: dict[str, Any]) -> None:
        await asyncio.to_thread(self._preserve_blocked_media_background_sync, item)

    def _queue_blocked_preservation_fast(self, *, media_url: str, logical: str, method: str, req_headers: dict[str, Any], page_url: str, browser_resource_type: str = "", root_evidence_id: int | None = None, source_engine: str = "live_browser_background_fast_route", preserve_reason: str = "") -> str:
        if self.sealed_preserve_cancel_requested.is_set():
            with self.sealed_preserve_lock:
                self.sealed_preserve_cancelled += 1
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason="sealed preservation canceled by user")
            return "sealed preservation canceled by user"
        ok, why, pol = self._sealed_preserve_allowed_fast(media_url=media_url, logical=logical, browser_resource_type=browser_resource_type)
        if not ok:
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason="aborted by live browser before body download; " + why)
            return why
        if pol.get("max_items_per_session") and self.sealed_preserved >= int(pol.get("max_items_per_session") or 0):
            with self.sealed_preserve_lock:
                self.sealed_preserve_skipped += 1
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason="sealed preservation skipped: per-session item limit reached")
            return "sealed preservation skipped: per-session item limit reached"
        if pol.get("max_total_bytes") and self.sealed_preserved_bytes >= int(pol.get("max_total_bytes") or 0):
            with self.sealed_preserve_lock:
                self.sealed_preserve_skipped += 1
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason="sealed preservation skipped: per-session byte limit reached")
            return "sealed preservation skipped: per-session byte limit reached"
        if len(self.sealed_preserve_bg_tasks) >= self.sealed_preserve_max_pending_tasks:
            with self.sealed_preserve_lock:
                self.sealed_preserve_skipped += 1
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason=f"sealed preservation skipped: background queue full ({len(self.sealed_preserve_bg_tasks)} >= {self.sealed_preserve_max_pending_tasks})")
            return "sealed preservation skipped: background queue full"
        if self.preserve_mode == "fast" and self.preserve_skip_decorative_fast and decorative_asset_url(media_url):
            with self.sealed_preserve_lock:
                self.sealed_preserve_skipped += 1
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method + "+sealed-preserve-skip", req_headers=req_headers, page_url=page_url, reason="sealed preservation skipped in fast mode: decorative asset")
            return "sealed preservation skipped in fast mode: decorative asset"
        clean_headers = cleaned_preserve_headers(req_headers, fallback_user_agent=self.user_agent, referer=req_headers.get("referer") or page_url or self.current_url)
        item = {"media_url": media_url, "logical": logical, "method": method, "request_headers": clean_headers, "page_url": page_url or self.current_url, "referrer": req_headers.get("referer") or page_url or self.current_url, "root_evidence_id": root_evidence_id, "source_engine": source_engine, "preserve_reason": preserve_reason}
        try:
            task = asyncio.create_task(self._preserve_blocked_media_background_fast(item))
            self.sealed_preserve_bg_tasks.add(task)
            task.add_done_callback(lambda t: self.sealed_preserve_bg_tasks.discard(t))
            return "sealed preservation queued in background; route returned immediately"
        except Exception as exc:
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason=f"sealed preservation queue failed: {str(exc)[:300]}")
            return "sealed preservation queue failed"

    async def _retry_blocked_media_records(self, blocked_ids: list[int] | None = None, *, retry_all_not_downloaded: bool = False, only_queue_full: bool = False) -> dict[str, Any]:
        """Re-queue existing blocked_media rows for encrypted background preservation.

        Used by the live-session UI to recover items that were skipped because
        the background queue was full, timed out, or otherwise did not download
        during fast browsing. Success updates the original blocked_media row.
        """
        self.sealed_preserve_cancel_requested.clear()
        ids = []
        for x in (blocked_ids or []):
            try:
                ids.append(int(x))
            except Exception:
                pass
        if retry_all_not_downloaded:
            if only_queue_full:
                rows = fetchall("SELECT * FROM blocked_media WHERE session_id=? AND downloaded=0 AND lower(reason) LIKE '%queue full%' ORDER BY id ASC", (self.session_id,))
            else:
                rows = fetchall("SELECT * FROM blocked_media WHERE session_id=? AND downloaded=0 ORDER BY id ASC", (self.session_id,))
        elif ids:
            ph = ",".join("?" for _ in ids)
            rows = fetchall(f"SELECT * FROM blocked_media WHERE session_id=? AND downloaded=0 AND id IN ({ph}) ORDER BY id ASC", (self.session_id, *ids))
        else:
            rows = []

        queued = 0
        skipped = 0
        already_downloaded = 0
        queue_full = 0
        errors = 0
        queued_ids: list[int] = []
        skipped_ids: list[int] = []
        error_samples: list[str] = []
        for row in rows:
            try:
                bid = int(row["id"])
                if int(row["downloaded"] or 0):
                    already_downloaded += 1
                    continue
                media_url = str(row["media_url"] or "")
                if not media_url.startswith(("http://", "https://")):
                    skipped += 1
                    skipped_ids.append(bid)
                    execute("UPDATE blocked_media SET reason=? WHERE id=?", ("sealed preservation retry skipped: non-network media URL", bid))
                    continue
                pending = len([t for t in list(self.sealed_preserve_bg_tasks) if not t.done()])
                if pending >= int(self.sealed_preserve_max_pending_tasks):
                    queue_full += 1
                    skipped_ids.append(bid)
                    execute("UPDATE blocked_media SET reason=? WHERE id=?", (f"sealed preservation retry not queued: background queue full ({pending} >= {self.sealed_preserve_max_pending_tasks})", bid))
                    continue
                logical = str(row["resource_type"] or classify_resource(media_url))
                method_raw = str(row["request_method"] or "GET")
                method = method_raw.split("+", 1)[0] or "GET"
                req_headers = jloads(row["request_headers_json"], {}) if row["request_headers_json"] else {}
                page_url = str(row["page_url"] or self.current_url or "")
                referrer = str(row["referrer"] or page_url or self.current_url or "")
                execute("UPDATE blocked_media SET reason=? WHERE id=?", ("sealed preservation retry queued by user", bid))
                task = asyncio.create_task(self._preserve_blocked_media_background(blocked_media_id=bid, media_url=media_url, logical=logical, method=method + "+retry", req_headers=req_headers, page_url=page_url, referrer=referrer))
                self.sealed_preserve_bg_tasks.add(task)
                task.add_done_callback(lambda t: self.sealed_preserve_bg_tasks.discard(t))
                queued += 1
                queued_ids.append(bid)
            except Exception as exc:
                errors += 1
                try:
                    skipped_ids.append(int(row["id"]))
                except Exception:
                    pass
                error_samples.append(str(exc)[:200])
        return {
            "ok": True,
            "session_id": self.session_id,
            "requested_rows": len(rows),
            "queued": queued,
            "queued_ids": queued_ids[:250],
            "skipped": skipped,
            "skipped_ids": skipped_ids[:250],
            "already_downloaded": already_downloaded,
            "queue_full": queue_full,
            "errors": errors,
            "error_samples": error_samples[:10],
            "status": self.preservation_status(),
        }

    def retry_blocked_media_records_sync(self, *, blocked_ids: list[int] | None = None, retry_all_not_downloaded: bool = False, only_queue_full: bool = False) -> dict[str, Any]:
        if self.loop is None or self.loop.is_closed() or self.stop_flag.is_set():
            raise HTTPException(409, "This live browser session is no longer active. Start a new session to retry blocked media with browser cookies/session state.")
        fut = asyncio.run_coroutine_threadsafe(self._retry_blocked_media_records(blocked_ids, retry_all_not_downloaded=retry_all_not_downloaded, only_queue_full=only_queue_full), self.loop)
        return fut.result(timeout=15)

    def preservation_status(self) -> dict[str, Any]:
        """Return lightweight live media-preservation progress for UI polling.

        Important: the progress bar reports preserved/downloaded success, not just
        whether background tasks have stopped trying. Earlier builds could show
        100% even when many items were skipped as queue-full; this version keeps
        the skipped/not-downloaded count visible and lowers the percent when that
        happens.
        """
        with self.sealed_preserve_lock:
            pending = len([t for t in list(self.sealed_preserve_bg_tasks) if not t.done()])
            preserved = int(self.sealed_preserved)
            skipped = int(self.sealed_preserve_skipped)
            cancelled = int(self.sealed_preserve_cancelled)
            timeouts = int(self.sealed_preserve_timeout_count)
            bytes_done = int(self.sealed_preserved_bytes)
        with self.deferred_blocked_lock:
            deferred_pending = len(self.deferred_blocked_media)
            deferred_dropped = int(self.deferred_blocked_dropped)
        stats = blocked_media_session_stats(self.session_id)
        downloaded_basis = max(stats["downloaded"], preserved)
        # Count everything the browser saw or the DB knows about, including
        # queue-full/not-downloaded rows and requests that have not been flushed
        # to SQLite yet. This prevents the UI from showing 100% success while
        # visible rows still say not downloaded.
        db_not_downloaded = int(stats["not_downloaded"] or 0)
        unrecorded_blocked = max(0, int(self.blocked) - int(stats["total"] or 0) - pending - deferred_pending)
        skipped_extra = max(0, skipped - db_not_downloaded)
        total_basis = max(
            int(self.blocked),
            int(stats["total"] or 0) + pending + deferred_pending + unrecorded_blocked,
            downloaded_basis + db_not_downloaded + pending + deferred_pending + unrecorded_blocked + skipped_extra + cancelled,
        )
        success_denominator = max(0, downloaded_basis + db_not_downloaded + pending + deferred_pending + unrecorded_blocked + skipped_extra)
        progress_pct = int((downloaded_basis / success_denominator) * 100) if success_denominator else (100 if downloaded_basis else 0)
        complete_basis = max(0, downloaded_basis + db_not_downloaded + pending + deferred_pending + unrecorded_blocked)
        attempt_done = max(0, downloaded_basis + db_not_downloaded)
        completion_pct = int((attempt_done / complete_basis) * 100) if complete_basis else (100 if downloaded_basis else 0)
        outstanding = max(0, db_not_downloaded + pending + deferred_pending + unrecorded_blocked + skipped_extra)
        return {
            "ok": True,
            "session_id": self.session_id,
            "running": bool(self.loop is not None and not self.loop.is_closed() and not self.stop_flag.is_set()),
            "mode": self.preserve_mode,
            "policy": self.sealed_media_policy_cache,
            "requests": int(self.requests),
            "blocked": int(self.blocked),
            "pending_tasks": pending,
            "deferred_metadata_pending": deferred_pending,
            "deferred_metadata_flushed": int(self.deferred_blocked_flushed),
            "deferred_metadata_dropped": deferred_dropped,
            "preserved": downloaded_basis,
            "preserved_bytes": bytes_done,
            "skipped_or_failed": max(skipped, stats["not_downloaded"]),
            "timeouts": max(timeouts, stats["timeouts"]),
            "cancelled": cancelled,
            "queue_limit": int(self.sealed_preserve_max_pending_tasks),
            "cancel_requested": bool(self.sealed_preserve_cancel_requested.is_set()),
            "db_total": stats["total"],
            "db_downloaded": stats["downloaded"],
            "db_not_downloaded": stats["not_downloaded"],
            "db_queue_full": stats["queue_full"],
            "db_timeouts": stats["timeouts"],
            "unrecorded_blocked": unrecorded_blocked,
            "skipped_extra": skipped_extra,
            "outstanding": outstanding,
            "all_downloaded": bool(total_basis and downloaded_basis >= total_basis and outstanding == 0),
            "success_percent": max(0, min(100, progress_pct)),
            "completion_percent": max(0, min(100, completion_pct)),
            "progress_percent": max(0, min(100, progress_pct)),
        }

    def cancel_preservation_sync(self) -> dict[str, Any]:
        """Cancel queued preservation work without stopping the live browser.

        Active thread downloads may finish anyway, but no new blocked media will be
        queued after this flag is set. This is intentionally coarse-grained;
        per-item cancellation would add a lot of UI/state complexity for little
        benefit in the current workflow.
        """
        self.sealed_preserve_cancel_requested.set()
        cancelled = 0
        for task in list(self.sealed_preserve_bg_tasks):
            if not task.done():
                try:
                    task.cancel()
                    cancelled += 1
                except Exception:
                    pass
        with self.sealed_preserve_lock:
            self.sealed_preserve_cancelled += cancelled
        return self.preservation_status()

    async def _record_captcha_challenge_allowed_from_browser(self, source, payload: dict[str, Any] | None = None) -> None:
        """Audit a browser-side CAPTCHA/challenge display exception.

        Network CAPTCHA images are visible through the route allowlist and are
        logged in _route. Inline darknet CAPTCHAs often arrive as data:image/*
        elements, so Playwright never sees a network request. The init script
        marks only inline images with CAPTCHA/challenge context and calls this
        binding so the display exception is still visible in browser_events and
        the custody audit log without storing the inline image itself.
        """
        if not self.allow_captcha_challenge_media:
            return
        payload = payload or {}
        try:
            page_url = str(payload.get("page_url") or getattr(source.get("page"), "url", "") or self.current_url or "")
        except Exception:
            page_url = str(payload.get("page_url") or self.current_url or "")
        tag = str(payload.get("tag") or "").lower()[:40]
        src_kind = str(payload.get("src_kind") or "").lower()[:80]
        src = str(payload.get("src") or "")
        src_prefix = str(payload.get("src_prefix") or "")[:140]
        src_length = safe_int(payload.get("src_length", 0), 0, min_value=0, max_value=100000000)
        context_text = str(payload.get("context_text") or "")[:700]
        reason = str(payload.get("reason") or "inline CAPTCHA/challenge display exception")[:300]
        # Keep the full data URL out of logs. If the browser passed it, hash it
        # and discard it immediately. The prefix/length are enough for human
        # debugging without persisting the CAPTCHA image.
        src_sha256 = sha256_text(src) if src else ""
        dedupe_key = sha256_text(canonical({
            "session_id": self.session_id,
            "page_url": page_url,
            "tag": tag,
            "src_kind": src_kind,
            "src_sha256": src_sha256,
            "src_prefix": src_prefix,
            "context_text": context_text[:160],
        }))
        if dedupe_key in self.captcha_challenge_inline_seen:
            return
        self.captcha_challenge_inline_seen.add(dedupe_key)
        self.captcha_challenge_allowed += 1
        details = {
            "reason": reason,
            "minimal_exception": True,
            "inline_data_image": src_kind == "inline_data_image",
            "src_kind": src_kind,
            "src_length": src_length,
            "src_sha256": src_sha256,
            "src_prefix": src_prefix,
            "tag": tag,
            "id": str(payload.get("id") or "")[:120],
            "class_name": str(payload.get("class_name") or "")[:180],
            "name": str(payload.get("name") or "")[:80],
            "alt": str(payload.get("alt") or "")[:160],
            "title": str(payload.get("title") or "")[:160],
            "role": str(payload.get("role") or "")[:80],
            "context_sha256": sha256_text(context_text),
            "context_sample": context_text[:300],
            "page_url_sha256": sha256_text(page_url),
            "media_policy": self.media_policy,
        }
        try:
            execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "captcha_challenge_inline_media_allowed", page_url, "image", "INLINE", None, "{}", header_hash({}), pretty(details)))
            log_event(self.actor, "CAPTCHA_CHALLENGE_INLINE_MEDIA_ALLOWED", case_id=self.case_id, session_id=self.session_id, details=details)
        except Exception:
            pass

    async def _route(self, route, request) -> None:
        self.requests += 1
        rt = request.resource_type
        req_headers = dict(request.headers or {})
        if live_policy_blocks(rt, self.media_policy, request.url):
            logical = classify_resource(request.url, browser_type=rt)
            if logical in {"document", "xhr", "fetch", "other"}:
                logical = classify_resource(request.url)
            if self.allow_captcha_challenge_media and captcha_challenge_media_candidate(request.url, rt):
                self.captcha_challenge_allowed += 1
                try:
                    execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "captcha_challenge_media_allowed", request.url, logical, request.method, None, "{}", header_hash({}), pretty({"reason": "minimal CAPTCHA/challenge display exception; ordinary media remains blocked", "url_sha256": sha256_text(request.url), "media_policy": self.media_policy})))
                    log_event(self.actor, "CAPTCHA_CHALLENGE_MEDIA_ALLOWED", case_id=self.case_id, session_id=self.session_id, details={"url_sha256": sha256_text(request.url), "resource_type": logical, "media_policy": self.media_policy, "reason": "minimal CAPTCHA/challenge display exception"})
                except Exception:
                    pass
                await route.continue_()
                return
            self.blocked += 1
            try:
                self._queue_blocked_preservation_fast(media_url=request.url, logical=logical, method=request.method, req_headers=req_headers, page_url=self.current_url, browser_resource_type=rt)
                if self.log_blocked_browser_events:
                    execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "blocked_request", request.url, logical, request.method, None, "{}", header_hash({}), pretty({"reason": "media policy pre-body abort", "fast_live_route": True})))
            except Exception:
                pass
            await route.abort()
            return
        if await self._capture_allowed_asset_via_route(route, request):
            return
        await route.continue_()

    def _on_frame_nav(self, page, frame) -> None:
        try:
            if page is not None and frame == page.main_frame:
                self.page = page
                self.active_page = page
                self.current_url = frame.url
                execute("UPDATE browser_sessions SET current_url=? WHERE session_id=?", (self.current_url, self.session_id))
                execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "navigation", self.current_url, "document", "GET", None, "{}", header_hash({}), pretty({"auto_capture_enabled": self.auto_capture, "tab_count": len(self._live_pages_snapshot()), "chat_capture_profile": chat_profile_url(self.current_url)})))
                if self.auto_capture and self.loop:
                    asyncio.run_coroutine_threadsafe(self._auto_capture_after_navigation(self.current_url, page), self.loop)
        except Exception:
            pass

    def _on_response(self, resp) -> None:
        if not self.log_live_responses:
            return
        async def inner():
            try:
                req = resp.request
                headers = await resp.all_headers()
                execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "response", resp.url, req.resource_type, req.method, resp.status, json.dumps(headers, ensure_ascii=False), header_hash(headers), pretty({"from_service_worker": getattr(resp, 'from_service_worker', False)})))
            except Exception:
                pass
        try:
            if self.loop and not self.loop.is_closed():
                asyncio.run_coroutine_threadsafe(inner(), self.loop)
        except Exception:
            pass

    async def _settle_page_for_capture(self, page=None) -> dict[str, Any]:
        """Wait for slow/lazy content before manual or automatic page capture.

        This deliberately avoids a single brittle wait. It combines load-state waits,
        a bounded network-idle wait, optional lazy-load auto-scroll, and repeated
        document-height stability checks. Long-polling pages can keep networkidle
        from completing, so timeouts are treated as warnings rather than failures.
        """
        page = page or self.page
        page_url = getattr(page, "url", "") or ""
        chat_profile = chat_profile_url(page_url)
        meta: dict[str, Any] = {"settle_enabled": self.settle_before_capture and setting_bool("capture_settle_before_save", "1"), "chat_dynamic_profile": chat_profile}
        if not meta["settle_enabled"] or page is None:
            return meta
        started = time.time()
        timeout_ms = max(1000, int(get_setting("capture_settle_timeout_ms", "30000") or "30000"))
        network_idle_ms = max(500, int(get_setting("capture_network_idle_timeout_ms", "20000") or "20000"))
        wait_after_ms = max(0, int(get_setting("capture_wait_after_load_ms", "5000") or "5000"))
        pause_ms = max(100, int(get_setting("capture_auto_scroll_pause_ms", "550") or "550"))
        max_steps = max(0, int(get_setting("capture_auto_scroll_max_steps", "30") or "30"))
        stable_rounds_required = max(1, int(get_setting("capture_stable_rounds", "3") or "3"))
        if chat_profile:
            timeout_ms = min(timeout_ms, max(2000, int(get_setting("capture_chat_settle_timeout_ms", "10000") or "10000")))
            network_idle_ms = min(network_idle_ms, max(500, int(get_setting("capture_chat_network_idle_timeout_ms", "1200") or "1200")))
            wait_after_ms = min(wait_after_ms, max(0, int(get_setting("capture_chat_wait_after_load_ms", "500") or "500")))
            max_steps = min(max_steps, max(0, int(get_setting("capture_chat_auto_scroll_max_steps", "8") or "8")))
            stable_rounds_required = min(stable_rounds_required, 2)
            pause_ms = min(pause_ms, 300)
        auto_scroll = bool(self.capture_auto_scroll_session) and setting_bool("capture_auto_scroll_enabled", "0")
        warnings: list[str] = []
        if wait_after_ms:
            await asyncio.sleep(wait_after_ms / 1000)
        wait_states = [("domcontentloaded", min(timeout_ms, 5000 if chat_profile else 10000))]
        if not chat_profile:
            wait_states.extend([("load", min(timeout_ms, 12000)), ("networkidle", min(timeout_ms, network_idle_ms))])
        else:
            meta["wait_load"] = "skipped_for_chat_dynamic_profile"
            meta["wait_networkidle"] = "skipped_for_chat_dynamic_profile"
        for state, state_timeout in wait_states:
            try:
                await page.wait_for_load_state(state, timeout=state_timeout)
                meta[f"wait_{state}"] = "ok"
            except Exception as exc:
                meta[f"wait_{state}"] = "timeout_or_unavailable"
                warnings.append(f"{state}: {str(exc)[:180]}")
        last_height = -1
        stable_rounds = 0
        steps = 0
        if auto_scroll:
            while steps < max_steps and (time.time() - started) * 1000 < timeout_ms:
                try:
                    height = int(await page.evaluate("() => Math.max(document.body ? document.body.scrollHeight : 0, document.documentElement ? document.documentElement.scrollHeight : 0, window.innerHeight || 0)"))
                    await page.evaluate("(y) => window.scrollTo(0, y)", height)
                    await asyncio.sleep(pause_ms / 1000)
                    new_height = int(await page.evaluate("() => Math.max(document.body ? document.body.scrollHeight : 0, document.documentElement ? document.documentElement.scrollHeight : 0, window.innerHeight || 0)"))
                    ready_state = str(await page.evaluate("() => document.readyState"))
                    if new_height == last_height and ready_state in {"interactive", "complete"}:
                        stable_rounds += 1
                    else:
                        stable_rounds = 0
                    last_height = new_height
                    steps += 1
                    if stable_rounds >= stable_rounds_required:
                        break
                except Exception as exc:
                    warnings.append(f"scroll/stability: {str(exc)[:180]}")
                    break
            try:
                await page.evaluate("() => window.scrollTo(0, 0)")
            except Exception:
                pass
        meta.update({
            "settle_elapsed_ms": int((time.time() - started) * 1000),
            "auto_scroll": auto_scroll,
            "auto_scroll_steps": steps,
            "stable_rounds": stable_rounds,
            "final_document_height": last_height if last_height >= 0 else None,
            "warnings": warnings[:10],
        })
        try:
            execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "capture_settle_completed", getattr(page, "url", "") or page_url, "document", "GET", None, "{}", header_hash({}), pretty(meta)))
        except Exception:
            pass
        return meta

    async def _auto_capture_after_navigation(self, nav_url: str, page=None) -> None:
        if not self.auto_capture or self.page is None:
            return
        try:
            delay_ms = max(0, int(get_setting("live_auto_capture_delay_ms", "2500") or "2500"))
            if delay_ms:
                await asyncio.sleep(delay_ms / 1000)
            if self.stop_flag.is_set() or self.page is None:
                return
            target_page = page or self.page
            current = (getattr(target_page, "url", "") if target_page is not None else "") or nav_url
            key = sha256_text(current)
            with self.auto_capture_lock:
                if key in self.auto_capture_seen:
                    return
                self.auto_capture_seen.add(key)
            eid = await self._capture_current(auto=True, page=target_page)
            log_event(self.actor, "LIVE_AUTO_CAPTURE_COMPLETED", case_id=self.case_id, evidence_id=eid, session_id=self.session_id, details={"url_sha256": key})
        except Exception as exc:
            log_event(self.actor, "LIVE_AUTO_CAPTURE_FAILED", case_id=self.case_id, session_id=self.session_id, details={"url_sha256": sha256_text(nav_url or ""), "error": str(exc)[:500]})

    async def _collect_page_media_refs(self, page=None) -> list[dict[str, Any]]:
        """Collect dynamic/lazy/remote media references from the live DOM before saving.

        This deliberately goes beyond img/src. Reddit/Shreddit, YouTube, and
        modern dynamic pages often expose media in custom-element attributes,
        srcsets, performance entries, manifests, or hydrated DOM state. These
        refs are used by the capture-side remote media sweep so safe/local
        reviewer playback does not have to depend on remote callbacks/scripts.
        """
        page = page or self.page
        if page is None:
            return []
        try:
            refs = await page.evaluate("""() => {
                const out = [];
                const add = (url, tag, attr, source='dom') => {
                    if (!url || typeof url !== 'string') return;
                    let v = url.trim();
                    if (!v || v === 'dynamic-scripts-preferred' || v.startsWith('data:') || v.startsWith('blob:') || v.startsWith('javascript:')) return;
                    v = v.replace(/&amp;/g, '&');
                    out.push({url: v, tag, attr, source, inline: false, dynamic: true});
                };
                const addSrcset = (ss, tag, attr, source='dom-srcset') => {
                    ss = ss || '';
                    for (const part of String(ss).split(',')) add((part.trim().split(/\\s+/)[0] || ''), tag, attr, source);
                };
                for (const img of Array.from(document.images || [])) {
                    add(img.currentSrc, 'img', 'currentSrc');
                    add(img.src, 'img', 'src');
                    for (const a of ['data-src','data-lazy-src','data-original','data-url','data-blindsite-src','data-current-src','data-remote-src']) add(img.getAttribute(a), 'img', a);
                    addSrcset(img.getAttribute('srcset'), 'img', 'srcset');
                    addSrcset(img.getAttribute('data-original-srcset'), 'img', 'data-original-srcset');
                    addSrcset(img.getAttribute('data-remote-srcset'), 'img', 'data-remote-srcset');
                }
                for (const src of Array.from(document.querySelectorAll('picture source, video source, audio source, source'))) {
                    add(src.src, src.tagName.toLowerCase(), 'src');
                    for (const a of ['data-src','data-blindsite-src','data-current-src','data-remote-src']) add(src.getAttribute(a), src.tagName.toLowerCase(), a);
                    addSrcset(src.getAttribute('srcset'), src.tagName.toLowerCase(), 'srcset');
                    addSrcset(src.getAttribute('data-original-srcset'), src.tagName.toLowerCase(), 'data-original-srcset');
                }
                for (const v of Array.from(document.querySelectorAll('video,audio'))) {
                    add(v.currentSrc, v.tagName.toLowerCase(), 'currentSrc');
                    add(v.src, v.tagName.toLowerCase(), 'src');
                    add(v.getAttribute('poster'), v.tagName.toLowerCase(), 'poster');
                    for (const a of ['data-src','data-blindsite-src','data-current-src','data-poster','data-remote-src','data-video-url','data-media-url']) add(v.getAttribute(a), v.tagName.toLowerCase(), a);
                }
                for (const meta of Array.from(document.querySelectorAll('meta[property="og:image"],meta[property="og:video"],meta[property="og:video:url"],meta[property="og:video:secure_url"],meta[name="twitter:image"],meta[name="twitter:player"]'))) {
                    add(meta.getAttribute('content'), 'meta', meta.getAttribute('property') || meta.getAttribute('name') || 'content');
                }
                for (const el of Array.from(document.querySelectorAll('[content-href],[data-blindsite-src],[data-original-srcset],[data-media-url],[data-video-url],[data-url],[poster],[src],[href]'))) {
                    for (const a of ['content-href','data-blindsite-src','data-media-url','data-video-url','data-url','poster','src','href']) add(el.getAttribute(a), el.tagName.toLowerCase(), a, 'custom-attr');
                    addSrcset(el.getAttribute('data-original-srcset'), el.tagName.toLowerCase(), 'data-original-srcset', 'custom-srcset');
                    addSrcset(el.getAttribute('srcset'), el.tagName.toLowerCase(), 'srcset', 'custom-srcset');
                }
                for (const el of Array.from(document.querySelectorAll('[style]'))) {
                    const style = el.getAttribute('style') || '';
                    for (const m of style.matchAll(/url\\((['\"]?)(.*?)\\1\\)/g)) add(m[2], 'style', 'url', 'style-url');
                }
                for (const a of Array.from(document.querySelectorAll('a[href]'))) {
                    const href = a.getAttribute('href') || '';
                    if (/\\.(jpg|jpeg|png|gif|webp|avif|bmp|svg|mp4|webm|mov|m4v|mp3|wav|ogg|m3u8|mpd)(\\?|#|$)/i.test(href)) add(href, 'a', 'href', 'anchor-media');
                }
                try {
                    for (const e of performance.getEntriesByType('resource') || []) {
                        const n = e && e.name ? String(e.name) : '';
                        if (/\\.(jpg|jpeg|png|gif|webp|avif|bmp|svg|mp4|webm|mov|m4v|mp3|wav|ogg|m3u8|mpd)(\\?|#|$)/i.test(n) || /(^|\\.)v\\.redd\\.it|i\\.redd\\.it|preview\\.redd\\.it|redditmedia\\.com|redd\\.it/i.test(n)) add(n, 'performance', e.initiatorType || 'resource', 'performance');
                    }
                } catch(e) {}
                try {
                    const html = document.documentElement ? document.documentElement.outerHTML : '';
                    const re = /https?:\\/\\/[^\\s\\"'<>\\)]+(?:i\\.redd\\.it|preview\\.redd\\.it|v\\.redd\\.it|redditmedia\\.com|redd\\.it)[^\\s\\"'<>\\)]*/ig;
                    let m; let count = 0;
                    while ((m = re.exec(html)) && count < 2000) { add(m[0].replace(/&amp;/g, '&'), 'html-regex', 'reddit-media-url', 'html-regex'); count++; }
                } catch(e) {}
                const seen = new Set();
                return out.filter(r => { const k = `${r.url}|${r.tag}|${r.attr}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 5000);
            }""")
            if isinstance(refs, list):
                normalized = []
                page_url = page.url
                for r in refs:
                    if isinstance(r, dict) and r.get("url"):
                        rr = dict(r)
                        rr["url"] = absolute_resource_url(page_url, str(rr.get("url") or ""))
                        normalized.append(rr)
                return normalized
        except Exception as exc:
            try:
                execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "dynamic_media_ref_collection_failed", self.current_url, "document", "GET", None, "{}", header_hash({}), pretty({"error": str(exc)[:500]})))
            except Exception:
                pass
        return []

    def _preserved_download_exists_for_url(self, url: str) -> bool:
        aliases = list(url_aliases(url))[:30]
        if not aliases:
            return False
        ph = ",".join(["?"] * len(aliases))
        row = fetchone(f"SELECT 1 FROM blocked_media WHERE session_id=? AND downloaded=1 AND media_url IN ({ph}) LIMIT 1", tuple([self.session_id] + aliases))
        return bool(row)

    async def _queue_discovered_remote_media_for_capture(self, *, page_evidence_id: int, page_url: str, refs: list[dict[str, Any]]) -> dict[str, Any]:
        """Queue remote media discovered in the DOM/performance log for sealed preservation.

        This is the missing bridge for Reddit/YouTube-style pages: scripts may reveal
        media URLs in the hydrated DOM or performance entries without those exact
        URLs being blocked as normal image/video requests. We save the page first,
        then queue those remote media URLs for encrypted preservation so safe/local
        reviewer rendering does not have to rely on remote callbacks later.
        """
        if not setting_bool("live_capture_remote_media_sweep_enabled", "1"):
            return {"enabled": False, "reason": "disabled"}
        pol0 = sealed_media_preservation_policy(case_for(self.case_id))
        if not pol0.get("enabled"):
            reason0 = "sealed media preservation disabled" if pol0.get("global_enabled") else "sealed media preservation disabled globally"
            return {"enabled": False, "reason": reason0, "policy": pol0}
        max_items = safe_int(get_setting("live_capture_remote_media_sweep_max_items", "800"), 800, min_value=0, max_value=5000)
        if max_items <= 0:
            return {"enabled": False, "reason": "max_items is 0"}
        candidates = expanded_remote_media_candidates(refs, page_url, limit=max_items)
        queued = 0
        skipped_existing = 0
        skipped_not_allowed = 0
        skipped_queue = 0
        skipped_other = 0
        sample: list[dict[str, Any]] = []
        for cand in candidates:
            u = str(cand.get("url") or "")
            if not u:
                continue
            logical = str(cand.get("logical") or classify_resource(u))
            if logical == "other" and Path(urlparse(u).path.lower()).suffix in {".m3u8", ".mpd"}:
                logical = "video"
            if self._preserved_download_exists_for_url(u):
                skipped_existing += 1
                continue
            ok2, why2, _ = sealed_media_preservation_allowed(self.case_id, url=u, resource_type=logical)
            if not ok2:
                skipped_not_allowed += 1
                continue
            reason = self._queue_blocked_preservation_fast(
                media_url=u,
                logical=logical,
                method="GET+capture-remote-sweep",
                req_headers={"referer": page_url, "accept": "video/*,audio/*,image/*,application/dash+xml,application/vnd.apple.mpegurl,application/x-mpegURL,application/octet-stream,*/*;q=0.6"},
                page_url=page_url,
                browser_resource_type=logical,
                root_evidence_id=page_evidence_id,
                source_engine="live_capture_remote_media_sweep",
                preserve_reason="remote media URL discovered in captured page; encrypted preservation for safe local reviewer playback",
            )
            if "queued" in reason:
                queued += 1
                if len(sample) < 30:
                    sample.append({"url_sha256": sha256_text(u), "host": urlparse(u).netloc, "path": urlparse(u).path[-120:], "logical": logical, "source": cand.get("source"), "score": cand.get("score")})
            elif "queue full" in reason:
                skipped_queue += 1
            else:
                skipped_other += 1
        wait_ms = safe_int(get_setting("live_capture_remote_media_sweep_wait_ms", "3500"), 3500, min_value=0, max_value=30000)
        waited = 0
        if queued and wait_ms > 0:
            start = time.time()
            while (time.time() - start) * 1000 < wait_ms:
                pending = [t for t in list(self.sealed_preserve_bg_tasks) if not t.done()]
                if not pending:
                    break
                await asyncio.sleep(0.15)
            waited = int((time.time() - start) * 1000)
        meta = {
            "enabled": True,
            "candidate_count": len(candidates),
            "queued": queued,
            "skipped_existing": skipped_existing,
            "skipped_not_allowed": skipped_not_allowed,
            "skipped_queue_full": skipped_queue,
            "skipped_other": skipped_other,
            "waited_ms": waited,
            "sample": sample,
        }
        try:
            execute("INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (self.session_id, utcnow(), "capture_remote_media_sweep", page_url, "media", "GET", None, "{}", header_hash({}), pretty(meta)))
        except Exception:
            pass
        return meta

    async def _prepare_dom_for_capture_snapshot(self, page=None) -> dict[str, Any]:
        """Annotate dynamic DOM state before page.content() for chat/forms/media pages.

        This keeps manual captures useful after a long chat by preserving current
        input values, textarea text, selected options, currentSrc/poster values,
        scroll positions, and javascript:void link counts in the saved DOM/metadata.
        """
        page = page or self.page
        if page is None:
            return {}
        try:
            data = await page.evaluate("""() => {
                const out = {javascript_void_links: 0, inputs: 0, textareas: 0, media: 0, scrollables: 0};
                for (const a of Array.from(document.querySelectorAll('a[href]'))) {
                    const href = a.getAttribute('href') || '';
                    if (/^javascript:\\s*void/i.test(href) || href.trim() === '#') {
                        a.setAttribute('data-blindsite-original-href', href);
                        a.setAttribute('data-blindsite-nonnavigational-link', '1');
                        out.javascript_void_links++;
                    }
                }
                for (const el of Array.from(document.querySelectorAll('input, textarea, select'))) {
                    const tag = el.tagName.toLowerCase();
                    if (tag === 'textarea') {
                        el.textContent = el.value || '';
                        el.setAttribute('data-blindsite-value-captured', el.value || '');
                        out.textareas++;
                    } else if (tag === 'select') {
                        for (const opt of Array.from(el.options || [])) {
                            if (opt.selected) opt.setAttribute('selected', 'selected');
                            else opt.removeAttribute('selected');
                        }
                        out.inputs++;
                    } else {
                        const typ = (el.getAttribute('type') || '').toLowerCase();
                        if (typ === 'password') {
                            el.setAttribute('data-blindsite-password-present', el.value ? '1' : '0');
                        } else if (typ === 'checkbox' || typ === 'radio') {
                            if (el.checked) el.setAttribute('checked', 'checked');
                            else el.removeAttribute('checked');
                        } else {
                            el.setAttribute('value', el.value || '');
                        }
                        out.inputs++;
                    }
                }
                for (const el of Array.from(document.querySelectorAll('img,video,audio,source'))) {
                    if (el.currentSrc) el.setAttribute('data-blindsite-current-src', el.currentSrc);
                    if (el.src) el.setAttribute('data-blindsite-src', el.src);
                    if (el.poster) el.setAttribute('data-blindsite-poster', el.poster);
                    out.media++;
                }
                const scrollables = Array.from(document.querySelectorAll('body, html, div, main, section, article, ul, ol'))
                  .filter(el => (el.scrollHeight || 0) > (el.clientHeight || 0) + 20 || (el.scrollWidth || 0) > (el.clientWidth || 0) + 20)
                  .slice(0, 200);
                for (const el of scrollables) {
                    el.setAttribute('data-blindsite-scroll-top', String(el.scrollTop || 0));
                    el.setAttribute('data-blindsite-scroll-left', String(el.scrollLeft || 0));
                    out.scrollables++;
                }
                return out;
            }""")
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            return {"error": str(exc)[:300]}

    async def _capture_current(self, auto: bool = False, page=None) -> int:
        page = page or self.page
        if page is None:
            raise HTTPException(409, "Session page is not ready")
        self.page = page
        url = page.url
        self.current_url = url
        case = case_for(self.case_id)
        safe = case_safe(case)
        settle_meta = await self._settle_page_for_capture(page)
        # Critical performance rule: save the page first. Media preservation is
        # background work and must never delay or prevent the page capture itself.
        preserve_flush_meta = {"pending_before": len([t for t in list(self.sealed_preserve_bg_tasks) if not t.done()]), "pending_after": len([t for t in list(self.sealed_preserve_bg_tasks) if not t.done()]), "waited_ms": 0, "page_saved_before_media_flush": True}
        title = ""
        try:
            title = await page.title()
        except Exception:
            pass
        dom_snapshot_meta = await self._prepare_dom_for_capture_snapshot(page)
        html_text = await page.content()
        dynamic_media_refs = await self._collect_page_media_refs(page)
        html_media_refs = extract_media_refs(url, html_text)
        combined_media_refs = html_media_refs + dynamic_media_refs
        inline_refs = [r for r in combined_media_refs if r.get("inline")]
        raw_allowed = (not safe) and (edition() == "lab" or bool(case and case.get("raw_root_allowed")))
        if raw_allowed:
            payload = html_text.encode("utf-8", errors="replace")
            storage_mode = "live_browser_raw_html"
            raw_persisted = True
            kind = "browser_root_html"
            filename = "live_browser_page.html"
            mime_type = "text/html"
        else:
            summary = sanitize_html_summary(url, html_text)
            if safe and inline_refs and setting_bool("reject_inline_media_in_safe_mode", "1"):
                summary["text"] = "Inline embedded media detected; sanitized DOM text was minimized by safe-mode policy."
                summary["inline_media_count"] = len(inline_refs)
            meta = {"session_id": self.session_id, "current_url": url, "current_url_sha256": sha256_text(url), "title": title, "browser": self.browser_choice, "use_tor": self.use_tor, "media_policy": self.media_policy, "user_agent_profile": self.user_agent_meta.get("profile"), "user_agent_label": self.user_agent_meta.get("label"), "user_agent_sha256": self.user_agent_meta.get("user_agent_sha256"), "requests": self.requests, "blocked": self.blocked, "sealed_preserved": self.sealed_preserved, "sealed_preserved_bytes": self.sealed_preserved_bytes, "sealed_preserve_skipped": self.sealed_preserve_skipped, "dynamic_media_refs_count": len(dynamic_media_refs), "dom_snapshot_meta": dom_snapshot_meta, "captured_at": utcnow(), "raw_root_persisted": False, "auto_capture": bool(auto), "settle_before_capture": settle_meta, "sealed_preserve_background_flush": preserve_flush_meta}
            payload = pretty({"live_browser_metadata": meta, "sanitized_summary": summary}).encode("utf-8")
            storage_mode = "live_browser_sanitized_summary"
            raw_persisted = False
            kind = "live_browser_summary"
            filename = "live_browser_sanitized_summary.json"
            mime_type = "application/json"
        evidence_meta = {"session_id": self.session_id, "browser": self.browser_choice, "use_tor": self.use_tor, "media_policy": self.media_policy, "user_agent_profile": self.user_agent_meta.get("profile"), "user_agent_label": self.user_agent_meta.get("label"), "user_agent_sha256": self.user_agent_meta.get("user_agent_sha256"), "requests": self.requests, "blocked": self.blocked, "sealed_preserved": self.sealed_preserved, "sealed_preserved_bytes": self.sealed_preserved_bytes, "sealed_preserve_skipped": self.sealed_preserve_skipped, "dynamic_media_refs_count": len(dynamic_media_refs), "dynamic_media_ref_aliases_sample": sorted(list(media_ref_aliases(dynamic_media_refs, url)))[:80], "dom_snapshot_meta": dom_snapshot_meta, "raw_allowed": raw_allowed, "page_title": title, "current_url": url, "auto_capture": bool(auto), "settle_before_capture": settle_meta, "sealed_preserve_background_flush": preserve_flush_meta}
        eid = persist_evidence(case_id=self.case_id, actor=self.actor, kind=kind, source_type="live_browser_capture", source_ref=url, filename=filename, mime_type=mime_type, payload=payload, encrypt=True, storage_mode=storage_mode, raw_persisted=raw_persisted, meta=evidence_meta)
        pcid = register_page_capture(session_id=self.session_id, case_id=self.case_id, evidence_id=eid, page_url=url, title=title, capture_mode=storage_mode, raw_persisted=raw_persisted, meta=evidence_meta)
        deferred_blocked_flush_meta = await self._flush_deferred_blocked_media(root_evidence_id=eid, page_url=url)
        sealed_snapshot_id: int | None = None
        snapshot_allowed, snapshot_reason = sealed_page_snapshot_allowed(self.case_id)
        if (not raw_persisted) and snapshot_allowed and html_text:
            try:
                snapshot_meta = {
                    **evidence_meta,
                    "sealed_page_snapshot": True,
                    "snapshot_reason": snapshot_reason,
                    "parent_page_evidence_id": eid,
                    "page_capture_id": pcid,
                    "current_url": url,
                    "title": title,
                    "page_title": title,
                    "raw_root_persisted": True,
                    "viewer_note": "Hard-sealed rendered DOM snapshot for cleared reviewer full-page reconstruction; local vault key cannot decrypt this object.",
                }
                sealed_snapshot_id = persist_evidence(case_id=self.case_id, actor=self.actor, kind="page", source_type="sealed_page_snapshot", source_ref=url, filename="sealed_reviewer_page_snapshot.html", mime_type="text/html", payload=html_text.encode("utf-8", errors="replace"), encrypt=True, parent_id=eid, storage_mode=SEALED_PRESERVED_PAGE_SNAPSHOT_STORAGE_MODE, raw_persisted=True, meta=snapshot_meta, quarantined=True, lock_original=True, disable_plaintext=True, never_materialize=True)
                log_event(self.actor, "SEALED_PAGE_SNAPSHOT_STORED", case_id=self.case_id, evidence_id=sealed_snapshot_id, session_id=self.session_id, details={"parent_page_evidence_id": eid, "page_capture_id": pcid, "url_sha256": sha256_text(url), "snapshot_reason": snapshot_reason})
            except Exception as exc:
                log_event(self.actor, "SEALED_PAGE_SNAPSHOT_FAILED", case_id=self.case_id, evidence_id=eid, session_id=self.session_id, details={"error": str(exc)[:500], "url_sha256": sha256_text(url), "snapshot_reason": snapshot_reason})
        remote_media_sweep_meta = await self._queue_discovered_remote_media_for_capture(page_evidence_id=eid, page_url=url, refs=combined_media_refs)
        asset_ids: list[int] = []
        if raw_persisted and self.download_allowed_media and not case_safe(case_for(self.case_id)) and not lockdown():
            current_ref_urls = set()
            for ref in combined_media_refs:
                if not ref.get("inline"):
                    ref_url = str(ref.get("url") or "")
                    current_ref_urls.update(url_aliases(ref_url, url))
            with self.asset_lock:
                cached_assets = list(self.asset_cache.values())
            for asset in cached_assets:
                asset_url = str(asset.get("url") or "")
                asset_type = str(asset.get("resource_type") or "")
                if current_ref_urls and not (url_aliases(asset_url) & current_ref_urls) and asset_type != "font":
                    continue
                try:
                    body = asset.get("body") or b""
                    if not isinstance(body, bytes) or not body:
                        continue
                    child = persist_evidence(case_id=self.case_id, actor=self.actor, kind=kind_for(asset.get("mime_type", ""), asset.get("filename", "")), source_type="live_captured_asset", source_ref=asset.get("url"), filename=asset.get("filename") or "asset.bin", mime_type=asset.get("mime_type") or "application/octet-stream", payload=body, encrypt=True, parent_id=eid, storage_mode="captured_asset_local", raw_persisted=True, meta={k:v for k,v in asset.items() if k != "body"})
                    aid = register_captured_asset(actor=self.actor, case_id=self.case_id, session_id=self.session_id, root_evidence_id=eid, resource_evidence_id=child, original_url=asset.get("url", ""), resource_type=asset.get("resource_type", "other"), mime_type=asset.get("mime_type"), size=asset.get("size"), sha256=asset.get("sha256"), meta={k:v for k,v in asset.items() if k != "body"})
                    asset_ids.append(aid)
                except Exception as exc:
                    log_event(self.actor, "LIVE_CAPTURED_ASSET_STORE_FAILED", case_id=self.case_id, evidence_id=eid, session_id=self.session_id, details={"error": str(exc)[:500], "url_sha256": asset.get("url_sha256")})
        preserved_link_ids = link_preserved_media_to_page_capture(actor=self.actor, case_id=self.case_id, session_id=self.session_id, page_evidence_id=eid, page_url=url, html_refs=html_media_refs, dynamic_refs=dynamic_media_refs)
        asset_ids.extend(preserved_link_ids)
        update_evidence_meta(eid, {"page_capture_id": pcid, "captured_asset_count": len(asset_ids), "sealed_preserved_asset_links": len(preserved_link_ids), "sealed_page_snapshot_id": sealed_snapshot_id, "deferred_blocked_media_flush": deferred_blocked_flush_meta, "captured_asset_cache_skipped": self.asset_skipped, "captured_asset_total_bytes": self.asset_bytes_total, "remote_media_sweep": remote_media_sweep_meta})
        log_event(self.actor, "LIVE_CURRENT_PAGE_CAPTURED", case_id=self.case_id, evidence_id=eid, session_id=self.session_id, details={"url_sha256": sha256_text(url), "raw_persisted": raw_persisted, "page_capture_id": pcid, "captured_assets": len(asset_ids), "sealed_preserved_asset_links": len(preserved_link_ids), "sealed_page_snapshot_id": sealed_snapshot_id, "deferred_blocked_media_flush": deferred_blocked_flush_meta, "asset_skipped": self.asset_skipped, "remote_media_sweep": remote_media_sweep_meta, "auto_capture": bool(auto), "settle_elapsed_ms": settle_meta.get("settle_elapsed_ms")})
        return eid

    def capture_current_sync(self) -> int:
        if self.loop is None or self.loop.is_closed() or self.stop_flag.is_set():
            execute("UPDATE browser_sessions SET status='stopped', stopped_at=coalesce(stopped_at, ?) WHERE session_id=?", (utcnow(), self.session_id))
            raise HTTPException(409, "This live browser session is no longer active. Start a new live session before capturing.")
        fut = asyncio.run_coroutine_threadsafe(self._capture_current(), self.loop)
        return int(fut.result(timeout=120))

    async def _capture_all_open_tabs(self) -> list[int]:
        ids: list[int] = []
        pages = self._live_pages_snapshot()
        seen_urls: set[str] = set()
        for p in pages:
            try:
                url = getattr(p, "url", "") or ""
                if not url or url.startswith(("about:", "chrome:", "edge:", "devtools:")):
                    continue
                key = sha256_text(url)
                if key in seen_urls:
                    continue
                seen_urls.add(key)
                ids.append(await self._capture_current(auto=False, page=p))
            except Exception as exc:
                log_event(self.actor, "LIVE_TAB_CAPTURE_FAILED", case_id=self.case_id, session_id=self.session_id, details={"url": getattr(p, "url", "") or "", "error": str(exc)[:500]})
        return ids

    def capture_all_open_tabs_sync(self) -> list[int]:
        if self.loop is None or self.loop.is_closed() or self.stop_flag.is_set():
            execute("UPDATE browser_sessions SET status='stopped', stopped_at=coalesce(stopped_at, ?) WHERE session_id=?", (utcnow(), self.session_id))
            raise HTTPException(409, "This live browser session is no longer active. Start a new live session before capturing tabs.")
        fut = asyncio.run_coroutine_threadsafe(self._capture_all_open_tabs(), self.loop)
        return list(fut.result(timeout=300))

    def _remember_tabs_snapshot(self, tabs: list[dict[str, Any]]) -> None:
        if not tabs:
            return
        with self.tabs_snapshot_lock:
            self.last_tabs_snapshot = [dict(t) for t in tabs]
            self.last_tabs_snapshot_time = time.time()

    def _last_known_tabs_snapshot(self, max_age_s: float = 120.0) -> list[dict[str, Any]]:
        with self.tabs_snapshot_lock:
            if not self.last_tabs_snapshot or not self.last_tabs_snapshot_time:
                return []
            age = time.time() - self.last_tabs_snapshot_time
            if age > max_age_s or self.stop_flag.is_set():
                return []
            cached = [dict(t) for t in self.last_tabs_snapshot]
        for t in cached:
            t["transient_snapshot"] = True
        return cached

    async def _tab_info(self) -> list[dict[str, Any]]:
        """Return a robust snapshot of open browser tabs/pages.

        Firefox/Chromium can briefly give an empty or half-ready page list while
        a tab is navigating. The UI polls this every few seconds, so a single
        transient empty read used to make the table blink to "No tracked tabs".
        Keep returning a short last-known-good snapshot during those gaps.
        """
        out: list[dict[str, Any]] = []
        pages = self._live_pages_snapshot()
        for i, p in enumerate(pages, start=1):
            try:
                if p is None or p.is_closed():
                    continue
            except Exception:
                continue
            url = ""
            title = ""
            try:
                url = p.url or ""
            except Exception:
                url = ""
            try:
                title = await asyncio.wait_for(p.title(), timeout=0.75)
            except Exception:
                title = ""
            out.append({
                "index": i,
                "url": url,
                "title": title,
                "url_sha256": sha256_text(url) if url else "",
                "is_current": bool(p == self.active_page or p == self.page),
                "capturable": bool(url and not url.startswith(("about:", "chrome:", "edge:", "devtools:"))),
            })
        if out:
            self._remember_tabs_snapshot(out)
            return out
        return self._last_known_tabs_snapshot()

    def open_tabs_sync(self) -> list[dict[str, Any]]:
        if self.loop is None or self.loop.is_closed():
            return self._last_known_tabs_snapshot()
        try:
            return list(asyncio.run_coroutine_threadsafe(self._tab_info(), self.loop).result(timeout=10))
        except Exception:
            return self._last_known_tabs_snapshot()

    async def _capture_tab_index(self, tab_index: int) -> int:
        pages = self._live_pages_snapshot()
        idx = max(1, int(tab_index or 1)) - 1
        if idx < 0 or idx >= len(pages):
            raise HTTPException(404, f"Tracked browser tab #{tab_index} is not available")
        p = pages[idx]
        try:
            if p is None or p.is_closed():
                raise HTTPException(409, f"Tracked browser tab #{tab_index} is closed")
        except HTTPException:
            raise
        except Exception:
            pass
        url = getattr(p, "url", "") or ""
        if not url or url.startswith(("about:", "chrome:", "edge:", "devtools:")):
            raise HTTPException(409, f"Tracked browser tab #{tab_index} is not capturable yet: {url or 'blank'}")
        self.page = p
        self.active_page = p
        self.current_url = url
        execute("UPDATE browser_sessions SET current_url=? WHERE session_id=?", (self.current_url, self.session_id))
        return int(await self._capture_current(auto=False, page=p))

    def capture_tab_index_sync(self, tab_index: int) -> int:
        if self.loop is None or self.loop.is_closed() or self.stop_flag.is_set():
            execute("UPDATE browser_sessions SET status='stopped', stopped_at=coalesce(stopped_at, ?) WHERE session_id=?", (utcnow(), self.session_id))
            raise HTTPException(409, "This live browser session is no longer active. Start a new live session before capturing a tab.")
        fut = asyncio.run_coroutine_threadsafe(self._capture_tab_index(tab_index), self.loop)
        return int(fut.result(timeout=180))

    def stop_sync(self) -> None:
        self.stop_flag.set()


def start_live_session(*, actor: str, case_id: int | None, start_url: str, browser_choice: str, use_tor: bool, media_policy: str, headless: bool, user_agent_profile: str | None = None, custom_user_agent: str | None = None, download_allowed_media: bool = False, auto_capture: bool = False, settle_before_capture: bool = True, sealed_media_preservation_session: bool = True, capture_auto_scroll_session: bool = False, allow_captcha_challenge_media: bool = False) -> LiveBrowserSession:
    case = case_for(case_id)
    if browser_choice in {"torbrowser", "tor_managed_chromium", "tor_managed_firefox"}:
        use_tor = True
        if browser_choice == "torbrowser":
            headless = False
        if not user_agent_profile or user_agent_profile == "chrome_windows":
            user_agent_profile = "tor_browser_windows" if os.name == "nt" else "tor_browser_linux"
    if case and case.get("force_tor"):
        use_tor = True
    policy = effective_media_policy(case, media_policy)
    if case_safe(case) or lockdown():
        download_allowed_media = False
    sid = uuid.uuid4().hex[:16]
    ua_meta = user_agent_info(user_agent_profile, custom_user_agent)
    ensure_application_genesis_event(f"session:{sid}", case_id=case_id, session_id=sid, actor="system")
    session_genesis = application_genesis_report(investigation_id=f"session:{sid}")
    execute("""INSERT INTO browser_sessions(session_id,case_id,actor,browser_choice,start_url,use_tor,media_policy,headless,status,current_url,created_at,meta_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (sid, case_id, actor, browser_choice, normalize_url(start_url), 1 if use_tor else 0, policy, 1 if headless else 0, "starting", normalize_url(start_url), utcnow(), pretty({"version": APP_VERSION, "user_agent_profile": ua_meta["profile"], "user_agent_label": ua_meta["label"], "user_agent_sha256": ua_meta["user_agent_sha256"], "user_agent": ua_meta["user_agent"], "download_allowed_media": bool(download_allowed_media), "sealed_media_preservation": sealed_media_preservation_policy(case), "auto_capture": bool(auto_capture), "settle_before_capture": bool(settle_before_capture), "sealed_media_preservation_session": bool(sealed_media_preservation_session), "capture_settle_timeout_ms": get_setting("capture_settle_timeout_ms", "30000"), "capture_auto_scroll_enabled": get_setting("capture_auto_scroll_enabled", "0"), "capture_auto_scroll_session": bool(capture_auto_scroll_session), "allow_captcha_challenge_media": bool(allow_captcha_challenge_media), "application_genesis": session_genesis, "tor_browser_path": str(detect_tor_browser_executable() or "") if browser_choice == "torbrowser" else ""})))
    session = LiveBrowserSession(session_id=sid, case_id=case_id, actor=actor, start_url=start_url, browser_choice=browser_choice, use_tor=use_tor, media_policy=policy, headless=headless, user_agent_profile=ua_meta["profile"], custom_user_agent=custom_user_agent or "", download_allowed_media=download_allowed_media, auto_capture=auto_capture, settle_before_capture=settle_before_capture, sealed_media_preservation_session=sealed_media_preservation_session, capture_auto_scroll_session=capture_auto_scroll_session, allow_captcha_challenge_media=allow_captcha_challenge_media)
    with LIVE_LOCK:
        LIVE[sid] = session
    session.start()
    return session


def stop_live_session(sid: str) -> None:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        execute("UPDATE browser_sessions SET status='stopped', stopped_at=? WHERE session_id=?", (utcnow(), sid))
        return
    session.stop_sync()


def capture_live_session(sid: str) -> int:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process. Start a new live session.")
    return session.capture_current_sync()


def capture_all_live_session_tabs(sid: str) -> list[int]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process. Start a new live session.")
    return session.capture_all_open_tabs_sync()


def capture_live_session_tab(sid: str, tab_index: int) -> int:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process. Start a new live session.")
    return session.capture_tab_index_sync(tab_index)


def live_tabs_status_for(sid: str) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        row = rowdict(fetchone("SELECT * FROM browser_sessions WHERE session_id=?", (sid,)))
        return {"ok": False, "session_id": sid, "running": False, "tabs": [], "message": "Live session is not running in this app process", "db_status": row.get("status") if row else "missing"}
    tabs = session.open_tabs_sync()
    transient = any(bool(t.get("transient_snapshot")) for t in tabs)
    return {"ok": True, "session_id": sid, "running": not session.stop_flag.is_set(), "tabs": tabs, "count": len(tabs), "current_url": session.current_url, "transient_snapshot": transient}


def live_preservation_status_for(sid: str) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        row = rowdict(fetchone("SELECT * FROM browser_sessions WHERE session_id=?", (sid,)))
        if not row:
            # Avoid noisy 404 spam from old browser tabs polling stale live-session pages.
            return {"ok": False, "session_id": sid, "running": False, "status": "missing", "message": "Live session not found or no longer available", "progress_percent": 0, "blocked": 0, "pending_tasks": 0, "db_total": 0, "db_downloaded": 0, "db_not_downloaded": 0, "db_queue_full": 0, "outstanding": 0, "all_downloaded": False}
        meta = jloads(row.get("meta_json"), {})
        stats = blocked_media_session_stats(sid)
        pct = int((stats["downloaded"] / stats["total"]) * 100) if stats["total"] else 100
        outstanding = int(stats["not_downloaded"] or 0)
        return {"ok": True, "session_id": sid, "running": False, "status": row.get("status"), "mode": meta.get("sealed_media_preservation", {}).get("mode") or get_setting("sealed_media_preserve_mode", "balanced"), "requests": 0, "blocked": stats["total"], "pending_tasks": 0, "deferred_metadata_pending": 0, "preserved": stats["downloaded"], "preserved_bytes": 0, "skipped_or_failed": stats["not_downloaded"], "timeouts": stats["timeouts"], "cancelled": 0, "queue_limit": 0, "cancel_requested": False, "db_total": stats["total"], "db_downloaded": stats["downloaded"], "db_not_downloaded": stats["not_downloaded"], "db_queue_full": stats["queue_full"], "db_timeouts": stats["timeouts"], "outstanding": outstanding, "all_downloaded": bool(stats["total"] and outstanding == 0), "success_percent": pct, "completion_percent": 100, "progress_percent": pct}
    return session.preservation_status()


def cancel_live_preservation(sid: str) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process.")
    return session.cancel_preservation_sync()


def retry_live_blocked_media(sid: str, *, actor: str, blocked_ids: list[int] | None = None, retry_all_not_downloaded: bool = False, only_queue_full: bool = False) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process. Retry works while the live browser session is active so cookies/session state can be reused.")
    result = session.retry_blocked_media_records_sync(blocked_ids=blocked_ids, retry_all_not_downloaded=retry_all_not_downloaded, only_queue_full=only_queue_full)
    log_event(actor, "LIVE_BLOCKED_MEDIA_RETRY_REQUESTED", session_id=sid, case_id=session.case_id, details={"retry_all_not_downloaded": retry_all_not_downloaded, "only_queue_full": only_queue_full, "selected_count": len(blocked_ids or []), "result": result})
    return result


def early_access_warning_html() -> str:
    return """
    <div class='card warn' style='text-align:center;max-width:980px;margin:14px auto;'>
      <h2 style='margin-top:0'>Early-access safety notice</h2>
      <p><b>BlindSite is an early-access evidence-preservation tool.</b> Use it only for lawful investigations and only under policies you understand. File and media workflows can be risky depending on the content, facts, and jurisdiction.</p>
      <p><b>Sealed Sender / file-download mode</b> keeps media blocked from normal live viewing while preserving selected blocked files encrypted for sealed export and cleared-reviewer access. In Civilian Unknown Master Key mode, hard-sealed originals cannot be decrypted by the local civilian installation.</p>
      <p><b>Civilian use of Organization-Controlled Key mode:</b> use it only for lawful, non-risky investigations where no illegal or high-risk content will be downloaded or viewed. It can be appropriate when intentionally viewing ordinary, non-risky images/media is necessary.</p>
      <p class='small muted'>This is a technical custody and workflow control. It is not legal advice and does not guarantee legal protection. Default: file downloads enabled. You can change Sealed Sender globally in Settings, per case, and per live session.</p>
    </div>
    """


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    body = f"""{flash(error)}
    {early_access_warning_html()}
    <div class='card'><h2>Sign in</h2><form method='post' action='/login'><label>Username</label><input name='username' autofocus><label>Password</label><input name='password' type='password'><label><input type='checkbox' name='init_tor_session' value='1'> Initialize Tor in the background for this session</label><label><input type='checkbox' name='force_tor_all_cases' value='1'> Force Tor for all case captures/live sessions this sign-in session</label><p class='small muted'>Tor initialization is non-blocking. It prepares Tor so later Tor sessions do not have to wait, but it does not force normal traffic through Tor unless selected above or in a case/session.</p><div class='row' style='justify-content:center;align-items:center'><button class='good' style='flex:0 1 auto' name='sealed_sender_file_downloads' value='enabled'>Continue with file downloads enabled</button><button class='secondary' style='flex:0 1 auto' name='sealed_sender_file_downloads' value='disabled'>Continue with file downloads disabled</button></div></form><p class='muted'>First run default: admin / change-me-now</p></div>"""
    return layout(request, "Login", body)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), init_tor_session: str | None = Form(None), force_tor_all_cases: str | None = Form(None), sealed_sender_file_downloads: str = Form("enabled")) -> RedirectResponse:
    init_db()
    row = fetchone("SELECT * FROM users WHERE username=?", (username.strip(),))
    if not row or not check_password(password, row["password_hash"]):
        return RedirectResponse("/login?error=Invalid%20login", 303)
    sealed_sender_enabled = str(sealed_sender_file_downloads or "enabled").strip().lower() != "disabled"
    if truthy(row["require_webauthn"]):
        if not webauthn_user_has_credentials(row["username"]):
            log_event(row["username"], "YUBIKEY_LOGIN_BLOCKED_NO_CREDENTIAL", details={"username": row["username"]})
            return RedirectResponse("/login?error=YubiKey%20is%20required%20for%20this%20account%20but%20no%20key%20is%20enrolled", 303)
        request.session.clear()
        request.session["pending_webauthn_login_username"] = row["username"]
        request.session["pending_login_init_tor"] = "1" if init_tor_session else "0"
        request.session["pending_login_force_tor_all_cases"] = "1" if force_tor_all_cases else "0"
        request.session["pending_login_sealed_sender_enabled"] = "1" if sealed_sender_enabled else "0"
        log_event(row["username"], "YUBIKEY_LOGIN_REQUIRED", details={"init_tor_session": bool(init_tor_session), "force_tor_all_cases": bool(force_tor_all_cases), "sealed_sender_file_downloads_enabled": sealed_sender_enabled})
        return RedirectResponse("/webauthn/login", 303)
    request.session["username"] = row["username"]
    request.session["sealed_sender_file_downloads_enabled"] = "1" if sealed_sender_enabled else "0"
    set_setting("sealed_media_preservation_enabled", "1" if sealed_sender_enabled else "0")
    if force_tor_all_cases:
        request.session["force_tor_all_cases"] = "1"
    else:
        request.session.pop("force_tor_all_cases", None)
    log_event(row["username"], "LOGIN", details={"init_tor_session": bool(init_tor_session), "force_tor_all_cases": bool(force_tor_all_cases), "sealed_sender_file_downloads_enabled": sealed_sender_enabled, "yubikey_login": False})
    # Optional Tor prewarm is intentionally non-blocking. It starts/verifies the
    # Tor provider in the background so sign-in remains fast and normal traffic
    # is not forced through Tor unless a Tor browser/session is explicitly used.
    try:
        if init_tor_session or setting_bool("tor_background_prewarm_enabled", "0"):
            tor_prewarm_background("login-session" if init_tor_session else "login")
    except Exception:
        pass
    if get_setting("setup_required", "0") == "1" and row["role"] == "admin":
        return RedirectResponse("/setup", 303)
    return RedirectResponse("/", 303)


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    user = current_user(request)
    if user:
        log_event(user["username"], "LOGOUT")
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, msg: str | None = None) -> HTMLResponse:
    require_admin(request)
    bundled = load_uscm_escrow_public_key()
    body = f"""{flash(msg)}
    {early_access_warning_html()}
    <div class='card warn'><h2>First-run setup</h2><p>Choose who controls original reveal/decrypt authority. Organization-Controlled Key mode is for agencies, internal teams, and lawful non-risky civilian investigations where the operator may intentionally view ordinary non-risky images/media. Civilian Unknown Master Key mode is the safer default for unknown or risky investigations because sensitive originals are hard-sealed for USCM/law-enforcement handoff without the local civilian user knowing the reveal key.</p>
    <form method='post' action='/setup' enctype='multipart/form-data'>
      <label>New admin password</label><input type='password' name='password' required minlength='10'>
      <div class='grid'>
        <div class='card'><h3><label><input type='radio' name='custody_choice' value='organization' checked> Organization-Controlled Key</label></h3><p>Your organization/admin creates and controls the master reveal key. Normal evidence remains encrypted in the local vault and reveal is controlled by organization policy. Civilians should use this mode only for lawful, non-risky investigations where no illegal or high-risk content will be downloaded or viewed and where viewing ordinary non-risky images is intentional.</p><label>Master reveal key</label><input type='password' name='master_key' minlength='12'><label>Default edition</label><select name='edition'><option value='lockdown'>Lockdown / compliance-safe</option><option value='supervised'>Supervised approval mode</option><option value='lab'>Lab/full-forensic mode</option></select><label><input type='checkbox' name='hard_safe' value='1' checked> Hard default safe mode</label><div class='card warn'><h3>Optional organization hard-sealed media</h3><p class='small muted'>For blocked media preservation, an organization can paste its escrow public key so preserved blocked media is sealed for reviewer/private-key access and cannot be decrypted by the local vault key.</p><label><input type='checkbox' name='organization_hard_seal_media_enabled' value='1'> Hard-seal preserved blocked media to organization escrow public key</label><label>Organization escrow public key PEM</label><textarea name='organization_hard_seal_public_key_pem' rows='7' placeholder='Paste organization/reviewer escrow_public_key.pem here'></textarea></div></div>
        <div class='card safe'><h3><label><input type='radio' name='custody_choice' value='civilian_unknown_master'> Civilian Unknown Master Key</label></h3><p>The local user does not create, know, or control the private reveal key. Lockdown stays forced. Sensitive/original evidence is hard-sealed to the embedded USCM escrow public key so it cannot be decrypted by the local civilian installation. Use this mode for unknown, risky, or handoff-focused investigations.</p><label>USCM escrow public key PEM</label><textarea name='escrow_public_key' rows='9' readonly>{h(bundled)}</textarea><p class='small muted'>Civilian Unknown Master Key mode uses this USCM public key only. Do not use your own key for this mode; doing so defeats the custody separation. Organizations that need to control their own keys should use Organization-Controlled Key mode.</p></div>
        <div class='card warn'><h3>Sealed Media Preservation Mode</h3><p class='small muted'>Optional in both custody modes. Block images/video/audio from user display, but preserve selected blocked media for sealed export and cleared-reviewer access. Civilian mode always hard-seals to the USCM key. Organization mode can either use normal local vault encryption or the optional organization hard-seal public key above.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' checked> Enable Sealed Sender / file downloads by default</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' checked> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' checked> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' checked> Preserve blocked audio encrypted</label><label>Maximum bytes per preserved media object</label><input name='sealed_media_preserve_max_bytes' value='52428800'><p class='small muted'>Default is 52,428,800 bytes. Preserved media never renders in the live browser when blocked; it is stored encrypted and linked to captured pages for sealed export/reviewer viewing.</p></div>
        <div class='card good'><h3>Law-enforcement / cleared reviewer import</h3><p>Optional: initialize this installation as a reviewer workstation by importing a sealed evidence ZIP now. You can also do this later from <b>LE Reviewer</b>.</p><label>Sealed BlindSite evidence ZIP</label><input type='file' name='reviewer_package' accept='.zip'><label>Escrow private key PEM</label><input type='file' name='reviewer_private_key' accept='.pem,.key,.txt'><label>Private-key passphrase, if any</label><input type='password' name='reviewer_private_key_passphrase'><label>Reviewer import note</label><textarea name='reviewer_note' placeholder='agency/case note'></textarea></div>
      </div>
      <button class='good'>Finish setup</button>
    </form></div>"""
    return layout(request, "Setup", body)


@app.post("/setup")
async def setup_submit(request: Request, password: str = Form(...), custody_choice: str = Form("organization"), master_key: str = Form(""), escrow_public_key: str = Form(""), organization_hard_seal_media_enabled: str | None = Form(None), organization_hard_seal_public_key_pem: str = Form(""), edition: str = Form("lockdown"), hard_safe: str | None = Form(None), sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800"), reviewer_package: UploadFile | None = File(None), reviewer_private_key: UploadFile | None = File(None), reviewer_private_key_passphrase: str = Form(""), reviewer_note: str = Form("")) -> RedirectResponse:
    user = require_admin(request)
    if len(password) < 10:
        raise HTTPException(400, "Admin password must be at least 10 characters")
    if edition not in EDITIONS:
        edition = "lockdown"
    execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(password), user["username"]))
    if custody_choice == "civilian_unknown_master":
        # Civilian Unknown Master Key mode is intentionally NOT a user-supplied
        # key workflow. The civilian collector must not possess or control the
        # private reveal key, so this mode uses the embedded USCM escrow public
        # key only. Organization-Controlled Key mode remains available for
        # organizations that need to control their own keys.
        pem = load_uscm_escrow_public_key().strip()
        fp = escrow_public_fingerprint(pem)
        if not pem or not fp:
            raise HTTPException(400, "Civilian Unknown Master Key mode requires the embedded USCM RSA escrow public key")
        submitted_fp = escrow_public_fingerprint((escrow_public_key or "").strip()) if (escrow_public_key or "").strip() else fp
        if submitted_fp and submitted_fp != fp:
            raise HTTPException(400, "Civilian Unknown Master Key mode uses the USCM escrow public key only. Do not use your own key for this mode.")
        hidden_master = secrets.token_urlsafe(40)
        set_master_key(hidden_master)
        set_setting("custody_mode", "civilian_unknown_master")
        set_setting("escrow_public_key_pem", pem)
        set_setting("escrow_public_key_fingerprint", fp)
        set_setting("wrapped_master_key", escrow_wrap(pem, hidden_master.encode("utf-8")))
        set_setting("wrapped_storage_key", escrow_wrap(pem, KEY_FILE.read_bytes()))
        edition = "lockdown"
        hard_safe = "1"
        for k in ["disable_full_reveal_in_lockdown", "disable_plaintext_export_in_lockdown", "disable_materialization_in_lockdown", "require_master_key_full_reveal", "require_approval_full_reveal", "require_approval_plaintext_export", "require_approval_materialization"]:
            set_setting(k, "1")
        set_setting("sealed_media_preservation_enabled", "1" if sealed_media_preservation_enabled else "0")
        set_setting("sealed_media_preserve_images", "1" if sealed_media_preserve_images else "0")
        set_setting("sealed_media_preserve_video", "1" if sealed_media_preserve_video else "0")
        set_setting("sealed_media_preserve_audio", "1" if sealed_media_preserve_audio else "0")
        set_setting("sealed_media_preserve_max_bytes", str(safe_int(sealed_media_preserve_max_bytes, 52428800, min_value=1048576)))
    else:
        if len(master_key or "") < 12:
            raise HTTPException(400, "Organization-Controlled Key mode requires a master reveal key of at least 12 characters")
        set_master_key(master_key)
        set_setting("custody_mode", "organization")
        org_pem = (organization_hard_seal_public_key_pem or "").strip()
        org_fp = escrow_public_fingerprint(org_pem) if org_pem else ""
        if organization_hard_seal_media_enabled and not org_fp:
            raise HTTPException(400, "Organization hard-sealed media requires a valid organization escrow public key PEM")
        set_setting("organization_hard_seal_media_enabled", "1" if organization_hard_seal_media_enabled else "0")
        set_setting("organization_hard_seal_public_key_pem", org_pem if org_fp else "")
        set_setting("organization_hard_seal_public_key_fingerprint", org_fp)
    set_setting("sealed_media_preservation_enabled", "1" if sealed_media_preservation_enabled else "0")
    set_setting("sealed_media_preserve_images", "1" if sealed_media_preserve_images else "0")
    set_setting("sealed_media_preserve_video", "1" if sealed_media_preserve_video else "0")
    set_setting("sealed_media_preserve_audio", "1" if sealed_media_preserve_audio else "0")
    set_setting("sealed_media_preserve_max_bytes", str(safe_int(sealed_media_preserve_max_bytes, 52428800, min_value=1048576)))
    if custody_choice == "civilian_unknown_master":
        set_setting("organization_hard_seal_media_enabled", "0")
    set_setting("edition", edition)
    set_setting("default_case_mode", edition)
    set_setting("hard_default_safe_mode", "1" if hard_safe else "0")
    set_setting("setup_required", "0")
    if organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0"):
        try:
            migrate_existing_organization_preserved_media_to_hard_sealed()
        except Exception:
            pass
    log_event(user["username"], "FIRST_RUN_SETUP_COMPLETED", details={"edition": edition, "hard_safe": bool(hard_safe), "custody_mode": custody_mode(), "sealed_media_preservation_enabled": setting_bool("sealed_media_preservation_enabled", "0"), "organization_hard_seal_media_enabled": setting_bool("organization_hard_seal_media_enabled", "0"), "organization_hard_seal_public_key_fingerprint": get_setting("organization_hard_seal_public_key_fingerprint", "")})
    package_supplied = bool(reviewer_package and reviewer_package.filename)
    key_supplied = bool(reviewer_private_key and reviewer_private_key.filename)
    if package_supplied or key_supplied:
        if not (package_supplied and key_supplied):
            raise HTTPException(400, "Reviewer setup import requires both the sealed ZIP and the escrow private key PEM")
        package_bytes = await reviewer_package.read()  # type: ignore[union-attr]
        private_pem = await reviewer_private_key.read()  # type: ignore[union-attr]
        import_id = reviewer_import_package(package_bytes, reviewer_package.filename or "sealed_evidence.zip", private_pem, reviewer_private_key_passphrase, user["username"], reviewer_note or "first-run reviewer import")
        return RedirectResponse(f"/reviewer/imports/{import_id}/viewer?msg=Setup%20complete%20and%20sealed%20package%20imported", 303)
    return RedirectResponse("/?msg=Setup%20complete", 303)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, msg: str | None = None, error: str | None = None) -> HTMLResponse:
    user = require_user(request)
    if get_setting("setup_required", "0") == "1" and user["role"] == "admin":
        return RedirectResponse("/setup", 303)  # type: ignore
    counts = {
        "cases": fetchone("SELECT count(*) c FROM cases")["c"],
        "evidence": fetchone("SELECT count(*) c FROM evidence")["c"],
        "blocked": fetchone("SELECT count(*) c FROM blocked_media")["c"],
        "sessions": fetchone("SELECT count(*) c FROM browser_sessions")["c"],
        "pending": fetchone("SELECT count(*) c FROM approvals WHERE status='pending'")["c"],
        "captures": fetchone("SELECT count(*) c FROM page_captures")["c"],
        "media": fetchone("SELECT count(*) c FROM evidence WHERE lower(kind) IN ('image','video','audio','media') OR lower(mime_type) LIKE 'image/%' OR lower(mime_type) LIKE 'video/%' OR lower(mime_type) LIKE 'audio/%'")["c"],
        "reviewer_imports": fetchone("SELECT count(*) c FROM reviewer_imports")["c"],
    }
    audit = verify_audit_chain()
    recent = fetchall("SELECT * FROM evidence ORDER BY id DESC LIMIT 10")
    rows = "".join(f"<tr><td><a href='/evidence/{r['id']}'>#{r['id']}</a></td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td>{h(r['storage_mode'])}</td><td><code>{h(r['sha256'][:18])}…</code></td></tr>" for r in recent)
    body = f"""{flash(msg or error)}<div class='grid'>
      <div class='card'><h2>Cases</h2><p class='big'>{counts['cases']}</p><a class='button' href='/cases'>Open cases</a></div>
      <div class='card'><h2>Evidence</h2><p class='big'>{counts['evidence']}</p><a class='button' href='/search'>Search</a></div>
      <div class='card safe'><h2>Blocked media</h2><p class='big'>{counts['blocked']}</p><a class='button' href='/blocked'>Review metadata</a></div>
      <div class='card good'><h2>Saved pages</h2><p class='big'>{counts['captures']}</p><a class='button good' href='/captures'>Open saved pages</a></div>
      <div class='card'><h2>Media</h2><p class='big'>{counts['media']}</p><a class='button' href='/media'>Media gallery</a></div>
      <div class='card safe'><h2>LE Reviewer imports</h2><p class='big'>{counts['reviewer_imports']}</p><a class='button good' href='/reviewer'>Open reviewer</a></div>
      <div class='card'><h2>Live sessions</h2><p class='big'>{counts['sessions']}</p><a class='button good' href='/live'>Start browser session</a></div>
      <div class='card {'safe' if audit['ok'] else 'danger'}'><h2>Audit chain</h2><p>{badge('verified','good') if audit['ok'] else badge('tamper warning','bad')}</p><p class='small mono'>Head: {h(audit['head'][:32])}…</p><a class='button' href='/audit/verify'>Verify</a></div>
      <div class='card warn'><h2>Pending approvals</h2><p class='big'>{counts['pending']}</p><a class='button warn' href='/approvals'>Approvals</a></div>
    </div><div class='card'><h2>Recent evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>Storage</th><th>SHA-256</th></tr>{rows}</table></div>"""
    return layout(request, "Dashboard", body)


@app.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request) -> HTMLResponse:
    require_user(request)
    rows = fetchall("SELECT * FROM cases ORDER BY id DESC")
    table_rows = []
    for rr in rows:
        r = rowdict(rr)
        table_rows.append(f"<tr><td><a href='/cases/{r['id']}'>#{r['id']}</a></td><td>{h(r['name'])}</td><td>{hashtag_badges(r.get('hashtags') or '')}</td><td>{badge(r['mode'],'good' if r['mode']=='lockdown' else 'warn')}</td><td>{badge('safe','good') if r['compliance_safe'] else badge('not safe','warn')}</td><td>{h(r['default_media_policy'])}</td><td>{badge('sealed media preserve','warn') if r['sealed_media_preservation_enabled'] else ''}</td><td>{h(r['created_at'])}</td></tr>")
    table = "".join(table_rows)
    body = f"""<div class='card'><h2>Create case</h2><form method='post' action='/cases'>
      <label>Name</label><input name='name' required>
      <label>Description</label><textarea name='description'></textarea>
      <label>Case hashtags</label><input name='hashtags' placeholder='#priority #agency #casework'>
      <div class='row'><div><label>Mode</label><select name='mode'><option value='lockdown'>Lockdown</option><option value='supervised'>Supervised</option><option value='lab'>Lab/full-forensic</option></select></div>
      <div><label>Default media policy</label><select name='media_policy'><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div>
      <label><input type='checkbox' name='force_tor' value='1' {'checked' if request.session.get('force_tor_all_cases') else ''}> Force Tor for this case {'(session default)' if request.session.get('force_tor_all_cases') else ''}</label>
      <label><input type='checkbox' name='raw_root_allowed' value='1'> Allow raw root persistence in lab/supervised workflows</label>
      <div class='card warn'><h3>Sealed Media Preservation for this case</h3><p class='small muted'>Active in both custody modes when the global setting and this case setting are enabled. Media remains blocked from display, but selected blocked media can be stored encrypted for sealed export and cleared review.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' {'checked' if setting_bool('sealed_media_preservation_enabled','1') else ''}> Enable for this case</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' checked> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' checked> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' checked> Preserve blocked audio encrypted</label><label>Case max bytes per preserved media object</label><input name='sealed_media_preserve_max_bytes' value='{h(get_setting('sealed_media_preserve_max_bytes','52428800'))}'></div>
      <button>Create case</button></form></div>
      <div class='card'><h2>Cases</h2><table><tr><th>ID</th><th>Name</th><th>Hashtags</th><th>Mode</th><th>Safe</th><th>Media policy</th><th>Sealed media</th><th>Created</th></tr>{table}</table></div>"""
    return layout(request, "Cases", body)


@app.post("/cases")
def create_case(request: Request, name: str = Form(...), description: str = Form(""), mode: str = Form("lockdown"), media_policy: str = Form("block_images_video"), force_tor: str | None = Form(None), raw_root_allowed: str | None = Form(None), sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800"), hashtags: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    if mode not in EDITIONS:
        mode = "lockdown"
    if media_policy not in MEDIA_POLICIES:
        media_policy = "block_images_video"
    compliance = 1 if mode == "lockdown" or setting_bool("hard_default_safe_mode", "1") else 0
    cid = execute("""INSERT INTO cases(name,description,mode,compliance_safe,irreversible_lock,never_materialize_originals,no_plaintext_export,raw_root_allowed,default_media_policy,force_tor,quarantine_default,sealed_media_preservation_enabled,sealed_media_preserve_images,sealed_media_preserve_video,sealed_media_preserve_audio,sealed_media_preserve_max_bytes,hashtags,created_by,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (name.strip(), description, mode, compliance, 1 if mode == "lockdown" else 0, 1 if mode in {"lockdown", "supervised"} else 0, 1 if mode in {"lockdown", "supervised"} else 0, 1 if raw_root_allowed else 0, media_policy, 1 if (force_tor or request.session.get("force_tor_all_cases")) else 0, 1, 1 if sealed_media_preservation_enabled else 0, 1 if sealed_media_preserve_images else 0, 1 if sealed_media_preserve_video else 0, 1 if sealed_media_preserve_audio else 0, safe_int(sealed_media_preserve_max_bytes, safe_int(get_setting("sealed_media_preserve_max_bytes", "52428800"), 52428800, min_value=1048576), min_value=1048576), normalize_hashtags(hashtags), user["username"], utcnow()))
    ensure_application_genesis_event(f"case:{cid}", case_id=cid, actor="system")
    log_event(user["username"], "CASE_CREATED", case_id=cid, details={"mode": mode, "media_policy": media_policy, "force_tor": bool(force_tor or request.session.get("force_tor_all_cases")), "sealed_media_preservation_enabled": bool(sealed_media_preservation_enabled), "hashtags": normalize_hashtags(hashtags), "application_genesis": application_genesis_report(case_id=cid)})
    return RedirectResponse(f"/cases/{cid}", 303)


@app.post("/cases/{case_id}/hashtags")
def case_hashtags_update(request: Request, case_id: int, hashtags: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    tags = normalize_hashtags(hashtags)
    execute("UPDATE cases SET hashtags=? WHERE id=?", (tags, case_id))
    log_event(user["username"], "CASE_HASHTAGS_UPDATED", case_id=case_id, details={"hashtags": tags})
    return RedirectResponse(f"/cases/{case_id}?msg=Case%20hashtags%20saved", 303)


@app.post("/cases/{case_id}/sealed-media-preservation")
def case_sealed_media_preservation_update(request: Request, case_id: int, sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800"), hashtags: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    max_bytes = safe_int(sealed_media_preserve_max_bytes, safe_int(get_setting("sealed_media_preserve_max_bytes", "52428800"), 52428800, min_value=1048576), min_value=1048576)
    execute("""UPDATE cases SET sealed_media_preservation_enabled=?, sealed_media_preserve_images=?, sealed_media_preserve_video=?, sealed_media_preserve_audio=?, sealed_media_preserve_max_bytes=? WHERE id=?""", (1 if sealed_media_preservation_enabled else 0, 1 if sealed_media_preserve_images else 0, 1 if sealed_media_preserve_video else 0, 1 if sealed_media_preserve_audio else 0, max_bytes, case_id))
    log_event(user["username"], "CASE_SEALED_MEDIA_PRESERVATION_UPDATED", case_id=case_id, details={"enabled": bool(sealed_media_preservation_enabled), "images": bool(sealed_media_preserve_images), "video": bool(sealed_media_preserve_video), "audio": bool(sealed_media_preserve_audio), "max_bytes": max_bytes})
    return RedirectResponse(f"/cases/{case_id}?msg=Sealed%20media%20preservation%20settings%20saved", 303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: int, msg: str | None = None) -> HTMLResponse:
    require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    evs = fetchall("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC LIMIT 100", (case_id,))
    blocked = fetchall("SELECT * FROM blocked_media WHERE case_id=? ORDER BY id DESC LIMIT 50", (case_id,))
    captures = page_captures_for_case(case_id)
    ev_rows = "".join(f"<tr><td><a href='/evidence/{r['id']}'>#{r['id']}</a></td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td>{h(r['storage_mode'])}</td><td>{badge('quarantine','warn') if r['quarantined'] else ''}</td></tr>" for r in evs)
    b_rows = "".join(f"<tr><td><a href='/blocked/{r['id']}'>#{r['id']}</a></td><td>{h(r['resource_type'])}</td><td class='small'>{h(r['media_url'][:100])}</td><td><code>{h(r['url_sha256'][:18])}…</code></td></tr>" for r in blocked)
    cap_rows = "".join(f"<tr><td><a class='button good' href='/cases/{case_id}/pages?eid={c['evidence_id']}'>Open in case viewer</a></td><td><a href='/evidence/{c['evidence_id']}/page-render'>Full renderer</a></td><td><a href='/evidence/{c['evidence_id']}'>Evidence #{c['evidence_id']}</a></td><td>{h(c['title'] or c['filename'] or 'Saved page')}</td><td>{h(c['capture_mode'])}</td><td>{badge('exact-capable','warn') if c['raw_persisted'] else badge('safe-summary','good')}</td><td class='urlcell'>{h(c['page_url'])}</td></tr>" for c in captures)
    sealed_preserved_count = fetchone("SELECT count(*) c FROM evidence WHERE case_id=? AND storage_mode=?", (case_id, SEALED_PRESERVED_STORAGE_MODE))["c"]
    sealed_form = f"""<div class='card warn'><h2>Sealed Media Preservation Mode</h2><p>{badge('global on','good') if setting_bool('sealed_media_preservation_enabled','0') else badge('global off','warn')} {badge('case on','good') if case.get('sealed_media_preservation_enabled') else badge('case off','warn')} {badge(custody_label(),'info')} {badge('preserved '+str(sealed_preserved_count),'info')}</p><p class='small muted'>When active, blocked images/video/audio stay blocked from normal display, but are stored as encrypted vault evidence for sealed export and reviewer decrypt/import. Organization-mode local reveal still requires the master-key workflow; Civilian Unknown Master Key mode keeps local reveal blocked.</p><form method='post' action='/cases/{case_id}/sealed-media-preservation'><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' {'checked' if case.get('sealed_media_preservation_enabled') else ''}> Enable for this case</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' {'checked' if case.get('sealed_media_preserve_images') else ''}> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' {'checked' if case.get('sealed_media_preserve_video') else ''}> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' {'checked' if case.get('sealed_media_preserve_audio') else ''}> Preserve blocked audio encrypted</label><label>Case max bytes per preserved media object</label><input name='sealed_media_preserve_max_bytes' value='{h(case.get('sealed_media_preserve_max_bytes') or get_setting('sealed_media_preserve_max_bytes','52428800'))}'><button class='warn'>Save sealed media preservation settings</button></form></div>"""
    quick_viewer = ""
    if captures:
        latest = captures[0]
        quick_viewer = f"""<div class='card good'><h2>Latest saved page quick viewer</h2><p>{badge('safe render','good')} <span class='small muted'>This embedded preview uses the safe no-network renderer. Open the full case page viewer to unlock exact local rendering with saved images/video/CSS.</span></p><p><a class='button good' href='/cases/{case_id}/pages?eid={latest['evidence_id']}'>Open full case page viewer</a> <a class='button' href='/evidence/{latest['evidence_id']}/page-render'>Open renderer controls</a></p><iframe class='render-frame' sandbox='allow-same-origin' src='/evidence/{latest['evidence_id']}/page-render-frame?render=safe'></iframe></div>"""
    body = f"""{flash(msg)}<div class='card'><h2>{h(case['name'])}</h2><p>{badge(case['mode'],'good' if case['mode']=='lockdown' else 'warn')} {badge('compliance-safe','good') if case['compliance_safe'] else badge('review/lab','warn')} {badge('force Tor','info') if case['force_tor'] else ''} {badge('irreversible lock','warn') if case['irreversible_lock'] else ''} {hashtag_badges(case.get('hashtags') or '')}</p><form method='post' action='/cases/{case_id}/hashtags' class='noprint'><label>Case hashtags</label><input name='hashtags' value='{h(normalize_hashtags(case.get('hashtags') or ''))}' placeholder='#priority #agency #casework'><button class='secondary'>Save case hashtags</button></form><pre>{h(pretty(case))}</pre><p><a class='button' href='/cases/{case_id}/report'>Case report</a> <a class='button' href='/cases/{case_id}/report.zip'>Report-only ZIP</a> <a class='button good' href='/cases/{case_id}/pages'>Case page viewer</a> <a class='button good' href='/captures?case_id={case_id}'>Saved pages</a> <a class='button' href='/media?case_id={case_id}'>Media</a> <a class='button warn' href='/cases/{case_id}/sealed-export'>Sealed LE Export</a></p><form method='post' action='/cases/{case_id}/rendered-export' class='noprint' data-webauthn-action='plaintext_export' data-webauthn-if-checked='include_assets'><h3>Export offline saved-page viewer ZIP</h3><label><input type='checkbox' name='include_assets' value='1'> Include saved local image/video/audio/style/font assets where policy permits</label><label>Master key required if including viewable assets</label><input type='password' name='master_key'><button class='warn'>Export viewer ZIP</button></form></div>{sealed_form}{quick_viewer}
    <div class='grid'><div class='card'><h2>Upload evidence</h2><form method='post' action='/upload' enctype='multipart/form-data'><input type='hidden' name='case_id' value='{case_id}'><label>File</label><input type='file' name='file' required><label><input type='checkbox' name='quarantine' value='1' checked> Quarantine on intake</label><button>Upload</button></form></div>
    <div class='card'><h2>Direct URL capture</h2><form method='post' action='/capture'><input type='hidden' name='case_id' value='{case_id}'><label>URL</label><input name='url' placeholder='https://example.org' required><div class='row'><div><label>Mode</label><select name='capture_mode'><option value='metadata_only'>Metadata only</option><option value='safe_summary'>Sanitized summary</option><option value='evidence_safe'>Evidence safe</option><option value='full_forensic'>Full forensic</option></select></div><div><label>Media policy</label><select name='media_policy'><option value='{h(case['default_media_policy'])}'>{h(case['default_media_policy'])} (case default)</option><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div><div class='row'><div><label>User agent</label><select name='user_agent_profile'>{ua_select_html('user_agent_profile')}</select></div><div><label>Custom UA, if selected</label><input name='custom_user_agent' placeholder='optional custom user agent'></div></div><label><input type='checkbox' name='use_tor' value='1' {'checked' if case['force_tor'] or request.session.get('force_tor_all_cases') else ''}> Use Tor SOCKS</label><label><input type='checkbox' name='download_allowed_media' value='1'> In lab/full-forensic only: download allowed original media unblurred</label><button>Capture URL</button></form></div>
    <div class='card good'><h2>Start visible live browser</h2><form method='post' action='/live/start'><input type='hidden' name='case_id' value='{case_id}'><label>Start URL</label><input name='start_url' value='https://www.google.com' required><div class='row'><div><label>Browser</label><select name='browser_choice'>{browser_select_html('browser_choice')}</select></div><div><label>Media policy</label><select name='media_policy'><option value='{h(case['default_media_policy'])}'>{h(case['default_media_policy'])} (case default)</option><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div><div class='row'><div><label>User agent</label><select name='user_agent_profile'>{ua_select_html('user_agent_profile')}</select></div><div><label>Custom UA, if selected</label><input name='custom_user_agent' placeholder='optional custom user agent'></div></div><label><input type='checkbox' name='use_tor' value='1' {'checked' if case['force_tor'] or request.session.get('force_tor_all_cases') else ''}> Route browser through Tor</label><label><input type='checkbox' name='download_allowed_media' value='1' {'checked' if setting_bool('live_download_allowed_media_default','0') else ''}> Lab/full-forensic only: save allowed images/video/audio for exact page renderer</label><label><input type='checkbox' name='sealed_media_preservation_session' value='1' {'checked' if sealed_media_preservation_policy(case).get('enabled') else ''}> Block display, preserve blocked media encrypted for sealed export in this session</label><label><input type='checkbox' name='allow_captcha_challenge_media' value='1' {'checked' if setting_bool('live_allow_captcha_challenge_media_default','0') else ''}> Allow only CAPTCHA/challenge images, including inline/base64 data images, while other media remains blocked</label><label><input type='checkbox' name='settle_before_capture' value='1' {'checked' if setting_bool('capture_settle_before_save','1') else ''}> Before manual/auto capture, wait for page load/DOM settle</label><label><input type='checkbox' name='capture_auto_scroll_session' value='1' {'checked' if setting_bool('capture_auto_scroll_enabled','0') else ''}> Before capture, auto-scroll to trigger lazy-loaded content</label><label><input type='checkbox' name='auto_capture' value='1' {'checked' if setting_bool('live_auto_capture_default','0') else ''}> Auto-capture each new page after it settles</label><label><input type='checkbox' name='headless' value='1'> Headless instead of visible</label><button class='good'>Open controlled browser</button></form></div></div>
    <div class='card'><h2>Saved page captures / case page viewer</h2><p class='small muted'>Open case page viewer to render the captured page from locally saved bytes. In lab/full-forensic captures with saved media, the renderer can show saved images/video/audio without contacting the live site.</p><div class='table-scroll'><table><tr><th>Case viewer</th><th>Full renderer</th><th>Evidence</th><th>Title</th><th>Mode</th><th>Renderer state</th><th>URL</th></tr>{cap_rows or '<tr><td colspan="7" class="muted">No saved pages yet. Start a live session and click Capture Current Page, or use Direct URL capture.</td></tr>'}</table></div></div><div class='card'><h2>Evidence</h2><table><tr><th>ID</th><th>File</th><th>Kind</th><th>Storage</th><th>Status</th></tr>{ev_rows}</table></div><div class='card'><h2>Blocked media records</h2><table><tr><th>ID</th><th>Type</th><th>URL</th><th>URL hash</th></tr>{b_rows}</table></div>"""
    return layout(request, f"Case #{case_id}", body)


@app.post("/upload")
async def upload(request: Request, case_id: int = Form(...), file: UploadFile = File(...), quarantine: str | None = Form(None)) -> RedirectResponse:
    user = require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    data = await file.read()
    mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    eid = persist_evidence(case_id=case_id, actor=user["username"], kind=kind_for(mime_type, file.filename or ""), source_type="upload", source_ref=file.filename, filename=file.filename or "upload.bin", mime_type=mime_type, payload=data, encrypt=setting_bool("default_encrypt", "1"), storage_mode="uploaded_original", raw_persisted=True, meta={"upload_content_type": file.content_type}, quarantined=bool(quarantine))
    return RedirectResponse(f"/evidence/{eid}", 303)


@app.post("/capture")
def capture_route(request: Request, case_id: int | None = Form(None), url: str = Form(...), capture_mode: str = Form("metadata_only"), media_policy: str = Form("block_images_video"), use_tor: str | None = Form(None), download_allowed_media: str | None = Form(None), user_agent_profile: str = Form(""), custom_user_agent: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    case = case_for(case_id)
    options = CaptureOptions(use_tor=bool(use_tor or request.session.get("force_tor_all_cases")), capture_mode=effective_capture_mode(case, capture_mode), media_policy=effective_media_policy(case, media_policy), encrypt=True, download_allowed_media=bool(download_allowed_media), head_probe_blocked_media=setting_bool("head_probe_blocked_media", "1"), max_root_read_bytes=int(get_setting("max_root_read_bytes", "524288")), max_blocked_records=int(get_setting("max_blocked_records", "1000")), user_agent_profile=user_agent_profile or get_setting("default_user_agent_profile", "chrome_windows"), custom_user_agent=custom_user_agent)
    try:
        result = capture_direct(url, case_id, user["username"], options)
        return RedirectResponse(f"/evidence/{result['root_evidence_id']}/capture-view?msg=URL%20capture%20saved", 303)
    except Exception as exc:
        log_event(user["username"], "URL_CAPTURE_FAILED", case_id=case_id, details={"url_sha256": sha256_text(url), "error": str(exc)})
        return RedirectResponse(f"/cases/{case_id or ''}?msg=Capture%20failed:%20{h(str(exc))}", 303)


@app.get("/live", response_class=HTMLResponse)
def live_page(request: Request, msg: str | None = None) -> HTMLResponse:
    require_user(request)
    rows = fetchall("SELECT s.*,c.name case_name FROM browser_sessions s LEFT JOIN cases c ON c.id=s.case_id ORDER BY s.id DESC LIMIT 100")
    cases = fetchall("SELECT id,name,default_media_policy,force_tor FROM cases ORDER BY id DESC")
    case_options = "<option value=''>No case</option>" + "".join(f"<option value='{r['id']}'>{h(r['name'])}</option>" for r in cases)
    sess_rows = "".join(f"<tr><td><a href='/live/{r['session_id']}'>{h(r['session_id'])}</a></td><td>{h(r['case_name'] or '')}</td><td>{h(r['actor'])}</td><td>{h(r['browser_choice'])}</td><td>{badge('Tor','info') if r['use_tor'] else 'Direct'}</td><td>{badge(r['status'],'good' if r['status']=='running' else 'warn' if r['status']=='starting' else '')}</td><td class='small'>{h((r['current_url'] or r['start_url'])[:120])}</td></tr>" for r in rows)
    body = f"""{flash(msg)}<div class='card good'><h2>Start visible controlled browser</h2><p>This opens its own controlled Playwright browser window. Browse manually, then return here and click <b>Capture Current Page</b>. Media policy blocks images/video/audio before body download.</p><form method='post' action='/live/start'>
      <div class='row'><div><label>Case</label><select name='case_id'>{case_options}</select></div><div><label>Browser</label><select name='browser_choice'>{browser_select_html('browser_choice')}</select></div></div>
      <label>Start URL</label><input name='start_url' value='https://www.google.com' required>
      <div class='row'><div><label>Media policy</label><select name='media_policy'><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div><div><label>Mode note</label><input value='Capture uses case policy; safe mode stores summary/metadata, not raw HTML.' readonly></div></div>
      <div class='row'><div><label>User agent</label><select name='user_agent_profile'>{ua_select_html('user_agent_profile')}</select></div><div><label>Custom UA, if selected</label><input name='custom_user_agent' placeholder='optional custom user agent'></div></div>
      <label><input type='checkbox' name='use_tor' value='1' {'checked' if request.session.get('force_tor_all_cases') else ''}> Route browser through Tor SOCKS {'(forced for this sign-in session)' if request.session.get('force_tor_all_cases') else ''}</label>
      <label><input type='checkbox' name='download_allowed_media' value='1' {'checked' if setting_bool('live_download_allowed_media_default','0') else ''}> Lab/full-forensic only: save allowed images/video/audio/CSS for exact page renderer</label>
      <label><input type='checkbox' name='sealed_media_preservation_session' value='1' {'checked' if setting_bool('sealed_media_preservation_enabled','0') else ''}> Block display, preserve blocked media encrypted for sealed export in this session</label>
      <label><input type='checkbox' name='allow_captcha_challenge_media' value='1' {'checked' if setting_bool('live_allow_captcha_challenge_media_default','0') else ''}> Allow only CAPTCHA/challenge images, including inline/base64 data images, while other media remains blocked</label>
      <label><input type='checkbox' name='settle_before_capture' value='1' {'checked' if setting_bool('capture_settle_before_save','1') else ''}> Before manual/auto capture, wait for page load/DOM settle</label>
      <label><input type='checkbox' name='capture_auto_scroll_session' value='1' {'checked' if setting_bool('capture_auto_scroll_enabled','0') else ''}> Before capture, auto-scroll to trigger lazy-loaded content</label>
      <label><input type='checkbox' name='auto_capture' value='1' {'checked' if setting_bool('live_auto_capture_default','0') else ''}> Auto-capture each new page after it settles</label>
      <label><input type='checkbox' name='headless' value='1'> Headless instead of visible</label>
      <button class='good'>Open controlled browser window</button>
    </form><p class='muted small'>If browser binaries are missing, run <code>python BlindSite.py --install-browsers</code>.</p></div><div class='card'><h2>Sessions</h2><table><tr><th>Session</th><th>Case</th><th>Actor</th><th>Browser</th><th>Route</th><th>Status</th><th>Current URL</th></tr>{sess_rows}</table></div>"""
    return layout(request, "Live Sessions", body)


@app.post("/live/start")
def live_start(request: Request, case_id: str = Form(""), start_url: str = Form(...), browser_choice: str = Form("chromium"), media_policy: str = Form("block_images_video"), use_tor: str | None = Form(None), headless: str | None = Form(None), download_allowed_media: str | None = Form(None), sealed_media_preservation_session: str | None = Form(None), allow_captcha_challenge_media: str | None = Form(None), auto_capture: str | None = Form(None), settle_before_capture: str | None = Form(None), capture_auto_scroll_session: str | None = Form(None), user_agent_profile: str = Form(""), custom_user_agent: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip() else None
    sess = start_live_session(actor=user["username"], case_id=cid, start_url=start_url, browser_choice=browser_choice, use_tor=bool(use_tor or request.session.get("force_tor_all_cases")), media_policy=media_policy, headless=bool(headless), download_allowed_media=bool(download_allowed_media), auto_capture=bool(auto_capture), settle_before_capture=bool(settle_before_capture), capture_auto_scroll_session=bool(capture_auto_scroll_session), sealed_media_preservation_session=bool(sealed_media_preservation_session), allow_captcha_challenge_media=bool(allow_captcha_challenge_media), user_agent_profile=user_agent_profile or get_setting("default_user_agent_profile", "chrome_windows"), custom_user_agent=custom_user_agent)
    return RedirectResponse(f"/live/{sess.session_id}?msg=Browser%20session%20started", 303)


@app.get("/live/{sid}", response_class=HTMLResponse)
def live_detail(request: Request, sid: str, msg: str | None = None) -> HTMLResponse:
    require_user(request)
    row = rowdict(fetchone("SELECT s.*,c.name case_name FROM browser_sessions s LEFT JOIN cases c ON c.id=s.case_id WHERE session_id=?", (sid,)))
    if not row:
        raise HTTPException(404, "Live session not found")
    with LIVE_LOCK:
        mem = LIVE.get(sid)
    running = bool(mem and not mem.stop_flag.is_set() and row["status"] in {"running", "starting"})
    events = fetchall("SELECT * FROM browser_events WHERE session_id=? ORDER BY id DESC LIMIT 200", (sid,))
    blocked = fetchall("SELECT * FROM blocked_media WHERE session_id=? ORDER BY id DESC LIMIT 200", (sid,))
    captures = page_captures_for_session(sid)
    controls = ""
    if running:
        controls = f"<form method='post' action='/live/{sid}/capture' style='display:inline'><button class='good'>Capture Current Page / Active Tab</button></form><form method='post' action='/live/{sid}/capture-all-tabs' style='display:inline'><button class='warn'>Capture All Open Tabs</button></form><a class='button good' href='/live/{sid}/pages'>Session page viewer</a><form method='post' action='/live/{sid}/stop' style='display:inline'><button class='danger'>Stop Session</button></form>"
    else:
        controls = "<p class='muted'>This session is not running in this app process. Start a new live session if needed.</p>"
    if mem:
        tabs = mem.open_tabs_sync()
        def tab_row(t: dict[str, Any]) -> str:
            idx = int(t.get('index') or 0)
            active = " style='background:#082f49'" if t.get('is_current') else ""
            cap = f"<form method='post' action='/live/{sid}/capture-tab' style='display:inline'><input type='hidden' name='tab_index' value='{idx}'><button class='secondary'>Capture tab</button></form>" if t.get('capturable') else "<span class='muted small'>not capturable</span>"
            return f"<tr{active}><td>{h(idx)}</td><td>{cap}</td><td>{h(t.get('title') or '')}</td><td class='urlcell'>{h(t.get('url') or '')}</td></tr>"
        tabs_html = "".join(tab_row(t) for t in tabs)
        runtime = f"""<p>{badge('in-memory running','good') if running else badge('in-memory stopped','warn')} {badge('requests '+str(mem.requests),'info')} {badge('blocked '+str(mem.blocked),'warn')} <span id='live-tabs-badge'>{badge('tabs '+str(len(tabs)),'info')}</span> {badge('current '+mem.current_url[:120],'info')}</p><details class='card' open><summary>Tracked browser tabs</summary><p class='small muted'>This list refreshes automatically and works around Firefox tabs that do not update the static page view. Use Capture tab if the browser's selected tab is not the one BlindSite last tracked.</p><table><thead><tr><th>#</th><th>Action</th><th>Title</th><th>URL</th></tr></thead><tbody id='tracked-tabs-body'>{tabs_html or '<tr><td colspan="4" class="muted">No tracked tabs yet.</td></tr>'}</tbody></table></details><script>(function(){{
  const sid = {json.dumps(sid)};
  const initialTabsBody = document.getElementById('tracked-tabs-body');
  if (initialTabsBody && initialTabsBody.querySelector('tr') && !initialTabsBody.textContent.includes('No tracked tabs yet')) initialTabsBody.dataset.lastHadRows = '1';
  let trackedTabsRefreshInFlight = false;
  function esc(v){{ return String(v || '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c])); }}
  async function refreshTrackedTabs(){{
    if (trackedTabsRefreshInFlight) return;
    trackedTabsRefreshInFlight = true;
    try{{
      const r = await fetch('/live/' + encodeURIComponent(sid) + '/tabs', {{cache:'no-store'}});
      const j = await r.json();
      const body = document.getElementById('tracked-tabs-body');
      const badge = document.getElementById('live-tabs-badge');
      const tabCount = Number(j.count || 0);
      const transient = Boolean(j.transient_snapshot);
      if (badge) badge.innerHTML = `<span class="badge info">tabs ${{tabCount}}${{transient ? ' refreshing' : ''}}</span>`;
      if (!body) return;
      const rows = (j.tabs || []).map(t => {{
        const idx = Number(t.index || 0);
        const cap = t.capturable ? `<form method="post" action="/live/${{sid}}/capture-tab" style="display:inline"><input type="hidden" name="tab_index" value="${{idx}}"><button class="secondary">Capture tab</button></form>` : `<span class="muted small">not capturable</span>`;
        const active = t.is_current ? ` style="background:#082f49"` : '';
        return `<tr${{active}}><td>${{esc(idx)}}</td><td>${{cap}}</td><td>${{esc(t.title || '')}}</td><td class="urlcell">${{esc(t.url || '')}}</td></tr>`;
      }}).join('');
      if (rows) {{
        body.innerHTML = rows;
        body.dataset.lastHadRows = '1';
      }} else if (j.running && body.dataset.lastHadRows === '1') {{
        if (badge) badge.innerHTML = `<span class="badge info">tabs refreshing</span>`;
      }} else {{
        body.innerHTML = '<tr><td colspan="4" class="muted">No tracked tabs yet.</td></tr>';
        body.dataset.lastHadRows = '';
      }}
      if (!j.running) clearInterval(window.__blindsiteTabsTimer);
    }}catch(e){{}}
    finally{{ trackedTabsRefreshInFlight = false; }}
  }}
  refreshTrackedTabs();
  window.__blindsiteTabsTimer = setInterval(refreshTrackedTabs, 2000);
}})();</script>"""
    else:
        runtime = ""
    preservation_panel = f"""<div class='card safe noprint' id='preservation-panel'>
      <h2>Background media preservation</h2>
      <p class='small muted'>Blocked media is preserved in the background so live browsing stays fast. Page capture saves the page first; pending media can continue afterward.</p>
      <div style='height:18px;border:1px solid #334155;border-radius:999px;overflow:hidden;background:#020617;margin:8px 0'>
        <div id='preservation-bar' style='height:100%;width:0%;background:#0284c7'></div>
      </div>
      <p id='preservation-text' class='mono small'>Loading preservation status…</p>
      <form method='post' action='/live/{sid}/preservation-cancel' style='display:inline' onsubmit='return confirm("Cancel pending background media preservation for this live session? Active downloads may finish, but no new blocked media will be queued.")'>
        <button class='secondary'>Cancel pending media preservation</button>
      </form>
      <script>
      (function(){{
        async function refreshPreservation(){{
          try{{
            const r = await fetch('/live/{sid}/preservation-status', {{cache:'no-store'}});
            const s = await r.json();
            const pct = Math.max(0, Math.min(100, s.progress_percent || 0));
            const bar = document.getElementById('preservation-bar');
            const txt = document.getElementById('preservation-text');
            if (bar) bar.style.width = pct + '%';
            if (txt) txt.textContent = `mode=${{s.mode || ''}} | blocked=${{s.blocked || 0}} | pending=${{s.pending_tasks || 0}} | downloaded=${{s.db_downloaded ?? s.preserved ?? 0}}/${{s.db_total ?? s.blocked ?? 0}} | not-downloaded=${{s.db_not_downloaded ?? s.skipped_or_failed ?? 0}} | queue-full=${{s.db_queue_full ?? 0}} | outstanding=${{s.outstanding ?? 0}} | timeouts=${{s.timeouts || 0}} | bytes=${{s.preserved_bytes || 0}} | success ${{pct}}%${{s.all_downloaded ? ' | all downloaded' : ''}}`;
            if (typeof refreshBlockedMediaTable === 'function') refreshBlockedMediaTable();
          }} catch(e){{
            const txt = document.getElementById('preservation-text');
            if (txt) txt.textContent = 'Preservation status unavailable: ' + e;
          }}
        }}
        refreshPreservation();
        setInterval(refreshPreservation, 1500);
      }})();
      </script>
    </div>"""
    cap_rows = "".join(f"<tr><td><a href='/evidence/{c['evidence_id']}/page-render'>Open renderer</a></td><td><a href='/evidence/{c['evidence_id']}'>Evidence #{c['evidence_id']}</a></td><td>{h(c['capture_mode'])}</td><td>{badge('raw','warn') if c['raw_persisted'] else badge('safe summary','good')}</td><td>{h(c['created_at'])}</td><td class='urlcell'>{h(c['page_url'])}</td><td class='hashcell'><code>{h(c['sha256'])}</code></td></tr>" for c in captures)
    ev_rows = "".join(f"<tr><td>{h(e['created_at'])}</td><td>{h(e['event_type'])}</td><td>{h(e['resource_type'])}</td><td>{h(e['status_code'] or '')}</td><td class='urlcell'>{h(e['url'] or '')}</td><td class='hashcell'>{event_header_hash_html(e['headers_json'], e['header_sha256'])}</td></tr>" for e in events)
    bm_stats = blocked_media_session_stats(sid)
    bm_type_counts = blocked_media_session_file_type_counts(sid)
    bm_type_chips = render_blocked_media_type_chips(bm_type_counts)
    bm_rows = render_live_blocked_media_rows(blocked)
    blocked_media_panel = f"""<div class='card' id='blocked-media-panel'><h2>Blocked media</h2>
      <p class='small muted'>Blocked requests are aborted from live display. If queue-full/timeouts leave media not downloaded, select rows here and retry encrypted preservation without slowing normal browsing.</p>
      <p id='blocked-media-stats'>{render_live_blocked_media_stats(bm_stats)}</p>
      <div id='blocked-media-type-chips'>{bm_type_chips}</div>
      <form method='post' action='/live/{sid}/blocked-media/retry' id='blockedRetryForm'>
        <div class='noprint' style='margin:8px 0'>
          <label class='small'>Include ext/type <input id='blockedMediaExtFilter' class='compact-input' placeholder='mp4, jpg, webp, m3u8' oninput='filterBlockedMediaRows()'></label>
          <label class='small'>Exclude ext/type <input id='blockedMediaExtExclude' class='compact-input' placeholder='xml, ico, svg' oninput='filterBlockedMediaRows()'></label>
          <label class='small'>Include reason/URL <input id='blockedMediaTextFilter' class='compact-input' placeholder='queue full, v.redd.it' oninput='filterBlockedMediaRows()'></label>
          <label class='small'>Exclude reason/URL <input id='blockedMediaTextExclude' class='compact-input' placeholder='favicon, award, avatar' oninput='filterBlockedMediaRows()'></label>
          <span id='blockedMediaFilterCount' class='badge info'>visible: all</span>
          <button type='button' class='secondary' onclick='filterBlockedMediaRows()'>Apply filters</button>
          <button type='button' class='secondary' onclick='selectBlockedMedia("notdownloaded")'>Select not downloaded visible</button>
          <button type='button' class='secondary' onclick='selectBlockedMedia("queuefull")'>Select queue-full visible</button>
          <button type='button' class='secondary' onclick='selectBlockedMedia("none")'>Clear selection</button>
          <button name='action' value='selected' class='warn'>Retry selected</button>
          <button name='action' value='all_not_downloaded' class='good' onclick='return confirm("Retry all not-downloaded media in this live session? This queues as many as the current background limit allows.")'>Retry all not downloaded in session</button>
          <button name='action' value='all_queue_full' class='good' onclick='return confirm("Retry all queue-full media in this live session? This queues as many as the current background limit allows.")'>Retry all queue-full in session</button>
          <label class='small'>Auto retry mode
            <select id='autoRetryMode' class='compact-input' style='max-width:190px'>
              <option value='all_queue_full' selected>Queue-full only</option>
              <option value='all_not_downloaded'>All not-downloaded</option>
            </select>
          </label>
          <button type='button' class='good' id='autoRetryBtn' onclick='toggleAutoRetryBlockedMedia()'>Start auto retry</button>
          <span id='autoRetryStatus' class='small muted'></span>
        </div>
        <div class='table-scroll'><table><tr><th>Select</th><th>ID</th><th>Type</th><th>File type</th><th>State</th><th>Reason</th><th>URL</th><th>URL Hash</th></tr><tbody id='blocked-media-rows'>{bm_rows}</tbody></table></div>
      </form>
      <script>
      function rowVisible(row){{ return !row.dataset.hiddenByFilter || row.dataset.hiddenByFilter === '0'; }}
      function splitTokens(v){{ return (v || '').toLowerCase().split(/[\\s,;|]+/).filter(Boolean).map(x => x.replace(/^\\./,'')); }}
      function textTokens(v){{ return (v || '').toLowerCase().split(/[,;|]+/).map(x => x.trim()).filter(Boolean); }}
      function tokenMatches(rowText, ext, kind, token){{ return token === ext || kind.includes(token) || rowText.includes(token) || rowText.includes('.' + token) || rowText.includes('/' + token); }}
      function filterBlockedMediaRows(){{
        const includeExts = splitTokens(document.getElementById('blockedMediaExtFilter')?.value || '');
        const excludeExts = splitTokens(document.getElementById('blockedMediaExtExclude')?.value || '');
        const includeTexts = textTokens(document.getElementById('blockedMediaTextFilter')?.value || '');
        const excludeTexts = textTokens(document.getElementById('blockedMediaTextExclude')?.value || '');
        let visibleCount = 0, hiddenCount = 0, totalCount = 0;
        document.querySelectorAll('#blocked-media-rows tr.bm-row').forEach(function(row){{
          totalCount++;
          const ext = (row.dataset.ext || '').toLowerCase();
          const kind = (row.dataset.kind || '').toLowerCase();
          const rowText = row.textContent.toLowerCase();
          const includeExtOk = !includeExts.length || includeExts.some(e => tokenMatches(rowText, ext, kind, e));
          const excludeExtHit = excludeExts.some(e => tokenMatches(rowText, ext, kind, e));
          const includeTextOk = !includeTexts.length || includeTexts.some(t => rowText.includes(t));
          const excludeTextHit = excludeTexts.some(t => rowText.includes(t));
          const visible = includeExtOk && includeTextOk && !excludeExtHit && !excludeTextHit;
          row.style.display = visible ? '' : 'none';
          row.dataset.hiddenByFilter = visible ? '0' : '1';
          if (!visible) {{ const cb = row.querySelector('.bm-check'); if (cb) cb.checked = false; hiddenCount++; }} else {{ visibleCount++; }}
        }});
        const count = document.getElementById('blockedMediaFilterCount');
        if (count) count.textContent = `visible: ${{visibleCount}} / ${{totalCount}}${{hiddenCount ? ' (hidden ' + hiddenCount + ')' : ''}}`;
      }}
      function selectBlockedMedia(mode){{
        filterBlockedMediaRows();
        document.querySelectorAll('#blockedRetryForm .bm-check').forEach(function(cb){{
          const row = cb.closest('tr');
          if (!row || cb.disabled || !rowVisible(row)) return;
          if (mode === 'none') cb.checked = false;
          else if (mode === 'notdownloaded') cb.checked = row.dataset.notdownloaded === '1';
          else if (mode === 'queuefull') cb.checked = row.dataset.queuefull === '1';
        }});
      }}
      async function refreshBlockedMediaTable(){{
        try {{
          if (document.querySelector('#blockedRetryForm .bm-check:checked')) return;
          const r = await fetch('/live/{sid}/blocked-media-fragment', {{cache:'no-store'}});
          const j = await r.json();
          if (!j.ok) return;
          const stats = document.getElementById('blocked-media-stats');
          const rows = document.getElementById('blocked-media-rows');
          if (stats) stats.innerHTML = j.stats_html;
          const chips = document.getElementById('blocked-media-type-chips');
          if (chips && j.type_chips_html) chips.innerHTML = j.type_chips_html;
          if (rows) {{ rows.innerHTML = j.rows_html; filterBlockedMediaRows(); }}
        }} catch(e) {{}}
      }}
      let blindSiteAutoRetryTimer = null;
      let blindSiteAutoRetryAdvancedConfirmed = false;
      function autoRetryActionLabel(action){{
        return action === 'all_not_downloaded' ? 'all not-downloaded' : 'queue-full only';
      }}
      async function retryAutoOnce(){{
        const status = document.getElementById('autoRetryStatus');
        const mode = document.getElementById('autoRetryMode');
        const action = mode ? mode.value : 'all_queue_full';
        try {{
          const fd = new FormData();
          fd.append('action', action);
          const r = await fetch('/live/{sid}/blocked-media/retry-json', {{method:'POST', body:fd, cache:'no-store'}});
          const j = await r.json();
          if (status) {{
            if (j.ok) {{
              const res = j.result || {{}};
              status.textContent = `auto-retry (${{autoRetryActionLabel(action)}}): queued=${{res.queued || 0}}, queue-full=${{res.queue_full || 0}}, skipped=${{res.skipped || 0}}, errors=${{res.errors || 0}}`;
            }} else {{
              status.textContent = 'auto-retry unavailable: ' + (j.error || 'unknown error');
            }}
          }}
          refreshBlockedMediaTable();
        }} catch(e) {{ if (status) status.textContent = 'auto-retry error: ' + e; }}
      }}
      function toggleAutoRetryBlockedMedia(){{
        const btn = document.getElementById('autoRetryBtn');
        const status = document.getElementById('autoRetryStatus');
        const mode = document.getElementById('autoRetryMode');
        const action = mode ? mode.value : 'all_queue_full';
        if (blindSiteAutoRetryTimer) {{
          clearInterval(blindSiteAutoRetryTimer);
          blindSiteAutoRetryTimer = null;
          if (btn) btn.textContent = 'Start auto retry';
          if (mode) mode.disabled = false;
          if (status) status.textContent = 'auto-retry stopped';
          return;
        }}
        if (action === 'all_not_downloaded' && !blindSiteAutoRetryAdvancedConfirmed) {{
          const ok = confirm('Auto retry all not-downloaded media is aggressive. It can repeatedly retry items that may have failed because of MIME rules, size limits, server errors, auth failures, or unsupported references. Continue?');
          if (!ok) {{
            if (status) status.textContent = 'auto-retry not started';
            return;
          }}
          blindSiteAutoRetryAdvancedConfirmed = true;
        }}
        if (btn) btn.textContent = 'Stop auto retry';
        if (mode) mode.disabled = true;
        if (status) status.textContent = `auto-retry running every 5s (${{autoRetryActionLabel(action)}})`;
        retryAutoOnce();
        blindSiteAutoRetryTimer = setInterval(retryAutoOnce, 5000);
      }}
      setInterval(refreshBlockedMediaTable, 2500);
      </script>
    </div>"""
    body = f"""{flash(msg)}<div class='card'><h2>Live session {h(sid)}</h2><p>{badge(row['status'],'good' if row['status']=='running' else 'warn')} {badge(row['browser_choice'])} {badge('Tor','info') if row['use_tor'] else badge('Direct')} {badge(row['media_policy'],'good')} {badge('saves allowed media','warn') if jloads(row.get('meta_json'),{}).get('download_allowed_media') else ""}</p><p><b>Case:</b> {h(row.get('case_name') or '')}</p><p><b>Start:</b> <span class='mono'>{h(row['start_url'])}</span></p><p><b>Current:</b> <span class='mono'>{h(row.get('current_url') or '')}</span></p><p><b>User agent:</b> <span class='mono'>{h((jloads(row.get('meta_json'),{}).get('user_agent_label') or jloads(row.get('meta_json'),{}).get('user_agent_profile') or 'default'))}</span> <span class='small muted'>SHA-256 {h((jloads(row.get('meta_json'),{}).get('user_agent_sha256') or '')[:24])}</span></p><p><a class='button good' href='/live/{sid}/pages'>Open session page viewer</a></p>{runtime}<div class='noprint'>{controls}</div>{preservation_panel}<p class='small muted'>Browse in the popped-up browser. Each time you click Capture Current Page, a saved-page evidence item is created below. This build does not block scripts, stylesheets, documents, XHR, or fetch requests.</p></div>
    <div class='card'><h2>Saved page captures from this session</h2><p class='small muted'>Click Open saved page to load the capture exactly as the program saved it: raw HTML in lab mode or a safe reconstructed summary in compliance-safe mode.</p><div class='table-scroll'><table><tr><th>Viewer</th><th>Evidence</th><th>Capture mode</th><th>Raw state</th><th>Captured</th><th>Page URL</th><th>Evidence SHA-256</th></tr>{cap_rows or '<tr><td colspan="7" class="muted">No saved pages yet. Use Capture Current Page while the session is running.</td></tr>'}</table></div></div>
    <div class='grid'><div class='card'><h2>Network/session events</h2><p class='small muted'>Scroll sideways for full URLs. Navigation-only rows may show “No headers captured”; response rows with captured headers show a header SHA-256.</p><div class='table-scroll'><table><tr><th>Time</th><th>Event</th><th>Type</th><th>Status</th><th>URL</th><th>Header hash</th></tr>{ev_rows}</table></div></div>{blocked_media_panel}</div>"""
    return layout(request, f"Live {sid}", body)


@app.get("/live/{sid}/preservation-status")
def live_preservation_status(request: Request, sid: str) -> JSONResponse:
    require_user(request)
    return JSONResponse(live_preservation_status_for(sid))


@app.get("/live/{sid}/blocked-media-fragment")
def live_blocked_media_fragment(request: Request, sid: str) -> JSONResponse:
    require_user(request)
    rows = blocked_media_session_rows(sid)
    stats = blocked_media_session_stats(sid)
    type_counts = blocked_media_session_file_type_counts(sid)
    return JSONResponse({"ok": True, "session_id": sid, "stats": stats, "type_counts": type_counts, "stats_html": render_live_blocked_media_stats(stats), "type_chips_html": render_blocked_media_type_chips(type_counts), "rows_html": render_live_blocked_media_rows(rows)})


@app.post("/live/{sid}/preservation-cancel")
def live_preservation_cancel(request: Request, sid: str) -> RedirectResponse:
    user = require_user(request)
    status = cancel_live_preservation(sid)
    log_event(user["username"], "LIVE_PRESERVATION_CANCEL_REQUESTED", session_id=sid, details=status)
    return RedirectResponse(f"/live/{sid}?msg=Pending%20media%20preservation%20cancelled", 303)


@app.post("/live/{sid}/blocked-media/retry")
def live_blocked_media_retry(request: Request, sid: str, action: str = Form("selected"), blocked_ids: list[int] | None = Form(None)) -> RedirectResponse:
    user = require_user(request)
    ids = [int(x) for x in (blocked_ids or [])]
    try:
        if action == "all_not_downloaded":
            result = retry_live_blocked_media(sid, actor=user["username"], retry_all_not_downloaded=True)
        elif action == "all_queue_full":
            result = retry_live_blocked_media(sid, actor=user["username"], retry_all_not_downloaded=True, only_queue_full=True)
        else:
            result = retry_live_blocked_media(sid, actor=user["username"], blocked_ids=ids)
        msg = f"Retry queued {int(result.get('queued') or 0)} item(s); queue-full {int(result.get('queue_full') or 0)}; errors {int(result.get('errors') or 0)}"
        return RedirectResponse(f"/live/{sid}?msg={quote(msg)}", 303)
    except Exception as exc:
        return RedirectResponse(f"/live/{sid}?msg={quote('Retry failed: ' + str(exc)[:180])}", 303)


@app.post("/live/{sid}/blocked-media/retry-json")
def live_blocked_media_retry_json(request: Request, sid: str, action: str = Form("all_queue_full"), blocked_ids: list[int] | None = Form(None)) -> JSONResponse:
    user = require_user(request)
    ids = [int(x) for x in (blocked_ids or [])]
    try:
        if action == "all_not_downloaded":
            result = retry_live_blocked_media(sid, actor=user["username"], retry_all_not_downloaded=True)
        elif action == "all_queue_full":
            result = retry_live_blocked_media(sid, actor=user["username"], retry_all_not_downloaded=True, only_queue_full=True)
        else:
            result = retry_live_blocked_media(sid, actor=user["username"], blocked_ids=ids)
        return JSONResponse({"ok": True, "session_id": sid, "action": action, "result": result, "status": live_preservation_status_for(sid)})
    except Exception as exc:
        return JSONResponse({"ok": False, "session_id": sid, "error": str(exc)}, status_code=409)


@app.post("/live/{sid}/capture")
def live_capture(request: Request, sid: str) -> RedirectResponse:
    user = require_user(request)
    eid = capture_live_session(sid)
    log_event(user["username"], "LIVE_CAPTURE_BUTTON_USED", evidence_id=eid, session_id=sid)
    return RedirectResponse(f"/evidence/{eid}/page-render?msg=Current%20page%20captured", 303)


@app.post("/live/{sid}/capture-all-tabs")
def live_capture_all_tabs(request: Request, sid: str) -> RedirectResponse:
    user = require_user(request)
    ids = capture_all_live_session_tabs(sid)
    log_event(user["username"], "LIVE_CAPTURE_ALL_TABS_BUTTON_USED", session_id=sid, details={"captured_evidence_ids": ids, "count": len(ids)})
    if ids:
        return RedirectResponse(f"/live/{sid}/pages?msg=Captured%20{len(ids)}%20open%20tab(s)", 303)
    return RedirectResponse(f"/live/{sid}?msg=No%20open%20tabs%20captured", 303)


@app.get("/live/{sid}/tabs")
def live_tabs_status(request: Request, sid: str) -> JSONResponse:
    require_user(request)
    return JSONResponse(live_tabs_status_for(sid))


@app.post("/live/{sid}/capture-tab")
def live_capture_tab(request: Request, sid: str, tab_index: int = Form(...)) -> RedirectResponse:
    user = require_user(request)
    eid = capture_live_session_tab(sid, tab_index)
    log_event(user["username"], "LIVE_CAPTURE_TRACKED_TAB_BUTTON_USED", evidence_id=eid, session_id=sid, details={"tab_index": int(tab_index)})
    return RedirectResponse(f"/evidence/{eid}/page-render?msg=Tracked%20tab%20{int(tab_index)}%20captured", 303)


@app.post("/live/{sid}/stop")
def live_stop(request: Request, sid: str) -> RedirectResponse:
    user = require_user(request)
    stop_live_session(sid)
    log_event(user["username"], "LIVE_STOP_BUTTON_USED", session_id=sid)
    return RedirectResponse(f"/live/{sid}?msg=Session%20stop%20requested", 303)


# Backward-compatible aliases for earlier builds that called this area /sessions.
@app.get("/sessions", response_class=HTMLResponse)
def sessions_alias(request: Request) -> HTMLResponse:
    return live_page(request)


@app.post("/sessions/start")
def sessions_start_alias(request: Request, case_id: str = Form(""), start_url: str = Form(...), browser_choice: str = Form("chromium"), media_policy: str = Form("block_images_video"), use_tor: str | None = Form(None), headless: str | None = Form(None), download_allowed_media: str | None = Form(None), sealed_media_preservation_session: str | None = Form(None), allow_captcha_challenge_media: str | None = Form(None), auto_capture: str | None = Form(None), settle_before_capture: str | None = Form(None), capture_auto_scroll_session: str | None = Form(None), user_agent_profile: str = Form(""), custom_user_agent: str = Form("")) -> RedirectResponse:
    return live_start(request, case_id, start_url, browser_choice, media_policy, use_tor, headless, download_allowed_media, sealed_media_preservation_session, allow_captcha_challenge_media, auto_capture, settle_before_capture, capture_auto_scroll_session, user_agent_profile, custom_user_agent)


@app.get("/sessions/{sid}", response_class=HTMLResponse)
def sessions_detail_alias(request: Request, sid: str, msg: str | None = None) -> HTMLResponse:
    return live_detail(request, sid, msg)



@app.get("/captures", response_class=HTMLResponse)
def captures_page(request: Request, case_id: str = "", q: str = "", starred: str = "", hashtag: str = "") -> HTMLResponse:
    require_user(request)
    cid = int(case_id) if str(case_id).strip().isdigit() else None
    star_filter = truthy(starred)
    tag_filter = normalize_hashtags(hashtag)
    rows = page_capture_rows(case_id=cid, q=q, starred=star_filter, hashtag=tag_filter, limit=500)
    cases = fetchall("SELECT id,name,hashtags FROM cases ORDER BY id DESC")
    case_opts = "<option value=''>All cases</option>" + "".join(f"<option value='{r['id']}' {'selected' if cid == r['id'] else ''}>{h(r['name'])}</option>" for r in cases)
    cards = []
    return_to = "/captures?" + urlencode({"case_id": case_id, "q": q, "starred": starred, "hashtag": hashtag})
    for r in rows:
        rd = rowdict(r)
        star = bool(rd.get("starred"))
        tags = normalize_hashtags(rd.get("hashtags") or "")
        cards.append(f"""<div class='card {'good' if star else ''}'>
          <h2>{'★ ' if star else '☆ '}{h(rd.get('title') or rd.get('filename') or 'Saved page')}</h2>
          <p>{badge(rd.get('capture_mode'),'info')} {badge('raw persisted','warn') if rd.get('raw_persisted') else badge('safe summary / metadata','good')} {badge('case '+str(rd.get('case_id')),'info') if rd.get('case_id') else ''} {badge('starred','warn') if star else ''} {hashtag_badges(tags)}</p>
          <p class='small muted'>Captured {h(rd.get('created_at'))}</p>
          <p><b>Source:</b> <span class='mono urlcell'>{h(rd.get('page_url'))}</span></p>
          <p><b>Evidence SHA-256:</b> <code>{h(rd.get('sha256'))}</code></p>
          <form method='post' action='/captures/{int(rd.get('id'))}/star' style='display:inline'><input type='hidden' name='return_to' value='{h(return_to)}'><input type='hidden' name='starred' value='{0 if star else 1}'><button class='{'warn' if not star else 'secondary'}'>{'Star page' if not star else 'Unstar page'}</button></form>
          <form method='post' action='/captures/{int(rd.get('id'))}/hashtags' style='display:inline'><input type='hidden' name='return_to' value='{h(return_to)}'><input name='hashtags' value='{h(tags)}' placeholder='#priority #reddit' style='max-width:260px'><button class='secondary'>Save hashtags</button></form>
          <p><a class='button good' href='/evidence/{rd.get('evidence_id')}/page-render'>Open renderer</a> <a class='button' href='/evidence/{rd.get('evidence_id')}/capture-frame' target='_blank'>Open safe frame</a> <a class='button secondary' href='/evidence/{rd.get('evidence_id')}'>Evidence #{rd.get('evidence_id')}</a></p>
        </div>""")
    body = f"""<div class='card good'><h2>Saved pages</h2><p>This is where captured pages live. Open saved page loads the page exactly as BlindSite preserved it: raw HTML only in approved lab mode, otherwise a safe reconstructed summary/metadata view that fetches no remote resources.</p><form><div class='row'><div><label>Case</label><select name='case_id'>{case_opts}</select></div><div><label>Search URL/title/hash/tag</label><input name='q' value='{h(q)}'></div><div><label>Hashtag</label><input name='hashtag' value='{h(tag_filter)}' placeholder='#priority'></div><div><label><input type='checkbox' name='starred' value='1' {'checked' if star_filter else ''}> Starred only</label><button>Filter</button></div></div></form><p class='small muted'>You can star important captures and tag saved pages with hashtags such as <code>#priority</code>, <code>#reddit</code>, or <code>#review</code>.</p></div>{''.join(cards) or '<div class="card"><p class="muted">No saved page captures matched. Start a live session or run direct URL capture, then click Capture Current Page.</p></div>'}"""
    return layout(request, "Saved Pages", body)


@app.post("/captures/{capture_id}/star")
def capture_star_update(request: Request, capture_id: int, starred: int = Form(1), return_to: str = Form("/captures")) -> RedirectResponse:
    user = require_user(request)
    val = 1 if int(starred or 0) else 0
    execute("UPDATE page_captures SET starred=? WHERE id=?", (val, capture_id))
    row = rowdict(fetchone("SELECT evidence_id, case_id FROM page_captures WHERE id=?", (capture_id,))) or {}
    log_event(user["username"], "PAGE_CAPTURE_STAR_UPDATED", case_id=row.get("case_id"), evidence_id=row.get("evidence_id"), details={"capture_id": capture_id, "starred": bool(val)})
    return RedirectResponse(return_to or "/captures", 303)


@app.post("/captures/{capture_id}/hashtags")
def capture_hashtags_update(request: Request, capture_id: int, hashtags: str = Form(""), return_to: str = Form("/captures")) -> RedirectResponse:
    user = require_user(request)
    tags = normalize_hashtags(hashtags)
    execute("UPDATE page_captures SET hashtags=? WHERE id=?", (tags, capture_id))
    row = rowdict(fetchone("SELECT evidence_id, case_id FROM page_captures WHERE id=?", (capture_id,))) or {}
    log_event(user["username"], "PAGE_CAPTURE_HASHTAGS_UPDATED", case_id=row.get("case_id"), evidence_id=row.get("evidence_id"), details={"capture_id": capture_id, "hashtags": tags})
    return RedirectResponse(return_to or "/captures", 303)


@app.get("/media", response_class=HTMLResponse)
def media_page(request: Request, case_id: str = "", state: str = "all", kind: str = "all", preview: str = "none", q: str = "", starred: str = "", hashtag: str = "", exts: str = "") -> HTMLResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip().isdigit() else None
    if state not in {"all", "blocked", "saved", "materialized"}:
        state = "all"
    if kind not in {"all", "image", "video", "audio", "font"}:
        kind = "all"
    if preview not in {"none", "blur"}:
        preview = "none"
    star_filter = truthy(starred)
    tag_filter = normalize_hashtags(hashtag)
    ext_filter_text = ",".join(extension_filter_list(exts))
    cases = fetchall("SELECT id,name FROM cases ORDER BY id DESC")
    case_opts = "<option value=''>All cases</option>" + "".join(f"<option value='{r['id']}' {'selected' if cid == r['id'] else ''}>{h(r['name'])}</option>" for r in cases)
    state_opts = "".join(f"<option value='{x}' {'selected' if state==x else ''}>{x}</option>" for x in ["all","blocked","saved","materialized"])
    kind_opts = "".join(f"<option value='{x}' {'selected' if kind==x else ''}>{x}</option>" for x in ["all","image","video","audio","font"])
    prev_opts = "".join(f"<option value='{x}' {'selected' if preview==x else ''}>{'blurred image previews' if x=='blur' else 'metadata cards only'}</option>" for x in ["none","blur"])
    saved = [] if state == "blocked" else saved_media_rows(case_id=cid, q=q, kind=kind, state=state, limit=400, starred=star_filter, hashtag=tag_filter, exts=ext_filter_text)
    blocked = [] if state == "saved" else blocked_media_rows(case_id=cid, q=q, kind=kind, state=state, limit=400)
    if extension_filter_list(ext_filter_text):
        blocked = [b for b in blocked if extension_matches(str(b['media_url'] or ''), str(b['content_type'] or ''), extension_filter_list(ext_filter_text))]
    return_to = "/media?" + urlencode({"case_id": case_id, "state": state, "kind": kind, "preview": preview, "q": q, "starred": starred, "hashtag": hashtag, "exts": ext_filter_text})
    saved_cards = []
    for r in saved:
        ev = dict(r)
        tags = normalize_hashtags(ev.get("hashtags") or "")
        star = bool(ev.get("starred"))
        preview_html = evidence_thumb(ev, user, preview)
        label = extension_label_from_url_or_name(str(ev.get('filename') or ev.get('source_ref') or ''), str(ev.get('mime_type') or ''))
        saved_cards.append(f"""<div class='card media-card {'good' if star else ''}'>{preview_html}<h3>{'★ ' if star else ''}{h(ev.get('filename'))}</h3><p>{badge(ev.get('kind'))} {badge(ev.get('mime_type'))} {badge(label,'info')} {badge(ev.get('storage_mode'),'info')} {badge('starred','warn') if star else ''} {hashtag_badges(tags)}</p><p><b>Case:</b> {h(ev.get('case_name') or '')}</p><p><b>SHA-256:</b> <code>{h(ev.get('sha256'))}</code></p><p class='small urlcell'>{h(ev.get('source_ref') or '')}</p><div class='media-tools'><form method='post' action='/media/evidence/{ev['id']}/star'><input type='hidden' name='return_to' value='{h(return_to)}'><button class='secondary starbtn'>{'Unstar' if star else 'Star'} {'★' if star else '☆'}</button></form><form method='post' action='/media/evidence/{ev['id']}/hashtags' class='tagline'><input type='hidden' name='return_to' value='{h(return_to)}'><input class='compact-input' name='hashtags' value='{h(tags)}' placeholder='#important #video'><button class='secondary'>Save tags</button></form></div><p><a class='button good' href='/evidence/{ev['id']}'>Open evidence viewer</a></p></div>""")
    blocked_rows = []
    for b in blocked:
        mat = f"<a href='/evidence/{b['materialized_evidence_id']}'>Evidence #{b['materialized_evidence_id']}</a>" if b['materialized_evidence_id'] else ""
        ext = extension_label_from_url_or_name(str(b['media_url'] or ''), str(b['content_type'] or ''))
        blocked_rows.append(f"<tr><td><a href='/blocked/{b['id']}'>#{b['id']}</a></td><td>{h(b['resource_type'])}</td><td>{badge(ext,'info')}</td><td>{badge('downloaded','warn') if b['downloaded'] else badge('not downloaded','good')}</td><td>{h(b['reason'])}</td><td>{mat}</td><td class='urlcell'>{h(b['media_url'])}</td><td class='hashcell'><code>{h(b['url_sha256'])}</code></td></tr>")
    body = f"""<div class='card good'><h2>Media gallery and blocked-media viewer</h2><p>Star and tag important media files, filter by extension/MIME, and review blocked-media metadata without losing evidence safety controls.</p><form><div class='row'><div><label>Case</label><select name='case_id'>{case_opts}</select></div><div><label>State</label><select name='state'>{state_opts}</select></div><div><label>Kind</label><select name='kind'>{kind_opts}</select></div><div><label>Preview</label><select name='preview'>{prev_opts}</select></div></div><div class='row'><div><label>Search URL/hash/filename/tag</label><input name='q' value='{h(q)}'></div><div><label>Hashtag</label><input name='hashtag' value='{h(tag_filter)}' placeholder='#priority'></div><div><label>Extensions / MIME tokens</label><input name='exts' value='{h(ext_filter_text)}' placeholder='mp4, jpg, webp, m3u8'></div><div><label><input type='checkbox' name='starred' value='1' {'checked' if star_filter else ''}> Starred only</label><button>Filter</button></div></div></form></div>
    <div class='card'><h2>Saved/materialized media evidence</h2><div class='media-grid'>{''.join(saved_cards) or '<p class="muted">No saved media evidence matched this filter.</p>'}</div></div>
    <div class='card'><h2>Blocked media records</h2><p class='small muted'>Scroll sideways for full URLs and hashes. These are records of media references that were blocked before body download unless marked downloaded/materialized.</p><div class='table-scroll'><table><tr><th>ID</th><th>Type</th><th>File type</th><th>State</th><th>Reason</th><th>Materialized evidence</th><th>URL</th><th>URL SHA-256</th></tr>{''.join(blocked_rows) or '<tr><td colspan="8" class="muted">No blocked media matched this filter.</td></tr>'}</table></div></div>"""
    return layout(request, "Media", body)


@app.post("/media/evidence/{eid}/star")
def media_evidence_star(request: Request, eid: int, return_to: str = Form("/media")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    new_val = 0 if int(ev.get("starred") or 0) else 1
    execute("UPDATE evidence SET starred=? WHERE id=?", (new_val, eid))
    log_event(user["username"], "EVIDENCE_STAR_UPDATED", case_id=ev.get("case_id"), evidence_id=eid, details={"starred": bool(new_val)})
    return RedirectResponse(return_to or "/media", 303)


@app.post("/media/evidence/{eid}/hashtags")
def media_evidence_hashtags(request: Request, eid: int, hashtags: str = Form(""), return_to: str = Form("/media")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    tags = normalize_hashtags(hashtags)
    execute("UPDATE evidence SET hashtags=? WHERE id=?", (tags, eid))
    log_event(user["username"], "EVIDENCE_HASHTAGS_UPDATED", case_id=ev.get("case_id"), evidence_id=eid, details={"hashtags": tags})
    return RedirectResponse(return_to or "/media", 303)

def approval_exists(action: str, case_id: int | None = None, evidence_id: int | None = None, blocked_media_id: int | None = None) -> bool:
    row = fetchone("SELECT 1 FROM approvals WHERE status='approved' AND action=? AND coalesce(case_id,0)=coalesce(?,0) AND coalesce(evidence_id,0)=coalesce(?,0) AND coalesce(blocked_media_id,0)=coalesce(?,0) ORDER BY id DESC LIMIT 1", (action, case_id, evidence_id, blocked_media_id))
    return bool(row)


def reveal_allowed(user: dict[str, Any], ev: dict[str, Any], mode: str, master_key: str = "") -> tuple[bool, str]:
    case = case_for(ev.get("case_id"))
    if mode == "blocked":
        return True, "blocked mode always allowed"
    if hard_sealed_escrow_evidence(ev):
        meta = evidence_meta_dict(ev)
        if meta.get("hard_sealed_organization_media"):
            return False, "organization hard-sealed preserved media cannot be locally revealed or decrypted by the vault key; use sealed export and reviewer decrypt with the matching organization escrow private key"
        return False, "Civilian Unknown Master Key hard-sealed evidence cannot be locally revealed or decrypted; use sealed export and reviewer decrypt"
    if sealed_preserved_media_evidence(ev):
        if mode == "blur":
            return False, "sealed-preserved blocked media does not allow blur previews; use master-key full reveal in organization mode or sealed reviewer decrypt"
        if mode == "full":
            if civilian_unknown_master_mode():
                return False, "Civilian Unknown Master Key mode blocks local reveal of sealed-preserved media; use sealed export and reviewer decrypt"
            if custody_mode() != "organization":
                return False, "sealed-preserved media local reveal is only available in Organization-Controlled Key mode"
            if user.get("image_policy") != "full" and not is_admin(user):
                return False, "your account policy does not allow full media/original reveal"
            if setting_bool("require_approval_full_reveal", "1") and not is_admin(user) and not approval_exists("full_reveal", ev.get("case_id"), ev.get("id"), None):
                return False, "approved full reveal request required"
            if not verify_master_key(master_key):
                return False, "organization master reveal key required for sealed-preserved media"
            return True, "sealed-preserved media full reveal allowed by organization master-key workflow"
        return False, "sealed-preserved media supports only blocked mode or master-key full reveal in organization mode"
    if mode == "blur":
        if not str(ev.get("mime_type", "")).startswith("image/"):
            return False, "blur preview is only for images"
        if user.get("image_policy") == "none":
            return False, "your account policy blocks image viewing"
        if lockdown() and not setting_bool("allow_blur_in_lockdown", "1"):
            return False, "lockdown disables blur previews"
        return True, "blur preview allowed"
    if mode == "full":
        if lockdown() and setting_bool("disable_full_reveal_in_lockdown", "1"):
            return False, "global lockdown disables full reveal"
        if case and case.get("compliance_safe"):
            return False, "case compliance-safe policy disables full reveal"
        if ev.get("lock_direct_original_access"):
            return False, "evidence direct-original lock disables full reveal"
        if user.get("image_policy") != "full" and not is_admin(user):
            return False, "your account policy does not allow full image/original reveal"
        if setting_bool("require_approval_full_reveal", "1") and not is_admin(user) and not approval_exists("full_reveal", ev.get("case_id"), ev.get("id"), None):
            return False, "approved full reveal request required"
        if setting_bool("require_master_key_full_reveal", "1") or user.get("require_master_key"):
            if not verify_master_key(master_key):
                return False, "admin master reveal key required"
        return True, "full reveal allowed"
    return False, "unknown view mode"


def create_blur(ev: dict[str, Any], actor: str) -> int:
    existing = fetchone("SELECT * FROM derived WHERE evidence_id=? AND kind='blurred_preview' ORDER BY id DESC LIMIT 1", (ev["id"],))
    if existing:
        return existing["id"]
    data = read_evidence(ev["id"])
    try:
        im = Image.open(io.BytesIO(data)).convert("RGB")
        im.thumbnail((1400, 1400))
        blurred = im.filter(ImageFilter.GaussianBlur(radius=35))
        out = io.BytesIO()
        blurred.save(out, format="JPEG", quality=75)
        payload = out.getvalue()
    except Exception as exc:
        raise HTTPException(400, f"Cannot create blurred preview: {exc}")
    did = persist_derived(evidence_id=ev["id"], kind="blurred_preview", filename=f"blurred_{ev['id']}.jpg", mime_type="image/jpeg", payload=payload, encrypt=True, meta={"blur_radius": 35, "source_sha256": ev["sha256"]})
    log_event(actor, "BLURRED_PREVIEW_CREATED", case_id=ev.get("case_id"), evidence_id=ev["id"], details={"derived_id": did})
    return did


def signed_token(eid: int, mode: str, username: str) -> str:
    return serializer.dumps({"evidence_id": eid, "mode": mode, "user": username, "issued_at": utcnow()})


def verify_view_token(token: str, eid: int, mode: str, username: str) -> dict[str, Any]:
    try:
        payload = serializer.loads(token, max_age=600)
    except SignatureExpired as exc:
        raise HTTPException(403, "View token expired") from exc
    except BadSignature as exc:
        raise HTTPException(403, "Invalid view token") from exc
    if payload.get("evidence_id") != eid or payload.get("mode") != mode or payload.get("user") != username:
        raise HTTPException(403, "Mismatched view token")
    return payload


@app.get("/evidence/{eid}", response_class=HTMLResponse)
def evidence_page(request: Request, eid: int, mode: str = "blocked", token: str = "", msg: str | None = None) -> HTMLResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    case = case_for(ev.get("case_id"))
    execute("UPDATE evidence SET status=CASE WHEN status='unviewed' THEN 'metadata_opened' ELSE status END WHERE id=?", (eid,))
    log_event(user["username"], "EVIDENCE_PAGE_OPENED", case_id=ev.get("case_id"), evidence_id=eid, details={"viewer_mode": mode})
    viewer = "<div class='viewer'><div><h2>BLOCKED MODE</h2><p>No original visual bytes are rendered.</p></div></div>"
    if token and mode in {"blur", "full"}:
        try:
            verify_view_token(token, eid, mode, user["username"])
            if mode == "blur":
                viewer = f"<div class='viewer'><img src='/evidence/{eid}/serve?mode=blur&token={h(token)}' alt='blurred preview'></div>"
            else:
                if str(ev["mime_type"]).startswith("image/"):
                    viewer = f"<div class='viewer'><img src='/evidence/{eid}/serve?mode=full&token={h(token)}' alt='full evidence'></div>"
                else:
                    viewer = f"<div class='viewer'><a class='button danger' href='/evidence/{eid}/serve?mode=full&token={h(token)}'>Open/download original bytes</a></div>"
        except HTTPException as exc:
            viewer = f"<div class='viewer'><p>{badge(exc.detail,'bad')}</p></div>"
    can_blur, blur_why = reveal_allowed(user, ev, "blur")
    can_full_static, full_why_static = reveal_allowed(user, ev, "full", "")
    # Let user submit if only missing dynamic master key/approval; route enforces final decision.
    dynamic_reason = any(x in full_why_static for x in ["master reveal key", "approved full reveal", "hardware-key"])
    full_disabled = (not can_full_static) and not dynamic_reason
    derived = fetchall("SELECT * FROM derived WHERE evidence_id=? ORDER BY id DESC", (eid,))
    children = fetchall("SELECT * FROM evidence WHERE parent_evidence_id=? ORDER BY id DESC", (eid,))
    blocked = fetchall("SELECT * FROM blocked_media WHERE root_evidence_id=? ORDER BY id DESC LIMIT 200", (eid,))
    audit_rows = fetchall("SELECT * FROM audit_events WHERE evidence_id=? ORDER BY id DESC LIMIT 100", (eid,))
    d_rows = "".join(f"<tr><td>#{r['id']}</td><td>{h(r['kind'])}</td><td>{h(r['mime_type'])}</td><td><code>{h(r['sha256'][:18])}…</code></td></tr>" for r in derived)
    c_rows = "".join(f"<tr><td><a href='/evidence/{r['id']}'>#{r['id']}</a></td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td>{h(r['storage_mode'])}</td></tr>" for r in children)
    b_rows = "".join(f"<tr><td><a href='/blocked/{r['id']}'>#{r['id']}</a></td><td>{h(r['resource_type'])}</td><td class='small'>{h(r['media_url'][:130])}</td><td><code>{h(r['metadata_record_hash'][:18])}…</code></td><td>{badge('downloaded','warn') if r['downloaded'] else badge('not downloaded','good')}</td></tr>" for r in blocked)
    a_rows = "".join(f"<tr><td>{h(r['created_at'])}</td><td>{h(r['actor'])}</td><td>{h(r['action'])}</td><td><code>{h(r['event_hash'][:18])}…</code></td></tr>" for r in audit_rows)
    meta_pre = h(pretty(meta_of(ev))[:20000])
    page_view_link = f"<p class='noprint'><a class='button good' href='/evidence/{eid}/page-render'>Open page renderer</a> <a class='button' href='/evidence/{eid}/capture-view'>Capture data</a> <a class='button' href='/evidence/{eid}/capture-frame' target='_blank'>Open safe frame</a></p>" if is_page_capture_evidence(ev) else ""
    body = f"""{flash(msg)}<div class='card'><h2>Evidence #{eid}</h2><p>{badge(ev['kind'])} {badge(ev['mime_type'])} {badge(ev['storage_mode'])} {badge('encrypted','good') if ev['encrypted'] else badge('not encrypted','warn')} {badge('raw persisted','warn') if ev['raw_persisted'] else badge('no raw root persisted','good')} {badge('quarantined','warn') if ev['quarantined'] else ''}</p><table><tr><th>Case</th><td>{('<a href="/cases/'+str(ev['case_id'])+'">#'+str(ev['case_id'])+'</a>') if ev.get('case_id') else ''}</td></tr><tr><th>Filename</th><td>{h(ev['filename'])}</td></tr><tr><th>Source</th><td>{h(ev['source_type'])}: {h(ev['source_ref'])}</td></tr><tr><th>SHA-256</th><td><code>{h(ev['sha256'])}</code></td></tr><tr><th>Size</th><td>{h(ev['size'])} bytes</td></tr><tr><th>Created</th><td>{h(ev['created_at'])}</td></tr></table>{page_view_link}</div>
    <div class='card noprint'><h2>Controlled viewer</h2><p>{badge('compliance-safe','good') if case_safe(case) else badge('review/lab','warn')} {badge('original locked','warn') if ev['lock_direct_original_access'] else badge('original policy-dependent','info')}</p><div class='row'><form method='post' action='/evidence/{eid}/issue-token'><input type='hidden' name='mode' value='blocked'><button class='secondary'>Confirm blocked mode</button></form><form method='post' action='/evidence/{eid}/issue-token'><input type='hidden' name='mode' value='blur'><button {'disabled' if not can_blur else ''}>Blur preview</button><p class='small muted'>{h(blur_why)}</p></form></div><form method='post' action='/evidence/{eid}/issue-token' class='card danger' data-webauthn-action='full_reveal'><h3>Full reveal/original bytes</h3><input type='hidden' name='mode' value='full'><label>Reason</label><input name='reason'><label>Admin master reveal key</label><input type='password' name='master_key'><button class='danger' {'disabled' if full_disabled else ''}>Issue full reveal token</button><p class='small muted'>{h(full_why_static)}</p></form><form method='post' action='/approvals/request'><input type='hidden' name='action' value='full_reveal'><input type='hidden' name='case_id' value='{h(ev.get('case_id') or '')}'><input type='hidden' name='evidence_id' value='{eid}'><label>Request supervisor approval</label><input name='reason' placeholder='Why access is needed'><button class='warn'>Request approval</button></form></div>{viewer}
    <div class='card noprint'><h2>Export</h2><form method='post' action='/evidence/{eid}/export' data-webauthn-action='plaintext_export' data-webauthn-if-checked='include_plaintext'><label><input type='checkbox' name='include_plaintext' value='1'> Include decrypted plaintext/originals where policy permits</label><label>Master key for plaintext export</label><input name='master_key' type='password'><button>Export evidence ZIP</button></form><form method='post' action='/evidence/{eid}/quarantine'><button class='warn'>{'Release from quarantine' if ev['quarantined'] else 'Quarantine'}</button></form></div>
    <div class='grid'><div class='card'><h2>Metadata</h2><pre>{meta_pre}</pre></div><div class='card'><h2>Derived artifacts</h2><table><tr><th>ID</th><th>Kind</th><th>MIME</th><th>SHA</th></tr>{d_rows}</table></div></div><div class='card'><h2>Child evidence</h2><table><tr><th>ID</th><th>Name</th><th>Kind</th><th>Storage</th></tr>{c_rows}</table></div><div class='card'><h2>Blocked media tied to this evidence</h2><table><tr><th>ID</th><th>Type</th><th>URL</th><th>Metadata hash</th><th>State</th></tr>{b_rows}</table></div><div class='card'><h2>Audit for this evidence</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Event hash</th></tr>{a_rows}</table></div>"""
    return layout(request, f"Evidence #{eid}", body)




@app.get("/evidence/{eid}/capture-view", response_class=HTMLResponse)
def evidence_capture_view(request: Request, eid: int, msg: str | None = None) -> HTMLResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if not is_page_capture_evidence(ev):
        raise HTTPException(400, "This evidence item is not a saved URL/page capture")
    model = saved_capture_model(ev)
    blocked = blocked_media_for_capture(ev, model, 500)
    links = model["summary"].get("links") if isinstance(model.get("summary"), dict) else []
    removed = model["summary"].get("removed_counts") if isinstance(model.get("summary"), dict) else {}
    link_rows = "".join(f"<tr><td>{h((ln.get('text') or '')[:200])}</td><td class='urlcell'>{h(ln.get('url') or '')}</td><td class='hashcell'><code>{h(ln.get('url_sha256') or sha256_text(ln.get('url') or ''))}</code></td></tr>" for ln in (links or []))
    removed_rows = "".join(f"<tr><td>{h(k)}</td><td>{h(v)}</td></tr>" for k, v in (removed or {}).items())
    bm_rows = "".join(f"<tr><td><a href='/blocked/{b['id']}'>#{b['id']}</a></td><td>{h(b['resource_type'])}</td><td>{badge('downloaded','warn') if b['downloaded'] else badge('not downloaded','good')}</td><td class='urlcell'>{h(b['media_url'])}</td><td class='hashcell'><code>{h(b['url_sha256'])}</code></td></tr>" for b in blocked)
    meta_pre = h(pretty(model.get("metadata") or {})[:30000])
    source_url = h(model.get("source_url") or ev.get("source_ref") or "")
    source_hash = h(model.get("source_url_sha256") or sha256_text(model.get("source_url") or ""))
    text_preview = h(str((model.get("summary") or {}).get("text") or "")[: int(get_setting("max_text_summary_chars", "20000") or "20000")])
    render_ok, render_why = render_assets_allowed(user, ev)
    frame_url = f"/evidence/{eid}/capture-frame?renderer=safe"
    frame_label = "safe summary renderer"
    log_event(user["username"], "SAVED_CAPTURE_VIEW_OPENED", case_id=ev.get("case_id"), evidence_id=eid, details={"source_url_sha256": model.get("source_url_sha256"), "payload_kind": model.get("payload_kind"), "renderer": frame_label})
    body = f"""{flash(msg)}<div class='card good'><h2>Saved page viewer for evidence #{eid}</h2><p>{badge(ev['storage_mode'],'info')} {badge('raw persisted','warn') if ev['raw_persisted'] else badge('safe summary / metadata','good')} {badge(model.get('payload_kind'),'info')} {badge(frame_label,'good' if render_ok else 'info')}</p><p class='muted'>This viewer reconstructs the page from what the tool saved. Exact mode only uses local saved assets and never fetches the live site. {h(render_why)}</p><table><tr><th>Title</th><td>{h(model.get('title') or '')}</td></tr><tr><th>Source URL</th><td class='urlcell'>{source_url}</td></tr><tr><th>Source URL SHA-256</th><td class='hashcell'><code>{source_hash}</code></td></tr><tr><th>Evidence SHA-256</th><td class='hashcell'><code>{h(ev['sha256'])}</code></td></tr></table><p class='noprint'><a class='button' href='/evidence/{eid}'>Evidence record</a> <a class='button good' href='/evidence/{eid}/page-render'>Open page renderer / exact controls</a> <a class='button' href='{frame_url}' target='_blank'>Open safe summary frame</a> <a class='button' href='{frame_url}&download=1'>Download safe viewer HTML</a></p></div>
    <div class='card'><h2>Saved page render</h2><iframe class='saved-frame' sandbox='allow-same-origin' src='{frame_url}'></iframe></div>
    <div class='grid'><div class='card'><h2>Captured text</h2><pre>{text_preview}</pre></div><div class='card'><h2>Capture metadata</h2><pre>{meta_pre}</pre></div></div>
    <div class='card'><h2>Links preserved from saved page</h2><p class='small muted'>Scroll sideways for full URLs and hashes.</p><div class='table-scroll'><table><tr><th>Text</th><th>URL</th><th>URL SHA-256</th></tr>{link_rows or '<tr><td colspan="3" class="muted">No links in the saved summary.</td></tr>'}</table></div></div>
    <div class='grid'><div class='card'><h2>Removed/suppressed elements</h2><table><tr><th>Element</th><th>Count</th></tr>{removed_rows or '<tr><td colspan="2" class="muted">No removed-count data.</td></tr>'}</table></div><div class='card'><h2>Associated blocked media</h2><p class='small muted'>These are media references blocked or logged for this captured page/session.</p><div class='table-scroll'><table><tr><th>ID</th><th>Type</th><th>State</th><th>URL</th><th>URL SHA-256</th></tr>{bm_rows or '<tr><td colspan="5" class="muted">No blocked media linked.</td></tr>'}</table></div></div></div>"""
    return layout(request, f"Saved Page #{eid}", body)


@app.get("/evidence/{eid}/capture-frame", response_class=HTMLResponse)
def evidence_capture_frame(request: Request, eid: int, renderer: str = "auto", download: str | None = None) -> HTMLResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if not is_page_capture_evidence(ev):
        raise HTTPException(400, "This evidence item is not a saved URL/page capture")
    model = saved_capture_model(ev)
    render_ok, render_why = render_assets_allowed(user, ev)
    unlocked_for_exact = page_render_unlock_ok(request, eid)
    use_exact = renderer in {"exact", "auto"} and render_ok and unlocked_for_exact
    if renderer == "exact" and (not render_ok or not unlocked_for_exact):
        log_event(user["username"], "EXACT_RENDERER_DENIED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": render_why if not render_ok else "exact renderer not unlocked"})
    if use_exact:
        html_doc = rendered_capture_html(ev, model)
        csp = "default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
        log_event(user["username"], "EXACT_CAPTURE_RENDERER_OPENED", case_id=ev.get("case_id"), evidence_id=eid, details={"source_url_sha256": model.get("source_url_sha256"), "asset_count": len(captured_assets_for_model(ev, model))})
    else:
        html_doc = saved_capture_frame_html(ev, model)
        csp = "default-src 'none'; img-src 'none'; media-src 'none'; script-src 'none'; connect-src 'none'; frame-src 'none'; style-src 'unsafe-inline'"
        log_event(user["username"], "SAFE_CAPTURE_RENDERER_OPENED", case_id=ev.get("case_id"), evidence_id=eid, details={"source_url_sha256": model.get("source_url_sha256"), "reason": render_why})
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Content-Security-Policy": csp,
    }
    if download:
        headers["Content-Disposition"] = f"attachment; filename=saved_capture_{eid}_{'exact' if use_exact else 'safe'}.html"
    return HTMLResponse(html_doc, headers=headers)


def page_render_unlock_ok(request: Request, eid: int) -> bool:
    item = request.session.get(f"page_render_unlock_{eid}")
    if not isinstance(item, dict):
        return False
    try:
        return item.get("user") == request.session.get("username") and float(item.get("expires", 0)) > time.time()
    except Exception:
        return False



def page_viewer_render_block(request: Request, selected_id: int, *, back_url: str, heading: str) -> tuple[str, str]:
    """Return (info_html, iframe_html) for the selected saved-page capture.

    This is the main case/session page renderer block. Safe mode uses a sanitized
    no-network reconstruction. Exact mode is available only when raw HTML plus
    local saved assets exist and the user has temporarily unlocked the renderer.
    """
    if not selected_id:
        return "<p class='muted'>No saved pages yet. Start a live session or direct capture.</p>", "<div class='viewer'><p class='muted'>No page capture selected.</p></div>"
    user = require_user(request)
    ev = evidence_for(selected_id)
    if not ev:
        return "<p class='muted'>Selected saved page was not found.</p>", "<div class='viewer'><p class='muted'>Selected saved page missing.</p></div>"
    model = saved_capture_model(ev)
    assets = captured_assets_for_model(ev, model)
    ok, why = render_assets_allowed(user, ev)
    unlocked = page_render_unlock_ok(request, selected_id)
    requested_render = str(request.query_params.get('render') or 'safe').lower()
    exact_active = requested_render == 'exact' and ok and unlocked
    mode = 'exact' if exact_active else 'safe'
    iframe = f"<iframe class='render-frame' sandbox='allow-same-origin' src='/evidence/{selected_id}/page-render-frame?render={mode}'></iframe>"
    asset_rows = "".join(
        f"<tr><td><a href='/evidence/{a['resource_evidence_id']}'>#{a['resource_evidence_id']}</a></td><td>{h(a['resource_type'])}</td><td>{h(a['mime_type'])}</td><td>{h(a['size'])}</td><td class='hashcell'><code>{h(a['sha256'])}</code></td><td class='urlcell'>{h(a['original_url'])}</td></tr>"
        for a in assets
    )
    exact_controls = ""
    if ok and not unlocked:
        exact_controls = f"""<form class='card warn noprint' method='post' action='{back_url}/{selected_id}/unlock' data-webauthn-action='exact_page_render'>
          <h3>Unlock exact local page render</h3>
          <p class='small muted'>Exact mode can show locally saved images, video, audio, CSS, and fonts from this capture. It does <b>not</b> contact the source website. Unlock is temporary and logged.</p>
          <input type='hidden' name='return_to' value='{h(str(request.url))}'>
          <label>Reason</label><input name='reason' placeholder='case note / reason'>
          <label>Admin master key</label><input type='password' name='master_key' required>
          <button class='warn'>Unlock exact local page</button>
        </form>"""
    elif ok and unlocked:
        exact_controls = f"<div class='card good noprint'><b>Exact local renderer unlocked for this browser session.</b> <a class='button good' href='{h(back_url)}?eid={selected_id}&render=exact'>Show exact local render here</a> <a class='button' href='{h(back_url)}?eid={selected_id}&render=safe'>Show safe render</a> <a class='button' href='/evidence/{selected_id}/page-render?render=exact'>Open full renderer controls</a></div>"
    else:
        exact_controls = f"<div class='card'><b>Exact local renderer unavailable:</b> {h(why)}. Saved local assets linked: {len(assets)}.</div>"
    info = f"""<div class='card good'><h2>{h(heading)}</h2>
      <p>{badge('exact local render active','warn') if exact_active else badge('safe render active','good')} {badge(ev.get('storage_mode'),'info')} {badge('raw persisted','warn') if ev.get('raw_persisted') else badge('safe summary','good')} {badge('saved assets '+str(len(assets)),'info')}</p>
      <p class='small muted'>Safe render is the default no-network view. Exact local render only uses the HTML/media/CSS assets that BlindSite saved into this case.</p>
      <p><a class='button good' href='/evidence/{selected_id}/page-render'>Open full page renderer</a> <a class='button' href='/evidence/{selected_id}/capture-view'>Capture data</a> <a class='button secondary' href='/evidence/{selected_id}'>Evidence record</a></p>
      <table><tr><th>Title</th><td>{h(model.get('title') or ev.get('filename') or '')}</td></tr><tr><th>Source URL</th><td class='urlcell'>{h(model.get('source_url') or ev.get('source_ref') or '')}</td></tr><tr><th>Evidence SHA-256</th><td class='hashcell'><code>{h(ev.get('sha256'))}</code></td></tr></table>
    </div>{exact_controls}<div class='card'><h3>Local assets linked to this saved page</h3><p class='small muted'>These are the images/video/audio/CSS/fonts the renderer can use when exact mode is unlocked. Scroll sideways for full URLs/hashes.</p><div class='table-scroll'><table><tr><th>Evidence</th><th>Type</th><th>MIME</th><th>Size</th><th>SHA-256</th><th>Original URL</th></tr>{asset_rows or '<tr><td colspan="6" class="muted">No saved local assets for this capture. Use lab/full-forensic + allow media + download allowed media to preserve media for exact rendering.</td></tr>'}</table></div></div>"""
    return info, iframe


@app.get("/cases/{case_id}/pages", response_class=HTMLResponse)
def case_pages_viewer(request: Request, case_id: int, eid: str = "", render: str = "safe", msg: str | None = None) -> HTMLResponse:
    require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    captures = page_captures_for_case(case_id)
    selected_id = int(eid) if str(eid).isdigit() else (int(captures[0]["evidence_id"]) if captures else 0)
    rows = []
    for c in captures:
        active = " style='background:#0f2f46'" if int(c["evidence_id"]) == selected_id else ""
        rows.append(f"<tr{active}><td><a class='button good' href='/cases/{case_id}/pages?eid={c['evidence_id']}'>Load safe</a> <a class='button warn' href='/cases/{case_id}/pages?eid={c['evidence_id']}&render=exact'>Try exact</a></td><td><a href='/evidence/{c['evidence_id']}/page-render'>Full page</a></td><td>{h(c['title'] or c['filename'] or '')}<br><span class='small muted'>{h(c['created_at'])}</span></td><td>{badge(c['capture_mode'],'info')} {badge('raw','warn') if c['raw_persisted'] else badge('safe','good')}</td><td class='urlcell'>{h(c['page_url'])}</td></tr>")
    info, iframe = page_viewer_render_block(request, selected_id, back_url=f"/cases/{case_id}/pages", heading=f"Case page viewer: {case['name']}")
    body = f"""{flash(msg)}<div class='card'><h2>Case page viewer: {h(case['name'])}</h2><p>{badge(case['mode'],'info')} {badge('compliance-safe','good') if case['compliance_safe'] else badge('review/lab','warn')} {badge(case['default_media_policy'],'info')}</p><p class='small muted'>Use Load safe for a no-media/no-network reconstruction. Use Try exact only when this case captured raw HTML plus locally saved media and an authorized admin unlocks it.</p></div><div class='grid' style='grid-template-columns:minmax(360px,42%) minmax(480px,1fr)'><div class='card capture-list'><h2>Saved pages</h2><div class='table-scroll'><table><tr><th>Load</th><th>Open</th><th>Title</th><th>Mode</th><th>URL</th></tr>{''.join(rows) or '<tr><td colspan="5" class="muted">No saved pages.</td></tr>'}</table></div></div><div><div>{info}</div><div class='card'><h2>Rendered saved page</h2>{iframe}</div></div></div>"""
    return layout(request, f"Case pages #{case_id}", body)


@app.post("/cases/{case_id}/pages/{eid}/unlock")
def case_pages_unlock(request: Request, case_id: int, eid: int, master_key: str = Form(""), reason: str = Form(""), return_to: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev or int(ev.get('case_id') or 0) != int(case_id):
        raise HTTPException(404, "Saved page not found in this case")
    redir = webauthn_recent_or_redirect(request, user, "exact_page_render", f"/cases/{case_id}/pages?eid={eid}")
    if redir:
        return redir
    ok, why = render_assets_allowed(user, ev)
    if not ok:
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=case_id, evidence_id=eid, details={"reason": why})
        raise HTTPException(403, why)
    if not verify_master_key(master_key):
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=case_id, evidence_id=eid, details={"reason": "bad master key", "user_reason": reason})
        raise HTTPException(403, "Master key required")
    request.session[f"page_render_unlock_{eid}"] = {"user": user["username"], "expires": time.time() + 900, "reason": reason}
    log_event(user["username"], "CASE_PAGE_RENDER_EXACT_UNLOCKED", case_id=case_id, evidence_id=eid, details={"reason": reason, "ttl_seconds": 900})
    return RedirectResponse(f"/cases/{case_id}/pages?eid={eid}&render=exact&msg=Exact%20local%20renderer%20unlocked", 303)


@app.get("/live/{sid}/pages", response_class=HTMLResponse)
def live_pages_viewer(request: Request, sid: str, eid: str = "", render: str = "safe", msg: str | None = None) -> HTMLResponse:
    require_user(request)
    row = rowdict(fetchone("SELECT s.*,c.name case_name FROM browser_sessions s LEFT JOIN cases c ON c.id=s.case_id WHERE session_id=?", (sid,)))
    if not row:
        raise HTTPException(404, "Live session not found")
    captures = page_captures_for_session(sid)
    selected_id = int(eid) if str(eid).isdigit() else (int(captures[0]["evidence_id"]) if captures else 0)
    rows = []
    for c in captures:
        active = " style='background:#0f2f46'" if int(c["evidence_id"]) == selected_id else ""
        rows.append(f"<tr{active}><td><a class='button good' href='/live/{sid}/pages?eid={c['evidence_id']}'>Load safe</a> <a class='button warn' href='/live/{sid}/pages?eid={c['evidence_id']}&render=exact'>Try exact</a></td><td><a href='/evidence/{c['evidence_id']}/page-render'>Full page</a></td><td>{h(c['title'] or c['filename'] or '')}<br><span class='small muted'>{h(c['created_at'])}</span></td><td>{badge(c['capture_mode'],'info')} {badge('raw','warn') if c['raw_persisted'] else badge('safe','good')}</td><td class='urlcell'>{h(c['page_url'])}</td></tr>")
    info, iframe = page_viewer_render_block(request, selected_id, back_url=f"/live/{sid}/pages", heading=f"Session page viewer: {sid}")
    body = f"""{flash(msg)}<div class='card'><h2>Live session page viewer</h2><p>{badge(row['status'],'good' if row['status']=='running' else 'warn')} {badge(row['browser_choice'],'info')} {badge('Tor','info') if row['use_tor'] else badge('Direct')} {badge(row['media_policy'],'info')}</p><p><a class='button' href='/live/{sid}'>Back to session data</a> {'<a class="button" href="/cases/'+str(row['case_id'])+'/pages">Open case page viewer</a>' if row.get('case_id') else ''}</p></div><div class='grid' style='grid-template-columns:minmax(360px,42%) minmax(480px,1fr)'><div class='card capture-list'><h2>Saved pages from this session</h2><div class='table-scroll'><table><tr><th>Load</th><th>Open</th><th>Title</th><th>Mode</th><th>URL</th></tr>{''.join(rows) or '<tr><td colspan="5" class="muted">No saved pages yet.</td></tr>'}</table></div></div><div><div>{info}</div><div class='card'><h2>Rendered saved page</h2>{iframe}</div></div></div>"""
    return layout(request, f"Session pages {sid}", body)


@app.post("/live/{sid}/pages/{eid}/unlock")
def live_pages_unlock(request: Request, sid: str, eid: int, master_key: str = Form(""), reason: str = Form(""), return_to: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    row = rowdict(fetchone("SELECT * FROM browser_sessions WHERE session_id=?", (sid,)))
    ev = evidence_for(eid)
    if not row or not ev:
        raise HTTPException(404, "Saved page not found")
    model = saved_capture_model(ev)
    if str((model.get('metadata') or {}).get('session_id') or '') != sid:
        raise HTTPException(403, "Saved page is not linked to this session")
    redir = webauthn_recent_or_redirect(request, user, "exact_page_render", f"/live/{sid}/pages?eid={eid}")
    if redir:
        return redir
    ok, why = render_assets_allowed(user, ev)
    if not ok:
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=ev.get('case_id'), evidence_id=eid, session_id=sid, details={"reason": why})
        raise HTTPException(403, why)
    if not verify_master_key(master_key):
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=ev.get('case_id'), evidence_id=eid, session_id=sid, details={"reason": "bad master key", "user_reason": reason})
        raise HTTPException(403, "Master key required")
    request.session[f"page_render_unlock_{eid}"] = {"user": user["username"], "expires": time.time() + 900, "reason": reason}
    log_event(user["username"], "SESSION_PAGE_RENDER_EXACT_UNLOCKED", case_id=ev.get('case_id'), evidence_id=eid, session_id=sid, details={"reason": reason, "ttl_seconds": 900})
    return RedirectResponse(f"/live/{sid}/pages?eid={eid}&render=exact&msg=Exact%20local%20renderer%20unlocked", 303)


@app.get("/evidence/{eid}/page-render", response_class=HTMLResponse)
def evidence_page_renderer(request: Request, eid: int, msg: str | None = None, render: str = "safe") -> HTMLResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if not is_page_capture_evidence(ev):
        raise HTTPException(400, "This evidence item is not a saved URL/page capture")
    model = saved_capture_model(ev)
    assets = captured_assets_for_model(ev, model)
    allowed, why = render_assets_allowed(user, ev)
    unlocked = page_render_unlock_ok(request, eid)
    exact_available = allowed
    active = "exact" if render == "exact" and exact_available and unlocked else "safe"
    iframe_src = f"/evidence/{eid}/page-render-frame?render={active}"
    asset_rows = "".join(f"<tr><td><a href='/evidence/{a['resource_evidence_id']}'>#{a['resource_evidence_id']}</a></td><td>{h(a['resource_type'])}</td><td>{h(a['mime_type'])}</td><td>{h(a['size'])}</td><td class='hashcell'><code>{h(a['sha256'])}</code></td><td class='urlcell'>{h(a['original_url'])}</td></tr>" for a in assets)
    unlock_form = ""
    if exact_available and not unlocked:
        unlock_form = f"""<form class='card warn noprint' method='post' action='/evidence/{eid}/page-render/unlock' data-webauthn-action='exact_page_render'><h3>Unlock exact local renderer</h3><p class='small muted'>This uses saved local original assets only. It does not contact the source website. It can reveal locally saved images/video/audio from this capture.</p><label>Reason</label><input name='reason' placeholder='case note / reason'><label>Admin master key</label><input type='password' name='master_key' required><button class='warn'>Unlock for this session</button></form>"""
    elif exact_available and unlocked:
        unlock_form = f"<div class='card good noprint'><b>Exact local renderer unlocked for this browser session.</b> <a class='button good' href='/evidence/{eid}/page-render?render=exact'>Load exact local renderer</a></div>"
    else:
        unlock_form = f"<div class='card'><b>Exact renderer unavailable:</b> {h(why)}. Saved assets: {len(assets)}.</div>"
    body = f"""{flash(msg)}<div class='card good'><h2>Page renderer for evidence #{eid}</h2><p>{badge('safe renderer active','good') if active=='safe' else badge('exact local renderer active','warn')} {badge(ev['storage_mode'],'info')} {badge('raw persisted','warn') if ev['raw_persisted'] else badge('safe summary','good')}</p><p class='muted'>Safe renderer shows the sanitized saved page. Exact renderer, when policy permits and master key is supplied, rewrites the original saved HTML to locally saved assets only. Scripts, forms, frames, remote network, and navigation are disabled.</p><p><a class='button' href='/evidence/{eid}/capture-view'>Capture data</a> <a class='button secondary' href='/evidence/{eid}'>Evidence record</a> <a class='button' href='/evidence/{eid}/capture-frame' target='_blank'>Open safe summary frame</a></p><table><tr><th>Title</th><td>{h(model.get('title') or '')}</td></tr><tr><th>Source URL</th><td class='urlcell'>{h(model.get('source_url') or ev.get('source_ref') or '')}</td></tr><tr><th>Evidence SHA-256</th><td class='hashcell'><code>{h(ev['sha256'])}</code></td></tr></table></div>{unlock_form}<div class='card'><h2>Rendered page</h2><iframe class='render-frame' sandbox='allow-same-origin' src='{iframe_src}'></iframe></div><div class='card'><h2>Saved local assets available for exact renderer</h2><p class='small muted'>Scroll sideways for full source URLs and hashes.</p><div class='table-scroll'><table><tr><th>Evidence</th><th>Type</th><th>MIME</th><th>Size</th><th>SHA-256</th><th>Original URL</th></tr>{asset_rows or '<tr><td colspan="6" class="muted">No saved local assets for this capture.</td></tr>'}</table></div></div>"""
    log_event(user["username"], "PAGE_RENDERER_OPENED", case_id=ev.get("case_id"), evidence_id=eid, details={"active": active, "asset_count": len(assets), "source_url_sha256": model.get("source_url_sha256")})
    return layout(request, f"Page Renderer #{eid}", body)


@app.post("/evidence/{eid}/page-render/unlock")
def evidence_page_renderer_unlock(request: Request, eid: int, master_key: str = Form(""), reason: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    redir = webauthn_recent_or_redirect(request, user, "exact_page_render", f"/evidence/{eid}/page-render")
    if redir:
        return redir
    ok, why = render_assets_allowed(user, ev)
    if not ok:
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": why})
        raise HTTPException(403, why)
    if not verify_master_key(master_key):
        log_event(user["username"], "PAGE_RENDER_UNLOCK_DENIED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": "bad master key", "user_reason": reason})
        raise HTTPException(403, "Master key required")
    request.session[f"page_render_unlock_{eid}"] = {"user": user["username"], "expires": time.time() + 900, "reason": reason}
    log_event(user["username"], "PAGE_RENDER_EXACT_UNLOCKED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": reason, "ttl_seconds": 900})
    return RedirectResponse(f"/evidence/{eid}/page-render?render=exact&msg=Exact%20local%20renderer%20unlocked", 303)


@app.get("/evidence/{eid}/page-render-frame", response_class=HTMLResponse)
def evidence_page_render_frame(request: Request, eid: int, render: str = "safe") -> HTMLResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if not is_page_capture_evidence(ev):
        raise HTTPException(400, "This evidence item is not a saved URL/page capture")
    headers = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}
    if render == "exact":
        ok, why = render_assets_allowed(user, ev)
        if not ok or not page_render_unlock_ok(request, eid):
            raise HTTPException(403, why if not ok else "Exact renderer is not unlocked for this browser session")
        log_event(user["username"], "PAGE_RENDER_EXACT_SERVED", case_id=ev.get("case_id"), evidence_id=eid)
        return HTMLResponse(rendered_capture_html(ev), headers=headers)
    model = saved_capture_model(ev)
    log_event(user["username"], "PAGE_RENDER_SAFE_SERVED", case_id=ev.get("case_id"), evidence_id=eid)
    return HTMLResponse(saved_capture_frame_html(ev, model), headers=headers)




def response_with_optional_range(request: Request, data: bytes, media_type: str, *, filename: str = "", download: bool = False, cache_control: str = "no-store, no-cache, must-revalidate, max-age=0") -> Response:
    """Serve bytes with basic HTTP Range support for recovered media playback.

    Browsers often request video/audio with Range headers. Serving the full file
    with 200 OK can leave some dynamic players stuck on poster/loading states.
    This helper keeps existing behavior for normal requests while returning 206
    for valid byte-range requests.
    """
    media_type = media_type or "application/octet-stream"
    headers = {"Cache-Control": cache_control, "Pragma": "no-cache", "Accept-Ranges": "bytes"}
    if download:
        headers["Content-Disposition"] = f"attachment; filename={clean_filename(filename or 'recovered_object.bin')}"
    range_header = (request.headers.get("range") or request.headers.get("Range") or "").strip()
    if not range_header or not range_header.lower().startswith("bytes="):
        headers["Content-Length"] = str(len(data))
        return Response(data, media_type=media_type, headers=headers)
    size = len(data)
    spec = range_header.split("=", 1)[1].split(",", 1)[0].strip()
    try:
        if spec.startswith("-"):
            length = int(spec[1:] or "0")
            if length <= 0:
                raise ValueError("bad suffix range")
            start = max(0, size - length)
            end = size - 1
        else:
            start_s, end_s = (spec.split("-", 1) + [""])[:2]
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        if start < 0 or end < start or start >= size:
            raise ValueError("range outside object")
        end = min(end, size - 1)
    except Exception:
        bad_headers = dict(headers)
        bad_headers["Content-Range"] = f"bytes */{size}"
        return Response(b"", status_code=416, media_type=media_type, headers=bad_headers)
    chunk = data[start:end + 1]
    headers.update({
        "Content-Range": f"bytes {start}-{end}/{size}",
        "Content-Length": str(len(chunk)),
    })
    return Response(chunk, status_code=206, media_type=media_type, headers=headers)


@app.get("/evidence/{page_eid}/render-asset/{asset_eid}")
def evidence_render_asset(request: Request, page_eid: int, asset_eid: int) -> Response:
    user = require_user(request)
    page_ev = evidence_for(page_eid)
    asset_ev = evidence_for(asset_eid)
    if not page_ev or not asset_ev:
        raise HTTPException(404, "Asset not found")
    ok, why = render_assets_allowed(user, page_ev)
    if not ok or not page_render_unlock_ok(request, page_eid):
        raise HTTPException(403, why if not ok else "Exact renderer is not unlocked")
    linked = fetchone("SELECT 1 FROM captured_assets WHERE root_evidence_id=? AND resource_evidence_id=?", (page_eid, asset_eid))
    if not linked and asset_ev.get("parent_evidence_id") != page_eid:
        model = saved_capture_model(page_ev)
        session_id = str((model.get("metadata") or {}).get("session_id") or "")
        source_url = str(model.get("source_url") or page_ev.get("source_ref") or "")
        source_aliases = url_aliases(source_url)
        bm = None
        if session_id:
            bm = fetchone("SELECT * FROM blocked_media WHERE materialized_evidence_id=? AND session_id=? LIMIT 1", (asset_eid, session_id))
        if not bm and source_aliases:
            for row in fetchall("SELECT * FROM blocked_media WHERE materialized_evidence_id=? LIMIT 50", (asset_eid,)):
                if (url_aliases(str(row["page_url"] or "")) & source_aliases) or (url_aliases(str(row["referrer"] or "")) & source_aliases):
                    bm = row
                    break
        if not bm:
            raise HTTPException(403, "Asset is not linked to this page capture")
    data = read_evidence(asset_eid)
    log_event(user["username"], "PAGE_RENDER_ASSET_SERVED", case_id=page_ev.get("case_id"), evidence_id=asset_eid, details={"page_evidence_id": page_eid})
    return response_with_optional_range(request, data, asset_ev["mime_type"] or "application/octet-stream", filename=asset_ev.get("filename") or "asset.bin", cache_control="no-store")


@app.post("/evidence/{eid}/issue-token")
def issue_token(request: Request, eid: int, mode: str = Form(...), master_key: str = Form(""), reason: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if mode == "full":
        redir = webauthn_recent_or_redirect(request, user, "full_reveal", f"/evidence/{eid}")
        if redir:
            return redir
    ok, why = reveal_allowed(user, ev, mode, master_key)
    if not ok:
        log_event(user["username"], "VIEW_TOKEN_DENIED", case_id=ev.get("case_id"), evidence_id=eid, details={"mode": mode, "reason": why, "user_reason": reason})
        raise HTTPException(403, why)
    if mode == "blur":
        create_blur(ev, user["username"])
        execute("UPDATE evidence SET status='blurred_preview_viewed' WHERE id=?", (eid,))
        log_event(user["username"], "BLURRED_PREVIEW_VIEWED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": reason})
    elif mode == "full":
        execute("UPDATE evidence SET status='full_reveal_token_issued' WHERE id=?", (eid,))
        log_event(user["username"], "FULL_REVEAL_TOKEN_ISSUED", case_id=ev.get("case_id"), evidence_id=eid, details={"reason": reason})
    else:
        log_event(user["username"], "BLOCKED_MODE_CONFIRMED", case_id=ev.get("case_id"), evidence_id=eid)
    tok = signed_token(eid, mode, user["username"])
    return RedirectResponse(f"/evidence/{eid}?mode={mode}&token={tok}", 303)


@app.get("/evidence/{eid}/serve")
def serve_evidence(request: Request, eid: int, mode: str = "blocked", token: str = "") -> Response:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    verify_view_token(token, eid, mode, user["username"])
    if hard_sealed_escrow_evidence(ev):
        meta = evidence_meta_dict(ev)
        if meta.get("hard_sealed_organization_media"):
            raise HTTPException(403, "This evidence is hard-sealed to the organization escrow public key and cannot be locally served; use sealed export/reviewer decrypt")
        raise HTTPException(403, "This evidence is hard-sealed for Civilian Unknown Master Key custody and cannot be locally served")
    if mode == "blur":
        ok, why = reveal_allowed(user, ev, "blur")
        if not ok:
            raise HTTPException(403, why)
        did = create_blur(ev, user["username"])
        derived, data = read_derived(did)
        log_event(user["username"], "BLURRED_PREVIEW_SERVED", case_id=ev.get("case_id"), evidence_id=eid, details={"derived_id": did})
        return Response(data, media_type=derived["mime_type"])
    if mode == "full":
        if sealed_preserved_media_evidence(ev):
            if civilian_unknown_master_mode() or custody_mode() != "organization":
                raise HTTPException(403, "Sealed-preserved blocked media is only locally served in Organization-Controlled Key mode after master-key token issuance")
            data = read_evidence(eid)
            log_event(user["username"], "SEALED_PRESERVED_MEDIA_FULL_SERVED", case_id=ev.get("case_id"), evidence_id=eid)
            return Response(data, media_type=ev["mime_type"], headers={"Cache-Control": "no-store"})
        ok, why = reveal_allowed(user, ev, "full", "")
        # Token already proved master-key was supplied at issue time; re-check static hard blocks only.
        if lockdown() or case_safe(case_for(ev.get("case_id"))) or ev.get("lock_direct_original_access"):
            raise HTTPException(403, "Full serve blocked by hard policy")
        data = read_evidence(eid)
        log_event(user["username"], "FULL_ORIGINAL_SERVED", case_id=ev.get("case_id"), evidence_id=eid)
        return Response(data, media_type=ev["mime_type"])
    raise HTTPException(403, "Blocked mode does not serve bytes")


@app.post("/evidence/{eid}/export")
def export_evidence(request: Request, eid: int, include_plaintext: str | None = Form(None), master_key: str = Form("")) -> StreamingResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    case = case_for(ev.get("case_id"))
    want_plain = bool(include_plaintext)
    if want_plain:
        redir = webauthn_recent_or_redirect(request, user, "plaintext_export", f"/evidence/{eid}")
        if redir:
            return redir
        if hard_sealed_escrow_evidence(ev):
            raise HTTPException(403, "Hard-sealed escrow evidence cannot be plaintext-exported from the local app; use sealed export and reviewer decrypt workflow")
        if sealed_preserved_media_evidence(ev):
            raise HTTPException(403, "Sealed-preserved blocked media cannot be plaintext-exported from the civilian/local app; use sealed LE export and reviewer decrypt workflow")
        if lockdown() and setting_bool("disable_plaintext_export_in_lockdown", "1"):
            raise HTTPException(403, "Lockdown disables plaintext export")
        if case and case.get("no_plaintext_export"):
            raise HTTPException(403, "Case policy disables plaintext export")
        if ev.get("disable_plaintext_export"):
            raise HTTPException(403, "Evidence policy disables plaintext export")
        if setting_bool("require_approval_plaintext_export", "1") and not is_admin(user) and not approval_exists("plaintext_export", ev.get("case_id"), eid, None):
            raise HTTPException(403, "Plaintext export requires approval")
        if not verify_master_key(master_key):
            raise HTTPException(403, "Master key required for plaintext export")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        app_genesis = application_genesis_report(case_id=ev.get("case_id")) if ev.get("case_id") else application_genesis_report(investigation_id="global")
        manifest = {"exported_at": utcnow(), "exported_by": user["username"], "evidence": ev, "case": case, "include_plaintext": want_plain, "audit_verification": verify_audit_chain(), "application_genesis": app_genesis, "executable_genesis_seal": app_genesis}
        z.writestr("manifest.json", pretty(manifest))
        z.writestr("integrity/application_genesis.json", pretty(app_genesis))
        z.write(data_path(ev["object_path"]), f"encrypted_or_stored/{Path(ev['object_path']).name}")
        z.writestr("audit_for_evidence.json", pretty([dict(r) for r in fetchall("SELECT * FROM audit_events WHERE evidence_id=? ORDER BY id", (eid,))]))
        if want_plain:
            z.writestr(f"plaintext/{ev['filename']}", read_evidence(eid))
    log_event(user["username"], "EVIDENCE_EXPORTED", case_id=ev.get("case_id"), evidence_id=eid, details={"include_plaintext": want_plain})
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f"attachment; filename=evidence_{eid}_bundle.zip"})


@app.post("/evidence/{eid}/quarantine")
def toggle_quarantine(request: Request, eid: int) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    new = 0 if ev.get("quarantined") else 1
    execute("UPDATE evidence SET quarantined=? WHERE id=?", (new, eid))
    log_event(user["username"], "EVIDENCE_QUARANTINE_TOGGLED", case_id=ev.get("case_id"), evidence_id=eid, details={"quarantined": bool(new)})
    return RedirectResponse(f"/evidence/{eid}", 303)


@app.get("/blocked", response_class=HTMLResponse)
def blocked_list(request: Request, q: str = "") -> HTMLResponse:
    require_user(request)
    if q:
        like = f"%{q}%"
        rows = fetchall("SELECT * FROM blocked_media WHERE media_url LIKE ? OR url_sha256 LIKE ? OR resource_type LIKE ? OR metadata_record_hash LIKE ? ORDER BY id DESC LIMIT 300", (like, like, like, like))
    else:
        rows = fetchall("SELECT * FROM blocked_media ORDER BY id DESC LIMIT 300")
    trs = "".join(f"<tr><td><a href='/blocked/{r['id']}'>#{r['id']}</a></td><td>{h(r['resource_type'])}</td><td>{h(r['policy'])}</td><td>{badge('downloaded','warn') if r['downloaded'] else badge('not downloaded','good')}</td><td class='small'>{h(r['media_url'][:140])}</td><td><code>{h(r['metadata_record_hash'][:18])}…</code></td></tr>" for r in rows)
    body = f"<div class='card'><h2>Blocked media metadata</h2><form><input name='q' value='{h(q)}' placeholder='URL, hash, type'><button>Search</button></form><table><tr><th>ID</th><th>Type</th><th>Policy</th><th>State</th><th>URL</th><th>Metadata hash</th></tr>{trs}</table></div>"
    return layout(request, "Blocked Media", body)


@app.get("/blocked/{bid}", response_class=HTMLResponse)
def blocked_detail(request: Request, bid: int, msg: str | None = None) -> HTMLResponse:
    require_user(request)
    bm = rowdict(fetchone("SELECT * FROM blocked_media WHERE id=?", (bid,)))
    if not bm:
        raise HTTPException(404, "Blocked media record not found")
    case = case_for(bm.get("case_id"))
    can_materialize = not (lockdown() and setting_bool("disable_materialization_in_lockdown", "1")) and not (case and (case.get("compliance_safe") or case.get("never_materialize_originals")))
    form = "<div class='card safe'><h2>Original materialization disabled</h2><p>This record remains metadata-only under current safe/lockdown policy.</p></div>"
    if can_materialize:
        form = f"""<div class='card danger'><h2>Materialize original bytes</h2><p>This downloads the original body into evidence. Use only for approved lab/supervised workflows.</p><form method='post' action='/blocked/{bid}/materialize' data-webauthn-action='materialize_original'><label>Reason</label><input name='reason' required><label>Master reveal key</label><input name='master_key' type='password'><label><input type='checkbox' name='use_tor' value='1'> Use Tor</label><button class='danger'>Download original into evidence</button></form><form method='post' action='/approvals/request'><input type='hidden' name='action' value='materialize_original'><input type='hidden' name='case_id' value='{h(bm.get('case_id') or '')}'><input type='hidden' name='blocked_media_id' value='{bid}'><label>Request approval</label><input name='reason'><button class='warn'>Request materialization approval</button></form></div>"""
    body = f"{flash(msg)}<div class='card'><h2>Blocked media #{bid}</h2><p>{badge(bm['resource_type'])} {badge('not downloaded','good') if not bm['downloaded'] else badge('downloaded','warn')}</p><table><tr><th>URL</th><td>{h(bm['media_url'])}</td></tr><tr><th>URL SHA-256</th><td><code>{h(bm['url_sha256'])}</code></td></tr><tr><th>Metadata record SHA-256</th><td><code>{h(bm['metadata_record_hash'])}</code></td></tr><tr><th>Header SHA-256</th><td><code>{h(bm['header_sha256'])}</code></td></tr><tr><th>Content SHA-256</th><td>{h(bm['content_sha256'] or 'not available because body was not downloaded')}</td></tr></table><pre>{h(pretty(bm))}</pre></div>{form}"
    return layout(request, f"Blocked #{bid}", body)


@app.post("/blocked/{bid}/materialize")
def blocked_materialize(request: Request, bid: int, reason: str = Form(...), master_key: str = Form(""), use_tor: str | None = Form(None)) -> RedirectResponse:
    user = require_user(request)
    redir = webauthn_recent_or_redirect(request, user, "materialize_original", f"/blocked/{bid}")
    if redir:
        return redir
    bm = rowdict(fetchone("SELECT * FROM blocked_media WHERE id=?", (bid,)))
    if not bm:
        raise HTTPException(404, "Blocked media record not found")
    case = case_for(bm.get("case_id"))
    if lockdown() and setting_bool("disable_materialization_in_lockdown", "1"):
        raise HTTPException(403, "Lockdown disables materialization")
    if case and (case.get("compliance_safe") or case.get("never_materialize_originals")):
        raise HTTPException(403, "Case policy disables materialization")
    if setting_bool("require_approval_materialization", "1") and not is_admin(user) and not approval_exists("materialize_original", bm.get("case_id"), None, bid):
        raise HTTPException(403, "Materialization requires approval")
    if not verify_master_key(master_key):
        raise HTTPException(403, "Master key required")
    r = request_session(bool(use_tor)).get(bm["media_url"], timeout=30)
    r.raise_for_status()
    mt = (header_get(dict(r.headers), "Content-Type") or bm.get("content_type") or "application/octet-stream").split(";", 1)[0]
    fname = clean_filename(Path(urlparse(bm["media_url"]).path).name or f"materialized_{bid}{ext_for_mime(mt)}")
    eid = persist_evidence(case_id=bm.get("case_id"), actor=user["username"], kind=kind_for(mt, fname), source_type="blocked_media_materialization", source_ref=bm["media_url"], filename=fname, mime_type=mt, payload=r.content, encrypt=True, parent_id=bm.get("root_evidence_id"), storage_mode="materialized_original", raw_persisted=True, meta={"blocked_media_id": bid, "reason": reason, "headers": dict(r.headers), "url_sha256": bm["url_sha256"]}, quarantined=True, lock_original=False if edition()=="lab" else True)
    execute("UPDATE blocked_media SET downloaded=1, materialized_evidence_id=?, status_code=?, content_type=?, content_length=?, headers_json=?, content_sha256=? WHERE id=?", (eid, r.status_code, mt, str(len(r.content)), json.dumps(dict(r.headers), ensure_ascii=False), sha256_bytes(r.content), bid))
    log_event(user["username"], "BLOCKED_MEDIA_MATERIALIZED", case_id=bm.get("case_id"), evidence_id=eid, blocked_media_id=bid, details={"reason": reason})
    return RedirectResponse(f"/evidence/{eid}", 303)


@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request) -> HTMLResponse:
    user = require_user(request)
    rows = fetchall("SELECT * FROM approvals ORDER BY id DESC LIMIT 300")
    trs = "".join(f"<tr><td>#{r['id']}</td><td>{h(r['action'])}</td><td>{badge(r['status'],'good' if r['status']=='approved' else 'bad' if r['status']=='denied' else 'warn')}</td><td>{h(r['requested_by'])}</td><td>{h(r['reason'])}</td><td>{h(r['reviewed_by'] or '')}</td><td>{('<form method=\'post\' action=\'/approvals/'+str(r['id'])+'/review\'><input type=\'hidden\' name=\'status\' value=\'approved\'><input name=\'review_reason\' placeholder=\'review note\'><button class=\'good\'>Approve</button></form><form method=\'post\' action=\'/approvals/'+str(r['id'])+'/review\'><input type=\'hidden\' name=\'status\' value=\'denied\'><input name=\'review_reason\' placeholder=\'review note\'><button class=\'danger\'>Deny</button></form>') if is_admin(user) and r['status']=='pending' else ''}</td></tr>" for r in rows)
    return layout(request, "Approvals", f"<div class='card'><h2>Approval queue</h2><table><tr><th>ID</th><th>Action</th><th>Status</th><th>Requested by</th><th>Reason</th><th>Reviewed by</th><th>Review</th></tr>{trs}</table></div>")


@app.post("/approvals/request")
def approval_request(request: Request, action: str = Form(...), reason: str = Form(""), case_id: str = Form(""), evidence_id: str = Form(""), blocked_media_id: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip() else None
    eid = int(evidence_id) if str(evidence_id).strip() else None
    bid = int(blocked_media_id) if str(blocked_media_id).strip() else None
    aid = execute("INSERT INTO approvals(case_id,evidence_id,blocked_media_id,action,requested_by,reason,status,created_at) VALUES(?,?,?,?,?,?,?,?)", (cid, eid, bid, action, user["username"], reason, "pending", utcnow()))
    app_genesis = application_genesis_report(case_id=cid) if cid else application_genesis_report(investigation_id="global")
    log_event(user["username"], "APPROVAL_REQUESTED", case_id=cid, evidence_id=eid, blocked_media_id=bid, details={"approval_id": aid, "action": action, "reason": reason, "custody_access_request_json": {"approval_id": aid, "action": action, "reason": reason, "case_id": cid, "evidence_id": eid, "blocked_media_id": bid, "requested_by": user["username"], "custody_mode": custody_mode(), "application_genesis": app_genesis}})
    target = f"/evidence/{eid}" if eid else f"/blocked/{bid}" if bid else "/approvals"
    return RedirectResponse(target + "?msg=Approval%20requested", 303)


@app.post("/approvals/{aid}/review")
def approval_review(request: Request, aid: int, status: str = Form(...), review_reason: str = Form("")) -> RedirectResponse:
    user = require_admin(request)
    if status not in {"approved", "denied"}:
        raise HTTPException(400, "Status must be approved or denied")
    row = rowdict(fetchone("SELECT * FROM approvals WHERE id=?", (aid,)))
    if not row:
        raise HTTPException(404, "Approval not found")
    execute("UPDATE approvals SET status=?, reviewed_by=?, review_reason=?, reviewed_at=? WHERE id=?", (status, user["username"], review_reason, utcnow(), aid))
    log_event(user["username"], "APPROVAL_REVIEWED", case_id=row.get("case_id"), evidence_id=row.get("evidence_id"), blocked_media_id=row.get("blocked_media_id"), details={"approval_id": aid, "status": status, "review_reason": review_reason})
    return RedirectResponse("/approvals", 303)


@app.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "") -> HTMLResponse:
    require_user(request)
    evs: list[sqlite3.Row] = []
    bms: list[sqlite3.Row] = []
    audits: list[sqlite3.Row] = []
    if q:
        like = f"%{q}%"
        evs = fetchall("SELECT * FROM evidence WHERE filename LIKE ? OR source_ref LIKE ? OR sha256 LIKE ? OR mime_type LIKE ? OR kind LIKE ? ORDER BY id DESC LIMIT 100", (like, like, like, like, like))
        bms = fetchall("SELECT * FROM blocked_media WHERE media_url LIKE ? OR url_sha256 LIKE ? OR metadata_record_hash LIKE ? OR resource_type LIKE ? ORDER BY id DESC LIMIT 100", (like, like, like, like))
        audits = fetchall("SELECT * FROM audit_events WHERE actor LIKE ? OR action LIKE ? OR details_json LIKE ? OR event_hash LIKE ? ORDER BY id DESC LIMIT 100", (like, like, like, like))
    ev_rows = "".join(f"<tr><td><a href='/evidence/{r['id']}'>#{r['id']}</a></td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td><code>{h(r['sha256'][:20])}…</code></td></tr>" for r in evs)
    bm_rows = "".join(f"<tr><td><a href='/blocked/{r['id']}'>#{r['id']}</a></td><td>{h(r['resource_type'])}</td><td class='small'>{h(r['media_url'][:130])}</td><td><code>{h(r['url_sha256'][:20])}…</code></td></tr>" for r in bms)
    au_rows = "".join(f"<tr><td>{h(r['created_at'])}</td><td>{h(r['actor'])}</td><td>{h(r['action'])}</td><td><code>{h(r['event_hash'][:20])}…</code></td></tr>" for r in audits)
    body = f"<div class='card'><h2>Search</h2><form><input name='q' value='{h(q)}' placeholder='filename, URL, hash, actor, policy, event'><button>Search</button></form></div><div class='grid'><div class='card'><h2>Evidence</h2><table><tr><th>ID</th><th>Name</th><th>Kind</th><th>SHA</th></tr>{ev_rows}</table></div><div class='card'><h2>Blocked media</h2><table><tr><th>ID</th><th>Type</th><th>URL</th><th>URL hash</th></tr>{bm_rows}</table></div><div class='card'><h2>Audit events</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Event hash</th></tr>{au_rows}</table></div></div>"
    return layout(request, "Search", body)


def report_data(case_id: int | None = None) -> dict[str, Any]:
    if case_id:
        case = case_for(case_id)
        evidence = [dict(r) for r in fetchall("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,))]
        blocked = [dict(r) for r in fetchall("SELECT * FROM blocked_media WHERE case_id=? ORDER BY id", (case_id,))]
        approvals = [dict(r) for r in fetchall("SELECT * FROM approvals WHERE case_id=? ORDER BY id", (case_id,))]
        audit = [dict(r) for r in fetchall("SELECT * FROM audit_events WHERE case_id=? ORDER BY id", (case_id,))]
        page_captures = [dict(r) for r in page_capture_rows(case_id=case_id, limit=1000)]
        media_evidence = [dict(r) for r in saved_media_rows(case_id=case_id, limit=1000)]
    else:
        case = None
        evidence = [dict(r) for r in fetchall("SELECT * FROM evidence ORDER BY id DESC LIMIT 500")]
        blocked = [dict(r) for r in fetchall("SELECT * FROM blocked_media ORDER BY id DESC LIMIT 500")]
        approvals = [dict(r) for r in fetchall("SELECT * FROM approvals ORDER BY id DESC LIMIT 500")]
        audit = [dict(r) for r in fetchall("SELECT * FROM audit_events ORDER BY id DESC LIMIT 1000")]
        page_captures = [dict(r) for r in page_capture_rows(limit=1000)]
        media_evidence = [dict(r) for r in saved_media_rows(limit=1000)]
    app_genesis = application_genesis_report(case_id=case_id) if case_id else application_genesis_report(investigation_id="global")
    return {
        "generated_at": utcnow(),
        "app": APP_NAME,
        "version": APP_VERSION,
        "case": case,
        "evidence": evidence,
        "page_captures": page_captures,
        "media_evidence": media_evidence,
        "blocked_media": blocked,
        "approvals": approvals,
        "audit_events": audit,
        "audit_verification": verify_audit_chain(),
        "application_genesis": app_genesis,
        "executable_genesis_seal": app_genesis,
        "settings_summary": {
            "edition": edition(),
            "hard_default_safe_mode": get_setting("hard_default_safe_mode", "1"),
            "default_media_policy": get_setting("default_media_policy", "block_images_video"),
            "default_user_agent_profile": get_setting("default_user_agent_profile", "chrome_windows"),
        },
    }


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request) -> HTMLResponse:
    require_user(request)
    cases = fetchall("SELECT c.*, (SELECT count(*) FROM evidence e WHERE e.case_id=c.id) ev_count, (SELECT count(*) FROM blocked_media b WHERE b.case_id=c.id) bm_count FROM cases c ORDER BY c.id DESC")
    rows = "".join(f"<tr><td><a href='/cases/{r['id']}/report'>#{r['id']}</a></td><td>{h(r['name'])}</td><td>{h(r['mode'])}</td><td>{r['ev_count']}</td><td>{r['bm_count']}</td><td><a href='/cases/{r['id']}/report.json'>JSON</a> | <a href='/cases/{r['id']}/report.csv'>CSV</a> | <a href='/cases/{r['id']}/report.zip'>ZIP</a> | <a href='/cases/{r['id']}/sealed-export'>Sealed</a></td></tr>" for r in cases)
    body = f"<div class='card'><h2>Global reports</h2><p><a class='button' href='/reports/global.json'>Global JSON</a> <a class='button' href='/reports/global.csv'>Global CSV</a></p></div><div class='card'><h2>Case reports</h2><table><tr><th>ID</th><th>Case</th><th>Mode</th><th>Evidence</th><th>Blocked</th><th>Exports</th></tr>{rows}</table></div>"
    return layout(request, "Reports", body)


@app.get("/reports/global.json")
def global_json(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(report_data())


@app.get("/reports/global.csv")
def global_csv(request: Request) -> StreamingResponse:
    require_user(request)
    return csv_response(report_data(), "global_report.csv")


@app.get("/cases/{case_id}/report", response_class=HTMLResponse)
def case_report(request: Request, case_id: int) -> HTMLResponse:
    require_user(request)
    data = report_data(case_id)
    if not data["case"]:
        raise HTTPException(404, "Case not found")
    ev_rows = "".join(f"<tr><td>#{r['id']}</td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td>{h(r['storage_mode'])}</td><td><code>{h(r['sha256'][:20])}…</code></td></tr>" for r in data["evidence"])
    bm_rows = "".join(f"<tr><td>#{r['id']}</td><td>{h(r['resource_type'])}</td><td>{h(r['policy'])}</td><td>{'yes' if r['downloaded'] else 'no'}</td><td><code>{h(r['metadata_record_hash'][:20])}…</code></td></tr>" for r in data["blocked_media"])
    page_rows = "".join(f"<tr><td><a href='/evidence/{r['evidence_id']}/page-render'>Open renderer</a></td><td>#{r['evidence_id']}</td><td>{h(r['title'] or r['filename'])}</td><td>{h(r['capture_mode'])}</td><td class='urlcell'>{h(r['page_url'])}</td></tr>" for r in data.get("page_captures", []))
    media_rows = "".join(f"<tr><td><a href='/evidence/{r['id']}'>#{r['id']}</a></td><td>{h(r['filename'])}</td><td>{h(r['kind'])}</td><td>{h(r['mime_type'])}</td><td><code>{h(r['sha256'][:20])}…</code></td></tr>" for r in data.get("media_evidence", []))
    genesis_block = application_genesis_html_block(data.get("application_genesis"))
    body = f"<div class='card'><h2>Case report: {h(data['case']['name'])}</h2><p>{badge('audit verified','good') if data['audit_verification']['ok'] else badge('audit problem','bad')}</p><p><a class='button' href='/cases/{case_id}/report.json'>JSON</a> <a class='button' href='/cases/{case_id}/report.csv'>CSV</a> <a class='button' href='/cases/{case_id}/report.zip'>Report-only ZIP with saved pages</a> <a class='button good' href='/captures?case_id={case_id}'>Saved pages</a> <a class='button' href='/media?case_id={case_id}'>Media</a> <a class='button warn' href='/cases/{case_id}/sealed-export'>Sealed LE Export</a></p><pre>{h(pretty(data['case']))}</pre></div><div class='card'>{genesis_block}</div><div class='card'><h2>Saved pages</h2><div class='table-scroll'><table><tr><th>Viewer</th><th>Evidence</th><th>Title</th><th>Mode</th><th>URL</th></tr>{page_rows or '<tr><td colspan="5" class="muted">No saved pages.</td></tr>'}</table></div></div><div class='card'><h2>Media evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>MIME</th><th>SHA</th></tr>{media_rows or '<tr><td colspan="5" class="muted">No saved media evidence.</td></tr>'}</table></div><div class='card'><h2>Evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>Storage</th><th>SHA</th></tr>{ev_rows}</table></div><div class='card'><h2>Blocked media</h2><table><tr><th>ID</th><th>Type</th><th>Policy</th><th>Downloaded</th><th>Metadata hash</th></tr>{bm_rows}</table></div>"
    return layout(request, f"Case {case_id} Report", body)


@app.get("/cases/{case_id}/report.json")
def case_report_json(request: Request, case_id: int) -> JSONResponse:
    require_user(request)
    return JSONResponse(report_data(case_id))


@app.get("/cases/{case_id}/report.csv")
def case_report_csv(request: Request, case_id: int) -> StreamingResponse:
    require_user(request)
    return csv_response(report_data(case_id), f"case_{case_id}_report.csv")


def csv_response(data: dict[str, Any], filename: str) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "id", "field1", "field2", "field3", "field4"])
    if data.get("case"):
        c = data["case"]
        w.writerow(["case", c["id"], c["name"], c["mode"], c["compliance_safe"], c["created_at"]])
    for e in data.get("evidence", []):
        w.writerow(["evidence", e["id"], e["filename"], e["kind"], e["sha256"], e["storage_mode"]])
    for b in data.get("blocked_media", []):
        w.writerow(["blocked_media", b["id"], b["resource_type"], b["url_sha256"], b["metadata_record_hash"], b["downloaded"]])
    for a in data.get("approvals", []):
        w.writerow(["approval", a["id"], a["action"], a["status"], a["requested_by"], a.get("reviewed_by")])
    out = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    return StreamingResponse(out, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})



@app.post("/cases/{case_id}/rendered-export")
def case_rendered_export(request: Request, case_id: int, include_assets: str | None = Form(None), master_key: str = Form("")) -> StreamingResponse:
    user = require_user(request)
    if include_assets:
        redir = webauthn_recent_or_redirect(request, user, "exact_page_render", f"/cases/{case_id}")
        if redir:
            return redir
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    want_assets = bool(include_assets)
    if want_assets:
        if lockdown() or case_safe(case) or case.get("no_plaintext_export"):
            raise HTTPException(403, "Policy disables export of local original assets for this case")
        if not verify_master_key(master_key):
            raise HTTPException(403, "Master key required to export local original assets")
        if setting_bool("require_approval_plaintext_export", "1") and not is_admin(user) and not approval_exists("plaintext_export", case_id, None, None):
            raise HTTPException(403, "Plaintext/local asset export requires approval")
    captures = page_captures_for_case(case_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        index_rows = []
        for c in captures:
            ev = evidence_for(int(c["evidence_id"]))
            if not ev:
                continue
            if want_assets and ev.get("raw_persisted"):
                prefix = f"assets/evidence_{ev['id']}"
                html_doc = rendered_capture_html(ev, for_export=True, export_asset_prefix=prefix)
                for a in captured_assets_for_model(ev, saved_capture_model(ev)):
                    asset_ev = evidence_for(int(a["resource_evidence_id"]))
                    if asset_ev:
                        z.writestr(f"rendered_pages/{prefix}/asset_{a['resource_evidence_id']}_{clean_filename(asset_ev['filename'])}", read_evidence(int(a["resource_evidence_id"])))
                fname = f"rendered_pages/evidence_{ev['id']}_exact_local.html"
            else:
                html_doc = saved_capture_frame_html(ev, saved_capture_model(ev), for_export=True)
                fname = f"rendered_pages/evidence_{ev['id']}_safe.html"
            z.writestr(fname, html_doc)
            index_rows.append(f"<tr><td>#{h(ev['id'])}</td><td><a href='{h(fname.split('/',1)[1] if fname.startswith('rendered_pages/') else fname)}'>{h(c['title'] or ev['filename'])}</a></td><td>{h(c['capture_mode'])}</td><td>{h(c['page_url'])}</td></tr>")
        z.writestr("rendered_pages/index.html", f"<!doctype html><html><head><meta charset='utf-8'><title>Rendered pages</title><style>body{{font-family:Arial;margin:24px}}td,th{{border:1px solid #ddd;padding:8px}}table{{border-collapse:collapse;width:100%}}</style></head><body><h1>Rendered pages for case {h(case['name'])}</h1><p>Assets included: {h(want_assets)}. Exact local renderers contain no remote-network permission and no scripts.</p><table><tr><th>Evidence</th><th>Open</th><th>Mode</th><th>URL</th></tr>{''.join(index_rows)}</table></body></html>")
        z.writestr("README.txt", "Open rendered_pages/index.html. Safe exports include no original media bytes. Asset exports require master-key policy and contain locally saved originals for renderer playback only.\n")
    log_event(user["username"], "CASE_RENDERED_EXPORT_CREATED", case_id=case_id, details={"include_assets": want_assets, "captures": len(captures)})
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f"attachment; filename=case_{case_id}_rendered_pages.zip"})



# -------------------------------
# Sealed Law-Enforcement / Escrow Evidence Export
# -------------------------------

def rows_as_dicts(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in fetchall(sql, params)]


def collect_case_sealed_rows(case_id: int) -> dict[str, Any]:
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    evidence = rows_as_dicts("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,))
    derived = rows_as_dicts("SELECT d.* FROM derived d JOIN evidence e ON e.id=d.evidence_id WHERE e.case_id=? ORDER BY d.id", (case_id,))
    blocked = rows_as_dicts("SELECT * FROM blocked_media WHERE case_id=? ORDER BY id", (case_id,))
    page_captures = rows_as_dicts("SELECT * FROM page_captures WHERE case_id=? ORDER BY id", (case_id,))
    captured_assets = rows_as_dicts("SELECT * FROM captured_assets WHERE case_id=? ORDER BY id", (case_id,))
    sessions = rows_as_dicts("SELECT * FROM browser_sessions WHERE case_id=? ORDER BY id", (case_id,))
    session_ids = [s["session_id"] for s in sessions]
    browser_events: list[dict[str, Any]] = []
    if session_ids:
        q = ",".join("?" for _ in session_ids)
        browser_events = rows_as_dicts(f"SELECT * FROM browser_events WHERE session_id IN ({q}) ORDER BY id", tuple(session_ids))
    approvals = rows_as_dicts("SELECT * FROM approvals WHERE case_id=? ORDER BY id", (case_id,))
    stop_reports = rows_as_dicts("SELECT * FROM stop_reports WHERE case_id=? ORDER BY id", (case_id,))
    ev_ids = [e["id"] for e in evidence]
    bm_ids = [b["id"] for b in blocked]
    clauses = ["case_id=?"]
    params: list[Any] = [case_id]
    if ev_ids:
        clauses.append("evidence_id IN (%s)" % ",".join("?" for _ in ev_ids))
        params.extend(ev_ids)
    if bm_ids:
        clauses.append("blocked_media_id IN (%s)" % ",".join("?" for _ in bm_ids))
        params.extend(bm_ids)
    if session_ids:
        clauses.append("session_id IN (%s)" % ",".join("?" for _ in session_ids))
        params.extend(session_ids)
    audit_events = rows_as_dicts("SELECT * FROM audit_events WHERE " + " OR ".join(clauses) + " ORDER BY id", tuple(params))
    return {
        "case": case,
        "evidence": evidence,
        "derived": derived,
        "blocked_media": blocked,
        "page_captures": page_captures,
        "captured_assets": captured_assets,
        "browser_sessions": sessions,
        "browser_events": browser_events,
        "approvals": approvals,
        "stop_reports": stop_reports,
        "audit_events": audit_events,
    }


def sealed_public_key(recipient_public_key_pem: str = "") -> tuple[str, str]:
    if civilian_unknown_master_mode():
        uscm_pem = load_uscm_escrow_public_key().strip()
        uscm_fp = escrow_public_fingerprint(uscm_pem)
        if not uscm_pem or not uscm_fp:
            raise HTTPException(400, "Civilian Unknown Master Key mode requires the embedded USCM escrow public key")
        if recipient_public_key_pem and escrow_public_fingerprint(recipient_public_key_pem.strip()) != uscm_fp:
            raise HTTPException(400, "Civilian Unknown Master Key mode uses the USCM escrow public key only. Do not provide a recipient/custom key for this custody mode.")
        return uscm_pem, uscm_fp
    org_hard_pem, org_hard_fp = organization_hard_seal_public_key()
    recipient_pem = (recipient_public_key_pem or "").strip()
    recipient_fp = escrow_public_fingerprint(recipient_pem) if recipient_pem else ""
    if organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0") and org_hard_pem and org_hard_fp:
        # Preserved blocked media may already be hard-sealed to the organization key.
        # Use the same public key for sealed export so one matching private key can
        # decrypt both hard-sealed media and normal vault-wrapped objects.
        if recipient_pem and recipient_fp != org_hard_fp:
            raise HTTPException(400, "Organization hard-sealed media preservation is enabled. Use the same organization escrow public key for sealed export, or disable hard-sealed media preservation before exporting to a different key.")
        pem = org_hard_pem
        fp = org_hard_fp
        return pem, fp
    pem = (recipient_pem or get_setting("escrow_public_key_pem", "") or load_bundled_escrow_public_key()).strip()
    fp = escrow_public_fingerprint(pem) if pem else ""
    if not fp and get_setting("escrow_public_key_fingerprint", ""):
        fp = get_setting("escrow_public_key_fingerprint", "")
    if not pem or not fp:
        raise HTTPException(400, "Sealed export requires a valid escrow/recipient RSA public key. Organization mode can paste a recipient public key on this page.")
    return pem, fp


def sealed_key_material(recipient_public_key_pem: str = "") -> dict[str, Any]:
    pem, fp = sealed_public_key(recipient_public_key_pem)
    wrapped_storage = escrow_wrap(pem, KEY_FILE.read_bytes())
    configured_fp = get_setting("escrow_public_key_fingerprint", "")
    wrapped_master = ""
    if civilian_unknown_master_mode():
        wrapped_master = get_setting("wrapped_master_key", "")
        if not wrapped_master:
            raise HTTPException(500, "Civilian Unknown Master Key mode is missing the wrapped master reveal key")
    return {"escrow_public_key_pem": pem, "escrow_public_key_fingerprint": fp, "wrapped_storage_key": wrapped_storage, "wrapped_master_key": wrapped_master, "recipient_public_key_used": bool(recipient_public_key_pem and not civilian_unknown_master_mode())}


def add_sealed_object(z: zipfile.ZipFile, row: dict[str, Any], object_class: str, out: list[dict[str, Any]]) -> None:
    rel_path = row.get("object_path") or ""
    src = data_path(rel_path)
    row_hard_sealed = hard_sealed_escrow_evidence(row)
    row_meta = evidence_meta_dict(row)
    info: dict[str, Any] = {
        "object_class": object_class,
        "id": row.get("id"),
        "database_object_path": rel_path,
        "filename": row.get("filename"),
        "mime_type": row.get("mime_type"),
        "logical_sha256": row.get("sha256"),
        "logical_size": row.get("size"),
        "source_encrypted": bool(row.get("encrypted")),
        "hard_sealed_escrow_evidence": bool(row_hard_sealed),
        "hard_sealed_civilian_evidence": bool(row_meta.get("hard_sealed_civilian_evidence")),
        "hard_sealed_organization_media": bool(row_meta.get("hard_sealed_organization_media")),
        "hard_sealed_escrow_public_key_fingerprint": row_meta.get("escrow_public_key_fingerprint"),
        "sealed_reencrypted": False,
        "missing": False,
    }
    if not rel_path or not src.exists():
        info["missing"] = True
        out.append(info)
        return
    stored = src.read_bytes()
    sealed = stored
    decrypt_with = "escrow_wrapped_vault_storage_key"
    if row_hard_sealed:
        # Already encrypted to the escrow public key with a per-object key. The
        # local vault key cannot decrypt this object; sealed export copies the
        # hard-sealed container as-is for reviewer/private-key recovery.
        if not parse_hard_sealed_container(stored):
            info["hard_sealed_container_warning"] = "row is marked hard-sealed, but object did not parse as a hard-sealed escrow container"
        decrypt_with = "escrow_hard_sealed_object_key"
    elif not bool(row.get("encrypted")):
        # Never write plaintext evidence bytes to a sealed handoff package.
        sealed = encrypt_bytes(stored)
        info["sealed_reencrypted"] = True
    zip_name = f"encrypted_objects/{object_class}/{int(row.get('id') or 0):06d}_{clean_filename(row.get('filename') or Path(rel_path).name)}.fvault"
    z.writestr(zip_name, sealed)
    info.update({
        "zip_path": zip_name,
        "stored_object_sha256": sha256_bytes(stored),
        "sealed_object_sha256": sha256_bytes(sealed),
        "sealed_object_size": len(sealed),
        "decrypt_with": decrypt_with,
    })
    out.append(info)


def hard_sealed_object_fingerprints(rows: list[dict[str, Any]]) -> set[str]:
    fps: set[str] = set()
    for row in rows:
        if not hard_sealed_escrow_evidence(row):
            continue
        meta = evidence_meta_dict(row)
        fp = str(meta.get("escrow_public_key_fingerprint") or "").strip()
        if fp:
            fps.add(fp)
            continue
        rel_path = row.get("object_path") or ""
        try:
            container = parse_hard_sealed_container(data_path(rel_path).read_bytes()) if rel_path else None
            cfp = str((container or {}).get("escrow_public_key_fingerprint") or "").strip()
            if cfp:
                fps.add(cfp)
        except Exception:
            pass
    return fps


def sealed_html_summary(manifest: dict[str, Any]) -> str:
    case = manifest.get("case") or {}
    ev_rows = "".join(f"<tr><td>#{h(o.get('id'))}</td><td>{h(o.get('filename'))}</td><td>{h(o.get('object_class'))}</td><td>{h(o.get('mime_type'))}</td><td><code>{h(o.get('logical_sha256'))}</code></td><td>{h(o.get('zip_path'))}</td></tr>" for o in manifest.get("objects", []))
    bm_rows = "".join(f"<tr><td>#{h(b.get('id'))}</td><td>{h(b.get('resource_type'))}</td><td>{h(b.get('downloaded'))}</td><td>{h(b.get('media_url'))}</td><td><code>{h(b.get('metadata_record_hash'))}</code></td></tr>" for b in manifest.get("blocked_media", [])[:1000])
    genesis_block = application_genesis_html_block(manifest.get("application_genesis"))
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>BlindSite Sealed Export</title><style>body{{font-family:Arial;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;vertical-align:top}}code{{word-break:break-all}}.warn{{background:#fff3cd;border:1px solid #d6b656;padding:10px;margin:12px 0}}</style></head><body><h1>BlindSite Sealed Evidence Export</h1><div class='warn'>This report is metadata only. Original evidence bytes are included only as encrypted vault objects.</div><h2>Case</h2><p><b>ID:</b> {h(case.get('id'))}<br><b>Name:</b> {h(case.get('name'))}<br><b>Custody:</b> {h(manifest.get('custody_mode'))}<br><b>Escrow fingerprint:</b> <code>{h(manifest.get('escrow_public_key_fingerprint'))}</code></p>{genesis_block}<h2>Encrypted objects</h2><table><tr><th>ID</th><th>Filename</th><th>Class</th><th>MIME</th><th>Logical SHA-256</th><th>ZIP path</th></tr>{ev_rows}</table><h2>Blocked/media records</h2><table><tr><th>ID</th><th>Type</th><th>Downloaded</th><th>URL</th><th>Metadata hash</th></tr>{bm_rows}</table></body></html>"""


def build_sealed_case_package(case_id: int, actor: str, recipient: str = "", reason: str = "", recipient_public_key_pem: str = "") -> tuple[bytes, dict[str, Any]]:
    if not setting_bool("sealed_export_enabled", "1"):
        raise HTTPException(403, "Sealed evidence export is disabled in Settings")
    data = collect_case_sealed_rows(case_id)
    keymat = sealed_key_material(recipient_public_key_pem)
    hard_fps = hard_sealed_object_fingerprints(data.get("evidence") or [])
    if hard_fps and keymat["escrow_public_key_fingerprint"] not in hard_fps:
        raise HTTPException(400, "This case contains hard-sealed evidence encrypted to escrow fingerprint(s) " + ", ".join(sorted(hard_fps)) + ". Use the matching escrow public key for sealed export so the reviewer private key can recover all objects.")
    created_at = utcnow()
    app_genesis = application_genesis_report(case_id=case_id)
    objects: list[dict[str, Any]] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for row in data["evidence"]:
            add_sealed_object(z, row, "evidence", objects)
        if setting_bool("sealed_export_include_derived", "1"):
            for row in data["derived"]:
                add_sealed_object(z, row, "derived", objects)
        manifest = {
            "package_type": "blindsite_sealed_law_enforcement_evidence_package",
            "format_version": 3,
            "app": APP_NAME,
            "version": APP_VERSION,
            "created_at": created_at,
            "created_by": actor,
            "recipient": recipient,
            "reason": reason,
            "case_id": case_id,
            "application_genesis": app_genesis,
            "executable_genesis_seal": app_genesis,
            "case": data["case"],
            "custody_mode": custody_mode(),
            "civilian_unknown_master_key_mode": civilian_unknown_master_mode(),
            "local_user_plaintext_export_allowed": False,
            "contains_plaintext_evidence": False,
            "contains_encrypted_original_evidence": True,
            "escrow_public_key_fingerprint": keymat["escrow_public_key_fingerprint"],
            "wrapped_storage_key_present": bool(keymat.get("wrapped_storage_key")),
            "wrapped_master_key_present": bool(keymat.get("wrapped_master_key")),
            "recipient_public_key_used": bool(keymat.get("recipient_public_key_used")),
            "audit_verification_at_export": verify_audit_chain(),
            "storage_hash_at_export": storage_hash(),
            "object_count": len(objects),
            "sealed_preserved_media_count": sum(1 for e in data["evidence"] if e.get("storage_mode") == SEALED_PRESERVED_STORAGE_MODE),
            "hard_sealed_escrow_evidence_count": sum(1 for o in objects if o.get("hard_sealed_escrow_evidence")),
            "hard_sealed_civilian_evidence_count": sum(1 for o in objects if o.get("hard_sealed_civilian_evidence")),
            "hard_sealed_organization_media_count": sum(1 for o in objects if o.get("hard_sealed_organization_media")),
            "hard_sealed_escrow_fingerprints": sorted(hard_fps),
            "civilian_hard_sealed_storage": civilian_unknown_master_mode(),
            "organization_hard_sealed_media_storage": organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0"),
            "sealed_media_preservation_policy": sealed_media_preservation_policy(data.get("case")),
            "objects": objects,
            "blocked_media": data["blocked_media"],
            "page_captures": data["page_captures"],
            "captured_assets": data["captured_assets"],
            "browser_sessions": data["browser_sessions"],
            "approvals": data["approvals"],
            "stop_reports": data["stop_reports"],
            "audit_events": data["audit_events"],
            "important_disclosure": "This ZIP contains encrypted evidence objects, metadata, hashes, blocked-media records, and escrow-wrapped keys. It intentionally contains no plaintext originals.",
            "decrypt_command": "python BlindSite.py decrypt-sealed blindsite_case_SEALED.zip --private-key escrow_private_key.pem --out reviewed_package --decrypt-evidence --i-understand",
        }
        manifest_text = pretty(manifest)
        z.writestr("manifest.json", manifest_text)
        z.writestr("manifest_sha256.txt", sha256_text(manifest_text) + "\n")
        z.writestr("integrity/application_genesis.json", pretty(app_genesis))
        z.writestr("case/report.json", pretty(report_data(case_id)))
        z.writestr("case/all_case_records.json", pretty(data))
        z.writestr("reports/sealed_export_summary.html", sealed_html_summary(manifest))
        z.writestr("escrow/escrow_public_key_fingerprint.txt", keymat["escrow_public_key_fingerprint"] + "\n")
        z.writestr("escrow/escrow_public_key.pem", keymat["escrow_public_key_pem"])
        z.writestr("escrow/wrapped_vault_storage_key.txt", keymat["wrapped_storage_key"] + "\n")
        if keymat.get("wrapped_master_key"):
            z.writestr("escrow/wrapped_master_reveal_key.txt", keymat["wrapped_master_key"] + "\n")
        z.writestr("integrity/audit_verification.json", pretty(verify_audit_chain()))
        z.writestr("integrity/storage_hash.txt", storage_hash() + "\n")
        z.writestr("README_LAW_ENFORCEMENT.txt", f"""BlindSite sealed evidence package

Case: {data['case'].get('name')} (#{case_id})
Created: {created_at}
Created by: {actor}
Recipient: {recipient or 'not specified'}
Custody mode: {custody_label()}
Escrow public key fingerprint: {keymat['escrow_public_key_fingerprint']}
Application Genesis Hash: {app_genesis.get('executable_sha256') or 'UNAVAILABLE'}
Executable Genesis Seal: {app_genesis.get('genesis_hash') or app_genesis.get('event_hash') or 'UNAVAILABLE'}

Verification helper:
{app_genesis.get('verification_statement') or ''}

This package is intended for law enforcement, counsel, USCM, or another cleared reviewer.
It contains actual stored evidence objects, but only in encrypted form. It does not include plaintext originals.

Civilian Unknown Master Key statement:
- If custody_mode is civilian_unknown_master, the local user did not create, know, or control the private reveal key through BlindSite.
- Sensitive/original evidence objects may be hard-sealed at capture time to the USCM escrow public key. These hard-sealed objects are not decryptable by the local civilian vault key.
- Full reveal, plaintext export, and original materialization are blocked locally through BlindSite.
- A cleared reviewer with the escrow private key can decrypt both hard-sealed objects and normal vault-encrypted objects using this single Python file's decrypt-sealed command.

Organization hard-sealed media statement:
- If Organization-Controlled Key mode has organization hard-sealed media enabled, preserved blocked media may be hard-sealed at capture time to the organization escrow public key.
- Those hard-sealed media objects are not decryptable by the local BlindSite vault key and require the matching organization escrow private key in reviewer/decrypt workflow.

Suggested review command:
python BlindSite.py decrypt-sealed blindsite_case_{case_id}_sealed_evidence.zip --private-key escrow_private_key.pem --out decrypted_case_{case_id} --decrypt-evidence --i-understand
""")
    payload = buf.getvalue()
    summary = {"case_id": case_id, "package_sha256": sha256_bytes(payload), "package_size": len(payload), "application_genesis": app_genesis, "object_count": len(objects), "sealed_preserved_media_count": sum(1 for e in data["evidence"] if e.get("storage_mode") == SEALED_PRESERVED_STORAGE_MODE), "hard_sealed_escrow_evidence_count": sum(1 for o in objects if o.get("hard_sealed_escrow_evidence")), "hard_sealed_civilian_evidence_count": sum(1 for o in objects if o.get("hard_sealed_civilian_evidence")), "hard_sealed_organization_media_count": sum(1 for o in objects if o.get("hard_sealed_organization_media")), "recipient": recipient, "reason": reason, "custody_mode": custody_mode(), "escrow_public_key_fingerprint": keymat["escrow_public_key_fingerprint"]}
    return payload, summary


@app.get("/cases/{case_id}/sealed-export", response_class=HTMLResponse)
def sealed_export_page(request: Request, case_id: int) -> HTMLResponse:
    require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0") and get_setting("organization_hard_seal_public_key_fingerprint", ""):
        fp = get_setting("organization_hard_seal_public_key_fingerprint", "")
        fp_note = "Organization hard-sealed media public key will be used by default."
    else:
        fp = get_setting("escrow_public_key_fingerprint", "") or escrow_public_fingerprint(get_setting("escrow_public_key_pem", "") or load_bundled_escrow_public_key())
        fp_note = "Paste a recipient/agency public key below for Organization-Controlled exports if no default is configured."
    body = f"""<div class='card safe'><h2>Sealed law-enforcement evidence export</h2><p>This exports the actual stored evidence blobs in encrypted form so a civilian can hand evidence to law enforcement/USCM without local plaintext reveal.</p><p>{badge(custody_label(),'info')} {badge('No plaintext originals in ZIP','good')} {badge('Encrypted evidence blobs included','warn')}</p><p><b>Default escrow public-key fingerprint:</b> <code>{h(fp or 'not configured')}</code><br><span class='small muted'>{h(fp_note)}</span></p><form method='post' action='/cases/{case_id}/sealed-export' data-webauthn-action='sealed_export'><label>Recipient / agency</label><input name='recipient' placeholder='Law enforcement / agency / counsel'><label>Reason / handoff note</label><textarea name='reason'></textarea><label>Optional recipient/agency public key PEM</label><textarea name='recipient_public_key_pem' rows='8' placeholder='Organization mode can paste a recipient public key here. Civilian mode uses the USCM escrow public key only.'></textarea><button class='good'>Download sealed encrypted evidence ZIP</button></form></div>"""
    return layout(request, "Sealed Evidence Export", body)


@app.post("/cases/{case_id}/sealed-export")
def sealed_export_download(request: Request, case_id: int, recipient: str = Form(""), reason: str = Form(""), recipient_public_key_pem: str = Form("")) -> StreamingResponse:
    user = require_user(request)
    redir = webauthn_recent_or_redirect(request, user, "sealed_export", f"/cases/{case_id}/sealed-export")
    if redir:
        return redir
    package, summary = build_sealed_case_package(case_id, user["username"], recipient.strip(), reason.strip(), recipient_public_key_pem.strip())
    log_event(user["username"], "SEALED_EVIDENCE_PACKAGE_EXPORTED", case_id=case_id, details=summary)
    return StreamingResponse(io.BytesIO(package), media_type="application/zip", headers={"Content-Disposition": f"attachment; filename=blindsite_case_{case_id}_sealed_evidence.zip"})


@app.get("/cases/{case_id}/sealed", response_class=HTMLResponse)
def sealed_export_alias(request: Request, case_id: int) -> HTMLResponse:
    return sealed_export_page(request, case_id)


# -------------------------------
# Law-Enforcement / Cleared Reviewer Import + Case Viewer
# -------------------------------

def is_reviewer(user: dict[str, Any]) -> bool:
    return user.get("role") in {"admin", "supervisor", "reviewer"}


def require_reviewer(request: Request) -> dict[str, Any]:
    user = require_user(request)
    if not is_reviewer(user):
        raise HTTPException(403, "Law-enforcement / cleared reviewer area only")
    if not setting_bool("reviewer_enabled", "1"):
        raise HTTPException(403, "Reviewer import/viewer is disabled in Settings")
    return user


def load_escrow_private_key(private_key_pem: str | bytes, passphrase: str = "") -> Any:
    data = private_key_pem if isinstance(private_key_pem, bytes) else private_key_pem.encode("utf-8")
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        return serialization.load_pem_private_key(data, password=password)
    except Exception as exc:
        raise HTTPException(400, f"Could not load escrow private key: {exc}") from exc


def escrow_unwrap(private_key: Any, wrapped_b64: str) -> bytes:
    try:
        wrapped = base64.urlsafe_b64decode((wrapped_b64 or "").strip().encode("ascii"))
        return private_key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(400, f"Could not unwrap sealed package key with this private key: {exc}") from exc


def reviewer_import_for(import_id: int) -> dict[str, Any] | None:
    return rowdict(fetchone("SELECT * FROM reviewer_imports WHERE id=?", (import_id,)))


def reviewer_import_notes(imp: dict[str, Any] | None) -> dict[str, Any]:
    if not imp:
        return {}
    return jloads(imp.get("notes_json"), {}) if isinstance(imp, dict) else {}


def reviewer_import_password_hash(imp: dict[str, Any] | None) -> str:
    notes = reviewer_import_notes(imp)
    return str(notes.get("review_case_password_hash") or "")


def reviewer_import_is_password_protected(imp: dict[str, Any] | None) -> bool:
    return bool(reviewer_import_password_hash(imp))


def reviewer_import_webauthn_protected(imp: dict[str, Any] | None) -> bool:
    notes = reviewer_import_notes(imp)
    return truthy(notes.get("review_case_webauthn_protected", "0"))


def reviewer_import_is_protected(imp: dict[str, Any] | None) -> bool:
    return reviewer_import_is_password_protected(imp) or reviewer_import_webauthn_protected(imp)


def reviewer_import_unlock_timeout_seconds() -> int:
    # 0 disables inactivity locking. Default is 15 minutes.
    return safe_int(get_setting("reviewer_import_unlock_timeout_seconds", "900"), 900, min_value=0, max_value=86400)


def reviewer_import_session_key(import_id: int) -> str:
    return f"reviewer_import_unlocked_{int(import_id)}"


def reviewer_import_unlock_session(request: Request, import_id: int, username: str, method: str) -> None:
    now = time.time()
    request.session[reviewer_import_session_key(import_id)] = {
        "unlocked": True,
        "user": username,
        "method": method,
        "unlocked_at": now,
        "last_activity": now,
    }


def reviewer_import_lock_session(request: Request, import_id: int) -> None:
    request.session.pop(reviewer_import_session_key(import_id), None)


def reviewer_import_session_info(request: Request, import_id: int) -> dict[str, Any]:
    raw = request.session.get(reviewer_import_session_key(import_id))
    if isinstance(raw, dict):
        return dict(raw)
    if raw:
        # Backward-compatible legacy unlock session value from earlier builds.
        now = time.time()
        info = {"unlocked": True, "user": request.session.get("username") or "", "method": "legacy", "unlocked_at": now, "last_activity": now}
        request.session[reviewer_import_session_key(import_id)] = info
        return info
    return {}


def reviewer_import_is_unlocked(request: Request, import_id: int, imp: dict[str, Any] | None = None) -> bool:
    imp = imp or reviewer_import_for(import_id)
    if not reviewer_import_is_protected(imp):
        return True
    info = reviewer_import_session_info(request, import_id)
    if not info.get("unlocked"):
        return False
    username = str(request.session.get("username") or "")
    if info.get("user") and username and str(info.get("user")) != username:
        reviewer_import_lock_session(request, import_id)
        return False
    timeout_s = reviewer_import_unlock_timeout_seconds()
    now = time.time()
    try:
        last_activity = float(info.get("last_activity") or info.get("unlocked_at") or 0)
    except Exception:
        last_activity = 0.0
    if timeout_s and last_activity and now - last_activity > timeout_s:
        reviewer_import_lock_session(request, import_id)
        user = current_user(request)
        if user:
            log_event(user["username"], "REVIEWER_IMPORT_UNLOCK_TIMEOUT", details={"reviewer_import_id": import_id, "timeout_seconds": timeout_s})
        return False
    info["last_activity"] = now
    request.session[reviewer_import_session_key(import_id)] = info
    return True


def require_reviewer_import_unlocked(request: Request, import_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    if reviewer_import_is_protected(imp) and not reviewer_import_is_unlocked(request, import_id, imp):
        raise HTTPException(423, f"Reviewer import is locked. Unlock at /reviewer/imports/{import_id}/unlock")
    return user, imp


def set_reviewer_import_password(import_id: int, password: str, actor: str = "") -> None:
    if not password:
        return
    imp = reviewer_import_for(import_id)
    notes = reviewer_import_notes(imp)
    notes["review_case_password_protected"] = True
    notes["review_case_password_hash"] = hash_password(password)
    notes["review_case_password_set_at"] = utcnow()
    if actor:
        notes["review_case_password_set_by"] = actor
    execute("UPDATE reviewer_imports SET notes_json=? WHERE id=?", (pretty(notes), import_id))


def set_reviewer_import_webauthn_protection(import_id: int, enabled: bool, actor: str = "") -> None:
    imp = reviewer_import_for(import_id)
    notes = reviewer_import_notes(imp)
    notes["review_case_webauthn_protected"] = bool(enabled)
    notes["review_case_webauthn_updated_at"] = utcnow()
    if actor:
        notes["review_case_webauthn_updated_by"] = actor
    execute("UPDATE reviewer_imports SET notes_json=? WHERE id=?", (pretty(notes), import_id))


def reviewer_import_protection_badges(request: Request, imp: dict[str, Any] | sqlite3.Row | None) -> str:
    impd = dict(imp) if isinstance(imp, sqlite3.Row) else (imp or {})
    import_id = int(impd.get("id") or 0)
    bits: list[str] = []
    if reviewer_import_is_password_protected(impd):
        bits.append(badge("password protected", "warn"))
    if reviewer_import_webauthn_protected(impd):
        bits.append(badge("YubiKey protected", "warn"))
    if reviewer_import_is_protected(impd):
        bits.append(badge("unlocked", "good") if reviewer_import_is_unlocked(request, import_id, impd) else badge("locked", "bad"))
        timeout_s = reviewer_import_unlock_timeout_seconds()
        bits.append(badge(("timeout off" if timeout_s == 0 else f"timeout {timeout_s}s"), "info"))
    else:
        bits.append(badge("no local reviewer lock", "info"))
    return " ".join(bits)


def reviewer_import_protection_panel(request: Request, import_id: int, imp: dict[str, Any]) -> str:
    user = current_user(request) or {}
    has_yubi = webauthn_user_has_credentials(str(user.get("username") or "")) if user else False
    timeout_s = reviewer_import_unlock_timeout_seconds()
    info = reviewer_import_session_info(request, import_id)
    last = float(info.get("last_activity") or 0) if info else 0.0
    remaining = max(0, int(timeout_s - (time.time() - last))) if timeout_s and last else (0 if timeout_s else -1)
    remaining_text = "timeout disabled" if timeout_s == 0 else (f"locks after about {remaining}s of inactivity" if remaining else f"timeout {timeout_s}s")
    yubi_disabled = "" if has_yubi else "disabled"
    yubi_note = "" if has_yubi else "<p class='small muted'>Enroll a YubiKey/security key first from Settings → YubiKey to enable YubiKey protection for this import.</p>"
    return f"""<div class='card warn noprint'><h2>Reviewer case protection</h2><p>{reviewer_import_protection_badges(request, imp)} <span class='small muted'>{h(remaining_text)}</span></p><p class='small muted'>This protects access to the imported LE reviewer case inside BlindSite. Unlock can use the review-case password or this user's enrolled YubiKey/security key when enabled.</p><form method='post' action='/reviewer/imports/{import_id}/protection'><label><input type='checkbox' name='review_case_yubikey' value='1' {'checked' if reviewer_import_webauthn_protected(imp) else ''} {yubi_disabled}> Require YubiKey/WebAuthn unlock for this imported case</label>{yubi_note}<button class='secondary'>Save reviewer case protection</button></form><form method='post' action='/reviewer/imports/{import_id}/lock' style='display:inline'><button class='warn'>Lock reviewer case now</button></form></div>"""


def reviewer_object_for(object_id: int) -> dict[str, Any] | None:
    return rowdict(fetchone("SELECT * FROM reviewer_objects WHERE id=?", (object_id,)))


def read_reviewer_object(obj: dict[str, Any]) -> bytes:
    rel = obj.get("plaintext_path") or ""
    if not rel:
        raise HTTPException(404, "Recovered reviewer object has no local vault path")
    path = data_path(rel)
    try:
        if not path.exists() or not path.is_file() or not path.resolve().is_relative_to(REVIEW_DIR.resolve()):
            raise HTTPException(404, "Recovered reviewer object is missing from local review vault")
    except AttributeError:
        resolved = str(path.resolve())
        if not resolved.startswith(str(REVIEW_DIR.resolve())):
            raise HTTPException(403, "Recovered reviewer path is outside review vault")
        if not path.exists() or not path.is_file():
            raise HTTPException(404, "Recovered reviewer object is missing from local review vault")
    return path.read_bytes()


def sealed_zip_inspect_bytes(package_bytes: bytes) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as z:
            names = z.namelist()
            manifest = {}
            manifest_text = ""
            if "manifest.json" in names:
                manifest_text = z.read("manifest.json").decode("utf-8", errors="replace")
                manifest = json.loads(manifest_text)
            manifest_sha_ok = None
            if "manifest_sha256.txt" in names and manifest_text:
                expected = z.read("manifest_sha256.txt").decode("utf-8", errors="replace").strip().split()[0]
                manifest_sha_ok = expected == sha256_text(manifest_text)
            return {
                "ok": True,
                "package_sha256": sha256_bytes(package_bytes),
                "package_size": len(package_bytes),
                "zip_file_count": len(names),
                "manifest_present": bool(manifest),
                "manifest_sha256_ok": manifest_sha_ok,
                "package_type": manifest.get("package_type"),
                "format_version": manifest.get("format_version"),
                "app": manifest.get("app"),
                "version": manifest.get("version"),
                "created_at": manifest.get("created_at"),
                "case_id": manifest.get("case_id"),
                "case_name": (manifest.get("case") or {}).get("name"),
                "custody_mode": manifest.get("custody_mode"),
                "escrow_public_key_fingerprint": manifest.get("escrow_public_key_fingerprint"),
                "contains_plaintext_evidence": manifest.get("contains_plaintext_evidence"),
                "contains_encrypted_original_evidence": manifest.get("contains_encrypted_original_evidence"),
                "object_count": len(manifest.get("objects") or []),
                "sealed_preserved_media_count": manifest.get("sealed_preserved_media_count"),
                "hard_sealed_escrow_evidence_count": manifest.get("hard_sealed_escrow_evidence_count"),
                "hard_sealed_civilian_evidence_count": manifest.get("hard_sealed_civilian_evidence_count"),
                "hard_sealed_organization_media_count": manifest.get("hard_sealed_organization_media_count"),
                "civilian_hard_sealed_storage": manifest.get("civilian_hard_sealed_storage"),
                "organization_hard_sealed_media_storage": manifest.get("organization_hard_sealed_media_storage"),
                "objects": manifest.get("objects") or [],
            }
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "Uploaded file is not a valid ZIP package") from exc
    except Exception as exc:
        raise HTTPException(400, f"Could not inspect sealed ZIP: {exc}") from exc


def sealed_zip_read_json(z: zipfile.ZipFile, name: str, default: Any) -> Any:
    try:
        if name in z.namelist():
            return json.loads(z.read(name).decode("utf-8", errors="replace"))
    except Exception:
        pass
    return default


def reviewer_filename_suggests_audio_fragment(filename: str) -> bool:
    fn = (filename or "").lower()
    return any(x in fn for x in ["cmaf_audio", "_audio_", "audio_", "dash_audio", "audiotrack"])


def reviewer_filename_suggests_playable_video(filename: str) -> bool:
    fn = (filename or "").lower()
    if reviewer_filename_suggests_audio_fragment(fn):
        return False
    if not any(fn.endswith(ext) for ext in VIDEO_EXTS):
        return False
    return any(x in fn for x in ["cmaf_", "m2-res", "dash", "video", "res_"]) or not any(x in fn for x in ["audio", "init"])


def reviewer_playback_kind(obj: dict[str, Any] | sqlite3.Row | None) -> str:
    if not obj:
        return "other"
    try:
        fn = str(obj["filename"] or "")
        mt = str(obj["mime_type"] or "").split(";", 1)[0].lower()
        kind = str(obj["kind"] or "").lower()
        size = int(obj["size"] or 0)
    except Exception:
        d = obj if isinstance(obj, dict) else {}
        fn = str(d.get("filename") or "")
        mt = str(d.get("mime_type") or "").split(";", 1)[0].lower()
        kind = str(d.get("kind") or "").lower()
        size = int(d.get("size") or 0)
    if reviewer_filename_suggests_audio_fragment(fn):
        return "audio"
    if mt.startswith("audio/") or kind == "audio":
        return "audio"
    if mt.startswith("image/") or kind == "image":
        return "image"
    if mt.startswith("video/") or kind == "video" or Path(fn.lower()).suffix in VIDEO_EXTS:
        # Very tiny MP4s from Reddit are often byte-range/init/audio-ish fragments.
        # Treat CMAF_AUDIO as audio above; for non-audio tiny MP4s keep video but
        # de-prioritize in selection rather than hiding them completely.
        return "video"
    return "other"


def reviewer_effective_mime_type(obj: dict[str, Any] | sqlite3.Row | None) -> str:
    """Return a browser-friendly MIME type for recovered-object playback.

    Recovered objects can arrive with generic/misleading MIME types. The viewer
    and raw endpoint should serve clear image/video/audio Content-Type values
    when filename/kind make the type clear.
    """
    if not obj:
        return "application/octet-stream"
    try:
        filename = str(obj["filename"] or "")
        mt = str(obj["mime_type"] or "").split(";", 1)[0].lower().strip()
    except Exception:
        d = obj if isinstance(obj, dict) else {}
        filename = str(d.get("filename") or "")
        mt = str(d.get("mime_type") or "").split(";", 1)[0].lower().strip()
    playback = reviewer_playback_kind(obj)
    guessed = (mimetypes.guess_type(filename)[0] or "").split(";", 1)[0].lower()
    ext = Path(filename.lower()).suffix
    if playback == "image":
        if guessed.startswith("image/"):
            return guessed
        return mt if mt.startswith("image/") else "image/png"
    if playback == "video":
        if ext == ".webm":
            return "video/webm"
        if ext in {".mov", ".qt"}:
            return "video/quicktime"
        if ext in {".m4v", ".mp4"}:
            return "video/mp4"
        if guessed.startswith("video/"):
            return guessed
        return mt if mt.startswith("video/") else "video/mp4"
    if playback == "audio":
        if ext == ".m4a" or (ext == ".mp4" and reviewer_filename_suggests_audio_fragment(filename)):
            return "audio/mp4"
        if guessed.startswith("audio/"):
            return guessed
        return mt if mt.startswith("audio/") else "audio/mpeg"
    return mt or guessed or "application/octet-stream"



def reviewer_best_playback_object(import_id: int, selected: dict[str, Any]) -> dict[str, Any]:
    """If a selected recovered video is a tiny fragment/init/audio-ish file, choose a better related playable object when available."""
    if reviewer_playback_kind(selected) != "video":
        return selected
    try:
        size = int(selected.get("size") or 0)
    except Exception:
        size = 0
    fn = str(selected.get("filename") or "").lower()
    # If this already looks like a substantial playable video, keep it.
    if size >= 150000 and not reviewer_filename_suggests_audio_fragment(fn):
        return selected
    selected_urls = reviewer_object_urls(selected)
    selected_hosts = {urlparse(u).netloc.lower() for u in selected_urls if urlparse(u).netloc}
    selected_ids = set(re.findall(r"v\.redd\.it/([^/?#]+)", " ".join(selected_urls), flags=re.I))
    rows = [rowdict(r) for r in fetchall("SELECT * FROM reviewer_objects WHERE import_id=? AND (kind='video' OR mime_type LIKE 'video/%' OR filename LIKE '%.mp4' OR filename LIKE '%.webm' OR filename LIKE '%.m4v')", (import_id,))]
    candidates = []
    for r in rows:
        if not r or int(r.get("id") or 0) == int(selected.get("id") or 0):
            continue
        if reviewer_playback_kind(r) != "video":
            continue
        r_fn = str(r.get("filename") or "").lower()
        if reviewer_filename_suggests_audio_fragment(r_fn):
            continue
        try:
            r_size = int(r.get("size") or 0)
        except Exception:
            r_size = 0
        if r_size <= size or r_size < 50000:
            continue
        r_urls = reviewer_object_urls(r)
        r_hosts = {urlparse(u).netloc.lower() for u in r_urls if urlparse(u).netloc}
        r_ids = set(re.findall(r"v\.redd\.it/([^/?#]+)", " ".join(r_urls), flags=re.I))
        score = r_size
        if selected_ids and r_ids & selected_ids:
            score += 10_000_000_000
        elif selected_hosts and r_hosts & selected_hosts:
            score += 1_000_000
        if any(x in r_fn for x in ("m2-res", "dash_", "cmaf_", "fallback", "480", "720", "1080")):
            score += 500_000
        candidates.append((score, r))
    if not candidates:
        return selected
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]

def reviewer_object_urls(obj: dict[str, Any] | sqlite3.Row | None) -> set[str]:
    if not obj:
        return set()
    out: set[str] = set()
    try:
        r = dict(obj)
    except Exception:
        r = obj if isinstance(obj, dict) else {}
    for field in ["original_url", "source_ref", "page_url"]:
        out.update(url_aliases(str(r.get(field) or "")))
    try:
        src = reviewer_source_record(r)
        out.update(url_aliases(str(src.get("source_ref") or "")))
        meta = reviewer_nested_json(src.get("meta_json"))
        for field in ["media_url", "media_final_url", "original_url", "page_url"]:
            out.update(url_aliases(str(meta.get(field) or "")))
        for u in meta.get("url_aliases") or []:
            out.update(url_aliases(str(u or "")))
    except Exception:
        pass
    return {u for u in out if u}


def reddit_media_id_from_url(url: str) -> str:
    try:
        p = urlparse(str(url or ""))
        host = p.netloc.lower()
        bits = [b for b in (p.path or "").split("/") if b]
        if host.endswith("v.redd.it") and bits:
            return bits[0]
        # preview/i.redd.it URLs often encode the filename/ID in the path.
        if host.endswith("redd.it") and bits:
            stem = Path(bits[-1]).stem
            return stem.split("-v0-")[-1] if "-v0-" in stem else stem
    except Exception:
        pass
    return ""


def reviewer_best_media_for_reddit_post(import_id: int, source_url: str, asset_map: dict[str, dict[str, Any]], candidates: list[str], post_type: str = "") -> tuple[str, dict[str, Any] | None]:
    """Choose the best recovered object for a Reddit/Shreddit card.

    Reddit video pages often preserve many CMAF objects. Some are tiny audio/init
    fragments (for example CMAF_AUDIO_64.mp4, often ~800 bytes) and should not be
    used as the main <video> source. Prefer non-audio, larger video objects whose
    URL aliases share the same v.redd.it ID or directly match a captured URL.
    """
    post_type_l = (post_type or "").lower()
    cand_aliases: set[str] = set()
    reddit_ids: set[str] = set()
    for u in candidates:
        au = absolute_resource_url(source_url, str(u or ""))
        cand_aliases.update(url_aliases(au))
        rid = reddit_media_id_from_url(au)
        if rid:
            reddit_ids.add(rid)
    rows: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for r in asset_map.values():
        try:
            rid = int(r.get("id") or 0)
        except Exception:
            rid = 0
        if rid and rid in seen_ids:
            continue
        if rid:
            seen_ids.add(rid)
        rows.append(r)
    best: tuple[int, str, dict[str, Any] | None] = (-10**9, "", None)
    for r in rows:
        urls = reviewer_object_urls(r)
        fn = str(r.get("filename") or "")
        mt = str(r.get("mime_type") or "").lower()
        size = int(r.get("size") or 0)
        playback = reviewer_playback_kind(r)
        score = 0
        direct_match = bool(urls & cand_aliases)
        if direct_match:
            score += 900
        obj_ids = {reddit_media_id_from_url(u) for u in urls}
        id_match = bool(reddit_ids and (obj_ids & reddit_ids))
        if id_match:
            score += 650
        # Never rescue a Reddit post with an arbitrary session image/video. If the
        # captured post supplied media candidates, the recovered object must match
        # one of those aliases or the same Reddit media ID. This prevents repeated
        # wrong images appearing in unrelated fallback cards.
        if candidates and not direct_match and not id_match:
            continue
        if post_type_l in {"video", "hosted:video", "rich:video"}:
            if playback == "video":
                score += 500
            elif playback == "audio":
                score -= 900
            elif playback == "image":
                score += 40
            if reviewer_filename_suggests_audio_fragment(fn):
                score -= 1200
            if reviewer_filename_suggests_playable_video(fn):
                score += 220
            fn_l = fn.lower()
            # Prefer muxed/resolution video names when available. Reddit CMAF/DASH
            # files are often video-only with a separate audio track, while m2-res
            # and similar files are more likely to play as a complete browser MP4.
            if "m2-res" in fn_l or "fallback" in fn_l or "progressive" in fn_l:
                score += 360
            if "cmaf_" in fn_l and "audio" not in fn_l:
                score += 90
            if size < 4096:
                score -= 260
            score += min(size // 2000, 360)
        elif post_type_l == "image":
            if playback == "image":
                score += 500
            elif playback == "video":
                score -= 200
            score += min(size // 4000, 120)
        else:
            if playback in {"image", "video"}:
                score += 200
            if playback == "audio":
                score -= 100
            score += min(size // 5000, 150)
        # Prefer exact candidate URL string for remote fallback if no object wins.
        first_url = next(iter(urls), "")
        if score > best[0]:
            best = (score, first_url, r)
    if best[2] is not None and best[0] > 0:
        preferred_url = ""
        for c in candidates:
            if url_aliases(absolute_resource_url(source_url, c)) & reviewer_object_urls(best[2]):
                preferred_url = absolute_resource_url(source_url, c)
                break
        return preferred_url or best[1], best[2]
    return (absolute_resource_url(source_url, candidates[0]) if candidates else ""), None


def reviewer_kind_for(mime_type: str, filename: str, source_record: dict[str, Any] | None, object_class: str) -> str:
    source_record = source_record or {}
    mt = (mime_type or "").split(";", 1)[0].lower().strip()
    fn = (filename or "").lower()
    storage_mode = str(source_record.get("storage_mode") or "").lower()
    source_type = str(source_record.get("source_type") or "").lower()
    src_kind = str(source_record.get("kind") or "").lower()
    snapshot_hint = any(x in " ".join([fn, storage_mode, source_type, src_kind]) for x in ["snapshot", "screenshot", "preview", "derived"])
    if snapshot_hint and object_class == "derived":
        return "snapshot"
    if source_type in {"live_browser_capture", "url_capture"} or storage_mode in {"live_browser_raw_html", "live_browser_sanitized_summary", "sanitized_summary", "metadata_only", "raw_root"} or mt in {"text/html", "application/xhtml+xml"}:
        return "page"
    if mt.startswith("image/"):
        return "image"
    if reviewer_filename_suggests_audio_fragment(fn):
        return "audio"
    if mt.startswith("video/"):
        return "video"
    if mt.startswith("audio/"):
        return "audio"
    if mt == "application/pdf" or fn.endswith(".pdf"):
        return "pdf"
    if "json" in mt or fn.endswith(".json"):
        return "json"
    if mt.startswith("text/") or mt in {"application/xml", "application/xhtml+xml"}:
        return "text"
    if snapshot_hint:
        return "snapshot"
    return "other"


def reviewer_filter_matches(kind: str, selected: str) -> bool:
    if selected == "all":
        return True
    if selected == "pages":
        return kind == "page"
    if selected == "snapshots":
        return kind == "snapshot"
    if selected == "images":
        return kind == "image"
    if selected == "videos":
        return kind == "video"
    if selected == "audio":
        return kind == "audio"
    if selected == "text":
        return kind in {"text", "json"}
    if selected == "other":
        return kind not in {"page", "snapshot", "image", "video", "audio", "text", "json"}
    return True


def decrypt_sealed_package_to_vault(package_bytes: bytes, private_key_pem: str | bytes, passphrase: str, out_dir: Path) -> dict[str, Any]:
    private_key = load_escrow_private_key(private_key_pem, passphrase)
    out_dir.mkdir(parents=True, exist_ok=True)
    objects_dir = out_dir / "objects"
    objects_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as z:
        names = set(z.namelist())
        if "manifest.json" not in names:
            raise HTTPException(400, "Sealed package is missing manifest.json")
        manifest = json.loads(z.read("manifest.json").decode("utf-8", errors="replace"))
        all_records = sealed_zip_read_json(z, "case/all_case_records.json", {})
        report = sealed_zip_read_json(z, "case/report.json", {})
        if "escrow/wrapped_vault_storage_key.txt" not in names:
            raise HTTPException(400, "Sealed package is missing escrow/wrapped_vault_storage_key.txt")
        wrapped_storage_key = z.read("escrow/wrapped_vault_storage_key.txt").decode("utf-8", errors="replace").strip()
        vault_key = escrow_unwrap(private_key, wrapped_storage_key)
        try:
            package_fernet = Fernet(vault_key)
        except Exception as exc:
            raise HTTPException(400, f"Unwrapped storage key is not a valid vault key: {exc}") from exc
        evidence_records = {int(r.get("id")): r for r in (all_records.get("evidence") or []) if r.get("id") is not None}
        derived_records = {int(r.get("id")): r for r in (all_records.get("derived") or []) if r.get("id") is not None}
        page_by_evidence = {int(r.get("evidence_id")): r for r in (all_records.get("page_captures") or []) if r.get("evidence_id") is not None}
        asset_by_resource = {int(r.get("resource_evidence_id")): r for r in (all_records.get("captured_assets") or []) if r.get("resource_evidence_id") is not None}
        recovered: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for obj in manifest.get("objects") or []:
            zip_path = obj.get("zip_path") or ""
            object_class = obj.get("object_class") or "evidence"
            original_id = int(obj.get("id") or 0)
            if not zip_path or zip_path not in names:
                errors.append({"object": obj, "error": "encrypted object file missing from ZIP"})
                continue
            try:
                sealed = z.read(zip_path)
                if obj.get("decrypt_with") == "escrow_hard_sealed_object_key" or obj.get("hard_sealed_escrow_evidence") or obj.get("hard_sealed_civilian_evidence") or obj.get("hard_sealed_organization_media") or parse_hard_sealed_container(sealed):
                    plaintext = escrow_hard_unseal_bytes(private_key, sealed)
                else:
                    plaintext = package_fernet.decrypt(sealed)
                expected = obj.get("logical_sha256") or obj.get("sha256") or ""
                actual = sha256_bytes(plaintext)
                hash_ok = (actual == expected) if expected else True
                source_record = evidence_records.get(original_id) if object_class == "evidence" else derived_records.get(original_id, {})
                asset_record = asset_by_resource.get(original_id, {}) if object_class == "evidence" else {}
                page_record = page_by_evidence.get(original_id, {}) if object_class == "evidence" else {}
                filename = clean_filename(obj.get("filename") or (source_record or {}).get("filename") or f"object_{original_id}.bin")
                mime_type = obj.get("mime_type") or (source_record or {}).get("mime_type") or mimetypes.guess_type(filename)[0] or "application/octet-stream"
                display_kind = reviewer_kind_for(mime_type, filename, source_record, object_class)
                prefix = f"{object_class}_{original_id:06d}_"
                rel_file = objects_dir / f"{prefix}{filename}"
                # Avoid overwriting if duplicate safe filenames exist.
                if rel_file.exists():
                    rel_file = objects_dir / f"{prefix}{uuid.uuid4().hex[:8]}_{filename}"
                rel_file.write_bytes(plaintext)
                try:
                    stored_plaintext_path = relative(rel_file)
                except Exception:
                    stored_plaintext_path = str(rel_file)
                source_meta = jloads((source_record or {}).get("meta_json"), {}) if isinstance((source_record or {}).get("meta_json"), str) else ((source_record or {}).get("meta_json") or {})
                page_capture_url = page_record.get("page_url") or source_meta.get("page_url") or source_meta.get("current_url") or source_meta.get("final_url") or source_meta.get("requested_url") or ""
                media_original_url = asset_record.get("original_url") or source_meta.get("media_url") or (source_record or {}).get("source_ref") or ""
                source_ref_value = (source_record or {}).get("source_ref") or page_capture_url or media_original_url or ""
                root_original_value = asset_record.get("root_evidence_id") or (source_record or {}).get("parent_evidence_id")
                meta = {
                    "manifest_object": obj,
                    "source_record": source_record or {},
                    "source_record_meta": source_meta or {},
                    "page_capture": page_record or {},
                    "captured_asset": asset_record or {},
                    "zip_path": zip_path,
                    "hash_ok": hash_ok,
                }
                recovered.append({
                    "object_class": object_class,
                    "original_id": original_id,
                    "filename": filename,
                    "mime_type": mime_type,
                    "kind": display_kind,
                    "sha256": actual,
                    "size": len(plaintext),
                    "plaintext_path": stored_plaintext_path,
                    "zip_path": zip_path,
                    "source_ref": source_ref_value,
                    "page_url": page_capture_url or source_ref_value,
                    "original_url": media_original_url,
                    "root_original_id": root_original_value,
                    "resource_original_id": asset_record.get("resource_evidence_id") or original_id,
                    "logical_sha256_expected": expected,
                    "hash_ok": hash_ok,
                    "meta_json": meta,
                })
            except Exception as exc:
                errors.append({"object": obj, "zip_path": zip_path, "error": str(exc)})
        (out_dir / "manifest.json").write_text(pretty(manifest), encoding="utf-8")
        (out_dir / "all_case_records.json").write_text(pretty(all_records), encoding="utf-8")
        (out_dir / "report.json").write_text(pretty(report), encoding="utf-8")
        if errors:
            (out_dir / "import_errors.json").write_text(pretty(errors), encoding="utf-8")
        return {
            "manifest": manifest,
            "all_records": all_records,
            "report": report,
            "objects": recovered,
            "errors": errors,
            "vault_storage_key_sha256": sha256_bytes(vault_key),
            "wrapped_storage_key_sha256": sha256_text(wrapped_storage_key),
        }


def reviewer_import_package(package_bytes: bytes, package_name: str, private_key_pem: str | bytes, passphrase: str, actor: str, note: str = "") -> int:
    inspect = sealed_zip_inspect_bytes(package_bytes)
    manifest_case = {}
    manifest = {}
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as z:
            if "manifest.json" in z.namelist():
                manifest = json.loads(z.read("manifest.json").decode("utf-8", errors="replace"))
                manifest_case = manifest.get("case") or {}
    except Exception:
        pass
    vault_folder = REVIEW_DIR / f"import_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:10]}"
    vault_folder.mkdir(parents=True, exist_ok=True)
    import_id = execute("""INSERT INTO reviewer_imports(package_name,package_sha256,package_size,status,imported_by,created_at,escrow_public_key_fingerprint,wrapped_storage_key_sha256,object_count,recovered_count,case_name,case_id_original,vault_path,manifest_json,notes_json)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (clean_filename(package_name or "sealed_evidence.zip"), sha256_bytes(package_bytes), len(package_bytes), "importing", actor, utcnow(), inspect.get("escrow_public_key_fingerprint") or "", "", int(inspect.get("object_count") or 0), 0, manifest_case.get("name") or inspect.get("case_name") or "", manifest.get("case_id") or manifest_case.get("id"), relative(vault_folder), pretty(manifest or inspect), pretty({"note": note})))
    try:
        result = decrypt_sealed_package_to_vault(package_bytes, private_key_pem, passphrase, vault_folder)
        for rec in result["objects"]:
            execute("""INSERT INTO reviewer_objects(import_id,object_class,original_id,filename,mime_type,kind,sha256,size,plaintext_path,zip_path,source_ref,page_url,original_url,root_original_id,resource_original_id,logical_sha256_expected,hash_ok,meta_json,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (import_id, rec["object_class"], rec["original_id"], rec["filename"], rec["mime_type"], rec["kind"], rec["sha256"], rec["size"], rec["plaintext_path"], rec["zip_path"], rec.get("source_ref") or "", rec.get("page_url") or "", rec.get("original_url") or "", rec.get("root_original_id"), rec.get("resource_original_id"), rec.get("logical_sha256_expected") or "", 1 if rec.get("hash_ok") else 0, pretty(rec.get("meta_json") or {}), utcnow()))
        notes = {"note": note, "errors": result.get("errors") or [], "vault_storage_key_sha256": result.get("vault_storage_key_sha256")}
        execute("UPDATE reviewer_imports SET status=?, wrapped_storage_key_sha256=?, recovered_count=?, manifest_json=?, notes_json=? WHERE id=?", ("imported" if not result.get("errors") else "imported_with_errors", result.get("wrapped_storage_key_sha256") or "", len(result["objects"]), pretty(result.get("manifest") or {}), pretty(notes), import_id))
        log_event(actor, "REVIEWER_SEALED_PACKAGE_IMPORTED", details={"reviewer_import_id": import_id, "package_sha256": sha256_bytes(package_bytes), "object_count": int(inspect.get("object_count") or 0), "recovered_count": len(result["objects"]), "errors": len(result.get("errors") or [])})
        return import_id
    except Exception as exc:
        execute("UPDATE reviewer_imports SET status=?, notes_json=? WHERE id=?", ("error", pretty({"note": note, "error": str(exc), "traceback": traceback.format_exc(limit=8)}), import_id))
        log_event(actor, "REVIEWER_SEALED_PACKAGE_IMPORT_FAILED", details={"reviewer_import_id": import_id, "package_sha256": sha256_bytes(package_bytes), "error": str(exc)})
        raise



def reviewer_objects_filtered(import_id: int, kind_filter: str = "all", q: str = "", limit: int = 800, starred: bool = False, hashtag: str = "", exts: str = "") -> list[dict[str, Any]]:
    clauses = ["import_id=?"]
    params: list[Any] = [import_id]
    if starred:
        clauses.append("starred=1")
    tag = normalize_hashtags(hashtag).split()
    if tag:
        clauses.append("lower(hashtags) LIKE ?")
        params.append(f"%{tag[0].lower()}%")
    if q:
        like = f"%{q}%"
        clauses.append("(filename LIKE ? OR source_ref LIKE ? OR page_url LIKE ? OR original_url LIKE ? OR sha256 LIKE ? OR logical_sha256_expected LIKE ? OR mime_type LIKE ? OR kind LIKE ? OR meta_json LIKE ? OR hashtags LIKE ?)")
        params.extend([like, like, like, like, like, like, like, like, like, like])
    params.append(limit)
    rows = [dict(r) for r in fetchall(f"SELECT * FROM reviewer_objects WHERE {' AND '.join(clauses)} ORDER BY starred DESC, id LIMIT ?", tuple(params))]
    rows = [r for r in rows if reviewer_filter_matches(str(r.get("kind") or "other"), kind_filter)]
    ext_filters = extension_filter_list(exts)
    if ext_filters:
        rows = [r for r in rows if extension_matches(str(r.get("filename") or r.get("source_ref") or r.get("original_url") or ""), str(r.get("mime_type") or ""), ext_filters)]
    return rows

def reviewer_object_meta(obj: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any]:
    if not obj:
        return {}
    try:
        raw = obj["meta_json"]  # type: ignore[index]
    except Exception:
        raw = getattr(obj, "meta_json", "")
    meta = jloads(raw, {})
    return meta if isinstance(meta, dict) else {}


def reviewer_source_record(obj: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any]:
    meta = reviewer_object_meta(obj)
    rec = meta.get("source_record") if isinstance(meta, dict) else {}
    return rec if isinstance(rec, dict) else {}


def reviewer_page_capture_record(obj: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any]:
    meta = reviewer_object_meta(obj)
    rec = meta.get("page_capture") if isinstance(meta, dict) else {}
    return rec if isinstance(rec, dict) else {}


def reviewer_captured_asset_record(obj: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any]:
    meta = reviewer_object_meta(obj)
    rec = meta.get("captured_asset") if isinstance(meta, dict) else {}
    return rec if isinstance(rec, dict) else {}


def reviewer_nested_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    parsed = jloads(value, {})
    return parsed if isinstance(parsed, dict) else {}


def reviewer_import_all_records(import_id: int) -> dict[str, Any]:
    imp = reviewer_import_for(import_id)
    if not imp:
        return {}
    rel = imp.get("vault_path") or ""
    if rel:
        path = data_path(rel) / "all_case_records.json"
        try:
            resolved = path.resolve()
            review_root = REVIEW_DIR.resolve()
            try:
                inside = resolved.is_relative_to(review_root)
            except AttributeError:
                inside = str(resolved).startswith(str(review_root))
            if inside and path.exists() and path.is_file():
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    manifest = jloads(imp.get("manifest_json"), {})
    return manifest if isinstance(manifest, dict) else {}


def reviewer_page_context(obj: dict[str, Any]) -> dict[str, Any]:
    source = reviewer_source_record(obj)
    page_cap = reviewer_page_capture_record(obj)
    source_meta = reviewer_nested_json(source.get("meta_json"))
    page_meta = reviewer_nested_json(page_cap.get("meta_json"))
    page_url = str(
        page_cap.get("page_url")
        or obj.get("page_url")
        or source_meta.get("current_url")
        or source_meta.get("final_url")
        or source_meta.get("requested_url")
        or source_meta.get("page_url")
        or page_meta.get("current_url")
        or page_meta.get("final_url")
        or page_meta.get("requested_url")
        or source.get("source_ref")
        or obj.get("source_ref")
        or obj.get("original_url")
        or ""
    )
    session_id = str(page_cap.get("session_id") or source_meta.get("session_id") or page_meta.get("session_id") or "")
    title = str(
        page_cap.get("title")
        or source_meta.get("page_title")
        or source_meta.get("title")
        or page_meta.get("title")
        or obj.get("filename")
        or f"Recovered page #{obj.get('id')}"
    )
    return {
        "title": title,
        "page_url": page_url,
        "page_url_sha256": sha256_text(page_url or ""),
        "session_id": session_id,
        "capture_mode": page_cap.get("capture_mode") or source.get("storage_mode") or obj.get("kind") or "page",
        "raw_persisted": bool(page_cap.get("raw_persisted") or source.get("raw_persisted")),
        "created_at": page_cap.get("created_at") or source.get("created_at") or obj.get("created_at") or "",
        "source_record": source,
        "page_capture": page_cap,
        "source_meta": source_meta,
        "page_meta": page_meta,
    }


def reviewer_page_url_for(obj: dict[str, Any] | None) -> str:
    return reviewer_page_context(obj).get("page_url", "") if obj else ""


def reviewer_session_id_for(obj: dict[str, Any] | None) -> str:
    return reviewer_page_context(obj).get("session_id", "") if obj else ""


def reviewer_page_title_for(obj: dict[str, Any]) -> str:
    return reviewer_page_context(obj).get("title") or f"Recovered page #{obj.get('id')}"


def reviewer_page_objects(import_id: int, q: str = "", limit: int = 1000) -> list[dict[str, Any]]:
    clauses = ["import_id=?"]
    params: list[Any] = [import_id]
    if q:
        like = f"%{q}%"
        clauses.append("(filename LIKE ? OR source_ref LIKE ? OR page_url LIKE ? OR original_url LIKE ? OR sha256 LIKE ? OR mime_type LIKE ? OR kind LIKE ? OR meta_json LIKE ?)")
        params.extend([like, like, like, like, like, like, like, like])
    params.append(limit * 3)
    rows = [dict(r) for r in fetchall(f"SELECT * FROM reviewer_objects WHERE {' AND '.join(clauses)} ORDER BY id LIMIT ?", tuple(params))]
    records = reviewer_import_all_records(import_id)
    page_eids = {int(r.get("evidence_id")) for r in (records.get("page_captures") or []) if isinstance(r, dict) and r.get("evidence_id") is not None}
    pages: list[dict[str, Any]] = []
    for r in rows:
        src = reviewer_source_record(r)
        storage = str(src.get("storage_mode") or "").lower()
        source_type = str(src.get("source_type") or "").lower()
        mt = str(r.get("mime_type") or "").split(";", 1)[0].lower()
        is_page = (
            r.get("kind") == "page"
            or int(r.get("original_id") or 0) in page_eids
            or source_type in {"live_browser_capture", "url_capture"}
            or storage in {"live_browser_raw_html", "live_browser_sanitized_summary", "sanitized_summary", "metadata_only", "raw_root"}
            or mt in {"text/html", "application/xhtml+xml"}
        )
        if is_page:
            pages.append(r)
    def page_preference(row: dict[str, Any]) -> int:
        mt = str(row.get("mime_type") or "").split(";", 1)[0].lower()
        src = reviewer_source_record(row)
        storage = str(src.get("storage_mode") or "").lower()
        meta = reviewer_object_meta(row)
        if storage == SEALED_PRESERVED_PAGE_SNAPSHOT_STORAGE_MODE or meta.get("sealed_page_snapshot"):
            return 0
        if mt in {"text/html", "application/xhtml+xml"}:
            return 1
        return 2

    best_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in pages:
        ctx = reviewer_page_context(row)
        key = (str(ctx.get("session_id") or ""), str(ctx.get("page_url") or row.get("source_ref") or row.get("original_url") or row.get("id") or "").split("#", 1)[0])
        existing = best_by_key.get(key)
        if existing is None or page_preference(row) < page_preference(existing):
            best_by_key[key] = row
    pages = list(best_by_key.values())

    def sort_key(row: dict[str, Any]) -> tuple[str, int, int]:
        ctx = reviewer_page_context(row)
        return (str(ctx.get("created_at") or row.get("created_at") or ""), page_preference(row), int(row.get("id") or 0))
    pages.sort(key=sort_key)
    return pages[:limit]


def reviewer_page_media_refs(import_id: int, page_obj: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    try:
        data = read_reviewer_object(page_obj)
        mt = (page_obj.get("mime_type") or "").split(";", 1)[0].lower()
        if mt in {"text/html", "application/xhtml+xml"} or data[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
            source_url = reviewer_page_url_for(page_obj)
            html_text = data.decode("utf-8", errors="replace")
            for ref in extract_media_refs(source_url, html_text):
                url = str(ref.get("url") or "")
                if url and not url.startswith("data:"):
                    refs.update(url_aliases(url, source_url))
    except Exception:
        pass
    return refs


def reviewer_blocked_records_for_page(import_id: int, page_obj: dict[str, Any], limit: int = 600) -> list[dict[str, Any]]:
    records = reviewer_import_all_records(import_id)
    blocked = records.get("blocked_media") or []
    if not isinstance(blocked, list):
        return []
    original_id = int(page_obj.get("original_id") or 0)
    page_url = reviewer_page_url_for(page_obj)
    page_url_nohash = page_url.split("#", 1)[0] if page_url else ""
    session_id = reviewer_session_id_for(page_obj)
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for b in blocked:
        if not isinstance(b, dict):
            continue
        match = False
        try:
            if original_id and b.get("root_evidence_id") is not None and int(b.get("root_evidence_id") or 0) == original_id:
                match = True
        except Exception:
            pass
        b_page = str(b.get("page_url") or "")
        if page_url and b_page and (b_page == page_url or b_page.split("#", 1)[0] == page_url_nohash):
            match = True
        if session_id and str(b.get("session_id") or "") == session_id:
            match = True
        if match:
            key = b.get("id") or b.get("metadata_record_hash") or b.get("media_url")
            if key not in seen:
                seen.add(key)
                out.append(b)
        if len(out) >= limit:
            break
    return out


def reviewer_related_objects(import_id: int, page_obj: dict[str, Any], *, include_session_fallback: bool = True, include_non_media: bool = True, limit: int = 800) -> list[dict[str, Any]]:
    page_original_id = int(page_obj.get("original_id") or 0)
    page_url = reviewer_page_url_for(page_obj)
    page_url_nohash = page_url.split("#", 1)[0] if page_url else ""
    page_hash = sha256_text(page_url or "")
    session_id = reviewer_session_id_for(page_obj)
    ref_urls = reviewer_page_media_refs(import_id, page_obj)
    records = reviewer_import_all_records(import_id)
    blocked_by_materialized: dict[int, list[dict[str, Any]]] = {}
    for b in records.get("blocked_media") or []:
        if not isinstance(b, dict):
            continue
        mid = b.get("materialized_evidence_id")
        if mid is not None:
            try:
                blocked_by_materialized.setdefault(int(mid), []).append(b)
            except Exception:
                pass
    captured_by_resource: dict[int, dict[str, Any]] = {}
    for a in records.get("captured_assets") or []:
        if not isinstance(a, dict):
            continue
        rid = a.get("resource_evidence_id")
        if rid is not None:
            try:
                captured_by_resource[int(rid)] = a
            except Exception:
                pass
    rows = [dict(r) for r in fetchall("SELECT * FROM reviewer_objects WHERE import_id=? ORDER BY id", (import_id,))]
    scored: list[tuple[int, dict[str, Any]]] = []
    for r in rows:
        if int(r.get("id") or 0) == int(page_obj.get("id") or 0):
            continue
        kind = str(r.get("kind") or "other")
        mt = str(r.get("mime_type") or "").lower()
        if not include_non_media and kind not in {"image", "video", "audio"} and not mt.startswith(("image/", "video/", "audio/")):
            continue
        if include_non_media and kind == "page":
            continue
        score = 0
        reasons: list[str] = []
        original_id = int(r.get("original_id") or 0)
        src = reviewer_source_record(r)
        src_meta = reviewer_nested_json(src.get("meta_json"))
        captured_asset = reviewer_captured_asset_record(r)
        try:
            if page_original_id and r.get("root_original_id") is not None and int(r.get("root_original_id") or 0) == page_original_id:
                score = max(score, 100); reasons.append("captured asset linked to page evidence")
        except Exception:
            pass
        try:
            if page_original_id and src.get("parent_evidence_id") is not None and int(src.get("parent_evidence_id") or 0) == page_original_id:
                score = max(score, 95); reasons.append("child evidence of page")
        except Exception:
            pass
        cap = captured_by_resource.get(original_id)
        if cap:
            try:
                if page_original_id and int(cap.get("root_evidence_id") or 0) == page_original_id:
                    score = max(score, 100); reasons.append("captured_assets table link")
            except Exception:
                pass
        candidate_urls = {
            str(r.get("source_ref") or ""),
            str(r.get("original_url") or ""),
            str(src.get("source_ref") or ""),
            str(src_meta.get("media_url") or ""),
            str(src_meta.get("media_final_url") or ""),
            str(captured_asset.get("original_url") or ""),
        }
        candidate_aliases: set[str] = set()
        for u in candidate_urls:
            candidate_aliases.update(url_aliases(u))
        for u in (src_meta.get("url_aliases") or []):
            candidate_aliases.update(url_aliases(str(u or "")))
        for u in (captured_asset.get("url_aliases") or []):
            candidate_aliases.update(url_aliases(str(u or "")))
        if candidate_aliases & ref_urls:
            score = max(score, 92); reasons.append("referenced by recovered HTML")
        candidate_page_url = str(src_meta.get("page_url") or captured_asset.get("page_url") or r.get("page_url") or "")
        if page_url and candidate_page_url:
            if candidate_page_url == page_url or candidate_page_url.split("#", 1)[0] == page_url_nohash:
                score = max(score, 86); reasons.append("same captured page URL")
            elif src_meta.get("page_url_sha256") == page_hash:
                score = max(score, 86); reasons.append("same page URL hash")
        candidate_session = str(src_meta.get("session_id") or captured_asset.get("session_id") or "")
        if session_id and candidate_session and candidate_session == session_id:
            score = max(score, 48); reasons.append("same browser session")
        for b in blocked_by_materialized.get(original_id, []):
            try:
                if page_original_id and b.get("root_evidence_id") is not None and int(b.get("root_evidence_id") or 0) == page_original_id:
                    score = max(score, 100); reasons.append("blocked-media root link")
            except Exception:
                pass
            b_page = str(b.get("page_url") or "")
            if page_url and b_page and (b_page == page_url or b_page.split("#", 1)[0] == page_url_nohash):
                score = max(score, 90); reasons.append("blocked-media page URL")
            if session_id and str(b.get("session_id") or "") == session_id:
                score = max(score, 50); reasons.append("blocked-media same session")
        if score:
            row = dict(r)
            row["_reviewer_related_score"] = score
            row["_reviewer_match_reason"] = ", ".join(dict.fromkeys(reasons))
            scored.append((score, row))
    has_strong = any(score >= 80 for score, _ in scored)
    threshold = 80 if has_strong else (45 if include_session_fallback else 80)
    filtered = [r for score, r in scored if score >= threshold]
    filtered.sort(key=lambda row: (-int(row.get("_reviewer_related_score") or 0), str(row.get("kind") or ""), str(row.get("filename") or "")))
    return filtered[:limit]


def reviewer_object_is_decorative_for_inline_star(obj: dict[str, Any] | None) -> bool:
    """Avoid placing inline star buttons on avatars, awards, icons, favicons, and emoji."""
    if not obj:
        return True
    blob = " ".join([
        str(obj.get("filename") or ""),
        str(obj.get("source_ref") or ""),
        str(obj.get("original_url") or ""),
        str(obj.get("page_url") or ""),
        str(obj.get("mime_type") or ""),
    ]).lower()
    urls = reviewer_object_urls(obj)
    if any(reviewer_url_is_reddit_primary_media(u) for u in urls):
        return False
    decorative_terms = [
        "snoovatar", "snoo_assets", "avatar", "profileicon", "profile_icon",
        "subreddit-icon", "award", "emoji", "flair", "favicon", "icon",
        "logo", "sprite", "badge", "rating", "tableflip"
    ]
    if any(t in blob for t in decorative_terms):
        return True
    try:
        size = int(obj.get("size") or 0)
        mt = str(obj.get("mime_type") or "").lower()
        if mt.startswith("image/") and size and size < 2048:
            return True
    except Exception:
        pass
    return False


def reviewer_star_control_html(import_id: int, obj: dict[str, Any], return_to: str = "") -> str:
    oid = int(obj.get("id") or 0)
    if not oid:
        return ""
    starred = bool(obj.get("starred"))
    ret = return_to or f"/reviewer/imports/{int(import_id)}/viewer?obj={oid}"
    return f"""<form method='post' target='_parent' action='/reviewer/imports/{int(import_id)}/objects/{oid}/star' class='blindsite-inline-star-form' style='display:inline-block;margin:4px 0 6px 0'>
      <input type='hidden' name='return_to' value='{h(ret)}'>
      <button type='submit' title='Star this recovered media object' style='border:1px solid #475569;border-radius:999px;background:{'#f59e0b' if starred else '#0f172a'};color:{'#111827' if starred else '#facc15'};font-weight:800;padding:4px 8px;cursor:pointer'>{'★ Starred' if starred else '☆ Star media'}</button>
    </form>"""


def reviewer_insert_inline_star_control(soup: BeautifulSoup, import_id: int, page_obj: dict[str, Any], media_tag, asset_row: dict[str, Any]) -> None:
    """Place one unobtrusive local star control on real recovered media.

    The control is intentionally skipped for Reddit avatars/awards/icons and is
    deduplicated by reviewer object ID so large captured pages do not get random
    repeated Star buttons in the wrong places.
    """
    try:
        if not asset_row or not asset_row.get("id"):
            return
        oid = int(asset_row["id"])
        if reviewer_object_is_decorative_for_inline_star(asset_row):
            return
        if soup.find("form", attrs={"data-blindsite-inline-star-object": str(oid)}):
            return
        target = media_tag
        if getattr(media_tag, "name", "") == "source" and getattr(media_tag, "parent", None) and media_tag.parent.name in {"video", "audio"}:
            target = media_tag.parent
        if getattr(target, "attrs", {}).get("data-blindsite-star-control-added"):
            return
        if getattr(target, "name", "") not in {"img", "video", "audio"}:
            return
        target["data-blindsite-reviewer-object-id"] = str(oid)
        target["data-blindsite-star-control-added"] = "1"
        return_to = f"/reviewer/imports/{int(import_id)}/pages?page={int(page_obj.get('id') or 0)}"
        starred = bool(asset_row.get("starred"))
        form = soup.new_tag("form", method="post", target="_parent", action=f"/reviewer/imports/{int(import_id)}/objects/{oid}/star")
        form["class"] = "blindsite-inline-star-form"
        form["data-blindsite-inline-star-object"] = str(oid)
        form["style"] = "position:absolute;top:6px;left:6px;z-index:2147483600;margin:0"
        hidden = soup.new_tag("input", type="hidden", name="return_to", value=return_to)
        form.append(hidden)
        btn = soup.new_tag("button", type="submit", title="Star this recovered media object")
        btn["style"] = "border:1px solid #475569;border-radius:999px;background:%s;color:%s;font-weight:800;padding:3px 7px;cursor:pointer;box-shadow:0 2px 8px #0008;font-size:12px" % ("#f59e0b" if starred else "#0f172a", "#111827" if starred else "#facc15")
        btn.string = "★" if starred else "☆"
        form.append(btn)
        wrapper = soup.new_tag("span" if target.name == "img" else "div")
        wrapper["class"] = "blindsite-star-media-wrap"
        wrapper["style"] = "position:relative;display:inline-block;max-width:100%;vertical-align:top"
        target.wrap(wrapper)
        wrapper.insert(0, form)
    except Exception:
        pass


def reviewer_media_card(import_id: int, obj: dict[str, Any]) -> str:
    raw = f"/reviewer/imports/{import_id}/objects/{int(obj['id'])}/raw"
    mt = (obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower()
    title = h(obj.get("filename") or f"object_{obj.get('id')}")
    source = h(obj.get("source_ref") or obj.get("original_url") or obj.get("page_url") or "")
    playback = reviewer_playback_kind(obj)
    if playback == "image":
        preview = f"<div class='thumb'><img src='{raw}' alt='{title}'></div>"
    elif playback == "video":
        preview = f"<div class='thumb'><video controls preload='metadata' src='{raw}'></video></div>"
    elif playback == "audio":
        preview = f"<div class='thumb'><audio controls preload='metadata' src='{raw}'></audio></div>"
    else:
        preview = f"<div class='thumb'><span class='muted'>{h(mt)}</span></div>"
    star_control = reviewer_star_control_html(import_id, obj, return_to=f"/reviewer/imports/{import_id}/viewer?obj={int(obj['id'])}")
    tags = hashtag_badges(normalize_hashtags(obj.get('hashtags') or ''))
    return f"<div class='card media-card'>{preview}<h3>{'★ ' if obj.get('starred') else ''}{title}</h3>{star_control}<p>{badge(obj.get('kind'),'info')} {badge(mt)} {tags} {badge('score '+str(obj.get('_reviewer_related_score','')),'info') if obj.get('_reviewer_related_score') else ''}</p><p class='small urlcell'>{source}</p><p><a class='button' href='{raw}?download=1'>Download</a> <a class='button secondary' href='/reviewer/imports/{import_id}/viewer?obj={int(obj['id'])}'>Object details</a></p></div>"


def reviewer_asset_map(import_id: int, page_obj: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = reviewer_related_objects(import_id, page_obj, include_session_fallback=True, include_non_media=True, limit=1200)
    original_page_id = int(page_obj.get("original_id") or 0)
    if original_page_id:
        for r in fetchall("SELECT * FROM reviewer_objects WHERE import_id=? AND root_original_id=? ORDER BY id", (import_id, original_page_id)):
            row = dict(r)
            if not any(int(x.get("id") or 0) == int(row.get("id") or 0) for x in rows):
                rows.append(row)
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        src = reviewer_source_record(r)
        src_meta = reviewer_nested_json(src.get("meta_json"))
        cap = reviewer_captured_asset_record(r)
        alias_set: set[str] = set()
        for url in [r.get("original_url"), r.get("source_ref"), src.get("source_ref"), src_meta.get("media_url"), src_meta.get("media_final_url"), cap.get("original_url")]:
            alias_set.update(url_aliases(str(url or "")))
        for url in (src_meta.get("url_aliases") or []):
            alias_set.update(url_aliases(str(url or "")))
        for url in (cap.get("url_aliases") or []):
            alias_set.update(url_aliases(str(url or "")))
        for alias in alias_set:
            out.setdefault(alias, r)
    return out


def reviewer_rewrite_css_urls(css_text: str, source_url: str, asset_map: dict[str, dict[str, Any]], asset_url_func, allow_remote: bool) -> str:
    def repl(match: re.Match) -> str:
        quote = match.group(1) or ""
        raw = (match.group(2) or "").strip()
        if raw.startswith(("data:", "blob:")):
            return f"url({quote}{raw}{quote})"
        absu = absolute_resource_url(source_url, raw)
        asset = asset_map.get(absu) or asset_map.get(absu.split("#", 1)[0])
        if asset:
            return f"url({quote}{asset_url_func(asset)}{quote})"
        if allow_remote and absu.startswith(("http://", "https://")):
            return f"url({quote}{absu}{quote})"
        return "url('')"
    return re.sub(r"url\(\s*(['\"]?)(.*?)(?:\1)\s*\)", repl, css_text or "")


def reviewer_absolute_remote_srcset(value: str, source_url: str) -> str:
    """Convert a srcset to absolute remote URLs for dynamic scripts mode.

    In reviewer scripts mode, some sites such as Reddit expect their original
    CDN/media URLs while their JavaScript player hydrates. Local asset rewriting
    is still used in safe/local modes, but scripts mode should not break player
    state by mixing local recovered media URLs with remote scripts/callbacks.
    """
    out: list[str] = []
    for item in (value or "").split(","):
        bits = item.strip().split()
        if not bits:
            continue
        raw = bits[0]
        if raw.startswith(("data:", "blob:")):
            bits[0] = raw
        else:
            absu = absolute_resource_url(source_url, raw)
            if not absu.startswith(("http://", "https://")):
                continue
            bits[0] = absu
        out.append(" ".join(bits))
    return ", ".join(out)


def reviewer_rewrite_srcset(value: str, source_url: str, asset_map: dict[str, dict[str, Any]], asset_url_func, allow_remote: bool) -> str:
    parts: list[str] = []
    for item in (value or "").split(','):
        item = item.strip()
        if not item:
            continue
        bits = item.split()
        raw = bits[0]
        absu = absolute_resource_url(source_url, raw)
        asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
        if asset:
            bits[0] = asset_url_func(asset)
            parts.append(' '.join(bits))
        elif allow_remote and absu.startswith(("http://", "https://")):
            bits[0] = absu
            parts.append(' '.join(bits))
    return ', '.join(parts)


def reviewer_csp_for_mode(mode: str) -> str:
    if mode == "auto":
        mode = "safe"
    if mode == "scripts":
        # Explicit cleared-reviewer dynamic mode. This is intentionally broad because
        # modern sites such as Reddit/YouTube often need workers, blobs, manifests,
        # websocket/API callbacks, iframes, and range-capable media URLs after their
        # JavaScript hydrates. Safe/local mode remains the default.
        return "default-src 'self' data: blob: http: https:; img-src 'self' data: blob: http: https:; media-src 'self' data: blob: http: https:; style-src 'self' 'unsafe-inline' http: https:; font-src 'self' data: http: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: http: https:; script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' data: blob: http: https:; script-src-attr 'self' 'unsafe-inline'; connect-src 'self' data: blob: http: https: ws: wss:; frame-src 'self' data: blob: http: https:; child-src 'self' data: blob: http: https:; worker-src 'self' data: blob: http: https:; manifest-src 'self' data: blob: http: https:; prefetch-src 'self' data: blob: http: https:; object-src 'none'; base-uri 'self' http: https:; form-action 'self' http: https:"
    if mode == "remote":
        return "default-src 'none'; img-src 'self' data: blob: http: https:; media-src 'self' data: blob: http: https:; style-src 'self' 'unsafe-inline' http: https:; font-src 'self' data: http: https:; script-src 'none'; connect-src http: https:; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
    return "default-src 'none'; img-src 'self' data: blob:; media-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"


def reviewer_proxy_url(import_id: int, remote_url: str, *, persist: bool = False, source_object_id: int | None = None, page_url: str = "") -> str:
    qs = {"url": str(remote_url or "")}
    if persist:
        qs["persist"] = "1"
    if source_object_id:
        qs["source_object_id"] = str(int(source_object_id))
    if page_url:
        qs["page_url"] = page_url
    return f"/reviewer/imports/{int(import_id)}/remote-proxy?{urlencode(qs)}"


def reviewer_should_proxy_script_url(url: str) -> bool:
    u = (url or "").lower()
    if not u.startswith(("http://", "https://")):
        return False
    path = urlparse(u).path
    if path.endswith((".js", ".mjs")):
        return True
    # Reddit's loader commonly uses concat endpoints without a .js suffix, and
    # module scripts from redditstatic fail CORS when executed from the local
    # BlindSite reviewer origin. Proxying only in explicit scripts mode keeps
    # safe/local mode locked down while restoring old dynamic Reddit playback.
    if "redditstatic.com/js/concat" in u or "redditstatic.com/shreddit/" in u:
        return True
    return False


def reviewer_find_asset_for_url(asset_map: dict[str, dict[str, Any]], source_url: str, raw_url: str) -> dict[str, Any] | None:
    if not raw_url:
        return None
    candidates = url_aliases(absolute_resource_url(source_url, str(raw_url)))
    candidates.update(url_aliases(str(raw_url)))
    for cand in candidates:
        if cand in asset_map:
            return asset_map[cand]
    return None


def reviewer_srcset_candidates(value: str, source_url: str) -> list[str]:
    out: list[str] = []
    for item in (value or "").split(','):
        bits = item.strip().split()
        if bits:
            out.append(absolute_resource_url(source_url, bits[0]))
    return out


def reviewer_inject_dynamic_origin_proxy(soup: BeautifulSoup, import_id: int, *, capture_remote_assets: bool = False, source_object_id: int | None = None, source_url: str = "") -> None:
    """Install a same-origin proxy shim for explicit reviewer scripts mode.

    This fixes Reddit/YouTube-style CORS/module-source problems in the cleared
    reviewer "remote callbacks + scripts" mode by rewriting remote module/script
    URLs through BlindSite's local reviewer proxy. When the reviewer explicitly
    enables remote media capture, the shim also asks BlindSite to save media URLs
    discovered by dynamic JavaScript as supplemental reviewer objects.
    """
    if soup.head is None:
        return
    endpoint = f"/reviewer/imports/{int(import_id)}/remote-proxy?url="
    capture_endpoint = f"/reviewer/imports/{int(import_id)}/remote-media-capture"
    script = soup.new_tag("script")
    script["data-blindsite-dynamic-origin-proxy"] = "1"
    script.string = f"""
(function(){{
  const endpoint = {json.dumps(endpoint)};
  const captureEndpoint = {json.dumps(capture_endpoint)};
  const captureRemoteAssets = {json.dumps(bool(capture_remote_assets))};
  const sourceObjectId = {int(source_object_id or 0)};
  const pageUrl = {json.dumps(source_url or '')};
  const seenCapture = new Set();
  function isHttp(u){{ return /^https?:[/][/]/i.test(String(u || '')); }}
  function shouldProxyScript(u){{
    try {{
      const s = String(u || '');
      if (!isHttp(s)) return false;
      const l = s.toLowerCase();
      return l.includes('redditstatic.com/js/concat') || l.includes('redditstatic.com/shreddit/') || /[.](m?js)([?#]|$)/i.test(l);
    }} catch(e) {{ return false; }}
  }}
  function shouldProxyNetwork(u){{
    try {{
      const s = String(u || '');
      if (!isHttp(s)) return false;
      const host = new URL(s).hostname.toLowerCase();
      const l = s.toLowerCase();
      if (shouldProxyScript(s)) return true;
      if (host.endsWith('reddit.com') || host.endsWith('redditstatic.com') || host.endsWith('redditmedia.com') || host.endsWith('redd.it')) return true;
      if (host.endsWith('youtube.com') || host.endsWith('youtube-nocookie.com') || host.endsWith('googlevideo.com') || host.endsWith('ytimg.com') || host.endsWith('youtubei.googleapis.com')) return true;
      if (/[.](m3u8|mpd|mp4|m4v|webm|mov|jpg|jpeg|png|gif|webp|avif|svg)([?#]|$)/i.test(l)) return true;
      return false;
    }} catch(e) {{ return false; }}
  }}
  function looksMedia(u){{
    try {{
      const s = String(u || '');
      if (!isHttp(s)) return false;
      const l = s.toLowerCase();
      return /[.](jpg|jpeg|png|gif|webp|avif|svg|ico|mp4|m4v|webm|mov|m3u8|mpd|mp3|wav|ogg|m4a)([?#]|$)/i.test(l) || l.includes('v.redd.it') || l.includes('i.redd.it') || l.includes('preview.redd.it') || l.includes('googlevideo.com/videoplayback') || l.includes('ytimg.com/');
    }} catch(e) {{ return false; }}
  }}
  function prox(u){{ return shouldProxyScript(u) ? endpoint + encodeURIComponent(String(u)) : u; }}
  function proxNetwork(u){{ return shouldProxyNetwork(u) ? endpoint + encodeURIComponent(String(u)) : u; }}
  function submitCapture(u, reason){{
    try {{
      if (!captureRemoteAssets || !looksMedia(u)) return;
      u = String(u || '').trim();
      if (!u || seenCapture.has(u)) return;
      seenCapture.add(u);
      const body = JSON.stringify({{url:u, page_object_id:sourceObjectId, page_url:pageUrl, reason:reason||'dynamic'}});
      if (navigator.sendBeacon) navigator.sendBeacon(captureEndpoint, new Blob([body], {{type:'application/json'}}));
      else fetch(captureEndpoint, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body}}).catch(()=>{{}});
    }} catch(e) {{}}
  }}
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value){{
    try {{
      const n = String(name || '').toLowerCase();
      const tag = String(this.tagName || '').toUpperCase();
      if (tag === 'SCRIPT' && n === 'src') value = prox(value);
      if (tag === 'LINK' && n === 'href') {{
        const rel = String(this.getAttribute('rel') || '').toLowerCase();
        const asv = String(this.getAttribute('as') || '').toLowerCase();
        if (rel.includes('modulepreload') || asv === 'script' || asv === 'worker') value = prox(value);
      }}
      if (captureRemoteAssets && ['IMG','VIDEO','AUDIO','SOURCE','TRACK'].includes(tag) && ['src','poster','href'].includes(n)) submitCapture(value, 'setAttribute:' + tag + ':' + n);
    }} catch(e) {{}}
    return origSetAttribute.call(this, name, value);
  }};
  try {{
    const desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {{ configurable:true, get:function(){{ return desc && desc.get ? desc.get.call(this) : this.getAttribute('src') || ''; }}, set:function(v){{ if (desc && desc.set) desc.set.call(this, prox(v)); else origSetAttribute.call(this, 'src', prox(v)); }} }});
  }} catch(e) {{}}
  try {{
    const origFetch = window.fetch;
    if (origFetch) window.fetch = function(input, init){{
      try {{
        const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        let originalUrl = (typeof input === 'string') ? input : (input && input.url ? input.url : '');
        if ((method === 'GET' || method === 'HEAD') && originalUrl) {{
          if (captureRemoteAssets) submitCapture(originalUrl, 'fetch');
          if (typeof input === 'string') input = proxNetwork(input); else if (input && input.url) input = proxNetwork(input.url);
        }}
      }} catch(e) {{}}
      return origFetch.call(this, input, init);
    }};
  }} catch(e) {{}}
  try {{
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url){{
      try {{
        const m = String(method || 'GET').toUpperCase();
        if ((m === 'GET' || m === 'HEAD') && typeof url === 'string') {{ if (captureRemoteAssets) submitCapture(url, 'xhr'); arguments[1] = proxNetwork(url); }}
      }} catch(e) {{}}
      return origOpen.apply(this, arguments);
    }};
  }} catch(e) {{}}
  try {{ const OrigWorker = window.Worker; if (OrigWorker) window.Worker = function(url, opts){{ return new OrigWorker(proxNetwork(url), opts); }}; }} catch(e) {{}}
  function rewriteExisting(){{
    try {{
      document.querySelectorAll('script[src]').forEach(s => {{ const v=s.getAttribute('src'); const p=prox(v); if (p!==v) s.setAttribute('src', p); }});
      document.querySelectorAll('link[href]').forEach(l => {{ const rel=String(l.getAttribute('rel')||'').toLowerCase(); const asv=String(l.getAttribute('as')||'').toLowerCase(); if (rel.includes('modulepreload') || asv==='script' || asv==='worker') {{ const v=l.getAttribute('href'); const p=prox(v); if (p!==v) l.setAttribute('href', p); }} }});
      if (captureRemoteAssets) {{
        document.querySelectorAll('img,video,audio,source,track').forEach(el => {{ ['currentSrc','src','poster','href'].forEach(k => {{ try {{ const v = el[k] || el.getAttribute(k); if (v) submitCapture(v, 'existing:' + k); }} catch(e) {{}} }}); }});
        document.querySelectorAll('shreddit-post[content-href]').forEach(p => {{ try {{ submitCapture(p.getAttribute('content-href'), 'shreddit-content-href'); }} catch(e) {{}} }});
        if (performance && performance.getEntriesByType) performance.getEntriesByType('resource').forEach(e => submitCapture(e.name, 'performance'));
      }}
    }} catch(e) {{}}
  }}
  rewriteExisting();
  [500,1500,3500,7000,12000].forEach(t => setTimeout(rewriteExisting, t));
  try {{ new MutationObserver(rewriteExisting).observe(document.documentElement, {{childList:true, subtree:true, attributes:true, attributeFilter:['src','href','rel','as','poster','srcset']}}); }} catch(e) {{}}
}})();
"""
    soup.head.insert(1 if soup.head.contents else 0, script)




def reviewer_url_is_reddit_primary_media(url: str) -> bool:
    """Return True for URLs likely to be the actual Reddit post media, not avatars/awards/icons."""
    try:
        u = str(url or "").strip()
        if not u or u.startswith(("data:", "blob:", "javascript:")):
            return False
        p = urlparse(u)
        host = p.netloc.lower()
        path = (p.path or "").lower()
        full = (host + path).lower()
        decorative_terms = [
            "snoovatar", "avatar", "profileicon", "profile_icon", "subreddit-icon", "award", "emoji",
            "icon", "sprite", "flair", "trophy", "badge", "logo",
        ]
        if any(term in full for term in decorative_terms):
            return False
        if host.endswith("v.redd.it"):
            return True
        if host.endswith("i.redd.it"):
            return True
        if host.endswith("preview.redd.it"):
            return True
        if path.endswith(tuple(IMAGE_EXTS + VIDEO_EXTS + AUDIO_EXTS)) and ("redd.it" in host or "redditmedia.com" in host):
            return True
    except Exception:
        pass
    return False


def reviewer_img_looks_like_post_media(img) -> bool:
    try:
        cls = " ".join(str(c).lower() for c in (img.get("class") or []))
        if any(x in cls for x in ["avatar", "icon", "subreddit", "award", "emoji", "flair"]):
            return False
        if any(x in cls for x in ["preview-img", "post-media", "media-lightbox", "non-lightboxed-content", "post-background-image-filter"]):
            return True
        for attr in ["data-blindsite-src", "src"]:
            v = str(img.get(attr) or "").strip()
            if reviewer_url_is_reddit_primary_media(v):
                return True
        for attr in ["srcset", "data-original-srcset"]:
            if any(reviewer_url_is_reddit_primary_media(u) for u in reviewer_srcset_candidates(str(img.get(attr) or ""), "https://www.reddit.com/")):
                return True
    except Exception:
        pass
    return False


def reviewer_shreddit_post_has_primary_media(post, post_type: str = "") -> bool:
    """Detect whether the captured Reddit/shreddit post already contains visible primary media.

    The static fallback cards are only useful when Reddit's custom elements fail
    to hydrate or the media was not represented in the DOM. If a post already has
    a normal primary image/video area, injecting a second large blue fallback card
    duplicates the post and makes review noisy.
    """
    post_type_l = (post_type or "").lower()
    try:
        if post_type_l in {"image", "gallery"}:
            if any(reviewer_img_looks_like_post_media(img) for img in post.find_all("img")):
                return True
        for vid in post.find_all("video"):
            if str(vid.get("src") or "").strip():
                return True
            if vid.find("source", src=True):
                return True
        # Reddit image posts can also expose media through a content-href attribute.
        if post_type_l in {"image", "gallery"} and reviewer_url_is_reddit_primary_media(str(post.get("content-href") or "")):
            return True
    except Exception:
        pass
    return False


def reviewer_best_audio_for_reddit_post(asset_map: dict[str, dict[str, Any]], source_url: str, candidates: list[str], chosen_asset: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Find a matching recovered Reddit audio object for video-only Reddit streams.

    Reddit frequently stores video and audio as separate CMAF/DASH objects. We do
    not mux streams in the reviewer, but exposing the matching audio object keeps
    reviewers from thinking audio was lost when it was actually preserved as a
    separate object.
    """
    cand_ids: set[str] = set()
    for u in candidates:
        rid = reddit_media_id_from_url(absolute_resource_url(source_url, str(u or "")))
        if rid:
            cand_ids.add(rid)
    if chosen_asset:
        for u in reviewer_object_urls(chosen_asset):
            rid = reddit_media_id_from_url(u)
            if rid:
                cand_ids.add(rid)
    best: tuple[int, dict[str, Any] | None] = (-10**9, None)
    seen: set[int] = set()
    for r in asset_map.values():
        try:
            rid_row = int(r.get("id") or 0)
        except Exception:
            rid_row = 0
        if rid_row and rid_row in seen:
            continue
        if rid_row:
            seen.add(rid_row)
        if reviewer_playback_kind(r) != "audio":
            continue
        urls = reviewer_object_urls(r)
        obj_ids = {reddit_media_id_from_url(u) for u in urls}
        score = 0
        if cand_ids and (cand_ids & obj_ids):
            score += 600
        fn = str(r.get("filename") or "").lower()
        size = int(r.get("size") or 0)
        if "cmaf_audio" in fn or "dash_audio" in fn or "audio" in fn:
            score += 180
        if size < 512:
            score -= 100
        score += min(size // 1000, 200)
        if score > best[0]:
            best = (score, r)
    return best[1] if best[0] > 0 else None


def reviewer_dedup_media_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate display-only media rows by hash/filename/size/source.

    The database may legitimately contain repeated Reddit byte-range/audio/media
    objects. For the embedded reviewer shelf, repeated cards are distracting, so
    this keeps the largest/newest representative without altering stored evidence.
    """
    by_key: dict[str, dict[str, Any]] = {}
    for r in rows:
        try:
            sha = str(r.get("sha256") or "").strip()
            fn = str(r.get("filename") or "").strip().lower()
            size = int(r.get("size") or 0)
            urls = sorted(reviewer_object_urls(r))
            key = sha or (fn + "|" + str(size) + "|" + (urls[0] if urls else ""))
            old = by_key.get(key)
            if not old or int(r.get("size") or 0) >= int(old.get("size") or 0):
                by_key[key] = r
        except Exception:
            by_key[str(id(r))] = r
    return list(by_key.values())

def reviewer_inject_shreddit_fallbacks(soup: BeautifulSoup, import_id: int, source_url: str, asset_map: dict[str, dict[str, Any]], asset_url_func, allow_remote: bool, capture_remote_assets: bool = False, source_object_id: int | None = None) -> int:
    """Build visible static fallbacks for Reddit custom elements.

    Reddit's <shreddit-post> markup contains the title, author, subreddit,
    content-href, permalink, score, comments, and often preview/original media
    URLs. If Reddit's web components do not hydrate in the local reviewer origin,
    this fallback still reconstructs the important page content from captured DOM
    and recovered local assets.
    """
    posts = list(soup.find_all("shreddit-post"))
    if not posts:
        return 0
    count = 0
    for post in posts:
        if post.find(attrs={"data-blindsite-shreddit-fallback": "1"}):
            continue
        title = str(post.get("post-title") or "").strip()
        author = str(post.get("author") or "").strip()
        subreddit = str(post.get("subreddit-prefixed-name") or post.get("subreddit-name") or "").strip()
        score = str(post.get("score") or "").strip()
        comments = str(post.get("comment-count") or "").strip()
        post_type = str(post.get("post-type") or "").strip().lower()
        permalink = absolute_resource_url(source_url, str(post.get("permalink") or ""))
        candidates: list[str] = []
        for attr in ["content-href", "url"]:
            v = str(post.get(attr) or "").strip()
            if v:
                candidates.append(absolute_resource_url(source_url, v))
        for img in post.find_all("img"):
            if not reviewer_img_looks_like_post_media(img):
                continue
            for attr in ["data-blindsite-src", "src"]:
                v = str(img.get(attr) or "").strip()
                if v and not v.startswith(("data:", "blob:")) and reviewer_url_is_reddit_primary_media(v):
                    candidates.append(absolute_resource_url(source_url, v))
            for attr in ["srcset", "data-original-srcset"]:
                candidates.extend([u for u in reviewer_srcset_candidates(str(img.get(attr) or ""), source_url) if reviewer_url_is_reddit_primary_media(u)])
        for media in post.find_all(["video", "source", "audio"]):
            for attr in ["data-blindsite-src", "src", "poster"]:
                v = str(media.get(attr) or "").strip()
                if v and not v.startswith(("data:", "blob:")):
                    candidates.append(absolute_resource_url(source_url, v))
        # Prefer main content URLs first, but keep previews as fallback.
        dedup: list[str] = []
        seen: set[str] = set()
        for u in candidates:
            if u and u not in seen:
                seen.add(u); dedup.append(u)
        chosen_url, chosen_asset = reviewer_best_media_for_reddit_post(import_id, source_url, asset_map, dedup, post_type=post_type)
        if not chosen_url and dedup:
            chosen_url = dedup[0]
        existing_primary_media = reviewer_shreddit_post_has_primary_media(post, post_type)
        playback_for_choice = reviewer_playback_kind(chosen_asset) if isinstance(chosen_asset, dict) else ("video" if post_type in {"video", "hosted:video", "rich:video"} and chosen_url else "image")
        chosen_size = int(chosen_asset.get("size") or 0) if isinstance(chosen_asset, dict) else 0
        # Avoid duplicate blue fallback cards when the native captured Reddit post
        # already renders its image/gallery/link preview. Keep fallbacks for video
        # only when we have a real recovered video object to rescue a broken player.
        if existing_primary_media and post_type not in {"video", "hosted:video", "rich:video"}:
            continue
        if post_type in {"link", "text", "self"} and not (chosen_asset and playback_for_choice in {"image", "video"} and reviewer_url_is_reddit_primary_media(chosen_url)):
            continue
        if post_type in {"video", "hosted:video", "rich:video"} and (not chosen_asset or playback_for_choice != "video" or chosen_size < 4096):
            continue
        card = soup.new_tag("div")
        card["data-blindsite-shreddit-fallback"] = "1"
        card["class"] = "blindsite-shreddit-fallback blindsite-shreddit-media-rescue"
        card["style"] = "display:block!important;position:relative!important;z-index:2147483000!important;margin:6px 0 10px 0;padding:0;border:0;background:transparent;color:inherit;font-family:inherit;clear:both"
        meta = soup.new_tag("div")
        meta["style"] = "font-size:11px;color:#64748b;margin:2px 0 4px 0;word-break:break-word"
        meta.string = " • ".join([x for x in [subreddit, f"u/{author}" if author else "", f"score {score}" if score else "", f"comments {comments}" if comments else "", post_type] if x]) or "Reddit post"
        card.append(meta)
        if title:
            t = soup.new_tag("div")
            t["style"] = "font-weight:700;font-size:14px;margin:4px 0 6px 0;line-height:1.25;color:inherit"
            t.string = title
            card.append(t)
        matching_audio_asset = reviewer_best_audio_for_reddit_post(asset_map, source_url, dedup, chosen_asset) if post_type in {"video", "hosted:video", "rich:video"} else None
        media_src = asset_url_func(chosen_asset) if chosen_asset else (reviewer_proxy_url(import_id, chosen_url, persist=capture_remote_assets, source_object_id=source_object_id, page_url=source_url) if allow_remote and chosen_url.startswith(("http://", "https://")) else "")
        mt = (chosen_asset.get("mime_type") if chosen_asset else "") if isinstance(chosen_asset, dict) else ""
        mt = str(mt or "").lower()
        if media_src:
            playback = reviewer_playback_kind(chosen_asset) if isinstance(chosen_asset, dict) else ("video" if post_type in {"video", "hosted:video", "rich:video"} or urlparse(media_src).path.lower().endswith(tuple(VIDEO_EXTS)) else "image")
            if playback == "video":
                el = soup.new_tag("video", src=media_src, controls="controls", preload="metadata")
                el["style"] = "max-width:100%;max-height:520px;background:#000;display:block;margin-top:8px"
            elif playback == "audio":
                el = soup.new_tag("audio", src=media_src, controls="controls", preload="metadata")
                el["style"] = "width:100%;display:block;margin-top:8px"
            else:
                el = soup.new_tag("img", src=media_src, alt=title or "Reddit recovered media")
                el["style"] = "max-width:100%;max-height:520px;object-fit:contain;background:#111827;display:block;margin-top:8px"
            if chosen_url:
                el["data-original-src"] = chosen_url
            card.append(el)
            if playback == "video" and isinstance(matching_audio_asset, dict):
                audio_src = asset_url_func(matching_audio_asset)
                note = soup.new_tag("div")
                note["style"] = "font-size:11px;color:#94a3b8;margin-top:4px"
                note.string = "Separate recovered Reddit audio track:"
                card.append(note)
                aud = soup.new_tag("audio", src=audio_src, controls="controls", preload="metadata")
                aud["style"] = "width:100%;max-width:520px;display:block;margin:4px 0 0 0"
                card.append(aud)
        elif chosen_url:
            miss = soup.new_tag("div")
            miss["style"] = "font-size:12px;color:#fbbf24;word-break:break-all"
            miss.string = f"Media URL captured but no recovered local object matched: {chosen_url}"
            card.append(miss)
        if permalink and permalink.startswith(("http://", "https://")):
            a = soup.new_tag("a", href=permalink)
            a["style"] = "display:inline-block;margin-top:8px;color:#7dd3fc"
            a.string = "Original permalink"
            card.append(a)
        post.insert(0, card)
        count += 1
    return count


def reviewer_render_html(import_id: int, obj: dict[str, Any], mode: str = "auto", capture_remote_assets: bool = False) -> str:
    mode = mode if mode in {"auto", "safe", "remote", "scripts"} else "auto"
    if mode == "auto":
        mode = "safe"
    allow_remote = mode in {"remote", "scripts"}
    allow_scripts = mode == "scripts"
    raw_html = read_reviewer_object(obj).decode("utf-8", errors="replace")
    source_url = reviewer_page_url_for(obj) or obj.get("source_ref") or obj.get("original_url") or ""
    asset_map = reviewer_asset_map(import_id, obj)

    def asset_url(asset_row: dict[str, Any]) -> str:
        return f"/reviewer/imports/{import_id}/objects/{int(asset_row['id'])}/raw"

    soup = BeautifulSoup(raw_html, "html.parser")
    strip_blindsite_live_media_blockers(soup)
    if not allow_scripts:
        for tag in soup.find_all(["script", "iframe", "object", "embed"]):
            placeholder = soup.new_tag("div")
            placeholder["data-reviewer-removed"] = tag.name
            placeholder.string = f"[Reviewer safe view removed {tag.name}]"
            tag.replace_with(placeholder)
    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv") or "").lower() in {"refresh", "content-security-policy"}:
            meta.decompose()
    for el in soup.find_all(True):
        if not allow_scripts:
            for attr in list(el.attrs):
                if attr.lower().startswith("on"):
                    del el.attrs[attr]
            if el.name == "a" and el.has_attr("href"):
                original = absolute_resource_url(source_url, str(el.get("href") or ""))
                el["data-original-href"] = original
                el["href"] = "#"
                el["title"] = f"Original link preserved but disabled: {original}"
            if el.name == "form":
                el["data-original-action"] = str(el.get("action") or "")
                el["action"] = "#"
                el["method"] = "get"
    dynamic_scripts_mode = allow_scripts and allow_remote
    dynamic_media_tags = {"img", "video", "audio", "source", "track"}
    for tag in soup.find_all(["img", "video", "audio", "source", "track"]):
        for attr in ["src", "poster"]:
            if tag.has_attr(attr):
                raw = str(tag.get(attr) or "")
                if raw.startswith(("data:", "blob:")):
                    continue
                absu = absolute_resource_url(source_url, raw)
                asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
                # Local recovered media should win in all modes, including scripts
                # mode. Keep the original remote URL as metadata so Reddit/YouTube
                # player scripts and diagnostics can still see what was captured.
                if asset:
                    tag[attr] = asset_url(asset)
                    tag[f"data-original-{attr}"] = absu
                    reviewer_insert_inline_star_control(soup, import_id, obj, tag, asset)
                    if dynamic_scripts_mode and absu.startswith(("http://", "https://")):
                        tag[f"data-remote-{attr}"] = absu
                    if tag.name in {"video", "audio"}:
                        tag["controls"] = "controls"
                elif allow_remote and absu.startswith(("http://", "https://")):
                    tag[attr] = absu
                    tag[f"data-remote-{attr}"] = "allowed"
                    if tag.name in {"video", "audio"}:
                        tag["controls"] = "controls"
                else:
                    tag[f"data-missing-{attr}"] = absu
                    tag[attr] = ""
        if tag.has_attr("srcset"):
            original = str(tag.get("srcset") or "")
            if dynamic_scripts_mode:
                local_rewritten = reviewer_rewrite_srcset(original, source_url, asset_map, asset_url, False)
                remote_rewritten = reviewer_absolute_remote_srcset(original, source_url)
                tag["data-original-srcset"] = original
                if local_rewritten:
                    tag["srcset"] = local_rewritten
                    if remote_rewritten:
                        tag["data-remote-srcset"] = remote_rewritten
                elif remote_rewritten:
                    tag["srcset"] = remote_rewritten
                    tag["data-remote-srcset"] = "allowed"
                else:
                    del tag.attrs["srcset"]
                continue
            rewritten = reviewer_rewrite_srcset(original, source_url, asset_map, asset_url, allow_remote)
            tag["data-original-srcset"] = original
            if rewritten:
                tag["srcset"] = rewritten
            else:
                del tag.attrs["srcset"]
    for link in list(soup.find_all("link")):
        rel_val = link.get("rel")
        rel = " ".join(rel_val).lower() if isinstance(rel_val, list) else str(rel_val or "").lower()
        href = str(link.get("href") or "")
        as_attr = str(link.get("as") or "").lower()
        if href and dynamic_scripts_mode and ("modulepreload" in rel or as_attr in {"script", "worker"}):
            absu = absolute_resource_url(source_url, href)
            if reviewer_should_proxy_script_url(absu):
                link["href"] = reviewer_proxy_url(import_id, absu)
                link["data-original-href"] = absu
                link["data-blindsite-proxied"] = "1"
            elif absu.startswith(("http://", "https://")):
                link["href"] = absu
                link["data-remote-href"] = "allowed"
        elif href and ("stylesheet" in rel or as_attr in {"style", "font"}):
            absu = absolute_resource_url(source_url, href)
            asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
            if asset:
                link["href"] = asset_url(asset)
                link["data-original-href"] = absu
            elif allow_remote and absu.startswith(("http://", "https://")):
                link["href"] = absu
                link["data-remote-href"] = "allowed"
            else:
                link.decompose()
        elif not allow_scripts:
            link.decompose()
    if allow_scripts:
        for script in soup.find_all("script"):
            if script.has_attr("src"):
                raw = str(script.get("src") or "")
                absu = absolute_resource_url(source_url, raw)
                asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
                if dynamic_scripts_mode and reviewer_should_proxy_script_url(absu):
                    script["src"] = reviewer_proxy_url(import_id, absu)
                    script["data-original-src"] = absu
                    script["data-blindsite-proxied"] = "1"
                elif asset:
                    script["src"] = asset_url(asset)
                    script["data-original-src"] = absu
                elif allow_remote and absu.startswith(("http://", "https://")):
                    script["src"] = absu
                    script["data-remote-src"] = "allowed"
    for el in soup.find_all(style=True):
        el["style"] = reviewer_rewrite_css_urls(str(el.get("style") or ""), source_url, asset_map, asset_url, allow_remote)
    for style in soup.find_all("style"):
        style.string = reviewer_rewrite_css_urls(style.string or "", source_url, asset_map, asset_url, allow_remote)
    if soup.html is None:
        html_tag = soup.new_tag("html")
        existing = list(soup.contents)
        for child in existing:
            html_tag.append(child.extract())
        soup.append(html_tag)
    if soup.head is None:
        head = soup.new_tag("head")
        soup.html.insert(0, head)
    if soup.body is None:
        body = soup.new_tag("body")
        soup.html.append(body)
    csp = soup.new_tag("meta")
    csp["http-equiv"] = "Content-Security-Policy"
    csp["content"] = reviewer_csp_for_mode(mode)
    soup.head.insert(0, csp)
    if dynamic_scripts_mode:
        reviewer_inject_dynamic_origin_proxy(soup, import_id, capture_remote_assets=capture_remote_assets, source_object_id=int(obj.get("id") or 0), source_url=source_url)
    fallback_count = reviewer_inject_shreddit_fallbacks(soup, import_id, source_url, asset_map, asset_url, allow_remote, capture_remote_assets=capture_remote_assets, source_object_id=int(obj.get("id") or 0))
    style_tag = soup.new_tag("style")
    style_tag.string = "[data-reviewer-removed]{display:block;padding:8px;margin:4px;border:1px dashed #64748b;background:#111827;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif}.reviewer-banner{position:sticky;top:0;z-index:2147483647;background:#111827;color:#e5e7eb;border-bottom:2px solid #38bdf8;padding:8px 12px;font:14px Segoe UI,Arial,sans-serif}.blindsite-shreddit-fallback,.blindsite-recovered-media-shelf{position:relative!important;z-index:2147483000!important}.blindsite-shreddit-media-rescue{background:transparent!important;border:0!important;color:inherit!important}.blindsite-hidden-blank-overlay{display:none!important}faceplate-progress{display:none!important}faceplate-loader:empty,faceplate-partial:empty{display:none!important}img,video{max-width:100%;height:auto}"
    soup.head.append(style_tag)
    if allow_scripts:
        guard = soup.new_tag("script")
        guard["data-blindsite-reviewer-guard"] = "1"
        guard.string = r"""
(function(){
  // Dynamic reviewer safety net: some modern sites render correctly, then their
  // client JS clears/replaces the DOM when cookies/API state are missing. Keep
  // the best recovered DOM seen early in the page lifecycle and restore it if
  // the page becomes visually blank. This only runs in explicit remote+scripts
  // reviewer mode; safe/local mode remains static and no-callback.
  let best = null;
  let bestScore = 0;
  let restoreCount = 0;
  function score(){
    if (!document.body) return {score:0, html:'', textLen:0, media:0, anchors:0, nodes:0};
    const html = document.body.innerHTML || '';
    const text = (document.body.innerText || '').trim();
    const media = document.querySelectorAll('img,video,source,picture,iframe,canvas,svg').length;
    const anchors = document.querySelectorAll('a[href]').length;
    const nodes = document.querySelectorAll('body *').length;
    // Media-heavy pages such as Reddit/YouTube may have modest text but lots of
    // meaningful media/player nodes. Score all of it, not just text length.
    return {
      score: Math.min(html.length, 120000) + text.length * 20 + media * 700 + anchors * 80 + nodes * 20,
      html, textLen: text.length, media, anchors, nodes
    };
  }
  function take(){
    const s = score();
    if (s.html.length > 400 && s.score > bestScore && (s.textLen > 10 || s.media > 0 || s.anchors > 3)) {
      best = s; bestScore = s.score;
    }
  }
  function restore(reason){
    if (!best || !document.body) return;
    restoreCount++;
    document.body.innerHTML = best.html;
    const note = document.createElement('div');
    note.className = 'reviewer-banner';
    note.textContent = 'BlindSite restored the recovered DOM after site JavaScript blanked/replaced the page (' + reason + '). Remote scripts/callbacks remain enabled in this view.';
    document.body.insertBefore(note, document.body.firstChild);
    // Remove script tags after restore so a failed hydrator does not immediately
    // blank the recovered DOM again. Already-running timers may still exist, so
    // the interval below can restore more than once if needed.
    try { document.querySelectorAll('script').forEach(s => s.remove()); } catch(e) {}
  }
  function hideBlankOverlays(){
    try {
      const vw = Math.max(1, window.innerWidth || document.documentElement.clientWidth || 1);
      const vh = Math.max(1, window.innerHeight || document.documentElement.clientHeight || 1);
      document.querySelectorAll('body *').forEach(el => {
        try {
          if (el.classList && (el.classList.contains('reviewer-banner') || el.classList.contains('blindsite-shreddit-fallback') || el.classList.contains('blindsite-recovered-media-shelf'))) return;
          const st = getComputedStyle(el);
          const pos = st.position;
          if (!['fixed','absolute','sticky'].includes(pos)) return;
          const r = el.getBoundingClientRect();
          if (r.width < vw * 0.55 || r.height < vh * 0.28) return;
          const text = (el.innerText || '').trim();
          const media = el.querySelectorAll('img,video,canvas,svg,iframe').length;
          const bg = st.backgroundColor || '';
          const zi = parseInt(st.zIndex || '0', 10) || 0;
          const whiteish = bg.includes('255, 255, 255') || bg.includes('250, 250, 250') || bg === 'white' || bg === 'rgb(255, 255, 255)';
          if (text.length < 20 && media === 0 && (whiteish || zi > 1000)) {
            el.classList.add('blindsite-hidden-blank-overlay');
            el.setAttribute('data-blindsite-hidden-blank-overlay', '1');
          }
        } catch(e) {}
      });
    } catch(e) {}
  }

  function check(){
    if (!best || !document.body) return;
    const cur = score();
    const tinyHtml = cur.html.length < Math.max(250, best.html.length * 0.18);
    const tinyScore = cur.score < Math.max(800, bestScore * 0.22);
    const lostMedia = best.media >= 2 && cur.media < Math.max(1, best.media * 0.25);
    const lostText = best.textLen >= 120 && cur.textLen < best.textLen * 0.18;
    const visuallyBlank = (cur.textLen < 20 && cur.media === 0 && cur.anchors < 2 && cur.nodes < 30);
    if (tinyHtml || tinyScore || lostMedia || lostText || visuallyBlank) {
      restore(tinyHtml ? 'html-shrank' : tinyScore ? 'score-dropped' : lostMedia ? 'media-disappeared' : lostText ? 'text-disappeared' : 'blank-body');
    } else {
      take();
    }
  }
  window.addEventListener('DOMContentLoaded', function(){ [100,300,700,1200,2200,4000].forEach(t => setTimeout(take, t)); });
  [100,300,700,1200,2200,4000,7000,10000].forEach(t => setTimeout(take, t));
  let n = 0; const id = setInterval(function(){ hideBlankOverlays(); check(); if (++n > 90) clearInterval(id); }, 700);
  [300,1000,2500,5000,9000].forEach(t => setTimeout(hideBlankOverlays, t));
})();
"""
        soup.head.append(guard)
    banner = soup.new_tag("div")
    banner["class"] = "reviewer-banner"
    if mode == "scripts":
        banner.string = f"Cleared reviewer SCRIPT view — dynamic remote media/scripts allowed via same-origin proxy where needed; recovered local assets and Reddit fallbacks available ({fallback_count}); supplemental remote media capture {'ON' if capture_remote_assets else 'OFF'} — source: {source_url}"
    elif mode == "remote":
        banner.string = f"Cleared reviewer REMOTE-CALLBACK view — scripts disabled; local recovered assets used first; missing remote media/style may load — source: {source_url}"
    else:
        banner.string = f"Cleared reviewer SAFE local page view — scripts and remote callbacks disabled; local recovered assets only — source: {source_url}"
    soup.body.insert(0, banner)
    # Make the renderer self-auditing for complex pages: if a dynamic player fails
    # to place every recovered media object back into the DOM, reviewers still get
    # a local recovered-media shelf inside the rendered page. This does not fetch
    # anything remote; it uses reviewer recovered objects already imported.
    try:
        related_media = reviewer_dedup_media_rows(reviewer_related_objects(import_id, obj, include_session_fallback=True, include_non_media=False, limit=600))
        if related_media:
            shelf = soup.new_tag("details")
            shelf["class"] = "blindsite-recovered-media-shelf"
            shelf["style"] = "margin:16px;padding:10px;border:1px solid #334155;background:#0f172a;color:#e5e7eb;font:14px Segoe UI,Arial,sans-serif;clear:both"
            summary = soup.new_tag("summary")
            summary.string = f"BlindSite recovered media shelf ({len(related_media)} unique objects)"
            shelf.append(summary)
            p = soup.new_tag("p")
            p.string = "Collapsed by default to avoid duplicating the main recovered page. Open this shelf if a site player did not place a recovered object back into the page."
            shelf.append(p)
            grid = soup.new_tag("div")
            grid["style"] = "display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px"
            for media_obj in related_media[:250]:
                mt = (media_obj.get("mime_type") or "application/octet-stream").split(";",1)[0].lower()
                raw = f"/reviewer/imports/{import_id}/objects/{int(media_obj['id'])}/raw"
                card = soup.new_tag("div")
                card["style"] = "border:1px solid #334155;background:#020617;border-radius:10px;padding:8px;overflow:hidden"
                title_el = soup.new_tag("div")
                title_el["style"] = "font-size:12px;color:#cbd5e1;word-break:break-all;margin-bottom:6px"
                title_el.string = str(media_obj.get("filename") or f"object_{media_obj.get('id')}")
                card.append(title_el)
                playback = reviewer_playback_kind(media_obj)
                if playback == "image":
                    el = soup.new_tag("img", src=raw)
                    el["style"] = "max-width:100%;max-height:220px;object-fit:contain;background:#111827"
                    card.append(el)
                elif playback == "video" or mt in {"application/vnd.apple.mpegurl", "application/x-mpegurl", "application/dash+xml", "application/mp4"}:
                    el = soup.new_tag("video", src=raw, controls="controls", preload="metadata")
                    el["style"] = "max-width:100%;max-height:260px;background:#000"
                    card.append(el)
                elif playback == "audio":
                    el = soup.new_tag("audio", src=raw, controls="controls", preload="metadata")
                    el["style"] = "width:100%"
                    card.append(el)
                else:
                    a = soup.new_tag("a", href=raw)
                    a.string = f"Open recovered object #{media_obj.get('id')}"
                    card.append(a)
                reason = soup.new_tag("div")
                reason["style"] = "font-size:11px;color:#94a3b8;word-break:break-word;margin-top:6px"
                reason.string = str(media_obj.get("_reviewer_match_reason") or media_obj.get("source_ref") or media_obj.get("original_url") or "")[:500]
                card.append(reason)
                grid.append(card)
            shelf.append(grid)
            soup.body.append(shelf)
    except Exception:
        pass
    return "<!doctype html>\n" + str(soup)


def reviewer_page_payload_model(obj: dict[str, Any]) -> dict[str, Any]:
    data = read_reviewer_object(obj)
    text = data.decode("utf-8", errors="replace")
    mt = (obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower().strip()
    ctx = reviewer_page_context(obj)
    raw_html = mt in {"text/html", "application/xhtml+xml"} or data[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body"))
    parsed: Any = None
    if not raw_html and ("json" in mt or str(obj.get("filename") or "").lower().endswith(".json") or text.lstrip().startswith(("{", "["))):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
    if raw_html:
        summary = sanitize_html_summary(ctx.get("page_url") or obj.get("source_ref") or "", text)
        return {**ctx, "payload_kind": "raw_html", "raw_html": text, "summary": summary, "metadata": ctx.get("source_meta") or {}, "parsed": None}
    if isinstance(parsed, dict):
        metadata = parsed.get("live_browser_metadata") or parsed.get("root_metadata") or parsed.get("metadata") or ctx.get("source_meta") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        summary = parsed.get("sanitized_summary") or parsed.get("summary") or {}
        if not isinstance(summary, dict):
            summary = {"text": pretty(summary), "links": [], "removed_counts": {}}
        summary.setdefault("links", [])
        summary.setdefault("removed_counts", {})
        summary.setdefault("text", "")
        title = summary.get("title") or metadata.get("title") or metadata.get("page_title") or ctx.get("title") or ""
        page_url = metadata.get("current_url") or metadata.get("final_url") or metadata.get("requested_url") or ctx.get("page_url") or ""
        session_id = metadata.get("session_id") or ctx.get("session_id") or ""
        return {**ctx, "title": str(title or ctx.get("title") or ""), "page_url": str(page_url or ""), "page_url_sha256": sha256_text(str(page_url or "")), "session_id": str(session_id or ""), "payload_kind": "safe_summary_json", "summary": summary, "metadata": metadata, "parsed": parsed}
    return {**ctx, "payload_kind": "text_page", "summary": {"title": ctx.get("title") or obj.get("filename"), "text": text[:300000], "links": [], "removed_counts": {}}, "metadata": ctx.get("source_meta") or {}, "parsed": parsed}


def reviewer_page_summary_frame_html(import_id: int, page_obj: dict[str, Any], mode: str = "auto") -> str:
    model = reviewer_page_payload_model(page_obj)
    media = reviewer_related_objects(import_id, page_obj, include_session_fallback=True, include_non_media=False, limit=300)
    blocked = reviewer_blocked_records_for_page(import_id, page_obj, limit=500)
    summary = model.get("summary") if isinstance(model.get("summary"), dict) else {}
    metadata = model.get("metadata") if isinstance(model.get("metadata"), dict) else {}
    links = summary.get("links") if isinstance(summary.get("links"), list) else []
    removed = summary.get("removed_counts") if isinstance(summary.get("removed_counts"), dict) else {}
    text_block = str(summary.get("text") or "")
    title = model.get("title") or page_obj.get("filename") or f"Recovered page {page_obj.get('id')}"
    page_url = model.get("page_url") or page_obj.get("page_url") or page_obj.get("source_ref") or ""
    media_cards = "".join(reviewer_media_card(import_id, m) for m in media)
    link_rows = "".join(f"<tr><td>{h((ln.get('text') or '')[:220])}</td><td class='urlcell'>{h(ln.get('url') or '')}</td><td class='hashcell'><code>{h(ln.get('url_sha256') or sha256_text(ln.get('url') or ''))}</code></td></tr>" for ln in links if isinstance(ln, dict))
    removed_rows = "".join(f"<tr><td>{h(k)}</td><td>{h(v)}</td></tr>" for k, v in removed.items())
    blocked_rows = "".join(f"<tr><td>{h(b.get('id') or '')}</td><td>{h(b.get('resource_type') or '')}</td><td>{'downloaded/recovered' if b.get('downloaded') else 'metadata only'}</td><td class='urlcell'>{h(b.get('media_url') or '')}</td><td class='hashcell'><code>{h(b.get('url_sha256') or sha256_text(b.get('media_url') or ''))}</code></td></tr>" for b in blocked)
    meta_pre = h(pretty(metadata)[:80000])
    if mode == "auto":
        mode = "safe"
    mode_note = "Best available local recovered-media view. Scripts, forms, navigation, and remote callbacks are disabled."
    if mode == "remote":
        mode_note = "Remote-callback mode selected. Safe-summary page text is local; raw HTML pages may load missing remote media/style."
    elif mode == "scripts":
        mode_note = "Scripts mode selected. Safe-summary page text remains local; raw HTML pages may run scripts only when raw HTML exists."
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'self'">
<title>{h(title)}</title><style>
body{{margin:0;background:#0f172a;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;padding:18px}}a{{color:#7dd3fc}}.banner{{position:sticky;top:0;z-index:10;background:#111827;border-bottom:2px solid #38bdf8;margin:-18px -18px 18px;padding:10px 16px}}.card{{background:#111827;border:1px solid #334155;border-radius:12px;padding:14px;margin:14px 0}}.muted{{color:#9ca3af}}.small{{font-size:.85rem}}.mono,code,pre{{font-family:Consolas,Menlo,monospace}}pre{{white-space:pre-wrap;background:#020617;border:1px solid #334155;border-radius:10px;padding:12px;overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #334155;padding:7px;text-align:left;vertical-align:top}}.urlcell,.hashcell{{word-break:break-all}}.badge{{display:inline-block;border:1px solid #475569;border-radius:999px;padding:3px 8px;margin:2px;background:#020617;color:#dbeafe;font-size:.8rem}}.media-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}}.thumb{{background:#020617;border:1px solid #334155;border-radius:10px;min-height:170px;display:flex;align-items:center;justify-content:center;overflow:hidden}}.thumb img,.thumb video{{max-width:100%;max-height:260px}}.thumb audio{{width:95%}}
</style></head><body><div class='banner'><b>Cleared reviewer page viewer</b> — {h(mode_note)}</div>
<div class='card'><h1>{h(title)}</h1><p><span class='badge'>{h(model.get('payload_kind'))}</span><span class='badge'>Page object #{h(page_obj.get('id'))}</span><span class='badge'>Original evidence #{h(page_obj.get('original_id'))}</span><span class='badge'>Associated media {h(len(media))}</span></p><p><b>Source URL:</b> <span class='mono urlcell'>{h(page_url)}</span></p><p><b>Source URL SHA-256:</b> <code>{h(model.get('page_url_sha256') or sha256_text(str(page_url)))}</code></p><p><b>Evidence SHA-256:</b> <code>{h(page_obj.get('sha256') or '')}</code></p></div>
<div class='card'><h2>Recovered page content</h2><pre>{h(text_block or '[No text summary was present in this captured page object.]')}</pre></div>
<div class='card'><h2>Recovered media associated with this page</h2><p class='small muted'>These are recovered images/video/audio tied to this page by captured-asset records, blocked-media materialization records, page URL/session metadata, or raw HTML references.</p><div class='media-grid'>{media_cards or '<p class="muted">No recovered media objects were associated with this page.</p>'}</div></div>
<div class='card'><h2>Links captured from the page</h2><table><tr><th>Text</th><th>URL</th><th>URL SHA-256</th></tr>{link_rows or '<tr><td colspan="3" class="muted">No links were recorded in this page summary.</td></tr>'}</table></div>
<div class='card'><h2>Blocked/recovered media records for this page</h2><table><tr><th>ID</th><th>Type</th><th>State</th><th>URL</th><th>URL SHA-256</th></tr>{blocked_rows or '<tr><td colspan="5" class="muted">No blocked-media metadata matched this page.</td></tr>'}</table></div>
<div class='card'><h2>Removed/suppressed elements</h2><table><tr><th>Element</th><th>Count</th></tr>{removed_rows or '<tr><td colspan="2" class="muted">No removed-count data was present.</td></tr>'}</table></div>
<div class='card'><h2>Capture metadata</h2><pre>{meta_pre}</pre></div>
</body></html>"""


def reviewer_page_frame_html(import_id: int, page_obj: dict[str, Any], mode: str = "auto", capture_remote_assets: bool = False) -> str:
    data = read_reviewer_object(page_obj)
    mt = (page_obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower()
    if mt in {"text/html", "application/xhtml+xml"} or data[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        return reviewer_render_html(import_id, page_obj, mode, capture_remote_assets=capture_remote_assets)
    return reviewer_page_summary_frame_html(import_id, page_obj, mode)


def reviewer_object_frame_html(import_id: int, obj: dict[str, Any], mode: str = "safe", capture_remote_assets: bool = False) -> str:
    data = read_reviewer_object(obj)
    mt = reviewer_effective_mime_type(obj)
    raw_url = f"/reviewer/imports/{import_id}/objects/{obj['id']}/raw"
    title = obj.get("filename") or f"object_{obj['id']}"
    if obj.get("kind") == "page":
        return reviewer_page_frame_html(import_id, obj, mode)
    if mt in {"text/html", "application/xhtml+xml"} or data[:256].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        return reviewer_render_html(import_id, obj, mode, capture_remote_assets=capture_remote_assets)
    playback = reviewer_playback_kind(obj)
    if playback == "image":
        body = f"<div class='viewer'><img src='{raw_url}' alt='{h(title)}'><p class='small muted'>If the image does not appear, use Download recovered object.</p></div>"
    elif playback == "video":
        body = f"<div class='viewer media-viewer'><video controls preload='metadata' playsinline style='max-width:100%;max-height:80vh;background:#000'><source src='{raw_url}' type='{h(mt)}'>Your browser could not play this recovered video object.</video><p class='small muted'>Served as {h(mt)}. If playback fails, the object may be a fragment/manifest; use Download recovered object or inspect related media.</p></div>"
    elif playback == "audio":
        body = f"<div class='viewer media-viewer'><audio controls preload='metadata' style='width:95%'><source src='{raw_url}' type='{h(mt)}'>Your browser could not play this recovered audio object.</audio><p class='small muted'>Served as {h(mt)}.</p></div>"
    elif mt == "application/pdf":
        body = f"<iframe style='width:100%;height:82vh;border:0;background:white' src='{raw_url}'></iframe>"
    elif "json" in mt or title.lower().endswith(".json"):
        try:
            text = pretty(json.loads(data.decode("utf-8", errors="replace")))
        except Exception:
            text = data.decode("utf-8", errors="replace")
        body = f"<pre>{h(text[:300000])}</pre>"
    elif mt.startswith("text/") or mt in {"application/xml", "application/xhtml+xml"}:
        body = f"<pre>{h(data.decode('utf-8', errors='replace')[:300000])}</pre>"
    else:
        body = f"<div class='viewer'><div><h2>Binary object</h2><p>{h(mt)}</p><p>{h(len(data))} bytes</p><p><a href='{raw_url}?download=1'>Download recovered object</a></p></div></div>"
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; script-src 'none'; connect-src 'none'"><style>body{{margin:0;background:#0f172a;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;padding:18px}}pre{{white-space:pre-wrap;background:#020617;border:1px solid #334155;border-radius:10px;padding:12px;overflow:auto}}.viewer{{min-height:70vh;border:1px dashed #475569;border-radius:12px;display:flex;align-items:center;justify-content:center;text-align:center;background:#020617}}.media-viewer{{flex-direction:column;gap:10px}}.viewer img{{max-width:100%;max-height:82vh}}a{{color:#7dd3fc}}
.rv-thumb-small{width:74px;height:56px;border:1px solid #334155;border-radius:8px;background:#020617;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative;color:#cbd5e1;font-size:10px}
.rv-thumb-small img,.rv-thumb-small video{width:100%;height:100%;object-fit:cover;display:block;background:#000}
.rv-thumb-small .thumb-label{position:absolute;left:2px;bottom:2px;background:rgba(0,0,0,.65);color:#fff;border-radius:4px;padding:1px 3px;font-size:9px}
.thumb-doc,.thumb-audio{display:flex;flex-direction:column;gap:2px;align-items:center;justify-content:center;text-align:center;font-size:12px;color:#cbd5e1}.thumb-doc span{font-weight:800}.thumb-audio span{font-size:22px}.media-tools{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.media-tools input{max-width:260px}.starbtn{font-size:18px;padding:3px 8px}.tagline{display:flex;gap:5px;align-items:center;flex-wrap:wrap}.compact-input{max-width:220px}
</style><title>{h(title)}</title></head><body><h2>{h(title)}</h2><p>{h(obj.get('kind'))} · {h(mt)} · SHA-256 <code>{h(obj.get('sha256'))}</code></p>{body}</body></html>"""


@app.get("/reviewer", response_class=HTMLResponse)
def reviewer_page(request: Request, msg: str | None = None) -> HTMLResponse:
    user = require_reviewer(request)
    rows = fetchall("SELECT * FROM reviewer_imports ORDER BY id DESC LIMIT 100")
    trs = "".join(f"<tr><td><a href='/reviewer/imports/{r['id']}/viewer'>#{r['id']}</a></td><td>{h(r['package_name'])}</td><td>{badge(r['status'],'good' if r['status']=='imported' else 'warn' if r['status']=='imported_with_errors' else 'bad' if r['status']=='error' else 'info')} {reviewer_import_protection_badges(request, dict(r))}</td><td>{h(r['case_name'] or '')}</td><td>{h(r['recovered_count'])}/{h(r['object_count'])}</td><td><a class='button good' href='/reviewer/imports/{r['id']}/pages'>Pages</a> <a class='button secondary' href='/reviewer/imports/{r['id']}/viewer'>Objects</a></td><td><code>{h((r['package_sha256'] or '')[:24])}…</code></td><td>{h(r['created_at'])}</td></tr>" for r in rows)
    yubi_ready = webauthn_user_has_credentials(user["username"])
    yubi_import_disabled = "" if yubi_ready else "disabled"
    yubi_import_note = "" if yubi_ready else "<p class='small muted'>Enroll a YubiKey/security key first from Settings → YubiKey to use YubiKey protection on import.</p>"
    body = f"""{flash(msg)}<div class='card safe'><h2>Law-enforcement / cleared reviewer import</h2><p>Import a sealed BlindSite evidence package with the escrow private key. Recovered plaintext is written only into this local review vault and indexed for browsing.</p><form method='post' action='/reviewer/import' enctype='multipart/form-data'><label>Sealed evidence ZIP</label><input type='file' name='package' accept='.zip' required><label>Escrow private key PEM</label><input type='file' name='private_key' accept='.pem,.key,.txt' required><label>Private-key passphrase, if any</label><input type='password' name='passphrase'><label>Review case password (optional but recommended)</label><input type='password' name='review_case_password' placeholder='Protect this imported case in the LE viewer'><label>Confirm review case password</label><input type='password' name='review_case_password_confirm'><label><input type='checkbox' name='review_case_yubikey' value='1' {yubi_import_disabled}> Protect this imported case with my YubiKey/WebAuthn key</label>{yubi_import_note}<p class='small muted'>Password/YubiKey protection controls access to the imported LE reviewer case inside BlindSite. Unlock expires after the configured inactivity timeout. This does not replace package cryptography or evidence hashes.</p><label>Import note</label><textarea name='note' placeholder='Agency/case note'></textarea><button class='good'>Import and decrypt into review vault</button></form></div><div class='card'><h2>Reviewer imports</h2><table><tr><th>ID</th><th>Package</th><th>Status</th><th>Case</th><th>Recovered</th><th>Open</th><th>Package SHA-256</th><th>Imported</th></tr>{trs or '<tr><td colspan="8" class="muted">No reviewer imports yet.</td></tr>'}</table></div>"""
    log_event(user["username"], "REVIEWER_AREA_OPENED")
    return layout(request, "LE Reviewer", body)


@app.post("/reviewer/import")
async def reviewer_import_route(request: Request, package: UploadFile = File(...), private_key: UploadFile = File(...), passphrase: str = Form(""), note: str = Form(""), review_case_password: str = Form(""), review_case_password_confirm: str = Form(""), review_case_yubikey: str | None = Form(None)) -> RedirectResponse:
    user = require_reviewer(request)
    package_bytes = await package.read()
    private_pem = await private_key.read()
    if not package_bytes:
        raise HTTPException(400, "Sealed evidence ZIP is empty")
    if not private_pem:
        raise HTTPException(400, "Escrow private key PEM is empty")
    if review_case_password or review_case_password_confirm:
        if review_case_password != review_case_password_confirm:
            raise HTTPException(400, "Review case passwords did not match")
        if len(review_case_password) < 6:
            raise HTTPException(400, "Review case password must be at least 6 characters")
    if review_case_yubikey and not webauthn_user_has_credentials(user["username"]):
        raise HTTPException(400, "Enroll a YubiKey/WebAuthn security key before enabling YubiKey protection for a reviewer import")
    import_id = reviewer_import_package(package_bytes, package.filename or "sealed_evidence.zip", private_pem, passphrase, user["username"], note)
    protected_methods: list[str] = []
    if review_case_password:
        set_reviewer_import_password(import_id, review_case_password, user["username"])
        protected_methods.append("password")
        log_event(user["username"], "REVIEWER_IMPORT_PASSWORD_PROTECTED", details={"reviewer_import_id": import_id})
    if review_case_yubikey:
        set_reviewer_import_webauthn_protection(import_id, True, user["username"])
        protected_methods.append("yubikey")
        log_event(user["username"], "REVIEWER_IMPORT_YUBIKEY_PROTECTED", details={"reviewer_import_id": import_id})
    if protected_methods:
        reviewer_import_unlock_session(request, import_id, user["username"], "+".join(protected_methods))
    return RedirectResponse(f"/reviewer/imports/{import_id}/pages?msg=Sealed%20package%20imported", 303)


@app.get("/reviewer/imports/{import_id}", response_class=HTMLResponse)
def reviewer_import_detail_alias(request: Request, import_id: int) -> HTMLResponse:
    if not reviewer_import_is_unlocked(request, import_id):
        return RedirectResponse(f"/reviewer/imports/{import_id}/unlock", 303)
    return reviewer_viewer(request, import_id)


@app.get("/reviewer/imports/{import_id}/unlock", response_class=HTMLResponse)
def reviewer_import_unlock_page(request: Request, import_id: int, msg: str | None = None) -> HTMLResponse:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    if not reviewer_import_is_protected(imp):
        reviewer_import_unlock_session(request, import_id, user["username"], "unprotected")
        return RedirectResponse(f"/reviewer/imports/{import_id}/viewer", 303)
    timeout_s = reviewer_import_unlock_timeout_seconds()
    timeout_text = "timeout disabled" if timeout_s == 0 else f"will lock after {timeout_s} seconds of inactivity"
    password_form = ""
    if reviewer_import_is_password_protected(imp):
        password_form = f"""<div class='card'><h3>Password unlock</h3><form method='post' action='/reviewer/imports/{import_id}/unlock'><label>Review case password</label><input type='password' name='review_password' autofocus required><button class='good'>Unlock with password</button></form></div>"""
    yubikey_form = ""
    yubi_script = ""
    if reviewer_import_webauthn_protected(imp):
        if webauthn_user_has_credentials(user["username"]):
            return_to = f"/reviewer/imports/{import_id}/unlock-yubikey"
            # Escape the JSON string before placing it inside the HTML attribute.
            # Without this, the double quotes from json.dumps(return_to) terminate
            # the onclick attribute and the YubiKey button appears ready but does
            # nothing when clicked.
            return_to_js = h(json.dumps(return_to))
            yubikey_form = f"""<div class='card'><h3>YubiKey / WebAuthn unlock</h3><p>Use your enrolled YubiKey/security key to unlock this LE reviewer case.</p><div id='webauthn-status'>{badge('ready','info')}</div><button class='good' type='button' onclick="bsAuthenticateKey('stepup','reviewer_import_unlock',{return_to_js});return false;">Unlock with YubiKey</button></div>"""
            yubi_script = webauthn_browser_script(purpose="manual")
        else:
            yubikey_form = "<div class='card danger'><h3>YubiKey required</h3><p>This import allows YubiKey unlock, but this account has no enrolled key. Enroll one from Settings → YubiKey, or unlock with the review-case password if one was set.</p><p><a class='button warn' href='/webauthn'>Open YubiKey settings</a></p></div>"
    body = f"""{flash(msg)}<div class='card warn'><h2>Unlock LE reviewer case import #{import_id}</h2><p>{reviewer_import_protection_badges(request, imp)}</p><p>This imported review case is protected. Unlock with the configured review-case password or YubiKey/security key. The unlock session {h(timeout_text)}.</p>{password_form}{yubikey_form}<p><a class='button secondary' href='/reviewer'>Back to LE reviewer imports</a></p></div>{yubi_script}"""
    return layout(request, "Unlock reviewer import", body)


@app.post("/reviewer/imports/{import_id}/unlock")
def reviewer_import_unlock(request: Request, import_id: int, review_password: str = Form("")) -> RedirectResponse:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    pw_hash = reviewer_import_password_hash(imp)
    if not pw_hash:
        return RedirectResponse(f"/reviewer/imports/{import_id}/unlock?msg=Password%20unlock%20is%20not%20configured%20for%20this%20case", 303)
    if check_password(review_password or "", pw_hash):
        reviewer_import_unlock_session(request, import_id, user["username"], "password")
        log_event(user["username"], "REVIEWER_IMPORT_UNLOCKED", details={"reviewer_import_id": import_id, "method": "password", "timeout_seconds": reviewer_import_unlock_timeout_seconds()})
        return RedirectResponse(f"/reviewer/imports/{import_id}/viewer?msg=Reviewer%20case%20unlocked", 303)
    log_event(user["username"], "REVIEWER_IMPORT_UNLOCK_FAILED", details={"reviewer_import_id": import_id, "method": "password"})
    return RedirectResponse(f"/reviewer/imports/{import_id}/unlock?msg=Invalid%20review%20case%20password", 303)


@app.get("/reviewer/imports/{import_id}/unlock-yubikey")
def reviewer_import_unlock_yubikey(request: Request, import_id: int) -> RedirectResponse:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    if not reviewer_import_webauthn_protected(imp):
        return RedirectResponse(f"/reviewer/imports/{import_id}/unlock?msg=YubiKey%20unlock%20is%20not%20enabled%20for%20this%20case", 303)
    if not webauthn_step_up_valid(request, user):
        return RedirectResponse(f"/webauthn/step-up?action=reviewer_import_unlock&return_to={quote('/reviewer/imports/' + str(import_id) + '/unlock-yubikey')}", 303)
    reviewer_import_unlock_session(request, import_id, user["username"], "yubikey")
    log_event(user["username"], "REVIEWER_IMPORT_UNLOCKED", details={"reviewer_import_id": import_id, "method": "yubikey", "timeout_seconds": reviewer_import_unlock_timeout_seconds()})
    return RedirectResponse(f"/reviewer/imports/{import_id}/viewer?msg=Reviewer%20case%20unlocked%20with%20YubiKey", 303)


@app.post("/reviewer/imports/{import_id}/protection")
def reviewer_import_protection_update(request: Request, import_id: int, review_case_yubikey: str | None = Form(None)) -> RedirectResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    enable_yubi = bool(review_case_yubikey)
    if enable_yubi and not webauthn_user_has_credentials(user["username"]):
        raise HTTPException(400, "Enroll a YubiKey/WebAuthn security key before enabling YubiKey protection for a reviewer import")
    set_reviewer_import_webauthn_protection(import_id, enable_yubi, user["username"])
    if enable_yubi:
        reviewer_import_unlock_session(request, import_id, user["username"], "yubikey-protection-updated")
    log_event(user["username"], "REVIEWER_IMPORT_PROTECTION_UPDATED", details={"reviewer_import_id": import_id, "yubikey_protected": enable_yubi, "timeout_seconds": reviewer_import_unlock_timeout_seconds()})
    return RedirectResponse(f"/reviewer/imports/{import_id}/viewer?msg=Reviewer%20case%20protection%20saved", 303)


@app.post("/reviewer/imports/{import_id}/lock")
def reviewer_import_lock(request: Request, import_id: int) -> RedirectResponse:
    user = require_reviewer(request)
    reviewer_import_lock_session(request, import_id)
    log_event(user["username"], "REVIEWER_IMPORT_LOCKED", details={"reviewer_import_id": import_id})
    return RedirectResponse(f"/reviewer/imports/{import_id}/unlock?msg=Reviewer%20case%20locked", 303)


@app.get("/reviewer/imports/{import_id}/pages", response_class=HTMLResponse)
def reviewer_pages_viewer(request: Request, import_id: int, page: str = "", render: str = "auto", q: str = "", remote_capture: str = "0", msg: str | None = None) -> HTMLResponse:
    if not reviewer_import_is_unlocked(request, import_id):
        return RedirectResponse(f"/reviewer/imports/{import_id}/unlock", 303)
    user, imp = require_reviewer_import_unlocked(request, import_id)
    if render not in {"auto", "safe", "remote", "scripts"}:
        render = get_setting("reviewer_default_render_mode", "auto")
        render = render if render in {"auto", "safe", "remote", "scripts"} else "auto"
    remote_capture_enabled = truthy(remote_capture) and render == "scripts"
    pages = reviewer_page_objects(import_id, q=q, limit=600)
    selected_id = int(page) if str(page).isdigit() else (int(pages[0]["id"]) if pages else 0)
    selected = reviewer_object_for(selected_id) if selected_id else None
    if selected and int(selected.get("import_id") or 0) != import_id:
        selected = None
    page_rows: list[str] = []
    for p_obj in pages:
        ctx = reviewer_page_context(p_obj)
        active = " style='background:#0f2f46'" if selected and int(p_obj["id"]) == int(selected["id"]) else ""
        media_count = len(reviewer_related_objects(import_id, p_obj, include_session_fallback=True, include_non_media=False, limit=301))
        media_label = "300+" if media_count > 300 else str(media_count)
        page_rows.append(
            f"<tr{active}><td><input type='checkbox' name='page_ids' value='{int(p_obj['id'])}' {'checked' if selected and int(p_obj['id']) == int(selected['id']) else ''}></td><td><a class='button good' href='/reviewer/imports/{import_id}/pages?page={p_obj['id']}&render={h(render)}&remote_capture={1 if remote_capture_enabled else 0}&q={h(q)}'>Load</a></td>"
            f"<td>{h(ctx.get('title') or p_obj.get('filename') or 'Recovered page')}<br><span class='small muted'>{h(ctx.get('created_at') or '')}</span></td>"
            f"<td>{badge(ctx.get('capture_mode') or p_obj.get('kind'),'info')} {badge('media '+media_label,'warn' if media_count else 'info')}</td>"
            f"<td class='urlcell'>{h(ctx.get('page_url') or p_obj.get('source_ref') or '')}</td>"
            f"<td class='hashcell'><code>{h(p_obj.get('sha256') or '')}</code></td></tr>"
        )
    frame = "<div class='viewer'><p class='muted'>No captured page selected.</p></div>"
    selected_info = ""
    media_table = ""
    if selected:
        ctx = reviewer_page_context(selected)
        associated = reviewer_related_objects(import_id, selected, include_session_fallback=True, include_non_media=False, limit=500)
        blocked = reviewer_blocked_records_for_page(import_id, selected, limit=500)
        sandbox = "allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-presentation allow-downloads allow-top-navigation-by-user-activation" if render == "scripts" else "allow-same-origin allow-forms allow-top-navigation-by-user-activation"
        frame_url = f"/reviewer/imports/{import_id}/pages/{selected['id']}/frame?mode={h(render)}&remote_capture={1 if remote_capture_enabled else 0}"
        frame = f"<iframe class='render-frame' sandbox='{sandbox}' src='{frame_url}'></iframe>"
        base = f"/reviewer/imports/{import_id}/pages?page={selected['id']}&q={h(q)}"
        render_controls = f"""<div class='card {'danger' if render=='scripts' else 'warn' if render=='remote' else 'safe'}'><h3>Page render mode</h3><p>{badge('best available local view','good') if render=='auto' else badge('local safe page view','good') if render=='safe' else badge('allow remote callbacks','warn') if render=='remote' else badge('allow remote callbacks + scripts','bad')}</p><p><a class='button good' href='{base}&render=auto'>Best available</a> <a class='button good' href='{base}&render=safe'>Local safe view</a> <a class='button warn' href='{base}&render=remote'>Allow remote callbacks</a> <a class='button danger' href='{base}&render=scripts'>Allow remote callbacks + scripts</a> <a class='button {'danger' if remote_capture_enabled else 'secondary'}' href='{base}&render=scripts&remote_capture={0 if remote_capture_enabled else 1}'>Remote media capture: {'ON' if remote_capture_enabled else 'OFF'}</a></p><p class='small muted'>Best available is safe/local by default. Use remote+scripts for dynamic sites that need live callbacks; BlindSite adds a small DOM guard to restore the recovered page if site JavaScript blanks it. Remote media capture is optional and stores media URLs discovered by dynamic scripts as supplemental reviewer objects.</p></div>"""
        media_rows = "".join(
            f"<tr><td><a class='button' href='/reviewer/imports/{import_id}/viewer?obj={m['id']}'>Open</a></td><td>{badge(m.get('kind'),'info')}</td><td>{h(m.get('filename'))}</td><td>{h(m.get('mime_type'))}</td><td>{h(m.get('size'))}</td><td class='urlcell'>{h(m.get('original_url') or m.get('source_ref') or '')}</td><td>{h(m.get('_reviewer_match_reason') or '')}</td><td class='hashcell'><code>{h(m.get('sha256') or '')}</code></td></tr>"
            for m in associated
        )
        blocked_rows = "".join(
            f"<tr><td>{h(b.get('id') or '')}</td><td>{h(b.get('resource_type') or '')}</td><td>{'downloaded/recovered' if b.get('downloaded') else 'metadata only'}</td><td class='urlcell'>{h(b.get('media_url') or '')}</td><td class='hashcell'><code>{h(b.get('url_sha256') or sha256_text(b.get('media_url') or ''))}</code></td></tr>"
            for b in blocked[:120]
        )
        media_table = f"""<div class='card'><h2>Associated recovered media for selected page</h2><p class='small muted'>This table is filtered to media tied to the selected captured page, instead of making reviewers browse every recovered image/video/audio object.</p><div class='table-scroll'><table><tr><th>Open</th><th>Kind</th><th>Filename</th><th>MIME</th><th>Size</th><th>Source</th><th>Match reason</th><th>SHA-256</th></tr>{media_rows or '<tr><td colspan="8" class="muted">No recovered media was associated with this page.</td></tr>'}</table></div></div><div class='card'><h2>Blocked-media records for selected page</h2><div class='table-scroll'><table><tr><th>ID</th><th>Type</th><th>State</th><th>URL</th><th>URL SHA-256</th></tr>{blocked_rows or '<tr><td colspan="5" class="muted">No blocked-media records matched this page.</td></tr>'}</table></div></div>"""
        selected_info = f"""<div class='card good'><h2>Selected captured page</h2><p>{badge(selected.get('kind'),'info')} {badge(selected.get('mime_type') or '')} {badge('associated media '+str(len(associated)),'warn' if associated else 'info')}</p><table><tr><th>Title</th><td>{h(ctx.get('title') or selected.get('filename') or '')}</td></tr><tr><th>Source URL</th><td class='urlcell'>{h(ctx.get('page_url') or selected.get('source_ref') or '')}</td></tr><tr><th>Page object</th><td>Reviewer object #{h(selected.get('id'))} / original evidence #{h(selected.get('original_id'))}</td></tr><tr><th>SHA-256</th><td class='hashcell'><code>{h(selected.get('sha256') or '')}</code></td></tr></table><p><a class='button' href='/reviewer/imports/{import_id}/viewer?obj={selected['id']}'>Object details</a> <a class='button' href='/reviewer/imports/{import_id}/objects/{selected['id']}/raw?download=1'>Download page object</a></p></div>{render_controls}"""
        log_event(user["username"], "REVIEWER_PAGE_VIEWER_OPENED", details={"reviewer_import_id": import_id, "page_object_id": selected["id"], "render": render, "remote_capture": remote_capture_enabled, "associated_media": len(associated)})
    protection_panel = reviewer_import_protection_panel(request, import_id, imp)
    body = f"""{flash(msg)}<div class='card safe'><h2>LE Captured Page Viewer — import #{import_id}</h2><p>{badge(imp['status'],'good' if imp['status']=='imported' else 'warn')} {badge('pages '+str(len(pages)),'info')} {badge('case '+str(imp.get('case_id_original') or ''),'info') if imp.get('case_id_original') else ''} {reviewer_import_protection_badges(request, imp)}</p><p class='small muted'>This workspace is organized around captured pages first. Select a page on the left; the viewer renders the recovered page content and groups recovered images/video/audio associated with that page.</p><p><a class='button' href='/reviewer/imports/{import_id}/viewer'>All recovered objects</a> <a class='button good' href='/reviewer/imports/{import_id}/pages'>Captured page viewer</a></p><table><tr><th>Package</th><td>{h(imp['package_name'])}</td></tr><tr><th>Case</th><td>{h(imp.get('case_name') or '')}</td></tr><tr><th>Package SHA-256</th><td class='hashcell'><code>{h(imp['package_sha256'])}</code></td></tr></table></div>{protection_panel}<div class='card noprint'><h2>Find captured pages</h2><form><input type='hidden' name='render' value='{h(render)}'><input type='hidden' name='remote_capture' value='{1 if remote_capture_enabled else 0}'><label>Search page title, URL, filename, hash, or MIME</label><input name='q' value='{h(q)}'><button>Search pages</button></form></div><div class='grid' style='grid-template-columns:minmax(430px,40%) minmax(560px,1fr)'><div class='card'><h2>Captured pages</h2><form method='post' action='/reviewer/imports/{import_id}/pages/pdf-report/start' class='noprint'><div class='media-tools'><button class='good'>Generate PDF report from selected pages</button><a class='button secondary' href='/reviewer/imports/{import_id}/pages/pdf-report/jobs'>View PDF report queue</a><select name='render_mode'><option value='scripts' selected>Remote callbacks + scripts screenshot</option><option value='safe'>Local safe screenshot</option><option value='remote'>Remote callbacks screenshot</option></select><label class='small'><input type='checkbox' name='encrypt_pdf' value='1'> Encrypt PDF report</label><input class='compact-input' type='password' name='pdf_password' placeholder='PDF password'><input class='compact-input' type='password' name='pdf_password_confirm' placeholder='Confirm PDF password'><span class='small muted'>PDF uses screenshots of the rendered reviewer page. Select up to 20 pages; generation runs in the background with progress. Encryption is opt-in.</span></div><div class='table-scroll'><table><tr><th>Select</th><th>Load</th><th>Title</th><th>Capture</th><th>URL</th><th>SHA-256</th></tr>{''.join(page_rows) or '<tr><td colspan="6" class="muted">No recovered page captures matched this filter.</td></tr>'}</table></div></form></div><div><div>{selected_info or '<div class="card"><p class="muted">Select a recovered page to view it.</p></div>'}</div><div class='card'><h2>Rendered captured page</h2>{frame}</div></div></div>{media_table}"""
    return layout(request, f"LE Pages Import #{import_id}", body)


def screenshot_is_mostly_blank_white(png: bytes) -> bool:
    """Heuristic for Reddit/YouTube renderer screenshots that went blank/white."""
    try:
        im = Image.open(io.BytesIO(png)).convert("RGB")
        im.thumbnail((160, 200))
        pixels = list(im.getdata())
        if not pixels:
            return False
        whiteish = 0
        very_light = 0
        colorful_dark = 0
        for r, g, b in pixels:
            if r > 245 and g > 245 and b > 245:
                whiteish += 1
            if r > 225 and g > 225 and b > 225:
                very_light += 1
            if min(r, g, b) < 180 and max(r, g, b) - min(r, g, b) > 20:
                colorful_dark += 1
        total = len(pixels)
        return (whiteish / total > 0.78 or very_light / total > 0.88) and colorful_dark / total < 0.04
    except Exception:
        return False


def valid_reviewer_pdf_page_ids(import_id: int, page_ids: list[int]) -> list[int]:
    valid_ids: list[int] = []
    seen: set[int] = set()
    for oid in page_ids:
        try:
            oid_int = int(oid)
        except Exception:
            continue
        if oid_int in seen:
            continue
        obj = reviewer_object_for(oid_int)
        if obj and int(obj.get("import_id") or 0) == int(import_id) and (obj.get("kind") == "page" or (obj.get("mime_type") or "").split(";", 1)[0].lower() in {"text/html", "application/xhtml+xml", "application/json"}):
            valid_ids.append(oid_int)
            seen.add(oid_int)
    return valid_ids


def pdf_report_job_update(job_id: str, **updates: Any) -> None:
    with PDF_REPORT_LOCK:
        job = PDF_REPORT_JOBS.get(job_id)
        if not job:
            return
        job.update(updates)
        job["updated_at"] = utcnow()


def pdf_report_job_log(job_id: str, message: str) -> None:
    with PDF_REPORT_LOCK:
        job = PDF_REPORT_JOBS.get(job_id)
        if not job:
            return
        logs = list(job.get("logs") or [])
        logs.append({"time": utcnow(), "message": str(message)[:500]})
        job["logs"] = logs[-100:]
        job["updated_at"] = utcnow()


def pdf_report_job_snapshot(job_id: str) -> dict[str, Any]:
    with PDF_REPORT_LOCK:
        job = dict(PDF_REPORT_JOBS.get(job_id) or {})
    if not job:
        return {"ok": False, "error": "job not found"}
    job.pop("cookies", None)
    job.pop("output_path", None)
    job.pop("pdf_password", None)
    return {"ok": True, **job}

def pdf_report_jobs_for_import(import_id: int) -> list[dict[str, Any]]:
    with PDF_REPORT_LOCK:
        jobs = [dict(v) for v in PDF_REPORT_JOBS.values() if int(v.get("import_id") or 0) == int(import_id)]
    for j in jobs:
        j.pop("cookies", None)
        j.pop("output_path", None)
        j.pop("pdf_password", None)
    jobs.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return jobs[:50]


def pdf_report_job_cancelled(job_id: str) -> bool:
    with PDF_REPORT_LOCK:
        job = PDF_REPORT_JOBS.get(job_id) or {}
        return str(job.get("status") or "") == "cancelled" or bool(job.get("cancel_requested"))


async def playwright_screenshot_no_font_hang(page: Any, *, full_page: bool = True, timeout_ms: int = 12000, full_width: bool = False, max_width: int = 2400, max_height: int = 24000) -> bytes:
    """Take a screenshot without letting web-font waits hang PDF report generation.

    PDF reports need slightly different behavior from ordinary browser screenshots:
    heavy dynamic pages can hang on fonts, and recovered reviewer pages can have
    horizontal overflow wider than the default viewport. When full_width is set,
    this expands/captures to the document scroll width within safe admin-configured
    limits so the right side of the page is not cut off.
    """
    first_exc: Exception | None = None
    try:
        with contextlib.suppress(Exception):
            await page.add_style_tag(content="""
                * { font-family: Arial, Helvetica, sans-serif !important; }
                html, body { overflow-x: visible !important; }
                .blindsite-inline-star, .blindsite-star-media-btn { display:none !important; }
            """)
        if full_page and full_width:
            with contextlib.suppress(Exception):
                dims = await page.evaluate("""() => ({
                    width: Math.ceil(Math.max(
                        document.documentElement ? document.documentElement.scrollWidth : 0,
                        document.body ? document.body.scrollWidth : 0,
                        window.innerWidth || 0
                    )),
                    height: Math.ceil(Math.max(
                        document.documentElement ? document.documentElement.scrollHeight : 0,
                        document.body ? document.body.scrollHeight : 0,
                        window.innerHeight || 0
                    )),
                    viewportWidth: window.innerWidth || 0,
                    viewportHeight: window.innerHeight || 0
                })""")
                wanted_w = max(int(dims.get("viewportWidth") or 0), int(dims.get("width") or 0), 1)
                wanted_w = max(640, min(int(max_width or 2400), wanted_w))
                wanted_h = max(600, min(12000, int(dims.get("viewportHeight") or PDF_REPORT_VIEWPORT_HEIGHT or 1600)))
                await page.set_viewport_size({"width": wanted_w, "height": wanted_h})
                await page.wait_for_timeout(250)
    except Exception as exc:
        first_exc = exc

    # For full-width PDF report captures, prefer CDP. It can capture beyond the
    # viewport and avoids several Playwright screenshot/font wait edge cases.
    if full_page and full_width:
        try:
            client = await page.context.new_cdp_session(page)
            metrics = await client.send("Page.getLayoutMetrics")
            clip = metrics.get("contentSize") or {}
            width = max(1, min(int(max_width or 2400), int(clip.get("width") or 1280)))
            height = max(1, min(int(max_height or 24000), int(clip.get("height") or 1600)))
            result = await client.send("Page.captureScreenshot", {
                "format": "png",
                "fromSurface": True,
                "captureBeyondViewport": True,
                "clip": {"x": 0, "y": 0, "width": width, "height": height, "scale": 1},
            })
            data = base64.b64decode(result.get("data") or "")
            if data:
                return data
        except Exception as exc:
            first_exc = exc

    try:
        try:
            return await page.screenshot(full_page=full_page, type="png", timeout=timeout_ms, scale="device")
        except TypeError:
            return await page.screenshot(full_page=full_page, type="png", timeout=timeout_ms)
    except Exception as normal_exc:
        if first_exc is None:
            first_exc = normal_exc
        try:
            client = await page.context.new_cdp_session(page)
            metrics = await client.send("Page.getLayoutMetrics")
            clip = metrics.get("contentSize") or {}
            width = max(1, min(int(max_width or 2400), int(clip.get("width") or 1280)))
            height = max(1, min(int(max_height or 24000), int(clip.get("height") or 1600)))
            result = await client.send("Page.captureScreenshot", {
                "format": "png",
                "fromSurface": True,
                "captureBeyondViewport": bool(full_page),
                "clip": {"x": 0, "y": 0, "width": width, "height": height, "scale": 1},
            })
            data = base64.b64decode(result.get("data") or "")
            if data:
                return data
            raise RuntimeError("CDP screenshot returned no image data")
        except Exception as cdp_exc:
            raise RuntimeError(f"screenshot failed; preflight={first_exc}; normal={normal_exc}; cdp={cdp_exc}")


def pdf_report_runtime_settings() -> dict[str, int]:
    """Settings used by the LE reviewer PDF report screenshot pipeline."""
    return {
        "navigation_timeout_ms": safe_int(get_setting("pdf_report_navigation_timeout_ms", "60000"), 60000, min_value=5000, max_value=300000),
        "domcontentloaded_timeout_ms": safe_int(get_setting("pdf_report_domcontentloaded_timeout_ms", "20000"), 20000, min_value=1000, max_value=180000),
        "scripts_wait_ms": safe_int(get_setting("pdf_report_scripts_wait_ms", "12000"), 12000, min_value=0, max_value=120000),
        "safe_wait_ms": safe_int(get_setting("pdf_report_safe_wait_ms", "3000"), 3000, min_value=0, max_value=60000),
        "screenshot_timeout_ms": safe_int(get_setting("pdf_report_screenshot_timeout_ms", "30000"), 30000, min_value=3000, max_value=180000),
        "fallback_timeout_ms": safe_int(get_setting("pdf_report_fallback_timeout_ms", "30000"), 30000, min_value=3000, max_value=180000),
        "full_width_capture": 1 if setting_bool("pdf_report_full_width_capture", "1") else 0,
        "max_capture_width": safe_int(get_setting("pdf_report_max_capture_width", "2400"), 2400, min_value=640, max_value=8000),
        "max_capture_height": safe_int(get_setting("pdf_report_max_capture_height", "24000"), 24000, min_value=1200, max_value=60000),
        "pdf_page_width_px": safe_int(get_setting("pdf_report_pdf_page_width_px", "1224"), 1224, min_value=480, max_value=5000),
        "pdf_page_height_px": safe_int(get_setting("pdf_report_pdf_page_height_px", "1584"), 1584, min_value=640, max_value=7000),
        "pdf_margin_px": safe_int(get_setting("pdf_report_pdf_margin_px", "36"), 36, min_value=0, max_value=400),
        "split_overlap_px": safe_int(get_setting("pdf_report_split_overlap_px", "24"), 24, min_value=0, max_value=300),
    }


def pdf_report_error_png_fallback(oid: int, error_text: str, cfg: dict[str, int] | None = None) -> bytes:
    cfg = cfg or pdf_report_runtime_settings()
    width = max(640, int(cfg.get("pdf_page_width_px") or PDF_REPORT_VIEWPORT_WIDTH or 1224))
    height = max(800, min(1800, int(cfg.get("pdf_page_height_px") or 1584)))
    im = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(im)
    lines = [
        f"BlindSite PDF render fallback — reviewer object #{oid}",
        "",
        "This reviewer page could not be rendered before the PDF timeout.",
        "The PDF report was not aborted; this page records the render error for review.",
        "",
        str(error_text or "")[:5000],
    ]
    y = 34
    for block in lines:
        wrapped = textwrap.wrap(block, width=110) if block else [""]
        for line in wrapped:
            draw.text((36, y), line, fill="black")
            y += 22
            if y > height - 45:
                break
        if y > height - 45:
            break
    out = io.BytesIO()
    im.save(out, format="PNG")
    return out.getvalue()


def pdf_report_pngs_to_pdf_pages(shots: list[tuple[int, bytes]], cfg: dict[str, int]) -> list[Image.Image]:
    """Convert full-page screenshots into standard-size PDF pages.

    Older builds embedded each full-page screenshot as one huge PDF page. PDF
    viewers then looked horizontally cut off or awkwardly zoomed. This scales
    each screenshot to a normal page width and splits tall screenshots into
    multiple standard pages so no right side is lost.
    """
    resample_filter = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.LANCZOS if hasattr(Image, "LANCZOS") else Image.BICUBIC)
    page_w = max(480, int(cfg.get("pdf_page_width_px") or 1224))
    page_h = max(640, int(cfg.get("pdf_page_height_px") or 1584))
    margin = max(0, min(int(cfg.get("pdf_margin_px") or 36), min(page_w, page_h) // 4))
    content_w = max(64, page_w - margin * 2)
    content_h = max(64, page_h - margin * 2)
    overlap = max(0, min(int(cfg.get("split_overlap_px") or 24), max(0, content_h // 3)))
    pdf_pages: list[Image.Image] = []
    for oid, png in shots:
        im = Image.open(io.BytesIO(png)).convert("RGB")
        max_h = PDF_REPORT_MAX_IMAGE_HEIGHT
        if im.height > max_h:
            ratio = max_h / float(im.height)
            im = im.resize((max(1, int(im.width * ratio)), max_h), resample_filter)
        if im.width != content_w:
            ratio = content_w / float(max(1, im.width))
            im = im.resize((content_w, max(1, int(im.height * ratio))), resample_filter)
        y = 0
        step = max(1, content_h - overlap)
        while y < im.height:
            crop_h = min(content_h, im.height - y)
            crop = im.crop((0, y, im.width, y + crop_h))
            page_img = Image.new("RGB", (page_w, page_h), "white")
            x = margin + max(0, (content_w - crop.width) // 2)
            page_img.paste(crop, (x, margin))
            pdf_pages.append(page_img)
            if y + crop_h >= im.height:
                break
            y += step
    return pdf_pages


def build_reviewer_pages_pdf_report_core(
    import_id: int,
    valid_ids: list[int],
    render_mode: str,
    base: str,
    cookies: dict[str, str] | None = None,
    progress: Optional[Any] = None,
    cancel_check: Optional[Any] = None,
) -> bytes:
    render_mode = render_mode if render_mode in {"safe", "remote", "scripts", "auto"} else "scripts"
    if not valid_ids:
        raise HTTPException(400, "No valid reviewer page objects selected for PDF report")
    if len(valid_ids) > PDF_REPORT_MAX_PAGES:
        raise HTTPException(400, f"PDF report supports up to {PDF_REPORT_MAX_PAGES} pages at once")
    cfg = pdf_report_runtime_settings()

    def emit(**data: Any) -> None:
        if progress:
            try:
                progress(data)
            except Exception:
                pass

    def check_cancelled() -> None:
        if cancel_check:
            try:
                if cancel_check():
                    raise RuntimeError("PDF report job cancelled")
            except RuntimeError:
                raise
            except Exception:
                pass

    async def _capture() -> list[tuple[int, bytes]]:
        from playwright.async_api import async_playwright  # type: ignore
        shots: list[tuple[int, bytes]] = []
        async with async_playwright() as pw:
            check_cancelled()
            emit(phase="launching_browser", current=0, total=len(valid_ids), message="Launching headless Chromium for PDF report")
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": PDF_REPORT_VIEWPORT_WIDTH, "height": PDF_REPORT_VIEWPORT_HEIGHT},
                device_scale_factor=PDF_REPORT_DEVICE_SCALE_FACTOR,
            )
            cookie_items = [{"name": n, "value": v, "url": base + "/"} for n, v in (cookies or {}).items()]
            if cookie_items:
                await context.add_cookies(cookie_items)

            async def _html_error_screenshot(oid: int, error_text: str) -> bytes:
                fallback = f"""<!doctype html><html><head><meta charset='utf-8'><title>BlindSite PDF render fallback</title></head><body style='font-family:Arial,Helvetica,sans-serif;padding:40px;background:white;color:black;line-height:1.45'><h1>BlindSite PDF render fallback</h1><p><b>Reviewer object:</b> #{h(oid)}</p><p>This page could not be rendered before the PDF timeout. The report continues and records the error below.</p><pre style='white-space:pre-wrap;border:1px solid #ccc;padding:12px;background:#f5f5f5'>{html_mod.escape(error_text)}</pre></body></html>"""
                err_page = None
                try:
                    err_page = await context.new_page()
                    try:
                        await err_page.set_content(fallback, wait_until="domcontentloaded", timeout=min(10000, int(cfg["fallback_timeout_ms"])))
                    except Exception:
                        await err_page.goto("data:text/html;charset=utf-8," + quote(fallback), wait_until="commit", timeout=min(10000, int(cfg["fallback_timeout_ms"])))
                    await err_page.wait_for_timeout(250)
                    return await playwright_screenshot_no_font_hang(err_page, full_page=True, timeout_ms=int(cfg["screenshot_timeout_ms"]), full_width=False, max_width=int(cfg["max_capture_width"]), max_height=int(cfg["max_capture_height"]))
                except Exception as fallback_exc:
                    return pdf_report_error_png_fallback(oid, f"{error_text}\nHTML fallback renderer error: {fallback_exc}", cfg)
                finally:
                    if err_page is not None:
                        with contextlib.suppress(Exception):
                            await err_page.close()

            try:
                for idx, oid in enumerate(valid_ids, start=1):
                    check_cancelled()
                    emit(phase="rendering_page", current=idx - 1, total=len(valid_ids), page_object_id=oid, message=f"Rendering page {idx}/{len(valid_ids)}")
                    url = f"{base}/reviewer/imports/{import_id}/pages/{oid}/frame?mode={quote(render_mode)}&remote_capture={1 if render_mode == 'scripts' else 0}"
                    page = await context.new_page()
                    try:
                        try:
                            await page.goto(url, wait_until="commit", timeout=int(cfg["navigation_timeout_ms"]))
                            with contextlib.suppress(Exception):
                                await page.wait_for_load_state("domcontentloaded", timeout=int(cfg["domcontentloaded_timeout_ms"]))
                            wait_ms = int(cfg["scripts_wait_ms"] if render_mode == "scripts" else cfg["safe_wait_ms"])
                            if wait_ms:
                                await page.wait_for_timeout(wait_ms)
                            check_cancelled()
                            emit(phase="screenshotting_page", current=idx - 1, total=len(valid_ids), page_object_id=oid, message=f"Screenshotting page {idx}/{len(valid_ids)}")
                            png = await playwright_screenshot_no_font_hang(page, full_page=True, timeout_ms=int(cfg["screenshot_timeout_ms"]), full_width=bool(cfg.get("full_width_capture")), max_width=int(cfg["max_capture_width"]), max_height=int(cfg["max_capture_height"]))
                            if render_mode == "scripts" and screenshot_is_mostly_blank_white(png):
                                emit(phase="fallback_safe_render", current=idx - 1, total=len(valid_ids), page_object_id=oid, message=f"Dynamic render blanked; falling back to local safe render for page {idx}/{len(valid_ids)}")
                                safe_url = f"{base}/reviewer/imports/{import_id}/pages/{oid}/frame?mode=safe&remote_capture=0"
                                await page.goto(safe_url, wait_until="commit", timeout=int(cfg["fallback_timeout_ms"]))
                                with contextlib.suppress(Exception):
                                    await page.wait_for_load_state("domcontentloaded", timeout=min(int(cfg["domcontentloaded_timeout_ms"]), int(cfg["fallback_timeout_ms"])))
                                if int(cfg["safe_wait_ms"]):
                                    await page.wait_for_timeout(int(cfg["safe_wait_ms"]))
                                png = await playwright_screenshot_no_font_hang(page, full_page=True, timeout_ms=int(cfg["screenshot_timeout_ms"]), full_width=bool(cfg.get("full_width_capture")), max_width=int(cfg["max_capture_width"]), max_height=int(cfg["max_capture_height"]))
                            shots.append((oid, png))
                            emit(phase="page_done", current=idx, total=len(valid_ids), page_object_id=oid, message=f"Captured page {idx}/{len(valid_ids)}")
                        except Exception as exc:
                            primary_error = str(exc)
                            emit(phase="page_error", current=idx, total=len(valid_ids), page_object_id=oid, message=f"Page {idx}/{len(valid_ids)} failed: {primary_error[:240]}")
                            safe_error = ""
                            if render_mode != "safe":
                                try:
                                    check_cancelled()
                                    emit(phase="fallback_safe_render", current=idx - 1, total=len(valid_ids), page_object_id=oid, message=f"Dynamic render failed; trying local safe render for page {idx}/{len(valid_ids)}")
                                    safe_url = f"{base}/reviewer/imports/{import_id}/pages/{oid}/frame?mode=safe&remote_capture=0"
                                    await page.goto(safe_url, wait_until="commit", timeout=int(cfg["fallback_timeout_ms"]))
                                    with contextlib.suppress(Exception):
                                        await page.wait_for_load_state("domcontentloaded", timeout=min(int(cfg["domcontentloaded_timeout_ms"]), int(cfg["fallback_timeout_ms"])))
                                    if int(cfg["safe_wait_ms"]):
                                        await page.wait_for_timeout(int(cfg["safe_wait_ms"]))
                                    png = await playwright_screenshot_no_font_hang(page, full_page=True, timeout_ms=int(cfg["screenshot_timeout_ms"]), full_width=bool(cfg.get("full_width_capture")), max_width=int(cfg["max_capture_width"]), max_height=int(cfg["max_capture_height"]))
                                    shots.append((oid, png))
                                    emit(phase="page_done", current=idx, total=len(valid_ids), page_object_id=oid, message=f"Captured page {idx}/{len(valid_ids)} with safe fallback")
                                    continue
                                except Exception as safe_exc:
                                    safe_error = str(safe_exc)
                                    emit(phase="fallback_safe_failed", current=idx - 1, total=len(valid_ids), page_object_id=oid, message=f"Safe fallback failed for page {idx}/{len(valid_ids)}: {safe_error[:220]}")
                            fallback_text = f"Primary render error: {primary_error}" + (f"\nSafe fallback error: {safe_error}" if safe_error else "")
                            shots.append((oid, await _html_error_screenshot(oid, fallback_text)))
                            emit(phase="page_done_with_fallback", current=idx, total=len(valid_ids), page_object_id=oid, message=f"Captured render-error fallback for page {idx}/{len(valid_ids)}")
                    finally:
                        with contextlib.suppress(Exception):
                            await page.close()
            finally:
                await browser.close()
        return shots

    try:
        shots = asyncio.run(_capture())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            shots = loop.run_until_complete(_capture())
        finally:
            loop.close()
    if not shots:
        raise HTTPException(500, "No page screenshots were produced for PDF report")
    emit(phase="building_pdf", current=len(valid_ids), total=len(valid_ids), message="Building PDF from screenshots")
    images = pdf_report_pngs_to_pdf_pages(shots, cfg)
    if not images:
        raise HTTPException(500, "No PDF pages were produced from screenshots")
    out = io.BytesIO()
    images[0].save(
        out,
        format="PDF",
        save_all=True,
        append_images=images[1:],
        resolution=PDF_REPORT_DPI,
        quality=PDF_REPORT_JPEG_QUALITY,
    )
    for im in images:
        with contextlib.suppress(Exception):
            im.close()
    emit(phase="pdf_done", current=len(valid_ids), total=len(valid_ids), message="PDF report generated")
    return out.getvalue()

def encrypt_pdf_report_bytes(pdf: bytes, password: str) -> bytes:
    password = password or ""
    if not password:
        return pdf
    try:
        from pypdf import PdfReader, PdfWriter  # type: ignore
    except Exception as exc:
        raise RuntimeError("PDF encryption requires pypdf. Install with: python -m pip install pypdf") from exc
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with contextlib.suppress(Exception):
        writer.add_metadata(reader.metadata or {})
    writer.encrypt(password)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def build_reviewer_pages_pdf_report(request: Request, import_id: int, page_ids: list[int], render_mode: str = "scripts") -> bytes:
    valid_ids = valid_reviewer_pdf_page_ids(import_id, page_ids)
    if not valid_ids:
        raise HTTPException(400, "No valid reviewer page objects selected for PDF report")
    base = str(request.base_url).rstrip("/")
    return build_reviewer_pages_pdf_report_core(import_id, valid_ids, render_mode, base, dict(request.cookies), None)


def run_reviewer_pdf_report_job(job_id: str) -> None:
    with PDF_REPORT_LOCK:
        job = dict(PDF_REPORT_JOBS.get(job_id) or {})
    if not job:
        return
    import_id = int(job["import_id"])
    valid_ids = [int(x) for x in job.get("page_ids") or []]
    render_mode = str(job.get("render_mode") or "scripts")
    base = str(job.get("base") or "http://127.0.0.1:8765").rstrip("/")
    cookies = dict(job.get("cookies") or {})
    actor = str(job.get("actor") or "unknown")
    try:
        pdf_report_job_update(job_id, status="running", phase="starting", current=0, total=len(valid_ids), progress_percent=0, started_at=utcnow(), message="Starting PDF report")
        pdf_report_job_log(job_id, f"Starting PDF report job with {len(valid_ids)} page(s), render mode {render_mode}")
        pdf_report_job_log(job_id, "PDF settings: " + json.dumps(pdf_report_runtime_settings(), sort_keys=True))

        def progress(ev: dict[str, Any]) -> None:
            current = int(ev.get("current") or 0)
            total = max(1, int(ev.get("total") or len(valid_ids) or 1))
            pct = max(0, min(100, round((current / total) * 100, 1)))
            pdf_report_job_update(job_id, phase=ev.get("phase") or "running", current=current, total=total, progress_percent=pct, page_object_id=ev.get("page_object_id"), message=ev.get("message") or "")
            if ev.get("message"):
                pdf_report_job_log(job_id, ev["message"])

        if pdf_report_job_cancelled(job_id):
            raise RuntimeError("PDF report job cancelled")
        pdf = build_reviewer_pages_pdf_report_core(import_id, valid_ids, render_mode, base, cookies, progress, cancel_check=lambda: pdf_report_job_cancelled(job_id))
        if bool(job.get("encrypt_pdf")):
            pdf_report_job_update(job_id, phase="encrypting_pdf", message="Encrypting PDF report")
            pdf_report_job_log(job_id, "Encrypting PDF report with selected password")
            pdf = encrypt_pdf_report_bytes(pdf, str(job.get("pdf_password") or ""))
        PDF_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = PDF_REPORT_DIR / f"reviewer_import_{import_id}_pages_{job_id}.pdf"
        out_path.write_bytes(pdf)
        pdf_sha = sha256_bytes(pdf)
        pdf_report_job_update(job_id, status="done", phase="done", current=len(valid_ids), total=len(valid_ids), progress_percent=100, output_path=str(out_path), output_sha256=pdf_sha, output_bytes=len(pdf), finished_at=utcnow(), message="PDF report ready")
        pdf_report_job_log(job_id, f"PDF report ready: {len(pdf)} bytes, SHA-256 {pdf_sha}")
        log_event(actor, "REVIEWER_PAGES_PDF_REPORT_GENERATED", details={"reviewer_import_id": import_id, "page_object_ids": valid_ids, "render_mode": render_mode, "pdf_sha256": pdf_sha, "bytes": len(pdf), "job_id": job_id, "encrypt_pdf": bool(job.get("encrypt_pdf"))})
    except Exception as exc:
        if "cancelled" in str(exc).lower() or pdf_report_job_cancelled(job_id):
            pdf_report_job_update(job_id, status="cancelled", phase="cancelled", error="", finished_at=utcnow(), message="PDF report cancelled")
            pdf_report_job_log(job_id, "PDF report cancelled")
            log_event(actor, "REVIEWER_PAGES_PDF_REPORT_CANCELLED", details={"reviewer_import_id": import_id, "page_object_ids": valid_ids, "render_mode": render_mode, "job_id": job_id})
        else:
            pdf_report_job_update(job_id, status="error", phase="error", error=str(exc)[:1000], finished_at=utcnow(), message="PDF report failed")
            pdf_report_job_log(job_id, f"ERROR: {str(exc)[:500]}")
            log_event(actor, "REVIEWER_PAGES_PDF_REPORT_FAILED", details={"reviewer_import_id": import_id, "page_object_ids": valid_ids, "render_mode": render_mode, "error": str(exc)[:500], "job_id": job_id})


@app.post("/reviewer/imports/{import_id}/pages/pdf-report/start")
def reviewer_pages_pdf_report_start(request: Request, import_id: int, page_ids: list[int] = Form(...), render_mode: str = Form("scripts"), encrypt_pdf: str | None = Form(None), pdf_password: str = Form(""), pdf_password_confirm: str = Form("")) -> RedirectResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    valid_ids = valid_reviewer_pdf_page_ids(import_id, page_ids)
    if not valid_ids:
        raise HTTPException(400, "No valid reviewer page objects selected for PDF report")
    if len(valid_ids) > PDF_REPORT_MAX_PAGES:
        valid_ids = valid_ids[:PDF_REPORT_MAX_PAGES]
    render_mode = render_mode if render_mode in {"safe", "remote", "scripts", "auto"} else "scripts"
    encrypt_pdf_enabled = bool(encrypt_pdf)
    if encrypt_pdf_enabled:
        if pdf_password != pdf_password_confirm:
            raise HTTPException(400, "PDF report passwords did not match")
        if len(pdf_password) < 6:
            raise HTTPException(400, "PDF report password must be at least 6 characters")
    job_id = secrets.token_hex(12)
    with PDF_REPORT_LOCK:
        PDF_REPORT_JOBS[job_id] = {
            "id": job_id,
            "import_id": int(import_id),
            "status": "queued",
            "phase": "queued",
            "current": 0,
            "total": len(valid_ids),
            "progress_percent": 0,
            "page_ids": valid_ids,
            "render_mode": render_mode,
            "actor": user["username"],
            "base": str(request.base_url).rstrip("/"),
            "cookies": dict(request.cookies),
            "encrypt_pdf": encrypt_pdf_enabled,
            "pdf_password": pdf_password if encrypt_pdf_enabled else "",
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "logs": [{"time": utcnow(), "message": "PDF report job queued"}],
            "message": "PDF report job queued",
            "pdf_report_settings": pdf_report_runtime_settings(),
        }
    threading.Thread(target=run_reviewer_pdf_report_job, args=(job_id,), name=f"blindsite-pdf-report-{job_id}", daemon=True).start()
    log_event(user["username"], "REVIEWER_PAGES_PDF_REPORT_QUEUED", details={"reviewer_import_id": import_id, "page_object_ids": valid_ids, "render_mode": render_mode, "job_id": job_id, "encrypt_pdf": encrypt_pdf_enabled})
    return RedirectResponse(f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}", 303)


@app.get("/reviewer/imports/{import_id}/pages/pdf-report/jobs", response_class=HTMLResponse)
def reviewer_pages_pdf_report_queue_page(request: Request, import_id: int) -> HTMLResponse:
    """Queue/index page for LE PDF report jobs for a reviewer import.

    This gives reviewers a stable place to return to after leaving a report
    progress page. It intentionally does not create or modify jobs.
    """
    user, imp = require_reviewer_import_unlocked(request, import_id)
    jobs = pdf_report_jobs_for_import(import_id)
    active = any(str(j.get("status") or "") not in {"done", "error", "cancelled"} for j in jobs)
    refresh_meta = "<meta http-equiv='refresh' content='5'>" if active else ""

    def pct_for(j: dict[str, Any]) -> float:
        try:
            return float(j.get("progress_percent") or 0)
        except Exception:
            return 0.0

    rows = []
    for j in jobs:
        jid = str(j.get("id") or "")
        status = str(j.get("status") or "")
        pct = pct_for(j)
        detail_url = f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{h(jid)}"
        download_url = f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{h(jid)}/download"
        download = f"<a class='button good' href='{download_url}'>Download</a>" if status == "done" else ""
        rows.append(
            f"<tr><td><a href='{detail_url}'><code>{h(jid)}</code></a></td>"
            f"<td>{badge(status, 'good' if status=='done' else 'bad' if status=='error' else 'warn' if status=='cancelled' else 'info')}</td>"
            f"<td>{h(j.get('phase') or '')}</td>"
            f"<td><div style='height:14px;background:#111827;border:1px solid #334155;border-radius:999px;overflow:hidden;min-width:110px'><div style='height:100%;width:{pct}%;background:#22c55e'></div></div><span class='small'>{h(pct)}%</span></td>"
            f"<td>{h(j.get('current') or 0)} / {h(j.get('total') or 0)}</td>"
            f"<td>{h(j.get('render_mode') or '')}</td>"
            f"<td>{h(j.get('message') or '')}</td>"
            f"<td>{h(j.get('created_at') or '')}</td>"
            f"<td>{download}</td></tr>"
        )
    body = f"""
    {refresh_meta}
    <div class='card safe'>
      <h2>LE PDF report queue — import #{import_id}</h2>
      <p>{badge('queue','info')} {badge(str(len(jobs))+' jobs','info')} {badge('auto-refreshing','good') if active else badge('no active jobs','muted')}</p>
      <p class='small muted'>Return here anytime to check report progress, open a job, cancel it from the job page, or download completed reports. This page lists in-memory report jobs for the current app run.</p>
      <p><a class='button secondary' href='/reviewer/imports/{import_id}/pages'>Back to captured pages</a></p>
    </div>
    <div class='card'>
      <h2>Jobs</h2>
      <div class='table-scroll'><table>
        <tr><th>Job</th><th>Status</th><th>Phase</th><th>Progress</th><th>Pages</th><th>Render</th><th>Message</th><th>Created</th><th>Output</th></tr>
        {''.join(rows) or '<tr><td colspan="9" class="muted">No PDF report jobs have been started for this import yet.</td></tr>'}
      </table></div>
    </div>
    """
    return layout(request, "LE PDF report queue", body)


@app.get("/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}", response_class=HTMLResponse)
def reviewer_pages_pdf_report_job_page(request: Request, import_id: int, job_id: str) -> HTMLResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    snap = pdf_report_job_snapshot(job_id)
    if not snap.get("ok") or int(snap.get("import_id") or 0) != int(import_id):
        raise HTTPException(404, "PDF report job not found")
    status_url = f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/status"
    download_url = f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/download"
    cancel_url = f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/cancel"
    status = str(snap.get("status") or "queued")
    pct = float(snap.get("progress_percent") or 0)
    total = int(snap.get("total") or 0)
    current = int(snap.get("current") or 0)
    logs = snap.get("logs") or []
    jobs = pdf_report_jobs_for_import(import_id)
    job_rows = "".join(
        f"<tr{' style=background:#0f2f46' if j.get('id')==job_id else ''}><td><a href='/reviewer/imports/{import_id}/pages/pdf-report/jobs/{h(j.get('id'))}'>{h(j.get('id'))}</a></td><td>{badge(j.get('status') or '', 'good' if j.get('status')=='done' else 'bad' if j.get('status')=='error' else 'warn' if j.get('status')=='cancelled' else 'info')}</td><td>{h(j.get('phase') or '')}</td><td>{h(j.get('current') or 0)} / {h(j.get('total') or 0)}</td><td>{h(j.get('message') or '')}</td><td>{h(j.get('created_at') or '')}</td></tr>"
        for j in jobs
    )
    refresh_meta = "" if status in {"done", "error", "cancelled"} else "<meta http-equiv='refresh' content='5'>"
    log_text = "\n".join("[" + str(x.get("time") or "") + "] " + str(x.get("message") or "") for x in logs)
    output_html = "Working..."
    if status == "done":
        output_html = f"Ready — <a class='button good' href='{download_url}'>Download PDF report</a><br>SHA-256 <code>{h(snap.get('output_sha256') or '')}</code> — {h(snap.get('output_bytes') or 0)} bytes"
    elif status == "error":
        output_html = "Error: " + h(snap.get("error") or "unknown error")
    elif status == "cancelled":
        output_html = "Cancelled"
    cancel_form = "" if status in {"done", "error", "cancelled"} else f"<form method='post' action='{cancel_url}' style='display:inline' onsubmit='return confirm(\"Cancel this PDF report job?\")'><button class='danger'>Cancel job</button></form>"
    status_badges = f"{badge('background job','info')} {badge('up to '+str(PDF_REPORT_MAX_PAGES)+' pages','warn')} {badge('heavy dynamic pages supported','good')} {badge(status, 'good' if status=='done' else 'bad' if status=='error' else 'warn' if status=='cancelled' else 'info')}"
    body = f"""
    {refresh_meta}
    <div class='card safe'>
      <h2>LE PDF report generator</h2>
      <p>{status_badges}</p>
      <p class='small muted'>This page now renders current job status server-side and also polls with JavaScript. If JavaScript stalls, the page auto-refreshes while the job is running.</p>
      <p><a class='button secondary' href='/reviewer/imports/{import_id}/pages'>Back to captured pages</a> <a id='downloadBtn' class='button good' {'style="display:none"' if status!='done' else ''} href='{download_url}'>Download PDF report</a> {cancel_form}</p>
    </div>
    <div class='card'>
      <h2>Status</h2>
      <div style='height:22px;background:#111827;border:1px solid #334155;border-radius:999px;overflow:hidden'><div id='bar' style='height:100%;width:{pct}%;background:#22c55e'></div></div>
      <p><b id='pct'>{pct}%</b> <span id='statusText'>{h(status)} / {h(snap.get('phase') or '')}</span></p>
      <table><tr><th>Job</th><td><code>{h(job_id)}</code></td></tr><tr><th>Render mode</th><td id='renderMode'>{h(snap.get('render_mode') or '')}</td></tr><tr><th>PDF encryption</th><td>{badge('encrypted','warn') if snap.get('encrypt_pdf') else badge('not encrypted','info')}</td></tr><tr><th>Pages</th><td id='pages'>{current} / {total} selected: {h(', '.join(str(x) for x in (snap.get('page_ids') or [])))}</td></tr><tr><th>Phase</th><td id='phase'>{h(snap.get('phase') or '')}</td></tr><tr><th>Message</th><td id='message'>{h(snap.get('message') or '')}</td></tr><tr><th>Output</th><td id='output'>{output_html}</td></tr></table>
    </div>
    <div class='card'><h2>PDF report queue for this import</h2><div class='table-scroll'><table><tr><th>Job</th><th>Status</th><th>Phase</th><th>Progress</th><th>Message</th><th>Created</th></tr>{job_rows or '<tr><td colspan="6" class="muted">No PDF jobs found.</td></tr>'}</table></div></div>
    <div class='card'><h2>Progress log</h2><pre id='logs' style='white-space:pre-wrap;max-height:420px;overflow:auto'>{h(log_text)}</pre></div>
    <script>
    async function poll(){{
      try{{
        const r = await fetch({json.dumps(status_url)}, {{cache:'no-store'}});
        const j = await r.json();
        if(!j.ok){{ document.getElementById('statusText').textContent = j.error || 'job error'; return; }}
        const pct = Number(j.progress_percent || 0);
        document.getElementById('bar').style.width = pct + '%';
        document.getElementById('pct').textContent = pct + '%';
        document.getElementById('statusText').textContent = (j.status || '') + ' / ' + (j.phase || '');
        document.getElementById('renderMode').textContent = j.render_mode || '';
        document.getElementById('pages').textContent = (j.current || 0) + ' / ' + (j.total || 0) + ' selected: ' + (j.page_ids || []).join(', ');
        document.getElementById('phase').textContent = j.phase || '';
        document.getElementById('message').textContent = j.message || '';
        if(j.status === 'done'){{
          document.getElementById('downloadBtn').style.display = 'inline-block';
          document.getElementById('output').innerHTML = 'Ready — SHA-256 <code>' + (j.output_sha256 || '') + '</code> — ' + (j.output_bytes || 0) + ' bytes';
        }} else if(j.status === 'error'){{
          document.getElementById('output').textContent = 'Error: ' + (j.error || 'unknown error');
        }} else if(j.status === 'cancelled'){{
          document.getElementById('output').textContent = 'Cancelled';
        }} else {{
          document.getElementById('output').textContent = 'Working...';
        }}
        const logs = (j.logs || []).map(x => '[' + (x.time || '') + '] ' + (x.message || '')).join('\n');
        document.getElementById('logs').textContent = logs;
        if(j.status !== 'done' && j.status !== 'error' && j.status !== 'cancelled') setTimeout(poll, 1500);
      }}catch(e){{
        document.getElementById('statusText').textContent = 'poll error: ' + e;
        setTimeout(poll, 3000);
      }}
    }}
    poll();
    </script>
    """
    return layout(request, "LE PDF report generator", body)


@app.post("/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/cancel")
def reviewer_pages_pdf_report_job_cancel(request: Request, import_id: int, job_id: str) -> RedirectResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    snap = pdf_report_job_snapshot(job_id)
    if not snap.get("ok") or int(snap.get("import_id") or 0) != int(import_id):
        raise HTTPException(404, "PDF report job not found")
    if str(snap.get("status") or "") not in {"done", "error", "cancelled"}:
        pdf_report_job_update(job_id, status="cancelled", phase="cancel_requested", cancel_requested=True, message="Cancellation requested")
        pdf_report_job_log(job_id, f"Cancellation requested by {user['username']}")
        log_event(user["username"], "REVIEWER_PAGES_PDF_REPORT_CANCEL_REQUESTED", details={"reviewer_import_id": import_id, "job_id": job_id})
    return RedirectResponse(f"/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}", 303)

@app.get("/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/status")
def reviewer_pages_pdf_report_job_status(request: Request, import_id: int, job_id: str) -> JSONResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    snap = pdf_report_job_snapshot(job_id)
    if snap.get("ok") and int(snap.get("import_id") or 0) != int(import_id):
        return JSONResponse({"ok": False, "error": "job/import mismatch"}, status_code=404)
    return JSONResponse(snap)


@app.get("/reviewer/imports/{import_id}/pages/pdf-report/jobs/{job_id}/download")
def reviewer_pages_pdf_report_job_download(request: Request, import_id: int, job_id: str) -> StreamingResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    with PDF_REPORT_LOCK:
        job = dict(PDF_REPORT_JOBS.get(job_id) or {})
    if not job or int(job.get("import_id") or 0) != int(import_id):
        raise HTTPException(404, "PDF report job not found")
    if job.get("status") != "done" or not job.get("output_path"):
        raise HTTPException(409, "PDF report is not ready yet")
    path = Path(job["output_path"])
    if not path.exists():
        raise HTTPException(404, "PDF report file is missing")
    data = path.read_bytes()
    log_event(user["username"], "REVIEWER_PAGES_PDF_REPORT_DOWNLOADED", details={"reviewer_import_id": import_id, "job_id": job_id, "pdf_sha256": sha256_bytes(data), "bytes": len(data)})
    suffix = "_encrypted" if bool(job.get("encrypt_pdf")) else ""
    filename = f"blindsite_reviewer_import_{import_id}_pages_report_{job_id}{suffix}.pdf"
    return StreamingResponse(io.BytesIO(data), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.post("/reviewer/imports/{import_id}/pages/pdf-report")
def reviewer_pages_pdf_report(request: Request, import_id: int, page_ids: list[int] = Form(...), render_mode: str = Form("scripts")) -> StreamingResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    pdf = build_reviewer_pages_pdf_report(request, import_id, page_ids, render_mode)
    log_event(user["username"], "REVIEWER_PAGES_PDF_REPORT_GENERATED", details={"reviewer_import_id": import_id, "page_object_ids": page_ids, "render_mode": render_mode, "pdf_sha256": sha256_bytes(pdf), "bytes": len(pdf)})
    filename = f"blindsite_reviewer_import_{import_id}_pages_report.pdf"
    return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/reviewer/imports/{import_id}/pages/{object_id}/frame", response_class=HTMLResponse)
def reviewer_page_frame_route(request: Request, import_id: int, object_id: int, mode: str = "auto", remote_capture: str = "0") -> HTMLResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered page object not found")
    if obj.get("kind") != "page" and (obj.get("mime_type") or "").split(";", 1)[0].lower() not in {"text/html", "application/xhtml+xml"}:
        raise HTTPException(400, "Selected object is not a recovered page capture")
    mode = mode if mode in {"auto", "safe", "remote", "scripts"} else "auto"
    html_doc = reviewer_page_frame_html(import_id, obj, mode, capture_remote_assets=truthy(remote_capture) and mode == "scripts")
    log_event(user["username"], "REVIEWER_PAGE_FRAME_SERVED", details={"reviewer_import_id": import_id, "page_object_id": object_id, "mode": mode, "remote_capture": truthy(remote_capture) and mode == "scripts"})
    return HTMLResponse(html_doc, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Content-Security-Policy": reviewer_csp_for_mode(mode)})


@app.get("/reviewer/imports/{import_id}/viewer", response_class=HTMLResponse)
def reviewer_viewer(request: Request, import_id: int, kind: str = "all", q: str = "", obj: str = "", render: str = "safe", remote_capture: str = "0", starred: str = "", hashtag: str = "", exts: str = "", msg: str | None = None) -> HTMLResponse:
    if not reviewer_import_is_unlocked(request, import_id):
        return RedirectResponse(f"/reviewer/imports/{import_id}/unlock", 303)
    user, imp = require_reviewer_import_unlocked(request, import_id)
    if kind not in {"all", "pages", "snapshots", "images", "videos", "audio", "text", "other"}:
        kind = "all"
    if render not in {"auto", "safe", "remote", "scripts"}:
        render = get_setting("reviewer_default_render_mode", "auto")
        render = render if render in {"auto", "safe", "remote", "scripts"} else "auto"
    remote_capture_enabled = truthy(remote_capture) and render == "scripts"
    star_filter = truthy(starred)
    tag_filter = normalize_hashtags(hashtag)
    ext_filter_text = ",".join(extension_filter_list(exts))
    objects = reviewer_objects_filtered(import_id, kind, q, limit=1000, starred=star_filter, hashtag=tag_filter, exts=ext_filter_text)
    selected_id = int(obj) if str(obj).isdigit() else (int(objects[0]["id"]) if objects else 0)
    selected = reviewer_object_for(selected_id) if selected_id else None
    if selected and int(selected.get("import_id") or 0) != import_id:
        selected = None
    counts = {r["kind"]: r["c"] for r in fetchall("SELECT kind,count(*) c FROM reviewer_objects WHERE import_id=? GROUP BY kind", (import_id,))}
    common_qs = {"q": q, "render": render, "remote_capture": 1 if remote_capture_enabled else 0, "starred": starred, "hashtag": hashtag, "exts": ext_filter_text}
    filter_links = []
    for key, label in [("all", "all"), ("pages", "pages"), ("snapshots", "snapshots"), ("images", "images"), ("videos", "videos"), ("audio", "audio"), ("text", "text"), ("other", "other")]:
        total = sum(counts.values()) if key == "all" else sum(v for k, v in counts.items() if reviewer_filter_matches(k, key))
        qs = dict(common_qs); qs["kind"] = key
        filter_links.append(f"<a class='button {'good' if kind==key else 'secondary'}' href='/reviewer/imports/{import_id}/viewer?{h(urlencode(qs))}'>{h(label)} ({h(total)})</a>")
    return_to = "/reviewer/imports/%d/viewer?%s" % (import_id, urlencode({"kind": kind, "q": q, "obj": selected_id, "render": render, "remote_capture": 1 if remote_capture_enabled else 0, "starred": starred, "hashtag": hashtag, "exts": ext_filter_text}))
    obj_rows = []
    for r in objects:
        active = " style='background:#0f2f46'" if selected and int(r["id"]) == int(selected["id"]) else ""
        star = bool(r.get("starred"))
        tags = normalize_hashtags(r.get("hashtags") or "")
        label = extension_label_from_url_or_name(str(r.get('filename') or r.get('source_ref') or r.get('original_url') or ''), str(r.get('mime_type') or ''))
        qs = urlencode({"kind": kind, "q": q, "obj": r['id'], "render": render, "remote_capture": 1 if remote_capture_enabled else 0, "starred": starred, "hashtag": hashtag, "exts": ext_filter_text})
        row_return = "/reviewer/imports/%d/viewer?%s" % (import_id, urlencode({"kind": kind, "q": q, "obj": r["id"], "render": render, "remote_capture": 1 if remote_capture_enabled else 0, "starred": starred, "hashtag": hashtag, "exts": ext_filter_text}))
        star_form = f"<form method='post' action='/reviewer/imports/{import_id}/objects/{int(r['id'])}/star' style='display:inline'><input type='hidden' name='return_to' value='{h(row_return)}'><button class='secondary starbtn' title='Star/unstar recovered object'>{'★' if star else '☆'}</button></form>"
        tag_form = f"<form method='post' action='/reviewer/imports/{import_id}/objects/{int(r['id'])}/hashtags' class='tagline' style='margin-top:4px'><input type='hidden' name='return_to' value='{h(row_return)}'><input class='compact-input' name='hashtags' value='{h(tags)}' placeholder='#tag'><button class='secondary'>Save</button></form>"
        obj_rows.append(f"<tr{active}><td>{reviewer_object_thumb(import_id, r)}</td><td><a class='button good' href='/reviewer/imports/{import_id}/viewer?{h(qs)}'>View</a></td><td>{star_form}<br>{tag_form}</td><td>{badge(r['kind'],'info')} {badge(label,'info')}</td><td>{'★ ' if star else ''}{h(r['filename'])}<br><span class='small'>{hashtag_badges(tags)}</span></td><td>{h(reviewer_effective_mime_type(r))}</td><td>{h(r['size'])}</td><td>{badge('hash ok','good') if r['hash_ok'] else badge('hash mismatch','bad')}</td><td class='urlcell'>{h(r['source_ref'] or r['page_url'] or r['original_url'])}</td><td class='hashcell'><code>{h(r['sha256'])}</code></td></tr>")
    render_controls = ""
    panel = "<div class='viewer'><p class='muted'>No recovered object selected.</p></div>"
    if selected:
        safe_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=safe&starred={h(starred)}&hashtag={h(hashtag)}&exts={h(ext_filter_text)}"
        remote_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=remote&starred={h(starred)}&hashtag={h(hashtag)}&exts={h(ext_filter_text)}"
        scripts_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=scripts&starred={h(starred)}&hashtag={h(hashtag)}&exts={h(ext_filter_text)}"
        page_workspace = f" <a class='button good' href='/reviewer/imports/{import_id}/pages?page={selected['id']}&render={h(render)}'>Open in page viewer</a>" if selected.get("kind") == "page" else ""
        render_controls = f"<div class='card {'danger' if render=='scripts' else 'warn' if render=='remote' else 'safe'}'><h3>Reviewer render mode</h3><p>{badge('local safe view','good') if render=='safe' else badge('remote callbacks allowed','warn') if render=='remote' else badge('remote callbacks + scripts allowed','bad')}</p><p><a class='button good' href='{safe_url}'>Local safe view</a> <a class='button warn' href='{remote_url}'>Allow remote callbacks</a> <a class='button danger' href='{scripts_url}'>Allow remote callbacks + scripts</a> <a class='button {'danger' if remote_capture_enabled else 'secondary'}' href='{scripts_url}&remote_capture={0 if remote_capture_enabled else 1}'>Remote media capture: {'ON' if remote_capture_enabled else 'OFF'}</a>{page_workspace}</p><p class='small muted'>Local safe view is the default. It uses recovered local assets first and blocks scripts/forms/navigation/remote loads. Remote media capture stores media URLs discovered by dynamic scripts as supplemental reviewer objects.</p></div>"
        selected_playback = reviewer_playback_kind(selected)
        playback_obj = reviewer_best_playback_object(import_id, selected) if selected_playback == "video" else selected
        playback_note = ""
        if playback_obj is not selected and int(playback_obj.get("id") or 0) != int(selected.get("id") or 0):
            playback_note = f"<p class='small warn'>Selected object appears to be a tiny/fragment video, so the embedded player is using related recovered object #{h(playback_obj.get('id'))}: {h(playback_obj.get('filename') or '')}. The selected object itself is still available for download.</p>"
        selected_raw_url = f"/reviewer/imports/{import_id}/objects/{int(playback_obj['id'])}/raw?v={h(str(playback_obj.get('sha256') or '')[:12])}"
        selected_mime = reviewer_effective_mime_type(playback_obj)
        if selected_playback == "image":
            panel = f"<div class='viewer' style='min-height:420px'><img src='{selected_raw_url}' style='max-width:100%;max-height:82vh' alt='{h(selected.get('filename') or '')}'></div>"
        elif selected_playback == "video":
            panel = f"<div class='viewer' style='min-height:420px;display:block;text-align:center;padding:12px'><video controls preload='metadata' playsinline style='max-width:100%;max-height:82vh;background:#000' src='{selected_raw_url}'><source src='{selected_raw_url}' type='{h(selected_mime)}'>Your browser could not play this recovered video object.</video>{playback_note}<p class='small muted'>Served as {h(selected_mime)}. If this is still black/unplayable, the selected recovered object may be a fragment/manifest/audio track; use filters to choose a larger related MP4 or inspect the manifest.</p></div>"
        elif selected_playback == "audio":
            panel = f"<div class='viewer' style='min-height:220px'><audio controls preload='metadata' style='width:95%' src='{selected_raw_url}'><source src='{selected_raw_url}' type='{h(selected_mime)}'>Your browser could not play this recovered audio object.</audio></div>"
        else:
            sandbox = "allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-presentation allow-downloads allow-top-navigation-by-user-activation" if render == "scripts" else "allow-same-origin allow-forms allow-top-navigation-by-user-activation"
            frame_url = f"/reviewer/imports/{import_id}/objects/{selected['id']}/frame?mode={h(render)}&remote_capture={1 if remote_capture_enabled else 0}"
            panel = f"<iframe class='render-frame' sandbox='{sandbox}' src='{frame_url}'></iframe>"
        log_event(user["username"], "REVIEWER_OBJECT_VIEWED", details={"reviewer_import_id": import_id, "reviewer_object_id": selected["id"], "kind": selected.get("kind"), "render": render})
    manifest_pre = h(pretty(jloads(imp.get("manifest_json"), {}))[:22000])
    selected_meta = h(pretty(jloads(selected.get("meta_json"), {}))[:22000]) if selected else ""
    selected_info = ""
    if selected:
        selected_tags = normalize_hashtags(selected.get("hashtags") or "")
        selected_star = bool(selected.get("starred"))
        selected_info = f"""<div class='card'><h2>Selected object #{selected['id']}</h2><p>{badge(selected['kind'],'info')} {badge(reviewer_effective_mime_type(selected))} {badge('hash ok','good') if selected['hash_ok'] else badge('hash mismatch','bad')} {badge('starred','warn') if selected_star else ''} {hashtag_badges(selected_tags)}</p><p class='small muted'>Star and hashtag controls are in the Recovered objects table on the left.</p><table><tr><th>Filename</th><td>{h(selected['filename'])}</td></tr><tr><th>Source / URL</th><td class='urlcell'>{h(selected.get('source_ref') or selected.get('page_url') or selected.get('original_url') or '')}</td></tr><tr><th>SHA-256</th><td class='hashcell'><code>{h(selected['sha256'])}</code></td></tr><tr><th>Original package object</th><td>{h(selected['object_class'])} #{h(selected['original_id'])}</td></tr></table><p><a class='button' href='/reviewer/imports/{import_id}/objects/{selected['id']}/raw?download=1'>Download recovered object</a>{' <a class="button good" href="/reviewer/imports/'+str(import_id)+'/pages?page='+str(selected['id'])+'">Open captured-page viewer</a>' if selected.get('kind') == 'page' else ''}</p></div>{render_controls}<div class='card'><h2>Embedded viewer</h2>{panel}</div><div class='card'><h2>Object metadata</h2><pre>{selected_meta}</pre></div>"""
    protection_panel = reviewer_import_protection_panel(request, import_id, imp)
    body = f"""{flash(msg)}<div class='card safe'><h2>LE Case Viewer — import #{import_id}</h2><p>{badge(imp['status'],'good' if imp['status']=='imported' else 'warn')} {badge('objects '+str(imp['recovered_count']),'info')} {badge('case '+str(imp.get('case_id_original') or ''),'info') if imp.get('case_id_original') else ''} {reviewer_import_protection_badges(request, imp)}</p><p><a class='button good' href='/reviewer/imports/{import_id}/pages'>Open captured page viewer</a> <a class='button secondary' href='/reviewer/imports/{import_id}/viewer?kind=pages'>Filter page objects</a></p><table><tr><th>Package</th><td>{h(imp['package_name'])}</td></tr><tr><th>Case</th><td>{h(imp.get('case_name') or '')}</td></tr><tr><th>Package SHA-256</th><td class='hashcell'><code>{h(imp['package_sha256'])}</code></td></tr><tr><th>Escrow public-key fingerprint</th><td class='hashcell'><code>{h(imp.get('escrow_public_key_fingerprint') or '')}</code></td></tr></table></div>{protection_panel}<div class='card noprint'><h2>Browse recovered evidence</h2><p>{''.join(filter_links)}</p><form><input type='hidden' name='kind' value='{h(kind)}'><input type='hidden' name='render' value='{h(render)}'><input type='hidden' name='remote_capture' value='{1 if remote_capture_enabled else 0}'><div class='row'><div><label>Search filename, URL/source, hash, MIME, kind, or tag</label><input name='q' value='{h(q)}'></div><div><label>Hashtag</label><input name='hashtag' value='{h(tag_filter)}' placeholder='#priority'></div><div><label>Extensions / MIME tokens</label><input name='exts' value='{h(ext_filter_text)}' placeholder='mp4, jpg, webp'></div><div><label><input type='checkbox' name='starred' value='1' {'checked' if star_filter else ''}> Starred only</label><button>Search</button></div></div></form></div><div class='grid' style='grid-template-columns:minmax(500px,50%) minmax(480px,1fr)'><div class='card'><h2>Recovered objects</h2><div class='table-scroll'><table><tr><th>Thumb</th><th>Open</th><th>Star / tags</th><th>Kind</th><th>Filename</th><th>Type</th><th>Size</th><th>Hash</th><th>Source</th><th>SHA-256</th></tr>{''.join(obj_rows) or '<tr><td colspan="10" class="muted">No recovered objects match this filter.</td></tr>'}</table></div></div><div>{selected_info or '<div class="card"><p class="muted">Select an object to view it.</p></div>'}</div></div><div class='card'><h2>Sealed package manifest</h2><pre>{manifest_pre}</pre></div>"""
    return layout(request, f"LE Viewer Import #{import_id}", body)


@app.post("/reviewer/imports/{import_id}/objects/{object_id}/star")
def reviewer_object_star(request: Request, import_id: int, object_id: int, return_to: str = Form("")) -> RedirectResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Reviewer object not found")
    new_val = 0 if int(obj.get("starred") or 0) else 1
    execute("UPDATE reviewer_objects SET starred=? WHERE id=?", (new_val, object_id))
    log_event(user["username"], "REVIEWER_OBJECT_STAR_UPDATED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "starred": bool(new_val)})
    return RedirectResponse(return_to or f"/reviewer/imports/{import_id}/viewer?obj={object_id}", 303)


@app.post("/reviewer/imports/{import_id}/objects/{object_id}/hashtags")
def reviewer_object_hashtags(request: Request, import_id: int, object_id: int, hashtags: str = Form(""), return_to: str = Form("")) -> RedirectResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Reviewer object not found")
    tags = normalize_hashtags(hashtags)
    execute("UPDATE reviewer_objects SET hashtags=? WHERE id=?", (tags, object_id))
    log_event(user["username"], "REVIEWER_OBJECT_HASHTAGS_UPDATED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "hashtags": tags})
    return RedirectResponse(return_to or f"/reviewer/imports/{import_id}/viewer?obj={object_id}", 303)

def reviewer_supplemental_remote_media_exists(import_id: int, url: str) -> dict[str, Any] | None:
    uhash = sha256_text(url or "")
    rows = fetchall("SELECT * FROM reviewer_objects WHERE import_id=? AND (source_ref=? OR original_url=? OR meta_json LIKE ?) ORDER BY id DESC LIMIT 20", (import_id, url, url, f"%{uhash}%"))
    for r in rows:
        meta = jloads(r["meta_json"], {})
        if r.get("source_ref") == url or r.get("original_url") == url or meta.get("remote_url_sha256") == uhash:
            return dict(r)
    return None


def reviewer_store_supplemental_remote_media(import_id: int, url: str, data: bytes, mime_type: str, *, page_object_id: int = 0, page_url: str = "", reason: str = "dynamic-remote-media", response_headers: dict[str, Any] | None = None, status_code: int | None = None, final_url: str = "") -> int:
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    existing = reviewer_supplemental_remote_media_exists(import_id, url)
    if existing:
        return int(existing["id"])
    page_obj = reviewer_object_for(page_object_id) if page_object_id else None
    root_original_id = page_obj.get("original_id") if page_obj else None
    vault_rel = imp.get("vault_path") or ""
    vault_dir = data_path(vault_rel) if vault_rel else (REVIEW_DIR / f"import_{import_id}")
    supplemental_dir = vault_dir / "supplemental_remote_media"
    supplemental_dir.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(url)
    base_name = clean_filename(Path(parsed.path).name or f"remote_media_{sha256_text(url)[:12]}.bin")
    if "." not in base_name:
        base_name += mimetypes.guess_extension(mime_type) or ".bin"
    out_name = f"{sha256_text(url)[:12]}_{base_name}"
    out_path = supplemental_dir / out_name
    out_path.write_bytes(data)
    sha = sha256_bytes(data)
    kind = reviewer_kind_for(mime_type, out_name, {"source_type": "reviewer_remote_media_capture"}, "supplemental_remote")
    meta = {
        "reviewer_supplemental_remote_capture": True,
        "remote_url": url,
        "remote_url_sha256": sha256_text(url),
        "final_url": final_url or url,
        "page_object_id": page_object_id or None,
        "page_url": page_url,
        "reason": reason,
        "status_code": status_code,
        "response_headers": response_headers or {},
        "important_disclosure": "Supplemental reviewer-side remote media capture. This object was fetched during reviewer remote+scripts mode and was not part of the original sealed package unless separately exported later.",
    }
    oid = execute("""INSERT INTO reviewer_objects(import_id,object_class,original_id,filename,mime_type,kind,sha256,size,plaintext_path,zip_path,source_ref,page_url,original_url,root_original_id,resource_original_id,logical_sha256_expected,hash_ok,meta_json,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (import_id, "supplemental_remote", None, out_name, mime_type, kind, sha, len(data), relative(out_path), "", url, page_url, url, root_original_id, None, sha, 1, pretty(meta), utcnow()))
    execute("UPDATE reviewer_imports SET recovered_count=(SELECT COUNT(*) FROM reviewer_objects WHERE import_id=?) WHERE id=?", (import_id, import_id))
    return int(oid)


@app.post("/reviewer/imports/{import_id}/remote-media-capture")
async def reviewer_remote_media_capture(request: Request, import_id: int) -> JSONResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    url = str(payload.get("url") or "").strip()
    page_object_id = int(payload.get("page_object_id") or 0)
    page_url = str(payload.get("page_url") or "").strip()
    reason = str(payload.get("reason") or "dynamic-remote-media").strip()[:200]
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return JSONResponse({"ok": False, "error": "not an absolute http/https URL"}, status_code=400)
    existing = reviewer_supplemental_remote_media_exists(import_id, url)
    if existing:
        return JSONResponse({"ok": True, "duplicate": True, "reviewer_object_id": existing.get("id"), "url_sha256": sha256_text(url)})
    max_bytes = 250 * 1024 * 1024
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "Accept": "video/*,audio/*,image/*,application/dash+xml,application/vnd.apple.mpegurl,application/x-mpegURL,application/octet-stream,*/*;q=0.6", "Accept-Language": "en-US,en;q=0.9"}
    if page_url:
        headers["Referer"] = page_url
    try:
        r = requests.get(url, headers=headers, timeout=30, stream=True)
        r.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                return JSONResponse({"ok": False, "error": "remote media exceeded reviewer capture size limit", "limit": max_bytes}, status_code=413)
            chunks.append(chunk)
        data = b"".join(chunks)
        if not data:
            return JSONResponse({"ok": False, "error": "empty response"}, status_code=502)
        ctype = (r.headers.get("Content-Type") or mimetypes.guess_type(parsed.path)[0] or "application/octet-stream").split(";", 1)[0].strip() or "application/octet-stream"
        if not (ctype.startswith(("image/", "video/", "audio/")) or ctype in {"application/dash+xml", "application/vnd.apple.mpegurl", "application/x-mpegurl", "application/mp4", "application/octet-stream"}):
            return JSONResponse({"ok": False, "error": "not a media response", "content_type": ctype}, status_code=415)
        oid = reviewer_store_supplemental_remote_media(import_id, url, data, ctype, page_object_id=page_object_id, page_url=page_url, reason=reason, response_headers=dict(r.headers), status_code=r.status_code, final_url=r.url)
        log_event(user["username"], "REVIEWER_SUPPLEMENTAL_REMOTE_MEDIA_CAPTURED", details={"reviewer_import_id": import_id, "reviewer_object_id": oid, "page_object_id": page_object_id, "url_sha256": sha256_text(url), "content_type": ctype, "bytes": len(data)})
        return JSONResponse({"ok": True, "reviewer_object_id": oid, "sha256": sha256_bytes(data), "bytes": len(data), "mime_type": ctype})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)[:500], "url_sha256": sha256_text(url)}, status_code=502)


@app.get("/reviewer/imports/{import_id}/remote-proxy")
def reviewer_remote_proxy(request: Request, import_id: int, url: str, persist: str = "0", source_object_id: str = "", page_url: str = "") -> Response:
    """Explicit reviewer scripts-mode same-origin proxy for dynamic site assets.

    This is only used by reviewer pages when a cleared reviewer chooses
    "Allow remote callbacks + scripts". It helps module scripts from sites like
    Reddit load in the local reviewer origin without CORS/module-source failures.
    Safe/local reviewer modes do not use this route.
    """
    user, imp = require_reviewer_import_unlocked(request, import_id)
    remote = str(url or "").strip()
    parsed = urlparse(remote)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(400, "Only absolute http/https URLs may be proxied")
    # Keep this bounded. It is for scripts/CSS/player assets, not bulk evidence
    # acquisition. Media preservation remains handled by the sealed vault path.
    max_bytes = (250 * 1024 * 1024) if truthy(persist) else (25 * 1024 * 1024)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/javascript,text/javascript,text/css,application/json,text/plain,image/*,video/*,audio/*,font/*,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if page_url:
            headers["Referer"] = page_url
        r = requests.get(remote, headers=headers, timeout=20, stream=True)
        r.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(413, "Remote proxied asset exceeded size limit")
            chunks.append(chunk)
        data = b"".join(chunks)
        ctype = (r.headers.get("Content-Type") or mimetypes.guess_type(parsed.path)[0] or "application/octet-stream").split(";", 1)[0]
        if parsed.path.lower().endswith((".js", ".mjs")) or "redditstatic.com/js/concat" in remote.lower() or "redditstatic.com/shreddit/" in remote.lower():
            ctype = "application/javascript"
        stored_oid = None
        if truthy(persist) and (ctype.startswith(("image/", "video/", "audio/")) or ctype in {"application/dash+xml", "application/vnd.apple.mpegurl", "application/x-mpegurl", "application/mp4", "application/octet-stream"}):
            try:
                stored_oid = reviewer_store_supplemental_remote_media(import_id, remote, data, ctype, page_object_id=int(source_object_id or 0), page_url=page_url, reason="remote-proxy-persist", response_headers=dict(r.headers), status_code=r.status_code, final_url=r.url)
            except Exception:
                stored_oid = None
        log_event(user["username"], "REVIEWER_REMOTE_PROXY_FETCH", details={"reviewer_import_id": import_id, "url_sha256": sha256_text(remote), "host": parsed.netloc, "content_type": ctype, "bytes": len(data), "persist": truthy(persist), "stored_reviewer_object_id": stored_oid})
        return Response(data, media_type=ctype, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Access-Control-Allow-Origin": "*"})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Remote proxy fetch failed: {str(exc)[:300]}")


@app.get("/reviewer/imports/{import_id}/objects/{object_id}/raw")
def reviewer_object_raw(request: Request, import_id: int, object_id: int, download: str | None = None) -> Response:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered object not found")
    data = read_reviewer_object(obj)
    headers = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}
    if download:
        headers["Content-Disposition"] = f"attachment; filename={clean_filename(obj.get('filename') or 'recovered_object.bin')}"
    log_event(user["username"], "REVIEWER_OBJECT_RAW_SERVED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "download": bool(download)})
    return response_with_optional_range(request, data, reviewer_effective_mime_type(obj), filename=obj.get("filename") or "recovered_object.bin", download=bool(download))


@app.get("/reviewer/imports/{import_id}/objects/{object_id}/frame", response_class=HTMLResponse)
def reviewer_object_frame(request: Request, import_id: int, object_id: int, mode: str = "safe", remote_capture: str = "0") -> HTMLResponse:
    user, imp = require_reviewer_import_unlocked(request, import_id)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered object not found")
    mode = mode if mode in {"safe", "remote", "scripts"} else "safe"
    html_doc = reviewer_object_frame_html(import_id, obj, mode, capture_remote_assets=truthy(remote_capture) and mode == "scripts")
    log_event(user["username"], "REVIEWER_OBJECT_FRAME_SERVED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "mode": mode, "remote_capture": truthy(remote_capture) and mode == "scripts"})
    csp = reviewer_csp_for_mode(mode) if (obj.get("mime_type") or "").split(";",1)[0].lower() in {"text/html", "application/xhtml+xml"} or obj.get("kind") == "page" else "default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; script-src 'none'; connect-src 'none'"
    return HTMLResponse(html_doc, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Content-Security-Policy": csp})


@app.get("/custody", response_class=HTMLResponse)
def custody_page(request: Request) -> HTMLResponse:
    require_user(request)
    fp = get_setting("escrow_public_key_fingerprint", "")
    cases = fetchall("SELECT id,name,mode FROM cases ORDER BY id DESC LIMIT 100")
    rows = "".join(f"<tr><td><a href='/cases/{c['id']}'>#{c['id']}</a></td><td>{h(c['name'])}</td><td>{h(c['mode'])}</td><td><a class='button good' href='/cases/{c['id']}/sealed-export'>Sealed LE export</a></td></tr>" for c in cases)
    body = f"""<div class='card'><h2>Custody / master key mode</h2><p>{badge(custody_label(),'info')} {badge('local reveal blocked','good') if civilian_unknown_master_mode() else badge('organization controlled','warn')}</p><p><b>Escrow public-key fingerprint:</b> <code>{h(fp or 'not configured')}</code></p><p>Civilian Unknown Master Key mode means the local user did not create or know the master reveal key. Use sealed exports to hand off encrypted evidence and records without plaintext originals.</p></div><div class='card'><h2>Case sealed handoff packages</h2><table><tr><th>ID</th><th>Case</th><th>Mode</th><th>Export</th></tr>{rows or '<tr><td colspan="4" class="muted">No cases yet.</td></tr>'}</table></div>"""
    return layout(request, "Custody", body)

@app.get("/cases/{case_id}/report.zip")
def case_report_zip(request: Request, case_id: int) -> StreamingResponse:
    require_user(request)
    data = report_data(case_id)
    if not data["case"]:
        raise HTTPException(404, "Case not found")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.json", pretty(data))
        z.writestr("integrity/application_genesis.json", pretty(data.get("application_genesis") or {}))
        z.writestr("case_report.html", build_case_report_html(data))
        z.writestr("saved_pages/index.html", build_case_saved_pages_index(case_id, data))
        z.writestr("media/index.html", build_case_media_index(data))
        csv_buf = io.StringIO()
        w = csv.writer(csv_buf)
        w.writerow(["section", "id", "field1", "field2", "field3", "field4"])
        for e in data["evidence"]:
            w.writerow(["evidence", e["id"], e["filename"], e["kind"], e["sha256"], e["storage_mode"]])
        for c in data.get("page_captures", []):
            w.writerow(["saved_page", c["evidence_id"], c.get("title"), c.get("capture_mode"), c.get("page_url_sha256"), c.get("page_url")])
        for b in data["blocked_media"]:
            w.writerow(["blocked_media", b["id"], b["resource_type"], b["url_sha256"], b["metadata_record_hash"], b["downloaded"]])
        z.writestr("report.csv", csv_buf.getvalue())
        for c in data.get("page_captures", []):
            try:
                ev = evidence_for(int(c["evidence_id"]))
                if ev:
                    model = saved_capture_model(ev)
                    z.writestr(f"saved_pages/evidence_{ev['id']}.html", saved_capture_frame_html(ev, model, for_export=True))
                    z.writestr(f"saved_pages/metadata/evidence_{ev['id']}.json", pretty({"page_capture": c, "model_metadata": model.get("metadata"), "evidence": ev}))
            except Exception as exc:
                z.writestr(f"saved_pages/errors/evidence_{c.get('evidence_id','unknown')}.txt", str(exc))
        z.writestr("README.txt", "Report-only bundle. No original evidence/media bytes are included. Open case_report.html first. Saved page viewers are in saved_pages/. They are safe reconstructed viewers and do not fetch remote resources. See integrity/application_genesis.json for the Application Genesis Hash / Executable Genesis Seal.\n")
    log_event(current_user(request)["username"], "CASE_REPORT_ZIP_EXPORTED", case_id=case_id, details={"report_only": True})
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f"attachment; filename=case_{case_id}_report_only.zip"})


@app.post("/cases/{case_id}/viewer.zip")
def case_viewer_zip(request: Request, case_id: int, include_assets: str | None = Form(None), master_key: str = Form("")) -> StreamingResponse:
    user = require_user(request)
    case = case_for(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    want_assets = bool(include_assets)
    if want_assets:
        if lockdown() or case_safe(case) or case.get("no_plaintext_export"):
            raise HTTPException(403, "Current case/global policy blocks export of viewable saved assets")
        if setting_bool("require_approval_plaintext_export", "1") and not is_admin(user) and not approval_exists("plaintext_export", case_id, None, None):
            raise HTTPException(403, "Offline viewer ZIP with assets requires plaintext-export approval")
        if not verify_master_key(master_key):
            raise HTTPException(403, "Master reveal key required to export viewable saved assets")
    data = report_data(case_id)
    captures = data.get("page_captures", [])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", (
            "BlindSite offline case viewer. Open index.html first.\n"
            "If include_assets=false, viewers are safe summaries and contain no original media bytes.\n"
            "If include_assets=true, saved local assets captured under lab/full-forensic policy are included and rendered offline.\n"
            "No page viewer in this bundle contacts the live site.\n"
        ))
        z.writestr("report.json", pretty(data))
        rows = []
        for c in captures:
            try:
                ev = evidence_for(int(c["evidence_id"]))
                if not ev:
                    continue
                model = saved_capture_model(ev)
                asset_count = 0
                if want_assets and ev.get("raw_persisted"):
                    asset_prefix = f"assets/evidence_{ev['id']}"
                    for asset in captured_assets_for_model(ev, model):
                        aid = int(asset["resource_evidence_id"])
                        asset_ev = evidence_for(aid)
                        if not asset_ev:
                            continue
                        fname = clean_filename(str(asset_ev.get("filename") or f"asset_{aid}.bin"))
                        z.writestr(f"saved_pages/{asset_prefix}/asset_{aid}_{fname}", read_evidence(aid))
                        asset_count += 1
                    html_doc = rendered_capture_html(ev, model, for_export=True, export_asset_prefix=asset_prefix)
                    renderer = "exact-local-assets"
                else:
                    html_doc = saved_capture_frame_html(ev, model, for_export=True)
                    renderer = "safe-summary"
                page_name = f"saved_pages/evidence_{ev['id']}.html"
                z.writestr(page_name, html_doc)
                z.writestr(f"saved_pages/metadata/evidence_{ev['id']}.json", pretty({"page_capture": c, "model_metadata": model.get("metadata"), "evidence": ev, "renderer": renderer, "asset_count": asset_count}))
                rows.append(f"<tr><td><a href='{h(page_name)}'>{h(model.get('title') or ev.get('filename') or 'Saved page')}</a></td><td>{h(renderer)}</td><td>{h(asset_count)}</td><td>{h(c.get('capture_mode'))}</td><td>{h(c.get('page_url'))}</td><td><code>{h(ev.get('sha256'))}</code></td></tr>")
            except Exception as exc:
                z.writestr(f"saved_pages/errors/evidence_{c.get('evidence_id','unknown')}.txt", str(exc))
        index = f"""<!doctype html><html><head><meta charset='utf-8'><title>BlindSite case {h(case_id)} offline viewer</title><style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;vertical-align:top}}code{{word-break:break-all}}.muted{{color:#666}}</style></head><body><h1>BlindSite offline case viewer</h1><h2>{h(case.get('name',''))}</h2><p class='muted'>Generated {h(utcnow())}. Include saved assets: {h(want_assets)}. All viewers use local files only and do not contact the live site.</p><table><tr><th>Saved page</th><th>Renderer</th><th>Saved assets</th><th>Capture mode</th><th>Source URL</th><th>Evidence SHA-256</th></tr>{''.join(rows) or '<tr><td colspan="6">No saved pages.</td></tr>'}</table></body></html>"""
        z.writestr("index.html", index)
    log_event(user["username"], "CASE_VIEWER_ZIP_EXPORTED", case_id=case_id, details={"include_assets": want_assets, "page_count": len(captures)})
    buf.seek(0)
    suffix = "with_assets" if want_assets else "safe"
    return StreamingResponse(buf, media_type="application/zip", headers={"Content-Disposition": f"attachment; filename=case_{case_id}_offline_viewer_{suffix}.zip"})


@app.post("/tor/prewarm")
def tor_prewarm_route(request: Request, return_to: str = Form("/settings")) -> RedirectResponse:
    user = require_user(request)
    if user.get("role") not in {"admin", "supervisor"}:
        raise HTTPException(403, "Only admins/supervisors can start Tor prewarm")
    status = tor_prewarm_background("manual")
    log_event(user["username"], "TOR_BACKGROUND_PREWARM_REQUESTED", details=status)
    return RedirectResponse(return_to + ("&" if "?" in return_to else "?") + "msg=Tor%20background%20prewarm%20started", 303)

@app.post("/tor/prewarm-json")
def tor_prewarm_json_route(request: Request) -> JSONResponse:
    user = require_user(request)
    if user.get("role") not in {"admin", "supervisor"}:
        raise HTTPException(403, "Only admins/supervisors can start Tor prewarm")
    status = tor_prewarm_background("manual-json")
    log_event(user["username"], "TOR_BACKGROUND_PREWARM_REQUESTED", details=status)
    return JSONResponse({"ok": True, "status": tor_prewarm_status()})

@app.get("/tor/prewarm-status")
def tor_prewarm_status_route(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(tor_prewarm_status())


@app.post("/tor/restart-json")
def tor_restart_json_route(request: Request) -> JSONResponse:
    user = require_user(request)
    if user.get("role") not in {"admin", "supervisor"}:
        raise HTTPException(403, "Only admins/supervisors can restart Tor")
    stopped = stop_managed_tor("manual-restart")
    status = tor_prewarm_background("manual-restart")
    log_event(user["username"], "TOR_BACKGROUND_RESTART_REQUESTED", details={"stopped": stopped, "status": status})
    return JSONResponse({"ok": True, "stopped": stopped, "status": tor_prewarm_status()})


@app.post("/tor/stop-json")
def tor_stop_json_route(request: Request) -> JSONResponse:
    user = require_user(request)
    if user.get("role") not in {"admin", "supervisor"}:
        raise HTTPException(403, "Only admins/supervisors can stop Tor")
    result = stop_managed_tor("manual-stop")
    with TOR_PREWARM_LOCK:
        TOR_PREWARM_STATUS.update({"running": False, "ok": False, "message": result.get("message", "Tor stopped"), "updated_at": utcnow(), "reason": "manual-stop", "diagnostics": tor_diagnostics(), "log_tail": tor_log_tail(3500)})
    log_event(user["username"], "TOR_BACKGROUND_STOP_REQUESTED", details=result)
    return JSONResponse({"ok": bool(result.get("ok")), "result": result, "status": tor_prewarm_status()})


@app.get("/tor/diagnostics")
def tor_diagnostics_route(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(tor_diagnostics())

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, msg: str | None = None) -> HTMLResponse:
    user = require_admin(request)
    s = all_settings()
    users = fetchall("SELECT * FROM users ORDER BY username")
    user_rows = "".join(f"<tr><td>{h(r['username'])}</td><td>{h(r['role'])}</td><td>{h(r['image_policy'])}</td><td>{'yes' if r['require_master_key'] else 'no'}</td><td>{'yes' if r['require_approval'] else 'no'}</td><td>{'yes' if r['require_webauthn'] else 'no'}</td></tr>" for r in users)
    def opt(name: str, value: str, label: str | None = None) -> str:
        return f"<option value='{h(value)}' {'selected' if s.get(name)==value else ''}>{h(label or value)}</option>"
    sealed_mime_allowlist = h(s.get("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream"))
    body = f"""{flash(msg)}<div class='card'><h2>Global safety profile</h2><form method='post' action='/settings' data-webauthn-action='admin_settings'>
      <div class='row'><div><label>Edition</label><select name='edition'>{opt('edition','lockdown','Lockdown / compliance-safe')}{opt('edition','supervised','Supervised approval')}{opt('edition','lab','Lab/full-forensic')}</select></div><div><label>Default capture mode</label><select name='default_capture_mode'>{''.join(f'<option value="{m}" {"selected" if s.get("default_capture_mode")==m else ""}>{m}</option>' for m in CAPTURE_MODES)}</select></div><div><label>Default media policy</label><select name='default_media_policy'>{''.join(f'<option value="{m}" {"selected" if s.get("default_media_policy")==m else ""}>{m}</option>' for m in MEDIA_POLICIES)}</select></div></div><div class='row'><div><label>Default user agent profile</label><select name='default_user_agent_profile'>{ua_select_html('default_user_agent_profile', s.get('default_user_agent_profile','chrome_windows'))}</select></div><div><label>Custom user agent default</label><input name='custom_user_agent' value='{h(s.get('custom_user_agent',''))}' placeholder='Only used when profile is Custom'></div></div>
      <label><input type='checkbox' name='hard_default_safe_mode' value='1' {'checked' if truthy(s.get('hard_default_safe_mode')) else ''}> Hard default safe mode</label>
      <label><input type='checkbox' name='disable_full_reveal_in_lockdown' value='1' {'checked' if truthy(s.get('disable_full_reveal_in_lockdown')) else ''}> Lockdown: disable full reveal</label>
      <label><input type='checkbox' name='disable_plaintext_export_in_lockdown' value='1' {'checked' if truthy(s.get('disable_plaintext_export_in_lockdown')) else ''}> Lockdown: disable plaintext export</label>
      <label><input type='checkbox' name='disable_materialization_in_lockdown' value='1' {'checked' if truthy(s.get('disable_materialization_in_lockdown')) else ''}> Lockdown: disable blocked-media materialization</label>
      <label><input type='checkbox' name='allow_blur_in_lockdown' value='1' {'checked' if truthy(s.get('allow_blur_in_lockdown')) else ''}> Allow blurred previews in lockdown</label>
      <label><input type='checkbox' name='require_master_key_full_reveal' value='1' {'checked' if truthy(s.get('require_master_key_full_reveal')) else ''}> Require master key for full reveal</label>
      <label><input type='checkbox' name='require_approval_full_reveal' value='1' {'checked' if truthy(s.get('require_approval_full_reveal')) else ''}> Require approval for full reveal for non-admins</label>
      <label><input type='checkbox' name='require_approval_plaintext_export' value='1' {'checked' if truthy(s.get('require_approval_plaintext_export')) else ''}> Require approval for plaintext export</label>
      <label><input type='checkbox' name='require_approval_materialization' value='1' {'checked' if truthy(s.get('require_approval_materialization')) else ''}> Require approval for blocked original materialization</label>
      <label><input type='checkbox' name='live_javascript_enabled' value='1' {'checked' if truthy(s.get('live_javascript_enabled')) else ''}> Live browser: JavaScript enabled</label>
      <label><input type='checkbox' name='live_download_allowed_media_default' value='1' {'checked' if truthy(s.get('live_download_allowed_media_default')) else ''}> Live browser: check “save allowed media for exact renderer” by default</label>
      <label><input type='checkbox' name='live_auto_capture_default' value='1' {'checked' if truthy(s.get('live_auto_capture_default','0')) else ''}> Live browser: check “auto-capture each new settled page” by default</label>
      <label><input type='checkbox' name='live_allow_captcha_challenge_media_default' value='1' {'checked' if truthy(s.get('live_allow_captcha_challenge_media_default','0')) else ''}> Live browser: check “allow only CAPTCHA/challenge images, including inline/base64 data images, while media remains blocked” by default</label>
      <label><input type='checkbox' name='capture_settle_before_save' value='1' {'checked' if truthy(s.get('capture_settle_before_save','1')) else ''}> Capture: wait/settle before saving manual and auto captures</label>
      <label><input type='checkbox' name='capture_auto_scroll_enabled' value='1' {'checked' if truthy(s.get('capture_auto_scroll_enabled','0')) else ''}> Capture: auto-scroll before saving to trigger lazy-loaded content</label>
      <div class='row'><div><label>Capture wait after load (ms)</label><input name='capture_wait_after_load_ms' value='{h(s.get('capture_wait_after_load_ms','5000'))}'></div><div><label>Capture network-idle timeout (ms)</label><input name='capture_network_idle_timeout_ms' value='{h(s.get('capture_network_idle_timeout_ms','20000'))}'></div><div><label>Capture total settle timeout (ms)</label><input name='capture_settle_timeout_ms' value='{h(s.get('capture_settle_timeout_ms','30000'))}'></div></div>
      <div class='row'><div><label>Auto-scroll max steps</label><input name='capture_auto_scroll_max_steps' value='{h(s.get('capture_auto_scroll_max_steps','30'))}'></div><div><label>Auto-scroll pause (ms)</label><input name='capture_auto_scroll_pause_ms' value='{h(s.get('capture_auto_scroll_pause_ms','550'))}'></div><div><label>Stable rounds before save</label><input name='capture_stable_rounds' value='{h(s.get('capture_stable_rounds','3'))}'></div></div>
      <div class='row'><div><label>Initial navigation timeout (ms)</label><input name='live_initial_navigation_timeout_ms' value='{h(s.get('live_initial_navigation_timeout_ms','60000'))}'></div><div><label>Auto-capture delay after navigation (ms)</label><input name='live_auto_capture_delay_ms' value='{h(s.get('live_auto_capture_delay_ms','2500'))}'></div><div><label>Reviewer default render mode</label><select name='reviewer_default_render_mode'><option value='auto' {'selected' if s.get('reviewer_default_render_mode','auto')=='auto' else ''}>auto / best available</option><option value='safe' {'selected' if s.get('reviewer_default_render_mode','auto')=='safe' else ''}>safe local only</option><option value='remote' {'selected' if s.get('reviewer_default_render_mode','auto')=='remote' else ''}>allow remote callbacks</option><option value='scripts' {'selected' if s.get('reviewer_default_render_mode','auto')=='scripts' else ''}>allow remote + scripts</option></select></div></div>
      <div class='row'><div><label>LE reviewer import unlock timeout (seconds)</label><input name='reviewer_import_unlock_timeout_seconds' value='{h(s.get('reviewer_import_unlock_timeout_seconds','900'))}'><p class='small muted'>Default 900 seconds. Use 0 to disable inactivity locking for imported reviewer cases.</p></div></div>
      <div class='card warn'><h3>LE PDF report generator</h3><p class='small muted'>Timeout/layout settings for reviewer page screenshot PDF reports. Raising timeouts helps slow dynamic pages. Standard PDF page sizing prevents screenshots from producing oversized/cut-off PDF pages.</p><div class='row'><div><label>Navigation timeout (ms)</label><input name='pdf_report_navigation_timeout_ms' value='{h(s.get('pdf_report_navigation_timeout_ms','60000'))}'></div><div><label>DOM loaded timeout (ms)</label><input name='pdf_report_domcontentloaded_timeout_ms' value='{h(s.get('pdf_report_domcontentloaded_timeout_ms','20000'))}'></div><div><label>Dynamic/scripts wait (ms)</label><input name='pdf_report_scripts_wait_ms' value='{h(s.get('pdf_report_scripts_wait_ms','12000'))}'></div></div><div class='row'><div><label>Safe render wait (ms)</label><input name='pdf_report_safe_wait_ms' value='{h(s.get('pdf_report_safe_wait_ms','3000'))}'></div><div><label>Screenshot timeout (ms)</label><input name='pdf_report_screenshot_timeout_ms' value='{h(s.get('pdf_report_screenshot_timeout_ms','30000'))}'></div><div><label>Fallback timeout (ms)</label><input name='pdf_report_fallback_timeout_ms' value='{h(s.get('pdf_report_fallback_timeout_ms','30000'))}'></div></div><div class='row'><div><label><input type='checkbox' name='pdf_report_full_width_capture' value='1' {'checked' if truthy(s.get('pdf_report_full_width_capture','1')) else ''}> Capture full document width to prevent right-side clipping</label></div><div><label>Max capture width px</label><input name='pdf_report_max_capture_width' value='{h(s.get('pdf_report_max_capture_width','2400'))}'></div><div><label>Max capture height px</label><input name='pdf_report_max_capture_height' value='{h(s.get('pdf_report_max_capture_height','24000'))}'></div></div><div class='row'><div><label>PDF page width px</label><input name='pdf_report_pdf_page_width_px' value='{h(s.get('pdf_report_pdf_page_width_px','1224'))}'><p class='small muted'>1224 px = 8.5 inches at 144 DPI.</p></div><div><label>PDF page height px</label><input name='pdf_report_pdf_page_height_px' value='{h(s.get('pdf_report_pdf_page_height_px','1584'))}'><p class='small muted'>1584 px = 11 inches at 144 DPI.</p></div><div><label>PDF margin px</label><input name='pdf_report_pdf_margin_px' value='{h(s.get('pdf_report_pdf_margin_px','36'))}'></div><div><label>Page split overlap px</label><input name='pdf_report_split_overlap_px' value='{h(s.get('pdf_report_split_overlap_px','24'))}'></div></div></div>
      <label><input type='checkbox' name='reviewer_enabled' value='1' {'checked' if truthy(s.get('reviewer_enabled','1')) else ''}> Enable law-enforcement / cleared reviewer import and viewer area</label>
      <label><input type='checkbox' name='sealed_export_enabled' value='1' {'checked' if truthy(s.get('sealed_export_enabled','1')) else ''}> Enable sealed encrypted law-enforcement evidence export</label>
      <label><input type='checkbox' name='sealed_export_include_derived' value='1' {'checked' if truthy(s.get('sealed_export_include_derived','1')) else ''}> Sealed export includes encrypted derived artifacts/snapshots when available</label>
      <div class='card warn'><h3>Sealed Sender / Sealed Media Preservation Mode</h3><p class='small muted'>Works in both Organization-Controlled Key and Civilian Unknown Master Key modes. Blocked images/video/audio remain invisible in the live browser, but selected blocked media can be stored encrypted for sealed reviewer / law-enforcement access. Organization mode can use normal local vault encryption or optional hard-sealed reviewer-key storage; civilian mode local reveal remains blocked. This is a technical custody control, not legal advice or a guarantee of legal protection.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' {'checked' if truthy(s.get('sealed_media_preservation_enabled','1')) else ''}> Enable Sealed Sender / file downloads globally</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' {'checked' if truthy(s.get('sealed_media_preserve_images','1')) else ''}> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' {'checked' if truthy(s.get('sealed_media_preserve_video','1')) else ''}> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' {'checked' if truthy(s.get('sealed_media_preserve_audio','1')) else ''}> Preserve blocked audio encrypted</label><div class='row'><div><label>Preservation mode</label><select name='sealed_media_preserve_mode'><option value='fast' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='fast' else ''}>fast / least page slowdown</option><option value='balanced' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='balanced' else ''}>balanced / default</option><option value='complete' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='complete' else ''}>complete / try harder</option></select></div><div><label>Route fetch timeout (ms)</label><input name='sealed_media_preserve_fetch_timeout_ms' value='{h(s.get('sealed_media_preserve_fetch_timeout_ms','3500'))}'></div><div><label>Background timeout (ms)</label><input name='sealed_media_preserve_background_timeout_ms' value='{h(s.get('sealed_media_preserve_background_timeout_ms','18000'))}'></div></div><div class='row'><div><label>Max bytes per preserved object</label><input name='sealed_media_preserve_max_bytes' value='{h(s.get('sealed_media_preserve_max_bytes','52428800'))}'></div><div><label>Max total bytes per live session</label><input name='sealed_media_preserve_max_total_bytes' value='{h(s.get('sealed_media_preserve_max_total_bytes','209715200'))}'></div><div><label>Max preserved items per live session</label><input name='sealed_media_preserve_max_items_per_session' value='{h(s.get('sealed_media_preserve_max_items_per_session','2500'))}'></div><div><label>Max pending background tasks</label><input name='sealed_media_preserve_max_pending_tasks' value='{h(s.get('sealed_media_preserve_max_pending_tasks','75'))}'><p class='small muted'>Default is 75. Raise to 128 if you still see queue full on very media-heavy sites.</p></div></div><label><input type='checkbox' name='sealed_media_preserve_skip_decorative_fast' value='1' {'checked' if truthy(s.get('sealed_media_preserve_skip_decorative_fast','1')) else ''}> Fast mode: skip/deprioritize decorative logo/favicon/badge assets so they do not slow page loading</label><label>MIME allowlist, one prefix/type per line</label><textarea name='sealed_media_preserve_mime_allowlist'>{sealed_mime_allowlist}</textarea><div class='card warn'><h3>Organization hard-sealed preserved media</h3><p class='small muted'>Organization mode only. When enabled, preserved blocked media is encrypted to this organization/reviewer public key at capture time. The local vault key cannot decrypt those preserved media originals; reviewer import requires the matching private key.</p><label><input type='checkbox' name='organization_hard_seal_media_enabled' value='1' {'checked' if truthy(s.get('organization_hard_seal_media_enabled','0')) else ''}> Hard-seal preserved blocked media to organization escrow public key</label><label>Organization escrow public key PEM</label><textarea name='organization_hard_seal_public_key_pem' rows='8' placeholder='Paste organization/reviewer escrow_public_key.pem here'>{h(s.get('organization_hard_seal_public_key_pem',''))}</textarea><p class='small muted'>Current fingerprint: <code>{h(s.get('organization_hard_seal_public_key_fingerprint','') or 'not configured')}</code></p></div></div>
      <label><input type='checkbox' name='head_probe_blocked_media' value='1' {'checked' if truthy(s.get('head_probe_blocked_media')) else ''}> HEAD probe blocked media for headers without body download</label>
      <label><input type='checkbox' name='reject_inline_media_in_safe_mode' value='1' {'checked' if truthy(s.get('reject_inline_media_in_safe_mode')) else ''}> Safe mode: minimize/reject inline embedded media summaries</label>
      <div class='row'><div><label>Max root read bytes</label><input name='max_root_read_bytes' value='{h(s.get('max_root_read_bytes','524288'))}'></div><div><label>Max summary chars</label><input name='max_text_summary_chars' value='{h(s.get('max_text_summary_chars','20000'))}'></div><div><label>Max blocked records</label><input name='max_blocked_records' value='{h(s.get('max_blocked_records','1000'))}'></div></div>
      <div class='row'><div><label>Snapshot max media bytes per file</label><input name='snapshot_max_media_bytes' value='{h(s.get('snapshot_max_media_bytes','52428800'))}'></div><div><label>Snapshot max media items per capture</label><input name='snapshot_max_media_items' value='{h(s.get('snapshot_max_media_items','250'))}'></div><div><label>Snapshot max total bytes per live session</label><input name='snapshot_max_total_asset_bytes' value='{h(s.get('snapshot_max_total_asset_bytes','209715200'))}'></div></div>
      <label>Safe allowlist domains, one per line</label><textarea name='safe_allowlist_domains'>{h(s.get('safe_allowlist_domains',''))}</textarea>
      <label>Capture denylist domains, one per line</label><textarea name='capture_denylist_domains'>{h(s.get('capture_denylist_domains',''))}</textarea>
      <h3>Tor</h3><div class='card'><h3>Tor / One-Click managed Tor</h3><p>{tor_browser_status_html()}</p><label>Default live browser</label><select name='live_browser_default'>{browser_select_html('live_browser_default', s.get('live_browser_default','chromium'))}</select><label>Tor Browser path</label><input name='tor_browser_path' value='{h(s.get('tor_browser_path',''))}' placeholder='C:/Users/you/Desktop/Tor Browser/Browser/firefox.exe'><label>Bundled/standalone tor executable path</label><input name='tor_executable_path' value='{h(s.get('tor_executable_path',''))}' placeholder='Optional: .../TorBrowser/Tor/tor.exe'><label><input type='checkbox' name='tor_auto_start_from_browser_bundle' value='1' {'checked' if truthy(s.get('tor_auto_start_from_browser_bundle','1')) else ''}> One-click Tor: auto-start bundled tor.exe if SOCKS is not already open</label><label><input type='checkbox' name='tor_browser_force_socks' value='1' {'checked' if truthy(s.get('tor_browser_force_socks')) else ''}> When using Tor Browser option, also force the configured SOCKS proxy</label><label><input type='checkbox' name='tor_background_prewarm_enabled' value='1' {'checked' if truthy(s.get('tor_background_prewarm_enabled','0')) else ''}> Pre-initialize Tor provider in the background on app startup / sign-in</label><button type='button' class='secondary' onclick="torAction('/tor/prewarm-json')">Start / verify Tor in background now</button><button type='button' class='warn' onclick="torAction('/tor/restart-json')">Restart managed Tor</button><button type='button' class='secondary' onclick="torAction('/tor/stop-json')">Stop managed Tor</button><button type='button' class='warn' onclick="fetch('/tor/newnym',{{method:'POST'}}).then(r=>r.json()).then(j=>alert('New Tor identity: '+JSON.stringify(j,null,2))).catch(e=>alert(e))">Request new Tor identity</button><button type='button' class='secondary' onclick="fetch('/tor/exit-ip').then(r=>r.json()).then(j=>alert('Tor exit IP: '+JSON.stringify(j,null,2))).catch(e=>alert(e))">Check Tor exit IP</button><p class='small muted'>Background prewarm starts or verifies the Tor SOCKS provider without slowing sign-in or forcing normal traffic through Tor. Current background status: <code id='tor-prewarm-status'>{h(tor_prewarm_status().get('message',''))}</code></p><pre id='tor-diagnostics' class='small' style='max-height:260px;overflow:auto;white-space:pre-wrap;background:#071019;border:1px solid #244;padding:10px;border-radius:10px'>{h(pretty(tor_prewarm_status()))}</pre><script>
function torRender(j){{
  let s=(j.status||j);
  let e=document.getElementById('tor-prewarm-status');
  if(e) e.textContent=(s.message||'')+(s.running?' (running)':'');
  let d=document.getElementById('tor-diagnostics');
  if(d) d.textContent=JSON.stringify(s,null,2);
}}
function torAction(url){{
  fetch(url,{{method:'POST'}}).then(r=>r.json()).then(j=>torRender(j)).catch(e=>alert(e));
}}
setInterval(()=>fetch('/tor/prewarm-status').then(r=>r.json()).then(j=>torRender(j)).catch(()=>{{}}), 2000);
</script></div><div class='row'><div><label>Tor host</label><input name='tor_host' value='{h(s.get('tor_host','127.0.0.1'))}'></div><div><label>SOCKS port</label><input name='tor_socks_port' value='{h(s.get('tor_socks_port','9050'))}'><p class='small muted'>Auto-detect also checks 9150 and 9050.</p></div><div><label>Control port</label><input name='tor_control_port' value='{h(s.get('tor_control_port','9051'))}'></div></div><label>Tor control password (optional)</label><input name='tor_control_password' type='password' value='{h(s.get('tor_control_password',''))}'>
      <button class='good'>Save settings</button></form></div>
      <div class='card'><h2>Master reveal key</h2><form method='post' action='/settings/master-key' data-webauthn-action='admin_settings'><label>New master reveal key</label><input name='master_key' type='password' minlength='12'><button class='danger'>Rotate master key</button></form></div>
      <div class='card'><h2>Create user</h2><form method='post' action='/settings/users' data-webauthn-action='admin_settings'><div class='row'><div><label>Username</label><input name='username'></div><div><label>Password</label><input name='password' type='password'></div><div><label>Role</label><select name='role'><option value='investigator'>investigator</option><option value='supervisor'>supervisor</option><option value='reviewer'>reviewer</option><option value='admin'>admin</option></select></div><div><label>Image policy</label><select name='image_policy'><option value='none'>none</option><option value='blur'>blur</option><option value='full'>full</option></select></div></div><button>Create user</button></form><table><tr><th>User</th><th>Role</th><th>Image policy</th><th>Master</th><th>Approval</th><th>WebAuthn</th></tr>{user_rows}</table></div>
      <div class='card'><h2>Diagnostics</h2><p><a class='button' href='/self-test'>Self-test</a> <a class='button' href='/debug-bundle.zip'>Debug bundle</a> <a class='button' href='/tor/status'>Tor status</a> <a class='button warn' href='/webauthn'>YubiKey/WebAuthn hooks</a></p></div>"""
    return layout(request, "Settings", body)


@app.post("/settings")
def settings_save(request: Request,
    edition: str = Form("lockdown"), default_capture_mode: str = Form("metadata_only"), default_media_policy: str = Form("block_images_video"), default_user_agent_profile: str = Form("chrome_windows"), custom_user_agent: str = Form(""), live_browser_default: str = Form("chromium"),
    hard_default_safe_mode: str | None = Form(None), disable_full_reveal_in_lockdown: str | None = Form(None), disable_plaintext_export_in_lockdown: str | None = Form(None), disable_materialization_in_lockdown: str | None = Form(None), allow_blur_in_lockdown: str | None = Form(None), require_master_key_full_reveal: str | None = Form(None), require_approval_full_reveal: str | None = Form(None), require_approval_plaintext_export: str | None = Form(None), require_approval_materialization: str | None = Form(None), live_javascript_enabled: str | None = Form(None), live_download_allowed_media_default: str | None = Form(None), live_auto_capture_default: str | None = Form(None), live_allow_captcha_challenge_media_default: str | None = Form(None), capture_settle_before_save: str | None = Form(None), capture_auto_scroll_enabled: str | None = Form(None), reviewer_enabled: str | None = Form(None), sealed_export_enabled: str | None = Form(None), sealed_export_include_derived: str | None = Form(None), sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800"), sealed_media_preserve_max_total_bytes: str = Form("209715200"), sealed_media_preserve_max_items_per_session: str = Form("2500"), sealed_media_preserve_max_pending_tasks: str = Form("75"), sealed_media_preserve_mime_allowlist: str = Form("image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream"), sealed_media_preserve_mode: str = Form("balanced"), sealed_media_preserve_fetch_timeout_ms: str = Form("3500"), sealed_media_preserve_background_timeout_ms: str = Form("18000"), sealed_media_preserve_skip_decorative_fast: str | None = Form(None), organization_hard_seal_media_enabled: str | None = Form(None), organization_hard_seal_public_key_pem: str = Form(""), head_probe_blocked_media: str | None = Form(None), reject_inline_media_in_safe_mode: str | None = Form(None), max_root_read_bytes: str = Form("524288"), max_text_summary_chars: str = Form("20000"), max_blocked_records: str = Form("1000"), snapshot_max_media_bytes: str = Form("52428800"), snapshot_max_media_items: str = Form("250"), snapshot_max_total_asset_bytes: str = Form("209715200"), capture_wait_after_load_ms: str = Form("5000"), capture_network_idle_timeout_ms: str = Form("20000"), capture_settle_timeout_ms: str = Form("30000"), capture_auto_scroll_max_steps: str = Form("30"), capture_auto_scroll_pause_ms: str = Form("550"), capture_stable_rounds: str = Form("3"), live_initial_navigation_timeout_ms: str = Form("60000"), live_auto_capture_delay_ms: str = Form("2500"), reviewer_default_render_mode: str = Form("auto"), reviewer_import_unlock_timeout_seconds: str = Form("900"), pdf_report_navigation_timeout_ms: str = Form("60000"), pdf_report_domcontentloaded_timeout_ms: str = Form("20000"), pdf_report_scripts_wait_ms: str = Form("12000"), pdf_report_safe_wait_ms: str = Form("3000"), pdf_report_screenshot_timeout_ms: str = Form("30000"), pdf_report_fallback_timeout_ms: str = Form("30000"), pdf_report_full_width_capture: str | None = Form(None), pdf_report_max_capture_width: str = Form("2400"), pdf_report_max_capture_height: str = Form("24000"), pdf_report_pdf_page_width_px: str = Form("1224"), pdf_report_pdf_page_height_px: str = Form("1584"), pdf_report_pdf_margin_px: str = Form("36"), pdf_report_split_overlap_px: str = Form("24"), safe_allowlist_domains: str = Form(""), capture_denylist_domains: str = Form(""), tor_browser_path: str = Form(""), tor_executable_path: str = Form(""), tor_auto_start_from_browser_bundle: str | None = Form(None), tor_browser_force_socks: str | None = Form(None), tor_background_prewarm_enabled: str | None = Form(None), tor_host: str = Form("127.0.0.1"), tor_socks_port: str = Form("9050"), tor_control_port: str = Form("9051"), tor_control_password: str = Form("")) -> RedirectResponse:
    user = require_admin(request)
    redir = webauthn_recent_or_redirect(request, user, "admin_settings", "/settings")
    if redir:
        return redir
    if civilian_unknown_master_mode():
        edition = "lockdown"
        hard_default_safe_mode = "1"
        disable_full_reveal_in_lockdown = "1"
        disable_plaintext_export_in_lockdown = "1"
        disable_materialization_in_lockdown = "1"
        require_master_key_full_reveal = "1"
        require_approval_full_reveal = "1"
        require_approval_plaintext_export = "1"
        require_approval_materialization = "1"
        organization_hard_seal_media_enabled = None
        organization_hard_seal_public_key_pem = ""
    if edition not in EDITIONS: edition = "lockdown"
    if default_capture_mode not in CAPTURE_MODES: default_capture_mode = "metadata_only"
    if default_media_policy not in MEDIA_POLICIES: default_media_policy = "block_images_video"
    if default_user_agent_profile not in USER_AGENT_PROFILES: default_user_agent_profile = "chrome_windows"
    if live_browser_default not in BROWSERS: live_browser_default = "chromium"
    if reviewer_default_render_mode not in {"auto", "safe", "remote", "scripts"}: reviewer_default_render_mode = "auto"
    reviewer_import_unlock_timeout_seconds = str(safe_int(reviewer_import_unlock_timeout_seconds, 900, min_value=0, max_value=86400))
    pdf_report_navigation_timeout_ms = str(safe_int(pdf_report_navigation_timeout_ms, 60000, min_value=5000, max_value=300000))
    pdf_report_domcontentloaded_timeout_ms = str(safe_int(pdf_report_domcontentloaded_timeout_ms, 20000, min_value=1000, max_value=180000))
    pdf_report_scripts_wait_ms = str(safe_int(pdf_report_scripts_wait_ms, 12000, min_value=0, max_value=120000))
    pdf_report_safe_wait_ms = str(safe_int(pdf_report_safe_wait_ms, 3000, min_value=0, max_value=60000))
    pdf_report_screenshot_timeout_ms = str(safe_int(pdf_report_screenshot_timeout_ms, 30000, min_value=3000, max_value=180000))
    pdf_report_fallback_timeout_ms = str(safe_int(pdf_report_fallback_timeout_ms, 30000, min_value=3000, max_value=180000))
    pdf_report_max_capture_width = str(safe_int(pdf_report_max_capture_width, 2400, min_value=640, max_value=8000))
    pdf_report_max_capture_height = str(safe_int(pdf_report_max_capture_height, 24000, min_value=1200, max_value=60000))
    pdf_report_pdf_page_width_px = str(safe_int(pdf_report_pdf_page_width_px, 1224, min_value=480, max_value=5000))
    pdf_report_pdf_page_height_px = str(safe_int(pdf_report_pdf_page_height_px, 1584, min_value=640, max_value=7000))
    pdf_report_pdf_margin_px = str(safe_int(pdf_report_pdf_margin_px, 36, min_value=0, max_value=400))
    pdf_report_split_overlap_px = str(safe_int(pdf_report_split_overlap_px, 24, min_value=0, max_value=300))
    vals = locals().copy(); vals.pop("request"); vals.pop("user")
    for key in ["hard_default_safe_mode", "disable_full_reveal_in_lockdown", "disable_plaintext_export_in_lockdown", "disable_materialization_in_lockdown", "allow_blur_in_lockdown", "require_master_key_full_reveal", "require_approval_full_reveal", "require_approval_plaintext_export", "require_approval_materialization", "live_javascript_enabled", "live_download_allowed_media_default", "live_auto_capture_default", "live_allow_captcha_challenge_media_default", "capture_settle_before_save", "capture_auto_scroll_enabled", "reviewer_enabled", "sealed_export_enabled", "sealed_export_include_derived", "sealed_media_preservation_enabled", "sealed_media_preserve_images", "sealed_media_preserve_video", "sealed_media_preserve_audio", "sealed_media_preserve_skip_decorative_fast", "organization_hard_seal_media_enabled", "tor_auto_start_from_browser_bundle", "tor_browser_force_socks", "tor_background_prewarm_enabled", "head_probe_blocked_media", "reject_inline_media_in_safe_mode", "pdf_report_full_width_capture"]:
        vals[key] = "1" if vals.get(key) else "0"
    vals["sealed_media_preserve_max_bytes"] = str(safe_int(vals.get("sealed_media_preserve_max_bytes"), 52428800, min_value=1048576))
    vals["sealed_media_preserve_max_total_bytes"] = str(safe_int(vals.get("sealed_media_preserve_max_total_bytes"), 209715200, min_value=1048576))
    vals["sealed_media_preserve_max_items_per_session"] = str(safe_int(vals.get("sealed_media_preserve_max_items_per_session"), 2500, min_value=1))
    vals["sealed_media_preserve_max_pending_tasks"] = str(safe_int(vals.get("sealed_media_preserve_max_pending_tasks"), 75, min_value=1, max_value=1000))
    if vals.get("sealed_media_preserve_mode") not in {"fast", "balanced", "complete"}:
        vals["sealed_media_preserve_mode"] = "balanced"
    vals["sealed_media_preserve_fetch_timeout_ms"] = str(safe_int(vals.get("sealed_media_preserve_fetch_timeout_ms"), 3500, min_value=500, max_value=60000))
    vals["sealed_media_preserve_background_timeout_ms"] = str(safe_int(vals.get("sealed_media_preserve_background_timeout_ms"), 18000, min_value=1000, max_value=120000))
    org_pem = str(vals.get("organization_hard_seal_public_key_pem") or "").strip()
    org_fp = escrow_public_fingerprint(org_pem) if org_pem else ""
    if civilian_unknown_master_mode():
        vals["organization_hard_seal_media_enabled"] = "0"
        vals["organization_hard_seal_public_key_pem"] = ""
        vals["organization_hard_seal_public_key_fingerprint"] = ""
    else:
        if vals.get("organization_hard_seal_media_enabled") == "1" and not org_fp:
            raise HTTPException(400, "Organization hard-sealed media requires a valid organization escrow public key PEM")
        vals["organization_hard_seal_public_key_pem"] = org_pem if org_fp else ""
        vals["organization_hard_seal_public_key_fingerprint"] = org_fp
    for k, v in vals.items():
        set_setting(k, v)
    if organization_controlled_mode() and setting_bool("organization_hard_seal_media_enabled", "0"):
        try:
            migrate_existing_organization_preserved_media_to_hard_sealed()
        except Exception as exc:
            log_event(user["username"], "ORGANIZATION_PRESERVED_MEDIA_HARD_SEAL_MIGRATION_FAILED", details={"error": str(exc)[:500]})
    log_event(user["username"], "SETTINGS_UPDATED", details={"edition": edition, "default_capture_mode": default_capture_mode, "default_media_policy": default_media_policy, "default_user_agent_profile": default_user_agent_profile, "sealed_media_preservation_enabled": vals.get("sealed_media_preservation_enabled"), "organization_hard_seal_media_enabled": vals.get("organization_hard_seal_media_enabled"), "organization_hard_seal_public_key_fingerprint": vals.get("organization_hard_seal_public_key_fingerprint", "")})
    try:
        if setting_bool("tor_background_prewarm_enabled", "0"):
            tor_prewarm_background("settings-save")
    except Exception:
        pass
    return RedirectResponse("/settings?msg=Settings%20saved", 303)


@app.post("/settings/master-key")
def settings_master(request: Request, master_key: str = Form(...)) -> RedirectResponse:
    user = require_admin(request)
    redir = webauthn_recent_or_redirect(request, user, "admin_settings", "/settings")
    if redir:
        return redir
    if civilian_unknown_master_mode():
        raise HTTPException(403, "Civilian Unknown Master Key mode blocks local master-key rotation")
    set_master_key(master_key)
    log_event(user["username"], "MASTER_KEY_ROTATED")
    return RedirectResponse("/settings?msg=Master%20key%20updated", 303)


@app.post("/settings/users")
def settings_create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("investigator"), image_policy: str = Form("blur")) -> RedirectResponse:
    user = require_admin(request)
    redir = webauthn_recent_or_redirect(request, user, "admin_settings", "/settings")
    if redir:
        return redir
    if role not in {"investigator", "supervisor", "reviewer", "admin"}: role = "investigator"
    if image_policy not in {"none", "blur", "full"}: image_policy = "blur"
    if len(password) < 8: raise HTTPException(400, "Password too short")
    execute("INSERT INTO users(username,password_hash,role,image_policy,require_master_key,require_approval,created_at) VALUES(?,?,?,?,?,?,?)", (username.strip(), hash_password(password), role, image_policy, 1 if role == "investigator" else 0, 1 if role == "investigator" else 0, utcnow()))
    log_event(user["username"], "USER_CREATED", details={"username": username, "role": role, "image_policy": image_policy})
    return RedirectResponse("/settings?msg=User%20created", 303)


def tor_status_bootstrap_fast(timeout: float = 0.75) -> dict[str, Any]:
    res = tor_control_command("GETINFO status/bootstrap-phase", timeout=timeout)
    if not res.get("ok"):
        return {"ok": False, "percent": None, "message": res.get("error") or res.get("response") or "control unavailable", "raw": res}
    raw = res.get("response") or ""
    m = re.search(r"PROGRESS=(\d+)", raw)
    pct = int(m.group(1)) if m else None
    return {"ok": True, "percent": pct, "message": raw, "raw": res}


def tor_status_data() -> dict[str, Any]:
    host = get_setting("tor_host", "127.0.0.1")
    socks = safe_int(get_setting("tor_socks_port", "9050"), 9050)
    ctrl = safe_int(get_setting("tor_control_port", "9051"), 9051)
    out: dict[str, Any] = {"host": host, "socks_port": socks, "control_port": ctrl, "socks_open": False, "control_open": False, "running": False, "ok": False, "percent": None, "state": "closed", "label": "Tor: closed", "message": "Tor SOCKS is closed"}
    for key, port in [("socks_open", socks), ("control_open", ctrl)]:
        try:
            with socket.create_connection((host, port), timeout=0.6):
                out[key] = True
        except Exception as exc:
            out[key + "_error"] = str(exc)
    try:
        with TOR_PREWARM_LOCK:
            prewarm = dict(TOR_PREWARM_STATUS)
    except Exception:
        prewarm = {}
    out["prewarm"] = {k: v for k, v in prewarm.items() if k not in {"diagnostics", "log_tail"}}
    out["running"] = bool(prewarm.get("running"))
    boot = prewarm.get("bootstrap") if isinstance(prewarm.get("bootstrap"), dict) else {}
    if out["control_open"]:
        boot = tor_status_bootstrap_fast(timeout=0.75)
    out["bootstrap"] = boot
    pct = boot.get("percent") if isinstance(boot, dict) else None
    if pct is None and isinstance(prewarm.get("bootstrap"), dict):
        pct = prewarm["bootstrap"].get("percent")
    try:
        pct = int(pct) if pct is not None else None
    except Exception:
        pct = None
    out["percent"] = pct
    if pct is not None and pct >= 100:
        out.update({"ok": True, "state": "ready", "label": "Tor: ready 100%", "message": f"Tor ready on {host}:{socks}; bootstrap 100%"})
    elif pct is not None:
        out.update({"ok": False, "state": "bootstrapping", "label": f"Tor: bootstrapping {pct}%", "message": f"Tor bootstrapping {pct}% on {host}:{socks}"})
    elif out["socks_open"] and not out["control_open"]:
        out.update({"ok": True, "state": "socks_open", "label": "Tor: SOCKS open", "message": f"Tor SOCKS open on {host}:{socks}; control unavailable"})
    elif out["socks_open"]:
        out.update({"ok": True, "state": "socks_open", "label": "Tor: SOCKS open", "message": f"Tor SOCKS open on {host}:{socks}"})
    elif out["running"]:
        out.update({"ok": False, "state": "starting", "label": "Tor: starting", "message": str(prewarm.get("message") or "Tor is starting")})
    else:
        out.update({"ok": False, "state": "closed", "label": "Tor: closed", "message": str(prewarm.get("message") or "Tor SOCKS is closed")})
    return out


@app.get("/tor/status")
def tor_status(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(tor_status_data())


@app.post("/tor/newnym")
def tor_newnym(request: Request) -> JSONResponse:
    user = require_user(request)
    result = tor_control_command("SIGNAL NEWNYM", timeout=8.0)
    result["exit_ip_after_signal_note"] = "Tor may take several seconds to build a new circuit; check exit IP again after a short wait."
    log_event(user["username"], "TOR_NEWNYM_REQUESTED", details=result)
    return JSONResponse(result)


@app.get("/tor/exit-ip")
def tor_exit_ip_route(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(tor_exit_ip())


def webauthn_browser_script(*, purpose: str, action: str = "", return_to: str = "/") -> str:
    """Shared browser-side WebAuthn helpers.

    The browser itself shows the YubiKey/security-key prompt. The app only
    starts the ceremony and verifies the signed result server-side.
    """
    return f"""
<script>
function bsB64ToBuf(s) {{
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}}
function bsBufToB64(buf) {{
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/g, '');
}}
function bsStatus(msg, good=false) {{
  const el = document.getElementById('webauthn-status');
  if (el) el.innerHTML = `<span class="badge ${{good ? 'good' : 'warn'}}">${{msg}}</span>`;
}}
function bsWebAuthnErrorMessage(e) {{
  const raw = (e && (e.message || e.name)) ? String(e.name || '') + ': ' + String(e.message || '') : String(e || 'unknown error');
  if (/insecure|SecurityError|secure context/i.test(raw)) {{
    return raw + ' — WebAuthn is strict about local origins. Open BlindSite at http://localhost:' + location.port + '/webauthn instead of 127.0.0.1/IP, then retry. If using a remote/deployed host, use HTTPS with a trusted certificate.';
  }}
  if (/rp id|relying party|not a registrable|rpId/i.test(raw)) {{
    return raw + ' — The YubiKey RP ID must match the current browser host. Use the same localhost/host URL for enrollment and sign-in.';
  }}
  return raw;
}}
function bsEnsureWebAuthnSafeOrigin() {{
  const host = (location.hostname || '').toLowerCase();
  if (location.protocol === 'http:' && (host === '127.0.0.1' || host === '::1' || host === '0.0.0.0')) {{
    const target = 'http://localhost:' + location.port + location.pathname + location.search + location.hash;
    window.location.replace(target);
    throw new Error('Switching to localhost for YubiKey/WebAuthn. Try again after the page reloads.');
  }}
  if (!window.isSecureContext) {{
    throw new Error('WebAuthn requires a secure browser context. Use http://localhost for local BlindSite, or HTTPS for deployed instances.');
  }}
}}
async function bsRegisterKey() {{
  try {{
    bsEnsureWebAuthnSafeOrigin();
    if (!navigator.credentials || !window.PublicKeyCredential) throw new Error('This browser does not expose WebAuthn. Try Chrome/Edge/Firefox on localhost or HTTPS.');
    bsStatus('Asking browser for your YubiKey/security key…');
    const nickname = (document.getElementById('webauthn-nickname') || {{value:''}}).value || 'YubiKey / security key';
    const enablePolicy = !!(document.getElementById('webauthn-enable-policy') || {{checked:false}}).checked;
    const r = await fetch('/webauthn/register/options', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{nickname:nickname}})}});
    const opts = await r.json();
    if (!opts.ok) throw new Error(opts.error || 'Could not start enrollment');
    const pub = opts.publicKey;
    pub.challenge = bsB64ToBuf(pub.challenge);
    pub.user.id = bsB64ToBuf(pub.user.id);
    if (pub.excludeCredentials) pub.excludeCredentials = pub.excludeCredentials.map(c => ({{...c, id: bsB64ToBuf(c.id)}}));
    const cred = await navigator.credentials.create({{publicKey: pub}});
    const payload = {{
      rawId: bsBufToB64(cred.rawId),
      id: cred.id,
      type: cred.type,
      nickname: nickname,
      enable_policy: enablePolicy,
      response: {{
        clientDataJSON: bsBufToB64(cred.response.clientDataJSON),
        attestationObject: bsBufToB64(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : []
      }}
    }};
    const vr = await fetch('/webauthn/register/verify', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
    const v = await vr.json();
    if (!v.ok) throw new Error(v.error || 'Enrollment failed');
    bsStatus('YubiKey/security key enrolled.', true);
    setTimeout(() => window.location = '/webauthn?msg=YubiKey%20enrolled', 700);
  }} catch(e) {{ bsStatus('YubiKey enrollment failed: ' + bsWebAuthnErrorMessage(e)); }}
}}
async function bsAuthenticateKey(mode, action, returnTo) {{
  try {{
    bsEnsureWebAuthnSafeOrigin();
    if (!navigator.credentials || !window.PublicKeyCredential) throw new Error('This browser does not expose WebAuthn. Try Chrome/Edge/Firefox on localhost or HTTPS.');
    bsStatus('Touch your YubiKey/security key when the browser asks…');
    const url = mode === 'login' ? '/webauthn/login/options' : ('/webauthn/auth/options?action=' + encodeURIComponent(action || 'step_up'));
    const r = await fetch(url, {{cache:'no-store'}});
    const opts = await r.json();
    if (!opts.ok) throw new Error(opts.error || 'Could not start WebAuthn');
    const pub = opts.publicKey;
    pub.challenge = bsB64ToBuf(pub.challenge);
    if (pub.allowCredentials) pub.allowCredentials = pub.allowCredentials.map(c => ({{...c, id: bsB64ToBuf(c.id)}}));
    const assertion = await navigator.credentials.get({{publicKey: pub}});
    const payload = {{
      mode: mode,
      action: action || '',
      return_to: returnTo || '',
      rawId: bsBufToB64(assertion.rawId),
      id: assertion.id,
      type: assertion.type,
      response: {{
        clientDataJSON: bsBufToB64(assertion.response.clientDataJSON),
        authenticatorData: bsBufToB64(assertion.response.authenticatorData),
        signature: bsBufToB64(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bsBufToB64(assertion.response.userHandle) : ''
      }}
    }};
    const endpoint = mode === 'login' ? '/webauthn/login/verify' : '/webauthn/auth/verify';
    const vr = await fetch(endpoint, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
    const v = await vr.json();
    if (!v.ok) throw new Error(v.error || 'WebAuthn verification failed');
    bsStatus('YubiKey/security key verified.', true);
    setTimeout(() => {{ const dest = (mode === 'login') ? (v.redirect || returnTo || '/') : (returnTo || v.redirect || '/'); window.location = dest; }}, 500);
  }} catch(e) {{ bsStatus('YubiKey verification failed: ' + bsWebAuthnErrorMessage(e)); }}
}}
{ "bsAuthenticateKey('login', '', '/')" if purpose == "login_auto" else "" }
{ "bsAuthenticateKey('stepup', " + json.dumps(action) + ", " + json.dumps(return_to) + ")" if purpose == "stepup_auto" else "" }
</script>
"""


@app.get("/webauthn/diagnostics")
def webauthn_diagnostics(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(webauthn_secure_context_hint(request))


@app.get("/webauthn", response_class=HTMLResponse)
def webauthn_page(request: Request, msg: str | None = None) -> HTMLResponse:
    redir = webauthn_canonical_redirect_if_needed(request)
    if redir:
        return redir  # type: ignore[return-value]
    user = require_user(request)
    creds = [dict(r) for r in webauthn_credential_rows(user["username"])]
    rows = "".join(
        f"<tr><td>{h(c.get('nickname') or 'YubiKey / security key')}</td><td><code>{h((c.get('credential_id') or '')[:28])}…</code></td><td>{h(c.get('created_at'))}</td><td>{h(c.get('last_used_at') or '')}</td><td><form method='post' action='/webauthn/credentials/{int(c['id'])}/delete' onsubmit='return confirm(\"Remove this YubiKey credential?\")'><button class='danger'>Remove</button></form></td></tr>"
        for c in creds
    )
    enabled = truthy(user.get("require_webauthn"))
    status = badge("required for this account", "good") if enabled else badge("not required for login", "warn")
    verified = badge("verified this session", "good") if webauthn_step_up_valid(request, user) else badge("not recently verified", "warn")
    hint = webauthn_secure_context_hint(request)
    hint_rows = "".join(f"<li>{h(w)}</li>" for w in (hint.get("warnings") or []))
    hint_block = f"<div class='card danger'><h3>YubiKey/WebAuthn origin warning</h3><ul>{hint_rows}</ul><p><a class='button warn' href='{h(hint.get('canonical_local_url') or '/webauthn')}'>Open localhost YubiKey page</a></p></div>" if hint_rows else ""
    body = f"""{flash(msg)}{hint_block}<div class='card warn'><h2>YubiKey / WebAuthn</h2>
      <p>{status} {verified}</p>
      <p>Enroll a YubiKey or any FIDO2/WebAuthn security key. This is optional and additive: it does not replace the master reveal key, approvals, custody locks, or existing policy checks. BlindSite uses the browser's native security-key prompt; no extra desktop app is required.</p>
      <p class='small muted'>Localhost is supported by modern browsers for WebAuthn testing. Production agency deployments should use HTTPS and counsel/IT-approved identity policy.</p>
      <div id='webauthn-status'>{badge('ready','info')}</div>
      <label>Key nickname</label><input id='webauthn-nickname' value='YubiKey / security key'>
      <label><input id='webauthn-enable-policy' type='checkbox'> Also require this key at next sign-in and high-risk actions for my account (optional)</label><p class='small muted'>YubiKey/WebAuthn is optional and additive. It does not replace the master reveal key, approvals, custody locks, or existing policy checks.</p>
      <button class='good' type='button' onclick='bsRegisterKey()'>Enroll YubiKey / security key</button>
      <button class='secondary' type='button' onclick="bsAuthenticateKey('stepup','manual','/webauthn')">Test / verify key now</button>
      <form method='post' action='/webauthn/policy' style='display:inline'><input type='hidden' name='enabled' value='{0 if enabled else 1}'><button class='{'secondary' if enabled else 'warn'}'>{'Disable account YubiKey requirement' if enabled else 'Require YubiKey for my account'}</button></form>
    </div>
    <div class='card'><h2>Enrolled keys</h2><table><tr><th>Nickname</th><th>Credential ID</th><th>Created</th><th>Last used</th><th>Remove</th></tr>{rows or '<tr><td colspan="5" class="muted">No YubiKey/security key enrolled yet.</td></tr>'}</table></div>
    <div class='card safe'><h2>Where BlindSite asks for the key</h2><p>After you opt in, BlindSite asks through the browser's native security-key prompt before sign-in, full reveal, plaintext export, blocked-media materialization, sealed export, and exact local page rendering. YubiKey is optional and never replaces the master reveal key or approval workflow.</p></div>
    {webauthn_browser_script(purpose='manage')}
    """
    return layout(request, "YubiKey / WebAuthn", body)


@app.post("/webauthn/policy")
def webauthn_policy(request: Request, enabled: int = Form(1)) -> RedirectResponse:
    user = require_user(request)
    want_enabled = bool(int(enabled or 0))
    if want_enabled and not webauthn_user_has_credentials(user["username"]):
        return RedirectResponse("/webauthn?msg=Enroll%20a%20YubiKey%20or%20security%20key%20before%20requiring%20it", 303)
    execute("UPDATE users SET require_webauthn=? WHERE username=?", (1 if want_enabled else 0, user["username"]))
    if not want_enabled:
        request.session.pop("webauthn_verified_at", None)
        request.session.pop("webauthn_verified_user", None)
        request.session.pop("webauthn_verified_action", None)
    log_event(user["username"], "YUBIKEY_POLICY_UPDATED", details={"require_webauthn": want_enabled})
    return RedirectResponse("/webauthn?msg=YubiKey%20policy%20updated", 303)


@app.post("/webauthn/credentials/{credential_db_id}/delete")
def webauthn_delete_credential(request: Request, credential_db_id: int) -> RedirectResponse:
    user = require_user(request)
    row = rowdict(fetchone("SELECT * FROM webauthn_credentials WHERE id=?", (credential_db_id,)))
    if not row or row.get("username") != user["username"]:
        raise HTTPException(404, "YubiKey credential not found")
    execute("DELETE FROM webauthn_credentials WHERE id=?", (credential_db_id,))
    remaining = webauthn_credential_count(user["username"])
    if remaining == 0:
        execute("UPDATE users SET require_webauthn=0 WHERE username=?", (user["username"],))
    log_event(user["username"], "YUBIKEY_CREDENTIAL_REMOVED", details={"credential_db_id": credential_db_id, "remaining_credentials": remaining})
    return RedirectResponse("/webauthn?msg=YubiKey%20credential%20removed", 303)


@app.post("/webauthn/register/options")
async def webauthn_register_options(request: Request) -> JSONResponse:
    user = require_user(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    challenge = b64url(secrets.token_bytes(32))
    request.session["webauthn_register_challenge"] = challenge
    username = str(user["username"])
    existing = [{"type": "public-key", "id": r["credential_id"]} for r in webauthn_credential_rows(username)]
    rp: dict[str, Any] = {"name": APP_NAME}
    explicit_rp_id = webauthn_public_key_rp_id(request)
    if explicit_rp_id:
        rp["id"] = explicit_rp_id
    options = {
        "challenge": challenge,
        "rp": rp,
        "user": {"id": b64url(username.encode("utf-8")), "name": username, "displayName": username},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": existing,
        "authenticatorSelection": {"residentKey": "discouraged", "userVerification": "preferred"},
    }
    hint = webauthn_secure_context_hint(request)
    log_event(username, "YUBIKEY_REGISTRATION_STARTED", details={"rp_id": explicit_rp_id or "browser-default-local-origin", "rp_id_candidates": webauthn_rp_id_candidates(request), "secure_context_hint": hint, "nickname": str(payload.get("nickname") or "")[:80]})
    return JSONResponse({"ok": True, "publicKey": options, "secureContextHint": hint})


@app.post("/webauthn/register/verify")
async def webauthn_register_verify(request: Request) -> JSONResponse:
    user = require_user(request)
    username = str(user["username"])
    try:
        payload = await request.json()
        client_obj, client_raw = webauthn_check_client_data(request, payload.get("response", {}).get("clientDataJSON", ""), "webauthn.create", "webauthn_register_challenge")
        att_obj = cbor_decode(b64url_decode(payload.get("response", {}).get("attestationObject", "")))
        auth_data = att_obj.get("authData") if isinstance(att_obj, dict) else None
        if not isinstance(auth_data, bytes):
            raise ValueError("attestation object did not contain authData")
        parsed = webauthn_parse_authenticator_data(auth_data)
        if not webauthn_rp_hash_valid(request, parsed["rp_id_hash"]):
            raise ValueError("RP ID hash mismatch for this origin. Use the same localhost/host URL you used when enrolling the key.")
        if not (int(parsed["flags"]) & 0x01):
            raise ValueError("Authenticator did not assert user presence")
        cred_id = b64url(parsed["credential_id"])
        public_key_pem, alg = webauthn_public_key_from_cose(parsed["cose_public_key"])
        transports = payload.get("response", {}).get("transports") or []
        execute("""INSERT INTO webauthn_credentials(username,credential_id,public_key_pem,cose_alg,sign_count,aaguid,nickname,transports_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(credential_id) DO UPDATE SET nickname=excluded.nickname, transports_json=excluded.transports_json""", (username, cred_id, public_key_pem, alg, int(parsed.get("sign_count") or 0), parsed.get("aaguid", b"").hex(), clean_filename(str(payload.get("nickname") or "YubiKey / security key")), json.dumps(transports), utcnow()))
        if payload.get("enable_policy", True):
            execute("UPDATE users SET require_webauthn=1 WHERE username=?", (username,))
        request.session.pop("webauthn_register_challenge", None)
        log_event(username, "YUBIKEY_CREDENTIAL_ENROLLED", details={"credential_id_sha256": sha256_text(cred_id), "cose_alg": alg, "transports": transports, "require_webauthn": bool(payload.get("enable_policy", True))})
        return JSONResponse({"ok": True})
    except Exception as exc:
        log_event(username, "YUBIKEY_CREDENTIAL_ENROLLMENT_FAILED", details={"error": str(exc)[:500]})
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


def webauthn_options_for_username(request: Request, username: str, *, challenge_key: str, action: str = "") -> dict[str, Any]:
    creds = list(webauthn_credential_rows(username))
    if not creds:
        raise HTTPException(400, "No YubiKey/WebAuthn credential is enrolled for this account")
    challenge = b64url(secrets.token_bytes(32))
    request.session[challenge_key] = challenge
    if action:
        request.session["webauthn_auth_action"] = action
    options: dict[str, Any] = {
        "challenge": challenge,
        "timeout": 60000,
        "allowCredentials": [{"type": "public-key", "id": r["credential_id"]} for r in creds],
        "userVerification": "preferred",
    }
    explicit_rp_id = webauthn_public_key_rp_id(request)
    if explicit_rp_id:
        options["rpId"] = explicit_rp_id
    return options


@app.get("/webauthn/required")
def webauthn_required_status(request: Request, action: str = "step_up") -> JSONResponse:
    user = require_user(request)
    required = webauthn_action_requires_stepup(user, action)
    has_creds = webauthn_user_has_credentials(user["username"])
    verified = webauthn_step_up_valid(request, user)
    return JSONResponse({
        "ok": True,
        "action": action,
        "label": WEBAUTHN_STEPUP_ACTION_LABELS.get(action, action.replace("_", " ")),
        "required": bool(required),
        "has_credentials": bool(has_creds),
        "verified": bool(verified),
        "optional": True,
    })


@app.get("/webauthn/auth/options")
def webauthn_auth_options(request: Request, action: str = "step_up") -> JSONResponse:
    user = require_user(request)
    if not webauthn_action_requires_stepup(user, action) and action not in {"manual", "step_up", "reviewer_import_unlock"}:
        return JSONResponse({"ok": False, "error": "YubiKey/WebAuthn is not required for this action on this account"}, status_code=400)
    return JSONResponse({"ok": True, "publicKey": webauthn_options_for_username(request, user["username"], challenge_key="webauthn_auth_challenge", action=action)})


def webauthn_verify_assertion_for_username(request: Request, username: str, payload: dict[str, Any], *, challenge_key: str) -> dict[str, Any]:
    response = payload.get("response") or {}
    _client_obj, client_raw = webauthn_check_client_data(request, response.get("clientDataJSON", ""), "webauthn.get", challenge_key)
    credential_id = payload.get("rawId") or payload.get("id") or ""
    cred = rowdict(fetchone("SELECT * FROM webauthn_credentials WHERE username=? AND credential_id=?", (username, credential_id)))
    if not cred:
        raise HTTPException(403, "This YubiKey/security key is not enrolled for the current account")
    auth_data = b64url_decode(response.get("authenticatorData", ""))
    parsed = webauthn_parse_authenticator_data(auth_data)
    if not webauthn_rp_hash_valid(request, parsed["rp_id_hash"]):
        raise HTTPException(403, "RP ID hash mismatch for this origin. Use the same localhost/host URL you used when enrolling the key.")
    if not (int(parsed["flags"]) & 0x01):
        raise HTTPException(403, "Authenticator did not assert user presence")
    signed_data = auth_data + hashlib.sha256(client_raw).digest()
    webauthn_verify_signature(str(cred["public_key_pem"]), b64url_decode(response.get("signature", "")), signed_data)
    old_count = int(cred.get("sign_count") or 0)
    new_count = int(parsed.get("sign_count") or 0)
    warning = ""
    if old_count and new_count and new_count <= old_count:
        warning = "Authenticator sign counter did not increase; continuing but recording warning."
    if new_count > old_count:
        execute("UPDATE webauthn_credentials SET sign_count=?, last_used_at=? WHERE id=?", (new_count, utcnow(), cred["id"]))
    else:
        execute("UPDATE webauthn_credentials SET last_used_at=? WHERE id=?", (utcnow(), cred["id"]))
    return {"credential_db_id": cred["id"], "credential_id_sha256": sha256_text(credential_id), "warning": warning, "flags": parsed.get("flags"), "sign_count": new_count}


@app.post("/webauthn/auth/verify")
async def webauthn_auth_verify(request: Request) -> JSONResponse:
    user = require_user(request)
    username = str(user["username"])
    try:
        payload = await request.json()
        result = webauthn_verify_assertion_for_username(request, username, payload, challenge_key="webauthn_auth_challenge")
        action = str(payload.get("action") or request.session.get("webauthn_auth_action") or "step_up")
        request.session["webauthn_verified_at"] = time.time()
        request.session["webauthn_verified_user"] = username
        request.session["webauthn_verified_action"] = action
        request.session.pop("webauthn_auth_challenge", None)
        log_event(username, "YUBIKEY_STEP_UP_VERIFIED", details={"action": action, **result})
        redirect_to = request.session.pop("webauthn_return_to", "") if request.session.get("webauthn_return_to") else ""
        redirect_to = redirect_to or str(payload.get("return_to") or "") or "/"
        return JSONResponse({"ok": True, "redirect": redirect_to})
    except HTTPException as exc:
        return JSONResponse({"ok": False, "error": str(exc.detail)}, status_code=exc.status_code)
    except Exception as exc:
        log_event(username, "YUBIKEY_STEP_UP_FAILED", details={"error": str(exc)[:500]})
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.get("/webauthn/step-up", response_class=HTMLResponse)
def webauthn_stepup_page(request: Request, action: str = "step_up", return_to: str = "/") -> HTMLResponse:
    redir = webauthn_canonical_redirect_if_needed(request)
    if redir:
        return redir  # type: ignore[return-value]
    user = require_user(request)
    if not webauthn_user_has_credentials(user["username"]):
        return RedirectResponse("/webauthn?msg=Enroll%20a%20YubiKey%20before%20using%20step-up", 303)  # type: ignore[return-value]
    request.session["webauthn_return_to"] = return_to or "/"
    label = WEBAUTHN_STEPUP_ACTION_LABELS.get(action, action.replace("_", " "))
    body = f"""<div class='card warn' style='text-align:center;max-width:900px;margin:20px auto'>
      <h2>YubiKey step-up required</h2>
      <p>BlindSite needs your YubiKey/security key before: <b>{h(label)}</b>.</p>
      <div id='webauthn-status'>{badge('waiting for browser prompt','warn')}</div>
      <p><button class='good' type='button' onclick="bsAuthenticateKey('stepup',{h(json.dumps(action))},{h(json.dumps(return_to or '/'))});return false;">Use YubiKey now</button> <a class='button secondary' href='{h(return_to or '/')}' >Cancel</a></p>
      <p class='small muted'>The browser will show the security-key prompt. Touch your YubiKey when asked.</p>
    </div>{webauthn_browser_script(purpose='stepup_auto', action=action, return_to=return_to or '/')}
    """
    return layout(request, "YubiKey step-up", body)


@app.get("/webauthn/login", response_class=HTMLResponse)
def webauthn_login_page(request: Request) -> HTMLResponse:
    redir = webauthn_canonical_redirect_if_needed(request)
    if redir:
        return redir  # type: ignore[return-value]
    username = str(request.session.get("pending_webauthn_login_username") or "")
    if not username:
        return RedirectResponse("/login", 303)  # type: ignore[return-value]
    body = f"""<div class='card warn' style='text-align:center;max-width:900px;margin:20px auto'>
      <h2>YubiKey sign-in required</h2>
      <p>Password accepted for <b>{h(username)}</b>. Touch your YubiKey/security key to finish signing in.</p>
      <div id='webauthn-status'>{badge('waiting for browser prompt','warn')}</div>
      <p><button class='good' type='button' onclick="bsAuthenticateKey('login','','/')">Use YubiKey now</button> <a class='button secondary' href='/login'>Cancel</a></p>
    </div>{webauthn_browser_script(purpose='login_auto')}
    """
    return layout(request, "YubiKey sign-in", body)


@app.get("/webauthn/login/options")
def webauthn_login_options(request: Request) -> JSONResponse:
    username = str(request.session.get("pending_webauthn_login_username") or "")
    if not username:
        return JSONResponse({"ok": False, "error": "No pending YubiKey login"}, status_code=400)
    return JSONResponse({"ok": True, "publicKey": webauthn_options_for_username(request, username, challenge_key="webauthn_login_challenge", action="login")})


@app.post("/webauthn/login/verify")
async def webauthn_login_verify(request: Request) -> JSONResponse:
    username = str(request.session.get("pending_webauthn_login_username") or "")
    if not username:
        return JSONResponse({"ok": False, "error": "No pending YubiKey login"}, status_code=400)
    try:
        payload = await request.json()
        result = webauthn_verify_assertion_for_username(request, username, payload, challenge_key="webauthn_login_challenge")
        init_tor_session = truthy(request.session.get("pending_login_init_tor"))
        force_tor_all_cases = truthy(request.session.get("pending_login_force_tor_all_cases"))
        sealed_sender_enabled = truthy(request.session.get("pending_login_sealed_sender_enabled", "1"))
        request.session.clear()
        request.session["username"] = username
        request.session["sealed_sender_file_downloads_enabled"] = "1" if sealed_sender_enabled else "0"
        if force_tor_all_cases:
            request.session["force_tor_all_cases"] = "1"
        request.session["webauthn_verified_at"] = time.time()
        request.session["webauthn_verified_user"] = username
        request.session["webauthn_verified_action"] = "login"
        set_setting("sealed_media_preservation_enabled", "1" if sealed_sender_enabled else "0")
        log_event(username, "LOGIN", details={"init_tor_session": init_tor_session, "force_tor_all_cases": force_tor_all_cases, "sealed_sender_file_downloads_enabled": sealed_sender_enabled, "yubikey_login": True})
        log_event(username, "YUBIKEY_LOGIN_VERIFIED", details=result)
        try:
            if init_tor_session or setting_bool("tor_background_prewarm_enabled", "0"):
                tor_prewarm_background("login-session" if init_tor_session else "login")
        except Exception:
            pass
        row = fetchone("SELECT role FROM users WHERE username=?", (username,))
        redirect = "/setup" if get_setting("setup_required", "0") == "1" and row and row["role"] == "admin" else "/"
        return JSONResponse({"ok": True, "redirect": redirect})
    except HTTPException as exc:
        return JSONResponse({"ok": False, "error": str(exc.detail)}, status_code=exc.status_code)
    except Exception as exc:
        log_event(username, "YUBIKEY_LOGIN_FAILED", details={"error": str(exc)[:500]})
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.get("/audit/verify", response_class=HTMLResponse)
def audit_verify_page(request: Request) -> HTMLResponse:
    require_user(request)
    result = verify_audit_chain()
    return layout(request, "Audit Verification", f"<div class='card {'safe' if result['ok'] else 'danger'}'><h2>Audit chain verification</h2><pre>{h(pretty(result))}</pre><form method='post' action='/audit/seal'><button class='good'>Create audit/storage seal</button></form></div>")


@app.post("/audit/seal")
def audit_seal(request: Request) -> RedirectResponse:
    user = require_admin(request)
    audit = verify_audit_chain()
    store = storage_hash()
    seal = sha256_text(canonical({"audit_head": audit["head"], "storage_hash": store, "created_at": utcnow()}))
    sid = execute("INSERT INTO seals(created_at,actor,audit_head,storage_hash,seal_hash,meta_json) VALUES(?,?,?,?,?,?)", (utcnow(), user["username"], audit["head"], store, seal, pretty({"audit_ok": audit["ok"]})))
    (SEAL_DIR / f"seal_{sid}.json").write_text(pretty({"id": sid, "audit": audit, "storage_hash": store, "seal_hash": seal}), encoding="utf-8")
    log_event(user["username"], "AUDIT_STORAGE_SEAL_CREATED", details={"seal_id": sid, "seal_hash": seal})
    return RedirectResponse("/audit/verify", 303)


@app.get("/stop-report", response_class=HTMLResponse)
def stop_report_page(request: Request) -> HTMLResponse:
    require_user(request)
    return layout(request, "Stop / Report", "<div class='card danger'><h2>Stop and report workflow</h2><p>Use this when suspected illegal/prohibited material is encountered. The tool records that the user stopped and escalated instead of continuing to investigate.</p><form method='post' action='/stop-report'><label>Case ID</label><input name='case_id'><label>Evidence ID</label><input name='evidence_id'><label>Session ID</label><input name='session_id'><label>Reason</label><input name='reason' required><label>Notes / handoff target</label><textarea name='notes'></textarea><button class='danger'>Record stop/report event</button></form></div>")


@app.post("/stop-report")
def stop_report_submit(request: Request, reason: str = Form(...), notes: str = Form(""), case_id: str = Form(""), evidence_id: str = Form(""), session_id: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip() else None
    eid = int(evidence_id) if str(evidence_id).strip() else None
    sid = session_id.strip() or None
    rid = execute("INSERT INTO stop_reports(case_id,evidence_id,session_id,actor,reason,notes,created_at) VALUES(?,?,?,?,?,?,?)", (cid, eid, sid, user["username"], reason, notes, utcnow()))
    log_event(user["username"], "STOP_REPORT_RECORDED", case_id=cid, evidence_id=eid, session_id=sid, details={"stop_report_id": rid, "reason": reason, "notes": notes})
    return RedirectResponse("/?msg=Stop/report%20event%20recorded", 303)


def build_debug_bundle(actor: str = "system") -> bytes:
    """Create a no-plaintext diagnostic bundle with Application Genesis Hash info."""
    ensure_application_genesis_event("global", actor="system")
    buf = io.BytesIO()
    safe_settings = all_settings()
    for secret_key in ["tor_control_password", "master_key_hash", "wrapped_master_key", "wrapped_storage_key", "escrow_public_key_pem", "organization_hard_seal_public_key_pem"]:
        if secret_key in safe_settings:
            safe_settings[secret_key] = "[redacted]"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("application_genesis.json", pretty(application_genesis_report(investigation_id="global")))
        z.writestr("application_build_identity.json", pretty(application_build_identity()))
        z.writestr("self_test.json", pretty(run_self_tests()))
        z.writestr("audit_verification.json", pretty(verify_audit_chain()))
        z.writestr("tor_diagnostics.json", pretty(tor_diagnostics()))
        z.writestr("settings_summary.json", pretty(safe_settings))
        z.writestr("README.txt", "BlindSite debug bundle. This bundle intentionally omits plaintext evidence and redacts local secrets. It includes Application Genesis Hash / Executable Genesis Seal information for build verification.\n")
    return buf.getvalue()


@app.get("/debug-bundle.zip")
def debug_bundle_zip(request: Request) -> StreamingResponse:
    user = require_user(request)
    payload = build_debug_bundle(user["username"])
    log_event(user["username"], "DEBUG_BUNDLE_EXPORTED", details={"application_genesis": application_genesis_report(investigation_id="global"), "size": len(payload)})
    return StreamingResponse(io.BytesIO(payload), media_type="application/zip", headers={"Content-Disposition": "attachment; filename=blindsite_debug_bundle.zip"})


def run_self_tests() -> dict[str, Any]:
    init_db()
    ensure_application_genesis_event("global", actor="system")
    tests: dict[str, Any] = {"app": APP_NAME, "version": APP_VERSION, "time": utcnow()}
    tests["database"] = DB_PATH.exists()
    tests["fernet_key"] = KEY_FILE.exists()
    sample = b"selftest-" + secrets.token_bytes(8)
    tests["encryption_roundtrip"] = decrypt_bytes(encrypt_bytes(sample)) == sample
    tests["application_genesis_hash"] = application_build_identity()
    tests["application_genesis"] = application_genesis_report(investigation_id="global")
    tests["executable_genesis_seal"] = tests["application_genesis"]
    tests["audit"] = verify_audit_chain()
    tests["tor"] = tor_status_data()
    tests["captcha_challenge_display_exception"] = {
        "optional": True,
        "default_enabled": setting_bool("live_allow_captcha_challenge_media_default", "0"),
        "scope": "image-only CAPTCHA/challenge URLs plus inline data:image CAPTCHA elements with CAPTCHA/challenge context; ordinary images/video/audio remain blocked and sealed-preserved according to policy",
        "known_network_candidate_example": captcha_challenge_media_candidate("https://www.google.com/recaptcha/api2/payload?p=test", "image"),
        "known_inline_data_candidate_example": captcha_challenge_inline_data_candidate("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAE=", "class captchabtn alt captcha answer are you not a robot"),
        "ordinary_inline_data_image_blocked_without_context": not captcha_challenge_inline_data_candidate("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAE=", "site logo avatar banner"),
    }
    tests["yubikey_webauthn"] = {
        "enabled": True,
        "optional": True,
        "credential_count": fetchone("SELECT count(*) c FROM webauthn_credentials")["c"],
        "users_requiring_webauthn": fetchone("SELECT count(*) c FROM users WHERE require_webauthn=1")["c"],
        "stepup_max_age_seconds": webauthn_stepup_max_age(),
        "localhost_origin_fix": True,
        "rp_id_behavior": "BlindSite omits explicit rp.id/rpId for localhost/loopback ceremonies so browsers can use the current local origin and avoid SecurityError / operation-is-insecure failures.",
        "reviewer_import_unlock_action_supported": True,
        "note": "Browser-native WebAuthn/YubiKey ceremonies are tested interactively in the browser; self-test verifies database/config presence only.",
    }
    tests["reviewer_import_security"] = {
        "password_protection_supported": True,
        "yubikey_webauthn_protection_supported": True,
        "unlock_inactivity_timeout_seconds": reviewer_import_unlock_timeout_seconds(),
        "protected_import_count": fetchone("SELECT count(*) c FROM reviewer_imports WHERE notes_json LIKE '%review_case_password_hash%' OR notes_json LIKE '%review_case_webauthn_protected%'")["c"],
        "note": "LE reviewer imports can be protected by review-case password and/or optional YubiKey/WebAuthn. Unlock sessions expire after inactivity timeout unless set to 0.",
    }
    try:
        import playwright  # type: ignore
        tests["playwright_python"] = True
    except Exception as exc:
        tests["playwright_python"] = False
        tests["playwright_error"] = str(exc)
    return tests


@app.get("/self-test", response_class=HTMLResponse)
def self_test_page(request: Request) -> HTMLResponse:
    require_user(request)
    return layout(request, "Self-test", f"<div class='card'><h2>Self-test</h2><pre>{h(pretty(run_self_tests()))}</pre></div>")


@app.get("/api/self-test")
def self_test_api(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(run_self_tests())


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "app": APP_NAME, "version": APP_VERSION})


@app.get("/code", response_class=PlainTextResponse)
def code_download(request: Request) -> PlainTextResponse:
    require_admin(request)
    return PlainTextResponse(Path(__file__).read_text(encoding="utf-8"), media_type="text/plain")


# -------------------------------
# Single-file escrow command-line utilities
# -------------------------------

def public_key_fingerprint_from_key_obj(key_obj: Any) -> str:
    if hasattr(key_obj, "public_key"):
        key_obj = key_obj.public_key()
    der = key_obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # type: ignore[attr-defined]
    return sha256_bytes(der)


def cli_load_key_file(path: str, passphrase: str = "") -> Any:
    data = Path(path).read_bytes()
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        if b"PRIVATE KEY" in data:
            return serialization.load_pem_private_key(data, password=password)
        return serialization.load_pem_public_key(data)
    except Exception as exc:
        raise SystemExit(f"Could not load key {path}: {exc}")


def escrow_cli_generate(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Generate escrow RSA keypair for sealed evidence packages")
    p.add_argument("--out", default="escrow_keys", help="Output directory")
    p.add_argument("--bits", type=int, default=3072, choices=[2048, 3072, 4096], help="RSA key size")
    p.add_argument("--passphrase", default="", help="Optional private-key passphrase")
    args = p.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    enc = serialization.BestAvailableEncryption(args.passphrase.encode("utf-8")) if args.passphrase else serialization.NoEncryption()
    priv_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    pub_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = public_key_fingerprint_from_key_obj(private_key)
    (out / "escrow_private_key.pem").write_bytes(priv_pem)
    (out / "escrow_public_key.pem").write_bytes(pub_pem)
    (out / "escrow_public_fingerprint.txt").write_text(fp + "\n", encoding="utf-8")
    print(pretty({"ok": True, "out": str(out), "private_key": str(out / "escrow_private_key.pem"), "public_key": str(out / "escrow_public_key.pem"), "public_key_fingerprint": fp, "private_key_encrypted": bool(args.passphrase)}))
    return 0


def escrow_cli_fingerprint(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Print escrow public-key fingerprint")
    p.add_argument("--key", required=True, help="Public or private PEM key")
    p.add_argument("--passphrase", default="", help="Private-key passphrase, if needed")
    args = p.parse_args(argv)
    key_obj = cli_load_key_file(args.key, args.passphrase)
    fp = public_key_fingerprint_from_key_obj(key_obj)
    print(fp)
    return 0


def escrow_cli_inspect(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Inspect a sealed evidence package without decrypting evidence")
    p.add_argument("package", help="Sealed evidence ZIP")
    p.add_argument("--objects", action="store_true", help="Include object list in output")
    args = p.parse_args(argv)
    summary = sealed_zip_inspect_bytes(Path(args.package).read_bytes())
    if not args.objects:
        summary.pop("objects", None)
    print(pretty(summary))
    return 0


def escrow_cli_decrypt(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Decrypt a sealed evidence package with an escrow private key")
    p.add_argument("package", help="Sealed evidence ZIP")
    p.add_argument("--private-key", required=True, help="Escrow private key PEM")
    p.add_argument("--passphrase", default="", help="Private-key passphrase, if any")
    p.add_argument("--out", required=True, help="Output folder")
    p.add_argument("--decrypt-evidence", action="store_true", help="Recover plaintext evidence objects")
    p.add_argument("--i-understand", action="store_true", help="Required with --decrypt-evidence")
    args = p.parse_args(argv)
    package_bytes = Path(args.package).read_bytes()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    inspect = sealed_zip_inspect_bytes(package_bytes)
    (out / "sealed_package_inspection.json").write_text(pretty({k: v for k, v in inspect.items() if k != "objects"}), encoding="utf-8")
    if not args.decrypt_evidence:
        print(pretty({"ok": True, "mode": "inspect_only", "out": str(out), "note": "No plaintext evidence recovered. Re-run with --decrypt-evidence --i-understand to recover objects.", "package_sha256": inspect.get("package_sha256"), "object_count": inspect.get("object_count")}))
        return 0
    if not args.i_understand:
        raise SystemExit("--decrypt-evidence requires --i-understand because plaintext evidence will be written to disk")
    result = decrypt_sealed_package_to_vault(package_bytes, Path(args.private_key).read_bytes(), args.passphrase, out)
    summary = {
        "ok": True,
        "mode": "plaintext_recovered",
        "out": str(out),
        "package_sha256": sha256_bytes(package_bytes),
        "case_name": (result.get("manifest") or {}).get("case", {}).get("name"),
        "object_count": len(result.get("objects") or []),
        "errors": result.get("errors") or [],
        "vault_storage_key_sha256": result.get("vault_storage_key_sha256"),
    }
    (out / "decryption_summary.json").write_text(pretty(summary), encoding="utf-8")
    print(pretty(summary))
    return 0


def handle_escrow_cli(argv: list[str]) -> bool:
    if not argv:
        return False
    cmd = argv[0]
    aliases = {
        "generate": escrow_cli_generate,
        "escrow-generate": escrow_cli_generate,
        "fingerprint": escrow_cli_fingerprint,
        "escrow-fingerprint": escrow_cli_fingerprint,
        "inspect-sealed": escrow_cli_inspect,
        "escrow-inspect": escrow_cli_inspect,
        "decrypt-sealed": escrow_cli_decrypt,
        "escrow-decrypt": escrow_cli_decrypt,
    }
    if cmd not in aliases:
        return False
    raise SystemExit(aliases[cmd](argv[1:]))


def launch(host: str, port: int, open_browser: bool = True) -> None:
    init_db()
    url = webauthn_public_url_for(host, port) if webauthn_loopback_host(host) else f"http://{host}:{port}"
    bind_note = f"Binding: http://{host}:{port}"
    yubi_note = "YubiKey/WebAuthn local enrollment uses localhost. If you opened 127.0.0.1 manually, BlindSite will redirect WebAuthn pages to localhost."
    print(f"\n{APP_NAME} {APP_VERSION}\nOpen: {url}\n{bind_note}\n{yubi_note}\nDefault login on first run: admin / change-me-now\n")
    if open_browser and setting_bool("auto_open_browser", "1"):
        def opener() -> None:
            time.sleep(1.0)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=opener, daemon=True).start()
    import uvicorn
    # Important: pass the app object, not 'app:app', so the file can be renamed.
    try:
        uvicorn.run(app, host=host, port=port, reload=False)
    finally:
        # Ctrl-C / terminal shutdown cleanup: stop only the Tor provider process
        # that BlindSite started and recorded. This intentionally does not kill
        # unrelated external Tor Browser/Tor instances.
        try:
            stop_managed_tor("terminal-shutdown")
        except Exception as exc:
            tor_append_runtime_log(f"Terminal shutdown Tor cleanup failed: {exc}")


def main() -> None:
    handle_escrow_cli(sys.argv[1:])
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--no-browser", action="store_true", help="Alias for --no-open")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--install-browsers", action="store_true", help="Install Playwright Chromium and Firefox engines")
    args = parser.parse_args()
    if args.self_test:
        print(pretty(run_self_tests()))
        return
    if args.install_browsers:
        cmd = [sys.executable, "-m", "playwright", "install", "chromium", "firefox"]
        print("Running:", " ".join(cmd))
        raise SystemExit(subprocess.call(cmd))
    launch(args.host, args.port, open_browser=not (args.no_open or args.no_browser))


if __name__ == "__main__":
    main()
