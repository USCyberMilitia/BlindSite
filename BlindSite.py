from __future__ import annotations

import argparse
import asyncio
import base64
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
import zipfile
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse, unquote

import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse, PlainTextResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image, ImageFilter
from starlette.middleware.sessions import SessionMiddleware

APP_NAME = "US Cyber Militia / BlindSite"
APP_VERSION = "5.12.1-preservation-queue-setting"
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
VIDEO_EXTS = {".mp4", ".m4v", ".webm", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".mpeg", ".mpg"}
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
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1y8+WnLXjlnuV+HqL/yM
/pGqYkbYzYf0AkoxtUdb8nOjfUPtiDq0dcvMqXkAuHK625lyf1Bq0j8wJai766XG
04ZnZCcK1m4Yw0WMkQEjcn2qlWZB7vniQs07i92pd4EswK9SkCLzCAvDXq3n2xE3
FTLuqGKnjZcr/1uFpUWcsVGUqZ7fYnPIjNtRPiOCUs/i9kJ6ryKsLoOMx7PgvI8f
6HHWwcbh5bdeHXi/P+ntri4EbBPqlnMWdYUeF6SuvlhgLwTt1wSzO9ZHic1iCF4G
hNIoNhbxolBSD41BsuvntXUfebqymWskGbiITLE8plHyrUminzqnZXAkSnOEBqaF
duDHHCiqLxI71KO+rUZ73IbOBy0a0cJCIJ/qeYh7G8NMyW6PfcCw+TTbsXLZkHI6
Vl6hfZaoJvZ43/SPt/YwL7FOq+Aef3GHTqHoX/HTR5txHzvH+gApIDs3kFKjwd7D
yElca3eFGGQM4cijcSpazFVHycZYGOL/DbKxHUjsnYBR5yhPYgDvAz0o+RsKK5ws
SspvPQ4+DFUDQK4zkj/ZAbrsrdsZtQn51yRXcFfNCUrhUCoEivTmJzq8WGOTsIqA
taLsgBIqjLIc+fWr4+CNKSGRnkXAWCe+ebmokCZeDAHpwgX/BrLnjr62v+jJnJ46
cyO7zcKE0wuSAXZ1+tPKP+UCAwEAAQ==
-----END PUBLIC KEY-----
""".strip()

LIVE: dict[str, "LiveBrowserSession"] = {}
LIVE_LOCK = threading.RLock()


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
        "sealed_media_preservation_enabled": "0",
        "sealed_media_preserve_images": "1",
        "sealed_media_preserve_video": "1",
        "sealed_media_preserve_audio": "1",
        "sealed_media_preserve_max_bytes": "52428800",
        "sealed_media_preserve_max_total_bytes": "209715200",
        "sealed_media_preserve_max_items_per_session": "250",
        "sealed_media_preserve_mime_allowlist": "image/\nvideo/\naudio/",
        "sealed_media_preserve_fetch_timeout_ms": "3500",
        "sealed_media_preserve_mode": "balanced",
        "sealed_media_preserve_background_timeout_ms": "18000",
        "sealed_media_preserve_flush_before_capture_ms": "0",
        "sealed_media_preserve_max_pending_tasks": "12",
        "sealed_media_preserve_skip_decorative_fast": "1",
        "live_response_logging": "0",
        "live_blocked_event_logging": "0",
        "organization_hard_seal_media_enabled": "0",
        "organization_hard_seal_public_key_pem": "",
        "organization_hard_seal_public_key_fingerprint": "",
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
        "capture_settle_before_save": "1",
        "capture_wait_after_load_ms": "1500",
        "capture_network_idle_timeout_ms": "8000",
        "capture_settle_timeout_ms": "30000",
        "capture_auto_scroll_enabled": "1",
        "capture_auto_scroll_max_steps": "30",
        "capture_auto_scroll_pause_ms": "550",
        "capture_stable_rounds": "3",
        "live_initial_navigation_timeout_ms": "60000",
        "live_auto_capture_delay_ms": "2500",
        "reviewer_enabled": "1",
        "reviewer_default_render_mode": "auto",
        "capture_chat_profile_enabled": "1",
        "capture_chat_url_keywords": "chat\nchatroom\nrooms",
        "capture_chat_settle_timeout_ms": "10000",
        "capture_chat_network_idle_timeout_ms": "1200",
        "capture_chat_wait_after_load_ms": "500",
        "capture_chat_auto_scroll_max_steps": "8",
    }
    for k, v in defaults.items():
        if fetchone("SELECT 1 FROM settings WHERE key=?", (k,)) is None:
            set_setting(k, v)
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


def log_event(actor: str, action: str, *, case_id: int | None = None, evidence_id: int | None = None, blocked_media_id: int | None = None, session_id: str | None = None, details: dict[str, Any] | None = None) -> str:
    details = details or {}
    prev = fetchone("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1")
    prev_hash = prev["event_hash"] if prev else "GENESIS"
    event = {
        "created_at": utcnow(),
        "actor": actor,
        "action": action,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "blocked_media_id": blocked_media_id,
        "session_id": session_id,
        "details": details,
        "prev_hash": prev_hash,
    }
    event_hash = sha256_text(canonical(event))
    execute("""INSERT INTO audit_events(created_at,actor,action,case_id,evidence_id,blocked_media_id,session_id,details_json,prev_hash,event_hash)
               VALUES(?,?,?,?,?,?,?,?,?,?)""", (event["created_at"], actor, action, case_id, evidence_id, blocked_media_id, session_id, json.dumps(details, ensure_ascii=False), prev_hash, event_hash))
    return event_hash


def verify_audit_chain() -> dict[str, Any]:
    rows = fetchall("SELECT * FROM audit_events ORDER BY id ASC")
    prev = "GENESIS"
    bad: list[dict[str, Any]] = []
    for r in rows:
        details = jloads(r["details_json"], {})
        event = {"created_at": r["created_at"], "actor": r["actor"], "action": r["action"], "case_id": r["case_id"], "evidence_id": r["evidence_id"], "blocked_media_id": r["blocked_media_id"], "session_id": r["session_id"], "details": details, "prev_hash": r["prev_hash"]}
        expected = sha256_text(canonical(event))
        if r["prev_hash"] != prev or r["event_hash"] != expected:
            bad.append({"id": r["id"], "expected": expected, "actual": r["event_hash"], "expected_prev": prev, "actual_prev": r["prev_hash"]})
        prev = r["event_hash"]
    return {"ok": not bad, "count": len(rows), "head": prev, "bad": bad[:20]}


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
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=app_secret(), same_site="lax", https_only=False)
serializer = URLSafeTimedSerializer(app_secret(), salt="blindsite-view-token")


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
      <a href='/'>Dashboard</a><a href='/cases'>Cases</a><a href='/live'>Live Sessions</a><a href='/captures'>Saved Pages</a><a href='/media'>Media</a><a href='/reviewer'>LE Reviewer</a><a href='/search'>Search</a><a href='/reports'>Reports</a><a href='/blocked'>Blocked Media</a><a href='/approvals'>Approvals</a><a href='/custody'>Custody</a><a href='/settings'>Settings</a>{setup}
      <span class='right'>Signed in as {h(u['username'])} ({h(u['role'])}) <a href='/logout'>Logout</a></span>
    </nav>
    """


def flash(msg: str | None = None) -> str:
    return f"<div class='flash'>{h(msg)}</div>" if msg else ""


def layout(request: Request, title: str, body: str) -> HTMLResponse:
    edition = get_setting("edition", "lockdown")
    safe = get_setting("hard_default_safe_mode", "1")
    css = """
    :root{--bg:#0f172a;--panel:#111827;--panel2:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--line:#334155;--accent:#38bdf8;--danger:#ef4444;--warn:#f59e0b;--good:#22c55e}
    *{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#020617,#0f172a 45%,#111827);color:var(--text);font-family:Segoe UI,Roboto,Arial,sans-serif}a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}
    nav{position:sticky;top:0;z-index:10;background:#020617cc;backdrop-filter:blur(8px);border-bottom:1px solid var(--line);padding:12px 18px}nav a{margin-left:14px}.right{float:right}.wrap{max-width:1380px;margin:0 auto;padding:22px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}.card{background:#111827e6;border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0;box-shadow:0 12px 30px #0005}.card h2,.card h3{margin-top:0}.danger{border-color:#7f1d1d!important;background:#2a1015!important}.safe{border-color:#14532d!important}.warn{border-color:#78350f!important}.muted{color:var(--muted)}.small{font-size:.85rem}.mono,code,pre{font-family:Consolas,Menlo,monospace}pre{white-space:pre-wrap;background:#020617;border:1px solid var(--line);border-radius:10px;padding:12px;max-height:520px;overflow:auto}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}th{color:#bae6fd}input,select,textarea{width:100%;padding:10px;border-radius:9px;border:1px solid #475569;background:#020617;color:var(--text);margin:4px 0 10px}textarea{min-height:90px}label{display:block;font-weight:600}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}.row>*{flex:1;min-width:180px}button,.button{display:inline-block;border:0;border-radius:9px;padding:10px 14px;background:#0284c7;color:white;font-weight:700;cursor:pointer;margin:3px}.button.secondary,button.secondary{background:#475569}.button.danger,button.danger{background:#dc2626}.button.warn,button.warn{background:#d97706}.button.good,button.good{background:#16a34a}.badge{display:inline-block;border:1px solid #475569;border-radius:999px;padding:3px 8px;margin:2px;background:#020617;color:#dbeafe;font-size:.8rem}.badge.good{border-color:#15803d;color:#86efac}.badge.bad{border-color:#991b1b;color:#fca5a5}.badge.warn{border-color:#92400e;color:#fcd34d}.badge.info{border-color:#0369a1;color:#7dd3fc}.viewer{min-height:300px;border:2px dashed #475569;border-radius:12px;background:#020617;display:flex;align-items:center;justify-content:center;text-align:center;overflow:auto}.viewer img{max-width:100%;max-height:75vh}.table-scroll{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:10px}.table-scroll table{min-width:980px}.urlcell{min-width:420px;max-width:900px;white-space:normal;word-break:break-all}.hashcell{min-width:320px;word-break:break-all}.media-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}.thumb{background:#020617;border:1px solid var(--line);border-radius:10px;min-height:180px;display:flex;align-items:center;justify-content:center;overflow:hidden}.thumb img{max-width:100%;max-height:240px}.saved-frame,.render-frame{width:100%;height:72vh;border:1px solid var(--line);border-radius:12px;background:#020617}.flash{padding:12px;border:1px solid #0369a1;background:#082f49;border-radius:12px;margin:10px 0}.noprint{}@media print{nav,.noprint,button,.button{display:none!important}body{background:white;color:black}.card{background:white;color:black;border:1px solid #aaa;box-shadow:none}a{color:black}}
    """
    banner = f"<div class='card {'danger' if edition=='lockdown' else 'warn' if edition=='supervised' else ''}'><b>Custody:</b> {badge(custody_label(),'info')} <b>Edition:</b> {badge(edition,'good' if edition=='lockdown' else 'warn')} <b>Hard default safe mode:</b> {badge(safe,'good' if truthy(safe) else 'warn')} <b>Version:</b> {h(APP_VERSION)}</div>"
    html = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{h(title)} - {APP_NAME}</title><style>{css}</style></head><body>{nav(request)}<main class='wrap'>{banner}<h1>{h(title)}</h1>{body}</main></body></html>"""
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


def start_bundled_tor_if_possible() -> tuple[bool, str]:
    tor_exe = detect_tor_executable()
    if not tor_exe:
        return False, "No bundled/standalone tor executable found"
    host = get_setting("tor_host", "127.0.0.1")
    preferred_ports = []
    for raw in [get_setting("tor_socks_port", "9050"), "9150", "9050"]:
        try:
            port = int(str(raw).strip())
            if port not in preferred_ports:
                preferred_ports.append(port)
        except Exception:
            pass
    data_dir = DATA_DIR / "tor_runtime"
    data_dir.mkdir(parents=True, exist_ok=True)
    last_error = ""
    for port in preferred_ports:
        try:
            if socket_open(host, port):
                set_setting("tor_socks_port", str(port))
                return True, f"Tor already listening on {host}:{port}"
            cmd = [str(tor_exe), "--SocksPort", str(port), "--DataDirectory", str(data_dir)]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(tor_exe.parent))
            for _ in range(30):
                time.sleep(0.25)
                if socket_open(host, port):
                    set_setting("tor_socks_port", str(port))
                    log_event("system", "TOR_PROVIDER_STARTED", details={"tor_exe": str(tor_exe), "socks_port": port})
                    return True, f"Started Tor provider on {host}:{port}"
        except Exception as exc:
            last_error = str(exc)
    return False, last_error or "Tor executable started but no SOCKS port opened"


def ensure_tor_proxy_ready() -> tuple[bool, str]:
    port = choose_open_tor_socks_port()
    if port:
        return True, f"Tor SOCKS is open on {get_setting('tor_host','127.0.0.1')}:{port}"
    if setting_bool("tor_auto_start_from_browser_bundle", "1"):
        return start_bundled_tor_if_possible()
    return False, "Tor SOCKS is not open and auto-start is disabled"

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


def live_policy_blocks(browser_resource_type: str, policy: str) -> bool:
    # Critical hang fix: never block document/script/stylesheet/xhr/fetch just because media blocking is on.
    rt = browser_resource_type.lower()
    if rt == "media":
        logical = "media"
    elif rt in {"image", "font"}:
        logical = rt
    else:
        return False
    return policy_blocks_resource(logical, policy)


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
    skip = {"host", "connection", "content-length", "accept-encoding"}
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
    raw = get_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/")
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
        "max_items_per_session": safe_int(get_setting("sealed_media_preserve_max_items_per_session", "250"), 250, min_value=0),
        "mime_allowlist": get_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/"),
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
    session_id = str((model.get("metadata") or {}).get("session_id") or "")
    clauses = ["a.root_evidence_id=?"]
    params: list[Any] = [ev["id"]]
    if session_id:
        clauses.append("a.session_id=?")
        params.append(session_id)
    params.append(limit)
    rows = fetchall(f"""SELECT a.*, e.filename, e.kind, e.storage_mode, e.object_path, e.encrypted, e.disable_plaintext_export, e.lock_direct_original_access
                       FROM captured_assets a JOIN evidence e ON e.id=a.resource_evidence_id
                       WHERE {' OR '.join(clauses)}
                       ORDER BY a.id DESC LIMIT ?""", tuple(params))
    # Backward-compatible fallback: direct/full-forensic media children from older builds.
    if rows:
        return rows
    return fetchall("""SELECT NULL id, e.case_id, '' session_id, e.parent_evidence_id root_evidence_id, e.id resource_evidence_id,
                             e.source_ref original_url, e.sha256 url_sha256, e.kind resource_type, e.mime_type, e.size, e.sha256, e.created_at, e.meta_json,
                             e.filename, e.kind, e.storage_mode, e.object_path, e.encrypted, e.disable_plaintext_export, e.lock_direct_original_access
                      FROM evidence e WHERE e.parent_evidence_id=? AND e.source_type IN ('allowed_media_download','captured_asset','live_captured_asset','sealed_preserved_blocked_media')
                      ORDER BY e.id DESC LIMIT ?""", (ev["id"], limit))


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
    csp["content"] = "default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
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


def page_capture_rows(case_id: int | None = None, q: str = "", session_id: str | None = None, limit: int = 500) -> list[sqlite3.Row]:
    clauses = ["1=1"]
    params: list[Any] = []
    if case_id is not None:
        clauses.append("p.case_id=?")
        params.append(case_id)
    if session_id:
        clauses.append("p.session_id=?")
        params.append(session_id)
    if q:
        like = f"%{q}%"
        clauses.append("(p.page_url LIKE ? OR p.title LIKE ? OR e.filename LIKE ? OR e.sha256 LIKE ?)")
        params.extend([like, like, like, like])
    params.append(limit)
    return fetchall(f"""SELECT p.*, e.sha256, e.filename, e.storage_mode, e.raw_persisted, e.mime_type, c.name case_name
                       FROM page_captures p
                       JOIN evidence e ON e.id=p.evidence_id
                       LEFT JOIN cases c ON c.id=p.case_id
                       WHERE {' AND '.join(clauses)}
                       ORDER BY p.id DESC LIMIT ?""", tuple(params))


def saved_media_rows(case_id: int | None = None, q: str = "", kind: str = "all", state: str = "all", limit: int = 300) -> list[sqlite3.Row]:
    clauses = ["(lower(e.kind) IN ('image','video','audio','media') OR lower(e.mime_type) LIKE 'image/%' OR lower(e.mime_type) LIKE 'video/%' OR lower(e.mime_type) LIKE 'audio/%' OR e.storage_mode IN ('allowed_media_original','materialized_original'))"]
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
    if q:
        like = f"%{q}%"
        clauses.append("(e.filename LIKE ? OR e.source_ref LIKE ? OR e.sha256 LIKE ? OR e.mime_type LIKE ?)")
        params.extend([like, like, like, like])
    params.append(limit)
    return fetchall(f"""SELECT e.*, c.name case_name FROM evidence e LEFT JOIN cases c ON c.id=e.case_id
                       WHERE {' AND '.join(clauses)} ORDER BY e.id DESC LIMIT ?""", tuple(params))


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


def build_case_report_html(data: dict[str, Any]) -> str:
    case = data.get("case") or {}
    ev_rows = "".join(f"<tr><td>#{h(e.get('id'))}</td><td>{h(e.get('filename'))}</td><td>{h(e.get('kind'))}</td><td>{h(e.get('storage_mode'))}</td><td><code>{h(e.get('sha256'))}</code></td></tr>" for e in data.get("evidence", []))
    page_rows = "".join(f"<tr><td>#{h(c.get('evidence_id'))}</td><td><a href='saved_pages/evidence_{h(c.get('evidence_id'))}.html'>{h(c.get('title') or c.get('filename') or 'Saved page')}</a></td><td>{h(c.get('capture_mode'))}</td><td>{h(c.get('page_url'))}</td></tr>" for c in data.get("page_captures", []))
    blocked_rows = "".join(f"<tr><td>#{h(b.get('id'))}</td><td>{h(b.get('resource_type'))}</td><td>{'downloaded' if b.get('downloaded') else 'not downloaded'}</td><td><code>{h(b.get('metadata_record_hash'))}</code></td><td>{h(b.get('media_url'))}</td></tr>" for b in data.get("blocked_media", []))
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Case report {h(case.get('id'))}</title><style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;vertical-align:top}}code{{word-break:break-all}}.good{{color:green}}.bad{{color:#b91c1c}}</style></head><body><h1>BlindSite case report</h1><h2>{h(case.get('name',''))}</h2><p>Generated: {h(data.get('generated_at'))}</p><p>Audit chain: <b class='{'good' if data.get('audit_verification',{}).get('ok') else 'bad'}'>{'verified' if data.get('audit_verification',{}).get('ok') else 'problem detected'}</b></p><h2>Saved pages</h2><table><tr><th>Evidence</th><th>Offline viewer</th><th>Capture mode</th><th>Source URL</th></tr>{page_rows or '<tr><td colspan="4">No saved pages.</td></tr>'}</table><h2>Evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>Storage</th><th>SHA-256</th></tr>{ev_rows}</table><h2>Blocked media</h2><table><tr><th>ID</th><th>Type</th><th>State</th><th>Metadata hash</th><th>URL</th></tr>{blocked_rows}</table></body></html>"""


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


class LiveBrowserSession:
    def __init__(self, *, session_id: str, case_id: int | None, actor: str, start_url: str, browser_choice: str, use_tor: bool, media_policy: str, headless: bool, user_agent_profile: str | None = None, custom_user_agent: str | None = None, download_allowed_media: bool = False, auto_capture: bool = False, settle_before_capture: bool = True, sealed_media_preservation_session: bool = True):
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
        self.sealed_preserve_max_pending_tasks = safe_int(get_setting("sealed_media_preserve_max_pending_tasks", "12"), 12, min_value=1, max_value=1000)
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
                await self.context.route("**/*", self._route)
                self.context.on("page", self._on_new_page)
                self.page = await self.context.new_page()
                await self._register_page(self.page, reason="initial")
                execute("UPDATE browser_sessions SET status='running' WHERE session_id=?", (self.session_id,))
                log_event(self.actor, "LIVE_SESSION_STARTED", case_id=self.case_id, session_id=self.session_id, details={"browser": self.browser_choice, "use_tor": self.use_tor, "media_policy": self.media_policy, "headless": self.headless, "download_allowed_media": self.download_allowed_media, "sealed_media_preservation": self.sealed_media_policy_cache, "user_agent_profile": self.user_agent_meta.get("profile"), "user_agent_sha256": self.user_agent_meta.get("user_agent_sha256")})
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
                log_event(self.actor, "LIVE_SESSION_STOPPED", case_id=self.case_id, session_id=self.session_id, details={"requests": self.requests, "blocked": self.blocked, "sealed_preserved": self.sealed_preserved, "sealed_preserved_bytes": self.sealed_preserved_bytes, "sealed_preserve_skipped": self.sealed_preserve_skipped, "current_url": self.current_url, "sealed_preserve_timeouts": self.sealed_preserve_timeout_count, "sealed_preserve_pending": len(self.sealed_preserve_bg_tasks)})
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
        if live_policy_blocks(rt, self.media_policy):
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
        max_pending = safe_int(get_setting("sealed_media_preserve_max_pending_tasks", "40"), 40, min_value=1, max_value=1000)
        if len(self.sealed_preserve_bg_tasks) >= max_pending:
            self.sealed_preserve_skipped += 1
            return False, f"sealed preservation skipped: background queue full ({len(self.sealed_preserve_bg_tasks)} >= {max_pending})"
        return True, "ok"

    def _download_preserved_media_requests(self, media_url: str, headers: dict[str, str], timeout_ms: int, max_each: int) -> dict[str, Any]:
        sess = request_session(self.use_tor, self.user_agent_profile, self.custom_user_agent)
        sess.headers.clear()
        sess.headers.update(headers)
        timeout_s = max(1.0, float(timeout_ms) / 1000.0)
        started = time.time()
        with sess.get(media_url, stream=True, timeout=(min(8.0, timeout_s), timeout_s), allow_redirects=True) as r:
            response_headers = dict(r.headers or {})
            mt = (header_get(response_headers, "Content-Type") or mimetypes.guess_type(media_url)[0] or "application/octet-stream").split(";", 1)[0].strip()
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
            return {"ok": bool(body), "reason": "ok" if body else "sealed preservation skipped: empty response body", "headers": response_headers, "status_code": r.status_code, "mime_type": mt, "content_length": str(len(body)), "body": body, "final_url": r.url, "elapsed_ms": int((time.time() - started) * 1000)}

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
                bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=None, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical, request_method=method + "+sealed-preserve-bg-failed", referrer=referrer, policy=self.media_policy, reason=reason, request_headers=headers, response_headers=dict(result.get("headers") or {}), status_code=result.get("status_code"), content_type=result.get("mime_type"), content_length=str(result.get("content_length") or ""), downloaded=False, use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
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
            eid = persist_sealed_preserved_media(actor=self.actor, case_id=self.case_id, session_id=self.session_id, root_evidence_id=None, page_url=page_url, media_url=media_url, resource_type=logical2, mime_type=mt, payload=body, request_method=method + "+sealed-preserve-bg", referrer=referrer, request_headers=headers, response_headers=response_headers, status_code=status_code, reason="blocked from local display by live browser; background encrypted preservation for sealed reviewer handoff", source_engine="live_browser_background_fast_route", final_url=str(result.get("final_url") or media_url))
            bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=None, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical2, request_method=method + "+sealed-preserve-bg", referrer=referrer, policy=self.media_policy, reason="blocked from local display by live browser; background encrypted preservation complete", request_headers=headers, response_headers=response_headers, status_code=status_code, content_type=mt, content_length=str(len(body)), downloaded=True, content_sha256=sha256_bytes(body), use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
            execute("UPDATE blocked_media SET materialized_evidence_id=? WHERE id=?", (eid, bid))
            with self.sealed_preserve_lock:
                self.sealed_preserved += 1
                self.sealed_preserved_bytes += len(body)
            log_event(self.actor, "SEALED_BLOCKED_MEDIA_PRESERVED_BACKGROUND", case_id=self.case_id, evidence_id=eid, blocked_media_id=bid, session_id=self.session_id, details={"media_url_sha256": sha256_text(media_url), "resource_type": logical2, "size": len(body), "elapsed_ms": result.get("elapsed_ms"), "fast_live_route": True})
            return {"ok": True, "evidence_id": eid, "blocked_media_id": bid, "size": len(body)}
        except Exception as exc:
            reason = f"sealed preservation failed in background: {str(exc)[:450]}"
            try:
                bid = record_blocked_media(actor=self.actor, case_id=self.case_id, root_evidence_id=None, session_id=self.session_id, page_url=page_url, media_url=media_url, resource_type=logical, request_method=method + "+sealed-preserve-bg-error", referrer=referrer, policy=self.media_policy, reason=reason, request_headers=headers, use_tor=self.use_tor, head_probe=False, user_agent_profile=self.user_agent_profile, custom_user_agent=self.custom_user_agent)
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

    def _queue_blocked_preservation_fast(self, *, media_url: str, logical: str, method: str, req_headers: dict[str, Any], page_url: str, browser_resource_type: str = "") -> str:
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
        item = {"media_url": media_url, "logical": logical, "method": method, "request_headers": clean_headers, "page_url": page_url or self.current_url, "referrer": req_headers.get("referer") or page_url or self.current_url}
        try:
            task = asyncio.create_task(self._preserve_blocked_media_background_fast(item))
            self.sealed_preserve_bg_tasks.add(task)
            task.add_done_callback(lambda t: self.sealed_preserve_bg_tasks.discard(t))
            return "sealed preservation queued in background; route returned immediately"
        except Exception as exc:
            self._defer_blocked_media_record(media_url=media_url, logical=logical, method=method, req_headers=req_headers, page_url=page_url, reason=f"sealed preservation queue failed: {str(exc)[:300]}")
            return "sealed preservation queue failed"

    def preservation_status(self) -> dict[str, Any]:
        """Return lightweight live media-preservation progress for UI polling."""
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
        total_seen = max(0, preserved + skipped + cancelled + pending + deferred_pending)
        complete = max(0, preserved + skipped + cancelled)
        pct = int((complete / total_seen) * 100) if total_seen else 100
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
            "preserved": preserved,
            "preserved_bytes": bytes_done,
            "skipped_or_failed": skipped,
            "timeouts": timeouts,
            "cancelled": cancelled,
            "queue_limit": int(self.sealed_preserve_max_pending_tasks),
            "cancel_requested": bool(self.sealed_preserve_cancel_requested.is_set()),
            "progress_percent": max(0, min(100, pct)),
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

    async def _route(self, route, request) -> None:
        self.requests += 1
        rt = request.resource_type
        req_headers = dict(request.headers or {})
        if live_policy_blocks(rt, self.media_policy):
            self.blocked += 1
            logical = classify_resource(request.url, browser_type=rt)
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
        network_idle_ms = max(500, int(get_setting("capture_network_idle_timeout_ms", "8000") or "8000"))
        wait_after_ms = max(0, int(get_setting("capture_wait_after_load_ms", "1500") or "1500"))
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
        auto_scroll = setting_bool("capture_auto_scroll_enabled", "1")
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
        """Collect dynamic/lazy media references from the live DOM before saving.

        This catches currentSrc/srcset/poster/background/meta image values that may
        not be visible in static HTML until JavaScript has hydrated the page.
        """
        page = page or self.page
        if page is None:
            return []
        try:
            refs = await page.evaluate("""() => {
                const out = [];
                const add = (url, tag, attr) => {
                    if (!url || typeof url !== 'string') return;
                    const v = url.trim();
                    if (!v || v.startsWith('data:') || v.startsWith('blob:') || v.startsWith('javascript:')) return;
                    out.push({url: v, tag, attr, inline: false, dynamic: true});
                };
                for (const img of Array.from(document.images || [])) {
                    add(img.currentSrc, 'img', 'currentSrc');
                    add(img.src, 'img', 'src');
                    add(img.getAttribute('data-src'), 'img', 'data-src');
                    add(img.getAttribute('data-lazy-src'), 'img', 'data-lazy-src');
                    const ss = img.getAttribute('srcset') || '';
                    for (const part of ss.split(',')) add((part.trim().split(/\\s+/)[0] || ''), 'img', 'srcset');
                }
                for (const src of Array.from(document.querySelectorAll('picture source, video source, audio source, source'))) {
                    add(src.src, src.tagName.toLowerCase(), 'src');
                    const ss = src.getAttribute('srcset') || '';
                    for (const part of ss.split(',')) add((part.trim().split(/\\s+/)[0] || ''), src.tagName.toLowerCase(), 'srcset');
                }
                for (const v of Array.from(document.querySelectorAll('video,audio'))) {
                    add(v.currentSrc, v.tagName.toLowerCase(), 'currentSrc');
                    add(v.src, v.tagName.toLowerCase(), 'src');
                    add(v.getAttribute('poster'), v.tagName.toLowerCase(), 'poster');
                }
                for (const meta of Array.from(document.querySelectorAll('meta[property="og:image"],meta[property="og:video"],meta[name="twitter:image"],meta[name="twitter:player"]'))) {
                    add(meta.getAttribute('content'), 'meta', meta.getAttribute('property') || meta.getAttribute('name') || 'content');
                }
                for (const el of Array.from(document.querySelectorAll('[style]'))) {
                    const style = el.getAttribute('style') || '';
                    for (const m of style.matchAll(/url\\((['\\"]?)(.*?)\\1\\)/g)) add(m[2], 'style', 'url');
                }
                for (const a of Array.from(document.querySelectorAll('a[href]'))) {
                    const href = a.getAttribute('href') || '';
                    if (/\\.(jpg|jpeg|png|gif|webp|avif|bmp|svg|mp4|webm|mov|m4v|mp3|wav|ogg)(\\?|#|$)/i.test(href)) add(href, 'a', 'href');
                }
                const seen = new Set();
                return out.filter(r => { const k = `${r.url}|${r.tag}|${r.attr}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 2500);
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
        update_evidence_meta(eid, {"page_capture_id": pcid, "captured_asset_count": len(asset_ids), "sealed_preserved_asset_links": len(preserved_link_ids), "sealed_page_snapshot_id": sealed_snapshot_id, "deferred_blocked_media_flush": deferred_blocked_flush_meta, "captured_asset_cache_skipped": self.asset_skipped, "captured_asset_total_bytes": self.asset_bytes_total})
        log_event(self.actor, "LIVE_CURRENT_PAGE_CAPTURED", case_id=self.case_id, evidence_id=eid, session_id=self.session_id, details={"url_sha256": sha256_text(url), "raw_persisted": raw_persisted, "page_capture_id": pcid, "captured_assets": len(asset_ids), "sealed_preserved_asset_links": len(preserved_link_ids), "sealed_page_snapshot_id": sealed_snapshot_id, "deferred_blocked_media_flush": deferred_blocked_flush_meta, "asset_skipped": self.asset_skipped, "auto_capture": bool(auto), "settle_elapsed_ms": settle_meta.get("settle_elapsed_ms")})
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

    def open_tabs_sync(self) -> list[dict[str, Any]]:
        if self.loop is None or self.loop.is_closed():
            return []
        async def inner() -> list[dict[str, Any]]:
            out = []
            for i, p in enumerate(self._live_pages_snapshot(), start=1):
                try:
                    out.append({"index": i, "url": p.url, "title": await p.title()})
                except Exception:
                    pass
            return out
        try:
            return list(asyncio.run_coroutine_threadsafe(inner(), self.loop).result(timeout=10))
        except Exception:
            return []

    def stop_sync(self) -> None:
        self.stop_flag.set()


def start_live_session(*, actor: str, case_id: int | None, start_url: str, browser_choice: str, use_tor: bool, media_policy: str, headless: bool, user_agent_profile: str | None = None, custom_user_agent: str | None = None, download_allowed_media: bool = False, auto_capture: bool = False, settle_before_capture: bool = True, sealed_media_preservation_session: bool = True) -> LiveBrowserSession:
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
    execute("""INSERT INTO browser_sessions(session_id,case_id,actor,browser_choice,start_url,use_tor,media_policy,headless,status,current_url,created_at,meta_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (sid, case_id, actor, browser_choice, normalize_url(start_url), 1 if use_tor else 0, policy, 1 if headless else 0, "starting", normalize_url(start_url), utcnow(), pretty({"version": APP_VERSION, "user_agent_profile": ua_meta["profile"], "user_agent_label": ua_meta["label"], "user_agent_sha256": ua_meta["user_agent_sha256"], "user_agent": ua_meta["user_agent"], "download_allowed_media": bool(download_allowed_media), "sealed_media_preservation": sealed_media_preservation_policy(case), "auto_capture": bool(auto_capture), "settle_before_capture": bool(settle_before_capture), "sealed_media_preservation_session": bool(sealed_media_preservation_session), "capture_settle_timeout_ms": get_setting("capture_settle_timeout_ms", "30000"), "capture_auto_scroll_enabled": get_setting("capture_auto_scroll_enabled", "1"), "tor_browser_path": str(detect_tor_browser_executable() or "") if browser_choice == "torbrowser" else ""})))
    session = LiveBrowserSession(session_id=sid, case_id=case_id, actor=actor, start_url=start_url, browser_choice=browser_choice, use_tor=use_tor, media_policy=policy, headless=headless, user_agent_profile=ua_meta["profile"], custom_user_agent=custom_user_agent or "", download_allowed_media=download_allowed_media, auto_capture=auto_capture, settle_before_capture=settle_before_capture, sealed_media_preservation_session=sealed_media_preservation_session)
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


def live_preservation_status_for(sid: str) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        row = rowdict(fetchone("SELECT * FROM browser_sessions WHERE session_id=?", (sid,)))
        if not row:
            raise HTTPException(404, "Live session not found")
        meta = jloads(row.get("meta_json"), {})
        return {"ok": True, "session_id": sid, "running": False, "status": row.get("status"), "mode": meta.get("sealed_media_preservation", {}).get("mode") or get_setting("sealed_media_preserve_mode", "balanced"), "requests": 0, "blocked": fetchone("SELECT count(*) c FROM blocked_media WHERE session_id=?", (sid,))["c"], "pending_tasks": 0, "deferred_metadata_pending": 0, "preserved": fetchone("SELECT count(*) c FROM blocked_media WHERE session_id=? AND downloaded=1", (sid,))["c"], "preserved_bytes": 0, "skipped_or_failed": fetchone("SELECT count(*) c FROM blocked_media WHERE session_id=? AND downloaded=0", (sid,))["c"], "timeouts": 0, "cancelled": 0, "queue_limit": 0, "cancel_requested": False, "progress_percent": 100}
    return session.preservation_status()


def cancel_live_preservation(sid: str) -> dict[str, Any]:
    with LIVE_LOCK:
        session = LIVE.get(sid)
    if not session:
        raise HTTPException(409, "This live session is not running in this app process.")
    return session.cancel_preservation_sync()


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    return layout(request, "Login", f"""{flash(error)}<div class='card'><h2>Sign in</h2><form method='post' action='/login'><label>Username</label><input name='username' autofocus><label>Password</label><input name='password' type='password'><button>Login</button></form><p class='muted'>First run default: admin / change-me-now</p></div>""")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    init_db()
    row = fetchone("SELECT * FROM users WHERE username=?", (username.strip(),))
    if not row or not check_password(password, row["password_hash"]):
        return RedirectResponse("/login?error=Invalid%20login", 303)
    request.session["username"] = row["username"]
    log_event(row["username"], "LOGIN")
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
    body = f"""{flash(msg)}<div class='card warn'><h2>First-run setup</h2><p>Choose who controls original reveal/decrypt authority. Organization mode is for agencies and internal teams. Civilian Unknown Master Key mode lets a civilian export sealed encrypted evidence for USCM/law-enforcement handoff without knowing the reveal key.</p>
    <form method='post' action='/setup' enctype='multipart/form-data'>
      <label>New admin password</label><input type='password' name='password' required minlength='10'>
      <div class='grid'>
        <div class='card'><h3><label><input type='radio' name='custody_choice' value='organization' checked> Organization-Controlled Key</label></h3><p>Your organization/admin creates and controls the master reveal key. Normal evidence remains encrypted in the local vault and reveal is controlled by organization policy.</p><label>Master reveal key</label><input type='password' name='master_key' minlength='12'><label>Default edition</label><select name='edition'><option value='lockdown'>Lockdown / compliance-safe</option><option value='supervised'>Supervised approval mode</option><option value='lab'>Lab/full-forensic mode</option></select><label><input type='checkbox' name='hard_safe' value='1' checked> Hard default safe mode</label><div class='card warn'><h3>Optional organization hard-sealed media</h3><p class='small muted'>For blocked media preservation, an organization can paste its escrow public key so preserved blocked media is sealed for reviewer/private-key access and cannot be decrypted by the local vault key.</p><label><input type='checkbox' name='organization_hard_seal_media_enabled' value='1'> Hard-seal preserved blocked media to organization escrow public key</label><label>Organization escrow public key PEM</label><textarea name='organization_hard_seal_public_key_pem' rows='7' placeholder='Paste organization/reviewer escrow_public_key.pem here'></textarea></div></div>
        <div class='card safe'><h3><label><input type='radio' name='custody_choice' value='civilian_unknown_master'> Civilian Unknown Master Key</label></h3><p>The local user does not create, know, or control the private reveal key. Lockdown stays forced. Sensitive/original evidence is hard-sealed to the embedded USCM escrow public key so it cannot be decrypted by the local civilian installation.</p><label>USCM escrow public key PEM</label><textarea name='escrow_public_key' rows='9' readonly>{h(bundled)}</textarea><p class='small muted'>Civilian Unknown Master Key mode uses this USCM public key only. Do not use your own key for this mode; doing so defeats the custody separation. Organizations that need to control their own keys should use Organization-Controlled Key mode.</p></div>
        <div class='card warn'><h3>Sealed Media Preservation Mode</h3><p class='small muted'>Optional in both custody modes. Block images/video/audio from user display, but preserve selected blocked media for sealed export and cleared-reviewer access. Civilian mode always hard-seals to the USCM key. Organization mode can either use normal local vault encryption or the optional organization hard-seal public key above.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1'> Enable sealed media preservation by default</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' checked> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' checked> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' checked> Preserve blocked audio encrypted</label><label>Maximum bytes per preserved media object</label><input name='sealed_media_preserve_max_bytes' value='52428800'><p class='small muted'>Default is 52,428,800 bytes. Preserved media never renders in the live browser when blocked; it is stored encrypted and linked to captured pages for sealed export/reviewer viewing.</p></div>
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
    table = "".join(f"<tr><td><a href='/cases/{r['id']}'>#{r['id']}</a></td><td>{h(r['name'])}</td><td>{badge(r['mode'],'good' if r['mode']=='lockdown' else 'warn')}</td><td>{badge('safe','good') if r['compliance_safe'] else badge('not safe','warn')}</td><td>{h(r['default_media_policy'])}</td><td>{badge('sealed media preserve','warn') if r['sealed_media_preservation_enabled'] else ''}</td><td>{h(r['created_at'])}</td></tr>" for r in rows)
    body = f"""<div class='card'><h2>Create case</h2><form method='post' action='/cases'>
      <label>Name</label><input name='name' required>
      <label>Description</label><textarea name='description'></textarea>
      <div class='row'><div><label>Mode</label><select name='mode'><option value='lockdown'>Lockdown</option><option value='supervised'>Supervised</option><option value='lab'>Lab/full-forensic</option></select></div>
      <div><label>Default media policy</label><select name='media_policy'><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div>
      <label><input type='checkbox' name='force_tor' value='1'> Force Tor for this case</label>
      <label><input type='checkbox' name='raw_root_allowed' value='1'> Allow raw root persistence in lab/supervised workflows</label>
      <div class='card warn'><h3>Sealed Media Preservation for this case</h3><p class='small muted'>Active in both custody modes when the global setting and this case setting are enabled. Media remains blocked from display, but selected blocked media can be stored encrypted for sealed export and cleared review.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' {'checked' if setting_bool('sealed_media_preservation_enabled','0') and civilian_unknown_master_mode() else ''}> Enable for this case</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' checked> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' checked> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' checked> Preserve blocked audio encrypted</label><label>Case max bytes per preserved media object</label><input name='sealed_media_preserve_max_bytes' value='{h(get_setting('sealed_media_preserve_max_bytes','52428800'))}'></div>
      <button>Create case</button></form></div>
      <div class='card'><h2>Cases</h2><table><tr><th>ID</th><th>Name</th><th>Mode</th><th>Safe</th><th>Media policy</th><th>Sealed media</th><th>Created</th></tr>{table}</table></div>"""
    return layout(request, "Cases", body)


@app.post("/cases")
def create_case(request: Request, name: str = Form(...), description: str = Form(""), mode: str = Form("lockdown"), media_policy: str = Form("block_images_video"), force_tor: str | None = Form(None), raw_root_allowed: str | None = Form(None), sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800")) -> RedirectResponse:
    user = require_user(request)
    if mode not in EDITIONS:
        mode = "lockdown"
    if media_policy not in MEDIA_POLICIES:
        media_policy = "block_images_video"
    compliance = 1 if mode == "lockdown" or setting_bool("hard_default_safe_mode", "1") else 0
    cid = execute("""INSERT INTO cases(name,description,mode,compliance_safe,irreversible_lock,never_materialize_originals,no_plaintext_export,raw_root_allowed,default_media_policy,force_tor,quarantine_default,sealed_media_preservation_enabled,sealed_media_preserve_images,sealed_media_preserve_video,sealed_media_preserve_audio,sealed_media_preserve_max_bytes,created_by,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (name.strip(), description, mode, compliance, 1 if mode == "lockdown" else 0, 1 if mode in {"lockdown", "supervised"} else 0, 1 if mode in {"lockdown", "supervised"} else 0, 1 if raw_root_allowed else 0, media_policy, 1 if force_tor else 0, 1, 1 if sealed_media_preservation_enabled else 0, 1 if sealed_media_preserve_images else 0, 1 if sealed_media_preserve_video else 0, 1 if sealed_media_preserve_audio else 0, safe_int(sealed_media_preserve_max_bytes, safe_int(get_setting("sealed_media_preserve_max_bytes", "52428800"), 52428800, min_value=1048576), min_value=1048576), user["username"], utcnow()))
    log_event(user["username"], "CASE_CREATED", case_id=cid, details={"mode": mode, "media_policy": media_policy, "force_tor": bool(force_tor), "sealed_media_preservation_enabled": bool(sealed_media_preservation_enabled)})
    return RedirectResponse(f"/cases/{cid}", 303)


@app.post("/cases/{case_id}/sealed-media-preservation")
def case_sealed_media_preservation_update(request: Request, case_id: int, sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800")) -> RedirectResponse:
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
    body = f"""{flash(msg)}<div class='card'><h2>{h(case['name'])}</h2><p>{badge(case['mode'],'good' if case['mode']=='lockdown' else 'warn')} {badge('compliance-safe','good') if case['compliance_safe'] else badge('review/lab','warn')} {badge('force Tor','info') if case['force_tor'] else ''} {badge('irreversible lock','warn') if case['irreversible_lock'] else ''}</p><pre>{h(pretty(case))}</pre><p><a class='button' href='/cases/{case_id}/report'>Case report</a> <a class='button' href='/cases/{case_id}/report.zip'>Report-only ZIP</a> <a class='button good' href='/cases/{case_id}/pages'>Case page viewer</a> <a class='button good' href='/captures?case_id={case_id}'>Saved pages</a> <a class='button' href='/media?case_id={case_id}'>Media</a> <a class='button warn' href='/cases/{case_id}/sealed-export'>Sealed LE Export</a></p><form method='post' action='/cases/{case_id}/rendered-export' class='noprint'><h3>Export offline saved-page viewer ZIP</h3><label><input type='checkbox' name='include_assets' value='1'> Include saved local image/video/audio/style/font assets where policy permits</label><label>Master key required if including viewable assets</label><input type='password' name='master_key'><button class='warn'>Export viewer ZIP</button></form></div>{sealed_form}{quick_viewer}
    <div class='grid'><div class='card'><h2>Upload evidence</h2><form method='post' action='/upload' enctype='multipart/form-data'><input type='hidden' name='case_id' value='{case_id}'><label>File</label><input type='file' name='file' required><label><input type='checkbox' name='quarantine' value='1' checked> Quarantine on intake</label><button>Upload</button></form></div>
    <div class='card'><h2>Direct URL capture</h2><form method='post' action='/capture'><input type='hidden' name='case_id' value='{case_id}'><label>URL</label><input name='url' placeholder='https://example.org' required><div class='row'><div><label>Mode</label><select name='capture_mode'><option value='metadata_only'>Metadata only</option><option value='safe_summary'>Sanitized summary</option><option value='evidence_safe'>Evidence safe</option><option value='full_forensic'>Full forensic</option></select></div><div><label>Media policy</label><select name='media_policy'><option value='{h(case['default_media_policy'])}'>{h(case['default_media_policy'])} (case default)</option><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div><div class='row'><div><label>User agent</label><select name='user_agent_profile'>{ua_select_html('user_agent_profile')}</select></div><div><label>Custom UA, if selected</label><input name='custom_user_agent' placeholder='optional custom user agent'></div></div><label><input type='checkbox' name='use_tor' value='1' {'checked' if case['force_tor'] else ''}> Use Tor SOCKS</label><label><input type='checkbox' name='download_allowed_media' value='1'> In lab/full-forensic only: download allowed original media unblurred</label><button>Capture URL</button></form></div>
    <div class='card good'><h2>Start visible live browser</h2><form method='post' action='/live/start'><input type='hidden' name='case_id' value='{case_id}'><label>Start URL</label><input name='start_url' value='https://www.google.com' required><div class='row'><div><label>Browser</label><select name='browser_choice'>{browser_select_html('browser_choice')}</select></div><div><label>Media policy</label><select name='media_policy'><option value='{h(case['default_media_policy'])}'>{h(case['default_media_policy'])} (case default)</option><option value='block_images_video'>Block images + video/audio</option><option value='block_all_media'>Block all media + fonts</option><option value='block_images'>Block images only</option><option value='allow_all'>Allow all</option></select></div></div><div class='row'><div><label>User agent</label><select name='user_agent_profile'>{ua_select_html('user_agent_profile')}</select></div><div><label>Custom UA, if selected</label><input name='custom_user_agent' placeholder='optional custom user agent'></div></div><label><input type='checkbox' name='use_tor' value='1' {'checked' if case['force_tor'] else ''}> Route browser through Tor</label><label><input type='checkbox' name='download_allowed_media' value='1' {'checked' if setting_bool('live_download_allowed_media_default','0') else ''}> Lab/full-forensic only: save allowed images/video/audio for exact page renderer</label><label><input type='checkbox' name='sealed_media_preservation_session' value='1' {'checked' if sealed_media_preservation_policy(case).get('enabled') else ''}> Block display, preserve blocked media encrypted for sealed export in this session</label><label><input type='checkbox' name='settle_before_capture' value='1' {'checked' if setting_bool('capture_settle_before_save','1') else ''}> Before manual/auto capture, wait for slow content and auto-scroll lazy-loaded sections</label><label><input type='checkbox' name='auto_capture' value='1' {'checked' if setting_bool('live_auto_capture_default','0') else ''}> Auto-capture each new page after it settles</label><label><input type='checkbox' name='headless' value='1'> Headless instead of visible</label><button class='good'>Open controlled browser</button></form></div></div>
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
    options = CaptureOptions(use_tor=bool(use_tor), capture_mode=effective_capture_mode(case, capture_mode), media_policy=effective_media_policy(case, media_policy), encrypt=True, download_allowed_media=bool(download_allowed_media), head_probe_blocked_media=setting_bool("head_probe_blocked_media", "1"), max_root_read_bytes=int(get_setting("max_root_read_bytes", "524288")), max_blocked_records=int(get_setting("max_blocked_records", "1000")), user_agent_profile=user_agent_profile or get_setting("default_user_agent_profile", "chrome_windows"), custom_user_agent=custom_user_agent)
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
      <label><input type='checkbox' name='use_tor' value='1'> Route browser through Tor SOCKS</label>
      <label><input type='checkbox' name='download_allowed_media' value='1' {'checked' if setting_bool('live_download_allowed_media_default','0') else ''}> Lab/full-forensic only: save allowed images/video/audio/CSS for exact page renderer</label>
      <label><input type='checkbox' name='sealed_media_preservation_session' value='1' {'checked' if setting_bool('sealed_media_preservation_enabled','0') else ''}> Block display, preserve blocked media encrypted for sealed export in this session</label>
      <label><input type='checkbox' name='settle_before_capture' value='1' {'checked' if setting_bool('capture_settle_before_save','1') else ''}> Before manual/auto capture, wait for slow content and auto-scroll lazy-loaded sections</label>
      <label><input type='checkbox' name='auto_capture' value='1' {'checked' if setting_bool('live_auto_capture_default','0') else ''}> Auto-capture each new page after it settles</label>
      <label><input type='checkbox' name='headless' value='1'> Headless instead of visible</label>
      <button class='good'>Open controlled browser window</button>
    </form><p class='muted small'>If browser binaries are missing, run <code>python BlindSite.py --install-browsers</code>.</p></div><div class='card'><h2>Sessions</h2><table><tr><th>Session</th><th>Case</th><th>Actor</th><th>Browser</th><th>Route</th><th>Status</th><th>Current URL</th></tr>{sess_rows}</table></div>"""
    return layout(request, "Live Sessions", body)


@app.post("/live/start")
def live_start(request: Request, case_id: str = Form(""), start_url: str = Form(...), browser_choice: str = Form("chromium"), media_policy: str = Form("block_images_video"), use_tor: str | None = Form(None), headless: str | None = Form(None), download_allowed_media: str | None = Form(None), sealed_media_preservation_session: str | None = Form(None), auto_capture: str | None = Form(None), settle_before_capture: str | None = Form(None), user_agent_profile: str = Form(""), custom_user_agent: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip() else None
    sess = start_live_session(actor=user["username"], case_id=cid, start_url=start_url, browser_choice=browser_choice, use_tor=bool(use_tor), media_policy=media_policy, headless=bool(headless), download_allowed_media=bool(download_allowed_media), auto_capture=bool(auto_capture), settle_before_capture=bool(settle_before_capture), sealed_media_preservation_session=bool(sealed_media_preservation_session), user_agent_profile=user_agent_profile or get_setting("default_user_agent_profile", "chrome_windows"), custom_user_agent=custom_user_agent)
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
        tabs_html = "".join(f"<tr><td>{h(t.get('index'))}</td><td>{h(t.get('title') or '')}</td><td class='urlcell'>{h(t.get('url') or '')}</td></tr>" for t in tabs)
        runtime = f"<p>{badge('in-memory running','good') if running else badge('in-memory stopped','warn')} {badge('requests '+str(mem.requests),'info')} {badge('blocked '+str(mem.blocked),'warn')} {badge('tabs '+str(len(tabs)),'info')} {badge('current '+mem.current_url[:120],'info')}</p><details class='card'><summary>Tracked browser tabs</summary><table><tr><th>#</th><th>Title</th><th>URL</th></tr>{tabs_html or '<tr><td colspan="3" class="muted">No tracked tabs yet.</td></tr>'}</table></details>"
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
            if (txt) txt.textContent = `mode=${{s.mode || ''}} | blocked=${{s.blocked || 0}} | pending=${{s.pending_tasks || 0}} | metadata-pending=${{s.deferred_metadata_pending || 0}} | preserved=${{s.preserved || 0}} | failed/skipped=${{s.skipped_or_failed || 0}} | timeouts=${{s.timeouts || 0}} | cancelled=${{s.cancelled || 0}} | bytes=${{s.preserved_bytes || 0}} | ${{pct}}%`;
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
    ev_rows = "".join(f"<tr><td>{h(e['created_at'])}</td><td>{h(e['event_type'])}</td><td>{h(e['resource_type'])}</td><td>{h(e['status_code'] or '')}</td><td class='urlcell'>{h(e['url'] or '')}</td><td class='hashcell'><code>{h(e['header_sha256'] or '')}</code></td></tr>" for e in events)
    bm_rows = "".join(f"<tr><td><a href='/blocked/{b['id']}'>#{b['id']}</a></td><td>{h(b['resource_type'])}</td><td>{badge('downloaded','warn') if b['downloaded'] else badge('not downloaded','good')}</td><td>{h(b['reason'])}</td><td class='urlcell'>{h(b['media_url'])}</td><td class='hashcell'><code>{h(b['url_sha256'])}</code></td></tr>" for b in blocked)
    body = f"""{flash(msg)}<div class='card'><h2>Live session {h(sid)}</h2><p>{badge(row['status'],'good' if row['status']=='running' else 'warn')} {badge(row['browser_choice'])} {badge('Tor','info') if row['use_tor'] else badge('Direct')} {badge(row['media_policy'],'good')} {badge('saves allowed media','warn') if jloads(row.get('meta_json'),{}).get('download_allowed_media') else ""}</p><p><b>Case:</b> {h(row.get('case_name') or '')}</p><p><b>Start:</b> <span class='mono'>{h(row['start_url'])}</span></p><p><b>Current:</b> <span class='mono'>{h(row.get('current_url') or '')}</span></p><p><b>User agent:</b> <span class='mono'>{h((jloads(row.get('meta_json'),{}).get('user_agent_label') or jloads(row.get('meta_json'),{}).get('user_agent_profile') or 'default'))}</span> <span class='small muted'>SHA-256 {h((jloads(row.get('meta_json'),{}).get('user_agent_sha256') or '')[:24])}</span></p><p><a class='button good' href='/live/{sid}/pages'>Open session page viewer</a></p>{runtime}<div class='noprint'>{controls}</div>{preservation_panel}<p class='small muted'>Browse in the popped-up browser. Each time you click Capture Current Page, a saved-page evidence item is created below. This build does not block scripts, stylesheets, documents, XHR, or fetch requests.</p></div>
    <div class='card'><h2>Saved page captures from this session</h2><p class='small muted'>Click Open saved page to load the capture exactly as the program saved it: raw HTML in lab mode or a safe reconstructed summary in compliance-safe mode.</p><div class='table-scroll'><table><tr><th>Viewer</th><th>Evidence</th><th>Capture mode</th><th>Raw state</th><th>Captured</th><th>Page URL</th><th>Evidence SHA-256</th></tr>{cap_rows or '<tr><td colspan="7" class="muted">No saved pages yet. Use Capture Current Page while the session is running.</td></tr>'}</table></div></div>
    <div class='grid'><div class='card'><h2>Network/session events</h2><p class='small muted'>Scroll sideways for full URLs and header hashes.</p><div class='table-scroll'><table><tr><th>Time</th><th>Event</th><th>Type</th><th>Status</th><th>URL</th><th>Header hash</th></tr>{ev_rows}</table></div></div><div class='card'><h2>Blocked media</h2><p class='small muted'>Blocked requests were aborted before body download.</p><div class='table-scroll'><table><tr><th>ID</th><th>Type</th><th>State</th><th>Reason</th><th>URL</th><th>URL Hash</th></tr>{bm_rows}</table></div></div></div>"""
    return layout(request, f"Live {sid}", body)


@app.get("/live/{sid}/preservation-status")
def live_preservation_status(request: Request, sid: str) -> JSONResponse:
    require_user(request)
    return JSONResponse(live_preservation_status_for(sid))


@app.post("/live/{sid}/preservation-cancel")
def live_preservation_cancel(request: Request, sid: str) -> RedirectResponse:
    user = require_user(request)
    status = cancel_live_preservation(sid)
    log_event(user["username"], "LIVE_PRESERVATION_CANCEL_REQUESTED", session_id=sid, details=status)
    return RedirectResponse(f"/live/{sid}?msg=Pending%20media%20preservation%20cancelled", 303)


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
def sessions_start_alias(request: Request, case_id: str = Form(""), start_url: str = Form(...), browser_choice: str = Form("chromium"), media_policy: str = Form("block_images_video"), use_tor: str | None = Form(None), headless: str | None = Form(None), download_allowed_media: str | None = Form(None), sealed_media_preservation_session: str | None = Form(None), auto_capture: str | None = Form(None), settle_before_capture: str | None = Form(None), user_agent_profile: str = Form(""), custom_user_agent: str = Form("")) -> RedirectResponse:
    return live_start(request, case_id, start_url, browser_choice, media_policy, use_tor, headless, download_allowed_media, sealed_media_preservation_session, auto_capture, settle_before_capture, user_agent_profile, custom_user_agent)


@app.get("/sessions/{sid}", response_class=HTMLResponse)
def sessions_detail_alias(request: Request, sid: str, msg: str | None = None) -> HTMLResponse:
    return live_detail(request, sid, msg)



@app.get("/captures", response_class=HTMLResponse)
def captures_page(request: Request, case_id: str = "", q: str = "") -> HTMLResponse:
    require_user(request)
    cid = int(case_id) if str(case_id).strip().isdigit() else None
    rows = page_capture_rows(case_id=cid, q=q, limit=500)
    cases = fetchall("SELECT id,name FROM cases ORDER BY id DESC")
    case_opts = "<option value=''>All cases</option>" + "".join(f"<option value='{r['id']}' {'selected' if cid == r['id'] else ''}>{h(r['name'])}</option>" for r in cases)
    cards = []
    for r in rows:
        cards.append(f"""<div class='card'>
          <h2>{h(r['title'] or r['filename'] or 'Saved page')}</h2>
          <p>{badge(r['capture_mode'],'info')} {badge('raw persisted','warn') if r['raw_persisted'] else badge('safe summary / metadata','good')} {badge('case '+str(r['case_id']),'info') if r['case_id'] else ''}</p>
          <p class='small muted'>Captured {h(r['created_at'])}</p>
          <p><b>Source:</b> <span class='mono urlcell'>{h(r['page_url'])}</span></p>
          <p><b>Evidence SHA-256:</b> <code>{h(r['sha256'])}</code></p>
          <p><a class='button good' href='/evidence/{r['evidence_id']}/page-render'>Open renderer</a> <a class='button' href='/evidence/{r['evidence_id']}/capture-frame' target='_blank'>Open safe frame</a> <a class='button secondary' href='/evidence/{r['evidence_id']}'>Evidence #{r['evidence_id']}</a></p>
        </div>""")
    body = f"""<div class='card good'><h2>Saved pages</h2><p>This is where captured pages live. Open saved page loads the page exactly as BlindSite preserved it: raw HTML only in approved lab mode, otherwise a safe reconstructed summary/metadata view that fetches no remote resources.</p><form><div class='row'><div><label>Case</label><select name='case_id'>{case_opts}</select></div><div><label>Search URL/title/hash</label><input name='q' value='{h(q)}'></div><div><button>Filter</button></div></div></form></div>{''.join(cards) or '<div class="card"><p class="muted">No saved page captures yet. Start a live session or run direct URL capture, then click Capture Current Page.</p></div>'}"""
    return layout(request, "Saved Pages", body)


@app.get("/media", response_class=HTMLResponse)
def media_page(request: Request, case_id: str = "", state: str = "all", kind: str = "all", preview: str = "none", q: str = "") -> HTMLResponse:
    user = require_user(request)
    cid = int(case_id) if str(case_id).strip().isdigit() else None
    if state not in {"all", "blocked", "saved", "materialized"}:
        state = "all"
    if kind not in {"all", "image", "video", "audio", "font"}:
        kind = "all"
    if preview not in {"none", "blur"}:
        preview = "none"
    cases = fetchall("SELECT id,name FROM cases ORDER BY id DESC")
    case_opts = "<option value=''>All cases</option>" + "".join(f"<option value='{r['id']}' {'selected' if cid == r['id'] else ''}>{h(r['name'])}</option>" for r in cases)
    state_opts = "".join(f"<option value='{x}' {'selected' if state==x else ''}>{x}</option>" for x in ["all","blocked","saved","materialized"])
    kind_opts = "".join(f"<option value='{x}' {'selected' if kind==x else ''}>{x}</option>" for x in ["all","image","video","audio","font"])
    prev_opts = "".join(f"<option value='{x}' {'selected' if preview==x else ''}>{'blurred image previews' if x=='blur' else 'metadata cards only'}</option>" for x in ["none","blur"])
    saved = [] if state == "blocked" else saved_media_rows(case_id=cid, q=q, kind=kind, state=state, limit=300)
    blocked = [] if state == "saved" else blocked_media_rows(case_id=cid, q=q, kind=kind, state=state, limit=300)
    saved_cards = []
    for r in saved:
        ev = dict(r)
        preview_html = "<div class='thumb'><span class='muted'>metadata-only preview</span></div>"
        if preview == "blur" and str(ev.get("mime_type","")).startswith("image/"):
            ok, why = reveal_allowed(user, ev, "blur")
            if ok:
                tok = signed_token(int(ev["id"]), "blur", user["username"])
                preview_html = f"<div class='thumb'><img src='/evidence/{ev['id']}/serve?mode=blur&token={h(tok)}' alt='blurred preview'></div>"
            else:
                preview_html = f"<div class='thumb'><span class='muted'>{h(why)}</span></div>"
        elif str(ev.get("mime_type","")).startswith("video/"):
            preview_html = "<div class='thumb'><span class='muted'>video evidence; open record for controlled reveal/export workflow</span></div>"
        elif str(ev.get("mime_type","")).startswith("audio/"):
            preview_html = "<div class='thumb'><span class='muted'>audio evidence; open record for controlled reveal/export workflow</span></div>"
        saved_cards.append(f"""<div class='card media-card'>{preview_html}<h3>{h(ev.get('filename'))}</h3><p>{badge(ev.get('kind'))} {badge(ev.get('mime_type'))} {badge(ev.get('storage_mode'),'info')}</p><p><b>Case:</b> {h(ev.get('case_name') or '')}</p><p><b>SHA-256:</b> <code>{h(ev.get('sha256'))}</code></p><p class='small urlcell'>{h(ev.get('source_ref') or '')}</p><p><a class='button good' href='/evidence/{ev['id']}'>Open evidence viewer</a></p></div>""")
    blocked_rows = []
    for b in blocked:
        mat = f"<a href='/evidence/{b['materialized_evidence_id']}'>Evidence #{b['materialized_evidence_id']}</a>" if b['materialized_evidence_id'] else ""
        blocked_rows.append(f"<tr><td><a href='/blocked/{b['id']}'>#{b['id']}</a></td><td>{h(b['resource_type'])}</td><td>{badge('downloaded','warn') if b['downloaded'] else badge('not downloaded','good')}</td><td>{h(b['reason'])}</td><td>{mat}</td><td class='urlcell'>{h(b['media_url'])}</td><td class='hashcell'><code>{h(b['url_sha256'])}</code></td></tr>")
    body = f"""<div class='card good'><h2>Media gallery and blocked-media viewer</h2><p>Use this panel to review saved/materialized media evidence and blocked media metadata without losing the safety controls on the evidence viewer.</p><form><div class='row'><div><label>Case</label><select name='case_id'>{case_opts}</select></div><div><label>State</label><select name='state'>{state_opts}</select></div><div><label>Kind</label><select name='kind'>{kind_opts}</select></div><div><label>Preview</label><select name='preview'>{prev_opts}</select></div></div><label>Search URL/hash/filename</label><input name='q' value='{h(q)}'><button>Filter</button></form></div>
    <div class='card'><h2>Saved/materialized media evidence</h2><div class='media-grid'>{''.join(saved_cards) or '<p class="muted">No saved media evidence matched this filter.</p>'}</div></div>
    <div class='card'><h2>Blocked media records</h2><p class='small muted'>Scroll sideways for full URLs and hashes. These are records of media references that were blocked before body download unless marked downloaded/materialized.</p><div class='table-scroll'><table><tr><th>ID</th><th>Type</th><th>State</th><th>Reason</th><th>Materialized evidence</th><th>URL</th><th>URL SHA-256</th></tr>{''.join(blocked_rows) or '<tr><td colspan="7" class="muted">No blocked media matched this filter.</td></tr>'}</table></div></div>"""
    return layout(request, "Media", body)


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
            if user.get("require_webauthn"):
                return False, "hardware-key/WebAuthn step-up required by account policy"
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
        if user.get("require_webauthn"):
            # Hook exists; full enforcement can be backed by fido2/WebAuthn enrollment.
            return False, "hardware-key/WebAuthn step-up required by account policy"
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
    <div class='card noprint'><h2>Controlled viewer</h2><p>{badge('compliance-safe','good') if case_safe(case) else badge('review/lab','warn')} {badge('original locked','warn') if ev['lock_direct_original_access'] else badge('original policy-dependent','info')}</p><div class='row'><form method='post' action='/evidence/{eid}/issue-token'><input type='hidden' name='mode' value='blocked'><button class='secondary'>Confirm blocked mode</button></form><form method='post' action='/evidence/{eid}/issue-token'><input type='hidden' name='mode' value='blur'><button {'disabled' if not can_blur else ''}>Blur preview</button><p class='small muted'>{h(blur_why)}</p></form></div><form method='post' action='/evidence/{eid}/issue-token' class='card danger'><h3>Full reveal/original bytes</h3><input type='hidden' name='mode' value='full'><label>Reason</label><input name='reason'><label>Admin master reveal key</label><input type='password' name='master_key'><button class='danger' {'disabled' if full_disabled else ''}>Issue full reveal token</button><p class='small muted'>{h(full_why_static)}</p></form><form method='post' action='/approvals/request'><input type='hidden' name='action' value='full_reveal'><input type='hidden' name='case_id' value='{h(ev.get('case_id') or '')}'><input type='hidden' name='evidence_id' value='{eid}'><label>Request supervisor approval</label><input name='reason' placeholder='Why access is needed'><button class='warn'>Request approval</button></form></div>{viewer}
    <div class='card noprint'><h2>Export</h2><form method='post' action='/evidence/{eid}/export'><label><input type='checkbox' name='include_plaintext' value='1'> Include decrypted plaintext/originals where policy permits</label><label>Master key for plaintext export</label><input name='master_key' type='password'><button>Export evidence ZIP</button></form><form method='post' action='/evidence/{eid}/quarantine'><button class='warn'>{'Release from quarantine' if ev['quarantined'] else 'Quarantine'}</button></form></div>
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
        csp = "default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
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
        exact_controls = f"""<form class='card warn noprint' method='post' action='{back_url}/{selected_id}/unlock'>
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
        unlock_form = f"""<form class='card warn noprint' method='post' action='/evidence/{eid}/page-render/unlock'><h3>Unlock exact local renderer</h3><p class='small muted'>This uses saved local original assets only. It does not contact the source website. It can reveal locally saved images/video/audio from this capture.</p><label>Reason</label><input name='reason' placeholder='case note / reason'><label>Admin master key</label><input type='password' name='master_key' required><button class='warn'>Unlock for this session</button></form>"""
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
        raise HTTPException(403, "Asset is not linked to this page capture")
    data = read_evidence(asset_eid)
    log_event(user["username"], "PAGE_RENDER_ASSET_SERVED", case_id=page_ev.get("case_id"), evidence_id=asset_eid, details={"page_evidence_id": page_eid})
    return Response(data, media_type=asset_ev["mime_type"] or "application/octet-stream", headers={"Cache-Control": "no-store"})


@app.post("/evidence/{eid}/issue-token")
def issue_token(request: Request, eid: int, mode: str = Form(...), master_key: str = Form(""), reason: str = Form("")) -> RedirectResponse:
    user = require_user(request)
    ev = evidence_for(eid)
    if not ev:
        raise HTTPException(404, "Evidence not found")
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
        manifest = {"exported_at": utcnow(), "exported_by": user["username"], "evidence": ev, "case": case, "include_plaintext": want_plain, "audit_verification": verify_audit_chain()}
        z.writestr("manifest.json", pretty(manifest))
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
        form = f"""<div class='card danger'><h2>Materialize original bytes</h2><p>This downloads the original body into evidence. Use only for approved lab/supervised workflows.</p><form method='post' action='/blocked/{bid}/materialize'><label>Reason</label><input name='reason' required><label>Master reveal key</label><input name='master_key' type='password'><label><input type='checkbox' name='use_tor' value='1'> Use Tor</label><button class='danger'>Download original into evidence</button></form><form method='post' action='/approvals/request'><input type='hidden' name='action' value='materialize_original'><input type='hidden' name='case_id' value='{h(bm.get('case_id') or '')}'><input type='hidden' name='blocked_media_id' value='{bid}'><label>Request approval</label><input name='reason'><button class='warn'>Request materialization approval</button></form></div>"""
    body = f"{flash(msg)}<div class='card'><h2>Blocked media #{bid}</h2><p>{badge(bm['resource_type'])} {badge('not downloaded','good') if not bm['downloaded'] else badge('downloaded','warn')}</p><table><tr><th>URL</th><td>{h(bm['media_url'])}</td></tr><tr><th>URL SHA-256</th><td><code>{h(bm['url_sha256'])}</code></td></tr><tr><th>Metadata record SHA-256</th><td><code>{h(bm['metadata_record_hash'])}</code></td></tr><tr><th>Header SHA-256</th><td><code>{h(bm['header_sha256'])}</code></td></tr><tr><th>Content SHA-256</th><td>{h(bm['content_sha256'] or 'not available because body was not downloaded')}</td></tr></table><pre>{h(pretty(bm))}</pre></div>{form}"
    return layout(request, f"Blocked #{bid}", body)


@app.post("/blocked/{bid}/materialize")
def blocked_materialize(request: Request, bid: int, reason: str = Form(...), master_key: str = Form(""), use_tor: str | None = Form(None)) -> RedirectResponse:
    user = require_user(request)
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
    log_event(user["username"], "APPROVAL_REQUESTED", case_id=cid, evidence_id=eid, blocked_media_id=bid, details={"approval_id": aid, "action": action, "reason": reason})
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
    return {"generated_at": utcnow(), "app": APP_NAME, "version": APP_VERSION, "case": case, "evidence": evidence, "page_captures": page_captures, "media_evidence": media_evidence, "blocked_media": blocked, "approvals": approvals, "audit_events": audit, "audit_verification": verify_audit_chain(), "settings_summary": {"edition": edition(), "hard_default_safe_mode": get_setting("hard_default_safe_mode", "1"), "default_media_policy": get_setting("default_media_policy", "block_images_video"), "default_user_agent_profile": get_setting("default_user_agent_profile", "chrome_windows")}}


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
    body = f"<div class='card'><h2>Case report: {h(data['case']['name'])}</h2><p>{badge('audit verified','good') if data['audit_verification']['ok'] else badge('audit problem','bad')}</p><p><a class='button' href='/cases/{case_id}/report.json'>JSON</a> <a class='button' href='/cases/{case_id}/report.csv'>CSV</a> <a class='button' href='/cases/{case_id}/report.zip'>Report-only ZIP with saved pages</a> <a class='button good' href='/captures?case_id={case_id}'>Saved pages</a> <a class='button' href='/media?case_id={case_id}'>Media</a> <a class='button warn' href='/cases/{case_id}/sealed-export'>Sealed LE Export</a></p><pre>{h(pretty(data['case']))}</pre></div><div class='card'><h2>Saved pages</h2><div class='table-scroll'><table><tr><th>Viewer</th><th>Evidence</th><th>Title</th><th>Mode</th><th>URL</th></tr>{page_rows or '<tr><td colspan="5" class="muted">No saved pages.</td></tr>'}</table></div></div><div class='card'><h2>Media evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>MIME</th><th>SHA</th></tr>{media_rows or '<tr><td colspan="5" class="muted">No saved media evidence.</td></tr>'}</table></div><div class='card'><h2>Evidence</h2><table><tr><th>ID</th><th>Filename</th><th>Kind</th><th>Storage</th><th>SHA</th></tr>{ev_rows}</table></div><div class='card'><h2>Blocked media</h2><table><tr><th>ID</th><th>Type</th><th>Policy</th><th>Downloaded</th><th>Metadata hash</th></tr>{bm_rows}</table></div>"
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
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>BlindSite Sealed Export</title><style>body{{font-family:Arial;margin:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;vertical-align:top}}code{{word-break:break-all}}.warn{{background:#fff3cd;border:1px solid #d6b656;padding:10px}}</style></head><body><h1>BlindSite Sealed Evidence Export</h1><div class='warn'>This report is metadata only. Original evidence bytes are included only as encrypted vault objects.</div><h2>Case</h2><p><b>ID:</b> {h(case.get('id'))}<br><b>Name:</b> {h(case.get('name'))}<br><b>Custody:</b> {h(manifest.get('custody_mode'))}<br><b>Escrow fingerprint:</b> <code>{h(manifest.get('escrow_public_key_fingerprint'))}</code></p><h2>Encrypted objects</h2><table><tr><th>ID</th><th>Filename</th><th>Class</th><th>MIME</th><th>Logical SHA-256</th><th>ZIP path</th></tr>{ev_rows}</table><h2>Blocked/media records</h2><table><tr><th>ID</th><th>Type</th><th>Downloaded</th><th>URL</th><th>Metadata hash</th></tr>{bm_rows}</table></body></html>"""


def build_sealed_case_package(case_id: int, actor: str, recipient: str = "", reason: str = "", recipient_public_key_pem: str = "") -> tuple[bytes, dict[str, Any]]:
    if not setting_bool("sealed_export_enabled", "1"):
        raise HTTPException(403, "Sealed evidence export is disabled in Settings")
    data = collect_case_sealed_rows(case_id)
    keymat = sealed_key_material(recipient_public_key_pem)
    hard_fps = hard_sealed_object_fingerprints(data.get("evidence") or [])
    if hard_fps and keymat["escrow_public_key_fingerprint"] not in hard_fps:
        raise HTTPException(400, "This case contains hard-sealed evidence encrypted to escrow fingerprint(s) " + ", ".join(sorted(hard_fps)) + ". Use the matching escrow public key for sealed export so the reviewer private key can recover all objects.")
    created_at = utcnow()
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
    summary = {"case_id": case_id, "package_sha256": sha256_bytes(payload), "package_size": len(payload), "object_count": len(objects), "sealed_preserved_media_count": sum(1 for e in data["evidence"] if e.get("storage_mode") == SEALED_PRESERVED_STORAGE_MODE), "hard_sealed_escrow_evidence_count": sum(1 for o in objects if o.get("hard_sealed_escrow_evidence")), "hard_sealed_civilian_evidence_count": sum(1 for o in objects if o.get("hard_sealed_civilian_evidence")), "hard_sealed_organization_media_count": sum(1 for o in objects if o.get("hard_sealed_organization_media")), "recipient": recipient, "reason": reason, "custody_mode": custody_mode(), "escrow_public_key_fingerprint": keymat["escrow_public_key_fingerprint"]}
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
    body = f"""<div class='card safe'><h2>Sealed law-enforcement evidence export</h2><p>This exports the actual stored evidence blobs in encrypted form so a civilian can hand evidence to law enforcement/USCM without local plaintext reveal.</p><p>{badge(custody_label(),'info')} {badge('No plaintext originals in ZIP','good')} {badge('Encrypted evidence blobs included','warn')}</p><p><b>Default escrow public-key fingerprint:</b> <code>{h(fp or 'not configured')}</code><br><span class='small muted'>{h(fp_note)}</span></p><form method='post' action='/cases/{case_id}/sealed-export'><label>Recipient / agency</label><input name='recipient' placeholder='Law enforcement / agency / counsel'><label>Reason / handoff note</label><textarea name='reason'></textarea><label>Optional recipient/agency public key PEM</label><textarea name='recipient_public_key_pem' rows='8' placeholder='Organization mode can paste a recipient public key here. Civilian mode uses the USCM escrow public key only.'></textarea><button class='good'>Download sealed encrypted evidence ZIP</button></form></div>"""
    return layout(request, "Sealed Evidence Export", body)


@app.post("/cases/{case_id}/sealed-export")
def sealed_export_download(request: Request, case_id: int, recipient: str = Form(""), reason: str = Form(""), recipient_public_key_pem: str = Form("")) -> StreamingResponse:
    user = require_user(request)
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



def reviewer_objects_filtered(import_id: int, kind_filter: str = "all", q: str = "", limit: int = 800) -> list[dict[str, Any]]:
    clauses = ["import_id=?"]
    params: list[Any] = [import_id]
    if q:
        like = f"%{q}%"
        clauses.append("(filename LIKE ? OR source_ref LIKE ? OR page_url LIKE ? OR original_url LIKE ? OR sha256 LIKE ? OR logical_sha256_expected LIKE ? OR mime_type LIKE ? OR kind LIKE ? OR meta_json LIKE ?)")
        params.extend([like, like, like, like, like, like, like, like, like])
    params.append(limit)
    rows = [dict(r) for r in fetchall(f"SELECT * FROM reviewer_objects WHERE {' AND '.join(clauses)} ORDER BY id LIMIT ?", tuple(params))]
    return [r for r in rows if reviewer_filter_matches(str(r.get("kind") or "other"), kind_filter)]


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


def reviewer_media_card(import_id: int, obj: dict[str, Any]) -> str:
    raw = f"/reviewer/imports/{import_id}/objects/{int(obj['id'])}/raw"
    mt = (obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower()
    title = h(obj.get("filename") or f"object_{obj.get('id')}")
    source = h(obj.get("source_ref") or obj.get("original_url") or obj.get("page_url") or "")
    if mt.startswith("image/"):
        preview = f"<div class='thumb'><img src='{raw}' alt='{title}'></div>"
    elif mt.startswith("video/"):
        preview = f"<div class='thumb'><video controls preload='metadata' src='{raw}'></video></div>"
    elif mt.startswith("audio/"):
        preview = f"<div class='thumb'><audio controls preload='metadata' src='{raw}'></audio></div>"
    else:
        preview = f"<div class='thumb'><span class='muted'>{h(mt)}</span></div>"
    return f"<div class='card media-card'>{preview}<h3>{title}</h3><p>{badge(obj.get('kind'),'info')} {badge(mt)} {badge('score '+str(obj.get('_reviewer_related_score','')),'info') if obj.get('_reviewer_related_score') else ''}</p><p class='small urlcell'>{source}</p><p><a class='button' href='{raw}?download=1'>Download</a> <a class='button secondary' href='/reviewer/imports/{import_id}/viewer?obj={int(obj['id'])}'>Object details</a></p></div>"


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
        return "default-src 'self' data: blob: http: https:; img-src 'self' data: blob: http: https:; media-src 'self' data: blob: http: https:; style-src 'self' 'unsafe-inline' http: https:; font-src 'self' data: http: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https:; connect-src 'self' http: https: ws: wss:; frame-src http: https:; object-src 'none'; base-uri 'none'; form-action http: https:"
    if mode == "remote":
        return "default-src 'none'; img-src 'self' data: blob: http: https:; media-src 'self' data: blob: http: https:; style-src 'self' 'unsafe-inline' http: https:; font-src 'self' data: http: https:; script-src 'none'; connect-src http: https:; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    return "default-src 'none'; img-src 'self' data: blob:; media-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"


def reviewer_render_html(import_id: int, obj: dict[str, Any], mode: str = "auto") -> str:
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
    for tag in soup.find_all(["img", "video", "audio", "source"]):
        for attr in ["src", "poster"]:
            if tag.has_attr(attr):
                raw = str(tag.get(attr) or "")
                if raw.startswith("data:"):
                    continue
                absu = absolute_resource_url(source_url, raw)
                asset = asset_map.get(absu) or asset_map.get(absu.split('#', 1)[0])
                if asset:
                    tag[attr] = asset_url(asset)
                    tag[f"data-original-{attr}"] = absu
                    if tag.name in {"video", "audio"}:
                        tag["controls"] = "controls"
                elif allow_remote and absu.startswith(("http://", "https://")):
                    tag[attr] = absu
                    tag[f"data-remote-{attr}"] = "allowed"
                else:
                    tag[f"data-missing-{attr}"] = absu
                    tag[attr] = ""
        if tag.has_attr("srcset"):
            original = str(tag.get("srcset") or "")
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
        if href and ("stylesheet" in rel or as_attr in {"style", "font"}):
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
                if asset:
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
    style_tag = soup.new_tag("style")
    style_tag.string = "[data-reviewer-removed]{display:block;padding:8px;margin:4px;border:1px dashed #64748b;background:#111827;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif}.reviewer-banner{position:sticky;top:0;z-index:2147483647;background:#111827;color:#e5e7eb;border-bottom:2px solid #38bdf8;padding:8px 12px;font:14px Segoe UI,Arial,sans-serif}img,video{max-width:100%;height:auto}"
    soup.head.append(style_tag)
    if allow_scripts:
        guard = soup.new_tag("script")
        guard["data-blindsite-reviewer-guard"] = "1"
        guard.string = r"""
(function(){
  // Dynamic reviewer safety net: some modern sites render correctly, then their
  // client JS clears the DOM when cookies/API state are missing. Preserve the
  // first usable recovered DOM and restore it if the page blanks itself.
  let snap = null;
  let snapTextLen = 0;
  function take(){
    if (!document.body) return;
    const html = document.body.innerHTML || '';
    const text = (document.body.innerText || '').trim();
    if (html.length > 500 && text.length > 20) { snap = html; snapTextLen = text.length; }
  }
  function check(){
    if (!snap || !document.body) return;
    const html = document.body.innerHTML || '';
    const text = (document.body.innerText || '').trim();
    if ((html.length < Math.max(300, snap.length * 0.20)) || (snapTextLen > 100 && text.length < snapTextLen * 0.15)) {
      document.body.innerHTML = snap;
      const note = document.createElement('div');
      note.className = 'reviewer-banner';
      note.textContent = 'BlindSite restored the recovered DOM after site JavaScript blanked the page. Remote scripts/callbacks are still enabled in this view.';
      document.body.insertBefore(note, document.body.firstChild);
    }
  }
  window.addEventListener('DOMContentLoaded', function(){ setTimeout(take, 250); setTimeout(take, 1000); });
  setTimeout(take, 500);
  let n = 0; const id = setInterval(function(){ check(); if (++n > 18) clearInterval(id); }, 700);
})();
"""
        soup.head.append(guard)
    banner = soup.new_tag("div")
    banner["class"] = "reviewer-banner"
    if mode == "scripts":
        banner.string = f"Cleared reviewer SCRIPT view — local recovered assets used first; remote callbacks and scripts allowed — source: {source_url}"
    elif mode == "remote":
        banner.string = f"Cleared reviewer REMOTE-CALLBACK view — scripts disabled; local recovered assets used first; missing remote media/style may load — source: {source_url}"
    else:
        banner.string = f"Cleared reviewer SAFE local page view — scripts and remote callbacks disabled; local recovered assets only — source: {source_url}"
    soup.body.insert(0, banner)
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
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
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


def reviewer_page_frame_html(import_id: int, page_obj: dict[str, Any], mode: str = "auto") -> str:
    data = read_reviewer_object(page_obj)
    mt = (page_obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower()
    if mt in {"text/html", "application/xhtml+xml"} or data[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        return reviewer_render_html(import_id, page_obj, mode)
    return reviewer_page_summary_frame_html(import_id, page_obj, mode)


def reviewer_object_frame_html(import_id: int, obj: dict[str, Any], mode: str = "safe") -> str:
    data = read_reviewer_object(obj)
    mt = (obj.get("mime_type") or "application/octet-stream").split(";", 1)[0].lower()
    raw_url = f"/reviewer/imports/{import_id}/objects/{obj['id']}/raw"
    title = obj.get("filename") or f"object_{obj['id']}"
    if obj.get("kind") == "page":
        return reviewer_page_frame_html(import_id, obj, mode)
    if mt in {"text/html", "application/xhtml+xml"} or data[:256].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        return reviewer_render_html(import_id, obj, mode)
    if mt.startswith("image/"):
        body = f"<div class='viewer'><img src='{raw_url}' alt='{h(title)}'></div>"
    elif mt.startswith("video/"):
        body = f"<video controls style='max-width:100%;max-height:80vh' src='{raw_url}'></video>"
    elif mt.startswith("audio/"):
        body = f"<audio controls style='width:100%' src='{raw_url}'></audio>"
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
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; script-src 'none'; connect-src 'none'"><style>body{{margin:0;background:#0f172a;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;padding:18px}}pre{{white-space:pre-wrap;background:#020617;border:1px solid #334155;border-radius:10px;padding:12px;overflow:auto}}.viewer{{min-height:70vh;border:1px dashed #475569;border-radius:12px;display:flex;align-items:center;justify-content:center;text-align:center;background:#020617}}.viewer img{{max-width:100%;max-height:82vh}}a{{color:#7dd3fc}}</style><title>{h(title)}</title></head><body><h2>{h(title)}</h2><p>{h(obj.get('kind'))} · {h(mt)} · SHA-256 <code>{h(obj.get('sha256'))}</code></p>{body}</body></html>"""


@app.get("/reviewer", response_class=HTMLResponse)
def reviewer_page(request: Request, msg: str | None = None) -> HTMLResponse:
    user = require_reviewer(request)
    rows = fetchall("SELECT * FROM reviewer_imports ORDER BY id DESC LIMIT 100")
    trs = "".join(f"<tr><td><a href='/reviewer/imports/{r['id']}/viewer'>#{r['id']}</a></td><td>{h(r['package_name'])}</td><td>{badge(r['status'],'good' if r['status']=='imported' else 'warn' if r['status']=='imported_with_errors' else 'bad' if r['status']=='error' else 'info')}</td><td>{h(r['case_name'] or '')}</td><td>{h(r['recovered_count'])}/{h(r['object_count'])}</td><td><a class='button good' href='/reviewer/imports/{r['id']}/pages'>Pages</a> <a class='button secondary' href='/reviewer/imports/{r['id']}/viewer'>Objects</a></td><td><code>{h((r['package_sha256'] or '')[:24])}…</code></td><td>{h(r['created_at'])}</td></tr>" for r in rows)
    body = f"""{flash(msg)}<div class='card safe'><h2>Law-enforcement / cleared reviewer import</h2><p>Import a sealed BlindSite evidence package with the escrow private key. Recovered plaintext is written only into this local review vault and indexed for browsing.</p><form method='post' action='/reviewer/import' enctype='multipart/form-data'><label>Sealed evidence ZIP</label><input type='file' name='package' accept='.zip' required><label>Escrow private key PEM</label><input type='file' name='private_key' accept='.pem,.key,.txt' required><label>Private-key passphrase, if any</label><input type='password' name='passphrase'><label>Import note</label><textarea name='note' placeholder='Agency/case note'></textarea><button class='good'>Import and decrypt into review vault</button></form></div><div class='card'><h2>Reviewer imports</h2><table><tr><th>ID</th><th>Package</th><th>Status</th><th>Case</th><th>Recovered</th><th>Open</th><th>Package SHA-256</th><th>Imported</th></tr>{trs or '<tr><td colspan="8" class="muted">No reviewer imports yet.</td></tr>'}</table></div>"""
    log_event(user["username"], "REVIEWER_AREA_OPENED")
    return layout(request, "LE Reviewer", body)


@app.post("/reviewer/import")
async def reviewer_import_route(request: Request, package: UploadFile = File(...), private_key: UploadFile = File(...), passphrase: str = Form(""), note: str = Form("")) -> RedirectResponse:
    user = require_reviewer(request)
    package_bytes = await package.read()
    private_pem = await private_key.read()
    if not package_bytes:
        raise HTTPException(400, "Sealed evidence ZIP is empty")
    if not private_pem:
        raise HTTPException(400, "Escrow private key PEM is empty")
    import_id = reviewer_import_package(package_bytes, package.filename or "sealed_evidence.zip", private_pem, passphrase, user["username"], note)
    return RedirectResponse(f"/reviewer/imports/{import_id}/pages?msg=Sealed%20package%20imported", 303)


@app.get("/reviewer/imports/{import_id}", response_class=HTMLResponse)
def reviewer_import_detail_alias(request: Request, import_id: int) -> HTMLResponse:
    return reviewer_viewer(request, import_id)


@app.get("/reviewer/imports/{import_id}/pages", response_class=HTMLResponse)
def reviewer_pages_viewer(request: Request, import_id: int, page: str = "", render: str = "auto", q: str = "", msg: str | None = None) -> HTMLResponse:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    if render not in {"auto", "safe", "remote", "scripts"}:
        render = get_setting("reviewer_default_render_mode", "auto")
        render = render if render in {"auto", "safe", "remote", "scripts"} else "auto"
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
            f"<tr{active}><td><a class='button good' href='/reviewer/imports/{import_id}/pages?page={p_obj['id']}&render={h(render)}&q={h(q)}'>Load</a></td>"
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
        sandbox = "allow-same-origin allow-scripts allow-forms allow-popups" if render == "scripts" else "allow-same-origin"
        frame_url = f"/reviewer/imports/{import_id}/pages/{selected['id']}/frame?mode={h(render)}"
        frame = f"<iframe class='render-frame' sandbox='{sandbox}' src='{frame_url}'></iframe>"
        base = f"/reviewer/imports/{import_id}/pages?page={selected['id']}&q={h(q)}"
        render_controls = f"""<div class='card {'danger' if render=='scripts' else 'warn' if render=='remote' else 'safe'}'><h3>Page render mode</h3><p>{badge('best available local view','good') if render=='auto' else badge('local safe page view','good') if render=='safe' else badge('allow remote callbacks','warn') if render=='remote' else badge('allow remote callbacks + scripts','bad')}</p><p><a class='button good' href='{base}&render=auto'>Best available</a> <a class='button good' href='{base}&render=safe'>Local safe view</a> <a class='button warn' href='{base}&render=remote'>Allow remote callbacks</a> <a class='button danger' href='{base}&render=scripts'>Allow remote callbacks + scripts</a></p><p class='small muted'>Best available is safe/local by default. Use remote+scripts for dynamic sites that need live callbacks; BlindSite adds a small DOM guard to restore the recovered page if site JavaScript blanks it.</p></div>"""
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
        log_event(user["username"], "REVIEWER_PAGE_VIEWER_OPENED", details={"reviewer_import_id": import_id, "page_object_id": selected["id"], "render": render, "associated_media": len(associated)})
    body = f"""{flash(msg)}<div class='card safe'><h2>LE Captured Page Viewer — import #{import_id}</h2><p>{badge(imp['status'],'good' if imp['status']=='imported' else 'warn')} {badge('pages '+str(len(pages)),'info')} {badge('case '+str(imp.get('case_id_original') or ''),'info') if imp.get('case_id_original') else ''}</p><p class='small muted'>This workspace is organized around captured pages first. Select a page on the left; the viewer renders the recovered page content and groups recovered images/video/audio associated with that page.</p><p><a class='button' href='/reviewer/imports/{import_id}/viewer'>All recovered objects</a> <a class='button good' href='/reviewer/imports/{import_id}/pages'>Captured page viewer</a></p><table><tr><th>Package</th><td>{h(imp['package_name'])}</td></tr><tr><th>Case</th><td>{h(imp.get('case_name') or '')}</td></tr><tr><th>Package SHA-256</th><td class='hashcell'><code>{h(imp['package_sha256'])}</code></td></tr></table></div><div class='card noprint'><h2>Find captured pages</h2><form><input type='hidden' name='render' value='{h(render)}'><label>Search page title, URL, filename, hash, or MIME</label><input name='q' value='{h(q)}'><button>Search pages</button></form></div><div class='grid' style='grid-template-columns:minmax(430px,40%) minmax(560px,1fr)'><div class='card'><h2>Captured pages</h2><div class='table-scroll'><table><tr><th>Load</th><th>Title</th><th>Capture</th><th>URL</th><th>SHA-256</th></tr>{''.join(page_rows) or '<tr><td colspan="5" class="muted">No recovered page captures matched this filter.</td></tr>'}</table></div></div><div><div>{selected_info or '<div class="card"><p class="muted">Select a recovered page to view it.</p></div>'}</div><div class='card'><h2>Rendered captured page</h2>{frame}</div></div></div>{media_table}"""
    return layout(request, f"LE Pages Import #{import_id}", body)


@app.get("/reviewer/imports/{import_id}/pages/{object_id}/frame", response_class=HTMLResponse)
def reviewer_page_frame_route(request: Request, import_id: int, object_id: int, mode: str = "auto") -> HTMLResponse:
    user = require_reviewer(request)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered page object not found")
    if obj.get("kind") != "page" and (obj.get("mime_type") or "").split(";", 1)[0].lower() not in {"text/html", "application/xhtml+xml"}:
        raise HTTPException(400, "Selected object is not a recovered page capture")
    mode = mode if mode in {"auto", "safe", "remote", "scripts"} else "auto"
    html_doc = reviewer_page_frame_html(import_id, obj, mode)
    log_event(user["username"], "REVIEWER_PAGE_FRAME_SERVED", details={"reviewer_import_id": import_id, "page_object_id": object_id, "mode": mode})
    return HTMLResponse(html_doc, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Content-Security-Policy": reviewer_csp_for_mode(mode)})


@app.get("/reviewer/imports/{import_id}/viewer", response_class=HTMLResponse)
def reviewer_viewer(request: Request, import_id: int, kind: str = "all", q: str = "", obj: str = "", render: str = "safe", msg: str | None = None) -> HTMLResponse:
    user = require_reviewer(request)
    imp = reviewer_import_for(import_id)
    if not imp:
        raise HTTPException(404, "Reviewer import not found")
    if kind not in {"all", "pages", "snapshots", "images", "videos", "audio", "text", "other"}:
        kind = "all"
    if render not in {"auto", "safe", "remote", "scripts"}:
        render = get_setting("reviewer_default_render_mode", "auto")
        render = render if render in {"auto", "safe", "remote", "scripts"} else "auto"
    objects = reviewer_objects_filtered(import_id, kind, q, limit=1000)
    selected_id = int(obj) if str(obj).isdigit() else (int(objects[0]["id"]) if objects else 0)
    selected = reviewer_object_for(selected_id) if selected_id else None
    if selected and int(selected.get("import_id") or 0) != import_id:
        selected = None
    counts = {r["kind"]: r["c"] for r in fetchall("SELECT kind,count(*) c FROM reviewer_objects WHERE import_id=? GROUP BY kind", (import_id,))}
    filter_links = []
    for key, label in [("all", "all"), ("pages", "pages"), ("snapshots", "snapshots"), ("images", "images"), ("videos", "videos"), ("audio", "audio"), ("text", "text"), ("other", "other")]:
        total = sum(counts.values()) if key == "all" else sum(v for k, v in counts.items() if reviewer_filter_matches(k, key))
        filter_links.append(f"<a class='button {'good' if kind==key else 'secondary'}' href='/reviewer/imports/{import_id}/viewer?kind={h(key)}&q={h(q)}&render={h(render)}'>{h(label)} ({h(total)})</a>")
    obj_rows = []
    for r in objects:
        active = " style='background:#0f2f46'" if selected and int(r["id"]) == int(selected["id"]) else ""
        obj_rows.append(f"<tr{active}><td><a class='button good' href='/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={r['id']}&render={h(render)}'>View</a></td><td>{badge(r['kind'],'info')}</td><td>{h(r['filename'])}</td><td>{h(r['mime_type'])}</td><td>{h(r['size'])}</td><td>{badge('hash ok','good') if r['hash_ok'] else badge('hash mismatch','bad')}</td><td class='urlcell'>{h(r['source_ref'] or r['page_url'] or r['original_url'])}</td><td class='hashcell'><code>{h(r['sha256'])}</code></td></tr>")
    render_controls = ""
    panel = "<div class='viewer'><p class='muted'>No recovered object selected.</p></div>"
    if selected:
        safe_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=safe"
        remote_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=remote"
        scripts_url = f"/reviewer/imports/{import_id}/viewer?kind={h(kind)}&q={h(q)}&obj={selected['id']}&render=scripts"
        page_workspace = f" <a class='button good' href='/reviewer/imports/{import_id}/pages?page={selected['id']}&render={h(render)}'>Open in page viewer</a>" if selected.get("kind") == "page" else ""
        render_controls = f"<div class='card {'danger' if render=='scripts' else 'warn' if render=='remote' else 'safe'}'><h3>Reviewer render mode</h3><p>{badge('local safe view','good') if render=='safe' else badge('remote callbacks allowed','warn') if render=='remote' else badge('remote callbacks + scripts allowed','bad')}</p><p><a class='button good' href='{safe_url}'>Local safe view</a> <a class='button warn' href='{remote_url}'>Allow remote callbacks</a> <a class='button danger' href='{scripts_url}'>Allow remote callbacks + scripts</a>{page_workspace}</p><p class='small muted'>Local safe view is the default. It uses recovered local assets first and blocks scripts/forms/navigation/remote loads. The two remote modes are explicit reviewer choices and are audit logged.</p></div>"
        sandbox = "allow-same-origin allow-scripts allow-forms allow-popups" if render == "scripts" else "allow-same-origin"
        frame_url = f"/reviewer/imports/{import_id}/objects/{selected['id']}/frame?mode={h(render)}"
        panel = f"<iframe class='render-frame' sandbox='{sandbox}' src='{frame_url}'></iframe>"
        log_event(user["username"], "REVIEWER_OBJECT_VIEWED", details={"reviewer_import_id": import_id, "reviewer_object_id": selected["id"], "kind": selected.get("kind"), "render": render})
    manifest_pre = h(pretty(jloads(imp.get("manifest_json"), {}))[:22000])
    selected_meta = h(pretty(jloads(selected.get("meta_json"), {}))[:22000]) if selected else ""
    selected_info = ""
    if selected:
        selected_info = f"""<div class='card'><h2>Selected object #{selected['id']}</h2><p>{badge(selected['kind'],'info')} {badge(selected['mime_type'])} {badge('hash ok','good') if selected['hash_ok'] else badge('hash mismatch','bad')}</p><table><tr><th>Filename</th><td>{h(selected['filename'])}</td></tr><tr><th>Source / URL</th><td class='urlcell'>{h(selected.get('source_ref') or selected.get('page_url') or selected.get('original_url') or '')}</td></tr><tr><th>SHA-256</th><td class='hashcell'><code>{h(selected['sha256'])}</code></td></tr><tr><th>Original package object</th><td>{h(selected['object_class'])} #{h(selected['original_id'])}</td></tr></table><p><a class='button' href='/reviewer/imports/{import_id}/objects/{selected['id']}/raw?download=1'>Download recovered object</a>{' <a class="button good" href="/reviewer/imports/'+str(import_id)+'/pages?page='+str(selected['id'])+'">Open captured-page viewer</a>' if selected.get('kind') == 'page' else ''}</p></div>{render_controls}<div class='card'><h2>Embedded viewer</h2>{panel}</div><div class='card'><h2>Object metadata</h2><pre>{selected_meta}</pre></div>"""
    body = f"""{flash(msg)}<div class='card safe'><h2>LE Case Viewer — import #{import_id}</h2><p>{badge(imp['status'],'good' if imp['status']=='imported' else 'warn')} {badge('objects '+str(imp['recovered_count']),'info')} {badge('case '+str(imp.get('case_id_original') or ''),'info') if imp.get('case_id_original') else ''}</p><p><a class='button good' href='/reviewer/imports/{import_id}/pages'>Open captured page viewer</a> <a class='button secondary' href='/reviewer/imports/{import_id}/viewer?kind=pages'>Filter page objects</a></p><table><tr><th>Package</th><td>{h(imp['package_name'])}</td></tr><tr><th>Case</th><td>{h(imp.get('case_name') or '')}</td></tr><tr><th>Package SHA-256</th><td class='hashcell'><code>{h(imp['package_sha256'])}</code></td></tr><tr><th>Escrow public-key fingerprint</th><td class='hashcell'><code>{h(imp.get('escrow_public_key_fingerprint') or '')}</code></td></tr></table></div><div class='card noprint'><h2>Browse recovered evidence</h2><p>{''.join(filter_links)}</p><form><input type='hidden' name='kind' value='{h(kind)}'><input type='hidden' name='render' value='{h(render)}'><label>Search filename, URL/source, hash, MIME, or kind</label><input name='q' value='{h(q)}'><button>Search</button></form></div><div class='grid' style='grid-template-columns:minmax(430px,48%) minmax(480px,1fr)'><div class='card'><h2>Recovered objects</h2><div class='table-scroll'><table><tr><th>Open</th><th>Kind</th><th>Filename</th><th>MIME</th><th>Size</th><th>Hash</th><th>Source</th><th>SHA-256</th></tr>{''.join(obj_rows) or '<tr><td colspan="8" class="muted">No recovered objects match this filter.</td></tr>'}</table></div></div><div>{selected_info or '<div class="card"><p class="muted">Select an object to view it.</p></div>'}</div></div><div class='card'><h2>Sealed package manifest</h2><pre>{manifest_pre}</pre></div>"""
    return layout(request, f"LE Viewer Import #{import_id}", body)


@app.get("/reviewer/imports/{import_id}/objects/{object_id}/raw")
def reviewer_object_raw(request: Request, import_id: int, object_id: int, download: str | None = None) -> Response:
    user = require_reviewer(request)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered object not found")
    data = read_reviewer_object(obj)
    headers = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}
    if download:
        headers["Content-Disposition"] = f"attachment; filename={clean_filename(obj.get('filename') or 'recovered_object.bin')}"
    log_event(user["username"], "REVIEWER_OBJECT_RAW_SERVED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "download": bool(download)})
    return Response(data, media_type=obj.get("mime_type") or "application/octet-stream", headers=headers)


@app.get("/reviewer/imports/{import_id}/objects/{object_id}/frame", response_class=HTMLResponse)
def reviewer_object_frame(request: Request, import_id: int, object_id: int, mode: str = "safe") -> HTMLResponse:
    user = require_reviewer(request)
    obj = reviewer_object_for(object_id)
    if not obj or int(obj.get("import_id") or 0) != import_id:
        raise HTTPException(404, "Recovered object not found")
    mode = mode if mode in {"safe", "remote", "scripts"} else "safe"
    html_doc = reviewer_object_frame_html(import_id, obj, mode)
    log_event(user["username"], "REVIEWER_OBJECT_FRAME_SERVED", details={"reviewer_import_id": import_id, "reviewer_object_id": object_id, "mode": mode})
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
        z.writestr("README.txt", "Report-only bundle. No original evidence/media bytes are included. Open case_report.html first. Saved page viewers are in saved_pages/. They are safe reconstructed viewers and do not fetch remote resources.\n")
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


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, msg: str | None = None) -> HTMLResponse:
    user = require_admin(request)
    s = all_settings()
    users = fetchall("SELECT * FROM users ORDER BY username")
    user_rows = "".join(f"<tr><td>{h(r['username'])}</td><td>{h(r['role'])}</td><td>{h(r['image_policy'])}</td><td>{'yes' if r['require_master_key'] else 'no'}</td><td>{'yes' if r['require_approval'] else 'no'}</td><td>{'yes' if r['require_webauthn'] else 'no'}</td></tr>" for r in users)
    def opt(name: str, value: str, label: str | None = None) -> str:
        return f"<option value='{h(value)}' {'selected' if s.get(name)==value else ''}>{h(label or value)}</option>"
    sealed_mime_allowlist = h(s.get("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/"))
    body = f"""{flash(msg)}<div class='card'><h2>Global safety profile</h2><form method='post' action='/settings'>
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
      <label><input type='checkbox' name='capture_settle_before_save' value='1' {'checked' if truthy(s.get('capture_settle_before_save','1')) else ''}> Capture: wait/settle before saving manual and auto captures</label>
      <label><input type='checkbox' name='capture_auto_scroll_enabled' value='1' {'checked' if truthy(s.get('capture_auto_scroll_enabled','1')) else ''}> Capture: auto-scroll before saving to trigger lazy-loaded content</label>
      <div class='row'><div><label>Capture wait after load (ms)</label><input name='capture_wait_after_load_ms' value='{h(s.get('capture_wait_after_load_ms','1500'))}'></div><div><label>Capture network-idle timeout (ms)</label><input name='capture_network_idle_timeout_ms' value='{h(s.get('capture_network_idle_timeout_ms','8000'))}'></div><div><label>Capture total settle timeout (ms)</label><input name='capture_settle_timeout_ms' value='{h(s.get('capture_settle_timeout_ms','30000'))}'></div></div>
      <div class='row'><div><label>Auto-scroll max steps</label><input name='capture_auto_scroll_max_steps' value='{h(s.get('capture_auto_scroll_max_steps','30'))}'></div><div><label>Auto-scroll pause (ms)</label><input name='capture_auto_scroll_pause_ms' value='{h(s.get('capture_auto_scroll_pause_ms','550'))}'></div><div><label>Stable rounds before save</label><input name='capture_stable_rounds' value='{h(s.get('capture_stable_rounds','3'))}'></div></div>
      <div class='row'><div><label>Initial navigation timeout (ms)</label><input name='live_initial_navigation_timeout_ms' value='{h(s.get('live_initial_navigation_timeout_ms','60000'))}'></div><div><label>Auto-capture delay after navigation (ms)</label><input name='live_auto_capture_delay_ms' value='{h(s.get('live_auto_capture_delay_ms','2500'))}'></div><div><label>Reviewer default render mode</label><select name='reviewer_default_render_mode'><option value='auto' {'selected' if s.get('reviewer_default_render_mode','auto')=='auto' else ''}>auto / best available</option><option value='safe' {'selected' if s.get('reviewer_default_render_mode','auto')=='safe' else ''}>safe local only</option><option value='remote' {'selected' if s.get('reviewer_default_render_mode','auto')=='remote' else ''}>allow remote callbacks</option><option value='scripts' {'selected' if s.get('reviewer_default_render_mode','auto')=='scripts' else ''}>allow remote + scripts</option></select></div></div>
      <label><input type='checkbox' name='reviewer_enabled' value='1' {'checked' if truthy(s.get('reviewer_enabled','1')) else ''}> Enable law-enforcement / cleared reviewer import and viewer area</label>
      <label><input type='checkbox' name='sealed_export_enabled' value='1' {'checked' if truthy(s.get('sealed_export_enabled','1')) else ''}> Enable sealed encrypted law-enforcement evidence export</label>
      <label><input type='checkbox' name='sealed_export_include_derived' value='1' {'checked' if truthy(s.get('sealed_export_include_derived','1')) else ''}> Sealed export includes encrypted derived artifacts/snapshots when available</label>
      <div class='card warn'><h3>Sealed Media Preservation Mode</h3><p class='small muted'>Works in both Organization-Controlled Key and Civilian Unknown Master Key modes. Blocked images/video/audio remain invisible in the live browser, but selected blocked media can be stored encrypted for sealed reviewer / law-enforcement access. Organization mode can use normal local vault encryption or optional hard-sealed reviewer-key storage; civilian mode local reveal remains blocked.</p><label><input type='checkbox' name='sealed_media_preservation_enabled' value='1' {'checked' if truthy(s.get('sealed_media_preservation_enabled','0')) else ''}> Enable sealed media preservation globally</label><label><input type='checkbox' name='sealed_media_preserve_images' value='1' {'checked' if truthy(s.get('sealed_media_preserve_images','1')) else ''}> Preserve blocked images encrypted</label><label><input type='checkbox' name='sealed_media_preserve_video' value='1' {'checked' if truthy(s.get('sealed_media_preserve_video','1')) else ''}> Preserve blocked video encrypted</label><label><input type='checkbox' name='sealed_media_preserve_audio' value='1' {'checked' if truthy(s.get('sealed_media_preserve_audio','1')) else ''}> Preserve blocked audio encrypted</label><div class='row'><div><label>Preservation mode</label><select name='sealed_media_preserve_mode'><option value='fast' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='fast' else ''}>fast / least page slowdown</option><option value='balanced' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='balanced' else ''}>balanced / default</option><option value='complete' {'selected' if s.get('sealed_media_preserve_mode','balanced')=='complete' else ''}>complete / try harder</option></select></div><div><label>Route fetch timeout (ms)</label><input name='sealed_media_preserve_fetch_timeout_ms' value='{h(s.get('sealed_media_preserve_fetch_timeout_ms','3500'))}'></div><div><label>Background timeout (ms)</label><input name='sealed_media_preserve_background_timeout_ms' value='{h(s.get('sealed_media_preserve_background_timeout_ms','18000'))}'></div></div><div class='row'><div><label>Max bytes per preserved object</label><input name='sealed_media_preserve_max_bytes' value='{h(s.get('sealed_media_preserve_max_bytes','52428800'))}'></div><div><label>Max total bytes per live session</label><input name='sealed_media_preserve_max_total_bytes' value='{h(s.get('sealed_media_preserve_max_total_bytes','209715200'))}'></div><div><label>Max preserved items per live session</label><input name='sealed_media_preserve_max_items_per_session' value='{h(s.get('sealed_media_preserve_max_items_per_session','250'))}'></div><div><label>Max pending background tasks</label><input name='sealed_media_preserve_max_pending_tasks' value='{h(s.get('sealed_media_preserve_max_pending_tasks','12'))}'><p class='small muted'>Raise to 24–64 if you see queue full.</p></div></div><label><input type='checkbox' name='sealed_media_preserve_skip_decorative_fast' value='1' {'checked' if truthy(s.get('sealed_media_preserve_skip_decorative_fast','1')) else ''}> Fast mode: skip/deprioritize decorative logo/favicon/badge assets so they do not slow page loading</label><label>MIME allowlist, one prefix/type per line</label><textarea name='sealed_media_preserve_mime_allowlist'>{sealed_mime_allowlist}</textarea><div class='card warn'><h3>Organization hard-sealed preserved media</h3><p class='small muted'>Organization mode only. When enabled, preserved blocked media is encrypted to this organization/reviewer public key at capture time. The local vault key cannot decrypt those preserved media originals; reviewer import requires the matching private key.</p><label><input type='checkbox' name='organization_hard_seal_media_enabled' value='1' {'checked' if truthy(s.get('organization_hard_seal_media_enabled','0')) else ''}> Hard-seal preserved blocked media to organization escrow public key</label><label>Organization escrow public key PEM</label><textarea name='organization_hard_seal_public_key_pem' rows='8' placeholder='Paste organization/reviewer escrow_public_key.pem here'>{h(s.get('organization_hard_seal_public_key_pem',''))}</textarea><p class='small muted'>Current fingerprint: <code>{h(s.get('organization_hard_seal_public_key_fingerprint','') or 'not configured')}</code></p></div></div>
      <label><input type='checkbox' name='head_probe_blocked_media' value='1' {'checked' if truthy(s.get('head_probe_blocked_media')) else ''}> HEAD probe blocked media for headers without body download</label>
      <label><input type='checkbox' name='reject_inline_media_in_safe_mode' value='1' {'checked' if truthy(s.get('reject_inline_media_in_safe_mode')) else ''}> Safe mode: minimize/reject inline embedded media summaries</label>
      <div class='row'><div><label>Max root read bytes</label><input name='max_root_read_bytes' value='{h(s.get('max_root_read_bytes','524288'))}'></div><div><label>Max summary chars</label><input name='max_text_summary_chars' value='{h(s.get('max_text_summary_chars','20000'))}'></div><div><label>Max blocked records</label><input name='max_blocked_records' value='{h(s.get('max_blocked_records','1000'))}'></div></div>
      <div class='row'><div><label>Snapshot max media bytes per file</label><input name='snapshot_max_media_bytes' value='{h(s.get('snapshot_max_media_bytes','52428800'))}'></div><div><label>Snapshot max media items per capture</label><input name='snapshot_max_media_items' value='{h(s.get('snapshot_max_media_items','250'))}'></div><div><label>Snapshot max total bytes per live session</label><input name='snapshot_max_total_asset_bytes' value='{h(s.get('snapshot_max_total_asset_bytes','209715200'))}'></div></div>
      <label>Safe allowlist domains, one per line</label><textarea name='safe_allowlist_domains'>{h(s.get('safe_allowlist_domains',''))}</textarea>
      <label>Capture denylist domains, one per line</label><textarea name='capture_denylist_domains'>{h(s.get('capture_denylist_domains',''))}</textarea>
      <h3>Tor</h3><div class='card'><h3>Tor / One-Click managed Tor</h3><p>{tor_browser_status_html()}</p><label>Default live browser</label><select name='live_browser_default'>{browser_select_html('live_browser_default', s.get('live_browser_default','tor_managed_chromium'))}</select><label>Tor Browser path</label><input name='tor_browser_path' value='{h(s.get('tor_browser_path',''))}' placeholder='C:/Users/you/Desktop/Tor Browser/Browser/firefox.exe'><label>Bundled/standalone tor executable path</label><input name='tor_executable_path' value='{h(s.get('tor_executable_path',''))}' placeholder='Optional: .../TorBrowser/Tor/tor.exe'><label><input type='checkbox' name='tor_auto_start_from_browser_bundle' value='1' {'checked' if truthy(s.get('tor_auto_start_from_browser_bundle','1')) else ''}> One-click Tor: auto-start bundled tor.exe if SOCKS is not already open</label><label><input type='checkbox' name='tor_browser_force_socks' value='1' {'checked' if truthy(s.get('tor_browser_force_socks')) else ''}> When using Tor Browser option, also force the configured SOCKS proxy</label></div><div class='row'><div><label>Tor host</label><input name='tor_host' value='{h(s.get('tor_host','127.0.0.1'))}'></div><div><label>SOCKS port</label><input name='tor_socks_port' value='{h(s.get('tor_socks_port','9050'))}'><p class='small muted'>Auto-detect also checks 9150 and 9050.</p></div><div><label>Control port</label><input name='tor_control_port' value='{h(s.get('tor_control_port','9051'))}'></div></div><label>Tor control password (optional)</label><input name='tor_control_password' type='password' value='{h(s.get('tor_control_password',''))}'>
      <button class='good'>Save settings</button></form></div>
      <div class='card'><h2>Master reveal key</h2><form method='post' action='/settings/master-key'><label>New master reveal key</label><input name='master_key' type='password' minlength='12'><button class='danger'>Rotate master key</button></form></div>
      <div class='card'><h2>Create user</h2><form method='post' action='/settings/users'><div class='row'><div><label>Username</label><input name='username'></div><div><label>Password</label><input name='password' type='password'></div><div><label>Role</label><select name='role'><option value='investigator'>investigator</option><option value='supervisor'>supervisor</option><option value='reviewer'>reviewer</option><option value='admin'>admin</option></select></div><div><label>Image policy</label><select name='image_policy'><option value='none'>none</option><option value='blur'>blur</option><option value='full'>full</option></select></div></div><button>Create user</button></form><table><tr><th>User</th><th>Role</th><th>Image policy</th><th>Master</th><th>Approval</th><th>WebAuthn</th></tr>{user_rows}</table></div>
      <div class='card'><h2>Diagnostics</h2><p><a class='button' href='/self-test'>Self-test</a> <a class='button' href='/tor/status'>Tor status</a> <a class='button warn' href='/webauthn'>YubiKey/WebAuthn hooks</a></p></div>"""
    return layout(request, "Settings", body)


@app.post("/settings")
def settings_save(request: Request,
    edition: str = Form("lockdown"), default_capture_mode: str = Form("metadata_only"), default_media_policy: str = Form("block_images_video"), default_user_agent_profile: str = Form("chrome_windows"), custom_user_agent: str = Form(""), live_browser_default: str = Form("tor_managed_chromium"),
    hard_default_safe_mode: str | None = Form(None), disable_full_reveal_in_lockdown: str | None = Form(None), disable_plaintext_export_in_lockdown: str | None = Form(None), disable_materialization_in_lockdown: str | None = Form(None), allow_blur_in_lockdown: str | None = Form(None), require_master_key_full_reveal: str | None = Form(None), require_approval_full_reveal: str | None = Form(None), require_approval_plaintext_export: str | None = Form(None), require_approval_materialization: str | None = Form(None), live_javascript_enabled: str | None = Form(None), live_download_allowed_media_default: str | None = Form(None), live_auto_capture_default: str | None = Form(None), capture_settle_before_save: str | None = Form(None), capture_auto_scroll_enabled: str | None = Form(None), reviewer_enabled: str | None = Form(None), sealed_export_enabled: str | None = Form(None), sealed_export_include_derived: str | None = Form(None), sealed_media_preservation_enabled: str | None = Form(None), sealed_media_preserve_images: str | None = Form(None), sealed_media_preserve_video: str | None = Form(None), sealed_media_preserve_audio: str | None = Form(None), sealed_media_preserve_max_bytes: str = Form("52428800"), sealed_media_preserve_max_total_bytes: str = Form("209715200"), sealed_media_preserve_max_items_per_session: str = Form("250"), sealed_media_preserve_max_pending_tasks: str = Form("12"), sealed_media_preserve_mime_allowlist: str = Form("image/\nvideo/\naudio/"), sealed_media_preserve_mode: str = Form("balanced"), sealed_media_preserve_fetch_timeout_ms: str = Form("3500"), sealed_media_preserve_background_timeout_ms: str = Form("18000"), sealed_media_preserve_skip_decorative_fast: str | None = Form(None), organization_hard_seal_media_enabled: str | None = Form(None), organization_hard_seal_public_key_pem: str = Form(""), head_probe_blocked_media: str | None = Form(None), reject_inline_media_in_safe_mode: str | None = Form(None), max_root_read_bytes: str = Form("524288"), max_text_summary_chars: str = Form("20000"), max_blocked_records: str = Form("1000"), snapshot_max_media_bytes: str = Form("52428800"), snapshot_max_media_items: str = Form("250"), snapshot_max_total_asset_bytes: str = Form("209715200"), capture_wait_after_load_ms: str = Form("1500"), capture_network_idle_timeout_ms: str = Form("8000"), capture_settle_timeout_ms: str = Form("30000"), capture_auto_scroll_max_steps: str = Form("30"), capture_auto_scroll_pause_ms: str = Form("550"), capture_stable_rounds: str = Form("3"), live_initial_navigation_timeout_ms: str = Form("60000"), live_auto_capture_delay_ms: str = Form("2500"), reviewer_default_render_mode: str = Form("auto"), safe_allowlist_domains: str = Form(""), capture_denylist_domains: str = Form(""), tor_browser_path: str = Form(""), tor_executable_path: str = Form(""), tor_auto_start_from_browser_bundle: str | None = Form(None), tor_browser_force_socks: str | None = Form(None), tor_host: str = Form("127.0.0.1"), tor_socks_port: str = Form("9050"), tor_control_port: str = Form("9051"), tor_control_password: str = Form("")) -> RedirectResponse:
    user = require_admin(request)
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
    if live_browser_default not in BROWSERS: live_browser_default = "tor_managed_chromium"
    if reviewer_default_render_mode not in {"auto", "safe", "remote", "scripts"}: reviewer_default_render_mode = "auto"
    vals = locals().copy(); vals.pop("request"); vals.pop("user")
    for key in ["hard_default_safe_mode", "disable_full_reveal_in_lockdown", "disable_plaintext_export_in_lockdown", "disable_materialization_in_lockdown", "allow_blur_in_lockdown", "require_master_key_full_reveal", "require_approval_full_reveal", "require_approval_plaintext_export", "require_approval_materialization", "live_javascript_enabled", "live_download_allowed_media_default", "live_auto_capture_default", "capture_settle_before_save", "capture_auto_scroll_enabled", "reviewer_enabled", "sealed_export_enabled", "sealed_export_include_derived", "sealed_media_preservation_enabled", "sealed_media_preserve_images", "sealed_media_preserve_video", "sealed_media_preserve_audio", "sealed_media_preserve_skip_decorative_fast", "organization_hard_seal_media_enabled", "tor_auto_start_from_browser_bundle", "tor_browser_force_socks", "head_probe_blocked_media", "reject_inline_media_in_safe_mode"]:
        vals[key] = "1" if vals.get(key) else "0"
    vals["sealed_media_preserve_max_bytes"] = str(safe_int(vals.get("sealed_media_preserve_max_bytes"), 52428800, min_value=1048576))
    vals["sealed_media_preserve_max_total_bytes"] = str(safe_int(vals.get("sealed_media_preserve_max_total_bytes"), 209715200, min_value=1048576))
    vals["sealed_media_preserve_max_items_per_session"] = str(safe_int(vals.get("sealed_media_preserve_max_items_per_session"), 250, min_value=1))
    vals["sealed_media_preserve_max_pending_tasks"] = str(safe_int(vals.get("sealed_media_preserve_max_pending_tasks"), 12, min_value=1, max_value=1000))
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
    return RedirectResponse("/settings?msg=Settings%20saved", 303)


@app.post("/settings/master-key")
def settings_master(request: Request, master_key: str = Form(...)) -> RedirectResponse:
    user = require_admin(request)
    if civilian_unknown_master_mode():
        raise HTTPException(403, "Civilian Unknown Master Key mode blocks local master-key rotation")
    set_master_key(master_key)
    log_event(user["username"], "MASTER_KEY_ROTATED")
    return RedirectResponse("/settings?msg=Master%20key%20updated", 303)


@app.post("/settings/users")
def settings_create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("investigator"), image_policy: str = Form("blur")) -> RedirectResponse:
    user = require_admin(request)
    if role not in {"investigator", "supervisor", "reviewer", "admin"}: role = "investigator"
    if image_policy not in {"none", "blur", "full"}: image_policy = "blur"
    if len(password) < 8: raise HTTPException(400, "Password too short")
    execute("INSERT INTO users(username,password_hash,role,image_policy,require_master_key,require_approval,created_at) VALUES(?,?,?,?,?,?,?)", (username.strip(), hash_password(password), role, image_policy, 1 if role == "investigator" else 0, 1 if role == "investigator" else 0, utcnow()))
    log_event(user["username"], "USER_CREATED", details={"username": username, "role": role, "image_policy": image_policy})
    return RedirectResponse("/settings?msg=User%20created", 303)


def tor_status_data() -> dict[str, Any]:
    host = get_setting("tor_host", "127.0.0.1")
    socks = int(get_setting("tor_socks_port", "9050") or "9050")
    ctrl = int(get_setting("tor_control_port", "9051") or "9051")
    out = {"host": host, "socks_port": socks, "control_port": ctrl, "socks_open": False, "control_open": False}
    for key, port in [("socks_open", socks), ("control_open", ctrl)]:
        try:
            with socket.create_connection((host, port), timeout=2):
                out[key] = True
        except Exception as exc:
            out[key + "_error"] = str(exc)
    return out


@app.get("/tor/status")
def tor_status(request: Request) -> JSONResponse:
    require_user(request)
    return JSONResponse(tor_status_data())


@app.post("/tor/newnym")
def tor_newnym(request: Request) -> JSONResponse:
    user = require_user(request)
    host = get_setting("tor_host", "127.0.0.1")
    port = int(get_setting("tor_control_port", "9051") or "9051")
    pw = get_setting("tor_control_password", "")
    result: dict[str, Any] = {"ok": False}
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rw", newline="\r\n")
            if pw:
                f.write(f'AUTHENTICATE "{pw}"\r\n')
            else:
                f.write('AUTHENTICATE\r\n')
            f.flush(); auth = f.readline().strip()
            f.write('SIGNAL NEWNYM\r\n'); f.flush(); resp = f.readline().strip()
            f.write('QUIT\r\n'); f.flush()
            result = {"ok": auth.startswith("250") and resp.startswith("250"), "auth": auth, "response": resp}
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
    log_event(user["username"], "TOR_NEWNYM_REQUESTED", details=result)
    return JSONResponse(result)


@app.get("/webauthn", response_class=HTMLResponse)
def webauthn_page(request: Request) -> HTMLResponse:
    require_user(request)
    return layout(request, "YubiKey / WebAuthn", "<div class='card'><h2>Hardware-key support hooks</h2><p>This build keeps per-user WebAuthn/YubiKey policy flags and blocks full reveal for accounts requiring hardware-key step-up unless integrated enrollment is completed. Use the <code>fido2</code> package and a trusted HTTPS deployment for production WebAuthn ceremonies.</p><p class='muted'>Localhost is acceptable for browser testing, but agency deployment should use counsel/IT-approved identity management.</p></div>")


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


def run_self_tests() -> dict[str, Any]:
    init_db()
    tests: dict[str, Any] = {"app": APP_NAME, "version": APP_VERSION, "time": utcnow()}
    tests["database"] = DB_PATH.exists()
    tests["fernet_key"] = KEY_FILE.exists()
    sample = b"selftest-" + secrets.token_bytes(8)
    tests["encryption_roundtrip"] = decrypt_bytes(encrypt_bytes(sample)) == sample
    tests["audit"] = verify_audit_chain()
    tests["tor"] = tor_status_data()
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
    url = f"http://{host}:{port}"
    print(f"\n{APP_NAME} {APP_VERSION}\nOpen: {url}\nDefault login on first run: admin / change-me-now\n")
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
    uvicorn.run(app, host=host, port=port, reload=False)


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
