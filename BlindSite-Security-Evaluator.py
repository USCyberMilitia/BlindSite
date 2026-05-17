#!/usr/bin/env python3
"""
BlindSite Claims Validation Suite

US CYBER MILITIA | BLINDSITE

Standalone validation harness for BlindSite.py.

What this validates:
- app compiles and self-test runs;
- local vault evidence is encrypted at rest;
- Civilian Unknown Master Key hard-sealed evidence cannot be decrypted by the local vault key;
- Organization hard-sealed media cannot be decrypted by the local vault key;
- matching escrow private keys can decrypt reviewer/sealed packages where appropriate;
- wrong private keys fail;
- sealed export contains .fvault evidence objects and no plaintext test payload;
- reviewer decrypt/import recovers expected fake evidence with the right private key;
- audit-chain tampering is detected;
- storage tampering changes the storage hash;
- true local live browser blocked-media integration test: blocked from display -> background preserved -> hard-sealed -> logged -> sealed export -> reviewer recovery -> wrong key fails;
- optional external website sample image can be fetched quickly and pushed through the same hard-sealed preservation path;
- public repo hygiene scan can flag obvious secrets/private artifacts;
- reviewer import password protection stores only a hash and gates locked imports through session state;
- optional PDF report encryption produces an encrypted PDF that rejects the wrong password and accepts the correct password.

Important:
This suite provides technical validation evidence. It does not certify legal admissibility,
courtroom defensibility, or operational fitness for every environment.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import hashlib
import http.server
import importlib.util
import json
import os
import platform
import py_compile
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


APP_VERSION = "1.3-review-password-pdf-encryption-security"
DEFAULT_TIMEOUT = 8
MAX_WEBSITE_IMAGE_BYTES = 2_000_000
LIVE_BROWSER_TEST_TIMEOUT = 45


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


class Validator:
    def __init__(self, *, app_path: Path, report_root: Path, keep_temp: bool = False, verbose: bool = True):
        self.original_app_path = app_path.expanduser().resolve()
        self.report_root = report_root.expanduser().resolve()
        self.keep_temp = keep_temp
        self.verbose = verbose
        self.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.checks: list[Check] = []
        self.tempdir_obj: tempfile.TemporaryDirectory[str] | None = None
        self.workdir: Path | None = None
        self.app_copy: Path | None = None
        self.m = None
        self.test_payloads: dict[str, bytes] = {}
        self.org_private_pem: bytes | None = None
        self.org_private_passphrase: str = ""
        self.org_public_pem: str = ""
        self.org_public_fp: str = ""
        self.wrong_private_pem: bytes | None = None
        self.wrong_private_passphrase: str = ""
        self.wrong_public_pem: str = ""
        self.wrong_public_fp: str = ""
        self.case_id: int | None = None
        self.normal_eid: int | None = None
        self.civilian_eid: int | None = None
        self.org_hard_eid: int | None = None
        self.website_eid: int | None = None
        self.live_page_eid: int | None = None
        self.live_media_eid: int | None = None
        self.live_media_payload: bytes | None = None
        self.live_media_url: str = ""
        self.live_session_id: str = ""
        self.sealed_package_bytes: bytes | None = None
        self.reconstruction_dir: Path | None = None
        self.reconstruction_artifacts: list[dict[str, Any]] = []
        self.reconstruction_steps: list[dict[str, Any]] = []
        self.payload_registry: dict[str, dict[str, Any]] = {}

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def add(self, name: str, status: str, detail: str = "", **evidence: Any) -> None:
        self.checks.append(Check(name=name, status=status, detail=detail, evidence=evidence))
        prefix = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️", "INFO": "ℹ️"}.get(status, "•")
        self.log(f"{prefix} {status}: {name}" + (f" — {detail}" if detail else ""))

    def fail(self, name: str, detail: str, **evidence: Any) -> None:
        self.add(name, "FAIL", detail, **evidence)

    def pass_(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "PASS", detail, **evidence)

    def warn(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "WARN", detail, **evidence)

    def skip(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "SKIP", detail, **evidence)

    def setup(self) -> None:
        if not self.original_app_path.exists():
            raise SystemExit(f"BlindSite file not found: {self.original_app_path}")
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.tempdir_obj = tempfile.TemporaryDirectory(prefix="blindsite_validation_")
        self.workdir = Path(self.tempdir_obj.name)
        self.app_copy = self.workdir / "BlindSite_under_test.py"
        self.reconstruction_dir = self.workdir / "reconstruction_artifacts"
        self.reconstruction_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.original_app_path, self.app_copy)
        self.log(f"Using sandbox: {self.workdir}")
        self.log(f"Copied app under test: {self.app_copy}")
        self.write_artifact_json("environment/run_context.json", self.run_context(), "Run context and environment metadata")

    def cleanup(self) -> None:
        if self.keep_temp:
            self.warn("temporary sandbox retained", str(self.workdir))
            return
        if self.tempdir_obj:
            self.tempdir_obj.cleanup()

    def import_app(self) -> Any:
        assert self.app_copy is not None
        spec = importlib.util.spec_from_file_location("blindsite_under_test", self.app_copy)
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not create import spec for BlindSite file")
        module = importlib.util.module_from_spec(spec)
        sys.modules["blindsite_under_test"] = module
        spec.loader.exec_module(module)
        self.m = module
        return module

    def run(self, website_url: str = "", use_existing_org_keys: bool = False, org_public_key_path: str = "", org_private_key_path: str = "", org_private_passphrase: str = "", run_live_browser_test: bool = True) -> None:
        self.setup()
        try:
            self.test_compile()
            self.test_selftest_subprocess()
            m = self.import_app()
            m.init_db()
            self.pass_("import and isolated DB init", "BlindSite imported inside a temporary sandbox", version=getattr(m, "APP_VERSION", "unknown"))
            self.prepare_keys(use_existing_org_keys, org_public_key_path, org_private_key_path, org_private_passphrase)
            self.test_keypair_integrity()
            self.create_case()
            self.test_normal_vault_encryption()
            self.test_civilian_unknown_hard_seal()
            self.test_organization_hard_sealed_media()
            if website_url:
                self.test_website_sample_media(website_url)
            if run_live_browser_test:
                self.test_live_browser_blocked_media_integration()
            else:
                self.skip("live browser blocked-media integration", "disabled by user")
            self.test_sealed_export_and_reviewer_decrypt()
            self.test_reviewer_import_password_protection()
            self.test_pdf_report_encryption()
            self.test_wrong_private_key_fails()
            self.test_audit_chain_tamper_detection()
            self.test_storage_hash_tamper_detection()
            self.scan_public_repo_hygiene(self.original_app_path.parent)
        except Exception as exc:
            self.fail("validation suite crashed", str(exc), traceback=traceback.format_exc(limit=12))
        finally:
            self.write_reports()
            self.cleanup()

    def test_compile(self) -> None:
        assert self.app_copy is not None
        try:
            py_compile.compile(str(self.app_copy), doraise=True)
            self.pass_("Python compile", "py_compile completed without syntax errors")
        except Exception as exc:
            self.fail("Python compile", str(exc))
            raise

    def test_selftest_subprocess(self) -> None:
        assert self.app_copy is not None and self.workdir is not None
        try:
            result = subprocess.run(
                [sys.executable, str(self.app_copy), "--self-test"],
                cwd=str(self.workdir),
                text=True,
                capture_output=True,
                timeout=60,
            )
            if result.returncode == 0:
                self.pass_("BlindSite --self-test", "self-test command exited 0", stdout_tail=result.stdout[-1000:])
            else:
                self.fail("BlindSite --self-test", f"exit code {result.returncode}", stdout=result.stdout[-1000:], stderr=result.stderr[-1000:])
        except subprocess.TimeoutExpired:
            self.fail("BlindSite --self-test", "timed out after 60 seconds")
        except Exception as exc:
            self.fail("BlindSite --self-test", str(exc))

    def prepare_keys(self, use_existing: bool, public_path: str, private_path: str, passphrase: str) -> None:
        if use_existing:
            pub_p = Path(public_path).expanduser()
            priv_p = Path(private_path).expanduser()
            if not pub_p.exists() or not priv_p.exists():
                raise SystemExit("Existing organization key paths were requested but one or both files were missing")
            self.org_public_pem = pub_p.read_text(encoding="utf-8")
            self.org_private_pem = priv_p.read_bytes()
            self.org_private_passphrase = passphrase
            self.org_public_fp = public_key_fingerprint_from_pem(self.org_public_pem)
            self.pass_("organization key loaded", "existing public/private key loaded; private key not copied to reports", public_key_fingerprint=self.org_public_fp, public_key_file=pub_p.name, private_key_file=priv_p.name)
        else:
            private_pem, public_pem, fp, pw = generate_encrypted_rsa_keypair()
            self.org_private_pem = private_pem
            self.org_private_passphrase = pw
            self.org_public_pem = public_pem
            self.org_public_fp = fp
            self.pass_("temporary organization key generated", "disposable encrypted keypair generated in memory", public_key_fingerprint=fp)

        wrong_private, wrong_public, wrong_fp, wrong_pw = generate_encrypted_rsa_keypair()
        self.wrong_private_pem = wrong_private
        self.wrong_private_passphrase = wrong_pw
        self.wrong_public_pem = wrong_public
        self.wrong_public_fp = wrong_fp
        self.pass_("wrong-key control generated", "disposable wrong keypair generated for negative tests", public_key_fingerprint=wrong_fp)

    def test_keypair_integrity(self) -> None:
        assert self.org_private_pem is not None
        try:
            private_key = serialization.load_pem_private_key(self.org_private_pem, password=self.org_private_passphrase.encode("utf-8"))
            public_key = serialization.load_pem_public_key(self.org_public_pem.encode("utf-8"))
            fp_priv = public_key_fingerprint_from_key(private_key)
            fp_pub = public_key_fingerprint_from_key(public_key)
            if fp_priv == fp_pub == self.org_public_fp:
                self.pass_("organization public/private key match", "fingerprints match", fingerprint=self.org_public_fp)
            else:
                self.fail("organization public/private key match", "fingerprints did not match", public_fp=fp_pub, private_fp=fp_priv, expected=self.org_public_fp)
        except Exception as exc:
            self.fail("organization public/private key match", str(exc))
            raise

        try:
            serialization.load_pem_private_key(self.org_private_pem, password=b"wrong-passphrase")
            self.fail("private key wrong passphrase rejection", "private key unexpectedly loaded with wrong passphrase")
        except Exception:
            self.pass_("private key wrong passphrase rejection", "wrong passphrase did not unlock the private key")

    def create_case(self) -> None:
        m = self.m
        assert m is not None
        self.case_id = m.execute("""INSERT INTO cases(name,description,mode,compliance_safe,irreversible_lock,never_materialize_originals,no_plaintext_export,raw_root_allowed,default_media_policy,force_tor,quarantine_default,created_by,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            "Validation Case",
            "Fake validation case generated by BlindSite Claims Validation Suite.",
            "lab",
            0,
            0,
            1,
            1,
            1,
            "block_images_video",
            0,
            1,
            "validation_suite",
            m.utcnow(),
        ))
        self.pass_("fake case created", f"case_id={self.case_id}")

    def payload(self, label: str) -> bytes:
        if label not in self.test_payloads:
            token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
            self.test_payloads[label] = f"BLINDSITE_VALIDATION_SECRET::{label}::{token}".encode("utf-8")
            self.record_payload(label, self.test_payloads[label], f"Original fake validation payload for {label}", write_bytes=True, mime="text/plain")
        return self.test_payloads[label]

    def evidence_file_bytes(self, eid: int) -> bytes:
        m = self.m
        ev = m.evidence_for(eid)
        if not ev:
            raise RuntimeError(f"evidence {eid} not found")
        return m.data_path(ev["object_path"]).read_bytes()

    def run_context(self) -> dict[str, Any]:
        return {
            "suite_version": APP_VERSION,
            "started_at_utc": self.started,
            "argv": sys.argv[:],
            "python_version": sys.version,
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "working_directory": str(Path.cwd()),
            "app_file": str(self.original_app_path),
            "app_sha256": sha256_file(self.original_app_path) if self.original_app_path.exists() else "",
            "sandbox": str(self.workdir) if self.workdir else "",
            "note": "Private-key passphrases are never written to reports. Private keys are not copied to reconstruction artifacts.",
        }

    def artifact_path(self, rel_path: str) -> Path:
        if self.reconstruction_dir is None:
            raise RuntimeError("reconstruction directory not initialized")
        clean = rel_path.replace("\\", "/").lstrip("/")
        if ".." in Path(clean).parts:
            raise ValueError("artifact path cannot contain ..")
        p = self.reconstruction_dir / clean
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_artifact_bytes(self, rel_path: str, data: bytes, description: str, *, category: str = "artifact", mime: str = "application/octet-stream") -> dict[str, Any]:
        p = self.artifact_path(rel_path)
        p.write_bytes(data)
        record = {
            "path": rel_path.replace("\\", "/"),
            "description": description,
            "category": category,
            "mime": mime,
            "size": len(data),
            "sha256": sha256_bytes(data),
        }
        self.reconstruction_artifacts.append(record)
        return record

    def write_artifact_json(self, rel_path: str, obj: Any, description: str, *, category: str = "json") -> dict[str, Any]:
        data = json.dumps(obj, indent=2, default=str, ensure_ascii=False).encode("utf-8")
        return self.write_artifact_bytes(rel_path, data, description, category=category, mime="application/json")

    def record_step(self, name: str, detail: str = "", **data: Any) -> None:
        self.reconstruction_steps.append({
            "index": len(self.reconstruction_steps) + 1,
            "name": name,
            "detail": detail,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "data": data,
        })

    def parse_hard_sealed_container(self, stored: bytes) -> dict[str, Any] | None:
        """Compatibility wrapper for BlindSite versions with differently named parsers."""
        m = self.m
        for fn_name in ("parse_hard_sealed_container", "parse_escrow_hard_sealed_container"):
            fn = getattr(m, fn_name, None)
            if callable(fn):
                try:
                    return fn(stored)
                except Exception:
                    return None
        try:
            obj = json.loads(stored.decode("utf-8"))
            if isinstance(obj, dict) and ("wrapped_key" in obj or "wrapped_object_key" in obj or "ciphertext" in obj):
                return obj
        except Exception:
            pass
        return None

    def hard_sealed_container_summary(self, stored: bytes) -> dict[str, Any] | None:
        c = self.parse_hard_sealed_container(stored)
        if not c:
            return None
        summary: dict[str, Any] = {}
        for k in ("magic", "version", "alg", "algorithm", "kdf", "escrow_public_key_fingerprint", "object_key_alg", "content_alg"):
            if k in c:
                summary[k] = c.get(k)
        for k, v in c.items():
            if isinstance(v, str) and any(term in k.lower() for term in ("cipher", "wrapped", "nonce", "salt", "tag")):
                raw = v.encode("utf-8")
                summary[f"{k}_text_len"] = len(v)
                summary[f"{k}_sha256_of_text"] = sha256_bytes(raw)
        return summary

    def evidence_snapshot(self, label: str, eid: int, *, original_payload_label: str = "") -> dict[str, Any]:
        m = self.m
        ev = m.evidence_for(eid)
        if not ev:
            raise RuntimeError(f"evidence {eid} not found")
        evd = dict(ev)
        stored = self.evidence_file_bytes(eid)
        object_copy = self.write_artifact_bytes(
            f"evidence_objects/{eid:06d}_{safe_filename(str(evd.get('filename') or label))}.fvault",
            stored,
            f"Encrypted stored .fvault bytes for evidence_id={eid} ({label})",
            category="encrypted_evidence_object",
            mime="application/octet-stream",
        )
        meta = safe_json_loads(evd.get("meta_json"))
        snapshot = {
            "label": label,
            "evidence_id": eid,
            "row": sanitize_mapping(evd),
            "meta_json_parsed": meta,
            "stored_object": object_copy,
            "stored_sha256": sha256_bytes(stored),
            "stored_size": len(stored),
            "stored_path_in_sandbox": str(m.data_path(evd["object_path"])),
            "hard_sealed_container_summary": self.hard_sealed_container_summary(stored),
            "original_payload_label": original_payload_label,
            "original_payload_sha256": self.payload_registry.get(original_payload_label, {}).get("sha256") if original_payload_label else "",
            "plaintext_marker_present_in_stored_object": (self.test_payloads.get(original_payload_label, b"__missing__") in stored) if original_payload_label else None,
        }
        self.write_artifact_json(f"snapshots/evidence_{eid:06d}_{safe_filename(label)}.json", snapshot, f"Evidence row/object snapshot for {label}", category="evidence_snapshot")
        return snapshot

    def rows_snapshot(self, label: str, rows: list[Any], *, rel_path: str | None = None) -> dict[str, Any]:
        clean_rows = [sanitize_mapping(dict(r)) for r in rows]
        snapshot = {"label": label, "row_count": len(clean_rows), "rows": clean_rows}
        self.write_artifact_json(rel_path or f"snapshots/{safe_filename(label)}.json", snapshot, f"Database row snapshot: {label}", category="db_snapshot")
        return snapshot

    def record_payload(self, label: str, payload: bytes, description: str, *, write_bytes: bool = True, mime: str = "application/octet-stream") -> dict[str, Any]:
        rec = {
            "label": label,
            "description": description,
            "size": len(payload),
            "sha256": sha256_bytes(payload),
            "safe_fake_test_payload": True,
        }
        if write_bytes:
            art = self.write_artifact_bytes(f"original_payloads/{safe_filename(label)}.bin", payload, description, category="original_fake_payload", mime=mime)
            rec["artifact"] = art
        self.payload_registry[label] = rec
        return rec

    def test_normal_vault_encryption(self) -> None:
        m = self.m
        payload = self.payload("normal_vault")
        m.set_setting("custody_mode", "organization")
        m.set_setting("organization_hard_seal_media_enabled", "0")
        eid = m.persist_evidence(
            case_id=self.case_id,
            actor="validation_suite",
            kind="document",
            source_type="validation_normal_vault",
            source_ref="validation://normal",
            filename="normal_vault_validation.txt",
            mime_type="text/plain",
            payload=payload,
            encrypt=True,
            storage_mode="validation_normal_vault",
            raw_persisted=True,
            meta={"validation": True},
            lock_original=False,
            disable_plaintext=False,
            never_materialize=False,
        )
        self.normal_eid = eid
        self.record_step("normal_vault_evidence_persisted", "Normal vault encrypted fake evidence was persisted", evidence_id=eid, original_payload_sha256=sha256_bytes(payload))
        self.evidence_snapshot("normal_vault", eid, original_payload_label="normal_vault")
        stored = self.evidence_file_bytes(eid)
        if payload in stored:
            self.fail("normal vault plaintext absence", "plaintext marker was found inside stored .fvault file", evidence_id=eid)
        else:
            self.pass_("normal vault plaintext absence", "stored .fvault does not contain plaintext marker", evidence_id=eid)
        recovered = m.read_evidence(eid)
        if recovered == payload:
            self.pass_("normal vault authorized read", "local vault can recover normal encrypted evidence", evidence_id=eid)
        else:
            self.fail("normal vault authorized read", "recovered payload mismatch", evidence_id=eid)

    def test_civilian_unknown_hard_seal(self) -> None:
        m = self.m
        payload = self.payload("civilian_hard_seal")
        m.set_setting("custody_mode", "civilian_unknown_master")
        eid = m.persist_evidence(
            case_id=self.case_id,
            actor="validation_suite",
            kind="image",
            source_type="upload",
            source_ref="validation://civilian",
            filename="civilian_hard_sealed_image.bin",
            mime_type="image/png",
            payload=payload,
            encrypt=True,
            storage_mode="uploaded_original",
            raw_persisted=True,
            meta={"validation": True},
        )
        self.civilian_eid = eid
        self.record_step("civilian_hard_sealed_evidence_persisted", "Civilian Unknown Master Key fake evidence was persisted", evidence_id=eid, original_payload_sha256=sha256_bytes(payload))
        self.evidence_snapshot("civilian_hard_seal", eid, original_payload_label="civilian_hard_seal")
        stored = self.evidence_file_bytes(eid)
        ev = m.evidence_for(eid)
        container = self.parse_hard_sealed_container(stored)
        if container and ev and int(ev["encrypted"]) == getattr(m, "HARD_SEALED_ENCRYPTED_FLAG", 2):
            self.pass_("civilian hard-sealed container", "stored as BlindSite hard-sealed escrow container", evidence_id=eid, escrow_fingerprint=container.get("escrow_public_key_fingerprint"))
        else:
            self.fail("civilian hard-sealed container", "stored object was not hard-sealed", evidence_id=eid, encrypted=ev["encrypted"] if ev else None)

        if payload in stored:
            self.fail("civilian hard-sealed plaintext absence", "plaintext marker was found inside hard-sealed file", evidence_id=eid)
        else:
            self.pass_("civilian hard-sealed plaintext absence", "local stored bytes do not contain plaintext marker", evidence_id=eid)

        try:
            m.decrypt_bytes(stored)
            self.fail("civilian hard-sealed vault-key rejection", "local vault key unexpectedly decrypted hard-sealed object", evidence_id=eid)
        except Exception:
            self.pass_("civilian hard-sealed vault-key rejection", "local vault key cannot decrypt hard-sealed object", evidence_id=eid)

        try:
            m.read_evidence(eid)
            self.fail("civilian hard-sealed local read blocked", "read_evidence unexpectedly returned hard-sealed civilian evidence", evidence_id=eid)
        except Exception as exc:
            if "hard-sealed" in str(exc).lower() or "403" in str(exc):
                self.pass_("civilian hard-sealed local read blocked", "local read path blocks civilian hard-sealed evidence", evidence_id=eid)
            else:
                self.fail("civilian hard-sealed local read blocked", str(exc), evidence_id=eid)

    def test_organization_hard_sealed_media(self) -> None:
        m = self.m
        payload = self.payload("org_hard_seal")
        m.set_setting("custody_mode", "organization")
        m.set_setting("organization_hard_seal_media_enabled", "1")
        m.set_setting("organization_hard_seal_public_key_pem", self.org_public_pem)
        m.set_setting("organization_hard_seal_public_key_fingerprint", self.org_public_fp)

        eid = m.persist_sealed_preserved_media(
            actor="validation_suite",
            case_id=self.case_id,
            session_id=None,
            root_evidence_id=None,
            page_url="https://validation.local/page",
            media_url="https://validation.local/media/org-hard-sealed.png",
            resource_type="image",
            mime_type="image/png",
            payload=payload,
            reason="validation suite organization hard-sealed media",
            source_engine="validation_suite",
        )
        self.org_hard_eid = eid
        self.record_step("organization_hard_sealed_media_persisted", "Organization hard-sealed fake media was persisted", evidence_id=eid, original_payload_sha256=sha256_bytes(payload), escrow_public_key_fingerprint=self.org_public_fp)
        self.evidence_snapshot("org_hard_seal", eid, original_payload_label="org_hard_seal")
        stored = self.evidence_file_bytes(eid)
        ev = m.evidence_for(eid)
        container = self.parse_hard_sealed_container(stored)
        if container and container.get("escrow_public_key_fingerprint") == self.org_public_fp:
            self.pass_("organization hard-sealed media container", "stored to organization escrow public key", evidence_id=eid, escrow_fingerprint=self.org_public_fp)
        else:
            self.fail("organization hard-sealed media container", "not sealed to expected organization public key", evidence_id=eid, expected=self.org_public_fp, actual=container.get("escrow_public_key_fingerprint") if container else None)

        if payload in stored:
            self.fail("organization hard-sealed plaintext absence", "plaintext marker found inside hard-sealed media file", evidence_id=eid)
        else:
            self.pass_("organization hard-sealed plaintext absence", "stored media does not contain plaintext marker", evidence_id=eid)

        try:
            m.decrypt_bytes(stored)
            self.fail("organization hard-sealed vault-key rejection", "local vault key unexpectedly decrypted organization hard-sealed media", evidence_id=eid)
        except Exception:
            self.pass_("organization hard-sealed vault-key rejection", "local vault key cannot decrypt organization hard-sealed media", evidence_id=eid)

        try:
            m.read_evidence(eid)
            self.fail("organization hard-sealed local read blocked", "read_evidence unexpectedly returned organization hard-sealed media", evidence_id=eid)
        except Exception as exc:
            if "organization escrow" in str(exc).lower() or "hard-sealed" in str(exc).lower() or "403" in str(exc):
                self.pass_("organization hard-sealed local read blocked", "local read path blocks organization hard-sealed media", evidence_id=eid)
            else:
                self.fail("organization hard-sealed local read blocked", str(exc), evidence_id=eid)

        private_key = serialization.load_pem_private_key(self.org_private_pem, password=self.org_private_passphrase.encode("utf-8"))
        recovered = m.escrow_hard_unseal_bytes(private_key, stored)
        if recovered == payload:
            self.pass_("organization hard-sealed private-key recovery", "matching private key recovered hard-sealed media", evidence_id=eid)
        else:
            self.fail("organization hard-sealed private-key recovery", "recovered payload mismatch", evidence_id=eid)

        wrong_key = serialization.load_pem_private_key(self.wrong_private_pem, password=self.wrong_private_passphrase.encode("utf-8"))
        try:
            m.escrow_hard_unseal_bytes(wrong_key, stored)
            self.fail("organization hard-sealed wrong-key failure", "wrong private key unexpectedly unsealed media", evidence_id=eid)
        except Exception:
            self.pass_("organization hard-sealed wrong-key failure", "wrong private key cannot unseal media", evidence_id=eid)

    def test_website_sample_media(self, website_url: str) -> None:
        self.log(f"\n🌐 Website sample test: {website_url}")
        try:
            sample = fetch_sample_image(website_url, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_WEBSITE_IMAGE_BYTES)
        except Exception as exc:
            self.warn("website sample image fetch", f"could not fetch sample image quickly: {exc}", url=website_url)
            return

        m = self.m
        payload = sample["payload"]
        # Store the website sample payload in-memory so sealed export/reviewer recovery
        # can verify that the exact downloaded media bytes were recovered.
        self.test_payloads["website_sample"] = payload
        self.record_payload("website_sample", payload, "External website sample image payload. Bytes are not written as an artifact by default; hash/size/source URL are recorded.", write_bytes=False, mime=sample.get("mime_type") or "application/octet-stream")
        media_url = sample["media_url"]
        mime_type = sample["mime_type"]
        m.set_setting("custody_mode", "organization")
        m.set_setting("organization_hard_seal_media_enabled", "1")
        m.set_setting("organization_hard_seal_public_key_pem", self.org_public_pem)
        m.set_setting("organization_hard_seal_public_key_fingerprint", self.org_public_fp)

        eid = m.persist_sealed_preserved_media(
            actor="validation_suite",
            case_id=self.case_id,
            session_id=None,
            root_evidence_id=None,
            page_url=website_url,
            media_url=media_url,
            resource_type="image",
            mime_type=mime_type,
            payload=payload,
            response_headers=sample.get("headers") or {},
            status_code=sample.get("status_code"),
            reason="validation suite website sample image",
            source_engine="validation_suite_website_sample",
        )
        self.website_eid = eid
        self.record_step("website_sample_media_persisted", "External website sample media was hard-sealed", evidence_id=eid, media_url=media_url, payload_sha256=sha256_bytes(payload))
        self.evidence_snapshot("website_sample", eid, original_payload_label="website_sample")
        stored = self.evidence_file_bytes(eid)
        container = self.parse_hard_sealed_container(stored)
        if container and payload not in stored:
            self.pass_("website sample hard-sealed preservation", "sample image was fetched and hard-sealed without plaintext on disk", evidence_id=eid, media_url=media_url, bytes=len(payload), mime_type=mime_type)
        else:
            self.fail("website sample hard-sealed preservation", "website sample was not hard-sealed correctly", evidence_id=eid, media_url=media_url)

    def test_live_browser_blocked_media_integration(self) -> None:
        """End-to-end live browser test for the most important runtime claim.

        Proves, in a local deterministic page:
        blocked from display -> queued/background preserved -> encrypted/hard-sealed ->
        logged -> included in sealed export later -> recoverable by reviewer later.
        """
        m = self.m
        assert m is not None
        self.log("\n🧪 Live browser blocked-media integration test")
        try:
            import playwright  # type: ignore  # noqa: F401
        except Exception as exc:
            self.warn("live browser blocked-media integration", "Playwright Python package not available; live browser test skipped", error=str(exc))
            return

        payload = tiny_png_bytes()
        self.live_media_payload = payload
        self.test_payloads["live_blocked_media"] = payload
        self.record_payload("live_blocked_media", payload, "Original fake live-browser blocked image payload served by local test website", write_bytes=True, mime="image/png")
        self.write_artifact_bytes("live_test_site/index.html", live_test_html_bytes(), "HTML served by the local live-browser validation site", category="live_test_site", mime="text/html")
        server = LocalMediaTestServer(payload)
        session = None
        try:
            server.start()
            start_url = server.url("/")
            self.live_media_url = server.url("/blocked-test-image.png")

            m.set_setting("custody_mode", "organization")
            m.set_setting("edition", "lab")
            m.set_setting("hard_default_safe_mode", "0")
            m.set_setting("sealed_media_preservation_enabled", "1")
            m.set_setting("sealed_media_preserve_images", "1")
            m.set_setting("sealed_media_preserve_video", "1")
            m.set_setting("sealed_media_preserve_audio", "1")
            m.set_setting("sealed_media_preserve_mime_allowlist", "image/\nvideo/\naudio/")
            m.set_setting("sealed_media_preserve_mode", "balanced")
            m.set_setting("sealed_media_preserve_max_pending_tasks", "24")
            m.set_setting("sealed_media_preserve_background_timeout_ms", "10000")
            m.set_setting("sealed_media_preserve_fetch_timeout_ms", "3000")
            m.set_setting("organization_hard_seal_media_enabled", "1")
            m.set_setting("organization_hard_seal_public_key_pem", self.org_public_pem)
            m.set_setting("organization_hard_seal_public_key_fingerprint", self.org_public_fp)

            m.execute("""UPDATE cases SET mode='lab', compliance_safe=0, raw_root_allowed=1,
                         default_media_policy='block_images_video', sealed_media_preservation_enabled=1,
                         sealed_media_preserve_images=1, sealed_media_preserve_video=1,
                         sealed_media_preserve_audio=1, sealed_media_preserve_max_bytes=?
                         WHERE id=?""", (MAX_WEBSITE_IMAGE_BYTES, self.case_id))

            try:
                session = m.start_live_session(
                    actor="validation_suite",
                    case_id=self.case_id,
                    start_url=start_url,
                    browser_choice="chromium",
                    use_tor=False,
                    media_policy="block_images_video",
                    headless=True,
                    sealed_media_preservation_session=True,
                    settle_before_capture=False,
                )
            except Exception as exc:
                msg = str(exc)
                if "Playwright" in msg or "browser" in msg.lower() or "Executable" in msg:
                    self.warn("live browser blocked-media integration", "could not start Playwright browser; install browsers to run this test", error=msg)
                    return
                self.fail("live browser start", msg)
                return

            self.live_session_id = session.session_id
            self.pass_("live browser session started", "controlled headless Chromium session started", session_id=session.session_id, start_url=start_url, media_url=self.live_media_url)
            self.record_step("live_browser_session_started", "Headless Chromium controlled browser session started for deterministic local test site", session_id=session.session_id, start_url=start_url, media_url=self.live_media_url)

            # Give the route handler/background queue a short deterministic window.
            deadline = time.time() + LIVE_BROWSER_TEST_TIMEOUT
            display_result = None
            status = {}
            while time.time() < deadline:
                status = session.preservation_status()
                try:
                    display_result = eval_on_live_page(session, """() => {
                        const img = document.getElementById('blocked-img');
                        return {
                          found: !!img,
                          complete: img ? img.complete : null,
                          naturalWidth: img ? img.naturalWidth : null,
                          naturalHeight: img ? img.naturalHeight : null,
                          currentSrc: img ? img.currentSrc : null,
                          bodyText: document.body ? document.body.innerText : ''
                        };
                    }""")
                except Exception:
                    display_result = None
                if status.get("blocked", 0) >= 1 and status.get("preserved", 0) >= 1:
                    break
                time.sleep(0.35)

            with contextlib.suppress(Exception):
                screenshot = screenshot_live_page(session)
                self.write_artifact_bytes("live_test_site/investigator_browser_after_block.png", screenshot, "Investigator browser screenshot after media blocking; fake image should not render", category="browser_screenshot", mime="image/png")

            if display_result and display_result.get("found") and int(display_result.get("naturalWidth") or 0) == 0:
                self.pass_("live media blocked from display", "test image element exists but did not render pixels in the investigator browser", display_result=display_result)
            else:
                self.fail("live media blocked from display", "test image appeared rendered or could not be verified", display_result=display_result, preservation_status=status)

            if int(status.get("blocked") or 0) >= 1:
                self.pass_("live blocked request counted", "Playwright route saw and blocked media request", preservation_status=status)
            else:
                self.fail("live blocked request counted", "no blocked media request was observed", preservation_status=status)

            if int(status.get("preserved") or 0) >= 1:
                self.pass_("live background preservation completed", "background preservation stored at least one blocked media object", preservation_status=status)
            else:
                self.fail("live background preservation completed", "blocked media was not preserved within timeout", preservation_status=status)

            try:
                page_eid = m.capture_live_session(session.session_id)
                self.live_page_eid = page_eid
                self.record_step("live_manual_page_captured", "Manual capture saved a page evidence record after blocked-media preservation", page_evidence_id=page_eid)
                with contextlib.suppress(Exception):
                    self.evidence_snapshot("live_manual_page_capture", page_eid)
                self.pass_("live manual page capture", "manual capture saved a page evidence record after blocked-media preservation", page_evidence_id=page_eid)
            except Exception as exc:
                self.fail("live manual page capture", str(exc), session_id=session.session_id)
                page_eid = None

            # Flush/stop after capture so records are definitely written.
            with contextlib.suppress(Exception):
                m.stop_live_session(session.session_id)
            time.sleep(0.5)

            rows = m.fetchall("""SELECT b.*, e.id AS ev_id, e.object_path, e.encrypted, e.storage_mode, e.meta_json
                                  FROM blocked_media b
                                  LEFT JOIN evidence e ON e.id=b.materialized_evidence_id
                                  WHERE b.session_id=? AND b.media_url LIKE ?
                                  ORDER BY b.id DESC""", (session.session_id, "%blocked-test-image.png%"))
            if rows:
                row = dict(rows[0])
                self.pass_("live blocked media logged", "blocked_media row exists for the test image", blocked_media_id=row.get("id"), downloaded=row.get("downloaded"), materialized_evidence_id=row.get("materialized_evidence_id"), reason=row.get("reason"))
            else:
                self.fail("live blocked media logged", "no blocked_media row found for the test image", session_id=session.session_id)
                return

            preserved = [dict(r) for r in rows if r["materialized_evidence_id"]]
            if not preserved:
                self.fail("live preserved media evidence linked", "blocked_media row did not link to preserved evidence", rows=[dict(r) for r in rows[:3]])
                return
            ev_id = int(preserved[0]["materialized_evidence_id"])
            self.live_media_eid = ev_id
            self.rows_snapshot("live_blocked_media_rows", rows, rel_path="snapshots/live_blocked_media_rows.json")
            self.pass_("live preserved media evidence linked", "blocked_media row links to preserved evidence object", blocked_media_id=preserved[0].get("id"), evidence_id=ev_id, materialized_evidence_id=ev_id)
            self.record_step("live_blocked_media_linked", "Blocked-media metadata row linked to preserved evidence object", blocked_media_id=preserved[0].get("id"), evidence_id=ev_id)
            self.evidence_snapshot("live_blocked_media", ev_id, original_payload_label="live_blocked_media")
            ev = m.evidence_for(ev_id)
            stored = m.data_path(ev["object_path"]).read_bytes()
            container = self.parse_hard_sealed_container(stored)
            if container and payload not in stored:
                self.pass_("live preserved media encrypted/hard-sealed", "live blocked media evidence is a hard-sealed container and does not contain plaintext", evidence_id=ev_id, storage_mode=ev.get("storage_mode"), escrow_fingerprint=container.get("escrow_public_key_fingerprint"))
            else:
                self.fail("live preserved media encrypted/hard-sealed", "live preserved media was not hard-sealed or leaked plaintext", evidence_id=ev_id)

            try:
                m.decrypt_bytes(stored)
                self.fail("live preserved media vault-key rejection", "local vault key unexpectedly decrypted live preserved media", evidence_id=ev_id)
            except Exception:
                self.pass_("live preserved media vault-key rejection", "local vault key cannot decrypt live hard-sealed media", evidence_id=ev_id)

            try:
                m.read_evidence(ev_id)
                self.fail("live preserved media local read blocked", "read_evidence unexpectedly returned live hard-sealed media", evidence_id=ev_id)
            except Exception:
                self.pass_("live preserved media local read blocked", "local read path blocks live hard-sealed media", evidence_id=ev_id)

            audits = m.fetchall("SELECT * FROM audit_events WHERE session_id=? AND action LIKE '%SEALED_BLOCKED_MEDIA%' ORDER BY id DESC", (session.session_id,))
            if audits:
                self.pass_("live preservation audit logged", "audit event exists for live sealed blocked-media preservation", audit_count=len(audits), latest_action=audits[0]["action"])
            else:
                self.warn("live preservation audit logged", "no SEALED_BLOCKED_MEDIA audit event found; blocked_media/evidence rows still exist", session_id=session.session_id)

        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    m.stop_live_session(session.session_id)
            with contextlib.suppress(Exception):
                server.stop()
    def test_sealed_export_and_reviewer_decrypt(self) -> None:
        m = self.m
        assert self.case_id is not None
        package, summary = m.build_sealed_case_package(
            self.case_id,
            "validation_suite",
            recipient="Validation Reviewer",
            reason="Claims validation sealed export test",
            recipient_public_key_pem=self.org_public_pem,
        )
        self.sealed_package_bytes = package
        self.write_artifact_bytes("sealed_export/sealed_export_validation.zip", package, "Full sealed export ZIP generated from fake validation case", category="sealed_export", mime="application/zip")
        self.record_step("sealed_export_created", "Sealed export ZIP created from fake validation case", package_sha256=sha256_bytes(package), package_size=len(package))
        marker_hits = []
        for label, payload in self.test_payloads.items():
            if payload in package:
                marker_hits.append(label)
        if marker_hits:
            self.fail("sealed export plaintext absence", "plaintext marker(s) found in sealed ZIP bytes", marker_hits=marker_hits)
        else:
            self.pass_("sealed export plaintext absence", "sealed ZIP does not contain fake plaintext markers", package_sha256=sha256_bytes(package), package_size=len(package))

        with zipfile.ZipFile(bytes_io(package), "r") as z:
            names = z.namelist()
            object_names = [n for n in names if n.startswith("encrypted_objects/")]
            non_fvault = [n for n in object_names if not n.endswith(".fvault")]
            manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            zip_listing = []
            for name in names:
                data = z.read(name)
                zip_listing.append({"path": name, "size": len(data), "sha256": sha256_bytes(data), "is_fvault": name.endswith(".fvault")})
        self.write_artifact_json("sealed_export/manifest.json", manifest, "manifest.json extracted from sealed export", category="sealed_export_manifest")
        self.write_artifact_json("sealed_export/zip_listing.json", zip_listing, "ZIP entry listing with SHA-256 for every sealed export member", category="sealed_export_listing")
        if object_names and not non_fvault:
            self.pass_("sealed export .fvault evidence objects", f"{len(object_names)} encrypted object(s) are .fvault", object_count=len(object_names))
        else:
            self.fail("sealed export .fvault evidence objects", "missing encrypted .fvault objects or non-.fvault evidence objects found", objects=object_names[:20], non_fvault=non_fvault)

        if self.live_media_eid:
            live_obj = [o for o in manifest.get("objects", []) if int(o.get("id") or 0) == int(self.live_media_eid)]
            if live_obj and live_obj[0].get("zip_path", "").endswith(".fvault"):
                self.pass_("live preserved media included in sealed export", "live blocked-media evidence appears in manifest and encrypted_objects", evidence_id=self.live_media_eid, zip_path=live_obj[0].get("zip_path"), decrypt_with=live_obj[0].get("decrypt_with"))
            else:
                self.fail("live preserved media included in sealed export", "live media evidence was not found in sealed export manifest", evidence_id=self.live_media_eid)

        if manifest.get("contains_plaintext_evidence") is False and manifest.get("contains_encrypted_original_evidence") is True:
            self.pass_("sealed export manifest custody flags", "manifest marks encrypted evidence and no plaintext evidence", hard_sealed_count=manifest.get("hard_sealed_escrow_evidence_count"), custody_mode=manifest.get("custody_mode"))
        else:
            self.fail("sealed export manifest custody flags", "manifest custody flags not as expected", contains_plaintext=manifest.get("contains_plaintext_evidence"), contains_encrypted=manifest.get("contains_encrypted_original_evidence"))

        out_dir = Path(self.workdir) / "reviewer_recovered"
        result = m.decrypt_sealed_package_to_vault(package, self.org_private_pem, self.org_private_passphrase, out_dir)
        recovered_markers = []
        recovered_details = []
        for obj in result.get("objects", []):
            p = Path(obj.get("plaintext_path") or "")
            detail = {"object": sanitize_mapping(obj), "plaintext_path_exists": p.exists()}
            if p.exists():
                data = p.read_bytes()
                detail.update({"size": len(data), "sha256": sha256_bytes(data)})
                copied = self.write_artifact_bytes(f"reviewer_recovered/{safe_filename(p.name)}", data, f"Reviewer recovered plaintext object for fake validation evidence: {p.name}", category="reviewer_recovered_object", mime="application/octet-stream")
                detail["artifact"] = copied
                matched_labels = []
                for label, payload in self.test_payloads.items():
                    if payload == data:
                        recovered_markers.append(label)
                        matched_labels.append(label)
                detail["matched_payload_labels"] = matched_labels
            recovered_details.append(detail)
        self.write_artifact_json("reviewer_recovered/recovered_objects.json", {"objects": recovered_details, "raw_result": sanitize_mapping(result)}, "Reviewer decrypt/import result with recovered object hashes", category="reviewer_recovery")
        expected = {"normal_vault", "org_hard_seal"}
        if self.website_eid:
            expected.add("website_sample")
        if self.live_media_eid:
            expected.add("live_blocked_media")
        if expected.issubset(set(recovered_markers)):
            self.pass_("reviewer decrypt/import recovery", "matching org private key recovered expected fake evidence", recovered_markers=sorted(recovered_markers), expected=sorted(expected), recovered_count=len(result.get("objects", [])))
            self.pass_("reviewer recovered hashes match originals", "recovered reviewer objects match original fake payload hashes", matched_payload_labels=sorted(recovered_markers), expected=sorted(expected))
        else:
            self.fail("reviewer decrypt/import recovery", "expected evidence was not recovered", recovered_markers=sorted(recovered_markers), expected=sorted(expected), recovered_count=len(result.get("objects", [])), errors=result.get("errors"))

    def test_reviewer_import_password_protection(self) -> None:
        """Validate the new LE reviewer case password gate.

        This does not claim recovered files are encrypted at rest. It verifies the
        security claim actually made in the app: a password-protected reviewer
        import stores only a password hash and the BlindSite interface considers
        the import locked until the session is explicitly unlocked.
        """
        m = self.m
        if not self.sealed_package_bytes:
            self.skip("reviewer import password protection", "sealed package not available")
            return
        required = ["reviewer_import_package", "set_reviewer_import_password", "reviewer_import_for", "reviewer_import_is_password_protected", "reviewer_import_is_unlocked", "reviewer_import_session_key", "check_password"]
        missing = [name for name in required if not hasattr(m, name)]
        if missing:
            self.skip("reviewer import password protection", "BlindSite version does not expose reviewer password helpers", missing=missing)
            return
        password = "BlindSite-Validation-ReviewPass-123!"
        try:
            import_id = m.reviewer_import_package(
                self.sealed_package_bytes,
                "validation_password_protected_import.zip",
                self.org_private_pem,
                self.org_private_passphrase,
                "validation_suite",
                "security evaluator password-protected reviewer import test",
            )
            m.set_reviewer_import_password(import_id, password, "validation_suite")
            imp = m.reviewer_import_for(import_id)
            notes = m.reviewer_import_notes(imp)
            self.write_artifact_json(
                f"reviewer_password/import_{import_id:06d}_row.json",
                sanitize_mapping({"import": imp, "notes": notes}),
                "Reviewer import row after password protection was applied",
                category="reviewer_password_security",
            )
            stored = str(imp.get("notes_json") or "") if imp else ""
            if password in stored:
                self.fail("reviewer import password not stored in plaintext", "plaintext password appeared in reviewer_imports.notes_json", reviewer_import_id=import_id)
            else:
                self.pass_("reviewer import password not stored in plaintext", "review-case password is not present in stored notes_json", reviewer_import_id=import_id)

            pw_hash = m.reviewer_import_password_hash(imp)
            if pw_hash and m.check_password(password, pw_hash) and not m.check_password("wrong-" + password, pw_hash):
                self.pass_("reviewer import password hash verification", "correct password verifies and wrong password fails", reviewer_import_id=import_id, password_hash_prefix=pw_hash[:24])
            else:
                self.fail("reviewer import password hash verification", "password hash did not verify as expected", reviewer_import_id=import_id, password_hash_prefix=pw_hash[:24])

            class DummyRequest:
                def __init__(self) -> None:
                    self.session: dict[str, str] = {}

            req = DummyRequest()
            locked = not bool(m.reviewer_import_is_unlocked(req, import_id, imp))
            req.session[m.reviewer_import_session_key(import_id)] = "1"
            unlocked = bool(m.reviewer_import_is_unlocked(req, import_id, imp))
            if locked and unlocked and m.reviewer_import_is_password_protected(imp):
                self.pass_("reviewer import lock/unlock session gate", "import is locked before session unlock and unlocked after session flag", reviewer_import_id=import_id)
            else:
                self.fail("reviewer import lock/unlock session gate", "lock/unlock helper behavior did not match expectations", reviewer_import_id=import_id, locked=locked, unlocked=unlocked, protected=m.reviewer_import_is_password_protected(imp))
        except Exception as exc:
            self.fail("reviewer import password protection", str(exc), traceback=traceback.format_exc(limit=12))

    def test_pdf_report_encryption(self) -> None:
        """Validate opt-in PDF encryption helper for LE reports.

        The test uses a fake one-page PDF generated inside the sandbox. It proves
        the helper returns an encrypted PDF, rejects the wrong password, and opens
        with the selected password. It does not test full report rendering, which
        belongs in the performance evaluator.
        """
        m = self.m
        if not hasattr(m, "encrypt_pdf_report_bytes"):
            self.skip("PDF report encryption", "BlindSite version does not expose encrypt_pdf_report_bytes")
            return
        try:
            try:
                from pypdf import PdfReader, PdfWriter  # type: ignore
            except Exception as exc:
                self.skip("PDF report encryption", f"pypdf is not installed in this environment: {exc}")
                return
            writer = PdfWriter()
            writer.add_blank_page(width=300, height=200)
            import io
            src = io.BytesIO()
            writer.write(src)
            plain_pdf = src.getvalue()
            password = "BlindSite-PDF-Validation-123!"
            encrypted_pdf = m.encrypt_pdf_report_bytes(plain_pdf, password)
            self.write_artifact_bytes("pdf_encryption/plain_validation_report.pdf", plain_pdf, "Fake unencrypted one-page PDF used as input for encryption test", category="pdf_security", mime="application/pdf")
            self.write_artifact_bytes("pdf_encryption/encrypted_validation_report.pdf", encrypted_pdf, "Fake encrypted PDF output created by BlindSite encryption helper", category="pdf_security", mime="application/pdf")
            reader = PdfReader(io.BytesIO(encrypted_pdf))
            is_encrypted = bool(reader.is_encrypted)
            wrong_result = None
            correct_result = None
            if is_encrypted:
                try:
                    wrong_result = reader.decrypt("wrong-" + password)
                except Exception as exc:
                    wrong_result = f"error:{exc.__class__.__name__}"
                reader2 = PdfReader(io.BytesIO(encrypted_pdf))
                correct_result = reader2.decrypt(password)
                page_count = len(reader2.pages)
            else:
                page_count = 0
            if is_encrypted and int(correct_result or 0) > 0 and page_count == 1:
                self.pass_("PDF report encryption helper", "encrypted PDF requires password and opens with correct password", plain_sha256=sha256_bytes(plain_pdf), encrypted_sha256=sha256_bytes(encrypted_pdf), wrong_password_result=wrong_result, correct_password_result=correct_result, page_count=page_count)
            else:
                self.fail("PDF report encryption helper", "PDF encryption helper did not produce a verifiably encrypted/openable PDF", is_encrypted=is_encrypted, wrong_password_result=wrong_result, correct_password_result=correct_result, page_count=page_count)
        except Exception as exc:
            self.fail("PDF report encryption helper", str(exc), traceback=traceback.format_exc(limit=12))

    def test_wrong_private_key_fails(self) -> None:
        m = self.m
        if not self.sealed_package_bytes:
            self.skip("wrong private key sealed package failure", "sealed package not available")
            return
        try:
            m.decrypt_sealed_package_to_vault(self.sealed_package_bytes, self.wrong_private_pem, self.wrong_private_passphrase, Path(self.workdir) / "wrong_key_out")
            self.fail("wrong private key sealed package failure", "wrong private key unexpectedly decrypted sealed package")
        except Exception as exc:
            self.pass_("wrong private key sealed package failure", "wrong private key could not decrypt sealed package", error_type=exc.__class__.__name__, error_message=str(exc)[:500])

    def test_audit_chain_tamper_detection(self) -> None:
        m = self.m
        before = m.verify_audit_chain()
        self.write_artifact_json("tamper/audit_verify_before.json", before, "Audit-chain verification result before intentional tamper", category="tamper_detection")
        if not before.get("ok"):
            self.warn("audit chain initially valid", "audit chain was already invalid before tamper test", result=before)
            return
        con = sqlite3.connect(m.DB_PATH)
        try:
            row = con.execute("SELECT id FROM audit_events ORDER BY id LIMIT 1").fetchone()
            if not row:
                self.skip("audit chain tamper detection", "no audit rows to tamper")
                return
            con.execute("UPDATE audit_events SET action='VALIDATION_TAMPERED_ACTION' WHERE id=?", (row[0],))
            con.commit()
        finally:
            con.close()
        after = m.verify_audit_chain()
        self.write_artifact_json("tamper/audit_verify_after.json", after, "Audit-chain verification result after intentional DB tamper", category="tamper_detection")
        if not after.get("ok"):
            self.pass_("audit chain tamper detection", "audit verification failed after direct DB tamper", bad_count=len(after.get("bad") or []))
        else:
            self.fail("audit chain tamper detection", "audit verification still passed after tampering")

    def test_storage_hash_tamper_detection(self) -> None:
        m = self.m
        before = m.storage_hash()
        rows = m.fetchall("SELECT object_path FROM evidence ORDER BY id LIMIT 1")
        if not rows:
            self.skip("storage hash tamper detection", "no evidence objects to tamper")
            return
        p = m.data_path(rows[0]["object_path"])
        with p.open("ab") as f:
            f.write(b"\nVALIDATION_STORAGE_TAMPER")
        after = m.storage_hash()
        if before != after:
            self.pass_("storage hash tamper detection", "storage hash changed after direct evidence-file tamper", before=before, after=after)
        else:
            self.fail("storage hash tamper detection", "storage hash did not change after evidence-file tamper", before=before, after=after)

    def scan_public_repo_hygiene(self, repo_dir: Path) -> None:
        suspicious_patterns = [
            "PRIVATE KEY",
            "vault.key",
            "app_secret.key",
            "escrow_private_key",
            ".env",
            "vault.sqlite3",
        ]
        suspicious_files = []
        for p in repo_dir.rglob("*"):
            if p.is_dir():
                if p.name in {".git", "__pycache__", "data", "node_modules"}:
                    continue
            if p.is_file():
                rel = str(p.relative_to(repo_dir))
                lower = rel.lower()
                if any(x in lower for x in ["vault.sqlite3", "vault.key", "app_secret.key", "escrow_private_key", ".env"]):
                    suspicious_files.append({"file": rel, "reason": "suspicious filename"})
                    continue
                if p.suffix.lower() in {".py", ".md", ".txt", ".pem", ".key", ".env"} and p.stat().st_size < 2_000_000:
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    if re.search(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", text):
                        suspicious_files.append({"file": rel, "reason": "contains actual PEM private key block"})
        if suspicious_files:
            self.warn("public repo hygiene scan", "possible sensitive files/strings found; review before publishing", findings=suspicious_files[:50], count=len(suspicious_files))
        else:
            self.pass_("public repo hygiene scan", "no obvious private key/vault artifacts found in app folder")

    def write_reports(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = self.report_root / f"blindsite_validation_{stamp}"
        out.mkdir(parents=True, exist_ok=True)
        counts = {s: sum(1 for c in self.checks if c.status == s) for s in ["PASS", "FAIL", "WARN", "SKIP", "INFO"]}
        claim_matrix = build_claim_matrix(self.checks)
        reconstruction_bundle = {
            "purpose": "Lets reviewers reconstruct the validation chain using fake test artifacts and hashes, without trusting summary text alone.",
            "artifacts_directory": "reconstruction_artifacts",
            "payload_registry": self.payload_registry,
            "steps": self.reconstruction_steps,
            "artifacts": self.reconstruction_artifacts,
            "important_note": "Private keys and passphrases are intentionally not stored. All payload artifacts are fake validation data unless explicitly marked as external website metadata only.",
        }
        self.write_artifact_json("reconstruction_chain.json", reconstruction_bundle, "Full reconstruction chain index", category="reconstruction_index")
        report = {
            "tool": "BlindSite Claims Validation Suite",
            "suite_version": APP_VERSION,
            "started_at_utc": self.started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "app_file": str(self.original_app_path),
            "app_sha256": sha256_file(self.original_app_path) if self.original_app_path.exists() else "",
            "result_counts": counts,
            "overall_pass": counts.get("FAIL", 0) == 0,
            "security_note": "No private-key passphrases are written to this report. Existing private keys are read only for in-memory validation.",
            "legal_note": "This is technical validation evidence, not legal certification or forensic admissibility certification.",
            "short_summary": build_short_summary(counts, claim_matrix),
            "claim_matrix": claim_matrix,
            "reconstruction_bundle": reconstruction_bundle,
            "checks": [c.__dict__ for c in self.checks],
        }
        if self.reconstruction_dir and self.reconstruction_dir.exists():
            dest = out / "reconstruction_artifacts"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(self.reconstruction_dir, dest)
        (out / "validation_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        (out / "validation_report.md").write_text(render_markdown_report(report), encoding="utf-8")
        self.log("\n" + "=" * 72)
        self.log("VALIDATION COMPLETE")
        self.log("=" * 72)
        self.log(f"Report folder: {out}")
        self.log(f"Pass: {counts.get('PASS',0)} | Fail: {counts.get('FAIL',0)} | Warn: {counts.get('WARN',0)} | Skip: {counts.get('SKIP',0)}")
        self.log("Short summary:")
        for line in build_short_summary(counts, claim_matrix):
            self.log("- " + line)
        if counts.get("FAIL", 0):
            self.log("Overall: FAIL")
        else:
            self.log("Overall: PASS with caveats/warnings as listed")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def bytes_io(data: bytes):
    import io
    return io.BytesIO(data)


def public_key_fingerprint_from_key(key_obj: Any) -> str:
    if hasattr(key_obj, "public_key"):
        key_obj = key_obj.public_key()
    der = key_obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_bytes(der)


def public_key_fingerprint_from_pem(public_pem: str) -> str:
    key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    return public_key_fingerprint_from_key(key)


def generate_encrypted_rsa_keypair() -> tuple[bytes, str, str, str]:
    passphrase = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    fp = public_key_fingerprint_from_key(private_key)
    return priv_pem, pub_pem, fp, passphrase


def fetch_sample_image(url: str, *, timeout: int = DEFAULT_TIMEOUT, max_bytes: int = MAX_WEBSITE_IMAGE_BYTES) -> dict[str, Any]:
    import requests
    from bs4 import BeautifulSoup

    url = normalize_url(url)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    html = r.text
    soup = BeautifulSoup(html, "html.parser")

    candidates: list[str] = []

    for meta in soup.find_all("meta"):
        prop = str(meta.get("property") or meta.get("name") or "").lower()
        if prop in {"og:image", "twitter:image", "twitter:image:src"} and meta.get("content"):
            candidates.append(urljoin(r.url, str(meta.get("content"))))

    for img in soup.find_all("img"):
        for attr in ["src", "data-src", "data-lazy-src", "data-original", "data-url"]:
            val = img.get(attr)
            if val and not str(val).startswith("data:"):
                candidates.append(urljoin(r.url, str(val)))
        srcset = img.get("srcset")
        if srcset:
            candidates.extend(parse_srcset(str(srcset), r.url))

    for source in soup.find_all("source"):
        srcset = source.get("srcset")
        if srcset:
            candidates.extend(parse_srcset(str(srcset), r.url))
        src = source.get("src")
        if src and not str(src).startswith("data:"):
            candidates.append(urljoin(r.url, str(src)))

    seen = set()
    unique = []
    for c in candidates:
        c = c.strip()
        if not c or c in seen or c.startswith(("data:", "blob:", "javascript:")):
            continue
        seen.add(c)
        unique.append(c)

    if not unique:
        raise RuntimeError("No image candidates found in page HTML")

    img_headers = {
        "User-Agent": headers["User-Agent"],
        "Accept": "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": r.url,
    }
    errors = []
    for candidate in unique[:10]:
        try:
            ir = requests.get(candidate, headers=img_headers, timeout=timeout, stream=True)
            ir.raise_for_status()
            ctype = (ir.headers.get("Content-Type") or guess_mime(candidate)).split(";", 1)[0].strip() or "application/octet-stream"
            if not (ctype.startswith("image/") or Path(urlparse(candidate).path).suffix.lower() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif"}):
                continue
            chunks = []
            total = 0
            for chunk in ir.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError(f"image exceeded max sample bytes ({max_bytes})")
            payload = b"".join(chunks)
            if not payload:
                continue
            return {
                "page_url": r.url,
                "media_url": ir.url,
                "mime_type": ctype,
                "payload": payload,
                "status_code": ir.status_code,
                "headers": dict(ir.headers),
            }
        except Exception as exc:
            errors.append({"url": candidate, "error": str(exc)})
    raise RuntimeError("Could not download any candidate image quickly: " + json.dumps(errors[:5], indent=2))


def parse_srcset(srcset: str, base_url: str) -> list[str]:
    out = []
    for item in srcset.split(","):
        bits = item.strip().split()
        if bits:
            out.append(urljoin(base_url, bits[0]))
    return out


def guess_mime(url: str) -> str:
    ext = Path(urlparse(url).path.lower()).suffix
    return {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".bmp": "image/bmp",
        ".avif": "image/avif",
    }.get(ext, "application/octet-stream")


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise RuntimeError("URL is required")
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def safe_filename(value: str, max_len: int = 96) -> str:
    value = (value or "artifact").strip().replace("\\", "_").replace("/", "_")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (value[:max_len] or "artifact")


def safe_json_loads(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return value


def sanitize_mapping(obj: Any) -> Any:
    """Convert sqlite rows/paths/bytes to JSON-safe values and avoid private material."""
    if isinstance(obj, sqlite3.Row):
        obj = dict(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(secret in kl for secret in ("private_key", "passphrase", "password")):
                out[k] = "[REDACTED]"
            else:
                out[k] = sanitize_mapping(v)
        return out
    if isinstance(obj, list):
        return [sanitize_mapping(x) for x in obj]
    if isinstance(obj, tuple):
        return [sanitize_mapping(x) for x in obj]
    if isinstance(obj, bytes):
        return {"bytes_len": len(obj), "sha256": sha256_bytes(obj)}
    if isinstance(obj, Path):
        return str(obj)
    return obj


def build_claim_matrix(checks: list[Check]) -> dict[str, Any]:
    names = {c.name: c for c in checks}

    def status_for(required: list[str], warnings: list[str] | None = None) -> dict[str, Any]:
        warnings = warnings or []
        missing = [n for n in required if n not in names]
        failed = [n for n in required if n in names and names[n].status == "FAIL"]
        skipped = [n for n in required if n in names and names[n].status == "SKIP"]
        warn = [n for n in warnings if n in names and names[n].status == "WARN"]
        if failed:
            status = "FAIL"
        elif missing:
            status = "INCOMPLETE"
        elif skipped:
            status = "SKIP"
        elif warn:
            status = "WARN"
        else:
            status = "PASS"
        return {"status": status, "required_checks": required, "missing": missing, "failed": failed, "skipped": skipped, "warnings": warn}

    live_required = ["live browser session started", "live media blocked from display", "live blocked request counted", "live background preservation completed", "live manual page capture", "live blocked media logged", "live preserved media evidence linked", "live preserved media encrypted/hard-sealed", "live preserved media vault-key rejection", "live preserved media local read blocked", "live preserved media included in sealed export"]
    if "live browser blocked-media integration" in names and names["live browser blocked-media integration"].status in {"SKIP", "WARN"}:
        live_status = {
            "status": names["live browser blocked-media integration"].status,
            "required_checks": live_required,
            "missing": live_required,
            "failed": [],
            "skipped": ["live browser blocked-media integration"] if names["live browser blocked-media integration"].status == "SKIP" else [],
            "warnings": ["live browser blocked-media integration"] if names["live browser blocked-media integration"].status == "WARN" else [],
            "note": names["live browser blocked-media integration"].detail,
        }
    else:
        live_status = status_for(live_required, warnings=["live preservation audit logged"])

    return {
        "app_runs": status_for(["Python compile", "BlindSite --self-test", "import and isolated DB init"]),
        "normal_vault_encryption": status_for(["normal vault plaintext absence", "normal vault authorized read"]),
        "civilian_unknown_hard_seal": status_for(["civilian hard-sealed container", "civilian hard-sealed plaintext absence", "civilian hard-sealed vault-key rejection", "civilian hard-sealed local read blocked"]),
        "organization_hard_sealed_media": status_for(["organization hard-sealed media container", "organization hard-sealed plaintext absence", "organization hard-sealed vault-key rejection", "organization hard-sealed local read blocked", "organization hard-sealed private-key recovery", "organization hard-sealed wrong-key failure"]),
        "live_browser_blocked_media_flow": live_status,
        "sealed_export_and_reviewer_recovery": status_for(["sealed export plaintext absence", "sealed export .fvault evidence objects", "sealed export manifest custody flags", "reviewer decrypt/import recovery", "reviewer recovered hashes match originals", "wrong private key sealed package failure"]),
        "reviewer_access_and_pdf_security": status_for(["reviewer import password not stored in plaintext", "reviewer import password hash verification", "reviewer import lock/unlock session gate", "PDF report encryption helper"]),
        "tamper_detection": status_for(["audit chain tamper detection", "storage hash tamper detection"]),
        "repo_hygiene": status_for(["public repo hygiene scan"]),
    }


def build_short_summary(counts: dict[str, int], claim_matrix: dict[str, Any]) -> list[str]:
    lines = []
    lines.append(f"Checks: {counts.get('PASS',0)} pass, {counts.get('FAIL',0)} fail, {counts.get('WARN',0)} warn, {counts.get('SKIP',0)} skip.")
    for claim, result in claim_matrix.items():
        status = result.get("status")
        label = claim.replace("_", " ")
        lines.append(f"{label}: {status}")
    return lines


def tiny_png_bytes() -> bytes:
    # 1x1 transparent PNG. Small, deterministic, valid image bytes for local live browser tests.
    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
    )


def live_test_html_bytes() -> bytes:
    return b"""<!doctype html><html><head><meta charset='utf-8'><title>BlindSite Live Validation</title></head>
<body><h1 id='marker'>BLINDSITE LIVE VALIDATION PAGE</h1>
<p>This page contains one image that should be blocked from display and preserved in the background.</p>
<img id='blocked-img' src='/blocked-test-image.png' alt='blocked test image'>
<script>window.BLINDSITE_LIVE_VALIDATION_SCRIPT_RAN = true;</script>
</body></html>"""


class LocalMediaTestHandler(http.server.BaseHTTPRequestHandler):
    image_payload: bytes = tiny_png_bytes()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path.startswith("/blocked-test-image.png"):
            body = self.image_payload
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        html = live_test_html_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html)


class LocalMediaTestServer:
    def __init__(self, image_payload: bytes):
        self.image_payload = image_payload
        self.httpd: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> None:
        handler_cls = type("BlindSiteLocalMediaTestHandler", (LocalMediaTestHandler,), {"image_payload": self.image_payload})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = int(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=2)


def eval_on_live_page(session: Any, expression: str, timeout: float = 8.0) -> Any:
    import asyncio
    if session.loop is None or session.loop.is_closed():
        raise RuntimeError("session loop is closed")
    page = getattr(session, "active_page", None) or getattr(session, "page", None)
    if page is None:
        raise RuntimeError("session has no active page")
    fut = asyncio.run_coroutine_threadsafe(page.evaluate(expression), session.loop)
    return fut.result(timeout=timeout)


def screenshot_live_page(session: Any, timeout: float = 8.0) -> bytes:
    import asyncio
    if session.loop is None or session.loop.is_closed():
        raise RuntimeError("session loop is closed")
    page = getattr(session, "active_page", None) or getattr(session, "page", None)
    if page is None:
        raise RuntimeError("session has no active page")
    fut = asyncio.run_coroutine_threadsafe(page.screenshot(full_page=True), session.loop)
    return fut.result(timeout=timeout)


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = []
    lines.append("# BlindSite Claims Validation Report")
    lines.append("")
    lines.append(f"- Suite version: `{report.get('suite_version')}`")
    lines.append(f"- Started: `{report.get('started_at_utc')}`")
    lines.append(f"- Finished: `{report.get('finished_at_utc')}`")
    lines.append(f"- App file: `{report.get('app_file')}`")
    lines.append(f"- App SHA-256: `{report.get('app_sha256')}`")
    lines.append(f"- Overall pass: `{report.get('overall_pass')}`")
    lines.append("")
    lines.append("## Important notes")
    lines.append("")
    lines.append("- This is technical validation evidence, not legal certification.")
    lines.append("- The suite uses fake test evidence in an isolated sandbox.")
    lines.append("- Existing private-key passphrases are used only in memory and are not written to this report.")
    lines.append("- The `reconstruction_artifacts/` folder contains fake original payloads, encrypted `.fvault` copies, sealed-export manifest/listing, recovered-object hashes, and tamper evidence so the chain can be inspected without trusting summary text alone.")
    lines.append("")
    counts = report.get("result_counts") or {}
    lines.append("## Short summary")
    lines.append("")
    for item in report.get("short_summary", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Claim matrix")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(report.get("claim_matrix") or {}, indent=2, default=str))
    lines.append("```")
    lines.append("")
    lines.append("## Check counts")
    lines.append("")
    lines.append(f"- PASS: {counts.get('PASS', 0)}")
    lines.append(f"- FAIL: {counts.get('FAIL', 0)}")
    lines.append(f"- WARN: {counts.get('WARN', 0)}")
    lines.append(f"- SKIP: {counts.get('SKIP', 0)}")
    lines.append("")
    lines.append("## Reconstruction bundle")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(report.get("reconstruction_bundle") or {}, indent=2, default=str)[:12000])
    lines.append("```")
    lines.append("")
    lines.append("## Verbose checks")
    lines.append("")
    for c in report.get("checks", []):
        lines.append(f"### {c.get('status')}: {c.get('name')}")
        lines.append("")
        if c.get("detail"):
            lines.append(c["detail"])
            lines.append("")
        ev = c.get("evidence") or {}
        if ev:
            lines.append("```json")
            lines.append(json.dumps(ev, indent=2, default=str)[:5000])
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def prompt_path(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    default_text = "Y/n" if default else "y/N"
    while True:
        val = input(f"{prompt} [{default_text}]: ").strip().lower()
        if not val:
            return default
        if val in {"y", "yes"}:
            return True
        if val in {"n", "no"}:
            return False
        print("Please answer y or n.")


def interactive() -> argparse.Namespace:
    print("\nBlindSite Claims Validation Suite")
    print("=" * 40)
    print("This will copy BlindSite.py into a temporary sandbox and run fake-evidence validation tests.")
    print("It will not touch your live data/ folder.\n")

    app_path = prompt_path("Path to BlindSite.py", "BlindSite.py")
    report_dir = prompt_path("Report output folder", "blindsite_validation_reports")
    keep_temp = prompt_yes_no("Keep temporary sandbox after test? Usually no.", False)
    verbose = prompt_yes_no("Verbose output?", True)

    run_live_browser_test = prompt_yes_no("Run true live browser blocked-media integration test? Recommended if Playwright browsers are installed.", True)

    website_url = ""
    if prompt_yes_no("Run optional quick external website sample-image preservation test?", False):
        website_url = prompt_path("Website URL to test", "")

    use_existing = prompt_yes_no("Use an existing organization/reviewer keypair for org hard-seal tests?", False)
    public_key_path = ""
    private_key_path = ""
    passphrase = ""
    if use_existing:
        public_key_path = prompt_path("Path to organization public key PEM")
        private_key_path = prompt_path("Path to matching private key PEM")
        if prompt_yes_no("Is the private key passphrase-protected?", True):
            passphrase = getpass.getpass("Private key passphrase (not stored): ")

    return argparse.Namespace(
        app=app_path,
        report_dir=report_dir,
        keep_temp=keep_temp,
        verbose=verbose,
        website_url=website_url,
        run_live_browser_test=run_live_browser_test,
        use_existing_org_keys=use_existing,
        org_public_key=public_key_path,
        org_private_key=private_key_path,
        org_private_passphrase=passphrase,
    )


def main() -> int:
    if len(sys.argv) == 1:
        args = interactive()
    else:
        parser = argparse.ArgumentParser(description="BlindSite standalone claims validation suite")
        parser.add_argument("--app", default="BlindSite.py", help="Path to BlindSite.py")
        parser.add_argument("--report-dir", default="blindsite_validation_reports")
        parser.add_argument("--keep-temp", action="store_true")
        parser.add_argument("--quiet", action="store_true")
        parser.add_argument("--website-url", default="", help="Optional website URL for quick sample-image preservation test")
        parser.add_argument("--skip-live-browser-test", action="store_true", help="Skip local Playwright live blocked-media integration test")
        parser.add_argument("--use-existing-org-keys", action="store_true")
        parser.add_argument("--org-public-key", default="")
        parser.add_argument("--org-private-key", default="")
        parser.add_argument("--prompt-org-private-passphrase", action="store_true")
        args = parser.parse_args()
        args.verbose = not args.quiet
        args.org_private_passphrase = ""
        if args.prompt_org_private_passphrase:
            args.org_private_passphrase = getpass.getpass("Organization private-key passphrase (not stored): ")

    v = Validator(
        app_path=Path(args.app),
        report_root=Path(args.report_dir),
        keep_temp=bool(args.keep_temp),
        verbose=bool(args.verbose),
    )
    v.run(
        website_url=getattr(args, "website_url", "") or "",
        run_live_browser_test=not bool(getattr(args, "skip_live_browser_test", False)),
        use_existing_org_keys=bool(getattr(args, "use_existing_org_keys", False)),
        org_public_key_path=getattr(args, "org_public_key", "") or "",
        org_private_key_path=getattr(args, "org_private_key", "") or "",
        org_private_passphrase=getattr(args, "org_private_passphrase", "") or "",
    )
    return 1 if any(c.status == "FAIL" for c in v.checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
