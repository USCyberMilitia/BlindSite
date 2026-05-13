#!/usr/bin/env python3
"""
BlindSite Claims Validation Suite

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
- optional website sample image can be fetched quickly and pushed through the same hard-sealed preservation path;
- public repo hygiene scan can flag obvious secrets/private artifacts.

Important:
This suite provides technical validation evidence. It does not certify legal admissibility,
courtroom defensibility, or operational fitness for every environment.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib.util
import json
import os
import py_compile
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
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


APP_VERSION = "1.0"
DEFAULT_TIMEOUT = 8
MAX_WEBSITE_IMAGE_BYTES = 2_000_000


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
        self.sealed_package_bytes: bytes | None = None

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
        shutil.copy2(self.original_app_path, self.app_copy)
        self.log(f"Using sandbox: {self.workdir}")
        self.log(f"Copied app under test: {self.app_copy}")

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

    def run(self, website_url: str = "", use_existing_org_keys: bool = False, org_public_key_path: str = "", org_private_key_path: str = "", org_private_passphrase: str = "") -> None:
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
            self.test_sealed_export_and_reviewer_decrypt()
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
        return self.test_payloads[label]

    def evidence_file_bytes(self, eid: int) -> bytes:
        m = self.m
        ev = m.evidence_for(eid)
        if not ev:
            raise RuntimeError(f"evidence {eid} not found")
        return m.data_path(ev["object_path"]).read_bytes()

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
        stored = self.evidence_file_bytes(eid)
        ev = m.evidence_for(eid)
        container = m.parse_hard_sealed_container(stored)
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
        stored = self.evidence_file_bytes(eid)
        ev = m.evidence_for(eid)
        container = m.parse_hard_sealed_container(stored)
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
        stored = self.evidence_file_bytes(eid)
        container = m.parse_hard_sealed_container(stored)
        if container and payload not in stored:
            self.pass_("website sample hard-sealed preservation", "sample image was fetched and hard-sealed without plaintext on disk", evidence_id=eid, media_url=media_url, bytes=len(payload), mime_type=mime_type)
        else:
            self.fail("website sample hard-sealed preservation", "website sample was not hard-sealed correctly", evidence_id=eid, media_url=media_url)

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
        if object_names and not non_fvault:
            self.pass_("sealed export .fvault evidence objects", f"{len(object_names)} encrypted object(s) are .fvault", object_count=len(object_names))
        else:
            self.fail("sealed export .fvault evidence objects", "missing encrypted .fvault objects or non-.fvault evidence objects found", objects=object_names[:20], non_fvault=non_fvault)

        if manifest.get("contains_plaintext_evidence") is False and manifest.get("contains_encrypted_original_evidence") is True:
            self.pass_("sealed export manifest custody flags", "manifest marks encrypted evidence and no plaintext evidence", hard_sealed_count=manifest.get("hard_sealed_escrow_evidence_count"), custody_mode=manifest.get("custody_mode"))
        else:
            self.fail("sealed export manifest custody flags", "manifest custody flags not as expected", contains_plaintext=manifest.get("contains_plaintext_evidence"), contains_encrypted=manifest.get("contains_encrypted_original_evidence"))

        out_dir = Path(self.workdir) / "reviewer_recovered"
        result = m.decrypt_sealed_package_to_vault(package, self.org_private_pem, self.org_private_passphrase, out_dir)
        recovered_markers = []
        for obj in result.get("objects", []):
            p = Path(obj.get("plaintext_path") or "")
            if p.exists():
                data = p.read_bytes()
                for label, payload in self.test_payloads.items():
                    if payload == data:
                        recovered_markers.append(label)
        expected = {"normal_vault", "org_hard_seal"}
        if self.website_eid:
            expected.add("website_sample")
        if expected.issubset(set(recovered_markers)):
            self.pass_("reviewer decrypt/import recovery", "matching org private key recovered expected fake evidence", recovered_markers=sorted(recovered_markers), recovered_count=len(result.get("objects", [])))
        else:
            self.fail("reviewer decrypt/import recovery", "expected evidence was not recovered", recovered_markers=sorted(recovered_markers), expected=sorted(expected), recovered_count=len(result.get("objects", [])), errors=result.get("errors"))

    def test_wrong_private_key_fails(self) -> None:
        m = self.m
        if not self.sealed_package_bytes:
            self.skip("wrong private key sealed package failure", "sealed package not available")
            return
        try:
            m.decrypt_sealed_package_to_vault(self.sealed_package_bytes, self.wrong_private_pem, self.wrong_private_passphrase, Path(self.workdir) / "wrong_key_out")
            self.fail("wrong private key sealed package failure", "wrong private key unexpectedly decrypted sealed package")
        except Exception:
            self.pass_("wrong private key sealed package failure", "wrong private key could not decrypt sealed package")

    def test_audit_chain_tamper_detection(self) -> None:
        m = self.m
        before = m.verify_audit_chain()
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
                    if "PRIVATE KEY" in text and "BEGIN PUBLIC KEY" not in text:
                        suspicious_files.append({"file": rel, "reason": "contains PRIVATE KEY text"})
        if suspicious_files:
            self.warn("public repo hygiene scan", "possible sensitive files/strings found; review before publishing", findings=suspicious_files[:50], count=len(suspicious_files))
        else:
            self.pass_("public repo hygiene scan", "no obvious private key/vault artifacts found in app folder")

    def write_reports(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = self.report_root / f"blindsite_validation_{stamp}"
        out.mkdir(parents=True, exist_ok=True)
        counts = {s: sum(1 for c in self.checks if c.status == s) for s in ["PASS", "FAIL", "WARN", "SKIP", "INFO"]}
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
            "checks": [c.__dict__ for c in self.checks],
        }
        (out / "validation_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        (out / "validation_report.md").write_text(render_markdown_report(report), encoding="utf-8")
        self.log("\n" + "=" * 72)
        self.log("VALIDATION COMPLETE")
        self.log("=" * 72)
        self.log(f"Report folder: {out}")
        self.log(f"Pass: {counts.get('PASS',0)} | Fail: {counts.get('FAIL',0)} | Warn: {counts.get('WARN',0)} | Skip: {counts.get('SKIP',0)}")
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
    lines.append("")
    counts = report.get("result_counts") or {}
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- PASS: {counts.get('PASS', 0)}")
    lines.append(f"- FAIL: {counts.get('FAIL', 0)}")
    lines.append(f"- WARN: {counts.get('WARN', 0)}")
    lines.append(f"- SKIP: {counts.get('SKIP', 0)}")
    lines.append("")
    lines.append("## Checks")
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

    website_url = ""
    if prompt_yes_no("Run optional quick website sample-image preservation test?", False):
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
        use_existing_org_keys=bool(getattr(args, "use_existing_org_keys", False)),
        org_public_key_path=getattr(args, "org_public_key", "") or "",
        org_private_key_path=getattr(args, "org_private_key", "") or "",
        org_private_passphrase=getattr(args, "org_private_passphrase", "") or "",
    )
    return 1 if any(c.status == "FAIL" for c in v.checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())