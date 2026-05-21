#!/usr/bin/env python3
"""
BlindSite Performance Evaluator
US CYBER MILITIA | BLINDSITE

Standalone performance/workflow validation harness for BlindSite.py.

This evaluator focuses on speed, responsiveness, and reconstructable performance
artifacts for current BlindSite features, including the newest hardening additions:

  - Application Genesis Hash / Executable Genesis Seal helper timing;
  - Tor status bar/status API timing and reconstructable status samples;
  - CAPTCHA/challenge exception predicate speed and narrowness, including inline/base64 data:image CAPTCHAs;
  - empty-header display helper speed/clarity;
  - blocked-media retry statistics proving all-not-downloaded includes queue-full;
  - workflow regression checks moved out of the security evaluator, including retry semantics, Tor status surface, and header-display clarity;
  - reconstructable workflow logs/artifacts for retry actions, Tor runtime/status samples, and browser-event header rows;
  - LE Reviewer import password/YubiKey protection timeout helper timing;
  - optional local live-browser blocked-media benchmark;
  - optional Tor prewarm/status benchmark.

It produces a report folder containing JSON/Markdown/CSV and an artifacts folder
so the logs are reconstructable instead of being just summary claims.

This is a performance/workflow evaluator, not a legal or forensic certification.
Security/encryption claims should be covered by BlindSite-Security-Evaluator.py.
"""

from __future__ import annotations

import argparse
import gc
import base64
import contextlib
import hashlib
import http.server
import importlib.util
import inspect
import json
import os
import platform
import py_compile
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

APP_VERSION = "2.1-workflow-performance-reconstructable"
DEFAULT_TIMEOUT = 12
ZERO_HASH = "0" * 64


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Benchmark:
    name: str
    elapsed_seconds: float
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)


class PerformanceEvaluator:
    def __init__(
        self,
        *,
        app_path: Path,
        report_root: Path,
        keep_temp: bool = False,
        verbose: bool = True,
        quick_iterations: int = 1000,
        retry_rows: int = 600,
        live_assets: int = 60,
        live_delay_ms: int = 5,
    ):
        self.original_app_path = app_path.expanduser().resolve()
        self.report_root = report_root.expanduser().resolve()
        self.keep_temp = keep_temp
        self.verbose = verbose
        self.quick_iterations = max(1, int(quick_iterations))
        self.retry_rows = max(10, int(retry_rows))
        self.live_assets = max(1, int(live_assets))
        self.live_delay_ms = max(0, int(live_delay_ms))
        self.started_at = utcnow()
        self.checks: list[Check] = []
        self.benchmarks: list[Benchmark] = []
        self.artifacts: list[dict[str, Any]] = []
        self.reconstruction_steps: list[dict[str, Any]] = []
        self.tempdir_obj: tempfile.TemporaryDirectory[str] | None = None
        self.workdir: Path | None = None
        self.app_copy: Path | None = None
        self.artifact_dir: Path | None = None
        self.m = None

    # ------------------ logging/checks ------------------

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def add(self, name: str, status: str, detail: str = "", **evidence: Any) -> None:
        self.checks.append(Check(name=name, status=status, detail=detail, evidence=safe_json(evidence)))
        prefix = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️", "INFO": "ℹ️"}.get(status, "•")
        self.log(f"{prefix} {status}: {name}" + (f" — {detail}" if detail else ""))

    def pass_(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "PASS", detail, **evidence)

    def warn(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "WARN", detail, **evidence)

    def fail(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "FAIL", detail, **evidence)

    def skip(self, name: str, detail: str = "", **evidence: Any) -> None:
        self.add(name, "SKIP", detail, **evidence)

    def step(self, name: str, detail: str = "", **data: Any) -> None:
        self.reconstruction_steps.append({
            "index": len(self.reconstruction_steps) + 1,
            "timestamp_utc": utcnow(),
            "name": name,
            "detail": detail,
            "data": safe_json(data),
        })

    def bench(self, name: str, elapsed: float, detail: str = "", **metrics: Any) -> None:
        self.benchmarks.append(Benchmark(name=name, elapsed_seconds=round(float(elapsed), 6), detail=detail, metrics=safe_json(metrics)))
        self.log(f"⏱️ BENCH: {name} — {elapsed:.4f}s" + (f" — {detail}" if detail else ""))

    # ------------------ setup/import ------------------

    def setup(self) -> None:
        if not self.original_app_path.exists():
            raise SystemExit(f"BlindSite file not found: {self.original_app_path}")
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.tempdir_obj = tempfile.TemporaryDirectory(prefix="blindsite_perf_eval_")
        self.workdir = Path(self.tempdir_obj.name)
        self.app_copy = self.workdir / "BlindSite_under_test.py"
        self.artifact_dir = self.workdir / "performance_artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.original_app_path, self.app_copy)
        self.write_json_artifact("environment/run_context.json", self.run_context(), "Run context and environment metadata", category="environment")
        self.log(f"Using sandbox: {self.workdir}")
        self.log(f"Copied app under test: {self.app_copy}")

    def cleanup(self) -> None:
        """Release imported BlindSite resources and remove the temporary sandbox.

        On Windows, sqlite files can remain locked for a short time if an imported
        module or a benchmark fixture still has a connection/handle alive. Cleanup
        must never turn an otherwise successful performance validation into a
        traceback, so we explicitly release known resources, retry deletion, and
        downgrade leftover temp-file locks to a warning.
        """
        if self.keep_temp:
            self.warn("temporary sandbox retained", str(self.workdir))
            return

        # Ask any in-memory live sessions / managed helpers from the imported app
        # to stop before deleting the copied app/data directory. These calls are
        # intentionally best-effort; cleanup should not mask the validation result.
        if self.m is not None:
            with contextlib.suppress(Exception):
                live = getattr(self.m, "LIVE", {})
                for session in list(live.values()):
                    with contextlib.suppress(Exception):
                        session.stop_sync()
            with contextlib.suppress(Exception):
                if hasattr(self.m, "stop_managed_tor"):
                    self.m.stop_managed_tor("performance-evaluator-cleanup")

        # Drop the imported module reference so sqlite connections and file handles
        # held by module globals/closures can be garbage-collected before rmtree.
        with contextlib.suppress(Exception):
            sys.modules.pop("blindsite_perf_under_test", None)
        self.m = None
        gc.collect()

        if not self.tempdir_obj:
            return

        sandbox = Path(self.tempdir_obj.name)
        # Detach TemporaryDirectory's finalizer and do the deletion ourselves so
        # a Windows PermissionError can be reported as a warning instead of a
        # post-report traceback.
        with contextlib.suppress(Exception):
            self.tempdir_obj._finalizer.detach()  # type: ignore[attr-defined]

        last_exc: Exception | None = None
        for attempt in range(12):
            try:
                if sandbox.exists():
                    shutil.rmtree(sandbox)
                self.tempdir_obj = None
                return
            except PermissionError as exc:
                last_exc = exc
                gc.collect()
                time.sleep(0.25)
            except Exception as exc:
                last_exc = exc
                break

        # Last-resort ignore-errors pass. If a locked sqlite file remains, leave
        # the sandbox path in the report output instead of crashing after PASS.
        with contextlib.suppress(Exception):
            shutil.rmtree(sandbox, ignore_errors=True)
        if sandbox.exists():
            self.warn(
                "temporary sandbox cleanup retained locked files",
                "Validation completed, but Windows still had a temporary file open. Close Python/BlindSite processes and delete the sandbox manually if desired.",
                sandbox=str(sandbox),
                error=str(last_exc) if last_exc else "unknown cleanup error",
            )
        self.tempdir_obj = None

    def import_app(self) -> Any:
        assert self.app_copy is not None
        spec = importlib.util.spec_from_file_location("blindsite_perf_under_test", self.app_copy)
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not import BlindSite under test")
        module = importlib.util.module_from_spec(spec)
        sys.modules["blindsite_perf_under_test"] = module
        spec.loader.exec_module(module)
        self.m = module
        return module

    def run(self, *, live_browser_test: bool = False, tor_prewarm: bool = False, tor_required: bool = False) -> None:
        self.setup()
        try:
            self.test_compile()
            self.test_selftest_subprocess()
            m = self.import_app()
            t0 = time.perf_counter()
            m.init_db()
            self.bench("imported init_db", time.perf_counter() - t0, "BlindSite init_db in isolated sandbox")
            self.pass_("import and isolated DB init", "BlindSite imported and initialized in sandbox", version=getattr(m, "APP_VERSION", "unknown"))
            self.configure_for_benchmarks()
            self.test_feature_surface()
            self.benchmark_application_genesis_hash()
            self.benchmark_tor_status()
            self.benchmark_captcha_predicates()
            self.benchmark_header_display()
            self.benchmark_blocked_media_retry_stats()
            self.benchmark_workflow_log_reconstructability()
            self.benchmark_reviewer_import_timeout_helpers()
            self.benchmark_debug_bundle_surface()
            if live_browser_test:
                self.run_local_live_browser_benchmark()
            else:
                self.skip("local live-browser performance benchmark", "disabled; pass --live-browser-test to run Playwright/local media benchmark")
            if tor_prewarm:
                self.run_tor_prewarm_benchmark(required=tor_required)
            else:
                self.skip("Tor prewarm performance benchmark", "disabled; pass --tor-prewarm to run")
        except Exception as exc:
            self.fail("performance evaluator crashed", str(exc), traceback=traceback.format_exc(limit=20))
        finally:
            self.write_reports()
            self.cleanup()

    # ------------------ core checks ------------------

    def test_compile(self) -> None:
        assert self.app_copy is not None
        try:
            t0 = time.perf_counter()
            py_compile.compile(str(self.app_copy), doraise=True)
            elapsed = time.perf_counter() - t0
            self.bench("Python compile", elapsed, "py_compile completed")
            self.pass_("Python compile", "py_compile completed without syntax errors", elapsed_seconds=round(elapsed, 5))
        except Exception as exc:
            self.fail("Python compile", str(exc))
            raise

    def test_selftest_subprocess(self) -> None:
        assert self.app_copy is not None and self.workdir is not None
        try:
            t0 = time.perf_counter()
            result = subprocess.run([sys.executable, str(self.app_copy), "--self-test"], cwd=str(self.workdir), text=True, capture_output=True, timeout=90)
            elapsed = time.perf_counter() - t0
            self.bench("BlindSite --self-test", elapsed, "subprocess self-test")
            evidence = {"returncode": result.returncode, "elapsed_seconds": round(elapsed, 5), "stdout_tail": result.stdout[-2500:], "stderr_tail": result.stderr[-2500:]}
            self.write_json_artifact("self_test/selftest_subprocess.json", evidence, "BlindSite --self-test subprocess output", category="self_test")
            if result.returncode == 0:
                self.pass_("BlindSite --self-test", "self-test exited 0", **evidence)
            else:
                self.warn("BlindSite --self-test", "self-test did not exit 0; performance tests may still run", **evidence)
        except subprocess.TimeoutExpired:
            self.warn("BlindSite --self-test", "timed out after 90 seconds")
        except Exception as exc:
            self.warn("BlindSite --self-test", str(exc))

    def configure_for_benchmarks(self) -> None:
        m = self.m
        settings = {
            "sealed_media_preservation_enabled": "1",
            "sealed_media_preserve_mode": "fast",
            "sealed_media_preserve_max_pending_tasks": "75",
            "sealed_media_preserve_max_items_per_session": "2500",
            "capture_wait_after_load_ms": "5000",
            "capture_network_idle_timeout_ms": "20000",
            "capture_auto_scroll_enabled": "0",
            "live_allow_captcha_challenge_media_default": "0",
            "reviewer_import_unlock_timeout_seconds": "900",
        }
        for k, v in settings.items():
            with contextlib.suppress(Exception):
                m.set_setting(k, v)
        self.write_json_artifact("settings/performance_settings.json", settings, "Settings applied for local performance checks", category="settings")
        self.pass_("performance settings applied", "local benchmark settings applied", settings=settings)

    def test_feature_surface(self) -> None:
        m = self.m
        assert self.app_copy is not None
        source = self.app_copy.read_text(encoding="utf-8", errors="ignore")
        helpers = [
            "application_build_identity",
            "application_genesis_report",
            "tor_status_data",
            "captcha_challenge_media_candidate",
            "captcha_challenge_inline_data_candidate",
            "event_header_hash_html",
            "blocked_media_session_stats",
            "reviewer_import_unlock_timeout_seconds",
            "reviewer_import_unlock_session",
            "reviewer_import_is_unlocked",
            "build_debug_bundle",
        ]
        missing = [h for h in helpers if not hasattr(m, h)]
        markers = {
            "inline_data_captcha": "data:image" in source and "CAPTCHA_CHALLENGE_INLINE_MEDIA_ALLOWED" in source,
            "tor_status_bar": "/tor/status" in source and "tor-status" in source,
            "header_empty_display": "No headers captured" in source,
            "all_not_downloaded_retry": "all_not_downloaded" in source and "only_queue_full" in source,
            "reviewer_timeout": "reviewer_import_unlock_timeout_seconds" in source,
        }
        self.write_json_artifact("feature_surface/current_feature_surface.json", {"helpers": helpers, "missing": missing, "markers": markers}, "Current feature surface scan", category="feature_surface")
        if not missing and all(markers.values()):
            self.pass_("current performance-relevant feature surface", "all current performance-relevant helper surfaces are present")
        else:
            self.fail("current performance-relevant feature surface", "missing helpers or source markers", missing=missing, markers=markers)

    # ------------------ micro benchmarks ------------------

    def benchmark_application_genesis_hash(self) -> None:
        m = self.m
        if not hasattr(m, "application_build_identity"):
            self.fail("Application Genesis Hash timing", "application_build_identity missing")
            return
        samples = []
        for i in range(5):
            t0 = time.perf_counter()
            ident = m.application_build_identity()
            elapsed = time.perf_counter() - t0
            samples.append({"iteration": i + 1, "elapsed_seconds": round(elapsed, 6), "identity": safe_json(ident)})
        self.write_json_artifact("genesis/application_build_identity_samples.json", samples, "Application Genesis Hash timing samples", category="genesis_timing")
        max_elapsed = max(s["elapsed_seconds"] for s in samples)
        first = samples[0]["identity"]
        sha = first.get("executable_sha256") or first.get("source_sha256") or first.get("application_sha256")
        self.bench("Application Genesis Hash helper", max_elapsed, "max of 5 calls", sha256=sha)
        if sha and max_elapsed < 5.0:
            self.pass_("Application Genesis Hash timing", "build/source identity hash computed quickly", max_elapsed=max_elapsed, sha256=sha, mode=first.get("mode"))
        else:
            self.warn("Application Genesis Hash timing", "hash missing or slow", max_elapsed=max_elapsed, identity=first)

    def benchmark_tor_status(self) -> None:
        m = self.m
        if not hasattr(m, "tor_status_data"):
            self.fail("Tor status performance", "tor_status_data missing")
            return
        samples = []
        total_start = time.perf_counter()
        for i in range(20):
            t0 = time.perf_counter()
            st = m.tor_status_data()
            elapsed = time.perf_counter() - t0
            samples.append({"iteration": i + 1, "elapsed_seconds": round(elapsed, 6), "status": safe_json(st)})
        total = time.perf_counter() - total_start
        elapsed_values = [s["elapsed_seconds"] for s in samples]
        avg = sum(elapsed_values) / len(elapsed_values)
        worst = max(elapsed_values)
        self.write_json_artifact("tor/tor_status_samples.json", samples, "Tor status bar/status API performance samples", category="tor_status")
        self.bench("Tor status data", total, "20 tor_status_data calls", average_seconds=avg, worst_seconds=worst)
        required = {"state", "label", "message", "percent", "socks_open", "control_open", "prewarm"}
        if worst < 3.0 and required.issubset(set(samples[-1]["status"].keys())):
            self.pass_("Tor status performance", "tor_status_data is UI-friendly and non-blocking", average_seconds=round(avg, 6), worst_seconds=round(worst, 6), final=samples[-1]["status"])
        else:
            self.fail("Tor status performance", "tor_status_data was slow or missing keys", average_seconds=round(avg, 6), worst_seconds=round(worst, 6), final=samples[-1]["status"])

    def benchmark_captcha_predicates(self) -> None:
        m = self.m
        required = ["captcha_challenge_media_candidate", "captcha_challenge_inline_data_candidate", "captcha_challenge_context_candidate"]
        missing = [x for x in required if not hasattr(m, x)]
        if missing:
            self.fail("CAPTCHA predicate performance", "missing CAPTCHA helper(s)", missing=missing)
            return
        data_uri = "data:image/png;base64," + base64.b64encode(b"fake-inline-captcha").decode("ascii")
        checks = {
            "network_captcha_allowed": bool(m.captcha_challenge_media_candidate("https://captcha.example/onion/captcha.png", "image")),
            "network_logo_blocked": not bool(m.captcha_challenge_media_candidate("https://example.com/static/logo.png", "image")),
            "video_blocked": not bool(m.captcha_challenge_media_candidate("https://example.com/captcha.mp4", "media")),
            "inline_context_allowed": bool(m.captcha_challenge_inline_data_candidate(data_uri, "class captchabtn Are you not a Robot ring_id captcha")),
            "inline_without_context_blocked": not bool(m.captcha_challenge_inline_data_candidate(data_uri, "avatar logo gallery banner")),
        }
        t0 = time.perf_counter()
        for _ in range(self.quick_iterations):
            m.captcha_challenge_media_candidate("https://www.google.com/recaptcha/api2/payload?p=abc", "image")
            m.captcha_challenge_inline_data_candidate(data_uri, "captcha challenge ring_id human verification")
            m.captcha_challenge_context_candidate("ordinary avatar logo banner")
        elapsed = time.perf_counter() - t0
        per_call = elapsed / (self.quick_iterations * 3)
        artifact = {"iterations": self.quick_iterations, "elapsed_seconds": round(elapsed, 6), "seconds_per_call": per_call, "checks": checks}
        self.write_json_artifact("captcha/captcha_predicate_benchmark.json", artifact, "CAPTCHA/challenge predicate speed and scope", category="captcha_performance")
        self.bench("CAPTCHA predicate helpers", elapsed, f"{self.quick_iterations * 3} helper calls", seconds_per_call=per_call)
        if all(checks.values()) and per_call < 0.005:
            self.pass_("CAPTCHA predicate performance", "CAPTCHA/challenge checks are narrow and fast", **artifact)
        else:
            self.fail("CAPTCHA predicate performance", "CAPTCHA helper scope or timing failed", **artifact)

    def benchmark_header_display(self) -> None:
        m = self.m
        if not hasattr(m, "event_header_hash_html"):
            self.fail("Header display performance", "event_header_hash_html missing")
            return
        empty_hash = m.header_hash({})
        real_headers = {"Content-Type": "text/html", "Server": "validation"}
        real_hash = m.header_hash(real_headers)
        t0 = time.perf_counter()
        for _ in range(self.quick_iterations):
            empty_html = m.event_header_hash_html("{}", empty_hash)
            real_html = m.event_header_hash_html(json.dumps(real_headers), real_hash)
        elapsed = time.perf_counter() - t0
        per_render = elapsed / (self.quick_iterations * 2)
        artifact = {"iterations": self.quick_iterations, "elapsed_seconds": round(elapsed, 6), "seconds_per_render": per_render, "empty_hash": empty_hash, "empty_html": empty_html, "real_hash": real_hash, "real_html": real_html}
        self.write_json_artifact("headers/header_display_benchmark.json", artifact, "Header display helper timing and output", category="header_display")
        self.bench("Header display helper", elapsed, f"{self.quick_iterations * 2} renders", seconds_per_render=per_render)
        if "No headers captured" in empty_html and empty_hash not in empty_html and real_hash in real_html and per_render < 0.005:
            self.pass_("Header display performance", "empty-header display is clear and fast", **artifact)
        else:
            self.fail("Header display performance", "header display output/timing failed", **artifact)

    def benchmark_blocked_media_retry_stats(self) -> None:
        m = self.m
        if not hasattr(m, "blocked_media_session_stats") or not hasattr(m, "sha256_text") or not hasattr(m, "header_hash"):
            self.fail("Blocked-media retry stats performance", "blocked-media stats/hash helpers missing")
            return
        sid = "perf-retry-" + hashlib.sha256(os.urandom(8)).hexdigest()[:10]
        qf_count = self.retry_rows // 3
        timeout_count = self.retry_rows // 3
        downloaded_count = self.retry_rows - qf_count - timeout_count

        def row(media_url: str, reason: str, downloaded: bool) -> tuple[Any, ...]:
            record = {
                "session_id": sid,
                "media_url_sha256": m.sha256_text(media_url),
                "resource_type": "image",
                "policy": "block_images_video",
                "reason": reason,
                "downloaded": bool(downloaded),
                "created_at": m.utcnow() if hasattr(m, "utcnow") else utcnow(),
            }
            metadata_record_hash = m.sha256_text(json.dumps(record, sort_keys=True, separators=(",", ":")))
            return (
                None, None, sid, "http://example.test", media_url, record["media_url_sha256"], "image",
                "GET", "img", "http://example.test", "block_images_video", reason, None,
                "image/png", "1", "", "", "{}", "{}", m.header_hash({}), "",
                1 if downloaded else 0, None, metadata_record_hash, record["created_at"],
            )

        rows_to_insert: list[tuple[Any, ...]] = []
        for i in range(qf_count):
            rows_to_insert.append(row(f"http://example.test/qf_{i}.png", "sealed preservation skipped: background queue full (75 >= 75)", False))
        for i in range(timeout_count):
            rows_to_insert.append(row(f"http://example.test/timeout_{i}.png", "sealed preservation failed in background: timeout", False))
        for i in range(downloaded_count):
            rows_to_insert.append(row(f"http://example.test/done_{i}.png", "background encrypted preservation complete", True))

        t_insert = time.perf_counter()
        con = m.db()
        try:
            con.executemany(
                """INSERT INTO blocked_media(case_id,root_evidence_id,session_id,page_url,media_url,url_sha256,resource_type,request_method,tag_type,referrer,policy,reason,status_code,content_type,content_length,etag,last_modified,headers_json,request_headers_json,header_sha256,content_sha256,downloaded,materialized_evidence_id,metadata_record_hash,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows_to_insert,
            )
            con.commit()
        finally:
            with contextlib.suppress(Exception):
                con.close()
        insert_elapsed = time.perf_counter() - t_insert

        t_stats = time.perf_counter()
        stats = m.blocked_media_session_stats(sid)
        stats_elapsed = time.perf_counter() - t_stats
        rows = [dict(r) for r in m.fetchall("SELECT id,downloaded,reason,url_sha256,metadata_record_hash FROM blocked_media WHERE session_id=? ORDER BY id LIMIT 50", (sid,))]
        artifact = {"session_id": sid, "inserted_rows": self.retry_rows, "expected": {"queue_full": qf_count, "timeouts": timeout_count, "downloaded": downloaded_count}, "stats": stats, "insert_elapsed_seconds": insert_elapsed, "stats_elapsed_seconds": stats_elapsed, "sample_rows": rows, "insert_method": "direct transactional fixture insert to measure stats/retry workflow rather than record_blocked_media audit overhead"}
        self.write_json_artifact("retry/blocked_media_retry_stats_benchmark.json", artifact, "Blocked-media retry/statistics performance and reconstructable rows", category="retry_stats")
        self.bench("Blocked-media retry stats", stats_elapsed, f"stats over {self.retry_rows} rows", insert_seconds=insert_elapsed, stats=stats)
        expected_not = qf_count + timeout_count
        ok = int(stats.get("total") or 0) == self.retry_rows and int(stats.get("not_downloaded") or 0) == expected_not and int(stats.get("queue_full") or 0) == qf_count and stats_elapsed < 2.0
        if ok:
            self.pass_("Blocked-media retry stats performance", "all-not-downloaded includes queue-full and stats are fast", **artifact)
        else:
            self.fail("Blocked-media retry stats performance", "retry stats output or timing failed", **artifact)

    def benchmark_workflow_log_reconstructability(self) -> None:
        """Reconstruct workflow/reliability logs that are not pure security controls.

        These checks intentionally live in the performance/workflow evaluator:
        - retry request events and queue-full/not-downloaded semantics;
        - Tor runtime/status samples;
        - browser_events rows with empty vs real headers and display labels.
        """
        m = self.m
        required = ["log_event", "tor_status_data", "header_hash", "event_header_hash_html"]
        missing = [x for x in required if not hasattr(m, x)]
        if missing:
            self.fail("Workflow log reconstructability", "missing helper(s)", missing=missing)
            return
        sid = "perf-workflow-log-" + hashlib.sha256(os.urandom(8)).hexdigest()[:10]
        try:
            t0 = time.perf_counter()
            retry_details = {
                "retry_all_not_downloaded": True,
                "only_queue_full": False,
                "selected_count": 0,
                "result": {"queued": 3, "queue_full": 1, "errors": 0},
                "evaluator_note": "workflow/performance reconstructability sample",
            }
            retry_hash = m.log_event("performance_evaluator", "LIVE_BLOCKED_MEDIA_RETRY_REQUESTED", session_id=sid, details=retry_details)

            tor_before = m.tor_status_data()
            if hasattr(m, "tor_append_runtime_log"):
                m.tor_append_runtime_log("performance evaluator reconstructability sample: tor status observed")
            tor_after = m.tor_status_data()
            tor_log_tail = m.tor_log_tail(2000) if hasattr(m, "tor_log_tail") else ""

            empty_headers_json = "{}"
            empty_header_sha = m.header_hash({})
            real_headers = {"Content-Type": "text/html", "Server": "performance-evaluator"}
            real_headers_json = json.dumps(real_headers, sort_keys=True)
            real_header_sha = m.header_hash(real_headers)
            now = m.utcnow() if hasattr(m, "utcnow") else utcnow()
            m.execute(
                "INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sid, now, "performance_empty_header_sample", "http://example.test/empty", "document", "GET", None, empty_headers_json, empty_header_sha, json.dumps({"display_html": m.event_header_hash_html(empty_headers_json, empty_header_sha)}, ensure_ascii=False)),
            )
            m.execute(
                "INSERT INTO browser_events(session_id,created_at,event_type,url,resource_type,method,status_code,headers_json,header_sha256,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sid, now, "performance_real_header_sample", "http://example.test/real", "document", "GET", 200, real_headers_json, real_header_sha, json.dumps({"display_html": m.event_header_hash_html(real_headers_json, real_header_sha)}, ensure_ascii=False)),
            )
            audit_rows = [dict(r) for r in m.fetchall("SELECT * FROM audit_events WHERE session_id=? ORDER BY id ASC", (sid,))]
            browser_rows = [dict(r) for r in m.fetchall("SELECT * FROM browser_events WHERE session_id=? ORDER BY id ASC", (sid,))]
            elapsed = time.perf_counter() - t0
            reconstructed = {
                "session_id": sid,
                "elapsed_seconds": elapsed,
                "retry_event_hash": retry_hash,
                "retry_details": retry_details,
                "audit_rows": safe_json(audit_rows),
                "browser_rows": safe_json(browser_rows),
                "tor_status_before": safe_json(tor_before),
                "tor_status_after": safe_json(tor_after),
                "tor_log_tail_sample": tor_log_tail[-1000:],
                "empty_header_display": m.event_header_hash_html(empty_headers_json, empty_header_sha),
                "real_header_display": m.event_header_hash_html(real_headers_json, real_header_sha),
                "empty_header_sha256": empty_header_sha,
                "real_header_sha256": real_header_sha,
            }
            self.write_json_artifact("workflow_logs/workflow_log_reconstructability.json", reconstructed, "Workflow log reconstructability sample for retry, Tor status, and header display rows", category="workflow_log_reconstructability")
            self.bench("Workflow log reconstructability", elapsed, "insert/read audit+browser workflow rows and Tor status samples")
            ok = (
                audit_rows
                and browser_rows
                and "No headers captured" in reconstructed["empty_header_display"]
                and empty_header_sha not in reconstructed["empty_header_display"]
                and real_header_sha in reconstructed["real_header_display"]
                and isinstance(tor_before, dict)
                and isinstance(tor_after, dict)
            )
            if ok:
                self.pass_("Workflow log reconstructability", "retry events, Tor status samples, and empty/real header browser-event rows are reconstructable", elapsed_seconds=round(elapsed, 6), session_id=sid)
            else:
                self.fail("Workflow log reconstructability", "workflow log reconstruction sample failed", **reconstructed)
        except Exception as exc:
            self.fail("Workflow log reconstructability", str(exc), traceback=traceback.format_exc(limit=12))

    def benchmark_reviewer_import_timeout_helpers(self) -> None:
        m = self.m
        required = ["reviewer_import_unlock_timeout_seconds", "reviewer_import_unlock_session", "reviewer_import_is_unlocked", "reviewer_import_lock_session", "reviewer_import_session_key", "set_reviewer_import_password", "set_reviewer_import_webauthn_protection"]
        missing = [x for x in required if not hasattr(m, x)]
        if missing:
            self.fail("LE Reviewer timeout helper performance", "missing helper(s)", missing=missing)
            return
        class DummyRequest:
            def __init__(self) -> None:
                self.session = {"username": "admin"}
        try:
            now = m.utcnow()
            import_id = m.execute("""INSERT INTO reviewer_imports(package_name,package_sha256,package_size,status,imported_by,created_at,object_count,recovered_count,case_name,vault_path,manifest_json,notes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", ("perf_timeout_import.zip", "0" * 64, 0, "imported", "performance_evaluator", now, 0, 0, "Performance Timeout Import", "perf_timeout", "{}", "{}"))
            m.set_reviewer_import_password(import_id, "Perf-Reviewer-Password-123!", "performance_evaluator")
            m.set_reviewer_import_webauthn_protection(import_id, True, "performance_evaluator")
            imp = m.reviewer_import_for(import_id)
            req = DummyRequest()
            t0 = time.perf_counter()
            m.set_setting("reviewer_import_unlock_timeout_seconds", "1")
            m.reviewer_import_unlock_session(req, import_id, "admin", "password+yubikey")
            key = m.reviewer_import_session_key(import_id)
            req.session[key]["last_activity"] = time.time() - 5
            locked_after_timeout = not bool(m.reviewer_import_is_unlocked(req, import_id, imp))
            m.set_setting("reviewer_import_unlock_timeout_seconds", "0")
            m.reviewer_import_unlock_session(req, import_id, "admin", "password+yubikey")
            req.session[key]["last_activity"] = time.time() - 3600
            unlocked_no_timeout = bool(m.reviewer_import_is_unlocked(req, import_id, imp))
            elapsed = time.perf_counter() - t0
            notes = m.reviewer_import_notes(imp)
            artifact = {"import_id": import_id, "elapsed_seconds": elapsed, "locked_after_timeout": locked_after_timeout, "unlocked_no_timeout": unlocked_no_timeout, "session": safe_json(req.session), "notes": safe_json(notes)}
            self.write_json_artifact("reviewer_timeout/reviewer_import_timeout_benchmark.json", artifact, "LE Reviewer import timeout helper timing and session reconstruction", category="reviewer_timeout")
            self.bench("LE Reviewer timeout helpers", elapsed, "unlock/timeout/no-timeout helper flow")
            if locked_after_timeout and unlocked_no_timeout and elapsed < 2.0:
                self.pass_("LE Reviewer timeout helper performance", "reviewer import timeout helpers are fast and reconstructable", **artifact)
            else:
                self.fail("LE Reviewer timeout helper performance", "timeout helper behavior or timing failed", **artifact)
        except Exception as exc:
            self.fail("LE Reviewer timeout helper performance", str(exc), traceback=traceback.format_exc(limit=12))

    def benchmark_debug_bundle_surface(self) -> None:
        m = self.m
        if not hasattr(m, "build_debug_bundle"):
            self.warn("Debug bundle surface", "build_debug_bundle missing")
            return
        try:
            t0 = time.perf_counter()
            data = m.build_debug_bundle("performance_evaluator")
            elapsed = time.perf_counter() - t0
            listing = zip_listing(data)
            artifact = {"elapsed_seconds": elapsed, "size": len(data), "listing": listing}
            self.write_json_artifact("debug_bundle/debug_bundle_summary.json", artifact, "Debug bundle generation performance and listing", category="debug_bundle")
            self.bench("Debug bundle generation", elapsed, "build_debug_bundle")
            needed = {"application_genesis.json", "self_test.json", "application_build_identity.json"}
            names = {Path(x["name"]).name for x in listing}
            if needed.issubset(names) and elapsed < 10.0:
                self.pass_("Debug bundle performance", "debug bundle includes reconstructable current-feature diagnostics", **artifact)
            else:
                self.warn("Debug bundle performance", "debug bundle generated but missing expected files or slow", **artifact)
        except Exception as exc:
            self.warn("Debug bundle performance", str(exc), traceback=traceback.format_exc(limit=8))

    # ------------------ optional live browser benchmark ------------------

    def run_local_live_browser_benchmark(self) -> None:
        m = self.m
        if not hasattr(m, "start_live_session"):
            self.skip("local live-browser performance benchmark", "start_live_session missing")
            return
        server = LocalMediaServer(asset_count=self.live_assets, delay_ms=self.live_delay_ms)
        server.start()
        session = None
        try:
            case_id = create_lab_case(m, "Performance Local Live Benchmark")
            with contextlib.suppress(Exception):
                m.set_setting("sealed_media_preservation_enabled", "1")
                m.execute("UPDATE cases SET sealed_media_preservation_enabled=1, sealed_media_preserve_images=1, sealed_media_preserve_video=1, sealed_media_preserve_audio=1 WHERE id=?", (case_id,))
            start_url = server.url("/")
            t0 = time.perf_counter()
            kwargs = {
                "actor": "performance_evaluator",
                "case_id": case_id,
                "start_url": start_url,
                "browser_choice": "chromium",
                "use_tor": False,
                "media_policy": "block_images_video",
                "headless": True,
                "download_allowed_media": False,
                "auto_capture": False,
                "settle_before_capture": True,
                "sealed_media_preservation_session": True,
                "capture_auto_scroll_session": False,
                "allow_captcha_challenge_media": True,
            }
            sig = inspect.signature(m.start_live_session)
            kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
            session = m.start_live_session(**kwargs)
            start_elapsed = time.perf_counter() - t0
            sid = session.session_id
            samples = []
            wait_start = time.perf_counter()
            while time.perf_counter() - wait_start < 20:
                samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": safe_json(m.live_preservation_status_for(sid))})
                if int(samples[-1]["status"].get("blocked") or 0) >= max(1, self.live_assets // 2):
                    break
                time.sleep(0.5)
            capture_start = time.perf_counter()
            eid = session.capture_current_sync()
            capture_elapsed = time.perf_counter() - capture_start
            final_status = m.live_preservation_status_for(sid)
            rows = [dict(r) for r in m.fetchall("SELECT id,event_type,url,resource_type,method,headers_json,header_sha256,meta_json FROM browser_events WHERE session_id=? ORDER BY id LIMIT 200", (sid,))]
            result = {"case_id": case_id, "session_id": sid, "start_url": start_url, "session_start_seconds": start_elapsed, "capture_seconds": capture_elapsed, "samples": samples, "final_status": safe_json(final_status), "server_requests": server.request_count, "browser_events": safe_json(rows), "page_evidence_id": eid}
            self.write_json_artifact("live_browser/local_live_benchmark.json", result, "Optional local live browser benchmark with CAPTCHA exception enabled", category="live_browser")
            self.bench("Local live browser benchmark", start_elapsed + capture_elapsed, "session start + capture", final_status=final_status)
            if capture_elapsed < 30:
                self.pass_("local live-browser performance benchmark", "live session and page capture completed", **result)
            else:
                self.warn("local live-browser performance benchmark", "capture completed but was slow", **result)
        except Exception as exc:
            msg = str(exc)
            if "Executable doesn't exist" in msg or "playwright" in msg.lower():
                self.skip("local live-browser performance benchmark", "Playwright browser is unavailable; run `python -m playwright install chromium` to enable this benchmark", error=msg[:1000])
            else:
                self.warn("local live-browser performance benchmark", str(exc), traceback=traceback.format_exc(limit=12))
        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    session.stop_sync()
            server.stop()

    def run_tor_prewarm_benchmark(self, *, required: bool = False) -> None:
        m = self.m
        if not hasattr(m, "tor_prewarm_background") or not hasattr(m, "tor_prewarm_status"):
            self.skip("Tor prewarm performance benchmark", "Tor prewarm helpers missing")
            return
        samples = []
        try:
            t0 = time.perf_counter()
            initial = m.tor_prewarm_background("performance-evaluator")
            samples.append({"elapsed": 0.0, "status": safe_json(initial)})
            final = initial
            for _ in range(60):
                time.sleep(1)
                final = m.tor_prewarm_status()
                samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": safe_json(final)})
                if not final.get("running"):
                    break
            elapsed = time.perf_counter() - t0
            artifact = {"elapsed_seconds": elapsed, "initial": safe_json(initial), "final": safe_json(final), "samples": samples}
            self.write_json_artifact("tor/tor_prewarm_benchmark.json", artifact, "Optional Tor prewarm/status benchmark", category="tor_prewarm")
            self.bench("Tor prewarm benchmark", elapsed, "tor_prewarm_background/tor_prewarm_status")
            if final.get("ok"):
                self.pass_("Tor prewarm performance benchmark", "Tor prewarm completed", **artifact)
            elif required:
                self.fail("Tor prewarm performance benchmark", "Tor was required but did not become ready", **artifact)
            else:
                self.warn("Tor prewarm performance benchmark", "Tor did not become ready; expected if Tor is not configured", **artifact)
        except Exception as exc:
            if required:
                self.fail("Tor prewarm performance benchmark", str(exc), traceback=traceback.format_exc(limit=12))
            else:
                self.warn("Tor prewarm performance benchmark", str(exc), traceback=traceback.format_exc(limit=12))

    # ------------------ artifacts/reports ------------------

    def run_context(self) -> dict[str, Any]:
        return {
            "suite": "BlindSite Performance Evaluator",
            "suite_version": APP_VERSION,
            "started_at_utc": self.started_at,
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
            "parameters": {
                "quick_iterations": self.quick_iterations,
                "retry_rows": self.retry_rows,
                "live_assets": self.live_assets,
                "live_delay_ms": self.live_delay_ms,
            },
        }

    def artifact_path(self, rel: str) -> Path:
        if self.artifact_dir is None:
            raise RuntimeError("artifact directory not initialized")
        rel = rel.replace("\\", "/").lstrip("/")
        if ".." in Path(rel).parts:
            raise ValueError("artifact path cannot contain ..")
        p = self.artifact_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_bytes_artifact(self, rel: str, data: bytes, description: str, *, category: str = "artifact", mime: str = "application/octet-stream") -> dict[str, Any]:
        p = self.artifact_path(rel)
        p.write_bytes(data)
        rec = {"path": rel.replace("\\", "/"), "description": description, "category": category, "mime": mime, "size": len(data), "sha256": sha256_bytes(data)}
        self.artifacts.append(rec)
        return rec

    def write_json_artifact(self, rel: str, obj: Any, description: str, *, category: str = "json") -> dict[str, Any]:
        data = json.dumps(safe_json(obj), indent=2, ensure_ascii=False).encode("utf-8")
        return self.write_bytes_artifact(rel, data, description, category=category, mime="application/json")

    def write_reports(self) -> None:
        out = self.report_root / ("blindsite_performance_validation_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
        out.mkdir(parents=True, exist_ok=True)
        counts: dict[str, int] = {}
        for c in self.checks:
            counts[c.status] = counts.get(c.status, 0) + 1
        report = {
            "suite": "BlindSite Performance Evaluator",
            "suite_version": APP_VERSION,
            "started_at_utc": self.started_at,
            "finished_at_utc": utcnow(),
            "counts": counts,
            "overall": "FAIL" if counts.get("FAIL") else "PASS with caveats/warnings/skips as listed",
            "checks": [c.__dict__ for c in self.checks],
            "benchmarks": [b.__dict__ for b in self.benchmarks],
            "artifacts": self.artifacts,
            "reconstruction_steps": self.reconstruction_steps,
        }
        (out / "performance_report.json").write_text(json.dumps(safe_json(report), indent=2, ensure_ascii=False), encoding="utf-8")
        (out / "performance_report.md").write_text(render_markdown_report(report), encoding="utf-8")
        (out / "benchmark_summary.csv").write_text(render_benchmark_csv(self.benchmarks), encoding="utf-8")
        (out / "reconstruction_chain.json").write_text(json.dumps({"steps": self.reconstruction_steps, "artifacts": self.artifacts}, indent=2, ensure_ascii=False), encoding="utf-8")
        if self.artifact_dir and self.artifact_dir.exists():
            shutil.copytree(self.artifact_dir, out / "performance_artifacts", dirs_exist_ok=True)
        self.log("\n" + "=" * 72)
        self.log("PERFORMANCE VALIDATION COMPLETE")
        self.log("=" * 72)
        self.log(f"Report folder: {out}")
        self.log(f"Pass: {counts.get('PASS',0)} | Fail: {counts.get('FAIL',0)} | Warn: {counts.get('WARN',0)} | Skip: {counts.get('SKIP',0)}")
        self.log("Overall: " + report["overall"])


# ------------------ local server ------------------

class LocalMediaServer:
    def __init__(self, *, asset_count: int, delay_ms: int):
        self.asset_count = asset_count
        self.delay_ms = delay_ms
        self.httpd = None
        self.thread = None
        self.port = 0
        self.request_count = 0
        self._lock = threading.Lock()
        self.png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")

    def start(self) -> None:
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return
            def do_GET(self) -> None:
                with outer._lock:
                    outer.request_count += 1
                if outer.delay_ms:
                    time.sleep(outer.delay_ms / 1000.0)
                if self.path == "/" or self.path.startswith("/?"):
                    body = outer.index_html().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path.startswith("/img"):
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(outer.png)))
                    self.end_headers()
                    self.wfile.write(outer.png)
                elif self.path.startswith("/captcha"):
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(outer.png)))
                    self.end_headers()
                    self.wfile.write(outer.png)
                else:
                    self.send_response(404)
                    self.end_headers()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def index_html(self) -> str:
        data_uri = "data:image/png;base64," + base64.b64encode(self.png).decode("ascii")
        images = "\n".join(f"<img src='/img{i}.png' alt='asset {i}'>" for i in range(self.asset_count))
        return f"""<!doctype html><html><head><title>BlindSite Performance Local Media Stress Page</title></head><body>
<h1>BlindSite Performance Local Media Stress Page</h1>
<form><p>Are you not a Robot? Select the CAPTCHA ring.</p><img class='captchabtn' alt='captcha challenge' src='{data_uri}'><input name='ring_id' value='7'><button>Submit</button></form>
<img src='/captcha.png' alt='captcha image'>
{images}
</body></html>"""

    def url(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self) -> None:
        if self.httpd:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
            with contextlib.suppress(Exception):
                self.httpd.server_close()


# ------------------ helpers ------------------

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_json(obj: Any) -> Any:
    if isinstance(obj, sqlite3.Row):
        obj = dict(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(x in kl for x in ["password", "private_key", "passphrase", "token", "challenge"]):
                if "public" in kl or "fingerprint" in kl:
                    out[k] = safe_json(v)
                else:
                    out[k] = "[REDACTED]"
            else:
                out[k] = safe_json(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [safe_json(x) for x in obj]
    if isinstance(obj, bytes):
        return {"bytes_len": len(obj), "sha256": sha256_bytes(obj)}
    if isinstance(obj, Path):
        return str(obj)
    return obj


def zip_listing(data: bytes) -> list[dict[str, Any]]:
    import zipfile
    out = []
    with zipfile.ZipFile(__import__("io").BytesIO(data), "r") as z:
        for info in z.infolist():
            payload = z.read(info.filename)
            out.append({"name": info.filename, "size": len(payload), "sha256": sha256_bytes(payload)})
    return out


def create_lab_case(m: Any, name: str) -> int:
    now = m.utcnow()
    cid = m.execute("""INSERT INTO cases(name,description,mode,compliance_safe,irreversible_lock,never_materialize_originals,no_plaintext_export,raw_root_allowed,default_media_policy,force_tor,quarantine_default,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (name, "Performance evaluator generated test case.", "lab", 0, 0, 1, 1, 1, "block_images_video", 0, 1, "performance_evaluator", now))
    with contextlib.suppress(Exception):
        m.ensure_application_genesis_event(f"case:{cid}", case_id=cid, actor="system")
    return int(cid)


def render_markdown_report(report: dict[str, Any]) -> str:
    counts = report.get("counts", {})
    lines = [
        "# BlindSite Performance Validation Report",
        "",
        f"Suite version: `{report.get('suite_version')}`",
        f"Started: `{report.get('started_at_utc')}`",
        f"Finished: `{report.get('finished_at_utc')}`",
        f"Overall: **{report.get('overall')}**",
        "",
        f"Checks: **{counts.get('PASS', 0)} pass**, **{counts.get('FAIL', 0)} fail**, **{counts.get('WARN', 0)} warn**, **{counts.get('SKIP', 0)} skip**.",
        "",
        "## Benchmarks",
        "",
        "| Benchmark | Seconds | Detail |",
        "|---|---:|---|",
    ]
    for b in report.get("benchmarks", []):
        lines.append(f"| {b.get('name')} | {b.get('elapsed_seconds')} | {str(b.get('detail') or '').replace('|','/')} |")
    lines += ["", "## Checks", "", "| Status | Check | Detail |", "|---|---|---|"]
    for c in report.get("checks", []):
        lines.append(f"| {c.get('status')} | {c.get('name')} | {str(c.get('detail') or '').replace('|','/')} |")
    lines += [
        "",
        "## Reconstructability",
        "",
        "The `performance_artifacts/` folder contains timing samples, DB row samples, status snapshots, feature scans, and helper outputs used to reconstruct the validation run.",
        "The `reconstruction_chain.json` file lists the evaluator steps and artifact hashes.",
    ]
    return "\n".join(lines) + "\n"


def render_benchmark_csv(benchmarks: list[Benchmark]) -> str:
    lines = ["name,elapsed_seconds,detail"]
    for b in benchmarks:
        name = str(b.name).replace('"', '""')
        detail = str(b.detail or "").replace('"', '""')
        lines.append(f'"{name}",{b.elapsed_seconds},"{detail}"')
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="BlindSite performance/workflow validation harness")
    ap.add_argument("--app", required=True, help="Path to BlindSite.py")
    ap.add_argument("--report-dir", default="performance_eval_report", help="Output report directory")
    ap.add_argument("--keep-temp", action="store_true", help="Keep temporary sandbox")
    ap.add_argument("--quiet", action="store_true", help="Reduce console output")
    ap.add_argument("--quick-iterations", type=int, default=1000, help="Iterations for micro benchmarks")
    ap.add_argument("--retry-rows", type=int, default=600, help="Rows to insert for retry-stat benchmark")
    ap.add_argument("--live-browser-test", action="store_true", help="Run optional Playwright local live-browser benchmark")
    ap.add_argument("--live-assets", type=int, default=60, help="Number of local image assets in optional live benchmark")
    ap.add_argument("--live-delay-ms", type=int, default=5, help="Server delay per asset in optional live benchmark")
    ap.add_argument("--tor-prewarm", action="store_true", help="Run optional Tor prewarm/status benchmark")
    ap.add_argument("--tor-required", action="store_true", help="Fail if Tor prewarm benchmark does not become ready")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    ev = PerformanceEvaluator(
        app_path=Path(args.app),
        report_root=Path(args.report_dir),
        keep_temp=args.keep_temp,
        verbose=not args.quiet,
        quick_iterations=args.quick_iterations,
        retry_rows=args.retry_rows,
        live_assets=args.live_assets,
        live_delay_ms=args.live_delay_ms,
    )
    ev.run(live_browser_test=bool(args.live_browser_test), tor_prewarm=bool(args.tor_prewarm), tor_required=bool(args.tor_required))


if __name__ == "__main__":
    main()
