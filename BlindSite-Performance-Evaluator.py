#!/usr/bin/env python3
"""
BlindSite Performance Evaluator

US CYBER MILITIA | BLINDSITE

Standalone performance validation harness for BlindSite.py.

Purpose:
- Measure live browser/capture performance in a controlled local test.
- Produce reconstructable logs/artifacts instead of only summary claims.
- Validate that the fast live-route model stays fast while blocked media
  preservation runs in the background.
- Optionally run a quick real-website benchmark.
- Optionally run a Tor prewarm/status performance check.

This is a performance/workflow evaluator, not a security certification.
Security/encryption claims should be covered by BlindSite-Security-Evaluator.py.
"""

from __future__ import annotations

import argparse
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


APP_VERSION = "1.1.1-performance-workflow-validation-v5.14"
DEFAULT_ASSET_COUNT = 80
DEFAULT_SVG_COUNT = 20
DEFAULT_VIDEO_COUNT = 4
DEFAULT_ASSET_DELAY_MS = 10
DEFAULT_PAGE_WAIT_SECONDS = 20
DEFAULT_PRESERVATION_WAIT_SECONDS = 45
DEFAULT_QUEUE_LIMIT = 45
DEFAULT_MAX_ITEMS = 2500


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


class PerformanceEvaluator:
    def __init__(
        self,
        *,
        app_path: Path,
        report_root: Path,
        keep_temp: bool = False,
        verbose: bool = True,
        asset_count: int = DEFAULT_ASSET_COUNT,
        svg_count: int = DEFAULT_SVG_COUNT,
        video_count: int = DEFAULT_VIDEO_COUNT,
        asset_delay_ms: int = DEFAULT_ASSET_DELAY_MS,
        queue_limit: int = DEFAULT_QUEUE_LIMIT,
        max_items: int = DEFAULT_MAX_ITEMS,
        preserve_mode: str = "fast",
    ):
        self.original_app_path = app_path.expanduser().resolve()
        self.report_root = report_root.expanduser().resolve()
        self.keep_temp = keep_temp
        self.verbose = verbose
        self.asset_count = int(asset_count)
        self.svg_count = int(svg_count)
        self.video_count = int(video_count)
        self.asset_delay_ms = int(asset_delay_ms)
        self.queue_limit = int(queue_limit)
        self.max_items = int(max_items)
        self.preserve_mode = preserve_mode if preserve_mode in {"fast", "balanced", "complete"} else "fast"
        self.started_at = now_iso()
        self.checks: list[Check] = []
        self.tempdir_obj: tempfile.TemporaryDirectory[str] | None = None
        self.workdir: Path | None = None
        self.app_copy: Path | None = None
        self.m = None
        self.artifact_dir: Path | None = None
        self.artifacts: list[dict[str, Any]] = []
        self.benchmarks: list[dict[str, Any]] = []
        self.reconstruction_steps: list[dict[str, Any]] = []

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
            "name": name,
            "detail": detail,
            "timestamp_utc": now_iso(),
            "data": safe_json(data),
        })

    def setup(self) -> None:
        if not self.original_app_path.exists():
            raise SystemExit(f"BlindSite file not found: {self.original_app_path}")
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.tempdir_obj = tempfile.TemporaryDirectory(prefix="blindsite_perf_")
        self.workdir = Path(self.tempdir_obj.name)
        self.app_copy = self.workdir / "BlindSite_under_test.py"
        self.artifact_dir = self.workdir / "performance_artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.original_app_path, self.app_copy)
        self.write_json_artifact("environment/run_context.json", self.run_context(), "Run context and environment metadata")
        self.log(f"Using sandbox: {self.workdir}")
        self.log(f"Copied app under test: {self.app_copy}")

    def cleanup(self) -> None:
        if self.keep_temp:
            self.warn("temporary sandbox retained", str(self.workdir))
            return
        if self.tempdir_obj:
            self.tempdir_obj.cleanup()

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
            "benchmark_defaults": {
                "asset_count": self.asset_count,
                "svg_count": self.svg_count,
                "video_count": self.video_count,
                "asset_delay_ms": self.asset_delay_ms,
                "queue_limit": self.queue_limit,
                "max_items": self.max_items,
                "preserve_mode": self.preserve_mode,
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
        rec = {
            "path": rel.replace("\\", "/"),
            "description": description,
            "category": category,
            "mime": mime,
            "size": len(data),
            "sha256": sha256_bytes(data),
        }
        self.artifacts.append(rec)
        return rec

    def write_json_artifact(self, rel: str, obj: Any, description: str, *, category: str = "json") -> dict[str, Any]:
        data = json.dumps(safe_json(obj), indent=2, ensure_ascii=False).encode("utf-8")
        return self.write_bytes_artifact(rel, data, description, category=category, mime="application/json")

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

    def run(self, *, external_url: str = "", run_control: bool = True, run_tor_prewarm: bool = False, tor_required: bool = False) -> None:
        self.setup()
        try:
            self.test_compile()
            self.test_selftest_subprocess()
            m = self.import_app()
            m.init_db()
            self.pass_("import and isolated DB init", "BlindSite imported and initialized in sandbox", version=getattr(m, "APP_VERSION", "unknown"))
            self.configure_app_for_performance_tests()
            self.test_new_feature_surface()
            self.test_pdf_report_queue_helpers()
            self.run_local_media_benchmarks(run_control=run_control)
            if external_url:
                self.run_external_url_benchmark(external_url)
            if run_tor_prewarm:
                self.run_tor_prewarm_benchmark(required=tor_required)
        except Exception as exc:
            self.fail("performance evaluator crashed", str(exc), traceback=traceback.format_exc(limit=20))
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
                timeout=90,
            )
            evidence = {"returncode": result.returncode, "stdout_tail": result.stdout[-1500:], "stderr_tail": result.stderr[-1500:]}
            if result.returncode == 0:
                self.pass_("BlindSite --self-test", "self-test exited 0", **evidence)
            else:
                self.warn("BlindSite --self-test", "self-test did not exit 0; performance tests may still run", **evidence)
        except subprocess.TimeoutExpired:
            self.warn("BlindSite --self-test", "timed out after 90 seconds")
        except Exception as exc:
            self.warn("BlindSite --self-test", str(exc))

    def configure_app_for_performance_tests(self) -> None:
        m = self.m
        assert m is not None
        pub_pem, pub_fp = generate_public_key_for_org_hardseal()
        settings = {
            "custody_mode": "organization",
            "sealed_media_preservation_enabled": "1",
            "sealed_media_preserve_images": "1",
            "sealed_media_preserve_video": "1",
            "sealed_media_preserve_audio": "1",
            "sealed_media_preserve_mode": self.preserve_mode,
            "sealed_media_preserve_max_pending_tasks": str(self.queue_limit),
            "sealed_media_preserve_max_items_per_session": str(self.max_items),
            "sealed_media_preserve_max_bytes": str(50 * 1024 * 1024),
            "sealed_media_preserve_max_total_bytes": str(512 * 1024 * 1024),
            "sealed_media_preserve_background_timeout_ms": "8000",
            "sealed_media_preserve_fetch_timeout_ms": "6000",
            "sealed_media_preserve_flush_before_capture_ms": "1000",
            "sealed_media_preserve_skip_decorative_fast": "0",
            "sealed_media_preserve_mime_allowlist": "image/\nvideo/\naudio/\napplication/dash+xml\napplication/vnd.apple.mpegurl\napplication/x-mpegurl\napplication/mp4\napplication/octet-stream",
            "organization_hard_seal_media_enabled": "1",
            "organization_hard_seal_public_key_pem": pub_pem,
            "organization_hard_seal_public_key_fingerprint": pub_fp,
            "live_browser_default": "chromium",
            "capture_auto_scroll_default": "0",
            "capture_settle_before_capture_default": "1",
            "auto_capture_after_settle_default": "0",
        }
        for k, v in settings.items():
            set_app_setting(m, k, v)
        self.write_json_artifact("settings/performance_test_settings.json", settings, "Settings applied for performance benchmark", category="settings")
        self.pass_("performance settings applied", "settings configured for fast blocked-media preservation", queue_limit=self.queue_limit, max_items=self.max_items, preserve_mode=self.preserve_mode, org_public_key_fingerprint=pub_fp)

    def create_case(self, name: str, *, sealed: bool = True) -> int:
        m = self.m
        assert m is not None
        now = getattr(m, "utcnow", now_iso)()
        cid = m.execute(
            """INSERT INTO cases(name,description,mode,compliance_safe,irreversible_lock,never_materialize_originals,no_plaintext_export,raw_root_allowed,default_media_policy,force_tor,quarantine_default,created_by,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name,
                "Performance evaluator generated test case.",
                "lab",
                0,
                0,
                1,
                1,
                1,
                "block_images_video",
                0,
                1,
                "performance_evaluator",
                now,
            ),
        )
        with contextlib.suppress(Exception):
            m.execute(
                """UPDATE cases SET sealed_media_preservation_enabled=?, sealed_media_preserve_images=?, sealed_media_preserve_video=?, sealed_media_preserve_audio=?, sealed_media_preserve_max_bytes=? WHERE id=?""",
                (1 if sealed else 0, 1, 1, 1, 50 * 1024 * 1024, cid),
            )
        return int(cid)

    def test_new_feature_surface(self) -> None:
        """Check that recent workstation/performance feature surfaces exist.

        This is not a security proof. It ensures the app under test exposes the
        operational features that the performance evaluator can rely on or report
        about: PDF job queues, Tor prewarm/status helpers, reviewer password
        helpers, and PDF encryption helper.
        """
        m = self.m
        required = [
            "pdf_report_jobs_for_import",
            "pdf_report_job_snapshot",
            "pdf_report_job_update",
            "pdf_report_job_log",
            "pdf_report_job_cancelled",
            "tor_prewarm_background",
            "tor_prewarm_status",
            "set_reviewer_import_password",
            "reviewer_import_is_password_protected",
            "encrypt_pdf_report_bytes",
        ]
        missing = [name for name in required if not hasattr(m, name)]
        constants = {
            "PDF_REPORT_MAX_PAGES": getattr(m, "PDF_REPORT_MAX_PAGES", None),
            "PDF_REPORT_DEVICE_SCALE_FACTOR": getattr(m, "PDF_REPORT_DEVICE_SCALE_FACTOR", None),
            "PDF_REPORT_DPI": getattr(m, "PDF_REPORT_DPI", None),
            "PDF_REPORT_JPEG_QUALITY": getattr(m, "PDF_REPORT_JPEG_QUALITY", None),
        }
        self.write_json_artifact("feature_surface/recent_features.json", {"required_helpers": required, "missing": missing, "pdf_constants": constants}, "Recent BlindSite feature surface check", category="feature_surface")
        if missing:
            self.warn("recent feature surface", "some recent feature helpers were not found; older app build may be under test", missing=missing, pdf_constants=constants)
        else:
            self.pass_("recent feature surface", "recent PDF/Tor/reviewer helper surfaces are present", pdf_constants=constants)
        if constants.get("PDF_REPORT_MAX_PAGES") == 20:
            self.pass_("PDF max page configuration", "PDF report max pages is configured for 20 pages", value=constants.get("PDF_REPORT_MAX_PAGES"))
        else:
            self.warn("PDF max page configuration", "PDF report max pages was not 20", value=constants.get("PDF_REPORT_MAX_PAGES"))
        try:
            if float(constants.get("PDF_REPORT_DEVICE_SCALE_FACTOR") or 0) >= 2:
                self.pass_("PDF high-resolution capture configuration", "PDF report device scale factor is >= 2", **constants)
            else:
                self.warn("PDF high-resolution capture configuration", "PDF report scale factor is lower than expected", **constants)
        except Exception:
            self.warn("PDF high-resolution capture configuration", "could not evaluate PDF scale factor", **constants)

    def test_pdf_report_queue_helpers(self) -> None:
        """Reconstructably test the in-memory PDF job queue helpers without heavy rendering.

        Full screenshot/PDF rendering is intentionally not forced here because it
        can be environment-dependent and expensive. This validates the queue
        mechanics that should remain visible even when a user leaves the progress
        page: create/update/log/list/snapshot/cancel.
        """
        m = self.m
        required = ["PDF_REPORT_JOBS", "PDF_REPORT_LOCK", "pdf_report_jobs_for_import", "pdf_report_job_snapshot", "pdf_report_job_update", "pdf_report_job_log", "pdf_report_job_cancelled"]
        missing = [name for name in required if not hasattr(m, name)]
        if missing:
            self.skip("PDF report job queue helpers", "queue helpers not available in this app build", missing=missing)
            return
        try:
            # Create a minimal reviewer_import row so the job belongs to a real import id.
            now = getattr(m, "utcnow", now_iso)()
            import_id = m.execute("""INSERT INTO reviewer_imports(package_name,package_sha256,package_size,status,imported_by,created_at,object_count,recovered_count,case_name,vault_path,manifest_json,notes_json)
                                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (
                "performance_pdf_queue_test.zip",
                "0" * 64,
                0,
                "imported",
                "performance_evaluator",
                now,
                0,
                0,
                "Performance PDF Queue Test",
                "performance_pdf_queue_test",
                "{}",
                "{}",
            ))
            job_id = "perfjob_" + hashlib.sha256(os.urandom(16)).hexdigest()[:16]
            with m.PDF_REPORT_LOCK:
                m.PDF_REPORT_JOBS[job_id] = {
                    "id": job_id,
                    "import_id": import_id,
                    "status": "queued",
                    "phase": "queued",
                    "current": 0,
                    "total": 3,
                    "progress_percent": 0,
                    "page_ids": [101, 102, 103],
                    "render_mode": "scripts",
                    "created_at": now,
                    "logs": [f"[{now}] performance evaluator queued test job"],
                }
            snap1 = m.pdf_report_job_snapshot(job_id)
            m.pdf_report_job_update(job_id, status="running", phase="screenshotting_page", current=1, progress_percent=33, message="Performance evaluator simulated screenshot")
            m.pdf_report_job_log(job_id, "Performance evaluator simulated progress log entry")
            queue = m.pdf_report_jobs_for_import(import_id)
            snap2 = m.pdf_report_job_snapshot(job_id)
            m.pdf_report_job_update(job_id, status="cancelled", phase="cancel_requested", cancel_requested=True, message="Performance evaluator cancel simulation")
            cancelled = bool(m.pdf_report_job_cancelled(job_id))
            snap3 = m.pdf_report_job_snapshot(job_id)
            artifact = {"import_id": import_id, "job_id": job_id, "initial": snap1, "after_update": snap2, "queue_for_import": queue, "after_cancel": snap3, "cancelled": cancelled}
            self.write_json_artifact("pdf_queue/pdf_job_queue_simulation.json", artifact, "PDF job queue helper simulation with queue/list/snapshot/cancel states", category="pdf_queue")
            if snap1.get("status") == "queued" and snap2.get("status") == "running" and queue and cancelled:
                self.pass_("PDF report job queue helpers", "job queue supports create/list/snapshot/update/log/cancel", import_id=import_id, job_id=job_id, queued_count=len(queue))
            else:
                self.warn("PDF report job queue helpers", "queue helpers ran but returned unexpected states", **artifact)
        except Exception as exc:
            self.warn("PDF report job queue helpers", str(exc), traceback=traceback.format_exc(limit=12))

    def run_local_media_benchmarks(self, *, run_control: bool) -> None:
        # Control run: no sealed media preservation, still blocks display.
        if run_control:
            self.run_local_media_benchmark(label="control_block_no_preservation", sealed_preservation=False)

        # Main run: sealed/background preservation enabled.
        self.run_local_media_benchmark(label="fast_route_background_preservation", sealed_preservation=True)

        if run_control and len(self.benchmarks) >= 2:
            control = next((b for b in self.benchmarks if b.get("label") == "control_block_no_preservation"), None)
            main = next((b for b in self.benchmarks if b.get("label") == "fast_route_background_preservation"), None)
            if control and main:
                comparison = compare_benchmarks(control, main)
                self.write_json_artifact("benchmarks/control_vs_preservation_comparison.json", comparison, "Control vs background preservation benchmark comparison", category="benchmark_comparison")
                overhead = comparison.get("capture_overhead_seconds")
                if overhead is not None and overhead < 10:
                    self.pass_("background preservation overhead bounded", "capture overhead versus no-preservation control was under 10 seconds", **comparison)
                else:
                    self.warn("background preservation overhead", "capture overhead was high or could not be measured", **comparison)

    def run_local_media_benchmark(self, *, label: str, sealed_preservation: bool) -> None:
        m = self.m
        assert m is not None

        server = MediaStressServer(
            image_count=self.asset_count,
            svg_count=self.svg_count,
            video_count=self.video_count,
            delay_ms=self.asset_delay_ms,
        )
        server.start()
        case_id = self.create_case(f"Performance Benchmark {label}", sealed=sealed_preservation)
        self.write_json_artifact(f"local_site/{label}_asset_manifest.json", server.asset_manifest(), f"Local stress-test asset manifest for {label}", category="test_site")
        self.write_bytes_artifact(f"local_site/{label}_index.html", server.index_html().encode("utf-8"), f"HTML served by local stress-test site for {label}", category="test_site", mime="text/html")

        session = None
        status_samples: list[dict[str, Any]] = []
        timings: dict[str, float] = {}
        start_url = server.url("/")
        self.step("local_benchmark_start", f"Starting local media benchmark {label}", label=label, sealed_preservation=sealed_preservation, start_url=start_url, expected_assets=server.expected_request_count)

        try:
            set_app_setting(m, "sealed_media_preservation_enabled", "1" if sealed_preservation else "0")
            t0 = time.perf_counter()
            session = self.start_live_session(case_id=case_id, start_url=start_url, sealed_preservation=sealed_preservation)
            timings["session_start_seconds"] = round(time.perf_counter() - t0, 4)
            sid = getattr(session, "session_id", "")
            self.pass_("live session started: " + label, "headless live browser session started", session_id=sid, seconds=timings["session_start_seconds"], sealed_preservation=sealed_preservation)

            t_wait = time.perf_counter()
            expected_min = max(1, int(server.expected_request_count * 0.60))
            while time.perf_counter() - t_wait < DEFAULT_PAGE_WAIT_SECONDS:
                st = get_preservation_status(m, session)
                status_samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": st})
                if int(st.get("blocked") or 0) >= expected_min:
                    break
                time.sleep(0.4)
            timings["time_to_expected_blocked_seconds"] = round(time.perf_counter() - t_wait, 4)

            # Manual capture should prioritize page capture and not wait for all media.
            t_cap = time.perf_counter()
            page_eid = capture_session(m, session)
            timings["manual_capture_seconds"] = round(time.perf_counter() - t_cap, 4)
            self.pass_("manual capture completed: " + label, "page capture completed", page_evidence_id=page_eid, seconds=timings["manual_capture_seconds"])

            # Poll preservation after capture so we can reconstruct queue/progress behavior.
            t_pres = time.perf_counter()
            last_st = {}
            while time.perf_counter() - t_pres < DEFAULT_PRESERVATION_WAIT_SECONDS:
                last_st = get_preservation_status(m, session)
                status_samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": last_st})
                if not sealed_preservation:
                    break
                pending = int(last_st.get("pending_tasks") or 0)
                outstanding = int(last_st.get("outstanding") or 0)
                # A few failures/skips are recorded in status; don't wait forever if no active pending work.
                if pending == 0 and time.perf_counter() - t_pres > 2:
                    break
                time.sleep(0.75)
            timings["post_capture_preservation_poll_seconds"] = round(time.perf_counter() - t_pres, 4)
            timings["total_live_benchmark_seconds"] = round(time.perf_counter() - t0, 4)

            stats = blocked_media_stats(m, sid)
            type_counts = blocked_media_type_counts(m, sid)
            rows = blocked_media_rows(m, sid)
            self.write_json_artifact(f"benchmarks/{label}_status_samples.json", status_samples, f"Preservation/status polling samples for {label}", category="status_samples")
            self.write_json_artifact(f"benchmarks/{label}_blocked_media_rows.json", rows, f"Blocked-media database rows for {label}", category="db_rows")
            self.write_json_artifact(f"benchmarks/{label}_type_counts.json", type_counts, f"Blocked media file-type counts for {label}", category="db_counts")
            filter_proofs = self.simulate_blocked_media_filters(rows)
            self.write_json_artifact(f"benchmarks/{label}_filter_proofs.json", filter_proofs, f"Positive/negative blocked-media filter reconstruction for {label}", category="filter_proof")

            result = {
                "label": label,
                "sealed_preservation": sealed_preservation,
                "session_id": sid,
                "case_id": case_id,
                "start_url": start_url,
                "expected_asset_requests": server.expected_request_count,
                "timings": timings,
                "final_preservation_status": last_st,
                "blocked_media_stats": stats,
                "file_type_counts": type_counts,
                "filter_proofs": filter_proofs,
                "blocked_rows_count": len(rows),
                "server_request_log_count": len(server.request_log),
                "server_request_counts": server.request_counts(),
                "page_evidence_id": page_eid,
            }
            self.benchmarks.append(result)
            self.write_json_artifact(f"benchmarks/{label}_summary.json", result, f"Benchmark summary for {label}", category="benchmark")

            blocked = int((last_st or {}).get("blocked") or stats.get("total") or 0)
            if blocked >= expected_min:
                self.pass_("blocked-media request throughput: " + label, f"blocked {blocked} requests for local media-heavy page", blocked=blocked, expected_min=expected_min, expected_assets=server.expected_request_count, timings=timings)
            else:
                self.warn("blocked-media request throughput: " + label, f"blocked count lower than expected; page or browser may not have requested every asset", blocked=blocked, expected_min=expected_min, expected_assets=server.expected_request_count)

            if timings["manual_capture_seconds"] <= 20:
                self.pass_("manual capture speed: " + label, "manual capture completed within 20 seconds", seconds=timings["manual_capture_seconds"])
            else:
                self.warn("manual capture speed: " + label, "manual capture exceeded 20 seconds", seconds=timings["manual_capture_seconds"])

            if sealed_preservation:
                downloaded = int(stats.get("downloaded") or 0)
                not_downloaded = int(stats.get("not_downloaded") or 0)
                queue_full = int(stats.get("queue_full") or 0)
                if downloaded > 0:
                    self.pass_("background preservation made progress: " + label, "at least one blocked media item was preserved", downloaded=downloaded, not_downloaded=not_downloaded, queue_full=queue_full)
                else:
                    self.warn("background preservation made progress: " + label, "no blocked media rows were marked downloaded during benchmark window", downloaded=downloaded, not_downloaded=not_downloaded, queue_full=queue_full)
                if queue_full == 0:
                    self.pass_("queue capacity not exceeded: " + label, "no queue-full rows were recorded", queue_limit=self.queue_limit)
                else:
                    self.warn("queue capacity exceeded: " + label, "queue-full rows were recorded; raise queue limit or reduce asset pressure", queue_full=queue_full, queue_limit=self.queue_limit)

        except Exception as exc:
            msg = str(exc)
            if "Executable doesn't exist" in msg or "playwright install" in msg or "Playwright" in msg and "browser" in msg.lower():
                self.skip("local media benchmark: " + label, "Playwright browser executable is not installed in this environment; run `python -m playwright install chromium` to enable live performance benchmark", error=msg[:1000])
            else:
                self.fail("local media benchmark: " + label, msg, traceback=traceback.format_exc(limit=12))
        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    stop_session(m, session)
            server.stop()

    def run_external_url_benchmark(self, url: str) -> None:
        m = self.m
        assert m is not None
        case_id = self.create_case("External URL Performance Benchmark", sealed=True)
        url = normalize_url(url)
        self.step("external_benchmark_start", "Starting optional external URL benchmark", url=url)

        session = None
        status_samples = []
        timings = {}
        try:
            t0 = time.perf_counter()
            session = self.start_live_session(case_id=case_id, start_url=url, sealed_preservation=True)
            timings["session_start_seconds"] = round(time.perf_counter() - t0, 4)
            sid = getattr(session, "session_id", "")
            self.pass_("external live session started", "headless live browser session started for external URL", session_id=sid, url=url, seconds=timings["session_start_seconds"])

            wait_seconds = min(25, DEFAULT_PAGE_WAIT_SECONDS + 5)
            t_wait = time.perf_counter()
            while time.perf_counter() - t_wait < wait_seconds:
                st = get_preservation_status(m, session)
                status_samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": st})
                # Don't try to fully settle arbitrary pages.
                if int(st.get("requests") or 0) >= 10 and time.perf_counter() - t_wait > 3:
                    break
                time.sleep(0.8)

            t_cap = time.perf_counter()
            page_eid = capture_session(m, session)
            timings["manual_capture_seconds"] = round(time.perf_counter() - t_cap, 4)
            self.pass_("external manual capture completed", "page capture completed for external URL", page_evidence_id=page_eid, seconds=timings["manual_capture_seconds"])

            # Quick post-capture poll only; this is not intended to preserve an entire real site.
            t_pres = time.perf_counter()
            while time.perf_counter() - t_pres < 10:
                st = get_preservation_status(m, session)
                status_samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": st})
                if int(st.get("pending_tasks") or 0) == 0 and time.perf_counter() - t_pres > 2:
                    break
                time.sleep(1.0)

            stats = blocked_media_stats(m, sid)
            rows = blocked_media_rows(m, sid)
            type_counts = blocked_media_type_counts(m, sid)
            filter_proofs = self.simulate_blocked_media_filters(rows)
            result = {
                "label": "external_url",
                "url": url,
                "session_id": sid,
                "case_id": case_id,
                "timings": timings,
                "final_preservation_status": status_samples[-1]["status"] if status_samples else {},
                "blocked_media_stats": stats,
                "file_type_counts": type_counts,
                "filter_proofs": filter_proofs,
                "blocked_rows_count": len(rows),
            }
            self.benchmarks.append(result)
            self.write_json_artifact("external_url/status_samples.json", status_samples, "Status polling samples for optional external URL benchmark", category="status_samples")
            self.write_json_artifact("external_url/blocked_media_rows.json", rows, "Blocked-media rows for optional external URL benchmark", category="db_rows")
            self.write_json_artifact("external_url/type_counts.json", type_counts, "Blocked media file-type counts for optional external URL benchmark", category="db_counts")
            self.write_json_artifact("external_url/filter_proofs.json", filter_proofs, "Positive/negative blocked-media filter reconstruction for optional external URL benchmark", category="filter_proof")
            self.write_json_artifact("external_url/summary.json", result, "External URL benchmark summary", category="benchmark")

        except Exception as exc:
            self.warn("external URL benchmark", f"external benchmark failed or could not complete quickly: {exc}", traceback=traceback.format_exc(limit=10), url=url)
        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    stop_session(m, session)

    def run_tor_prewarm_benchmark(self, *, required: bool) -> None:
        m = self.m
        assert m is not None
        if not hasattr(m, "tor_prewarm_background") or not hasattr(m, "tor_prewarm_status"):
            self.skip("Tor prewarm benchmark", "BlindSite under test does not expose tor_prewarm_background/tor_prewarm_status")
            return
        self.step("tor_prewarm_start", "Starting optional Tor prewarm benchmark")
        try:
            set_app_setting(m, "tor_background_prewarm_enabled", "1")
            t0 = time.perf_counter()
            initial = m.tor_prewarm_background("performance-evaluator")
            samples = [{"elapsed": 0, "status": safe_json(initial)}]
            final = {}
            for _ in range(90):
                time.sleep(1)
                final = safe_json(m.tor_prewarm_status())
                samples.append({"elapsed": round(time.perf_counter() - t0, 3), "status": final})
                if not final.get("running"):
                    break
            elapsed = round(time.perf_counter() - t0, 4)
            self.write_json_artifact("tor/tor_prewarm_samples.json", samples, "Tor prewarm status samples", category="tor")
            result = {"elapsed_seconds": elapsed, "initial": safe_json(initial), "final": final}
            self.write_json_artifact("tor/tor_prewarm_summary.json", result, "Tor prewarm benchmark summary", category="tor")
            if final.get("ok"):
                self.pass_("Tor prewarm benchmark", "Tor prewarm completed successfully", **result)
            elif required:
                self.fail("Tor prewarm benchmark", "Tor prewarm did not complete successfully and --tor-required was set", **result)
            else:
                self.warn("Tor prewarm benchmark", "Tor prewarm did not complete successfully; this may be expected if tor.exe is not configured/installed", **result)
        except Exception as exc:
            if required:
                self.fail("Tor prewarm benchmark", str(exc), traceback=traceback.format_exc(limit=12))
            else:
                self.warn("Tor prewarm benchmark", str(exc), traceback=traceback.format_exc(limit=12))

    def start_live_session(self, *, case_id: int, start_url: str, sealed_preservation: bool):
        m = self.m
        assert m is not None
        if not hasattr(m, "start_live_session"):
            raise RuntimeError("BlindSite under test does not expose start_live_session")
        kwargs = {
            "actor": "performance_evaluator",
            "case_id": case_id,
            "start_url": start_url,
            "browser_choice": "chromium",
            "use_tor": False,
            "media_policy": "block_images_video",
            "headless": True,
            "user_agent_profile": "chrome_windows",
            "custom_user_agent": "",
            "download_allowed_media": False,
            "auto_capture": False,
            "settle_before_capture": True,
            "sealed_media_preservation_session": sealed_preservation,
            "capture_auto_scroll_session": False,
        }
        sig = inspect.signature(m.start_live_session)
        filtered = {k: v for k, v in kwargs.items() if k in sig.parameters}
        return m.start_live_session(**filtered)

    def simulate_blocked_media_filters(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Reconstruct positive + negative blocked-media filter behavior from DB rows.

        This mirrors the operational question the UI answers: after a user filters
        for include/exclude extension/type/reason/URL, how many rows are visible
        and which IDs are selectable for retry.
        """
        scenarios = [
            {"name": "include_video_exclude_xml", "include_ext": ["mp4", "m3u8", "mpd"], "exclude_ext": ["xml"], "include_text": [], "exclude_text": []},
            {"name": "exclude_decorative_common", "include_ext": [], "exclude_ext": ["ico", "svg"], "include_text": [], "exclude_text": ["favicon", "logo"]},
            {"name": "not_downloaded_queue_full_excluding_xml", "include_ext": [], "exclude_ext": ["xml"], "include_text": ["queue full"], "exclude_text": []},
        ]
        def ext_for(row: dict[str, Any]) -> str:
            url = str(row.get("media_url") or row.get("url") or "")
            ext = Path(urlparse(url).path).suffix.lower().lstrip(".")
            if ext:
                return ext
            mime = str(row.get("mime_type") or row.get("content_type") or "")
            if "/" in mime:
                return mime.split("/", 1)[-1].split(";", 1)[0].lower()
            return str(row.get("resource_type") or row.get("kind") or "other").lower()
        def row_text(row: dict[str, Any]) -> str:
            return " ".join(str(row.get(k) or "") for k in ("reason", "media_url", "url", "mime_type", "content_type", "resource_type")).lower()
        out = {"total_rows": len(rows), "scenarios": []}
        for sc in scenarios:
            inc_ext = [x.lower().strip(" .") for x in sc["include_ext"]]
            exc_ext = [x.lower().strip(" .") for x in sc["exclude_ext"]]
            inc_text = [x.lower() for x in sc["include_text"]]
            exc_text = [x.lower() for x in sc["exclude_text"]]
            visible = []
            for r in rows:
                e = ext_for(r)
                t = row_text(r)
                if inc_ext and e not in inc_ext:
                    continue
                if exc_ext and e in exc_ext:
                    continue
                if inc_text and not all(term in t for term in inc_text):
                    continue
                if exc_text and any(term in t for term in exc_text):
                    continue
                visible.append({"id": r.get("id"), "ext": e, "downloaded": r.get("downloaded"), "reason": r.get("reason"), "url": r.get("media_url") or r.get("url")})
            out["scenarios"].append({"scenario": sc, "visible_count": len(visible), "visible_ids_sample": [v.get("id") for v in visible[:50]], "extension_counts": count_values([v.get("ext") for v in visible]), "sample_rows": visible[:20]})
        return out

    def write_reports(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = self.report_root / f"blindsite_performance_{stamp}"
        out.mkdir(parents=True, exist_ok=True)
        counts = {s: sum(1 for c in self.checks if c.status == s) for s in ["PASS", "FAIL", "WARN", "SKIP", "INFO"]}
        performance_summary = summarize_benchmarks(self.benchmarks)
        report = {
            "tool": "BlindSite Performance Evaluator",
            "suite_version": APP_VERSION,
            "started_at_utc": self.started_at,
            "finished_at_utc": now_iso(),
            "app_file": str(self.original_app_path),
            "app_sha256": sha256_file(self.original_app_path) if self.original_app_path.exists() else "",
            "result_counts": counts,
            "overall_pass": counts.get("FAIL", 0) == 0,
            "performance_summary": performance_summary,
            "benchmarks": self.benchmarks,
            "reconstruction_steps": self.reconstruction_steps,
            "artifacts": self.artifacts,
            "checks": [c.__dict__ for c in self.checks],
            "important_note": "This is performance/workflow validation, not legal certification or security certification. Use the security evaluator for encryption/custody proof.",
        }
        # Copy artifacts out of temp sandbox into final report folder.
        if self.artifact_dir and self.artifact_dir.exists():
            dest = out / "performance_artifacts"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(self.artifact_dir, dest)
        (out / "performance_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        (out / "performance_report.md").write_text(render_markdown_report(report), encoding="utf-8")

        self.log("\n" + "=" * 72)
        self.log("PERFORMANCE EVALUATION COMPLETE")
        self.log("=" * 72)
        self.log(f"Report folder: {out}")
        self.log(f"Pass: {counts.get('PASS',0)} | Fail: {counts.get('FAIL',0)} | Warn: {counts.get('WARN',0)} | Skip: {counts.get('SKIP',0)}")
        self.log(f"Overall: {'PASS' if report['overall_pass'] else 'FAIL'}")
        if performance_summary:
            self.log("Summary:")
            for k, v in performance_summary.items():
                self.log(f"  {k}: {v}")


class MediaStressServer:
    def __init__(self, *, image_count: int, svg_count: int, video_count: int, delay_ms: int):
        self.image_count = max(0, int(image_count))
        self.svg_count = max(0, int(svg_count))
        self.video_count = max(0, int(video_count))
        self.delay_ms = max(0, int(delay_ms))
        self.httpd: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port = find_free_port()
        self.request_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def expected_request_count(self) -> int:
        # Main images + SVGs + posters + video sources.
        return self.image_count + self.svg_count + (self.video_count * 2)

    def url(self, path: str = "/") -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"http://127.0.0.1:{self.port}{path}"

    def index_html(self) -> str:
        imgs = []
        for i in range(self.image_count):
            imgs.append(f'<img class="perf-img" src="/img/{i:04d}.png" width="16" height="16" alt="img-{i}">')
        for i in range(self.svg_count):
            imgs.append(f'<img class="perf-svg" src="/svg/{i:04d}.svg" width="16" height="16" alt="svg-{i}">')
        videos = []
        for i in range(self.video_count):
            videos.append(f'<video class="perf-video" width="120" height="80" poster="/img/poster_{i:04d}.png" muted><source src="/video/{i:04d}.mp4" type="video/mp4"></video>')
        # Include background-image refs because real dynamic pages use them.
        css_bg = "\n".join([f".bg-{i}{{background-image:url('/img/bg_{i:04d}.png');width:12px;height:12px;display:inline-block}}" for i in range(min(10, self.image_count))])
        bg_divs = "".join([f'<span class="bg-{i}"></span>' for i in range(min(10, self.image_count))])
        return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>BlindSite Performance Local Media Stress Page</title>
<style>
body {{ font-family: Arial, sans-serif; }}
.grid {{ display: grid; grid-template-columns: repeat(20, 18px); gap: 2px; }}
{css_bg}
</style>
</head>
<body>
<h1>BlindSite Performance Local Media Stress Page</h1>
<p id="asset-count">Images: {self.image_count}; SVG: {self.svg_count}; Videos: {self.video_count}; Delay: {self.delay_ms}ms</p>
<div id="backgrounds">{bg_divs}</div>
<div class="grid">
{''.join(imgs)}
</div>
<div id="videos">
{''.join(videos)}
</div>
<script>
window.BLINDSITE_PERF_PAGE_LOADED = true;
</script>
</body>
</html>"""

    def asset_manifest(self) -> dict[str, Any]:
        assets = []
        for i in range(self.image_count):
            assets.append({"path": f"/img/{i:04d}.png", "url": self.url(f"/img/{i:04d}.png"), "mime": "image/png", "sha256": sha256_bytes(tiny_png_bytes())})
        for i in range(min(10, self.image_count)):
            assets.append({"path": f"/img/bg_{i:04d}.png", "url": self.url(f"/img/bg_{i:04d}.png"), "mime": "image/png", "sha256": sha256_bytes(tiny_png_bytes())})
        for i in range(self.video_count):
            assets.append({"path": f"/img/poster_{i:04d}.png", "url": self.url(f"/img/poster_{i:04d}.png"), "mime": "image/png", "sha256": sha256_bytes(tiny_png_bytes())})
            assets.append({"path": f"/video/{i:04d}.mp4", "url": self.url(f"/video/{i:04d}.mp4"), "mime": "video/mp4", "sha256": sha256_bytes(fake_mp4_bytes(i))})
        for i in range(self.svg_count):
            payload = svg_bytes(i)
            assets.append({"path": f"/svg/{i:04d}.svg", "url": self.url(f"/svg/{i:04d}.svg"), "mime": "image/svg+xml", "sha256": sha256_bytes(payload)})
        return {"base_url": self.url("/"), "expected_request_count": self.expected_request_count, "assets": assets}

    def start(self) -> None:
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                parent.handle(self)

            def do_HEAD(self) -> None:
                parent.handle(self, head=True)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="blindsite-perf-media-server")
        self.thread.start()
        wait_for_port("127.0.0.1", self.port, timeout=5)

    def stop(self) -> None:
        if self.httpd:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
            with contextlib.suppress(Exception):
                self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=3)

    def record_request(self, handler: http.server.BaseHTTPRequestHandler, content_type: str, size: int, status: int) -> None:
        with self._lock:
            self.request_log.append({
                "timestamp_utc": now_iso(),
                "path": handler.path,
                "method": handler.command,
                "content_type": content_type,
                "size": size,
                "status": status,
            })

    def request_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._lock:
            for r in self.request_log:
                key = str(r.get("content_type") or "unknown").split(";", 1)[0]
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def handle(self, handler: http.server.BaseHTTPRequestHandler, head: bool = False) -> None:
        path = urlparse(handler.path).path
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000.0)

        if path == "/" or path == "/index.html":
            body = self.index_html().encode("utf-8")
            self.respond(handler, 200, body, "text/html; charset=utf-8", head=head)
            return

        if path.startswith("/img/") and path.endswith(".png"):
            body = tiny_png_bytes()
            self.respond(handler, 200, body, "image/png", head=head)
            return

        if path.startswith("/svg/") and path.endswith(".svg"):
            try:
                idx = int(Path(path).stem)
            except Exception:
                idx = 0
            body = svg_bytes(idx)
            self.respond(handler, 200, body, "image/svg+xml", head=head)
            return

        if path.startswith("/video/") and path.endswith(".mp4"):
            try:
                idx = int(Path(path).stem)
            except Exception:
                idx = 0
            body = fake_mp4_bytes(idx)
            self.respond(handler, 200, body, "video/mp4", head=head)
            return

        body = b"not found"
        self.respond(handler, 404, body, "text/plain", head=head)

    def respond(self, handler: http.server.BaseHTTPRequestHandler, status: int, body: bytes, content_type: str, head: bool = False) -> None:
        self.record_request(handler, content_type, len(body), status)
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        if not head:
            handler.wfile.write(body)


def get_preservation_status(m: Any, session: Any) -> dict[str, Any]:
    try:
        if hasattr(session, "preservation_status"):
            return safe_json(session.preservation_status())
    except Exception:
        pass
    try:
        if hasattr(m, "live_preservation_status_for"):
            return safe_json(m.live_preservation_status_for(session.session_id))
    except Exception:
        pass
    return {
        "session_id": getattr(session, "session_id", ""),
        "requests": getattr(session, "requests", None),
        "blocked": getattr(session, "blocked", None),
        "pending_tasks": None,
        "preserved": getattr(session, "sealed_preserved", None),
        "preserved_bytes": getattr(session, "sealed_preserved_bytes", None),
    }


def capture_session(m: Any, session: Any) -> int:
    if hasattr(session, "capture_current_sync"):
        return int(session.capture_current_sync())
    if hasattr(m, "capture_live_session"):
        return int(m.capture_live_session(session.session_id))
    raise RuntimeError("No capture method available")


def stop_session(m: Any, session: Any) -> None:
    if hasattr(m, "stop_live_session"):
        m.stop_live_session(session.session_id)
    elif hasattr(session, "stop_sync"):
        session.stop_sync()


def blocked_media_stats(m: Any, sid: str) -> dict[str, Any]:
    with contextlib.suppress(Exception):
        if hasattr(m, "blocked_media_session_stats"):
            return safe_json(m.blocked_media_session_stats(sid))
    rows = blocked_media_rows(m, sid)
    return {
        "total": len(rows),
        "downloaded": sum(1 for r in rows if int(r.get("downloaded") or 0) == 1),
        "not_downloaded": sum(1 for r in rows if int(r.get("downloaded") or 0) == 0),
        "queue_full": sum(1 for r in rows if "queue full" in str(r.get("reason") or "").lower()),
        "timeouts": sum(1 for r in rows if "timeout" in str(r.get("reason") or "").lower()),
    }


def blocked_media_type_counts(m: Any, sid: str) -> dict[str, Any]:
    with contextlib.suppress(Exception):
        if hasattr(m, "blocked_media_session_file_type_counts"):
            return safe_json(m.blocked_media_session_file_type_counts(sid))
    counts: dict[str, int] = {}
    for r in blocked_media_rows(m, sid):
        url = str(r.get("media_url") or "")
        ext = Path(urlparse(url).path).suffix.lower().strip(".") or str(r.get("resource_type") or "other")
        counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def blocked_media_rows(m: Any, sid: str) -> list[dict[str, Any]]:
    try:
        rows = m.fetchall("SELECT * FROM blocked_media WHERE session_id=? ORDER BY id ASC", (sid,))
        return [safe_json(dict(r)) for r in rows]
    except Exception:
        return []


def set_app_setting(m: Any, key: str, value: str) -> None:
    if hasattr(m, "set_setting"):
        m.set_setting(key, value)
        return
    now = getattr(m, "utcnow", now_iso)()
    m.execute(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now),
    )


def generate_public_key_for_org_hardseal() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = private.public_key()
    public_pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    fp = sha256_bytes(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    return public_pem, fp


def compare_benchmarks(control: dict[str, Any], main: dict[str, Any]) -> dict[str, Any]:
    ctim = control.get("timings") or {}
    mtim = main.get("timings") or {}
    cc = ctim.get("manual_capture_seconds")
    mc = mtim.get("manual_capture_seconds")
    total_c = ctim.get("total_live_benchmark_seconds")
    total_m = mtim.get("total_live_benchmark_seconds")
    out: dict[str, Any] = {
        "control_label": control.get("label"),
        "main_label": main.get("label"),
        "control_capture_seconds": cc,
        "main_capture_seconds": mc,
        "control_total_seconds": total_c,
        "main_total_seconds": total_m,
    }
    if isinstance(cc, (int, float)) and isinstance(mc, (int, float)):
        out["capture_overhead_seconds"] = round(mc - cc, 4)
        out["capture_overhead_percent_vs_control"] = round(((mc - cc) / cc) * 100, 2) if cc else None
    if isinstance(total_c, (int, float)) and isinstance(total_m, (int, float)):
        out["total_overhead_seconds"] = round(total_m - total_c, 4)
        out["total_overhead_percent_vs_control"] = round(((total_m - total_c) / total_c) * 100, 2) if total_c else None
    return out


def count_values(values: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in values:
        key = str(v or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def summarize_benchmarks(benchmarks: list[dict[str, Any]]) -> dict[str, Any]:
    if not benchmarks:
        return {}
    out: dict[str, Any] = {"benchmark_count": len(benchmarks)}
    for b in benchmarks:
        label = b.get("label", "benchmark")
        timings = b.get("timings") or {}
        stats = b.get("blocked_media_stats") or {}
        out[label] = {
            "manual_capture_seconds": timings.get("manual_capture_seconds"),
            "total_live_benchmark_seconds": timings.get("total_live_benchmark_seconds"),
            "blocked": (b.get("final_preservation_status") or {}).get("blocked") or stats.get("total"),
            "downloaded": stats.get("downloaded"),
            "not_downloaded": stats.get("not_downloaded"),
            "queue_full": stats.get("queue_full"),
            "file_type_counts": b.get("file_type_counts"),
        }
    return out


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = []
    lines.append("# BlindSite Performance Evaluation Report")
    lines.append("")
    lines.append(f"- Suite version: `{report.get('suite_version')}`")
    lines.append(f"- Started: `{report.get('started_at_utc')}`")
    lines.append(f"- Finished: `{report.get('finished_at_utc')}`")
    lines.append(f"- App file: `{report.get('app_file')}`")
    lines.append(f"- App SHA-256: `{report.get('app_sha256')}`")
    lines.append(f"- Overall pass: `{report.get('overall_pass')}`")
    lines.append("")
    lines.append("## Important note")
    lines.append("")
    lines.append("This is performance/workflow validation, not legal certification or security certification. Use the security evaluator for encryption/custody proof.")
    lines.append("")
    counts = report.get("result_counts") or {}
    lines.append("## Result counts")
    lines.append("")
    for k in ["PASS", "FAIL", "WARN", "SKIP", "INFO"]:
        lines.append(f"- {k}: {counts.get(k, 0)}")
    lines.append("")
    lines.append("## Performance summary")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(report.get("performance_summary") or {}, indent=2, default=str)[:12000])
    lines.append("```")
    lines.append("")
    lines.append("## Reconstructable artifacts")
    lines.append("")
    lines.append("The `performance_artifacts/` folder contains the local test-site HTML, asset manifest, status samples, blocked-media rows, benchmark summaries, and optional Tor/external URL samples.")
    lines.append("")
    lines.append("## Checks")
    lines.append("")
    for c in report.get("checks", []):
        lines.append(f"### {c.get('status')}: {c.get('name')}")
        lines.append("")
        if c.get("detail"):
            lines.append(str(c.get("detail")))
            lines.append("")
        ev = c.get("evidence") or {}
        if ev:
            lines.append("```json")
            lines.append(json.dumps(ev, indent=2, default=str)[:6000])
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tiny_png_bytes() -> bytes:
    # 1x1 transparent PNG.
    return base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")


def svg_bytes(i: int) -> bytes:
    color = f"#{(i * 1103515245 + 12345) & 0xFFFFFF:06x}"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16">
<rect width="16" height="16" fill="{color}"/>
<text x="1" y="12" font-size="6" fill="#fff">{i}</text>
</svg>""".encode("utf-8")


def fake_mp4_bytes(i: int) -> bytes:
    # Small MP4-like bytes for performance transfer testing. It is not intended
    # as a media-playback validation; viewer playback belongs in app/manual tests.
    payload = f"BLINDSITE_FAKE_MP4_PERFORMANCE_PAYLOAD_{i}".encode("ascii")
    return b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00\x00\x00\x08free" + payload


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((host, port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {host}:{port}")


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise RuntimeError("URL is required")
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def safe_json(obj: Any) -> Any:
    if isinstance(obj, sqlite3.Row):
        return {k: safe_json(obj[k]) for k in obj.keys()}
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(secret in kl for secret in ("private_key", "password", "passphrase")):
                out[k] = "[REDACTED]"
            else:
                out[k] = safe_json(v)
        return out
    if isinstance(obj, (list, tuple, set)):
        return [safe_json(x) for x in obj]
    if isinstance(obj, bytes):
        return {"bytes_len": len(obj), "sha256": sha256_bytes(obj)}
    if isinstance(obj, Path):
        return str(obj)
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return str(obj)


def prompt(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{msg}{suffix}: ").strip()
    return val if val else default


def prompt_int(msg: str, default: int) -> int:
    while True:
        val = prompt(msg, str(default))
        try:
            return int(val)
        except ValueError:
            print("Please enter a number.")


def prompt_yes_no(msg: str, default: bool = False) -> bool:
    default_text = "Y/n" if default else "y/N"
    while True:
        val = input(f"{msg} [{default_text}]: ").strip().lower()
        if not val:
            return default
        if val in {"y", "yes"}:
            return True
        if val in {"n", "no"}:
            return False
        print("Please answer y or n.")


def interactive_args() -> argparse.Namespace:
    print("\nBlindSite Performance Evaluator")
    print("=" * 38)
    print("This runs a controlled performance/workflow benchmark in a temporary sandbox.")
    print("It does not touch your live BlindSite data folder.\n")
    app = prompt("Path to BlindSite.py", "BlindSite.py")
    report_dir = prompt("Report output folder", "blindsite_performance_reports")
    keep_temp = prompt_yes_no("Keep temporary sandbox after test?", False)
    verbose = prompt_yes_no("Verbose output?", True)
    asset_count = prompt_int("Local test image count", DEFAULT_ASSET_COUNT)
    svg_count = prompt_int("Local test SVG count", DEFAULT_SVG_COUNT)
    video_count = prompt_int("Local test video-like asset count", DEFAULT_VIDEO_COUNT)
    delay_ms = prompt_int("Local asset response delay in ms", DEFAULT_ASSET_DELAY_MS)
    queue_limit = prompt_int("Queue limit to test", DEFAULT_QUEUE_LIMIT)
    max_items = prompt_int("Max preserved items/session to test", DEFAULT_MAX_ITEMS)
    preserve_mode = prompt("Preservation mode fast/balanced/complete", "fast").lower()
    include_control = prompt_yes_no("Run no-preservation control comparison?", True)
    external_url = ""
    if prompt_yes_no("Run optional quick external website benchmark?", False):
        external_url = prompt("External website URL", "")
    tor_test = prompt_yes_no("Run optional Tor prewarm/status benchmark?", False)
    tor_required = False
    if tor_test:
        tor_required = prompt_yes_no("Treat Tor failure as FAIL instead of WARN?", False)
    return argparse.Namespace(
        app=app,
        report_dir=report_dir,
        keep_temp=keep_temp,
        verbose=verbose,
        asset_count=asset_count,
        svg_count=svg_count,
        video_count=video_count,
        asset_delay_ms=delay_ms,
        queue_limit=queue_limit,
        max_items=max_items,
        preserve_mode=preserve_mode,
        include_control=include_control,
        external_url=external_url,
        tor_prewarm_test=tor_test,
        tor_required=tor_required,
    )


def main() -> int:
    if len(sys.argv) == 1:
        args = interactive_args()
    else:
        parser = argparse.ArgumentParser(description="BlindSite performance/workflow evaluator")
        parser.add_argument("--app", default="BlindSite.py", help="Path to BlindSite.py")
        parser.add_argument("--report-dir", default="blindsite_performance_reports")
        parser.add_argument("--keep-temp", action="store_true")
        parser.add_argument("--quiet", action="store_true")
        parser.add_argument("--asset-count", type=int, default=DEFAULT_ASSET_COUNT)
        parser.add_argument("--svg-count", type=int, default=DEFAULT_SVG_COUNT)
        parser.add_argument("--video-count", type=int, default=DEFAULT_VIDEO_COUNT)
        parser.add_argument("--asset-delay-ms", type=int, default=DEFAULT_ASSET_DELAY_MS)
        parser.add_argument("--queue-limit", type=int, default=DEFAULT_QUEUE_LIMIT)
        parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
        parser.add_argument("--preserve-mode", default="fast", choices=["fast", "balanced", "complete"])
        parser.add_argument("--no-control", action="store_true", help="Skip no-preservation control comparison")
        parser.add_argument("--external-url", default="", help="Optional quick real website benchmark URL")
        parser.add_argument("--tor-prewarm-test", action="store_true", help="Optional Tor prewarm/status benchmark")
        parser.add_argument("--tor-required", action="store_true", help="Treat Tor prewarm failure as FAIL instead of WARN")
        args = parser.parse_args()
        args.verbose = not args.quiet
        args.include_control = not args.no_control

    evaluator = PerformanceEvaluator(
        app_path=Path(args.app),
        report_root=Path(args.report_dir),
        keep_temp=bool(args.keep_temp),
        verbose=bool(args.verbose),
        asset_count=int(args.asset_count),
        svg_count=int(args.svg_count),
        video_count=int(args.video_count),
        asset_delay_ms=int(args.asset_delay_ms),
        queue_limit=int(args.queue_limit),
        max_items=int(args.max_items),
        preserve_mode=str(args.preserve_mode),
    )
    evaluator.run(
        external_url=str(args.external_url or ""),
        run_control=bool(args.include_control),
        run_tor_prewarm=bool(args.tor_prewarm_test),
        tor_required=bool(args.tor_required),
    )
    return 1 if any(c.status == "FAIL" for c in evaluator.checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())