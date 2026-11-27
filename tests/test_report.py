"""Regression tests de acr_audit.report."""

from __future__ import annotations

import json
from pathlib import Path

from acr_audit.report import ScanMeta, Violation, build_report, write_json


def make_meta() -> ScanMeta:
    return ScanMeta(
        acr="acme.azurecr.io",
        scanned_at="2026-11-27T13:45:00+00:00",
        duration_s=12.3,
        repos_total=100,
        repos_scanned=80,
        images_scanned=400,
        violations_count=1,
        errors_count=0,
        required_labels=["com.empresa.base-image"],
        excluded_repos=["base-images/*"],
        top_per_repo=5,
        platform="linux/amd64",
    )


def test_build_report_structure() -> None:
    meta = make_meta()
    violation = Violation(
        repo="teamx/api",
        tags=["v1", "latest"],
        digest="sha256:abc",
        pushed_at="2026-11-20T10:00:00Z",
        missing_labels=["com.empresa.base-image"],
    )
    report = build_report(meta, [violation], errors=[])
    assert set(report) == {"scan", "violations", "errors"}
    assert report["scan"]["acr"] == "acme.azurecr.io"
    assert report["violations"][0]["repo"] == "teamx/api"
    assert report["violations"][0]["missing_labels"] == ["com.empresa.base-image"]


def test_build_report_includes_errors() -> None:
    meta = make_meta()
    errors = [{"repo": "broken", "stage": "list_manifests", "error": "HTTP 500"}]
    report = build_report(meta, [], errors)
    assert report["errors"] == errors


def test_write_json_round_trip(tmp_path: Path) -> None:
    meta = make_meta()
    violation = Violation(
        repo="teamx/api",
        tags=["v1"],
        digest="sha256:abc",
        pushed_at=None,
        missing_labels=["x", "y!=z"],
    )
    out = tmp_path / "report.json"
    write_json(str(out), meta, [violation], errors=[])

    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["scan"]["acr"] == "acme.azurecr.io"
    assert loaded["violations"] == [
        {
            "repo": "teamx/api",
            "tags": ["v1"],
            "digest": "sha256:abc",
            "pushed_at": None,
            "missing_labels": ["x", "y!=z"],
        }
    ]
    assert loaded["errors"] == []


def test_write_json_file_ends_with_newline(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    write_json(str(out), make_meta(), [], errors=[])
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_write_json_preserves_utf8(tmp_path: Path) -> None:
    meta = make_meta()
    violation = Violation(
        repo="açaí/áudio",
        tags=["v1"],
        digest="sha256:a",
        pushed_at=None,
        missing_labels=["ção"],
    )
    out = tmp_path / "report.json"
    write_json(str(out), meta, [violation], errors=[])
    content = out.read_text(encoding="utf-8")
    assert "açaí/áudio" in content
    assert "ção" in content
