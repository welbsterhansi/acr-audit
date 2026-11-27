"""Smoke test end-to-end do audit.py.

Mockamos o RegistryClient inteiro (via duck typing) para exercitar o fluxo
completo sem rede e sem az CLI.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import audit
from acr_audit.client import RegistryClient


class ScriptedClient:
    """Implementa a superfície usada por registry.py (paginate + get_json)."""

    def __init__(
        self,
        pages: dict[str, list[Any]],
        gets: dict[str, dict[str, Any]],
    ) -> None:
        self._pages = pages
        self._gets = gets

    def paginate(
        self, path: str, scope: str, items_key: str, *, limit: int | None = None
    ) -> Iterator[Any]:
        items = list(self._pages.get(path, []))
        if limit is not None:
            items = items[:limit]
        yield from items

    def get_json(
        self, path: str, scope: str, *, accept: str = "application/json"
    ) -> tuple[dict[str, Any], None]:
        if path not in self._gets:
            raise AssertionError(f"get_json inesperado em smoke: {path}")
        return self._gets[path], None


def make_e2e_client() -> ScriptedClient:
    """Dois repos auditáveis, um bypass e um conforme, mais um repo base (excluído)."""
    pages = {
        "/v2/_catalog?n=500": [
            "base-images/ubi9",
            "teamx/api",
            "teamy/legacy",
        ],
        "/acr/v1/teamx/api/_manifests?orderby=timedesc&n=2": [
            {
                "digest": "sha256:good",
                "tags": ["v2"],
                "lastUpdateTime": "2026-11-26T12:00:00Z",
            },
            {
                "digest": "sha256:bypass",
                "tags": ["v1"],
                "lastUpdateTime": "2026-11-20T08:00:00Z",
            },
        ],
        "/acr/v1/teamy/legacy/_manifests?orderby=timedesc&n=2": [
            {
                "digest": "sha256:legacy",
                "tags": ["old"],
                "lastUpdateTime": "2024-01-01T00:00:00Z",
            },
        ],
    }
    gets = {
        "/v2/teamx/api/manifests/sha256:good": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg-good"},
        },
        "/v2/teamx/api/blobs/sha256:cfg-good": {
            "config": {"Labels": {"com.empresa.base-image": "ubi9"}},
        },
        "/v2/teamx/api/manifests/sha256:bypass": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg-bypass"},
        },
        "/v2/teamx/api/blobs/sha256:cfg-bypass": {
            "config": {"Labels": {"some.other.label": "x"}},
        },
        "/v2/teamy/legacy/manifests/sha256:legacy": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:cfg-legacy"},
        },
        "/v2/teamy/legacy/blobs/sha256:cfg-legacy": {
            "config": {"Labels": None},
        },
    }
    return ScriptedClient(pages=pages, gets=gets)


def test_main_writes_report_with_violations(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    stderr = io.StringIO()

    exit_code = audit.main(
        [
            "--acr",
            "acme",
            "--label",
            "com.empresa.base-image",
            "--exclude-repo",
            "base-images/*",
            "--top",
            "2",
            "--workers",
            "4",
            "--output",
            str(out),
            "--fail-on-violation",
        ],
        client_builder=lambda _fqdn: make_e2e_client(),  # type: ignore[arg-type]
        stderr=stderr,
    )

    assert exit_code == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["scan"]["acr"] == "acme.azurecr.io"
    assert data["scan"]["excluded_repos"] == ["base-images/*"]
    assert data["scan"]["top_per_repo"] == 2
    assert data["scan"]["violations_count"] == 2

    violations_by_repo = {(v["repo"], v["digest"]): v for v in data["violations"]}
    assert ("teamx/api", "sha256:bypass") in violations_by_repo
    assert ("teamy/legacy", "sha256:legacy") in violations_by_repo
    bypass = violations_by_repo[("teamx/api", "sha256:bypass")]
    assert bypass["missing_labels"] == ["com.empresa.base-image"]
    assert bypass["pushed_at"] == "2026-11-20T08:00:00Z"


def test_main_exits_zero_without_fail_flag(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    code = audit.main(
        [
            "--acr",
            "acme",
            "--label",
            "com.empresa.base-image",
            "--exclude-repo",
            "base-images/*",
            "--top",
            "2",
            "--output",
            str(out),
        ],
        client_builder=lambda _fqdn: make_e2e_client(),  # type: ignore[arg-type]
        stderr=io.StringIO(),
    )
    assert code == 0


def test_main_fail_flag_only_triggers_on_violation(tmp_path: Path) -> None:
    pages = {"/v2/_catalog?n=500": []}
    client = ScriptedClient(pages=pages, gets={})
    out = tmp_path / "report.json"
    code = audit.main(
        [
            "--acr",
            "acme",
            "--label",
            "com.empresa.base-image",
            "--output",
            str(out),
            "--fail-on-violation",
        ],
        client_builder=lambda _fqdn: client,  # type: ignore[arg-type]
        stderr=io.StringIO(),
    )
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["scan"]["violations_count"] == 0


def test_parse_args_requires_label() -> None:
    with pytest.raises(SystemExit):
        audit.parse_args(["--acr", "foo"])


def test_parse_args_defaults() -> None:
    ns = audit.parse_args(["--acr", "foo", "--label", "x"])
    assert ns.top == 10
    assert ns.platform == "linux/amd64"
    assert ns.workers == 16
    assert ns.output == "audit-report.json"


def test_audit_repo_records_inspect_error() -> None:
    class ExplodingClient:
        def paginate(self, *_a: Any, **_kw: Any) -> Iterator[dict[str, Any]]:
            yield {"digest": "sha256:x", "tags": ["v1"], "lastUpdateTime": "2026-01-01"}

        def get_json(self, *_a: Any, **_kw: Any) -> tuple[dict[str, Any], None]:
            raise RuntimeError("boom")

    required = [audit.parse_label("com.empresa.base-image")]
    violations, errors, scanned = audit.audit_repo(
        ExplodingClient(),  # type: ignore[arg-type]
        "r",
        required,
        top=5,
        platform="linux/amd64",
    )
    assert violations == []
    assert scanned == 1
    assert errors == [{"repo": "r", "digest": "sha256:x", "stage": "inspect", "error": "boom"}]


def test_audit_repo_records_list_error() -> None:
    class Broken:
        def paginate(self, *_a: Any, **_kw: Any) -> Iterator[dict[str, Any]]:
            raise RuntimeError("catalog down")
            yield  # pragma: no cover

        def get_json(self, *_a: Any, **_kw: Any) -> tuple[dict[str, Any], None]:
            raise AssertionError("não deveria ser chamado")

    violations, errors, scanned = audit.audit_repo(
        Broken(),  # type: ignore[arg-type]
        "r",
        [],
        top=5,
        platform="linux/amd64",
    )
    assert violations == []
    assert scanned == 0
    assert errors == [{"repo": "r", "stage": "list_manifests", "error": "catalog down"}]


def test_registryclient_type_hint_still_resolves() -> None:
    """Protege contra regressão de imports entre audit.py e acr_audit.*."""
    assert RegistryClient is not None
