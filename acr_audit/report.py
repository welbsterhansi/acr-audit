"""Modelos do relatório e serialização JSON.

Relatório enxuto: só o que o leitor precisa pra agir — qual imagem bypassou
qual governança, quando foi pushada, e um sumário do scan.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Violation:
    repo: str
    tags: list[str]
    digest: str
    pushed_at: str | None
    missing_labels: list[str]


@dataclass(slots=True)
class ScanMeta:
    acr: str
    scanned_at: str
    duration_s: float
    repos_total: int
    repos_scanned: int
    images_scanned: int
    violations_count: int
    errors_count: int
    required_labels: list[str]
    excluded_repos: list[str] = field(default_factory=list)
    included_repos: list[str] = field(default_factory=list)
    top_per_repo: int = 0
    platform: str = ""


def build_report(
    meta: ScanMeta,
    violations: list[Violation],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Retorna o dict do relatório pronto pra serialização."""
    return {
        "scan": asdict(meta),
        "violations": [asdict(v) for v in violations],
        "errors": errors,
    }


def write_json(
    path: str,
    meta: ScanMeta,
    violations: list[Violation],
    errors: list[dict[str, Any]],
) -> None:
    """Escreve o relatório em ``path`` como JSON indentado."""
    payload = build_report(meta, violations, errors)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)
        fh.write("\n")
