"""Entry point da POC de auditoria de governança de imagens no ACR.

Uso:
    python3 audit.py --acr <nome-ou-fqdn>
                     --label com.empresa.base-image
                     --label com.empresa.pipeline=governed
                     --exclude-repo 'base-images/*'
                     --top 10
                     --output report.json

Reusa a sessão ativa do ``az login`` (não precisa de service principal nem
admin user no ACR). O usuário precisa ter permissão de pull no registry.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from acr_audit.auth import TokenProvider, get_refresh_token, normalize_fqdn
from acr_audit.client import RegistryClient
from acr_audit.registry import (
    list_recent_manifests,
    list_repositories,
    resolve_image_config,
)
from acr_audit.report import ScanMeta, Violation, write_json
from acr_audit.rules import LabelRequirement, check_labels, parse_label


@dataclass(slots=True)
class AuditOptions:
    acr_fqdn: str
    required_labels: list[LabelRequirement]
    required_labels_raw: list[str]
    exclude_repos: list[str] = field(default_factory=list)
    include_repos: list[str] = field(default_factory=list)
    top_per_repo: int = 10
    platform: str = "linux/amd64"
    workers: int = 16


@dataclass(slots=True)
class AuditResult:
    meta: ScanMeta
    violations: list[Violation]
    errors: list[dict[str, Any]]


def audit_repo(
    client: RegistryClient,
    repo: str,
    required: list[LabelRequirement],
    top: int,
    platform: str,
) -> tuple[list[Violation], list[dict[str, Any]], int]:
    """Audita um único repo. Retorna ``(violations, errors, images_scanned)``."""
    violations: list[Violation] = []
    errors: list[dict[str, Any]] = []
    try:
        manifests = list_recent_manifests(client, repo, top=top)
    except Exception as err:
        return [], [{"repo": repo, "stage": "list_manifests", "error": str(err)}], 0

    scanned = 0
    for manifest in manifests:
        scanned += 1
        try:
            config = resolve_image_config(client, repo, manifest.digest, platform)
            if config is None:
                continue  # nenhum manifest para a plataforma pedida
            labels = (config.get("config") or {}).get("Labels") or {}
            missing = check_labels(labels, required)
            if missing:
                violations.append(
                    Violation(
                        repo=repo,
                        tags=list(manifest.tags),
                        digest=manifest.digest,
                        pushed_at=manifest.pushed_at,
                        missing_labels=missing,
                    )
                )
        except Exception as err:
            errors.append(
                {
                    "repo": repo,
                    "digest": manifest.digest,
                    "stage": "inspect",
                    "error": str(err),
                }
            )
    return violations, errors, scanned


def run_audit(
    client: RegistryClient,
    options: AuditOptions,
    *,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> AuditResult:
    """Orquestra o scan de todos os repos. Determinístico quanto à inclusão de resultados."""
    started = time.monotonic()
    repos = list(
        list_repositories(
            client,
            exclude=options.exclude_repos,
            include=options.include_repos,
        )
    )

    violations: list[Violation] = []
    errors: list[dict[str, Any]] = []
    images_scanned = 0
    completed = 0

    with ThreadPoolExecutor(max_workers=options.workers) as pool:
        futures = {
            pool.submit(
                audit_repo,
                client,
                repo,
                options.required_labels,
                options.top_per_repo,
                options.platform,
            ): repo
            for repo in repos
        }
        for fut in as_completed(futures):
            repo = futures[fut]
            try:
                vs, errs, scanned = fut.result()
            except Exception as err:
                errors.append({"repo": repo, "stage": "worker", "error": str(err)})
                completed += 1
                continue
            violations.extend(vs)
            errors.extend(errs)
            images_scanned += scanned
            completed += 1
            if on_progress is not None:
                on_progress(completed, len(repos), len(violations))

    meta = ScanMeta(
        acr=options.acr_fqdn,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        duration_s=round(time.monotonic() - started, 2),
        repos_total=len(repos),
        repos_scanned=len(repos),
        images_scanned=images_scanned,
        violations_count=len(violations),
        errors_count=len(errors),
        required_labels=list(options.required_labels_raw),
        excluded_repos=list(options.exclude_repos),
        included_repos=list(options.include_repos),
        top_per_repo=options.top_per_repo,
        platform=options.platform,
    )
    return AuditResult(meta=meta, violations=violations, errors=errors)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="audit.py",
        description="Audita imagens no ACR em busca de labels de governança.",
    )
    ap.add_argument(
        "--acr",
        required=True,
        help="Nome do ACR ('acme' ou 'acme.azurecr.io').",
    )
    ap.add_argument(
        "--label",
        action="append",
        required=True,
        metavar="KEY[=VALUE]",
        help="Label exigida. KEY só exige existência; KEY=VALUE exige valor. Repetível.",
    )
    ap.add_argument(
        "--exclude-repo",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob de repos a ignorar (ex.: 'base-images/*'). Repetível.",
    )
    ap.add_argument(
        "--include-repo",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob de repos a incluir (default: todos). Repetível.",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=10,
        help="Número das imagens mais recentes por repo a inspecionar. Padrão 10.",
    )
    ap.add_argument(
        "--platform",
        default="linux/amd64",
        help="Plataforma a inspecionar em image index multi-arch. Padrão linux/amd64.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Threads paralelas (uma por repo). Padrão 16.",
    )
    ap.add_argument(
        "--output",
        default="audit-report.json",
        help="Arquivo JSON de saída. Padrão audit-report.json.",
    )
    ap.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit code 1 se houver pelo menos uma violação.",
    )
    return ap.parse_args(argv)


def _default_client_builder(fqdn: str) -> RegistryClient:
    refresh_token = get_refresh_token(fqdn)
    return RegistryClient(fqdn=fqdn, token_provider=TokenProvider(fqdn, refresh_token))


def main(
    argv: list[str] | None = None,
    *,
    client_builder: Callable[[str], RegistryClient] = _default_client_builder,
    stderr: Any = sys.stderr,
) -> int:
    args = parse_args(argv)
    fqdn = normalize_fqdn(args.acr)
    options = AuditOptions(
        acr_fqdn=fqdn,
        required_labels=[parse_label(raw) for raw in args.label],
        required_labels_raw=list(args.label),
        exclude_repos=list(args.exclude_repo),
        include_repos=list(args.include_repo),
        top_per_repo=args.top,
        platform=args.platform,
        workers=args.workers,
    )

    print(f"[*] Autenticando em {fqdn} (via az login)...", file=stderr)
    client = client_builder(fqdn)

    print("[*] Varrendo catálogo e inspecionando labels...", file=stderr)

    def on_progress(done: int, total: int, viols: int) -> None:
        if done == total or done % 50 == 0:
            print(f"    {done}/{total} repos ({viols} violações até agora)", file=stderr)

    result = run_audit(client, options, on_progress=on_progress)

    write_json(args.output, result.meta, result.violations, result.errors)
    print(
        f"[*] {result.meta.images_scanned} imagens inspecionadas em "
        f"{result.meta.repos_scanned} repos ({result.meta.duration_s}s).",
        file=stderr,
    )
    print(
        f"[*] {result.meta.violations_count} violações, "
        f"{result.meta.errors_count} erros. Relatório: {args.output}",
        file=stderr,
    )

    if args.fail_on_violation and result.violations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
