"""Operações de domínio do ACR.

Três primitivas:

* :func:`list_repositories` — catálogo paginado via ``/v2/_catalog`` com
  filtros glob (include/exclude).
* :func:`list_recent_manifests` — top-N manifests mais recentes por repo via
  ``/acr/v1/{repo}/_manifests?orderby=timedesc``; traz o ``lastUpdateTime``
  (data de push) direto, sem precisar abrir cada manifest.
* :func:`resolve_image_config` — dado um manifest digest, resolve multi-arch
  pelo platform selector e retorna o image config (onde moram as labels e
  os ``rootfs.diff_ids``).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from acr_audit.client import MANIFEST_ACCEPT, RegistryClient


@dataclass(frozen=True, slots=True)
class ManifestInfo:
    """Metadados resumidos de um manifest (vindos de /acr/v1/.../_manifests)."""

    digest: str
    tags: tuple[str, ...]
    pushed_at: str | None  # ISO 8601 do lastUpdateTime; createdTime como fallback


def list_repositories(
    client: RegistryClient,
    *,
    exclude: Iterable[str] = (),
    include: Iterable[str] = (),
) -> Iterator[str]:
    """Pagina ``/v2/_catalog`` e filtra por globs (``fnmatch``).

    ``include`` vazio = tudo é incluído. ``exclude`` sempre tem precedência.
    """
    exclude_list = list(exclude)
    include_list = list(include)
    scope = "registry:catalog:*"
    for repo in client.paginate("/v2/_catalog?n=500", scope=scope, items_key="repositories"):
        if not isinstance(repo, str):
            continue
        if _matches_any(repo, exclude_list):
            continue
        if include_list and not _matches_any(repo, include_list):
            continue
        yield repo


def list_recent_manifests(
    client: RegistryClient,
    repo: str,
    top: int,
) -> list[ManifestInfo]:
    """Retorna os ``top`` manifests **com tag** mais recentes do repo.

    Manifests sem tag são ignorados (tipicamente artefatos de scan do Defender,
    SBOM attestations, ou órfãos). Como ninguém puxa esses via ``FROM``, não
    fazem parte do universo auditável. Paginação continua até acumularmos
    ``top`` manifests tagged ou acabarem os resultados.

    Usa ``/acr/v1/{repo}/_manifests?orderby=timedesc&n=100``.
    """
    if top <= 0:
        return []
    path = f"/acr/v1/{repo}/_manifests?orderby=timedesc&n=100"
    scope = _repo_scope(repo)
    out: list[ManifestInfo] = []
    for raw in client.paginate(path, scope=scope, items_key="manifests"):
        digest = raw.get("digest")
        if not isinstance(digest, str):
            continue
        tags_raw = raw.get("tags") or []
        tags = tuple(t for t in tags_raw if isinstance(t, str))
        if not tags:
            continue
        pushed = raw.get("lastUpdateTime") or raw.get("createdTime")
        out.append(ManifestInfo(digest=digest, tags=tags, pushed_at=pushed))
        if len(out) >= top:
            break
    return out


def resolve_image_config(
    client: RegistryClient,
    repo: str,
    manifest_digest: str,
    platform: str = "linux/amd64",
) -> dict[str, Any] | None:
    """Resolve o image config JSON.

    Se o manifest for um índice multi-arch, segue o manifest da plataforma
    pedida. Retorna ``None`` quando nenhum manifest da plataforma existe
    (image index só com outras arquiteturas, por exemplo).
    """
    want_os, want_arch = _parse_platform(platform)
    scope = _repo_scope(repo)
    manifest, _ = client.get_json(
        f"/v2/{repo}/manifests/{manifest_digest}",
        scope=scope,
        accept=MANIFEST_ACCEPT,
    )
    if _is_image_index(manifest):
        target = _pick_platform_manifest(manifest, want_os, want_arch)
        if target is None:
            return None
        return resolve_image_config(client, repo, target, platform)

    config_digest = _nested_get(manifest, "config", "digest")
    if not isinstance(config_digest, str):
        return None
    config, _ = client.get_json(f"/v2/{repo}/blobs/{config_digest}", scope=scope)
    return config


def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def _repo_scope(repo: str) -> str:
    return f"repository:{repo}:metadata_read,pull"


def _parse_platform(platform: str) -> tuple[str, str]:
    if "/" not in platform:
        raise ValueError(f"plataforma inválida: {platform!r} (esperado os/arch)")
    os_, arch = platform.split("/", 1)
    return os_.strip(), arch.strip()


def _is_image_index(manifest: dict[str, Any]) -> bool:
    media = manifest.get("mediaType", "")
    if "index" in media or "manifest.list" in media:
        return True
    # Alguns manifests não vêm com mediaType — detectamos por estrutura.
    return "manifests" in manifest and "config" not in manifest


def _pick_platform_manifest(index: dict[str, Any], want_os: str, want_arch: str) -> str | None:
    for entry in index.get("manifests", []):
        platform = entry.get("platform") or {}
        if platform.get("os") == want_os and platform.get("architecture") == want_arch:
            digest = entry.get("digest")
            if isinstance(digest, str):
                return digest
    return None


def _nested_get(data: dict[str, Any], *keys: str) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur
