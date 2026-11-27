"""Regression tests de acr_audit.registry.

Usamos um FakeClient que implementa a mesma superfície de RegistryClient
(paginate + get_json), mas devolve dados pré-roteirizados.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from acr_audit.registry import (
    ManifestInfo,
    list_recent_manifests,
    list_repositories,
    resolve_image_config,
)


class FakeClient:
    def __init__(
        self,
        pages: dict[str, list[Any]] | None = None,
        gets: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._pages = pages or {}
        self._gets = gets or {}
        self.paginate_calls: list[tuple[str, str]] = []
        self.get_calls: list[tuple[str, str]] = []

    def paginate(
        self, path: str, scope: str, items_key: str, *, limit: int | None = None
    ) -> Iterator[Any]:
        self.paginate_calls.append((path, scope))
        items = list(self._pages.get(path, []))
        if limit is not None:
            items = items[:limit]
        yield from items

    def get_json(
        self, path: str, scope: str, *, accept: str = "application/json"
    ) -> tuple[dict[str, Any], None]:
        self.get_calls.append((path, scope))
        if path not in self._gets:
            raise AssertionError(f"get_json inesperado: {path}")
        return self._gets[path], None


class TestListRepositories:
    def test_yields_all_without_filters(self) -> None:
        client = FakeClient(pages={"/v2/_catalog?n=500": ["a", "b", "c"]})
        assert list(list_repositories(client)) == ["a", "b", "c"]
        assert client.paginate_calls == [("/v2/_catalog?n=500", "registry:catalog:*")]

    def test_exclude_filters_out(self) -> None:
        client = FakeClient(pages={"/v2/_catalog?n=500": ["a", "base-images/x", "b"]})
        assert list(list_repositories(client, exclude=["base-images/*"])) == ["a", "b"]

    def test_exclude_matches_nested_paths(self) -> None:
        """fnmatch com '*' casa '/' também — importante pra repos aninhados."""
        pages = {"/v2/_catalog?n=500": ["base-images/foo", "base-images/team/api", "other"]}
        client = FakeClient(pages=pages)
        assert list(list_repositories(client, exclude=["base-images/*"])) == ["other"]

    def test_include_restricts(self) -> None:
        pages = {"/v2/_catalog?n=500": ["teamx/api", "teamy/api", "random"]}
        client = FakeClient(pages=pages)
        result = list(list_repositories(client, include=["teamx/*", "teamy/*"]))
        assert result == ["teamx/api", "teamy/api"]

    def test_exclude_wins_over_include(self) -> None:
        pages = {"/v2/_catalog?n=500": ["teamx/api", "teamx/base"]}
        client = FakeClient(pages=pages)
        result = list(list_repositories(client, include=["teamx/*"], exclude=["teamx/base"]))
        assert result == ["teamx/api"]

    def test_skips_non_string_items(self) -> None:
        client = FakeClient(pages={"/v2/_catalog?n=500": ["a", 42, None, "b"]})
        assert list(list_repositories(client)) == ["a", "b"]


class TestListRecentManifests:
    def test_zero_top_returns_empty(self) -> None:
        client = FakeClient()
        assert list_recent_manifests(client, "repo", top=0) == []

    def test_maps_fields(self) -> None:
        pages = {
            "/acr/v1/myrepo/_manifests?orderby=timedesc&n=5": [
                {
                    "digest": "sha256:aaa",
                    "tags": ["v1", "latest"],
                    "lastUpdateTime": "2026-11-20T10:00:00Z",
                    "createdTime": "2026-11-19T10:00:00Z",
                },
                {
                    "digest": "sha256:bbb",
                    "tags": [],
                    "createdTime": "2026-11-18T10:00:00Z",
                },
            ],
        }
        client = FakeClient(pages=pages)
        result = list_recent_manifests(client, "myrepo", top=5)
        assert result == [
            ManifestInfo(
                digest="sha256:aaa",
                tags=("v1", "latest"),
                pushed_at="2026-11-20T10:00:00Z",
            ),
            ManifestInfo(
                digest="sha256:bbb",
                tags=(),
                pushed_at="2026-11-18T10:00:00Z",
            ),
        ]

    def test_prefers_last_update_over_created(self) -> None:
        pages = {
            "/acr/v1/r/_manifests?orderby=timedesc&n=1": [
                {
                    "digest": "sha256:x",
                    "lastUpdateTime": "2026-11-20",
                    "createdTime": "2020-01-01",
                },
            ],
        }
        client = FakeClient(pages=pages)
        [m] = list_recent_manifests(client, "r", top=1)
        assert m.pushed_at == "2026-11-20"

    def test_page_size_capped_at_100(self) -> None:
        pages = {"/acr/v1/r/_manifests?orderby=timedesc&n=100": []}
        client = FakeClient(pages=pages)
        list_recent_manifests(client, "r", top=5000)
        assert client.paginate_calls[0][0] == "/acr/v1/r/_manifests?orderby=timedesc&n=100"

    def test_requires_repo_scope(self) -> None:
        pages = {"/acr/v1/r/_manifests?orderby=timedesc&n=5": []}
        client = FakeClient(pages=pages)
        list_recent_manifests(client, "r", top=5)
        assert client.paginate_calls[0][1] == "repository:r:metadata_read,pull"

    def test_skips_entries_without_digest(self) -> None:
        pages = {
            "/acr/v1/r/_manifests?orderby=timedesc&n=2": [
                {"tags": ["x"]},
                {"digest": "sha256:ok"},
            ],
        }
        client = FakeClient(pages=pages)
        result = list_recent_manifests(client, "r", top=2)
        assert [m.digest for m in result] == ["sha256:ok"]


class TestResolveImageConfig:
    def test_single_arch_returns_config_blob(self) -> None:
        gets = {
            "/v2/r/manifests/sha256:m": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": "sha256:c"},
            },
            "/v2/r/blobs/sha256:c": {"config": {"Labels": {"x": "1"}}},
        }
        client = FakeClient(gets=gets)
        result = resolve_image_config(client, "r", "sha256:m")
        assert result == {"config": {"Labels": {"x": "1"}}}

    def test_multi_arch_picks_platform_amd64(self) -> None:
        gets = {
            "/v2/r/manifests/sha256:idx": {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
                    {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
                ],
            },
            "/v2/r/manifests/sha256:amd": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": "sha256:c-amd"},
            },
            "/v2/r/blobs/sha256:c-amd": {"architecture": "amd64"},
        }
        client = FakeClient(gets=gets)
        result = resolve_image_config(client, "r", "sha256:idx", platform="linux/amd64")
        assert result == {"architecture": "amd64"}

    def test_multi_arch_platform_absent_returns_none(self) -> None:
        gets = {
            "/v2/r/manifests/sha256:idx": {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
                ],
            },
        }
        client = FakeClient(gets=gets)
        assert resolve_image_config(client, "r", "sha256:idx", platform="linux/amd64") is None

    def test_detects_index_without_mediatype(self) -> None:
        """Manifests legados podem não ter mediaType; detectamos pela estrutura."""
        gets = {
            "/v2/r/manifests/sha256:idx": {
                "manifests": [
                    {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
                ],
            },
            "/v2/r/manifests/sha256:amd": {"config": {"digest": "sha256:c"}},
            "/v2/r/blobs/sha256:c": {"ok": True},
        }
        client = FakeClient(gets=gets)
        assert resolve_image_config(client, "r", "sha256:idx") == {"ok": True}

    def test_missing_config_digest_returns_none(self) -> None:
        gets = {"/v2/r/manifests/sha256:m": {"mediaType": "image.manifest"}}
        client = FakeClient(gets=gets)
        assert resolve_image_config(client, "r", "sha256:m") is None

    def test_invalid_platform_raises(self) -> None:
        client = FakeClient()
        with pytest.raises(ValueError, match="plataforma inválida"):
            resolve_image_config(client, "r", "sha256:x", platform="linux-amd64")
