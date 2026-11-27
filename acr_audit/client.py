"""Cliente HTTP para a API do Azure Container Registry.

Encapsula autenticação via ``TokenProvider``, retry com backoff exponencial
em 429/5xx, e paginação pelo header ``Link: <...>; rel="next"`` da Docker
Registry API v2.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any, Protocol

DEFAULT_ACCEPT = "application/json"
MANIFEST_ACCEPT = ",".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 5
_DEFAULT_TIMEOUT = 30


class TokenProvider(Protocol):
    """Fornece access tokens escopados. Implementado em ``acr_audit.auth``."""

    def get(self, scope: str) -> str: ...


class RegistryError(RuntimeError):
    """Falha definitiva (após retries) ao acessar o registry."""


class RegistryClient:
    """Cliente mínimo para a API do ACR.

    ``token_provider`` entrega tokens já escopados por repositório.
    ``opener`` é injetável para testes (default: ``urllib.request.urlopen``).
    """

    def __init__(
        self,
        fqdn: str,
        token_provider: TokenProvider,
        *,
        opener: Any = None,
        sleep: Any = time.sleep,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.fqdn = fqdn
        self._tokens = token_provider
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep
        self._timeout = timeout

    def get_json(
        self,
        path: str,
        scope: str,
        *,
        accept: str = DEFAULT_ACCEPT,
    ) -> tuple[dict[str, Any], str | None]:
        """GET ``path`` com Bearer. Retorna ``(body_json, next_url_or_None)``."""
        url = self._absolutize(path)
        last_err: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            token = self._tokens.get(scope)
            req = urllib.request.Request(
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": accept},
            )
            try:
                with self._opener(req, timeout=self._timeout) as resp:
                    raw = resp.read()
                    body: dict[str, Any] = json.loads(raw) if raw else {}
                    next_url = self._parse_next_link(resp.headers.get("Link"))
                    return body, next_url
            except urllib.error.HTTPError as err:
                last_err = err
                if err.code in _RETRY_STATUSES and attempt < _MAX_ATTEMPTS - 1:
                    self._sleep(2**attempt)
                    continue
                raise RegistryError(f"HTTP {err.code} em {url}") from err
            except urllib.error.URLError as err:
                last_err = err
                if attempt < _MAX_ATTEMPTS - 1:
                    self._sleep(2**attempt)
                    continue
                raise RegistryError(f"falha de rede em {url}: {err}") from err
        raise RegistryError(f"esgotou retries em {url}") from last_err

    def paginate(
        self,
        path: str,
        scope: str,
        items_key: str,
        *,
        limit: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Itera sobre ``body[items_key]`` seguindo ``Link: rel="next"``.

        Para quando ``limit`` itens forem emitidos ou acabarem as páginas.
        Nunca perde itens: cada página é totalmente consumida antes do próximo
        fetch (crítico pros 15k+ imagens do inventário real).
        """
        emitted = 0
        next_url: str | None = path
        while next_url is not None:
            body, next_url = self.get_json(next_url, scope)
            items = body.get(items_key) or []
            for item in items:
                yield item
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

    def _absolutize(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return f"https://{self.fqdn}{path_or_url}"

    def _parse_next_link(self, link_header: str | None) -> str | None:
        """Extrai a URL do próximo Link rel=next, se houver.

        Formato: ``</v2/_catalog?last=foo&n=500>; rel="next"``.
        Pode conter vários links separados por vírgula; retornamos o primeiro
        com ``rel=next``.
        """
        if not link_header:
            return None
        for chunk in link_header.split(","):
            segments = [s.strip() for s in chunk.split(";")]
            if not segments:
                continue
            if not any("rel=" in s and "next" in s for s in segments[1:]):
                continue
            target = segments[0].strip("<>")
            return self._absolutize(target)
        return None
