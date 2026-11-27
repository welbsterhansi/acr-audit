"""Autenticação contra o Azure Container Registry.

Reutiliza a sessão ativa do ``az login`` — o usuário precisa já estar logado
e ter permissão de pull no ACR. O fluxo é:

1. ``az acr login --name <acr> --expose-token`` devolve o refresh token do
   ACR, trocado a partir do token AAD da sessão atual. Não precisamos lidar
   com AAD nem com service principal.
2. Para cada operação, trocamos o refresh token por um access token escopado
   (ex.: ``repository:<repo>:metadata_read,pull``) via
   ``POST /oauth2/token``.

``TokenProvider`` é thread-safe: workers paralelos requisitando o mesmo
scope só disparam uma troca HTTP.
"""

from __future__ import annotations

import json
import subprocess
import threading
import urllib.parse
import urllib.request
from typing import Any


class AuthError(RuntimeError):
    """Falha ao obter credencial do ACR."""


def normalize_fqdn(name_or_fqdn: str) -> str:
    """Aceita ``"acme"`` ou ``"acme.azurecr.io"``, retorna o FQDN."""
    cleaned = name_or_fqdn.strip().lower()
    if not cleaned:
        raise ValueError("ACR vazio")
    if "." in cleaned:
        return cleaned
    return f"{cleaned}.azurecr.io"


def get_refresh_token(
    fqdn: str,
    *,
    runner: Any = None,
) -> str:
    """Executa ``az acr login --expose-token`` e retorna o refresh token.

    ``runner`` é injetável para testes (default: ``subprocess.run``).
    """
    run = runner or subprocess.run
    try:
        completed = run(
            ["az", "acr", "login", "--name", fqdn, "--expose-token", "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise AuthError("comando 'az' não encontrado no PATH") from err
    except subprocess.CalledProcessError as err:
        raise AuthError(f"az acr login falhou: {err.stderr.strip() or err}") from err
    try:
        payload = json.loads(completed.stdout)
        return payload["accessToken"]
    except (json.JSONDecodeError, KeyError) as err:
        raise AuthError("saída inesperada de az acr login") from err


class TokenProvider:
    """Cache thread-safe de access tokens por scope."""

    def __init__(
        self,
        fqdn: str,
        refresh_token: str,
        *,
        opener: Any = None,
        timeout: int = 30,
    ) -> None:
        self._fqdn = fqdn
        self._refresh_token = refresh_token
        self._opener = opener or urllib.request.urlopen
        self._timeout = timeout
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._cache.get(scope)
            if cached is not None:
                return cached
            token = self._fetch(scope)
            self._cache[scope] = token
            return token

    def _fetch(self, scope: str) -> str:
        data = urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "service": self._fqdn,
                "scope": scope,
                "refresh_token": self._refresh_token,
            }
        ).encode()
        req = urllib.request.Request(
            f"https://{self._fqdn}/oauth2/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with self._opener(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read())
        except Exception as err:
            raise AuthError(f"troca de token falhou para scope={scope}: {err}") from err
        try:
            return payload["access_token"]
        except KeyError as err:
            raise AuthError(f"resposta sem access_token para scope={scope}") from err
