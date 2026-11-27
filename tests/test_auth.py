"""Regression tests de acr_audit.auth."""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

import pytest

from acr_audit.auth import AuthError, TokenProvider, get_refresh_token, normalize_fqdn


class TestNormalizeFqdn:
    def test_short_name(self) -> None:
        assert normalize_fqdn("acme") == "acme.azurecr.io"

    def test_already_fqdn(self) -> None:
        assert normalize_fqdn("acme.azurecr.io") == "acme.azurecr.io"

    def test_uppercase_normalized(self) -> None:
        assert normalize_fqdn("ACME") == "acme.azurecr.io"

    def test_whitespace_trimmed(self) -> None:
        assert normalize_fqdn("  acme  ") == "acme.azurecr.io"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="vazio"):
            normalize_fqdn("")


class FakeCompleted:
    def __init__(self, stdout: str, stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr


class TestGetRefreshToken:
    def test_parses_access_token(self) -> None:
        def runner(cmd: list[str], **_: Any) -> FakeCompleted:
            assert cmd[:3] == ["az", "acr", "login"]
            assert "--name" in cmd and "acme.azurecr.io" in cmd
            assert "--expose-token" in cmd
            return FakeCompleted(json.dumps({"accessToken": "ref-tok", "loginServer": "x"}))

        assert get_refresh_token("acme.azurecr.io", runner=runner) == "ref-tok"

    def test_cli_not_installed(self) -> None:
        def runner(*_a: Any, **_kw: Any) -> FakeCompleted:
            raise FileNotFoundError("az")

        with pytest.raises(AuthError, match="'az' não encontrado"):
            get_refresh_token("acme", runner=runner)

    def test_cli_error_surfaces_stderr(self) -> None:
        def runner(cmd: list[str], **_: Any) -> FakeCompleted:
            raise subprocess.CalledProcessError(1, cmd, stderr="not logged in")

        with pytest.raises(AuthError, match="not logged in"):
            get_refresh_token("acme", runner=runner)

    def test_unexpected_output(self) -> None:
        def runner(*_a: Any, **_kw: Any) -> FakeCompleted:
            return FakeCompleted("not-json")

        with pytest.raises(AuthError, match="saída inesperada"):
            get_refresh_token("acme", runner=runner)

    def test_missing_field_in_output(self) -> None:
        def runner(*_a: Any, **_kw: Any) -> FakeCompleted:
            return FakeCompleted(json.dumps({"something": "else"}))

        with pytest.raises(AuthError, match="saída inesperada"):
            get_refresh_token("acme", runner=runner)


class FakeHttpResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = json.dumps(body).encode()

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def read(self) -> bytes:
        return self._body


class TestTokenProvider:
    def test_fetches_access_token_once_per_scope(self) -> None:
        calls: list[Any] = []

        def opener(req: Any, timeout: int = 0) -> FakeHttpResponse:
            calls.append(req)
            return FakeHttpResponse({"access_token": "scoped-tok"})

        tp = TokenProvider("acme.azurecr.io", "ref-tok", opener=opener)
        assert tp.get("repository:foo:pull") == "scoped-tok"
        assert tp.get("repository:foo:pull") == "scoped-tok"
        assert len(calls) == 1

    def test_different_scopes_get_different_tokens(self) -> None:
        responses = iter(
            [FakeHttpResponse({"access_token": "a"}), FakeHttpResponse({"access_token": "b"})]
        )

        def opener(_req: Any, timeout: int = 0) -> FakeHttpResponse:
            return next(responses)

        tp = TokenProvider("acme.azurecr.io", "ref-tok", opener=opener)
        assert tp.get("scope-a") == "a"
        assert tp.get("scope-b") == "b"

    def test_posts_refresh_token_grant(self) -> None:
        captured: dict[str, Any] = {}

        def opener(req: Any, timeout: int = 0) -> FakeHttpResponse:
            captured["url"] = req.full_url
            captured["body"] = req.data.decode()
            captured["content_type"] = req.get_header("Content-type")
            return FakeHttpResponse({"access_token": "t"})

        tp = TokenProvider("acme.azurecr.io", "my-refresh", opener=opener)
        tp.get("repository:foo:pull")

        assert captured["url"] == "https://acme.azurecr.io/oauth2/token"
        assert captured["content_type"] == "application/x-www-form-urlencoded"
        assert "grant_type=refresh_token" in captured["body"]
        assert "service=acme.azurecr.io" in captured["body"]
        assert "scope=repository" in captured["body"]
        assert "refresh_token=my-refresh" in captured["body"]

    def test_http_failure_wraps_in_auth_error(self) -> None:
        def opener(*_a: Any, **_kw: Any) -> FakeHttpResponse:
            raise OSError("connection refused")

        tp = TokenProvider("acme.azurecr.io", "ref-tok", opener=opener)
        with pytest.raises(AuthError, match="troca de token falhou"):
            tp.get("scope")

    def test_missing_access_token_in_response(self) -> None:
        def opener(*_a: Any, **_kw: Any) -> FakeHttpResponse:
            return FakeHttpResponse({"other": "field"})

        tp = TokenProvider("acme.azurecr.io", "ref-tok", opener=opener)
        with pytest.raises(AuthError, match="sem access_token"):
            tp.get("scope")

    def test_thread_safe_single_fetch_per_scope(self) -> None:
        """Garante que N threads concorrentes pelo mesmo scope fazem só 1 troca."""
        fetch_count = [0]
        start = threading.Event()

        def opener(_req: Any, timeout: int = 0) -> FakeHttpResponse:
            start.wait(timeout=1)
            fetch_count[0] += 1
            return FakeHttpResponse({"access_token": "t"})

        tp = TokenProvider("acme.azurecr.io", "ref", opener=opener)
        threads = [threading.Thread(target=tp.get, args=("same-scope",)) for _ in range(10)]
        for t in threads:
            t.start()
        start.set()
        for t in threads:
            t.join()
        assert fetch_count[0] == 1
