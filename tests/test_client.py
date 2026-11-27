"""Regression tests de acr_audit.client.

Mockamos ``urlopen`` (via injeção no construtor) para cobrir:
    - header Authorization/Accept
    - retry em 429/5xx
    - parsing do Link header
    - paginate não perde itens entre páginas
    - paginate respeita limit
"""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from acr_audit.client import MANIFEST_ACCEPT, RegistryClient, RegistryError


class StubTokenProvider:
    def __init__(self, token: str = "tok-fake") -> None:
        self.token = token
        self.calls: list[str] = []

    def get(self, scope: str) -> str:
        self.calls.append(scope)
        return self.token


class FakeResponse:
    def __init__(self, body: Any, link: str | None = None) -> None:
        self._body = json.dumps(body).encode()
        self.headers = {"Link": link} if link else {}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def read(self) -> bytes:
        return self._body


class ScriptedOpener:
    """Opener que devolve respostas em sequência. Falhas são instâncias de Exception."""

    def __init__(self, responses: list[Any]) -> None:
        self._queue = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: int = 0) -> Any:
        self.requests.append(request)
        if not self._queue:
            raise AssertionError("opener chamado mais vezes que o esperado")
        nxt = self._queue.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def make_http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://example/", code=code, msg="boom", hdrs=None, fp=io.BytesIO(b"")
    )


def new_client(opener: ScriptedOpener, tokens: StubTokenProvider | None = None) -> RegistryClient:
    return RegistryClient(
        fqdn="foo.azurecr.io",
        token_provider=tokens or StubTokenProvider(),
        opener=opener,
        sleep=lambda _s: None,
    )


class TestGetJson:
    def test_sends_bearer_and_accept(self) -> None:
        opener = ScriptedOpener([FakeResponse({"ok": True})])
        tokens = StubTokenProvider("my-tok")
        client = new_client(opener, tokens)

        body, next_url = client.get_json("/v2/_catalog", scope="registry:catalog:*")

        assert body == {"ok": True}
        assert next_url is None
        assert tokens.calls == ["registry:catalog:*"]
        req = opener.requests[0]
        assert req.get_header("Authorization") == "Bearer my-tok"
        assert req.get_header("Accept") == "application/json"

    def test_custom_accept_header(self) -> None:
        opener = ScriptedOpener([FakeResponse({})])
        client = new_client(opener)
        client.get_json("/v2/x/manifests/y", scope="s", accept=MANIFEST_ACCEPT)
        assert opener.requests[0].get_header("Accept") == MANIFEST_ACCEPT

    def test_absolutizes_path(self) -> None:
        opener = ScriptedOpener([FakeResponse({})])
        client = new_client(opener)
        client.get_json("/v2/_catalog", scope="s")
        assert opener.requests[0].full_url == "https://foo.azurecr.io/v2/_catalog"

    def test_keeps_absolute_url(self) -> None:
        opener = ScriptedOpener([FakeResponse({})])
        client = new_client(opener)
        client.get_json("https://other.azurecr.io/v2/_catalog", scope="s")
        assert opener.requests[0].full_url == "https://other.azurecr.io/v2/_catalog"

    def test_retries_on_429_then_succeeds(self) -> None:
        opener = ScriptedOpener([make_http_error(429), FakeResponse({"ok": 1})])
        client = new_client(opener)
        body, _ = client.get_json("/x", scope="s")
        assert body == {"ok": 1}
        assert len(opener.requests) == 2

    def test_retries_on_503_then_succeeds(self) -> None:
        opener = ScriptedOpener([make_http_error(503), FakeResponse({"ok": 1})])
        client = new_client(opener)
        body, _ = client.get_json("/x", scope="s")
        assert body == {"ok": 1}

    def test_does_not_retry_on_401(self) -> None:
        opener = ScriptedOpener([make_http_error(401)])
        client = new_client(opener)
        with pytest.raises(RegistryError, match="HTTP 401"):
            client.get_json("/x", scope="s")
        assert len(opener.requests) == 1

    def test_gives_up_after_max_attempts(self) -> None:
        opener = ScriptedOpener([make_http_error(500)] * 5)
        client = new_client(opener)
        with pytest.raises(RegistryError, match="HTTP 500"):
            client.get_json("/x", scope="s")
        assert len(opener.requests) == 5


class TestNextLink:
    def test_parses_next_link(self) -> None:
        link = '</v2/_catalog?n=500&last=foo>; rel="next"'
        opener = ScriptedOpener([FakeResponse({}, link=link)])
        client = new_client(opener)
        _, next_url = client.get_json("/v2/_catalog", scope="s")
        assert next_url == "https://foo.azurecr.io/v2/_catalog?n=500&last=foo"

    def test_no_link_header_returns_none(self) -> None:
        opener = ScriptedOpener([FakeResponse({})])
        client = new_client(opener)
        _, next_url = client.get_json("/v2/_catalog", scope="s")
        assert next_url is None

    def test_link_without_next_rel_ignored(self) -> None:
        link = '</v2/_catalog>; rel="prev"'
        opener = ScriptedOpener([FakeResponse({}, link=link)])
        client = new_client(opener)
        _, next_url = client.get_json("/v2/_catalog", scope="s")
        assert next_url is None

    def test_multiple_links_picks_next(self) -> None:
        link = '</prev>; rel="prev", </next?n=10>; rel="next"'
        opener = ScriptedOpener([FakeResponse({}, link=link)])
        client = new_client(opener)
        _, next_url = client.get_json("/v2/_catalog", scope="s")
        assert next_url == "https://foo.azurecr.io/next?n=10"


class TestPaginate:
    def test_follows_pages_until_exhausted(self) -> None:
        opener = ScriptedOpener(
            [
                FakeResponse({"repositories": ["a", "b"]}, link='</p?last=b>; rel="next"'),
                FakeResponse({"repositories": ["c", "d"]}, link='</p?last=d>; rel="next"'),
                FakeResponse({"repositories": ["e"]}),
            ]
        )
        client = new_client(opener)
        out = list(client.paginate("/p", scope="s", items_key="repositories"))
        assert out == ["a", "b", "c", "d", "e"]
        assert len(opener.requests) == 3

    def test_respects_limit_mid_page(self) -> None:
        opener = ScriptedOpener(
            [
                FakeResponse({"repositories": ["a", "b"]}, link='</p?last=b>; rel="next"'),
                FakeResponse({"repositories": ["c", "d"]}, link='</p?last=d>; rel="next"'),
            ]
        )
        client = new_client(opener)
        out = list(client.paginate("/p", scope="s", items_key="repositories", limit=3))
        assert out == ["a", "b", "c"]

    def test_empty_items_key_still_follows_link(self) -> None:
        opener = ScriptedOpener(
            [
                FakeResponse({"repositories": []}, link='</p?last=x>; rel="next"'),
                FakeResponse({"repositories": ["a"]}),
            ]
        )
        client = new_client(opener)
        out = list(client.paginate("/p", scope="s", items_key="repositories"))
        assert out == ["a"]

    def test_missing_items_key_yields_nothing_and_stops(self) -> None:
        opener = ScriptedOpener([FakeResponse({})])
        client = new_client(opener)
        assert list(client.paginate("/p", scope="s", items_key="repositories")) == []
