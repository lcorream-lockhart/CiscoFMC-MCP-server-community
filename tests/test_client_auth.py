# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

import asyncio

import httpx
import pytest

from sfw_mcp_fmc.config import FMCSettings
from sfw_mcp_fmc.fmc import client as client_mod
from sfw_mcp_fmc.fmc.client import FMCClient


def _make_client(monkeypatch, handler):
    monkeypatch.setattr(client_mod.asyncio, "sleep", _no_sleep)
    c = FMCClient(
        FMCSettings(base_url="https://fmc", username="u", password="p", domain_uuid="dom")
    )
    monkeypatch.setattr(
        c, "_build_httpx_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    return c


async def _no_sleep(_):
    return None


def _auth_response(access, refresh):
    return httpx.Response(204, headers={"X-auth-access-token": access, "X-auth-refresh-token": refresh})


def test_401_triggers_refresh_not_reauth(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path)
        if req.url.path.endswith("generatetoken"):
            return _auth_response("a1", "r1")
        if req.url.path.endswith("refreshtoken"):
            assert req.headers["X-auth-refresh-token"] == "r1"
            return _auth_response("a2", "r1")
        if req.headers["X-auth-access-token"] == "a1":
            return httpx.Response(401)
        return httpx.Response(200, json={"ok": True})

    c = _make_client(monkeypatch, handler)
    assert asyncio.run(c.request("GET", "object/networks")) == {"ok": True}
    assert sum(p.endswith("generatetoken") for p in seen) == 1
    assert sum(p.endswith("refreshtoken") for p in seen) == 1


def test_401_reauthenticates_after_refresh_limit(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path)
        if req.url.path.endswith("generatetoken"):
            return _auth_response("fresh", "r")
        if req.headers["X-auth-access-token"] == "fresh":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401)

    c = _make_client(monkeypatch, handler)
    c._access_token = "stale"
    c._refresh_token = "r"
    c._refresh_count = client_mod.MAX_TOKEN_REFRESHES

    assert asyncio.run(c.request("GET", "object/networks")) == {"ok": True}
    assert not any(p.endswith("refreshtoken") for p in seen)
    assert any(p.endswith("generatetoken") for p in seen)


def test_5xx_retried_for_get_but_not_post(monkeypatch):
    calls = {"GET": 0, "POST": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("generatetoken"):
            return _auth_response("a", "r")
        calls[req.method] += 1
        if req.method == "GET" and calls["GET"] < 3:
            return httpx.Response(503)
        if req.method == "POST":
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    c = _make_client(monkeypatch, handler)
    assert asyncio.run(c.request("GET", "object/networks")) == {"ok": True}
    assert calls["GET"] == 3

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(c.request("POST", "object/networks", json_body={}))
    assert calls["POST"] == 1
