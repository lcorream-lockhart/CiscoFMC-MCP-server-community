# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

import asyncio

import httpx

from sfw_mcp_fmc.tools import api_tools


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


class _FakeClient:
    def __init__(self, deployable=None, fail_status=None):
        self.calls = []
        self._deployable = deployable or []
        self._fail_status = fail_status

    async def request(self, method, path, *, params=None, json_body=None):
        self.calls.append((method, path, json_body))
        if self._fail_status:
            req = httpx.Request(method, "https://fmc/x")
            resp = httpx.Response(self._fail_status, json={"error": "nope"}, request=req)
            raise httpx.HTTPStatusError("boom", request=req, response=resp)
        return {"ok": True}

    async def get_all(self, path, **kwargs):
        return self._deployable


def _setup(client):
    mcp = _FakeMCP()
    api_tools.register(mcp, lambda profile, domain_uuid_override=None: client)
    return mcp.tools


def test_fmc_post_blocked_in_read_only(monkeypatch):
    monkeypatch.setenv("FMC_READ_ONLY", "true")
    client = _FakeClient()
    tools = _setup(client)

    out = asyncio.run(tools["fmc_post"]("object/networks", {"name": "n"}))

    assert out["error"]["category"] == "READ_ONLY"
    assert client.calls == []


def test_fmc_get_allowed_in_read_only(monkeypatch):
    monkeypatch.setenv("FMC_READ_ONLY", "true")
    client = _FakeClient()
    tools = _setup(client)

    assert asyncio.run(tools["fmc_get"]("object/networks")) == {"ok": True}


def test_http_error_returned_as_structured_error(monkeypatch):
    monkeypatch.delenv("FMC_READ_ONLY", raising=False)
    tools = _setup(_FakeClient(fail_status=404))

    out = asyncio.run(tools["fmc_get"]("object/networks/missing"))

    assert out["error"]["status_code"] == 404
    assert out["error"]["body"] == {"error": "nope"}


def test_update_access_rule_injects_id(monkeypatch):
    monkeypatch.delenv("FMC_READ_ONLY", raising=False)
    client = _FakeClient()
    tools = _setup(client)

    asyncio.run(tools["update_access_rule"]("p1", "r1", {"name": "x"}))

    assert client.calls == [("PUT", "policy/accesspolicies/p1/accessrules/r1", {"name": "x", "id": "r1"})]


def test_deploy_groups_by_version_and_rejects_unknown(monkeypatch):
    monkeypatch.delenv("FMC_READ_ONLY", raising=False)
    deployable = [
        {"device": {"id": "d1"}, "version": "100"},
        {"device": {"id": "d2"}, "version": "200"},
    ]
    client = _FakeClient(deployable=deployable)
    tools = _setup(client)

    asyncio.run(tools["deploy_to_devices"](["d1", "d2"]))
    assert sorted(c[2]["version"] for c in client.calls) == ["100", "200"]

    out = asyncio.run(tools["deploy_to_devices"](["nope"]))
    assert out["error"]["category"] == "NO_PENDING_CHANGES"
