# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Generic FMC REST passthrough tools plus curated read/write/deploy tools."""

from __future__ import annotations

import os
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx

from ..errors import FMCClientError
from ..fmc.client import FMCClient
from ..logging_conf import configure_logging

logger = configure_logging("sfw-mcp-fmc")

ClientFactory = Callable[..., FMCClient]

_PLATFORM_SERVER_VERSION = "/api/fmc_platform/v1/info/serverversion"
_PLATFORM_DOMAINS = "/api/fmc_platform/v1/info/domain"


def read_only_enabled() -> bool:
    return os.getenv("FMC_READ_ONLY", "false").strip().lower() in {"1", "true", "yes", "y", "on"}


def _error(category: str, message: str, **extra: Any) -> Dict[str, Any]:
    return {"error": {"category": category, "message": message, **extra}}


def _http_error(exc: httpx.HTTPStatusError) -> Dict[str, Any]:
    try:
        body: Any = exc.response.json()
    except Exception:
        body = exc.response.text[:1000]
    return _error("FMC_HTTP_ERROR", str(exc), status_code=exc.response.status_code, body=body)


def register(mcp: Any, create_client: ClientFactory) -> None:
    """Attach the generic and curated tools to `mcp`."""

    async def _run(
        fmc_profile: Optional[str],
        domain_uuid: Optional[str],
        fn: Callable[[FMCClient], Awaitable[Any]],
        *,
        write: bool = False,
    ) -> Any:
        if write and read_only_enabled():
            return _error("READ_ONLY", "FMC_READ_ONLY is enabled; write operations are disabled.")
        try:
            client = create_client(fmc_profile, domain_uuid_override=domain_uuid)
            return await fn(client)
        except httpx.HTTPStatusError as exc:
            logger.warning("FMC HTTP error: %s", exc)
            return _http_error(exc)
        except FMCClientError as exc:
            logger.warning("FMC client error: %s", exc)
            return _error(type(exc).__name__, str(exc))
        except Exception as exc:
            logger.exception("Unexpected error in FMC tool")
            return _error("UNEXPECTED", str(exc))

    # ------------------------------------------------------------------ #
    # Generic passthrough
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def fmc_get(
        path: str,
        params: Optional[Dict[str, Any]] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Raw GET against the FMC API for one object or endpoint.

        `path` is relative to /api/fmc_config/v1/domain/{domainUUID}/ (e.g. "object/networks/<id>").
        Pass a full path starting with "/api/" for non-domain endpoints.
        Use fmc_get_all for paginated list endpoints.
        """
        return await _run(fmc_profile, domain_uuid, lambda c: c.request("GET", path, params=params))

    @mcp.tool()
    async def fmc_get_all(
        path: str,
        params: Optional[Dict[str, Any]] = None,
        expanded: bool = False,
        max_pages: int = 20,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Fetch every item from a paginated FMC list endpoint (e.g. "object/networks").

        Set expanded=True for full object detail; max_pages bounds the number of pages fetched.
        """
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.get_all(path, params=params, expanded=expanded, max_pages=max_pages),
        )

    @mcp.tool()
    async def fmc_post(
        path: str,
        body: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Create an object via POST. `body` must match the FMC schema for that object (usually includes "type")."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("POST", path, params=params, json_body=body),
            write=True,
        )

    @mcp.tool()
    async def fmc_put(
        path: str,
        body: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Update an object via PUT. `path` must include the object id; most FMC types need a full-body replace."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("PUT", path, params=params, json_body=body),
            write=True,
        )

    @mcp.tool()
    async def fmc_delete(
        path: str,
        params: Optional[Dict[str, Any]] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Delete an object via DELETE. `path` must include the object id. Irreversible."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("DELETE", path, params=params),
            write=True,
        )

    # ------------------------------------------------------------------ #
    # Platform / domains
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def get_server_version(fmc_profile: Optional[str] = None) -> Any:
        """Get the FMC server version and build info."""
        return await _run(fmc_profile, None, lambda c: c.request("GET", _PLATFORM_SERVER_VERSION))

    @mcp.tool()
    async def list_domains(fmc_profile: Optional[str] = None) -> Any:
        """List domains visible to the API user (multi-domain FMC)."""
        return await _run(fmc_profile, None, lambda c: c.request("GET", _PLATFORM_DOMAINS))

    # ------------------------------------------------------------------ #
    # Devices
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def list_devices(
        name_filter: Optional[str] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """List managed devices; `name_filter` applies a server-side name filter."""
        params = {"filter": f"name:{name_filter}"} if name_filter else None
        return await _run(
            fmc_profile, domain_uuid, lambda c: c.get_all("/devices/devicerecords", params=params)
        )

    @mcp.tool()
    async def get_device(
        device_id: str, domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """Get full details for one managed device by UUID."""
        return await _run(
            fmc_profile, domain_uuid, lambda c: c.get_device_record(device_id, expanded=False)
        )

    # ------------------------------------------------------------------ #
    # Access policies and rules
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def list_access_policies(
        domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """List all access control policies."""
        return await _run(fmc_profile, domain_uuid, lambda c: c.list_access_policies(expanded=False))

    @mcp.tool()
    async def get_access_policy(
        policy_id: str, domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """Get one access control policy by UUID."""
        return await _run(
            fmc_profile, domain_uuid, lambda c: c.get_access_policy(policy_id, expanded=False)
        )

    @mcp.tool()
    async def list_access_rules(
        policy_id: str,
        expanded: bool = True,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """List all rules in an access control policy (expanded=True returns full rule detail)."""
        return await _run(
            fmc_profile, domain_uuid, lambda c: c.list_access_rules(policy_id, expanded=expanded)
        )

    @mcp.tool()
    async def get_access_rule(
        policy_id: str,
        rule_id: str,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Get one access control rule by id."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("GET", f"policy/accesspolicies/{policy_id}/accessrules/{rule_id}"),
        )

    @mcp.tool()
    async def create_access_rule(
        policy_id: str,
        rule: Dict[str, Any],
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Create an access rule in a policy. `rule` is the FMC AccessRule JSON body (needs at least
        "name" and "action"). Look up zone/network/port object ids first via fmc_get_all.
        Changes take effect on devices only after deploy_to_devices.
        """
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("POST", f"policy/accesspolicies/{policy_id}/accessrules", json_body=rule),
            write=True,
        )

    @mcp.tool()
    async def update_access_rule(
        policy_id: str,
        rule_id: str,
        rule: Dict[str, Any],
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Replace an access rule. Fetch it with get_access_rule, modify, and send the whole object back."""
        body = {**rule, "id": rule_id}
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request(
                "PUT", f"policy/accesspolicies/{policy_id}/accessrules/{rule_id}", json_body=body
            ),
            write=True,
        )

    @mcp.tool()
    async def delete_access_rule(
        policy_id: str,
        rule_id: str,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Delete an access rule. Irreversible; deploy afterwards to apply."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("DELETE", f"policy/accesspolicies/{policy_id}/accessrules/{rule_id}"),
            write=True,
        )

    # ------------------------------------------------------------------ #
    # Network / host objects
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def list_network_objects(
        name_filter: Optional[str] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """List network (CIDR) objects, optionally filtered by name or value."""
        params = {"filter": f"nameOrValue:{name_filter}"} if name_filter else None
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.get_all("/object/networks", params=params, expanded=True),
        )

    @mcp.tool()
    async def create_network_object(
        name: str,
        value: str,
        description: Optional[str] = None,
        overridable: bool = False,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Create a network object, e.g. name="Corp-LAN", value="10.1.0.0/16"."""
        body: Dict[str, Any] = {"name": name, "value": value, "overridable": overridable, "type": "Network"}
        if description:
            body["description"] = description
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("POST", "object/networks", json_body=body),
            write=True,
        )

    @mcp.tool()
    async def update_network_object(
        object_id: str,
        name: str,
        value: str,
        description: Optional[str] = None,
        overridable: bool = False,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Update a network object (full replace; pass all fields)."""
        body: Dict[str, Any] = {
            "id": object_id,
            "name": name,
            "value": value,
            "overridable": overridable,
            "type": "Network",
        }
        if description:
            body["description"] = description
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("PUT", f"object/networks/{object_id}", json_body=body),
            write=True,
        )

    @mcp.tool()
    async def delete_network_object(
        object_id: str, domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """Delete a network object. Fails if it is still referenced."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("DELETE", f"object/networks/{object_id}"),
            write=True,
        )

    @mcp.tool()
    async def list_host_objects(
        name_filter: Optional[str] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """List host (single-IP) objects, optionally filtered by name or value."""
        params = {"filter": f"nameOrValue:{name_filter}"} if name_filter else None
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.get_all("/object/hosts", params=params, expanded=True),
        )

    @mcp.tool()
    async def create_host_object(
        name: str,
        value: str,
        description: Optional[str] = None,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Create a host object, e.g. name="web-1", value="10.1.2.3"."""
        body: Dict[str, Any] = {"name": name, "value": value, "type": "Host"}
        if description:
            body["description"] = description
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("POST", "object/hosts", json_body=body),
            write=True,
        )

    @mcp.tool()
    async def delete_host_object(
        object_id: str, domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """Delete a host object. Fails if it is still referenced."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.request("DELETE", f"object/hosts/{object_id}"),
            write=True,
        )

    # ------------------------------------------------------------------ #
    # Deployment
    # ------------------------------------------------------------------ #

    @mcp.tool()
    async def get_deployable_devices(
        domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """List devices with pending changes, including the `version` token each needs for deployment."""
        return await _run(
            fmc_profile,
            domain_uuid,
            lambda c: c.get_all("/deployment/deployabledevices", expanded=True),
        )

    @mcp.tool()
    async def deploy_to_devices(
        device_ids: List[str],
        force_deploy: bool = False,
        ignore_warning: bool = True,
        domain_uuid: Optional[str] = None,
        fmc_profile: Optional[str] = None,
    ) -> Any:
        """Deploy pending changes to devices. Looks up each device's pending-change version first and
        submits one request per distinct version. Poll progress with get_deployment_status.
        """

        async def _deploy(c: FMCClient) -> Any:
            deployable = await c.get_all("/deployment/deployabledevices", expanded=True)
            by_id: Dict[str, Any] = {}
            for entry in deployable:
                dev_id = (entry.get("device") or {}).get("id")
                if dev_id:
                    by_id[dev_id] = entry.get("version")

            missing = [d for d in device_ids if d not in by_id]
            if missing:
                return _error(
                    "NO_PENDING_CHANGES",
                    f"No pending changes for device id(s): {missing}. "
                    "Only devices from get_deployable_devices can be deployed.",
                )

            results = []
            for version in {by_id[d] for d in device_ids}:
                body = {
                    "type": "DeploymentRequest",
                    "version": version,
                    "forceDeploy": force_deploy,
                    "ignoreWarning": ignore_warning,
                    "deviceList": [d for d in device_ids if by_id[d] == version],
                }
                results.append(await c.request("POST", "deployment/deploymentrequests", json_body=body))
            return results if len(results) > 1 else results[0]

        return await _run(fmc_profile, domain_uuid, _deploy, write=True)

    @mcp.tool()
    async def get_deployment_status(
        task_id: str, domain_uuid: Optional[str] = None, fmc_profile: Optional[str] = None
    ) -> Any:
        """Poll the status of a deployment (or other async) task by id."""
        return await _run(
            fmc_profile, domain_uuid, lambda c: c.request("GET", f"job/taskstatuses/{task_id}")
        )
