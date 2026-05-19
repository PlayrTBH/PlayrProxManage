"""
Proxmox VE REST API client, plus a registry that holds one client per
configured cluster.

Auth uses an API *token* (recommended over password tickets): scoped,
revocable, never expires. Token is sent via the Authorization header:

    Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET

Docs: https://pve.proxmox.com/pve-docs/api-viewer/
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import ClusterConfig

log = logging.getLogger("proxmox")


class ProxmoxError(RuntimeError):
    """Raised when a Proxmox API call fails or the host is unreachable."""


class ProxmoxClient:
    """Talks to a single Proxmox cluster (or standalone node)."""

    def __init__(self, cfg: ClusterConfig, timeout: float = 15.0):
        self.cluster_id = cfg.id
        self.cluster_name = cfg.name
        self.base_url = f"https://{cfg.host}:{cfg.port}/api2/json"
        self._headers = {
            "Authorization": f"PVEAPIToken={cfg.token_id}={cfg.token_secret}"
        }
        self._verify = cfg.verify_ssl
        self._timeout = timeout

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(
                verify=self._verify, timeout=self._timeout
            ) as client:
                resp = await client.request(
                    method, url, headers=self._headers, params=params, data=data
                )
        except httpx.RequestError as exc:
            raise ProxmoxError(
                f"[{self.cluster_id}] cannot reach Proxmox: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise ProxmoxError(
                f"[{self.cluster_id}] Proxmox rejected the API token (401). "
                f"Check token id/secret and its privileges."
            )
        if resp.status_code == 403:
            raise ProxmoxError(
                f"[{self.cluster_id}] token lacks privilege for {path} (403)."
            )
        if resp.status_code >= 400:
            raise ProxmoxError(
                f"[{self.cluster_id}] API error {resp.status_code} on {path}: "
                f"{resp.text}"
            )

        return resp.json().get("data")

    # ----- read endpoints -------------------------------------------------

    async def get_cluster_resources(self, kind: str = "vm") -> list[dict]:
        """Every VM/CT across every node in this cluster, in one call."""
        return await self._request(
            "GET", "/cluster/resources", params={"type": kind}
        ) or []

    async def get_nodes(self) -> list[dict]:
        return await self._request("GET", "/nodes") or []

    async def get_vm_status(self, node: str, vmid: int, kind: str = "qemu") -> dict:
        return await self._request(
            "GET", f"/nodes/{node}/{kind}/{vmid}/status/current"
        ) or {}

    async def get_vm_config(self, node: str, vmid: int, kind: str = "qemu") -> dict:
        return await self._request(
            "GET", f"/nodes/{node}/{kind}/{vmid}/config"
        ) or {}

    async def get_node_status(self, node: str) -> dict:
        return await self._request("GET", f"/nodes/{node}/status") or {}

    # ----- power actions --------------------------------------------------

    async def vm_action(
        self, node: str, vmid: int, action: str, kind: str = "qemu"
    ) -> str:
        """
        Power action. Returns the UPID (Proxmox task id).
          start    - power on
          stop     - hard power off
          shutdown - ACPI graceful shutdown
          reboot   - graceful reboot
          suspend / resume
        """
        allowed = {"start", "stop", "shutdown", "reboot", "suspend", "resume"}
        if action not in allowed:
            raise ProxmoxError(f"Unsupported action '{action}'")
        return await self._request(
            "POST", f"/nodes/{node}/{kind}/{vmid}/status/{action}"
        )

    async def get_task_status(self, node: str, upid: str) -> dict:
        return await self._request(
            "GET", f"/nodes/{node}/tasks/{upid}/status"
        ) or {}

    async def ping(self) -> bool:
        await self._request("GET", "/version")
        return True


class ClusterRegistry:
    """Holds a ProxmoxClient per configured cluster, keyed by cluster id."""

    def __init__(self, clusters: list[ClusterConfig]):
        self._clients: dict[str, ProxmoxClient] = {
            c.id: ProxmoxClient(c) for c in clusters
        }

    def get(self, cluster_id: str) -> ProxmoxClient:
        client = self._clients.get(cluster_id)
        if client is None:
            raise ProxmoxError(f"Unknown cluster id '{cluster_id}'")
        return client

    def all(self) -> list[ProxmoxClient]:
        return list(self._clients.values())

    def ids(self) -> list[str]:
        return list(self._clients.keys())
