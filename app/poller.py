"""
Background poller. One asyncio task for the service lifetime.

Every `poll_interval` seconds it walks every configured cluster, records a
stats sample for every VM/CT, and periodically prunes rows past retention.

Per-cluster failures are isolated: if cluster B is unreachable, clusters A
and C are still recorded, and B's error is surfaced via /api/health.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .database import Database
from .proxmox import ClusterRegistry, ProxmoxError

log = logging.getLogger("poller")


class Poller:
    def __init__(
        self,
        registry: ClusterRegistry,
        db: Database,
        interval: int,
        retention_days: int,
    ):
        self._registry = registry
        self._db = db
        self._interval = interval
        self._retention_days = retention_days
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.last_run_ts: int | None = None
        # cluster_id -> last error string (or absent if healthy)
        self.cluster_errors: dict[str, str] = {}

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="poller")
        log.info("Poller started (interval=%ss)", self._interval)

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task

    async def _run(self) -> None:
        prune_accum = 0
        while not self._stop.is_set():
            await self._poll_all()

            prune_accum += self._interval
            if prune_accum >= 3600:
                prune_accum = 0
                try:
                    removed = self._db.prune(self._retention_days)
                    if removed:
                        log.info("Pruned %d old stat rows", removed)
                except Exception:  # noqa: BLE001
                    log.exception("Prune failed")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass

    async def _poll_all(self) -> None:
        now = int(time.time())
        all_samples: list[dict] = []

        for client in self._registry.all():
            try:
                resources = await client.get_cluster_resources(kind="vm")
                self.cluster_errors.pop(client.cluster_id, None)
            except ProxmoxError as exc:
                self.cluster_errors[client.cluster_id] = str(exc)
                log.warning("Poll failed for %s: %s", client.cluster_id, exc)
                continue
            except Exception as exc:  # noqa: BLE001
                self.cluster_errors[client.cluster_id] = str(exc)
                log.exception("Unexpected poll error for %s", client.cluster_id)
                continue

            for r in resources:
                all_samples.append(
                    {
                        "ts": now,
                        "cluster": client.cluster_id,
                        "vmid": r.get("vmid"),
                        "node": r.get("node"),
                        "name": r.get("name"),
                        "status": r.get("status"),
                        "cpu": r.get("cpu"),
                        "mem_used": r.get("mem"),
                        "mem_max": r.get("maxmem"),
                        "disk_read": r.get("diskread"),
                        "disk_write": r.get("diskwrite"),
                        "net_in": r.get("netin"),
                        "net_out": r.get("netout"),
                        "uptime": r.get("uptime"),
                    }
                )

        try:
            self._db.insert_stats(all_samples)
        except Exception:  # noqa: BLE001
            log.exception("Failed to write stat samples")

        self.last_run_ts = now
        log.debug("Recorded %d samples across all clusters", len(all_samples))
