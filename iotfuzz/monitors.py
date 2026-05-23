from __future__ import annotations

import asyncio
import socket
import subprocess
from dataclasses import dataclass
from typing import Any

import httpx

from .models import MonitorConfig


@dataclass(slots=True)
class HealthStatus:
    name: str
    ok: bool
    detail: str = ""
    evidence: dict[str, Any] | None = None


class Monitor:
    name = "base"

    async def healthcheck(self) -> HealthStatus:
        return HealthStatus(self.name, True)

    async def collect_evidence(self) -> dict[str, Any]:
        return {}


class PingMonitor(Monitor):
    name = "ping"

    def __init__(self, host: str, timeout_sec: float = 1.0) -> None:
        self.host = host
        self.timeout_sec = timeout_sec

    async def healthcheck(self) -> HealthStatus:
        proc = await asyncio.to_thread(
            subprocess.run,
            ["ping", "-c", "1", "-W", str(max(1, int(self.timeout_sec))), self.host],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = proc.returncode == 0
        return HealthStatus(self.name, ok, "ping ok" if ok else proc.stderr.strip() or proc.stdout.strip())


class HttpMonitor(Monitor):
    name = "http"

    def __init__(self, url: str, timeout_sec: float = 3.0) -> None:
        self.url = url
        self.timeout_sec = timeout_sec

    async def healthcheck(self) -> HealthStatus:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_sec, follow_redirects=True, trust_env=False) as client:
                response = await client.get(self.url)
            ok = response.status_code < 500
            return HealthStatus(self.name, ok, f"HTTP {response.status_code}", {"status_code": response.status_code})
        except Exception as exc:
            return HealthStatus(self.name, False, repr(exc))


class TcpMonitor(Monitor):
    name = "tcp"

    def __init__(self, host: str, ports: list[int], timeout_sec: float = 1.0) -> None:
        self.host = host
        self.ports = ports
        self.timeout_sec = timeout_sec

    async def healthcheck(self) -> HealthStatus:
        failures: list[str] = []
        for port in self.ports:
            ok = await asyncio.to_thread(self._connect, port)
            if not ok:
                failures.append(str(port))
        if failures:
            return HealthStatus(self.name, False, f"closed/unreachable ports: {', '.join(failures)}")
        return HealthStatus(self.name, True, "tcp ok")

    def _connect(self, port: int) -> bool:
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout_sec):
                return True
        except OSError:
            return False


def build_monitors(configs: list[MonitorConfig]) -> list[Monitor]:
    monitors: list[Monitor] = []
    for config in configs:
        values = config.values
        if config.type == "ping":
            monitors.append(PingMonitor(str(values["host"]), float(values.get("timeout_sec", 1))))
        elif config.type == "http":
            monitors.append(HttpMonitor(str(values["url"]), float(values.get("timeout_sec", 3))))
        elif config.type == "tcp":
            monitors.append(
                TcpMonitor(
                    str(values["host"]),
                    [int(port) for port in values.get("ports", [])],
                    float(values.get("timeout_sec", 1)),
                )
            )
    return monitors


async def run_healthchecks(monitors: list[Monitor]) -> list[HealthStatus]:
    return await asyncio.gather(*(monitor.healthcheck() for monitor in monitors))
