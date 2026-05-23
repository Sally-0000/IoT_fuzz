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


class SshMonitor(Monitor):
    name = "ssh"

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        identity_file: str | None = None,
        timeout_sec: float = 3.0,
        evidence_commands: list[str] | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.port = port
        self.identity_file = identity_file
        self.timeout_sec = timeout_sec
        self.evidence_commands = evidence_commands or [
            "ps | grep -E '[h]ttpd|[u]httpd|[b]oa|[l]ighttpd'",
            "dmesg | tail -80",
            "logread | tail -80",
        ]

    async def healthcheck(self) -> HealthStatus:
        proc = await self._run("echo ok")
        ok = proc.returncode == 0 and "ok" in proc.stdout
        detail = "ssh ok" if ok else (proc.stderr.strip() or proc.stdout.strip())
        return HealthStatus(self.name, ok, detail, {"returncode": proc.returncode})

    async def collect_evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for command in self.evidence_commands:
            proc = await self._run(command)
            out[command] = {
                "returncode": proc.returncode,
                "stdout": proc.stdout[-8000:],
                "stderr": proc.stderr[-4000:],
            }
        return out

    async def _run(self, remote_command: str) -> subprocess.CompletedProcess[str]:
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={max(1, int(self.timeout_sec))}",
            "-p",
            str(self.port),
        ]
        if self.identity_file:
            cmd.extend(["-i", self.identity_file])
        cmd.extend([f"{self.username}@{self.host}", remote_command])
        return await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=self.timeout_sec + 2,
        )


class SerialMonitor(Monitor):
    name = "serial"

    def __init__(self, port: str, baud: int = 115200, capture_sec: float = 2.0) -> None:
        self.port = port
        self.baud = baud
        self.capture_sec = capture_sec

    async def healthcheck(self) -> HealthStatus:
        try:
            with open(self.port, "rb"):
                pass
            return HealthStatus(self.name, True, "serial port available")
        except OSError as exc:
            return HealthStatus(self.name, False, repr(exc))

    async def collect_evidence(self) -> dict[str, Any]:
        cmd = f"stty -F {self.port} {self.baud} raw -echo && timeout {self.capture_sec} cat {self.port}"
        proc = await asyncio.to_thread(
            subprocess.run,
            ["sh", "-c", cmd],
            capture_output=True,
            text=True,
            check=False,
            timeout=self.capture_sec + 2,
        )
        return {
            "port": self.port,
            "baud": self.baud,
            "stdout": proc.stdout[-12000:],
            "stderr": proc.stderr[-4000:],
            "returncode": proc.returncode,
        }


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
        elif config.type == "ssh":
            monitors.append(
                SshMonitor(
                    host=str(values["host"]),
                    username=str(values.get("username", "root")),
                    port=int(values.get("port", 22)),
                    identity_file=str(values["identity_file"]) if values.get("identity_file") else None,
                    timeout_sec=float(values.get("timeout_sec", 3)),
                    evidence_commands=[str(item) for item in values.get("evidence_commands", [])]
                    if values.get("evidence_commands")
                    else None,
                )
            )
        elif config.type == "serial":
            monitors.append(
                SerialMonitor(
                    port=str(values["port"]),
                    baud=int(values.get("baud", 115200)),
                    capture_sec=float(values.get("capture_sec", 2)),
                )
            )
    return monitors


async def run_healthchecks(monitors: list[Monitor]) -> list[HealthStatus]:
    return await asyncio.gather(*(monitor.healthcheck() for monitor in monitors))


async def collect_evidence(monitors: list[Monitor]) -> dict[str, Any]:
    rows = await asyncio.gather(*(monitor.collect_evidence() for monitor in monitors), return_exceptions=True)
    evidence: dict[str, Any] = {}
    for monitor, row in zip(monitors, rows):
        if isinstance(row, Exception):
            evidence[monitor.name] = {"error": repr(row)}
        elif row:
            evidence[monitor.name] = row
    return evidence
