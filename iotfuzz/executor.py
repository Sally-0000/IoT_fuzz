from __future__ import annotations

import asyncio
import time
from dataclasses import asdict
from typing import Any

import httpx

from .findings import FindingRecorder
from .models import AppConfig, FuzzCase
from .monitors import Monitor, run_healthchecks


class FuzzExecutor:
    def __init__(self, config: AppConfig, monitors: list[Monitor], recorder: FindingRecorder) -> None:
        self.config = config
        self.monitors = monitors
        self.recorder = recorder
        self.last_request_at = 0.0

    async def run(self, cases: list[FuzzCase]) -> None:
        max_cases = self.config.fuzz.max_cases
        if max_cases is not None:
            cases = cases[:max_cases]
        async with httpx.AsyncClient(**self._client_args()) as client:
            await self._login(client)
            for index, case in enumerate(cases, 1):
                await self._rate_limit()
                request = self._build_request(case)
                response_data: dict[str, Any] | None = None
                reason = ""
                try:
                    response = await client.request(**request)
                    response_data = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "text_sample": response.text[:4096],
                        "elapsed_sec": response.elapsed.total_seconds(),
                    }
                    if response.status_code >= 500:
                        reason = f"http_status_{response.status_code}"
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                    reason = exc.__class__.__name__
                    response_data = {"error": repr(exc)}

                health_rows = []
                if reason or index % self.config.fuzz.healthcheck_every == 0:
                    health = await run_healthchecks(self.monitors)
                    health_rows = [asdict(item) for item in health]
                    if not reason:
                        failed = [item for item in health if not item.ok]
                        if failed:
                            reason = "healthcheck_failed:" + ",".join(item.name for item in failed)

                if reason:
                    confirmed = await self._confirm(client, case)
                    self.recorder.record(case, reason, request, response_data, health_rows, confirmed)
                    print(f"[finding] {reason} {case.seed.method} {case.seed.path} {case.location}.{case.name}")

    async def _rate_limit(self) -> None:
        rate = self.config.fuzz.rate_limit_per_sec
        if rate <= 0:
            return
        interval = 1.0 / rate
        elapsed = time.monotonic() - self.last_request_at
        if elapsed < interval:
            await asyncio.sleep(interval - elapsed)
        self.last_request_at = time.monotonic()

    def _build_request(self, case: FuzzCase) -> dict[str, Any]:
        return build_request(self.config, case)

    def _client_args(self) -> dict[str, Any]:
        args: dict[str, Any] = {
            "timeout": self.config.fuzz.request_timeout_sec,
            "follow_redirects": True,
            "trust_env": False,
        }
        auth = self.config.auth
        if auth.get("type") == "basic":
            args["auth"] = (str(auth.get("username", "")), str(auth.get("password", "")))
        return args

    async def _login(self, client: httpx.AsyncClient) -> None:
        auth = self.config.auth
        if auth.get("type") != "form":
            return
        login_url = str(auth.get("login_url") or "")
        if not login_url:
            raise ValueError("auth.login_url is required for form auth")
        method = str(auth.get("method", "POST")).upper()
        data = {str(k): str(v) for k, v in (auth.get("data") or {}).items()}
        url = self.config.target.base_url.rstrip("/") + "/" + login_url.lstrip("/")
        response = await client.request(method, url, data=data)
        if response.status_code >= 500:
            raise RuntimeError(f"login failed with HTTP {response.status_code}")

    async def _confirm(self, client: httpx.AsyncClient, case: FuzzCase) -> bool:
        attempts = max(0, self.config.fuzz.confirm_attempts)
        if attempts == 0:
            return False
        for _ in range(attempts):
            await self._rate_limit()
            request = self._build_request(case)
            try:
                response = await client.request(**request)
                if response.status_code >= 500:
                    return True
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
                return True
        return False


def build_request(config: AppConfig, case: FuzzCase) -> dict[str, Any]:
    seed = case.seed
    query = dict(seed.query)
    data = dict(seed.data)
    if case.location == "query":
        query[case.name] = case.payload
    elif case.location == "data":
        data[case.name] = case.payload
    request: dict[str, Any] = {
        "method": seed.method,
        "url": seed.url(config.target.base_url),
        "headers": seed.headers,
        "params": query,
    }
    if seed.body is not None:
        request["content"] = seed.body
    elif data:
        request["data"] = data
    return request


async def replay(config: AppConfig, finding: dict[str, Any]) -> dict[str, Any]:
    case_data = finding["case"]
    from .models import FuzzCase, RequestSeed

    case = FuzzCase(
        seed=RequestSeed.from_mapping(case_data["seed"]),
        location=case_data["location"],
        name=case_data["name"],
        original=case_data.get("original", ""),
        payload=case_data["payload"],
    )
    request = build_request(config, case)
    executor = FuzzExecutor(config, [], FindingRecorder("/tmp/iotfuzz-replay-unused"))
    async with httpx.AsyncClient(**executor._client_args()) as client:
        await executor._login(client)
        try:
            response = await client.request(**request)
            return {
                "request": request,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text_sample": response.text[:4096],
            }
        except Exception as exc:
            return {"request": request, "error": repr(exc)}
