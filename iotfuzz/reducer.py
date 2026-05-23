from __future__ import annotations

from typing import Any

import httpx

from .executor import build_request
from .matchers import match_response
from .models import AppConfig, FuzzCase, RequestSeed


def case_from_finding(finding: dict[str, Any]) -> FuzzCase:
    case_data = finding["case"]
    return FuzzCase(
        seed=RequestSeed.from_mapping(case_data["seed"]),
        location=case_data["location"],
        name=case_data["name"],
        original=case_data.get("original", ""),
        payload=case_data["payload"],
    )


async def reduce_finding(config: AppConfig, finding: dict[str, Any]) -> dict[str, Any]:
    case = case_from_finding(finding)
    original_payload = case.payload
    best = original_payload
    reason = finding.get("reason", "")

    async with httpx.AsyncClient(timeout=config.fuzz.request_timeout_sec, follow_redirects=True, trust_env=False) as client:
        for candidate in _candidates(original_payload):
            if len(candidate) >= len(best):
                continue
            test_case = FuzzCase(case.seed, case.location, case.name, case.original, candidate)
            if await _still_triggers(client, config, test_case, reason):
                best = candidate

    return {
        "original_payload": original_payload,
        "reduced_payload": best,
        "original_len": len(original_payload),
        "reduced_len": len(best),
        "changed": best != original_payload,
    }


def _candidates(payload: str) -> list[str]:
    if not payload:
        return []
    candidates: list[str] = []
    for size in (512, 256, 128, 64, 32, 16, 8, 4, 1):
        if len(payload) > size:
            candidates.append(payload[:size])
    if len(set(payload)) == 1:
        char = payload[0]
        candidates.extend(char * size for size in (512, 256, 128, 64, 32, 16, 8, 4, 1) if size < len(payload))
    for token in ("../etc/passwd", "../../etc/passwd", "'\"`", "%00", ";id", "&&id", ";sleep 3"):
        if token in payload:
            candidates.append(token)
    return list(dict.fromkeys(candidates))


async def _still_triggers(client: httpx.AsyncClient, config: AppConfig, case: FuzzCase, reason: str) -> bool:
    try:
        response = await client.request(**build_request(config, case))
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
        return any(item in reason for item in ("Timeout", "ConnectError", "RemoteProtocolError"))
    if response.status_code >= 500 and reason.startswith("http_status_"):
        return True
    if reason.startswith("response_match:") and match_response(response.text, case):
        return True
    return False
