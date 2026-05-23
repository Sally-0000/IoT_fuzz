from __future__ import annotations

from dataclasses import dataclass

from .models import FuzzCase, FuzzConfig, RequestSeed
from .mutator import generate_cases

HIGH_RISK_PATH_TERMS = {
    "goform": 100,
    "apply.cgi": 95,
    "setup.cgi": 85,
    "cgi-bin": 80,
    "hnap": 75,
    "diagnostic": 70,
    "ping": 70,
    "traceroute": 70,
    "nslookup": 65,
    "dns": 60,
    "ntp": 60,
    "ddns": 60,
    "upload": 60,
    "restore": 60,
    "backup": 50,
    "system": 45,
    "wan": 45,
    "firewall": 40,
    "vpn": 40,
}

HIGH_RISK_PARAM_TERMS = {
    "host": 60,
    "ip": 55,
    "addr": 55,
    "server": 50,
    "domain": 45,
    "dns": 45,
    "ntp": 45,
    "gateway": 40,
    "mask": 35,
    "file": 35,
    "path": 35,
    "url": 35,
    "cmd": 35,
    "command": 35,
    "name": 20,
    "password": 10,
}

PAYLOAD_SCORE_TERMS = {
    "AAAA": 35,
    "../": 30,
    "%2e%2e": 30,
    "2147483647": 25,
    "4294967295": 25,
    "-1": 20,
    "'\"`": 20,
    "%00": 20,
    "<script": 10,
    ";id": 45,
    "&&id": 45,
    "|id": 45,
    "sleep": 40,
    "curl": 120,
    "wget": 120,
}


@dataclass(slots=True)
class PlanSummary:
    seeds: int
    cases: int
    selected_cases: int
    estimated_seconds: float
    top_cases: list[FuzzCase]


def build_cases(seeds: list[RequestSeed], config: FuzzConfig, oob_url: str | None = None) -> list[FuzzCase]:
    cases = generate_cases(seeds, config.profile, oob_url=oob_url)
    if config.strategy == "priority":
        cases.sort(key=case_score, reverse=True)
    elif config.strategy == "path":
        cases.sort(key=lambda case: (case.seed.path, case.seed.method, case.location, case.name))
    return cases


def summarize_plan(seeds: list[RequestSeed], config: FuzzConfig, top: int = 20, oob_url: str | None = None) -> PlanSummary:
    cases = build_cases(seeds, config, oob_url=oob_url)
    selected = cases if config.max_cases is None else cases[: config.max_cases]
    rate = config.rate_limit_per_sec if config.rate_limit_per_sec > 0 else 1
    base_seconds = len(selected) / rate
    health_seconds = 0
    if config.healthcheck_every > 0:
        health_seconds = (len(selected) // config.healthcheck_every) * 0.5
    return PlanSummary(
        seeds=len(seeds),
        cases=len(cases),
        selected_cases=len(selected),
        estimated_seconds=base_seconds + health_seconds,
        top_cases=selected[:top],
    )


def case_score(case: FuzzCase) -> int:
    seed = case.seed
    score = 0
    path = seed.path.lower()
    param = case.name.lower()
    payload = case.payload.lower()
    for term, value in HIGH_RISK_PATH_TERMS.items():
        if term in path:
            score += value
    for term, value in HIGH_RISK_PARAM_TERMS.items():
        if term in param:
            score += value
    for term, value in PAYLOAD_SCORE_TERMS.items():
        if term.lower() in payload:
            score += value
    if seed.method == "POST":
        score += 25
    if case.location == "data":
        score += 15
    if seed.auth_required:
        score += 5
    if len(case.payload) >= 256:
        score += 15
    if len(case.payload) >= 1024:
        score += 20
    return score


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"
