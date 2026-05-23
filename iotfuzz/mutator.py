from __future__ import annotations

from .models import FuzzCase, RequestSeed
from .payloads import payloads_for_profile


def generate_cases(seeds: list[RequestSeed], profile: str = "safe", oob_url: str | None = None) -> list[FuzzCase]:
    payloads = payloads_for_profile(profile, oob_url=oob_url)
    cases: list[FuzzCase] = []
    for seed in seeds:
        for location, params in (("query", seed.query), ("data", seed.data)):
            for name, original in params.items():
                for payload in payloads:
                    cases.append(
                        FuzzCase(
                            seed=seed,
                            location=location,
                            name=name,
                            original=original,
                            payload=payload,
                        )
                    )
        if not seed.query and not seed.data and seed.method == "GET":
            for payload in payloads:
                cases.append(FuzzCase(seed=seed, location="query", name="q", original="", payload=payload))
    return cases
