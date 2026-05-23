from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .models import FuzzCase
from .util import write_json


class FindingRecorder:
    def __init__(self, out_dir: str | Path) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.counter = self._next_counter()

    def record(
        self,
        case: FuzzCase,
        reason: str,
        request: dict[str, Any],
        response: dict[str, Any] | None,
        health: list[dict[str, Any]],
        confirmed: bool,
    ) -> Path:
        finding_id = f"FND-{self.counter:06d}"
        self.counter += 1
        case_dir = self.out_dir / finding_id
        case_dir.mkdir(parents=True, exist_ok=False)

        summary = {
            "id": finding_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "confirmed": confirmed,
            "case": {
                "location": case.location,
                "name": case.name,
                "original": case.original,
                "payload": case.payload,
                "seed": case.seed.to_mapping(),
            },
            "request": request,
            "response": response,
            "health": health,
        }
        write_json(case_dir / "finding.json", summary)
        (case_dir / "request.raw").write_text(_raw_request(request), encoding="utf-8")
        if response:
            (case_dir / "response.txt").write_text(json.dumps(response, indent=2), encoding="utf-8")
        (case_dir / "curl.txt").write_text(_curl(request) + "\n", encoding="utf-8")
        return case_dir

    def _next_counter(self) -> int:
        existing = sorted(self.out_dir.glob("FND-*"))
        if not existing:
            return 1
        try:
            return int(existing[-1].name.split("-")[-1]) + 1
        except ValueError:
            return 1


def _raw_request(request: dict[str, Any]) -> str:
    url = _url_with_params(request)
    lines = [f"{request['method']} {url}"]
    for key, value in request.get("headers", {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    if request.get("body"):
        lines.append(str(request["body"]))
    elif request.get("data"):
        lines.append(json.dumps(request["data"], sort_keys=True))
    return "\n".join(lines) + "\n"


def _curl(request: dict[str, Any]) -> str:
    parts = ["curl", "-i", "-X", _shell_quote(request["method"])]
    for key, value in request.get("headers", {}).items():
        parts.extend(["-H", _shell_quote(f"{key}: {value}")])
    if request.get("data"):
        for key, value in request["data"].items():
            parts.extend(["--data-urlencode", _shell_quote(f"{key}={value}")])
    elif request.get("body"):
        parts.extend(["--data-raw", _shell_quote(str(request["body"]))])
    parts.append(_shell_quote(_url_with_params(request)))
    return " ".join(parts)


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _url_with_params(request: dict[str, Any]) -> str:
    params = request.get("params") or {}
    if not params:
        return str(request["url"])
    separator = "&" if "?" in str(request["url"]) else "?"
    return str(request["url"]) + separator + urlencode(params, doseq=True)
