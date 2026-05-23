from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .models import RequestSeed


def import_har(path: str | Path) -> list[RequestSeed]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    seeds: list[RequestSeed] = []
    for entry in entries:
        request = entry.get("request") or {}
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "/")
        parsed = urlparse(url)
        headers = {
            str(item.get("name")): str(item.get("value", ""))
            for item in request.get("headers", [])
            if item.get("name") and str(item.get("name")).lower() not in {"host", "content-length"}
        }
        query = {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
        for item in request.get("queryString", []):
            if item.get("name"):
                query[str(item["name"])] = str(item.get("value", ""))

        data_fields: dict[str, str] = {}
        body = None
        post = request.get("postData") or {}
        for item in post.get("params", []) or []:
            if item.get("name"):
                data_fields[str(item["name"])] = str(item.get("value", ""))
        if not data_fields and post.get("text"):
            mime = str(post.get("mimeType", ""))
            text = str(post["text"])
            if "application/x-www-form-urlencoded" in mime:
                data_fields = {k: v for k, v in parse_qsl(text, keep_blank_values=True)}
            else:
                body = text

        seeds.append(
            RequestSeed(
                method=method,
                path=parsed.path or "/",
                headers=headers,
                query=query,
                data=data_fields,
                body=body,
                auth_required=_looks_authenticated(headers),
                source=f"har:{path}",
            )
        )
    return seeds


def _looks_authenticated(headers: dict[str, str]) -> bool:
    lowered = {key.lower(): value for key, value in headers.items()}
    return bool(lowered.get("cookie") or lowered.get("authorization"))
