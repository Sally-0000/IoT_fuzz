from __future__ import annotations

import html.parser
import re
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .models import RequestSeed

TEXT_SUFFIXES = {
    ".html",
    ".htm",
    ".asp",
    ".js",
    ".json",
    ".cgi",
    ".conf",
    ".txt",
    ".xml",
}

URL_RE = re.compile(
    r"""(?P<url>/(?:cgi-bin/[^'"\s<>]{1,160}|goform/[^'"\s<>]{1,160}|HNAP1[^'"\s<>]{0,160}|apply\.cgi[^'"\s<>]{0,160}|setup\.cgi[^'"\s<>]{0,160}|[^'"\s<>]{1,160}?\.(?:cgi|asp|php|json|xml)(?:\?[^'"\s<>]*)?))"""
)
PARAM_RE = re.compile(r"""(?:name|id)\s*=\s*["'](?P<name>[A-Za-z0-9_.:-]{1,80})["']""")


class FormParser(html.parser.HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__()
        self.source = source
        self.forms: list[RequestSeed] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        if tag.lower() == "form":
            self._current = {
                "method": (attr.get("method") or "GET").upper(),
                "path": attr.get("action") or "/",
                "data": {},
            }
        elif self._current is not None and tag.lower() in {"input", "select", "textarea"}:
            name = attr.get("name") or attr.get("id")
            if name:
                data = self._current["data"]
                assert isinstance(data, dict)
                data[name] = attr.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            method = str(self._current["method"])
            seed = RequestSeed(
                method=method,
                path=str(self._current["path"]),
                data={str(k): str(v) for k, v in dict(self._current["data"]).items()},
                auth_required=True,
                source=self.source,
            )
            if method == "GET":
                seed.query = seed.data
                seed.data = {}
            self.forms.append(seed)
            self._current = None


def analyze_rootfs(rootfs: str | Path, max_file_bytes: int = 2_000_000) -> list[RequestSeed]:
    rootfs = Path(rootfs)
    if not rootfs.is_dir():
        raise ValueError(f"rootfs is not a directory: {rootfs}")

    seeds: dict[tuple[str, str, tuple[str, ...], tuple[str, ...]], RequestSeed] = {}
    for path in rootfs.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(rootfs)
        if path.stat().st_size > max_file_bytes:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="ignore")
        elif _looks_executable(path):
            text = _strings(path)
        else:
            continue
        source = f"rootfs:{rel}"
        for seed in _extract_from_text(text, source):
            key = (seed.method, seed.path, tuple(sorted(seed.query)), tuple(sorted(seed.data)))
            seeds[key] = seed
    return sorted(seeds.values(), key=lambda item: (item.path, item.method, item.source))


def _looks_executable(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
        return head == b"\x7fELF"
    except OSError:
        return False


def _strings(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["strings", "-a", "-n", "4", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout


def _extract_from_text(text: str, source: str) -> list[RequestSeed]:
    seeds: list[RequestSeed] = []

    parser = FormParser(source)
    try:
        parser.feed(text)
        seeds.extend(parser.forms)
    except html.parser.HTMLParseError:
        pass

    names = sorted({m.group("name") for m in PARAM_RE.finditer(text)})
    default_params = {name: "" for name in names[:40]}
    for match in URL_RE.finditer(text):
        raw = match.group("url")
        parsed = urlparse(raw)
        query = {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
        if not query and default_params:
            query = dict(list(default_params.items())[:10])
        seeds.append(
            RequestSeed(
                method="GET",
                path=parsed.path or raw,
                query=query,
                auth_required=True,
                source=source,
            )
        )
    return seeds
