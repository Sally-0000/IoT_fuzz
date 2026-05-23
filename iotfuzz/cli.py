from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .analyze import analyze_rootfs
from .executor import FuzzExecutor, replay
from .findings import FindingRecorder
from .har import import_har
from .models import AppConfig, RequestSeed
from .monitors import build_monitors
from .mutator import generate_cases
from .util import load_mapping, read_jsonl, write_json


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iotfuzz")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze-rootfs", help="extract HTTP seeds from a firmware rootfs")
    analyze.add_argument("rootfs")
    analyze.add_argument("--out", required=True)

    har = sub.add_parser("import-har", help="convert a HAR file to seed JSONL")
    har.add_argument("har")
    har.add_argument("--out", required=True)

    run = sub.add_parser("run", help="run low-rate structured fuzzing against a real device")
    run.add_argument("--target", required=True)
    run.add_argument("--seeds", required=True)
    run.add_argument("--out", default="findings")

    replay_cmd = sub.add_parser("replay", help="replay a saved finding")
    replay_cmd.add_argument("finding")
    replay_cmd.add_argument("--target")

    args = parser.parse_args(argv)
    if args.command == "analyze-rootfs":
        seeds = analyze_rootfs(args.rootfs)
        _write_seeds(args.out, seeds)
        print(f"wrote {len(seeds)} seeds to {args.out}")
    elif args.command == "import-har":
        seeds = import_har(args.har)
        _write_seeds(args.out, seeds)
        print(f"wrote {len(seeds)} seeds to {args.out}")
    elif args.command == "run":
        config = AppConfig.from_mapping(load_mapping(args.target))
        seeds = [RequestSeed.from_mapping(row) for row in read_jsonl(args.seeds)]
        cases = generate_cases(seeds, config.fuzz.profile)
        print(f"loaded {len(seeds)} seeds, generated {len(cases)} cases")
        monitors = build_monitors(config.monitors)
        recorder = FindingRecorder(args.out)
        asyncio.run(FuzzExecutor(config, monitors, recorder).run(cases))
    elif args.command == "replay":
        finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
        if args.target:
            config = AppConfig.from_mapping(load_mapping(args.target))
        else:
            base_url = _base_from_finding(finding)
            config = AppConfig.from_mapping({"target": {"base_url": base_url}})
        result = asyncio.run(replay(config, finding))
        print(json.dumps(result, indent=2, sort_keys=True))


def _write_seeds(path: str, seeds: list[RequestSeed]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for seed in seeds:
            fh.write(json.dumps(seed.to_mapping(), sort_keys=True) + "\n")


def _base_from_finding(finding: dict) -> str:
    url = finding.get("request", {}).get("url")
    if not url:
        raise SystemExit("--target is required when finding has no request.url")
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
