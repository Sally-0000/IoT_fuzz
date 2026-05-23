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
from .scheduler import build_cases, format_duration, summarize_plan
from .util import load_mapping, read_jsonl

DEFAULT_TARGET = "target.yaml"
DEFAULT_SEEDS = "corpus/seeds.jsonl"
DEFAULT_HAR_SEEDS = "corpus/har-seeds.jsonl"
DEFAULT_FINDINGS = "findings"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iotfuzz")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a target.yaml in the current directory")
    init.add_argument("--target-ip", default="192.168.1.1")
    init.add_argument("--base-url")
    init.add_argument("--force", action="store_true")

    analyze = sub.add_parser("analyze-rootfs", help="extract HTTP seeds from a firmware rootfs")
    analyze.add_argument("rootfs")
    analyze.add_argument("--out", default=DEFAULT_SEEDS)

    har = sub.add_parser("import-har", help="convert a HAR file to seed JSONL")
    har.add_argument("har")
    har.add_argument("--out", default=DEFAULT_HAR_SEEDS)

    plan = sub.add_parser("plan", help="estimate and preview prioritized fuzz cases")
    plan.add_argument("--target")
    plan.add_argument("--seeds", default=DEFAULT_SEEDS)
    plan.add_argument("--top", type=int, default=20)

    run = sub.add_parser("run", help="run low-rate structured fuzzing against a real device")
    run.add_argument("--target")
    run.add_argument("--seeds", default=DEFAULT_SEEDS)
    run.add_argument("--out", default=DEFAULT_FINDINGS)

    replay_cmd = sub.add_parser("replay", help="replay a saved finding")
    replay_cmd.add_argument("finding")
    replay_cmd.add_argument("--target")

    args = parser.parse_args(argv)
    if args.command == "init":
        path = Path(DEFAULT_TARGET)
        if path.exists() and not args.force:
            raise SystemExit(f"{path} already exists; use --force to overwrite")
        base_url = (args.base_url or f"http://{args.target_ip}").rstrip("/")
        write_json_or_yaml_target(path, args.target_ip, base_url)
        print(f"wrote {path}")
    elif args.command == "analyze-rootfs":
        seeds = analyze_rootfs(args.rootfs)
        _write_seeds(args.out, seeds)
        print(f"wrote {len(seeds)} seeds to {args.out}")
    elif args.command == "import-har":
        seeds = import_har(args.har)
        _write_seeds(args.out, seeds)
        print(f"wrote {len(seeds)} seeds to {args.out}")
    elif args.command == "plan":
        target_path = resolve_target(args.target)
        seeds_path = resolve_existing(args.seeds, "seeds")
        config = AppConfig.from_mapping(load_mapping(target_path))
        seeds = [RequestSeed.from_mapping(row) for row in read_jsonl(seeds_path)]
        summary = summarize_plan(seeds, config.fuzz, top=args.top)
        print(f"seeds: {summary.seeds}")
        print(f"generated cases: {summary.cases}")
        print(f"selected cases: {summary.selected_cases}")
        print(f"rate: {config.fuzz.rate_limit_per_sec}/s")
        print(f"estimated minimum time: {format_duration(summary.estimated_seconds)}")
        print(f"strategy: {config.fuzz.strategy}")
        print("")
        for idx, case in enumerate(summary.top_cases, 1):
            print(
                f"{idx:04d} score target: {case.seed.method} {case.seed.path} "
                f"{case.location}.{case.name} payload={_short(case.payload)!r}"
            )
    elif args.command == "run":
        target_path = resolve_target(args.target)
        seeds_path = resolve_existing(args.seeds, "seeds")
        config = AppConfig.from_mapping(load_mapping(target_path))
        seeds = [RequestSeed.from_mapping(row) for row in read_jsonl(seeds_path)]
        cases = build_cases(seeds, config.fuzz)
        selected = cases if config.fuzz.max_cases is None else cases[: config.fuzz.max_cases]
        print(f"loaded {len(seeds)} seeds, generated {len(cases)} cases, selected {len(selected)}", flush=True)
        monitors = build_monitors(config.monitors)
        recorder = FindingRecorder(args.out)
        asyncio.run(FuzzExecutor(config, monitors, recorder).run(selected))
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


def resolve_target(value: str | None) -> Path:
    if value:
        return resolve_existing(value, "target config")
    for candidate in (Path(DEFAULT_TARGET), Path("target.json")):
        if candidate.exists():
            return candidate
    raise SystemExit(
        "target config not found. Run `iotfuzz init --target-ip 192.168.1.1` "
        "or pass `--target /path/to/target.yaml`."
    )


def resolve_existing(value: str, label: str) -> Path:
    path = Path(value)
    if not path.exists():
        raise SystemExit(f"{label} not found: {path}")
    return path


def write_json_or_yaml_target(path: Path, target_ip: str, base_url: str) -> None:
    text = f"""target:
  host: {target_ip}
  base_url: {base_url}

auth:
  type: none

fuzz:
  concurrency: 1
  rate_limit_per_sec: 1
  request_timeout_sec: 3
  healthcheck_every: 10
  confirm_attempts: 1
  max_cases: 200
  profile: safe
  strategy: priority

monitors:
  - type: ping
    host: {target_ip}
    timeout_sec: 1
  - type: http
    url: {base_url}/
    timeout_sec: 3
  - type: tcp
    host: {target_ip}
    ports: [80]
    timeout_sec: 1

recovery:
  type: manual
"""
    path.write_text(text, encoding="utf-8")


def _short(value: str, limit: int = 80) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"...<{len(value)} chars>"


def _base_from_finding(finding: dict) -> str:
    url = finding.get("request", {}).get("url")
    if not url:
        raise SystemExit("--target is required when finding has no request.url")
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
