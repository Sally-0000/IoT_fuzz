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
from .oob import run_http_callback
from .reducer import reduce_finding
from .scheduler import build_cases, format_duration, summarize_plan
from .util import load_mapping, read_jsonl

DEFAULT_TARGET = "target.yaml"
DEFAULT_SEEDS = "corpus/seeds.jsonl"
DEFAULT_HAR_SEEDS = "corpus/har-seeds.jsonl"
DEFAULT_FINDINGS = "findings"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="iotfuzz",
        description="面向真实路由器/IoT 设备的结构化 HTTP fuzz 工具。",
        epilog=(
            "例子:\n"
            "  iotfuzz init --target-ip 192.168.1.1\n"
            "  iotfuzz analyze-rootfs ./rootfs\n"
            "  iotfuzz import-har login.har --out corpus/login-seeds.jsonl\n"
            "  iotfuzz plan --top 50 --max-cases 500 --rate 2\n"
            "  iotfuzz run --max-cases 500 --rate 2 --profile safe\n"
            "  iotfuzz run --auto --max-cases 200 --rate 1\n"
            "  iotfuzz run --fin-auto --max-cases 500 --rate 2\n"
            "  iotfuzz run --fast --concurrency 100\n"
            "  iotfuzz run --seeds corpus/login-seeds.jsonl --profile cmd-light --max-cases 100\n"
            "  iotfuzz oob-http --port 8088 --log oob/callbacks.jsonl\n"
            "  iotfuzz replay findings/FND-000001/finding.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser(
        "init",
        help="在当前目录创建 target.yaml",
        description="在当前 fuzz 工作目录创建一份保守的 target.yaml。",
        epilog="例子:\n  iotfuzz init --target-ip 192.168.1.1\n  iotfuzz init --base-url http://192.168.0.1:8080 --target-ip 192.168.0.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init.add_argument("--target-ip", default="192.168.1.1", help="目标设备 IP，默认 192.168.1.1")
    init.add_argument("--base-url", help="目标 Web 根 URL，例如 http://192.168.1.1:8080")
    init.add_argument("--force", action="store_true", help="覆盖已有 target.yaml")

    analyze = sub.add_parser(
        "analyze-rootfs",
        help="从固件 rootfs 提取 HTTP seed",
        description="扫描固件 rootfs 中的 HTML 表单、JavaScript/API 路径和 ELF 字符串，生成请求种子。",
        epilog="例子:\n  iotfuzz analyze-rootfs ./rootfs\n  iotfuzz analyze-rootfs ./rootfs --out corpus/vendor-a.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analyze.add_argument("rootfs", help="固件文件系统目录")
    analyze.add_argument("--out", default=DEFAULT_SEEDS, help=f"输出 seed JSONL，默认 {DEFAULT_SEEDS}")

    har = sub.add_parser(
        "import-har",
        help="把 HAR 流量转换成 seed JSONL",
        description="把浏览器/Burp 导出的 HAR 流量转换成请求种子，适合认证态页面和真实 UI 操作。",
        epilog="例子:\n  iotfuzz import-har traffic.har\n  iotfuzz import-har login.har --out corpus/login-seeds.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    har.add_argument("har", help="HAR 文件路径")
    har.add_argument("--out", default=DEFAULT_HAR_SEEDS, help=f"输出 seed JSONL，默认 {DEFAULT_HAR_SEEDS}")

    plan = sub.add_parser(
        "plan",
        help="预估和预览 fuzz 计划",
        description="不发送流量，只预览 case 数量、预计耗时和高优先级目标。",
        epilog="例子:\n  iotfuzz plan\n  iotfuzz plan --top 50 --max-cases 500 --rate 2 --strategy priority",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    plan.add_argument("--target", help="目标配置文件，默认自动找 target.yaml 或 target.json")
    plan.add_argument("--seeds", default=DEFAULT_SEEDS, help=f"seed JSONL，默认 {DEFAULT_SEEDS}")
    plan.add_argument("--top", type=int, default=20, help="显示前 N 个高优先级 case，默认 20")
    add_fuzz_overrides(plan)

    run = sub.add_parser(
        "run",
        help="对真实设备执行低速结构化 fuzz",
        description=(
            "向目标真实设备发送变异后的 HTTP 请求并保存异常 case。\n"
            "普通模式只跑第一批 max-cases；--auto 会分批继续直到发现 finding；"
            "--fin-auto 会分批跑完整个 case 集合。"
        ),
        epilog=(
            "例子:\n"
            "  iotfuzz run\n"
            "  iotfuzz run --max-cases 500 --rate 2\n"
            "  iotfuzz run --auto --max-cases 200 --rate 1\n"
            "  iotfuzz run --fin-auto --max-cases 500 --rate 2\n"
            "  iotfuzz run --fast --concurrency 100\n"
            "  iotfuzz run --profile cmd-light --max-cases 100 --rate 1\n"
            "  iotfuzz run --profile cmd-timeout --max-cases 50 --rate 0.5\n"
            "  iotfuzz run --seeds corpus/har-seeds.jsonl --out findings-har\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument("--target", help="目标配置文件，默认自动找 target.yaml 或 target.json")
    run.add_argument("--seeds", default=DEFAULT_SEEDS, help=f"seed JSONL，默认 {DEFAULT_SEEDS}")
    run.add_argument("--out", default=DEFAULT_FINDINGS, help=f"finding 输出目录，默认 {DEFAULT_FINDINGS}")
    run.add_argument(
        "--fast",
        action="store_true",
        help="拉满模式：取消限速；未指定 --max-cases 时扫描全部；未指定确认/健康检查时使用更激进默认值",
    )
    auto_group = run.add_mutually_exclusive_group()
    auto_group.add_argument(
        "--auto",
        action="store_true",
        help="自动分批扫描：第一批没有 finding 就继续，发现 finding 后终止",
    )
    auto_group.add_argument(
        "--fin-auto",
        action="store_true",
        help="完整自动扫描：按批次扫完整个 case 集合，发现 finding 也不终止",
    )
    add_fuzz_overrides(run)

    replay_cmd = sub.add_parser(
        "replay",
        help="重放已保存的 finding",
        description="根据 finding.json 重放触发请求。",
        epilog="例子:\n  iotfuzz replay findings/FND-000001/finding.json\n  iotfuzz replay findings/FND-000001/finding.json --target target.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    replay_cmd.add_argument("finding", help="finding.json 路径")
    replay_cmd.add_argument("--target", help="目标配置文件；不指定时从 finding 里的 URL 推断 base_url")

    reduce_cmd = sub.add_parser(
        "reduce",
        help="最小化 finding payload",
        description="尝试重放更短的 payload，输出仍能触发相似异常的最短候选。",
        epilog="例子:\n  iotfuzz reduce findings/FND-000001/finding.json --target target.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    reduce_cmd.add_argument("finding", help="finding.json 路径")
    reduce_cmd.add_argument("--target", help="目标配置文件；不指定时从 finding 里的 URL 推断 base_url")

    oob_cmd = sub.add_parser(
        "oob-http",
        help="启动 HTTP OOB callback 记录器",
        description="启动本地 HTTP callback server，用于命令注入/SSRF 等 OOB 检测。",
        epilog="例子:\n  iotfuzz oob-http --host 0.0.0.0 --port 8088 --log oob/callbacks.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    oob_cmd.add_argument("--host", default="0.0.0.0", help="监听地址，默认 0.0.0.0")
    oob_cmd.add_argument("--port", type=int, default=8088, help="监听端口，默认 8088")
    oob_cmd.add_argument("--log", default="oob/callbacks.jsonl", help="callback JSONL 日志路径")

    args = parser.parse_args(argv)
    if args.command == "init":
        path = Path(DEFAULT_TARGET)
        if path.exists() and not args.force:
            raise SystemExit(f"{path} already exists; use --force to overwrite")
        base_url = (args.base_url or f"http://{args.target_ip}").rstrip("/")
        write_json_or_yaml_target(path, args.target_ip, base_url)
        print(f"已写入 {path}")
    elif args.command == "analyze-rootfs":
        seeds = analyze_rootfs(args.rootfs)
        _write_seeds(args.out, seeds)
        print(f"已写入 {len(seeds)} 个 seeds 到 {args.out}")
    elif args.command == "import-har":
        seeds = import_har(args.har)
        _write_seeds(args.out, seeds)
        print(f"已写入 {len(seeds)} 个 seeds 到 {args.out}")
    elif args.command == "plan":
        target_path = resolve_target(args.target)
        seeds_path = resolve_existing(args.seeds, "seeds")
        config = AppConfig.from_mapping(load_mapping(target_path))
        apply_fuzz_overrides(config, args)
        seeds = [RequestSeed.from_mapping(row) for row in read_jsonl(seeds_path)]
        summary = summarize_plan(seeds, config.fuzz, top=args.top, oob_url=config.oob.get("http_url"))
        print(f"seeds 数量: {summary.seeds}")
        print(f"生成 case 总数: {summary.cases}")
        print(f"本批选择 case: {summary.selected_cases}")
        print(f"速率: {config.fuzz.rate_limit_per_sec}/s")
        print(f"预计最短耗时: {format_duration(summary.estimated_seconds)}")
        print(f"调度策略: {config.fuzz.strategy}")
        print("")
        for idx, case in enumerate(summary.top_cases, 1):
            print(
                f"{idx:04d} 目标: {case.seed.method} {case.seed.path} "
                f"{case.location}.{case.name} payload={_short(case.payload)!r}"
            )
    elif args.command == "run":
        target_path = resolve_target(args.target)
        seeds_path = resolve_existing(args.seeds, "seeds")
        config = AppConfig.from_mapping(load_mapping(target_path))
        apply_fuzz_overrides(config, args)
        apply_fast_mode(config, args)
        seeds = [RequestSeed.from_mapping(row) for row in read_jsonl(seeds_path)]
        cases = build_cases(seeds, config.fuzz, oob_url=config.oob.get("http_url"))
        selected = cases if config.fuzz.max_cases is None else cases[: config.fuzz.max_cases]
        if args.auto or args.fin_auto:
            batch_size = config.fuzz.max_cases or len(cases)
            print(f"已加载 {len(seeds)} 个 seeds，生成 {len(cases)} 个 cases，每批最多 {batch_size} 个", flush=True)
        else:
            print(f"已加载 {len(seeds)} 个 seeds，生成 {len(cases)} 个 cases，本次选择 {len(selected)} 个", flush=True)
        monitors = build_monitors(config.monitors)
        recorder = FindingRecorder(args.out)
        if args.auto or args.fin_auto:
            asyncio.run(run_auto_batches(config, monitors, recorder, cases, stop_on_finding=args.auto))
        else:
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
    elif args.command == "reduce":
        finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
        if args.target:
            config = AppConfig.from_mapping(load_mapping(args.target))
        else:
            base_url = _base_from_finding(finding)
            config = AppConfig.from_mapping({"target": {"base_url": base_url}})
        result = asyncio.run(reduce_finding(config, finding))
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "oob-http":
        run_http_callback(args.host, args.port, args.log)


def _write_seeds(path: str, seeds: list[RequestSeed]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for seed in seeds:
            fh.write(json.dumps(seed.to_mapping(), sort_keys=True) + "\n")


def add_fuzz_overrides(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("fuzz 参数覆盖")
    group.add_argument("--rate", type=float, help="每秒请求数，覆盖 fuzz.rate_limit_per_sec")
    group.add_argument("--concurrency", type=int, help="并发请求数，默认从配置读取；--fast 未指定时默认 50")
    group.add_argument("--max-cases", type=int, help="普通模式的一批 case 数；auto 模式的每批 case 数")
    group.add_argument("--timeout", type=float, help="单个请求超时时间，单位秒")
    group.add_argument("--healthcheck-every", type=int, help="每 N 个 case 执行一次健康检查")
    group.add_argument("--confirm-attempts", type=int, help="异常 case 重放确认次数")
    group.add_argument(
        "--profile",
        choices=["safe", "cmd-light", "cmd-timeout", "oob", "dangerous"],
        help="payload 集合：safe 安全边界；cmd-light 使用 id 类命令探测；cmd-timeout 使用 sleep 类探测；oob 使用 callback；dangerous 全开",
    )
    group.add_argument(
        "--strategy",
        choices=["priority", "path", "none"],
        help="case 排序策略：priority 优先高风险路径/参数；path 按路径排序；none 保持生成顺序",
    )


def apply_fuzz_overrides(config: AppConfig, args: argparse.Namespace) -> None:
    mapping = {
        "rate": "rate_limit_per_sec",
        "concurrency": "concurrency",
        "max_cases": "max_cases",
        "timeout": "request_timeout_sec",
        "healthcheck_every": "healthcheck_every",
        "confirm_attempts": "confirm_attempts",
        "profile": "profile",
        "strategy": "strategy",
    }
    for arg_name, field_name in mapping.items():
        value = getattr(args, arg_name, None)
        if value is not None:
            setattr(config.fuzz, field_name, value)


def apply_fast_mode(config: AppConfig, args: argparse.Namespace) -> None:
    if not getattr(args, "fast", False):
        return
    config.fuzz.rate_limit_per_sec = 0
    if getattr(args, "concurrency", None) is None:
        config.fuzz.concurrency = 50
    if getattr(args, "max_cases", None) is None:
        config.fuzz.max_cases = None
    if getattr(args, "confirm_attempts", None) is None:
        config.fuzz.confirm_attempts = 0
    if getattr(args, "healthcheck_every", None) is None:
        config.fuzz.healthcheck_every = 100
    print("[fast] 已启用拉满模式：不限速，减少确认和健康检查开销", flush=True)


async def run_auto_batches(
    config: AppConfig,
    monitors,
    recorder: FindingRecorder,
    cases,
    stop_on_finding: bool,
) -> None:
    batch_size = config.fuzz.max_cases or len(cases)
    if batch_size <= 0:
        raise SystemExit("--max-cases 必须大于 0")
    total_findings = 0
    total = len(cases)
    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        batch = cases[start:end]
        print(f"[auto] 开始批次 {start // batch_size + 1}: cases {start + 1}-{end}/{total}", flush=True)
        findings = await FuzzExecutor(config, monitors, recorder).run(batch)
        total_findings += findings
        print(f"[auto] 批次完成: findings={findings}, 累计 findings={total_findings}", flush=True)
        if stop_on_finding and findings > 0:
            print("[auto] 已发现 finding，按 --auto 策略终止", flush=True)
            break
    else:
        print(f"[auto] 所有批次完成，累计 findings={total_findings}", flush=True)


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

oob:
  # Used by --profile oob or dangerous payloads.
  # Start with: iotfuzz oob-http --host 0.0.0.0 --port 8088 --log oob/callbacks.jsonl
  http_url: ""

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
  # Optional later:
  # - type: ssh
  #   host: {target_ip}
  #   username: root
  #   identity_file: ~/.ssh/router_key
  #   evidence_commands:
  #     - "ps | grep -E '[h]ttpd|[u]httpd|[b]oa'"
  #     - "dmesg | tail -80"
  #     - "logread | tail -80"
  # - type: serial
  #   port: /dev/ttyUSB0
  #   baud: 115200
  #   capture_sec: 2

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
