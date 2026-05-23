# IoT_fuzz

`iotfuzz` is a Python toolkit for low-rate, structured HTTP fuzzing against real router/IoT devices. Firmware/rootfs data is used offline to build request seeds; fuzz execution happens against the physical device.

## v0.1 Scope

- Target configuration through JSON or YAML.
- Rootfs URL/form/parameter extraction.
- HAR import for authenticated real traffic seeds.
- Single-device HTTP fuzzing with conservative rate limits.
- Ping, HTTP, and TCP health checks.
- Finding bundles with raw request/response and replay metadata.
- Replay of saved finding cases.

SSH and serial shell monitors are intentionally left as later plugins.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[yaml]'
```

If you do not need YAML, `pip install -e .` is enough and JSON configs still work.

## Quick Start

Create a workspace anywhere, then initialize the target config:

```bash
mkdir -p ~/router-fuzz/run1
cd ~/router-fuzz/run1
iotfuzz init --target-ip 192.168.1.1
```

Analyze a rootfs and generate seed requests:

```bash
iotfuzz analyze-rootfs ./rootfs
```

Import captured browser traffic:

```bash
iotfuzz import-har traffic.har
```

Run against a real device:

```bash
iotfuzz run
```

Auto mode scans in batches using `--max-cases` as the batch size:

```bash
# Run the first batch; if no finding appears, keep scanning batch by batch.
# Stop as soon as a finding is found.
iotfuzz run --auto --max-cases 200 --rate 1

# Scan every batch until all generated cases are finished.
# Findings do not stop the run.
iotfuzz run --fin-auto --max-cases 500 --rate 2
```

Override fuzz parameters from the CLI:

```bash
iotfuzz run --max-cases 500 --rate 2 --timeout 3
iotfuzz run --profile dangerous --max-cases 100 --rate 1
iotfuzz run --seeds corpus/har-seeds.jsonl --out findings-har
```

Preview the prioritized run plan before sending traffic:

```bash
iotfuzz plan --top 30
iotfuzz plan --top 50 --max-cases 500 --rate 2
```

Replay a finding:

```bash
iotfuzz replay findings/FND-000001/finding.json
```

The default workspace paths are:

- `target.yaml`
- `corpus/seeds.jsonl`
- `findings/`

You can still override them with `--target`, `--seeds`, and `--out`.

## Common Fuzz Options

These options work with both `iotfuzz plan` and `iotfuzz run`:

```text
--rate N                 requests per second
--max-cases N            cap the number of cases
--timeout N              per-request timeout in seconds
--healthcheck-every N    run monitors every N cases
--confirm-attempts N     replay abnormal cases N times
--profile safe|cmd-light|cmd-timeout|oob|dangerous payload set
--strategy priority|path|none case ordering
```

Examples:

```bash
# Fast smoke test
iotfuzz run --max-cases 100 --rate 1 --confirm-attempts 1

# Prioritized first pass
iotfuzz run --max-cases 1000 --rate 2 --strategy priority

# Focus on HAR traffic captured from authenticated UI actions
iotfuzz run --seeds corpus/har-seeds.jsonl --max-cases 300 --rate 1

# Light command-injection probes such as ;id
iotfuzz run --profile cmd-light --max-cases 100 --rate 1

# Timeout command-injection probes such as ;sleep 3
iotfuzz run --profile cmd-timeout --max-cases 50 --rate 0.5 --timeout 5
```

## Matchers

`iotfuzz` records findings not only for timeouts and HTTP 5xx responses, but also for response content matches:

- `/etc/passwd` style `root:` entries
- `uid=0` / `gid=0` command-output markers
- crash or stack markers such as `segmentation fault`, `SIGSEGV`, `Traceback`, `core dumped`
- SQL error markers
- reflected XSS payloads

Matcher hits are saved in `finding.json` under `matches`.

## SSH And Serial Evidence

Optional monitors can collect stronger evidence when a finding is recorded:

```yaml
monitors:
  - type: ssh
    host: 192.168.1.1
    username: root
    identity_file: ~/.ssh/router_key
    evidence_commands:
      - "ps | grep -E '[h]ttpd|[u]httpd|[b]oa'"
      - "dmesg | tail -80"
      - "logread | tail -80"

  - type: serial
    port: /dev/ttyUSB0
    baud: 115200
    capture_sec: 2
```

SSH uses the system `ssh` client with `BatchMode=yes`, so key-based login should already work. Serial collection captures a short log slice when a finding is recorded.

## OOB Callback

Start a local callback logger:

```bash
iotfuzz oob-http --host 0.0.0.0 --port 8088 --log oob/callbacks.jsonl
```

Set the callback URL in `target.yaml`:

```yaml
oob:
  http_url: http://YOUR_LAPTOP_IP:8088/cb
```

Then run OOB payloads:

```bash
iotfuzz run --profile oob --max-cases 100 --rate 1
```

Callbacks are appended to `oob/callbacks.jsonl`. This is useful for command injection and SSRF checks where the HTTP response does not show command output.

## Reducer

Minimize a saved finding payload:

```bash
iotfuzz reduce findings/FND-000001/finding.json --target target.yaml
```

The reducer tries shorter payload candidates and reports the smallest payload that still triggers a similar signal.

## Target Config

See [examples/target.yaml](examples/target.yaml).

Supported auth modes in v0.1:

```yaml
auth:
  type: none
```

```yaml
auth:
  type: basic
  username: admin
  password: admin
```

```yaml
auth:
  type: form
  login_url: /login.cgi
  method: POST
  data:
    username: admin
    password: admin
```

By default `iotfuzz` ignores system proxy environment variables during fuzzing and HTTP health checks, which avoids accidentally sending router traffic through a local or corporate proxy.

For first contact with a real device, use a small `max_cases` and priority scheduling:

```yaml
fuzz:
  rate_limit_per_sec: 1
  healthcheck_every: 10
  confirm_attempts: 1
  max_cases: 200
  profile: safe
  strategy: priority
```
