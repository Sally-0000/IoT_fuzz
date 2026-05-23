# iotfuzz

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

Analyze a rootfs and generate seed requests:

```bash
iotfuzz analyze-rootfs ./rootfs --out corpus/seeds.jsonl
```

Import captured browser traffic:

```bash
iotfuzz import-har traffic.har --out corpus/har-seeds.jsonl
```

Run against a real device:

```bash
iotfuzz run --target examples/target.yaml --seeds corpus/seeds.jsonl --out findings
```

Replay a finding:

```bash
iotfuzz replay findings/FND-000001/finding.json
```

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
