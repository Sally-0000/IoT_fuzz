from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin


@dataclass(slots=True)
class TargetConfig:
    host: str
    base_url: str


@dataclass(slots=True)
class FuzzConfig:
    concurrency: int = 1
    rate_limit_per_sec: float = 2.0
    request_timeout_sec: float = 3.0
    healthcheck_every: int = 10
    confirm_attempts: int = 2
    max_cases: int | None = 1000
    profile: str = "safe"
    strategy: str = "priority"


@dataclass(slots=True)
class MonitorConfig:
    type: str
    values: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AppConfig:
    target: TargetConfig
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)
    monitors: list[MonitorConfig] = field(default_factory=list)
    auth: dict[str, Any] = field(default_factory=lambda: {"type": "none"})
    recovery: dict[str, Any] = field(default_factory=lambda: {"type": "manual"})

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "AppConfig":
        target_data = data.get("target") or {}
        if not target_data.get("base_url"):
            raise ValueError("target.base_url is required")
        target = TargetConfig(
            host=str(target_data.get("host") or target_data["base_url"]),
            base_url=str(target_data["base_url"]).rstrip("/"),
        )
        fuzz = FuzzConfig(**{**asdict(FuzzConfig()), **(data.get("fuzz") or {})})
        monitors = [
            MonitorConfig(type=str(item["type"]), values={k: v for k, v in item.items() if k != "type"})
            for item in data.get("monitors", [])
            if isinstance(item, dict) and item.get("type")
        ]
        return cls(
            target=target,
            fuzz=fuzz,
            monitors=monitors,
            auth=data.get("auth") or {"type": "none"},
            recovery=data.get("recovery") or {"type": "manual"},
        )


@dataclass(slots=True)
class RequestSeed:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    auth_required: bool = False
    source: str = "manual"

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RequestSeed":
        return cls(
            method=str(data.get("method", "GET")).upper(),
            path=str(data.get("path", "/")),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            query={str(k): str(v) for k, v in (data.get("query") or data.get("params") or {}).items()},
            data={str(k): str(v) for k, v in (data.get("data") or {}).items()},
            body=str(data["body"]) if data.get("body") is not None else None,
            auth_required=bool(data.get("auth_required", False)),
            source=str(data.get("source", "manual")),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "query": self.query,
            "data": self.data,
            "body": self.body,
            "auth_required": self.auth_required,
            "source": self.source,
        }

    def url(self, base_url: str) -> str:
        return urljoin(base_url.rstrip("/") + "/", self.path.lstrip("/"))


@dataclass(slots=True)
class FuzzCase:
    seed: RequestSeed
    location: str
    name: str
    original: str
    payload: str

    def id_hint(self) -> str:
        return f"{self.seed.method}_{self.seed.path}_{self.location}_{self.name}"
