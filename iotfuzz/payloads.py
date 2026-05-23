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

DANGEROUS_PAYLOADS = [
    ";id",
    "&&id",
    "|id",
    "`id`",
    "$(id)",
    ";sleep 3",
    "&&sleep 3",
]


def payloads_for_profile(profile: str) -> list[str]:
    if profile == "dangerous":
        return SAFE_PAYLOADS + DANGEROUS_PAYLOADS
    return SAFE_PAYLOADS
