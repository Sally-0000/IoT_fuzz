from __future__ import annotations

import re
from dataclasses import dataclass

from .models import FuzzCase


@dataclass(slots=True)
class Match:
    name: str
    severity: str
    detail: str


PASSWD_RE = re.compile(r"root:[^:\r\n]*:\d+:\d+:", re.I)
UID_RE = re.compile(r"\buid=0(?:\(|\b)|\bgid=0(?:\(|\b)", re.I)
STACK_RE = re.compile(
    r"(segmentation fault|sigsegv|sigbus|traceback|stack trace|assertion failed|"
    r"addresssanitizer|runtime error|core dumped|bus error|illegal instruction)",
    re.I,
)
SQL_RE = re.compile(r"(sql syntax|mysql_fetch|sqlite error|odbc|syntax error near)", re.I)


def match_response(text: str, case: FuzzCase) -> list[Match]:
    matches: list[Match] = []
    if not text:
        return matches
    if PASSWD_RE.search(text):
        matches.append(Match("etc_passwd", "high", "response contains passwd-style root entry"))
    if UID_RE.search(text):
        matches.append(Match("uid_zero", "high", "response contains uid=0/gid=0 command-output marker"))
    if STACK_RE.search(text):
        matches.append(Match("error_stack", "medium", "response contains crash/stack/error marker"))
    if SQL_RE.search(text):
        matches.append(Match("sql_error", "medium", "response contains SQL error marker"))
    payload = case.payload
    if payload and len(payload) <= 256 and payload in text:
        if "<script" in payload.lower():
            matches.append(Match("xss_reflection", "medium", "script payload reflected in response"))
        elif payload in {"'\"`", "%00"}:
            matches.append(Match("payload_reflection", "low", "special-character payload reflected in response"))
    return matches
