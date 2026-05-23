from __future__ import annotations

import sys
import time


class ProgressReporter:
    def __init__(self, total: int, enabled: bool = True) -> None:
        self.total = total
        self.enabled = enabled
        self.start = time.monotonic()
        self.last_print = 0.0
        self.findings = 0
        self.is_tty = sys.stderr.isatty()

    def increment_findings(self) -> None:
        self.findings += 1

    def update(self, current: int, force: bool = False) -> None:
        if not self.enabled or self.total <= 0:
            return
        now = time.monotonic()
        interval = 0.2 if self.is_tty else 10.0
        if not force and now - self.last_print < interval and current < self.total:
            return
        self.last_print = now
        elapsed = max(0.001, now - self.start)
        rate = current / elapsed
        remaining = max(0, self.total - current)
        eta = remaining / rate if rate > 0 else 0
        pct = (current / self.total) * 100
        line = (
            f"progress {current}/{self.total} {pct:5.1f}% "
            f"rate={rate:4.1f}/s eta={format_duration(eta)} findings={self.findings}"
        )
        if self.is_tty:
            sys.stderr.write("\r" + line[:160])
            sys.stderr.flush()
        else:
            print(line, file=sys.stderr)

    def message(self, text: str) -> None:
        if self.is_tty:
            sys.stderr.write("\n")
            sys.stderr.flush()
        print(text, file=sys.stderr)

    def finish(self) -> None:
        if self.enabled and self.is_tty:
            sys.stderr.write("\n")
            sys.stderr.flush()


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"
