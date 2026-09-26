"""日志审计模块: 结构化审计记录 + 环形缓冲 + 可选落盘."""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass(slots=True)
class AuditRecord:
    action: str
    client: str
    method: str
    url: str
    status: int
    severity: str = "info"
    rules: tuple[int, ...] = ()
    backend: str = ""
    latency_ms: float = 0.0
    bytes_out: int = 0
    extra: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_line(self) -> str:
        return json.dumps(
            {
                "ts": round(self.ts, 6),
                "action": self.action,
                "client": self.client,
                "method": self.method,
                "url": self.url,
                "status": self.status,
                "severity": self.severity,
                "rules": list(self.rules),
                "backend": self.backend,
                "latency_ms": round(self.latency_ms, 3),
                "bytes_out": self.bytes_out,
                **({"extra": self.extra} if self.extra else {}),
            },
            ensure_ascii=False,
        )


class AuditLog:
    """线程安全审计日志. 支持内存检索与（可选）JSONL 落盘."""

    def __init__(self, capacity: int = 20000, path: str | None = None) -> None:
        self._records: deque[AuditRecord] = deque(maxlen=capacity)
        self._lock = threading.RLock()
        self.path = path
        self.total = 0
        self._fp = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._fp = open(path, "a", encoding="utf-8")

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)
            self.total += 1
            if self._fp is not None:
                self._fp.write(record.to_line() + "\n")
                self._fp.flush()

    def __len__(self) -> int:
        return len(self._records)

    def recent(self, limit: int = 100) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)[-limit:]

    def search(self, needle: str = "", severity: str | None = None,
               action: str | None = None, limit: int = 500) -> list[AuditRecord]:
        needle = needle.lower()
        out: list[AuditRecord] = []
        with self._lock:
            for rec in reversed(self._records):
                if severity and rec.severity != severity:
                    continue
                if action and rec.action != action:
                    continue
                if needle and needle not in f"{rec.url} {rec.client} {rec.action}".lower():
                    continue
                out.append(rec)
                if len(out) >= limit:
                    break
        return out

    def counts_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._lock:
            for rec in self._records:
                counts[rec.action] = counts.get(rec.action, 0) + 1
        return counts

    def __iter__(self) -> Iterator[AuditRecord]:
        return iter(self.recent(len(self._records)))

    def close(self) -> None:
        with self._lock:
            if self._fp is not None:
                self._fp.close()
                self._fp = None
