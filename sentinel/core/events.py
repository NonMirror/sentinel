"""事件驱动总线 (架构图中的 "事件驱动" 组件).

同步、线程安全的发布/订阅实现。生产者在 WAF/扫描器管道中调用
:meth:`EventBus.publish`, TUI 与审计组件通过 :meth:`EventBus.subscribe` 消费。
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from itertools import count
from typing import Any, Callable, Iterable


class Topic(str):
    """常用主题常量 (str 子类, 便于直接传字符串)."""

    REQUEST = "request"
    DECISION = "decision"
    BLOCK = "block"
    IDS = "ids"
    AUDIT = "audit"
    SCAN_FINDING = "scan.finding"
    SCAN_PROGRESS = "scan.progress"
    METRIC = "metric"
    CONFIG = "config"
    LIFECYCLE = "lifecycle"


@dataclass(slots=True)
class Event:
    topic: str
    payload: Any = None
    ts: float = field(default_factory=time.time)
    seq: int = 0


Handler = Callable[[Event], None]


class EventBus:
    """轻量事件总线, 支持通配符 ``*`` 订阅与有界历史回放."""

    def __init__(self, history: int = 2000) -> None:
        self._subs: dict[str, list[Handler]] = {}
        self._history: deque[Event] = deque(maxlen=history)
        self._lock = threading.RLock()
        self._seq = count(1)
        self.published = 0

    def subscribe(self, topic: str, handler: Handler) -> Callable[[], None]:
        with self._lock:
            self._subs.setdefault(topic, []).append(handler)
        return lambda: self.unsubscribe(topic, handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        with self._lock:
            handlers = self._subs.get(topic)
            if handlers and handler in handlers:
                handlers.remove(handler)

    def publish(self, topic: str, payload: Any = None) -> Event:
        event = Event(topic=topic, payload=payload, seq=next(self._seq))
        with self._lock:
            handlers = list(self._subs.get(topic, ())) + list(self._subs.get("*", ()))
            self._history.append(event)
            self.published += 1
        for handler in handlers:
            try:
                handler(event)
            except Exception:  # 单个订阅者异常不得影响主链路
                continue
        return event

    def history(self, topic: str | None = None, limit: int = 100) -> list[Event]:
        with self._lock:
            events: Iterable[Event] = list(self._history)
        if topic:
            events = [e for e in events if e.topic == topic]
        return list(events)[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
