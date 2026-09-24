"""时间、标识等可替换端口。"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Protocol


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return utc_now()


class ScriptedClock:
    """测试/离线场景使用的脚本时钟，可显式设定与推进。"""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or utc_now()

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("脚本时钟必须使用带时区的时间")
        self._now = value

    def advance(self, seconds: float) -> datetime:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)
        return self._now


class IdGenerator(Protocol):
    def new(self, prefix: str) -> str: ...


class UuidIds:
    def new(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:12]}"


class SequentialIds:
    """确定性标识生成器，便于离线场景稳定复现与断言。"""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def new(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n:03d}"
