"""时间与标识生成适配器。"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone


class SystemClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FixedClock:
    """可复现场景用：从固定起点推进；now() 默认不自动跳时，用 advance 控制。"""

    def __init__(self, start: str = "2026-09-24T00:00:00+00:00") -> None:
        self._dt = datetime.fromisoformat(start)

    def now(self) -> str:
        return self._dt.isoformat(timespec="seconds")

    def advance(self, seconds: int) -> str:
        self._dt = self._dt + timedelta(seconds=seconds)
        return self.now()

    def set(self, iso_ts: str) -> None:
        self._dt = datetime.fromisoformat(iso_ts)


class SequentialIdGenerator:
    """prefix-0001 形式的稳定 ID；同一前缀独立计数。"""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def new_id(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n:04d}"

    def state(self) -> dict[str, int]:
        return dict(self._counters)

    def load_state(self, state: dict[str, int]) -> None:
        self._counters = dict(state)


class PersistentIdGenerator(SequentialIdGenerator):
    """计数器落盘的 ID 生成器，服务重启后不回绕。"""

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self.load_state(json.load(fh))

    def new_id(self, prefix: str) -> str:
        result = super().new_id(prefix)
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.state(), fh)
            os.replace(tmp, self._path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return result
