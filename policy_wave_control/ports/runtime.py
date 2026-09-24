"""端口：时间与标识生成，保证业务过程可复现。"""

from __future__ import annotations

from typing import Protocol


class Clock(Protocol):
    def now(self) -> str:
        """返回 UTC ISO8601 时间字符串。"""
        ...


class IdGenerator(Protocol):
    def new_id(self, prefix: str) -> str:
        ...
