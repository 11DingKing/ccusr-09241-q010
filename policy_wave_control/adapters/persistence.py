"""JSON 文件持久化：每个聚合一份文件，原子写入；运行数据位于源码目录之外。"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from ..domain.models import PolicyException, PolicyVersion, TopologySnapshot
from ..domain.release import AuditLog, Rollout


class JsonRepository:
    """通用 JSON 仓库。

    entity_type 决定文件名与反序列化方式；save 采用临时文件 + 原子替换，
    避免服务重启时读到半写入状态。
    """

    _TYPES: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {}

    def __init_subclass__(cls, entity_type: str = "", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    def __init__(self, directory: str | Path, kind: str, loader: Callable[[dict[str, Any]], Any]) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.kind = kind
        self.loader = loader

    def _path(self, entity_id: str) -> Path:
        safe = entity_id.replace("/", "_")
        return self.dir / f"{self.kind}__{safe}.json"

    def save(self, entity: Any) -> None:
        data = entity.to_dict()
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self._path(getattr(entity, "id")))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def get(self, entity_id: str) -> Any | None:
        path = self._path(entity_id)
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as fh:
            return self.loader(json.load(fh))

    def all(self) -> list[Any]:
        items: list[Any] = []
        prefix = f"{self.kind}__"
        for path in sorted(self.dir.glob(f"{prefix}*.json")):
            with path.open(encoding="utf-8") as fh:
                items.append(self.loader(json.load(fh)))
        return items


class SnapshotRepository(JsonRepository):
    def __init__(self, directory: str | Path) -> None:
        super().__init__(directory, "snapshot", TopologySnapshot.from_dict)


class PolicyRepository(JsonRepository):
    def __init__(self, directory: str | Path) -> None:
        super().__init__(directory, "policy", PolicyVersion.from_dict)


class ExceptionRepository(JsonRepository):
    def __init__(self, directory: str | Path) -> None:
        super().__init__(directory, "exception", PolicyException.from_dict)


class RolloutRepository(JsonRepository):
    def __init__(self, directory: str | Path) -> None:
        super().__init__(directory, "rollout", Rollout.from_dict)


class JsonAuditStore:
    """审计日志单文件追加存储；载入时重放为 AuditLog。"""

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "audit.log.json"

    def load(self) -> AuditLog:
        if not self.path.exists():
            return AuditLog()
        with self.path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return AuditLog.from_list(data.get("entries", []))

    def store(self, log: AuditLog) -> None:
        payload = {"entries": log.to_list()}
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
