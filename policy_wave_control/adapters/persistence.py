"""JSON 文件持久化适配：原子写，重启后可恢复发布游标与全部状态。"""

from __future__ import annotations

import json
import os
import tempfile

from ..domain.exceptions import PolicyException
from ..domain.policy import PolicyRule, PolicyVersion
from ..domain.release import Release
from ..domain.topology import CriticalService, Device, TopologySnapshot, Zone


class _JsonStore:
    def __init__(self, path: str) -> None:
        self._path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    def _atomic_write(self, payload) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self._path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def _read(self, default):
        if not os.path.exists(self._path):
            return default
        with open(self._path, "r", encoding="utf-8") as fh:
            return json.load(fh)


class JsonReleaseRepository(_JsonStore):
    def save(self, release: Release) -> None:
        self._atomic_write(release.to_dict())

    def get(self, release_id: str) -> Release:
        data = self._read(None)
        if data is None or data.get("release_id") != release_id:
            from ..domain.errors import NotFoundError
            raise NotFoundError(f"发布单不存在: {release_id}")
        return Release.from_dict(data)

    def exists(self) -> bool:
        return self._read(None) is not None

    def list_all(self) -> list[Release]:
        data = self._read(None)
        return [Release.from_dict(data)] if data else []


class InMemoryReleaseRepository:
    def __init__(self) -> None:
        self._release: Release | None = None

    def save(self, release: Release) -> None:
        self._release = release

    def get(self, release_id: str) -> Release:
        from ..domain.errors import NotFoundError
        if self._release is None or self._release.release_id != release_id:
            raise NotFoundError(f"发布单不存在: {release_id}")
        return self._release

    def list_all(self) -> list[Release]:
        return [self._release] if self._release else []


class CatalogStore(_JsonStore):
    """拓扑快照、策略版本、例外三类清单的 JSON 集合存储。"""

    def _items(self) -> dict:
        return self._read({})

    def _write_items(self, items: dict) -> None:
        self._atomic_write(items)


class TopologyRepository(CatalogStore):
    def save_snapshot(self, snapshot: TopologySnapshot) -> None:
        items = self._items()
        items[snapshot.snapshot_id] = snapshot.to_dict()
        items["__latest__"] = snapshot.snapshot_id
        self._write_items(items)

    def get_latest(self) -> TopologySnapshot:
        items = self._items()
        latest = items.get("__latest__")
        return self.get(latest) if latest else self._none()

    def get(self, snapshot_id: str) -> TopologySnapshot:
        items = self._items()
        data = items.get(snapshot_id)
        if data is None:
            from ..domain.errors import NotFoundError
            raise NotFoundError(f"拓扑快照不存在: {snapshot_id}")
        return _snapshot_from_dict(data)

    @staticmethod
    def _none():
        from ..domain.errors import NotFoundError
        raise NotFoundError("尚无拓扑快照")


class PolicyRepository(CatalogStore):
    def save(self, policy: PolicyVersion) -> None:
        items = self._items()
        items[policy.policy_id] = policy.to_dict()
        self._write_items(items)

    def get(self, policy_id: str) -> PolicyVersion:
        data = self._items().get(policy_id)
        if data is None:
            from ..domain.errors import NotFoundError
            raise NotFoundError(f"策略版本不存在: {policy_id}")
        return _policy_from_dict(data)

    def list_all(self) -> list[PolicyVersion]:
        return [_policy_from_dict(v) for k, v in self._items().items() if k != "__latest__"]


class ExceptionRepository(CatalogStore):
    def save(self, exc: PolicyException) -> None:
        items = self._items()
        items[exc.exception_id] = exc.to_dict()
        self._write_items(items)

    def get(self, exception_id: str) -> PolicyException:
        data = self._items().get(exception_id)
        if data is None:
            from ..domain.errors import NotFoundError
            raise NotFoundError(f"例外不存在: {exception_id}")
        return PolicyException(**data)

    def list_all(self) -> list[PolicyException]:
        return [PolicyException(**v) for k, v in self._items().items() if k != "__latest__"]

    def active_for(self, rule_id: str, zone_id: str, now_iso: str) -> PolicyException | None:
        for exc in self.list_all():
            if exc.rule_id == rule_id and exc.zone_id == zone_id and exc.is_active(now_iso):
                return exc
        return None


class InMemoryCatalog:
    """拓扑/策略/例外三合一的内存仓储（离线场景运行器用）。"""

    def __init__(self) -> None:
        self._snapshots: dict[str, TopologySnapshot] = {}
        self._latest: str | None = None
        self._policies: dict[str, PolicyVersion] = {}
        self._exceptions: dict[str, PolicyException] = {}

    # topology
    def save_snapshot(self, snapshot: TopologySnapshot) -> None:
        self._snapshots[snapshot.snapshot_id] = snapshot
        self._latest = snapshot.snapshot_id

    def get_latest(self) -> TopologySnapshot:
        from ..domain.errors import NotFoundError
        if self._latest is None:
            raise NotFoundError("尚无拓扑快照")
        return self._snapshots[self._latest]

    def get(self, snapshot_id: str) -> TopologySnapshot:
        from ..domain.errors import NotFoundError
        if snapshot_id not in self._snapshots:
            raise NotFoundError(f"拓扑快照不存在: {snapshot_id}")
        return self._snapshots[snapshot_id]

    # policy
    def save_policy(self, policy: PolicyVersion) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> PolicyVersion:
        from ..domain.errors import NotFoundError
        if policy_id not in self._policies:
            raise NotFoundError(f"策略版本不存在: {policy_id}")
        return self._policies[policy_id]

    def list_policies(self) -> list[PolicyVersion]:
        return list(self._policies.values())

    # exceptions
    def save_exception(self, exc: PolicyException) -> None:
        self._exceptions[exc.exception_id] = exc

    def get_exception(self, exception_id: str) -> PolicyException:
        from ..domain.errors import NotFoundError
        if exception_id not in self._exceptions:
            raise NotFoundError(f"例外不存在: {exception_id}")
        return self._exceptions[exception_id]

    def list_exceptions(self) -> list[PolicyException]:
        return list(self._exceptions.values())

    def active_for(self, rule_id: str, zone_id: str, now_iso: str) -> PolicyException | None:
        for exc in self._exceptions.values():
            if exc.rule_id == rule_id and exc.zone_id == zone_id and exc.is_active(now_iso):
                return exc
        return None


def _snapshot_from_dict(data: dict) -> TopologySnapshot:
    return TopologySnapshot(
        snapshot_id=data["snapshot_id"],
        version=data["version"],
        taken_at=data["taken_at"],
        zones=tuple(Zone(**z) for z in data["zones"]),
        devices=tuple(
            Device(d["device_id"], d["zone_id"], frozenset(d["capabilities"]),
                   d["firmware"], d.get("critical", False))
            for d in data["devices"]
        ),
        services=tuple(CriticalService(**s) for s in data["services"]),
    )


def _policy_from_dict(data: dict) -> PolicyVersion:
    return PolicyVersion(
        policy_id=data["policy_id"],
        version=data["version"],
        created_at=data["created_at"],
        rules=tuple(PolicyRule(**r) for r in data["rules"]),
        depends_on={k: tuple(v) for k, v in data.get("depends_on", {}).items()},
        note=data.get("note", ""),
    )
