"""应用组装：把端口与适配器接成可用的服务。"""

from __future__ import annotations

import os

from .adapters.audit_log import AppendOnlyAuditLog, InMemoryAuditLog
from .adapters.gateway import SimulatedDeviceGateway
from .adapters.persistence import (
    ExceptionRepository,
    InMemoryCatalog,
    InMemoryReleaseRepository,
    JsonReleaseRepository,
    PolicyRepository,
    TopologyRepository,
)
from .adapters.runtime import FixedClock, PersistentIdGenerator, SequentialIdGenerator, SystemClock
from .application.service import ReleaseService


def build_service(data_dir: str | None = None, *, clock=None,
                  in_memory: bool = False) -> ReleaseService:
    """组装服务。

    data_dir 为 None 时使用内存实现（离线场景运行器/测试）；
    否则在该目录下落盘（JSON + JSONL），重启后状态与游标完整恢复。
    """
    clock = clock or (FixedClock() if in_memory else SystemClock())

    if in_memory or data_dir is None:
        idgen = SequentialIdGenerator()
        catalog = _InMemoryCatalogAdapter(InMemoryCatalog())
        release_repo = InMemoryReleaseRepository()
        audit = InMemoryAuditLog(clock)
    else:
        os.makedirs(data_dir, exist_ok=True)
        idgen = PersistentIdGenerator(os.path.join(data_dir, "id_counters.json"))
        catalog = _FileCatalogAdapter(
            TopologyRepository(os.path.join(data_dir, "topology.json")),
            PolicyRepository(os.path.join(data_dir, "policy.json")),
            ExceptionRepository(os.path.join(data_dir, "exceptions.json")),
        )
        release_repo = JsonReleaseRepository(os.path.join(data_dir, "release.json"))
        audit = AppendOnlyAuditLog(os.path.join(data_dir, "audit.log.jsonl"), clock)

    gateway = SimulatedDeviceGateway(clock)
    return ReleaseService(
        catalog=catalog, release_repo=release_repo, audit=audit,
        gateway=gateway, clock=clock, idgen=idgen,
    )


class _InMemoryCatalogAdapter:
    """统一 catalog 端口的方法名，供服务层调用。"""

    def __init__(self, inner: InMemoryCatalog) -> None:
        self.inner = inner

    def save_snapshot(self, snapshot) -> None:
        self.inner.save_snapshot(snapshot)

    def get(self, snapshot_id: str):
        return self.inner.get(snapshot_id)

    def get_latest(self):
        return self.inner.get_latest()

    def save_policy(self, policy) -> None:
        self.inner.save_policy(policy)

    def get_policy(self, policy_id: str):
        return self.inner.get_policy(policy_id)

    def list_policies(self):
        return self.inner.list_policies()

    def save_exception(self, exc) -> None:
        self.inner.save_exception(exc)

    def get_exception(self, exception_id: str):
        return self.inner.get_exception(exception_id)

    def list_exceptions(self):
        return self.inner.list_exceptions()

    def active_for(self, rule_id: str, zone_id: str, now_iso: str):
        return self.inner.active_for(rule_id, zone_id, now_iso)


class _FileCatalogAdapter:
    def __init__(self, topo: TopologyRepository, policy: PolicyRepository,
                 exc: ExceptionRepository) -> None:
        self._topo = topo
        self._policy = policy
        self._exc = exc

    def save_snapshot(self, snapshot) -> None:
        self._topo.save_snapshot(snapshot)

    def get(self, snapshot_id: str):
        return self._topo.get(snapshot_id)

    def get_latest(self):
        return self._topo.get_latest()

    def save_policy(self, policy) -> None:
        self._policy.save(policy)

    def get_policy(self, policy_id: str):
        return self._policy.get(policy_id)

    def list_policies(self):
        return self._policy.list_all()

    def save_exception(self, exc) -> None:
        self._exc.save(exc)

    def get_exception(self, exception_id: str):
        return self._exc.get(exception_id)

    def list_exceptions(self):
        return self._exc.list_all()

    def active_for(self, rule_id: str, zone_id: str, now_iso: str):
        return self._exc.active_for(rule_id, zone_id, now_iso)
