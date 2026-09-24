"""测试夹具：内存仓库与脚本化时钟。"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from typing import Any

from policy_wave_control.application.ports import ScriptedClock, SequentialIds
from policy_wave_control.application.services import ReleaseService, RollbackStep
from policy_wave_control.domain.release import AuditLog

T0 = datetime(2026, 9, 24, 2, 0, 0, tzinfo=timezone.utc)


class MemoryRepository:
    def __init__(self) -> None:
        self._items: dict[str, Any] = {}

    def save(self, entity: Any) -> None:
        self._items[entity.id] = entity

    def get(self, entity_id: str) -> Any | None:
        return self._items.get(entity_id)

    def all(self) -> list[Any]:
        return list(self._items.values())


class MemoryAuditStore:
    def __init__(self) -> None:
        self.log = AuditLog()

    def load(self) -> AuditLog:
        return self.log

    def store(self, log: AuditLog) -> None:
        self.log = log


class ScriptedFailures:
    def __init__(self, fail_devices: set[str]) -> None:
        self.fail_devices = fail_devices
        self.calls: list[str] = []

    def undo(self, step: RollbackStep) -> bool:
        self.calls.append(step.device_id)
        return step.device_id not in self.fail_devices


class ServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ScriptedClock(T0)
        self.ids = SequentialIds()
        self.snapshots = MemoryRepository()
        self.policies = MemoryRepository()
        self.exceptions = MemoryRepository()
        self.rollouts = MemoryRepository()
        self.audit_store = MemoryAuditStore()
        self.service = ReleaseService(
            snapshots=self.snapshots,
            policies=self.policies,
            exceptions=self.exceptions,
            rollouts=self.rollouts,
            audit_store=self.audit_store,
            clock=self.clock,
            ids=self.ids,
        )

    def build_standard_world(self) -> tuple[str, str]:
        snapshot = self.service.add_snapshot(
            name="标准三区域",
            zones=[
                {"id": "zp", "name": "个人区", "kind": "personal"},
                {"id": "zm", "name": "机器区", "kind": "machine", "default_policy": "deny"},
                {"id": "zi", "name": "物联区", "kind": "iot"},
            ],
            devices=[
                {"id": "p1", "zone_id": "zp", "name": "p1", "capabilities": ["acl-v2"]},
                {"id": "p2", "zone_id": "zp", "name": "p2", "capabilities": ["acl-v2"]},
                {"id": "p3", "zone_id": "zp", "name": "p3-old", "capabilities": ["acl-v1"]},
                {"id": "m1", "zone_id": "zm", "name": "m1", "capabilities": ["acl-v2", "acl-log"]},
                {"id": "m2", "zone_id": "zm", "name": "m2", "capabilities": ["acl-v2", "acl-log"]},
                {"id": "i1", "zone_id": "zi", "name": "i1-critical", "capabilities": ["acl-v2"], "critical": True},
                {"id": "i2", "zone_id": "zi", "name": "i2", "capabilities": ["acl-v2"]},
            ],
            edges=[
                {"src_zone": "zp", "dst_zone": "zi", "service": "http"},
                {"src_zone": "zm", "dst_zone": "zp", "service": "ssh"},
                {"src_zone": "zi", "dst_zone": "zm", "service": "telemetry", "critical": True},
            ],
            actor="admin",
        )
        policy = self.service.add_policy(
            name="策略v1",
            snapshot_id=snapshot.id,
            rules=[
                {"id": "rb", "name": "封http", "action": "deny", "src_zone": "zp",
                 "dst_zone": "zi", "service": "http", "requires": ["acl-v2"]},
                {"id": "rs", "name": "封ssh", "action": "deny", "src_zone": "zm",
                 "dst_zone": "zp", "service": "ssh", "requires": ["acl-v2", "acl-log"],
                 "depends_on": ["rb"]},
                {"id": "rt", "name": "放遥测", "action": "allow", "src_zone": "zi",
                 "dst_zone": "zm", "service": "telemetry", "requires": ["acl-v2"],
                 "depends_on": ["rb"]},
            ],
            actor="sec",
        )
        return snapshot.id, policy.id
