"""发布聚合：批次、设备命令、回执状态机、健康闸门与回退计划。"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

from .models import DomainError

# ---------------------------------------------------------------- 发布状态

ROLLOUT_PLANNED = "planned"
ROLLOUT_ACTIVE = "active"
ROLLOUT_PAUSED = "paused"
ROLLOUT_ROLLING_BACK = "rolling_back"
ROLLOUT_ROLLED_BACK = "rolled_back"
ROLLOUT_PARTIALLY_ROLLED_BACK = "partially_rolled_back"
ROLLOUT_COMPLETED = "completed"
ROLLOUT_BLOCKED = "blocked"

BATCH_PENDING = "pending"          # 尚未开始
BATCH_IN_FLIGHT = "in_flight"
BATCH_COMPLETED = "completed"
BATCH_HELD = "held"               # 恶化时暂停、未开始的批次
BATCH_ROLLED_BACK = "rolled_back"
BATCH_PARTIALLY_ROLLED_BACK = "partially_rolled_back"

CMD_PENDING = "pending"
CMD_DISPATCHED = "dispatched"
CMD_ACKED = "acked"
CMD_APPLIED = "applied"
CMD_FAILED = "failed"

# 同一次下发内，回执状态只允许沿此秩单调推进；
# APPLIED 为终态成功，晚到的失败/确认不得覆盖。
_STATE_RANK = {
    CMD_PENDING: 0,
    CMD_DISPATCHED: 1,
    CMD_ACKED: 2,
    CMD_FAILED: 3,
    CMD_APPLIED: 4,
}

STEP_PENDING = "pending"
STEP_DONE = "done"
STEP_FAILED = "failed"


# ---------------------------------------------------------------- 审计

def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def hash_entry(entry: dict[str, Any], prev_hash: str) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    body["prev_hash"] = prev_hash
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    ts: datetime
    actor: str
    action: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        return cls(
            seq=data["seq"],
            ts=datetime.fromisoformat(data["ts"]),
            actor=data["actor"],
            action=data["action"],
            payload=data.get("payload", {}),
            prev_hash=data["prev_hash"],
            hash=data["hash"],
        )


class AuditLog:
    """追加式、哈希链式日志；任何业务动作都必须经此留痕。"""

    GENESIS = "GENESIS"

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, ts: datetime, actor: str, action: str, payload: dict[str, Any]) -> AuditEntry:
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].hash if self._entries else self.GENESIS
        base: dict[str, Any] = {
            "seq": seq,
            "ts": ts.isoformat(),
            "actor": actor,
            "action": action,
            "payload": payload,
        }
        digest = hash_entry(base, prev_hash)
        entry = AuditEntry(
            seq=seq,
            ts=ts,
            actor=actor,
            action=action,
            payload=payload,
            prev_hash=prev_hash,
            hash=digest,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify(self) -> dict[str, Any]:
        """重算整条哈希链，返回校验结论与首个断裂位置。"""
        prev = self.GENESIS
        for entry in self._entries:
            expected = hash_entry(
                {
                    "seq": entry.seq,
                    "ts": entry.ts.isoformat(),
                    "actor": entry.actor,
                    "action": entry.action,
                    "payload": entry.payload,
                },
                prev,
            )
            if entry.prev_hash != prev:
                return {"ok": False, "broken_at": entry.seq, "reason": "prev_hash 不衔接"}
            if entry.hash != expected:
                return {"ok": False, "broken_at": entry.seq, "reason": "哈希不匹配，记录可能被篡改"}
            prev = entry.hash
        return {"ok": True, "entries": len(self._entries), "last_hash": prev}

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries]

    @classmethod
    def from_list(cls, items: list[dict[str, Any]]) -> "AuditLog":
        log = cls()
        log._entries = [AuditEntry.from_dict(i) for i in items]
        return log


# ---------------------------------------------------------------- 命令与回执

@dataclass
class Receipt:
    command_id: str
    revision: int
    claimed_state: str
    produced_at: datetime
    received_at: datetime
    accepted: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "produced_at": self.produced_at.isoformat(),
            "received_at": self.received_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Receipt":
        return cls(
            command_id=d["command_id"],
            revision=d["revision"],
            claimed_state=d["claimed_state"],
            produced_at=datetime.fromisoformat(d["produced_at"]),
            received_at=datetime.fromisoformat(d["received_at"]),
            accepted=d["accepted"],
            reason=d.get("reason", ""),
        )


@dataclass
class Command:
    id: str
    batch_index: int
    rule_id: str
    device_id: str
    topo_seq: int  # 规则依赖拓扑序（下发升序、回退逆序）
    state: str = CMD_PENDING
    revision: int = 0
    dispatched_at: datetime | None = None
    updated_at: datetime | None = None
    duplicate_dispatches: int = 0
    receipts: list[Receipt] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"b{self.batch_index}:{self.rule_id}@{self.device_id}"

    def mark_dispatched(self, at: datetime) -> bool:
        """返回 True 表示这是一次新下发；False 表示重复命令被幂等忽略。"""
        if self.state in (CMD_APPLIED,):
            # 已完成的命令再次下发：计重复，不重开状态
            self.duplicate_dispatches += 1
            return False
        if self.state == CMD_DISPATCHED and self.revision > 0:
            self.duplicate_dispatches += 1
            return False
        self.revision += 1
        self.state = CMD_DISPATCHED
        self.dispatched_at = at
        self.updated_at = at
        return True

    def apply_receipt(self, revision: int, claimed: str, produced_at: datetime, received_at: datetime) -> tuple[bool, str]:
        """应用回执。旧版本回执或状态回退都会被拒绝，绝不覆盖较新状态。"""
        if claimed not in _STATE_RANK:
            return False, f"未知回执状态 {claimed}"
        if revision < self.revision:
            return False, (
                f"过期回执：回执版本 r{revision} 早于命令当前版本 r{self.revision}，"
                "拒绝覆盖"
            )
        if revision > self.revision:
            return False, (
                f"乱序回执：回执版本 r{revision} 超前于命令当前版本 r{self.revision}，"
                "尚无对应下发"
            )
        if _STATE_RANK[claimed] < _STATE_RANK[self.state]:
            return False, (
                f"乱序回执：{claimed}(秩{_STATE_RANK[claimed]}) 晚到，"
                f"当前状态 {self.state}(秩{_STATE_RANK[self.state]})，拒绝回退"
            )
        if _STATE_RANK[claimed] == _STATE_RANK[self.state]:
            return False, f"重复回执：状态已经是 {self.state}，幂等忽略"
        self.state = claimed
        self.updated_at = received_at
        return True, "accepted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "batch_index": self.batch_index,
            "rule_id": self.rule_id,
            "device_id": self.device_id,
            "topo_seq": self.topo_seq,
            "state": self.state,
            "revision": self.revision,
            "dispatched_at": self.dispatched_at.isoformat() if self.dispatched_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "duplicate_dispatches": self.duplicate_dispatches,
            "receipts": [r.to_dict() for r in self.receipts],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Command":
        return cls(
            id=d["id"],
            batch_index=d["batch_index"],
            rule_id=d["rule_id"],
            device_id=d["device_id"],
            topo_seq=d["topo_seq"],
            state=d["state"],
            revision=d["revision"],
            dispatched_at=datetime.fromisoformat(d["dispatched_at"]) if d.get("dispatched_at") else None,
            updated_at=datetime.fromisoformat(d["updated_at"]) if d.get("updated_at") else None,
            duplicate_dispatches=d.get("duplicate_dispatches", 0),
            receipts=[Receipt.from_dict(r) for r in d.get("receipts", [])],
        )


# ---------------------------------------------------------------- 证据与审批

@dataclass
class Evidence:
    id: str
    batch_index: int
    metric: str
    value: float
    source: str
    adopted_by: str
    at: datetime
    in_range: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"at": self.at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(
            id=d["id"],
            batch_index=d["batch_index"],
            metric=d["metric"],
            value=d["value"],
            source=d["source"],
            adopted_by=d["adopted_by"],
            at=datetime.fromisoformat(d["at"]),
            in_range=d["in_range"],
        )


@dataclass
class Approval:
    role: str
    actor: str
    at: datetime
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"at": self.at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Approval":
        return cls(role=d["role"], actor=d["actor"], at=datetime.fromisoformat(d["at"]), comment=d.get("comment", ""))


# ---------------------------------------------------------------- 批次与计划

@dataclass
class Gate:
    min_applied_ratio: float = 1.0
    # metric -> {"min": x?, "max": y?}
    metrics: dict[str, dict[str, float]] = field(default_factory=dict)
    min_evidence: int = 1

    def evaluate(self, commands: list[Command], evidence: list[Evidence]) -> dict[str, Any]:
        total = len(commands)
        applied = sum(1 for c in commands if c.state == CMD_APPLIED)
        ratio = applied / total if total else 0.0
        latest: dict[str, Evidence] = {}
        for ev in evidence:
            latest[ev.metric] = ev  # 采纳顺序即时间顺序，后者为最新
        metric_results: dict[str, Any] = {}
        metrics_ok = True
        for name, bounds in self.metrics.items():
            ev = latest.get(name)
            if ev is None:
                metric_results[name] = {"ok": False, "reason": "缺少证据"}
                metrics_ok = False
                continue
            lo = bounds.get("min")
            hi = bounds.get("max")
            ok = True
            reasons = []
            if lo is not None and ev.value < lo:
                ok = False
                reasons.append(f"{ev.value} < 下限 {lo}")
            if hi is not None and ev.value > hi:
                ok = False
                reasons.append(f"{ev.value} > 上限 {hi}")
            metric_results[name] = {"ok": ok, "value": ev.value, "reason": "; ".join(reasons)}
            metrics_ok = metrics_ok and ok
        enough_evidence = len(evidence) >= self.min_evidence
        ratio_ok = ratio + 1e-9 >= self.min_applied_ratio
        return {
            "passed": ratio_ok and metrics_ok and enough_evidence,
            "applied_ratio": round(ratio, 4),
            "ratio_ok": ratio_ok,
            "metrics_ok": metrics_ok,
            "enough_evidence": enough_evidence,
            "metrics": metric_results,
        }

    def check_breach(self, evidence: list[Evidence]) -> dict[str, Any]:
        """单看指标是否越界（供“观测恶化自动暂停”使用）。"""
        latest: dict[str, Evidence] = {}
        for ev in evidence:
            latest[ev.metric] = ev
        breached: list[dict[str, Any]] = []
        for name, bounds in self.metrics.items():
            ev = latest.get(name)
            if ev is None:
                continue
            lo, hi = bounds.get("min"), bounds.get("max")
            if (lo is not None and ev.value < lo) or (hi is not None and ev.value > hi):
                breached.append({"metric": name, "value": ev.value, "bounds": bounds})
        return {"breached": bool(breached), "items": breached}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Gate":
        return cls(
            min_applied_ratio=d.get("min_applied_ratio", 1.0),
            metrics=d.get("metrics", {}),
            min_evidence=d.get("min_evidence", 1),
        )


@dataclass
class Batch:
    index: int
    name: str
    is_canary: bool
    zone_ids: list[str]
    commands: list[Command]
    gate: Gate
    required_roles: list[str]
    state: str = BATCH_PENDING
    evidence: list[Evidence] = field(default_factory=list)
    approvals: list[Approval] = field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def command_by_id(self, command_id: str) -> Command:
        for c in self.commands:
            if c.id == command_id:
                return c
        raise DomainError(f"批次 {self.index} 中不存在命令 {command_id}")

    def has_role_approval(self, role: str) -> bool:
        return any(a.role == role for a in self.approvals)

    def approvals_satisfied(self) -> tuple[bool, list[str]]:
        missing = [r for r in self.required_roles if not self.has_role_approval(r)]
        return (not missing, missing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "is_canary": self.is_canary,
            "zone_ids": list(self.zone_ids),
            "commands": [c.to_dict() for c in self.commands],
            "gate": self.gate.to_dict(),
            "required_roles": list(self.required_roles),
            "state": self.state,
            "evidence": [e.to_dict() for e in self.evidence],
            "approvals": [a.to_dict() for a in self.approvals],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Batch":
        return cls(
            index=d["index"],
            name=d["name"],
            is_canary=d["is_canary"],
            zone_ids=list(d["zone_ids"]),
            commands=[Command.from_dict(c) for c in d["commands"]],
            gate=Gate.from_dict(d["gate"]),
            required_roles=list(d.get("required_roles", [])),
            state=d["state"],
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            approvals=[Approval.from_dict(a) for a in d.get("approvals", [])],
            started_at=datetime.fromisoformat(d["started_at"]) if d.get("started_at") else None,
            completed_at=datetime.fromisoformat(d["completed_at"]) if d.get("completed_at") else None,
        )


@dataclass
class RollbackStep:
    seq: int
    command_id: str
    batch_index: int
    rule_id: str
    device_id: str
    topo_seq: int
    status: str = STEP_PENDING
    reason: str = ""
    executed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "command_id": self.command_id,
            "batch_index": self.batch_index,
            "rule_id": self.rule_id,
            "device_id": self.device_id,
            "topo_seq": self.topo_seq,
            "status": self.status,
            "reason": self.reason,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RollbackStep":
        return cls(
            seq=d["seq"],
            command_id=d["command_id"],
            batch_index=d["batch_index"],
            rule_id=d["rule_id"],
            device_id=d["device_id"],
            topo_seq=d["topo_seq"],
            status=d["status"],
            reason=d.get("reason", ""),
            executed_at=datetime.fromisoformat(d["executed_at"]) if d.get("executed_at") else None,
        )


@dataclass
class RollbackPlan:
    created_at: datetime
    reason: str
    steps: list[RollbackStep]
    executed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at.isoformat(),
            "reason": self.reason,
            "executed": self.executed,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RollbackPlan":
        return cls(
            created_at=datetime.fromisoformat(d["created_at"]),
            reason=d["reason"],
            steps=[RollbackStep.from_dict(s) for s in d["steps"]],
            executed=d.get("executed", False),
        )


# ---------------------------------------------------------------- 发布单

@dataclass
class Rollout:
    id: str
    name: str
    policy_id: str
    snapshot_id: str
    created_at: datetime
    created_by: str
    batches: list[Batch]
    state: str = ROLLOUT_PLANNED
    cursor: int = 0  # 当前/下一个待推进批次下标，重启后据此恢复
    preflight: dict[str, Any] | None = None
    rollback_plan: RollbackPlan | None = None
    pause_reason: str = ""

    def batch(self, index: int) -> Batch:
        if index < 0 or index >= len(self.batches):
            raise DomainError(f"发布单 {self.id} 不存在批次 {index}")
        return self.batches[index]

    @property
    def current_batch(self) -> Batch | None:
        if self.state in (
            ROLLOUT_COMPLETED,
            ROLLOUT_ROLLED_BACK,
            ROLLOUT_PARTIALLY_ROLLED_BACK,
        ):
            return None
        running = [b for b in self.batches if b.state == BATCH_IN_FLIGHT]
        if running:
            return running[0]
        if self.cursor < len(self.batches):
            return self.batches[self.cursor]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "policy_id": self.policy_id,
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "state": self.state,
            "cursor": self.cursor,
            "preflight": self.preflight,
            "pause_reason": self.pause_reason,
            "batches": [b.to_dict() for b in self.batches],
            "rollback_plan": self.rollback_plan.to_dict() if self.rollback_plan else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rollout":
        return cls(
            id=d["id"],
            name=d["name"],
            policy_id=d["policy_id"],
            snapshot_id=d["snapshot_id"],
            created_at=datetime.fromisoformat(d["created_at"]),
            created_by=d["created_by"],
            state=d["state"],
            cursor=d.get("cursor", 0),
            preflight=d.get("preflight"),
            pause_reason=d.get("pause_reason", ""),
            batches=[Batch.from_dict(b) for b in d["batches"]],
            rollback_plan=RollbackPlan.from_dict(d["rollback_plan"]) if d.get("rollback_plan") else None,
        )
