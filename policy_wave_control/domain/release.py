"""发布聚合：发布单、波次批次、设备命令、健康证据、回退计划。

状态机要点
----------
* 设备命令以 receipt_seq 单调序号仲裁：序号不大于已采纳值的回执一律视为
  “迟到的旧回执”，只记录不覆盖新状态。
* 批次严格按游标推进：前一批健康阈值达标且对应角色确认后，下一批才可下发。
* 观测恶化时未开始批次冻结为 PAUSED，并生成遵循规则依赖逆序的回退计划。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import (
    BatchStatus,
    CommandStatus,
    ReceiptStatus,
    ReleaseStatus,
    RollbackPlanStatus,
)
from .errors import ConflictError, ValidationError

# 命令正向状态秩，用于仲裁新旧回执
_FORWARD_RANK = {
    CommandStatus.PLANNED.value: 0,
    CommandStatus.SENT.value: 1,
    CommandStatus.APPLIED.value: 2,
    CommandStatus.REJECTED.value: 2,
    CommandStatus.TIMEOUT.value: 2,
}
_TERMINAL_RECEIPTS = {
    ReceiptStatus.APPLIED.value,
    ReceiptStatus.REJECTED.value,
    ReceiptStatus.TIMEOUT.value,
}
_RECEIPT_TO_COMMAND = {
    ReceiptStatus.APPLIED.value: CommandStatus.APPLIED.value,
    ReceiptStatus.REJECTED.value: CommandStatus.REJECTED.value,
    ReceiptStatus.TIMEOUT.value: CommandStatus.TIMEOUT.value,
}


@dataclass
class DeviceCommand:
    """下发到单台设备的单条规则命令，command_id 是幂等键。"""

    command_id: str
    batch_index: int
    device_id: str
    zone_id: str
    rule_id: str
    rule_order: int
    status: str = CommandStatus.PLANNED.value
    last_receipt_seq: int = 0
    last_receipt_status: str | None = None
    sent_at: str | None = None
    resolved_at: str | None = None
    # 回退阶段字段
    rollback_status: str = CommandStatus.PLANNED.value
    rollback_last_seq: int = 0
    rollback_sent_at: str | None = None
    rollback_resolved_at: str | None = None
    dispatch_count: int = 0

    def mark_sent(self, now_iso: str) -> bool:
        """返回 True 表示实际下发；False 表示重复命令（幂等保留原状态）。"""
        if self.status == CommandStatus.PLANNED.value:
            self.status = CommandStatus.SENT.value
            self.sent_at = now_iso
            self.dispatch_count = 1
            return True
        # 已下发/已终结：重复下发不改状态，仅计数，供日志识别“重复命令”
        self.dispatch_count += 1
        return False

    def apply_receipt(self, status: str, seq: int, now_iso: str) -> str:
        """采纳设备回执。

        返回:
            applied  - 采纳并推进状态
            stale    - 旧回执晚到，序号落后，拒绝覆盖
            ignored  - 当前命令阶段不应收到该回执
        """
        if status not in _TERMINAL_RECEIPTS:
            raise ValidationError(f"未知回执状态: {status}")
        if seq <= self.last_receipt_seq:
            return "stale"
        if self.status not in (CommandStatus.SENT.value, CommandStatus.APPLIED.value,
                               CommandStatus.REJECTED.value, CommandStatus.TIMEOUT.value):
            return "ignored"
        self.last_receipt_seq = seq
        self.last_receipt_status = status
        self.status = _RECEIPT_TO_COMMAND[status]
        self.resolved_at = now_iso
        return "applied"

    def mark_rollback_sent(self, now_iso: str) -> bool:
        # PLANNED 首次下发；ROLLBACK_FAILED 允许人工重试重新下发
        if self.rollback_status in (CommandStatus.PLANNED.value,
                                    CommandStatus.ROLLBACK_FAILED.value):
            self.rollback_status = CommandStatus.ROLLBACK_SENT.value
            self.rollback_sent_at = now_iso
            return True
        return False  # 已在回退中/已回退：重复回退命令幂等

    def apply_rollback_receipt(self, status: str, seq: int, now_iso: str) -> str:
        if seq <= self.rollback_last_seq:
            return "stale"
        if status == ReceiptStatus.APPLIED.value:
            self.rollback_status = CommandStatus.ROLLED_BACK.value
        elif status in (ReceiptStatus.REJECTED.value, ReceiptStatus.TIMEOUT.value):
            self.rollback_status = CommandStatus.ROLLBACK_FAILED.value
        else:
            raise ValidationError(f"未知回退回执状态: {status}")
        self.rollback_last_seq = seq
        self.rollback_resolved_at = now_iso
        return "applied"

    @property
    def applied(self) -> bool:
        return self.status == CommandStatus.APPLIED.value

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceCommand":
        return cls(**data)


@dataclass
class HealthEvidence:
    """一份健康证据；同来源以 seq 单调仲裁，迟到旧证据不采纳。"""

    evidence_id: str
    source: str
    seq: int
    observed_at: str
    adopted_at: str
    health_score: float  # 0~1，越高越健康
    critical_reachable: dict[str, bool]  # service_id -> 是否可达
    adopted: bool = True

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "HealthEvidence":
        return cls(**data)


@dataclass
class Approval:
    role: str
    actor: str
    confirmed_at: str
    note: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "Approval":
        return cls(**data)


@dataclass
class GateEvaluation:
    evaluated_at: str
    mean_health: float
    samples: int
    critical_blocked: list[str]
    passed: bool
    reason: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "GateEvaluation":
        return cls(**data)


@dataclass
class Batch:
    batch_id: str
    index: int
    kind: str  # canary | zone
    zone_id: str | None  # 金丝雀批次跨区域，为 None
    required_role: str
    rule_ids: list[str]  # 已按规则依赖顺序排列
    commands: list[DeviceCommand] = field(default_factory=list)
    status: str = BatchStatus.PENDING.value
    dispatched_at: str | None = None
    evidence: list[HealthEvidence] = field(default_factory=list)
    evidence_seq_by_source: dict[str, int] = field(default_factory=dict)
    gate_evaluations: list[GateEvaluation] = field(default_factory=list)
    approvals: list[Approval] = field(default_factory=list)
    degraded_reason: str | None = None
    paused_at: str | None = None

    # ---- 回执与部署比例门禁 ----
    def command(self, command_id: str) -> DeviceCommand | None:
        return next((c for c in self.commands if c.command_id == command_id), None)

    def deploy_ratio(self) -> float:
        if not self.commands:
            return 0.0
        applied = sum(1 for c in self.commands if c.applied)
        return applied / len(self.commands)

    def all_commands_terminal(self) -> bool:
        return all(
            c.status in (CommandStatus.APPLIED.value, CommandStatus.REJECTED.value,
                         CommandStatus.TIMEOUT.value)
            for c in self.commands
        )

    def check_deploy_gate(self, required_ratio: float) -> str | None:
        """回执收敛后判定部署门禁。返回事件：watch / failed / None（继续等待）。"""
        if self.status not in (BatchStatus.DISPATCHED.value,):
            return None
        if self.deploy_ratio() >= required_ratio:
            return "watch"
        if self.all_commands_terminal():
            return "failed"
        return None

    # ---- 证据与健康门禁 ----
    def adopt_evidence(self, item: HealthEvidence) -> str:
        last = self.evidence_seq_by_source.get(item.source, 0)
        if item.seq <= last:
            item.adopted = False
            return "stale"
        self.evidence_seq_by_source[item.source] = item.seq
        self.evidence.append(item)
        return "adopted"

    def latest_evidence(self) -> list[HealthEvidence]:
        """每个来源只保留最新序号的证据参与评估。"""
        latest: dict[str, HealthEvidence] = {}
        for ev in self.evidence:
            if not ev.adopted:
                continue
            cur = latest.get(ev.source)
            if cur is None or ev.seq > cur.seq:
                latest[ev.source] = ev
        return list(latest.values())

    def evaluate_health(self, now_iso: str, window_seconds: int,
                        threshold: float, degrade_floor: float) -> GateEvaluation:
        """计算当前健康门禁结论。窗口未满或样本不足不做通过判定。"""
        latest = self.latest_evidence()
        blocked = sorted(
            {sid for ev in latest for sid, ok in ev.critical_reachable.items() if not ok}
        )
        mean_health = sum(ev.health_score for ev in latest) / len(latest) if latest else 0.0

        # 即时恶化：任何在制证据低于恶化底线，立即失败，不必等窗口
        bad = [ev for ev in latest if ev.health_score < degrade_floor]
        if bad or blocked:
            reason = (
                f"关键业务不可达: {','.join(blocked)}" if blocked
                else f"健康分 {min(ev.health_score for ev in bad):.2f} 低于恶化底线 {degrade_floor:.2f}"
            )
            result = GateEvaluation(now_iso, mean_health, len(latest), blocked, False, reason)
            self.gate_evaluations.append(result)
            return result

        if not self.dispatched_at:
            raise ConflictError("批次尚未下发，无法评估健康", {"batch_id": self.batch_id})
        window_end = _plus_seconds(self.dispatched_at, window_seconds)
        if now_iso < window_end:
            result = GateEvaluation(
                now_iso, mean_health, len(latest), blocked, False,
                f"观测窗口未满（至 {window_end}）",
            )
            self.gate_evaluations.append(result)
            return result
        if not latest:
            result = GateEvaluation(now_iso, 0.0, 0, blocked, False, "窗口内无任何健康证据")
            self.gate_evaluations.append(result)
            return result

        passed = mean_health >= threshold and not blocked
        reason = (
            f"平均健康分 {mean_health:.2f} 达标（阈值 {threshold:.2f}）"
            if passed else f"平均健康分 {mean_health:.2f} 未达阈值 {threshold:.2f}"
        )
        result = GateEvaluation(now_iso, mean_health, len(latest), blocked, passed, reason)
        self.gate_evaluations.append(result)
        return result

    def confirm(self, role: str, actor: str, now_iso: str, note: str = "") -> Approval:
        from .errors import AuthorizationError, ConflictError

        if self.status != BatchStatus.AWAITING_APPROVAL.value:
            raise ConflictError(
                "批次未在等待审批状态",
                {"batch_id": self.batch_id, "status": self.status},
            )
        if role != self.required_role:
            raise AuthorizationError(
                "该批次需要其他角色确认",
                {"batch_id": self.batch_id, "required_role": self.required_role, "given": role},
            )
        approval = Approval(role=role, actor=actor, confirmed_at=now_iso, note=note)
        self.approvals.append(approval)
        self.status = BatchStatus.CONFIRMED.value
        return approval

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "index": self.index,
            "kind": self.kind,
            "zone_id": self.zone_id,
            "required_role": self.required_role,
            "rule_ids": self.rule_ids,
            "commands": [c.to_dict() for c in self.commands],
            "status": self.status,
            "dispatched_at": self.dispatched_at,
            "evidence": [e.to_dict() for e in self.evidence],
            "evidence_seq_by_source": self.evidence_seq_by_source,
            "gate_evaluations": [g.to_dict() for g in self.gate_evaluations],
            "approvals": [a.to_dict() for a in self.approvals],
            "degraded_reason": self.degraded_reason,
            "paused_at": self.paused_at,
            "deploy_ratio": self.deploy_ratio(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Batch":
        return cls(
            batch_id=data["batch_id"],
            index=data["index"],
            kind=data["kind"],
            zone_id=data.get("zone_id"),
            required_role=data["required_role"],
            rule_ids=data["rule_ids"],
            commands=[DeviceCommand.from_dict(c) for c in data["commands"]],
            status=data["status"],
            dispatched_at=data.get("dispatched_at"),
            evidence=[HealthEvidence.from_dict(e) for e in data.get("evidence", [])],
            evidence_seq_by_source=dict(data.get("evidence_seq_by_source", {})),
            gate_evaluations=[GateEvaluation.from_dict(g) for g in data.get("gate_evaluations", [])],
            approvals=[Approval.from_dict(a) for a in data.get("approvals", [])],
            degraded_reason=data.get("degraded_reason"),
            paused_at=data.get("paused_at"),
        )


@dataclass
class RollbackStep:
    """单条已生效命令的回退步骤，顺序遵循规则依赖的逆序。"""

    command_id: str
    batch_index: int
    device_id: str
    rule_id: str
    rule_order: int
    status: str = RollbackPlanStatus.PLANNED.value  # planned|sent|done|skipped|failed
    detail: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "RollbackStep":
        return cls(**data)


@dataclass
class RollbackPlan:
    generated_at: str
    reason: str
    steps: list[RollbackStep]
    status: str = RollbackPlanStatus.PLANNED.value

    def step(self, command_id: str) -> RollbackStep | None:
        return next((s for s in self.steps if s.command_id == command_id), None)

    def recompute_status(self) -> str:
        statuses = {s.status for s in self.steps}
        if statuses <= {RollbackPlanStatus.DONE.value, RollbackPlanStatus.SKIPPED.value}:
            self.status = RollbackPlanStatus.DONE.value
        elif RollbackPlanStatus.DONE.value in statuses or RollbackPlanStatus.SKIPPED.value in statuses:
            self.status = RollbackPlanStatus.PARTIAL.value
        elif statuses <= {RollbackPlanStatus.PLANNED.value}:
            self.status = RollbackPlanStatus.PLANNED.value
        else:
            self.status = RollbackPlanStatus.EXECUTING.value
        return self.status

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "reason": self.reason,
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RollbackPlan":
        return cls(
            generated_at=data["generated_at"],
            reason=data["reason"],
            status=data.get("status", RollbackPlanStatus.PLANNED.value),
            steps=[RollbackStep.from_dict(s) for s in data["steps"]],
        )


@dataclass
class Thresholds:
    deploy_ratio: float = 0.8  # 批次设备回执生效比例下限
    health_threshold: float = 0.95  # 健康分阈值
    degrade_floor: float = 0.80  # 单证据低于此值立即判恶化
    health_window_seconds: int = 300
    canary_ratio: float = 0.25  # 金丝雀设备占比（每区至少 1 台）

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "Thresholds":
        return cls(**data)


def _plus_seconds(iso_ts: str, seconds: int) -> str:
    from datetime import datetime, timedelta

    dt = datetime.fromisoformat(iso_ts)
    return (dt + timedelta(seconds=seconds)).isoformat()


@dataclass
class Release:
    release_id: str
    snapshot_id: str
    policy_id: str
    thresholds: Thresholds
    created_at: str
    status: str = ReleaseStatus.DRAFT.value
    batches: list[Batch] = field(default_factory=list)
    cursor: int = 0  # 发布游标：当前应下发/在制的批次下标，持久化用于重启恢复
    preflight: dict | None = None
    rollback_plan: RollbackPlan | None = None
    paused_at: str | None = None
    pause_reason: str | None = None
    completed_at: str | None = None

    def batch(self, ref: int | str) -> Batch:
        from .errors import NotFoundError

        if isinstance(ref, int):
            if 0 <= ref < len(self.batches):
                return self.batches[ref]
            raise NotFoundError(f"批次下标不存在: {ref}")
        found = next((b for b in self.batches if b.batch_id == ref), None)
        if found is None:
            raise NotFoundError(f"批次不存在: {ref}")
        return found

    def current_batch(self) -> Batch | None:
        if 0 <= self.cursor < len(self.batches):
            return self.batches[self.cursor]
        return None

    def pending_batches(self) -> list[Batch]:
        """尚未开始（未下发）的批次——恶化时需要被暂停的正是它们。"""
        return [b for b in self.batches if b.status == BatchStatus.PENDING.value]

    def freeze_pending(self, now_iso: str) -> list[str]:
        frozen: list[str] = []
        for b in self.batches:
            if b.status == BatchStatus.PENDING.value:
                b.status = BatchStatus.PAUSED.value
                b.paused_at = now_iso
                frozen.append(b.batch_id)
        return frozen

    def applied_batches_reverse(self) -> list[Batch]:
        """已有命令生效的批次，按批次逆序（后下发的先回退）。"""
        return [b for b in reversed(self.batches) if any(c.applied for c in b.commands)]

    def build_rollback_steps(self) -> list[RollbackStep]:
        """生成遵循依赖顺序的回退步骤。

        * 批次按推进的逆序回退；
        * 批次内命令按 rule_order 逆序（被依赖的规则最后撤）；
        * 仅 APPLIED 的命令需要回退，未生效的标记 skipped——构成“部分回退”。
        """
        steps: list[RollbackStep] = []
        for batch in self.applied_batches_reverse():
            ordered = sorted(
                (c for c in batch.commands),
                key=lambda c: (-c.rule_order, c.device_id),
            )
            for cmd in ordered:
                if cmd.applied:
                    steps.append(RollbackStep(
                        command_id=cmd.command_id,
                        batch_index=cmd.batch_index,
                        device_id=cmd.device_id,
                        rule_id=cmd.rule_id,
                        rule_order=cmd.rule_order,
                    ))
                else:
                    steps.append(RollbackStep(
                        command_id=cmd.command_id,
                        batch_index=cmd.batch_index,
                        device_id=cmd.device_id,
                        rule_id=cmd.rule_id,
                        rule_order=cmd.rule_order,
                        status=RollbackPlanStatus.SKIPPED.value,
                        detail="命令从未生效，无需回退",
                    ))
        return steps

    def to_dict(self) -> dict:
        return {
            "release_id": self.release_id,
            "snapshot_id": self.snapshot_id,
            "policy_id": self.policy_id,
            "thresholds": self.thresholds.to_dict(),
            "created_at": self.created_at,
            "status": self.status,
            "batches": [b.to_dict() for b in self.batches],
            "cursor": self.cursor,
            "preflight": self.preflight,
            "rollback_plan": self.rollback_plan.to_dict() if self.rollback_plan else None,
            "paused_at": self.paused_at,
            "pause_reason": self.pause_reason,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Release":
        return cls(
            release_id=data["release_id"],
            snapshot_id=data["snapshot_id"],
            policy_id=data["policy_id"],
            thresholds=Thresholds.from_dict(data["thresholds"]),
            created_at=data["created_at"],
            status=data["status"],
            batches=[Batch.from_dict(b) for b in data.get("batches", [])],
            cursor=data.get("cursor", 0),
            preflight=data.get("preflight"),
            rollback_plan=(
                RollbackPlan.from_dict(data["rollback_plan"])
                if data.get("rollback_plan") else None
            ),
            paused_at=data.get("paused_at"),
            pause_reason=data.get("pause_reason"),
            completed_at=data.get("completed_at"),
        )


class NotFound:  # pragma: no cover - 小辅助，保持下方 raise 语法统一
    @staticmethod
    def raise_(msg: str) -> Exception:
        from .errors import NotFoundError
        return NotFoundError(msg)
