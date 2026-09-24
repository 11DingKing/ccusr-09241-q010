"""应用服务：发布编排的唯一用例入口。

所有写操作遵循同一套约定：
1. 校验领域规则；2. 变更聚合；3. 追加哈希链审计；4. 持久化。
任何自动动作（观测恶化暂停、生成回退计划）同样写入审计日志。
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Protocol

from ..domain.models import (
    Device,
    DomainError,
    FlowEdge,
    PolicyException,
    PolicyRule,
    PolicyVersion,
    TopologySnapshot,
    Zone,
)
from ..domain.reachability import ReachabilitySimulator
from ..domain.release import (
    BATCH_COMPLETED,
    BATCH_HELD,
    BATCH_IN_FLIGHT,
    BATCH_PARTIALLY_ROLLED_BACK,
    BATCH_PENDING,
    BATCH_ROLLED_BACK,
    CMD_APPLIED,
    CMD_FAILED,
    ROLLOUT_ACTIVE,
    ROLLOUT_COMPLETED,
    ROLLOUT_PARTIALLY_ROLLED_BACK,
    ROLLOUT_PAUSED,
    ROLLOUT_PLANNED,
    ROLLOUT_ROLLED_BACK,
    ROLLOUT_ROLLING_BACK,
    STEP_DONE,
    STEP_FAILED,
    STEP_PENDING,
    Approval,
    AuditLog,
    Evidence,
    Receipt,
    RollbackPlan,
    RollbackStep,
    Rollout,
)
from .planning import build_batches
from .ports import Clock, IdGenerator, SystemClock, UuidIds


class Repository(Protocol):
    def save(self, entity: Any) -> None: ...
    def get(self, entity_id: str) -> Any: ...
    def all(self) -> list[Any]: ...


class AuditStore(Protocol):
    def load(self) -> AuditLog: ...
    def store(self, log: AuditLog) -> None: ...


class RollbackExecutor(Protocol):
    """设备侧撤销动作端口；返回 False 表示该设备撤销失败（部分回退）。"""

    def undo(self, step: RollbackStep) -> bool: ...


class ImmediateRollbackExecutor:
    def undo(self, step: RollbackStep) -> bool:
        return True


class ReleaseService:
    def __init__(
        self,
        snapshots: Repository,
        policies: Repository,
        exceptions: Repository,
        rollouts: Repository,
        audit_store: AuditStore,
        clock: Clock | None = None,
        ids: IdGenerator | None = None,
        rollback_executor: RollbackExecutor | None = None,
    ) -> None:
        self.snapshots = snapshots
        self.policies = policies
        self.exceptions = exceptions
        self.rollouts = rollouts
        self.audit_store = audit_store
        self.clock = clock or SystemClock()
        self.ids = ids or UuidIds()
        self.rollback_executor = rollback_executor or ImmediateRollbackExecutor()
        self._audit_log = audit_store.load()
        self._simulator = ReachabilitySimulator()

    # ------------------------------------------------------------ 内部工具

    def _now(self) -> datetime:
        return self.clock.now()

    def _audit(self, actor: str, action: str, payload: dict[str, Any]) -> None:
        self._audit_log.append(self._now(), actor, action, payload)
        self.audit_store.store(self._audit_log)

    def _save_rollout(self, rollout: Rollout) -> None:
        self.rollouts.save(rollout)

    def _get_rollout(self, rollout_id: str) -> Rollout:
        rollout = self.rollouts.get(rollout_id)
        if rollout is None:
            raise DomainError(f"发布单不存在: {rollout_id}")
        return rollout

    def _find_command(self, rollout: Rollout, command_id: str):
        for batch in rollout.batches:
            for cmd in batch.commands:
                if cmd.id == command_id:
                    return batch, cmd
        raise DomainError(f"发布单 {rollout.id} 中不存在命令 {command_id}")

    # ------------------------------------------------------------ 快照

    def add_snapshot(
        self,
        name: str,
        zones: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        edges: list[dict[str, Any]] | None = None,
        note: str = "",
        actor: str = "system",
    ) -> TopologySnapshot:
        snapshot = TopologySnapshot(
            id=self.ids.new("snap"),
            name=name,
            created_at=self._now(),
            zones=[Zone(**z) for z in zones],
            devices=[Device(**d) for d in devices],
            edges=[FlowEdge(**e) for e in (edges or [])],
            note=note,
        )
        zone_ids = {z.id for z in snapshot.zones}
        for d in snapshot.devices:
            if d.zone_id not in zone_ids:
                raise DomainError(f"设备 {d.id} 引用了不存在的区域 {d.zone_id}")
        for e in snapshot.edges:
            if e.src_zone not in zone_ids or e.dst_zone not in zone_ids:
                raise DomainError(f"链路 {e.src_zone}->{e.dst_zone} 引用了不存在的区域")
        self.snapshots.save(snapshot)
        self._audit(actor, "snapshot.created", {"snapshot_id": snapshot.id, "name": name})
        return snapshot

    # ------------------------------------------------------------ 策略

    def add_policy(
        self,
        name: str,
        snapshot_id: str,
        rules: list[dict[str, Any]],
        notes: str = "",
        actor: str = "system",
    ) -> PolicyVersion:
        snapshot = self.snapshots.get(snapshot_id)
        if snapshot is None:
            raise DomainError(f"快照不存在: {snapshot_id}")
        policy_rules = [PolicyRule(**r) for r in rules]
        ids = [r.id for r in policy_rules]
        if len(set(ids)) != len(ids):
            raise DomainError("策略规则 id 重复")
        rule_ids = set(ids)
        zone_ids = {z.id for z in snapshot.zones}
        for r in policy_rules:
            if r.src_zone not in zone_ids or r.dst_zone not in zone_ids:
                raise DomainError(f"规则 {r.id} 引用了快照中不存在的区域")
            for dep in r.depends_on:
                if dep not in rule_ids:
                    raise DomainError(f"规则 {r.id} 依赖了不存在的规则 {dep}")
        policy = PolicyVersion(
            id=self.ids.new("pol"),
            name=name,
            snapshot_id=snapshot_id,
            created_at=self._now(),
            rules=policy_rules,
            notes=notes,
        )
        self.policies.save(policy)
        self._audit(actor, "policy.created", {
            "policy_id": policy.id,
            "snapshot_id": snapshot_id,
            "rule_count": len(policy_rules),
        })
        return policy

    # ------------------------------------------------------------ 例外

    def add_exception(
        self,
        rule_id: str,
        reason: str,
        created_by: str,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        scope_device_id: str | None = None,
    ) -> PolicyException:
        if not any(r.id == rule_id for p in self.policies.all() for r in p.rules):
            raise DomainError(f"例外引用了不存在的规则 {rule_id}")
        exc = PolicyException(
            id=self.ids.new("exc"),
            rule_id=rule_id,
            reason=reason,
            created_by=created_by,
            valid_from=valid_from or self._now(),
            valid_until=valid_until
            or (self._now() + timedelta(days=7)),
            scope_device_id=scope_device_id,
            created_at=self._now(),
        )
        self.exceptions.save(exc)
        self._audit(created_by, "exception.created", {
            "exception_id": exc.id,
            "rule_id": rule_id,
            "valid_until": exc.valid_until.isoformat(),
            "reason": reason,
        })
        return exc

    def renew_exception(
        self, exception_id: str, new_until: datetime, actor: str, reason: str = ""
    ) -> PolicyException:
        exc = self.exceptions.get(exception_id)
        if exc is None:
            raise DomainError(f"例外不存在: {exception_id}")
        if exc.revoked_at is not None:
            raise DomainError(f"例外 {exception_id} 已吊销，不能续期")
        old_until = exc.valid_until
        exc.renew(new_until, actor, self._now(), reason)
        self.exceptions.save(exc)
        self._audit(actor, "exception.renewed", {
            "exception_id": exc.id,
            "rule_id": exc.rule_id,
            "previous_until": old_until.isoformat(),
            "new_until": new_until.isoformat(),
            "reason": reason,
        })
        return exc

    def revoke_exception(self, exception_id: str, actor: str) -> PolicyException:
        exc = self.exceptions.get(exception_id)
        if exc is None:
            raise DomainError(f"例外不存在: {exception_id}")
        exc.revoke(self._now())
        self.exceptions.save(exc)
        self._audit(actor, "exception.revoked", {
            "exception_id": exc.id,
            "rule_id": exc.rule_id,
        })
        return exc

    # ------------------------------------------------------------ 预演

    def preflight(self, policy_id: str, at: datetime | None = None):
        policy = self.policies.get(policy_id)
        if policy is None:
            raise DomainError(f"策略版本不存在: {policy_id}")
        snapshot = self.snapshots.get(policy.snapshot_id)
        if snapshot is None:
            raise DomainError(f"快照不存在: {policy.snapshot_id}")
        return self._simulator.preflight(
            snapshot, policy, self.exceptions.all(), at or self._now()
        )

    # ------------------------------------------------------------ 发布单

    def create_rollout(
        self,
        policy_id: str,
        name: str,
        actor: str,
        gate_metrics: dict[str, dict[str, float]] | None = None,
        min_applied_ratio: float = 1.0,
        at: datetime | None = None,
    ) -> Rollout:
        policy = self.policies.get(policy_id)
        if policy is None:
            raise DomainError(f"策略版本不存在: {policy_id}")
        snapshot = self.snapshots.get(policy.snapshot_id)
        if snapshot is None:
            raise DomainError(f"快照不存在: {policy.snapshot_id}")
        moment = at or self._now()
        report = self._simulator.preflight(snapshot, policy, self.exceptions.all(), moment)
        if report.verdict == "blocked":
            self._audit(actor, "rollout.preflight_blocked", {
                "policy_id": policy_id,
                "critical_impacts": [f.matched_rule_id for f in report.critical_impacts],
                "gaps": report.enforcement_gaps,
            })
            raise DomainError(
                "预演未通过：关键业务链路将被阻断或关键规则无设备可落地；"
                f"影响 {[f'{f.src_zone}->{f.dst_zone}/{f.service}' for f in report.critical_impacts]}"
            )
        plan = build_batches(
            snapshot, policy, report, self.ids,
            gate_metrics=gate_metrics, min_applied_ratio=min_applied_ratio,
        )
        rollout = Rollout(
            id=self.ids.new("rl"),
            name=name,
            policy_id=policy_id,
            snapshot_id=snapshot.id,
            created_at=self._now(),
            created_by=actor,
            batches=plan.batches,
            state=ROLLOUT_PLANNED,
            cursor=0,
            preflight=report.to_dict(),
        )
        self._save_rollout(rollout)
        self._audit(actor, "rollout.created", {
            "rollout_id": rollout.id,
            "policy_id": policy_id,
            "batch_count": len(rollout.batches),
            "deferred_rules": plan.deferred_rules,
            "uncovered": plan.uncovered,
            "expired_exceptions": report.expired_exceptions,
            "active_exceptions": report.active_exceptions,
        })
        return rollout

    def status(self, rollout_id: str) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        return self._status_dict(rollout)

    def _status_dict(self, rollout: Rollout) -> dict[str, Any]:
        return {
            "id": rollout.id,
            "name": rollout.name,
            "state": rollout.state,
            "cursor": rollout.cursor,
            "pause_reason": rollout.pause_reason,
            "policy_id": rollout.policy_id,
            "snapshot_id": rollout.snapshot_id,
            "batches": [
                {
                    "index": b.index,
                    "name": b.name,
                    "is_canary": b.is_canary,
                    "state": b.state,
                    "zone_ids": b.zone_ids,
                    "command_total": len(b.commands),
                    "applied": sum(1 for c in b.commands if c.state == CMD_APPLIED),
                    "failed": sum(1 for c in b.commands if c.state == CMD_FAILED),
                    "duplicate_dispatches": sum(c.duplicate_dispatches for c in b.commands),
                    "approvals": [a.role for a in b.approvals],
                    "required_roles": list(b.required_roles),
                }
                for b in rollout.batches
            ],
            "rollback_plan": rollout.rollback_plan.to_dict() if rollout.rollback_plan else None,
            "preflight": rollout.preflight,
        }

    # ------------------------------------------------------------ 审批

    def approve(
        self, rollout_id: str, batch_index: int, role: str, actor: str, comment: str = ""
    ) -> Approval:
        rollout = self._get_rollout(rollout_id)
        batch = rollout.batch(batch_index)
        if role not in batch.required_roles:
            raise DomainError(
                f"批次 {batch_index} 不需要角色 {role} 的确认；"
                f"需要: {batch.required_roles}"
            )
        if batch.has_role_approval(role):
            raise DomainError(f"角色 {role} 已确认过批次 {batch_index}，不得重复确认")
        if batch.state in (BATCH_ROLLED_BACK, BATCH_PARTIALLY_ROLLED_BACK):
            raise DomainError("批次已回退，不能再确认")
        approval = Approval(role=role, actor=actor, at=self._now(), comment=comment)
        batch.approvals.append(approval)
        self._save_rollout(rollout)
        self._audit(actor, "batch.approved", {
            "rollout_id": rollout.id,
            "batch_index": batch_index,
            "role": role,
            "comment": comment,
        })
        return approval

    # ------------------------------------------------------------ 下发

    def dispatch_batch(self, rollout_id: str, batch_index: int | None = None, actor: str = "dispatcher") -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        if rollout.state in (ROLLOUT_PAUSED, ROLLOUT_ROLLING_BACK, ROLLOUT_ROLLED_BACK,
                             ROLLOUT_PARTIALLY_ROLLED_BACK, ROLLOUT_COMPLETED):
            raise DomainError(f"发布单当前状态 {rollout.state}，不能下发批次")
        index = rollout.cursor if batch_index is None else batch_index
        batch = rollout.batch(index)
        if index != rollout.cursor:
            raise DomainError(
                f"只能按顺序推进：当前游标指向批次 {rollout.cursor}，请求的是 {index}"
            )
        if batch.state == BATCH_COMPLETED:
            raise DomainError(f"批次 {index} 已完成")
        if batch.state == BATCH_HELD:
            raise DomainError(f"批次 {index} 已被暂停挂起，需先恢复发布")
        ok_roles, missing = batch.approvals_satisfied()
        if not ok_roles:
            raise DomainError(f"批次 {index} 尚未获得全部角色确认，缺少: {missing}")

        new_ids: list[str] = []
        duplicate_ids: list[str] = []
        if rollout.state == ROLLOUT_PLANNED:
            rollout.state = ROLLOUT_ACTIVE
        if batch.state == BATCH_PENDING:
            batch.state = BATCH_IN_FLIGHT
            batch.started_at = self._now()
        for cmd in batch.commands:
            is_new = cmd.mark_dispatched(self._now())
            (new_ids if is_new else duplicate_ids).append(cmd.id)
        self._save_rollout(rollout)
        self._audit(actor, "batch.dispatched", {
            "rollout_id": rollout.id,
            "batch_index": index,
            "new_commands": len(new_ids),
            "duplicate_commands": len(duplicate_ids),
            "command_ids": new_ids,
            "duplicate_ids": duplicate_ids,
            "resend": bool(duplicate_ids) and not new_ids,
        })
        return {
            "batch_index": index,
            "state": batch.state,
            "new": new_ids,
            "duplicates": duplicate_ids,
        }

    # ------------------------------------------------------------ 回执

    def receive_receipt(
        self,
        rollout_id: str,
        command_id: str,
        revision: int,
        claimed_state: str,
        produced_at: datetime | None = None,
    ) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        batch, cmd = self._find_command(rollout, command_id)
        received = self._now()
        produced = produced_at or received
        accepted, reason = cmd.apply_receipt(revision, claimed_state, produced, received)
        receipt = Receipt(
            command_id=command_id,
            revision=revision,
            claimed_state=claimed_state,
            produced_at=produced,
            received_at=received,
            accepted=accepted,
            reason=reason,
        )
        cmd.receipts.append(receipt)
        self._save_rollout(rollout)
        self._audit("device", "receipt.received", {
            "rollout_id": rollout.id,
            "batch_index": batch.index,
            "command_id": command_id,
            "revision": revision,
            "claimed_state": claimed_state,
            "produced_at": produced.isoformat(),
            "accepted": accepted,
            "reason": reason,
        })
        return {"accepted": accepted, "reason": reason, "command_id": command_id,
                "state": cmd.state, "revision": cmd.revision}

    # ------------------------------------------------------------ 证据与闸门

    def gate_status(self, rollout_id: str, batch_index: int) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        batch = rollout.batch(batch_index)
        result = batch.gate.evaluate(batch.commands, batch.evidence)
        ok_roles, missing = batch.approvals_satisfied()
        result["approvals_ok"] = ok_roles
        result["missing_roles"] = missing
        result["batch_state"] = batch.state
        return result

    def adopt_evidence(
        self,
        rollout_id: str,
        batch_index: int,
        metric: str,
        value: float,
        source: str,
        actor: str = "observer",
    ) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        batch = rollout.batch(batch_index)
        if batch.state != BATCH_IN_FLIGHT:
            raise DomainError(f"批次 {batch_index} 当前状态 {batch.state}，只接受在途批次的证据")
        bounds = batch.gate.metrics.get(metric, {})
        lo, hi = bounds.get("min"), bounds.get("max")
        in_range = (lo is None or value >= lo) and (hi is None or value <= hi)
        evidence = Evidence(
            id=self.ids.new("ev"),
            batch_index=batch_index,
            metric=metric,
            value=value,
            source=source,
            adopted_by=actor,
            at=self._now(),
            in_range=in_range,
        )
        batch.evidence.append(evidence)
        self._save_rollout(rollout)
        self._audit(actor, "evidence.adopted", {
            "rollout_id": rollout.id,
            "batch_index": batch_index,
            "metric": metric,
            "value": value,
            "source": source,
            "evidence_id": evidence.id,
        })
        # 观测恶化：自动暂停尚未开始的批次并生成回退计划
        breach = batch.gate.check_breach(batch.evidence)
        auto_actions: list[str] = []
        if breach["breached"]:
            self._auto_pause_and_plan(rollout, f"指标越界: {breach['items']}")
            auto_actions.append("paused_and_rollback_planned")
        return {
            "evidence_id": evidence.id,
            "breach": breach,
            "auto_actions": auto_actions,
            "rollout_state": rollout.state,
        }

    def _auto_pause_and_plan(self, rollout: Rollout, reason: str) -> None:
        """恶化处置：未开始批次挂起；生成依赖逆序的回退计划（不自动执行）。"""
        if rollout.state == ROLLOUT_PAUSED:
            return
        held: list[int] = []
        for batch in rollout.batches:
            if batch.state == BATCH_PENDING:
                batch.state = BATCH_HELD
                held.append(batch.index)
        rollout.state = ROLLOUT_PAUSED
        rollout.pause_reason = reason
        self._save_rollout(rollout)
        self._audit("monitor:auto", "rollout.auto_paused", {
            "rollout_id": rollout.id,
            "reason": reason,
            "held_batches": held,
        })
        self._build_rollback_plan(rollout, reason, actor="monitor:auto")

    def pause(self, rollout_id: str, actor: str, reason: str) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        if rollout.state not in (ROLLOUT_ACTIVE, ROLLOUT_PLANNED):
            raise DomainError(f"发布单状态 {rollout.state}，不能暂停")
        held: list[int] = []
        for batch in rollout.batches:
            if batch.state == BATCH_PENDING:
                batch.state = BATCH_HELD
                held.append(batch.index)
        rollout.state = ROLLOUT_PAUSED
        rollout.pause_reason = reason
        self._save_rollout(rollout)
        self._audit(actor, "rollout.paused", {
            "rollout_id": rollout.id, "reason": reason, "held_batches": held,
        })
        return {"state": rollout.state, "held_batches": held}

    def resume(self, rollout_id: str, actor: str) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        if rollout.state != ROLLOUT_PAUSED:
            raise DomainError(f"发布单状态 {rollout.state}，无需恢复")
        for batch in rollout.batches:
            if batch.state == BATCH_HELD:
                batch.state = BATCH_PENDING
        rollout.state = ROLLOUT_ACTIVE
        rollout.pause_reason = ""
        self._save_rollout(rollout)
        self._audit(actor, "rollout.resumed", {"rollout_id": rollout.id})
        return {"state": rollout.state}

    # ------------------------------------------------------------ 推进

    def advance(self, rollout_id: str, actor: str) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        if rollout.state not in (ROLLOUT_PLANNED, ROLLOUT_ACTIVE):
            raise DomainError(f"发布单状态 {rollout.state}，不能推进")
        batch = rollout.batch(rollout.cursor)
        if batch.state != BATCH_IN_FLIGHT:
            raise DomainError(f"批次 {batch.index} 尚未在途（当前 {batch.state}）")
        gate = batch.gate.evaluate(batch.commands, batch.evidence)
        if not gate["passed"]:
            raise DomainError(f"健康闸门未通过: {gate}")
        ok_roles, missing = batch.approvals_satisfied()
        if not ok_roles:
            raise DomainError(f"缺少角色确认: {missing}")
        failed = [c.id for c in batch.commands if c.state == CMD_FAILED]
        if failed:
            raise DomainError(f"批次存在失败命令: {failed}，不能推进")
        batch.state = BATCH_COMPLETED
        batch.completed_at = self._now()
        finished_index = batch.index
        rollout.cursor = finished_index + 1
        completed = rollout.cursor >= len(rollout.batches)
        if completed:
            rollout.state = ROLLOUT_COMPLETED
        self._save_rollout(rollout)
        self._audit(actor, "batch.completed", {
            "rollout_id": rollout.id,
            "batch_index": finished_index,
            "gate": gate,
            "rollout_completed": completed,
            "next_cursor": rollout.cursor,
        })
        return {
            "completed_batch": finished_index,
            "next_cursor": rollout.cursor,
            "rollout_state": rollout.state,
            "gate": gate,
        }

    # ------------------------------------------------------------ 回退

    def _build_rollback_plan(self, rollout: Rollout, reason: str, actor: str) -> RollbackPlan:
        if rollout.rollback_plan is not None:
            return rollout.rollback_plan
        applied = [
            (b, c)
            for b in rollout.batches
            for c in b.commands
            if c.state == CMD_APPLIED
        ]
        # 依赖逆序：后发批次先撤；同批内 topo_seq 大的（依赖方）先撤
        applied.sort(key=lambda bc: (-bc[0].index, -bc[1].topo_seq, bc[1].device_id))
        steps = [
            RollbackStep(
                seq=i + 1,
                command_id=c.id,
                batch_index=b.index,
                rule_id=c.rule_id,
                device_id=c.device_id,
                topo_seq=c.topo_seq,
            )
            for i, (b, c) in enumerate(applied)
        ]
        plan = RollbackPlan(created_at=self._now(), reason=reason, steps=steps)
        rollout.rollback_plan = plan
        self._save_rollout(rollout)
        self._audit(actor, "rollback.plan_created", {
            "rollout_id": rollout.id,
            "reason": reason,
            "step_count": len(steps),
            "order": [
                {"seq": s.seq, "batch": s.batch_index, "rule": s.rule_id, "device": s.device_id}
                for s in steps
            ],
        })
        return plan

    def create_rollback_plan(self, rollout_id: str, reason: str, actor: str = "operator") -> RollbackPlan:
        rollout = self._get_rollout(rollout_id)
        return self._build_rollback_plan(rollout, reason, actor)

    def execute_rollback(self, rollout_id: str, actor: str) -> dict[str, Any]:
        rollout = self._get_rollout(rollout_id)
        plan = rollout.rollback_plan
        if plan is None:
            raise DomainError("尚无回退计划")
        if plan.executed:
            raise DomainError(
                "回退计划已执行；仍有失败步骤时请使用 retry_rollback 进行补偿重试"
            )
        if plan.steps and not any(s.status == STEP_PENDING for s in plan.steps):
            raise DomainError(
                "首轮回退已结束且无待执行步骤；残留失败请使用 retry_rollback 补偿重试"
            )
        return self._run_rollback_steps(rollout, actor)

    def retry_rollback(self, rollout_id: str, actor: str) -> dict[str, Any]:
        """部分回退后的补偿：仅重试上一轮失败的撤销步骤。"""
        rollout = self._get_rollout(rollout_id)
        plan = rollout.rollback_plan
        if plan is None or not any(
            s.status in (STEP_FAILED, STEP_DONE) for s in plan.steps
        ):
            raise DomainError("回退尚未执行过，没有可重试的失败步骤")
        pending_retry = [s for s in plan.steps if s.status == STEP_FAILED]
        if not pending_retry:
            raise DomainError("没有失败的回退步骤需要重试")
        rollout.state = ROLLOUT_ROLLING_BACK
        self._save_rollout(rollout)
        return self._run_rollback_steps(rollout, actor, only_failed=True)

    def _run_rollback_steps(self, rollout: Rollout, actor: str, only_failed: bool = False) -> dict[str, Any]:
        plan = rollout.rollback_plan
        assert plan is not None
        if not only_failed:
            rollout.state = ROLLOUT_ROLLING_BACK
            self._save_rollout(rollout)

        results: list[dict[str, Any]] = []
        for step in plan.steps:
            if step.status != STEP_PENDING and not (only_failed and step.status == STEP_FAILED):
                continue
            try:
                ok = bool(self.rollback_executor.undo(step))
            except Exception as exc:  # 设备侧异常同样记为该步失败，继续其余步骤
                ok = False
                step.reason = f"撤销异常: {exc}"
            if ok:
                step.status = STEP_DONE
                step.reason = ""
            else:
                step.status = STEP_FAILED
                if not step.reason:
                    step.reason = "设备拒绝撤销或超时"
            step.executed_at = self._now()
            results.append({"seq": step.seq, "device": step.device_id, "status": step.status})
            self._audit("rollback:auto" if ok else actor, "rollback.step_executed", {
                "rollout_id": rollout.id,
                "seq": step.seq,
                "command_id": step.command_id,
                "device_id": step.device_id,
                "status": step.status,
                "reason": step.reason,
                "retry": only_failed,
            })

        failed_steps = [s for s in plan.steps if s.status == STEP_FAILED]
        done_steps = [s for s in plan.steps if s.status == STEP_DONE]
        # 仅在没有遗留失败步骤时才收尾为已执行
        plan.executed = not failed_steps

        touched_batches = {s.batch_index for s in plan.steps}
        for bi in touched_batches:
            batch = rollout.batch(bi)
            batch_failed = [s for s in failed_steps if s.batch_index == bi]
            batch.state = BATCH_PARTIALLY_ROLLED_BACK if batch_failed else BATCH_ROLLED_BACK
        # 在途但命令从未生效的批次：无设备变更可撤，标记挂起并在审计中说明
        for batch in rollout.batches:
            if batch.state == BATCH_IN_FLIGHT and batch.index not in touched_batches:
                batch.state = BATCH_HELD

        rollout.state = (
            ROLLOUT_PARTIALLY_ROLLED_BACK if failed_steps else ROLLOUT_ROLLED_BACK
        )
        self._save_rollout(rollout)
        self._audit(actor, "rollback.completed", {
            "rollout_id": rollout.id,
            "done": len(done_steps),
            "failed": len(failed_steps),
            "partial": bool(failed_steps),
            "failed_steps": [
                {"seq": s.seq, "device": s.device_id, "reason": s.reason}
                for s in failed_steps
            ],
        })
        return {
            "state": rollout.state,
            "done": len(done_steps),
            "failed": len(failed_steps),
            "steps": results,
        }

    # ------------------------------------------------------------ 审计与恢复

    def verify_audit(self) -> dict[str, Any]:
        return self._audit_log.verify()

    def read_audit(self, limit: int | None = None, action_prefix: str | None = None) -> list[dict[str, Any]]:
        entries = self._audit_log.entries
        if action_prefix:
            entries = [e for e in entries if e.action.startswith(action_prefix)]
        if limit:
            entries = entries[-limit:]
        return [e.to_dict() for e in entries]

    def recover(self) -> dict[str, Any]:
        """服务重启后调用：从持久化状态恢复发布游标，不改变任何业务状态。"""
        rollouts = []
        for rollout in self.rollouts.all():
            current = rollout.current_batch
            rollouts.append({
                "rollout_id": rollout.id,
                "state": rollout.state,
                "cursor": rollout.cursor,
                "current_batch": current.index if current else None,
                "total_batches": len(rollout.batches),
                "has_rollback_plan": rollout.rollback_plan is not None,
            })
        self._audit("system", "service.recovered", {"rollouts": rollouts})
        return {"audit": self._audit_log.verify(), "rollouts": rollouts}
