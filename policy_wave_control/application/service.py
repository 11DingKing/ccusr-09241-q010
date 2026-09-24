"""发布编排应用服务：唯一的状态机入口，所有动作写追加式日志。"""

from __future__ import annotations

from ..domain.enums import (
    ALL_ROLES,
    BatchStatus,
    ReceiptStatus,
    ReleaseStatus,
    RollbackPlanStatus,
)
from ..domain.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from ..domain.exceptions import PolicyException
from ..domain.release import (
    HealthEvidence,
    Release,
    RollbackPlan,
    Thresholds,
)
from .preflight import PreflightEngine


SYSTEM_ACTOR = "system"


class ReleaseService:
    def __init__(self, *, catalog, release_repo, audit, gateway, clock, idgen) -> None:
        self.catalog = catalog
        self.releases = release_repo
        self.audit = audit
        self.gateway = gateway
        self.clock = clock
        self.idgen = idgen
        self._preflight = PreflightEngine(idgen)

    def _now(self) -> str:
        return self.clock.now()

    def _log(self, actor: str, action: str, target_type: str,
             target_id: str, payload: dict | None = None) -> None:
        self.audit.append(actor, action, target_type, target_id, payload or {})

    # ==================================================================
    # 清单：拓扑快照 / 策略版本 / 例外
    # ==================================================================
    def register_snapshot(self, payload: dict, actor: str = "operator") -> dict:
        from ..domain.topology import CriticalService, Device, TopologySnapshot, Zone

        snapshot_id = payload.get("snapshot_id") or self.idgen.new_id("topo")
        snapshot = TopologySnapshot(
            snapshot_id=snapshot_id,
            version=int(payload["version"]),
            taken_at=payload.get("taken_at") or self._now(),
            zones=tuple(Zone(**z) for z in payload["zones"]),
            devices=tuple(
                Device(d["device_id"], d["zone_id"], frozenset(d["capabilities"]),
                       d["firmware"], d.get("critical", False))
                for d in payload["devices"]
            ),
            services=tuple(CriticalService(**s) for s in payload.get("services", [])),
        )
        self.catalog.save_snapshot(snapshot)
        self._log(actor, "topology.snapshot_registered", "topology", snapshot_id,
                  {"version": snapshot.version, "zones": len(snapshot.zones),
                   "devices": len(snapshot.devices), "services": len(snapshot.services)})
        return snapshot.to_dict()

    def register_policy(self, payload: dict, actor: str = "operator") -> dict:
        from ..domain.policy import PolicyRule, PolicyVersion

        policy_id = payload.get("policy_id") or self.idgen.new_id("policy")
        policy = PolicyVersion(
            policy_id=policy_id,
            version=int(payload["version"]),
            created_at=payload.get("created_at") or self._now(),
            rules=tuple(PolicyRule(**r) for r in payload["rules"]),
            depends_on={k: tuple(v) for k, v in payload.get("depends_on", {}).items()},
            note=payload.get("note", ""),
        )
        # 提前暴露依赖环
        policy.topological_order()
        self.catalog.save_policy(policy)
        self._log(actor, "policy.version_registered", "policy", policy_id,
                  {"version": policy.version, "rules": len(policy.rules)})
        return policy.to_dict()

    def create_exception(self, payload: dict, actor: str) -> dict:
        for field_name in ("rule_id", "zone_id", "expires_at", "reason"):
            if not payload.get(field_name):
                raise ValidationError(f"缺少例外字段: {field_name}")
        now = self._now()
        if payload["expires_at"] <= now:
            raise ValidationError("新建例外的到期时间必须晚于当前时间",
                                  {"expires_at": payload["expires_at"], "now": now})
        exc = PolicyException(
            exception_id=self.idgen.new_id("exc"),
            rule_id=payload["rule_id"],
            zone_id=payload["zone_id"],
            reason=payload["reason"],
            created_at=now,
            expires_at=payload["expires_at"],
            created_by=actor,
        )
        self.catalog.save_exception(exc)
        self._log(actor, "exception.created", "exception", exc.exception_id,
                  {"rule_id": exc.rule_id, "zone_id": exc.zone_id,
                   "expires_at": exc.expires_at, "reason": exc.reason})
        return exc.to_dict(now)

    def renew_exception(self, exception_id: str, new_expires_at: str, actor: str) -> dict:
        exc = self.catalog.get_exception(exception_id)
        old = exc.expires_at
        exc.renew(new_expires_at, self._now(), actor)
        self.catalog.save_exception(exc)
        self._log(actor, "exception.renewed", "exception", exception_id,
                  {"old_expires_at": old, "new_expires_at": new_expires_at,
                   "renewed_count": exc.renewed_count})
        return exc.to_dict(self._now())

    def revoke_exception(self, exception_id: str, actor: str) -> dict:
        exc = self.catalog.get_exception(exception_id)
        exc.revoke(self._now(), actor)
        self.catalog.save_exception(exc)
        self._log(actor, "exception.revoked", "exception", exception_id,
                  {"rule_id": exc.rule_id, "zone_id": exc.zone_id})
        return exc.to_dict(self._now())

    def list_exceptions(self) -> dict:
        now = self._now()
        items = [e.to_dict(now) for e in self.catalog.list_exceptions()]
        return {"now": now, "exceptions": items,
                "expired": [e["exception_id"] for e in items if e.get("expired")]}

    # ==================================================================
    # 预演与建批
    # ==================================================================
    def plan_release(self, *, snapshot_id: str | None = None, policy_id: str | None = None,
                     thresholds: dict | None = None, actor: str = "planner") -> dict:
        existing = self.releases.list_all()
        if existing and existing[0].status not in (
            ReleaseStatus.COMPLETED.value,
            ReleaseStatus.ROLLED_BACK.value,
        ):
            raise ConflictError("已有进行中的发布单，请先完成或回退",
                                {"release_id": existing[0].release_id})
        snapshot = (self.catalog.get(snapshot_id) if snapshot_id
                    else self.catalog.get_latest())
        policy = (self.catalog.get_policy(policy_id) if policy_id
                  else self.catalog.list_policies()[-1])
        thr = Thresholds(**(thresholds or {}))
        now = self._now()
        release_id = self.idgen.new_id("rel")
        batches, report = self._preflight.run(
            release_id, snapshot, policy,
            self.catalog.list_exceptions(), thr, now,
        )
        self._log(actor, "release.preflight_run", "release", release_id,
                  {"passable": report["passable"],
                   "capability_blockers": len(report["capability_blockers"]),
                   "blocked_services": len(report["reachability"]["blocked"]),
                   "expired_exceptions": len(report["expired_exceptions"])})
        if not report["passable"]:
            self._log(actor, "release.plan_rejected", "release", release_id,
                      {"blockers": report["capability_blockers"],
                       "blocked_services": report["reachability"]["blocked"]})
            raise ConflictError("预演未通过，不能生成发布计划", {"preflight": report})

        release = Release(
            release_id=release_id,
            snapshot_id=snapshot.snapshot_id,
            policy_id=policy.policy_id,
            thresholds=thr,
            created_at=now,
            status=ReleaseStatus.PLANNED.value,
            batches=batches or [],
            cursor=0,
            preflight=report,
        )
        self.releases.save(release)
        self._log(actor, "release.planned", "release", release_id,
                  {"snapshot_id": snapshot.snapshot_id, "policy_id": policy.policy_id,
                   "batches": len(release.batches), "cursor": 0})
        return {"release": release.to_dict(), "preflight": report}

    def get_release(self, release_id: str) -> dict:
        return self.releases.get(release_id).to_dict()

    def release_view(self, release_id: str) -> dict:
        """带游标恢复信息的视图：重启后据此知道该做什么。"""
        release = self.releases.get(release_id)
        cur = release.current_batch()
        return {
            "release": release.to_dict(),
            "resume_hint": {
                "status": release.status,
                "cursor": release.cursor,
                "current_batch_id": cur.batch_id if cur else None,
                "current_batch_status": cur.status if cur else None,
                "action": self._next_action(release),
            },
        }

    @staticmethod
    def _next_action(release: Release) -> str:
        if release.status == ReleaseStatus.PLANNED.value:
            return "dispatch_current_batch"
        if release.status == ReleaseStatus.ACTIVE.value:
            cur = release.current_batch()
            if cur is None:
                return "none"
            return {
                BatchStatus.PENDING.value: "dispatch_current_batch",
                BatchStatus.DISPATCHED.value: "collect_receipts",
                BatchStatus.HEALTH_WATCH.value: "submit_evidence",
                BatchStatus.AWAITING_APPROVAL.value: "await_role_confirmation",
            }.get(cur.status, "inspect")
        if release.status == ReleaseStatus.PAUSED.value:
            return "start_rollback" if release.rollback_plan else "resume_or_keep_paused"
        if release.status in (ReleaseStatus.ROLLING_BACK.value,
                              ReleaseStatus.PARTIALLY_ROLLED_BACK.value):
            return "collect_rollback_receipts"
        return "none"

    # ==================================================================
    # 下发与回执
    # ==================================================================
    def _load(self) -> Release:
        releases = self.releases.list_all()
        if not releases:
            raise NotFoundError("尚无发布单")
        return releases[0]

    def dispatch_current(self, actor: str = SYSTEM_ACTOR) -> dict:
        """下发游标所在批次（金丝雀或后续批次）。"""
        release = self._load()
        if release.status not in (ReleaseStatus.PLANNED.value, ReleaseStatus.ACTIVE.value):
            raise ConflictError("发布单当前状态不允许下发",
                                {"release_id": release.release_id, "status": release.status})
        batch = release.current_batch()
        if batch is None:
            raise ConflictError("发布游标已越过最后批次", {"cursor": release.cursor})
        if batch.status != BatchStatus.PENDING.value:
            raise ConflictError("当前批次不在待下发状态（如需重发请使用 resend_current）",
                                {"batch_id": batch.batch_id, "status": batch.status})

        outcomes = self.gateway.send_commands(batch.commands)
        dispatched = [cid for cid, o in outcomes.items() if o == "dispatched"]
        duplicate = [cid for cid, o in outcomes.items() if o == "duplicate"]
        batch.status = BatchStatus.DISPATCHED.value
        batch.dispatched_at = batch.dispatched_at or self._now()
        if release.status == ReleaseStatus.PLANNED.value:
            release.status = ReleaseStatus.ACTIVE.value
        self.releases.save(release)
        self._log(actor, "batch.dispatched", "batch", batch.batch_id,
                  {"index": batch.index, "kind": batch.kind, "zone_id": batch.zone_id,
                   "dispatched": len(dispatched), "duplicate": len(duplicate),
                   "release_cursor": release.cursor})
        return {"batch_id": batch.batch_id, "index": batch.index,
                "status": batch.status, "dispatched": len(dispatched),
                "duplicate": duplicate}

    def resend_current(self, actor: str) -> dict:
        """显式重复下发（演示重复命令幂等）：所有命令均返回 duplicate。"""
        release = self._load()
        batch = release.current_batch()
        if batch is None or batch.status not in (
            BatchStatus.DISPATCHED.value, BatchStatus.HEALTH_WATCH.value,
        ):
            raise ConflictError("仅在制批次可以重复下发", {"cursor": release.cursor})
        outcomes = self.gateway.send_commands(batch.commands)
        duplicate = [cid for cid, o in outcomes.items() if o == "duplicate"]
        self.releases.save(release)
        self._log(actor, "batch.redispatched_duplicate", "batch", batch.batch_id,
                  {"duplicate": len(duplicate), "dispatch_counts":
                   {c.command_id: c.dispatch_count for c in batch.commands}})
        return {"batch_id": batch.batch_id, "duplicate_commands": duplicate,
                "note": "重复命令被幂等抑制，未改变任何设备状态"}

    def _find_command(self, release: Release, command_id: str):
        for batch in release.batches:
            cmd = batch.command(command_id)
            if cmd is not None:
                return batch, cmd
        raise NotFoundError(f"命令不存在: {command_id}")

    def receive_receipt(self, command_id: str, status: str, seq: int,
                        actor: str = "device") -> dict:
        """采纳设备回执；旧序号回执拒绝覆盖新状态。"""
        release = self._load()
        batch, cmd = self._find_command(release, command_id)
        # 恶化冻结/回退开始后，正向回执不再改变已定稿的状态与回退计划
        frozen_by_rollback = (
            release.rollback_plan is not None
            and release.status in (
                ReleaseStatus.PAUSED.value,
                ReleaseStatus.ROLLING_BACK.value,
                ReleaseStatus.PARTIALLY_ROLLED_BACK.value,
                ReleaseStatus.ROLLED_BACK.value,
            )
        )
        if frozen_by_rollback:
            self._log(actor, "receipt.ignored_after_rollback", "command", command_id,
                      {"seq": seq, "status": status,
                       "current_state": cmd.status,
                       "release_status": release.status})
            return {"command_id": command_id, "verdict": "ignored_rollback_started",
                    "state": cmd.status, "batch_status": batch.status,
                    "auto_events": [], "release_status": release.status}
        before = cmd.status
        verdict = cmd.apply_receipt(status, seq, self._now())
        self._log(actor, "receipt.received", "command", command_id,
                  {"batch_id": batch.batch_id, "seq": seq, "status": status,
                   "verdict": verdict, "state_before": before,
                   "state_after": cmd.status, "last_seq": cmd.last_receipt_seq})
        if verdict == "stale":
            # 旧回执：不落业务状态，仅审计留存
            return {"command_id": command_id, "verdict": "stale",
                    "state": before, "last_seq": cmd.last_receipt_seq}

        auto_events: list[str] = []
        if batch.status == BatchStatus.DISPATCHED.value:
            gate = batch.check_deploy_gate(release.thresholds.deploy_ratio)
            if gate == "watch":
                batch.status = BatchStatus.HEALTH_WATCH.value
                auto_events.append("deploy_gate_passed:enter_health_watch")
                self._log(SYSTEM_ACTOR, "batch.deploy_gate_passed", "batch", batch.batch_id,
                          {"deploy_ratio": batch.deploy_ratio(),
                           "threshold": release.thresholds.deploy_ratio})
                # 部署期已有证据时立即补评估一次，避免批次卡在观测态
                if batch.latest_evidence():
                    self._evaluate_gate(release, batch, auto_events)
            elif gate == "failed":
                self._degrade(release, batch,
                              f"部署比例 {batch.deploy_ratio():.2%} 未达阈值 "
                              f"{release.thresholds.deploy_ratio:.2%}，设备回执已收敛",
                              cause="deploy_gate")
                auto_events.append("degraded:rollback_plan_generated")

        self.releases.save(release)
        return {"command_id": command_id, "verdict": verdict,
                "state": cmd.status, "batch_status": batch.status,
                "auto_events": auto_events,
                "release_status": release.status}

    # ==================================================================
    # 健康证据与门禁
    # ==================================================================
    def submit_evidence(self, batch_id: str, *, source: str, seq: int,
                        health_score: float, critical_reachable: dict[str, bool],
                        actor: str = "observer") -> dict:
        release = self._load()
        batch = release.batch(batch_id)
        now = self._now()
        item = HealthEvidence(
            evidence_id=self.idgen.new_id("ev"),
            source=source, seq=seq, observed_at=now, adopted_at=now,
            health_score=health_score, critical_reachable=dict(critical_reachable),
        )
        verdict = batch.adopt_evidence(item)
        self._log(actor, "evidence.submitted", "batch", batch_id,
                  {"source": source, "seq": seq, "health_score": health_score,
                   "critical_blocked": [s for s, ok in critical_reachable.items() if not ok],
                   "verdict": verdict})
        if verdict == "stale":
            return {"batch_id": batch_id, "verdict": "stale",
                    "last_seq": batch.evidence_seq_by_source.get(source, 0)}

        auto_events: list[str] = []
        if batch.status == BatchStatus.HEALTH_WATCH.value:
            self._evaluate_gate(release, batch, auto_events)

        self.releases.save(release)
        return {"batch_id": batch_id, "verdict": verdict,
                "batch_status": batch.status, "auto_events": auto_events,
                "release_status": release.status}

    def _evaluate_gate(self, release: Release, batch, auto_events: list[str]) -> None:
        """健康门禁统一评估：即时恶化 / 窗口满通过或失败 / 窗口未满等待。"""
        now = self._now()
        evaluation = batch.evaluate_health(
            now, release.thresholds.health_window_seconds,
            release.thresholds.health_threshold,
            release.thresholds.degrade_floor,
        )
        self._log(SYSTEM_ACTOR, "batch.health_evaluated", "batch", batch.batch_id,
                  {"passed": evaluation.passed, "reason": evaluation.reason,
                   "mean_health": evaluation.mean_health, "samples": evaluation.samples,
                   "critical_blocked": evaluation.critical_blocked})
        instant_bad = bool(evaluation.critical_blocked) or any(
            ev.health_score < release.thresholds.degrade_floor
            for ev in batch.latest_evidence()
        )
        window_open = "观测窗口未满" in evaluation.reason
        if instant_bad:
            # 关键业务被阻断或突破恶化底线：立即冻结后续批次并生成回退计划
            self._degrade(release, batch, evaluation.reason, cause="health")
            auto_events.append("degraded:rollback_plan_generated")
        elif evaluation.passed:
            batch.status = BatchStatus.AWAITING_APPROVAL.value
            auto_events.append(f"health_gate_passed:await_{batch.required_role}")
            self._log(SYSTEM_ACTOR, "batch.health_gate_passed", "batch", batch.batch_id,
                      {"required_role": batch.required_role})
        elif not window_open:
            # 窗口已满（含无证据情形）但未达阈值：门禁失败，转恶化回退
            self._degrade(release, batch,
                          f"观测窗口结束但{evaluation.reason}", cause="health")
            auto_events.append("degraded:rollback_plan_generated")

    def _degrade(self, release: Release, batch, reason: str, cause: str) -> None:
        """观测恶化：冻结所有未开始批次，批次标记恶化，生成依赖逆序回退计划。"""
        batch.status = (BatchStatus.FAILED.value if cause == "deploy_gate"
                        else BatchStatus.DEGRADED.value)
        batch.degraded_reason = reason
        frozen = release.freeze_pending(self._now())
        steps = release.build_rollback_steps()
        release.rollback_plan = RollbackPlan(generated_at=self._now(), reason=reason, steps=steps)
        release.status = ReleaseStatus.PAUSED.value
        release.paused_at = self._now()
        release.pause_reason = reason
        self._log(SYSTEM_ACTOR, "release.degraded", "release", release.release_id,
                  {"batch_id": batch.batch_id, "cause": cause, "reason": reason,
                   "frozen_batches": frozen})
        self._log(SYSTEM_ACTOR, "rollback.plan_generated", "release", release.release_id,
                  {"reason": reason, "steps": len(steps),
                   "steps_detail": [s.to_dict() for s in steps]})

    # ==================================================================
    # 角色确认与游标推进
    # ==================================================================
    def confirm_batch(self, batch_id: str, role: str, actor: str, note: str = "") -> dict:
        if role not in ALL_ROLES:
            raise AuthorizationError("未知角色", {"given": role})
        release = self._load()
        batch = release.batch(batch_id)
        approval = batch.confirm(role, actor, self._now(), note)
        self._log(actor, "batch.confirmed", "batch", batch_id,
                  {"role": role, "required_role": batch.required_role, "note": note})

        auto_events: list[str] = []
        if batch.index == release.cursor:
            release.cursor += 1
            nxt = release.current_batch()
            if nxt is None:
                release.status = ReleaseStatus.COMPLETED.value
                release.completed_at = self._now()
                auto_events.append("release_completed")
                self._log(SYSTEM_ACTOR, "release.completed", "release", release.release_id,
                          {"batches": len(release.batches)})
            else:
                auto_events.append(f"cursor_advanced:{release.cursor}:await_dispatch")
            self._log(SYSTEM_ACTOR, "release.cursor_advanced", "release", release.release_id,
                      {"cursor": release.cursor, "next_batch": nxt.batch_id if nxt else None})
        self.releases.save(release)
        return {"batch_id": batch_id, "approval": approval.to_dict(),
                "cursor": release.cursor, "release_status": release.status,
                "auto_events": auto_events}

    # ==================================================================
    # 人工暂停 / 恢复
    # ==================================================================
    def pause_release(self, actor: str, reason: str) -> dict:
        release = self._load()
        if release.status not in (ReleaseStatus.ACTIVE.value, ReleaseStatus.PLANNED.value):
            raise ConflictError("仅进行中的发布可以暂停", {"status": release.status})
        frozen = release.freeze_pending(self._now())
        release.status = ReleaseStatus.PAUSED.value
        release.paused_at = self._now()
        release.pause_reason = reason
        self.releases.save(release)
        self._log(actor, "release.paused", "release", release.release_id,
                  {"reason": reason, "frozen_batches": frozen})
        return {"status": release.status, "frozen_batches": frozen}

    def resume_release(self, actor: str) -> dict:
        release = self._load()
        if release.status != ReleaseStatus.PAUSED.value:
            raise ConflictError("发布未暂停，无法恢复", {"status": release.status})
        if release.rollback_plan is not None:
            raise ConflictError("恶化暂停已生成回退计划，不能直接恢复，请执行回退",
                                {"plan_steps": len(release.rollback_plan.steps)})
        unfrozen: list[str] = []
        for b in release.batches:
            if b.status == BatchStatus.PAUSED.value:
                b.status = BatchStatus.PENDING.value
                b.paused_at = None
                unfrozen.append(b.batch_id)
        release.status = ReleaseStatus.ACTIVE.value
        release.paused_at = None
        release.pause_reason = None
        self.releases.save(release)
        self._log(actor, "release.resumed", "release", release.release_id,
                  {"unfrozen_batches": unfrozen, "cursor": release.cursor})
        return {"status": release.status, "unfrozen_batches": unfrozen,
                "cursor": release.cursor}

    # ==================================================================
    # 回退（遵循依赖逆序，支持部分回退）
    # ==================================================================
    def start_rollback(self, actor: str) -> dict:
        release = self._load()
        plan = release.rollback_plan
        if plan is None:
            raise ConflictError("不存在回退计划（仅恶化暂停后自动生成）")
        # 回退已全部完成时，重复启动为幂等空操作（重复命令的一类）
        if (plan.status == RollbackPlanStatus.DONE.value
                and release.status == ReleaseStatus.ROLLED_BACK.value):
            self._log(actor, "rollback.start_ignored_already_done", "release",
                      release.release_id, {"steps": len(plan.steps)})
            return {"status": release.status, "sent": [], "duplicate": [],
                    "plan": plan.to_dict()}
        if release.status not in (ReleaseStatus.PAUSED.value,
                                  ReleaseStatus.PARTIALLY_ROLLED_BACK.value):
            raise ConflictError("当前状态不能启动回退", {"status": release.status})

        release.status = ReleaseStatus.ROLLING_BACK.value
        by_id = {c.command_id: c for b in release.batches for c in b.commands}
        sent: list[str] = []
        duplicate: list[str] = []
        for step in plan.steps:
            if step.status == RollbackPlanStatus.SKIPPED.value:
                continue
            if step.status == RollbackPlanStatus.DONE.value:
                continue  # 已完成的回退绝不重复执行
            # PLANNED/EXECUTING（重启后重发）/FAILED（部分回退后重试）都重新发送
            cmd = by_id[step.command_id]
            outcomes = self.gateway.send_commands([cmd], rollback=True)
            if outcomes[step.command_id] == "duplicate":
                duplicate.append(step.command_id)
            else:
                sent.append(step.command_id)
            step.status = RollbackPlanStatus.EXECUTING.value
            affected = release.batches[step.batch_index]
            if affected.status not in (BatchStatus.ROLLING_BACK.value,
                                       BatchStatus.PARTIALLY_ROLLED_BACK.value):
                affected.status = BatchStatus.ROLLING_BACK.value
        plan.recompute_status()
        self.releases.save(release)
        self._log(actor, "rollback.started", "release", release.release_id,
                  {"sent": len(sent), "duplicate": len(duplicate),
                   "skipped": sum(1 for s in plan.steps
                                  if s.status == RollbackPlanStatus.SKIPPED.value),
                   "order": [s.command_id for s in plan.steps]})
        return {"status": release.status, "sent": sent, "duplicate": duplicate,
                "plan": plan.to_dict()}

    def receive_rollback_receipt(self, command_id: str, status: str, seq: int,
                                 actor: str = "device") -> dict:
        release = self._load()
        plan = release.rollback_plan
        if plan is None:
            raise ConflictError("不存在回退计划")
        batch, cmd = self._find_command(release, command_id)
        step = plan.step(command_id)
        if step is None or step.status == RollbackPlanStatus.SKIPPED.value:
            raise ConflictError("该命令不在回退计划中（可能原本就未生效）",
                                {"command_id": command_id})
        verdict = cmd.apply_rollback_receipt(status, seq, self._now())
        self._log(actor, "rollback.receipt_received", "command", command_id,
                  {"seq": seq, "status": status, "verdict": verdict,
                   "rollback_state": cmd.rollback_status})
        if verdict == "stale":
            return {"command_id": command_id, "verdict": "stale",
                    "rollback_state": cmd.rollback_status}

        if status == ReceiptStatus.APPLIED.value:
            step.status = RollbackPlanStatus.DONE.value
            step.detail = "已恢复到发布前状态"
        else:
            step.status = RollbackPlanStatus.FAILED.value
            step.detail = f"设备回退未成功: {status}"

        plan.recompute_status()
        self._finalize_rollback_if_terminal(release, batch)
        self.releases.save(release)
        return {"command_id": command_id, "verdict": verdict,
                "step_status": step.status, "plan_status": plan.status,
                "release_status": release.status}

    def _finalize_rollback_if_terminal(self, release: Release, current_batch) -> None:
        plan = release.rollback_plan
        pending = [s for s in plan.steps
                   if s.status in (RollbackPlanStatus.PLANNED.value,
                                   RollbackPlanStatus.EXECUTING.value)]
        if pending:
            return
        failed = [s for s in plan.steps if s.status == RollbackPlanStatus.FAILED.value]
        # 批次粒度状态
        steps_by_batch: dict[int, list] = {}
        for s in plan.steps:
            steps_by_batch.setdefault(s.batch_index, []).append(s)
        for idx, steps in steps_by_batch.items():
            bstatuses = {s.status for s in steps}
            b = release.batches[idx]
            if bstatuses <= {RollbackPlanStatus.DONE.value, RollbackPlanStatus.SKIPPED.value}:
                b.status = BatchStatus.ROLLED_BACK.value
            else:
                b.status = BatchStatus.PARTIALLY_ROLLED_BACK.value
        if failed:
            release.status = ReleaseStatus.PARTIALLY_ROLLED_BACK.value
            self._log(SYSTEM_ACTOR, "rollback.partial", "release", release.release_id,
                      {"failed_steps": [s.command_id for s in failed]})
        else:
            release.status = ReleaseStatus.ROLLED_BACK.value
            self._log(SYSTEM_ACTOR, "rollback.completed", "release", release.release_id,
                      {"steps": len(plan.steps)})

    # ==================================================================
    # 审计与诊断
    # ==================================================================
    def audit_entries(self, target_id: str | None = None) -> list[dict]:
        return [e.to_dict() for e in self.audit.entries(target_id)]

    def verify_audit(self) -> dict:
        return self.audit.verify()

    def gateway_records(self) -> list[dict]:
        return self.gateway.sent_records()
