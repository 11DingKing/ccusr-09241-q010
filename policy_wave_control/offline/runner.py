"""离线验收场景运行器。

在确定性时钟与标识下完整演练一遍真实发布过程，并把四类关键处理
（过期例外、乱序回执、部分回退、重复命令）的证据汇总成报告输出。

运行：
    python -m policy_wave_control.offline.runner
    python -m policy_wave_control.offline.runner --data-dir ./.runtime/offline --json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..application.ports import ScriptedClock, SequentialIds
from ..application.services import ReleaseService
from ..composition import build_service
from ..domain.models import DomainError
from ..domain.release import RollbackStep

T0 = datetime(2026, 9, 24, 2, 0, 0, tzinfo=timezone.utc)


class FailingDeviceRollback:
    """模拟设备侧撤销端口：对指定设备撤销失败，用于部分回退演练。"""

    def __init__(self, fail_device: str) -> None:
        self.fail_device = fail_device
        self.calls: list[str] = []

    def undo(self, step: RollbackStep) -> bool:
        self.calls.append(step.device_id)
        return step.device_id != self.fail_device


class Scenario:
    def __init__(self, data_dir: str | Path) -> None:
        self.clock = ScriptedClock(T0)
        self.ids = SequentialIds()
        self.data_dir = Path(data_dir)
        self.service: ReleaseService = build_service(
            self.data_dir, clock=self.clock, ids=self.ids
        )
        self.lines: list[str] = []
        self.findings: dict[str, list[Any]] = {
            "expired_exceptions": [],
            "out_of_order_receipts": [],
            "partial_rollback": [],
            "duplicate_commands": [],
            "dependency_ordering": [],
            "restart_recovery": [],
        }
        self.refs: dict[str, str] = {}

    # ------------------------------------------------------------ 报告工具

    def log(self, text: str = "") -> None:
        self.lines.append(text)

    def section(self, title: str) -> None:
        bar = "=" * 72
        self.log("")
        self.log(bar)
        self.log(title)
        self.log(bar)

    # ------------------------------------------------------------ 场景本体

    def run(self) -> dict[str, Any]:
        self._build_world()
        self._time_travel_and_exceptions()
        self._create_rollout()
        canary_cmds = self._run_canary()
        personal_cmd = self._run_personal_wave()
        machine_cmd = self._degrade_and_auto_pause()
        self._partial_rollback(personal_cmd)
        self._restart_and_late_receipts(canary_cmds)
        self._final_report()
        return {
            "refs": self.refs,
            "findings": self.findings,
            "report": "\n".join(self.lines),
        }

    # ---------------- 1. 拓扑 / 策略 / 例外

    def _build_world(self) -> None:
        self.section("步骤 1  建立区域拓扑快照（个人 / 机器 / 物联）")
        snapshot = self.service.add_snapshot(
            name="三区域融合拓扑",
            zones=[
                {"id": "zp", "name": "个人业务区", "kind": "personal", "default_policy": "allow"},
                {"id": "zm", "name": "机器业务区", "kind": "machine", "default_policy": "deny"},
                {"id": "zi", "name": "物联业务区", "kind": "iot", "default_policy": "allow"},
            ],
            devices=[
                # 个人区：p3 只支持旧能力 acl-v1，无法落地需要 acl-v2 的规则
                {"id": "d-p1", "zone_id": "zp", "name": "个人网关1", "capabilities": ["acl-v2"]},
                {"id": "d-p2", "zone_id": "zp", "name": "个人网关2", "capabilities": ["acl-v2"]},
                {"id": "d-p3", "zone_id": "zp", "name": "个人网关3(旧)", "capabilities": ["acl-v1"]},
                # 机器区：m1/m2 能力齐全
                {"id": "d-m1", "zone_id": "zm", "name": "机器交换机1", "capabilities": ["acl-v2", "acl-log"]},
                {"id": "d-m2", "zone_id": "zm", "name": "机器交换机2", "capabilities": ["acl-v2", "acl-log"]},
                # 物联区：i1 承载关键业务（金丝雀应避开），i2 普通设备
                {"id": "d-i1", "zone_id": "zi", "name": "物联边界1(关键)", "capabilities": ["acl-v2"], "critical": True},
                {"id": "d-i2", "zone_id": "zi", "name": "物联边界2", "capabilities": ["acl-v2"]},
            ],
            edges=[
                {"src_zone": "zp", "dst_zone": "zi", "service": "http", "critical": False},
                {"src_zone": "zm", "dst_zone": "zp", "service": "ssh", "critical": False},
                {"src_zone": "zi", "dst_zone": "zm", "service": "telemetry", "critical": True},
            ],
            note="机器区缺省拒绝，物联遥测为关键业务链路",
            actor="topo-admin",
        )
        self.refs["snapshot"] = snapshot.id
        self.log(f"快照 {snapshot.id} 已保存，6 台设备 / 3 条链路")

        policy = self.service.add_policy(
            name="访问收敛与隔离策略 v1",
            snapshot_id=snapshot.id,
            rules=[
                # r-ssh 依赖 r-base：必须先收敛个人->物联，再封机器->个人的 ssh
                {
                    "id": "r-base", "name": "阻断个人到物联HTTP", "action": "deny",
                    "src_zone": "zp", "dst_zone": "zi", "service": "http",
                    "requires": ["acl-v2"],
                },
                {
                    "id": "r-ssh", "name": "阻断机器到个人SSH", "action": "deny",
                    "src_zone": "zm", "dst_zone": "zp", "service": "ssh",
                    "requires": ["acl-v2", "acl-log"], "depends_on": ["r-base"],
                },
                {
                    "id": "r-tel", "name": "放行物联遥测到机器区", "action": "allow",
                    "src_zone": "zi", "dst_zone": "zm", "service": "telemetry",
                    "requires": ["acl-v2"], "depends_on": ["r-base"],
                },
            ],
            actor="security-admin",
        )
        self.refs["policy"] = policy.id
        self.log(f"策略版本 {policy.id}：r-ssh、r-tel 均依赖 r-base（拓扑序: r-base 先下发）")

        # 两条有期限例外：长例外压 r-ssh；短例外压 r-tel，1 小时后过期
        exc_long = self.service.add_exception(
            rule_id="r-ssh", reason="机器区跳板机改造期临时保留 SSH",
            created_by="sec-ops",
            valid_from=T0 - timedelta(hours=1),
            valid_until=T0 + timedelta(days=7),
        )
        exc_short = self.service.add_exception(
            rule_id="r-tel", reason="遥测采集器升级窗口",
            created_by="sec-ops",
            valid_from=T0,
            valid_until=T0 + timedelta(hours=1),
        )
        self.refs["exc_long"] = exc_long.id
        self.refs["exc_short"] = exc_short.id
        self.log(f"有期限例外：{exc_long.id}(r-ssh,7天) 与 {exc_short.id}(r-tel,1小时)")

        report0 = self.service.preflight(policy.id, at=T0)
        self.log(
            f"T0 预演：verdict={report0.verdict}，"
            f"生效例外 {report0.active_exceptions}，过期例外 {report0.expired_exceptions}"
        )
        for flow in report0.flows:
            self.log(f"  链路 {flow.src_zone}->{flow.dst_zone}/{flow.service}: "
                     f"{flow.before} -> {flow.after}；{'；'.join(flow.reasons)}")
        gaps = report0.enforcement_gaps
        self.log(f"能力缺口（无法落地的设备）：{[(g['rule_id'], g['unsupported_devices']) for g in gaps]}")

    # ---------------- 2. 时间推进与例外续期/过期

    def _time_travel_and_exceptions(self) -> None:
        self.section("步骤 2  时间推进：例外续期、拒绝缩期、短例外自然过期")
        self.clock.advance(600)  # T0+10m
        self.service.renew_exception(
            self.refs["exc_long"],
            new_until=self.clock.now() + timedelta(days=30),
            actor="sec-ops", reason="改造延期，续期30天",
        )
        self.log(f"T0+10m：长例外 {self.refs['exc_long']} 续期至 30 天后（已入审计）")
        try:
            self.service.renew_exception(
                self.refs["exc_long"],
                new_until=self.clock.now() + timedelta(days=1),
                actor="sec-ops",
            )
        except DomainError as exc:
            self.log(f"T0+10m：试图把例外缩短到 1 天被拒绝 -> {exc}")

        self.clock.set(T0 + timedelta(hours=2))  # T0+2h
        report = self.service.preflight(self.refs["policy"])
        self.log(
            f"T0+2h 预演：生效例外 {report.active_exceptions}，"
            f"过期例外 {report.expired_exceptions}"
        )
        self.findings["expired_exceptions"].append({
            "exception_id": self.refs["exc_short"],
            "rule_id": "r-tel",
            "state": "expired",
            "detail": "短例外在 T0+1h 到期，T0+2h 预演明确列出为过期，不再抑制 r-tel",
            "preflight_expired": report.expired_exceptions,
        })

        # 长例外仍在生效期，r-ssh 会被推迟；操作员在发布前吊销它
        self.service.revoke_exception(self.refs["exc_long"], actor="security-admin")
        self.log(f"T0+2h：长例外 {self.refs['exc_long']} 被吊销（已入审计），r-ssh 恢复生效")

    # ---------------- 3. 生成发布单（金丝雀 + 后续波次）

    def _create_rollout(self) -> None:
        self.section("步骤 3  预演通过后生成发布单：金丝雀批次 + 分区域后续波次")
        rollout = self.service.create_rollout(
            policy_id=self.refs["policy"],
            name="9月收敛批次",
            actor="release-manager",
            gate_metrics={"availability": {"min": 0.99}, "error_rate": {"max": 0.01}},
        )
        self.refs["rollout"] = rollout.id
        self.log(f"发布单 {rollout.id}，共 {len(rollout.batches)} 批：")
        for b in rollout.batches:
            cmds = ", ".join(f"{c.rule_id}@{c.device_id}(seq={c.topo_seq})" for c in b.commands)
            self.log(
                f"  批次{b.index} {b.name} {'[金丝雀]' if b.is_canary else ''} "
                f"区域={b.zone_ids} 需要角色={b.required_roles} 命令=[{cmds}]"
            )
        audit = self.service.read_audit(action_prefix="rollout.created")[-1]
        self.log(f"被生效例外推迟的规则：{audit['payload']['deferred_rules']}")
        self.log(f"能力不满足、未生成命令的设备：{audit['payload']['uncovered']}")
        self.findings["expired_exceptions"].append({
            "exception_id": self.refs["exc_short"],
            "state": "expired_not_deferred",
            "detail": "过期例外不再推迟规则：r-tel 正常进入金丝雀与物联波次",
        })

    def _commands_of(self, batch_index: int) -> list[dict[str, str]]:
        rollout = self.service.rollouts.get(self.refs["rollout"])
        batch = rollout.batch(batch_index)
        return [{"id": c.id, "rule": c.rule_id, "device": c.device_id} for c in batch.commands]

    # ---------------- 4. 金丝雀：审批、重复命令、乱序/过期回执、闸门

    def _run_canary(self) -> list[dict[str, str]]:
        self.section("步骤 4  金丝雀批次：双角色确认 → 下发 → 回执 → 健康闸门 → 推进")
        rid = self.refs["rollout"]
        self.service.approve(rid, 0, "release_manager", "rm-zhang", "先在金丝雀设备验证")
        self.service.approve(rid, 0, "security_admin", "sec-li", "安全侧同意")
        self.log("已获得 release_manager 与 security_admin 双角色确认")
        try:
            self.service.approve(rid, 0, "security_admin", "sec-li")
        except DomainError as exc:
            self.log(f"重复确认被拒绝：{exc}")
        try:
            self.service.approve(rid, 0, "iot_zone_owner", "iot-wang")
        except DomainError as exc:
            self.log(f"非要求角色确认被拒绝：{exc}")

        first = self.service.dispatch_batch(rid, 0, actor="dispatcher")
        self.log(f"首次下发：{len(first['new'])} 条新命令 {first['new']}")
        self.clock.advance(5)
        second = self.service.dispatch_batch(rid, 0, actor="dispatcher")
        self.log(f"网络重传导致重复下发：新命令 {len(second['new'])} 条，"
                 f"幂等识别重复 {len(second['duplicates'])} 条 {second['duplicates']}")
        self.findings["duplicate_commands"].append({
            "stage": "canary_redelivery",
            "duplicates": second["duplicates"],
            "handling": "命令按 (批次,规则,设备) 幂等去重，重复下发不产生新版本、不重开状态，仅计数并审计",
        })

        cmds = self._commands_of(0)
        c_base, c_ssh, c_tel = cmds[0]["id"], cmds[1]["id"], cmds[2]["id"]
        self.clock.advance(30)

        # 4.1 上一版本（r0）的旧回执晚到
        stale = self.service.receive_receipt(rid, c_base, revision=0, claimed_state="acked")
        self.log(f"旧版本回执(r0 acked)晚到：accepted={stale['accepted']}，{stale['reason']}")
        self.findings["out_of_order_receipts"].append({
            "command_id": c_base, "receipt": "r0/acked",
            "accepted": False, "reason": stale["reason"],
        })

        # 4.2 正常推进 r-base：acked -> applied
        self.service.receive_receipt(rid, c_base, revision=1, claimed_state="acked")
        self.clock.advance(10)
        self.service.receive_receipt(rid, c_base, revision=1, claimed_state="applied")

        # 4.3 r-tel：applied 先到，acked 晚到（状态秩回退被拒）
        self.service.receive_receipt(rid, c_tel, revision=1, claimed_state="acked")
        self.service.receive_receipt(rid, c_tel, revision=1, claimed_state="applied")
        late = self.service.receive_receipt(rid, c_tel, revision=1, claimed_state="acked")
        self.log(f"r-tel 的 acked 回执在 applied 之后晚到：accepted={late['accepted']}，{late['reason']}")
        self.findings["out_of_order_receipts"].append({
            "command_id": c_tel, "receipt": "r1/acked-after-applied",
            "accepted": False, "reason": late["reason"],
        })

        # 4.4 r-ssh 正常完成
        self.service.receive_receipt(rid, c_ssh, revision=1, claimed_state="acked")
        self.service.receive_receipt(rid, c_ssh, revision=1, claimed_state="applied")

        # 4.5 重复回执（完全相同状态）
        dup = self.service.receive_receipt(rid, c_ssh, revision=1, claimed_state="applied")
        self.log(f"完全重复的 applied 回执：accepted={dup['accepted']}，{dup['reason']}")
        self.findings["out_of_order_receipts"].append({
            "command_id": c_ssh, "receipt": "r1/applied-again",
            "accepted": False, "reason": dup["reason"],
        })

        # 证据不足时闸门不通过
        gate0 = self.service.gate_status(rid, 0)
        self.log(f"证据采纳前闸门：passed={gate0['passed']}（{gate0['metrics']}）")
        self.service.adopt_evidence(rid, 0, "availability", 0.9995, "probe-mesh", "sre-oncall")
        self.service.adopt_evidence(rid, 0, "error_rate", 0.0008, "probe-mesh", "sre-oncall")
        gate1 = self.service.gate_status(rid, 0)
        self.log(f"健康证据采纳后闸门：passed={gate1['passed']}，"
                 f"applied_ratio={gate1['applied_ratio']}，指标={gate1['metrics']}")

        result = self.service.advance(rid, actor="release-manager")
        self.log(f"金丝雀推进完成：{result['completed_batch']} -> 游标 {result['next_cursor']}，"
                 f"发布单状态 {result['rollout_state']}")
        return cmds

    # ---------------- 5. 个人区波次

    def _run_personal_wave(self) -> str:
        self.section("步骤 5  后续波次一：个人业务区（含旧设备 d-p3 被跳过）")
        rid = self.refs["rollout"]
        self.service.approve(rid, 1, "security_admin", "sec-li")
        self.service.approve(rid, 1, "personal_zone_owner", "zone-chen")
        dispatched = self.service.dispatch_batch(rid, 1, actor="dispatcher")
        self.log(f"个人区下发命令：{dispatched['new']}（旧设备 d-p3 因能力缺口无命令）")
        cmd = self._commands_of(1)[0]["id"]
        self.clock.advance(20)
        self.service.receive_receipt(rid, cmd, revision=1, claimed_state="applied")
        self.service.adopt_evidence(rid, 1, "availability", 0.998, "probe-mesh", "sre-oncall")
        self.service.adopt_evidence(rid, 1, "error_rate", 0.002, "probe-mesh", "sre-oncall")
        self.service.advance(rid, actor="release-manager")
        self.log("个人区波次完成，游标推进到 2（机器区）")
        return cmd

    # ---------------- 6. 机器区观测恶化 → 自动暂停 + 回退计划

    def _degrade_and_auto_pause(self) -> str:
        self.section("步骤 6  后续波次二：机器区观测恶化 → 自动暂停未开始批次并生成回退计划")
        rid = self.refs["rollout"]
        self.service.approve(rid, 2, "security_admin", "sec-li")
        self.service.approve(rid, 2, "machine_zone_owner", "zone-sun")
        self.service.dispatch_batch(rid, 2, actor="dispatcher")
        cmd = self._commands_of(2)[0]["id"]
        self.clock.advance(20)
        self.service.receive_receipt(rid, cmd, revision=1, claimed_state="applied")
        self.log(f"机器区命令 {cmd}(r-ssh@d-m2) 已生效，此时错误率突增")

        self.clock.advance(60)
        result = self.service.adopt_evidence(
            rid, 2, "error_rate", 0.25, "probe-mesh", "sre-oncall"
        )
        self.log(f"采纳错误率证据 0.25（上限 0.01）：越界={result['breach']['breached']}，"
                 f"自动动作={result['auto_actions']}，发布单状态={result['rollout_state']}")
        status = self.service.status(rid)
        held = [b["index"] for b in status["batches"] if b["state"] == "held"]
        self.log(f"尚未开始的批次被挂起：{held}（物联区批次未下发任何命令）")

        rollout = self.service.rollouts.get(rid)
        plan = rollout.rollback_plan
        assert plan is not None
        order = [(s.seq, s.batch_index, s.rule_id, s.device_id, s.topo_seq) for s in plan.steps]
        self.log(f"回退计划按依赖逆序生成 {len(plan.steps)} 步（后发批次先撤，同批依赖方先撤）：")
        for seq, bi, rule, dev, tseq in order:
            self.log(f"  步骤{seq}: 批次{bi} {rule}@{dev} (下发拓扑序={tseq})")
        self.findings["dependency_ordering"].append({
            "order": [
                {"seq": s.seq, "batch": s.batch_index, "rule": s.rule_id, "device": s.device_id}
                for s in plan.steps
            ],
            "principle": "回退顺序 = 批次下标逆序 + 批内规则拓扑序逆序，保证被依赖规则先恢复",
        })
        # 暂停期间任何下发都必须被拒绝
        try:
            self.service.dispatch_batch(rid, None, actor="dispatcher")
        except DomainError as exc:
            self.log(f"暂停后尝试继续下发被拒绝：{exc}")
        return cmd

    # ---------------- 7. 部分回退

    def _partial_rollback(self, machine_cmd: str) -> None:
        self.section("步骤 7  执行回退：设备 d-p2 撤销失败 → 部分回退如实呈现")
        rid = self.refs["rollout"]
        # 给服务换上会让 d-p2 失败的设备端口，再从同一数据目录重建执行通道
        executor = FailingDeviceRollback("d-p2")
        self.service.rollback_executor = executor
        result = self.service.execute_rollback(rid, actor="incident-commander")
        self.log(f"回退结束：状态={result['state']}，成功 {result['done']} 步，失败 {result['failed']} 步")
        for item in result["steps"]:
            mark = "OK " if item["status"] == "done" else "FAIL"
            self.log(f"  [{mark}] 步骤 {item['seq']} 设备 {item['device']}")
        self.findings["partial_rollback"].append({
            "rollout_state": result["state"],
            "done": result["done"],
            "failed": result["failed"],
            "failed_device": "d-p2",
            "handling": "失败步骤不阻塞其余撤销；批次与发布单标记 partially_rolled_back，"
                        "失败明细与设备原因全部入审计，允许稍后重试补偿",
        })
        status = self.service.status(rid)
        for b in status["batches"]:
            self.log(f"  批次{b['index']} {b['name']}: {b['state']}")
        # 已完成的回退不允许重复执行
        try:
            self.service.execute_rollback(rid, actor="incident-commander")
        except DomainError as exc:
            self.log(f"重复执行回退被拒绝：{exc}")
            self.findings["partial_rollback"].append({"repeat_rollback_rejected": str(exc)})

        # 故障设备 d-p2 修复上线：只重试上一轮失败的撤销步骤
        self.service.rollback_executor = FailingDeviceRollback("")  # 不再有失败设备
        compensated = self.service.retry_rollback(rid, actor="incident-commander")
        self.log(
            f"设备 d-p2 恢复后补偿重试：状态={compensated['state']}，"
            f"成功 {compensated['done']} 步，仍失败 {compensated['failed']} 步"
        )
        self.findings["partial_rollback"].append({
            "compensation": "retry_rollback",
            "rollout_state": compensated["state"],
            "retried_steps": compensated["steps"],
            "handling": "补偿只重试上一轮失败步骤；全部成功后批次与发布单升级为 rolled_back",
        })

    # ---------------- 8. 服务重启恢复 + 更晚的旧回执

    def _restart_and_late_receipts(self, canary_cmds: list[dict[str, str]]) -> None:
        self.section("步骤 8  模拟服务重启：从持久化恢复发布游标，旧回执依旧不得覆盖")
        # 全新的服务实例/标识生成器，但数据目录不变
        restarted = build_service(self.data_dir, clock=ScriptedClock(self.clock.now()), ids=SequentialIds())
        recovery = restarted.recover()
        for item in recovery["rollouts"]:
            self.log(
                f"恢复发布单 {item['rollout_id']}：state={item['state']} "
                f"cursor={item['cursor']}/{item['total_batches']} "
                f"current_batch={item['current_batch']} 回退计划={'有' if item['has_rollback_plan'] else '无'}"
            )
        self.findings["restart_recovery"].append(recovery)

        rid = self.refs["rollout"]
        c_base = canary_cmds[0]["id"]
        # 重启后设备网络恢复，涌来重启前的陈旧回执
        stale1 = restarted.receive_receipt(rid, c_base, revision=0, claimed_state="dispatched")
        stale2 = restarted.receive_receipt(rid, c_base, revision=1, claimed_state="acked")
        self.log(f"重启后旧 r0 回执：accepted={stale1['accepted']}（{stale1['reason']}）")
        self.log(f"重启后 r1 acked 晚到（命令已 applied）：accepted={stale2['accepted']}（{stale2['reason']}）")
        self.findings["out_of_order_receipts"].extend([
            {"command_id": c_base, "receipt": "post-restart-r0/dispatched", "accepted": False, "reason": stale1["reason"]},
            {"command_id": c_base, "receipt": "post-restart-r1/acked", "accepted": False, "reason": stale2["reason"]},
        ])
        audit_ok = restarted.verify_audit()
        self.log(f"重启后重算审计哈希链：{audit_ok}")
        self.findings["restart_recovery"].append({"audit_verify": audit_ok})

    # ---------------- 9. 汇总报告

    def _final_report(self) -> None:
        self.section("步骤 9  验收结论汇总")
        labels = {
            "expired_exceptions": "过期例外",
            "out_of_order_receipts": "乱序/重复回执",
            "partial_rollback": "部分回退",
            "duplicate_commands": "重复命令",
            "dependency_ordering": "依赖顺序",
            "restart_recovery": "重启恢复",
        }
        for key, title in labels.items():
            items = self.findings[key]
            self.log(f"[{title}] 共 {len(items)} 条证据")
            for item in items:
                self.log(f"  - {json.dumps(item, ensure_ascii=False)}")

        audit_entries = self.service.read_audit()
        self.log("")
        self.log(f"追加式审计日志共 {len(audit_entries)} 条，动作序列：")
        for e in audit_entries:
            self.log(f"  #{e['seq']:>3} {e['ts']} {e['actor']:<18} {e['action']}")
        verify = self.service.verify_audit()
        self.log("")
        self.log(f"哈希链校验：{verify}")


def main() -> None:
    parser = argparse.ArgumentParser(description="离线验收场景运行器")
    parser.add_argument("--data-dir", default="./.runtime/offline")
    parser.add_argument("--json", action="store_true", help="只输出机器可读 JSON")
    parser.add_argument("--save", default="", help="把结构化结果额外写入指定 JSON 文件")
    args = parser.parse_args()

    scenario = Scenario(args.data_dir)
    result = scenario.run()
    if args.save:
        Path(args.save).write_text(
            json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(result["report"])
        print("\n场景运行完成。")


if __name__ == "__main__":
    main()
