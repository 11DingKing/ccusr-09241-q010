"""应用服务集成测试：用内存装配走完整状态机，另测落盘重启恢复与篡改检测。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from policy_wave_control.adapters.runtime import FixedClock
from policy_wave_control.application.service import ReleaseService
from policy_wave_control.bootstrap import build_service
from policy_wave_control.domain.errors import ConflictError
from policy_wave_control.domain.enums import BatchStatus, ReleaseStatus


def topology() -> dict:
    return {
        "snapshot_id": "topo-1", "version": 1,
        "taken_at": "2026-09-24T00:00:00+00:00",
        "zones": [
            {"zone_id": "zp", "name": "个人区", "kind": "personal", "cidr": "10.10.0.0/16"},
            {"zone_id": "zm", "name": "机器区", "kind": "machine", "cidr": "10.20.0.0/16"},
            {"zone_id": "zi", "name": "物联区", "kind": "iot", "cidr": "10.30.0.0/16"},
        ],
        "devices": [
            *[{"device_id": f"p{i}", "zone_id": "zp",
               "capabilities": ["acl_v2"], "firmware": "3"} for i in range(1, 5)],
            *[{"device_id": f"m{i}", "zone_id": "zm",
               "capabilities": ["acl_v2"], "firmware": "4"} for i in range(1, 5)],
            *[{"device_id": f"iot{i}", "zone_id": "zi",
               "capabilities": ["acl_v2"], "firmware": "2"} for i in range(1, 5)],
        ],
        "services": [
            {"service_id": "svc1", "name": "关键计费",
             "src_zone": "zm", "dst_zone": "zm", "protocol": "tcp", "port": 443,
             "owner": "计费组"},
        ],
    }


def policy() -> dict:
    return {
        "policy_id": "pol-1", "version": 1,
        "created_at": "2026-09-24T00:00:00+00:00",
        "rules": [
            {"rule_id": "r1", "action": "deny", "src_zone": "zp", "dst_zone": "zi",
             "protocol": "tcp", "port": 502, "required_capability": "acl_v2"},
            {"rule_id": "r2", "action": "deny", "src_zone": "zm", "dst_zone": "zi",
             "protocol": "tcp", "port": 1883, "required_capability": "acl_v2"},
        ],
        "depends_on": {"r2": ["r1"]},
    }


class _Scenario:
    def __init__(self) -> None:
        self.clock = FixedClock("2026-09-24T00:00:00+00:00")
        self.svc = build_service(None, clock=self.clock, in_memory=True)
        self.svc.register_snapshot(topology(), actor="ops")
        self.svc.register_policy(policy(), actor="arch")

    def plan(self, thresholds=None):
        return self.svc.plan_release(thresholds=thresholds, actor="planner")

    def release(self):
        rid = self.svc.releases.list_all()[0].release_id
        return rid


class PlanningTests(unittest.TestCase):
    def test_capability_blocker_rejects_plan(self) -> None:
        sc = _Scenario()
        sc.svc.register_policy({
            "policy_id": "pol-cap", "version": 1,
            "rules": [{"rule_id": "rx", "action": "isolate", "src_zone": "zi",
                       "dst_zone": "zm", "protocol": "tcp", "port": 1,
                       "required_capability": "micro_seg"}]},
            actor="arch")
        with self.assertRaises(ConflictError) as ctx:
            sc.svc.plan_release(policy_id="pol-cap", actor="planner")
        self.assertEqual(len(ctx.exception.details["preflight"]["capability_blockers"]), 4)
        self.assertEqual(sc.svc.releases.list_all(), [])

    def test_expired_exception_does_not_exempt(self) -> None:
        sc = _Scenario()
        sc.svc.create_exception(
            {"rule_id": "r1", "zone_id": "zp",
             "expires_at": "2026-09-25T00:00:00+00:00", "reason": "old"},
            actor="owner")
        sc.clock.set("2026-09-26T00:00:00+00:00")
        plan = sc.plan()
        self.assertEqual(len(plan["preflight"]["expired_exceptions"]), 1)
        self.assertEqual(plan["preflight"]["exempted_commands"], [])

    def test_batch_order_is_canary_then_machine_personal_iot(self) -> None:
        plan = _Scenario().plan()
        kinds = [(b["kind"], b["zone_id"]) for b in plan["preflight"]["batch_plan"]]
        self.assertEqual(kinds[0], ("canary", None))
        zones = [z for _, z in kinds[1:]]
        self.assertEqual(zones, ["zm", "zp"])


class LifecycleTests(unittest.TestCase):
    def test_confirmation_advances_cursor_and_completes(self) -> None:
        sc = _Scenario()
        plan = sc.plan()
        rid = plan["release"]["release_id"]
        for idx, batch in enumerate(plan["release"]["batches"]):
            sc.svc.dispatch_current(actor="ops")
            for cmd in batch["commands"]:
                sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
            sc.clock.advance(301)
            sc.svc.submit_evidence(
                batch["batch_id"], source="probe", seq=1, health_score=0.99,
                critical_reachable={"svc1": True}, actor="obs")
            role = batch["required_role"]
            result = sc.svc.confirm_batch(batch["batch_id"], role=role, actor=role)
        self.assertEqual(result["release_status"], ReleaseStatus.COMPLETED.value)
        view = sc.svc.release_view(rid)
        self.assertEqual(view["resume_hint"]["action"], "none")

    def test_cannot_confirm_batch_out_of_cursor_order(self) -> None:
        sc = _Scenario()
        plan = sc.plan()
        sc.svc.dispatch_current(actor="ops")
        canary = plan["release"]["batches"][0]
        for cmd in canary["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.clock.advance(301)
        sc.svc.submit_evidence(
            canary["batch_id"], source="p", seq=1, health_score=0.99,
            critical_reachable={"svc1": True})
        # 后续批次尚不可确认
        later = plan["release"]["batches"][1]
        with self.assertRaises(ConflictError):
            sc.svc.confirm_batch(later["batch_id"], role="network_operator",
                                 actor="ops")

    def test_deploy_gate_failure_triggers_rollback_plan(self) -> None:
        sc = _Scenario()
        plan = sc.plan(thresholds={"canary_ratio": 1.0})  # 金丝雀即全部设备
        sc.svc.dispatch_current(actor="ops")
        canary = plan["release"]["batches"][0]
        cmds = canary["commands"]
        # 多数 reject 且全部回执收敛 -> 部署门禁失败
        for cmd in cmds[:-1]:
            sc.svc.receive_receipt(cmd["command_id"], "rejected", seq=1)
        result = sc.svc.receive_receipt(cmds[-1]["command_id"], "timeout", seq=1)
        self.assertTrue(any(e.startswith("degraded") for e in result["auto_events"]))
        rid = plan["release"]["release_id"]
        view = sc.svc.release_view(rid)["release"]
        self.assertEqual(view["status"], ReleaseStatus.PAUSED.value)
        self.assertIsNotNone(view["rollback_plan"])
        # 无任何生效命令：所有步骤 skipped
        self.assertTrue(
            all(s["status"] == "skipped" for s in view["rollback_plan"]["steps"]))

    def test_health_degradation_freezes_future_and_partial_rollback(self) -> None:
        sc = _Scenario()
        plan = sc.plan()
        # 金丝雀全过并确认
        canary = plan["release"]["batches"][0]
        sc.svc.dispatch_current(actor="ops")
        for cmd in canary["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.clock.advance(301)
        sc.svc.submit_evidence(
            canary["batch_id"], source="p", seq=1, health_score=0.99,
            critical_reachable={"svc1": True})
        sc.svc.confirm_batch(canary["batch_id"], role="security_officer", actor="w")

        # 机器批次生效后健康恶化（关键业务阻断，立即触发）
        sc.svc.dispatch_current(actor="ops")
        mb = sc.svc.release_view(plan["release"]["release_id"])["release"]["batches"][1]
        for cmd in mb["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.clock.advance(10)
        bad = sc.svc.submit_evidence(
            mb["batch_id"], source="p", seq=1, health_score=0.5,
            critical_reachable={"svc1": False})
        self.assertTrue(any(e.startswith("degraded") for e in bad["auto_events"]))

        view = sc.svc.release_view(plan["release"]["release_id"])["release"]
        self.assertEqual(view["batches"][2]["status"], BatchStatus.PAUSED.value)
        # 回退：首个步骤失败 -> 部分回退；其余成功
        started = sc.svc.start_rollback(actor="w")
        steps = [s for s in started["plan"]["steps"] if s["status"] != "skipped"]
        sc.svc.receive_rollback_receipt(steps[0]["command_id"], "rejected", seq=1)
        for s in steps[1:]:
            sc.svc.receive_rollback_receipt(s["command_id"], "applied", seq=1)
        view = sc.svc.release_view(plan["release"]["release_id"])["release"]
        self.assertEqual(view["status"], ReleaseStatus.PARTIALLY_ROLLED_BACK.value)
        # 恢复暂停被禁止（已有回退计划）
        with self.assertRaises(ConflictError):
            sc.svc.resume_release(actor="w")

    def test_window_end_without_passing_health_degrades(self) -> None:
        sc = _Scenario()
        plan = sc.plan()
        canary = plan["release"]["batches"][0]
        sc.svc.dispatch_current(actor="ops")
        for cmd in canary["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.clock.advance(301)
        result = sc.svc.submit_evidence(
            canary["batch_id"], source="p", seq=1, health_score=0.85,
            critical_reachable={"svc1": True})  # 高于恶化底线 0.80，低于阈值 0.95
        self.assertTrue(any(e.startswith("degraded") for e in result["auto_events"]))

    def test_forward_receipt_ignored_after_rollback_started(self) -> None:
        sc = _Scenario()
        plan = sc.plan()
        canary = plan["release"]["batches"][0]
        sc.svc.dispatch_current(actor="ops")
        for cmd in canary["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.clock.advance(301)
        sc.svc.submit_evidence(
            canary["batch_id"], source="p", seq=1, health_score=0.99,
            critical_reachable={"svc1": True})
        sc.svc.confirm_batch(canary["batch_id"], role="security_officer", actor="w")
        sc.svc.dispatch_current(actor="ops")
        mb = sc.svc.release_view(plan["release"]["release_id"])["release"]["batches"][1]
        for cmd in mb["commands"]:
            sc.svc.receive_receipt(cmd["command_id"], "applied", seq=1)
        sc.svc.submit_evidence(
            mb["batch_id"], source="p", seq=1, health_score=0.5,
            critical_reachable={"svc1": False})
        # 恶化已触发：迟到的正向回执不得再改变命令状态
        target = mb["commands"][0]
        result = sc.svc.receive_receipt(target["command_id"], "rejected", seq=2)
        self.assertEqual(result["verdict"], "ignored_rollback_started")
        self.assertEqual(result["state"], "applied")

    def test_manual_pause_and_resume(self) -> None:
        sc = _Scenario()
        sc.plan()
        sc.svc.dispatch_current(actor="ops")
        paused = sc.svc.pause_release(actor="boss", reason="变更窗口临时关闭")
        self.assertTrue(paused["frozen_batches"])
        resumed = sc.svc.resume_release(actor="boss")
        self.assertEqual(resumed["status"], ReleaseStatus.ACTIVE.value)


class PersistenceTests(unittest.TestCase):
    def test_restart_restores_cursor_and_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            clock = FixedClock("2026-09-24T00:00:00+00:00")
            svc = build_service(data_dir, clock=clock)
            svc.register_snapshot(topology(), actor="ops")
            svc.register_policy(policy(), actor="arch")
            plan = svc.plan_release(actor="planner")
            rid = plan["release"]["release_id"]
            svc.dispatch_current(actor="ops")

            svc2 = build_service(data_dir, clock=clock)
            view = svc2.release_view(rid)
            self.assertEqual(view["resume_hint"]["cursor"], 0)
            self.assertEqual(view["resume_hint"]["status"], "active")
            self.assertTrue(svc2.verify_audit()["ok"])

    def test_tampered_audit_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            clock = FixedClock("2026-09-24T00:00:00+00:00")
            svc = build_service(data_dir, clock=clock)
            svc.register_snapshot(topology(), actor="ops")
            log_path = os.path.join(data_dir, "audit.log.jsonl")
            with open(log_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
            obj = json.loads(lines[0])
            obj["actor"] = "intruder"
            lines[0] = json.dumps(obj, ensure_ascii=False) + "\n"
            with open(log_path, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
            svc2 = build_service(data_dir, clock=clock)
            verdict = svc2.verify_audit()
            self.assertFalse(verdict["ok"])
            self.assertEqual(verdict["broken_at_seq"], 1)


if __name__ == "__main__":
    unittest.main()
