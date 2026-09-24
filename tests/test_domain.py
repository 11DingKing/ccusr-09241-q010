"""领域模型单元测试：依赖排序、回执仲裁、例外时效、门禁评估、回退顺序。"""

from __future__ import annotations

import unittest

from policy_wave_control.domain.enums import (
    BatchStatus,
    CommandStatus,
    ExceptionStatus,
    ReceiptStatus,
    ReleaseStatus,
    RollbackPlanStatus,
)
from policy_wave_control.domain.errors import (
    AuthorizationError,
    ConflictError,
    DependencyCycleError,
    ValidationError,
)
from policy_wave_control.domain.exceptions import PolicyException
from policy_wave_control.domain.policy import PolicyRule, PolicyVersion
from policy_wave_control.domain.release import (
    Batch,
    DeviceCommand,
    HealthEvidence,
    Release,
    Thresholds,
)


def make_cmd(cid: str, status: str = CommandStatus.PLANNED.value,
             seq: int = 0, rule_order: int = 0, batch_index: int = 0) -> DeviceCommand:
    return DeviceCommand(
        command_id=cid, batch_index=batch_index, device_id=f"dev-{cid}",
        zone_id="z1", rule_id=f"r{rule_order}", rule_order=rule_order,
        status=status, last_receipt_seq=seq,
    )


class ReceiptArbitrationTests(unittest.TestCase):
    def test_stale_receipt_never_overwrites_newer_state(self) -> None:
        cmd = make_cmd("c1")
        self.assertTrue(cmd.mark_sent("2026-09-24T00:01:00+00:00"))
        self.assertEqual(cmd.apply_receipt(ReceiptStatus.APPLIED.value, 2, "t1"),
                         "applied")
        self.assertEqual(cmd.status, CommandStatus.APPLIED.value)
        # 旧的 reject 晚到
        verdict = cmd.apply_receipt(ReceiptStatus.REJECTED.value, 1, "t2")
        self.assertEqual(verdict, "stale")
        self.assertEqual(cmd.status, CommandStatus.APPLIED.value)
        self.assertEqual(cmd.last_receipt_seq, 2)
        # 同序号重复也不采纳
        self.assertEqual(
            cmd.apply_receipt(ReceiptStatus.TIMEOUT.value, 2, "t3"), "stale")
        self.assertEqual(cmd.status, CommandStatus.APPLIED.value)

    def test_newer_receipt_can_move_state(self) -> None:
        cmd = make_cmd("c2")
        cmd.mark_sent("t")
        cmd.apply_receipt(ReceiptStatus.APPLIED.value, 1, "t")
        self.assertEqual(
            cmd.apply_receipt(ReceiptStatus.REJECTED.value, 3, "t"), "applied")
        self.assertEqual(cmd.status, CommandStatus.REJECTED.value)

    def test_duplicate_dispatch_is_idempotent(self) -> None:
        cmd = make_cmd("c3")
        self.assertTrue(cmd.mark_sent("t"))
        self.assertFalse(cmd.mark_sent("t"))
        self.assertEqual(cmd.dispatch_count, 2)
        self.assertEqual(cmd.status, CommandStatus.SENT.value)


class PolicyOrderTests(unittest.TestCase):
    def _policy(self, deps: dict) -> PolicyVersion:
        rules = tuple(
            PolicyRule(rule_id=rid, action="deny", src_zone="z1", dst_zone="z2",
                       protocol="tcp", port=80, required_capability="acl_v2")
            for rid in ("a", "b", "c")
        )
        return PolicyVersion(
            policy_id="p1", version=1, created_at="2026-09-24T00:00:00+00:00",
            rules=rules, depends_on={k: tuple(v) for k, v in deps.items()},
        )

    def test_topological_order(self) -> None:
        order = self._policy({"b": ["a"], "c": ["b"]}).topological_order()
        self.assertEqual(order, ["a", "b", "c"])

    def test_dependency_cycle_is_rejected(self) -> None:
        with self.assertRaises(DependencyCycleError) as ctx:
            self._policy({"a": ["b"], "b": ["a"]}).topological_order()
        self.assertIn("a", ctx.exception.details["cycle"])

    def test_invalid_rule_action(self) -> None:
        with self.assertRaises(ValidationError):
            PolicyRule(rule_id="x", action="inspect", src_zone="z", dst_zone="z",
                       protocol="tcp", port=1, required_capability="c")


class ExceptionLifecycleTests(unittest.TestCase):
    def _exc(self, expires: str) -> PolicyException:
        return PolicyException(
            exception_id="e1", rule_id="r1", zone_id="z1", reason="t",
            created_at="2026-09-20T00:00:00+00:00", expires_at=expires,
            created_by="owner",
        )

    def test_expiry_is_time_relative(self) -> None:
        exc = self._exc("2026-09-25T00:00:00+00:00")
        self.assertTrue(exc.is_active("2026-09-24T00:00:00+00:00"))
        self.assertFalse(exc.is_active("2026-09-26T00:00:00+00:00"))
        self.assertEqual(exc.effective_state("2026-09-26T00:00:00+00:00"),
                         ExceptionStatus.EXPIRED.value)
        # 过期是延迟计算，落库状态保持 active，不依赖后台任务
        self.assertEqual(exc.status, ExceptionStatus.ACTIVE.value)

    def test_renew_rules(self) -> None:
        exc = self._exc("2026-09-25T00:00:00+00:00")
        exc.renew("2026-10-01T00:00:00+00:00", "2026-09-24T00:00:00+00:00", "officer")
        self.assertEqual(exc.renewed_count, 1)
        with self.assertRaises(ValidationError):
            exc.renew("2026-09-26T00:00:00+00:00", "2026-09-24T00:00:00+00:00", "o")
        with self.assertRaises(ConflictError):
            exc.renew("2026-11-01T00:00:00+00:00",
                      "2026-10-02T00:00:00+00:00", "o")  # 已过期

    def test_revoked_exception_cannot_renew(self) -> None:
        exc = self._exc("2026-10-25T00:00:00+00:00")
        exc.revoke("2026-09-24T00:00:00+00:00", "officer")
        with self.assertRaises(ConflictError):
            exc.renew("2026-11-01T00:00:00+00:00",
                      "2026-09-24T00:00:00+00:00", "o")


class HealthGateTests(unittest.TestCase):
    def _batch(self, dispatched_at: str) -> Batch:
        return Batch(
            batch_id="b1", index=0, kind="canary", zone_id=None,
            required_role="security_officer", rule_ids=["r1"],
            commands=[make_cmd("c1", CommandStatus.APPLIED.value, 1)],
            dispatched_at=dispatched_at,
        )

    def test_window_not_full_does_not_pass(self) -> None:
        b = self._batch("2026-09-24T00:00:00+00:00")
        ev = HealthEvidence("ev1", "probe", 1, "t", "t", 0.99, {"s1": True})
        b.adopt_evidence(ev)
        gate = b.evaluate_health("2026-09-24T00:01:00+00:00", 300, 0.95, 0.80)
        self.assertFalse(gate.passed)
        self.assertIn("窗口未满", gate.reason)

    def test_threshold_pass_after_window(self) -> None:
        b = self._batch("2026-09-24T00:00:00+00:00")
        b.adopt_evidence(HealthEvidence("ev1", "probe", 1, "t", "t", 0.96,
                                        {"s1": True}))
        gate = b.evaluate_health("2026-09-24T00:06:00+00:00", 300, 0.95, 0.80)
        self.assertTrue(gate.passed)

    def test_critical_blocked_is_instant_degradation(self) -> None:
        b = self._batch("2026-09-24T00:00:00+00:00")
        b.adopt_evidence(HealthEvidence("ev1", "probe", 1, "t", "t", 0.99,
                                        {"s1": False}))
        gate = b.evaluate_health("2026-09-24T00:00:01+00:00", 300, 0.95, 0.80)
        self.assertFalse(gate.passed)
        self.assertEqual(gate.critical_blocked, ["s1"])

    def test_stale_evidence_rejected_by_source_seq(self) -> None:
        b = self._batch("2026-09-24T00:00:00+00:00")
        self.assertEqual(b.adopt_evidence(
            HealthEvidence("e1", "p", 5, "t", "t", 0.99, {})), "adopted")
        self.assertEqual(b.adopt_evidence(
            HealthEvidence("e2", "p", 4, "t", "t", 0.10, {})), "stale")
        self.assertEqual(len(b.latest_evidence()), 1)

    def test_confirm_requires_matching_role_and_state(self) -> None:
        b = self._batch("2026-09-24T00:00:00+00:00")
        with self.assertRaises(ConflictError):
            b.confirm("security_officer", "a", "t")  # 未在等待审批
        b.status = BatchStatus.AWAITING_APPROVAL.value
        with self.assertRaises(AuthorizationError):
            b.confirm("network_operator", "a", "t")  # 角色不符
        b.confirm("security_officer", "wang", "t")
        self.assertEqual(b.status, BatchStatus.CONFIRMED.value)


class RollbackOrderTests(unittest.TestCase):
    def test_steps_follow_reverse_dependency_and_skip_non_applied(self) -> None:
        release = Release(
            release_id="rel1", snapshot_id="s1", policy_id="p1",
            thresholds=Thresholds(), created_at="t",
            status=ReleaseStatus.PAUSED.value,
        )
        b0 = Batch("b0", 0, "canary", None, "security_officer", ["r1"],
                   commands=[make_cmd("c-a", CommandStatus.APPLIED.value, 1,
                                      rule_order=0, batch_index=0)])
        b1 = Batch("b1", 1, "zone", "z1", "network_operator", ["r1"],
                   commands=[
                       make_cmd("c-b", CommandStatus.APPLIED.value, 1,
                                rule_order=1, batch_index=1),
                       make_cmd("c-c", CommandStatus.REJECTED.value, 1,
                                rule_order=0, batch_index=1),
                   ])
        release.batches = [b0, b1]
        steps = release.build_rollback_steps()
        # 后下发批次先回退；批内 rule_order 逆序；未生效者 skipped
        self.assertEqual([s.command_id for s in steps], ["c-b", "c-c", "c-a"])
        self.assertEqual([s.status for s in steps],
                         [RollbackPlanStatus.PLANNED.value,
                          RollbackPlanStatus.SKIPPED.value,
                          RollbackPlanStatus.PLANNED.value])

    def test_freeze_pending_only_touches_unstarted_batches(self) -> None:
        release = Release(
            release_id="rel", snapshot_id="s", policy_id="p",
            thresholds=Thresholds(), created_at="t",
        )
        b0 = Batch("b0", 0, "canary", None, "security_officer", [],
                   status=BatchStatus.HEALTH_WATCH.value)
        b1 = Batch("b1", 1, "zone", "z", "network_operator", [])
        release.batches = [b0, b1]
        frozen = release.freeze_pending("t")
        self.assertEqual(frozen, ["b1"])
        self.assertEqual(b0.status, BatchStatus.HEALTH_WATCH.value)
        self.assertEqual(b1.status, BatchStatus.PAUSED.value)


if __name__ == "__main__":
    unittest.main()
