"""发布编排全流程：审批闸门、回执单调性、重复命令、自动暂停与回退。"""

from datetime import timedelta  # noqa: F401  (保留供断言扩展)

from policy_wave_control.domain.models import DomainError
from policy_wave_control.domain.release import (
    BATCH_HELD,
    BATCH_PARTIALLY_ROLLED_BACK,
    ROLLOUT_PAUSED,
    ROLLOUT_PARTIALLY_ROLLED_BACK,
    ROLLOUT_ROLLED_BACK,
)
from tests.support import ScriptedFailures, ServiceTestCase


class ReleaseLifecycleTests(ServiceTestCase):
    def _create(self) -> str:
        _, policy_id = self.build_standard_world()
        rollout = self.service.create_rollout(policy_id, "发布", "rm")
        return rollout.id

    def test_requires_all_role_approvals_before_dispatch(self) -> None:
        rid = self._create()
        with self.assertRaises(DomainError):
            self.service.dispatch_batch(rid)
        self.service.approve(rid, 0, "release_manager", "rm")
        with self.assertRaises(DomainError):
            self.service.dispatch_batch(rid)
        self.service.approve(rid, 0, "security_admin", "sec")
        result = self.service.dispatch_batch(rid)
        self.assertEqual(len(result["new"]), 3)

    def test_cannot_skip_batches_or_dispatch_held(self) -> None:
        rid = self._create()
        with self.assertRaises(DomainError):
            self.service.dispatch_batch(rid, batch_index=2)
        # 手动暂停后批次挂起，不能下发
        self.service.pause(rid, "rm", "等窗口")
        with self.assertRaises(DomainError):
            self.service.dispatch_batch(rid)
        self.service.resume(rid, "rm")

    def test_duplicate_dispatch_is_idempotent(self) -> None:
        rid = self._create()
        self.service.approve(rid, 0, "release_manager", "rm")
        self.service.approve(rid, 0, "security_admin", "sec")
        first = self.service.dispatch_batch(rid)
        second = self.service.dispatch_batch(rid)
        self.assertEqual(len(first["new"]), 3)
        self.assertEqual(second["new"], [])
        self.assertEqual(len(second["duplicates"]), 3)
        rollout = self.rollouts.get(rid)
        self.assertTrue(all(c.revision == 1 for c in rollout.batches[0].commands))
        self.assertTrue(all(c.duplicate_dispatches == 1 for c in rollout.batches[0].commands))

    def test_stale_and_out_of_order_receipts_never_overwrite(self) -> None:
        rid = self._create()
        self.service.approve(rid, 0, "release_manager", "rm")
        self.service.approve(rid, 0, "security_admin", "sec")
        self.service.dispatch_batch(rid)
        cmd = self.rollouts.get(rid).batches[0].commands[0].id

        stale = self.service.receive_receipt(rid, cmd, revision=0, claimed_state="acked")
        self.assertFalse(stale["accepted"])
        future = self.service.receive_receipt(rid, cmd, revision=9, claimed_state="acked")
        self.assertFalse(future["accepted"])

        self.assertTrue(self.service.receive_receipt(rid, cmd, 1, "acked")["accepted"])
        self.assertTrue(self.service.receive_receipt(rid, cmd, 1, "applied")["accepted"])
        # 晚到的旧状态
        late = self.service.receive_receipt(rid, cmd, 1, "dispatched")
        self.assertFalse(late["accepted"])
        # 完全重复
        dup = self.service.receive_receipt(rid, cmd, 1, "applied")
        self.assertFalse(dup["accepted"])
        state = self.rollouts.get(rid).batches[0].command_by_id(cmd)
        self.assertEqual(state.state, "applied")
        self.assertEqual(len(state.receipts), 6)
        accepted = [r for r in state.receipts if r.accepted]
        rejected = [r for r in state.receipts if not r.accepted]
        self.assertEqual(
            [(r.revision, r.claimed_state) for r in accepted],
            [(1, "acked"), (1, "applied")],
        )
        self.assertEqual(len(rejected), 4)
        # 无论旧版本、超前版本还是状态回退，都不得改动命令的终态
        self.assertEqual(state.state, "applied")
        self.assertEqual(state.revision, 1)

    def test_gate_blocks_advance_until_thresholds_and_evidence(self) -> None:
        rid = self._create()
        self.service.approve(rid, 0, "release_manager", "rm")
        self.service.approve(rid, 0, "security_admin", "sec")
        self.service.dispatch_batch(rid)
        for cmd in self.rollouts.get(rid).batches[0].commands:
            self.service.receive_receipt(rid, cmd.id, 1, "applied")
        with self.assertRaises(DomainError):  # 缺证据
            self.service.advance(rid, "rm")
        self.service.adopt_evidence(rid, 0, "availability", 0.999, "probe", "sre")
        self.service.adopt_evidence(rid, 0, "error_rate", 0.001, "probe", "sre")
        result = self.service.advance(rid, "rm")
        self.assertEqual(result["completed_batch"], 0)
        self.assertEqual(result["next_cursor"], 1)

    def test_failed_command_blocks_advance(self) -> None:
        rid = self._create()
        self.service.approve(rid, 0, "release_manager", "rm")
        self.service.approve(rid, 0, "security_admin", "sec")
        self.service.dispatch_batch(rid)
        cmds = self.rollouts.get(rid).batches[0].commands
        for cmd in cmds[:-1]:
            self.service.receive_receipt(rid, cmd.id, 1, "applied")
        self.service.receive_receipt(rid, cmds[-1].id, 1, "failed")
        self.service.adopt_evidence(rid, 0, "availability", 1.0, "probe", "sre")
        self.service.adopt_evidence(rid, 0, "error_rate", 0.0, "probe", "sre")
        with self.assertRaises(DomainError):
            self.service.advance(rid, "rm")

    def test_metric_breach_auto_pauses_and_plans_rollback(self) -> None:
        rid = self._create()
        # 完成金丝雀
        self._complete_batch(rid, 0, roles=("release_manager", "security_admin"))
        # 个人区批次在途，证据越界
        self.service.approve(rid, 1, "security_admin", "sec")
        self.service.approve(rid, 1, "personal_zone_owner", "owner")
        self.service.dispatch_batch(rid)
        for cmd in self.rollouts.get(rid).batches[1].commands:
            self.service.receive_receipt(rid, cmd.id, 1, "applied")
        result = self.service.adopt_evidence(rid, 1, "error_rate", 0.5, "probe", "sre")
        self.assertIn("paused_and_rollback_planned", result["auto_actions"])
        rollout = self.rollouts.get(rid)
        self.assertEqual(rollout.state, ROLLOUT_PAUSED)
        held = [b.index for b in rollout.batches if b.state == BATCH_HELD]
        self.assertIn(2, held)
        self.assertIsNotNone(rollout.rollback_plan)
        # 暂停期间不能推进在途批次之外的任何批次
        with self.assertRaises(DomainError):
            self.service.dispatch_batch(rid)

    def test_rollback_plan_respects_reverse_dependency_order(self) -> None:
        rid = self._create()
        self._complete_batch(rid, 0)
        self._complete_batch(rid, 1, roles=("security_admin", "personal_zone_owner"))
        plan = self.service.create_rollback_plan(rid, "人工回退", "ic")
        seqs = [(s.batch_index, s.topo_seq) for s in plan.steps]
        self.assertEqual(seqs, sorted(seqs, key=lambda x: (-x[0], -x[1])))

    def test_partial_rollback_marks_state_and_continues_other_steps(self) -> None:
        rid = self._create()
        self._complete_batch(rid, 0)
        self._complete_batch(rid, 1, roles=("security_admin", "personal_zone_owner"))
        self.service.create_rollback_plan(rid, "恶化", "ic")
        self.service.rollback_executor = ScriptedFailures({"p1"})
        result = self.service.execute_rollback(rid, "ic")
        self.assertEqual(result["state"], ROLLOUT_PARTIALLY_ROLLED_BACK)
        self.assertGreaterEqual(result["failed"], 1)
        self.assertGreater(result["done"], 0)
        rollout = self.rollouts.get(rid)
        failed_devices = {s.device_id for s in rollout.rollback_plan.steps if s.status == "failed"}
        self.assertIn("p1", failed_devices)
        with self.assertRaises(DomainError):
            self.service.execute_rollback(rid, "ic")

    def test_partial_rollback_can_be_retried_after_device_recovers(self) -> None:
        rid = self._create()
        self._complete_batch(rid, 0)
        self._complete_batch(rid, 1, roles=("security_admin", "personal_zone_owner"))
        self.service.create_rollback_plan(rid, "恶化", "ic")
        self.service.rollback_executor = ScriptedFailures({"p1"})
        first = self.service.execute_rollback(rid, "ic")
        self.assertEqual(first["state"], ROLLOUT_PARTIALLY_ROLLED_BACK)

        # 设备恢复：替换端口后重试失败步骤，全部成功，状态升级为完全回退
        self.service.rollback_executor = ScriptedFailures(set())
        again = self.service.retry_rollback(rid, "ic")
        self.assertEqual(again["state"], ROLLOUT_ROLLED_BACK)
        self.assertEqual(again["failed"], 0)
        self.assertGreater(again["done"], 0)
        self.assertTrue(self.rollouts.get(rid).rollback_plan.executed)
        rollout = self.rollouts.get(rid)
        for b in rollout.batches:
            self.assertNotIn(b.state, (BATCH_PARTIALLY_ROLLED_BACK,))

        # 全部成功后再重试无事可做
        with self.assertRaises(DomainError):
            self.service.retry_rollback(rid, "ic")

    def test_full_rollback_state(self) -> None:
        rid = self._create()
        self._complete_batch(rid, 0)
        self.service.create_rollback_plan(rid, "撤回", "ic")
        result = self.service.execute_rollback(rid, "ic")
        self.assertEqual(result["state"], ROLLOUT_ROLLED_BACK)
        self.assertEqual(result["failed"], 0)

    def test_completing_all_batches(self) -> None:
        rid = self._create()
        self._complete_batch(rid, 0)
        self._complete_batch(rid, 1, roles=("security_admin", "personal_zone_owner"))
        self._complete_batch(rid, 2, roles=("security_admin", "machine_zone_owner"))
        result = self._complete_batch(rid, 3, roles=("security_admin", "iot_zone_owner"))
        self.assertEqual(result["rollout_state"], "completed")
        self.assertIsNone(self.rollouts.get(rid).current_batch)

    def _complete_batch(self, rid: str, index: int, roles: tuple[str, ...] = (
        "release_manager", "security_admin"
    )) -> dict:
        for role in roles:
            self.service.approve(rid, index, role, role)
        self.service.dispatch_batch(rid)
        for cmd in self.rollouts.get(rid).batches[index].commands:
            self.service.receive_receipt(rid, cmd.id, 1, "applied")
        self.service.adopt_evidence(rid, index, "availability", 1.0, "probe", "sre")
        self.service.adopt_evidence(rid, index, "error_rate", 0.0, "probe", "sre")
        return self.service.advance(rid, "rm")
