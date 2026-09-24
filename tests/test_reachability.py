"""可达性预演：缺省策略、能力缺口、例外抑制、关键业务阻断。"""

from datetime import timedelta

from policy_wave_control.domain.models import (
    PolicyException,
)
from tests.support import T0, ServiceTestCase


class PreflightTests(ServiceTestCase):
    def test_deny_rule_and_capability_gap_reported(self) -> None:
        _, policy_id = self.build_standard_world()
        report = self.service.preflight(policy_id, at=T0)
        # rb 在个人区：p1 可落地，p2 能力不足（缺口），http 被阻断
        flows = {(f.src_zone, f.dst_zone, f.service): f for f in report.flows}
        self.assertEqual(flows[("zp", "zi", "http")].after, "deny")
        # 机器区缺省拒绝：rt(allow telemetry) 让遥测从 deny -> allow，关键业务不断
        tel = flows[("zi", "zm", "telemetry")]
        self.assertEqual(tel.before, "deny")
        self.assertEqual(tel.after, "allow")
        gap_rules = {g["rule_id"] for g in report.enforcement_gaps}
        self.assertIn("rb", gap_rules)
        self.assertEqual(report.verdict, "ready")

    def test_active_exception_suppresses_rule_and_appears_in_report(self) -> None:
        _, policy_id = self.build_standard_world()
        self.service.add_exception(
            rule_id="rb", reason="临时窗口", created_by="ops",
            valid_from=T0, valid_until=T0 + timedelta(hours=1),
        )
        report = self.service.preflight(policy_id, at=T0)
        self.assertEqual(report.active_exceptions, ["exc-001"])
        flows = {(f.src_zone, f.dst_zone, f.service): f for f in report.flows}
        self.assertEqual(flows[("zp", "zi", "http")].after, "allow")

    def test_expired_exception_does_not_suppress(self) -> None:
        _, policy_id = self.build_standard_world()
        exc = PolicyException(
            id="ex", rule_id="rb", reason="old", created_by="ops",
            valid_from=T0 - timedelta(days=2), valid_until=T0 - timedelta(days=1),
        )
        self.service.exceptions.save(exc)
        report = self.service.preflight(policy_id, at=T0)
        self.assertIn("ex", report.expired_exceptions)
        flows = {(f.src_zone, f.dst_zone, f.service): f for f in report.flows}
        self.assertEqual(flows[("zp", "zi", "http")].after, "deny")

    def test_critical_impact_blocks_verdict(self) -> None:
        # 只保留关键遥测链路，且没有 allow 规则：机器区 default-deny 阻断关键业务
        snapshot = self.service.add_snapshot(
            name="关键阻断",
            zones=[
                {"id": "zi", "name": "物联区", "kind": "iot"},
                {"id": "zm", "name": "机器区", "kind": "machine", "default_policy": "deny"},
            ],
            devices=[
                {"id": "i1", "zone_id": "zi", "name": "i1", "capabilities": ["acl-v2"]},
            ],
            edges=[{"src_zone": "zi", "dst_zone": "zm", "service": "telemetry", "critical": True}],
        )
        policy = self.service.add_policy(
            name="无放行", snapshot_id=snapshot.id, rules=[],
        )
        report = self.service.preflight(policy.id, at=T0)
        self.assertEqual(report.verdict, "blocked")
        self.assertEqual(len(report.critical_impacts), 1)

    def test_scoped_exemption_skips_single_device(self) -> None:
        _, policy_id = self.build_standard_world()
        from datetime import timedelta as td

        # 仅对旧设备 p3 意义不大；这里对 p1 做设备级豁免，预演显示该规则在 p1 被作用域豁免
        exc = PolicyException(
            id="exc-scope", rule_id="rb", reason="p1 改造窗口", created_by="ops",
            valid_from=T0, valid_until=T0 + td(hours=1), scope_device_id="p1",
        )
        self.service.exceptions.save(exc)
        report = self.service.preflight(policy_id, at=T0)
        eff = report.rule_effects["rb"]
        self.assertTrue(eff.active)
        self.assertIn("p1", eff.scoped_out)
        self.assertEqual(eff.scoped_out["p1"], ["exc-scope"])
        self.assertNotIn("p1", eff.capable_devices)
        # p2 仍然可落地
        self.assertIn("p2", eff.capable_devices)

        rollout = self.service.create_rollout(policy_id, "发布", "rm")
        canary = rollout.batches[0]
        # 个人区金丝雀本应选 p1，但 p1 被作用域豁免，改由 p2 承担
        self.assertNotIn("p1", [c.device_id for c in canary.commands if c.rule_id == "rb"])

    def test_policy_snapshot_mismatch_rejected(self) -> None:
        from policy_wave_control.domain.reachability import ReachabilitySimulator
        snap = self.snapshots.get(self.build_standard_world()[0])
        other = self.service.add_snapshot(
            name="另一个",
            zones=[{"id": "zp", "name": "p", "kind": "personal"}],
            devices=[], edges=[],
        )
        policy = self.policies.all()[0]
        object.__setattr__(policy, "snapshot_id", other.id)
        with self.assertRaises(ValueError):
            ReachabilitySimulator().preflight(snap, policy, [], T0)
