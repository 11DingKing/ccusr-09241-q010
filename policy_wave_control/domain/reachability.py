"""预演：在给定时刻计算策略生效后的可达性与关键业务影响。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import (
    ACTION_ALLOW,
    ACTION_DENY,
    PolicyException,
    PolicyRule,
    PolicyVersion,
    TopologySnapshot,
)


@dataclass
class RuleEffect:
    rule_id: str
    suppressed_by: list[str] = field(default_factory=list)  # 全局生效中的例外
    scoped_out: dict[str, list[str]] = field(default_factory=dict)  # 设备级例外：设备 -> 例外
    capable_devices: list[str] = field(default_factory=list)
    unsupported_devices: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return not self.suppressed_by

    @property
    def enforceable(self) -> bool:
        return self.active and bool(self.capable_devices)


@dataclass
class FlowResult:
    src_zone: str
    dst_zone: str
    service: str
    critical: bool
    before: str
    after: str
    matched_rule_id: str | None = None
    suppressed_rule_id: str | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.before != self.after

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "service": self.service,
            "critical": self.critical,
            "before": self.before,
            "after": self.after,
            "matched_rule_id": self.matched_rule_id,
            "suppressed_rule_id": self.suppressed_rule_id,
            "reasons": list(self.reasons),
            "changed": self.changed,
        }


@dataclass
class PreflightReport:
    at: datetime
    verdict: str  # ready | blocked
    rule_effects: dict[str, RuleEffect]
    flows: list[FlowResult]
    expired_exceptions: list[str]
    active_exceptions: list[str]
    critical_impacts: list[FlowResult]
    enforcement_gaps: list[dict[str, Any]]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "verdict": self.verdict,
            "rule_effects": {
                rid: {
                    "rule_id": rid,
                    "active": e.active,
                    "suppressed_by": list(e.suppressed_by),
                    "scoped_out": dict(e.scoped_out),
                    "capable_devices": list(e.capable_devices),
                    "unsupported_devices": list(e.unsupported_devices),
                }
                for rid, e in self.rule_effects.items()
            },
            "flows": [f.to_dict() for f in self.flows],
            "expired_exceptions": list(self.expired_exceptions),
            "active_exceptions": list(self.active_exceptions),
            "critical_impacts": [f.to_dict() for f in self.critical_impacts],
            "enforcement_gaps": list(self.enforcement_gaps),
            "warnings": list(self.warnings),
        }


class ReachabilitySimulator:
    """根据快照、策略版本与例外计算“变更前/变更后”的流可达性。"""

    def preflight(
        self,
        snapshot: TopologySnapshot,
        policy: PolicyVersion,
        exceptions: list[PolicyException],
        at: datetime,
    ) -> PreflightReport:
        if policy.snapshot_id != snapshot.id:
            raise ValueError(
                f"策略版本 {policy.id} 基于快照 {policy.snapshot_id}，"
                f"与当前快照 {snapshot.id} 不一致"
            )

        active_exc = [e for e in exceptions if e.is_active(at)]
        expired_exc = [
            e.id for e in exceptions if e.state_at(at) == "expired"
        ]
        suppressed: dict[str, list[str]] = {}
        for exc in active_exc:
            suppressed.setdefault(exc.rule_id, []).append(exc.id)

        effects: dict[str, RuleEffect] = {}
        for rule in policy.rules:
            devices = snapshot.devices_of(rule.src_zone)
            global_suppressed = [
                e.id for e in active_exc
                if e.rule_id == rule.id and e.scope_device_id is None
            ]
            scoped: dict[str, list[str]] = {}
            capable: list[str] = []
            unsupported: list[str] = []
            for device in devices:
                dev_exc = [
                    e.id for e in active_exc
                    if e.rule_id == rule.id and e.scope_device_id == device.id
                ]
                if dev_exc:
                    # 设备级有期限例外：该设备在有效期内豁免，不参与落地判定
                    scoped[device.id] = dev_exc
                elif device.supports(rule.requires):
                    capable.append(device.id)
                else:
                    unsupported.append(device.id)
            effects[rule.id] = RuleEffect(
                rule_id=rule.id,
                suppressed_by=global_suppressed,
                scoped_out=scoped,
                capable_devices=capable,
                unsupported_devices=unsupported,
            )

        flows: list[FlowResult] = []
        warnings: list[str] = []

        def match(rule: PolicyRule, src: str, dst: str, service: str) -> bool:
            return (
                rule.src_zone == src
                and rule.dst_zone == dst
                and rule.service == service
            )

        # 规则级能力缺口：规则生效中，但其源区域存在无法落地的设备
        gaps: list[dict[str, Any]] = []
        for rule in policy.rules:
            eff = effects[rule.id]
            if eff.active and eff.unsupported_devices:
                related_edges = [
                    e for e in snapshot.edges
                    if e.src_zone == rule.src_zone
                    and e.dst_zone == rule.dst_zone
                    and e.service == rule.service
                ]
                gaps.append(
                    {
                        "rule_id": rule.id,
                        "src_zone": rule.src_zone,
                        "dst_zone": rule.dst_zone,
                        "service": rule.service,
                        "unsupported_devices": list(eff.unsupported_devices),
                        "critical": any(e.critical for e in related_edges),
                    }
                )

        for edge in snapshot.edges:
            dst_zone = snapshot.zone(edge.dst_zone)
            before = ACTION_DENY if dst_zone.default_policy == ACTION_DENY else ACTION_ALLOW

            allows = [r for r in policy.rules if match(r, edge.src_zone, edge.dst_zone, edge.service) and r.action == ACTION_ALLOW]
            denies = [r for r in policy.rules if match(r, edge.src_zone, edge.dst_zone, edge.service) and r.action == ACTION_DENY]

            after = before
            matched: str | None = None
            suppressed_rule: str | None = None
            reasons: list[str] = []

            # default-deny 区域：只有存在可落地的 allow 才放行
            if before == ACTION_DENY:
                ok = next((r for r in allows if effects[r.id].enforceable), None)
                if ok is not None:
                    after = ACTION_ALLOW
                    matched = ok.id
                    reasons.append(f"允许规则 {ok.id} 可在能力设备上落地")
                else:
                    reasons.append("目的区域缺省拒绝且无可用允许规则")
            else:
                # 安全优先：只要存在一条可落地的 deny 即阻断
                enforced_deny = next((r for r in denies if effects[r.id].enforceable), None)
                if enforced_deny is not None:
                    after = ACTION_DENY
                    matched = enforced_deny.id
                    reasons.append(f"拒绝规则 {enforced_deny.id} 已生效")
                else:
                    after = ACTION_ALLOW

            for r in denies + allows:
                eff = effects[r.id]
                if not eff.active and eff.suppressed_by:
                    suppressed_rule = r.id
                    reasons.append(
                        f"规则 {r.id} 被例外 {','.join(eff.suppressed_by)} 暂时抑制"
                    )
                if eff.active and not eff.capable_devices:
                    reasons.append(
                        f"规则 {r.id} 在本区域无任何支持其能力条件的设备，无法落地"
                    )

            flows.append(
                FlowResult(
                    src_zone=edge.src_zone,
                    dst_zone=edge.dst_zone,
                    service=edge.service,
                    critical=edge.critical,
                    before=before,
                    after=after,
                    matched_rule_id=matched,
                    suppressed_rule_id=suppressed_rule,
                    reasons=reasons,
                )
            )

        # 关键业务在变更后不可达（含 allow->deny 的新增阻断，以及 default-deny
        # 区域始终没有可用放行规则）均阻断发布
        critical_impacts = [
            f for f in flows if f.critical and f.after == ACTION_DENY
        ]
        # 关键链路上的规则若完全无设备可落地（allow 无法使 default-deny 区域放行），
        # 同样判定为阻断发布
        critical_no_device: list[dict[str, Any]] = []
        for edge in snapshot.edges:
            if not edge.critical:
                continue
            related = [
                r for r in policy.rules
                if match(r, edge.src_zone, edge.dst_zone, edge.service)
                and r.action == ACTION_ALLOW
                and snapshot.zone(edge.dst_zone).default_policy == ACTION_DENY
            ]
            for r in related:
                eff = effects[r.id]
                if eff.active and not eff.capable_devices:
                    critical_no_device.append(
                        {"rule_id": r.id, "edge": f"{edge.src_zone}->{edge.dst_zone}/{edge.service}"}
                    )
        critical_gaps = [g for g in gaps if g["critical"] and not effects[g["rule_id"]].capable_devices]
        for g in critical_gaps:
            warnings.append(
                f"关键链路 {g['src_zone']}->{g['dst_zone']}/{g['service']} 的规则 "
                f"{g['rule_id']} 没有任何支持其能力条件的设备，策略无法落地"
            )

        verdict = "blocked" if critical_impacts or critical_no_device or critical_gaps else "ready"
        if not snapshot.edges:
            warnings.append("快照中没有任何基线链路，可达性结论为空")

        return PreflightReport(
            at=at,
            verdict=verdict,
            rule_effects=effects,
            flows=flows,
            expired_exceptions=expired_exc,
            active_exceptions=[e.id for e in active_exc],
            critical_impacts=critical_impacts,
            enforcement_gaps=gaps,
            warnings=warnings,
        )
