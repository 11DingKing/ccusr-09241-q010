"""批次规划：规则依赖拓扑序、金丝雀批次与后续波次生成。"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..domain.models import DomainError, PolicyRule, PolicyVersion, TopologySnapshot
from ..domain.reachability import PreflightReport
from ..domain.release import (
    Batch,
    Command,
    Gate,
)
from .ports import IdGenerator

# 后续波次在区域类型上的默认推进顺序：个人 -> 机器 -> 物联
DEFAULT_ZONE_ORDER = ("personal", "machine", "iot")

DEFAULT_GATE_METRICS: dict[str, dict[str, float]] = {
    "availability": {"min": 0.99},
    "error_rate": {"max": 0.01},
}


def topological_order(rules: list[PolicyRule]) -> dict[str, int]:
    """按 depends_on 计算拓扑序；被依赖者序号更小，先下发、后回退。"""
    by_id = {r.id: r for r in rules}
    for r in rules:
        for dep in r.depends_on:
            if dep not in by_id:
                raise DomainError(f"规则 {r.id} 依赖了不存在的规则 {dep}")
            if dep == r.id:
                raise DomainError(f"规则 {r.id} 不能依赖自身")

    visited: dict[str, int] = {}  # 0=访问中 1=完成
    order: list[str] = []

    def visit(rule_id: str, stack: list[str]) -> None:
        state = visited.get(rule_id)
        if state == 1:
            return
        if state == 0:
            cycle = " -> ".join(stack + [rule_id])
            raise DomainError(f"规则依赖存在环: {cycle}")
        visited[rule_id] = 0
        for dep in by_id[rule_id].depends_on:
            visit(dep, stack + [rule_id])
        visited[rule_id] = 1
        order.append(rule_id)

    for r in sorted(rules, key=lambda x: x.id):
        visit(r.id, [])

    return {rid: i for i, rid in enumerate(order)}


@dataclass
class BatchPlanResult:
    batches: list[Batch]
    deferred_rules: list[dict[str, str]] = field(default_factory=list)
    uncovered: list[dict[str, object]] = field(default_factory=list)


def build_batches(
    snapshot: TopologySnapshot,
    policy: PolicyVersion,
    report: PreflightReport,
    ids: IdGenerator,
    gate_metrics: dict[str, dict[str, float]] | None = None,
    min_applied_ratio: float = 1.0,
) -> BatchPlanResult:
    """根据预演结论生成金丝雀批次与后续波次。

    被生效中例外抑制的规则推迟（不进入本次发布）；能力不满足的设备
    不生成命令（其缺口已在预演中报告）。
    """
    metrics = gate_metrics if gate_metrics is not None else dict(DEFAULT_GATE_METRICS)
    topo = topological_order(policy.rules)
    rule_by_id = {r.id: r for r in policy.rules}

    deferred: list[dict[str, str]] = []
    scoped_exemptions: dict[str, set[str]] = {
        rid: set(eff.scoped_out.keys()) for rid, eff in report.rule_effects.items()
    }
    active_rules: list[PolicyRule] = []
    for r in policy.rules:
        effect = report.rule_effects[r.id]
        if not effect.active:
            deferred.append(
                {"rule_id": r.id, "reason": f"被生效中例外 {','.join(effect.suppressed_by)} 抑制，推迟发布"}
            )
            continue
        active_rules.append(r)

    # 每个区域选出金丝雀设备：优先非关键业务设备，按 id 稳定取第一个；
    # 设备至少要支持该区域一条生效规则、且未被设备级例外豁免，才有资格。
    canary_device: dict[str, str] = {}
    uncovered: list[dict[str, object]] = []
    for zone in sorted(snapshot.zones, key=lambda z: z.id):
        devices = snapshot.devices_of(zone.id)
        zone_rules = [r for r in active_rules if r.src_zone == zone.id]

        def can_serve(device_id: str) -> bool:
            device = snapshot.device(device_id)
            return any(
                device.supports(r.requires) and device_id not in scoped_exemptions.get(r.id, set())
                for r in zone_rules
            )

        eligible = sorted(
            [d for d in devices if can_serve(d.id)], key=lambda d: (d.critical, d.id)
        )
        if eligible:
            canary_device[zone.id] = eligible[0].id

    def make_commands(rule: PolicyRule, device_ids: list[str]) -> list[Command]:
        result: list[Command] = []
        exempt = scoped_exemptions.get(rule.id, set())
        for dev_id in device_ids:
            if dev_id in exempt:
                # 设备级有期限例外：该设备在有效期内不下发此规则
                continue
            device = snapshot.device(dev_id)
            if not device.supports(rule.requires):
                uncovered.append(
                    {"rule_id": rule.id, "device_id": dev_id, "missing": sorted(
                        set(rule.requires) - set(device.capabilities))}
                )
                continue
            result.append(
                Command(
                    id=ids.new("cmd"),
                    batch_index=-1,  # 批次生成后回填
                    rule_id=rule.id,
                    device_id=dev_id,
                    topo_seq=topo[rule.id],
                )
            )
        return result

    batches: list[Batch] = []

    def new_gate() -> Gate:
        return Gate(min_applied_ratio=min_applied_ratio, metrics={k: dict(v) for k, v in metrics.items()})

    # ---- 批次 0：金丝雀（每区域一台设备，命令按依赖拓扑序排列）
    canary_commands: list[Command] = []
    for rule in sorted(active_rules, key=lambda r: topo[r.id]):
        dev_id = canary_device.get(rule.src_zone)
        if dev_id is not None:
            canary_commands.extend(make_commands(rule, [dev_id]))
    canary_commands.sort(key=lambda c: (c.topo_seq, c.device_id))
    canary_zones = sorted({rule_by_id[c.rule_id].src_zone for c in canary_commands})
    batches.append(
        Batch(
            index=0,
            name="canary",
            is_canary=True,
            zone_ids=canary_zones,
            commands=canary_commands,
            gate=new_gate(),
            required_roles=["release_manager", "security_admin"],
        )
    )

    # ---- 后续波次：按区域类型顺序，每区域一批剩余设备
    zone_kind_order = {kind: i for i, kind in enumerate(DEFAULT_ZONE_ORDER)}
    ordered_zones = sorted(
        snapshot.zones,
        key=lambda z: (zone_kind_order.get(z.kind, len(zone_kind_order)), z.id),
    )
    index = 1
    for zone in ordered_zones:
        canary_id = canary_device.get(zone.id)
        remainder = [
            d.id
            for d in sorted(snapshot.devices_of(zone.id), key=lambda d: d.id)
            if d.id != canary_id
        ]
        zone_rules = [r for r in active_rules if r.src_zone == zone.id]
        if not zone_rules:
            continue
        commands: list[Command] = []
        for rule in sorted(zone_rules, key=lambda r: topo[r.id]):
            commands.extend(make_commands(rule, remainder))
        if not commands:
            continue
        commands.sort(key=lambda c: (c.topo_seq, c.device_id))
        kind = zone.kind
        batches.append(
            Batch(
                index=index,
                name=f"wave-{kind}-{zone.id}",
                is_canary=False,
                zone_ids=[zone.id],
                commands=commands,
                gate=new_gate(),
                required_roles=["security_admin", f"{kind}_zone_owner"],
            )
        )
        index += 1

    for cmd in sum((b.commands for b in batches), []):
        cmd.batch_index = next(b.index for b in batches if cmd in b.commands)

    return BatchPlanResult(batches=batches, deferred_rules=deferred, uncovered=uncovered)
