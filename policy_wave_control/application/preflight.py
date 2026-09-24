"""预演引擎：能力条件校验、例外有效性、可达性影响与批次生成。"""

from __future__ import annotations

import math

from ..domain.enums import (
    ROLE_SECURITY_OFFICER,
    RuleAction,
    ZONE_KIND_ROLE,
)
from ..domain.release import Batch, DeviceCommand
from ..domain.topology import TopologySnapshot
from ..domain.policy import PolicyVersion
from ..domain.exceptions import PolicyException
from ..domain.enums import ExceptionStatus


# 金丝雀之后，各区域批次按区域类型的默认先后（机器区先于个人区先于物联区；
# 同类型内再按规则依赖顺序，见 planner 中的排序）。
_ZONE_KIND_ORDER = {"machine": 0, "personal": 1, "iot": 2}


class PreflightEngine:
    def __init__(self, idgen) -> None:
        self._id = idgen

    # ------------------------------------------------------------------
    def check_capabilities(
        self, snapshot: TopologySnapshot, policy: PolicyVersion
    ) -> list[dict]:
        """每条规则要求其执行区域内所有设备具备 required_capability。"""
        blockers: list[dict] = []
        for rule in policy.rules:
            for device in snapshot.devices_in(rule.src_zone):
                if rule.required_capability not in device.capabilities:
                    blockers.append({
                        "rule_id": rule.rule_id,
                        "zone_id": rule.src_zone,
                        "device_id": device.device_id,
                        "required_capability": rule.required_capability,
                        "firmware": device.firmware,
                    })
        return blockers

    def classify_exceptions(
        self,
        policy: PolicyVersion,
        exceptions: list[PolicyException],
        now_iso: str,
    ) -> tuple[dict[tuple[str, str], PolicyException], list[dict]]:
        """把与本策略相关的例外分为生效豁免表与过期清单。"""
        rule_ids = {r.rule_id for r in policy.rules}
        active: dict[tuple[str, str], PolicyException] = {}
        expired: list[dict] = []
        for exc in exceptions:
            if exc.rule_id not in rule_ids or exc.status == ExceptionStatus.REVOKED.value:
                continue
            if exc.is_active(now_iso):
                active[(exc.rule_id, exc.zone_id)] = exc
            else:
                expired.append({
                    "exception_id": exc.exception_id,
                    "rule_id": exc.rule_id,
                    "zone_id": exc.zone_id,
                    "expires_at": exc.expires_at,
                    "reason": exc.reason,
                })
        return active, expired

    def simulate_reachability(
        self,
        snapshot: TopologySnapshot,
        policy: PolicyVersion,
        active_exemptions: dict[tuple[str, str], PolicyException],
        expired: list[dict],
    ) -> dict:
        """以关键业务流为对象模拟新策略下的可达性。

        规则匹配 (src_zone, dst_zone, protocol, port)：
        * deny/isolate 生效即阻断，除非 (rule_id, src_zone) 存在生效例外；
        * 过期例外不产生豁免，并在结果中标记其影响。
        """
        rules_by_flow: dict[tuple, list] = {}
        for rule in policy.rules:
            rules_by_flow.setdefault(rule.flow_key(), []).append(rule)

        expired_by_flow: dict[tuple, list[str]] = {}
        for item in expired:
            rule = policy.rule(item["rule_id"])
            if rule is not None:
                expired_by_flow.setdefault(rule.flow_key(), []).append(item["exception_id"])

        reachable: list[str] = []
        blocked: list[dict] = []
        for svc in snapshot.services:
            flow = svc.flow_key()
            blocking = []
            for rule in rules_by_flow.get(flow, []):
                if rule.action == RuleAction.ALLOW.value:
                    continue
                if (rule.rule_id, rule.src_zone) in active_exemptions:
                    continue
                blocking.append(rule.rule_id)
            if blocking:
                blocked.append({
                    "service_id": svc.service_id,
                    "name": svc.name,
                    "flow": {"src_zone": flow[0], "dst_zone": flow[1],
                             "protocol": flow[2], "port": flow[3]},
                    "blocked_by_rules": blocking,
                    "expired_exceptions": expired_by_flow.get(flow, []),
                    "owner": svc.owner,
                })
            else:
                reachable.append(svc.service_id)
        return {
            "checked": len(snapshot.services),
            "reachable": reachable,
            "blocked": blocked,
        }

    # ------------------------------------------------------------------
    def build_batches(
        self,
        release_id: str,
        snapshot: TopologySnapshot,
        policy: PolicyVersion,
        active_exemptions: dict[tuple[str, str], PolicyException],
        thresholds,
    ) -> tuple[list[Batch], list[dict]]:
        """生成金丝雀批次 + 后续区域批次，返回 (批次列表, 豁免明细)。"""
        ordered_rule_ids = policy.topological_order()
        rule_order = {rid: i for i, rid in enumerate(ordered_rule_ids)}
        exempted: list[dict] = []

        # 收集命令：rule_order -> zone -> [DeviceCommand]
        per_zone: dict[str, list[DeviceCommand]] = {}
        for rid in ordered_rule_ids:
            rule = policy.rule(rid)  # type: ignore[union-attr]
            exc = active_exemptions.get((rid, rule.src_zone))
            if exc is not None:
                exempted.append({
                    "rule_id": rid,
                    "zone_id": rule.src_zone,
                    "exception_id": exc.exception_id,
                    "expires_at": exc.expires_at,
                })
                continue
            for device in sorted(snapshot.devices_in(rule.src_zone),
                                 key=lambda d: (not d.critical, d.device_id)):
                cmd = DeviceCommand(
                    command_id=self._id.new_id("cmd"),
                    batch_index=-1,  # 批次确定后回填
                    device_id=device.device_id,
                    zone_id=rule.src_zone,
                    rule_id=rid,
                    rule_order=rule_order[rid],
                )
                per_zone.setdefault(rule.src_zone, []).append(cmd)

        canary_commands: list[DeviceCommand] = []
        zone_remaining: dict[str, list[DeviceCommand]] = {}
        canary_devices: dict[str, set[str]] = {}
        for zone_id, cmds in per_zone.items():
            devices = sorted({c.device_id for c in cmds})
            pick = max(1, math.ceil(len(devices) * thresholds.canary_ratio))
            picked = set(devices[:pick])
            canary_devices[zone_id] = picked
            for c in cmds:
                if c.device_id in picked:
                    canary_commands.append(c)
                else:
                    zone_remaining.setdefault(zone_id, []).append(c)

        batches: list[Batch] = []
        canary = Batch(
            batch_id=self._id.new_id("batch"),
            index=0,
            kind="canary",
            zone_id=None,
            required_role=ROLE_SECURITY_OFFICER,
            rule_ids=ordered_rule_ids,
            commands=sorted(canary_commands, key=lambda c: (c.rule_order, c.zone_id, c.device_id)),
        )
        batches.append(canary)

        def zone_sort_key(zid: str) -> tuple:
            zone = snapshot.zone(zid)
            kind_rank = _ZONE_KIND_ORDER.get(zone.kind if zone else "iot", 9)
            min_order = min(c.rule_order for c in zone_remaining[zid])
            return (kind_rank, min_order, zid)

        for i, zid in enumerate(sorted(zone_remaining, key=zone_sort_key), start=1):
            zone = snapshot.zone(zid)
            role = ZONE_KIND_ROLE.get(zone.kind if zone else "", ROLE_SECURITY_OFFICER)
            batches.append(Batch(
                batch_id=self._id.new_id("batch"),
                index=i,
                kind="zone",
                zone_id=zid,
                required_role=role,
                rule_ids=sorted({c.rule_id for c in zone_remaining[zid]},
                                key=lambda r: rule_order[r]),
                commands=sorted(zone_remaining[zid],
                                key=lambda c: (c.rule_order, c.device_id)),
            ))

        for b in batches:
            for c in b.commands:
                c.batch_index = b.index
        return batches, exempted

    # ------------------------------------------------------------------
    def run(
        self,
        release_id: str,
        snapshot: TopologySnapshot,
        policy: PolicyVersion,
        exceptions: list[PolicyException],
        thresholds,
        now_iso: str,
    ) -> tuple[list[Batch] | None, dict]:
        """执行完整预演，返回 (批次或 None, 报告)。存在硬性阻断时批次为 None。"""
        blockers = self.check_capabilities(snapshot, policy)
        active, expired = self.classify_exceptions(policy, exceptions, now_iso)
        reachability = self.simulate_reachability(snapshot, policy, active, expired)

        active_used = [
            {"rule_id": rid, "zone_id": zid,
             "exception_id": exc.exception_id, "expires_at": exc.expires_at}
            for (rid, zid), exc in sorted(active.items())
        ]

        hard_blocked = bool(blockers) or bool(reachability["blocked"])
        batches: list[Batch] | None = None
        exempted: list[dict] = []
        if not blockers:
            # 即便有关键业务阻断也生成计划供展示，但不允许进入 PLANNED
            batches, exempted = self.build_batches(
                release_id, snapshot, policy, active, thresholds
            )

        report = {
            "simulated_at": now_iso,
            "snapshot_id": snapshot.snapshot_id,
            "policy_id": policy.policy_id,
            "capability_blockers": blockers,
            "active_exceptions": active_used,
            "expired_exceptions": expired,
            "exempted_commands": exempted,
            "reachability": reachability,
            "batch_plan": [
                {"index": b.index, "kind": b.kind, "zone_id": b.zone_id,
                 "required_role": b.required_role, "command_count": len(b.commands)}
                for b in (batches or [])
            ],
            "passable": not hard_blocked,
        }
        return batches, report
