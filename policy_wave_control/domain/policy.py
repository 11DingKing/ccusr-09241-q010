"""策略版本：规则、能力条件与规则间依赖顺序。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import RuleAction
from .errors import DependencyCycleError, ValidationError


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    action: str  # RuleAction 值
    src_zone: str
    dst_zone: str
    protocol: str
    port: int
    required_capability: str  # 执行该规则设备必须具备的能力
    description: str = ""

    def __post_init__(self) -> None:
        if self.action not in {a.value for a in RuleAction}:
            raise ValidationError(f"未知规则动作: {self.action}")
        if self.port < 0 or self.port > 65535:
            raise ValidationError(f"非法端口: {self.port}")

    def flow_key(self) -> tuple[str, str, str, int]:
        return (self.src_zone, self.dst_zone, self.protocol, self.port)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "protocol": self.protocol,
            "port": self.port,
            "required_capability": self.required_capability,
            "description": self.description,
        }


@dataclass(frozen=True)
class PolicyVersion:
    """一次待发布的策略集合。depends_on 给出规则下发的先后约束。"""

    policy_id: str
    version: int
    created_at: str
    rules: tuple[PolicyRule, ...]
    # rule_id -> 必须先于它下发的 rule_id 列表
    depends_on: dict[str, tuple[str, ...]] = field(default_factory=dict)
    note: str = ""

    def rule(self, rule_id: str) -> PolicyRule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "created_at": self.created_at,
            "rules": [r.to_dict() for r in self.rules],
            "depends_on": {k: list(v) for k, v in self.depends_on.items()},
            "note": self.note,
        }

    def topological_order(self) -> list[str]:
        """按依赖顺序返回规则 ID；存在环时抛出 DependencyCycleError。"""
        ids = {r.rule_id for r in self.rules}
        deps = {rid: [d for d in self.depends_on.get(rid, ()) if d in ids] for rid in ids}
        order: list[str] = []
        state: dict[str, int] = {}  # 0=访问中 1=完成

        def visit(node: str, stack: list[str]) -> None:
            mark = state.get(node)
            if mark == 1:
                return
            if mark == 0:
                cycle = stack[stack.index(node):] + [node]
                raise DependencyCycleError(cycle)
            state[node] = 0
            stack.append(node)
            for dep in deps[node]:
                visit(dep, stack)
            stack.pop()
            state[node] = 1
            order.append(node)

        for rid in sorted(ids):
            visit(rid, [])
        return order
