"""核心领域模型：区域拓扑快照、策略版本与有期限例外。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Iterable

# ---------------------------------------------------------------- 常量

ZONE_PERSONAL = "personal"
ZONE_MACHINE = "machine"
ZONE_IOT = "iot"
ZONE_KINDS = (ZONE_PERSONAL, ZONE_MACHINE, ZONE_IOT)

ACTION_ALLOW = "allow"
ACTION_DENY = "deny"


class DomainError(ValueError):
    """所有领域规则违反的统一异常，message 可直接呈现给调用方。"""


# ---------------------------------------------------------------- 拓扑

@dataclass
class Device:
    id: str
    zone_id: str
    name: str
    capabilities: list[str] = field(default_factory=list)
    critical: bool = False  # 承载关键业务的设备

    def supports(self, required: Iterable[str]) -> bool:
        return all(cap in self.capabilities for cap in required)


@dataclass
class Zone:
    id: str
    name: str
    kind: str
    default_policy: str = ACTION_ALLOW  # 缺省放行；可配置为 default-deny

    def __post_init__(self) -> None:
        if self.kind not in ZONE_KINDS:
            raise DomainError(f"未知区域类型: {self.kind}")
        if self.default_policy not in (ACTION_ALLOW, ACTION_DENY):
            raise DomainError(f"非法缺省策略: {self.default_policy}")


@dataclass
class FlowEdge:
    """区域间基线链路（物理/ Underlay 可达）。"""

    src_zone: str
    dst_zone: str
    service: str
    critical: bool = False


@dataclass
class TopologySnapshot:
    id: str
    name: str
    created_at: datetime
    zones: list[Zone]
    devices: list[Device]
    edges: list[FlowEdge] = field(default_factory=list)
    note: str = ""

    def zone(self, zone_id: str) -> Zone:
        for z in self.zones:
            if z.id == zone_id:
                return z
        raise DomainError(f"快照 {self.id} 中不存在区域 {zone_id}")

    def device(self, device_id: str) -> Device:
        for d in self.devices:
            if d.id == device_id:
                return d
        raise DomainError(f"快照 {self.id} 中不存在设备 {device_id}")

    def devices_of(self, zone_id: str) -> list[Device]:
        return [d for d in self.devices if d.zone_id == zone_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "zones": [asdict(z) for z in self.zones],
            "devices": [asdict(d) for d in self.devices],
            "edges": [asdict(e) for e in self.edges],
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TopologySnapshot":
        return cls(
            id=data["id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            zones=[Zone(**z) for z in data["zones"]],
            devices=[Device(**d) for d in data["devices"]],
            edges=[FlowEdge(**e) for e in data["edges"]],
            note=data.get("note", ""),
        )


# ---------------------------------------------------------------- 策略

@dataclass
class PolicyRule:
    id: str
    name: str
    action: str
    src_zone: str
    dst_zone: str
    service: str
    # 能力条件：设备缺少任一能力则该规则不可下发
    requires: list[str] = field(default_factory=list)
    # 依赖：depends_on 中的规则必须先于本规则下发（回退时逆序）
    depends_on: list[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        if self.action not in (ACTION_ALLOW, ACTION_DENY):
            raise DomainError(f"规则 {self.id} 的动作非法: {self.action}")


@dataclass
class PolicyVersion:
    id: str
    name: str
    snapshot_id: str
    created_at: datetime
    rules: list[PolicyRule]
    notes: str = ""

    def rule(self, rule_id: str) -> PolicyRule:
        for r in self.rules:
            if r.id == rule_id:
                return r
        raise DomainError(f"策略版本 {self.id} 中不存在规则 {rule_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at.isoformat(),
            "rules": [asdict(r) for r in self.rules],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyVersion":
        return cls(
            id=data["id"],
            name=data["name"],
            snapshot_id=data["snapshot_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            rules=[PolicyRule(**r) for r in data["rules"]],
            notes=data.get("notes", ""),
        )


# ---------------------------------------------------------------- 例外

EXC_ACTIVE = "active"
EXC_EXPIRED = "expired"
EXC_REVOKED = "revoked"


@dataclass
class PolicyException:
    """对单条规则的有期限例外；有效期内该规则不生效。"""

    id: str
    rule_id: str
    reason: str
    created_by: str
    valid_from: datetime
    valid_until: datetime
    scope_device_id: str | None = None
    revoked_at: datetime | None = None
    renewals: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.valid_until <= self.valid_from:
            raise DomainError(f"例外 {self.id} 的截止时间必须晚于生效时间")

    def is_active(self, at: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return self.valid_from <= at <= self.valid_until

    def state_at(self, at: datetime) -> str:
        if self.revoked_at is not None:
            return EXC_REVOKED
        if at > self.valid_until:
            return EXC_EXPIRED
        return EXC_ACTIVE

    def renew(self, new_until: datetime, actor: str, at: datetime, reason: str = "") -> None:
        """续期：只能延长，不能借续期把时间改短。"""
        if new_until <= self.valid_until:
            raise DomainError(
                f"例外 {self.id} 续期失败：新截止时间 {new_until.isoformat()} 不晚于"
                f"当前截止时间 {self.valid_until.isoformat()}"
            )
        self.renewals.append(
            {
                "previous_until": self.valid_until.isoformat(),
                "new_until": new_until.isoformat(),
                "actor": actor,
                "at": at.isoformat(),
                "reason": reason,
            }
        )
        self.valid_until = new_until

    def revoke(self, at: datetime) -> None:
        if self.revoked_at is not None:
            raise DomainError(f"例外 {self.id} 已被吊销")
        self.revoked_at = at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "created_by": self.created_by,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "scope_device_id": self.scope_device_id,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "renewals": list(self.renewals),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyException":
        return cls(
            id=data["id"],
            rule_id=data["rule_id"],
            reason=data["reason"],
            created_by=data["created_by"],
            valid_from=datetime.fromisoformat(data["valid_from"]),
            valid_until=datetime.fromisoformat(data["valid_until"]),
            scope_device_id=data.get("scope_device_id"),
            revoked_at=datetime.fromisoformat(data["revoked_at"]) if data.get("revoked_at") else None,
            renewals=list(data.get("renewals", [])),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
        )
