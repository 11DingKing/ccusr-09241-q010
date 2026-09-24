"""区域拓扑快照：设备、区域、关键业务与能力清单的不可变版本。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import ZoneKind


@dataclass(frozen=True)
class Device:
    device_id: str
    zone_id: str
    capabilities: frozenset[str]  # 设备支持的能力，如 acl_v2 / micro_segmentation
    firmware: str
    critical: bool = False  # 关键设备（承载关键业务）

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "zone_id": self.zone_id,
            "capabilities": sorted(self.capabilities),
            "firmware": self.firmware,
            "critical": self.critical,
        }


@dataclass(frozen=True)
class Zone:
    zone_id: str
    name: str
    kind: str  # ZoneKind 值
    cidr: str

    def __post_init__(self) -> None:
        if self.kind not in {k.value for k in ZoneKind}:
            raise ValueError(f"未知区域类型: {self.kind}")

    def to_dict(self) -> dict:
        return {"zone_id": self.zone_id, "name": self.name, "kind": self.kind, "cidr": self.cidr}


@dataclass(frozen=True)
class CriticalService:
    """关键业务：发布必须保证其在可达性预演中不被新策略阻断。"""

    service_id: str
    name: str
    src_zone: str
    dst_zone: str
    protocol: str
    port: int
    owner: str  # 业务责任人
    rto_minutes: int = 30  # 可接受恢复时间目标，影响金丝雀健康窗口

    def flow_key(self) -> tuple[str, str, str, int]:
        return (self.src_zone, self.dst_zone, self.protocol, self.port)

    def to_dict(self) -> dict:
        return {
            "service_id": self.service_id,
            "name": self.name,
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "protocol": self.protocol,
            "port": self.port,
            "owner": self.owner,
            "rto_minutes": self.rto_minutes,
        }


@dataclass(frozen=True)
class TopologySnapshot:
    """某一时刻的拓扑视图。快照一经发布不可变，发布单始终绑定快照版本。"""

    snapshot_id: str
    version: int
    taken_at: str
    zones: tuple[Zone, ...]
    devices: tuple[Device, ...]
    services: tuple[CriticalService, ...]

    def zone(self, zone_id: str) -> Zone | None:
        return next((z for z in self.zones if z.zone_id == zone_id), None)

    def devices_in(self, zone_id: str) -> list[Device]:
        return [d for d in self.devices if d.zone_id == zone_id]

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "version": self.version,
            "taken_at": self.taken_at,
            "zones": [z.to_dict() for z in self.zones],
            "devices": [d.to_dict() for d in self.devices],
            "services": [s.to_dict() for s in self.services],
        }
