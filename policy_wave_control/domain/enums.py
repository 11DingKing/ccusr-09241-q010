"""领域枚举与角色常量。"""

from __future__ import annotations

from enum import Enum


class ZoneKind(str, Enum):
    PERSONAL = "personal"  # 个人业务区
    MACHINE = "machine"  # 机器（服务器/工作负载）业务区
    IOT = "iot"  # 物联业务区


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ISOLATE = "isolate"


class ReleaseStatus(str, Enum):
    DRAFT = "draft"
    PLANNED = "planned"  # 预演通过、批次已生成，等待金丝雀下发
    ACTIVE = "active"  # 正在分波推进
    PAUSED = "paused"  # 观测恶化或人工暂停，未开始批次被冻结
    ROLLING_BACK = "rolling_back"
    PARTIALLY_ROLLED_BACK = "partially_rolled_back"
    ROLLED_BACK = "rolled_back"
    COMPLETED = "completed"
    FAILED = "failed"


class BatchStatus(str, Enum):
    PENDING = "pending"  # 尚未开始（前序未确认）
    DISPATCHED = "dispatched"  # 命令已下发，等待回执
    HEALTH_WATCH = "health_watch"  # 设备回执达标，正在采集健康证据
    AWAITING_APPROVAL = "awaiting_approval"  # 健康阈值达标，等待相应角色确认
    CONFIRMED = "confirmed"
    PAUSED = "paused"  # 未开始批次被冻结
    DEGRADED = "degraded"  # 在制批次观测恶化
    FAILED = "failed"  # 设备回执未达部署比例
    ROLLING_BACK = "rolling_back"
    PARTIALLY_ROLLED_BACK = "partially_rolled_back"
    ROLLED_BACK = "rolled_back"


class CommandStatus(str, Enum):
    PLANNED = "planned"
    SENT = "sent"
    APPLIED = "applied"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    ROLLBACK_SENT = "rollback_sent"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class ReceiptStatus(str, Enum):
    APPLIED = "applied"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    DUPLICATE = "duplicate"


class ExceptionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RollbackPlanStatus(str, Enum):
    PLANNED = "planned"
    EXECUTING = "executing"
    PARTIAL = "partial"
    DONE = "done"
    SKIPPED = "skipped"  # 仅用于步骤：命令原本未生效，无需回退
    FAILED = "failed"  # 仅用于步骤：回退命令被设备拒绝/超时


# 角色：安全主管 / 网络运维 / 业务责任人
ROLE_SECURITY_OFFICER = "security_officer"
ROLE_NETWORK_OPERATOR = "network_operator"
ROLE_SERVICE_OWNER = "service_owner"

ALL_ROLES = {
    ROLE_SECURITY_OFFICER,
    ROLE_NETWORK_OPERATOR,
    ROLE_SERVICE_OWNER,
}

# 区域类型 -> 确认该区域批次所需的角色
ZONE_KIND_ROLE = {
    ZoneKind.PERSONAL.value: ROLE_SECURITY_OFFICER,
    ZoneKind.MACHINE.value: ROLE_NETWORK_OPERATOR,
    ZoneKind.IOT.value: ROLE_SERVICE_OWNER,
}
