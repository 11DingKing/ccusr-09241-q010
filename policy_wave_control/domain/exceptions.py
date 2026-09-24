"""有期限的策略例外（长期白名单），支持续期与到期失效。"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import ExceptionStatus
from .errors import ConflictError, ValidationError


@dataclass
class PolicyException:
    """对某条规则在指定区域上的临时豁免。

    - 例外有 expires_at；到期后发布预演和设备下发都不再承认它。
    - 续期只能延后到期时间，且需要相应角色审批，全过程入追加式日志。
    - 已撤销/已过期的例外不能被“复活”，需新建。
    """

    exception_id: str
    rule_id: str
    zone_id: str
    reason: str
    created_at: str
    expires_at: str
    created_by: str
    status: str = ExceptionStatus.ACTIVE.value
    renewed_count: int = 0
    last_renewed_at: str | None = None
    last_renewed_by: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None

    def is_active(self, now_iso: str) -> bool:
        """以 ISO 字符串字典序判定是否在有效期（系统内部统一 UTC，可安全比较）。"""
        return self.status == ExceptionStatus.ACTIVE.value and self.expires_at > now_iso

    def effective_state(self, now_iso: str) -> str:
        """返回考虑当前时间后的状态（过期是延迟计算的，不依赖后台任务）。"""
        if self.status == ExceptionStatus.ACTIVE.value and self.expires_at <= now_iso:
            return ExceptionStatus.EXPIRED.value
        return self.status

    def renew(self, new_expires_at: str, now_iso: str, actor: str) -> None:
        if self.effective_state(now_iso) != ExceptionStatus.ACTIVE.value:
            raise ConflictError(
                "仅生效中的例外可以续期，已过期或撤销的例外请重新申请",
                {"exception_id": self.exception_id, "status": self.effective_state(now_iso)},
            )
        if new_expires_at <= self.expires_at:
            raise ValidationError(
                "续期必须晚于当前到期时间",
                {"current_expires_at": self.expires_at, "requested": new_expires_at},
            )
        self.expires_at = new_expires_at
        self.renewed_count += 1
        self.last_renewed_at = now_iso
        self.last_renewed_by = actor

    def revoke(self, now_iso: str, actor: str) -> None:
        if self.status != ExceptionStatus.ACTIVE.value:
            raise ConflictError("例外不在生效中，无法撤销", {"exception_id": self.exception_id})
        self.status = ExceptionStatus.REVOKED.value
        self.revoked_at = now_iso
        self.revoked_by = actor

    def to_dict(self, now_iso: str | None = None) -> dict:
        data = {
            "exception_id": self.exception_id,
            "rule_id": self.rule_id,
            "zone_id": self.zone_id,
            "reason": self.reason,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "created_by": self.created_by,
            "status": self.status if now_iso is None else self.effective_state(now_iso),
            "renewed_count": self.renewed_count,
            "last_renewed_at": self.last_renewed_at,
            "last_renewed_by": self.last_renewed_by,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }
        if now_iso is not None:
            data["expired"] = not self.is_active(now_iso)
        return data
