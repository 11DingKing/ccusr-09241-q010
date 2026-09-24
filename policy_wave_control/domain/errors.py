"""领域错误：所有业务规则违背都抛出携带稳定错误码的异常。"""

from __future__ import annotations


class DomainError(Exception):
    """业务错误基类，code 供接口层映射为状态码与结构化响应。"""

    code = "domain_error"
    http_status = 400

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "details": self.details}


class NotFoundError(DomainError):
    code = "not_found"
    http_status = 404


class ConflictError(DomainError):
    code = "conflict"
    http_status = 409


class AuthorizationError(DomainError):
    code = "forbidden"
    http_status = 403


class ValidationError(DomainError):
    code = "validation_error"
    http_status = 422


class CapabilityBlockedError(ConflictError):
    """目标区域设备能力不满足策略条件，无法编排发布波次。"""

    code = "capability_blocked"

    def __init__(self, blockers: list[dict]) -> None:
        super().__init__(
            "部分设备缺少执行规则所需能力，请先升级固件或调整策略范围",
            {"blockers": blockers},
        )
        self.blockers = blockers


class DependencyCycleError(ConflictError):
    code = "dependency_cycle"

    def __init__(self, cycle: list[str]) -> None:
        super().__init__("规则依赖存在环，无法确定下发顺序", {"cycle": cycle})


class HealthGateError(ConflictError):
    code = "health_gate_failed"

    def __init__(self, message: str, evaluation: dict) -> None:
        super().__init__(message, {"evaluation": evaluation})
        self.evaluation = evaluation
