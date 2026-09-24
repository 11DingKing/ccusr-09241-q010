"""仓储与外部网关端口。"""

from __future__ import annotations

from typing import Protocol

from ..domain.release import Batch, DeviceCommand, Release


class ReleaseRepository(Protocol):
    def save(self, release: Release) -> None: ...

    def get(self, release_id: str) -> Release: ...

    def list_all(self) -> list[Release]: ...


class TopologyRepository(Protocol):
    def save_snapshot(self, snapshot) -> None: ...

    def get_latest(self) -> object: ...

    def get(self, snapshot_id: str) -> object: ...


class PolicyRepository(Protocol):
    def save(self, policy) -> None: ...

    def get(self, policy_id: str) -> object: ...

    def list_all(self) -> list[object]: ...


class ExceptionRepository(Protocol):
    def save(self, exc) -> None: ...

    def get(self, exception_id: str) -> object: ...

    def list_all(self) -> list[object]: ...

    def active_for(self, rule_id: str, zone_id: str, now_iso: str) -> object | None: ...


class AuditLog(Protocol):
    def append(self, actor: str, action: str, target_type: str,
               target_id: str, payload: dict) -> object: ...

    def entries(self, target_id: str | None = None) -> list[object]: ...

    def verify(self) -> dict: ...


class DeviceGateway(Protocol):
    """向设备下发命令。返回每命令的发送结果：dispatched（首次）或 duplicate（重复）。"""

    def send_commands(self, commands: list[DeviceCommand], rollback: bool = False) -> dict[str, str]:
        """返回 command_id -> 'dispatched' | 'duplicate'。"""
        ...

    def sent_records(self) -> list[dict]:
        """离线场景运行器用：返回所有发送记录（含重复发送痕迹）。"""
        ...
