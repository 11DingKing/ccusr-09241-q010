"""组合根：基于数据目录组装服务。"""

from __future__ import annotations

from pathlib import Path

from .adapters.persistence import (
    ExceptionRepository,
    JsonAuditStore,
    PolicyRepository,
    RolloutRepository,
    SnapshotRepository,
)
from .application.ports import Clock, IdGenerator, SystemClock, UuidIds
from .application.services import ReleaseService, RollbackExecutor


def build_service(
    data_dir: str | Path,
    clock: Clock | None = None,
    ids: IdGenerator | None = None,
    rollback_executor: RollbackExecutor | None = None,
) -> ReleaseService:
    base = Path(data_dir)
    base.mkdir(parents=True, exist_ok=True)
    return ReleaseService(
        snapshots=SnapshotRepository(base),
        policies=PolicyRepository(base),
        exceptions=ExceptionRepository(base),
        rollouts=RolloutRepository(base),
        audit_store=JsonAuditStore(base),
        clock=clock or SystemClock(),
        ids=ids or UuidIds(),
        rollback_executor=rollback_executor,
    )
