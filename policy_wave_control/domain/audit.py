"""追加式审计日志条目（带哈希链，可校验防篡改）。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: str
    actor: str          # 操作角色或 "system"（自动动作）
    action: str         # 稳定动作码，如 release.plan / batch.confirm
    target_type: str
    target_id: str
    payload: dict
    prev_hash: str
    entry_hash: str = ""

    def digest(self) -> str:
        body = {
            "seq": self.seq,
            "at": self.at,
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "at": self.at,
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


GENESIS_HASH = "0" * 64


def compute_chain(entries: list[AuditEntry]) -> list[str]:
    """重算整条链的哈希，返回每条应有的 entry_hash 列表。"""
    prev = GENESIS_HASH
    out: list[str] = []
    for e in entries:
        body = AuditEntry(
            seq=e.seq, at=e.at, actor=e.actor, action=e.action,
            target_type=e.target_type, target_id=e.target_id,
            payload=e.payload, prev_hash=prev,
        )
        out.append(body.digest())
        prev = out[-1]
    return out
