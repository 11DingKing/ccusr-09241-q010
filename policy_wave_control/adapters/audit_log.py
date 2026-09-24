"""追加式审计日志：JSONL 落盘 + SHA256 哈希链，可重放校验。"""

from __future__ import annotations

import json
import os

from ..domain.audit import GENESIS_HASH, AuditEntry


class _AuditChain:
    """哈希链追加与校验的共享实现，不绑定存储介质。"""

    def __init__(self, clock) -> None:
        self._clock = clock
        self._entries: list[AuditEntry] = []
        self._tail_hash = GENESIS_HASH

    def _append_entry(self, actor: str, action: str, target_type: str,
                      target_id: str, payload: dict | None) -> AuditEntry:
        seq = len(self._entries) + 1
        at = self._clock.now()
        draft = AuditEntry(
            seq=seq, at=at, actor=actor, action=action,
            target_type=target_type, target_id=target_id,
            payload=payload or {}, prev_hash=self._tail_hash,
        )
        entry = AuditEntry(
            seq=seq, at=at, actor=actor, action=action,
            target_type=target_type, target_id=target_id,
            payload=payload or {}, prev_hash=self._tail_hash,
            entry_hash=draft.digest(),
        )
        self._entries.append(entry)
        self._tail_hash = entry.entry_hash
        return entry

    def _ingest(self, raw: dict) -> AuditEntry:
        entry = AuditEntry(
            seq=raw["seq"], at=raw["at"], actor=raw["actor"], action=raw["action"],
            target_type=raw["target_type"], target_id=raw["target_id"],
            payload=raw.get("payload", {}), prev_hash=raw["prev_hash"],
            entry_hash=raw.get("entry_hash", ""),
        )
        self._entries.append(entry)
        self._tail_hash = entry.entry_hash or self._tail_hash
        return entry

    def entries(self, target_id: str | None = None) -> list[AuditEntry]:
        if target_id is None:
            return list(self._entries)
        return [e for e in self._entries if e.target_id == target_id]

    def verify(self) -> dict:
        """重放哈希链，返回校验结论与首个断点。"""
        prev = GENESIS_HASH
        for e in self._entries:
            rebuilt = AuditEntry(
                seq=e.seq, at=e.at, actor=e.actor, action=e.action,
                target_type=e.target_type, target_id=e.target_id,
                payload=e.payload, prev_hash=prev,
            )
            expect = rebuilt.digest()
            if e.prev_hash != prev:
                return {"ok": False, "broken_at_seq": e.seq,
                        "reason": "prev_hash 与前条不符（条目可能被删除或插入）"}
            if e.entry_hash != expect:
                return {"ok": False, "broken_at_seq": e.seq,
                        "reason": "entry_hash 不匹配（条目内容被篡改）"}
            prev = expect
        seqs = [e.seq for e in self._entries]
        if seqs != list(range(1, len(seqs) + 1)):
            return {"ok": False, "broken_at_seq": None, "reason": "序号不连续"}
        return {"ok": True, "entries": len(self._entries),
                "tail_hash": self._tail_hash}


class AppendOnlyAuditLog(_AuditChain):
    """每行一个 JSON 对象，只允许追加；entry_hash 与 prev_hash 构成链。"""

    def __init__(self, path: str, clock) -> None:
        super().__init__(clock)
        self._path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._ingest(json.loads(line))

    def append(self, actor: str, action: str, target_type: str,
               target_id: str, payload: dict | None = None) -> AuditEntry:
        entry = self._append_entry(actor, action, target_type, target_id, payload)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry

    @property
    def path(self) -> str:
        return self._path


class InMemoryAuditLog(_AuditChain):
    """测试与离线场景用：不落盘，仍保持哈希链语义。"""

    def append(self, actor: str, action: str, target_type: str,
               target_id: str, payload: dict | None = None) -> AuditEntry:
        return self._append_entry(actor, action, target_type, target_id, payload)
