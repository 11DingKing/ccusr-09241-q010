"""持久化与重启恢复：JSON 仓库原子保存，游标/状态完整复原。"""

import tempfile
import unittest
from pathlib import Path

from policy_wave_control.application.ports import ScriptedClock, SequentialIds
from policy_wave_control.composition import build_service
from tests.support import T0


class PersistenceRecoveryTests(unittest.TestCase):
    def test_state_survives_service_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"

            def fresh():
                return build_service(data, clock=ScriptedClock(T0), ids=SequentialIds())

            svc = fresh()
            snap = svc.add_snapshot(
                name="t",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[{"id": "d1", "zone_id": "zp", "name": "d", "capabilities": ["c"]},
                         {"id": "d2", "zone_id": "zp", "name": "d2", "capabilities": ["c"]}],
                edges=[],
            )
            pol = svc.add_policy(
                name="p", snapshot_id=snap.id,
                rules=[{"id": "r1", "name": "n", "action": "deny",
                        "src_zone": "zp", "dst_zone": "zp", "service": "x",
                        "requires": ["c"]}],
            )
            rl = svc.create_rollout(pol.id, "发布", "rm")
            svc.approve(rl.id, 0, "release_manager", "rm")
            svc.approve(rl.id, 0, "security_admin", "sec")
            svc.dispatch_batch(rl.id)
            for cmd in svc.rollouts.get(rl.id).batches[0].commands:
                svc.receive_receipt(rl.id, cmd.id, 1, "applied")

            restarted = fresh()
            recovered = restarted.recover()
            record = next(r for r in recovered["rollouts"] if r["rollout_id"] == rl.id)
            self.assertEqual(record["cursor"], 0)
            # 批次在途：current_batch 指向批次 0
            self.assertEqual(record["current_batch"], 0)
            self.assertEqual(record["state"], "active")
            self.assertTrue(recovered["audit"]["ok"])

            # 重启后继续推进：补证据、完成批次 0，再完成批次 1
            restarted.adopt_evidence(rl.id, 0, "availability", 1.0, "p", "s")
            restarted.adopt_evidence(rl.id, 0, "error_rate", 0.0, "p", "s")
            restarted.advance(rl.id, "rm")
            restarted.approve(rl.id, 1, "security_admin", "sec")
            restarted.approve(rl.id, 1, "personal_zone_owner", "owner")
            restarted.dispatch_batch(rl.id)
            for cmd in restarted.rollouts.get(rl.id).batches[1].commands:
                restarted.receive_receipt(rl.id, cmd.id, 1, "applied")
            restarted.adopt_evidence(rl.id, 1, "availability", 1.0, "p", "s")
            restarted.adopt_evidence(rl.id, 1, "error_rate", 0.0, "p", "s")
            restarted.advance(rl.id, "rm")

            final = fresh().recover()
            final_record = next(r for r in final["rollouts"] if r["rollout_id"] == rl.id)
            self.assertEqual(final_record["state"], "completed")
            self.assertEqual(final_record["cursor"], 2)
            self.assertIsNone(final_record["current_batch"])

    def test_files_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            svc = build_service(data)
            svc.add_snapshot(
                name="t",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[], edges=[],
            )
            self.assertTrue(any(data.glob("snapshot__*.json")))
            self.assertTrue((data / "audit.log.json").exists())
