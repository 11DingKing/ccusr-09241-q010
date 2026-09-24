"""审计哈希链：正常校验通过；任何字段被篡改都会被检出。"""

import json
import tempfile
import unittest
from pathlib import Path

from policy_wave_control.application.ports import ScriptedClock, SequentialIds
from policy_wave_control.composition import build_service
from tests.support import T0


class AuditChainTests(unittest.TestCase):
    def test_verify_after_full_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            svc = build_service(Path(tmp), clock=ScriptedClock(T0), ids=SequentialIds())
            snap = svc.add_snapshot(
                name="t",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[{"id": "d", "zone_id": "zp", "name": "d", "capabilities": ["c"]}],
                edges=[],
            )
            pol = svc.add_policy(
                name="p", snapshot_id=snap.id,
                rules=[{"id": "r", "name": "n", "action": "deny", "src_zone": "zp",
                        "dst_zone": "zp", "service": "s", "requires": ["c"]}],
            )
            rl = svc.create_rollout(pol.id, "发", "rm")
            result = svc.verify_audit()
            self.assertTrue(result["ok"])
            self.assertGreaterEqual(result["entries"], 3)

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            svc = build_service(data, clock=ScriptedClock(T0), ids=SequentialIds())
            snap = svc.add_snapshot(
                name="t",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[{"id": "d", "zone_id": "zp", "name": "d", "capabilities": ["c"]}],
                edges=[],
            )
            svc.add_policy(
                name="p", snapshot_id=snap.id,
                rules=[{"id": "r", "name": "n", "action": "deny", "src_zone": "zp",
                        "dst_zone": "zp", "service": "s", "requires": ["c"]}],
            )
            svc.create_rollout(svc.policies.all()[0].id, "发", "rm")

            log_path = data / "audit.log.json"
            payload = json.loads(log_path.read_text(encoding="utf-8"))
            # 篡改中间一条审计记录的动作
            payload["entries"][1]["action"] = "policy.deleted"
            log_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

            reloaded = build_service(data, clock=ScriptedClock(T0), ids=SequentialIds())
            result = reloaded.verify_audit()
            self.assertFalse(result["ok"])
            self.assertIn(result["broken_at"], (2, 3))

    def test_appending_after_tamper_keeps_verification_honest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            svc = build_service(data, clock=ScriptedClock(T0), ids=SequentialIds())
            svc.add_snapshot(
                name="t",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[], edges=[],
            )
            log_path = data / "audit.log.json"
            payload = json.loads(log_path.read_text(encoding="utf-8"))
            payload["entries"][0]["actor"] = "forged"
            log_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            reloaded = build_service(data, clock=ScriptedClock(T0), ids=SequentialIds())
            self.assertFalse(reloaded.verify_audit()["ok"])
