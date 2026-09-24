"""本地 HTTP 接口端到端冒烟：创建、审批、下发、回执、推进、审计校验。"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from policy_wave_control.interfaces.http_api import serve
from policy_wave_control.composition import build_service


def _request(url: str, method: str = "GET", payload: dict | None = None):
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        service = build_service(Path(self.tmp.name) / "data")
        self.server = serve(service, port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_full_flow_over_http(self) -> None:
        code, snap = _request(f"{self.base}/api/snapshots", "POST", {
            "name": "拓扑",
            "zones": [{"id": "zp", "name": "个人", "kind": "personal"}],
            "devices": [
                {"id": "d1", "zone_id": "zp", "name": "d1", "capabilities": ["c"]},
                {"id": "d2", "zone_id": "zp", "name": "d2", "capabilities": ["c"]},
            ],
            "edges": [],
        })
        self.assertEqual(code, 200)

        code, pol = _request(f"{self.base}/api/policies", "POST", {
            "name": "策略",
            "snapshot_id": snap["id"],
            "rules": [
                {"id": "r1", "name": "封", "action": "deny",
                 "src_zone": "zp", "dst_zone": "zp", "service": "s", "requires": ["c"]},
            ],
        })
        self.assertEqual(code, 200)

        code, rl = _request(f"{self.base}/api/rollouts", "POST", {
            "policy_id": pol["id"], "name": "发布",
            "gate_metrics": {"availability": {"min": 0.9}},
        })
        self.assertEqual(code, 200)
        rid = rl["id"]
        self.assertEqual(len(rl["batches"]), 2)

        # 未审批直接下发 -> 400
        code, err = _request(f"{self.base}/api/rollouts/{rid}/dispatch", "POST", {})
        self.assertEqual(code, 400)

        code, _ = _request(f"{self.base}/api/rollouts/{rid}/approve", "POST", {
            "batch_index": 0, "role": "release_manager", "actor": "rm",
        })
        self.assertEqual(code, 200)
        code, _ = _request(f"{self.base}/api/rollouts/{rid}/approve", "POST", {
            "batch_index": 0, "role": "security_admin", "actor": "sec",
        })
        self.assertEqual(code, 200)

        code, disp = _request(f"{self.base}/api/rollouts/{rid}/dispatch", "POST", {})
        self.assertEqual(code, 200)
        cmd_ids = disp["new"]
        self.assertEqual(len(cmd_ids), 1)

        # 重复下发 -> 全部识别为 duplicates
        code, disp2 = _request(f"{self.base}/api/rollouts/{rid}/dispatch", "POST", {})
        self.assertEqual(disp2["new"], [])
        self.assertEqual(disp2["duplicates"], cmd_ids)

        for cid in cmd_ids:
            code, _ = _request(f"{self.base}/api/rollouts/{rid}/receipts", "POST", {
                "command_id": cid, "revision": 1, "claimed_state": "applied",
            })
            self.assertEqual(code, 200)

        # 旧版本回执被拒
        code, stale = _request(f"{self.base}/api/rollouts/{rid}/receipts", "POST", {
            "command_id": cmd_ids[0], "revision": 0, "claimed_state": "acked",
        })
        self.assertEqual(code, 200)
        self.assertFalse(stale["accepted"])

        code, _ = _request(f"{self.base}/api/rollouts/{rid}/evidence", "POST", {
            "batch_index": 0, "metric": "availability", "value": 0.999, "source": "p",
        })
        self.assertEqual(code, 200)
        code, adv = _request(f"{self.base}/api/rollouts/{rid}/advance", "POST", {})
        self.assertEqual(code, 200)
        self.assertEqual(adv["completed_batch"], 0)

        code, status = _request(f"{self.base}/api/rollouts/{rid}")
        self.assertEqual(status["cursor"], 1)
        code, verify = _request(f"{self.base}/api/audit/verify")
        self.assertTrue(verify["ok"])

    def test_health_and_unknown_route(self) -> None:
        code, body = _request(f"{self.base}/healthz")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        code, body = _request(f"{self.base}/api/nope")
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
