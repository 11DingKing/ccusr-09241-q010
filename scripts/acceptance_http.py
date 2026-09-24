#!/usr/bin/env python3
"""本地 HTTP 接口验收脚本：启动真实服务并用 HTTP 调用完成全流程。

运行（项目根目录）：
    python3 scripts/acceptance_http.py

不依赖第三方库；自动使用临时数据目录，结束后清理。
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from http.server import ThreadingHTTPServer  # noqa: E402

from policy_wave_control.interfaces.http_api import create_handler  # noqa: E402
from policy_wave_control.bootstrap import build_service  # noqa: E402

BASE = "http://127.0.0.1:0"
CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"  [{'通过' if ok else '失败'}] {name}" + (f" —— {detail}" if detail else ""))


class Api:
    def __init__(self, base_url: str) -> None:
        self.base = base_url

    def call(self, method: str, path: str, body: dict | None = None,
             role: str | None = None, expect_error: bool = False):
        data = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data if method == "POST" else None,
            method=method,
            headers={"Content-Type": "application/json",
                     "X-Actor": "acceptance", **({"X-Role": role} if role else {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8"))
            if expect_error:
                return exc.code, payload
            raise AssertionError(f"{method} {path} 意外失败: {payload}") from None


def start_server(data_dir: str) -> tuple[ThreadingHTTPServer, Api, threading.Thread]:
    service = build_service(data_dir)
    server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(service))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, Api(f"http://127.0.0.1:{port}"), thread


def topology() -> dict:
    return {
        "snapshot_id": "topo-http-1", "version": 1,
        "zones": [
            {"zone_id": "zp", "name": "个人区", "kind": "personal", "cidr": "10.10/16"},
            {"zone_id": "zm", "name": "机器区", "kind": "machine", "cidr": "10.20/16"},
            {"zone_id": "zi", "name": "物联区", "kind": "iot", "cidr": "10.30/16"},
        ],
        "devices": [
            *[{"device_id": f"p{i}", "zone_id": "zp", "capabilities": ["acl_v2"],
               "firmware": "3"} for i in range(1, 5)],
            *[{"device_id": f"m{i}", "zone_id": "zm", "capabilities": ["acl_v2"],
               "firmware": "4"} for i in range(1, 7)],
            *[{"device_id": f"iot{i}", "zone_id": "zi", "capabilities": ["acl_v2"],
               "firmware": "2"} for i in range(1, 5)],
        ],
        "services": [
            {"service_id": "svc-billing", "name": "计费", "src_zone": "zm",
             "dst_zone": "zm", "protocol": "tcp", "port": 443, "owner": "计费组"},
        ],
    }


def policy() -> dict:
    return {
        "policy_id": "pol-http-1", "version": 1,
        "rules": [
            {"rule_id": "r1", "action": "isolate", "src_zone": "zp", "dst_zone": "zi",
             "protocol": "tcp", "port": 502, "required_capability": "acl_v2"},
            {"rule_id": "r2", "action": "deny", "src_zone": "zm", "dst_zone": "zi",
             "protocol": "tcp", "port": 1883, "required_capability": "acl_v2"},
        ],
        "depends_on": {"r2": ["r1"]},
    }


def main() -> int:
    with tempfile.TemporaryDirectory() as data_dir:
        print("=" * 70)
        print("本地 HTTP 接口验收")
        print("=" * 70)
        server, api, _ = start_server(data_dir)
        try:
            status, _ = api.call("GET", "/health")
            check("健康检查 200", status == 200)

            print("\n-- 清单注册与预演 --")
            api.call("POST", "/topology/snapshots", topology())
            api.call("POST", "/policy/versions", policy())
            # 有效例外（过期例外的处理由离线场景运行器在固定时钟下完整演示）
            _, exc = api.call("POST", "/exceptions", {
                "rule_id": "r1", "zone_id": "zp",
                "expires_at": "2026-12-31T00:00:00+00:00", "reason": "割接白名单"})
            check("例外创建并经接口可查", exc["status"] == "active")
            # 续期必须晚于当前到期时间，否则 422
            code, _ = api.call("POST", f"/exceptions/{exc['exception_id']}/renew",
                               {"new_expires_at": "2026-06-01T00:00:00+00:00"},
                               expect_error=True)
            check("例外续期早于到期时间返回 422", code == 422, f"http={code}")
            _, renewed = api.call("POST", f"/exceptions/{exc['exception_id']}/renew",
                                  {"new_expires_at": "2027-06-30T00:00:00+00:00"})
            check("例外续期成功并留痕计数", renewed["renewed_count"] == 1)

            # 能力均满足且过期例外不阻断关键业务：预演成功（观测窗口设 0 便于接口验收）
            status, planned = api.call("POST", "/releases/plan", {
                "policy_id": "pol-http-1",
                "thresholds": {"canary_ratio": 0.25, "health_window_seconds": 0}})
            check("预演通过并生成批次", status == 200, f"http={status}")
            rid = planned["release"]["release_id"]
            canary = planned["release"]["batches"][0]
            check("首批为金丝雀", canary["kind"] == "canary")

            print("\n-- 乱序回执与重复命令 --")
            api.call("POST", "/releases/dispatch", {})
            cmd = canary["commands"][0]
            _, r1 = api.call("POST", "/receipts",
                             {"command_id": cmd["command_id"], "status": "applied", "seq": 2})
            _, r2 = api.call("POST", "/receipts",
                             {"command_id": cmd["command_id"], "status": "rejected", "seq": 1})
            check("旧回执经接口拒绝覆盖", r2["verdict"] == "stale" and r2["state"] == "applied")
            for c in canary["commands"][1:]:
                api.call("POST", "/receipts",
                         {"command_id": c["command_id"], "status": "applied", "seq": 1})
            _, resend = api.call("POST", "/releases/resend", {})
            check("重复命令接口返回 duplicate",
                  len(resend["duplicate_commands"]) == len(canary["commands"]))

            print("\n-- 健康证据、角色确认与游标推进 --")
            _, ev_ok = api.call("POST", f"/batches/{canary['batch_id']}/evidence", {
                "source": "probe", "seq": 2, "health_score": 0.99,
                "critical_reachable": {"svc-billing": True}})
            _, ev_stale = api.call("POST", f"/batches/{canary['batch_id']}/evidence", {
                "source": "probe", "seq": 1, "health_score": 0.10,
                "critical_reachable": {"svc-billing": False}})
            check("乱序证据经接口拒绝", ev_stale["verdict"] == "stale")
            check("健康门禁达标进入等待审批",
                  ev_ok["batch_status"] == "awaiting_approval", ev_ok["batch_status"])

            # 错误角色：403
            code, _ = api.call("POST", f"/batches/{canary['batch_id']}/confirm",
                               {"note": "x"}, role="network_operator", expect_error=True)
            check("错误角色确认返回 403", code == 403, f"http={code}")
            # 正确角色（安全主管）确认金丝雀 -> 游标推进
            _, confirmed = api.call("POST", f"/batches/{canary['batch_id']}/confirm",
                                    {"note": "金丝雀正常"}, role="security_officer")
            check("正确角色确认后游标推进", confirmed["cursor"] == 1,
                  f"cursor={confirmed['cursor']}")

            print("\n-- 审计链校验 --")
            _, verify = api.call("GET", "/audit/verify")
            check("接口返回哈希链校验通过", verify["ok"], f"条目={verify['entries']}")
            _, records = api.call("GET", "/gateway/records")
            check("网关留痕包含重复命令",
                  any(x["outcome"] == "duplicate" for x in records["records"]))
        finally:
            server.shutdown()
            server.server_close()

        print("\n-- 服务重启恢复（同数据目录重新监听）--")
        server2, api2, _ = start_server(data_dir)
        try:
            _, view = api2.call("GET", f"/releases/{rid}")
            hint = view["resume_hint"]
            check("重启后游标与状态恢复",
                  hint["cursor"] == 1 and hint["status"] == "active"
                  and hint["current_batch_status"] == "pending"
                  and hint["action"] == "dispatch_current_batch",
                  f"hint={hint}")
            _, verify2 = api2.call("GET", "/audit/verify")
            check("重启后审计链续写且校验通过", verify2["ok"])
        finally:
            server2.shutdown()
            server2.server_close()

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    print("\n" + "#" * 70)
    print(f"HTTP 接口验收结论：{passed}/{len(CHECKS)} 通过")
    print("#" * 70)
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
