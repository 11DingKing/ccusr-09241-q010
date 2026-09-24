"""HTTP 接口层：仅用标准库，把应用服务暴露为本地 JSON 接口。"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from ..domain.errors import DomainError
from ..application.service import ReleaseService


def create_handler(service: ReleaseService):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:  # 静默，验收脚本自行输出
            return

        # ---- 基础工具 ----
        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def _actor(self, body: dict) -> str:
            return self.headers.get("X-Actor") or body.get("actor") or "operator"

        def _role(self, body: dict, key: str = "role") -> str:
            return self.headers.get("X-Role") or body[key]

        def _handle(self, fn, *, ok_status: int = 200) -> None:
            try:
                payload = fn()
            except DomainError as exc:
                self._send(exc.http_status, {"error": exc.to_dict()})
            except (KeyError, TypeError, ValueError) as exc:
                self._send(400, {"error": {"code": "bad_request", "message": str(exc)}})
            else:
                self._send(ok_status, payload if payload is not None else {"ok": True})

        # ---- 路由 ----
        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/health":
                self._send(200, {"ok": True})
            elif path.startswith("/releases/"):
                rid = path.rsplit("/", 1)[-1]
                self._handle(lambda: service.release_view(rid))
            elif path == "/exceptions":
                self._handle(lambda: service.list_exceptions())
            elif path == "/audit":
                self._handle(lambda: {"entries": service.audit_entries()})
            elif path == "/audit/verify":
                self._handle(lambda: service.verify_audit())
            elif path == "/gateway/records":
                self._handle(lambda: {"records": service.gateway_records()})
            else:
                self._send(404, {"error": {"code": "not_found", "message": path}})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                body = self._body()
            except json.JSONDecodeError as exc:
                self._send(400, {"error": {"code": "bad_json", "message": str(exc)}})
                return

            routes: dict = {
                "/topology/snapshots": lambda: service.register_snapshot(
                    body, actor=self._actor(body)),
                "/policy/versions": lambda: service.register_policy(
                    body, actor=self._actor(body)),
                "/exceptions": lambda: service.create_exception(
                    body, actor=self._actor(body)),
                "/releases/plan": lambda: service.plan_release(
                    snapshot_id=body.get("snapshot_id"),
                    policy_id=body.get("policy_id"),
                    thresholds=body.get("thresholds"),
                    actor=self._actor(body)),
                "/releases/dispatch": lambda: service.dispatch_current(
                    actor=self._actor(body)),
                "/releases/resend": lambda: service.resend_current(
                    actor=self._actor(body)),
                "/releases/pause": lambda: service.pause_release(
                    actor=self._actor(body), reason=body.get("reason", "人工暂停")),
                "/releases/resume": lambda: service.resume_release(
                    actor=self._actor(body)),
                "/releases/rollback": lambda: service.start_rollback(
                    actor=self._actor(body)),
                "/receipts": lambda: service.receive_receipt(
                    command_id=body["command_id"], status=body["status"],
                    seq=int(body["seq"]), actor=self._actor(body)),
                "/rollback-receipts": lambda: service.receive_rollback_receipt(
                    command_id=body["command_id"], status=body["status"],
                    seq=int(body["seq"]), actor=self._actor(body)),
            }

            if path in routes:
                self._handle(routes[path], ok_status=200)
                return

            if path.startswith("/exceptions/") and path.endswith("/renew"):
                exc_id = path.split("/")[2]
                self._handle(lambda: service.renew_exception(
                    exc_id, body["new_expires_at"], actor=self._actor(body)))
                return
            if path.startswith("/exceptions/") and path.endswith("/revoke"):
                exc_id = path.split("/")[2]
                self._handle(lambda: service.revoke_exception(
                    exc_id, actor=self._actor(body)))
                return
            if path.startswith("/batches/") and path.endswith("/evidence"):
                batch_id = path.split("/")[2]
                self._handle(lambda: service.submit_evidence(
                    batch_id, source=body["source"], seq=int(body["seq"]),
                    health_score=float(body["health_score"]),
                    critical_reachable=body["critical_reachable"],
                    actor=self._actor(body)))
                return
            if path.startswith("/batches/") and path.endswith("/confirm"):
                batch_id = path.split("/")[2]
                self._handle(lambda: service.confirm_batch(
                    batch_id, role=self._role(body),
                    actor=self._actor(body), note=body.get("note", "")))
                return

            self._send(404, {"error": {"code": "not_found", "message": path}})

    return Handler


def run_server(host: str, port: int, data_dir: str) -> ThreadingHTTPServer:
    from ..bootstrap import build_service

    service = build_service(data_dir)
    server = ThreadingHTTPServer((host, port), create_handler(service))
    return server
