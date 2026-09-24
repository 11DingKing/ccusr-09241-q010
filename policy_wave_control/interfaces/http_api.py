"""本地 HTTP 接口（标准库实现，零外部依赖）。

启动：
    python -m policy_wave_control.interfaces.http_api --data-dir ./.runtime/data --port 8080
"""

from __future__ import annotations

import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ..application.services import ReleaseService
from ..domain.models import DomainError


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


class HttpApi:
    def __init__(self, service: ReleaseService) -> None:
        self.service = service

    def routes(self) -> list[tuple[str, str, Callable[[dict[str, Any], dict[str, str]], Any]]]:
        return [
            ("POST", "/api/snapshots", self._create_snapshot),
            ("POST", "/api/policies", self._create_policy),
            ("POST", "/api/exceptions", self._create_exception),
            ("POST", "/api/rollouts", self._create_rollout),
            ("GET", "/api/audit/verify", lambda b, p: self.service.verify_audit()),
            ("POST", "/api/recover", lambda b, p: self.service.recover()),
        ]

    # 以下方法由 handler 按路径分发
    def _create_snapshot(self, body: dict[str, Any], _: dict[str, str]) -> Any:
        return self.service.add_snapshot(
            name=body["name"],
            zones=body.get("zones", []),
            devices=body.get("devices", []),
            edges=body.get("edges", []),
            note=body.get("note", ""),
            actor=body.get("actor", "system"),
        ).to_dict()

    def _create_policy(self, body: dict[str, Any], _: dict[str, str]) -> Any:
        return self.service.add_policy(
            name=body["name"],
            snapshot_id=body["snapshot_id"],
            rules=body.get("rules", []),
            notes=body.get("notes", ""),
            actor=body.get("actor", "system"),
        ).to_dict()

    def _create_exception(self, body: dict[str, Any], _: dict[str, str]) -> Any:
        return self.service.add_exception(
            rule_id=body["rule_id"],
            reason=body.get("reason", ""),
            created_by=body.get("created_by", body.get("actor", "operator")),
            valid_from=_parse_dt(body.get("valid_from")),
            valid_until=_parse_dt(body.get("valid_until")),
            scope_device_id=body.get("scope_device_id"),
        ).to_dict()

    def _create_rollout(self, body: dict[str, Any], _: dict[str, str]) -> Any:
        return self.service.create_rollout(
            policy_id=body["policy_id"],
            name=body.get("name", body["policy_id"]),
            actor=body.get("actor", "operator"),
            gate_metrics=body.get("gate_metrics"),
            min_applied_ratio=body.get("min_applied_ratio", 1.0),
            at=_parse_dt(body.get("at")),
        ).to_dict()


def make_handler(service: ReleaseService) -> type[BaseHTTPRequestHandler]:
    api = HttpApi(service)
    static_routes = {
        (method, path): fn for method, path, fn in api.routes()
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "PolicyWaveControl/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:  # 安静日志
            return

        def _send(self, code: int, payload: Any) -> None:
            data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            try:
                body = self._read_body() if method in ("POST", "PUT", "PATCH") else {}
                result = self._dispatch(method, path, query, body)
                self._send(200, result)
            except DomainError as exc:
                self._send(400, {"error": str(exc), "type": "domain_error"})
            except KeyError as exc:
                self._send(400, {"error": f"缺少必填字段: {exc.args[0]}", "type": "bad_request"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, {"error": f"请求格式错误: {exc}", "type": "bad_request"})
            except FileNotFoundError as exc:
                self._send(404, {"error": str(exc), "type": "not_found"})
            except Exception as exc:  # 兜底，避免单请求异常拖垮进程
                self._send(500, {"error": f"内部错误: {exc}", "type": "internal_error"})

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        # -------------------------------------------------- 路由

        def _dispatch(self, method: str, path: str, query: dict[str, list[str]], body: dict[str, Any]) -> Any:
            if method == "GET" and path == "/healthz":
                return {"ok": True, "service": "policy-wave-control"}
            if (method, path) in static_routes:
                return static_routes[(method, path)](body, {})
            if method == "GET" and path == "/api/audit":
                limit = int(query["limit"][0]) if query.get("limit") else None
                prefix = query["action_prefix"][0] if query.get("action_prefix") else None
                return {"entries": service.read_audit(limit=limit, action_prefix=prefix)}

            parts = [p for p in path.split("/") if p]
            # /api/...
            if len(parts) >= 3 and parts[:2] == ["api", "policies"]:
                policy_id = parts[2]
                if method == "GET" and len(parts) == 4 and parts[3] == "preflight":
                    return service.preflight(policy_id, at=_parse_dt(query.get("at", [None])[0])).to_dict()
            if len(parts) >= 3 and parts[:2] == ["api", "exceptions"]:
                exc_id = parts[2]
                if method == "POST" and parts[3:] == ["renew"]:
                    return service.renew_exception(
                        exc_id,
                        new_until=_parse_dt(body["new_until"]),
                        actor=body.get("actor", "operator"),
                        reason=body.get("reason", ""),
                    ).to_dict()
                if method == "POST" and parts[3:] == ["revoke"]:
                    return service.revoke_exception(exc_id, actor=body.get("actor", "operator")).to_dict()
            if len(parts) >= 3 and parts[:2] == ["api", "rollouts"]:
                return self._rollout_dispatch(method, parts[2], parts[3:], query, body)
            raise DomainError(f"未找到路由: {method} {path}")

        def _rollout_dispatch(
            self, method: str, rollout_id: str, tail: list[str],
            query: dict[str, list[str]], body: dict[str, Any],
        ) -> Any:
            if method == "GET" and not tail:
                return service.status(rollout_id)
            if method == "POST" and tail == ["approve"]:
                return {
                    "approval": service.approve(
                        rollout_id,
                        batch_index=int(body["batch_index"]),
                        role=body["role"],
                        actor=body.get("actor", "operator"),
                        comment=body.get("comment", ""),
                    ).to_dict()
                }
            if method == "POST" and tail == ["dispatch"]:
                return service.dispatch_batch(
                    rollout_id,
                    batch_index=body.get("batch_index"),
                    actor=body.get("actor", "dispatcher"),
                )
            if method == "POST" and tail == ["receipts"]:
                return service.receive_receipt(
                    rollout_id,
                    command_id=body["command_id"],
                    revision=int(body["revision"]),
                    claimed_state=body["claimed_state"],
                    produced_at=_parse_dt(body.get("produced_at")),
                )
            if method == "POST" and tail == ["evidence"]:
                return service.adopt_evidence(
                    rollout_id,
                    batch_index=int(body["batch_index"]),
                    metric=body["metric"],
                    value=float(body["value"]),
                    source=body.get("source", "observer"),
                    actor=body.get("actor", "observer"),
                )
            if method == "GET" and tail == ["gate"]:
                return service.gate_status(
                    rollout_id, int(query["batch_index"][0])
                )
            if method == "POST" and tail == ["advance"]:
                return service.advance(rollout_id, actor=body.get("actor", "operator"))
            if method == "POST" and tail == ["pause"]:
                return service.pause(
                    rollout_id, actor=body.get("actor", "operator"),
                    reason=body.get("reason", "manual pause"),
                )
            if method == "POST" and tail == ["resume"]:
                return service.resume(rollout_id, actor=body.get("actor", "operator"))
            if method == "POST" and tail == ["rollback-plan"]:
                return service.create_rollback_plan(
                    rollout_id, reason=body.get("reason", "operator rollback"),
                    actor=body.get("actor", "operator"),
                ).to_dict()
            if method == "POST" and tail == ["rollback"]:
                return service.execute_rollback(rollout_id, actor=body.get("actor", "operator"))
            if method == "POST" and tail == ["rollback-retry"]:
                return service.retry_rollback(rollout_id, actor=body.get("actor", "operator"))
            raise DomainError(f"未找到发布单操作: {method} {'/'.join(tail)}")

    return Handler


def serve(service: ReleaseService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(service))
    return server


def main() -> None:
    import argparse

    from ..composition import build_service

    parser = argparse.ArgumentParser(description="融合网络安全策略分波发布系统 HTTP 接口")
    parser.add_argument("--data-dir", default="./.runtime/data")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    service = build_service(args.data_dir)
    recovery = service.recover()
    server = serve(service, host=args.host, port=args.port)
    print(f"服务已启动: http://{args.host}:{args.port}  数据目录: {args.data_dir}")
    print(f"启动恢复: {json.dumps(recovery, ensure_ascii=False)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
