"""本地 HTTP 服务启动入口。

用法：
    python3 -m policy_wave_control.server --data-dir ./runtime_data --port 8080

数据（含发布游标、审计链）全部落在 --data-dir，删除该目录即清空环境。
"""

from __future__ import annotations

import argparse

from .interfaces.http_api import run_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="融合网络安全策略分波发布系统")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default="./runtime_data",
                        help="运行数据目录（JSON 状态 + 追加式审计日志）")
    args = parser.parse_args(argv)

    server = run_server(args.host, args.port, args.data_dir)
    print(f"服务已启动: http://{args.host}:{args.port}  数据目录: {args.data_dir}")
    print("健康检查: GET /health；审计校验: GET /audit/verify")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n收到中断信号，关闭服务（状态已持久化，重启可恢复游标）")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
