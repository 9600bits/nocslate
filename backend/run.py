from __future__ import annotations

import argparse
import multiprocessing
import threading
import webbrowser
import sys
from urllib.parse import quote

import uvicorn

from app.main import app
from app.local_auth import enable as enable_local_security
from app import config


def main() -> None:
    multiprocessing.freeze_support()
    ap = argparse.ArgumentParser(description="NOCSlate 本地网络运维与安全工作台")
    ap.add_argument("--port", type=int, default=8321)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = ap.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        ap.error("基础设施与凭据功能仅允许监听本机回环地址（127.0.0.1、::1 或 localhost）")
    url = f"http://{args.host}:{args.port}"
    launch_token = enable_local_security(app)
    if getattr(sys, "frozen", False):
        config.migrate_legacy_key()
    boot_url = f"{url}/?token={quote(launch_token)}"
    if not args.no_browser:
        threading.Timer(1.2, webbrowser.open, args=(boot_url,)).start()
    print(f"NOCSlate 运行于 {url} （Ctrl+C 退出）")
    print(f"本次安全访问地址：{boot_url}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
