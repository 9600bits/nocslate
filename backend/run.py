from __future__ import annotations

import argparse
import multiprocessing
import threading
import webbrowser

import uvicorn

from app.main import app


def main() -> None:
    multiprocessing.freeze_support()
    ap = argparse.ArgumentParser(description="Packet Lens 抓包分析工具")
    ap.add_argument("--port", type=int, default=8321)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = ap.parse_args()
    url = f"http://{args.host}:{args.port}"
    if not args.no_browser:
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    print(f"Packet Lens 运行于 {url} （Ctrl+C 退出）")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
