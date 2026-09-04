"""Per-launch protection for the localhost web application."""

from __future__ import annotations

import hashlib
import secrets
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse


SESSION_COOKIE = "nocslate_session"
CSRF_COOKIE = "nocslate_csrf"


def enable(app) -> str:
    launch_token = secrets.token_urlsafe(32)
    app.state.local_security_enabled = True
    app.state.launch_token_hash = hashlib.sha256(launch_token.encode()).hexdigest()
    app.state.session_token = secrets.token_urlsafe(32)
    app.state.csrf_token = secrets.token_urlsafe(24)
    return launch_token


def _valid_launch(app, token: str) -> bool:
    if not token:
        return False
    expected = getattr(app.state, "launch_token_hash", "")
    return secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected)


def _loopback_origin(request: Request) -> bool:
    origin = request.headers.get("origin", "")
    if not origin:
        return True
    try:
        return (urlparse(origin).hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
    except ValueError:
        return False


async def middleware(request: Request, call_next):
    app = request.app
    if not getattr(app.state, "local_security_enabled", False):
        return await call_next(request)
    token = request.query_params.get("token", "")
    if request.method == "GET" and token and _valid_launch(app, token):
        response = RedirectResponse(request.url.path or "/", status_code=302)
        response.set_cookie(SESSION_COOKIE, app.state.session_token, httponly=True, samesite="strict")
        response.set_cookie(CSRF_COOKIE, app.state.csrf_token, httponly=False, samesite="strict")
        return response
    if request.url.path.startswith("/api/"):
        session = request.cookies.get(SESSION_COOKIE, "")
        if not secrets.compare_digest(session, getattr(app.state, "session_token", "!")):
            return JSONResponse({"detail": "本次 NOCSlate 会话已失效，请从程序重新打开页面"}, status_code=401)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf = request.headers.get("x-csrf-token", "")
            if not _loopback_origin(request) or not secrets.compare_digest(
                csrf, getattr(app.state, "csrf_token", "!")
            ):
                return JSONResponse({"detail": "请求来源验证失败"}, status_code=403)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response
