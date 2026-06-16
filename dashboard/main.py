#!/usr/bin/env python3
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pathlib import Path
import json
import requests
import subprocess
from datetime import datetime, timedelta
import secrets
from auth import AuthManager

app = FastAPI(title="SentinelSpawn Command Center")
templates = Jinja2Templates(directory="templates")
auth = AuthManager()
ALERT_TIME_DISPLAY_LENGTH = 19
ALERT_SIGNATURE_DISPLAY_LENGTH = 60

# Mount static files
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    return request.url.scheme == "https" or forwarded_proto == "https"


def _clear_expired_sessions() -> None:
    now = datetime.utcnow()
    for session_id, session in list(auth.sessions.items()):
        if session.get("expires_at", now) <= now:
            auth.sessions.pop(session_id, None)
    for challenge_id, challenge in list(auth.pending_mfa.items()):
        if challenge.get("expires_at", now) <= now:
            auth.pending_mfa.pop(challenge_id, None)


def get_current_user(request: Request):
    _clear_expired_sessions()
    session_id = request.cookies.get("session_id")
    session = auth.sessions.get(session_id) if session_id else None
    if not session:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return session

@app.get("/")
async def root():
    # Send visitors who hit the bare root to the setup page. When an admin
    # already exists, /setup itself forwards on to /login.
    return RedirectResponse("/setup")

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if auth.has_admin():
        return RedirectResponse("/login")
    return templates.TemplateResponse("setup.html", {"request": request})

@app.post("/setup")
async def create_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    if password != confirm_password:
        return templates.TemplateResponse("setup.html", {
            "request": request, "error": "Passwords do not match"
        })
    if len(password) < 12:
        return templates.TemplateResponse("setup.html", {
            "request": request, "error": "Password must be at least 12 characters"
        })

    try:
        qr_uri = auth.create_admin(username, password)
        return templates.TemplateResponse("setup_complete.html", {
            "request": request, "qr_uri": qr_uri, "username": username
        })
    except Exception as e:
        return templates.TemplateResponse("setup.html", {"request": request, "error": str(e)})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not auth.has_admin():
        return RedirectResponse("/setup")
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    user = auth.verify_password(username, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        })

    challenge_id = secrets.token_urlsafe(32)
    auth.pending_mfa[challenge_id] = {
        "username": user["username"],
        "requires_password_change": user["requires_password_change"],
        "expires_at": datetime.utcnow() + timedelta(minutes=5)
    }
    return templates.TemplateResponse("mfa.html", {
        "request": request,
        "username": user["username"],
        "challenge_id": challenge_id
    })

@app.post("/login/mfa")
async def mfa_verify(
    request: Request,
    challenge_id: str = Form(...),
    totp_code: str = Form(...)
):
    _clear_expired_sessions()
    challenge = auth.pending_mfa.get(challenge_id)
    if challenge and auth.verify_totp(challenge["username"], totp_code):
        auth.pending_mfa.pop(challenge_id, None)
        session_id = secrets.token_urlsafe(32)
        auth.sessions[session_id] = {
            "username": challenge["username"],
            "requires_password_change": challenge["requires_password_change"],
            "expires_at": datetime.utcnow() + timedelta(hours=1)
        }
        response = RedirectResponse("/dashboard", status_code=302)
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            max_age=3600,
            secure=_is_secure_request(request),
            samesite="lax",
        )
        return response
    return templates.TemplateResponse("mfa.html", {
        "request": request,
        "username": challenge["username"] if challenge else "",
        "challenge_id": challenge_id,
        "error": "Invalid credentials or TOTP code"
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(get_current_user)):
    if user.get("requires_password_change"):
        return RedirectResponse("/change-password", status_code=302)

    stats = {}
    stats_file = Path("/app/notifier/stats.json")
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
        except Exception:
            pass

    adguard_stats = {"blocked": 0, "dns_queries": 0}
    try:
        r = requests.get("http://adguardhome/control/stats", timeout=3)
        if r.status_code == 200:
            data = r.json()
            adguard_stats["blocked"] = data.get("num_blocked_filtered", 0)
            adguard_stats["dns_queries"] = data.get("num_dns_queries", 0)
    except Exception:
        pass

    recent_alerts = []
    try:
        result = subprocess.run(["tail", "-n", "100", "/var/log/suricata/eve.json"], 
                               capture_output=True, text=True, timeout=5)
        for line in result.stdout.strip().split("\n"):
            if '"alert"' in line:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        signature = event.get("alert", {}).get("signature", "Unknown")
                        if len(signature) > ALERT_SIGNATURE_DISPLAY_LENGTH:
                            signature = signature[:ALERT_SIGNATURE_DISPLAY_LENGTH] + "..."
                        recent_alerts.append({
                            "time": event.get("timestamp", "")[:ALERT_TIME_DISPLAY_LENGTH],
                            "signature": signature,
                            "src_ip": event.get("src_ip", "N/A"),
                            "dest_ip": event.get("dest_ip", "N/A")
                        })
                except Exception:
                    continue
    except Exception:
        pass

    wg_peers = 0
    try:
        result = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=3)
        wg_peers = len([l for l in result.stdout.splitlines() if "peer" in l.lower()])
    except Exception:
        pass

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user["username"],
        "stats": stats,
        "adguard": adguard_stats,
        "recent_alerts": recent_alerts[:12],
        "wg_peers": wg_peers,
        "now": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    })


@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "user": user["username"]
    })


@app.post("/change-password")
async def change_password_post(
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(get_current_user)
):
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user["username"],
            "error": "Passwords do not match"
        })
    if len(new_password) < 12:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user["username"],
            "error": "Password must be at least 12 characters"
        })

    auth.change_password(user["username"], new_password)
    session_id = request.cookies.get("session_id")
    if session_id and session_id in auth.sessions:
        auth.sessions[session_id]["requires_password_change"] = False
    return RedirectResponse("/dashboard", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        auth.sessions.pop(session_id, None)
    response = RedirectResponse("/login")
    response.delete_cookie("session_id")
    return response

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
