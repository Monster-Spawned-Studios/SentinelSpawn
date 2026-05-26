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
from datetime import datetime
from auth import AuthManager

app = FastAPI(title="SentinelSpawn Command Center")
templates = Jinja2Templates(directory="templates")
auth = AuthManager()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in auth.sessions:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return auth.sessions[session_id]

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
    # First stage: username + password. MFA on next page.
    # For simplicity we do full verification on /mfa
    return templates.TemplateResponse("mfa.html", {
        "request": request,
        "username": username,
        "password": password  # passed temporarily for verification (not stored)
    })

@app.post("/login/mfa")
async def mfa_verify(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(...)
):
    if auth.verify_login(username, password, totp_code):
        session_id = secrets.token_urlsafe(32)
        auth.sessions[session_id] = username
        response = RedirectResponse("/dashboard", status_code=302)
        response.set_cookie(key="session_id", value=session_id, httponly=True, max_age=3600)
        return response
    return templates.TemplateResponse("mfa.html", {
        "request": request,
        "username": username,
        "password": password,
        "error": "Invalid credentials or TOTP code"
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_user)):
    stats = {}
    stats_file = Path("/app/notifier/stats.json")
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
        except:
            pass

    adguard_stats = {"blocked": 0, "dns_queries": 0}
    try:
        r = requests.get("http://adguardhome/control/stats", timeout=3)
        if r.status_code == 200:
            data = r.json()
            adguard_stats["blocked"] = data.get("num_blocked_filtered", 0)
            adguard_stats["dns_queries"] = data.get("num_dns_queries", 0)
    except:
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
                        recent_alerts.append({
                            "time": event.get("timestamp", "")[:19],
                            "signature": event.get("alert", {}).get("signature", "Unknown")[:50],
                            "src_ip": event.get("src_ip", "N/A"),
                            "dest_ip": event.get("dest_ip", "N/A")
                        })
                except:
                    continue
    except:
        pass

    wg_peers = 0
    try:
        result = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=3)
        wg_peers = len([l for l in result.stdout.splitlines() if "peer" in l.lower()])
    except:
        pass

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "stats": stats,
        "adguard": adguard_stats,
        "recent_alerts": recent_alerts[:12],
        "wg_peers": wg_peers,
        "now": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    })

@app.get("/logout")
async def logout():
    response = RedirectResponse("/login")
    response.delete_cookie("session_id")
    return response

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
