import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────

AUTH_FILE = "/data/auth"
CONFIG_FILE = "/data/config.json"
NGINX_LOG = "/var/log/nginx/access.log"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8


def get_jwt_secret() -> str:
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    secret = cfg.get("jwt_secret_key")
    if not secret:
        raise RuntimeError("jwt_secret_key missing from config.json")
    return secret


def load_users() -> dict:
    """Return {username: {"password": ..., "role": ...}}"""
    users = {}
    with open(AUTH_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            username = parts[0]
            password = parts[1]
            role = parts[2] if len(parts) >= 3 else "user"
            users[username] = {"password": password, "role": role}
    return users


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Visitor Tracker", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


# ── Auth helpers ──────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


def create_token(username: str, role: str) -> str:
    secret = get_jwt_secret()
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    secret = get_jwt_secret()
    try:
        return jwt.decode(token, secret, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_token(creds.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return payload


# ── Log parsing ───────────────────────────────────────────────────────────────

def parse_log(limit: int = 200) -> list[dict]:
    """Read nginx JSON access log, newest-first."""
    entries = []
    try:
        with open(NGINX_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    # Skip malformed lines (e.g. during format transition)
                    continue
    except FileNotFoundError:
        return []

    entries.reverse()
    return entries[:limit]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/login")
def login(req: LoginRequest):
    users = load_users()
    user = users.get(req.username)
    if user is None or user["password"] != req.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_token(req.username, user["role"])
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.get("/api/visitors")
def visitors(limit: int = 200, _: dict = Depends(require_admin)):
    return {"visitors": parse_log(limit), "limit": limit}


@app.get("/api/stats")
def stats(_: dict = Depends(require_admin)):
    entries = parse_log(limit=100_000)

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    unique_ips: set[str] = set()
    today_count = 0

    for e in entries:
        ip = e.get("ip", "")
        if ip:
            unique_ips.add(ip)
        t = e.get("time", "")
        if t.startswith(today_str):
            today_count += 1

    return {
        "total_requests": len(entries),
        "unique_ips": len(unique_ips),
        "today_visits": today_count,
    }
