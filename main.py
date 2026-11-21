import os, re, hmac, hashlib, secrets, time, json, base64
from datetime import datetime, timezone
from typing import Optional
import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app = FastAPI(title="Stormy License API", version="1.0.0")

def db():
    return psycopg.connect(DATABASE_URL)

def key_hash(value: str) -> str:
    return hashlib.sha256(value.strip().upper().encode()).hexdigest()

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_token(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = b64(raw)
    sig = hmac.new(TOKEN_SECRET, body.encode(), hashlib.sha256).digest()
    return body + "." + b64(sig)

def read_token(token: str) -> dict:
    try:
        body, signature = token.split(".", 1)
        expected = b64(hmac.new(TOKEN_SECRET, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception:
        raise HTTPException(401, "Invalid or expired license token")

def require_admin(value: Optional[str]):
    if not value or not hmac.compare_digest(value, ADMIN_SECRET):
        raise HTTPException(401, "Admin authentication failed")

@app.on_event("startup")
def startup():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key_hash TEXT PRIMARY KEY,
            label TEXT NOT NULL DEFAULT '',
            expires_at BIGINT,
            hwid_hash TEXT,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at BIGINT NOT NULL
        )
        """)
        conn.commit()

class CreateKey(BaseModel):
    duration_days: Optional[int] = Field(default=30, ge=1, le=36500)
    label: str = Field(default="", max_length=80)

class ActivateRequest(BaseModel):
    license_key: str = Field(min_length=8, max_length=100)
    hwid: str = Field(min_length=16, max_length=256)

class VerifyRequest(BaseModel):
    token: str
    hwid: str = Field(min_length=16, max_length=256)

@app.get("/")
def home():
    return {"service": "Stormy License API", "status": "online"}

@app.get("/health")
def health():
    with db() as conn:
        conn.execute("SELECT 1")
    return {"ok": True}

@app.post("/admin/keys")
def create_key(data: CreateKey, x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    raw_key = "STORMY-" + secrets.token_hex(12).upper()
    expires = None if data.duration_days is None else int(time.time()) + data.duration_days * 86400
    with db() as conn:
        conn.execute(
            "INSERT INTO licenses (key_hash,label,expires_at,created_at) VALUES (%s,%s,%s,%s)",
            (key_hash(raw_key), data.label, expires, int(time.time()))
        )
        conn.commit()
    return {"license_key": raw_key, "duration_days": data.duration_days, "note": "Copy this key now; it is not stored in readable form."}

@app.post("/admin/revoke")
def revoke_key(license_key: str, x_admin_secret: Optional[str] = Header(default=None)):
    require_admin(x_admin_secret)
    with db() as conn:
        cur = conn.execute("UPDATE licenses SET revoked=TRUE WHERE key_hash=%s", (key_hash(license_key),))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Key not found")
    return {"revoked": True}

@app.post("/activate")
def activate(data: ActivateRequest):
    kh = key_hash(data.license_key)
    hh = hashlib.sha256(data.hwid.encode()).hexdigest()
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT expires_at, hwid_hash, revoked FROM licenses WHERE key_hash=%s",
            (kh,)
        ).fetchone()
        if not row:
            raise HTTPException(403, "Invalid license key")
        expires_at, bound_hwid, revoked = row
        if revoked:
            raise HTTPException(403, "License revoked")
        if expires_at is not None and expires_at < now:
            raise HTTPException(403, "License expired")
        if bound_hwid and not hmac.compare_digest(bound_hwid, hh):
            raise HTTPException(403, "License is already activated on another device")
        if not bound_hwid:
            conn.execute("UPDATE licenses SET hwid_hash=%s WHERE key_hash=%s", (hh, kh))
            conn.commit()
    exp = min(expires_at, now + TOKEN_TTL_SECONDS) if expires_at else now + TOKEN_TTL_SECONDS
    token = make_token({"kh": kh, "hw": hh, "exp": exp})
    return {"ok": True, "token": token, "expires_at": exp}

@app.post("/verify")
def verify(data: VerifyRequest):
    payload = read_token(data.token)
    hh = hashlib.sha256(data.hwid.encode()).hexdigest()
    if not hmac.compare_digest(payload.get("hw", ""), hh):
        raise HTTPException(403, "Device mismatch")
    with db() as conn:
        row = conn.execute(
            "SELECT expires_at, hwid_hash, revoked FROM licenses WHERE key_hash=%s",
            (payload.get("kh"),)
        ).fetchone()
    if not row:
        raise HTTPException(403, "License not found")
    expires_at, bound_hwid, revoked = row
    if revoked or not bound_hwid or not hmac.compare_digest(bound_hwid, hh):
        raise HTTPException(403, "License inactive")
    now = int(time.time())
    if expires_at is not None and expires_at < now:
        raise HTTPException(403, "License expired")
    return {"ok": True, "valid_until": expires_at}
