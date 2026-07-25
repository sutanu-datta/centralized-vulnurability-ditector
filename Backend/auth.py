import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from fastapi import Header, HTTPException
from database import get_conn


SECRET_KEY = "change-this-secret-key-for-production"
TOKEN_EXPIRY_SECONDS = 60 * 60 * 24


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return base64.b64encode(salt + key).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        raw = base64.b64decode(stored_hash.encode())
        salt = raw[:16]
        stored_key = raw[16:]
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(user_id: int, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "nonce": secrets.token_hex(8),
    }

    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signature = hmac.new(
        SECRET_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    return payload_b64 + "." + b64url_encode(signature)


def verify_token(token: str) -> dict:
    try:
        payload_b64, signature_b64 = token.split(".", 1)

        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).digest()

        actual_signature = b64url_decode(signature_b64)

        if not hmac.compare_digest(expected_signature, actual_signature):
            raise HTTPException(status_code=401, detail="Invalid token.")

        payload = json.loads(b64url_decode(payload_b64).decode())

        if payload["exp"] < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expired.")

        return payload

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token.")


def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header.")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format.")

    token = authorization.replace("Bearer ", "").strip()
    payload = verify_token(token)

    conn = get_conn()
    user = conn.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?",
        (payload["user_id"],)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    return dict(user)