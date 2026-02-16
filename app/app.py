from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# -----------------------
# App setup
# -----------------------

app = FastAPI()

# -----------------------
# Key management
# -----------------------


class KeyPair:
    def __init__(self, kid: str, private_key: rsa.RSAPrivateKey, expires_at: datetime) -> None:
        self.kid = kid
        self.private_key = private_key
        self.expires_at = expires_at

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at <= now


def generate_key(expires_at: datetime) -> KeyPair:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = secrets.token_hex(16)
    return KeyPair(kid=kid, private_key=priv, expires_at=expires_at)


# Generate keys on startup 
_now = datetime.now(timezone.utc)
ACTIVE_KEY = generate_key(expires_at=_now + timedelta(hours=1))
EXPIRED_KEY = generate_key(expires_at=_now - timedelta(hours=1))

# -----------------------
# JWKS helpers
# -----------------------


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\x00"
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def rsa_public_key_to_jwk(pub: rsa.RSAPublicKey, kid: str) -> dict[str, Any]:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


# -----------------------
# Routes (RESTful API)
# -----------------------

@app.api_route("/.well-known/jwks.json", methods=["GET", "POST", "HEAD", "OPTIONS"])
def jwks() -> dict[str, Any]:
    """
    Return JWKS containing ONLY unexpired public keys.
    """
    now = datetime.now(timezone.utc)
    keys: list[dict[str, Any]] = []

    # Only serve unexpired keys
    if not ACTIVE_KEY.is_expired(now):
        keys.append(rsa_public_key_to_jwk(ACTIVE_KEY.private_key.public_key(), ACTIVE_KEY.kid))

    return {"keys": keys}


@app.post("/auth")
async def auth(request: Request) -> JSONResponse:
    """
    POST /auth               -> issue JWT signed with active key (unexpired)
    POST /auth?expired=true  -> issue JWT signed with expired key and expired exp
    No request body required (per rubric).
    """
    now = datetime.now(timezone.utc)
    use_expired = "expired" in request.query_params  # presence check

    kp = EXPIRED_KEY if use_expired else ACTIVE_KEY

    payload = {
        "sub": "fake-user",
        "iat": int(now.timestamp()),
        "exp": int(kp.expires_at.timestamp()),  # expired when using expired key
        "iss": "jwks-server",
        "aud": "test-client",
    }

    token = jwt.encode(
        payload,
        kp.private_key,
        algorithm="RS256",
        headers={"kid": kp.kid},  # IMPORTANT: include kid in header
    )

    return JSONResponse({"token": token})


# connect with different methods - public endpoint
@app.api_route("/connect", methods=["GET", "POST", "HEAD", "OPTIONS"])
def connect() -> JSONResponse:
    return JSONResponse(
        {
            "service": "jwks-server",
            "status": "ok",
            "endpoints": {
                "jwks": "/.well-known/jwks.json",
                "auth": "/auth",
                "auth_expired": "/auth?expired=true",
            },
        },
        status_code=200,
    )



@app.api_route("/health", methods=["GET", "POST", "HEAD", "OPTIONS"])
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"}, status_code=200)


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "jwks-server"}
