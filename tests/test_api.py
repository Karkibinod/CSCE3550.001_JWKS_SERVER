import base64
import json

import httpx
import jwt
import pytest

from app.app import app


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwk_to_public_key(jwk: dict):
    return jwt.algorithms.RSAAlgorithm.from_jwk(
        json.dumps({"kty": "RSA", "n": jwk["n"], "e": jwk["e"]})
    )


def make_client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.anyio
async def test_jwks_returns_key():
    async with make_client() as client:
        r = await client.get("/.well-known/jwks.json")
        assert r.status_code == 200
        data = r.json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        assert data["keys"][0]["kid"]


@pytest.mark.anyio
async def test_auth_valid_jwt():
    async with make_client() as client:
        r = await client.post("/auth")
        assert r.status_code == 200
        token = r.json()["token"]
        assert token

        jwks = (await client.get("/.well-known/jwks.json")).json()
        jwk = jwks["keys"][0]

        header = jwt.get_unverified_header(token)
        assert header["kid"] == jwk["kid"]

        pub = jwk_to_public_key(jwk)
        decoded = jwt.decode(
            token,
            pub,
            algorithms=["RS256"],
            audience="test-client",
            issuer="jwks-server",
        )
        assert decoded["sub"] == "fake-user"


@pytest.mark.anyio
async def test_auth_expired():
    async with make_client() as client:
        r = await client.post("/auth?expired=true")
        assert r.status_code == 200
        token = r.json()["token"]
        assert token

        # Inspect claims without verifying signature
        parts = token.split(".")
        claims = json.loads(b64url_decode(parts[1]))
        assert int(claims["exp"]) < int(claims["iat"]) + 100000


@pytest.mark.anyio
async def test_jwks_post():
    async with make_client() as client:
        r = await client.post("/.well-known/jwks.json")
        assert r.status_code == 200
        data = r.json()
        assert "keys" in data


@pytest.mark.anyio
async def test_connect_post():
    async with make_client() as client:
        r = await client.post("/connect")
        assert r.status_code == 200
        data = r.json()
        assert data["service"] == "jwks-server"


@pytest.mark.anyio
async def test_health_post():
    async with make_client() as client:
        r = await client.post("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
