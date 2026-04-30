import os
os.environ.setdefault("NOT_MY_KEY", "test-secret-key-for-pytest")

import base64
import json

import httpx
import jwt
import pytest

from app.app import app
import app.app as app_module


@pytest.fixture
def anyio_backend():
    return "asyncio"


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


def _set_temp_db(monkeypatch, tmp_path):
    """Point the app at an isolated temp database for a test."""
    temp_db = tmp_path / "test.db"
    monkeypatch.setattr(app_module, "DB_FILE", str(temp_db))
    return temp_db


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


def test_startup_event_seeds_keys(monkeypatch, tmp_path):
    _set_temp_db(monkeypatch, tmp_path)
    app_module.startup_event()

    conn = app_module.get_db_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    finally:
        conn.close()

    assert count == 2


def test_seed_keys_idempotent(monkeypatch, tmp_path):
    _set_temp_db(monkeypatch, tmp_path)
    app_module.init_db()
    app_module.seed_keys_if_needed()
    app_module.seed_keys_if_needed()  # second call should not add more rows

    conn = app_module.get_db_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    finally:
        conn.close()

    assert count == 2


@pytest.mark.anyio
async def test_auth_returns_404_when_no_keys(monkeypatch, tmp_path):
    _set_temp_db(monkeypatch, tmp_path)
    app_module.init_db()  # don't seed keys

    async with make_client() as client:
        r = await client.post("/auth")
        assert r.status_code == 404
        assert r.json()["error"] == "No suitable key found"


@pytest.mark.anyio
async def test_root_endpoint(monkeypatch, tmp_path):
    # Use isolated DB to avoid depending on local state
    _set_temp_db(monkeypatch, tmp_path)
    app_module.startup_event()

    async with make_client() as client:
        r = await client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["service"] == "jwks-server"
