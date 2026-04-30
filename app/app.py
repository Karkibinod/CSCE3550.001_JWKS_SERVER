from __future__ import annotations

import os
import sqlite3
import base64
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI()
hasher = PasswordHasher()
RAW_AES_KEY = os.environ.get("NOT_MY_KEY")

if not RAW_AES_KEY:
    raise RuntimeError("Environment variable NOT_MY_KEY is required. Do not commit secrets.")

AES_KEY = RAW_AES_KEY.encode("utf-8").ljust(32, b"\0")[:32]
BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = str(BASE_DIR / "totally_not_my_privateKeys.db")

def encrypt_data(data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(data: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# datbase connection helper 
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

#initilize database and create table if not exists
def init_db() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

#convert primary key to PEM format for storage
def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

#convert PEM back to private key object
def pem_to_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None)

#generate RSA key
def generate_key(expires_at: datetime) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

#store in database
def store_key(private_key: rsa.RSAPrivateKey, expires_at: datetime) -> None:
    pem  = private_key_to_pem(private_key)
    encryoted_pem = encrypt_data(pem)
    exp_timestamp = int(expires_at.timestamp())
    conn = get_db_connection()
    curser = conn.cursor()
    curser.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (encryoted_pem, exp_timestamp),
    )
    conn.commit()
    conn.close()


#seed database 
def seed_keys_if_needed() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    conn.close()

    if count == 0:
        now = datetime.now(timezone.utc)

        store_key(generate_key(now + timedelta(hours=1)), now + timedelta(hours=1))
        store_key(generate_key(now - timedelta(hours=1)), now - timedelta(hours=1))

# JWKS helpers


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

@app.on_event("startup")
def startup_event() -> None:
    init_db()
    seed_keys_if_needed()

# Routes (RESTful API)

@app.api_route("/.well-known/jwks.json", methods=["GET", "POST", "HEAD", "OPTIONS"])
def jwks() -> dict[str, Any]:
    now = int(datetime.now(timezone.utc).timestamp())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()

    keys: list[dict[str, Any]] = []


    for row in rows:
        decrypted_pem = decrypt_data(row["key"]) # Decrypt here
        private_key = pem_to_private_key(decrypted_pem)
        public_key = private_key.public_key()
        keys.append(rsa_public_key_to_jwk(public_key, str(row["kid"])))


    return {"keys": keys}


@app.post("/auth")
async def auth(request: Request) -> JSONResponse:
    now = int(datetime.now(timezone.utc).timestamp())
    use_expired = "expired" in request.query_params

    request_ip = request.client.host if request.client else "unknown"

    conn = get_db_connection()
    cursor = conn.cursor()

    if use_expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()

    if row is None:
        conn.close()
        return JSONResponse({"error": "No suitable key found"}, status_code=404)

    decrypted_pem = decrypt_data(row["key"])
    private_key = pem_to_private_key(decrypted_pem)

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": row["exp"],
        "iss": "jwks-server",
        "aud": "test-client",
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )

    cursor.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, None)
    )

    conn.commit()
    conn.close()

    return JSONResponse({"token": token}, status_code=200)


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


@app.post("/register")
async def register(request: Request) -> JSONResponse:
    data = await request.json()

    username = data.get("username")
    email = data.get("email")

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    password = str(uuid.uuid4())
    password_hash = hasher.hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists"
        )

    conn.close()

    return JSONResponse({"password": password}, status_code=201)



@app.api_route("/health", methods=["GET", "POST", "HEAD", "OPTIONS"])
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"}, status_code=200)


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "jwks-server"}
