# JWKS Server (Project 2)

SQLite-backed JWKS/JWT service with encrypted key storage.

## Features

- RSA private keys persisted in SQLite with AES-256 encryption
- Key expiry support via `exp` unix timestamp
- Unique `kid` per key (SQLite `AUTOINCREMENT`)
- `POST /auth` signs JWT with valid (non-expired) key
- `POST /auth?expired=true` signs JWT with expired key
- `GET/POST /.well-known/jwks.json` returns only unexpired public keys in JWKS format
- Parameterized SQL queries to prevent injection attacks

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
export NOT_MY_KEY="your-secret-key-here"
uvicorn app.app:app --host 127.0.0.1 --port 8080
```

**Required**: Set `NOT_MY_KEY` environment variable before running (used for AES-256 encryption of stored keys).

Database (`totally_not_my_privateKeys.db`) is created automatically on startup.

## API Endpoints

### GET `/.well-known/jwks.json`
Returns the public keys in JWKS format (only non-expired keys).

**Example response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "abc123def456...",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```
### GET `/`
Simple health check endpoint.

### POST `/auth`
Issues a JWT signed with the first non-expired key. Response: `{"token": "<jwt>"}`.

### POST `/auth?expired=true`
Issues a JWT signed with the most recent expired key (useful for testing exp handling).

### GET/POST `/connect`
Service discovery endpoint that returns information about available endpoints and service status.

**Example response:**
```json
{
  "service": "jwks-server",
  "status": "ok",
  "endpoints": {
    "jwks": "/.well-known/jwks.json",
    "auth": "/auth",
    "auth_expired": "/auth?expired=true"
  }
}
```

### GET/POST `/health`
Health check endpoint for monitoring service availability.

**Example response:**
```json
{
  "status": "ok"
}
```

## Running Tests

```bash
.venv/bin/python -m coverage run -m pytest --disable-warnings -q
.venv/bin/python -m coverage report -m
```

This runs the test suite and shows code coverage statistics.

## Project Structure

```
app/
  app.py          - Main server application
  __init__.py     - Package initialization
tests/
  test_api.py     - Test suite
requirements.txt  - Python dependencies
README.md         - This file
```

## How It Works

1. **Key Generation**: On startup, the server creates two RSA key pairs:
   - One active key (expires in 1 hour)
   - One expired key (already expired)

2. **JWKS Endpoint**: When you request `/.well-known/jwks.json`, it returns only the public parts of non-expired keys


## Key Features

- RSA-2048 key generation
- Automatic key expiration handling
- JWKS format compliance
- JWT signing with RS256 algorithm
- Support for expired token testing
- Full test coverage (tests use isolated temp DBs; prod DB untouched)

## Dependencies

- **FastAPI**: Modern web framework for building APIs
- **Uvicorn**: ASGI server to run the app
- **PyJWT**: JWT token creation and verification
- **cryptography**: RSA key generation and management
