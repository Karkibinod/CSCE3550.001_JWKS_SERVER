# JWKS Server

A simple JSON Web Key Set (JWKS) server that generates RSA key pairs and issues digitally signed JWTs (JSON Web Tokens).

## What This Does

This server provides two main features:

1. **Key Management**: Generates RSA cryptographic key pairs, each with a unique ID and expiration time
2. **JWT Issuance**: Creates and signs JSON Web Tokens that can be verified using the public keys

## Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone or download this project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

```bash
uvicorn app.app:app --host 0.0.0.0 --port 8080
```

The server will start on `http://localhost:8080`

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
pytest tests/ -v --cov=app --cov-report=term-missing
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
- Full test coverage

## Dependencies

- **FastAPI**: Modern web framework for building APIs
- **Uvicorn**: ASGI server to run the app
- **PyJWT**: JWT token creation and verification
- **cryptography**: RSA key generation and management
