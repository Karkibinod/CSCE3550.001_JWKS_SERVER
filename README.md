# JWKS Server (Project 3)

SQLite-backed JWKS/JWT authentication service with encrypted private key storage, user registration, and request logging.

## Screenshots

- Gradebot result: `ss/Project 3 SS /Gradebot3.png`
- Test coverage: `ss/Project 3 SS /Coverage3.png`

## Features

- **AES-256 Encryption**: Private keys encrypted in the database using a secure encryption key
- **User Registration**: Register users with secure Argon2 password hashing
- **Authentication Logging**: Track all auth requests with IP, timestamp, and user ID
- **Rate Limiting** (Optional): Limit auth requests to prevent abuse (10 requests/second)
- **Key Expiry**: Automatic expiration handling for RSA key pairs
- **SQL Injection Prevention**: All database queries use parameterized statements
- **JWKS Compliance**: Standard JSON Web Key Set format for public key distribution

## Security

- Private keys are encrypted at rest using AES-256
- Passwords are hashed using Argon2 (never stored in plaintext)
- Environment variable `NOT_MY_KEY` required—**never commit secrets**
- Parameterized SQL queries prevent injection attacks

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

**Required**: Set the `NOT_MY_KEY` environment variable before starting the server (used for AES-256 key encryption).

The database (`totally_not_my_privateKeys.db`) is created and initialized on startup.

## API Endpoints

### POST `/register`
Register a new user with secure password generation.

**Request:**
```json
{"username": "john_doe", "email": "john@example.com"}
```

**Response:**
```json
{"password": "550e8400-e29b-41d4-a716-446655440000"}
```

HTTP Status: `200 OK` or `201 Created`

### POST `/auth`
Authenticate and receive a signed JWT.

**Query Parameters:**
- `expired=true` (optional): Sign with an expired key for testing

**Response:**
```json
{"token": "eyJhbGc..."}
```

Logs request to `auth_logs` table (IP, timestamp, user ID).

### GET `/.well-known/jwks.json`
Retrieve public keys in JWKS format (non-expired keys only).

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### GET `/health`
Health check endpoint.

## Testing

```bash
python -m coverage run -m pytest --disable-warnings -q
python -m coverage report -m
```

## Database Schema

The server automatically creates these tables on startup:

- `keys`: RSA private keys (encrypted)
- `users`: User accounts with hashed passwords
- `auth_logs`: Authentication request logs

## Dependencies

- **FastAPI**: Web framework
- **Uvicorn**: ASGI server
- **PyJWT**: JWT handling
- **cryptography**: RSA and AES encryption
- **argon2-cffi**: Secure password hashing
- **slowapi** (optional): Rate limiting
