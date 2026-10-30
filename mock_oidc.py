"""Synthetic OIDC / RFC 8693 provider for isolated load tests. NOT production auth."""
import base64
import hashlib
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse

app = FastAPI(title="ATLAS Synthetic OIDC", version="0.1.0")
ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8001").rstrip("/")
CLIENT = os.getenv("OIDC_CLIENT_ID", "atlas-loadtest")
SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
ACCESS_TTL = int(os.getenv("OIDC_ACCESS_TTL", "300"))
REFRESH_TTL = int(os.getenv("OIDC_REFRESH_TTL", "3600"))
AUDIENCES = set(os.getenv("OIDC_ALLOWED_AUDIENCES", "atlas,mock-litellm,mock-mcp").split(","))
KEY_FILE = os.getenv("OIDC_PRIVATE_KEY_FILE", "")
if KEY_FILE:
    PRIVATE_KEY = serialization.load_pem_private_key(Path(KEY_FILE).read_bytes(), password=None)
else:
    PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
nums = PUBLIC_KEY.public_numbers()

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def uint(value):
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))

JWK = {"kty": "RSA", "alg": "RS256", "use": "sig", "n": uint(nums.n), "e": uint(nums.e)}
KID = b64u(hashlib.sha256(str(nums.n).encode()).digest()[:12])
JWK["kid"] = KID

# Ephemeral, per-process storage: run one IdP instance unless you add a shared store.
codes = {}
refreshes = {}

def issue(subject, audience="atlas", scope="openid profile", ttl=ACCESS_TTL, token_type="access"):
    now = int(time.time())
    claims = {
        "iss": ISSUER, "sub": subject, "aud": audience, "iat": now,
        "nbf": now, "exp": now + ttl, "jti": secrets.token_hex(12),
        "scope": scope, "preferred_username": subject,
        "groups": ["atlas-load-test"], "token_type": token_type,
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})

def decode(token, audience=None):
    try:
        return jwt.decode(
            token, PUBLIC_KEY, algorithms=["RS256"], issuer=ISSUER,
            audience=audience, options={"verify_aud": audience is not None},
            leeway=5,
        )
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid_token")

def client_auth(form):
    if form.get("client_id") != CLIENT or (SECRET and form.get("client_secret") != SECRET):
        raise HTTPException(401, "invalid_client")

def bundle(subject, scope="openid profile"):
    refresh = secrets.token_urlsafe(48)
    refreshes[refresh] = (subject, scope, time.time() + REFRESH_TTL)
    return {
        "access_token": issue(subject, scope=scope),
        "id_token": issue(subject, audience=CLIENT, scope=scope, token_type="id"),
        "refresh_token": refresh, "token_type": "Bearer",
        "expires_in": ACCESS_TTL, "scope": scope,
    }

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token", "jwks_uri": ISSUER + "/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code", "refresh_token", "password",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }

@app.get("/jwks")
def jwks():
    return {"keys": [JWK]}

@app.get("/.well-known/jwks.json")
def jwks_alias():
    return jwks()

@app.get("/authorize")
def authorize(response_type: str, client_id: str, redirect_uri: str,
              code_challenge: str, code_challenge_method: str = "S256",
              scope: str = "openid profile", state: str = "",
              login_hint: str = "loaduser-0001"):
    # Deliberate test-only auto-login; redirect URI must be controlled by caller.
    if response_type != "code" or client_id != CLIENT or code_challenge_method != "S256":
        raise HTTPException(400, "invalid_request")
    if not login_hint.startswith("loaduser-"):
        raise HTTPException(400, "synthetic users must start with loaduser-")
    code = secrets.token_urlsafe(32)
    codes[code] = (login_hint, redirect_uri, code_challenge, scope, time.time() + 90)
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(redirect_uri + sep + urlencode({"code": code, "state": state}))

@app.post("/token")
async def token(request: Request):
    form = dict(await request.form())
    client_auth(form)
    grant = form.get("grant_type")
    if grant == "password":
        user = form.get("username", "")
        if not user.startswith("loaduser-") or form.get("password") != "test":
            raise HTTPException(401, "invalid_grant")
        return bundle(user, form.get("scope", "openid profile"))
    if grant == "authorization_code":
        item = codes.pop(form.get("code", ""), None)
        if not item:
            raise HTTPException(400, "invalid_grant")
        user, redirect_uri, challenge, scope, expiry = item
        verifier = form.get("code_verifier", "")
        calculated = b64u(hashlib.sha256(verifier.encode()).digest())
        if expiry < time.time() or redirect_uri != form.get("redirect_uri") or challenge != calculated:
            raise HTTPException(400, "invalid_grant")
        return bundle(user, scope)
    if grant == "refresh_token":
        old = form.get("refresh_token", "")
        item = refreshes.pop(old, None)
        if not item or item[2] < time.time():
            raise HTTPException(400, "invalid_grant")
        return bundle(item[0], item[1])
    if grant == "urn:ietf:params:oauth:grant-type:token-exchange":
        if form.get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token":
            raise HTTPException(400, "invalid_request")
        subject = decode(form.get("subject_token", ""), audience=None)
        if subject.get("token_type") != "access":
            raise HTTPException(400, "invalid_grant")
        audience = form.get("audience", "mock-litellm")
        if audience not in AUDIENCES:
            raise HTTPException(400, "invalid_target")
        scope = form.get("scope", subject.get("scope", "openid profile"))
        return {
            "access_token": issue(subject["sub"], audience=audience, scope=scope),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer", "expires_in": ACCESS_TTL, "scope": scope,
        }
    raise HTTPException(400, "unsupported_grant_type")
