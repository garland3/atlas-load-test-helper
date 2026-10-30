# ATLAS load-test helpers

Two deliberately **non-production** FastAPI services for horizontal-scaling experiments:

- `mock_oidc.py`: synthetic OIDC issuer, JWKS, authorization-code + PKCE, refresh, password-grant shortcut for load generators, and RFC 8693 token exchange.
- `mock_litellm.py`: OpenAI-compatible `/v1/chat/completions` streaming/non-streaming mock, `/v1/models`, and JWT validation against the synthetic issuer.

These simulate **real RSA signing and verification**, not static bearer-token bypasses. They **do not implement the full Microsoft Entra or LiteLLM Enterprise protocols**; adapt claims, audiences, headers, and exchange parameters to ATLAS's actual integration before using as a faithful end-to-end benchmark.

## Quick start

Python 3.11+:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# terminal 1
OIDC_ISSUER=http://localhost:8001 uvicorn mock_oidc:app --host 127.0.0.1 --port 8001
# terminal 2
OIDC_ISSUER=http://localhost:8001 uvicorn mock_litellm:app --host 127.0.0.1 --port 8002
```

Synthetic password-grant login (convenient for k6; **not a production OIDC practice**):

```bash
TOKEN=$(curl -fsS -X POST http://localhost:8001/token \
  -d 'grant_type=password' -d 'client_id=atlas-loadtest' \
  -d 'username=loaduser-0001' -d 'password=test' | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# RFC 8693 exchange: produce a delegated audience-specific token.
DELEGATED=$(curl -fsS -X POST http://localhost:8001/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'client_id=atlas-loadtest' \
  -d "subject_token=$TOKEN" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d 'audience=mock-litellm' | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -fsS http://localhost:8002/v1/chat/completions \
  -H "Authorization: Bearer $DELEGATED" -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"hello"}],"stream":false}'
```

For streamed output set `"stream":true` and add `-N` to curl.


## Docker

One image runs either service, selected with `APP_MODULE`. Both need the same `OIDC_ISSUER`, which must be resolvable by the mock LiteLLM container and by ATLAS.

```bash
docker build -t atlas-load-helper .
docker network create atlas-load-net

docker run -d --name mock-oidc --network atlas-load-net -p 8001:8000 \
  -e OIDC_ISSUER=http://mock-oidc:8000 \
  atlas-load-helper

docker run -d --name mock-litellm --network atlas-load-net -p 8002:8000 \
  -e APP_MODULE=mock_litellm \
  -e OIDC_ISSUER=http://mock-oidc:8000 \
  atlas-load-helper
```

The IdP is reachable from the host at `http://localhost:8001` and the LLM mock at `http://localhost:8002`. JWT issuer and JWKS URLs use `http://mock-oidc:8000`, so any ATLAS instance validating these tokens must resolve that hostname (e.g., join the Docker network or use an appropriately configured DNS address). For production-like load testing, provide a mounted persistent signing key via `OIDC_PRIVATE_KEY_FILE` and use an isolated test network.

## Configuration

| Variable | Default | Use |
|---|---|---|
| `OIDC_ISSUER` | `http://localhost:8001` | Must be identical in both services and match the URL clients use |
| `OIDC_CLIENT_ID` | `atlas-loadtest` | Accepted test client |
| `OIDC_CLIENT_SECRET` | empty | Optional shared client secret for token endpoint |
| `OIDC_PRIVATE_KEY_FILE` | empty | PEM RSA private key; required for stable tokens across multiple IdP replicas/restarts |
| `OIDC_ACCESS_TTL` | `300` | Access token life in seconds |
| `OIDC_REFRESH_TTL` | `3600` | Refresh token life in seconds |
| `OIDC_ALLOWED_AUDIENCES` | `atlas,mock-litellm,mock-mcp` | Comma-separated audiences allowed on exchange |
| `MOCK_LLM_AUDIENCE` | `mock-litellm` | Expected delegated JWT audience |
| `MOCK_LLM_MODEL` | `mock-model` | Exposed model name |
| `MOCK_LLM_TOKENS` | `100` | Simulated output tokens |
| `MOCK_LLM_TOKEN_DELAY_MS` | `40` | Delay per streamed token |
| `MOCK_LLM_START_DELAY_MS` | `100` | Delay before generation |

Check `http://localhost:8001/.well-known/openid-configuration` and `http://localhost:8001/jwks` for discovery and keys.

## Integrating ATLAS

Configure ATLAS's **test instance only** to accept the synthetic issuer and configure its downstream delegated-token audience as `mock-litellm`. Point the OpenAI-compatible model base URL to `http://<mock-host>:8002/v1`. Exact ATLAS Entra OBO/LiteLLM-specific flow and config switches may need adapters; the generic RFC 8693 endpoint does **not** automatically replace Entra's on-behalf-of grant.

For steady-state replica benchmarks, pre-create user tokens and stagger renewals. For identity stress tests, include login, refresh, and token-exchange traffic and measure the IdP separately from ATLAS.

## Limitations and safety

**Never expose these services to the public internet or use for production auth.** Any synthetic `loaduser-*` identity can authenticate with the test password and the `/authorize` shortcut deliberately skips human authentication. Keep the issuer, clients, and keys isolated; do not register this issuer as trusted by production ATLAS. In-memory authorization codes and refresh tokens are single-process only; use a shared store to scale the IdP itself. Generated signing keys change on restart unless `OIDC_PRIVATE_KEY_FILE` is set. DPoP, consent, real MFA, enterprise conditional-access policies, and actual LLM inference costs are not simulated.
