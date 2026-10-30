"""Small OpenAI-compatible mock with delegated JWT verification and streaming."""
import asyncio
import json
import os
import time
import uuid

import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

app = FastAPI(title="ATLAS Mock LiteLLM", version="0.1.0")
ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8001").rstrip("/")
AUDIENCE = os.getenv("MOCK_LLM_AUDIENCE", "mock-litellm")
MODEL = os.getenv("MOCK_LLM_MODEL", "mock-model")
TOKENS = int(os.getenv("MOCK_LLM_TOKENS", "100"))
DELAY = float(os.getenv("MOCK_LLM_TOKEN_DELAY_MS", "40")) / 1000
START_DELAY = float(os.getenv("MOCK_LLM_START_DELAY_MS", "100")) / 1000
JWKS = PyJWKClient(ISSUER + "/jwks", cache_jwk_set=True, lifespan=300)

class Chat(BaseModel):
    model: str = MODEL
    messages: list[dict] = Field(default_factory=list)
    stream: bool = False
    max_tokens: int | None = None

def verify(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing_bearer")
    token = authorization.removeprefix("Bearer ")
    try:
        key = JWKS.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER, audience=AUDIENCE, leeway=5)
    except (jwt.PyJWTError, Exception) as exc:
        raise HTTPException(401, "invalid_token") from exc

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/v1/models")
def models(authorization: str | None = Header(default=None)):
    verify(authorization)
    return {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "load-test"}]}

@app.post("/v1/chat/completions")
async def completions(body: Chat, authorization: str | None = Header(default=None)):
    identity = verify(authorization)
    if body.model != MODEL:
        raise HTTPException(404, "model_not_found")
    n = max(1, min(body.max_tokens or TOKENS, 4096))
    request_id = "chatcmpl-" + uuid.uuid4().hex
    created = int(time.time())
    # Deterministic filler, not language generation; each chunk approximates one token.
    answer = " ".join(["load"] * n)
    base = {"id": request_id, "object": "chat.completion.chunk", "created": created, "model": MODEL}

    if not body.stream:
        await asyncio.sleep(START_DELAY + n * DELAY)
        return {
            "id": request_id, "object": "chat.completion", "created": created,
            "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(1, len(str(body.messages)) // 4), "completion_tokens": n,
                      "total_tokens": max(1, len(str(body.messages)) // 4) + n},
        }

    async def events():
        await asyncio.sleep(START_DELAY)
        def event(delta, finish=None):
            return "data: " + json.dumps({**base, "choices": [
                {"index": 0, "delta": delta, "finish_reason": finish}
            ]}) + "\\n\\n"
        yield event({"role": "assistant", "content": ""})
        for _ in range(n):
            await asyncio.sleep(DELAY)
            yield event({"content": " load"})
        yield event({}, "stop")
        yield "data: [DONE]\\n\\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
