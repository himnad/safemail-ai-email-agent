"""Trusted approval-service token issuance. Never import this module in the agent."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from approval_service.storage import get_request, store_authorization

TOKEN_TTL_SECONDS = 300


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def issue_signed_authorization(request_id: str, *, signing_key=None) -> str:
    """Issue and register one content-bound token for an approved request.

    This must be called only by a trusted approval-service code path after
    authenticated admin approval. It does not authenticate the caller itself.
    """
    if signing_key is None:
        signing_key = os.environ.get("SAFEMAIL_SIGNING_KEY")
    if not isinstance(signing_key, str) or len(signing_key) < 32:
        raise ValueError("SAFEMAIL_SIGNING_KEY must have at least 32 characters")
    request = get_request(request_id)
    if request is None or request["status"] != "APPROVED":
        raise ValueError("Only approved requests can be authorized")
    recipient, subject, body = (request[k] for k in ("recipient", "subject", "body"))
    if not all(isinstance(v, str) and v.strip() for v in (request_id, recipient, subject, body)):
        raise ValueError("Invalid approved email")
    now = int(time.time())
    claims = {
        "iss": "safemail-approval-service",
        "aud": "safemail-email-gateway",
        "request_id": request_id,
        "recipient": recipient,
        "subject": subject,
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(32),
    }
    payload = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(hmac.new(signing_key.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    token = f"{payload}.{signature}"
    success, message = store_authorization(request_id, hashlib.sha256(token.encode("utf-8")).hexdigest(), ttl_seconds=TOKEN_TTL_SECONDS)
    if not success:
        raise ValueError(message)
    return token
