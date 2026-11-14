
import os
import hmac
import json
import time
import base64
import hashlib

from safemail.policy_engine import (
    evaluate_email_action,
    BLOCK,
    REQUIRE_HUMAN_REVIEW
)
from safemail.audit import record_event


class GatewayError(Exception):
    """Raised when an email execution is denied or fails."""
    pass


# =========================================================
# TOKEN HELPERS
# =========================================================

def _decode_base64url(value):
    """Decode URL-safe Base64, including omitted padding."""

    if not isinstance(value, str) or not value:
        raise GatewayError("Invalid authorization token encoding.")

    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise GatewayError("Invalid authorization token encoding.") from exc


def _verify_authorization_token(
    token,
    recipient,
    subject,
    body,
    secret
):
    """
    Verify the administrator-issued HMAC authorization.

    Token format:
        base64url(json_claims).base64url(hmac_signature)
    """

    if not isinstance(secret, str) or len(secret) < 32:
        raise GatewayError("Gateway signing key is missing or invalid.")

    if not isinstance(token, str):
        raise GatewayError("Authorization token must be a string.")

    parts = token.split(".")

    if len(parts) != 2:
        raise GatewayError("Malformed authorization token.")

    payload_part, signature_part = parts

    # Verify the HMAC before trusting any claims.
    supplied_signature = _decode_base64url(signature_part)

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_part.encode("ascii"),
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(
        supplied_signature,
        expected_signature
    ):
        raise GatewayError("Authorization signature is invalid.")

    # Decode claims only after signature verification.
    try:
        payload_bytes = _decode_base64url(payload_part)
        claims = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise GatewayError("Invalid authorization claims.") from exc

    if not isinstance(claims, dict):
        raise GatewayError("Invalid authorization claims.")

    required_claims = {
        "iss",
        "aud",
        "request_id",
        "recipient",
        "subject",
        "body_sha256",
        "iat",
        "exp",
        "jti"
    }

    if not required_claims.issubset(claims):
        raise GatewayError("Authorization claims are incomplete.")

    # Verify issuer and intended gateway.
    if claims["iss"] != "safemail-approval-service":
        raise GatewayError("Untrusted authorization issuer.")

    if claims["aud"] != "safemail-email-gateway":
        raise GatewayError("Authorization audience mismatch.")

    # Validate claim types.
    for field in (
        "request_id",
        "recipient",
        "subject",
        "body_sha256",
        "jti"
    ):
        if not isinstance(claims[field], str) or not claims[field]:
            raise GatewayError(f"Invalid authorization field: {field}")

    for field in ("iat", "exp"):
        if (
            not isinstance(claims[field], int)
            or isinstance(claims[field], bool)
        ):
            raise GatewayError(f"Invalid authorization timestamp: {field}")

    # Validate issue and expiration times.
    now = int(time.time())

    if claims["iat"] > now + 30:
        raise GatewayError("Authorization issue time is in the future.")

    if claims["exp"] <= now:
        raise GatewayError("Authorization has expired.")

    if claims["exp"] <= claims["iat"]:
        raise GatewayError("Invalid authorization lifetime.")

    if claims["exp"] - claims["iat"] > 300:
        raise GatewayError("Authorization lifetime exceeds the allowed limit.")

    # Bind authorization to the exact email recipient and subject.
    if not hmac.compare_digest(
        claims["recipient"],
        recipient
    ):
        raise GatewayError("Recipient does not match approved content.")

    if not hmac.compare_digest(
        claims["subject"],
        subject
    ):
        raise GatewayError("Subject does not match approved content.")

    # Bind authorization to the exact email body.
    expected_body_hash = hashlib.sha256(
        body.encode("utf-8")
    ).hexdigest()

    if not hmac.compare_digest(
        claims["body_sha256"],
        expected_body_hash
    ):
        raise GatewayError("Email body was modified after approval.")

    return claims


# =========================================================
# SECURE EMAIL GATEWAY
# =========================================================

def execute_approved_email(
    approval,
    recipient,
    subject,
    body,
    secret=None,
    db_path="safemail/approvals.db",
    from_header=None,
    reply_to_header=None,
    send_function=None
):
    """
    Execute an email only after administrator authorization.

    Security workflow:
      1. Evaluate deterministic security policy.
      2. Verify administrator-issued HMAC signature.
      3. Verify issuer, audience and expiration.
      4. Verify exact recipient, subject and body.
      5. Resolve the email sending function.
      6. Atomically consume the stored authorization hash.
      7. Send the email exactly once.

    The authorization database is managed by approval_service.storage.
    db_path is retained for compatibility with the audit logger.
    """

    # -----------------------------------------------------
    # STEP 1: Validate email inputs
    # -----------------------------------------------------

    if not all(
        isinstance(value, str) and value.strip()
        for value in (recipient, subject, body)
    ):
        raise GatewayError("Recipient, subject and body are required.")

    # -----------------------------------------------------
    # STEP 2: Apply deterministic security policy
    # -----------------------------------------------------

    policy_result = evaluate_email_action(
        recipient=recipient,
        subject=subject,
        body=body,
        from_header=from_header,
        reply_to_header=reply_to_header
    )

    if policy_result["decision"] == BLOCK:
        record_event(
            "POLICY_BLOCKED",
            db_path=db_path,
            details={
                "reason_codes": policy_result.get("reasons", [])
            }
        )

        raise GatewayError(
            "Email blocked by security policy: "
            + "; ".join(policy_result.get("reasons", []))
        )

    if policy_result["decision"] != REQUIRE_HUMAN_REVIEW:
        raise GatewayError("Unexpected policy decision.")

    # -----------------------------------------------------
    # STEP 3: Verify administrator-issued authorization
    # -----------------------------------------------------

    if secret is None:
        secret = os.getenv("SAFEMAIL_SIGNING_KEY")

    claims = _verify_authorization_token(
        token=approval,
        recipient=recipient,
        subject=subject,
        body=body,
        secret=secret
    )

    request_id = claims["request_id"]

    # Hash the complete token exactly as the approval service did.
    token_hash = hashlib.sha256(
        approval.encode("utf-8")
    ).hexdigest()

    # -----------------------------------------------------
    # STEP 4: Resolve sender before consuming authorization
    # -----------------------------------------------------

    if send_function is None:
        from tools.email_tools import send_email
        send_function = send_email

    # -----------------------------------------------------
    # STEP 5: Atomically consume authorization
    # -----------------------------------------------------

    try:
        from approval_service.storage import consume_authorization

        consume_result = consume_authorization(
            request_id,
            token_hash
        )

        if isinstance(consume_result, tuple):
            consumed = bool(consume_result[0])
            consume_message = (
                consume_result[1]
                if len(consume_result) > 1
                else "Authorization could not be consumed."
            )
        else:
            consumed = bool(consume_result)
            consume_message = "Authorization is invalid, expired or already used."

        if not consumed:
            raise GatewayError(consume_message)

    except GatewayError:
        raise

    except Exception as exc:
        raise GatewayError(
            "Authorization storage verification failed. "
            "Email sending was blocked."
        ) from exc

    # -----------------------------------------------------
    # STEP 6: Send the exact approved email
    # -----------------------------------------------------

    try:
        send_result = send_function(
            recipient,
            subject,
            body
        )

    except Exception as exc:
        record_event(
            "EMAIL_SEND_FAILED",
            db_path=db_path,
            details={
                "request_id": request_id,
                "error_type": type(exc).__name__
            }
        )

        raise GatewayError(
            "Email sending failed or its outcome is uncertain. "
            "Authorization has already been consumed. "
            "Do not retry automatically; check Gmail Sent first."
        ) from exc

    # -----------------------------------------------------
    # STEP 7: Extract Gmail message ID
    # -----------------------------------------------------

    message_id = None

    if isinstance(send_result, dict):
        message_id = send_result.get("message_id")

    record_event(
        "EMAIL_SEND_SUCCEEDED",
        db_path=db_path,
        details={
            "request_id": request_id,
            "message_id": message_id
        }
    )

    # -----------------------------------------------------
    # STEP 8: Return execution result
    # -----------------------------------------------------

    return {
        "status": "SENT",
        "recipient": recipient,
        "subject": subject,
        "message_id": message_id,
        "request_id": request_id,
        "message": "Email execution completed successfully."
    }
