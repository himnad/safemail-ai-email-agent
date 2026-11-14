"""Offline, no-Gmail tests for the new signed-token gateway protocol."""
import pytest
from approval_service import storage
from approval_service.signed_tokens import issue_signed_authorization
from safemail.gateway import execute_approved_email, GatewayError

KEY = "test-only-strong-signing-key-1234567890"
RECIPIENT = "manager@company.com"
SUBJECT = "Meeting"
BODY = "I confirm my availability."


@pytest.fixture
def approved(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "approvals.db")
    storage.initialize_database()
    rid = storage.create_request(RECIPIENT, SUBJECT, BODY, ttl_seconds=600)
    assert storage.decide_request(rid, "APPROVED")[0]
    return rid


def _send(token, sent, *, recipient=RECIPIENT, subject=SUBJECT, body=BODY, key=KEY):
    return execute_approved_email(
        approval=token, recipient=recipient, subject=subject, body=body,
        secret=key, from_header=RECIPIENT,
        send_function=lambda *args: sent.append(args) or {"message_id": "mock-id"},
    )


def test_signed_token_sends_once(approved):
    token = issue_signed_authorization(approved, signing_key=KEY)
    sent = []
    assert _send(token, sent)["status"] == "SENT"
    assert len(sent) == 1
    with pytest.raises(GatewayError):
        _send(token, sent)
    assert len(sent) == 1


@pytest.mark.parametrize("change", ["recipient", "subject", "body", "key"])
def test_modified_claims_never_send(approved, change):
    token = issue_signed_authorization(approved, signing_key=KEY)
    sent = []
    changes = {"recipient": "attacker@example.com", "subject": "Altered", "body": "Altered body", "key": "another-strong-signing-key-123456789"}
    with pytest.raises(GatewayError):
        _send(token, sent, **{change: changes[change]})
    assert sent == []


def test_forged_token_never_sends(approved):
    token = issue_signed_authorization(approved, signing_key=KEY)
    sent = []
    payload, signature = token.split(".")
    forged = payload + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(GatewayError):
        _send(forged, sent)
    assert sent == []


def test_unapproved_request_cannot_issue(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "approvals.db")
    storage.initialize_database()
    rid = storage.create_request(RECIPIENT, SUBJECT, BODY)
    with pytest.raises(ValueError):
        issue_signed_authorization(rid, signing_key=KEY)
