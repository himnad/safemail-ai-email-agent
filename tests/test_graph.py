import os
from unittest.mock import Mock, patch

from graph.email_agent_graph import (
    email_agent_graph,
    triage_email,
    generate_reply,
    handle_fyi,
    handle_action,
    send_approved_email,
    human_review,
)

from safemail.policy_engine import REQUIRE_HUMAN_REVIEW


# =========================================================
# TEST CONFIGURATION
# =========================================================

def base_state():
    return {
        "email": """
FROM: test@example.com
SUBJECT: Meeting confirmation

BODY:

Hello,

Can you please confirm whether you are available
for the meeting tomorrow?

Regards,
Test User
""",
        "sender": "test@example.com",
        "reply_to": "",
        "original_subject": "Meeting confirmation",
        "category": "",
        "response": "",
        "recipient": "",
        "subject": "",
        "draft_body": "",
        "review_status": "",
        "request_id": "",
    }


def fake_llm_response(text):
    fake_llm = Mock()
    fake_llm.invoke.return_value = Mock(content=text)
    return fake_llm


def valid_draft_state():
    state = base_state()
    state.update({
        "recipient": "test@example.com",
        "subject": "Re: Meeting confirmation",
        "draft_body": "Yes, I am available.",
    })
    return state


def approved_policy():
    return {
        "decision": REQUIRE_HUMAN_REVIEW,
        "reasons": []
    }


# =========================================================
# TRIAGE TESTS
# =========================================================

def test_triage_needs_reply():
    with patch(
        "graph.email_agent_graph.llm",
        fake_llm_response("NEEDS_REPLY")
    ):
        result = triage_email(base_state())

    assert result["category"] == "NEEDS_REPLY"


def test_triage_fyi():
    with patch(
        "graph.email_agent_graph.llm",
        fake_llm_response("FYI")
    ):
        result = triage_email(base_state())

    assert result["category"] == "FYI"
