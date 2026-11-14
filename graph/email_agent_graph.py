
import re
from email.utils import parseaddr
from typing import TypedDict

from dotenv import load_dotenv

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from agent.llm import llm

from approval_service.storage import (
    initialize_database,
    create_request
)

from safemail.policy_engine import (
    evaluate_email_action,
    BLOCK,
    REQUIRE_HUMAN_REVIEW
)

load_dotenv()


# =========================================================
# STATE
# =========================================================

class EmailAgentState(TypedDict, total=False):
    email: str
    sender: str
    reply_to: str
    original_subject: str

    category: str
    response: str

    recipient: str
    subject: str
    draft_body: str

    review_status: str
    request_id: str
    error_message: str


# =========================================================
# EMAIL CLASSIFICATION
# =========================================================

def triage_email(state: EmailAgentState):

    prompt = f"""
You are an email triage assistant.

Classify the following email into exactly one category:

NEEDS_REPLY
FYI
ACTION_NEEDED

NEEDS_REPLY: Sender expects a response.
FYI: Informational email; no response required.
ACTION_NEEDED: User must perform an action.

Return only the category name.

Email:
{state["email"]}
"""

    try:
        result = llm.invoke(prompt)
        category = result.content.strip().upper()

        if category not in {
            "NEEDS_REPLY",
            "FYI",
            "ACTION_NEEDED"
        }:
            raise ValueError(
                f"Invalid AI classification: {category}"
            )

        return {
            "category": category,
            "error_message": ""
        }

    except Exception as e:
        return {
            "category": "AI_ERROR",
            "error_message": str(e)
        }


def route_email(state: EmailAgentState):

    category = state.get("category")

    if category == "NEEDS_REPLY":
        return "reply"

    if category == "ACTION_NEEDED":
        return "action"

    if category == "AI_ERROR":
        return "error"

    return "fyi"


# =========================================================
# GENERATE REPLY
# =========================================================

def generate_reply(state: EmailAgentState):

    sender = state.get("sender", "")
    recipient = parseaddr(sender)[1]

    # Never guess the recipient from email body.
    if (
        not recipient
        or "@" not in recipient
        or "\n" in recipient
        or "\r" in recipient
    ):
        return {
            "category": "AI_ERROR",
            "error_message": "Invalid sender email address.",
            "response": (
                "Reply recipient could not be identified."
            )
        }

    # Extract original subject.
    original_subject = (
        state.get("original_subject") or ""
    ).strip()

    if not original_subject:

        match = re.search(
            r"^SUBJECT:\s*(.+)$",
            state.get("email", ""),
            flags=re.IGNORECASE | re.MULTILINE
        )

        if match:
            original_subject = match.group(1).strip()

    if not original_subject:
        original_subject = "Email"

    # Avoid Re: Re: duplication.
    reply_subject = (
        original_subject
        if original_subject.lower().startswith("re:")
        else f"Re: {original_subject}"
    )

    prompt = f"""
You are a professional email assistant.

Write a concise, polite reply to this email.

Rules:
- Do not invent facts or commitments.
- Do not promise meetings, payments, or actions.
- Do not include a subject line.
- Return only the email body.

Email:
{state["email"]}
"""

    try:
        result = llm.invoke(prompt)
        draft_body = result.content.strip()

        if not draft_body:
            raise ValueError(
                "AI generated an empty reply."
            )

        return {
            "recipient": recipient,
            "subject": reply_subject,
            "draft_body": draft_body,
            "response": draft_body,
            "error_message": ""
        }

    except Exception as e:
        return {
            "category": "AI_ERROR",
            "error_message": str(e),
            "response": "Reply generation failed."
        }


# =========================================================
# FYI EMAIL
# =========================================================

def handle_fyi(state: EmailAgentState):

    return {
        "category": "FYI",
        "response": (
            "This email is informational and "
            "does not require a reply."
        )
    }


# =========================================================
# ACTION NEEDED
# =========================================================

def handle_action(state: EmailAgentState):

    prompt = f"""
Explain what action the user needs to take.

Do not perform the action.
Do not invent missing information.

Email:
{state["email"]}
"""

    try:
        result = llm.invoke(prompt)

        return {
            "category": "ACTION_NEEDED",
            "response": result.content.strip()
        }

    except Exception as e:
        return {
            "category": "AI_ERROR",
            "error_message": str(e),
            "response": "Action analysis failed."
        }


# =========================================================
# AI ERROR HANDLER
# =========================================================

def handle_ai_error(state: EmailAgentState):

    return {
        "category": "AI_ERROR",
        "response": (
            "AI processing failed. "
            "No email was sent."
        )
    }


# =========================================================
# INDEPENDENT ADMIN APPROVAL REQUEST
# =========================================================

def human_review(state: EmailAgentState):
    """
    Submit the generated email for independent
    administrator approval.

    The AI agent cannot approve its own email.
    The AI agent cannot issue authorization.
    This function never sends an email.
    """

    recipient = state.get("recipient", "")
    subject = state.get("subject", "")
    body = state.get("draft_body", "")
    sender = state.get("sender", "")
    reply_to = state.get("reply_to")

    # Validate email content.
    if not all(
        isinstance(value, str) and value.strip()
        for value in (recipient, subject, body)
    ):
        return {
            "category": "SEND_BLOCKED",
            "review_status": "rejected",
            "request_id": "",
            "error_message": (
                "Recipient, subject and body are required."
            ),
            "response": (
                "Invalid email draft. "
                "No request was created."
            )
        }

    # Apply security policy before creating request.
    policy = evaluate_email_action(
        recipient=recipient,
        subject=subject,
        body=body,
        from_header=sender,
        reply_to_header=reply_to
    )

    if policy["decision"] == BLOCK:

        return {
            "category": "SEND_BLOCKED",
            "review_status": "rejected",
            "request_id": "",
            "error_message": "; ".join(
                policy.get("reasons", [])
            ),
            "response": (
                "Email blocked by security policy. "
                "No request was created."
            )
        }

    if policy["decision"] != REQUIRE_HUMAN_REVIEW:

        return {
            "category": "SEND_BLOCKED",
            "review_status": "rejected",
            "request_id": "",
            "error_message": "Unexpected policy decision.",
            "response": (
                "Email was not submitted for approval."
            )
        }

    # Create pending request in approval service database.
    try:

        initialize_database()

        request_id = create_request(
            recipient=recipient,
            subject=subject,
            body=body,
            ttl_seconds=300
        )

        return {
            "category": "PENDING_APPROVAL",
            "review_status": "pending",
            "request_id": request_id,
            "response": (
                "Email submitted for independent "
                "administrator approval. "
                "No authorization has been issued "
                "and no email has been sent."
            )
        }

    except Exception as exc:

        return {
            "category": "SEND_BLOCKED",
            "review_status": "rejected",
            "request_id": "",
            "error_message": str(exc),
            "response": (
                "Approval request creation failed. "
                "No email was sent."
            )
        }


# =========================================================
# ROUTE AFTER REQUEST CREATION
# =========================================================

def route_after_review(state: EmailAgentState):

    # The agent always stops after submitting the request.
    # Sending is not reachable from this graph.
    return "stop"


# =========================================================
# DIRECT SENDING DISABLED
# =========================================================

def send_approved_email(state: EmailAgentState):
    """
    Fail-closed compatibility function.

    Direct sending from the AI agent is disabled.
    A separate trusted gateway workflow must verify
    administrator-issued authorization.
    """

    return {
        "category": "SEND_BLOCKED",
        "review_status": "pending",
        "error_message": (
            "Direct sending from the AI agent is disabled. "
            "Independent administrator authorization "
            "is required."
        ),
        "response": (
            "Email was not sent. It must be approved "
            "through the independent administrator "
            "approval service."
        )
    }


# =========================================================
# BUILD LANGGRAPH
# =========================================================

graph_builder = StateGraph(EmailAgentState)


graph_builder.add_node(
    "triage_email",
    triage_email
)

graph_builder.add_node(
    "generate_reply",
    generate_reply
)

graph_builder.add_node(
    "handle_fyi",
    handle_fyi
)

graph_builder.add_node(
    "handle_action",
    handle_action
)

graph_builder.add_node(
    "handle_ai_error",
    handle_ai_error
)

graph_builder.add_node(
    "human_review",
    human_review
)


# ---------------- START ----------------

graph_builder.add_edge(
    START,
    "triage_email"
)


# ---------------- CLASSIFICATION ROUTING ----------------

graph_builder.add_conditional_edges(
    "triage_email",
    route_email,
    {
        "reply": "generate_reply",
        "fyi": "handle_fyi",
        "action": "handle_action",
        "error": "handle_ai_error"
    }
)


# ---------------- REPLY ROUTING ----------------

graph_builder.add_conditional_edges(
    "generate_reply",
    lambda state: (
        "error"
        if state.get("category") == "AI_ERROR"
        else "review"
    ),
    {
        "review": "human_review",
        "error": "handle_ai_error"
    }
)


# ---------------- APPROVAL REQUEST ROUTING ----------------

graph_builder.add_conditional_edges(
    "human_review",
    route_after_review,
    {
        "stop": END
    }
)


# ---------------- END ROUTES ----------------

graph_builder.add_edge(
    "handle_fyi",
    END
)

graph_builder.add_edge(
    "handle_action",
    END
)

graph_builder.add_edge(
    "handle_ai_error",
    END
)


# =========================================================
# COMPILE LANGGRAPH
# =========================================================

memory = MemorySaver()

email_agent_graph = graph_builder.compile(
    checkpointer=memory
)
