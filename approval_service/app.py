
import os
import hmac
from html import escape

from starlette.concurrency import run_in_threadpool
from approval_service.demo_ai import analyze_email
from approval_service.signed_tokens import issue_signed_authorization

from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    PlainTextResponse,
    JSONResponse
)

from approval_service.storage import (
    initialize_database,
    list_pending_requests,
    get_request,
    decide_request
)

from approval_service.security import (
    verify_login_password,
    create_session,
    verify_session,
    verify_csrf_token
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = FastAPI(title="SafeMail Approval Service")

app.mount(
    "/demo-static",
    StaticFiles(directory=Path(__file__).resolve().parent / "static"),
    name="demo-static",
)

SESSION_COOKIE = "safemail_session"
DEMO_COOKIE = "safemail_demo_session"

# Public demo credentials.
# These credentials must ONLY provide simulated access.
DEMO_USERNAME = "interviewer"
DEMO_PASSWORD = "SafeMail-Demo@2026"

COOKIE_SECURE = (
    os.getenv("SAFEMAIL_COOKIE_SECURE", "false").lower() == "true"
)

initialize_database()


# --------------------------------------------------
# DEMO EMAIL DATA
# In-memory sample data. Never connected to Gmail.
# --------------------------------------------------

DEMO_EMAILS = [
    {
        "id": "demo-001",
        "sender": "hr@example.com",
        "subject": "Interview Schedule Confirmation",
        "body": (
            "Hello, your technical interview is scheduled "
            "for Friday at 10 AM. Please confirm your availability."
        ),
        "category": "NEEDS_REPLY",
        "status": "PENDING"
    },
    {
        "id": "demo-002",
        "sender": "newsletter@example.com",
        "subject": "November Product Newsletter",
        "body": (
            "Here are the latest product updates "
            "and announcements for this month."
        ),
        "category": "FYI",
        "status": "PENDING"
    },
    {
        "id": "demo-003",
        "sender": "security@example.com",
        "subject": "Suspicious Login Alert",
        "body": (
            "We detected a suspicious login attempt. "
            "Please review the activity before taking action."
        ),
        "category": "ACTION_NEEDED",
        "status": "PENDING"
    }
]


# --------------------------------------------------
# SESSION HELPERS
# --------------------------------------------------

def get_session(request: Request):
    """Return an administrator session only."""

    token = request.cookies.get(SESSION_COOKIE)
    session = verify_session(token)

    if not session or session.get("role") != "admin":
        return None

    return session


def get_demo_session(request: Request):
    """Return an interviewer demo session only."""

    token = request.cookies.get(DEMO_COOKIE)
    session = verify_session(token)

    if not session or session.get("role") != "demo":
        return None

    return session


# --------------------------------------------------
# HTML PAGE TEMPLATE
# --------------------------------------------------

def page(content):

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeMail Approval Center</title>

        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <style>

            * {{
                box-sizing: border-box;
            }}

            body {{
                font-family: Inter, Arial, sans-serif;
                max-width: 1040px;
                margin: 28px auto;
                padding: 20px;
                background: #f1f5f9;
                color: #172033;
                line-height: 1.55;
            }}

            h1 {{
                color: #172554;
                font-size: 30px;
                letter-spacing: -0.6px;
                margin-bottom: 24px;
            }}

            h2, h3 {{ color: #172554; }}

            .email-card {{
                border: 1px solid #dbe3ef;
                border-radius: 16px;
                padding: 24px;
                transition: box-shadow .18s ease, transform .18s ease;
            }}
            .email-card:hover {{
                box-shadow: 0 10px 28px rgba(15, 23, 42, .08);
                transform: translateY(-1px);
            }}
            .status-pill {{
                display: inline-block;
                border-radius: 999px;
                padding: 5px 10px;
                font-size: 12px;
                font-weight: 700;
                background: #fef3c7;
                color: #92400e;
            }}
            .status-pill.approved {{ background: #dcfce7; color: #166534; }}
            .status-pill.rejected {{ background: #fee2e2; color: #991b1b; }}
            .analysis-panel {{
                margin: 16px 0;
                padding: 18px;
                border-radius: 12px;
                background: #f5f8ff;
                border: 1px solid #d7e3ff;
            }}
            .analysis-panel textarea {{ background: white; }}
            .button-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
            button:disabled {{ opacity: .55; cursor: not-allowed; }}
            .notice {{ margin: 12px 0; color: #475569; font-size: 14px; }}
            .busy {{ opacity: .65; pointer-events: none; }}

            .card {{
                background: white;
                padding: 24px;
                margin-bottom: 20px;
                border-radius: 12px;
                border: 1px solid #e5e7eb;
                box-shadow: 0 2px 8px rgba(0,0,0,0.04);
            }}

            input, textarea {{
                width: 100%;
                padding: 12px;
                margin: 8px 0 15px;
                border: 1px solid #ccc;
                border-radius: 6px;
            }}

            textarea {{
                min-height: 120px;
                resize: vertical;
            }}

            button {{
                padding: 11px 18px;
                margin: 5px 5px 5px 0;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
            }}

            button:hover {{
                opacity: 0.85;
            }}

            .approve {{
                background: #16a34a;
                color: white;
            }}

            .reject {{
                background: #dc2626;
                color: white;
            }}

            .login {{
                background: #2563eb;
                color: white;
            }}

            .badge {{
                display: inline-block;
                padding: 6px 10px;
                background: #dbeafe;
                color: #1e40af;
                border-radius: 20px;
                font-size: 13px;
            }}

            .demo-box {{
                background: #eff6ff;
                border: 1px solid #bfdbfe;
            }}

            .muted {{
                color: #64748b;
            }}

            a {{
                color: #2563eb;
            }}

        </style>
    </head>

    <body>

        <h1>SafeMail Approval Center</h1>

        {content}

        <script src="/demo-static/dashboard.js" defer></script>
    </body>
    </html>
    """


# --------------------------------------------------
# SECURITY HEADERS
# --------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):

    response = await call_next(request)

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "style-src 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )

    return response


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):

    if get_demo_session(request):
        return RedirectResponse(
            "/demo/dashboard",
            status_code=303
        )

    if get_session(request):
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    return RedirectResponse(
        "/login",
        status_code=303
    )


# --------------------------------------------------
# ADMINISTRATOR LOGIN
# --------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page():

    content = """
    <div class="card">

        <h2>Administrator Login</h2>

        <form method="POST" action="/login">

            <label>Administrator Password</label>

            <input
                type="password"
                name="password"
                placeholder="Enter private administrator password"
                required
            >

            <button class="login" type="submit">
                Administrator Login
            </button>

        </form>

    </div>

    <div class="card demo-box">

        <h2>Interviewer Public Demo</h2>

        <p>
            Explore SafeMail using sample emails
            and simulated approval actions.
        </p>

        <p><b>Username:</b> interviewer</p>

        <p><b>Password:</b> SafeMail-Demo@2026</p>

        <p>
            <span class="badge">Public Demo Access</span>
        </p>

        <a href="/demo/login">
            <button class="login">
                Open Interviewer Demo
            </button>
        </a>

        <p class="muted">
            Demo mode uses simulated data only.
            No real emails are sent.
        </p>

    </div>
    """

    return HTMLResponse(page(content))


@app.post("/login")
async def admin_login(password: str = Form(...)):

    if not verify_login_password(password):

        return PlainTextResponse(
            "Invalid administrator password.",
            status_code=401
        )

    session = create_session(role="admin")

    response = RedirectResponse(
        "/dashboard",
        status_code=303
    )

    response.set_cookie(
        SESSION_COOKIE,
        session["session_token"],
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=1800,
        path="/"
    )

    return response


# --------------------------------------------------
# ADMINISTRATOR DASHBOARD
# --------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):

    session = get_session(request)

    if not session:
        return RedirectResponse("/login", status_code=303)

    requests = list_pending_requests()

    content = """
    <div class="card">
        <h2>Administrator Dashboard</h2>

        <span class="badge">Private Administrator Mode</span>

        <p>Pending email approval requests.</p>
    </div>
    """

    if not requests:

        content += """
        <div class="card">
            <p>No pending email requests.</p>
        </div>
        """

    for item in requests:

        rid = escape(item["request_id"])
        recipient = escape(item["recipient"])
        subject = escape(item["subject"])
        body = escape(item["body"])
        csrf = escape(session["csrf_token"])

        content += f"""
        <div class="card">

            <h3>Email Review</h3>

            <p><b>Recipient:</b> {recipient}</p>

            <p><b>Subject:</b> {subject}</p>

            <p><b>Message:</b></p>

            <textarea readonly>{body}</textarea>

            <form method="POST"
                  action="/requests/{rid}/approve">

                <input type="hidden"
                       name="csrf_token"
                       value="{csrf}">

                <button class="approve" type="submit">
                    Approve
                </button>

            </form>

            <form method="POST"
                  action="/requests/{rid}/reject">

                <input type="hidden"
                       name="csrf_token"
                       value="{csrf}">

                <button class="reject" type="submit">
                    Reject
                </button>

            </form>

        </div>
        """

    content += f"""
    <div class="card">

        <form method="POST" action="/logout">

            <input type="hidden"
                   name="csrf_token"
                   value="{escape(session['csrf_token'])}">

            <button type="submit">Logout</button>

        </form>

    </div>
    """

    return HTMLResponse(page(content))


# --------------------------------------------------
# ADMINISTRATOR APPROVE
# --------------------------------------------------

@app.post("/requests/{request_id}/approve")
async def approve(
    request_id: str,
    request: Request,
    csrf_token: str = Form(...)
):

    session = get_session(request)

    if not session:
        return RedirectResponse("/login", status_code=303)

    if not verify_csrf_token(session, csrf_token):

        return PlainTextResponse(
            "CSRF validation failed.",
            status_code=403
        )

    if not get_request(request_id):

        return PlainTextResponse(
            "Request not found.",
            status_code=404
        )

    success, message = decide_request(
        request_id,
        "APPROVED"
    )

    if not success:
        return PlainTextResponse(
            message,
            status_code=409
        )

    try:
        # Issue a signed authorization for the approved request.
        # Never expose the bearer token in the HTML response.
        issue_signed_authorization(request_id)

    except Exception:
        return PlainTextResponse(
            "Approval recorded, but authorization issuance "
            "failed. Administrator intervention is required.",
            status_code=500
        )


    return HTMLResponse(
        page(f"""
        <div class="card">

            <h2>{escape(message)}</h2>

            <p>
                Human approval recorded and signed authorization issued.
                No email has been sent.
            </p>

            <a href="/dashboard">Return to dashboard</a>

        </div>
        """),
        status_code=200 if success else 409
    )


# --------------------------------------------------
# ADMINISTRATOR REJECT
# --------------------------------------------------

@app.post("/requests/{request_id}/reject")
async def reject(
    request_id: str,
    request: Request,
    csrf_token: str = Form(...)
):

    session = get_session(request)

    if not session:
        return RedirectResponse("/login", status_code=303)

    if not verify_csrf_token(session, csrf_token):

        return PlainTextResponse(
            "CSRF validation failed.",
            status_code=403
        )

    if not get_request(request_id):

        return PlainTextResponse(
            "Request not found.",
            status_code=404
        )

    success, message = decide_request(
        request_id,
        "REJECTED"
    )

    return HTMLResponse(
        page(f"""
        <div class="card">

            <h2>{escape(message)}</h2>

            <a href="/dashboard">Return to dashboard</a>

        </div>
        """),
        status_code=200 if success else 409
    )


# --------------------------------------------------
# ADMINISTRATOR LOGOUT
# --------------------------------------------------

@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(...)
):

    session = get_session(request)

    if not session:
        return RedirectResponse("/login", status_code=303)

    if not verify_csrf_token(session, csrf_token):

        return PlainTextResponse(
            "CSRF validation failed.",
            status_code=403
        )

    response = RedirectResponse(
        "/login",
        status_code=303
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict"
    )

    return response


# ==================================================
# PUBLIC INTERVIEWER DEMO
# ==================================================


# --------------------------------------------------
# DEMO LOGIN PAGE
# --------------------------------------------------

@app.get("/demo/login", response_class=HTMLResponse)
async def demo_login_page():

    content = """
    <div class="card">

        <h2>Interviewer Demo Login</h2>

        <p>Explore the SafeMail public demonstration.</p>

        <form method="POST" action="/demo/login">

            <label>Username</label>

            <input
                type="text"
                name="username"
                value="interviewer"
                required
            >

            <label>Password</label>

            <input
                type="password"
                name="password"
                value="SafeMail-Demo@2026"
                required
            >

            <button class="login" type="submit">
                Enter Demo
            </button>

        </form>

    </div>

    <div class="card demo-box">

        <h3>Public Demo Credentials</h3>

        <p><b>Username:</b> interviewer</p>

        <p><b>Password:</b> SafeMail-Demo@2026</p>

        <span class="badge">Simulated Environment</span>

        <p class="muted">
            Sample emails and simulated approval actions.
            No Gmail access or real email sending.
        </p>

    </div>

    <p><a href="/login">Administrator Login</a></p>
    """

    return HTMLResponse(page(content))


# --------------------------------------------------
# DEMO LOGIN ACTION
# --------------------------------------------------

@app.post("/demo/login")
async def demo_login(
    username: str = Form(...),
    password: str = Form(...)
):

    valid_username = hmac.compare_digest(
        username,
        DEMO_USERNAME
    )

    valid_password = hmac.compare_digest(
        password,
        DEMO_PASSWORD
    )

    if not (valid_username and valid_password):

        return PlainTextResponse(
            "Invalid demo credentials.",
            status_code=401
        )

    session = create_session(role="demo")

    response = RedirectResponse(
        "/demo/dashboard",
        status_code=303
    )

    response.set_cookie(
        DEMO_COOKIE,
        session["session_token"],
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=1800,
        path="/"
    )

    return response


# --------------------------------------------------
# DEMO DASHBOARD
# --------------------------------------------------

@app.get("/demo/dashboard", response_class=HTMLResponse)
async def demo_dashboard(request: Request):

    session = get_demo_session(request)

    if not session:
        return RedirectResponse("/demo/login", status_code=303)

    content = f"""
    <div class="card">

        <h2>SafeMail Interviewer Dashboard</h2>

        <span class="badge">Public Demo Mode</span>

        <p>
            Welcome to SafeMail. Explore email classification
            and simulated human approval.
        </p>

        <p><b>Environment:</b> Simulated</p>

        <p><b>Real Gmail connection:</b> Disabled</p>

        <p><b>Real email sending:</b> Disabled</p>

        <form method="POST" action="/demo/logout">

            <input type="hidden"
                   name="csrf_token"
                   value="{escape(session['csrf_token'])}">

            <button type="submit">Logout</button>

        </form>

    </div>
    """

    for email in DEMO_EMAILS:

        email_id = escape(email["id"])
        sender = escape(email["sender"])
        subject = escape(email["subject"])
        body = escape(email["body"])
        analysis = email.get("analysis")
        category_value = (
            analysis.get("category")
            if analysis and analysis.get("analysis_status") == "SUCCESS"
            else email["category"]
        )
        category = escape(str(category_value))
        status = escape(email["status"])
        csrf = escape(session["csrf_token"])

        analysis_html = ""
        if analysis:
            ai_status = escape(str(analysis.get("analysis_status", "UNKNOWN")))
            ai_category = escape(str(analysis.get("category", "AI_ERROR")))
            ai_reason = escape(str(analysis.get("reason", "")))
            ai_action = escape(str(analysis.get("recommended_action", "")))
            ai_reply = escape(str(analysis.get("draft_reply", "")))

            analysis_html = f"""
            <div class="card demo-box">
                <h3>Gemini AI Analysis</h3>
                <p><b>Analysis status:</b> {ai_status}</p>
                <p><b>Classification:</b>
                    <span class="badge">{ai_category}</span>
                </p>
                <p><b>Reason:</b> {ai_reason}</p>
                <p><b>Recommended action:</b> {ai_action}</p>
                <p><b>Suggested reply:</b></p>
                <textarea readonly>{ai_reply}</textarea>
            </div>
            """

        content += f"""
        <div class="card email-card" data-email-id="{email_id}">

            <h3>{subject}</h3>

            <p><b>Sender:</b> {sender}</p>

            <p>
                <b>AI Classification:</b>
                <span class="badge" data-category>{category}</span>
            </p>

            <p><b>Status:</b> <span class="status-pill {status.lower()}" data-status>{status}</span></p>

            <p><b>Email Content:</b></p>

            <textarea readonly>{body}</textarea>

            <form method="POST" data-ajax="true"
                  action="/demo/analyze/{email_id}">

                <input type="hidden"
                       name="csrf_token"
                       value="{csrf}">

                <button class="login" type="submit">
                    Analyze with Gemini
                </button>

            </form>

            <div class="analysis-result analysis-panel">
                {analysis_html if analysis_html else '<p class="muted">Gemini analysis has not been run for this email yet.</p>'}
            </div>

            <form method="POST" data-ajax="true"
                  action="/demo/action/{email_id}">

                <input type="hidden"
                       name="csrf_token"
                       value="{csrf}">

                <button class="approve decision-button"
                        name="decision"
                        value="APPROVED"
                        type="submit">

                    Simulate Approve

                </button>

                <button class="reject decision-button"
                        name="decision"
                        value="REJECTED"
                        type="submit">

                    Simulate Reject

                </button>

            </form>

        </div>
        """

    content += """
    <div class="card">
        <p>
            <b>Demo disclaimer:</b>
            All emails are fictional. Approval and rejection
            actions only change simulated demo state.
        </p>
    </div>
    """

    return HTMLResponse(page(content))


# --------------------------------------------------
# DEMO AI EMAIL ANALYSIS
# --------------------------------------------------

@app.post("/demo/analyze/{email_id}")
async def demo_analyze(
    email_id: str,
    request: Request,
    csrf_token: str = Form(...)
):
    # Require a valid interviewer demo session.
    session = get_demo_session(request)
    if not session:
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "Session expired. Please log in again."}, status_code=401)
        return RedirectResponse("/demo/login", status_code=303)

    # Protect the state-changing POST request against CSRF.
    if not verify_csrf_token(session, csrf_token):
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "CSRF validation failed."}, status_code=403)
        return PlainTextResponse("CSRF validation failed.", status_code=403)

    # Only analyze known fictional demo emails.
    email = next((item for item in DEMO_EMAILS if item["id"] == email_id), None)
    if not email:
        return PlainTextResponse("Demo email not found.", status_code=404)

    # Gemini analysis is advisory: it cannot approve or send email.
    result = await run_in_threadpool(
        analyze_email,
        email["sender"],
        email["subject"],
        email["body"]
    )
    email["analysis"] = result

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JSONResponse({"ok": True, "type": "analysis", "analysis": result})

    return RedirectResponse("/demo/dashboard", status_code=303)


# --------------------------------------------------
# DEMO APPROVE / REJECT
# --------------------------------------------------

@app.post("/demo/action/{email_id}")
async def demo_action(
    email_id: str,
    request: Request,
    decision: str = Form(...),
    csrf_token: str = Form(...)
):

    session = get_demo_session(request)

    if not session:
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "Session expired. Please log in again."}, status_code=401)
        return RedirectResponse("/demo/login", status_code=303)

    if not verify_csrf_token(session, csrf_token):

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "CSRF validation failed."}, status_code=403)
        return PlainTextResponse("CSRF validation failed.", status_code=403)

    if decision not in {"APPROVED", "REJECTED"}:

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "Invalid decision."}, status_code=400)
        return PlainTextResponse("Invalid decision.", status_code=400)

    email = next(
        (
            item for item in DEMO_EMAILS
            if item["id"] == email_id
        ),
        None
    )

    if not email:

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "Demo email not found."}, status_code=404)
        return PlainTextResponse("Demo email not found.", status_code=404)

    if email["status"] != "PENDING":

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse({"ok": False, "message": "This demo email has already been processed."}, status_code=409)
        return PlainTextResponse("This demo email has already been processed.", status_code=409)

    email["status"] = decision

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JSONResponse({"ok": True, "type": "decision", "status": decision})

    return RedirectResponse(
        "/demo/dashboard",
        status_code=303
    )


# --------------------------------------------------
# DEMO LOGOUT
# --------------------------------------------------

@app.post("/demo/logout")
async def demo_logout(
    request: Request,
    csrf_token: str = Form(...)
):

    session = get_demo_session(request)

    if not session:
        return RedirectResponse("/demo/login", status_code=303)

    if not verify_csrf_token(session, csrf_token):

        return PlainTextResponse(
            "CSRF validation failed.",
            status_code=403
        )

    response = RedirectResponse(
        "/demo/login",
        status_code=303
    )

    response.delete_cookie(
        DEMO_COOKIE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict"
    )

    return response
