import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "cw2-demo-secret-key"

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"

#Configuration 
LOCKOUT_SECONDS = 60           # MFA lockout duration
DEMO_MFA_CODE = "246810"       # demo MFA code
MAX_MFA_FAILS = 3              # MFA lockout after 3 consecutive wrong codes

#Feature toggles (for controlled testing)
captcha_enabled = True

#In-memory stores
alerts: List[Dict[str, Any]] = []
mfa_fail_counts: Dict[str, int] = {}
mfa_lockouts: Dict[str, float] = {}


#Utility functions

def now_ts() -> float:
    return time.time()


def mask_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:12]


def load_users() -> List[Dict[str, Any]]:
    with USERS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_user(username: str) -> Optional[Dict[str, Any]]:
    for user in load_users():
        if user["username"] == username:
            return user
    return None


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = find_user(username)
    if user and user["password"] == password:
        return user
    return None


def cleanup_lockouts() -> None:
    current = now_ts()
    for u in [k for k, v in mfa_lockouts.items() if v <= current]:
        del mfa_lockouts[u]


def create_alert(ip: str, username: str, reasons: List[str]) -> None:
    alerts.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "masked_ip": mask_ip(ip),
        "username": username,
        "reasons": reasons,
    })


def is_mfa_locked(username: str) -> Tuple[bool, str]:
    cleanup_lockouts()
    if username in mfa_lockouts and mfa_lockouts[username] > now_ts():
        return True, "Account locked: too many failed MFA attempts."
    return False, ""


def _render_login(error=None, status_code=200):
    """Render login page with fresh server-side CAPTCHA values."""
    a = random.randint(1, 20)
    b = random.randint(1, 20)
    session["captcha_expected"] = str(a + b)
    return (
        render_template(
            "login_secure.html",
            error=error,
            captcha_a=a,
            captcha_b=b,
            captcha_enabled=captcha_enabled,
        ),
        status_code,
    )


#Routes

@app.route("/")
def home():
    return redirect(url_for("login_secure"))


@app.route("/login_secure", methods=["GET", "POST"])
def login_secure():
    if request.method == "GET":
        return _render_login()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip = request.remote_addr or "unknown"

    #Defence 1: CAPTCHA (server-side)
    if captcha_enabled:
        answer = request.form.get("captcha_answer", "").strip()
        expected = session.pop("captcha_expected", None)
        if not expected or answer != expected:
            return _render_login(
                "CAPTCHA verification failed. Please solve the challenge.",
                403,
            )

    #Defence 2: Credential check
    user = authenticate(username, password)
    if user is None:
        return _render_login(
            "Login failed. Please check your credentials.", 401
        )

    # Password correct → proceed to MFA
    session["pending_user"] = username
    session["pending_ip"] = ip
    return redirect(url_for("mfa"))


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("login_secure"))

    #Defence 3: MFA rate-limiting
    locked, msg = is_mfa_locked(pending)
    if locked:
        return render_template(
            "mfa.html", error=msg, username=pending
        ), 429

    if request.method == "GET":
        return render_template("mfa.html", error=None, username=pending)

    code = request.form.get("mfa_code", "").strip()

    if code != DEMO_MFA_CODE:
        mfa_fail_counts[pending] = mfa_fail_counts.get(pending, 0) + 1
        fails = mfa_fail_counts[pending]

        if fails >= MAX_MFA_FAILS:
            # Lock account and raise alert
            mfa_lockouts[pending] = now_ts() + LOCKOUT_SECONDS
            ip = session.get("pending_ip", "unknown")
            create_alert(ip, pending, [
                f"Account locked: {fails} consecutive failed MFA attempts",
                "Possible MFA brute-force attack detected",
            ])
            return render_template(
                "mfa.html",
                error="Account locked due to too many failed MFA attempts.",
                username=pending,
            ), 429

        return render_template(
            "mfa.html",
            error=f"Invalid MFA code. Attempt {fails}/{MAX_MFA_FAILS}.",
            username=pending,
        ), 401

    # MFA passed — finalise session
    mfa_fail_counts.pop(pending, None)
    session["authenticated_user"] = pending
    session.pop("pending_user", None)
    session.pop("pending_ip", None)
    return redirect(url_for("account_secure", username=pending))


@app.route("/account_secure/<username>")
def account_secure(username: str):
    if session.get("authenticated_user") != username:
        return redirect(url_for("login_secure"))
    user = find_user(username)
    if not user:
        return "User not found.", 404
    return render_template("account_secure.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_secure"))


@app.route("/alerts")
def view_alerts():
    return render_template("alerts.html", alerts=alerts)


#Testing API (used by simulate_attack.py)

@app.route("/api/captcha_toggle", methods=["POST"])
def api_captcha_toggle():
    global captcha_enabled
    data = request.get_json(silent=True) or {}
    captcha_enabled = data.get("enabled", not captcha_enabled)
    return jsonify({"captcha_enabled": captcha_enabled})


@app.route("/api/reset_state", methods=["POST"])
def api_reset_state():
    alerts.clear()
    mfa_fail_counts.clear()
    mfa_lockouts.clear()
    return jsonify({"status": "reset"})


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    return jsonify(alerts)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
