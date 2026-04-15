import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"


def load_users() -> List[Dict[str, Any]]:
    """Load mock users from users.json."""
    with USERS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_user(username: str) -> Optional[Dict[str, Any]]:
    """Return a user dictionary if username exists, otherwise None."""
    users = load_users()
    for user in users:
        if user["username"] == username:
            return user
    return None


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Simple mock authentication: exact username/password match."""
    user = find_user(username)
    if not user:
        return None
    if user["password"] == password:
        return user
    return None


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    user = authenticate(username, password)
    if user:
        return redirect(url_for("account", username=user["username"]))

    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


@app.route("/account/<username>", methods=["GET"])
def account(username: str):
    user = find_user(username)
    if not user:
        return "User not found.", 404

    return render_template("account.html", user=user)


if __name__ == "__main__":
    # Debug=True is fine for local coursework demo only.
    app.run(host="127.0.0.1", port=5000, debug=True)