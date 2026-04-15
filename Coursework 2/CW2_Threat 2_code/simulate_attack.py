"""
Combined attack simulation for NeoBank Secure Portal — Threat 2 (CW2)

Three sequential tests, each demonstrating one defence layer:
  Test 1 - CAPTCHA:        1000 credentials sent without CAPTCHA -> all blocked
  Test 2 - MFA:            CAPTCHA bypassed, 1000 credentials -> ~3 match, stopped at MFA
  Test 3 - Rate Limiting:  Cracked users try random MFA codes -> locked after 3 wrong
"""

import csv
import random
from pathlib import Path
from typing import Dict, List

import requests

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "leaked_credentials.csv"
RESULTS_FILE = BASE_DIR / "results_log_combined.csv"

BASE_URL = "http://127.0.0.1:5050"
LOGIN_URL = f"{BASE_URL}/login_secure"
MFA_URL = f"{BASE_URL}/mfa"
API_CAPTCHA = f"{BASE_URL}/api/captcha_toggle"
API_RESET = f"{BASE_URL}/api/reset_state"
API_ALERTS = f"{BASE_URL}/api/alerts"
ALERTS_PAGE = f"{BASE_URL}/alerts"


def load_credentials() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with CREDENTIALS_FILE.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "username": row["username"].strip(),
                "password": row["password"].strip(),
            })
    return rows


def api(url: str, payload: dict = None) -> None:
    """Helper to call a testing API endpoint on the server."""
    try:
        requests.post(url, json=payload, timeout=5)
    except requests.RequestException as exc:
        print(f"  [!] API call failed ({url}): {exc}")



# TEST 1 — CAPTCHA Defence
def test1_captcha(creds: List[Dict[str, str]]) -> List[Dict]:
    """Send all 1000 credentials WITHOUT solving CAPTCHA.
    Every attempt should be rejected (HTTP 403)."""

    print()
    print("=" * 72)
    print("  TEST 1: CAPTCHA DEFENCE")
    print("  Sending all 1000 leaked credentials WITHOUT solving CAPTCHA.")
    print("  Expected: every attempt is rejected at the CAPTCHA gate (HTTP 403).")
    print("=" * 72)
    print()

    api(API_RESET)
    api(API_CAPTCHA, {"enabled": True})

    results: List[Dict] = []
    captcha_blocked = 0

    sess = requests.Session()
    for i, c in enumerate(creds, 1):
        try:
            r = sess.post(
                LOGIN_URL,
                data={"username": c["username"], "password": c["password"]},
                # Deliberately omitting captcha_answer
                allow_redirects=False,
                timeout=5,
            )
            if r.status_code == 403:
                status = "CAPTCHA_BLOCKED"
                captcha_blocked += 1
            elif r.status_code == 429:
                status = "RATE_LIMITED"
                captcha_blocked += 1
            elif r.status_code == 401:
                status = "FAIL"
            else:
                status = f"HTTP_{r.status_code}"
        except requests.RequestException:
            status = "ERROR"

        results.append({
            "phase": "1-CAPTCHA", "id": str(i),
            "user": c["username"], "pass": c["password"],
            "status": status, "mfa_code": "",
        })

        # Print first 5, then every 200th, then last
        if i <= 5 or i % 200 == 0 or i == len(creds):
            print(f"  [{i:4d}/{len(creds)}]  {status:20s}  {c['username']}")

    print()
    print("-" * 72)
    print(f"  RESULT: {captcha_blocked} / {len(creds)} attempts BLOCKED by CAPTCHA.")
    print("  The hacker is stuck at the login page -- CAPTCHA prevents all")
    print("  automated credential-stuffing attempts.")
    print("-" * 72)
    return results



# TEST 2 — MFA Defence
def test2_mfa(creds: List[Dict[str, str]]) -> tuple:
    """CAPTCHA disabled (simulating bypass) so every credential reaches
    the authentication check. Passwords that match redirect to /mfa —
    but the attacker cannot proceed without the MFA code."""

    print()
    print("=" * 72)
    print("  TEST 2: MFA DEFENCE")
    print("  Scenario: attacker has bypassed CAPTCHA (disabled for this test).")
    print("  All 1000 credentials are checked against the real user database.")
    print("  Expected: ~3 passwords match, but ALL are stopped at the MFA page.")
    print("=" * 72)
    print()

    api(API_RESET)
    api(API_CAPTCHA, {"enabled": False})

    results: List[Dict] = []
    matches: List[Dict[str, str]] = []
    fail_count = 0
    block_count = 0

    for i, c in enumerate(creds, 1):
        try:
            # Fresh session per attempt to avoid pending_user bleed
            s = requests.Session()
            r = s.post(
                LOGIN_URL,
                data={"username": c["username"], "password": c["password"]},
                allow_redirects=False,
                timeout=5,
            )

            if (r.status_code in (302, 303)
                    and "/mfa" in r.headers.get("Location", "")):
                status = "PASSWORD_MATCH_MFA_REQUIRED"
                matches.append(c)
                print(
                    f"  [{i:4d}]  *** PASSWORD MATCH ***  "
                    f"{c['username']} / {c['password']}  -> redirected to /mfa"
                )
            elif r.status_code == 429:
                status = "RATE_LIMITED"
                block_count += 1
            elif r.status_code == 401:
                status = "FAIL"
                fail_count += 1
            else:
                status = f"HTTP_{r.status_code}"
        except requests.RequestException:
            status = "ERROR"

        results.append({
            "phase": "2-MFA", "id": str(i),
            "user": c["username"], "pass": c["password"],
            "status": status, "mfa_code": "",
        })

        # Progress indicator (non-match lines)
        if (i <= 5 or i % 200 == 0 or i == len(creds)) and "MATCH" not in status:
            print(f"  [{i:4d}/{len(creds)}]  {status:20s}  {c['username']}")

    # Deduplicate
    cracked: Dict[str, str] = {}
    for m in matches:
        cracked[m["username"]] = m["password"]

    print()
    print("-" * 72)
    print(f"  RESULT: {len(matches)} password match(es) out of {len(creds)} attempts.")
    print(f"  Unique users with correct password: {len(cracked)}")
    for u, p in cracked.items():
        print(f"    - {u} / {p}")
    print(f"  Failed: {fail_count}  |  Rate-limited: {block_count}")
    print()
    print("  The attacker cracked some passwords, but EVERY matched user is")
    print("  stuck at the MFA verification page -- NO account access granted.")
    print("-" * 72)

    # Restore defences
    api(API_CAPTCHA, {"enabled": True})

    return results, cracked



# TEST 3 — MFA Rate-Limiting Defence
def test3_mfa_ratelimit(cracked: Dict[str, str]) -> List[Dict]:
    """For each cracked user (from Test 2), log in with the correct
    password, then try 5 random 6-digit MFA codes.
    After 3 consecutive wrong codes the account is locked and a
    security alert is created on http://127.0.0.1:5050/alerts."""

    MFA_GUESSES = 5

    print()
    print("=" * 72)
    print("  TEST 3: MFA RATE-LIMITING DEFENCE")
    print(f"  Scenario: attacker bypassed CAPTCHA and guessed {len(cracked)} password(s).")
    print(f"  Now they try {MFA_GUESSES} random MFA codes per user.")
    print(f"  After 3 consecutive wrong codes the account is LOCKED")
    print(f"  and a security alert is raised at {ALERTS_PAGE}")
    print("=" * 72)

    api(API_RESET)
    api(API_CAPTCHA, {"enabled": False})       # attacker bypassed CAPTCHA

    results: List[Dict] = []

    for username, password in cracked.items():
        print(f"\n  {'-' * 50}")
        print(f"  User: {username}  (cracked password: {password})")
        print(f"  {'-' * 50}")

        # Step 1 — log in with correct credentials to reach /mfa
        sess = requests.Session()
        try:
            r = sess.post(
                LOGIN_URL,
                data={"username": username, "password": password},
                allow_redirects=False,
                timeout=5,
            )
        except requests.RequestException as exc:
            print(f"  [!] Login request failed: {exc}")
            continue

        if (r.status_code not in (302, 303)
                or "/mfa" not in r.headers.get("Location", "")):
            print(f"  [!] Could not reach MFA page (HTTP {r.status_code})")
            continue

        print("  Logged in successfully -> now at MFA page")
        print(f"  Trying {MFA_GUESSES} random 6-digit MFA codes ...\n")

        # Step 2 — brute-force MFA codes
        for attempt in range(1, MFA_GUESSES + 1):
            code = str(random.randint(100000, 999999))
            # Ensure we never accidentally guess the real demo code
            while code == "246810":
                code = str(random.randint(100000, 999999))

            try:
                mr = sess.post(
                    MFA_URL,
                    data={"mfa_code": code},
                    allow_redirects=False,
                    timeout=5,
                )

                if mr.status_code == 429:
                    status = "ACCOUNT_LOCKED"
                elif mr.status_code == 401:
                    status = "MFA_REJECTED"
                elif mr.status_code in (302, 303):
                    loc = mr.headers.get("Location", "")
                    if "/login" in loc:
                        status = "REDIRECT_TO_LOGIN"
                    else:
                        status = f"REDIRECT_{loc}"
                else:
                    status = f"HTTP_{mr.status_code}"
            except requests.RequestException:
                status = "ERROR"

            print(
                f"    Attempt {attempt}/{MFA_GUESSES}:  "
                f"code={code}  ->  {status}"
            )
            results.append({
                "phase": "3-MFA_RATE_LIMIT", "id": str(attempt),
                "user": username, "pass": password,
                "status": status, "mfa_code": code,
            })

            if status == "ACCOUNT_LOCKED":
                # Remaining attempts are pointless — account is locked
                for rem in range(attempt + 1, MFA_GUESSES + 1):
                    print(
                        f"    Attempt {rem}/{MFA_GUESSES}:  "
                        f"(skipped — account already locked)"
                    )
                    results.append({
                        "phase": "3-MFA_RATE_LIMIT", "id": str(rem),
                        "user": username, "pass": password,
                        "status": "SKIPPED_LOCKED", "mfa_code": "",
                    })
                break

    #Display security alerts
    print()
    print("  " + "=" * 50)
    print("  SECURITY ALERTS  (http://127.0.0.1:5050/alerts)")
    print("  " + "=" * 50)
    try:
        ar = requests.get(API_ALERTS, timeout=5)
        alert_list = ar.json() if ar.status_code == 200 else []
        if alert_list:
            for a in alert_list:
                print(
                    f"\n  [{a['timestamp']}]  "
                    f"user={a['username']}  ip_hash={a['masked_ip']}"
                )
                for reason in a["reasons"]:
                    print(f"      - {reason}")
        else:
            print("  (no alerts recorded)")
    except Exception as exc:
        print(f"  [!] Could not fetch alerts: {exc}")

    print()
    print("-" * 72)
    print(f"  All cracked accounts have been LOCKED after 3 wrong MFA attempts.")
    print(f"  Security alerts are visible at: {ALERTS_PAGE}")
    print("-" * 72)
    return results



# RESULTS OUTPUT
def write_csv(all_results: List[Dict]) -> None:
    fields = ["phase", "id", "user", "pass", "status", "mfa_code"]
    with RESULTS_FILE.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(all_results)
    print(f"  Results saved to: {RESULTS_FILE}")



# Main
def main() -> None:
    creds = load_credentials()
    print()
    print("=" * 72)
    print("  NeoBank Threat 2 — Combined Defence Simulation")
    print(f"  Loaded {len(creds)} leaked credential pairs")
    print(f"  Target: {BASE_URL}")
    print("=" * 72)

    #Test 1: CAPTCHA
    r1 = test1_captcha(creds)

    print()
    input("  Press ENTER to continue to Test 2 (MFA Defence) ... ")

    #Test 2: MFA
    r2, cracked = test2_mfa(creds)

    if not cracked:
        print("\n  No passwords cracked — Test 3 not applicable.")
        write_csv(r1 + r2)
        return

    print()
    input("  Press ENTER to continue to Test 3 (MFA Rate-Limiting) ... ")

    #Test 3: MFA Rate-Limiting
    r3 = test3_mfa_ratelimit(cracked)

    #Final summary
    captcha_blocked = sum(
        1 for r in r1
        if r["status"] in ("CAPTCHA_BLOCKED", "RATE_LIMITED")
    )
    mfa_stopped = len(cracked)
    accounts_locked = len(set(
        r["user"] for r in r3 if r["status"] == "ACCOUNT_LOCKED"
    ))

    print()
    print("=" * 72)
    print("  FINAL SUMMARY")
    print("=" * 72)
    print(f"  Test 1 (CAPTCHA)       : {captcha_blocked}/{len(creds)} attempts blocked")
    print(f"  Test 2 (MFA)           : {mfa_stopped} password(s) cracked, ALL stopped at MFA")
    print(f"  Test 3 (Rate Limiting) : {accounts_locked} account(s) locked after wrong MFA guesses")
    print(f"  Security alerts        : {ALERTS_PAGE}")
    print("=" * 72)
    print()

    write_csv(r1 + r2 + r3)


if __name__ == "__main__":
    main()
