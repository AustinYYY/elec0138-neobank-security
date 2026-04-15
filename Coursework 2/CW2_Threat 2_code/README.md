# NeoBank CW2 -- Threat 2 Defense Prototype

## Environment and Requirements

### Software
- Python 3.x

## Requirements

pip install flask requests
pip install -r requirements.txt

## Files Description
- `app_secure.py`
  Combined hardened Flask login system with three defence layers:
  CAPTCHA (server-side), MFA, MFA-level rate limiting / account
  lockout, and privacy-aware logging (SHA256-hashed IPs in alerts).
- `simulate_attack.py`
  Combined three-phase attack simulation script. Runs Test 1 (CAPTCHA),
  Test 2 (MFA), and Test 3 (MFA rate limiting) sequentially.
- `users.json`
  Mock NeoBank user database (10 accounts).
- `leaked_credentials.csv`
  1,000 leaked credential pairs for attack simulation.
- `results_log_combined.csv`
  Output log from the combined simulation (all three tests).
- `templates/`
  HTML templates for:
  - `login_secure.html` -- secure login page with server-side CAPTCHA
  - `mfa.html` -- MFA code entry page
  - `account_secure.html` -- authenticated account dashboard
  - `alerts.html` -- security alerts page
---

## How to Run

1. Activate the virtual environment and start the hardened login system

```bash
.\.venv\Scripts\Activate.ps1
```
```bash
python app_secure.py
```

Then open:
http://127.0.0.1:5050/login_secure

The login page includes a server-side math CAPTCHA (e.g. "14 + 7 = ?").
The Sign In button remains disabled until the user solves it correctly.
The expected answer is stored in the Flask session, so automated scripts
cannot forge it. This prevents bots from submitting login requests.

2. Run the combined three-phase attack simulation

Open a new terminal and run:
```bash
python simulate_attack.py
```

The simulation runs three tests in order:

**Test 1 -- CAPTCHA Defence:**
All 1,000 leaked credentials are sent WITHOUT solving the CAPTCHA.
Result: 1,000/1,000 blocked (HTTP 403). The hacker is stuck at login.

**Test 2 -- MFA Defence:**
CAPTCHA is disabled (simulating bypass). All 1,000 credentials are tested.
Result: ~3 passwords match (melvin, charlie, adele), but ALL are stopped
at the MFA page. No account access is granted.

**Test 3 -- MFA Rate Limiting:**
For each cracked user from Test 2, the attacker tries 5 random MFA codes.
Result: After 3 consecutive wrong codes, the account is locked and a
security alert is raised at http://127.0.0.1:5050/alerts

3. Manual login test

You can manually verify the login flow in the browser:
- account: charlie
- password: charlie2025
- MFA code: 246810

4. View Security Alerts

Open http://127.0.0.1:5050/alerts while `app_secure.py` is running
to see all generated security alerts.

## API Endpoints (for testing)

- `POST /api/captcha_toggle` -- enable/disable CAPTCHA `{"enabled": true/false}`
- `POST /api/reset_state` -- clear all in-memory state (alerts, MFA counters, lockouts)
- `GET /api/alerts` -- get alerts as JSON
