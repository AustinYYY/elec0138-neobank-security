"""
Synthetic Data Generator for Credential Stuffing Simulation:

All data is entirely synthetic. No real credentials are used.
Credentials are randomly generated based on password patterns
documented in publicly available security research.

The structure and patterns are based on publicly documented research:

  [REF-1] NordPass "Top 200 Most Common Passwords" (2025, 7th edition)
          https://nordpass.com/most-common-passwords-list/
          — Used to model common weak passwords (e.g. 123456, admin, password).
          — Top 40 global passwords extracted directly from the published list.
          — "123456" has been #1 globally for 6 of the last 7 years.

  [REF-2] Random name generator 
          https://nordpass.com/most-common-passwords-list/
"""

import csv
import json
import random
import string
from pathlib import Path
from typing import Any, Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
CREDENTIALS_FILE = BASE_DIR / "leaked_credentials.csv"

TOTAL_CREDENTIALS = 1000
# Set SEED to a fixed integer for reproducible results, or None for a
# different random dataset on every run.
SEED = None

# Mock NeoBank Users 
# 10 users with varying password strengths.
# username generated using the random name generator
USERS: List[Dict[str, Any]] = [
    {
        "username": "adele",
        "password": "adele123",
        "display_name": "Adele Batts",
        "balance": 2550.50,
        "transaction_history": ["Grocery Shopping - 35.10", "Public Transport - 3.40", "Online Shopping - 15.99"],
    },
    {
        "username": "luci",
        "password": "secureluci!",
        "display_name": "Luci Tennyson",
        "balance": 620.00,
        "transaction_history": ["Taxi - 15.20", "Pharmacy - 8.50", "Restaurant - 12.00"],
    },
    {
        "username": "charlie",
        "password": "charlie2025",
        "display_name": "Charlie Way",
        "balance": 4010.00,
        "transaction_history": ["Salary +3200", "Rent -1500", "Electricity -95"],
    },
    {
        "username": "woody",
        "password": "woodyPass1",
        "display_name": "Woody Abbey",
        "balance": 3690.75,
        "transaction_history": ["Water Bill - 30", "Grocery Shopping - 44.80"],
    },
    {
        "username": "melvin",
        "password": "qwerty123",
        "display_name": "Melvin Doctor",
        "balance": 2500.00,
        "transaction_history": ["Streaming Service - 15.99", "Gym Membership - 29.99", "Bakery - 4.50"],
    },
    {
        "username": "serena",
        "password": "S!erena#Secure99",
        "display_name": "Serena Howse",
        "balance": 5850.25,
        "transaction_history": ["Salary +5500", "Mortgage -1800", "Grocery Shopping - 62.30"],
    },
    {
        "username": "karol",
        "password": "karol1990",
        "display_name": "Karol Avery",
        "balance": 340.10,
        "transaction_history": ["Food Delivery - 29.50", "Clothing Store - 35.00"],
    },
    {
        "username": "eileen",
        "password": "E@ileen!BankSafe",
        "display_name": "Eileen Colby",
        "balance": 22300.00,
        "transaction_history": ["Salary +5200", "Rent -1500", "Department Store - 120.00"],
    },
    {
        "username": "elisabeth",
        "password": "password1",
        "display_name": "Elisabeth Sackville",
        "balance": 860.50,
        "transaction_history": ["Gaming Platform - 39.99", "Streaming Service - 11.99"],
    },
    {
        "username": "loren",
        "password": "loren2024!",
        "display_name": "Loren Flowers",
        "balance": 1900.00,
        "transaction_history": ["Clothing Store - 55.00", "Coffee Shop - 3.80", "Public Transport - 6.20"],
    },
]

# Password Pattern Pools
# Top 40 common passwords globally [REF-1]
COMMON_PASSWORDS = [
    "123456", "admin", "12345678", "123456789", "12345",
    "password", "Aa123456", "1234567890", "Pass@123", "admin123",
    "1234567", "123123", "111111", "12345678910", "P@ssw0rd",
    "Password", "Aa@123456", "admintelecom", "Admin@123", "112233",
    "102030", "654321", "abcd1234", "abc123", "qwerty123",
    "Abcd@1234", "Pass@1234", "11223344", "admin@123", "87654321",
    "987654321", "qwerty", "123123123", "1q2w3e4r", "Aa112233",
    "12341234", "qwertyuiop", "11111111", "Admin", "Password@123",
]

# Common name pool for generating non-existent user entries.
# 40 names randomly generated [REF-2]
FAKE_NAMES = [
    "carl", "len", "wyatt", "liddy", "aric",
    "dell", "antonia", "brande", "patrick", "charissa",
    "jerald", "nona", "donald", "andre", "susie",
    "christian", "alva", "garry", "micheal", "marsha",
    "tammi", "carson", "tamika", "penny", "christa",
    "emilia", "herman", "bertram", "geneva", "marion",
    "debbie", "praise", "brianna", "lewis", "emil",
    "cole", "shauna", "jessy", "baz", "narelle",
]

# Common suffixes appended to names in passwords [REF-1]
NAME_SUFFIXES = [
    "123", "1234", "12345", "1", "01", "99", "00",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "!", "!!", "@1", "#1", "_1", "pass", "Pass",
]


# Generator Functions

def generate_common_password_attempts(
    rng: random.Random, count: int
) -> List[Tuple[str, str]]:
    """
    Category (a): Common passwords sprayed against real usernames [REF-1].
    Attackers often try top-N passwords against known usernames.
    """
    real_usernames = [u["username"] for u in USERS]
    pairs = []
    while len(pairs) < count:
        username = rng.choice(real_usernames)
        password = rng.choice(COMMON_PASSWORDS)
        pair = (username, password)
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def generate_name_based_guesses(
    rng: random.Random, count: int
) -> List[Tuple[str, str]]:

    real_usernames = [u["username"] for u in USERS]
    pairs = []
    while len(pairs) < count:
        username = rng.choice(real_usernames)
        suffix = rng.choice(NAME_SUFFIXES)
        password = username + suffix
        pair = (username, password)
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def generate_nonexistent_users(
    rng: random.Random, count: int
) -> List[Tuple[str, str]]:
   
    real_usernames = {u["username"] for u in USERS}
    pairs = []

    while len(pairs) < count:
        name = rng.choice(FAKE_NAMES)
        if name in real_usernames:
            continue

        pattern = rng.choice(["common", "name_based", "random"])
        if pattern == "common":
            password = rng.choice(COMMON_PASSWORDS)
        elif pattern == "name_based":
            password = name + rng.choice(NAME_SUFFIXES)
        else:
            # Short random string — simulates hashed-then-cracked passwords
            length = rng.randint(6, 10)
            password = "".join(
                rng.choices(string.ascii_lowercase + string.digits, k=length)
            )

        pair = (name, password)
        if pair not in pairs:
            pairs.append(pair)

    return pairs


def generate_credentials(rng: random.Random) -> List[Tuple[str, str]]:
    """
    Target composition (approximate):
      - 40%   common password spray against real usernames 
      - 20%   name-based guesses 
      - 40%   non-existent / stale users
    """
    # Max unique combos: common = 10 users × 40 passwords = 400
    # Max unique combos: name_based = 10 users × 20 suffixes = 200
    common = generate_common_password_attempts(rng, 400)
    name_based = generate_name_based_guesses(rng, 200)
    nonexistent = generate_nonexistent_users(rng, 400)

    all_pairs = common + name_based + nonexistent

    # Trim or pad to exactly TOTAL_CREDENTIALS
    if len(all_pairs) > TOTAL_CREDENTIALS:
        all_pairs = all_pairs[:TOTAL_CREDENTIALS]
    elif len(all_pairs) < TOTAL_CREDENTIALS:
        extra = generate_common_password_attempts(
            rng, TOTAL_CREDENTIALS - len(all_pairs)
        )
        all_pairs.extend(extra)

    return all_pairs[:TOTAL_CREDENTIALS]


#Main
def main() -> None:
    seed = SEED if SEED is not None else random.randint(0, 999999)
    rng = random.Random(seed)
    print(f"[*] Using seed: {seed}")

    # Generate leaked credential pairs
    credentials = generate_credentials(rng)

    # Write users.json
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(USERS, f, indent=2, ensure_ascii=False)
    print(f"[+] Generated {len(USERS)} mock users -> {USERS_FILE.name}")

    # Write leaked_credentials.csv
    with CREDENTIALS_FILE.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])
        for username, password in credentials:
            writer.writerow([username, password])
    print(f"[+] Generated {len(credentials)} leaked credential pairs -> {CREDENTIALS_FILE.name}")


if __name__ == "__main__":
    main()
