# Coursework 1 -- Threat 2: Credential Stuffing Simulation

## Environment and Requirements

### Software
- Python 3.x

### Libraries
Flask==3.0.3
requests==2.32.3

Install with:
pip install -r requirements.txt


---

## Folder Structure

```
CW1/
├── generate_data.py
├── users.json
├── leaked_credentials.csv
├── app.py
├── simulate_attack.py
├── results_log.csv
├── requirements.txt
├── README.md
├── templates/
│   ├── login.html
│   └── account.html

```

### File Descriptions

- **generate_data.py** — Generates synthetic mock users (`users.json`) and a leaked credential list (`leaked_credentials.csv`) using common password patterns.
- **users.json** — Stores the 10 mock NeoBank user accounts with usernames, passwords, balances, and transaction histories.
- **leaked_credentials.csv** — Contains 1,000 username/password pairs that simulate a leaked credential database used in the attack.
- **app.py** — Flask web application that serves the mock NeoBank login portal and account pages with simple authentication.
- **simulate_attack.py** — Reads leaked credentials and replays them against the running login portal, logging successful and failed attempts.
- **results_log.csv** — Output log from the attack simulation containing per-attempt results and a summary report.
- **requirements.txt** — Lists the Python package dependencies (Flask, requests) needed to run the project.
- **login.html** — HTML template for the NeoBank login page with a username/password form.
- **account.html** — HTML template for the account dashboard that displays user details, balance, and transactions.

---

## How to Run

### Step 1: Generate synthetic data
```bash
python generate_data.py
```
This creates `users.json` and `leaked_credentials.csv`.

### Step 2: Start the mock login portal
```bash
python app.py
```
The server runs at `http://127.0.0.1:5000/login`.

### Step 3: Run the credential stuffing simulation
Open a second terminal and run:
```bash
python simulate_attack.py
```
Results are printed to the terminal and saved to `results_log.csv`.
