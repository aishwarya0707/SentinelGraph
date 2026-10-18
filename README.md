
# SentinelGraph

A Blue Team security event detection and investigation platform built with Python, FastAPI, and SQLite.

## Features

- Security login event collection through REST APIs
- Brute-force detection using failed login thresholds
- Password-spraying detection across multiple usernames
- Alert severity classification
- Alert investigation with related event evidence
- Alert status management
- MITRE ATT&CK technique mapping
- Interactive security dashboard
- Detection Lab with synthetic attack scenarios
- Automated API tests using pytest

## Detection Rules

| Detection | Behavior |
|---|---|
| Repeated Failed Logins | Detects repeated failed logins from one source IP within five minutes |
| Multiple Accounts from One IP | Detects failed login activity across five distinct usernames within five minutes |

## Technology Stack

- Python
- FastAPI
- SQLite
- HTML, CSS, JavaScript
- Pytest
- MITRE ATT&CK

## Run Locally

Clone the repository and enter the project directory.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install fastapi "uvicorn[standard]" pytest httpx
```

Start the API:

```bash
python -m uvicorn app.main:app --reload
```

Open the dashboard at http://127.0.0.1:8000/dashboard.

API documentation is available at http://127.0.0.1:8000/docs.

## Run Tests

```bash
python -m pytest -v
```

## Detection Lab

The dashboard includes synthetic scenarios for:

- Brute force
- Password spraying
- Normal login activity

These scenarios use sample data and are intended for local demonstration and testing.

## Disclaimer

SentinelGraph is an educational security project. Its detection rules are simplified examples and should not be treated as a production-ready security monitoring system.
