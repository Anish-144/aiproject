"""
Case Manager — Persistent JSON-file-based case management.
Replaces the in-memory cases_store list for data that survives server restarts.
"""

import json
import os
import random
from datetime import datetime

CASES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cases.json")


def _ensure_file():
    """Ensure the cases JSON file exists."""
    os.makedirs(os.path.dirname(CASES_FILE), exist_ok=True)
    if not os.path.exists(CASES_FILE):
        with open(CASES_FILE, "w") as f:
            json.dump([], f)


def _read_cases() -> list:
    """Read all cases from disk."""
    _ensure_file()
    try:
        with open(CASES_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def _write_cases(cases: list):
    """Write cases list to disk."""
    _ensure_file()
    try:
        with open(CASES_FILE, "w") as f:
            json.dump(cases, f, indent=4)
    except IOError as e:
        print(f"[CaseManager] Write error: {e}")


def create_case(data: dict) -> dict:
    """
    Create a new case and persist it.
    Returns the created case dict with generated case_id.
    """
    cases = _read_cases()

    case_id = f"CASE-{random.randint(1000, 9999)}"

    new_case = {
        "case_id": case_id,
        "status": "Open",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "incident_summary": data.get("incident_summary", "N/A"),
        "severity": data.get("severity", "Unknown"),
        "ml_risk_score": data.get("ml_risk_score", 0),
        "mitre_techniques": data.get("mitre_techniques", []),
        "recommended_actions": data.get("recommended_actions", [])
    }

    cases.append(new_case)
    _write_cases(cases)

    return new_case


def get_all_cases() -> list:
    """Return all cases from persistent storage."""
    return _read_cases()


def update_status(case_id: str, new_status: str) -> dict:
    """
    Update the status of a case by case_id.
    Returns the updated case or None if not found.
    """
    cases = _read_cases()

    for case in cases:
        if case["case_id"] == case_id:
            case["status"] = new_status
            _write_cases(cases)
            return case

    return None
