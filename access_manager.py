# backend/access_manager.py
"""
Access control manager for temporary location sharing.
Stores access rules in a local JSON file.
"""

import json
import time
from pathlib import Path

ACCESS_FILE = Path(__file__).parent / "access_rules.json"

def _load_rules():
    if not ACCESS_FILE.exists():
        return []
    try:
        return json.loads(ACCESS_FILE.read_text())
    except Exception:
        return []

def _save_rules(rules):
    ACCESS_FILE.write_text(json.dumps(rules, indent=2))

def grant_access(owner: str, viewer: str, duration_minutes: int):
    """Grant access from owner → viewer for N minutes."""
    now = time.time()
    end = now + duration_minutes * 60
    rule = {
        "owner": owner,
        "viewer": viewer,
        "start": now,
        "end": end,
        "active": True
    }
    rules = _load_rules()
    # Remove existing duplicate rule
    rules = [r for r in rules if not (r["owner"] == owner and r["viewer"] == viewer)]
    rules.append(rule)
    _save_rules(rules)
    return rule

def is_access_allowed(owner: str, viewer: str) -> bool:
    """Check if viewer currently has access to owner's location."""
    now = time.time()
    rules = _load_rules()
    for r in rules:
        if r["owner"] == owner and r["viewer"] == viewer and r["active"]:
            if r["start"] <= now <= r["end"]:
                return True
    return False

def revoke_expired():
    """Deactivate expired rules."""
    now = time.time()
    rules = _load_rules()
    for r in rules:
        if r["end"] < now:
            r["active"] = False
    _save_rules(rules)
