#!/usr/bin/env python3
"""
JSON state management — persists findings, recon, and session data per target.
State files live in ~/.claudebbp/state/<target>.json
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

STATE_DIR = Path.home() / ".claudebbp" / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = Path.home() / ".claudebbp" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def _state_file(target: str) -> Path:
    return STATE_DIR / f"{_safe_name(target)}.json"


def load_state(target: str) -> dict:
    f = _state_file(target)
    if f.exists():
        try:
            return json.loads(f.read_text())
        except json.JSONDecodeError:
            pass
    return {
        "target": target,
        "findings": [],
        "recon": {},
        "scope": {},
        "created": _now(),
        "updated": _now(),
    }


def save_state(target: str, state: dict) -> None:
    state["updated"] = _now()
    _state_file(target).write_text(json.dumps(state, indent=2))


def add_finding(target: str, finding: dict) -> str:
    state = load_state(target)
    fid = f"F{len(state['findings']) + 1:03d}"
    finding["id"] = fid
    finding["ts"] = _now()
    finding.setdefault("target", target)
    state["findings"].append(finding)
    save_state(target, state)
    return fid


def get_findings(target: str) -> list:
    return load_state(target).get("findings", [])


def get_latest_finding(target: str) -> dict | None:
    findings = get_findings(target)
    return findings[-1] if findings else None


def update_finding(target: str, finding_id: str, updates: dict) -> bool:
    state = load_state(target)
    for i, f in enumerate(state["findings"]):
        if f.get("id") == finding_id:
            state["findings"][i].update(updates)
            save_state(target, state)
            return True
    return False


def set_recon(target: str, recon_data: dict) -> None:
    state = load_state(target)
    state["recon"].update(recon_data)
    save_state(target, state)


def get_recon(target: str) -> dict:
    return load_state(target).get("recon", {})


def list_targets() -> list[str]:
    return [f.stem for f in STATE_DIR.glob("*.json")]


def dump_state(target: str) -> str:
    return json.dumps(load_state(target), indent=2)


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"
