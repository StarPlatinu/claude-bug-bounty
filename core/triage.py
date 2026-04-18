#!/usr/bin/env python3
"""
Quick triage — fast go/no-go on a finding before full 7-Question Gate.
Uses a 3-question pre-filter: Real? Impact? Scope?
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import get_latest_finding, load_state


QUICK_QUESTIONS = [
    {
        "prompt": "Is this triggerable RIGHT NOW by an external attacker?",
        "yes_label": "Yes",
        "no_label":  "No (theoretical / requires inside access)",
    },
    {
        "prompt": "Does it have real impact? (ATO / RCE / data exfil / financial loss)",
        "yes_label": "Yes — clear impact",
        "no_label":  "No — informational, missing header, rate-limit",
    },
    {
        "prompt": "Is the asset clearly in scope?",
        "yes_label": "Yes",
        "no_label":  "No / Unsure",
    },
]

ALWAYS_KILL = [
    "self-xss",
    "missing headers",
    "rate limiting",
    "clickjacking",
    "username enumeration",
    "missing flag",
    "csv injection",
    "tab-nabbing",
]


def run(target: str | None = None, finding: dict | None = None) -> dict:
    """Quick 3-question triage. Returns {'go': bool, 'reason': str}."""
    log.section("QUICK TRIAGE")

    if not finding and target:
        finding = get_latest_finding(target)

    if finding:
        log.info(f"Finding: {finding.get('vuln_class','?')} @ {finding.get('url','?')}")
        _check_always_kill(finding)

    score = 0
    for q in QUICK_QUESTIONS:
        ans = _ask(q)
        if ans:
            score += 1
        else:
            # Any No = immediate kill
            result = {
                "go": False,
                "reason": f"Failed: '{q['prompt']}' → answered No",
                "score": score,
            }
            log.error(f"KILL — {result['reason']}")
            log.dim("Move on. Use /hunt to find the next target.")
            return result

    result = {"go": True, "reason": f"Passed all 3 gates ({score}/3) — run /validate for full gate", "score": score}
    log.success(f"GO — {result['reason']}")
    return result


def _ask(q: dict) -> bool:
    log.info(q["prompt"])
    print(f"  [y] {q['yes_label']}")
    print(f"  [n] {q['no_label']}")
    while True:
        ans = input("  Answer [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            print()
            return True
        if ans in ("n", "no"):
            print()
            return False


def _check_always_kill(finding: dict) -> None:
    vc = (finding.get("vuln_class") or "").lower()
    for kw in ALWAYS_KILL:
        if kw in vc:
            log.warn(f"'{vc}' matches always-kill pattern '{kw}' — strong signal to drop this")
