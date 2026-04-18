#!/usr/bin/env python3
"""
7-Question Gate — the full scoring system for killing weak findings.

Score ≥ 7  → Submit
Score 5-6  → Chain it first to raise severity
Score < 5  → Kill it — N/A will hurt your validity ratio

Questions and weights:
  Q1  Real & triggerable right now?          (0-2)
  Q2  Victim interaction realistic?          (0-2)
  Q3  Concrete security impact?              (0-2)
  Q4  Asset is in scope?                     (0-2)
  Q5  Working PoC with exact steps?          (0-1)
  Q6  Not already known / patched?           (0-1)
  Q7  Impact justifies writing a report?     (0-1)
  ─────────────────────────────────────────
  Max: 11   Threshold: 7
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Allow running as script from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import add_finding, load_state, save_state, update_finding

SUBMIT_THRESHOLD = 7
CHAIN_THRESHOLD  = 5


@dataclass
class GateResult:
    scores:   dict[str, float] = field(default_factory=dict)
    total:    float = 0.0
    verdict:  str   = ""          # SUBMIT | CHAIN | KILL
    rationale: str  = ""
    finding:  dict  = field(default_factory=dict)


# ── Question definitions ───────────────────────────────────────────────────────

QUESTIONS = [
    {
        "id": "Q1",
        "weight": 2,
        "prompt": "Is this vulnerability triggerable by an external attacker RIGHT NOW (no unusual pre-conditions)?",
        "options": [
            ("2", "Yes — any unauthenticated or low-priv user can trigger it"),
            ("1", "Partially — requires specific setup but still realistic"),
            ("0", "No — theoretical, requires inside access, or already mitigated"),
        ],
    },
    {
        "id": "Q2",
        "weight": 2,
        "prompt": "Does it require victim interaction? If yes, is the interaction realistic?",
        "options": [
            ("2", "No victim interaction required"),
            ("1", "Requires interaction but realistic (click link, view page)"),
            ("0", "Requires unlikely interaction (open malicious file, admin action)"),
        ],
    },
    {
        "id": "Q3",
        "weight": 2,
        "prompt": "What is the worst-case security impact?",
        "options": [
            ("2", "Critical — RCE, full account takeover, data exfil, financial loss, auth bypass"),
            ("1", "Medium — SSRF to internal, stored XSS, IDOR to sensitive data, info leak"),
            ("0", "Informational — missing headers, rate-limit, self-XSS, missing flag"),
        ],
    },
    {
        "id": "Q4",
        "weight": 2,
        "prompt": "Is the exact asset/endpoint clearly in-scope per the program policy?",
        "options": [
            ("2", "Yes — explicitly in scope"),
            ("1", "Unclear — likely in scope but not listed explicitly"),
            ("0", "No — out of scope, third-party, or excluded"),
        ],
    },
    {
        "id": "Q5",
        "weight": 1,
        "prompt": "Do you have a reproducible PoC with exact steps?",
        "options": [
            ("1", "Yes — full PoC, all steps, screenshots/recording"),
            ("0", "No — cannot reliably reproduce it"),
        ],
    },
    {
        "id": "Q6",
        "weight": 1,
        "prompt": "Is this NOT already known, patched, or listed as accepted risk?",
        "options": [
            ("1", "Yes — I verified it is NOT known/patched"),
            ("0", "No — it is already known, patched, or accepted risk"),
        ],
    },
    {
        "id": "Q7",
        "weight": 1,
        "prompt": "Does the real-world impact justify writing and submitting a report?",
        "options": [
            ("1", "Yes — clear business/security impact, payout likely"),
            ("0", "No — too low impact, not worth triager's time"),
        ],
    },
]

NEVER_SUBMIT = [
    "missing security headers (CSP, HSTS, X-Frame-Options)",
    "self-XSS (only affects attacker's own account)",
    "rate limiting missing on non-critical endpoints",
    "descriptive error messages without exploitable info",
    "SSL/TLS version below 1.3 on non-HTTPS page",
    "CSRF on logout endpoints",
    "username enumeration without further impact",
    "clickjacking on pages without sensitive actions",
    "tab-nabbing / reverse tabnabbing without exploit",
]


# ── Interactive gate ───────────────────────────────────────────────────────────

def run_gate(finding: dict | None = None, interactive: bool = True) -> GateResult:
    """Run the full 7-Question Gate. Returns a GateResult with verdict."""
    result = GateResult(finding=finding or {})
    log.section("7-QUESTION GATE")

    if finding:
        log.info(f"Target : {finding.get('target', 'unknown')}")
        log.info(f"Type   : {finding.get('vuln_class', 'unknown')}")
        log.info(f"URL    : {finding.get('url', 'N/A')}")
        print()

    _warn_never_submit(finding)

    total = 0.0
    for q in QUESTIONS:
        score = _ask_question(q, interactive)
        result.scores[q["id"]] = score
        total += score

    result.total = total
    result.verdict, result.rationale = _verdict(total)
    _print_result(result)

    if finding and finding.get("target"):
        _persist_gate_result(finding, result)

    return result


def _ask_question(q: dict, interactive: bool) -> float:
    log.info(f"[{q['id']}] {q['prompt']}")
    for key, desc in q["options"]:
        print(f"      [{key}] {desc}")

    if not interactive:
        return float(q["options"][0][0])

    while True:
        valid = {opt[0] for opt in q["options"]}
        ans = input("      Score: ").strip()
        if ans in valid:
            print()
            return float(ans)
        print(f"      Enter one of: {', '.join(sorted(valid))}")


def _verdict(total: float) -> tuple[str, str]:
    if total >= SUBMIT_THRESHOLD:
        return "SUBMIT", f"Score {total}/11 — strong enough to submit."
    if total >= CHAIN_THRESHOLD:
        return "CHAIN", f"Score {total}/11 — chain with another bug to raise severity before submitting."
    return "KILL", f"Score {total}/11 — too weak. N/A will hurt your validity ratio. Move on."


def _print_result(r: GateResult) -> None:
    print()
    log.section(f"RESULT: {r.verdict}")

    rows = [(q, f"{r.scores.get(q, 0)}/{QUESTIONS[i]['weight']}") for i, q in enumerate(r.scores)]
    log.table(["Question", "Score"], rows)
    print()

    colors = {"SUBMIT": "success", "CHAIN": "warn", "KILL": "error"}
    fn = getattr(log, colors.get(r.verdict, "info"))
    fn(r.rationale)

    if r.verdict == "KILL":
        log.dim("Never-submit list includes: " + " | ".join(NEVER_SUBMIT[:3]) + " ...")
    elif r.verdict == "CHAIN":
        log.info("Tip: use /chain to find a complementary bug that raises impact to High/Critical.")
    elif r.verdict == "SUBMIT":
        log.success("Run /report to generate the submission-ready report.")


def _warn_never_submit(finding: dict | None) -> None:
    if not finding:
        return
    vc = (finding.get("vuln_class") or "").lower()
    for ns in NEVER_SUBMIT:
        if any(word in vc for word in ns.split()[:2]):
            log.warn(f"Warning: '{vc}' is on the never-submit list → {ns}")


def _persist_gate_result(finding: dict, result: GateResult) -> None:
    target = finding.get("target", "unknown")
    finding.update({
        "gate_score":   result.total,
        "gate_verdict": result.verdict,
        "gate_scores":  result.scores,
    })
    if finding.get("id"):
        update_finding(target, finding["id"], finding)
    else:
        add_finding(target, finding)


# ── Non-interactive scoring (for autopilot) ────────────────────────────────────

def score_finding(finding: dict) -> GateResult:
    """Auto-score a finding dict without prompts. Used by autopilot."""
    result = GateResult(finding=finding)
    total = 0.0

    sev = (finding.get("severity") or "").lower()
    score_map = {"critical": 11, "high": 9, "medium": 6, "low": 3, "info": 1}
    inferred = score_map.get(sev, 5)

    # Distribute inferred score across questions proportionally
    weights = [q["weight"] for q in QUESTIONS]
    weight_total = sum(weights)
    for q in QUESTIONS:
        s = round((inferred / 11) * q["weight"], 1)
        result.scores[q["id"]] = s
        total += s

    result.total = total
    result.verdict, result.rationale = _verdict(total)
    return result


if __name__ == "__main__":
    run_gate()
