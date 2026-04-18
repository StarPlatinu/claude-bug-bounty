#!/usr/bin/env python3
"""
Chain builder — escalates severity by combining A→B→C bugs.
Knows common chain patterns and suggests complementary bugs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import get_findings, get_latest_finding, update_finding

# ── Known chain patterns ──────────────────────────────────────────────────────
# Format: (bug_a, bug_b, combined_severity, description, hunting_tip)
CHAINS = [
    ("open-redirect",  "oauth",              "critical",
     "Open Redirect → OAuth Token Theft → ATO",
     "Use the open redirect as the redirect_uri in OAuth flow to steal access tokens"),

    ("xss",            "csrf",               "high",
     "XSS → CSRF → Admin Action",
     "Use stored XSS to trigger CSRF form submission with victim's session"),

    ("xss",            "ato",                "critical",
     "XSS → Account Takeover",
     "Stored XSS that exfiltrates session cookies or triggers password change"),

    ("ssrf",           "cloud-metadata",     "critical",
     "SSRF → Cloud Metadata → Credential Leak",
     "SSRF to 169.254.169.254 leaks IAM credentials → full cloud account compromise"),

    ("ssrf",           "rce",                "critical",
     "SSRF → Internal Service → RCE",
     "SSRF to internal Elasticsearch/Redis/Memcached can lead to code execution"),

    ("idor",           "ato",                "high",
     "IDOR → Account Takeover",
     "IDOR on /api/user/<id>/email → change victim email → password reset → ATO"),

    ("subdomain-takeover", "xss",            "high",
     "Subdomain Takeover → Stored XSS",
     "Control the subdomain to serve malicious content on a trusted origin"),

    ("open-redirect",  "phishing",           "medium",
     "Open Redirect → Phishing",
     "Use trusted domain redirect to harvest credentials"),

    ("info-leak",      "idor",               "high",
     "Info Leak → IDOR → Data Exfil",
     "Leaked user IDs/GUIDs enable IDOR to access private records"),

    ("race-condition", "ato",                "critical",
     "Race Condition → Double-Spend / ATO",
     "Race on /api/redeem or /api/transfer for financial impact"),

    ("auth-bypass",    "rce",                "critical",
     "Auth Bypass → Admin Panel → RCE",
     "Bypass auth on admin interface → upload shell / execute commands"),

    ("file-upload",    "rce",                "critical",
     "File Upload → RCE",
     "Upload PHP/JSP webshell to a path that is served by the web server"),

    ("ssti",           "rce",                "critical",
     "SSTI → RCE",
     "Server-side template injection in Jinja2/Twig/Freemarker leads to RCE"),

    ("sqli",           "auth-bypass",        "critical",
     "SQLi → Auth Bypass → Admin",
     "' OR '1'='1 in login form bypasses auth entirely"),

    ("csrf",           "ato",                "high",
     "CSRF → Account Takeover",
     "CSRF on /account/change-email + no token → email change → ATO"),

    ("xxe",            "ssrf",               "high",
     "XXE → SSRF → Internal Data",
     "XXE DOCTYPE to file:// or http:// to read internal files or probe services"),

    ("cve",            "rce",                "critical",
     "CVE → RCE",
     "Unpatched CVE in public-facing component exploited for direct RCE"),
]

# Severity upgrade table: current → what you need → combined
UPGRADES = {
    "low":    ["info-leak", "open-redirect", "idor"],
    "medium": ["xss", "ssrf", "oauth", "race-condition"],
    "high":   ["ato", "rce", "cloud-metadata", "admin-access"],
}


def run(target: str | None = None, finding: dict | None = None) -> dict:
    """
    Suggest chain opportunities for the current finding.
    Returns {'chains': list, 'best': dict | None}
    """
    log.section("CHAIN BUILDER")

    if not finding and target:
        finding = get_latest_finding(target)

    if not finding:
        log.warn("No finding loaded. Run /hunt first or pass a finding dict.")
        return {"chains": [], "best": None}

    vc  = (finding.get("vuln_class") or "").lower()
    sev = (finding.get("severity") or "medium").lower()

    log.info(f"Current bug : {vc} [{sev}]")
    log.info(f"Target      : {finding.get('target','?')}")
    print()

    matches = _find_chains(vc)
    upgrade = _suggest_upgrade(sev)

    if matches:
        log.section("Matching Chain Patterns")
        for chain_a, chain_b, combined_sev, desc, tip in matches:
            log.finding(f"[{combined_sev.upper()}] {desc}")
            log.dim(f"   How: {tip}")
            print()
    else:
        log.info(f"No predefined chains for '{vc}' — try building a novel chain.")

    if upgrade:
        log.section(f"Upgrade from {sev.capitalize()} → Higher Severity")
        log.info(f"Find one of: {', '.join(upgrade)} to combine with your {vc}")

    # Persist chain suggestions to finding
    result = {
        "chains": [
            {"a": a, "b": b, "severity": s, "desc": d, "tip": t}
            for a, b, s, d, t in matches
        ],
        "best": None,
    }

    if matches:
        best = max(matches, key=lambda x: _sev_rank(x[2]))
        result["best"] = {
            "a": best[0], "b": best[1],
            "severity": best[2],
            "desc": best[3],
            "tip": best[4],
        }
        log.success(f"Best chain: {best[3]}")

        if finding.get("id") and target:
            update_finding(target, finding["id"], {"chain_suggestions": result["chains"]})

    _print_next_steps(vc, finding)
    return result


def _find_chains(vc: str) -> list[tuple]:
    return [c for c in CHAINS if vc in c[0] or vc in c[1]]


def _suggest_upgrade(current_sev: str) -> list[str]:
    return UPGRADES.get(current_sev, [])


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev.lower(), 0)


def _print_next_steps(vc: str, finding: dict) -> None:
    url = finding.get("url", "?")
    log.section("Next Steps")
    log.info(f"1. Confirm the current {vc} is reproducible at {url}")
    log.info("2. Search for the complementary bug listed in the best chain above")
    log.info("3. Write a combined PoC that shows the full attack chain end-to-end")
    log.info("4. Run /validate to re-score the combined finding")
    log.info("5. Run /report to generate the chained report")
