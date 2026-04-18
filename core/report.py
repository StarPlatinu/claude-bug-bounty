#!/usr/bin/env python3
"""
Report generator — produces H1/Bugcrowd/Intigriti-ready Markdown + JSON.
Wraps tools/report_generator.py for HTML; generates Markdown natively.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import get_findings, get_latest_finding, load_state

REPORTS_DIR = Path.home() / ".claudebbp" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_BOUNTY = {
    "critical": "$5000–$25000+",
    "high":     "$1000–$5000",
    "medium":   "$250–$1000",
    "low":      "$100–$250",
    "info":     "$0",
}


def generate(
    target: str,
    finding_id: str | None = None,
    platform: str = "hackerone",
    format: str = "markdown",
) -> dict:
    """
    Generate a report for the latest (or specified) finding.
    Returns {'markdown': str, 'json': dict, 'path': str}
    """
    log.section(f"REPORT GENERATOR [{platform.upper()}]")

    state = load_state(target)
    findings = state.get("findings", [])

    if not findings:
        log.error("No findings found. Run /hunt first.")
        return {}

    if finding_id:
        finding = next((f for f in findings if f.get("id") == finding_id), None)
        if not finding:
            log.error(f"Finding {finding_id} not found.")
            return {}
    else:
        finding = findings[-1]
        log.info(f"Using most recent finding: {finding.get('id')} — {finding.get('title','?')}")

    md  = _render_markdown(finding, platform, state)
    pdf = _render_json(finding, platform)

    # ── Write to disk ─────────────────────────────────────────────────────────
    safe_id = finding.get("id", "F001")
    ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    md_path  = REPORTS_DIR / f"{target}_{safe_id}_{ts}.md"
    json_path = REPORTS_DIR / f"{target}_{safe_id}_{ts}.json"

    md_path.write_text(md)
    json_path.write_text(json.dumps(pdf, indent=2))

    log.success(f"Markdown report : {md_path}")
    log.success(f"JSON report     : {json_path}")

    # Try existing HTML generator
    _try_html_generator(finding, target)

    print("\n" + "─" * 70)
    print(md[:3000])
    if len(md) > 3000:
        log.dim(f"… (full report at {md_path})")

    return {"markdown": md, "json": pdf, "path": str(md_path)}


def _render_markdown(f: dict, platform: str, state: dict) -> str:
    sev = f.get("severity", "medium").lower()
    vc  = f.get("vuln_class", "Unknown")
    url = f.get("url", "N/A")
    poc = f.get("poc", "")
    title = f.get("title") or f"{vc.upper()} in {url}"
    gate  = f.get("gate_score", "N/A")
    cvss  = f.get("cvss", "N/A")
    target = f.get("target", state.get("target", "unknown"))
    bounty = SEVERITY_BOUNTY.get(sev, "TBD")
    ts     = datetime.utcnow().strftime("%Y-%m-%d")

    lines = []

    if platform == "hackerone":
        lines += [
            f"# {title}",
            "",
            f"**Severity:** {sev.capitalize()}  ",
            f"**CVSS Score:** {cvss}  ",
            f"**Bounty Estimate:** {bounty}  ",
            f"**Date:** {ts}  ",
            f"**7-Question Gate Score:** {gate}/11  ",
            "",
            "## Summary",
            "",
            f"A **{vc}** vulnerability was identified in `{url}` affecting `{target}`. "
            f"An attacker can exploit this to {_impact_statement(sev, vc)}.",
            "",
            "## Steps to Reproduce",
            "",
        ]
        steps = f.get("steps") or _default_steps(vc, url)
        if isinstance(steps, list):
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append(str(steps))
        lines += [
            "",
            "## Impact",
            "",
            _impact_detail(sev, vc, target),
            "",
            "## Supporting Material / Proof of Concept",
            "",
            "```",
            poc or "See screenshots attached.",
            "```",
            "",
            "## Remediation",
            "",
            _remediation(vc),
        ]

    elif platform == "bugcrowd":
        lines += [
            f"# {title}",
            "",
            f"**Severity:** {sev.capitalize()}",
            f"**Asset:** {url}",
            "",
            "## Description",
            "",
            f"A {vc} vulnerability exists at `{url}`. {_impact_statement(sev, vc).capitalize()}.",
            "",
            "## Steps to Reproduce",
            "",
        ]
        steps = f.get("steps") or _default_steps(vc, url)
        if isinstance(steps, list):
            for i, s in enumerate(steps, 1):
                lines.append(f"{i}. {s}")
        lines += ["", "## Expected Result", "", "The application should not allow this action.", "",
                  "## Actual Result", "", f"The application is vulnerable to {vc}.", "",
                  "## Proof of Concept", "", f"```\n{poc}\n```", "",
                  "## Suggested Fix", "", _remediation(vc)]

    elif platform == "intigriti":
        lines += [
            f"# {title}",
            "",
            f"| Field | Value |",
            f"|---|---|",
            f"| Severity | {sev.capitalize()} |",
            f"| CVSS | {cvss} |",
            f"| Affected Asset | {url} |",
            f"| Date | {ts} |",
            "",
            "## Description",
            "",
            f"{_impact_statement(sev, vc).capitalize()}.",
            "",
            "## Steps to Reproduce",
            "",
        ]
        steps = f.get("steps") or _default_steps(vc, url)
        if isinstance(steps, list):
            for i, s in enumerate(steps, 1):
                lines.append(f"{i}. {s}")
        lines += ["", "## Impact", "", _impact_detail(sev, vc, target), "",
                  "## PoC", "", f"```\n{poc}\n```", "", "## Fix", "", _remediation(vc)]

    return "\n".join(lines)


def _render_json(f: dict, platform: str) -> dict:
    return {
        "platform":    platform,
        "id":          f.get("id"),
        "title":       f.get("title"),
        "severity":    f.get("severity"),
        "vuln_class":  f.get("vuln_class"),
        "target":      f.get("target"),
        "url":         f.get("url"),
        "cvss":        f.get("cvss"),
        "gate_score":  f.get("gate_score"),
        "poc":         f.get("poc"),
        "steps":       f.get("steps"),
        "ts":          datetime.utcnow().isoformat() + "Z",
    }


def _try_html_generator(finding: dict, target: str) -> None:
    gen = Path(__file__).resolve().parent.parent / "tools" / "report_generator.py"
    if not gen.exists():
        return
    try:
        import subprocess
        inp = json.dumps(finding)
        subprocess.run(
            [sys.executable, str(gen)],
            input=inp.encode(),
            capture_output=True,
            timeout=15,
        )
    except Exception:
        pass


def _impact_statement(severity: str, vc: str) -> str:
    mapping = {
        "idor":               "access other users' private data without authorization",
        "xss":                "execute arbitrary JavaScript in a victim's browser session",
        "ssrf":               "send requests from the server to internal services",
        "sqli":               "read, modify, or delete data from the database",
        "rce":                "execute arbitrary code on the server",
        "auth-bypass":        "bypass authentication and access protected resources",
        "open-redirect":      "redirect users to attacker-controlled domains (phishing)",
        "oauth":              "hijack OAuth tokens and take over victim accounts",
        "subdomain-takeover": "host malicious content on a trusted subdomain",
        "file-upload":        "upload and execute arbitrary files on the server",
        "cve":                "exploit a known vulnerability in an outdated component",
    }
    return mapping.get(vc.lower(), f"exploit the application via {vc}")


def _impact_detail(sev: str, vc: str, target: str) -> str:
    base = _impact_statement(sev, vc).capitalize()
    if sev == "critical":
        return f"{base}. This has critical business impact: full account takeover, data breach, or server compromise affecting all users of {target}."
    if sev == "high":
        return f"{base}. High business impact: significant data exposure or privilege escalation on {target}."
    return f"{base}. Medium business impact on {target}."


def _remediation(vc: str) -> str:
    mapping = {
        "idor":               "Implement server-side authorization checks. Verify that the requesting user owns the resource before returning data.",
        "xss":                "HTML-encode all user-supplied output. Implement a strict Content Security Policy (CSP).",
        "ssrf":               "Validate and allowlist outbound URLs. Block access to 169.254.169.254, 10.x, 172.x, 192.168.x from server-initiated requests.",
        "sqli":               "Use parameterized queries or prepared statements. Never interpolate user input into SQL strings.",
        "rce":                "Avoid passing user input to shell commands. Use language-native libraries instead of subprocess calls.",
        "auth-bypass":        "Enforce authentication middleware on all protected routes. Do not rely on client-side state for authorization.",
        "open-redirect":      "Validate redirect URLs against an allowlist of trusted domains.",
        "oauth":              "Enforce state parameter CSRF protection. Bind tokens to IP/user-agent. Validate redirect_uri server-side.",
        "subdomain-takeover": "Remove dangling DNS records pointing to unclaimed cloud services. Audit all CNAMEs regularly.",
        "file-upload":        "Validate file type server-side (magic bytes, not extension). Store uploads outside the web root.",
        "cve":                "Update the affected component to the latest patched version.",
    }
    return mapping.get(vc.lower(), "Review and patch the root cause. Consult OWASP guidelines for this vulnerability class.")


def _default_steps(vc: str, url: str) -> list[str]:
    return [
        f"Navigate to {url}",
        "Intercept the request with Burp Suite",
        f"Identify the parameter vulnerable to {vc}",
        "Craft the exploit payload",
        "Confirm impact by observing the server response",
    ]
