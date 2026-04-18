#!/usr/bin/env python3
"""
Hunt orchestrator — loads scope, reads recon output, runs targeted vuln checks.
Chains: scope → recon (if needed) → pick attack surface → vuln scanners.
"""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log, tools
from utils.state import add_finding, get_recon, load_state, save_state

_TOOLS = Path(__file__).resolve().parent.parent / "tools"

VULN_CLASSES = [
    "idor", "xss", "ssrf", "sqli", "xxe", "rce",
    "open-redirect", "auth-bypass", "oauth", "race-condition",
    "file-upload", "ssti", "cve", "subdomain-takeover",
]


async def run(
    target: str,
    vuln_class: str | None = None,
    quick: bool = False,
) -> list[dict]:
    """
    Hunt a target. Returns list of finding dicts.
    Pass vuln_class to narrow the hunt (e.g., 'ssrf', 'idor').
    """
    log.section(f"HUNT: {target}" + (f" [{vuln_class}]" if vuln_class else ""))

    # Load recon results — run recon if not available
    recon = get_recon(target)
    if not recon or not recon.get("live_hosts"):
        log.info("No recon data found — running recon first…")
        from core.recon import run as do_recon
        recon = await do_recon(target, quick=quick)

    live_hosts = recon.get("live_hosts", [f"https://{target}"])
    urls       = recon.get("urls", [])
    nuclei_hits = recon.get("nuclei", [])

    findings: list[dict] = []

    # ── Convert nuclei hits to findings ──────────────────────────────────────
    for hit in nuclei_hits:
        sev = hit.get("severity", "info").lower()
        if sev in ("high", "critical", "medium"):
            f = {
                "target":     target,
                "vuln_class": hit.get("template_id", "nuclei"),
                "url":        hit.get("matched_at") or hit.get("host"),
                "severity":   sev,
                "title":      hit.get("name", hit.get("template_id", "Nuclei Finding")),
                "source":     "nuclei",
                "poc":        f"Template: {hit.get('template_id')}",
            }
            findings.append(f)

    # ── Run targeted scanners based on vuln_class ─────────────────────────────
    classes_to_run = [vuln_class] if vuln_class else _pick_classes(recon, quick)

    scan_tasks = []
    for vc in classes_to_run:
        for host in live_hosts[:5]:  # limit to 5 live hosts per class
            task = _run_scanner(vc, host, target, urls)
            scan_tasks.append(task)

    if scan_tasks:
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

    # ── Deduplicate & persist ─────────────────────────────────────────────────
    findings = _deduplicate(findings)

    if findings:
        log.section(f"HUNT RESULTS: {len(findings)} findings")
        for f in findings:
            log.finding(f"[{f.get('severity','?').upper()}] {f.get('title','?')} — {f.get('url','?')}")
            fid = add_finding(target, f)
            f["id"] = fid
    else:
        log.info("No findings in this run. Try a different vuln class or check the scope.")

    return findings


async def _run_scanner(vc: str, host: str, target: str, urls: list[str]) -> list[dict]:
    findings: list[dict] = []

    if vc == "xss":
        findings.extend(await _scan_xss(host, target))
    elif vc == "idor":
        findings.extend(await _scan_idor(host, target))
    elif vc == "ssrf":
        findings.extend(await _scan_ssrf(host, target))
    elif vc == "cve":
        findings.extend(await _scan_cve(host, target))
    elif vc == "oauth":
        findings.extend(await _scan_oauth(host, target))
    elif vc == "subdomain-takeover":
        findings.extend(await _scan_subtakeover(target))
    elif vc in ("sqli", "sql-injection"):
        findings.extend(await _scan_sqli(host, target, urls))
    elif vc == "secrets":
        findings.extend(await _scan_secrets(target))

    return findings


# ── Individual scanners ───────────────────────────────────────────────────────

async def _scan_xss(host: str, target: str) -> list[dict]:
    stdout, stderr, rc = await tools.dalfox(host, timeout=120)
    if rc == 127:
        log.warn("dalfox not installed — skipping XSS scan")
        return []
    findings: list[dict] = []
    for line in stdout.splitlines():
        if "[V]" in line or "FOUND" in line.upper():
            findings.append({
                "target": target, "vuln_class": "xss",
                "url": host, "severity": "medium",
                "title": "Cross-Site Scripting (XSS)",
                "source": "dalfox", "poc": line.strip(),
            })
    return findings


async def _scan_idor(host: str, target: str) -> list[dict]:
    script = _TOOLS / "h1_idor_scanner.py"
    if not script.exists():
        return []
    try:
        out = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.check_output(
                    [sys.executable, str(script), "--target", host],
                    stderr=subprocess.DEVNULL, timeout=60
                ).decode(errors="replace")
            ),
            timeout=70,
        )
        return _parse_script_output(out, target, "idor")
    except Exception:
        return []


async def _scan_ssrf(host: str, target: str) -> list[dict]:
    # Lightweight SSRF probe via nuclei ssrf templates
    stdout, _, rc = await tools.nuclei(
        host, templates="ssrf", severity="medium,high,critical", timeout=120
    )
    if rc == 127:
        return []
    return _parse_nuclei_json(stdout, target, "ssrf")


async def _scan_cve(host: str, target: str) -> list[dict]:
    stdout, _, rc = await tools.nuclei(
        host, templates="cves", severity="high,critical", timeout=180
    )
    if rc == 127:
        return []
    return _parse_nuclei_json(stdout, target, "cve")


async def _scan_oauth(host: str, target: str) -> list[dict]:
    script = _TOOLS / "h1_oauth_tester.py"
    if not script.exists():
        return []
    try:
        out = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.check_output(
                [sys.executable, str(script), "--target", host],
                stderr=subprocess.DEVNULL, timeout=60
            ).decode(errors="replace")
        )
        return _parse_script_output(out, target, "oauth")
    except Exception:
        return []


async def _scan_subtakeover(target: str) -> list[dict]:
    stdout, _, rc = await tools.nuclei(
        target, templates="takeovers", severity="high,critical", timeout=120
    )
    if rc == 127:
        return []
    return _parse_nuclei_json(stdout, target, "subdomain-takeover")


async def _scan_sqli(host: str, target: str, urls: list[str]) -> list[dict]:
    # Scan parametrized URLs
    findings: list[dict] = []
    param_urls = [u for u in urls if "?" in u][:3]
    for u in param_urls:
        stdout, _, rc = await tools.sqlmap(u, level=1, risk=1, timeout=120)
        if rc == 0 and "is vulnerable" in stdout.lower():
            findings.append({
                "target": target, "vuln_class": "sqli",
                "url": u, "severity": "high",
                "title": "SQL Injection",
                "source": "sqlmap", "poc": u,
            })
    return findings


async def _scan_secrets(target: str) -> list[dict]:
    stdout, _, rc = await tools.trufflehog(f"https://github.com/{_org_from_target(target)}", timeout=120)
    if rc == 127 or rc != 0:
        return []
    findings: list[dict] = []
    for line in stdout.splitlines():
        try:
            import json as _j
            obj = _j.loads(line)
            if obj.get("Verified"):
                findings.append({
                    "target": target, "vuln_class": "exposed-secret",
                    "url": obj.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                    "severity": "high",
                    "title": f"Verified Secret: {obj.get('DetectorName','')}",
                    "source": "trufflehog", "poc": str(obj)[:200],
                })
        except Exception:
            pass
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pick_classes(recon: dict, quick: bool) -> list[str]:
    """Heuristically pick vuln classes based on recon tech stack."""
    classes = ["cve", "subdomain-takeover"]
    urls = recon.get("urls", [])
    hosts_text = " ".join(recon.get("live_hosts", []))

    if any("?" in u for u in urls):
        classes += ["xss", "ssrf", "idor"]
    if "oauth" in hosts_text.lower() or "/auth" in hosts_text.lower():
        classes.append("oauth")
    if not quick:
        classes += ["secrets"]

    return list(dict.fromkeys(classes))  # deduplicate preserving order


def _parse_nuclei_json(stdout: str, target: str, vc: str) -> list[dict]:
    findings: list[dict] = []
    for line in stdout.splitlines():
        try:
            import json as _j
            obj = _j.loads(line.strip())
            findings.append({
                "target":     target,
                "vuln_class": vc,
                "url":        obj.get("matched-at") or obj.get("host", ""),
                "severity":   obj.get("info", {}).get("severity", "info"),
                "title":      obj.get("info", {}).get("name", vc),
                "source":     "nuclei",
                "poc":        f"Template: {obj.get('template-id','')}",
            })
        except Exception:
            pass
    return findings


def _parse_script_output(text: str, target: str, vc: str) -> list[dict]:
    findings: list[dict] = []
    for line in text.splitlines():
        low = line.lower()
        if any(w in low for w in ("vulnerable", "found", "idor", "bypass", "success")):
            findings.append({
                "target": target, "vuln_class": vc,
                "url": "", "severity": "medium",
                "title": f"{vc.upper()} potential finding",
                "source": "script", "poc": line.strip()[:200],
            })
    return findings


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        key = f"{f.get('vuln_class','')}:{f.get('url','')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _org_from_target(target: str) -> str:
    parts = target.replace("https://", "").replace("http://", "").split(".")
    return parts[0] if parts else target
