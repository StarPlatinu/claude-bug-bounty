#!/usr/bin/env python3
"""
Intel — fetches CVEs, disclosed reports, and threat intel for a target.
Wraps tools/intel_engine.py + tools/learn.py.
"""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import load_state, save_state

_TOOLS = Path(__file__).resolve().parent.parent / "tools"


def fetch(target: str, vuln_class: str | None = None) -> dict:
    """
    Pull CVEs, disclosed HackerOne reports, and tech intel for target.
    Returns structured intel dict.
    """
    log.section(f"INTEL: {target}")
    results: dict = {
        "target": target,
        "cves": [],
        "disclosed_reports": [],
        "technologies": [],
        "notes": [],
    }

    # Try intel_engine.py first (richer output)
    intel_script = _TOOLS / "intel_engine.py"
    if intel_script.exists():
        try:
            out = subprocess.check_output(
                [sys.executable, str(intel_script), target],
                stderr=subprocess.DEVNULL,
                timeout=60,
            ).decode(errors="replace")
            results["raw_intel"] = out
            log.success(f"Intel engine returned {len(out.splitlines())} lines")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, Exception) as e:
            log.warn(f"intel_engine.py failed: {e}")

    # Try learn.py for disclosed reports
    learn_script = _TOOLS / "learn.py"
    if learn_script.exists():
        try:
            out = subprocess.check_output(
                [sys.executable, str(learn_script), target],
                stderr=subprocess.DEVNULL,
                timeout=60,
            ).decode(errors="replace")
            _parse_learn_output(out, results)
            log.success(f"learn.py: {len(results['disclosed_reports'])} disclosed reports found")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, Exception) as e:
            log.warn(f"learn.py failed: {e}")

    # HackerOne MCP (GraphQL)
    _try_h1_mcp(target, vuln_class, results)

    # CVE search via NVD (no key required)
    _search_nvd(target, results)

    _display_intel(results)
    _cache_intel(target, results)
    return results


def _try_h1_mcp(target: str, vuln_class: str | None, out: dict) -> None:
    mcp_server = Path(__file__).resolve().parent.parent / "mcp" / "hackerone-mcp" / "server.py"
    if not mcp_server.exists():
        return
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("h1_server", mcp_server)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        if hasattr(mod, "search_disclosed_reports"):
            query = f"{target} {vuln_class or ''}"
            reports = mod.search_disclosed_reports(query)
            if isinstance(reports, list):
                out["disclosed_reports"].extend(reports[:10])
                log.success(f"HackerOne MCP: {len(reports)} reports for {query}")

        if hasattr(mod, "get_program_policy"):
            policy = mod.get_program_policy(target)
            if policy:
                out["program_policy"] = policy
    except Exception as e:
        log.dim(f"HackerOne MCP skipped: {e}")


def _search_nvd(target: str, out: dict) -> None:
    import urllib.request, urllib.error
    base = _base_domain(target)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={base}&resultsPerPage=10"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "claudebbp-intel/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            cve = v.get("cve", {})
            out["cves"].append({
                "id":          cve.get("id"),
                "description": (cve.get("descriptions", [{}])[0] or {}).get("value", ""),
                "severity":    _nvd_severity(cve),
            })
        if out["cves"]:
            log.success(f"NVD: {len(out['cves'])} CVEs for {base}")
    except Exception as e:
        log.dim(f"NVD search skipped: {e}")


def _nvd_severity(cve: dict) -> str:
    try:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                return metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")
    except Exception:
        pass
    return "UNKNOWN"


def _parse_learn_output(text: str, out: dict) -> None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("http") and "hackerone.com" in line:
            out["disclosed_reports"].append({"url": line})
        elif line.startswith("CVE-"):
            out["cves"].append({"id": line})
        elif line:
            out["notes"].append(line)


def _display_intel(results: dict) -> None:
    if results["cves"]:
        log.section("CVEs")
        for c in results["cves"][:5]:
            log.warn(f"  {c['id']} [{c.get('severity','?')}] {c.get('description','')[:80]}")

    if results["disclosed_reports"]:
        log.section("Disclosed Reports")
        for r in results["disclosed_reports"][:5]:
            log.info(f"  {r.get('url') or r.get('title','')}")

    if results["notes"]:
        log.section("Notes")
        for n in results["notes"][:5]:
            log.dim(f"  {n}")


def _cache_intel(target: str, results: dict) -> None:
    state = load_state(target)
    state["intel"] = results
    save_state(target, state)


def _base_domain(target: str) -> str:
    parts = target.replace("https://", "").replace("http://", "").split("/")[0].split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else target
