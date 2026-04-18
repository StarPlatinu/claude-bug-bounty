#!/usr/bin/env python3
"""
Autopilot — autonomous hunt loop: scope → recon → rank → hunt → validate → report.
Three modes:
  --paranoid  : confirm each step before proceeding
  --normal    : confirm before hunting and reporting
  --yolo      : fully automated, no confirmations
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import get_findings, load_state, save_state
from core import recon as recon_mod
from core import hunt as hunt_mod
from core import validate as validate_mod
from core import report as report_mod
from core import intel as intel_mod
from core import scope as scope_mod
from core.validate import score_finding


MODES = ("paranoid", "normal", "yolo")


async def run(
    target: str,
    mode: str = "normal",
    vuln_class: str | None = None,
    scope_domains: list[str] | None = None,
) -> dict:
    """
    Full autonomous hunt loop.
    Returns {'target': str, 'findings': list, 'reports': list}
    """
    if mode not in MODES:
        log.warn(f"Unknown mode '{mode}' — defaulting to 'normal'")
        mode = "normal"

    log.banner(
        f"AUTOPILOT — {target}\n"
        f"Mode: {mode.upper()} | VulnClass: {vuln_class or 'auto'}"
    )

    results: dict = {"target": target, "findings": [], "reports": []}

    # ── Phase 0: Scope check ──────────────────────────────────────────────────
    log.section("Phase 0 — Scope Check")
    scope_result = scope_mod.check(target, scope_domains=scope_domains)
    if not scope_result["in_scope"]:
        log.error(f"TARGET IS OUT OF SCOPE: {scope_result['reason']}")
        log.error("Autopilot aborted. Fix your scope first.")
        return results

    if mode == "paranoid" and not _confirm("Proceed with recon?"):
        return results

    # ── Phase 1: Intel ────────────────────────────────────────────────────────
    log.section("Phase 1 — Intelligence Gathering")
    intel = intel_mod.fetch(target, vuln_class)
    _save_to_state(target, "intel_summary", {
        "cve_count":    len(intel.get("cves", [])),
        "report_count": len(intel.get("disclosed_reports", [])),
    })

    if mode == "paranoid" and not _confirm("Proceed with recon?"):
        return results

    # ── Phase 2: Recon ────────────────────────────────────────────────────────
    log.section("Phase 2 — Recon")
    quick = (mode == "yolo")
    recon_data = await recon_mod.run(target, quick=quick)

    live_count = len(recon_data.get("live_hosts", []))
    url_count  = len(recon_data.get("urls", []))
    log.success(f"Recon complete: {live_count} live hosts, {url_count} URLs")

    if mode == "paranoid" and not _confirm("Proceed with hunting?"):
        return results
    if mode == "normal" and not _confirm("Start hunting? (scope confirmed, recon done)"):
        return results

    # ── Phase 3: Hunt ─────────────────────────────────────────────────────────
    log.section("Phase 3 — Hunt")
    findings = await hunt_mod.run(target, vuln_class=vuln_class, quick=quick)
    results["findings"] = findings

    if not findings:
        log.info("No findings this run. Moving on.")
        return results

    log.success(f"{len(findings)} finding(s) discovered")

    # ── Phase 4: Validate (auto-score in autopilot) ───────────────────────────
    log.section("Phase 4 — Validate")
    submit_queue: list[dict] = []

    for f in findings:
        gate = score_finding(f)
        log.info(f"{f.get('id','?')} [{f.get('vuln_class','?')}] → {gate.verdict} (score {gate.total:.1f}/11)")
        if gate.verdict == "SUBMIT":
            submit_queue.append(f)
        elif gate.verdict == "CHAIN":
            log.info(f"  → Queued for chain analysis: {f.get('id','?')}")

    if not submit_queue:
        log.warn("No findings passed the gate. Run /chain to escalate severity.")
        return results

    log.success(f"{len(submit_queue)} finding(s) ready to report")

    if mode == "paranoid" and not _confirm("Generate reports?"):
        return results
    if mode == "normal" and not _confirm(f"Generate {len(submit_queue)} report(s)?"):
        return results

    # ── Phase 5: Report ───────────────────────────────────────────────────────
    log.section("Phase 5 — Report")
    for f in submit_queue:
        report = report_mod.generate(target, finding_id=f.get("id"))
        if report:
            results["reports"].append(report.get("path"))

    log.section("AUTOPILOT COMPLETE")
    log.table(
        ["Metric", "Value"],
        [
            ["Live Hosts",     live_count],
            ["URLs Discovered", url_count],
            ["Findings",       len(findings)],
            ["Passed Gate",    len(submit_queue)],
            ["Reports",        len(results["reports"])],
        ],
    )

    if results["reports"]:
        log.success("Reports saved:")
        for r in results["reports"]:
            log.success(f"  {r}")

    return results


def _confirm(prompt: str) -> bool:
    ans = input(f"\n[AUTOPILOT] {prompt} [y/n]: ").strip().lower()
    return ans in ("y", "yes")


def _save_to_state(target: str, key: str, value) -> None:
    state = load_state(target)
    state[key] = value
    save_state(target, state)
