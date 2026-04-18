#!/usr/bin/env python3
"""
claudebbp — Claude Bug Bounty Plugin CLI
Parses /command-style slash commands and dispatches to core modules.

Usage examples:
  python claudebbp.py /recon target.com
  python claudebbp.py /hunt target.com --vuln-class ssrf
  python claudebbp.py /validate
  python claudebbp.py /report --platform hackerone
  python claudebbp.py /chain
  python claudebbp.py /triage
  python claudebbp.py /scope api.target.com
  python claudebbp.py /intel target.com
  python claudebbp.py /autopilot target.com --mode normal
  python claudebbp.py /web3-audit contracts/Token.sol
  python claudebbp.py /token-scan contracts/Token.sol
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import typer
    from typing import Annotated, Optional
    _TYPER = True
except ImportError:
    _TYPER = False

from utils import logger as log

# ── App setup ─────────────────────────────────────────────────────────────────

if _TYPER:
    app = typer.Typer(
        name="claudebbp",
        help="Claude Bug Bounty Plugin — professional bug bounty automation",
        no_args_is_help=True,
        rich_markup_mode="rich",
    )


# ── /recon ────────────────────────────────────────────────────────────────────

def cmd_recon(target: str, quick: bool = False) -> None:
    """Subdomain enum → live host discovery → URL crawl → nuclei scan."""
    from core import recon
    asyncio.run(recon.run(target, quick=quick))


# ── /hunt ─────────────────────────────────────────────────────────────────────

def cmd_hunt(target: str, vuln_class: str | None = None, quick: bool = False) -> None:
    """Load scope, pick attack surface, run targeted vuln checks."""
    from core import hunt
    asyncio.run(hunt.run(target, vuln_class=vuln_class, quick=quick))


# ── /validate ─────────────────────────────────────────────────────────────────

def cmd_validate(target: str | None = None, finding_id: str | None = None) -> None:
    """Full 7-Question Gate with scoring on the latest (or specified) finding."""
    from core import validate
    from utils.state import get_latest_finding, get_findings

    finding = None
    if target:
        if finding_id:
            findings = get_findings(target)
            finding = next((f for f in findings if f.get("id") == finding_id), None)
        else:
            finding = get_latest_finding(target)

    validate.run_gate(finding=finding, interactive=True)


# ── /report ───────────────────────────────────────────────────────────────────

def cmd_report(
    target: str,
    platform: str = "hackerone",
    finding_id: str | None = None,
) -> None:
    """Generate submission-ready Markdown + JSON report."""
    from core import report
    report.generate(target, finding_id=finding_id, platform=platform)


# ── /triage ───────────────────────────────────────────────────────────────────

def cmd_triage(target: str | None = None) -> None:
    """Quick 3-question go/no-go triage."""
    from core import triage
    triage.run(target=target)


# ── /chain ────────────────────────────────────────────────────────────────────

def cmd_chain(target: str | None = None) -> None:
    """Build A→B→C exploit chain to escalate severity."""
    from core import chain
    chain.run(target=target)


# ── /scope ────────────────────────────────────────────────────────────────────

def cmd_scope(asset: str, program: str | None = None) -> None:
    """Verify an asset is in-scope before hunting."""
    from core import scope
    scope.check(asset, program=program)


# ── /intel ────────────────────────────────────────────────────────────────────

def cmd_intel(target: str, vuln_class: str | None = None) -> None:
    """Fetch CVEs, disclosed reports, and tech intel for a target."""
    from core import intel
    intel.fetch(target, vuln_class=vuln_class)


# ── /autopilot ────────────────────────────────────────────────────────────────

def cmd_autopilot(
    target: str,
    mode: str = "normal",
    vuln_class: str | None = None,
) -> None:
    """Fully autonomous hunt loop: scope → recon → hunt → validate → report."""
    from core import autopilot
    asyncio.run(autopilot.run(target, mode=mode, vuln_class=vuln_class))


# ── /web3-audit ───────────────────────────────────────────────────────────────

def cmd_web3_audit(contract_path: str, target: str = "web3") -> None:
    """Smart contract audit: Slither + Mythril + custom checks."""
    from core import web3
    asyncio.run(web3.audit_contract(contract_path, target=target))


# ── /token-scan ───────────────────────────────────────────────────────────────

def cmd_token_scan(contract: str) -> None:
    """Rug-pull / honeypot detection for EVM and Solana tokens."""
    from core import web3
    asyncio.run(web3.token_scan(contract))


# ── /surface ─────────────────────────────────────────────────────────────────

def cmd_surface(target: str) -> None:
    """Show ranked attack surface based on recon output."""
    from utils.state import get_recon, get_findings
    recon = get_recon(target)
    findings = get_findings(target)

    log.section(f"ATTACK SURFACE: {target}")

    if not recon:
        log.warn("No recon data. Run /recon first.")
        return

    log.table(
        ["Asset", "Count"],
        [
            ["Subdomains",  len(recon.get("subdomains", []))],
            ["Live Hosts",  len(recon.get("live_hosts", []))],
            ["URLs",        len(recon.get("urls", []))],
            ["Nuclei Hits", len(recon.get("nuclei", []))],
            ["Findings",    len(findings)],
        ],
    )

    live = recon.get("live_hosts", [])[:10]
    if live:
        log.section("Top Live Hosts")
        for h in live:
            log.info(h)

    nuclei = recon.get("nuclei", [])
    if nuclei:
        log.section("Nuclei Hits (ranked by severity)")
        ranked = sorted(nuclei, key=lambda x: _sev_rank(x.get("severity", "info")), reverse=True)
        for h in ranked[:10]:
            log.finding(f"[{h.get('severity','?').upper()}] {h.get('name') or h.get('template_id','?')} — {h.get('host','')}")


# ── /pickup ───────────────────────────────────────────────────────────────────

def cmd_pickup(target: str) -> None:
    """Pick up a previous hunt — show history, untested endpoints, suggestions."""
    from utils.state import load_state
    state = load_state(target)

    log.section(f"PICKING UP: {target}")

    findings  = state.get("findings", [])
    recon     = state.get("recon", {})
    intel     = state.get("intel", {})

    log.table(
        ["Metric", "Value"],
        [
            ["Last Updated",    state.get("updated", "never")],
            ["Findings",        len(findings)],
            ["Subdomains",      len(recon.get("subdomains", []))],
            ["Live Hosts",      len(recon.get("live_hosts", []))],
            ["URLs",            len(recon.get("urls", []))],
            ["CVEs Found",      len(intel.get("cves", []))],
        ],
    )

    if findings:
        log.section("Previous Findings")
        for f in findings[-5:]:
            verdict = f.get("gate_verdict", "?")
            log.info(f"  [{f.get('id','?')}] [{f.get('severity','?').upper()}] {f.get('title','?')} — {verdict}")

    untested = _untested_endpoints(recon, findings)
    if untested:
        log.section("Untested Endpoints (top 10)")
        for u in untested[:10]:
            log.info(f"  {u}")

    log.section("Suggested Next Steps")
    if not recon:
        log.info("→ Run /recon to populate attack surface")
    elif not findings:
        log.info("→ Run /hunt to start finding bugs")
    else:
        unsubmitted = [f for f in findings if f.get("gate_verdict") == "SUBMIT"]
        if unsubmitted:
            log.success(f"→ {len(unsubmitted)} finding(s) ready to submit — run /report")
        else:
            log.info("→ Run /chain to escalate existing findings or /hunt with a new vuln class")


# ── /remember ─────────────────────────────────────────────────────────────────

def cmd_remember(target: str, notes: str = "") -> None:
    """Log current finding / successful pattern to hunt memory."""
    from utils.state import get_latest_finding
    from memory.hunt_journal import HuntJournal

    finding = get_latest_finding(target)
    if not finding:
        log.error("No finding to remember. Run /hunt first.")
        return

    try:
        journal = HuntJournal()
        entry = {
            "target":     target,
            "action":     "finding_logged",
            "vuln_class": finding.get("vuln_class", "unknown"),
            "endpoint":   finding.get("url", ""),
            "result":     finding.get("gate_verdict", "unknown"),
            "severity":   finding.get("severity", ""),
            "technique":  finding.get("source", ""),
            "notes":      notes or finding.get("poc", ""),
        }
        journal.append(entry)
        log.success(f"Logged to hunt journal: {finding.get('vuln_class')} @ {finding.get('url','?')}")
    except Exception as e:
        log.warn(f"Could not write to hunt journal: {e}")


# ── Typer commands (if typer available) ──────────────────────────────────────

if _TYPER:
    @app.command("recon")
    def recon_cmd(
        target: str = typer.Argument(..., help="Target domain (e.g. target.com)"),
        quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan (no URL crawl)"),
    ):
        """Subdomain enum → live hosts → URL crawl → nuclei scan."""
        cmd_recon(target, quick=quick)

    @app.command("hunt")
    def hunt_cmd(
        target: str = typer.Argument(..., help="Target domain"),
        vuln_class: Optional[str] = typer.Option(None, "--vuln-class", "-v",
            help="Focus on: idor|xss|ssrf|sqli|oauth|rce|cve|subdomain-takeover|secrets"),
        quick: bool = typer.Option(False, "--quick", "-q"),
    ):
        """Load scope, pick attack surface, run targeted vuln checks."""
        cmd_hunt(target, vuln_class=vuln_class, quick=quick)

    @app.command("validate")
    def validate_cmd(
        target: Optional[str] = typer.Argument(None, help="Target domain (loads latest finding)"),
        finding_id: Optional[str] = typer.Option(None, "--id", help="Specific finding ID"),
    ):
        """Run the full 7-Question Gate on a finding."""
        cmd_validate(target=target, finding_id=finding_id)

    @app.command("report")
    def report_cmd(
        target: str = typer.Argument(...),
        platform: str = typer.Option("hackerone", "--platform", "-p",
            help="Platform: hackerone|bugcrowd|intigriti|immunefi"),
        finding_id: Optional[str] = typer.Option(None, "--id"),
    ):
        """Generate submission-ready Markdown + JSON report."""
        cmd_report(target, platform=platform, finding_id=finding_id)

    @app.command("triage")
    def triage_cmd(
        target: Optional[str] = typer.Argument(None),
    ):
        """Quick 3-question go/no-go triage."""
        cmd_triage(target=target)

    @app.command("chain")
    def chain_cmd(
        target: Optional[str] = typer.Argument(None),
    ):
        """Build A→B→C exploit chain to escalate severity."""
        cmd_chain(target=target)

    @app.command("scope")
    def scope_cmd(
        asset: str = typer.Argument(..., help="Asset to check (domain, IP, URL)"),
        program: Optional[str] = typer.Option(None, "--program", "-p"),
    ):
        """Verify an asset is in-scope before hunting."""
        cmd_scope(asset, program=program)

    @app.command("intel")
    def intel_cmd(
        target: str = typer.Argument(...),
        vuln_class: Optional[str] = typer.Option(None, "--vuln-class", "-v"),
    ):
        """Fetch CVEs, disclosed reports, and tech intel."""
        cmd_intel(target, vuln_class=vuln_class)

    @app.command("autopilot")
    def autopilot_cmd(
        target: str = typer.Argument(...),
        mode: str = typer.Option("normal", "--mode", "-m",
            help="Mode: paranoid|normal|yolo"),
        vuln_class: Optional[str] = typer.Option(None, "--vuln-class", "-v"),
    ):
        """Autonomous hunt loop: scope → recon → hunt → validate → report."""
        cmd_autopilot(target, mode=mode, vuln_class=vuln_class)

    @app.command("web3-audit")
    def web3_audit_cmd(
        contract_path: str = typer.Argument(..., help="Path to .sol contract file"),
        target: str = typer.Option("web3", "--target", "-t"),
    ):
        """Smart contract audit: Slither + Mythril + pattern checks."""
        cmd_web3_audit(contract_path, target=target)

    @app.command("token-scan")
    def token_scan_cmd(
        contract: str = typer.Argument(..., help="Contract address or .sol file path"),
    ):
        """Rug-pull / honeypot detection for EVM and Solana tokens."""
        cmd_token_scan(contract)

    @app.command("surface")
    def surface_cmd(
        target: str = typer.Argument(...),
    ):
        """Show ranked attack surface based on recon output."""
        cmd_surface(target)

    @app.command("pickup")
    def pickup_cmd(
        target: str = typer.Argument(...),
    ):
        """Pick up a previous hunt — show history and suggestions."""
        cmd_pickup(target)

    @app.command("remember")
    def remember_cmd(
        target: str = typer.Argument(...),
        notes: str = typer.Option("", "--notes", "-n"),
    ):
        """Log current finding / pattern to hunt memory."""
        cmd_remember(target, notes=notes)


# ── Slash-command parser (for /command style input) ──────────────────────────

SLASH_MAP = {
    "/recon":      cmd_recon,
    "/hunt":       cmd_hunt,
    "/validate":   cmd_validate,
    "/report":     cmd_report,
    "/triage":     cmd_triage,
    "/chain":      cmd_chain,
    "/scope":      cmd_scope,
    "/intel":      cmd_intel,
    "/autopilot":  cmd_autopilot,
    "/web3-audit": cmd_web3_audit,
    "/token-scan": cmd_token_scan,
    "/surface":    cmd_surface,
    "/pickup":     cmd_pickup,
    "/remember":   cmd_remember,
}


def run_slash(argv: list[str]) -> None:
    """
    Parse /command target [--flags] and dispatch.
    Supports: /recon target.com, /hunt target.com --vuln-class ssrf, etc.
    """
    if not argv:
        _print_help()
        return

    cmd = argv[0].lower()
    if not cmd.startswith("/"):
        cmd = "/" + cmd

    if cmd not in SLASH_MAP:
        log.error(f"Unknown command: {cmd}")
        log.info(f"Available: {', '.join(sorted(SLASH_MAP.keys()))}")
        return

    # Parse remaining args: positional → first arg, --flags
    args = argv[1:]
    positional = [a for a in args if not a.startswith("-")]
    flags = _parse_flags(args)

    fn = SLASH_MAP[cmd]
    _dispatch(fn, cmd, positional, flags)


def _dispatch(fn, cmd: str, positional: list[str], flags: dict) -> None:
    import inspect
    sig = inspect.signature(fn)
    params = list(sig.parameters.keys())

    call_args = {}
    for i, param in enumerate(params):
        if i < len(positional):
            call_args[param] = positional[i]
        elif param in flags:
            call_args[param] = flags[param]

    try:
        fn(**call_args)
    except TypeError as e:
        log.error(f"Bad arguments for {cmd}: {e}")
        log.info(f"Usage: {cmd} {' '.join(params)}")


def _parse_flags(args: list[str]) -> dict:
    flags: dict = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            key = a.lstrip("-").replace("-", "_")
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                flags[key] = args[i + 1]
                i += 2
            else:
                flags[key] = True
                i += 1
        else:
            i += 1
    return flags


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev.lower(), 0)


def _untested_endpoints(recon: dict, findings: list) -> list[str]:
    tested = {f.get("url", "") for f in findings}
    urls   = recon.get("urls", [])
    return [u for u in urls if u not in tested and "?" in u][:20]


def _print_help() -> None:
    log.banner("claudebbp — Claude Bug Bounty Plugin")
    rows = [
        ["/recon target.com",              "Subdomain enum + live hosts + URL crawl + nuclei"],
        ["/hunt target.com",               "Targeted vuln checks (IDOR, XSS, SSRF, CVE, ...)"],
        ["/validate [target]",             "7-Question Gate on latest finding"],
        ["/report target.com",             "Generate H1/Bugcrowd/Intigriti report"],
        ["/triage [target]",               "Quick 3-question go/no-go"],
        ["/chain [target]",                "Build A→B→C exploit chain"],
        ["/scope asset.com",               "Check if asset is in scope"],
        ["/intel target.com",              "CVEs + disclosed reports"],
        ["/autopilot target.com",          "Full autonomous loop"],
        ["/surface target.com",            "Ranked attack surface"],
        ["/pickup target.com",             "Resume previous hunt"],
        ["/remember target.com",           "Log finding to hunt journal"],
        ["/web3-audit Token.sol",          "Smart contract audit"],
        ["/token-scan Token.sol",          "Rug-pull / honeypot scan"],
    ]
    log.table(["Command", "Description"], rows)
    print()
    log.info("Golden path: /recon target → /hunt target → /validate → /report target")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]

    # Slash-command mode: claudebbp.py /recon target.com
    if args and args[0].startswith("/"):
        run_slash(args)
        return

    # typer mode: claudebbp.py recon target.com
    if _TYPER:
        app()
    else:
        run_slash(args)


if __name__ == "__main__":
    main()
