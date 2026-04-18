#!/usr/bin/env python3
"""
Web3 audit module — Slither + Mythril + custom checks for smart contracts.
Honeypot / rug-pull detection for /token-scan.
"""
import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log, tools
from utils.state import add_finding, load_state

_TOOLS = Path(__file__).resolve().parent.parent / "tools"

# ── Bug class patterns (grep-based pre-screen) ────────────────────────────────
CONTRACT_PATTERNS = {
    "reentrancy":         [r"\.call\{", r"\.call\.value\(", r"\.transfer\(.*\)"],
    "access-control":     [r"onlyOwner", r"require\(msg\.sender", r"tx\.origin"],
    "integer-overflow":   [r"\+\+", r"\+=", r"\*=", r"SafeMath"],
    "unchecked-return":   [r"\.send\(", r"\.call\("],
    "timestamp-depend":   [r"block\.timestamp", r"now\b"],
    "tx-origin-auth":     [r"tx\.origin\s*==", r"require.*tx\.origin"],
    "self-destruct":      [r"selfdestruct\(", r"suicide\("],
    "delegatecall":       [r"delegatecall\(", r"\.delegatecall"],
    "hidden-mint":        [r"function mint", r"_mint\(", r"totalSupply\s*\+="],
    "freeze-authority":   [r"frozen\[", r"blacklist\[", r"require.*!frozen"],
    "fee-manipulation":   [r"fee\s*=", r"_taxFee", r"_liquidityFee"],
    "fake-renounce":      [r"renounceOwnership", r"owner\s*=\s*address\(0\)"],
}

# ── Token rug-pull / honeypot patterns ───────────────────────────────────────
RUG_PATTERNS = {
    "honeypot":           r"require\(.*canSell|_isExcluded|maxTxAmount|sellCooldown",
    "hidden-mint":        r"function\s+mint|_mint\(|totalSupply\s*\+=|maxSupply\s*=\s*0",
    "fee-manipulation":   r"_taxFee\s*=\s*[5-9]\d|fee\s*>\s*[2-9]\d",
    "fake-renounce":      r"function renounceOwnership[\s\S]{0,200}owner\s*=\s*",
    "blacklist-control":  r"blacklist\[|addToBlacklist|require.*!blacklisted",
    "lp-lock-bypass":     r"removeLiquidity|withdrawAll.*liquidity|migrateLiquidity",
    "proxy-backdoor":     r"upgradeTo\(|_implementation\s*=|setImplementation",
    "max-tx-control":     r"maxTxAmount\s*=\s*\d|setMaxTx|updateMaxTx",
}


async def audit_contract(contract_path: str, target: str = "unknown") -> list[dict]:
    """
    Run full smart contract audit: static analysis + pattern scan.
    Returns list of finding dicts.
    """
    log.section(f"WEB3 AUDIT: {contract_path}")
    path = Path(contract_path)

    if not path.exists():
        log.error(f"Contract file not found: {contract_path}")
        return []

    source = path.read_text(errors="replace")
    findings: list[dict] = []

    # ── 1. Pattern-based pre-screen ───────────────────────────────────────────
    log.info("Running pattern-based analysis…")
    for bug_class, patterns in CONTRACT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, source):
                findings.append(_make_finding(
                    target=target,
                    vuln_class=bug_class,
                    title=f"Potential {bug_class.replace('-', ' ').title()}",
                    severity=_class_severity(bug_class),
                    url=contract_path,
                    poc=f"Pattern match: `{pat}` in {path.name}",
                    source="pattern",
                ))
                break  # one finding per class

    log.info(f"Pattern scan: {len(findings)} potential issues")

    # ── 2. Slither static analysis ────────────────────────────────────────────
    log.info("Running Slither…")
    slither_findings = await _run_slither(contract_path, target)
    findings.extend(slither_findings)

    # ── 3. Mythril symbolic execution ────────────────────────────────────────
    log.info("Running Mythril…")
    mythril_findings = await _run_mythril(contract_path, target)
    findings.extend(mythril_findings)

    # ── Deduplicate by (vuln_class, source) ───────────────────────────────────
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        k = f"{f['vuln_class']}:{f.get('source','')}"
        if k not in seen:
            seen.add(k)
            unique.append(f)
            add_finding(target, f)

    _display_results(unique)
    return unique


async def token_scan(contract_address_or_file: str, target: str = "token") -> dict:
    """
    Rug-pull / honeypot detection for EVM and Solana tokens.
    Returns {'red_flags': list, 'risk_score': int, 'verdict': str}
    """
    log.section(f"TOKEN SCAN: {contract_address_or_file}")

    # Try existing token_scanner.py first
    scanner = _TOOLS / "token_scanner.py"
    if scanner.exists():
        try:
            import subprocess
            out = subprocess.check_output(
                [sys.executable, str(scanner), contract_address_or_file],
                stderr=subprocess.DEVNULL,
                timeout=60,
            ).decode(errors="replace")
            log.info("Token scanner output:")
            print(out)
        except Exception as e:
            log.warn(f"token_scanner.py failed: {e}")

    # Also run our own pattern analysis if it's a file
    red_flags: list[dict] = []
    path = Path(contract_address_or_file)

    if path.exists():
        source = path.read_text(errors="replace")
        for flag_name, pattern in RUG_PATTERNS.items():
            if re.search(pattern, source, re.IGNORECASE):
                red_flags.append({
                    "flag":        flag_name,
                    "severity":    _rug_severity(flag_name),
                    "description": _rug_description(flag_name),
                    "pattern":     pattern[:60],
                })

    risk_score = sum(_sev_int(f["severity"]) for f in red_flags)
    verdict = _rug_verdict(risk_score, red_flags)

    result = {
        "contract":    contract_address_or_file,
        "red_flags":   red_flags,
        "risk_score":  risk_score,
        "verdict":     verdict,
    }

    log.section("TOKEN SCAN RESULTS")
    if red_flags:
        for rf in red_flags:
            log.finding(f"[{rf['severity'].upper()}] {rf['flag']}: {rf['description']}")
    else:
        log.success("No rug-pull patterns detected in source code")

    _verdict_label = {
        "SAFE":   log.success,
        "RISKY":  log.warn,
        "RUG":    log.error,
    }.get(verdict, log.info)
    _verdict_label(f"Verdict: {verdict} (risk score: {risk_score})")

    return result


# ── Slither ───────────────────────────────────────────────────────────────────

async def _run_slither(contract_path: str, target: str) -> list[dict]:
    stdout, stderr, rc = await tools.slither(contract_path)
    if rc == 127:
        log.warn("slither not installed — pip install slither-analyzer")
        return []
    findings: list[dict] = []
    try:
        data = json.loads(stdout)
        for det in data.get("results", {}).get("detectors", []):
            findings.append(_make_finding(
                target=target,
                vuln_class=det.get("check", "unknown"),
                title=det.get("description", "Slither finding")[:100],
                severity=_map_slither_impact(det.get("impact", "Informational")),
                url=contract_path,
                poc=det.get("description", "")[:300],
                source="slither",
            ))
    except json.JSONDecodeError:
        # Slither text output fallback
        for line in stderr.splitlines():
            if "Reference:" in line or line.startswith("\t-"):
                continue
            low = line.lower()
            if any(w in low for w in ("reentrancy", "overflow", "unchecked", "dangerous")):
                findings.append(_make_finding(
                    target=target,
                    vuln_class="slither-finding",
                    title=line.strip()[:100],
                    severity="medium",
                    url=contract_path,
                    poc=line.strip(),
                    source="slither",
                ))
    return findings[:20]  # cap


async def _run_mythril(contract_path: str, target: str) -> list[dict]:
    stdout, stderr, rc = await tools.mythril(contract_path)
    if rc == 127:
        log.warn("mythril not installed — pip install mythril")
        return []
    findings: list[dict] = []
    try:
        data = json.loads(stdout)
        for issue in data.get("issues", []):
            findings.append(_make_finding(
                target=target,
                vuln_class=issue.get("swc-id", "SWC-unknown"),
                title=issue.get("title", "Mythril finding"),
                severity=_map_mythril_severity(issue.get("severity", "Low")),
                url=f"{contract_path}:{issue.get('lineno', '?')}",
                poc=issue.get("description", "")[:300],
                source="mythril",
            ))
    except json.JSONDecodeError:
        pass
    return findings[:20]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(**kwargs) -> dict:
    return {
        "target":     kwargs.get("target", "unknown"),
        "vuln_class": kwargs.get("vuln_class", "unknown"),
        "title":      kwargs.get("title", ""),
        "severity":   kwargs.get("severity", "medium"),
        "url":        kwargs.get("url", ""),
        "poc":        kwargs.get("poc", ""),
        "source":     kwargs.get("source", ""),
    }


def _class_severity(bug_class: str) -> str:
    high    = {"reentrancy", "self-destruct", "tx-origin-auth", "delegatecall"}
    medium  = {"access-control", "integer-overflow", "unchecked-return"}
    return "high" if bug_class in high else "medium" if bug_class in medium else "low"


def _map_slither_impact(impact: str) -> str:
    return {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}.get(impact, "low")


def _map_mythril_severity(s: str) -> str:
    return {"High": "high", "Medium": "medium", "Low": "low"}.get(s, "low")


def _rug_severity(flag: str) -> str:
    critical = {"honeypot", "hidden-mint", "lp-lock-bypass", "proxy-backdoor"}
    return "critical" if flag in critical else "high"


def _sev_int(sev: str) -> int:
    return {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}.get(sev.lower(), 0)


def _rug_verdict(score: int, flags: list) -> str:
    if score >= 15 or any(f["flag"] == "honeypot" for f in flags):
        return "RUG"
    if score >= 7:
        return "RISKY"
    return "SAFE"


def _rug_description(flag: str) -> str:
    descriptions = {
        "honeypot":          "Contract may prevent token sales (honeypot)",
        "hidden-mint":       "Owner can mint unlimited tokens, diluting holders",
        "fee-manipulation":  "Fees can be changed to >50% to steal transfers",
        "fake-renounce":     "renounceOwnership does not truly give up control",
        "blacklist-control": "Owner can blacklist addresses from selling",
        "lp-lock-bypass":    "Liquidity can be removed unexpectedly",
        "proxy-backdoor":    "Proxy can be upgraded to change logic",
        "max-tx-control":    "Max transaction amount can be changed to 0 (freeze)",
    }
    return descriptions.get(flag, f"Suspicious pattern: {flag}")


def _display_results(findings: list[dict]) -> None:
    log.section(f"AUDIT RESULTS: {len(findings)} findings")
    for f in findings:
        log.finding(f"[{f['severity'].upper()}][{f['source']}] {f['title']}")
