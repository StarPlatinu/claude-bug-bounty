#!/usr/bin/env python3
"""
Scope checker — wraps tools/scope_checker.py + optional HackerOne MCP.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log
from utils.state import load_state, save_state

_TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(_TOOLS))

try:
    from scope_checker import ScopeChecker as _SC
    _HAVE_CHECKER = True
except ImportError:
    _HAVE_CHECKER = False


def check(asset: str, program: str | None = None, scope_domains: list[str] | None = None) -> dict:
    """
    Check whether an asset is in scope.

    Returns:
        {
          "asset": str,
          "in_scope": bool,
          "reason": str,
          "program": str | None,
          "scope_domains": list[str],
        }
    """
    log.section(f"SCOPE CHECK: {asset}")

    domains = scope_domains or _load_scope_from_state(program or asset)

    if not domains:
        log.warn("No scope domains loaded — add them to the program state or pass scope_domains=[]")
        log.warn("Defaulting to: assume in scope if asset matches target domain")
        base = _base_domain(asset)
        domains = [f"*.{base}", base]

    if _HAVE_CHECKER:
        checker = _SC(domains)
        url = asset if asset.startswith("http") else f"https://{asset}"
        in_scope = checker.is_in_scope(url)
    else:
        in_scope = _fallback_check(asset, domains)

    reason = (
        f"Matched scope pattern in {domains}" if in_scope
        else f"No pattern in {domains} matches {asset}"
    )

    result = {
        "asset": asset,
        "in_scope": in_scope,
        "reason": reason,
        "program": program,
        "scope_domains": domains,
    }

    if in_scope:
        log.success(f"IN SCOPE — {reason}")
    else:
        log.error(f"OUT OF SCOPE — {reason}")

    return result


def _load_scope_from_state(target: str) -> list[str]:
    state = load_state(target)
    scope = state.get("scope", {})
    return scope.get("domains", [])


def save_scope(target: str, domains: list[str], excluded: list[str] | None = None) -> None:
    """Persist program scope to state so all modules share the same scope."""
    state = load_state(target)
    state["scope"] = {
        "domains": domains,
        "excluded": excluded or [],
    }
    save_state(target, state)
    log.success(f"Scope saved: {len(domains)} domains for {target}")


def _base_domain(asset: str) -> str:
    parts = asset.replace("https://", "").replace("http://", "").split("/")[0].split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else asset


def _fallback_check(asset: str, domains: list[str]) -> bool:
    host = asset.replace("https://", "").replace("http://", "").split("/")[0].lower()
    for pattern in domains:
        p = pattern.lower().lstrip("*.")
        if host == p or host.endswith("." + p):
            return True
    return False
