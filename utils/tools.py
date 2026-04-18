#!/usr/bin/env python3
"""
Async wrappers for all external security tools.
Each function returns (stdout, stderr, returncode).
Pass timeout=N (seconds) to override the default per-tool timeout.
"""
import asyncio
import shutil
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
WORDLISTS = BASE_DIR / "wordlists"

# ── helpers ───────────────────────────────────────────────────────────────────

async def _run(
    *args: str,
    stdin: str | None = None,
    timeout: int = 120,
    env: dict | None = None,
) -> tuple[str, str, int]:
    """Run an external command asynchronously."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        in_bytes = stdin.encode() if stdin else None
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=in_bytes), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            return "", f"TIMEOUT after {timeout}s", 124
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except FileNotFoundError:
        return "", f"tool not found: {args[0]}", 127


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ── Recon ─────────────────────────────────────────────────────────────────────

async def subfinder(domain: str, silent: bool = True, timeout: int = 120) -> tuple[str, str, int]:
    args = ["subfinder", "-d", domain, "-all"]
    if silent:
        args.append("-silent")
    return await _run(*args, timeout=timeout)


async def dnsx(hosts_input: str, timeout: int = 60) -> tuple[str, str, int]:
    return await _run("dnsx", "-silent", "-resp", stdin=hosts_input, timeout=timeout)


async def httpx(
    hosts_input: str,
    tech_detect: bool = True,
    status_code: bool = True,
    title: bool = True,
    timeout: int = 60,
) -> tuple[str, str, int]:
    args = ["httpx", "-silent"]
    if tech_detect:
        args.append("-tech-detect")
    if status_code:
        args.append("-status-code")
    if title:
        args.append("-title")
    return await _run(*args, stdin=hosts_input, timeout=timeout)


async def katana(
    url: str,
    depth: int = 3,
    js_crawl: bool = True,
    timeout: int = 120,
) -> tuple[str, str, int]:
    args = ["katana", "-u", url, "-d", str(depth), "-silent"]
    if js_crawl:
        args.append("-jc")
    return await _run(*args, timeout=timeout)


async def gau(domain: str, timeout: int = 120) -> tuple[str, str, int]:
    return await _run("gau", "--subs", domain, timeout=timeout)


async def waybackurls(domain: str, timeout: int = 60) -> tuple[str, str, int]:
    return await _run("waybackurls", domain, timeout=timeout)


async def ffuf(
    url: str,
    wordlist: str | None = None,
    extensions: str = "php,asp,aspx,jsp,html,txt,json",
    rate: int = 150,
    timeout: int = 180,
) -> tuple[str, str, int]:
    wl = wordlist or str(WORDLISTS / "raft-medium-dirs.txt")
    return await _run(
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wl,
        "-e", extensions,
        "-rate", str(rate),
        "-o", "/dev/stdout",
        "-of", "json",
        "-silent",
        timeout=timeout,
    )


async def feroxbuster(
    url: str,
    wordlist: str | None = None,
    timeout: int = 180,
) -> tuple[str, str, int]:
    wl = wordlist or str(WORDLISTS / "raft-medium-dirs.txt")
    return await _run(
        "feroxbuster",
        "--url", url,
        "--wordlist", wl,
        "--silent",
        "--no-state",
        "--json",
        timeout=timeout,
    )


# ── Vulnerability Scanning ────────────────────────────────────────────────────

async def nuclei(
    target: str,
    templates: str = "",
    severity: str = "low,medium,high,critical",
    timeout: int = 300,
) -> tuple[str, str, int]:
    args = ["nuclei", "-target", target, "-severity", severity, "-silent", "-json"]
    if templates:
        args += ["-t", templates]
    return await _run(*args, timeout=timeout)


async def dalfox(
    url: str,
    timeout: int = 120,
) -> tuple[str, str, int]:
    return await _run("dalfox", "url", url, "--no-spinner", "--silence", timeout=timeout)


async def sqlmap(
    url: str,
    forms: bool = False,
    level: int = 1,
    risk: int = 1,
    timeout: int = 180,
) -> tuple[str, str, int]:
    args = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
    if forms:
        args.append("--forms")
    return await _run(*args, timeout=timeout)


async def trufflehog(
    source: str,
    timeout: int = 120,
) -> tuple[str, str, int]:
    if source.startswith("http"):
        return await _run("trufflehog", "git", source, "--json", "--no-update", timeout=timeout)
    return await _run("trufflehog", "filesystem", source, "--json", "--no-update", timeout=timeout)


# ── Web3 / Smart Contracts ────────────────────────────────────────────────────

async def slither(
    contract_path: str,
    timeout: int = 300,
) -> tuple[str, str, int]:
    return await _run(
        "slither", contract_path,
        "--json", "-",
        "--exclude-informational",
        timeout=timeout,
    )


async def mythril(
    contract_path: str,
    timeout: int = 300,
) -> tuple[str, str, int]:
    return await _run(
        "myth", "analyze", contract_path,
        "--output", "json",
        "--execution-timeout", "120",
        timeout=timeout,
    )


async def aderyn(
    contract_path: str,
    timeout: int = 180,
) -> tuple[str, str, int]:
    return await _run("aderyn", contract_path, "--output", "json", timeout=timeout)


# ── OSINT / Intel ─────────────────────────────────────────────────────────────

async def nmap(
    target: str,
    ports: str = "80,443,8080,8443,8000,3000,4000,5000",
    timeout: int = 120,
) -> tuple[str, str, int]:
    return await _run(
        "nmap", "-sV", "-p", ports, "--open", "-oN", "-", target,
        timeout=timeout,
    )


async def amass(
    domain: str,
    passive: bool = True,
    timeout: int = 180,
) -> tuple[str, str, int]:
    args = ["amass", "enum", "-d", domain, "-silent"]
    if passive:
        args.append("-passive")
    return await _run(*args, timeout=timeout)


async def assetfinder(domain: str, timeout: int = 60) -> tuple[str, str, int]:
    return await _run("assetfinder", "--subs-only", domain, timeout=timeout)


# ── Convenience ───────────────────────────────────────────────────────────────

async def run_parallel(*coros) -> list[Any]:
    """Run coroutines in parallel and return all results."""
    return await asyncio.gather(*coros, return_exceptions=True)
