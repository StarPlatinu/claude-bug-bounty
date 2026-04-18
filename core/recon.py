#!/usr/bin/env python3
"""
Recon pipeline — subdomain enum, live host discovery, URL crawl, nuclei scan.
Runs subfinder + dnsx + httpx + katana + gau + waybackurls in parallel.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import logger as log, tools
from utils.state import get_recon, load_state, save_state, set_recon

RECON_DIR = Path.home() / ".claudebbp" / "recon"
RECON_DIR.mkdir(parents=True, exist_ok=True)


async def run(target: str, quick: bool = False) -> dict:
    """
    Full recon pipeline. Returns structured recon dict.
    Saves results to ~/.claudebbp/state/<target>.json
    """
    log.section(f"RECON: {target}")
    out: dict = {
        "target": target,
        "subdomains": [],
        "live_hosts": [],
        "urls": [],
        "nuclei": [],
        "technologies": [],
    }

    # ── 1. Subdomain enumeration (parallel) ──────────────────────────────────
    log.info("Enumerating subdomains…")
    subs = await _enum_subdomains(target, quick)
    out["subdomains"] = subs
    log.success(f"Subdomains: {len(subs)} found")

    if not subs:
        subs = [target]

    # ── 2. Live host discovery ────────────────────────────────────────────────
    log.info("Probing live hosts…")
    hosts_input = "\n".join(subs)
    live = await _live_hosts(hosts_input)
    out["live_hosts"] = live
    log.success(f"Live hosts: {len(live)} found")

    if not live:
        live = [f"https://{target}"]

    # ── 3. URL discovery (parallel) ──────────────────────────────────────────
    if not quick:
        log.info("Crawling URLs…")
        urls = await _crawl_urls(target, live)
        out["urls"] = urls
        log.success(f"URLs: {len(urls)} discovered")

    # ── 4. Nuclei scan ───────────────────────────────────────────────────────
    log.info("Running nuclei…")
    nuclei_hits = await _nuclei_scan(target, quick)
    out["nuclei"] = nuclei_hits
    if nuclei_hits:
        log.finding(f"Nuclei: {len(nuclei_hits)} findings")
    else:
        log.info("Nuclei: no findings")

    # ── Persist & display ─────────────────────────────────────────────────────
    set_recon(target, out)
    _save_to_disk(target, out)
    _display_summary(out)
    return out


async def _enum_subdomains(target: str, quick: bool) -> list[str]:
    coros = [tools.subfinder(target)]
    if not quick:
        coros.append(tools.assetfinder(target))

    results = await tools.run_parallel(*coros)
    seen: set[str] = set()
    for r in results:
        if isinstance(r, tuple) and r[2] == 0:
            for line in r[0].splitlines():
                s = line.strip().lower()
                if s:
                    seen.add(s)
    return sorted(seen)


async def _live_hosts(hosts_input: str) -> list[str]:
    # httpx already resolves + checks HTTP
    stdout, stderr, rc = await tools.httpx(hosts_input, tech_detect=True, status_code=True, title=True)
    if rc != 0:
        log.warn(f"httpx error: {stderr[:120]}")
        return []
    live: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            # httpx output: "https://sub.target.com [200] [Title]"
            url = line.split()[0]
            if url.startswith("http"):
                live.append(url)
    return live


async def _crawl_urls(target: str, live_hosts: list[str]) -> list[str]:
    seen: set[str] = set()

    # gau + waybackurls for historical URLs
    gau_co = tools.gau(target)
    wb_co  = tools.waybackurls(target)

    # katana for live crawl of first 3 live hosts (to stay fast)
    katana_coros = [tools.katana(h) for h in live_hosts[:3]]

    results = await tools.run_parallel(gau_co, wb_co, *katana_coros)
    for r in results:
        if isinstance(r, tuple) and r[2] == 0:
            for line in r[0].splitlines():
                u = line.strip()
                if u.startswith("http"):
                    seen.add(u)
    return sorted(seen)


async def _nuclei_scan(target: str, quick: bool) -> list[dict]:
    sev = "high,critical" if quick else "low,medium,high,critical"
    stdout, stderr, rc = await tools.nuclei(target, severity=sev, timeout=300)
    if rc == 127:
        log.warn("nuclei not installed — skipping")
        return []
    findings: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json as _json
            obj = _json.loads(line)
            findings.append({
                "template_id": obj.get("template-id"),
                "severity":    obj.get("info", {}).get("severity"),
                "host":        obj.get("host"),
                "matched_at":  obj.get("matched-at"),
                "name":        obj.get("info", {}).get("name"),
            })
        except Exception:
            findings.append({"raw": line})
    return findings


def _save_to_disk(target: str, data: dict) -> None:
    import json, re
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    out_dir = RECON_DIR / safe
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "subdomains.txt").write_text("\n".join(data["subdomains"]))
    (out_dir / "live_hosts.txt").write_text("\n".join(data["live_hosts"]))
    (out_dir / "urls.txt").write_text("\n".join(data["urls"]))
    (out_dir / "nuclei.json").write_text(json.dumps(data["nuclei"], indent=2))
    log.dim(f"Recon saved to {out_dir}")


def _display_summary(data: dict) -> None:
    log.section("RECON SUMMARY")
    log.table(
        ["Category", "Count"],
        [
            ["Subdomains",  len(data["subdomains"])],
            ["Live Hosts",  len(data["live_hosts"])],
            ["URLs",        len(data["urls"])],
            ["Nuclei Hits", len(data["nuclei"])],
        ],
    )
    if data["nuclei"]:
        log.section("Nuclei Findings")
        for h in data["nuclei"][:10]:
            sev = h.get("severity", "?")
            name = h.get("name") or h.get("template_id") or h.get("raw", "")[:60]
            host = h.get("host", "")
            log.finding(f"[{sev.upper()}] {name} — {host}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(run(target))
