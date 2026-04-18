#!/usr/bin/env python3
"""
claudebbp Dashboard — FastAPI backend
Focused on: automation, recon details, vulnerability findings.
Manual submission handled by the user.
"""
import asyncio
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT   = Path(__file__).resolve().parent.parent
UI_DIR = Path(__file__).resolve().parent
STATIC = UI_DIR / "static"

sys.path.insert(0, str(ROOT))
from utils.state import list_targets, load_state, save_state, get_findings, set_recon

app = FastAPI(title="claudebbp", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_jobs: dict[str, asyncio.Queue] = {}

# ── Pages ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")

# ── Targets ───────────────────────────────────────────────────────────────────

@app.get("/api/targets")
async def api_targets():
    out = []
    for t in list_targets():
        state    = load_state(t)
        findings = state.get("findings", [])
        recon    = state.get("recon", {})
        bysev    = _count_sev(findings)
        out.append({
            "target":    t,
            "updated":   state.get("updated", ""),
            "scanning":  state.get("scanning", False),
            "findings":  len(findings),
            "critical":  bysev["critical"],
            "high":      bysev["high"],
            "medium":    bysev["medium"],
            "low":       bysev["low"],
            "subdomains": len(recon.get("subdomains", [])),
            "live_hosts": len(recon.get("live_hosts", [])),
            "urls":       len(recon.get("urls", [])),
        })
    return out


@app.delete("/api/targets/{target}")
async def del_target(target: str):
    state_dir = Path.home() / ".claudebbp" / "state"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    f = state_dir / f"{safe}.json"
    if f.exists():
        f.unlink()
        return {"ok": True}
    raise HTTPException(404, "Not found")

# ── Recon ─────────────────────────────────────────────────────────────────────

@app.get("/api/recon/{target}")
async def api_recon(target: str):
    state = load_state(target)
    recon = state.get("recon", {})

    # Enrich live_hosts with parsed fields
    hosts = []
    for h in recon.get("live_hosts", []):
        if isinstance(h, str):
            hosts.append(_parse_httpx_line(h))
        else:
            hosts.append(h)

    return {
        "target":     target,
        "subdomains": recon.get("subdomains", []),
        "live_hosts": hosts,
        "urls":       recon.get("urls", []),
        "nuclei":     recon.get("nuclei", []),
        "updated":    state.get("updated", ""),
    }

# ── Vulnerabilities ───────────────────────────────────────────────────────────

@app.get("/api/vulns/{target}")
async def api_vulns(target: str):
    findings = get_findings(target) or []
    enriched = []
    for f in findings:
        enriched.append({
            "id":         f.get("id", ""),
            "title":      f.get("title") or f.get("vuln_class", "Unknown"),
            "severity":   (f.get("severity") or "info").lower(),
            "vuln_class": f.get("vuln_class", ""),
            "url":        f.get("url", ""),
            "poc":        f.get("poc", ""),
            "source":     f.get("source", ""),
            "description":f.get("description") or _auto_desc(f),
            "steps":      f.get("steps") or _auto_steps(f),
            "remediation":f.get("remediation") or _auto_remediation(f.get("vuln_class", "")),
            "cvss":       f.get("cvss", ""),
            "gate_score": f.get("gate_score"),
            "gate_verdict":f.get("gate_verdict", ""),
            "ts":         f.get("ts", ""),
            "target":     f.get("target", target),
        })
    return enriched

# ── Scan orchestration ────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    mode: str = "full"   # full | recon | vulns | quick

@app.post("/api/scan")
async def start_scan(body: ScanRequest):
    job_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = queue

    # Mark scanning
    state = load_state(body.target)
    state["scanning"] = True
    save_state(body.target, state)

    asyncio.create_task(_run_scan(job_id, body.target, body.mode, queue))
    return {"job_id": job_id}

@app.post("/api/run")
async def run_cmd(body: dict):
    job_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = queue

    cmd = [sys.executable, str(ROOT / "claudebbp.py"), body["command"]]
    if body.get("target"):
        cmd.append(body["target"])
    for k, v in (body.get("flags") or {}).items():
        cmd += [f"--{k.replace('_','-')}", str(v)]

    asyncio.create_task(_run_job(job_id, cmd, queue, body.get("target")))
    return {"job_id": job_id}

@app.get("/api/stream/{job_id}")
async def stream(job_id: str):
    async def gen():
        q = _jobs.get(job_id)
        if not q:
            yield f"data: {json.dumps({'type':'error','line':'Job not found'})}\n\n"
            return
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=180)
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type':'error','line':'Timeout'})}\n\n"
                break
            if item is None:
                yield f"data: {json.dumps({'type':'done'})}\n\n"
                _jobs.pop(job_id, None)
                break
            yield f"data: {json.dumps({'type':'output','line': item})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Scan runner ───────────────────────────────────────────────────────────────

async def _run_scan(job_id: str, target: str, mode: str, queue: asyncio.Queue):
    try:
        if mode in ("full", "recon", "quick"):
            await queue.put(f"[PHASE] Recon — {target}")
            await _stream_cmd(job_id, [sys.executable, str(ROOT / "claudebbp.py"), "/recon",
                              target] + (["--quick"] if mode == "quick" else []), queue)

        if mode in ("full", "vulns"):
            await queue.put(f"[PHASE] Hunt — {target}")
            await _stream_cmd(job_id, [sys.executable, str(ROOT / "claudebbp.py"), "/hunt", target], queue)

    finally:
        state = load_state(target)
        state["scanning"] = False
        save_state(target, state)
        await queue.put(None)


async def _stream_cmd(job_id: str, cmd: list, queue: asyncio.Queue):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(ROOT),
        )
        async for raw in proc.stdout:
            line = re.sub(r"\x1b\[[0-9;]*[mK]", "", raw.decode(errors="replace").rstrip())
            if line:
                await queue.put(line)
        await proc.wait()
    except Exception as e:
        await queue.put(f"Error: {e}")


async def _run_job(job_id: str, cmd: list, queue: asyncio.Queue, target: str = None):
    await _stream_cmd(job_id, cmd, queue)
    if target:
        state = load_state(target)
        state["scanning"] = False
        save_state(target, state)
    await queue.put(None)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_sev(findings: list) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        c[s] = c.get(s, 0) + 1
    return c


def _parse_httpx_line(line: str) -> dict:
    """Parse httpx output line: 'https://sub.target.com [200] [Title] [tech,tech]'"""
    url   = line.split()[0] if line.split() else line
    code  = ""
    title = ""
    tech  = []
    parts = re.findall(r"\[([^\]]+)\]", line)
    for p in parts:
        if p.isdigit():
            code = p
        elif "," in p or any(t in p.lower() for t in ["nginx","apache","iis","cloudflare","react","vue","angular","php","asp","python","ruby","java","wordpress"]):
            tech = [t.strip() for t in p.split(",")]
        else:
            title = p
    return {"url": url, "status": code, "title": title, "tech": tech, "raw": line}


def _auto_desc(f: dict) -> str:
    vc = (f.get("vuln_class") or "").lower()
    descs = {
        "idor":  "An Insecure Direct Object Reference (IDOR) allows access to other users' data by manipulating object identifiers in requests.",
        "xss":   "Cross-Site Scripting (XSS) allows injection of malicious scripts into pages viewed by other users.",
        "ssrf":  "Server-Side Request Forgery (SSRF) forces the server to make requests to unintended locations, potentially exposing internal services.",
        "sqli":  "SQL Injection allows manipulation of database queries through unsanitized user input.",
        "rce":   "Remote Code Execution (RCE) allows an attacker to execute arbitrary code on the server.",
        "oauth": "OAuth misconfiguration allows token theft or account takeover via improper redirect_uri or state validation.",
        "cve":   "A known CVE was detected in a public-facing component. Update to the patched version immediately.",
        "subdomain-takeover": "A subdomain points to an unclaimed external service, allowing an attacker to host malicious content on a trusted origin.",
    }
    return descs.get(vc, f"Vulnerability class: {vc or 'unknown'}")


def _auto_steps(f: dict) -> list:
    return [
        f"Navigate to: {f.get('url', 'target URL')}",
        "Intercept the request in Burp Suite / browser DevTools",
        "Identify the vulnerable parameter",
        "Apply the payload from the PoC below",
        "Confirm impact by observing the server response",
    ]


def _auto_remediation(vc: str) -> str:
    r = {
        "idor":  "Add server-side authorization checks. Verify the requesting user owns the resource before returning data.",
        "xss":   "HTML-encode all user output. Implement a strict Content Security Policy (CSP).",
        "ssrf":  "Allowlist outbound URLs. Block access to 169.254.169.254, 10.x, 172.x, 192.168.x.",
        "sqli":  "Use parameterized queries / prepared statements.",
        "rce":   "Avoid passing user input to shell commands. Use language-native APIs.",
        "oauth": "Validate redirect_uri server-side. Enforce state parameter. Bind tokens to user-agent/IP.",
        "cve":   "Update the affected component to the latest patched version.",
        "subdomain-takeover": "Remove dangling DNS CNAMEs pointing to unclaimed services.",
    }
    return r.get(vc.lower(), "Review the root cause and apply the OWASP recommended fix for this vulnerability class.")


if __name__ == "__main__":
    print("\n  claudebbp Dashboard  →  http://localhost:8080\n")
    uvicorn.run("ui.server:app", host="0.0.0.0", port=8080,
                reload=False, log_level="warning", app_dir=str(ROOT))
