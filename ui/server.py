#!/usr/bin/env python3
"""
claudebbp Web UI — FastAPI backend
Real-time streaming via Server-Sent Events (SSE)

Usage:
  python ui/server.py
  # opens at http://localhost:8080
"""
import asyncio
import json
import sys
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Project root on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from utils.state import list_targets, load_state, get_findings

UI_DIR   = Path(__file__).resolve().parent
STATIC   = UI_DIR / "static"

app = FastAPI(title="claudebbp UI", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC), name="static")

# ── In-memory job store ───────────────────────────────────────────────────────
_jobs: dict[str, asyncio.Queue] = {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/targets")
async def get_targets():
    results = []
    for t in list_targets():
        state   = load_state(t)
        findings = state.get("findings", [])
        recon   = state.get("recon", {})
        results.append({
            "target":    t,
            "findings":  len(findings),
            "critical":  sum(1 for f in findings if f.get("severity","").lower() == "critical"),
            "high":      sum(1 for f in findings if f.get("severity","").lower() == "high"),
            "medium":    sum(1 for f in findings if f.get("severity","").lower() == "medium"),
            "low":       sum(1 for f in findings if f.get("severity","").lower() == "low"),
            "subdomains": len(recon.get("subdomains", [])),
            "live_hosts": len(recon.get("live_hosts", [])),
            "urls":       len(recon.get("urls", [])),
            "updated":   state.get("updated", "—"),
        })
    return results


@app.get("/api/findings/{target}")
async def get_findings_route(target: str):
    findings = get_findings(target)
    if findings is None:
        raise HTTPException(404, "Target not found")
    return findings


@app.get("/api/state/{target}")
async def get_state(target: str):
    return load_state(target)


@app.get("/api/reports")
async def get_reports():
    reports_dir = Path.home() / ".claudebbp" / "reports"
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob("*.md"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [
        {
            "name": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        }
        for f in files[:50]
    ]


@app.get("/api/report-content")
async def get_report_content(path: str):
    f = Path(path)
    if not f.exists() or not f.suffix == ".md":
        raise HTTPException(404, "Report not found")
    return {"content": f.read_text()}


class RunRequest(BaseModel):
    command: str          # e.g. "/recon"
    target: str = ""
    flags: dict = {}


@app.post("/api/run")
async def run_command(body: RunRequest):
    job_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue()
    _jobs[job_id] = queue

    cmd = [sys.executable, str(ROOT / "claudebbp.py"), body.command]
    if body.target:
        cmd.append(body.target)
    for k, v in body.flags.items():
        cmd += [f"--{k.replace('_','-')}", str(v)]

    asyncio.create_task(_run_job(job_id, cmd, queue))
    return {"job_id": job_id}


@app.get("/api/stream/{job_id}")
async def stream(job_id: str):
    async def generate():
        queue = _jobs.get(job_id)
        if not queue:
            yield f"data: {json.dumps({'line': '❌ Job not found', 'type': 'error'})}\n\n"
            return
        while True:
            try:
                line = await asyncio.wait_for(queue.get(), timeout=120)
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'line': '⏱ Timeout', 'type': 'error'})}\n\n"
                break
            if line is None:
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                _jobs.pop(job_id, None)
                break
            yield f"data: {json.dumps({'line': line, 'type': 'output'})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.delete("/api/target/{target}")
async def delete_target(target: str):
    state_dir = Path.home() / ".claudebbp" / "state"
    import re
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    f = state_dir / f"{safe}.json"
    if f.exists():
        f.unlink()
        return {"deleted": target}
    raise HTTPException(404, "Target not found")


# ── Job runner ────────────────────────────────────────────────────────────────

async def _run_job(job_id: str, cmd: list[str], queue: asyncio.Queue) -> None:
    await queue.put(f"$ {' '.join(cmd[2:])}")  # echo command (skip python + script path)
    await queue.put("─" * 60)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(ROOT),
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            # Strip ANSI escape codes for clean browser display
            import re
            line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line)
            if line:
                await queue.put(line)
        await proc.wait()
        await queue.put("─" * 60)
        rc = proc.returncode
        await queue.put(f"✓ Done (exit {rc})" if rc == 0 else f"✗ Failed (exit {rc})")
    except Exception as e:
        await queue.put(f"Error: {e}")
    finally:
        await queue.put(None)  # signal done


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  claudebbp UI  →  http://localhost:8080\n")
    uvicorn.run(
        "ui.server:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="warning",
        app_dir=str(ROOT),
    )
