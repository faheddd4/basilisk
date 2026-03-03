"""
Basilisk Desktop Backend — FastAPI server for Electron IPC.

Runs as a subprocess of the Electron main process, providing
REST API endpoints for scan management, session history,
module listing, and report generation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add parent to path for basilisk imports
sys.path.insert(0, str(Path(__file__).parent))

from basilisk.core.config import BasiliskConfig
from basilisk.core.session import ScanSession
from basilisk.core.finding import Severity

app = FastAPI(
    title="Basilisk Desktop Backend",
    version="0.1.0",
    docs_url="/docs" if os.environ.get("BASILISK_DEBUG") else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("basilisk.desktop")

# ============================================================
# State
# ============================================================

active_scans: dict[str, dict] = {}
scan_results: dict[str, dict] = {}
ws_clients: list[WebSocket] = []


# ============================================================
# Models
# ============================================================

class ScanConfig(BaseModel):
    target: str
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    auth: str = ""
    mode: str = "standard"
    evolve: bool = True
    generations: int = 5
    modules: list[str] = []
    output_format: str = "html"


class ReportRequest(BaseModel):
    format: str = "html"
    path: str = ""


# ============================================================
# Health & Status
# ============================================================

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/native/status")
async def native_status():
    try:
        from basilisk.native_bridge import native_status as get_status
        return get_status()
    except ImportError:
        return {"tokens_c": False, "encoder_c": False, "fuzzer_go": False, "matcher_go": False}


# ============================================================
# Scan Management
# ============================================================

@app.post("/api/scan")
async def start_scan(config: ScanConfig):
    """Start a new scan."""
    try:
        cfg = BasiliskConfig.from_cli_args(
            target=config.target, provider=config.provider, model=config.model,
            api_key=config.api_key, auth=config.auth, mode=config.mode,
            evolve=config.evolve, generations=config.generations,
            module=config.modules, output=config.output_format,
        )

        errors = cfg.validate()
        if errors:
            raise HTTPException(400, {"errors": errors})

        session = ScanSession(cfg)
        await session.initialize()

        active_scans[session.id] = {
            "session": session,
            "config": config.dict(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "initializing",
        }

        # Start scan in background
        asyncio.create_task(_run_scan_background(session, cfg))

        return {"session_id": session.id, "status": "started"}

    except Exception as e:
        raise HTTPException(500, {"error": str(e)})


@app.post("/api/scan/{session_id}/stop")
async def stop_scan(session_id: str):
    """Stop a running scan."""
    if session_id in active_scans:
        scan = active_scans[session_id]
        scan["status"] = "stopping"
        session = scan["session"]
        await session.close()
        active_scans.pop(session_id, None)
        return {"status": "stopped"}
    raise HTTPException(404, {"error": "Session not found"})


@app.get("/api/scan/{session_id}")
async def scan_status(session_id: str):
    """Get scan status."""
    if session_id in active_scans:
        scan = active_scans[session_id]
        session = scan["session"]
        return {
            "session_id": session_id,
            "status": scan["status"],
            "findings_count": len(session.findings),
            "findings": [f.to_dict() for f in session.findings[-10:]],  # Last 10
            "profile": session.profile.to_dict() if session.profile else None,
        }
    if session_id in scan_results:
        return scan_results[session_id]
    raise HTTPException(404, {"error": "Session not found"})


# ============================================================
# Session History
# ============================================================

@app.get("/api/sessions")
async def list_sessions():
    """List all sessions (active + completed)."""
    sessions = []
    for sid, data in active_scans.items():
        sessions.append({
            "id": sid, "status": data["status"],
            "target": data["config"]["target"],
            "started_at": data["started_at"],
        })
    for sid, data in scan_results.items():
        sessions.append({
            "id": sid, "status": "completed",
            "target": data.get("target", ""),
            "total_findings": data.get("total_findings", 0),
        })
    return {"sessions": sessions}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    if session_id in scan_results:
        return scan_results[session_id]
    if session_id in active_scans:
        scan = active_scans[session_id]
        session = scan["session"]
        return {
            "session_id": session_id,
            "status": scan["status"],
            "findings": [f.to_dict() for f in session.findings],
        }
    raise HTTPException(404, {"error": "Session not found"})


# ============================================================
# Modules
# ============================================================

@app.get("/api/modules")
async def list_modules():
    """List all available attack modules."""
    try:
        from basilisk.attacks.base import get_all_attack_modules
        modules = get_all_attack_modules()
        return {
            "modules": [
                {
                    "name": m.name,
                    "category": m.category.value,
                    "owasp_id": m.category.owasp_id,
                    "severity": m.severity_default.value,
                    "description": m.description,
                }
                for m in modules
            ]
        }
    except Exception as e:
        return {"error": str(e), "modules": []}


# ============================================================
# Reports
# ============================================================

@app.post("/api/report/{session_id}")
async def generate_report(session_id: str, req: ReportRequest):
    if session_id not in scan_results and session_id not in active_scans:
        raise HTTPException(404, {"error": "Session not found"})

    try:
        session = None
        if session_id in active_scans:
            session = active_scans[session_id]["session"]
        # Generate report
        from basilisk.report.generator import generate_report as gen
        from basilisk.core.config import OutputConfig
        output_cfg = OutputConfig(format=req.format, output_dir="./basilisk-reports")
        path = await gen(session, output_cfg)
        return {"path": path, "format": req.format}
    except Exception as e:
        raise HTTPException(500, {"error": str(e)})


@app.post("/api/report/{session_id}/export")
async def export_report(session_id: str, req: ReportRequest):
    result = await generate_report(session_id, req)
    if req.path:
        import shutil
        shutil.copy2(result["path"], req.path)
        return {"path": req.path, "format": req.format}
    return result


# ============================================================
# Settings
# ============================================================

class ApiKeyRequest(BaseModel):
    provider: str
    key: str

@app.post("/api/settings/apikey")
async def save_api_key(req: ApiKeyRequest):
    """Save API key as environment variable for current session."""
    env_map = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
        "azure": "AZURE_API_KEY",
    }
    env_var = env_map.get(req.provider)
    if env_var:
        os.environ[env_var] = req.key
        return {"status": "saved", "provider": req.provider}
    raise HTTPException(400, {"error": f"Unknown provider: {req.provider}"})


# ============================================================
# WebSocket for real-time updates
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            # Handle incoming commands if needed
    except WebSocketDisconnect:
        ws_clients.remove(ws)


async def broadcast(event: str, data: Any):
    """Broadcast event to all connected WebSocket clients."""
    message = json.dumps({"event": event, "data": data})
    disconnected = []
    for ws in ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_clients.remove(ws)


# ============================================================
# Background Scan Execution
# ============================================================

async def _run_scan_background(session: ScanSession, cfg: BasiliskConfig):
    """Execute scan pipeline in background."""
    sid = session.id
    try:
        active_scans[sid]["status"] = "recon"
        await broadcast("scan:status", {"session_id": sid, "phase": "recon"})

        # Create provider
        from basilisk.cli.scan import _create_provider, _run_recon
        prov = _create_provider(cfg)

        healthy = await prov.health_check()
        if not healthy:
            active_scans[sid]["status"] = "error"
            await broadcast("scan:error", {"session_id": sid, "error": "Provider health check failed"})
            return

        # Recon
        await _run_recon(prov, session)
        await broadcast("scan:profile", {"session_id": sid, "profile": session.profile.to_dict()})

        # Attacks
        active_scans[sid]["status"] = "attacking"
        from basilisk.attacks.base import get_all_attack_modules
        modules = get_all_attack_modules()

        if cfg.module:
            modules = [m for m in modules if m.name in cfg.module or any(m.name.startswith(f) for f in cfg.module)]

        for i, mod in enumerate(modules):
            active_scans[sid]["status"] = f"attacking:{mod.name}"
            await broadcast("scan:progress", {
                "session_id": sid, "module": mod.name,
                "progress": (i + 1) / len(modules),
            })

            try:
                findings = await mod.execute(prov, session, session.profile)
                for f in findings:
                    await broadcast("scan:finding", {
                        "session_id": sid, "finding": f.to_dict(),
                    })
            except Exception as e:
                logger.error(f"Module {mod.name} failed: {e}")

        # Complete
        active_scans[sid]["status"] = "complete"
        scan_results[sid] = {
            "session_id": sid,
            "status": "completed",
            "target": cfg.target.url,
            "total_findings": len(session.findings),
            "findings": [f.to_dict() for f in session.findings],
            "profile": session.profile.to_dict(),
            "summary": session.summary,
        }

        await broadcast("scan:complete", {
            "session_id": sid, "total_findings": len(session.findings),
            "summary": session.summary,
        })

        await session.close()
        active_scans.pop(sid, None)

    except Exception as e:
        logger.error(f"Scan {sid} failed: {e}")
        active_scans[sid]["status"] = "error"
        await broadcast("scan:error", {"session_id": sid, "error": str(e)})


# ============================================================
# Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Basilisk Desktop Backend")
    parser.add_argument("--port", type=int, default=8741)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    log_level = "debug" if args.debug else "info"
    uvicorn.run(app, host=args.host, port=args.port, log_level=log_level)


if __name__ == "__main__":
    main()
