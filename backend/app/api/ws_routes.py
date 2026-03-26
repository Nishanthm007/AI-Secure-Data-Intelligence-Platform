import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..services.detector import detect, mask_content
from ..services.risk_engine import calculate_score, classify_level, build_summary
from ..services.ai_service import generate_ai_insights
from ..models.schemas import AnalysisOptions

ws_router = APIRouter()


@ws_router.websocket("/ws/analyze")
async def ws_stream_analyze(websocket: WebSocket):
    """
    Real-time log streaming analysis.
    Client sends: {"content": "...", "options": {...}}
    Server streams:
      {"type": "progress", "line": N, "total": N, "percent": N}
      {"type": "finding",  "finding": {...}}
      {"type": "complete", "summary": ..., "risk_score": ..., ...}
      {"type": "error",    "message": ...}
    """
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        data = json.loads(raw)

        content = data.get("content", "").strip()
        if not content:
            await websocket.send_json({"type": "error", "message": "No content provided."})
            return

        opts = AnalysisOptions(**data.get("options", {}))
        lines = content.splitlines()
        total = len(lines)

        await websocket.send_json({"type": "start", "total_lines": total})

        all_findings = []
        line_risks: dict = {}

        for i, line in enumerate(lines, 1):
            line_findings = detect(line, line_offset=i - 1)

            if line_findings:
                severity_order = ["critical", "high", "medium", "low"]
                highest = min(line_findings, key=lambda f: severity_order.index(f.risk))
                line_risks[str(i)] = highest.risk

                for f in line_findings:
                    all_findings.append(f)
                    await websocket.send_json({
                        "type": "finding",
                        "finding": {
                            "type": f.type,
                            "risk": f.risk,
                            "value": f.value,
                            "line": f.line,
                            "context": f.context,
                        },
                    })

            # Send progress every 5 lines or on last line
            if i % 5 == 0 or i == total:
                await websocket.send_json({
                    "type": "progress",
                    "line": i,
                    "total": total,
                    "percent": round(i / total * 100),
                })

            # Yield control every 100 lines so the event loop stays responsive
            if i % 100 == 0:
                await asyncio.sleep(0)

        score = calculate_score(all_findings)
        level = classify_level(score)
        summary = build_summary(all_findings, "log")
        insights = await generate_ai_insights(all_findings, "log", content[:500])
        masked = mask_content(content) if opts.mask else content

        await websocket.send_json({
            "type": "complete",
            "summary": summary,
            "risk_score": score,
            "risk_level": level,
            "total_findings": len(all_findings),
            "insights": insights,
            "masked_content": masked,
            "line_risks": line_risks,
        })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
