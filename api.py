# api.py
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn

from parser import parse_logs
from detector import detect_threats
from risk import calculate_risk
from ai_summary import generate_summary
from report import generate_report
from pydantic import BaseModel
from typing import Optional, List

try:
    from threat_intel import enrich_threats
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False




class ThreatItem(BaseModel):
    ip:            str
    attack:        str
    owasp:         Optional[str]   = None
    count:         int
    risk:          str
    abuse_score:   Optional[int]   = None
    threat_label:  Optional[str]   = None
    country:       Optional[str]   = None
    city:          Optional[str]   = None
    isp:           Optional[str]   = None
    is_tor:        Optional[bool]  = None

class AnalysisSummary(BaseModel):
    total_logs:       int
    total_threats:    int
    high_risk_count:  int
    unique_ips:       int

class AnalysisResult(BaseModel):
    total_logs:       int
    total_threats:    int
    high_risk_count:  int
    threats:          List[ThreatItem]      # was List[dict]
    summary:          AnalysisSummary       # was dict


# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SIEM Threat Detection API",
    description="AI-powered log analysis and threat detection",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory store (last analysis result) ────────────────────────────────────
_last_result: dict = {}


# ── Pydantic models ───────────────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    total_logs: int
    total_threats: int
    high_risk_count: int
    threats: list[dict]
    summary: dict


class HealthResponse(BaseModel):
    status: str
    intel_available: bool
    version: str


# ══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse, tags=["Meta"])
def health():
    """Check API status and available modules."""
    return {
        "status": "ok",
        "intel_available": INTEL_AVAILABLE,
        "version": "1.0.0",
    }


@app.post("/analyze", response_model=AnalysisResult, tags=["Analysis"])
async def analyze(file: UploadFile = File(...)):
    """
    Upload a log file and get back a full threat analysis.
    Accepts Apache / Nginx access log format.
    """
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(status_code=400,
                            detail="Only .log and .txt files are supported.")

    content = await file.read()
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded.")

    if not lines:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── Core pipeline (same order as app.py) ─────────────────────────────────
    parsed   = parse_logs(lines)
    threats  = detect_threats(parsed)
    threats  = calculate_risk(threats)

    if INTEL_AVAILABLE and threats:
        threats = enrich_threats(threats)

    # ── Summary dict from AI module ───────────────────────────────────────────
    import pandas as pd
    df = pd.DataFrame(threats) if threats else pd.DataFrame()
    raw_summary = generate_summary(df) if not df.empty else "No threats detected."

    # Structure the summary into sections for easy frontend consumption
    summary = _parse_summary(raw_summary)

    result = {
        "total_logs":      len(parsed),
        "total_threats":   len(threats),
        "high_risk_count": sum(1 for t in threats if t.get("risk") == "High"),
        "threats":         threats,
        "summary":         summary,
    }

    global _last_result
    _last_result = result          # cache for GET /threats

    return result


@app.get("/threats", tags=["Analysis"])
def get_threats(
    risk: Optional[str]   = Query(None, description="Filter by risk: High, Medium, Low"),
    attack: Optional[str] = Query(None, description="Filter by attack type substring"),
    limit: int            = Query(50, ge=1, le=500, description="Max results to return"),
):
    """
    Return threats from the most recent /analyze call.
    Supports filtering by risk level and attack type.
    """
    if not _last_result:
        raise HTTPException(
            status_code=404,
            detail="No analysis run yet. POST a log file to /analyze first."
        )

    threats = _last_result.get("threats", [])

    if risk:
        threats = [t for t in threats if t.get("risk", "").lower() == risk.lower()]
    if attack:
        threats = [t for t in threats
                   if attack.lower() in t.get("attack", "").lower()]

    return {
        "count":   len(threats[:limit]),
        "threats": threats[:limit],
        "filters": {"risk": risk, "attack": attack, "limit": limit},
    }


@app.get("/report", tags=["Analysis"])
def get_report():
    """Return the plain-text security report from the last analysis."""
    if not _last_result:
        raise HTTPException(status_code=404,
                            detail="No analysis run yet. POST to /analyze first.")
    import pandas as pd
    df     = pd.DataFrame(_last_result.get("threats", []))
    report = generate_report(df) if not df.empty else "No threats to report."
    return {"report": report}


@app.get("/stats", tags=["Analysis"])
def get_stats():
    """High-level stats from the last analysis — useful for dashboards."""
    if not _last_result:
        raise HTTPException(status_code=404,
                            detail="No analysis run yet. POST to /analyze first.")

    threats = _last_result.get("threats", [])
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}
    attack_counts: dict = {}

    for t in threats:
        r = t.get("risk", "Low")
        risk_counts[r] = risk_counts.get(r, 0) + 1
        a = t.get("attack", "Unknown")
        attack_counts[a] = attack_counts.get(a, 0) + 1

    return {
        "total_logs":    _last_result.get("total_logs", 0),
        "total_threats": _last_result.get("total_threats", 0),
        "risk_breakdown":   risk_counts,
        "attack_breakdown": attack_counts,
        "top_ips": _top_ips(threats, n=5),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────
def _parse_summary(raw: str) -> dict:
    """Split the AI free-text output into named sections."""
    sections = {"raw": raw, "executive": "", "remediation": "", "recommendations": ""}
    current = "executive"
    for line in raw.splitlines():
        low = line.lower()
        if "remediation" in low:
            current = "remediation"
        elif "recommend" in low:
            current = "recommendations"
        sections[current] += line + "\n"
    return sections


def _top_ips(threats: list, n: int = 5) -> list:
    ip_counts: dict = {}
    for t in threats:
        ip = t.get("ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + t.get("count", 1)
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)