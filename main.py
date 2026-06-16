from dotenv import load_dotenv

load_dotenv()

import os

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.parser import parse_log
from app.analyzer import analyze_logs, enrich_entries

app = FastAPI(title="TENEX AI - Log Analysis API")

_allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "TENEX AI Backend Running"}


@app.post("/upload")
async def upload_log(file: UploadFile = File(...)):
    if not file.filename.endswith(('.log', '.txt')):
        raise HTTPException(status_code=400, detail="Only .log and .txt files supported")

    content = await file.read()
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    if not text.strip():
        raise HTTPException(status_code=400, detail="File is empty")

    # Parse → analyze → merge anomaly flags onto entries
    parsed = parse_log(text)
    analysis = analyze_logs(parsed["entries"], parsed["log_type"])
    anomalies = analysis.get("anomalies", [])
    enriched = enrich_entries(parsed["entries"], anomalies)

    # Weighted risk score from severity mix and anomaly density
    critical_count = sum(1 for a in anomalies if a.get("severity") == "Critical")
    medium_count = sum(1 for a in anomalies if a.get("severity") == "Medium")
    total = parsed["total_events"] or 1

    raw_score = (
        (critical_count * 25) +
        (medium_count * 10) +
        (len(anomalies) / total * 20)
    )
    risk_score = min(100, int(raw_score))

    risk_level = (
        "CRITICAL" if risk_score >= 80
        else "HIGH" if risk_score >= 60
        else "MEDIUM" if risk_score >= 40
        else "LOW"
    )

    return {
        "filename": file.filename,
        "total_events": parsed["total_events"],
        "summary": analysis.get("summary", ""),
        "detection_method": analysis.get("detection_method", "rule-based"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "entries": enriched
    }
