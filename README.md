# SOC Log Analysis — Backend

FastAPI service that accepts security log files, parses multiple formats, detects anomalies with Gemini (and rule-based fallback), and returns enriched analysis JSON for the frontend dashboard.

**Repo:** [soc-analysis-backend](https://github.com/Harshithareddy2002/soc-analysis-backend)  
**Frontend:** [soc-analysis-frontend](https://github.com/Harshithareddy2002/soc-analysis-frontend)

---

## Quick start

### Prerequisites

- Python 3.12+
- Gemini API key

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # add GEMINI_API_KEY
uvicorn main:app --reload --port 8000
```

API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### Test upload

```bash
curl -X POST http://localhost:8000/upload \
  -F "file=@/path/to/your.log"
```

---

## Environment variables

Copy `.env.example` to `.env`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes | — | Google Gemini API key |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | Comma-separated CORS origins for the frontend |

---

## API

### `GET /`

Health check — returns API status.

### `POST /upload`

Upload a `.log` or `.txt` file (UTF-8) for parsing and analysis.

**Response fields**

| Field | Description |
|-------|-------------|
| `filename` | Uploaded file name |
| `total_events` | Number of parsed log lines |
| `summary` | AI-generated incident narrative |
| `detection_method` | `gemini` or `rule-based` |
| `risk_score` | 0–100 weighted score |
| `risk_level` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `entries` | Parsed log entries with anomaly enrichment |

**Enrichment fields on each entry** (when flagged as anomaly)

| Field | Description |
|-------|-------------|
| `is_anomaly` | Whether the entry was flagged |
| `anomaly_reason` | Human-readable explanation |
| `severity` | Critical, Medium, or Low |
| `confidence` | 0–100 (Gemini detections) |
| `threat_type` | e.g. Brute Force, C2 Beaconing |
| `mitre_id` | MITRE ATT&CK technique ID |
| `tactic` | e.g. Credential Access |
| `recommendation` | Suggested SOC action |

**Errors**

| Code | Reason |
|------|--------|
| 400 | Wrong file type, not UTF-8, or empty file |

**Risk scoring**

```
score = min(100, critical×25 + medium×10 + (anomaly_count / total_events)×20)
```

| Score | Level |
|-------|-------|
| ≥ 80 | CRITICAL |
| ≥ 60 | HIGH |
| ≥ 40 | MEDIUM |
| < 40 | LOW |

---

## How it works

1. **Parse** (`app/parser.py`) — Detect log format, normalize each line into a standard entry shape, validate source IPs.
2. **Analyze** (`app/analyzer.py`) — Gemini analyzes a sample of entries; rule-based fallback runs if Gemini is unavailable.
3. **Enrich** (`app/analyzer.py`) — Merge anomaly metadata (severity, MITRE, recommendations) onto matching entries.
4. **Score** (`main.py`) — Compute risk score and level from anomaly severity mix and density.

---

## Supported log formats

| Format | Detection signal |
|--------|------------------|
| ZScaler key=value | `dateTime=` + `clientip=` |
| ZScaler CSV | Column headers or `ALLOWED` / `BLOCKED` rows |
| Apache access | IP + HTTP method pattern |
| Apache error | `[date] [error\|warn\|notice]` |
| Firewall | `IN=`, `OUT=`, `SRC=` |
| JSON (NDJSON) | Valid JSON per line |
| TSV | Tab-separated values |
| NSS | ISO timestamp prefix |
| Application | `ERROR`, `WARNING`, `Failed` |
| Unknown | Gemini-assisted parsing fallback |

---

## Project structure

```
main.py              FastAPI app, CORS, /upload, risk scoring
requirements.txt     Dependencies
.env.example         Environment template
app/
  parser.py          Format detection and per-format parsers
  analyzer.py        Gemini analysis, rule fallback, enrichment
```

---

## Notes for reviewers

| File | Focus |
|------|-------|
| `main.py` | Upload validation, orchestration, risk scoring |
| `app/parser.py` | Format detection, IP validation, column mapping |
| `app/analyzer.py` | Gemini prompt, rule logic, enrichment fields |

- Stateless API — no database; frontend stores results after upload
- Gemini analyzes the first 20 entries for cost/latency balance - I limited the AI context window to 20 events as I was using the Gemini free tier. The architecture is intentionally modular, so the next step would be to use the existing rule-based detection layer as a pre-filter and only send high-risk events to the LLM - but the full file is still parsed
- Rule-based detection ensures analysis runs when Gemini is unavailable
- IPv4 validation prevents non-IP tokens from appearing as source IPs
- There is a sample file (sample.log) available for testing

---


## Tech stack

FastAPI · Google Gemini (`google-genai`) · Pydantic · python-multipart · uvicorn
