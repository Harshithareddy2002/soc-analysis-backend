import os
import json
import pydantic
from typing import List, Dict, Any
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


# ── Pydantic schemas (Gemini structured output) ─────────────────────────────────

class Anomaly(pydantic.BaseModel):
    id: int
    reason: str
    confidence: int
    severity: str
    threat_type: str
    mitre_id: str
    tactic: str
    recommendation: str


class IncidentSummary(pydantic.BaseModel):
    anomalies: List[Anomaly]
    summary: str


class LogEntry(pydantic.BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination: str
    action: str
    bytes: int
    message: str
    raw: str


class ParsedLog(pydantic.BaseModel):
    entries: List[LogEntry]


# ── LLM fallback parser for unknown log formats ─────────────────────────────────

def parse_unknown_log(content: str) -> List[Dict[str, Any]]:
    sample_lines = '\n'.join(content.strip().split('\n')[:5])

    prompt = f"""
You are a log parsing expert.
Here are sample lines from an unknown log format:

{sample_lines}

Parse ALL these lines into structured entries:

{content[:2000]}
"""
    try:
        response = client.models.generate_content(
            model="models/gemini-3.1-flash-lite",
            contents=prompt,
            config=dict(
                response_mime_type="application/json",
                response_schema=ParsedLog,
            ),
        )
        result = json.loads(response.text)
        return result.get("entries", [])

    except Exception as e:
        print(f"LLM parser error: {e}")
        return []


# ── Rule-based anomaly detection (fallback when Gemini unavailable) ─────────────

MITRE_MAP = {
    'phish': ('Phishing', 'T1566', 'Initial Access', 'Block domain and reset credentials for affected user'),
    'credential': ('Credential Harvesting', 'T1556', 'Credential Access', 'Force password reset and enable MFA immediately'),
    'malware': ('Malware Delivery', 'T1105', 'Command and Control', 'Isolate host and run full EDR scan'),
    'trojan': ('Trojan', 'T1204', 'Execution', 'Isolate affected endpoint and initiate IR process'),
    'cobalt': ('C2 Beaconing', 'T1071', 'Command and Control', 'Immediately isolate host — CobaltStrike implant detected'),
    'beacon': ('C2 Beaconing', 'T1071', 'Command and Control', 'Isolate host and block C2 IP at perimeter firewall'),
    'botnet': ('Botnet C2', 'T1071', 'Command and Control', 'Block C2 IP and isolate affected endpoint'),
    'exfiltration': ('Data Exfiltration', 'T1041', 'Exfiltration', 'Block destination IP and initiate data breach response'),
    'ransomware': ('Ransomware', 'T1486', 'Impact', 'Isolate host immediately and initiate backup recovery'),
    'cryptomin': ('Cryptomining', 'T1496', 'Impact', 'Terminate miner process and patch entry point'),
    'miner': ('Cryptomining', 'T1496', 'Impact', 'Kill miner process and audit for persistence mechanisms'),
    'brute': ('Brute Force', 'T1110', 'Credential Access', 'Enable account lockout policy and MFA'),
    'scan': ('Network Scanning', 'T1046', 'Discovery', 'Review firewall rules and block scanning IP'),
    'powershell': ('Suspicious PowerShell', 'T1059.001', 'Execution', 'Review PowerShell logs and restrict execution policy'),
    'error': ('Service Error', 'T1499', 'Impact', 'Review service logs and check resource exhaustion'),
}


def _infer_mitre(raw: str, reasons: List[str]) -> tuple:
    raw_lower = raw.lower()
    for keyword, mapping in MITRE_MAP.items():
        if keyword in raw_lower:
            return mapping
    for reason in reasons:
        reason_lower = reason.lower()
        for keyword, mapping in MITRE_MAP.items():
            if keyword in reason_lower:
                return mapping
    return (
        'Suspicious Activity',
        'T1190',
        'Initial Access',
        'Investigate the flagged entry and escalate if needed',
    )


def rule_based_analysis(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    anomalies = []
    ip_counts: Dict[str, int] = {}

    for e in entries:
        reasons: List[str] = []
        severity = "Low"
        raw = e.get("raw", "")

        if "threatname=" in raw:
            threat = raw.split("threatname=")[1].split("|")[0].strip()
            if threat and threat != "None":
                reasons.append(f"Known threat detected: {threat}")
                severity = "Critical"

        if "threattype=" in raw:
            ttype = raw.split("threattype=")[1].split("|")[0].strip()
            if ttype and ttype not in ("None", ""):
                reasons.append(f"Threat type: {ttype}")
                severity = "Critical"

        if "action=Blocked" in raw or "action=BLOCKED" in raw:
            reasons.append("Connection blocked by security policy")
            if severity == "Low":
                severity = "Medium"

        try:
            if "outgoingbytes=" in raw:
                ob = int(raw.split("outgoingbytes=")[1].split("|")[0].strip())
                if ob > 10_000_000:
                    reasons.append(
                        f"Unusually large outgoing transfer: {ob / 1_000_000:.1f}MB — possible data exfiltration"
                    )
                    severity = "Critical"
        except (ValueError, IndexError):
            pass

        src_ip = e.get("source_ip", "unknown")
        dst = e.get("destination", "unknown")
        key = f"{src_ip}->{dst}"
        ip_counts[key] = ip_counts.get(key, 0) + 1

        suspicious_agents = ("curl", "powershell", "python", "wget", "custom_miner", "daemon")
        if "useragent=" in raw:
            ua = raw.split("useragent=")[1].split("|")[0].strip().lower()
            if any(agent in ua for agent in suspicious_agents):
                reasons.append(f"Suspicious user agent: {ua}")
                if severity == "Low":
                    severity = "Medium"

        if "Newly Registered" in raw:
            reasons.append("Connection to newly registered domain — common phishing indicator")
            if severity == "Low":
                severity = "Critical"

        if "url=http://" in raw and "threattype=" in raw:
            reasons.append("Unencrypted HTTP connection to suspicious destination")

        if reasons:
            threat_type, mitre_id, tactic, recommendation = _infer_mitre(raw, reasons)
            anomalies.append({
                "id": e["id"],
                "reason": " | ".join(reasons),
                "severity": severity,
                "confidence": 75 if severity == "Medium" else 90 if severity == "Critical" else 60,
                "threat_type": threat_type,
                "mitre_id": mitre_id,
                "tactic": tactic,
                "recommendation": recommendation,
            })

    # Second pass — flag repeated src→dst pairs as possible C2 beaconing
    flagged_ids = {a["id"] for a in anomalies}
    for e in entries:
        src_ip = e.get("source_ip", "unknown")
        dst = e.get("destination", "unknown")
        key = f"{src_ip}->{dst}"
        if (
            ip_counts.get(key, 0) >= 5
            and e["id"] not in flagged_ids
            and src_ip != "server"
            and dst != "internal"
        ):
            anomalies.append({
                "id": e["id"],
                "reason": f"Repeated connections from {src_ip} to {dst} — possible C2 beaconing",
                "severity": "Medium",
                "confidence": 78,
                "threat_type": "C2 Beaconing",
                "mitre_id": "T1071",
                "tactic": "Command and Control",
                "recommendation": "Block destination IP and investigate source host for compromise",
            })
            flagged_ids.add(e["id"])

    critical = sum(1 for a in anomalies if a["severity"] == "Critical")
    medium = sum(1 for a in anomalies if a["severity"] == "Medium")
    low = sum(1 for a in anomalies if a["severity"] == "Low")

    summary = (
        f"Analyzed {len(entries)} log entries. "
        f"Detected {len(anomalies)} anomalies — "
        f"{critical} Critical, {medium} Medium, {low} Low. "
    )
    if critical > 0:
        summary += (
            "Immediate investigation recommended for critical threats "
            "including malware, data exfiltration, and C2 beaconing activity."
        )

    return {"anomalies": anomalies, "summary": summary}


# ── Main analysis (Gemini with rule-based fallback) ─────────────────────────────

def analyze_logs(entries: List[Dict[str, Any]], log_type: str) -> Dict[str, Any]:
    log_text = "\n".join([
        f"ID:{e['id']} Time:{e['timestamp']} "
        f"SrcIP:{e['source_ip']} "
        f"Dst:{e['destination']} "
        f"Action:{e['action']} "
        f"Bytes:{e['bytes']} "
        f"Msg:{e.get('message', '')}"
        for e in entries[:20]
    ])

    prompt = f"""
You are an expert SOC analyst and threat intelligence engineer.
Analyze these {log_type} log entries and identify anomalies.

LOG ENTRIES:
{log_text}

Use this SOC priority framework:
- Critical: Allowed threats, outbound C2 callbacks, data exfiltration
- Medium: Blocked policy violations, brute force attempts
- Low: Standard blocked inbound noise

For each anomaly return:
- threat_type: e.g. "Malware Delivery", "C2 Beaconing", "Data Exfiltration"
- mitre_id: MITRE ATT&CK technique ID e.g. "T1566", "T1071"
- tactic: MITRE tactic e.g. "Initial Access", "Command and Control"
- recommendation: One specific actionable step for a SOC analyst

Return JSON:
{{
  "anomalies": [
    {{
      "id": <integer>,
      "reason": "<specific explanation>",
      "confidence": <0-100>,
      "severity": "<Critical|Medium|Low>",
      "threat_type": "<threat type>",
      "mitre_id": "<T####>",
      "tactic": "<MITRE tactic>",
      "recommendation": "<specific action>"
    }}
  ],
  "summary": "<2-3 sentence SOC analyst narrative>"
}}

Only flag genuinely suspicious entries.
Return ONLY valid JSON.
"""

    try:
        response = client.models.generate_content(
            model="models/gemini-3.1-flash-lite",
            contents=prompt,
            config=dict(
                response_mime_type="application/json",
                response_schema=IncidentSummary,
            ),
        )
        result = json.loads(response.text)
        result["detection_method"] = "gemini"
        return result

    except Exception as e:
        print(f"Gemini unavailable, using rule-based detection: {e}")
        result = rule_based_analysis(entries)
        result["detection_method"] = "rule-based"
        return result


# ── Merge anomaly flags onto parsed log entries ─────────────────────────────────

def enrich_entries(
    entries: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    anomaly_map = {a["id"]: a for a in anomalies}

    enriched = []
    for entry in entries:
        enriched_entry = entry.copy()
        if entry["id"] in anomaly_map:
            anomaly = anomaly_map[entry["id"]]
            enriched_entry["is_anomaly"] = True
            enriched_entry["anomaly_reason"] = anomaly.get("reason")
            enriched_entry["severity"] = anomaly.get("severity")
            enriched_entry["confidence"] = anomaly.get("confidence")
            enriched_entry["threat_type"] = anomaly.get("threat_type")
            enriched_entry["mitre_id"] = anomaly.get("mitre_id")
            enriched_entry["tactic"] = anomaly.get("tactic")
            enriched_entry["recommendation"] = anomaly.get("recommendation")
        else:
            enriched_entry["is_anomaly"] = False
            enriched_entry["anomaly_reason"] = None
            enriched_entry["severity"] = None
            enriched_entry["confidence"] = None
            enriched_entry["threat_type"] = None
            enriched_entry["mitre_id"] = None
            enriched_entry["tactic"] = None
            enriched_entry["recommendation"] = None
        enriched.append(enriched_entry)

    return enriched
