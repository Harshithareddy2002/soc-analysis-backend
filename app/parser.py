import re
import csv
import io
import json
from typing import List, Dict, Any


# ── Format detection ────────────────────────────────────────────────────────────

def detect_log_type(content: str) -> str:
    first_lines = content.strip().split('\n')[:5]
    sample = ' '.join(first_lines)
    first_line = content.strip().split('\n')[0]

    # JSON structured logs
    try:
        json.loads(first_line)
        return 'json'
    except:
        pass

    # TSV - tab separated
    if '\t' in first_line:
        return 'tsv'

    # Key=Value pipe-separated (ZScaler modern format)
    if 'dateTime=' in sample and 'clientip=' in sample:
        return 'keyvalue'

    # ZScaler CSV with headers
    first_line_lower = first_line.lower()
    if ',' in first_line_lower and any(h in first_line_lower for h in 
        ['datetime', 'clientip', 'srcip', 'threatname', 'urlcategory']):
        return 'zscaler_csv_headers'

    # ZScaler CSV (quoted or uppercase action keywords)
    if (
        ('Blocked' in sample or 'Allowed' in sample) and '"' in sample
    ) or 'ALLOWED' in sample or 'BLOCKED' in sample:
        return 'zscaler'

    # Apache error log
    if re.search(r'\[\w+ \w+ \d+ \d+:\d+:\d+ \d+\] \[(notice|error|warn)\]', sample):
        return 'apache_error'

    # Apache combined access log
    if re.search(r'\d+\.\d+\.\d+\.\d+.*\[.*\].*"(GET|POST|PUT|DELETE)', sample):
        return 'apache'

    # Firewall log
    if 'IN=' in sample and 'OUT=' in sample and 'SRC=' in sample:
        return 'firewall'

    # NSS Web log (space separated with timestamp + action)
    if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', first_line):
        return 'nss'

    # Application/auth logs
    if 'ERROR' in sample or 'WARNING' in sample or 'Failed' in sample:
        return 'application'

    return 'generic'


# ── Per-format parsers ──────────────────────────────────────────────────────────

_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _is_valid_ip(value: str) -> bool:
    if not value or value in ('unknown', '-', 'server', 'internal'):
        return False
    return bool(_IPV4_RE.match(value.strip()))


def _find_ip_in_values(*values: str) -> str:
    for value in values:
        cleaned = value.strip().strip('"')
        if _is_valid_ip(cleaned):
            return cleaned
    return "unknown"


def _find_ip_in_row(row: List[str]) -> str:
    for value in row:
        cleaned = value.strip().strip('"')
        if _is_valid_ip(cleaned):
            return cleaned
    return "unknown"


def _find_status_code(row: List[str]) -> str:
    for value in row:
        cleaned = value.strip().strip('"')
        if cleaned.isdigit() and len(cleaned) == 3:
            return cleaned
    return "unknown"


def parse_keyvalue(content: str) -> List[Dict[str, Any]]:
    entries = []

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        try:
            fields = {}
            for part in line.split('|'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    fields[key.strip()] = value.strip()

            entries.append({
                "id": i + 1,
                "timestamp": fields.get("dateTime", "unknown"),
                "source_ip": _find_ip_in_values(fields.get("clientip", "")),
                "destination": fields.get("url", fields.get("serverip", "unknown")),
                "action": fields.get("action", "unknown"),
                "bytes": int(fields.get("outgoingbytes", 0) or 0),
                "user": fields.get("login", "unknown"),
                "threatname": fields.get("threatname", "None"),
                "threattype": fields.get("threattype", "None"),
                "useragent": fields.get("useragent", "unknown"),
                "category": fields.get("urlcategory", "unknown"),
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing keyvalue line {i}: {e}")
            continue

    return entries


def parse_tsv(content: str) -> List[Dict[str, Any]]:
    entries = []
    lines = content.strip().split('\n')

    if not lines:
        return entries

    first_line = lines[0].lower()
    has_headers = any(h in first_line for h in
        ['timestamp', 'datetime', 'action', 'clientip', 'url', 'user'])

    if has_headers:
        headers = [h.strip().lower() for h in lines[0].split('\t')]
        data_lines = lines[1:]
    else:
        headers = ['timestamp', 'action', 'reason', 'url',
                   'source_ip', 'destination_ip', 'user',
                   'department', 'duration']
        data_lines = lines

    for i, line in enumerate(data_lines):
        if not line.strip():
            continue
        try:
            values = line.split('\t')
            row = dict(zip(headers, values))

            entries.append({
                "id": i + 1,
                "timestamp": row.get("timestamp", row.get("datetime", "unknown")),
                "source_ip": _find_ip_in_values(
                    row.get("clientip", ""),
                    row.get("srcip", ""),
                    row.get("src_ip", ""),
                    row.get("source_ip", ""),
                ),
                "destination": row.get("url", row.get("dst", "unknown")),
                "action": row.get("action", "unknown"),
                "bytes": int(row.get("bytes", row.get("outgoingbytes", 0)) or 0),
                "user": row.get("user", row.get("login", "unknown")),
                "threatname": row.get("threatname", "None"),
                "threattype": row.get("threattype", "None"),
                "useragent": row.get("useragent", "unknown"),
                "category": row.get("urlcategory", row.get("category", "unknown")),
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing TSV line {i}: {e}")
            continue

    return entries


def parse_zscaler(content: str) -> List[Dict[str, Any]]:
    entries = []
    reader = csv.reader(io.StringIO(content))

    for i, row in enumerate(reader):
        if not row or len(row) < 10:
            continue
        try:
            entries.append({
                "id": i + 1,
                "timestamp": row[0].strip('"'),
                "source_ip": _find_ip_in_row(row),
                "destination": row[3].strip('"') if len(row) > 3 else "unknown",
                "action": row[4].strip('"') if len(row) > 4 else "unknown",
                "bytes": int(row[8].strip('"')) if len(row) > 8 and row[8].strip('"').isdigit() else 0,
                "method": row[20].strip('"') if len(row) > 20 else "unknown",
                "status_code": _find_status_code(row),
                "user_agent": row[22].strip('"') if len(row) > 22 else "unknown",
                "category": row[7].strip('"') if len(row) > 7 else "unknown",
                "raw": ','.join(row)
            })
        except Exception as e:
            print(f"Error parsing ZScaler row {i}: {e}")
            continue

    return entries


def parse_zscaler_csv_headers(content: str) -> List[Dict[str, Any]]:
    entries = []
    lines = content.strip().split('\n')

    if not lines:
        return entries

    headers = [h.strip().lower().replace(' ', '_')
               for h in lines[0].split(',')]

    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            continue
        try:
            values = list(csv.reader([line]))[0]
            row = dict(zip(headers, values))

            entries.append({
                "id": i,
                "timestamp": row.get("datetime", row.get("timestamp", "unknown")),
                "source_ip": _find_ip_in_values(
                    row.get("clientip", ""),
                    row.get("srcip", ""),
                    row.get("src_ip", ""),
                ),
                "destination": row.get("url", row.get("dst", row.get("destination", "unknown"))),
                "action": row.get("action", "unknown"),
                "bytes": int(row.get("outgoingbytes", row.get("bytes", 0)) or 0),
                "user": row.get("login", row.get("user", "unknown")),
                "threatname": row.get("threatname", "None"),
                "threattype": row.get("threattype", "None"),
                "useragent": row.get("useragent", "unknown"),
                "category": row.get("urlcategory", row.get("category", "unknown")),
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing CSV header row {i}: {e}")
            continue

    return entries


def parse_apache(content: str) -> List[Dict[str, Any]]:
    entries = []
    pattern = r'(\S+) \S+ (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "?(.*?)"? "?(.*?)"?$'

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        if line.startswith('LogFormat') or line.startswith('#'):
            continue

        match = re.match(pattern, line)
        try:
            if match:
                request = match.group(4).split()
                method = request[0] if len(request) > 0 else "unknown"
                url = request[1] if len(request) > 1 else "/"
                prefix_tokens = line.split('[')[0].strip().split()

                entries.append({
                    "id": i + 1,
                    "timestamp": match.group(3),
                    "source_ip": _find_ip_in_values(*prefix_tokens[:3]),
                    "destination": url,
                    "action": f"{method} {match.group(5)}",
                    "bytes": int(match.group(6)) if match.group(6) != '-' else 0,
                    "user": match.group(2),
                    "status_code": match.group(5),
                    "referer": match.group(7),
                    "user_agent": match.group(8),
                    "raw": line
                })
            else:
                entries.append({
                    "id": i + 1,
                    "timestamp": "unknown",
                    "source_ip": "unknown",
                    "destination": "unknown",
                    "action": "unknown",
                    "bytes": 0,
                    "raw": line
                })
        except Exception as e:
            print(f"Error parsing Apache line {i}: {e}")
            continue

    return entries


def parse_apache_error(content: str) -> List[Dict[str, Any]]:
    entries = []
    pattern = r'\[(.*?)\] \[(\w+)\] (.*)'

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue

        match = re.match(pattern, line)
        try:
            if match:
                entries.append({
                    "id": i + 1,
                    "timestamp": match.group(1),
                    "source_ip": "server",
                    "destination": "internal",
                    "action": match.group(2).upper(),
                    "bytes": 0,
                    "message": match.group(3),
                    "raw": line
                })
            else:
                entries.append({
                    "id": i + 1,
                    "timestamp": "unknown",
                    "source_ip": "server",
                    "destination": "internal",
                    "action": "unknown",
                    "bytes": 0,
                    "message": line,
                    "raw": line
                })
        except Exception as e:
            print(f"Error parsing Apache error line {i}: {e}")
            continue

    return entries


def parse_firewall(content: str) -> List[Dict[str, Any]]:
    entries = []

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        try:
            fields = {}
            # Extract key=value pairs
            for match in re.finditer(r'(\w+)=(\S+)', line):
                fields[match.group(1)] = match.group(2)

            # Extract action from brackets
            action_match = re.search(r'\[([^\]]+)\]', line)
            action = action_match.group(1) if action_match else "unknown"

            # Extract timestamp
            ts_match = re.match(r'(\w+ \d+ \d+:\d+:\d+)', line)
            timestamp = ts_match.group(1) if ts_match else "unknown"

            entries.append({
                "id": i + 1,
                "timestamp": timestamp,
                "source_ip": _find_ip_in_values(fields.get("SRC", "")),
                "destination": fields.get("DST", "unknown"),
                "action": action,
                "bytes": int(fields.get("LEN", 0) or 0),
                "protocol": fields.get("PROTO", "unknown"),
                "src_port": fields.get("SPT", "unknown"),
                "dst_port": fields.get("DPT", "unknown"),
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing firewall line {i}: {e}")
            continue

    return entries


def parse_nss(content: str) -> List[Dict[str, Any]]:
    entries = []

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        try:
            parts = line.split()
            entries.append({
                "id": i + 1,
                "timestamp": parts[0] if len(parts) > 0 else "unknown",
                "action": parts[1] if len(parts) > 1 else "unknown",
                "destination": parts[3] if len(parts) > 3 else "unknown",
                "source_ip": _find_ip_in_values(parts[4] if len(parts) > 4 else ""),
                "bytes": 0,
                "user": parts[6] if len(parts) > 6 else "unknown",
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing NSS line {i}: {e}")
            continue

    return entries


def parse_json_logs(content: str) -> List[Dict[str, Any]]:
    entries = []

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        try:
            log = json.loads(line)
            entries.append({
                "id": i + 1,
                "timestamp": log.get("timestamp", "unknown"),
                "source_ip": _find_ip_in_values(
                    log.get("client_ip", ""),
                    log.get("clientip", ""),
                ),
                "destination": log.get("url", log.get("trace_id", "unknown")),
                "action": log.get("action", log.get("level", "unknown")),
                "bytes": int(log.get("bytes", log.get("outgoingbytes", 0)) or 0),
                "user": log.get("user", log.get("login", "unknown")),
                "threatname": log.get("threatname", "None"),
                "threattype": log.get("threattype", "None"),
                "message": log.get("message", ""),
                "extra": {
                    k: v for k, v in log.items()
                    if k not in ["timestamp", "action", "url", "client_ip",
                                 "service", "trace_id", "level", "message"]
                },
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing JSON line {i}: {e}")
            continue

    return entries


def parse_application(content: str) -> List[Dict[str, Any]]:
    entries = []

    for i, line in enumerate(content.strip().split('\n')):
        if not line.strip():
            continue
        parts = line.split()
        try:
            entries.append({
                "id": i + 1,
                "timestamp": f"{parts[0]} {parts[1]}" if len(parts) > 1 else "unknown",
                "source_ip": _find_ip_in_values(*parts),
                "destination": "internal",
                "action": parts[2] if len(parts) > 2 else "unknown",
                "bytes": 0,
                "message": ' '.join(parts[3:]) if len(parts) > 3 else line,
                "raw": line
            })
        except Exception as e:
            print(f"Error parsing application line {i}: {e}")
            continue

    return entries


# ── Entry point: detect format and dispatch to the matching parser ──────────────

def parse_log(content: str) -> Dict[str, Any]:
    log_type = detect_log_type(content)

    if log_type == 'keyvalue':
        entries = parse_keyvalue(content)
    elif log_type == 'tsv':
        entries = parse_tsv(content)
    elif log_type == 'zscaler_csv_headers':
        entries = parse_zscaler_csv_headers(content)
    elif log_type == 'zscaler':
        entries = parse_zscaler(content)
    elif log_type == 'apache':
        entries = parse_apache(content)
    elif log_type == 'apache_error':
        entries = parse_apache_error(content)
    elif log_type == 'firewall':
        entries = parse_firewall(content)
    elif log_type == 'nss':
        entries = parse_nss(content)
    elif log_type == 'json':
        entries = parse_json_logs(content)
    elif log_type == 'application':
        entries = parse_application(content)
    else:
        from app.analyzer import parse_unknown_log
        entries = parse_unknown_log(content)
        log_type = 'auto-detected'

    return {
        "log_type": log_type,
        "total_events": len(entries),
        "entries": entries
    }