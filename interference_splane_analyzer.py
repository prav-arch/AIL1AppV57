#!/usr/bin/env python3
import re, json, subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

BASE = Path("/home/users/praveen.joe/logs")
DU_LOG = BASE / "dulogs.txt"
CU_LOG = BASE / "cucplog.txt"
OUT    = BASE / "interference_splane_issues.json"

PAT_INTERF = r"SINR drop|RSRP at -\d+\s*dBm|CRC error|Timing drift"
PAT_SPDLY  = r"F1SetupRequest took \d+ms|UEContextSetupRequest took \d+ms|RRCSetup delayed"

def get_event_time(dt=None):
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def build_timestamp(hms: Optional[str]) -> str:
    if hms:
        today = datetime.utcnow().strftime("%Y-%m-%dT")
        return f"{today}{hms}Z"
    return "1970-01-01T00:00:00Z"

def scan(path: Path, pat: str, itype: str):
    ev=[]
    if not path.exists():
        print(f"[int_rule] WARNING: {path.name} missing"); return ev
    rgx = re.compile(pat, re.I)
    for ln in path.read_text(errors="ignore").splitlines():
        if rgx.search(ln):
            t = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", ln)
            ts = build_timestamp(t.group(1) if t else None)
            # Parse timestamp to event_time
            try:
                event_dt = datetime.strptime(ts.split("T")[0] + " " + ts.split("T")[1][:8], "%Y-%m-%d %H:%M:%S")
            except:
                event_dt = datetime.utcnow()
            ev.append({
                "timestamp": ts,
                "event_time": get_event_time(event_dt),
                "type"     : itype,
                "severity" : "high",
                "log_line" : ln.strip()
            })
    print(f"[int_rule] {len(ev):>4} {itype} in {path.name}")
    return ev

def insert_to_clickhouse(records, table, fields):
    import tempfile
    if not records:
        now = get_event_time()
        records = [{
            "event_time": now,
            "type": "none",
            "severity": "none",
            "log_line": "NO_ANOMALY_FOUND"
        }]
    with tempfile.NamedTemporaryFile("w", delete=False) as fout:
        for row in records:
            out = {field: row.get(field, "") for field in fields}
            fout.write(json.dumps(out) + "\n")
        fname = fout.name
    cmd = [
        "clickhouse-client", "--host", "localhost",
        "--database", "l1_app_db",
        "--query", f"INSERT INTO {table} ({','.join(fields)}) FORMAT JSONEachRow"
    ]
    with open(fname, "rb") as fin:
        subprocess.run(cmd, stdin=fin)
    print(f"[ClickHouse] Inserted {len(records)} records into {table}")

def main():
    res  = scan(DU_LOG, PAT_INTERF, "interference")
    res += scan(CU_LOG, PAT_INTERF, "interference")
    res += scan(DU_LOG, PAT_SPDLY,  "s_plane_delay")
    res += scan(CU_LOG, PAT_SPDLY,  "s_plane_delay")
    if res:
        OUT.write_text(json.dumps(res, indent=2))
    else:
        default = {
            "status": "ok",
            "anomaly_count": 0,
            "message": "No anomalies or errors found in the input log.",
            "timestamp": "1970-01-01T00:00:00Z",
            "results": []
        }
        OUT.write_text(json.dumps(default, indent=2))
    print(f"[int_rule] wrote {len(res)} issues → {OUT}")
    insert_to_clickhouse(
        res,
        "interference_splane",
        ["event_time", "type", "severity", "log_line"]
    )

if __name__ == "__main__":
    main()
