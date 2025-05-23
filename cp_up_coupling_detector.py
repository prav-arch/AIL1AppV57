#!/usr/bin/env python3
import re, json, subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

BASE = Path("/home/users/praveen.joe/logs")
CP_LOG = BASE / "cucplog.txt"
UP_LOG = BASE / "cuuplog.txt"
OUT    = BASE / "cp_up_coupling_issues.json"

PAT_CP = re.compile(r"RRC(Setup|Reestablishment|Release)|F1Setup|UEContextSetup", re.I)
PAT_UP = re.compile(r"DRB release|DL throughput drop|GTP-U tunnel drop|QoS mismatch", re.I)

def get_event_time(dt=None):
    # Always return 'YYYY-MM-DD HH:MM:SS' for ClickHouse
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def extract_time(line: str) -> Optional[datetime]:
    m = re.search(r"\[(\d{2}):(\d{2}):(\d{2})\]", line)
    if not m: return None
    h,mn,s = map(int,m.groups())
    today  = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return today + timedelta(hours=h, minutes=mn, seconds=s)

def parse(path: Path, patt: re.Pattern, is_cp: bool):
    arr=[]
    if not path.exists():
        print(f"[cp_up_rule] WARNING: {path.name} missing"); return arr
    for ln in path.read_text(errors="ignore").splitlines():
        if patt.search(ln):
            ts = extract_time(ln) or datetime.utcnow()
            arr.append({"time": ts, "log": ln.strip(), "cp": is_cp})
    print(f"[cp_up_rule] {len(arr):>4} {'CP' if is_cp else 'UP'} events in {path.name}")
    return arr

def correlate(cp, up):
    res=[]
    for c in cp:
        for u in up:
            if abs((u["time"]-c["time"]).total_seconds()) <= 5:
                event_dt = c["time"]
                res.append({
                    "timestamp": event_dt.isoformat(timespec="seconds")+"Z",
                    "event_time": get_event_time(event_dt),
                    "severity": "critical",
                    "cp_log": c["log"],
                    "up_log": u["log"]
                })
    return res

def insert_to_clickhouse(records, table, fields):
    import tempfile
    if not records:
        now = get_event_time()
        records = [{
            "event_time": now,
            "severity": "none",
            "cp_log": "NO_ANOMALY_FOUND",
            "up_log": "NO_ANOMALY_FOUND"
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
    cp=parse(CP_LOG,PAT_CP,True)
    up=parse(UP_LOG,PAT_UP,False)
    out=correlate(cp,up)
    if out:
        OUT.write_text(json.dumps(out,indent=2))
    else:
        default = {
            "status": "ok",
            "anomaly_count": 0,
            "message": "No anomalies or errors found in the input log.",
            "timestamp": "1970-01-01T00:00:00Z",
            "results": []
        }
        OUT.write_text(json.dumps(default, indent=2))
    print(f"[cp_up_rule] wrote {len(out)} coupling issues → {OUT}")
    insert_to_clickhouse(
        out,
        "cp_up_coupling",
        ["event_time", "severity", "cp_log", "up_log"]
    )

if __name__ == "__main__":
    main()
