#!/usr/bin/env python3
import json
import pandas as pd
from pathlib import Path
import subprocess
from datetime import datetime

INPUT_JSON = "/home/users/praveen.joe/logs/fh_protocol_violations_enhanced.json"
OUTPUT_JSON = "/home/users/praveen.joe/logs/fh_ml_anomalies.json"

def insert_to_clickhouse(records, table, fields):
    import tempfile
    if not records:
        now = datetime.utcnow().isoformat(sep=' ')
        records = [{
            "event_time": now,
            "type": "none",
            "severity": "none",
            "description": "NO_ANOMALY_FOUND",
            "log_line": "",
            "transport_ok": 1
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

with open(INPUT_JSON) as f:
    data = json.load(f)

if not isinstance(data, list) or not data:
    print(f"[ML] No anomalies found in {INPUT_JSON}. Exiting.")
    Path(OUTPUT_JSON).write_text("[]")
    insert_to_clickhouse([], "fh_violations", ["event_time", "type", "severity", "description", "log_line", "transport_ok"])
    exit(0)

df = pd.DataFrame(data)
if "severity" not in df.columns:
    print(f"[ML] No 'severity' column in input data. Exiting.")
    Path(OUTPUT_JSON).write_text("[]")
    insert_to_clickhouse([], "fh_violations", ["event_time", "type", "severity", "description", "log_line", "transport_ok"])
    exit(0)

df["is_anom"] = df["severity"].isin(["high", "critical"])
anomalies = df[df["is_anom"]].to_dict(orient="records")
print(f"[ML] wrote {len(anomalies)} anomalies → {OUTPUT_JSON}")
Path(OUTPUT_JSON).write_text(json.dumps(anomalies, indent=2))
insert_to_clickhouse(anomalies, "fh_violations", ["event_time", "type", "severity", "description", "log_line", "transport_ok"])
