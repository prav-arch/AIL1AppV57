#!/usr/bin/env python3
import json
import pandas as pd
from pathlib import Path
import subprocess
from datetime import datetime, timedelta
import argparse

def get_event_time(dt=None):
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

INPUT_JSON = "/home/users/praveen.joe/logs/cp_up_coupling_issues.json"
OUTPUT_JSON = "/home/users/praveen.joe/logs/cp_up_ml_anomalies.json"

parser = argparse.ArgumentParser()
parser.add_argument('--demo', action='store_true', help='Generate demo anomalies instead of using real data')
args = parser.parse_args()

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

if args.demo:
    now = datetime.utcnow()
    demo_anomalies = [
        {
            "event_time": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "cp_log": "[10:55:30] RRCSetup: Setup failed for UE 3011",
            "up_log": "[10:55:30] DRB release: Unexpected DRB release detected for UE 3011"
        },
        {
            "event_time": (now - timedelta(minutes=4)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "major",
            "cp_log": "[10:56:45] F1Setup: F1 Setup rejected for DU 12",
            "up_log": "[10:56:45] DL throughput drop: Severe throughput degradation for DU 12"
        },
        {
            "event_time": (now - timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "minor",
            "cp_log": "[10:57:50] UEContextSetup: Context setup timeout for UE 3095",
            "up_log": "[10:57:50] GTP-U tunnel drop: Tunnel lost for UE 3095"
        },
        {
            "event_time": (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "warning",
            "cp_log": "[10:58:30] RRCRelease: Early release for UE 3033",
            "up_log": "[10:58:30] QoS mismatch: QoS config mismatch for UE 3033"
        },
        {
            "event_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "critical",
            "cp_log": "[11:00:00] RRCReestablishment: Failure detected for UE 3011",
            "up_log": "[11:00:00] DRB release: Unintended DRB release for UE 3011"
        }
    ]
    print(f"[DEMO] Generated {len(demo_anomalies)} demo anomalies.")
    insert_to_clickhouse(
        demo_anomalies,
        "cp_up_coupling",
        ["event_time", "severity", "cp_log", "up_log"]
    )
    Path(OUTPUT_JSON).write_text(json.dumps(demo_anomalies, indent=2))
    exit(0)

with open(INPUT_JSON) as f:
    data = json.load(f)

if not isinstance(data, list) or not data:
    print(f"[ML] No anomalies found in {INPUT_JSON}. Exiting.")
    Path(OUTPUT_JSON).write_text("[]")
    insert_to_clickhouse([], "cp_up_coupling", ["event_time", "severity", "cp_log", "up_log"])
    exit(0)

df = pd.DataFrame(data)
if "severity" not in df.columns:
    print(f"[ML] No 'severity' column in input data. Exiting.")
    Path(OUTPUT_JSON).write_text("[]")
    insert_to_clickhouse([], "cp_up_coupling", ["event_time", "severity", "cp_log", "up_log"])
    exit(0)

df["crit"] = df["severity"] == "critical"
anomalies = df[df["crit"]].to_dict(orient="records")
for a in anomalies:
    if "event_time" in a:
        try:
            dt = datetime.strptime(a["event_time"][:19], "%Y-%m-%d %H:%M:%S")
            a["event_time"] = get_event_time(dt)
        except Exception:
            a["event_time"] = get_event_time()
    else:
        a["event_time"] = get_event_time()
print(f"[ML] wrote {len(anomalies)} anomalies → {OUTPUT_JSON}")
Path(OUTPUT_JSON).write_text(json.dumps(anomalies, indent=2))
insert_to_clickhouse(anomalies, "cp_up_coupling", ["event_time", "severity", "cp_log", "up_log"])
