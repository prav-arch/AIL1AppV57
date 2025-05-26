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

INPUT_JSON = "/home/users/praveen.joe/logs/fh_protocol_violations_enhanced.json"
OUTPUT_JSON = "/home/users/praveen.joe/logs/fh_ml_anomalies.json"

parser = argparse.ArgumentParser()
parser.add_argument('--demo', action='store_true', help='Generate demo anomalies instead of using real data')
args = parser.parse_args()

def insert_to_clickhouse(records, table, fields):
    import tempfile
    if not records:
        now = get_event_time()
        records = [{
            "event_time": now,
            "type": "none",
            "severity": "none",
            "description": "NO_ANOMALY_FOUND",
            "log_line": "NO_ANOMALY_FOUND",
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

if args.demo:
    now = datetime.utcnow()
    demo_anomalies = [
        {
            "event_time": (now - timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "DU Decode Error",
            "severity": "high",
            "description": "CRC / decode failure detected in DU log",
            "log_line": "[08:48:11] DU[2] CRC error: Block 32, CRC=0xA21B, UEID=204, Decoding failed.",
            "transport_ok": 1
        },
        {
            "event_time": (now - timedelta(minutes=11)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "Timing Drift",
            "severity": "medium",
            "description": "Timing drift over 1000ns",
            "log_line": "[08:49:15] DU[5] Timing drift detected: 1200ns. Sync lost after frame 11014.",
            "transport_ok": 1
        },
        {
            "event_time": (now - timedelta(minutes=8)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "F1 Setup Failure",
            "severity": "high",
            "description": "F1 setup failed in CU",
            "log_line": "[08:52:05] CU F1SetupFailure: DU_ID=7, Cause=Timeout, No response from DU.",
            "transport_ok": 1
        },
        {
            "event_time": (now - timedelta(minutes=6)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "eCPRI Seq Gap",
            "severity": "high",
            "description": "Gap detected in eCPRI sequence (100 -> 102)",
            "log_line": "[08:54:00] eCPRI stream[12] sequence gap: expected 101, got 102, last seen=100.",
            "transport_ok": 0
        },
        {
            "event_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "type": "PCAP Parse Error",
            "severity": "medium",
            "description": "Malformed eCPRI packet detected in capture",
            "log_line": "[09:00:00] PCAP parsing error: packet 9902 malformed, insufficient header length.",
            "transport_ok": 0
        }
    ]
    print(f"[DEMO] Generated {len(demo_anomalies)} demo anomalies.")
    insert_to_clickhouse(
        demo_anomalies,
        "fh_violations",
        ["event_time", "type", "severity", "description", "log_line", "transport_ok"]
    )
    Path(OUTPUT_JSON).write_text(json.dumps(demo_anomalies, indent=2))
    exit(0)

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
insert_to_clickhouse(anomalies, "fh_violations", ["event_time", "type", "severity", "description", "log_line", "transport_ok"])
