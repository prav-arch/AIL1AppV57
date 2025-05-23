#!/usr/bin/env python3
"""
interference_splane_analyzer.py
(timestamp-safe, emits default JSON if no anomaly)
"""
import re, json
from pathlib import Path
from datetime import datetime
from typing import Optional

BASE = Path("/home/users/praveen.joe/logs")
DU_LOG = BASE / "dulogs.txt"
CU_LOG = BASE / "cucplog.txt"
OUT    = BASE / "interference_splane_issues.json"

PAT_INTERF = r"SINR drop|RSRP at -\d+\s*dBm|CRC error|Timing drift"
PAT_SPDLY  = r"F1SetupRequest took \d+ms|UEContextSetupRequest took \d+ms|RRCSetup delayed"

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
            ev.append({
                "timestamp": build_timestamp(t.group(1) if t else None),
                "type"     : itype,
                "severity" : "high",
                "log_line" : ln.strip()
            })
    print(f"[int_rule] {len(ev):>4} {itype} in {path.name}")
    return ev

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

if __name__ == "__main__":
    main()
