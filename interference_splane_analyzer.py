#!/usr/bin/env python3
"""
Rule engine: Interference & S-Plane delay issues.
Outputs interference_splane_issues.json
"""

import re, json
from pathlib import Path
from datetime import datetime

BASE=Path("/home/users/praveen.joe/logs")
DU=BASE/"dulogs.txt"
CU=BASE/"cucplog.txt"
OUT=BASE/"interference_splane_issues.json"

INT=r"SINR drop|RSRP at -\\d+ dBm|CRC error|Timing drift"
SPD=r"F1SetupRequest took (\\d+)ms|UEContextSetupRequest took (\\d+)ms|RRCSetup delayed"

def scan(file, patt):
    ev=[]
    if not file.exists(): return ev
    for ln in file.read_text(errors="ignore").splitlines():
        if re.search(patt,ln,re.I):
            ts=re.search(r"\\[(\\d{2}:\\d{2}:\\d{2})\\]",ln)
            iso=datetime.utcnow().strftime("%Y-%m-%dT")+(ts.group(1) if ts else "00:00:00")+"Z"
            ev.append({"timestamp":iso,"severity":"high","type":"interference" if patt==INT else "s_plane_delay",
                       "log_line":ln.strip()})
    return ev

def main():
    res=[]
    res+=scan(DU,INT)
    res+=scan(CU,SPD)
    OUT.write_text(json.dumps(res,indent=2))
    print("[int_rule] wrote",len(res),"issues →",OUT)

if __name__=="__main__": main()
