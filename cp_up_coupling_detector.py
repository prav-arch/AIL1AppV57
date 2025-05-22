#!/usr/bin/env python3
"""
cp_up_coupling_detector.py  (timestamp-safe, Py-3.6+)
"""
import re, json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

BASE = Path("/home/users/praveen.joe/logs")
CP_LOG = BASE / "cucplog.txt"
UP_LOG = BASE / "cuuplog.txt"
OUT    = BASE / "cp_up_coupling_issues.json"

PAT_CP = re.compile(r"RRC(Setup|Reestablishment|Release)|F1Setup|UEContextSetup", re.I)
PAT_UP = re.compile(r"DRB release|DL throughput drop|GTP-U tunnel drop|QoS mismatch", re.I)

def extract_time(line: str) -> Optional[datetime]:
    m = re.search(r"\[(\d{2}):(\d{2}):(\d{2})\]", line)
    if not m:
        return None
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
                res.append({
                    "timestamp": c["time"].isoformat(timespec="seconds")+"Z",
                    "type": "CP+UP coupling",
                    "severity": "critical",
                    "cp_log": c["log"],
                    "up_log": u["log"]
                })
    return res

def main():
    cp=parse(CP_LOG,PAT_CP,True)
    up=parse(UP_LOG,PAT_UP,False)
    out=correlate(cp,up)
    OUT.write_text(json.dumps(out,indent=2))
    print(f"[cp_up_rule] wrote {len(out)} coupling issues → {OUT}")

if __name__ == "__main__":
    main()
