#!/usr/bin/env python3
"""
Rule engine: CP + UP coupling detector.
Outputs cp_up_coupling_issues.json
"""

import re, json
from datetime import datetime, timedelta
from pathlib import Path

BASE=Path("/home/users/praveen.joe/logs")
CUCP=BASE/"cucplog.txt"
CUUP=BASE/"cuuplog.txt"
OUT =BASE/"cp_up_coupling_issues.json"

CP=r"RRC(Setup|Reestablishment|Release)|F1Setup|UEContextSetup"
UP=r"DRB release|DL throughput drop|GTP-U tunnel drop|QoS mismatch"

def parse(p, patt, cp=True):
    ev=[]
    if not p.exists(): return ev
    for ln in p.read_text(errors="ignore").splitlines():
        if re.search(patt,ln,re.I):
            tm=re.search(r"\\[(\\d{2}:\\d{2}:\\d{2})\\]",ln)
            if tm:
                t=datetime.strptime(tm.group(1),"%H:%M:%S")
                ev.append({"time":t,"log":ln.strip(),"cp":cp})
    return ev

def correlate(c,u):
    res=[]
    for x in c:
        for y in u:
            if abs((y["time"]-x["time"]).total_seconds())<=5:
                res.append({"timestamp":datetime.utcnow().isoformat()+"Z",
                            "type":"CP+UP coupling","severity":"critical",
                            "cp_log":x["log"],"up_log":y["log"]})
    return res

def main():
    cp=parse(CUCP,CP,True)
    up=parse(CUUP,UP,False)
    out=correlate(cp,up)
    OUT.write_text(json.dumps(out,indent=2))
    print("[cp_up_rule] wrote",len(out),"issues →",OUT)

if __name__=="__main__": main()
