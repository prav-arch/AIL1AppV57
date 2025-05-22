#!/usr/bin/env python3
"""
Self-contained CP+UP ML detector.
Auto-runs cp_up_coupling_detector.py if needed.
"""

import json, subprocess, sys
from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE=Path("/home/users/praveen.joe/logs")
IN_J=BASE/"cp_up_coupling_issues.json"
OUT_J=BASE/"cp_up_ml_anomalies.json"
ENGINE=BASE/"cp_up_coupling_detector.py"

def ensure(): 
    if IN_J.exists(): return
    if not ENGINE.exists(): sys.exit("rule engine missing")
    subprocess.run([sys.executable,str(ENGINE)],check=True)
    if not IN_J.exists(): sys.exit("engine failed")

def main():
    ensure()
    df=pd.read_json(IN_J)
    df["bucket"]=pd.to_datetime(df["timestamp"]).dt.floor("5min")
    df["crit"]=df["severity"]=="critical"
    feat=(df.groupby("bucket").agg(crit=("crit","sum"),total=("type","count")).reset_index())
    iso=IsolationForest(contamination=0.03,random_state=42)
    X=feat[["crit","total"]]
    feat["anomaly"]=iso.fit_predict(X)==-1
    feat["score"]=iso.decision_function(X)
    an=feat[feat["anomaly"]]
    out=[]
    for _,r in an.iterrows():
        row=r.to_dict()
        bucket=df[df["bucket"]==r["bucket"]]
        row["description"]=f"5-min window with {row['crit']} critical events ({row['total']} total)."
        row["log_entries"]=[(x.get("cp_log") or x.get("up_log") or x.get("log_line"))
                            for x in bucket.to_dict("records")][:30]
        row["events"]=bucket.to_dict("records")
        out.append(row)
    OUT_J.write_text(json.dumps(out,indent=2,default=str))
    print("[cp_up_ml] wrote",len(out),"anomalies →",OUT_J)

if __name__=="__main__": main()
