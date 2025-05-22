#!/usr/bin/env python3
"""
Self-contained Interference / S-Plane ML detector.
Auto-runs interference_splane_analyzer.py if needed.
"""

import json, subprocess, sys
from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE=Path("/home/users/praveen.joe/logs")
IN_J=BASE/"interference_splane_issues.json"
OUT_J=BASE/"interference_splane_ml_anomalies.json"
ENGINE=BASE/"interference_splane_analyzer.py"

def ensure():
    if IN_J.exists(): return
    if not ENGINE.exists(): sys.exit("rule engine missing")
    subprocess.run([sys.executable,str(ENGINE)],check=True)
    if not IN_J.exists(): sys.exit("engine failed")

def main():
    ensure()
    df=pd.read_json(IN_J)
    df["date"]=pd.to_datetime(df["timestamp"]).dt.date
    df["high"]=df["severity"]=="high"
    feat=(df.groupby("date").agg(total=("type","count"),hi=("high","sum")).reset_index())
    iso=IsolationForest(contamination=0.05,random_state=42)
    X=feat[["total","hi"]]
    feat["anomaly"]=iso.fit_predict(X)==-1
    feat["score"]=iso.decision_function(X)
    an=feat[feat["anomaly"]]
    out=[]
    for _,r in an.iterrows():
        day_df=df[df["date"]==r["date"]]
        rec=r.to_dict()
        rec["description"]=f"Day with {rec['hi']} high-severity events ({rec['total']} total)."
        rec["log_entries"]=day_df["log_line"].tolist()[:40]
        rec["events"]=day_df.to_dict("records")
        out.append(rec)
    OUT_J.write_text(json.dumps(out,indent=2,default=str))
    print("[int_ml] wrote",len(out),"anomalies →",OUT_J)

if __name__=="__main__": main()
