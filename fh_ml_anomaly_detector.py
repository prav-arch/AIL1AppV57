#!/usr/bin/env python3
"""
Self-contained fronthaul ML detector.
– Auto-runs fh_violation_engine.py if violations JSON is absent.
"""

import json, subprocess, sys
from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE  = Path("/home/users/praveen.joe/logs")
IN_J  = BASE / "fh_protocol_violations_enhanced.json"
OUT_J = BASE / "fh_ml_anomalies.json"
ENGINE= BASE / "fh_violation_engine.py"

def ensure_json():
    if IN_J.exists(): return
    print("[fh_ml] running rule engine …")
    if not ENGINE.exists(): sys.exit("fh_violation_engine.py missing")
    subprocess.run([sys.executable, str(ENGINE)], check=True)
    if not IN_J.exists(): sys.exit("rule engine failed")

def main():
    ensure_json()
    df = pd.read_json(IN_J)
    df["bucket"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
    df["high"]   = df["severity"].isin(["high","critical"])
    feat=(df.groupby("bucket").agg(total=("type","count"),
                                   hi=("high","sum"),
                                   types=("type","nunique")).reset_index())
    iso=IsolationForest(contamination=0.05,random_state=42)
    X=feat[["total","hi","types"]]
    feat["anomaly"]=iso.fit_predict(X)==-1
    feat["score"]=iso.decision_function(X)
    anom=feat[feat["anomaly"]]
    out=[]
    for _,r in anom.iterrows():
        row=r.to_dict()
        row["description"]=f"Minute bucket has {row['hi']} high/critical events ({row['total']} total)."
        bucket_df=df[df["bucket"]==r["bucket"]]
        row["log_entries"]=bucket_df["log_line"].tolist()[:20]
        row["events"]=bucket_df.to_dict("records")
        out.append(row)
    OUT_J.write_text(json.dumps(out,indent=2))
    print("[fh_ml] wrote",len(out),"anomalies →",OUT_J)

if __name__=="__main__": main()
