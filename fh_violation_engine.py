#!/usr/bin/env python3
"""
Verbose fronthaul rule engine
─────────────────────────────
• Scans dulogs.txt, cucplog.txt, ecpri_4.pcap
• Adds eCPRI-spec checks (rev, msgType, payload, seq-gap)
• Prints every violation to console
• Writes fh_protocol_violations_enhanced.json
"""

import re, json, pyshark, sys
from pathlib import Path
from datetime import datetime

BASE = Path("/home/users/praveen.joe/logs")
DU_LOG = BASE / "dulogs.txt"
CU_LOG = BASE / "cucplog.txt"
PCAP   = BASE / "ecpri_4.pcap"
OUT    = BASE / "fh_protocol_violations_enhanced.json"

DU_RULES = [
    {"pattern": r"(CRC error|PDSCH decoding failure)", "type": "DU Decode Error",
     "severity": "medium", "description": "CRC / decode failure"},
    {"pattern": r"Timing drift.*?(\\d+)ns", "type": "Timing Drift",
     "severity": "high", "description": "Timing drift"},
    {"pattern": r"Sync lost", "type": "DU Sync Loss",
     "severity": "high", "description": "Sync lost"}
]
CU_RULES = [
    {"pattern": r"F1SetupFailure", "type": "F1 Setup Failure",
     "severity": "high", "description": "F1 setup failed"},
    {"pattern": r"UEContextSetup.*?timeout", "type": "UE Context Setup Delay",
     "severity": "medium", "description": "UEContext delay"}
]

def log(msg): print(f"[fh_engine] {msg}")

def scan_log(path, rules, src):
    if not path.exists():
        log(f"WARNING: {path.name} not found"); return []
    log(f"Scanning {path.name}")
    evs=[]
    for line in path.read_text(errors="ignore").splitlines():
        for r in rules:
            if re.search(r["pattern"], line, re.IGNORECASE):
                ts=re.search(r"\\[(\\d{2}:\\d{2}:\\d{2})\\]", line)
                iso=datetime.utcnow().strftime("%Y-%m-%dT")+(ts.group(1) if ts else "00:00:00")+"Z"
                ev={"timestamp": iso, "type": r["type"], "description": r["description"],
                    "severity": r["severity"], "log_line": line.strip(), "source": src}
                evs.append(ev); log(f"  • {ev['type']} @ {ev['timestamp']}")
    log(f"Found {len(evs)} in {path.name}")
    return evs

def pcap_violation(pkt,vtype,desc,sev):
    log(f"  • {vtype} ({desc})")
    return {"timestamp": pkt.sniff_time.isoformat()+"Z","type":vtype,
            "description": desc,"severity": sev}

def parse_pcap(path):
    if not path.exists():
        log("WARNING: pcap not found"); return []
    log("Parsing eCPRI pcap …")
    cap=pyshark.FileCapture(str(path),keep_packets=False)
    out,last=[],None
    for pkt in cap:
        try:
            ok=(hasattr(pkt,"eth") and pkt.eth.type=="0xaefe") or "UDP" in pkt
            if not ok:
                out.append(pcap_violation(pkt,"Bad Transport","Not eCPRI Ethertype/UDP","high"));continue
            raw=bytes.fromhex((pkt.udp.payload if "UDP" in pkt else pkt.data.data).replace(":",""))
            if len(raw)<4: out.append(pcap_violation(pkt,"Short eCPRI","<4 bytes","high"));continue
            rev,mtype,size=raw[0]>>4,raw[1],int.from_bytes(raw[2:4],"big")
            if rev>2:    out.append(pcap_violation(pkt,"Rev >2",f"rev {rev}","medium"))
            if mtype>11: out.append(pcap_violation(pkt,"Unknown msgType",f"{mtype}","medium"))
            if len(raw)-4!=size:
                out.append(pcap_violation(pkt,"Payload mismatch",f"{size} hdr vs {len(raw)-4} act","high"))
            if mtype==0 and len(raw)>=8:
                seq=int.from_bytes(raw[6:8],"big")
                if last is not None and seq!=((last+1)&0xFFFF):
                    out.append(pcap_violation(pkt,"eCPRI Seq Gap",f"{last}->{seq}","high"))
                last=seq
        except Exception as e:
            out.append(pcap_violation(pkt,"PCAP Parse Error",str(e),"medium"))
    log(f"PCAP scan complete – {len(out)} violations")
    return out

def main():
    log("=== Fronthaul Violation Engine (verbose) ===")
    events=[]
    events+=scan_log(DU_LOG,DU_RULES,"DU")
    events+=scan_log(CU_LOG,CU_RULES,"CU")
    events+=parse_pcap(PCAP)
    OUT.write_text(json.dumps(events,indent=2))
    log(f"Total written: {len(events)} → {OUT}")

if __name__=="__main__": main()
