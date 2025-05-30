#!/usr/bin/env python3
import re, json, pyshark, sys, subprocess
from pathlib import Path
from datetime import datetime

BASE = Path("/home/users/praveen.joe/logs")
DU_LOG = BASE / "dulogs.txt"
CU_LOG = BASE / "cucplog.txt"
PCAP   = BASE / "ecpri_4.pcap"
OUT    = BASE / "fh_protocol_violations_enhanced.json"

DU_RULES = [
    {"pattern": r"(CRC error|PDSCH decoding failure)",
     "type": "DU Decode Error", "severity": "medium",
     "description": "CRC / decode failure"},
    {"pattern": r"Timing drift.*?(\\d+)ns",
     "type": "Timing Drift",     "severity": "high",
     "description": "Timing drift"},
    {"pattern": r"Sync lost",
     "type": "DU Sync Loss",     "severity": "high",
     "description": "Sync lost"}
]

CU_RULES = [
    {"pattern": r"F1SetupFailure",
     "type": "F1 Setup Failure", "severity": "high",
     "description": "F1 setup failed"},
    {"pattern": r"UEContextSetup.*?timeout",
     "type": "UE Context Setup Delay", "severity": "medium",
     "description": "UEContext delay"}
]

def get_event_time(dt=None):
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def log(msg: str) -> None:
    print(f"[fh_engine] {msg}")

def scan_log(path: Path, rules, source: str):
    if not path.exists():
        log(f"WARNING: {path.name} not found"); return []
    log(f"Scanning {path.name}")
    events = []
    for line in path.read_text(errors="ignore").splitlines():
        for rule in rules:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                ts = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", line)
                try:
                    iso = (datetime.utcnow().strftime("%Y-%m-%dT")
                       + (ts.group(1) if ts else "00:00:00") + "Z")
                    event_dt = datetime.strptime(iso.split("T")[0] + " " + iso.split("T")[1][:8], "%Y-%m-%d %H:%M:%S")
                except:
                    event_dt = datetime.utcnow()
                ev = {
                    "timestamp": iso,
                    "event_time": get_event_time(event_dt),
                    "type": rule["type"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "log_line": line.strip(),
                    "transport_ok": 1
                }
                events.append(ev)
                log(f"  • {ev['type']} @ {ev['timestamp']}")
    log(f"Found {len(events)} violations in {path.name}")
    return events

def is_ecpri_transport(pkt) -> bool:
    if hasattr(pkt, "eth") and pkt.eth.type == "0xaefe":
        return True
    if hasattr(pkt, "vlan") and getattr(pkt.vlan, "eth_type", None) == "0xaefe":
        return True
    if hasattr(pkt, "eth") and pkt.eth.type == "0x88a8" and hasattr(pkt, "vlan_inner"):
        if getattr(pkt.vlan_inner, "eth_type", None) == "0xaefe":
            return True
    if "udp" in pkt:
        return True
    return False

def pcap_violation(pkt, vtype, desc, sev):
    log(f"  • {vtype} ({desc})")
    ts = pkt.sniff_time
    if isinstance(ts, str):
        try:
            ts = datetime.strptime(ts.split("T")[0] + " " + ts.split("T")[1][:8], "%Y-%m-%d %H:%M:%S")
        except:
            ts = datetime.utcnow()
    elif not isinstance(ts, datetime):
        ts = datetime.utcnow()
    return {
        "timestamp": ts.isoformat(timespec="seconds")+"Z",
        "event_time": get_event_time(ts),
        "type": vtype,
        "description": desc,
        "severity": sev,
        "log_line": "",
        "transport_ok": 0 if "Bad Transport" in vtype else 1
    }

def parse_pcap(pcap_path: Path):
    if not pcap_path.exists():
        log("WARNING: pcap not found"); return []
    log("Parsing eCPRI pcap …")
    cap = pyshark.FileCapture(str(pcap_path), keep_packets=False)
    violations, last_seq = [], None

    for pkt in cap:
        try:
            if not is_ecpri_transport(pkt):
                violations.append(
                    pcap_violation(pkt, "Bad Transport",
                                   "Not eCPRI Ethertype / VLAN AEFE / UDP", "high"))
                continue

            raw_hex = (
                pkt.udp.payload if "udp" in pkt else
                getattr(pkt, "vlan_inner", pkt).data
            )
            raw_bytes = bytes.fromhex(raw_hex.replace(":", ""))

            if len(raw_bytes) < 4:
                violations.append(pcap_violation(pkt, "Short eCPRI", "<4 bytes", "high"))
                continue

            rev      = raw_bytes[0] >> 4
            msg_type = raw_bytes[1]
            payload_size = int.from_bytes(raw_bytes[2:4], "big")

            if rev > 2:
                violations.append(pcap_violation(pkt, "Rev >2", f"rev {rev}", "medium"))
            if msg_type > 11:
                violations.append(pcap_violation(pkt, "Unknown msgType", f"{msg_type}", "medium"))
            if len(raw_bytes) - 4 != payload_size:
                violations.append(pcap_violation(
                    pkt, "Payload mismatch",
                    f"{payload_size} hdr vs {len(raw_bytes)-4} act", "high"))

            if msg_type == 0 and len(raw_bytes) >= 8:
                seq = int.from_bytes(raw_bytes[6:8], "big")
                if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                    violations.append(pcap_violation(
                        pkt, "eCPRI Seq Gap", f"{last_seq}->{seq}", "high"))
                last_seq = seq

        except Exception as e:
            violations.append(pcap_violation(pkt, "PCAP Parse Error", str(e), "medium"))

    log(f"PCAP scan complete – {len(violations)} violations")
    return violations

def insert_to_clickhouse(records, table, fields):
    import tempfile
    if not records:
        now = get_event_time()
        records = [{
            "event_time": now,
            "type": "none",
            "severity": "none",
            "description": "NO_ANOMALY_FOUND",
            "log_line": "",
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

def main():
    log("=== Fronthaul Violation Engine (verbose, VLAN-aware) ===")
    events  = []
    events += scan_log(DU_LOG, DU_RULES, "DU")
    events += scan_log(CU_LOG, CU_RULES, "CU")
    events += parse_pcap(PCAP)
    if events:
        OUT.write_text(json.dumps(events, indent=2))
    else:
        default = {
            "status": "ok",
            "anomaly_count": 0,
            "message": "No anomalies or errors found in the input log.",
            "timestamp": "1970-01-01T00:00:00Z",
            "results": []
        }
        OUT.write_text(json.dumps(default, indent=2))
    log(f"Total written: {len(events)} → {OUT}")
    insert_to_clickhouse(
        events,
        "fh_violations",
        ["event_time", "type", "severity", "description", "log_line", "transport_ok"]
    )

if __name__ == "__main__":
    main()
