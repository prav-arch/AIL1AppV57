#!/usr/bin/env python3
"""
fh_violation_engine.py  —  verbose & VLAN-aware
────────────────────────────────────────────────
• Scans dulogs.txt, cucplog.txt, ecpri_4.pcap
• Detects log-based and eCPRI-spec violations
• Transport check recognises:
      – Native Ethertype 0xAEFE
      – 802.1Q single-tag VLAN (outer 0x8100, inner 0xAEFE)
      – 802.1ad QinQ       (outer 0x88A8, inner VLAN.eth_type 0xAEFE)
      – UDP/IP (eCPRI over UDP)
• Prints each violation to console
• Writes fh_protocol_violations_enhanced.json
"""

import re, json, pyshark, sys
from pathlib import Path
from datetime import datetime

# ─────────────── configuration ────────────────
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

# ─────────────── helpers ──────────────────────
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
                ts = re.search(r"\\[(\\d{2}:\\d{2}:\\d{2})\\]", line)
                iso = (datetime.utcnow().strftime("%Y-%m-%dT")
                       + (ts.group(1) if ts else "00:00:00") + "Z")
                ev = {
                    "timestamp": iso,
                    "type": rule["type"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "log_line": line.strip(),
                    "source": source
                }
                events.append(ev)
                log(f"  • {ev['type']} @ {ev['timestamp']}")
    log(f"Found {len(events)} violations in {path.name}")
    return events

def pcap_violation(pkt, vtype, desc, sev):
    log(f"  • {vtype} ({desc})")
    return {
        "timestamp": pkt.sniff_time.isoformat() + "Z",
        "type": vtype,
        "description": desc,
        "severity": sev
    }

# Transport recogniser -------------------------------------------------
def is_ecpri_transport(pkt) -> bool:
    """
    True if native AEFE, VLAN-tagged AEFE, QinQ AEFE, or UDP/IP.
    """
    # Native Ethertype 0xAEFE
    if hasattr(pkt, "eth") and pkt.eth.type == "0xaefe":
        return True
    # Single 802.1Q tag: eth.type 0x8100, inside vlan.eth_type = 0xAEFE
    if hasattr(pkt, "vlan") and getattr(pkt.vlan, "eth_type", None) == "0xaefe":
        return True
    # QinQ 802.1ad: outer 0x88A8, inner vlan_inner.eth_type = 0xAEFE
    if hasattr(pkt, "eth") and pkt.eth.type == "0x88a8" and hasattr(pkt, "vlan_inner"):
        if getattr(pkt.vlan_inner, "eth_type", None) == "0xaefe":
            return True
    # UDP/IP
    if "udp" in pkt:
        return True
    return False

# Pcap parser ----------------------------------------------------------
def parse_pcap(pcap_path: Path):
    if not pcap_path.exists():
        log("WARNING: pcap not found"); return []
    log("Parsing eCPRI pcap …")
    cap = pyshark.FileCapture(str(pcap_path), keep_packets=False)
    violations, last_seq = [], None

    for pkt in cap:
        try:
            # Transport validation
            if not is_ecpri_transport(pkt):
                violations.append(
                    pcap_violation(pkt, "Bad Transport",
                                   "Not eCPRI Ethertype / VLAN AEFE / UDP", "high"))
                continue

            # Extract raw eCPRI bytes
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

            # IQ Data sequence gap check
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

# Main -----------------------------------------------------------------
def main():
    log("=== Fronthaul Violation Engine (verbose, VLAN-aware) ===")
    events  = []
    events += scan_log(DU_LOG, DU_RULES, "DU")
    events += scan_log(CU_LOG, CU_RULES, "CU")
    events += parse_pcap(PCAP)
    OUT.write_text(json.dumps(events, indent=2))
    log(f"Total written: {len(events)} → {OUT}")

if __name__ == "__main__":
    main()
