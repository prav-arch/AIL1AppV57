#!/usr/bin/env python3
"""
interference_splane_analyzer.py
───────────────────────────────
Rule engine that scans DU and CU logs for:
  • Interference events (SINR drop, RSRP very low, CRC burst, Timing drift)
  • S-Plane delay events  (F1 / RRC setup latency)
Always outputs a JSON array where each item has **timestamp**.
"""

import re, json
from pathlib import Path
from datetime import datetime

# ---------- paths ----------------------------------------------------
BASE = Path("/home/users/praveen.joe/logs")
DU_LOG = BASE / "dulogs.txt"
CU_LOG = BASE / "cucplog.txt"
OUT    = BASE / "interference_splane_issues.json"

# ---------- regex patterns ------------------------------------------
PAT_INTERFERENCE = r"SINR drop|RSRP at -\d+\s*dBm|CRC error|Timing drift"
PAT_SPLANE_DELAY = r"F1SetupRequest took \d+ms|UEContextSetupRequest took \d+ms|RRCSetup delayed"

# ---------- helper ---------------------------------------------------
def build_timestamp(hms: str | None) -> str:
    """Return ISO timestamp. If log line lacks [hh:mm:ss], use current UTC time."""
    if hms:
        today = datetime.utcnow().strftime("%Y-%m-%dT")
        return f"{today}{hms}Z"
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def scan_log(path: Path, pattern: str, issue_type: str):
    """Return list of violation dicts for one log file."""
    events = []
    if not path.exists():
        print(f"[int_rule] WARNING: {path.name} not found")
        return events

    regex = re.compile(pattern, re.I)
    for line in path.read_text(errors="ignore").splitlines():
        if regex.search(line):
            hhmmss = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", line)
            events.append({
                "timestamp": build_timestamp(hhmmss.group(1) if hhmmss else None),
                "type": issue_type,
                "severity": "high",
                "log_line": line.strip()
            })
    print(f"[int_rule] {len(events):>4} {issue_type} events in {path.name}")
    return events

# ---------- main -----------------------------------------------------
def main():
    results = []
    results += scan_log(DU_LOG, PAT_INTERFERENCE, "interference")
    results += scan_log(CU_LOG, PAT_INTERFERENCE, "interference")      # CU may log CRC/Timing too
    results += scan_log(DU_LOG, PAT_SPLANE_DELAY, "s_plane_delay")
    results += scan_log(CU_LOG, PAT_SPLANE_DELAY, "s_plane_delay")

    OUT.write_text(json.dumps(results, indent=2))
    print(f"[int_rule] Wrote {len(results)} events → {OUT}")

if __name__ == "__main__":
    main()
