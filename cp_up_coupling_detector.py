
#!/usr/bin/env python3
"""
cp_up_coupling_detector.py   (timestamp-safe)
─────────────────────────────────────────────
• Scans cucplog.txt  (CP) and cuuplog.txt  (UP)
• Correlates CP + UP lines occurring within ±5 seconds
• EVERY output record now carries a valid 'timestamp' key
  → fixes KeyError: 'timestamp' in downstream ML detector
Outputs: cp_up_coupling_issues.json
"""

import re, json, sys
from datetime import datetime, timedelta
from pathlib import Path

# --------------- paths ------------------------------------------------
BASE = Path("/home/users/praveen.joe/logs")
CP_LOG = BASE / "cucplog.txt"
UP_LOG = BASE / "cuuplog.txt"
OUT    = BASE / "cp_up_coupling_issues.json"

# --------------- regex patterns --------------------------------------
PAT_CP = re.compile(
    r"RRC(Setup|Reestablishment|Release)|F1Setup|UEContextSetup",
    re.I
)
PAT_UP = re.compile(
    r"DRB release|DL throughput drop|GTP-U tunnel drop|QoS mismatch",
    re.I
)

# --------------- helpers ---------------------------------------------
def extract_time(line: str) -> datetime | None:
    """Return datetime object if '[hh:mm:ss]' present; else None."""
    m = re.search(r"\[(\d{2}):(\d{2}):(\d{2})\]", line)
    if not m:
        return None
    hh, mm, ss = map(int, m.groups())
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return today + timedelta(hours=hh, minutes=mm, seconds=ss)

def parse_file(path: Path, pattern: re.Pattern, is_cp: bool):
    """Return list of dicts with parsed time + log line."""
    events = []
    if not path.exists():
        print(f"[cp_up_rule] WARNING: {path.name} not found")
        return events
    for line in path.read_text(errors="ignore").splitlines():
        if pattern.search(line):
            ts = extract_time(line)
            if ts is None:
                # Use current UTC if timestamp missing
                ts = datetime.utcnow()
            events.append({"time": ts, "log": line.strip(), "cp": is_cp})
    print(f"[cp_up_rule] {len(events):>4} {'CP' if is_cp else 'UP'} events in {path.name}")
    return events

def correlate(cp_events, up_events):
    """Return list of coupling issues (within ±5 s)."""
    out = []
    for ce in cp_events:
        for ue in up_events:
            if abs((ue["time"] - ce["time"]).total_seconds()) <= 5:
                out.append({
                    "timestamp": ce["time"].isoformat(timespec="seconds") + "Z",
                    "type": "CP+UP coupling",
                    "severity": "critical",
                    "cp_log": ce["log"],
                    "up_log": ue["log"]
                })
    return out

# --------------- main -------------------------------------------------
def main():
    cp_events = parse_file(CP_LOG, PAT_CP, True)
    up_events = parse_file(UP_LOG, PAT_UP, False)
    coupling  = correlate(cp_events, up_events)
    OUT.write_text(json.dumps(coupling, indent=2))
    print(f"[cp_up_rule] Wrote {len(coupling)} coupling issues → {OUT}")

if __name__ == "__main__":
    main()
