#!/usr/bin/env bash
# Schema for ClickHouse Server 18.16
# ──────────────────────────────────
# • Uses one clickhouse-client call per statement  → no “multi-statement” error
# • All UNION columns in the view are cast to String, so no Enum/String conflict
# • Creates:
#     − fh_violations                (raw fronthaul)
#     − cp_up_coupling               (raw CP+UP)
#     − interference_splane          (raw interference / S-plane)
#     − all_violations               (view  – String columns)
#     − violation_summary_daily      (SummingMergeTree)
#     − mv_daily_summary             (materialised view → summary table)

CH() { clickhouse-client --host localhost -q "$1"; }

###############################################################################
# 1) Database
###############################################################################
CH "CREATE DATABASE IF NOT EXISTS l1_app_db"

###############################################################################
# 2) Raw tables (old MergeTree syntax)
###############################################################################
CH "
CREATE TABLE IF NOT EXISTS l1_app_db.fh_violations
(
  event_date Date DEFAULT toDate(event_time),
  event_time DateTime,
  type       String,
  severity   Enum8('low'=1,'medium'=2,'high'=3,'critical'=4),
  description String,
  log_line   String DEFAULT '',
  transport_ok UInt8 DEFAULT 1
)
ENGINE = MergeTree(event_date, (event_date, severity, event_time), 8192)
"

CH "
CREATE TABLE IF NOT EXISTS l1_app_db.cp_up_coupling
(
  event_date   Date DEFAULT toDate(event_time),
  event_time   DateTime,
  severity     Enum8('critical'=4),
  cp_log       String,
  up_log       String
)
ENGINE = MergeTree(event_date, (event_date, event_time), 8192)
"

CH "
CREATE TABLE IF NOT EXISTS l1_app_db.interference_splane
(
  event_date Date DEFAULT toDate(event_time),
  event_time DateTime,
  type       Enum8('interference'=1,'s_plane_delay'=2),
  severity   Enum8('high'=3),
  log_line   String
)
ENGINE = MergeTree(event_date, (event_date, type, event_time), 8192)
"

###############################################################################
# 3) Union view with consistent String columns
###############################################################################
CH "DROP VIEW IF EXISTS l1_app_db.mv_daily_summary"
CH "DROP VIEW IF EXISTS l1_app_db.all_violations"

CH "
CREATE VIEW l1_app_db.all_violations AS
SELECT
    event_date,
    event_time,
    'fh' AS src,
    type AS event_type,
    toString(severity) AS severity_str,
    description AS details
FROM l1_app_db.fh_violations

UNION ALL
SELECT
    event_date,
    event_time,
    'cpup' AS src,
    'CP+UP coupling' AS event_type,
    toString(severity) AS severity_str,
    concat(cp_log,' | ',up_log) AS details
FROM l1_app_db.cp_up_coupling

UNION ALL
SELECT
    event_date,
    event_time,
    'intf' AS src,
    toString(type) AS event_type,          -- Enum8 → String
    toString(severity) AS severity_str,
    log_line AS details
FROM l1_app_db.interference_splane
"

###############################################################################
# 4) Daily summary table + materialised view
###############################################################################
CH "
CREATE TABLE IF NOT EXISTS l1_app_db.violation_summary_daily
(
    event_date Date,
    src        Enum8('fh'=1,'cpup'=2,'intf'=3),
    total_cnt  UInt64
)
ENGINE = SummingMergeTree(event_date, (event_date, src), 8192)
"

CH "
CREATE MATERIALIZED VIEW l1_app_db.mv_daily_summary
TO l1_app_db.violation_summary_daily
AS
SELECT
    event_date,
    src,
    count() AS total_cnt
FROM l1_app_db.all_violations
GROUP BY
    src,
    event_date
"

echo "✅  ClickHouse 18.16 schema created (DB: l1_app_db)"
