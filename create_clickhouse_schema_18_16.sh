#!/usr/bin/env bash
# create_clickhouse_schema_18_16.sh
# Compatible with ClickHouse Server 18.16

CH() { clickhouse-client --host localhost -q "$1"; }

###############################################################################
# 1) Database
###############################################################################
CH "CREATE DATABASE IF NOT EXISTS l1_app_db"

###############################################################################
# 2) Raw fronthaul-violation table   (from fh_protocol_violations_enhanced.json)
###############################################################################
CH "
CREATE TABLE IF NOT EXISTS l1_app_db.fh_violations
(
    event_date       Date   DEFAULT toDate(event_time),
    event_time       DateTime,
    type             String,
    severity         Enum8('low'=1,'medium'=2,'high'=3,'critical'=4),
    description      String,
    log_line         String DEFAULT '',
    transport_ok     UInt8  DEFAULT 1
)
ENGINE = MergeTree(event_date, (event_date, severity, event_time), 8192)
"

###############################################################################
# 3) Raw CP-UP coupling table        (from cp_up_coupling_issues.json)
###############################################################################
CH "
CREATE TABLE IF NOT EXISTS l1_app_db.cp_up_coupling
(
    event_date     Date   DEFAULT toDate(event_time),
    event_time     DateTime,
    severity       Enum8('critical'=4),
    cp_log         String,
    up_log         String
)
ENGINE = MergeTree(event_date, (event_date, event_time), 8192)
"

###############################################################################
# 4) Raw Interference / S-Plane table (from interference_splane_issues.json)
###############################################################################
CH "
CREATE TABLE IF NOT EXISTS l1_app_db.interference_splane
(
    event_date     Date   DEFAULT toDate(event_time),
    event_time     DateTime,
    type           Enum8('interference'=1,'s_plane_delay'=2),
    severity       Enum8('high'=3),          -- always high in current rules
    log_line       String
)
ENGINE = MergeTree(event_date, (event_date, type, event_time), 8192)
"

###############################################################################
# 5) UNION-ALL VIEW (generic violations view)  — optional, simplifies queries
###############################################################################
CH "
CREATE OR REPLACE VIEW l1_app_db.all_violations AS
SELECT event_date, event_time, 'fh' AS src , type, severity, description AS details
FROM l1_app_db.fh_violations
UNION ALL
SELECT event_date, event_time, 'cpup', 'CP+UP coupling', severity, concat(cp_log,' | ',up_log)
FROM l1_app_db.cp_up_coupling
UNION ALL
SELECT event_date, event_time, 'intf', type, severity, log_line
FROM l1_app_db.interference_splane
"

###############################################################################
# 6) Daily summary table (SummingMergeTree, old syntax)
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

###############################################################################
# 7) Materialised view to keep daily totals
###############################################################################
CH "
CREATE MATERIALIZED VIEW IF NOT EXISTS l1_app_db.mv_daily_summary
TO l1_app_db.violation_summary_daily
AS
SELECT
    toDate(event_time) AS event_date,
    src,
    count()            AS total_cnt
FROM l1_app_db.all_violations
GROUP BY
    src,
    event_date
"

echo "✅  ClickHouse schema for 18.16 created (DB: l1_app_db)"
