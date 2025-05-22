#!/usr/bin/env bash
# create_clickhouse_schema_18_16.sh
# Schema compatible with ClickHouse Server 18.16

CLICKHOUSE="clickhouse-client --host localhost --port 9000 --user default"

$CLICKHOUSE <<'SQL'
CREATE DATABASE IF NOT EXISTS l1_app_db;

CREATE TABLE IF NOT EXISTS l1_app_db.violations
(
    event_date     Date                         DEFAULT toDate(event_time),
    event_time     DateTime,
    violation_type Enum8('coupling'=1,'interference'=2,'s_plane_delay'=3,'fh_violation'=4),
    source          String,
    details         String,
    violation_count UInt32,
    window_ms       UInt32
)
ENGINE = MergeTree(event_date, (event_date, violation_type, event_time), 8192);

CREATE TABLE IF NOT EXISTS l1_app_db.violation_summary
(
    event_date     Date,
    violation_type Enum8('coupling'=1,'interference'=2,'s_plane_delay'=3,'fh_violation'=4),
    total_count    UInt64
)
ENGINE = SummingMergeTree(event_date, (event_date, violation_type), 8192);

CREATE MATERIALIZED VIEW IF NOT EXISTS l1_app_db.mv_violations_to_summary
TO l1_app_db.violation_summary
AS
SELECT
    toDate(event_time) AS event_date,
    violation_type,
    count()            AS total_count
FROM l1_app_db.violations
GROUP BY
    violation_type,
    event_date;
SQL

echo "✅ ClickHouse 18.16 schema created (DB: l1_app_db)"
