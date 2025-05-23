-- Database
CREATE DATABASE IF NOT EXISTS l1_app_db;

-- Table: cp_up_coupling
DROP TABLE IF EXISTS l1_app_db.cp_up_coupling;
CREATE TABLE l1_app_db.cp_up_coupling
(
    event_time DateTime,
    severity Enum8('critical'=4, 'major'=3, 'minor'=2, 'warning'=1, 'none'=0),
    cp_log String,
    up_log String
)
ENGINE = MergeTree()
ORDER BY event_time;

-- Table: interference_splane
DROP TABLE IF EXISTS l1_app_db.interference_splane;
CREATE TABLE l1_app_db.interference_splane
(
    event_time DateTime,
    type Enum8('interference'=1, 's_plane_delay'=2, 'none'=0),
    severity Enum8('high'=3, 'medium'=2, 'low'=1, 'none'=0),
    log_line String
)
ENGINE = MergeTree()
ORDER BY event_time;

-- Table: fh_violations
DROP TABLE IF EXISTS l1_app_db.fh_violations;
CREATE TABLE l1_app_db.fh_violations
(
    event_time DateTime,
    type String,                -- Kept as String for flexibility (enum not always possible)
    severity Enum8('high'=3, 'medium'=2, 'low'=1, 'none'=0),
    description String,
    log_line String,
    transport_ok UInt8
)
ENGINE = MergeTree()
ORDER BY event_time;
