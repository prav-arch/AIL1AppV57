#!/bin/bash
SQL_FILE="create_l1_app_db_with_none.sql"
CLICKHOUSE_HOST="localhost"
CLICKHOUSE_PORT="9000"
CLICKHOUSE_USER="default"
CLICKHOUSE_DB="default"

clickhouse-client --host $CLICKHOUSE_HOST --port $CLICKHOUSE_PORT --user $CLICKHOUSE_USER --multiquery < "$SQL_FILE"
