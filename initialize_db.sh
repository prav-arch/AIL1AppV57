#!/bin/bash

# This script will help initialize a PostgreSQL database cluster manually
# if the automatic installation didn't work correctly

# Set variables
echo "Please provide the path to your PostgreSQL installation directory"
echo "For example: /home/username/postgres16"
read -p "Installation directory: " INSTALL_DIR

# Make sure the directory exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: Directory $INSTALL_DIR does not exist"
    exit 1
fi

# Check if bin directory exists
if [ ! -d "$INSTALL_DIR/bin" ]; then
    echo "Error: $INSTALL_DIR/bin not found. This doesn't appear to be a PostgreSQL installation."
    exit 1
fi

# Create data directory
echo "Please provide a location for the PostgreSQL data directory"
echo "For example: /home/username/postgres16/data"
read -p "Data directory: " PGDATA

# Create the directory if it doesn't exist
mkdir -p $PGDATA
echo "Created data directory at: $PGDATA"

# Run initdb
echo "Initializing PostgreSQL database cluster..."
$INSTALL_DIR/bin/initdb -D $PGDATA --no-locale --encoding=UTF8

if [ $? -ne 0 ]; then
    echo "Error: initdb failed. Please check the error message above."
    exit 1
fi

# Set permissions
echo "Setting permissions to u=rwx..."
chmod -R u=rwx $PGDATA
echo "Permissions set."

# Configure PostgreSQL
echo "Configuring PostgreSQL..."
echo "listen_addresses = '*'" >> $PGDATA/postgresql.conf
echo "port = 5432" >> $PGDATA/postgresql.conf
echo "log_destination = 'stderr'" >> $PGDATA/postgresql.conf
echo "logging_collector = on" >> $PGDATA/postgresql.conf
echo "log_directory = 'pg_log'" >> $PGDATA/postgresql.conf
echo "log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'" >> $PGDATA/postgresql.conf

# Set up authentication
mkdir -p $PGDATA/pg_log
echo "# TYPE  DATABASE        USER            ADDRESS                 METHOD" > $PGDATA/pg_hba.conf
echo "local   all             all                                     md5" >> $PGDATA/pg_hba.conf
echo "host    all             all             127.0.0.1/32            md5" >> $PGDATA/pg_hba.conf
echo "host    all             all             ::1/128                 md5" >> $PGDATA/pg_hba.conf
echo "host    all             all             0.0.0.0/0               md5" >> $PGDATA/pg_hba.conf

echo "Starting PostgreSQL server..."
$INSTALL_DIR/bin/pg_ctl -D $PGDATA start

if [ $? -ne 0 ]; then
    echo "Error starting PostgreSQL server. Please check the error messages above."
    exit 1
fi

# Create user and database
echo "Creating user and database..."
echo "Enter a username for PostgreSQL (default: l1_app_user):"
read -p "Username: " DB_USER
DB_USER=${DB_USER:-l1_app_user}

echo "Enter a password for the user (default: test):"
read -p "Password: " DB_PASSWORD
DB_PASSWORD=${DB_PASSWORD:-test}

echo "Enter a database name (default: l1_app_db):"
read -p "Database name: " DB_NAME
DB_NAME=${DB_NAME:-l1_app_db}

$INSTALL_DIR/bin/psql -d postgres -c "CREATE ROLE $DB_USER WITH LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD '$DB_PASSWORD';"
$INSTALL_DIR/bin/createdb -O $DB_USER $DB_NAME
$INSTALL_DIR/bin/psql -d $DB_NAME -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# Create environment file
echo "Creating environment file..."
ENV_FILE=$HOME/.pgenv

cat > $ENV_FILE << EOF
# PostgreSQL Environment Variables
export PATH=$INSTALL_DIR/bin:\$PATH
export PGDATA=$PGDATA
export DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME
export PGHOST=localhost
export PGPORT=5432
export PGUSER=$DB_USER
export PGPASSWORD=$DB_PASSWORD
export PGDATABASE=$DB_NAME
EOF

echo "Environment file created at $ENV_FILE"
echo "To load these environment variables, run:"
echo "source $ENV_FILE"

echo "Installation and configuration complete!"
echo "You can now connect to your database with:"
echo "$INSTALL_DIR/bin/psql -d $DB_NAME -U $DB_USER"
echo ""
echo "Or after sourcing the environment file:"
echo "source $ENV_FILE"
echo "psql -d $DB_NAME"