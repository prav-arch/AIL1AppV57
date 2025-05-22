#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Minio installation...${NC}"

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
    echo -e "${YELLOW}Couldn't detect server IP. Using localhost instead.${NC}"
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p ~/minio/data
mkdir -p ~/.minio

# Download Minio binary with certificate checks disabled
echo "Downloading Minio..."
wget --no-check-certificate https://dl.min.io/server/minio/release/linux-amd64/minio -O ~/minio/minio
chmod +x ~/minio/minio

# Download Minio client with certificate checks disabled
echo "Downloading Minio client..."
wget --no-check-certificate https://dl.min.io/client/mc/release/linux-amd64/mc -O ~/minio/mc
chmod +x ~/minio/mc

# Create environment file
echo "Setting up credentials (dpcoe/dpcoeadmin)..."
cat > ~/.minio/config.env << EOF
export MINIO_ROOT_USER=dpcoe
export MINIO_ROOT_PASSWORD=dpcoeadmin
EOF

# Source environment variables
source ~/.minio/config.env

# Create startup script
echo "Creating startup script..."
cat > ~/minio/start-minio.sh << EOF
#!/bin/bash
source ~/.minio/config.env

# Define data directory
MINIO_DATA_DIR=~/minio/data

# Force HTTP (disable HTTPS completely)
export MINIO_SERVER_URL="http://${SERVER_IP}:8000"
export MINIO_BROWSER_REDIRECT_URL="http://${SERVER_IP}:8001"
export MINIO_CERT_INSECURE=true
export MINIO_SKIP_CLIENT_CERT_VERIFY=true
export MINIO_SKIP_CERT_VERIFY=true

# Start Minio server
~/minio/minio server --console-address :8001 --address :8000 --certs-dir=/tmp \$MINIO_DATA_DIR
EOF

chmod +x ~/minio/start-minio.sh

# Check if screen is installed
if ! command -v screen &> /dev/null; then
    echo -e "${YELLOW}screen is not installed. Minio will start in the foreground.${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop it, but this will terminate the Minio server.${NC}"
    echo -e "${YELLOW}It's recommended to install screen or tmux for background operation.${NC}"
    
    # Create a simple script to check if Minio is running
    cat > ~/minio/check-minio.sh << EOF
#!/bin/bash
if pgrep -f "minio server" > /dev/null; then
    echo "Minio is running."
else
    echo "Minio is not running. Start it with ~/minio/start-minio.sh"
fi
EOF
    chmod +x ~/minio/check-minio.sh
    
    echo -e "${GREEN}Installation complete!${NC}"
    echo -e "${GREEN}Minio will now start. To stop it, press Ctrl+C.${NC}"
    echo -e "${GREEN}To start Minio again later, run: ~/minio/start-minio.sh${NC}"
    echo -e "${GREEN}To check if Minio is running: ~/minio/check-minio.sh${NC}"
    echo -e "${GREEN}Access the Minio API at: http://${SERVER_IP}:8000${NC}"
    echo -e "${GREEN}Access the Minio Console at: http://${SERVER_IP}:8001${NC}"
    echo -e "${GREEN}Username: dpcoe${NC}"
    echo -e "${GREEN}Password: dpcoeadmin${NC}"
    
    # Start Minio in the foreground
    ~/minio/start-minio.sh
else
    # Start Minio in a screen session
    echo "Starting Minio in the background using screen..."
    screen -dmS minio ~/minio/start-minio.sh
    
    # Configure Minio client (with insecure flag)
    echo "Configuring Minio client..."
    export MC_INSECURE=true  # Set global environment variable to disable certificate checks
    ~/minio/mc --insecure alias set myminio http://${SERVER_IP}:8000 dpcoe dpcoeadmin --insecure
    
    # Create a bucket for data
    echo "Creating a data bucket..."
    ~/minio/mc --insecure mb myminio/data-bucket --insecure
    
    # Create a simple management script
    cat > ~/minio/manage-minio.sh << EOF
#!/bin/bash
case "\$1" in
    start)
        screen -dmS minio ~/minio/start-minio.sh
        echo "Minio started."
        ;;
    stop)
        pkill -f "minio server"
        echo "Minio stopped."
        ;;
    restart)
        pkill -f "minio server"
        sleep 2
        screen -dmS minio ~/minio/start-minio.sh
        echo "Minio restarted."
        ;;
    status)
        if pgrep -f "minio server" > /dev/null; then
            echo "Minio is running."
        else
            echo "Minio is not running."
        fi
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
esac
exit 0
EOF
    chmod +x ~/minio/manage-minio.sh
    
    # Display information
    echo -e "${GREEN}Installation complete!${NC}"
    echo -e "${GREEN}Minio is now running in the background.${NC}"
    echo -e "${GREEN}Management commands:${NC}"
    echo -e "${GREEN}  Start:   ~/minio/manage-minio.sh start${NC}"
    echo -e "${GREEN}  Stop:    ~/minio/manage-minio.sh stop${NC}"
    echo -e "${GREEN}  Restart: ~/minio/manage-minio.sh restart${NC}"
    echo -e "${GREEN}  Status:  ~/minio/manage-minio.sh status${NC}"
    echo -e "${GREEN}Access the Minio API at: http://${SERVER_IP}:8000${NC}"
    echo -e "${GREEN}Access the Minio Console at: http://${SERVER_IP}:8001${NC}"
    echo -e "${GREEN}Username: dpcoe${NC}"
    echo -e "${GREEN}Password: dpcoeadmin${NC}"
    
    # Check if Minio started successfully
    sleep 3
    if pgrep -f "minio server" > /dev/null; then
        echo -e "${GREEN}Minio started successfully!${NC}"
    else
        echo -e "${YELLOW}Minio may not have started properly. Please check with:${NC}"
        echo -e "${YELLOW}  ~/minio/manage-minio.sh status${NC}"
    fi
fi