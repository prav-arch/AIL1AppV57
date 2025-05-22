#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Minio login troubleshooting...${NC}"

# Check if Minio is running
echo -e "\n${YELLOW}Checking if Minio is running...${NC}"
if pgrep -f "minio server" > /dev/null; then
    echo -e "${GREEN}Minio is running.${NC}"
    
    # Get Minio process and environment variables
    MINIO_PID=$(pgrep -f "minio server")
    echo -e "\n${YELLOW}Minio process ID: ${MINIO_PID}${NC}"
    
    # Check environment variables set for the Minio process
    echo -e "\n${YELLOW}Checking Minio environment variables...${NC}"
    if [ -e "/proc/${MINIO_PID}/environ" ]; then
        echo -e "${GREEN}Environment variables for Minio process:${NC}"
        tr '\0' '\n' < /proc/${MINIO_PID}/environ | grep MINIO
    else
        echo -e "${RED}Could not access process environment variables.${NC}"
    fi
    
    # Check which ports Minio is listening on
    echo -e "\n${YELLOW}Checking ports Minio is listening on...${NC}"
    netstat -tulpn 2>/dev/null | grep minio || echo -e "${RED}Could not check ports (netstat command not found).${NC}"
    
    # Alternative way to check ports
    echo -e "\n${YELLOW}Alternative port check...${NC}"
    ss -tulpn 2>/dev/null | grep minio || echo -e "${RED}Could not check ports (ss command not found).${NC}"
    
    # List open files for the Minio process
    echo -e "\n${YELLOW}Checking open files and connections for Minio...${NC}"
    lsof -p ${MINIO_PID} 2>/dev/null || echo -e "${RED}Could not check open files (lsof command not found).${NC}"
else
    echo -e "${RED}Minio is not running!${NC}"
    echo -e "${YELLOW}Please start Minio first with: ~/minio/manage-minio.sh start${NC}"
    exit 1
fi

# Try connecting to Minio with mc client
echo -e "\n${YELLOW}Testing Minio connection with mc client...${NC}"
if [ -x ~/minio/mc ]; then
    echo -e "${YELLOW}Reconfiguring mc client with the current credentials...${NC}"
    export MC_INSECURE=true
    
    # Configure with explicit credentials, avoiding any variable expansion issues
    ~/minio/mc --insecure config host remove myminio 2>/dev/null
    ~/minio/mc --insecure config host add myminio http://localhost:8000 dpcoe dpcoeadmin --insecure
    
    echo -e "${YELLOW}Testing authentication with ls command...${NC}"
    ~/minio/mc --insecure ls myminio
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}MC client successfully authenticated!${NC}"
    else
        echo -e "${RED}MC client authentication failed.${NC}"
    fi
else
    echo -e "${RED}MC client not found at ~/minio/mc${NC}"
fi

# Fix attempt
echo -e "\n${YELLOW}Trying to fix the issue by restarting Minio with explicit credentials...${NC}"
echo -e "${YELLOW}Stopping any running Minio processes...${NC}"
pkill -f "minio server"

echo -e "${YELLOW}Creating updated startup script with fixed credentials...${NC}"
cat > ~/minio/start-minio-fixed.sh << EOF
#!/bin/bash

# Explicitly set credentials
export MINIO_ROOT_USER="dpcoe"
export MINIO_ROOT_PASSWORD="dpcoeadmin"

# Force HTTP (disable HTTPS completely)
export MINIO_SERVER_URL="http://127.0.0.1:8000"
export MINIO_BROWSER_REDIRECT_URL="http://127.0.0.1:8001"
export MINIO_CERT_INSECURE=true
export MINIO_SKIP_CLIENT_CERT_VERIFY=true
export MINIO_SKIP_CERT_VERIFY=true

# Set debugging
export MINIO_BROWSER_DEBUG=true

# Start Minio server without any redirections to ensure all output is visible
echo "Starting Minio with credentials: \$MINIO_ROOT_USER / \$MINIO_ROOT_PASSWORD"
~/minio/minio server --console-address :8001 --address :8000 --certs-dir=/tmp ~/minio/data
EOF

chmod +x ~/minio/start-minio-fixed.sh

echo -e "${GREEN}Created fixed startup script: ~/minio/start-minio-fixed.sh${NC}"
echo -e "${GREEN}To use it, run: screen -dmS minio ~/minio/start-minio-fixed.sh${NC}"
echo -e "${GREEN}Or to see debug output: ~/minio/start-minio-fixed.sh${NC}"
echo -e "${GREEN}Access Minio console at: http://localhost:8001${NC}"
echo -e "${GREEN}Login with: dpcoe / dpcoeadmin${NC}"

echo -e "\n${YELLOW}Troubleshooting complete.${NC}"