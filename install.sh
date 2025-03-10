#!/bin/bash

# NanoVM Installation Script
# Enterprise-grade rootless virtualization system with mTLS 1.2+ support

set -eo pipefail

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default installation options
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nanovm"
DATA_DIR="/var/lib/nanovm"
LOG_DIR="/var/log/nanovm"
RUN_DIR="/var/run/nanovm"
USER="nanovm"
GROUP="nanovm"

VERSION="0.1.0"
FEATURES="enterprise"
RELEASE_URL="https://github.com/TheMapleseed/NANOVM/releases/download/v${VERSION}/nanovm-${VERSION}-$(uname -m)-unknown-linux-musl.tar.gz"

# Print banner
echo -e "${BLUE}"
echo "================================================================================"
echo "  _   _                 __     ____  __ "
echo " | \ | | __ _ _ __   ___\ \   / /  \/  |"
echo " |  \| |/ _' | '_ \ / _ \\ \ / /| |\/| |"
echo " | |\  | (_| | | | | (_) |\ V / | |  | |"
echo " |_| \_|\__,_|_| |_|\___/  \_/  |_|  |_|"
echo ""
echo " Enterprise-grade rootless virtualization system with mTLS 1.2+ support"
echo "================================================================================"
echo -e "${NC}"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}" >&2
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        --run-dir)
            RUN_DIR="$2"
            shift 2
            ;;
        --user)
            USER="$2"
            shift 2
            ;;
        --group)
            GROUP="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            RELEASE_URL="https://github.com/TheMapleseed/NANOVM/releases/download/v${VERSION}/nanovm-${VERSION}-$(uname -m)-unknown-linux-musl.tar.gz"
            shift 2
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        --help)
            echo "NanoVM Installation Script"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --install-dir DIR    Installation directory (default: /usr/local/bin)"
            echo "  --config-dir DIR     Configuration directory (default: /etc/nanovm)"
            echo "  --data-dir DIR       Data directory (default: /var/lib/nanovm)"
            echo "  --log-dir DIR        Log directory (default: /var/log/nanovm)"
            echo "  --run-dir DIR        Runtime directory (default: /var/run/nanovm)"
            echo "  --user USER          User to run as (default: nanovm)"
            echo "  --group GROUP        Group to run as (default: nanovm)"
            echo "  --version VERSION    Version to install (default: ${VERSION})"
            echo "  --features FEATURES  Feature flags (default: enterprise)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $key${NC}" >&2
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Installing NanoVM version ${VERSION} with features: ${FEATURES}${NC}"
echo -e "${BLUE}Using the following paths:${NC}"
echo "  Installation directory: ${INSTALL_DIR}"
echo "  Configuration directory: ${CONFIG_DIR}"
echo "  Data directory: ${DATA_DIR}"
echo "  Log directory: ${LOG_DIR}"
echo "  Runtime directory: ${RUN_DIR}"
echo "  User: ${USER}"
echo "  Group: ${GROUP}"
echo ""

# Check for dependencies
echo -e "${BLUE}Checking dependencies...${NC}"
for cmd in curl tar grep id systemctl; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: Required command '$cmd' not found${NC}" >&2
        exit 1
    fi
done

# Create user and group if they don't exist
echo -e "${BLUE}Setting up user and group...${NC}"
if ! getent group $GROUP >/dev/null; then
    groupadd -r $GROUP
    echo "Created group: $GROUP"
fi
if ! getent passwd $USER >/dev/null; then
    useradd -r -g $GROUP -s /sbin/nologin -d $DATA_DIR $USER
    echo "Created user: $USER"
fi

# Create directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p $INSTALL_DIR $CONFIG_DIR $DATA_DIR $LOG_DIR $RUN_DIR

# Set permissions
echo -e "${BLUE}Setting permissions...${NC}"
chown -R $USER:$GROUP $CONFIG_DIR $DATA_DIR $LOG_DIR $RUN_DIR
chmod 750 $CONFIG_DIR $DATA_DIR $LOG_DIR $RUN_DIR

# Download and extract the binary
echo -e "${BLUE}Downloading NanoVM...${NC}"
TEMP_DIR=$(mktemp -d)
curl -L -o $TEMP_DIR/nanovm.tar.gz $RELEASE_URL
tar -xzf $TEMP_DIR/nanovm.tar.gz -C $TEMP_DIR

# Install the binary
echo -e "${BLUE}Installing NanoVM binary...${NC}"
install -m 0755 $TEMP_DIR/nanovm $INSTALL_DIR/nanovm

# Install the configuration file if it doesn't exist
if [ ! -f $CONFIG_DIR/nanovm_config.yaml ]; then
    echo -e "${BLUE}Installing default configuration...${NC}"
    install -m 0640 -o $USER -g $GROUP $TEMP_DIR/nanovm_config.yaml $CONFIG_DIR/nanovm_config.yaml
else
    echo -e "${YELLOW}Configuration file already exists, not overwriting${NC}"
fi

# Clean up temporary directory
rm -rf $TEMP_DIR

# Create systemd service
echo -e "${BLUE}Installing systemd service...${NC}"
cat > /etc/systemd/system/nanovm.service << EOF
[Unit]
Description=NanoVM - Enterprise-grade rootless virtualization system
Documentation=https://github.com/TheMapleseed/NANOVM
After=network.target

[Service]
Type=simple
User=${USER}
Group=${GROUP}
ExecStart=${INSTALL_DIR}/nanovm --config ${CONFIG_DIR}/nanovm_config.yaml
Restart=on-failure
RestartSec=5s
TimeoutStartSec=0
LimitNOFILE=65536
LimitNPROC=4096
WorkingDirectory=${DATA_DIR}
RuntimeDirectory=nanovm
StateDirectory=nanovm
LogsDirectory=nanovm
ConfigurationDirectory=nanovm

# Security hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable the service
echo -e "${BLUE}Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable nanovm.service
systemctl start nanovm.service

# Verify installation
echo -e "${BLUE}Verifying installation...${NC}"
if systemctl is-active --quiet nanovm.service; then
    echo -e "${GREEN}NanoVM has been successfully installed and started!${NC}"
    echo -e "Configuration file: ${CONFIG_DIR}/nanovm_config.yaml"
    echo -e "Logs can be viewed with: journalctl -u nanovm.service -f"
    echo -e "Service can be managed with: systemctl [start|stop|restart|status] nanovm.service"
else
    echo -e "${RED}NanoVM service failed to start. Please check logs with: journalctl -u nanovm.service -f${NC}"
    exit 1
fi

echo -e "${GREEN}Installation complete!${NC}" 