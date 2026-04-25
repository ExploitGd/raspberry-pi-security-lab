#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Cowrie SSH Honeypot Setup Script
# Author: Your Name
# Project: Home Security Lab Portfolio
# Description: Automates the installation and configuration of Cowrie SSH
#              honeypot on Ubuntu. Creates an isolated user, sets up a Python
#              virtual environment, configures the honeypot, and starts it
#              as a background service.
# Usage: sudo bash pi5_cowrie_setup.sh
# =============================================================================

set -e  # Exit immediately if any command fails

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper functions ---
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- Check running as root ---
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root. Use: sudo bash pi5_cowrie_setup.sh"
fi

echo ""
echo "============================================================"
echo "  Raspberry Pi 5 - Cowrie SSH Honeypot Setup Script"
echo "============================================================"
echo ""

# =============================================================================
# STEP 1: Install Dependencies
# WHY: Cowrie is a Python-based honeypot that needs several system libraries:
#      - git: to clone the Cowrie source code
#      - python3-venv: to create an isolated Python environment
#      - libssl-dev/libffi-dev: for cryptographic operations (SSH uses these)
#      - build-essential/python3-dev: to compile Python C extensions
#      Isolating Cowrie in its own environment prevents library conflicts
#      with other Python tools on the system.
# =============================================================================
info "Step 1: Installing system dependencies..."

apt update -y
apt install -y \
  git \
  python3-venv \
  python3-pip \
  python3.13-venv \
  libssl-dev \
  libffi-dev \
  build-essential \
  python3-dev

success "Dependencies installed."

# =============================================================================
# STEP 2: Create a Dedicated Cowrie User
# WHY: Running a honeypot as root is extremely dangerous — if an attacker
#      somehow escapes the honeypot sandbox, they'd have full root access.
#      A dedicated unprivileged user limits the blast radius to just that
#      account. This is the principle of least privilege in practice.
# =============================================================================
info "Step 2: Creating dedicated cowrie user..."

if id "cowrie" &>/dev/null; then
  warn "User 'cowrie' already exists. Skipping creation."
else
  adduser --disabled-password --gecos "" cowrie
  success "User 'cowrie' created."
fi

# =============================================================================
# STEP 3: Clone Cowrie from GitHub
# WHY: We pull directly from the official Cowrie repository to get the latest
#      version with current attack signatures and bug fixes. Installing to
#      /home/cowrie/cowrie keeps everything owned by the cowrie user and
#      separate from system files.
# =============================================================================
info "Step 3: Cloning Cowrie from GitHub..."

COWRIE_DIR="/home/cowrie/cowrie"

if [[ -d "$COWRIE_DIR/.git" ]]; then
  warn "Cowrie already cloned. Pulling latest changes..."
  sudo -u cowrie git -C "$COWRIE_DIR" pull
else
  sudo -u cowrie git clone https://github.com/cowrie/cowrie "$COWRIE_DIR"
  success "Cowrie cloned to $COWRIE_DIR"
fi

# =============================================================================
# STEP 4: Set Up Python Virtual Environment
# WHY: A virtualenv creates a completely isolated Python installation just
#      for Cowrie. This means:
#      1. Cowrie's dependencies don't conflict with system Python packages
#      2. We can update Cowrie without breaking anything else
#      3. The exact package versions Cowrie needs are pinned and reproducible
# =============================================================================
info "Step 4: Setting up Python virtual environment..."

sudo -u cowrie bash << 'VENV_EOF'
cd /home/cowrie/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip --quiet
pip install -e . --quiet
pip install -r requirements.txt --quiet
echo "Virtual environment ready."
VENV_EOF

success "Python virtual environment configured."

# =============================================================================
# STEP 5: Configure Cowrie
# WHY: The default config needs customization:
#      - hostname: sets what the fake server calls itself (makes it look real)
#      - listen port 2222: non-root users can't bind to ports below 1024,
#        so Cowrie listens on 2222 and we redirect port 22 traffic via iptables
#      - We copy .dist to .cfg so our changes survive Cowrie updates
# =============================================================================
info "Step 5: Configuring Cowrie..."

COWRIE_CFG="$COWRIE_DIR/etc/cowrie.cfg"
COWRIE_CFG_DIST="$COWRIE_DIR/etc/cowrie.cfg.dist"

if [[ ! -f "$COWRIE_CFG" ]]; then
  sudo -u cowrie cp "$COWRIE_CFG_DIST" "$COWRIE_CFG"
fi

# Set a convincing fake hostname
# WHY: Attackers are more likely to interact longer if the system looks real
sed -i 's/^hostname = .*/hostname = ubuntu-server/' "$COWRIE_CFG"

# Set listen port to 2222
# WHY: Port 2222 is accessible by non-root processes. We'll use iptables
#      to redirect external port 22 traffic here so attackers see port 22.
sed -i 's/^#*listen_endpoints = .*/listen_endpoints = tcp:2222:interface=0.0.0.0/' "$COWRIE_CFG"

success "Cowrie configured (hostname: ubuntu-server, port: 2222)"

# =============================================================================
# STEP 6: Open Firewall for Cowrie
# WHY: UFW blocks all incoming traffic by default (from Phase 1 hardening).
#      We need to explicitly allow port 2222 so attackers can reach the
#      honeypot. We do NOT expose this on the real SSH port (22) to avoid
#      confusing it with our actual SSH access.
# =============================================================================
info "Step 6: Opening firewall for Cowrie..."

ufw allow 2222/tcp
success "Port 2222 opened in UFW firewall."

# =============================================================================
# STEP 7: Create systemd Service for Cowrie
# WHY: Running Cowrie as a systemd service means:
#      1. It starts automatically on boot
#      2. It restarts if it crashes
#      3. Logs integrate with journalctl
#      4. We can manage it with standard systemctl commands
#      Running as the cowrie user (not root) maintains our security isolation.
# =============================================================================
info "Step 7: Creating systemd service for Cowrie..."

cat > /etc/systemd/system/cowrie.service << EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target
Documentation=https://cowrie.readthedocs.io

[Service]
# Run as unprivileged cowrie user - never root
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie

# Activate virtual environment and start Cowrie via twistd
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd \\
  --nodaemon \\
  --pidfile=/home/cowrie/cowrie/twistd.pid \\
  --logfile=/home/cowrie/cowrie/twistd.log \\
  cowrie

ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Security hardening for the service itself
PrivateTmp=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

# Wait for Cowrie to initialize
sleep 5

if systemctl is-active --quiet cowrie; then
  success "Cowrie service is active and running."
else
  error "Cowrie failed to start. Check: sudo journalctl -u cowrie -n 50"
fi

# =============================================================================
# STEP 8: Verify Cowrie is Listening
# WHY: Just because the service started doesn't mean it's actually accepting
#      connections. We verify the port is open and listening before declaring
#      success — this catches misconfigurations early.
# =============================================================================
info "Step 8: Verifying Cowrie is listening on port 2222..."

sleep 3

if ss -tlnp | grep -q ":2222"; then
  success "Cowrie is listening on port 2222."
else
  error "Cowrie is not listening on port 2222. Check: sudo journalctl -u cowrie -n 30"
fi

# =============================================================================
# STEP 9: Add Monitoring Aliases
# WHY: Quick access to Cowrie logs is essential for monitoring. These aliases
#      make it easy to watch live attacks, review sessions, and check status
#      without memorizing long paths — good operational hygiene.
# =============================================================================
info "Step 9: Adding monitoring aliases..."

BASHRC="/home/${SUDO_USER:-$USER}/.bashrc"
LOG_PATH="/home/cowrie/cowrie/var/log/cowrie"

cat >> "$BASHRC" << EOF

# --- Cowrie Honeypot monitoring aliases (added by pi5_cowrie_setup.sh) ---
alias cowrie-log='sudo tail -f $LOG_PATH/cowrie.json'
alias cowrie-status='sudo systemctl status cowrie'
alias cowrie-logins='sudo cat $LOG_PATH/cowrie.json | python3 -m json.tool | grep -A2 "login.success"'
alias cowrie-commands='sudo cat $LOG_PATH/cowrie.json | python3 -m json.tool | grep "command.input"'
alias cowrie-ips='sudo cat $LOG_PATH/cowrie.json | grep src_ip | sort | uniq -c | sort -rn'
EOF

success "Aliases added to $BASHRC"

# =============================================================================
# COMPLETE - Summary
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  Cowrie Honeypot Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  What was configured:"
echo "  [✓] System dependencies installed"
echo "  [✓] Dedicated 'cowrie' user created (unprivileged)"
echo "  [✓] Cowrie cloned from official GitHub repo"
echo "  [✓] Isolated Python virtual environment created"
echo "  [✓] Cowrie configured (hostname: ubuntu-server, port: 2222)"
echo "  [✓] Firewall opened for port 2222"
echo "  [✓] Cowrie running as systemd service"
echo "  [✓] Verified listening on port 2222"
echo "  [✓] Monitoring aliases added"
echo ""
echo "  Log locations:"
echo "  JSON events: /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
echo "  Service log: /home/cowrie/cowrie/twistd.log"
echo ""
echo "  Handy commands (after running source ~/.bashrc):"
echo "  cowrie-log       → watch live honeypot events"
echo "  cowrie-status    → check service status"
echo "  cowrie-logins    → show successful logins"
echo "  cowrie-commands  → show commands attackers typed"
echo "  cowrie-ips       → show attacker IPs by frequency"
echo ""
echo "  Test your honeypot:"
echo "  ssh -p 2222 root@your-pi-ip"
echo "  (use any password — Cowrie will accept it)"
echo ""
echo "  NEXT STEPS:"
echo "  1. Run: source ~/.bashrc"
echo "  2. Try: cowrie-log"
echo "  3. Move on to Phase 4: Grafana Dashboard"
echo "============================================================"
