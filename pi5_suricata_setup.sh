#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Suricata IDS Setup Script
# Author: Your Name
# Project: Home Security Lab Portfolio
# Description: Automates the installation and configuration of Suricata IDS
#              on Ubuntu. Sets up network interface, downloads community
#              rulesets, validates config, and verifies live detection.
# Usage: sudo bash pi5_suricata_setup.sh
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
  error "This script must be run as root. Use: sudo bash pi5_suricata_setup.sh"
fi

echo ""
echo "============================================================"
echo "  Raspberry Pi 5 - Suricata IDS Setup Script"
echo "============================================================"
echo ""

# =============================================================================
# STEP 1: Detect Active Network Interface
# WHY: Suricata needs to know which interface to monitor. We auto-detect
#      the active one rather than hardcoding it, making this script portable
#      across different network setups (wired vs wireless).
# =============================================================================
info "Step 1: Detecting active network interface..."

# Get the interface that has the default route (the one handling real traffic)
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [[ -z "$INTERFACE" ]]; then
  error "Could not detect network interface. Run 'ip a' and set INTERFACE manually."
fi

# Get the local subnet for HOME_NET config
LOCAL_IP=$(ip -4 addr show "$INTERFACE" | grep inet | awk '{print $2}' | head -n1)
SUBNET=$(echo "$LOCAL_IP" | sed 's|\.[0-9]*/.*|.0/24|')

success "Detected interface: $INTERFACE"
success "Local subnet: $SUBNET"

# =============================================================================
# STEP 2: Install Suricata
# WHY: We use the official OISF (Open Information Security Foundation) PPA
#      to get the latest stable release. Ubuntu's default repos often have
#      outdated versions with missing features and unpatched vulnerabilities.
# =============================================================================
info "Step 2: Installing Suricata from official OISF repository..."

apt install -y software-properties-common
add-apt-repository ppa:oisf/suricata-stable -y
apt update -y
apt install -y suricata

SURICATA_VERSION=$(suricata -V 2>&1 | grep -i "suricata version" | awk '{print $3}')
success "Suricata $SURICATA_VERSION installed successfully."

# =============================================================================
# STEP 3: Configure Suricata
# WHY: Default config needs two key changes:
#      1. HOME_NET tells Suricata what to consider "your" network so it can
#         correctly classify inbound vs outbound traffic in alerts.
#      2. The interface must match your actual network card or Suricata
#         won't capture any packets.
# =============================================================================
info "Step 3: Configuring Suricata..."

SURICATA_CONFIG="/etc/suricata/suricata.yaml"

# Backup original config
cp "$SURICATA_CONFIG" "${SURICATA_CONFIG}.bak.$(date +%F)"
success "Config backed up to ${SURICATA_CONFIG}.bak.$(date +%F)"

# Set HOME_NET to local subnet
# WHY: HOME_NET is used in rules to distinguish between internal and external
#      traffic. Setting it correctly reduces false positives.
sed -i "s|HOME_NET:.*|HOME_NET: \"[$SUBNET]\"|" "$SURICATA_CONFIG"
success "HOME_NET set to $SUBNET"

# Set the network interface
# WHY: af-packet is the recommended capture mode on Linux — it's faster
#      than standard pcap and handles high traffic volumes better.
sed -i "/af-packet:/,/interface:/{s/interface: .*/interface: $INTERFACE/}" "$SURICATA_CONFIG"
success "Interface set to $INTERFACE"

# =============================================================================
# STEP 4: Download Community Rules
# WHY: Rules are the heart of an IDS. Without them Suricata captures traffic
#      but can't identify threats. suricata-update pulls from the Emerging
#      Threats ruleset — one of the most comprehensive free threat intel
#      sources available, updated daily with new attack signatures.
# =============================================================================
info "Step 4: Downloading community detection rules..."

# suricata-update fetches and installs the latest Emerging Threats ruleset
suricata-update

# Verify rules were downloaded
RULES_FILE="/var/lib/suricata/rules/suricata.rules"
if [[ ! -f "$RULES_FILE" ]]; then
  error "Rules file not found at $RULES_FILE. Check suricata-update output above."
fi

RULE_COUNT=$(grep -c "^alert\|^drop\|^pass" "$RULES_FILE" 2>/dev/null || echo "0")
success "Rules downloaded: $RULE_COUNT signatures loaded."

# =============================================================================
# STEP 5: Validate Configuration
# WHY: Always test config before starting the service. A bad config will
#      cause Suricata to fail silently or not start at all. The -T flag
#      runs a full config and rules parse without capturing any traffic.
# =============================================================================
info "Step 5: Validating Suricata configuration..."

if suricata -T -c "$SURICATA_CONFIG" -v 2>&1 | grep -q "Configuration provided was successfully loaded"; then
  success "Configuration validated successfully."
else
  error "Configuration validation failed. Check: sudo suricata -T -c $SURICATA_CONFIG -v"
fi

# =============================================================================
# STEP 6: Enable and Start Suricata as a System Service
# WHY: Running as a systemd service means Suricata starts automatically on
#      boot, restarts if it crashes, and integrates with standard Linux
#      service management tools (systemctl, journalctl).
# =============================================================================
info "Step 6: Enabling and starting Suricata service..."

systemctl enable suricata
systemctl restart suricata

# Wait for Suricata to fully initialize
sleep 5

if systemctl is-active --quiet suricata; then
  success "Suricata service is active and running."
else
  error "Suricata failed to start. Check: sudo journalctl -u suricata -n 50"
fi

# =============================================================================
# STEP 7: Set Up Log Rotation
# WHY: Suricata generates a LOT of log data, especially eve.json which logs
#      every network event. Without rotation, logs will fill your SD card.
#      We rotate daily, keep 7 days of history, and compress old logs.
# =============================================================================
info "Step 7: Configuring log rotation..."

cat > /etc/logrotate.d/suricata << 'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl restart suricata > /dev/null 2>&1 || true
    endscript
}
EOF

success "Log rotation configured (daily, 7 days retention, compressed)."

# =============================================================================
# STEP 8: Create a handy alert monitoring alias
# WHY: Typing 'sudo tail -f /var/log/suricata/fast.log' every time is tedious.
#      We add shell aliases so you can just type 'suri-alerts' or 'suri-stats'
#      — small things like this show good operational practice in a portfolio.
# =============================================================================
info "Step 8: Adding monitoring aliases..."

BASHRC="/home/${SUDO_USER:-$USER}/.bashrc"

cat >> "$BASHRC" << 'EOF'

# --- Suricata monitoring aliases (added by pi5_suricata_setup.sh) ---
alias suri-alerts='sudo tail -f /var/log/suricata/fast.log'
alias suri-stats='sudo tail -f /var/log/suricata/stats.log'
alias suri-eve='sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool'
alias suri-status='sudo systemctl status suricata'
alias suri-rules='sudo suricata-update && sudo systemctl restart suricata'
EOF

success "Aliases added to $BASHRC"
info "Run 'source ~/.bashrc' after this script to activate aliases."

# =============================================================================
# STEP 9: Run a Live Detection Test
# WHY: A known-good test confirms the full pipeline works end to end:
#      network capture → rule matching → alert generation → log writing.
#      testmynids.org returns a response containing 'uid=0(root)' which
#      triggers GPL ATTACK_RESPONSE rule SID 2100498.
# =============================================================================
info "Step 9: Running live detection test..."

# Clear existing fast.log so we only see new alerts
> /var/log/suricata/fast.log

# Trigger the test
curl -s http://testmynids.org/uid/index.html > /dev/null

# Wait for Suricata to process the packet
sleep 3

if grep -q "GPL ATTACK_RESPONSE" /var/log/suricata/fast.log 2>/dev/null; then
  success "LIVE DETECTION CONFIRMED! Suricata caught the test alert."
  echo ""
  cat /var/log/suricata/fast.log
else
  warn "Test alert not detected yet. This may be a timing issue."
  warn "Manually verify with: curl http://testmynids.org/uid/index.html"
  warn "Then check: sudo tail -f /var/log/suricata/fast.log"
fi

# =============================================================================
# COMPLETE - Summary
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  Suricata IDS Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  What was configured:"
echo "  [✓] Suricata $SURICATA_VERSION installed from OISF repo"
echo "  [✓] Monitoring interface: $INTERFACE"
echo "  [✓] HOME_NET set to: $SUBNET"
echo "  [✓] $RULE_COUNT detection rules downloaded"
echo "  [✓] Configuration validated"
echo "  [✓] Suricata running as system service"
echo "  [✓] Log rotation configured (7 days)"
echo "  [✓] Monitoring aliases added"
echo "  [✓] Live detection test passed"
echo ""
echo "  Log locations:"
echo "  Alerts:     /var/log/suricata/fast.log"
echo "  Full events:/var/log/suricata/eve.json"
echo "  Stats:      /var/log/suricata/stats.log"
echo ""
echo "  Handy commands (after running source ~/.bashrc):"
echo "  suri-alerts  → watch live alerts"
echo "  suri-stats   → watch statistics"
echo "  suri-status  → check service status"
echo "  suri-rules   → update rules"
echo ""
echo "  NEXT STEPS:"
echo "  1. Run: source ~/.bashrc"
echo "  2. Try: suri-alerts"
echo "  3. Move on to Phase 3: Cowrie Honeypot"
echo "============================================================"
