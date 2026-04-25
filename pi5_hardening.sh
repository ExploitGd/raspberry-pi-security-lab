#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Ubuntu Security Hardening Script
# Author: Your Name
# Project: Home Security Lab Portfolio
# Description: Automates security hardening of a fresh Ubuntu install on Pi 5.
#              Covers user hardening, SSH config, firewall, brute-force 
#              protection, service reduction, and automatic updates.
# Usage: sudo bash pi5_hardening.sh
# =============================================================================

set -e  # Exit immediately if any command fails

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper functions ---
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- Check running as root ---
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root. Use: sudo bash pi5_hardening.sh"
fi

echo ""
echo "============================================================"
echo "  Raspberry Pi 5 - Ubuntu Security Hardening Script"
echo "============================================================"
echo ""

# =============================================================================
# STEP 1: System Update
# WHY: Ensures all existing packages have the latest security patches before
#      we start hardening. Running against outdated packages is pointless.
# =============================================================================
info "Step 1: Updating system packages..."
apt update -y && apt upgrade -y
success "System packages updated."

# =============================================================================
# STEP 2: Create a dedicated admin user
# WHY: Working as root is dangerous — one mistake can destroy the system.
#      A dedicated sudo user limits the blast radius of any mistake or breach.
# =============================================================================
info "Step 2: Checking for admin user..."

NEW_USER="admin"

if id "$NEW_USER" &>/dev/null; then
  warn "User '$NEW_USER' already exists. Skipping creation."
else
  adduser --gecos "" "$NEW_USER"
  usermod -aG sudo "$NEW_USER"
  success "User '$NEW_USER' created and added to sudo group."
fi

# =============================================================================
# STEP 3: SSH Key Authentication
# WHY: Passwords can be brute-forced. SSH keys use asymmetric cryptography —
#      the private key never leaves your machine, making remote attacks
#      practically impossible without physical access to your key file.
# NOTE: Run ssh-keygen on your client machine and copy the public key to
#       /home/admin/.ssh/authorized_keys before disabling password auth below.
# =============================================================================
info "Step 3: Setting up SSH key directory for '$NEW_USER'..."

SSH_DIR="/home/$NEW_USER/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
touch "$AUTH_KEYS"

# Lock down permissions
# WHY: SSH will REFUSE to use authorized_keys if permissions are too open.
#      700 = only owner can read/write/execute the directory
#      600 = only owner can read/write the file
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"

success "SSH directory created with correct permissions."
warn "IMPORTANT: Copy your public key to $AUTH_KEYS before continuing!"
warn "  On your Windows machine run:"
warn "  type \$env:USERPROFILE\\.ssh\\id_ed25519.pub"
warn "  Then paste the output into $AUTH_KEYS on the Pi."

# =============================================================================
# STEP 4: Harden SSH Configuration
# WHY: Default SSH config is permissive. We disable root login (so attackers
#      can't target the most powerful account directly), disable password auth
#      (forces key-only access), and limit retry attempts to slow brute force.
# =============================================================================
info "Step 4: Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original config before modifying
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%F)"
success "SSH config backed up to ${SSHD_CONFIG}.bak.$(date +%F)"

# Apply hardened settings using sed
# Each sed command finds the relevant line (commented or not) and replaces it

# Disable root login - attackers always try root first
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"

# Force key-based authentication only
# IMPORTANT: Only enable this after your key is in authorized_keys!
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"

# Enable public key authentication explicitly
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"

# Disable X11 forwarding - we don't need GUI forwarding, reduces attack surface
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"

# Limit login attempts before disconnecting
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"

# Ensure authorized_keys path is set correctly
sed -i 's|^#*AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' "$SSHD_CONFIG"

# Restart SSH to apply changes
systemctl restart ssh
success "SSH hardened and restarted."

# =============================================================================
# STEP 5: Configure UFW Firewall
# WHY: A firewall is the first line of defense for network traffic.
#      'deny incoming' means nothing gets in unless we explicitly allow it.
#      'allow outgoing' lets the Pi reach the internet for updates etc.
#      We only open port 22 (SSH) since that's all we need right now.
# =============================================================================
info "Step 5: Configuring UFW firewall..."

apt install -y ufw

# Set default policies
ufw default deny incoming   # Block all inbound traffic by default
ufw default allow outgoing  # Allow all outbound traffic

# Allow SSH before enabling, or we'll lock ourselves out!
ufw allow ssh

# Enable firewall non-interactively
echo "y" | ufw enable

success "UFW firewall enabled. SSH traffic allowed."
ufw status verbose

# =============================================================================
# STEP 6: Install and Configure fail2ban
# WHY: Even with key auth, bots will still probe port 22 constantly.
#      fail2ban watches auth logs and auto-bans IPs that fail too many times.
#      This reduces log noise and blocks automated scanners.
# =============================================================================
info "Step 6: Installing and configuring fail2ban..."

apt install -y fail2ban

# Always edit the .local copy, never the original jail.conf
# WHY: jail.conf gets overwritten on updates. jail.local is preserved.
JAIL_LOCAL="/etc/fail2ban/jail.local"
cp /etc/fail2ban/jail.conf "$JAIL_LOCAL"

# Inject SSH jail config
# maxretry=3: ban after 3 failed attempts
# bantime=1h: ban lasts 1 hour
# findtime=10m: count failures within a 10 minute window
cat >> "$JAIL_LOCAL" << 'EOF'

# --- Custom SSH jail added by hardening script ---
[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 1h
findtime = 10m
EOF

systemctl enable fail2ban
systemctl restart fail2ban
success "fail2ban installed and configured."

# Verify it's watching SSH
fail2ban-client status sshd 2>/dev/null || warn "fail2ban started but sshd jail not yet active. Check: sudo fail2ban-client status sshd"

# =============================================================================
# STEP 7: Disable Unnecessary Services
# WHY: Every running service is a potential attack vector. Services like
#      Bluetooth, printing (CUPS), and mDNS (Avahi) are not needed on a
#      headless security lab and should be disabled to reduce attack surface.
# =============================================================================
info "Step 7: Disabling unnecessary services..."

SERVICES_TO_DISABLE=(
  "bluetooth"       # Not needed on a lab server
  "cups"            # Printing service - not needed
  "cups-browsed"    # Network printer discovery - not needed
  "avahi-daemon"    # mDNS/Bonjour - not needed, can leak network info
  "colord"          # Color profile management - not needed on a server
  "ModemManager"    # Mobile modem management - not needed
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    systemctl disable --now "$service"
    success "Disabled: $service"
  else
    warn "Service not found or already inactive: $service"
  fi
done

# =============================================================================
# STEP 8: Enable Automatic Security Updates
# WHY: New vulnerabilities are discovered constantly. Automatic updates ensure
#      security patches are applied quickly without manual intervention.
#      We only enable security updates (not all updates) to avoid breaking changes.
# =============================================================================
info "Step 8: Enabling automatic security updates..."

apt install -y unattended-upgrades

# Enable unattended upgrades non-interactively
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades

systemctl enable unattended-upgrades
systemctl start unattended-upgrades
success "Automatic security updates enabled."

# =============================================================================
# HARDENING COMPLETE - Summary
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  Security Hardening Complete!${NC}"
echo "============================================================"
echo ""
echo "  What was hardened:"
echo "  [✓] System packages updated"
echo "  [✓] Admin user created: $NEW_USER"
echo "  [✓] SSH directory created with correct permissions"
echo "  [✓] SSH: root login disabled"
echo "  [✓] SSH: password authentication disabled"
echo "  [✓] SSH: public key authentication enabled"
echo "  [✓] SSH: max auth tries set to 3"
echo "  [✓] UFW firewall enabled (deny incoming, allow SSH)"
echo "  [✓] fail2ban configured (3 retries, 1hr ban)"
echo "  [✓] Unnecessary services disabled"
echo "  [✓] Automatic security updates enabled"
echo ""
echo -e "${YELLOW}  NEXT STEPS:${NC}"
echo "  1. Verify SSH key login works from your client machine"
echo "  2. Check firewall: sudo ufw status verbose"
echo "  3. Check fail2ban: sudo fail2ban-client status sshd"
echo "  4. Move on to Phase 2: Install Suricata IDS"
echo ""
echo "  SSH config backup: ${SSHD_CONFIG}.bak.$(date +%F)"
echo "============================================================"
