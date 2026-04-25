#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Grafana + Loki + Promtail Dashboard Setup Script
# Author: Your Name
# Project: Home Security Lab Portfolio
# Description: Automates the installation of Grafana, Loki, and Promtail
#              to create a live security dashboard visualizing Suricata IDS
#              alerts and Cowrie honeypot events.
# Usage: sudo bash pi5_dashboard_setup.sh
# =============================================================================

set -e

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root. Use: sudo bash pi5_dashboard_setup.sh"
fi

# --- Detect architecture for correct binary downloads ---
ARCH=$(dpkg --print-architecture)
if [[ "$ARCH" == "arm64" ]]; then
  LOKI_ARCH="arm64"
else
  LOKI_ARCH="amd64"
fi

LOKI_VERSION="3.0.0"
LOKI_BASE_URL="https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}"

echo ""
echo "============================================================"
echo "  Raspberry Pi 5 - Security Dashboard Setup"
echo "  Grafana + Loki + Promtail"
echo "============================================================"
echo ""

# =============================================================================
# STEP 1: Install Grafana
# WHY: Grafana is the industry-standard open source dashboard tool used by
#      SOC teams worldwide. It connects to data sources like Loki and renders
#      logs, metrics, and alerts into visual panels. Running it locally on
#      the Pi means our sensitive security data never leaves our network.
# =============================================================================
info "Step 1: Installing Grafana..."

apt install -y apt-transport-https software-properties-common wget gnupg

# Add official Grafana GPG key and repo
# WHY: Using the official repo ensures we get signed, verified packages
#      and automatic updates via apt rather than manual binary management
mkdir -p /etc/apt/keyrings
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list

apt update -y
apt install -y grafana

systemctl enable grafana-server
systemctl start grafana-server

sleep 3

if systemctl is-active --quiet grafana-server; then
  success "Grafana installed and running on port 3000."
else
  error "Grafana failed to start. Check: sudo journalctl -u grafana-server -n 30"
fi

# =============================================================================
# STEP 2: Install Loki
# WHY: Loki is Grafana's log aggregation system — think of it as a database
#      specifically designed for logs. Unlike Elasticsearch, Loki indexes only
#      metadata (labels) rather than full log content, making it extremely
#      lightweight and perfect for a Pi. It receives logs from Promtail and
#      makes them queryable in Grafana using LogQL query language.
# =============================================================================
info "Step 2: Installing Loki v${LOKI_VERSION}..."

cd /tmp
wget -q "${LOKI_BASE_URL}/loki-linux-${LOKI_ARCH}.zip" -O loki.zip
apt install -y unzip
unzip -o loki.zip
mv "loki-linux-${LOKI_ARCH}" /usr/local/bin/loki
chmod +x /usr/local/bin/loki

success "Loki binary installed to /usr/local/bin/loki"

# Create storage directories
# WHY: Loki needs separate directories for different storage components:
#      chunks = compressed log data, index = label index, rules = alert rules
mkdir -p /var/lib/loki/{chunks,index,rules,cache}
mkdir -p /etc/loki

# Write Loki v3 compatible config
# WHY: Loki v3 uses a 'common' block that simplifies config significantly.
#      tsdb store with v13 schema is the recommended setup for new installs.
cat > /etc/loki/loki-config.yaml << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093
EOF

# Create systemd service for Loki
cat > /etc/systemd/system/loki.service << 'EOF'
[Unit]
Description=Loki Log Aggregator
After=network.target
Documentation=https://grafana.com/docs/loki/latest/

[Service]
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable loki
systemctl start loki

sleep 5

if systemctl is-active --quiet loki; then
  success "Loki running on port 3100."
else
  error "Loki failed to start. Check: sudo journalctl -u loki -n 30"
fi

# =============================================================================
# STEP 3: Install Promtail
# WHY: Promtail is the log shipper that sits on the same machine as your logs
#      and tails them in real time, adding labels and forwarding to Loki.
#      It's configured to watch both Suricata's eve.json (network alerts) and
#      Cowrie's cowrie.json (honeypot events), tagging each with a job label
#      so we can query them separately in Grafana.
# =============================================================================
info "Step 3: Installing Promtail v${LOKI_VERSION}..."

cd /tmp
wget -q "${LOKI_BASE_URL}/promtail-linux-${LOKI_ARCH}.zip" -O promtail.zip
unzip -o promtail.zip
mv "promtail-linux-${LOKI_ARCH}" /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail

success "Promtail binary installed to /usr/local/bin/promtail"

mkdir -p /etc/promtail

# Write Promtail config
# WHY: We define two scrape jobs:
#      1. suricata: tails eve.json for IDS alerts
#      2. cowrie: tails cowrie.json for honeypot sessions
#      Labels let us filter by source in Grafana queries using {job="suricata"}
cat > /etc/promtail/promtail-config.yaml << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  # Suricata IDS alerts
  # WHY: eve.json is Suricata's JSON output format containing full event data
  #      including alert signatures, source/dest IPs, protocols, and severity
  - job_name: suricata
    static_configs:
      - targets:
          - localhost
        labels:
          job: suricata
          host: pi5-security-lab
          __path__: /var/log/suricata/eve.json

  # Cowrie honeypot events
  # WHY: cowrie.json logs all honeypot interactions including login attempts,
  #      credentials used, commands executed, and session duration
  - job_name: cowrie
    static_configs:
      - targets:
          - localhost
        labels:
          job: cowrie
          host: pi5-security-lab
          __path__: /home/cowrie/cowrie/var/log/cowrie/cowrie.json
EOF

# Create systemd service for Promtail
cat > /etc/systemd/system/promtail.service << 'EOF'
[Unit]
Description=Promtail Log Shipper
After=network.target loki.service
Documentation=https://grafana.com/docs/loki/latest/clients/promtail/

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail-config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable promtail
systemctl start promtail

sleep 3

if systemctl is-active --quiet promtail; then
  success "Promtail running on port 9080."
else
  error "Promtail failed to start. Check: sudo journalctl -u promtail -n 30"
fi

# =============================================================================
# STEP 4: Open Firewall for Grafana
# WHY: We only expose Grafana (3000) externally so we can access the dashboard
#      from our Windows machine. Loki (3100) and Promtail (9080) stay internal
#      — there's no reason for external access to the log pipeline.
# =============================================================================
info "Step 4: Opening firewall for Grafana..."

ufw allow 3000/tcp
success "Port 3000 opened for Grafana."

# =============================================================================
# STEP 5: Provision Loki as a Grafana Data Source Automatically
# WHY: Grafana supports provisioning via config files, meaning data sources
#      and dashboards can be set up automatically without clicking through
#      the UI. This is how it's done in production environments and shows
#      understanding of infrastructure-as-code principles.
# =============================================================================
info "Step 5: Provisioning Loki as Grafana data source..."

mkdir -p /etc/grafana/provisioning/datasources

cat > /etc/grafana/provisioning/datasources/loki.yaml << 'EOF'
apiVersion: 1

datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://localhost:3100
    isDefault: true
    version: 1
    editable: true
EOF

# Restart Grafana to pick up the provisioned data source
systemctl restart grafana-server
sleep 5
success "Loki provisioned as default Grafana data source."

# =============================================================================
# STEP 6: Add Monitoring Aliases
# =============================================================================
info "Step 6: Adding monitoring aliases..."

BASHRC="/home/${SUDO_USER:-$USER}/.bashrc"

cat >> "$BASHRC" << 'EOF'

# --- Dashboard monitoring aliases (added by pi5_dashboard_setup.sh) ---
alias dash-grafana='sudo systemctl status grafana-server'
alias dash-loki='sudo systemctl status loki'
alias dash-promtail='sudo systemctl status promtail'
alias dash-restart='sudo systemctl restart grafana-server loki promtail'
alias dash-logs='sudo journalctl -u grafana-server -u loki -u promtail -f'
EOF

success "Aliases added to $BASHRC"

# =============================================================================
# COMPLETE - Summary
# =============================================================================

# Get Pi's IP for the dashboard URL
PI_IP=$(ip route | grep default | awk '{NR==1; print $9}' | head -n1)
if [[ -z "$PI_IP" ]]; then
  PI_IP=$(hostname -I | awk '{print $1}')
fi

echo ""
echo "============================================================"
echo -e "${GREEN}  Security Dashboard Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  What was installed:"
echo "  [✓] Grafana (dashboard UI) — port 3000"
echo "  [✓] Loki (log aggregator) — port 3100"
echo "  [✓] Promtail (log shipper) — port 9080"
echo "  [✓] Loki provisioned as Grafana data source"
echo "  [✓] Firewall opened for Grafana"
echo "  [✓] Monitoring aliases added"
echo ""
echo "  Log sources being monitored:"
echo "  [✓] Suricata: /var/log/suricata/eve.json"
echo "  [✓] Cowrie:   /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
echo ""
echo "  Access your dashboard:"
echo "  URL:      http://${PI_IP}:3000"
echo "  Username: admin"
echo "  Password: admin (change this on first login!)"
echo ""
echo "  Suggested Grafana panels:"
echo "  {job=\"suricata\"}              → Suricata alert logs"
echo "  {job=\"cowrie\"}                → Cowrie honeypot events"
echo "  count_over_time({job=\"suricata\"}[24h]) → Alert count stat"
echo ""
echo "  Handy commands (after running source ~/.bashrc):"
echo "  dash-grafana   → check Grafana status"
echo "  dash-loki      → check Loki status"
echo "  dash-promtail  → check Promtail status"
echo "  dash-restart   → restart all dashboard services"
echo "  dash-logs      → tail all dashboard logs"
echo ""
echo "  NEXT STEPS:"
echo "  1. Open http://${PI_IP}:3000 in your browser"
echo "  2. Log in and change the default password"
echo "  3. Create dashboards using the queries above"
echo "  4. Write up your portfolio README!"
echo "============================================================"
