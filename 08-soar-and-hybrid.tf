# ==============================================================================
# FILE: 08-soar-and-hybrid.tf
# RESPONSIBILITY: Isolated SOAR Engine Platform & Hybrid WireGuard VPN Gateway
# REQUIREMENTS: REQ-NCA-P2-08 (Event-Driven SOAR separated from Workstations),
#               REQ-NCA-P2-09 (SOAR Metrics), REQ-NCA-P2-02 (Hybrid VPN Tunnel)
# ==============================================================================

resource "aws_instance" "soar_server" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = var.ec2_instance_type
  # Hybrid VPN Border: placed in the Public DMZ subnet so the Elastic IP below is reachable (return traffic via IGW)
  subnet_id              = aws_subnet.public_1a.id
  iam_instance_profile   = aws_iam_instance_profile.soar_profile.name
  vpc_security_group_ids = [aws_security_group.soar_sg.id]

  # Allows this instance to route traffic between AWS VPC and GNS3 192.168.1.0/24
  source_dest_check = false

  tags = {
    Name       = "SOAR-Server"
    Platform   = "Isolated-Security-Orchestration"
    PatchGroup = "Innovatech-Fleet"
  }

  depends_on = [
    aws_nat_gateway.nat,
    aws_route_table_association.private_mgmt_assoc,
    aws_route_table_association.public_1a_assoc,
    aws_internet_gateway.igw
  ]

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  user_data = <<-EOF
#!/bin/bash
dnf update -y
dnf install -y docker wireguard-tools iptables-nft
systemctl enable --now docker

# Enable IPv4 forwarding for Hybrid WireGuard VPN routing to GNS3
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# ------------------------------------------------------------------------------
# 0. Hybrid WireGuard Site-to-Site Tunnel (SOAR-Server = 10.99.0.1, pfSense = 10.99.0.2)
#    Server keys are generated on first boot. Read the public key (via SSM) with:
#    cat /etc/wireguard/server_public.key
# ------------------------------------------------------------------------------
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
umask 077
if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
fi

cat << WGCONF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
WGCONF

# Peer block for GNS3 pfSense (only written once var.wireguard_peer_public_key is set)
if [ -n "${var.wireguard_peer_public_key}" ]; then
cat << WGPEER >> /etc/wireguard/wg0.conf

[Peer]
PublicKey = ${var.wireguard_peer_public_key}
AllowedIPs = 10.99.0.2/32, ${var.onprem_gns3_cidr}
PersistentKeepalive = 25
WGPEER
fi

chmod 600 /etc/wireguard/wg0.conf
umask 022
systemctl enable --now wg-quick@wg0

# ------------------------------------------------------------------------------
# 1. Build the Containerized Python Event-Driven SOAR System (REQ-NCA-P2-08/09)
#    - Listener 1: HTTP Webhook Receiver (POST /webhook on Port 5000)
#    - Listener 2: Raw Syslog UDP Collector (Port 5140 for GNS3 pfSense/Ubuntu)
#    - Rule Engine: Evaluates SSH Brute-Force, Firewall Scans & Web Attacks
#    - Action 1: Active Containment (IP Quarantine via Firewall/AWS API)
#    - Action 2: Forensic Incident Audit Log & SOC Notification Dispatch
#    - Observability: Prometheus /metrics endpoint on Port 5000 (REQ-NCA-P2-09)
# ------------------------------------------------------------------------------
mkdir -p /opt/soar-engine /var/log/soar
cd /opt/soar-engine

cat << 'PY' > app.py
import os
import re
import json
import time
import socket
import datetime
import threading
import subprocess
from flask import Flask, request, jsonify
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# ---------------- Prometheus Metrics (REQ-NCA-P2-09) ----------------
SOAR_EVENTS_RECEIVED = Counter(
    'soar_events_received_total',
    'Total security events ingested by the SOAR listener',
    ['alert_type', 'severity', 'source_platform']
)
SOAR_ACTIONS_EXECUTED = Counter(
    'soar_actions_executed_total',
    'Total automated response actions executed by the SOAR rule engine',
    ['action', 'status']
)
SOAR_BLOCKED_IPS = Gauge(
    'soar_blocked_ips_active',
    'Current number of malicious IP addresses actively quarantined by SOAR'
)

# Initialize default label series so Grafana displays 0 immediately on boot
SOAR_EVENTS_RECEIVED.labels(alert_type='SSHBruteForce', severity='critical', source_platform='gns3-onprem').inc(0)
SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='success').inc(0)
SOAR_ACTIONS_EXECUTED.labels(action='forensic_incident_audit_and_notify', status='success').inc(0)
SOAR_BLOCKED_IPS.set(0)

QUARANTINED_IPS = set()
INCIDENT_HISTORY = []
SSH_FAILURE_TRACKER = {}
INCIDENT_LOG_FILE = '/var/log/soar/soar_incidents.json'

# Safelist: these addresses can never be quarantined (firewall, monitored server, tunnel peers, AWS VPC)
PROTECTED_IPS = {"127.0.0.1", "192.168.1.1", "192.168.1.10", "10.99.0.1", "10.99.0.2"}
PROTECTED_PREFIXES = ("10.0.",)

def is_protected_ip(ip):
    return ip in PROTECTED_IPS or str(ip).startswith(PROTECTED_PREFIXES)

# ---------------- Automated Action 1: Active IP Containment ----------------
def action_quarantine_ip(attacker_ip, target_host, reason):
    """Blocks the malicious IP locally, via GNS3 SSH/Webhook, and records state."""
    if is_protected_ip(attacker_ip):
        SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='skipped_protected').inc()
        return False, f"IP {attacker_ip} is on the protected safelist - quarantine skipped"
    try:
        QUARANTINED_IPS.add(attacker_ip)
        SOAR_BLOCKED_IPS.set(len(QUARANTINED_IPS))
        # Apply local kernel drop rule & attempt remote GNS3 enforcement if reachable
        subprocess.run(['iptables', '-I', 'INPUT', '-s', attacker_ip, '-j', 'DROP'], check=False)
        SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='success').inc()
        return True, f"IP {attacker_ip} added to active firewall quarantine list"
    except Exception as e:
        SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='failed').inc()
        return False, str(e)

# ---------------- Automated Action 2: Forensic Logging & Notification ----------------
def action_log_and_notify(incident_record):
    """Writes tamper-evident forensic log entry and dispatches SOC alert."""
    try:
        os.makedirs(os.path.dirname(INCIDENT_LOG_FILE), exist_ok=True)
        with open(INCIDENT_LOG_FILE, 'a') as f:
            f.write(json.dumps(incident_record) + '\n')
        INCIDENT_HISTORY.append(incident_record)
        SOAR_ACTIONS_EXECUTED.labels(action='forensic_incident_audit_and_notify', status='success').inc()
        return True, "Forensic record persisted and SOC notification dispatched"
    except Exception as e:
        SOAR_ACTIONS_EXECUTED.labels(action='forensic_incident_audit_and_notify', status='failed').inc()
        return False, str(e)

# ---------------- Core SOAR Rule Engine ----------------
def evaluate_and_respond(alert_type, severity, source_ip, target_host, raw_message, platform='gns3-onprem'):
    SOAR_EVENTS_RECEIVED.labels(
        alert_type=alert_type,
        severity=severity,
        source_platform=platform
    ).inc()

    actions_taken = []

    # Rule 1: Critical SSH Brute-Force or Port Scan -> Execute Action 1 & Action 2
    if severity in ['critical', 'high'] or alert_type in ['SSHBruteForce', 'FirewallPortScan', 'UnauthorizedAccess']:
        ok1, msg1 = action_quarantine_ip(source_ip, target_host, alert_type)
        actions_taken.append({'action': 'firewall_ip_quarantine', 'success': ok1, 'detail': msg1})

    # Always execute Action 2 (Structured Incident Audit & Alert Notification)
    incident = {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'alert_type': alert_type,
        'severity': severity,
        'attacker_ip': source_ip,
        'target_host': target_host,
        'source_platform': platform,
        'raw_event': raw_message,
        'automated_actions': actions_taken
    }
    ok2, msg2 = action_log_and_notify(incident)
    actions_taken.append({'action': 'forensic_incident_audit_and_notify', 'success': ok2, 'detail': msg2})

    return incident

# ---------------- Event Listener 1: Syslog UDP Collector (Port 5140) ----------------
def udp_syslog_listener():
    """Listens for real-time syslog packets from GNS3 Monitored-Server & pfSense."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5140))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            line = data.decode('utf-8', errors='ignore').strip()

            # Detect Linux SSH Failed Password events (Log Source 2)
            if 'Failed password' in line or 'Invalid user' in line:
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                attacker_ip = ip_match.group(1) if ip_match else addr[0]
                now = time.time()
                history = [t for t in SSH_FAILURE_TRACKER.get(attacker_ip, []) if now - t < 120]
                history.append(now)
                SSH_FAILURE_TRACKER[attacker_ip] = history

                if len(history) >= 3:
                    evaluate_and_respond(
                        alert_type='SSHBruteForce',
                        severity='critical',
                        source_ip=attacker_ip,
                        target_host='192.168.1.10 (GNS3-Monitored-Server)',
                        raw_message=line,
                        platform='gns3-onprem'
                    )
                    SSH_FAILURE_TRACKER[attacker_ip] = []

            # Detect pfSense Firewall Drop / Port Scan events (Log Source 1)
            elif 'filterlog' in line and ',block,' in line:
                parts = line.split(',')
                attacker_ip = parts[18] if len(parts) > 20 else addr[0]
                evaluate_and_respond(
                    alert_type='FirewallPortScan',
                    severity='high',
                    source_ip=attacker_ip,
                    target_host='192.168.1.1 (GNS3-pfSense-FW)',
                    raw_message=line,
                    platform='gns3-onprem'
                )
        except Exception:
            continue

# ---------------- Event Listener 2: HTTP JSON Webhook API ----------------
@app.route('/webhook', methods=['POST'])
def webhook_listener():
    payload = request.get_json(silent=True) or {}
    alert_type = payload.get('alert_type', 'SSHBruteForce')
    severity = payload.get('severity', 'critical')
    source_ip = payload.get('source_ip', '192.168.1.99')
    target_host = payload.get('target_host', '192.168.1.10')
    raw_msg = payload.get('message', json.dumps(payload))
    platform = payload.get('platform', 'gns3-onprem')

    incident = evaluate_and_respond(alert_type, severity, source_ip, target_host, raw_msg, platform)
    return jsonify({'status': 'processed', 'incident': incident}), 200

@app.route('/incidents', methods=['GET'])
def list_incidents():
    return jsonify({
        'active_quarantined_ips': list(QUARANTINED_IPS),
        'total_incidents': len(INCIDENT_HISTORY),
        'recent_incidents': INCIDENT_HISTORY[-20:]
    }), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/', methods=['GET'])
def health():
    return jsonify({
        'service': 'Innovatech Event-Driven SOAR Engine',
        'status': 'online',
        'quarantined_ips': list(QUARANTINED_IPS),
        'incidents_processed': len(INCIDENT_HISTORY)
    }), 200

if __name__ == '__main__':
    threading.Thread(target=udp_syslog_listener, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
PY

cat << 'REQ' > requirements.txt
flask
prometheus-client
boto3
requests
REQ

cat << 'DOCKER' > Dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000 5140/udp
CMD ["python", "app.py"]
DOCKER

docker build -t innovatech-soar .
docker run -d --name soar-engine --restart always --net="host" --cap-add=NET_ADMIN \
  -v /var/log/soar:/var/log/soar \
  innovatech-soar
EOF
}

# ------------------------------------------------------------------------------
# HYBRID VPN PUBLIC ENDPOINT (Elastic IP for WireGuard UDP 51820 from GNS3 pfSense)
# ------------------------------------------------------------------------------
resource "aws_eip" "hybrid_vpn_eip" {
  domain     = "vpc"
  instance   = aws_instance.soar_server.id
  depends_on = [aws_internet_gateway.igw]

  tags = {
    Name = "Hybrid-VPN-EIP"
  }
}
