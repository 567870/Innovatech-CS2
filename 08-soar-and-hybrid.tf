# ==============================================================================
# FILE: 08-soar-and-hybrid.tf
# RESPONSIBILITY: Isolated SOAR Engine Platform & Hybrid WireGuard VPN Gateway
# REQUIREMENTS: REQ-NCA-P2-08 (Event-Driven SOAR), REQ-NCA-P2-09 (SOAR Metrics)
# ==============================================================================

resource "aws_instance" "soar_server" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.public_1a.id
  iam_instance_profile   = aws_iam_instance_profile.soar_profile.name
  vpc_security_group_ids = [aws_security_group.soar_sg.id]

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
    ignore_changes = [ami]
  }

  user_data_replace_on_change = true

  user_data = <<-EOF
#!/bin/bash
dnf update -y
dnf install -y docker wireguard-tools iptables-nft
systemctl enable --now docker

sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# ------------------------------------------------------------------------------
# 0. Hybrid WireGuard Site-to-Site Tunnel
# ------------------------------------------------------------------------------
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
umask 077

if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey | tee /etc/wireguard/server_private.key \
    | wg pubkey > /etc/wireguard/server_public.key
fi

cat << WGCONF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ens5 -j MASQUERADE
WGCONF

if [ -n "${var.wireguard_peer_public_key}" ]; then
  cat << WGPEER >> /etc/wireguard/wg0.conf

[Peer]
PublicKey = ${var.wireguard_peer_public_key}
AllowedIPs = 10.99.0.2/32, ${var.onprem_gns3_cidr}
WGPEER
fi

chmod 600 /etc/wireguard/wg0.conf

cat << SYSCTL > /etc/sysctl.d/99-wireguard.conf
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system
systemctl enable --now wg-quick@wg0

# ------------------------------------------------------------------------------
# 1. Build the Containerized Python Event-Driven SOAR System
# ------------------------------------------------------------------------------
mkdir -p /opt/soar-engine /var/log/soar
cd /opt/soar-engine

export VPC_ID="${aws_vpc.main.id}"

cat << 'PY' > app.py
import os
import re
import json
import time
import socket
import datetime
import threading
import subprocess
import boto3
import random
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, Response
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)
ec2_client = boto3.client('ec2', region_name='eu-central-1')
VPC_ID = os.environ.get('VPC_ID')

# ---------------- Prometheus Metrics ----------------
SOAR_EVENTS_RECEIVED = Counter('soar_events_received_total', 'Total security events ingested', ['alert_type', 'severity', 'source_platform'])
SOAR_ACTIONS_EXECUTED = Counter('soar_actions_executed_total', 'Total automated response actions executed', ['action', 'status'])
SOAR_BLOCKED_IPS = Gauge('soar_blocked_ips_active', 'Current number of malicious IPs actively quarantined')
SOAR_BANNED_IP_LIST = Gauge('soar_banned_ip_list', 'Actively quarantined IP addresses', ['ip'])

SOAR_EVENTS_RECEIVED.labels(alert_type='SSHBruteForce', severity='critical', source_platform='gns3-onprem').inc(0)
SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='success').inc(0)
SOAR_ACTIONS_EXECUTED.labels(action='aws_nacl_quarantine', status='success').inc(0)
SOAR_BLOCKED_IPS.set(0)

QUARANTINED_IPS = set()
INCIDENT_HISTORY = []
SSH_FAILURE_TRACKER = {}
INCIDENT_LOG_FILE = '/var/log/soar/soar_incidents.json'
PROTECTED_IPS = {"127.0.0.1", "192.168.1.1", "192.168.1.10", "10.99.0.1", "10.99.0.2"}
PROTECTED_PREFIXES = ("10.0.",)

# ---------------- Security & Auth ----------------
def check_auth(username, password):
    return username == 'admin' and password == 'admin'

def authenticate():
    return Response('Access Denied: Please log in with valid credentials.\n', 401, {'WWW-Authenticate': 'Basic realm="SOAR Portal"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def is_protected_ip(ip):
    return ip in PROTECTED_IPS or str(ip).startswith(PROTECTED_PREFIXES)

# ---------------- Automated Containment Actions ----------------
def action_quarantine_ip(attacker_ip, target_host, reason):
    if is_protected_ip(attacker_ip): return False, f"IP {attacker_ip} is protected"
    try:
        QUARANTINED_IPS.add(attacker_ip)
        SOAR_BLOCKED_IPS.set(len(QUARANTINED_IPS))
        SOAR_BANNED_IP_LIST.labels(ip=attacker_ip).set(1)
        subprocess.run(['iptables', '-I', 'FORWARD', '-s', attacker_ip, '-j', 'DROP'], check=False)
        SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='success').inc()
        return True, f"IP blocked on hybrid firewall"
    except Exception as e:
        return False, str(e)

def action_aws_nacl_block(attacker_ip):
    if not VPC_ID or is_protected_ip(attacker_ip): return False, "Skipped"
    try:
        nacl_id = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}])['NetworkAcls'][0]['NetworkAclId']
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id, RuleNumber=random.randint(1000, 30000), Protocol='-1',
            RuleAction='deny', Egress=False, CidrBlock=f"{attacker_ip}/32"
        )
        SOAR_ACTIONS_EXECUTED.labels(action='aws_nacl_quarantine', status='success').inc()
        return True, f"IP {attacker_ip} blocked at AWS NACL"
    except Exception as e:
        return False, str(e)

def action_log_and_notify(incident_record):
    os.makedirs(os.path.dirname(INCIDENT_LOG_FILE), exist_ok=True)
    with open(INCIDENT_LOG_FILE, 'a') as f: f.write(json.dumps(incident_record) + '\n')
    INCIDENT_HISTORY.append(incident_record)

def evaluate_and_respond(alert_type, severity, source_ip, target_host, raw_message, platform='gns3-onprem'):
    SOAR_EVENTS_RECEIVED.labels(alert_type=alert_type, severity=severity, source_platform=platform).inc()
    if severity in ['critical', 'high'] or alert_type in ['SSHBruteForce', 'FirewallPortScan']:
        action_quarantine_ip(source_ip, target_host, alert_type)
        action_aws_nacl_block(source_ip)
    incident = {'timestamp': datetime.datetime.utcnow().isoformat() + 'Z', 'alert_type': alert_type, 'attacker_ip': source_ip}
    action_log_and_notify(incident)

# ---------------- Automated UNBLOCK Action ----------------
def unblock_ip(ip):
    if ip in QUARANTINED_IPS:
        QUARANTINED_IPS.remove(ip)
    SOAR_BLOCKED_IPS.set(len(QUARANTINED_IPS))
    try:
        SOAR_BANNED_IP_LIST.remove(ip)
    except Exception:
        SOAR_BANNED_IP_LIST.labels(ip=ip).set(0)

    # 1. Unblock local hybrid transit firewall
    subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], check=False)
    
    # 2. Dynamically search and remove from AWS NACL
    if VPC_ID:
        try:
            nacl = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}])['NetworkAcls'][0]
            nacl_id = nacl['NetworkAclId']
            for entry in nacl['Entries']:
                if entry.get('CidrBlock') == f"{ip}/32" and entry.get('RuleAction') == 'deny':
                    ec2_client.delete_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=entry['RuleNumber'], Egress=entry['Egress'])
        except Exception:
            pass

# ---------------- Event Listeners ----------------
def udp_syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5140))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            line = data.decode('utf-8', errors='ignore').strip()
            if 'Failed password' in line or 'Invalid user' in line:
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                attacker_ip = ip_match.group(1) if ip_match else addr[0]
                now = time.time()
                history = [t for t in SSH_FAILURE_TRACKER.get(attacker_ip, []) if now - t < 120]
                history.append(now)
                SSH_FAILURE_TRACKER[attacker_ip] = history
                if len(history) >= 3:
                    evaluate_and_respond('SSHBruteForce', 'critical', attacker_ip, '192.168.1.10', line)
                    SSH_FAILURE_TRACKER[attacker_ip] = []
        except Exception:
            continue

# ---------------- Web Interface & APIs ----------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Innovatech SOAR Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; margin: 40px; }
        .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        .btn { padding: 8px 16px; color: white; background-color: #e74c3c; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .btn:hover { background-color: #c0392b; }
        .success { color: #27ae60; background: #e8f8f5; padding: 10px; border-radius: 4px; margin-bottom: 20px; border-left: 5px solid #27ae60; }
        .footer { margin-top: 30px; font-size: 0.9em; color: #7f8c8d; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Innovatech SOAR Management Portal</h1>
        <p>Active Quarantined IP Addresses. These IPs are actively blocked via AWS Network ACLs and the Hybrid Transit Firewall.</p>
        {% if message %} <div class="success"><b>System Notice:</b> {{ message }}</div> {% endif %}
        <table>
            <tr><th>Attacker IP Address</th><th>Containment Action</th></tr>
            {% for ip in ips %}
            <tr>
                <td><strong>{{ ip }}</strong></td>
                <td>
                    <form method="POST" action="/unblock/{{ ip }}" style="margin:0;">
                        <button type="submit" class="btn">Unblock IP</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="2" style="text-align: center; color: #7f8c8d; padding: 20px;">No active security threats currently quarantined.</td></tr>
            {% endfor %}
        </table>
        <div class="footer">Innovatech Waterschap Brabantse Delta CS2 Architecture | End-to-End SOAR</div>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
@requires_auth
def index():
    msg = request.args.get('msg')
    return render_template_string(HTML_TEMPLATE, ips=list(QUARANTINED_IPS), message=msg)

@app.route('/unblock/<ip>', methods=['POST'])
@requires_auth
def route_unblock(ip):
    unblock_ip(ip)
    return redirect(url_for('index', msg=f"Threat Contained: IP {ip} has been successfully unblocked across AWS and Hybrid Transit."))

@app.route('/blocklist.txt', methods=['GET'])
def blocklist():
    return "\n".join(list(QUARANTINED_IPS)) + "\n", 200, {'Content-Type': 'text/plain'}

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'service': 'SOAR', 'status': 'online'}), 200

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

resource "aws_eip" "hybrid_vpn_eip" {
  domain     = "vpc"
  instance   = aws_instance.soar_server.id
  depends_on = [aws_internet_gateway.igw]

  tags = {
    Name = "Hybrid-VPN-EIP"
  }
}