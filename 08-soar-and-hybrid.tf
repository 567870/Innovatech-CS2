# ==============================================================================
# FILE: 08-soar-and-hybrid.tf
# RESPONSIBILITY: Isolated SOAR Engine Platform & Hybrid WireGuard VPN Gateway
# REQUIREMENTS: REQ-NCA-P2-08 (Event-Driven SOAR), REQ-NCA-P2-09 (SOAR Metrics)
#
# WHAT THE SOAR DOES
#   - Detects SSH brute force from syslog (UDP 5140) and quarantines the attacker on:
#       1. the hybrid gateway firewall (iptables FORWARD)
#       2. the AWS Network ACL(s) of the VPC
#       3. the pfSense firewall in GNS3, pushed over the WireGuard tunnel (SSH + pfctl)
#   - Keeps its state on disk, so quarantines survive a container restart / reboot
#   - Portal (port 5000) is reachable ONLY from the admin IP; /metrics also from Prometheus
# ==============================================================================

locals {
  # Only this IP may open the SOAR portal (port 5000).
  soar_portal_allowed_ip = "192.168.1.5"

  # pfSense push over the WireGuard tunnel (SSH + pfctl).
  soar_pfsense_push     = "true"
  soar_pfsense_ssh_host = "10.99.0.2" # pfSense tunnel address
  soar_pfsense_ssh_user = "admin"
  soar_pfsense_table    = "SOAR_BLOCKLIST" # alias name that must exist on pfSense

  # Leave empty = block on every NACL in the VPC that has subnets associated.
  # Or pin explicit NACLs, e.g. "acl-0123456789abcdef0,acl-0fedcba9876543210".
  soar_nacl_ids = ""

  soar_bootstrap = <<-EOT
#!/bin/bash
dnf update -y
dnf install -y docker wireguard-tools iptables-nft openssh-clients
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
# 1. Persistent directories + SSH key used to push the blocklist to pfSense
# ------------------------------------------------------------------------------
mkdir -p /opt/soar-engine /opt/soar-engine/ssh /var/log/soar /var/lib/soar
chmod 700 /opt/soar-engine/ssh

if [ ! -f /opt/soar-engine/ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -N "" -C "soar-engine" -f /opt/soar-engine/ssh/id_ed25519
fi

# ------------------------------------------------------------------------------
# 2. Build the Containerized Python Event-Driven SOAR System
# ------------------------------------------------------------------------------
cd /opt/soar-engine

cat << 'PY' > app.py
import os
import re
import json
import time
import hmac
import socket
import secrets
import logging
import ipaddress
import datetime
import threading
import subprocess
from collections import deque
from functools import wraps

import boto3
from botocore.exceptions import ClientError
from flask import (Flask, request, jsonify, render_template_string, redirect,
                   url_for, Response, flash, session)
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('soar')

# ---------------- Configuration (all injected by Terraform via docker -e) ----------------
def env_list(name, default=''):
    return [x.strip() for x in os.environ.get(name, default).split(',') if x.strip()]

REGION = os.environ.get('AWS_REGION', 'eu-central-1')
VPC_ID = os.environ.get('VPC_ID')
NACL_IDS_PINNED = env_list('NACL_IDS')
# Deny rules MUST sit below the first "allow" rule (default NACL allow-all is rule 100),
# otherwise they are never evaluated. 1-99 is the safe range.
NACL_RULE_MIN = int(os.environ.get('NACL_RULE_MIN', '1'))
NACL_RULE_MAX = int(os.environ.get('NACL_RULE_MAX', '99'))

PORTAL_ALLOWED_IPS = set(env_list('PORTAL_ALLOWED_IPS', '192.168.1.5'))
METRICS_ALLOWED_NETS = [ipaddress.ip_network(c, strict=False) for c in env_list('METRICS_ALLOWED_CIDRS')]
PROTECTED_NETS = [ipaddress.ip_network(c, strict=False)
                  for c in env_list('PROTECTED_CIDRS', '10.0.0.0/16,10.99.0.0/24')]
PROTECTED_IPS = {'127.0.0.1', '192.168.1.1', '192.168.1.10', '10.99.0.1', '10.99.0.2'} | PORTAL_ALLOWED_IPS

PFSENSE_ENABLED = os.environ.get('PFSENSE_PUSH_ENABLED', 'true').lower() == 'true'
PFSENSE_HOST = os.environ.get('PFSENSE_HOST', '10.99.0.2')
PFSENSE_USER = os.environ.get('PFSENSE_USER', 'admin')
PFSENSE_TABLE = os.environ.get('PFSENSE_TABLE', 'SOAR_BLOCKLIST')
PFSENSE_KEY = os.environ.get('PFSENSE_KEY', '/app/ssh/id_ed25519')
PFSENSE_KNOWN_HOSTS = os.environ.get('PFSENSE_KNOWN_HOSTS', '/app/ssh/known_hosts')
PFSENSE_SYNC_INTERVAL = int(os.environ.get('PFSENSE_SYNC_INTERVAL', '5'))
if not re.fullmatch(r'[A-Za-z0-9_]+', PFSENSE_TABLE):
    raise SystemExit('PFSENSE_TABLE may only contain letters, digits and underscore')

STATE_DIR = os.environ.get('STATE_DIR', '/var/lib/soar')
STATE_FILE = os.path.join(STATE_DIR, 'quarantine_state.json')
INCIDENT_LOG_FILE = os.environ.get('INCIDENT_LOG_FILE', '/var/log/soar/soar_incidents.json')
MAX_HISTORY = 200

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
ec2_client = boto3.client('ec2', region_name=REGION)

# ---------------- Prometheus Metrics ----------------
SOAR_EVENTS_RECEIVED = Counter('soar_events_received_total', 'Total security events ingested', ['alert_type', 'severity', 'source_platform'])
SOAR_ACTIONS_EXECUTED = Counter('soar_actions_executed_total', 'Total automated response actions executed', ['action', 'status'])
SOAR_BLOCKED_IPS = Gauge('soar_blocked_ips_active', 'Current number of malicious IPs actively quarantined')
SOAR_BANNED_IP_LIST = Gauge('soar_banned_ip_list', 'Actively quarantined IP addresses', ['ip'])
SOAR_PFSENSE_SYNC_OK = Gauge('soar_pfsense_sync_ok', '1 if the last pfSense blocklist sync succeeded, else 0')

SOAR_EVENTS_RECEIVED.labels(alert_type='SSHBruteForce', severity='critical', source_platform='gns3-onprem').inc(0)
for _action in ('firewall_ip_quarantine', 'aws_nacl_quarantine', 'pfsense_quarantine', 'ip_unblock'):
    for _status in ('success', 'failed'):
        SOAR_ACTIONS_EXECUTED.labels(action=_action, status=_status).inc(0)
SOAR_BLOCKED_IPS.set(0)
SOAR_PFSENSE_SYNC_OK.set(1 if not PFSENSE_ENABLED else 0)

# ---------------- State (persisted to disk) ----------------
STATE_LOCK = threading.RLock()
QUARANTINE = {}                       # ip -> entry dict
INCIDENT_HISTORY = deque(maxlen=MAX_HISTORY)
SSH_FAILURE_TRACKER = {}
_EXPORTED_IPS = set()

PFSENSE_DIRTY = threading.Event()
PFSENSE_PENDING_KILL = set()
PFSENSE_STATUS = {'ok': None, 'time': None, 'detail': 'not synced yet'}


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def fmt_ts(ts):
    return ts.replace('T', ' ').replace('Z', ' UTC') if ts else '-'


def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, 'timeout'
    except OSError as e:
        return 127, str(e)


def save_state():
    with STATE_LOCK:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = STATE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump({'quarantined': QUARANTINE}, f, indent=2)
            os.replace(tmp, STATE_FILE)
        except Exception:
            log.exception('could not save state file')


def load_state():
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except Exception:
        log.exception('could not read state file, starting empty')
        return
    with STATE_LOCK:
        for ip, entry in data.get('quarantined', {}).items():
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            entry['ip'] = ip
            entry['pfsense_ok'] = False      # re-verified by the first pfSense sync
            QUARANTINE[ip] = entry
    log.info('restored %d quarantined IP(s) from disk', len(QUARANTINE))


def load_incident_history():
    try:
        with open(INCIDENT_LOG_FILE) as f:
            lines = deque(f, maxlen=MAX_HISTORY)
    except FileNotFoundError:
        return
    for line in lines:
        try:
            INCIDENT_HISTORY.append(json.loads(line))
        except ValueError:
            continue


def refresh_metrics():
    with STATE_LOCK:
        current = set(QUARANTINE)
    for ip in _EXPORTED_IPS - current:
        try:
            SOAR_BANNED_IP_LIST.remove(ip)
        except KeyError:
            pass
    for ip in current:
        SOAR_BANNED_IP_LIST.labels(ip=ip).set(1)
    _EXPORTED_IPS.clear()
    _EXPORTED_IPS.update(current)
    SOAR_BLOCKED_IPS.set(len(current))


# ---------------- Security: client IP restriction + auth + CSRF ----------------
@app.before_request
def restrict_client_ip():
    ip = request.remote_addr
    if ip in PORTAL_ALLOWED_IPS:
        return None
    if request.path == '/metrics':
        try:
            addr = ipaddress.ip_address(ip)
            if any(addr in net for net in METRICS_ALLOWED_NETS):
                return None
        except ValueError:
            pass
    return Response('Forbidden\n', 403)


def check_auth(username, password):
    return username == 'admin' and password == 'admin'


def authenticate():
    return Response('Access Denied: Please log in with valid credentials.\n', 401,
                    {'WWW-Authenticate': 'Basic realm="SOAR Portal"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


def csrf_valid():
    expected = session.get('csrf', '')
    given = request.form.get('csrf', '')
    return bool(expected) and hmac.compare_digest(expected, given)


def is_protected_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return ip in PROTECTED_IPS or any(addr in net for net in PROTECTED_NETS)


# ---------------- Local hybrid firewall (iptables) ----------------
def iptables_block(ip):
    rc, out = run(['iptables', '-C', 'FORWARD', '-s', ip, '-j', 'DROP'])
    if rc == 0:
        return True, 'already present'
    rc, out = run(['iptables', '-I', 'FORWARD', '-s', ip, '-j', 'DROP'])
    return rc == 0, ('ok' if rc == 0 else out)


def iptables_unblock(ip):
    for _ in range(20):
        rc, out = run(['iptables', '-C', 'FORWARD', '-s', ip, '-j', 'DROP'])
        if rc == 1:
            return True, 'ok'                 # rule is gone
        if rc != 0:
            return False, out                 # iptables itself failed
        rc, out = run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'])
        if rc != 0:
            return False, out
    return False, 'could not remove all duplicate rules'


# ---------------- AWS Network ACLs ----------------
def list_target_nacls():
    acls = []
    paginator = ec2_client.get_paginator('describe_network_acls')
    for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]):
        acls.extend(page['NetworkAcls'])
    if NACL_IDS_PINNED:
        return [a for a in acls if a['NetworkAclId'] in NACL_IDS_PINNED]
    # every NACL that actually protects at least one subnet
    return [a for a in acls if a.get('Associations')]


def is_deny_for(entry, cidr):
    return (not entry['Egress'] and entry.get('RuleAction') == 'deny'
            and entry.get('CidrBlock') == cidr and str(entry.get('Protocol')) == '-1')


def nacl_add_deny(acl, cidr):
    acl_id = acl['NetworkAclId']
    ingress = [e for e in acl['Entries'] if not e['Egress']]
    for e in ingress:
        if is_deny_for(e, cidr):
            return e['RuleNumber']            # already blocked, reuse
    allow_numbers = [e['RuleNumber'] for e in ingress
                     if e['RuleAction'] == 'allow' and e['RuleNumber'] < 32767]
    first_allow = min(allow_numbers) if allow_numbers else NACL_RULE_MAX + 1
    upper = min(NACL_RULE_MAX, first_allow - 1)
    used = {e['RuleNumber'] for e in ingress}
    for number in range(NACL_RULE_MIN, upper + 1):
        if number in used:
            continue
        try:
            ec2_client.create_network_acl_entry(
                NetworkAclId=acl_id, RuleNumber=number, Protocol='-1',
                RuleAction='deny', Egress=False, CidrBlock=cidr)
            return number
        except ClientError as e:
            if e.response['Error']['Code'] == 'NetworkAclEntryAlreadyExists':
                used.add(number)
                continue
            raise
    raise RuntimeError('no free rule number below the first allow rule (%d-%d)' % (NACL_RULE_MIN, upper))


def nacl_block(ip):
    if not VPC_ID:
        return False, 'VPC_ID not configured', {}
    cidr = ip + '/32'
    try:
        acls = list_target_nacls()
    except Exception as e:
        return False, 'describe_network_acls failed: %s' % e, {}
    if not acls:
        return False, 'no NACL found for this VPC', {}
    rules, errors = {}, []
    for acl in acls:
        try:
            rules[acl['NetworkAclId']] = nacl_add_deny(acl, cidr)
        except Exception as e:
            errors.append('%s: %s' % (acl['NetworkAclId'], e))
    if errors:
        return False, '; '.join(errors), rules
    return True, 'denied on %d NACL(s)' % len(rules), rules


def nacl_unblock(ip):
    if not VPC_ID:
        return True, 'skipped (VPC_ID not configured)'
    cidr = ip + '/32'
    try:
        acls = list_target_nacls()
    except Exception as e:
        return False, 'describe_network_acls failed: %s' % e
    errors = []
    for acl in acls:
        for e in acl['Entries']:
            if not is_deny_for(e, cidr):
                continue
            try:
                ec2_client.delete_network_acl_entry(
                    NetworkAclId=acl['NetworkAclId'], RuleNumber=e['RuleNumber'], Egress=False)
            except ClientError as ce:
                if ce.response['Error']['Code'] != 'InvalidNetworkAclEntry.NotFound':
                    errors.append('%s rule %s: %s' % (acl['NetworkAclId'], e['RuleNumber'], ce))
            except Exception as ex:
                errors.append('%s rule %s: %s' % (acl['NetworkAclId'], e['RuleNumber'], ex))
    if errors:
        return False, '; '.join(errors)
    return True, 'ok'


# ---------------- pfSense (GNS3) over the WireGuard tunnel ----------------
def pfsense_ssh(remote_cmd):
    cmd = ['ssh', '-i', PFSENSE_KEY, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + PFSENSE_KNOWN_HOSTS,
           '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
           '%s@%s' % (PFSENSE_USER, PFSENSE_HOST), remote_cmd]
    rc, out = run(cmd, timeout=25)
    return rc == 0, out[-300:]


def pfsense_sync():
    """Make the pfSense table identical to our quarantine list, then kill live states of new IPs."""
    if not PFSENSE_ENABLED:
        return
    with STATE_LOCK:
        ips = sorted(QUARANTINE)
        kill = sorted(PFSENSE_PENDING_KILL & set(ips))
    if ips:
        cmd = 'pfctl -t %s -T replace %s' % (PFSENSE_TABLE, ' '.join(ips))
    else:
        cmd = 'pfctl -t %s -T flush' % PFSENSE_TABLE
    for ip in kill:
        cmd += ' && pfctl -k %s' % ip
    ok, out = pfsense_ssh(cmd)
    if ok:
        newly = 0
        with STATE_LOCK:
            for ip in ips:
                entry = QUARANTINE.get(ip)
                if entry is not None and not entry.get('pfsense_ok'):
                    entry['pfsense_ok'] = True
                    newly += 1
            PFSENSE_PENDING_KILL.difference_update(kill)
            PFSENSE_STATUS.update(ok=True, time=now_iso(), detail='in sync (%d IP(s))' % len(ips))
        SOAR_PFSENSE_SYNC_OK.set(1)
        if newly:
            SOAR_ACTIONS_EXECUTED.labels(action='pfsense_quarantine', status='success').inc(newly)
        save_state()
        log.info('pfSense sync OK (%d IP(s))', len(ips))
    else:
        with STATE_LOCK:
            PFSENSE_STATUS.update(ok=False, time=now_iso(), detail=out or 'unknown error')
        SOAR_PFSENSE_SYNC_OK.set(0)
        if ips:
            SOAR_ACTIONS_EXECUTED.labels(action='pfsense_quarantine', status='failed').inc()
        log.warning('pfSense sync FAILED: %s', out)


def pfsense_sync_loop():
    while True:
        PFSENSE_DIRTY.wait(timeout=PFSENSE_SYNC_INTERVAL)
        PFSENSE_DIRTY.clear()
        try:
            pfsense_sync()
        except Exception:
            log.exception('pfSense sync crashed')


# ---------------- Automated containment ----------------
def quarantine_ip(ip, reason, severity, platform):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return 'skipped: invalid IP'
    if is_protected_ip(ip):
        return 'skipped: protected IP'
    with STATE_LOCK:
        if ip in QUARANTINE:
            return 'already quarantined'
        entry = {'ip': ip, 'blocked_at': now_iso(), 'reason': reason, 'severity': severity,
                 'source_platform': platform, 'fw_ok': False, 'nacl_ok': False,
                 'pfsense_ok': False, 'nacl_rules': {}}
        QUARANTINE[ip] = entry                # saved first, so a crash mid-action is not forgotten
        PFSENSE_PENDING_KILL.add(ip)
    save_state()
    refresh_metrics()

    fw_ok, fw_msg = iptables_block(ip)
    nacl_ok, nacl_msg, rules = nacl_block(ip)
    SOAR_ACTIONS_EXECUTED.labels(action='firewall_ip_quarantine', status='success' if fw_ok else 'failed').inc()
    SOAR_ACTIONS_EXECUTED.labels(action='aws_nacl_quarantine', status='success' if nacl_ok else 'failed').inc()
    if not fw_ok:
        log.warning('iptables block failed for %s: %s', ip, fw_msg)
    if not nacl_ok:
        log.warning('NACL block failed for %s: %s', ip, nacl_msg)

    with STATE_LOCK:
        entry.update(fw_ok=fw_ok, nacl_ok=nacl_ok, nacl_rules=rules)
    save_state()
    if PFSENSE_ENABLED:
        PFSENSE_DIRTY.set()
    return 'quarantined (firewall %s, AWS NACL %s, pfSense %s)' % (
        'ok' if fw_ok else 'FAILED', 'ok' if nacl_ok else 'FAILED',
        'queued' if PFSENSE_ENABLED else 'disabled')


def unblock_ip(ip):
    """Returns (success, [problems]). The IP stays listed if the local/AWS removal fails."""
    problems = []
    ok, msg = iptables_unblock(ip)
    if not ok:
        problems.append('firewall: %s' % msg)
    ok, msg = nacl_unblock(ip)
    if not ok:
        problems.append('AWS NACL: %s' % msg)
    if problems:
        SOAR_ACTIONS_EXECUTED.labels(action='ip_unblock', status='failed').inc()
        log.warning('unblock of %s incomplete: %s', ip, problems)
        return False, problems
    with STATE_LOCK:
        QUARANTINE.pop(ip, None)
        PFSENSE_PENDING_KILL.discard(ip)
    save_state()
    refresh_metrics()
    SOAR_ACTIONS_EXECUTED.labels(action='ip_unblock', status='success').inc()
    if PFSENSE_ENABLED:
        PFSENSE_DIRTY.set()
    return True, []


def action_log_and_notify(record):
    try:
        os.makedirs(os.path.dirname(INCIDENT_LOG_FILE), exist_ok=True)
        with open(INCIDENT_LOG_FILE, 'a') as f:
            f.write(json.dumps(record) + '\n')
    except Exception:
        log.exception('could not write incident log')
    INCIDENT_HISTORY.append(record)


def evaluate_and_respond(alert_type, severity, source_ip, target_host, raw_message, platform='gns3-onprem'):
    SOAR_EVENTS_RECEIVED.labels(alert_type=alert_type, severity=severity, source_platform=platform).inc()
    result = 'logged only'
    if severity in ('critical', 'high') or alert_type in ('SSHBruteForce', 'FirewallPortScan'):
        result = quarantine_ip(source_ip, alert_type, severity, platform)
    action_log_and_notify({
        'timestamp': now_iso(), 'alert_type': alert_type, 'severity': severity,
        'attacker_ip': source_ip, 'target_host': target_host, 'platform': platform,
        'result': result,
    })


def reconcile_on_start():
    """Re-apply every restored quarantine (iptables rules are lost on reboot) and re-sync pfSense."""
    with STATE_LOCK:
        entries = list(QUARANTINE.values())
    for entry in entries:
        ip = entry['ip']
        fw_ok, _ = iptables_block(ip)
        nacl_ok, _, rules = nacl_block(ip)
        with STATE_LOCK:
            entry.update(fw_ok=fw_ok, nacl_ok=nacl_ok, nacl_rules=rules)
    save_state()
    PFSENSE_DIRTY.set()
    log.info('startup reconcile finished for %d IP(s)', len(entries))


# ---------------- Event listeners ----------------
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
            log.exception('syslog listener error')
            continue


# ---------------- Web interface ----------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="10">
    <title>Innovatech SOAR Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; margin: 16px; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 32px; }
        .table-wrap { overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; margin-top: 12px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; font-size: 0.95em; }
        th { background-color: #34495e; color: white; }
        .btn { padding: 8px 16px; color: white; background-color: #e74c3c; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .btn:hover { background-color: #c0392b; }
        .notice { padding: 10px; border-radius: 4px; margin-bottom: 16px; }
        .notice.success { color: #27ae60; background: #e8f8f5; border-left: 5px solid #27ae60; }
        .notice.warning { color: #9a6700; background: #fff8e1; border-left: 5px solid #f39c12; }
        .notice.error { color: #c0392b; background: #fdecea; border-left: 5px solid #c0392b; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; margin-right: 4px; }
        .badge.ok { background: #e8f8f5; color: #1e8449; }
        .badge.fail { background: #fdecea; color: #c0392b; }
        .badge.pending { background: #fff8e1; color: #9a6700; }
        .badge.off { background: #eceff1; color: #607d8b; }
        .empty { text-align: center; color: #7f8c8d; padding: 20px; }
        .footer { margin-top: 30px; font-size: 0.9em; color: #7f8c8d; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Innovatech SOAR Management Portal</h1>
        {% for category, message in get_flashed_messages(with_categories=true) %}
        <div class="notice {{ category }}"><b>System Notice:</b> {{ message }}</div>
        {% endfor %}
        <p>Active quarantined IP addresses. These IPs are blocked on the hybrid gateway firewall, the AWS Network ACLs and the pfSense firewall in GNS3.</p>
        <p><span class="badge {{ pf_class }}">{{ pf_text }}</span></p>

        <div class="table-wrap">
        <table>
            <tr><th>Attacker IP Address</th><th>Blocked at</th><th>Reason</th><th>Enforced on</th><th>Containment Action</th></tr>
            {% for r in rows %}
            <tr>
                <td><strong>{{ r.ip }}</strong></td>
                <td>{{ r.blocked_at }}</td>
                <td>{{ r.reason }}</td>
                <td>
                    <span class="badge {{ r.fw }}">Firewall</span>
                    <span class="badge {{ r.nacl }}">AWS NACL</span>
                    <span class="badge {{ r.pf }}">pfSense</span>
                </td>
                <td>
                    <form method="POST" action="/unblock/{{ r.ip }}" style="margin:0;" onsubmit="return confirm('Unblock {{ r.ip }}?');">
                        <input type="hidden" name="csrf" value="{{ csrf }}">
                        <button type="submit" class="btn">Unblock IP</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="5" class="empty">No active security threats currently quarantined.</td></tr>
            {% endfor %}
        </table>
        </div>

        <h2>Recent incidents</h2>
        <div class="table-wrap">
        <table>
            <tr><th>Time</th><th>Alert</th><th>Severity</th><th>Attacker IP</th><th>Result</th></tr>
            {% for i in incidents %}
            <tr>
                <td>{{ i.time }}</td>
                <td>{{ i.alert }}</td>
                <td>{{ i.severity }}</td>
                <td>{{ i.ip }}</td>
                <td>{{ i.result }}</td>
            </tr>
            {% else %}
            <tr><td colspan="5" class="empty">No incidents recorded yet.</td></tr>
            {% endfor %}
        </table>
        </div>

        <div class="footer">Innovatech-CS2 | SOAR, Detects and Responds to Security Threats</div>
    </div>
    <script>
        setTimeout(function () {
            document.querySelectorAll('.notice.success').forEach(function (n) {
                n.style.transition = 'opacity .5s';
                n.style.opacity = '0';
                setTimeout(function () { n.remove(); }, 500);
            });
        }, 5000);
    </script>
</body>
</html>
"""


def pfsense_status_view():
    if not PFSENSE_ENABLED:
        return 'off', 'pfSense push is disabled'
    with STATE_LOCK:
        s = dict(PFSENSE_STATUS)
    if s['ok'] is None:
        return 'pending', 'pfSense: waiting for first sync'
    if s['ok']:
        return 'ok', 'pfSense: %s - last sync %s' % (s['detail'], fmt_ts(s['time']))
    return 'fail', 'pfSense: sync FAILED at %s - %s' % (fmt_ts(s['time']), s['detail'])


@app.route('/', methods=['GET'])
@requires_auth
def index():
    with STATE_LOCK:
        entries = [dict(e) for e in QUARANTINE.values()]
    entries.sort(key=lambda e: (e.get('blocked_at', ''), e['ip']), reverse=True)
    rows = [{
        'ip': e['ip'],
        'blocked_at': fmt_ts(e.get('blocked_at')),
        'reason': e.get('reason', '-'),
        'fw': 'ok' if e.get('fw_ok') else 'fail',
        'nacl': 'ok' if e.get('nacl_ok') else 'fail',
        'pf': 'off' if not PFSENSE_ENABLED else ('ok' if e.get('pfsense_ok') else 'pending'),
    } for e in entries]
    incidents = [{
        'time': fmt_ts(i.get('timestamp')),
        'alert': i.get('alert_type', '-'),
        'severity': i.get('severity', '-'),
        'ip': i.get('attacker_ip', '-'),
        'result': i.get('result', '-'),
    } for i in list(INCIDENT_HISTORY)[-20:][::-1]]
    pf_class, pf_text = pfsense_status_view()
    return render_template_string(HTML_TEMPLATE, rows=rows, incidents=incidents,
                                  pf_class=pf_class, pf_text=pf_text, csrf=csrf_token())


@app.route('/unblock/<ip>', methods=['POST'])
@requires_auth
def route_unblock(ip):
    if not csrf_valid():
        flash('Session expired - please try again.', 'warning')
        return redirect(url_for('index'))
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flash('Invalid IP address.', 'error')
        return redirect(url_for('index'))
    ok, problems = unblock_ip(ip)
    if not ok:
        flash('IP %s was NOT fully unblocked and is still listed. %s' % (ip, ' | '.join(problems)), 'warning')
    elif PFSENSE_ENABLED and PFSENSE_STATUS['ok'] is False:
        flash('IP %s unblocked on the firewall and AWS, but pfSense is unreachable right now. '
              'The removal will be retried automatically.' % ip, 'warning')
    else:
        flash('IP %s has been unblocked on the firewall and AWS NACLs. pfSense is updated within seconds.' % ip, 'success')
    return redirect(url_for('index'))


@app.route('/blocklist.txt', methods=['GET'])
def blocklist():
    with STATE_LOCK:
        ips = sorted(QUARANTINE)
    return '\n'.join(ips) + '\n', 200, {'Content-Type': 'text/plain'}


@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'service': 'SOAR', 'status': 'online'}), 200


def start_background_threads():
    load_state()
    load_incident_history()
    refresh_metrics()
    threading.Thread(target=udp_syslog_listener, daemon=True).start()
    if PFSENSE_ENABLED:
        threading.Thread(target=pfsense_sync_loop, daemon=True).start()
    threading.Thread(target=reconcile_on_start, daemon=True).start()


if __name__ == '__main__':
    start_background_threads()
    app.run(host='0.0.0.0', port=5000, threaded=True)
PY

cat << 'REQ' > requirements.txt
flask
prometheus-client
boto3
REQ

cat << 'DOCKER' > Dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables openssh-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000 5140/udp
CMD ["python", "-u", "app.py"]
DOCKER

docker build -t innovatech-soar .
docker run -d --name soar-engine --restart always --net="host" --cap-add=NET_ADMIN \
  -e VPC_ID="${aws_vpc.main.id}" \
  -e AWS_REGION="eu-central-1" \
  -e PROTECTED_CIDRS="${var.vpc_cidr},${var.wireguard_vpn_cidr}" \
  -e PORTAL_ALLOWED_IPS="${local.soar_portal_allowed_ip}" \
  -e METRICS_ALLOWED_CIDRS="${aws_subnet.private_mgmt.cidr_block}" \
  -e NACL_IDS="${local.soar_nacl_ids}" \
  -e PFSENSE_PUSH_ENABLED="${local.soar_pfsense_push}" \
  -e PFSENSE_HOST="${local.soar_pfsense_ssh_host}" \
  -e PFSENSE_USER="${local.soar_pfsense_ssh_user}" \
  -e PFSENSE_TABLE="${local.soar_pfsense_table}" \
  -v /var/log/soar:/var/log/soar \
  -v /var/lib/soar:/var/lib/soar \
  -v /opt/soar-engine/ssh:/app/ssh \
  innovatech-soar
  EOT
}

# ------------------------------------------------------------------------------
# Cloud-init compression (same pattern as 07-monitoring.tf).
# The script is larger than the 16 KB raw user_data limit, so it is gzipped.
# ------------------------------------------------------------------------------
data "cloudinit_config" "soar_setup" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    content      = local.soar_bootstrap
  }
}

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
  user_data_base64            = data.cloudinit_config.soar_setup.rendered
}

resource "aws_eip" "hybrid_vpn_eip" {
  domain     = "vpc"
  instance   = aws_instance.soar_server.id
  depends_on = [aws_internet_gateway.igw]

  tags = {
    Name = "Hybrid-VPN-EIP"
  }
}
