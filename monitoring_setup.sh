#!/bin/bash
# 0. Prevent OOM Crashes on t3.micro (1GB Swap File)
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab

dnf update -y
dnf install -y wget tar unzip rsyslog

# ------------------------------------------------------------------------------
# 1. Configure Rsyslog Receiver (UDP 1514) for GNS3 Firewall & Auth Logs
# ------------------------------------------------------------------------------
mkdir -p /var/log/hybrid
cat << 'RSYSLOG' > /etc/rsyslog.d/hybrid-inputs.conf
module(load="imudp")
input(type="imudp" port="1514")

if ($fromhost-ip == '192.168.1.1' or $programname contains 'filterlog') then {
    action(type="omfile" file="/var/log/hybrid/pfsense-firewall.log")
} else {
    action(type="omfile" file="/var/log/hybrid/ubuntu-auth.log")
}
RSYSLOG
touch /var/log/hybrid/pfsense-firewall.log /var/log/hybrid/ubuntu-auth.log
chmod 644 /var/log/hybrid/*.log
systemctl enable --now rsyslog

# ------------------------------------------------------------------------------
# 2. Install Grafana Loki & Promtail (Log Storage & Indexing)
# ------------------------------------------------------------------------------
cd /tmp
wget -q https://github.com/grafana/loki/releases/download/v2.9.4/loki-linux-amd64.zip
wget -q https://github.com/grafana/loki/releases/download/v2.9.4/promtail-linux-amd64.zip
unzip -o loki-linux-amd64.zip
unzip -o promtail-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
mv promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/loki /usr/local/bin/promtail

mkdir -p /etc/loki /var/lib/loki
cat << 'LOKICONF' > /etc/loki/loki-config.yaml
auth_enabled: false
server:
  http_listen_port: 3100
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
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v12
      index:
        prefix: index_
        period: 24h
LOKICONF

cat << 'LOKISVC' > /etc/systemd/system/loki.service
[Unit]
Description=Grafana Loki Log Aggregation Service
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
LOKISVC

cat << 'PROMTAILCONF' > /etc/loki/promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://localhost:3100/loki/api/v1/push
scrape_configs:
  - job_name: gns3-pfsense-firewall
    static_configs:
      - targets: [localhost]
        labels:
          job: pfsense-firewall
          source: gns3-onprem-fw
          __path__: /var/log/hybrid/pfsense-firewall.log
  - job_name: gns3-ubuntu-auth
    static_configs:
      - targets: [localhost]
        labels:
          job: ubuntu-auth-syslog
          source: gns3-onprem-server
          __path__: /var/log/hybrid/ubuntu-auth.log
  - job_name: aws-system-logs
    static_configs:
      - targets: [localhost]
        labels:
          job: aws-messages
          source: aws-cloud
          __path__: /var/log/messages
PROMTAILCONF

cat << 'PROMTAILSVC' > /etc/systemd/system/promtail.service
[Unit]
Description=Promtail Log Shipper
After=loki.service

[Service]
Type=simple
ExecStart=/usr/local/bin/promtail -config.file=/etc/loki/promtail-config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
PROMTAILSVC

systemctl daemon-reload
systemctl enable --now loki promtail

# ------------------------------------------------------------------------------
# 3. Install Node Exporter (System Metrics)
# ------------------------------------------------------------------------------
useradd --no-create-home --shell /bin/false node_exporter
cd /tmp
wget -q https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvf node_exporter-1.7.0.linux-amd64.tar.gz
cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/
chown node_exporter:node_exporter /usr/local/bin/node_exporter

cat << 'SERVICE' > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now node_exporter

# ------------------------------------------------------------------------------
# 4. Install Prometheus
# ------------------------------------------------------------------------------
useradd --no-create-home --shell /bin/false prometheus
mkdir -p /etc/prometheus /var/lib/prometheus
chown prometheus:prometheus /etc/prometheus /var/lib/prometheus

wget -q https://github.com/prometheus/prometheus/releases/download/v2.50.1/prometheus-2.50.1.linux-amd64.tar.gz
tar xvf prometheus-2.50.1.linux-amd64.tar.gz
cp prometheus-2.50.1.linux-amd64/prometheus /usr/local/bin/
cp prometheus-2.50.1.linux-amd64/promtool /usr/local/bin/
chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

cat << 'ALERTS' > /etc/prometheus/alert_rules.yml
groups:
  - name: InfrastructureAndSecurityAlerts
    rules:
      - alert: WebServerDown
        expr: up{job="node-exporter"} == 0
        for: 10s
        labels:
          severity: critical
        annotations:
          summary: "Web server is offline"

      - alert: SOAREngineDown
        expr: up{job="soar-engine"} == 0
        for: 10s
        labels:
          severity: critical
        annotations:
          summary: "SOAR Engine is unreachable"

      - alert: SecurityAttackDetectedBySOAR
        expr: increase(soar_events_received_total[1m]) > 0
        for: 2s
        labels:
          severity: critical
        annotations:
          summary: "Active Security Incident Processed by SOAR"
          
      - alert: SOARpfSenseSyncFailure
        expr: soar_pfsense_sync_ok == 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "SOAR cannot push blocklist to pfSense via SSH"
ALERTS

cat << 'PROMCONFIG' > /etc/prometheus/prometheus.yml
global:
  scrape_interval: 2s
  evaluation_interval: 2s

rule_files:
  - /etc/prometheus/alert_rules.yml

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "monitoring-node"
    static_configs:
      - targets: ["localhost:9100"]
        labels:
          instance: "Monitoring-Server"

  - job_name: "node-exporter"
    ec2_sd_configs:
      - region: eu-central-1
        port: 9100
        filters:
          - name: tag:Name
            values: ["Web-ASG-Server"]
    relabel_configs:
      - source_labels: [__meta_ec2_instance_state]
        regex: running
        action: keep
      - source_labels: [__meta_ec2_private_ip]
        target_label: __address__
        replacement: '${1}:9100'

  - job_name: "nginx-web-servers"
    ec2_sd_configs:
      - region: eu-central-1
        port: 9113
        filters:
          - name: tag:Name
            values: ["Web-ASG-Server"]
    relabel_configs:
      - source_labels: [__meta_ec2_instance_state]
        regex: running
        action: keep
      - source_labels: [__meta_ec2_private_ip]
        target_label: __address__
        replacement: '${1}:9113'

  - job_name: "soar-engine"
    ec2_sd_configs:
      - region: eu-central-1
        port: 5000
        filters:
          - name: tag:Name
            values: ["SOAR-Server"]
    relabel_configs:
      - source_labels: [__meta_ec2_instance_state]
        regex: running
        action: keep
      - source_labels: [__meta_ec2_private_ip]
        target_label: __address__
        replacement: '${1}:5000'
  - job_name: "ticket-app"
    ec2_sd_configs:
      - region: eu-central-1
        port: 8080
        filters:
          - name: tag:Name
            values: ["Web-ASG-Server"]
    relabel_configs:
      - source_labels: [__meta_ec2_instance_state]
        regex: running
        action: keep
      - source_labels: [__meta_ec2_private_ip]
        target_label: __address__
        replacement: '${1}:8080'     
PROMCONFIG

chown -R prometheus:prometheus /etc/prometheus

cat << 'PROMSERVICE' > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/

[Install]
WantedBy=multi-user.target
PROMSERVICE

systemctl daemon-reload
systemctl enable --now prometheus

# ------------------------------------------------------------------------------
# 5. Install Grafana & Dashboards
# ------------------------------------------------------------------------------
cat << 'REPO' > /etc/yum.repos.d/grafana.repo
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
REPO

dnf install -y grafana

mkdir -p /etc/grafana/provisioning/datasources
cat << 'DATASOURCE' > /etc/grafana/provisioning/datasources/datasources.yaml
apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
  - name: Loki
    uid: loki
    type: loki
    access: proxy
    url: http://localhost:3100
DATASOURCE

mkdir -p /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
cat << 'DASHPROV' > /etc/grafana/provisioning/dashboards/default.yaml
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
DASHPROV

cat << 'JSON' > /var/lib/grafana/dashboards/flash-tickets.json
{
  "title": "Innovatech Operations, Logs & SOAR Dashboard",
  "schemaVersion": 38,
  "refresh": "2s",
  "panels": [
    {
      "title": "Total Tickets Sold",
      "type": "stat",
      "gridPos": {"h": 6, "w": 4, "x": 0, "y": 0},
      "targets": [{"expr": "sum(tickets_sold_total)", "refId": "A", "instant": true}]
    },
    {
      "title": "Active Web Servers (UP)",
      "type": "stat",
      "gridPos": {"h": 6, "w": 4, "x": 4, "y": 0},
      "targets": [{"expr": "sum(up{job=\"node-exporter\"})", "refId": "A", "instant": true}]
    },
    {
      "title": "SOAR System Status",
      "type": "stat",
      "gridPos": {"h": 6, "w": 4, "x": 8, "y": 0},
      "targets": [{"expr": "sum(up{job=\"soar-engine\"})", "refId": "A", "instant": true}]
    },
    {
      "title": "pfSense Sync Status",
      "type": "stat",
      "gridPos": {"h": 6, "w": 4, "x": 12, "y": 0},
      "targets": [{"expr": "soar_pfsense_sync_ok", "refId": "A", "instant": true}],
      "fieldConfig": {
        "defaults": {
          "mappings": [
            {
              "type": "value",
              "options": {
                "0": {"color": "red", "index": 1, "text": "FAILED"},
                "1": {"color": "green", "index": 0, "text": "SYNCED"}
              }
            }
          ]
        }
      }
    },
    {
      "title": "Actively Quarantined IPs",
      "type": "table",
      "gridPos": {"h": 6, "w": 8, "x": 16, "y": 0},
      "targets": [
        {
          "expr": "soar_banned_ip_list > 0",
          "refId": "A",
          "instant": true,
          "format": "table"
        }
      ],
      "transformations": [
        {
          "id": "organize",
          "options": {
            "excludeByName": {"Time": true, "Value": true, "__name__": true, "instance": true, "job": true},
            "renameByName": {"ip": "Attacker IP Address"}
          }
        }
      ]
    },
    {
      "title": "SOAR Security Events Processed & Actions Executed",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 6},
      "targets": [
        {"expr": "soar_events_received_total", "legendFormat": "Alerts Received ({{alert_type}})", "refId": "A"},
        {"expr": "soar_actions_executed_total", "legendFormat": "Action: {{action}} ({{status}})", "refId": "B"}
      ]
    },
    {
      "title": "Web Fleet CPU Usage (%)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 6},
      "targets": [{"expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[1m])) * 100)", "refId": "A"}]
    },
    {
      "title": "Hybrid Security Logs Stream",
      "type": "logs",
      "datasource": {"type": "loki", "uid": "loki"},
      "gridPos": {"h": 10, "w": 24, "x": 0, "y": 14},
      "targets": [{"expr": "{source=~\"gns3-onprem-fw|gns3-onprem-server|aws-cloud\"}", "refId": "A"}]
    }
  ]
}
JSON
chown -R grafana:grafana /var/lib/grafana/dashboards

systemctl daemon-reload
systemctl enable --now grafana-server