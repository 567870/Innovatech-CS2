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
${file("${path.module}/soar_app.py")}
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
  -v /opt/soar-engine/app.py:/app/app.py:ro \
  innovatech-soar
  EOT
}

# ------------------------------------------------------------------------------
# Cloud-init compression
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

  # IMPORTANT: Temporarily set to true for this exact commit to rebuild the instance with the new volume mount.
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

# ------------------------------------------------------------------------------
# CI/CD Automated SOAR Sync (Dynamically applies soar_app.py updates via SSM)
# ------------------------------------------------------------------------------
resource "aws_ssm_document" "soar_auto_updater" {
  name          = "Auto-Update-SOAR-App"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Pushes the latest Python code and restarts the container"
    parameters = {
      PythonCodeBase64 = {
        type        = "String"
        description = "Base64 encoded Python code to safely bypass formatting limits"
      }
    }
    mainSteps = [
      {
        action = "aws:runShellScript"
        name   = "UpdateApp"
        inputs = {
          runCommand = [
            "echo '{{ PythonCodeBase64 }}' | base64 -d > /opt/soar-engine/app.py",
            "docker restart soar-engine"
          ]
        }
      }
    ]
  })
}

resource "aws_ssm_association" "soar_live_sync" {
  name = aws_ssm_document.soar_auto_updater.name
  targets {
    key    = "InstanceIds"
    values = [aws_instance.soar_server.id]
  }
  parameters = {
    # Dynamically injects the Python file securely
    PythonCodeBase64 = base64encode(file("${path.module}/soar_app.py"))
  }
}