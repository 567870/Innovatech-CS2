# ==============================================================================
# FILE: 09-cicd-and-patching.tf
# RESPONSIBILITY: Self-Hosted CI/CD Runner, Multi-Node OS Patching & Outputs
# REQUIREMENTS: REQ-NCA-P1-05 (Automated Multi-Node OS Updates),
#               REQ-NCA-P2-11 (Local CI/CD Runner), REQ-NCA-P2-12 (DevOps)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. SELF-HOSTED GITHUB ACTIONS RUNNER EC2 INSTANCE (REQ-NCA-P2-11)
# ------------------------------------------------------------------------------
resource "aws_instance" "github_runner" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.private_mgmt.id
  iam_instance_profile   = aws_iam_instance_profile.runner_profile.name
  vpc_security_group_ids = [aws_security_group.runner_sg.id]

  tags = {
    Name       = "GitHub-Self-Hosted-Runner"
    PatchGroup = "Innovatech-Fleet"
  }

  depends_on = [aws_nat_gateway.nat, aws_route_table_association.private_mgmt_assoc]

  lifecycle {
    ignore_changes = [ami]
  }
}

# ------------------------------------------------------------------------------
# 2. CENTRALIZED AUTOMATED MULTI-NODE OS UPDATES (REQ-NCA-P1-05)
#    Uses AWS Systems Manager (SSM) State Manager + Ansible capability to
#    automatically update all tagged nodes simultaneously without manual SSH.
# ------------------------------------------------------------------------------
resource "aws_ssm_association" "automated_fleet_os_updates" {
  name             = "AWS-RunShellScript"
  association_name = "Innovatech-Automated-MultiNode-OS-Patching"

  # Automatically runs every Sunday at 03:00 UTC or on-demand via CI/CD
  schedule_expression = "cron(0 3 ? * SUN *)"

  targets {
    key    = "tag:PatchGroup"
    values = ["Innovatech-Fleet"]
  }

  parameters = {
    commands = <<-EOT
      #!/bin/bash
      echo "[REQ-NCA-P1-05] Starting centralized automated OS security upgrade..."
      if command -v dnf >/dev/null 2>&1; then
        dnf upgrade --security -y
      elif command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y && apt-get dist-upgrade -y
      fi
      echo "[REQ-NCA-P1-05] Node $(hostname) patched successfully at $(date -u)" >> /var/log/innovatech-patch-audit.log
    EOT
  }
}

# ------------------------------------------------------------------------------
# 3. INFRASTRUCTURE OUTPUTS (FOR OPERATIONS & GNS3 INTEGRATION)
# ------------------------------------------------------------------------------
output "alb_public_dns_url" {
  description = "Public URL for the Innovatech Flash Ticket Web Portal"
  value       = "http://${aws_lb.main_alb.dns_name}"
}

output "monitoring_server_instance_id" {
  description = "Instance ID of Monitoring-Server (Use with AWS SSM Port Forwarding)"
  value       = aws_instance.monitoring_server.id
}

output "monitoring_server_private_ip" {
  description = "Private IP of Monitoring-Server (Prometheus :9090, Grafana :3000, Loki :3100)"
  value       = aws_instance.monitoring_server.private_ip
}

output "soar_server_instance_id" {
  description = "Instance ID of the Isolated SOAR-Server"
  value       = aws_instance.soar_server.id
}

output "soar_server_private_ip" {
  description = "Private IP of SOAR-Server (Webhook/Metrics :5000, Syslog UDP :5140)"
  value       = aws_instance.soar_server.private_ip
}

output "hybrid_vpn_public_ip" {
  description = "Elastic IP of the WireGuard endpoint (use as Endpoint = <ip>:51820 in GNS3 pfSense)"
  value       = aws_eip.hybrid_vpn_eip.public_ip
}

output "internal_dns_endpoints" {
  description = "Private Route 53 DNS records created for REQ-NCA-P2-04"
  value = {
    database   = aws_route53_record.db_dns.fqdn
    monitoring = aws_route53_record.monitoring_dns.fqdn
    soar       = aws_route53_record.soar_dns.fqdn
    runner     = aws_route53_record.runner_dns.fqdn
    hq_server  = aws_route53_record.onprem_server_dns.fqdn
  }
}