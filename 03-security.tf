# ==============================================================================
# FILE: 03-security.tf
# RESPONSIBILITY: Stateful Firewall Security Groups & Least-Privilege IAM Roles
# REQUIREMENTS: REQ-NCA-P2-02 (Segmentation), REQ-NCA-P2-03 (Private Access),
#               REQ-NCA-P1-05 (SSM Agentless Management without SSH Port 22)
# ==============================================================================

# ------------------------------------------------------------------------------
# PART A: STATEFUL SECURITY GROUPS
# ------------------------------------------------------------------------------

# 1. Application Load Balancer Security Group
resource "aws_security_group" "alb_sg" {
  name        = "main-alb-sg"
  description = "Allow inbound HTTP from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ALB-SG" }
}

# 2. Web Tier EC2 Security Group
resource "aws_security_group" "web_sg" {
  name        = "main-web-sg"
  description = "Allow HTTP from ALB and Metrics scraping from Monitoring EC2"
  vpc_id      = aws_vpc.main.id

  # Accept HTTP port 80 strictly from ALB
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Accept NGINX Exporter scraping strictly from Monitoring EC2
  ingress {
    from_port       = 9113
    to_port         = 9113
    protocol        = "tcp"
    security_groups = [aws_security_group.monitoring_sg.id]
  }

  # Allow Prometheus to scrape Node Exporter (9100) and Python Flash Ticket App (8080)
  ingress {
    description = "Allow Prometheus to scrape Node Exporter"
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Allow ALB and Prometheus to reach Python Flash Ticket App"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Allow ICMP Ping from internal networks"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "Web-EC2-SG" }
}

# 3. Monitoring EC2 Security Group (Prometheus, Grafana, Loki, Alertmanager)
resource "aws_security_group" "monitoring_sg" {
  name        = "main-monitoring-sg"
  description = "Allow internal and hybrid access to Observability Stack"
  vpc_id      = aws_vpc.main.id

  # Grafana UI (3000) and Prometheus UI (9090)
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  # Grafana Loki Log Ingestion API (3100) & Syslog Receiver (1514 TCP/UDP) for REQ-NCA-P2-07
  ingress {
    description = "Allow Loki HTTP log push from VPC and GNS3 Hybrid VPN"
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  ingress {
    description = "Allow Rsyslog UDP stream from GNS3 pfSense and Ubuntu Server"
    from_port   = 1514
    to_port     = 1514
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "Monitoring-EC2-SG" }
}

# 4. Isolated SOAR Platform & Hybrid VPN Gateway Security Group (REQ-NCA-P2-08)
resource "aws_security_group" "soar_sg" {
  name        = "main-soar-sg"
  description = "Security Group for Isolated SOAR Engine and Hybrid WireGuard Tunnel"
  vpc_id      = aws_vpc.main.id

  # WireGuard Hybrid VPN UDP Port 51820 (Bridges GNS3 Breda HQ into AWS)
  ingress {
    description = "WireGuard Site-to-Site VPN from GNS3 HQ"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "Allow ICMP from GNS3 HQ"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["192.168.1.0/24"]
  }

  # SOAR Event Listener Webhook API & Prometheus /metrics Endpoint (Port 5000)
  ingress {
    description = "Allow Webhook Alerts and Prometheus Metrics Scraping"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  # Direct Syslog Alert Listener on SOAR (UDP 5140) from GNS3 pfSense & Monitored-Server
  ingress {
    description = "Allow direct security syslog alerts from GNS3 and VPC"
    from_port   = 5140
    to_port     = 5140
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr, var.onprem_gns3_cidr, var.wireguard_vpn_cidr]
  }

  ingress {
    description = "Allow return transit traffic from AWS VPC back to Hybrid Gateway"
    from_port   = 0
    to_port     = 0
    protocol    = "-1" 
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "SOAR-Platform-SG" }
}

# 6. GitHub Self-Hosted Runner Security Group
resource "aws_security_group" "runner_sg" {
  name        = "main-runner-sg"
  description = "Security group for GitHub self-hosted runner (Zero Inbound Ports)"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "GitHub-Runner-SG" }
}

# ------------------------------------------------------------------------------
# PART B: IAM ROLES & INSTANCE PROFILES
# ------------------------------------------------------------------------------

# 1. Web EC2 IAM Role (SSM Management)
resource "aws_iam_role" "web_role" {
  name = "web-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "web_profile" {
  name = "web-instance-profile"
  role = aws_iam_role.web_role.name
}

# 2. Monitoring EC2 IAM Role (SSM + EC2 Auto-Discovery)
resource "aws_iam_role" "monitoring_role" {
  name = "monitoring-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "monitoring_ssm" {
  role       = aws_iam_role.monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "monitoring_ec2_readonly" {
  role       = aws_iam_role.monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "monitoring_profile" {
  name = "monitoring-instance-profile"
  role = aws_iam_role.monitoring_role.name
}

# 3. SOAR Platform IAM Role (SSM + Automated Cloud Security Containment APIs)
resource "aws_iam_role" "soar_role" {
  name = "soar-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "soar_ssm" {
  role       = aws_iam_role.soar_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Allows SOAR Boto3 Engine to quarantine malicious IPs in AWS Network ACLs / Security Groups
resource "aws_iam_role_policy" "soar_security_response_policy" {
  name = "soar-automated-containment-policy"
  role = aws_iam_role.soar_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ssm:SendCommand"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "soar_profile" {
  name = "soar-instance-profile"
  role = aws_iam_role.soar_role.name
}

# 4. GitHub Runner IAM Role (SSM + Terraform Deployment Privileges)
resource "aws_iam_role" "runner_role" {
  name = "github-runner-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "runner_ssm" {
  role       = aws_iam_role.runner_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "runner_admin" {
  role       = aws_iam_role.runner_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "runner_profile" {
  name = "github-runner-profile"
  role = aws_iam_role.runner_role.name
}