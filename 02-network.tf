# ==============================================================================
# FILE: 02-network.tf
# RESPONSIBILITY: 4-Tier Segmented Multi-AZ VPC, Gateways & Route Tables
# REQUIREMENTS: REQ-NCA-P2-01 (Resilience), REQ-NCA-P2-02 (Segmentation),
#               REQ-NCA-P2-03 (Private Cloud Access)
# ==============================================================================

# 1. CORE VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "Main-VPC"
    Environment = "Lab"
    Company     = "Innovatech-Solutions"
  }
}

# 2. INTERNET & NAT GATEWAYS
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "Main-IGW"
  }
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags = {
    Name = "NAT-Gateway-EIP"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_1a.id
  tags = {
    Name = "Main-NAT-Gateway"
  }
  depends_on = [aws_internet_gateway.igw]
}

# 3. SUBNETS (4 Logical Tiers across Multi-AZ eu-central-1a and eu-central-1b)

# Tier 1: Public DMZ Tier (ALB, NAT Gateway & Hybrid VPN Border)
resource "aws_subnet" "public_1a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "Public-Subnet-1a"
    Tier = "Public-DMZ"
  }
}

resource "aws_subnet" "public_1b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "Public-Subnet-1b"
    Tier = "Public-DMZ"
  }
}

# Tier 2: Private Web Application Tier (Multi-AZ EC2 Auto Scaling Group)
resource "aws_subnet" "private_web_1a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = false
  tags = {
    Name = "Private-Web-Subnet-1a"
    Tier = "Private-Web"
  }
}

resource "aws_subnet" "private_web_1b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.11.0/24"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = false
  tags = {
    Name = "Private-Web-Subnet-1b"
    Tier = "Private-Web"
  }
}

# Tier 3: Private Management & Security Tier (Monitoring, CI/CD Runner, Isolated SOAR)
resource "aws_subnet" "private_mgmt" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.20.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = false
  tags = {
    Name = "Private-Mgmt-Subnet-1a"
    Tier = "Private-Management"
  }
}

# Tier 4: Air-Gapped Isolated Database Tier (RDS MySQL - REQ-NCA-P2-03)
resource "aws_subnet" "private_db_1a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.30.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = false
  tags = {
    Name = "Private-DB-Subnet-1a"
    Tier = "Isolated-Database"
  }
}

resource "aws_subnet" "private_db_1b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.31.0/24"
  availability_zone       = "eu-central-1b"
  map_public_ip_on_launch = false
  tags = {
    Name = "Private-DB-Subnet-1b"
    Tier = "Isolated-Database"
  }
}

# 4. ROUTE TABLES & SUBNET ASSOCIATIONS

# Public Route Table (Outbound to Internet Gateway)
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "Public-Route-Table"
  }
}

resource "aws_route_table_association" "public_1a_assoc" {
  subnet_id      = aws_subnet.public_1a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_1b_assoc" {
  subnet_id      = aws_subnet.public_1b.id
  route_table_id = aws_route_table.public_rt.id
}

# Private Route Table (Outbound via NAT Gateway + Hybrid Route to GNS3 On-Prem)
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "Private-Route-Table"
  }
}

# Route traffic destined for Breda HQ GNS3 LAN (192.168.1.0/24) and VPN (10.99.0.0/24) to SOAR/VPN Gateway
resource "aws_route" "hybrid_gns3_lan_route" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = var.onprem_gns3_cidr
  network_interface_id   = aws_instance.soar_server.primary_network_interface_id
}

resource "aws_route" "hybrid_wireguard_route" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = var.wireguard_vpn_cidr
  network_interface_id   = aws_instance.soar_server.primary_network_interface_id
}

resource "aws_route_table_association" "private_web_1a_assoc" {
  subnet_id      = aws_subnet.private_web_1a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_web_1b_assoc" {
  subnet_id      = aws_subnet.private_web_1b.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_mgmt_assoc" {
  subnet_id      = aws_subnet.private_mgmt.id
  route_table_id = aws_route_table.private_rt.id
}

# Isolated DB Route Table (Strictly Local VPC Routing Only - Zero Internet/NAT Route)
resource "aws_route_table" "isolated_db_rt" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "Isolated-DB-Route-Table"
  }
}

resource "aws_route_table_association" "db_1a_assoc" {
  subnet_id      = aws_subnet.private_db_1a.id
  route_table_id = aws_route_table.isolated_db_rt.id
}

resource "aws_route_table_association" "db_1b_assoc" {
  subnet_id      = aws_subnet.private_db_1b.id
  route_table_id = aws_route_table.isolated_db_rt.id
}

# Hybrid VPN routes for public subnets containing the WireGuard EC2
resource "aws_route" "public_hybrid_gns3_lan_route" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = var.onprem_gns3_cidr
  network_interface_id   = aws_instance.soar_server.primary_network_interface_id
}

resource "aws_route" "public_hybrid_wireguard_route" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = var.wireguard_vpn_cidr
  network_interface_id   = aws_instance.soar_server.primary_network_interface_id
}