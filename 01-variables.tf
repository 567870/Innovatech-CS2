# ==============================================================================
# FILE: 01-variables.tf
# RESPONSIBILITY: Centralized Parameters for Cloud, Hybrid GNS3, DNS & RDS
# REQUIREMENTS: REQ-NCA-P2-10 (Declarative IaC), REQ-NCA-P1-05 (Consistency)
# ==============================================================================

variable "aws_region" {
  description = "Primary AWS Region for Innovatech Solutions"
  type        = string
  default     = "eu-central-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the Main AWS Hub VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "onprem_gns3_cidr" {
  description = "CIDR block for Innovatech Breda HQ simulated in GNS3"
  type        = string
  default     = "192.168.1.0/24"
}

variable "wireguard_vpn_cidr" {
  description = "CIDR block for the Hybrid WireGuard VPN tunnel between GNS3 and AWS"
  type        = string
  default     = "10.99.0.0/24"
}

variable "internal_dns_domain" {
  description = "Private Route 53 Hosted Zone domain for internal name resolution (REQ-NCA-P2-04)"
  type        = string
  default     = "innovatech.internal"
}

variable "ec2_instance_type" {
  description = "Standard cost-effective EC2 instance size for Innovatech workloads"
  type        = string
  default     = "t3.micro"
}

variable "db_name" {
  description = "Database name for the Flash Ticket transactional RDS instance"
  type        = string
  default     = "labdb"
}

variable "db_username" {
  description = "Master username for RDS MySQL"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "Master password for RDS MySQL"
  type        = string
  sensitive   = true
  default     = "SuperSecretLabPassword123"
}

variable "wireguard_peer_public_key" {
  description = "WireGuard public key of the GNS3 pfSense peer (10.99.0.2). Leave empty on first apply, then add it and re-run the peer step"
  type        = string
  default     = ""
}
