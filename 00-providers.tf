# ==============================================================================
# FILE: 00-providers.tf
# RESPONSIBILITY: Remote S3 State Backend, AWS Provider Lock & Global Data Sources
# REQUIREMENTS: REQ-NCA-P2-10 (IaC), REQ-NCA-P2-12 (DevOps Integration)
# ==============================================================================

terraform {
  backend "s3" {
    bucket = "tf-state-hamdan-2026-lab"
    key    = "network/terraform.tfstate"
    region = "eu-central-1"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Global lookup for the latest Amazon Linux 2023 AMI across all compute tiers
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}