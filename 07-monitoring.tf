# ==============================================================================
# FILE: 07-monitoring.tf
# RESPONSIBILITY: Observability EC2 Instance & Cloud-Init Bootstrap
# NOTE: IAM Roles and Security Groups are centralized in 03-security.tf
# ==============================================================================

# 1. CLOUD-INIT COMPRESSION (Fixes the AWS 16KB user_data Limit)
data "cloudinit_config" "monitoring_setup" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    # This reads your bash script from the external file
    content      = file("${path.module}/monitoring_setup.sh")
  }
}

# 2. MONITORING EC2 INSTANCE
resource "aws_instance" "monitoring_server" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_mgmt.id 
  
  # References the IAM profile uniquely defined in 03-security.tf
  iam_instance_profile   = aws_iam_instance_profile.monitoring_profile.name
  vpc_security_group_ids = [aws_security_group.monitoring_sg.id]
  
  tags = {
    Name = "Monitoring-Server"
  }

  # Uses the compressed script block from above
  user_data = data.cloudinit_config.monitoring_setup.rendered
}