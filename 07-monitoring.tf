# ==========================================
# 1. IAM ROLE FOR MONITORING (SSM + EC2 Discovery)
# ==========================================
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

# Allow SSM connection for port forwarding and management
resource "aws_iam_role_policy_attachment" "monitoring_ssm" {
  role       = aws_iam_role.monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Allow Prometheus to query AWS for new Auto Scaling EC2 instances
resource "aws_iam_role_policy_attachment" "monitoring_ec2_readonly" {
  role       = aws_iam_role.monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "monitoring_profile" {
  name = "monitoring-instance-profile"
  role = aws_iam_role.monitoring_role.name
}

# ==========================================
# 2. CLOUD-INIT COMPRESSION (Fixes the 16KB Limit)
# ==========================================
data "cloudinit_config" "monitoring_setup" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    content      = file("${path.module}/monitoring_setup.sh")
  }
}

# ==========================================
# 3. MONITORING EC2 INSTANCE
# ==========================================
resource "aws_instance" "monitoring_server" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_mgmt.id 
  iam_instance_profile   = aws_iam_instance_profile.monitoring_profile.name
  vpc_security_group_ids = [aws_security_group.monitoring_sg.id]
  
  tags = {
    Name = "Monitoring-Server"
  }

  # Uses the compressed script block from above
  user_data = data.cloudinit_config.monitoring_setup.rendered
}