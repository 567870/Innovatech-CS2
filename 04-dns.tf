# ==============================================================================
# FILE: 04-dns.tf
# RESPONSIBILITY: Internal Private DNS Resolution across the Hybrid Cloud
# REQUIREMENTS: REQ-NCA-P2-04 (Internal DNS Resolution to Private IPs)
# ==============================================================================

# 1. PRIVATE HOSTED ZONE (innovatech.internal)
resource "aws_route53_zone" "internal" {
  name    = var.internal_dns_domain
  comment = "Private DNS namespace for Innovatech Solutions internal services (REQ-NCA-P2-04)"

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = {
    Name = "Innovatech-Internal-DNS-Zone"
  }
}

# 2. DATABASE PRIVATE DNS RECORD (db.innovatech.internal)
resource "aws_route53_record" "db_dns" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "db.${var.internal_dns_domain}"
  type    = "CNAME"
  ttl     = 60
  records = [aws_db_instance.mysql_db.address]
}

# 3. MONITORING SERVER PRIVATE DNS RECORD (monitoring.innovatech.internal)
resource "aws_route53_record" "monitoring_dns" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "monitoring.${var.internal_dns_domain}"
  type    = "A"
  ttl     = 60
  records = [aws_instance.monitoring_server.private_ip]
}

# 4. SOAR SERVER PRIVATE DNS RECORD (soar.innovatech.internal)
resource "aws_route53_record" "soar_dns" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "soar.${var.internal_dns_domain}"
  type    = "A"
  ttl     = 60
  records = [aws_instance.soar_server.private_ip]
}

# 5. CI/CD RUNNER PRIVATE DNS RECORD (runner.innovatech.internal)
resource "aws_route53_record" "runner_dns" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "runner.${var.internal_dns_domain}"
  type    = "A"
  ttl     = 60
  records = [aws_instance.github_runner.private_ip]
}

# 6. ON-PREMISES GNS3 MONITORED SERVER DNS RECORD (hq-server.innovatech.internal)
resource "aws_route53_record" "onprem_server_dns" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "hq-server.${var.internal_dns_domain}"
  type    = "A"
  ttl     = 300
  records = ["192.168.1.10"]
}