# ==============================================================================
# FILE: 05-database.tf
# RESPONSIBILITY: Isolated Private RDS MySQL Database Tier
# REQUIREMENTS: REQ-NCA-P2-03 (Private Cloud Resource Access - Zero Public IP)
# ==============================================================================

# 1. DATABASE SUBNET GROUP (Spans Isolated DB Subnets 1a & 1b)
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "main-db-subnet-group"
  subnet_ids = [aws_subnet.private_db_1a.id, aws_subnet.private_db_1b.id]

  tags = {
    Name = "Main-DB-Subnet-Group"
  }
}

# 2. AMAZON RDS MYSQL 8.0 INSTANCE
resource "aws_db_instance" "mysql_db" {
  identifier             = "main-mysql-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  publicly_accessible    = false
  skip_final_snapshot    = true

  tags = {
    Name = "Main-MySQL-Database"
  }
}