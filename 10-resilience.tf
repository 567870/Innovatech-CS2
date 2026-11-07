# ==============================================================================
# FILE: 10-resilience.tf
# RESPONSIBILITY: CloudWatch Auto-Recovery Alarms
# REQUIREMENTS: REQ-NCA-P3-01 (Design-for-Failure / System Resilience)
# ==============================================================================

# 1. Monitoring Server Auto-Recovery Alarm
resource "aws_cloudwatch_metric_alarm" "monitoring_recovery_alarm" {
  alarm_name          = "Monitoring-Server-Auto-Recovery"
  namespace           = "AWS/EC2"
  evaluation_periods  = 2
  period              = 60
  alarm_description   = "Auto-recovers the Monitoring server if underlying hardware fails."
  alarm_actions       = ["arn:aws:automate:${var.aws_region}:ec2:recover"]
  statistic           = "Minimum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  metric_name         = "StatusCheckFailed_System"
  
  dimensions = {
    InstanceId = aws_instance.monitoring_server.id
  }
}

# 2. SOAR Server Auto-Recovery Alarm
resource "aws_cloudwatch_metric_alarm" "soar_recovery_alarm" {
  alarm_name          = "SOAR-Server-Auto-Recovery"
  namespace           = "AWS/EC2"
  evaluation_periods  = 2
  period              = 60
  alarm_description   = "Auto-recovers the SOAR server if underlying hardware fails."
  alarm_actions       = ["arn:aws:automate:${var.aws_region}:ec2:recover"]
  statistic           = "Minimum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  metric_name         = "StatusCheckFailed_System"
  
  dimensions = {
    InstanceId = aws_instance.soar_server.id
  }
}
