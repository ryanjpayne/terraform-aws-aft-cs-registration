# ---------------------------------------------------------------------------
# CrowdStrike AFT Setup
#
# Creates SSM parameters in the AFT management account that the
# account-customizations pipeline reads when registering each vended account.
#
# Run this once against your AFT management account:
#   terraform init && terraform apply
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "client_id" {
  name        = "${var.ssm_prefix}/client_id"
  description = "CrowdStrike Falcon API client ID"
  type        = "SecureString"
  value       = var.falcon_client_id
  key_id      = var.kms_key_id
  overwrite   = true
}

resource "aws_ssm_parameter" "client_secret" {
  name        = "${var.ssm_prefix}/client_secret"
  description = "CrowdStrike Falcon API client secret"
  type        = "SecureString"
  value       = var.falcon_client_secret
  key_id      = var.kms_key_id
  overwrite   = true
}

resource "aws_ssm_parameter" "cloud" {
  name        = "${var.ssm_prefix}/cloud"
  description = "CrowdStrike cloud region (us-1, us-2, eu-1, us-gov)"
  type        = "String"
  value       = var.falcon_cloud
  overwrite   = true
}

resource "aws_ssm_parameter" "account_type" {
  name        = "${var.ssm_prefix}/account_type"
  description = "AWS account type (commercial or gov)"
  type        = "String"
  value       = var.account_type
  overwrite   = true
}

resource "aws_ssm_parameter" "enable_realtime_visibility" {
  name        = "${var.ssm_prefix}/enable_realtime_visibility"
  description = "Enable Falcon Real-time Visibility and Detection"
  type        = "String"
  value       = tostring(var.enable_realtime_visibility)
  overwrite   = true
}

resource "aws_ssm_parameter" "enable_idp" {
  name        = "${var.ssm_prefix}/enable_idp"
  description = "Enable Falcon Identity Protection"
  type        = "String"
  value       = tostring(var.enable_idp)
  overwrite   = true
}

resource "aws_ssm_parameter" "enable_sensor_management" {
  name        = "${var.ssm_prefix}/enable_sensor_management"
  description = "Enable Falcon 1-Click Sensor Management"
  type        = "String"
  value       = tostring(var.enable_sensor_management)
  overwrite   = true
}

resource "aws_ssm_parameter" "enable_dspm" {
  name        = "${var.ssm_prefix}/enable_dspm"
  description = "Enable Falcon Data Security Posture Management"
  type        = "String"
  value       = tostring(var.enable_dspm)
  overwrite   = true
}

resource "aws_ssm_parameter" "enable_vulnerability_scanning" {
  name        = "${var.ssm_prefix}/enable_vulnerability_scanning"
  description = "Enable Falcon Vulnerability Scanning"
  type        = "String"
  value       = tostring(var.enable_vulnerability_scanning)
  overwrite   = true
}

resource "aws_ssm_parameter" "resource_name_prefix" {
  name        = "${var.ssm_prefix}/resource_name_prefix"
  description = "Prefix applied to all CrowdStrike resource names"
  type        = "String"
  value       = var.resource_name_prefix
  overwrite   = true
}

resource "aws_ssm_parameter" "resource_name_suffix" {
  count       = var.resource_name_suffix != "" ? 1 : 0
  name        = "${var.ssm_prefix}/resource_name_suffix"
  description = "Suffix applied to all CrowdStrike resource names"
  type        = "String"
  value       = var.resource_name_suffix
  overwrite   = true
}
