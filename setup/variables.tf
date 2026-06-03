variable "falcon_client_id" {
  description = "CrowdStrike Falcon API client ID."
  type        = string
  sensitive   = true
}

variable "falcon_client_secret" {
  description = "CrowdStrike Falcon API client secret."
  type        = string
  sensitive   = true
}

variable "falcon_cloud" {
  description = "CrowdStrike cloud region. Valid values: us-1, us-2, eu-1, us-gov."
  type        = string
  default     = "us-1"

  validation {
    condition     = contains(["us-1", "us-2", "eu-1", "us-gov"], var.falcon_cloud)
    error_message = "falcon_cloud must be one of: us-1, us-2, eu-1, us-gov."
  }
}

variable "account_type" {
  description = "AWS account type. Use 'gov' for GovCloud accounts."
  type        = string
  default     = "commercial"

  validation {
    condition     = contains(["commercial", "gov"], var.account_type)
    error_message = "account_type must be 'commercial' or 'gov'."
  }
}

variable "enable_realtime_visibility" {
  description = "Enable Falcon Real-time Visibility and Detection (IOA / EventBridge)."
  type        = bool
  default     = false
}

variable "enable_idp" {
  description = "Enable Falcon Identity Protection."
  type        = bool
  default     = false
}

variable "enable_sensor_management" {
  description = "Enable Falcon 1-Click Sensor Management."
  type        = bool
  default     = false
}

variable "enable_dspm" {
  description = "Enable Falcon Data Security Posture Management (DSPM)."
  type        = bool
  default     = false
}

variable "enable_vulnerability_scanning" {
  description = "Enable Falcon Vulnerability Scanning."
  type        = bool
  default     = false
}

variable "resource_name_prefix" {
  description = "Prefix applied to all CrowdStrike resource names."
  type        = string
  default     = "CrowdStrike-"
}

variable "resource_name_suffix" {
  description = "Suffix applied to all CrowdStrike resource names."
  type        = string
  default     = ""
}

variable "ssm_prefix" {
  description = "SSM Parameter Store path prefix for CrowdStrike parameters."
  type        = string
  default     = "/aft/config/crowdstrike"
}

variable "kms_key_id" {
  description = "KMS key ID or ARN for encrypting SecureString parameters. Defaults to the AWS managed SSM key."
  type        = string
  default     = null
}
