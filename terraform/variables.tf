# ---------------------------------------------------------------------------
# Registration attributes - populated by api_helpers/python/crowdstrike_register.py
# and written to crowdstrike.auto.tfvars.json before Terraform runs.
# ---------------------------------------------------------------------------

variable "crowdstrike_external_id" {
  type        = string
  sensitive   = true
  description = "External ID for CrowdStrike cross-account role assumption (from API pre-hook)"
}

variable "crowdstrike_intermediate_role_arn" {
  type        = string
  description = "ARN of CrowdStrike's intermediate IAM role (from API pre-hook)"

  validation {
    condition     = can(regex("^arn:(aws|aws-us-gov):iam::[0-9]{12}:role/.+$", var.crowdstrike_intermediate_role_arn))
    error_message = "crowdstrike_intermediate_role_arn must be a valid AWS IAM role ARN."
  }
}

variable "crowdstrike_iam_role_name" {
  type        = string
  description = "Name of the reader IAM role CrowdStrike expects to assume (from API pre-hook)"
}

variable "crowdstrike_eventbus_arn" {
  type        = string
  default     = ""
  description = "EventBus ARN(s) for real-time visibility (from API pre-hook). Comma-separated for gov multi-region."
}

variable "crowdstrike_cloudtrail_bucket_name" {
  type        = string
  default     = ""
  description = "CrowdStrike-managed CloudTrail S3 bucket name (from API pre-hook). Empty when use_existing_cloudtrail=true."
}

# ---------------------------------------------------------------------------
# API credentials - written to crowdstrike.auto.tfvars.json by pre-hook.
# Required by sensor-management, agentless-scanning, and realtime-visibility
# (gov-commercial) submodules to store credentials in Secrets Manager / Lambda env.
# ---------------------------------------------------------------------------

variable "falcon_client_id" {
  type        = string
  sensitive   = true
  description = "CrowdStrike Falcon API Client ID"
}

variable "falcon_client_secret" {
  type        = string
  sensitive   = true
  description = "CrowdStrike Falcon API Client Secret"
}

# ---------------------------------------------------------------------------
# AWS deployment configuration
# ---------------------------------------------------------------------------

variable "regions" {
  type        = list(string)
  description = "AWS regions to deploy into. First element is the primary region for global resources."

  validation {
    condition     = length(var.regions) > 0
    error_message = "At least one region must be specified."
  }

  validation {
    condition = alltrue([
      for r in var.regions :
      can(regex("^(us|eu|ap|sa|ca|af|me|il)-(north|south|east|west|central|northeast|southeast|southwest|northwest)-[1-4]$", r)) ||
      can(regex("^us-gov-(east|west)-1$", r))
    ])
    error_message = "Each element must be a valid AWS region."
  }
}

variable "account_type" {
  type        = string
  description = "Must be 'commercial' or 'gov'. Written by the Python pre-hook from SSM."

  validation {
    condition     = contains(["commercial", "gov"], var.account_type)
    error_message = "account_type must be 'commercial' or 'gov'."
  }
}

variable "is_gov" {
  type        = bool
  default     = false
  description = "Set to true when deploying into GovCloud Falcon."
}

variable "permissions_boundary" {
  type        = string
  default     = ""
  description = "IAM policy name to use as a permissions boundary for all created roles."
}

variable "resource_prefix" {
  type        = string
  default     = "CrowdStrike-"
  description = "Prefix applied to all resource names."
}

variable "resource_suffix" {
  type        = string
  default     = ""
  description = "Suffix applied to all resource names."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all taggable resources."
}

# ---------------------------------------------------------------------------
# Feature flags
# Set once in setup/ — written to crowdstrike.auto.tfvars.json by the
# Python pre-hook so Terraform and the CrowdStrike API stay in sync.
# Do NOT set these in aft.auto.tfvars.
# ---------------------------------------------------------------------------

variable "enable_sensor_management" {
  type        = bool
  description = "Deploy 1-Click Sensor Management resources."
}

variable "enable_realtime_visibility" {
  type        = bool
  description = "Deploy real-time visibility (EventBridge / CloudTrail) resources."
}

variable "enable_idp" {
  type        = bool
  description = "Deploy Identity Protection resources (also enables real-time visibility)."
}

variable "use_existing_cloudtrail" {
  type        = bool
  default     = false
  description = "Set to true if a CloudTrail already exists; prevents creating a new one."
}

variable "use_existing_iam_reader_role" {
  type        = bool
  default     = false
  description = "Set to true to skip creating the asset-inventory reader role."
}

variable "create_rtvd_rules" {
  type        = bool
  default     = true
  description = "Set to false to suppress EventBridge rule creation in a region."
}

variable "eventbridge_role_name" {
  type        = string
  default     = "CrowdStrikeCSPMEventBridge"
  description = "Name of the IAM role used by EventBridge to forward events."
}

variable "log_ingestion_method" {
  type        = string
  default     = "eventbridge"
  description = "CloudTrail log ingestion method: 'eventbridge' (default) or 's3'."

  validation {
    condition     = contains(["eventbridge", "s3"], var.log_ingestion_method)
    error_message = "log_ingestion_method must be 'eventbridge' or 's3'."
  }
}

variable "log_ingestion_s3_bucket_name" {
  type    = string
  default = ""
}

variable "log_ingestion_sns_topic_arn" {
  type    = string
  default = ""
}

variable "log_ingestion_s3_bucket_prefix" {
  type    = string
  default = ""
}

variable "log_ingestion_kms_key_arn" {
  type    = string
  default = ""
}

variable "enable_dspm" {
  type        = bool
  description = "Deploy Agentless Scanning / DSPM resources."
}

variable "enable_vulnerability_scanning" {
  type        = bool
  description = "Deploy Vulnerability Scanning resources."
}

variable "agentless_scanning_regions" {
  type        = list(string)
  default     = null
  description = "Regions for agentless scanning infrastructure. Defaults to var.regions when null."

  validation {
    condition     = var.agentless_scanning_regions == null || try(length(var.agentless_scanning_regions) > 0, false)
    error_message = "If specified, agentless_scanning_regions must contain at least one region."
  }
}

variable "agentless_scanning_create_nat_gateway" {
  type    = bool
  default = true
}

variable "agentless_scanning_use_custom_vpc" {
  type    = bool
  default = false
}

variable "agentless_scanning_custom_vpc_resources_map" {
  type = map(object({
    vpc            = string
    scanner_subnet = string
    scanner_sg     = string
    db_subnet_a    = string
    db_subnet_b    = string
    db_sg          = string
  }))
  default = {}
}

variable "agentless_scanning_host_account_id" {
  type    = string
  default = ""

  validation {
    condition     = var.agentless_scanning_host_account_id == "" || can(regex("^\\d{12}$", var.agentless_scanning_host_account_id))
    error_message = "Must be empty or a 12-digit AWS account ID."
  }
}

variable "agentless_scanning_host_role_name" {
  type    = string
  default = "CrowdStrikeAgentlessScanningIntegrationRole"
}

variable "agentless_scanning_host_scanner_role_name" {
  type    = string
  default = "CrowdStrikeAgentlessScanningScannerRole"
}

variable "agentless_scanning_role_name" {
  type    = string
  default = "CrowdStrikeAgentlessScanningIntegrationRole"
}

variable "agentless_scanning_scanner_role_name" {
  type    = string
  default = "CrowdStrikeAgentlessScanningScannerRole"
}

variable "agentless_scanning_integration_role_unique_id" {
  type        = string
  default     = ""
  description = "Pre-existing integration role unique ID for non-primary agentless regions."
}

variable "agentless_scanning_scanner_role_unique_id" {
  type        = string
  default     = ""
  description = "Pre-existing scanner role unique ID for non-primary agentless regions."
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

variable "uninstall" {
  type        = bool
  default     = false
  description = "Set to true to destroy all CrowdStrike resources on the next pipeline run. Causes all module counts to evaluate to 0."
}
