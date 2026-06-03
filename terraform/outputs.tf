output "asset_inventory_role_arn" {
  description = "ARN of the CrowdStrike asset inventory reader IAM role."
  value       = local.is_primary_region && !var.uninstall ? module.asset_inventory[0].reader_role_arn : null
}

output "sensor_management_role_arn" {
  description = "ARN of the CrowdStrike sensor management IAM role. Null when not in primary region or feature is disabled."
  value       = null
}

output "agentless_scanning_integration_role_unique_id" {
  description = "Unique ID of the agentless scanning integration role. Pass this to non-primary region deployments via agentless_scanning_integration_role_unique_id."
  value       = local.is_primary_region && local.agentless_scanning_enabled && !var.is_gov && !var.uninstall ? module.agentless_scanning_roles[0].integration_role_unique_id : null
}

output "agentless_scanning_scanner_role_unique_id" {
  description = "Unique ID of the agentless scanning scanner role. Pass this to non-primary region deployments via agentless_scanning_scanner_role_unique_id."
  value       = local.is_primary_region && local.agentless_scanning_enabled && !var.is_gov && !var.uninstall ? module.agentless_scanning_roles[0].scanner_role_unique_id : null
}

output "primary_region" {
  description = "The primary AWS region where global resources were deployed."
  value       = local.primary_region
}

output "deployed_regions" {
  description = "All regions in which real-time visibility rules were deployed."
  value       = local.rtvd_enabled && !var.uninstall ? toset(var.regions) : toset([])
}
