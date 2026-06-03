data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  primary_region    = var.regions[0]
  aws_region        = data.aws_region.current.id
  is_primary_region = local.aws_region == local.primary_region
  aws_account_id    = data.aws_caller_identity.current.account_id

  is_gov_commercial          = var.is_gov && var.account_type == "commercial"
  rtvd_enabled               = var.enable_realtime_visibility || var.enable_idp
  agentless_scanning_enabled = var.enable_dspm || var.enable_vulnerability_scanning

  # Resolve agentless scanning regions: use override if set, otherwise all regions.
  agentless_scanning_regions = var.agentless_scanning_regions != null ? var.agentless_scanning_regions : var.regions

  # Suppress eventbus_arn for gov-commercial (Lambda handles forwarding instead).
  eventbus_arn = local.is_gov_commercial ? "" : var.crowdstrike_eventbus_arn

  # Suppress cloudtrail_bucket_name when caller brings their own trail.
  cloudtrail_bucket_name = var.use_existing_cloudtrail ? "" : var.crowdstrike_cloudtrail_bucket_name
}

# ---------------------------------------------------------------------------
# Asset Inventory
# Creates the CrowdStrike reader IAM role with SecurityAudit + supplemental
# permissions. Always deployed (it is the foundation of CSPM).
# ---------------------------------------------------------------------------
module "asset_inventory" {
  count  = var.uninstall ? 0 : (local.is_primary_region ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/asset-inventory?ref=main"

  external_id                  = var.crowdstrike_external_id
  intermediate_role_arn        = var.crowdstrike_intermediate_role_arn
  role_name                    = var.crowdstrike_iam_role_name
  permissions_boundary         = var.permissions_boundary
  use_existing_iam_reader_role = var.use_existing_iam_reader_role
  tags                         = var.tags
}

# ---------------------------------------------------------------------------
# Sensor Management (1-Click)
# Deploys the orchestrator Lambda and required IAM roles in the primary region.
# ---------------------------------------------------------------------------
module "sensor_management" {
  count  = var.uninstall ? 0 : (local.is_primary_region && var.enable_sensor_management ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/sensor-management?ref=main"

  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn
  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  permissions_boundary  = var.permissions_boundary
  account_type          = var.account_type
  is_gov                = var.is_gov
  resource_prefix       = var.resource_prefix
  resource_suffix       = var.resource_suffix
  tags                  = var.tags

  providers = { aws = aws }
}

# ---------------------------------------------------------------------------
# Real-time Visibility / Identity Protection
# One module block per region. Each is gated on local.rtvd_enabled and
# whether the region appears in var.regions.
# ---------------------------------------------------------------------------

module "realtime_visibility_us_east_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "us-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "us-east-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.us_east_1 }
}

/*
# To add a region:
#   1. Uncomment the provider alias in backend.tf.jinja
#   2. Uncomment the module block(s) below
#   3. Add the region to var.regions in aft.auto.tfvars
module "realtime_visibility_us_east_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "us-east-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "us-east-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.us_east_2 }
}

module "realtime_visibility_us_west_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "us-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "us-west-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.us_west_1 }
}

module "realtime_visibility_us_west_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "us-west-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "us-west-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.us_west_2 }
}

module "realtime_visibility_eu_west_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-west-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_west_1 }
}

module "realtime_visibility_eu_west_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-west-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-west-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_west_2 }
}

module "realtime_visibility_eu_west_3" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-west-3") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-west-3"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_west_3 }
}

module "realtime_visibility_eu_central_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-central-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_central_1 }
}

module "realtime_visibility_eu_central_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-central-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-central-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_central_2 }
}

module "realtime_visibility_eu_north_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-north-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-north-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_north_1 }
}

module "realtime_visibility_eu_south_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-south-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_south_1 }
}

module "realtime_visibility_eu_south_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "eu-south-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "eu-south-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.eu_south_2 }
}

module "realtime_visibility_ap_southeast_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-southeast-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-southeast-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_southeast_1 }
}

module "realtime_visibility_ap_southeast_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-southeast-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-southeast-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_southeast_2 }
}

module "realtime_visibility_ap_northeast_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-northeast-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-northeast-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_northeast_1 }
}

module "realtime_visibility_ap_northeast_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-northeast-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-northeast-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_northeast_2 }
}

module "realtime_visibility_ap_northeast_3" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-northeast-3") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-northeast-3"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_northeast_3 }
}

module "realtime_visibility_ap_south_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-south-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_south_1 }
}

module "realtime_visibility_ap_south_2" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-south-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-south-2"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_south_2 }
}

module "realtime_visibility_ap_east_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ap-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ap-east-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ap_east_1 }
}

module "realtime_visibility_ca_central_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ca-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ca-central-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ca_central_1 }
}

module "realtime_visibility_ca_west_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "ca-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "ca-west-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.ca_west_1 }
}

module "realtime_visibility_sa_east_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "sa-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "sa-east-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.sa_east_1 }
}

module "realtime_visibility_me_south_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "me-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "me-south-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.me_south_1 }
}

module "realtime_visibility_me_central_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "me-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "me-central-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.me_central_1 }
}

module "realtime_visibility_af_south_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "af-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "af-south-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.af_south_1 }
}

module "realtime_visibility_il_central_1" {
  count  = var.uninstall ? 0 : (local.rtvd_enabled && contains(var.regions, "il-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/realtime-visibility?ref=main"

  primary_region        = local.primary_region
  is_primary_region     = local.primary_region == "il-central-1"
  is_gov                = var.is_gov
  is_gov_commercial     = local.is_gov_commercial
  is_organization_trail = false

  use_existing_cloudtrail = var.use_existing_cloudtrail
  cloudtrail_bucket_name  = local.cloudtrail_bucket_name
  eventbridge_role_name   = var.eventbridge_role_name
  eventbus_arn            = local.eventbus_arn
  create_rules            = var.create_rtvd_rules

  falcon_client_id      = var.falcon_client_id
  falcon_client_secret  = var.falcon_client_secret
  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn

  log_ingestion_method           = var.log_ingestion_method
  log_ingestion_s3_bucket_name   = var.log_ingestion_s3_bucket_name
  log_ingestion_sns_topic_arn    = var.log_ingestion_sns_topic_arn
  log_ingestion_s3_bucket_prefix = var.log_ingestion_s3_bucket_prefix
  log_ingestion_kms_key_arn      = var.log_ingestion_kms_key_arn

  permissions_boundary = var.permissions_boundary
  resource_prefix      = var.resource_prefix
  resource_suffix      = var.resource_suffix
  tags                 = var.tags

  providers = { aws = aws.il_central_1 }
}
*/

# ---------------------------------------------------------------------------
# Agentless Scanning Roles
# Creates the integration + scanner IAM roles in the primary region.
# Skipped in GovCloud (agentless scanning is not available there).
# ---------------------------------------------------------------------------
module "agentless_scanning_roles" {
  count  = var.uninstall ? 0 : (local.is_primary_region && local.agentless_scanning_enabled && !var.is_gov ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-roles?ref=main"

  falcon_client_id     = var.falcon_client_id
  falcon_client_secret = var.falcon_client_secret

  external_id           = var.crowdstrike_external_id
  intermediate_role_arn = var.crowdstrike_intermediate_role_arn
  account_id            = local.aws_account_id

  agentless_scanning_role_name         = var.agentless_scanning_role_name
  agentless_scanning_scanner_role_name = var.agentless_scanning_scanner_role_name
  agentless_scanning_regions           = local.agentless_scanning_regions
  agentless_scanning_use_custom_vpc           = var.agentless_scanning_use_custom_vpc
  agentless_scanning_custom_vpc_resources_map = var.agentless_scanning_custom_vpc_resources_map
  agentless_scanning_host_account_id          = var.agentless_scanning_host_account_id
  agentless_scanning_host_scanner_role_name   = var.agentless_scanning_host_scanner_role_name

  enable_dspm                   = var.enable_dspm
  enable_vulnerability_scanning = var.enable_vulnerability_scanning
  dspm_s3_access                = true
  dspm_dynamodb_access          = true
  dspm_rds_access               = true
  dspm_redshift_access          = true
  dspm_ebs_access               = true

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Agentless Scanning Environments
# One module block per region. Each is gated on agentless_scanning_enabled,
# !is_gov, and whether the region appears in local.agentless_scanning_regions.
# The primary-region instance pulls role unique IDs from the roles module;
# non-primary regions require them via input variables.
# ---------------------------------------------------------------------------

module "agentless_scanning_us_east_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "us-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "us-east-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "us-east-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "us-east-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "us-east-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.us_east_1 }
}

/*
module "agentless_scanning_us_east_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "us-east-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "us-east-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "us-east-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "us-east-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "us-east-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.us_east_2 }
}

module "agentless_scanning_us_west_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "us-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "us-west-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "us-west-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "us-west-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "us-west-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.us_west_1 }
}

module "agentless_scanning_us_west_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "us-west-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "us-west-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "us-west-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "us-west-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "us-west-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.us_west_2 }
}

module "agentless_scanning_eu_west_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-west-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-west-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-west-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-west-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_west_1 }
}

module "agentless_scanning_eu_west_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-west-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-west-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-west-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-west-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-west-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_west_2 }
}

module "agentless_scanning_eu_west_3" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-west-3") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-west-3"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-west-3" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-west-3" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-west-3", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_west_3 }
}

module "agentless_scanning_eu_central_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-central-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-central-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-central-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-central-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_central_1 }
}

module "agentless_scanning_eu_central_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-central-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-central-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-central-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-central-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-central-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_central_2 }
}

module "agentless_scanning_eu_north_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-north-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-north-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-north-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-north-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-north-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_north_1 }
}

module "agentless_scanning_eu_south_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-south-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-south-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-south-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-south-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_south_1 }
}

module "agentless_scanning_eu_south_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "eu-south-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "eu-south-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "eu-south-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "eu-south-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "eu-south-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.eu_south_2 }
}

module "agentless_scanning_ap_southeast_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-southeast-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-southeast-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-southeast-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-southeast-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-southeast-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_southeast_1 }
}

module "agentless_scanning_ap_southeast_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-southeast-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-southeast-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-southeast-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-southeast-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-southeast-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_southeast_2 }
}

module "agentless_scanning_ap_northeast_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-northeast-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-northeast-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-northeast-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-northeast-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-northeast-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_northeast_1 }
}

module "agentless_scanning_ap_northeast_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-northeast-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-northeast-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-northeast-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-northeast-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-northeast-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_northeast_2 }
}

module "agentless_scanning_ap_northeast_3" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-northeast-3") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-northeast-3"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-northeast-3" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-northeast-3" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-northeast-3", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_northeast_3 }
}

module "agentless_scanning_ap_south_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-south-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-south-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-south-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-south-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_south_1 }
}

module "agentless_scanning_ap_south_2" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-south-2") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-south-2"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-south-2" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-south-2" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-south-2", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_south_2 }
}

module "agentless_scanning_ap_east_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ap-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ap-east-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ap-east-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ap-east-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ap-east-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ap_east_1 }
}

module "agentless_scanning_ca_central_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ca-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ca-central-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ca-central-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ca-central-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ca-central-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ca_central_1 }
}

module "agentless_scanning_ca_west_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "ca-west-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "ca-west-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "ca-west-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "ca-west-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "ca-west-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.ca_west_1 }
}

module "agentless_scanning_sa_east_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "sa-east-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "sa-east-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "sa-east-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "sa-east-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "sa-east-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.sa_east_1 }
}

module "agentless_scanning_me_south_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "me-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "me-south-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "me-south-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "me-south-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "me-south-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.me_south_1 }
}

module "agentless_scanning_me_central_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "me-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "me-central-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "me-central-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "me-central-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "me-central-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.me_central_1 }
}

module "agentless_scanning_af_south_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "af-south-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "af-south-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "af-south-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "af-south-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "af-south-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.af_south_1 }
}

module "agentless_scanning_il_central_1" {
  count  = var.uninstall ? 0 : (local.agentless_scanning_enabled && !var.is_gov && contains(local.agentless_scanning_regions, "il-central-1") ? 1 : 0)
  source = "github.com/crowdstrike/terraform-aws-cloud-registration//modules/agentless-scanning-environments?ref=main"

  deployment_name = "il-central-1"
  account_id      = local.aws_account_id

  integration_role_unique_id = local.primary_region == "il-central-1" ? module.agentless_scanning_roles[0].integration_role_unique_id : var.agentless_scanning_integration_role_unique_id
  scanner_role_unique_id     = local.primary_region == "il-central-1" ? module.agentless_scanning_roles[0].scanner_role_unique_id : var.agentless_scanning_scanner_role_unique_id

  agentless_scanning_create_nat_gateway = var.agentless_scanning_create_nat_gateway
  agentless_scanning_host_account_id    = var.agentless_scanning_host_account_id
  agentless_scanning_host_role_name     = var.agentless_scanning_host_role_name

  use_custom_vpc    = var.agentless_scanning_use_custom_vpc
  region_vpc_config = var.agentless_scanning_use_custom_vpc ? lookup(var.agentless_scanning_custom_vpc_resources_map, "il-central-1", null) : null

  vpc_cidr_block = var.vpc_cidr_block
  tags           = var.tags

  depends_on = [module.agentless_scanning_roles]

  providers = { aws = aws.il_central_1 }
}
*/
