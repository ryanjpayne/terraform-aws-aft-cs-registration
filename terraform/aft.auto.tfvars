# ---------------------------------------------------------------------------
# CrowdStrike AFT Integration — Terraform Variables
#
# Feature flags (enable_realtime_visibility, enable_idp, etc.) are NOT set
# here. They are read from SSM by the Python pre-hook and written to
# crowdstrike.auto.tfvars.json before Terraform runs. Configure them once
# in setup/ — Terraform and the CrowdStrike API will stay in sync automatically.
# ---------------------------------------------------------------------------

# Regions to deploy CrowdStrike resources into.
# First region is the primary — global IAM resources (reader role, EventBridge
# IAM role) are created here. Subsequent regions get EventBridge rules only.
#
# IMPORTANT: When changing this list:
#   1. Add/remove the corresponding provider alias in backend.tf.jinja
#   2. Uncomment/comment the corresponding module blocks in main.tf
#   3. Terraform initializes ALL declared provider aliases at startup, so
#      aliases for opt-in regions not enabled in your account will cause 403s.
regions = ["us-east-1"]

# Set true if a CloudTrail already exists at the organization level.
# Most Control Tower deployments have an org-level CloudTrail — set this true.
use_existing_cloudtrail = true

# Set to true to destroy all CrowdStrike resources on the next pipeline run.
# After the pipeline completes, set back to false (or remove the customization).
uninstall = false
