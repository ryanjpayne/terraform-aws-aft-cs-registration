#!/usr/bin/env bash
# pre-api-helpers.sh
#
# AFT pre-api-helpers hook that runs before Terraform.
# Calls the CrowdStrike API to fetch (or create) account registration
# attributes and writes them to terraform/crowdstrike.auto.tfvars.json
# so the Terraform step has no dependency on the CrowdStrike provider.
#
# Required SSM parameters (in the AFT management account):
#   /aft/config/crowdstrike/client_id        (SecureString)
#   /aft/config/crowdstrike/client_secret    (SecureString)
#   /aft/config/crowdstrike/cloud            (String, e.g. "us-1", "us-2", "eu-1", "us-gov")
#
# Optional SSM parameters:
#   /aft/config/crowdstrike/account_type              (String) - "commercial" or "gov" (default: commercial)
#   /aft/config/crowdstrike/enable_realtime_visibility (String) - "true"/"false"
#   /aft/config/crowdstrike/enable_idp                (String) - "true"/"false"
#   /aft/config/crowdstrike/enable_sensor_management  (String) - "true"/"false"
#   /aft/config/crowdstrike/enable_dspm               (String) - "true"/"false"
#   /aft/config/crowdstrike/enable_vulnerability_scanning (String) - "true"/"false"
#
# AFT environment variables consumed by the Python script:
#   VENDED_ACCOUNT_ID   - the 12-digit AWS account ID being provisioned

# NOTE: This script is SOURCED by the AFT buildspec (not executed as a subprocess).
# Use `return` instead of `exit` so errors propagate to the calling shell.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[crowdstrike] Installing Python dependencies..."
pip3 install -q -r "${SCRIPT_DIR}/python/requirements.txt" || { echo "[crowdstrike] ERROR: pip install failed."; return 1; }

echo "[crowdstrike] Running CrowdStrike registration pre-helper..."
python3 "${SCRIPT_DIR}/python/crowdstrike_register.py" || { echo "[crowdstrike] ERROR: crowdstrike_register.py failed."; return 1; }
echo "[crowdstrike] Pre-helper complete. crowdstrike.auto.tfvars.json written."
