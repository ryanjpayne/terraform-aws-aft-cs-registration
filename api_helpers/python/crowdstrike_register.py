#!/usr/bin/env python3
"""
crowdstrike_register.py

AFT pre-api-helpers script. Reads CrowdStrike API credentials and feature
flags from SSM Parameter Store, registers the vended AWS account with
CrowdStrike using the CloudAWSRegistration API (idempotent - skips if already
registered), then writes the registration attributes to
terraform/crowdstrike.auto.tfvars.json for consumption by the Terraform step.

Sensitive values (falcon_client_id, falcon_client_secret) are written to the
same file as Terraform sensitive variables - they are not printed to stdout
and the file is not committed to source control.

Dependencies: boto3, crowdstrike-falconpy (see requirements.txt)
"""

import json
import logging
import os
import pathlib
import sys

import boto3

try:
    from falconpy import CloudAWSRegistration
except ImportError:
    print("ERROR: falconpy not available. Install with: pip install crowdstrike-falconpy")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLOUD_BASE_URLS = {
    "us-1":   "https://api.crowdstrike.com",
    "us-2":   "https://api.us-2.crowdstrike.com",
    "eu-1":   "https://api.eu-1.crowdstrike.com",
    "us-gov": "https://api.laggar.gcw.crowdstrike.com",
}

SSM_PREFIX = "/aft/config/crowdstrike"

# Where the output file lands relative to this script:
# api_helpers/python/ -> ../../terraform/
TERRAFORM_DIR = pathlib.Path(__file__).resolve().parents[2] / "terraform"
OUTPUT_FILE = TERRAFORM_DIR / "crowdstrike.auto.tfvars.json"


# ---------------------------------------------------------------------------
# SSM helpers
# ---------------------------------------------------------------------------

def get_ssm_parameter(client, name: str, required: bool = True) -> str | None:
    """Fetch a single SSM parameter, decrypting SecureStrings."""
    try:
        resp = client.get_parameter(Name=name, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except client.exceptions.ParameterNotFound:
        if required:
            log.error("Required SSM parameter not found: %s", name)
            raise
        return None


def _ssm_bool(client, name: str) -> bool:
    """Read an optional SSM parameter as a boolean (default False)."""
    val = get_ssm_parameter(client, name, required=False) or "false"
    return val.strip().lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# CrowdStrike registration
# ---------------------------------------------------------------------------

def build_products(
    enable_ioa: bool,
    enable_idp: bool,
    enable_sensor_management: bool,
    enable_dspm: bool,
    enable_vulnerability_scanning: bool,
) -> tuple[list[dict], bool]:
    """
    Build the products list and csp_events flag for the registration payload.

    CSPM features (under one 'cspm' product):
        iom                  - asset inventory (always on)
        ioa                  - realtime visibility / indicators of attack
        sensormgmt           - 1-click sensor management
        dspm                 - data security posture management
        vulnerability_scanning

    IDP is a separate product with features=["default"].
    csp_events must be True when ioa or idp is active.
    """
    cspm_features = ["iom"]  # asset inventory is always on
    if enable_ioa:
        cspm_features.append("ioa")
    if enable_sensor_management:
        cspm_features.append("sensormgmt")
    if enable_dspm:
        cspm_features.append("dspm")
    if enable_vulnerability_scanning:
        cspm_features.append("vulnerability_scanning")

    products = [{"features": cspm_features, "product": "cspm"}]
    if enable_idp:
        products.append({"features": ["default"], "product": "idp"})

    csp_events = enable_ioa or enable_idp
    return products, csp_events


def get_account_registration(falcon: CloudAWSRegistration, account_id: str) -> dict | None:
    """Return the registration resource dict if the account is registered, else None."""
    resp = falcon.get_accounts(ids=account_id)
    status = resp.get("status_code")

    resources = resp.get("body", {}).get("resources", [])

    if status == 200:
        return resources[0] if resources else None

    # 207 Multi-Status is returned by the CloudAWSRegistration API when the
    # account is not found (no resources in body). Treat as not registered.
    if status in (207, 404):
        return None if not resources else resources[0]

    raise RuntimeError(
        f"Unexpected status {status} checking registration for {account_id}: "
        f"{resp.get('body', {}).get('errors', [])}"
    )


def register_account(
    falcon: CloudAWSRegistration,
    account_id: str,
    account_type: str,
    products: list[dict],
    csp_events: bool,
    resource_name_prefix: str | None = None,
    resource_name_suffix: str | None = None,
) -> dict:
    """
    Register the AWS account with CrowdStrike using the CloudAWSRegistration API.
    Returns the resource_metadata dict from the response.
    """
    resource = {
        "account_id":        account_id,
        "account_type":      account_type,
        "csp_events":        csp_events,
        "deployment_method": "terraform-native",
        "products":          products,
    }
    if resource_name_prefix:
        resource["resource_name_prefix"] = resource_name_prefix
    if resource_name_suffix:
        resource["resource_name_suffix"] = resource_name_suffix

    resp = falcon.create_account(body={"resources": [resource]})
    code = resp.get("status_code")

    if code in (200, 201):
        resp_resource = resp.get("body", {}).get("resources", [{}])[0]
        metadata = resp_resource.get("resource_metadata", {})
        if not metadata.get("external_id"):
            raise RuntimeError(
                f"Registration succeeded but external_id missing from response. "
                f"Raw resource keys: {list(resp_resource.keys())}"
            )
        log.info("Account %s registered with CrowdStrike.", account_id)
        return metadata

    errors = resp.get("body", {}).get("errors", [])
    raise RuntimeError(f"Registration failed (status {code}): {errors}")


# ---------------------------------------------------------------------------
# Attribute extraction
# ---------------------------------------------------------------------------

REQUIRED_ATTRS = ("external_id", "intermediate_role_arn", "iam_role_name")


def extract_attributes(record: dict) -> dict:
    """
    Pull registration attributes from an API record.

    create_account returns resource_metadata directly.
    get_accounts returns the full resource with resource_metadata nested inside.
    """
    metadata = record.get("resource_metadata") or record

    iam_role_arn  = metadata.get("iam_role_arn", "")
    iam_role_name = iam_role_arn.split("/")[-1] if iam_role_arn else ""

    attrs = {
        "external_id":            metadata.get("external_id", ""),
        "intermediate_role_arn":  metadata.get("intermediate_role_arn", ""),
        "iam_role_name":          iam_role_name,
        "eventbus_arn":           metadata.get("aws_eventbus_arn", ""),
        "cloudtrail_bucket_name": metadata.get("aws_cloudtrail_bucket_name", ""),
    }

    missing = [k for k in REQUIRED_ATTRS if not attrs[k]]
    if missing:
        raise RuntimeError(
            f"CrowdStrike API returned empty required attributes: {missing}. "
            f"Full record: {record}"
        )

    return attrs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # -----------------------------------------------------------------------
    # 1. Resolve the vended account ID from the AFT environment
    # -----------------------------------------------------------------------
    account_id = os.environ.get("VENDED_ACCOUNT_ID") or os.environ.get("AWS_ACCOUNT_ID")
    if not account_id:
        log.error(
            "Could not determine the vended account ID. "
            "Expected VENDED_ACCOUNT_ID or AWS_ACCOUNT_ID environment variable."
        )
        sys.exit(1)

    log.info("Vended account ID: %s", account_id)

    # -----------------------------------------------------------------------
    # 2. Fetch parameters from SSM
    # -----------------------------------------------------------------------
    # The AFT pre-api-helpers phase runs in CodeBuild with the AFT management
    # account's IAM role as the ambient credential. SSM parameters are stored
    # in the same account, so the default session is correct — no profile needed.
    ssm = boto3.client("ssm")

    client_id     = get_ssm_parameter(ssm, f"{SSM_PREFIX}/client_id")
    client_secret = get_ssm_parameter(ssm, f"{SSM_PREFIX}/client_secret")
    cloud         = get_ssm_parameter(ssm, f"{SSM_PREFIX}/cloud", required=False) or "us-1"
    account_type  = get_ssm_parameter(ssm, f"{SSM_PREFIX}/account_type", required=False) or "commercial"

    enable_ioa                    = _ssm_bool(ssm, f"{SSM_PREFIX}/enable_realtime_visibility")
    enable_idp                    = _ssm_bool(ssm, f"{SSM_PREFIX}/enable_idp")
    enable_sensor_management      = _ssm_bool(ssm, f"{SSM_PREFIX}/enable_sensor_management")
    enable_dspm                   = _ssm_bool(ssm, f"{SSM_PREFIX}/enable_dspm")
    enable_vulnerability_scanning = _ssm_bool(ssm, f"{SSM_PREFIX}/enable_vulnerability_scanning")

    resource_name_prefix = get_ssm_parameter(ssm, f"{SSM_PREFIX}/resource_name_prefix", required=False) or "CrowdStrike-"
    resource_name_suffix = get_ssm_parameter(ssm, f"{SSM_PREFIX}/resource_name_suffix", required=False) or ""

    base_url = CLOUD_BASE_URLS.get(cloud)
    if not base_url:
        log.error(
            "Unknown CrowdStrike cloud '%s'. Valid values: %s",
            cloud,
            list(CLOUD_BASE_URLS.keys()),
        )
        sys.exit(1)

    log.info(
        "CrowdStrike cloud: %s | account_type: %s | "
        "ioa=%s idp=%s sensormgmt=%s dspm=%s vuln=%s",
        cloud, account_type,
        enable_ioa, enable_idp, enable_sensor_management,
        enable_dspm, enable_vulnerability_scanning,
    )

    # -----------------------------------------------------------------------
    # 3. Build products list from feature flags
    # -----------------------------------------------------------------------
    products, csp_events = build_products(
        enable_ioa, enable_idp, enable_sensor_management,
        enable_dspm, enable_vulnerability_scanning,
    )
    log.info("Products: %s | csp_events: %s", json.dumps(products), csp_events)

    # -----------------------------------------------------------------------
    # 4. Fetch or create the registration record (idempotent)
    # -----------------------------------------------------------------------
    falcon = CloudAWSRegistration(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )

    record = get_account_registration(falcon, account_id)

    if record is None:
        log.info("Account %s is not yet registered. Registering...", account_id)
        metadata = register_account(
            falcon, account_id, account_type, products, csp_events,
            resource_name_prefix=resource_name_prefix,
            resource_name_suffix=resource_name_suffix,
        )
        reg_attrs = extract_attributes(metadata)
    else:
        log.info("Account %s is already registered. Fetching existing attributes.", account_id)
        reg_attrs = extract_attributes(record)

    log.info(
        "Registration attributes retrieved: external_id=%s  iam_role_name=%s",
        reg_attrs["external_id"],
        reg_attrs["iam_role_name"],
    )

    # -----------------------------------------------------------------------
    # 5. Write terraform/crowdstrike.auto.tfvars.json
    #
    #    Terraform loads *.auto.tfvars.json automatically.
    #    All values (including credentials) are marked sensitive=true in the
    #    Terraform variable declarations so they are redacted from plan output.
    #    This file must NOT be committed to source control (.gitignore it).
    # -----------------------------------------------------------------------
    tfvars = {
        # Registration attributes (fetched from CrowdStrike API)
        "crowdstrike_external_id":           reg_attrs["external_id"],
        "crowdstrike_intermediate_role_arn":  reg_attrs["intermediate_role_arn"],
        "crowdstrike_iam_role_name":          reg_attrs["iam_role_name"],
        "crowdstrike_eventbus_arn":           reg_attrs["eventbus_arn"],
        "crowdstrike_cloudtrail_bucket_name": reg_attrs["cloudtrail_bucket_name"],

        # API credentials - needed by sensor-management, agentless-scanning,
        # and realtime-visibility (gov-commercial Lambda) submodules.
        # Declared as sensitive=true in variables.tf.
        "falcon_client_id":     client_id,
        "falcon_client_secret": client_secret,

        # Resource naming — pass-through from SSM so Terraform uses the same
        # prefix/suffix that was sent to the CrowdStrike API during registration.
        "resource_prefix": resource_name_prefix,
        "resource_suffix": resource_name_suffix,

        # Feature flags — sourced from SSM (set once in setup/) so aft.auto.tfvars
        # never needs to duplicate them. Terraform and the CrowdStrike API stay
        # in sync automatically.
        "account_type":                account_type,
        "enable_realtime_visibility":  enable_ioa,
        "enable_idp":                  enable_idp,
        "enable_sensor_management":    enable_sensor_management,
        "enable_dspm":                 enable_dspm,
        "enable_vulnerability_scanning": enable_vulnerability_scanning,
    }

    TERRAFORM_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(tfvars, indent=2))

    # Mask the sensitive values immediately after writing
    tfvars["falcon_client_id"]     = "***"
    tfvars["falcon_client_secret"] = "***"
    log.info("Wrote %s: %s", OUTPUT_FILE, json.dumps(tfvars, indent=2))


if __name__ == "__main__":
    main()
