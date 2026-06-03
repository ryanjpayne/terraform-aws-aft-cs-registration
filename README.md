# CrowdStrike Falcon — AWS Control Tower AFT Integration

This package integrates CrowdStrike Falcon with AWS Control Tower via Account Factory for Terraform (AFT). When deployed, every account vended through your Control Tower is automatically registered with CrowdStrike and configured with the Falcon features you have enabled.

**Note:** This package is an AFT account customization. It assumes AFT is already deployed and your aft-account-customizations pipeline is operational.

## Architecture

```
AFT Management Account (SSM Parameter Store)
        │
        │  ← setup/ runs once: stores credentials & feature flags
        │
AFT Pipeline (per vended account)
  ├── api_helpers/python/crowdstrike_register.py
  │     ├── Reads SSM params from AFT mgmt account
  │     ├── Registers account via CloudAWSRegistration API (idempotent)
  │     └── Writes terraform/crowdstrike.auto.tfvars.json
  │
  └── terraform/
        ├── asset_inventory   (IAM reader role — always on)
        ├── realtime_visibility   (EventBridge rules, per region)
        ├── sensor_management     (1-click sensor install Lambda)
        └── agentless_scanning_*  (DSPM scanning infra, per region)
```

**Key design decisions:**

- The Python pre-hook runs before Terraform and handles the CrowdStrike API call. Terraform never calls the CrowdStrike API directly.
- Multi-region deployments use explicit per-region module blocks (not `for_each`) because Terraform provider aliases cannot be dynamically selected. Adding a region requires uncommenting paired blocks in both `backend.tf.jinja` and `main.tf`.
- Terraform initializes **all** declared provider aliases at startup. Aliases for AWS opt-in regions (ap-east-1, eu-south-*, etc.) must be commented out if those regions are not enabled in the target account, or AssumeRole will return a 403.

---

## Prerequisites

- AWS Control Tower with AFT configured
- A CrowdStrike Falcon API key with `CSPM Registration` read + write scope
- Terraform >= 1.5

---

## Deployment

### Step 1 — Run setup/ once in the AFT management account

The `setup/` module stores your CrowdStrike credentials and feature configuration into SSM Parameter Store in the AFT management account. Run it once; subsequent pipeline runs read from SSM.

```bash
cd setup/

# Create a terraform.tfvars (do not commit — it contains credentials)
cat > terraform.tfvars <<EOF
falcon_client_id     = "your-client-id"
falcon_client_secret = "your-client-secret"
falcon_cloud         = "us-1"   # us-1 | us-2 | eu-1 | us-gov

enable_realtime_visibility    = true
enable_idp                    = false
enable_sensor_management      = false
enable_dspm                   = false
enable_vulnerability_scanning = false
EOF

terraform init
terraform apply
```

#### SSM parameters created

| Parameter | Type | Description |
|-----------|------|-------------|
| `/aft/config/crowdstrike/client_id` | SecureString | Falcon API client ID |
| `/aft/config/crowdstrike/client_secret` | SecureString | Falcon API client secret |
| `/aft/config/crowdstrike/cloud` | String | CrowdStrike cloud (us-1, us-2, eu-1, us-gov) |
| `/aft/config/crowdstrike/account_type` | String | commercial or gov |
| `/aft/config/crowdstrike/enable_realtime_visibility` | String | true/false |
| `/aft/config/crowdstrike/enable_idp` | String | true/false |
| `/aft/config/crowdstrike/enable_sensor_management` | String | true/false |
| `/aft/config/crowdstrike/enable_dspm` | String | true/false |
| `/aft/config/crowdstrike/enable_vulnerability_scanning` | String | true/false |
| `/aft/config/crowdstrike/resource_name_prefix` | String | Prefix for AWS resource names (default: `CrowdStrike-`) |
| `/aft/config/crowdstrike/resource_name_suffix` | String | Suffix for AWS resource names (default: empty) |

### Step 2 — Configure aft.auto.tfvars

Edit `terraform/aft.auto.tfvars` to set the regions you want to deploy into. **Feature flags are not set here** — they come automatically from SSM via the Python pre-hook.

```hcl
# Regions to deploy into. First region is the primary (global IAM resources land here).
regions = ["us-east-1"]

# Set true if your organization already has a CloudTrail; prevents creating a duplicate.
use_existing_cloudtrail = true
```

### Step 3 — Deploy

Trigger the AFT pipeline for a new or existing account. The pipeline:

1. Sources `api_helpers/python/pre-api-helpers.sh`
2. Runs `crowdstrike_register.py`, which reads feature flags and credentials from SSM,
   registers the account with CrowdStrike, and writes `crowdstrike.auto.tfvars.json`
3. Runs `terraform apply` using the generated tfvars

---

## Adding a region

Three coordinated changes are required:

1. **`terraform/backend.tf.jinja`** — uncomment the provider alias for the region:
   ```hcl
   provider "aws" {
     alias  = "eu_west_1"
     region = "eu-west-1"
     assume_role { role_arn = "{{ target_admin_role_arn }}" }
   }
   ```

2. **`terraform/main.tf`** — uncomment the corresponding module blocks for `realtime_visibility_eu_west_1` and `agentless_scanning_eu_west_1`.

3. **`terraform/aft.auto.tfvars`** — add the region to `var.regions`:
   ```hcl
   regions = ["us-east-1", "us-east-2", "eu-west-1"]
   ```

> **Important:** Steps 1 and 2 must be kept in sync. Terraform will fail with `missing provider` if a module block references an alias that is not declared, and it will fail with `403 STS AssumeRole` at `terraform init` if an alias is declared for an AWS opt-in region that is not enabled in the account.

---

## Feature reference

| Feature | Variable | What it deploys |
|---------|----------|-----------------|
| Asset Inventory | always on | `CrowdStrike-ReadOnly` IAM role for CSPM read access |
| Real-time Visibility | `enable_realtime_visibility` | EventBridge rules (all regions), IAM EventBridge role (primary region), optional CloudTrail |
| Identity Protection | `enable_idp` | Also enables real-time visibility |
| Sensor Management | `enable_sensor_management` | Lambda + IAM role for 1-click sensor installation |
| DSPM / Agentless Scanning | `enable_dspm` | VPC, NAT gateway, scanning IAM roles (per region) |
| Vulnerability Scanning | `enable_vulnerability_scanning` | Registered as a CSPM product feature; no additional AWS infra |

---

## Optional variables (aft.auto.tfvars)

| Variable | Default | Description |
|----------|---------|-------------|
| `account_type` | `"commercial"` | `"commercial"` or `"gov"` |
| `is_gov` | `false` | Set `true` for GovCloud Falcon |
| `permissions_boundary` | `""` | IAM policy name for permissions boundary on all roles |
| `tags` | `{}` | Map of tags applied to all taggable resources |
| `eventbridge_role_name` | `"CrowdStrikeCSPMEventBridge"` | Override the EventBridge IAM role name |
| `log_ingestion_method` | `"eventbridge"` | `"eventbridge"` or `"s3"` |
| `use_existing_cloudtrail` | `false` | Skip CloudTrail creation if one already exists |
| `use_existing_iam_reader_role` | `false` | Skip reader role creation if it already exists |
| `agentless_scanning_create_nat_gateway` | `true` | Set `false` to use an existing NAT gateway |

---

## Uninstalling

To remove all CrowdStrike resources from an account, set `uninstall = true` in `terraform/aft.auto.tfvars` and retrigger the AFT pipeline for that account:

```hcl
# terraform/aft.auto.tfvars
uninstall = true
```

When the pipeline runs, all module `count` values evaluate to 0 and Terraform destroys every CrowdStrike resource in the account. The Python pre-hook still runs (it is idempotent) and the state file is updated normally.

> After the pipeline completes successfully, you can remove the account customization from the AFT repo entirely, or leave it in place with `uninstall = false` if you plan to re-enable later.

---

## Troubleshooting

### `Error: 403 STS AssumeRole` during `terraform init`

Terraform is trying to initialize a provider alias for an AWS opt-in region that is not enabled in the target account. The fix: comment out the provider alias in `backend.tf.jinja` **and** the corresponding module blocks in `main.tf`. Only declare aliases for regions that are both in `var.regions` and enabled in the account.

### `Error: missing provider provider["..."].ALIAS`

A module block references a provider alias that is not declared in `backend.tf.jinja`. Either uncomment the provider alias or comment out the module block. These must stay in sync.

### `409 EntityAlreadyExists` on IAM role creation

This can happen during a state migration (e.g., first run after upgrading from a `for_each`-based version). Terraform may attempt to create the new resource before destroying the old one. The apply will resolve itself — wait for completion or re-run. The second apply will be clean.

### Registration attributes missing / empty `external_id`

The Python script calls the CrowdStrike API before Terraform. Check the CodeBuild logs for the `crowdstrike_register.py` step. Common causes:
- Wrong `falcon_cloud` in SSM (us-1 vs us-2 vs eu-1)
- API credentials lack `CSPM Registration` write scope
- Account already registered under a different CID

### `crowdstrike.auto.tfvars.json: No such file or directory`

The Python pre-hook did not run or failed. Terraform requires this file. Check that `api_helpers/python/pre-api-helpers.sh` is sourced in the AFT buildspec and that the Python step exited 0.
