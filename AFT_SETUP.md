# Setting Up AWS Control Tower Account Factory for Terraform (AFT)

This guide walks through deploying AFT from scratch in preparation for the CrowdStrike Falcon AFT customization. If AFT is already operational in your environment, skip directly to the CrowdStrike package [README](README.md).

> **Important:** This guide is a general overview intended to help you get started. It is not a substitute for official AWS documentation. AWS requirements, service limits, and AFT behavior may change over time. For authoritative guidance on deploying and maintaining AFT — including security, networking, and compliance considerations specific to your environment — refer to the [AWS AFT documentation](https://docs.aws.amazon.com/controltower/latest/userguide/aft-getting-started.html) and consult your AWS account team as needed.

---

## What AFT Is

Account Factory for Terraform (AFT) is an AWS-provided framework that automates account vending and customization in Control Tower via Terraform and CodePipeline. When you vend a new account through AFT, it automatically runs any customizations you have configured — including the CrowdStrike registration in this package.

AFT does **not** replace Control Tower. It runs on top of it.

---

## Architecture Overview

```
AWS Organization
├── Management Account (Control Tower root)
│   ├── Log Archive Account
│   └── Audit Account
│
└── AFT Management Account  ← AFT infrastructure lives here
      ├── CodeCommit repos (account-request, account-customizations, ...)
      ├── CodePipeline / CodeBuild (runs on every vended account)
      ├── Step Functions (account vending workflow)
      ├── Lambda functions
      ├── DynamoDB (request tracking)
      └── S3 (Terraform state backend)
```

AFT is deployed into a **dedicated AFT management account** — not the Control Tower management account. This account is created first via the Control Tower Account Factory, then AFT infrastructure is deployed into it via Terraform.

---

## Prerequisites

Before starting:

- [ ] AWS Control Tower is set up and operational
- [ ] You have admin access to the Control Tower management account
- [ ] Terraform >= 1.5 installed locally
- [ ] AWS CLI installed and configured
- [ ] Git installed
- [ ] An IAM user or role in the Control Tower management account with `AdministratorAccess` (used to run the AFT Terraform module)

---

## Step 1 — Create the AFT Management Account

AFT requires a dedicated AWS account. Create it through the Control Tower Account Factory console — **do not create it manually** or it won't be enrolled in Control Tower.

1. Sign in to the Control Tower management account
2. Go to **Control Tower → Account Factory → Enroll account**
3. Fill in:
   - **Account email**: a unique email address (e.g. `aws-aft-management@yourcompany.com`)
   - **Account name**: `aft-management` (or similar)
   - **Organizational Unit**: place it in an OU with appropriate SCPs (a dedicated `Infrastructure` OU is common)
4. Wait for provisioning to complete (~15 minutes)
5. Note the **12-digit account ID** — you'll need it in the next step

---

## Step 2 — Note Your Control Tower Account IDs

You need four account IDs. Find them in the Control Tower console under **Organization**:

| Account | Where to find it |
|---------|-----------------|
| **CT Management** | The account you're logged into |
| **Log Archive** | Control Tower → Organization |
| **Audit** | Control Tower → Organization |
| **AFT Management** | The account you just created |

---

## Step 3 — Deploy AFT Infrastructure

Create a working directory and write the following `main.tf`. Run this from a terminal authenticated to the **Control Tower management account** with `AdministratorAccess`.

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"   # your Control Tower home region
}

module "aft" {
  source = "github.com/aws-ia/terraform-aws-control_tower_account_factory?ref=1.20.1"

  # Fill in your account IDs from Step 2
  ct_management_account_id  = "CONTROL_TOWER_MANAGEMENT_ACCOUNT_ID"
  log_archive_account_id    = "LOG_ARCHIVE_ACCOUNT_ID"
  audit_account_id          = "AUDIT_ACCOUNT_ID"
  aft_management_account_id = "AFT_MANAGEMENT_ACCOUNT_ID"
  ct_home_region            = "us-east-1"

  # VCS — use CodeCommit (repos are created automatically)
  vcs_provider                                  = "codecommit"
  account_request_repo_name                     = "aft-account-request"
  account_customizations_repo_name              = "aft-account-customizations"
  account_provisioning_customizations_repo_name = "aft-account-provisioning-customizations"
  global_customizations_repo_name               = "aft-global-customizations"

  # Terraform version used by AFT CodeBuild jobs
  terraform_version      = "1.5.7"
  terraform_distribution = "oss"

  # Set to a secondary region if you want a replicated Terraform state backend.
  # Leave empty for single-region deployments.
  tf_backend_secondary_region = ""

  # Set to true in production to deploy CodeBuild inside a VPC.
  # Requires a VPC with NAT gateway in the AFT management account.
  aft_enable_vpc = false
}
```

> **`tf_backend_secondary_region`**: When set, AFT creates a DynamoDB global table replica and an S3 replication rule for the Terraform state backend. This requires the secondary region to have DynamoDB global tables available. Leave empty unless you need cross-region state replication.

> **`aft_enable_vpc`**: When `true`, CodeBuild runs inside a VPC, which is the AWS recommendation for production. This requires a VPC with a NAT gateway in the AFT management account. For a simple deployment, `false` works fine.

Run:

```bash
terraform init
terraform apply
```

This takes 15–20 minutes. When complete, AFT has created:
- 4 CodeCommit repositories in the AFT management account
- CodePipelines for account requests and customizations
- Lambda functions, Step Functions, DynamoDB tables, and S3 buckets

---

## Step 4 — Clone the AFT Repos

AFT creates four CodeCommit repos in the AFT management account. Clone them to your local machine. You'll need credentials for the AFT management account.

```bash
# Configure the AWS CLI credential helper for CodeCommit
git config --global credential.helper '!aws codecommit credential-helper $@'
git config --global credential.UseHttpPath true

# Clone all four repos (replace REGION and ACCOUNT_ID)
git clone https://git-codecommit.REGION.amazonaws.com/v1/repos/aft-account-request
git clone https://git-codecommit.REGION.amazonaws.com/v1/repos/aft-account-customizations
git clone https://git-codecommit.REGION.amazonaws.com/v1/repos/aft-global-customizations
git clone https://git-codecommit.REGION.amazonaws.com/v1/repos/aft-account-provisioning-customizations
```

> **Tip:** If you use AWS SSO or named profiles, prefix git commands with `AWS_PROFILE=your-aft-profile`.

The repo URLs are also available in the AFT management account under **CodeCommit → Repositories**.

---

## Step 5 — Add the CrowdStrike Customization

Copy this package into the `aft-account-customizations` repo:

```
aft-account-customizations/
└── crowdstrike/
    ├── api_helpers/
    │   ├── pre-api-helpers.sh
    │   └── python/
    │       ├── crowdstrike_register.py
    │       └── requirements.txt
    ├── setup/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── versions.tf
    └── terraform/
        ├── aft.auto.tfvars
        ├── backend.tf.jinja
        ├── main.tf
        ├── outputs.tf
        ├── variables.tf
        └── versions.tf
```

Then follow the CrowdStrike package [README](README.md) from **Step 1 (Run setup/)** onwards.

---

## Step 6 — Vend Your First Account

To vend an account through AFT, push an account request to the `aft-account-request` repo. The request is a Terraform file describing the account:

```hcl
# aft-account-request/terraform/account-requests.tf

module "my_account" {
  source = "./modules/aft-account-request"

  control_tower_parameters = {
    AccountEmail              = "my-account@yourcompany.com"
    AccountName               = "my-account"
    ManagedOrganizationalUnit = "Sandbox"
    SSOUserEmail              = "admin@yourcompany.com"
    SSOUserFirstName          = "Admin"
    SSOUserLastName           = "User"
  }

  account_tags = {
    Environment = "sandbox"
  }

  change_management_parameters = {
    change_requested_by = "your-name"
    change_reason       = "Initial account creation"
  }

  account_customizations_name = "crowdstrike"
}
```

The value of `account_customizations_name` must match the directory name you used in `aft-account-customizations/` (e.g. `crowdstrike`).

Commit and push — AFT will detect the change, create the account via Control Tower, and run the CrowdStrike customization automatically.

---

## Troubleshooting AFT Setup

### `AWSControlTowerExecution` role errors during `terraform apply`

The AFT module assumes `AWSControlTowerExecution` in the CT management, log archive, and audit accounts. Your IAM credentials must have permission to assume this role in all three accounts. Run `terraform apply` from the Control Tower management account.

### CodeCommit 403 when cloning

The CodeCommit credential helper resolves credentials from the active AWS profile. Ensure your profile targets the AFT management account:

```bash
AWS_PROFILE=aft-management git clone https://git-codecommit...
```

If using SSO, run `aws sso login --profile aft-management` first.

### Pipeline does not trigger after pushing

AFT pipelines are triggered by CloudWatch Events rules watching the CodeCommit repos. If a push doesn't trigger a run, check:
1. The CloudWatch Events rule `aft-account-customizations-trigger` exists in the AFT management account
2. The rule target points to the correct CodePipeline
3. The branch name matches (AFT watches `main` by default)

### Useful references

- [AFT module documentation](https://github.com/aws-ia/terraform-aws-control_tower_account_factory)
- [AWS AFT Getting Started guide](https://docs.aws.amazon.com/controltower/latest/userguide/aft-getting-started.html)
- [AFT account request schema](https://github.com/aws-ia/terraform-aws-control_tower_account_factory/tree/main/modules/aft-account-request)
