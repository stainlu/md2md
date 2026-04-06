# Section 05: Evidence Collection, Audit Preparation & Ongoing Operations

This section contains everything an agent needs to automate evidence collection, prepare for audit fieldwork, and maintain compliance year-round. All scripts are copy-paste ready. All templates reference actual TSC criteria text from the AICPA 2017 Trust Services Criteria.

---

## Part 1: Evidence Collection Automation

### 1.1 Steampipe Queries for Evidence

Steampipe lets agents run SQL against cloud APIs. Install steampipe and the relevant plugins, then run these queries to produce audit evidence.

```bash
# install steampipe
brew install turbot/tap/steampipe

# install plugins
steampipe plugin install aws
steampipe plugin install github
steampipe plugin install okta
steampipe plugin install googleworkspace
```

#### IAM Users with MFA Status (Access Review Evidence)

```sql
SELECT
  user_name,
  mfa_enabled,
  password_last_used,
  create_date,
  password_enabled,
  access_key_1_active,
  access_key_2_active
FROM
  aws_iam_user
ORDER BY
  user_name;
```

#### S3 Buckets Encryption Status

```sql
SELECT
  name,
  server_side_encryption_configuration,
  bucket_policy_is_public,
  versioning_enabled,
  logging
FROM
  aws_s3_bucket;
```

#### RDS Instances Encryption and Backup Status

```sql
SELECT
  db_instance_identifier,
  storage_encrypted,
  kms_key_id,
  backup_retention_period,
  multi_az,
  publicly_accessible,
  engine,
  engine_version
FROM
  aws_rds_db_instance;
```

#### EBS Volumes Without Encryption

```sql
SELECT
  volume_id,
  encrypted,
  kms_key_id,
  state,
  size
FROM
  aws_ebs_volume
WHERE
  NOT encrypted;
```

#### CloudTrail Configuration

```sql
SELECT
  name,
  is_multi_region_trail,
  log_file_validation_enabled,
  kms_key_id,
  s3_bucket_name,
  is_logging
FROM
  aws_cloudtrail_trail;
```

#### Security Groups with Open Access

```sql
SELECT
  group_id,
  group_name,
  ip_permission_cidr,
  type,
  from_port,
  to_port
FROM
  aws_vpc_security_group_rule
WHERE
  cidr_ipv4 = '0.0.0.0/0';
```

#### GitHub Repository Security Settings

```sql
SELECT
  name,
  is_private,
  has_vulnerability_alerts_enabled,
  default_branch_ref_name
FROM
  github_repository
WHERE
  owner_login = '{{ORG}}';
```

#### KMS Key Rotation Status

```sql
SELECT
  id,
  title,
  key_rotation_enabled,
  key_state,
  creation_date
FROM
  aws_kms_key
WHERE
  key_manager = 'CUSTOMER';
```

#### Okta Users with MFA Status

```sql
SELECT
  login,
  status,
  created,
  last_login,
  type_name
FROM
  okta_user
ORDER BY
  login;
```

#### Google Workspace Users

```sql
SELECT
  primary_email,
  is_admin,
  is_enforced_in_2sv,
  is_enrolled_in_2sv,
  suspended,
  last_login_time,
  creation_time
FROM
  googleworkspace_user
ORDER BY
  primary_email;
```

---

### 1.2 Quarterly Access Review Script

This is the #1 missed evidence item in SOC 2 audits. Run every quarter. The script exports users from AWS IAM, GitHub, and your identity provider, flags stale and over-privileged accounts, and produces a signed markdown report.

```bash
#!/bin/bash
set -euo pipefail

# access-review.sh — quarterly access review evidence generator
# usage: ./access-review.sh [--org GITHUB_ORG] [--idp okta|google]
# output: evidence/access-review-YYYY-QN.md

# --- configuration ---
GITHUB_ORG="${GITHUB_ORG:-{{ORG}}}"
IDP="${IDP:-okta}"  # okta or google
STALE_DAYS=90
EVIDENCE_DIR="evidence"

# --- derived values ---
DATE=$(date +%Y-%m-%d)
MONTH=$(date +%-m)
QUARTER="Q$(( (MONTH - 1) / 3 + 1 ))"
YEAR=$(date +%Y)
OUTPUT_FILE="${EVIDENCE_DIR}/access-review-${YEAR}-${QUARTER}.md"

mkdir -p "$EVIDENCE_DIR"

STALE_CUTOFF=$(date -d "-${STALE_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -v-${STALE_DAYS}d +%Y-%m-%dT%H:%M:%SZ)

{

echo "# Access Review Report"
echo "**Quarter:** ${QUARTER} ${YEAR}"
echo "**Date Conducted:** ${DATE}"
echo "**Reviewer:** {{SECURITY_LEAD}}"
echo "**Review Period:** Previous 90 days"
echo ""
echo "---"
echo ""

# ============================================================
# AWS IAM USERS
# ============================================================
echo "## 1. AWS IAM Users"
echo ""
echo "| User | MFA | Groups | Password Last Used | Console Access | Access Keys | Status |"
echo "|------|-----|--------|--------------------|----------------|-------------|--------|"

aws iam generate-credential-report > /dev/null 2>&1
sleep 2

aws iam get-credential-report --query 'Content' --output text | base64 -d | tail -n +2 | while IFS=',' read -r user arn creation password_enabled password_last_used password_last_changed password_next_rotation mfa_active ak1_active ak1_last_rotated ak1_last_used_date ak1_last_used_region ak1_last_used_service ak2_active ak2_last_rotated ak2_last_used_date ak2_last_used_region ak2_last_used_service cert1 cert2; do
  # skip root account
  [ "$user" = "<root_account>" ] && continue

  # MFA status
  if [ "$mfa_active" = "true" ]; then
    mfa_status="YES"
  else
    mfa_status="**NO MFA**"
  fi

  # groups
  groups=$(aws iam list-groups-for-user --user-name "$user" --query 'Groups[*].GroupName' --output text 2>/dev/null | tr '\t' ', ')
  [ -z "$groups" ] && groups="(none)"

  # password last used
  if [ "$password_last_used" = "no_information" ] || [ "$password_last_used" = "N/A" ] || [ "$password_last_used" = "not_supported" ]; then
    pw_last="Never"
  else
    pw_last="$password_last_used"
  fi

  # access key status
  ak_status=""
  [ "$ak1_active" = "true" ] && ak_status="Key1: active"
  [ "$ak2_active" = "true" ] && ak_status="${ak_status:+$ak_status, }Key2: active"
  [ -z "$ak_status" ] && ak_status="None"

  # flag stale accounts
  flag=""
  if [ "$password_last_used" != "no_information" ] && [ "$password_last_used" != "N/A" ] && [ "$password_last_used" != "not_supported" ]; then
    if [[ "$password_last_used" < "$STALE_CUTOFF" ]]; then
      flag="**STALE (${STALE_DAYS}+ days)**"
    else
      flag="Active"
    fi
  else
    if [ "$password_enabled" = "true" ]; then
      flag="**STALE (never logged in)**"
    else
      flag="Programmatic only"
    fi
  fi

  echo "| ${user} | ${mfa_status} | ${groups} | ${pw_last} | ${password_enabled} | ${ak_status} | ${flag} |"
done

echo ""

# ============================================================
# GITHUB ORG MEMBERS
# ============================================================
echo "## 2. GitHub Organization Members"
echo ""
echo "| Username | Role | 2FA Enabled | Last Active |"
echo "|----------|------|-------------|-------------|"

# get members with role info
gh api "orgs/${GITHUB_ORG}/members?per_page=100" --paginate --jq '.[] | .login' | while read -r login; do
  membership=$(gh api "orgs/${GITHUB_ORG}/memberships/${login}" --jq '.role' 2>/dev/null || echo "member")
  echo "| ${login} | ${membership} | (see org settings) | (check audit log) |"
done

echo ""
echo "### Outside Collaborators"
echo ""
echo "| Username | Repositories | Added Date |"
echo "|----------|-------------|------------|"

gh api "orgs/${GITHUB_ORG}/outside_collaborators?per_page=100" --paginate --jq '.[] | .login' | while read -r login; do
  echo "| ${login} | (review repo access) | (check audit log) |"
done

echo ""
echo "### 2FA Enforcement Status"
echo ""
gh api "orgs/${GITHUB_ORG}" --jq '"Two-factor requirement enforced: \(.two_factor_requirement_enabled)"'
echo ""

# check for members without 2FA (requires org admin)
MEMBERS_NO_2FA=$(gh api "orgs/${GITHUB_ORG}/members?filter=2fa_disabled&per_page=100" --jq '. | length' 2>/dev/null || echo "N/A (requires admin)")
echo "Members without 2FA: ${MEMBERS_NO_2FA}"
echo ""

# ============================================================
# IDENTITY PROVIDER USERS
# ============================================================
echo "## 3. Identity Provider Users"
echo ""

if [ "$IDP" = "okta" ]; then
  echo "### Okta Users"
  echo ""
  echo "| Email | Status | MFA Enrolled | Last Login | Created | Groups |"
  echo "|-------|--------|-------------|------------|---------|--------|"

  # uses okta CLI or API — requires OKTA_ORG_URL and OKTA_API_TOKEN env vars
  if command -v okta-api &> /dev/null || [ -n "${OKTA_API_TOKEN:-}" ]; then
    curl -s -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
      "${OKTA_ORG_URL}/api/v1/users?limit=200" | \
    jq -r '.[] | "| \(.profile.email) | \(.status) | (check factors) | \(.lastLogin // "Never") | \(.created) | (check groups) |"'
  else
    echo "| (configure OKTA_API_TOKEN and OKTA_ORG_URL to populate) | | | | | |"
  fi

elif [ "$IDP" = "google" ]; then
  echo "### Google Workspace Users"
  echo ""
  echo "| Email | Admin | 2SV Enforced | 2SV Enrolled | Suspended | Last Login | Created |"
  echo "|-------|-------|-------------|-------------|-----------|------------|---------|"

  if command -v gam &> /dev/null; then
    gam print users fields name,email,isAdmin,isEnforcedIn2Sv,isEnrolledIn2Sv,suspended,lastLoginTime,creationTime 2>/dev/null | \
    tail -n +2 | while IFS=',' read -r email first last admin enforced enrolled suspended last_login created; do
      echo "| ${email} | ${admin} | ${enforced} | ${enrolled} | ${suspended} | ${last_login} | ${created} |"
    done
  else
    echo "| (install GAM — https://github.com/GAM-team/GAM — to populate) | | | | | | |"
  fi
fi

echo ""

# ============================================================
# STALE ACCOUNT SUMMARY
# ============================================================
echo "## 4. Stale Accounts (No Activity in ${STALE_DAYS}+ Days)"
echo ""
echo "Accounts flagged above as **STALE** require action: confirm the account is still needed or disable it."
echo ""
echo "| Account | Source | Last Activity | Action Required |"
echo "|---------|--------|---------------|-----------------|"
echo "| (auto-populated from flags above — review and add rows as needed) | | | Keep / Disable / Investigate |"
echo ""

# ============================================================
# OVER-PRIVILEGED ACCOUNTS
# ============================================================
echo "## 5. Over-Privileged Account Review"
echo ""
echo "### AWS IAM Users with Admin-Level Access"
echo ""
echo "| User | Policy | Justification |"
echo "|------|--------|---------------|"

aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read -r user; do
  # check for AdministratorAccess or IAMFullAccess
  policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)
  if echo "$policies" | grep -qiE 'admin|fullaccess'; then
    echo "| ${user} | ${policies} | **REVIEW — confirm admin access is justified** |"
  fi
  # check group-attached admin policies
  aws iam list-groups-for-user --user-name "$user" --query 'Groups[*].GroupName' --output text 2>/dev/null | tr '\t' '\n' | while read -r group; do
    group_policies=$(aws iam list-attached-group-policies --group-name "$group" --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)
    if echo "$group_policies" | grep -qiE 'admin|fullaccess'; then
      echo "| ${user} (via group: ${group}) | ${group_policies} | **REVIEW — admin via group** |"
    fi
  done
done

echo ""

# ============================================================
# REVIEW DECISIONS
# ============================================================
echo "## 6. Review Decisions"
echo ""
echo "For each user across all systems, confirm access is appropriate."
echo ""
echo "| User / Account | System | Current Access | Decision | Justification |"
echo "|----------------|--------|----------------|----------|---------------|"
echo "| | AWS IAM | | Keep / Modify / Remove | |"
echo "| | GitHub | | Keep / Modify / Remove | |"
echo "| | IdP | | Keep / Modify / Remove | |"
echo ""

# ============================================================
# SIGN-OFF
# ============================================================
echo "## 7. Sign-Off"
echo ""
echo "I have reviewed all user accounts across AWS IAM, GitHub, and the identity provider."
echo "Stale and over-privileged accounts have been identified and flagged for action."
echo "All access decisions are documented above."
echo ""
echo "| Role | Name | Signature | Date |"
echo "|------|------|-----------|------|"
echo "| Security Lead | {{SECURITY_LEAD}} | _________________________ | ${DATE} |"
echo "| CTO / VP Engineering | {{CTO}} | _________________________ | ${DATE} |"
echo "| Compliance Owner | {{COMPLIANCE_OWNER}} | _________________________ | ${DATE} |"

} > "$OUTPUT_FILE"

echo "Access review saved to: ${OUTPUT_FILE}"
```

---

### 1.3 Encryption Verification Script

Verifies encryption at rest and in transit across all data stores. Run quarterly or before audit fieldwork.

```bash
#!/bin/bash
set -euo pipefail

# verify-encryption.sh — encryption verification evidence generator
# usage: ./verify-encryption.sh [--endpoints endpoint1,endpoint2]
# output: evidence/encryption-verification-YYYY-MM-DD.md

EVIDENCE_DIR="evidence"
DATE=$(date +%Y-%m-%d)
OUTPUT_FILE="${EVIDENCE_DIR}/encryption-verification-${DATE}.md"
ENDPOINTS="${ENDPOINTS:-}"  # comma-separated list of public endpoints to check TLS

mkdir -p "$EVIDENCE_DIR"

PASS_COUNT_FILE=$(mktemp)
FAIL_COUNT_FILE=$(mktemp)
echo 0 > "$PASS_COUNT_FILE"
echo 0 > "$FAIL_COUNT_FILE"
trap 'rm -f "$PASS_COUNT_FILE" "$FAIL_COUNT_FILE"' EXIT

pass() { echo $(( $(cat "$PASS_COUNT_FILE") + 1 )) > "$PASS_COUNT_FILE"; echo "PASS"; }
fail() { echo $(( $(cat "$FAIL_COUNT_FILE") + 1 )) > "$FAIL_COUNT_FILE"; echo "**FAIL**"; }

{

echo "# Encryption Verification Report"
echo "**Date:** ${DATE}"
echo "**Conducted by:** {{SECURITY_LEAD}}"
echo ""
echo "---"
echo ""

# ============================================================
# S3 BUCKET ENCRYPTION
# ============================================================
echo "## 1. S3 Bucket Encryption"
echo ""
echo "| Bucket | Encrypted | Algorithm | KMS Key | Bucket Policy Public | Versioning |"
echo "|--------|-----------|-----------|---------|---------------------|------------|"

aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read -r bucket; do
  enc_config=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "NONE")

  if [ "$enc_config" = "NONE" ]; then
    algorithm="None"
    kms_key="N/A"
    encrypted=$(fail)
  else
    algorithm=$(echo "$enc_config" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "Unknown"')
    kms_key=$(echo "$enc_config" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID // "AWS managed"')
    encrypted=$(pass)
  fi

  # check public access
  public_status=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null | jq -r '[.PublicAccessBlockConfiguration | to_entries[] | select(.value == false) | .key] | if length > 0 then "**PARTIAL BLOCK**" else "Fully blocked" end' 2>/dev/null || echo "**NO BLOCK CONFIG**")

  # check versioning
  versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text 2>/dev/null)
  [ "$versioning" = "None" ] || [ -z "$versioning" ] && versioning="Disabled"

  echo "| ${bucket} | ${encrypted} | ${algorithm} | ${kms_key} | ${public_status} | ${versioning} |"
done

echo ""

# ============================================================
# RDS INSTANCE ENCRYPTION
# ============================================================
echo "## 2. RDS Instance Encryption"
echo ""
echo "| Instance | Engine | Encrypted | KMS Key | Multi-AZ | Publicly Accessible | Backup Retention |"
echo "|----------|--------|-----------|---------|----------|--------------------|--------------------|"

aws rds describe-db-instances --query 'DBInstances[*]' --output json | jq -r '.[] | [
  .DBInstanceIdentifier,
  .Engine,
  (if .StorageEncrypted then "PASS" else "**FAIL**" end),
  (.KmsKeyId // "N/A"),
  (if .MultiAZ then "Yes" else "No" end),
  (if .PubliclyAccessible then "**YES**" else "No" end),
  (.BackupRetentionPeriod | tostring)
] | join(" | ")' | while IFS= read -r line; do
  echo "| ${line} |"
done

echo ""

# ============================================================
# EBS VOLUME ENCRYPTION
# ============================================================
echo "## 3. EBS Volume Encryption"
echo ""

TOTAL_EBS=$(aws ec2 describe-volumes --query 'Volumes | length(@)' --output text)
ENCRYPTED_EBS=$(aws ec2 describe-volumes --filters Name=encrypted,Values=true --query 'Volumes | length(@)' --output text)
UNENCRYPTED_EBS=$((TOTAL_EBS - ENCRYPTED_EBS))

echo "Total volumes: ${TOTAL_EBS} | Encrypted: ${ENCRYPTED_EBS} | Unencrypted: ${UNENCRYPTED_EBS}"
echo ""

if [ "$UNENCRYPTED_EBS" -gt 0 ]; then
  echo "### Unencrypted EBS Volumes (ACTION REQUIRED)"
  echo ""
  echo "| Volume ID | Size (GB) | State | Attached To | AZ |"
  echo "|-----------|-----------|-------|-------------|-----|"

  aws ec2 describe-volumes --filters Name=encrypted,Values=false \
    --query 'Volumes[*].[VolumeId, Size, State, Attachments[0].InstanceId, AvailabilityZone]' \
    --output text | while read -r vol_id size state instance az; do
    [ "$instance" = "None" ] && instance="(detached)"
    echo "| ${vol_id} | ${size} | ${state} | ${instance} | ${az} |"
  done
  echo ""
fi

# check EBS default encryption
DEFAULT_EBS_ENC=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "Unknown")
echo "EBS default encryption enabled: **${DEFAULT_EBS_ENC}**"
echo ""

# ============================================================
# TLS CONFIGURATION ON PUBLIC ENDPOINTS
# ============================================================
echo "## 4. TLS Configuration (Public Endpoints)"
echo ""

if [ -n "$ENDPOINTS" ]; then
  echo "| Endpoint | TLS Version | Certificate Issuer | Certificate Expiry | HSTS | Result |"
  echo "|----------|-------------|--------------------|--------------------|------|--------|"

  IFS=',' read -ra ENDPOINT_LIST <<< "$ENDPOINTS"
  for endpoint in "${ENDPOINT_LIST[@]}"; do
    endpoint=$(echo "$endpoint" | xargs)  # trim whitespace

    # get TLS info via curl
    tls_info=$(curl -svI "https://${endpoint}" 2>&1 || true)
    tls_version=$(echo "$tls_info" | grep -oP 'SSL connection using \K[^/]+' 2>/dev/null || echo "Unknown")
    cert_issuer=$(echo "$tls_info" | grep -oP 'issuer: \K.*' 2>/dev/null | head -1 || echo "Unknown")
    cert_expiry=$(echo "$tls_info" | grep -oP 'expire date: \K.*' 2>/dev/null || echo "Unknown")
    hsts=$(echo "$tls_info" | grep -i 'strict-transport-security' 2>/dev/null && echo "Yes" || echo "No")

    # check for TLS 1.2+
    if echo "$tls_version" | grep -qE 'TLSv1\.[23]'; then
      result=$(pass)
    else
      result=$(fail)
    fi

    echo "| ${endpoint} | ${tls_version} | ${cert_issuer} | ${cert_expiry} | ${hsts} | ${result} |"
  done
else
  echo "No endpoints configured. Set ENDPOINTS env var (comma-separated) or pass --endpoints flag."
  echo ""
  echo "Manual verification command:"
  echo '```'
  echo 'curl -svI https://YOUR_ENDPOINT 2>&1 | grep -E "SSL connection|expire date|issuer"'
  echo '```'
fi

echo ""

# reject old TLS versions
echo "### Weak TLS Protocol Check"
echo ""
echo "Verifying that TLS 1.0 and 1.1 are rejected:"
echo ""

if [ -n "$ENDPOINTS" ]; then
  IFS=',' read -ra ENDPOINT_LIST <<< "$ENDPOINTS"
  for endpoint in "${ENDPOINT_LIST[@]}"; do
    endpoint=$(echo "$endpoint" | xargs)
    for proto in tls1 tls1_1; do
      result=$(curl -s --connect-timeout 5 --"$proto" "https://${endpoint}" 2>&1 && echo "**FAIL — ${proto} accepted**" || echo "PASS — ${proto} rejected")
      echo "- ${endpoint} (${proto}): ${result}"
    done
  done
fi

echo ""

# ============================================================
# KMS KEY ROTATION
# ============================================================
echo "## 5. KMS Key Rotation"
echo ""
echo "| Key ID | Description | Rotation Enabled | Key State | Created |"
echo "|--------|-------------|-----------------|-----------|---------|"

aws kms list-keys --query 'Keys[*].KeyId' --output text | tr '\t' '\n' | while read -r key_id; do
  key_info=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata' --output json 2>/dev/null)
  manager=$(echo "$key_info" | jq -r '.KeyManager')

  # skip AWS-managed keys
  [ "$manager" != "CUSTOMER" ] && continue

  description=$(echo "$key_info" | jq -r '.Description // "N/A"')
  state=$(echo "$key_info" | jq -r '.KeyState')
  created=$(echo "$key_info" | jq -r '.CreationDate')

  rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "N/A")

  if [ "$rotation" = "True" ]; then
    rot_status="PASS"
  elif [ "$rotation" = "False" ]; then
    rot_status="**FAIL — rotation disabled**"
  else
    rot_status="$rotation"
  fi

  echo "| ${key_id} | ${description} | ${rot_status} | ${state} | ${created} |"
done

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "## 6. Summary"
echo ""
echo "| Check | Count |"
echo "|-------|-------|"
echo "| Passed | $(cat "$PASS_COUNT_FILE") |"
echo "| Failed | $(cat "$FAIL_COUNT_FILE") |"
echo ""

if [ "$(cat "$FAIL_COUNT_FILE")" -gt 0 ]; then
  echo "**ACTION REQUIRED:** $(cat "$FAIL_COUNT_FILE") encryption check(s) failed. Remediate before audit fieldwork."
else
  echo "All encryption checks passed."
fi

echo ""
echo "## 7. Sign-Off"
echo ""
echo "| Role | Name | Signature | Date |"
echo "|------|------|-----------|------|"
echo "| Security Lead | {{SECURITY_LEAD}} | _________________________ | ${DATE} |"
echo "| CTO | {{CTO}} | _________________________ | ${DATE} |"

} > "$OUTPUT_FILE"

echo "Encryption verification saved to: ${OUTPUT_FILE}"
```

---

### 1.4 Change Management Evidence Script

Produces evidence that all code changes followed the defined change management process. Identifies exceptions (merges without review, direct pushes to main) that the auditor will flag.

```bash
#!/bin/bash
set -euo pipefail

# change-evidence.sh — change management evidence generator
# usage: ./change-evidence.sh 2026-01-01 2026-06-30 [--repo ORG/REPO]
# output: evidence/change-mgmt-YYYY-QN.md

START_DATE="${1:?Usage: ./change-evidence.sh START_DATE END_DATE [--repo ORG/REPO]}"
END_DATE="${2:?Usage: ./change-evidence.sh START_DATE END_DATE [--repo ORG/REPO]}"
REPO="${REPO:-{{ORG}}/{{REPO}}}"
EVIDENCE_DIR="evidence"

DATE=$(date +%Y-%m-%d)
MONTH=$(date +%-m)
QUARTER="Q$(( (MONTH - 1) / 3 + 1 ))"
YEAR=$(date +%Y)
OUTPUT_FILE="${EVIDENCE_DIR}/change-mgmt-${YEAR}-${QUARTER}.md"

mkdir -p "$EVIDENCE_DIR"

{

echo "# Change Management Evidence Report"
echo "**Audit Period:** ${START_DATE} to ${END_DATE}"
echo "**Repository:** ${REPO}"
echo "**Generated:** ${DATE}"
echo "**Owner:** {{CTO}}"
echo ""
echo "---"
echo ""

# ============================================================
# BRANCH PROTECTION STATUS
# ============================================================
echo "## 1. Branch Protection Configuration"
echo ""

protection=$(gh api "repos/${REPO}/branches/main/protection" 2>/dev/null || echo "NONE")

if [ "$protection" = "NONE" ]; then
  echo "**WARNING: No branch protection rules configured on main branch.**"
else
  echo "| Setting | Value |"
  echo "|---------|-------|"

  pr_required=$(echo "$protection" | jq -r '.required_pull_request_reviews.required_approving_review_count // "Not required"')
  echo "| Required approving reviews | ${pr_required} |"

  status_checks=$(echo "$protection" | jq -r '.required_status_checks.strict // "Not required"')
  echo "| Require branches to be up to date | ${status_checks} |"

  enforce_admins=$(echo "$protection" | jq -r '.enforce_admins.enabled // "false"')
  echo "| Enforce for admins | ${enforce_admins} |"

  dismiss_stale=$(echo "$protection" | jq -r '.required_pull_request_reviews.dismiss_stale_reviews // "false"')
  echo "| Dismiss stale reviews | ${dismiss_stale} |"

  force_push=$(echo "$protection" | jq -r '.allow_force_pushes.enabled // "false"')
  echo "| Allow force pushes | ${force_push} |"

  deletions=$(echo "$protection" | jq -r '.allow_deletions.enabled // "false"')
  echo "| Allow deletions | ${deletions} |"
fi

echo ""

# ============================================================
# ALL MERGED PRs
# ============================================================
echo "## 2. Pull Requests Merged to Main"
echo ""
echo "| PR # | Title | Author | Reviewers | CI Status | Merged At |"
echo "|------|-------|--------|-----------|-----------|-----------|"

# fetch all merged PRs in the audit period
gh pr list --repo "$REPO" --state merged --base main \
  --search "merged:${START_DATE}..${END_DATE}" --limit 500 \
  --json number,title,author,reviews,mergedAt,statusCheckRollup \
  --jq '.[]' | jq -c '.' | while read -r pr; do

  number=$(echo "$pr" | jq -r '.number')
  title=$(echo "$pr" | jq -r '.title' | sed 's/|/-/g')
  author=$(echo "$pr" | jq -r '.author.login')
  reviewers=$(echo "$pr" | jq -r '[.reviews[]? | .author.login] | unique | join(", ")')
  merged_at=$(echo "$pr" | jq -r '.mergedAt')
  ci_status=$(echo "$pr" | jq -r '[.statusCheckRollup[]? | .conclusion] | unique | join(", ")')

  [ -z "$reviewers" ] && reviewers="**NONE**"
  [ -z "$ci_status" ] && ci_status="N/A"

  echo "| #${number} | ${title} | ${author} | ${reviewers} | ${ci_status} | ${merged_at} |"
done

echo ""

# ============================================================
# PRs MERGED WITHOUT REVIEW (EXCEPTIONS)
# ============================================================
echo "## 3. PRs Merged Without Code Review (Potential Exceptions)"
echo ""
echo "These PRs were merged without any approving review. Each requires documented justification."
echo ""
echo "| PR # | Title | Author | Merged At | Exception Justification |"
echo "|------|-------|--------|-----------|------------------------|"

gh pr list --repo "$REPO" --state merged --base main \
  --search "merged:${START_DATE}..${END_DATE} review:none" --limit 500 \
  --json number,title,author,mergedAt \
  --jq '.[] | "| #\(.number) | \(.title) | \(.author.login) | \(.mergedAt) | **REQUIRES JUSTIFICATION** |"'

echo ""

# ============================================================
# DIRECT PUSHES TO MAIN (EXCEPTIONS)
# ============================================================
echo "## 4. Direct Pushes to Main (Definite Exceptions)"
echo ""
echo "Any commit pushed directly to main (not via a pull request merge) is an exception that requires documented justification."
echo ""
echo "| Commit SHA | Author | Date | Message | Exception Justification |"
echo "|------------|--------|------|---------|------------------------|"

# compare merge commits vs direct pushes
# get all commits on main in the period
gh api "repos/${REPO}/commits?sha=main&since=${START_DATE}T00:00:00Z&until=${END_DATE}T23:59:59Z&per_page=100" --paginate --jq '.[] | select(.parents | length <= 1) | "| \(.sha[:8]) | \(.commit.author.name) | \(.commit.author.date) | \(.commit.message | split("\n")[0] | gsub("\\|"; "-")) | **REQUIRES JUSTIFICATION** |"' 2>/dev/null || echo "| (unable to retrieve — check API permissions) | | | | |"

echo ""

# ============================================================
# CI/CD PIPELINE EVIDENCE
# ============================================================
echo "## 5. CI/CD Pipeline Configuration"
echo ""
echo "Verify that CI runs automatically on all PRs targeting main."
echo ""

# check for GitHub Actions workflows
echo "### GitHub Actions Workflows"
echo ""
gh api "repos/${REPO}/actions/workflows" --jq '.workflows[] | "- **\(.name)** (state: \(.state), path: \(.path))"' 2>/dev/null || echo "- (unable to retrieve workflows)"

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "## 6. Summary"
echo ""

total=$(gh pr list --repo "$REPO" --state merged --base main \
  --search "merged:${START_DATE}..${END_DATE}" --limit 500 \
  --json number --jq '. | length' 2>/dev/null || echo "N/A")

no_review=$(gh pr list --repo "$REPO" --state merged --base main \
  --search "merged:${START_DATE}..${END_DATE} review:none" --limit 500 \
  --json number --jq '. | length' 2>/dev/null || echo "N/A")

echo "| Metric | Count |"
echo "|--------|-------|"
echo "| Total PRs merged | ${total} |"
echo "| PRs without review | ${no_review} |"
echo "| Direct pushes to main | (count from section 4 above) |"
echo ""

if [ "$no_review" != "0" ] && [ "$no_review" != "N/A" ]; then
  echo "**ACTION REQUIRED:** ${no_review} PR(s) were merged without review. Document justification for each before audit."
fi

echo ""
echo "## 7. Sign-Off"
echo ""
echo "| Role | Name | Signature | Date |"
echo "|------|------|-----------|------|"
echo "| CTO | {{CTO}} | _________________________ | ${DATE} |"
echo "| Security Lead | {{SECURITY_LEAD}} | _________________________ | ${DATE} |"

} > "$OUTPUT_FILE"

echo "Change management evidence saved to: ${OUTPUT_FILE}"
```

---

### 1.5 Backup Verification Script

Verifies that automated backups are configured and recent. Run quarterly.

```bash
#!/bin/bash
set -euo pipefail

# verify-backups.sh — backup verification evidence generator
# usage: ./verify-backups.sh
# output: evidence/backup-verification-YYYY-QN.md

EVIDENCE_DIR="evidence"
DATE=$(date +%Y-%m-%d)
MONTH=$(date +%-m)
QUARTER="Q$(( (MONTH - 1) / 3 + 1 ))"
YEAR=$(date +%Y)
OUTPUT_FILE="${EVIDENCE_DIR}/backup-verification-${YEAR}-${QUARTER}.md"

mkdir -p "$EVIDENCE_DIR"

{

echo "# Backup Verification Report"
echo "**Quarter:** ${QUARTER} ${YEAR}"
echo "**Date:** ${DATE}"
echo "**Conducted by:** {{CTO}}"
echo ""
echo "---"
echo ""

# ============================================================
# RDS AUTOMATED BACKUPS
# ============================================================
echo "## 1. RDS Automated Backups"
echo ""
echo "| Instance | Engine | Backup Retention (days) | Latest Restorable Time | Multi-AZ | Encrypted | Status |"
echo "|----------|--------|------------------------|------------------------|----------|-----------|--------|"

aws rds describe-db-instances --query 'DBInstances[*]' --output json | jq -r '.[] | [
  .DBInstanceIdentifier,
  .Engine,
  (.BackupRetentionPeriod | tostring),
  (.LatestRestorableTime // "N/A"),
  (if .MultiAZ then "Yes" else "No" end),
  (if .StorageEncrypted then "Yes" else "No" end),
  (if .BackupRetentionPeriod >= 7 then "PASS" else "**FAIL — retention < 7 days**" end)
] | join(" | ")' | while IFS= read -r line; do
  echo "| ${line} |"
done

echo ""

# check automated backup freshness
echo "### Backup Freshness Check"
echo ""

aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,LatestRestorableTime]' --output text | while read -r instance restore_time; do
  if [ "$restore_time" = "None" ]; then
    echo "- **${instance}:** **FAIL — no restorable point available**"
  else
    # check if latest restorable time is within 24 hours
    restore_epoch=$(date -d "$restore_time" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%S" "$restore_time" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)
    diff_hours=$(( (now_epoch - restore_epoch) / 3600 ))

    if [ "$diff_hours" -lt 24 ]; then
      echo "- **${instance}:** PASS (latest restore point: ${restore_time}, ${diff_hours}h ago)"
    else
      echo "- **${instance}:** **WARNING — latest restore point is ${diff_hours}h old (${restore_time})**"
    fi
  fi
done

echo ""

# ============================================================
# RDS SNAPSHOTS
# ============================================================
echo "## 2. RDS Snapshots (Most Recent)"
echo ""
echo "| Instance | Snapshot ID | Created | Encrypted | Status |"
echo "|----------|------------|---------|-----------|--------|"

aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output text | tr '\t' '\n' | while read -r instance; do
  aws rds describe-db-snapshots \
    --db-instance-identifier "$instance" \
    --query 'sort_by(DBSnapshots, &SnapshotCreateTime)[-1]' \
    --output json 2>/dev/null | jq -r '
    if . == null then
      "| '"$instance"' | None | N/A | N/A | **FAIL — no snapshots** |"
    else
      "| '"$instance"' | \(.DBSnapshotIdentifier) | \(.SnapshotCreateTime) | \(if .Encrypted then "Yes" else "No" end) | PASS |"
    end'
done

echo ""

# ============================================================
# S3 CROSS-REGION REPLICATION
# ============================================================
echo "## 3. S3 Cross-Region Replication"
echo ""
echo "| Source Bucket | Replication Configured | Destination | Status |"
echo "|--------------|----------------------|-------------|--------|"

aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read -r bucket; do
  repl=$(aws s3api get-bucket-replication --bucket "$bucket" 2>/dev/null || echo "NONE")

  if [ "$repl" = "NONE" ]; then
    echo "| ${bucket} | No | N/A | (replication not configured) |"
  else
    dest=$(echo "$repl" | jq -r '.ReplicationConfiguration.Rules[0].Destination.Bucket // "Unknown"')
    status=$(echo "$repl" | jq -r '.ReplicationConfiguration.Rules[0].Status // "Unknown"')
    echo "| ${bucket} | Yes | ${dest} | ${status} |"
  fi
done

echo ""

# ============================================================
# DYNAMODB BACKUPS (if applicable)
# ============================================================
echo "## 4. DynamoDB Backups (if applicable)"
echo ""

TABLE_COUNT=$(aws dynamodb list-tables --query 'TableNames | length(@)' --output text 2>/dev/null || echo "0")

if [ "$TABLE_COUNT" -gt 0 ]; then
  echo "| Table | Point-in-Time Recovery | Continuous Backups | Status |"
  echo "|-------|----------------------|-------------------|--------|"

  aws dynamodb list-tables --query 'TableNames[*]' --output text | tr '\t' '\n' | while read -r table; do
    pitr=$(aws dynamodb describe-continuous-backups --table-name "$table" --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' --output text 2>/dev/null || echo "Unknown")

    if [ "$pitr" = "ENABLED" ]; then
      echo "| ${table} | ENABLED | Yes | PASS |"
    else
      echo "| ${table} | ${pitr} | No | **FAIL** |"
    fi
  done
else
  echo "No DynamoDB tables found. Skipping."
fi

echo ""

# ============================================================
# BACKUP RESTORE TEST LOG
# ============================================================
echo "## 5. Backup Restore Test History"
echo ""
echo "Document all backup restore tests conducted this quarter."
echo ""
echo "| Date | System | Backup Used | Recovery Time | Data Integrity | Tester | Result |"
echo "|------|--------|-------------|---------------|----------------|--------|--------|"
echo "| (fill in after each restore test) | | | | | | PASS / FAIL |"
echo ""
echo "**Requirement:** At least one restore test per quarter. Next scheduled test: ____________"

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "## 6. Summary"
echo ""
echo "| Check | Result |"
echo "|-------|--------|"
echo "| All RDS instances have backup retention >= 7 days | (see section 1) |"
echo "| All RDS backups are fresh (< 24 hours) | (see section 1) |"
echo "| All RDS snapshots encrypted | (see section 2) |"
echo "| S3 cross-region replication configured for critical buckets | (see section 3) |"
echo "| DynamoDB PITR enabled on all tables | (see section 4) |"
echo "| Backup restore test conducted this quarter | (see section 5) |"

echo ""
echo "## 7. Sign-Off"
echo ""
echo "| Role | Name | Signature | Date |"
echo "|------|------|-----------|------|"
echo "| CTO | {{CTO}} | _________________________ | ${DATE} |"
echo "| Security Lead | {{SECURITY_LEAD}} | _________________________ | ${DATE} |"

} > "$OUTPUT_FILE"

echo "Backup verification saved to: ${OUTPUT_FILE}"
```

---

## Part 2: Compliance Platform Integration

### 2.1 Vanta ($10K-$25K/yr)

**Best for:** most integrations (300+), largest auditor network, mature platform.

#### Required Integrations Checklist

Connect all of these before going live:

```
[ ] AWS — IAM, S3, RDS, EC2, CloudTrail, GuardDuty, Config, KMS, VPC
[ ] GitHub — repos, branch protection, PR reviews, Dependabot alerts
[ ] Okta or Google Workspace — users, MFA, groups, SSO apps
[ ] HR system (Rippling, Gusto, BambooHR) — employee list, onboarding/offboarding
[ ] MDM (Jamf, Intune, Kandji) — device inventory, encryption, OS compliance
[ ] CI/CD (GitHub Actions, CircleCI) — pipeline configs, run history
[ ] Monitoring (Datadog, Splunk, PagerDuty) — alert configs, incident tracking
[ ] Background check provider (Checkr, GoodHire) — completion records
[ ] Ticketing (Jira, Linear) — change management records
[ ] Training (KnowBe4, Curricula) — completion certificates
```

#### What Vanta Monitors Automatically

- AWS resource configurations (encryption, public access, IAM policies, security groups)
- GitHub branch protection, secret scanning, Dependabot alerts
- IdP MFA enforcement, user provisioning/deprovisioning
- MDM device compliance (encryption, OS version, screen lock)
- Employee onboarding/offboarding timeline
- Background check completion
- Training completion
- Vulnerability scanning results

#### What Still Requires Manual Evidence

- Risk assessment document and risk register (upload annually)
- Penetration test report (upload annually)
- DR test results (upload annually)
- Incident response tabletop exercise report (upload annually)
- Board/leadership meeting minutes showing security discussion
- Vendor security reviews for vendors not integrated with Vanta
- Management assertion letter (upload before audit)
- Policy review sign-off records (upload annually)

#### How to Connect Each Integration

**AWS:**
1. In Vanta, navigate to Integrations > AWS
2. Vanta provides a CloudFormation template — deploy it in your AWS account
3. The template creates a cross-account IAM role with read-only access
4. Vanta assumes this role to pull configuration data
5. Deploy in every AWS account (prod, staging, dev)

**GitHub:**
1. Integrations > GitHub > Install Vanta GitHub App
2. Grant access to all repositories (or select specific ones)
3. Requires org admin to approve the app installation

**Okta:**
1. Integrations > Okta > Create API token
2. In Okta admin: Security > API > Create Token with name "Vanta"
3. Copy token into Vanta
4. Provide Okta org URL (e.g., https://yourcompany.okta.com)

**Google Workspace:**
1. Integrations > Google Workspace > Authorize
2. Requires super admin to grant OAuth consent
3. Vanta requests read-only access to user directory, groups, and 2SV status

#### Vanta API for Custom Evidence

```bash
# upload custom evidence via Vanta API
# API docs: https://developer.vanta.com/

VANTA_API_TOKEN="your-api-token"

# list controls
curl -s -H "Authorization: Bearer ${VANTA_API_TOKEN}" \
  "https://api.vanta.com/v1/controls" | jq '.data[] | {id, title, status}'

# upload evidence document
curl -X POST \
  -H "Authorization: Bearer ${VANTA_API_TOKEN}" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@evidence/access-review-2026-Q1.md" \
  -F "controlId=your-control-id" \
  -F "description=Q1 2026 Access Review" \
  "https://api.vanta.com/v1/evidence"

# list tests and their status
curl -s -H "Authorization: Bearer ${VANTA_API_TOKEN}" \
  "https://api.vanta.com/v1/tests" | jq '.data[] | {id, title, outcome}'
```

---

### 2.2 Drata ($8K-$20K/yr)

**Best for:** cleanest UI, guided onboarding, good for teams new to compliance.

#### Required Integrations Checklist

```
[ ] AWS — CloudFormation stack for read-only access
[ ] GitHub — OAuth app installation at org level
[ ] Okta or Google Workspace — API token or OAuth
[ ] HR system (Rippling, Gusto, BambooHR, Deel)
[ ] MDM (Jamf, Kandji, Mosyle, Intune)
[ ] CI/CD (GitHub Actions, GitLab CI, CircleCI)
[ ] Monitoring (Datadog, Splunk, CloudWatch)
[ ] Background checks (Checkr, GoodHire)
[ ] Training — Drata includes built-in security awareness training
[ ] Ticketing (Jira, Linear, Asana)
```

#### What Drata Monitors Automatically

- Same AWS, GitHub, IdP, MDM monitoring as Vanta
- Built-in security awareness training with completion tracking
- Automatic policy version tracking and acknowledgment collection
- Employee access reviews with guided workflow
- Continuous control monitoring with pass/fail dashboard

#### What Still Requires Manual Evidence

- Risk assessment and risk register
- Penetration test report
- DR test results
- IR tabletop exercise report
- Vendor reviews for non-integrated vendors
- Management assertion letter
- Custom evidence for any controls not covered by integrations

#### How to Connect Each Integration

**AWS:**
1. Connections > Add Connection > AWS
2. Drata provides a CloudFormation template (read-only cross-account role)
3. Deploy the template and enter the role ARN in Drata

**GitHub:**
1. Connections > Add Connection > GitHub
2. Authorize Drata GitHub App (requires org admin)
3. Select repositories to monitor

**Okta:**
1. Connections > Add Connection > Okta
2. Create an API token in Okta admin (Security > API > Tokens)
3. Enter Okta domain and token in Drata

**Google Workspace:**
1. Connections > Add Connection > Google Workspace
2. Authorize with super admin credentials
3. Grant read-only directory access

#### Drata API for Custom Evidence

```bash
DRATA_API_KEY="your-api-key"

# list controls
curl -s -H "Authorization: Bearer ${DRATA_API_KEY}" \
  "https://public-api.drata.com/controls" | jq '.data[] | {id, name, status}'

# upload evidence
curl -X POST \
  -H "Authorization: Bearer ${DRATA_API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@evidence/access-review-2026-Q1.md" \
  -F "controlId=your-control-id" \
  "https://public-api.drata.com/evidence"
```

---

### 2.3 Secureframe ($12K-$20K/yr)

**Best for:** advisory support included, AI-assisted policy drafting, strong for first-time compliance.

#### Required Integrations Checklist

```
[ ] AWS — cross-account role via CloudFormation
[ ] GitHub — GitHub App installation
[ ] Okta or Google Workspace — API token or OAuth
[ ] HR system (Rippling, Gusto, BambooHR)
[ ] MDM (Jamf, Kandji, Intune)
[ ] CI/CD (GitHub Actions, CircleCI, Jenkins)
[ ] Monitoring (Datadog, Splunk, PagerDuty)
[ ] Background checks (Checkr, GoodHire)
[ ] Training — Secureframe includes built-in training
[ ] Ticketing (Jira, Linear)
```

#### What Secureframe Monitors Automatically

- Cloud infrastructure configurations
- Code repository security settings
- IdP users, MFA, and access groups
- Device compliance via MDM
- Employee lifecycle (onboarding/offboarding)
- Background check completion
- Training completion (built-in)
- Continuous monitoring with automated remediation guidance

#### What Still Requires Manual Evidence

- Risk assessment and risk register
- Penetration test report
- DR test results
- IR tabletop exercise report
- Vendor reviews for non-integrated vendors
- Management assertion letter

#### How to Connect Each Integration

**AWS:**
1. Integrations > AWS > Deploy CloudFormation Stack
2. Secureframe provides the template with scoped read-only permissions
3. One stack per AWS account

**GitHub:**
1. Integrations > GitHub > Install App
2. Org admin approves, select repos

**Okta / Google Workspace:**
1. Integrations > Identity Provider > Follow OAuth flow or enter API token

#### Secureframe API for Custom Evidence

```bash
SECUREFRAME_API_KEY="your-api-key"

# list controls
curl -s -H "Authorization: Bearer ${SECUREFRAME_API_KEY}" \
  "https://api.secureframe.com/controls"

# upload evidence
curl -X POST \
  -H "Authorization: Bearer ${SECUREFRAME_API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@evidence/access-review-2026-Q1.md" \
  -F "control_id=your-control-id" \
  "https://api.secureframe.com/evidence"
```

---

### 2.4 Sprinto ($5K-$10K/yr)

**Best for:** startups, lowest cost, solid integration coverage, quick onboarding.

#### Required Integrations Checklist

```
[ ] AWS — IAM role via CloudFormation or manual setup
[ ] GitHub — OAuth or GitHub App
[ ] Okta or Google Workspace — API or OAuth
[ ] HR system (Rippling, Gusto, BambooHR)
[ ] MDM (Jamf, Kandji, Intune)
[ ] CI/CD (GitHub Actions)
[ ] Monitoring (Datadog, CloudWatch)
[ ] Background checks (Checkr)
[ ] Training — Sprinto includes built-in training
[ ] Ticketing (Jira)
```

#### What Sprinto Monitors Automatically

- Cloud infrastructure configurations (AWS, GCP, Azure)
- Source control security settings
- IdP user lifecycle and MFA
- Device compliance
- Employee onboarding/offboarding
- Training completion
- Continuous control monitoring

#### What Still Requires Manual Evidence

- Risk assessment and risk register
- Penetration test report
- DR test results
- IR tabletop exercise report
- Vendor reviews for non-integrated vendors
- Management assertion letter

#### How to Connect Each Integration

**AWS:**
1. Connect Cloud > AWS > Sprinto provides CloudFormation or IAM role instructions
2. Deploy read-only access role
3. Enter role ARN in Sprinto

**GitHub:**
1. Connect Apps > GitHub > Authorize
2. Requires org admin approval

**Okta / Google Workspace:**
1. Connect Apps > Identity Provider > Follow setup guide

---

### 2.5 No Platform (Manual Evidence Collection)

If you are not using a compliance platform, collect all evidence manually. This is significantly more work but possible for very small teams.

#### Folder Structure

```
evidence/
  access-reviews/
    access-review-2026-Q1.md
    access-review-2026-Q2.md
    access-review-2026-Q3.md
    access-review-2026-Q4.md
  encryption/
    encryption-verification-2026-01-15.md
    encryption-verification-2026-07-15.md
  change-management/
    change-mgmt-2026-Q1.md
    change-mgmt-2026-Q2.md
    change-mgmt-2026-Q3.md
    change-mgmt-2026-Q4.md
  backups/
    backup-verification-2026-Q1.md
    backup-verification-2026-Q2.md
    backup-verification-2026-Q3.md
    backup-verification-2026-Q4.md
  risk/
    risk-assessment-2026.md
    risk-register-2026.csv
  incidents/
    incident-log-2026.md
    postmortem-INC-001.md
  vendor/
    vendor-register-2026.csv
    vendor-review-aws-2026.md
    vendor-review-stripe-2026.md
  training/
    training-log-2026.csv
    training-completion-jdoe-2026.pdf
  hr/
    onboarding-checklist-jdoe.md
    offboarding-checklist-asmith.md
    background-check-log-2026.csv
  policies/
    information-security-policy-v1.0.md
    access-control-policy-v1.0.md
    (all 12 policies)
  pentest/
    pentest-report-2026.pdf
  dr/
    dr-test-results-2026.md
  audit/
    system-description-2026.md
    control-matrix-2026.md
    management-assertion-letter-2026.md
```

#### File Naming Convention

```
{evidence-type}-{YYYY}-{period}.{ext}

period = Q1, Q2, Q3, Q4, or full date YYYY-MM-DD
ext = .md for reports, .csv for structured data, .pdf for third-party docs
```

#### Evidence Collection Schedule

| Evidence | Frequency | Script / Source |
|----------|-----------|----------------|
| Access review | Quarterly | access-review.sh |
| Encryption verification | Quarterly | verify-encryption.sh |
| Change management evidence | Quarterly | change-evidence.sh |
| Backup verification | Quarterly | verify-backups.sh |
| Risk assessment | Annually | Manual — security lead |
| Penetration test | Annually | Third-party vendor |
| DR test | Annually | Manual — CTO |
| IR tabletop | Annually | Manual — security lead |
| Vendor reviews | Annually | Manual — compliance owner |
| Training records | Ongoing | Training platform export |
| Onboarding/offboarding records | Per event | Ticketing system export |
| Policy reviews | Annually | Manual — security lead + CEO sign-off |

---

## Part 3: Audit Preparation

### 3.1 System Description Template

The auditor requires a system description as part of the SOC 2 report. An agent fills this in using intake questionnaire data and infrastructure discovery results.

```markdown
# System Description
## {{COMPANY_NAME}}

### 1. Company Overview

{{COMPANY_NAME}} is a {{INDUSTRY}} company founded in {{FOUNDED}} with
approximately {{EMPLOYEE_COUNT}} employees. The company provides {{PRODUCT}} to
{{CUSTOMER_TYPE}} customers.

Headquarters: {{HEADQUARTERS}}

### 2. Services Provided

{{PRODUCT_DESCRIPTION}}

The {{PRODUCT}} platform enables customers to [primary use case]. Key
capabilities include:
- [capability 1]
- [capability 2]
- [capability 3]

Customer data processed includes: {{CUSTOMER_DATA_TYPES}}.

### 3. Infrastructure Components

| Component | Service / Product | Provider | Purpose | Region(s) |
|-----------|------------------|----------|---------|-----------|
| Compute | [ECS/EKS/EC2/Lambda/Cloud Run] | {{CLOUD_PROVIDER}} | Application hosting | {{REGIONS}} |
| Database | {{DB_TYPE}} | {{DB_HOST}} | Primary data store | {{REGIONS}} |
| Object Storage | [S3/GCS/Azure Blob] | {{CLOUD_PROVIDER}} | File storage, backups | {{REGIONS}} |
| Cache | [ElastiCache/Memorystore/Redis] | {{CLOUD_PROVIDER}} | Application caching | {{REGIONS}} |
| CDN | [CloudFront/Cloudflare/Fastly] | [provider] | Content delivery, DDoS protection | Global |
| DNS | [Route 53/Cloud DNS] | {{CLOUD_PROVIDER}} | Domain management | Global |
| Load Balancer | [ALB/NLB/Cloud LB] | {{CLOUD_PROVIDER}} | Traffic distribution | {{REGIONS}} |
| Message Queue | [SQS/SNS/Pub-Sub] | {{CLOUD_PROVIDER}} | Async processing | {{REGIONS}} |
| Identity Provider | {{IDENTITY_PROVIDER}} | [provider] | Employee SSO, MFA | Cloud |
| Source Control | {{SOURCE_CONTROL}} | [provider] | Code repos, version control | Cloud |
| CI/CD | {{CI_CD}} | [provider] | Build, test, deploy pipeline | Cloud |
| Monitoring | {{MONITORING}} | [provider] | Observability, alerting | Cloud |
| Log Aggregation | [CloudWatch/Datadog/Splunk] | [provider] | Centralized logging | Cloud |
| Secrets Management | [AWS Secrets Manager/Vault/SSM] | [provider] | Secret storage, rotation | {{REGIONS}} |
| MDM | {{MDM}} | [provider] | Device management | Cloud |
| EDR | {{EDR}} | [provider] | Endpoint threat detection | Cloud |
| Communication | {{COMMUNICATION}} | [provider] | Team communication | Cloud |
| Ticketing | {{TICKETING}} | [provider] | Project and incident tracking | Cloud |

### 4. Data Flow

```
User Device                   {{COMPANY_NAME}} Infrastructure
-----------                   ---------------------------------

[Browser/App]
     |
     | HTTPS (TLS 1.2+)
     v
[CDN / WAF]
     |
     v
[Load Balancer]
     |
     v
[Application Servers]  --->  [Cache Layer]
     |
     | Encrypted connection
     v
[Primary Database]  --->  [Read Replicas]
(AES-256 at rest)         (AES-256 at rest)
     |
     | Encrypted snapshots
     v
[Backup Storage]
(Cross-region, AES-256)
```

1. Customer accesses the platform via HTTPS (TLS 1.2+ enforced)
2. Requests pass through CDN/WAF for DDoS protection and caching
3. Load balancer distributes traffic to application servers
4. Application authenticates the request and processes it
5. Data is read from / written to the primary database (encrypted at rest with AES-256 via {{CLOUD_PROVIDER}} KMS)
6. Responses are returned to the customer over the same encrypted channel
7. All data at rest is encrypted with AES-256. All data in transit uses TLS 1.2+.
8. Backups are stored encrypted in a separate region.

### 5. People

| Role | Count | Key Responsibilities |
|------|-------|---------------------|
| Executive Leadership | {{N}} | Strategy, risk acceptance, policy approval, budget |
| Engineering | {{N}} | Product development, code review, infrastructure management |
| Operations / SRE | {{N}} | Monitoring, incident response, on-call, deployments |
| Security | {{N}} | Security controls, compliance, risk management, vulnerability mgmt |
| HR / People Ops | {{N}} | Hiring, onboarding, offboarding, training, background checks |
| Product | {{N}} | Product strategy, requirements |
| Customer Support | {{N}} | Customer-facing support, escalation |

Key personnel:
- CEO: {{CEO}}
- CTO / VP Engineering: {{CTO}}
- Security Lead: {{SECURITY_LEAD}}
- HR Lead: {{HR_LEAD}}
- Compliance Owner: {{COMPLIANCE_OWNER}}

### 6. Sub-Service Organizations

| Vendor | Service | Data Shared | SOC 2 / ISO 27001 | CUECs |
|--------|---------|-------------|--------------------|-----------------------------------------|
| {{CLOUD_PROVIDER}} | Cloud infrastructure | All customer data (encrypted) | SOC 2 Type II | Customer responsible for: IAM config, encryption settings, network security groups, logging |
| [Database provider] | Managed database | Customer data | SOC 2 Type II | Customer responsible for: access controls, encryption config, backup settings |
| [Payment processor] | Payment processing | Payment data | PCI DSS + SOC 2 | Customer responsible for: not storing card numbers, using approved integration |
| [IdP provider] | Identity management | Employee credentials | SOC 2 Type II | Customer responsible for: MFA enforcement, password policies, access reviews |
| [Monitoring provider] | Observability | Application logs (may contain metadata) | SOC 2 Type II | Customer responsible for: not logging PII, retention config |

CUECs = Complementary User Entity Controls (controls the customer is responsible for implementing)

### 7. Trust Services Criteria in Scope

- **Security** (Common Criteria CC1-CC9) -- Required for all SOC 2 reports
- **Availability** (A1) -- [Include if selected. Recommended if you have uptime SLAs.]
- **Confidentiality** (C1) -- [Include if selected. Recommended if you handle sensitive business data.]
- **Processing Integrity** (PI1) -- [Include if selected. Recommended for financial/transaction processing.]
- **Privacy** (P1-P8) -- [Include if selected. Recommended if you process significant PII.]

### 8. Control Environment Summary

{{COMPANY_NAME}} has implemented the following control categories:

- **Access Control:** MFA required for all users via {{IDENTITY_PROVIDER}}. RBAC with least privilege. Quarterly access reviews. Automated onboarding/offboarding.
- **Encryption:** AES-256 at rest on all data stores. TLS 1.2+ in transit. KMS-managed keys with auto-rotation.
- **Logging and Monitoring:** Centralized logging via {{MONITORING}} with 1-year retention. Security alerts for anomalous activity. CloudTrail enabled for all API calls.
- **Incident Response:** Documented IR plan with severity levels and SLAs. Annual tabletop exercise. Post-incident review process.
- **Change Management:** All changes via PR with required code review and CI checks. Branch protection enforced. No direct production access.
- **Risk Management:** Annual risk assessment. Risk register maintained with treatment plans.
- **Vendor Management:** Tiered vendor classification. SOC 2/ISO 27001 required for critical vendors. Annual reviews.
- **Business Continuity:** Automated backups with cross-region storage. DR plan tested annually. RTO 4 hours, RPO 1 hour.
- **People Security:** Background checks for all employees. Security awareness training at onboarding and annually. Offboarding within 24 hours.
- **Endpoint Security:** MDM-managed devices. Disk encryption enforced. EDR on all endpoints.
```

---

### 3.2 Control Matrix with Exact TSC Criteria

This is the most important audit preparation document. It maps every control to the exact Trust Services Criteria text from the AICPA 2017 framework. The auditor uses this as the testing plan.

#### CC1: Control Environment

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC1-01 | Board and management demonstrate commitment to integrity and ethical values through a code of conduct and acceptable use policy signed by all employees | CC1.1 | The entity demonstrates a commitment to integrity and ethical values. | Signed AUP records, employee handbook acknowledgments | {{CEO}} |
| CC1-02 | Board of directors (or equivalent leadership) provides oversight of the security program through quarterly reviews of security metrics and risk status | CC1.2 | The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control. | Board/leadership meeting minutes, security review presentations | {{CEO}} |
| CC1-03 | Management establishes organizational structure with clear lines of authority for security through documented roles and responsibilities | CC1.3 | Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives. | Org chart, RACI matrix, policy ownership table | {{CEO}} |
| CC1-04 | The organization recruits and retains competent personnel through background checks, security training, and performance evaluations | CC1.4 | The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives. | Background check records, training completion records, job descriptions with security requirements | {{HR_LEAD}} |
| CC1-05 | Individuals are held accountable for their security responsibilities through documented policies, training acknowledgments, and disciplinary procedures | CC1.5 | The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives. | Signed AUP, training records, policy violation records, performance reviews | {{HR_LEAD}} |

#### CC2: Communication and Information

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC2-01 | The organization obtains and uses relevant security information through centralized logging ({{MONITORING}}), vulnerability scanning, and threat intelligence | CC2.1 | The entity obtains or generates and uses relevant, quality information to support the functioning of internal control. | Monitoring dashboard configs, log aggregation settings, vulnerability scan reports | {{SECURITY_LEAD}} |
| CC2-02 | Security policies, procedures, and responsibilities are communicated to all personnel through onboarding training, annual refresher training, and policy acknowledgments | CC2.2 | The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control. | Training records, policy acknowledgments, security awareness program materials, internal security communications | {{SECURITY_LEAD}} |
| CC2-03 | Security commitments, system requirements, and data handling practices are communicated to external parties through terms of service, privacy policy, and contractual agreements | CC2.3 | The entity communicates with external parties regarding matters affecting the functioning of internal control. | Terms of service, privacy policy, DPAs, customer-facing security documentation, status page | {{COMPLIANCE_OWNER}} |

#### CC3: Risk Assessment

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC3-01 | The organization defines security objectives aligned with business goals, including confidentiality, integrity, and availability requirements | CC3.1 | The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives. | Information security policy, risk assessment methodology document | {{SECURITY_LEAD}} |
| CC3-02 | A comprehensive risk assessment is conducted annually identifying threats to all assets in scope, assessing likelihood and impact | CC3.2 | The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed. | Annual risk assessment report, risk register | {{SECURITY_LEAD}} |
| CC3-03 | The risk assessment considers the potential for fraud including unauthorized access, data manipulation, and social engineering | CC3.3 | The entity considers the potential for fraud in assessing risks to the achievement of objectives. | Risk register entries for fraud-related risks (insider threat, phishing, credential theft) | {{SECURITY_LEAD}} |
| CC3-04 | The organization identifies and assesses changes that could significantly impact the control environment, triggering reassessment when material changes occur | CC3.4 | The entity identifies and assesses changes that could significantly impact the system of internal control. | Change-triggered reassessment records, risk register updates, new vendor assessments | {{SECURITY_LEAD}} |

#### CC4: Monitoring Activities

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC4-01 | The organization monitors security controls on an ongoing basis through continuous monitoring via compliance platform and automated alerting | CC4.1 | The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning. | Compliance platform dashboard, automated monitoring alerts, quarterly control reviews | {{COMPLIANCE_OWNER}} |
| CC4-02 | Security control deficiencies are identified, communicated to responsible parties, and remediated in a timely manner | CC4.2 | The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate. | Deficiency tracking in ticketing system, remediation records, management reports on open items | {{SECURITY_LEAD}} |

#### CC5: Control Activities

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC5-01 | The organization selects and develops control activities that mitigate risks to acceptable levels, including IT general controls and application controls | CC5.1 | The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels. | Control matrix, risk treatment plans, implemented technical controls | {{SECURITY_LEAD}} |
| CC5-02 | The organization selects and develops technology controls including access controls, encryption, logging, change management, and network security | CC5.2 | The entity also selects and develops general control activities over technology to support the achievement of objectives. | AWS security baseline configs, GitHub branch protection, IdP settings, network configs | {{CTO}} |
| CC5-03 | Control activities are implemented through documented policies and procedures that are communicated to all personnel | CC5.3 | The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action. | All 12 policies (signed and acknowledged), procedure documents, implementation evidence | {{SECURITY_LEAD}} |

#### CC6: Logical and Physical Access Controls

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC6-01 | Logical access security software and infrastructure are implemented to protect against unauthorized access including IdP with SSO, MFA, RBAC, and network segmentation | CC6.1 | The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives. | IdP config (SSO, MFA enforcement), RBAC group definitions, firewall rules, security groups, WAF config | {{SECURITY_LEAD}} |
| CC6-02 | User access is provisioned through a defined process tied to HR onboarding, and deprovisioned within 24 hours of termination. Quarterly access reviews verify continued appropriateness. | CC6.2 | Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity. For those users whose access is administered by the entity, user system credentials are removed when user access is no longer authorized. | Onboarding tickets, offboarding tickets with timestamps, quarterly access review reports | {{HR_LEAD}} |
| CC6-03 | Access to systems is authorized based on the principle of least privilege through RBAC via IdP groups, with no standing admin access to production | CC6.3 | The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties. | IdP group membership exports, production access logs, JIT access records, role change tickets | {{SECURITY_LEAD}} |
| CC6-04 | Physical access to data centers is managed by the cloud provider ({{CLOUD_PROVIDER}}) as documented in their SOC 2 report. Office physical security is managed via badge access. | CC6.4 | The entity restricts physical access to facilities and protected information assets (for example, data center facilities, back-up media storage, and other sensitive locations) to authorized personnel to meet the entity's objectives. | Cloud provider SOC 2 report (sub-service org), office badge access logs (if applicable) | {{COMPLIANCE_OWNER}} |
| CC6-05 | Logical access to information assets is protected through network segmentation (VPC, security groups), encryption, and monitoring | CC6.5 | The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required to meet the entity's objectives. | Data retention and disposal policy, decommissioning records, cryptographic erasure logs | {{CTO}} |
| CC6-06 | Threats to the system boundary are managed through security groups, WAF, DDoS protection, and vulnerability scanning | CC6.6 | The entity implements logical access security measures to protect against threats from sources outside its system boundaries. | Security group configs, WAF rules, DDoS protection config, vulnerability scan results, GuardDuty findings | {{CTO}} |
| CC6-07 | Data is protected in transit (TLS 1.2+) and at rest (AES-256 via KMS) with keys managed through {{CLOUD_PROVIDER}} KMS with automatic rotation | CC6.7 | The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives. | Encryption verification reports, TLS scan results, KMS key configs, S3/RDS/EBS encryption settings | {{CTO}} |
| CC6-08 | Endpoints are managed through MDM ({{MDM}}) with disk encryption enforced, EDR ({{EDR}}) installed, and OS update policies applied | CC6.8 | The entity implements controls to prevent or detect and act on the introduction of unauthorized or malicious software to meet the entity's objectives. | MDM device inventory and compliance reports, EDR deployment status, endpoint encryption status | {{SECURITY_LEAD}} |

#### CC7: System Operations

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC7-01 | Security events are detected through centralized monitoring ({{MONITORING}}), CloudTrail logging, GuardDuty threat detection, and EDR alerts | CC7.1 | To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities. | Monitoring config, CloudTrail settings, GuardDuty config, EDR config, vulnerability scanner config | {{CTO}} |
| CC7-02 | Security events are analyzed using automated alerting rules, log correlation, and manual investigation procedures to determine if they constitute incidents | CC7.2 | The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events. | Alert rules and thresholds, CloudWatch alarms, GuardDuty findings, alert response records | {{SECURITY_LEAD}} |
| CC7-03 | Security incidents are responded to according to the documented IR plan with defined severity levels, response SLAs, and communication procedures | CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures. | IR policy, incident tickets, response timeline records, communication logs | {{SECURITY_LEAD}} |
| CC7-04 | Incidents are fully remediated through root cause analysis, containment, eradication, and recovery, with findings documented in post-incident reviews | CC7.4 | The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate. | Post-incident review documents, remediation action items and completion records | {{SECURITY_LEAD}} |
| CC7-05 | Lessons learned from security incidents are incorporated into the control environment through updated procedures, additional controls, and training | CC7.5 | The entity identifies, develops, and implements activities to recover from identified security incidents. | Post-incident action items, control improvements implemented, training updates, risk register updates | {{SECURITY_LEAD}} |

#### CC8: Change Management

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC8-01 | All changes to production systems follow a defined change management process: PR with code review, CI checks (automated tests, linting, security scanning), approval, and automated deployment | CC8.1 | The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives. | Branch protection config, sample PRs with reviews and CI status, change management evidence reports, deployment logs | {{CTO}} |

#### CC9: Risk Mitigation

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| CC9-01 | Identified risks are mitigated through a combination of technical controls, administrative controls, and risk transfer (insurance) | CC9.1 | The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions. | Risk register with treatment plans, cyber insurance policy, technical control implementations | {{SECURITY_LEAD}} |
| CC9-02 | Vendor risk is managed through a tiered vendor management program requiring SOC 2/ISO 27001 for critical vendors, DPAs, and annual reviews | CC9.2 | The entity assesses and manages risks associated with vendors and business partners. | Vendor register, vendor assessment records, SOC 2 reports on file, DPAs, annual review records | {{COMPLIANCE_OWNER}} |

#### A1: Availability (if in scope)

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| A1-01 | The system is designed for availability through multi-AZ deployment, auto-scaling, load balancing, and health monitoring with defined RTO (4h) and RPO (1h) | A1.1 | The entity maintains, monitors, and evaluates current processing capacity and use of system components (infrastructure, data, and software) to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives. | Infrastructure architecture diagrams, auto-scaling configs, load balancer health checks, capacity monitoring dashboards | {{CTO}} |
| A1-02 | Data is protected through automated backups (daily snapshots, continuous WAL archiving) stored in a separate region with 90-day retention | A1.2 | The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure to meet its objectives. | Backup configs, backup verification reports, cross-region replication configs, restore test results | {{CTO}} |
| A1-03 | Recovery procedures are documented in a DR plan and tested annually through backup restore tests and failover exercises | A1.3 | The entity tests recovery plan procedures supporting system recovery to meet its objectives. | DR plan document, DR test results with recovery times, backup restore test records | {{CTO}} |

#### C1: Confidentiality (if in scope)

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| C1-01 | Confidential information is identified and classified according to the data classification policy (Restricted, Confidential, Internal, Public) | C1.1 | The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality. | Data classification policy, data inventory, classification labels in systems | {{SECURITY_LEAD}} |
| C1-02 | Confidential information is disposed of securely according to the data retention schedule using cryptographic erasure or secure deletion | C1.2 | The entity disposes of confidential information to meet the entity's objectives related to confidentiality. | Data retention policy, deletion records, customer data deletion confirmations, backup expiration logs | {{COMPLIANCE_OWNER}} |

#### PI1: Processing Integrity (if in scope)

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| PI1-01 | Processing objectives are defined including completeness, accuracy, timeliness, and authorization of system processing | PI1.1 | The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing, including definitions of data processed and product and service specifications, to support the use of products and services. | System specifications, API documentation, data processing definitions | {{CTO}} |
| PI1-02 | System inputs are validated for completeness, accuracy, and authorization through input validation, schema enforcement, and authentication | PI1.2 | The entity implements policies and procedures over system inputs, including controls over completeness and accuracy, to result in products, services, and reporting to meet the entity's objectives. | Input validation code, API schema definitions, authentication enforcement, sample validation logs | {{CTO}} |
| PI1-03 | System processing is monitored for completeness, accuracy, and timeliness through automated tests, checksums, and reconciliation processes | PI1.3 | The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives. | Processing monitoring dashboards, reconciliation reports, error handling logs | {{CTO}} |
| PI1-04 | System outputs are reviewed and delivered to intended parties through secure channels with appropriate access controls | PI1.4 | The entity implements policies and procedures to make available or deliver output completely, accurately, and timely in accordance with specifications to meet the entity's objectives. | Output delivery logs, access control records, data export audit trails | {{CTO}} |
| PI1-05 | Data in storage is protected to maintain completeness, accuracy, and validity through encryption, checksums, and access controls | PI1.5 | The entity implements policies and procedures to store inputs, items in processing, and outputs completely, accurately, and timely in accordance with system specifications to meet the entity's objectives. | Database integrity checks, storage encryption configs, data validation procedures | {{CTO}} |

#### P1-P8: Privacy (if in scope)

| Control ID | Control Description | TSC Criteria | Criteria Text | Evidence Source | Owner |
|-----------|-------------------|-------------|---------------|-----------------|-------|
| P1-01 | Privacy notice describes the entity's privacy practices including data collection, use, retention, disclosure, and individual rights | P1.0 | The entity provides notice to data subjects about its privacy practices to meet the entity's objectives related to privacy. | Published privacy policy, in-app consent notices, cookie banner | {{COMPLIANCE_OWNER}} |
| P2-01 | The entity obtains consent from data subjects for collection, use, and sharing of personal information where required | P2.0 | The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information to the data subjects to meet the entity's objectives related to privacy. | Consent collection mechanisms, opt-in/opt-out records, preference management | {{COMPLIANCE_OWNER}} |
| P3-01 | Personal information is collected only for identified purposes through defined data collection forms and APIs with explicit consent | P3.0 | The entity collects personal information only for the purposes identified in the notice to meet the entity's objectives related to privacy. | Data collection audit, purpose limitation documentation, collection points inventory | {{COMPLIANCE_OWNER}} |
| P4-01 | Personal information is used only for purposes identified in the privacy notice and with consent of the data subject | P4.0 | The entity limits the use of personal information to the purposes identified in the notice and for which the data subject has provided implicit or explicit consent to meet the entity's objectives related to privacy. | Data processing records, use limitation documentation | {{COMPLIANCE_OWNER}} |
| P5-01 | Personal information is retained only for the period necessary to fulfill the stated purposes and then securely disposed | P5.0 | The entity retains personal information for only as long as necessary to fulfill the stated purposes, unless the law requires otherwise, to meet the entity's objectives related to privacy. | Data retention schedule, automated deletion records, retention audit | {{COMPLIANCE_OWNER}} |
| P6-01 | Personal information is disclosed to third parties only for identified purposes, with consent, and under appropriate agreements (DPAs) | P6.0 | The entity discloses personal information to third parties only for the purposes identified in the notice and with the implicit or explicit consent of the data subject to meet the entity's objectives related to privacy. | Third-party data sharing agreements, DPAs, consent records, vendor register | {{COMPLIANCE_OWNER}} |
| P7-01 | The entity maintains accurate personal information and provides mechanisms for data subjects to review, update, and correct their data | P7.0 | The entity collects and maintains accurate, up-to-date, complete, and relevant personal information for the purposes identified in the notice to meet the entity's objectives related to privacy. | Data quality procedures, self-service data management features, correction request logs | {{COMPLIANCE_OWNER}} |
| P8-01 | The entity provides data subjects with access to their personal information for review and the ability to request deletion, and handles complaints and disputes | P8.1 | The entity implements a process for receiving, addressing, resolving, and communicating the resolution of inquiries, complaints, and disputes from data subjects and others and periodically monitors compliance to meet the entity's objectives related to privacy. | Data subject request log, complaint resolution records, DSAR procedures, response time tracking | {{COMPLIANCE_OWNER}} |

---

### 3.3 Auditor Interview Preparation

Prepare each interviewee with specific answers that reference your actual tools and processes. Do not memorize scripts word-for-word; understand the substance so you can answer naturally.

#### CTO / VP Engineering Interview Prep

**Q1: "Walk me through how a code change gets to production."**

> A developer creates a feature branch from main in {{SOURCE_CONTROL}}. They write code and tests, then open a pull request. Our CI pipeline ({{CI_CD}}) runs automatically on the PR: unit tests, integration tests, linting, static analysis, and dependency vulnerability scanning. The PR requires at least one approving review from a peer who is not the author. All CI checks must pass before merge is allowed — this is enforced via branch protection rules that even admins cannot bypass. Once approved and green, the developer merges to main. The merge triggers our deployment pipeline which first deploys to staging for verification, then promotes to production. We verify the deployment with automated smoke tests and monitoring checks. If anything fails, we have a documented rollback procedure.

**Q2: "How do you manage access to production systems?"**

> We use role-based access control via {{IDENTITY_PROVIDER}} with SSO. All access requires MFA — we enforce authenticator apps, no SMS. We have defined groups: engineering gets access to source control, staging, and CI/CD. Only senior engineers and on-call personnel get production read access through the engineering-production group. Production write access (database admin, infrastructure changes) requires just-in-time elevation with approval and is time-limited. There are no shared admin credentials — every admin has an individual account. We conduct quarterly access reviews where {{SECURITY_LEAD}} and each team lead verify every user's access is still appropriate. We remove access for anyone who doesn't need it and document the review with sign-off.

**Q3: "What happens if a critical vulnerability is discovered in production?"**

> Our vulnerability scanning (Dependabot / Snyk / Trivy) runs continuously. When a critical CVE is found in a production dependency, it creates an alert in {{MONITORING}} and a ticket in {{TICKETING}}. Our SLA for critical vulnerabilities is patch within 48 hours. The responsible engineer creates a fix, which goes through the normal PR process — but we treat it as high priority. If the vulnerability is actively exploited, we use our emergency change process: the on-call engineer can expedite the fix through an accelerated review, but it still goes through CI and automated deployment. The fix must be retroactively reviewed within 24 hours. We document the vulnerability, the fix, and the timeline in the ticket.

**Q4: "How are backups managed and tested?"**

> Our production database ({{DB_TYPE}}) has automated continuous backups — we use point-in-time recovery with automated snapshots. Backup retention is 90 days. Snapshots are stored in a different region from production, encrypted with KMS. Our S3 buckets with critical data have cross-region replication enabled. We test backup restoration quarterly: we restore from a recent backup to a separate test environment, verify data integrity, and measure recovery time against our RTO of 4 hours and RPO of 1 hour. We document the test results including actual recovery time and any issues found.

**Q5: "How do you handle infrastructure changes?"**

> All infrastructure is defined as code using Terraform (or Pulumi/CloudFormation). Infrastructure changes follow the same PR process as application code changes: branch, PR, peer review, CI checks (including terraform plan output review), approval, then merge and apply. No manual changes are made in the cloud console under normal operations. If a manual change is absolutely necessary during an emergency, it must be documented and codified in IaC within 24 hours.

**Q6: "How do you manage secrets and credentials?"**

> All secrets are stored in {{CLOUD_PROVIDER}} Secrets Manager (or SSM Parameter Store / HashiCorp Vault). We never put secrets in source code, environment variables in plain text, or configuration files. We have GitHub secret scanning enabled with push protection — it blocks commits that contain secrets. We use service accounts with IAM roles where possible instead of static credentials. Where API keys are necessary, they are rotated on a defined schedule. If a secret is compromised, we rotate it immediately as part of our incident response.

**Q7: "What monitoring do you have in place?"**

> We use {{MONITORING}} for application and infrastructure monitoring. CloudTrail captures all AWS API calls. GuardDuty provides threat detection. We have CloudWatch alarms for security events: unauthorized API calls, root account usage, security group changes, and IAM policy changes. All logs are retained for 1 year minimum. Our on-call engineer is paged through PagerDuty (or equivalent) for critical alerts. We review alert patterns quarterly and tune thresholds to reduce noise.

**Q8: "Describe your network security architecture."**

> Our production environment runs in a VPC with private subnets for application servers and databases. Public access goes through a load balancer in public subnets. Security groups restrict traffic to only what is necessary — no 0.0.0.0/0 ingress on production resources except through the load balancer on ports 80/443. We have VPC flow logs enabled for network traffic analysis. Our WAF (if applicable) provides protection against common web attacks. We use a CDN (CloudFront / Cloudflare) for DDoS protection on public endpoints.

#### Security Lead Interview Prep

**Q1: "Describe your incident response process."**

> We have a documented IR policy with four severity levels. Let me walk through a P1 — say we detect unauthorized access to a production system. The first responder pages the Incident Commander (me, or {{CTO}} as backup) within 15 minutes. I assess the situation, create an incident ticket in {{TICKETING}}, and assemble the response team: myself as IC, the on-call engineer as technical lead, and a scribe to document everything in real-time. We immediately contain — revoke the compromised credentials, isolate affected systems, preserve evidence. We investigate using CloudTrail logs, application logs in {{MONITORING}}, and GuardDuty findings to determine scope: what was accessed, when it started, how the attacker got in. We remediate the root cause, rotate any compromised credentials, and restore from clean state if needed. If customer data was affected, we notify our CEO for customer communication within 72 hours. After resolution, we conduct a blameless post-mortem within 5 business days, document lessons learned, and create action items to prevent recurrence.

**Q2: "How do you monitor for security events?"**

> We have multiple layers. {{MONITORING}} aggregates all application and infrastructure logs with a 1-year retention. CloudTrail records every AWS API call. We have CloudWatch metric filters and alarms for critical security events: unauthorized API calls (threshold of 5 in 5 minutes), any root account usage, changes to IAM policies, changes to security groups, and console logins without MFA. GuardDuty runs continuously for threat detection — compromised instances, cryptocurrency mining, brute force attacks. Our EDR ({{EDR}}) provides endpoint-level threat detection. All critical alerts page the on-call engineer via PagerDuty. We review and tune alert thresholds quarterly.

**Q3: "How do you assess and manage risk?"**

> We conduct a formal risk assessment annually in Q1. We start by inventorying all assets in scope: production infrastructure, customer data stores, corporate systems, endpoints, and third-party services. For each asset, we identify applicable threats using a standard threat catalog. We assess each risk on likelihood (high/medium/low) and impact (high/medium/low) to produce a risk score. Each risk gets a treatment decision: mitigate, accept, transfer, or avoid. Accepted risks require explicit sign-off from {{CEO}}. We maintain a risk register with treatment plans, owners, and target dates. The register is reviewed quarterly and updated when material changes occur — like adding a new cloud region, onboarding a critical vendor, or after a security incident.

**Q4: "How do you manage vendor security?"**

> We classify vendors into three tiers: critical (processes or stores customer data), important (accesses internal data), and standard (no sensitive data access). Before onboarding a critical or important vendor, we require a current SOC 2 Type II report or ISO 27001 certificate. If they have neither, we send a security questionnaire covering encryption, MFA, IR, breach notification, pen testing, and sub-processors. We require a Data Processing Agreement with breach notification within 72 hours. Critical vendors need approval from both {{CTO}} and me. We review all critical and important vendors annually: request updated SOC 2 reports, check for exceptions or findings, verify they still meet our requirements. Everything is tracked in our vendor register.

**Q5: "Walk me through your vulnerability management process."**

> We scan at multiple levels. Dependabot (or Snyk) scans code dependencies continuously and opens PRs for vulnerable packages. Our CI pipeline includes container image scanning. We run infrastructure vulnerability scans using Prowler (or equivalent) weekly against our AWS accounts. We engage an external firm for annual penetration testing. Vulnerabilities are triaged by severity: critical must be patched within 48 hours, high within 7 days, medium within 30 days, low within 90 days. Each finding is tracked in {{TICKETING}} with an owner and deadline. We report vulnerability metrics (open count by severity, time to remediate) quarterly.

**Q6: "How do you handle encryption key management?"**

> All encryption keys are managed through {{CLOUD_PROVIDER}} KMS. We use separate CMKs (customer-managed keys) for different purposes: one for CloudTrail logs, one for database encryption, one for S3 data. Automatic key rotation is enabled on all CMKs. Key access is restricted to specific IAM roles — application services can use the keys for encrypt/decrypt but cannot manage them. Key administration (create, delete, policy changes) is restricted to the admin role. All key usage is logged and auditable through CloudTrail. We verify key rotation status as part of our quarterly encryption verification.

**Q7: "What is your security awareness training program?"**

> All new employees complete security awareness training within 7 days of hire as part of onboarding. The training covers phishing identification, password hygiene and MFA, data classification, incident reporting, acceptable use, and social engineering awareness. We use [KnowBe4/Curricula/equivalent] for training delivery. All employees complete annual refresher training. We run quarterly phishing simulations — employees who click receive immediate feedback and additional training. Training completion is tracked automatically and reported to compliance. Current completion rate is tracked in our compliance platform.

**Q8: "Have you had any security incidents in the audit period?"**

> [If yes]: We had [N] incidents during the audit period. [Briefly describe each with severity, scope, and resolution.] Post-incident reviews were conducted for each, and action items were completed. I can provide the post-mortem documents.
>
> [If no]: We had no security incidents during the audit period. We did conduct a tabletop exercise in [month] to test our IR process. The exercise identified [N] improvements which we implemented.

#### HR Lead Interview Prep

**Q1: "Walk me through the employee onboarding process."**

> When a new hire starts, we follow a documented onboarding checklist tracked in {{TICKETING}}. First, the background check must be completed and cleared before their start date — we use [Checkr/GoodHire/equivalent] for identity verification, criminal record, and employment history. On day one, I create their account in {{IDENTITY_PROVIDER}} and add them to the appropriate groups based on their role. They set up MFA — we require authenticator app or hardware key, not SMS. Their device is enrolled in {{MDM}} for management. They get a {{PASSWORD_MANAGER}} account. They sign the Acceptable Use Policy and confidentiality agreement, and acknowledge the employee handbook. They have 7 days to complete security awareness training. The onboarding ticket tracks all of these items and is not closed until every step is confirmed complete.

**Q2: "What happens when an employee leaves the company?"**

> We have a documented offboarding process, also tracked in {{TICKETING}}. For voluntary departures, access must be revoked by end of their last working day. For involuntary terminations, access is revoked within 1 hour of notification. The process: I notify {{SECURITY_LEAD}} of the departure. The employee's account is disabled in {{IDENTITY_PROVIDER}}, which cascades to all SSO-connected applications. Their personal API keys and tokens are revoked. They are removed from the {{SOURCE_CONTROL}} organization and {{COMMUNICATION_TOOL}} workspace. Their company device is retrieved and remotely wiped via {{MDM}}. If they had access to any shared credentials, those are rotated. We conduct an exit interview. The offboarding ticket is closed with confirmation of every step. We verify no residual access remains.

**Q3: "How is security training managed?"**

> Security awareness training is mandatory for everyone. New hires must complete it within 7 days of their start date — this is tracked in the onboarding checklist. Annual refresher training is required and tracked through [KnowBe4/Curricula/equivalent]. I receive a monthly report of completion status. If someone is past due, they get automated reminders and I follow up personally. We also run quarterly phishing simulations — employees who click get additional targeted training. Completion certificates are retained as evidence. Current completion rate across the company is tracked and reported to leadership.

**Q4: "How do you handle background checks?"**

> Background checks are required for all employees before their start date — the offer is contingent on satisfactory results. We use [Checkr/GoodHire/equivalent] for identity verification, criminal record check, and employment history verification. For contractors, equivalent checks are required before we grant system access. Results are reviewed by me and retained securely in our HR system. We maintain a log of all background checks with dates and results.

**Q5: "How do you ensure all employees have signed the required policies?"**

> As part of onboarding, every employee signs the Acceptable Use Policy, confidentiality/NDA agreement, and acknowledges the employee handbook. These are collected electronically and stored in our HR system. We require annual re-acknowledgment of the Acceptable Use Policy. I track who has and hasn't signed through our compliance platform. If someone misses the annual acknowledgment, they get reminders and I escalate to their manager.

**Q6: "How are role changes handled?"**

> When an employee changes roles, their manager submits an access change request through {{TICKETING}}. {{SECURITY_LEAD}} or {{CTO}} approves the change. The employee is moved to the appropriate groups in {{IDENTITY_PROVIDER}} for their new role, and their previous role-specific access is removed. The change is documented in the ticket. This is also verified in our quarterly access reviews.

---

### 3.4 Management Assertion Letter Template

This letter is signed by management and included with the SOC 2 report. It asserts that the system description and controls are fairly presented.

```markdown
# Management Assertion Letter

[Date]

[Audit Firm Name]
[Audit Firm Address]

Re: Management's Assertion Regarding {{COMPANY_NAME}}'s [Product/Service Name]
System for the Period [Start Date] through [End Date]

Dear [Audit Partner Name]:

We are responsible for the assertion set forth below regarding the fairness
of the presentation of the description of {{COMPANY_NAME}}'s [Product/Service
Name] system ("the System") and the suitability of the design and operating
effectiveness of the controls described therein.

## Assertion

We assert that:

(a) The accompanying description of the System, entitled "System Description —
{{COMPANY_NAME}}," dated [date], fairly presents the System that was designed
and implemented throughout the period [Start Date] to [End Date], based on the
criteria for a description of a service organization's system set forth in
DC section 200, 2018 Description Criteria for a Description of a Service
Organization's System in a SOC 2 Report (AICPA, Description Criteria).
The description includes:

   i. The types of services provided
   ii. The components of the system used to provide the services
   iii. The boundaries of the system
   iv. The applicable trust services criteria and related controls
   v. Complementary user entity controls
   vi. Complementary subservice organization controls

(b) The controls stated in the description were suitably designed and operated
effectively throughout the period [Start Date] to [End Date] to meet the
applicable trust services criteria set forth in TSP section 100, 2017 Trust
Services Criteria for Security, Availability, Processing Integrity,
Confidentiality, and Privacy (AICPA, Trust Services Criteria), for the
following categories:

   - Security (Common Criteria)
   - Availability [if in scope]
   - Confidentiality [if in scope]
   - Processing Integrity [if in scope]
   - Privacy [if in scope]

## Inherent Limitations

Because of their nature, controls may not prevent, or detect and correct,
all misstatements, errors, or omissions. Furthermore, the projection of any
conclusions to future periods is subject to the risk that changes may alter
the validity of such conclusions.

## Basis for Assertion

{{COMPANY_NAME}}'s assertion is based on the criteria described above. We have
assessed the design and operating effectiveness of controls throughout the period
[Start Date] to [End Date] using these criteria.

Sincerely,

________________________________          ________________________________
{{CEO}}                                   {{CTO}}
Chief Executive Officer                   Chief Technology Officer
{{COMPANY_NAME}}                          {{COMPANY_NAME}}

Date: ________________________            Date: ________________________


________________________________
{{SECURITY_LEAD}}
[Security Lead Title]
{{COMPANY_NAME}}

Date: ________________________
```

**Requirements:**
- Must be signed by at least two members of senior management (CEO + CTO/CISO)
- Must be dated within 30 days of audit report issuance
- Must specify the exact audit period
- Must list the exact TSC categories in scope
- Must reference the specific system description document

---

## Part 4: Ongoing Operations

### 4.1 Annual Compliance Calendar

| Month | Tasks | Owner | Evidence Produced |
|-------|-------|-------|-------------------|
| January | Annual risk assessment. Review and update risk register. Update risk treatment plans. Present risk status to leadership. | {{SECURITY_LEAD}} | Risk assessment report, updated risk register, leadership sign-off |
| February | Annual policy review. Update all 12 policies for changes in tools, processes, or personnel. Get leadership sign-off on each policy. | {{SECURITY_LEAD}} | Updated policies with version history, leadership sign-off records |
| March | Q1 access review (run access-review.sh). Engage penetration test vendor. Scope and schedule pen test. | {{SECURITY_LEAD}} | Q1 access review report, pen test engagement letter |
| April | Security awareness training campaign. Send annual training to all employees. Run phishing simulation. Track completions. | {{HR_LEAD}} | Training completion records, phishing simulation results |
| May | Vendor review: reassess all critical and important vendors. Request updated SOC 2 reports. Review for exceptions. Update vendor register. | {{COMPLIANCE_OWNER}} | Updated vendor register, vendor SOC 2 reports on file, review notes |
| June | Q2 access review. DR test: conduct backup restore test or failover exercise. Document results including actual recovery time. | {{SECURITY_LEAD}}, {{CTO}} | Q2 access review report, DR test results |
| July | Incident response tabletop exercise. Simulate a realistic scenario (e.g., phishing leading to credential compromise). Document findings and improvements. | {{SECURITY_LEAD}} | Tabletop exercise report, action items |
| August | Mid-year compliance check. Verify all controls are functioning. Check compliance platform for failing tests. Address any gaps. Run Prowler/ScoutSuite scan. | {{COMPLIANCE_OWNER}} | Mid-year compliance status report, scan results, remediation records |
| September | Q3 access review. Engage auditor for Type II audit. Confirm audit timeline, scope, and logistics. | {{SECURITY_LEAD}}, {{COMPLIANCE_OWNER}} | Q3 access review report, auditor engagement letter |
| October | Audit preparation. Gather all evidence. Update system description. Prepare interviewees. Run all evidence scripts. Compile and organize evidence package. | {{COMPLIANCE_OWNER}} | Complete evidence package, updated system description, interview prep materials |
| November | Audit fieldwork (typical window -- adjust to your schedule). Support auditor with evidence requests, interviews, and walkthroughs. Address any findings promptly. | {{COMPLIANCE_OWNER}} | Auditor evidence requests fulfilled, interview records |
| December | Q4 access review. Receive audit report. Review any exceptions or findings. Plan next year's compliance calendar. Renew pen test engagement. | {{COMPLIANCE_OWNER}}, {{SECURITY_LEAD}} | Q4 access review report, SOC 2 report, next year's compliance plan |

---

### 4.2 Change-Triggered Reassessment

These events require re-evaluation of controls and documentation updates. Do not wait for the annual cycle.

| Trigger Event | What to Reassess | Action Required |
|--------------|-----------------|-----------------|
| New cloud account or region | Risk assessment, system description, encryption configs, monitoring coverage, network security | Run infrastructure discovery, update system description, extend monitoring and alerting, verify encryption defaults, update control matrix |
| New product or feature handling customer data | Risk assessment, data flow, privacy controls, access controls | Update data flow diagram, assess new data handling risks, verify encryption and access controls, update privacy notice if needed |
| Acquisition or merger | Everything: all policies, risk assessment, system description, vendor register, access controls | Full reassessment within 90 days. Extend security controls to acquired systems. Consolidate identity management. Update system boundaries. |
| Critical vendor change | Vendor risk assessment, system description, data flow, DPA | Assess new vendor security posture (SOC 2/ISO 27001), execute DPA, update vendor register, update system description |
| Security incident (P1 or P2) | Risk assessment, affected controls, monitoring coverage | Post-incident review, update risk register, implement additional controls as needed, update detection rules |
| Major organizational restructure | Access controls, roles and responsibilities, policy ownership | Review and update RBAC groups, update policy ownership, conduct out-of-cycle access review |
| Regulatory change affecting the business | All affected policies, risk assessment, controls | Legal review, gap assessment against new requirements, update policies and controls, document compliance approach |
| Employee count doubles | Access control scalability, training program, policy distribution | Review if current tools scale, consider compliance platform upgrade, update org chart and responsibility matrix |

---

### 4.3 Common Audit Exceptions and Prevention

The top 10 most common exceptions found by SOC 2 auditors, ranked by frequency, with specific prevention measures.

#### 1. Late Deprovisioning (68% of qualified opinions)

**The exception:** An employee left the company and their access was not revoked within the policy-defined timeframe (24 hours for voluntary, 1 hour for involuntary).

**Root cause:** Manual offboarding process, HR does not notify IT in time, SSO does not cascade to all apps.

**Prevention:**
- Automate deprovisioning with SCIM provisioning between HR system and IdP. When HR marks an employee as terminated, IdP disables the account automatically.
- If SCIM is not available: create a webhook or scheduled sync between HR system and IdP.
- Configure IdP to cascade disable to all connected SSO applications.
- Set up compliance platform alert for any user disabled in HR but still active in IdP after 24 hours.
- Have offboarding runbook in {{TICKETING}} that auto-creates when HR processes a termination.

```bash
# example: check for users disabled in IdP but still active in GitHub
# run weekly as a safety net
DISABLED_USERS=$(curl -s -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  "${OKTA_ORG_URL}/api/v1/users?filter=status+eq+%22DEPROVISIONED%22" | \
  jq -r '.[].profile.email')

for email in $DISABLED_USERS; do
  github_user=$(echo "$email" | cut -d@ -f1)
  if gh api "orgs/${GITHUB_ORG}/members/${github_user}" --silent 2>/dev/null; then
    echo "WARNING: ${email} is deprovisioned in Okta but still active in GitHub"
  fi
done
```

#### 2. Missed Access Reviews (52% of exceptions)

**The exception:** Quarterly access reviews were not conducted on time, or were incomplete (not all systems reviewed, no sign-off).

**Prevention:**
- Schedule access reviews as recurring calendar events with 2-week lead time.
- Use compliance platform automated reminders (Vanta/Drata/etc. track this).
- Automate evidence generation with access-review.sh (Section 1.2).
- Assign specific owner and due date for each quarterly review.
- If using a compliance platform, set it to alert when review is overdue.

#### 3. Missing Code Review Approvals (45% of exceptions)

**The exception:** PRs were merged to main without an approving review, or the author approved their own PR.

**Prevention:**
- Enable branch protection on main requiring at least 1 approving review.
- Enable "Dismiss stale reviews when new commits are pushed."
- Enable "Restrict who can push to matching branches."
- Set "Do not allow bypassing the above settings" — this prevents even org admins from bypassing.
- Run change-evidence.sh quarterly to catch any exceptions early.

```bash
# verify branch protection is correctly configured
gh api "repos/{{ORG}}/{{REPO}}/branches/main/protection" --jq '{
  required_reviews: .required_pull_request_reviews.required_approving_review_count,
  dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
  enforce_admins: .enforce_admins.enabled,
  force_push: .allow_force_pushes.enabled
}'
```

#### 4. Incomplete Evidence Documentation (40% of exceptions)

**The exception:** Controls exist but evidence is missing, outdated, or insufficient.

**Prevention:**
- Automate evidence collection with the scripts in Part 1.
- Use a compliance platform that continuously collects evidence.
- Schedule evidence runs as cron jobs or CI/CD pipeline steps.
- Maintain the evidence folder structure from Section 2.5.

```bash
# cron job to auto-generate quarterly evidence (add to crontab)
# runs on the 1st of Jan, Apr, Jul, Oct at 9am
0 9 1 1,4,7,10 * /path/to/access-review.sh && /path/to/verify-encryption.sh && /path/to/change-evidence.sh $(date -d "-3 months" +%Y-%m-%d) $(date +%Y-%m-%d) && /path/to/verify-backups.sh
```

#### 5. Stale Risk Assessment (35% of exceptions)

**The exception:** Risk assessment has not been updated in over 12 months, or does not reflect current infrastructure.

**Prevention:**
- Schedule annual risk assessment in Q1 as a non-negotiable calendar event.
- Implement change-triggered reassessment (Section 4.2) so the risk register stays current.
- Review risk register quarterly as part of access review meetings.
- Track risk register last-updated date in compliance platform.

#### 6. Missing Security Training Records (30% of exceptions)

**The exception:** Not all employees completed security training, or completion records are missing.

**Prevention:**
- Use a training platform (KnowBe4, Curricula, etc.) that tracks completion automatically.
- Set up automated reminders: 7-day, 14-day, 21-day after assignment.
- Escalate to manager after 21 days past due.
- Include training completion in onboarding checklist (not closed until training is done).
- Export completion records monthly to evidence folder.

#### 7. Unencrypted Data Stores (25% of exceptions)

**The exception:** An S3 bucket, EBS volume, or RDS instance is found without encryption.

**Prevention:**
- Enable EBS encryption by default at the account level.
- Use AWS Config rules to detect and auto-remediate unencrypted resources.
- Run verify-encryption.sh quarterly.
- Use SCP (Service Control Policy) to deny creation of unencrypted resources.

```bash
# enable EBS encryption by default
aws ec2 enable-ebs-encryption-by-default

# AWS Config rule for S3 bucket encryption
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
}'
```

#### 8. No Penetration Test (22% of exceptions)

**The exception:** No external penetration test was conducted during the audit period.

**Prevention:**
- Engage a pen test vendor annually. Schedule in March, complete by May (before June DR test).
- Budget $10K-$30K depending on scope.
- Retain the executive summary and remediation evidence.
- Track remediation of findings in {{TICKETING}} with deadlines.

#### 9. Missing DR Test (20% of exceptions)

**The exception:** The DR plan exists but was never tested during the audit period.

**Prevention:**
- Schedule annual DR test in June. At minimum, test backup restoration.
- Document: what was tested, recovery time achieved (vs. RTO target), data integrity verified (vs. RPO target), issues found, action items.
- File results as evidence/dr/dr-test-results-YYYY.md.

#### 10. Vendor Without Current SOC 2 / ISO 27001 (18% of exceptions)

**The exception:** A critical vendor does not have a current (within 12 months) SOC 2 Type II report or ISO 27001 certificate.

**Prevention:**
- Maintain vendor register with next-review dates.
- Set compliance platform reminders 60 days before each vendor's report expires.
- During annual vendor review (May), request updated reports.
- If a vendor cannot provide SOC 2 or ISO 27001, complete the vendor security questionnaire and document the compensating controls assessment.

---

## Part 5: Quick Reference Tables

### 5.1 Cost Summary by Company Size

| Company Size | Compliance Platform | Auditor (Type II) | Pen Test | Training Platform | Other Tools | First Year Total | Ongoing Annual |
|-------------|--------------------|--------------------|----------|-------------------|-------------|------------------|----------------|
| Startup (5-25 employees) | $5K-$12K | $20K-$35K | $10K-$15K | $2K-$5K | $5K-$10K | $45K-$65K | $25K-$40K |
| Mid-size (25-100 employees) | $10K-$20K | $30K-$50K | $15K-$25K | $5K-$10K | $10K-$20K | $65K-$110K | $40K-$65K |
| Larger (100-500 employees) | $15K-$25K | $45K-$80K | $20K-$35K | $10K-$20K | $15K-$30K | $100K-$200K | $60K-$120K |

"Other tools" includes MDM, EDR, password manager, vulnerability scanner, secret scanning, and training content.

### 5.2 Timeline Summary

| Path | Calendar Time | Effort Required | Best For |
|------|--------------|-----------------|----------|
| Type I (point-in-time) | 3-6 months | 200-400 hours | Companies needing a report fast to close a deal. Must follow with Type II. |
| Type I then Type II | 9-18 months total | 400-700 hours | Conservative approach. Type I proves design, then observe 3-6 months for Type II. |
| Straight to Type II | 6-15 months | 350-600 hours | Recommended. Implement controls, observe for 3-6 months, then audit. Saves the cost of a separate Type I audit. |

### 5.3 Compliance Platform Comparison

| Feature | Vanta | Drata | Secureframe | Sprinto |
|---------|-------|-------|-------------|---------|
| Price range | $10K-$25K/yr | $8K-$20K/yr | $12K-$20K/yr | $5K-$10K/yr |
| Integrations | 300+ | 200+ | 200+ | 150+ |
| Built-in training | No (partner integrations) | Yes | Yes | Yes |
| Policy templates | Yes | Yes | Yes (AI-assisted) | Yes |
| Auditor network | Largest | Large | Medium | Medium |
| Continuous monitoring | Yes | Yes | Yes | Yes |
| API for custom evidence | Yes | Yes | Yes | Limited |
| Multi-framework support | SOC 2, ISO 27001, HIPAA, PCI, GDPR, more | SOC 2, ISO 27001, HIPAA, PCI, GDPR, more | SOC 2, ISO 27001, HIPAA, PCI, GDPR | SOC 2, ISO 27001, HIPAA, GDPR |
| Best for | Most integrations, largest companies | Cleanest UX, guided onboarding | Advisory support, first-timers | Startups, budget-conscious |

### 5.4 SOC 2 vs Other Frameworks

| Aspect | SOC 2 | ISO 27001 | HIPAA | PCI DSS | GDPR |
|--------|-------|-----------|-------|---------|------|
| Type | Attestation report | Certification | Regulation (US) | Standard (payment industry) | Regulation (EU) |
| Issuer | CPA firm | Accredited certification body | Self-assessed + HHS enforcement | QSA (Qualified Security Assessor) | Self-assessed + DPA enforcement |
| Scope | Your system and controls | Your ISMS (Information Security Management System) | Protected Health Information (PHI) | Cardholder data environment | Personal data of EU residents |
| Mandatory? | No (market-driven) | No (market-driven) | Yes (if handling PHI) | Yes (if processing card payments) | Yes (if processing EU personal data) |
| Validity | 12-month observation period | 3-year certificate with annual surveillance | Ongoing | Annual assessment | Ongoing |
| Cost (typical) | $45K-$110K first year | $30K-$80K first year | $20K-$60K (gap assessment + remediation) | $50K-$200K+ (depends on scope) | $20K-$100K (DPO + assessment + remediation) |
| Time to achieve | 6-15 months | 6-12 months | 3-12 months | 3-12 months | 3-6 months (initial compliance) |
| Overlap with SOC 2 | N/A | ~70% control overlap | ~50% control overlap | ~40% control overlap | ~30% control overlap |
| Who asks for it | US enterprise buyers, SaaS customers | European buyers, global enterprises | Healthcare organizations, insurers | Banks, payment processors, merchants | Any company with EU customers |

### 5.5 Prowler Check Categories and Counts

Prowler is an open-source tool for AWS, GCP, and Azure security assessments. It maps findings to SOC 2 criteria.

```bash
# install prowler
pip install prowler

# run full scan against AWS
prowler aws --compliance soc2

# run specific categories
prowler aws -c iam_user_mfa_enabled_console_access
prowler aws -c s3_bucket_server_side_encryption
prowler aws -c cloudtrail_multi_region_enabled
```

| Category | Check Count (approx) | SOC 2 Criteria Mapped |
|----------|---------------------|----------------------|
| IAM | 35+ | CC6.1, CC6.2, CC6.3 |
| S3 | 20+ | CC6.1, CC6.7 |
| EC2 / VPC | 25+ | CC6.1, CC6.6 |
| RDS | 15+ | CC6.1, CC6.7, A1.2 |
| CloudTrail | 10+ | CC7.1, CC7.2 |
| KMS | 8+ | CC6.1, CC6.7 |
| GuardDuty | 3+ | CC7.1, CC7.2 |
| Config | 5+ | CC4.1, CC7.1 |
| Lambda | 8+ | CC6.1, CC8.1 |
| EKS | 10+ | CC6.1, CC6.6, CC8.1 |
| CloudWatch | 10+ | CC7.1, CC7.2 |
| SSM | 5+ | CC6.1, CC8.1 |
| Total | 150+ checks | Covers CC1-CC9, A1, C1 |

---

## Version

Section 05, v1.0 — Evidence collection automation, audit preparation materials, and ongoing operations.
