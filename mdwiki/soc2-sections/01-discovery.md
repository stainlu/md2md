# Section 01: Discovery & Assessment Engine

You cannot fix what you have not measured. Before writing a single policy or deploying a single config, you must discover the company's actual security posture. This section gives you every tool and command to do that.

The output of this section is a **Gap Report** — a prioritized list of every SOC 2 control that is missing, misconfigured, or incomplete. Every subsequent section references this report.

---

## 1. Intake Questionnaire

Present this questionnaire to the company contact. Every field is required — missing fields will cause incomplete audits and wasted remediation cycles. If a field is unknown, write `UNKNOWN` so it appears in the gap report.

```yaml
INTAKE QUESTIONNAIRE — SOC 2 Discovery

company:
  legal_name: ""                      # exact legal entity name for the audit report
  product: ""                         # one-line product description
  product_url: ""                     # production URL
  industry: ""                        # SaaS, fintech, healthtech, edtech, etc.
  employee_count: ""                  # current headcount (full-time + contractors)
  engineering_count: ""               # engineers with production access
  founded: ""                         # year
  hq_location: ""                     # city, state/country — affects data residency

people:
  ceo: ""                             # name + email
  cto: ""                             # name + email (or VP Engineering)
  security_lead: ""                   # name + email (if none, write NONE — this is a gap)
  hr_lead: ""                         # name + email
  compliance_owner: ""                # who will drive SOC 2 day-to-day — name + email
  # NOTE: if security_lead is NONE, flag GAP-PEOPLE-001 in the gap report.
  # SOC 2 requires a named security owner. The CTO can fill this role initially
  # but the auditor will ask about segregation of duties.

infrastructure:
  cloud_provider: ""                  # AWS, GCP, Azure, or multi-cloud (specify which)
  cloud_account_ids:                  # list each account
    - id: ""
      purpose: ""                     # prod, staging, dev, security, logging
      region: ""                      # primary region
  identity_provider: ""               # Okta, Google Workspace, Azure AD, JumpCloud, or NONE
  source_control: ""                  # GitHub, GitLab, Bitbucket — include org/workspace name
  source_control_org: ""              # the org or workspace name
  ci_cd: ""                           # GitHub Actions, CircleCI, Jenkins, ArgoCD, etc.
  monitoring: ""                      # Datadog, Splunk, CloudWatch, New Relic, etc.
  alerting: ""                        # PagerDuty, OpsGenie, or part of monitoring tool
  ticketing: ""                       # Jira, Linear, Asana, etc.
  communication: ""                   # Slack, Teams, Discord, etc.
  mdm: ""                             # Jamf, Intune, Kandji, or NONE
  edr: ""                             # CrowdStrike, SentinelOne, Carbon Black, or NONE
  password_manager: ""                # 1Password, Bitwarden, LastPass, or NONE
  vpn: ""                             # Tailscale, WireGuard, Cloudflare WARP, or NONE
  secrets_manager: ""                 # AWS Secrets Manager, HashiCorp Vault, Doppler, or NONE
  # NOTE: if mdm is NONE, flag GAP-INFRA-001. SOC 2 requires endpoint management.
  # NOTE: if edr is NONE, flag GAP-INFRA-002. SOC 2 requires endpoint detection.
  # NOTE: if password_manager is NONE, flag GAP-INFRA-003.

data:
  customer_data_types: ""             # list explicitly: names, emails, payment info, usage data, etc.
  pii_handled: ""                     # yes/no — if yes, list each PII type
  phi_handled: ""                     # yes/no — if yes, HIPAA is also in scope
  pci_data: ""                        # yes/no — if yes, PCI DSS is also in scope
  data_residency_requirements: ""     # geographic restrictions (EU-only, US-only, etc.)
  databases:                          # list every database
    - type: ""                        # Postgres, MySQL, DynamoDB, MongoDB, etc.
      hosting: ""                     # RDS, Cloud SQL, self-managed on EC2, etc.
      encrypted_at_rest: ""           # yes/no/unknown
      encrypted_in_transit: ""        # yes/no/unknown
      backup_enabled: ""              # yes/no/unknown
  storage:                            # list every object store
    - name: ""                        # bucket name
      provider: ""                    # S3, GCS, Azure Blob, etc.
      contains: ""                    # what data
      encrypted: ""                   # yes/no/unknown
      public: ""                      # yes/no/unknown

compliance:
  target_type: ""                     # type I or type II
                                      # type I = point-in-time snapshot (faster, less trusted)
                                      # type II = controls observed over 3-12 months (what buyers want)
  target_tsc:                         # Trust Services Criteria to include
    - security                        # REQUIRED — always included
    - availability                    # RECOMMENDED — include unless product has no SLA
    - confidentiality                 # RECOMMENDED — include if you handle sensitive data
    # - processing_integrity          # OPTIONAL — include for fintech, data pipelines
    # - privacy                       # OPTIONAL — include if you process PII under your own policy
  target_date: ""                     # when do you need the report by (YYYY-MM-DD)
  observation_window_start: ""        # for type II: when should the window start (YYYY-MM-DD)
  existing_frameworks: ""             # ISO 27001, HIPAA, PCI DSS, SOC 1, GDPR, etc.
  compliance_platform: ""             # Vanta, Drata, Secureframe, Sprinto, or NONE
  audit_firm: ""                      # already engaged? which firm?
  budget: ""                          # approximate budget for the engagement

vendors:
  critical_vendors:                   # every vendor that accesses, processes, or stores customer data
    - name: ""
      purpose: ""                     # what they do
      data_access: ""                 # what customer data they can access
      soc2_report: ""                 # yes/no — if yes, get a copy
      iso27001: ""                    # yes/no
      contract_reviewed: ""           # yes/no — does the contract include security terms
  # NOTE: any vendor with data_access != "none" and soc2_report == "no" and iso27001 == "no"
  # is a gap. Flag as GAP-VENDOR-NNN.
```

After receiving the questionnaire, validate it:
- If any `NONE` values appear in `identity_provider`, `mdm`, `edr`, or `password_manager`, these are automatic gaps. Log them immediately.
- If `security_lead` is `NONE`, this is a critical finding. SOC 2 auditors require a named security owner.
- If `compliance_platform` is `NONE`, expect 3-5x more manual work for evidence collection.
- If `target_type` is empty, default to `type II`. Type I is only acceptable as a stepping stone.
- Count vendors with `soc2_report == "no"` and `iso27001 == "no"` — each one needs a risk assessment.

Store all intake data. Every subsequent section will reference these values via `{{PLACEHOLDER}}` syntax.

---

## 2. Prowler-Based Automated Assessment

Prowler is an open-source tool that runs 156+ automated checks against AWS, Azure, and GCP infrastructure, mapped to SOC 2 requirements. It is the backbone of the automated discovery phase.

### 2.1 Install Prowler

```bash
# Option A: pip (works on any OS)
pip install prowler

# Option B: brew (macOS)
brew install prowler

# Option C: Docker (if pip/brew are unavailable)
docker pull toniblyx/prowler
```

Verify installation:
```bash
prowler --version
```
Expected output: `Prowler X.Y.Z` (version 3.x or 4.x).

If the command fails with `command not found`:
- Check that `~/.local/bin` is in `PATH` (pip installs there by default).
- Run `python -m prowler --version` as a fallback.
- If Docker was used: `docker run --rm toniblyx/prowler --version`.

### 2.2 Configure AWS Credentials

Prowler needs read-only access to the AWS account. It uses the standard AWS credential chain.

```bash
# Verify credentials are configured
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDAEXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/prowler-audit"
}
```

If this fails with `Unable to locate credentials`:
- Ask the company to provide AWS credentials (access key + secret key) for a read-only IAM user or role.
- The IAM user/role needs the AWS-managed policy `SecurityAudit` plus `ViewOnlyAccess`.
- Never run Prowler with admin credentials. If they only have admin credentials, create a read-only role first (see Section 02).

For multi-account setups, Prowler must run against each account separately:
```bash
# If using cross-account role assumption
export AWS_PROFILE=prod-audit  # or staging-audit, dev-audit, etc.
```

### 2.3 Run SOC 2 Assessment

```bash
# Run full SOC 2 compliance check, output as JSON
prowler aws --compliance soc2_aws --output-formats json csv

# Output files land in ./output/ by default
# Key files:
#   output/prowler-output-*.json     — machine-readable results
#   output/prowler-output-*.csv      — spreadsheet-friendly results
#   output/compliance/soc2_aws-*.csv — SOC 2-specific compliance mapping
```

For multi-region coverage:
```bash
# Run across all active regions
prowler aws --compliance soc2_aws --output-formats json \
  -f us-east-1 us-west-2 eu-west-1 eu-central-1
```

Expected runtime: 10-30 minutes depending on account size.

If Prowler fails with `AccessDenied` on specific checks:
- This means the IAM role is missing permissions for that service.
- Log the failed check ID. Continue with remaining checks.
- Add the missing permission and re-run only the failed checks: `prowler aws -c <check_id>`.

### 2.4 Interpret Prowler Output

Each check in the JSON output has this structure:
```json
{
  "CheckID": "iam_user_mfa_enabled_console_access",
  "CheckTitle": "Ensure MFA is enabled for all IAM users that have a console password",
  "Status": "FAIL",
  "StatusExtended": "IAM user 'deploy-bot' has console access but MFA is not enabled",
  "Severity": "critical",
  "ResourceId": "deploy-bot",
  "Region": "us-east-1",
  "Compliance": {
    "SOC2": ["CC6.1", "CC6.2"]
  }
}
```

Field interpretation:
- **Status**: `PASS` = control is in place. `FAIL` = control is missing or misconfigured. `INFO` = informational, not scored.
- **Severity**: `critical` = fix immediately, audit will flag this. `high` = fix within 2 weeks. `medium` = fix within 30 days. `low` = fix within 90 days.
- **Compliance.SOC2**: the SOC 2 Common Criteria (CC) controls this check maps to. Use this to group findings by control objective.

### 2.5 Parse Prowler Output into a Prioritized Remediation List

Run this script to generate a sorted remediation list from Prowler JSON output:

```bash
#!/usr/bin/env bash
# parse-prowler.sh — convert Prowler JSON output into a prioritized gap list
# Usage: bash parse-prowler.sh output/prowler-output-*.json

INPUT_FILE="$1"

if [ -z "$INPUT_FILE" ]; then
  echo "Usage: bash parse-prowler.sh <prowler-output.json>"
  exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: File not found: $INPUT_FILE"
  exit 1
fi

echo "============================================"
echo "PROWLER SOC 2 FINDINGS SUMMARY"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Source: $INPUT_FILE"
echo "============================================"
echo ""

# Count by status
TOTAL=$(jq 'length' "$INPUT_FILE")
PASS=$(jq '[.[] | select(.Status == "PASS")] | length' "$INPUT_FILE")
FAIL=$(jq '[.[] | select(.Status == "FAIL")] | length' "$INPUT_FILE")

if [ "$TOTAL" -eq 0 ]; then
  echo "WARNING: Prowler output contains 0 checks. Verify the file is correct."
  exit 1
fi

echo "TOTAL CHECKS: $TOTAL"
echo "PASSING:      $PASS ($(( PASS * 100 / TOTAL ))%)"
echo "FAILING:      $FAIL ($(( FAIL * 100 / TOTAL ))%)"
echo ""

# Count failures by severity
for sev in critical high medium low; do
  COUNT=$(jq --arg s "$sev" '[.[] | select(.Status == "FAIL" and .Severity == $s)] | length' "$INPUT_FILE")
  echo "  ${sev^^}: $COUNT"
done

# Print findings grouped by severity
print_findings() {
  local severity="$1"
  local label="$2"
  echo ""
  echo "============================================"
  echo "$label"
  echo "============================================"
  jq -r --arg s "$severity" '.[] | select(.Status == "FAIL" and .Severity == $s) |
    "- [\(.CheckID)] \(.CheckTitle)\n  Resource: \(.ResourceId) (\(.Region))\n  Detail: \(.StatusExtended)\n  SOC 2 Controls: \(.Compliance.SOC2 // ["unmapped"] | join(", "))\n"' \
    "$INPUT_FILE"
}

print_findings "critical" "CRITICAL FAILURES (fix immediately)"
print_findings "high"     "HIGH FAILURES (fix within 2 weeks)"
print_findings "medium"   "MEDIUM FAILURES (fix within 30 days)"
print_findings "low"      "LOW FAILURES (fix within 90 days)"
```

Dependencies: `jq` must be installed. If not: `brew install jq` or `apt-get install jq`.

If the Prowler output uses OCSF format (Prowler 4.x), the field names differ:
- `CheckID` may be `check_id` or nested under `finding_info`.
- Run `jq 'first' output.json` to inspect the schema, then adjust the field paths above.

---

## 3. Manual Discovery Commands

Prowler covers infrastructure controls but does not cover: source control configuration, IdP policies, endpoint management, or organizational policies. Run these commands to discover the remaining gaps.

### 3.1 AWS Discovery

Each command block targets a specific SOC 2 control area. Run all of them against every AWS account in scope.

**Prerequisites:** `aws` CLI configured, `jq` installed.

#### IAM: Users Without MFA (CC6.1, CC6.2)

```bash
# Generate and download the credential report
aws iam generate-credential-report
# Wait for report generation (usually 5-15 seconds)
sleep 10
aws iam generate-credential-report --query 'State' --output text
# Expected: "COMPLETE". If "STARTED", wait 10 more seconds and retry.

# List users without MFA who have console access
aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | \
  awk -F, 'NR > 1 && $4 == "true" && $8 == "false" {print "NO MFA: " $1}'
```

Expected output (if gaps exist):
```
NO MFA: deploy-user
NO MFA: jane.doe
```
If no output, all console users have MFA — this check passes.

If the command fails with `ReportNotPresent`: the report is still generating. Wait 15 seconds and re-run.

If `base64 -d` fails on macOS, use `base64 -D` (capital D) instead.

#### IAM: Overly Permissive Policies (CC6.1, CC6.3)

```bash
# Find IAM users with inline policies (should be zero — use groups/roles instead)
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  if [ -n "$policies" ] && [ "$policies" != "None" ]; then
    echo "INLINE POLICY on user: $user — policies: $policies"
  fi
done

# Find IAM policies with full admin access (Action: *, Resource: *)
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output text | \
  while read name arn; do
    version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
    has_star=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$version" \
      --query 'PolicyVersion.Document.Statement[?Effect==`Allow` && contains(Action, `*`) && contains(Resource, `*`)]' --output text)
    if [ -n "$has_star" ] && [ "$has_star" != "None" ]; then
      echo "FULL ADMIN: $name ($arn)"
    fi
  done
```

#### CloudTrail: Audit Logging (CC7.1, CC7.2)

```bash
# Check if CloudTrail is enabled and properly configured
aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled,KmsKeyId,S3BucketName]' \
  --output table
```

Expected output (healthy):
```
----------------------------------------------------------------------
|                          DescribeTrails                              |
+----------+-------+-------+---------------------+-------------------+
| main-trail| True | True | arn:aws:kms:...     | company-cloudtrail |
----------------------------------------------------------------------
```

Gaps to flag:
- No trails at all → GAP: CloudTrail not enabled. Critical.
- `IsMultiRegionTrail` = False → GAP: trail only covers one region. High.
- `LogFileValidationEnabled` = False → GAP: log integrity validation disabled. High.
- `KmsKeyId` = None → GAP: logs not encrypted with CMK. Medium.

```bash
# Verify CloudTrail is actually logging (not just configured)
aws cloudtrail get-trail-status --name <trail-name> \
  --query '[IsLogging, LatestDeliveryTime]' --output text
```

If `IsLogging` is `false`, the trail exists but is stopped — this is a critical gap.

#### S3: Encryption and Public Access (CC6.1, CC6.6)

```bash
# Check every bucket for encryption and public access settings
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  # Check encryption
  enc=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>&1)
  if echo "$enc" | grep -q "ServerSideEncryptionConfigurationNotFoundError"; then
    enc_status="NOT ENCRYPTED"
  else
    enc_status="encrypted"
  fi

  # Check public access block
  pub=$(aws s3api get-public-access-block --bucket "$bucket" 2>&1)
  if echo "$pub" | grep -q "NoSuchPublicAccessBlockConfiguration"; then
    pub_status="NO PUBLIC ACCESS BLOCK"
  else
    all_blocked=$(echo "$pub" | jq '.PublicAccessBlockConfiguration | .BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets')
    if [ "$all_blocked" = "true" ]; then
      pub_status="public access blocked"
    else
      pub_status="PARTIALLY OPEN"
    fi
  fi

  echo "$bucket: $enc_status | $pub_status"
done
```

Any bucket showing `NOT ENCRYPTED` or `PARTIALLY OPEN` or `NO PUBLIC ACCESS BLOCK` is a gap.

#### RDS: Database Encryption (CC6.1)

```bash
# Check encryption status of all RDS instances
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,Engine,StorageEncrypted,KmsKeyId,PubliclyAccessible,MultiAZ,BackupRetentionPeriod]' \
  --output table
```

Gaps to flag:
- `StorageEncrypted` = false → GAP: database not encrypted at rest. Critical.
- `PubliclyAccessible` = true → GAP: database has public endpoint. Critical.
- `BackupRetentionPeriod` = 0 → GAP: no automated backups. High.
- `MultiAZ` = false → GAP (if availability TSC is in scope): no failover. Medium.

Note: if an RDS instance is not encrypted and contains data, you cannot enable encryption in-place. You must create an encrypted snapshot and restore from it. This is a disruptive remediation — plan it carefully (see Section 02).

#### VPC: Flow Logs (CC7.2)

```bash
# Check every VPC for flow logs
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
  fl=$(aws ec2 describe-flow-logs \
    --filter Name=resource-id,Values=$vpc \
    --query 'FlowLogs[0].FlowLogId' --output text)
  if [ "$fl" = "None" ] || [ -z "$fl" ]; then
    echo "NO FLOW LOGS: $vpc"
  else
    echo "OK: $vpc → $fl"
  fi
done
```

Every VPC without flow logs is a gap. SOC 2 CC7.2 requires network activity monitoring.

#### GuardDuty: Threat Detection (CC7.1, CC7.2)

```bash
# Check if GuardDuty is enabled
detectors=$(aws guardduty list-detectors --query 'DetectorIds' --output text)
if [ -z "$detectors" ] || [ "$detectors" = "None" ]; then
  echo "GAP: GuardDuty is NOT enabled"
else
  for detector in $detectors; do
    status=$(aws guardduty get-detector --detector-id "$detector" --query 'Status' --output text)
    echo "GuardDuty detector $detector: $status"
  done
fi
```

If GuardDuty is not enabled, this is a high-severity gap. It is the primary AWS service for threat detection.

#### Config: Configuration Monitoring (CC7.1)

```bash
# Check if AWS Config recorder is running
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[*].[name,recording,lastStatus]' --output table
```

If no recorders exist or `recording` is false, this is a high-severity gap. AWS Config is required for continuous configuration monitoring.

#### KMS: Key Rotation (CC6.1)

```bash
# Check key rotation for all customer-managed keys
for key in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  # Skip AWS-managed keys (they rotate automatically)
  mgr=$(aws kms describe-key --key-id "$key" --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)
  if [ "$mgr" = "CUSTOMER" ]; then
    rot=$(aws kms get-key-rotation-status --key-id "$key" --query 'KeyRotationEnabled' --output text 2>/dev/null)
    echo "Key $key: rotation=$rot"
  fi
done
```

Any customer-managed key with `rotation=false` is a medium-severity gap.

#### Security Hub (CC7.1, CC7.2)

```bash
# Check if Security Hub is enabled
aws securityhub describe-hub 2>&1
```

If the response contains `InvalidAccessException` or `not subscribed`, Security Hub is not enabled. This is a medium-severity gap — Security Hub aggregates findings from GuardDuty, Inspector, and Config.

### 3.2 GitHub Discovery

**Prerequisites:** `gh` CLI installed and authenticated (`gh auth status`).

Replace `{owner}` with the GitHub org name and `{repo}` with each repository in scope.

#### Branch Protection (CC8.1)

```bash
# Check branch protection on main/master for each repo
for repo in $(gh repo list {owner} --json name --jq '.[].name'); do
  protection=$(gh api repos/{owner}/$repo/branches/main/protection 2>&1)
  if echo "$protection" | grep -q "Branch not protected"; then
    echo "NO PROTECTION: {owner}/$repo (main)"
  elif echo "$protection" | grep -q "Not Found"; then
    # Try master branch
    protection=$(gh api repos/{owner}/$repo/branches/master/protection 2>&1)
    if echo "$protection" | grep -q "Branch not protected"; then
      echo "NO PROTECTION: {owner}/$repo (master)"
    elif echo "$protection" | grep -q "Not Found"; then
      echo "NO DEFAULT BRANCH PROTECTION: {owner}/$repo"
    else
      echo "OK: {owner}/$repo (master) — protected"
    fi
  else
    # Check specific settings
    pr_required=$(echo "$protection" | jq -r '.required_pull_request_reviews.required_approving_review_count // 0')
    status_checks=$(echo "$protection" | jq -r '.required_status_checks.strict // false')
    echo "OK: {owner}/$repo — reviews=$pr_required, strict_status=$status_checks"
  fi
done
```

Gaps to flag:
- No branch protection at all → Critical. Anyone can push directly to main.
- `required_approving_review_count` = 0 → High. No code review enforced.
- `strict` = false → Medium. Status checks not required before merge.

#### Security Features (CC6.1, CC7.1)

```bash
# Check security features for each repo
for repo in $(gh repo list {owner} --json name --jq '.[].name'); do
  features=$(gh api repos/{owner}/$repo --jq '{
    secret_scanning: .security_and_analysis.secret_scanning.status,
    secret_scanning_push_protection: .security_and_analysis.secret_scanning_push_protection.status,
    dependabot_alerts: .security_and_analysis.dependabot_security_updates.status
  }')
  echo "$repo: $features"
done
```

Any feature showing `disabled` or `null` is a gap.

#### Organization Settings (CC6.1)

```bash
# Check org-level security settings
gh api orgs/{owner} --jq '{
  two_factor_requirement: .two_factor_requirement_enabled,
  default_repo_permission: .default_repository_permission,
  members_can_create_public_repos: .members_can_create_public_repositories
}'
```

Gaps to flag:
- `two_factor_requirement` = false → Critical. Org does not enforce 2FA.
- `default_repo_permission` = "admin" or "write" → High. Overly permissive defaults.
- `members_can_create_public_repos` = true → Medium. Risk of accidental public repos.

#### Dependabot / Vulnerability Alerts (CC7.1)

```bash
# Check if vulnerability alerts are enabled
for repo in $(gh repo list {owner} --json name --jq '.[].name'); do
  status=$(gh api repos/{owner}/$repo/vulnerability-alerts -i 2>&1 | head -1)
  if echo "$status" | grep -q "204"; then
    echo "OK: $repo — vulnerability alerts enabled"
  else
    echo "GAP: $repo — vulnerability alerts DISABLED"
  fi
done
```

### 3.3 Okta Discovery

**Prerequisites:** `OKTA_TOKEN` (API token with read-only admin scope) and `OKTA_DOMAIN` (e.g., `company.okta.com`) must be set as environment variables.

```bash
# Verify Okta API access
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=1"
```
Expected: `200`. If `401`: token is invalid or expired. If `403`: token lacks permissions. Ask for a new token.

#### User Inventory and MFA Status (CC6.1, CC6.2)

```bash
# List all active users and their MFA enrollment
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status+eq+%22ACTIVE%22" | \
  jq -r '.[] | [.profile.login, .status, (.credentials.provider.type // "PASSWORD")] | @tsv' | \
  column -t -s $'\t'
```

Then check MFA factors per user:
```bash
# For each user, check enrolled MFA factors
# Uses the initial user list to avoid redundant API calls per user
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status+eq+%22ACTIVE%22" | \
  jq -r '.[] | [.id, .profile.login] | @tsv' | while IFS=$'\t' read uid login; do
    factors=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/users/$uid/factors" | jq -r '[.[].factorType] | join(",")')
    if [ -z "$factors" ]; then
      echo "NO MFA: $login"
    else
      echo "OK: $login — factors: $factors"
    fi
  done
```

Any user with `NO MFA` is a gap.

Note: this script makes N+1 API calls (1 to list users, 1 per user for factors). For orgs with 200+ users, use pagination and add `sleep 0.5` between calls to respect Okta rate limits (600 req/min).

#### Password Policy (CC6.1)

```bash
# Check password complexity requirements
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" | \
  jq '.[0] | {
    name: .name,
    min_length: .settings.password.complexity.minLength,
    min_lowercase: .settings.password.complexity.minLowerCase,
    min_uppercase: .settings.password.complexity.minUpperCase,
    min_number: .settings.password.complexity.minNumber,
    min_symbol: .settings.password.complexity.minSymbol,
    max_age_days: .settings.password.age.maxAgeDays,
    history_count: .settings.password.age.historyCount,
    lockout_attempts: .settings.password.lockout.maxAttempts
  }'
```

SOC 2 minimum requirements:
- `min_length` >= 12 (NIST 800-63b recommends 8 minimum, but 12 is the practical standard)
- `max_age_days` should be 0 (no forced rotation) OR >= 90 (if forced rotation is required by policy)
- `lockout_attempts` should be <= 10
- `history_count` >= 5

Flag any value below these thresholds as a gap.

#### MFA Enrollment Policy (CC6.1)

```bash
# Check MFA enrollment policy
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" | \
  jq '.[0].settings.factors'
```

Expected: at least one hardware or software authenticator factor (e.g., `okta_otp`, `google_otp`, `fido_webauthn`) should be in `REQUIRED` or `OPTIONAL` status. If all factors are `INACTIVE`, MFA is effectively disabled — critical gap.

### 3.4 Google Workspace Discovery

**Prerequisites:** GAM (Google Apps Manager) installed and configured. Install: `https://github.com/GAM-team/GAM`.

If GAM is not available, use the Admin SDK via `curl` with an OAuth2 token with admin directory read scope.

#### 2-Step Verification (CC6.1, CC6.2)

```bash
# Check 2SV enrollment and enforcement for all users
gam print users fields isEnrolledIn2Sv,isEnforcedIn2Sv | \
  awk -F, 'NR > 1 && ($3 == "False" || $4 == "False") {
    print "GAP: " $1 " enrolled=" $3 " enforced=" $4
  }'
```

Any user with `isEnforcedIn2Sv=False` is a gap. The org should enforce 2SV for all users.

#### Password and Session Policies

```bash
# Check password policy length and strength requirements
gam print policies

# Check session duration settings
gam print adminsettings | grep -i session
```

If `gam` is not installed and cannot be installed:
```bash
# Fallback: use Google Admin API directly (requires OAuth2 token)
curl -s -H "Authorization: Bearer ${GOOGLE_TOKEN}" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=100&projection=full" | \
  jq '.users[] | {email: .primaryEmail, is2SvEnrolled: .isEnrolledIn2Sv, is2SvEnforced: .isEnforcedIn2Sv}'
```

---

## 4. Gap Report Generator

After running Prowler and all manual discovery commands, consolidate everything into a single structured gap report. This report is the input for every subsequent section.

```bash
#!/usr/bin/env bash
# generate-gap-report.sh
# Usage: bash generate-gap-report.sh <company_name> <prowler_output.json> [manual_findings.txt]
#
# manual_findings.txt format (one finding per line):
#   SEVERITY|GAP_ID|DESCRIPTION|SOC2_CONTROLS|REMEDIATION_SECTION
#   critical|GAP-GH-001|No branch protection on main branch for repo api|CC8.1|Section 02
#   high|GAP-OKTA-001|3 users without MFA enrollment|CC6.1,CC6.2|Section 02

COMPANY="$1"
PROWLER_FILE="$2"
MANUAL_FILE="$3"
DATE=$(date -u +%Y-%m-%d)
REPORT_FILE="gap-report-${DATE}.txt"

if [ -z "$COMPANY" ] || [ -z "$PROWLER_FILE" ]; then
  echo "Usage: bash generate-gap-report.sh <company_name> <prowler_output.json> [manual_findings.txt]"
  exit 1
fi

{
  echo "============================================================"
  echo "GAP REPORT — ${COMPANY} — ${DATE}"
  echo "============================================================"
  echo ""

  # --- Prowler Summary ---
  TOTAL=$(jq 'length' "$PROWLER_FILE")
  PASS=$(jq '[.[] | select(.Status == "PASS")] | length' "$PROWLER_FILE")
  FAIL=$(jq '[.[] | select(.Status == "FAIL")] | length' "$PROWLER_FILE")
  CRIT=$(jq '[.[] | select(.Status == "FAIL" and .Severity == "critical")] | length' "$PROWLER_FILE")
  HIGH=$(jq '[.[] | select(.Status == "FAIL" and .Severity == "high")] | length' "$PROWLER_FILE")
  MED=$(jq '[.[] | select(.Status == "FAIL" and .Severity == "medium")] | length' "$PROWLER_FILE")
  LOW=$(jq '[.[] | select(.Status == "FAIL" and .Severity == "low")] | length' "$PROWLER_FILE")

  # --- Manual findings count ---
  MANUAL_CRIT=0; MANUAL_HIGH=0; MANUAL_MED=0; MANUAL_LOW=0
  if [ -n "$MANUAL_FILE" ] && [ -f "$MANUAL_FILE" ]; then
    MANUAL_CRIT=$(grep -c "^critical|" "$MANUAL_FILE" 2>/dev/null || echo 0)
    MANUAL_HIGH=$(grep -c "^high|" "$MANUAL_FILE" 2>/dev/null || echo 0)
    MANUAL_MED=$(grep -c "^medium|" "$MANUAL_FILE" 2>/dev/null || echo 0)
    MANUAL_LOW=$(grep -c "^low|" "$MANUAL_FILE" 2>/dev/null || echo 0)
  fi

  TOTAL_CRIT=$((CRIT + MANUAL_CRIT))
  TOTAL_HIGH=$((HIGH + MANUAL_HIGH))
  TOTAL_MED=$((MED + MANUAL_MED))
  TOTAL_LOW=$((LOW + MANUAL_LOW))
  TOTAL_GAPS=$((FAIL + MANUAL_CRIT + MANUAL_HIGH + MANUAL_MED + MANUAL_LOW))

  echo "SUMMARY"
  echo "-------"
  if [ "$TOTAL" -eq 0 ]; then
    echo "WARNING: Prowler output contains 0 checks. Verify the file."
    PASS_PCT=0; FAIL_PCT=0
  else
    PASS_PCT=$(( PASS * 100 / TOTAL ))
    FAIL_PCT=$(( FAIL * 100 / TOTAL ))
  fi

  echo "Prowler automated checks:  $TOTAL"
  echo "  Passing:                 $PASS (${PASS_PCT}%)"
  echo "  Failing:                 $FAIL (${FAIL_PCT}%)"
  echo "Manual discovery findings: $((MANUAL_CRIT + MANUAL_HIGH + MANUAL_MED + MANUAL_LOW))"
  echo ""
  echo "Total gaps:    $TOTAL_GAPS"
  echo "  Critical:    $TOTAL_CRIT"
  echo "  High:        $TOTAL_HIGH"
  echo "  Medium:      $TOTAL_MED"
  echo "  Low:         $TOTAL_LOW"
  echo ""

  # --- Print gaps for a given severity ---
  print_gap_section() {
    local severity="$1"
    local label="$2"

    echo "============================================================"
    echo "$label"
    echo "============================================================"

    # Prowler findings for this severity
    jq -r --arg s "$severity" '.[] | select(.Status == "FAIL" and .Severity == $s) |
      "[\(.CheckID)] \(.CheckTitle)\n  Resource: \(.ResourceId) (\(.Region))\n  Detail: \(.StatusExtended)\n  SOC 2: \(.Compliance.SOC2 // ["unmapped"] | join(", "))\n  Remediation: See Section 02\n"' \
      "$PROWLER_FILE" 2>/dev/null

    # Manual findings for this severity
    if [ -n "$MANUAL_FILE" ] && [ -f "$MANUAL_FILE" ]; then
      grep "^${severity}|" "$MANUAL_FILE" 2>/dev/null | while IFS='|' read sev gid desc controls section; do
        echo "[$gid] $desc"
        echo "  SOC 2: $controls"
        echo "  Remediation: See $section"
        echo ""
      done
    fi
  }

  print_gap_section "critical" "CRITICAL GAPS — fix immediately"
  print_gap_section "high"     "HIGH GAPS — fix within 2 weeks"
  print_gap_section "medium"   "MEDIUM GAPS — fix within 30 days"
  print_gap_section "low"      "LOW GAPS — fix within 90 days"

  echo "============================================================"
  echo "NEXT STEPS"
  echo "============================================================"
  echo "1. Review this report with ${COMPANY} security lead and CTO."
  echo "2. Confirm priority ordering — business context may override severity."
  echo "3. Begin remediation using Section 02 (Technical Controls)."
  echo "4. After remediation, re-run Prowler and manual checks to verify."
  echo "============================================================"

} > "$REPORT_FILE"

echo "Gap report written to: $REPORT_FILE"
echo "Total gaps found: $TOTAL_GAPS (critical=$TOTAL_CRIT, high=$TOTAL_HIGH, medium=$TOTAL_MED, low=$TOTAL_LOW)"
```

### Manual Findings File Format

During manual discovery (section 3), log each finding as a single line in `manual_findings.txt`:

```
critical|GAP-GH-001|No branch protection on main for repo api-server|CC8.1|Section 02
critical|GAP-GH-002|GitHub org does not enforce 2FA|CC6.1|Section 02
high|GAP-OKTA-001|3 users without MFA: alice@co.com, bob@co.com, charlie@co.com|CC6.1,CC6.2|Section 02
high|GAP-INFRA-001|No MDM solution deployed — endpoint management missing|CC6.8|Section 03
high|GAP-INFRA-002|No EDR solution deployed — endpoint detection missing|CC7.1|Section 03
medium|GAP-GH-003|Secret scanning disabled on 4 repositories|CC6.1|Section 02
medium|GAP-OKTA-002|Password minimum length is 8 (should be 12)|CC6.1|Section 02
low|GAP-GH-004|Dependabot alerts disabled on 2 non-production repos|CC7.1|Section 02
```

---

## 5. Steampipe for Live Queries

Steampipe turns cloud APIs into SQL tables. Use it for ad-hoc queries during the assessment, or for continuous compliance monitoring after remediation.

### 5.1 Install Steampipe

```bash
# macOS
brew install turbot/tap/steampipe

# Linux
sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
```

Verify:
```bash
steampipe --version
```
Expected: `steampipe version 0.x.y`. If `command not found`: ensure `/usr/local/bin` (macOS) or `~/.steampipe` (Linux) is in `PATH`.

### 5.2 Install Plugins

Install only the plugins for services the company uses (based on intake questionnaire):

```bash
# AWS (if cloud_provider includes AWS)
steampipe plugin install aws

# GitHub (if source_control is GitHub)
steampipe plugin install github

# Okta (if identity_provider is Okta)
steampipe plugin install okta

# Google Workspace (if identity_provider is Google Workspace)
steampipe plugin install googleworkspace
```

Each plugin uses the same credential chain as the respective CLI tool. If the AWS CLI works, the AWS Steampipe plugin will work.

If a plugin install fails with a connection error, check that the Steampipe service is running: `steampipe service start`.

### 5.3 SOC 2 Discovery Queries

#### IAM: Users Without MFA (CC6.1, CC6.2)

```sql
SELECT
  user_name,
  password_enabled,
  mfa_active,
  access_key_1_active,
  access_key_2_active
FROM aws_iam_credential_report
WHERE password_enabled AND NOT mfa_active;
```

Expected: zero rows. Each row is a user who has console access without MFA — a gap.

#### Unencrypted EBS Volumes (CC6.1)

```sql
SELECT
  volume_id,
  state,
  size,
  encrypted,
  region
FROM aws_ebs_volume
WHERE NOT encrypted;
```

Expected: zero rows. Each row is an unencrypted volume — a gap.

#### S3 Buckets Without Versioning (CC6.1, A1.2)

```sql
SELECT
  name,
  region,
  versioning_enabled,
  logging
FROM aws_s3_bucket
WHERE NOT versioning_enabled;
```

Versioning is important for SOC 2 availability and data recovery controls. Each unversioned bucket is a medium-severity gap.

#### S3 Buckets Without Server-Side Encryption (CC6.1)

```sql
SELECT
  name,
  region,
  server_side_encryption_configuration
FROM aws_s3_bucket
WHERE server_side_encryption_configuration IS NULL;
```

#### Publicly Accessible RDS Instances (CC6.1, CC6.6)

```sql
SELECT
  db_instance_identifier,
  engine,
  publicly_accessible,
  storage_encrypted
FROM aws_rds_db_instance
WHERE publicly_accessible;
```

Critical gap: any row returned means a database is reachable from the internet.

#### Security Groups with 0.0.0.0/0 Ingress (CC6.6)

```sql
SELECT
  group_id,
  group_name,
  ip_permission ->> 'IpProtocol' AS protocol,
  ip_permission ->> 'FromPort' AS from_port,
  ip_permission ->> 'ToPort' AS to_port,
  cidr ->> 'CidrIp' AS cidr_ip
FROM aws_vpc_security_group,
  jsonb_array_elements(ip_permissions) AS ip_permission,
  jsonb_array_elements(ip_permission -> 'IpRanges') AS cidr
WHERE cidr ->> 'CidrIp' = '0.0.0.0/0'
  AND (ip_permission ->> 'FromPort')::int NOT IN (443, 80);
```

Any security group allowing inbound traffic from `0.0.0.0/0` on non-web ports is a critical gap.

#### GitHub Repos Without Branch Protection (CC8.1)

```sql
SELECT
  r.full_name,
  r.default_branch,
  bp.required_approving_review_count,
  bp.enforce_admins
FROM github_repository r
LEFT JOIN github_branch_protection bp
  ON r.full_name = bp.repository_full_name
  AND r.default_branch = bp.branch_name
WHERE bp.branch_name IS NULL
  AND NOT r.is_archived;
```

Each row is a repo where the default branch has no protection rules — a gap.

### 5.4 Running Queries

```bash
# Run a single query
steampipe query "SELECT user_name, mfa_active FROM aws_iam_credential_report WHERE NOT mfa_active"

# Run from a file
steampipe query --output json < query.sql

# Export results for the gap report
steampipe query --output csv "SELECT ..." > findings.csv
```

If a query fails with `relation does not exist`: the required plugin is not installed. Run `steampipe plugin install <name>`.

If a query fails with `access denied` or `403`: the credentials lack the required permissions. Check the plugin docs for required IAM permissions.

---

## 6. Discovery Execution Checklist

Run through this checklist to ensure complete coverage. Check off each item as you complete it.

```
DISCOVERY CHECKLIST — {{COMPANY_NAME}}

[ ] 1. Intake questionnaire completed and validated
[ ] 2. AWS credentials verified (aws sts get-caller-identity)
[ ] 3. Prowler installed and SOC 2 scan completed
[ ] 4. Prowler output parsed into prioritized findings
[ ] 5. Manual AWS discovery completed:
    [ ] IAM users without MFA
    [ ] IAM overly permissive policies
    [ ] CloudTrail enabled and logging
    [ ] S3 encryption and public access
    [ ] RDS encryption and public access
    [ ] VPC flow logs
    [ ] GuardDuty enabled
    [ ] AWS Config recorder running
    [ ] KMS key rotation
    [ ] Security Hub enabled
[ ] 6. GitHub discovery completed:
    [ ] Branch protection on all repos
    [ ] Security features (secret scanning, dependabot)
    [ ] Org-level 2FA enforcement
    [ ] Vulnerability alerts enabled
[ ] 7. IdP discovery completed (Okta / Google Workspace / Azure AD):
    [ ] All users inventoried
    [ ] MFA enrollment status checked
    [ ] Password policy reviewed
    [ ] MFA enrollment policy reviewed
[ ] 8. Steampipe queries run for cross-cutting checks
[ ] 9. Manual findings logged in manual_findings.txt
[ ] 10. Gap report generated (generate-gap-report.sh)
[ ] 11. Gap report reviewed with company security lead
[ ] 12. Remediation priorities confirmed

OUTPUT: gap-report-YYYY-MM-DD.txt → input for Section 02 (Technical Controls)
```

---

## Error Reference

Common errors you will encounter during discovery and how to handle them:

| Error | Cause | Fix |
|---|---|---|
| `aws: command not found` | AWS CLI not installed | `brew install awscli` or `pip install awscli` |
| `Unable to locate credentials` | No AWS credentials configured | Ask company for access key pair or IAM role |
| `AccessDenied` on specific AWS API | IAM role missing permissions | Add the specific service permission and retry |
| `gh: command not found` | GitHub CLI not installed | `brew install gh` then `gh auth login` |
| `gh api: 404 Not Found` | Wrong org/repo name or insufficient permissions | Verify org name, check token scopes |
| `HTTP 401` from Okta | Token expired or invalid | Ask company to generate a new API token |
| `HTTP 429` from Okta | Rate limited | Add `sleep 1` between API calls |
| `gam: command not found` | GAM not installed | See https://github.com/GAM-team/GAM for install |
| `steampipe: command not found` | Steampipe not installed | See install commands in section 5.1 |
| `relation does not exist` (Steampipe) | Plugin not installed | `steampipe plugin install <name>` |
| `jq: command not found` | jq not installed | `brew install jq` or `apt-get install jq` |
| Prowler `AccessDenied` on specific check | IAM missing service-specific permissions | Note the check ID, add permission, re-run that check only |
| `base64 -d` fails on macOS | macOS uses `-D` flag | Replace `base64 -d` with `base64 -D` |
