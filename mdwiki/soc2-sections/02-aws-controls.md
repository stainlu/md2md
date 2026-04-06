# Section 02: AWS Security Controls

> Full DISCOVER-FIX-VERIFY-EVIDENCE cycle for every SOC 2 control on AWS.
> Every command is copy-paste ready. Every control maps to a Trust Services Criteria (TSC).

## Prerequisites

```bash
# Confirm AWS CLI is configured and working
aws sts get-caller-identity

# Set reusable variables used throughout this document
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export EVIDENCE_DIR="./soc2-evidence/$(date +%Y-%m-%d)"
mkdir -p "$EVIDENCE_DIR"

# For multi-region commands
export ALL_REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)
```

---

## IAM Controls

### 1. Root Account MFA (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```
- PASS: returns `1`
- FAIL: returns `0`

**FIX** -- remediate if failing:
```
Root MFA cannot be enabled via CLI. You must:
1. Sign in as root at https://console.aws.amazon.com
2. Go to IAM > Security credentials
3. Activate MFA (hardware key preferred, TOTP acceptable)
4. Use a hardware security key (YubiKey) for highest assurance
```
Gotchas:
- Virtual MFA (authenticator app) is acceptable but hardware key is preferred for root
- Store backup codes in a physical safe, not digitally
- If the root account has never been used, you still need MFA -- auditors check this

**VERIFY** -- confirm the fix:
```bash
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
# Expected output: 1
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam get-account-summary > "$EVIDENCE_DIR/root-mfa-status-$(date +%Y%m%d-%H%M%S).json"
```

---

### 2. Root Account Access Keys (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
```
- PASS: returns `0`
- FAIL: returns `1` (root has access keys -- delete them immediately)

**FIX** -- remediate if failing:
```
Root access key deletion must be done via console:
1. Sign in as root at https://console.aws.amazon.com
2. Go to IAM > Security credentials
3. Delete all access keys listed under "Access keys"
```
Gotchas:
- Before deleting, verify no automation relies on root keys (it should never)
- If any automation uses root keys, migrate it to an IAM role first
- There is no CLI command to delete root access keys -- console only

**VERIFY** -- confirm the fix:
```bash
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
# Expected output: 0
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam get-account-summary --query '{RootMFA: SummaryMap.AccountMFAEnabled, RootAccessKeys: SummaryMap.AccountAccessKeysPresent}' \
  > "$EVIDENCE_DIR/root-account-status-$(date +%Y%m%d-%H%M%S).json"
```

---

### 3. IAM Users MFA (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Generate credential report (takes a few seconds)
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > /tmp/cred-report.csv

# Find users with password but no MFA
awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1}' /tmp/cred-report.csv
```
- PASS: no output (all password-enabled users have MFA)
- FAIL: lists usernames without MFA

**FIX** -- remediate if failing:
```bash
# Option A: Enforce MFA via IAM policy (attach to all users/groups)
cat > /tmp/require-mfa-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:ListVirtualMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ResyncMFADevice",
        "iam:ListMFADevices"
      ],
      "Resource": [
        "arn:aws:iam::*:mfa/${aws:username}",
        "arn:aws:iam::*:user/${aws:username}"
      ]
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }
  ]
}
POLICY

aws iam create-policy \
  --policy-name RequireMFA \
  --policy-document file:///tmp/require-mfa-policy.json

# Attach to a group that all users belong to
aws iam attach-group-policy \
  --group-name AllUsers \
  --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/RequireMFA"
```
Gotchas:
- Users locked out without MFA can still set up their own MFA device (the policy allows it)
- Service accounts (programmatic-only) do not need MFA -- they should not have passwords
- Notify all users before enforcing -- give 48h to set up MFA

**VERIFY** -- confirm the fix:
```bash
aws iam generate-credential-report > /dev/null 2>&1
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > /tmp/cred-report.csv
awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1}' /tmp/cred-report.csv
# Expected: no output
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam get-credential-report --query Content --output text | base64 -d \
  > "$EVIDENCE_DIR/iam-credential-report-$(date +%Y%m%d-%H%M%S).csv"
```

---

### 4. IAM Password Policy (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
aws iam get-account-password-policy
```
- PASS: output shows `MinimumPasswordLength >= 14`, `RequireSymbols: true`, `RequireNumbers: true`, `RequireUppercaseCharacters: true`, `RequireLowercaseCharacters: true`, `MaxPasswordAge <= 90`, `PasswordReusePrevention >= 24`
- FAIL: command returns `NoSuchEntity` error or values below requirements

**FIX** -- remediate if failing:
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --allow-users-to-change-password
```
Gotchas:
- This affects new passwords only -- existing passwords remain until next rotation
- `--max-password-age 90` means users must change every 90 days
- Consider `--hard-expiry` to lock users out when password expires (strict but can cause lockouts)

**VERIFY** -- confirm the fix:
```bash
aws iam get-account-password-policy
# Expected: all fields match the values set above
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam get-account-password-policy \
  > "$EVIDENCE_DIR/password-policy-$(date +%Y%m%d-%H%M%S).json"
```

---

### 5. Access Key Rotation (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Find access keys older than 90 days
aws iam get-credential-report --query Content --output text | base64 -d > /tmp/cred-report.csv

awk -F',' 'NR>1 && $9=="true" {
  cmd = "date -d \"" $10 "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S+00:00\" \"" $10 "\" +%s 2>/dev/null"
  cmd | getline created
  close(cmd)
  now = systime()
  age = (now - created) / 86400
  if (age > 90) print $1, "key1_age=" int(age) "d"
}' /tmp/cred-report.csv

awk -F',' 'NR>1 && $14=="true" {
  cmd = "date -d \"" $15 "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S+00:00\" \"" $15 "\" +%s 2>/dev/null"
  cmd | getline created
  close(cmd)
  now = systime()
  age = (now - created) / 86400
  if (age > 90) print $1, "key2_age=" int(age) "d"
}' /tmp/cred-report.csv
```
- PASS: no output (no keys older than 90 days)
- FAIL: lists users with stale keys and their age

**FIX** -- remediate if failing:
```bash
# For each user with old keys, rotate:
USERNAME="the-user"

# Step 1: Create new key
aws iam create-access-key --user-name "$USERNAME"
# (Record the new AccessKeyId and SecretAccessKey -- this is the only time you see the secret)

# Step 2: Update all systems using the old key

# Step 3: Deactivate old key (do NOT delete yet -- keep for rollback)
OLD_KEY_ID="AKIAEXAMPLE"
aws iam update-access-key --user-name "$USERNAME" --access-key-id "$OLD_KEY_ID" --status Inactive

# Step 4: After confirming nothing breaks (wait 24-48h), delete old key
aws iam delete-access-key --user-name "$USERNAME" --access-key-id "$OLD_KEY_ID"
```
Gotchas:
- Never delete the old key immediately -- deactivate first, wait, then delete
- The new secret is shown only once at creation time
- Automated rotation: use AWS Secrets Manager for machine credentials

**VERIFY** -- confirm the fix:
```bash
aws iam list-access-keys --user-name "$USERNAME" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'
# Expected: only active keys created recently
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam generate-credential-report > /dev/null 2>&1 && sleep 5
aws iam get-credential-report --query Content --output text | base64 -d \
  > "$EVIDENCE_DIR/access-key-rotation-$(date +%Y%m%d-%H%M%S).csv"
```

---

### 6. Unused Credentials (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
aws iam get-credential-report --query Content --output text | base64 -d > /tmp/cred-report.csv

# Users with passwords who have not logged in for 90+ days (or never)
awk -F',' 'NR>1 && $4=="true" {
  if ($5 == "no_information" || $5 == "N/A") {
    print $1, "password_never_used"
  } else {
    cmd = "date -d \"" $5 "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S+00:00\" \"" $5 "\" +%s 2>/dev/null"
    cmd | getline last
    close(cmd)
    now = systime()
    age = (now - last) / 86400
    if (age > 90) print $1, "password_last_used=" int(age) "d_ago"
  }
}' /tmp/cred-report.csv

# Users with active keys never used or not used in 90+ days
awk -F',' 'NR>1 && $9=="true" {
  if ($11 == "N/A" || $11 == "no_information") {
    print $1, "key1_never_used"
  } else {
    cmd = "date -d \"" $11 "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S+00:00\" \"" $11 "\" +%s 2>/dev/null"
    cmd | getline last
    close(cmd)
    now = systime()
    age = (now - last) / 86400
    if (age > 90) print $1, "key1_last_used=" int(age) "d_ago"
  }
}' /tmp/cred-report.csv
```
- PASS: no output
- FAIL: lists users with unused credentials

**FIX** -- remediate if failing:
```bash
USERNAME="the-user"

# Disable console access
aws iam delete-login-profile --user-name "$USERNAME"

# Deactivate access keys
for KEY_ID in $(aws iam list-access-keys --user-name "$USERNAME" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$USERNAME" --access-key-id "$KEY_ID" --status Inactive
done
```
Gotchas:
- Contact the user before disabling -- they may have a legitimate low-frequency use case
- Deactivate first (reversible), do not delete immediately
- Document the reason for disabling in your ticketing system

**VERIFY** -- confirm the fix:
```bash
aws iam get-login-profile --user-name "$USERNAME" 2>&1
# Expected: "NoSuchEntity" error (login profile deleted)

aws iam list-access-keys --user-name "$USERNAME" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}'
# Expected: all keys show Status=Inactive (or no keys)
```

**EVIDENCE** -- capture for auditor:
```bash
aws iam get-credential-report --query Content --output text | base64 -d \
  > "$EVIDENCE_DIR/unused-credentials-$(date +%Y%m%d-%H%M%S).csv"
```

---

### 7. IAM Policies (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Find users with inline policies (should be zero)
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  inline=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  if [ -n "$inline" ] && [ "$inline" != "None" ]; then
    echo "INLINE_POLICY: user=$user policies=$inline"
  fi
done

# Find policies with *:* (admin access on non-admin users)
for arn in $(aws iam list-policies --only-attached --query 'Policies[*].Arn' --output text); do
  version=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$version" --query 'PolicyVersion.Document' --output json)
  if echo "$doc" | grep -q '"Action":\s*"\*"' || echo "$doc" | grep -q '"Action":\s*\[.*"\*"'; then
    if echo "$doc" | grep -q '"Resource":\s*"\*"'; then
      echo "OVERLY_PERMISSIVE: $arn"
    fi
  fi
done

# Find groups with inline policies
for group in $(aws iam list-groups --query 'Groups[*].GroupName' --output text); do
  inline=$(aws iam list-group-policies --group-name "$group" --query 'PolicyNames' --output text)
  if [ -n "$inline" ] && [ "$inline" != "None" ]; then
    echo "INLINE_POLICY: group=$group policies=$inline"
  fi
done
```
- PASS: no output for any of the three checks
- FAIL: lists inline policies or overly permissive policies

**FIX** -- remediate if failing:
```bash
# Convert inline policy to managed policy
USERNAME="the-user"
POLICY_NAME="the-inline-policy"

# Step 1: Get the inline policy document
aws iam get-user-policy --user-name "$USERNAME" --policy-name "$POLICY_NAME" \
  --query 'PolicyDocument' > /tmp/policy-doc.json

# Step 2: Create as managed policy
aws iam create-policy \
  --policy-name "$POLICY_NAME" \
  --policy-document file:///tmp/policy-doc.json

# Step 3: Attach managed policy
aws iam attach-user-policy \
  --user-name "$USERNAME" \
  --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}"

# Step 4: Delete inline policy
aws iam delete-user-policy --user-name "$USERNAME" --policy-name "$POLICY_NAME"

# For overly permissive policies: replace *:* with least-privilege
# Use IAM Access Analyzer to generate least-privilege policies:
aws accessanalyzer list-analyzers --query 'analyzers[*].{Name:name,Status:status}'
```
Gotchas:
- AWS managed policies (arn:aws:iam::aws:policy/*) are acceptable -- focus on custom policies
- AdministratorAccess is acceptable for a break-glass role with strict conditions
- Use IAM Access Analyzer to generate least-privilege policies from actual usage

**VERIFY** -- confirm the fix:
```bash
# Re-run the inline policy checks -- expect no output
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  inline=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
  if [ -n "$inline" ] && [ "$inline" != "None" ]; then
    echo "FAIL: user=$user still has inline policies=$inline"
  fi
done
# Expected: no output
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo '{"users_with_policies": ['
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    attached=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[*].PolicyName' --output json)
    inline=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output json)
    echo "{\"user\": \"$user\", \"attached\": $attached, \"inline\": $inline},"
  done
  echo ']}'
} > "$EVIDENCE_DIR/iam-policy-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

### 8. Service-Linked Roles Over Access Keys (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# List IAM users with active access keys (should be minimal -- prefer roles)
aws iam get-credential-report --query Content --output text | base64 -d > /tmp/cred-report.csv

awk -F',' 'NR>1 && ($9=="true" || $14=="true") {print $1}' /tmp/cred-report.csv
```
- PASS: only human users who genuinely need CLI access (and use MFA with STS)
- FAIL: service accounts or EC2/Lambda workloads using long-lived access keys

**FIX** -- remediate if failing:
```bash
# For EC2 instances: attach an instance profile with an IAM role
aws iam create-role \
  --role-name MyAppRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam create-instance-profile --instance-profile-name MyAppProfile
aws iam add-role-to-instance-profile \
  --instance-profile-name MyAppProfile \
  --role-name MyAppRole

aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=MyAppProfile

# For Lambda: the execution role is already a role (no keys needed)
# For ECS: use task roles
# For cross-account: use sts:AssumeRole
```
Gotchas:
- Instance profiles are the EC2 mechanism for IAM roles -- one per instance
- Applications using AWS SDKs automatically pick up role credentials from instance metadata
- After attaching a role, remove the old access keys from the application config, then deactivate

**VERIFY** -- confirm the fix:
```bash
# Check that the instance has a profile attached
aws ec2 describe-instances --instance-ids i-1234567890abcdef0 \
  --query 'Reservations[*].Instances[*].IamInstanceProfile.Arn'
# Expected: returns the instance profile ARN

# Confirm old access keys are deactivated
aws iam list-access-keys --user-name service-account-name \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}'
# Expected: Status=Inactive or no keys
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "# Users with active access keys (should be minimal)"
  awk -F',' 'NR>1 && ($9=="true" || $14=="true") {print $1}' /tmp/cred-report.csv
  echo ""
  echo "# EC2 instances with IAM roles"
  aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{Id:InstanceId,Profile:IamInstanceProfile.Arn,State:State.Name}' \
    --output table
} > "$EVIDENCE_DIR/iam-roles-vs-keys-$(date +%Y%m%d-%H%M%S).txt"
```

---

## CloudTrail Controls

### 9. Multi-Region Trail (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,IsOrg:IsOrganizationTrail,HomeRegion:HomeRegion}'
```
- PASS: at least one trail with `IsMultiRegion: true` and logging is active
- FAIL: no trails, or all trails have `IsMultiRegion: false`

Also check that logging is actually on:
```bash
for trail in $(aws cloudtrail describe-trails --query 'trailList[*].TrailARN' --output text); do
  status=$(aws cloudtrail get-trail-status --name "$trail" --query 'IsLogging')
  echo "$trail logging=$status"
done
```

**FIX** -- remediate if failing:
```bash
# Create a multi-region trail
aws cloudtrail create-trail \
  --name soc2-audit-trail \
  --s3-bucket-name "${AWS_ACCOUNT_ID}-cloudtrail-logs" \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation \
  --kms-key-id alias/cloudtrail-key

aws cloudtrail start-logging --name soc2-audit-trail
```
Gotchas:
- The S3 bucket must exist and have the correct bucket policy (see Control 12)
- The KMS key must exist and grant CloudTrail encrypt permissions (see Control 11)
- If an organization trail exists in the management account, account-level trails may be redundant -- verify with `IsOrganizationTrail`
- Maximum 5 trails per region

**VERIFY** -- confirm the fix:
```bash
aws cloudtrail get-trail-status --name soc2-audit-trail \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
# Expected: IsLogging=true, LatestDeliveryTime is recent
```

**EVIDENCE** -- capture for auditor:
```bash
{
  aws cloudtrail describe-trails
  echo "---"
  for trail in $(aws cloudtrail describe-trails --query 'trailList[*].TrailARN' --output text); do
    aws cloudtrail get-trail-status --name "$trail"
  done
} > "$EVIDENCE_DIR/cloudtrail-config-$(date +%Y%m%d-%H%M%S).json"
```

---

### 10. CloudTrail Log File Validation (TSC: CC7.1)

**DISCOVER** -- check current state:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[*].{Name:Name,LogFileValidation:LogFileValidationEnabled}'
```
- PASS: all trails show `LogFileValidation: true`
- FAIL: any trail shows `LogFileValidation: false`

**FIX** -- remediate if failing:
```bash
aws cloudtrail update-trail \
  --name soc2-audit-trail \
  --enable-log-file-validation
```
Gotchas:
- Log file validation uses SHA-256 hashing -- it proves logs were not tampered with
- Digest files are delivered to the same S3 bucket under a different prefix
- This is non-disruptive -- can be enabled on a running trail

**VERIFY** -- confirm the fix:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[?Name==`soc2-audit-trail`].LogFileValidationEnabled'
# Expected: [true]
```

**EVIDENCE** -- capture for auditor:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[*].{Name:Name,LogFileValidation:LogFileValidationEnabled}' \
  > "$EVIDENCE_DIR/cloudtrail-log-validation-$(date +%Y%m%d-%H%M%S).json"
```

---

### 11. CloudTrail KMS Encryption (TSC: CC6.1, CC7.1)

**DISCOVER** -- check current state:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[*].{Name:Name,KmsKeyId:KmsKeyId}'
```
- PASS: all trails have a `KmsKeyId` value (ARN of a CMK)
- FAIL: `KmsKeyId` is `null` (using default S3 SSE, not CMK)

**FIX** -- remediate if failing:
```bash
# Create a KMS key for CloudTrail (if one does not exist)
KEY_ID=$(aws kms create-key \
  --description "CloudTrail log encryption" \
  --query 'KeyMetadata.KeyId' --output text)

aws kms create-alias --alias-name alias/cloudtrail-key --target-key-id "$KEY_ID"

# Grant CloudTrail permission to use the key
aws kms put-key-policy --key-id "$KEY_ID" --policy-name default --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyAdmin",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'"$AWS_ACCOUNT_ID"':root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowCloudTrailEncrypt",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "kms:GenerateDataKey*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:SourceArn": "arn:aws:cloudtrail:*:'"$AWS_ACCOUNT_ID"':trail/*"},
        "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:'"$AWS_ACCOUNT_ID"':trail/*"}
      }
    },
    {
      "Sid": "AllowCloudTrailDescribeKey",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "kms:DescribeKey",
      "Resource": "*"
    },
    {
      "Sid": "AllowDecryptForLogReaders",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'"$AWS_ACCOUNT_ID"':root"},
      "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
      "Resource": "*",
      "Condition": {
        "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:'"$AWS_ACCOUNT_ID"':trail/*"}
      }
    }
  ]
}'

# Apply to trail
aws cloudtrail update-trail \
  --name soc2-audit-trail \
  --kms-key-id "alias/cloudtrail-key"
```
Gotchas:
- The KMS key policy must explicitly allow CloudTrail to use the key
- Users who need to read logs must have `kms:Decrypt` permission
- Cross-region: the key must be in the trail's home region

**VERIFY** -- confirm the fix:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[?Name==`soc2-audit-trail`].KmsKeyId'
# Expected: returns the KMS key ARN
```

**EVIDENCE** -- capture for auditor:
```bash
{
  aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,KmsKeyId:KmsKeyId}'
  echo "---"
  aws kms describe-key --key-id alias/cloudtrail-key
} > "$EVIDENCE_DIR/cloudtrail-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 12. CloudTrail S3 Bucket Security (TSC: CC6.1, CC7.1)

**DISCOVER** -- check current state:
```bash
TRAIL_BUCKET=$(aws cloudtrail describe-trails \
  --query 'trailList[?Name==`soc2-audit-trail`].S3BucketName' --output text)

# Check public access block
aws s3api get-public-access-block --bucket "$TRAIL_BUCKET"

# Check bucket policy does not allow public access
aws s3api get-bucket-policy --bucket "$TRAIL_BUCKET" --query Policy --output text | python3 -m json.tool

# Check MFA delete
aws s3api get-bucket-versioning --bucket "$TRAIL_BUCKET"

# Check lifecycle policy
aws s3api get-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET"
```
- PASS: public access fully blocked, versioning enabled with MFA delete, lifecycle policy present
- FAIL: any public access, no versioning, no lifecycle

**FIX** -- remediate if failing:
```bash
# Block all public access
aws s3api put-public-access-block --bucket "$TRAIL_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable versioning (required before MFA delete)
aws s3api put-bucket-versioning --bucket "$TRAIL_BUCKET" \
  --versioning-configuration Status=Enabled

# MFA delete (requires root account credentials and MFA device serial)
# This MUST be done by the root account:
# aws s3api put-bucket-versioning --bucket "$TRAIL_BUCKET" \
#   --versioning-configuration Status=Enabled,MFADelete=Enabled \
#   --mfa "arn:aws:iam::${AWS_ACCOUNT_ID}:mfa/root-account-mfa-device TOKENCODE"

# Set lifecycle policy (retain 1 year, transition to Glacier after 90 days)
aws s3api put-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET" \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "CloudTrailRetention",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "Transitions": [{
        "Days": 90,
        "StorageClass": "GLACIER"
      }],
      "Expiration": {
        "Days": 2555
      }
    }]
  }'

# Set bucket policy for CloudTrail
aws s3api put-bucket-policy --bucket "$TRAIL_BUCKET" --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::'"$TRAIL_BUCKET"'"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::'"$TRAIL_BUCKET"'/AWSLogs/'"$AWS_ACCOUNT_ID"'/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    },
    {
      "Sid": "DenyUnencryptedPut",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::'"$TRAIL_BUCKET"'/*",
      "Condition": {
        "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
      }
    },
    {
      "Sid": "DenyNonSSL",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::'"$TRAIL_BUCKET"'", "arn:aws:s3:::'"$TRAIL_BUCKET"'/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}'
```
Gotchas:
- MFA delete can only be enabled by the root account -- IAM users cannot do it
- `Expiration: 2555 days` = ~7 years (adjust per your retention policy)
- The Glacier transition saves cost but adds retrieval time (3-5 hours standard)

**VERIFY** -- confirm the fix:
```bash
echo "=== Public Access Block ==="
aws s3api get-public-access-block --bucket "$TRAIL_BUCKET"
echo "=== Versioning ==="
aws s3api get-bucket-versioning --bucket "$TRAIL_BUCKET"
echo "=== Lifecycle ==="
aws s3api get-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET"
# Expected: all public access blocked, versioning enabled, lifecycle configured
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo '{"bucket": "'"$TRAIL_BUCKET"'",'
  echo '"public_access_block":'
  aws s3api get-public-access-block --bucket "$TRAIL_BUCKET"
  echo ','
  echo '"versioning":'
  aws s3api get-bucket-versioning --bucket "$TRAIL_BUCKET"
  echo ','
  echo '"lifecycle":'
  aws s3api get-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET" 2>/dev/null || echo '"none"'
  echo ','
  echo '"policy":'
  aws s3api get-bucket-policy --bucket "$TRAIL_BUCKET" --query Policy --output text 2>/dev/null || echo '"none"'
  echo '}'
} > "$EVIDENCE_DIR/cloudtrail-bucket-security-$(date +%Y%m%d-%H%M%S).json"
```

---

### 13. CloudTrail CloudWatch Integration (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[*].{Name:Name,CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn,CloudWatchLogsRoleArn:CloudWatchLogsRoleArn}'
```
- PASS: `CloudWatchLogsLogGroupArn` is set (not null)
- FAIL: `CloudWatchLogsLogGroupArn` is null

**FIX** -- remediate if failing:
```bash
# Create CloudWatch log group
aws logs create-log-group --log-group-name /cloudtrail/soc2-audit-trail
aws logs put-retention-policy --log-group-name /cloudtrail/soc2-audit-trail --retention-in-days 365

# Create IAM role for CloudTrail to write to CloudWatch
aws iam create-role --role-name CloudTrail-CloudWatch-Role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy --role-name CloudTrail-CloudWatch-Role \
  --policy-name CloudTrailCloudWatchPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:'"$AWS_ACCOUNT_ID"':log-group:/cloudtrail/soc2-audit-trail:*"
    }]
  }'

# Attach to trail
CW_LOG_GROUP_ARN="arn:aws:logs:$(aws configure get region):${AWS_ACCOUNT_ID}:log-group:/cloudtrail/soc2-audit-trail:*"
CW_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/CloudTrail-CloudWatch-Role"

aws cloudtrail update-trail \
  --name soc2-audit-trail \
  --cloud-watch-logs-log-group-arn "$CW_LOG_GROUP_ARN" \
  --cloud-watch-logs-role-arn "$CW_ROLE_ARN"
```
Gotchas:
- The role trust policy must allow cloudtrail.amazonaws.com
- The log group ARN in the trail config must include `:*` at the end
- CloudWatch Logs costs: ~$0.50/GB ingested -- budget for this

**VERIFY** -- confirm the fix:
```bash
aws cloudtrail describe-trails \
  --query 'trailList[?Name==`soc2-audit-trail`].CloudWatchLogsLogGroupArn'
# Expected: returns the log group ARN

# Confirm logs are flowing
aws logs describe-log-streams \
  --log-group-name /cloudtrail/soc2-audit-trail \
  --order-by LastEventTime --descending --limit 1 \
  --query 'logStreams[0].lastEventTimestamp'
# Expected: a recent timestamp
```

**EVIDENCE** -- capture for auditor:
```bash
{
  aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn}'
  echo "---"
  aws logs describe-log-groups --log-group-name-prefix /cloudtrail/
} > "$EVIDENCE_DIR/cloudtrail-cloudwatch-$(date +%Y%m%d-%H%M%S).json"
```

---

## GuardDuty Controls

### 14. GuardDuty Enabled in All Regions (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
for region in $ALL_REGIONS; do
  detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ "$detector" = "None" ] || [ -z "$detector" ]; then
    echo "DISABLED: $region"
  else
    status=$(aws guardduty get-detector --region "$region" --detector-id "$detector" --query 'Status' --output text)
    echo "ENABLED: $region detector=$detector status=$status"
  fi
done
```
- PASS: all regions show `ENABLED` with `status=ENABLED`
- FAIL: any region shows `DISABLED`

**FIX** -- remediate if failing:
```bash
for region in $ALL_REGIONS; do
  detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ "$detector" = "None" ] || [ -z "$detector" ]; then
    echo "Enabling GuardDuty in $region..."
    aws guardduty create-detector --enable \
      --finding-publishing-frequency FIFTEEN_MINUTES \
      --region "$region"
  fi
done
```
Gotchas:
- GuardDuty costs are usage-based -- typically $1-$5/day per region for moderate workloads
- For multi-account setup via AWS Organizations, use delegated administrator
- GuardDuty has a 30-day free trial per region
- Some regions may be opt-in (not enabled by default) -- enable the region first

**VERIFY** -- confirm the fix:
```bash
for region in $ALL_REGIONS; do
  detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ "$detector" != "None" ] && [ -n "$detector" ]; then
    status=$(aws guardduty get-detector --region "$region" --detector-id "$detector" --query 'Status' --output text)
    echo "$region: $status"
  else
    echo "$region: MISSING"
  fi
done
# Expected: all regions show ENABLED
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for region in $ALL_REGIONS; do
    detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
    if [ "$detector" != "None" ] && [ -n "$detector" ]; then
      echo "{\"region\": \"$region\", \"detector\": \"$detector\","
      aws guardduty get-detector --region "$region" --detector-id "$detector" \
        --query '{Status:Status,FindingPublishingFrequency:FindingPublishingFrequency,UpdatedAt:UpdatedAt}'
      echo "},"
    else
      echo "{\"region\": \"$region\", \"detector\": null},"
    fi
  done
} > "$EVIDENCE_DIR/guardduty-all-regions-$(date +%Y%m%d-%H%M%S).json"
```

---

### 15. GuardDuty Finding Publishing Frequency (TSC: CC7.2)

**DISCOVER** -- check current state:
```bash
REGION=$(aws configure get region)
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DETECTOR_ID" \
  --query 'FindingPublishingFrequency'
```
- PASS: returns `"FIFTEEN_MINUTES"`
- FAIL: returns `"ONE_HOUR"` or `"SIX_HOURS"`

**FIX** -- remediate if failing:
```bash
for region in $ALL_REGIONS; do
  detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ "$detector" != "None" ] && [ -n "$detector" ]; then
    aws guardduty update-detector --region "$region" \
      --detector-id "$detector" \
      --finding-publishing-frequency FIFTEEN_MINUTES
    echo "Updated $region"
  fi
done
```
Gotchas:
- FIFTEEN_MINUTES is the most frequent option -- there is no real-time option
- This controls how often findings are published to EventBridge (for alerting)
- Does not affect detection speed -- only notification speed

**VERIFY** -- confirm the fix:
```bash
for region in $ALL_REGIONS; do
  detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ "$detector" != "None" ] && [ -n "$detector" ]; then
    freq=$(aws guardduty get-detector --region "$region" --detector-id "$detector" --query 'FindingPublishingFrequency' --output text)
    echo "$region: $freq"
  fi
done
# Expected: all regions show FIFTEEN_MINUTES
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for region in $ALL_REGIONS; do
    detector=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
    if [ "$detector" != "None" ] && [ -n "$detector" ]; then
      freq=$(aws guardduty get-detector --region "$region" --detector-id "$detector" --query 'FindingPublishingFrequency' --output text)
      echo "$region: $freq"
    fi
  done
} > "$EVIDENCE_DIR/guardduty-frequency-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 16. GuardDuty SNS Notifications (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# Check if there is an EventBridge rule forwarding GuardDuty findings to SNS
aws events list-rules --query 'Rules[?contains(Name, `guardduty`) || contains(Name, `GuardDuty`)].{Name:Name,State:State}'

# If a rule exists, check its targets
RULE_NAME="guardduty-findings-to-sns"  # adjust to match your rule name
aws events list-targets-by-rule --rule "$RULE_NAME" 2>/dev/null
```
- PASS: rule exists, is ENABLED, and targets an SNS topic
- FAIL: no rule or rule is DISABLED

**FIX** -- remediate if failing:
```bash
# Create SNS topic for security alerts
TOPIC_ARN=$(aws sns create-topic --name security-guardduty-alerts --query 'TopicArn' --output text)

# Subscribe security team email
aws sns subscribe \
  --topic-arn "$TOPIC_ARN" \
  --protocol email \
  --notification-endpoint security-team@company.com
# (The subscriber must confirm via email)

# Create EventBridge rule to forward GuardDuty findings
aws events put-rule \
  --name guardduty-findings-to-sns \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 4]}]
    }
  }' \
  --state ENABLED \
  --description "Forward medium+ GuardDuty findings to SNS"

# Allow EventBridge to publish to SNS
aws sns set-topic-attributes \
  --topic-arn "$TOPIC_ARN" \
  --attribute-name Policy \
  --attribute-value '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "events.amazonaws.com"},
      "Action": "sns:Publish",
      "Resource": "'"$TOPIC_ARN"'"
    }]
  }'

# Set SNS as the target
aws events put-targets \
  --rule guardduty-findings-to-sns \
  --targets "Id=sns-target,Arn=$TOPIC_ARN"
```
Gotchas:
- Severity filter `>= 4` catches medium and high findings -- adjust threshold as needed (range is 1-8.9)
- GuardDuty severity: 1.0-3.9=Low, 4.0-6.9=Medium, 7.0-8.9=High
- Consider adding a Lambda function for formatting before SNS (raw JSON is hard to read)
- For Slack/PagerDuty, use SNS -> Lambda -> webhook or AWS Chatbot

**VERIFY** -- confirm the fix:
```bash
# Check rule
aws events describe-rule --name guardduty-findings-to-sns \
  --query '{State:State,EventPattern:EventPattern}'

# Check targets
aws events list-targets-by-rule --rule guardduty-findings-to-sns

# Check SNS subscriptions are confirmed
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" \
  --query 'Subscriptions[*].{Endpoint:Endpoint,Protocol:Protocol,Status:SubscriptionArn}'
# Expected: SubscriptionArn should NOT be "PendingConfirmation"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== EventBridge Rule ==="
  aws events describe-rule --name guardduty-findings-to-sns
  echo "=== Targets ==="
  aws events list-targets-by-rule --rule guardduty-findings-to-sns
  echo "=== SNS Subscriptions ==="
  aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN"
} > "$EVIDENCE_DIR/guardduty-notifications-$(date +%Y%m%d-%H%M%S).json"
```

---

## AWS Config Controls

### 17. Config Recorder Enabled (TSC: CC7.1)

**DISCOVER** -- check current state:
```bash
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[*].{Name:name,Recording:recording,LastStatus:lastStatus}'
```
- PASS: recorder exists, `recording: true`, `lastStatus: SUCCESS`, and `allSupported: true` with `includeGlobalResourceTypes: true`
- FAIL: no recorder, not recording, or not recording all resource types

**FIX** -- remediate if failing:
```bash
# Create IAM role for Config
aws iam create-role --role-name AWSConfigRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole

# Create recorder
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/AWSConfigRole" \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# Start recording
aws configservice start-configuration-recorder --configuration-recorder-name default
```
Gotchas:
- `includeGlobalResourceTypes=true` should only be set in ONE region (usually us-east-1) to avoid duplicate global resource records
- Config charges per configuration item recorded -- typically $2-$5/month for small accounts
- If the recorder was stopped, starting it does NOT backfill -- only records going forward

**VERIFY** -- confirm the fix:
```bash
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[*].{Name:name,Recording:recording,LastStatus:lastStatus}'
# Expected: recording=true, lastStatus=SUCCESS
```

**EVIDENCE** -- capture for auditor:
```bash
{
  aws configservice describe-configuration-recorders
  echo "---"
  aws configservice describe-configuration-recorder-status
} > "$EVIDENCE_DIR/config-recorder-$(date +%Y%m%d-%H%M%S).json"
```

---

### 18. Config Delivery Channel (TSC: CC7.1)

**DISCOVER** -- check current state:
```bash
aws configservice describe-delivery-channels
aws configservice describe-delivery-channel-status \
  --query 'DeliveryChannelsStatus[*].{Name:name,LastDeliveryTime:configStreamDeliveryInfo.lastStatusChangeTime,LastStatus:configStreamDeliveryInfo.lastStatus}'
```
- PASS: delivery channel exists, delivering to an S3 bucket, last status SUCCESS
- FAIL: no delivery channel or delivery failures

**FIX** -- remediate if failing:
```bash
# Create S3 bucket for Config
CONFIG_BUCKET="${AWS_ACCOUNT_ID}-aws-config-logs"
aws s3api create-bucket --bucket "$CONFIG_BUCKET" \
  --create-bucket-configuration LocationConstraint=$(aws configure get region)

aws s3api put-bucket-policy --bucket "$CONFIG_BUCKET" --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::'"$CONFIG_BUCKET"'"
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::'"$CONFIG_BUCKET"'/AWSLogs/'"$AWS_ACCOUNT_ID"'/Config/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}'

# Block public access on Config bucket
aws s3api put-public-access-block --bucket "$CONFIG_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create delivery channel
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName="$CONFIG_BUCKET"
```
Gotchas:
- Only one delivery channel per region is supported
- The S3 bucket can be in a different account (centralized logging)
- Consider adding an SNS topic to the delivery channel for real-time notifications

**VERIFY** -- confirm the fix:
```bash
aws configservice describe-delivery-channel-status
# Expected: lastStatus=SUCCESS
```

**EVIDENCE** -- capture for auditor:
```bash
{
  aws configservice describe-delivery-channels
  echo "---"
  aws configservice describe-delivery-channel-status
} > "$EVIDENCE_DIR/config-delivery-channel-$(date +%Y%m%d-%H%M%S).json"
```

---

### 19. AWS Config Managed Rules (TSC: CC6.1, CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Required rules for SOC 2
REQUIRED_RULES=(
  "cloudtrail-enabled"
  "cloud-trail-encryption-enabled"
  "cloud-trail-log-file-validation-enabled"
  "encrypted-volumes"
  "rds-storage-encrypted"
  "s3-bucket-server-side-encryption-enabled"
  "s3-bucket-public-read-prohibited"
  "s3-bucket-public-write-prohibited"
  "vpc-flow-logs-enabled"
  "iam-user-mfa-enabled"
  "root-account-mfa-enabled"
  "iam-password-policy"
  "restricted-ssh"
  "multi-region-cloud-trail-enabled"
  "guardduty-enabled-centralized"
)

EXISTING_RULES=$(aws configservice describe-config-rules --query 'ConfigRules[*].ConfigRuleName' --output text)

for rule in "${REQUIRED_RULES[@]}"; do
  if echo "$EXISTING_RULES" | grep -qw "$rule"; then
    compliance=$(aws configservice get-compliance-details-by-config-rule \
      --config-rule-name "$rule" \
      --compliance-types NON_COMPLIANT \
      --query 'EvaluationResults | length(@)' --output text 2>/dev/null)
    echo "DEPLOYED: $rule (non_compliant_resources=$compliance)"
  else
    echo "MISSING: $rule"
  fi
done
```
- PASS: all rules show `DEPLOYED` with 0 non-compliant resources
- FAIL: rules show `MISSING` or have non-compliant resources

**FIX** -- remediate if failing:
```bash
# Deploy all required Config rules
# Each rule uses an AWS managed source

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "cloudtrail-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "cloud-trail-encryption-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENCRYPTION_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "cloud-trail-log-file-validation-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "encrypted-volumes",
  "Source": {"Owner": "AWS", "SourceIdentifier": "ENCRYPTED_VOLUMES"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "rds-storage-encrypted",
  "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_STORAGE_ENCRYPTED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-write-prohibited",
  "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "vpc-flow-logs-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "VPC_FLOW_LOGS_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "iam-user-mfa-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_USER_MFA_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "root-account-mfa-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "iam-password-policy",
  "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_PASSWORD_POLICY"},
  "InputParameters": "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"PasswordReusePrevention\":\"24\",\"MaxPasswordAge\":\"90\"}"
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {"Owner": "AWS", "SourceIdentifier": "INCOMING_SSH_DISABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "multi-region-cloud-trail-enabled",
  "Source": {"Owner": "AWS", "SourceIdentifier": "MULTI_REGION_CLOUD_TRAIL_ENABLED"}
}'

aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "guardduty-enabled-centralized",
  "Source": {"Owner": "AWS", "SourceIdentifier": "GUARDDUTY_ENABLED_CENTRALIZED"}
}'
```
Gotchas:
- Config rules charge per evaluation (~$0.001 per evaluation)
- Rules evaluate on configuration changes and/or periodically (default: every 24h)
- Some rules (like `root-account-mfa-enabled`) are periodic-only since there is no config change event
- The `iam-password-policy` rule needs input parameters to match your password policy

**VERIFY** -- confirm the fix:
```bash
aws configservice describe-config-rules \
  --query 'ConfigRules[*].{Name:ConfigRuleName,State:ConfigRuleState}' \
  --output table
# Expected: all 15 rules in ACTIVE state

# Force re-evaluation
for rule in "${REQUIRED_RULES[@]}"; do
  aws configservice start-config-rules-evaluation --config-rule-names "$rule" 2>/dev/null
done
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Config Rules ==="
  aws configservice describe-config-rules \
    --query 'ConfigRules[*].{Name:ConfigRuleName,State:ConfigRuleState,Source:Source.SourceIdentifier}'
  echo "=== Compliance Summary ==="
  aws configservice describe-compliance-by-config-rule \
    --query 'ComplianceByConfigRules[*].{Rule:ConfigRuleName,Compliance:Compliance.ComplianceType}'
} > "$EVIDENCE_DIR/config-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

## S3 Controls

### 20. S3 Default Encryption (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  enc=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "NO_ENCRYPTION: $bucket"
  else
    algo=$(echo "$enc" | python3 -c "import sys,json; rules=json.load(sys.stdin)['ServerSideEncryptionConfiguration']['Rules']; print(rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'])" 2>/dev/null)
    echo "ENCRYPTED: $bucket algo=$algo"
  fi
done
```
- PASS: all buckets show `ENCRYPTED` with `AES256` or `aws:kms`
- FAIL: any bucket shows `NO_ENCRYPTION`

Note: As of January 2023, Amazon S3 applies server-side encryption with S3 managed keys (SSE-S3) as the base level of encryption for every new bucket. However, this check confirms it is explicitly configured and auditors prefer explicit configuration.

**FIX** -- remediate if failing:
```bash
BUCKET="the-bucket"

# Enable AES-256 (SSE-S3) -- simplest option
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
      "BucketKeyEnabled": true
    }]
  }'

# OR enable KMS (for buckets with sensitive data)
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "alias/s3-data-key"
      },
      "BucketKeyEnabled": true
    }]
  }'
```
Gotchas:
- **Default encryption only applies to NEW objects** -- existing unencrypted objects remain unencrypted
- To encrypt existing objects, copy them in-place: `aws s3 cp s3://bucket/ s3://bucket/ --recursive --sse AES256`
- `BucketKeyEnabled: true` reduces KMS costs by reducing KMS API calls
- The in-place copy preserves metadata but generates new versions (if versioning is on)

**VERIFY** -- confirm the fix:
```bash
aws s3api get-bucket-encryption --bucket "$BUCKET"
# Expected: SSEAlgorithm is AES256 or aws:kms
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    enc=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>&1)
    echo "{\"bucket\": \"$bucket\", \"encryption\": $enc},"
  done
} > "$EVIDENCE_DIR/s3-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 21. S3 Public Access Block (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Account-level block
echo "=== Account Level ==="
aws s3control get-public-access-block --account-id "$AWS_ACCOUNT_ID"

# Bucket-level block
echo "=== Bucket Level ==="
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  block=$(aws s3api get-public-access-block --bucket "$bucket" 2>&1)
  if echo "$block" | grep -q "NoSuchPublicAccessBlockConfiguration"; then
    echo "NO_BLOCK: $bucket"
  else
    echo "HAS_BLOCK: $bucket"
    echo "$block" | python3 -c "
import sys, json
config = json.load(sys.stdin)['PublicAccessBlockConfiguration']
for k,v in config.items():
    if not v:
        print(f'  WARNING: {k}=false')
" 2>/dev/null
  fi
done
```
- PASS: account-level block has all four settings true, all buckets have blocks
- FAIL: any setting is false or any bucket lacks a block

**FIX** -- remediate if failing:
```bash
# Account-level block (applies to ALL buckets)
aws s3control put-public-access-block --account-id "$AWS_ACCOUNT_ID" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Per-bucket block (belt and suspenders)
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api put-public-access-block --bucket "$bucket" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done
```
Gotchas:
- If you use S3 for static website hosting or public assets, those buckets need an exception
- Account-level block overrides bucket-level settings -- be careful with the order
- CloudFront distributions with S3 origins should use Origin Access Control (OAC) instead of public buckets

**VERIFY** -- confirm the fix:
```bash
aws s3control get-public-access-block --account-id "$AWS_ACCOUNT_ID"
# Expected: all four values are true
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Account Level ==="
  aws s3control get-public-access-block --account-id "$AWS_ACCOUNT_ID"
  echo "=== Bucket Level ==="
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo "--- $bucket ---"
    aws s3api get-public-access-block --bucket "$bucket" 2>&1
  done
} > "$EVIDENCE_DIR/s3-public-access-$(date +%Y%m%d-%H%M%S).json"
```

---

### 22. S3 Versioning (TSC: CC6.1, A1.2)

**DISCOVER** -- check current state:
```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  status=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
  if [ "$status" = "None" ] || [ -z "$status" ]; then
    echo "DISABLED: $bucket"
  else
    echo "$status: $bucket"
  fi
done
```
- PASS: critical buckets (logs, backups, data) show `Enabled`
- FAIL: critical buckets show `DISABLED` or `Suspended`

**FIX** -- remediate if failing:
```bash
BUCKET="the-critical-bucket"
aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
```
Gotchas:
- Versioning cannot be disabled once enabled -- only suspended (existing versions persist)
- Versioning increases storage costs (every overwrite keeps old version)
- Combine with lifecycle rules to expire old versions after N days
- Critical buckets include: CloudTrail logs, Config logs, backups, application data

**VERIFY** -- confirm the fix:
```bash
aws s3api get-bucket-versioning --bucket "$BUCKET"
# Expected: Status=Enabled
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    status=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
    echo "{\"bucket\": \"$bucket\", \"versioning\": \"$status\"},"
  done
} > "$EVIDENCE_DIR/s3-versioning-$(date +%Y%m%d-%H%M%S).json"
```

---

### 23. S3 Access Logging (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  logging=$(aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)
  if [ "$logging" = "None" ] || [ -z "$logging" ]; then
    echo "NO_LOGGING: $bucket"
  else
    echo "LOGGING: $bucket -> $logging"
  fi
done
```
- PASS: all buckets with sensitive data have logging enabled
- FAIL: critical buckets lack access logging

**FIX** -- remediate if failing:
```bash
# Create a dedicated logging bucket (if not existing)
LOG_BUCKET="${AWS_ACCOUNT_ID}-s3-access-logs"
aws s3api create-bucket --bucket "$LOG_BUCKET" \
  --create-bucket-configuration LocationConstraint=$(aws configure get region)

aws s3api put-public-access-block --bucket "$LOG_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable logging on a target bucket
BUCKET="the-bucket"
aws s3api put-bucket-logging --bucket "$BUCKET" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "'"$LOG_BUCKET"'",
      "TargetPrefix": "'"$BUCKET"'/"
    }
  }'
```
Gotchas:
- The logging bucket must be in the same region as the source bucket
- Do NOT enable logging on the logging bucket itself (creates infinite loop)
- S3 server access logs can take hours to appear -- they are best-effort delivery
- For real-time, use CloudTrail data events (more expensive but reliable)

**VERIFY** -- confirm the fix:
```bash
aws s3api get-bucket-logging --bucket "$BUCKET"
# Expected: LoggingEnabled with TargetBucket set
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    logging=$(aws s3api get-bucket-logging --bucket "$bucket" 2>&1)
    echo "{\"bucket\": \"$bucket\", \"logging\": $logging},"
  done
} > "$EVIDENCE_DIR/s3-access-logging-$(date +%Y%m%d-%H%M%S).json"
```

---

### 24. S3 Lifecycle Policies (TSC: A1.2)

**DISCOVER** -- check current state:
```bash
# Check lifecycle on log buckets (CloudTrail, Config, access logs)
LOG_BUCKETS=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | grep -E 'log|trail|config')

for bucket in $LOG_BUCKETS; do
  lifecycle=$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" 2>&1)
  if echo "$lifecycle" | grep -q "NoSuchLifecycleConfiguration"; then
    echo "NO_LIFECYCLE: $bucket"
  else
    echo "HAS_LIFECYCLE: $bucket"
  fi
done
```
- PASS: all log buckets have lifecycle policies
- FAIL: any log bucket lacks a lifecycle policy

**FIX** -- remediate if failing:
```bash
BUCKET="the-log-bucket"
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "TransitionToIA",
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "Transitions": [
          {"Days": 30, "StorageClass": "STANDARD_IA"},
          {"Days": 90, "StorageClass": "GLACIER"},
          {"Days": 365, "StorageClass": "DEEP_ARCHIVE"}
        ]
      },
      {
        "ID": "ExpireOldVersions",
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 90}
      },
      {
        "ID": "AbortIncompleteMultipart",
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
      }
    ]
  }'
```
Gotchas:
- Adjust retention based on your compliance requirements (SOC 2 typically needs 1 year minimum)
- DEEP_ARCHIVE has 12-48h retrieval time and 180-day minimum storage charge
- `NoncurrentVersionExpiration` only applies when versioning is enabled
- `AbortIncompleteMultipartUpload` prevents orphaned multipart uploads from accumulating

**VERIFY** -- confirm the fix:
```bash
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET"
# Expected: rules with transitions and expiration
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for bucket in $LOG_BUCKETS; do
    echo "--- $bucket ---"
    aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" 2>&1
  done
} > "$EVIDENCE_DIR/s3-lifecycle-$(date +%Y%m%d-%H%M%S).json"
```

---

## RDS Controls

### 25. RDS Storage Encryption (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted,KmsKey:KmsKeyId,Engine:Engine,Status:DBInstanceStatus}' \
  --output table
```
- PASS: all instances show `Encrypted: True`
- FAIL: any instance shows `Encrypted: False`

**FIX** -- remediate if failing:
```
CRITICAL: You CANNOT enable encryption on an existing unencrypted RDS instance in-place.
You must snapshot, copy the snapshot with encryption, and restore from the encrypted snapshot.
This causes downtime.
```

```bash
DB_ID="the-unencrypted-instance"
KMS_KEY="alias/rds-encryption-key"

# Step 1: Create snapshot of unencrypted instance
aws rds create-db-snapshot \
  --db-instance-identifier "$DB_ID" \
  --db-snapshot-identifier "${DB_ID}-pre-encryption-snapshot"

# Wait for snapshot to complete
aws rds wait db-snapshot-available \
  --db-snapshot-identifier "${DB_ID}-pre-encryption-snapshot"

# Step 2: Copy snapshot with encryption enabled
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier "${DB_ID}-pre-encryption-snapshot" \
  --target-db-snapshot-identifier "${DB_ID}-encrypted-snapshot" \
  --kms-key-id "$KMS_KEY"

aws rds wait db-snapshot-available \
  --db-snapshot-identifier "${DB_ID}-encrypted-snapshot"

# Step 3: Record current instance config (for restore)
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  > /tmp/rds-config-backup.json

# Step 4: Rename old instance (to free up the identifier)
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --new-db-instance-identifier "${DB_ID}-unencrypted-old" \
  --apply-immediately

aws rds wait db-instance-available \
  --db-instance-identifier "${DB_ID}-unencrypted-old"

# Step 5: Restore from encrypted snapshot with same identifier
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$DB_ID" \
  --db-snapshot-identifier "${DB_ID}-encrypted-snapshot"

aws rds wait db-instance-available --db-instance-identifier "$DB_ID"

# Step 6: Update application connection strings if endpoint changed
# Step 7: Verify, then delete old unencrypted instance
# aws rds delete-db-instance --db-instance-identifier "${DB_ID}-unencrypted-old" --skip-final-snapshot
```
Gotchas:
- **This is a destructive operation that causes downtime** -- plan a maintenance window
- The new instance will have a different endpoint unless you use the same identifier
- Security groups, parameter groups, and option groups must be re-attached
- Read replicas cannot be encrypted if the primary is not -- encrypt primary first
- For Aurora, the entire cluster must be encrypted or unencrypted

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  --query 'DBInstances[0].{Encrypted:StorageEncrypted,KmsKey:KmsKeyId}'
# Expected: Encrypted=true, KmsKey=<key ARN>
```

**EVIDENCE** -- capture for auditor:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted,KmsKey:KmsKeyId,Engine:Engine}' \
  > "$EVIDENCE_DIR/rds-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 26. RDS SSL/TLS Enforcement (TSC: CC6.1, CC6.7)

**DISCOVER** -- check current state:
```bash
# Check parameter groups for rds.force_ssl
for db in $(aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output text); do
  pg=$(aws rds describe-db-instances --db-instance-identifier "$db" \
    --query 'DBInstances[0].DBParameterGroups[0].DBParameterGroupName' --output text)
  ssl=$(aws rds describe-db-parameters --db-parameter-group-name "$pg" \
    --query "Parameters[?ParameterName=='rds.force_ssl'].ParameterValue" --output text 2>/dev/null)
  echo "$db: parameter_group=$pg force_ssl=$ssl"
done
```
- PASS: `force_ssl=1` for all instances
- FAIL: `force_ssl=0` or empty

**FIX** -- remediate if failing:
```bash
# Create a custom parameter group (if using default)
PARAM_GROUP="soc2-postgres14"
aws rds create-db-parameter-group \
  --db-parameter-group-name "$PARAM_GROUP" \
  --db-parameter-group-family postgres14 \
  --description "SOC2 compliant parameters for PostgreSQL 14"

# Set force_ssl
aws rds modify-db-parameter-group \
  --db-parameter-group-name "$PARAM_GROUP" \
  --parameters "ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=pending-reboot"

# Attach to instance
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --db-parameter-group-name "$PARAM_GROUP" \
  --apply-immediately

# Reboot to apply (force_ssl requires reboot)
aws rds reboot-db-instance --db-instance-identifier "$DB_ID"
```
Gotchas:
- `rds.force_ssl` requires a reboot to take effect -- plan accordingly
- For MySQL, use `require_secure_transport=1` instead of `rds.force_ssl`
- For Aurora PostgreSQL, use the cluster parameter group
- Applications must use SSL connections after this -- update connection strings with `sslmode=require`

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-parameters --db-parameter-group-name "$PARAM_GROUP" \
  --query "Parameters[?ParameterName=='rds.force_ssl'].{Name:ParameterName,Value:ParameterValue}"
# Expected: Value=1
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for db in $(aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output text); do
    pg=$(aws rds describe-db-instances --db-instance-identifier "$db" \
      --query 'DBInstances[0].DBParameterGroups[0].DBParameterGroupName' --output text)
    echo "--- $db (param_group=$pg) ---"
    aws rds describe-db-parameters --db-parameter-group-name "$pg" \
      --query "Parameters[?ParameterName=='rds.force_ssl' || ParameterName=='require_secure_transport']"
  done
} > "$EVIDENCE_DIR/rds-ssl-enforcement-$(date +%Y%m%d-%H%M%S).json"
```

---

### 27. RDS Automated Backups (TSC: A1.2)

**DISCOVER** -- check current state:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,BackupWindow:PreferredBackupWindow,LatestRestore:LatestRestorableTime}' \
  --output table
```
- PASS: all instances show `BackupRetention >= 7`
- FAIL: any instance shows `BackupRetention: 0` (backups disabled) or `< 7`

**FIX** -- remediate if failing:
```bash
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --backup-retention-period 14 \
  --preferred-backup-window "03:00-04:00" \
  --apply-immediately
```
Gotchas:
- Setting `BackupRetentionPeriod` to 0 disables backups entirely -- never do this in production
- SOC 2 auditors typically expect at least 7 days; 14-35 is recommended
- Backup window should be during low-traffic period
- Enabling backups on a previously-unbackupped instance causes a brief I/O suspension

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  --query 'DBInstances[0].{BackupRetention:BackupRetentionPeriod,BackupWindow:PreferredBackupWindow}'
# Expected: BackupRetention=14
```

**EVIDENCE** -- capture for auditor:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,BackupWindow:PreferredBackupWindow,LatestRestore:LatestRestorableTime}' \
  > "$EVIDENCE_DIR/rds-backups-$(date +%Y%m%d-%H%M%S).json"
```

---

### 28. RDS Multi-AZ (TSC: A1.1, A1.2)

**DISCOVER** -- check current state:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,MultiAZ:MultiAZ,Engine:Engine,Class:DBInstanceClass}' \
  --output table
```
- PASS: all production instances show `MultiAZ: True`
- FAIL: production instances show `MultiAZ: False`

**FIX** -- remediate if failing:
```bash
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --multi-az \
  --apply-immediately
```
Gotchas:
- Enabling Multi-AZ causes a brief failover (~60s downtime)
- Multi-AZ roughly doubles the RDS cost
- Dev/staging environments typically do not need Multi-AZ -- document the exception
- Aurora uses a different HA model (multi-AZ by default with 6-way replication)

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  --query 'DBInstances[0].{MultiAZ:MultiAZ,SecondaryAZ:SecondaryAvailabilityZone}'
# Expected: MultiAZ=true
```

**EVIDENCE** -- capture for auditor:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,MultiAZ:MultiAZ,AvailabilityZone:AvailabilityZone}' \
  > "$EVIDENCE_DIR/rds-multi-az-$(date +%Y%m%d-%H%M%S).json"
```

---

### 29. RDS Public Accessibility (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,PubliclyAccessible:PubliclyAccessible,Endpoint:Endpoint.Address}' \
  --output table
```
- PASS: all production instances show `PubliclyAccessible: False`
- FAIL: any production instance shows `PubliclyAccessible: True`

**FIX** -- remediate if failing:
```bash
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --no-publicly-accessible \
  --apply-immediately
```
Gotchas:
- Changing public accessibility requires the instance to be in a VPC
- Applications connecting from outside the VPC need a VPN, bastion host, or RDS Proxy
- This change may cause brief connectivity interruption
- Even with `PubliclyAccessible: true`, the security group must still allow inbound traffic

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  --query 'DBInstances[0].PubliclyAccessible'
# Expected: false
```

**EVIDENCE** -- capture for auditor:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,PubliclyAccessible:PubliclyAccessible,VPC:DBSubnetGroup.VpcId}' \
  > "$EVIDENCE_DIR/rds-public-access-$(date +%Y%m%d-%H%M%S).json"
```

---

### 30. RDS Enhanced Monitoring (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,MonitoringInterval:MonitoringInterval,MonitoringRole:MonitoringRoleArn}' \
  --output table
```
- PASS: `MonitoringInterval >= 1` (1, 5, 10, 15, 30, or 60 seconds)
- FAIL: `MonitoringInterval: 0` (enhanced monitoring disabled)

**FIX** -- remediate if failing:
```bash
# Create IAM role for enhanced monitoring
aws iam create-role --role-name rds-monitoring-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "monitoring.rds.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy --role-name rds-monitoring-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole

# Enable enhanced monitoring (60s interval is usually sufficient)
aws rds modify-db-instance \
  --db-instance-identifier "$DB_ID" \
  --monitoring-interval 60 \
  --monitoring-role-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:role/rds-monitoring-role" \
  --apply-immediately
```
Gotchas:
- Enhanced monitoring data is sent to CloudWatch Logs under the `RDSOSMetrics` log group
- Lower intervals (1s) provide more detail but cost more
- 60s is sufficient for SOC 2 compliance; 5s is useful for performance debugging
- Free tier includes 25 enhanced monitoring metrics

**VERIFY** -- confirm the fix:
```bash
aws rds describe-db-instances --db-instance-identifier "$DB_ID" \
  --query 'DBInstances[0].{MonitoringInterval:MonitoringInterval,MonitoringRole:MonitoringRoleArn}'
# Expected: MonitoringInterval=60, MonitoringRole=<role ARN>
```

**EVIDENCE** -- capture for auditor:
```bash
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,MonitoringInterval:MonitoringInterval,MonitoringRole:MonitoringRoleArn}' \
  > "$EVIDENCE_DIR/rds-monitoring-$(date +%Y%m%d-%H%M%S).json"
```

---

## VPC Controls

### 31. VPC Flow Logs (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
  flows=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" \
    --query 'FlowLogs[*].{Id:FlowLogId,Status:FlowLogStatus,Destination:LogDestinationType}' --output json)
  count=$(echo "$flows" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
  if [ "$count" = "0" ]; then
    echo "NO_FLOW_LOGS: $vpc"
  else
    echo "HAS_FLOW_LOGS: $vpc ($count logs)"
  fi
done
```
- PASS: all VPCs have at least one active flow log
- FAIL: any VPC shows `NO_FLOW_LOGS`

**FIX** -- remediate if failing:
```bash
VPC_ID="vpc-12345678"

# Option A: Send to CloudWatch Logs (easier to query, more expensive)
aws logs create-log-group --log-group-name "/vpc/flow-logs/${VPC_ID}"
aws logs put-retention-policy --log-group-name "/vpc/flow-logs/${VPC_ID}" --retention-in-days 365

# Create IAM role for flow logs
aws iam create-role --role-name VPCFlowLogsRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy --role-name VPCFlowLogsRole \
  --policy-name VPCFlowLogsPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }]
  }'

aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids "$VPC_ID" \
  --traffic-type ALL \
  --log-group-name "/vpc/flow-logs/${VPC_ID}" \
  --deliver-logs-permission-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:role/VPCFlowLogsRole"

# Option B: Send to S3 (cheaper for high-volume, harder to query)
# aws ec2 create-flow-logs \
#   --resource-type VPC \
#   --resource-ids "$VPC_ID" \
#   --traffic-type ALL \
#   --log-destination-type s3 \
#   --log-destination "arn:aws:s3:::${AWS_ACCOUNT_ID}-vpc-flow-logs"
```
Gotchas:
- **Cost considerations**: CloudWatch Logs costs ~$0.50/GB ingested; S3 is ~$0.023/GB stored
- High-traffic VPCs can generate GBs of flow logs per day -- estimate costs first
- `traffic-type ALL` captures accept and reject; use `REJECT` only if you want to reduce volume
- Flow logs do not capture DNS traffic, DHCP traffic, or traffic to the instance metadata service

**VERIFY** -- confirm the fix:
```bash
aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$VPC_ID" \
  --query 'FlowLogs[*].{Id:FlowLogId,Status:FlowLogStatus,Destination:LogDestinationType}'
# Expected: at least one flow log with Status=ACTIVE
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
    echo "--- $vpc ---"
    aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc"
  done
} > "$EVIDENCE_DIR/vpc-flow-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

### 32. Security Groups Audit (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Find security groups with 0.0.0.0/0 ingress on sensitive ports
SENSITIVE_PORTS="22 3389 3306 5432 1433 6379 27017 9200 11211"

for sg in $(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text); do
  for port in $SENSITIVE_PORTS; do
    open=$(aws ec2 describe-security-groups --group-ids "$sg" \
      --query "SecurityGroups[0].IpPermissions[?
        (FromPort<=\`$port\` && ToPort>=\`$port\`) &&
        (IpRanges[?CidrIp=='0.0.0.0/0'] || Ipv6Ranges[?CidrIpv6=='::/0'])
      ]" --output text)
    if [ -n "$open" ] && [ "$open" != "None" ]; then
      name=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].GroupName' --output text)
      echo "OPEN: sg=$sg name=$name port=$port (0.0.0.0/0)"
    fi
  done
done
```
- PASS: no output
- FAIL: lists security groups with open sensitive ports

**FIX** -- remediate if failing:
```bash
SG_ID="sg-12345678"
PORT=22

# Remove the offending 0.0.0.0/0 rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port "$PORT" \
  --cidr 0.0.0.0/0

# Add restricted rule (e.g., VPN CIDR only)
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port "$PORT" \
  --cidr 10.0.0.0/8
```
Gotchas:
- Port 22 (SSH): use Session Manager instead of SSH where possible (no open ports needed)
- Port 3389 (RDP): use Fleet Manager or a bastion host
- Database ports (3306, 5432, etc.): should only be accessible from application subnets
- Always restrict to specific CIDRs -- never 0.0.0.0/0 for anything except 80/443 on public ALBs

**VERIFY** -- confirm the fix:
```bash
aws ec2 describe-security-groups --group-ids "$SG_ID" \
  --query 'SecurityGroups[0].IpPermissions'
# Expected: no rules with 0.0.0.0/0 on sensitive ports
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Security Groups with Open Sensitive Ports ==="
  for sg in $(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text); do
    name=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].GroupName' --output text)
    rules=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions')
    echo "{\"sg\": \"$sg\", \"name\": \"$name\", \"inbound_rules\": $rules},"
  done
} > "$EVIDENCE_DIR/security-groups-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

### 33. Default Security Group Restricted (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
  default_sg=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$vpc" "Name=group-name,Values=default" \
    --query 'SecurityGroups[0].GroupId' --output text)

  inbound=$(aws ec2 describe-security-groups --group-ids "$default_sg" \
    --query 'SecurityGroups[0].IpPermissions | length(@)')
  outbound=$(aws ec2 describe-security-groups --group-ids "$default_sg" \
    --query 'SecurityGroups[0].IpPermissionsEgress | length(@)')

  if [ "$inbound" = "0" ] && [ "$outbound" = "0" ]; then
    echo "RESTRICTED: $vpc default_sg=$default_sg"
  else
    echo "OPEN: $vpc default_sg=$default_sg inbound_rules=$inbound outbound_rules=$outbound"
  fi
done
```
- PASS: all default security groups have 0 inbound and 0 outbound rules
- FAIL: any default security group has rules

**FIX** -- remediate if failing:
```bash
DEFAULT_SG="sg-12345678"

# Remove all inbound rules
aws ec2 describe-security-groups --group-ids "$DEFAULT_SG" \
  --query 'SecurityGroups[0].IpPermissions' --output json > /tmp/inbound.json

if [ "$(cat /tmp/inbound.json)" != "[]" ]; then
  aws ec2 revoke-security-group-ingress --group-id "$DEFAULT_SG" --ip-permissions file:///tmp/inbound.json
fi

# Remove all outbound rules
aws ec2 describe-security-groups --group-ids "$DEFAULT_SG" \
  --query 'SecurityGroups[0].IpPermissionsEgress' --output json > /tmp/outbound.json

if [ "$(cat /tmp/outbound.json)" != "[]" ]; then
  aws ec2 revoke-security-group-egress --group-id "$DEFAULT_SG" --ip-permissions file:///tmp/outbound.json
fi
```
Gotchas:
- You cannot delete the default security group -- only remove its rules
- Any resource launched without specifying a security group gets the default
- After restricting, ensure no existing resources rely on the default security group

**VERIFY** -- confirm the fix:
```bash
aws ec2 describe-security-groups --group-ids "$DEFAULT_SG" \
  --query 'SecurityGroups[0].{Inbound:IpPermissions,Outbound:IpPermissionsEgress}'
# Expected: Inbound=[], Outbound=[]
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
    default_sg=$(aws ec2 describe-security-groups \
      --filters "Name=vpc-id,Values=$vpc" "Name=group-name,Values=default" \
      --query 'SecurityGroups[0].GroupId' --output text)
    echo "--- VPC: $vpc Default SG: $default_sg ---"
    aws ec2 describe-security-groups --group-ids "$default_sg"
  done
} > "$EVIDENCE_DIR/default-sg-$(date +%Y%m%d-%H%M%S).json"
```

---

### 34. NACLs Documented (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
  echo "=== VPC: $vpc ==="
  aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$vpc" \
    --query 'NetworkAcls[*].{Id:NetworkAclId,IsDefault:IsDefault,InboundRules:Entries[?Egress==`false`].{RuleNum:RuleNumber,Action:RuleAction,CIDR:CidrBlock,Protocol:Protocol,Ports:PortRange},OutboundRules:Entries[?Egress==`true`].{RuleNum:RuleNumber,Action:RuleAction,CIDR:CidrBlock,Protocol:Protocol,Ports:PortRange}}' \
    --output json
done
```
- PASS: NACLs are documented, default NACLs are used (allow all -- security groups handle filtering), or custom NACLs with justified deny rules
- FAIL: custom NACLs exist without documentation or with overly permissive rules

**FIX** -- remediate if failing:
```bash
# NACLs are typically left as default (allow all) with security groups doing the filtering.
# If custom NACLs are needed, create them explicitly:

NACL_ID="acl-12345678"

# Example: deny specific traffic on a NACL
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=3389,To=3389 \
  --cidr-block 0.0.0.0/0 \
  --rule-action deny \
  --ingress
```
Gotchas:
- NACLs are stateless -- you must configure both inbound and outbound rules
- NACLs are evaluated in rule number order -- lower numbers first
- The default NACL allows all traffic -- this is intentional when security groups are the primary control
- Custom NACLs should be documented with justification for each rule

**VERIFY** -- confirm the fix:
```bash
aws ec2 describe-network-acls --network-acl-ids "$NACL_ID" \
  --query 'NetworkAcls[0].Entries'
# Expected: rules match documented configuration
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
    echo "=== VPC: $vpc ==="
    aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$vpc"
  done
} > "$EVIDENCE_DIR/nacl-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

## KMS Controls

### 35. KMS Key Rotation (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  # Skip AWS-managed keys (they auto-rotate)
  manager=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyManager' --output text)
  if [ "$manager" = "CUSTOMER" ]; then
    state=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyState' --output text)
    if [ "$state" = "Enabled" ]; then
      rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --query 'KeyRotationEnabled' --output text 2>/dev/null)
      alias=$(aws kms list-aliases --key-id "$key_id" --query 'Aliases[0].AliasName' --output text 2>/dev/null)
      echo "key=$key_id alias=$alias rotation=$rotation"
    fi
  fi
done
```
- PASS: all customer-managed keys show `rotation=True`
- FAIL: any key shows `rotation=False`

**FIX** -- remediate if failing:
```bash
KEY_ID="the-key-id"
aws kms enable-key-rotation --key-id "$KEY_ID"
```
Gotchas:
- Automatic rotation creates new key material annually but keeps old material for decryption
- AWS-managed keys (aws/s3, aws/ebs, etc.) auto-rotate every year -- you cannot control this
- Asymmetric keys and keys in custom key stores do not support automatic rotation
- For those, you must manually rotate by creating a new key and updating aliases

**VERIFY** -- confirm the fix:
```bash
aws kms get-key-rotation-status --key-id "$KEY_ID"
# Expected: KeyRotationEnabled=true
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
    manager=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyManager' --output text)
    if [ "$manager" = "CUSTOMER" ]; then
      state=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyState' --output text)
      if [ "$state" = "Enabled" ]; then
        rotation=$(aws kms get-key-rotation-status --key-id "$key_id" 2>/dev/null)
        desc=$(aws kms describe-key --key-id "$key_id")
        echo "{\"key\": \"$key_id\", \"rotation\": $rotation, \"metadata\": $desc},"
      fi
    fi
  done
} > "$EVIDENCE_DIR/kms-rotation-$(date +%Y%m%d-%H%M%S).json"
```

---

### 36. KMS Key Policies (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  manager=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyManager' --output text)
  if [ "$manager" = "CUSTOMER" ]; then
    state=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyState' --output text)
    if [ "$state" = "Enabled" ]; then
      policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default --output text)
      # Check for overly permissive grants (Principal: *)
      if echo "$policy" | grep -q '"Principal":\s*"\*"' || echo "$policy" | grep -q '"AWS":\s*"\*"'; then
        alias=$(aws kms list-aliases --key-id "$key_id" --query 'Aliases[0].AliasName' --output text 2>/dev/null)
        echo "OVERLY_PERMISSIVE: key=$key_id alias=$alias"
      fi

      # Check for grants
      grants=$(aws kms list-grants --key-id "$key_id" --query 'Grants | length(@)' --output text)
      if [ "$grants" != "0" ]; then
        alias=$(aws kms list-aliases --key-id "$key_id" --query 'Aliases[0].AliasName' --output text 2>/dev/null)
        echo "HAS_GRANTS: key=$key_id alias=$alias grant_count=$grants"
      fi
    fi
  fi
done
```
- PASS: no overly permissive key policies, grants are justified
- FAIL: keys with `Principal: *` or unexplained grants

**FIX** -- remediate if failing:
```bash
# Replace overly permissive key policy with a restrictive one
KEY_ID="the-key-id"
aws kms put-key-policy --key-id "$KEY_ID" --policy-name default --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyAdmin",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'"$AWS_ACCOUNT_ID"':root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyUsage",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'"$AWS_ACCOUNT_ID"':role/ApplicationRole"},
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}'

# Revoke unnecessary grants
GRANT_ID="the-grant-id"
aws kms revoke-grant --key-id "$KEY_ID" --grant-id "$GRANT_ID"
```
Gotchas:
- The root account statement (`arn:aws:iam::ACCOUNT:root`) is required -- without it you can lock yourself out
- Be careful with `kms:*` -- only key administrators should have full access
- Grants are used by AWS services (EBS, RDS) -- do not revoke service grants

**VERIFY** -- confirm the fix:
```bash
aws kms get-key-policy --key-id "$KEY_ID" --policy-name default --output text | python3 -m json.tool
# Expected: no Principal: * statements (except through root account)
```

**EVIDENCE** -- capture for auditor:
```bash
{
  for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
    manager=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyManager' --output text)
    if [ "$manager" = "CUSTOMER" ]; then
      state=$(aws kms describe-key --key-id "$key_id" --query 'KeyMetadata.KeyState' --output text)
      if [ "$state" = "Enabled" ]; then
        echo "--- key=$key_id ---"
        aws kms get-key-policy --key-id "$key_id" --policy-name default
        echo "grants:"
        aws kms list-grants --key-id "$key_id"
      fi
    fi
  done
} > "$EVIDENCE_DIR/kms-policies-$(date +%Y%m%d-%H%M%S).json"
```

---

### 37. KMS Usage Audit via CloudTrail (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check that CloudTrail is logging KMS events
aws cloudtrail get-event-selectors --trail-name soc2-audit-trail \
  --query 'EventSelectors[*].{ReadWriteType:ReadWriteType,IncludeManagementEvents:IncludeManagementEvents}'

# KMS operations are management events -- if IncludeManagementEvents=true, they are logged
# Verify by querying recent KMS events:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com \
  --max-results 5 \
  --query 'Events[*].{Time:EventTime,Name:EventName,User:Username}'
```
- PASS: `IncludeManagementEvents: true` and KMS events appear in CloudTrail
- FAIL: management events not included, or no KMS events found

**FIX** -- remediate if failing:
```bash
# Ensure management events are included (they are by default)
aws cloudtrail put-event-selectors --trail-name soc2-audit-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": []
  }]'
```
Gotchas:
- KMS operations are management events by default -- no special configuration needed
- High-volume KMS operations (Decrypt, GenerateDataKey) can generate many events
- If you need KMS data events specifically, add them to event selectors (increases cost)

**VERIFY** -- confirm the fix:
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com \
  --max-results 3 \
  --query 'Events[*].{Time:EventTime,Name:EventName}'
# Expected: recent KMS events (CreateKey, Encrypt, Decrypt, etc.)
```

**EVIDENCE** -- capture for auditor:
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com \
  --max-results 50 \
  > "$EVIDENCE_DIR/kms-audit-trail-$(date +%Y%m%d-%H%M%S).json"
```

---

## CloudWatch Controls

### 38. Log Group Retention (TSC: CC7.1, A1.2)

**DISCOVER** -- check current state:
```bash
# Find log groups with no retention (infinite) or < 365 days
aws logs describe-log-groups \
  --query 'logGroups[?retentionInDays==null || retentionInDays<`365`].{Name:logGroupName,Retention:retentionInDays}' \
  --output table
```
- PASS: no security-related log groups with retention < 365 days
- FAIL: security log groups with short or no retention

**FIX** -- remediate if failing:
```bash
# Set retention on all security log groups
SECURITY_LOG_GROUPS=(
  "/cloudtrail/soc2-audit-trail"
  "/vpc/flow-logs"
  "RDSOSMetrics"
)

for lg in "${SECURITY_LOG_GROUPS[@]}"; do
  # Match partial names
  for match in $(aws logs describe-log-groups --log-group-name-prefix "$lg" \
    --query 'logGroups[*].logGroupName' --output text); do
    aws logs put-retention-policy --log-group-name "$match" --retention-in-days 365
    echo "Set retention=365d on $match"
  done
done
```
Gotchas:
- Retention applies to new log data -- existing data older than the retention period is deleted
- Valid retention values: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
- No retention = infinite retention (expensive) -- always set a retention
- CloudWatch Logs storage costs ~$0.03/GB/month

**VERIFY** -- confirm the fix:
```bash
aws logs describe-log-groups \
  --query 'logGroups[*].{Name:logGroupName,Retention:retentionInDays}' \
  --output table
# Expected: all security log groups show 365 or higher
```

**EVIDENCE** -- capture for auditor:
```bash
aws logs describe-log-groups \
  --query 'logGroups[*].{Name:logGroupName,Retention:retentionInDays,StoredBytes:storedBytes}' \
  > "$EVIDENCE_DIR/log-retention-$(date +%Y%m%d-%H%M%S).json"
```

---

### 39. CloudWatch Metric Filters (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
CLOUDTRAIL_LOG_GROUP="/cloudtrail/soc2-audit-trail"

# Required metric filters for SOC 2 (CIS Benchmark 3.x)
REQUIRED_FILTERS=(
  "unauthorized-api-calls"
  "root-account-usage"
  "console-signin-failures"
  "iam-policy-changes"
  "cloudtrail-config-changes"
  "s3-bucket-policy-changes"
  "security-group-changes"
  "nacl-changes"
  "network-gateway-changes"
  "route-table-changes"
  "vpc-changes"
)

EXISTING=$(aws logs describe-metric-filters \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --query 'metricFilters[*].filterName' --output text 2>/dev/null)

for filter in "${REQUIRED_FILTERS[@]}"; do
  if echo "$EXISTING" | grep -qw "$filter"; then
    echo "EXISTS: $filter"
  else
    echo "MISSING: $filter"
  fi
done
```
- PASS: all required filters exist
- FAIL: any filter is missing

**FIX** -- remediate if failing:
```bash
CLOUDTRAIL_LOG_GROUP="/cloudtrail/soc2-audit-trail"
NAMESPACE="SOC2/CloudTrailMetrics"

# 1. Unauthorized API calls
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name unauthorized-api-calls \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedAccess") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICalls,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 2. Root account usage
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name root-account-usage \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountUsage,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 3. Console sign-in failures
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name console-signin-failures \
  --filter-pattern '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }' \
  --metric-transformations \
    metricName=ConsoleSigninFailures,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 4. IAM policy changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name iam-policy-changes \
  --filter-pattern '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }' \
  --metric-transformations \
    metricName=IAMPolicyChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 5. CloudTrail configuration changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name cloudtrail-config-changes \
  --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
  --metric-transformations \
    metricName=CloudTrailConfigChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 6. S3 bucket policy changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name s3-bucket-policy-changes \
  --filter-pattern '{ ($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication) }' \
  --metric-transformations \
    metricName=S3BucketPolicyChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 7. Security group changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name security-group-changes \
  --filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }' \
  --metric-transformations \
    metricName=SecurityGroupChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 8. NACL changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name nacl-changes \
  --filter-pattern '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }' \
  --metric-transformations \
    metricName=NACLChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 9. Network gateway changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name network-gateway-changes \
  --filter-pattern '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }' \
  --metric-transformations \
    metricName=NetworkGatewayChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 10. Route table changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name route-table-changes \
  --filter-pattern '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }' \
  --metric-transformations \
    metricName=RouteTableChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0

# 11. VPC changes
aws logs put-metric-filter \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --filter-name vpc-changes \
  --filter-pattern '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }' \
  --metric-transformations \
    metricName=VPCChanges,metricNamespace="$NAMESPACE",metricValue=1,defaultValue=0
```
Gotchas:
- Filter patterns are case-sensitive
- The `defaultValue=0` ensures the metric emits 0 when there are no matches (needed for alarms)
- These filters only work if CloudTrail is sending to the specified CloudWatch log group (Control 13)
- Metric filters do not process historical data -- only new events

**VERIFY** -- confirm the fix:
```bash
aws logs describe-metric-filters \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  --query 'metricFilters[*].filterName' --output table
# Expected: all 11 filters listed
```

**EVIDENCE** -- capture for auditor:
```bash
aws logs describe-metric-filters \
  --log-group-name "$CLOUDTRAIL_LOG_GROUP" \
  > "$EVIDENCE_DIR/metric-filters-$(date +%Y%m%d-%H%M%S).json"
```

---

### 40. CloudWatch Alarms for Metric Filters (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
NAMESPACE="SOC2/CloudTrailMetrics"
METRICS=(
  "UnauthorizedAPICalls"
  "RootAccountUsage"
  "ConsoleSigninFailures"
  "IAMPolicyChanges"
  "CloudTrailConfigChanges"
  "S3BucketPolicyChanges"
  "SecurityGroupChanges"
  "NACLChanges"
  "NetworkGatewayChanges"
  "RouteTableChanges"
  "VPCChanges"
)

for metric in "${METRICS[@]}"; do
  alarm=$(aws cloudwatch describe-alarms-for-metric \
    --namespace "$NAMESPACE" --metric-name "$metric" \
    --query 'MetricAlarms[0].AlarmName' --output text 2>/dev/null)
  if [ "$alarm" = "None" ] || [ -z "$alarm" ]; then
    echo "NO_ALARM: $metric"
  else
    echo "HAS_ALARM: $metric -> $alarm"
  fi
done
```
- PASS: all metrics have alarms
- FAIL: any metric lacks an alarm

**FIX** -- remediate if failing:
```bash
NAMESPACE="SOC2/CloudTrailMetrics"
SNS_TOPIC_ARN="arn:aws:sns:$(aws configure get region):${AWS_ACCOUNT_ID}:security-guardduty-alerts"

# Create alarm for each metric
# Threshold 1 means alert on any occurrence; adjust as needed

declare -A METRIC_THRESHOLDS=(
  ["UnauthorizedAPICalls"]=5
  ["RootAccountUsage"]=1
  ["ConsoleSigninFailures"]=5
  ["IAMPolicyChanges"]=1
  ["CloudTrailConfigChanges"]=1
  ["S3BucketPolicyChanges"]=1
  ["SecurityGroupChanges"]=1
  ["NACLChanges"]=1
  ["NetworkGatewayChanges"]=1
  ["RouteTableChanges"]=1
  ["VPCChanges"]=1
)

for metric in "${!METRIC_THRESHOLDS[@]}"; do
  threshold=${METRIC_THRESHOLDS[$metric]}
  aws cloudwatch put-metric-alarm \
    --alarm-name "soc2-${metric}" \
    --alarm-description "SOC 2 alert: ${metric} detected" \
    --namespace "$NAMESPACE" \
    --metric-name "$metric" \
    --statistic Sum \
    --period 300 \
    --threshold "$threshold" \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --treat-missing-data notBreaching \
    --alarm-actions "$SNS_TOPIC_ARN"
  echo "Created alarm for $metric (threshold=$threshold)"
done
```
Gotchas:
- `treat-missing-data notBreaching` prevents false alarms when no data flows
- Period of 300s (5 min) is standard -- lower periods increase cost
- UnauthorizedAPICalls and ConsoleSigninFailures use threshold 5 to reduce noise
- RootAccountUsage uses threshold 1 because any root usage is noteworthy
- The SNS topic must exist and have confirmed subscriptions (see Control 16)

**VERIFY** -- confirm the fix:
```bash
aws cloudwatch describe-alarms --alarm-name-prefix "soc2-" \
  --query 'MetricAlarms[*].{Name:AlarmName,State:StateValue,Actions:AlarmActions[0]}' \
  --output table
# Expected: all 11 alarms listed with State=OK or INSUFFICIENT_DATA
```

**EVIDENCE** -- capture for auditor:
```bash
aws cloudwatch describe-alarms --alarm-name-prefix "soc2-" \
  > "$EVIDENCE_DIR/cloudwatch-alarms-$(date +%Y%m%d-%H%M%S).json"
```

---

## Terraform Module

A complete, production-ready Terraform module that deploys all of the above controls as infrastructure-as-code.

```hcl
# ============================================================================
# SOC 2 AWS Controls - Complete Terraform Module
# ============================================================================
# Usage:
#   module "soc2" {
#     source               = "./modules/soc2-aws"
#     company_name         = "acme"
#     security_email       = "security@acme.com"
#     kms_admin_role_arn   = "arn:aws:iam::123456789012:role/SecurityAdmin"
#   }
# ============================================================================

variable "company_name" {
  description = "Company name used in resource naming"
  type        = string
}

variable "security_email" {
  description = "Email for security alerts"
  type        = string
}

variable "kms_admin_role_arn" {
  description = "ARN of the IAM role that should administer KMS keys"
  type        = string
}

variable "cloudtrail_log_retention_days" {
  description = "Retention period for CloudTrail CloudWatch logs"
  type        = number
  default     = 365
}

variable "s3_log_glacier_transition_days" {
  description = "Days before transitioning S3 logs to Glacier"
  type        = number
  default     = 90
}

variable "s3_log_expiration_days" {
  description = "Days before expiring S3 logs"
  type        = number
  default     = 2555
}

variable "rds_backup_retention_period" {
  description = "RDS backup retention period in days"
  type        = number
  default     = 14
}

variable "alarm_unauthorized_api_threshold" {
  description = "Threshold for unauthorized API call alarms"
  type        = number
  default     = 5
}

variable "alarm_signin_failure_threshold" {
  description = "Threshold for console sign-in failure alarms"
  type        = number
  default     = 5
}

variable "enabled_regions" {
  description = "List of AWS regions to enable GuardDuty in"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1"]
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

locals {
  default_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Module    = "soc2-aws"
    Purpose   = "SOC2-compliance"
  })

  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================================================
# KMS Keys
# ============================================================================

resource "aws_kms_key" "cloudtrail" {
  description             = "CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.default_tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowKeyAdmin"
        Effect    = "Allow"
        Principal = { AWS = [var.kms_admin_role_arn, "arn:aws:iam::${local.account_id}:root"] }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.company_name}-soc2-trail" }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*" }
        }
      },
      {
        Sid       = "AllowCloudTrailDescribe"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
      },
      {
        Sid       = "AllowDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = ["kms:Decrypt", "kms:ReEncryptFrom"]
        Resource  = "*"
        Condition = {
          StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*" }
        }
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.company_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.id
}

resource "aws_kms_key" "data" {
  description             = "Data encryption (S3, RDS, EBS)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.default_tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.company_name}-data"
  target_key_id = aws_kms_key.data.id
}

# ============================================================================
# S3 Buckets (CloudTrail Logs, Config Logs, Access Logs)
# ============================================================================

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.company_name}-cloudtrail-logs-${local.account_id}"
  tags   = local.default_tags
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "transition-and-expire"
    status = "Enabled"

    transition {
      days          = var.s3_log_glacier_transition_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.s3_log_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.cloudtrail.arn, "${aws_s3_bucket.cloudtrail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_s3_bucket" "config" {
  bucket = "${var.company_name}-aws-config-logs-${local.account_id}"
  tags   = local.default_tags
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# Account-level S3 public access block
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ============================================================================
# CloudTrail
# ============================================================================

resource "aws_cloudtrail" "soc2" {
  name                          = "${var.company_name}-soc2-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn
  tags                          = local.default_tags

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ============================================================================
# CloudWatch Log Groups
# ============================================================================

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudtrail/${var.company_name}-soc2-trail"
  retention_in_days = var.cloudtrail_log_retention_days
  kms_key_id        = aws_kms_key.cloudtrail.arn
  tags              = local.default_tags
}

# ============================================================================
# IAM Roles
# ============================================================================

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.company_name}-cloudtrail-cloudwatch"
  tags = local.default_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-to-cloudwatch"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_iam_role" "config" {
  name = "${var.company_name}-aws-config"
  tags = local.default_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ============================================================================
# GuardDuty
# ============================================================================

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = local.default_tags
}

# ============================================================================
# AWS Config
# ============================================================================

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# Config managed rules
locals {
  config_rules = {
    "cloudtrail-enabled"                        = "CLOUD_TRAIL_ENABLED"
    "cloud-trail-encryption-enabled"            = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    "cloud-trail-log-file-validation-enabled"   = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    "encrypted-volumes"                         = "ENCRYPTED_VOLUMES"
    "rds-storage-encrypted"                     = "RDS_STORAGE_ENCRYPTED"
    "s3-bucket-server-side-encryption-enabled"  = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    "s3-bucket-public-read-prohibited"          = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    "s3-bucket-public-write-prohibited"         = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    "vpc-flow-logs-enabled"                     = "VPC_FLOW_LOGS_ENABLED"
    "iam-user-mfa-enabled"                      = "IAM_USER_MFA_ENABLED"
    "root-account-mfa-enabled"                  = "ROOT_ACCOUNT_MFA_ENABLED"
    "restricted-ssh"                            = "INCOMING_SSH_DISABLED"
    "multi-region-cloud-trail-enabled"          = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
    "guardduty-enabled-centralized"             = "GUARDDUTY_ENABLED_CENTRALIZED"
  }
}

resource "aws_config_config_rule" "rules" {
  for_each = local.config_rules

  name = each.key
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.default_tags
}

resource "aws_config_config_rule" "iam_password_policy" {
  name = "iam-password-policy"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })
  depends_on = [aws_config_configuration_recorder.main]
  tags       = local.default_tags
}

# ============================================================================
# SNS Topic for Security Alerts
# ============================================================================

resource "aws_sns_topic" "security_alerts" {
  name = "${var.company_name}-security-alerts"
  tags = local.default_tags
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_email
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      },
      {
        Sid       = "AllowCloudWatch"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# ============================================================================
# GuardDuty EventBridge -> SNS
# ============================================================================

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.company_name}-guardduty-findings"
  description = "Forward medium+ GuardDuty findings to SNS"
  tags        = local.default_tags

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 4] }] }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "guardduty-to-sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# ============================================================================
# CloudWatch Metric Filters and Alarms
# ============================================================================

locals {
  metric_namespace = "SOC2/CloudTrailMetrics"

  metric_filters = {
    unauthorized-api-calls = {
      pattern   = "{ ($.errorCode = \"*UnauthorizedAccess\") || ($.errorCode = \"AccessDenied*\") }"
      metric    = "UnauthorizedAPICalls"
      threshold = var.alarm_unauthorized_api_threshold
    }
    root-account-usage = {
      pattern   = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      metric    = "RootAccountUsage"
      threshold = 1
    }
    console-signin-failures = {
      pattern   = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
      metric    = "ConsoleSigninFailures"
      threshold = var.alarm_signin_failure_threshold
    }
    iam-policy-changes = {
      pattern   = "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }"
      metric    = "IAMPolicyChanges"
      threshold = 1
    }
    cloudtrail-config-changes = {
      pattern   = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
      metric    = "CloudTrailConfigChanges"
      threshold = 1
    }
    s3-bucket-policy-changes = {
      pattern   = "{ ($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication) }"
      metric    = "S3BucketPolicyChanges"
      threshold = 1
    }
    security-group-changes = {
      pattern   = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
      metric    = "SecurityGroupChanges"
      threshold = 1
    }
    nacl-changes = {
      pattern   = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
      metric    = "NACLChanges"
      threshold = 1
    }
    network-gateway-changes = {
      pattern   = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
      metric    = "NetworkGatewayChanges"
      threshold = 1
    }
    route-table-changes = {
      pattern   = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
      metric    = "RouteTableChanges"
      threshold = 1
    }
    vpc-changes = {
      pattern   = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
      metric    = "VPCChanges"
      threshold = 1
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "filters" {
  for_each = local.metric_filters

  name           = each.key
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.value.metric
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarms" {
  for_each = local.metric_filters

  alarm_name          = "soc2-${each.value.metric}"
  alarm_description   = "SOC 2 alert: ${each.value.metric}"
  namespace           = local.metric_namespace
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = 300
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  tags                = local.default_tags
}

# ============================================================================
# IAM Password Policy
# ============================================================================

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}

# ============================================================================
# Outputs
# ============================================================================

output "cloudtrail_arn" {
  description = "ARN of the SOC 2 CloudTrail"
  value       = aws_cloudtrail.soc2.arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.id
}

output "config_s3_bucket" {
  description = "S3 bucket for AWS Config logs"
  value       = aws_s3_bucket.config.id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "kms_cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "kms_data_key_arn" {
  description = "KMS key ARN for data encryption"
  value       = aws_kms_key.data.arn
}
```

---

## AWS Config Auto-Remediation

Set up automatic remediation for critical controls using AWS Config rules + SSM Automation.

### Auto-Enable S3 Bucket Encryption

```bash
# Create SSM Automation document for S3 encryption
aws ssm create-document \
  --name "SOC2-EnableS3Encryption" \
  --document-type "Automation" \
  --document-format "YAML" \
  --content '{
    "schemaVersion": "0.3",
    "description": "Enable default encryption on S3 bucket",
    "assumeRole": "{{ AutomationAssumeRole }}",
    "parameters": {
      "BucketName": {"type": "String"},
      "AutomationAssumeRole": {"type": "String", "default": ""}
    },
    "mainSteps": [{
      "name": "EnableEncryption",
      "action": "aws:executeAwsApi",
      "inputs": {
        "Service": "s3",
        "Api": "PutBucketEncryption",
        "Bucket": "{{ BucketName }}",
        "ServerSideEncryptionConfiguration": {
          "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
              "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": true
          }]
        }
      }
    }]
  }'

# Create IAM role for auto-remediation
aws iam create-role --role-name SOC2-AutoRemediationRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Service": ["ssm.amazonaws.com", "config.amazonaws.com"]
      },
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy --role-name SOC2-AutoRemediationRole \
  --policy-name SOC2-AutoRemediationPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "ec2:CreateFlowLogs",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "iam:PassRole"
        ],
        "Resource": "*"
      }
    ]
  }'

# Attach auto-remediation to the Config rule
aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "SOC2-EnableS3Encryption",
    "Parameters": {
      "BucketName": {
        "ResourceValue": {"Value": "RESOURCE_ID"}
      },
      "AutomationAssumeRole": {
        "StaticValue": {"Values": ["arn:aws:iam::'"$AWS_ACCOUNT_ID"':role/SOC2-AutoRemediationRole"]}
      }
    },
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]'
```

### Auto-Restrict Public S3 Buckets

```bash
aws ssm create-document \
  --name "SOC2-BlockS3PublicAccess" \
  --document-type "Automation" \
  --document-format "YAML" \
  --content '{
    "schemaVersion": "0.3",
    "description": "Block public access on S3 bucket",
    "assumeRole": "{{ AutomationAssumeRole }}",
    "parameters": {
      "BucketName": {"type": "String"},
      "AutomationAssumeRole": {"type": "String", "default": ""}
    },
    "mainSteps": [{
      "name": "BlockPublicAccess",
      "action": "aws:executeAwsApi",
      "inputs": {
        "Service": "s3",
        "Api": "PutPublicAccessBlock",
        "Bucket": "{{ BucketName }}",
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": true,
          "IgnorePublicAcls": true,
          "BlockPublicPolicy": true,
          "RestrictPublicBuckets": true
        }
      }
    }]
  }'

# Attach to both public read and public write rules
for rule in "s3-bucket-public-read-prohibited" "s3-bucket-public-write-prohibited"; do
  aws configservice put-remediation-configurations \
    --remediation-configurations '[{
      "ConfigRuleName": "'"$rule"'",
      "TargetType": "SSM_DOCUMENT",
      "TargetId": "SOC2-BlockS3PublicAccess",
      "Parameters": {
        "BucketName": {
          "ResourceValue": {"Value": "RESOURCE_ID"}
        },
        "AutomationAssumeRole": {
          "StaticValue": {"Values": ["arn:aws:iam::'"$AWS_ACCOUNT_ID"':role/SOC2-AutoRemediationRole"]}
        }
      },
      "Automatic": true,
      "MaximumAutomaticAttempts": 3,
      "RetryAttemptSeconds": 60
    }]'
done
```

### Auto-Enable VPC Flow Logs

```bash
aws ssm create-document \
  --name "SOC2-EnableVPCFlowLogs" \
  --document-type "Automation" \
  --document-format "YAML" \
  --content '{
    "schemaVersion": "0.3",
    "description": "Enable VPC flow logs to CloudWatch",
    "assumeRole": "{{ AutomationAssumeRole }}",
    "parameters": {
      "VpcId": {"type": "String"},
      "AutomationAssumeRole": {"type": "String", "default": ""},
      "FlowLogsRoleArn": {"type": "String"},
      "LogGroupName": {"type": "String", "default": "/vpc/flow-logs/auto-remediated"}
    },
    "mainSteps": [
      {
        "name": "CreateLogGroup",
        "action": "aws:executeAwsApi",
        "inputs": {
          "Service": "logs",
          "Api": "CreateLogGroup",
          "logGroupName": "{{ LogGroupName }}"
        },
        "onFailure": "Continue"
      },
      {
        "name": "CreateFlowLogs",
        "action": "aws:executeAwsApi",
        "inputs": {
          "Service": "ec2",
          "Api": "CreateFlowLogs",
          "ResourceIds": ["{{ VpcId }}"],
          "ResourceType": "VPC",
          "TrafficType": "ALL",
          "LogGroupName": "{{ LogGroupName }}",
          "DeliverLogsPermissionArn": "{{ FlowLogsRoleArn }}"
        }
      }
    ]
  }'

aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "vpc-flow-logs-enabled",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "SOC2-EnableVPCFlowLogs",
    "Parameters": {
      "VpcId": {
        "ResourceValue": {"Value": "RESOURCE_ID"}
      },
      "AutomationAssumeRole": {
        "StaticValue": {"Values": ["arn:aws:iam::'"$AWS_ACCOUNT_ID"':role/SOC2-AutoRemediationRole"]}
      },
      "FlowLogsRoleArn": {
        "StaticValue": {"Values": ["arn:aws:iam::'"$AWS_ACCOUNT_ID"':role/VPCFlowLogsRole"]}
      }
    },
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]'
```

### Verify Auto-Remediation Setup

```bash
# List all remediation configurations
aws configservice describe-remediation-configurations \
  --config-rule-names \
    s3-bucket-server-side-encryption-enabled \
    s3-bucket-public-read-prohibited \
    s3-bucket-public-write-prohibited \
    vpc-flow-logs-enabled \
  --query 'RemediationConfigurations[*].{Rule:ConfigRuleName,Target:TargetId,Auto:Automatic}'

# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name s3-bucket-server-side-encryption-enabled
```

### Evidence for Auto-Remediation

```bash
{
  echo "=== Remediation Configurations ==="
  aws configservice describe-remediation-configurations \
    --config-rule-names \
      s3-bucket-server-side-encryption-enabled \
      s3-bucket-public-read-prohibited \
      s3-bucket-public-write-prohibited \
      vpc-flow-logs-enabled

  echo "=== Recent Remediation Executions ==="
  for rule in s3-bucket-server-side-encryption-enabled s3-bucket-public-read-prohibited vpc-flow-logs-enabled; do
    echo "--- $rule ---"
    aws configservice describe-remediation-execution-status --config-rule-name "$rule" 2>/dev/null
  done

  echo "=== SSM Automation Documents ==="
  aws ssm list-documents --filters "Key=Owner,Values=Self" \
    --query 'DocumentIdentifiers[?contains(Name, `SOC2`)].{Name:Name,Status:DocumentVersion}'
} > "$EVIDENCE_DIR/auto-remediation-$(date +%Y%m%d-%H%M%S).json"
```

---

## Important Edge Cases

### RDS Encryption: Cannot Encrypt Existing Instance

RDS encryption is a creation-time-only setting. You cannot enable encryption on an existing unencrypted RDS instance. The process is:

1. Create a snapshot of the unencrypted instance
2. Copy the snapshot with encryption enabled (specify a KMS key)
3. Restore from the encrypted snapshot to a new instance
4. Update DNS/connection strings to point to the new instance
5. Delete the old unencrypted instance

This causes **downtime**. For Aurora, the entire cluster must be recreated. Plan a maintenance window and test the migration in staging first.

### S3 Default Encryption: Existing Objects

Enabling default encryption on an S3 bucket only affects **new objects**. Existing unencrypted objects remain unencrypted. To encrypt them:

```bash
# Copy objects in-place with encryption
aws s3 cp s3://bucket/ s3://bucket/ --recursive --sse AES256
# This creates new versions (if versioning is on) and encrypts each object
```

For large buckets, use S3 Batch Operations instead of recursive copy.

### CloudTrail: Organization Trail vs Account Trail

If your AWS Organization management account has an organization trail, account-level trails may be **redundant** and cost extra. Check:

```bash
aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,IsOrg:IsOrganizationTrail}'
```

If `IsOrganizationTrail: true` exists, the account is already covered. You may still want an account-level trail for:
- Different S3 bucket (isolation)
- Different KMS key (key management boundary)
- Additional event selectors (data events)

### GuardDuty: Multi-Account via Organizations

For organizations with multiple AWS accounts:

```bash
# In the management account, designate a delegated admin
aws guardduty enable-organization-admin-account \
  --admin-account-id "SECURITY_ACCOUNT_ID"

# In the delegated admin account, auto-enable for new members
aws guardduty update-organization-configuration \
  --detector-id "DETECTOR_ID" \
  --auto-enable
```

### VPC Flow Logs: Cost Considerations

| Destination | Ingestion Cost | Storage Cost | Query Capability |
|---|---|---|---|
| CloudWatch Logs | $0.50/GB | $0.03/GB/month | CloudWatch Insights |
| S3 | $0 (no ingestion fee) | $0.023/GB/month | Athena |

For high-traffic VPCs (>10GB/day of flow logs), S3 is significantly cheaper. Use Athena for querying S3-based flow logs.
