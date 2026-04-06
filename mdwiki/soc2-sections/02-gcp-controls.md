# Section 02: GCP Security Controls

> Full DISCOVER-FIX-VERIFY-EVIDENCE cycle for every SOC 2 control on Google Cloud Platform.
> Every command is copy-paste ready. Every control maps to a Trust Services Criteria (TSC).

## Prerequisites

```bash
# Confirm gcloud CLI is configured and working
gcloud auth list
gcloud config get-value project

# Set reusable variables used throughout this document
export PROJECT_ID=$(gcloud config get-value project)
export ORG_ID=$(gcloud organizations list --format='value(ID)')
export EVIDENCE_DIR="./soc2-evidence/$(date +%Y-%m-%d)"
mkdir -p "$EVIDENCE_DIR"

# Verify organization-level access (required for org policies)
gcloud organizations get-iam-policy "$ORG_ID" --format=json > /dev/null 2>&1 \
  && echo "PASS: org-level access confirmed" \
  || echo "WARN: no org-level access -- org policy controls will require elevated permissions"

# Verify required APIs are enabled
for API in cloudresourcemanager.googleapis.com \
           iam.googleapis.com \
           logging.googleapis.com \
           monitoring.googleapis.com \
           securitycenter.googleapis.com \
           sqladmin.googleapis.com \
           compute.googleapis.com \
           cloudkms.googleapis.com \
           storage.googleapis.com; do
  gcloud services list --enabled --filter="name:$API" --format="value(name)" | grep -q "$API" \
    && echo "OK: $API" \
    || echo "MISSING: $API -- enable with: gcloud services enable $API"
done
```

---

## Cloud IAM Controls

### 1. Organization Policy Constraints (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List all active organization policies
gcloud org-policies list --organization="$ORG_ID" \
  --format="table(constraint,listPolicy.allValues,booleanPolicy.enforced)"

# Check specific critical constraints
for CONSTRAINT in \
  constraints/iam.allowedPolicyMemberDomains \
  constraints/storage.uniformBucketLevelAccess \
  constraints/storage.publicAccessPrevention \
  constraints/compute.requireOsLogin \
  constraints/iam.disableServiceAccountKeyCreation \
  constraints/compute.vmExternalIpAccess; do
  echo "=== $CONSTRAINT ==="
  gcloud org-policies describe "$CONSTRAINT" --organization="$ORG_ID" 2>/dev/null \
    || echo "NOT SET"
done
```
- PASS: critical constraints are set and enforced
- FAIL: constraints return "NOT SET" or are not enforced

**FIX** -- remediate if failing:
```bash
# Restrict IAM policy members to your domain only
# Replace DIRECTORY_CUSTOMER_ID with your Cloud Identity customer ID
# Find it at: https://admin.google.com > Account > Account Settings
cat > /tmp/allowed-domains-policy.yaml << 'EOF'
constraint: constraints/iam.allowedPolicyMemberDomains
listPolicy:
  allowedValues:
    - DIRECTORY_CUSTOMER_ID
EOF
gcloud org-policies set-policy /tmp/allowed-domains-policy.yaml \
  --organization="$ORG_ID"

# Enforce uniform bucket-level access (no legacy ACLs)
cat > /tmp/uniform-bucket-policy.yaml << 'EOF'
constraint: constraints/storage.uniformBucketLevelAccess
booleanPolicy:
  enforced: true
EOF
gcloud org-policies set-policy /tmp/uniform-bucket-policy.yaml \
  --organization="$ORG_ID"

# Enforce public access prevention on storage
cat > /tmp/public-access-policy.yaml << 'EOF'
constraint: constraints/storage.publicAccessPrevention
booleanPolicy:
  enforced: true
EOF
gcloud org-policies set-policy /tmp/public-access-policy.yaml \
  --organization="$ORG_ID"

# Disable service account key creation (prefer Workload Identity)
cat > /tmp/disable-sa-keys-policy.yaml << 'EOF'
constraint: constraints/iam.disableServiceAccountKeyCreation
booleanPolicy:
  enforced: true
EOF
gcloud org-policies set-policy /tmp/disable-sa-keys-policy.yaml \
  --organization="$ORG_ID"
```
Gotchas:
- Org policies require `roles/orgpolicy.policyAdmin` at the organization level
- `iam.allowedPolicyMemberDomains` uses your Cloud Identity customer ID (starts with `C`), not your domain name
- Policies propagate downward to all folders and projects -- child resources cannot override unless allowed
- Disabling SA key creation blocks all projects from creating keys -- exempt specific projects via policy overrides if needed

**VERIFY** -- confirm the fix:
```bash
for CONSTRAINT in \
  constraints/iam.allowedPolicyMemberDomains \
  constraints/storage.uniformBucketLevelAccess \
  constraints/storage.publicAccessPrevention \
  constraints/iam.disableServiceAccountKeyCreation; do
  echo "=== $CONSTRAINT ==="
  gcloud org-policies describe "$CONSTRAINT" --organization="$ORG_ID"
done
# Expected: each constraint shows enforced: true or has allowedValues set
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Organization Policies ==="
  gcloud org-policies list --organization="$ORG_ID" --format=json
  echo ""
  for CONSTRAINT in \
    constraints/iam.allowedPolicyMemberDomains \
    constraints/storage.uniformBucketLevelAccess \
    constraints/storage.publicAccessPrevention \
    constraints/iam.disableServiceAccountKeyCreation \
    constraints/compute.requireOsLogin \
    constraints/compute.vmExternalIpAccess; do
    echo "=== $CONSTRAINT ==="
    gcloud org-policies describe "$CONSTRAINT" --organization="$ORG_ID" 2>/dev/null
  done
} > "$EVIDENCE_DIR/org-policies-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 2. Service Account Audit (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# List all service accounts in the project
gcloud iam service-accounts list \
  --format="table(email,displayName,disabled)"

# Find service accounts with no activity in the last 90 days
# Requires IAM Recommender API (Policy Analyzer)
gcloud recommender insights list \
  --insight-type=google.iam.serviceAccount.Insight \
  --location=global \
  --project="$PROJECT_ID" \
  --format="table(content.email,content.lastAuthenticatedTime,stateInfo.state)" \
  2>/dev/null || echo "Recommender API not enabled or no insights available"

# List service accounts and check for excessive project-level roles
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:" \
  --format="table(bindings.role,bindings.members)"
```
- PASS: all service accounts are active and have least-privilege roles
- FAIL: service accounts with no recent activity, or with `roles/owner` or `roles/editor`

**FIX** -- remediate if failing:
```bash
# Disable unused service account (reversible -- safer than deletion)
SA_EMAIL="unused-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts disable "$SA_EMAIL"

# Remove overly permissive role and replace with specific role
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/editor"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/storage.objectViewer"

# Delete a service account (irreversible after 30-day recovery window)
# gcloud iam service-accounts delete "$SA_EMAIL"
```
Gotchas:
- Disabling is reversible; deletion is permanent after the 30-day undelete window
- Default service accounts (Compute Engine, App Engine) should be disabled if not used, but some services depend on them
- The IAM Recommender takes 90+ days of activity data before it can make recommendations
- Service accounts created by Google-managed services (agent service accounts) should not be modified

**VERIFY** -- confirm the fix:
```bash
# Check the service account is disabled
gcloud iam service-accounts describe "$SA_EMAIL" \
  --format="value(disabled)"
# Expected: True

# Check role bindings
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:$SA_EMAIL" \
  --format="table(bindings.role)"
# Expected: only least-privilege roles, no roles/owner or roles/editor
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Service Accounts ==="
  gcloud iam service-accounts list --format=json

  echo ""
  echo "=== Service Account IAM Bindings ==="
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --flatten="bindings[].members" \
    --filter="bindings.members:serviceAccount:" \
    --format=json

  echo ""
  echo "=== IAM Recommender Insights ==="
  gcloud recommender insights list \
    --insight-type=google.iam.serviceAccount.Insight \
    --location=global \
    --project="$PROJECT_ID" \
    --format=json 2>/dev/null || echo "No insights available"
} > "$EVIDENCE_DIR/service-accounts-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

### 3. Service Account Key Rotation (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Find all user-managed service account keys and their ages
for SA in $(gcloud iam service-accounts list --format="value(email)"); do
  KEYS=$(gcloud iam service-accounts keys list \
    --iam-account="$SA" \
    --managed-by=user \
    --format="csv[no-heading](name.basename(),validAfterTime)")
  if [ -n "$KEYS" ]; then
    echo "=== $SA ==="
    while IFS=',' read -r KEY_ID CREATED; do
      CREATED_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATED" +%s 2>/dev/null \
        || date -d "$CREATED" +%s 2>/dev/null)
      NOW_EPOCH=$(date +%s)
      AGE_DAYS=$(( (NOW_EPOCH - CREATED_EPOCH) / 86400 ))
      if [ "$AGE_DAYS" -gt 90 ]; then
        echo "  FAIL: key=$KEY_ID age=${AGE_DAYS}d (>90 days)"
      else
        echo "  OK:   key=$KEY_ID age=${AGE_DAYS}d"
      fi
    done <<< "$KEYS"
  fi
done
```
- PASS: no keys older than 90 days (or ideally no user-managed keys at all)
- FAIL: keys with age >90 days listed

**FIX** -- remediate if failing:
```bash
SA_EMAIL="my-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Step 1: Create new key
gcloud iam service-accounts keys create /tmp/new-sa-key.json \
  --iam-account="$SA_EMAIL"
echo "New key created. Update all systems using this service account."

# Step 2: Update all systems with the new key file
# (deployment-specific -- update secrets manager, k8s secrets, etc.)

# Step 3: Delete old key after confirming new key works
OLD_KEY_ID="abc123def456"
gcloud iam service-accounts keys delete "$OLD_KEY_ID" \
  --iam-account="$SA_EMAIL" --quiet
```
Gotchas:
- The best fix is to eliminate user-managed keys entirely -- use Workload Identity Federation instead (see control 5)
- New key JSON contains the private key -- store it in Secret Manager, not on disk
- Key deletion is immediate and irreversible -- confirm the new key works in all systems first
- If the org policy `iam.disableServiceAccountKeyCreation` is enforced, you must use Workload Identity instead

**VERIFY** -- confirm the fix:
```bash
gcloud iam service-accounts keys list \
  --iam-account="$SA_EMAIL" \
  --managed-by=user \
  --format="table(name.basename(),validAfterTime,validBeforeTime)"
# Expected: only keys created recently, or no user-managed keys at all
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Service Account Keys Audit ==="
  for SA in $(gcloud iam service-accounts list --format="value(email)"); do
    echo "--- $SA ---"
    gcloud iam service-accounts keys list \
      --iam-account="$SA" \
      --managed-by=user \
      --format=json 2>/dev/null
  done
} > "$EVIDENCE_DIR/sa-key-rotation-$(date +%Y%m%d-%H%M%S).json"
```

---

### 4. IAM Policy Audit (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Find overly permissive project-level bindings
# Look for roles/owner, roles/editor, or roles/viewer on broad scopes
echo "=== Overly Permissive Project Bindings ==="
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[]" \
  --filter="bindings.role:(roles/owner OR roles/editor)" \
  --format="table(bindings.role,bindings.members)"

echo ""
echo "=== allUsers / allAuthenticatedUsers Bindings ==="
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:(allUsers OR allAuthenticatedUsers)" \
  --format="table(bindings.role,bindings.members)"

echo ""
echo "=== Organization-Level Overly Permissive Bindings ==="
gcloud organizations get-iam-policy "$ORG_ID" \
  --flatten="bindings[]" \
  --filter="bindings.role:(roles/owner OR roles/editor)" \
  --format="table(bindings.role,bindings.members)" 2>/dev/null \
  || echo "No org-level access to check"
```
- PASS: no `allUsers`/`allAuthenticatedUsers` bindings; `roles/owner` only on break-glass accounts; `roles/editor` is minimized
- FAIL: broad roles on service accounts, `allUsers` has any binding, or `roles/editor` is widely used

**FIX** -- remediate if failing:
```bash
# Remove allUsers binding
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="allUsers" \
  --role="roles/storage.objectViewer"

# Replace roles/editor with specific roles
MEMBER="user:dev@example.com"
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="$MEMBER" \
  --role="roles/editor"

# Grant specific roles instead
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="$MEMBER" \
  --role="roles/compute.admin"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="$MEMBER" \
  --role="roles/storage.admin"

# Use IAM Recommender to find role reduction suggestions
gcloud recommender recommendations list \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --project="$PROJECT_ID" \
  --format="table(content.overview.member,content.overview.removedRole,content.overview.addedRoles)"
```
Gotchas:
- Removing `roles/editor` can break CI/CD pipelines -- audit which services rely on it first
- Use IAM Recommender suggestions as a starting point, but verify each one manually
- `roles/owner` should only be held by 2-3 break-glass admin accounts, never service accounts
- IAM changes take up to 60 seconds to propagate

**VERIFY** -- confirm the fix:
```bash
# Verify no allUsers/allAuthenticatedUsers bindings
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:(allUsers OR allAuthenticatedUsers)" \
  --format="table(bindings.role,bindings.members)"
# Expected: no output

# Verify roles/editor usage is minimized
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[]" \
  --filter="bindings.role:roles/editor" \
  --format="table(bindings.members)"
# Expected: empty or only known exceptions
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Full Project IAM Policy ==="
  gcloud projects get-iam-policy "$PROJECT_ID" --format=json

  echo ""
  echo "=== IAM Recommender Recommendations ==="
  gcloud recommender recommendations list \
    --recommender=google.iam.policy.Recommender \
    --location=global \
    --project="$PROJECT_ID" \
    --format=json 2>/dev/null || echo "No recommendations"
} > "$EVIDENCE_DIR/iam-policy-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

### 5. Workload Identity Federation (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Check if Workload Identity pools exist
gcloud iam workload-identity-pools list \
  --location="global" \
  --project="$PROJECT_ID" \
  --format="table(name,state,displayName)"

# Count user-managed service account keys (should be zero if using WIF)
TOTAL_USER_KEYS=0
for SA in $(gcloud iam service-accounts list --format="value(email)"); do
  COUNT=$(gcloud iam service-accounts keys list \
    --iam-account="$SA" \
    --managed-by=user \
    --format="value(name)" | wc -l)
  TOTAL_USER_KEYS=$((TOTAL_USER_KEYS + COUNT))
done
echo "Total user-managed SA keys: $TOTAL_USER_KEYS"
```
- PASS: Workload Identity pools exist and user-managed keys count is 0
- FAIL: no WIF pools, or user-managed keys still in use

**FIX** -- remediate if failing:
```bash
# Example: Set up Workload Identity Federation for GitHub Actions
POOL_NAME="github-pool"
PROVIDER_NAME="github-provider"
SA_EMAIL="github-deploy@${PROJECT_ID}.iam.gserviceaccount.com"
GITHUB_ORG="your-org"
GITHUB_REPO="your-repo"

# Create workload identity pool
gcloud iam workload-identity-pools create "$POOL_NAME" \
  --location="global" \
  --display-name="GitHub Actions Pool"

# Create OIDC provider for GitHub
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_NAME" \
  --location="global" \
  --workload-identity-pool="$POOL_NAME" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='${GITHUB_ORG}/${GITHUB_REPO}'"

# Allow the GitHub repo to impersonate the service account
POOL_ID=$(gcloud iam workload-identity-pools describe "$POOL_NAME" \
  --location="global" --format="value(name)")

gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/${POOL_ID}/attribute.repository/${GITHUB_ORG}/${GITHUB_REPO}"

# After confirming WIF works, delete the old SA key
# gcloud iam service-accounts keys delete OLD_KEY_ID --iam-account="$SA_EMAIL" --quiet
```
Gotchas:
- WIF eliminates long-lived service account keys -- this is the single biggest security improvement for CI/CD
- The `attribute-condition` is critical -- without it, any GitHub repo could impersonate the SA
- Supported OIDC providers: GitHub Actions, GitLab CI, AWS, Azure AD, any OIDC-compliant IdP
- For GKE workloads, use GKE Workload Identity (different from WIF but same concept)

**VERIFY** -- confirm the fix:
```bash
# Verify the pool and provider exist
gcloud iam workload-identity-pools providers describe "$PROVIDER_NAME" \
  --location="global" \
  --workload-identity-pool="$POOL_NAME" \
  --format="yaml(name,state,attributeCondition,issuerUri)"
# Expected: state: ACTIVE, correct issuerUri and attributeCondition

# Verify service account binding
gcloud iam service-accounts get-iam-policy "$SA_EMAIL" \
  --format=json
# Expected: binding with roles/iam.workloadIdentityUser for the pool principal
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Workload Identity Pools ==="
  gcloud iam workload-identity-pools list --location="global" --format=json

  echo ""
  echo "=== Pool Providers ==="
  for POOL in $(gcloud iam workload-identity-pools list --location="global" --format="value(name.basename())"); do
    echo "--- Pool: $POOL ---"
    gcloud iam workload-identity-pools providers list \
      --location="global" \
      --workload-identity-pool="$POOL" \
      --format=json
  done

  echo ""
  echo "=== User-Managed Key Count ==="
  for SA in $(gcloud iam service-accounts list --format="value(email)"); do
    COUNT=$(gcloud iam service-accounts keys list --iam-account="$SA" --managed-by=user --format="value(name)" | wc -l)
    echo "$SA: $COUNT user-managed keys"
  done
} > "$EVIDENCE_DIR/workload-identity-$(date +%Y%m%d-%H%M%S).json"
```

---

### 6. Cloud Identity MFA / 2-Step Verification (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# 2SV enforcement is managed via Google Admin Console (admin.google.com),
# not gcloud CLI. However, you can check the org policy for context:
gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains \
  --organization="$ORG_ID" 2>/dev/null

# Check if Cloud Identity users exist (indicates managed identities)
gcloud identity groups list --organization="$ORG_ID" \
  --format="table(displayName,groupKey.id)" 2>/dev/null \
  || echo "Cloud Identity Groups API not available -- check Admin Console"
```
- PASS: 2SV is enforced at the organizational unit level in Admin Console
- FAIL: 2SV is optional or not configured

**FIX** -- remediate if failing:
```
2SV enforcement cannot be done via gcloud CLI. You must use Google Admin Console:

1. Go to https://admin.google.com
2. Navigate to Security > Authentication > 2-step verification
3. Check "Allow users to turn on 2-Step Verification"
4. Set enforcement: "On" for the target organizational unit
5. Set enrollment period: give users 1-2 weeks to set up
6. Set allowed methods: Security keys preferred, authenticator apps acceptable
7. New user enrollment period: 1 day (require 2SV immediately for new accounts)

For highest assurance:
- Require security keys (phishing-resistant)
- Disable SMS and voice call options
- Set "Enforcement date" to enforce after enrollment period
```
Gotchas:
- Cloud Identity is separate from Google Workspace -- both require 2SV configuration
- If using external IdP (Okta, Azure AD), 2SV is managed in the IdP, not Google Admin
- Super admins can bypass 2SV temporarily -- configure backup codes for break-glass
- 2SV enforcement applies to Google Workspace / Cloud Identity users only -- federated users authenticate via their IdP

**VERIFY** -- confirm the fix:
```
Verification must be done via Admin Console:

1. Go to https://admin.google.com > Reports > User reports > 2-Step Verification
2. Verify "Enrollment" shows 100% (or near 100% with known exceptions)
3. Verify "Enforcement" shows "Enforced" for all organizational units

Alternatively, use the Admin SDK Directory API:
```
```bash
# If you have Admin SDK access, list users and check 2SV enrollment
# This requires the Admin SDK API and appropriate scopes
# gcloud auth application-default login --scopes="https://www.googleapis.com/auth/admin.directory.user.readonly"
# Then query: GET https://admin.googleapis.com/admin/directory/v1/users?domain=yourdomain.com&projection=full
# Check each user's isEnforcedIn2Sv and isEnrolledIn2Sv fields
echo "2SV verification requires Admin Console access -- see instructions above"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== 2SV Evidence ==="
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "2SV enforcement is configured via Google Admin Console."
  echo "Export the 2-Step Verification report from:"
  echo "  https://admin.google.com > Reports > User reports > 2-Step Verification"
  echo ""
  echo "=== Domain Restriction Policy ==="
  gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains \
    --organization="$ORG_ID" 2>/dev/null || echo "Not set"
  echo ""
  echo "=== Cloud Identity Groups ==="
  gcloud identity groups list --organization="$ORG_ID" --format=json 2>/dev/null \
    || echo "Requires Cloud Identity Groups API"
} > "$EVIDENCE_DIR/2sv-enforcement-$(date +%Y%m%d-%H%M%S).txt"
```

---

## Cloud Audit Logs Controls

### 7. Admin Activity Logs (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Admin Activity logs are always on and cannot be disabled.
# Verify they are working by querying recent admin activity:
gcloud logging read \
  'logName:"cloudaudit.googleapis.com%2Factivity"' \
  --project="$PROJECT_ID" \
  --limit=5 \
  --format="table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail)"
```
- PASS: returns recent admin activity entries
- FAIL: no entries (indicates a configuration or access issue -- admin logs are always on)

**FIX** -- remediate if failing:
```
Admin Activity audit logs are ALWAYS enabled and cannot be disabled or configured.
They are retained for 400 days at no charge.

If no logs appear, check:
1. The project has had admin activity (IAM changes, resource creation, etc.)
2. You have roles/logging.viewer or equivalent permission
3. The project ID is correct: gcloud config get-value project
```
Gotchas:
- Admin Activity logs are free and always on -- no action needed to enable
- Retention is 400 days by default (not configurable in Cloud Logging)
- For retention beyond 400 days, configure a log sink (see control 9)
- Admin Activity logs cover create/delete/update operations on resources and IAM policy changes

**VERIFY** -- confirm the fix:
```bash
# Verify logs are flowing
gcloud logging read \
  'logName:"cloudaudit.googleapis.com%2Factivity"' \
  --project="$PROJECT_ID" \
  --limit=1 \
  --format="value(timestamp)"
# Expected: a recent timestamp
```

**EVIDENCE** -- capture for auditor:
```bash
gcloud logging read \
  'logName:"cloudaudit.googleapis.com%2Factivity"' \
  --project="$PROJECT_ID" \
  --limit=50 \
  --format=json \
  > "$EVIDENCE_DIR/admin-activity-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

### 8. Data Access Logs (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Data Access logs must be explicitly enabled per service.
# Check the project's audit log configuration:
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs // "NOT CONFIGURED"'
```
- PASS: `auditConfigs` array contains entries for `allServices` or specific services with `DATA_READ`, `DATA_WRITE`, and `ADMIN_READ` log types
- FAIL: `auditConfigs` is null, empty, or missing critical services

**FIX** -- remediate if failing:
```bash
# Get current IAM policy
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/project-policy.json

# Add audit config to enable Data Access logs for all services
# Use jq to merge the audit config into the existing policy
jq '.auditConfigs = [
  {
    "service": "allServices",
    "auditLogConfigs": [
      {"logType": "ADMIN_READ"},
      {"logType": "DATA_READ"},
      {"logType": "DATA_WRITE"}
    ]
  }
]' /tmp/project-policy.json > /tmp/project-policy-updated.json

gcloud projects set-iam-policy "$PROJECT_ID" /tmp/project-policy-updated.json
```
Gotchas:
- Data Access logs are NOT enabled by default -- this is the most commonly missed SOC 2 control on GCP
- Enabling for `allServices` is the safest approach for compliance, but can generate significant log volume
- Data Access logs can be expensive -- BigQuery and Cloud Storage data reads can generate millions of log entries
- To reduce cost, enable selectively for critical services: IAM, Cloud SQL, Cloud KMS, Secret Manager
- Exempted members (e.g., automated monitoring service accounts) can be specified per service to reduce noise
- Changes to audit config require `roles/resourcemanager.projectIamAdmin`

**VERIFY** -- confirm the fix:
```bash
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs'
# Expected: array with allServices entry containing DATA_READ, DATA_WRITE, ADMIN_READ

# Verify logs are flowing (may take a few minutes after enabling)
gcloud logging read \
  'logName:"cloudaudit.googleapis.com%2Fdata_access"' \
  --project="$PROJECT_ID" \
  --limit=5 \
  --format="table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail)"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Data Access Audit Configuration ==="
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json | jq '.auditConfigs'

  echo ""
  echo "=== Recent Data Access Log Entries ==="
  gcloud logging read \
    'logName:"cloudaudit.googleapis.com%2Fdata_access"' \
    --project="$PROJECT_ID" \
    --limit=25 \
    --format=json
} > "$EVIDENCE_DIR/data-access-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

### 9. Log Sinks (TSC: CC7.1, A1.2)

**DISCOVER** -- check current state:
```bash
# List all log sinks in the project
gcloud logging sinks list --project="$PROJECT_ID" \
  --format="table(name,destination,filter,writerIdentity)"

# Check for organization-level sinks
gcloud logging sinks list --organization="$ORG_ID" \
  --format="table(name,destination,filter)" 2>/dev/null \
  || echo "No org-level access"
```
- PASS: at least one sink exists that exports audit logs to Cloud Storage or BigQuery for long-term retention
- FAIL: no sinks, or sinks do not cover audit logs

**FIX** -- remediate if failing:
```bash
# Create a Cloud Storage bucket for log retention
LOGS_BUCKET="gs://${PROJECT_ID}-audit-logs"
gcloud storage buckets create "$LOGS_BUCKET" \
  --location=us \
  --uniform-bucket-level-access \
  --public-access-prevention

# Create a log sink to export all audit logs to the bucket
gcloud logging sinks create audit-log-archive \
  --project="$PROJECT_ID" \
  --destination="storage.googleapis.com/${PROJECT_ID}-audit-logs" \
  --log-filter='logName:"cloudaudit.googleapis.com"'

# Get the sink's writer identity and grant it access to the bucket
WRITER_IDENTITY=$(gcloud logging sinks describe audit-log-archive \
  --project="$PROJECT_ID" \
  --format="value(writerIdentity)")

gcloud storage buckets add-iam-policy-binding "$LOGS_BUCKET" \
  --member="$WRITER_IDENTITY" \
  --role="roles/storage.objectCreator"

# Alternative: export to BigQuery for queryable log archive
# gcloud logging sinks create audit-log-bq \
#   --project="$PROJECT_ID" \
#   --destination="bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/audit_logs" \
#   --log-filter='logName:"cloudaudit.googleapis.com"'
```
Gotchas:
- The sink's writer identity (a service account) needs write permission on the destination
- Sinks only export logs generated AFTER creation -- they do not backfill
- For compliance, create sinks at the organization level to capture all projects
- BigQuery destinations allow querying with SQL; Cloud Storage is cheaper for archival
- If the destination bucket is in a different project, grant the writer identity cross-project access

**VERIFY** -- confirm the fix:
```bash
gcloud logging sinks describe audit-log-archive \
  --project="$PROJECT_ID" \
  --format="yaml(name,destination,filter,writerIdentity)"
# Expected: destination points to your log bucket, filter covers audit logs

# Check that logs are arriving (may take a few minutes)
gcloud storage ls "${LOGS_BUCKET}/" --recursive 2>/dev/null | head -5
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Log Sinks ==="
  gcloud logging sinks list --project="$PROJECT_ID" --format=json

  echo ""
  echo "=== Sink Details ==="
  for SINK in $(gcloud logging sinks list --project="$PROJECT_ID" --format="value(name)"); do
    echo "--- $SINK ---"
    gcloud logging sinks describe "$SINK" --project="$PROJECT_ID" --format=json
  done

  echo ""
  echo "=== Destination Bucket Lifecycle ==="
  gcloud storage buckets describe "$LOGS_BUCKET" --format=json 2>/dev/null || echo "N/A"
} > "$EVIDENCE_DIR/log-sinks-$(date +%Y%m%d-%H%M%S).json"
```

---

### 10. Log Retention (TSC: CC7.1, A1.2)

**DISCOVER** -- check current state:
```bash
# Check Cloud Logging retention settings for log buckets
gcloud logging buckets list --project="$PROJECT_ID" \
  --format="table(name,retentionDays,locked,lifecycleState)"

# Check the _Default and _Required bucket retention
gcloud logging buckets describe _Default \
  --project="$PROJECT_ID" \
  --location=global \
  --format="yaml(retentionDays,locked)"

gcloud logging buckets describe _Required \
  --project="$PROJECT_ID" \
  --location=global \
  --format="yaml(retentionDays,locked)"

# Check if a Cloud Storage sink bucket has lifecycle/retention policies
# (for logs exported via sinks)
LOGS_BUCKET="gs://${PROJECT_ID}-audit-logs"
gcloud storage buckets describe "$LOGS_BUCKET" \
  --format="json(retentionPolicy,lifecycle)" 2>/dev/null \
  || echo "Log archive bucket not found"
```
- PASS: `_Default` bucket retention >= 365 days, or a sink exports to a bucket with 365+ day retention
- FAIL: `_Default` retention is 30 days (the default) and no long-term sink exists

**FIX** -- remediate if failing:
```bash
# Option A: Increase Cloud Logging bucket retention (up to 3650 days)
# WARNING: Increasing retention increases Cloud Logging storage costs
gcloud logging buckets update _Default \
  --project="$PROJECT_ID" \
  --location=global \
  --retention-days=365

# Option B (recommended): Keep _Default at 30 days, rely on sink to Cloud Storage
# Set a retention policy on the Cloud Storage bucket
LOGS_BUCKET="gs://${PROJECT_ID}-audit-logs"
gcloud storage buckets update "$LOGS_BUCKET" \
  --retention-period=365d

# Lock the retention policy (makes it immutable -- cannot be shortened)
# WARNING: This is IRREVERSIBLE. Only do this when you are certain.
# gcloud storage buckets update "$LOGS_BUCKET" --lock-retention-period

# Set lifecycle rules for cost optimization
cat > /tmp/lifecycle-rules.json << 'EOF'
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
        "condition": {"age": 90}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
        "condition": {"age": 365}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "ARCHIVE"},
        "condition": {"age": 730}
      }
    ]
  }
}
EOF
gcloud storage buckets update "$LOGS_BUCKET" \
  --lifecycle-file=/tmp/lifecycle-rules.json
```
Gotchas:
- `_Required` bucket (Admin Activity, System Event logs) has 400-day retention and cannot be changed
- `_Default` bucket defaults to 30 days -- this is where Data Access logs go
- Increasing `_Default` retention is simpler but more expensive than using a sink + Cloud Storage
- Locking a Cloud Storage retention policy is irreversible -- you cannot delete the bucket until all objects age out
- SOC 2 typically requires 365 days minimum; some auditors accept 365 days in Cloud Storage with lifecycle tiering

**VERIFY** -- confirm the fix:
```bash
echo "=== Cloud Logging Buckets ==="
gcloud logging buckets list --project="$PROJECT_ID" \
  --format="table(name,retentionDays,locked)"

echo ""
echo "=== Cloud Storage Retention ==="
gcloud storage buckets describe "$LOGS_BUCKET" \
  --format="json(retentionPolicy,lifecycle)" 2>/dev/null
# Expected: retentionDays >= 365 on _Default, or retentionPolicy on the storage bucket
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud Logging Bucket Retention ==="
  gcloud logging buckets list --project="$PROJECT_ID" --format=json

  echo ""
  echo "=== _Default Bucket Details ==="
  gcloud logging buckets describe _Default \
    --project="$PROJECT_ID" --location=global --format=json

  echo ""
  echo "=== _Required Bucket Details ==="
  gcloud logging buckets describe _Required \
    --project="$PROJECT_ID" --location=global --format=json

  echo ""
  echo "=== Log Archive Bucket Retention + Lifecycle ==="
  gcloud storage buckets describe "gs://${PROJECT_ID}-audit-logs" --format=json 2>/dev/null \
    || echo "No separate archive bucket"
} > "$EVIDENCE_DIR/log-retention-$(date +%Y%m%d-%H%M%S).json"
```

---

### 11. Log-Based Alerts (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List existing log-based metrics
gcloud logging metrics list --project="$PROJECT_ID" \
  --format="table(name,filter)"

# List existing alerting policies
gcloud alpha monitoring policies list --project="$PROJECT_ID" \
  --format="table(displayName,enabled,conditions.displayName)" 2>/dev/null \
  || echo "Use: gcloud monitoring policies list (if available)"

# Check for critical alerts that should exist:
echo ""
echo "=== Checking for expected log-based metrics ==="
for METRIC in iam-policy-changes sa-key-creation admin-activity-changes \
              permission-grants firewall-changes; do
  gcloud logging metrics describe "$METRIC" --project="$PROJECT_ID" 2>/dev/null \
    && echo "FOUND: $METRIC" \
    || echo "MISSING: $METRIC"
done
```
- PASS: log-based metrics exist for IAM changes, SA key creation, permission grants, and firewall changes, with corresponding alerting policies
- FAIL: no log-based metrics or alerts configured

**FIX** -- remediate if failing:
```bash
# Create log-based metric: IAM policy changes
gcloud logging metrics create iam-policy-changes \
  --project="$PROJECT_ID" \
  --description="IAM policy changes on the project" \
  --log-filter='protoPayload.methodName="SetIamPolicy" OR protoPayload.methodName="SetOrgPolicy"'

# Create log-based metric: Service account key creation
gcloud logging metrics create sa-key-creation \
  --project="$PROJECT_ID" \
  --description="Service account key creation events" \
  --log-filter='protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"'

# Create log-based metric: Permission/role grants
gcloud logging metrics create permission-grants \
  --project="$PROJECT_ID" \
  --description="Role or permission grants" \
  --log-filter='protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"'

# Create log-based metric: Firewall rule changes
gcloud logging metrics create firewall-changes \
  --project="$PROJECT_ID" \
  --description="VPC firewall rule modifications" \
  --log-filter='resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.update" OR protoPayload.methodName:"compute.firewalls.delete" OR protoPayload.methodName:"compute.firewalls.patch")'

# Create log-based metric: Custom role changes
gcloud logging metrics create custom-role-changes \
  --project="$PROJECT_ID" \
  --description="Custom IAM role creation or modification" \
  --log-filter='resource.type="iam_role" AND (protoPayload.methodName:"CreateRole" OR protoPayload.methodName:"UpdateRole" OR protoPayload.methodName:"DeleteRole")'

# Create notification channel (email)
CHANNEL_ID=$(gcloud alpha monitoring channels create \
  --display-name="Security Team Email" \
  --type=email \
  --channel-labels="email_address=security@example.com" \
  --project="$PROJECT_ID" \
  --format="value(name.basename())" 2>/dev/null)
echo "Notification channel created: $CHANNEL_ID"

# Create alerting policy for IAM policy changes
cat > /tmp/iam-alert-policy.json << EOF
{
  "displayName": "IAM Policy Change Alert",
  "conditions": [
    {
      "displayName": "IAM policy change detected",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/iam-policy-changes\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["projects/${PROJECT_ID}/notificationChannels/${CHANNEL_ID}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/iam-alert-policy.json \
  --project="$PROJECT_ID"

# Create alerting policy for SA key creation
cat > /tmp/sa-key-alert-policy.json << EOF
{
  "displayName": "Service Account Key Creation Alert",
  "conditions": [
    {
      "displayName": "SA key created",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/sa-key-creation\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["projects/${PROJECT_ID}/notificationChannels/${CHANNEL_ID}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/sa-key-alert-policy.json \
  --project="$PROJECT_ID"

# Create alerting policy for firewall changes
cat > /tmp/firewall-alert-policy.json << EOF
{
  "displayName": "Firewall Rule Change Alert",
  "conditions": [
    {
      "displayName": "Firewall rule changed",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/firewall-changes\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["projects/${PROJECT_ID}/notificationChannels/${CHANNEL_ID}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/firewall-alert-policy.json \
  --project="$PROJECT_ID"
```
Gotchas:
- Log-based metrics only count events AFTER the metric is created -- no backfill
- Alerting policies require at least one notification channel
- `gcloud alpha monitoring` commands may change -- verify with `gcloud alpha monitoring --help`
- For production, use Terraform to manage alerting policies (see Terraform section)
- Consider PagerDuty or Slack integration for faster incident response

**VERIFY** -- confirm the fix:
```bash
echo "=== Log-Based Metrics ==="
gcloud logging metrics list --project="$PROJECT_ID" \
  --format="table(name,filter)"

echo ""
echo "=== Alerting Policies ==="
gcloud alpha monitoring policies list --project="$PROJECT_ID" \
  --format="table(displayName,enabled)" 2>/dev/null

echo ""
echo "=== Notification Channels ==="
gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --format="table(displayName,type)" 2>/dev/null
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Log-Based Metrics ==="
  gcloud logging metrics list --project="$PROJECT_ID" --format=json

  echo ""
  echo "=== Alerting Policies ==="
  gcloud alpha monitoring policies list --project="$PROJECT_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Notification Channels ==="
  gcloud alpha monitoring channels list --project="$PROJECT_ID" --format=json 2>/dev/null
} > "$EVIDENCE_DIR/log-based-alerts-$(date +%Y%m%d-%H%M%S).json"
```

---

## Security Command Center Controls

### 12. Enable Security Command Center (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check if SCC is enabled (requires organization-level access)
gcloud scc settings describe \
  --organization="$ORG_ID" \
  --format="yaml(name,serviceEnablementState)" 2>/dev/null \
  || echo "SCC not accessible -- may not be enabled or insufficient permissions"

# Check SCC sources (detectors)
gcloud scc sources list --organization="$ORG_ID" \
  --format="table(name,displayName)" 2>/dev/null \
  || echo "Cannot list SCC sources"
```
- PASS: SCC is enabled at organization level with sources listed
- FAIL: SCC not enabled or not accessible

**FIX** -- remediate if failing:
```
Security Command Center enablement requires organization-level access and is done
via the Google Cloud Console:

1. Go to https://console.cloud.google.com/security/command-center
2. Select your organization
3. Choose tier:
   - Standard (free): Security Health Analytics, Web Security Scanner, basic findings
   - Premium (paid): All Standard features + Event Threat Detection, Container Threat
     Detection, Virtual Machine Threat Detection, Rapid Vulnerability Detection
4. Enable for the entire organization
5. Grant the SCC service account access to scan resources

For SOC 2, Standard tier covers most requirements. Premium adds runtime threat
detection which auditors increasingly expect.

After enabling via Console, verify via CLI:
```
```bash
# Verify SCC is operational by listing recent findings
gcloud scc findings list "$ORG_ID" \
  --source="-" \
  --filter="state=\"ACTIVE\"" \
  --limit=10 \
  --format="table(finding.category,finding.severity,finding.resourceName)" 2>/dev/null
```
Gotchas:
- SCC is an organization-level service -- it cannot be enabled per-project
- Standard tier is free; Premium tier costs per resource per month
- SCC Premium includes Event Threat Detection (similar to AWS GuardDuty)
- Initial scan may take several hours to complete
- SCC requires the Security Center API: `gcloud services enable securitycenter.googleapis.com`

**VERIFY** -- confirm the fix:
```bash
# Verify SCC is working by checking for findings
gcloud scc findings list "$ORG_ID" \
  --source="-" \
  --filter="state=\"ACTIVE\"" \
  --limit=5 \
  --format="table(finding.category,finding.severity)"
# Expected: findings listed (even if severity is LOW -- that means SCC is scanning)
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== SCC Sources ==="
  gcloud scc sources list --organization="$ORG_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Active Findings Summary ==="
  gcloud scc findings list "$ORG_ID" \
    --source="-" \
    --filter="state=\"ACTIVE\"" \
    --format=json 2>/dev/null

  echo ""
  echo "=== Findings by Severity ==="
  for SEV in CRITICAL HIGH MEDIUM LOW; do
    COUNT=$(gcloud scc findings list "$ORG_ID" \
      --source="-" \
      --filter="state=\"ACTIVE\" AND finding.severity=\"$SEV\"" \
      --format="value(finding.name)" 2>/dev/null | wc -l)
    echo "$SEV: $COUNT findings"
  done
} > "$EVIDENCE_DIR/scc-status-$(date +%Y%m%d-%H%M%S).json"
```

---

### 13. Review SCC Findings (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# List active findings grouped by category and severity
echo "=== CRITICAL Findings ==="
gcloud scc findings list "$ORG_ID" \
  --source="-" \
  --filter="state=\"ACTIVE\" AND finding.severity=\"CRITICAL\"" \
  --format="table(finding.category,finding.resourceName,finding.createTime)" 2>/dev/null

echo ""
echo "=== HIGH Severity Findings ==="
gcloud scc findings list "$ORG_ID" \
  --source="-" \
  --filter="state=\"ACTIVE\" AND finding.severity=\"HIGH\"" \
  --format="table(finding.category,finding.resourceName,finding.createTime)" 2>/dev/null

echo ""
echo "=== Finding Categories Summary ==="
gcloud scc findings list "$ORG_ID" \
  --source="-" \
  --filter="state=\"ACTIVE\"" \
  --format="value(finding.category)" 2>/dev/null | sort | uniq -c | sort -rn
```
- PASS: no CRITICAL findings, HIGH findings are tracked and being remediated
- FAIL: unreviewed CRITICAL or HIGH findings

**FIX** -- remediate if failing:
```bash
# Common SCC findings and their remediations:

# PUBLIC_BUCKET_ACL -- a bucket allows public access
# Fix: remove public access (see control 16)

# OPEN_FIREWALL -- firewall rule allows 0.0.0.0/0
# Fix: restrict firewall rule (see control 28)

# MFA_NOT_ENFORCED -- 2SV not enforced for users
# Fix: enforce 2SV in Admin Console (see control 6)

# SA_KEY_NOT_ROTATED -- service account key older than 90 days
# Fix: rotate key (see control 3) or migrate to WIF (see control 5)

# To mark a finding as remediated after fixing:
FINDING_NAME="organizations/$ORG_ID/sources/SOURCE_ID/findings/FINDING_ID"
gcloud scc findings update "$FINDING_NAME" \
  --organization="$ORG_ID" \
  --state="INACTIVE"

# To mute a finding (acknowledged but accepted risk):
gcloud scc findings update "$FINDING_NAME" \
  --organization="$ORG_ID" \
  --mute="MUTED"
```
Gotchas:
- SCC findings auto-resolve when the underlying misconfiguration is fixed (for Security Health Analytics)
- Event Threat Detection findings (Premium) do not auto-resolve -- they must be manually triaged
- Muting a finding hides it from default views but preserves the audit trail
- Review findings weekly at minimum -- set up continuous exports (control 14) for real-time response

**VERIFY** -- confirm the fix:
```bash
# Verify critical and high findings count is decreasing
echo "CRITICAL: $(gcloud scc findings list "$ORG_ID" --source="-" \
  --filter='state="ACTIVE" AND finding.severity="CRITICAL"' \
  --format="value(finding.name)" 2>/dev/null | wc -l)"
echo "HIGH: $(gcloud scc findings list "$ORG_ID" --source="-" \
  --filter='state="ACTIVE" AND finding.severity="HIGH"' \
  --format="value(finding.name)" 2>/dev/null | wc -l)"
# Expected: 0 CRITICAL, LOW count for HIGH (with tracking)
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== SCC Findings Report ==="
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  for SEV in CRITICAL HIGH MEDIUM LOW; do
    echo "=== $SEV ==="
    gcloud scc findings list "$ORG_ID" \
      --source="-" \
      --filter="state=\"ACTIVE\" AND finding.severity=\"$SEV\"" \
      --format=json 2>/dev/null
    echo ""
  done
} > "$EVIDENCE_DIR/scc-findings-$(date +%Y%m%d-%H%M%S).json"
```

---

### 14. Continuous Exports from SCC (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List SCC notification configs (continuous exports)
gcloud scc notifications list --organization="$ORG_ID" \
  --format="table(name,description,pubsubTopic,filter)" 2>/dev/null \
  || echo "No SCC notification configs found"
```
- PASS: at least one notification config exists that exports findings to Pub/Sub or BigQuery
- FAIL: no notification configs

**FIX** -- remediate if failing:
```bash
# Create a Pub/Sub topic for SCC findings
gcloud pubsub topics create scc-findings-export \
  --project="$PROJECT_ID"

# Create a notification config to export all HIGH and CRITICAL findings
gcloud scc notifications create scc-high-critical-export \
  --organization="$ORG_ID" \
  --pubsub-topic="projects/${PROJECT_ID}/topics/scc-findings-export" \
  --filter='severity="HIGH" OR severity="CRITICAL"'

# Create a Pub/Sub subscription (for processing or archival)
gcloud pubsub subscriptions create scc-findings-sub \
  --topic=scc-findings-export \
  --project="$PROJECT_ID" \
  --ack-deadline=60

# Optional: Create a BigQuery subscription for long-term queryable storage
# gcloud pubsub subscriptions create scc-findings-bq \
#   --topic=scc-findings-export \
#   --project="$PROJECT_ID" \
#   --bigquery-table="${PROJECT_ID}:scc_exports.findings" \
#   --write-metadata

# Optional: export ALL findings (not just HIGH/CRITICAL)
# gcloud scc notifications create scc-all-findings-export \
#   --organization="$ORG_ID" \
#   --pubsub-topic="projects/${PROJECT_ID}/topics/scc-findings-export" \
#   --filter='state="ACTIVE"'
```
Gotchas:
- SCC notifications are real-time -- every new finding or state change triggers a Pub/Sub message
- The Pub/Sub topic must be in a project within the organization
- Filter syntax uses SCC finding fields (severity, category, state), not Cloud Logging filter syntax
- For BigQuery export, ensure the BigQuery dataset exists and the Pub/Sub service account has write access
- Maximum 500 notification configs per organization

**VERIFY** -- confirm the fix:
```bash
gcloud scc notifications describe scc-high-critical-export \
  --organization="$ORG_ID" \
  --format="yaml(name,pubsubTopic,filter)"
# Expected: shows the Pub/Sub topic and filter

# Verify Pub/Sub topic exists and has subscriptions
gcloud pubsub topics describe scc-findings-export \
  --project="$PROJECT_ID" \
  --format="yaml(name)"

gcloud pubsub subscriptions list --project="$PROJECT_ID" \
  --filter="topic:scc-findings-export" \
  --format="table(name)"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== SCC Notification Configs ==="
  gcloud scc notifications list --organization="$ORG_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Pub/Sub Topic ==="
  gcloud pubsub topics describe scc-findings-export --project="$PROJECT_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Pub/Sub Subscriptions ==="
  gcloud pubsub subscriptions list --project="$PROJECT_ID" \
    --filter="topic:scc-findings-export" --format=json 2>/dev/null
} > "$EVIDENCE_DIR/scc-exports-$(date +%Y%m%d-%H%M%S).json"
```

---

## Cloud Storage Controls

### 15. Uniform Bucket-Level Access (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Check all buckets for uniform bucket-level access
for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
  UBLA=$(gcloud storage buckets describe "gs://$BUCKET" \
    --format="value(uniform_bucket_level_access)")
  if [ "$UBLA" = "True" ]; then
    echo "PASS: $BUCKET (uniform access enabled)"
  else
    echo "FAIL: $BUCKET (legacy ACLs active)"
  fi
done
```
- PASS: all buckets show uniform access enabled
- FAIL: any bucket has legacy ACLs active

**FIX** -- remediate if failing:
```bash
BUCKET_NAME="your-bucket"
gcloud storage buckets update "gs://$BUCKET_NAME" \
  --uniform-bucket-level-access
```
Gotchas:
- Enabling uniform bucket-level access is irreversible after 90 days
- Legacy ACLs on existing objects are preserved but ignored -- all access is controlled by IAM
- If the org policy `storage.uniformBucketLevelAccess` is enforced, all new buckets automatically use uniform access
- Systems relying on object-level ACLs (e.g., signed URLs with ACLs) will break -- test first

**VERIFY** -- confirm the fix:
```bash
gcloud storage buckets describe "gs://$BUCKET_NAME" \
  --format="value(uniform_bucket_level_access)"
# Expected: True
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Bucket Uniform Access Status ==="
  for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
    UBLA=$(gcloud storage buckets describe "gs://$BUCKET" \
      --format="value(uniform_bucket_level_access)")
    echo "$BUCKET: uniform_bucket_level_access=$UBLA"
  done
} > "$EVIDENCE_DIR/bucket-uniform-access-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 16. Public Access Prevention (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check each bucket's public access prevention setting
for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
  PAP=$(gcloud storage buckets describe "gs://$BUCKET" \
    --format="value(public_access_prevention)")
  echo "$BUCKET: public_access_prevention=$PAP"
done

# Check org policy for public access prevention
gcloud org-policies describe constraints/storage.publicAccessPrevention \
  --organization="$ORG_ID" 2>/dev/null \
  || echo "Org policy not set"
```
- PASS: all buckets show `enforced` and org policy is set
- FAIL: any bucket shows `inherited` or `unspecified` without org policy enforcement

**FIX** -- remediate if failing:
```bash
# Enable at bucket level
BUCKET_NAME="your-bucket"
gcloud storage buckets update "gs://$BUCKET_NAME" \
  --public-access-prevention

# Enable at org level (applies to all buckets in all projects)
cat > /tmp/public-access-policy.yaml << 'EOF'
constraint: constraints/storage.publicAccessPrevention
booleanPolicy:
  enforced: true
EOF
gcloud org-policies set-policy /tmp/public-access-policy.yaml \
  --organization="$ORG_ID"
```
Gotchas:
- Public access prevention blocks `allUsers` and `allAuthenticatedUsers` IAM bindings
- If you need a public bucket (e.g., static website hosting), exempt that specific project from the org policy
- This does not affect signed URLs -- signed URLs bypass public access prevention
- Enabling at org level overrides project-level settings

**VERIFY** -- confirm the fix:
```bash
gcloud storage buckets describe "gs://$BUCKET_NAME" \
  --format="value(public_access_prevention)"
# Expected: enforced
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Bucket Public Access Prevention ==="
  for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
    PAP=$(gcloud storage buckets describe "gs://$BUCKET" \
      --format="value(public_access_prevention)")
    echo "$BUCKET: public_access_prevention=$PAP"
  done

  echo ""
  echo "=== Org Policy ==="
  gcloud org-policies describe constraints/storage.publicAccessPrevention \
    --organization="$ORG_ID" 2>/dev/null || echo "Not set"
} > "$EVIDENCE_DIR/bucket-public-access-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 17. Cloud Storage Encryption (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# All Cloud Storage data is encrypted at rest by default (Google-managed keys).
# Check if any buckets use CMEK (Customer-Managed Encryption Keys):
for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
  ENC=$(gcloud storage buckets describe "gs://$BUCKET" \
    --format="value(default_kms_key)")
  if [ -n "$ENC" ]; then
    echo "CMEK: $BUCKET -> $ENC"
  else
    echo "GOOGLE_MANAGED: $BUCKET"
  fi
done
```
- PASS: all buckets show encryption (always true -- Google encrypts by default); CMEK for sensitive/compliance buckets
- FAIL: sensitive or compliance-critical buckets without CMEK

**FIX** -- remediate if failing:
```bash
# Create a Cloud KMS key for bucket encryption (see Cloud KMS section for full key setup)
KEY_RING="soc2-keyring"
KEY_NAME="storage-key"
LOCATION="us"

gcloud kms keyrings create "$KEY_RING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID"

gcloud kms keys create "$KEY_NAME" \
  --keyring="$KEY_RING" \
  --location="$LOCATION" \
  --purpose=encryption \
  --rotation-period=90d \
  --next-rotation-time=$(date -u -v+90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ) \
  --project="$PROJECT_ID"

# Grant the Cloud Storage service agent access to the key
GCS_SA="service-$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')@gs-project-accounts.iam.gserviceaccount.com"
gcloud kms keys add-iam-policy-binding "$KEY_NAME" \
  --keyring="$KEY_RING" \
  --location="$LOCATION" \
  --member="serviceAccount:$GCS_SA" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --project="$PROJECT_ID"

# Set CMEK as default encryption on the bucket
BUCKET_NAME="your-sensitive-bucket"
gcloud storage buckets update "gs://$BUCKET_NAME" \
  --default-encryption-key="projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}"
```
Gotchas:
- Google-managed encryption is always on -- you do NOT need CMEK for basic SOC 2 compliance
- CMEK gives you control over the encryption key lifecycle (rotation, destruction, access control)
- Some auditors require CMEK for "encryption at rest" evidence; others accept Google-managed
- Setting CMEK on a bucket only affects new objects -- existing objects remain encrypted with their original key
- Deleting a CMEK key renders all data encrypted with it permanently inaccessible

**VERIFY** -- confirm the fix:
```bash
gcloud storage buckets describe "gs://$BUCKET_NAME" \
  --format="value(default_kms_key)"
# Expected: projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Bucket Encryption Configuration ==="
  for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
    echo "--- $BUCKET ---"
    gcloud storage buckets describe "gs://$BUCKET" \
      --format="json(default_kms_key,encryption)"
  done
} > "$EVIDENCE_DIR/bucket-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 18. Cloud Storage Versioning (TSC: CC6.1, A1.2)

**DISCOVER** -- check current state:
```bash
for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
  VERSIONING=$(gcloud storage buckets describe "gs://$BUCKET" \
    --format="value(versioning)")
  echo "$BUCKET: versioning=$VERSIONING"
done
```
- PASS: versioning enabled on critical/compliance buckets
- FAIL: versioning disabled on buckets containing important data

**FIX** -- remediate if failing:
```bash
BUCKET_NAME="your-critical-bucket"
gcloud storage buckets update "gs://$BUCKET_NAME" --versioning
```
Gotchas:
- Versioning increases storage costs -- every overwrite or delete creates a new version
- Combine with lifecycle rules to delete old versions after a retention period
- Versioning is essential for the audit log archive bucket to prevent tampering
- Suspending versioning stops creating new versions but preserves existing ones

**VERIFY** -- confirm the fix:
```bash
gcloud storage buckets describe "gs://$BUCKET_NAME" \
  --format="value(versioning)"
# Expected: True
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Bucket Versioning Status ==="
  for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
    VERSIONING=$(gcloud storage buckets describe "gs://$BUCKET" \
      --format="value(versioning)")
    echo "$BUCKET: versioning=$VERSIONING"
  done
} > "$EVIDENCE_DIR/bucket-versioning-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 19. Cloud Storage Lifecycle Policies (TSC: A1.2)

**DISCOVER** -- check current state:
```bash
for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
  echo "=== $BUCKET ==="
  gcloud storage buckets describe "gs://$BUCKET" \
    --format="json(lifecycle)" 2>/dev/null
done
```
- PASS: lifecycle rules exist on log buckets (transition to cheaper storage classes, eventual deletion)
- FAIL: no lifecycle rules on log or archive buckets

**FIX** -- remediate if failing:
```bash
BUCKET_NAME="${PROJECT_ID}-audit-logs"

cat > /tmp/lifecycle-rules.json << 'EOF'
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
        "condition": {"age": 90}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
        "condition": {"age": 365}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "ARCHIVE"},
        "condition": {"age": 730}
      },
      {
        "action": {"type": "Delete"},
        "condition": {"age": 2555, "isLive": true}
      },
      {
        "action": {"type": "Delete"},
        "condition": {"age": 30, "isLive": false}
      }
    ]
  }
}
EOF
gcloud storage buckets update "gs://$BUCKET_NAME" \
  --lifecycle-file=/tmp/lifecycle-rules.json
```
Gotchas:
- Lifecycle transitions incur early deletion fees if objects are moved before the minimum storage duration (30 days for Nearline, 90 for Coldline, 365 for Archive)
- `isLive: false` targets noncurrent (versioned) objects -- use this to clean up old versions
- Lifecycle rules apply retroactively to existing objects
- Retention policies and lifecycle delete rules can conflict -- retention takes precedence

**VERIFY** -- confirm the fix:
```bash
gcloud storage buckets describe "gs://$BUCKET_NAME" \
  --format="json(lifecycle)"
# Expected: lifecycle rules matching the configuration above
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Bucket Lifecycle Policies ==="
  for BUCKET in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)"); do
    echo "--- $BUCKET ---"
    gcloud storage buckets describe "gs://$BUCKET" --format="json(lifecycle)"
  done
} > "$EVIDENCE_DIR/bucket-lifecycle-$(date +%Y%m%d-%H%M%S).json"
```

---

### 20. Cloud Storage Access Logging (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Cloud Storage access logging is controlled via Cloud Audit Logs (Data Access logs).
# Check if Data Access logs are enabled for Cloud Storage:
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs[] | select(.service == "allServices" or .service == "storage.googleapis.com")'
```
- PASS: `DATA_READ` and `DATA_WRITE` audit log types are enabled for `allServices` or `storage.googleapis.com`
- FAIL: no audit config for storage, or Data Access logs not enabled

**FIX** -- remediate if failing:
```bash
# If Data Access logs are not enabled for all services (see control 8),
# enable specifically for Cloud Storage:
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/project-policy.json

# Add or merge storage-specific audit config
jq '.auditConfigs += [{
  "service": "storage.googleapis.com",
  "auditLogConfigs": [
    {"logType": "ADMIN_READ"},
    {"logType": "DATA_READ"},
    {"logType": "DATA_WRITE"}
  ]
}]' /tmp/project-policy.json > /tmp/project-policy-updated.json

gcloud projects set-iam-policy "$PROJECT_ID" /tmp/project-policy-updated.json
```
Gotchas:
- GCP does not use bucket-level access logs like AWS S3 -- it uses Cloud Audit Logs instead
- DATA_READ logs for high-traffic buckets can generate enormous log volume and cost
- Consider exempting automated service accounts from DATA_READ logging to reduce noise
- If you enabled Data Access logs for `allServices` in control 8, storage is already covered

**VERIFY** -- confirm the fix:
```bash
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs[] | select(.service == "allServices" or .service == "storage.googleapis.com")'
# Expected: auditLogConfigs containing DATA_READ, DATA_WRITE, ADMIN_READ

# Verify logs are flowing
gcloud logging read \
  'resource.type="gcs_bucket" AND logName:"cloudaudit.googleapis.com%2Fdata_access"' \
  --project="$PROJECT_ID" \
  --limit=5 \
  --format="table(timestamp,protoPayload.methodName,protoPayload.resourceName)"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Storage Audit Log Configuration ==="
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json | jq '.auditConfigs'

  echo ""
  echo "=== Recent Storage Access Logs ==="
  gcloud logging read \
    'resource.type="gcs_bucket" AND logName:"cloudaudit.googleapis.com%2Fdata_access"' \
    --project="$PROJECT_ID" \
    --limit=25 \
    --format=json
} > "$EVIDENCE_DIR/storage-access-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

## Cloud SQL Controls

### 21. Cloud SQL Encryption (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# All Cloud SQL instances are encrypted at rest by default (Google-managed keys).
# Check if any instances use CMEK:
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  KMS_KEY=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(diskEncryptionConfiguration.kmsKeyName)")
  if [ -n "$KMS_KEY" ]; then
    echo "CMEK: $INSTANCE -> $KMS_KEY"
  else
    echo "GOOGLE_MANAGED: $INSTANCE (encrypted, but not with CMEK)"
  fi
done
```
- PASS: all instances are encrypted (always true); CMEK for compliance-critical instances
- FAIL: compliance-critical instances without CMEK (if CMEK is required by your auditor)

**FIX** -- remediate if failing:
```
Cloud SQL encryption is a creation-time-only setting. You cannot change the
encryption key on an existing instance. To migrate to CMEK:

1. Create a Cloud KMS key (see control 32)
2. Export the database (pg_dump / mysqldump / gcloud sql export)
3. Create a new instance with CMEK:
```
```bash
KEY_NAME="projects/${PROJECT_ID}/locations/${REGION}/keyRings/soc2-keyring/cryptoKeys/cloudsql-key"

gcloud sql instances create "${INSTANCE}-cmek" \
  --database-version=POSTGRES_15 \
  --tier=db-custom-2-7680 \
  --region="$REGION" \
  --disk-encryption-key="$KEY_NAME" \
  --root-password="CHANGE_ME"

# 4. Import the database
# gcloud sql import sql "${INSTANCE}-cmek" gs://bucket/export.sql

# 5. Update application connection strings
# 6. Delete the old instance after verification
```
Gotchas:
- Cloud SQL is ALWAYS encrypted at rest with Google-managed keys -- this is non-negotiable and non-optional
- CMEK is optional but recommended for SOC 2 to demonstrate key management control
- CMEK cannot be added to an existing instance -- requires recreation
- The Cloud SQL service agent needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the KMS key
- Deleting the KMS key renders the database permanently inaccessible

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "${INSTANCE}-cmek" \
  --format="yaml(diskEncryptionConfiguration)"
# Expected: kmsKeyName points to your KMS key
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL Encryption Status ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(diskEncryptionConfiguration,diskEncryptionStatus)"
  done
} > "$EVIDENCE_DIR/cloudsql-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 22. Cloud SQL SSL/TLS Enforcement (TSC: CC6.1, CC6.7)

**DISCOVER** -- check current state:
```bash
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  SSL_MODE=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.ipConfiguration.sslMode)")
  REQUIRE_SSL=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.ipConfiguration.requireSsl)")
  echo "$INSTANCE: sslMode=$SSL_MODE requireSsl=$REQUIRE_SSL"
done
```
- PASS: `sslMode=ENCRYPTED_ONLY` or `requireSsl=True` on all instances
- FAIL: `requireSsl=False` or `sslMode` not set

**FIX** -- remediate if failing:
```bash
INSTANCE_NAME="your-instance"

# Require SSL for all connections (recommended: ENCRYPTED_ONLY mode)
gcloud sql instances patch "$INSTANCE_NAME" \
  --require-ssl

# For stricter enforcement (verify client certificates):
# gcloud sql instances patch "$INSTANCE_NAME" \
#   --ssl-mode=TRUSTED_CLIENT_CERTIFICATE_REQUIRED

# Generate client certificates for applications
gcloud sql ssl client-certs create "app-cert" /tmp/client-cert.pem \
  --instance="$INSTANCE_NAME"

gcloud sql ssl client-certs describe "app-cert" \
  --instance="$INSTANCE_NAME" \
  --format="value(cert)" > /tmp/client-cert.pem

# Download server CA certificate
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="value(serverCaCert.cert)" > /tmp/server-ca.pem
```
Gotchas:
- `--require-ssl` rejects non-SSL connections but does not verify client certificates
- `--ssl-mode=TRUSTED_CLIENT_CERTIFICATE_REQUIRED` requires valid client certs -- strongest but requires certificate management
- Cloud SQL Auth Proxy handles SSL automatically -- if using the proxy, SSL is already enforced
- Enabling SSL does not disconnect existing connections -- they persist until they disconnect and must reconnect with SSL
- Some connection poolers may need configuration changes for SSL

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="yaml(settings.ipConfiguration.sslMode,settings.ipConfiguration.requireSsl)"
# Expected: requireSsl: true (or sslMode: ENCRYPTED_ONLY)
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL SSL Configuration ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(settings.ipConfiguration.sslMode,settings.ipConfiguration.requireSsl,serverCaCert.expirationTime)"
  done
} > "$EVIDENCE_DIR/cloudsql-ssl-$(date +%Y%m%d-%H%M%S).json"
```

---

### 23. Cloud SQL Automated Backups (TSC: A1.2)

**DISCOVER** -- check current state:
```bash
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  BACKUP_ENABLED=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.backupConfiguration.enabled)")
  PITR=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.backupConfiguration.pointInTimeRecoveryEnabled)")
  RETENTION=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.backupConfiguration.transactionLogRetentionDays)")
  BACKUP_RETENTION=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.backupConfiguration.backupRetentionSettings.retainedBackups)")
  echo "$INSTANCE: backup=$BACKUP_ENABLED pitr=$PITR logRetention=${RETENTION}d backupCount=$BACKUP_RETENTION"
done
```
- PASS: `backup=True`, `pitr=True`, retention >= 7 days, backup count >= 7
- FAIL: backups disabled, PITR disabled, or insufficient retention

**FIX** -- remediate if failing:
```bash
INSTANCE_NAME="your-instance"

gcloud sql instances patch "$INSTANCE_NAME" \
  --backup-start-time="02:00" \
  --enable-bin-log \
  --enable-point-in-time-recovery \
  --retained-backups-count=14 \
  --retained-transaction-log-days=7
```
Gotchas:
- `--enable-bin-log` is required for MySQL PITR; PostgreSQL uses WAL archiving automatically
- Backup start time is in UTC -- choose a low-traffic window
- Increasing `retained-backups-count` increases storage costs
- PITR allows recovery to any point within the transaction log retention window
- Backups are stored in the same region as the instance by default

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="yaml(settings.backupConfiguration)"
# Expected: enabled: true, pointInTimeRecoveryEnabled: true, retainedBackups >= 7

# List recent backups
gcloud sql backups list --instance="$INSTANCE_NAME" \
  --format="table(id,type,status,startTime,endTime)"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL Backup Configuration ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(settings.backupConfiguration)"
    echo ""
    echo "Recent backups:"
    gcloud sql backups list --instance="$INSTANCE" --format=json 2>/dev/null
  done
} > "$EVIDENCE_DIR/cloudsql-backups-$(date +%Y%m%d-%H%M%S).json"
```

---

### 24. Cloud SQL High Availability (TSC: A1.1, A1.2)

**DISCOVER** -- check current state:
```bash
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  HA=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.availabilityType)")
  echo "$INSTANCE: availabilityType=$HA"
done
```
- PASS: `REGIONAL` (high availability with automatic failover)
- FAIL: `ZONAL` (single zone, no automatic failover)

**FIX** -- remediate if failing:
```bash
INSTANCE_NAME="your-instance"

# Enable high availability (regional)
gcloud sql instances patch "$INSTANCE_NAME" \
  --availability-type=REGIONAL
```
Gotchas:
- Switching from ZONAL to REGIONAL causes a brief outage (a few minutes) for failover setup
- REGIONAL doubles the cost (standby replica in another zone)
- Failover is automatic on zone failure -- RTO is typically 1-2 minutes
- Read replicas do NOT count as HA -- they are for read scaling, not failover
- Test failover with: `gcloud sql instances failover INSTANCE_NAME`

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="value(settings.availabilityType)"
# Expected: REGIONAL
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL High Availability ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(settings.availabilityType,gceZone,secondaryGceZone,state)"
  done
} > "$EVIDENCE_DIR/cloudsql-ha-$(date +%Y%m%d-%H%M%S).json"
```

---

### 25. Cloud SQL Public IP (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  PUBLIC_IP=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(ipAddresses.filter(type=PRIMARY).ipAddress)")
  PRIVATE_IP=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(ipAddresses.filter(type=PRIVATE).ipAddress)")
  PRIVATE_NETWORK=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.ipConfiguration.privateNetwork)")
  echo "$INSTANCE: publicIP=$PUBLIC_IP privateIP=$PRIVATE_IP privateNetwork=$PRIVATE_NETWORK"
done
```
- PASS: no public IP assigned, private IP configured with VPC peering
- FAIL: public IP present

**FIX** -- remediate if failing:
```bash
INSTANCE_NAME="your-instance"
VPC_NETWORK="projects/${PROJECT_ID}/global/networks/default"

# Enable Private IP (requires VPC network with private service connection)
# First, ensure private services access is configured on the VPC:
gcloud compute addresses create google-managed-services-range \
  --global \
  --purpose=VPC_PEERING \
  --prefix-length=16 \
  --network=default \
  --project="$PROJECT_ID"

gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-range \
  --network=default \
  --project="$PROJECT_ID"

# Enable private IP on the instance
gcloud sql instances patch "$INSTANCE_NAME" \
  --network="$VPC_NETWORK" \
  --no-assign-ip

# If you cannot remove the public IP immediately, restrict authorized networks
# gcloud sql instances patch "$INSTANCE_NAME" \
#   --authorized-networks="" \
#   --no-assign-ip
```
Gotchas:
- Removing public IP breaks connections from outside the VPC -- ensure all clients use private IP or Cloud SQL Auth Proxy
- Cloud SQL Auth Proxy is the recommended connection method -- it handles SSL, IAM auth, and works from anywhere
- Private services access requires VPC network admin permissions
- The VPC peering range must not overlap with existing subnet ranges
- You can use Cloud SQL Auth Proxy from Cloud Run, GKE, or Compute Engine without a public IP

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="yaml(ipAddresses,settings.ipConfiguration.privateNetwork,settings.ipConfiguration.ipv4Enabled)"
# Expected: no PRIMARY IP, PRIVATE IP present, ipv4Enabled: false
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL Network Configuration ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(ipAddresses,settings.ipConfiguration)"
  done
} > "$EVIDENCE_DIR/cloudsql-network-$(date +%Y%m%d-%H%M%S).json"
```

---

### 26. Cloud SQL Authorized Networks (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
  echo "=== $INSTANCE ==="
  gcloud sql instances describe "$INSTANCE" \
    --format="json(settings.ipConfiguration.authorizedNetworks)"
  # Check for overly permissive 0.0.0.0/0
  OPEN=$(gcloud sql instances describe "$INSTANCE" \
    --format="value(settings.ipConfiguration.authorizedNetworks.value)" | grep -c "0.0.0.0/0" || true)
  if [ "$OPEN" -gt 0 ]; then
    echo "FAIL: 0.0.0.0/0 in authorized networks -- open to the entire internet!"
  fi
done
```
- PASS: no `0.0.0.0/0` in authorized networks; ideally no authorized networks at all (private IP only)
- FAIL: `0.0.0.0/0` present, or overly broad CIDR ranges

**FIX** -- remediate if failing:
```bash
INSTANCE_NAME="your-instance"

# Remove all authorized networks (safest if using private IP + Auth Proxy)
gcloud sql instances patch "$INSTANCE_NAME" \
  --clear-authorized-networks

# Or restrict to specific known IPs
gcloud sql instances patch "$INSTANCE_NAME" \
  --authorized-networks="203.0.113.10/32,198.51.100.0/24"
```
Gotchas:
- `--clear-authorized-networks` removes all public IP access rules
- If public IP is required, restrict to the narrowest CIDR possible
- Cloud SQL Auth Proxy is the recommended alternative to authorized networks
- Authorized networks only apply when the instance has a public IP -- private IP instances ignore them

**VERIFY** -- confirm the fix:
```bash
gcloud sql instances describe "$INSTANCE_NAME" \
  --format="json(settings.ipConfiguration.authorizedNetworks)"
# Expected: empty array [] or only specific narrow CIDRs
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud SQL Authorized Networks ==="
  for INSTANCE in $(gcloud sql instances list --format="value(name)"); do
    echo "--- $INSTANCE ---"
    gcloud sql instances describe "$INSTANCE" \
      --format="json(settings.ipConfiguration.authorizedNetworks,settings.ipConfiguration.ipv4Enabled)"
  done
} > "$EVIDENCE_DIR/cloudsql-authorized-networks-$(date +%Y%m%d-%H%M%S).json"
```

---

## VPC / Network Controls

### 27. VPC Flow Logs (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check all subnets for flow log configuration
for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
  --format="csv[no-heading](name,region)"); do
  SUBNET_NAME=$(echo "$SUBNET" | cut -d',' -f1)
  REGION=$(echo "$SUBNET" | cut -d',' -f2)
  FLOW_LOGS=$(gcloud compute networks subnets describe "$SUBNET_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="value(enableFlowLogs)")
  SAMPLE_RATE=$(gcloud compute networks subnets describe "$SUBNET_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="value(logConfig.flowSampling)" 2>/dev/null)
  if [ "$FLOW_LOGS" = "True" ]; then
    echo "PASS: $SUBNET_NAME ($REGION) flowLogs=enabled sampleRate=$SAMPLE_RATE"
  else
    echo "FAIL: $SUBNET_NAME ($REGION) flowLogs=disabled"
  fi
done
```
- PASS: all subnets have flow logs enabled
- FAIL: any subnet has flow logs disabled

**FIX** -- remediate if failing:
```bash
SUBNET_NAME="your-subnet"
REGION="us-central1"

# Enable VPC Flow Logs with recommended settings
gcloud compute networks subnets update "$SUBNET_NAME" \
  --region="$REGION" \
  --enable-flow-logs \
  --logging-aggregation-interval=INTERVAL_5_SEC \
  --logging-flow-sampling=0.5 \
  --logging-metadata=INCLUDE_ALL_METADATA \
  --project="$PROJECT_ID"

# Enable on ALL subnets at once:
for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
  --format="csv[no-heading](name,region)"); do
  SNAME=$(echo "$SUBNET" | cut -d',' -f1)
  SREG=$(echo "$SUBNET" | cut -d',' -f2)
  echo "Enabling flow logs on $SNAME ($SREG)..."
  gcloud compute networks subnets update "$SNAME" \
    --region="$SREG" \
    --enable-flow-logs \
    --logging-aggregation-interval=INTERVAL_5_SEC \
    --logging-flow-sampling=0.5 \
    --logging-metadata=INCLUDE_ALL_METADATA \
    --project="$PROJECT_ID"
done
```
Gotchas:
- Flow logs cost money -- sampling rate (0.5 = 50%) is a cost/visibility tradeoff
- `INTERVAL_5_SEC` is the most granular aggregation interval; `INTERVAL_10_MIN` is cheapest
- `INCLUDE_ALL_METADATA` adds source/dest instance info but increases log size
- Flow logs are per-subnet, not per-VPC
- For high-traffic subnets, consider `--logging-flow-sampling=0.1` (10%) to reduce cost
- Logs appear in Cloud Logging under `resource.type="gce_subnetwork"`

**VERIFY** -- confirm the fix:
```bash
gcloud compute networks subnets describe "$SUBNET_NAME" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --format="yaml(enableFlowLogs,logConfig)"
# Expected: enableFlowLogs: true with logConfig showing sampling and metadata settings
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== VPC Flow Logs Configuration ==="
  for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
    --format="csv[no-heading](name,region)"); do
    SNAME=$(echo "$SUBNET" | cut -d',' -f1)
    SREG=$(echo "$SUBNET" | cut -d',' -f2)
    echo "--- $SNAME ($SREG) ---"
    gcloud compute networks subnets describe "$SNAME" \
      --region="$SREG" \
      --project="$PROJECT_ID" \
      --format="json(enableFlowLogs,logConfig)"
  done
} > "$EVIDENCE_DIR/vpc-flow-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

### 28. Firewall Rules Audit (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Find overly permissive firewall rules (0.0.0.0/0 on sensitive ports)
echo "=== All Rules Allowing 0.0.0.0/0 ==="
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND direction=INGRESS" \
  --format="table(name,network,direction,allowed[].map().firewall_rule().list():label=ALLOWED,sourceRanges)"

echo ""
echo "=== Rules Allowing All Ports from Anywhere ==="
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND allowed.ports=() AND direction=INGRESS" \
  --format="table(name,network,allowed)"

echo ""
echo "=== Rules Exposing SSH (22) to Anywhere ==="
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND allowed.ports:(22)" \
  --format="table(name,network)"

echo ""
echo "=== Rules Exposing RDP (3389) to Anywhere ==="
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND allowed.ports:(3389)" \
  --format="table(name,network)"

echo ""
echo "=== Rules Exposing Database Ports to Anywhere ==="
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND (allowed.ports:(3306) OR allowed.ports:(5432) OR allowed.ports:(27017) OR allowed.ports:(6379))" \
  --format="table(name,network,allowed)"
```
- PASS: no rules allow 0.0.0.0/0 on SSH, RDP, database ports, or all ports
- FAIL: any of the above queries return results

**FIX** -- remediate if failing:
```bash
RULE_NAME="default-allow-ssh"

# Option A: Delete the overly permissive rule
gcloud compute firewall-rules delete "$RULE_NAME" \
  --project="$PROJECT_ID" --quiet

# Option B: Restrict to specific source ranges
gcloud compute firewall-rules update "$RULE_NAME" \
  --source-ranges="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
  --project="$PROJECT_ID"

# Option C: Replace with IAP tunnel for SSH (recommended)
# 1. Delete the open SSH rule
gcloud compute firewall-rules delete "default-allow-ssh" \
  --project="$PROJECT_ID" --quiet

# 2. Create IAP tunnel rule (allows SSH only via IAP)
gcloud compute firewall-rules create allow-ssh-via-iap \
  --project="$PROJECT_ID" \
  --network=default \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 \
  --description="Allow SSH via IAP tunnel only"
```
Gotchas:
- The default network has permissive firewall rules (`default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`, `default-allow-internal`) -- review and restrict all of them
- `35.235.240.0/20` is the IAP tunnel IP range -- this is the only source range needed for SSH via IAP
- Firewall rules are evaluated by priority (lower number = higher priority) -- ensure restrictive rules have lower priority numbers
- Use network tags to scope firewall rules to specific instances rather than entire networks
- Implied deny rule at priority 65535 blocks all ingress not explicitly allowed

**VERIFY** -- confirm the fix:
```bash
# Re-run the discovery commands
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="sourceRanges:(0.0.0.0/0) AND direction=INGRESS" \
  --format="table(name,network,allowed,sourceRanges)"
# Expected: no results, or only rules for load balancer health checks (130.211.0.0/22, 35.191.0.0/16)
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== All Firewall Rules ==="
  gcloud compute firewall-rules list --project="$PROJECT_ID" --format=json

  echo ""
  echo "=== Overly Permissive Rules (0.0.0.0/0 ingress) ==="
  gcloud compute firewall-rules list --project="$PROJECT_ID" \
    --filter="sourceRanges:(0.0.0.0/0) AND direction=INGRESS" --format=json
} > "$EVIDENCE_DIR/firewall-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

### 29. Private Google Access (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
  --format="csv[no-heading](name,region)"); do
  SUBNET_NAME=$(echo "$SUBNET" | cut -d',' -f1)
  REGION=$(echo "$SUBNET" | cut -d',' -f2)
  PGA=$(gcloud compute networks subnets describe "$SUBNET_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="value(privateIpGoogleAccess)")
  echo "$SUBNET_NAME ($REGION): privateGoogleAccess=$PGA"
done
```
- PASS: all subnets have Private Google Access enabled
- FAIL: any subnet has `privateGoogleAccess=False`

**FIX** -- remediate if failing:
```bash
SUBNET_NAME="your-subnet"
REGION="us-central1"

gcloud compute networks subnets update "$SUBNET_NAME" \
  --region="$REGION" \
  --enable-private-ip-google-access \
  --project="$PROJECT_ID"

# Enable on ALL subnets:
for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
  --format="csv[no-heading](name,region)"); do
  SNAME=$(echo "$SUBNET" | cut -d',' -f1)
  SREG=$(echo "$SUBNET" | cut -d',' -f2)
  gcloud compute networks subnets update "$SNAME" \
    --region="$SREG" \
    --enable-private-ip-google-access \
    --project="$PROJECT_ID"
done
```
Gotchas:
- Private Google Access allows VMs without external IPs to reach Google APIs (Cloud Storage, BigQuery, etc.)
- Without PGA, VMs without external IPs cannot reach `*.googleapis.com`
- PGA is required when using Cloud NAT or VMs without public IPs
- No additional cost for enabling PGA

**VERIFY** -- confirm the fix:
```bash
gcloud compute networks subnets describe "$SUBNET_NAME" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --format="value(privateIpGoogleAccess)"
# Expected: True
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Private Google Access Status ==="
  for SUBNET in $(gcloud compute networks subnets list --project="$PROJECT_ID" \
    --format="csv[no-heading](name,region)"); do
    SNAME=$(echo "$SUBNET" | cut -d',' -f1)
    SREG=$(echo "$SUBNET" | cut -d',' -f2)
    PGA=$(gcloud compute networks subnets describe "$SNAME" \
      --region="$SREG" --project="$PROJECT_ID" \
      --format="value(privateIpGoogleAccess)")
    echo "$SNAME ($SREG): privateGoogleAccess=$PGA"
  done
} > "$EVIDENCE_DIR/private-google-access-$(date +%Y%m%d-%H%M%S).txt"
```

---

### 30. Cloud NAT (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List all Cloud NAT configurations
gcloud compute routers list --project="$PROJECT_ID" \
  --format="table(name,region,network)"

# Check for NAT configurations on each router
for ROUTER in $(gcloud compute routers list --project="$PROJECT_ID" \
  --format="csv[no-heading](name,region)"); do
  ROUTER_NAME=$(echo "$ROUTER" | cut -d',' -f1)
  REGION=$(echo "$ROUTER" | cut -d',' -f2)
  echo "=== $ROUTER_NAME ($REGION) ==="
  gcloud compute routers nats list \
    --router="$ROUTER_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="table(name,natIpAllocateOption,sourceSubnetworkIpRangesToNat)" 2>/dev/null \
    || echo "No NAT configured"
done

# Check if VMs exist without external IPs and without Cloud NAT
echo ""
echo "=== VMs Without External IPs ==="
gcloud compute instances list --project="$PROJECT_ID" \
  --filter="networkInterfaces.accessConfigs.natIP='' OR NOT networkInterfaces.accessConfigs:*" \
  --format="table(name,zone,networkInterfaces[0].networkIP)" 2>/dev/null
```
- PASS: Cloud NAT configured for subnets with VMs that lack external IPs
- FAIL: VMs without external IPs exist but no Cloud NAT is configured

**FIX** -- remediate if failing:
```bash
REGION="us-central1"
NETWORK="default"
ROUTER_NAME="nat-router"
NAT_NAME="cloud-nat"

# Create a Cloud Router (required for Cloud NAT)
gcloud compute routers create "$ROUTER_NAME" \
  --network="$NETWORK" \
  --region="$REGION" \
  --project="$PROJECT_ID"

# Create Cloud NAT with automatic IP allocation
gcloud compute routers nats create "$NAT_NAME" \
  --router="$ROUTER_NAME" \
  --region="$REGION" \
  --auto-allocate-nat-external-ips \
  --nat-all-subnet-ip-ranges \
  --enable-logging \
  --project="$PROJECT_ID"
```
Gotchas:
- Cloud NAT allows VMs without external IPs to access the internet (outbound only)
- Cloud NAT is regional -- you need one per region with VMs
- `--nat-all-subnet-ip-ranges` applies to all subnets; use `--nat-custom-subnet-ip-ranges` to limit scope
- Cloud NAT logging helps track outbound connections for security monitoring
- Cloud NAT has a per-VM port allocation limit -- default is 64 ports per VM, increase if VMs make many outbound connections
- No inbound connections through Cloud NAT -- it is egress-only

**VERIFY** -- confirm the fix:
```bash
gcloud compute routers nats describe "$NAT_NAME" \
  --router="$ROUTER_NAME" \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --format="yaml(name,natIpAllocateOption,sourceSubnetworkIpRangesToNat,enableEndpointIndependentMapping,logConfig)"
# Expected: NAT configured with AUTO_ONLY IP allocation and ALL_SUBNETWORKS_ALL_IP_RANGES
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Cloud NAT Configurations ==="
  for ROUTER in $(gcloud compute routers list --project="$PROJECT_ID" \
    --format="csv[no-heading](name,region)"); do
    RNAME=$(echo "$ROUTER" | cut -d',' -f1)
    RREG=$(echo "$ROUTER" | cut -d',' -f2)
    echo "--- Router: $RNAME ($RREG) ---"
    gcloud compute routers nats list \
      --router="$RNAME" --region="$RREG" --project="$PROJECT_ID" --format=json 2>/dev/null
  done
} > "$EVIDENCE_DIR/cloud-nat-$(date +%Y%m%d-%H%M%S).json"
```

---

### 31. Default Network (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check if the default network exists
gcloud compute networks list --project="$PROJECT_ID" \
  --filter="name=default" \
  --format="table(name,autoCreateSubnetworks,subnetMode)"

# If it exists, check its firewall rules
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="network:default" \
  --format="table(name,direction,allowed,sourceRanges)"
```
- PASS: default network does not exist, or its permissive firewall rules have been removed
- FAIL: default network exists with its permissive default rules

**FIX** -- remediate if failing:
```bash
# Option A (recommended): Delete the default network entirely
# First, delete all firewall rules on the default network
for RULE in $(gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="network:default" --format="value(name)"); do
  gcloud compute firewall-rules delete "$RULE" --project="$PROJECT_ID" --quiet
done

# Delete the default network
gcloud compute networks delete default --project="$PROJECT_ID" --quiet

# Option B: Keep the default network but restrict its firewall rules
# Delete overly permissive rules
gcloud compute firewall-rules delete default-allow-ssh --project="$PROJECT_ID" --quiet
gcloud compute firewall-rules delete default-allow-rdp --project="$PROJECT_ID" --quiet
gcloud compute firewall-rules delete default-allow-icmp --project="$PROJECT_ID" --quiet

# Restrict internal rule to specific protocols and ports
gcloud compute firewall-rules update default-allow-internal \
  --project="$PROJECT_ID" \
  --rules=tcp:22,tcp:443,icmp \
  --source-ranges="10.128.0.0/9"

# Prevent the default network from being recreated in new projects
# (org policy)
cat > /tmp/skip-default-network.yaml << 'EOF'
constraint: constraints/compute.skipDefaultNetworkCreation
booleanPolicy:
  enforced: true
EOF
gcloud org-policies set-policy /tmp/skip-default-network.yaml \
  --organization="$ORG_ID"
```
Gotchas:
- The default network has four permissive rules: `default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`, `default-allow-internal`
- Deleting the default network requires deleting all its firewall rules and subnets first
- Some GCP services create resources in the default network if no network is specified -- deletion forces explicit network selection
- The org policy `compute.skipDefaultNetworkCreation` prevents the default network from being created in new projects
- If instances, load balancers, or other resources use the default network, migrate them before deletion

**VERIFY** -- confirm the fix:
```bash
# Verify default network is gone
gcloud compute networks list --project="$PROJECT_ID" \
  --filter="name=default" \
  --format="value(name)"
# Expected: no output

# Or verify its firewall rules are restricted
gcloud compute firewall-rules list --project="$PROJECT_ID" \
  --filter="network:default" \
  --format="table(name,allowed,sourceRanges)"
# Expected: no overly permissive rules
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Networks ==="
  gcloud compute networks list --project="$PROJECT_ID" --format=json

  echo ""
  echo "=== Default Network Firewall Rules ==="
  gcloud compute firewall-rules list --project="$PROJECT_ID" \
    --filter="network:default" --format=json 2>/dev/null

  echo ""
  echo "=== Org Policy: Skip Default Network ==="
  gcloud org-policies describe constraints/compute.skipDefaultNetworkCreation \
    --organization="$ORG_ID" 2>/dev/null || echo "Not set"
} > "$EVIDENCE_DIR/default-network-$(date +%Y%m%d-%H%M%S).json"
```

---

## Cloud KMS Controls

### 32. Key Rotation (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# List all keyrings and keys with rotation settings
# Check each location where keyrings may exist
for LOCATION in global us us-central1; do
  for KEYRING in $(gcloud kms keyrings list --location="$LOCATION" --project="$PROJECT_ID" \
    --format="value(name.basename())" 2>/dev/null); do
    for KEY in $(gcloud kms keys list \
      --keyring="$KEYRING" --location="$LOCATION" --project="$PROJECT_ID" \
      --format="value(name.basename())" 2>/dev/null); do
      ROTATION=$(gcloud kms keys describe "$KEY" \
        --keyring="$KEYRING" --location="$LOCATION" --project="$PROJECT_ID" \
        --format="value(rotationPeriod)" 2>/dev/null)
      NEXT=$(gcloud kms keys describe "$KEY" \
        --keyring="$KEYRING" --location="$LOCATION" --project="$PROJECT_ID" \
        --format="value(nextRotationTime)" 2>/dev/null)
      if [ -n "$ROTATION" ]; then
        echo "OK: $KEY (keyring=$KEYRING, location=$LOCATION) rotation=$ROTATION next=$NEXT"
      else
        echo "FAIL: $KEY (keyring=$KEYRING, location=$LOCATION) NO ROTATION configured"
      fi
    done
  done
done
```
- PASS: all encryption keys have automatic rotation configured (90 days recommended)
- FAIL: any key has no rotation period set

**FIX** -- remediate if failing:
```bash
KEYRING="soc2-keyring"
KEY_NAME="your-key"
LOCATION="us"

# Enable automatic rotation every 90 days
gcloud kms keys update "$KEY_NAME" \
  --keyring="$KEYRING" \
  --location="$LOCATION" \
  --rotation-period=90d \
  --next-rotation-time=$(date -u -v+90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ) \
  --project="$PROJECT_ID"
```
Gotchas:
- Rotation creates a new key version -- old versions are still used to decrypt data encrypted with them
- Only symmetric encryption keys support automatic rotation
- Asymmetric keys must be rotated manually (create new version, update references)
- Minimum rotation period is 1 day; recommended is 90 days for SOC 2
- Key rotation does NOT re-encrypt existing data -- data remains encrypted with the key version used at write time
- To re-encrypt with the latest key version, read and rewrite the data

**VERIFY** -- confirm the fix:
```bash
gcloud kms keys describe "$KEY_NAME" \
  --keyring="$KEYRING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID" \
  --format="yaml(rotationPeriod,nextRotationTime,primary.state)"
# Expected: rotationPeriod: 7776000s (90 days), nextRotationTime set, primary.state: ENABLED
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== KMS Key Rotation Status ==="
  for LOCATION in global us us-central1; do
    for KEYRING in $(gcloud kms keyrings list --location="$LOCATION" --project="$PROJECT_ID" \
      --format="value(name.basename())" 2>/dev/null); do
      for KEY in $(gcloud kms keys list --keyring="$KEYRING" --location="$LOCATION" \
        --project="$PROJECT_ID" --format="value(name.basename())" 2>/dev/null); do
        echo "--- $KEY (keyring=$KEYRING, location=$LOCATION) ---"
        gcloud kms keys describe "$KEY" \
          --keyring="$KEYRING" --location="$LOCATION" --project="$PROJECT_ID" \
          --format="json(rotationPeriod,nextRotationTime,primary,versionTemplate)" 2>/dev/null
      done
    done
  done
} > "$EVIDENCE_DIR/kms-rotation-$(date +%Y%m%d-%H%M%S).json"
```

---

### 33. IAM Policies on Keyrings (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Check IAM policies on each keyring for overly permissive bindings
for LOCATION in global us us-central1; do
  for KEYRING in $(gcloud kms keyrings list --location="$LOCATION" --project="$PROJECT_ID" \
    --format="value(name.basename())" 2>/dev/null); do
    echo "=== $KEYRING ($LOCATION) ==="
    gcloud kms keyrings get-iam-policy "$KEYRING" \
      --location="$LOCATION" \
      --project="$PROJECT_ID" \
      --format="table(bindings.role,bindings.members)"

    # Check for broad bindings
    BROAD=$(gcloud kms keyrings get-iam-policy "$KEYRING" \
      --location="$LOCATION" \
      --project="$PROJECT_ID" \
      --flatten="bindings[].members" \
      --filter="bindings.members:(allUsers OR allAuthenticatedUsers OR domain:)" \
      --format="value(bindings.members)" 2>/dev/null)
    if [ -n "$BROAD" ]; then
      echo "FAIL: Overly broad access detected: $BROAD"
    fi
  done
done
```
- PASS: keyring IAM policies follow least privilege -- only specific service accounts and admin users
- FAIL: broad domain-wide access, `allUsers`, or unnecessary `roles/cloudkms.admin` bindings

**FIX** -- remediate if failing:
```bash
KEYRING="soc2-keyring"
LOCATION="us"

# Remove overly broad binding
gcloud kms keyrings remove-iam-policy-binding "$KEYRING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID" \
  --member="domain:example.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Add specific least-privilege bindings
# Encrypt/decrypt for application service accounts
gcloud kms keyrings add-iam-policy-binding "$KEYRING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID" \
  --member="serviceAccount:app-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Admin for security team only
gcloud kms keyrings add-iam-policy-binding "$KEYRING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID" \
  --member="group:security-admins@example.com" \
  --role="roles/cloudkms.admin"
```
Gotchas:
- `roles/cloudkms.admin` can manage keys but NOT encrypt/decrypt -- separation of duties
- `roles/cloudkms.cryptoKeyEncrypterDecrypter` can encrypt/decrypt but NOT manage keys
- Never grant `roles/owner` at the keyring level -- use specific KMS roles
- IAM policies can be set at keyring or individual key level -- key-level is more granular
- Destroying a key version requires `roles/cloudkms.admin` -- restrict this carefully

**VERIFY** -- confirm the fix:
```bash
gcloud kms keyrings get-iam-policy "$KEYRING" \
  --location="$LOCATION" \
  --project="$PROJECT_ID" \
  --format="table(bindings.role,bindings.members)"
# Expected: only specific service accounts and admin groups
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== KMS Keyring IAM Policies ==="
  for LOCATION in global us us-central1; do
    for KEYRING in $(gcloud kms keyrings list --location="$LOCATION" --project="$PROJECT_ID" \
      --format="value(name.basename())" 2>/dev/null); do
      echo "--- $KEYRING ($LOCATION) ---"
      gcloud kms keyrings get-iam-policy "$KEYRING" \
        --location="$LOCATION" --project="$PROJECT_ID" --format=json
    done
  done
} > "$EVIDENCE_DIR/kms-iam-policies-$(date +%Y%m%d-%H%M%S).json"
```

---

### 34. Key Usage Audit (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Cloud KMS operations are automatically logged in Admin Activity and Data Access audit logs.
# Verify KMS audit logs are flowing:
gcloud logging read \
  'resource.type="cloudkms_cryptokey" OR resource.type="cloudkms_cryptokeyversion"' \
  --project="$PROJECT_ID" \
  --limit=10 \
  --format="table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)"

# Check Data Access logs for encrypt/decrypt operations
gcloud logging read \
  'protoPayload.serviceName="cloudkms.googleapis.com" AND logName:"data_access"' \
  --project="$PROJECT_ID" \
  --limit=10 \
  --format="table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail)" 2>/dev/null
```
- PASS: KMS audit logs show recent operations (key management and encrypt/decrypt)
- FAIL: no KMS audit logs (Data Access logs may not be enabled -- see control 8)

**FIX** -- remediate if failing:
```bash
# KMS admin operations (create, rotate, destroy keys) are always logged via Admin Activity logs.
# Encrypt/decrypt operations are logged via Data Access logs -- these must be enabled.
# See control 8 for enabling Data Access logs.

# Verify Data Access logs are enabled for KMS specifically:
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs[] | select(.service == "allServices" or .service == "cloudkms.googleapis.com")'

# If not enabled for allServices, enable for KMS:
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/project-policy.json

jq '.auditConfigs += [{
  "service": "cloudkms.googleapis.com",
  "auditLogConfigs": [
    {"logType": "ADMIN_READ"},
    {"logType": "DATA_READ"},
    {"logType": "DATA_WRITE"}
  ]
}]' /tmp/project-policy.json > /tmp/project-policy-updated.json

gcloud projects set-iam-policy "$PROJECT_ID" /tmp/project-policy-updated.json
```
Gotchas:
- Admin Activity logs for KMS are always on (key creation, rotation, destruction)
- Data Access logs for KMS (encrypt/decrypt operations) require explicit enablement
- High-volume encrypt/decrypt operations can generate significant log volume -- consider exempting automated service accounts from DATA_READ
- KMS audit logs include the key name and version used but NOT the plaintext data

**VERIFY** -- confirm the fix:
```bash
# Verify Data Access logs for KMS are enabled
gcloud projects get-iam-policy "$PROJECT_ID" \
  --format=json | jq '.auditConfigs[] | select(.service == "allServices" or .service == "cloudkms.googleapis.com")'
# Expected: DATA_READ, DATA_WRITE, ADMIN_READ log types

# Verify logs are flowing
gcloud logging read \
  'protoPayload.serviceName="cloudkms.googleapis.com"' \
  --project="$PROJECT_ID" \
  --limit=5 \
  --format="table(timestamp,protoPayload.methodName)"
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== KMS Audit Log Configuration ==="
  gcloud projects get-iam-policy "$PROJECT_ID" \
    --format=json | jq '.auditConfigs[] | select(.service == "allServices" or .service == "cloudkms.googleapis.com")'

  echo ""
  echo "=== Recent KMS Admin Activity ==="
  gcloud logging read \
    'resource.type="cloudkms_cryptokey" AND logName:"activity"' \
    --project="$PROJECT_ID" --limit=25 --format=json

  echo ""
  echo "=== Recent KMS Data Access ==="
  gcloud logging read \
    'protoPayload.serviceName="cloudkms.googleapis.com" AND logName:"data_access"' \
    --project="$PROJECT_ID" --limit=25 --format=json 2>/dev/null
} > "$EVIDENCE_DIR/kms-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

## Cloud Monitoring Controls

### 35. Log-Based Metrics (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# List all custom log-based metrics
gcloud logging metrics list --project="$PROJECT_ID" \
  --format="table(name,description,filter)"

# Check for expected security metrics
EXPECTED_METRICS=(
  "unauthorized-access-attempts"
  "iam-policy-changes"
  "sa-key-creation"
  "firewall-changes"
  "custom-role-changes"
  "vpc-network-changes"
  "cloud-storage-permission-changes"
  "route-changes"
  "cloudsql-config-changes"
)
echo ""
echo "=== Expected Metrics Check ==="
for METRIC in "${EXPECTED_METRICS[@]}"; do
  gcloud logging metrics describe "$METRIC" --project="$PROJECT_ID" 2>/dev/null \
    && echo "FOUND: $METRIC" \
    || echo "MISSING: $METRIC"
done
```
- PASS: all expected security metrics exist
- FAIL: missing metrics

**FIX** -- remediate if failing:
```bash
# Unauthorized access attempts (403 errors)
gcloud logging metrics create unauthorized-access-attempts \
  --project="$PROJECT_ID" \
  --description="Unauthorized API access attempts (permission denied)" \
  --log-filter='protoPayload.status.code=7 OR protoPayload.status.message="PERMISSION_DENIED"'

# VPC network changes
gcloud logging metrics create vpc-network-changes \
  --project="$PROJECT_ID" \
  --description="VPC network creation, deletion, or modification" \
  --log-filter='resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.update" OR protoPayload.methodName:"compute.subnetworks.insert" OR protoPayload.methodName:"compute.subnetworks.delete" OR protoPayload.methodName:"compute.subnetworks.patch")'

# Cloud Storage IAM/permission changes
gcloud logging metrics create cloud-storage-permission-changes \
  --project="$PROJECT_ID" \
  --description="Cloud Storage bucket IAM or ACL changes" \
  --log-filter='resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"'

# Route changes
gcloud logging metrics create route-changes \
  --project="$PROJECT_ID" \
  --description="VPC route creation or deletion" \
  --log-filter='resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.insert" OR protoPayload.methodName:"compute.routes.delete")'

# SQL instance configuration changes
gcloud logging metrics create cloudsql-config-changes \
  --project="$PROJECT_ID" \
  --description="Cloud SQL instance configuration changes" \
  --log-filter='protoPayload.methodName="cloudsql.instances.update" OR protoPayload.methodName="cloudsql.instances.patch"'
```
Gotchas:
- Log-based metrics only count log entries AFTER metric creation -- no historical data
- Metrics created in control 11 (iam-policy-changes, sa-key-creation, firewall-changes, custom-role-changes) are listed here for completeness
- Filter syntax must match Cloud Logging filter language exactly
- Test filters first with `gcloud logging read 'YOUR_FILTER' --limit=5` to verify they match expected events
- Custom metrics appear under `logging.googleapis.com/user/METRIC_NAME` in Cloud Monitoring

**VERIFY** -- confirm the fix:
```bash
gcloud logging metrics list --project="$PROJECT_ID" \
  --format="table(name,filter)"
# Expected: all security metrics listed
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Log-Based Metrics ==="
  gcloud logging metrics list --project="$PROJECT_ID" --format=json
} > "$EVIDENCE_DIR/log-based-metrics-$(date +%Y%m%d-%H%M%S).json"
```

---

### 36. Alerting Policies (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List all alerting policies
gcloud alpha monitoring policies list --project="$PROJECT_ID" \
  --format="table(displayName,enabled,conditions.displayName)" 2>/dev/null

# Check notification channels
gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --format="table(displayName,type,enabled)" 2>/dev/null
```
- PASS: alerting policies exist for each log-based metric, with active notification channels
- FAIL: no alerting policies or no notification channels

**FIX** -- remediate if failing:
```bash
# Create notification channels (if not already done in control 11)

# Email channel
EMAIL_CHANNEL=$(gcloud alpha monitoring channels create \
  --display-name="Security Alerts Email" \
  --type=email \
  --channel-labels="email_address=security@example.com" \
  --project="$PROJECT_ID" \
  --format="value(name)" 2>/dev/null)

# Slack channel (requires Slack workspace integration)
# SLACK_CHANNEL=$(gcloud alpha monitoring channels create \
#   --display-name="Security Alerts Slack" \
#   --type=slack \
#   --channel-labels="channel_name=#security-alerts,auth_token=xoxb-YOUR-TOKEN" \
#   --project="$PROJECT_ID" \
#   --format="value(name)" 2>/dev/null)

# PagerDuty channel
# PD_CHANNEL=$(gcloud alpha monitoring channels create \
#   --display-name="Security PagerDuty" \
#   --type=pagerduty \
#   --channel-labels="service_key=YOUR_PD_KEY" \
#   --project="$PROJECT_ID" \
#   --format="value(name)" 2>/dev/null)

# Create alerting policy for unauthorized access attempts
cat > /tmp/unauth-alert.json << EOF
{
  "displayName": "Unauthorized Access Attempts Spike",
  "conditions": [
    {
      "displayName": "Unauthorized access > 10 in 5 minutes",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/unauthorized-access-attempts\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 10,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["${EMAIL_CHANNEL}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/unauth-alert.json \
  --project="$PROJECT_ID"

# Create alerting policy for VPC network changes
cat > /tmp/vpc-alert.json << EOF
{
  "displayName": "VPC Network Change Alert",
  "conditions": [
    {
      "displayName": "VPC network modification detected",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/vpc-network-changes\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["${EMAIL_CHANNEL}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/vpc-alert.json \
  --project="$PROJECT_ID"

# Create alerting policy for Cloud SQL config changes
cat > /tmp/sql-alert.json << EOF
{
  "displayName": "Cloud SQL Configuration Change Alert",
  "conditions": [
    {
      "displayName": "Cloud SQL config modified",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/cloudsql-config-changes\" AND resource.type=\"project\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "0s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_COUNT"
          }
        ]
      }
    }
  ],
  "notificationChannels": ["${EMAIL_CHANNEL}"],
  "combiner": "OR",
  "enabled": true
}
EOF
gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/sql-alert.json \
  --project="$PROJECT_ID"
```
Gotchas:
- Each alerting policy requires at least one notification channel
- Slack and PagerDuty channels require prior integration setup in the Cloud Console
- Alert conditions use `alignmentPeriod` to aggregate -- 300s (5 minutes) is typical
- `thresholdValue: 0` with `COMPARISON_GT` means "alert on any occurrence"
- For noisy metrics (like unauthorized access), set a higher threshold to reduce false positives
- Alerting policies can also be managed via Terraform (see Terraform section)

**VERIFY** -- confirm the fix:
```bash
echo "=== Alerting Policies ==="
gcloud alpha monitoring policies list --project="$PROJECT_ID" \
  --format="table(displayName,enabled)" 2>/dev/null

echo ""
echo "=== Notification Channels ==="
gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --format="table(displayName,type,enabled)" 2>/dev/null
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Alerting Policies ==="
  gcloud alpha monitoring policies list --project="$PROJECT_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Notification Channels ==="
  gcloud alpha monitoring channels list --project="$PROJECT_ID" --format=json 2>/dev/null
} > "$EVIDENCE_DIR/alerting-policies-$(date +%Y%m%d-%H%M%S).json"
```

---

### 37. Uptime Checks (TSC: A1.1, A1.2)

**DISCOVER** -- check current state:
```bash
gcloud monitoring uptime list-configs --project="$PROJECT_ID" \
  --format="table(displayName,monitoredResource.type,httpCheck.path,period)" 2>/dev/null \
  || echo "No uptime checks configured"
```
- PASS: uptime checks exist for all production endpoints
- FAIL: no uptime checks or missing coverage for critical endpoints

**FIX** -- remediate if failing:
```bash
# Create uptime check for a production HTTPS endpoint
cat > /tmp/uptime-check.json << 'EOF'
{
  "displayName": "Production API Health Check",
  "monitoredResource": {
    "type": "uptime_url",
    "labels": {
      "project_id": "PROJECT_ID_PLACEHOLDER",
      "host": "api.example.com"
    }
  },
  "httpCheck": {
    "path": "/health",
    "port": 443,
    "useSsl": true,
    "validateSsl": true,
    "requestMethod": "GET",
    "acceptedResponseStatusCodes": [
      {"statusClass": "STATUS_CLASS_2XX"}
    ]
  },
  "period": "60s",
  "timeout": "10s",
  "selectedRegions": [
    "USA",
    "EUROPE",
    "ASIA_PACIFIC"
  ]
}
EOF
# Replace placeholder
sed -i '' "s/PROJECT_ID_PLACEHOLDER/$PROJECT_ID/" /tmp/uptime-check.json 2>/dev/null \
  || sed -i "s/PROJECT_ID_PLACEHOLDER/$PROJECT_ID/" /tmp/uptime-check.json

gcloud monitoring uptime create --config-from-file=/tmp/uptime-check.json \
  --project="$PROJECT_ID" 2>/dev/null \
  || echo "Create uptime check via Console: https://console.cloud.google.com/monitoring/uptime"

# Create alerting policy for uptime check failure
# (Uptime checks auto-create a metric: monitoring.googleapis.com/uptime_check/check_passed)
# Configure the alert via Console or Terraform for best results
```
Gotchas:
- Uptime checks run from Google-owned IP ranges -- ensure firewall rules allow these IPs
- Google publishes uptime check source IPs: `gcloud monitoring uptime list-ips`
- Maximum 100 uptime checks per project (default quota)
- Uptime check results are visible in Cloud Monitoring dashboards
- For internal endpoints (private IP), use internal uptime checks (requires VPC access)
- `gcloud monitoring uptime` commands may require `monitoring.uptimeCheckConfigs.create` permission

**VERIFY** -- confirm the fix:
```bash
gcloud monitoring uptime list-configs --project="$PROJECT_ID" \
  --format="table(displayName,monitoredResource.labels.host,httpCheck.path,period)"
# Expected: uptime checks for all production endpoints
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Uptime Check Configurations ==="
  gcloud monitoring uptime list-configs --project="$PROJECT_ID" --format=json 2>/dev/null

  echo ""
  echo "=== Uptime Check Source IPs ==="
  gcloud monitoring uptime list-ips --format=json 2>/dev/null
} > "$EVIDENCE_DIR/uptime-checks-$(date +%Y%m%d-%H%M%S).json"
```

---

### 38. Notification Channels (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --format="table(displayName,type,enabled,verificationStatus)" 2>/dev/null
```
- PASS: multiple notification channel types configured (email + at least one of: Slack, PagerDuty, SMS), all verified and enabled
- FAIL: no channels, or only unverified channels

**FIX** -- remediate if failing:
```bash
# Email notification channel
gcloud alpha monitoring channels create \
  --display-name="Security Team Email" \
  --type=email \
  --channel-labels="email_address=security@example.com" \
  --project="$PROJECT_ID"

# Additional email channel for on-call
gcloud alpha monitoring channels create \
  --display-name="On-Call Email" \
  --type=email \
  --channel-labels="email_address=oncall@example.com" \
  --project="$PROJECT_ID"

# Slack integration (requires setup in Cloud Console first):
# 1. Go to https://console.cloud.google.com/monitoring/settings/notification
# 2. Click "Add New" under Slack
# 3. Authorize the Google Cloud Monitoring Slack app
# 4. Select the channel

# PagerDuty integration (requires PagerDuty service key):
# 1. In PagerDuty, create a new Service with Google Cloud Monitoring integration
# 2. Copy the integration key
# gcloud alpha monitoring channels create \
#   --display-name="PagerDuty Security" \
#   --type=pagerduty \
#   --channel-labels="service_key=YOUR_INTEGRATION_KEY" \
#   --project="$PROJECT_ID"

# Verify email channels (sends verification email)
for CHANNEL_ID in $(gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --filter="type=email AND verificationStatus!=VERIFIED" \
  --format="value(name.basename())" 2>/dev/null); do
  gcloud alpha monitoring channels verify "$CHANNEL_ID" --project="$PROJECT_ID" 2>/dev/null
done
```
Gotchas:
- Email channels must be verified before they receive alerts
- Slack and PagerDuty integrations require initial setup in the Cloud Console (not CLI-only)
- For SOC 2, auditors want to see at least two notification methods (redundancy)
- Notification channels are per-project -- for organization-wide alerts, configure in a central monitoring project
- Test each channel by triggering a test notification from the Cloud Console

**VERIFY** -- confirm the fix:
```bash
gcloud alpha monitoring channels list --project="$PROJECT_ID" \
  --format="table(displayName,type,enabled,verificationStatus)" 2>/dev/null
# Expected: multiple channels, all enabled and verified
```

**EVIDENCE** -- capture for auditor:
```bash
{
  echo "=== Notification Channels ==="
  gcloud alpha monitoring channels list --project="$PROJECT_ID" --format=json 2>/dev/null
} > "$EVIDENCE_DIR/notification-channels-$(date +%Y%m%d-%H%M%S).json"
```

---

## Terraform GCP Module

A complete, production-ready Terraform module that deploys all foundational SOC 2 controls on GCP.

```hcl
# ============================================================================
# SOC 2 GCP Controls - Complete Terraform Module
# ============================================================================
# Usage:
#   module "soc2_gcp" {
#     source              = "./modules/soc2-gcp"
#     project_id          = "my-project"
#     org_id              = "123456789"
#     region              = "us-central1"
#     security_email      = "security@example.com"
#     log_retention_days  = 365
#   }
# ============================================================================

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "org_id" {
  description = "GCP organization ID"
  type        = string
}

variable "region" {
  description = "Default GCP region"
  type        = string
  default     = "us-central1"
}

variable "security_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain logs in Cloud Storage"
  type        = number
  default     = 365
}

variable "kms_rotation_period" {
  description = "KMS key rotation period in seconds (default: 90 days)"
  type        = string
  default     = "7776000s"
}

variable "flow_log_sampling" {
  description = "VPC Flow Log sampling rate (0.0 to 1.0)"
  type        = number
  default     = 0.5
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}

locals {
  default_labels = merge(var.labels, {
    managed_by = "terraform"
    module     = "soc2-gcp"
    purpose    = "soc2-compliance"
  })

  project_number = data.google_project.current.number
}

data "google_project" "current" {
  project_id = var.project_id
}

# ============================================================================
# Organization Policies
# ============================================================================

resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "organizations/${var.org_id}/policies/storage.uniformBucketLevelAccess"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "public_access_prevention" {
  name   = "organizations/${var.org_id}/policies/storage.publicAccessPrevention"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "skip_default_network" {
  name   = "organizations/${var.org_id}/policies/compute.skipDefaultNetworkCreation"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ============================================================================
# Cloud Audit Log Configuration (Data Access Logs for All Services)
# ============================================================================

resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# ============================================================================
# Log Sink to Cloud Storage with Retention
# ============================================================================

resource "google_storage_bucket" "audit_logs" {
  name          = "${var.project_id}-soc2-audit-logs"
  project       = var.project_id
  location      = upper(var.region)
  force_destroy = false
  labels        = local.default_labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  retention_policy {
    is_locked        = false  # Set to true after validation to make immutable
    retention_period = var.log_retention_days * 86400
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 90
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 365
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 730
    }
  }
}

resource "google_logging_project_sink" "audit_log_sink" {
  name        = "soc2-audit-log-archive"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""

  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_log_sink.writer_identity
}

# ============================================================================
# Cloud Logging Bucket Retention
# ============================================================================

resource "google_logging_project_bucket_config" "default" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "_Default"
  retention_days = var.log_retention_days
}

# ============================================================================
# Security Command Center (enablement is org-level via Console)
# SCC notification export to Pub/Sub
# ============================================================================

resource "google_pubsub_topic" "scc_findings" {
  name    = "scc-findings-export"
  project = var.project_id
  labels  = local.default_labels
}

resource "google_pubsub_subscription" "scc_findings_sub" {
  name    = "scc-findings-sub"
  topic   = google_pubsub_topic.scc_findings.name
  project = var.project_id
  labels  = local.default_labels

  ack_deadline_seconds = 60

  expiration_policy {
    ttl = ""  # Never expire
  }
}

resource "google_scc_notification_config" "high_critical" {
  config_id    = "soc2-high-critical-findings"
  organization = var.org_id
  description  = "Export HIGH and CRITICAL SCC findings to Pub/Sub"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "severity=\"HIGH\" OR severity=\"CRITICAL\""
  }
}

# ============================================================================
# Cloud KMS Key for Encryption
# ============================================================================

resource "google_kms_key_ring" "soc2" {
  name     = "soc2-keyring"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "storage" {
  name            = "storage-encryption-key"
  key_ring        = google_kms_key_ring.soc2.id
  rotation_period = var.kms_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  labels = local.default_labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "cloudsql" {
  name            = "cloudsql-encryption-key"
  key_ring        = google_kms_key_ring.soc2.id
  rotation_period = var.kms_rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  labels = local.default_labels

  lifecycle {
    prevent_destroy = true
  }
}

# ============================================================================
# Log-Based Metrics
# ============================================================================

resource "google_logging_metric" "iam_policy_changes" {
  name    = "iam-policy-changes"
  project = var.project_id
  filter  = "protoPayload.methodName=\"SetIamPolicy\" OR protoPayload.methodName=\"SetOrgPolicy\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_logging_metric" "sa_key_creation" {
  name    = "sa-key-creation"
  project = var.project_id
  filter  = "protoPayload.methodName=\"google.iam.admin.v1.CreateServiceAccountKey\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_logging_metric" "firewall_changes" {
  name    = "firewall-changes"
  project = var.project_id
  filter  = "resource.type=\"gce_firewall_rule\" AND (protoPayload.methodName:\"compute.firewalls.insert\" OR protoPayload.methodName:\"compute.firewalls.update\" OR protoPayload.methodName:\"compute.firewalls.delete\" OR protoPayload.methodName:\"compute.firewalls.patch\")"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_logging_metric" "unauthorized_access" {
  name    = "unauthorized-access-attempts"
  project = var.project_id
  filter  = "protoPayload.status.code=7 OR protoPayload.status.message=\"PERMISSION_DENIED\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_logging_metric" "custom_role_changes" {
  name    = "custom-role-changes"
  project = var.project_id
  filter  = "resource.type=\"iam_role\" AND (protoPayload.methodName:\"CreateRole\" OR protoPayload.methodName:\"UpdateRole\" OR protoPayload.methodName:\"DeleteRole\")"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_logging_metric" "vpc_network_changes" {
  name    = "vpc-network-changes"
  project = var.project_id
  filter  = "resource.type=\"gce_network\" AND (protoPayload.methodName:\"compute.networks.insert\" OR protoPayload.methodName:\"compute.networks.delete\" OR protoPayload.methodName:\"compute.networks.patch\")"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# ============================================================================
# Notification Channel
# ============================================================================

resource "google_monitoring_notification_channel" "security_email" {
  display_name = "Security Team Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.security_email
  }
}

# ============================================================================
# Alerting Policies
# ============================================================================

resource "google_monitoring_alert_policy" "iam_changes" {
  display_name = "IAM Policy Change Alert"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "IAM policy change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_policy_changes.name}\" AND resource.type=\"project\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.security_email.name
  ]
}

resource "google_monitoring_alert_policy" "sa_key_creation" {
  display_name = "Service Account Key Creation Alert"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "SA key created"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_creation.name}\" AND resource.type=\"project\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.security_email.name
  ]
}

resource "google_monitoring_alert_policy" "firewall_changes" {
  display_name = "Firewall Rule Change Alert"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "Firewall rule changed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.firewall_changes.name}\" AND resource.type=\"project\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.security_email.name
  ]
}

resource "google_monitoring_alert_policy" "unauthorized_access" {
  display_name = "Unauthorized Access Attempts Spike"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "Unauthorized access > 10 in 5 minutes"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unauthorized_access.name}\" AND resource.type=\"project\""
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.security_email.name
  ]
}

# ============================================================================
# VPC Flow Logs on All Subnets
# ============================================================================
# Note: VPC Flow Logs must be enabled per-subnet. If you manage subnets via
# Terraform, add the log_config block to each google_compute_subnetwork resource:
#
#   resource "google_compute_subnetwork" "example" {
#     name          = "example-subnet"
#     ip_cidr_range = "10.0.0.0/24"
#     region        = var.region
#     network       = google_compute_network.vpc.id
#     project       = var.project_id
#
#     log_config {
#       aggregation_interval = "INTERVAL_5_SEC"
#       flow_sampling        = var.flow_log_sampling
#       metadata             = "INCLUDE_ALL_METADATA"
#     }
#   }
#
# For existing subnets not managed by Terraform, use the gcloud commands
# in control 27 to enable flow logs.

# ============================================================================
# Outputs
# ============================================================================

output "audit_log_bucket" {
  description = "Cloud Storage bucket for audit log archive"
  value       = google_storage_bucket.audit_logs.name
}

output "kms_keyring" {
  description = "KMS keyring for SOC 2 encryption keys"
  value       = google_kms_key_ring.soc2.id
}

output "kms_storage_key" {
  description = "KMS key for Cloud Storage encryption"
  value       = google_kms_crypto_key.storage.id
}

output "kms_cloudsql_key" {
  description = "KMS key for Cloud SQL encryption"
  value       = google_kms_crypto_key.cloudsql.id
}

output "scc_pubsub_topic" {
  description = "Pub/Sub topic for SCC finding exports"
  value       = google_pubsub_topic.scc_findings.name
}

output "notification_channel" {
  description = "Monitoring notification channel for security alerts"
  value       = google_monitoring_notification_channel.security_email.name
}

output "log_sink" {
  description = "Log sink for audit log archival"
  value       = google_logging_project_sink.audit_log_sink.name
}
```

---

## Edge Cases and Gotchas

### Cloud SQL Encryption Is Always On

Cloud SQL instances are always encrypted at rest with Google-managed keys. Unlike AWS RDS where unencrypted instances are possible, GCP enforces encryption by default. CMEK (Customer-Managed Encryption Keys) is optional and provides:
- Customer-controlled key lifecycle (rotation, destruction)
- Separation of key management from data management
- Required by some auditors for demonstrating full encryption control

CMEK is a creation-time setting -- you cannot add CMEK to an existing instance. Migration requires export, new instance creation with CMEK, and import.

### Data Access Logs Are NOT Enabled by Default

This is the most commonly missed GCP SOC 2 control. Admin Activity logs are always on, but Data Access logs (who read what data) must be explicitly enabled per service or for `allServices`. Without Data Access logs, you have no visibility into:
- Who accessed data in Cloud Storage, BigQuery, Cloud SQL
- Who read secrets from Secret Manager
- Who downloaded encryption keys from KMS

Enable for `allServices` for compliance, but be aware of the cost implications on high-volume services.

### Default VPC Network Has Permissive Firewall Rules

Every GCP project gets a `default` network with four permissive firewall rules:
- `default-allow-ssh` -- SSH (22) from `0.0.0.0/0`
- `default-allow-rdp` -- RDP (3389) from `0.0.0.0/0`
- `default-allow-icmp` -- ICMP from `0.0.0.0/0`
- `default-allow-internal` -- all protocols/ports from `10.128.0.0/9`

For SOC 2: delete the default network or restrict these rules. Use the org policy `compute.skipDefaultNetworkCreation` to prevent the default network in new projects.

### Organization Policies Require Organization-Level Access

Org policies (`gcloud org-policies`) operate at the organization level, not the project level. You need:
- `roles/orgpolicy.policyAdmin` at the organization level
- Organization ID (not project ID): `gcloud organizations list`

If you only have project-level access, you can still audit individual resources (buckets, instances, etc.) but cannot set organization-wide constraints. Coordinate with your organization admin.

### Some SCC Features Require Premium Tier

Security Command Center tiers:

| Feature | Standard (Free) | Premium (Paid) |
|---|---|---|
| Security Health Analytics | Yes | Yes |
| Web Security Scanner | Yes | Yes |
| Event Threat Detection | No | Yes |
| Container Threat Detection | No | Yes |
| VM Threat Detection | No | Yes |
| Rapid Vulnerability Detection | No | Yes |
| Attack Path Simulation | No | Yes |

Standard tier covers most SOC 2 requirements (misconfiguration detection). Premium adds runtime threat detection comparable to AWS GuardDuty. The cost is per-resource per month.

### Cloud Identity Is Separate from Google Workspace

Cloud Identity provides identity management (users, groups, 2SV) independently from Google Workspace (email, docs, etc.). Key differences:
- Cloud Identity Free: basic user/group management, 2SV, no Workspace apps
- Cloud Identity Premium: adds device management, advanced security features
- Google Workspace: includes Cloud Identity + Workspace apps

For GCP-only environments without Google Workspace, use Cloud Identity Free for user management and 2SV enforcement. 2SV is managed in Google Admin Console (`admin.google.com`), not gcloud CLI.

### VPC Flow Logs Cost Optimization

| Sampling Rate | Log Volume | Cost Impact | Use Case |
|---|---|---|---|
| 1.0 (100%) | Full | Highest | Forensic analysis, strict compliance |
| 0.5 (50%) | Half | Moderate | Recommended for SOC 2 |
| 0.1 (10%) | Low | Lowest | High-traffic production environments |

Aggregation interval also affects cost:
- `INTERVAL_5_SEC` -- most granular, highest volume
- `INTERVAL_10_MIN` -- least granular, lowest volume

For SOC 2, 50% sampling with 5-second intervals is a reasonable default. Adjust based on traffic volume and budget.

### Cloud Logging Retention vs Cloud Storage Retention

| Log Type | Default Retention | Max in Cloud Logging | Recommended Approach |
|---|---|---|---|
| Admin Activity | 400 days (fixed) | 400 days (cannot change) | Sink to Cloud Storage for >400 days |
| Data Access | 30 days | 3650 days | Increase _Default bucket or sink |
| System Event | 400 days (fixed) | 400 days (cannot change) | Sink to Cloud Storage for >400 days |
| Policy Denied | 30 days | 3650 days | Increase _Default bucket or sink |

The most cost-effective approach: keep Cloud Logging `_Default` at 30 days, sink all audit logs to Cloud Storage with lifecycle tiering (Nearline at 90d, Coldline at 365d, Archive at 730d).
