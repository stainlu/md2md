# section 03: platform controls

covers source control (GitHub), identity providers (Okta, Google Workspace), and endpoint security. every control follows DISCOVER > FIX > VERIFY > EVIDENCE.

> this section addresses CC6.1 (logical access), CC6.2 (credentials), CC6.3 (access removal), CC8.1 (change management), and CC7.1 (monitoring) as they apply to platform-layer controls.

---

## 3.1 GitHub / source control security

### 3.1.1 branch protection on main/production

the #1 change management control auditors check. without branch protection, anyone can push directly to production — instant audit finding.

**DISCOVER**

```bash
# check current branch protection on main
gh api repos/{{OWNER}}/{{REPO}}/branches/main/protection \
  --jq '{
    required_status_checks: .required_status_checks,
    enforce_admins: .enforce_admins.enabled,
    required_pull_request_reviews: {
      required_approving_review_count: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale_reviews: .required_pull_request_reviews.dismiss_stale_reviews
    },
    allow_force_pushes: .allow_force_pushes.enabled,
    allow_deletions: .allow_deletions.enabled
  }' 2>&1

# expected response when NOT protected:
# gh: Not Found (HTTP 404)
# expected response when protected: JSON with the fields above
```

**FIX**

```bash
# set branch protection — requires admin access to the repo
gh api repos/{{OWNER}}/{{REPO}}/branches/main/protection \
  -X PUT \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/tests", "ci/lint", "ci/security"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true,
  "required_conversation_resolution": true
}
EOF

# notes:
# - "contexts" must match your actual CI job names — list them with:
#   gh api repos/{{OWNER}}/{{REPO}}/commits/main/check-runs --jq '.check_runs[].name'
# - require_last_push_approval: prevents author from pushing a new commit
#   after approval and merging without re-review
# - enforce_admins: true means even org owners cannot bypass — auditors love this
# - restrictions: null means no restriction on who can push (handled by PR requirement)
#   set to {"users":[],"teams":["release-team"]} to restrict merge to specific teams
```

**VERIFY**

```bash
# re-read protection and confirm all fields
gh api repos/{{OWNER}}/{{REPO}}/branches/main/protection \
  --jq '{
    status_checks_enforced: (.required_status_checks != null),
    strict_status_checks: .required_status_checks.strict,
    pr_reviews_required: .required_pull_request_reviews.required_approving_review_count,
    dismiss_stale_reviews: .required_pull_request_reviews.dismiss_stale_reviews,
    enforce_admins: .enforce_admins.enabled,
    force_push_blocked: (.allow_force_pushes.enabled == false),
    deletions_blocked: (.allow_deletions.enabled == false)
  }'

# expected:
# {
#   "status_checks_enforced": true,
#   "strict_status_checks": true,
#   "pr_reviews_required": 1,
#   "dismiss_stale_reviews": true,
#   "enforce_admins": true,
#   "force_push_blocked": true,
#   "deletions_blocked": true
# }
```

**EVIDENCE**

```bash
# save branch protection config as audit artifact
gh api repos/{{OWNER}}/{{REPO}}/branches/main/protection \
  > evidence/github-branch-protection-$(date +%Y-%m-%d).json
```

---

### 3.1.2 secret scanning and push protection

prevents credentials from being committed to the repository. covers both detection of existing secrets and blocking new ones at push time.

**DISCOVER**

```bash
# check secret scanning status on a repo
gh api repos/{{OWNER}}/{{REPO}} \
  --jq '{
    secret_scanning: .security_and_analysis.secret_scanning.status,
    secret_scanning_push_protection: .security_and_analysis.secret_scanning_push_protection.status
  }'

# expected when disabled:
# { "secret_scanning": "disabled", "secret_scanning_push_protection": "disabled" }

# check for existing secret scanning alerts
gh api repos/{{OWNER}}/{{REPO}}/secret-scanning/alerts \
  --jq '[.[] | select(.state == "open")] | length'
# any number > 0 means leaked secrets that need immediate rotation
```

**FIX**

```bash
# enable secret scanning and push protection on a single repo
gh api repos/{{OWNER}}/{{REPO}} -X PATCH \
  --input - << 'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF

# enable at org level (applies to all repos including new ones)
gh api orgs/{{ORG}} -X PATCH \
  --input - << 'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF

# note: requires GitHub Advanced Security for private repos on Enterprise plan.
# for public repos, secret scanning is free.
# for GitHub Team plan, secret scanning is available but push protection requires GHAS.
```

**VERIFY**

```bash
gh api repos/{{OWNER}}/{{REPO}} \
  --jq '{
    secret_scanning: .security_and_analysis.secret_scanning.status,
    push_protection: .security_and_analysis.secret_scanning_push_protection.status
  }'

# expected: { "secret_scanning": "enabled", "push_protection": "enabled" }
```

**EVIDENCE**

```bash
# export secret scanning status for all repos in the org
gh api orgs/{{ORG}}/repos --paginate \
  --jq '.[] | {
    repo: .full_name,
    secret_scanning: .security_and_analysis.secret_scanning.status,
    push_protection: .security_and_analysis.secret_scanning_push_protection.status
  }' > evidence/github-secret-scanning-status-$(date +%Y-%m-%d).json

# export open alerts (should be zero)
gh api repos/{{OWNER}}/{{REPO}}/secret-scanning/alerts \
  --jq '[.[] | select(.state == "open")]' \
  > evidence/github-secret-alerts-open-$(date +%Y-%m-%d).json
```

---

### 3.1.3 dependabot security updates

automated dependency vulnerability detection and patching.

**DISCOVER**

```bash
# check if dependabot.yml exists
gh api repos/{{OWNER}}/{{REPO}}/contents/.github/dependabot.yml \
  --jq '.content' 2>&1
# HTTP 404 means no dependabot config

# check if vulnerability alerts are enabled
gh api repos/{{OWNER}}/{{REPO}}/vulnerability-alerts \
  -i 2>&1 | head -1
# "HTTP/2 204" = enabled, "HTTP/2 404" = disabled

# list open dependabot alerts
gh api repos/{{OWNER}}/{{REPO}}/dependabot/alerts \
  --jq '[.[] | select(.state == "open")] | length'
```

**FIX**

```bash
# enable vulnerability alerts on the repo
gh api repos/{{OWNER}}/{{REPO}}/vulnerability-alerts -X PUT

# enable automated security updates
gh api repos/{{OWNER}}/{{REPO}}/automated-security-fixes -X PUT

# create dependabot.yml — adapt ecosystems to your stack
# first, check what package ecosystems are in the repo:
gh api repos/{{OWNER}}/{{REPO}}/languages --jq 'keys[]'

# then create the config. example for a Node + Python + Docker project:
gh api repos/{{OWNER}}/{{REPO}}/contents/.github/dependabot.yml \
  -X PUT \
  --input - << 'GHEOF'
{
  "message": "chore: add dependabot configuration",
  "content": "dmVyc2lvbjogMgp1cGRhdGVzOgogIC0gcGFja2FnZS1lY29zeXN0ZW06ICJucG0iCiAgICBkaXJlY3Rvcnk6ICIvIgogICAgc2NoZWR1bGU6CiAgICAgIGludGVydmFsOiAid2Vla2x5IgogICAgb3Blbi1wdWxsLXJlcXVlc3RzLWxpbWl0OiAxMAogIC0gcGFja2FnZS1lY29zeXN0ZW06ICJwaXAiCiAgICBkaXJlY3Rvcnk6ICIvIgogICAgc2NoZWR1bGU6CiAgICAgIGludGVydmFsOiAid2Vla2x5IgogIC0gcGFja2FnZS1lY29zeXN0ZW06ICJkb2NrZXIiCiAgICBkaXJlY3Rvcnk6ICIvIgogICAgc2NoZWR1bGU6CiAgICAgIGludGVydmFsOiAid2Vla2x5IgogIC0gcGFja2FnZS1lY29zeXN0ZW06ICJnaXRodWItYWN0aW9ucyIKICAgIGRpcmVjdG9yeTogIi8iCiAgICBzY2hlZHVsZToKICAgICAgaW50ZXJ2YWw6ICJ3ZWVrbHkiCg=="
}
GHEOF

# the base64 above decodes to:
# version: 2
# updates:
#   - package-ecosystem: "npm"
#     directory: "/"
#     schedule:
#       interval: "weekly"
#     open-pull-requests-limit: 10
#   - package-ecosystem: "pip"
#     directory: "/"
#     schedule:
#       interval: "weekly"
#   - package-ecosystem: "docker"
#     directory: "/"
#     schedule:
#       interval: "weekly"
#   - package-ecosystem: "github-actions"
#     directory: "/"
#     schedule:
#       interval: "weekly"

# alternatively, create the file locally and commit:
cat > .github/dependabot.yml << 'EOF'
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
EOF
git add .github/dependabot.yml && git commit -m "chore: add dependabot config"
```

**VERIFY**

```bash
# confirm the file exists and alerts are enabled
gh api repos/{{OWNER}}/{{REPO}}/contents/.github/dependabot.yml \
  --jq '.name' 2>&1
# expected: "dependabot.yml"

gh api repos/{{OWNER}}/{{REPO}}/vulnerability-alerts -i 2>&1 | head -1
# expected: "HTTP/2 204"
```

**EVIDENCE**

```bash
# export dependabot alert summary
gh api repos/{{OWNER}}/{{REPO}}/dependabot/alerts \
  --jq '[.[] | {
    package: .dependency.package.name,
    ecosystem: .dependency.package.ecosystem,
    severity: .security_advisory.severity,
    state: .state,
    created: .created_at,
    fixed_at: .fixed_at
  }]' > evidence/github-dependabot-alerts-$(date +%Y-%m-%d).json
```

---

### 3.1.4 org-level 2FA requirement

**DISCOVER**

```bash
gh api orgs/{{ORG}} --jq '.two_factor_requirement_enabled'
# expected: true

# list members without 2FA (only works if 2FA is NOT yet required)
gh api orgs/{{ORG}}/members?filter=2fa_disabled --paginate \
  --jq '.[].login'
# if 2FA is already required, this returns empty (non-compliant users are auto-removed)
```

**FIX**

> **agent cannot do this via API.** instruct the human:
>
> 1. go to https://github.com/organizations/{{ORG}}/settings/security
> 2. check "Require two-factor authentication for everyone in the {{ORG}} organization"
> 3. click Save
>
> **warning:** enabling this will immediately remove any org member who does not have 2FA configured. notify all members first and give a 7-day deadline to enable 2FA.

**VERIFY**

```bash
gh api orgs/{{ORG}} --jq '.two_factor_requirement_enabled'
# expected: true

# confirm no members without 2FA
gh api orgs/{{ORG}}/members?filter=2fa_disabled --paginate \
  --jq 'length'
# expected: 0
```

**EVIDENCE**

```bash
gh api orgs/{{ORG}} \
  --jq '{org: .login, two_factor_requirement_enabled: .two_factor_requirement_enabled}' \
  > evidence/github-2fa-requirement-$(date +%Y-%m-%d).json
```

---

### 3.1.5 audit log streaming

critical for detecting unauthorized actions. GitHub audit log retains 180 days in the UI but streaming gives you permanent retention.

**DISCOVER**

```bash
# fetch recent audit log entries (GitHub Enterprise Cloud only)
# rate limit: 15 requests/hour for this endpoint
gh api orgs/{{ORG}}/audit-log?per_page=5 \
  --jq '.[0] | {action: .action, actor: .actor, created_at: .@timestamp}'

# check if audit log streaming is configured
gh api orgs/{{ORG}}/audit-log/streams \
  --jq '.[].stream_type' 2>&1
# HTTP 404 = no streaming configured or not on Enterprise plan
```

**FIX**

> **audit log streaming setup requires GitHub Enterprise Cloud and admin access.**
>
> option 1 — S3 streaming:
> instruct the human to go to https://github.com/organizations/{{ORG}}/settings/audit-log
> select "Set up a stream" > Amazon S3
> provide: S3 bucket name, AWS access key ID, AWS secret access key, region
>
> option 2 — Datadog streaming:
> same page, select Datadog
> provide: Datadog API key, Datadog site (e.g., datadoghq.com)
>
> option 3 — Splunk streaming:
> same page, select Splunk
> provide: Splunk HEC URL, HEC token
>
> option 4 — Azure Event Hubs:
> same page, select Azure Event Hubs
> provide: SAS connection string, event hub name, consumer group

for teams without Enterprise Cloud, use a cron job to export audit logs periodically:

```bash
#!/bin/bash
# github-audit-export.sh — run daily via cron
# cron: 0 2 * * * /opt/scripts/github-audit-export.sh

ORG="{{ORG}}"
OUTPUT_DIR="/var/log/github-audit"
mkdir -p "$OUTPUT_DIR"

YESTERDAY=$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d)

gh api "orgs/${ORG}/audit-log?phrase=created:${YESTERDAY}&per_page=100" \
  --paginate > "${OUTPUT_DIR}/audit-log-${YESTERDAY}.json"

# ship to your SIEM
# example: aws s3 cp "${OUTPUT_DIR}/audit-log-${YESTERDAY}.json" \
#   "s3://{{COMPANY}}-audit-logs/github/${YESTERDAY}.json"
```

**VERIFY**

```bash
# confirm streaming is active by checking for recent entries in your SIEM
# or confirm the cron job ran:
ls -la /var/log/github-audit/audit-log-$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d).json
```

**EVIDENCE**

```bash
# sample of recent audit log entries
gh api "orgs/{{ORG}}/audit-log?per_page=10" \
  --jq '[.[] | {action, actor, created_at: .["@timestamp"]}]' \
  > evidence/github-audit-log-sample-$(date +%Y-%m-%d).json
```

---

### 3.1.6 CODEOWNERS file

ensures changes to critical paths require review from designated owners. auditors see this as evidence of separation of duties.

**DISCOVER**

```bash
# check for CODEOWNERS in any of the three valid locations
for path in "CODEOWNERS" ".github/CODEOWNERS" "docs/CODEOWNERS"; do
  status=$(gh api repos/{{OWNER}}/{{REPO}}/contents/${path} --jq '.name' 2>&1)
  if [ "$status" = "CODEOWNERS" ]; then
    echo "found: ${path}"
    gh api repos/{{OWNER}}/{{REPO}}/contents/${path} \
      --jq '.content' | base64 -d
    break
  fi
done
```

**FIX**

```bash
# generate CODEOWNERS based on common patterns
# adapt paths and teams to your repo structure
cat > CODEOWNERS << 'EOF'
# default — require engineering lead review on everything
*                           @{{ORG}}/engineering-leads

# infrastructure — require SRE/platform team review
/terraform/                 @{{ORG}}/platform-team
/infrastructure/            @{{ORG}}/platform-team
/.github/workflows/         @{{ORG}}/platform-team
Dockerfile                  @{{ORG}}/platform-team

# security-sensitive files — require security team review
/auth/                      @{{ORG}}/security-team
/crypto/                    @{{ORG}}/security-team
**/permissions*             @{{ORG}}/security-team
**/rbac*                    @{{ORG}}/security-team

# database migrations — require engineering lead + DBA
/migrations/                @{{ORG}}/engineering-leads @{{ORG}}/dba-team
/db/                        @{{ORG}}/engineering-leads @{{ORG}}/dba-team

# CI/CD configuration — require platform team
.circleci/                  @{{ORG}}/platform-team

# dependency files — require security awareness
package.json                @{{ORG}}/engineering-leads
package-lock.json           @{{ORG}}/engineering-leads
requirements.txt            @{{ORG}}/engineering-leads
go.mod                      @{{ORG}}/engineering-leads
EOF

git add CODEOWNERS && git commit -m "chore: add CODEOWNERS for review enforcement"
git push
```

**VERIFY**

```bash
# confirm CODEOWNERS is active — check a PR that touches a protected path
gh api repos/{{OWNER}}/{{REPO}}/contents/CODEOWNERS --jq '.name'
# expected: "CODEOWNERS"

# also verify branch protection has "require_code_owner_reviews" enabled:
gh api repos/{{OWNER}}/{{REPO}}/branches/main/protection \
  --jq '.required_pull_request_reviews.require_code_owner_reviews'
# if false, update branch protection:
# (see section 3.1.1 FIX — set require_code_owner_reviews to true)
```

**EVIDENCE**

```bash
gh api repos/{{OWNER}}/{{REPO}}/contents/CODEOWNERS \
  --jq '.content' | base64 -d > evidence/github-codeowners-$(date +%Y-%m-%d).txt
```

---

### 3.1.7 GitHub Actions security

poorly configured Actions are a supply chain attack vector. auditors check for overly permissive tokens and unpinned third-party actions.

**DISCOVER**

```bash
# check default GITHUB_TOKEN permissions at org level
gh api orgs/{{ORG}} \
  --jq '.default_repository_permission'

# check per-repo token permissions
gh api repos/{{OWNER}}/{{REPO}} \
  --jq '.permissions'

# find workflow files that use unpinned actions (tag instead of SHA)
gh api repos/{{OWNER}}/{{REPO}}/contents/.github/workflows \
  --jq '.[].name' | while read file; do
  gh api "repos/{{OWNER}}/{{REPO}}/contents/.github/workflows/${file}" \
    --jq '.content' | base64 -d | grep -n "uses:" | grep -v "@[a-f0-9]\{40\}" || true
done

# find workflows with write permissions or permissions: write-all
gh api repos/{{OWNER}}/{{REPO}}/contents/.github/workflows \
  --jq '.[].name' | while read file; do
  content=$(gh api "repos/{{OWNER}}/{{REPO}}/contents/.github/workflows/${file}" \
    --jq '.content' | base64 -d)
  if echo "$content" | grep -q "permissions:"; then
    echo "=== ${file} ==="
    echo "$content" | grep -A5 "permissions:"
  fi
done
```

**FIX**

```bash
# 1. set default token permissions to read-only at org level
gh api orgs/{{ORG}}/actions/permissions/workflow \
  -X PUT \
  --input - << 'EOF'
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": false
}
EOF

# 2. set per-repo default to read-only
gh api repos/{{OWNER}}/{{REPO}}/actions/permissions/workflow \
  -X PUT \
  --input - << 'EOF'
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": false
}
EOF

# 3. pin third-party actions to SHA
# before: uses: actions/checkout@v4
# after:  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
#
# to find the SHA for a specific version:
# git ls-remote --tags https://github.com/actions/checkout | grep "v4.1.1"
#
# automate pinning with step-security/secure-repo:
# npx @stepsecurity/secure-repo --repo {{OWNER}}/{{REPO}}

# 4. restrict which actions can run (org level)
gh api orgs/{{ORG}}/actions/permissions \
  -X PUT \
  --input - << 'EOF'
{
  "enabled_repositories": "all",
  "allowed_actions": "selected"
}
EOF

# allow only verified creators and specific actions
gh api orgs/{{ORG}}/actions/permissions/selected-actions \
  -X PUT \
  --input - << 'EOF'
{
  "github_owned_allowed": true,
  "verified_allowed": true,
  "patterns_allowed": []
}
EOF
```

**VERIFY**

```bash
# confirm default permissions are read-only
gh api orgs/{{ORG}}/actions/permissions/workflow \
  --jq '{default_workflow_permissions, can_approve_pull_request_reviews}'
# expected: { "default_workflow_permissions": "read", "can_approve_pull_request_reviews": false }

# confirm allowed actions policy
gh api orgs/{{ORG}}/actions/permissions \
  --jq '{enabled_repositories, allowed_actions}'
# expected: { "enabled_repositories": "all", "allowed_actions": "selected" }
```

**EVIDENCE**

```bash
gh api orgs/{{ORG}}/actions/permissions/workflow \
  > evidence/github-actions-permissions-$(date +%Y-%m-%d).json

gh api orgs/{{ORG}}/actions/permissions/selected-actions \
  >> evidence/github-actions-permissions-$(date +%Y-%m-%d).json
```

---

## 3.2 Okta identity provider

### 3.2.1 MFA enforcement

every user must have MFA. no exceptions. SMS-based MFA is not acceptable for SOC 2 — require TOTP or FIDO2.

**DISCOVER**

```bash
OKTA_DOMAIN="{{OKTA_DOMAIN}}"  # e.g., yourcompany.okta.com
OKTA_TOKEN="{{OKTA_API_TOKEN}}"

# check MFA enrollment policies
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" \
  | jq '.[].name'

# get details of each MFA policy
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" \
  | jq '.[] | {
    name: .name,
    status: .status,
    settings: .settings
  }'

# find users WITHOUT MFA enrolled
# first get all active users
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq -r '.[].id' | while read uid; do
    factors=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/users/${uid}/factors" \
      | jq '[.[] | select(.status == "ACTIVE")] | length')
    if [ "$factors" -eq 0 ]; then
      curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
        "https://${OKTA_DOMAIN}/api/v1/users/${uid}" \
        | jq '{id: .id, email: .profile.email, mfa_factors: 0}'
    fi
done

# expected: no output (all users have MFA)
# any output = users missing MFA = audit finding
```

**FIX**

```bash
# create an MFA enrollment policy that requires TOTP and FIDO2
# first, get the default MFA policy ID
DEFAULT_MFA_POLICY=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" \
  | jq -r '.[0].id')

# create a new strict MFA enrollment policy
curl -s -X POST \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies" \
  -d '{
    "type": "MFA_ENROLL",
    "name": "SOC2 - Require Strong MFA",
    "status": "ACTIVE",
    "priority": 1,
    "conditions": {
      "people": {
        "groups": {
          "include": ["{{EVERYONE_GROUP_ID}}"]
        }
      }
    },
    "settings": {
      "factors": {
        "okta_otp": {
          "enroll": { "self": "REQUIRED" }
        },
        "fido_webauthn": {
          "enroll": { "self": "OPTIONAL" }
        },
        "okta_sms": {
          "enroll": { "self": "NOT_ALLOWED" }
        },
        "okta_call": {
          "enroll": { "self": "NOT_ALLOWED" }
        },
        "okta_email": {
          "enroll": { "self": "NOT_ALLOWED" }
        }
      }
    }
  }' | jq '{id: .id, name: .name, status: .status}'

# to find your EVERYONE_GROUP_ID:
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/groups?q=Everyone&limit=1" \
  | jq -r '.[0].id'

# create a sign-on policy rule that requires MFA for every authentication
# first get the global session policy
SIGNON_POLICY=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
  | jq -r '.[0].id')

curl -s -X POST \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY}/rules" \
  -d '{
    "name": "SOC2 - Require MFA Always",
    "priority": 1,
    "status": "ACTIVE",
    "conditions": {
      "people": {
        "groups": {
          "include": ["{{EVERYONE_GROUP_ID}}"]
        }
      }
    },
    "actions": {
      "signon": {
        "access": "ALLOW",
        "requireFactor": true,
        "factorPromptMode": "SESSION",
        "rememberDeviceByDefault": false,
        "factorLifetime": 0,
        "session": {
          "usePersistentCookie": false,
          "maxSessionIdleMinutes": 720,
          "maxSessionLifetimeMinutes": 1440
        }
      }
    }
  }' | jq '{id: .id, name: .name, status: .status}'
```

**VERIFY**

```bash
# re-check: list all active users and their MFA factors
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq '[.[] | {
    email: .profile.email,
    status: .status,
    factors_url: (._links.self.href + "/factors")
  }]'

# spot-check a user's MFA factors
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/{{USER_ID}}/factors" \
  | jq '[.[] | {type: .factorType, provider: .provider, status: .status}]'
```

**EVIDENCE**

```bash
# generate MFA compliance report for all users
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq -r '.[].id' | while read uid; do
    user=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/users/${uid}")
    factors=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/users/${uid}/factors" \
      | jq '[.[] | select(.status == "ACTIVE") | .factorType]')
    echo "$user" | jq --argjson f "$factors" \
      '{email: .profile.email, status: .status, active_mfa_factors: $f}'
done | jq -s '.' > evidence/okta-mfa-compliance-$(date +%Y-%m-%d).json
```

---

### 3.2.2 password policy

**DISCOVER**

```bash
# list password policies
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  | jq '.[] | {
    id: .id,
    name: .name,
    status: .status,
    settings: .settings.password
  }'

# expected minimum: 14 chars, complexity, lockout, expiry
```

**FIX**

```bash
# get the default password policy ID
PASSWORD_POLICY_ID=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  | jq -r '.[0].id')

# update password policy to SOC 2 standards
curl -s -X PUT \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${PASSWORD_POLICY_ID}" \
  -d '{
    "name": "Default Policy",
    "type": "PASSWORD",
    "status": "ACTIVE",
    "settings": {
      "password": {
        "complexity": {
          "minLength": 14,
          "minLowerCase": 1,
          "minUpperCase": 1,
          "minNumber": 1,
          "minSymbol": 1,
          "excludeUsername": true,
          "dictionary": {
            "common": { "exclude": true }
          }
        },
        "age": {
          "maxAgeDays": 90,
          "expireWarnDays": 14,
          "minAgeMinutes": 60,
          "historyCount": 12
        },
        "lockout": {
          "maxAttempts": 5,
          "autoUnlockMinutes": 30,
          "showLockoutFailures": true
        }
      },
      "recovery": {
        "factors": {
          "okta_email": {
            "status": "ACTIVE",
            "properties": {
              "recoveryToken": {
                "tokenLifetimeMinutes": 60
              }
            }
          }
        }
      },
      "delegation": {
        "options": {
          "skipUnlock": false
        }
      }
    }
  }' | jq '{id: .id, name: .name, status: .status}'
```

**VERIFY**

```bash
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${PASSWORD_POLICY_ID}" \
  | jq '{
    min_length: .settings.password.complexity.minLength,
    max_age_days: .settings.password.age.maxAgeDays,
    history_count: .settings.password.age.historyCount,
    lockout_attempts: .settings.password.lockout.maxAttempts,
    exclude_common: .settings.password.complexity.dictionary.common.exclude
  }'

# expected:
# {
#   "min_length": 14,
#   "max_age_days": 90,
#   "history_count": 12,
#   "lockout_attempts": 5,
#   "exclude_common": true
# }
```

**EVIDENCE**

```bash
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  > evidence/okta-password-policy-$(date +%Y-%m-%d).json
```

---

### 3.2.3 session management

**DISCOVER**

```bash
# check session policies
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
  | jq '.[] | {
    id: .id,
    name: .name,
    rules_url: (._links.rules.href)
  }'

# get session settings from sign-on policy rules
SIGNON_POLICY_ID=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
  | jq -r '.[0].id')

curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY_ID}/rules" \
  | jq '.[] | {
    name: .name,
    idle_timeout_minutes: .actions.signon.session.maxSessionIdleMinutes,
    max_lifetime_minutes: .actions.signon.session.maxSessionLifetimeMinutes,
    persistent_cookie: .actions.signon.session.usePersistentCookie
  }'
```

**FIX**

```bash
# get the first rule ID in the sign-on policy
RULE_ID=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY_ID}/rules" \
  | jq -r '.[0].id')

# update session timeouts
# idle timeout: 720 minutes (12 hours)
# max session lifetime: 1440 minutes (24 hours)
# no persistent cookies
curl -s -X PUT \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY_ID}/rules/${RULE_ID}" \
  -d '{
    "name": "SOC2 - Session Controls",
    "priority": 1,
    "status": "ACTIVE",
    "conditions": {
      "people": {
        "groups": {
          "include": ["{{EVERYONE_GROUP_ID}}"]
        }
      }
    },
    "actions": {
      "signon": {
        "access": "ALLOW",
        "requireFactor": true,
        "factorPromptMode": "SESSION",
        "rememberDeviceByDefault": false,
        "factorLifetime": 0,
        "session": {
          "usePersistentCookie": false,
          "maxSessionIdleMinutes": 720,
          "maxSessionLifetimeMinutes": 1440
        }
      }
    }
  }' | jq '{id: .id, name: .name}'
```

**VERIFY**

```bash
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY_ID}/rules/${RULE_ID}" \
  | jq '{
    idle_timeout_minutes: .actions.signon.session.maxSessionIdleMinutes,
    max_lifetime_minutes: .actions.signon.session.maxSessionLifetimeMinutes,
    persistent_cookie: .actions.signon.session.usePersistentCookie
  }'

# expected:
# { "idle_timeout_minutes": 720, "max_lifetime_minutes": 1440, "persistent_cookie": false }
```

**EVIDENCE**

```bash
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/policies/${SIGNON_POLICY_ID}/rules" \
  > evidence/okta-session-policy-$(date +%Y-%m-%d).json
```

---

### 3.2.4 user deprovisioning automation

> **this is the single most critical control in SOC 2 compliance.** 68% of qualified (failed) SOC 2 opinions cite user deprovisioning failures. the control is CC6.3: "The entity disables or removes access to information and assets when no longer needed." if a terminated employee retains access for even one day beyond the SLA, it is a finding.

the problem is simple: HR terminates someone, but their accounts stay active. this happens because:
1. there is no automated link between HR and the identity provider
2. manual offboarding checklists have steps that get skipped
3. non-SSO apps are forgotten
4. shared credentials are not rotated

the fix is automation, not checklists.

**DISCOVER**

```bash
# step 1: get all active Okta users
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq '[.[] | {id: .id, email: .profile.email, name: (.profile.firstName + " " + .profile.lastName)}]' \
  > /tmp/okta-active-users.json

# step 2: get terminated employees from HR system
# this depends on your HR system. examples:

# --- Rippling ---
# curl -s -H "Authorization: Bearer ${RIPPLING_TOKEN}" \
#   "https://api.rippling.com/platform/api/employees?employment_status=TERMINATED" \
#   | jq '[.[] | {email: .work_email, name: (.first_name + " " + .last_name), terminated_date: .termination_date}]' \
#   > /tmp/hr-terminated.json

# --- BambooHR ---
# curl -s -H "Authorization: Basic $(echo -n "${BAMBOO_API_KEY}:x" | base64)" \
#   "https://api.bamboohr.com/api/gateway.php/{{BAMBOO_SUBDOMAIN}}/v1/reports/custom?format=JSON" \
#   -d '{"filters":{"lastChanged":{"includeNull":"no"}},"fields":["workEmail","status","terminationDate"]}' \
#   | jq '[.employees[] | select(.status == "Inactive") | {email: .workEmail, terminated_date: .terminationDate}]' \
#   > /tmp/hr-terminated.json

# --- Gusto ---
# curl -s -H "Authorization: Bearer ${GUSTO_TOKEN}" \
#   "https://api.gusto-demo.com/v1/companies/{{COMPANY_ID}}/employees?terminated=true" \
#   | jq '[.[] | {email: .email, name: (.first_name + " " + .last_name), terminated_date: .termination_date}]' \
#   > /tmp/hr-terminated.json

# step 3: find terminated employees who still have active Okta accounts
jq -r '.[].email' /tmp/hr-terminated.json | while read email; do
  match=$(jq -r --arg e "$email" '.[] | select(.email == $e) | .email' /tmp/okta-active-users.json)
  if [ -n "$match" ]; then
    echo "CRITICAL: terminated employee still active in Okta: ${email}"
  fi
done

# any output here is a SOC 2 finding
```

**FIX**

the fix has three tiers: automated provisioning (prevents the problem), manual deprovisioning procedure (handles exceptions), and weekly reconciliation (catches anything that falls through).

**tier 1: HR-to-Okta SCIM provisioning (the real fix)**

```bash
# SCIM (System for Cross-domain Identity Management) allows your HR system
# to automatically create, update, and deactivate Okta users.
#
# when HR marks an employee as terminated:
# 1. HR system sends SCIM PATCH to Okta with active: false
# 2. Okta deactivates the user
# 3. all SSO sessions are terminated immediately
# 4. all SSO-connected apps lose access

# --- set up SCIM provisioning in Okta ---
# this is done in the Okta Admin Console, not via API:
#
# 1. go to Okta Admin > Applications > Add Application
# 2. search for your HR system (Rippling, BambooHR, Gusto, Workday)
# 3. configure SCIM provisioning:
#    - enable "Create Users"
#    - enable "Update User Attributes"
#    - enable "Deactivate Users"  <-- this is the critical one
# 4. provide HR system API credentials
# 5. set attribute mappings (email, firstName, lastName, department, title)
# 6. set provisioning schedule or enable real-time webhook

# --- verify SCIM is configured ---
# list all apps with provisioning enabled
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/apps?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq '[.[] | select(.features | index("PUSH_NEW_USERS") or index("PUSH_USER_DEACTIVATION")) | {
    name: .label,
    features: .features,
    status: .status
  }]'
```

**tier 2: manual deprovisioning procedure (for edge cases)**

```bash
# when automated SCIM is not available (contractor termination, emergency removal),
# use this script to deactivate a user across all systems.

#!/bin/bash
# offboard-user.sh — emergency deprovisioning
# usage: ./offboard-user.sh user@company.com "involuntary termination"

USER_EMAIL="$1"
REASON="$2"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "=== DEPROVISIONING: ${USER_EMAIL} ==="
echo "Reason: ${REASON}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

# step 1: deactivate Okta account (kills all SSO sessions immediately)
USER_ID=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?search=profile.email+eq+%22${USER_EMAIL}%22" \
  | jq -r '.[0].id')

if [ "$USER_ID" != "null" ] && [ -n "$USER_ID" ]; then
  curl -s -X POST \
    -H "Authorization: SSWS ${OKTA_TOKEN}" \
    "https://${OKTA_DOMAIN}/api/v1/users/${USER_ID}/lifecycle/deactivate"
  echo "[OK] Okta account deactivated: ${USER_ID}"

  # clear all active sessions
  curl -s -X DELETE \
    -H "Authorization: SSWS ${OKTA_TOKEN}" \
    "https://${OKTA_DOMAIN}/api/v1/users/${USER_ID}/sessions"
  echo "[OK] Active sessions cleared"
else
  echo "[WARN] User not found in Okta: ${USER_EMAIL}"
fi

# step 2: remove from GitHub org
gh api orgs/{{ORG}}/members/${USER_EMAIL%%@*} -X DELETE 2>/dev/null \
  && echo "[OK] Removed from GitHub org" \
  || echo "[SKIP] Not found in GitHub org"

# step 3: revoke AWS IAM access (if applicable)
# aws iam delete-login-profile --user-name "${USER_EMAIL}" 2>/dev/null
# aws iam list-access-keys --user-name "${USER_EMAIL}" --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
#   tr '\t' '\n' | while read key; do
#     aws iam update-access-key --user-name "${USER_EMAIL}" --access-key-id "$key" --status Inactive
#   done
# echo "[OK] AWS IAM access revoked"

# step 4: request MDM device wipe (requires human action for confirmation)
echo "[ACTION REQUIRED] Request MDM device wipe for ${USER_EMAIL}"
echo "  Jamf: Devices > Search ${USER_EMAIL} > Management > Wipe Device"
echo "  Intune: Devices > All devices > Search > Wipe"

# step 5: log the deprovisioning event
echo ""
echo "=== DEPROVISIONING LOG ==="
echo "user: ${USER_EMAIL}"
echo "okta_id: ${USER_ID}"
echo "reason: ${REASON}"
echo "deactivated_at: ${TIMESTAMP}"
echo "performed_by: $(whoami)"
echo ""
echo "Save this output as evidence for SOC 2 audit."
```

**tier 3: weekly reconciliation script**

```bash
#!/bin/bash
# deprovision-reconciliation.sh — run weekly via cron
# compares HR terminated list with Okta active accounts
# cron: 0 9 * * 1 /opt/scripts/deprovision-reconciliation.sh
#
# SLA reminder:
#   involuntary termination: deactivate within 1 hour
#   voluntary termination: deactivate by end of last working day

OKTA_DOMAIN="{{OKTA_DOMAIN}}"
OKTA_TOKEN="{{OKTA_API_TOKEN}}"
ALERT_EMAIL="{{SECURITY_LEAD_EMAIL}}"
DATE=$(date +%Y-%m-%d)

echo "# Deprovisioning Reconciliation Report"
echo "**Date:** ${DATE}"
echo ""

# get active Okta users
OKTA_USERS=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq -r '.[].profile.email')

# get HR active employee list
# replace with your HR system API call:
# HR_ACTIVE=$(curl -s -H "Authorization: Bearer ${HR_TOKEN}" \
#   "https://api.yourhrsystem.com/employees?status=active" \
#   | jq -r '.[].email')

# compare: find Okta users NOT in the HR active list
echo "## Users in Okta but NOT in HR system (potential orphaned accounts)"
echo ""
for okta_email in $OKTA_USERS; do
  if ! echo "$HR_ACTIVE" | grep -qi "^${okta_email}$"; then
    echo "- ALERT: ${okta_email} — active in Okta, not found in HR active list"
  fi
done

echo ""
echo "## Summary"
echo "- Active Okta users: $(echo "$OKTA_USERS" | wc -l | tr -d ' ')"
echo "- Active HR employees: $(echo "$HR_ACTIVE" | wc -l | tr -d ' ')"
echo ""
echo "## Action Required"
echo "For each flagged user above:"
echo "1. Confirm with HR if the employee is terminated"
echo "2. If terminated, run: ./offboard-user.sh <email> 'missed deprovisioning'"
echo "3. Document the finding and remediation in the compliance platform"
echo ""

# optional: send alert email if discrepancies found
# if discrepancies found, send to ALERT_EMAIL via your notification channel
```

**VERIFY**

```bash
# after setting up SCIM provisioning, verify it works end-to-end:

# 1. check that the HR SCIM integration is active
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/apps?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq '[.[] | select(.features | index("PUSH_USER_DEACTIVATION")) | .label]'
# expected: your HR app appears in the list

# 2. check Okta system log for recent deprovisioning events
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+%22user.lifecycle.deactivate%22&limit=10" \
  | jq '[.[] | {
    timestamp: .published,
    actor: .actor.displayName,
    target: .target[0].displayName,
    outcome: .outcome.result
  }]'
```

**EVIDENCE**

```bash
# deprovisioning evidence package for auditors:

# 1. SCIM integration config
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/apps?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq '[.[] | select(.features | index("PUSH_USER_DEACTIVATION")) | {
    name: .label,
    features: .features,
    status: .status
  }]' > evidence/okta-scim-integrations-$(date +%Y-%m-%d).json

# 2. recent deprovisioning events from Okta system log
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+%22user.lifecycle.deactivate%22&since=$(date -d '90 days ago' +%Y-%m-%dT00:00:00Z 2>/dev/null || date -v-90d +%Y-%m-%dT00:00:00Z)&limit=100" \
  | jq '[.[] | {
    timestamp: .published,
    actor: .actor.displayName,
    target_user: .target[0].displayName,
    target_email: .target[0].alternateId,
    outcome: .outcome.result
  }]' > evidence/okta-deprovisioning-events-$(date +%Y-%m-%d).json

# 3. reconciliation report
# ./deprovision-reconciliation.sh > evidence/deprovision-reconciliation-$(date +%Y-%m-%d).md

# 4. offboarding tickets with timestamps (export from your ticketing system)
# jira: jql "project = IT AND type = 'Offboarding' AND created >= -90d"
# linear: query for offboarding issues
```

---

### 3.2.5 provisioning via groups

direct app assignment to individual users is an access control anti-pattern. all access should flow through group membership so that role changes and offboarding cascade automatically.

**DISCOVER**

```bash
# list all Okta groups
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/groups?limit=200" \
  | jq '[.[] | {id: .id, name: .profile.name, type: .type, member_count: .profile.memberCount // "unknown"}]'

# find users with direct app assignments (not via group)
# for each app, compare direct assignments vs group-based assignments
APP_ID="{{APP_ID}}"
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/apps/${APP_ID}/users?limit=200" \
  | jq '[.[] | select(.scope == "USER") | {email: .credentials.userName, scope: .scope}]'
# scope "USER" = directly assigned. scope "GROUP" = assigned via group.
# all direct assignments should be migrated to group-based.
```

**FIX**

```bash
# step 1: create role-based groups
for group_name in "eng-all" "eng-production" "eng-admin" "security" "hr" "finance"; do
  curl -s -X POST \
    -H "Authorization: SSWS ${OKTA_TOKEN}" \
    -H "Content-Type: application/json" \
    "https://${OKTA_DOMAIN}/api/v1/groups" \
    -d "{
      \"profile\": {
        \"name\": \"${group_name}\",
        \"description\": \"SOC2 RBAC group - ${group_name}\"
      }
    }" | jq '{id: .id, name: .profile.name}'
done

# step 2: assign apps to groups instead of users
GROUP_ID="{{GROUP_ID}}"
APP_ID="{{APP_ID}}"
curl -s -X PUT \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/apps/${APP_ID}/groups/${GROUP_ID}"

# step 3: remove direct user assignments (after confirming group assignment works)
# curl -s -X DELETE \
#   -H "Authorization: SSWS ${OKTA_TOKEN}" \
#   "https://${OKTA_DOMAIN}/api/v1/apps/${APP_ID}/users/{{USER_ID}}"
```

**VERIFY**

```bash
# check that no direct user assignments remain
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/apps/${APP_ID}/users?limit=200" \
  | jq '[.[] | select(.scope == "USER")] | length'
# expected: 0
```

**EVIDENCE**

```bash
# export group memberships for all groups
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/groups?limit=200" \
  | jq -r '.[].id' | while read gid; do
    gname=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/groups/${gid}" | jq -r '.profile.name')
    members=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
      "https://${OKTA_DOMAIN}/api/v1/groups/${gid}/users?limit=200" \
      | jq '[.[] | .profile.email]')
    echo "{\"group\": \"${gname}\", \"members\": ${members}}"
done | jq -s '.' > evidence/okta-group-memberships-$(date +%Y-%m-%d).json
```

---

## 3.3 Google Workspace (alternative to Okta)

use this section if Google Workspace is your primary identity provider instead of Okta. many startups use Google Workspace for both email and SSO.

> tool: [GAM](https://github.com/GAM-team/GAM) (Google Apps Manager) is a command-line tool for Google Workspace admin operations. install: `bash <(curl -s -S -L https://gam-shortn.appspot.com/gam-install)` or use the Admin SDK REST API directly.

### 3.3.1 2-step verification enforcement

**DISCOVER**

```bash
# using GAM
gam print users fields isEnrolledIn2Sv,isEnforcedIn2Sv > /tmp/gw-2sv-status.csv

# count users without 2SV
gam print users fields isEnrolledIn2Sv | grep -c "False"

# using Admin SDK API directly
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    enrolled_2sv: .isEnrolledIn2Sv,
    enforced_2sv: .isEnforcedIn2Sv
  }]'

# find users not enrolled
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&projection=full&maxResults=500" \
  | jq '[.users[] | select(.isEnrolledIn2Sv == false) | .primaryEmail]'
```

**FIX**

> **2SV enforcement must be done via Admin Console** (no API for this setting):
>
> 1. go to https://admin.google.com > Security > Authentication > 2-Step Verification
> 2. check "Allow users to turn on 2-Step Verification"
> 3. under Enforcement, select "On" and set the enforcement date (give users 7 days)
> 4. under Methods, select "Any except verification codes via text, phone call" (same as Okta: no SMS)
> 5. click Save
>
> **important:** set a new employee enforcement deadline. new users should be required to set up 2SV within 24 hours of account creation.

**VERIFY**

```bash
# re-check enrollment after enforcement deadline
gam print users fields isEnrolledIn2Sv,isEnforcedIn2Sv \
  | grep "False"
# expected: no output (all users enrolled and enforced)

# or via API
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&projection=full&maxResults=500" \
  | jq '[.users[] | select(.isEnrolledIn2Sv == false)] | length'
# expected: 0
```

**EVIDENCE**

```bash
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,creationTime \
  > evidence/gw-2sv-status-$(date +%Y-%m-%d).csv

# or via API
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    enrolled_2sv: .isEnrolledIn2Sv,
    enforced_2sv: .isEnforcedIn2Sv,
    created: .creationTime
  }]' > evidence/gw-2sv-status-$(date +%Y-%m-%d).json
```

---

### 3.3.2 password policy

**DISCOVER**

```bash
# GAM does not expose password policy settings directly.
# check via Admin Console: admin.google.com > Security > Authentication > Password management
# or check with the API (Chrome Policy API for managed devices):

# the password requirements for Google Workspace are set at the OU level.
# you can read them via the Admin SDK, but setting them requires the Admin Console.

# check current settings via GAM (limited):
gam print orgs
# then for each OU, check password policy via Admin Console
```

**FIX**

> **must be done in Admin Console:**
>
> 1. go to https://admin.google.com > Security > Authentication > Password management
> 2. set minimum password length: 14 characters
> 3. check "Enforce password policy at next login"
> 4. set password expiration: 90 days (or "Never expire" if using MFA — many auditors accept this)
> 5. do not allow password reuse for 12 generations
> 6. click Save

**VERIFY**

> take a screenshot of the Admin Console password management page showing the settings. this is the standard evidence format for Google Workspace controls that lack API access.

**EVIDENCE**

```bash
# export a report showing when users last changed passwords
gam print users fields primaryEmail,lastLoginTime,creationTime \
  > evidence/gw-password-report-$(date +%Y-%m-%d).csv
```

---

### 3.3.3 session controls

**DISCOVER**

```bash
# check current session length (Admin Console only — not available via API)
# admin.google.com > Security > Google Cloud session control
# and: admin.google.com > Security > Access and data control > Google session control
```

**FIX**

> **must be done in Admin Console:**
>
> 1. go to https://admin.google.com > Security > Access and data control > Google session control
> 2. set session duration (recommended: 12 hours for web, 24 hours for mobile)
> 3. go to Security > Google Cloud session control
> 4. set reauthentication frequency for Google Cloud console access (recommended: 12 hours)
> 5. consider enabling context-aware access: Security > Access and data control > Context-aware access
>    - this allows restricting access based on device security posture and network

**VERIFY**

> take a screenshot of the Admin Console session control page.

**EVIDENCE**

```bash
# export login activity to verify session behavior
gam report login > evidence/gw-login-activity-$(date +%Y-%m-%d).csv

# or via Reports API
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=100" \
  | jq '[.items[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    ip: .ipAddress
  }]' > evidence/gw-login-events-$(date +%Y-%m-%d).json
```

---

### 3.3.4 admin audit log

**DISCOVER**

```bash
# check admin audit events via GAM
gam report admin > /tmp/gw-admin-audit.csv

# or via Reports API
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?maxResults=50" \
  | jq '[.items[:5] | .[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    parameters: [.events[0].parameters[]? | {name: .name, value: (.value // .intValue // .boolValue)}]
  }]'
```

**FIX**

```bash
# Google Workspace admin audit logging is always on — you cannot disable it.
# the fix is ensuring logs are exported to your SIEM for long-term retention.

# option 1: BigQuery export (built-in)
# admin.google.com > Account > Account settings > Legal and compliance > Sharing options
# enable "Google Workspace data export to BigQuery"
# this streams all admin audit logs, login events, and drive activity to BigQuery

# option 2: export via API to S3/Splunk
#!/bin/bash
# gw-audit-export.sh — run daily via cron
# cron: 0 3 * * * /opt/scripts/gw-audit-export.sh

OUTPUT_DIR="/var/log/gw-audit"
mkdir -p "$OUTPUT_DIR"
YESTERDAY=$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d)

for app in admin login drive; do
  curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
    "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/${app}?startTime=${YESTERDAY}T00:00:00Z&endTime=${YESTERDAY}T23:59:59Z&maxResults=1000" \
    > "${OUTPUT_DIR}/${app}-${YESTERDAY}.json"
done

# ship to SIEM
# aws s3 sync "$OUTPUT_DIR" "s3://{{COMPANY}}-audit-logs/google-workspace/"
```

**VERIFY**

```bash
# confirm logs are flowing
gam report admin event_name=CREATE_USER | head -5
# expected: recent user creation events

# or via API
curl -s -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?maxResults=1" \
  | jq '.items[0].id.time'
# expected: recent timestamp
```

**EVIDENCE**

```bash
gam report admin > evidence/gw-admin-audit-$(date +%Y-%m-%d).csv
gam report login > evidence/gw-login-audit-$(date +%Y-%m-%d).csv
```

---

## 3.4 endpoint security

endpoint controls protect the "last mile" — the employee's device. a single unencrypted laptop lost at an airport can be a data breach.

### 3.4.1 MDM enrollment verification

**DISCOVER**

```bash
# --- Jamf Pro ---
# list all managed computers
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  -H "Accept: application/json" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&page-size=200" \
  | jq '[.results[] | {
    id: .id,
    name: .general.name,
    serial: .hardware.serialNumber,
    os_version: .hardware.osVersion,
    last_contact: .general.lastContactTime,
    managed: .general.remoteManagement.managed
  }]' > /tmp/jamf-devices.json

# --- Microsoft Intune ---
# list all managed devices
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$select=deviceName,serialNumber,osVersion,lastSyncDateTime,complianceState,isEncrypted,managedDeviceOwnerType" \
  | jq '[.value[] | {
    name: .deviceName,
    serial: .serialNumber,
    os_version: .osVersion,
    last_sync: .lastSyncDateTime,
    compliance: .complianceState,
    encrypted: .isEncrypted,
    owner_type: .managedDeviceOwnerType
  }]' > /tmp/intune-devices.json

# --- Kandji ---
curl -s -H "Authorization: Bearer ${KANDJI_TOKEN}" \
  "https://{{KANDJI_SUBDOMAIN}}.api.kandji.io/api/v1/devices/?limit=300" \
  | jq '[.[] | {
    id: .device_id,
    name: .device_name,
    serial: .serial_number,
    os_version: .os_version,
    last_check_in: .last_check_in
  }]' > /tmp/kandji-devices.json

# compare enrolled devices with employee list
# get employee count from HR
echo "MDM enrolled devices: $(jq length /tmp/jamf-devices.json)"
echo "Expected (from HR employee count): {{EMPLOYEE_COUNT}}"
# any gap = unmanaged devices = finding
```

**FIX**

> **for unmanaged devices:**
>
> 1. identify owners of unmanaged devices (compare serial numbers / user assignments)
> 2. send enrollment instructions:
>    - Jamf: provide enrollment URL (https://{{JAMF_URL}}/enroll)
>    - Intune: Company Portal app from App Store / Microsoft Store
>    - Kandji: enrollment link from Kandji console
> 3. set a deadline (7 days)
> 4. after deadline, block network access for unmanaged devices (via NAC or conditional access)
>
> **for BYOD:** require MDM enrollment for any personal device that accesses company data, or use MAM (Mobile Application Management) for app-level controls without full MDM.

**VERIFY**

```bash
# re-check enrolled device count matches employee count
# Jamf:
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=GENERAL&page-size=1" \
  | jq '.totalCount'

# Intune:
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/\$count" \
  -H "ConsistencyLevel: eventual"
```

**EVIDENCE**

```bash
# export full device inventory with compliance status
# Jamf:
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=DISK_ENCRYPTION&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    serial: .hardware.serialNumber,
    os_version: .hardware.osVersion,
    last_contact: .general.lastContactTime,
    managed: .general.remoteManagement.managed,
    filevault_enabled: (.diskEncryption.individualRecoveryKeyValidityStatus // "unknown")
  }]' > evidence/mdm-device-inventory-$(date +%Y-%m-%d).json

# Intune:
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$select=deviceName,serialNumber,osVersion,lastSyncDateTime,complianceState,isEncrypted" \
  | jq '[.value[] | {
    name: .deviceName,
    serial: .serialNumber,
    os_version: .osVersion,
    last_sync: .lastSyncDateTime,
    compliance: .complianceState,
    encrypted: .isEncrypted
  }]' > evidence/mdm-device-inventory-$(date +%Y-%m-%d).json
```

---

### 3.4.2 disk encryption enforcement

**DISCOVER**

```bash
# --- Jamf: FileVault status ---
# check via Smart Group or direct API query
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=DISK_ENCRYPTION&page-size=200" \
  | jq '[.results[] | {
    id: .id,
    filevault_status: .diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State,
    recovery_key_valid: .diskEncryption.individualRecoveryKeyValidityStatus
  }]'

# find devices WITHOUT encryption
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=DISK_ENCRYPTION&section=GENERAL&page-size=200" \
  | jq '[.results[] | select(
    .diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State != "ENCRYPTED"
  ) | {name: .general.name, status: .diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State}]'

# --- Intune: BitLocker status ---
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$filter=isEncrypted+eq+false&\$select=deviceName,serialNumber,isEncrypted" \
  | jq '[.value[] | {name: .deviceName, serial: .serialNumber, encrypted: .isEncrypted}]'
# expected: empty array (all devices encrypted)
```

**FIX**

```bash
# --- Jamf: push FileVault enforcement profile ---
# create a configuration profile in Jamf Pro:
# 1. Jamf Pro > Computers > Configuration Profiles > New
# 2. name: "SOC2 - FileVault Enforcement"
# 3. Security & Privacy > FileVault:
#    - Enable FileVault: checked
#    - Defer: enable (prompts user at next logout)
#    - Recovery Key Type: Individual and Institutional
#    - Escrow Key to Jamf Pro: checked
# 4. scope: All Managed Clients
#
# or via Jamf API (create profile):
cat > /tmp/filevault-profile.mobileconfig << 'MCEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>Enabled</key>
            <string>On</string>
            <key>Defer</key>
            <true/>
            <key>ShowRecoveryKey</key>
            <false/>
            <key>UseRecoveryKey</key>
            <true/>
            <key>PayloadType</key>
            <string>com.apple.MCX.FileVault2</string>
            <key>PayloadIdentifier</key>
            <string>com.company.filevault</string>
            <key>PayloadUUID</key>
            <string>{{GENERATE_UUID}}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SOC2 - FileVault Enforcement</string>
    <key>PayloadIdentifier</key>
    <string>com.company.soc2.filevault</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{{GENERATE_UUID}}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
MCEOF

# --- Intune: push BitLocker enforcement ---
# must be done via Endpoint Manager portal or Graph API:
# endpoint.microsoft.com > Devices > Configuration profiles > Create profile
# Platform: Windows 10 and later
# Profile type: Endpoint protection
# BitLocker > OS drive encryption: Require
# Recovery key rotation: enabled
```

**VERIFY**

```bash
# Jamf: confirm all devices encrypted
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=DISK_ENCRYPTION&page-size=200" \
  | jq '[.results[] | select(
    .diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State != "ENCRYPTED"
  )] | length'
# expected: 0

# Intune: confirm all devices encrypted
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$filter=isEncrypted+eq+false" \
  | jq '.value | length'
# expected: 0
```

**EVIDENCE**

```bash
# export encryption compliance report
# Jamf:
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=DISK_ENCRYPTION&section=GENERAL&section=HARDWARE&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    serial: .hardware.serialNumber,
    os: .hardware.osVersion,
    filevault_state: .diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State,
    recovery_key_valid: .diskEncryption.individualRecoveryKeyValidityStatus
  }]' > evidence/endpoint-encryption-$(date +%Y-%m-%d).json

# Intune:
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$select=deviceName,serialNumber,osVersion,isEncrypted,complianceState" \
  | jq '[.value[] | {
    name: .deviceName,
    serial: .serialNumber,
    os: .osVersion,
    encrypted: .isEncrypted,
    compliance: .complianceState
  }]' > evidence/endpoint-encryption-$(date +%Y-%m-%d).json
```

---

### 3.4.3 OS auto-update enforcement

**DISCOVER**

```bash
# Jamf: check OS versions across fleet
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=HARDWARE&page-size=200" \
  | jq '[.results[] | .hardware.osVersion] | group_by(.) | map({version: .[0], count: length}) | sort_by(.version) | reverse'

# Intune: check OS versions
curl -s -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$select=deviceName,osVersion" \
  | jq '[.value[] | .osVersion] | group_by(.) | map({version: .[0], count: length}) | sort_by(.version) | reverse'

# identify devices on outdated OS
# define your minimum acceptable version (update as new versions release)
MIN_MACOS="15.0"
MIN_WINDOWS="10.0.22631"

# Jamf:
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=HARDWARE&section=GENERAL&page-size=200" \
  | jq --arg min "$MIN_MACOS" '[.results[] | select(.hardware.osVersion < $min) | {
    name: .general.name,
    os_version: .hardware.osVersion
  }]'
```

**FIX**

```bash
# --- Jamf: enforce automatic updates ---
# Jamf Pro > Computers > Configuration Profiles > New
# Restrictions payload:
#   - Force automatic software updates: checked
#   - Delay software updates: 3 days (allows testing)
#
# or push a managed software update:
curl -s -X POST \
  -H "Authorization: Bearer ${JAMF_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://{{JAMF_URL}}/api/v1/managed-software-updates/plans" \
  -d '{
    "devices": [{"deviceId": "{{DEVICE_ID}}", "objectType": "COMPUTER"}],
    "config": {
      "updateAction": "DOWNLOAD_INSTALL_SCHEDULE",
      "versionType": "LATEST_ANY",
      "forceInstallLocalDateTime": "2026-04-13T20:00:00"
    }
  }'

# --- Intune: enforce Windows Update ---
# endpoint.microsoft.com > Devices > Windows > Update rings
# Create profile with:
#   Quality update deferral: 3 days
#   Feature update deferral: 14 days
#   Automatic update behavior: Auto install and restart at scheduled time
#   Active hours: 08:00 - 17:00
```

**VERIFY**

```bash
# re-check OS version distribution after update deadline
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=HARDWARE&page-size=200" \
  | jq --arg min "$MIN_MACOS" '[.results[] | select(.hardware.osVersion < $min)] | length'
# expected: 0
```

**EVIDENCE**

```bash
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=HARDWARE&section=GENERAL&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    serial: .hardware.serialNumber,
    os_version: .hardware.osVersion,
    last_contact: .general.lastContactTime
  }]' > evidence/endpoint-os-versions-$(date +%Y-%m-%d).json
```

---

### 3.4.4 EDR deployment

**DISCOVER**

```bash
# --- CrowdStrike Falcon ---
# step 1: get all device IDs
DEVICE_IDS=$(curl -s -X GET \
  -H "Authorization: Bearer ${CS_TOKEN}" \
  "https://api.crowdstrike.com/devices/queries/devices-scroll/v1?limit=5000" \
  | jq -r '.resources | join("&ids=")')

# step 2: batch lookup (single request, up to 5000 IDs)
curl -s -H "Authorization: Bearer ${CS_TOKEN}" \
  "https://api.crowdstrike.com/devices/entities/devices/v2?ids=${DEVICE_IDS}" \
  | jq '[.resources[] | {
    hostname: .hostname,
    os: .os_version,
    sensor_version: .agent_version,
    last_seen: .last_seen,
    status: .status
  }]'

# get OAuth2 token for CrowdStrike:
# CS_TOKEN=$(curl -s -X POST "https://api.crowdstrike.com/oauth2/token" \
#   -d "client_id=${CS_CLIENT_ID}&client_secret=${CS_CLIENT_SECRET}" \
#   | jq -r '.access_token')

# --- SentinelOne ---
curl -s -H "Authorization: APIToken ${S1_TOKEN}" \
  "https://{{S1_CONSOLE}}.sentinelone.net/web/api/v2.1/agents?limit=200" \
  | jq '[.data[] | {
    name: .computerName,
    os: .osName,
    agent_version: .agentVersion,
    last_active: .lastActiveDate,
    infected: .infected,
    is_active: .isActive
  }]'

# compare EDR device count with MDM device count
echo "EDR protected devices: $(curl -s ... | jq '.resources | length')"
echo "MDM enrolled devices: $(curl -s ... | jq '.totalCount')"
# any gap = unprotected devices
```

**FIX**

> **deploy EDR agent via MDM:**
>
> Jamf + CrowdStrike:
> 1. upload CrowdStrike Falcon sensor .pkg to Jamf Pro > Packages
> 2. create a Policy: Jamf Pro > Policies > New
>    - trigger: Enrollment Complete + Recurring Check-in
>    - package: CrowdStrike Falcon sensor
>    - install command: `/usr/sbin/installer -pkg /tmp/FalconSensor.pkg -target /`
>    - post-install script: `/Library/CS/falconctl license {{CS_CID}}`
>    - scope: All Managed Clients
>
> Intune + CrowdStrike:
> 1. endpoint.microsoft.com > Apps > Windows > Add > Windows app (Win32)
> 2. upload CrowdStrike sensor .intunewin package
> 3. install command: `WindowsSensor.exe /install /quiet /norestart CID={{CS_CID}}`
> 4. assign to All Devices

**VERIFY**

```bash
# CrowdStrike: count devices with active sensor
curl -s -H "Authorization: Bearer ${CS_TOKEN}" \
  "https://api.crowdstrike.com/devices/count/v1?type=status&value=normal" \
  | jq '.resources'

# SentinelOne: count active agents
curl -s -H "Authorization: APIToken ${S1_TOKEN}" \
  "https://{{S1_CONSOLE}}.sentinelone.net/web/api/v2.1/agents/count?isActive=true" \
  | jq '.data.total'
```

**EVIDENCE**

```bash
# CrowdStrike: export device protection report
curl -s -H "Authorization: Bearer ${CS_TOKEN}" \
  "https://api.crowdstrike.com/devices/queries/devices-scroll/v1?limit=5000" \
  | jq -r '.resources[]' > /tmp/cs-device-ids.txt

# batch lookup (CrowdStrike supports up to 5000 IDs per request)
paste -sd '&ids=' /tmp/cs-device-ids.txt | while read ids; do
  curl -s -H "Authorization: Bearer ${CS_TOKEN}" \
    "https://api.crowdstrike.com/devices/entities/devices/v2?ids=${ids}"
done | jq '[.resources[] | {
  hostname: .hostname,
  serial: .serial_number,
  os: .os_version,
  sensor_version: .agent_version,
  last_seen: .last_seen,
  status: .status
}]' > evidence/edr-deployment-status-$(date +%Y-%m-%d).json

# SentinelOne:
curl -s -H "Authorization: APIToken ${S1_TOKEN}" \
  "https://{{S1_CONSOLE}}.sentinelone.net/web/api/v2.1/agents?limit=200" \
  | jq '[.data[] | {
    name: .computerName,
    serial: .serialNumber,
    os: .osName,
    agent_version: .agentVersion,
    last_active: .lastActiveDate,
    is_active: .isActive,
    infected: .infected
  }]' > evidence/edr-deployment-status-$(date +%Y-%m-%d).json
```

---

### 3.4.5 screen lock enforcement

**DISCOVER**

```bash
# Jamf: check for screen lock configuration profile
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=CONFIGURATION_PROFILES&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    profiles: [.configurationProfiles[]?.profileName]
  }]'
# look for a profile with "screen lock" or "passcode" in the name
```

**FIX**

```bash
# --- Jamf: push screen lock profile ---
# Jamf Pro > Computers > Configuration Profiles > New
# Security & Privacy payload:
#   - Require password after sleep or screen saver: Immediately
# Passcode payload (iOS/macOS):
#   - Maximum auto-lock: 5 minutes
#   - Require alphanumeric passcode
#
# alternatively, push via command:
cat > /tmp/screenlock-profile.mobileconfig << 'MCEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.screensaver</string>
            <key>PayloadIdentifier</key>
            <string>com.company.screensaver</string>
            <key>PayloadUUID</key>
            <string>{{GENERATE_UUID}}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>askForPassword</key>
            <true/>
            <key>askForPasswordDelay</key>
            <integer>0</integer>
            <key>idleTime</key>
            <integer>300</integer>
            <key>loginWindowIdleTime</key>
            <integer>300</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SOC2 - Screen Lock</string>
    <key>PayloadIdentifier</key>
    <string>com.company.soc2.screenlock</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{{GENERATE_UUID}}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
MCEOF

# --- Intune: push screen lock policy ---
# endpoint.microsoft.com > Devices > Configuration profiles > Create profile
# Platform: Windows 10 and later
# Profile type: Device restrictions
# Password:
#   - Require a password: Yes
#   - Maximum minutes of inactivity before screen locks: 5
#   - Password type: Alphanumeric
```

**VERIFY**

```bash
# Jamf: confirm profile is installed on all devices
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=CONFIGURATION_PROFILES&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    has_screenlock_profile: ([.configurationProfiles[]?.profileName | select(test("Screen Lock|screenlock|SOC2.*Screen"; "i"))] | length > 0)
  }] | map(select(.has_screenlock_profile == false))'
# expected: empty array (all devices have the profile)
```

**EVIDENCE**

```bash
curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=CONFIGURATION_PROFILES&section=GENERAL&page-size=200" \
  | jq '[.results[] | {
    name: .general.name,
    profiles: [.configurationProfiles[]?.profileName]
  }]' > evidence/endpoint-screenlock-profiles-$(date +%Y-%m-%d).json
```

---

## 3.5 deprovisioning automation — deep dive

> this section expands on 3.2.4 because deprovisioning failures are the #1 cause of SOC 2 audit exceptions (68% of qualified opinions). the difference between a clean opinion and a qualified opinion often comes down to whether one terminated employee retained access for 48 hours.

### the deprovisioning chain

when an employee leaves, access must be removed from every system. the chain looks like this:

```
HR system (source of truth)
  |
  v  (SCIM / webhook)
identity provider (Okta / Google Workspace)
  |
  v  (SSO session termination)
SSO-connected apps (automatic)
  |
  v  (manual / scripted)
non-SSO apps (manual revocation)
  |
  v  (MDM command)
devices (wipe / lock)
  |
  v  (rotation)
shared credentials & API keys
```

### step 1: HR system triggers IdP deactivation

```bash
# --- Rippling to Okta SCIM ---
# Rippling has built-in Okta integration:
# 1. Rippling admin > IT Management > App Management > Add Okta
# 2. Enable SCIM provisioning
# 3. Map: Rippling termination -> Okta deactivation
#
# when an employee is terminated in Rippling:
# Rippling sends: PATCH /Users/{id} {"active": false}
# Okta receives the SCIM call and deactivates the user
# all active sessions are immediately revoked

# --- BambooHR to Okta ---
# uses Okta's BambooHR integration:
# 1. Okta Admin > Applications > Add Application > BambooHR
# 2. Provisioning tab > Configure API Integration
# 3. Enable: Import Users, Create Users, Deactivate Users
# 4. Schedule import: hourly (or use webhook for real-time)
#
# BambooHR webhook setup for real-time:
# BambooHR > Settings > Webhooks > Add > Employee Terminated
# POST to: https://{{OKTA_DOMAIN}}/api/v1/inboundSCIM/{{APP_ID}}/Users

# --- Google Workspace as IdP ---
# if using Google Workspace instead of Okta, deactivation = suspending the user:
# gam update user employee@company.com suspended on
# this terminates all sessions and revokes access to all Google services and SSO apps

# --- manual deactivation API call ---
# Okta:
curl -s -X POST \
  -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/{{USER_ID}}/lifecycle/deactivate"

# Google Workspace:
curl -s -X PUT \
  -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/users/{{USER_EMAIL}}" \
  -d '{"suspended": true}'
```

### step 2: SSO-connected apps (automatic)

when the IdP deactivates a user, all SSO-connected apps automatically lose access because SAML/OIDC authentication fails. no action needed for:
- Slack (if SSO-only)
- Jira/Confluence (if SSO-only)
- Datadog (if SSO-only)
- AWS IAM Identity Center / SSO (if federated)
- any app configured for "SSO-only" authentication (no local passwords)

**critical check:** ensure all apps are configured for SSO-only. if an app allows local passwords alongside SSO, deactivating the IdP account does NOT revoke access.

```bash
# Okta: list apps that the user had access to
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users/{{USER_ID}}/appLinks" \
  | jq '[.[] | {app: .label, link: .linkUrl}]'
```

### step 3: non-SSO apps (manual revocation required)

these apps do not support SSO or have local credentials that persist after IdP deactivation. you must revoke access manually or via API:

```bash
# common non-SSO apps that need manual revocation:

# --- GitHub (if not SSO-only) ---
gh api orgs/{{ORG}}/members/{{USERNAME}} -X DELETE

# --- AWS IAM (if using IAM users, not SSO) ---
aws iam delete-login-profile --user-name "{{USERNAME}}"
aws iam list-access-keys --user-name "{{USERNAME}}" --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  tr '\t' '\n' | while read key; do
    aws iam delete-access-key --user-name "{{USERNAME}}" --access-key-id "$key"
done
aws iam remove-user-from-group --user-name "{{USERNAME}}" --group-name "{{GROUP}}"

# --- Heroku ---
# curl -s -X DELETE \
#   -H "Authorization: Bearer ${HEROKU_TOKEN}" \
#   "https://api.heroku.com/teams/{{TEAM}}/members/{{EMAIL}}"

# --- Vercel ---
# curl -s -X DELETE \
#   -H "Authorization: Bearer ${VERCEL_TOKEN}" \
#   "https://api.vercel.com/v1/teams/{{TEAM_ID}}/members/{{USER_ID}}"

# --- npm (package registry access) ---
# npm owner rm {{USERNAME}} {{PACKAGE_NAME}}

# --- Docker Hub ---
# curl -s -X DELETE \
#   -H "Authorization: Bearer ${DOCKER_TOKEN}" \
#   "https://hub.docker.com/v2/orgs/{{ORG}}/members/{{USERNAME}}"

# --- Stripe ---
# must be done in Stripe Dashboard: Settings > Team > Remove member
# no API for team management

# --- MongoDB Atlas ---
# curl -s -X DELETE \
#   --digest -u "{{ATLAS_PUBLIC_KEY}}:{{ATLAS_PRIVATE_KEY}}" \
#   "https://cloud.mongodb.com/api/atlas/v1.0/orgs/{{ORG_ID}}/users/{{USER_ID}}"
```

### step 4: source control access revocation

```bash
# remove from GitHub org
gh api orgs/{{ORG}}/members/{{USERNAME}} -X DELETE

# remove from all teams
gh api orgs/{{ORG}}/teams --paginate --jq '.[].slug' | while read team; do
  gh api orgs/{{ORG}}/teams/${team}/members/{{USERNAME}} -X DELETE 2>/dev/null
done

# revoke any personal access tokens (user must do this themselves, but you
# can remove their org membership which revokes org-scoped tokens)

# remove deploy keys they created
gh api repos/{{OWNER}}/{{REPO}}/keys --paginate --jq '.[] | select(.title | test("{{USERNAME}}"; "i")) | .id' | while read key_id; do
  gh api repos/{{OWNER}}/{{REPO}}/keys/${key_id} -X DELETE
done

# GitLab alternative:
# curl -s -X DELETE \
#   -H "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
#   "https://gitlab.com/api/v4/groups/{{GROUP_ID}}/members/{{USER_ID}}"
```

### step 5: cloud provider IAM cleanup

```bash
# --- AWS ---
# remove user from all groups
aws iam list-groups-for-user --user-name "{{USERNAME}}" --query 'Groups[].GroupName' --output text | \
  tr '\t' '\n' | while read group; do
    aws iam remove-user-from-group --user-name "{{USERNAME}}" --group-name "$group"
done

# delete access keys
aws iam list-access-keys --user-name "{{USERNAME}}" --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  tr '\t' '\n' | while read key; do
    aws iam delete-access-key --user-name "{{USERNAME}}" --access-key-id "$key"
done

# delete login profile (console access)
aws iam delete-login-profile --user-name "{{USERNAME}}" 2>/dev/null

# detach inline policies
aws iam list-user-policies --user-name "{{USERNAME}}" --query 'PolicyNames[]' --output text | \
  tr '\t' '\n' | while read policy; do
    aws iam delete-user-policy --user-name "{{USERNAME}}" --policy-name "$policy"
done

# detach managed policies
aws iam list-attached-user-policies --user-name "{{USERNAME}}" --query 'AttachedPolicies[].PolicyArn' --output text | \
  tr '\t' '\n' | while read arn; do
    aws iam detach-user-policy --user-name "{{USERNAME}}" --policy-arn "$arn"
done

# delete MFA devices
aws iam list-mfa-devices --user-name "{{USERNAME}}" --query 'MFADevices[].SerialNumber' --output text | \
  tr '\t' '\n' | while read mfa; do
    aws iam deactivate-mfa-device --user-name "{{USERNAME}}" --serial-number "$mfa"
    aws iam delete-virtual-mfa-device --serial-number "$mfa" 2>/dev/null
done

# finally, delete the IAM user
aws iam delete-user --user-name "{{USERNAME}}"

# --- GCP ---
# gcloud projects remove-iam-policy-binding {{PROJECT_ID}} \
#   --member="user:{{EMAIL}}" \
#   --role="{{ROLE}}"
# repeat for each role the user held

# --- Azure ---
# az ad user delete --id "{{USER_OBJECT_ID}}"
```

### step 6: API key and token rotation

```bash
# when an employee with infrastructure access leaves, rotate these:

# AWS access keys — rotate for any service accounts they could have accessed
# find service account keys:
aws iam list-users --query 'Users[?starts_with(UserName, `svc-`)].UserName' --output text | \
  tr '\t' '\n' | while read svc; do
    echo "Service account: $svc"
    aws iam list-access-keys --user-name "$svc" --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Created:CreateDate}' --output table
done
# rotate any key the departing employee had access to

# Okta API tokens
# curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
#   "https://${OKTA_DOMAIN}/api/v1/api-tokens" | jq '.[] | {name, created, lastUpdated}'
# revoke tokens created by the departing user

# CI/CD secrets — if the departing user had access to CI/CD secrets:
# rotate all secrets in GitHub Actions:
#   gh secret list --repo {{OWNER}}/{{REPO}}
# for each, generate a new value and update:
#   gh secret set SECRET_NAME --repo {{OWNER}}/{{REPO}}

# database credentials — if the user had direct database access:
# rotate the credentials for any shared database accounts
# drop their personal database user if they had one
```

### step 7: shared credential rotation

```bash
# if the departing employee had access to shared credentials in 1Password/Bitwarden:
# 1. identify which vaults they had access to
# 2. rotate all credentials in those vaults
# 3. remove them from the password manager

# 1Password (using 1Password CLI):
# op list users --group "engineering" | jq '.[] | select(.email == "{{EMAIL}}")'
# op remove user "{{EMAIL}}" --group "engineering"
# op list items --vault "engineering-shared" | jq '.[].title'
# (rotate each credential above)

# Bitwarden:
# bw list org-members --organizationid {{ORG_ID}} | jq '.[] | select(.email == "{{EMAIL}}")'
# bw confirm org-member {{USER_ID}} --organizationid {{ORG_ID}} --remove
```

### step 8: device wipe via MDM

```bash
# --- Jamf: remote wipe ---
# find the device
DEVICE_ID=$(curl -s -H "Authorization: Bearer ${JAMF_TOKEN}" \
  "https://{{JAMF_URL}}/api/v1/computers-inventory?section=GENERAL&page-size=200" \
  | jq -r --arg email "{{EMAIL}}" '.results[] | select(.general.lastIpAddress != null) | .id')

# send wipe command
curl -s -X POST \
  -H "Authorization: Bearer ${JAMF_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://{{JAMF_URL}}/api/v1/jamf-management-framework/commands" \
  -d "{\"deviceIds\": [\"${DEVICE_ID}\"], \"commandType\": \"ERASE_DEVICE\"}"

# --- Intune: remote wipe ---
# curl -s -X POST \
#   -H "Authorization: Bearer ${GRAPH_TOKEN}" \
#   -H "Content-Type: application/json" \
#   "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{{DEVICE_ID}}/wipe"

# note: for personal devices (BYOD), use "retire" instead of "wipe" to only
# remove corporate data without erasing personal data:
# Jamf: REMOVE_MDMPROFILE command
# Intune: /retire endpoint instead of /wipe
```

### step 9: weekly reconciliation script (production-ready)

```bash
#!/bin/bash
# deprovision-reconciliation-full.sh
# run weekly: cron 0 9 * * 1 /opt/scripts/deprovision-reconciliation-full.sh
#
# compares HR active list with every system that has user accounts.
# any discrepancy = potential deprovisioning failure = SOC 2 finding.

set -euo pipefail

DATE=$(date +%Y-%m-%d)
REPORT_FILE="/var/log/compliance/deprovision-reconciliation-${DATE}.json"
FINDINGS=0

echo "{ \"date\": \"${DATE}\", \"findings\": [" > "$REPORT_FILE"

# --- get HR active employee list (source of truth) ---
# replace with your HR system API:
# HR_EMAILS=$(curl -s -H "Authorization: Bearer ${HR_TOKEN}" \
#   "https://api.yourhrsystem.com/employees?status=active" \
#   | jq -r '.[].work_email')

# --- check Okta ---
OKTA_ACTIVE=$(curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" \
  | jq -r '.[].profile.email')

for email in $OKTA_ACTIVE; do
  if ! echo "$HR_EMAILS" | grep -qi "^${email}$"; then
    echo "  {\"system\": \"okta\", \"email\": \"${email}\", \"finding\": \"active in Okta but not in HR\"}," >> "$REPORT_FILE"
    FINDINGS=$((FINDINGS + 1))
  fi
done

# --- check GitHub ---
GH_MEMBERS=$(gh api orgs/{{ORG}}/members --paginate --jq '.[].login')
# note: GitHub uses usernames not emails — you need a mapping table
# gh api orgs/{{ORG}}/members --paginate --jq '.[].login' | while read user; do
#   email=$(gh api users/${user} --jq '.email // empty')
#   ...
# done

# --- check AWS IAM ---
AWS_USERS=$(aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n')
for user in $AWS_USERS; do
  if [[ "$user" != svc-* ]] && ! echo "$HR_EMAILS" | grep -qi "${user}"; then
    echo "  {\"system\": \"aws-iam\", \"user\": \"${user}\", \"finding\": \"IAM user not in HR active list\"}," >> "$REPORT_FILE"
    FINDINGS=$((FINDINGS + 1))
  fi
done

echo "  ], \"total_findings\": ${FINDINGS} }" >> "$REPORT_FILE"

echo "Reconciliation complete. Findings: ${FINDINGS}"
echo "Report: ${REPORT_FILE}"

# alert if findings > 0
if [ "$FINDINGS" -gt 0 ]; then
  echo "ALERT: ${FINDINGS} potential deprovisioning failures found. Review ${REPORT_FILE}"
  # send to Slack, PagerDuty, email, etc.
fi
```

### step 10: audit trail requirements

every deprovisioning event must be documented with:

```
required fields for each offboarding:
- employee name and email
- termination date (from HR)
- termination type (voluntary / involuntary)
- deactivation timestamp (from IdP logs)
- time delta: (deactivation timestamp - termination date) — must be within SLA
- SLA: involuntary = 1 hour, voluntary = end of last working day
- systems deactivated (list each with timestamp)
- device status (returned / wiped / pending)
- shared credential rotation status
- offboarding ticket ID (Jira/Linear)
- performed by (name of person/automation who executed)
```

```bash
# pull deprovisioning evidence for audit period from Okta system log
curl -s -H "Authorization: SSWS ${OKTA_TOKEN}" \
  "https://${OKTA_DOMAIN}/api/v1/logs?filter=eventType+eq+%22user.lifecycle.deactivate%22&since={{AUDIT_PERIOD_START}}T00:00:00Z&until={{AUDIT_PERIOD_END}}T23:59:59Z&limit=1000" \
  | jq '[.[] | {
    timestamp: .published,
    actor: .actor.displayName,
    actor_email: .actor.alternateId,
    target_user: .target[0].displayName,
    target_email: .target[0].alternateId,
    outcome: .outcome.result,
    reason: .outcome.reason
  }]' > evidence/deprovisioning-audit-trail-$(date +%Y-%m-%d).json

# cross-reference with HR termination dates to calculate SLA compliance
# the auditor will sample 5-10 terminations and check the time delta
```

---

## control-to-TSC mapping

| control | TSC criteria | section |
|---------|-------------|---------|
| branch protection | CC8.1 (change management) | 3.1.1 |
| secret scanning | CC6.1 (logical access) | 3.1.2 |
| dependabot | CC7.1 (monitoring), CC8.1 | 3.1.3 |
| org 2FA | CC6.2 (credentials) | 3.1.4 |
| audit log streaming | CC7.2 (monitoring anomalies) | 3.1.5 |
| CODEOWNERS | CC8.1 (change management) | 3.1.6 |
| Actions security | CC6.1, CC8.1 | 3.1.7 |
| MFA enforcement (IdP) | CC6.1, CC6.2 | 3.2.1 |
| password policy (IdP) | CC6.1, CC6.2 | 3.2.2 |
| session management | CC6.1 | 3.2.3 |
| user deprovisioning | CC6.3 (access removal) | 3.2.4 |
| group-based provisioning | CC6.1, CC6.3 | 3.2.5 |
| 2SV enforcement (GW) | CC6.1, CC6.2 | 3.3.1 |
| password policy (GW) | CC6.1, CC6.2 | 3.3.2 |
| session controls (GW) | CC6.1 | 3.3.3 |
| admin audit log (GW) | CC7.2 | 3.3.4 |
| MDM enrollment | CC6.7 (physical/logical) | 3.4.1 |
| disk encryption | CC6.7 | 3.4.2 |
| OS auto-update | CC7.1 | 3.4.3 |
| EDR deployment | CC7.1, CC7.2 | 3.4.4 |
| screen lock | CC6.7 | 3.4.5 |
| deprovisioning chain | CC6.3 | 3.5 |
