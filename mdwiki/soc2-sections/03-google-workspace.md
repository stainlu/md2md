# section 03-gws: Google Workspace security controls

deep Google Workspace coverage for companies using GWS as their primary identity provider. every control follows DISCOVER > FIX > VERIFY > EVIDENCE. provides both GAM commands and direct Admin SDK API calls for every operation.

> this section addresses CC6.1 (logical access), CC6.2 (credentials), CC6.3 (access removal), CC7.2 (monitoring), and CC8.1 (change management) as they apply to Google Workspace identity and platform controls.

> **prerequisite:** this section assumes Google Workspace Business Plus or Enterprise tier. some controls (DLP, Context-Aware Access, Alert Center API) require Enterprise tier. the section notes tier requirements where applicable.

---

## setup: Google Workspace Admin SDK API access

before running any commands, you need authenticated access via GAM or direct API calls.

### option 1: GAM (recommended for most operations)

```bash
# install GAM
# https://github.com/GAM-team/GAM
bash <(curl -s -S -L https://gam-shortn.appspot.com/gam-install)

# verify installation
gam version

# GAM handles OAuth automatically on first run.
# it will open a browser for admin consent. authorize with a super admin account.
# scopes are pre-configured for common operations.

# verify GAM is working
gam info domain
# expected output:
# Customer ID: C01234abc
# Primary Domain: yourdomain.com
# ...
```

### option 2: direct API calls via service account

```bash
# 1. create a service account in Google Cloud Console:
#    https://console.cloud.google.com/iam-admin/serviceaccounts
#
# 2. enable these APIs in the Google Cloud project:
#    - Admin SDK API
#    - Reports API
#    - Alert Center API
#    - Cloud Identity API (for device management)
#
# 3. delegate domain-wide authority to the service account:
#    a. copy the service account's Client ID (numeric)
#    b. go to admin.google.com > Security > Access and data control > API controls
#    c. click "Manage Domain Wide Delegation"
#    d. add new delegation with the Client ID and these scopes:
#
#       https://www.googleapis.com/auth/admin.directory.user
#       https://www.googleapis.com/auth/admin.directory.user.security
#       https://www.googleapis.com/auth/admin.directory.group
#       https://www.googleapis.com/auth/admin.directory.group.member
#       https://www.googleapis.com/auth/admin.directory.rolemanagement
#       https://www.googleapis.com/auth/admin.directory.device.mobile
#       https://www.googleapis.com/auth/admin.reports.audit.readonly
#       https://www.googleapis.com/auth/apps.alerts
#       https://www.googleapis.com/auth/cloud-identity.devices.readonly
#
# 4. download the service account JSON key file

# get an access token (impersonating a super admin)
ACCESS_TOKEN=$(gcloud auth print-access-token \
  --impersonate-service-account=sa@project.iam.gserviceaccount.com)

# or if using a service account key file:
# ACCESS_TOKEN=$(python3 -c "
# import google.auth.transport.requests
# from google.oauth2 import service_account
# creds = service_account.Credentials.from_service_account_file(
#     'service-account-key.json',
#     scopes=['https://www.googleapis.com/auth/admin.directory.user'],
#     subject='admin@yourdomain.com'  # super admin to impersonate
# )
# creds.refresh(google.auth.transport.requests.Request())
# print(creds.token)
# ")

DOMAIN="yourdomain.com"
CUSTOMER_ID="my_customer"  # literal string "my_customer" works for your own domain

# verify access
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?domain=$DOMAIN&maxResults=1" \
  | jq '.users[0].primaryEmail'
# expected: "someuser@yourdomain.com"
```

### pagination helper

many Google API endpoints return paginated results. use this pattern for any list operation.

```bash
# generic pagination for Admin SDK list endpoints
paginate_gws_api() {
  local url="$1"
  local items_key="$2"  # e.g., "users", "groups", "members"
  local all_items="[]"
  local page_token=""

  while true; do
    local page_url="$url"
    if [ -n "$page_token" ]; then
      if echo "$url" | grep -q '?'; then
        page_url="${url}&pageToken=${page_token}"
      else
        page_url="${url}?pageToken=${page_token}"
      fi
    fi

    local response
    response=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$page_url")

    local page_items
    page_items=$(echo "$response" | jq ".${items_key} // []")
    all_items=$(echo "$all_items $page_items" | jq -s '.[0] + .[1]')

    page_token=$(echo "$response" | jq -r '.nextPageToken // empty')
    if [ -z "$page_token" ]; then
      break
    fi
  done

  echo "$all_items"
}

# usage:
# paginate_gws_api \
#   "https://admin.googleapis.com/admin/directory/v1/users?domain=$DOMAIN&maxResults=500&projection=full" \
#   "users"
```

---

## 3-gws.1 2-step verification (2SV) enforcement

2SV is the Google Workspace equivalent of MFA. it is the single most impactful credential control. without it, a phished password grants full access to email, drive, and all SSO-connected apps.

### DISCOVER

```bash
# --- via GAM ---
# list all users with 2SV enrollment and enforcement status
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,orgUnitPath \
  > /tmp/gw-2sv-status.csv

# count users not enrolled
gam print users fields primaryEmail,isEnrolledIn2Sv \
  | awk -F, '$NF == "False"' | wc -l
# expected: 0 (all users enrolled)

# count users not enforced
gam print users fields primaryEmail,isEnforcedIn2Sv \
  | awk -F, '$NF == "False"' | wc -l
# expected: 0 (enforcement turned on for all)

# --- via API ---
# get all users with 2SV status
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    enrolled_2sv: .isEnrolledIn2Sv,
    enforced_2sv: .isEnforcedIn2Sv,
    org_unit: .orgUnitPath
  }]'

# find users NOT enrolled in 2SV
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | select(.isEnrolledIn2Sv == false) | {
    email: .primaryEmail,
    org_unit: .orgUnitPath,
    created: .creationTime,
    last_login: .lastLoginTime
  }]'
# expected: []
# any non-empty result is a finding

# summary statistics
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '{
    total_users: (.users | length),
    enrolled_2sv: [.users[] | select(.isEnrolledIn2Sv == true)] | length,
    not_enrolled_2sv: [.users[] | select(.isEnrolledIn2Sv == false)] | length,
    enforced_2sv: [.users[] | select(.isEnforcedIn2Sv == true)] | length,
    not_enforced_2sv: [.users[] | select(.isEnforcedIn2Sv == false)] | length
  }'
# expected:
# {
#   "total_users": 50,
#   "enrolled_2sv": 50,
#   "not_enrolled_2sv": 0,
#   "enforced_2sv": 50,
#   "not_enforced_2sv": 0
# }
```

### FIX

> **2SV enforcement must be configured via Admin Console** (there is no Admin SDK API endpoint for changing this policy — it is a known limitation).
>
> 1. go to https://admin.google.com > Security > Authentication > 2-Step Verification
> 2. check "Allow users to turn on 2-Step Verification"
> 3. under Enforcement, select **"On"** and set the enforcement date (give existing users 7 days)
> 4. under Methods, select **"Any except verification codes via text, phone call"**
>    - this blocks SMS-based 2SV which is vulnerable to SIM-swapping attacks
>    - allowed methods: security keys (FIDO2), Google Authenticator, Google prompts
>    - for highest security: select "Only security key" (requires physical FIDO2 keys)
> 5. set new user enrollment period: **1 day** (new hires must enroll within 24 hours)
> 6. click Save
>
> apply the policy at the top-level OU ("/") so it inherits to all sub-OUs.
>
> **why no API?** Google treats 2SV enforcement as an organizational policy, not a per-user setting. the `isEnforcedIn2Sv` field on the user object is read-only — it reflects whether the OU policy applies to that user. you can read it via API but cannot set it via API.

```bash
# after setting the policy in Admin Console, monitor enrollment progress:
# run this daily until all users are enrolled
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv \
  | awk -F, '$2 == "False" || $3 == "False"'
# expected: no output once all users comply
```

### VERIFY

```bash
# --- via GAM ---
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv \
  | awk -F, 'NR > 1 && ($2 == "False" || $3 == "False") { found=1; print } END { if (!found) print "ALL USERS COMPLIANT" }'

# --- via API ---
NOT_COMPLIANT=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | select(.isEnrolledIn2Sv == false or .isEnforcedIn2Sv == false)]')

echo "$NOT_COMPLIANT" | jq 'length'
# expected: 0

if [ "$(echo "$NOT_COMPLIANT" | jq 'length')" -gt 0 ]; then
  echo "FINDING: the following users are not 2SV compliant:"
  echo "$NOT_COMPLIANT" | jq '.[].primaryEmail'
fi
```

### EVIDENCE

```bash
# --- via GAM ---
gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,creationTime,lastLoginTime,orgUnitPath \
  > evidence/gw-2sv-status-$(date +%Y-%m-%d).csv

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    enrolled_2sv: .isEnrolledIn2Sv,
    enforced_2sv: .isEnforcedIn2Sv,
    created: .creationTime,
    last_login: .lastLoginTime,
    org_unit: .orgUnitPath
  }]' > evidence/gw-2sv-status-$(date +%Y-%m-%d).json

echo "evidence saved: evidence/gw-2sv-status-$(date +%Y-%m-%d).json"
echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

---

## 3-gws.2 password policy

password policy controls the minimum complexity and lifecycle of user passwords. auditors verify that passwords meet industry standards (NIST 800-63b or SOC 2 TSC CC6.1).

### DISCOVER

```bash
# --- via GAM ---
# GAM does not directly expose password policy settings.
# list organizational units to understand policy inheritance:
gam print orgs fields orgUnitPath,name

# check individual user password metadata (when they last changed it):
gam print users fields primaryEmail,lastLoginTime,creationTime,changePasswordAtNextLogin

# --- via API ---
# the Admin SDK Directory API does not have a dedicated password policy endpoint.
# password policy is set per OU via the Admin Console.
#
# however, you can check whether individual users are forced to change password:
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    must_change_password: .changePasswordAtNextLogin,
    last_login: .lastLoginTime,
    created: .creationTime
  }]'

# check for users who have "change password at next login" set (may indicate stale setup):
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | select(.changePasswordAtNextLogin == true) | .primaryEmail]'
# expected: [] (unless new accounts are pending first login)
```

### FIX

> **password policy must be set via Admin Console** (no API endpoint):
>
> 1. go to https://admin.google.com > Security > Authentication > Password management
> 2. set minimum password length: **14 characters** (NIST 800-63b recommends 8+ but SOC 2 auditors typically expect 12-14)
> 3. check **"Enforce password policy at next sign-in"**
> 4. set password expiration: **never expire** if 2SV is enforced, or **90 days** if 2SV is not yet enforced
>    - NIST 800-63b (2024) recommends against mandatory password rotation when MFA is in place
>    - many auditors now accept "no expiration + MFA" — discuss with your auditor
> 5. do not allow password reuse for **the last 12 passwords**
> 6. apply to the root OU ("/") for org-wide coverage
> 7. click Save
>
> **for new employees:** use `changePasswordAtNextLogin: true` when creating accounts via API to force password setup:

```bash
# force a specific user to change password at next login
gam update user newemployee@yourdomain.com changepassword on

# or via API
curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/users/newemployee@yourdomain.com" \
  -d '{"changePasswordAtNextLogin": true}'
```

### VERIFY

> take a screenshot of the Admin Console password management page showing the configured settings. this is the standard evidence format for Google Workspace controls that lack API read access.
>
> additionally, verify user-level compliance:

```bash
# check no users have stale "change password" flags (they should have logged in)
gam print users fields primaryEmail,changePasswordAtNextLogin \
  | awk -F, '$NF == "True"'
# expected: no output (all users have completed password setup)

# via API
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | select(.changePasswordAtNextLogin == true) | .primaryEmail]'
# expected: []
```

### EVIDENCE

```bash
# user password compliance report
gam print users fields primaryEmail,lastLoginTime,creationTime,changePasswordAtNextLogin,orgUnitPath \
  > evidence/gw-password-compliance-$(date +%Y-%m-%d).csv

# via API
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&projection=full&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    must_change_password: .changePasswordAtNextLogin,
    last_login: .lastLoginTime,
    created: .creationTime,
    org_unit: .orgUnitPath
  }]' > evidence/gw-password-compliance-$(date +%Y-%m-%d).json

# also save the Admin Console screenshot as:
# evidence/gw-password-policy-screenshot-$(date +%Y-%m-%d).png
```

---

## 3-gws.3 session management

session controls determine how long users can stay signed in before re-authentication. long sessions increase risk if a device is compromised.

### DISCOVER

```bash
# session length is configured at the OU level via Admin Console.
# there is no Admin SDK endpoint to read session policy.

# however, you can verify session behavior by checking login frequency in audit logs:

# --- via GAM ---
gam report login start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -20

# --- via API ---
# check login events for the past 7 days to observe session patterns
SEVEN_DAYS_AGO=$(date -v-7d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "7 days ago" +%Y-%m-%dT00:00:00.000Z)

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$SEVEN_DAYS_AGO&maxResults=100" \
  | jq '[.items[:10] | .[] | {
    user: .actor.email,
    time: .id.time,
    event: .events[0].name,
    login_type: (.events[0].parameters[]? | select(.name == "login_type") | .value),
    ip: .ipAddress
  }]'

# check for suspicious login patterns (multiple re-auths = session too short,
# zero re-auths = session too long or no enforcement)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$SEVEN_DAYS_AGO&maxResults=1000" \
  | jq '[.items[] | .actor.email] | group_by(.) | map({user: .[0], login_count_7d: length}) | sort_by(.login_count_7d) | reverse[:10]'
# shows top 10 users by login frequency — useful to understand session behavior
```

### FIX

> **session controls must be set via Admin Console:**
>
> 1. go to https://admin.google.com > Security > Access and data control > Google session control
>    - set web session duration: **12 hours** (forces re-auth after 12h of inactivity)
>    - this applies to all Google services (Gmail, Drive, Docs, etc.)
>
> 2. go to https://admin.google.com > Security > Access and data control > Google Cloud session control
>    - set re-authentication frequency: **12 hours**
>    - set re-authentication policy: **require password** (or security key)
>    - this applies to Google Cloud Console and gcloud CLI
>
> 3. consider enabling trusted apps exception:
>    - if mobile apps (Gmail, Drive) need longer sessions: set mobile session to 24 hours
>    - Admin Console: Security > Access and data control > Google session control > Mobile session
>
> **note on OAuth tokens:** Google Workspace OAuth tokens (used by third-party apps) have separate lifetimes. revoking a user's session does not revoke OAuth tokens. see section 3-gws.8 (OAuth App Access Control) for managing those.

### VERIFY

> take a screenshot of the Admin Console session control pages showing:
> - Google session control: 12h web, 24h mobile
> - Google Cloud session control: 12h with re-auth required

```bash
# verify session enforcement by checking recent login activity
# users should show regular re-authentication events

# --- via GAM ---
gam report login start_date $(date -v-1d +%Y-%m-%d 2>/dev/null || date -d "yesterday" +%Y-%m-%d) \
  > /tmp/gw-login-yesterday.csv
wc -l /tmp/gw-login-yesterday.csv
# if users are logging in daily, session controls are working

# --- via API ---
YESTERDAY=$(date -v-1d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "yesterday" +%Y-%m-%dT00:00:00.000Z)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$YESTERDAY&maxResults=10" \
  | jq '.items | length'
# expected: > 0 (users are re-authenticating)
```

### EVIDENCE

```bash
# export login activity as evidence of session enforcement
gam report login start_date $(date -v-30d +%Y-%m-%d 2>/dev/null || date -d "30 days ago" +%Y-%m-%d) \
  > evidence/gw-login-activity-$(date +%Y-%m-%d).csv

# via API
THIRTY_DAYS_AGO=$(date -v-30d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "30 days ago" +%Y-%m-%dT00:00:00.000Z)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$THIRTY_DAYS_AGO&maxResults=1000" \
  | jq '[.items[] | {
    user: .actor.email,
    time: .id.time,
    event: .events[0].name,
    ip: .ipAddress
  }]' > evidence/gw-login-events-$(date +%Y-%m-%d).json

# also save Admin Console screenshots as:
# evidence/gw-session-policy-screenshot-$(date +%Y-%m-%d).png
# evidence/gw-cloud-session-policy-screenshot-$(date +%Y-%m-%d).png
```

---

## 3-gws.4 user provisioning and lifecycle management

user lifecycle management covers account creation, status tracking, and detection of stale accounts. this is the read side — deprovisioning (the write side) is covered separately in 3-gws.5.

### DISCOVER

```bash
# --- via GAM ---

# all active users with key metadata
gam print users fields primaryEmail,suspended,creationTime,lastLoginTime,orgUnitPath,isAdmin \
  query "isSuspended=false" > /tmp/gw-active-users.csv

# suspended users (should match terminated employees)
gam print users query "isSuspended=true" \
  fields primaryEmail,suspensionReason,creationTime,lastLoginTime

# recently created users (last 30 days — review for unauthorized account creation)
gam print users fields primaryEmail,creationTime,orgUnitPath \
  query "isSuspended=false" \
  | awk -F, -v cutoff="$(date -v-30d +%Y-%m-%d 2>/dev/null || date -d '30 days ago' +%Y-%m-%d)" \
    'NR > 1 && $2 >= cutoff'

# users who have never logged in (potential stale accounts or misconfigured accounts)
gam print users fields primaryEmail,lastLoginTime,creationTime \
  query "isSuspended=false" \
  | awk -F, 'NR > 1 && ($2 == "" || $2 == "Never logged in")'

# users inactive for 90+ days (candidates for suspension)
gam print users fields primaryEmail,lastLoginTime,creationTime \
  query "isSuspended=false" \
  | awk -F, -v cutoff="$(date -v-90d +%Y-%m-%d 2>/dev/null || date -d '90 days ago' +%Y-%m-%d)" \
    'NR > 1 && $2 != "" && $2 < cutoff'

# --- via API ---

# all active users
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isSuspended=false&maxResults=500&projection=full" \
  | jq '[.users[] | {
    email: .primaryEmail,
    name: .name.fullName,
    created: .creationTime,
    last_login: .lastLoginTime,
    org_unit: .orgUnitPath,
    is_admin: .isAdmin,
    is_delegated_admin: .isDelegatedAdmin,
    enrolled_2sv: .isEnrolledIn2Sv
  }]'

# suspended users
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isSuspended=true&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    suspended: .suspended,
    suspension_reason: .suspensionReason,
    last_login: .lastLoginTime
  }]'

# stale accounts: active but no login in 90+ days
NINETY_DAYS_AGO=$(date -v-90d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "90 days ago" +%Y-%m-%dT00:00:00.000Z)

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isSuspended=false&maxResults=500&projection=full" \
  | jq --arg cutoff "$NINETY_DAYS_AGO" '[.users[] | select(
    .lastLoginTime == null or .lastLoginTime < $cutoff
  ) | {
    email: .primaryEmail,
    last_login: (.lastLoginTime // "never"),
    created: .creationTime,
    org_unit: .orgUnitPath
  }]'
# any results here need investigation — either suspend or verify the account is still needed
```

### FIX

```bash
# stale accounts should be suspended, not deleted.
# deletion removes audit trail; suspension preserves it.

# --- via GAM ---
# suspend a stale account
gam update user stale@yourdomain.com suspended on

# --- via API ---
curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/users/stale@yourdomain.com" \
  -d '{"suspended": true}'

# expected response: user object with "suspended": true

# for new user provisioning, use standardized creation:
# --- via GAM ---
gam create user newuser@yourdomain.com \
  firstname "Jane" lastname "Doe" \
  password "TemporaryP@ss123!" \
  changepassword on \
  org "/Engineering"

# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/users" \
  -d '{
    "primaryEmail": "newuser@yourdomain.com",
    "name": {"givenName": "Jane", "familyName": "Doe"},
    "password": "TemporaryP@ss123!",
    "changePasswordAtNextLogin": true,
    "orgUnitPath": "/Engineering"
  }'
```

### VERIFY

```bash
# verify no stale accounts remain after cleanup
gam print users fields primaryEmail,lastLoginTime query "isSuspended=false" \
  | awk -F, -v cutoff="$(date -v-90d +%Y-%m-%d 2>/dev/null || date -d '90 days ago' +%Y-%m-%d)" \
    'NR > 1 && $2 != "" && $2 < cutoff'
# expected: no output

# verify suspended accounts match HR termination list
gam print users query "isSuspended=true" fields primaryEmail | wc -l
```

### EVIDENCE

```bash
gam print users fields primaryEmail,suspended,suspensionReason,creationTime,lastLoginTime,orgUnitPath,isAdmin,isEnrolledIn2Sv \
  > evidence/gw-all-users-$(date +%Y-%m-%d).csv

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&maxResults=500&projection=full" \
  | jq '[.users[] | {
    email: .primaryEmail,
    suspended: .suspended,
    suspension_reason: .suspensionReason,
    created: .creationTime,
    last_login: .lastLoginTime,
    org_unit: .orgUnitPath,
    is_admin: .isAdmin,
    enrolled_2sv: .isEnrolledIn2Sv
  }]' > evidence/gw-all-users-$(date +%Y-%m-%d).json
```

---

## 3-gws.5 user deprovisioning (the critical control)

> **this is the single most critical control in SOC 2 compliance.** 68% of qualified (failed) SOC 2 opinions cite user deprovisioning failures. the control is CC6.3: "The entity disables or removes access to information and assets when no longer needed." if a terminated employee retains access for even one day beyond the SLA, it is a finding.

deprovisioning in Google Workspace = suspend + revoke tokens + transfer data + remove group memberships + wipe devices.

### DISCOVER

```bash
# step 1: get all active Google Workspace users
# --- via GAM ---
gam print users query "isSuspended=false" \
  fields primaryEmail,lastLoginTime,creationTime \
  > /tmp/gw-active-users.csv

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isSuspended=false&maxResults=500" \
  | jq '[.[] | {email: .primaryEmail}]' \
  > /tmp/gw-active-users.json

# step 2: get terminated employees from HR system
# (same as Okta section — depends on your HR system)
# --- Rippling ---
# curl -s -H "Authorization: Bearer ${RIPPLING_TOKEN}" \
#   "https://api.rippling.com/platform/api/employees?employment_status=TERMINATED" \
#   | jq '[.[] | {email: .work_email, terminated_date: .termination_date}]' \
#   > /tmp/hr-terminated.json

# --- BambooHR ---
# curl -s -H "Authorization: Basic $(echo -n "${BAMBOO_API_KEY}:x" | base64)" \
#   "https://api.bamboohr.com/api/gateway.php/{{BAMBOO_SUBDOMAIN}}/v1/reports/custom?format=JSON" \
#   -d '{"filters":{"lastChanged":{"includeNull":"no"}},"fields":["workEmail","status","terminationDate"]}' \
#   | jq '[.employees[] | select(.status == "Inactive") | {email: .workEmail, terminated_date: .terminationDate}]' \
#   > /tmp/hr-terminated.json

# step 3: find terminated employees who still have active Google Workspace accounts
jq -r '.[].email' /tmp/hr-terminated.json | while read email; do
  match=$(gam print users query "email:${email}" fields primaryEmail,suspended \
    | awk -F, 'NR > 1 && $2 == "False" { print $1 }')
  if [ -n "$match" ]; then
    echo "CRITICAL: terminated employee still active in Google Workspace: ${email}"
  fi
done

# any output here is a SOC 2 finding
```

### FIX

the fix has three tiers: automated provisioning (prevents the problem), manual deprovisioning procedure (handles exceptions), and weekly reconciliation (catches anything that falls through).

**tier 1: HR-to-Google Workspace automated provisioning (the real fix)**

```bash
# Google Workspace supports two approaches for automated user lifecycle:
#
# option A: SCIM via Cloud Identity
#   - Google Workspace supports inbound SCIM 2.0 via Cloud Identity
#   - HR system sends SCIM PATCH with active: false
#   - Google Workspace suspends the user
#   - supported by: Okta, Rippling, BambooHR (via middleware), Workday
#
# option B: Admin SDK API integration
#   - build a custom integration that:
#     1. polls HR system for status changes (or receives webhooks)
#     2. calls Admin SDK to suspend user
#     3. calls token revocation API
#     4. calls data transfer API
#     5. logs the entire operation
#
# option C: Google Workspace auto-licensing with Cloud Identity
#   - if using Cloud Identity Premium, Google can auto-suspend based on
#     external IdP signals

# verify SCIM or automated provisioning is working:
# check recent user suspension events in admin audit log

# --- via GAM ---
gam report admin event_name=SUSPEND_USER \
  start_date $(date -v-30d +%Y-%m-%d 2>/dev/null || date -d "30 days ago" +%Y-%m-%d)

# --- via API ---
THIRTY_DAYS_AGO=$(date -v-30d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "30 days ago" +%Y-%m-%dT00:00:00.000Z)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?eventName=SUSPEND_USER&startTime=$THIRTY_DAYS_AGO&maxResults=100" \
  | jq '[.items[] | {
    actor: .actor.email,
    target: (.events[0].parameters[]? | select(.name == "USER_EMAIL") | .value),
    time: .id.time
  }]'
```

**tier 2: manual deprovisioning script (for edge cases and emergencies)**

```bash
#!/bin/bash
# offboard-gws.sh — Google Workspace deprovisioning
# usage: ./offboard-gws.sh user@domain.com manager@domain.com "involuntary termination"

set -euo pipefail

USER_EMAIL="$1"
MANAGER_EMAIL="$2"
REASON="${3:-voluntary termination}"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LOG_FILE="evidence/deprovision-${USER_EMAIL}-${TIMESTAMP}.log"

mkdir -p evidence

log() {
  echo "[$(date -u +%H:%M:%S)] $1" | tee -a "$LOG_FILE"
}

log "=== DEPROVISIONING: ${USER_EMAIL} ==="
log "Manager: ${MANAGER_EMAIL}"
log "Reason: ${REASON}"
log "Started: ${TIMESTAMP}"
log ""

# step 1: suspend user (immediately kills all web sessions)
log "--- step 1: suspend account ---"
gam update user "$USER_EMAIL" suspended on 2>&1 | tee -a "$LOG_FILE"
# or via API:
# curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
#   -H "Content-Type: application/json" \
#   "https://admin.googleapis.com/admin/directory/v1/users/$USER_EMAIL" \
#   -d '{"suspended": true}'
log "[OK] Account suspended"

# step 2: revoke all OAuth tokens (third-party app access)
log "--- step 2: revoke OAuth tokens ---"
TOKENS=$(gam user "$USER_EMAIL" show tokens 2>/dev/null || echo "")
if [ -n "$TOKENS" ]; then
  gam user "$USER_EMAIL" deprovision 2>&1 | tee -a "$LOG_FILE"
  log "[OK] OAuth tokens revoked"
else
  log "[SKIP] No OAuth tokens found"
fi

# or via API:
# TOKEN_LIST=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
#   "https://admin.googleapis.com/admin/directory/v1/users/$USER_EMAIL/tokens")
# echo "$TOKEN_LIST" | jq -r '.items[]?.clientId' | while read client_id; do
#   if [ -n "$client_id" ] && [ "$client_id" != "null" ]; then
#     curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
#       "https://admin.googleapis.com/admin/directory/v1/users/$USER_EMAIL/tokens/$client_id"
#     log "[OK] Revoked token for client: $client_id"
#   fi
# done

# step 3: revoke app-specific passwords (if any — used for IMAP, etc.)
log "--- step 3: revoke app-specific passwords ---"
gam user "$USER_EMAIL" show asp 2>/dev/null | tee -a "$LOG_FILE"
gam user "$USER_EMAIL" delete asp 2>&1 | tee -a "$LOG_FILE" || log "[SKIP] No ASPs found"

# or via API:
# ASP_LIST=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
#   "https://admin.googleapis.com/admin/directory/v1/users/$USER_EMAIL/asps")
# echo "$ASP_LIST" | jq -r '.items[]?.codeId' | while read code_id; do
#   if [ -n "$code_id" ] && [ "$code_id" != "null" ]; then
#     curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
#       "https://admin.googleapis.com/admin/directory/v1/users/$USER_EMAIL/asps/$code_id"
#     log "[OK] Revoked ASP: $code_id"
#   fi
# done

# step 4: transfer Drive files to manager
log "--- step 4: transfer Drive files ---"
gam create datatransfer "$USER_EMAIL" gdrive "$MANAGER_EMAIL" privacy_level shared,private \
  2>&1 | tee -a "$LOG_FILE"
log "[OK] Drive transfer initiated to ${MANAGER_EMAIL}"

# or via API (Data Transfer API):
# TRANSFER=$(curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
#   -H "Content-Type: application/json" \
#   "https://admin.googleapis.com/admin/datatransfer/v1/transfers" \
#   -d "{
#     \"oldOwnerUserId\": \"$(gam info user $USER_EMAIL | grep 'User ID' | awk '{print $NF}')\",
#     \"newOwnerUserId\": \"$(gam info user $MANAGER_EMAIL | grep 'User ID' | awk '{print $NF}')\",
#     \"applicationDataTransfers\": [{
#       \"applicationId\": \"55656082996\",
#       \"applicationTransferParams\": [{
#         \"key\": \"PRIVACY_LEVEL\",
#         \"value\": [\"SHARED\", \"PRIVATE\"]
#       }]
#     }]
#   }")
# TRANSFER_ID=$(echo "$TRANSFER" | jq -r '.id')
# log "[OK] Drive transfer initiated: $TRANSFER_ID"

# step 5: remove from all groups
log "--- step 5: remove group memberships ---"
gam user "$USER_EMAIL" show groups | tee -a "$LOG_FILE"
gam user "$USER_EMAIL" delete groups 2>&1 | tee -a "$LOG_FILE"
log "[OK] Removed from all groups"

# or via API:
# GROUPS=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
#   "https://admin.googleapis.com/admin/directory/v1/groups?userKey=$USER_EMAIL&maxResults=200")
# echo "$GROUPS" | jq -r '.groups[]?.email' | while read group_email; do
#   curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
#     "https://admin.googleapis.com/admin/directory/v1/groups/$group_email/members/$USER_EMAIL"
#   log "[OK] Removed from group: $group_email"
# done

# step 6: wipe mobile devices
log "--- step 6: wipe mobile devices ---"
DEVICES=$(gam print mobile query "email:${USER_EMAIL}" fields resourceId,status 2>/dev/null || echo "")
if [ -n "$DEVICES" ]; then
  gam print mobile query "email:${USER_EMAIL}" fields resourceId \
    | awk -F, 'NR > 1 { print $1 }' | while read device_id; do
      gam update mobile "$device_id" action account_wipe
      log "[OK] Account wipe initiated for device: $device_id"
    done
else
  log "[SKIP] No mobile devices found"
fi

# or via API:
# MOBILE_DEVICES=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
#   "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile?query=email:$USER_EMAIL")
# echo "$MOBILE_DEVICES" | jq -r '.mobiledevices[]?.resourceId' | while read device_id; do
#   if [ -n "$device_id" ] && [ "$device_id" != "null" ]; then
#     curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
#       -H "Content-Type: application/json" \
#       "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile/$device_id/action" \
#       -d '{"action": "account_wipe"}'
#     log "[OK] Account wipe initiated for device: $device_id"
#   fi
# done

# step 7: set auto-reply on email (optional but professional)
log "--- step 7: set out-of-office auto-reply ---"
gam user "$USER_EMAIL" vacation on \
  subject "No longer at company" \
  message "This person is no longer with the organization. Please contact ${MANAGER_EMAIL} for assistance." \
  2>&1 | tee -a "$LOG_FILE"
log "[OK] Auto-reply set"

# summary
log ""
log "=== DEPROVISIONING COMPLETE ==="
log "User: ${USER_EMAIL}"
log "Suspended: yes"
log "Tokens revoked: yes"
log "Drive transferred to: ${MANAGER_EMAIL}"
log "Groups removed: yes"
log "Devices wiped: yes"
log "Auto-reply set: yes"
log "Completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Performed by: $(whoami)"
log ""
log "Save ${LOG_FILE} as audit evidence."
```

**deprovisioning SLA:**
- involuntary termination: **1 hour** (from HR notification to account suspension)
- voluntary termination: **end of last working day**
- the SLA matters because auditors check the delta between HR termination date and account suspension timestamp

**tier 3: weekly reconciliation script**

```bash
#!/bin/bash
# gw-deprovision-reconciliation.sh — run weekly via cron
# compares HR terminated list with active Google Workspace accounts
# cron: 0 9 * * 1 /opt/scripts/gw-deprovision-reconciliation.sh

set -euo pipefail

ALERT_EMAIL="{{SECURITY_LEAD_EMAIL}}"
DATE=$(date +%Y-%m-%d)
REPORT_FILE="evidence/gw-reconciliation-${DATE}.md"

echo "# Google Workspace Deprovisioning Reconciliation Report" > "$REPORT_FILE"
echo "**Date:** ${DATE}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# get active Google Workspace users
GWS_ACTIVE=$(gam print users query "isSuspended=false" fields primaryEmail \
  | awk -F, 'NR > 1 { print tolower($1) }')

# get HR active employee list
# replace with your HR system API call:
# HR_ACTIVE=$(curl -s -H "Authorization: Bearer ${HR_TOKEN}" \
#   "https://api.yourhrsystem.com/employees?status=active" \
#   | jq -r '.[].email' | tr '[:upper:]' '[:lower:]')

# compare: find GWS users NOT in the HR active list
echo "## Users in Google Workspace but NOT in HR system" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
ORPHAN_COUNT=0
for gws_email in $GWS_ACTIVE; do
  if ! echo "$HR_ACTIVE" | grep -qi "^${gws_email}$"; then
    echo "- ALERT: ${gws_email} — active in GWS, not found in HR active list" >> "$REPORT_FILE"
    ORPHAN_COUNT=$((ORPHAN_COUNT + 1))
  fi
done

echo "" >> "$REPORT_FILE"
echo "## Summary" >> "$REPORT_FILE"
echo "- Active GWS users: $(echo "$GWS_ACTIVE" | wc -l | tr -d ' ')" >> "$REPORT_FILE"
echo "- Active HR employees: $(echo "$HR_ACTIVE" | wc -l | tr -d ' ')" >> "$REPORT_FILE"
echo "- Orphaned accounts found: ${ORPHAN_COUNT}" >> "$REPORT_FILE"

if [ "$ORPHAN_COUNT" -gt 0 ]; then
  echo "" >> "$REPORT_FILE"
  echo "**ACTION REQUIRED:** investigate orphaned accounts above." >> "$REPORT_FILE"
  # send alert
  # echo "Orphaned GWS accounts found: ${ORPHAN_COUNT}. See ${REPORT_FILE}" \
  #   | mail -s "GWS Reconciliation Alert" "$ALERT_EMAIL"
fi

echo "report saved: ${REPORT_FILE}"
```

### VERIFY

```bash
# after running deprovisioning, verify the user is fully disabled:

# --- via GAM ---
gam info user user@yourdomain.com | grep -E "suspended|lastLogin|Admin"
# expected: Account Suspended: true

# check token revocation
gam user user@yourdomain.com show tokens
# expected: no tokens

# check group removal
gam user user@yourdomain.com show groups
# expected: no groups

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users/user@yourdomain.com?projection=full" \
  | jq '{
    email: .primaryEmail,
    suspended: .suspended,
    suspension_reason: .suspensionReason,
    last_login: .lastLoginTime
  }'
# expected: suspended: true

# verify no remaining tokens
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users/user@yourdomain.com/tokens" \
  | jq '.items // [] | length'
# expected: 0
```

### EVIDENCE

```bash
# save deprovisioning evidence for audit
# the offboard-gws.sh script already creates a log file per user.
# additionally, export system-level evidence:

# all suspension events in the audit period
gam report admin event_name=SUSPEND_USER \
  start_date {{AUDIT_PERIOD_START}} \
  > evidence/gw-suspension-events-$(date +%Y-%m-%d).csv

# via API
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?eventName=SUSPEND_USER&startTime={{AUDIT_PERIOD_START}}T00:00:00Z&maxResults=1000" \
  | jq '[.items[] | {
    actor: .actor.email,
    target_user: (.events[0].parameters[]? | select(.name == "USER_EMAIL") | .value),
    time: .id.time,
    ip: .ipAddress
  }]' > evidence/gw-suspension-events-$(date +%Y-%m-%d).json

# data transfer events
gam report admin event_name=TRANSFER_DATA_INITIATED \
  start_date {{AUDIT_PERIOD_START}} \
  > evidence/gw-data-transfers-$(date +%Y-%m-%d).csv

# reconciliation reports (saved by the weekly script)
# evidence/gw-reconciliation-*.md
```

---

## 3-gws.6 group-based access management

group-based access is how you grant and revoke access at scale. access should always flow through groups, not direct user permissions. auditors verify that access is managed via groups because it makes access reviews tractable.

### DISCOVER

```bash
# --- via GAM ---
# list all groups with member counts
gam print groups fields email,name,directMembersCount,description

# list members of a specific group
gam print group-members group engineering@yourdomain.com \
  fields email,role,type

# list all groups and all members (full export)
gam print group-members > /tmp/gw-all-group-members.csv

# --- via API ---
# list all groups
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups?customer=$CUSTOMER_ID&maxResults=200" \
  | jq '[.groups[] | {
    email: .email,
    name: .name,
    member_count: .directMembersCount,
    description: .description
  }]'

# list members of a specific group
GROUP_EMAIL="engineering@yourdomain.com"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups/$GROUP_EMAIL/members?maxResults=200" \
  | jq '[.members[] | {
    email: .email,
    role: .role,
    type: .type,
    status: .status
  }]'

# find groups with external members (potential security risk)
gam print group-members | awk -F, -v domain="yourdomain.com" \
  'NR > 1 && $1 !~ domain { print "EXTERNAL MEMBER:", $0 }'
```

### FIX

```bash
# add user to a group
# --- via GAM ---
gam update group engineering@yourdomain.com add member user@yourdomain.com

# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/groups/engineering@yourdomain.com/members" \
  -d '{
    "email": "user@yourdomain.com",
    "role": "MEMBER"
  }'

# remove user from a group
# --- via GAM ---
gam update group engineering@yourdomain.com remove member user@yourdomain.com

# --- via API ---
curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups/engineering@yourdomain.com/members/user@yourdomain.com"

# create a new group (for role-based access)
# --- via GAM ---
gam create group security-team@yourdomain.com \
  name "Security Team" \
  description "Security team members — grants access to security tools"

# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/groups" \
  -d '{
    "email": "security-team@yourdomain.com",
    "name": "Security Team",
    "description": "Security team members — grants access to security tools"
  }'
```

### VERIFY

```bash
# verify group membership matches expected state
# --- via GAM ---
gam print group-members group engineering@yourdomain.com fields email,role \
  | sort

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups/engineering@yourdomain.com/members?maxResults=200" \
  | jq '[.members[] | {email: .email, role: .role}] | sort_by(.email)'

# check for empty groups (may indicate misconfiguration)
gam print groups fields email,directMembersCount \
  | awk -F, 'NR > 1 && $NF == "0" { print "EMPTY GROUP:", $1 }'
```

### EVIDENCE

```bash
# full group membership export
gam print groups fields email,name,directMembersCount \
  > evidence/gw-groups-$(date +%Y-%m-%d).csv

gam print group-members fields email,role,type \
  > evidence/gw-group-memberships-$(date +%Y-%m-%d).csv

# via API (all groups with members)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/groups?customer=$CUSTOMER_ID&maxResults=200" \
  | jq -r '.groups[].email' | while read group_email; do
    members=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
      "https://admin.googleapis.com/admin/directory/v1/groups/$group_email/members?maxResults=200" \
      | jq '[.members[]? | {email: .email, role: .role}]')
    echo "{\"group\": \"$group_email\", \"members\": $members}"
  done | jq -s '.' > evidence/gw-group-memberships-$(date +%Y-%m-%d).json
```

---

## 3-gws.7 admin roles audit

admin accounts have unrestricted access to all organizational data and settings. the number of super admins should be minimal (2-3 for redundancy, never 1, never more than 5). auditors specifically check this.

### DISCOVER

```bash
# --- via GAM ---
# list all admin users
gam print admins

# list super admins specifically
gam print users query "isAdmin=true" fields primaryEmail,isAdmin,isDelegatedAdmin,lastLoginTime

# list delegated admins (users with partial admin roles)
gam print users query "isDelegatedAdmin=true" fields primaryEmail,isDelegatedAdmin,lastLoginTime

# --- via API ---
# super admins
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isAdmin=true&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    is_super_admin: .isAdmin,
    is_delegated_admin: .isDelegatedAdmin,
    last_login: .lastLoginTime,
    created: .creationTime,
    enrolled_2sv: .isEnrolledIn2Sv
  }]'

# list all admin role assignments
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roleassignments?maxResults=200" \
  | jq '[.items[] | {
    role_id: .roleId,
    assigned_to: .assignedTo,
    scope_type: .scopeType,
    org_unit_id: .orgUnitId
  }]'

# list all defined admin roles (built-in + custom)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roles?maxResults=100" \
  | jq '[.items[] | {
    role_id: .roleId,
    role_name: .roleName,
    is_system_role: .isSystemRole,
    is_super_admin_role: .isSuperAdminRole,
    privileges: [.rolePrivileges[]? | .privilegeName] | length
  }]'

# cross-reference: get human-readable admin role assignments
ROLES=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roles?maxResults=100")
ASSIGNMENTS=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roleassignments?maxResults=200")

echo "$ASSIGNMENTS" | jq -r '.items[]? | "\(.assignedTo) \(.roleId)"' | while read user_id role_id; do
  role_name=$(echo "$ROLES" | jq -r --arg rid "$role_id" '.items[]? | select(.roleId == $rid) | .roleName')
  user_email=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://admin.googleapis.com/admin/directory/v1/users/$user_id" | jq -r '.primaryEmail')
  echo "{\"email\": \"$user_email\", \"role\": \"$role_name\"}"
done | jq -s '.'
```

### FIX

```bash
# remove unnecessary admin access
# --- via GAM ---
gam update user user@yourdomain.com admin off

# --- via API ---
# to remove a role assignment, you need the roleAssignmentId:
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roleassignments?maxResults=200" \
  | jq '.items[] | select(.assignedTo == "USER_ID_HERE") | .roleAssignmentId'

# then delete it:
# curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
#   "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roleassignments/ROLE_ASSIGNMENT_ID"

# best practices:
# - 2-3 super admins maximum (CTO, security lead, + 1 backup)
# - all admins MUST have 2SV enrolled with security keys (not just TOTP)
# - use delegated admin roles for specific tasks instead of super admin
# - create custom roles with least-privilege scoping

# create a custom admin role with limited privileges:
# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roles" \
  -d '{
    "roleName": "User Manager",
    "roleDescription": "Can manage user accounts but not org settings",
    "rolePrivileges": [
      {"privilegeName": "USERS_RETRIEVE", "serviceId": "00haapch16h1ysv"},
      {"privilegeName": "USERS_UPDATE", "serviceId": "00haapch16h1ysv"}
    ]
  }'
```

### VERIFY

```bash
# re-check admin list after cleanup
# --- via GAM ---
gam print users query "isAdmin=true" fields primaryEmail,isAdmin,isEnrolledIn2Sv
# expected: 2-3 super admins, all with 2SV enrolled

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isAdmin=true&maxResults=500" \
  | jq '{
    super_admin_count: [.users[] | select(.isAdmin == true)] | length,
    super_admins: [.users[] | select(.isAdmin == true) | {
      email: .primaryEmail,
      has_2sv: .isEnrolledIn2Sv
    }]
  }'
# expected:
# {
#   "super_admin_count": 2,
#   "super_admins": [
#     {"email": "cto@yourdomain.com", "has_2sv": true},
#     {"email": "security@yourdomain.com", "has_2sv": true}
#   ]
# }

# verify ALL admins have 2SV (this is a hard requirement)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isAdmin=true&maxResults=500" \
  | jq '[.users[] | select(.isEnrolledIn2Sv == false) | .primaryEmail]'
# expected: [] (empty — all admins have 2SV)
# any non-empty result is a CRITICAL finding
```

### EVIDENCE

```bash
gam print admins > evidence/gw-admins-$(date +%Y-%m-%d).csv

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users?customer=$CUSTOMER_ID&query=isAdmin=true&maxResults=500" \
  | jq '[.users[] | {
    email: .primaryEmail,
    is_super_admin: .isAdmin,
    is_delegated_admin: .isDelegatedAdmin,
    enrolled_2sv: .isEnrolledIn2Sv,
    last_login: .lastLoginTime,
    created: .creationTime
  }]' > evidence/gw-admins-$(date +%Y-%m-%d).json

# role assignments
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/roleassignments?maxResults=200" \
  > evidence/gw-role-assignments-$(date +%Y-%m-%d).json
```

---

## 3-gws.8 OAuth app access control

third-party OAuth apps that users have authorized can access Google data (email, drive, calendar). uncontrolled OAuth grants are a major data exfiltration risk. auditors check that you inventory and control which apps can access organizational data.

### DISCOVER

```bash
# --- via GAM ---
# list all OAuth tokens (apps that users have authorized)
gam all users show tokens > /tmp/gw-oauth-tokens.csv

# or for a specific user
gam user user@yourdomain.com show tokens

# --- via API ---
# list tokens for a specific user
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users/user@yourdomain.com/tokens" \
  | jq '[.items[]? | {
    client_id: .clientId,
    display_text: .displayText,
    scopes: .scopes,
    native_app: .nativeApp,
    user_key: .userKey
  }]'

# to get all users' tokens (audit entire organization):
gam print users fields primaryEmail query "isSuspended=false" \
  | awk -F, 'NR > 1 { print $1 }' | while read user_email; do
    tokens=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
      "https://admin.googleapis.com/admin/directory/v1/users/$user_email/tokens" \
      | jq '[.items[]? | {client_id: .clientId, display_text: .displayText, scopes: .scopes}]')
    if [ "$(echo "$tokens" | jq 'length')" -gt 0 ]; then
      echo "{\"user\": \"$user_email\", \"tokens\": $tokens}"
    fi
  done | jq -s '.'

# look for high-risk OAuth scopes (these apps can read all email or drive files):
# risky scopes:
#   https://mail.google.com/ (full email access)
#   https://www.googleapis.com/auth/drive (full drive access)
#   https://www.googleapis.com/auth/gmail.readonly (read all email)
```

### FIX

> **OAuth app control is configured in Admin Console:**
>
> 1. go to https://admin.google.com > Security > Access and data control > API controls
> 2. under "App access control":
>    - set default access: **"Don't allow users to access any third-party apps"** (restrictive)
>    - or: **"Allow users to access only trusted apps"** (moderate)
> 3. under "Manage third-party app access":
>    - review the list of authorized apps
>    - mark known business apps as "Trusted" (e.g., Slack, Zoom, Salesforce)
>    - mark unknown or risky apps as "Blocked"
> 4. enable "Force users to get admin approval before accessing new third-party apps"

```bash
# revoke a specific OAuth token for a user
# --- via GAM ---
gam user user@yourdomain.com delete token clientid "CLIENT_ID_HERE"

# --- via API ---
curl -s -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/users/user@yourdomain.com/tokens/CLIENT_ID_HERE"

# bulk revoke all tokens for a user (during offboarding)
gam user user@yourdomain.com deprovision
```

### VERIFY

```bash
# verify app access policy is restrictive
# check via Admin Console: Security > API controls > App access control
# take a screenshot showing the policy is set to restricted/trusted-only

# verify no unauthorized high-risk tokens remain
gam all users show tokens \
  | grep -iE "mail\.google\.com|auth/drive[^.]|gmail\.readonly" \
  | sort -u
# expected: only known, trusted apps should appear
```

### EVIDENCE

```bash
gam all users show tokens > evidence/gw-oauth-tokens-$(date +%Y-%m-%d).csv

# also save Admin Console screenshot:
# evidence/gw-oauth-policy-screenshot-$(date +%Y-%m-%d).png
```

---

## 3-gws.9 audit log export (Reports API)

Google Workspace audit logs record all admin actions, user logins, drive activity, and OAuth grants. these logs are critical for incident investigation and SOC 2 evidence. Google retains audit logs for 6 months — you must export them for long-term retention.

### DISCOVER

```bash
# --- via GAM ---
# login activity
gam report login start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -20

# admin activity
gam report admin start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -20

# token activity (OAuth grants and revocations)
gam report token start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -20

# drive activity
gam report drive start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -20

# --- via API (Reports API) ---
# available applications: admin, login, drive, token, groups_enterprise,
#   calendar, gcp, chat, meet, rules, user_accounts

SEVEN_DAYS_AGO=$(date -v-7d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "7 days ago" +%Y-%m-%dT00:00:00.000Z)

# login events
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$SEVEN_DAYS_AGO&maxResults=10" \
  | jq '[.items[:5] | .[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    ip: .ipAddress,
    login_type: (.events[0].parameters[]? | select(.name == "login_type") | .value)
  }]'

# admin events
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?startTime=$SEVEN_DAYS_AGO&maxResults=10" \
  | jq '[.items[:5] | .[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    parameters: [.events[0].parameters[]? | {name: .name, value: (.value // .intValue // .boolValue)}]
  }]'

# token events (OAuth grants/revocations)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?startTime=$SEVEN_DAYS_AGO&maxResults=10" \
  | jq '[.items[:5] | .[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    app_name: (.events[0].parameters[]? | select(.name == "app_name") | .value),
    scopes: (.events[0].parameters[]? | select(.name == "scope") | .multiValue)
  }]'

# check for suspicious login events (failed logins, logins from new locations)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$SEVEN_DAYS_AGO&eventName=login_failure&maxResults=100" \
  | jq '[.items[]? | {
    user: .actor.email,
    time: .id.time,
    ip: .ipAddress,
    failure_reason: (.events[0].parameters[]? | select(.name == "login_failure_type") | .value)
  }]'
```

### FIX

```bash
# Google Workspace admin audit logging is always on — you cannot disable it.
# the fix is ensuring logs are exported for long-term retention (>= 1 year for SOC 2).

# option 1: BigQuery export (built-in, recommended)
# go to admin.google.com > Account > Account settings > Legal and compliance > Sharing options
# enable "Google Workspace data export to BigQuery"
# this streams all audit logs to a BigQuery dataset in real-time.
# BigQuery retains data indefinitely (subject to your table expiration settings).

# option 2: daily export via API to your SIEM or S3
#!/bin/bash
# gw-audit-export.sh — run daily via cron
# cron: 0 3 * * * /opt/scripts/gw-audit-export.sh

OUTPUT_DIR="/var/log/gw-audit"
mkdir -p "$OUTPUT_DIR"
YESTERDAY=$(date -v-1d +%Y-%m-%d 2>/dev/null || date -d "yesterday" +%Y-%m-%d)

for app in admin login drive token groups_enterprise user_accounts; do
  echo "exporting ${app} logs for ${YESTERDAY}..."
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/${app}?startTime=${YESTERDAY}T00:00:00Z&endTime=${YESTERDAY}T23:59:59Z&maxResults=1000" \
    > "${OUTPUT_DIR}/${app}-${YESTERDAY}.json"

  count=$(jq '.items | length // 0' "${OUTPUT_DIR}/${app}-${YESTERDAY}.json" 2>/dev/null || echo 0)
  echo "  exported ${count} events"
done

# ship to SIEM or S3
# aws s3 sync "$OUTPUT_DIR" "s3://{{COMPANY}}-audit-logs/google-workspace/"
# or: send to Splunk via HEC, Datadog, etc.
```

### VERIFY

```bash
# confirm logs are flowing and recent
# --- via GAM ---
gam report admin event_name=CREATE_USER | head -5
# expected: recent user creation events (or other admin events)

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?maxResults=1" \
  | jq '.items[0].id.time'
# expected: recent timestamp (within last 24 hours)

# verify BigQuery export (if using option 1):
# bq query --use_legacy_sql=false \
#   'SELECT COUNT(*) as event_count, DATE(id.time) as day
#    FROM `project.dataset.activity`
#    WHERE DATE(id.time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
#    GROUP BY day ORDER BY day DESC'
```

### EVIDENCE

```bash
# export audit logs for the audit period
gam report admin start_date {{AUDIT_PERIOD_START}} end_date {{AUDIT_PERIOD_END}} \
  > evidence/gw-admin-audit-$(date +%Y-%m-%d).csv

gam report login start_date {{AUDIT_PERIOD_START}} end_date {{AUDIT_PERIOD_END}} \
  > evidence/gw-login-audit-$(date +%Y-%m-%d).csv

# via API (sample — auditors typically want a sample, not the full dataset)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime={{AUDIT_PERIOD_START}}T00:00:00Z&maxResults=100" \
  | jq '[.items[] | {
    user: .actor.email,
    time: .id.time,
    event: .events[0].name,
    ip: .ipAddress
  }]' > evidence/gw-login-sample-$(date +%Y-%m-%d).json

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?startTime={{AUDIT_PERIOD_START}}T00:00:00Z&maxResults=100" \
  | jq '[.items[] | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name
  }]' > evidence/gw-admin-sample-$(date +%Y-%m-%d).json
```

---

## 3-gws.10 mobile device management

mobile devices accessing corporate Google data must be managed. unmanaged devices are a data leakage vector — if an employee's phone is lost or stolen, corporate email and drive data are exposed.

### DISCOVER

```bash
# --- via GAM ---
gam print mobile fields email,os,type,status,deviceId,model,serialNumber,lastSync

# count by status
gam print mobile fields status | awk -F, 'NR > 1 { count[$1]++ } END { for (s in count) print s, count[s] }'

# find devices not synced in 30+ days (stale)
gam print mobile fields email,lastSync,status \
  | awk -F, -v cutoff="$(date -v-30d +%Y-%m-%d 2>/dev/null || date -d '30 days ago' +%Y-%m-%d)" \
    'NR > 1 && $2 < cutoff { print "STALE:", $0 }'

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile?maxResults=100" \
  | jq '[.mobiledevices[]? | {
    email: .email[0],
    os: .os,
    type: .type,
    model: .model,
    status: .status,
    device_id: .deviceId,
    last_sync: .lastSync,
    serial_number: .serialNumber,
    encryption_status: .encryptionStatus,
    device_compromised: .deviceCompromisedStatus
  }]'

# find compromised or unencrypted devices
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile?maxResults=100" \
  | jq '[.mobiledevices[]? | select(
    .deviceCompromisedStatus == "COMPROMISED" or
    .encryptionStatus == "UNENCRYPTED"
  ) | {
    email: .email[0],
    device_id: .deviceId,
    compromised: .deviceCompromisedStatus,
    encrypted: .encryptionStatus
  }]'
# expected: [] (no compromised or unencrypted devices)
```

### FIX

> **MDM settings are configured via Admin Console:**
>
> 1. go to https://admin.google.com > Devices > Mobile & endpoints > Settings > Universal
> 2. enable **Advanced mobile management** (requires Business Plus or Enterprise)
> 3. under Mobile management:
>    - require device approval before accessing corporate data
>    - require screen lock with PIN/password
>    - require device encryption
>    - enable remote account wipe
> 4. under App management:
>    - push required apps (e.g., company authenticator)
>    - block unapproved apps from accessing corporate data
> 5. enable **Endpoint Verification** for desktop devices:
>    - Devices > Mobile & endpoints > Settings > Endpoint Verification
>    - this installs a Chrome extension that reports device security posture

```bash
# approve a pending device
# --- via GAM ---
gam update mobile DEVICE_RESOURCE_ID action approve

# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile/DEVICE_RESOURCE_ID/action" \
  -d '{"action": "approve"}'

# wipe a device (during offboarding or if lost/stolen)
# account_wipe: removes only corporate data
# wipe: full device wipe (use for company-owned devices only)

# --- via GAM ---
gam update mobile DEVICE_RESOURCE_ID action account_wipe

# --- via API ---
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile/DEVICE_RESOURCE_ID/action" \
  -d '{"action": "account_wipe"}'
```

### VERIFY

```bash
# re-check device inventory after policy enforcement
# --- via GAM ---
gam print mobile fields email,status,encryptionStatus | grep -v "APPROVED"
# expected: no unapproved devices (or only recently enrolled pending approval)

# --- via API ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile?maxResults=100" \
  | jq '{
    total_devices: (.mobiledevices | length),
    approved: [.mobiledevices[]? | select(.status == "APPROVED")] | length,
    pending: [.mobiledevices[]? | select(.status == "PENDING")] | length,
    compromised: [.mobiledevices[]? | select(.deviceCompromisedStatus == "COMPROMISED")] | length,
    unencrypted: [.mobiledevices[]? | select(.encryptionStatus == "UNENCRYPTED")] | length
  }'
# expected: compromised=0, unencrypted=0
```

### EVIDENCE

```bash
gam print mobile fields email,os,type,status,model,serialNumber,lastSync,encryptionStatus,deviceCompromisedStatus \
  > evidence/gw-mobile-devices-$(date +%Y-%m-%d).csv

curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/directory/v1/customer/$CUSTOMER_ID/devices/mobile?maxResults=500" \
  | jq '[.mobiledevices[]? | {
    email: .email[0],
    os: .os,
    type: .type,
    model: .model,
    status: .status,
    last_sync: .lastSync,
    encrypted: .encryptionStatus,
    compromised: .deviceCompromisedStatus
  }]' > evidence/gw-mobile-devices-$(date +%Y-%m-%d).json
```

---

## 3-gws.11 context-aware access

context-aware access (CAA) restricts access to Google services based on device security posture, network location, and other signals. it is the Google Workspace equivalent of conditional access in Azure AD / Entra ID.

> **requires:** Google Workspace Enterprise Standard/Plus, or BeyondCorp Enterprise

### DISCOVER

```bash
# context-aware access is configured via Admin Console and managed through
# the Access Context Manager API (part of BeyondCorp).

# check if any access levels are defined:
# go to admin.google.com > Security > Access and data control > Context-aware access

# via gcloud (Access Context Manager API):
# list access policies
gcloud access-context-manager policies list

# list access levels within a policy
# gcloud access-context-manager levels list --policy=POLICY_ID

# note: the Access Context Manager API requires Google Cloud organization-level
# permissions and is separate from the Admin SDK.
```

### FIX

> **configure in Admin Console:**
>
> 1. go to https://admin.google.com > Security > Access and data control > Context-aware access
> 2. create access levels based on:
>    - device encryption status: must be encrypted
>    - OS version: minimum OS version (e.g., macOS 14+, Windows 11+, ChromeOS latest-1)
>    - endpoint verification: device must have endpoint verification extension
>    - network: restrict to corporate VPN or known IP ranges (optional)
>    - device management: device must be company-managed
> 3. assign access levels to apps:
>    - Gmail: require encrypted + endpoint verified
>    - Drive: require encrypted + endpoint verified
>    - Admin Console: require managed device + corporate network
> 4. set monitoring mode first (logs violations but does not block) for 2 weeks
> 5. switch to enforcement mode after confirming no false positives
>
> **note:** context-aware access only works for apps that users access through their browser or mobile apps. it does not affect API access via service accounts.

### VERIFY

> take a screenshot of the Admin Console context-aware access page showing:
> - defined access levels and their conditions
> - app-to-access-level assignments
> - enforcement mode (not just monitoring)

### EVIDENCE

```bash
# export access level definitions via gcloud:
# gcloud access-context-manager levels list --policy=POLICY_ID --format=json \
#   > evidence/gw-caa-access-levels-$(date +%Y-%m-%d).json

# save Admin Console screenshots:
# evidence/gw-context-aware-access-screenshot-$(date +%Y-%m-%d).png

# check access denial events in audit logs:
# (context-aware access denials appear in the login audit log)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=$SEVEN_DAYS_AGO&eventName=login_failure&maxResults=100" \
  | jq '[.items[]? | select(
    .events[0].parameters[]? | select(.name == "login_failure_type") | .value == "login_challenge_method"
  ) | {
    user: .actor.email,
    time: .id.time,
    ip: .ipAddress
  }]' > evidence/gw-caa-denials-$(date +%Y-%m-%d).json
```

---

## 3-gws.12 data loss prevention (DLP)

DLP rules detect and block sensitive data (SSN, credit card numbers, API keys) from being shared externally via Gmail or Drive.

> **requires:** Google Workspace Enterprise Standard/Plus

### DISCOVER

```bash
# DLP rules are configured via Admin Console.
# there is no public REST API to read DLP rule configurations directly.

# check via Admin Console:
# admin.google.com > Security > Access and data control > Data protection
# review existing rules, their conditions, and actions

# check DLP violation events in the Rules audit log:
# --- via GAM ---
gam report rules start_date $(date -v-30d +%Y-%m-%d 2>/dev/null || date -d "30 days ago" +%Y-%m-%d)

# --- via API ---
THIRTY_DAYS_AGO=$(date -v-30d +%Y-%m-%dT00:00:00.000Z 2>/dev/null || date -d "30 days ago" +%Y-%m-%dT00:00:00.000Z)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules?startTime=$THIRTY_DAYS_AGO&maxResults=100" \
  | jq '[.items[]? | {
    actor: .actor.email,
    time: .id.time,
    event: .events[0].name,
    rule_name: (.events[0].parameters[]? | select(.name == "rule_name") | .value),
    triggered_action: (.events[0].parameters[]? | select(.name == "triggered_actions") | .value)
  }]'
```

### FIX

> **configure DLP rules in Admin Console:**
>
> 1. go to https://admin.google.com > Security > Access and data control > Data protection
> 2. click "Manage Rules" > "Add Rule"
> 3. create rules for:
>    - **SSN detection:** condition = "US Social Security Number", action = block external sharing + alert admin
>    - **credit card detection:** condition = "Credit Card Number", action = block external sharing + alert admin
>    - **API key/secret detection:** condition = custom regex patterns for common key formats, action = warn user + alert admin
>    - **source code protection:** condition = file type is code (.py, .js, .go, etc.), action = warn when sharing externally
> 4. for each rule:
>    - scope: all users or specific OUs
>    - triggers: Gmail (outbound), Drive (external sharing)
>    - actions: warn, block, quarantine, alert admin
> 5. start with "warn" mode (shows users a warning but allows the action) for 2 weeks
> 6. switch to "block" mode after confirming rules are accurate

### VERIFY

> take a screenshot of the Admin Console DLP rules page showing all configured rules, their conditions, and actions.

```bash
# verify DLP is triggering by checking the rules audit log:
gam report rules start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d) \
  | head -10
# if DLP rules are working, you should see events when sensitive content is detected
```

### EVIDENCE

```bash
# DLP rule trigger events
gam report rules start_date {{AUDIT_PERIOD_START}} end_date {{AUDIT_PERIOD_END}} \
  > evidence/gw-dlp-events-$(date +%Y-%m-%d).csv

# Admin Console screenshot of DLP rule configuration:
# evidence/gw-dlp-rules-screenshot-$(date +%Y-%m-%d).png

# summary statistics via API
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules?startTime={{AUDIT_PERIOD_START}}T00:00:00Z&maxResults=1000" \
  | jq '{
    total_events: (.items | length),
    by_rule: [.items[]? | (.events[0].parameters[]? | select(.name == "rule_name") | .value)] | group_by(.) | map({rule: .[0], count: length})
  }' > evidence/gw-dlp-summary-$(date +%Y-%m-%d).json
```

---

## 3-gws.13 Alert Center

the Alert Center aggregates security alerts from across Google Workspace — suspicious login attempts, government-backed attacks, device compromises, DLP violations, and more. auditors want to see that you monitor and respond to security alerts.

### DISCOVER

```bash
# --- via API (Alert Center API) ---
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=20" \
  | jq '[.alerts[]? | {
    alert_id: .alertId,
    type: .type,
    source: .source,
    create_time: .createTime,
    start_time: .startTime,
    status: .metadata.status,
    severity: .metadata.severity,
    customer_id: .customerId
  }]'

# filter by type (common alert types):
# - "Google identity"          — suspicious login, leaked password
# - "Gmail phishing"           — phishing email detected
# - "Device compromised"       — device rooted/jailbroken
# - "Government backed attack" — state-sponsored attack targeting your users
# - "Suspicious login"         — login from unusual location
# - "User reported phishing"   — user reported email as phishing

# get alert details
ALERT_ID="your-alert-id-here"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://alertcenter.googleapis.com/v1beta1/alerts/$ALERT_ID" \
  | jq '{
    type: .type,
    source: .source,
    create_time: .createTime,
    status: .metadata.status,
    data: .data
  }'

# list unresolved alerts
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://alertcenter.googleapis.com/v1beta1/alerts?filter=status%3D%22NOT_STARTED%22&pageSize=50" \
  | jq '[.alerts[]? | {
    type: .type,
    create_time: .createTime,
    severity: .metadata.severity
  }]'
```

### FIX

> **configure alert notification rules:**
>
> 1. go to https://admin.google.com > Security > Alert center
> 2. click "Settings" (gear icon)
> 3. for each alert type, configure:
>    - email notification to security team distribution list
>    - integration with your incident management tool (PagerDuty, Opsgenie, etc.)
>
> **for automated response:**

```bash
# mark an alert as acknowledged
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://alertcenter.googleapis.com/v1beta1/alerts/$ALERT_ID/feedback" \
  -d '{"type": "ALERT_FEEDBACK_TYPE_USEFUL", "alertId": "'"$ALERT_ID"'"}'

# update alert metadata (mark as in progress)
curl -s -X PATCH -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://alertcenter.googleapis.com/v1beta1/alerts/$ALERT_ID/metadata" \
  -d '{"status": "IN_PROGRESS"}'
```

### VERIFY

```bash
# verify alerts are flowing and being processed
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=5" \
  | jq '{
    total_alerts: (.alerts | length),
    unresolved: [.alerts[]? | select(.metadata.status != "CLOSED")] | length,
    most_recent: .alerts[0]?.createTime
  }'
# expected: most_recent should be recent, unresolved should not be accumulating
```

### EVIDENCE

```bash
# export all alerts for the audit period
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=200" \
  | jq '[.alerts[]? | {
    type: .type,
    source: .source,
    create_time: .createTime,
    status: .metadata.status,
    severity: .metadata.severity
  }]' > evidence/gw-alerts-$(date +%Y-%m-%d).json

# alert center screenshot:
# evidence/gw-alert-center-screenshot-$(date +%Y-%m-%d).png
```

---

## quarterly access review script (Google Workspace)

this script generates a complete quarterly access review report. run it at the start of each quarter.

```bash
#!/bin/bash
# gw-quarterly-access-review.sh
# generates a markdown evidence report for SOC 2 quarterly access review.
# usage: ./gw-quarterly-access-review.sh 2026 Q2

set -euo pipefail

YEAR="${1:-$(date +%Y)}"
QUARTER="${2:-Q$(( ($(date +%-m) - 1) / 3 + 1 ))}"
DATE=$(date +%Y-%m-%d)
REPORT_FILE="evidence/access-review-gws-${YEAR}-${QUARTER}.md"
EVIDENCE_DIR="evidence"

mkdir -p "$EVIDENCE_DIR"

echo "generating Google Workspace access review for ${YEAR} ${QUARTER}..."

# --- header ---
cat > "$REPORT_FILE" << EOF
# Google Workspace Access Review — ${YEAR} ${QUARTER}

**Generated:** ${DATE}
**Reviewer:** $(whoami)
**Tool:** GAM + Admin SDK API

---

EOF

# --- 1. all active users with 2SV status ---
echo "## 1. Active Users with 2SV Status" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

gam print users fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,orgUnitPath,isAdmin \
  query "isSuspended=false" \
  | tee "${EVIDENCE_DIR}/gw-active-users-${DATE}.csv" \
  >> "$REPORT_FILE"

echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

TOTAL_USERS=$(gam print users query "isSuspended=false" fields primaryEmail | awk 'NR > 1' | wc -l | tr -d ' ')
echo "**Total active users:** ${TOTAL_USERS}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- 2. all groups and memberships ---
echo "## 2. Groups and Memberships" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

gam print groups fields email,name,directMembersCount \
  | tee "${EVIDENCE_DIR}/gw-groups-${DATE}.csv" \
  >> "$REPORT_FILE"

echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "### Group Membership Details" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

gam print group-members fields email,role,type \
  | tee "${EVIDENCE_DIR}/gw-group-memberships-${DATE}.csv" \
  >> "$REPORT_FILE"

echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- 3. all admin users ---
echo "## 3. Admin Users" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

gam print users query "isAdmin=true" \
  fields primaryEmail,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,lastLoginTime \
  | tee "${EVIDENCE_DIR}/gw-admins-${DATE}.csv" \
  >> "$REPORT_FILE"

echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

ADMIN_COUNT=$(gam print users query "isAdmin=true" fields primaryEmail | awk 'NR > 1' | wc -l | tr -d ' ')
echo "**Total admin users:** ${ADMIN_COUNT}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- 4. stale accounts (no login in 90+ days) ---
echo "## 4. Stale Accounts (No Login in 90+ Days)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

CUTOFF_DATE=$(date -v-90d +%Y-%m-%d 2>/dev/null || date -d "90 days ago" +%Y-%m-%d)

STALE_ACCOUNTS=$(gam print users fields primaryEmail,lastLoginTime,creationTime,orgUnitPath \
  query "isSuspended=false" \
  | awk -F, -v cutoff="$CUTOFF_DATE" \
    'NR > 1 && ($2 == "" || $2 < cutoff)')

if [ -n "$STALE_ACCOUNTS" ]; then
  STALE_COUNT=$(echo "$STALE_ACCOUNTS" | wc -l | tr -d ' ')
  echo "**FINDING:** ${STALE_COUNT} stale account(s) detected:" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "$STALE_ACCOUNTS" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "**Remediation:** investigate and suspend if no longer needed." >> "$REPORT_FILE"
else
  echo "No stale accounts found. All active users have logged in within the past 90 days." >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# --- 5. users without 2SV ---
echo "## 5. Users Without 2-Step Verification" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

NO_2SV=$(gam print users fields primaryEmail,isEnrolledIn2Sv \
  query "isSuspended=false" \
  | awk -F, 'NR > 1 && $NF == "False"')

if [ -n "$NO_2SV" ]; then
  NO_2SV_COUNT=$(echo "$NO_2SV" | wc -l | tr -d ' ')
  echo "**FINDING:** ${NO_2SV_COUNT} user(s) without 2SV:" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "$NO_2SV" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "**Remediation:** enforce 2SV immediately for these users." >> "$REPORT_FILE"
else
  echo "All active users have 2-Step Verification enrolled." >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# --- 6. suspended users ---
echo "## 6. Suspended Users" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

gam print users query "isSuspended=true" \
  fields primaryEmail,suspensionReason,lastLoginTime \
  | tee "${EVIDENCE_DIR}/gw-suspended-users-${DATE}.csv" \
  >> "$REPORT_FILE"

echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# --- 7. summary ---
echo "## 7. Review Summary" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| metric | count |" >> "$REPORT_FILE"
echo "|--------|-------|" >> "$REPORT_FILE"
echo "| active users | ${TOTAL_USERS} |" >> "$REPORT_FILE"
echo "| admin users | ${ADMIN_COUNT} |" >> "$REPORT_FILE"
echo "| stale accounts (90+ days) | ${STALE_COUNT:-0} |" >> "$REPORT_FILE"
echo "| users without 2SV | ${NO_2SV_COUNT:-0} |" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

FINDINGS=0
[ "${STALE_COUNT:-0}" -gt 0 ] && FINDINGS=$((FINDINGS + 1))
[ "${NO_2SV_COUNT:-0}" -gt 0 ] && FINDINGS=$((FINDINGS + 1))
[ "${ADMIN_COUNT}" -gt 5 ] && FINDINGS=$((FINDINGS + 1))

if [ "$FINDINGS" -gt 0 ]; then
  echo "**Total findings:** ${FINDINGS}" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "**Status:** requires remediation before sign-off." >> "$REPORT_FILE"
else
  echo "**Total findings:** 0" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "**Status:** clean — ready for reviewer sign-off." >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "---" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Reviewed by:** _____________________________ **Date:** __________" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Approved by:** _____________________________ **Date:** __________" >> "$REPORT_FILE"

echo ""
echo "report generated: ${REPORT_FILE}"
echo "supporting evidence files:"
ls -la "${EVIDENCE_DIR}/gw-"*"-${DATE}"* 2>/dev/null || echo "(run GAM commands to generate)"
```

---

## deprovisioning automation (Google Workspace)

this section covers the full automation pipeline from HR termination signal to Google Workspace account suspension.

### HR system integration options

```bash
# Google Workspace supports automated user lifecycle management through:
#
# 1. SCIM via Cloud Identity (recommended for large orgs)
#    - Google Cloud Identity supports inbound SCIM 2.0
#    - HR systems like Okta, Rippling, Workday, and BambooHR can push
#      user lifecycle events (create, update, deactivate) via SCIM
#    - configuration:
#      a. enable Cloud Identity API in Google Cloud Console
#      b. create a SCIM provisioning app in your HR/IdP system
#      c. configure SCIM endpoint: https://www.googleapis.com/scim/v2
#      d. authenticate with service account credentials
#      e. map attributes: active=false triggers suspension
#
# 2. Admin SDK API integration (recommended for custom/small orgs)
#    - build a webhook listener that receives termination events from HR
#    - calls Admin SDK to suspend the user
#    - this is what the offboard-gws.sh script does manually
#
# 3. Google Workspace Auto-licensing with Cloud Identity
#    - if your IdP (Okta, Azure AD) is the master, Google Workspace
#      can auto-suspend when the IdP signals deactivation
#    - configure via admin.google.com > Account > Product management

# --- verify SCIM integration is working ---
# check for recent automated suspension events (actor should be the service account):
gam report admin event_name=SUSPEND_USER \
  start_date $(date -v-7d +%Y-%m-%d 2>/dev/null || date -d "7 days ago" +%Y-%m-%d)
# expected: suspension events with actor = your service account email
```

### automated offboarding pipeline

the `offboard-gws.sh` script from section 3-gws.5 (tier 2) contains the core offboarding steps. to automate it via HR webhook or cron, wrap it with JSON input parsing and SLA tracking:

```bash
#!/bin/bash
# gw-auto-offboard.sh — triggered by HR webhook or cron
# wraps offboard-gws.sh with JSON input and SLA compliance tracking.
#
# expected input: JSON payload with terminated employee details
# {
#   "email": "user@yourdomain.com",
#   "manager_email": "manager@yourdomain.com",
#   "termination_type": "involuntary",
#   "termination_date": "2026-04-06",
#   "hr_ticket_id": "HR-1234"
# }

set -euo pipefail

INPUT="${1:?usage: $0 <json-payload-file>}"
USER_EMAIL=$(jq -r '.email' "$INPUT")
MANAGER_EMAIL=$(jq -r '.manager_email' "$INPUT")
TERM_TYPE=$(jq -r '.termination_type' "$INPUT")
HR_TICKET=$(jq -r '.hr_ticket_id' "$INPUT")
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# run the core offboarding script (see section 3-gws.5 tier 2)
./offboard-gws.sh "$USER_EMAIL" "$MANAGER_EMAIL" "${TERM_TYPE} — HR ticket: ${HR_TICKET}"

# calculate SLA compliance
COMPLETION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
START_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$TIMESTAMP" +%s 2>/dev/null || date -d "$TIMESTAMP" +%s)
END_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$COMPLETION_TIME" +%s 2>/dev/null || date -d "$COMPLETION_TIME" +%s)
DURATION_MINUTES=$(( (END_EPOCH - START_EPOCH) / 60 ))

if [ "$TERM_TYPE" = "involuntary" ]; then
  SLA_MINUTES=60
  SLA_LABEL="1 hour"
else
  SLA_MINUTES=480
  SLA_LABEL="8 hours (end of day)"
fi

if [ "$DURATION_MINUTES" -le "$SLA_MINUTES" ]; then
  echo "SLA: COMPLIANT (${DURATION_MINUTES} minutes, SLA: ${SLA_LABEL})"
else
  echo "SLA: VIOLATION (${DURATION_MINUTES} minutes, SLA: ${SLA_LABEL})"
fi
```

### weekly reconciliation

the `gw-deprovision-reconciliation.sh` from section 3-gws.5 (tier 3) handles orphaned account detection. extend it with a reverse diff (HR active but missing in GWS) by using sorted lists and `comm`:

```bash
#!/bin/bash
# gw-weekly-reconciliation.sh — cron: 0 9 * * 1
# extends the tier-3 reconciliation with bidirectional diff.

set -euo pipefail

DATE=$(date +%Y-%m-%d)
REPORT="evidence/gw-weekly-recon-${DATE}.md"
mkdir -p evidence

echo "# Weekly GWS Reconciliation — ${DATE}" > "$REPORT"
echo "" >> "$REPORT"

# get active GWS users
GWS_ACTIVE=$(gam print users query "isSuspended=false" fields primaryEmail \
  | awk -F, 'NR > 1 { print tolower($1) }' | sort)

# get HR active employees (replace with your HR API call)
# HR_ACTIVE=$(curl -s -H "Authorization: Bearer ${HR_TOKEN}" \
#   "https://api.yourhrsystem.com/employees?status=active" \
#   | jq -r '.[].email' | tr '[:upper:]' '[:lower:]' | sort)

# orphaned: active in GWS but not in HR
echo "## Orphaned Accounts (active in GWS, not in HR)" >> "$REPORT"
echo "" >> "$REPORT"
ORPHANS=$(comm -23 <(echo "$GWS_ACTIVE") <(echo "$HR_ACTIVE") || true)
if [ -n "$ORPHANS" ]; then
  echo "$ORPHANS" | while read email; do echo "- ALERT: $email" >> "$REPORT"; done
else
  echo "None found." >> "$REPORT"
fi

# missing: in HR but not in GWS
echo "" >> "$REPORT"
echo "## Missing Accounts (in HR, not in GWS)" >> "$REPORT"
echo "" >> "$REPORT"
MISSING=$(comm -13 <(echo "$GWS_ACTIVE") <(echo "$HR_ACTIVE") || true)
if [ -n "$MISSING" ]; then
  echo "$MISSING" | while read email; do echo "- WARN: $email" >> "$REPORT"; done
else
  echo "None found." >> "$REPORT"
fi

echo "" >> "$REPORT"
echo "## Summary" >> "$REPORT"
echo "- GWS active: $(echo "$GWS_ACTIVE" | wc -l | tr -d ' ')" >> "$REPORT"
echo "- HR active: $(echo "$HR_ACTIVE" | wc -l | tr -d ' ')" >> "$REPORT"
echo "- Orphaned: $(echo "$ORPHANS" | grep -c . || echo 0)" >> "$REPORT"
echo "- Missing: $(echo "$MISSING" | grep -c . || echo 0)" >> "$REPORT"

echo "report: ${REPORT}"
```

### audit trail requirements

```bash
# for SOC 2 compliance, every deprovisioning event must have:
#
# 1. HR termination record (HR ticket ID, termination date, termination type)
# 2. Google Workspace suspension timestamp (from admin audit log)
# 3. token revocation confirmation
# 4. data transfer confirmation (transfer ID, destination user)
# 5. group removal confirmation
# 6. device wipe confirmation
# 7. SLA compliance calculation (time from HR notification to suspension)
# 8. person who performed the action (or "automated" if via SCIM/script)
#
# the offboard-gws.sh script produces a log file per user that covers items 2-8.
# item 1 comes from your HR system.
#
# auditors will cross-reference:
#   HR termination date <-> GWS suspension timestamp
# the gap between these two dates must be within SLA.
#
# export deprovisioning evidence for audit period:

gam report admin event_name=SUSPEND_USER \
  start_date {{AUDIT_PERIOD_START}} end_date {{AUDIT_PERIOD_END}} \
  > evidence/gw-all-suspensions-audit-period.csv

# cross-reference with HR terminations:
# for each suspension event, verify a corresponding HR ticket exists
# and the time delta is within SLA.
```

---

## SOC 2 control mapping

| control | TSC criteria | section |
|---------|-------------|---------|
| 2SV enforcement | CC6.1, CC6.2 | 3-gws.1 |
| password policy | CC6.1, CC6.2 | 3-gws.2 |
| session management | CC6.1 | 3-gws.3 |
| user provisioning | CC6.1, CC6.3 | 3-gws.4 |
| user deprovisioning | CC6.3 (access removal) | 3-gws.5 |
| group-based access | CC6.1, CC6.3 | 3-gws.6 |
| admin roles audit | CC6.1 | 3-gws.7 |
| OAuth app control | CC6.1, CC6.6 | 3-gws.8 |
| audit log export | CC7.2 (monitoring) | 3-gws.9 |
| mobile device management | CC6.1, CC6.8 | 3-gws.10 |
| context-aware access | CC6.1, CC6.6 | 3-gws.11 |
| data loss prevention | CC6.5 (data protection) | 3-gws.12 |
| alert center | CC7.2, CC7.3 (monitoring) | 3-gws.13 |
