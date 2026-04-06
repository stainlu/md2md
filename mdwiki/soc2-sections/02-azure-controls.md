# Section 02-AZ: Azure Security Controls

> Full DISCOVER-FIX-VERIFY-EVIDENCE cycle for every SOC 2 control on Azure.
> Every command is copy-paste ready. Every control maps to a Trust Services Criteria (TSC).

## Prerequisites

```bash
# Verify az CLI is configured and working
az account show
az account list --output table

# Set reusable variables used throughout this document
export SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export TENANT_ID=$(az account show --query tenantId -o tsv)
export RESOURCE_GROUP="your-rg-name"
export LOCATION="eastus"
export EVIDENCE_DIR="./soc2-evidence/$(date +%Y-%m-%d)"
mkdir -p "$EVIDENCE_DIR"

# Verify Microsoft Graph CLI extension is available (required for Entra ID controls)
az extension add --name account 2>/dev/null
az extension add --name log-analytics 2>/dev/null
az extension add --name monitor-control-service 2>/dev/null

# Login with sufficient permissions for Entra ID operations
# You need Global Administrator or Security Administrator role for most Entra ID controls
az login --tenant "$TENANT_ID"
```

---

## Entra ID (Azure AD) Controls

### 1. MFA Enforcement (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# List Conditional Access policies that enforce MFA
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?grantControls.builtInControls[?@ == 'mfa']].[displayName, state, conditions.users.includeUsers]" \
  -o table
```
- PASS: at least one policy targets `All` users with MFA grant control and state is `enabled`
- FAIL: no policy found, or policies are in `report-only` or `disabled` state, or policies target only specific groups (leaving gaps)

**FIX** -- remediate if failing:
```bash
# Create a Conditional Access policy requiring MFA for all users
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "SOC2 - Require MFA for all users",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeUsers": ["All"],
        "excludeUsers": []
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "clientAppTypes": ["all"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }'
```
Gotchas:
- Start with `enabledForReportingButNotEnforced` (report-only mode) to avoid locking users out
- Monitor the Conditional Access insights workbook for 1-2 weeks before switching to `enabled`
- Conditional Access requires Entra ID P1 or P2 license -- without it, use per-user MFA (legacy, not recommended)
- Exclude break-glass (emergency access) accounts from MFA but monitor them with alerts
- Service principals and managed identities are not affected by user-targeted policies

To switch from report-only to enforced after validation:
```bash
POLICY_ID="<policy-id-from-creation>"
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$POLICY_ID" \
  --headers "Content-Type=application/json" \
  --body '{"state": "enabled"}'
```

**VERIFY** -- confirm the fix:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?grantControls.builtInControls[?@ == 'mfa']].[displayName, state]" \
  -o table
# Expected: at least one policy with state "enabled" targeting All users
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -o json > "$EVIDENCE_DIR/conditional-access-policies-$(date +%Y%m%d-%H%M%S).json"
```

---

### 2. Conditional Access Policies (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List all Conditional Access policies with their state and conditions
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].[displayName, state, conditions.locations, conditions.platforms, conditions.signInRiskLevels, conditions.userRiskLevels]" \
  -o json

# Check for named locations (required for location-based policies)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" \
  --query "value[].[displayName, '@odata.type']" \
  -o table
```
- PASS: policies exist for location-based access, device compliance, and risk-based sign-in; named locations are defined for trusted office IPs
- FAIL: no location-based or risk-based policies; no named locations defined

**FIX** -- remediate if failing:
```bash
# Step 1: Create a named location for trusted office IPs
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" \
  --headers "Content-Type=application/json" \
  --body '{
    "@odata.type": "#microsoft.graph.ipNamedLocation",
    "displayName": "Corporate Office IPs",
    "isTrusted": true,
    "ipRanges": [
      {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "203.0.113.0/24"},
      {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "198.51.100.0/24"}
    ]
  }'

# Step 2: Create policy to block access from untrusted locations for admins
TRUSTED_LOCATION_ID="<id-from-step-1>"
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "SOC2 - Block admin access from untrusted locations",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeRoles": [
          "62e90394-69f5-4237-9190-012177145e10",
          "194ae4cb-b126-40b2-bd5b-6091b380977d"
        ]
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "locations": {
        "includeLocations": ["All"],
        "excludeLocations": ["'"$TRUSTED_LOCATION_ID"'", "AllTrusted"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }'

# Step 3: Create risk-based policy requiring MFA for medium+ risk sign-ins
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "SOC2 - Require MFA for risky sign-ins",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeUsers": ["All"]
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "signInRiskLevels": ["medium", "high"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }'
```
Gotchas:
- Role GUIDs: `62e90394-...` = Global Administrator, `194ae4cb-...` = Security Administrator
- Risk-based policies require Entra ID P2 license
- Device compliance policies require devices enrolled in Intune (Microsoft Endpoint Manager)
- Always start in report-only mode and validate before enforcing
- Named locations support both IP ranges and country-based locations

**VERIFY** -- confirm the fix:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].[displayName, state]" \
  -o table
# Expected: policies for location-based, risk-based, and MFA requirements all present
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -o json > "$EVIDENCE_DIR/conditional-access-full-$(date +%Y%m%d-%H%M%S).json"

az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" \
  -o json > "$EVIDENCE_DIR/named-locations-$(date +%Y%m%d-%H%M%S).json"
```

---

### 3. Privileged Identity Management (PIM) (TSC: CC6.1, CC6.2, CC6.3)

**DISCOVER** -- check current state:
```bash
# Check if PIM is configured for directory roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances" \
  --query "value[].[principal.displayName, roleDefinition.displayName, assignmentType, endDateTime]" \
  -o json 2>/dev/null

# List permanently active privileged role assignments (these should be minimal)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
  --query "value[].[principal.displayName, roleDefinition.displayName]" \
  -o table

# Count permanent Global Admins (should be <= 2 break-glass accounts)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/filterByRoleId(roleId='62e90394-69f5-4237-9190-012177145e10')/members" \
  --query "value[].[displayName, userPrincipalName]" \
  -o table
```
- PASS: most admin roles are assigned as "eligible" (just-in-time), permanent assignments limited to 1-2 break-glass accounts
- FAIL: multiple users with permanent Global Administrator or other privileged role assignments

**FIX** -- remediate if failing:
```bash
# Convert a permanent admin assignment to PIM-eligible (just-in-time)
# Step 1: Remove the permanent role assignment
USER_OBJECT_ID="<user-object-id>"
ROLE_DEFINITION_ID="62e90394-69f5-4237-9190-012177145e10"  # Global Administrator

# Find the assignment ID
ASSIGNMENT_ID=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$USER_OBJECT_ID' and roleDefinitionId eq '$ROLE_DEFINITION_ID'" \
  --query "value[0].id" -o tsv)

# Remove permanent assignment
az rest --method DELETE \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$ASSIGNMENT_ID"

# Step 2: Create PIM-eligible assignment (user must activate when needed)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" \
  --headers "Content-Type=application/json" \
  --body '{
    "action": "adminAssign",
    "justification": "SOC2 compliance - converting to just-in-time access",
    "roleDefinitionId": "'"$ROLE_DEFINITION_ID"'",
    "directoryScopeId": "/",
    "principalId": "'"$USER_OBJECT_ID"'",
    "scheduleInfo": {
      "startDateTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
      "expiration": {
        "type": "afterDuration",
        "duration": "P365D"
      }
    }
  }'

# Step 3: Configure PIM role settings (max activation duration, require MFA, require justification)
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments" \
  --headers "Content-Type=application/json" \
  --body '{
    "comment": "Enforcing PIM settings for SOC2 compliance"
  }'
```
Gotchas:
- PIM requires Entra ID P2 license
- Always keep 2 break-glass accounts with permanent Global Administrator role (not subject to PIM)
- Break-glass accounts must be cloud-only (not federated), have strong passwords stored in a physical safe, and be monitored with alerts
- PIM activation duration should be set to maximum 8 hours for Global Administrator
- Require MFA and justification on activation
- Set up approval workflow for Global Administrator activations

**VERIFY** -- confirm the fix:
```bash
# Check that most admin roles are now eligible (not permanent)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" \
  --query "value | length(@)"
# Expected: count > 0 (eligible assignments exist)

# Count remaining permanent Global Admins (should be <= 2)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/filterByRoleId(roleId='62e90394-69f5-4237-9190-012177145e10')/members" \
  --query "value | length(@)"
# Expected: 2 or fewer
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
  -o json > "$EVIDENCE_DIR/pim-permanent-assignments-$(date +%Y%m%d-%H%M%S).json"

az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" \
  -o json > "$EVIDENCE_DIR/pim-eligible-assignments-$(date +%Y%m%d-%H%M%S).json"
```

---

### 4. Password Policy (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Check tenant password policy (Entra ID manages this at tenant level)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[].[id, passwordValidityPeriodInDays, passwordNotificationWindowInDays]" \
  -o table

# Check if custom banned password list is enabled
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/settings" \
  -o json 2>/dev/null | grep -A 5 "BannedPasswordCheckOnPremisesMode"

# Check authentication methods policy
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" \
  -o json
```
- PASS: password expiry is configured (90 days or based on risk), custom banned password list is enabled, smart lockout is configured
- FAIL: default policy with no customization, no banned password list

**FIX** -- remediate if failing:
```bash
# Set password expiration policy on the domain
DOMAIN_NAME="yourdomain.onmicrosoft.com"
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/domains/$DOMAIN_NAME" \
  --headers "Content-Type=application/json" \
  --body '{
    "passwordValidityPeriodInDays": 90,
    "passwordNotificationWindowInDays": 14
  }'

# Enable custom banned password protection
# Note: Custom banned passwords are configured in Entra ID portal:
# 1. Azure Portal > Entra ID > Security > Authentication methods > Password protection
# 2. Set "Enable password protection on Windows Server Active Directory" to Yes
# 3. Set "Mode" to "Enforced"
# 4. Add custom banned passwords (company name, product names, common weak passwords)

# Configure smart lockout thresholds
# This must be done via the Azure Portal:
# Entra ID > Security > Authentication methods > Password protection
# - Lockout threshold: 10 (failed attempts before lockout)
# - Lockout duration: 60 seconds (minimum)
```
Gotchas:
- Azure AD enforces a minimum password length of 8 characters and complexity rules by default -- you cannot reduce these but also cannot increase minimum length beyond 256 via standard settings
- Microsoft recommends AGAINST password expiry if MFA is enforced (NIST 800-63B alignment) -- but many auditors still expect it
- Custom banned password list supports up to 1000 words
- Smart lockout is always on -- you can only customize thresholds
- For hybrid environments (AD Connect sync), on-premises AD password policy takes precedence for synced users

**VERIFY** -- confirm the fix:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  --query "value[].[id, passwordValidityPeriodInDays, passwordNotificationWindowInDays]" \
  -o table
# Expected: passwordValidityPeriodInDays = 90, passwordNotificationWindowInDays = 14
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/domains" \
  -o json > "$EVIDENCE_DIR/password-policy-$(date +%Y%m%d-%H%M%S).json"

az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" \
  -o json > "$EVIDENCE_DIR/auth-methods-policy-$(date +%Y%m%d-%H%M%S).json"
```

---

### 5. Guest User Audit (TSC: CC6.1, CC6.2, CC6.3)

**DISCOVER** -- check current state:
```bash
# List all guest users in the tenant
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'" \
  --query "value[].[displayName, mail, createdDateTime, signInActivity.lastSignInDateTime]" \
  -o table

# Count guest users
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users/\$count?\$filter=userType eq 'Guest'" \
  --headers "ConsistencyLevel=eventual" \
  -o tsv

# Find guest users with directory role assignments (high risk)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[].id" -o tsv | while read ROLE_ID; do
    MEMBERS=$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members" \
      --query "value[?userType=='Guest'].[displayName, mail]" -o tsv 2>/dev/null)
    if [ -n "$MEMBERS" ]; then
      ROLE_NAME=$(az rest --method GET \
        --uri "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID" \
        --query "displayName" -o tsv)
      echo "ROLE: $ROLE_NAME"
      echo "$MEMBERS"
    fi
done

# Find guest users who have not signed in for 90+ days
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$select=displayName,mail,signInActivity" \
  -o json | jq '.value[] | select(.signInActivity.lastSignInDateTime == null or
    (.signInActivity.lastSignInDateTime | fromdateiso8601) < (now - 7776000)) |
    {displayName, mail, lastSignIn: .signInActivity.lastSignInDateTime}'
```
- PASS: no guest users with privileged roles, all guests have recent sign-in activity, total guest count is reasonable
- FAIL: guest users with admin roles, stale guests with no activity for 90+ days

**FIX** -- remediate if failing:
```bash
# Remove a guest user with excessive permissions
GUEST_USER_ID="<guest-object-id>"

# Option A: Remove from specific role
ROLE_ID="<directory-role-id>"
az rest --method DELETE \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members/$GUEST_USER_ID/\$ref"

# Option B: Remove stale guest entirely
az rest --method DELETE \
  --uri "https://graph.microsoft.com/v1.0/users/$GUEST_USER_ID"

# Configure guest access restrictions (limit what guests can see)
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
  --headers "Content-Type=application/json" \
  --body '{
    "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b"
  }'
# Guest role IDs:
# a0b1b346-... = Same as member users (most permissive, avoid)
# 10dae51f-... = Limited access (default)
# 2af84b1e-... = Restricted access (most restrictive, recommended)
```
Gotchas:
- Contact the guest user's sponsor (the internal person who invited them) before removing
- Removing a guest does not revoke existing tokens immediately -- token lifetime is up to 1 hour by default
- Configure Entra ID Access Reviews to automate periodic guest user reviews
- Consider setting up automatic guest expiry via lifecycle workflows

**VERIFY** -- confirm the fix:
```bash
# Re-check guest users with roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[].id" -o tsv | while read ROLE_ID; do
    az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members" \
      --query "value[?userType=='Guest'].[displayName]" -o tsv 2>/dev/null
done
# Expected: no output (no guests in privileged roles)
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$select=displayName,mail,createdDateTime,signInActivity" \
  -o json > "$EVIDENCE_DIR/guest-users-$(date +%Y%m%d-%H%M%S).json"
```

---

### 6. App Registrations Audit (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# List all app registrations with their credential expiry
az ad app list --all \
  --query "[].{AppId:appId, DisplayName:displayName, SignInAudience:signInAudience, KeyCredCount:length(keyCredentials), PasswordCredCount:length(passwordCredentials)}" \
  -o table

# Find app registrations with expired credentials (still exist but expired)
az ad app list --all -o json | jq '
  .[] | select(
    (.passwordCredentials[]? | .endDateTime | fromdateiso8601 < now) or
    (.keyCredentials[]? | .endDateTime | fromdateiso8601 < now)
  ) | {appId, displayName, expiredCreds: true}'

# Find app registrations with overly permissive API permissions
az ad app list --all -o json | jq '
  .[] | select(
    .requiredResourceAccess[]?.resourceAccess[]?.type == "Role"
  ) | {appId, displayName,
    permissions: [.requiredResourceAccess[].resourceAccess[] | select(.type == "Role") | .id]}'

# Find apps with no owner (orphaned)
for APP_ID in $(az ad app list --all --query "[].id" -o tsv); do
  OWNER_COUNT=$(az ad app owner list --id "$APP_ID" --query "length(@)" -o tsv 2>/dev/null)
  if [ "$OWNER_COUNT" = "0" ]; then
    APP_NAME=$(az ad app show --id "$APP_ID" --query "displayName" -o tsv)
    echo "ORPHANED: $APP_NAME ($APP_ID)"
  fi
done
```
- PASS: all apps have owners, no expired credentials, permissions follow least privilege
- FAIL: orphaned apps, expired credentials, apps with Application-level (Role) permissions on Microsoft Graph for Directory.ReadWrite.All or similar

**FIX** -- remediate if failing:
```bash
# Remove an unused or orphaned app registration
APP_ID="<application-object-id>"
az ad app delete --id "$APP_ID"

# Remove expired credential from an app
az ad app credential delete --id "$APP_ID" --key-id "<credential-key-id>"

# Add an owner to an orphaned app (assign a responsible person)
az ad app owner add --id "$APP_ID" --owner-object-id "<user-object-id>"

# Remove overly permissive API permission
az ad app permission delete --id "$APP_ID" --api "00000003-0000-0000-c000-000000000000"
# Then re-add with least privilege permissions as needed
```
Gotchas:
- Before deleting an app, check if any services depend on its client ID / service principal
- Apps with "Application" permission type (vs "Delegated") can act without a user context -- these are higher risk
- App registrations and enterprise applications (service principals) are different objects -- deleting the app registration also deletes the service principal
- Multi-tenant apps (signInAudience = AzureADMultipleOrgs) can authenticate users from any tenant -- review these carefully

**VERIFY** -- confirm the fix:
```bash
az ad app list --all \
  --query "[].{AppId:appId, DisplayName:displayName, OwnerCount:length(owners || [])}" \
  -o table
# Expected: no orphaned apps, no expired credentials
```

**EVIDENCE** -- capture for auditor:
```bash
az ad app list --all -o json > "$EVIDENCE_DIR/app-registrations-$(date +%Y%m%d-%H%M%S).json"
```

---

### 7. Sign-In Risk Policy (TSC: CC6.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check for sign-in risk Conditional Access policy
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?conditions.signInRiskLevels != null].[displayName, state, conditions.signInRiskLevels]" \
  -o json

# Check for user risk Conditional Access policy
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?conditions.userRiskLevels != null].[displayName, state, conditions.userRiskLevels]" \
  -o json

# Review recent risky sign-ins
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" \
  --query "value[].[userDisplayName, riskLevel, riskState, riskLastUpdatedDateTime]" \
  -o table
```
- PASS: sign-in risk policy exists and is enabled, user risk policy exists and is enabled, risky users are being actively remediated
- FAIL: no risk-based policies, or policies in report-only mode, or risky users with `atRisk` state unaddressed

**FIX** -- remediate if failing:
```bash
# Create sign-in risk policy (require MFA for medium+, block for high)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "SOC2 - Sign-in risk: require MFA for medium+",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeUsers": ["All"],
        "excludeUsers": []
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "signInRiskLevels": ["medium", "high"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }'

# Create user risk policy (require password change for high-risk users)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "SOC2 - User risk: require password change for high",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeUsers": ["All"]
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "userRiskLevels": ["high"]
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": ["mfa", "passwordChange"]
    }
  }'

# Dismiss or remediate risky users that have been addressed
RISKY_USER_ID="<user-object-id>"
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss" \
  --headers "Content-Type=application/json" \
  --body '{"userIds": ["'"$RISKY_USER_ID"'"]}'
```
Gotchas:
- Risk detection requires Entra ID P2 license
- Sign-in risk is evaluated in real-time (at login), user risk is evaluated offline (background analysis)
- Risk levels: low, medium, high -- high-risk sign-ins often indicate compromised credentials
- Password change as a grant control requires self-service password reset (SSPR) to be enabled
- Do not dismiss risky users without investigation -- review the risk detections first

**VERIFY** -- confirm the fix:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?conditions.signInRiskLevels != null].[displayName, state]" \
  -o table
# Expected: sign-in and user risk policies present and enabled

az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" \
  --query "value[?riskState=='atRisk'] | length(@)"
# Expected: 0 (all risky users addressed)
```

**EVIDENCE** -- capture for auditor:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?conditions.signInRiskLevels != null || conditions.userRiskLevels != null]" \
  -o json > "$EVIDENCE_DIR/risk-policies-$(date +%Y%m%d-%H%M%S).json"

az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" \
  -o json > "$EVIDENCE_DIR/risky-users-$(date +%Y%m%d-%H%M%S).json"
```

---

## Azure Activity Log & Monitoring Controls

### 8. Diagnostic Settings -- Activity Log Export (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check if Activity Log diagnostic settings are configured
az monitor diagnostic-settings subscription list \
  --subscription "$SUBSCRIPTION_ID" \
  -o table

# Verify the diagnostic settings export to Log Analytics
az monitor diagnostic-settings subscription list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, WorkspaceId:workspaceId, StorageAccount:storageAccountId, EventHub:eventHubAuthorizationRuleId}" \
  -o table
```
- PASS: at least one diagnostic setting exists exporting to Log Analytics workspace (workspaceId is populated)
- FAIL: empty list or no workspace destination configured

**FIX** -- remediate if failing:
```bash
# First, create a Log Analytics workspace if one does not exist (see control #9)
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Create diagnostic setting for Activity Log
az monitor diagnostic-settings subscription create \
  --name "soc2-activity-log-export" \
  --subscription "$SUBSCRIPTION_ID" \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "ServiceHealth", "enabled": true},
    {"category": "Alert", "enabled": true},
    {"category": "Recommendation", "enabled": true},
    {"category": "Policy", "enabled": true},
    {"category": "Autoscale", "enabled": true},
    {"category": "ResourceHealth", "enabled": true}
  ]'
```
Gotchas:
- Activity Log has only 90-day built-in retention -- exporting to Log Analytics gives you configurable retention (365+ days for SOC 2)
- You need one diagnostic setting per subscription -- if you have multiple subscriptions, configure each
- You can export to multiple destinations simultaneously (Log Analytics + Storage Account for long-term archival)
- The command uses `subscription create` not `create` -- this is a subscription-level diagnostic setting, not a resource-level one

**VERIFY** -- confirm the fix:
```bash
az monitor diagnostic-settings subscription list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, WorkspaceId:workspaceId}" \
  -o table
# Expected: diagnostic setting with a valid workspace ID
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor diagnostic-settings subscription list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/activity-log-diagnostic-settings-$(date +%Y%m%d-%H%M%S).json"
```

---

### 9. Log Analytics Workspace (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# List all Log Analytics workspaces
az monitor log-analytics workspace list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, SKU:sku.name, RetentionDays:retentionInDays, DailyCapGB:workspaceCapping.dailyQuotaGb}" \
  -o table
```
- PASS: workspace exists with retentionInDays >= 365 and appropriate SKU (PerGB2018 recommended)
- FAIL: no workspace, or retention < 365 days

**FIX** -- remediate if failing:
```bash
# Create Log Analytics workspace with 365-day retention
az monitor log-analytics workspace create \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --location "$LOCATION" \
  --retention-time 365 \
  --sku PerGB2018

# If workspace exists but retention is too low, update it
az monitor log-analytics workspace update \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --retention-time 365
```
Gotchas:
- Free tier (legacy) only allows 7 days retention -- use PerGB2018 SKU
- Retention beyond 31 days incurs additional storage charges ($0.10/GB/month approximately)
- Retention can be set from 30 to 730 days (workspace level), or use table-level retention for fine-grained control
- Data ingestion costs are the primary cost driver -- set a daily cap for cost control (but be aware: hitting the cap stops ingestion)
- Archive tier (up to 12 years) is available for long-term retention at reduced cost

**VERIFY** -- confirm the fix:
```bash
az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --query "{Name:name, RetentionDays:retentionInDays, SKU:sku.name}" \
  -o table
# Expected: RetentionDays = 365, SKU = PerGB2018
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor log-analytics workspace list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/log-analytics-workspaces-$(date +%Y%m%d-%H%M%S).json"
```

---

### 10. Activity Log Alerts (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List existing activity log alerts
az monitor activity-log alert list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, Enabled:enabled, Conditions:condition.allOf[].{Field:field, Equals:equals}}" \
  -o json
```
- PASS: alerts exist for policy assignment changes, role assignment changes, resource group deletions, network security group changes, and security solution modifications
- FAIL: no activity log alerts, or missing critical event types

**FIX** -- remediate if failing:
```bash
# Prerequisite: create an action group first (see control #12)
ACTION_GROUP_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/actionGroups/soc2-security-alerts"

# Alert 1: Policy assignment changes
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-policy-changes" \
  --description "Alert on Azure Policy assignment changes" \
  --condition category=Administrative and operationName="Microsoft.Authorization/policyAssignments/write" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true

# Alert 2: Role assignment changes
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-role-changes" \
  --description "Alert on role assignment changes" \
  --condition category=Administrative and operationName="Microsoft.Authorization/roleAssignments/write" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true

# Alert 3: Resource group deletions
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-rg-deletions" \
  --description "Alert on resource group deletions" \
  --condition category=Administrative and operationName="Microsoft.Resources/subscriptions/resourceGroups/delete" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true

# Alert 4: NSG rule changes
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-nsg-changes" \
  --description "Alert on NSG rule changes" \
  --condition category=Administrative and operationName="Microsoft.Network/networkSecurityGroups/securityRules/write" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true

# Alert 5: Security solution changes (Defender)
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-security-solution-changes" \
  --description "Alert on security solution modifications" \
  --condition category=Security and operationName="Microsoft.Security/securitySolutions/write" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true

# Alert 6: SQL Server firewall rule changes
az monitor activity-log alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-sql-firewall-changes" \
  --description "Alert on SQL Server firewall rule changes" \
  --condition category=Administrative and operationName="Microsoft.Sql/servers/firewallRules/write" \
  --action-group "$ACTION_GROUP_ID" \
  --enabled true
```
Gotchas:
- Activity log alerts are subscription-scoped -- they fire on events across the entire subscription
- Each alert can have multiple conditions (AND logic) via the `--condition` parameter
- These alerts are free -- they do not count toward Azure Monitor alert limits
- For more complex alerting (log queries), use Log Analytics alert rules instead (see control #43)

**VERIFY** -- confirm the fix:
```bash
az monitor activity-log alert list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, Enabled:enabled}" \
  -o table
# Expected: all 6 alerts listed and enabled
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor activity-log alert list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/activity-log-alerts-$(date +%Y%m%d-%H%M%S).json"
```

---

### 11. Azure Monitor Metric Alerts (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List all metric alert rules
az monitor metrics alert list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name, Enabled:enabled, Severity:severity, TargetResource:scopes}" \
  -o table

# Check for alerts on critical resources (VMs, databases, etc.)
az monitor metrics alert list \
  --resource-group "$RESOURCE_GROUP" \
  -o json | jq '.[] | {name, severity, targetResource: .scopes[0], criteria: .criteria}'
```
- PASS: metric alerts exist for CPU, memory, disk, DTU utilization on critical resources
- FAIL: no metric alerts configured

**FIX** -- remediate if failing:
```bash
# Prerequisite: action group must exist (see control #12)
ACTION_GROUP_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/actionGroups/soc2-security-alerts"

# Example: VM CPU > 90% for 5 minutes
VM_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/your-vm-name"

az monitor metrics alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-vm-high-cpu" \
  --description "VM CPU utilization above 90%" \
  --scopes "$VM_ID" \
  --condition "avg Percentage CPU > 90" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2 \
  --action "$ACTION_GROUP_ID"

# Example: SQL Database DTU > 90%
SQL_DB_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Sql/servers/your-server/databases/your-db"

az monitor metrics alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-sql-high-dtu" \
  --description "SQL Database DTU utilization above 90%" \
  --scopes "$SQL_DB_ID" \
  --condition "avg dtu_consumption_percent > 90" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2 \
  --action "$ACTION_GROUP_ID"

# Example: Storage Account availability drop
STORAGE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/yourstorageaccount"

az monitor metrics alert create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-storage-availability" \
  --description "Storage Account availability below 99.9%" \
  --scopes "$STORAGE_ID" \
  --condition "avg Availability < 99.9" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 1 \
  --action "$ACTION_GROUP_ID"
```
Gotchas:
- Metric alerts cost approximately $0.10/month per alert rule
- Use severity levels consistently: 0=Critical, 1=Error, 2=Warning, 3=Informational, 4=Verbose
- Static thresholds are simpler but dynamic thresholds (machine learning based) reduce false positives
- Multi-resource alerts can target all VMs in a subscription with a single rule

**VERIFY** -- confirm the fix:
```bash
az monitor metrics alert list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name, Enabled:enabled, Severity:severity}" \
  -o table
# Expected: alerts for CPU, DTU, availability present and enabled
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor metrics alert list \
  --resource-group "$RESOURCE_GROUP" \
  -o json > "$EVIDENCE_DIR/metric-alerts-$(date +%Y%m%d-%H%M%S).json"
```

---

### 12. Action Groups (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List all action groups
az monitor action-group list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name, Enabled:enabled, EmailReceivers:emailReceivers[].emailAddress, SMSReceivers:smsReceivers[].phoneNumber, WebhookReceivers:webhookReceivers[].serviceUri}" \
  -o json
```
- PASS: at least one action group exists with email and/or SMS receivers for security notifications
- FAIL: no action groups, or action groups with no receivers

**FIX** -- remediate if failing:
```bash
# Create an action group for security alerts
az monitor action-group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-security-alerts" \
  --short-name "soc2sec" \
  --action email security-team security@yourcompany.com \
  --action email cto cto@yourcompany.com

# Add SMS receiver for critical alerts
az monitor action-group update \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-security-alerts" \
  --add-action sms oncall-sms 1 5551234567

# Add webhook for PagerDuty integration
az monitor action-group update \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-security-alerts" \
  --add-action webhook pagerduty "https://events.pagerduty.com/integration/<your-integration-key>/enqueue"

# Create a separate action group for non-critical operational alerts
az monitor action-group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-ops-alerts" \
  --short-name "soc2ops" \
  --action email ops-team ops@yourcompany.com
```
Gotchas:
- Short name must be 12 characters or fewer (used in SMS notifications)
- Email receivers get a confirmation email -- they must click to confirm
- SMS has rate limits: max 1 SMS every 5 minutes per phone number
- Action groups support: email, SMS, voice call, webhook, ITSM connector, Azure Function, Logic App, Automation Runbook
- Test the action group to verify delivery: `az monitor action-group test-notifications create ...`

**VERIFY** -- confirm the fix:
```bash
az monitor action-group list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name, Enabled:enabled, EmailCount:length(emailReceivers)}" \
  -o table
# Expected: action groups with at least one email receiver
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor action-group list \
  --resource-group "$RESOURCE_GROUP" \
  -o json > "$EVIDENCE_DIR/action-groups-$(date +%Y%m%d-%H%M%S).json"
```

---

## Microsoft Defender for Cloud Controls

### 13. Enable Defender for Cloud (TSC: CC6.1, CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check which Defender plans are enabled
az security pricing list \
  --query "[].{Name:name, Tier:pricingTier, FreeTrialRemaining:freeTrialRemainingTime}" \
  -o table
```
- PASS: all relevant resource types show `pricingTier = Standard` (Servers, Storage, Sql, AppServices, KeyVaults, Arm, Dns, ContainerRegistry, Containers, etc.)
- FAIL: any resource type shows `pricingTier = Free`

**FIX** -- remediate if failing:
```bash
# Enable Defender for each resource type
for PLAN in VirtualMachines SqlServers AppServices StorageAccounts \
  SqlServerVirtualMachines KeyVaults Arm Dns OpenSourceRelationalDatabases \
  Containers ContainerRegistry CloudPosture; do
    az security pricing create \
      --name "$PLAN" \
      --tier Standard
done
```
Gotchas:
- Each Defender plan is billed separately -- review pricing at https://azure.microsoft.com/pricing/details/defender-for-cloud/
- Defender for Servers has two sub-plans (P1 and P2) -- P2 includes vulnerability assessment, JIT VM access, and file integrity monitoring
- Defender for Storage includes malware scanning (additional cost per GB scanned)
- Free tier provides Security Score and basic recommendations but no threat detection
- Changes take up to 24 hours to fully propagate
- For Defender for Servers P2: `az security pricing create --name VirtualMachines --tier Standard --subplan P2`

**VERIFY** -- confirm the fix:
```bash
az security pricing list \
  --query "[].{Name:name, Tier:pricingTier}" \
  -o table
# Expected: all plans show Standard
```

**EVIDENCE** -- capture for auditor:
```bash
az security pricing list \
  -o json > "$EVIDENCE_DIR/defender-pricing-$(date +%Y%m%d-%H%M%S).json"
```

---

### 14. Security Score Review (TSC: CC4.1, CC7.1)

**DISCOVER** -- check current state:
```bash
# Get current Secure Score
az security secure-score list \
  --query "[].{Name:displayName, Current:currentScore, Max:maxScore, Percentage:percentage}" \
  -o table

# List all recommendations sorted by severity
az security assessment list \
  --query "[?status.code=='Unhealthy'].{Name:displayName, Severity:metadata.severity, Status:status.code, Category:metadata.category}" \
  -o table

# Count unhealthy findings by severity
az security assessment list \
  --query "[?status.code=='Unhealthy'] | [].metadata.severity" \
  -o tsv | sort | uniq -c | sort -rn
```
- PASS: Secure Score > 80%, no High-severity unhealthy recommendations
- FAIL: Secure Score < 70%, or any High-severity findings remain unaddressed

**FIX** -- remediate if failing:
```bash
# There is no single fix -- review each recommendation and remediate individually.
# List the top 10 highest-impact unhealthy recommendations:
az security assessment list \
  --query "sort_by([?status.code=='Unhealthy'], &metadata.severity) | [0:10].{Name:displayName, Severity:metadata.severity, Remediation:metadata.remediationDescription}" \
  -o json

# Each recommendation links to specific remediation steps.
# Common high-impact fixes:
# - Enable MFA (control #1 above)
# - Enable disk encryption on VMs
# - Restrict public network access on storage accounts (control #19)
# - Enable auditing on SQL servers (control #25)
# - Configure NSG rules (control #31)
```
Gotchas:
- Secure Score updates can take up to 24 hours after remediation
- Some recommendations require Defender Standard tier to evaluate
- "Not applicable" assessments do not affect the score
- You can exempt specific resources from recommendations if they have a justified reason (but document the justification)

**VERIFY** -- confirm the fix:
```bash
az security secure-score list \
  --query "[].{Name:displayName, Current:currentScore, Max:maxScore, Percentage:percentage}" \
  -o table
# Expected: percentage > 80%
```

**EVIDENCE** -- capture for auditor:
```bash
az security secure-score list \
  -o json > "$EVIDENCE_DIR/secure-score-$(date +%Y%m%d-%H%M%S).json"

az security assessment list \
  -o json > "$EVIDENCE_DIR/security-assessments-$(date +%Y%m%d-%H%M%S).json"
```

---

### 15. Continuous Export (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check if continuous export is configured
az security automation list \
  --query "[].{Name:name, Enabled:isEnabled, Scope:scopes[0].scopePath, Targets:actions[0].actionType}" \
  -o table
```
- PASS: at least one automation (continuous export) exists, is enabled, and targets Log Analytics or Event Hub
- FAIL: no automations or all disabled

**FIX** -- remediate if failing:
```bash
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Create continuous export to Log Analytics
# Note: This is best configured via Azure Portal or Terraform due to the complex JSON body.
# Portal path: Defender for Cloud > Environment settings > [subscription] > Continuous export

# Via CLI (the body is complex):
az security automation create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-continuous-export" \
  --scopes "[{\"scopePath\": \"/subscriptions/$SUBSCRIPTION_ID\"}]" \
  --sources "[{\"eventSource\": \"Assessments\", \"ruleSets\": []}, {\"eventSource\": \"Alerts\", \"ruleSets\": []}, {\"eventSource\": \"SecureScores\", \"ruleSets\": []}]" \
  --actions "[{\"actionType\": \"LogAnalytics\", \"workspaceResourceId\": \"$WORKSPACE_ID\"}]" \
  --is-enabled true
```
Gotchas:
- Continuous export sends data in near-real-time but there can be a delay of up to 30 minutes
- Export to Event Hub is required for integration with external SIEMs (Splunk, Sentinel, etc.)
- Export to Log Analytics is simpler and integrates directly with Azure Sentinel
- You can export assessments (recommendations), alerts, and Secure Score changes
- Each export configuration is scoped to a subscription

**VERIFY** -- confirm the fix:
```bash
az security automation list \
  --query "[].{Name:name, Enabled:isEnabled}" \
  -o table
# Expected: at least one enabled automation
```

**EVIDENCE** -- capture for auditor:
```bash
az security automation list \
  -o json > "$EVIDENCE_DIR/continuous-export-$(date +%Y%m%d-%H%M%S).json"
```

---

### 16. Regulatory Compliance Dashboard (TSC: CC4.1)

**DISCOVER** -- check current state:
```bash
# List enabled regulatory compliance standards
az security regulatory-compliance-standards list \
  --query "[].{Name:name, State:state}" \
  -o table

# Check if SOC 2 standard is enabled
az security regulatory-compliance-standards list \
  --query "[?contains(name, 'SOC') || contains(name, 'soc')]" \
  -o table
```
- PASS: SOC 2 Type 2 standard appears in the list and state is `Passed` or assessments are in progress
- FAIL: SOC 2 standard not enabled, or no regulatory standards at all

**FIX** -- remediate if failing:
```bash
# Regulatory compliance standards are enabled via the Azure Portal or Terraform:
# Portal path: Defender for Cloud > Regulatory compliance > Manage compliance policies
# Select your subscription > Add standard > SOC 2 Type 2

# Via Terraform (see Terraform module section below) or via REST API:
az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Security/regulatoryComplianceStandards/SOC-2?api-version=2019-01-01-preview" \
  --headers "Content-Type=application/json" \
  --body '{"properties": {"state": "Enabled"}}'
```
Gotchas:
- Available standards include: Azure CIS, NIST 800-53, PCI DSS, SOC 2, ISO 27001, HIPAA, and more
- Some standards require Defender for Cloud Standard tier
- Compliance dashboard shows a percentage score per standard -- aim for 100% on all controls in scope
- The dashboard reflects your actual resource configuration -- there is no way to "pass" without actually remediating

**VERIFY** -- confirm the fix:
```bash
az security regulatory-compliance-standards list \
  --query "[?contains(name, 'SOC')].[name, state]" \
  -o table
# Expected: SOC 2 standard present
```

**EVIDENCE** -- capture for auditor:
```bash
az security regulatory-compliance-standards list \
  -o json > "$EVIDENCE_DIR/regulatory-compliance-$(date +%Y%m%d-%H%M%S).json"

# Export detailed control assessment for SOC 2
SOC2_STANDARD=$(az security regulatory-compliance-standards list \
  --query "[?contains(name, 'SOC')].name | [0]" -o tsv)

if [ -n "$SOC2_STANDARD" ]; then
  az security regulatory-compliance-controls list \
    --standard-name "$SOC2_STANDARD" \
    -o json > "$EVIDENCE_DIR/soc2-controls-detail-$(date +%Y%m%d-%H%M%S).json"
fi
```

---

### 17. Auto-Provisioning -- Defender Agents (TSC: CC7.1)

**DISCOVER** -- check current state:
```bash
# Check auto-provisioning settings
az security auto-provisioning-setting list \
  --query "[].{Name:name, AutoProvision:autoProvision}" \
  -o table
```
- PASS: autoProvision is `On` for default (Log Analytics agent / Azure Monitor Agent)
- FAIL: autoProvision is `Off`

**FIX** -- remediate if failing:
```bash
# Enable auto-provisioning of monitoring agent
az security auto-provisioning-setting update \
  --name default \
  --auto-provision On
```
Gotchas:
- Auto-provisioning installs the Log Analytics agent (MMA) or Azure Monitor Agent (AMA) on VMs
- Microsoft is deprecating MMA in favor of AMA -- configure AMA via data collection rules for new deployments
- Auto-provisioning does not affect existing VMs -- you must install the agent manually or use Azure Policy to remediate
- For Kubernetes, Defender for Containers auto-provisions its own extensions
- VM scale sets require additional configuration for auto-provisioning

**VERIFY** -- confirm the fix:
```bash
az security auto-provisioning-setting list \
  --query "[].{Name:name, AutoProvision:autoProvision}" \
  -o table
# Expected: autoProvision = On
```

**EVIDENCE** -- capture for auditor:
```bash
az security auto-provisioning-setting list \
  -o json > "$EVIDENCE_DIR/auto-provisioning-$(date +%Y%m%d-%H%M%S).json"
```

---

## Storage Account Controls

### 18. Encryption (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Check encryption settings for all storage accounts
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, Encryption:encryption.services.blob.enabled, KeySource:encryption.keySource, InfraEncryption:encryption.requireInfrastructureEncryption}" \
  -o table
```
- PASS: all accounts show `Encryption = true`, `KeySource` is either `Microsoft.Storage` (MMK) or `Microsoft.Keyvault` (CMK)
- FAIL: encryption disabled (extremely unlikely for new accounts -- Azure enforces encryption by default since 2017)

**FIX** -- remediate if failing:
```bash
# Storage account encryption is enabled by default and cannot be disabled.
# To upgrade from Microsoft-managed keys (MMK) to customer-managed keys (CMK):

STORAGE_ACCOUNT="yourstorageaccount"
KEY_VAULT_NAME="your-keyvault"
KEY_NAME="storage-encryption-key"

# Step 1: Create a key in Key Vault (see Key Vault section for setup)
az keyvault key create \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  --kty RSA \
  --size 2048

# Step 2: Get the key URI
KEY_URI=$(az keyvault key show \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  --query "key.kid" -o tsv)

# Step 3: Assign managed identity to storage account (for Key Vault access)
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --assign-identity

IDENTITY_PRINCIPAL=$(az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "identity.principalId" -o tsv)

# Step 4: Grant Key Vault access to the storage account identity
az keyvault set-policy \
  --name "$KEY_VAULT_NAME" \
  --object-id "$IDENTITY_PRINCIPAL" \
  --key-permissions get wrapKey unwrapKey

# Step 5: Configure CMK encryption
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault "https://$KEY_VAULT_NAME.vault.azure.net" \
  --encryption-key-name "$KEY_NAME"
```
Gotchas:
- Azure enforces storage encryption by default -- you cannot create an unencrypted storage account
- MMK is sufficient for most SOC 2 audits -- CMK is required only if your security policy mandates customer-managed keys
- CMK requires Key Vault with soft delete and purge protection enabled
- If the Key Vault key is deleted or access is revoked, the storage account becomes inaccessible
- CMK can be configured with automatic key rotation (recommended)

**VERIFY** -- confirm the fix:
```bash
az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{Encryption:encryption.services.blob.enabled, KeySource:encryption.keySource, KeyVault:encryption.keyVaultProperties.keyVaultUri}" \
  -o table
# Expected: KeySource = Microsoft.Keyvault (if CMK was configured)
```

**EVIDENCE** -- capture for auditor:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, KeySource:encryption.keySource, InfraEncryption:encryption.requireInfrastructureEncryption}" \
  -o json > "$EVIDENCE_DIR/storage-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 19. Public Access Prevention (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check blob public access settings for all storage accounts
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, AllowBlobPublicAccess:allowBlobPublicAccess}" \
  -o table
```
- PASS: all accounts show `AllowBlobPublicAccess = false` (or null, which means public access is disabled by default for accounts created after 2023)
- FAIL: any account shows `AllowBlobPublicAccess = true`

**FIX** -- remediate if failing:
```bash
# Disable blob public access on a specific storage account
STORAGE_ACCOUNT="yourstorageaccount"

az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --allow-blob-public-access false
```
Gotchas:
- Disabling blob public access at the account level overrides any container-level public access settings
- New storage accounts (created after November 2023) have public access disabled by default
- Before disabling, verify no application relies on anonymous blob access (CDN scenarios, public websites)
- If you need selective public access (e.g., a specific CDN container), use Azure Front Door or CDN with private origin instead
- Azure Policy can enforce this setting across all storage accounts: `Microsoft.Storage/storageAccounts/allowBlobPublicAccess` should be `false`

**VERIFY** -- confirm the fix:
```bash
az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{Name:name, AllowBlobPublicAccess:allowBlobPublicAccess}" \
  -o table
# Expected: AllowBlobPublicAccess = false
```

**EVIDENCE** -- capture for auditor:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, AllowBlobPublicAccess:allowBlobPublicAccess}" \
  -o json > "$EVIDENCE_DIR/storage-public-access-$(date +%Y%m%d-%H%M%S).json"
```

---

### 20. Soft Delete (TSC: A1.2, CC6.1)

**DISCOVER** -- check current state:
```bash
# Check blob soft delete for all storage accounts
for SA in $(az storage account list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az storage account show --name "$SA" --query "resourceGroup" -o tsv)
  BLOB_DELETE=$(az storage account blob-service-properties show \
    --account-name "$SA" \
    --resource-group "$RG" \
    --query "{BlobSoftDelete:deleteRetentionPolicy.enabled, BlobRetentionDays:deleteRetentionPolicy.days}" \
    -o json 2>/dev/null)
  CONTAINER_DELETE=$(az storage account blob-service-properties show \
    --account-name "$SA" \
    --resource-group "$RG" \
    --query "{ContainerSoftDelete:containerDeleteRetentionPolicy.enabled, ContainerRetentionDays:containerDeleteRetentionPolicy.days}" \
    -o json 2>/dev/null)
  echo "SA=$SA $BLOB_DELETE $CONTAINER_DELETE"
done
```
- PASS: all accounts have blob soft delete enabled with retention >= 7 days AND container soft delete enabled with retention >= 7 days
- FAIL: soft delete disabled or retention < 7 days

**FIX** -- remediate if failing:
```bash
STORAGE_ACCOUNT="yourstorageaccount"

# Enable blob soft delete (14 days retention)
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-delete-retention true \
  --delete-retention-days 14

# Enable container soft delete (14 days retention)
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-container-delete-retention true \
  --container-delete-retention-days 14
```
Gotchas:
- Soft delete protects against accidental deletion -- deleted blobs/containers can be recovered within the retention period
- Soft-deleted data incurs storage costs during the retention period
- Soft delete does not protect against storage account deletion -- use resource locks for that
- Blob versioning (separate feature) provides point-in-time restore capability and is complementary to soft delete
- Azure Policy can enforce soft delete settings: `Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled` should be `true`

**VERIFY** -- confirm the fix:
```bash
az storage account blob-service-properties show \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{BlobSoftDelete:deleteRetentionPolicy.enabled, BlobRetentionDays:deleteRetentionPolicy.days, ContainerSoftDelete:containerDeleteRetentionPolicy.enabled, ContainerRetentionDays:containerDeleteRetentionPolicy.days}" \
  -o table
# Expected: both soft delete enabled with 14 days retention
```

**EVIDENCE** -- capture for auditor:
```bash
for SA in $(az storage account list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az storage account show --name "$SA" --query "resourceGroup" -o tsv)
  az storage account blob-service-properties show \
    --account-name "$SA" \
    --resource-group "$RG" \
    -o json
done > "$EVIDENCE_DIR/storage-soft-delete-$(date +%Y%m%d-%H%M%S).json"
```

---

### 21. Infrastructure Encryption (Double Encryption) (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Check infrastructure encryption (double encryption) setting
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, InfrastructureEncryption:encryption.requireInfrastructureEncryption}" \
  -o table
```
- PASS: accounts storing highly sensitive data show `InfrastructureEncryption = true`
- FAIL: infrastructure encryption is null/false on accounts that require it per your security policy

**FIX** -- remediate if failing:
```bash
# Infrastructure encryption CANNOT be enabled on an existing storage account.
# You must create a new account with it enabled and migrate data.

az storage account create \
  --name "yourstorageaccountnew" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --require-infrastructure-encryption true \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

# Then migrate data from old account to new account:
# az storage copy --source-account-name old --destination-account-name new ...
```
Gotchas:
- Infrastructure encryption (double encryption) is a creation-time-only setting -- it cannot be enabled on an existing account
- This provides two layers of encryption using two different algorithms (AES-256 at service level + AES-256 at infrastructure level)
- Not all storage account types support infrastructure encryption
- This is optional for most SOC 2 audits -- only required if your data classification policy mandates double encryption
- Enabling infrastructure encryption has no performance impact

**VERIFY** -- confirm the fix:
```bash
az storage account show \
  --name "yourstorageaccountnew" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{Name:name, InfrastructureEncryption:encryption.requireInfrastructureEncryption}" \
  -o table
# Expected: InfrastructureEncryption = true
```

**EVIDENCE** -- capture for auditor:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, InfrastructureEncryption:encryption.requireInfrastructureEncryption}" \
  -o json > "$EVIDENCE_DIR/storage-infra-encryption-$(date +%Y%m%d-%H%M%S).json"
```

---

### 22. Secure Transfer Required (HTTPS Only) (TSC: CC6.1, CC6.7)

**DISCOVER** -- check current state:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, HTTPSOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion}" \
  -o table
```
- PASS: all accounts show `HTTPSOnly = true` and `MinTLS = TLS1_2`
- FAIL: any account shows `HTTPSOnly = false` or `MinTLS` below TLS1_2

**FIX** -- remediate if failing:
```bash
STORAGE_ACCOUNT="yourstorageaccount"

# Enable HTTPS-only and set minimum TLS version
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --https-only true \
  --min-tls-version TLS1_2
```
Gotchas:
- HTTPS-only is enabled by default for new storage accounts
- TLS 1.0 and 1.1 are deprecated -- always enforce TLS 1.2 minimum
- Applications using older SDKs or tools may break when TLS 1.2 is enforced -- test first
- NFS Azure Blob Storage does not support HTTPS -- if you use NFS protocol, this setting must remain false for that account (use network isolation instead)

**VERIFY** -- confirm the fix:
```bash
az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{HTTPSOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion}" \
  -o table
# Expected: HTTPSOnly = true, MinTLS = TLS1_2
```

**EVIDENCE** -- capture for auditor:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, HTTPSOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion}" \
  -o json > "$EVIDENCE_DIR/storage-secure-transfer-$(date +%Y%m%d-%H%M%S).json"
```

---

### 23. Network Rules (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check network rules for all storage accounts
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DefaultAction:networkRuleSet.defaultAction, VNetRules:length(networkRuleSet.virtualNetworkRules), IPRules:length(networkRuleSet.ipRules), Bypass:networkRuleSet.bypass}" \
  -o table
```
- PASS: `DefaultAction = Deny` on all production storage accounts, with specific VNet rules or IP rules allowing access
- FAIL: `DefaultAction = Allow` (open to all networks)

**FIX** -- remediate if failing:
```bash
STORAGE_ACCOUNT="yourstorageaccount"

# Step 1: Add allowed VNet/subnet before changing default action
VNET_NAME="your-vnet"
SUBNET_NAME="your-subnet"
VNET_RG="your-vnet-rg"

# Enable service endpoint on the subnet first
az network vnet subnet update \
  --resource-group "$VNET_RG" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --service-endpoints Microsoft.Storage

# Add VNet rule
az storage account network-rule add \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME"

# Add specific IP (e.g., office IP)
az storage account network-rule add \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --ip-address "203.0.113.0/24"

# Step 2: Change default action to deny
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --default-action Deny

# Allow trusted Azure services (required for Azure Backup, Defender, etc.)
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --bypass AzureServices Logging Metrics
```
Gotchas:
- ALWAYS add your allowed VNet/IP rules BEFORE changing default action to Deny -- otherwise you lock yourself out
- `--bypass AzureServices` allows trusted Azure first-party services (Backup, Defender, etc.) to access the account
- Private endpoints provide the strongest network isolation (see control #34)
- Service endpoints are simpler but do not encrypt traffic at the Azure backbone level
- Changes to network rules take up to 30 seconds to propagate

**VERIFY** -- confirm the fix:
```bash
az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{DefaultAction:networkRuleSet.defaultAction, VNetRules:networkRuleSet.virtualNetworkRules[].id, IPRules:networkRuleSet.ipRules[].ipAddressOrRange, Bypass:networkRuleSet.bypass}" \
  -o json
# Expected: DefaultAction = Deny, with appropriate VNet/IP rules
```

**EVIDENCE** -- capture for auditor:
```bash
az storage account list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DefaultAction:networkRuleSet.defaultAction, VNetRules:networkRuleSet.virtualNetworkRules, IPRules:networkRuleSet.ipRules, Bypass:networkRuleSet.bypass}" \
  -o json > "$EVIDENCE_DIR/storage-network-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

## Azure SQL Controls

### 24. Transparent Data Encryption (TDE) (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# List all SQL servers and their TDE status
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    TDE=$(az sql db tde show \
      --server "$SERVER" \
      --database "$DB" \
      --resource-group "$RG" \
      --query "state" -o tsv)
    echo "SERVER=$SERVER DB=$DB TDE=$TDE"
  done
done
```
- PASS: all databases show `TDE = Enabled`
- FAIL: any database shows `TDE = Disabled` (extremely unlikely -- TDE is enabled by default since 2017)

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-sql-server"
SQL_DB="your-database"

# Enable TDE (if somehow disabled)
az sql db tde set \
  --server "$SQL_SERVER" \
  --database "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --status Enabled

# To use customer-managed key (CMK) instead of service-managed key:
KEY_VAULT_NAME="your-keyvault"
KEY_NAME="sql-tde-key"

# Create the key in Key Vault
az keyvault key create \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  --kty RSA \
  --size 2048

KEY_URI=$(az keyvault key show \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  --query "key.kid" -o tsv)

# Assign managed identity to SQL server
az sql server update \
  --name "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --assign-identity

SQL_IDENTITY=$(az sql server show \
  --name "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query "identity.principalId" -o tsv)

# Grant Key Vault access
az keyvault set-policy \
  --name "$KEY_VAULT_NAME" \
  --object-id "$SQL_IDENTITY" \
  --key-permissions get wrapKey unwrapKey

# Set TDE protector to CMK
az sql server tde-key set \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --server-key-type AzureKeyVault \
  --kid "$KEY_URI"
```
Gotchas:
- TDE is enabled by default on Azure SQL Database and cannot be disabled for new databases
- TDE can be disabled on Azure SQL Managed Instance but this is strongly discouraged
- CMK TDE requires Key Vault with soft delete and purge protection enabled
- If the Key Vault key is deleted or access is lost, the database becomes inaccessible (data-loss scenario)
- tempdb is also encrypted when TDE is enabled

**VERIFY** -- confirm the fix:
```bash
az sql db tde show \
  --server "$SQL_SERVER" \
  --database "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{State:state}" \
  -o table
# Expected: State = Enabled

# Verify TDE protector (CMK if configured)
az sql server tde-key show \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{Type:serverKeyType, KeyUri:uri}" \
  -o table
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    az sql db tde show --server "$SERVER" --database "$DB" --resource-group "$RG" -o json
  done
done > "$EVIDENCE_DIR/sql-tde-$(date +%Y%m%d-%H%M%S).json"
```

---

### 25. SQL Auditing (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check auditing settings on all SQL servers
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  AUDIT=$(az sql server audit-policy show \
    --server "$SERVER" \
    --resource-group "$RG" \
    --query "{State:state, StorageEndpoint:storageEndpoint, LogAnalyticsWorkspace:isAzureMonitorTargetEnabled, RetentionDays:retentionDays}" \
    -o json)
  echo "SERVER=$SERVER $AUDIT"
done
```
- PASS: audit state is `Enabled`, with a valid storage endpoint or Log Analytics workspace as destination, retention >= 90 days
- FAIL: audit state is `Disabled` or no destination configured

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-sql-server"
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Option A: Send audit logs to Log Analytics (recommended)
az sql server audit-policy update \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --state Enabled \
  --lats Enabled \
  --lawri "$WORKSPACE_ID"

# Option B: Send audit logs to Storage Account
STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/yourstorageaccount"

az sql server audit-policy update \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --state Enabled \
  --storage-account "$STORAGE_ACCOUNT_ID" \
  --retention-days 365
```
Gotchas:
- Server-level auditing applies to all databases on the server
- Database-level auditing can override server-level settings (avoid this complexity -- use server-level only)
- Log Analytics destination requires the SQL server to have a system-assigned managed identity
- Audit logs contain: operation type, principal name, timestamp, affected resource, result
- For high-volume databases, audit logs can be expensive -- use action groups to audit only security-relevant events

**VERIFY** -- confirm the fix:
```bash
az sql server audit-policy show \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{State:state, LogAnalytics:isAzureMonitorTargetEnabled, RetentionDays:retentionDays}" \
  -o table
# Expected: State = Enabled, LogAnalytics = true or valid storage endpoint
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  az sql server audit-policy show --server "$SERVER" --resource-group "$RG" -o json
done > "$EVIDENCE_DIR/sql-auditing-$(date +%Y%m%d-%H%M%S).json"
```

---

### 26. Firewall Rules (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List firewall rules on all SQL servers
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  echo "=== $SERVER ==="
  az sql server firewall-rule list \
    --server "$SERVER" \
    --resource-group "$RG" \
    --query "[].{Name:name, StartIP:startIpAddress, EndIP:endIpAddress}" \
    -o table

  # Check for "Allow Azure services" rule (0.0.0.0 - 0.0.0.0)
  ALLOW_AZURE=$(az sql server firewall-rule list \
    --server "$SERVER" \
    --resource-group "$RG" \
    --query "[?startIpAddress=='0.0.0.0' && endIpAddress=='0.0.0.0'].name" -o tsv)
  if [ -n "$ALLOW_AZURE" ]; then
    echo "WARNING: 'Allow Azure services' rule is enabled ($ALLOW_AZURE)"
  fi
done
```
- PASS: no `0.0.0.0 - 0.0.0.0` rule (Allow Azure services), firewall rules are specific IPs or small CIDR blocks
- FAIL: `Allow Azure services` rule exists, or overly broad IP ranges (e.g., `0.0.0.0 - 255.255.255.255`)

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-sql-server"

# Remove "Allow Azure services" rule
az sql server firewall-rule delete \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --name "AllowAllWindowsAzureIps"

# Remove overly broad rules
az sql server firewall-rule delete \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --name "overly-broad-rule-name"

# Add specific IP rules
az sql server firewall-rule create \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --name "office-ip" \
  --start-ip-address "203.0.113.10" \
  --end-ip-address "203.0.113.10"

# Better: use private endpoints instead of firewall rules (see control #34)
```
Gotchas:
- `AllowAllWindowsAzureIps` (0.0.0.0 - 0.0.0.0) allows ANY Azure service from ANY subscription to connect -- this is overly permissive
- Instead of "Allow Azure services," use VNet service endpoints or private endpoints
- The Azure Portal shows "Allow Azure services and resources to access this server" as a toggle -- this creates the 0.0.0.0 rule
- If your application runs on Azure App Service, use VNet integration + service endpoints instead of the Azure services rule
- Firewall rules do not apply to connections through private endpoints

**VERIFY** -- confirm the fix:
```bash
az sql server firewall-rule list \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name, StartIP:startIpAddress, EndIP:endIpAddress}" \
  -o table
# Expected: no 0.0.0.0 rule, only specific IPs
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  az sql server firewall-rule list --server "$SERVER" --resource-group "$RG" -o json
done > "$EVIDENCE_DIR/sql-firewall-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

### 27. Advanced Threat Protection (TSC: CC6.1, CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check Advanced Threat Protection (ATP) on all SQL servers
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  ATP=$(az sql server advanced-threat-protection-setting show \
    --server "$SERVER" \
    --resource-group "$RG" \
    --query "state" -o tsv 2>/dev/null)
  echo "SERVER=$SERVER ATP=$ATP"
done
```
- PASS: all servers show `state = Enabled`
- FAIL: any server shows `state = Disabled` or `New`

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-sql-server"

# Enable Advanced Threat Protection
az sql server advanced-threat-protection-setting update \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --state Enabled
```
Gotchas:
- ATP detects: SQL injection, SQL injection vulnerability, anomalous login patterns, data exfiltration, brute force attempts
- ATP is included with Defender for SQL (part of Defender for Cloud) -- enabling Defender for SQL enables ATP
- ATP alerts are visible in Defender for Cloud and can be sent to email/Action Groups
- No performance impact on the database -- ATP analyzes audit logs asynchronously
- ATP can be configured per-server or per-database (server-level is recommended)

**VERIFY** -- confirm the fix:
```bash
az sql server advanced-threat-protection-setting show \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{State:state}" \
  -o table
# Expected: State = Enabled
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  az sql server advanced-threat-protection-setting show \
    --server "$SERVER" --resource-group "$RG" -o json 2>/dev/null
done > "$EVIDENCE_DIR/sql-atp-$(date +%Y%m%d-%H%M%S).json"
```

---

### 28. Geo-Replication (TSC: A1.1, A1.2)

**DISCOVER** -- check current state:
```bash
# Check geo-replication links for all SQL databases
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    REPLICAS=$(az sql db replica list-links \
      --server "$SERVER" \
      --database "$DB" \
      --resource-group "$RG" \
      --query "[].{PartnerServer:partnerServer, PartnerDatabase:partnerDatabase, Role:role, ReplicationState:replicationState}" \
      -o json 2>/dev/null)
    if [ "$REPLICAS" = "[]" ] || [ -z "$REPLICAS" ]; then
      echo "NO_REPLICA: SERVER=$SERVER DB=$DB"
    else
      echo "REPLICATED: SERVER=$SERVER DB=$DB $REPLICAS"
    fi
  done
done

# Check for failover groups
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  az sql failover-group list \
    --server "$SERVER" \
    --resource-group "$RG" \
    --query "[].{Name:name, PartnerServers:partnerServers[].id, ReadWriteEndpoint:readWriteEndpoint.failoverPolicy}" \
    -o json 2>/dev/null
done
```
- PASS: production databases have at least one geo-replica or are part of a failover group
- FAIL: production databases with no geo-replication and no failover group

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-primary-server"
SQL_DB="your-database"
PARTNER_SERVER="your-secondary-server"
PARTNER_RG="your-secondary-rg"
PARTNER_LOCATION="westus2"

# Option A: Active geo-replication (manual failover)
# First, create the partner server if it does not exist
az sql server create \
  --name "$PARTNER_SERVER" \
  --resource-group "$PARTNER_RG" \
  --location "$PARTNER_LOCATION" \
  --admin-user "sqladmin" \
  --admin-password "<strong-password>"

# Create the geo-replica
az sql db replica create \
  --server "$SQL_SERVER" \
  --name "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --partner-server "$PARTNER_SERVER" \
  --partner-resource-group "$PARTNER_RG"

# Option B: Auto-failover group (recommended for production)
az sql failover-group create \
  --name "your-failover-group" \
  --server "$SQL_SERVER" \
  --resource-group "$RESOURCE_GROUP" \
  --partner-server "$PARTNER_SERVER" \
  --partner-resource-group "$PARTNER_RG" \
  --failover-policy Automatic \
  --grace-period 1 \
  --add-db "$SQL_DB"
```
Gotchas:
- Geo-replication is asynchronous -- there is always some replication lag (typically < 5 seconds)
- Failover groups provide a read-write listener endpoint that automatically redirects after failover
- The secondary region should be the Azure paired region for optimal performance and disaster recovery SLA
- Geo-replication doubles your database cost (you pay for the secondary)
- Dev/staging databases typically do not need geo-replication -- this is for production databases serving customers

**VERIFY** -- confirm the fix:
```bash
az sql db replica list-links \
  --server "$SQL_SERVER" \
  --database "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{PartnerServer:partnerServer, Role:role, ReplicationState:replicationState}" \
  -o table
# Expected: replicationState = CATCH_UP or SEEDING (initially), then CATCH_UP
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    az sql db replica list-links --server "$SERVER" --database "$DB" --resource-group "$RG" -o json 2>/dev/null
  done
  az sql failover-group list --server "$SERVER" --resource-group "$RG" -o json 2>/dev/null
done > "$EVIDENCE_DIR/sql-geo-replication-$(date +%Y%m%d-%H%M%S).json"
```

---

### 29. Long-Term Backup Retention (TSC: A1.2)

**DISCOVER** -- check current state:
```bash
# Check long-term retention (LTR) policies on all databases
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    LTR=$(az sql db ltr-policy show \
      --server "$SERVER" \
      --database "$DB" \
      --resource-group "$RG" \
      --query "{WeeklyRetention:weeklyRetention, MonthlyRetention:monthlyRetention, YearlyRetention:yearlyRetention, WeekOfYear:weekOfYear}" \
      -o json 2>/dev/null)
    echo "SERVER=$SERVER DB=$DB $LTR"
  done
done

# Also check short-term backup retention (PITR)
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    PITR=$(az sql db show \
      --server "$SERVER" \
      --name "$DB" \
      --resource-group "$RG" \
      --query "earliestRestoreDate" -o tsv)
    echo "SERVER=$SERVER DB=$DB PITR_earliest=$PITR"
  done
done
```
- PASS: LTR policy configured with at least monthly retention (e.g., `P12M` for 12 months), PITR retention >= 7 days
- FAIL: all LTR values are `PT0S` (zero -- not configured)

**FIX** -- remediate if failing:
```bash
SQL_SERVER="your-sql-server"
SQL_DB="your-database"

# Set long-term backup retention policy
az sql db ltr-policy set \
  --server "$SQL_SERVER" \
  --database "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --weekly-retention "P4W" \
  --monthly-retention "P12M" \
  --yearly-retention "P5Y" \
  --week-of-year 1

# Set short-term backup retention (PITR) to 14 days (default is 7)
az sql db str-policy set \
  --server "$SQL_SERVER" \
  --name "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --diffbackup-hours 12 \
  --retention-days 14
```
Gotchas:
- Azure SQL Database has automatic backups (full weekly, differential every 12 hours, transaction log every 5-10 minutes)
- Short-term retention (PITR) covers 1-35 days and is always enabled
- Long-term retention (LTR) extends beyond 35 days using weekly, monthly, and yearly policies
- LTR backups are stored in Azure-managed storage -- cost is based on RA-GRS storage pricing
- ISO 8601 duration format: P4W = 4 weeks, P12M = 12 months, P5Y = 5 years
- LTR is not available for Azure SQL Managed Instance Hyperscale tier

**VERIFY** -- confirm the fix:
```bash
az sql db ltr-policy show \
  --server "$SQL_SERVER" \
  --database "$SQL_DB" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{WeeklyRetention:weeklyRetention, MonthlyRetention:monthlyRetention, YearlyRetention:yearlyRetention}" \
  -o table
# Expected: WeeklyRetention=P4W, MonthlyRetention=P12M, YearlyRetention=P5Y
```

**EVIDENCE** -- capture for auditor:
```bash
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  for DB in $(az sql db list --server "$SERVER" --resource-group "$RG" --query "[?name != 'master'].name" -o tsv); do
    az sql db ltr-policy show --server "$SERVER" --database "$DB" --resource-group "$RG" -o json 2>/dev/null
  done
done > "$EVIDENCE_DIR/sql-ltr-policy-$(date +%Y%m%d-%H%M%S).json"
```

---

## Network Security Controls

### 30. NSG Flow Logs (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# List all NSGs and check which have flow logs enabled
for NSG_ID in $(az network nsg list --subscription "$SUBSCRIPTION_ID" --query "[].id" -o tsv); do
  NSG_NAME=$(echo "$NSG_ID" | rev | cut -d'/' -f1 | rev)
  NSG_RG=$(echo "$NSG_ID" | rev | cut -d'/' -f5 | rev)

  FLOW_LOG=$(az network watcher flow-log list \
    --location "$LOCATION" \
    --query "[?targetResourceId=='$NSG_ID'].{Name:name, Enabled:enabled, Version:format.version, RetentionDays:retentionPolicy.days, TrafficAnalytics:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled}" \
    -o json 2>/dev/null)

  if [ "$FLOW_LOG" = "[]" ] || [ -z "$FLOW_LOG" ]; then
    echo "NO_FLOW_LOG: $NSG_NAME ($NSG_RG)"
  else
    echo "FLOW_LOG: $NSG_NAME $FLOW_LOG"
  fi
done
```
- PASS: all NSGs have flow logs enabled, version 2, with retention >= 90 days and traffic analytics enabled
- FAIL: NSGs without flow logs, or flow logs using version 1

**FIX** -- remediate if failing:
```bash
NSG_NAME="your-nsg"
NSG_RG="your-nsg-rg"
STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/yourstorageaccount"
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Ensure Network Watcher is enabled in the region
az network watcher configure \
  --resource-group "NetworkWatcherRG" \
  --locations "$LOCATION" \
  --enabled true

# Create NSG flow log (version 2 with traffic analytics)
az network watcher flow-log create \
  --name "flowlog-$NSG_NAME" \
  --nsg "$NSG_NAME" \
  --resource-group "$NSG_RG" \
  --location "$LOCATION" \
  --storage-account "$STORAGE_ACCOUNT_ID" \
  --enabled true \
  --format JSON \
  --log-version 2 \
  --retention 90 \
  --traffic-analytics true \
  --workspace "$WORKSPACE_ID"
```
Gotchas:
- Network Watcher must be enabled in each region where you have NSGs
- Flow log version 2 includes additional fields (bytes, packets) -- always use V2
- Traffic Analytics provides flow visualization in Azure Monitor and requires a Log Analytics workspace
- Flow logs are stored in the storage account -- cost is based on storage volume
- Flow logs capture traffic at the NSG level, not at the individual NIC level
- Processing interval for traffic analytics: 10 minutes (default) or 60 minutes (cheaper)

**VERIFY** -- confirm the fix:
```bash
az network watcher flow-log list \
  --location "$LOCATION" \
  --query "[].{Name:name, Enabled:enabled, Version:format.version, RetentionDays:retentionPolicy.days, TrafficAnalytics:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled}" \
  -o table
# Expected: all flow logs enabled, version 2, retention >= 90, traffic analytics true
```

**EVIDENCE** -- capture for auditor:
```bash
az network watcher flow-log list \
  --location "$LOCATION" \
  -o json > "$EVIDENCE_DIR/nsg-flow-logs-$(date +%Y%m%d-%H%M%S).json"
```

---

### 31. NSG Rules Audit (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Find overly permissive NSG rules
for NSG in $(az network nsg list --subscription "$SUBSCRIPTION_ID" --query "[].{Name:name, RG:resourceGroup}" -o json | jq -r '.[] | "\(.Name)|\(.RG)"'); do
  NSG_NAME=$(echo "$NSG" | cut -d'|' -f1)
  NSG_RG=$(echo "$NSG" | cut -d'|' -f2)

  # Check for rules allowing Any source on SSH (22), RDP (3389), or all ports
  az network nsg rule list \
    --nsg-name "$NSG_NAME" \
    --resource-group "$NSG_RG" \
    --query "[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].{Name:name, Priority:priority, Source:sourceAddressPrefix, DestPort:destinationPortRange, Protocol:protocol}" \
    -o table
done
```
- PASS: no inbound rules allowing `*` or `0.0.0.0/0` or `Internet` as source, especially on ports 22, 3389, or all ports
- FAIL: rules allowing unrestricted inbound access on management ports or all ports

**FIX** -- remediate if failing:
```bash
NSG_NAME="your-nsg"
NSG_RG="your-nsg-rg"

# Remove the overly permissive rule
az network nsg rule delete \
  --nsg-name "$NSG_NAME" \
  --resource-group "$NSG_RG" \
  --name "bad-allow-all-ssh"

# Replace with restrictive rule (specific source IP)
az network nsg rule create \
  --nsg-name "$NSG_NAME" \
  --resource-group "$NSG_RG" \
  --name "allow-ssh-from-office" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes "203.0.113.0/24" \
  --destination-port-ranges 22 \
  --source-port-ranges "*" \
  --destination-address-prefixes "*"

# For RDP, prefer Azure Bastion instead of direct NSG rules
# For SSH, prefer Azure Bastion or Just-In-Time (JIT) VM access via Defender
```
Gotchas:
- Azure Bastion provides secure RDP/SSH without exposing management ports on the public internet
- JIT VM access (Defender for Servers P2) automatically opens NSG rules for a limited time on request
- Default NSG rules allow all outbound and deny all inbound (except from VNet and load balancer)
- Priority 65000-65500 are default rules that cannot be modified
- Application Security Groups (ASGs) simplify NSG rules for multi-tier applications

**VERIFY** -- confirm the fix:
```bash
# Re-run the discovery command to confirm no overly permissive rules remain
az network nsg rule list \
  --nsg-name "$NSG_NAME" \
  --resource-group "$NSG_RG" \
  --query "[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].{Name:name, DestPort:destinationPortRange}" \
  -o table
# Expected: no output (no overly permissive rules)
```

**EVIDENCE** -- capture for auditor:
```bash
for NSG in $(az network nsg list --subscription "$SUBSCRIPTION_ID" --query "[].{Name:name, RG:resourceGroup}" -o json | jq -r '.[] | "\(.Name)|\(.RG)"'); do
  NSG_NAME=$(echo "$NSG" | cut -d'|' -f1)
  NSG_RG=$(echo "$NSG" | cut -d'|' -f2)
  echo "=== $NSG_NAME ==="
  az network nsg rule list --nsg-name "$NSG_NAME" --resource-group "$NSG_RG" -o json
done > "$EVIDENCE_DIR/nsg-rules-audit-$(date +%Y%m%d-%H%M%S).json"
```

---

### 32. Azure Firewall or NVA (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check for Azure Firewall instances
az network firewall list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, ProvisioningState:provisioningState, ThreatIntelMode:threatIntelMode, SKU:sku.tier}" \
  -o table

# Check for Azure Firewall policies
az network firewall policy list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, ThreatIntelMode:threatIntelMode, DNSProxy:dnsSettings.enableProxy}" \
  -o table

# Check for route tables directing traffic through the firewall
az network route-table list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, Routes:routes[].{Prefix:addressPrefix, NextHop:nextHopType, NextHopIP:nextHopIpAddress}}" \
  -o json
```
- PASS: Azure Firewall or NVA exists, traffic from production subnets routes through it, threat intelligence is enabled
- FAIL: no centralized firewall, production traffic goes directly to the internet

**FIX** -- remediate if failing:
```bash
# Note: Azure Firewall is a significant infrastructure component.
# This is a simplified setup -- production deployment should use Terraform (see module below).

FIREWALL_NAME="soc2-firewall"
VNET_NAME="your-hub-vnet"
FIREWALL_SUBNET="AzureFirewallSubnet"  # Must be named exactly this

# Create the firewall subnet (if it does not exist)
az network vnet subnet create \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$FIREWALL_SUBNET" \
  --address-prefixes "10.0.1.0/26"

# Create public IP for the firewall
az network public-ip create \
  --resource-group "$RESOURCE_GROUP" \
  --name "${FIREWALL_NAME}-pip" \
  --sku Standard \
  --allocation-method Static

# Create the firewall (Standard tier includes threat intelligence)
az network firewall create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FIREWALL_NAME" \
  --location "$LOCATION" \
  --vnet-name "$VNET_NAME" \
  --tier Standard \
  --threat-intel-mode Alert

# Get the firewall private IP
FIREWALL_IP=$(az network firewall show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FIREWALL_NAME" \
  --query "ipConfigurations[0].privateIPAddress" -o tsv)

# Create route table to send traffic through the firewall
az network route-table create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-udr-through-firewall"

az network route-table route create \
  --resource-group "$RESOURCE_GROUP" \
  --route-table-name "soc2-udr-through-firewall" \
  --name "default-through-firewall" \
  --address-prefix "0.0.0.0/0" \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address "$FIREWALL_IP"

# Associate route table with production subnet
az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "production-subnet" \
  --route-table "soc2-udr-through-firewall"
```
Gotchas:
- Azure Firewall costs approximately $1.25/hour (Standard tier) -- it is not free
- The firewall subnet MUST be named "AzureFirewallSubnet" and have at least a /26 prefix
- Azure Firewall Premium adds TLS inspection, IDPS, and URL filtering -- consider for high-security environments
- For cost-sensitive environments, consider Azure Firewall Basic tier or third-party NVA
- Hub-and-spoke topology is the recommended architecture for centralized firewall

**VERIFY** -- confirm the fix:
```bash
az network firewall show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FIREWALL_NAME" \
  --query "{Name:name, ProvisioningState:provisioningState, ThreatIntelMode:threatIntelMode}" \
  -o table
# Expected: ProvisioningState = Succeeded, ThreatIntelMode = Alert or Deny
```

**EVIDENCE** -- capture for auditor:
```bash
az network firewall list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/azure-firewall-$(date +%Y%m%d-%H%M%S).json"

az network route-table list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/route-tables-$(date +%Y%m%d-%H%M%S).json"
```

---

### 33. DDoS Protection (TSC: A1.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check if DDoS Protection Plan exists
az network ddos-protection list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, ProvisioningState:provisioningState}" \
  -o table

# Check which VNets have DDoS Protection enabled
az network vnet list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DDoSProtection:enableDdosProtection, DDoSPlan:ddosProtectionPlan.id}" \
  -o table
```
- PASS: DDoS Protection plan exists and is associated with production VNets (`enableDdosProtection = true`)
- FAIL: no DDoS Protection plan, or production VNets not protected

**FIX** -- remediate if failing:
```bash
# Create DDoS Protection Plan
az network ddos-protection create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-ddos-plan" \
  --location "$LOCATION"

DDOS_PLAN_ID=$(az network ddos-protection show \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-ddos-plan" \
  --query "id" -o tsv)

# Associate with production VNet
az network vnet update \
  --resource-group "$RESOURCE_GROUP" \
  --name "your-production-vnet" \
  --ddos-protection true \
  --ddos-protection-plan "$DDOS_PLAN_ID"
```
Gotchas:
- DDoS Protection Standard costs approximately $2,944/month per plan (covers up to 100 public IPs)
- One plan can protect multiple VNets across multiple subscriptions
- Azure provides DDoS Infrastructure Protection (Basic) for free on all public endpoints -- Standard adds telemetry, alerting, cost protection, and faster mitigation
- For cost-sensitive environments, consider using DDoS IP Protection (per-IP pricing) instead of the full plan
- DDoS Protection Standard includes a cost protection SLA -- if you are DDoSed, Azure credits the scale-out costs

**VERIFY** -- confirm the fix:
```bash
az network vnet show \
  --resource-group "$RESOURCE_GROUP" \
  --name "your-production-vnet" \
  --query "{Name:name, DDoSProtection:enableDdosProtection, DDoSPlan:ddosProtectionPlan.id}" \
  -o table
# Expected: DDoSProtection = true, DDoSPlan = <plan-id>
```

**EVIDENCE** -- capture for auditor:
```bash
az network ddos-protection list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/ddos-protection-$(date +%Y%m%d-%H%M%S).json"

az network vnet list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DDoSProtection:enableDdosProtection, DDoSPlan:ddosProtectionPlan.id}" \
  -o json > "$EVIDENCE_DIR/vnet-ddos-status-$(date +%Y%m%d-%H%M%S).json"
```

---

### 34. Private Endpoints (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List all private endpoints
az network private-endpoint list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, Subnet:subnet.id, TargetResource:privateLinkServiceConnections[0].privateLinkServiceId, GroupId:privateLinkServiceConnections[0].groupIds[0]}" \
  -o table

# Check which PaaS services do NOT have private endpoints
# Storage accounts without private endpoints:
az storage account list --subscription "$SUBSCRIPTION_ID" \
  --query "[?networkRuleSet.defaultAction=='Allow'].{Name:name, DefaultAction:networkRuleSet.defaultAction}" \
  -o table

# SQL servers without private endpoints:
for SERVER in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  RG=$(az sql server show --name "$SERVER" --query "resourceGroup" -o tsv)
  PE_COUNT=$(az network private-endpoint-connection list \
    --id "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.Sql/servers/$SERVER" \
    --query "length(@)" -o tsv 2>/dev/null)
  if [ "${PE_COUNT:-0}" = "0" ]; then
    echo "NO_PRIVATE_ENDPOINT: SQL Server $SERVER"
  fi
done
```
- PASS: all production PaaS services (Storage, SQL, Key Vault) have private endpoints configured
- FAIL: PaaS services accessible only via public endpoints

**FIX** -- remediate if failing:
```bash
VNET_NAME="your-vnet"
SUBNET_NAME="private-endpoints-subnet"

# Create a dedicated subnet for private endpoints (if it does not exist)
az network vnet subnet create \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --address-prefixes "10.0.10.0/24" \
  --disable-private-endpoint-network-policies true

# Private endpoint for Storage Account
STORAGE_ACCOUNT_ID=$(az storage account show \
  --name "yourstorageaccount" \
  --resource-group "$RESOURCE_GROUP" \
  --query "id" -o tsv)

az network private-endpoint create \
  --resource-group "$RESOURCE_GROUP" \
  --name "pe-storage" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME" \
  --private-connection-resource-id "$STORAGE_ACCOUNT_ID" \
  --group-id blob \
  --connection-name "pe-storage-connection"

# Private endpoint for SQL Server
SQL_SERVER_ID=$(az sql server show \
  --name "your-sql-server" \
  --resource-group "$RESOURCE_GROUP" \
  --query "id" -o tsv)

az network private-endpoint create \
  --resource-group "$RESOURCE_GROUP" \
  --name "pe-sql" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME" \
  --private-connection-resource-id "$SQL_SERVER_ID" \
  --group-id sqlServer \
  --connection-name "pe-sql-connection"

# Private endpoint for Key Vault
KV_ID=$(az keyvault show \
  --name "your-keyvault" \
  --resource-group "$RESOURCE_GROUP" \
  --query "id" -o tsv)

az network private-endpoint create \
  --resource-group "$RESOURCE_GROUP" \
  --name "pe-keyvault" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME" \
  --private-connection-resource-id "$KV_ID" \
  --group-id vault \
  --connection-name "pe-kv-connection"

# Configure Private DNS zones for name resolution
az network private-dns zone create \
  --resource-group "$RESOURCE_GROUP" \
  --name "privatelink.blob.core.windows.net"

az network private-dns link vnet create \
  --resource-group "$RESOURCE_GROUP" \
  --zone-name "privatelink.blob.core.windows.net" \
  --name "blob-dns-link" \
  --virtual-network "$VNET_NAME" \
  --registration-enabled false

# Create DNS zone group for automatic DNS record management
az network private-endpoint dns-zone-group create \
  --resource-group "$RESOURCE_GROUP" \
  --endpoint-name "pe-storage" \
  --name "default" \
  --private-dns-zone "privatelink.blob.core.windows.net" \
  --zone-name "blob"
```
Gotchas:
- Private endpoints require Private DNS zones for name resolution -- without DNS, connections will still go to the public endpoint
- Each PaaS service type has a different group ID: blob, file, queue, table (Storage); sqlServer (SQL); vault (Key Vault)
- Private endpoints cost approximately $0.01/hour per endpoint + data processing charges
- After creating private endpoints, disable public access on the PaaS service for full isolation
- Private endpoint subnet must have `privateEndpointNetworkPolicies` disabled (the `--disable-private-endpoint-network-policies` flag)

**VERIFY** -- confirm the fix:
```bash
az network private-endpoint list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, TargetResource:privateLinkServiceConnections[0].privateLinkServiceId, Status:privateLinkServiceConnections[0].privateLinkServiceConnectionState.status}" \
  -o table
# Expected: all private endpoints show Status = Approved
```

**EVIDENCE** -- capture for auditor:
```bash
az network private-endpoint list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/private-endpoints-$(date +%Y%m%d-%H%M%S).json"
```

---

### 35. Service Endpoints (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# List service endpoints configured on all subnets
az network vnet list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{VNet:name, Subnets:subnets[].{Subnet:name, ServiceEndpoints:serviceEndpoints[].service}}" \
  -o json
```
- PASS: production subnets have service endpoints for the Azure services they access (Microsoft.Storage, Microsoft.Sql, Microsoft.KeyVault)
- FAIL: no service endpoints configured on subnets that access PaaS services (and private endpoints are also not in use)

**FIX** -- remediate if failing:
```bash
VNET_NAME="your-vnet"
SUBNET_NAME="your-production-subnet"

# Add service endpoints for Storage, SQL, and Key Vault
az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --service-endpoints Microsoft.Storage Microsoft.Sql Microsoft.KeyVault
```
Gotchas:
- Service endpoints are free -- no additional cost
- Service endpoints keep traffic on the Azure backbone network but do not provide full network isolation (the PaaS public endpoint still exists)
- For full isolation, use private endpoints (control #34) -- service endpoints are the minimum acceptable configuration
- Adding or removing service endpoints causes a brief subnet connectivity disruption (seconds) -- plan maintenance window
- Service endpoints must be enabled on both the subnet AND the target resource (e.g., storage account network rules)

**VERIFY** -- confirm the fix:
```bash
az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --query "serviceEndpoints[].service" \
  -o table
# Expected: Microsoft.Storage, Microsoft.Sql, Microsoft.KeyVault
```

**EVIDENCE** -- capture for auditor:
```bash
az network vnet list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{VNet:name, Subnets:subnets[].{Subnet:name, ServiceEndpoints:serviceEndpoints[].service}}" \
  -o json > "$EVIDENCE_DIR/service-endpoints-$(date +%Y%m%d-%H%M%S).json"
```

---

## Key Vault Controls

### 36. Soft Delete and Purge Protection (TSC: CC6.1, A1.2)

**DISCOVER** -- check current state:
```bash
# Check soft delete and purge protection on all Key Vaults
az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection, RetentionDays:properties.softDeleteRetentionInDays}" \
  -o table
```
- PASS: all Key Vaults show `SoftDelete = true` and `PurgeProtection = true` with retention >= 7 days (90 days recommended)
- FAIL: any Key Vault with purge protection disabled

**FIX** -- remediate if failing:
```bash
KEY_VAULT_NAME="your-keyvault"

# Enable purge protection (soft delete is now always enabled by default)
az keyvault update \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-purge-protection true
```
Gotchas:
- Soft delete is enabled by default for all new Key Vaults and CANNOT be disabled (enforced since February 2025)
- Purge protection prevents permanent deletion during the retention period -- once enabled, it CANNOT be disabled
- Default soft delete retention is 90 days (configurable: 7-90 days at creation time only)
- This is a one-way operation: enabling purge protection is irreversible
- If a key/secret/certificate is deleted, it moves to a "soft-deleted" state and can be recovered within the retention period

**VERIFY** -- confirm the fix:
```bash
az keyvault show \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "{SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection, RetentionDays:properties.softDeleteRetentionInDays}" \
  -o table
# Expected: SoftDelete = true, PurgeProtection = true, RetentionDays >= 7
```

**EVIDENCE** -- capture for auditor:
```bash
az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection, RetentionDays:properties.softDeleteRetentionInDays}" \
  -o json > "$EVIDENCE_DIR/keyvault-soft-delete-$(date +%Y%m%d-%H%M%S).json"
```

---

### 37. Access Policies or RBAC (TSC: CC6.1, CC6.3)

**DISCOVER** -- check current state:
```bash
# Check access model (vault access policy vs RBAC)
az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, AccessModel:properties.enableRbacAuthorization}" \
  -o table

# For vaults using access policies, list who has access
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[?properties.enableRbacAuthorization!=true || properties.enableRbacAuthorization==null].name" -o tsv); do
  echo "=== $KV (Access Policies) ==="
  az keyvault show --name "$KV" \
    --query "properties.accessPolicies[].{ObjectId:objectId, KeyPerms:permissions.keys, SecretPerms:permissions.secrets, CertPerms:permissions.certificates}" \
    -o table
done

# For vaults using RBAC, list role assignments
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[?properties.enableRbacAuthorization==true].{Name:name, Id:id}" -o json | jq -r '.[] | "\(.Name)|\(.Id)"'); do
  KV_NAME=$(echo "$KV" | cut -d'|' -f1)
  KV_ID=$(echo "$KV" | cut -d'|' -f2)
  echo "=== $KV_NAME (RBAC) ==="
  az role assignment list --scope "$KV_ID" \
    --query "[].{Principal:principalName, Role:roleDefinitionName}" \
    -o table
done
```
- PASS: RBAC is enabled (preferred), role assignments follow least privilege, no overly broad access
- FAIL: access policies grant excessive permissions (e.g., all key/secret/certificate permissions to non-admin users)

**FIX** -- remediate if failing:
```bash
KEY_VAULT_NAME="your-keyvault"

# Option A (recommended): Convert to RBAC model
az keyvault update \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-rbac-authorization true

# Grant specific RBAC roles (least privilege)
# Key Vault Secrets User (read secrets only):
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "<user-or-sp-object-id>" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME"

# Key Vault Administrator (full access -- for admin only):
az role assignment create \
  --role "Key Vault Administrator" \
  --assignee "<admin-object-id>" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME"

# Option B: If staying on access policies, restrict permissions
az keyvault set-policy \
  --name "$KEY_VAULT_NAME" \
  --object-id "<user-object-id>" \
  --secret-permissions get list \
  --key-permissions get list \
  --certificate-permissions get list
```
Gotchas:
- RBAC is the recommended access model -- it integrates with Entra ID Conditional Access and PIM
- Converting from access policies to RBAC: existing access policies are preserved but no longer evaluated -- you must create equivalent RBAC role assignments first
- Built-in Key Vault RBAC roles: Key Vault Administrator, Key Vault Secrets Officer, Key Vault Secrets User, Key Vault Crypto Officer, Key Vault Crypto User, Key Vault Certificates Officer, Key Vault Reader
- Access policies support up to 1024 policies per vault

**VERIFY** -- confirm the fix:
```bash
az keyvault show \
  --name "$KEY_VAULT_NAME" \
  --query "{AccessModel:properties.enableRbacAuthorization}" \
  -o table
# Expected: AccessModel = true (RBAC enabled)

az role assignment list \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME" \
  --query "[].{Principal:principalName, Role:roleDefinitionName}" \
  -o table
# Expected: only necessary roles assigned
```

**EVIDENCE** -- capture for auditor:
```bash
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  KV_ID=$(az keyvault show --name "$KV" --query "id" -o tsv)
  echo "=== $KV ==="
  az keyvault show --name "$KV" --query "properties.{AccessModel:enableRbacAuthorization, AccessPolicies:accessPolicies}" -o json
  az role assignment list --scope "$KV_ID" -o json 2>/dev/null
done > "$EVIDENCE_DIR/keyvault-access-$(date +%Y%m%d-%H%M%S).json"
```

---

### 38. Key Rotation (TSC: CC6.1)

**DISCOVER** -- check current state:
```bash
# Check key rotation policies on all Key Vault keys
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  for KEY in $(az keyvault key list --vault-name "$KV" --query "[].name" -o tsv 2>/dev/null); do
    ROTATION=$(az keyvault key rotation-policy show \
      --vault-name "$KV" \
      --name "$KEY" \
      --query "{AutoRotate:lifetimeActions[?action.type=='Rotate'].trigger, Notify:lifetimeActions[?action.type=='Notify'].trigger}" \
      -o json 2>/dev/null)
    echo "KV=$KV KEY=$KEY $ROTATION"
  done
done
```
- PASS: keys have rotation policies configured with automatic rotation
- FAIL: no rotation policies, or keys that have not been rotated in > 365 days

**FIX** -- remediate if failing:
```bash
KEY_VAULT_NAME="your-keyvault"
KEY_NAME="your-key"

# Set automatic key rotation policy (rotate every 90 days, notify 30 days before expiry)
az keyvault key rotation-policy update \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  --value '{
    "lifetimeActions": [
      {
        "trigger": {"timeAfterCreate": "P90D"},
        "action": {"type": "Rotate"}
      },
      {
        "trigger": {"timeBeforeExpiry": "P30D"},
        "action": {"type": "Notify"}
      }
    ],
    "attributes": {
      "expiryTime": "P1Y"
    }
  }'

# Manually rotate a key immediately
az keyvault key rotate \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME"
```
Gotchas:
- Automatic key rotation creates a new version of the key -- applications using the key without version pinning will automatically use the new version
- Applications that pin to a specific key version will NOT automatically use the rotated key -- they must be updated
- Key rotation policies use ISO 8601 duration: P90D = 90 days, P1Y = 1 year
- Notification actions send events to Event Grid -- you must configure an Event Grid subscription to receive them
- For keys used as TDE protectors or CMK for storage, Azure services handle version rotation automatically

**VERIFY** -- confirm the fix:
```bash
az keyvault key rotation-policy show \
  --vault-name "$KEY_VAULT_NAME" \
  --name "$KEY_NAME" \
  -o json
# Expected: lifetimeActions contains a Rotate trigger
```

**EVIDENCE** -- capture for auditor:
```bash
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].name" -o tsv); do
  for KEY in $(az keyvault key list --vault-name "$KV" --query "[].name" -o tsv 2>/dev/null); do
    echo "KV=$KV KEY=$KEY"
    az keyvault key rotation-policy show --vault-name "$KV" --name "$KEY" -o json 2>/dev/null
  done
done > "$EVIDENCE_DIR/keyvault-key-rotation-$(date +%Y%m%d-%H%M%S).json"
```

---

### 39. Diagnostic Logging (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check diagnostic settings on all Key Vaults
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].{Name:name, Id:id}" -o json | jq -r '.[] | "\(.Name)|\(.Id)"'); do
  KV_NAME=$(echo "$KV" | cut -d'|' -f1)
  KV_ID=$(echo "$KV" | cut -d'|' -f2)
  DIAG=$(az monitor diagnostic-settings list \
    --resource "$KV_ID" \
    --query "[].{Name:name, WorkspaceId:workspaceId, Logs:logs[?enabled==true].category}" \
    -o json 2>/dev/null)
  echo "KV=$KV_NAME $DIAG"
done
```
- PASS: all Key Vaults have diagnostic settings sending AuditEvent logs to Log Analytics
- FAIL: no diagnostic settings, or AuditEvent category not enabled

**FIX** -- remediate if failing:
```bash
KEY_VAULT_NAME="your-keyvault"
KV_ID=$(az keyvault show --name "$KEY_VAULT_NAME" --query "id" -o tsv)
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

az monitor diagnostic-settings create \
  --name "soc2-kv-diagnostics" \
  --resource "$KV_ID" \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "AuditEvent", "enabled": true, "retentionPolicy": {"enabled": false, "days": 0}},
    {"category": "AzurePolicyEvaluationDetails", "enabled": true, "retentionPolicy": {"enabled": false, "days": 0}}
  ]' \
  --metrics '[
    {"category": "AllMetrics", "enabled": true, "retentionPolicy": {"enabled": false, "days": 0}}
  ]'
```
Gotchas:
- AuditEvent logs capture every key/secret/certificate operation (get, list, set, delete, etc.)
- Retention is controlled at the Log Analytics workspace level, not at the diagnostic setting level (retention policy in diagnostic settings is deprecated)
- High-volume Key Vault operations can generate significant log volume -- monitor ingestion costs
- You can send to multiple destinations (Log Analytics + Storage Account) for redundancy

**VERIFY** -- confirm the fix:
```bash
KV_ID=$(az keyvault show --name "$KEY_VAULT_NAME" --query "id" -o tsv)
az monitor diagnostic-settings list \
  --resource "$KV_ID" \
  --query "[].{Name:name, Logs:logs[?enabled==true].category}" \
  -o table
# Expected: AuditEvent category enabled
```

**EVIDENCE** -- capture for auditor:
```bash
for KV in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource "$KV" -o json 2>/dev/null
done > "$EVIDENCE_DIR/keyvault-diagnostics-$(date +%Y%m%d-%H%M%S).json"
```

---

### 40. Network Restrictions (TSC: CC6.1, CC6.6)

**DISCOVER** -- check current state:
```bash
# Check network restrictions on all Key Vaults
az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DefaultAction:properties.networkAcls.defaultAction, Bypass:properties.networkAcls.bypass, IPRules:properties.networkAcls.ipRules, VNetRules:properties.networkAcls.virtualNetworkRules}" \
  -o json
```
- PASS: `DefaultAction = Deny` with specific IP or VNet rules, or private endpoint configured
- FAIL: `DefaultAction = Allow` (open to all networks)

**FIX** -- remediate if failing:
```bash
KEY_VAULT_NAME="your-keyvault"

# Add network rules before changing default action
az keyvault network-rule add \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --ip-address "203.0.113.0/24"

az keyvault network-rule add \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "your-vnet" \
  --subnet "your-subnet"

# Change default action to deny
az keyvault update \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --default-action Deny \
  --bypass AzureServices
```
Gotchas:
- ALWAYS add your allowed IPs and VNet rules BEFORE changing default action to Deny
- `--bypass AzureServices` allows trusted Azure first-party services to access the vault (required for Azure Backup, Disk Encryption, etc.)
- Private endpoints provide the strongest isolation (see control #34)
- Network rules do not apply to operations performed by the vault owner (who has management plane access)
- If you lock yourself out, you can still manage network rules via the management plane (Azure Portal, CLI)

**VERIFY** -- confirm the fix:
```bash
az keyvault show \
  --name "$KEY_VAULT_NAME" \
  --query "{DefaultAction:properties.networkAcls.defaultAction, Bypass:properties.networkAcls.bypass}" \
  -o table
# Expected: DefaultAction = Deny, Bypass = AzureServices
```

**EVIDENCE** -- capture for auditor:
```bash
az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, DefaultAction:properties.networkAcls.defaultAction, Bypass:properties.networkAcls.bypass, IPRules:length(properties.networkAcls.ipRules), VNetRules:length(properties.networkAcls.virtualNetworkRules)}" \
  -o json > "$EVIDENCE_DIR/keyvault-network-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

## Azure Monitor / Log Analytics Controls

### 41. Workspace Configuration (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Detailed workspace configuration
az monitor log-analytics workspace list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, SKU:sku.name, RetentionDays:retentionInDays, DailyCapGB:workspaceCapping.dailyQuotaGb, ProvisioningState:provisioningState}" \
  -o table

# Check workspace data export rules
for WS in $(az monitor log-analytics workspace list --subscription "$SUBSCRIPTION_ID" --query "[].{Name:name, RG:resourceGroup}" -o json | jq -r '.[] | "\(.Name)|\(.RG)"'); do
  WS_NAME=$(echo "$WS" | cut -d'|' -f1)
  WS_RG=$(echo "$WS" | cut -d'|' -f2)
  echo "=== $WS_NAME ==="
  az monitor log-analytics workspace data-export list \
    --resource-group "$WS_RG" \
    --workspace-name "$WS_NAME" \
    -o table 2>/dev/null
done
```
- PASS: SKU is PerGB2018, retention >= 365 days, provisioning state is Succeeded
- FAIL: legacy SKU (Free, Standalone), retention < 365 days, or no workspace at all

**FIX** -- remediate if failing:
```bash
# Update workspace SKU and retention (if workspace exists)
az monitor log-analytics workspace update \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --retention-time 365 \
  --sku PerGB2018

# Set a daily cap to control costs (optional but recommended)
az monitor log-analytics workspace update \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --quota 5

# Configure data export for long-term archival (to Storage Account)
az monitor log-analytics workspace data-export create \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --name "archive-to-storage" \
  --destination "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/yourstorageaccount" \
  --tables SecurityEvent Heartbeat AzureActivity
```
Gotchas:
- PerGB2018 is the current recommended SKU -- legacy SKUs (PerNode, Standalone) are not recommended for new workspaces
- Daily cap stops data ingestion when reached -- set it high enough to avoid missing critical security events
- Data export is continuous and near-real-time -- use it for long-term archival beyond the workspace retention period
- Archive tier (up to 12 years) provides cost-effective long-term retention within the workspace itself
- Table-level retention allows different retention periods for different data types

**VERIFY** -- confirm the fix:
```bash
az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "soc2-law" \
  --query "{SKU:sku.name, RetentionDays:retentionInDays, DailyCap:workspaceCapping.dailyQuotaGb}" \
  -o table
# Expected: SKU=PerGB2018, RetentionDays=365
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor log-analytics workspace list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/workspace-config-$(date +%Y%m%d-%H%M%S).json"
```

---

### 42. Diagnostic Settings on All Resources (TSC: CC7.1, CC7.2)

**DISCOVER** -- check current state:
```bash
# Check which resources have diagnostic settings configured
# This queries all resources in the subscription and checks for diagnostic settings
az resource list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[?type!='Microsoft.Network/networkSecurityGroups/securityRules' && type!='Microsoft.Network/virtualNetworks/subnets'].{Name:name, Type:type, Id:id}" \
  -o json | jq -r '.[] | "\(.Name)|\(.Type)|\(.Id)"' | while read RESOURCE; do
    NAME=$(echo "$RESOURCE" | cut -d'|' -f1)
    TYPE=$(echo "$RESOURCE" | cut -d'|' -f2)
    ID=$(echo "$RESOURCE" | cut -d'|' -f3)
    DIAG_COUNT=$(az monitor diagnostic-settings list \
      --resource "$ID" \
      --query "length(@)" -o tsv 2>/dev/null)
    if [ "${DIAG_COUNT:-0}" = "0" ]; then
      echo "NO_DIAGNOSTICS: $NAME ($TYPE)"
    fi
done
```
- PASS: all critical resources (Key Vaults, SQL Servers, Storage Accounts, NSGs, VNets, App Services) have diagnostic settings
- FAIL: critical resources without diagnostic settings

**FIX** -- remediate if failing:
```bash
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Use Azure Policy to enforce diagnostic settings across all resources
# Deploy the built-in policy initiative "Enable Azure Monitor for VMs" or create custom policies

# Example: Enable diagnostics on a specific resource
RESOURCE_ID="<resource-id>"

az monitor diagnostic-settings create \
  --name "soc2-diagnostics" \
  --resource "$RESOURCE_ID" \
  --workspace "$WORKSPACE_ID" \
  --logs '[{"categoryGroup": "allLogs", "enabled": true}]' \
  --metrics '[{"category": "AllMetrics", "enabled": true}]'

# For bulk deployment, use Azure Policy with DeployIfNotExists effect:
# Built-in policy: "Deploy Diagnostic Settings for Key Vault to Log Analytics workspace"
# Built-in policy: "Deploy Diagnostic Settings for Azure SQL Database to Log Analytics workspace"
# Assign these policies at the subscription level:
az policy assignment create \
  --name "diag-keyvault-to-law" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/bef3f64c-5290-43b7-85b0-9b254eef4c47" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --params '{"logAnalytics": {"value": "'"$WORKSPACE_ID"'"}}'
```
Gotchas:
- Not all resource types support diagnostic settings -- check the resource provider documentation
- `categoryGroup: allLogs` enables all log categories -- this is simpler than specifying each category individually
- Azure Policy with DeployIfNotExists effect can automatically create diagnostic settings on new resources
- Policy remediation can backfill diagnostic settings on existing resources: `az policy remediation create ...`
- Some log categories generate very high volume -- monitor ingestion costs after enabling

**VERIFY** -- confirm the fix:
```bash
# Re-run the discovery script and confirm fewer (ideally zero) resources without diagnostics
az monitor diagnostic-settings list \
  --resource "$RESOURCE_ID" \
  --query "[].{Name:name, Workspace:workspaceId}" \
  -o table
# Expected: at least one diagnostic setting per critical resource
```

**EVIDENCE** -- capture for auditor:
```bash
# Capture diagnostic settings for all critical resource types
for KV_ID in $(az keyvault list --subscription "$SUBSCRIPTION_ID" --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource "$KV_ID" -o json 2>/dev/null
done > "$EVIDENCE_DIR/diagnostics-keyvaults-$(date +%Y%m%d-%H%M%S).json"

for SQL_ID in $(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource "$SQL_ID" -o json 2>/dev/null
done > "$EVIDENCE_DIR/diagnostics-sql-$(date +%Y%m%d-%H%M%S).json"

for SA_ID in $(az storage account list --subscription "$SUBSCRIPTION_ID" --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource "$SA_ID" -o json 2>/dev/null
done > "$EVIDENCE_DIR/diagnostics-storage-$(date +%Y%m%d-%H%M%S).json"
```

---

### 43. Alert Rules for Security Events (TSC: CC7.2, CC7.3)

**DISCOVER** -- check current state:
```bash
# List all scheduled query alert rules (log-based alerts)
az monitor scheduled-query list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, RG:resourceGroup, Enabled:enabled, Severity:severity}" \
  -o table
```
- PASS: alert rules exist for role changes, resource deletions, policy changes, and other security events
- FAIL: no scheduled query alert rules for security events

**FIX** -- remediate if failing:
```bash
ACTION_GROUP_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/actionGroups/soc2-security-alerts"
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/soc2-law"

# Alert: Role assignment changes
az monitor scheduled-query create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-role-assignment-changes" \
  --description "Alert on Azure role assignment changes" \
  --scopes "$WORKSPACE_ID" \
  --condition "count 'AzureActivity | where OperationNameValue =~ \"Microsoft.Authorization/roleAssignments/write\" | where ActivityStatusValue =~ \"Success\"' > 0" \
  --condition-query 'AzureActivity | where OperationNameValue =~ "Microsoft.Authorization/roleAssignments/write" | where ActivityStatusValue =~ "Success"' \
  --window-size 5m \
  --evaluation-frequency 5m \
  --severity 2 \
  --action-groups "$ACTION_GROUP_ID"

# Alert: Resource deletions
az monitor scheduled-query create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-resource-deletions" \
  --description "Alert on resource deletions" \
  --scopes "$WORKSPACE_ID" \
  --condition "count 'AzureActivity | where OperationNameValue endswith \"/delete\" | where ActivityStatusValue =~ \"Success\"' > 0" \
  --condition-query 'AzureActivity | where OperationNameValue endswith "/delete" | where ActivityStatusValue =~ "Success"' \
  --window-size 5m \
  --evaluation-frequency 5m \
  --severity 2 \
  --action-groups "$ACTION_GROUP_ID"

# Alert: Key Vault access anomalies
az monitor scheduled-query create \
  --resource-group "$RESOURCE_GROUP" \
  --name "soc2-keyvault-access" \
  --description "Alert on Key Vault secret access outside business hours" \
  --scopes "$WORKSPACE_ID" \
  --condition "count 'AzureDiagnostics | where ResourceType == \"VAULTS\" | where OperationName == \"SecretGet\" | where TimeGenerated between (datetime(00:00) .. datetime(06:00)) or TimeGenerated between (datetime(22:00) .. datetime(23:59))' > 0" \
  --condition-query 'AzureDiagnostics | where ResourceType == "VAULTS" | where OperationName == "SecretGet"' \
  --window-size 1h \
  --evaluation-frequency 1h \
  --severity 1 \
  --action-groups "$ACTION_GROUP_ID"
```
Gotchas:
- Scheduled query alerts run KQL queries against Log Analytics workspace data
- Alert rules cost approximately $1.50/month per rule
- Evaluation frequency determines how often the query runs -- balance responsiveness vs cost
- KQL query must return a numeric result that is compared against the threshold
- For complex queries, test them in the Log Analytics query editor first

**VERIFY** -- confirm the fix:
```bash
az monitor scheduled-query list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, Enabled:enabled, Severity:severity}" \
  -o table
# Expected: alert rules for role changes, resource deletions, Key Vault access
```

**EVIDENCE** -- capture for auditor:
```bash
az monitor scheduled-query list \
  --subscription "$SUBSCRIPTION_ID" \
  -o json > "$EVIDENCE_DIR/query-alert-rules-$(date +%Y%m%d-%H%M%S).json"
```

---

### 44. Workbooks and Dashboards (TSC: CC4.1, CC7.1)

**DISCOVER** -- check current state:
```bash
# List Azure Monitor workbooks
az monitor app-insights workbook list \
  --resource-group "$RESOURCE_GROUP" \
  --category "workbook" \
  --query "[].{Name:displayName, Kind:kind}" \
  -o table 2>/dev/null

# Check for shared dashboards
az portal dashboard list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[].{Name:name}" \
  -o table 2>/dev/null
```
- PASS: a security overview workbook or dashboard exists, providing visibility into security posture
- FAIL: no security workbooks or dashboards

**FIX** -- remediate if failing:
```bash
# Azure Monitor Workbooks are best created via the Portal or ARM templates.
# Deploy the built-in security workbook templates:

# Option A: Use built-in Microsoft Sentinel workbook templates (if Sentinel is deployed)
# Portal: Microsoft Sentinel > Workbooks > Templates > search "Security"

# Option B: Create a custom workbook via ARM template
# The workbook JSON is too complex for CLI creation -- use the Portal or Terraform:
# Portal: Azure Monitor > Workbooks > New > Add query
# Useful queries for a security dashboard:

# 1. Failed sign-ins in the last 24h:
#    SigninLogs | where ResultType != 0 | summarize count() by UserDisplayName, ResultType, bin(TimeGenerated, 1h)

# 2. Privileged role activations:
#    AuditLogs | where OperationName == "Add member to role" | project TimeGenerated, InitiatedBy, TargetResources

# 3. Resource changes:
#    AzureActivity | where OperationNameValue endswith "/write" or OperationNameValue endswith "/delete" | summarize count() by OperationNameValue, Caller, bin(TimeGenerated, 1h)

# 4. Key Vault operations:
#    AzureDiagnostics | where ResourceType == "VAULTS" | summarize count() by OperationName, CallerIPAddress, bin(TimeGenerated, 1h)

# 5. Security alerts from Defender:
#    SecurityAlert | summarize count() by AlertName, AlertSeverity, bin(TimeGenerated, 1h)
```
Gotchas:
- Workbooks are interactive and support parameters, filters, and drill-down -- preferred over static dashboards
- Azure Portal dashboards have a 200-tile limit and limited interactivity
- Workbooks can be shared at resource group or subscription level
- If Microsoft Sentinel is deployed, it includes pre-built security workbook templates
- Export workbook JSON for version control and repeatable deployment

**VERIFY** -- confirm the fix:
```bash
# Verification is visual -- open the workbook in the Azure Portal and confirm it displays data
# Check that the workbook queries return data:
az monitor log-analytics query \
  --workspace "soc2-law" \
  --analytics-query "AzureActivity | take 1" \
  -o table
# Expected: at least one row (confirms data is flowing to the workspace)
```

**EVIDENCE** -- capture for auditor:
```bash
# Capture a summary of data flowing into the workspace
az monitor log-analytics query \
  --workspace "soc2-law" \
  --analytics-query "Usage | where TimeGenerated > ago(7d) | summarize TotalGB=sum(Quantity)/1024 by DataType | order by TotalGB desc" \
  -o json > "$EVIDENCE_DIR/workspace-data-summary-$(date +%Y%m%d-%H%M%S).json"
```

---

## Terraform Azure Module

A complete, production-ready Terraform module that deploys the core Azure SOC 2 controls as infrastructure-as-code.

```hcl
# ============================================================================
# SOC 2 Azure Controls - Complete Terraform Module
# ============================================================================
# Usage:
#   module "soc2_azure" {
#     source              = "./modules/soc2-azure"
#     company_name        = "acme"
#     security_email      = "security@acme.com"
#     location            = "eastus"
#     resource_group_name = "acme-security-rg"
#   }
# ============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

# ============================================================================
# Variables
# ============================================================================

variable "company_name" {
  description = "Company name used in resource naming"
  type        = string
}

variable "security_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group for SOC 2 resources"
  type        = string
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 365
}

variable "soft_delete_retention_days" {
  description = "Key Vault soft delete retention in days"
  type        = number
  default     = 90
}

variable "storage_soft_delete_retention_days" {
  description = "Storage account blob soft delete retention in days"
  type        = number
  default     = 14
}

variable "nsg_flow_log_retention_days" {
  description = "NSG flow log retention in days"
  type        = number
  default     = 90
}

variable "defender_plans" {
  description = "List of Defender for Cloud plans to enable"
  type        = list(string)
  default = [
    "VirtualMachines",
    "SqlServers",
    "AppServices",
    "StorageAccounts",
    "KeyVaults",
    "Arm",
    "Dns",
    "OpenSourceRelationalDatabases",
    "Containers",
    "CloudPosture",
  ]
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# Locals
# ============================================================================

locals {
  default_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Module    = "soc2-azure"
    Purpose   = "SOC2-compliance"
  })

  name_prefix = var.company_name
}

# ============================================================================
# Data Sources
# ============================================================================

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

# ============================================================================
# Resource Group
# ============================================================================

resource "azurerm_resource_group" "soc2" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.default_tags
}

# ============================================================================
# Log Analytics Workspace (365-day retention)
# ============================================================================

resource "azurerm_log_analytics_workspace" "soc2" {
  name                = "${local.name_prefix}-soc2-law"
  location            = azurerm_resource_group.soc2.location
  resource_group_name = azurerm_resource_group.soc2.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.default_tags
}

# ============================================================================
# Diagnostic Settings for Activity Log
# ============================================================================

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${local.name_prefix}-activity-log-export"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.soc2.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "ServiceHealth"
  }
  enabled_log {
    category = "Alert"
  }
  enabled_log {
    category = "Recommendation"
  }
  enabled_log {
    category = "Policy"
  }
  enabled_log {
    category = "Autoscale"
  }
  enabled_log {
    category = "ResourceHealth"
  }
}

# ============================================================================
# Defender for Cloud - Enable all plans
# ============================================================================

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = toset(var.defender_plans)
  tier          = "Standard"
  resource_type = each.value
}

# ============================================================================
# Key Vault (with soft delete and purge protection)
# ============================================================================

resource "azurerm_key_vault" "soc2" {
  name                        = "${local.name_prefix}-soc2-kv"
  location                    = azurerm_resource_group.soc2.location
  resource_group_name         = azurerm_resource_group.soc2.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = var.soft_delete_retention_days
  purge_protection_enabled    = true
  enable_rbac_authorization   = true
  tags                        = local.default_tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# Grant the deploying identity Key Vault Administrator role
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.soc2.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Key Vault diagnostic settings
resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "soc2-kv-diagnostics"
  target_resource_id         = azurerm_key_vault.soc2.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.soc2.id

  enabled_log {
    category = "AuditEvent"
  }
  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }
  metric {
    category = "AllMetrics"
  }
}

# ============================================================================
# Storage Account (secure defaults)
# ============================================================================

resource "azurerm_storage_account" "soc2" {
  name                            = "${replace(local.name_prefix, "-", "")}soc2sa"
  resource_group_name             = azurerm_resource_group.soc2.name
  location                        = azurerm_resource_group.soc2.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false
  tags                            = local.default_tags

  blob_properties {
    delete_retention_policy {
      days = var.storage_soft_delete_retention_days
    }
    container_delete_retention_policy {
      days = var.storage_soft_delete_retention_days
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }
}

# Storage account diagnostic settings
resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "soc2-storage-diagnostics"
  target_resource_id         = azurerm_storage_account.soc2.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.soc2.id

  metric {
    category = "Transaction"
  }
}

# ============================================================================
# NSG Flow Logs
# ============================================================================

resource "azurerm_network_watcher" "soc2" {
  name                = "${local.name_prefix}-nw"
  location            = azurerm_resource_group.soc2.location
  resource_group_name = azurerm_resource_group.soc2.name
  tags                = local.default_tags
}

# Note: NSG Flow Logs require an existing NSG. This resource is created
# per-NSG. Below is a template -- instantiate for each NSG in your environment.
#
# resource "azurerm_network_watcher_flow_log" "example" {
#   network_watcher_name = azurerm_network_watcher.soc2.name
#   resource_group_name  = azurerm_resource_group.soc2.name
#   name                 = "flowlog-example-nsg"
#   network_security_group_id = azurerm_network_security_group.example.id
#   storage_account_id        = azurerm_storage_account.soc2.id
#   enabled                   = true
#   version                   = 2
#
#   retention_policy {
#     enabled = true
#     days    = var.nsg_flow_log_retention_days
#   }
#
#   traffic_analytics {
#     enabled               = true
#     workspace_id          = azurerm_log_analytics_workspace.soc2.workspace_id
#     workspace_region      = azurerm_log_analytics_workspace.soc2.location
#     workspace_resource_id = azurerm_log_analytics_workspace.soc2.id
#     interval_in_minutes   = 10
#   }
# }

# ============================================================================
# Action Group (notification channel)
# ============================================================================

resource "azurerm_monitor_action_group" "security" {
  name                = "${local.name_prefix}-soc2-security-alerts"
  resource_group_name = azurerm_resource_group.soc2.name
  short_name          = "soc2sec"
  tags                = local.default_tags

  email_receiver {
    name          = "security-team"
    email_address = var.security_email
  }
}

# ============================================================================
# Activity Log Alerts (security events)
# ============================================================================

resource "azurerm_monitor_activity_log_alert" "policy_changes" {
  name                = "${local.name_prefix}-soc2-policy-changes"
  resource_group_name = azurerm_resource_group.soc2.name
  scopes              = [data.azurerm_subscription.current.id]
  description         = "Alert on Azure Policy assignment changes"
  tags                = local.default_tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/policyAssignments/write"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

resource "azurerm_monitor_activity_log_alert" "role_changes" {
  name                = "${local.name_prefix}-soc2-role-changes"
  resource_group_name = azurerm_resource_group.soc2.name
  scopes              = [data.azurerm_subscription.current.id]
  description         = "Alert on role assignment changes"
  tags                = local.default_tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

resource "azurerm_monitor_activity_log_alert" "rg_deletions" {
  name                = "${local.name_prefix}-soc2-rg-deletions"
  resource_group_name = azurerm_resource_group.soc2.name
  scopes              = [data.azurerm_subscription.current.id]
  description         = "Alert on resource group deletions"
  tags                = local.default_tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Resources/subscriptions/resourceGroups/delete"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

resource "azurerm_monitor_activity_log_alert" "nsg_changes" {
  name                = "${local.name_prefix}-soc2-nsg-changes"
  resource_group_name = azurerm_resource_group.soc2.name
  scopes              = [data.azurerm_subscription.current.id]
  description         = "Alert on NSG rule changes"
  tags                = local.default_tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Network/networkSecurityGroups/securityRules/write"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

resource "azurerm_monitor_activity_log_alert" "sql_firewall_changes" {
  name                = "${local.name_prefix}-soc2-sql-firewall-changes"
  resource_group_name = azurerm_resource_group.soc2.name
  scopes              = [data.azurerm_subscription.current.id]
  description         = "Alert on SQL Server firewall rule changes"
  tags                = local.default_tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Sql/servers/firewallRules/write"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }
}

# ============================================================================
# Auto-Provisioning (Defender agents)
# ============================================================================

resource "azurerm_security_center_auto_provisioning" "default" {
  auto_provision = "On"
}

# ============================================================================
# Outputs
# ============================================================================

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = azurerm_log_analytics_workspace.soc2.id
}

output "log_analytics_workspace_name" {
  description = "Log Analytics workspace name"
  value       = azurerm_log_analytics_workspace.soc2.name
}

output "key_vault_id" {
  description = "Key Vault resource ID"
  value       = azurerm_key_vault.soc2.id
}

output "key_vault_name" {
  description = "Key Vault name"
  value       = azurerm_key_vault.soc2.name
}

output "storage_account_id" {
  description = "Storage account resource ID"
  value       = azurerm_storage_account.soc2.id
}

output "storage_account_name" {
  description = "Storage account name"
  value       = azurerm_storage_account.soc2.name
}

output "action_group_id" {
  description = "Action group resource ID for security alerts"
  value       = azurerm_monitor_action_group.security.id
}
```

---

## Important Edge Cases

### TDE on Azure SQL: Enabled by Default

Transparent Data Encryption is enabled by default on Azure SQL Database and **cannot be disabled** for new databases (since 2017). If you find a database with TDE disabled, it was either:
- Created before 2017 and never had TDE enabled
- An Azure SQL Managed Instance where TDE was explicitly disabled (possible but not recommended)

To check and remediate:
```bash
# This should always return Enabled for Azure SQL Database
az sql db tde show \
  --server "your-server" \
  --database "your-db" \
  --resource-group "your-rg" \
  --query "state" -o tsv
```

### Key Vault Soft Delete: Mandatory Since February 2025

Soft delete is now enabled by default and **cannot be disabled** on any Key Vault. Purge protection is still optional but strongly recommended (and required for CMK encryption scenarios). Once purge protection is enabled, it **cannot be disabled**.

### Defender for Cloud: Per-Plan Billing

Each Defender plan is billed independently. Common pricing (approximate, check current pricing):
| Plan | Unit | Approximate Cost |
|---|---|---|
| Servers P1 | per server/month | $5 |
| Servers P2 | per server/month | $15 |
| SQL Servers | per instance/month | $15 |
| Storage | per storage account/month | $10 |
| Key Vaults | per vault/month | $0.02/10k operations |
| App Services | per instance/month | $15 |
| Containers | per vCore/month | $7 |
| ARM | per subscription/month | $4 |

### Conditional Access: Requires Entra ID P1/P2

- Basic Conditional Access policies require **Entra ID P1** license
- Risk-based policies (sign-in risk, user risk) require **Entra ID P2** license
- PIM (Privileged Identity Management) requires **Entra ID P2** license
- Without these licenses, you cannot use these features -- consider purchasing the license or using alternative controls (manual access reviews, per-user MFA)

### NSG Flow Logs: V2 Required

NSG Flow Logs version 2 provides:
- All V1 fields (tuples, byte counts)
- Additional: flow state (begin/continue/end), packets, bytes per direction
- Required for Traffic Analytics

Always use V2:
```bash
az network watcher flow-log update \
  --name "your-flow-log" \
  --location "$LOCATION" \
  --log-version 2
```

### Activity Log: 90-Day Built-In Retention

The Azure Activity Log provides only 90 days of built-in retention. For SOC 2, you need 365+ days. The solution is to export Activity Log data to Log Analytics workspace (control #8) or Storage Account.

```bash
# Verify export is configured
az monitor diagnostic-settings subscription list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].{Name:name, Workspace:workspaceId}" \
  -o table
```

Without this export, you lose visibility into events older than 90 days -- an auditor will flag this as a control failure.

### "Allow Azure Services" on SQL: Overly Permissive

The `AllowAllWindowsAzureIps` firewall rule (0.0.0.0 - 0.0.0.0) allows **any** Azure resource from **any** subscription and **any** tenant to connect to your SQL server. This includes:
- Other customers' Azure resources
- Azure resources in subscriptions you do not control
- Compromised Azure VMs anywhere in Azure

Use VNet service endpoints or private endpoints instead:
```bash
# Check if the rule exists
az sql server firewall-rule list \
  --server "your-server" \
  --resource-group "your-rg" \
  --query "[?startIpAddress=='0.0.0.0']" \
  -o table

# Remove it
az sql server firewall-rule delete \
  --server "your-server" \
  --resource-group "your-rg" \
  --name "AllowAllWindowsAzureIps"
```
