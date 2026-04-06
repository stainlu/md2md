# Section 04: Policies with Decision Logic

> previous approach: `{{IDENTITY_PROVIDER}}` placeholder — agent fills in a name.
> new approach: the agent already discovered the company uses Okta with MFA enforced, AWS with CloudTrail enabled, GitHub with branch protection. the policy text references these ACTUAL controls. each conditional block is selected based on intake data, not guessed.

---

## how policy generation works

the agent completed intake (section 01) and infrastructure discovery (section 02–03). it now holds structured facts:

```
intake.infrastructure.cloud_provider = "AWS"
intake.infrastructure.identity_provider = "Okta"
intake.infrastructure.source_control = "GitHub"
intake.infrastructure.ci_cd = "GitHub Actions"
intake.infrastructure.monitoring = "Datadog"
intake.infrastructure.ticketing = "Linear"
intake.infrastructure.communication = "Slack"
intake.infrastructure.mdm = "Jamf"
intake.infrastructure.edr = "CrowdStrike"
intake.infrastructure.password_manager = "1Password"
intake.infrastructure.iac_tool = "Terraform"
intake.data.pii_handled = true
intake.data.phi_handled = false
intake.compliance.compliance_platform = "Vanta"
discovery.okta.mfa_enforced = true
discovery.aws.cloudtrail_enabled = true
discovery.aws.guardduty_enabled = true
discovery.github.branch_protection_enabled = true
```

for each policy below, the agent:
1. reads the decision points
2. selects the matching conditional blocks
3. renders the final policy with actual tool names and discovered states
4. strips all conditional markers from the output

conditional syntax used in templates:
- `[IF condition:]` ... `[END IF]` — include this block when condition is true
- `[IF NOT condition:]` ... `[END IF]` — include this block when condition is false
- conditions reference intake and discovery data directly

every policy shares this header structure:

```
# [Policy Name]
**[Company Name]**
**Version:** 1.0
**Effective Date:** [date agent generates the policy]
**Last Reviewed:** [same date]
**Owner:** [from intake.people]
**Approved By:** [from intake.people]
**TSC Coverage:** [listed criteria]
```

every policy has these sections: Purpose, Scope, Roles and Responsibilities, Policy Statements, Exceptions, Review Schedule.

---

## Policy 1: Information Security Policy

**TSC Coverage:** CC1.1, CC1.2, CC1.3, CC1.4, CC1.5, CC2.1, CC2.2, CC2.3
**Generate when:** always — this is the master policy

### Decision points:
- If compliance_platform exists: reference it as the central evidence repository
- If cloud = AWS: reference AWS-specific services (CloudTrail, GuardDuty, Config)
- If cloud = GCP: reference GCP-specific services (Cloud Audit Logs, Security Command Center)
- If cloud = Azure: reference Azure-specific services (Azure Monitor, Defender for Cloud)
- If mdm exists: include endpoint management line
- If edr exists: include endpoint detection line
- If mdm = none AND edr = none: include "endpoint controls under evaluation" note

### Template:

```markdown
# Information Security Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.security_lead]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC1.1, CC1.2, CC1.3, CC1.4, CC1.5, CC2.1, CC2.2, CC2.3

## 1. Purpose

This policy establishes the information security program for [intake.company.name].
It defines the security controls, governance structure, and responsibilities that protect
company and customer data across all systems, personnel, and operations.

This is the master security policy. All other policies referenced below are subordinate
and must be read in conjunction with this document.

## 2. Scope

This policy applies to all employees, contractors, and third parties who access
[intake.company.name] systems or data. It covers:
- All production systems and infrastructure
- All corporate systems and endpoints
- All third-party services used to deliver [intake.company.product]
- All data classified as Restricted, Confidential, or Internal (see Data Classification Policy)

## 3. Roles and Responsibilities

| Role | Person | Responsibilities |
|------|--------|-----------------|
| Executive Sponsor | [intake.people.ceo] | Approves security program, allocates budget, accepts residual risk |
| Security Lead | [intake.people.security_lead] | Manages day-to-day security operations, leads incident response, maintains policies |
| Engineering Lead | [intake.people.cto] | Ensures security controls are implemented in infrastructure and code |
| HR Lead | [intake.people.hr_lead] | Manages background checks, onboarding/offboarding security procedures, training |
| Compliance Owner | [intake.people.compliance_owner] | Coordinates SOC 2 audit, manages evidence collection, vendor reviews |
| All Employees | Everyone | Follow security policies, complete training, report incidents |

## 4. Security Program Components

[intake.company.name] maintains the following security controls:

- **Access Control** — all authentication through [intake.infrastructure.identity_provider] with MFA enforced; role-based access control; quarterly access reviews (see Access Control Policy)
- **Encryption** — AES-256 at rest, TLS 1.2+ in transit; keys managed through [IF cloud = AWS:]AWS KMS[END IF][IF cloud = GCP:]Cloud KMS[END IF][IF cloud = Azure:]Azure Key Vault[END IF] (see Encryption Policy)
- **Logging and Monitoring** — centralized logging via [intake.infrastructure.monitoring]; [IF cloud = AWS:]CloudTrail for API audit trail, GuardDuty for threat detection[END IF][IF cloud = GCP:]Cloud Audit Logs for API audit trail, Security Command Center for threat detection[END IF][IF cloud = Azure:]Azure Monitor for audit trail, Defender for Cloud for threat detection[END IF]; alerts for anomalous activity
- **Incident Response** — documented plan with severity levels P1-P4 and response SLAs; response team led by [intake.people.security_lead]; communication via [intake.infrastructure.communication] (see Incident Response Policy)
- **Change Management** — all changes via pull request in [intake.infrastructure.source_control]; CI/CD pipeline via [intake.infrastructure.ci_cd]; infrastructure as code via [intake.infrastructure.iac_tool]; no manual production changes (see Change Management Policy)
- **Vendor Management** — risk assessment before onboarding; annual review of critical vendors; DPA and breach notification requirements (see Vendor Management Policy)
- **Business Continuity** — automated backups, multi-AZ deployment, DR tested annually (see Business Continuity and DR Policy)
- **Risk Management** — formal risk assessment annually and after material changes; risk register maintained [IF compliance_platform exists:]in [intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:]in a dedicated spreadsheet[END IF] (see Risk Assessment Policy)
- **People Security** — background checks, security awareness training, phishing simulations, onboarding/offboarding checklists (see HR Security Policy)
[IF mdm exists:]- **Endpoint Security** — devices managed through [intake.infrastructure.mdm]; disk encryption enforced; [IF edr exists:][intake.infrastructure.edr] for endpoint detection and response[END IF]
[END IF]
[IF mdm = none AND edr = none:]- **Endpoint Security** — disk encryption required on all company devices; endpoint management solution under evaluation
[END IF]
- **Data Protection** — four-tier data classification (Restricted, Confidential, Internal, Public); retention schedules defined; disposal methods by classification (see Data Classification Policy)

## 5. Data Classification

| Level | Definition | Examples | Handling |
|-------|-----------|----------|----------|
| Restricted | Highest sensitivity — legal, regulatory, or severe business impact if exposed | Customer PII, credentials, encryption keys, SOC 2 reports | Encrypted at rest and in transit, access logged, need-to-know only |
| Confidential | Business-sensitive — material impact if exposed | Customer data (non-PII), financial records, contracts, employee records | Encrypted at rest, access restricted by role |
| Internal | For internal use — minor impact if exposed | Internal docs, architecture diagrams, meeting notes | Share within company, do not expose externally |
| Public | No sensitivity — intended for external consumption | Marketing content, public docs, open source code | No special handling required |

## 6. Policy Framework

This Information Security Policy is supported by the following policies, each addressing specific control domains:

| Policy | TSC Coverage | Owner |
|--------|-------------|-------|
| Access Control Policy | CC6.1-CC6.3, CC6.6-CC6.8 | [intake.people.security_lead] |
| Incident Response Policy | CC7.3-CC7.5 | [intake.people.security_lead] |
| Change Management Policy | CC8.1 | [intake.people.cto] |
| Risk Assessment Policy | CC3.1-CC3.4 | [intake.people.security_lead] |
| Data Classification and Handling Policy | CC6.1, CC6.7 | [intake.people.security_lead] |
| Acceptable Use Policy | CC1.4, CC2.2 | [intake.people.hr_lead] |
| Vendor Management Policy | CC9.2 | [intake.people.compliance_owner] |
| Business Continuity and DR Policy | A1.1-A1.3 | [intake.people.cto] |
| Encryption Policy | CC6.1, CC6.7 | [intake.people.cto] |
| HR Security Policy | CC1.4 | [intake.people.hr_lead] |
| Data Retention and Disposal Policy | CC6.5 | [intake.people.compliance_owner] |

## 7. Exceptions

Any exception to this policy or its subordinate policies must be:
1. Documented with business justification
2. Approved by [intake.people.security_lead]
3. Time-limited (maximum 90 days, then re-evaluate)
4. Recorded in the risk register with risk acceptance if applicable
5. Critical/High risk exceptions require additional approval from [intake.people.ceo]

## 8. Enforcement

Violations of this policy may result in disciplinary action, up to and including
termination. Suspected violations should be reported to [intake.people.security_lead]
via [intake.infrastructure.communication] #security channel or email.

## 9. Review Schedule

This policy is reviewed and updated:
- At least annually
- After significant changes to infrastructure, personnel, or business operations
- After any P1 or P2 security incident
- When required by regulatory or contractual changes
```

---

## Policy 2: Access Control Policy

**TSC Coverage:** CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8
**Generate when:** always

### Decision points:
- If IdP = Okta: reference Okta MFA policies, Okta groups, Okta lifecycle management
- If IdP = Google Workspace: reference 2-Step Verification enforcement, Google Groups, Google Admin console
- If IdP = Azure AD: reference Conditional Access policies, Azure AD groups, Azure AD lifecycle
- If cloud = AWS: reference IAM roles, AWS SSO, assume-role patterns
- If cloud = GCP: reference IAM bindings, Workload Identity, service accounts
- If source_control = GitHub: reference GitHub org membership, team-based access
- If source_control = GitLab: reference GitLab group membership, project-level access
- If mdm exists: include device enrollment in onboarding
- If compliance_platform exists: reference it for access review evidence storage

### Template:

```markdown
# Access Control Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.security_lead]
**Approved By:** [intake.people.cto]
**TSC Coverage:** CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8

## 1. Purpose

Defines how [intake.company.name] manages user access to all systems and data.
Ensures only authorized personnel have appropriate access at all times, following
the principle of least privilege.

## 2. Scope

All systems, applications, cloud infrastructure, and data stores used by
[intake.company.name] to deliver [intake.company.product] and conduct business operations.

## 3. Authentication Requirements

- All users MUST authenticate via [intake.infrastructure.identity_provider] (SSO) for every application that supports it
- MFA is REQUIRED for all accounts — no exceptions
[IF IdP = Okta:]
- MFA method: Okta Verify (push notification or TOTP), FIDO2 hardware keys, or biometric authenticator. SMS-based MFA is prohibited.
- Okta sign-on policy must enforce MFA at every authentication event, not just new devices
- Okta session timeout: 12 hours maximum, re-authentication required after
[END IF]
[IF IdP = Google Workspace:]
- MFA method: Google 2-Step Verification enforced organization-wide via Admin console. Acceptable methods: security key (FIDO2), Google Authenticator (TOTP), Google prompts. SMS-based 2SV is prohibited.
- Session timeout: 12 hours via Google session control policies
- Advanced Protection Program encouraged for admin accounts
[END IF]
[IF IdP = Azure AD:]
- MFA method: Microsoft Authenticator (push or TOTP), FIDO2 security keys. SMS-based MFA is prohibited.
- Azure AD Conditional Access policies enforce MFA for all cloud apps
- Session timeout: 12 hours via Conditional Access session controls
[END IF]
- Service accounts use API keys, OAuth tokens, or cloud IAM roles — never personal credentials
- Shared credentials are prohibited — every user has an individual account

## 4. Authorization Model

Access follows Role-Based Access Control (RBAC) via [intake.infrastructure.identity_provider] groups:

| Group | Access | Members |
|-------|--------|---------|
| engineering | [intake.infrastructure.source_control] repos, staging environments, [intake.infrastructure.ci_cd] (read), [intake.infrastructure.monitoring] (read) | All engineers |
| engineering-production | Production infrastructure (read), deployment pipelines, [intake.infrastructure.monitoring] (read/write), on-call tools | Senior engineers, on-call rotation |
| engineering-admin | Production infrastructure (write), database admin, [intake.infrastructure.iac_tool] apply permissions | [intake.people.cto], designated SREs |
| security | Security tools, audit logs, vulnerability scanner, [intake.infrastructure.compliance_platform] | [intake.people.security_lead], security team |
| hr | HR systems, background check results, employee records | [intake.people.hr_lead], HR team |
| finance | Billing systems, financial systems, expense management | Finance team |
| admin | [intake.infrastructure.identity_provider] admin, cloud account admin | [intake.people.cto], [intake.people.security_lead] only |

Principle: **least privilege** — users get the minimum access needed for their role.

[IF cloud = AWS:]
### AWS IAM Structure
- No IAM users for human access — use AWS SSO (IAM Identity Center) federated from [intake.infrastructure.identity_provider]
- IAM roles for service-to-service access with scoped policies
- No inline policies — use managed policies attached to roles
- Production account access restricted to engineering-admin and engineering-production groups
- Separate AWS accounts for production, staging, and development
- No standing admin access — use assume-role with MFA for elevated operations
[END IF]

[IF cloud = GCP:]
### GCP IAM Structure
- No service account keys for human access — use Workload Identity Federation from [intake.infrastructure.identity_provider]
- Custom IAM roles scoped to minimum required permissions
- Production project access restricted to engineering-admin and engineering-production groups
- Separate GCP projects for production, staging, and development
- No standing Owner role — use just-in-time elevation via PAM or equivalent
[END IF]

[IF cloud = Azure:]
### Azure RBAC Structure
- No local Azure AD accounts for human access — federate from [intake.infrastructure.identity_provider]
- Azure RBAC roles scoped to minimum required permissions
- Production subscription access restricted to engineering-admin and engineering-production groups
- Separate Azure subscriptions for production, staging, and development
- Privileged Identity Management (PIM) for just-in-time admin access
[END IF]

## 5. User Lifecycle

### Onboarding (complete within first day)
1. HR creates user account in [intake.infrastructure.identity_provider]
2. User added to appropriate groups based on role (see authorization table)
3. User configures MFA — verified before any system access is granted
[IF mdm exists:]
4. Company device enrolled in [intake.infrastructure.mdm]
[END IF]
5. User account created in [intake.infrastructure.password_manager]
6. User signs Acceptable Use Policy
7. User completes security awareness training within 7 days
8. Onboarding ticket created in [intake.infrastructure.ticketing] and tracked to completion

### Role Change
1. Manager submits access change request in [intake.infrastructure.ticketing]
2. [intake.people.security_lead] or [intake.people.cto] approves the change
3. Groups updated in [intake.infrastructure.identity_provider]
4. Previous role-specific access removed — verified, not assumed
5. Change documented in ticket with before/after access summary

### Offboarding

**Deprovisioning SLA:**
- Voluntary departure: access revoked within 24 hours of last working day
- Involuntary termination: access revoked within 1 hour of notification
- Security incident (compromised account): access revoked immediately

**Offboarding steps (all must be completed within SLA):**
1. HR notifies [intake.people.security_lead] of departure date and type (voluntary/involuntary)
2. Account disabled in [intake.infrastructure.identity_provider] — this cascades SSO revocation to all connected applications
3. Active sessions terminated in [intake.infrastructure.identity_provider]
4. Personal API keys and tokens revoked across all systems
5. User removed from [intake.infrastructure.source_control] organization
6. User removed from [intake.infrastructure.communication] workspace
7. User removed from all [intake.infrastructure.identity_provider] groups
[IF mdm exists:]
8. Company device retrieved and remotely wiped via [intake.infrastructure.mdm]
[END IF]
9. Shared credentials rotated if departing employee had access to any service accounts or shared secrets
10. Offboarding ticket completed in [intake.infrastructure.ticketing] with confirmation of every step
11. [intake.people.security_lead] performs spot-check: verify no residual access in [intake.infrastructure.identity_provider], [intake.infrastructure.source_control], and cloud console

## 6. Access Reviews

**Frequency:** quarterly (every 90 days)
**Conducted by:** [intake.people.security_lead] with each team lead
**Evidence stored in:** [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:][intake.infrastructure.ticketing][END IF]

**Process:**
1. Export current user list and group memberships from [intake.infrastructure.identity_provider]
[IF cloud = AWS:]
2. Export IAM Identity Center user assignments from AWS
[END IF]
[IF cloud = GCP:]
2. Export IAM bindings from GCP projects (production, staging)
[END IF]
[IF cloud = Azure:]
2. Export Azure RBAC role assignments from all subscriptions
[END IF]
3. Export collaborator list from [intake.infrastructure.source_control]
4. For each user: verify role is current, access level is appropriate, no stale accounts
5. Identify and remove accounts for departed employees (should be zero — offboarding should catch these)
6. Identify and remove excessive permissions (users in groups they no longer need)
7. Team lead signs off on their team's access
8. [intake.people.security_lead] signs off on the overall review
9. Retain evidence: export screenshots, sign-off records, remediation actions

## 7. Privileged Access

- Production database access: requires approval from [intake.people.cto], logged, time-limited (maximum 4 hours)
- Cloud admin access: requires MFA re-authentication, logged, time-limited
- No shared admin credentials — every admin has an individual account
- Emergency break-glass access: documented procedure, every use reviewed by [intake.people.security_lead] within 24 hours, credentials rotated after use
- Root/owner cloud account credentials: stored in [intake.infrastructure.password_manager] vault, used only for break-glass scenarios, MFA hardware key required

## 8. Exceptions

Any exception to this policy must be:
1. Documented with business justification in [intake.infrastructure.ticketing]
2. Approved by [intake.people.security_lead]
3. Time-limited (maximum 90 days)
4. Recorded in the risk register

## 9. Review Schedule

This policy is reviewed at least annually, after any access-related security incident,
and after significant changes to the identity or access management infrastructure.
```

---

## Policy 3: Incident Response Policy

**TSC Coverage:** CC7.3, CC7.4, CC7.5
**Generate when:** always

### Decision points:
- Reference actual monitoring tool for detection
- Reference actual communication tool for incident channels
- Reference actual ticketing tool for incident tracking
- If compliance_platform exists: reference it for incident evidence storage
- Tabletop scenario references actual IdP by name for realistic phishing scenario

### Template:

```markdown
# Incident Response Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.security_lead]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC7.3, CC7.4, CC7.5

## 1. Purpose

Defines how [intake.company.name] detects, responds to, and recovers from security
incidents. Ensures timely response, minimizes impact, and meets notification obligations.

## 2. Scope

All security events affecting [intake.company.name] systems, data, or personnel.
Includes production infrastructure, corporate systems, and third-party services.

## 3. Severity Levels and Response SLAs

| Severity | Definition | Response Time | Update Frequency | Examples |
|----------|-----------|---------------|-----------------|---------|
| P1 — Critical | Active breach, data exfiltration confirmed, complete service outage | 15 minutes | Every 30 minutes | Unauthorized access to customer data, ransomware, production database compromised |
| P2 — High | Likely breach, partial outage, vulnerability actively exploited | 1 hour | Every 2 hours | Suspicious admin login from unknown location, critical CVE in production dependency, significant service degradation |
| P3 — Medium | Security event needing investigation, no confirmed customer impact | 4 hours | Daily | Failed brute-force attempt (blocked), medium-severity vulnerability, phishing email reported and contained |
| P4 — Low | Informational, minor risk, process improvement | 1 business day | As needed | Policy question, low-severity vulnerability in non-production, security enhancement suggestion |

## 4. Incident Response Team

| Role | Primary | Backup | Responsibility |
|------|---------|--------|---------------|
| Incident Commander | [intake.people.security_lead] | [intake.people.cto] | Coordinates response, makes containment decisions, manages communication |
| Technical Lead | On-call engineer | Senior engineer | Investigates, contains, and remediates the technical issue |
| Communications Lead | [intake.people.ceo] | [intake.people.compliance_owner] | Customer notification, public statements, regulatory reporting |
| Scribe | Assigned at incident start | — | Documents timeline, decisions, and actions in real-time |

## 5. Response Procedure

### Step 1: Detect and Report
- Any employee who suspects a security incident reports immediately
- Reporting channels (in priority order):
  1. [intake.infrastructure.communication] #security-incidents channel — for fast triage
  2. Email: security@[intake.company.domain] — for external reports or when [intake.infrastructure.communication] is unavailable
  3. Direct message or phone call to [intake.people.security_lead] — for sensitive incidents
- Automated detection sources:
  - [intake.infrastructure.monitoring] alerts (anomalous metrics, error rate spikes)
[IF cloud = AWS:]
  - GuardDuty findings (reconnaissance, credential compromise, crypto mining)
  - CloudTrail anomalies (unauthorized API calls, root account usage)
  - AWS Config rule violations (non-compliant resource changes)
[END IF]
[IF cloud = GCP:]
  - Security Command Center findings (misconfiguration, vulnerability, threat)
  - Cloud Audit Log anomalies (unauthorized API calls, admin activity)
[END IF]
[IF cloud = Azure:]
  - Defender for Cloud alerts (security recommendations, threat detections)
  - Azure Monitor anomalies (unauthorized operations, suspicious sign-ins)
[END IF]
[IF edr exists:]
  - [intake.infrastructure.edr] alerts (malware detection, suspicious process activity)
[END IF]

### Step 2: Triage (within response time SLA)
- Incident Commander assesses severity using the table in Section 3
- Creates incident ticket in [intake.infrastructure.ticketing] with:
  - Description of the event
  - Severity level and justification
  - Affected systems
  - Initial assessment of scope
- For P1/P2: creates dedicated [intake.infrastructure.communication] channel: #incident-YYYY-MM-DD-[brief-name]
- Assembles response team based on severity

### Step 3: Contain
- Isolate affected systems:
  - Revoke compromised credentials in [intake.infrastructure.identity_provider]
  - Disable compromised accounts
  - Block malicious IPs at network/WAF level
  - Isolate affected instances (security group / network policy change)
- Preserve evidence — do NOT delete logs, terminate instances, or overwrite data
  - Take snapshots of affected systems
  - Export relevant logs from [intake.infrastructure.monitoring]
  - Record the current state before making changes
- If customer data is potentially affected: notify [intake.people.ceo] immediately

### Step 4: Investigate
Determine:
- What happened (attack vector, actions taken by attacker)
- When it started (first indicator of compromise)
- What was affected (systems, data, users)
- How it happened (root cause)
- Whether it is still ongoing

Evidence sources to check:
- [intake.infrastructure.identity_provider] authentication logs
- [intake.infrastructure.monitoring] application and infrastructure logs
[IF cloud = AWS:]
- CloudTrail events (API calls, console sign-ins)
- VPC Flow Logs (network traffic)
- GuardDuty findings timeline
[END IF]
[IF cloud = GCP:]
- Cloud Audit Logs (Admin Activity, Data Access)
- VPC Flow Logs
- Security Command Center finding details
[END IF]
- [intake.infrastructure.source_control] audit log (code changes, permission changes)
- Document all findings in the incident ticket in real-time

### Step 5: Remediate
- Fix the root cause: patch vulnerability, close access gap, fix misconfiguration
- Verify the fix is effective — confirm the attack vector is closed
- Restore affected systems from clean state if compromised
- Rotate all credentials that may have been exposed
- Update security controls to prevent recurrence

### Step 6: Notify (if customer data affected)
- Notify affected customers within 72 hours of confirming data involvement
- Notification template:

> Subject: Security Incident Notification — [intake.company.name]
>
> Dear [Customer Name],
>
> We are writing to inform you of a security incident that affected your data.
>
> **What happened:** On [DATE], we detected [DESCRIPTION OF INCIDENT]. Our investigation
> determined that [SCOPE — what data was accessed/exposed and time period].
>
> **What data was involved:** [SPECIFIC DATA TYPES — e.g., names, email addresses, usage data.
> State clearly if credentials, financial data, or highly sensitive PII was NOT involved.]
>
> **What we have done:** [ACTIONS TAKEN — e.g., revoked compromised access, patched the vulnerability,
> engaged third-party forensics, notified law enforcement if applicable.]
>
> **What you can do:** [RECOMMENDATIONS — e.g., rotate API keys, review access logs, monitor for
> suspicious activity.]
>
> **What happens next:** We will provide updates as our investigation continues. We have implemented
> [SPECIFIC CONTROLS] to prevent recurrence.
>
> If you have questions, contact us at security@[intake.company.domain].
>
> [intake.people.security_lead]
> [intake.company.name]

- For P1 incidents affecting multiple customers: also post to status page
- Regulatory notification: if required (GDPR: 72 hours to DPA; state breach laws: varies)

### Step 7: Post-Incident Review
- Conduct blameless post-mortem within 5 business days of resolution
- All members of the incident response team attend
- Post-mortem template:

> ## Post-Incident Review: [INCIDENT TITLE]
> **Date of incident:** [DATE] | **Date of review:** [DATE]
> **Severity:** P1/P2/P3/P4 | **Duration:** [TIME from detection to resolution]
> **Incident Commander:** [NAME] | **Scribe:** [NAME]
>
> ### Summary
> [One paragraph: what happened, what the impact was, how it was resolved.]
>
> ### Timeline
> | Time (UTC) | Event |
> |------------|-------|
> | HH:MM | First indicator of compromise / alert triggered |
> | HH:MM | Incident declared, team assembled |
> | HH:MM | Root cause identified |
> | HH:MM | Containment achieved |
> | HH:MM | Remediation complete |
> | HH:MM | All-clear declared |
>
> ### Root Cause
> [Technical root cause. Be specific — "misconfigured S3 bucket allowed public read"
> not "access control issue".]
>
> ### Impact
> - Systems affected: [list]
> - Customers affected: [number or "none"]
> - Data affected: [specific data types or "no customer data involved"]
> - Duration of exposure: [time period]
> - Financial impact: [if known]
>
> ### What Went Well
> - [e.g., "Detection was fast — GuardDuty alert fired within 3 minutes"]
> - [e.g., "Containment was effective — account disabled within 10 minutes"]
>
> ### What To Improve
> - [e.g., "No automated response to this alert type — add runbook"]
> - [e.g., "Communication to customers was delayed — pre-approve template"]
>
> ### Action Items
> | Action | Owner | Deadline | Status |
> |--------|-------|----------|--------|
> | [specific remediation action] | [name] | [date] | Open |
> | [process improvement] | [name] | [date] | Open |

- Assign action items with owners and deadlines in [intake.infrastructure.ticketing]
- Track action items to completion — reviewed in next quarterly security review

## 6. Tabletop Exercise

Conduct at least annually. Simulate a realistic scenario and walk through the full response procedure.

**Scenario (customize to your environment):**

> It is Tuesday at 2:15 PM. [intake.people.security_lead] receives an alert from
> [IF cloud = AWS:]GuardDuty[END IF][IF cloud = GCP:]Security Command Center[END IF][IF cloud = Azure:]Defender for Cloud[END IF]:
> unusual API activity from an engineer's account — bulk S3/GCS object listing across
> multiple customer data buckets, followed by GetObject calls for several hundred objects.
>
> Investigation reveals: the engineer received a phishing email that appeared to be
> from [intake.infrastructure.identity_provider] ("Your session has expired — click to
> re-authenticate"). The engineer entered their credentials on the phishing page.
> The attacker obtained valid credentials and passed the MFA challenge via real-time
> proxy. The engineer is in the engineering-production group.
>
> Walk through:
> 1. What is the severity? What triggers do we see?
> 2. Who do we assemble? What channel do we create?
> 3. What do we contain first — account, network, or both?
> 4. How do we determine exactly what customer data was accessed?
> 5. What is our customer notification obligation? Timeline?
> 6. What would we change to prevent this specific attack?

## 7. Exceptions

Emergency deviations from this procedure must be documented within 24 hours
and reviewed by [intake.people.security_lead].

## 8. Review Schedule

This policy is reviewed annually, after every P1/P2 incident, and after each
tabletop exercise.
```

---

## Policy 4: Change Management Policy

**TSC Coverage:** CC8.1
**Generate when:** always

### Decision points:
- If source_control = GitHub: reference GitHub branch protection rules, GitHub pull requests
- If source_control = GitLab: reference GitLab merge requests, protected branches
- If ci_cd = GitHub Actions: reference workflow YAML, required status checks
- If ci_cd = CircleCI: reference CircleCI config, required status checks via GitHub integration
- If ci_cd = GitLab CI: reference .gitlab-ci.yml, merge request pipelines
- If iac_tool = Terraform: reference terraform plan/apply workflow
- If iac_tool = Pulumi: reference pulumi preview/up workflow
- If iac_tool = CloudFormation: reference changeset review workflow

### Template:

```markdown
# Change Management Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.cto]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC8.1

## 1. Purpose

Defines how [intake.company.name] manages changes to production systems, application
code, infrastructure, and configuration. Ensures all changes are reviewed, tested,
and traceable.

## 2. Scope

All changes to:
- Application code deployed to production
- Infrastructure (cloud resources, networking, DNS)
- Application and system configuration
- Database schemas
- Third-party integrations

## 3. Standard Change Process

### Code Changes
1. Developer creates feature branch from main in [intake.infrastructure.source_control]
2. Developer writes code and tests
[IF source_control = GitHub:]
3. Developer opens pull request in GitHub
4. CI pipeline runs automatically via [intake.infrastructure.ci_cd]:
[END IF]
[IF source_control = GitLab:]
3. Developer opens merge request in GitLab
4. CI pipeline runs automatically via [intake.infrastructure.ci_cd]:
[END IF]
   - Unit tests
   - Integration tests
   - Linting and static analysis
   - Security scanning (dependency vulnerabilities, secret detection)
   - Build verification
5. At least 1 peer review and approval required (reviewer must not be the author)
6. All CI checks must pass before merge is allowed
7. Developer merges to main
8. Automated deployment pipeline deploys to staging
9. Verification in staging environment
10. Deployment to production (automated or manual promotion with approval depending on change risk)
11. Post-deployment verification: smoke tests, monitoring check in [intake.infrastructure.monitoring]

### Infrastructure Changes
[IF iac_tool = Terraform:]
1. All infrastructure defined in Terraform — no manual cloud console changes under normal operations
2. Developer creates branch, modifies Terraform configuration
3. Pull request opened — CI runs `terraform plan` and posts plan output as PR comment
4. Reviewer examines plan output: resources created, modified, destroyed
5. Approval required before merge
6. `terraform apply` runs via CI pipeline after merge (or via approved manual trigger for sensitive changes)
7. State file stored in encrypted remote backend with versioning
[END IF]
[IF iac_tool = Pulumi:]
1. All infrastructure defined in Pulumi — no manual cloud console changes under normal operations
2. Developer creates branch, modifies Pulumi program
3. Pull request opened — CI runs `pulumi preview` and posts diff as PR comment
4. Reviewer examines preview output: resources created, modified, destroyed
5. Approval required before merge
6. `pulumi up` runs via CI pipeline after merge
7. State managed via Pulumi Cloud or encrypted backend
[END IF]
[IF iac_tool = CloudFormation:]
1. All infrastructure defined in CloudFormation templates — no manual console changes under normal operations
2. Developer creates branch, modifies CloudFormation template
3. Pull request opened — CI creates a changeset and posts summary as PR comment
4. Reviewer examines changeset: resources created, modified, destroyed
5. Approval required before merge
6. Changeset executed via CI pipeline after merge
[END IF]
8. If manual change is absolutely necessary (emergency): document it and codify it in IaC within 24 hours

### Configuration Changes
1. Application configuration changes follow the same PR and review process
2. Database schema changes follow the same PR process, require review by senior engineer
3. DNS changes require approval from [intake.people.cto] or [intake.people.security_lead]
4. Firewall / security group changes require review by [intake.people.security_lead]

## 4. Branch Protection Rules

[IF source_control = GitHub:]
Applied to `main` branch in all GitHub repositories:
- Require pull request before merging
- Require at least 1 approving review
- Dismiss stale reviews when new commits are pushed
- Require status checks to pass before merging ([intake.infrastructure.ci_cd] pipeline)
- Require branches to be up to date before merging
- Restrict who can push directly to main
- Do not allow bypassing the above settings (applies to admins too)
- Do not allow force pushes
- Do not allow branch deletion

Verified by: GitHub branch protection API — see infrastructure discovery evidence.
[END IF]

[IF source_control = GitLab:]
Applied to `main` branch in all GitLab projects:
- Protected branch: no direct pushes allowed
- Merge requests required for all changes
- At least 1 approval required (approver must not be the author)
- All CI pipelines must succeed before merge
- Merge request squash or merge commit required (linear history)
- No force pushes allowed

Verified by: GitLab protected branch settings — see infrastructure discovery evidence.
[END IF]

## 5. Emergency Change Process

For critical production issues requiring immediate fix:

1. On-call engineer makes the fix
2. Fix MUST still go through the CI pipeline — no direct production changes
3. Review requirements relaxed: retroactive peer review within 24 hours (instead of pre-merge)
4. Emergency change documented in [intake.infrastructure.ticketing] with:
   - Justification for bypassing standard process
   - Description of the change
   - Who approved it (Incident Commander or [intake.people.cto])
   - Link to retroactive review
5. If a direct production change is absolutely unavoidable:
   - Document exactly what was changed and why
   - Create a PR to codify the change within 24 hours
   - [intake.people.cto] approves the retroactive codification
6. All emergency changes are reviewed in the next post-incident review

## 6. Rollback Procedure

If a deployment causes issues:
1. Detect via [intake.infrastructure.monitoring] alerts or user report
2. Assess severity — if P1/P2, initiate rollback immediately
3. Rollback method (in order of preference):
   - Revert the merge commit in [intake.infrastructure.source_control] and deploy through normal pipeline
   - Deploy the previous known-good version tag/commit via [intake.infrastructure.ci_cd]
   - If blue/green or canary deployment: route traffic back to previous version
4. Verify rollback is successful via [intake.infrastructure.monitoring]
5. Investigate root cause before re-attempting the change
6. Document the rollback in [intake.infrastructure.ticketing]

## 7. Exceptions

Emergency changes that bypass standard review are documented per Section 5.
All other exceptions require approval from [intake.people.cto].

## 8. Review Schedule

This policy is reviewed annually and after any incident caused by a change management failure.
```

---

## Policy 5: Risk Assessment Policy

**TSC Coverage:** CC3.1, CC3.2, CC3.3, CC3.4
**Generate when:** always

### Decision points:
- Risk register location depends on compliance_platform existence
- Pre-populated risks reference actual cloud provider and tools
- Sign-off requirements reference actual leadership names

### Template:

```markdown
# Risk Assessment Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.security_lead]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC3.1, CC3.2, CC3.3, CC3.4

## 1. Purpose

Defines the process for identifying, assessing, and managing risks to
[intake.company.name]'s information assets, systems, and operations. Ensures
risk-informed decisions at all levels.

## 2. Scope

All information assets, systems, processes, and third-party relationships
that support the delivery of [intake.company.product].

## 3. Assessment Schedule

- **Annual assessment:** comprehensive review of all risks, conducted in Q1 each year
- **Triggered assessment:** within 30 days of any material change:
  - New product launch or major feature release
  - New cloud provider, region, or significant infrastructure change
  - Acquisition or merger
  - P1 or P2 security incident
  - Regulatory change affecting the business
  - Addition of a new critical vendor
  - Significant growth (employee count doubles, customer base doubles)

## 4. Risk Assessment Process

### Step 1: Identify Assets
List all assets in scope:
- Production infrastructure ([intake.infrastructure.cloud_provider] — compute, databases, storage, networking)
- Applications and services ([intake.company.product] and supporting services)
- Customer data stores (databases, object storage, backups)
- Corporate systems ([intake.infrastructure.identity_provider], [intake.infrastructure.communication], [intake.infrastructure.ticketing])
- Source code and CI/CD ([intake.infrastructure.source_control], [intake.infrastructure.ci_cd])
- Endpoints (employee laptops, mobile devices)
- Third-party services and vendors (see vendor register)

### Step 2: Identify Threats
For each asset, identify applicable threats:
- Unauthorized access (external attacker, insider threat, credential compromise)
- Data breach / data exfiltration
- Service disruption (DDoS, infrastructure failure, dependency outage)
- Malware / ransomware
- Phishing / social engineering
- Supply chain compromise (vendor breach, dependency poisoning)
- Misconfiguration (cloud resources, application settings, network rules)
- Data loss (accidental deletion, corruption, backup failure)
- Compliance violation (regulatory penalty, audit finding)
- Key person risk (single point of failure for critical knowledge)

### Step 3: Assess Likelihood and Impact

**Likelihood:**
| Rating | Definition |
|--------|-----------|
| High | Expected to occur within the next year based on threat intelligence and industry trends |
| Medium | Could reasonably occur within the next year |
| Low | Unlikely to occur within the next year given current controls |

**Impact:**
| Rating | Definition |
|--------|-----------|
| High | Major data breach (>1000 records), significant financial loss (>$100K), regulatory action, customer trust materially damaged |
| Medium | Limited data exposure (<1000 records), moderate financial impact ($10K-$100K), some customer disruption |
| Low | Minimal impact, no data exposure, easily contained, <$10K cost |

**Risk Matrix:**

| | High Impact | Medium Impact | Low Impact |
|---|------------|---------------|------------|
| **High Likelihood** | Critical | High | Medium |
| **Medium Likelihood** | High | Medium | Low |
| **Low Likelihood** | Medium | Low | Low |

### Step 4: Document in Risk Register

Maintain the risk register in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:]a dedicated spreadsheet accessible to leadership[END IF].

Fields for each risk:

| Field | Description |
|-------|-------------|
| Risk ID | Unique identifier (RISK-NNN) |
| Description | Specific risk description — what could go wrong |
| Asset(s) Affected | Which systems or data |
| Threat | The threat vector |
| Likelihood | High / Medium / Low |
| Impact | High / Medium / Low |
| Risk Score | Critical / High / Medium / Low (from matrix) |
| Current Controls | What is already in place to address this risk |
| Residual Risk | Risk level after current controls |
| Treatment | Mitigate / Accept / Transfer / Avoid |
| Treatment Plan | Specific actions to reduce risk |
| Owner | Person responsible for the risk |
| Target Date | When treatment should be complete |
| Status | Open / In Progress / Closed / Accepted |
| Last Reviewed | Date of most recent review |

### Step 5: Risk Treatment
- **Mitigate:** implement controls to reduce likelihood or impact to acceptable level
- **Accept:** document the risk and obtain management sign-off; Critical/High risks require [intake.people.ceo] approval
- **Transfer:** transfer risk to third party via insurance or vendor SLA
- **Avoid:** eliminate the activity that creates the risk

### Step 6: Review and Sign-Off
- Present risk register to leadership: [intake.people.ceo], [intake.people.cto], [intake.people.security_lead]
- All Critical and High risks require documented sign-off on treatment decision
- Accepted risks require explicit written acknowledgment from [intake.people.ceo]
- Sign-off recorded in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:][intake.infrastructure.ticketing][END IF]

## 5. Pre-Populated Risk Register

The following common SaaS risks are pre-populated. The agent should adjust likelihood
and current controls based on what was discovered during infrastructure assessment.

| ID | Risk | Likelihood | Impact | Score | Current Controls |
|----|------|-----------|--------|-------|-----------------|
| RISK-001 | Unauthorized access to production database via compromised credentials | Medium | High | High | MFA enforced via [intake.infrastructure.identity_provider]; database access restricted to engineering-admin group; access logged |
| RISK-002 | Customer data exposure via application vulnerability (SQLi, IDOR, etc.) | Medium | High | High | Code review required; dependency scanning in CI; annual penetration test |
| RISK-003 | Service outage due to [intake.infrastructure.cloud_provider] regional failure | Low | High | Medium | Multi-AZ deployment; automated failover; backups in secondary region |
| RISK-004 | Data loss due to failed or untested backups | Low | High | Medium | Automated daily backups; backup restore tested [quarterly/annually]; 90-day retention |
| RISK-005 | Insider threat — employee accesses data beyond their role | Low | High | Medium | RBAC via [intake.infrastructure.identity_provider]; quarterly access reviews; least privilege enforced |
| RISK-006 | Supply chain attack via compromised dependency | Medium | Medium | Medium | Dependency scanning in [intake.infrastructure.ci_cd]; Dependabot/Renovate enabled; lockfile pinning |
| RISK-007 | Phishing attack compromises employee credentials | High | Medium | High | MFA enforced; security awareness training; phishing simulations quarterly |
| RISK-008 | Misconfigured cloud resources expose data publicly | Medium | High | High | [IF cloud = AWS:]AWS Config rules; S3 Block Public Access enabled account-wide; GuardDuty enabled[END IF][IF cloud = GCP:]Security Command Center enabled; uniform bucket-level access enforced[END IF][IF cloud = Azure:]Defender for Cloud recommendations; storage account public access disabled[END IF] |
| RISK-009 | Vendor breach exposes customer data shared with sub-processor | Medium | High | High | Vendor risk assessment; DPA required; SOC 2/ISO 27001 required for critical vendors |
| RISK-010 | Ransomware encrypts production systems | Low | High | Medium | [IF edr exists:][intake.infrastructure.edr] on all endpoints; [END IF]immutable backups; network segmentation; MFA everywhere |

## 6. Exceptions

Deviations from the assessment schedule require approval from [intake.people.ceo].

## 7. Review Schedule

This policy is reviewed annually. The risk register itself is a living document —
updated whenever new risks are identified or existing risks change.
```

---

## Policy 6: Data Classification and Handling Policy

**TSC Coverage:** CC6.1, CC6.7
**Generate when:** always

### Decision points:
- If pii_handled = true: add PII-specific handling requirements section
- If phi_handled = true (healthcare): add PHI handling requirements section
- If cloud = AWS: reference S3, RDS, KMS for storage/encryption specifics
- If cloud = GCP: reference GCS, Cloud SQL, Cloud KMS

### Template:

```markdown
# Data Classification and Handling Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.security_lead]
**Approved By:** [intake.people.cto]
**TSC Coverage:** CC6.1, CC6.7

## 1. Purpose

Defines how [intake.company.name] classifies, handles, stores, and disposes of data
based on its sensitivity level. Ensures appropriate protection for all data types.

## 2. Scope

All data created, collected, processed, stored, or transmitted by [intake.company.name],
including customer data, employee data, business data, and technical data.

## 3. Classification Levels

| Level | Definition | Examples | Storage Requirements | Access Requirements | Disposal Method |
|-------|-----------|----------|---------------------|--------------------|-----------------| 
| Restricted | Highest sensitivity. Legal, regulatory, or severe business impact if exposed. | Customer PII, authentication credentials, encryption keys, security configurations, SOC 2 reports, penetration test results | Encrypted at rest (AES-256) and in transit (TLS 1.2+). Dedicated access controls. Stored only in approved systems. | Need-to-know only. Access logged and reviewed quarterly. Requires MFA. | Cryptographic erasure or physical destruction. |
| Confidential | Business-sensitive. Material impact if exposed. | Customer usage data (non-PII), financial records, contracts, employee HR records, internal security documentation, vendor assessments | Encrypted at rest and in transit. Role-based access via [intake.infrastructure.identity_provider]. | Restricted to authorized roles. | Secure deletion (overwrite or cryptographic erasure). |
| Internal | For internal use. Minor impact if exposed externally. | Internal documentation, architecture diagrams, meeting notes, project plans, non-sensitive code | Standard company systems with authentication. | All employees. | Standard deletion. |
| Public | No sensitivity. Intended for external consumption. | Marketing content, public documentation, open source code, job postings, published blog posts | Any system. | Anyone. | No special handling. |

## 4. Handling Requirements by Level

### Restricted Data
- NEVER store in email bodies, chat messages, shared documents, or local files
- NEVER log in application logs — mask, redact, or tokenize all Restricted data before logging
- NEVER include in error messages, stack traces, or debugging output
- Access requires MFA via [intake.infrastructure.identity_provider] + role-based authorization + explicit approval
- Every access is logged and auditable
- Encryption keys stored in [IF cloud = AWS:]AWS KMS[END IF][IF cloud = GCP:]Cloud KMS[END IF][IF cloud = Azure:]Azure Key Vault[END IF] — never in application code, config files, or environment variables
- Transmitted only over encrypted channels (TLS 1.2+)
- Retained only as long as legally or contractually required
- Deleted using cryptographic erasure when retention period expires
- Backups containing Restricted data follow the same encryption and access requirements

### Confidential Data
- Store only in approved company systems with access controls
- Do not share externally without NDA and explicit approval from data owner
- Encrypt at rest and in transit
- Access restricted by role via [intake.infrastructure.identity_provider] groups
- Retained per data retention schedule (see Data Retention Policy)

### Internal Data
- Keep within company systems (do not post publicly)
- Do not share with external parties without manager approval
- No special encryption requirements beyond system defaults (which are encrypted at rest)

### Public Data
- No restrictions on sharing
- Before sharing: verify the data is actually classified as Public (check with data owner if unsure)

[IF pii_handled = true:]
## 5. PII-Specific Handling Requirements

In addition to the Restricted classification requirements, all Personally Identifiable
Information (PII) has these additional requirements:

- **Collection minimization:** collect only the PII necessary for the stated purpose
- **Purpose limitation:** use PII only for the purpose it was collected for; new uses require updated consent
- **Access logging:** every read/write to PII data stores is logged with user identity, timestamp, and records accessed
- **Pseudonymization:** where possible, replace direct identifiers with pseudonymous tokens in non-production environments
- **Data subject rights:** support customer requests to access, correct, export, and delete their PII within 30 days
- **Cross-border transfer:** PII must not be transferred to jurisdictions without adequate data protection unless appropriate safeguards (Standard Contractual Clauses, DPA) are in place
- **Breach notification:** if PII is involved in a breach, follow the notification timeline in the Incident Response Policy (72 hours for GDPR, per-state requirements for US)
- **Vendor PII sharing:** vendors receiving PII must have a signed DPA and meet the requirements in the Vendor Management Policy

PII types handled by [intake.company.name]:
[Agent: list the specific PII types from intake.data.customer_data_types here — e.g., names, email addresses, phone numbers, IP addresses, billing addresses]
[END IF]

[IF phi_handled = true:]
## 6. PHI-Specific Handling Requirements

In addition to the Restricted and PII requirements, all Protected Health Information
(PHI) has these additional requirements per HIPAA:

- **Minimum necessary standard:** access only the minimum PHI necessary for the specific task
- **Business Associate Agreements (BAA):** required with every vendor that creates, receives, maintains, or transmits PHI
- **Audit trail:** all access to PHI must be logged with unique user identification, date, time, and actions performed; logs retained for minimum 6 years
- **Workstation security:** PHI must not be accessed on personal devices without approved MDM and encryption
- **Disposal:** PHI must be disposed of in accordance with NIST SP 800-88 guidelines
- **Training:** HIPAA-specific training required for all employees with PHI access, in addition to general security awareness training
- **Incident reporting:** PHI breaches affecting 500+ individuals must be reported to HHS within 60 days
[END IF]

## 7. Data Retention Schedule

> Note: section numbers 5 and 6 are reserved for PII and PHI handling requirements.
> If neither applies, this section renders as section 5 in the final output. The agent
> should renumber sequentially when stripping conditional blocks.

| Data Type | Retention Period | Legal Basis | Disposal Method |
|-----------|-----------------|-------------|-----------------|
| Customer application data | Duration of contract + 30 days | Contractual obligation | Cryptographic erasure from all systems |
| Customer PII | Duration of contract + 30 days | Privacy obligations, contractual | Cryptographic erasure from all systems |
| Application logs | 1 year | Security monitoring, SOC 2 | Automatic expiration via log rotation |
| Security and audit logs | 1 year minimum | SOC 2 requirement, incident investigation | Automatic expiration |
| Authentication logs | 1 year | SOC 2 requirement | Automatic expiration |
| Employee HR records | Duration of employment + 3 years | Employment law | Secure deletion |
| Financial records | 7 years | Tax and accounting requirements | Secure deletion |
| Contracts and agreements | Duration + 3 years | Legal requirements | Secure deletion |
| Backup data | 90 days rolling | Operational recovery | Automatic expiration (encrypted backups) |
| Marketing and analytics data | 2 years | Business purpose | Standard deletion |

## 8. Exceptions

Data retention exceptions (legal hold, regulatory requirement) must be documented
and approved by [intake.people.compliance_owner]. See Data Retention and Disposal Policy
for legal hold procedure.

## 9. Review Schedule

This policy is reviewed annually, when new data types are introduced, or when
regulatory requirements change.
```

---

## Policy 7: Acceptable Use Policy

**TSC Coverage:** CC1.4, CC2.2
**Generate when:** always

### Decision points:
- Reference actual password_manager, mdm, edr tools
- If mdm = none: omit MDM references, adjust device requirements
- If edr = none: omit EDR references
- Keep concise — this policy must be 2 pages maximum for employee readability

### Template:

```markdown
# Acceptable Use Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.hr_lead]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC1.4, CC2.2

## 1. Purpose

Defines acceptable and prohibited use of [intake.company.name] systems and data.
Every employee and contractor must read, understand, and sign this policy.

## 2. Scope

All employees and contractors of [intake.company.name]. By using company systems,
you agree to these terms.

## 3. You MUST

- Use MFA on all company accounts — no exceptions
- Lock your screen when stepping away (set auto-lock to 5 minutes maximum)
- Use [intake.infrastructure.password_manager] for all work passwords — unique password per service, minimum 16 characters
- Keep your OS and all applications up to date — apply security updates within 7 days
- Report suspected security incidents to [intake.people.security_lead] immediately via [intake.infrastructure.communication] #security-incidents
- Complete security awareness training within 7 days of hire and annually thereafter
[IF mdm exists:]
- Use company-managed devices enrolled in [intake.infrastructure.mdm] for all work
- Keep [intake.infrastructure.mdm] agent active and reporting — do not remove or disable it
[END IF]
[IF mdm = none:]
- Enable full-disk encryption on any device used for work (FileVault on macOS, BitLocker on Windows)
[END IF]
[IF edr exists:]
- Keep [intake.infrastructure.edr] active on your device — do not disable or interfere with it
[END IF]
- Use encrypted connections for all work (HTTPS, VPN when on untrusted networks)
- Verify suspicious emails before clicking links — report phishing to [intake.infrastructure.communication] #security-incidents

## 4. You MUST NOT

- Share your credentials with anyone, including coworkers and IT staff
- Use personal email or personal accounts for company business
- Store customer data or Restricted/Confidential data on personal devices or personal cloud storage
- Install unauthorized software on company devices without approval
- Disable or circumvent security controls (firewall, disk encryption, [IF edr exists:][intake.infrastructure.edr], [END IF][IF mdm exists:][intake.infrastructure.mdm][END IF])
- Access systems or data beyond what your role requires
- Share Confidential or Restricted information externally without written approval
- Use company systems for illegal activities
- Connect to company systems from shared or public computers
- Use unauthorized AI/LLM tools to process customer data or Restricted information

## 5. Consequences

Violations may result in disciplinary action, up to and including termination.
Serious violations may be reported to law enforcement.

## 6. Acknowledgment

I have read, understood, and agree to comply with this Acceptable Use Policy.

Signature: ________________________
Print Name: ________________________
Date: ________________________
```

---

## Policy 8: Vendor Management Policy

**TSC Coverage:** CC9.2
**Generate when:** always

### Decision points:
- Pre-populate vendor register from intake.vendors.critical_vendors
- If compliance_platform exists: reference it as the vendor assessment tracking system
- Reference actual cloud provider as a critical vendor

### Template:

```markdown
# Vendor Management Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.compliance_owner]
**Approved By:** [intake.people.cto]
**TSC Coverage:** CC9.2

## 1. Purpose

Defines how [intake.company.name] assesses, onboards, monitors, and manages
third-party vendors to ensure they meet security and compliance requirements.

## 2. Scope

All third-party vendors that access, process, or store [intake.company.name]
data, or provide services critical to business operations.

## 3. Vendor Classification

| Tier | Definition | Examples | Assessment | Review Frequency |
|------|-----------|----------|------------|-----------------|
| Critical | Processes, stores, or accesses customer data. Outage directly impacts customers. | [intake.infrastructure.cloud_provider] (cloud infrastructure), database hosting, payment processor | Full security assessment + SOC 2/ISO 27001 required | Annually + at contract renewal |
| Important | Accesses internal data or provides significant business function. No direct customer data access. | [intake.infrastructure.identity_provider], [intake.infrastructure.communication], [intake.infrastructure.monitoring], [intake.infrastructure.ci_cd] | Security assessment + SOC 2/ISO 27001 preferred | Annually |
| Standard | No access to sensitive data. Limited business impact if unavailable. | Office supplies, marketing analytics, design tools | Basic due diligence at onboarding | At onboarding only |

## 4. Vendor Onboarding Process

Before engaging any Critical or Important vendor:

### Step 1: Security Assessment
- Does the vendor have a SOC 2 Type II report? Request the most recent report and review it.
- If no SOC 2: does the vendor have ISO 27001 certification? Request the certificate.
- If neither: the vendor must complete our Vendor Security Questionnaire (Section 8)
- Review for: encryption practices, access controls, incident response capability, data handling, sub-processors

### Step 2: Contractual Requirements
For Critical and Important vendors, the contract MUST include:
- **Data Processing Agreement (DPA):** defining data processing scope, obligations, and restrictions
- **Security obligations:** encryption (at rest and in transit), access controls, vulnerability management
- **Breach notification SLA:** vendor must notify [intake.company.name] within 72 hours of a confirmed or suspected breach
- **Right to audit:** [intake.company.name] reserves the right to audit or request evidence of security controls
- **Data deletion:** vendor must delete all [intake.company.name] data within 30 days of contract termination
- **Sub-processor disclosure:** vendor must disclose sub-processors and notify of changes
- **Cyber liability insurance:** appropriate coverage for the services provided

### Step 3: Approval
- Critical vendors: approved by both [intake.people.cto] and [intake.people.security_lead]
- Important vendors: approved by [intake.people.security_lead]
- Standard vendors: approved by requesting manager
- Approval documented in [intake.infrastructure.ticketing]

### Step 4: Add to Vendor Register

## 5. Vendor Register

Maintain in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:]a dedicated spreadsheet accessible to [intake.people.compliance_owner] and [intake.people.security_lead][END IF]:

| Vendor | Tier | Service Provided | Data Accessed | SOC 2 / ISO 27001 | Report Date | DPA Signed | Last Reviewed | Next Review | Owner |
|--------|------|-----------------|---------------|-------------------|-------------|------------|--------------|-------------|-------|

**Pre-populated from intake (agent fills these based on intake.vendors.critical_vendors):**

[Agent: for each vendor in intake.vendors.critical_vendors, add a row with:
- Vendor name
- Tier (Critical if it accesses customer data, Important otherwise)
- Service description (from intake)
- Data accessed (from intake)
- SOC 2/ISO 27001 status (from intake)
- DPA status (to be confirmed)
- Owner (default: intake.people.compliance_owner)]

Additionally, always include these infrastructure vendors (agent populates the remaining register columns):

| Vendor | Tier | Service Provided | Data Accessed |
|--------|------|-----------------|---------------|
| [intake.infrastructure.cloud_provider] | Critical | Cloud infrastructure — compute, storage, networking, databases | Customer data, application data, all backups |
| [intake.infrastructure.identity_provider] | Important | Identity provider — SSO, MFA, user lifecycle | Employee identities, group memberships |
| [intake.infrastructure.source_control] | Important | Source code management | Source code, CI/CD configurations |
| [intake.infrastructure.monitoring] | Important | Monitoring and observability | Application logs, metrics (may contain customer identifiers) |

## 6. Annual Vendor Review

For each Critical and Important vendor, annually:
1. Request updated SOC 2 Type II report or ISO 27001 certificate
2. Review for any qualified opinions, exceptions, or findings in their report
3. Assess whether the vendor still meets our security requirements
4. Check for any security incidents disclosed by the vendor
5. Verify contractual terms are still appropriate for current scope
6. Verify DPA is still in effect and covers current data processing activities
7. Update vendor register with review date and findings
8. Document review in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:][intake.infrastructure.ticketing][END IF]

## 7. Vendor Offboarding

When terminating a vendor relationship:
1. Confirm data deletion per contractual terms (30-day window)
2. Request written confirmation of data deletion from vendor
3. Revoke all access granted to the vendor (API keys, accounts, network access)
4. Update vendor register to reflect terminated status
5. Retain vendor assessment records for 3 years

## 8. Vendor Security Questionnaire

For vendors without SOC 2 or ISO 27001, send this questionnaire to their security team:

1. Do you encrypt customer data at rest? What algorithm and key length?
2. Do you encrypt data in transit? What TLS version minimum?
3. Do you require MFA for all employees who access customer data?
4. Do you have a documented incident response plan? What is your breach notification timeline?
5. Do you conduct annual penetration testing by an independent third party? Can you share the executive summary?
6. Do you conduct background checks on employees who access customer data?
7. Do you maintain cyber liability insurance? What is the coverage amount?
8. How do you handle data deletion when a customer terminates their contract?
9. Do you use sub-processors that access customer data? If yes, list them and their SOC 2/ISO 27001 status.
10. Have you experienced any security incidents or data breaches in the past 24 months? If yes, describe.

Minimum acceptable responses for Critical vendors: questions 1-4 must all be "yes" with specifics.
Vendors that cannot demonstrate adequate controls must not be classified as Critical.

## 9. Exceptions

Exceptions to vendor assessment requirements require written approval from
[intake.people.cto] and [intake.people.security_lead], documented in the risk register.

## 10. Review Schedule

This policy is reviewed annually. The vendor register is a living document updated
whenever vendors are added, removed, or undergo their annual review.
```

---

## Policy 9: Business Continuity and Disaster Recovery Policy

**TSC Coverage:** A1.1, A1.2, A1.3
**Generate when:** always

### Decision points:
- If cloud = AWS: reference RDS snapshots, S3 cross-region replication, EBS snapshots, Route 53 failover, AWS Backup
- If cloud = GCP: reference Cloud SQL backups, GCS dual-region/multi-region, Persistent Disk snapshots, Cloud DNS failover
- If cloud = Azure: reference Azure SQL geo-replication, Azure Blob geo-redundant storage, managed disk snapshots, Azure Traffic Manager
- Backup specifics reference actual database types from intake.data.databases

### Template:

```markdown
# Business Continuity and Disaster Recovery Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.cto]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** A1.1, A1.2, A1.3

## 1. Purpose

Defines [intake.company.name]'s strategy for maintaining business operations and
recovering systems in the event of disruption, disaster, or major outage.

## 2. Scope

All production systems, data stores, and critical business operations that support
the delivery of [intake.company.product].

## 3. Recovery Objectives

| System | RTO (Recovery Time Objective) | RPO (Recovery Point Objective) | Justification |
|--------|------------------------------|-------------------------------|---------------|
| Production application | 4 hours | 1 hour | Customer-facing — direct revenue and trust impact |
| Production database | 4 hours | 1 hour (point-in-time recovery) | Core data store — data loss unacceptable |
| Authentication ([intake.infrastructure.identity_provider]) | 1 hour | N/A (managed SaaS) | Blocks all employee access if unavailable |
| Monitoring ([intake.infrastructure.monitoring]) | 8 hours | 24 hours | Degraded visibility, not customer-facing |
| Communication ([intake.infrastructure.communication]) | 8 hours | N/A (managed SaaS) | Internal coordination — can use backup channels |
| Source control ([intake.infrastructure.source_control]) | 8 hours | N/A (managed SaaS) | Blocks deployments but not existing production |
| CI/CD ([intake.infrastructure.ci_cd]) | 8 hours | N/A (managed SaaS) | Blocks new deployments only |

## 4. Backup Strategy

[IF cloud = AWS:]
| Data | Method | Frequency | Retention | Storage Location |
|------|--------|-----------|-----------|-----------------|
| Production database (RDS) | Automated RDS snapshots + continuous WAL archiving (point-in-time recovery) | Continuous PITR + daily automated snapshots | 90 days for snapshots; PITR within backup retention window | Cross-region: snapshots copied to [secondary region] |
| Object storage (S3) | S3 Cross-Region Replication (CRR) | Continuous (real-time replication) | Same lifecycle as source bucket | Secondary region S3 bucket |
| Block storage (EBS) | EBS snapshots via AWS Backup | Daily | 90 days | Same region (snapshots are incremental and region-redundant) |
| Application configuration | Stored in [intake.infrastructure.source_control] | Every commit | Indefinite | [intake.infrastructure.source_control] (managed SaaS) |
| Infrastructure state | Terraform state in S3 with versioning + DynamoDB lock | Every `terraform apply` | Versioned, 90-day lifecycle | Encrypted S3 bucket with versioning |
| Secrets | AWS Secrets Manager or SSM Parameter Store | Every change | Versioned | Managed service (region-redundant) |
[END IF]

[IF cloud = GCP:]
| Data | Method | Frequency | Retention | Storage Location |
|------|--------|-----------|-----------|-----------------|
| Production database (Cloud SQL) | Automated backups + point-in-time recovery via binary logging | Continuous PITR + daily automated backups | 90 days | Cross-region: backups stored in [secondary region] |
| Object storage (GCS) | Dual-region or multi-region bucket, or cross-region Transfer Service | Continuous (built into bucket type) or scheduled | Same lifecycle as source | Dual-region / multi-region GCS bucket |
| Persistent Disk | Scheduled snapshots via Cloud Scheduler or Snapshot Schedule | Daily | 90 days | Regional or multi-regional (snapshot is region-redundant) |
| Application configuration | Stored in [intake.infrastructure.source_control] | Every commit | Indefinite | [intake.infrastructure.source_control] (managed SaaS) |
| Infrastructure state | Terraform state in GCS with versioning | Every `terraform apply` | Versioned, 90-day lifecycle | Encrypted GCS bucket with versioning |
| Secrets | Secret Manager | Every change | Versioned | Managed service (region-redundant) |
[END IF]

[IF cloud = Azure:]
| Data | Method | Frequency | Retention | Storage Location |
|------|--------|-----------|-----------|-----------------|
| Production database (Azure SQL) | Automated backups with geo-replication | Continuous PITR + geo-redundant backups | 90 days (configurable) | Geo-paired region |
| Blob storage | Geo-redundant storage (GRS) or read-access GRS (RA-GRS) | Continuous (built into storage redundancy) | Same lifecycle as source | Geo-paired region |
| Managed disks | Azure Backup or disk snapshots | Daily | 90 days | Same region (backup vault is redundant) |
| Application configuration | Stored in [intake.infrastructure.source_control] | Every commit | Indefinite | [intake.infrastructure.source_control] (managed SaaS) |
| Infrastructure state | Terraform state in Azure Storage with versioning | Every `terraform apply` | Versioned, 90-day lifecycle | Encrypted Azure Storage with versioning |
| Secrets | Azure Key Vault | Every change | Versioned, soft-delete enabled | Managed service (region-redundant) |
[END IF]

## 5. Recovery Procedures

### Database Recovery
[IF cloud = AWS:]
1. Identify the target recovery point (timestamp before the incident)
2. Initiate RDS point-in-time recovery:
   `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier [prod-db] --target-db-instance-identifier [prod-db-recovered] --restore-time [ISO-8601-timestamp]`
3. Wait for new instance to become available
4. Verify data integrity on recovered instance (run validation queries)
5. Update application configuration or DNS to point to recovered instance
6. Verify application functionality end-to-end
7. Decommission old instance after confirmation
[END IF]

[IF cloud = GCP:]
1. Identify the target recovery point (timestamp before the incident)
2. Initiate Cloud SQL point-in-time recovery:
   `gcloud sql instances clone [source-instance] [recovered-instance] --point-in-time [ISO-8601-timestamp]`
3. Wait for clone to complete
4. Verify data integrity on recovered instance
5. Update application configuration to point to recovered instance
6. Verify application functionality end-to-end
7. Decommission old instance after confirmation
[END IF]

[IF cloud = Azure:]
1. Identify the target recovery point (timestamp before the incident)
2. Initiate Azure SQL point-in-time restore via portal or CLI:
   `az sql db restore --dest-name [recovered-db] --resource-group [rg] --server [server] --name [source-db] --time [ISO-8601-timestamp]`
3. Wait for restore to complete
4. Verify data integrity on recovered database
5. Update application configuration to point to recovered database
6. Verify application functionality end-to-end
7. Decommission old database after confirmation
[END IF]

### Full Region Failover
1. Confirm primary region is genuinely unavailable (not a transient issue — wait 15 minutes, check cloud provider status page)
2. [intake.people.cto] authorizes failover decision
3. Activate secondary region infrastructure:
   - If hot standby: infrastructure already running — proceed to step 4
   - If warm standby: scale up secondary region resources
   - If cold: deploy infrastructure from IaC ([intake.infrastructure.iac_tool]) to secondary region
4. Restore or promote database in secondary region
5. Update DNS to point to secondary region (TTL should already be low — 60 seconds recommended)
6. Verify all services operational in secondary region
7. Notify customers via status page and email
8. Plan and execute failback to primary region once it recovers

### Single Service Recovery
1. Identify the failed service via [intake.infrastructure.monitoring] alerts
2. Check if automated recovery has resolved it (auto-scaling, container restart, health check replacement)
3. If not resolved: redeploy the service from the last known-good version via [intake.infrastructure.ci_cd]
4. If infrastructure issue: restore from IaC (`[IF iac_tool = Terraform:]terraform apply[END IF][IF iac_tool = Pulumi:]pulumi up[END IF][IF iac_tool = CloudFormation:]deploy changeset[END IF]`)
5. Verify service health via [intake.infrastructure.monitoring]
6. Document the incident and recovery

## 6. DR Testing

**Frequency:** at least annually; recommended semi-annually

**Test types:**
- **Tabletop exercise:** walk through a disaster scenario with [intake.people.cto], [intake.people.security_lead], and on-call engineers. Document decisions, gaps, and action items.
- **Backup restore test:** restore production database backup to a test environment. Verify data integrity. Measure time to recovery (compare against RTO). Run at least annually.
- **Failover test (recommended):** actually fail over to secondary region during a planned maintenance window. Measure recovery time. Verify customer-facing functionality. Run if resources allow.

**Document results:**
- What was tested (scope, systems, scenario)
- Time to recovery (actual vs. RTO target)
- Issues discovered during testing
- Action items with owners and deadlines
- Store evidence in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:][intake.infrastructure.ticketing][END IF]

## 7. Communication During Outage

| Audience | Channel | Timeline |
|----------|---------|----------|
| Internal team | [intake.infrastructure.communication] #incidents channel | Immediately upon detection |
| Customers | Status page + email | Within 1 hour of confirmed outage |
| Customers (update) | Status page | Every hour until resolved |
| Customers (resolved) | Status page + email | Within 1 hour of resolution |
| Post-incident | Email to affected customers | Within 5 business days (post-mortem summary) |

## 8. Exceptions

Changes to RTO/RPO targets require approval from [intake.people.ceo].
Skipping a scheduled DR test requires documented justification and [intake.people.cto] approval.

## 9. Review Schedule

This policy is reviewed annually, after every DR test, and after any real disaster recovery event.
```

---

## Policy 10: Encryption Policy

**TSC Coverage:** CC6.1, CC6.7
**Generate when:** always

### Decision points:
- If cloud = AWS: reference AWS KMS, S3 SSE-KMS, EBS encryption, RDS encryption, ACM
- If cloud = GCP: reference Cloud KMS, GCS CMEK, Persistent Disk encryption, Cloud SQL encryption, managed SSL certs
- If cloud = Azure: reference Azure Key Vault, Storage Service Encryption, Azure Disk Encryption, Azure SQL TDE, App Service managed certs

### Template:

```markdown
# Encryption Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.cto]
**Approved By:** [intake.people.security_lead]
**TSC Coverage:** CC6.1, CC6.7

## 1. Purpose

Defines encryption standards for all data at rest and in transit within
[intake.company.name] systems. Ensures consistent, auditable cryptographic protection.

## 2. Scope

All systems, storage, and communication channels used to process or store
[intake.company.name] and customer data.

## 3. Encryption Standards

| Context | Minimum Standard | Preferred | Prohibited |
|---------|-----------------|-----------|------------|
| Data at rest | AES-256 | AES-256-GCM | DES, 3DES, AES-128, RC4 |
| Data in transit | TLS 1.2 | TLS 1.3 | SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 |
| Password hashing | bcrypt (cost factor 12) | Argon2id | MD5, SHA-1, SHA-256 (unsalted), plain text |
| Digital signatures | RSA-2048, ECDSA P-256 | RSA-4096, ECDSA P-384, Ed25519 | RSA-1024, DSA |
| Key exchange | ECDHE-RSA, ECDHE-ECDSA | X25519 | Static RSA key exchange, DHE < 2048-bit |
| Key management | Cloud-managed KMS | HSM-backed KMS | Keys in source code, config files, or env vars |
| Key rotation | Annual minimum | Quarterly | Manual/never |

## 4. Implementation Checklist

### At Rest
[IF cloud = AWS:]
- [ ] RDS encryption enabled (AES-256 via KMS) — must be set at instance creation
- [ ] S3 default encryption enabled (SSE-KMS with dedicated CMK, not SSE-S3)
- [ ] EBS encryption enabled by default for all new volumes in all regions
- [ ] DynamoDB encryption enabled (AWS managed key or CMK)
- [ ] ElastiCache encryption at rest enabled
- [ ] Backup encryption: all automated and manual snapshots inherit source encryption
[END IF]
[IF cloud = GCP:]
- [ ] Cloud SQL encryption enabled (Google-managed key or CMEK via Cloud KMS)
- [ ] GCS default encryption (Google-managed key or CMEK)
- [ ] Persistent Disk encryption enabled (default Google-managed; CMEK for Restricted data)
- [ ] Datastore/Firestore encryption enabled (automatic with Google-managed keys)
- [ ] Memorystore encryption at rest enabled
- [ ] Backup encryption: all backups inherit source encryption settings
[END IF]
[IF cloud = Azure:]
- [ ] Azure SQL Transparent Data Encryption (TDE) enabled with service-managed or customer-managed key
- [ ] Azure Blob Storage encryption enabled (Microsoft-managed or customer-managed key via Key Vault)
- [ ] Azure Managed Disk encryption enabled (Azure Disk Encryption or server-side encryption with CMK)
- [ ] Cosmos DB encryption at rest enabled (automatic with Microsoft-managed keys; CMK available)
- [ ] Azure Cache for Redis encryption at rest enabled
- [ ] Backup encryption: Azure Backup vault encryption with platform or customer-managed keys
[END IF]
- [ ] Laptop full-disk encryption enforced: FileVault (macOS), BitLocker (Windows)[IF mdm exists:] — verified via [intake.infrastructure.mdm][END IF]

### In Transit
- [ ] All public endpoints serve HTTPS only (HTTP requests redirect to HTTPS)
- [ ] TLS 1.2 minimum enforced; TLS 1.0 and 1.1 disabled
- [ ] Internal service-to-service communication uses TLS or mTLS
- [ ] Database connections require SSL (reject unencrypted connections)
[IF cloud = AWS:]
- [ ] Certificate management via ACM (auto-renewal) for public endpoints
- [ ] RDS `rds.force_ssl = 1` parameter set
[END IF]
[IF cloud = GCP:]
- [ ] Certificate management via Google-managed SSL certificates (auto-renewal)
- [ ] Cloud SQL `require_ssl = true` flag set
[END IF]
[IF cloud = Azure:]
- [ ] Certificate management via App Service managed certificates or Key Vault
- [ ] Azure SQL `Minimum TLS Version` set to 1.2
[END IF]

### Key Management
[IF cloud = AWS:]
- [ ] Encryption keys stored in AWS KMS — never in application code, config files, or environment variables
- [ ] Automatic annual key rotation enabled on all KMS CMKs
- [ ] Key access restricted to specific IAM roles via KMS key policy
- [ ] Key usage logged via CloudTrail KMS events
- [ ] Secrets stored in AWS Secrets Manager or SSM Parameter Store (SecureString)
[END IF]
[IF cloud = GCP:]
- [ ] Encryption keys stored in Cloud KMS — never in application code, config files, or environment variables
- [ ] Automatic key rotation configured (recommended: 90 days)
- [ ] Key access restricted to specific IAM roles via KMS IAM bindings
- [ ] Key usage logged via Cloud Audit Logs
- [ ] Secrets stored in Secret Manager
[END IF]
[IF cloud = Azure:]
- [ ] Encryption keys stored in Azure Key Vault — never in application code, config files, or environment variables
- [ ] Automatic key rotation configured via Key Vault rotation policy
- [ ] Key access restricted via Key Vault access policies or Azure RBAC
- [ ] Key usage logged via Key Vault diagnostics (sent to Azure Monitor)
- [ ] Secrets stored in Key Vault secrets
[END IF]

### Secret Management
- [ ] Repository scanning enabled for leaked secrets ([intake.infrastructure.source_control] secret scanning, or GitGuardian/gitleaks)
- [ ] Pre-commit hooks to catch secrets before they are committed
- [ ] Secret rotation procedures documented for each secret type
- [ ] Compromised secrets rotated immediately upon discovery — no exceptions

## 5. Exceptions

Any exception to encryption standards (e.g., a legacy system that does not support
TLS 1.2) must be:
1. Documented with business justification and compensating controls
2. Approved by [intake.people.security_lead]
3. Time-limited with a remediation plan
4. Recorded in the risk register

## 6. Review Schedule

This policy is reviewed annually and whenever new storage or communication
systems are introduced.
```

---

## Policy 11: Human Resources Security Policy

**TSC Coverage:** CC1.4
**Generate when:** always

### Decision points:
- Onboarding checklist references actual IdP, MDM, password manager, communication tool
- Offboarding references actual tools and deprovisioning SLAs
- If mdm = none: adjust device management steps
- If edr = none: adjust endpoint steps

### Template:

```markdown
# Human Resources Security Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.hr_lead]
**Approved By:** [intake.people.ceo]
**TSC Coverage:** CC1.4

## 1. Purpose

Defines security requirements throughout the employee lifecycle: pre-employment,
onboarding, ongoing employment, and offboarding. Ensures people-related security
risks are managed consistently.

## 2. Scope

All employees and contractors of [intake.company.name].

## 3. Pre-Employment

- Background check REQUIRED for all employees before their start date
- Background check includes: identity verification, criminal record check, employment history verification
- Background check provider: [agent fills from company's provider, or recommend Checkr/GoodHire]
- Results reviewed by [intake.people.hr_lead] and retained securely (classification: Restricted)
- Employment offer contingent on satisfactory background check results
- Contractors: equivalent background checks required before any system access is granted
- International hires: country-appropriate background check equivalent

## 4. Onboarding Checklist (Day 1)

Complete ALL items before the employee accesses any production systems:

| Step | Action | Responsible | System |
|------|--------|------------|--------|
| 1 | Create user account | [intake.people.hr_lead] or IT | [intake.infrastructure.identity_provider] |
| 2 | Configure and verify MFA | New employee | [intake.infrastructure.identity_provider] |
| 3 | Add to appropriate access groups (per Access Control Policy) | [intake.people.security_lead] or IT | [intake.infrastructure.identity_provider] |
[IF mdm exists:]
| 4 | Enroll device in MDM | New employee / IT | [intake.infrastructure.mdm] |
[END IF]
| 5 | Create password manager account | IT | [intake.infrastructure.password_manager] |
[IF edr exists:]
| 6 | Verify EDR agent is installed and reporting | IT | [intake.infrastructure.edr] |
[END IF]
| 7 | Sign Acceptable Use Policy | New employee | HR system or DocuSign |
| 8 | Sign confidentiality / NDA agreement | New employee | HR system or DocuSign |
| 9 | Acknowledge employee handbook | New employee | HR system |
| 10 | Assign security awareness training (due within 7 days) | [intake.people.hr_lead] | Training platform |
| 11 | Create onboarding ticket tracking completion of all steps | [intake.people.hr_lead] | [intake.infrastructure.ticketing] |

Onboarding ticket is not closed until ALL steps are confirmed complete.

## 5. Security Awareness Training

- **Required for:** all employees and contractors
- **Initial:** complete within 7 days of hire
- **Renewal:** annually (within 30 days of anniversary or company-wide annual date)
- **Topics must cover:**
  - Phishing identification and reporting
  - Password hygiene and MFA usage
  - Data classification and handling (four levels)
  - Incident reporting procedures (how and when to report)
  - Acceptable use of company systems
  - Social engineering awareness (vishing, pretexting, tailgating)
  - Secure remote work practices
- **Delivery:** online training platform (KnowBe4, Curricula, or equivalent)
- **Evidence:** completion certificates retained in [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:]HR system[END IF]
- **Non-completion:** employees who do not complete training within the required window have their access restricted until completion

## 6. Phishing Simulation Program

- **Frequency:** quarterly (every 90 days)
- **Method:** simulated phishing emails sent to all employees via training platform
- **Scenarios:** rotate through common vectors — credential harvesting, malicious attachment, CEO impersonation, vendor impersonation
- **Results tracked per employee:**
  - Did not click: no action needed
  - Clicked but did not submit credentials: receives brief awareness reminder
  - Submitted credentials: mandatory supplemental training within 7 days
  - Reported the phishing email: positive recognition
- **Metrics reported quarterly to [intake.people.security_lead]:** click rate, credential submission rate, report rate, trends over time
- **Target:** organization click rate below 5% within 12 months

## 7. Offboarding Checklist

Complete ALL items within the deprovisioning SLA:
- Voluntary departure: within 24 hours of last working day
- Involuntary termination: within 1 hour of notification
- Security incident (compromised account): immediately

| Step | Action | Responsible | System |
|------|--------|------------|--------|
| 1 | Disable user account (cascades SSO to all connected apps) | IT / [intake.people.security_lead] | [intake.infrastructure.identity_provider] |
| 2 | Terminate all active sessions | IT | [intake.infrastructure.identity_provider] |
| 3 | Revoke personal API keys and tokens | IT / Engineering | All systems with programmatic access |
| 4 | Remove from source control organization | IT | [intake.infrastructure.source_control] |
| 5 | Remove from communication workspace | IT | [intake.infrastructure.communication] |
| 6 | Remove from all access groups | IT | [intake.infrastructure.identity_provider] |
| 7 | Retrieve company device | IT / HR | Physical |
[IF mdm exists:]
| 8 | Remote wipe company device | IT | [intake.infrastructure.mdm] |
[END IF]
| 9 | Rotate shared credentials if departing employee had access | [intake.people.security_lead] | Relevant systems |
| 10 | Conduct exit interview (voluntary departures) | [intake.people.hr_lead] | — |
| 11 | Complete offboarding ticket with confirmation of all steps | [intake.people.hr_lead] | [intake.infrastructure.ticketing] |
| 12 | Spot-check: verify no residual access | [intake.people.security_lead] | [intake.infrastructure.identity_provider], cloud console, [intake.infrastructure.source_control] |

THIS CHECKLIST IS CRITICAL. Incomplete offboarding is one of the most common SOC 2 findings.
Auditors will sample departures and verify every step was completed within the SLA.

## 8. Ongoing Employment

- Role changes: access updated within 2 business days; old role access removed (not just new access added)
- Annual re-acknowledgment of Acceptable Use Policy
- Annual security awareness training completion
- Quarterly phishing simulation participation
- Disciplinary action for policy violations documented in HR records

## 9. Exceptions

Exceptions to background check requirements (e.g., short-term contractor for
non-sensitive work) require written approval from [intake.people.hr_lead] and
[intake.people.security_lead].

## 10. Review Schedule

This policy is reviewed annually and after any personnel-related security incident.
```

---

## Policy 12: Data Retention and Disposal Policy

**TSC Coverage:** CC6.5
**Generate when:** always

### Decision points:
- If pii_handled = true: include GDPR/CCPA deletion requirements and customer right-to-erasure process
- If phi_handled = true: include HIPAA retention minimums (6 years for certain records)
- Reference actual database and storage types from intake for disposal methods
- If cloud = AWS: reference S3 lifecycle policies, RDS snapshot deletion
- If cloud = GCP: reference GCS lifecycle policies, Cloud SQL backup deletion

### Template:

```markdown
# Data Retention and Disposal Policy
**[intake.company.name]**
**Version:** 1.0
**Effective Date:** [generation_date]
**Last Reviewed:** [generation_date]
**Owner:** [intake.people.compliance_owner]
**Approved By:** [intake.people.cto]
**TSC Coverage:** CC6.5

## 1. Purpose

Defines how long [intake.company.name] retains different categories of data and
how data is securely disposed of when the retention period expires. Ensures compliance
with legal, regulatory, and contractual obligations.

## 2. Scope

All data created, collected, processed, or stored by [intake.company.name],
across all systems, backups, and third-party services.

## 3. Retention Schedule

| Data Category | Retention Period | Legal Basis | System(s) | Disposal Method |
|--------------|-----------------|-------------|-----------|-----------------|
| Customer application data | Duration of contract + 30 days | Contractual obligation, customer expectation | Production database, backups | Cryptographic erasure from all systems |
| Customer PII | Duration of contract + 30 days | Privacy obligations (GDPR, CCPA, contractual) | Production database, backups | Cryptographic erasure from all systems |
| Application logs (non-security) | 1 year | Operational troubleshooting | [intake.infrastructure.monitoring], log storage | Automatic expiration via TTL/lifecycle policy |
| Security and audit logs | 1 year minimum (recommend 2 years) | SOC 2 requirement, incident investigation | [IF cloud = AWS:]CloudTrail S3 bucket, CloudWatch Logs[END IF][IF cloud = GCP:]Cloud Audit Logs, Cloud Logging[END IF][IF cloud = Azure:]Azure Monitor, Log Analytics[END IF] | Automatic expiration via lifecycle policy |
| Authentication logs | 1 year minimum | SOC 2 requirement | [intake.infrastructure.identity_provider], cloud provider | Automatic expiration per provider settings |
| Employee HR records | Duration of employment + 3 years | Employment law | HR system | Secure deletion |
| Financial records | 7 years | Tax and accounting requirements (IRS, state) | Financial systems | Secure deletion |
| Contracts and agreements | Duration + 3 years | Legal requirements | Document storage | Secure deletion |
| Backup data | 90 days rolling | Operational recovery | [IF cloud = AWS:]S3, RDS snapshots, EBS snapshots[END IF][IF cloud = GCP:]GCS, Cloud SQL backups, disk snapshots[END IF][IF cloud = Azure:]Blob storage, Azure SQL backups, disk snapshots[END IF] | Automatic expiration via retention policy (encrypted backups) |
| Marketing and analytics data | 2 years | Business purpose | Analytics platforms | Standard deletion |
| Vendor assessment records | 3 years after vendor relationship ends | Compliance audit trail | [IF compliance_platform exists:][intake.compliance.compliance_platform][END IF][IF NOT compliance_platform exists:]Document storage[END IF] | Secure deletion |
| Incident response records | 3 years | SOC 2 requirement, legal | [intake.infrastructure.ticketing], document storage | Secure deletion |
[IF phi_handled = true:]
| HIPAA-related documentation | 6 years from creation or last effective date | HIPAA requirement (45 CFR 164.530(j)) | HR system, compliance platform | Secure deletion per NIST SP 800-88 |
[END IF]

## 4. Disposal Methods by Data Classification

| Classification | Disposal Method | Verification |
|---------------|-----------------|-------------|
| Restricted | Cryptographic erasure (delete encryption keys rendering data unreadable) OR DOD 5220.22-M compliant overwrite (3-pass minimum) OR physical destruction | Written confirmation of disposal method and date |
| Confidential | Secure deletion (single-pass overwrite) or cryptographic erasure | Disposal logged in [intake.infrastructure.ticketing] |
| Internal | Standard deletion (file system delete) | No special verification required |
| Public | Standard deletion | No special verification required |

For cloud-hosted data:
[IF cloud = AWS:]
- S3: delete objects + delete bucket, or rely on lifecycle policy auto-expiration. For Restricted data in S3 with SSE-KMS: schedule KMS key deletion (7-30 day waiting period) as cryptographic erasure.
- RDS: delete instance with final snapshot (retained per policy), then delete snapshot after retention. For encrypted instances, deleting the KMS key renders all snapshots unreadable.
- EBS: delete volume (data is cryptographically erased because EBS volumes are encrypted). Snapshots follow separate lifecycle.
[END IF]
[IF cloud = GCP:]
- GCS: delete objects + delete bucket, or rely on lifecycle policy auto-expiration. For Restricted data with CMEK: schedule Cloud KMS key version destruction (24-hour minimum waiting period).
- Cloud SQL: delete instance. Automated backups are deleted with the instance. On-demand backups must be deleted separately.
- Persistent Disk: delete disk. For CMEK-encrypted disks, destroying the key version renders data unreadable.
[END IF]
[IF cloud = Azure:]
- Blob Storage: delete blobs + container, or rely on lifecycle management auto-expiration. For Restricted data with CMK: disable key in Key Vault (soft-delete period applies).
- Azure SQL: delete database. Geo-replicated copies must be deleted separately. Backups follow retention policy.
- Managed Disks: delete disk. For customer-managed key encryption, disabling the key renders data unreadable.
[END IF]

## 5. Customer Data Deletion Process

When a customer terminates their contract:

1. **Day 0:** Customer contract terminates. Customer notified that data will be retained for 30 days and then permanently deleted.
2. **Days 0-30:** Customer may request a data export. Provide export in a standard format (JSON, CSV) via secure download link.
3. **Day 30:** Begin deletion process:
   a. Delete all customer data from production database (all tables referencing this customer)
   b. Delete from all read replicas (verify replication propagation)
   c. Delete from application caches
   d. Delete customer-specific files from object storage
   e. Remove customer-specific configuration
4. **Day 30-120:** Backups containing customer data age out per 90-day backup retention. No action needed — automated expiration handles this.
5. **Post-deletion:** Send written confirmation to the customer that their data has been deleted from all production systems, with note that backup expiration will complete within 90 days.
6. **Documentation:** record the deletion in [intake.infrastructure.ticketing] with:
   - Customer name and contract end date
   - Date deletion was executed
   - Systems from which data was deleted
   - Confirmation that all steps were completed
   - Name of person who executed the deletion

[IF pii_handled = true:]
### Right to Erasure (GDPR Article 17 / CCPA Delete Requests)

For individual data subject deletion requests (separate from contract termination):
1. Receive and log the request in [intake.infrastructure.ticketing]
2. Verify the identity of the requester
3. Determine if an exemption applies (legal obligation, legitimate interest, legal claims)
4. If no exemption: delete the individual's PII from all production systems within 30 days
5. Notify any third parties to whom the PII was disclosed (per vendor DPA terms)
6. Confirm deletion to the requester in writing
7. Backups: PII in backups will age out per retention policy. If the backup is restored, the deletion must be re-applied.
[END IF]

## 6. Legal Hold Procedure

If litigation, regulatory investigation, or government inquiry is pending or reasonably anticipated:

1. [intake.people.compliance_owner] or legal counsel issues a legal hold notice
2. ALL deletion and disposal of potentially relevant data is immediately suspended
3. Legal hold notice specifies:
   - Scope: which data categories, systems, and time periods are covered
   - Start date
   - Affected custodians (employees whose data may be relevant)
   - Preservation obligations
4. Affected employees are notified of their preservation obligations
5. Automated deletion policies (lifecycle rules, TTLs) are suspended or overridden for in-scope data
6. Legal hold is documented and tracked by [intake.people.compliance_owner]
7. Legal hold is lifted ONLY when legal counsel confirms the matter is resolved
8. Upon lifting: resume normal retention and disposal; document the hold period

## 7. Exceptions

Extensions to retention periods require written approval from [intake.people.compliance_owner]
and legal counsel. Shortened retention periods are not permitted where a legal minimum applies.

## 8. Review Schedule

This policy is reviewed annually, when new data types are introduced, when entering
new jurisdictions with different retention requirements, or when regulatory requirements change.
```

---

## Cross-reference: TSC criteria to policies

For the auditor and for the agent to verify complete coverage:

| TSC Criteria | Policy | Section |
|-------------|--------|---------|
| CC1.1 — COSO principle 1: integrity and ethical values | Information Security Policy | Sections 1-3, 7-8 |
| CC1.2 — COSO principle 2: board oversight | Information Security Policy | Section 3 (roles table) |
| CC1.3 — COSO principle 3: management structure | Information Security Policy | Sections 3, 6 |
| CC1.4 — COSO principle 4: commitment to competence | Acceptable Use Policy, HR Security Policy | AUP entire; HRS Sections 4-6 |
| CC1.5 — COSO principle 5: accountability | Information Security Policy | Sections 3, 7, 8 |
| CC2.1 — information and communication (internal) | Information Security Policy | Section 4, 6 |
| CC2.2 — communication of policies | Acceptable Use Policy | Entire policy; acknowledgment block |
| CC2.3 — communication with external parties | Information Security Policy | Section 6 (vendor, customer references) |
| CC3.1 — risk identification | Risk Assessment Policy | Sections 4.1-4.2 |
| CC3.2 — risk analysis | Risk Assessment Policy | Section 4.3 (likelihood x impact) |
| CC3.3 — risk significance | Risk Assessment Policy | Section 4.3 (risk matrix) |
| CC3.4 — risk response | Risk Assessment Policy | Sections 4.5, 5 |
| CC6.1 — logical access security | Access Control Policy, Data Classification Policy, Encryption Policy | ACP Sections 3-6; DCP Section 4; EP entire |
| CC6.2 — access provisioning | Access Control Policy | Section 5 (onboarding, role change) |
| CC6.3 — access removal | Access Control Policy | Section 5 (offboarding, deprovisioning SLAs) |
| CC6.5 — data disposal | Data Retention and Disposal Policy | Sections 3-6 |
| CC6.6 — restriction of access | Access Control Policy | Sections 4, 6 (RBAC, privileged access) |
| CC6.7 — data protection | Data Classification Policy, Encryption Policy | DCP Sections 3-4; EP Sections 3-4 |
| CC6.8 — prevention of unauthorized removal | Access Control Policy | Section 4 (RBAC), Section 6 (privileged access) |
| CC7.3 — detection of security events | Incident Response Policy | Section 5, Step 1 (detection sources) |
| CC7.4 — response to security events | Incident Response Policy | Section 5, Steps 2-5 |
| CC7.5 — recovery and communication | Incident Response Policy | Section 5, Steps 5-7 |
| CC8.1 — change management | Change Management Policy | Entire policy |
| CC9.2 — vendor risk management | Vendor Management Policy | Entire policy |
| A1.1 — processing capacity | BCP/DR Policy | Section 3 (RTO/RPO) |
| A1.2 — recovery procedures | BCP/DR Policy | Sections 4-5 |
| A1.3 — recovery testing | BCP/DR Policy | Section 6 |
