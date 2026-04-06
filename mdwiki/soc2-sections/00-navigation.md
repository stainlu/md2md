# SOC 2 Implementation Skill — Navigation

executable SOC 2 implementation playbook for AI agents. contains discovery commands, remediation procedures (DISCOVER > FIX > VERIFY > EVIDENCE), policy templates, evidence automation, and audit preparation — everything to take a company from zero to SOC 2 report.

> SOC 2 = Service Organization Control 2 (AICPA). attestation report, not certification. security is the only mandatory TSC category. type II (controls proven over 3-12 months) is what enterprise buyers expect.

**what you can do with this file:** assess a company's current security posture, fix every gap with copy-paste commands, generate customized policies, automate evidence collection, and prepare for audit fieldwork.

---

## how to use this file

### route by task

| situation | start here |
|-----------|-----------|
| starting from scratch | section 01 (intake + discovery) |
| know the gaps, need to fix AWS | section 02 (AWS controls) |
| fixing GitHub, Okta, Google Workspace, or endpoint gaps | section 03 (platform controls) |
| writing policies | section 04 (policies with decision logic) |
| collecting evidence | section 05, part 1 (evidence automation) |
| integrating a compliance platform (Vanta, Drata, etc.) | section 05, part 2 (platform integration) |
| preparing for audit | section 05, part 3 (audit prep) |
| ongoing maintenance | section 05, part 4 (operations) |

### route by cloud provider

| provider | sections to read |
|----------|-----------------|
| AWS | 01 (discovery) + 02 (AWS controls) |
| GCP | 01 (discovery) + 03 has GCP stubs in deprovisioning only; full GCP controls section not yet written |
| Azure | 01 (discovery) + 03 has Azure stubs in deprovisioning only; full Azure controls section not yet written |
| multi-cloud | 01 + 02 (AWS) + relevant parts of 03 |

### route by identity provider

| provider | where |
|----------|-------|
| Okta | section 03, subsection 3.2 (~line 5670 in assembled file) |
| Google Workspace | section 03, subsection 3.3 (~line 6414 in assembled file) |
| neither configured | flag as GAP — section 01 intake will catch this |

---

## table of contents

| section | title | content | lines (assembled) |
|---------|-------|---------|--------------------|
| 00 | navigation | this section — overview, routing, TOC | 1-~150 |
| 01 | discovery & assessment | intake questionnaire, Prowler scan, manual discovery commands, gap report template | ~150-1120 |
| 02 | AWS security controls | 40+ controls across IAM, CloudTrail, GuardDuty, Config, S3, RDS, VPC, KMS, CloudWatch — each with DISCOVER > FIX > VERIFY > EVIDENCE. includes Terraform module and Config auto-remediation | ~1120-5040 |
| 03 | platform controls | GitHub (branch protection, secret scanning, Dependabot, Actions security), Okta (MFA, password, session, deprovisioning), Google Workspace, endpoint security (MDM, encryption, EDR), deprovisioning deep dive | ~5040-7630 |
| 04 | policies with decision logic | 12 policy templates that reference actual discovered infrastructure — not placeholders. includes information security, access control, change management, incident response, and more | ~7630-9610 |
| 05 | evidence, audit prep & operations | part 1: Steampipe queries + evidence scripts. part 2: compliance platform integration (Vanta, Drata, Secureframe, Sprinto). part 3: system description template, control matrix, auditor interview prep. part 4: annual calendar, change-triggered reassessment, common exceptions. part 5: quick reference tables | ~9610-11810 |

### section 03 subsection index

| subsection | topic | offset in section file |
|------------|-------|----------------------|
| 3.1 | GitHub / source control | line 9 |
| 3.2 | Okta identity provider | line 635 |
| 3.3 | Google Workspace | line 1378 |
| 3.4 | endpoint security (MDM, encryption, EDR) | line 1614 |
| 3.5 | deprovisioning deep dive | line 2175 |

### section 05 part index

| part | topic | offset in section file |
|------|-------|----------------------|
| part 1 | evidence collection automation (Steampipe, access review, encryption, change mgmt, backup) | line 7 |
| part 2 | compliance platform integration (Vanta, Drata, Secureframe, Sprinto, manual) | line 1057 |
| part 3 | audit preparation (system description, control matrix, interview prep, assertion letter) | line 1446 |
| part 4 | ongoing operations (annual calendar, change triggers, common exceptions) | line 1912 |
| part 5 | quick reference tables | line 2106 |

---

## quick reference

five facts before you start:

1. **security is the only mandatory TSC category** — availability, processing integrity, confidentiality, and privacy are optional add-ons
2. **type II is what buyers expect** — type I (point-in-time) exists but enterprise procurement requires type II (3-12 month observation period)
3. **#1 audit exception: late deprovisioning** — 68% of qualified opinions cite access not revoked within SLA. section 03.5 covers this in depth
4. **Prowler is the backbone** — `prowler aws --compliance soc2_aws` scans all AWS controls at once. section 01 covers setup and interpretation
5. **every control follows DISCOVER > FIX > VERIFY > EVIDENCE** — discover the current state, fix the gap, verify the fix worked, collect evidence for the auditor

---

## prerequisites

what the agent needs before starting:

| requirement | why |
|-------------|-----|
| cloud provider credentials (AWS CLI configured, or GCP/Azure equivalents) | discovery and remediation commands need authenticated access |
| GitHub CLI authenticated (`gh auth login`) | section 03 GitHub controls use `gh api` calls |
| identity provider API token (Okta API token or Google Workspace admin SDK access) | section 03 identity controls query and configure IdP |
| Python 3.9+ | Prowler requires Python |
| Steampipe | section 05 evidence collection queries run on Steampipe |
| jq | JSON parsing throughout all sections |
| curl, bash | scripts assume bash with curl available |

### install Prowler (if not already installed)

```bash
pip install prowler
prowler aws --list-compliance | grep soc2
```

### install Steampipe (if not already installed)

```bash
brew install turbot/tap/steampipe   # macOS
steampipe plugin install aws
```

---

## control flow

```
intake questionnaire (01)
        |
        v
discovery scan: Prowler + manual commands (01)
        |
        v
gap report (01)
        |
        v
fix AWS controls (02)  +  fix platform controls (03)
        |                          |
        v                          v
generate policies from discovered state (04)
        |
        v
automate evidence collection (05, part 1-2)
        |
        v
audit prep: system description + control matrix + interview prep (05, part 3)
        |
        v
ongoing: annual calendar + change triggers (05, part 4)
```

---

*end of navigation section. proceed to section 01 for discovery.*
