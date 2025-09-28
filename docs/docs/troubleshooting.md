!!! warning "Start here when something goes wrong"
    This Troubleshooting Guide highlights common issues and practical fixes. If problems persist, collect logs and audit records before contacting support.

# Troubleshooting Guide :mag_right:

Each section includes symptoms, likely causes, and steps to resolve.

## 1) Admin Console inaccessible

Symptoms:
- Cannot reach the Admin Console URL

Likely causes & fixes:
- Network/DNS misconfiguration: verify your load balancer and DNS entries
- TLS issues: check certificate validity and chain
- Service down: inspect the Gateway and Admin API health endpoints

## 2) Missing objects in Storage

Symptoms:
- Object ID returns 404 or not found in browser

Causes & fixes:
- Retention policy applied: check retention rules and archived location
- Insufficient role: confirm your account has read access
- Wrong object ID: search by metadata filters in Storage Browser

## 3) Messages not delivered to plugin

Symptoms:
- Messaging publishes but plugins report no receipt

Causes & fixes:
- Plugin not subscribed: check manifest and subscription list
- Filter rules blocking messages: inspect Messaging filters in Policies
- Plugin unhealthy: open plugin health page in Admin Console and restart if needed

## 4) Transformations yield unexpected results

Symptoms:
- Canonical objects missing fields or values changed unexpectedly

Causes & fixes:
- Transformation rules changed: review transformation policies
- Input did not match expected schema: validate upstream payloads via Gateway logs

## 5) Audit entries missing or incomplete

Symptoms:
- No audit records for operations you performed

Causes & fixes:
- Insufficient role to view audits: request audit-view role
- Audit subsystem unhealthy: check Admin API /admin/health for audit status
- Log indexing delay: wait briefly for background indexers or check system queues

## 6) Plugin setup failing in Admin Console

Symptoms:
- Setup wizard reports an error when validating credentials

Causes & fixes:
- Wrong credentials: re-enter via Admin Console and avoid copy/paste issues
- Outbound network restrictions: confirm gateway allowlists and firewall rules
- Plugin implementation error: check plugin logs and health endpoints

## Collecting logs and evidence

When opening a support ticket or escalating:
- Record the request/response payloads (redact PHI)
- Note timestamps and object IDs
- Export audit slices covering the timeframe
- Include plugin health and system health snapshots

!!! tip "Redact before sharing"
    Before sharing logs externally, redact PHI/PII and follow your organization's data handling guidelines.
