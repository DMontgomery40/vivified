# Frigg Module Selection Matrix — Step 1

Goal: Choose stable, widely used modules with pinned versions for a self‑hosted integrator. Favor CRM (HubSpot) for end‑to‑end demo.

## Environment
- Node: 20.x (LTS)
- Package manager: npm (lock via package-lock.json)

## Candidates

| Provider | Package | Latest | Chosen | Notes |
|---|---|---:|---:|---|
| HubSpot | `@friggframework/api-module-hubspot` | 1.1.7 | 1.1.7 | Mature, used in tutorials; OAuth2; contact/deal APIs |
| Salesforce | `@friggframework/api-module-salesforce` | tbd | tbd | Consider for Phase 2; verify token model |
| Slack | `@friggframework/api-module-slack` | tbd | tbd | Event model differs; not needed for Step 1 |

Note: Only HubSpot is targeted for Step 1 acceptance criteria. Others are tracked for future expansion.

## Version Pinning Policy
- Use caret pins to latest minor when safe (e.g., `^1.1.7`) and record the resolved version in the PR.
- Breakage response: freeze exact version and open follow‑up task to validate upgrades.

## Selection Rationale
- HubSpot alignment with requirements; strong docs and module maturity.
- Low risk OAuth2 with refresh; simple sample data path (contacts metadata).

