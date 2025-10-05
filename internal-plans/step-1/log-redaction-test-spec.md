# Log Redaction Test Spec — Step 1

Objective: Prove no PHI/PII/tokens leak into logs for integration actions.

## Patterns to Forbid (non‑exhaustive)
- OAuth tokens and codes: strings of length ≥ 20 with mixed case/nums; common keys: `access_token`, `refresh_token`, `code`
- Email patterns: `/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/`
- Phone: `/\+?\d[\d\-() ]{7,}\d/`
- SSN: `/\b\d{3}-\d{2}-\d{4}\b/`
- Address keywords: `address`, `street`, `city`, `state`, `zip`

## Allowed Fields in Audit Details
- `provider`, `result`, `account_name` (non‑sensitive display), counts (e.g., `contacts_count`)
- Never: raw IDs, tokens, emails, phone numbers

## Test Approach (pytest)
1) Capture logs during:
   - Connect initiation (POST `/integrations/{provider}/connect`)
   - Callback (GET `/integrations/{provider}/callback?code=...` using `TEST_CODE` in test mode)
   - Status and revoke flow
2) Assert no forbidden patterns present in captured logs.
3) Assert audit events exist with expected safe fields only (parse JSON lines from `audit_event=` entries).

## Implementation Hints
- Configure Python logging to stream to a buffer in tests (caplog or custom handler)
- Use environment toggle to force `TEST_CODE` path in integrator
- Keep test data non‑sensitive; do not introduce real emails in fixtures

