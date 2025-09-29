# Operator Allowlist

Operator Lane RPCs are allowed on a per‑caller→target basis. Core enforces a fine‑grained allowlist stored in ConfigService at keys like `operator.allow.<caller->target>`.

## Admin Console

- Open Admin Console → Operator Policy.
- Enter caller and target plugin IDs.
- Click “Auto‑generate” to seed operations from the target plugin’s manifest endpoints.
- Edit or paste operations, then click Save.
- Optional: Toggle “Allow manifest‑declared operations without explicit allowlist” for development, then “Save Dev Toggle”. This sets `operator.allow.dev_all` in ConfigService.

## API

- Get: `GET /admin/operator/allowlist?caller=<id>&target=<id>` → `{ caller, target, operations[] }`
- Set: `PUT /admin/operator/allowlist { caller, target, operations[] }`
- Auto‑generate: `POST /admin/operator/allowlist/auto-generate { caller, target, merge?: true }`
  - Uses the target plugin’s manifest `endpoints` keys as operations. When `merge=true`, merges with existing operations.

## Development Mode

- For development only, you can allow any operation that is declared in the target’s manifest without adding it to the allowlist:
  - Env: `DEV_MODE=true`, or
  - Config: `operator.allow.dev_all=true` (via Admin Console → Operator Policy toggle)

This preserves Admin Console parity while enabling quick iteration.

