# Messaging (Canonical Event Bus and Direct Messages)

Vivified provides two paths for plugin-to-plugin communication:

- Canonical events: fan-out via the Event Bus with policy and audit.
- Direct messages: point-to-point delivery via the Core gateway to a plugin inbox endpoint.

The Event Bus supports pluggable backends selected by `EVENT_BUS_BACKEND` (memory, nats, redis). Direct message delivery is handled by Core and dispatched to plugins over HTTP with retry/backoff and best‑effort persistence.

## What You Need To Do

- Ensure plugins expose an inbox endpoint:
  - Recommended to add endpoint key `message.receive` (or `messages.receive`, `inbox`, or `message`) in the plugin manifest to point to the handler path (e.g., `/inbox`).
- Configure operator allowlists:
  - Use `POST /admin/operator/allowlist/auto-generate` to seed from the target manifest, then refine if needed.
  - Optional dev-mode: set `DEV_MODE=true` or `operator.allow.dev_all=true` in ConfigService to allow manifest-declared operations without explicit allowlist during development.
- Optional tuning via env:
  - `MESSAGE_MAX_ATTEMPTS`, `MESSAGE_RETRY_BASE_SECONDS`, `MESSAGE_DELIVERY_TIMEOUT`.

## Admin Console First

- Use Admin Console → Operator Policy to:
  - Auto‑generate operator rules from a target plugin manifest (button: “Auto‑generate”).
  - Toggle development mode to allow manifest‑declared operations without explicit allowlist.
  - View and edit allowed operations per caller→target.

## Delivery Semantics

- Direct messages are delivered with exponential backoff and audit logging.
- Pending messages are stored in ConfigService under `messaging.pending.<message_id>` and cleared on successful delivery (best‑effort at‑least‑once).
- For durable streams (high volume), configure an external broker (NATS/Redis) and consider enabling stream semantics in the next iteration.

