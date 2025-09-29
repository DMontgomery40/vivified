# Environment Variables

Key runtime environment variables used by Core messaging and delivery:

- `EVENT_BUS_BACKEND`: Select the Event Bus backend.
  - Values: `memory` (default), `nats`, `redis`
  - Related (when applicable): `NATS_SERVERS`, `REDIS_URL`
- `MESSAGE_MAX_ATTEMPTS`: Direct message delivery retry attempts (default: 3)
- `MESSAGE_RETRY_BASE_SECONDS`: Base backoff seconds (default: 2.0)
- `MESSAGE_DELIVERY_TIMEOUT`: HTTP delivery timeout seconds (default: 30)
- `DEV_MODE`: When `true`, unlocks development shortcuts (e.g., Operator Lane dev allow behavior)

ConfigService toggles (set via Admin Console):

- `operator.allow.dev_all`: When true, allow any operation declared in the target’s manifest without explicit allowlist (development only).

