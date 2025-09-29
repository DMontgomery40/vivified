# Environment Variables

Messaging and delivery

- `EVENT_BUS_BACKEND` — Select event bus backend: `memory` (default), `nats`, `redis`
  - Related (when applicable): `NATS_SERVERS`, `REDIS_URL`
- `MESSAGE_MAX_ATTEMPTS` — Direct message delivery retry attempts (default: 3)
- `MESSAGE_RETRY_BASE_SECONDS` — Base backoff seconds (default: 2.0)
- `MESSAGE_DELIVERY_TIMEOUT` — HTTP delivery timeout seconds (default: 30)
- `MESSAGE_DELIVERY_BACKEND` — Durable delivery: `redis_streams` to enable Redis Streams consumer‑group acks (default: memory)
  - `MESSAGE_REDIS_URL`, `MESSAGE_STREAM_KEY` (default `msg:direct`), `MESSAGE_GROUP` (default `core`), `MESSAGE_CONSUMER_ID` (default `core-1`)

Development & toggles

- `DEV_MODE` — When `true`, enables development shortcuts. With `operator.allow.dev_all` (Config), Core permits manifest‑declared operations without explicit allowlist.

AI/RAG (for reference)

- `REDIS_URL` — Default RAG store backend `redis://localhost:6379/0` unless configured via Admin Console.

