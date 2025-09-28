!!! info "Admin API Reference — quick access"
    The Admin API manages users, plugins, configuration, audits, and health. Use role-based tokens or API keys to authenticate.

# API Reference :page_with_curl: 

Base URL: https://api.example.com (replace with your deployment URL)

Authentication: Bearer token in Authorization header. Admin-level tokens grant broader access.

## Common headers

- Authorization: Bearer <API_KEY>
- Content-Type: application/json

---

## GET /admin/health

Returns system health and component statuses.

Response example:

```json
{
  "status": "ok",
  "components": {
    "canonical": "ok",
    "storage": "ok",
    "messaging": "ok",
    "gateway": "ok"
  }
}
```

---

## Users

### GET /admin/users

List users (requires appropriate role).

Response:

```json
[{"id": "user-1", "username": "alice", "email": "alice@example.com", "roles": ["admin"]}]
```

### POST /admin/users

Create a user.

Request body:

```json
{
  "username": "bob",
  "email": "bob@example.com",
  "roles": ["viewer"]
}
```

Response:

```json
{
  "id": "user-2",
  "username": "bob",
  "email": "bob@example.com",
  "roles": ["viewer"],
  "created_at": "2025-02-14T12:00:00Z"
}
```

---

## Plugins

### GET /admin/plugins

List installed plugins and their statuses.

Response:

```json
[{"id": "plugin-1", "name": "Example Provider", "status": "healthy", "configured": true}]
```

### POST /admin/plugins/{plugin_id}/test

Run an outbound smoke test for the plugin. Returns a result object.

Response:

```json
{"status": "success", "details": "Outbound message accepted by provider"}
```

---

## Storage

### POST /storage/objects

Uploads an object. Use multipart/form-data for files.

Response:

```json
{"object_id": "obj-123", "classification": "sensitive", "created_at": "2025-02-14T12:00:00Z"}
```

### GET /storage/objects/{object_id}

Fetch object metadata or content depending on Accept header.

Response (metadata):

```json
{"object_id": "obj-123", "metadata": {"patient_id": "p-123"}, "classification": "sensitive"}
```

---

## Audit

### GET /admin/audit

Query audit records. Supports filters: actor, event_type, time range.

Response (paginated):

```json
{
  "items": [
    {"id": "audit-1", "actor": "user-1", "action": "store_object", "timestamp": "2025-02-14T12:01:00Z"}
  ],
  "next_cursor": null
}
```

---

## Examples (multi-language)

=== "Python"

```python
import requests
resp = requests.get('https://api.example.com/admin/users', headers={'Authorization': 'Bearer <KEY>'})
print(resp.json())
```

=== "Node.js"

```javascript
const res = await fetch('https://api.example.com/admin/users', { headers: { Authorization: `Bearer ${KEY}` } });
const users = await res.json();
console.log(users);
```

---

!!! note "Error handling"
    API responses use standard HTTP codes. 4xx indicates client errors (bad request, unauthorized). 5xx indicates server errors. Use the message field in the response for details.
