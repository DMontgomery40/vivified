!!! danger "HIPAA Reminder"
    Storage operations often contain PHI/PII. Ensure you have the right access and audit approvals before performing any queries or exports.

# Storage Service :file_cabinet: 

The Storage Service is an encrypted storage abstraction with PHI-aware classification, tagging, retention policies, and audit integration.

## Features (user-facing)

- Encrypted object storage for PHI/PII
- Automatic classification and tagging when objects are stored
- Retention and deletion policies manageable from the Admin Console
- Searchable storage browser with role-based filters

## Common tasks

- Store an object (API)
- List objects with filters
- Inspect an object’s metadata and classification
- Configure retention and deletion rules via Admin Console

=== "Store object (curl)"

```bash
curl -X POST "https://api.example.com/storage/objects" \
  -H "Authorization: Bearer <KEY>" \
  -F "file=@record.pdf" \
  -F "metadata={\"patient_id\":\"p-123\"};type=application/json"
```

=== "Python upload"

```python
# (1) Upload a file with metadata
files = {'file': open('record.pdf', 'rb')}
metadata = {'patient_id': 'p-123'}
resp = requests.post(f"{BASE}/storage/objects", headers={'Authorization': f'Bearer {TOKEN}'}, files=files, data={'metadata': json.dumps(metadata)})
# (1) Make sure to stream large files in production
```

## Automatic Classification

The Storage Service applies classification rules when objects are stored. Classification influences searchability, retention, and redaction options.

!!! note "Non-destructive tagging"
    Tags and classification are stored as metadata and do not modify the original object content.

## Retention Policies

- Configure retention rules from the Admin Console under Policies → Retention.
- Policies can be time-based, event-based, or tag-based.

??? details "Retention example"
    A rule might keep event-related objects for 7 years and mark them for review before deletion.

## Audit Integration

- Every store/read/delete operation writes an audit event with the actor, action, and reason.
- Audit events are visible in the Admin Console and queryable via the Admin API.

## Troubleshooting

- Missing object: verify object ID, check retention rules (they may hide expired items), and check your role.
- Classification seems wrong: review the classification rules in the Admin Console and submit a support request with the object ID.
