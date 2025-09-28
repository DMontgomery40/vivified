#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-vivified.dev}"
HOSTNAME="${2:-docs}"
TARGET="${3:-dmontgomery40.github.io}"

if [[ -z "${NETLIFY_AUTH_TOKEN:-}" ]]; then
  echo "NETLIFY_AUTH_TOKEN is not set" >&2
  exit 1
fi

echo "Looking up Netlify DNS zone for ${DOMAIN}..."
ZONE_JSON=$(curl -s -H "Authorization: Bearer $NETLIFY_AUTH_TOKEN" https://api.netlify.com/api/v1/dns_zones)
ZONE_ID=$(python3 - "$DOMAIN" << 'PY'
import json, os, sys
zones=json.loads(os.environ.get('ZONE_JSON','[]'))
domain=sys.argv[1]
for z in zones:
    if z.get('name')==domain:
        print(z.get('id'))
        break
PY
)

if [[ -z "${ZONE_ID}" ]]; then
  echo "Could not find Netlify DNS zone for ${DOMAIN}" >&2
  exit 2
fi

echo "Zone ID: ${ZONE_ID}"

echo "Checking existing DNS records for ${HOSTNAME}.${DOMAIN}..."
RECS=$(curl -s -H "Authorization: Bearer $NETLIFY_AUTH_TOKEN" "https://api.netlify.com/api/v1/dns_zones/${ZONE_ID}/dns_records")
EXISTS=$(python3 - "$HOSTNAME" "$TARGET" << 'PY'
import json, os, sys
recs=json.loads(os.environ.get('RECS','[]'))
host=sys.argv[1]
target=sys.argv[2]
for r in recs:
    if r.get('type')=='CNAME' and r.get('hostname')==host:
        # If already points to desired target, exit 0
        if r.get('value')==target:
            print('present')
            break
        else:
            print('conflict')
            break
PY
)

if [[ "${EXISTS}" == "present" ]]; then
  echo "CNAME ${HOSTNAME}.${DOMAIN} -> ${TARGET} already present. Nothing to do."
  exit 0
fi

if [[ "${EXISTS}" == "conflict" ]]; then
  echo "A CNAME for ${HOSTNAME}.${DOMAIN} exists with a different target. Please adjust manually." >&2
  exit 3
fi

echo "Creating CNAME ${HOSTNAME}.${DOMAIN} -> ${TARGET}..."
curl -s -X POST \
  -H "Authorization: Bearer $NETLIFY_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  "https://api.netlify.com/api/v1/dns_zones/${ZONE_ID}/dns_records" \
  -d "{\"type\":\"CNAME\",\"hostname\":\"${HOSTNAME}\",\"value\":\"${TARGET}\",\"ttl\":3600}"

echo
echo "Created. DNS propagation may take a few minutes."

