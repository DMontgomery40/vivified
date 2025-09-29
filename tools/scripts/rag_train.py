#!/usr/bin/env python3
"""
Train the internal RAG index by calling the local API.

Usage:
  AI_API_URL=http://localhost:8000 API_KEY=bootstrap_admin_only \
    python tools/scripts/rag_train.py --sources docs internal-plans

If environment variables are not set, defaults to http://localhost:8000 and bootstrap dev key.
"""
import os
import sys
import json
import urllib.request


def main():
    api = os.getenv("AI_API_URL", "http://localhost:8000").rstrip("/")
    key = os.getenv("API_KEY", "bootstrap_admin_only")
    sources = sys.argv[1:] or ["docs", "internal-plans"]

    req = urllib.request.Request(
        f"{api}/admin/ai/train",
        data=json.dumps({"sources": sources}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "X-API-Key": key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()

