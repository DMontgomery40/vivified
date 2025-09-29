#!/usr/bin/env python3
"""
Simple smoke test for RAG + embeddings.

Usage:
  API_KEY=bootstrap_admin_only AI_API_URL=http://localhost:8000 \
    OPENAI_API_KEY=sk-... \
    python tools/scripts/rag_smoke.py --train --query "Vivified"
"""

import os
import sys
import json
import time
import argparse
import urllib.request


def _req(path: str, method: str = "GET", body: dict | None = None):
    base = os.getenv("AI_API_URL", "http://localhost:8000").rstrip("/")
    url = f"{base}{path}"
    data = None
    headers = {
        "Authorization": f"Bearer {os.getenv('API_KEY','bootstrap_admin_only')}",
        "X-API-Key": os.getenv("API_KEY", "bootstrap_admin_only"),
        "Content-Type": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:  # nosec - local smoke only
        return json.loads(r.read().decode() or "{}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="Trigger training from repo root (.)")
    ap.add_argument("--query", default="Vivified", help="Query string to test")
    args = ap.parse_args()

    print("[smoke] GET /admin/ai/status ...", flush=True)
    st = _req("/admin/ai/status")
    print(json.dumps(st, indent=2))

    if args.train:
        print("[smoke] POST /admin/ai/train {sources:["."]} ...", flush=True)
        tr = _req("/admin/ai/train", method="POST", body={"sources": ["."]})
        print(json.dumps(tr, indent=2))
        time.sleep(1)

    print(f"[smoke] POST /admin/ai/query {{q:{args.query!r}}} ...", flush=True)
    qr = _req("/admin/ai/query", method="POST", body={"q": args.query})
    items = (qr or {}).get("items") or []
    print(json.dumps({"count": len(items), "items": items[:5]}, indent=2))

    ok = True
    if st.get("backend") not in {"redis", "memory"}:
        print("[smoke] unexpected backend label", file=sys.stderr)
        ok = False
    if len(items) == 0:
        print("[smoke] WARNING: zero results; embeddings or indexing may be missing", file=sys.stderr)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

