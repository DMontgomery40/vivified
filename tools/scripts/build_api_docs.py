#!/usr/bin/env python3
"""
Build static API docs (Swagger UI + Redoc) for deployment to Netlify.

Outputs to site/api/:
  - openapi.json
  - index.html (links to Swagger and Redoc)
  - docs/index.html (Swagger UI)
  - redoc/index.html (Redoc)

Notes:
  - Uses CDN for swagger-ui and redoc scripts so no bundling is needed.
  - Relies on importing core.main:app and calling app.openapi().
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys


def generate_openapi() -> dict:
    # Import here to avoid side effects during module import
    from core.main import app  # type: ignore

    schema = app.openapi()
    # Minimal metadata defaults
    schema.setdefault("info", {}).setdefault("title", "Vivified API")
    schema["info"].setdefault("version", "1.0.0")
    return schema


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    root = Path(os.getcwd())
    # Ensure repo root is on sys.path so `import core.*` works
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    # Versioned API docs under /api/v1
    api_root = root / "site" / "api"
    out_dir = api_root / "v1"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) openapi.json
    openapi = generate_openapi()
    write_file(out_dir / "openapi.json", json.dumps(openapi, indent=2))

    # /api/v1/index.html (links)
    write_file(
        out_dir / "index.html",
        """<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Vivified API</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:2rem;line-height:1.5} a{color:#0366d6;text-decoration:none} a:hover{text-decoration:underline}</style>
  </head>
  <body>
    <h1>Vivified API</h1>
    <p>Static API docs generated from the live OpenAPI schema.</p>
    <ul>
      <li><a href="docs/">Swagger UI</a></li>
      <li><a href="redoc/">Redoc</a></li>
      <li><a href="openapi.json">openapi.json</a></li>
    </ul>
  </body>
</html>
""",
    )

    # 3) Swagger UI
    write_file(
        out_dir / "docs" / "index.html",
        """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Vivified API • Swagger UI</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>body{margin:0}</style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: '../openapi.json',
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis],
          layout: 'BaseLayout',
        });
      };
    </script>
  </body>
</html>
""",
    )

    # 4) Redoc
    write_file(
        out_dir / "redoc" / "index.html",
        """<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Vivified API • Redoc</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>body{margin:0}</style>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </head>
  <body>
    <redoc spec-url="../openapi.json"></redoc>
  </body>
</html>
""",
    )

    # /api/index.html redirect to /api/v1/
    write_file(
        api_root / "index.html",
        """<!doctype html><meta http-equiv="refresh" content="0; url=/api/v1/">
<link rel="canonical" href="/api/v1/" />
""",
    )

    print(f"[api-docs] Wrote static docs to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
