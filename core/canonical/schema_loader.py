from __future__ import annotations

import json
import os

from .schema_registry import SchemaRegistry, Version


def _parse_version(name: str) -> Version:
    parts = name.split(".")
    if len(parts) != 3:
        return (1, 0, 0)
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return (1, 0, 0)


def load_builtin_schemas(registry: SchemaRegistry) -> int:
    """Load JSON Schemas shipped in core/canonical/schemas/* into the registry.

    Returns the number of schemas loaded. If a schema version already exists in the
    in-memory registry, it is left as-is (idempotent).
    """
    here = os.path.dirname(__file__)
    base = os.path.join(here, "schemas")
    if not os.path.isdir(base):
        return 0

    loaded = 0
    for root, _dirs, files in os.walk(base):
        # Expect structure: base/<namespace>/<entity>/<version>.json
        for fn in files:
            if not fn.endswith(".json"):
                continue
            version = _parse_version(fn[:-5])
            rel_dir = os.path.relpath(root, base)
            parts = rel_dir.split(os.sep)
            if len(parts) != 2:
                # Skip unexpected nesting
                continue
            namespace, entity = parts
            name = f"{namespace}.{entity}"

            # Skip if version already present
            if version in registry._schemas.get(name, {}):  # type: ignore[attr-defined]
                continue

            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                registry.upsert(name, version, data)
                # Auto-activate the first seen major if not set
                major = version[0]
                if registry.get_active(name, major) is None:
                    registry.activate(name, version)
                loaded += 1
            except Exception:
                # Best-effort loader; ignore malformed files
                continue

    return loaded
