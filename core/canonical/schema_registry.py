"""
In-memory Canonical Schema Registry.

Manages versioned canonical schemas and active pointers per major version.
This is a lightweight implementation to satisfy the core UI and API; it can be
replaced with a persistent backend later (DB or config service integration).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Any, List

try:
    from ..config.service import get_config_service  # type: ignore
except Exception:  # pragma: no cover
    get_config_service = None  # type: ignore


Version = Tuple[int, int, int]


@dataclass
class CanonicalSchema:
    name: str
    version: Version
    schema_data: Dict[str, Any]


@dataclass
class SchemaRegistry:
    _schemas: Dict[str, Dict[Version, CanonicalSchema]] = field(default_factory=dict)
    _active: Dict[str, Dict[int, Version]] = field(
        default_factory=dict
    )  # name -> major -> version

    def upsert(
        self, name: str, version: Version, schema_data: Dict[str, Any]
    ) -> CanonicalSchema:
        # Persist to ConfigService if available
        if get_config_service is not None:
            svc = get_config_service()
            key_versions = f"canonical.schemas.{name}.versions"
            import asyncio

            async def _write():
                existing = await svc.get(key_versions) or {}
                if not isinstance(existing, dict):
                    existing = {}
                ver_str = f"{version[0]}.{version[1]}.{version[2]}"
                existing[ver_str] = schema_data or {}
                await svc.set(
                    key_versions,
                    existing,
                    is_sensitive=False,
                    updated_by="schema_registry",
                    reason="schema_upsert",
                )

            asyncio.get_event_loop().run_until_complete(_write())

        versions = self._schemas.setdefault(name, {})
        sch = CanonicalSchema(name=name, version=version, schema_data=schema_data or {})
        versions[version] = sch
        return sch

    def activate(self, name: str, version: Version) -> bool:
        if name not in self._schemas or version not in self._schemas[name]:
            return False
        major = version[0]
        majors = self._active.setdefault(name, {})
        majors[major] = version
        # Persist active pointer
        if get_config_service is not None:
            svc = get_config_service()
            key_active = f"canonical.schemas.{name}.active.{major}"
            import asyncio

            async def _write():
                ver_str = f"{version[0]}.{version[1]}.{version[2]}"
                await svc.set(
                    key_active,
                    ver_str,
                    is_sensitive=False,
                    updated_by="schema_registry",
                    reason="schema_activate",
                )

            asyncio.get_event_loop().run_until_complete(_write())
        return True

    def get_active(self, name: str, major: int) -> Optional[CanonicalSchema]:
        vmap = self._active.get(name, {})
        ver = vmap.get(major)
        if not ver:
            return None
        return self._schemas.get(name, {}).get(ver)

    def list_versions(self, name: str) -> List[Version]:
        return sorted(list(self._schemas.get(name, {}).keys()))
