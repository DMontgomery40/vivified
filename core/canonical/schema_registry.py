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

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_write())
            except RuntimeError:
                # No running loop; safe to run synchronously
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

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_write())
            except RuntimeError:
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

    async def hydrate_from_config(self) -> int:
        """Load schemas and active pointers from ConfigService if available.

        Returns number of schema versions loaded. Safe to call multiple times.
        """
        if get_config_service is None:
            return 0
        try:
            svc = get_config_service()
            all_items = await svc.get_all(reveal=True)
        except Exception:  # pragma: no cover - config not available
            return 0

        loaded = 0
        # Load versions
        for key, value in all_items.items():
            # canonical.schemas.<name>.versions
            if not key.startswith("canonical.schemas."):
                continue
            parts = key.split(".")
            if len(parts) == 4 and parts[-1] == "versions":
                name = parts[2]
                try:
                    if isinstance(value, dict):
                        for ver_str, sch in value.items():
                            try:
                                vx = tuple(int(p) for p in str(ver_str).split("."))
                                if len(vx) != 3:
                                    continue
                                self.upsert(name, (vx[0], vx[1], vx[2]), sch or {})
                                loaded += 1
                            except Exception:
                                continue
                except Exception:
                    continue

        # Load active pointers
        for key, value in all_items.items():
            # canonical.schemas.<name>.active.<major>
            if not key.startswith("canonical.schemas."):
                continue
            parts = key.split(".")
            if len(parts) == 5 and parts[3] == "active":
                name = parts[2]
                try:
                    ver_str = str(value or "")
                    vx = tuple(int(p) for p in ver_str.split("."))
                    if len(vx) == 3 and self._schemas.get(name, {}).get(vx):
                        self.activate(name, (vx[0], vx[1], vx[2]))
                except Exception:
                    continue

        return loaded
