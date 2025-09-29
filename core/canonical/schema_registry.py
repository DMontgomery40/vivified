"""
In-memory Canonical Schema Registry.

Manages versioned canonical schemas and active pointers per major version.
This is a lightweight implementation to satisfy the core UI and API; it can be
replaced with a persistent backend later (DB or config service integration).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Any, List


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
        return True

    def get_active(self, name: str, major: int) -> Optional[CanonicalSchema]:
        vmap = self._active.get(name, {})
        ver = vmap.get(major)
        if not ver:
            return None
        return self._schemas.get(name, {}).get(ver)

    def list_versions(self, name: str) -> List[Version]:
        return sorted(list(self._schemas.get(name, {}).keys()))
