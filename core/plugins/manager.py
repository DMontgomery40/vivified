from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.plugins.contracts.integration import (
    IntegrationManifest,
    IntegrationPluginBase,
)


@dataclass
class IntegrationEntry:
    key: str
    manifest: IntegrationManifest
    impl: IntegrationPluginBase


class IntegrationPluginRegistry:
    """Discover and expose integration plugins packaged with core.

    Scans plugins/integration-*/manifest.json and loads impl.py::Plugin.
    """

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = Path(repo_root or os.getcwd())
        self._entries: Dict[str, IntegrationEntry] = {}

    def discover(self) -> None:
        base = self.repo_root / "plugins"
        if not base.exists():
            return
        for d in base.iterdir():
            if not d.is_dir():
                continue
            if not d.name.startswith("integration-"):
                continue
            key = d.name.split("integration-")[-1]
            manifest_path = d / "manifest.json"
            impl_path = d / "impl.py"
            if not manifest_path.exists() or not impl_path.exists():
                continue
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest = IntegrationManifest(
                    key=str(raw.get("key") or key),
                    name=str(raw.get("name") or key.title()),
                    category=str(raw.get("category") or "other"),
                    hipaa_eligible=bool(raw.get("hipaaEligible", False)),
                    allowed_hosts=list(raw.get("allowedHosts") or []),
                    scopes=list(raw.get("scopes") or []),
                    icon=str(raw.get("icon") or "hub"),
                )
                impl = self._load_impl(impl_path)
                self._entries[manifest.key] = IntegrationEntry(
                    key=manifest.key, manifest=manifest, impl=impl
                )
            except Exception:
                # Skip invalid entries quietly to avoid breaking core
                continue

    def _load_impl(self, impl_path: Path) -> IntegrationPluginBase:
        spec = importlib.util.spec_from_file_location(
            f"vivified.plugins.{impl_path.parent.name}", str(impl_path)
        )
        if not spec or not spec.loader:
            raise RuntimeError("Cannot load plugin impl")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[assignment]
        plugin_cls = getattr(module, "Plugin")
        impl: IntegrationPluginBase = plugin_cls()  # type: ignore[call-arg]
        return impl

    def list(self) -> List[IntegrationEntry]:
        if not self._entries:
            self.discover()
        return list(self._entries.values())

    def get(self, key: str) -> Optional[IntegrationEntry]:
        if not self._entries:
            self.discover()
        return self._entries.get(key)
