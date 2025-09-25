from __future__ import annotations
import json, os, shutil, subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional
from .types import ViviContext, ViviPlugin, PluginInfo
from .config import HybridConfigProvider, EnvConfigProvider, ConfigProvider

@dataclass
class _ExternalPlugin:
    name: str
    version: str
    path: str
    capabilities: list[str]
    requires_traits: set[str]

class Kernel:
    def __init__(self, ctx: ViviContext, config: Optional[ConfigProvider] = None):
        self.ctx = ctx
        self.config = config or HybridConfigProvider(fallback=EnvConfigProvider())
        self._py_plugins: Dict[str, ViviPlugin] = {}
        self._ext_plugins: Dict[str, _ExternalPlugin] = {}

    def register(self, plugin: ViviPlugin) -> None:
        info = plugin.info
        if info.name in self._py_plugins or info.name in self._ext_plugins:
            raise ValueError(f"Plugin already registered: {info.name}")
        self._py_plugins[info.name] = plugin
        plugin.init(self.ctx)

    def register_external(self, path: str) -> None:
        exe = shutil.which(path) or path
        if not os.path.exists(exe):
            raise FileNotFoundError(f"External plugin not found: {path}")
        meta = self._rpc(exe, {"method": "capabilities"}) or {}
        name = meta.get("name", os.path.basename(path))
        if name in self._py_plugins or name in self._ext_plugins:
            raise ValueError(f"Plugin already registered: {name}")
        version = meta.get("version", "0.0.0")
        caps = list(meta.get("capabilities", []))
        req = set(meta.get("requires_traits", []))
        self._ext_plugins[name] = _ExternalPlugin(name, version, exe, caps, req)
        self._rpc(exe, {"method": "init", "params": {"env": dict(self.ctx.env), "traits": list(self.ctx.traits)}})

    def list(self) -> list[str]:
        return sorted(list(self._py_plugins.keys()) + list(self._ext_plugins.keys()))

    def run(self, name: str, args: list[str]) -> int:
        if name in self._py_plugins:
            req = set(self._py_plugins[name].info.requires_traits or [])
            if not req.issubset(self.ctx.traits):
                missing = ", ".join(sorted(req - self.ctx.traits))
                raise PermissionError(f"missing traits: {missing}")
            code = self._py_plugins[name].run(args, self.ctx)
            return int(code or 0)
        if name in self._ext_plugins:
            ext = self._ext_plugins[name]
            if not ext.requires_traits.issubset(self.ctx.traits):
                missing = ", ".join(sorted(ext.requires_traits - self.ctx.traits))
                raise PermissionError(f"missing traits: {missing}")
            out = self._rpc(ext.path, {"method": "run", "params": {"args": args}})
            return int(out or 0)
        raise KeyError(f"Plugin not found: {name}")

    def _rpc(self, exe: str, payload: dict) -> Any:
        p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert p.stdin and p.stdout
            p.stdin.write(json.dumps(payload) + "\n")
            p.stdin.flush()
            line = p.stdout.readline().strip()
            if not line:
                err = p.stderr.read()
                raise RuntimeError(f"Empty response from {exe}. stderr={err}")
            resp = json.loads(line)
            if "error" in resp and resp["error"]:
                raise RuntimeError(f"Plugin error: {resp['error']}")
            return resp.get("result")
        finally:
            try: p.stdin.close()
            except Exception: pass
            try: p.stdout.close()
            except Exception: pass
            try: p.stderr.close()
            except Exception: pass
            try: p.wait(timeout=5)
            except Exception: pass

def create_default_context() -> ViviContext:
    traits = set(filter(None, (os.getenv("VIVI_TRAITS","" ).split(","))))
    return ViviContext(env=os.environ, traits=traits)
