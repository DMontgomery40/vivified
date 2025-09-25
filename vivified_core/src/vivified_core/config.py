from __future__ import annotations
import os, json
from typing import Any, Optional, Protocol, Mapping

class ConfigProvider(Protocol):
    def get(self, key: str, default: Any = None, *, context: Optional[Mapping[str, Any]] = None) -> Any: ...
    def get_bool(self, key: str, default: bool = False, *, context: Optional[Mapping[str, Any]] = None) -> bool: ...
    def get_int(self, key: str, default: int = 0, *, context: Optional[Mapping[str, Any]] = None) -> int: ...

class EnvConfigProvider:
    def get(self, key: str, default: Any = None, *, context: Optional[Mapping[str, Any]] = None) -> Any:
        v = os.getenv(key)
        if v is None: return default
        lv = v.lower()
        if lv in ("true","false"): return lv == "true"
        try:
            return int(v)
        except Exception:
            try:
                return float(v)
            except Exception:
                try:
                    return json.loads(v)
                except Exception:
                    return v

    def get_bool(self, key: str, default: bool = False, *, context=None) -> bool:
        v = os.getenv(key)
        return default if v is None else v.strip().lower() in ("1","true","yes","on")

    def get_int(self, key: str, default: int = 0, *, context=None) -> int:
        try:
            return int(os.getenv(key, ""))
        except Exception:
            return default

class InMemoryConfigProvider:
    def __init__(self, data: Optional[dict[str, Any]] = None) -> None:
        self.data = data or {}
    def get(self, key: str, default: Any = None, *, context=None) -> Any:
        return self.data.get(key, default)
    def get_bool(self, key: str, default: bool = False, *, context=None) -> bool:
        v = self.data.get(key, None)
        return default if v is None else bool(v)
    def get_int(self, key: str, default: int = 0, *, context=None) -> int:
        v = self.data.get(key, None)
        try:
            return int(v)
        except Exception:
            return default

class HybridConfigProvider:
    """Primary->fallback chain. Later, swap primary for DB-backed provider."""
    def __init__(self, primary: Optional[ConfigProvider] = None, fallback: Optional[ConfigProvider] = None) -> None:
        self.primary = primary or InMemoryConfigProvider()
        self.fallback = fallback or EnvConfigProvider()
    def get(self, key: str, default: Any = None, *, context=None) -> Any:
        sentinel = object()
        v = self.primary.get(key, sentinel, context=context)  # type: ignore
        if v is sentinel:
            v = self.fallback.get(key, default, context=context)  # type: ignore
        return v
    def get_bool(self, key: str, default: bool = False, *, context=None) -> bool:
        pv = self.primary.get(key, None, context=context)  # type: ignore
        return self.fallback.get_bool(key, default, context=context) if pv is None else bool(pv)  # type: ignore
    def get_int(self, key: str, default: int = 0, *, context=None) -> int:
        pv = self.primary.get(key, None, context=context)  # type: ignore
        try:
            return int(pv) if pv is not None else self.fallback.get_int(key, default, context=context)  # type: ignore
        except Exception:
            return default
