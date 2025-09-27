"""
Configuration service with simple in-memory persistence and optional encryption.

This is a Phase 2 minimal implementation designed to back the Admin UI
Brand Settings while we finalize DB-backed config in later phases.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from dataclasses import dataclass
import os
import json
import logging

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


@dataclass
class ConfigItem:
    key: str
    value: Any
    is_sensitive: bool = False
    updated_by: Optional[str] = None
    reason: Optional[str] = None


class ConfigService:
    def __init__(self, encryption_key: Optional[str] = None):
        self._store: Dict[str, ConfigItem] = {}
        self._cipher: Optional[Fernet] = (
            Fernet(encryption_key.encode()) if encryption_key else None
        )
        self._load_defaults()

    def _load_defaults(self) -> None:
        defaults_file = os.getenv("CONFIG_DEFAULTS_FILE", "config.defaults.json")
        try:
            if os.path.exists(defaults_file):
                with open(defaults_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self._store[k] = ConfigItem(key=k, value=v, is_sensitive=False)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to load defaults: %s", e)

    def _protect(self, value: Any, is_sensitive: bool) -> Any:
        if not is_sensitive or not self._cipher:
            return value
        data = json.dumps(value).encode("utf-8")
        return self._cipher.encrypt(data).decode("utf-8")

    def _unprotect(self, value: Any, is_sensitive: bool) -> Any:
        if not is_sensitive or not self._cipher:
            return value
        try:
            raw = self._cipher.decrypt(str(value).encode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            # Return marker if decryption fails
            return {"error": "decryption_failed"}

    def set(self, key: str, value: Any, *, is_sensitive: bool, updated_by: Optional[str], reason: Optional[str]) -> None:
        protected = self._protect(value, is_sensitive)
        self._store[key] = ConfigItem(
            key=key, value=protected, is_sensitive=is_sensitive, updated_by=updated_by, reason=reason
        )

    def get(self, key: str, reveal: bool = True) -> Optional[Any]:
        item = self._store.get(key)
        if not item:
            return None
        return self._unprotect(item.value, item.is_sensitive) if reveal else item.value

    def get_all(self, reveal: bool = True) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for k, item in self._store.items():
            result[k] = self._unprotect(item.value, item.is_sensitive) if reveal else item.value
        return result


_CONFIG_SERVICE: Optional[ConfigService] = None


def get_config_service() -> ConfigService:
    global _CONFIG_SERVICE
    if _CONFIG_SERVICE is None:
        enc = os.getenv("CONFIG_ENC_KEY")
        _CONFIG_SERVICE = ConfigService(enc)
    return _CONFIG_SERVICE

