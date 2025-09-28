"""
Configuration service with database persistence and encryption support.

This implementation provides hierarchical configuration with encryption
for sensitive values and comprehensive audit logging.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, List
from dataclasses import dataclass
import os
import json
import logging
from datetime import datetime

from cryptography.fernet import Fernet
from sqlalchemy import select, update, insert
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Configuration, ConfigHistory

logger = logging.getLogger(__name__)


@dataclass
class ConfigItem:
    key: str
    value: Any
    is_sensitive: bool = False
    updated_by: Optional[str] = None
    reason: Optional[str] = None


class ConfigService:
    def __init__(self, db_session: Optional[AsyncSession] = None, encryption_key: Optional[str] = None):
        self.db = db_session
        self._store: Dict[str, ConfigItem] = {}  # Fallback in-memory store
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

    async def set(
        self, 
        key: str, 
        value: Any, 
        *, 
        is_sensitive: bool, 
        updated_by: Optional[str], 
        reason: Optional[str],
        plugin_id: Optional[str] = None,
        environment: str = "default"
    ) -> None:
        """Set configuration value with database persistence and audit trail."""
        if self.db:
            await self._set_db(key, value, is_sensitive, updated_by, reason, plugin_id, environment)
        else:
            # Fallback to in-memory storage
            protected = self._protect(value, is_sensitive)
            self._store[key] = ConfigItem(
                key=key, value=protected, is_sensitive=is_sensitive, updated_by=updated_by, reason=reason
            )

    async def get(
        self, 
        key: str, 
        reveal: bool = True,
        plugin_id: Optional[str] = None,
        environment: str = "default"
    ) -> Optional[Any]:
        """Get configuration value with hierarchical override."""
        if self.db:
            return await self._get_db(key, reveal, plugin_id, environment)
        else:
            # Fallback to in-memory storage
            item = self._store.get(key)
            if not item:
                return None
            return self._unprotect(item.value, item.is_sensitive) if reveal else item.value

    async def get_all(self, reveal: bool = True, plugin_id: Optional[str] = None) -> Dict[str, Any]:
        """Get all configuration values."""
        if self.db:
            return await self._get_all_db(reveal, plugin_id)
        else:
            # Fallback to in-memory storage
            result: Dict[str, Any] = {}
            for k, item in self._store.items():
                result[k] = self._unprotect(item.value, item.is_sensitive) if reveal else item.value
            return result

    async def _set_db(
        self,
        key: str,
        value: Any,
        is_sensitive: bool,
        updated_by: Optional[str],
        reason: Optional[str],
        plugin_id: Optional[str],
        environment: str
    ) -> None:
        """Set configuration value in database with audit trail."""
        # Get current value for history
        current = await self.db.scalar(
            select(Configuration).where(
                Configuration.key == key,
                Configuration.plugin_id == plugin_id,
                Configuration.environment == environment
            )
        )
        
        # Encrypt sensitive values
        encrypted = False
        if is_sensitive and self._cipher:
            value = self._encrypt_value(value)
            encrypted = True
        
        if current:
            # Update existing
            await self.db.execute(
                update(Configuration)
                .where(Configuration.id == current.id)
                .values(
                    value=value,
                    is_encrypted=encrypted,
                    is_sensitive=is_sensitive,
                    updated_at=datetime.utcnow(),
                    updated_by=updated_by,
                    version=Configuration.version + 1
                )
            )
            
            # Add to history
            history_entry = ConfigHistory(
                config_id=current.id,
                old_value=current.value,
                new_value=value,
                changed_by=updated_by,
                change_reason=reason
            )
            self.db.add(history_entry)
        else:
            # Insert new
            config_entry = Configuration(
                key=key,
                value=value,
                plugin_id=plugin_id,
                environment=environment,
                is_encrypted=encrypted,
                is_sensitive=is_sensitive,
                updated_by=updated_by
            )
            self.db.add(config_entry)
            await self.db.flush()
            
            # Add to history
            history_entry = ConfigHistory(
                config_id=config_entry.id,
                old_value=None,
                new_value=value,
                changed_by=updated_by,
                change_reason=reason or "initial_configuration"
            )
            self.db.add(history_entry)
        
        await self.db.commit()
        
        logger.info(f"Configuration updated: {key}", extra={
            "trace_id": updated_by,
            "plugin_id": plugin_id,
            "key": key,
            "sensitive": is_sensitive
        })

    async def _get_db(
        self,
        key: str,
        reveal: bool,
        plugin_id: Optional[str],
        environment: str
    ) -> Optional[Any]:
        """Get configuration value from database with hierarchical override."""
        # Check database
        result = await self.db.scalar(
            select(Configuration).where(
                Configuration.key == key,
                Configuration.plugin_id == plugin_id,
                Configuration.environment == environment
            )
        )
        
        if result:
            value = result.value
            if result.is_encrypted and reveal and self._cipher:
                value = self._decrypt_value(value)
            return value
        
        # Check environment variable override
        env_key = f"{plugin_id or 'CORE'}_{key}".upper().replace(".", "_")
        if env_value := os.getenv(env_key):
            return env_value
        
        # Fall back to defaults
        if plugin_id:
            return self.defaults.get("plugins", {}).get(plugin_id, {}).get(key)
        return self._get_nested_default(key)

    async def _get_all_db(self, reveal: bool, plugin_id: Optional[str]) -> Dict[str, Any]:
        """Get all configuration values from database."""
        query = select(Configuration)
        if plugin_id:
            query = query.where(Configuration.plugin_id == plugin_id)
        
        result = await self.db.execute(query)
        configs = result.scalars().all()
        
        items = {}
        for config in configs:
            value = config.value
            if config.is_encrypted and reveal and self._cipher:
                value = self._decrypt_value(value)
            items[config.key] = value
        
        return items

    def _get_nested_default(self, key: str) -> Any:
        """Get nested default value using dot notation."""
        keys = key.split(".")
        value = self.defaults
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return None
        return value


_CONFIG_SERVICE: Optional[ConfigService] = None


def get_config_service() -> ConfigService:
    global _CONFIG_SERVICE
    if _CONFIG_SERVICE is None:
        enc = os.getenv("CONFIG_ENC_KEY")
        _CONFIG_SERVICE = ConfigService(encryption_key=enc)
    return _CONFIG_SERVICE

