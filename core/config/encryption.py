"""
Configuration encryption utilities.
"""

import os
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet


class ConfigEncryption:
    """Encryption utilities for configuration values."""

    def __init__(self, key: Optional[str] = None):
        """Initialize with encryption key."""
        self.key: bytes
        if key:
            self.key = key.encode()
        else:
            # Generate or load key from environment
            env_key = os.getenv("CONFIG_ENC_KEY")
            if env_key:
                self.key = env_key.encode()
            else:
                # Generate a new key (not recommended for production)
                self.key = Fernet.generate_key()

        # Create cipher
        self.cipher = Fernet(self.key)

    def encrypt(self, value: str) -> str:
        """Encrypt a configuration value."""
        return self.cipher.encrypt(value.encode()).decode()

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a configuration value."""
        return self.cipher.decrypt(encrypted_value.encode()).decode()

    def encrypt_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt all string values in a dictionary."""
        encrypted: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                encrypted[key] = self.encrypt(value)
            elif isinstance(value, dict):
                encrypted[key] = self.encrypt_dict(value)
            else:
                encrypted[key] = value
        return encrypted

    def decrypt_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt all string values in a dictionary."""
        decrypted: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    decrypted[key] = self.decrypt(value)
                except Exception:
                    # If decryption fails, assume it's not encrypted
                    decrypted[key] = value
            elif isinstance(value, dict):
                decrypted[key] = self.decrypt_dict(value)
            else:
                decrypted[key] = value
        return decrypted
