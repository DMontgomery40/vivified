"""
Configuration encryption utilities.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class ConfigEncryption:
    """Encryption utilities for configuration values."""
    
    def __init__(self, key: str = None):
        """Initialize with encryption key."""
        if key:
            self.key = key.encode()
        else:
            # Generate or load key from environment
            key = os.getenv("CONFIG_ENC_KEY")
            if key:
                self.key = key.encode()
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
    
    def encrypt_dict(self, data: dict) -> dict:
        """Encrypt all string values in a dictionary."""
        encrypted = {}
        for key, value in data.items():
            if isinstance(value, str):
                encrypted[key] = self.encrypt(value)
            elif isinstance(value, dict):
                encrypted[key] = self.encrypt_dict(value)
            else:
                encrypted[key] = value
        return encrypted
    
    def decrypt_dict(self, data: dict) -> dict:
        """Decrypt all string values in a dictionary."""
        decrypted = {}
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
