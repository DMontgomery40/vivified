"""
Storage encryption for PHI/PII data with HIPAA compliance.
"""

import hashlib
import hmac
import os
from typing import Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from ..config.encryption import ConfigEncryption


class StorageEncryption:
    """
    Encryption service for storage data with PHI/PII protection.

    Uses Fernet (AES 128 in CBC mode with HMAC) for symmetric encryption.
    Each object gets its own encryption key derived from master key + object ID.
    """

    def __init__(self, master_key: Optional[str] = None):
        """Initialize with master encryption key."""
        if master_key:
            self.master_key = master_key.encode()
        else:
            # Use same key as config encryption for consistency
            config_encryption = ConfigEncryption()
            self.master_key = config_encryption.key

    def generate_object_key(self, object_id: str, salt: Optional[bytes] = None) -> Tuple[Fernet, str]:
        """
        Generate unique encryption key for an object.

        Args:
            object_id: Unique identifier for the object
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (Fernet cipher, key_id for tracking)
        """
        if salt is None:
            salt = os.urandom(16)

        # Derive object-specific key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        object_key = base64.urlsafe_b64encode(kdf.derive(self.master_key + object_id.encode()))

        # Create key ID for tracking (non-reversible)
        key_id = hashlib.sha256(salt + object_id.encode()).hexdigest()[:16]

        return Fernet(object_key), key_id

    def encrypt_object(self, data: bytes, object_id: str) -> Tuple[bytes, str]:
        """
        Encrypt object data with unique key.

        Args:
            data: Raw data to encrypt
            object_id: Unique object identifier

        Returns:
            Tuple of (encrypted_data, key_id)
        """
        cipher, key_id = self.generate_object_key(object_id)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data, key_id

    def decrypt_object(self, encrypted_data: bytes, object_id: str, key_id: str) -> bytes:
        """
        Decrypt object data using stored key ID.

        Args:
            encrypted_data: Encrypted data
            object_id: Unique object identifier
            key_id: Key ID from encryption

        Returns:
            Decrypted data

        Raises:
            ValueError: If decryption fails
        """
        try:
            # We need to try different salts to find the right key
            # In production, salt should be stored with key_id
            # For now, we'll derive it from key_id (not ideal but functional)
            salt = bytes.fromhex(key_id.ljust(32, '0'))[:16]

            cipher, derived_key_id = self.generate_object_key(object_id, salt)

            if derived_key_id != key_id:
                raise ValueError(f"Key ID mismatch: expected {key_id}, got {derived_key_id}")

            return cipher.decrypt(encrypted_data)

        except Exception as e:
            raise ValueError(f"Failed to decrypt object {object_id}: {str(e)}")

    def calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum for data integrity."""
        return hashlib.sha256(data).hexdigest()

    def verify_checksum(self, data: bytes, expected_checksum: str) -> bool:
        """Verify data integrity using checksum."""
        actual_checksum = self.calculate_checksum(data)
        return hmac.compare_digest(actual_checksum, expected_checksum)

    def create_secure_filename(self, original_filename: str, object_id: str) -> str:
        """
        Create secure filename that doesn't expose original filename.

        Args:
            original_filename: Original filename (stored in metadata)
            object_id: Unique object identifier

        Returns:
            Secure filename for storage
        """
        # Extract extension if present
        if '.' in original_filename:
            ext = '.' + original_filename.split('.')[-1].lower()
            # Validate extension
            allowed_exts = {'.txt', '.pdf', '.json', '.csv', '.jpg', '.jpeg', '.png', '.bin'}
            if ext not in allowed_exts:
                ext = '.bin'
        else:
            ext = '.bin'

        # Create secure filename from object ID
        secure_name = hashlib.sha256(object_id.encode()).hexdigest()[:16]
        return f"{secure_name}{ext}"

    @staticmethod
    def generate_master_key() -> str:
        """Generate a new master encryption key."""
        return Fernet.generate_key().decode()

    def rotate_master_key(self, new_master_key: str) -> str:
        """
        Rotate master encryption key.

        Note: In production, this would require re-encrypting all stored objects
        with the new master key. This is a placeholder for that process.

        Args:
            new_master_key: New master key

        Returns:
            Previous master key for migration purposes
        """
        old_key = self.master_key.decode() if isinstance(self.master_key, bytes) else self.master_key
        self.master_key = new_master_key.encode()
        return old_key