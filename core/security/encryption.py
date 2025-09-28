"""
HIPAA-grade encryption utilities for PHI/PII using AES-256-GCM.

Implements an authenticated encryption service that:
- Uses PBKDF2-SHA256 to derive separate encryption and HMAC keys
- Encrypts JSON-serializable PHI payloads with AES-256-GCM
- Authenticates with associated data (e.g., patient_id)
- Supports key versioning for rotation (basic in-memory policy)

Note: Long-term key storage/rotation should use a KMS/HSM. This module
provides a safe default implementation suitable for development and CI.
"""

from __future__ import annotations

from typing import Dict, Tuple, Optional, Any, List
import base64
import json
import hmac
import hashlib
import logging
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)


class HIPAAEncryption:
    """AES-256-GCM encryption service for PHI data.

    Keys are derived from a master key using PBKDF2-SHA256 with a static
    salt (configurable via PHI_KDF_SALT). For production, use a KMS/HSM.
    """

    def __init__(self, master_key: str, key_rotation_days: int = 90):
        if not isinstance(master_key, str) or not master_key:
            raise ValueError("master_key must be a non-empty string")
        self.backend = default_backend()
        self.master_key: bytes = master_key.encode()
        self.key_rotation_days = int(key_rotation_days)
        self.current_key_version: int = 1
        self._derive_keys()

    def _derive_keys(self) -> None:
        """Derive encryption and HMAC keys from the master key."""
        salt_env = os.getenv("PHI_KDF_SALT", "vivified-phi-salt-v1").encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt_env,
            iterations=200_000,
            backend=self.backend,
        )
        derived = kdf.derive(self.master_key)
        self._encryption_key = derived[:32]  # 256-bit
        self._hmac_key = derived[32:]

    def encrypt_phi(self, data: Dict[str, Any], patient_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt PHI data with AES-256-GCM.

        Returns base64-encoded ciphertext bytes and metadata required for
        decryption (nonce, tag, version, algorithm, patient_id_hash).
        """
        if not isinstance(data, dict):
            raise TypeError("data must be a dict")
        if not isinstance(patient_id, str) or not patient_id:
            raise ValueError("patient_id must be a non-empty string")

        plaintext = json.dumps(data).encode()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self._encryption_key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(patient_id.encode())
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        metadata: Dict[str, Any] = {
            "version": self.current_key_version,
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(encryptor.tag).decode(),
            "patient_id_hash": self._hash_patient_id(patient_id),
        }

        logger.info("PHI encrypted for patient %s", metadata["patient_id_hash"])  # no PHI in logs
        return base64.b64encode(ciphertext), metadata

    def decrypt_phi(self, ciphertext: bytes, metadata: Dict[str, Any], patient_id: str) -> Dict[str, Any]:
        """Decrypt PHI data with AES-256-GCM using provided metadata."""
        if metadata.get("patient_id_hash") != self._hash_patient_id(patient_id):
            raise ValueError("Patient ID mismatch")

        raw_ct = base64.b64decode(ciphertext)
        nonce = base64.b64decode(str(metadata.get("nonce", "")))
        tag = base64.b64decode(str(metadata.get("tag", "")))
        key = self._get_key_version(int(metadata.get("version", 1)))

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(patient_id.encode())
        plaintext = decryptor.update(raw_ct) + decryptor.finalize()
        return json.loads(plaintext.decode())

    def _hash_patient_id(self, patient_id: str) -> str:
        return hmac.new(self._hmac_key, patient_id.encode(), hashlib.sha256).hexdigest()

    def _get_key_version(self, version: int) -> bytes:
        # In-memory single-version for now. Extend to real KMS-backed lookup.
        return self._encryption_key

    # Optional helpers for field-level transformations (non-cryptographic FPE placeholders)
    def encrypt_field(self, value: str, field_type: str = "pii") -> str:
        if field_type == "email":
            return self._encrypt_email_preserving_domain(value)
        if field_type == "ssn":
            return self._mask_ssn_like(value)
        # Default: base64 as a visibility reduction placeholder (not cryptographic)
        return base64.urlsafe_b64encode(value.encode()).decode()

    def _encrypt_email_preserving_domain(self, email: str) -> str:
        if "@" not in email:
            return base64.urlsafe_b64encode(email.encode()).decode()
        local, domain = email.split("@", 1)
        digest = hashlib.sha256(self._encryption_key + local.encode()).digest()
        token = base64.urlsafe_b64encode(digest[:6]).decode().rstrip("=")
        return f"{token}@{domain}"

    def _mask_ssn_like(self, ssn: str) -> str:
        digits = [c for c in ssn if c.isdigit()]
        if len(digits) < 9:
            return "***-**-****"
        # Deterministic masking based on key and position
        masked: List[str] = []
        for i, d in enumerate(digits[:9]):
            h = hashlib.sha256(self._encryption_key + bytes([i]) + d.encode()).digest()
            masked.append(str(h[0] % 10))
        return f"{''.join(masked[:3])}-{''.join(masked[3:5])}-{''.join(masked[5:9])}"


# Simple module-level singleton for admin surfaces
_PHI_ENCRYPTION_SVC: Optional[HIPAAEncryption] = None


def get_phi_encryption() -> HIPAAEncryption:
    global _PHI_ENCRYPTION_SVC
    if _PHI_ENCRYPTION_SVC is None:
        master = os.getenv("PHI_MASTER_KEY") or os.getenv("CONFIG_ENC_KEY") or "dev-phi-master"
        _PHI_ENCRYPTION_SVC = HIPAAEncryption(master)
    return _PHI_ENCRYPTION_SVC


def rotate_phi_encryption(new_master_key: Optional[str] = None) -> int:
    svc = get_phi_encryption()
    if new_master_key and isinstance(new_master_key, str) and new_master_key:
        svc.master_key = new_master_key.encode()
        svc._derive_keys()
    svc.current_key_version += 1
    logger.info("PHI encryption key version rotated to %s", svc.current_key_version)
    return svc.current_key_version


