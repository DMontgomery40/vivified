# Runbook 06: Security Implementation Guide

## Objective
Comprehensive security implementation covering encryption, authentication, authorization, PHI/PII protection, vulnerability management, and compliance controls for HIPAA.

## Critical Security Requirements

### HIPAA Technical Safeguards Implementation
- 164.312(a) - Access Control
- 164.312(b) - Audit Controls  
- 164.312(c) - Integrity Controls
- 164.312(d) - Transmission Security
- 164.312(e) - Encryption

## Tasks

### 1. Encryption Implementation

#### 1.1 Data at Rest Encryption
```python
# core/security/encryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import hmac
import secrets
import base64
import json
from typing import Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class HIPAAEncryption:
    """HIPAA-compliant encryption service for PHI data."""
    
    def __init__(self, master_key: str, key_rotation_days: int = 90):
        """Initialize with master key and rotation policy."""
        self.backend = default_backend()
        self.master_key = master_key.encode()
        self.key_rotation_days = key_rotation_days
        self.current_key_version = 1
        self._derive_keys()
        
    def _derive_keys(self):
        """Derive encryption and authentication keys from master key."""
        # Use PBKDF2 for key derivation
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption + 32 for HMAC
            salt=b'vivified-salt-v1',  # Should be stored securely
            iterations=100000,
            backend=self.backend
        )
        derived = kdf.derive(self.master_key)
        
        self.encryption_key = derived[:32]
        self.hmac_key = derived[32:]
        
    def encrypt_phi(self, data: Dict, patient_id: str) -> Tuple[bytes, Dict]:
        """Encrypt PHI data with AES-256-GCM."""
        # Serialize data
        plaintext = json.dumps(data).encode()
        
        # Generate nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Add patient ID as associated data for authentication
        encryptor.authenticate_additional_data(patient_id.encode())
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Create metadata
        metadata = {
            "version": self.current_key_version,
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(encryptor.tag).decode(),
            "patient_id_hash": self._hash_patient_id(patient_id)
        }
        
        # Log encryption event (without sensitive data)
        logger.info(f"PHI encrypted for patient {metadata['patient_id_hash']}")
        
        return base64.b64encode(ciphertext), metadata
    
    def decrypt_phi(self, ciphertext: bytes, metadata: Dict, patient_id: str) -> Dict:
        """Decrypt PHI data."""
        # Verify patient ID
        if metadata["patient_id_hash"] != self._hash_patient_id(patient_id):
            raise ValueError("Patient ID mismatch")
        
        # Decode components
        ciphertext = base64.b64decode(ciphertext)
        nonce = base64.b64decode(metadata["nonce"])
        tag = base64.b64decode(metadata["tag"])
        
        # Get appropriate key version
        key = self._get_key_version(metadata["version"])
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Verify associated data
        decryptor.authenticate_additional_data(patient_id.encode())
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Deserialize
        return json.loads(plaintext.decode())
    
    def _hash_patient_id(self, patient_id: str) -> str:
        """Create secure hash of patient ID."""
        return hmac.new(
            self.hmac_key,
            patient_id.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _get_key_version(self, version: int) -> bytes:
        """Get encryption key for specific version."""
        # Implement key versioning for rotation
        if version != self.current_key_version:
            # Retrieve historical key from secure storage
            pass
        return self.encryption_key
    
    def encrypt_field(self, value: str, field_type: str = "pii") -> str:
        """Encrypt individual field with format-preserving encryption."""
        if field_type == "ssn":
            # Format-preserving encryption for SSN
            return self._encrypt_ssn(value)
        elif field_type == "email":
            # Encrypt but preserve domain
            return self._encrypt_email(value)
        else:
            # Standard encryption
            f = Fernet(base64.urlsafe_b64encode(self.encryption_key))
            return f.encrypt(value.encode()).decode()
    
    def _encrypt_ssn(self, ssn: str) -> str:
        """Format-preserving encryption for SSN."""
        # Remove formatting
        clean_ssn = ssn.replace("-", "")
        
        # Encrypt while preserving format XXX-XX-XXXX
        encrypted = []
        for i, digit in enumerate(clean_ssn):
            # Use deterministic encryption for each position
            key_material = self.encryption_key + str(i).encode()
            hash_val = hashlib.sha256(key_material + digit.encode()).digest()
            encrypted_digit = str(int.from_bytes(hash_val[:1], 'big') % 10)
            encrypted.append(encrypted_digit)
        
        # Restore format
        result = "".join(encrypted)
        return f"{result[:3]}-{result[3:5]}-{result[5:]}"
    
    def _encrypt_email(self, email: str) -> str:
        """Encrypt email preserving domain."""
        if "@" not in email:
            return self.encrypt_field(email)
        
        local, domain = email.split("@", 1)
        
        # Encrypt local part
        f = Fernet(base64.urlsafe_b64encode(self.encryption_key))
        encrypted_local = base64.urlsafe_b64encode(
            f.encrypt(local.encode())[:8]  # Truncate for readability
        ).decode().rstrip("=")
        
        return f"{encrypted_local}@{domain}"
```

#### 1.2 Data in Transit Security
```python
# core/security/tls_manager.py
import ssl
import certifi
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class TLSManager:
    """Manages TLS certificates and secure connections."""
    
    def __init__(self, cert_path: str, key_path: str, ca_path: str):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.min_tls_version = ssl.TLSVersion.TLSv1_3
        
    def create_server_context(self) -> ssl.SSLContext:
        """Create secure server SSL context."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load certificates
        context.load_cert_chain(self.cert_path, self.key_path)
        context.load_verify_locations(self.ca_path)
        
        # Configure security
        context.minimum_version = self.min_tls_version
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Disable weak ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Enable hostname checking
        context.check_hostname = True
        
        # Set DH parameters for perfect forward secrecy
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        # Disable compression to prevent CRIME attack
        context.options |= ssl.OP_NO_COMPRESSION
        
        logger.info("TLS server context created with TLS 1.3 minimum")
        
        return context
    
    def create_client_context(self, verify: bool = True) -> ssl.SSLContext:
        """Create secure client SSL context."""
        if verify:
            context = ssl.create_default_context(cafile=self.ca_path)
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        # Configure security
        context.minimum_version = self.min_tls_version
        
        # Load client certificate if available
        if self.cert_path and self.key_path:
            context.load_cert_chain(self.cert_path, self.key_path)
        
        return context
    
    def generate_self_signed_cert(self, hostname: str) -> Tuple[str, str]:
        """Generate self-signed certificate for development."""
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vivified"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        # Serialize
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_pem.decode(), key_pem.decode()
```

### 2. Authentication & Authorization

#### 2.1 Multi-Factor Authentication
```python
# core/security/mfa.py
import pyotp
import qrcode
import io
import base64
from typing import Optional, Tuple
import secrets
import logging

logger = logging.getLogger(__name__)

class MFAService:
    """Multi-factor authentication service for HIPAA compliance."""
    
    def __init__(self, issuer: str = "Vivified Platform"):
        self.issuer = issuer
        self.backup_codes_count = 10
        
    def setup_totp(self, user_id: str, user_email: str) -> Tuple[str, str, List[str]]:
        """Set up TOTP for a user."""
        # Generate secret
        secret = pyotp.random_base32()
        
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = self.generate_backup_codes()
        
        logger.info(f"MFA setup initiated for user {user_id}")
        
        return secret, qr_code, backup_codes
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token."""
        totp = pyotp.TOTP(secret)
        valid = totp.verify(token, valid_window=window)
        
        if not valid:
            logger.warning("Invalid TOTP token attempted")
        
        return valid
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes for account recovery."""
        codes = []
        for _ in range(self.backup_codes_count):
            code = secrets.token_hex(4)  # 8-character hex code
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes
    
    def verify_backup_code(self, stored_codes: List[str], provided_code: str) -> Tuple[bool, Optional[str]]:
        """Verify and consume backup code."""
        formatted_code = provided_code.replace("-", "").lower()
        
        for stored_code in stored_codes:
            if stored_code.replace("-", "").lower() == formatted_code:
                logger.info("Backup code used for authentication")
                return True, stored_code  # Return code to remove from list
        
        logger.warning("Invalid backup code attempted")
        return False, None
    
    def enforce_mfa_for_role(self, role: str) -> bool:
        """Check if role requires MFA."""
        mfa_required_roles = [
            "admin",
            "phi_handler",
            "security_admin",
            "compliance_officer"
        ]
        return role in mfa_required_roles
```

#### 2.2 Role-Based Access Control (RBAC)
```python
# core/security/rbac.py
from typing import Dict, List, Set, Optional
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

class Permission(Enum):
    """System permissions."""
    # PHI Permissions
    PHI_READ = "phi:read"
    PHI_WRITE = "phi:write"
    PHI_DELETE = "phi:delete"
    PHI_EXPORT = "phi:export"
    
    # Plugin Permissions
    PLUGIN_MANAGE = "plugin:manage"
    PLUGIN_VIEW = "plugin:view"
    PLUGIN_CONFIGURE = "plugin:configure"
    
    # User Permissions
    USER_CREATE = "user:create"
    USER_MODIFY = "user:modify"
    USER_DELETE = "user:delete"
    USER_VIEW = "user:view"
    
    # System Permissions
    SYSTEM_CONFIGURE = "system:configure"
    SYSTEM_AUDIT = "system:audit"
    SYSTEM_BACKUP = "system:backup"
    
    # Security Permissions
    SECURITY_MANAGE = "security:manage"
    SECURITY_AUDIT = "security:audit"
    SECURITY_INCIDENT = "security:incident"

class RBACService:
    """Role-based access control service."""
    
    def __init__(self):
        self.roles = self._initialize_roles()
        self.role_hierarchy = self._initialize_hierarchy()
        
    def _initialize_roles(self) -> Dict[str, Set[Permission]]:
        """Initialize role definitions."""
        return {
            "super_admin": {
                Permission.PHI_READ, Permission.PHI_WRITE, Permission.PHI_DELETE, Permission.PHI_EXPORT,
                Permission.PLUGIN_MANAGE, Permission.PLUGIN_VIEW, Permission.PLUGIN_CONFIGURE,
                Permission.USER_CREATE, Permission.USER_MODIFY, Permission.USER_DELETE, Permission.USER_VIEW,
                Permission.SYSTEM_CONFIGURE, Permission.SYSTEM_AUDIT, Permission.SYSTEM_BACKUP,
                Permission.SECURITY_MANAGE, Permission.SECURITY_AUDIT, Permission.SECURITY_INCIDENT
            },
            "admin": {
                Permission.PHI_READ, Permission.PHI_WRITE,
                Permission.PLUGIN_MANAGE, Permission.PLUGIN_VIEW, Permission.PLUGIN_CONFIGURE,
                Permission.USER_CREATE, Permission.USER_MODIFY, Permission.USER_VIEW,
                Permission.SYSTEM_CONFIGURE, Permission.SYSTEM_AUDIT,
                Permission.SECURITY_AUDIT
            },
            "phi_handler": {
                Permission.PHI_READ, Permission.PHI_WRITE,
                Permission.PLUGIN_VIEW,
                Permission.USER_VIEW,
                Permission.SYSTEM_AUDIT
            },
            "operator": {
                Permission.PLUGIN_VIEW, Permission.PLUGIN_CONFIGURE,
                Permission.USER_VIEW,
                Permission.SYSTEM_AUDIT
            },
            "viewer": {
                Permission.PLUGIN_VIEW,
                Permission.USER_VIEW
            },
            "security_admin": {
                Permission.SECURITY_MANAGE, Permission.SECURITY_AUDIT, Permission.SECURITY_INCIDENT,
                Permission.SYSTEM_AUDIT,
                Permission.USER_VIEW
            },
            "compliance_officer": {
                Permission.PHI_READ,
                Permission.SYSTEM_AUDIT,
                Permission.SECURITY_AUDIT,
                Permission.USER_VIEW
            }
        }
    
    def _initialize_hierarchy(self) -> Dict[str, List[str]]:
        """Initialize role hierarchy (role inheritance)."""
        return {
            "super_admin": ["admin", "security_admin", "compliance_officer"],
            "admin": ["phi_handler", "operator"],
            "phi_handler": ["viewer"],
            "operator": ["viewer"],
            "security_admin": ["operator"],
            "compliance_officer": ["viewer"]
        }
    
    def check_permission(
        self,
        user_roles: List[str],
        required_permission: Permission,
        resource_context: Optional[Dict] = None
    ) -> bool:
        """Check if user has required permission."""
        # Expand roles based on hierarchy
        all_roles = self._expand_roles(user_roles)
        
        # Collect all permissions
        user_permissions = set()
        for role in all_roles:
            if role in self.roles:
                user_permissions.update(self.roles[role])
        
        # Basic permission check
        has_permission = required_permission in user_permissions
        
        # Context-based checks
        if has_permission and resource_context:
            has_permission = self._check_context_constraints(
                user_roles,
                required_permission,
                resource_context
            )
        
        # Audit access decision
        self._audit_access_decision(
            user_roles,
            required_permission,
            has_permission,
            resource_context
        )
        
        return has_permission
    
    def _expand_roles(self, user_roles: List[str]) -> Set[str]:
        """Expand roles based on hierarchy."""
        expanded = set(user_roles)
        
        for role in user_roles:
            if role in self.role_hierarchy:
                for inherited in self.role_hierarchy[role]:
                    expanded.add(inherited)
                    # Recursively add inherited roles
                    expanded.update(self._expand_roles([inherited]))
        
        return expanded
    
    def _check_context_constraints(
        self,
        user_roles: List[str],
        permission: Permission,
        context: Dict
    ) -> bool:
        """Check context-based access constraints."""
        # PHI access constraints
        if permission in [Permission.PHI_READ, Permission.PHI_WRITE]:
            # Check if user has valid treatment relationship
            if context.get("requires_treatment_relationship"):
                if not context.get("has_treatment_relationship"):
                    logger.warning(f"PHI access denied - no treatment relationship")
                    return False
            
            # Check purpose of use
            valid_purposes = ["treatment", "payment", "operations"]
            if context.get("purpose") not in valid_purposes:
                logger.warning(f"PHI access denied - invalid purpose: {context.get('purpose')}")
                return False
        
        # Time-based constraints
        if context.get("business_hours_only"):
            from datetime import datetime
            now = datetime.now()
            if not (8 <= now.hour < 18 and now.weekday() < 5):
                logger.warning("Access denied outside business hours")
                return False
        
        # Location-based constraints
        if context.get("restricted_locations"):
            user_location = context.get("user_location")
            if user_location not in context["restricted_locations"]:
                logger.warning(f"Access denied from location: {user_location}")
                return False
        
        return True
    
    def _audit_access_decision(
        self,
        user_roles: List[str],
        permission: Permission,
        granted: bool,
        context: Optional[Dict]
    ):
        """Audit access control decision."""
        audit_entry = {
            "roles": user_roles,
            "permission": permission.value,
            "granted": granted,
            "context": context,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Access decision: {json.dumps(audit_entry)}")
```

### 3. PHI/PII Protection

#### 3.1 Data Classification & Tagging
```python
# core/security/data_classification.py
import re
from typing import Dict, List, Set, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PHI = "phi"
    PII = "pii"
    RESTRICTED = "restricted"

class DataClassifier:
    """Classifies and tags data for protection."""
    
    def __init__(self):
        self.phi_patterns = self._load_phi_patterns()
        self.pii_patterns = self._load_pii_patterns()
        
    def _load_phi_patterns(self) -> Dict[str, re.Pattern]:
        """Load PHI detection patterns."""
        return {
            "mrn": re.compile(r"\b\d{6,10}\b"),  # Medical Record Number
            "diagnosis_code": re.compile(r"\b[A-Z]\d{2}\.\d{1,2}\b"),  # ICD-10
            "procedure_code": re.compile(r"\b\d{5}\b"),  # CPT codes
            "insurance_id": re.compile(r"\b[A-Z]{3}\d{9}\b"),
            "prescription": re.compile(r"\b(mg|mcg|ml|tablet|capsule)\b", re.I),
            "medical_terms": re.compile(
                r"\b(diagnosis|treatment|medication|prescription|"
                r"symptom|condition|disease|disorder|syndrome)\b", re.I
            )
        }
    
    def _load_pii_patterns(self) -> Dict[str, re.Pattern]:
        """Load PII detection patterns."""
        return {
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "phone": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
            "credit_card": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
            "drivers_license": re.compile(r"\b[A-Z]\d{7,12}\b"),
            "passport": re.compile(r"\b[A-Z][0-9]{8}\b"),
            "address": re.compile(
                r"\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|"
                r"Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl)\b", re.I
            )
        }
    
    def classify_data(self, data: Any) -> Set[DataClassification]:
        """Classify data and return classification tags."""
        classifications = {DataClassification.INTERNAL}  # Default
        
        if isinstance(data, dict):
            classifications.update(self._classify_dict(data))
        elif isinstance(data, str):
            classifications.update(self._classify_string(data))
        elif isinstance(data, (list, tuple)):
            for item in data:
                classifications.update(self.classify_data(item))
        
        return classifications
    
    def _classify_dict(self, data: Dict) -> Set[DataClassification]:
        """Classify dictionary data."""
        classifications = set()
        
        # Check field names
        phi_fields = {
            "diagnosis", "treatment", "medication", "medical_history",
            "lab_results", "imaging", "notes", "mrn", "patient_id"
        }
        
        pii_fields = {
            "ssn", "social_security", "email", "phone", "address",
            "date_of_birth", "dob", "name", "first_name", "last_name"
        }
        
        for key, value in data.items():
            key_lower = key.lower()
            
            if any(field in key_lower for field in phi_fields):
                classifications.add(DataClassification.PHI)
            
            if any(field in key_lower for field in pii_fields):
                classifications.add(DataClassification.PII)
            
            # Classify values
            if value:
                classifications.update(self.classify_data(value))
        
        return classifications
    
    def _classify_string(self, data: str) -> Set[DataClassification]:
        """Classify string data using patterns."""
        classifications = set()
        
        # Check for PHI patterns
        for pattern_name, pattern in self.phi_patterns.items():
            if pattern.search(data):
                classifications.add(DataClassification.PHI)
                break
        
        # Check for PII patterns
        for pattern_name, pattern in self.pii_patterns.items():
            if pattern.search(data):
                classifications.add(DataClassification.PII)
                break
        
        return classifications
    
    def redact_sensitive_data(self, data: Any, classifications: Set[DataClassification]) -> Any:
        """Redact sensitive data based on classification."""
        if DataClassification.PHI in classifications or DataClassification.PII in classifications:
            if isinstance(data, str):
                return self._redact_string(data)
            elif isinstance(data, dict):
                return self._redact_dict(data)
        return data
    
    def _redact_string(self, data: str) -> str:
        """Redact sensitive patterns in string."""
        redacted = data
        
        # Redact PHI
        for pattern in self.phi_patterns.values():
            redacted = pattern.sub("[REDACTED-PHI]", redacted)
        
        # Redact PII
        for pattern_name, pattern in self.pii_patterns.items():
            if pattern_name == "email":
                # Partial redaction for email
                redacted = pattern.sub(
                    lambda m: f"{m.group()[:2]}***@***.***",
                    redacted
                )
            else:
                redacted = pattern.sub("[REDACTED-PII]", redacted)
        
        return redacted
    
    def _redact_dict(self, data: Dict) -> Dict:
        """Redact sensitive fields in dictionary."""
        redacted = {}
        
        sensitive_fields = {
            "ssn", "social_security", "credit_card", "patient_id",
            "mrn", "diagnosis", "treatment", "medication"
        }
        
        for key, value in data.items():
            if any(field in key.lower() for field in sensitive_fields):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, str):
                redacted[key] = self._redact_string(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            else:
                redacted[key] = value
        
        return redacted
```

### 4. Vulnerability Management

#### 4.1 Security Scanning Service
```python
# core/security/vulnerability_scanner.py
import subprocess
import json
import yaml
from typing import Dict, List, Tuple
from pathlib import Path
import logging
import asyncio

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Scans for security vulnerabilities in code and dependencies."""
    
    def __init__(self):
        self.scanners = {
            "dependencies": self._scan_dependencies,
            "code": self._scan_code,
            "containers": self._scan_containers,
            "secrets": self._scan_secrets
        }
        
    async def run_full_scan(self, target_path: str) -> Dict:
        """Run all security scans."""
        results = {}
        
        for scan_type, scanner in self.scanners.items():
            logger.info(f"Running {scan_type} scan...")
            try:
                results[scan_type] = await scanner(target_path)
            except Exception as e:
                logger.error(f"Scan failed for {scan_type}: {e}")
                results[scan_type] = {"error": str(e)}
        
        # Generate summary
        results["summary"] = self._generate_summary(results)
        
        return results
    
    async def _scan_dependencies(self, path: str) -> Dict:
        """Scan for vulnerable dependencies."""
        results = {
            "python": [],
            "nodejs": [],
            "go": []
        }
        
        # Python dependencies
        if (Path(path) / "requirements.txt").exists():
            try:
                cmd = ["safety", "check", "--json"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=path
                )
                stdout, stderr = await proc.communicate()
                
                if stdout:
                    vulnerabilities = json.loads(stdout.decode())
                    results["python"] = vulnerabilities
            except Exception as e:
                logger.error(f"Python dependency scan failed: {e}")
        
        # Node.js dependencies
        if (Path(path) / "package.json").exists():
            try:
                cmd = ["npm", "audit", "--json"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=path
                )
                stdout, stderr = await proc.communicate()
                
                if stdout:
                    audit = json.loads(stdout.decode())
                    results["nodejs"] = audit.get("vulnerabilities", {})
            except Exception as e:
                logger.error(f"Node dependency scan failed: {e}")
        
        return results
    
    async def _scan_code(self, path: str) -> Dict:
        """Scan code for security issues."""
        results = []
        
        # Use Semgrep for static analysis
        try:
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--no-rewrite-rule-ids",
                path
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if stdout:
                findings = json.loads(stdout.decode())
                
                # Filter and prioritize findings
                for result in findings.get("results", []):
                    severity = result.get("extra", {}).get("severity", "INFO")
                    
                    if severity in ["ERROR", "WARNING"]:
                        results.append({
                            "file": result.get("path"),
                            "line": result.get("start", {}).get("line"),
                            "rule": result.get("check_id"),
                            "message": result.get("extra", {}).get("message"),
                            "severity": severity
                        })
                        
        except Exception as e:
            logger.error(f"Code scan failed: {e}")
        
        return results
    
    async def _scan_containers(self, path: str) -> Dict:
        """Scan container images for vulnerabilities."""
        results = []
        
        # Find Dockerfiles
        dockerfiles = list(Path(path).glob("**/Dockerfile*"))
        
        for dockerfile in dockerfiles:
            try:
                # Use Trivy for container scanning
                cmd = [
                    "trivy",
                    "config",
                    "--format", "json",
                    "--severity", "HIGH,CRITICAL",
                    str(dockerfile)
                ]
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                
                if stdout:
                    scan_result = json.loads(stdout.decode())
                    results.append({
                        "file": str(dockerfile),
                        "vulnerabilities": scan_result
                    })
                    
            except Exception as e:
                logger.error(f"Container scan failed for {dockerfile}: {e}")
        
        return results
    
    async def _scan_secrets(self, path: str) -> List[Dict]:
        """Scan for hardcoded secrets."""
        results = []
        
        try:
            # Use GitLeaks for secret scanning
            cmd = [
                "gitleaks",
                "detect",
                "--source", path,
                "--format", "json",
                "--no-git"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if stdout:
                leaks = json.loads(stdout.decode())
                
                for leak in leaks:
                    results.append({
                        "file": leak.get("File"),
                        "line": leak.get("StartLine"),
                        "type": leak.get("RuleID"),
                        "match": leak.get("Match")[:50] + "..." if len(leak.get("Match", "")) > 50 else leak.get("Match"),
                        "severity": "CRITICAL"
                    })
                    
        except Exception as e:
            logger.error(f"Secret scan failed: {e}")
        
        return results
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate vulnerability summary."""
        summary = {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "recommendations": []
        }
        
        # Count vulnerabilities by severity
        for scan_type, findings in results.items():
            if scan_type == "summary":
                continue
                
            if isinstance(findings, list):
                for finding in findings:
                    severity = finding.get("severity", "").upper()
                    if severity == "CRITICAL":
                        summary["critical"] += 1
                    elif severity == "HIGH":
                        summary["high"] += 1
                    elif severity == "MEDIUM":
                        summary["medium"] += 1
                    else:
                        summary["low"] += 1
                    summary["total_vulnerabilities"] += 1
        
        # Generate recommendations
        if summary["critical"] > 0:
            summary["recommendations"].append(
                "URGENT: Address critical vulnerabilities immediately"
            )
        
        if results.get("secrets"):
            summary["recommendations"].append(
                "Remove hardcoded secrets and use secure secret management"
            )
        
        if summary["total_vulnerabilities"] > 10:
            summary["recommendations"].append(
                "Implement regular vulnerability scanning in CI/CD pipeline"
            )
        
        return summary
```

### 5. Incident Response

#### 5.1 Security Incident Handler
```python
# core/security/incident_response.py
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum
import asyncio
import logging

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    """Incident severity levels."""
    CRITICAL = "critical"  # PHI breach, system compromise
    HIGH = "high"         # Failed security control, suspicious activity
    MEDIUM = "medium"     # Policy violation, configuration issue
    LOW = "low"           # Minor issue, informational

class IncidentType(Enum):
    """Types of security incidents."""
    PHI_BREACH = "phi_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE = "malware"
    DOS_ATTACK = "dos_attack"
    DATA_LOSS = "data_loss"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_COMPROMISE = "system_compromise"

class IncidentResponseService:
    """Handles security incident response."""
    
    def __init__(self, notification_service, audit_service):
        self.notification = notification_service
        self.audit = audit_service
        self.active_incidents = {}
        self.response_team = self._load_response_team()
        
    def _load_response_team(self) -> Dict:
        """Load incident response team contacts."""
        return {
            "security_lead": {"email": "security@vivified.local", "phone": "+1234567890"},
            "compliance_officer": {"email": "compliance@vivified.local", "phone": "+1234567891"},
            "legal": {"email": "legal@vivified.local", "phone": "+1234567892"},
            "ciso": {"email": "ciso@vivified.local", "phone": "+1234567893"}
        }
    
    async def report_incident(
        self,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        description: str,
        affected_resources: List[str],
        reporter: Optional[str] = None
    ) -> str:
        """Report a security incident."""
        incident_id = self._generate_incident_id()
        
        incident = {
            "id": incident_id,
            "type": incident_type.value,
            "severity": severity.value,
            "description": description,
            "affected_resources": affected_resources,
            "reporter": reporter or "system",
            "reported_at": datetime.utcnow().isoformat(),
            "status": "new",
            "response_actions": [],
            "timeline": []
        }
        
        self.active_incidents[incident_id] = incident
        
        # Log incident
        await self.audit.log_security_incident(incident)
        
        # Trigger response workflow
        asyncio.create_task(self._response_workflow(incident))
        
        return incident_id
    
    async def _response_workflow(self, incident: Dict):
        """Execute incident response workflow."""
        incident_id = incident["id"]
        severity = IncidentSeverity(incident["severity"])
        incident_type = IncidentType(incident["type"])
        
        # Step 1: Initial assessment
        await self._add_timeline_entry(incident_id, "Initial assessment started")
        
        # Step 2: Containment
        if severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
            await self._contain_incident(incident)
        
        # Step 3: Notification
        await self._notify_stakeholders(incident)
        
        # Step 4: Investigation
        investigation_results = await self._investigate_incident(incident)
        incident["investigation"] = investigation_results
        
        # Step 5: Remediation
        if incident_type == IncidentType.PHI_BREACH:
            await self._handle_phi_breach(incident)
        
        # Step 6: Recovery
        await self._recovery_actions(incident)
        
        # Step 7: Post-incident review
        if severity == IncidentSeverity.CRITICAL:
            await self._schedule_post_incident_review(incident)
    
    async def _contain_incident(self, incident: Dict):
        """Contain the security incident."""
        incident_type = IncidentType(incident["type"])
        
        containment_actions = {
            IncidentType.UNAUTHORIZED_ACCESS: [
                "Disable compromised accounts",
                "Reset all passwords",
                "Revoke active sessions"
            ],
            IncidentType.PHI_BREACH: [
                "Isolate affected systems",
                "Stop data flows",
                "Enable enhanced auditing"
            ],
            IncidentType.MALWARE: [
                "Quarantine infected systems",
                "Block malicious IPs",
                "Disable affected plugins"
            ],
            IncidentType.DOS_ATTACK: [
                "Enable DDoS protection",
                "Rate limit all endpoints",
                "Scale infrastructure"
            ]
        }
        
        actions = containment_actions.get(incident_type, ["Isolate affected resources"])
        
        for action in actions:
            await self._add_response_action(incident["id"], action)
            logger.info(f"Containment action for {incident['id']}: {action}")
    
    async def _notify_stakeholders(self, incident: Dict):
        """Notify relevant stakeholders about incident."""
        severity = IncidentSeverity(incident["severity"])
        
        # Determine who to notify based on severity
        if severity == IncidentSeverity.CRITICAL:
            recipients = ["security_lead", "compliance_officer", "legal", "ciso"]
        elif severity == IncidentSeverity.HIGH:
            recipients = ["security_lead", "compliance_officer"]
        else:
            recipients = ["security_lead"]
        
        for recipient in recipients:
            contact = self.response_team.get(recipient)
            if contact:
                await self.notification.send_incident_alert(
                    contact["email"],
                    incident
                )
        
        await self._add_timeline_entry(
            incident["id"],
            f"Stakeholders notified: {', '.join(recipients)}"
        )
    
    async def _handle_phi_breach(self, incident: Dict):
        """Handle PHI breach according to HIPAA requirements."""
        # HIPAA Breach Notification Rule requirements
        
        # Determine if breach is reportable
        risk_assessment = await self._assess_breach_risk(incident)
        incident["risk_assessment"] = risk_assessment
        
        if risk_assessment["reportable"]:
            # Individual notifications (within 60 days)
            await self._add_response_action(
                incident["id"],
                "Prepare individual breach notifications"
            )
            
            # Media notice (if >500 individuals affected)
            if risk_assessment["affected_count"] > 500:
                await self._add_response_action(
                    incident["id"],
                    "Prepare media notice for major breach"
                )
            
            # HHS notification
            await self._add_response_action(
                incident["id"],
                "Submit breach report to HHS OCR portal"
            )
            
            # Document everything for compliance
            await self.audit.log_hipaa_breach(incident, risk_assessment)
    
    async def _assess_breach_risk(self, incident: Dict) -> Dict:
        """Assess risk of PHI breach."""
        # HIPAA risk assessment factors
        return {
            "reportable": True,  # Conservative default
            "affected_count": len(incident.get("affected_resources", [])),
            "nature_of_phi": "comprehensive",  # Type of PHI exposed
            "unauthorized_recipient": "unknown",
            "mitigation_possible": False,
            "assessment_date": datetime.utcnow().isoformat()
        }
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"INC-{timestamp}"
    
    async def _add_timeline_entry(self, incident_id: str, entry: str):
        """Add entry to incident timeline."""
        if incident_id in self.active_incidents:
            self.active_incidents[incident_id]["timeline"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "entry": entry
            })
    
    async def _add_response_action(self, incident_id: str, action: str):
        """Add response action to incident."""
        if incident_id in self.active_incidents:
            self.active_incidents[incident_id]["response_actions"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": action
            })
```

## Security Validation Checklist

### Encryption
- [ ] AES-256-GCM for PHI encryption
- [ ] TLS 1.3 minimum for all communications
- [ ] Key rotation every 90 days
- [ ] Format-preserving encryption for SSN/email
- [ ] Encrypted database connections
- [ ] Secure key storage (HSM/KMS)

### Authentication
- [ ] MFA enforced for admin/PHI roles
- [ ] JWT tokens with 15-minute expiry
- [ ] Account lockout after 5 failed attempts
- [ ] Backup codes for account recovery
- [ ] Password complexity requirements met
- [ ] Session timeout after 30 minutes

### Authorization
- [ ] RBAC implemented with permissions
- [ ] Role hierarchy working
- [ ] Context-based access control
- [ ] PHI access requires treatment relationship
- [ ] Business hours enforcement (if configured)
- [ ] All decisions audited

### PHI/PII Protection
- [ ] Automatic data classification
- [ ] PHI/PII detection patterns working
- [ ] Redaction functioning correctly
- [ ] Field-level encryption available
- [ ] Data minimization enforced
- [ ] Retention policies configured

### Vulnerability Management
- [ ] Dependency scanning automated
- [ ] Code scanning in CI/CD
- [ ] Container scanning operational
- [ ] Secret detection working
- [ ] Regular penetration testing
- [ ] Vulnerability remediation tracked

### Incident Response
- [ ] Incident reporting functional
- [ ] Response workflow automated
- [ ] Stakeholder notifications working
- [ ] PHI breach procedures tested
- [ ] Risk assessment documented
- [ ] Post-incident reviews scheduled

### Compliance
- [ ] HIPAA controls implemented
- [ ] Audit logs complete and tamper-proof
- [ ] 7-year retention configured
- [ ] Breach notification ready
- [ ] Access reports available
- [ ] Compliance dashboard operational

## Next Steps
Proceed to Runbook 07 for comprehensive Plugin Development Guide.