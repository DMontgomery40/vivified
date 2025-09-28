# Runbook 07: Plugin Development Guide

## Objective
Complete walkthrough for developing, testing, and deploying Vivified plugins with emphasis on security, PHI handling, and compliance requirements.

## Prerequisites
- Vivified SDK installed
- CLI tool available
- Development environment configured
- Access to core platform for testing

## Plugin Development Lifecycle

### 1. Planning & Design

#### 1.1 Plugin Architecture Design
```yaml
# plugin-design.yaml
plugin:
  name: Patient Record Manager
  id: patient-record-manager
  type: healthcare
  
capabilities:
  - Store patient records
  - Search patient history
  - Generate reports
  - Audit access
  
data_handling:
  classification:
    - phi
    - pii
    - medical_records
  
  encryption:
    at_rest: AES-256-GCM
    in_transit: TLS 1.3
    
  retention:
    active: 7 years
    archived: 10 years
    
compliance:
  hipaa_controls:
    - 164.312(a) - Access Control
    - 164.312(b) - Audit Controls
    - 164.312(c) - Integrity
    - 164.312(d) - Transmission Security
    - 164.312(e) - Encryption
    
  certifications:
    - HIPAA
    - HITECH
    
integration:
  event_subscriptions:
    - PatientAdmitted
    - PatientDischarged
    - RecordRequested
    
  rpc_endpoints:
    - /api/patients/{id}
    - /api/patients/{id}/history
    - /api/patients/{id}/records
    
  external_apis:
    - https://api.healthix.org  # HIE integration
    
security:
  authentication: JWT
  authorization: RBAC
  mfa_required: true
  
  traits:
    - handles_phi
    - audit_required
    - encryption_required
    - critical_service
```

#### 1.2 Security Threat Model
```python
# threat_model.py
"""
Threat Model for Patient Record Manager Plugin

STRIDE Analysis:
- Spoofing: Mitigated by JWT authentication and MFA
- Tampering: Mitigated by integrity checks and audit logs
- Repudiation: Mitigated by comprehensive audit trail
- Information Disclosure: Mitigated by encryption and access controls
- Denial of Service: Mitigated by rate limiting and circuit breakers
- Elevation of Privilege: Mitigated by RBAC and principle of least privilege

Attack Vectors:
1. Unauthorized PHI access
2. Data exfiltration
3. Injection attacks
4. Session hijacking
5. Insider threats

Mitigations:
1. All PHI access requires valid treatment relationship
2. Data loss prevention controls
3. Input validation and parameterized queries
4. Session timeout and token rotation
5. Behavioral monitoring and audit reviews
"""
```

### 2. Plugin Implementation

#### 2.1 Full Plugin Implementation Example
```python
# patient_record_manager/main.py
"""Patient Record Manager Plugin - HIPAA Compliant."""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import hashlib

from vivified import (
    VivifiedPlugin,
    event_handler,
    rpc_endpoint,
    require_traits,
    audit_log,
    track_metrics,
    SecurityContext,
    CanonicalModels
)
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

Base = declarative_base()

class PatientRecord(Base):
    """Patient record model with encryption."""
    __tablename__ = 'patient_records'
    
    id = Column(String, primary_key=True)
    patient_id_hash = Column(String, index=True)  # Hashed for privacy
    record_type = Column(String)
    encrypted_data = Column(Text)
    encryption_metadata = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    accessed_at = Column(DateTime)
    accessed_by = Column(String)
    is_active = Column(Boolean, default=True)

class PatientRecordManager(VivifiedPlugin):
    """HIPAA-compliant patient record management plugin."""
    
    def __init__(self):
        super().__init__("manifest.json")
        self.db_engine = None
        self.db_session = None
        self.encryption_key = None
        self.access_cache = {}  # Cache for treatment relationships
        
    async def initialize(self):
        """Initialize plugin with security controls."""
        logger.info("Initializing Patient Record Manager")
        
        # Set up database with encryption
        await self._setup_database()
        
        # Initialize encryption
        await self._setup_encryption()
        
        # Subscribe to healthcare events
        await self.event_bus.subscribe([
            "PatientAdmitted",
            "PatientDischarged",
            "EmergencyAccess",
            "AuditRequest"
        ], self.handle_healthcare_event)
        
        # Set up background tasks
        asyncio.create_task(self._audit_retention_cleanup())
        asyncio.create_task(self._access_review_task())
        
        # Initialize metrics
        self.init_metrics()
        
    async def _setup_database(self):
        """Set up encrypted database connection."""
        # Get database configuration from core
        db_config = await self.get_config("database")
        
        # Create encrypted connection
        connection_string = f"postgresql+asyncpg://{db_config['user']}:{db_config['password']}@{db_config['host']}/{db_config['database']}?sslmode=require"
        
        self.db_engine = create_engine(
            connection_string,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=3600
        )
        
        Base.metadata.create_all(self.db_engine)
        Session = sessionmaker(bind=self.db_engine)
        self.db_session = Session()
        
    async def _setup_encryption(self):
        """Initialize encryption for PHI data."""
        # Get encryption key from secure storage
        key_config = await self.get_config("encryption")
        self.encryption_key = Fernet(key_config["key"].encode())
        
    @rpc_endpoint("/api/patients/{patient_id}")
    @require_traits(["handles_phi", "authenticated"])
    @audit_log("patient_record_access")
    @track_metrics("record_retrieval")
    async def get_patient_record(
        self,
        patient_id: str,
        context: SecurityContext
    ) -> Dict:
        """Retrieve patient record with access control."""
        # Verify treatment relationship
        if not await self._verify_treatment_relationship(
            context.user_id,
            patient_id,
            context.purpose
        ):
            logger.warning(f"Unauthorized access attempt by {context.user_id} for patient {patient_id}")
            raise PermissionError("No valid treatment relationship")
        
        # Hash patient ID for privacy
        patient_hash = self._hash_patient_id(patient_id)
        
        # Retrieve encrypted records
        records = self.db_session.query(PatientRecord).filter(
            PatientRecord.patient_id_hash == patient_hash,
            PatientRecord.is_active == True
        ).all()
        
        if not records:
            return {"patient_id": patient_id, "records": [], "status": "no_records"}
        
        # Decrypt records
        decrypted_records = []
        for record in records:
            try:
                decrypted_data = self._decrypt_record(record)
                
                # Apply data minimization
                minimized_data = self._apply_data_minimization(
                    decrypted_data,
                    context.purpose
                )
                
                decrypted_records.append(minimized_data)
                
                # Update access audit
                record.accessed_at = datetime.utcnow()
                record.accessed_by = context.user_id
                
            except Exception as e:
                logger.error(f"Failed to decrypt record {record.id}: {e}")
                continue
        
        self.db_session.commit()
        
        # Log PHI access for HIPAA compliance
        await self.audit_phi_access(
            user_id=context.user_id,
            patient_id=patient_id,
            records_accessed=len(decrypted_records),
            purpose=context.purpose
        )
        
        return {
            "patient_id": patient_id,
            "records": decrypted_records,
            "access_timestamp": datetime.utcnow().isoformat(),
            "purpose": context.purpose
        }
    
    @rpc_endpoint("/api/patients/{patient_id}/records")
    @require_traits(["handles_phi", "write_access"])
    @audit_log("patient_record_creation")
    async def create_patient_record(
        self,
        patient_id: str,
        record_data: Dict,
        context: SecurityContext
    ) -> Dict:
        """Create new patient record with encryption."""
        # Validate record data
        if not self._validate_record_data(record_data):
            raise ValueError("Invalid record data")
        
        # Check for consent
        if not await self._verify_patient_consent(patient_id, "record_creation"):
            raise PermissionError("Patient consent required")
        
        # Encrypt PHI data
        encrypted_data, encryption_metadata = self._encrypt_record(record_data)
        
        # Create database record
        record = PatientRecord(
            id=self._generate_record_id(),
            patient_id_hash=self._hash_patient_id(patient_id),
            record_type=record_data.get("type", "general"),
            encrypted_data=encrypted_data,
            encryption_metadata=json.dumps(encryption_metadata),
            created_by=context.user_id
        )
        
        self.db_session.add(record)
        self.db_session.commit()
        
        # Publish event
        await self.event_bus.publish(
            "PatientRecordCreated",
            {
                "patient_id": patient_id,
                "record_id": record.id,
                "record_type": record.record_type,
                "created_by": context.user_id
            },
            data_traits=["phi"]
        )
        
        return {
            "record_id": record.id,
            "status": "created",
            "timestamp": record.created_at.isoformat()
        }
    
    @event_handler("EmergencyAccess")
    @audit_log("emergency_override")
    async def handle_emergency_access(self, event: Dict):
        """Handle emergency access requests with break-glass functionality."""
        request = event["payload"]
        patient_id = request["patient_id"]
        requester_id = request["requester_id"]
        reason = request["reason"]
        
        # Log break-glass access
        logger.critical(f"EMERGENCY ACCESS: {requester_id} accessing {patient_id} - Reason: {reason}")
        
        # Grant temporary access
        self.access_cache[f"{requester_id}:{patient_id}"] = {
            "granted_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "reason": reason,
            "emergency": True
        }
        
        # Send immediate notification
        await self.notification.send_emergency_alert({
            "type": "break_glass_access",
            "requester": requester_id,
            "patient": patient_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Schedule access review
        asyncio.create_task(self._schedule_emergency_review(requester_id, patient_id))
    
    async def _verify_treatment_relationship(
        self,
        user_id: str,
        patient_id: str,
        purpose: str
    ) -> bool:
        """Verify valid treatment relationship for PHI access."""
        # Check cache first
        cache_key = f"{user_id}:{patient_id}"
        if cache_key in self.access_cache:
            cached = self.access_cache[cache_key]
            if cached["expires_at"] > datetime.utcnow():
                return True
        
        # Check with authorization service
        auth_result = await self.rpc_client.call(
            "authorization-service",
            "verify_treatment_relationship",
            {
                "provider_id": user_id,
                "patient_id": patient_id,
                "purpose": purpose
            }
        )
        
        if auth_result.get("authorized"):
            # Cache the relationship
            self.access_cache[cache_key] = {
                "granted_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(hours=8),
                "purpose": purpose,
                "emergency": False
            }
            return True
        
        return False
    
    def _encrypt_record(self, data: Dict) -> Tuple[str, Dict]:
        """Encrypt patient record data."""
        # Serialize data
        json_data = json.dumps(data)
        
        # Encrypt with Fernet (AES-128 in CBC mode)
        encrypted = self.encryption_key.encrypt(json_data.encode())
        
        # Generate metadata
        metadata = {
            "algorithm": "AES-128-CBC",
            "timestamp": datetime.utcnow().isoformat(),
            "version": 1
        }
        
        return encrypted.decode(), metadata
    
    def _decrypt_record(self, record: PatientRecord) -> Dict:
        """Decrypt patient record data."""
        encrypted_data = record.encrypted_data.encode()
        decrypted = self.encryption_key.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    
    def _hash_patient_id(self, patient_id: str) -> str:
        """Hash patient ID for privacy."""
        salt = self.manifest.get("security", {}).get("salt", "vivified-salt")
        return hashlib.sha256(f"{patient_id}:{salt}".encode()).hexdigest()
    
    def _apply_data_minimization(self, data: Dict, purpose: str) -> Dict:
        """Apply data minimization based on access purpose."""
        if purpose == "billing":
            # Remove clinical notes for billing access
            minimized = {k: v for k, v in data.items() 
                        if k not in ["clinical_notes", "psychotherapy_notes"]}
        elif purpose == "research":
            # Remove identifiers for research
            minimized = {k: v for k, v in data.items()
                        if k not in ["name", "ssn", "address", "phone"]}
        else:
            minimized = data
        
        return minimized
    
    def _validate_record_data(self, data: Dict) -> bool:
        """Validate record data structure and content."""
        required_fields = ["type", "content"]
        
        # Check required fields
        if not all(field in data for field in required_fields):
            return False
        
        # Validate record type
        valid_types = ["clinical", "laboratory", "imaging", "prescription", "procedure"]
        if data["type"] not in valid_types:
            return False
        
        # Check for injection attacks
        if self._detect_injection(str(data)):
            logger.warning("Potential injection attack detected in record data")
            return False
        
        return True
    
    def _detect_injection(self, content: str) -> bool:
        """Detect potential injection attacks."""
        suspicious_patterns = [
            "<script", "javascript:", "onerror=",
            "DROP TABLE", "DELETE FROM", "UPDATE SET",
            "../", "\\x00", "%00"
        ]
        
        content_lower = content.lower()
        return any(pattern in content_lower for pattern in suspicious_patterns)
    
    async def _audit_retention_cleanup(self):
        """Clean up audit logs per retention policy."""
        while True:
            try:
                # HIPAA requires 7-year retention
                retention_date = datetime.utcnow() - timedelta(days=2555)
                
                # Archive old records
                old_records = self.db_session.query(PatientRecord).filter(
                    PatientRecord.created_at < retention_date
                ).all()
                
                for record in old_records:
                    # Archive to cold storage
                    await self._archive_record(record)
                    
                    # Mark as archived
                    record.is_active = False
                
                self.db_session.commit()
                
                logger.info(f"Archived {len(old_records)} old records")
                
            except Exception as e:
                logger.error(f"Retention cleanup failed: {e}")
            
            # Run daily
            await asyncio.sleep(86400)
    
    async def _access_review_task(self):
        """Review access patterns for anomalies."""
        while True:
            try:
                # Check for unusual access patterns
                recent_accesses = self.db_session.query(PatientRecord).filter(
                    PatientRecord.accessed_at > datetime.utcnow() - timedelta(hours=1)
                ).all()
                
                # Group by accessor
                access_by_user = {}
                for record in recent_accesses:
                    user = record.accessed_by
                    if user not in access_by_user:
                        access_by_user[user] = 0
                    access_by_user[user] += 1
                
                # Flag excessive access
                for user, count in access_by_user.items():
                    if count > 50:  # Threshold for unusual activity
                        await self.notification.send_security_alert({
                            "type": "excessive_phi_access",
                            "user": user,
                            "access_count": count,
                            "period": "1 hour"
                        })
                
            except Exception as e:
                logger.error(f"Access review failed: {e}")
            
            # Run every hour
            await asyncio.sleep(3600)
    
    def init_metrics(self):
        """Initialize Prometheus metrics."""
        from prometheus_client import Counter, Histogram, Gauge
        
        self.metrics = {
            "records_accessed": Counter(
                "patient_records_accessed_total",
                "Total patient records accessed",
                ["purpose", "user_role"]
            ),
            "records_created": Counter(
                "patient_records_created_total",
                "Total patient records created",
                ["record_type"]
            ),
            "access_denied": Counter(
                "patient_records_access_denied_total",
                "Access denied attempts",
                ["reason"]
            ),
            "encryption_operations": Counter(
                "encryption_operations_total",
                "Encryption/decryption operations",
                ["operation"]
            ),
            "active_records": Gauge(
                "patient_records_active",
                "Number of active patient records"
            )
        }

# Entry point
if __name__ == "__main__":
    plugin = PatientRecordManager()
    plugin.run(port=8080)
```

### 3. Testing Strategy

#### 3.1 Comprehensive Test Suite
```python
# tests/test_patient_record_manager.py
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import json

from patient_record_manager import PatientRecordManager, PatientRecord

class TestPatientRecordManager:
    """Test suite for Patient Record Manager plugin."""
    
    @pytest.fixture
    async def plugin(self):
        """Create plugin instance for testing."""
        with patch('patient_record_manager.create_engine'):
            plugin = PatientRecordManager()
            plugin.encryption_key = Mock()
            plugin.db_session = Mock()
            plugin.event_bus = AsyncMock()
            plugin.rpc_client = AsyncMock()
            await plugin.initialize()
            yield plugin
    
    @pytest.fixture
    def security_context(self):
        """Create mock security context."""
        from vivified import SecurityContext
        return SecurityContext(
            user_id="test-user",
            roles=["phi_handler"],
            purpose="treatment",
            trace_id="test-trace"
        )
    
    @pytest.mark.asyncio
    async def test_patient_record_access_authorized(self, plugin, security_context):
        """Test authorized patient record access."""
        # Mock treatment relationship verification
        plugin._verify_treatment_relationship = AsyncMock(return_value=True)
        
        # Mock database query
        mock_record = Mock(spec=PatientRecord)
        mock_record.encrypted_data = b"encrypted"
        plugin.db_session.query.return_value.filter.return_value.all.return_value = [mock_record]
        
        # Mock decryption
        plugin._decrypt_record = Mock(return_value={"test": "data"})
        
        # Test
        result = await plugin.get_patient_record("patient-123", security_context)
        
        # Assertions
        assert result["patient_id"] == "patient-123"
        assert len(result["records"]) == 1
        plugin._verify_treatment_relationship.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_patient_record_access_denied(self, plugin, security_context):
        """Test denied patient record access."""
        # Mock no treatment relationship
        plugin._verify_treatment_relationship = AsyncMock(return_value=False)
        
        # Test
        with pytest.raises(PermissionError):
            await plugin.get_patient_record("patient-123", security_context)
    
    @pytest.mark.asyncio
    async def test_encryption_decryption(self, plugin):
        """Test PHI encryption and decryption."""
        from cryptography.fernet import Fernet
        
        # Set up real encryption
        plugin.encryption_key = Fernet(Fernet.generate_key())
        
        # Test data
        original_data = {
            "patient_name": "John Doe",
            "diagnosis": "Hypertension",
            "ssn": "123-45-6789"
        }
        
        # Encrypt
        encrypted, metadata = plugin._encrypt_record(original_data)
        
        # Decrypt
        mock_record = Mock()
        mock_record.encrypted_data = encrypted
        decrypted = plugin._decrypt_record(mock_record)
        
        # Assertions
        assert decrypted == original_data
        assert metadata["algorithm"] == "AES-128-CBC"
    
    @pytest.mark.asyncio
    async def test_emergency_access(self, plugin):
        """Test emergency break-glass access."""
        # Mock notification service
        plugin.notification = AsyncMock()
        
        # Test event
        event = {
            "payload": {
                "patient_id": "patient-123",
                "requester_id": "doctor-456",
                "reason": "Emergency surgery"
            }
        }
        
        # Handle emergency
        await plugin.handle_emergency_access(event)
        
        # Verify access granted
        cache_key = "doctor-456:patient-123"
        assert cache_key in plugin.access_cache
        assert plugin.access_cache[cache_key]["emergency"] is True
        
        # Verify notification sent
        plugin.notification.send_emergency_alert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_data_minimization(self, plugin):
        """Test data minimization for different purposes."""
        full_data = {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "diagnosis": "Hypertension",
            "clinical_notes": "Patient shows improvement",
            "billing_code": "99213"
        }
        
        # Test billing purpose
        billing_data = plugin._apply_data_minimization(full_data, "billing")
        assert "clinical_notes" not in billing_data
        assert "billing_code" in billing_data
        
        # Test research purpose
        research_data = plugin._apply_data_minimization(full_data, "research")
        assert "ssn" not in research_data
        assert "diagnosis" in research_data
    
    @pytest.mark.asyncio
    async def test_injection_detection(self, plugin):
        """Test SQL/XSS injection detection."""
        # Test SQL injection
        malicious_sql = {
            "type": "clinical",
            "content": "'; DROP TABLE patients; --"
        }
        assert not plugin._validate_record_data(malicious_sql)
        
        # Test XSS
        malicious_xss = {
            "type": "clinical",
            "content": "<script>alert('xss')</script>"
        }
        assert not plugin._validate_record_data(malicious_xss)
        
        # Test valid data
        valid_data = {
            "type": "clinical",
            "content": "Normal clinical notes"
        }
        assert plugin._validate_record_data(valid_data)
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, plugin, security_context):
        """Test HIPAA audit logging."""
        plugin.audit_phi_access = AsyncMock()
        plugin._verify_treatment_relationship = AsyncMock(return_value=True)
        plugin.db_session.query.return_value.filter.return_value.all.return_value = []
        
        # Access record
        await plugin.get_patient_record("patient-123", security_context)
        
        # Verify audit log created
        plugin.audit_phi_access.assert_called_once_with(
            user_id="test-user",
            patient_id="patient-123",
            records_accessed=0,
            purpose="treatment"
        )
    
    @pytest.mark.asyncio
    async def test_consent_verification(self, plugin, security_context):
        """Test patient consent verification."""
        plugin._verify_patient_consent = AsyncMock(return_value=False)
        
        # Try to create record without consent
        with pytest.raises(PermissionError, match="consent required"):
            await plugin.create_patient_record(
                "patient-123",
                {"type": "clinical", "content": "test"},
                security_context
            )
    
    @pytest.mark.asyncio
    async def test_retention_policy(self, plugin):
        """Test 7-year retention policy enforcement."""
        # Create old record
        old_date = datetime.utcnow() - timedelta(days=2556)
        old_record = Mock(spec=PatientRecord)
        old_record.created_at = old_date
        
        plugin.db_session.query.return_value.filter.return_value.all.return_value = [old_record]
        plugin._archive_record = AsyncMock()
        
        # Run retention cleanup
        await plugin._audit_retention_cleanup()
        
        # Verify archival
        plugin._archive_record.assert_called_once_with(old_record)
        assert old_record.is_active is False
```

### 4. Deployment Configuration

#### 4.1 Production Dockerfile
```dockerfile
# Dockerfile
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev postgresql-dev

# Create build directory
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Runtime image
FROM python:3.11-alpine

# Install runtime dependencies
RUN apk update && apk upgrade && \
    apk add --no-cache libpq libssl1.1 ca-certificates && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 vivified && \
    adduser -D -u 1001 -G vivified vivified

# Copy wheels and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/* && rm -rf /wheels

# Set up application
WORKDIR /app
COPY --chown=vivified:vivified . .

# Security hardening
RUN chmod -R 550 /app && \
    mkdir -p /app/logs && \
    chown vivified:vivified /app/logs && \
    chmod 750 /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('https://localhost:8080/health', verify=False)"

# Run as non-root
USER vivified

# No shell for security
ENTRYPOINT ["python", "-m", "patient_record_manager"]
```

#### 4.2 Kubernetes Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patient-record-manager
  namespace: vivified-plugins
  labels:
    app: patient-record-manager
    type: plugin
    compliance: hipaa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: patient-record-manager
  template:
    metadata:
      labels:
        app: patient-record-manager
        handles-phi: "true"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: patient-record-plugin
      
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault
          
      containers:
      - name: patient-record-manager
        image: vivified/patient-record-manager:1.0.0
        imagePullPolicy: Always
        
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
          
        env:
        - name: CORE_URL
          value: "https://vivified-core:8443"
        - name: NATS_URL
          value: "nats://nats:4222"
        - name: LOG_LEVEL
          value: "INFO"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: patient-record-db
              key: connection-string
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: patient-record-encryption
              key: key
              
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
            
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
          
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
          
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /app/logs
        - name: certs
          mountPath: /certs
          readOnly: true
          
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
      - name: certs
        secret:
          secretName: patient-record-certs
          defaultMode: 0400
```

### 5. Performance Optimization

#### 5.1 Performance Tuning Configuration
```python
# performance_config.py
"""Performance optimization configuration for plugin."""

# Connection pooling
DATABASE_POOL_SIZE = 20
DATABASE_MAX_OVERFLOW = 10
DATABASE_POOL_TIMEOUT = 30
DATABASE_POOL_RECYCLE = 3600

# Caching configuration
CACHE_TTL = {
    "treatment_relationship": 28800,  # 8 hours
    "patient_consent": 86400,         # 24 hours
    "user_roles": 3600,               # 1 hour
    "config": 300                     # 5 minutes
}

# Rate limiting
RATE_LIMITS = {
    "patient_record_access": {
        "requests": 100,
        "period": 60  # seconds
    },
    "record_creation": {
        "requests": 10,
        "period": 60
    },
    "bulk_operations": {
        "requests": 1,
        "period": 60
    }
}

# Circuit breaker settings
CIRCUIT_BREAKER = {
    "failure_threshold": 5,
    "recovery_timeout": 60,
    "expected_exception": ConnectionError
}

# Async settings
ASYNC_WORKERS = 4
ASYNC_QUEUE_SIZE = 100

# Batch processing
BATCH_SIZES = {
    "audit_logs": 100,
    "notifications": 50,
    "archive": 1000
}
```

## Plugin Development Checklist

### Security Requirements
- [ ] All PHI data encrypted at rest
- [ ] TLS 1.3 for all communications
- [ ] Authentication required for all endpoints
- [ ] Authorization checks implemented
- [ ] Input validation on all data
- [ ] Injection prevention implemented
- [ ] Audit logging comprehensive

### HIPAA Compliance
- [ ] Access control implemented (164.312(a))
- [ ] Audit controls in place (164.312(b))
- [ ] Integrity controls verified (164.312(c))
- [ ] Transmission security ensured (164.312(d))
- [ ] Encryption implemented (164.312(e))
- [ ] 7-year retention policy configured
- [ ] Break-glass functionality tested

### Testing Requirements
- [ ] Unit tests >80% coverage
- [ ] Integration tests passing
- [ ] Security tests completed
- [ ] Performance tests meeting SLOs
- [ ] PHI handling tests verified
- [ ] Emergency access tested
- [ ] Audit trail validated

### Documentation
- [ ] API documentation complete
- [ ] Security threat model documented
- [ ] Deployment guide written
- [ ] Configuration documented
- [ ] Troubleshooting guide available
- [ ] Compliance mapping complete

### Deployment Readiness
- [ ] Container security hardened
- [ ] Kubernetes manifests tested
- [ ] Secrets management configured
- [ ] Monitoring enabled
- [ ] Alerts configured
- [ ] Backup procedures tested
- [ ] Disaster recovery plan verified

## Next Steps
Proceed to Runbook 08 for comprehensive Testing & QA Procedures.