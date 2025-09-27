# Runbook 08: Testing & QA Procedures

## Objective
Establish comprehensive testing strategies covering unit, integration, security, compliance, performance, and chaos testing for the Vivified platform.

## Testing Framework

### 1. Unit Testing

#### 1.1 Core Service Unit Tests
```python
# tests/unit/test_identity_service.py
import pytest
from unittest.mock import Mock, AsyncMock, patch
import jwt
from datetime import datetime, timedelta
import bcrypt

from core.identity.service import IdentityService

@pytest.fixture
async def identity_service():
    """Create identity service instance for testing."""
    mock_db = AsyncMock()
    jwt_secret = "test-secret-key"
    service = IdentityService(mock_db, jwt_secret)
    return service

class TestIdentityService:
    """Unit tests for identity service."""
    
    @pytest.mark.asyncio
    async def test_create_user_with_password_hashing(self, identity_service):
        """Test user creation with secure password hashing."""
        # Arrange
        username = "testuser"
        email = "test@example.com"
        password = "SecureP@ssw0rd123"
        
        identity_service.db.execute = AsyncMock()
        identity_service.db.execute.return_value.fetchone.return_value = ["user-123"]
        
        # Act
        result = await identity_service.create_user(username, email, password)
        
        # Assert
        assert result["username"] == username
        assert "id" in result
        
        # Verify password was hashed
        call_args = identity_service.db.execute.call_args[0]
        stored_hash = call_args[1][2]  # password_hash parameter
        assert bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    
    @pytest.mark.asyncio
    async def test_authentication_success(self, identity_service):
        """Test successful authentication with valid credentials."""
        # Arrange
        username = "testuser"
        password = "SecureP@ssw0rd123"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        identity_service.db.fetchone = AsyncMock(return_value={
            "id": "user-123",
            "password_hash": password_hash,
            "mfa_secret": None,
            "mfa_enabled": False,
            "failed_login_attempts": 0,
            "locked_until": None
        })
        
        identity_service._get_user_traits = AsyncMock(return_value=["user", "viewer"])
        identity_service.db.execute = AsyncMock()
        identity_service._audit_log = AsyncMock()
        
        # Act
        result = await identity_service.authenticate(username, password)
        
        # Assert
        assert result is not None
        assert "token" in result
        assert "expires_in" in result
        
        # Verify JWT token
        decoded = jwt.decode(result["token"], "test-secret-key", algorithms=["HS256"])
        assert decoded["sub"] == "user-123"
        assert decoded["traits"] == ["user", "viewer"]
    
    @pytest.mark.asyncio
    async def test_authentication_lockout(self, identity_service):
        """Test account lockout after failed attempts."""
        # Arrange
        username = "testuser"
        locked_until = datetime.utcnow() + timedelta(minutes=30)
        
        identity_service.db.fetchone = AsyncMock(return_value={
            "id": "user-123",
            "password_hash": "hash",
            "locked_until": locked_until,
            "failed_login_attempts": 5
        })
        
        identity_service._audit_log = AsyncMock()
        
        # Act
        result = await identity_service.authenticate(username, "anypassword")
        
        # Assert
        assert result is None
        identity_service._audit_log.assert_called_with(
            "user-123", "failed_login", False, {"reason": "account_locked"}
        )
    
    @pytest.mark.asyncio
    async def test_mfa_verification(self, identity_service):
        """Test MFA token verification."""
        import pyotp
        
        # Arrange
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        # Act
        result = identity_service._verify_mfa(secret, valid_token)
        
        # Assert
        assert result is True
        
        # Test invalid token
        assert identity_service._verify_mfa(secret, "000000") is False
    
    @pytest.mark.asyncio
    async def test_token_expiry(self, identity_service):
        """Test JWT token expiry validation."""
        # Create expired token
        expired_payload = {
            "sub": "user-123",
            "exp": datetime.utcnow() - timedelta(minutes=1)
        }
        expired_token = jwt.encode(expired_payload, "test-secret-key", algorithm="HS256")
        
        # Verify token is rejected
        result = await identity_service.verify_token(expired_token)
        assert result is None
```

#### 1.2 Policy Engine Unit Tests
```python
# tests/unit/test_policy_engine.py
import pytest
from core.policy.engine import PolicyEngine, PolicyRule

class TestPolicyEngine:
    """Unit tests for policy engine."""
    
    @pytest.fixture
    def policy_engine(self):
        """Create policy engine instance."""
        return PolicyEngine()
    
    def test_phi_protection_rule(self, policy_engine):
        """Test PHI protection policy."""
        # Arrange
        source_plugin = {"id": "plugin1", "traits": ["handles_phi"]}
        target_plugin = {"id": "plugin2", "traits": ["handles_phi"]}
        data = {"traits": ["phi"]}
        
        # Act
        decision, reason = policy_engine.evaluate_plugin_interaction(
            source_plugin, target_plugin, data
        )
        
        # Assert
        assert decision == "allow"
        assert reason == "phi_protection"
    
    def test_phi_block_unauthorized(self, policy_engine):
        """Test PHI access blocked for unauthorized plugin."""
        # Arrange
        source_plugin = {"id": "plugin1", "traits": ["handles_phi"]}
        target_plugin = {"id": "plugin2", "traits": []}  # No PHI trait
        data = {"traits": ["phi"]}
        
        # Act
        decision, reason = policy_engine.evaluate_plugin_interaction(
            source_plugin, target_plugin, data
        )
        
        # Assert
        assert decision == "deny"
        assert reason == "phi_block_unauthorized"
    
    def test_sanitization_for_external_service(self, policy_engine):
        """Test data sanitization for external services."""
        # Arrange
        source_plugin = {"id": "plugin1", "traits": ["handles_phi"]}
        target_plugin = {"id": "external", "traits": ["external_service"]}
        data = {"traits": ["phi", "confidential"]}
        
        # Act
        decision, reason = policy_engine.evaluate_plugin_interaction(
            source_plugin, target_plugin, data
        )
        
        # Assert
        assert decision == "sanitize"
        assert reason == "external_service_restriction"
    
    def test_user_action_authorization(self, policy_engine):
        """Test user action authorization."""
        # Test admin access
        result, reason = policy_engine.evaluate_user_action(
            ["admin"], "delete", ["phi"]
        )
        assert result is True
        assert reason == "admin_privilege"
        
        # Test unauthorized PHI access
        result, reason = policy_engine.evaluate_user_action(
            ["viewer"], "read", ["phi"]
        )
        assert result is False
        assert reason == "unauthorized_phi_access"
```

### 2. Integration Testing

#### 2.1 End-to-End Integration Test
```python
# tests/integration/test_e2e_workflow.py
import pytest
import asyncio
import httpx
from datetime import datetime
import json

@pytest.fixture
async def test_environment():
    """Set up test environment with all services."""
    # Start test containers
    import docker
    client = docker.from_env()
    
    # Start core services
    core = client.containers.run(
        "vivified/core:test",
        detach=True,
        network="test-network",
        environment={
            "TEST_MODE": "true",
            "JWT_SECRET": "test-secret"
        }
    )
    
    # Start test plugins
    email_plugin = client.containers.run(
        "vivified/email-gateway:test",
        detach=True,
        network="test-network"
    )
    
    user_plugin = client.containers.run(
        "vivified/user-management:test",
        detach=True,
        network="test-network"
    )
    
    # Wait for services to be ready
    await wait_for_health("http://localhost:8443/health")
    
    yield {
        "core_url": "http://localhost:8443",
        "containers": [core, email_plugin, user_plugin]
    }
    
    # Cleanup
    for container in [core, email_plugin, user_plugin]:
        container.stop()
        container.remove()

class TestEndToEndWorkflow:
    """Integration tests for complete workflows."""
    
    @pytest.mark.asyncio
    async def test_user_onboarding_workflow(self, test_environment):
        """Test complete user onboarding workflow."""
        base_url = test_environment["core_url"]
        
        async with httpx.AsyncClient(verify=False) as client:
            # Step 1: Admin login
            login_response = await client.post(
                f"{base_url}/auth/login",
                json={
                    "username": "admin",
                    "password": "admin123",
                    "mfa_token": "123456"
                }
            )
            assert login_response.status_code == 200
            token = login_response.json()["token"]
            
            headers = {"Authorization": f"Bearer {token}"}
            
            # Step 2: Create new user
            create_user_response = await client.post(
                f"{base_url}/admin/users",
                headers=headers,
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "SecureP@ss123",
                    "roles": ["phi_handler"]
                }
            )
            assert create_user_response.status_code == 200
            user_id = create_user_response.json()["id"]
            
            # Step 3: Wait for UserCreated event to trigger email
            await asyncio.sleep(2)
            
            # Step 4: Verify email plugin received event
            email_status = await client.get(
                f"{base_url}/admin/plugins/email-gateway/status",
                headers=headers
            )
            assert email_status.status_code == 200
            assert email_status.json()["last_event"] == "UserCreated"
            
            # Step 5: Verify audit log
            audit_response = await client.get(
                f"{base_url}/admin/audit?event_type=user_created",
                headers=headers
            )
            assert audit_response.status_code == 200
            assert len(audit_response.json()["entries"]) > 0
    
    @pytest.mark.asyncio
    async def test_phi_access_workflow(self, test_environment):
        """Test PHI access with proper authorization."""
        base_url = test_environment["core_url"]
        
        async with httpx.AsyncClient(verify=False) as client:
            # Login as PHI handler
            login_response = await client.post(
                f"{base_url}/auth/login",
                json={
                    "username": "doctor",
                    "password": "doctor123",
                    "mfa_token": "654321"
                }
            )
            token = login_response.json()["token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # Access patient record
            record_response = await client.get(
                f"{base_url}/api/patients/patient-123/records",
                headers=headers
            )
            assert record_response.status_code == 200
            
            # Verify audit trail
            audit_response = await client.get(
                f"{base_url}/admin/audit?event_type=phi_access",
                headers=headers
            )
            audit_entries = audit_response.json()["entries"]
            
            # Verify PHI access was logged
            phi_access_logged = any(
                entry["details"].get("patient_id") == "patient-123"
                for entry in audit_entries
            )
            assert phi_access_logged
```

### 3. Security Testing

#### 3.1 Security Test Suite
```python
# tests/security/test_security.py
import pytest
import httpx
import asyncio
from typing import List

class TestSecurityVulnerabilities:
    """Security vulnerability tests."""
    
    @pytest.mark.asyncio
    async def test_sql_injection(self, test_environment):
        """Test SQL injection prevention."""
        base_url = test_environment["core_url"]
        
        # Attempt SQL injection in various endpoints
        injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--"
        ]
        
        async with httpx.AsyncClient(verify=False) as client:
            for payload in injection_payloads:
                # Try login endpoint
                response = await client.post(
                    f"{base_url}/auth/login",
                    json={
                        "username": payload,
                        "password": "test"
                    }
                )
                
                # Should return 401, not 500 (SQL error)
                assert response.status_code == 401
                
                # Verify no sensitive data in response
                assert "sql" not in response.text.lower()
                assert "syntax" not in response.text.lower()
    
    @pytest.mark.asyncio
    async def test_xss_prevention(self, test_environment):
        """Test XSS attack prevention."""
        base_url = test_environment["core_url"]
        token = await get_test_token(base_url)
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>"
        ]
        
        async with httpx.AsyncClient(verify=False) as client:
            for payload in xss_payloads:
                # Try to inject in user creation
                response = await client.post(
                    f"{base_url}/admin/users",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "username": payload,
                        "email": "test@example.com",
                        "password": "Test123!"
                    }
                )
                
                # Should be rejected or sanitized
                if response.status_code == 200:
                    user = response.json()
                    # Verify payload was sanitized
                    assert "<script>" not in user.get("username", "")
    
    @pytest.mark.asyncio
    async def test_authentication_bypass(self, test_environment):
        """Test authentication bypass attempts."""
        base_url = test_environment["core_url"]
        
        async with httpx.AsyncClient(verify=False) as client:
            # Try accessing protected endpoint without token
            response = await client.get(f"{base_url}/admin/users")
            assert response.status_code == 401
            
            # Try with invalid token
            response = await client.get(
                f"{base_url}/admin/users",
                headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 401
            
            # Try with expired token
            expired_token = create_expired_jwt()
            response = await client.get(
                f"{base_url}/admin/users",
                headers={"Authorization": f"Bearer {expired_token}"}
            )
            assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_path_traversal(self, test_environment):
        """Test path traversal prevention."""
        base_url = test_environment["core_url"]
        token = await get_test_token(base_url)
        
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        async with httpx.AsyncClient(verify=False) as client:
            for payload in traversal_payloads:
                response = await client.get(
                    f"{base_url}/api/files/{payload}",
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                # Should return 400 or 404, not file contents
                assert response.status_code in [400, 404]
                assert "/etc/passwd" not in response.text
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, test_environment):
        """Test rate limiting protection."""
        base_url = test_environment["core_url"]
        
        async with httpx.AsyncClient(verify=False) as client:
            # Make rapid requests
            responses = []
            for _ in range(100):
                response = await client.post(
                    f"{base_url}/auth/login",
                    json={
                        "username": "test",
                        "password": "test"
                    }
                )
                responses.append(response.status_code)
            
            # Should see rate limiting (429) after threshold
            assert 429 in responses
    
    @pytest.mark.asyncio
    async def test_session_fixation(self, test_environment):
        """Test session fixation prevention."""
        base_url = test_environment["core_url"]
        
        async with httpx.AsyncClient(verify=False) as client:
            # Login as user1
            response1 = await client.post(
                f"{base_url}/auth/login",
                json={
                    "username": "user1",
                    "password": "password1"
                }
            )
            token1 = response1.json()["token"]
            
            # Login as user2
            response2 = await client.post(
                f"{base_url}/auth/login",
                json={
                    "username": "user2",
                    "password": "password2"
                }
            )
            token2 = response2.json()["token"]
            
            # Tokens should be different
            assert token1 != token2
            
            # User1's token shouldn't work for user2's resources
            response = await client.get(
                f"{base_url}/api/users/user2/profile",
                headers={"Authorization": f"Bearer {token1}"}
            )
            assert response.status_code == 403
```

### 4. Compliance Testing

#### 4.1 HIPAA Compliance Tests
```python
# tests/compliance/test_hipaa.py
import pytest
from datetime import datetime, timedelta

class TestHIPAACompliance:
    """HIPAA compliance verification tests."""
    
    @pytest.mark.asyncio
    async def test_access_control_164_312_a(self, test_environment):
        """Test Access Control (164.312(a))."""
        # Unique user identification
        users = await create_test_users(["doctor", "nurse", "admin"])
        for user in users:
            assert user["id"] is not None
            assert user["id"] != ""
        
        # Automatic logoff
        token = await login_user("doctor")
        await asyncio.sleep(1801)  # Wait 30 minutes + 1 second
        
        response = await make_authenticated_request(
            test_environment["core_url"],
            "/api/patients",
            token
        )
        assert response.status_code == 401  # Session expired
        
        # Encryption and decryption
        phi_data = {"patient_name": "John Doe", "ssn": "123-45-6789"}
        encrypted = await encrypt_phi(phi_data)
        assert encrypted != phi_data
        decrypted = await decrypt_phi(encrypted)
        assert decrypted == phi_data
    
    @pytest.mark.asyncio
    async def test_audit_controls_164_312_b(self, test_environment):
        """Test Audit Controls (164.312(b))."""
        base_url = test_environment["core_url"]
        
        # Perform PHI access
        token = await login_user("doctor")
        patient_id = "patient-123"
        
        await access_patient_record(base_url, token, patient_id)
        
        # Verify audit log created
        audit_logs = await get_audit_logs(base_url, token, event_type="phi_access")
        
        # Find our access
        our_access = [
            log for log in audit_logs 
            if log["patient_id"] == patient_id
        ]
        
        assert len(our_access) > 0
        audit_entry = our_access[0]
        
        # Verify required audit fields
        assert "timestamp" in audit_entry
        assert "user_id" in audit_entry
        assert "patient_id" in audit_entry
        assert "action" in audit_entry
        assert "outcome" in audit_entry
    
    @pytest.mark.asyncio
    async def test_integrity_controls_164_312_c(self, test_environment):
        """Test Integrity Controls (164.312(c))."""
        # Test data integrity verification
        record = {
            "patient_id": "123",
            "diagnosis": "Hypertension",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Calculate integrity hash
        hash1 = calculate_integrity_hash(record)
        
        # Verify tampering detection
        record["diagnosis"] = "Modified"
        hash2 = calculate_integrity_hash(record)
        
        assert hash1 != hash2
        
        # Verify audit log integrity
        audit_logs = await get_audit_logs(test_environment["core_url"])
        for log in audit_logs:
            assert verify_audit_integrity(log)
    
    @pytest.mark.asyncio
    async def test_transmission_security_164_312_d(self, test_environment):
        """Test Transmission Security (164.312(d))."""
        import ssl
        
        base_url = test_environment["core_url"]
        
        # Test TLS is enforced
        async with httpx.AsyncClient(verify=False) as client:
            # Try HTTP (should fail or redirect)
            with pytest.raises((httpx.ConnectError, httpx.HTTPStatusError)):
                await client.get(base_url.replace("https", "http"))
        
        # Verify TLS version
        context = ssl.create_default_context()
        with socket.create_connection(("localhost", 8443)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                # Should be TLS 1.2 or higher
                assert ssock.version() in ["TLSv1.2", "TLSv1.3"]
    
    @pytest.mark.asyncio
    async def test_encryption_164_312_e(self, test_environment):
        """Test Encryption and Decryption (164.312(e))."""
        # Test data at rest encryption
        phi_data = {
            "patient_name": "Jane Doe",
            "medical_record_number": "MRN123456",
            "diagnosis_code": "I10"
        }
        
        # Store PHI
        record_id = await store_phi_record(test_environment["core_url"], phi_data)
        
        # Verify data is encrypted in database
        raw_data = await get_raw_database_record(record_id)
        
        # Raw data should not contain plaintext PHI
        assert "Jane Doe" not in str(raw_data)
        assert "MRN123456" not in str(raw_data)
        
        # Verify authorized retrieval returns decrypted data
        retrieved = await retrieve_phi_record(test_environment["core_url"], record_id)
        assert retrieved["patient_name"] == "Jane Doe"
    
    @pytest.mark.asyncio
    async def test_retention_policy(self, test_environment):
        """Test 7-year retention policy for audit logs."""
        # Create old audit log (simulated)
        old_date = datetime.utcnow() - timedelta(days=2556)  # >7 years
        old_log = create_audit_log(date=old_date)
        
        # Create recent audit log
        recent_log = create_audit_log(date=datetime.utcnow())
        
        # Run retention cleanup
        await trigger_retention_cleanup(test_environment["core_url"])
        
        # Verify old log archived, recent log retained
        logs = await get_all_audit_logs(test_environment["core_url"])
        
        assert recent_log["id"] in [log["id"] for log in logs]
        assert old_log["id"] not in [log["id"] for log in logs]
        
        # Verify archived logs still accessible for compliance
        archived = await get_archived_audit_logs(test_environment["core_url"])
        assert old_log["id"] in [log["id"] for log in archived]
```

### 5. Performance Testing

#### 5.1 Load Testing
```python
# tests/performance/test_load.py
import pytest
import asyncio
import aiohttp
import time
from statistics import mean, median, stdev

class TestPerformance:
    """Performance and load tests."""
    
    @pytest.mark.asyncio
    async def test_rpc_latency_slo(self, test_environment):
        """Test RPC latency meets SLO (<5ms p50, <50ms p99)."""
        base_url = test_environment["core_url"]
        token = await get_test_token(base_url)
        
        latencies = []
        
        # Make 1000 RPC calls
        async with aiohttp.ClientSession() as session:
            for _ in range(1000):
                start = time.perf_counter()
                
                async with session.post(
                    f"{base_url}/gateway/user-management/get_user",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"user_id": "test-user"}
                ) as response:
                    await response.json()
                
                latency = (time.perf_counter() - start) * 1000  # ms
                latencies.append(latency)
        
        # Calculate percentiles
        latencies.sort()
        p50 = latencies[500]
        p99 = latencies[990]
        
        # Verify SLOs
        assert p50 < 5, f"P50 latency {p50}ms exceeds 5ms SLO"
        assert p99 < 50, f"P99 latency {p99}ms exceeds 50ms SLO"
    
    @pytest.mark.asyncio
    async def test_event_processing_throughput(self, test_environment):
        """Test event processing throughput (>1000 events/sec)."""
        base_url = test_environment["core_url"]
        token = await get_test_token(base_url)
        
        events_sent = 0
        start_time = time.time()
        
        # Send events for 10 seconds
        async with aiohttp.ClientSession() as session:
            while time.time() - start_time < 10:
                tasks = []
                
                # Send batch of 100 events
                for i in range(100):
                    task = session.post(
                        f"{base_url}/events/publish",
                        headers={"Authorization": f"Bearer {token}"},
                        json={
                            "event_type": "TestEvent",
                            "payload": {"id": i},
                            "source_plugin": "test-plugin"
                        }
                    )
                    tasks.append(task)
                
                # Wait for batch
                responses = await asyncio.gather(*tasks)
                events_sent += sum(1 for r in responses if r.status == 200)
        
        # Calculate throughput
        duration = time.time() - start_time
        throughput = events_sent / duration
        
        assert throughput > 1000, f"Throughput {throughput}/sec below 1000/sec SLO"
    
    @pytest.mark.asyncio
    async def test_concurrent_users(self, test_environment):
        """Test system handles 100+ concurrent users."""
        base_url = test_environment["core_url"]
        
        async def simulate_user(user_id: int):
            """Simulate a user session."""
            # Login
            token = await login_user(f"user{user_id}")
            
            # Perform operations
            for _ in range(10):
                await make_authenticated_request(
                    base_url,
                    f"/api/users/user{user_id}/profile",
                    token
                )
                await asyncio.sleep(0.1)
            
            return True
        
        # Simulate 100 concurrent users
        tasks = [simulate_user(i) for i in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check success rate
        successes = sum(1 for r in results if r is True)
        success_rate = successes / len(results)
        
        assert success_rate > 0.95, f"Success rate {success_rate} below 95%"
    
    @pytest.mark.asyncio
    async def test_memory_usage(self, test_environment):
        """Test memory usage remains stable under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate load
        for _ in range(10000):
            await make_test_request(test_environment["core_url"])
        
        # Check memory after load
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory should not increase by more than 100MB
        assert memory_increase < 100, f"Memory increased by {memory_increase}MB"
```

### 6. Chaos Testing

#### 6.1 Chaos Engineering Tests
```python
# tests/chaos/test_resilience.py
import pytest
import docker
import random
import asyncio

class TestChaosEngineering:
    """Chaos engineering tests for resilience."""
    
    @pytest.mark.asyncio
    async def test_plugin_failure_isolation(self, test_environment):
        """Test that plugin failure doesn't affect core."""
        client = docker.from_env()
        
        # Kill a plugin container
        plugin_container = client.containers.get("email-gateway")
        plugin_container.kill()
        
        # Core should remain healthy
        core_health = await check_core_health(test_environment["core_url"])
        assert core_health["status"] == "healthy"
        
        # Other plugins should continue working
        user_plugin_status = await check_plugin_status(
            test_environment["core_url"],
            "user-management"
        )
        assert user_plugin_status["status"] == "healthy"
        
        # Restart killed plugin
        plugin_container.start()
    
    @pytest.mark.asyncio
    async def test_network_partition(self, test_environment):
        """Test behavior during network partition."""
        # Simulate network partition
        await simulate_network_partition("core", "nats", duration=30)
        
        # System should handle gracefully
        # Events should queue
        events_queued = await check_event_queue_status(
            test_environment["core_url"]
        )
        assert events_queued["queued"] > 0
        
        # After partition heals, events should process
        await asyncio.sleep(35)
        events_processed = await check_event_queue_status(
            test_environment["core_url"]
        )
        assert events_processed["queued"] == 0
    
    @pytest.mark.asyncio
    async def test_database_failure_recovery(self, test_environment):
        """Test database failure and recovery."""
        client = docker.from_env()
        
        # Stop database
        db_container = client.containers.get("postgres")
        db_container.stop()
        
        # System should enter degraded mode
        await asyncio.sleep(5)
        system_status = await check_system_status(test_environment["core_url"])
        assert system_status["mode"] == "degraded"
        assert system_status["database"] == "unavailable"
        
        # Critical functions should still work (from cache)
        auth_works = await test_cached_authentication(test_environment["core_url"])
        assert auth_works
        
        # Restart database
        db_container.start()
        await asyncio.sleep(10)
        
        # System should recover
        system_status = await check_system_status(test_environment["core_url"])
        assert system_status["mode"] == "normal"
        assert system_status["database"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_cpu_stress(self, test_environment):
        """Test system under CPU stress."""
        # Apply CPU stress to core container
        await apply_cpu_stress("vivified-core", cpu_percent=90, duration=60)
        
        # System should remain responsive (with degraded performance)
        response_times = []
        for _ in range(10):
            start = time.time()
            await make_health_check(test_environment["core_url"])
            response_times.append(time.time() - start)
        
        # Average response time should be under 5 seconds
        avg_response = mean(response_times)
        assert avg_response < 5, f"Response time {avg_response}s during CPU stress"
    
    @pytest.mark.asyncio
    async def test_memory_pressure(self, test_environment):
        """Test system under memory pressure."""
        # Apply memory pressure
        await apply_memory_pressure("vivified-core", memory_mb=400)
        
        # System should handle gracefully
        # Check for OOM kills
        container_stats = await get_container_stats("vivified-core")
        assert container_stats["oom_killed"] is False
        
        # Verify system still functional
        health = await check_core_health(test_environment["core_url"])
        assert health["status"] == "healthy"
```

## Test Automation Framework

### CI/CD Pipeline Configuration
```yaml
# .github/workflows/test-pipeline.yml
name: Comprehensive Test Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11]
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-asyncio
      - name: Run unit tests
        run: |
          pytest tests/unit/ --cov=core --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: true

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Set up Docker
        uses: docker/setup-buildx-action@v2
      - name: Start test environment
        run: |
          docker-compose -f docker-compose.test.yml up -d
          ./scripts/wait-for-healthy.sh
      - name: Run integration tests
        run: |
          pytest tests/integration/ -v
      - name: Collect logs
        if: failure()
        run: |
          docker-compose -f docker-compose.test.yml logs > integration-test-logs.txt
      - name: Upload logs
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: integration-test-logs
          path: integration-test-logs.txt

  security-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Run security scans
        run: |
          pip install safety bandit
          safety check
          bandit -r core/
      - name: Run OWASP dependency check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'vivified'
          path: '.'
          format: 'HTML'
      - name: Run container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'vivified/core:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
      - name: Upload security results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  compliance-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    steps:
      - uses: actions/checkout@v3
      - name: Start compliance test environment
        run: |
          docker-compose -f docker-compose.compliance.yml up -d
      - name: Run HIPAA compliance tests
        run: |
          pytest tests/compliance/ -v --tb=short
      - name: Generate compliance report
        run: |
          python scripts/generate_compliance_report.py > compliance-report.html
      - name: Upload compliance report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.html

  performance-tests:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    steps:
      - uses: actions/checkout@v3
      - name: Start performance test environment
        run: |
          docker-compose -f docker-compose.perf.yml up -d
      - name: Run load tests
        run: |
          pip install locust
          locust -f tests/performance/locustfile.py --headless \
            --users 100 --spawn-rate 10 --run-time 5m \
            --host http://localhost:8443
      - name: Analyze results
        run: |
          python scripts/analyze_performance.py locust_stats.csv
      - name: Upload performance results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: performance-report.html

  chaos-tests:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      - name: Install chaos tools
        run: |
          pip install chaostoolkit chaostoolkit-kubernetes
      - name: Run chaos experiments
        run: |
          chaos run experiments/plugin-failure.json
          chaos run experiments/network-partition.json
      - name: Generate chaos report
        run: |
          chaos report --export-format=html journal.json report.html
      - name: Upload chaos results
        uses: actions/upload-artifact@v3
        with:
          name: chaos-report
          path: report.html
```

## Testing Checklist

### Unit Testing
- [ ] All functions have unit tests
- [ ] Edge cases covered
- [ ] Error conditions tested
- [ ] Mocking used appropriately
- [ ] Code coverage >80%
- [ ] No flaky tests

### Integration Testing
- [ ] End-to-end workflows tested
- [ ] Service interactions verified
- [ ] Database operations tested
- [ ] Message passing validated
- [ ] API contracts verified

### Security Testing
- [ ] OWASP Top 10 covered
- [ ] Authentication tested
- [ ] Authorization verified
- [ ] Input validation tested
- [ ] Encryption validated
- [ ] Session management tested

### Compliance Testing
- [ ] All HIPAA controls verified
- [ ] Audit trail complete
- [ ] Retention policies tested
- [ ] Access controls validated
- [ ] Encryption verified
- [ ] Breach procedures tested

### Performance Testing
- [ ] Load tests passing SLOs
- [ ] Stress tests completed
- [ ] Memory leaks checked
- [ ] Database performance verified
- [ ] Network latency tested
- [ ] Scalability validated

### Chaos Testing
- [ ] Component failures tested
- [ ] Network partitions simulated
- [ ] Resource exhaustion tested
- [ ] Recovery procedures verified
- [ ] Data integrity maintained
- [ ] No cascading failures

## Next Steps
Proceed to Runbook 09 for Deployment & Operations procedures.