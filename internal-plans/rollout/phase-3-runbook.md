# Runbook 03: Phase 3 - Inter-Plugin Communication

## Objective
Implement the three communication lanes (Event Bus, RPC Gateway, Proxy Service), integrate policy engine enforcement, and demonstrate complex workflows across plugins.

## Prerequisites
- Phase 2 completed (Identity, Policy, Config services operational)
- NATS JetStream running
- Plugin authentication working
- Policy engine configured

## Tasks

### 1. Event Bus Integration (Canonical Lane)

#### 1.1 NATS JetStream Configuration
```yaml
# nats-config.conf
jetstream {
  store_dir: "/data/jetstream"
  max_memory_store: 1GB
  max_file_store: 10GB
}

# Security configuration
authorization {
  users = [
    {
      user: core
      password: $CORE_NATS_PASSWORD
      permissions: {
        publish: ">"
        subscribe: ">"
      }
    }
    {
      user: plugin
      password: $PLUGIN_NATS_PASSWORD
      permissions: {
        publish: ["events.>", "heartbeat.>"]
        subscribe: ["events.canonical.>", "commands.$PLUGIN_ID.>"]
      }
    }
  ]
}

# Monitoring
http_port: 8222
```

#### 1.2 Core Event Bus Service
```python
# core/messaging/event_bus.py
import asyncio
import nats
from nats.js import JetStreamContext
import json
from typing import Dict, List, Callable, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

class EventBus:
    """Manages canonical event publishing and subscription with policy enforcement."""
    
    def __init__(self, policy_engine, audit_service):
        self.nc = None
        self.js = None
        self.policy = policy_engine
        self.audit = audit_service
        self.subscriptions = {}
        self.event_handlers = {}
        self.event_metrics = {
            "published": 0,
            "delivered": 0,
            "blocked": 0,
            "errors": 0
        }
    
    async def connect(self, servers: List[str], credentials: Dict):
        """Connect to NATS with authentication."""
        try:
            self.nc = await nats.connect(
                servers=servers,
                user=credentials.get("user"),
                password=credentials.get("password"),
                reconnect_time_wait=2,
                max_reconnect_attempts=60,
                error_cb=self._error_callback,
                disconnected_cb=self._disconnected_callback,
                reconnected_cb=self._reconnected_callback
            )
            
            # Initialize JetStream
            self.js = self.nc.jetstream()
            
            # Create streams for canonical events
            await self._setup_streams()
            
            # Subscribe to all events for monitoring
            await self._setup_monitoring_subscription()
            
            logger.info("Connected to NATS event bus")
            
        except Exception as e:
            logger.error(f"Failed to connect to NATS: {e}")
            raise
    
    async def _setup_streams(self):
        """Set up JetStream streams for event persistence."""
        # Create canonical events stream
        try:
            await self.js.add_stream(
                name="CANONICAL_EVENTS",
                subjects=["events.canonical.>"],
                retention="limits",
                max_msgs=1000000,
                max_age=86400 * 7,  # 7 days
                storage="file",
                replicas=1,
                discard="old"
            )
            
            # Create audit stream for compliance
            await self.js.add_stream(
                name="AUDIT_EVENTS",
                subjects=["audit.>"],
                retention="limits",
                max_msgs=10000000,
                max_age=86400 * 365 * 7,  # 7 years for HIPAA
                storage="file",
                replicas=1,
                discard="old"
            )
            
            logger.info("JetStream streams configured")
            
        except Exception as e:
            logger.warning(f"Streams may already exist: {e}")
    
    async def publish_event(
        self,
        event_type: str,
        payload: Dict,
        source_plugin: str,
        data_traits: List[str] = None,
        trace_id: Optional[str] = None
    ) -> str:
        """Publish a canonical event with policy enforcement."""
        event_id = str(uuid.uuid4())
        trace_id = trace_id or str(uuid.uuid4())
        
        # Build canonical event
        event = {
            "event_id": event_id,
            "trace_id": trace_id,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "source_plugin": source_plugin,
            "data_traits": data_traits or [],
            "payload": payload
        }
        
        # Check if source is authorized to publish this type
        source_info = await self._get_plugin_info(source_plugin)
        if not self._can_publish_event(source_info, event_type, data_traits):
            logger.warning(f"Plugin {source_plugin} not authorized to publish {event_type}")
            self.event_metrics["blocked"] += 1
            await self._audit_event_blocked(event, "unauthorized_publisher")
            return None
        
        # Sanitize payload based on traits
        sanitized_payload = await self._sanitize_payload(payload, data_traits)
        event["payload"] = sanitized_payload
        
        # Publish to NATS
        subject = f"events.canonical.{event_type.lower()}"
        try:
            ack = await self.js.publish(
                subject,
                json.dumps(event).encode(),
                headers={
                    "trace_id": trace_id,
                    "source": source_plugin,
                    "event_id": event_id
                }
            )
            
            self.event_metrics["published"] += 1
            
            # Audit successful publish
            await self._audit_event_published(event)
            
            logger.info(f"Event published: {event_type} from {source_plugin}", extra={
                "trace_id": trace_id,
                "event_id": event_id
            })
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            self.event_metrics["errors"] += 1
            raise
    
    async def subscribe_to_events(
        self,
        plugin_id: str,
        event_types: List[str],
        handler: Callable,
        traits: List[str] = None
    ):
        """Subscribe a plugin to specific event types with policy check."""
        plugin_info = await self._get_plugin_info(plugin_id)
        plugin_traits = plugin_info.get("traits", [])
        
        for event_type in event_types:
            # Check if plugin is authorized to receive this event type
            if not self._can_receive_event(plugin_traits, event_type):
                logger.warning(f"Plugin {plugin_id} not authorized for {event_type}")
                continue
            
            subject = f"events.canonical.{event_type.lower()}"
            
            # Create filtered handler that enforces policy
            async def filtered_handler(msg):
                try:
                    event = json.loads(msg.data.decode())
                    
                    # Check data traits against plugin traits
                    event_traits = event.get("data_traits", [])
                    decision, reason = self.policy.evaluate_data_access(
                        plugin_traits,
                        event_traits
                    )
                    
                    if decision == "deny":
                        logger.warning(f"Event blocked for {plugin_id}: {reason}")
                        self.event_metrics["blocked"] += 1
                        await self._audit_event_blocked(event, reason, plugin_id)
                        return
                    
                    if decision == "sanitize":
                        event["payload"] = await self._sanitize_for_plugin(
                            event["payload"],
                            event_traits,
                            plugin_traits
                        )
                    
                    # Deliver to plugin handler
                    await handler(event)
                    self.event_metrics["delivered"] += 1
                    
                except Exception as e:
                    logger.error(f"Error in event handler for {plugin_id}: {e}")
                    self.event_metrics["errors"] += 1
            
            # Subscribe with queue group for load balancing
            sub = await self.nc.subscribe(
                subject,
                queue=f"plugin.{plugin_id}",
                cb=filtered_handler
            )
            
            # Track subscription
            if plugin_id not in self.subscriptions:
                self.subscriptions[plugin_id] = []
            self.subscriptions[plugin_id].append(sub)
            
            logger.info(f"Plugin {plugin_id} subscribed to {event_type}")
    
    async def _setup_monitoring_subscription(self):
        """Subscribe to all events for monitoring and compliance."""
        async def monitor_handler(msg):
            try:
                event = json.loads(msg.data.decode())
                
                # Log for compliance
                await self.audit.log_event(
                    event_type="canonical_event",
                    details=event,
                    trace_id=event.get("trace_id")
                )
                
                # Update metrics
                self._update_event_metrics(event)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
        
        await self.nc.subscribe("events.>", cb=monitor_handler)
    
    def _can_publish_event(
        self,
        plugin_info: Dict,
        event_type: str,
        data_traits: List[str]
    ) -> bool:
        """Check if plugin can publish event type with data traits."""
        plugin_traits = plugin_info.get("traits", [])
        
        # PHI events require handles_phi trait
        if data_traits and "phi" in data_traits:
            if "handles_phi" not in plugin_traits:
                return False
        
        # PII events require handles_pii trait
        if data_traits and "pii" in data_traits:
            if "handles_pii" not in plugin_traits:
                return False
        
        return True
    
    def _can_receive_event(self, plugin_traits: List[str], event_type: str) -> bool:
        """Check if plugin can receive event type."""
        # Define event type requirements
        protected_events = {
            "UserCreated": ["handles_pii"],
            "PatientDataUpdated": ["handles_phi"],
            "PaymentProcessed": ["handles_pii", "handles_financial"]
        }
        
        required_traits = protected_events.get(event_type, [])
        return all(trait in plugin_traits for trait in required_traits)
    
    async def _sanitize_payload(
        self,
        payload: Dict,
        data_traits: List[str]
    ) -> Dict:
        """Sanitize payload based on data traits."""
        if not data_traits:
            return payload
        
        sanitized = payload.copy()
        
        if "phi" in data_traits:
            # Remove direct identifiers
            for field in ["ssn", "medical_record_number", "insurance_id"]:
                if field in sanitized:
                    sanitized[field] = "REDACTED"
        
        if "pii" in data_traits:
            # Mask PII fields
            for field in ["email", "phone", "address"]:
                if field in sanitized:
                    sanitized[field] = self._mask_field(sanitized[field])
        
        return sanitized
    
    def _mask_field(self, value: str) -> str:
        """Mask sensitive field value."""
        if not value:
            return value
        
        if "@" in value:  # Email
            parts = value.split("@")
            return f"{parts[0][:2]}***@{parts[1]}"
        elif len(value) > 4:  # General string
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        else:
            return "*" * len(value)
```

### 2. RPC Gateway Implementation (Operator Lane)

#### 2.1 RPC Gateway Service
```python
# core/gateway/rpc_gateway.py
import httpx
from typing import Dict, Any, Optional
import json
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class RPCGateway:
    """Handles synchronous plugin-to-plugin calls with policy enforcement."""
    
    def __init__(self, registry, policy_engine, audit_service):
        self.registry = registry
        self.policy = policy_engine
        self.audit = audit_service
        self.call_metrics = {
            "total_calls": 0,
            "successful_calls": 0,
            "blocked_calls": 0,
            "failed_calls": 0,
            "total_latency": 0
        }
        self.circuit_breakers = {}
    
    async def invoke_plugin(
        self,
        caller_plugin: str,
        target_plugin: str,
        action: str,
        payload: Dict,
        caller_token: str,
        trace_id: Optional[str] = None
    ) -> Dict:
        """Route RPC call from one plugin to another with security checks."""
        start_time = datetime.utcnow()
        trace_id = trace_id or str(uuid.uuid4())
        
        self.call_metrics["total_calls"] += 1
        
        # Authenticate caller
        caller_info = await self._authenticate_plugin(caller_token)
        if not caller_info or caller_info["id"] != caller_plugin:
            await self._audit_rpc_blocked(
                caller_plugin, target_plugin, action, "authentication_failed"
            )
            self.call_metrics["blocked_calls"] += 1
            raise HTTPException(status_code=401, detail="Authentication failed")
        
        # Get target plugin info
        target_info = self.registry.get_plugin(target_plugin)
        if not target_info:
            raise HTTPException(status_code=404, detail="Target plugin not found")
        
        # Check if target is healthy
        if not await self._is_plugin_healthy(target_plugin):
            raise HTTPException(status_code=503, detail="Target plugin unhealthy")
        
        # Evaluate policy
        decision, reason = self.policy.evaluate_plugin_interaction(
            caller_info,
            target_info,
            {"action": action, "payload": payload}
        )
        
        if decision == "deny":
            await self._audit_rpc_blocked(
                caller_plugin, target_plugin, action, reason
            )
            self.call_metrics["blocked_calls"] += 1
            raise HTTPException(status_code=403, detail=f"Access denied: {reason}")
        
        # Sanitize payload if needed
        if decision == "sanitize":
            payload = await self._sanitize_rpc_payload(
                payload,
                caller_info.get("traits", []),
                target_info.get("traits", [])
            )
        
        # Get target endpoint
        endpoint = self._get_plugin_endpoint(target_info, action)
        if not endpoint:
            raise HTTPException(status_code=404, detail=f"Action {action} not found")
        
        # Check circuit breaker
        if self._is_circuit_open(target_plugin):
            raise HTTPException(status_code=503, detail="Circuit breaker open")
        
        # Make the call
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    endpoint,
                    json=payload,
                    headers={
                        "X-Caller-Plugin": caller_plugin,
                        "X-Trace-Id": trace_id,
                        "Authorization": f"Bearer {await self._get_inter_plugin_token()}"
                    }
                )
                
                if response.status_code >= 500:
                    self._record_circuit_breaker_failure(target_plugin)
                    self.call_metrics["failed_calls"] += 1
                    raise HTTPException(
                        status_code=502,
                        detail="Target plugin error"
                    )
                
                result = response.json()
                
                # Apply response filtering if needed
                if decision == "sanitize":
                    result = await self._sanitize_rpc_response(
                        result,
                        target_info.get("traits", []),
                        caller_info.get("traits", [])
                    )
                
                # Record success
                self._record_circuit_breaker_success(target_plugin)
                self.call_metrics["successful_calls"] += 1
                
                # Audit successful call
                latency = (datetime.utcnow() - start_time).total_seconds()
                self.call_metrics["total_latency"] += latency
                
                await self._audit_rpc_success(
                    caller_plugin, target_plugin, action, latency, trace_id
                )
                
                return result
                
        except httpx.TimeoutException:
            self._record_circuit_breaker_failure(target_plugin)
            self.call_metrics["failed_calls"] += 1
            raise HTTPException(status_code=504, detail="Target plugin timeout")
            
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            self.call_metrics["failed_calls"] += 1
            raise HTTPException(status_code=500, detail="Internal gateway error")
    
    def _get_plugin_endpoint(self, plugin_info: Dict, action: str) -> Optional[str]:
        """Get the endpoint URL for a plugin action."""
        endpoints = plugin_info.get("manifest", {}).get("endpoints", {})
        
        # Map action to endpoint
        action_map = {
            "get_user": "/api/users/{id}",
            "send_message": "/api/messages/send",
            "store_file": "/api/storage/store",
            # Add more mappings as needed
        }
        
        endpoint_path = endpoints.get(action) or action_map.get(action)
        if not endpoint_path:
            return None
        
        # Construct full URL
        plugin_host = plugin_info.get("host", plugin_info["id"])
        plugin_port = plugin_info.get("port", 8080)
        
        return f"http://{plugin_host}:{plugin_port}{endpoint_path}"
    
    def _is_circuit_open(self, plugin_id: str) -> bool:
        """Check if circuit breaker is open for a plugin."""
        breaker = self.circuit_breakers.get(plugin_id, {})
        
        if breaker.get("state") == "open":
            # Check if we should attempt half-open
            last_failure = breaker.get("last_failure")
            if last_failure:
                time_since_failure = (datetime.utcnow() - last_failure).seconds
                if time_since_failure > 60:  # 60 second timeout
                    self.circuit_breakers[plugin_id]["state"] = "half_open"
                    return False
            return True
        
        return False
    
    def _record_circuit_breaker_failure(self, plugin_id: str):
        """Record a failure for circuit breaker."""
        if plugin_id not in self.circuit_breakers:
            self.circuit_breakers[plugin_id] = {
                "failures": 0,
                "state": "closed"
            }
        
        breaker = self.circuit_breakers[plugin_id]
        breaker["failures"] += 1
        breaker["last_failure"] = datetime.utcnow()
        
        # Open circuit after 5 consecutive failures
        if breaker["failures"] >= 5:
            breaker["state"] = "open"
            logger.warning(f"Circuit breaker opened for {plugin_id}")
    
    def _record_circuit_breaker_success(self, plugin_id: str):
        """Record a success for circuit breaker."""
        if plugin_id in self.circuit_breakers:
            self.circuit_breakers[plugin_id]["failures"] = 0
            self.circuit_breakers[plugin_id]["state"] = "closed"
    
    async def _sanitize_rpc_payload(
        self,
        payload: Dict,
        caller_traits: List[str],
        target_traits: List[str]
    ) -> Dict:
        """Sanitize RPC payload based on trait differences."""
        sanitized = payload.copy()
        
        # If target doesn't handle PHI but data contains it
        if "handles_phi" not in target_traits:
            for field in ["diagnosis", "treatment", "medical_history"]:
                if field in sanitized:
                    del sanitized[field]
        
        # If target doesn't handle PII but data contains it
        if "handles_pii" not in target_traits:
            for field in ["ssn", "email", "phone", "address"]:
                if field in sanitized:
                    sanitized[field] = "REDACTED"
        
        return sanitized
```

### 3. Proxy Service (Guarded Lane)

#### 3.1 Proxy Service Implementation
```python
# core/gateway/proxy_service.py
import httpx
from urllib.parse import urlparse
import asyncio
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ProxyService:
    """Controlled proxy for external API calls with strict security."""
    
    def __init__(self, registry, audit_service, config_service):
        self.registry = registry
        self.audit = audit_service
        self.config = config_service
        self.rate_limits = {}  # Per-plugin rate limiting
        self.request_cache = {}  # Cache for responses
    
    async def proxy_request(
        self,
        plugin_id: str,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        body: Optional[Dict] = None,
        plugin_token: str = None,
        trace_id: Optional[str] = None
    ) -> Dict:
        """Proxy an external request with security controls."""
        trace_id = trace_id or str(uuid.uuid4())
        
        # Authenticate plugin
        plugin_info = await self._authenticate_plugin(plugin_token)
        if not plugin_info or plugin_info["id"] != plugin_id:
            await self._audit_proxy_blocked(plugin_id, url, "authentication_failed")
            raise HTTPException(status_code=401, detail="Authentication failed")
        
        # Parse and validate URL
        parsed = urlparse(url)
        domain = parsed.hostname
        
        # Check domain allowlist
        if not await self._is_domain_allowed(plugin_id, domain):
            await self._audit_proxy_blocked(plugin_id, url, "domain_not_allowed")
            raise HTTPException(status_code=403, detail=f"Domain {domain} not allowed")
        
        # Check for internal network access attempts
        if self._is_internal_address(domain):
            await self._audit_proxy_blocked(plugin_id, url, "internal_address")
            raise HTTPException(status_code=403, detail="Internal addresses not allowed")
        
        # Apply rate limiting
        if not await self._check_rate_limit(plugin_id):
            await self._audit_proxy_blocked(plugin_id, url, "rate_limit_exceeded")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Check cache for GET requests
        if method == "GET":
            cached = self._get_cached_response(plugin_id, url)
            if cached:
                logger.info(f"Returning cached response for {url}")
                return cached
        
        # Sanitize headers
        safe_headers = self._sanitize_headers(headers or {})
        
        # Add security headers
        safe_headers.update({
            "X-Forwarded-For": "vivified-proxy",
            "X-Proxy-Plugin": plugin_id,
            "User-Agent": "Vivified-Platform/1.0"
        })
        
        # Make the request
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=False,
                max_redirects=0
            ) as client:
                
                # Build request based on method
                if method == "GET":
                    response = await client.get(url, headers=safe_headers)
                elif method == "POST":
                    response = await client.post(url, json=body, headers=safe_headers)
                elif method == "PUT":
                    response = await client.put(url, json=body, headers=safe_headers)
                elif method == "DELETE":
                    response = await client.delete(url, headers=safe_headers)
                else:
                    raise HTTPException(status_code=405, detail="Method not allowed")
                
                # Check response
                if response.status_code >= 400:
                    logger.warning(f"Proxy request failed: {response.status_code}")
                    await self._audit_proxy_failure(plugin_id, url, response.status_code)
                    raise HTTPException(
                        status_code=502,
                        detail=f"External service error: {response.status_code}"
                    )
                
                # Filter response
                filtered_response = self._filter_response(response)
                
                # Cache successful GET responses
                if method == "GET" and response.status_code == 200:
                    self._cache_response(plugin_id, url, filtered_response)
                
                # Audit successful request
                await self._audit_proxy_success(plugin_id, url, method, trace_id)
                
                return filtered_response
                
        except httpx.TimeoutException:
            await self._audit_proxy_failure(plugin_id, url, "timeout")
            raise HTTPException(status_code=504, detail="External service timeout")
            
        except httpx.RequestError as e:
            logger.error(f"Proxy request error: {e}")
            await self._audit_proxy_failure(plugin_id, url, str(e))
            raise HTTPException(status_code=502, detail="External service error")
    
    async def _is_domain_allowed(self, plugin_id: str, domain: str) -> bool:
        """Check if domain is in plugin's allowlist."""
        plugin_info = self.registry.get_plugin(plugin_id)
        if not plugin_info:
            return False
        
        allowed_domains = plugin_info.get("manifest", {}).get("allowed_domains", [])
        
        # Check exact match and wildcard
        for allowed in allowed_domains:
            if allowed.startswith("*."):
                # Wildcard subdomain
                if domain.endswith(allowed[2:]) or domain == allowed[2:]:
                    return True
            elif domain == allowed:
                return True
        
        return False
    
    def _is_internal_address(self, domain: str) -> bool:
        """Check if address is internal/private."""
        if not domain:
            return True
        
        # Check for localhost variants
        if domain in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
            return True
        
        # Check for private IP ranges
        private_prefixes = [
            "10.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
            "169.254.",  # Link-local
            "fc00:", "fd00:",  # IPv6 private
        ]
        
        for prefix in private_prefixes:
            if domain.startswith(prefix):
                return True
        
        # Check for Docker internal DNS
        if domain.endswith(".local") or domain.endswith(".internal"):
            return True
        
        return False
    
    async def _check_rate_limit(self, plugin_id: str) -> bool:
        """Check if plugin has exceeded rate limit."""
        now = datetime.utcnow()
        
        if plugin_id not in self.rate_limits:
            self.rate_limits[plugin_id] = {
                "requests": [],
                "limit": 100,  # 100 requests per minute
                "window": 60  # seconds
            }
        
        limits = self.rate_limits[plugin_id]
        
        # Remove old requests outside window
        cutoff = now - timedelta(seconds=limits["window"])
        limits["requests"] = [
            req for req in limits["requests"] 
            if req > cutoff
        ]
        
        # Check if under limit
        if len(limits["requests"]) >= limits["limit"]:
            return False
        
        # Add current request
        limits["requests"].append(now)
        return True
    
    def _sanitize_headers(self, headers: Dict) -> Dict:
        """Remove dangerous headers from request."""
        dangerous_headers = [
            "cookie",
            "authorization",
            "x-api-key",
            "x-auth-token",
            "proxy-authorization",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-real-ip"
        ]
        
        safe_headers = {}
        for key, value in headers.items():
            if key.lower() not in dangerous_headers:
                safe_headers[key] = value
        
        return safe_headers
    
    def _filter_response(self, response: httpx.Response) -> Dict:
        """Filter response to remove sensitive data."""
        filtered = {
            "status_code": response.status_code,
            "headers": {},
            "body": None
        }
        
        # Filter headers
        safe_response_headers = [
            "content-type",
            "content-length",
            "cache-control",
            "etag",
            "last-modified"
        ]
        
        for header in safe_response_headers:
            if header in response.headers:
                filtered["headers"][header] = response.headers[header]
        
        # Parse body based on content type
        content_type = response.headers.get("content-type", "")
        
        if "application/json" in content_type:
            try:
                filtered["body"] = response.json()
            except:
                filtered["body"] = response.text
        elif "text/" in content_type:
            filtered["body"] = response.text[:10000]  # Limit size
        else:
            # Don't return binary data
            filtered["body"] = f"Binary data ({len(response.content)} bytes)"
        
        return filtered
```

### 4. Communication Integration & Workflow

#### 4.1 Plugin SDK Communication Module
```python
# sdk/python/vivified_sdk/communication.py
import asyncio
import httpx
import nats
from typing import Dict, Callable, Optional, List
import json
import logging

logger = logging.getLogger(__name__)

class VivifiedCommunication:
    """Communication module for Vivified plugins."""
    
    def __init__(self, plugin_id: str, plugin_token: str, core_url: str):
        self.plugin_id = plugin_id
        self.plugin_token = plugin_token
        self.core_url = core_url
        self.nc = None
        self.event_handlers = {}
        
    async def connect(self, nats_url: str):
        """Connect to the event bus."""
        self.nc = await nats.connect(nats_url)
        logger.info(f"Plugin {self.plugin_id} connected to event bus")
    
    async def publish_event(
        self,
        event_type: str,
        payload: Dict,
        data_traits: List[str] = None
    ) -> str:
        """Publish a canonical event."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.core_url}/events/publish",
                json={
                    "event_type": event_type,
                    "payload": payload,
                    "source_plugin": self.plugin_id,
                    "data_traits": data_traits or []
                },
                headers={"Authorization": f"Bearer {self.plugin_token}"}
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to publish event: {response.text}")
            
            return response.json()["event_id"]
    
    async def subscribe_to_events(
        self,
        event_types: List[str],
        handler: Callable
    ):
        """Subscribe to canonical events."""
        for event_type in event_types:
            subject = f"events.canonical.{event_type.lower()}"
            
            async def wrapped_handler(msg):
                try:
                    event = json.loads(msg.data.decode())
                    await handler(event)
                except Exception as e:
                    logger.error(f"Error handling event: {e}")
            
            await self.nc.subscribe(subject, cb=wrapped_handler)
            logger.info(f"Subscribed to {event_type}")
    
    async def call_plugin(
        self,
        target_plugin: str,
        action: str,
        payload: Dict
    ) -> Dict:
        """Make an RPC call to another plugin."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.core_url}/gateway/{target_plugin}/{action}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.plugin_token}",
                    "X-Plugin-Id": self.plugin_id
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"RPC call failed: {response.text}")
            
            return response.json()
    
    async def call_external_api(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        body: Optional[Dict] = None
    ) -> Dict:
        """Make an external API call through the proxy."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.core_url}/proxy",
                json={
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "body": body
                },
                headers={
                    "Authorization": f"Bearer {self.plugin_token}",
                    "X-Plugin-Id": self.plugin_id
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Proxy request failed: {response.text}")
            
            return response.json()
```

#### 4.2 End-to-End Workflow Example
```python
# Example: User Onboarding Workflow

# plugins/workflow_orchestrator/main.py
from vivified_sdk import VivifiedPlugin
import logging

logger = logging.getLogger(__name__)

class WorkflowOrchestrator(VivifiedPlugin):
    """Orchestrates complex workflows across plugins."""
    
    async def initialize(self):
        """Initialize workflow orchestrator."""
        await super().initialize()
        
        # Subscribe to events that trigger workflows
        await self.communication.subscribe_to_events(
            ["UserCreated"],
            self.handle_user_created
        )
        
        await self.communication.subscribe_to_events(
            ["EmailSent"],
            self.handle_email_sent
        )
    
    async def handle_user_created(self, event: Dict):
        """Handle new user creation workflow."""
        user_id = event["payload"]["user_id"]
        user_email = event["payload"]["email"]
        
        logger.info(f"Starting onboarding workflow for user {user_id}")
        
        # Step 1: Get extended user info
        try:
            user_info = await self.communication.call_plugin(
                "user-management",
                "get_user_extended",
                {"user_id": user_id}
            )
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            return
        
        # Step 2: Send welcome email
        try:
            email_result = await self.communication.call_plugin(
                "email-gateway",
                "send_email",
                {
                    "to": user_email,
                    "template": "welcome",
                    "variables": {
                        "name": user_info.get("name"),
                        "department": user_info.get("department")
                    }
                }
            )
            
            logger.info(f"Welcome email sent: {email_result}")
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}")
            
            # Publish failure event
            await self.communication.publish_event(
                "WorkflowFailed",
                {
                    "workflow": "user_onboarding",
                    "step": "send_welcome_email",
                    "user_id": user_id,
                    "error": str(e)
                }
            )
            return
        
        # Step 3: Set up user preferences via external API
        if self.manifest.get("allowed_domains"):
            try:
                result = await self.communication.call_external_api(
                    "https://api.preferences.example.com/users",
                    method="POST",
                    body={
                        "user_id": user_id,
                        "defaults": {
                            "notifications": True,
                            "theme": "light"
                        }
                    }
                )
                
                logger.info(f"User preferences set: {result}")
                
            except Exception as e:
                logger.warning(f"Failed to set preferences: {e}")
        
        # Step 4: Publish completion event
        await self.communication.publish_event(
            "OnboardingCompleted",
            {
                "user_id": user_id,
                "steps_completed": [
                    "user_info_retrieved",
                    "welcome_email_sent",
                    "preferences_set"
                ]
            },
            data_traits=["pii"]  # Contains user ID
        )
    
    async def handle_email_sent(self, event: Dict):
        """Track email sending for audit."""
        email_id = event["payload"]["email_id"]
        recipient = event["payload"]["recipient"]
        
        # Log for compliance
        logger.info(f"Email {email_id} sent to {recipient}", extra={
            "trace_id": event.get("trace_id"),
            "audit": True
        })
```

## Validation Checklist

### Phase 3 Completion Criteria
- [ ] NATS JetStream configured and running
- [ ] Event bus service publishing canonical events
- [ ] Policy enforcement on event delivery
- [ ] Event sanitization for PHI/PII
- [ ] RPC gateway routing plugin calls
- [ ] Circuit breaker pattern implemented
- [ ] Proxy service with domain allowlisting
- [ ] Rate limiting on proxy requests
- [ ] SDK communication module working
- [ ] End-to-end workflow demonstrated
- [ ] All three lanes tested
- [ ] Audit logging for all communications
- [ ] Performance metrics collected

## Security Validation
- [ ] Plugins cannot bypass communication lanes
- [ ] PHI events blocked to unauthorized plugins
- [ ] Internal network addresses blocked in proxy
- [ ] Rate limits enforced per plugin
- [ ] All external calls logged
- [ ] Circuit breakers prevent cascade failures
- [ ] Event payloads sanitized based on traits
- [ ] RPC calls authenticated and authorized

## Performance Testing
```bash
# Test event throughput
./tests/load_test_events.sh 1000  # 1000 events/sec

# Test RPC latency
./tests/measure_rpc_latency.sh

# Test proxy rate limiting
./tests/test_rate_limits.sh

# Verify metrics
curl http://localhost:8000/metrics | grep -E "event_|rpc_|proxy_"
```

## Next Steps
Proceed to Runbook 04 for implementing Security & Production-Ready Features (Admin UI, monitoring, TLS, etc.)