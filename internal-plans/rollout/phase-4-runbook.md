# Runbook 04: Phase 4 - Security & Production-Ready Features

## Objective
Harden the system for production use with comprehensive security measures, implement the Admin Console UI, add monitoring/alerting, and prepare deployment assets for enterprise environments.

## Prerequisites
- Phase 3 completed (all communication lanes operational)
- Plugin ecosystem functional
- Core services stable
- Development environment tested

## Tasks

### 1. Security Hardening

#### 1.1 TLS Configuration
```yaml
# tls/generate_certs.sh
#!/bin/bash
# Generate self-signed certificates for development

# Create CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=Vivified/CN=Vivified-CA"

# Generate server certificate for core
openssl genrsa -out core.key 2048
openssl req -new -key core.key -out core.csr \
    -subj "/C=US/ST=State/L=City/O=Vivified/CN=vivified-core"

cat > core.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = vivified-core
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in core.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out core.crt -days 365 -sha256 -extfile core.ext

# Generate certificates for plugins
for plugin in user-management email-gateway; do
    openssl genrsa -out ${plugin}.key 2048
    openssl req -new -key ${plugin}.key -out ${plugin}.csr \
        -subj "/C=US/ST=State/L=City/O=Vivified/CN=${plugin}"
    openssl x509 -req -in ${plugin}.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out ${plugin}.crt -days 365 -sha256
done
```

#### 1.2 Core TLS Implementation
```python
# core/security/tls_config.py
import ssl
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class TLSConfig:
    """Manages TLS configuration for secure communications."""
    
    def __init__(self, cert_dir: str = "/certs"):
        self.cert_dir = Path(cert_dir)
        self.ca_cert = self.cert_dir / "ca.crt"
        self.server_cert = self.cert_dir / "core.crt"
        self.server_key = self.cert_dir / "core.key"
        
    def create_ssl_context(self, purpose: ssl.Purpose = ssl.Purpose.CLIENT_AUTH) -> ssl.SSLContext:
        """Create SSL context for server."""
        context = ssl.create_default_context(purpose)
        
        # Load server certificate and key
        context.load_cert_chain(
            certfile=str(self.server_cert),
            keyfile=str(self.server_key)
        )
        
        # Load CA certificate for mutual TLS
        context.load_verify_locations(cafile=str(self.ca_cert))
        
        # Require TLS 1.3 minimum
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Strong cipher suites only
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Enable hostname checking
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    def get_client_context(self, plugin_name: str) -> ssl.SSLContext:
        """Create SSL context for plugin client."""
        context = ssl.create_default_context()
        
        # Load plugin certificate
        plugin_cert = self.cert_dir / f"{plugin_name}.crt"
        plugin_key = self.cert_dir / f"{plugin_name}.key"
        
        if plugin_cert.exists() and plugin_key.exists():
            context.load_cert_chain(
                certfile=str(plugin_cert),
                keyfile=str(plugin_key)
            )
        
        # Load CA for verification
        context.load_verify_locations(cafile=str(self.ca_cert))
        
        return context

# Update FastAPI to use HTTPS
# core/main.py
import uvicorn
from core.security.tls_config import TLSConfig

if __name__ == "__main__":
    tls = TLSConfig()
    ssl_context = tls.create_ssl_context()
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=str(tls.server_key),
        ssl_certfile=str(tls.server_cert),
        ssl_ca_certs=str(tls.ca_cert),
        ssl_cert_reqs=2  # CERT_REQUIRED
    )
```

#### 1.3 Container Security Hardening
```dockerfile
# core/Dockerfile.secure
FROM python:3.11-alpine AS builder

# Build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Runtime image
FROM python:3.11-alpine

# Security: Install security updates
RUN apk update && apk upgrade && apk add --no-cache \
    libssl1.1 \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Security: Create unprivileged user
RUN addgroup -g 1001 vivified && \
    adduser -D -H -u 1001 -G vivified vivified

# Install Python packages from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels

# Security: Set up app directory with restricted permissions
WORKDIR /app
COPY --chown=vivified:vivified . .
RUN chmod -R 550 /app && \
    mkdir -p /app/logs && \
    chown -R vivified:vivified /app/logs && \
    chmod 750 /app/logs

# Security: Drop all capabilities and run as non-root
USER vivified
EXPOSE 8443

# Security: No shell in production
ENTRYPOINT ["python", "-m", "core.main"]

# Health check without exposing sensitive data
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys; import urllib.request; \
    req = urllib.request.urlopen('https://localhost:8443/health', \
    context=__import__('ssl')._create_unverified_context()); \
    sys.exit(0 if req.status == 200 else 1)"
```

#### 1.4 Network Security Configuration
```yaml
# docker-compose.secure.yml
version: '3.8'

networks:
  public:
    driver: bridge
  internal:
    driver: bridge
    internal: true
  data:
    driver: bridge
    internal: true

services:
  postgres:
    image: postgres:15-alpine
    networks:
      - data
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      POSTGRES_DB: vivified
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres-tls:/var/lib/postgresql/tls:ro
    command:
      - postgres
      - -c
      - ssl=on
      - -c
      - ssl_cert_file=/var/lib/postgresql/tls/server.crt
      - -c
      - ssl_key_file=/var/lib/postgresql/tls/server.key

  vivified-core:
    build:
      context: ./core
      dockerfile: Dockerfile.secure
    networks:
      - public
      - internal
      - data
    environment:
      DATABASE_URL: postgresql://vivified:password@postgres:5432/vivified?sslmode=require
    secrets:
      - jwt_secret
      - encryption_key
    volumes:
      - ./certs:/certs:ro
      - logs:/app/logs
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

  plugin:
    networks:
      - internal
    security_opt:
      - no-new-privileges:true
    read_only: true
    cap_drop:
      - ALL

secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  encryption_key:
    file: ./secrets/encryption_key.txt

volumes:
  postgres_data:
    driver: local
    driver_opts:
      type: none
      o: bind,uid=999,gid=999
      device: /secure/data/postgres
  logs:
    driver: local
```

### 2. Admin Console UI Implementation

#### 2.1 React Application Setup
```json
# core/ui/package.json
{
  "name": "vivified-admin",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "@mui/material": "^5.11.0",
    "@mui/icons-material": "^5.11.0",
    "@emotion/react": "^11.10.0",
    "@emotion/styled": "^11.10.0",
    "axios": "^1.3.0",
    "recharts": "^2.5.0",
    "react-query": "^3.39.0",
    "@reduxjs/toolkit": "^1.9.0",
    "react-redux": "^8.0.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "GENERATE_SOURCEMAP=false react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject",
    "lint": "eslint src/",
    "security-scan": "npm audit --audit-level=moderate"
  },
  "devDependencies": {
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "typescript": "^4.9.0",
    "react-scripts": "5.0.1",
    "eslint": "^8.0.0",
    "prettier": "^2.8.0"
  },
  "browserslist": {
    "production": [">0.2%", "not dead", "not op_mini all"],
    "development": ["last 1 chrome version"]
  }
}
```

#### 2.2 Main App Component
```typescript
// core/ui/src/App.tsx
import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Provider } from 'react-redux';
import { store } from './store';
import { theme } from './theme';
import { AuthProvider } from './contexts/AuthContext';
import { SecurityProvider } from './contexts/SecurityContext';

// Components
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Plugins from './pages/Plugins';
import Users from './pages/Users';
import Configuration from './pages/Configuration';
import AuditLog from './pages/AuditLog';
import PrivateRoute from './components/PrivateRoute';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
    },
  },
});

function App() {
  useEffect(() => {
    // Security: Prevent clickjacking
    if (window.top !== window.self) {
      window.top.location = window.self.location;
    }
    
    // Security: CSP meta tag
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";
    document.head.appendChild(meta);
  }, []);

  return (
    <ErrorBoundary>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <AuthProvider>
              <SecurityProvider>
                <BrowserRouter>
                  <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
                      <Route index element={<Navigate to="/dashboard" />} />
                      <Route path="dashboard" element={<Dashboard />} />
                      <Route path="plugins" element={<Plugins />} />
                      <Route path="users" element={<Users />} />
                      <Route path="config" element={<Configuration />} />
                      <Route path="audit" element={<AuditLog />} />
                    </Route>
                  </Routes>
                </BrowserRouter>
              </SecurityProvider>
            </AuthProvider>
          </ThemeProvider>
        </QueryClientProvider>
      </Provider>
    </ErrorBoundary>
  );
}

export default App;
```

#### 2.3 Dashboard Component
```typescript
// core/ui/src/pages/Dashboard.tsx
import React from 'react';
import {
  Grid, Paper, Typography, Box, Card, CardContent,
  Alert, LinearProgress, Chip
} from '@mui/material';
import {
  Security, Warning, CheckCircle, Error,
  Storage, NetworkCheck, Memory
} from '@mui/icons-material';
import { useQuery } from 'react-query';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { api } from '../services/api';

const Dashboard: React.FC = () => {
  const { data: systemHealth } = useQuery('systemHealth', api.getSystemHealth, {
    refetchInterval: 5000,
  });

  const { data: metrics } = useQuery('metrics', api.getMetrics, {
    refetchInterval: 10000,
  });

  const { data: alerts } = useQuery('alerts', api.getAlerts);

  const getHealthIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle color="success" />;
      case 'warning': return <Warning color="warning" />;
      case 'error': return <Error color="error" />;
      default: return null;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        System Dashboard
      </Typography>

      {/* Critical Alerts */}
      {alerts?.critical && alerts.critical.length > 0 && (
        <Alert severity="error" sx={{ mb: 2 }}>
          <Typography variant="subtitle1">Critical Alerts</Typography>
          {alerts.critical.map((alert: any) => (
            <Typography key={alert.id} variant="body2">
              {alert.message}
            </Typography>
          ))}
        </Alert>
      )}

      {/* System Health Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography variant="h6">Security Status</Typography>
                  <Box display="flex" alignItems="center">
                    {getHealthIcon(systemHealth?.security)}
                    <Typography variant="body2" sx={{ ml: 1 }}>
                      {systemHealth?.security || 'Loading...'}
                    </Typography>
                  </Box>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <NetworkCheck color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography variant="h6">Plugins</Typography>
                  <Typography variant="h4">
                    {systemHealth?.plugins?.active || 0}/{systemHealth?.plugins?.total || 0}
                  </Typography>
                  <Typography variant="caption">Active/Total</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Storage color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography variant="h6">Storage</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={systemHealth?.storage?.percentage || 0} 
                    sx={{ my: 1 }}
                  />
                  <Typography variant="caption">
                    {systemHealth?.storage?.used || 0}GB / {systemHealth?.storage?.total || 0}GB
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Memory color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography variant="h6">Memory</Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={systemHealth?.memory?.percentage || 0}
                    color={systemHealth?.memory?.percentage > 80 ? 'error' : 'primary'}
                    sx={{ my: 1 }}
                  />
                  <Typography variant="caption">
                    {systemHealth?.memory?.percentage || 0}% Used
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Metrics Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Request Rate
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={metrics?.requestRate}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="rate" stroke="#8884d8" />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Event Processing
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={metrics?.eventProcessing}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Area type="monotone" dataKey="events" stroke="#82ca9d" fill="#82ca9d" />
              </AreaChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              PHI Access Audit
            </Typography>
            <Box>
              {metrics?.phiAccess?.map((access: any) => (
                <Box key={access.id} sx={{ mb: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1 }}>
                  <Typography variant="body2">
                    <Chip label={access.plugin} size="small" sx={{ mr: 1 }} />
                    accessed {access.dataType} at {access.time}
                    {access.blocked && <Chip label="BLOCKED" color="error" size="small" sx={{ ml: 1 }} />}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
```

### 3. Monitoring & Alerting

#### 3.1 Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    environment: 'production'
    platform: 'vivified'

# Alerting
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

# Load rules
rule_files:
  - 'alerts/*.yml'

# Scrape configs
scrape_configs:
  - job_name: 'vivified-core'
    scheme: https
    tls_config:
      ca_file: /certs/ca.crt
      cert_file: /certs/prometheus.crt
      key_file: /certs/prometheus.key
    static_configs:
      - targets: ['vivified-core:8443']
    metrics_path: '/metrics'

  - job_name: 'plugins'
    scheme: https
    tls_config:
      ca_file: /certs/ca.crt
    service_discovery_configs:
      - docker_sd_configs:
          host: unix:///var/run/docker.sock
          filters:
            - name: label
              values: ["vivified.plugin=true"]

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'nats'
    static_configs:
      - targets: ['nats:8222']
    metrics_path: '/metrics'
```

#### 3.2 Alert Rules
```yaml
# monitoring/alerts/security.yml
groups:
  - name: security_alerts
    interval: 30s
    rules:
      - alert: PHIAccessViolation
        expr: vivified_phi_access_denied_total > 0
        for: 1m
        labels:
          severity: critical
          category: compliance
        annotations:
          summary: "PHI access violation detected"
          description: "{{ $value }} PHI access violations in the last minute"

      - alert: AuthenticationFailures
        expr: rate(vivified_auth_failures_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} auth failures per second"

      - alert: PluginSecurityViolation
        expr: vivified_plugin_policy_violations_total > 0
        for: 1m
        labels:
          severity: high
          category: security
        annotations:
          summary: "Plugin security policy violation"
          description: "Plugin {{ $labels.plugin }} violated security policy"

  - name: performance_alerts
    interval: 30s
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.99, vivified_request_duration_seconds_bucket) > 0.5
        for: 5m
        labels:
          severity: warning
          category: performance
        annotations:
          summary: "High request latency"
          description: "P99 latency is {{ $value }}s"

      - alert: HighErrorRate
        expr: rate(vivified_request_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
          category: reliability
        annotations:
          summary: "High error rate"
          description: "Error rate is {{ $value | humanizePercentage }}"
```

#### 3.3 Metrics Implementation
```python
# core/monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, Info, CollectorRegistry
from functools import wraps
import time
import logging

logger = logging.getLogger(__name__)

# Create registry
registry = CollectorRegistry()

# Security metrics
auth_attempts = Counter(
    'vivified_auth_attempts_total',
    'Total authentication attempts',
    ['result', 'method'],
    registry=registry
)

phi_access = Counter(
    'vivified_phi_access_total',
    'PHI data access attempts',
    ['plugin', 'result', 'data_type'],
    registry=registry
)

policy_violations = Counter(
    'vivified_policy_violations_total',
    'Security policy violations',
    ['plugin', 'policy', 'action'],
    registry=registry
)

# Performance metrics
request_duration = Histogram(
    'vivified_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint', 'status'],
    registry=registry
)

event_processing = Histogram(
    'vivified_event_processing_seconds',
    'Event processing duration',
    ['event_type', 'result'],
    registry=registry
)

rpc_latency = Histogram(
    'vivified_rpc_latency_seconds',
    'RPC call latency',
    ['source', 'target', 'action'],
    registry=registry
)

# System metrics
active_plugins = Gauge(
    'vivified_active_plugins',
    'Number of active plugins',
    registry=registry
)

connected_users = Gauge(
    'vivified_connected_users',
    'Number of connected users',
    registry=registry
)

# Compliance metrics
audit_entries = Counter(
    'vivified_audit_entries_total',
    'Total audit log entries',
    ['type', 'severity'],
    registry=registry
)

# Decorators for automatic metric collection
def track_request_duration(method: str):
    """Decorator to track request duration."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.time()
            status = "success"
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start
                request_duration.labels(
                    method=method,
                    endpoint=func.__name__,
                    status=status
                ).observe(duration)
        return wrapper
    return decorator

def track_phi_access(data_type: str):
    """Decorator to track PHI access."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            plugin = kwargs.get('plugin_id', 'unknown')
            try:
                result = await func(*args, **kwargs)
                phi_access.labels(
                    plugin=plugin,
                    result="success",
                    data_type=data_type
                ).inc()
                return result
            except Exception as e:
                phi_access.labels(
                    plugin=plugin,
                    result="denied",
                    data_type=data_type
                ).inc()
                raise
        return wrapper
    return decorator

# Export metrics endpoint
from fastapi import APIRouter
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

metrics_router = APIRouter()

@metrics_router.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint."""
    return Response(
        generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST
    )
```

### 4. Compliance & Audit Implementation

#### 4.1 Comprehensive Audit Service
```python
# core/audit/service.py
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging

logger = logging.getLogger(__name__)

class ComplianceAuditService:
    """HIPAA-compliant audit logging service."""
    
    def __init__(self, db_session, encryption_key):
        self.db = db_session
        self.encryption_key = encryption_key
        self.retention_days = 2555  # 7 years for HIPAA
        
    async def log_phi_access(
        self,
        user_id: Optional[str],
        plugin_id: Optional[str],
        patient_id: str,
        data_accessed: List[str],
        action: str,
        result: str,
        trace_id: str
    ):
        """Log PHI access for HIPAA compliance."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "plugin_id": plugin_id,
            "patient_id": self._hash_patient_id(patient_id),
            "data_accessed": data_accessed,
            "action": action,
            "result": result,
            "trace_id": trace_id,
            "integrity_hash": None
        }
        
        # Calculate integrity hash
        entry["integrity_hash"] = self._calculate_integrity_hash(entry)
        
        # Store in database
        await self.db.execute(
            """INSERT INTO phi_audit_log 
               (user_id, plugin_id, patient_id_hash, data_accessed, 
                action, result, trace_id, integrity_hash, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
            user_id, plugin_id, entry["patient_id"], 
            json.dumps(data_accessed), action, result, 
            trace_id, entry["integrity_hash"], datetime.utcnow()
        )
        
        # Alert on suspicious access patterns
        await self._check_access_patterns(user_id, plugin_id)
    
    def _hash_patient_id(self, patient_id: str) -> str:
        """Hash patient ID for privacy."""
        return hashlib.sha256(
            f"{patient_id}:{self.encryption_key}".encode()
        ).hexdigest()
    
    def _calculate_integrity_hash(self, entry: Dict) -> str:
        """Calculate integrity hash for audit entry."""
        # Remove the hash field itself
        entry_copy = {k: v for k, v in entry.items() if k != "integrity_hash"}
        entry_str = json.dumps(entry_copy, sort_keys=True)
        return hashlib.sha512(entry_str.encode()).hexdigest()
    
    async def _check_access_patterns(self, user_id: str, plugin_id: str):
        """Check for suspicious PHI access patterns."""
        # Check for excessive access
        recent_accesses = await self.db.fetch(
            """SELECT COUNT(*) as count FROM phi_audit_log
               WHERE (user_id = $1 OR plugin_id = $2)
               AND created_at > $3""",
            user_id, plugin_id, 
            datetime.utcnow() - timedelta(minutes=5)
        )
        
        if recent_accesses[0]["count"] > 100:
            await self._raise_security_alert(
                "Excessive PHI access detected",
                {"user_id": user_id, "plugin_id": plugin_id}
            )
    
    async def verify_audit_integrity(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """Verify audit log integrity for compliance."""
        entries = await self.db.fetch(
            """SELECT * FROM phi_audit_log 
               WHERE created_at BETWEEN $1 AND $2
               ORDER BY created_at""",
            start_date, end_date
        )
        
        valid = 0
        invalid = 0
        
        for entry in entries:
            # Reconstruct and verify hash
            entry_dict = dict(entry)
            stored_hash = entry_dict.pop("integrity_hash")
            calculated_hash = self._calculate_integrity_hash(entry_dict)
            
            if stored_hash == calculated_hash:
                valid += 1
            else:
                invalid += 1
                logger.error(f"Integrity violation in audit log: {entry['id']}")
        
        return {
            "total": len(entries),
            "valid": valid,
            "invalid": invalid,
            "integrity": invalid == 0
        }
```

### 5. Production Deployment Configuration

#### 5.1 Kubernetes Security Manifests
```yaml
# k8s/security/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: vivified-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true

---
# k8s/security/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vivified-network-policy
  namespace: vivified
spec:
  podSelector:
    matchLabels:
      app: vivified
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: vivified
        - podSelector:
            matchLabels:
              app: vivified-core
      ports:
        - protocol: TCP
          port: 8443
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: vivified
      ports:
        - protocol: TCP
          port: 5432  # PostgreSQL
        - protocol: TCP
          port: 4222  # NATS
    - to:
        - podSelector:
            matchLabels:
              app: vivified-core
      ports:
        - protocol: TCP
          port: 8443
```

#### 5.2 Helm Chart Configuration
```yaml
# k8s/helm/vivified/values.yaml
replicaCount: 3

image:
  repository: vivified/core
  pullPolicy: Always
  tag: "1.0.0"

imagePullSecrets:
  - name: registry-secret

service:
  type: LoadBalancer
  port: 443
  targetPort: 8443
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: "arn:aws:acm:..."
    service.beta.kubernetes.io/aws-load-balancer-backend-protocol: "https"

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: vivified.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vivified-tls
      hosts:
        - vivified.example.com

resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

securityContext:
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1001
  fsGroup: 1001

postgresql:
  enabled: true
  auth:
    database: vivified
    existingSecret: postgres-secret
  tls:
    enabled: true
    certificatesSecret: postgres-tls
  backup:
    enabled: true
    schedule: "0 2 * * *"
    retention: "30d"

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true
    adminPassword: changeme

compliance:
  hipaa:
    enabled: true
    auditRetentionDays: 2555
    encryptionAtRest: true
    encryptionInTransit: true
```

## Validation Checklist

### Phase 4 Security Validation
- [ ] TLS 1.3 configured for all communications
- [ ] Mutual TLS between services
- [ ] All containers running as non-root
- [ ] Network segmentation implemented
- [ ] No hardcoded secrets
- [ ] Security headers configured
- [ ] Pod Security Policies enforced
- [ ] Network Policies restricting traffic

### Admin UI Validation
- [ ] Login with MFA working
- [ ] Dashboard showing real-time metrics
- [ ] Plugin management functional
- [ ] User management with role assignment
- [ ] Configuration changes audited
- [ ] Audit log viewer working
- [ ] PHI access tracking visible
- [ ] Real-time alerts displayed

### Monitoring Validation
- [ ] Prometheus scraping all targets
- [ ] Security alerts configured
- [ ] Performance metrics collected
- [ ] Grafana dashboards operational
- [ ] Alert manager sending notifications
- [ ] PHI access metrics tracked
- [ ] Compliance reports generated

### Production Readiness
- [ ] Kubernetes manifests tested
- [ ] Helm chart deployable
- [ ] Autoscaling configured
- [ ] Backup procedures verified
- [ ] Disaster recovery tested
- [ ] Load testing passed
- [ ] Security scanning clean
- [ ] Compliance audit passed

## Next Steps
Proceed to Runbook 05 for Developer Experience & Ecosystem implementation.