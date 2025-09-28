# Runbook 05: Phase 5 - Developer Experience & Ecosystem

## Objective
Complete multi-language SDKs, build the CLI tool, create plugin templates, finalize reference plugins, and ensure comprehensive documentation for third-party developers.

## Prerequisites
- Core platform fully functional
- Communication lanes tested
- Security measures implemented
- Admin UI operational

## Agent Prompt (execute non-interactively, CI-safe)
You are an automation agent. Execute Phase 5 end-to-end. After EACH portion, run the smoke tests and CI gates to prevent regressions. Enforce AGENTS.md at all times:
- Zero Trust: no direct plugin-to-plugin or UI-to-plugin calls. All traffic goes through the Core gateway/proxy.
- HIPAA: no PHI/PII in logs; mask/redact; 15-minute JWTs; MFA for admins (DEV bootstrap only when `DEV_MODE=true`).
- Three Lanes only: Canonical (event bus), Operator (RPC via gateway), Proxy (allowlisted via core proxy). No bypass.
- Security defaults: TLS 1.3+, rate limits on admin endpoints, session timeout ≤ 30 minutes.
- All actions must be reproducible and CI-pass before advancing.

Working directory: `/Users/davidmontgomery/faxbot_folder/vivified`

---

## Portions, Smoke Tests, and CI Gates

### Portion 1/12 — Define SDK API Contract and Parity Spec
Action:
- Create/verify a single JSON parity spec (e.g., `tools/validator/sdk_parity.json`) that lists: `VivifiedClient`, `publish_event`, `subscribe`, `call_plugin`, `call_external`, `get_config`, `set_config`.

Smoke tests:
```bash
rg -n "VivifiedClient|publish_event|subscribe|call_plugin|call_external|get_config" sdk -S | cat
```
- Expect stubs/signatures across Python/Node/Go SDKs.

CI gates:
```bash
pip install black flake8 mypy || true
black --check sdk/python || true; flake8 sdk/python || true; mypy sdk/python || true
node -v && npm -v | cat
```

### Portion 2/12 — Python SDK implementation and tests
Action:
- Implement `sdk/python/vivified_sdk` with identical API. Use HTTP to Core; do not talk to NATS directly.

Smoke tests:
```bash
cd sdk/python
pip install -e .[dev] || true
pytest -q | cat
cd -
```

CI gates:
```bash
black --check sdk/python && flake8 sdk/python && mypy sdk/python | cat
```

### Portion 3/12 — Node.js SDK implementation and tests
Action:
- Implement `sdk/nodejs` in TS; use axios; no direct NATS.

Smoke tests:
```bash
cd sdk/nodejs
rm -rf node_modules package-lock.json && npm ci
npm run lint | cat
npm test --silent | cat
npm run build | cat
cd -
```

CI gates:
```bash
cd sdk/nodejs && npm audit --audit-level=moderate || true; cd -
```

### Portion 4/12 — Go SDK implementation and tests
Action:
- Implement `sdk/go` with matching API; idiomatic method names.

Smoke tests:
```bash
cd sdk/go
go mod tidy
go vet ./... | cat
go test ./... -v | cat
cd -
```

CI gates:
- Ensure tests make no external network calls.

### Portion 5/12 — Cross-SDK parity checker
Action:
- Implement `tools/validator/check_sdk_parity.py` that introspects each SDK and compares to the JSON spec.

Smoke tests:
```bash
python tools/validator/check_sdk_parity.py | cat
```
- Expect: Parity OK.

CI gates: fail build on parity mismatch.

### Portion 6/12 — CLI scaffolder and validator
Action:
- Implement `tools/cli/vivified` with commands:
  - `create-plugin --lang python|node|go --name NAME --type TYPE`
  - `validate-manifest --file plugin.json`
  - `doctor` (optional environment check)

Smoke tests:
```bash
cd tools/cli
pip install -e . || true
vivified --help | cat
vivified create-plugin --lang python --name example_plugin --type communication | cat
vivified validate-manifest --file plugins/example_plugin/manifest.json | cat
cd -
```

CI gates: Lint CLI; create temp plugin and assert files exist and validate.

### Portion 7/12 — Manifest schema wiring (single source)
Action:
- Ensure CLI and Core use the same `tools/validator/manifest_schema.json`.
- Ensure registration path in Core calls the same validator (no duplicates).

Smoke tests:
```bash
vivified validate-manifest --file plugins/example_plugin/manifest.json | cat
# Negative
jq '.traits=["admin"]' plugins/example_plugin/manifest.json > /tmp/bad.json
vivified validate-manifest --file /tmp/bad.json || echo "Validation failed as expected"
```

CI gates: Add manifest validation step on any `plugins/**/manifest.json` changes.

### Portion 8/12 — Language templates
Action:
- Provide templates under `tools/templates/{python,nodejs,go}/{communication,storage,identity,workflow,custom}` with `/health`, registration to Core on startup, tests, Dockerfile (non-root/caps), and minimal config.

Smoke tests:
```bash
vivified create-plugin --lang python --name hello_py --type communication
cd plugins/hello_py && pytest -q | cat; cd -
vivified create-plugin --lang node --name hello_js --type communication
cd plugins/hello_js && npm ci && npm test --silent | cat; cd -
```

CI gates: Build/lint/test template outputs in CI without network egress.

### Portion 9/12 — Sample plugin local registration
Action:
- Start Core and a generated plugin; validate `/admin/plugins` shows registration; ensure auditing.

Smoke tests:
```bash
make up
sleep 8
curl -s http://localhost:8000/health | cat
# Start a python sample in foreground (dev)
cd plugins/hello_py && python -m app & sleep 5; cd -
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' -d '{"username":"bootstrap_admin_only","password":"bootstrap_admin_only","mfa_code":"000000"}' | jq -r .token)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/admin/plugins | jq '.plugins | length' | cat
```
- Expect ≥1 plugin and an audit record for registration.

CI gates: containerized integration test (core + minimal plugin) asserting registration & health.

### Portion 10/12 — E2E lanes sanity (events/RPC/proxy)
Action:
- Using the sample plugin + SDKs, validate:
  - Canonical publish/subscribe via Core
  - RPC via gateway with trait enforcement
  - Proxy call to an allowlisted, non-sensitive endpoint; internal addresses blocked

Smoke tests:
```bash
curl -s -X POST http://localhost:8000/events/publish -H 'Content-Type: application/json' \
 -d '{"event_type":"DevHello","payload":{"msg":"hello"},"source_plugin":"hello_py","data_traits":[]}' | cat
curl -s -X POST http://localhost:8000/gateway/hello_py/ping -H 'Content-Type: application/json' -d '{}' | cat
curl -s -X POST http://localhost:8000/proxy -H 'Content-Type: application/json' \
 -d '{"plugin_id":"hello_py","url":"https://api.github.com","method":"GET"}' | cat
```
- Expect authorized responses; denied on policy/allowlist violations; audited.

CI gates: integration tests assert audit entries and policy behavior.

### Portion 11/12 — Docs and DX
Action:
- Generate SDK references, CLI usage, and a “first plugin” tutorial. Build docs with mkdocs.

Smoke tests:
```bash
pip install mkdocs || true
mkdocs build --strict | cat
```

CI gates: docs build required.

### Portion 12/12 — CI pipeline integration
Action:
- Add jobs in CI: SDK parity checker; CLI generate + validate; template build/lint/test; integration test of registration + lanes.

Smoke tests:
- Trigger all jobs locally where possible via `make` targets.

CI gates: all pass; ≥80% coverage for SDK/CLI code.

---

## Tasks

### 1. Multi-Language SDK Implementation

#### 1.1 Python SDK
```python
# sdk/python/setup.py
from setuptools import setup, find_packages

setup(
    name="vivified-sdk",
    version="1.0.0",
    author="Vivified Platform",
    description="SDK for building Vivified plugins",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/vivified/python-sdk",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.95.0",
        "httpx>=0.24.0",
        "pydantic>=2.0.0",
        "nats-py>=2.3.0",
        "prometheus-client>=0.16.0",
        "cryptography>=40.0.0",
        "python-jose>=3.3.0",
        "python-multipart>=0.0.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0",
        ]
    }
)
```

```python
# sdk/python/vivified/__init__.py
"""Vivified Plugin SDK for Python."""

from .plugin import VivifiedPlugin
from .communication import EventBus, RPCClient, ProxyClient
from .security import SecurityContext, TraitValidator
from .storage import StorageClient
from .canonical import CanonicalTransformer, CanonicalModels
from .decorators import (
    event_handler,
    rpc_endpoint,
    require_traits,
    audit_log,
    rate_limit,
    track_metrics
)
from .exceptions import (
    VivifiedError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    CommunicationError
)

__version__ = "1.0.0"
__all__ = [
    "VivifiedPlugin",
    "EventBus",
    "RPCClient",
    "ProxyClient",
    "SecurityContext",
    "TraitValidator",
    "StorageClient",
    "CanonicalTransformer",
    "CanonicalModels",
    "event_handler",
    "rpc_endpoint",
    "require_traits",
    "audit_log",
    "rate_limit",
    "track_metrics",
    "VivifiedError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "CommunicationError",
]
```

```python
# sdk/python/vivified/plugin.py
import asyncio
import os
import json
import logging
from typing import Dict, Any, Optional, List, Callable
from abc import ABC, abstractmethod
import httpx
from fastapi import FastAPI, HTTPException, Request
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class VivifiedPlugin(ABC):
    """Base class for all Vivified plugins."""
    
    def __init__(self, manifest_path: str = "manifest.json"):
        """Initialize plugin with manifest."""
        self.manifest = self._load_manifest(manifest_path)
        self.plugin_id = self.manifest["id"]
        self.plugin_token = None
        self.core_url = os.getenv("CORE_URL", "https://vivified-core:8443")
        self.app = FastAPI(
            title=self.manifest["name"],
            version=self.manifest["version"],
            lifespan=self._lifespan
        )
        self._setup_routes()
        self._setup_security()
        
    def _load_manifest(self, path: str) -> Dict:
        """Load and validate plugin manifest."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Manifest not found: {path}")
        
        with open(path) as f:
            manifest = json.load(f)
        
        # Validate required fields
        required = ["id", "name", "version", "contracts", "traits", "security", "compliance"]
        missing = [field for field in required if field not in manifest]
        if missing:
            raise ValueError(f"Missing required manifest fields: {missing}")
        
        # Validate HIPAA compliance if handling PHI
        if "handles_phi" in manifest.get("traits", []):
            if not manifest.get("compliance", {}).get("hipaa_controls"):
                raise ValueError("PHI handlers must declare HIPAA controls")
        
        return manifest
    
    @asynccontextmanager
    async def _lifespan(self, app: FastAPI):
        """Manage plugin lifecycle."""
        # Startup
        await self._register_with_core()
        await self.initialize()
        self._start_background_tasks()
        yield
        # Shutdown
        await self.shutdown()
        await self._unregister_from_core()
    
    async def _register_with_core(self):
        """Register this plugin with the core platform."""
        async with httpx.AsyncClient(verify=False) as client:  # Use proper TLS in production
            try:
                response = await client.post(
                    f"{self.core_url}/plugins/register",
                    json=self.manifest,
                    headers={"Authorization": f"Bearer {os.getenv('REGISTRATION_TOKEN', '')}"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.plugin_token = data["token"]
                    logger.info(f"Plugin {self.plugin_id} registered successfully")
                else:
                    raise RuntimeError(f"Registration failed: {response.text}")
                    
            except Exception as e:
                logger.error(f"Failed to register plugin: {e}")
                raise
    
    def _setup_routes(self):
        """Set up standard plugin routes."""
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return await self.health_check()
        
        @self.app.post("/heartbeat")
        async def heartbeat():
            """Heartbeat endpoint for core monitoring."""
            return {"status": "alive", "plugin_id": self.plugin_id}
    
    def _setup_security(self):
        """Set up security middleware."""
        @self.app.middleware("http")
        async def security_middleware(request: Request, call_next):
            # Validate caller authentication
            auth_header = request.headers.get("Authorization")
            if not auth_header or not self._validate_auth(auth_header):
                if request.url.path not in ["/health", "/heartbeat"]:
                    return HTTPException(status_code=401, detail="Unauthorized")
            
            # Add security headers
            response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
            
            return response
    
    def _validate_auth(self, auth_header: str) -> bool:
        """Validate authentication token."""
        # Implement JWT validation
        return True  # Placeholder
    
    def _start_background_tasks(self):
        """Start background tasks for plugin."""
        # Heartbeat task
        asyncio.create_task(self._heartbeat_loop())
        
        # Metrics reporting
        if self.manifest.get("compliance", {}).get("audit_level") != "none":
            asyncio.create_task(self._metrics_loop())
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to core."""
        while True:
            try:
                await asyncio.sleep(30)
                async with httpx.AsyncClient(verify=False) as client:
                    await client.post(
                        f"{self.core_url}/plugins/heartbeat",
                        json={"plugin_id": self.plugin_id, "status": "healthy"},
                        headers={"Authorization": f"Bearer {self.plugin_token}"}
                    )
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
    
    @abstractmethod
    async def initialize(self):
        """Initialize plugin - override in subclass."""
        pass
    
    @abstractmethod
    async def shutdown(self):
        """Shutdown plugin - override in subclass."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Health check - override in subclass."""
        return {"status": "healthy", "plugin_id": self.plugin_id}
```

#### 1.2 Node.js SDK
```javascript
// sdk/nodejs/package.json
{
  "name": "@vivified/plugin-sdk",
  "version": "1.0.0",
  "description": "Vivified Plugin SDK for Node.js",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "lint": "eslint src/",
    "prepublish": "npm run build"
  },
  "keywords": ["vivified", "plugin", "sdk", "healthcare", "hipaa"],
  "author": "Vivified Platform",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.0",
    "axios": "^1.3.0",
    "nats": "^2.7.0",
    "jsonwebtoken": "^9.0.0",
    "prom-client": "^14.2.0",
    "winston": "^3.8.0",
    "joi": "^17.9.0"
  },
  "devDependencies": {
    "@types/express": "^4.17.0",
    "@types/node": "^18.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0",
    "eslint": "^8.0.0",
    "@typescript-eslint/eslint-plugin": "^5.0.0"
  }
}
```

```typescript
// sdk/nodejs/src/VivifiedPlugin.ts
import express, { Application, Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { connect, NatsConnection, StringCodec } from 'nats';
import jwt from 'jsonwebtoken';
import { Registry, collectDefaultMetrics } from 'prom-client';
import winston from 'winston';
import * as fs from 'fs';
import * as path from 'path';

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  contracts: string[];
  traits: string[];
  security: {
    authentication_required: boolean;
    data_classification: string[];
  };
  compliance: {
    hipaa_controls: string[];
    audit_level: string;
  };
}

export abstract class VivifiedPlugin {
  protected manifest: PluginManifest;
  protected app: Application;
  protected pluginToken: string | null = null;
  protected coreUrl: string;
  protected natsConnection: NatsConnection | null = null;
  protected logger: winston.Logger;
  protected metricsRegistry: Registry;

  constructor(manifestPath: string = 'manifest.json') {
    this.manifest = this.loadManifest(manifestPath);
    this.coreUrl = process.env.CORE_URL || 'https://vivified-core:8443';
    this.app = express();
    this.setupLogger();
    this.setupExpress();
    this.setupMetrics();
  }

  private loadManifest(manifestPath: string): PluginManifest {
    const fullPath = path.resolve(manifestPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Manifest not found: ${fullPath}`);
    }

    const content = fs.readFileSync(fullPath, 'utf-8');
    const manifest = JSON.parse(content) as PluginManifest;

    // Validate PHI handling
    if (manifest.traits.includes('handles_phi')) {
      if (!manifest.compliance.hipaa_controls || manifest.compliance.hipaa_controls.length === 0) {
        throw new Error('PHI handlers must declare HIPAA controls');
      }
    }

    return manifest;
  }

  private setupLogger(): void {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { plugin: this.manifest.id },
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
      ]
    });
  }

  private setupExpress(): void {
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Security middleware
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      next();
    });

    // Authentication middleware
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      if (['/health', '/heartbeat', '/metrics'].includes(req.path)) {
        return next();
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !this.validateAuth(authHeader)) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      next();
    });

    // Standard routes
    this.app.get('/health', async (req: Request, res: Response) => {
      const health = await this.healthCheck();
      res.json(health);
    });

    this.app.post('/heartbeat', (req: Request, res: Response) => {
      res.json({ status: 'alive', plugin_id: this.manifest.id });
    });

    this.app.get('/metrics', (req: Request, res: Response) => {
      res.set('Content-Type', this.metricsRegistry.contentType);
      res.end(this.metricsRegistry.metrics());
    });
  }

  private setupMetrics(): void {
    this.metricsRegistry = new Registry();
    collectDefaultMetrics({ register: this.metricsRegistry });
  }

  private validateAuth(authHeader: string): boolean {
    try {
      const token = authHeader.replace('Bearer ', '');
      jwt.verify(token, process.env.JWT_SECRET || '');
      return true;
    } catch {
      return false;
    }
  }

  public async start(port: number = 8080): Promise<void> {
    await this.registerWithCore();
    await this.initialize();
    await this.connectToEventBus();
    
    this.app.listen(port, () => {
      this.logger.info(`Plugin ${this.manifest.id} listening on port ${port}`);
    });

    // Start background tasks
    this.startHeartbeat();
  }

  private async registerWithCore(): Promise<void> {
    try {
      const response = await axios.post(
        `${this.coreUrl}/plugins/register`,
        this.manifest,
        {
          headers: {
            'Authorization': `Bearer ${process.env.REGISTRATION_TOKEN || ''}`
          },
          httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Use proper TLS in production
          })
        }
      );

      this.pluginToken = response.data.token;
      this.logger.info('Successfully registered with core');
    } catch (error) {
      this.logger.error('Failed to register with core', error);
      throw error;
    }
  }

  private async connectToEventBus(): Promise<void> {
    const natsUrl = process.env.NATS_URL || 'nats://nats:4222';
    this.natsConnection = await connect({ servers: natsUrl });
    this.logger.info('Connected to NATS event bus');
  }

  private startHeartbeat(): void {
    setInterval(async () => {
      try {
        await axios.post(
          `${this.coreUrl}/plugins/heartbeat`,
          { plugin_id: this.manifest.id, status: 'healthy' },
          {
            headers: {
              'Authorization': `Bearer ${this.pluginToken}`
            }
          }
        );
      } catch (error) {
        this.logger.error('Heartbeat failed', error);
      }
    }, 30000);
  }

  // Abstract methods to implement
  protected abstract initialize(): Promise<void>;
  protected abstract healthCheck(): Promise<any>;
}
```

#### 1.3 Go SDK
```go
// sdk/go/go.mod
module github.com/vivified/go-sdk

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/nats-io/nats.go v1.25.0
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/prometheus/client_golang v1.15.0
    go.uber.org/zap v1.24.0
    github.com/go-playground/validator/v10 v10.12.0
)
```

```go
// sdk/go/plugin.go
package vivified

import (
    "context"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/nats-io/nats.go"
    "github.com/golang-jwt/jwt/v5"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "go.uber.org/zap"
)

// PluginManifest represents plugin configuration
type PluginManifest struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Version     string                 `json:"version"`
    Contracts   []string              `json:"contracts"`
    Traits      []string              `json:"traits"`
    Security    SecurityConfig        `json:"security"`
    Compliance  ComplianceConfig      `json:"compliance"`
}

// SecurityConfig defines security requirements
type SecurityConfig struct {
    AuthenticationRequired bool     `json:"authentication_required"`
    DataClassification    []string `json:"data_classification"`
}

// ComplianceConfig defines compliance requirements
type ComplianceConfig struct {
    HIPAAControls []string `json:"hipaa_controls"`
    AuditLevel    string   `json:"audit_level"`
}

// Plugin interface that all plugins must implement
type Plugin interface {
    Initialize(ctx context.Context) error
    Shutdown(ctx context.Context) error
    HealthCheck(ctx context.Context) (map[string]interface{}, error)
}

// VivifiedPlugin base struct for all plugins
type VivifiedPlugin struct {
    Manifest     *PluginManifest
    Router       *gin.Engine
    pluginToken  string
    coreURL      string
    natsConn     *nats.Conn
    logger       *zap.Logger
    metrics      *prometheus.Registry
    impl         Plugin
}

// NewPlugin creates a new Vivified plugin
func NewPlugin(manifestPath string, impl Plugin) (*VivifiedPlugin, error) {
    manifest, err := loadManifest(manifestPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load manifest: %w", err)
    }

    // Validate PHI handling
    if contains(manifest.Traits, "handles_phi") {
        if len(manifest.Compliance.HIPAAControls) == 0 {
            return nil, fmt.Errorf("PHI handlers must declare HIPAA controls")
        }
    }

    logger, _ := zap.NewProduction()
    
    p := &VivifiedPlugin{
        Manifest: manifest,
        Router:   gin.New(),
        coreURL:  getEnv("CORE_URL", "https://vivified-core:8443"),
        logger:   logger,
        metrics:  prometheus.NewRegistry(),
        impl:     impl,
    }

    p.setupRouter()
    p.setupMetrics()

    return p, nil
}

func loadManifest(path string) (*PluginManifest, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var manifest PluginManifest
    if err := json.Unmarshal(data, &manifest); err != nil {
        return nil, err
    }

    return &manifest, nil
}

func (p *VivifiedPlugin) setupRouter() {
    // Security middleware
    p.Router.Use(func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000")
        c.Next()
    })

    // Authentication middleware
    p.Router.Use(func(c *gin.Context) {
        if c.Request.URL.Path == "/health" || 
           c.Request.URL.Path == "/heartbeat" ||
           c.Request.URL.Path == "/metrics" {
            c.Next()
            return
        }

        authHeader := c.GetHeader("Authorization")
        if !p.validateAuth(authHeader) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }
        c.Next()
    })

    // Standard routes
    p.Router.GET("/health", p.handleHealth)
    p.Router.POST("/heartbeat", p.handleHeartbeat)
    p.Router.GET("/metrics", gin.WrapH(promhttp.HandlerFor(
        p.metrics,
        promhttp.HandlerOpts{},
    )))
}

func (p *VivifiedPlugin) setupMetrics() {
    // Register default metrics
    prometheus.MustRegister(p.metrics)
}

func (p *VivifiedPlugin) validateAuth(authHeader string) bool {
    // Implement JWT validation
    tokenString := authHeader[7:] // Remove "Bearer "
    
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(os.Getenv("JWT_SECRET")), nil
    })

    return err == nil && token.Valid
}

// Start initializes and starts the plugin
func (p *VivifiedPlugin) Start(ctx context.Context, port int) error {
    // Register with core
    if err := p.registerWithCore(ctx); err != nil {
        return fmt.Errorf("failed to register: %w", err)
    }

    // Initialize implementation
    if err := p.impl.Initialize(ctx); err != nil {
        return fmt.Errorf("initialization failed: %w", err)
    }

    // Connect to NATS
    if err := p.connectToNATS(); err != nil {
        p.logger.Warn("Failed to connect to NATS", zap.Error(err))
    }

    // Start heartbeat
    go p.heartbeatLoop(ctx)

    // Start server
    addr := fmt.Sprintf(":%d", port)
    p.logger.Info("Starting plugin", 
        zap.String("id", p.Manifest.ID),
        zap.String("address", addr))

    return p.Router.Run(addr)
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### 2. CLI Tool Implementation

#### 2.1 CLI Tool Structure
```python
# tools/cli/setup.py
from setuptools import setup, find_packages

setup(
    name="vivified-cli",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "requests>=2.28.0",
        "jsonschema>=4.17.0",
        "cookiecutter>=2.1.0",
    ],
    entry_points={
        "console_scripts": [
            "vivified=vivified_cli.main:cli",
        ],
    },
)
```

```python
# tools/cli/vivified_cli/main.py
import click
import os
import json
import yaml
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track
from jsonschema import validate, ValidationError
from cookiecutter.main import cookiecutter

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Vivified Platform CLI - Build secure, compliant plugins."""
    pass

@cli.command()
@click.option('--name', prompt='Plugin name', help='Name of the plugin')
@click.option('--type', 'plugin_type', 
              type=click.Choice(['communication', 'storage', 'identity', 'workflow', 'custom']),
              prompt='Plugin type', help='Type of plugin')
@click.option('--language', 
              type=click.Choice(['python', 'nodejs', 'go']),
              prompt='Language', help='Programming language')
@click.option('--phi', is_flag=True, prompt='Will handle PHI?', 
              help='Plugin will handle Protected Health Information')
@click.option('--output', '-o', default='.', help='Output directory')
def create(name, plugin_type, language, phi, output):
    """Create a new Vivified plugin from template."""
    console.print(f"[bold green]Creating new {plugin_type} plugin: {name}[/bold green]")
    
    # Prepare context
    context = {
        "plugin_name": name,
        "plugin_id": name.lower().replace(' ', '-'),
        "plugin_type": plugin_type,
        "language": language,
        "handles_phi": phi,
        "hipaa_controls": ["164.312(a)", "164.312(e)"] if phi else [],
        "traits": ["handles_phi", "audit_required"] if phi else []
    }
    
    # Select template
    template_dir = Path(__file__).parent.parent / "templates" / language / plugin_type
    if not template_dir.exists():
        template_dir = Path(__file__).parent.parent / "templates" / language / "custom"
    
    try:
        # Generate from template
        output_dir = cookiecutter(
            str(template_dir),
            extra_context=context,
            output_dir=output,
            no_input=True
        )
        
        console.print(f"[green]✓[/green] Plugin created at: {output_dir}")
        
        # Show next steps
        console.print("\n[bold]Next steps:[/bold]")
        console.print("1. cd " + output_dir)
        console.print("2. Review and update manifest.json")
        console.print("3. Install dependencies")
        if language == "python":
            console.print("   pip install -r requirements.txt")
        elif language == "nodejs":
            console.print("   npm install")
        elif language == "go":
            console.print("   go mod download")
        console.print("4. Run tests: vivified test")
        console.print("5. Deploy: vivified deploy")
        
    except Exception as e:
        console.print(f"[red]Error creating plugin: {e}[/red]")
        raise click.Exit(1)

@cli.command()
@click.argument('manifest_file', type=click.Path(exists=True))
def validate(manifest_file):
    """Validate a plugin manifest file."""
    console.print(f"Validating manifest: {manifest_file}")
    
    # Load manifest
    with open(manifest_file) as f:
        if manifest_file.endswith('.yaml') or manifest_file.endswith('.yml'):
            manifest = yaml.safe_load(f)
        else:
            manifest = json.load(f)
    
    # Load schema
    schema_path = Path(__file__).parent.parent / "validator" / "manifest_schema.json"
    with open(schema_path) as f:
        schema = json.load(f)
    
    try:
        # Validate against schema
        validate(instance=manifest, schema=schema)
        
        # Additional security checks
        warnings = []
        errors = []
        
        # Check PHI handling
        if "handles_phi" in manifest.get("traits", []):
            if not manifest.get("compliance", {}).get("hipaa_controls"):
                errors.append("PHI handlers must declare HIPAA controls")
            if manifest.get("compliance", {}).get("audit_level") == "none":
                errors.append("PHI handlers must enable auditing")
        
        # Check PII handling
        if "handles_pii" in manifest.get("traits", []):
            if "pii" not in manifest.get("security", {}).get("data_classification", []):
                warnings.append("PII handler should declare PII in data classification")
        
        # Check external domains
        for domain in manifest.get("allowed_domains", []):
            if any(blocked in domain for blocked in ["localhost", "127.0.0.1", "192.168"]):
                errors.append(f"Invalid domain in allowlist: {domain}")
        
        # Display results
        if errors:
            console.print("[red]✗ Validation failed:[/red]")
            for error in errors:
                console.print(f"  - {error}")
            raise click.Exit(1)
        
        if warnings:
            console.print("[yellow]⚠ Warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  - {warning}")
        
        console.print("[green]✓ Manifest is valid[/green]")
        
        # Display summary
        table = Table(title="Manifest Summary")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("ID", manifest["id"])
        table.add_row("Name", manifest["name"])
        table.add_row("Version", manifest["version"])
        table.add_row("Traits", ", ".join(manifest.get("traits", [])))
        table.add_row("Contracts", ", ".join(manifest.get("contracts", [])))
        table.add_row("Audit Level", manifest.get("compliance", {}).get("audit_level", "none"))
        
        console.print(table)
        
    except ValidationError as e:
        console.print(f"[red]✗ Schema validation failed:[/red]")
        console.print(f"  {e.message}")
        raise click.Exit(1)

@cli.command()
@click.option('--plugin', default='.', help='Plugin directory')
@click.option('--coverage', is_flag=True, help='Run with coverage')
def test(plugin, coverage):
    """Run plugin tests."""
    plugin_path = Path(plugin)
    
    if not plugin_path.exists():
        console.print(f"[red]Plugin directory not found: {plugin}[/red]")
        raise click.Exit(1)
    
    # Detect language
    if (plugin_path / "requirements.txt").exists():
        language = "python"
    elif (plugin_path / "package.json").exists():
        language = "nodejs"
    elif (plugin_path / "go.mod").exists():
        language = "go"
    else:
        console.print("[red]Could not detect plugin language[/red]")
        raise click.Exit(1)
    
    console.print(f"Running tests for {language} plugin...")
    
    # Run language-specific tests
    if language == "python":
        cmd = "pytest tests/"
        if coverage:
            cmd += " --cov=. --cov-report=html"
        os.system(f"cd {plugin} && {cmd}")
        
    elif language == "nodejs":
        cmd = "npm test"
        if coverage:
            cmd = "npm run test:coverage"
        os.system(f"cd {plugin} && {cmd}")
        
    elif language == "go":
        cmd = "go test ./..."
        if coverage:
            cmd += " -cover"
        os.system(f"cd {plugin} && {cmd}")

@cli.command()
@click.option('--manifest', default='manifest.json', help='Manifest file')
@click.option('--environment', default='dev', help='Target environment')
@click.option('--dry-run', is_flag=True, help='Perform dry run')
def deploy(manifest, environment, dry_run):
    """Deploy plugin to Vivified platform."""
    console.print(f"Deploying plugin to {environment}...")
    
    if dry_run:
        console.print("[yellow]DRY RUN - No changes will be made[/yellow]")
    
    # Load manifest
    with open(manifest) as f:
        manifest_data = json.load(f)
    
    console.print(f"Plugin: {manifest_data['name']} v{manifest_data['version']}")
    
    # Validate before deploy
    ctx = click.get_current_context()
    ctx.invoke(validate, manifest_file=manifest)
    
    if not dry_run:
        # Build and push container
        console.print("Building container...")
        os.system(f"docker build -t vivified/{manifest_data['id']}:{manifest_data['version']} .")
        
        console.print("Pushing to registry...")
        os.system(f"docker push vivified/{manifest_data['id']}:{manifest_data['version']}")
        
        console.print("[green]✓ Deployment complete[/green]")

if __name__ == '__main__':
    cli()
```

### 3. Plugin Templates

#### 3.1 Python Plugin Template
```python
# tools/templates/python/custom/{{cookiecutter.plugin_id}}/main.py
"""{{cookiecutter.plugin_name}} - Vivified Plugin."""

from vivified import VivifiedPlugin, event_handler, rpc_endpoint, require_traits
import logging
import asyncio
from typing import Dict, Any

logger = logging.getLogger(__name__)

class {{cookiecutter.plugin_name.replace(' ', '')}}Plugin(VivifiedPlugin):
    """{{cookiecutter.plugin_name}} implementation."""
    
    async def initialize(self):
        """Initialize plugin."""
        logger.info(f"Initializing {{cookiecutter.plugin_name}}")
        
        # Load configuration
        self.config = await self.get_config()
        
        {% if cookiecutter.handles_phi %}
        # Initialize PHI handling
        self.setup_phi_compliance()
        {% endif %}
        
        # Subscribe to events
        await self.event_bus.subscribe("UserCreated", self.handle_user_created)
    
    async def shutdown(self):
        """Clean shutdown."""
        logger.info("Shutting down {{cookiecutter.plugin_name}}")
        await self.event_bus.disconnect()
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check implementation."""
        return {
            "status": "healthy",
            "plugin_id": self.plugin_id,
            "version": self.manifest["version"]
        }
    
    @event_handler("UserCreated")
    {% if cookiecutter.handles_phi %}
    @require_traits(["handles_phi"])
    {% endif %}
    async def handle_user_created(self, event: Dict):
        """Handle user creation event."""
        user_id = event["payload"]["user_id"]
        logger.info(f"Processing new user: {user_id}")
        
        # Implement your logic here
        try:
            # Example: Set up user preferences
            await self.setup_user_preferences(user_id)
            
            # Publish completion event
            await self.event_bus.publish(
                "UserSetupCompleted",
                {"user_id": user_id},
                {% if cookiecutter.handles_phi %}
                data_traits=["phi"]
                {% else %}
                data_traits=[]
                {% endif %}
            )
        except Exception as e:
            logger.error(f"Failed to process user {user_id}: {e}")
            raise
    
    @rpc_endpoint("/api/{{cookiecutter.plugin_id}}/process")
    async def process_request(self, request: Dict) -> Dict:
        """Process an RPC request."""
        # Validate input
        if "data" not in request:
            raise ValueError("Missing required field: data")
        
        # Process request
        result = await self.process_data(request["data"])
        
        return {
            "status": "success",
            "result": result
        }
    
    async def process_data(self, data: Any) -> Any:
        """Process data - implement your logic."""
        # TODO: Implement your business logic
        return {"processed": True}
    
    {% if cookiecutter.handles_phi %}
    def setup_phi_compliance(self):
        """Set up PHI compliance measures."""
        # Enable encryption
        self.enable_encryption()
        
        # Set up audit logging
        self.enable_detailed_audit()
        
        # Configure data retention
        self.set_retention_policy(days=2555)  # 7 years for HIPAA
    {% endif %}

if __name__ == "__main__":
    plugin = {{cookiecutter.plugin_name.replace(' ', '')}}Plugin()
    plugin.run()
```

### 4. Reference Plugin Implementations

#### 4.1 Complete Email Gateway Plugin
```python
# plugins/email_gateway/main.py
from vivified import VivifiedPlugin, event_handler, rpc_endpoint, audit_log
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
import logging
from typing import Dict, List, Optional
import asyncio

logger = logging.getLogger(__name__)

class EmailGatewayPlugin(VivifiedPlugin):
    """Email gateway plugin for sending notifications."""
    
    async def initialize(self):
        """Initialize email gateway."""
        logger.info("Initializing Email Gateway")
        
        # Load configuration
        config = await self.get_config()
        self.smtp_host = config.get("smtp_host", "localhost")
        self.smtp_port = config.get("smtp_port", 587)
        self.smtp_user = config.get("smtp_user")
        self.smtp_password = config.get("smtp_password")
        self.from_address = config.get("from_address", "noreply@vivified.local")
        self.use_tls = config.get("use_tls", True)
        
        # Load email templates
        self.templates = await self.load_templates()
        
        # Subscribe to events that trigger emails
        await self.event_bus.subscribe("UserCreated", self.send_welcome_email)
        await self.event_bus.subscribe("PasswordReset", self.send_password_reset)
        await self.event_bus.subscribe("SecurityAlert", self.send_security_alert)
        
        # Set up email queue for batch processing
        self.email_queue = asyncio.Queue()
        asyncio.create_task(self.process_email_queue())
    
    async def load_templates(self) -> Dict[str, Template]:
        """Load email templates."""
        templates = {}
        
        # Welcome email template
        templates["welcome"] = Template("""
        <!DOCTYPE html>
        <html>
        <head><title>Welcome to Vivified</title></head>
        <body>
            <h1>Welcome, {{ name }}!</h1>
            <p>Your account has been created successfully.</p>
            <p>Department: {{ department }}</p>
            <p>Please <a href="{{ activation_link }}">activate your account</a>.</p>
        </body>
        </html>
        """)
        
        # Password reset template
        templates["password_reset"] = Template("""
        <!DOCTYPE html>
        <html>
        <head><title>Password Reset</title></head>
        <body>
            <h1>Password Reset Request</h1>
            <p>Click <a href="{{ reset_link }}">here</a> to reset your password.</p>
            <p>This link expires in 1 hour.</p>
        </body>
        </html>
        """)
        
        # Security alert template
        templates["security_alert"] = Template("""
        <!DOCTYPE html>
        <html>
        <head><title>Security Alert</title></head>
        <body>
            <h1>Security Alert</h1>
            <p><strong>{{ alert_type }}</strong></p>
            <p>{{ message }}</p>
            <p>Time: {{ timestamp }}</p>
            <p>Please review your account activity.</p>
        </body>
        </html>
        """)
        
        return templates
    
    @event_handler("UserCreated")
    @audit_log("email_sent")
    async def send_welcome_email(self, event: Dict):
        """Send welcome email to new user."""
        user_data = event["payload"]
        
        # Get user details via RPC if needed
        user_details = await self.rpc_client.call(
            "user-management",
            "get_user_details",
            {"user_id": user_data["user_id"]}
        )
        
        # Prepare email
        email_data = {
            "to": user_data["email"],
            "subject": "Welcome to Vivified Platform",
            "template": "welcome",
            "variables": {
                "name": user_details.get("name", "User"),
                "department": user_details.get("department", "N/A"),
                "activation_link": f"https://vivified.example.com/activate/{user_data['activation_token']}"
            }
        }
        
        # Queue email
        await self.email_queue.put(email_data)
        
        # Publish event
        await self.event_bus.publish(
            "EmailQueued",
            {"email_id": email_data["to"], "type": "welcome"},
            data_traits=["pii"]  # Email is PII
        )
    
    @rpc_endpoint("/api/email/send")
    @audit_log("email_api_send")
    async def send_email_api(self, request: Dict) -> Dict:
        """RPC endpoint to send email."""
        required_fields = ["to", "subject", "body"]
        missing = [f for f in required_fields if f not in request]
        if missing:
            raise ValueError(f"Missing fields: {missing}")
        
        # Validate email address
        if not self.is_valid_email(request["to"]):
            raise ValueError("Invalid email address")
        
        # Check if recipient opted out
        if await self.is_opted_out(request["to"]):
            return {"status": "skipped", "reason": "opted_out"}
        
        # Send email
        success = await self.send_email(
            to=request["to"],
            subject=request["subject"],
            body=request["body"],
            html=request.get("html", False)
        )
        
        return {
            "status": "sent" if success else "failed",
            "email_id": self.generate_email_id()
        }
    
    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        html: bool = False,
        cc: Optional[List[str]] = None
    ) -> bool:
        """Send an email via SMTP."""
        try:
            # Create message
            msg = MIMEMultipart("alternative") if html else MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.from_address
            msg["To"] = to
            if cc:
                msg["Cc"] = ", ".join(cc)
            
            if html:
                msg.attach(MIMEText(body, "html"))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                
                # Send email
                recipients = [to] + (cc or [])
                server.send_message(msg, to_addrs=recipients)
            
            logger.info(f"Email sent to {to}")
            
            # Publish success event
            await self.event_bus.publish(
                "EmailSent",
                {
                    "to": to,
                    "subject": subject,
                    "timestamp": self.get_timestamp()
                },
                data_traits=["pii"]
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to}: {e}")
            
            # Publish failure event
            await self.event_bus.publish(
                "EmailFailed",
                {
                    "to": to,
                    "error": str(e),
                    "timestamp": self.get_timestamp()
                },
                data_traits=["pii"]
            )
            
            return False
    
    async def process_email_queue(self):
        """Process queued emails in batches."""
        while True:
            try:
                # Collect batch
                batch = []
                for _ in range(10):  # Process up to 10 emails at once
                    try:
                        email = await asyncio.wait_for(
                            self.email_queue.get(),
                            timeout=1.0
                        )
                        batch.append(email)
                    except asyncio.TimeoutError:
                        break
                
                # Send batch
                if batch:
                    logger.info(f"Processing {len(batch)} queued emails")
                    for email_data in batch:
                        # Render template if specified
                        if "template" in email_data:
                            template = self.templates.get(email_data["template"])
                            if template:
                                body = template.render(email_data.get("variables", {}))
                                await self.send_email(
                                    to=email_data["to"],
                                    subject=email_data["subject"],
                                    body=body,
                                    html=True
                                )
                
                await asyncio.sleep(5)  # Wait before next batch
                
            except Exception as e:
                logger.error(f"Email queue processing error: {e}")
                await asyncio.sleep(10)
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email address format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    async def is_opted_out(self, email: str) -> bool:
        """Check if email is on opt-out list."""
        # Check with preference service
        try:
            result = await self.rpc_client.call(
                "preference-service",
                "check_opt_out",
                {"email": email}
            )
            return result.get("opted_out", False)
        except:
            # Default to not opted out if service unavailable
            return False
```

## Validation Checklist

### SDK Validation
- [ ] Python SDK fully functional
- [ ] Node.js SDK tested
- [ ] Go SDK operational
- [ ] All SDKs handle PHI traits correctly
- [ ] Authentication working in all SDKs
- [ ] Event handling tested
- [ ] RPC calls functional
- [ ] Metrics collection working

### CLI Tool Validation
- [ ] Plugin creation from templates
- [ ] Manifest validation working
- [ ] Test runner functional
- [ ] Deploy command tested
- [ ] All languages supported
- [ ] PHI handling flags working

### Template Validation
- [ ] Python template generates valid plugin
- [ ] Node.js template working
- [ ] Go template functional
- [ ] PHI compliance included when selected
- [ ] Tests included in templates
- [ ] Docker files generated

### Reference Plugin Validation
- [ ] Email Gateway fully implemented
- [ ] SMTP integration tested
- [ ] Template rendering working
- [ ] Queue processing functional
- [ ] Events published correctly
- [ ] Audit logging complete
- [ ] Error handling robust

## Next Steps
Proceed to Runbook 06 for comprehensive Security Implementation Guide.