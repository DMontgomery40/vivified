# Runbook 01: Phase 1 - Core Scaffolding & Plugin Interface Baseline

## Objective
Set up the basic project skeleton, implement a minimal running core service, define plugin interfaces and manifest schema, and register a simple example plugin.

## Prerequisites
- Git repository access
- Docker and Docker Compose installed
- Python 3.11+, Node.js 18+, Go 1.21+
- CI/CD platform access (GitHub Actions)

## Tasks

### 1. Initialize Repository & CI

#### 1.1 Repository Setup
```bash
# Create repository structure
mkdir -p vivified/{core,plugins,sdk,tools,docs,k8s}
cd vivified

# Initialize submodules
mkdir -p core/{proto,gateway,identity,config,policy,messaging,plugin_manager,storage,canonical,audit,ui}
mkdir -p plugins/{email_gateway,user_management}
mkdir -p sdk/{python,nodejs,go}
mkdir -p tools/{cli,validator,templates}

# Create essential files
touch README.md LICENSE .gitignore docker-compose.yml Makefile mkdocs.yml
```

#### 1.2 Git Configuration
```bash
# Initialize git
git init
git checkout -b develop

# Configure .gitignore
cat > .gitignore << EOF
# Python
__pycache__/
*.py[cod]
venv/
.env
.pytest_cache/

# Node
node_modules/
dist/
.npm

# Go
vendor/
bin/

# Docker
.docker/

# Security
*.key
*.pem
*.crt
secrets/

# IDE
.vscode/
.idea/
EOF
```

#### 1.3 CI Pipeline Setup
```yaml
# .github/workflows/ci.yml
name: CI Pipeline
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security scan
        run: |
          pip install safety bandit
          safety check
          bandit -r core/
      
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Python lint
        run: |
          pip install black flake8 mypy
          black --check core/
          flake8 core/
          mypy core/
  
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: |
          pip install pytest pytest-cov
          pytest --cov=core --cov-report=xml
      - name: Check coverage
        run: |
          coverage report --fail-under=80
```

### 2. Core Application Skeleton

#### 2.1 Core Service Structure
```python
# core/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime
import os

# Configure logging for HIPAA compliance
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - trace_id=%(trace_id)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Vivified Core Platform",
    version="1.0.0",
    docs_url=None,  # Disable in production
    redoc_url=None
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.on_event("startup")
async def startup_event():
    logger.info("Vivified Core Platform starting", extra={"trace_id": "system"})
    # Initialize core services here
    
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Vivified Core Platform shutting down", extra={"trace_id": "system"})
```

#### 2.2 Dockerfile for Core
```dockerfile
# core/Dockerfile
FROM python:3.11-alpine AS base

# Security: Create non-root user
RUN adduser -D -H -s /bin/sh vivified

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=vivified:vivified . .

# Security: Run as non-root
USER vivified

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')"

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 3. Define Plugin Interface Contracts

#### 3.1 Base Plugin Interface
```python
# core/plugin_interface.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

@dataclass
class PluginManifest:
    """Plugin manifest structure."""
    id: str
    name: str
    version: str
    description: str
    contracts: List[str]
    traits: List[str]
    dependencies: List[str]
    allowed_domains: List[str]
    endpoints: Dict[str, str]
    security: Dict[str, Any]
    compliance: Dict[str, Any]

class PluginBase(ABC):
    """Base class all plugins must implement."""
    
    @abstractmethod
    async def initialize(self, core_context: Dict[str, Any]) -> bool:
        """Initialize plugin with core context."""
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """Clean shutdown of plugin."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Return plugin health status."""
        pass
    
    @abstractmethod
    def get_manifest(self) -> PluginManifest:
        """Return plugin manifest."""
        pass

class CommunicationPlugin(PluginBase):
    """Interface for communication plugins."""
    
    @abstractmethod
    async def send_message(self, message: Dict[str, Any]) -> str:
        """Send a message through the communication channel."""
        pass
    
    @abstractmethod
    async def receive_messages(self) -> List[Dict[str, Any]]:
        """Retrieve pending messages."""
        pass

class StoragePlugin(PluginBase):
    """Interface for storage plugins."""
    
    @abstractmethod
    async def store(self, data: bytes, metadata: Dict[str, Any]) -> str:
        """Store data with metadata, return ID."""
        pass
    
    @abstractmethod
    async def retrieve(self, id: str) -> Optional[bytes]:
        """Retrieve data by ID."""
        pass
    
    @abstractmethod
    async def delete(self, id: str) -> bool:
        """Delete data by ID."""
        pass
```

#### 3.2 Canonical Data Models
```protobuf
# core/proto/canonical_models.proto
syntax = "proto3";

package vivified.canonical;

import "google/protobuf/timestamp.proto";
import "google/protobuf/any.proto";

// Event envelope for all canonical events
message CanonicalEvent {
  string event_id = 1;
  string trace_id = 2;
  string event_type = 3;
  google.protobuf.Timestamp timestamp = 4;
  string source_plugin = 5;
  repeated string data_traits = 6;  // PHI, PII, confidential
  google.protobuf.Any payload = 7;
  map<string, string> metadata = 8;
}

// Canonical user representation
message CanonicalUser {
  string id = 1;
  string username = 2;
  string email = 3;
  repeated string roles = 4;
  repeated string traits = 5;
  google.protobuf.Timestamp created_at = 6;
  map<string, string> attributes = 7;
}

// Canonical message for communication
message CanonicalMessage {
  string id = 1;
  string from_user = 2;
  string to_user = 3;
  string content_type = 4;
  bytes content = 5;
  repeated string data_traits = 6;
  google.protobuf.Timestamp sent_at = 7;
}
```

#### 3.3 Plugin Manifest Schema
```json
# tools/validator/manifest_schema.json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["id", "name", "version", "contracts", "traits", "security", "compliance"],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-z0-9-]+$"
    },
    "name": {
      "type": "string"
    },
    "version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$"
    },
    "description": {
      "type": "string"
    },
    "contracts": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["CommunicationPlugin", "StoragePlugin", "IdentityPlugin"]
      }
    },
    "traits": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["handles_phi", "handles_pii", "requires_encryption", "external_service", "audit_required"]
      }
    },
    "dependencies": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "allowed_domains": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "endpoints": {
      "type": "object"
    },
    "security": {
      "type": "object",
      "required": ["authentication_required", "data_classification"],
      "properties": {
        "authentication_required": {
          "type": "boolean"
        },
        "data_classification": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["public", "internal", "confidential", "phi", "pii"]
          }
        }
      }
    },
    "compliance": {
      "type": "object",
      "required": ["hipaa_controls", "audit_level"],
      "properties": {
        "hipaa_controls": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "audit_level": {
          "type": "string",
          "enum": ["none", "basic", "detailed", "complete"]
        }
      }
    }
  }
}
```

### 4. Basic Plugin Registration Mechanism

#### 4.1 Plugin Registry Implementation
```python
# core/plugin_manager/registry.py
from typing import Dict, Optional, List
from datetime import datetime
import uuid
import jwt
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

class PluginRegistry:
    """Manages plugin registration and lifecycle."""
    
    def __init__(self, jwt_secret: str):
        self.plugins: Dict[str, Dict] = {}
        self.jwt_secret = jwt_secret
        
    async def register_plugin(self, manifest: Dict) -> Dict:
        """Register a new plugin with the core."""
        plugin_id = manifest.get("id")
        
        # Validate manifest
        if not self._validate_manifest(manifest):
            raise HTTPException(status_code=400, detail="Invalid manifest")
        
        # Check for duplicate registration
        if plugin_id in self.plugins:
            raise HTTPException(status_code=409, detail="Plugin already registered")
        
        # Generate authentication token for plugin
        token = self._generate_plugin_token(plugin_id)
        
        # Store plugin information
        self.plugins[plugin_id] = {
            "manifest": manifest,
            "status": "registered",
            "registered_at": datetime.utcnow().isoformat(),
            "last_heartbeat": datetime.utcnow().isoformat(),
            "token": token,
            "health": "unknown"
        }
        
        logger.info(f"Plugin registered: {plugin_id}", extra={"trace_id": str(uuid.uuid4())})
        
        return {
            "status": "registered",
            "token": token,
            "plugin_id": plugin_id
        }
    
    def _validate_manifest(self, manifest: Dict) -> bool:
        """Validate plugin manifest against schema."""
        # Implement JSON schema validation
        required_fields = ["id", "name", "version", "contracts", "traits", "security", "compliance"]
        return all(field in manifest for field in required_fields)
    
    def _generate_plugin_token(self, plugin_id: str) -> str:
        """Generate JWT token for plugin authentication."""
        payload = {
            "plugin_id": plugin_id,
            "type": "plugin",
            "issued_at": datetime.utcnow().isoformat()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    async def heartbeat(self, plugin_id: str, status: Dict) -> bool:
        """Update plugin heartbeat and status."""
        if plugin_id not in self.plugins:
            return False
        
        self.plugins[plugin_id]["last_heartbeat"] = datetime.utcnow().isoformat()
        self.plugins[plugin_id]["health"] = status.get("health", "healthy")
        return True
```

### 5. Create Example Plugin

#### 5.1 User Management Plugin
```python
# plugins/user_management/main.py
from fastapi import FastAPI
import httpx
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="User Management Plugin")

CORE_URL = os.getenv("CORE_URL", "http://vivified-core:8000")
PLUGIN_ID = "user-management"

# Plugin manifest
MANIFEST = {
    "id": PLUGIN_ID,
    "name": "User Management Plugin",
    "version": "1.0.0",
    "description": "Manages user profiles and extended attributes",
    "contracts": ["IdentityPlugin"],
    "traits": ["handles_pii", "audit_required"],
    "dependencies": [],
    "allowed_domains": [],
    "endpoints": {
        "health": "/health",
        "user_info": "/api/users/{id}"
    },
    "security": {
        "authentication_required": True,
        "data_classification": ["pii", "internal"]
    },
    "compliance": {
        "hipaa_controls": ["164.312(a)", "164.312(d)"],
        "audit_level": "detailed"
    }
}

@app.on_event("startup")
async def register_with_core():
    """Register this plugin with the core on startup."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{CORE_URL}/plugins/register",
                json=MANIFEST
            )
            if response.status_code == 200:
                data = response.json()
                # Store token for future use
                os.environ["PLUGIN_TOKEN"] = data["token"]
                logger.info(f"Successfully registered with core: {data}")
            else:
                logger.error(f"Failed to register: {response.text}")
        except Exception as e:
            logger.error(f"Registration error: {e}")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "plugin": PLUGIN_ID}

@app.get("/api/users/{user_id}")
async def get_user_info(user_id: str):
    """Get extended user information."""
    # Placeholder implementation
    return {
        "user_id": user_id,
        "department": "Engineering",
        "manager": "manager-123",
        "traits": ["handles_pii"]
    }
```

### 6. Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

networks:
  vivified-net:
    driver: bridge

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: vivified
      POSTGRES_USER: vivified
      POSTGRES_PASSWORD: ${DB_PASSWORD:-changeme}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - vivified-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vivified"]
      interval: 10s
      timeout: 5s
      retries: 5

  nats:
    image: nats:2.10-alpine
    command: ["-js", "-m", "8222"]
    ports:
      - "4222:4222"
      - "8222:8222"
    networks:
      - vivified-net
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "4222"]
      interval: 10s
      timeout: 5s
      retries: 5

  vivified-core:
    build: ./core
    environment:
      DATABASE_URL: postgresql://vivified:${DB_PASSWORD:-changeme}@postgres:5432/vivified
      NATS_URL: nats://nats:4222
      JWT_SECRET: ${JWT_SECRET:-change-this-secret}
      LOG_LEVEL: INFO
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      nats:
        condition: service_healthy
    networks:
      - vivified-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  user-management-plugin:
    build: ./plugins/user_management
    environment:
      CORE_URL: http://vivified-core:8000
      LOG_LEVEL: INFO
    depends_on:
      vivified-core:
        condition: service_healthy
    networks:
      - vivified-net
    restart: unless-stopped

volumes:
  postgres_data:
```

### 7. Makefile

```makefile
# Makefile
.PHONY: help build up down test lint proto clean

help:
	@echo "Available commands:"
	@echo "  make build   - Build all Docker images"
	@echo "  make up      - Start all services"
	@echo "  make down    - Stop all services"
	@echo "  make test    - Run tests"
	@echo "  make lint    - Run linters"
	@echo "  make proto   - Compile protobuf files"
	@echo "  make clean   - Clean build artifacts"

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

test:
	pytest tests/ --cov=core --cov-report=html

lint:
	black core/ plugins/
	flake8 core/ plugins/
	mypy core/

proto:
	protoc -I=core/proto --python_out=core/proto core/proto/*.proto

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	docker-compose down -v
```

## Validation Steps

### Phase 1 Checklist
- [ ] Repository structure created
- [ ] CI/CD pipeline configured and passing
- [ ] Core service starts and health endpoint responds
- [ ] Plugin interfaces defined
- [ ] Canonical models defined in protobuf
- [ ] Manifest schema validated
- [ ] Plugin registration endpoint working
- [ ] Example plugin successfully registers
- [ ] Docker Compose brings up all services
- [ ] Network connectivity verified between services
- [ ] Basic logging implemented
- [ ] Non-root containers verified
- [ ] Documentation updated

## Security Considerations
- All services run as non-root users
- JWT secrets stored in environment variables
- Network isolation between services
- Health checks don't expose sensitive information
- Logging configured without PII/PHI

## Next Steps
After completing Phase 1, proceed to Runbook 02 for implementing core services (Identity, Configuration, Policy Engine).