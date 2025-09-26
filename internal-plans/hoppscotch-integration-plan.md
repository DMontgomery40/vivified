# Hoppscotch Integration Plan for Vivified Platform

> Revised to match the current Vivi architecture. This adds an MVP that uses the existing external-plugin model (`/plugins`, `/run`, `/state`) and removes assumptions that do not exist in this repo (custom FastAPI routers per plugin, DB providers, Python plugin base classes). The sections below supersede any conflicting details later in this file.

## Reality Check vs Current Codebase

- Plugins implement a minimal protocol (`init`, `run`) and can be external executables speaking JSON-over-stdio; the Kernel enforces required traits and executes by name.
- API already exposes everything needed: `GET /plugins`, `POST /run { plugin, args }`, and `GET/POST /state` for trait/disable management.
- Admin Console already talks to these endpoints via `admin/src/api.ts`.

Implication: MVP should be a single external executable plugin named `hoppscotch`, registered via `plugins.d`, invoked from the Admin UI through `/run`. No new FastAPI router or DB migrations are required to ship.

## MVP Plan (Ship Safely and Quickly)

1) Build an external executable `hoppscotch-vivi` (Node.js recommended) implementing three JSON-over-stdio methods:
   - `capabilities` → `{ name: "hoppscotch", version, capabilities:["api_testing"], requires_traits:["api_testing"] }`
   - `init` → reads env + traits and discovers CLI path
   - `run` → subcommands:
     - `version` → verifies Hoppscotch CLI, prints one-line JSON, exits 0/!=0
     - `exec <METHOD> <URL> [--header k:v]* [--data base64json] [--timeout ms]` → executes one request using `hopp` if present, else a built-in HTTP fetch fallback

2) Register it via `plugins.d` so the API auto-loads it on start (example file `plugins.d/hoppscotch.json`): `{ "executables": ["/usr/local/bin/hoppscotch-vivi"] }`.

3) Admin UI page `APIDevelopment` uses `runPlugin("hoppscotch", ["version"])` to show readiness and a small form mapping to `runPlugin("hoppscotch", ["exec", method, url, ...])`.

4) Trait gating: require `api_testing`. During dev, add it with `POST /state`.

Configuration via existing env provider:
- `HOPPSCOTCH_CLI_PATH` (default `hopp`)
- `HOPPSCOTCH_TIMEOUT_MS` (default `30000`)
- `HOPPSCOTCH_DEFAULT_HEADERS` (JSON string merged into requests)

## External Plugin I/O Contract

- One-line JSON in/out on stdout; never print logs to stdout; stderr for diagnostics only.
- Success examples (single-line JSON):
  - version: `{ "ok": true, "cli": "hopp", "version": "1.2.3" }`
  - exec: `{ "status": 200, "duration_ms": 123, "headers": {"content-type":"application/json"}, "body_preview": "{...", "ok": true }`
- Failure example: `{ "status": 500, "duration_ms": 456, "error": "Internal Server Error", "ok": false }`

## Smoke Tests

- Registration: place executable + `plugins.d/hoppscotch.json`; start API; `GET /plugins` includes `hoppscotch`.
- Traits: with `api_testing` absent, `/run` on `["version"]` fails with missing trait; add trait and retry succeeds.
- CLI presence: bad `HOPPSCOTCH_CLI_PATH` makes `version` nonzero; UI shows error.
- Happy path: `/run` with `["exec","GET","https://httpbin.org/get"]` → code 0 and `ok:true`.
- Error path: invalid host → nonzero and `ok:false`.
- Timeout: `--timeout 1` against a slow endpoint → returns quickly and nonzero.
- UI: APIDevelopment shows readiness after `version` passes; executes and renders JSON result.

## Risks & Mitigations

- Assumed per-plugin FastAPI router (not present): use `/run` for MVP; consider routers later.
- No DB/storage provider in Kernel: Phase 2 uses file-backed collections under `~/.vivi/hoppscotch`; Phase 3 introduces DB.
- Stdio fragility: enforce single-line JSON; flush; kill child on timeout.
- CLI variance across OS: `version` check and HTTP fallback; override path via `HOPPSCOTCH_CLI_PATH`.
- Secrets in URLs: prefer headers/body; redact; never echo secrets in UI.
- Rate limits: client throttling and optional exponential backoff.

Further hardening: [dev.to](https://dev.to/hoss/3-common-api-integration-mistakes-and-how-to-avoid-them-1k51?utm_source=openai), [appicsoftwares.com](https://appicsoftwares.com/blog/mistakes-to-avoid-while-integrating-apis-into-your-app/?utm_source=openai), [apicove.com](https://apicove.com/blog/api-integration-challenges-and-solutions/?utm_source=openai), [integrate.io](https://www.integrate.io/blog/top-10-mistakes-made-by-api-developers/?utm_source=openai), [medium.com](https://medium.com/big-data-processing/the-hidden-pitfalls-of-api-integration-and-how-to-fix-them-1f051997c78e?utm_source=openai).

## Deployment Notes

- Ensure `hoppscotch-vivi` is executable and on PATH or referenced explicitly in `plugins.d`.
- Set `HOPPSCOTCH_*` env vars in the API container; Admin `.env` sets `VITE_API_BASE`.

## Phase 2–3 (Beyond MVP)

- File-backed collections/environments first; then DB with migrations.
- Collaboration behind `team_collaboration` trait; optional Hoppscotch Cloud sync.
- Scheduled runs/monitors via plugin args; surface execution history in UI.

## Executive Summary

This document provides a comprehensive plan for integrating Hoppscotch (API testing tool) into the Vivified platform as a plugin. The integration will allow users to build, test, and manage their APIs directly within the Vivified Admin Console, leveraging Vivified's modular plugin architecture and trait-based access control.

## Context & Platform Understanding

### Vivified Platform Architecture
- **Modular Design**: Every component is a plugin following strict interfaces
- **Trait-Based Access**: Features are gated by user capabilities (traits)
- **Hierarchical Configuration**: Global → Tenant → Group → User configuration inheritance
- **Canonical Models**: Standardized data formats across all plugins
- **Admin Console First**: Primary interface for all user operations
- **Plugin Discovery**: Manifest-based plugin loading and validation

### Hoppscotch Capabilities
- **API Testing**: REST, GraphQL, WebSocket testing
- **Collection Management**: Organize requests into collections
- **Environment Variables**: Dynamic configuration management
- **CLI Interface**: Command-line execution for automation
- **Team Collaboration**: Shared collections and environments
- **Import/Export**: Support for various API formats (OpenAPI, Postman, etc.)

## Integration Architecture

### Plugin Type: `api_development`
```json
{
  "id": "hoppscotch_integration",
  "type": "api_development",
  "traits": [
    "api_testing",
    "collection_management", 
    "environment_management",
    "team_collaboration",
    "import_export"
  ],
  "required_scope": "trusted"
}
```

### Core Components

1. **Hoppscotch Plugin** (`api/app/plugins/api_development/hoppscotch/`)
2. **CLI Wrapper Service** (Node.js service for Hoppscotch CLI)
3. **Collection Storage** (Database integration)
4. **Environment Manager** (Configuration integration)
5. **UI Components** (React components for Admin Console)

## Detailed Implementation Plan

### Phase 1: Foundation Setup (Week 1-2)

#### 1.1 Plugin Structure Creation
Create the plugin directory structure following Vivified conventions:

```
api/app/plugins/api_development/hoppscotch/
├── manifest.json
├── plugin.py
├── cli_wrapper/
│   ├── package.json
│   ├── wrapper.js
│   └── hoppscotch-service.js
├── ui/
│   ├── HoppscotchPanel.tsx
│   ├── CollectionManager.tsx
│   ├── RequestBuilder.tsx
│   └── EnvironmentEditor.tsx
├── models/
│   ├── collection.py
│   ├── request.py
│   └── environment.py
└── services/
    ├── cli_service.py
    ├── collection_service.py
    └── environment_service.py
```

#### 1.2 Plugin Manifest
```json
{
  "id": "hoppscotch_integration",
  "version": "1.0.0",
  "type": "api_development",
  "name": "Hoppscotch API Development",
  "description": "Integrated API testing and development environment",
  
  "core_version_required": ">=3.0.0",
  "plugin_api_version": "1.0",
  
  "contracts": [
    "api_development:1.0",
    "collection_management:1.0"
  ],
  
  "dependencies": {
    "config_provider": ">=1.0",
    "storage_provider": ">=1.0",
    "identity_provider": ">=1.0"
  },
  
  "traits": {
    "provides": [
      "api_testing",
      "collection_management",
      "environment_management",
      "team_collaboration",
      "import_export"
    ],
    "requires": ["internet_access"],
    "optional": ["hipaa_compliant"]
  },
  
  "permissions": {
    "create_collection": {
      "default_unix": "664",
      "description": "Create API collections",
      "required_traits": ["api_testing"]
    },
    "execute_requests": {
      "default_unix": "644", 
      "description": "Execute API requests",
      "required_traits": ["api_testing"]
    },
    "manage_environments": {
      "default_unix": "600",
      "description": "Manage API environments",
      "required_traits": ["environment_management"]
    }
  },
  
  "configuration_schema": {
    "hoppscotch_cli_path": {
      "type": "string",
      "default": "/usr/local/bin/hopp",
      "description": "Path to Hoppscotch CLI executable"
    },
    "max_collections": {
      "type": "integer",
      "default": 50,
      "minimum": 1,
      "maximum": 1000
    },
    "request_timeout": {
      "type": "integer", 
      "default": 30,
      "minimum": 5,
      "maximum": 300
    }
  },
  
  "ui_components": {
    "main_panel": {
      "component": "/plugins/hoppscotch/ui/HoppscotchPanel.tsx",
      "traits": ["api_testing"]
    },
    "collection_manager": {
      "component": "/plugins/hoppscotch/ui/CollectionManager.tsx", 
      "traits": ["collection_management"]
    }
  },
  
  "database_migrations": [
    "001_create_hoppscotch_collections.sql",
    "002_create_hoppscotch_requests.sql", 
    "003_create_hoppscotch_environments.sql"
  ]
}
```

#### 1.3 Base Plugin Class
```python
# api/app/plugins/api_development/hoppscotch/plugin.py
from api.app.plugins.base import ApiDevelopmentPlugin
from api.app.canonical import CanonicalRequest, CanonicalResponse
from api.app.plugins.api_development.hoppscotch.services import (
    CLIService, CollectionService, EnvironmentService
)

class HoppscotchPlugin(ApiDevelopmentPlugin):
    """Hoppscotch API development plugin"""
    
    plugin_name = "Hoppscotch Integration"
    plugin_type = "api_development"
    required_scope = "trusted"
    traits = {
        "api_testing", "collection_management", 
        "environment_management", "team_collaboration"
    }
    
    def __init__(self, config_provider, storage_provider, identity_provider):
        super().__init__()
        self.config = config_provider
        self.storage = storage_provider
        self.identity = identity_provider
        
        # Initialize services
        self.cli_service = CLIService(config_provider)
        self.collection_service = CollectionService(storage_provider)
        self.environment_service = EnvironmentService(config_provider)
        
    async def initialize(self) -> bool:
        """Initialize Hoppscotch plugin"""
        try:
            # Verify Hoppscotch CLI is available
            if not await self.cli_service.verify_installation():
                raise RuntimeError("Hoppscotch CLI not found")
                
            # Initialize database tables
            await self._run_migrations()
            
            # Register with core platform
            self.core_platform.register_plugin(self)
            
            return True
        except Exception as e:
            audit_event('hoppscotch_plugin_init_failed', error=str(e))
            return False
    
    async def execute_request(self, request: CanonicalRequest) -> CanonicalResponse:
        """Execute API request via Hoppscotch CLI"""
        return await self.cli_service.execute_request(request)
    
    async def create_collection(self, name: str, description: str = None) -> str:
        """Create new API collection"""
        return await self.collection_service.create_collection(name, description)
    
    async def get_collections(self, user_context: UserContext) -> List[Collection]:
        """Get user's API collections"""
        return await self.collection_service.get_user_collections(user_context)
```

### Phase 2: CLI Integration Service (Week 3-4)

#### 2.1 Node.js CLI Wrapper
Create a Node.js service to interface with Hoppscotch CLI:

```javascript
// cli_wrapper/hoppscotch-service.js
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class HoppscotchService {
    constructor(config) {
        this.cliPath = config.hoppscotch_cli_path || 'hopp';
        this.timeout = config.request_timeout || 30000;
    }
    
    async executeRequest(requestData) {
        return new Promise((resolve, reject) => {
            const tempFile = `/tmp/hoppscotch-${Date.now()}.json`;
            
            // Write request to temp file
            fs.writeFile(tempFile, JSON.stringify(requestData))
                .then(() => {
                    // Execute Hoppscotch CLI
                    const hopp = spawn(this.cliPath, ['run', tempFile], {
                        timeout: this.timeout
                    });
                    
                    let stdout = '';
                    let stderr = '';
                    
                    hopp.stdout.on('data', (data) => {
                        stdout += data.toString();
                    });
                    
                    hopp.stderr.on('data', (data) => {
                        stderr += data.toString();
                    });
                    
                    hopp.on('close', (code) => {
                        // Cleanup temp file
                        fs.unlink(tempFile).catch(() => {});
                        
                        if (code === 0) {
                            resolve({
                                success: true,
                                response: JSON.parse(stdout),
                                rawOutput: stdout
                            });
                        } else {
                            reject(new Error(`Hoppscotch CLI failed: ${stderr}`));
                        }
                    });
                })
                .catch(reject);
        });
    }
    
    async createCollection(collectionData) {
        // Implementation for creating collections
    }
    
    async exportCollection(collectionId, format = 'json') {
        // Implementation for exporting collections
    }
}

module.exports = HoppscotchService;
```

#### 2.2 Python CLI Service
```python
# services/cli_service.py
import asyncio
import json
import tempfile
import subprocess
from typing import Dict, Any, Optional

class CLIService:
    def __init__(self, config_provider: ConfigProvider):
        self.config = config_provider
        self.cli_path = None
        self.timeout = 30
        
    async def initialize(self):
        """Initialize CLI service with configuration"""
        self.cli_path = await self.config.get(
            'hoppscotch_integration.hoppscotch_cli_path',
            default='hopp'
        )
        self.timeout = await self.config.get(
            'hoppscotch_integration.request_timeout',
            default=30
        )
    
    async def verify_installation(self) -> bool:
        """Verify Hoppscotch CLI is installed and accessible"""
        try:
            result = await asyncio.create_subprocess_exec(
                self.cli_path, '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            return result.returncode == 0
        except Exception:
            return False
    
    async def execute_request(self, request: CanonicalRequest) -> CanonicalResponse:
        """Execute API request using Hoppscotch CLI"""
        try:
            # Convert canonical request to Hoppscotch format
            hoppscotch_request = self._canonical_to_hoppscotch(request)
            
            # Create temporary file for request
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(hoppscotch_request, f)
                temp_file = f.name
            
            try:
                # Execute Hoppscotch CLI
                process = await asyncio.create_subprocess_exec(
                    self.cli_path, 'run', temp_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                if process.returncode != 0:
                    raise RuntimeError(f"Hoppscotch CLI failed: {stderr.decode()}")
                
                # Parse response
                response_data = json.loads(stdout.decode())
                return self._hoppscotch_to_canonical(response_data)
                
            finally:
                # Cleanup temp file
                os.unlink(temp_file)
                
        except Exception as e:
            audit_event('hoppscotch_request_failed', error=str(e))
            raise
    
    def _canonical_to_hoppscotch(self, request: CanonicalRequest) -> Dict[str, Any]:
        """Convert canonical request to Hoppscotch format"""
        return {
            "name": request.name or "API Request",
            "method": request.method.upper(),
            "url": request.url,
            "headers": request.headers or {},
            "body": request.body,
            "params": request.query_params or {}
        }
    
    def _hoppscotch_to_canonical(self, response_data: Dict[str, Any]) -> CanonicalResponse:
        """Convert Hoppscotch response to canonical format"""
        return CanonicalResponse(
            status_code=response_data.get('status', 200),
            headers=response_data.get('headers', {}),
            body=response_data.get('body', ''),
            execution_time=response_data.get('duration', 0),
            success=200 <= response_data.get('status', 0) < 300
        )
```

### Phase 3: Database Models & Services (Week 5-6)

#### 3.1 Database Schema
```sql
-- Collections table
CREATE TABLE hoppscotch_collections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id VARCHAR(100),
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, name)
);

-- Requests table  
CREATE TABLE hoppscotch_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID NOT NULL REFERENCES hoppscotch_collections(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    headers JSONB,
    body TEXT,
    query_params JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Environments table
CREATE TABLE hoppscotch_environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    variables JSONB NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id VARCHAR(100),
    is_global BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, name)
);

-- Request execution history
CREATE TABLE hoppscotch_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES hoppscotch_requests(id),
    user_id UUID NOT NULL REFERENCES users(id),
    status_code INTEGER,
    response_headers JSONB,
    response_body TEXT,
    execution_time_ms INTEGER,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT NOW()
);
```

#### 3.2 Collection Service
```python
# services/collection_service.py
from typing import List, Optional
from api.app.plugins.api_development.hoppscotch.models import Collection, Request

class CollectionService:
    def __init__(self, storage_provider: StorageProvider):
        self.storage = storage_provider
    
    async def create_collection(self, name: str, description: str, 
                              user_context: UserContext) -> str:
        """Create new API collection"""
        collection = Collection(
            name=name,
            description=description,
            user_id=user_context.user_id,
            tenant_id=user_context.tenant_id
        )
        
        collection_id = await self.storage.create('hoppscotch_collections', collection.dict())
        
        audit_event('collection_created', 
                   collection_id=collection_id,
                   user_id=user_context.user_id)
        
        return collection_id
    
    async def get_user_collections(self, user_context: UserContext) -> List[Collection]:
        """Get all collections for user"""
        collections = await self.storage.query(
            'hoppscotch_collections',
            filters={
                'user_id': user_context.user_id,
                'tenant_id': user_context.tenant_id
            }
        )
        
        return [Collection(**col) for col in collections]
    
    async def add_request_to_collection(self, collection_id: str, 
                                      request: Request) -> str:
        """Add request to collection"""
        request.collection_id = collection_id
        request_id = await self.storage.create('hoppscotch_requests', request.dict())
        
        return request_id
```

### Phase 4: UI Components (Week 7-8)

#### 4.1 Main Hoppscotch Panel
```typescript
// ui/HoppscotchPanel.tsx
import React, { useState, useEffect } from 'react';
import { useTraitBasedUI } from '@/hooks/useTraitBasedUI';
import { ResponsiveCard, ResponsiveFormSection } from '@/components/common';

interface HoppscotchPanelProps {
  user: User;
  config: ConfigProvider;
}

export default function HoppscotchPanel({ user, config }: HoppscotchPanelProps) {
  const uiContext = useTraitBasedUI(user);
  const [collections, setCollections] = useState<Collection[]>([]);
  const [selectedCollection, setSelectedCollection] = useState<Collection | null>(null);
  const [requests, setRequests] = useState<Request[]>([]);
  
  // Check user capabilities
  const canTestAPIs = user.traits.includes('api_testing');
  const canManageCollections = user.traits.includes('collection_management');
  
  if (!canTestAPIs) {
    return (
      <Alert severity="warning">
        You don't have permission to use API testing features.
        Required trait: api_testing
      </Alert>
    );
  }
  
  return (
    <ResponsiveCard title="API Development with Hoppscotch">
      <Grid container spacing={3}>
        {/* Collections Sidebar */}
        <Grid item xs={12} md={4}>
          <CollectionManager
            collections={collections}
            selectedCollection={selectedCollection}
            onSelectCollection={setSelectedCollection}
            canManage={canManageCollections}
            user={user}
          />
        </Grid>
        
        {/* Main Request Area */}
        <Grid item xs={12} md={8}>
          {selectedCollection ? (
            <RequestBuilder
              collection={selectedCollection}
              requests={requests}
              onRequestChange={setRequests}
              user={user}
            />
          ) : (
            <EmptyState
              title="Select a Collection"
              description="Choose a collection to start building API requests"
            />
          )}
        </Grid>
      </Grid>
    </ResponsiveCard>
  );
}
```

#### 4.2 Request Builder Component
```typescript
// ui/RequestBuilder.tsx
interface RequestBuilderProps {
  collection: Collection;
  requests: Request[];
  onRequestChange: (requests: Request[]) => void;
  user: User;
}

export default function RequestBuilder({ 
  collection, 
  requests, 
  onRequestChange, 
  user 
}: RequestBuilderProps) {
  const [currentRequest, setCurrentRequest] = useState<Request | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [response, setResponse] = useState<Response | null>(null);
  
  const executeRequest = async (request: Request) => {
    setIsExecuting(true);
    try {
      const result = await api.post('/plugins/hoppscotch/execute', {
        collection_id: collection.id,
        request: request
      });
      setResponse(result.data);
    } catch (error) {
      console.error('Request execution failed:', error);
    } finally {
      setIsExecuting(false);
    }
  };
  
  return (
    <Box>
      {/* Request Method & URL */}
      <Box sx={{ mb: 2 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Select
            value={currentRequest?.method || 'GET'}
            onChange={(e) => updateRequest({ method: e.target.value })}
            size="small"
            sx={{ minWidth: 100 }}
          >
            <MenuItem value="GET">GET</MenuItem>
            <MenuItem value="POST">POST</MenuItem>
            <MenuItem value="PUT">PUT</MenuItem>
            <MenuItem value="DELETE">DELETE</MenuItem>
          </Select>
          
          <TextField
            fullWidth
            placeholder="Enter API endpoint URL"
            value={currentRequest?.url || ''}
            onChange={(e) => updateRequest({ url: e.target.value })}
            size="small"
          />
          
          <Button
            variant="contained"
            onClick={() => executeRequest(currentRequest)}
            disabled={!currentRequest?.url || isExecuting}
            startIcon={isExecuting ? <CircularProgress size={16} /> : <PlayArrow />}
          >
            {isExecuting ? 'Sending...' : 'Send'}
          </Button>
        </Stack>
      </Box>
      
      {/* Request Details Tabs */}
      <Tabs value={activeTab} onChange={setActiveTab}>
        <Tab label="Headers" />
        <Tab label="Body" />
        <Tab label="Params" />
        <Tab label="Auth" />
      </Tabs>
      
      <TabPanel value={activeTab} index={0}>
        <HeadersEditor
          headers={currentRequest?.headers || {}}
          onChange={(headers) => updateRequest({ headers })}
        />
      </TabPanel>
      
      <TabPanel value={activeTab} index={1}>
        <BodyEditor
          body={currentRequest?.body || ''}
          onChange={(body) => updateRequest({ body })}
        />
      </TabPanel>
      
      {/* Response Display */}
      {response && (
        <ResponseDisplay response={response} />
      )}
    </Box>
  );
}
```

### Phase 5: Integration & Testing (Week 9-10)

#### 5.1 Admin Console Integration
Update the Admin Console to include the Hoppscotch plugin:

```typescript
// admin/src/pages/APIDevelopment.tsx
export default function APIDevelopment() {
  const { user } = useAuth();
  const canUseAPI = user.traits.includes('api_testing');
  
  if (!canUseAPI) {
    return <AccessDenied feature="API Development" />;
  }
  
  return (
    <ResponsiveLayout>
      <HoppscotchPanel user={user} />
    </ResponsiveLayout>
  );
}
```

#### 5.2 API Endpoints
```python
# api/app/routes/hoppscotch.py
from fastapi import APIRouter, Depends, HTTPException
from api.app.plugins.api_development.hoppscotch.plugin import HoppscotchPlugin

router = APIRouter(prefix="/plugins/hoppscotch")

@router.post("/execute")
async def execute_request(
    request_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Execute API request via Hoppscotch"""
    if not current_user.has_trait('api_testing'):
        raise HTTPException(403, "API testing permission required")
    
    plugin = get_plugin('hoppscotch_integration')
    if not plugin:
        raise HTTPException(503, "Hoppscotch plugin not available")
    
    try:
        canonical_request = CanonicalRequest(**request_data['request'])
        response = await plugin.execute_request(canonical_request)
        return response.dict()
    except Exception as e:
        raise HTTPException(500, f"Request execution failed: {str(e)}")

@router.get("/collections")
async def get_collections(current_user: User = Depends(get_current_user)):
    """Get user's API collections"""
    if not current_user.has_trait('collection_management'):
        raise HTTPException(403, "Collection management permission required")
    
    plugin = get_plugin('hoppscotch_integration')
    collections = await plugin.get_collections(current_user)
    return [col.dict() for col in collections]
```

## Security & Compliance Considerations

### HIPAA Compliance
- **Data Isolation**: Collections and requests are tenant-scoped
- **Audit Logging**: All API executions are logged with user context
- **PHI Detection**: Integrate with core PHI detection for request bodies
- **Encryption**: Sensitive data encrypted at rest using platform encryption

### Access Control
- **Trait-Based**: Features gated by user traits
- **Tenant Isolation**: Users only see their tenant's data
- **Permission Levels**: Different access levels for different operations

### Security Measures
- **Input Validation**: All user inputs validated and sanitized
- **Rate Limiting**: Prevent abuse of API execution
- **Timeout Controls**: Prevent long-running requests from blocking system
- **Error Handling**: Secure error messages without exposing internals

## Configuration Management

### Hierarchical Configuration
```yaml
# Global defaults
hoppscotch_integration:
  cli_path: "/usr/local/bin/hopp"
  max_collections: 50
  request_timeout: 30
  enable_team_features: false

# Tenant overrides
tenant:mercy_hospital:
  hoppscotch_integration:
    max_collections: 100
    enable_team_features: true
    allowed_domains: ["*.mercyhealth.com"]

# User overrides  
user:admin_user:
  hoppscotch_integration:
    request_timeout: 60
    enable_debug_mode: true
```

## Testing Strategy

### Unit Tests
- Plugin initialization and configuration
- CLI service execution
- Collection and request management
- UI component rendering

### Integration Tests
- End-to-end API request execution
- Database operations
- User permission enforcement
- Error handling scenarios

### Performance Tests
- Concurrent request execution
- Large collection handling
- Memory usage optimization
- Response time benchmarks

## Deployment Considerations

### Prerequisites
- Node.js runtime for CLI wrapper
- Hoppscotch CLI installed on system
- Database migrations applied
- Plugin registry updated

### Environment Variables
```bash
# Required
HOPPSCOTCH_CLI_PATH=/usr/local/bin/hopp
NODE_PATH=/usr/local/bin/node

# Optional
HOPPSCOTCH_MAX_COLLECTIONS=50
HOPPSCOTCH_REQUEST_TIMEOUT=30
HOPPSCOTCH_ENABLE_DEBUG=false
```

### Monitoring & Observability
- Plugin health checks
- Request execution metrics
- Error rate monitoring
- Performance dashboards

## Future Enhancements

### Phase 2 Features
- **Team Collaboration**: Shared collections and environments
- **API Documentation**: Auto-generate docs from collections
- **Testing Automation**: Scheduled test execution
- **Integration Testing**: Multi-request test suites

### Phase 3 Features
- **Custom Scripts**: JavaScript execution in requests
- **Mock Servers**: Built-in API mocking
- **Performance Testing**: Load testing capabilities
- **API Monitoring**: Continuous API health monitoring

## Success Metrics

### User Adoption
- Number of active users
- Collections created per user
- Requests executed per day
- Feature usage distribution

### Performance
- Average request execution time
- Plugin initialization time
- Memory usage per request
- Error rate percentage

### Business Value
- Developer productivity improvement
- API development time reduction
- Quality improvement metrics
- User satisfaction scores

## Conclusion

This integration plan provides a comprehensive approach to integrating Hoppscotch into the Vivified platform while maintaining the platform's core principles of modularity, security, and user-centric design. The phased approach ensures stable delivery while building toward a powerful API development environment that scales with user needs.

The implementation leverages Vivified's plugin architecture, trait-based access control, and hierarchical configuration to create a seamless experience that feels native to the platform while providing the full power of Hoppscotch's API testing capabilities.
