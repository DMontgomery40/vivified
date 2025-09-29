# Plugin SDK Reference

The Vivified platform provides SDKs in multiple languages to simplify plugin development. Each SDK handles authentication, communication protocols, and provides helper utilities for common tasks.

<div class='grid cards' markdown>

-   :material-language-python:{ .lg .middle } **Python SDK**
    
    ---
    Full-featured SDK with async support and type hints

-   :material-nodejs:{ .lg .middle } **Node.js SDK**
    
    ---
    Complete JavaScript/TypeScript SDK with full plugin capabilities

-   :material-language-go:{ .lg .middle } **Go SDK**
    
    ---
    High-performance SDK (Coming Soon - Q1 2025)

</div>

## Installation

=== "Python"
    ```bash
    pip install vivified-plugin-sdk
    ```

=== "Node.js"
    ```bash
    npm install @vivified/plugin-sdk
    # or
    yarn add @vivified/plugin-sdk
    ```

=== "Go"
    ```bash
    # Coming Soon - Q1 2025
    go get github.com/vivified/plugin-sdk-go
    ```

## Quick Start

### Python SDK Example

```python
from vivified_sdk import Plugin, PluginManifest
from vivified_sdk.traits import Traits
from vivified_sdk.contracts import StoragePlugin

class MyPlugin(Plugin, StoragePlugin):
    def __init__(self):
        manifest = PluginManifest(
            id="my-plugin",
            name="My Storage Plugin",
            version="1.0.0",
            contracts=["StoragePlugin"],
            traits=[Traits.HANDLES_PII, Traits.AUDIT_REQUIRED]
        )
        super().__init__(manifest)
    
    async def store(self, key: str, data: bytes) -> bool:
        """Implement storage interface"""
        # Your implementation here
        return True
    
    async def retrieve(self, key: str) -> bytes:
        """Implement retrieval interface"""
        # Your implementation here
        return b""

# Run the plugin
if __name__ == "__main__":
    plugin = MyPlugin()
    plugin.run()
```

### Node.js SDK Example

```javascript
const { Plugin, PluginManifest, Traits } = require('@vivified/plugin-sdk');

class MyPlugin extends Plugin {
    constructor() {
        const manifest = new PluginManifest({
            id: 'my-plugin',
            name: 'My Storage Plugin',
            version: '1.0.0',
            contracts: ['StoragePlugin'],
            traits: [Traits.HANDLES_PII, Traits.AUDIT_REQUIRED]
        });
        super(manifest);
    }
    
    async store(key, data) {
        // Your implementation here
        return true;
    }
    
    async retrieve(key) {
        // Your implementation here
        return Buffer.from('');
    }
}

// Run the plugin
const plugin = new MyPlugin();
plugin.run();
```

### Go SDK (Coming Soon)

```go
// Coming Q1 2025 - Full Go SDK with complete feature parity
package main

import (
    "github.com/vivified/plugin-sdk-go"
)

type MyPlugin struct {
    plugin.Base
}

func main() {
    manifest := plugin.NewManifest(
        "my-plugin",
        "My Storage Plugin",
        "1.0.0",
    )
    p := &MyPlugin{}
    plugin.Run(p, manifest)
}
```

## Core Components

### Plugin Manifest

The manifest declares your plugin's capabilities and requirements:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique plugin identifier |
| `name` | string | Yes | Human-readable name |
| `version` | string | Yes | Semantic version |
| `contracts` | array | Yes | Implemented interfaces |
| `traits` | array | Yes | Plugin capabilities/requirements |
| `security` | object | Yes | Security configuration |
| `allowed_domains` | array | No | External domains for proxy access |

## Communication APIs

### Event Bus (Canonical Lane)

=== "Python"
    ```python
    # Emit an event
    await plugin.emit_event("user.created", {
        "user_id": "123",
        "email": "user@example.com"
    })
    
    # Listen for events
    @plugin.on_event("document.processed")
    async def handle_document(event):
        print(f"Document {event.document_id} processed")
    ```

=== "Node.js"
    ```javascript
    // Emit an event
    await plugin.emitEvent('user.created', {
        userId: '123',
        email: 'user@example.com'
    });
    
    // Listen for events
    plugin.onEvent('document.processed', async (event) => {
        console.log(`Document ${event.documentId} processed`);
    });
    ```

=== "Go"
    ```go
    // Coming Soon - Q1 2025
    // Full event bus integration
    ```

## SDK Features

### All SDKs Provide:

- ✅ **Authentication** - Automatic token management
- ✅ **Health Checks** - Built-in health monitoring
- ✅ **Configuration** - Dynamic configuration updates
- ✅ **Storage Integration** - Encrypted storage service access
- ✅ **Event Bus** - Canonical event publishing/subscription
- ✅ **Operator API** - Inter-plugin communication
- ✅ **Proxy Service** - Filtered external API access
- ✅ **Audit Logging** - Automatic audit trail generation
- ✅ **Error Handling** - Standardized error types
- ✅ **Testing Utilities** - Unit and integration test helpers

## SDK Version Compatibility

| SDK | Current Version | Min Core Version | Status |
|-----|-----------------|------------------|--------|
| Python | 1.0.0 | 1.0.0 | ✅ Stable |
| Node.js | 1.0.0 | 1.0.0 | ✅ Stable |
| Go | - | 1.0.0 | 🚧 Coming Q1 2025 |
| Rust | - | 1.0.0 | 📅 Planned Q2 2025 |
| Java | - | 1.0.0 | 📅 Planned Q2 2025 |

## Resources

- **API Documentation**: Full SDK API reference for each language
- **Example Plugins**: [Plugin Examples](examples.md)
- **Development Guide**: [Plugin Development](development.md)
- **GitHub**: [github.com/vivified/plugin-sdk](https://github.com/vivified/plugin-sdk)