Phase 1: Implementation Plan for Faxbot v4 Overhaul (Plugin Architecture)

Overview: Phase 1 focuses on laying a robust foundation for Faxbot v4 by introducing a plugin-based architecture with strict trait/type/scope definitions and a guided setup. The goal is to make every component pluggable and modular, so that adding or modifying features (like fax providers, storage, UI hooks, etc.) is done via plugins that can't break core functionality. We will define clear interfaces (abstract base classes) for plugins, enforce traits (capabilities a plugin can have), types (categories of plugins), and scopes (allowed access boundaries for plugins).

Admin Console First (per `AGENTS.md`): The primary user-facing setup and management must be through the Admin Console UI. A CLI wizard may exist only as an optional helper and must not be the only path. All new capabilities introduced in Phase 1 must have UI coverage (read-only acceptable for some areas in Phase 1) with trait-gated rendering and “Learn more” links built from `docsBase`.

Config source of truth: Phase 1 must use a DB‑first, `.env` fallback hybrid configuration, not a standalone `config.yaml`. Reads resolve via a HybridConfigProvider (DB → `.env`), and minimal, safe writes go to the DB so changes apply without a service restart. Provider and UI gating must query traits from the server/provider traits registry; no backend-name checks.

 

Key Objectives of Phase 1:

Plugin Interface & Manager: Create a standardized plugin system (base classes and manager) to load and manage plugins (e.g., fax providers) dynamically.

Traits & Types System: Define what capabilities (traits) each plugin can have and enforce plugin types (categories) with clear scopes (permissions/contexts) to prevent out-of-bounds behavior.

Refactor Core into Plugins: Decouple existing functionalities (fax sending, receiving, storage, etc.) into plugin implementations following the new interface. Built-in providers (Phaxio, Sinch, SIP/Asterisk) become plugins.

Wizard for Setup: Implement a CLI wizard for configuring the system (e.g., setting up provider API keys, selecting active plugins) to guide users and ensure correct setup. Lay groundwork for future wizards (e.g., adding new plugins) using a common Wizard framework.

Robust Error Handling: Wrap plugin operations in error handlers so that any exception in a plugin is caught and logged, preventing domino effects. Define fallback behaviors if a plugin fails (e.g., disable that plugin and continue running).

No Guesswork Architecture: Clearly specify all new classes, methods, and file/module organization so that a developer (or AI agent) can implement them directly without ambiguity.

Below is the step-by-step implementation plan for Phase 1, broken into micro-tasks:

Step-by-Step Implementation Plan

Create a plugins Module and Base Plugin Interface:

Module Setup: In the project structure, create a new package/folder `api/app/plugins/` (with `__init__.py`). Use type‑first foldering so discovery is deterministic and mirrors plugin types:

```
api/app/plugins/
  transport/
    phaxio/        # plugin.py + manifest.json
    asterisk/
  storage/
  notification/
  ui/
```
This will house all plugin-related code (base classes, manager, and plugin implementations) aligned with the existing API layout.

Base Abstract Class: Define an abstract base class FaxbotPlugin in a new file `api/app/plugins/base.py`. This class will declare the common interface that all plugins must implement. Use Python’s abc module for abstract methods. For now, include methods for initialization and a standard entry point (e.g., initialize() and shutdown()), and possibly an optional method that plugins can override for a health check or basic operation. All plugins will subclass this. Example skeleton:

# api/app/plugins/base.py
from abc import ABC, abstractmethod

class FaxbotPlugin(ABC):
    """Abstract base class for all Faxbot plugins (async interfaces)."""
    plugin_name: str  # human-readable name for the plugin
    plugin_type: str  # category of plugin (e.g. 'transport', 'storage', etc.)

    def __init__(self):
        """Common initialization for plugins (can be extended by subclasses)."""
        pass

    @abstractmethod
    async def initialize(self, config: dict) -> None:
        """Initialize plugin with given config (e.g. API keys, settings)."""
        raise NotImplementedError

    @abstractmethod
    async def shutdown(self) -> None:
        """Gracefully shutdown the plugin (cleanup resources)."""
        raise NotImplementedError


Usage: initialize() will be called by the system (plugin manager) to set up the plugin (for example, establishing API connections using credentials). shutdown() will be called on application exit or when disabling the plugin. We use plugin_name and plugin_type class attributes so each plugin declares its identity and category.

Mixins (if needed): If there are cross-cutting features (like logging or permission checks) that many plugins might share, define mixin classes. For example, a LoggingMixin could provide standardized logging capability to plugins. You might create `api/app/plugins/mixins.py` for such helpers. (In this phase, mixins are optional; implement them if you notice duplicate code in plugin classes during refactoring.)

Define Plugin Types, Traits, and Scopes:
To enforce what a plugin can do and prevent misuse, define formal structures for types, traits, and scopes:

Plugin Type Enumeration: Create an Enum or constant definitions for plugin types in a new file `api/app/plugins/registry.py` (or a config file). For example:

# faxbot/plugins/registry.py (part of it)
from enum import Enum

class PluginType(str, Enum):
    TRANSPORT = "transport"    # fax sending/receiving providers
    STORAGE = "storage"        # storing faxes or logs
    NOTIFICATION = "notification"  # e.g., email/SMS alerts
    UI = "ui"                  # user-interface plugin, if any (like dashboard hooks)
    # ... add other categories as needed


Each plugin will declare its plugin_type (as set on the base class attribute or via subclass property). The types help the manager load and group plugins appropriately.

Trait Definitions: Define what capabilities or features a plugin can have. Traits could be represented as an Enum as well, e.g., PluginTrait. For instance, traits might include SEND_FAX, RECEIVE_FAX, PRINT_FAX, WEBHOOK_HANDLER, etc., depending on what functionality we expect plugins to possibly provide. This allows the core to check if a plugin supports a required capability at runtime. Example:

class PluginTrait(str, Enum):
    SEND_FAX = "send_fax"
    RECEIVE_FAX = "receive_fax"
    STATUS_CALLBACK = "status_callback"   # handles status webhook
    # ...other traits like PRINT, ANALYTICS, etc.


We will use these traits in plugin classes (possibly as a list or set attribute in each plugin) to declare what the plugin can do. For example, a PhaxioTransport plugin might declare traits {PluginTrait.SEND_FAX, PluginTrait.STATUS_CALLBACK}.

Scope Concept: Define what system resources or permissions a plugin is allowed – e.g., file system access, network access, database access, etc. In this phase, we will implement scope as a policy check rather than a full sandbox (full sandboxing might come in a later phase if needed). Create a class or structured config for PluginScope in faxbot/plugins/registry.py describing possible scope levels. For example:

class PluginScope(str, Enum):
    SANDBOXED = "sandboxed"    # Highly restricted (no direct disk or net access unless via provided API)
    TRUSTED = "trusted"        # Allowed to use certain system resources
    FULL_ACCESS = "full_access" # (Avoid using; implies plugin can do anything)


Each plugin will declare a scope requirement (maybe as a class variable required_scope). In Phase 1, we won’t implement actual OS-level sandboxing, but we will use this to validate and log what scope a plugin needs. For instance, a third-party or unverified plugin might only be allowed if it’s SANDBOXED, whereas built-in plugins can be TRUSTED. The plugin manager will check a plugin’s declared required_scope against a configuration or admin setting to decide if it should load.

Documentation & Enforcement: Clearly document in code comments how plugin authors should specify their plugin’s type, traits, and scope. Also, in the plugin manager (next step), add checks: e.g., if a plugin declares an unknown type or trait, refuse to load it; if a plugin’s scope is higher than allowed by global settings, do not enable it. This ensures no unexpected capabilities slip in.

Plugin Manifest and Schema (manifest‑first discovery):

Each plugin must ship a `manifest.json` next to its `plugin.py`. The manifest is validated against a JSON Schema at `plugin-dev-kit/manifest.schema.json` during load to prevent malformed plugins.

Example `api/app/plugins/transport/phaxio/manifest.json`:

```json
{
  "id": "phaxio",
  "name": "Phaxio",
  "type": "transport",
  "traits": ["send_fax", "status_callback", "verify_webhook"],
  "requiredScope": "trusted",
  "configSchema": {
    "type": "object",
    "required": ["apiKey", "apiSecret"],
    "properties": {
      "apiKey":   { "type": "string", "title": "API Key",   "secret": true },
      "apiSecret":{ "type": "string", "title": "API Secret","secret": true }
    }
  },
  "docs": { "learnMore": "/backends/phaxio-setup.html" }
}
```

Implement the Plugin Manager:
Create a PluginManager class in `api/app/plugins/manager.py` responsible for discovering, loading, and managing plugin instances. This manager ensures plugins are initialized properly and enforces the rules from step 2. Key functions and responsibilities:

Registry of Plugins: Maintain a registry (dictionary or list) of loaded plugin instances, probably keyed by plugin type and name. For example, self.plugins could be a dict of {plugin_type: {plugin_name: plugin_instance, ...}, ...} for quick access.

Discovery: Provide a method to discover plugins by scanning manifests, then importing modules.

- Scan `api/app/plugins/*/*/manifest.json`
- Validate each manifest against `plugin-dev-kit/manifest.schema.json`
- Import `plugin.py` beside the manifest and obtain the plugin class
- Verify the plugin class inherits the correct base for its declared type (e.g., `TransportPlugin`)
- Initialize with config resolved via HybridConfigProvider

Initialization & Teardown: Implement initialize_all(config) which iterates through all plugin classes (or selected ones) and calls each plugin’s initialize(config_for_that_plugin). Ensure to catch exceptions during init – if a plugin fails to initialize, log the error and skip loading that plugin (so one bad plugin doesn’t stop the system). Also implement shutdown_all() to iterate and call shutdown() on each loaded plugin when the application is closing.

Trait/Scope Enforcement: When loading each plugin, verify it meets the declared contracts: check that plugin_type matches one of the allowed types, and that the plugin’s declared traits cover the needed capabilities for that type. Also verify or assign a scope: e.g., if a plugin is not marked trusted and the system is in a strict mode, you might restrict certain actions. At this stage, enforcement can simply be logging warnings or preventing load of a disallowed plugin. For example, if a plugin declares required_scope = FULL_ACCESS but the deployment config says only sandboxed plugins allowed, the manager should refuse to load it.

Plugin Access API: Provide methods to retrieve a plugin by type or trait for use by the core logic. For example, get_plugins_by_type(plugin_type) -> list or get_plugin(name) -> instance. Also, if there should be only one active plugin of a given type (e.g., one active Transport provider at a time), decide and enforce that here. (We may allow multiple transport plugins if the system can handle multiple fax gateways, but maybe only one is “primary”. This can be configured via the config/wizard.)

Example Implementation Outline:

# api/app/plugins/manager.py
import importlib
from api.app.plugins.registry import PluginType, PluginScope

class PluginManager:
    def __init__(self):
        self.plugins = {}  # e.g., {'transport': {'Phaxio': phaxio_plugin_instance, ...}, ...}

    async def load_plugins(self, config: dict):
        """Discover and load plugins based on config (async init)."""
        plugins_to_load = config.get("plugins", [])
        for plugin_info in plugins_to_load:
            module_path = plugin_info["module"]   # e.g., "api.app.plugins.transport.phaxio.plugin"
            class_name = plugin_info["class"]    # e.g., "PhaxioPlugin"
            plugin_config = plugin_info.get("config", {})
            try:
                module = importlib.import_module(module_path)
                PluginClass = getattr(module, class_name)
            except ImportError as e:
                log.error(f"Plugin module {module_path} not found: {e}")
                continue
            except AttributeError as e:
                log.error(f"Plugin class {class_name} not found in {module_path}: {e}")
                continue

            # Instantiate plugin
            plugin_instance = PluginClass()
            # Verify plugin meets type/trait/scope requirements
            if not self._validate_plugin(plugin_instance):
                continue  # skip if invalid

            # Initialize plugin with its config (await async; offload sync)
            try:
                import inspect
                from fastapi.concurrency import run_in_threadpool
                if inspect.iscoroutinefunction(plugin_instance.initialize):
                    await plugin_instance.initialize(plugin_config)
                else:
                    await run_in_threadpool(plugin_instance.initialize, plugin_config)
            except Exception as e:
                log.error(f"Failed to initialize plugin {PluginClass.__name__}: {e}", exc_info=True)
                continue

            # Register plugin in self.plugins
            p_type = plugin_instance.plugin_type
            p_name = getattr(plugin_instance, "plugin_name", PluginClass.__name__)
            self.plugins.setdefault(p_type, {})[p_name] = plugin_instance
            log.info(f"Loaded plugin {p_name} of type {p_type}")
        # Done loading

    def _validate_plugin(self, plugin_instance) -> bool:
        """Check plugin's declared type, traits, and scope against policy."""
        p_type = plugin_instance.plugin_type
        if p_type not in PluginType._value2member_map_:  # ensure valid type
            log.error(f"Plugin {plugin_instance} has unknown type '{p_type}'")
            return False
        # Example: ensure required scope is allowed (simple policy check)
        required_scope = getattr(plugin_instance, "required_scope", PluginScope.TRUSTED)
        # (Here, add logic to compare required_scope with global allowed scope, etc.)
        # For now, just log:
        if required_scope == PluginScope.FULL_ACCESS:
            log.warning(f"Plugin {plugin_instance} requests FULL_ACCESS scope. Ensure you trust this plugin.")
        return True

    def shutdown_all(self):
        """Gracefully shut down all loaded plugins."""
        for p_type, plugins in self.plugins.items():
            for name, plugin in plugins.items():
                try:
                    plugin.shutdown()
                    log.info(f"Plugin {name} shut down.")
                except Exception as e:
                    log.error(f"Error shutting down plugin {name}: {e}", exc_info=True)


Notes: The above code is a guideline. The actual log should be replaced with whatever logging mechanism exists (possibly the Python logging module or the MCP server’s logging). The configuration structure (plugins_to_load) will be prepared in a later step (likely by the wizard or a config file). We perform safe imports and catch errors to ensure a broken plugin doesn’t crash the whole manager. The _validate_plugin method currently just checks type and logs scope issues; it can be extended to enforce trait requirements as well (e.g., if plugin type is TRANSPORT but it doesn’t have SEND_FAX trait, log an error).

After this, the core application can use PluginManager.load_plugins() at startup (passing the config gathered from user via wizard or config file), and then call get_plugins_by_type or access manager.plugins where needed to route functionality to plugins.

Current Faxbot Integration Map (Phase 1 — Expanded)

- Plugin registry/ingestor (reuse, not replace):
  - Reuse `api/app/plugins/registry/service.py`, `validator.py`, `signature.py` for manifest validation/signature and loader glue.
  - Phase‑1 manifest‑first discovery must call into this registry layer; do not hand‑roll a new ingestor.
- Existing storage plugins (must remain supported):
  - Keep `storage/local` as the default, plus cloud backends: `storage/s3`, `storage/azure`, `storage/gcs`.
  - Provide a `LocalStoragePlugin` stub in the new typed system and map it to current local storage behavior.
- Providers (outbound + inbound):
  - Implement `transport/phaxio`, `transport/sinch`, `transport/asterisk` as `TransportPlugin`s.
  - Preserve existing send endpoints and callback routes; inside handlers route to `plugin.verify_webhook()` and `plugin.handle_status_callback()`.
  - Unified inbound endpoint must autodetect by signature header (e.g., `X-Phaxio-Signature`, `X-Sinch-Signature`) and dispatch accordingly.
- Sinch support (must ship in Phase 1):
  - Config keys: `SINCH_PROJECT_ID`, `SINCH_API_KEY`, `SINCH_API_SECRET`, `SINCH_BASE_URL`, optional `SINCH_AUTH_*` map to typed config and hierarchical keys.
  - Fallback behavior: when `SINCH_*` unset, allow fallback to `PHAXIO_*` (per docs) — document this in HybridConfigProvider resolution.
  - Inbound basic auth fields (user/pass) honored for `/sinch-inbound`.
- Identity shells (acknowledge, used in Phase 2):
  - `plugins/identity/ldap`, `saml`, `oauth2` remain as the structure for Phase‑2 identity providers.
- Events/webhooks (baseline compatibility):
  - Integrate canonical events with `api/app/events/bus.py`, `webhooks.py`, `delivery.py` instead of inventing a separate bus.
- Marketplace (no changes in Phase‑1):
  - `api/app/marketplace/*` reserved; no runtime changes this phase.
- Inbound pipeline:
  - Preserve internal Asterisk/Freeswitch result hook `POST /_internal/freeswitch/outbound_result` secured by `ASTERISK_INBOUND_SECRET`.
  - Route inbound artifacts through `StoragePlugin`; honor `INBOUND_RETENTION_DAYS` and `INBOUND_TOKEN_TTL_MINUTES`.
- Storage mapping:
  - Map envs `STORAGE_BACKEND`, `S3_BUCKET`, `S3_PREFIX`, `S3_REGION`, `S3_ENDPOINT_URL`, `S3_KMS_KEY_ID` to hierarchical `storage.*` keys.
  - Honor retention envs: `ARTIFACT_TTL_DAYS`, `CLEANUP_INTERVAL_MINUTES`.

Admin Console Integration (Phase 1)
- Providers tab: must list Phaxio, Sinch, SIP/Asterisk with trait‑gated sections; include “Test connection” per provider; preserve “Register with Sinch” action under Tunnels.
- Settings: show provider‑specific fields trait‑gated; never gate by backend name; build docs links from `docsBase`.
- Diagnostics: surface provider health placeholders, trait snapshot, SSE baseline; inbound guidance for Sinch (basic auth), Phaxio (HMAC), SIP (AMI when `requires_ami=true`).
- Terminal: keep local‑only Admin Terminal surfaced and gated by `ENABLE_LOCAL_ADMIN`.
- Scripts & Tests: keep present panel; ensure outbound smoke tests cover Sinch.

UI Trait‑Gating Fix (Required)
- Replace UI comparisons like `active?.outbound === 'sinch' | 'phaxio' | 'sip'` with trait checks via `useTraits().hasTrait(direction, key)` and `traitValue`.
- Add provider traits such as `webhook_path`, `sample_payload`, `requires_ami`, `supports_status_callback` to the server registry/manifest so UI can stop fallback mapping.

Provider Traits (P0: ship UI‑needed fields server‑side)
```json
{
  "id": "phaxio",
  "type": "transport",
  "traits": [
    "send_fax",
    "status_callback",
    "webhook_hmac",
    "inbound_supported",
    "sample_payload",
    "webhook_path:/callbacks/phaxio",
    "verify_header:X-Phaxio-Signature"
  ]
}
{
  "id": "sinch",
  "type": "transport",
  "traits": [
    "send_fax",
    "status_callback",
    "webhook_basic_auth",
    "inbound_supported",
    "sample_payload",
    "webhook_path:/callbacks/sinch",
    "verify_header:X-Sinch-Signature",
    "basic_auth_env:SINCH_INBOUND_BASIC_USER,SINCH_INBOUND_BASIC_PASS",
    "env_fallback:SINCH_*=PHAXIO_*"
  ]
}
```

Storage (Phase 1 deliverable; retention in Phase 3 hierarchy)
- Ship LocalStoragePlugin (default) and S3StoragePlugin (SSE‑KMS, S3‑compatible endpoints) in Phase 1.
- Map envs to hierarchical keys (used in Phase 3 Config Manager):
  - `storage.backend`, `storage.s3.bucket`, `storage.s3.region`, `storage.s3.prefix`, `storage.s3.endpoint_url`, `storage.s3.kms_key_id`.
- Add retention keys (Phase 3 safe‑edit):
  - `storage.retention.days` (int, 0=off), `storage.cleanup_interval_minutes` (int).

Admin Terminal (local‑only)
- Enforce loopback‑only access to `/admin/terminal` and do not expose over tunnels; keep `ENABLE_LOCAL_ADMIN` gating.

Lock Base Interfaces and Refactor Existing Fax Functionality into Plugins:
Now that we have the plugin framework, transition current core features into this new model, so the core logic calls plugins instead of hardwired functions. First, lock the typed bases so implementations are consistent and verifiable at import time:

```python
# api/app/plugins/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class FaxbotPlugin(ABC):
    plugin_name: str
    plugin_type: str            # "transport" | "storage" | "notification" | "ui"
    required_scope: str         # "sandboxed" | "trusted" | "full_access"
    traits: set[str]

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None: ...

    @abstractmethod
    def shutdown(self) -> None: ...

class TransportPlugin(FaxbotPlugin, ABC):
    plugin_type = "transport"

    @abstractmethod
    async def send_fax(
        self,
        recipient_number: str,
        file_path: str,
        *,
        idempotency_key: Optional[str] = None
    ) -> str: ...

    async def handle_status_callback(self, data: Dict[str, Any]) -> None: ...

    async def verify_webhook(self, headers: Dict[str, str], body: bytes) -> bool: ...
```

Key refactors:

Fax Sending (Transport) Plugins: Faxbot currently supports sending faxes via Phaxio (cloud) and via Asterisk T.38 (on-prem). We will create plugin classes for each of these, subclassing `TransportPlugin`. These should reside under `api/app/plugins/transport/` (type‑first). For instance, make `api/app/plugins/transport/phaxio/plugin.py` with:

# api/app/plugins/transport/phaxio/plugin.py
from api.app.plugins.base import TransportPlugin
from api.app.plugins.registry import PluginType, PluginTrait

class PhaxioPlugin(TransportPlugin):
    plugin_name = "Phaxio"
    plugin_type = PluginType.TRANSPORT
    required_scope = "trusted"  # could use PluginScope.TRUSTED
    traits = {PluginTrait.SEND_FAX, PluginTrait.STATUS_CALLBACK}

    def __init__(self):
        super().__init__()
        self.api_key = None
        self.api_secret = None
        # ... any other Phaxio-specific state ...

    async def initialize(self, config: dict):
        """Load API credentials and test connection to Phaxio."""
        self.api_key = config.get("api_key")
        self.api_secret = config.get("api_secret")
        if not self.api_key or not self.api_secret:
            raise ValueError("Phaxio API credentials not provided")
        # Possibly perform a test request to Phaxio API to verify credentials
        # e.g., Phaxio API call to /accounts or similar for verification
        test_ok = await self._test_connection()
        if not test_ok:
            raise RuntimeError("Failed to connect to Phaxio API with provided credentials.")

    async def send_fax(self, recipient_number: str, file_path: str, *, idempotency_key: Optional[str] = None) -> str:
        """Send a fax via Phaxio. Returns a transmission ID or raises on error."""
        # Use Phaxio API (e.g., via requests) to send the fax.
        # Construct payload with recipient_number and file_path, plus self.api_key/secret for auth.
        # Send POST request to Phaxio endpoint.
        # Parse response; if success, return fax ID; if failure, raise exception.
        pass  # (implementation of API call goes here)

    async def shutdown(self):
        """Cleanup if necessary (Phaxio API might not need explicit cleanup)."""
        return

    # Additional helper, not part of base interface:
    async def _test_connection(self) -> bool:
        # (Optional) Implement a simple verify call to Phaxio API using httpx.AsyncClient
        return True  # assume success for skeleton


Similarly, create `api/app/plugins/transport/asterisk/plugin.py` for the Asterisk T.38 backend: it might have to interface with a local service or use a library to send faxes via an Asterisk server. Its `initialize` might set up a connection or verify the Asterisk service is reachable; its `send_fax` will invoke the appropriate command or API (perhaps using AMI or an internal helper). Both classes share `plugin_type = transport` and implement the `TransportPlugin` methods.
Note: The base class FaxbotPlugin didn’t define send_fax as abstract because not all plugins will send faxes (e.g., a storage plugin won’t have send_fax). To enforce that Transport plugins implement send_fax, we can do one of two things: (a) define a subclass abstract base TransportPlugin(FaxbotPlugin) with abstract send_fax, and have Phaxio/Asterisk inherit from that; or (b) simply document that transport-type plugins must have send_fax method, and optionally check at runtime. A cleaner approach is (a). For completeness, we can introduce a specialized base:

# faxbot/plugins/base.py (extend with specialized base)
class TransportPlugin(FaxbotPlugin):
    @abstractmethod
    def send_fax(self, recipient_number: str, file_path: str) -> str:
        """Send fax to the given number using this transport. Return transmission ID."""
        raise NotImplementedError


Then let PhaxioPlugin(TransportPlugin) and AsteriskPlugin(TransportPlugin) instead of directly FaxbotPlugin. This way, send_fax is guaranteed.

Routing Send Fax Calls: Modify the core Faxbot logic that handles sending faxes (perhaps an API endpoint or internal function that was previously choosing Phaxio vs Asterisk). Now, instead of directly calling those services, it will:

Use PluginManager to get the active transport plugin. Possibly decide which plugin to use based on config or user input (for example, if both Phaxio and Asterisk are loaded, maybe the user selects one as default or the wizard ensures only one is active).

Call plugin.send_fax(recipient, file) on that plugin instance.

If that call raises an exception, the core should catch it and return an error response, but the plugin manager should have already logged it. This ensures one failing plugin doesn’t crash the whole system. Possibly the plugin manager could even try a fallback plugin if one transport fails (e.g., if primary fails, try secondary), though that’s an advanced behavior that can be considered later.

The core should also handle the returned transmission ID (if any) for tracking.

Webhook/Status Handling: Faxbot likely handles incoming status webhooks (callbacks from Phaxio with fax status or from Asterisk events). Refactor this such that the plugin that sent the fax (or a plugin designated to handle callbacks) processes the webhook. For example, in the web endpoint that receives a Phaxio webhook, we can route it to the PhaxioPlugin instance to parse and validate. We could add a method like handle_callback(request_data) in the TransportPlugin interface. For now, perhaps define in TransportPlugin:

def handle_status_callback(self, data: dict) -> None:
    """Process incoming status callback. Update fax status or logs."""
    # default: do nothing or basic log
    return


And override it in PhaxioPlugin to actually verify the signature (Phaxio webhooks come with a token), update internal status or notify the system. The core application when receiving a webhook can determine which plugin to hand it to (maybe by endpoint or by an ID in the callback data linking to which service) and call plugin.handle_status_callback(data).

Other Core Functions to Plugins: If Faxbot has other functionalities (e.g., storing fax records, sending notifications of delivery, etc.), plan to offload those to plugins in a similar fashion. For instance, if there’s a component that saves sent fax files or metadata, that could be a Storage Plugin with traits like STORE_FAX. Phase 1 may not implement a new storage mechanism, but ensure the architecture can accommodate it. Perhaps create a stub LocalStoragePlugin (that just saves files to disk) as a starting point for storage plugin type. This demonstrates that the design supports multiple plugin categories.

Setup and Configuration (Admin Console primary, optional CLI helper):
To ensure no user or misconfiguration breaks the system, implement a guided setup primarily through the Admin Console. The Console must expose at least: active outbound provider selection, a minimal safe toggle or input for that provider, and read-only visibility into effective configuration and traits. A CLI wizard can exist as an optional helper for local, non-UI environments, but all routine operations must be operable from the Admin Console per `AGENTS.md`.

CLI Wizard Base Class (Optional): For extensibility, create a base class `Wizard` in `api/app/plugins/wizard.py` (or `api/app/wizard.py` if more appropriate) that other wizard workflows can extend. It might have helper methods like ask_question(prompt), confirm(prompt), etc., using input(). Example:

class Wizard:
    def __init__(self):
        self.responses = {}

    def ask(self, question: str, validator=None):
        """Ask a question via CLI and return the answer (validated if validator provided)."""
        while True:
            answer = input(question + " ")
            if validator:
                try:
                    validator(answer)
                    self.responses[question] = answer
                    return answer
                except Exception as e:
                    print(f"Invalid input: {e}")
                    continue
            else:
                self.responses[question] = answer
                return answer

    def confirm(self, prompt: str) -> bool:
        """Ask for yes/no confirmation."""
        ans = input(prompt + " (y/n) ")
        return ans.strip().lower() in ('y', 'yes')


This is a basic synchronous wizard helper. (We assume the environment is interactive. If Faxbot runs as a daemon, the wizard could be a separate CLI command or run on first startup in an interactive shell.)

Initial Setup Wizard (optional): Implement a subclass or a specific function `run_initial_setup()` that guides through selecting and configuring the primary transport plugin. Steps might include:

Greet the user and explain this will configure Faxbot.

Ask which fax sending method to use (present a list: e.g., “1 for Phaxio (cloud), 2 for Asterisk (on-prem), ...”). Based on choice, select the corresponding plugin class.

For the chosen plugin, ask for necessary configuration. For Phaxio: ask for API key and API secret; for Asterisk: perhaps ask for server address, credentials, or confirm that Asterisk is installed. Use Wizard.ask() to get these inputs and validate (e.g., non-empty).

Optionally, ask if they want to enable any additional plugins (if others exist, like an email notification plugin or storage plugin). In Phase 1, we may skip additional plugins and focus on the main transport. But the framework allows adding more.

Persist configuration using the HybridConfigProvider (DB-first, `.env` fallback). Do not write a standalone `config.yaml`. The wizard should either call internal services or Admin endpoints to set safe, minimal keys in the DB (e.g., active outbound provider and one provider credential placeholder). Secrets must be stored encrypted per the config provider policy; never logged.

HybridConfigProvider surface (freeze now):

```python
# api/app/config/provider.py
from abc import ABC, abstractmethod
from typing import Optional, Literal, Any

Source = Literal["db","env","default"]

class HybridConfigProvider(ABC):
    @abstractmethod
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]: ...

    @abstractmethod
    def set(self, key: str, value: str, *, scope: str = "global") -> None: ...

    @abstractmethod
    def source(self, key: str) -> Source: ...

    @abstractmethod
    def get_provider_config(self, provider_id: str) -> dict: ...
```

Minimal DB table: `config_entries(key PK, value_encrypted TEXT, scope TEXT, updated_at TIMESTAMP)` encrypted at rest (AES‑GCM). Master key provided via `CONFIG_MASTER_KEY`. See hierarchical migration doc for the extended model.

Possibly test the configuration: e.g., after inputting Phaxio credentials, the wizard can call a test method (like `_test_connection()` in `PhaxioPlugin` via the PluginManager) to verify the creds. Inform the user if the test fails and allow retry. The Admin Console should also expose a small “Test connection” action with a loader and actionable error text.

Conclude the wizard, maybe asking if they want to run a test fax (this could be optional, perhaps out-of-scope for initial config, but it’s a nice validation step). If so, prompt for a test recipient number and dummy document, then use the plugin to send a fax and report success or failure.

Wizard Integration: The wizard should be triggered when the system has no config yet or via a command. For example, if Faxbot is started without a config file, it could detect that and prompt "No configuration found. Start setup wizard? (y/n)". Alternatively, provide a separate CLI entry point like faxbot_setup.py to run the wizard. In this phase, implement whichever is simplest: e.g., if running the main program and no config, launch wizard.

Error Prevention: By guiding through these steps, we reduce chances of "errant user" causing issues. The wizard ensures required settings are provided and can validate them, so later the PluginManager.load_plugins() receives a correct config. This addresses the goal that no bad input breaks the system.

Note: Future wizards (beyond phase 1) could include: adding a new plugin at runtime, upgrading configuration, or a troubleshooting wizard. Our Wizard base is designed to be reused. For now, implement just the initial setup path in detail.

Integrate and Test Phase 1 Changes:
With the above components in place, integrate them into the application flow and verify stability:

Configuration Loading: Modify the application’s startup sequence to resolve configuration via the HybridConfigProvider (DB → `.env`), scan manifests, validate, import plugin modules, then call `PluginManager.load_plugins(config)`. Ensure this happens early in the program initialization, before handling any fax send requests.

Core Logic Changes: Wherever the core previously directly handled tasks now managed by plugins, update it to use the PluginManager. For instance:

When an API call or function to send a fax is invoked, instead of calling a Phaxio SDK or Asterisk command, retrieve the active transport plugin:

transports = plugin_manager.plugins.get(PluginType.TRANSPORT, {})
if not transports:
    return Error("No transport plugin configured.")
# assuming one active transport for now:
plugin = list(transports.values())[0]
try:
    fax_id = plugin.send_fax(to_number, file_path)
    return Success(fax_id)
except Exception as e:
    log.error(f"Fax sending failed: {e}")
    return Error("Fax sending failed, please check logs.")


This way, the send logic is abstracted. If needed, identify the plugin by id if multiple are loaded (the DB config should mark one as default/active). Never branch on backend name strings in code; always select by traits/manifest.

Idempotency and Canonical Events (Phase 1 scope):

- `POST /fax/send` accepts `Idempotency-Key` header
- Persist `{ idempotency_key, provider_id, external_job_id, status }` and return the same job on duplicates
- Emit canonical events: `FAX_QUEUED`, `FAX_SENT`, `FAX_DELIVERED`, `FAX_FAILED` from a central mapper, regardless of provider

Webhook Routing (never guess):

- On send, persist `job.provider_id` and `job.external_id`
- On webhook: use plugin.verify_webhook(headers, body); load by `external_id` and `provider_id`, then dispatch to that plugin’s handler

Async Webhooks & SSE:

- Webhook endpoints must be `async def`, and call `await plugin.verify_webhook(...)` then `await plugin.handle_status_callback(...)`.
- SSE diagnostics should use an async generator with periodic heartbeats to keep connections alive; never stream PHI.

When a status webhook is received (if applicable), determine which plugin it pertains to. If Phaxio, forward the payload to PhaxioPlugin.handle_status_callback(data). If Asterisk or others, similarly. You might map endpoints or use an identifier in the webhook (Phaxio might include a fax ID or something that can map to a plugin). Since Phase 1 mainly ensures the structure, a simple approach is: if Phaxio plugin is loaded, assume callbacks are for Phaxio, etc. In future, a more dynamic mapping can be done (like storing fax_id->plugin mapping when sending faxes).

Error Handling & Logging: Verify that any exception in a plugin’s method (e.g., if Phaxio API is down and send_fax raises) is caught by the core or by the plugin manager. We have try/except in PluginManager.initialize and plan to catch in usage as above. This prevents crashes. Ensure that plugin exceptions don’t propagate uncaught to the main event loop or API. All plugin errors should be logged with context (which plugin, what error) for debugging, but the system should continue running.

Unit Tests: Write tests (if possible) for critical parts of Phase 1:

Test that PluginManager.load_plugins correctly loads a dummy plugin and handles errors. You can create a dummy plugin class in tests that intentionally raises in initialize to see if PluginManager skips it gracefully.

Test that send_fax routing works: e.g., monkeypatch a plugin’s send_fax to return a known value and see that the core function returns that.

Test the wizard input parsing (this could be done by simulating input streams). Also test that the wizard produces a valid config file given sample answers.

Manual Testing: Given the significance of this overhaul, also perform manual integration testing:

Run the setup wizard in a dev environment, input fake or real credentials, and ensure a config file is created properly.

Start Faxbot with the new config, ensure the plugin loads (check log output or internal state).

Attempt to send a fax (maybe simulate it if actual fax services aren’t easily testable) and verify the flow goes through the plugin’s send_fax. If using real services (Phaxio), try a real API call to confirm it works under the new structure.

Simulate a plugin failure: e.g., change the API key to an invalid one, and ensure that send_fax raises an error which is caught and does not crash the app. The error should be reported clearly.

If possible, test switching plugins (e.g., run wizard to configure Asterisk instead of Phaxio, and see that the system uses the Asterisk plugin accordingly).

Admin Console wiring (read‑only for Phase 1):

- `/admin/providers`: list active/available providers with `name`, `type`, `traits[]`, `status`, and an action: “Test connection”
- `/admin/config`: show effective config with source badges `(db|env)`, secrets masked, and a banner if DB is empty (“Using .env fallback”)
Both are trait‑gated and all links are built from `docsBase`.

Diagnostics and Circuit Breaker:

- Add diagnostics: active provider, config source (db|env), trait snapshot, SSE health; never include PHI
- Track plugin failures; mark `status="degraded"` after N failures in M minutes; surface in Diagnostics; manual disable in Phase 1 (auto‑disable can follow in Phase 2)

Hardening and Documentation:

Documentation for Developers: Create a markdown document (or update README) explaining the new plugin architecture: how to add a new plugin, what traits/types/scopes mean, and how to configure via the Admin Console (primary) or optional CLI wizard. Outline the steps to create a plugin (inherit FaxbotPlugin, declare type/traits, implement methods, etc.), and how to integrate it via the HybridConfigProvider and the `plugin_registry.json`.

Enforce Non-Breakability: Add final touches to ensure even a malicious or buggy plugin can’t easily break things:

Use timeouts or threading if a plugin could hang (e.g., ensure that if a plugin doesn’t respond or takes too long, the core can move on or kill that operation – this might be advanced for Phase 1, but at least note it for future phases).

If a plugin throws exceptions frequently, consider marking it as unstable. Perhaps the manager can maintain a failure count and auto-disable a plugin if it exceeds a threshold, with a log message. This way it stops cascading failures (for example, a plugin consistently throwing in a scheduled task).

Make sure that plugins operate only through well-defined interfaces. For example, if a plugin needs to write a file or send a network request, ideally provide utility functions or services for them rather than letting them use arbitrary calls (this is more of a Phase 2/3 security hardening, but in Phase 1, we at least delineate what they should do).

Configuration Safety: Ensure that loading of config and plugins is robust. If the DB config is absent, fall back to `.env` and surface a clear Admin Console banner to complete setup. If a plugin referenced in the registry isn’t available, log and skip. Always fail gracefully with guidance, not just stack traces.

Non‑blocking I/O policy (Phase 1):

- Replace `requests` with `httpx.AsyncClient` for provider calls.
- Use `anyio.open_file` for small file reads; offload large file ops and conversions to a threadpool or `asyncio.create_subprocess_exec`.
- Limit manifest scanning/validation to startup only; never scan on request paths.

Blocking I/O Audit (dev helper):

```bash
# Run from repo root to surface blocking/sync usage on hot paths
echo "== requests/http sync use ==" && rg -n "requests\."
echo "== sync SQLAlchemy in async context ==" && rg -n "\.query\(" api/app | rg -v "tests?/"
echo "== subprocess blocking ==" && rg -n "subprocess\.(run|Popen|check_)" api/app
echo "== time.sleep ==" && rg -n "time\.sleep\(" api/app
echo "== file open on hot path ==" && rg -n "open\(" api/app | rg -v "(migrations|setup|tests?)/"
echo "== os.walk on request path ==" && rg -n "os\.walk\(" api/app
echo "== sync YAML/JSON loads per-request ==" && rg -n "(yaml|json)\.(load|loads)\(" api/app | rg -v "config/bootstrap|startup"
```

Wizard polish: Make sure the wizard has clear prompts and validations to minimize user error. For example, if expecting a phone number for fax test, ensure it’s numeric; if expecting a file path, perhaps allow the user to just press Enter for default, etc. This ties back to user-friendliness and preventing "errant user input" from causing issues.

Conclusion of Phase 1: After implementing the above, Faxbot will have a solid, modular core. All critical functionalities are behind plugin interfaces, with a manager orchestrating them. The system is configuration-driven (HybridConfigProvider with DB-first reads), which means future changes (Phase 2–5) can build on this without needing to rewrite the core again. We have minimized the risk of domino-effect failures by isolating plugin errors and validating inputs early, and we have honored the Admin Console–first mandate.

Result: Phase 1 delivers a pluggable architecture where adding or modifying fax backends (or other features) is done via well-defined plugin classes. A new developer or AI agent can read the clear class/function definitions and extend or fix components without guessing where things belong. The Admin Console provides the primary setup path (with an optional CLI helper), reducing support burden and aligning with compliance needs. With this foundation in place, subsequent phases can add more plugins (for new features), UI improvements, security hardening, etc., on top of a stable core.

Phase 1 Alignment & Acceptance Criteria (AGENTS.md)

- Admin Console first:
  - At least one minimal, trait-gated configuration panel in `api/admin_ui` that shows effective provider traits and a safe toggle/input for the active outbound provider.
  - All links built from `docsBase`; at least one “Learn more” link per screen. Use Responsive kits and verify xs/sm/md breakpoints.
- Traits-first gating, no backend-name checks:
  - UI and server must gate logic by traits from `config/provider_traits.json` and provider manifests. Use server helpers (e.g., `providerHasTrait`) and surface traits to the UI via `/admin/config` and `/admin/providers`.
- Hybrid configuration:
  - Reads resolve DB → `.env`; minimal safe writes persist to DB without restart. No standalone `config.yaml`.
- Security and PHI:
  - No PHI in logs; mask secrets in UI; error codes map to 400/401/404/413/415 consistently.
- MCP transport (HIPAA):
  - SSE is the only HIPAA-compliant transport; validate SSE path with the MCP Inspector before closing Phase 1.
- Diagnostics:
  - Add a small diagnostics readout: current active provider, config source (DB/env), traits snapshot, SSE health.
- Manifest-first discovery:
  - Plugins are discovered via `manifest.json` scanning and validated against `plugin-dev-kit/manifest.schema.json`. Plugin classes must inherit the correct typed base (`TransportPlugin`, etc.).
- API contract improvements:
  - `POST /fax/send` supports `Idempotency-Key` and emits canonical events. Webhooks route by persisted `provider_id`/`external_id` and use plugin `verify_webhook`.
- Admin endpoints and UI:
  - Server exposes `/admin/providers` and `/admin/config` with effective config and source badges; Admin Console renders read‑only panels and a “Test connection” action.

Sources
