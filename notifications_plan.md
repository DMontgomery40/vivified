Vivified Notification Plugins: Apprise and Pushover – Implementation Plan
Overview and Objectives

We will implement two notification plugins – AppriseNotifier and PushoverNotifier – as proof-of-concept plugins for the Vivified platform. These plugins will be bundled with Vivified’s core (optional at runtime) to exercise the full plugin architecture. The goal is to demonstrate how plugins integrate via Vivified’s three-lane model and manifest system:

Canonical Lane: Both plugins subscribe to canonical NotificationRequest events (universal notification requests) and publish NotificationSent events after processing. This tests the event bus integration and trait-based event routing (only plugins with a “notifications” trait get notification events).

Operator Lane: Each plugin exposes a POST /send HTTP endpoint for direct dispatch. This allows the Admin Console or other plugins to invoke notifications on-demand through Vivified’s API gateway. We will show an example POST /send call with JSON payload and the plugin’s response.

Manifest System: Each plugin includes a manifest (YAML/JSON) declaring its traits, required config keys, event subscriptions, transformers, and endpoints. The core uses this at registration to wire the plugin into the system (enforcing any dependencies or policies).

Policy Engine Integration: The core’s policy engine will use the manifest traits to enforce security. For example, it ensures that only plugins with the handles_notifications trait receive NotificationRequest events and that only authorized users/plugins invoke the /send endpoint. The policy engine checks trait and role compatibility on every cross-component interaction.

By implementing AppriseNotifier (a multi-provider notification gateway) and PushoverNotifier (a single-provider push service), we validate that Vivified can support both complex, multi-channel integrations and simple, targeted integrations. Both plugins will be containerized (each running as an isolated service) and registered with Vivified at startup via their manifests. Below, we detail the file layout, manifest contents, event flows, and lifecycle for each plugin, along with example data contracts and how they surface in the Admin Console.

Vivified Plugin Architecture Context

Before diving into the plugins, recall that Vivified’s architecture uses a three-lane communication model. The two relevant lanes here are:

Canonical Lane (Event Bus): a publish/subscribe channel for standardized events. Plugins communicate using canonical data models – e.g. a CanonicalNotification schema – so that all services share a common language. For instance, when a notification is requested, a NotificationRequest canonical event is published on the central bus. Notification plugins subscribe to such events and transform them into provider-specific actions. Likewise, after sending, plugins emit a NotificationSent event on the bus, which other components (or audit loggers) can consume. The core brokers these events and can attach metadata or enforce filters as needed.

Operator Lane (Direct Calls): a request/response path for invoking plugin operations via the core (acting as an API gateway). Each plugin exposes HTTP endpoints (like /send) that the core can call on behalf of users or other plugins. All such calls go through core’s gateway for authentication and authorization. For example, one plugin can request another plugin to perform an action by calling a core URL like /gateway/{plugin}/{operation}; the core verifies permissions and forwards the request to the target plugin’s service. In our case, the Admin Console or an automated script can call the Apprise or Pushover plugin’s /send endpoint through the core to send a notification immediately. Every call is checked by the policy engine (e.g. only an admin or an allowed plugin can trigger a send) and is traced for auditing.

Each plugin runs in isolation (in its own Docker container), communicating with core only via these lanes. They never directly access core’s database or internal files; all interaction is through events or API calls mediated by core. This plugin-first design, with strong contracts and isolation, ensures that plugins can be added or removed without modifying core, and that security and compliance are centrally enforced.

Plugin Manifest and Traits

Vivified plugins include a manifest file describing their capabilities and requirements. The manifest for each of our notification plugins will declare:

Name and Role: e.g. "name": "AppriseNotifier" and that it implements a Communication/Notification plugin interface (implicitly understood by core). This identifies the plugin and its general category.

Traits: e.g. ["handles_notifications", "requires_config", "external_api"]. Traits are flags that describe plugin capabilities or needs.

handles_notifications indicates the plugin deals with notification events, allowing it to subscribe to notification-related canonical topics. The core will use this to route NotificationRequest events only to appropriate plugins.

requires_config tells core that the plugin needs configuration (API keys, etc.) before it can function. Core’s config service or Admin UI will prompt the operator to supply those settings, and core will ensure they are present (and encrypted if needed) before fully enabling the plugin.

external_api (if used) flags that the plugin communicates with an external service over the network (e.g. Pushover’s REST API or various Apprise targets). The core can use this to apply sandbox rules – for example, only allowing network access to whitelisted domains for this plugin. In the manifest we can include an allowed_domains list (for PushoverNotifier, this might include api.pushover.net) so that core’s proxy or network policy permits those calls.

Config Keys: a list of configuration parameters the plugin needs. For AppriseNotifier, this might be an Apprise config (like a list of service URLs or a path to a config file) and optionally credentials for certain services if not embedded in the URLs. For PushoverNotifier, the required config would be Pushover API credentials – e.g. PUSHOVER_API_TOKEN and PUSHOVER_USER_KEY. The manifest can specify metadata for each (type, description), allowing the Admin Console to render a settings form for these keys.

Event Subscriptions/Pubs: which canonical events the plugin subscribes to and which it publishes. Both plugins will subscribe to the NotificationRequest event type (on the canonical bus) and will publish NotificationSent events. We will also include any other events they handle – for example, they might subscribe to a HealthCheck event (if the core uses an event to trigger health checks) and publish a PluginStatus event in response, though health is primarily handled via HTTP heartbeat in our design. The manifest enumerates these so core knows how to connect the plugin to the event bus topics.

Transformers: references to transformer functions or classes that convert between canonical models and plugin-specific data. For instance, a NotificationRequest (canonical) needs to be transformed into an Apprise notification payload or a Pushover API call. We will implement transformer hooks (in code) and list them in the manifest, such as "transformers": {"CanonicalNotification->ApprisePayload": "apprise_notifier.transformers.to_apprise"}. This helps Vivified’s Canonical Model Engine understand how to normalize data to/from this plugin.

Endpoints & Hooks: the HTTP endpoints the plugin exposes (like /send, /health) and any lifecycle hooks. We will list the base URL or route patterns and supported methods (e.g. POST /send). Lifecycle hooks include an init routine (called when the plugin starts), a heartbeat/health endpoint (for core’s periodic checks), and a shutdown routine for graceful termination. These allow the core to manage the plugin’s lifecycle (e.g. ping it periodically to ensure it’s responsive, and call shutdown during system stop).

Finally, the manifest can also specify dependencies (if a plugin requires another plugin or core service). In our case, PushoverNotifier might depend on an Identity plugin if it needed to lookup user contact info. We will note this possibility but for the base implementation we’ll assume direct config of the user key. If identity integration is desired, we could add to the manifest something like depends_on: ["IdentityPlugin"] to ensure the identity service is available for lookup.

With this context, we now detail each plugin.

Apprise Notification Plugin (Multi-Provider)

AppriseNotifier is a multi-channel notification plugin built on the Apprise library. Apprise is a Python notification library that supports 100+ services (email, Slack, Discord, SMS, push, etc.) through a unified API
github.com
. This plugin will serve as a general outbound notifier that can fan-out messages to multiple providers at once, demonstrating Vivified’s ability to handle broad integrations.

Plugin File Structure and Containerization

We will package AppriseNotifier as a Python microservice. The directory structure (within Vivified’s plugins folder) might be:

vivified/plugins/apprise_notifier/
├── Dockerfile
├── manifest.yaml
├── app.py                 # Main application (Flask/FastAPI app & event handling)
├── transformers.py        # Canonical <-> Apprise data transformations
├── requirements.txt       # (including apprise library)
└── README.md              # Plugin documentation (optional)


Dockerfile: Based on a lightweight Python image, installing the apprise package. For example, FROM python:3.11-slim then pip install apprise. It will copy in the app.py, transformers.py, etc., and set the entrypoint to launch the web app (and connect to the event bus).

manifest.yaml: Declares plugin metadata as discussed (traits, events, config, etc.). See sample manifest excerpt below.

app.py: Implements the plugin’s logic. It will likely use a small web framework (Flask or FastAPI) to define the /send and /health endpoints, and use the Vivified Python SDK for event bus access. On startup, it registers event subscriptions (e.g. subscribe to NotificationRequest on the NATS or Redis bus) and defines an event handler callback. It also loads configuration (e.g. from environment variables or a core config service API).

transformers.py: Defines functions to transform a CanonicalNotification object to the format needed for Apprise (and possibly vice versa for events it emits). For instance, to_apprise(canonical_notif) might produce a list of Apprise target URLs and a message.

requirements.txt: will include apprise and any framework (Flask/FastAPI, NATS client library, etc.).

README.md: describes how to configure and use the plugin (for developers).

Containerization: The plugin runs in its own container, e.g. vivified_apprise_notifier. In a development setup (docker-compose), this container would connect to the event bus and be reachable by the core for operator calls. The manifest could specify a default internal port (e.g. 5000) so the core knows where to contact it. The container will run as a non-root user and be limited in permissions (only needs network access to send outbound requests to notification services) – we may use Docker networking rules to only allow egress to certain domains (or rely on core’s proxy if enforcing that path).

Manifest for AppriseNotifier
# vivified/plugins/apprise_notifier/manifest.yaml (excerpt)
name: AppriseNotifier
version: "1.0"
traits: 
  - handles_notifications 
  - requires_config 
  - external_api            # calls external notification services
contract: CommunicationPlugin  # (implements sending messages)
allowed_domains: ["*"]      # (for demo, allow all or specify known domains like smtp, slack.com, etc.)
config:
  - key: APPRISE_TARGET_URLS
    description: "One or more Apprise service URLs (comma-separated) to send notifications to."
    required: true
  - key: APPRISE_CONFIG_FILE
    description: "(Optional) Path to Apprise config file for complex setups."
    required: false
events:
  subscribes:
    - NotificationRequest   # listen for incoming notification requests (canonical)
    - System.Heartbeat      # e.g. listen for heartbeat ping events (if used by core)
  publishes:
    - NotificationSent      # emit after sending notifications
    - PluginStatus          # e.g. emit status/metrics on heartbeat (optional)
transformers:
  - name: CanonicalToApprise
    from: CanonicalNotification
    to: ApprisePayload
    handler: apprise_notifier.transformers.to_apprise
  - name: AppriseResultToCanonical
    from: AppriseResult
    to: CanonicalNotificationSent
    handler: apprise_notifier.transformers.to_canonical_sent
endpoints:
  - path: /send
    method: POST
    purpose: "Send a notification immediately via Apprise"
  - path: /health
    method: GET
    purpose: "Health check endpoint for core"
lifecycle:
  init: "apprise_notifier.app:init_plugin"        # initialization hook
  shutdown: "apprise_notifier.app:shutdown_plugin"
  heartbeat: "apprise_notifier.app:health_check"  # could be triggered by core


Notes: The manifest above indicates the plugin’s intentions to the core. For example, handles_notifications trait tells the core that when a NotificationRequest event occurs, this plugin is a valid target. The requires_config trait and config keys ensure that Vivified’s config service or Admin UI will provide APPRISE_TARGET_URLS (e.g. the admin might configure it to "mailto://alerts@company.com,smtp://smtp.server/..." or a Slack webhook URL, etc.) before enabling the plugin. In practice, the core might inject these as environment variables or the plugin can call the core to fetch them on init. The external_api trait combined with allowed_domains hints that this plugin will reach out to external hosts; the core may restrict network access only to those domains (for simplicity, ["*"] or a broad list can be used in dev, but production would tighten this).

The events section declares interest in NotificationRequest. The core’s messaging engine will subscribe the plugin to the appropriate bus topic (e.g. events.NotificationRequest) when the plugin registers. Similarly, the plugin’s published events (like NotificationSent) can be topics it publishes to (e.g. events.NotificationSent or plugin.AppriseNotifier.NotificationSent depending on naming convention).

Handling Notification Events (Canonical Lane Flow)

Once running, AppriseNotifier will handle notification events as follows:

Subscription: On startup, the plugin (via the SDK or custom code) subscribes to NotificationRequest events on the canonical event bus. For example, it might subscribe to a subject like events.notification.request (or similar) that core uses for all notification requests. Core only delivers these events to plugins with the proper trait; when a NotificationRequest comes in, core’s policy engine checks that AppriseNotifier has handles_notifications and then allows it through. (If it did not, core would drop or ignore the event for this plugin.)

Event Structure: We define NotificationRequest (canonical model) to include fields such as: a notification ID, recipient or user reference, message title, message body, and possibly a category/priority. For example, a NotificationRequest event JSON might look like:

{
  "event_type": "NotificationRequest",
  "notification_id": "abc123",
  "user_id": "u001",
  "title": "Welcome to Vivified",
  "body": "Hello, your account is created.",
  "priority": "normal",
  "channel": "any" 
}


(The channel or similar field could hint if this is an email, SMS, etc., but since AppriseNotifier can broadcast to multiple channels, it might ignore or use a default set.)

Transformation to Apprise Payload: Upon receiving the event, AppriseNotifier invokes its transformer to convert the canonical notification into a format suitable for Apprise. The transformer (to_apprise in transformers.py) will do tasks such as:

Look up the actual target addresses. If the event provides a specific user_id, the plugin might call an identity service (via operator lane) to get that user’s contact info (email, phone, etc.), though for simplicity, AppriseNotifier might just use the configured target list. In a more advanced use, the plugin could map user_id to specific Apprise URLs (for instance, if the user’s email or Telegram ID is stored in a profile). For this proof-of-concept, assume the plugin uses a static list of targets provided in config (like an email address list or chat webhook for broadcasts).

Construct the message content. It might use title and body from the event to form the notification. Apprise can handle a title and a body separately, which maps well from canonical.

The result might be an Apprise API call. For example, using Apprise in code:

import apprise
targets = os.getenv("APPRISE_TARGET_URLS").split(",")
app = apprise.Apprise()
for url in targets:
    app.add(url)
# Send the notification
app.notify(title=notif.title, body=notif.body)


Apprise will then dispatch that message to all configured URLs asynchronously. If any target fails, Apprise returns a result with success/failure per service.

Apprise supports many services; by adjusting the config, this one plugin can send emails, Slack messages, SMS, etc. (Multi-provider fan-out). This demonstrates Vivified’s multi-backend provider support, letting one canonical event trigger notifications on multiple platforms
github.com
.

Sending and Response: The plugin executes the send. We log the outcome (success or any errors per service). Because all heavy lifting is inside Apprise, our plugin code mostly just handles input and output. If needed, any exceptions or failed sends could be caught; for example, if Apprise indicates a particular service failed (maybe invalid credentials), the plugin might decide to emit a warning log or even a specialized event (like NotificationFailed), but for now we’ll just handle overall success.

Emit NotificationSent Event: After attempting delivery, AppriseNotifier publishes a canonical NotificationSent event on the bus. This event serves as an acknowledgment that a notification was processed (and presumably delivered). It will include information such as:

{
  "event_type": "NotificationSent",
  "notification_id": "abc123",
  "plugin": "AppriseNotifier",
  "timestamp": "2025-09-28T08:00:00Z",
  "status": "sent", 
  "details": {
     "targets": ["email:success", "slack:success"] 
  }
}


The details might list each target and whether it succeeded. The core receives this event (and can log it or display it in the UI), and any other plugin that cares (perhaps an Audit plugin or the originating service) can subscribe to NotificationSent. This round-trip (Request -> Sent) confirms the event-driven workflow is working. It also tests the canonical transformer on the output side, converting any Apprise response into our canonical NotificationSent format (handled by AppriseResultToCanonical in transformers). All events on the bus carry metadata (timestamp, source plugin ID, etc.) that the core can use for audit trails.

In summary, AppriseNotifier listens on the canonical lane, transforms canonical messages to provider-specific actions, and emits canonical results. This showcases the decoupled integration: any part of the system can ask for a notification by raising an event, without needing to know how or to whom it’s sent – the Apprise plugin handles it and reports back asynchronously.

Direct Send Endpoint (Operator Lane)

AppriseNotifier also exposes an operator endpoint /send to allow direct triggering of notifications via a synchronous API call. This is useful for the Admin Console (e.g. a “Send Test Notification” button) or for other plugins that want to send a notification on-demand (rather than emitting an event and waiting). The operator lane call goes through Vivified’s core API gateway which then invokes the plugin:

Endpoint Definition: POST /send (as listed in manifest) expects a JSON payload describing the notification to send. We design the payload to mirror the canonical model for convenience. For example, an admin could call (via core) POST /plugins/apprise_notifier/send with body:

{
  "title": "System Alert",
  "body": "All systems operational.",
  "targets": ["mailto://ops@company.com"] 
}


If targets is omitted, the plugin could default to its configured APPRISE_TARGET_URLS list (broadcast). If provided, the plugin may either override or filter against allowed targets (for security, perhaps only certain domains or types are allowed – though with admin invoking, we assume trust). The plugin could also accept an optional user_id instead of raw targets, to look up a specific user’s contacts, demonstrating integration with identity.

Core Mediation: The call from the UI or another service actually hits the core’s API gateway, not the plugin directly. The core will authenticate the caller (e.g. ensure the user is an Admin or the calling plugin is allowed) and then forward the request internally to AppriseNotifier’s service. This may involve core looking up the plugin’s address/port from a registry. The entire operator call is access-controlled: the policy engine verifies that the caller’s role/traits allow invoking this plugin’s operation. (For instance, if a non-admin user tried to hit this endpoint, core would reject it, since sending arbitrary notifications is likely an admin privilege.)

Processing: Once the request reaches the plugin’s /send handler (in app.py), the plugin will parse the JSON and create a CanonicalNotification object (or simply reuse the JSON as input to the same logic used for events). It can then call the same internal function as above to perform the send (i.e. use Apprise to deliver). In effect, this is just another entry point to trigger the same behavior as the event subscription, but synchronously.

Response: The plugin returns an acknowledgment. Typically, we’d return a JSON indicating that the notification was dispatched, possibly including an internal tracking ID or the content of a NotificationSent event. For example:

{
  "status": "ok",
  "notification_id": "abc123",
  "sent": true,
  "timestamp": "2025-09-28T08:00:00Z"
}


If the plugin actually waits for confirmation, it could indicate success per target, but since Apprise sends asynchronously, we might just respond quickly with status "queued" or "ok". Meanwhile, the actual confirmation comes via the NotificationSent event later. In a simple implementation, we assume success if no error raised in Apprise, and return 200 OK.

This operator call demonstrates direct plugin invocation and how the core’s gateway brokers it. It’s a concrete example of Vivified’s operator lane: the Admin Console (or another plugin) performs an HTTP call to core, core authenticates and forwards to plugin, plugin executes action and replies. All such calls are logged and auditable (the core would log “Admin called AppriseNotifier.send”) for compliance.

Example: The Admin UI might have a form to test notifications. When submitted, it calls the core’s admin API, which maps to the plugin’s /send. The admin’s credentials (JWT or session) ensure they have the right to do so. The plugin sends the notification (maybe to the admin’s own address as a test) and returns a result. This round-trip confirms the plugin’s operator interface is functioning as expected.

Configuration and Security Considerations

AppriseNotifier requires configuration to know where to send notifications. We leverage Vivified’s config service and manifest declarations to handle this:

Config Management: The keys defined (like APPRISE_TARGET_URLS) will be set via the Admin Console’s plugin configuration UI. The Admin Console reads the manifest and renders input fields for these keys. For example, the admin might enter a comma-separated list of Apprise URLs or supply an Apprise YAML config file. Core stores this securely (possibly encrypted) and provides it to the plugin. The plugin can retrieve config either by environment variables (if core injects them at container launch) or by calling a core API (e.g. GET /admin/config/{plugin}/{key} if available). In our design, passing via env on startup is simplest for POC.

Requires Config Trait: The requires_config trait means core will not fully activate the plugin until config is provided. If the plugin starts without config, it might run in a dormant state (or core could even not start it). In the Admin Console, this trait could also visually indicate that “setup is needed” (e.g. a warning icon until configured).

Secrets: The Apprise plugin might not need traditional API secrets itself (because it might send to services like email or Slack where credentials are in the URLs or in config file). But if it did (e.g. Twilio SMS requires account SID/token), those would be included in the APPRISE_TARGET_URLS or config file. We ensure these values are stored securely by core and not exposed. The plugin sees them only as needed to send out messages. This follows the Vivified principle that core handles all sensitive config and provides only what’s necessary to plugins.

External Access: Since Apprise will make outbound network calls to various services (SMTP servers, Slack webhooks, etc.), in a hardened deployment we would use the Proxy Lane or sandbox rules. For the POC, we might allow direct egress to simplify things, but we note how it fits architecture:

Allowed Domains: The manifest can include known domains or patterns the plugin will contact (we put "*" for now, but ideally this might be a list like ["slack.com", "smtp.sendgrid.net", "api.pushover.net"] depending on usage). The Vivified core or deployment uses this to configure network policy (e.g. in Docker, the plugin’s network could be restricted except to those hosts).

Proxy Option: Alternatively, the plugin could call an internal proxy API (e.g. core/proxy?url=https://api.service.com/...) to have core perform the external request on its behalf. This ensures all external calls are mediated. For Apprise, that would require intercepting each HTTP call Apprise makes – not trivial without custom adapter – so likely we rely on allowed outbound domains in this case. The external_api trait simply flags to operators that this plugin talks to outside services.

Permissions: The policy engine will ensure that only authorized components trigger this plugin. Since it’s a notification sender, we likely restrict usage to internal system events or admin actions. Regular end-users wouldn’t directly call it. In trait terms, perhaps only plugins with a “can_trigger_notifications” trait or core itself can send NotificationRequest events of certain types. At the event bus level, if a highly sensitive event came through, core could filter it if the plugin isn’t cleared for it (not applicable here beyond the basic notification trait). This aspect isn’t heavily in play for AppriseNotifier (since it’s meant to handle notifications), but it’s part of the architecture that we verify: the core does indeed check trait compatibility when routing events and calls.

Lifecycle Hooks: Initialization, Heartbeat, and Shutdown

The AppriseNotifier plugin implements the standard lifecycle hooks to integrate with Vivified’s monitoring and control:

Initialization: When the plugin container starts, it runs an init_plugin() function (referenced in manifest). This function might register the plugin with the core (if core requires a handshake), fetch initial config, and connect to the event bus. For example, it might log “AppriseNotifier initialized” and perhaps send a small event or call to core to announce it’s ready. If config is missing or invalid (e.g. no targets provided), it can notify core of an error state so the admin knows to configure it (or core can disable it). In dev, we’ll assume config is set beforehand.

Heartbeat/Health: The plugin exposes a /health endpoint (or similar). The core will periodically call this (e.g. every 30s) to check if the plugin is alive. Our /health simply returns 200 OK and perhaps some info (like {"status":"ok","uptime":12345}). Internally, we can also monitor Apprise’s health. While Apprise is a library (it doesn’t maintain a persistent connection), health mainly means “is the plugin service running and able to send”. We simulate deeper health checks by possibly performing a lightweight action on interval: e.g., the plugin could attempt to send a no-op or ping to one of its providers or just rotate an internal flag. Additionally, we can implement a heartbeat event subscription: if core broadcasts a System.Heartbeat event on the bus, the plugin can listen and respond by emitting a PluginStatus event with metrics. For instance, on receiving a ping, it could publish:

{
  "event_type": "PluginStatus",
  "plugin": "AppriseNotifier",
  "uptime": 3600,
  "notifications_sent_count": 10,
  "last_error": null
}


This is one way to report connectivity and metrics via events, in addition to the HTTP health check. It demonstrates that plugins can respond to system triggers with status info. The core can aggregate these or display them in the Admin Console.

Metrics Tracking: As notifications are sent, AppriseNotifier can keep counters (e.g. using Prometheus client or simple variables). For example, emails_sent_count or a general notifications_sent_count. The plugin can expose these via an endpoint or the aforementioned status event. Vivified’s monitoring infrastructure (if using Prometheus/Grafana) could scrape an endpoint from the plugin container. We intend to include at least a basic metric: count of notifications sent. This aligns with the platform’s approach of each plugin contributing metrics that core collects. In our POC, we might not set up a full Prometheus, but we ensure the plugin has the hook (e.g. a /metrics endpoint or part of /health output).

Shutdown: If the system is stopping or the plugin is being disabled, core will call the plugin’s shutdown hook (or send a terminate signal to the container). Our plugin will implement shutdown_plugin(), which can perform cleanup like flushing logs, closing bus connections gracefully, etc. Since Apprise doesn’t hold long connections, it’s mostly about ensuring no events are being processed mid-way. The plugin should deregister from the bus (if needed) and prepare to stop. It might emit a final log or event indicating it’s going offline (useful in a cluster scenario so core knows it’s gone).

These lifecycle hooks prove that the plugin can be managed by the core. The health monitoring in particular shows how Vivified ensures plugins remain responsive (the core will mark a plugin unhealthy if /health fails or if no heartbeat event is received in a while). By implementing these, we simulate connectivity monitoring – for instance, if AppriseNotifier had lost connectivity to the event bus or crashed, it wouldn’t respond to health checks, and core could flag it. We also simulate system metrics triggers by possibly responding to a metrics collection event or at least logging metrics that core can scrape.

Admin Console Integration (AppriseNotifier)

From the admin perspective, once AppriseNotifier is included:

It will appear in the Admin Console’s plugin list (likely under a section for Notification Plugins, since the UI can group or label plugins by their traits/capabilities). The console, using data from core, might show something like: “AppriseNotifier – Traits: notifications, external – Status: Active (Configured)”. The UI is traits-first in the sense that it displays what the plugin does and any special flags. For example, an icon or label for “Notification Channel” could be attached due to handles_notifications, and maybe a warning or note if external_api (indicating it connects outside). If the current user is not allowed to use this plugin, the UI would disable its controls (using the allowed: false info from core’s feature endpoint).

In the Plugin Management page, the admin can click AppriseNotifier to view its details. The manifest-driven UI will show a Configuration form for APPRISE_TARGET_URLS (and any other config). Since this plugin requires config, if it’s not provided yet, the UI likely highlights “Requires configuration” and prompts the admin to fill it. After entering values and saving, core updates the config and likely restarts or notifies the plugin to use the new settings. The UI might also allow enabling/disabling the plugin (a toggle). If disabled, core would not route events to it or might stop the container.

The status/health of the plugin could be visible: e.g. a green dot indicating healthy (because the heartbeat is ok). If the plugin fails a health check, core would mark it and the UI might show it as offline.

The /send operator function can be exposed in the UI as well. The admin console could provide a small interface to invoke the plugin’s operations (especially for testing). For instance, there might be a “Send Test Notification” button which internally triggers the /send call. We ensure to document the expected payload, so the Admin UI knows what fields to ask for. Alternatively, in an advanced scenario, the manifest might describe the /send operation’s input schema, which the UI can use to generate a form. (If not, a cURL or a fixed test could be used.)

By bundling AppriseNotifier with the platform, we provide a canonical example of a notification plugin, which will also serve as a reference for developers (showing how to implement a plugin that handles events, transforms data, uses config, and provides endpoints). In summary, AppriseNotifier validates: event-driven notifications, multi-channel fan-out, config management, external API integration, and lifecycle health checks within the Vivified architecture.

What AppriseNotifier Validates in Vivified:

Canonical Event Handling: Subscribing to a common event and producing a common result event, with core mediating (demonstrated by trait-based delivery and event normalization).

Data Transformation Hooks: Conversion between Vivified’s canonical models and an external library’s inputs/outputs.

Multi-Provider Capability: One plugin sending notifications to multiple services (leveraging Apprise)
github.com
, showing that the platform can support broad integrations through a single plugin.

Required Configuration Workflow: Use of requires_config trait and manifest-defined config keys to integrate with core’s config service and UI (ensuring secrets/credentials can be managed securely and provided to the plugin).

Operator Lane Call: A safe, audited way to trigger plugin actions via HTTP call through core, with permission checks.

Lifecycle Management: The plugin cleanly registers, heartbeats, and shuts down as orchestrated by core, contributing health status and metrics to the system monitoring.

Policy Enforcement: Confirmation that only appropriate events reach the plugin and only authorized actors invoke it (e.g. trait “notifications” required to get the event, admin role required to call /send).

Pushover Notification Plugin (Single-Provider)

PushoverNotifier is a plugin dedicated to sending push notifications via the Pushover service. Pushover is a popular simple push notification service with a straightforward API: you post to an HTTPS endpoint with your app’s API token and the user’s key, plus a message
pushover.net
. This plugin serves as a focused example of integrating a single external provider. It complements AppriseNotifier by demonstrating a more specialized, lightweight plugin (and one that might be used for high-priority or individual notifications, e.g. sending critical alerts to an admin’s phone).

Plugin Structure and Setup

File layout is similar to Apprise’s, but simpler since the logic is specific:

vivified/plugins/pushover_notifier/
├── Dockerfile
├── manifest.yaml
├── app.py               # Main service (handles /send and event subscribe)
├── transformers.py      # (optional) transforms for Pushover payload
└── requirements.txt     # e.g. Python requests library for HTTP calls


Dockerfile: Could use a Python base as well (or even a very small Go program, but Python is fine). It will install any needed HTTP library (like requests for simplicity) to call Pushover. We include no heavy SDK; the plugin’s job is small.

manifest.yaml: Defines traits, config (Pushover keys), events, etc., as detailed below.

app.py: Will implement the subscription to NotificationRequest and the /send endpoint, analogous to Apprise’s but calling Pushover’s REST API. Could use Flask or even no framework by using Python’s BaseHTTPServer (for a minimal approach). However, using Flask can speed development. The event handling could be done via a background thread connected to the bus (with NATS/Redis client).

transformers.py: Might contain a helper to map a CanonicalNotification into the parameters needed for Pushover (title, message, etc.). Since Pushover’s API is simple, we might inline this logic in app.py, but having a separate file keeps parity in structure.

requirements.txt: e.g. flask, requests, pynats etc., and maybe python-dotenv if needed for config.

Containerization: The Pushover plugin container (vivified_pushover_notifier) will likewise join the Vivified network. It likely needs outbound internet access to reach api.pushover.net (443). If using strict network policies, we add an exception for that domain or route calls through core’s proxy. For development, we might allow direct egress. The container runs the Flask app on a given port (say 5001) and listens for core’s calls and connects to event bus for subscription.

Manifest for PushoverNotifier
# vivified/plugins/pushover_notifier/manifest.yaml (excerpt)
name: PushoverNotifier
version: "1.0"
traits:
  - handles_notifications
  - requires_config
  - external_api
contract: CommunicationPlugin 
allowed_domains: ["api.pushover.net"]
config:
  - key: PUSHOVER_API_TOKEN
    description: "API Token for your Pushover application"
    required: true
  - key: PUSHOVER_USER_KEY
    description: "Target user's Pushover User Key (or group key) to notify"
    required: true
events:
  subscribes:
    - NotificationRequest
  publishes:
    - NotificationSent
transformers:
  - name: CanonicalToPushover
    from: CanonicalNotification
    to: PushoverPayload
    handler: pushover_notifier.transformers.to_pushover
endpoints:
  - path: /send
    method: POST
    purpose: "Send a Pushover notification"
  - path: /health
    method: GET
    purpose: "Health check endpoint"
lifecycle:
  init: "pushover_notifier.app:init_plugin"
  heartbeat: "pushover_notifier.app:health_check"
  shutdown: "pushover_notifier.app:shutdown_plugin"


Key points in this manifest:

We again mark handles_notifications (so it will receive NotificationRequest events) and requires_config (must have API token and user key set). external_api is included because it will call out to api.pushover.net. We specifically list that domain in allowed_domains for clarity and security – core can ensure only that host is reachable by this container.

Config keys: PUSHOVER_API_TOKEN and PUSHOVER_USER_KEY are mandatory. These are values you obtain from Pushover’s website (the token identifies the Vivified application, and the user key identifies the recipient). The design here assumes one target user or group is configured – meaning this plugin, as initially implemented, always sends to the same user/group (e.g. an admin or an on-call team). We choose this for simplicity. In future, we could extend it so that the NotificationRequest event could specify which user or group to notify (and then lookup the corresponding key), but that requires either including the user key in the event or mapping user IDs to keys (through identity service). We mention that possibility below.

We subscribe to NotificationRequest events. It’s possible we might want to filter which notifications Pushover handles (e.g. only urgent alerts), but that filtering can be done either at the plugin (ignore events below a certain priority) or via event metadata and core policy. For now, it will respond to all NotificationRequests (which is fine if multiple plugins handle the same event).

One transformer is noted, though in practice we might not need a complex transform – essentially it will pick the title and message from CanonicalNotification and maybe truncate or format them to Pushover’s requirements (Pushover limits length, etc., but we won’t get into those details here).

Endpoints: /send and /health as expected. No extra operator endpoints (PushoverNotifier is narrowly focused).

Lifecycle hooks included similarly to Apprise.

Event Handling for Pushover (Canonical to Pushover flow)

When a NotificationRequest event is published on the bus, PushoverNotifier will receive it (assuming trait check passes). The flow:

Receive NotificationRequest: The plugin’s event listener picks up the event. Let’s say the event content is similar to the earlier example (title, body, user_id, etc.). If a user_id is provided and we wanted to target that specific user, the plugin could use it. For our base case, we will treat PUSHOVER_USER_KEY from config as the target regardless (meaning this plugin sends all notifications to one pre-set user or group). In a real scenario, user_id could be used to look up that user’s Pushover key:

If integrated with Identity: the plugin could make an operator call to Identity service: e.g. GET /identity/user/u001 to fetch user’s profile, expecting maybe a field pushover_user_key. This is analogous to the EmailGateway example where it fetched user data to personalize the email. This would demonstrate inter-plugin operator calls. However, this adds complexity for the POC. We can mention that if multiple users or dynamic routing were needed, that approach would be used, but for now assume a single target configured.

Core’s policy would allow this call only if PushoverNotifier is permitted to access identity info (we’d ensure trait compatibility, e.g. it might have a trait or permission to get basic user contact data).

Prepare API Call: Using either the event’s data or config, we form the HTTPS request to Pushover. Pushover’s API expects a POST to https://api.pushover.net/1/messages.json with form fields: token, user, message, and optionally title, etc.
pushover.net
. Our plugin will do something like:

import requests
payload = {
    "token": os.getenv("PUSHOVER_API_TOKEN"),
    "user": os.getenv("PUSHOVER_USER_KEY"),
    "message": notif.body
}
if notif.title:
    payload["title"] = notif.title
# Optionally handle priority, URL, etc if present in notif and needed
resp = requests.post("https://api.pushover.net/1/messages.json", data=payload, timeout=5)


We’d check resp.status_code and maybe parse resp.json() for a confirmation (Pushover returns a JSON with status and request ID). A successful response typically has "status":1 in JSON.

Because this is an external call, it’s subject to network reliability. The plugin should handle exceptions (timeout, DNS fail, etc.). For now, we assume it goes through.

Error Handling: If the Pushover API responds with an error (e.g. invalid token or user), the plugin can log this. It could also emit a different event like NotificationFailed (not required for this task, but worth noting). At minimum, we capture the error to include in the NotificationSent event.

Emit NotificationSent: Similar to AppriseNotifier, after attempting the send, PushoverNotifier emits a NotificationSent canonical event. This might contain:

{
  "event_type": "NotificationSent",
  "notification_id": "abc123",
  "plugin": "PushoverNotifier",
  "timestamp": "2025-09-28T08:05:00Z",
  "status": "sent",
  "details": {
    "pushover_receipt": "RX1ID2... (request ID from Pushover)",
    "user": "u001"
  }
}


If there was an error, status might be "failed" and details could include the error message. This event goes on the canonical bus; core will see it and can log it, and any other component waiting for notification results can act on it. This closes the loop for the event-driven path.

Notably, if both AppriseNotifier and PushoverNotifier subscribe to the same NotificationRequest, both will act (unless we set filters). This is acceptable in many cases (one event triggers multiple notifications via different channels). If it’s not desired for some notifications, those events could carry metadata about which channel or plugin to use, and plugins could decide to skip if they're not the intended channel. For simplicity, we assume every NotificationRequest is meant to be handled by all notification plugins (like a broadcast to all available channels).

Operator /send Endpoint for Pushover

The Pushover plugin’s /send works analogously to Apprise’s, but targeting the Pushover API. It allows immediate sends via API call:

Usage: An example call from an admin (through core) might be:

POST /plugins/pushover_notifier/send  (via core gateway)
{
  "message": "Backup completed successfully."
}


Since the plugin is already configured with the user key and token, the payload can be minimal – just the message text and an optional title. We could allow title, priority, etc., but assume defaults for brevity. If we wanted to override the target user, we could allow a user_key field in the JSON; the plugin would then use that instead of the configured one. This might be useful if an admin wants to send to a different person occasionally. However, allowing arbitrary user keys might be a security concern (someone could send to an unauthorized target), so by default we might disallow that for external calls. The admin could always change the config if they needed to send to a different user.

Processing: Upon receiving the POST, the plugin will create a dummy NotificationRequest internally or directly perform the steps to call Pushover (like the code above). It then returns a synchronous response indicating success or failure of the send.

Response: If successful, perhaps {"status":"ok","sent":true,"timestamp":...} or even include Pushover’s receipt. If failed (e.g. Pushover API returned an error), we might return a 500 status with an error message in JSON. The admin UI could show this result. Regardless, the plugin will also emit the NotificationSent or NotificationFailed event to the bus as record of the attempt.

Core Auth: The core ensures the caller is allowed. In this case, probably only Admin role can call this plugin’s endpoint. If another plugin needed to send a critical alert via PushoverNotifier, that plugin would issue an operator call (which core would treat similarly, checking if that plugin has rights – perhaps we allow any plugin to request a notification send as long as it’s an internal system action, or we restrict it to certain plugins like a “MonitoringPlugin” if specified). These rules can be configured in the policy engine. For now, assume admin or system components only.

This operator usage is straightforward and confirms that even a very simple plugin can expose functionality to others in a uniform way.

Configuration & Policy for PushoverNotifier

Config Setup: The admin must enter the Pushover API Token and User Key in the Admin Console (or via CLI/ENV in a dev environment) before PushoverNotifier can function. These are secret values (especially the API token). Core will store them securely (e.g. not expose in logs, possibly encrypt at rest). The plugin gets them as environment variables on startup. If not provided, the plugin’s init can detect that and either refuse to proceed or run in a state where /send calls will fail with a clear error. The Admin UI should indicate missing config if the plugin is enabled without those values (thanks to requires_config trait).

Single vs Multi-User: As mentioned, our POC uses one configured user key. This is fine for sending generic alerts (like to an ops team group key). If the use case expands to user-specific notifications (e.g. send a notification to user X on Pushover when something related to that user happens), we’d integrate with the identity system:

The NotificationRequest event might include a user_id or a target identifier.

The Pushover plugin would then require mapping from user_id to that user’s Pushover key. This could be done via an extended config (a table of user->key) or by storing the key in the user’s profile (and having IdentityPlugin provide it).

Demonstrating this fully would involve an operator call at runtime (plugin calling IdentityPlugin). We note it as a potential extension (and it’s similar to how the EmailGateway example fetched user emails via core).

For now, we assume notifications are either system-wide or to a fixed recipient.

Security/Policy: PushoverNotifier is by design sending data outside (to Pushover servers). The manifest’s allowed_domains: ["api.pushover.net"] ensures core knows about this external dependency. In a locked-down deployment, core could enforce that the plugin must use the proxy lane to reach that domain. If implemented, the plugin would instead call a core endpoint to relay the message. Since our plan is focusing on architecture rather than implementing the proxy, we allow direct POST with the understanding that core’s network policy will restrict the plugin from calling anywhere except api.pushover.net. This ensures even an exploited plugin couldn’t exfiltrate data to arbitrary hosts – it’s only allowed to talk to the Pushover API.

Audit Trails: Every time a notification is sent via PushoverNotifier (whether by event or API call), it’s a notable action. Vivified’s audit log would record events like “Plugin PushoverNotifier sent notification to user X at time Y” and any operator calls “Admin invoked PushoverNotifier.send”. This is important for compliance (especially if these notifications could contain sensitive info – though ideally they wouldn’t, as Pushover is outside system control). Our implementation will include logging those actions for audit (even if just to console in this POC).

Trait Enforcement: If there were some notifications that should not be sent via a push channel, we could tag those events differently. For example, a NotificationRequest event might carry a trait or type (say “PHI” if it contained health info). We might design the policy such that PushoverNotifier does not have handles_phi trait, so core would block any PHI-tagged notification from reaching it (to avoid sending sensitive info to a personal device). This kind of fine-grained control is part of Vivified’s policy engine and, while not fully fleshed out in the POC, we ensure our plugin has the traits that allow it to receive the events it should and none that it shouldn’t. In this case, it only has the generic notifications trait.

Health Monitoring and Metrics in PushoverNotifier

PushoverNotifier also includes basic health and metric reporting:

Health Endpoint: /health will respond with a simple status (HTTP 200 and maybe {"status":"ok","last_send":"2025-09-28T08:05:00Z"}). If the plugin encounters a persistent failure (e.g. wrong API token causing every send to fail), we might reflect that in health status (perhaps still 200 OK but with a field error_state: "Authentication failed" after trying, so the admin can see it). The core will treat any non-200 or non-responsive health check as a problem. The plugin should thus be lightweight and reliable in responding.

Connectivity Check: Unlike Apprise (which depends on various endpoints), PushoverNotifier depends on a single external service. We can implement a connectivity test by using Pushover’s validate API for user keys
pushover.net
. For example, on startup or periodically, we could call Pushover’s /users/validate.json with the token & user key to verify they’re correct. If the validation fails, we know upfront that sending will fail. This could trigger the plugin to emit a warning event or update an internal flag. For demonstration, we might manually call this in init_plugin() and log a message like "Pushover credentials invalid!" if so. That simulates proactive connectivity monitoring.

Metrics: We can maintain a count of messages sent via Pushover. Every time we call the API, increment a counter. We might track the last response time or last error too. These metrics can be exposed similarly to AppriseNotifier’s – e.g. via a PluginStatus event on a heartbeat or via a Prometheus metric. For instance, after each send, we update pushover_last_send_time and a cumulative pushover_messages_sent. The core’s monitoring could scrape those. In our design, we’ll at least log them or include in health output (e.g. /health could return {"status":"ok","sent_count":5}).

Shutdown: Nothing special needed; just ensure any threads (like an event listener thread) are stopped. PushoverNotifier is stateless aside from counters, so shutdown is straightforward.

Admin Console and Usage (PushoverNotifier)

Once deployed, PushoverNotifier will also appear in the Admin Console’s plugin list:

It may be listed alongside AppriseNotifier under “Notification Plugins”. Its trait list (notifications, external) is similar, and UI will show that. An admin can click it to configure the API token and user key. The UI likely hides the actual token after entry (for security), but allows updating it. The presence of external_api trait could prompt the UI to show an advisory (like “This plugin connects to an external service: api.pushover.net”) for transparency.

After configuring and enabling, the admin can test it. The UI might have a small form under this plugin’s page: e.g. fields for title and message and a “Send” button that calls the plugin’s /send via the core. This uses the same mechanism described earlier. The admin can confirm on their Pushover app that the notification arrived. Additionally, they can check the Vivified logs or NotificationSent events in the console to see that it was recorded.

If the plugin had an error (say the token was wrong), the Admin Console would likely surface that: maybe the health status turns red or an event in an “Alerts” panel says “PushoverNotifier: Authentication failure on send”. In our POC, we’d ensure that an error is logged and perhaps reflected in the NotificationSent event (status failed). The admin would then realize the config is incorrect.

The Admin Console uses the manifest to know what config fields to present (so it will show two input boxes for the token and user key). If we provided regex or format hints, it could even validate them (not mandatory here).

As with Apprise, the plugin can be toggled on/off. If off, core won’t route events to it (or will not start it at all). This might be used if, say, the admin only wants to use Apprise or Pushover, not both, to avoid duplicate notifications. Bundling them with core means they’re available, but the admin has control to enable the ones they want.

What PushoverNotifier Validates:

Direct Third-Party API Integration: Demonstrates that a Vivified plugin can connect to a specific external service using its API. We show how to incorporate the required keys and perform the HTTP call, which is a common pattern for many integrations
pushover.net
.

Fine-Grained Config and Secrets: Introduces a plugin that explicitly needs secret tokens, testing Vivified’s config distribution and secret management path.

Allowed Domain & Sandbox: By specifying the external domain in the manifest, we test Vivified’s approach to restricting plugin network access to only approved endpoints. PushoverNotifier essentially serves as a template for any plugin that calls an external REST API – it must declare the domain and abide by core’s proxy/firewall rules.

Trait-Limited Event Handling: If we later categorize notifications, we could show that PushoverNotifier only gets certain events. Even without that, it reinforces that only plugins with the notification trait get those events (we now have two such plugins to validate multiple subscription scenario).

Operator Endpoint with Auth: Confirms that even a simple plugin’s endpoint is protected by core. We can test that if a non-admin tries to hit the endpoint, core rejects it (not directly visible in output, but part of the design).

End-to-End Alerting Use Case: By having AppriseNotifier and PushoverNotifier in tandem, we can simulate a scenario: e.g., a system monitoring plugin publishes a NotificationRequest event “High CPU usage on Server X”. Immediately, AppriseNotifier might email or Slack the ops team, and PushoverNotifier might ping the on-call phone. Both report back with NotificationSent. This showcases Vivified’s ability to deliver the same canonical event to multiple plugins and have multiple channels of notification active concurrently – all coordinated through the common event bus. It also demonstrates how an urgent alert can be triggered programmatically via event, and also how an admin could manually trigger a notification via the UI if needed (two entry points, same outcome, all governed by the platform).

End-to-End Lifecycle and Example Scenarios

To tie everything together, consider the following end-to-end workflow that exercises all components:

Scenario: User Onboarding Alert – When a new user is created in the system (handled by an Identity plugin or core service), we want to notify administrators via both email (AppriseNotifier, configured to use email/SMS) and push notification (PushoverNotifier).

Event Emission: The Identity service/plugin creates a user and emits a UserCreated canonical event. Separately, a small orchestrator (maybe core itself) recognizes this and emits a NotificationRequest event saying “Welcome email to new user” or “New user created: notify admins”. (Alternatively, the Identity plugin could directly emit a NotificationRequest; either way, one is generated on the bus.)

Core Routing: Core sees the NotificationRequest event. It tags it as a notification-type event. It consults subscriptions: AppriseNotifier and PushoverNotifier are subscribed. Core’s policy engine checks that each has handles_notifications trait, which is compatible with this event’s type. It allows delivery to both. (If there were another plugin without that trait, it would not receive the event.)

AppriseNotifier Handling: AppriseNotifier receives the event. Suppose its config has an email address for the ops team and a Slack webhook. It transforms the event into an email (“New user onboarded: [details]”) and a Slack message, and uses Apprise to send both. Meanwhile, it might also fetch some user info if needed (not in this case). It succeeds, and emits NotificationSent with details for email and Slack.

PushoverNotifier Handling: PushoverNotifier receives the same event. It calls the Pushover API with a message like “New user created (username)” to the configured admin user’s device. Let’s say this succeeds (Pushover returns status=1). PushoverNotifier emits its NotificationSent event indicating success.

Result Collection: The core (and any interested plugin) now sees two NotificationSent events. The system could correlate them to the original request (e.g. by notification_id). In a real system, the initiator of the request might mark the notification task complete once at least one NotificationSent returns, or specifically wait for certain channels. In our case, it’s mainly for audit/logging. The Admin Console could list in an activity feed: “NotificationSent by AppriseNotifier at 10:00 (email, Slack), NotificationSent by PushoverNotifier at 10:00 (push to admin)”.

Operator Trigger Example: Later, an admin wants to send a manual notification – perhaps a system-wide announcement. They open the Admin Console’s Notifications section, type a message and select channels. If they choose the Apprise plugin, the console calls POST /plugins/apprise_notifier/send with their message and maybe a set of targets. This goes through core (admin authenticated) and hits AppriseNotifier. The plugin sends out the announcement (say via all configured channels) and returns an OK. If they also want a push, they trigger PushoverNotifier similarly. The admin immediately sees a confirmation (and gets the push on their device). These actions are all recorded.

Health and Monitoring: Over time, core continuously or periodically calls /health on both plugins. They respond OK. If AppriseNotifier’s Slack webhook started failing (say the URL expired), it might start marking notifications as failed and possibly could set an internal flag. If enough failures occur, we might consider that an unhealthy state. The plugin could either still return 200 on /health but report those errors in an aggregated form (which an admin might see in a plugin status page), or potentially return a non-OK status if it deems itself unable to function. In our design, we lean towards reporting issues via events/logs rather than failing the health check (health check is more about the service running). In any case, an admin can see metrics like “5 notifications sent, 1 failed” on the dashboard. Core’s monitoring (if integrated with Prometheus) might show a graph of notifications sent by each plugin per hour.

Shutdown: When Vivified is shutting down or the admin disables a plugin, core will invoke the plugin’s shutdown. The AppriseNotifier and PushoverNotifier receive this call (or signal) and cleanly unsubscribe from events and stop accepting requests. The core then stops their containers. This ensures no stray notifications are processed during shutdown, and resources are freed properly.

Throughout these scenarios, we have demonstrated each facet of the plugin architecture in action. The two plugins together verify that:

The canonical event bus can route one event to multiple plugins and that plugins can publish events back.

The operator gateway allows for direct calls into plugins, enabling user-driven interactions and plugin-to-plugin RPC (we described how identity lookup could work as an example of plugin calling out via core).

The manifest system successfully registers plugins with the needed traits, config, and endpoints so that core knows how to interact with them and the UI can present them correctly.

The policy engine uses those traits to enforce who gets what and who can do what – e.g. only notification handlers get the events, only admins trigger sends.

The plugins run in isolation (separate containers, only communicating through well-defined lanes) and follow the core’s rules for external communication, proving the security model of Vivified (no direct DB access, controlled network egress, etc.).

The Admin Console is able to display and manage these plugins (with config forms generated from manifest, status indicators from health checks, and possibly grouping by capability). This gives a “traits-first” UX where the capabilities (notifications) are front and center, and the admin can intuitively configure and use the plugin.

Conclusion

In this implementation plan, we provided a comprehensive blueprint for two reference notification plugins in Vivified. AppriseNotifier serves as a multi-provider notification hub, demonstrating how a single plugin can route messages to many channels using a canonical event input
github.com
. PushoverNotifier showcases a straightforward integration with an external push service via REST API, highlighting configuration of secrets and external call sandboxing
pushover.net
.

Both plugins illustrate the power of Vivified’s plugin architecture: they communicate through the canonical event bus (publishing/subscribing standardized events) and offer operator endpoints for direct invocation, all defined and governed by the plugin manifest and core policy engine. We have shown example manifest entries, file layouts, and data flows for each, as well as how they would be used and monitored in a running system. By implementing these plugins, we effectively validate the key architectural elements of Vivified:

Canonical Model Interoperability: Plugins using canonical schemas (like CanonicalNotification) to interoperate without tight coupling.

Trait-Based Access Control: The core enforcing that only appropriate plugins receive or act on certain data (e.g. only those with handles_notifications get notification events).

Secure Operator Calls: All direct plugin calls are mediated by core with authentication/authorization, ensuring plugins and users only invoke what they are allowed.

Manifest-Driven Integration: Automatic registration of plugins and UI generation for config based on manifest declarations.

Lifecycle Management and Observability: Plugins can be managed (started/stopped) at runtime and provide health status and metrics to the core for a unified view.

With AppriseNotifier and PushoverNotifier implemented as described, Vivified will have a solid foundation for notifications. These two serve as blueprints for future plugins – whether it’s another channel (SMS, WhatsApp, etc.) or entirely different domains – by exemplifying the patterns of event handling, config use, external integration, and compliance with the Vivified framework.

Finally, these plugins will appear in the Admin Console as first-class, optional modules that administrators can configure and leverage immediately, thereby “vivifying” (bringing to life) the platform’s extensibility with real, working examples.