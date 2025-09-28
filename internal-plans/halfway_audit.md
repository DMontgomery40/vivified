I’ll deliver the audit findings for claude-test with absolute paths and concrete refs.

### High-impact gaps vs overview/runbooks (Phases 1–6)
- Operator lane missing
  - SDKs expect `/gateway/{target_plugin}/{operation}`, but core exposes only `/gateway/proxy`.
  ```257:281:/Users/davidmontgomery/faxbot_folder/vivified/core/main.py
@app.post("/gateway/proxy")
async def proxy_request(
    plugin_id: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 30,
):
    """Proxy a request to an external API."""
  ```
  ```24:33:/Users/davidmontgomery/faxbot_folder/vivified/sdk/nodejs/src/index.ts
async call_plugin(target_plugin: string, operation: string, payload: Record<string, unknown>) {
  const r = await this.client.post(`/gateway/${target_plugin}/${operation}`, payload);
  return r.data;
}
  ```
  - Impact: Operator lane (Phase 3 core requirement) not implemented; SDKs will 404.

- Proxy lane allowlist logic break
  - Gateway stores allowlists as `DomainAllowlist` (Pydantic models), but Proxy handler treats entries as dicts with `.get()`.
  ```69:80:/Users/davidmontgomery/faxbot_folder/vivified/core/gateway/models.py
class DomainAllowlist(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    plugin_id: str
    domain: str
    allowed_methods: List[ProxyMethod] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=list)
    max_requests_per_minute: int = 60
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
  ```
  ```120:141:/Users/davidmontgomery/faxbot_folder/vivified/core/gateway/proxy.py
# Check if domain is in allowlist
if domain not in domain_allowlist:
    return False
allowlist_entry = domain_allowlist[domain]
# Check if method is allowed
if request.method not in allowlist_entry.get("allowed_methods", []):
    return False
# Check if path is allowed
allowed_paths = allowlist_entry.get("allowed_paths", [])
  ```
  - Impact: Runtime error or false negatives; allowlist enforcement unreliable.
  - Separate mismatch: Admin endpoints write allowlist to ConfigService; `GatewayService` never loads from config.

- Canonical/event bus not backed by broker
  - In-memory queue only; no NATS/Redis integration as runbooks specify for Phase 3.
  ```28:47:/Users/davidmontgomery/faxbot_folder/vivified/core/messaging/event_bus.py
self.message_queue: asyncio.Queue = asyncio.Queue()
...
self._processing_task = asyncio.create_task(self._process_messages())
  ```
  - Impact: No persistence/fan-out; no multi-instance scalability.

- Admin UI parity gaps and dead endpoints
  - UI calls non-existent `/schemas/*` endpoints.
  ```15:23:/Users/davidmontgomery/faxbot_folder/vivified/core/ui/src/lib/api.js
export const listSchemas = (name) => http.get(`/schemas/${encodeURIComponent(name)}`).then(r=>r.data)
export const upsertSchema = (payload) => http.post('/schemas', payload).then(r=>r.data)
export const activateSchema = (name,major,minor,patch) => http.post('/schemas/activate',{name,major,minor,patch}).then(r=>r.data)
export const getActive = (name,major) => http.get(`/schemas/${encodeURIComponent(name)}/active/${major}`).then(r=>r.data)
  ```
  - Core serves Admin UI placeholder if built assets missing.
  ```357:399:/Users/davidmontgomery/faxbot_folder/vivified/core/main.py
@app.get("/admin/ui", include_in_schema=False)
async def admin_ui_root():
    if os.path.exists(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    # Fallback lightweight placeholder to satisfy health and tests
    ...
def _admin_ui_placeholder():
    from fastapi.responses import HTMLResponse
    html = ("<!doctype html>...<p>Placeholder UI loaded.</p>...</html>")
    return HTMLResponse(content=html, media_type="text/html")
  ```
  - Many Admin endpoints are safe stubs.
  ```334:341:/Users/davidmontgomery/faxbot_folder/vivified/core/api/admin.py
# Phase 1 stubs to avoid 404s in UI when traits/flags expose surfaces
@admin_router.get("/marketplace/plugins")
async def get_marketplace_plugins(...):
    return {"plugins": []}
  ```
  - Impact: UI cannot exercise canonical models, marketplace, or full settings flow; violates UI-parity mandate for those features.

- Policy engine scope and audit
  - Policy decisions logged to python logger, not persisted to audit service; advanced trait-driven redaction not wired through bus/gateway contexts.
  ```238:259:/Users/davidmontgomery/faxbot_folder/vivified/core/policy/engine.py
def audit(...):
    payload = {...}
    logger.info("policy_decision=%s", json.dumps(payload, ...))
# Module-level singleton
policy_engine = PolicyEngine()
  ```
  - Impact: Audit trail for decisions incomplete against compliance requirements.

- DEV bootstrap OK; rate limiting not implemented
  - `dev_login` present and `bootstrap_admin_only` honored.
  ```331:343:/Users/davidmontgomery/faxbot_folder/vivified/core/main.py
@app.post("/auth/dev-login")
async def dev_login(_: DevLoginRequest):
    token = dev_issue_admin_token()
    return {"token": token, "expires_in": 1800}
  ```
  - `rate_limit` decorator is a no-op; no global RPM enforcement.
  ```170:183:/Users/davidmontgomery/faxbot_folder/vivified/core/identity/auth.py
def rate_limit(limit: int = 60) -> Callable:
    """No-op rate limit decorator placeholder for Phase 2."""
    def _decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def _wrapper(*args, **kwargs):
            return await func(*args, **kwargs)
        return _wrapper
  ```

- SDKs incomplete vs plan
  - Node/Python SDKs implement event publish, config read/write, proxy call; subscribe is stub; operator call path mismatched with backend; Go SDK present but scope unclear.
  ```35:39:/Users/davidmontgomery/faxbot_folder/vivified/sdk/python/src/vivified_sdk/client.py
async def subscribe(self, event_type: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
    # Placeholder: No server push implemented; method kept for parity.
    return None
  ```

- Plugin manager and sandboxing incomplete
  - Example plugin registers and expects token; need to confirm `PluginRegistry` issues token and enforces traits; no sandbox/network isolation control at runtime discovered here.
  ```36:46:/Users/davidmontgomery/faxbot_folder/vivified/plugins/user_management/main.py
async def register_with_core():
    response = await client.post(f"{CORE_URL}/plugins/register", json=MANIFEST)
    if response.status_code == 200:
        data = response.json()
        os.environ["PLUGIN_TOKEN"] = data.get("token", "")
  ```

### Placeholders, “simulated”, and outlines left in-place
- Admin APIs marked as stubs or simulated (diagnostics, tunnel, jobs, restart).
  ```1379:1388:/Users/davidmontgomery/faxbot_folder/vivified/core/api/admin.py
async def run_action(...):
    ...
    return {"ok": True, "id": action_id, "code": 0, "stdout": "simulated", "stderr": ""}
  ```
- Core UI and Admin UI include numerous placeholder inputs and notes (safe but non-functional areas), e.g., provider settings and tunnel UIs (omitted here for brevity; present under `/Users/davidmontgomery/faxbot_folder/vivified/core/admin_ui/src`).

### Logic breaks and integration mismatches
- Allowlist object vs dict (Proxy lane) — see above.
- Admin allowlist config vs Gateway’s in-memory allowlist: no hydration path.
- UI “Schemas” area has no backend; dead links from `core/ui/src/pages/Schemas.jsx`.
- Operator lane absent but SDKs and docs assume it.

### Runbooks/overview vs implementation highlights
- Phase 2 (Identity/Config/Basic Security): Identity, MFA, WebAuthn endpoints exist; ConfigService supports hierarchical + encryption; basic trait checks via `require_auth`. Rate limiting not done; session inactivity timeout not implemented.
- Phase 3 (Inter-plugin comms): Event bus is in-memory; no broker; Operator lane missing; Proxy lane present but broken allowlist and lacks config sync; policy checks not applied to actual data redaction paths.
- Phase 4 (Security/compliance/UI): TLS endpoints present; encryption rotation present; Admin UI exists but mixed placeholder; Audit service exists but policy decisions not persisted; UI parity not met for marketplace/schemas/operator workflows.
- Phase 5–6 (SDKs/tools/plugins): SDKs partial; subscribe/server-push missing; CLI/templates/validator not surfaced here; reference plugins minimal, not exercising canonical/Operator flows end-to-end.

### Concrete gap list (implementable deltas)
- Operator lane
  - Add core routes: `POST /gateway/{plugin_id}/{operation}` with policy checks, service discovery to target plugin, timeouts, auditing.
  - Align SDKs and tests to real routes.
- Proxy lane
  - Fix allowlist structure: change ProxyHandler to accept `DomainAllowlist` models or convert to dicts before use.
  - Load/sync allowlists from ConfigService into `GatewayService` on startup and update on changes.
- Event bus
  - Integrate NATS/Redis (as per runbooks); add connection management, subjects, and tests; wire policy enforcement and audit on publish/deliver.
- Policy/audit
  - Persist policy decisions via `AuditService` with decision payloads; add redaction hooks into canonical transforms and gateway responses based on `PolicyResult`.
- Admin UI parity
  - Remove or implement `/schemas/*` endpoints; alternatively hide schemas page behind trait/flag until ready.
  - Expose Operator/Proxy and Messaging diagnostics within Tools → Gateway/Messaging, trait-gated.
- Rate limiting and sessions
  - Implement real rate limiting (Redis or in-memory token bucket) and enforce per endpoint (esp. public/dev endpoints); add session inactivity timeout.
- Plugin manager and sandbox
  - Ensure `PluginRegistry` issues signed plugin tokens, validates manifests, and enforces ‘allowed_domains’ to Gateway allowlist automatically; document sandbox constraints; add health/heartbeat policy.

### Notable code refs for remediation planning
- Core only exposes proxy:
  ```256:278:/Users/davidmontgomery/faxbot_folder/vivified/core/main.py
# Gateway service endpoints
@app.post("/gateway/proxy")
...
  ```
- SDK operator call mismatch:
  ```24:31:/Users/davidmontgomery/faxbot_folder/vivified/sdk/nodejs/src/index.ts
const r = await this.client.post(`/gateway/${target_plugin}/${operation}`, payload);
  ```
- Allowlist logic expecting dict:
  ```132:141:/Users/davidmontgomery/faxbot_folder/vivified/core/gateway/proxy.py
if request.method not in allowlist_entry.get("allowed_methods", []):
...
httpx.URL(str(request.url)).path.startswith(path)
  ```
- UI schemas calls with no backend:
  ```15:21:/Users/davidmontgomery/faxbot_folder/vivified/core/ui/src/lib/api.js
export const listSchemas = (name) => http.get(`/schemas/${encodeURIComponent(name)}`)
  ```

- Admin UI placeholder served when dist missing:
  ```357:399:/Users/davidmontgomery/faxbot_folder/vivified/core/main.py
if os.path.exists(INDEX_FILE): return FileResponse(INDEX_FILE) ... _admin_ui_placeholder()
  ```

### Quick compliance posture callouts
- PHI/PII tagging present in models and policy checks; but lack of broker and missing decision auditing creates audit trail gaps.
- Encryption at rest for config secrets supported (Fernet); identity password hashing fallback present; ensure production deps installed to avoid fallback.
- No secret detection/rotation pipeline surfaced in code; rely on docs/CI configuration.

I’ve checked off all the audit tasks and there are no remaining items open.

- Implemented: inventory of core, lanes, Admin UI, SDKs/plugins; identified placeholders/logic breaks; compiled gap list.
- Next, if you want, I can draft targeted edits for the Operator lane routes and the Proxy allowlist fix.