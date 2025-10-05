# Vivified Ghost-Code Map — Initial Pass (Step 1)

Scope: Identify candidates for cleanup in Step 2+ to reduce confusion during integrations work. No code removal in Step 1.

Method:
- `rg` unused symbols, long‑dead endpoints, legacy aliases; scan routers and services for callsites=0
- Compare trait registry to UI/route checks; flag unreferenced traits

Findings (initial):
1) No existing `/integrations` router — new surface will be added in Step 1
2) Traits registry is comprehensive; new `integration_manager` added for this feature (capability, requires `admin`)
3) Admin AI HIPAA toggles are UX‑focused; runtime HIPAA for integrations will be added in Step 1
4) Canonical tools and gateway tools are active; not ghost

Deferred deeper pass:
- Enumerate functions/classes in `core/automation`, `core/canonical` with zero callsites (if any)
- Cross‑check plugin traits used by `/plugins` endpoints vs registry
- Validate admin UI components for unused exports

Next steps (post Step 1):
- Produce a `rg`/`git grep` driven report with symbol lists and proposed deletions or consolidations

