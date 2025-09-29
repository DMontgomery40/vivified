# Plugins Overview

Plugins extend Vivified via canonical events, operator RPC, and proxied egress. This section catalogs available plugins and how to build your own.

## Setup Wizard (Admin Console)

Use Admin → Plugins → Plugin Setup Wizard:
- Toggle “Use AI Assistance” to have the embedded model draft your manifest.
- Choose a plugin type (LLM OSS, RAG DB Backend, Notifier, Storage, Other).
- Fill HIPAA and traits; the wizard pre-populates common traits.
- Click “Validate” to get schema validation and policy suggestions.
- “Apply Suggested Policies” writes Gateway allowlist and Operator allowlist (e.g., ai-core → rag_index/rag_query).
- “Register Plugin” sends your manifest to Core and issues a plugin token.
- “Download Scaffold” gives you a zip (manifest + server skeleton) to start implementing.

For local/on‑prem LLMs, see LLM OSS (Local). For custom vector/RAG storage, see RAG DB Plugin.
