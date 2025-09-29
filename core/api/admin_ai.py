from __future__ import annotations

from typing import Any, Dict, Optional
import os
from fastapi import APIRouter, Depends, HTTPException

from core.api.dependencies import require_auth, get_current_user
from core.ai.service import RAGService, AgentService
from core.config.service import get_config_service as _get_cfg


ai_router = APIRouter(prefix="/admin/ai", tags=["ai"])

_RAG: Optional[RAGService] = None
_AGENT: Optional[AgentService] = None


def configure_ai_api(*, rag_service: RAGService) -> None:
    global _RAG, _AGENT
    _RAG = rag_service
    _AGENT = AgentService(rag_service)


@ai_router.get("/status")
async def ai_status(_: Dict = Depends(require_auth(["admin"]))):
    global _RAG, _AGENT
    if _RAG is None:
        _RAG = RAGService(os.getenv("REDIS_URL"))  # type: ignore[name-defined]
        _AGENT = AgentService(_RAG)
    st = await _RAG.status()  # type: ignore[union-attr]
    # Determine backend by checking Redis availability rather than env alone
    try:
        rd = await _RAG._ensure_redis()  # type: ignore[attr-defined]
        backend = "redis" if rd else "memory"
    except Exception:
        backend = "memory"
    return {
        "docs_indexed": st.docs_indexed,
        "last_trained_ts": st.last_trained_ts,
        "backend": backend,
    }


@ai_router.post("/clear")
async def ai_clear(_: Dict = Depends(require_auth(["admin"]))):
    global _RAG
    if _RAG is None:
        _RAG = RAGService(os.getenv("REDIS_URL"))
    await _RAG.clear()  # type: ignore[union-attr]
    return {"ok": True}


@ai_router.post("/train")
async def ai_train(payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))):
    global _RAG
    if _RAG is None:
        _RAG = RAGService(os.getenv("REDIS_URL"))
    sources = payload.get("sources") or []
    if not isinstance(sources, list) or not sources:
        # Default to repository root: index everything not ignored
        sources = ["."]
    try:
        count = await _RAG.train([str(s) for s in sources])  # type: ignore[union-attr]
        st = await _RAG.status()  # type: ignore[union-attr]
        return {"ok": True, "indexed": count, "total": st.docs_indexed}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Training failed: {e}")


@ai_router.post("/query")
async def ai_query(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    global _RAG
    if _RAG is None:
        _RAG = RAGService(os.getenv("REDIS_URL"))
    q = (payload.get("q") or payload.get("query") or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="query required")
    res = await _RAG.query(q, user_traits=(user.get("traits") or []))  # type: ignore[union-attr]
    return {"items": res}


@ai_router.post("/agent/run")
async def ai_agent_run(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin"])),
):
    global _AGENT, _RAG
    if _AGENT is None:
        if _RAG is None:
            _RAG = RAGService(os.getenv("REDIS_URL"))
        _AGENT = AgentService(_RAG)
    prompt = str(payload.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt required")
    out = await _AGENT.run(prompt, user_traits=(user.get("traits") or []))  # type: ignore[union-attr]
    return out


@ai_router.get("/config")
async def ai_get_config(_: Dict = Depends(require_auth(["admin"]))):
    """Return AI config (safe). Hides secret values."""
    cfg = _get_cfg()
    model = await cfg.get("ai.llm.model")
    provider = await cfg.get("ai.llm.provider")
    base_url = await cfg.get("ai.llm.base_url")
    emb_model = await cfg.get("ai.embeddings.model")
    api_key_present = bool(await cfg.get("secrets.ai.openai.api_key"))
    safe = {
        "llm": {
            "provider": provider or "openai",
            "model": model
            or (
                os.getenv("AI_LLM_MODEL")
                or os.getenv("OPENAI_DEFAULT_MODEL")
                or "gpt-5-mini"
            ),
            "base_url": base_url or os.getenv("OPENAI_BASE_URL"),
            "api_key_present": bool(api_key_present or os.getenv("OPENAI_API_KEY")),
        },
        "embeddings": {
            "model": emb_model
            or os.getenv("EMBEDDING_MODEL")
            or os.getenv("OPENAI_EMBEDDING_MODEL")
            or "text-embedding-3-small",
        },
    }
    return safe


@ai_router.put("/config")
async def ai_set_config(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin"])),
):
    """Set AI config. Stores API key as sensitive."""
    cfg = _get_cfg()
    changed = []
    if "model" in payload:
        await cfg.set(
            "ai.llm.model",
            str(payload["model"]),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_config",
        )
        changed.append("ai.llm.model")
    if "embeddings_model" in payload:
        await cfg.set(
            "ai.embeddings.model",
            str(payload["embeddings_model"]),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_config",
        )
        changed.append("ai.embeddings.model")
    if "embeddings_model" in payload:
        await cfg.set(
            "ai.embeddings.model",
            str(payload["embeddings_model"]),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_config",
        )
        changed.append("ai.embeddings.model")
    if "provider" in payload:
        await cfg.set(
            "ai.llm.provider",
            str(payload["provider"]),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_config",
        )
        changed.append("ai.llm.provider")
    if "base_url" in payload:
        await cfg.set(
            "ai.llm.base_url",
            str(payload["base_url"]),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_config",
        )
        changed.append("ai.llm.base_url")
    if "openai_api_key" in payload and payload["openai_api_key"]:
        await cfg.set(
            "secrets.ai.openai.api_key",
            str(payload["openai_api_key"]),
            is_sensitive=True,
            updated_by=str(user.get("id")),
            reason="ai_config_secret",
        )
        changed.append("secrets.ai.openai.api_key")
    return {"ok": True, "changed": changed}


@ai_router.get("/rag-rules")
async def ai_rag_rules(_: Dict = Depends(require_auth(["admin"]))):
    cfg = _get_cfg()
    traits = await cfg.get("ai.rag.required_traits")
    cls = await cfg.get("ai.rag.classification")
    return {
        "required_traits": traits or {},
        "classification": cls or {},
    }


@ai_router.put("/rag-rules")
async def ai_set_rag_rules(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    cfg = _get_cfg()
    rt = payload.get("required_traits")
    cl = payload.get("classification")
    if isinstance(rt, dict):
        await cfg.set(
            "ai.rag.required_traits",
            rt,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_rag_rules",
        )
    if isinstance(cl, dict):
        await cfg.set(
            "ai.rag.classification",
            cl,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_rag_rules",
        )
    return {"ok": True}


@ai_router.get("/connectors")
async def ai_connectors_get(_: Dict = Depends(require_auth(["admin"]))):
    cfg = _get_cfg()
    openai_cfg = await cfg.get("ai.connectors.openai") or {}
    anthropic_cfg = await cfg.get("ai.connectors.anthropic") or {}
    local_cfg = await cfg.get("ai.connectors.local") or {}
    agent_cfg = await cfg.get("ai.agent") or {}
    provider = (
        await cfg.get("ai.llm.provider") or os.getenv("AI_LLM_PROVIDER") or "openai"
    )
    api_key_present = bool(await cfg.get("secrets.ai.openai.api_key"))
    ant_key_present = bool(await cfg.get("secrets.ai.anthropic.api_key"))
    # Provide sensible defaults when not set
    openai_base = (
        openai_cfg.get("base_url")
        or await cfg.get("ai.llm.base_url")
        or os.getenv("OPENAI_BASE_URL")
        or "https://api.openai.com"
    )
    openai_model = (
        openai_cfg.get("default_model")
        or await cfg.get("ai.llm.model")
        or os.getenv("OPENAI_DEFAULT_MODEL")
        or "gpt-4o-mini"
    )
    anthropic_base = (
        anthropic_cfg.get("base_url")
        or os.getenv("ANTHROPIC_BASE_URL")
        or "https://api.anthropic.com"
    )
    anthropic_model = (
        anthropic_cfg.get("default_model")
        or os.getenv("ANTHROPIC_DEFAULT_MODEL")
        or "claude-3-haiku-20240307"
    )
    return {
        "provider": provider,
        "openai": {
            "base_url": openai_base,
            "default_model": openai_model,
            "api_key_present": api_key_present,
        },
        "anthropic": {
            "base_url": anthropic_base,
            "default_model": anthropic_model,
            "api_key_present": ant_key_present,
        },
        "local": {
            "base_url": local_cfg.get("base_url")
            or os.getenv("LOCAL_LLM_BASE_URL")
            or "http://localhost:11434",
            "default_model": local_cfg.get("default_model")
            or os.getenv("LOCAL_LLM_MODEL")
            or "llama3.1:8b",
        },
        "agent": {"tool_calling": bool(agent_cfg.get("tool_calling"))},
    }


@ai_router.put("/connectors")
async def ai_connectors_put(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    cfg = _get_cfg()
    changed: list[str] = []
    op = payload.get("openai") or {}
    ap = payload.get("anthropic") or {}
    ag = payload.get("agent") or {}
    provider = payload.get("provider")
    if provider:
        await cfg.set(
            "ai.llm.provider",
            str(provider),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_connectors",
        )
        changed.append("ai.llm.provider")
    if isinstance(op, dict):
        if op.get("base_url") is not None:
            await cfg.set(
                "ai.connectors.openai",
                {
                    **(await cfg.get("ai.connectors.openai") or {}),
                    "base_url": str(op.get("base_url")),
                },
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.openai.base_url")
        if op.get("default_model") is not None:
            await cfg.set(
                "ai.connectors.openai",
                {
                    **(await cfg.get("ai.connectors.openai") or {}),
                    "default_model": str(op.get("default_model")),
                },
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.openai.default_model")
        if op.get("api_key"):
            await cfg.set(
                "secrets.ai.openai.api_key",
                str(op.get("api_key")),
                is_sensitive=True,
                updated_by=str(user.get("id")),
                reason="ai_connectors_secret",
            )
            changed.append("secrets.ai.openai.api_key")
    if isinstance(ap, dict):
        if ap.get("base_url") is not None:
            await cfg.set(
                "ai.connectors.anthropic",
                {
                    **(await cfg.get("ai.connectors.anthropic") or {}),
                    "base_url": str(ap.get("base_url")),
                },
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.anthropic.base_url")
        if ap.get("default_model") is not None:
            await cfg.set(
                "ai.connectors.anthropic",
                {
                    **(await cfg.get("ai.connectors.anthropic") or {}),
                    "default_model": str(ap.get("default_model")),
                },
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.anthropic.default_model")
        if ap.get("api_key"):
            await cfg.set(
                "secrets.ai.anthropic.api_key",
                str(ap.get("api_key")),
                is_sensitive=True,
                updated_by=str(user.get("id")),
                reason="ai_connectors_secret",
            )
            changed.append("secrets.ai.anthropic.api_key")
    if isinstance(ag, dict) and "tool_calling" in ag:
        await cfg.set(
            "ai.agent.tool_calling",
            bool(ag.get("tool_calling")),
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="ai_agent",
        )
        changed.append("ai.agent.tool_calling")
    # Update gateway allowlist for ai-core based on configured provider base URLs
    try:
        from urllib.parse import urlparse

        allow: Dict[str, Any] = {}
        o_base = (
            (isinstance(op, dict) and op.get("base_url"))
            or (await cfg.get("ai.connectors.openai") or {}).get("base_url")
            or "https://api.openai.com"
        )
        a_base = (
            (isinstance(ap, dict) and ap.get("base_url"))
            or (await cfg.get("ai.connectors.anthropic") or {}).get("base_url")
            or None
        )

        def host(u: Optional[str]) -> Optional[str]:
            try:
                return urlparse(str(u)).netloc if u else None
            except Exception:
                return None

        o_host = host(o_base)
        a_host = host(a_base)
        try:
            l_base = (isinstance(lc, dict) and lc.get("base_url")) or (
                await cfg.get("ai.connectors.local") or {}
            ).get("base_url")
        except Exception:
            l_base = None
        l_host = host(l_base)
        if o_host:
            allow[o_host] = {
                "allowed_methods": ["POST", "GET"],
                "allowed_paths": ["/v1/"],
            }
        if a_host:
            allow[a_host] = {
                "allowed_methods": ["POST", "GET"],
                "allowed_paths": ["/v1/"],
            }
        if l_host:
            allow[l_host] = {
                "allowed_methods": ["POST", "GET"],
                "allowed_paths": ["/"],
            }
        if allow:
            await cfg.set(
                "gateway.allowlist.ai-core",
                allow,
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors_allowlist",
            )
            try:
                from core.main import gateway_service as _gw  # type: ignore

                if _gw is not None:
                    await _gw.preload_allowlists(["ai-core"])  # type: ignore[attr-defined]
            except Exception:
                pass
    except Exception:
        pass
    return {"ok": True, "changed": changed}


# --- Connectors & Tool-Calling Configuration ---


@ai_router.get("/models")
async def ai_models(
    provider: str,
    typ: Optional[str] = None,
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    """List available models for provider. typ in {chat, embeddings}.

    Attempts provider API via gateway; falls back to curated defaults.
    """
    provider = (provider or "").strip().lower()
    typ = (typ or "chat").strip().lower()
    cfg = _get_cfg()
    models: list[str] = []
    try:
        import httpx  # type: ignore

        core_base = os.getenv("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")
        if provider in {"openai", "oai"}:
            o_cfg = await cfg.get("ai.connectors.openai") or {}
            base = (
                o_cfg.get("base_url")
                or await cfg.get("ai.llm.base_url")
                or os.getenv("OPENAI_BASE_URL")
                or "https://api.openai.com"
            )
            key = await cfg.get("secrets.ai.openai.api_key") or os.getenv(
                "OPENAI_API_KEY"
            )
            headers = (
                {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
                if key
                else {"Content-Type": "application/json"}
            )
            url = f"{str(base).rstrip('/')}/v1/models"
            r = await httpx.AsyncClient(timeout=30).post(
                f"{core_base}/gateway/proxy",
                json={
                    "plugin_id": "ai-core",
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "timeout": 30,
                },
            )
            if r.status_code < 300:
                data = r.json() or {}
                arr = data.get("data") or []
                ids = [
                    str((m or {}).get("id"))
                    for m in arr
                    if isinstance(m, dict) and (m.get("id") is not None)
                ]
                if typ == "embeddings":
                    models = [m for m in ids if "embedding" in m]
                else:
                    models = [
                        m
                        for m in ids
                        if not any(
                            x in m for x in ["embedding", "whisper", "tts", "audio"]
                        )
                    ]
        elif provider in {"claude", "anthropic"}:
            a_cfg = await cfg.get("ai.connectors.anthropic") or {}
            base = (
                a_cfg.get("base_url")
                or os.getenv("ANTHROPIC_BASE_URL")
                or "https://api.anthropic.com"
            )
            key = await cfg.get("secrets.ai.anthropic.api_key") or os.getenv(
                "ANTHROPIC_API_KEY"
            )
            headers = (
                {"x-api-key": key, "anthropic-version": "2023-06-01"}
                if key
                else {"anthropic-version": "2023-06-01"}
            )
            url = f"{str(base).rstrip('/')}/v1/models"
            r = await httpx.AsyncClient(timeout=30).post(
                f"{core_base}/gateway/proxy",
                json={
                    "plugin_id": "ai-core",
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "timeout": 30,
                },
            )
            if r.status_code < 300:
                data = r.json() or {}
                arr = data.get("data") or []
                ids = [
                    str((m or {}).get("id"))
                    for m in arr
                    if isinstance(m, dict) and (m.get("id") is not None)
                ]
                if typ == "embeddings":
                    models = (
                        []
                    )  # Anthropic doesn't publish embeddings; use OpenAI or local
                else:
                    models = [m for m in ids if m.lower().startswith("claude")]
        elif provider in {"local", "ollama"}:
            l_cfg = await cfg.get("ai.connectors.local") or {}
            base = (
                l_cfg.get("base_url")
                or os.getenv("LOCAL_LLM_BASE_URL")
                or "http://localhost:11434"
            )
            # Try Ollama tags
            url = f"{str(base).rstrip('/')}/api/tags"
            r = await httpx.AsyncClient(timeout=10).post(
                f"{core_base}/gateway/proxy",
                json={
                    "plugin_id": "ai-core",
                    "method": "GET",
                    "url": url,
                    "headers": {},
                    "timeout": 10,
                },
            )
            if r.status_code < 300:
                data = r.json() or {}
                arr = data.get("models") or []
                names = [
                    str((m or {}).get("name"))
                    for m in arr
                    if isinstance(m, dict) and (m.get("name") is not None)
                ]
                if typ == "embeddings":
                    models = []  # user-provided
                else:
                    models = names
    except Exception:
        pass

    # Fallback curated lists
    if not models:
        if provider in {"openai", "oai"}:
            if typ == "embeddings":
                models = [
                    "text-embedding-3-small",
                    "text-embedding-3-large",
                    "text-embedding-ada-002",
                ]
            else:
                models = [
                    "gpt-4o-mini",
                    "gpt-4o",
                    "gpt-4.1-mini",
                    "gpt-3.5-turbo",
                ]
        elif provider in {"claude", "anthropic"}:
            if typ == "embeddings":
                models = []
            else:
                models = [
                    "claude-3.5-sonnet-20240620",
                    "claude-3-opus-20240229",
                    "claude-3-sonnet-20240229",
                    "claude-3-haiku-20240307",
                ]
        elif provider in {"local", "ollama"}:
            models = [
                "llama3.1:8b",
                "llama3.1:70b",
                "mistral:7b",
                "qwen2.5:7b-instruct",
            ]
    return {"provider": provider, "type": typ, "models": models}
