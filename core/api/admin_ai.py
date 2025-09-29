from __future__ import annotations

from typing import Any, Dict, Optional
import os
from fastapi import APIRouter, Depends, HTTPException

from core.api.dependencies import require_auth, get_current_user
from core.ai.service import RAGService, AgentService
from core.config.service import get_config_service
from core.config.service import get_config_service


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
    # lightweight backend hint
    backend = "redis" if os.getenv("REDIS_URL") else "memory"
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
    cfg = get_config_service()
    model = await cfg.get("ai.llm.model")
    provider = await cfg.get("ai.llm.provider")
    base_url = await cfg.get("ai.llm.base_url")
    api_key_present = bool(await cfg.get("secrets.ai.openai.api_key"))
    return {
        "llm": {
            "provider": provider or "openai",
            "model": model or (os.getenv("AI_LLM_MODEL") or os.getenv("OPENAI_DEFAULT_MODEL") or "gpt-5-mini"),
            "base_url": base_url or os.getenv("OPENAI_BASE_URL"),
            "api_key_present": api_key_present or bool(os.getenv("OPENAI_API_KEY")),
        }
    }


@ai_router.put("/config")
async def ai_set_config(payload: Dict[str, Any], user: Dict = Depends(get_current_user), _: Dict = Depends(require_auth(["admin"]))):
    """Set AI config. Stores API key as sensitive."""
    cfg = get_config_service()
    changed = []
    if "model" in payload:
        await cfg.set("ai.llm.model", str(payload["model"]), is_sensitive=False, updated_by=str(user.get("id")), reason="ai_config")
        changed.append("ai.llm.model")
    if "provider" in payload:
        await cfg.set("ai.llm.provider", str(payload["provider"]), is_sensitive=False, updated_by=str(user.get("id")), reason="ai_config")
        changed.append("ai.llm.provider")
    if "base_url" in payload:
        await cfg.set("ai.llm.base_url", str(payload["base_url"]), is_sensitive=False, updated_by=str(user.get("id")), reason="ai_config")
        changed.append("ai.llm.base_url")
    if "openai_api_key" in payload and payload["openai_api_key"]:
        await cfg.set("secrets.ai.openai.api_key", str(payload["openai_api_key"]), is_sensitive=True, updated_by=str(user.get("id")), reason="ai_config_secret")
        changed.append("secrets.ai.openai.api_key")
    return {"ok": True, "changed": changed}


# --- Connectors & Tool-Calling Configuration ---


@ai_router.get("/connectors")
async def ai_connectors_get(_: Dict = Depends(require_auth(["admin"]))):
    cfg = get_config_service()
    openai_cfg = await cfg.get("ai.connectors.openai") or {}
    anthropic_cfg = await cfg.get("ai.connectors.anthropic") or {}
    tool_calling = await cfg.get("ai.agent.tool_calling")

    # Redact API keys
    def redacted(d: Any) -> Any:
        if not isinstance(d, dict):
            return {}
        out = dict(d)
        if out.get("api_key"):
            out["api_key"] = "***"
        return out

    return {
        "openai": redacted(openai_cfg),
        "anthropic": redacted(anthropic_cfg),
        "agent": {
            "tool_calling": (
                bool(tool_calling) if isinstance(tool_calling, bool) else False
            )
        },
    }


@ai_router.put("/connectors")
async def ai_connectors_put(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin"])),
):
    cfg = get_config_service()
    actor = str(user.get("id") or user.get("email") or "admin")

    # Persist connectors configs
    openai_in = (
        (payload.get("openai") or {}) if isinstance(payload.get("openai"), dict) else {}
    )
    anthropic_in = (
        (payload.get("anthropic") or {})
        if isinstance(payload.get("anthropic"), dict)
        else {}
    )
    agent_in = (
        (payload.get("agent") or {}) if isinstance(payload.get("agent"), dict) else {}
    )

    # Store API keys as sensitive; other fields non-sensitive
    async def upsert_connector(name: str, data: Dict[str, Any]):
        if not data:
            return
        # separate sensitive
        data = dict(data)
        api_key = data.pop("api_key", None)
        if api_key:
            # merge with existing to avoid dropping other fields
            existing = await cfg.get(f"ai.connectors.{name}") or {}
            existing = dict(existing) if isinstance(existing, dict) else {}
            existing.update(data)
            existing["api_key"] = api_key
            await cfg.set(
                f"ai.connectors.{name}",
                existing,
                is_sensitive=True,
                updated_by=actor,
                reason="update_ai_connector",
            )
        else:
            await cfg.set(
                f"ai.connectors.{name}",
                data,
                is_sensitive=False,
                updated_by=actor,
                reason="update_ai_connector",
            )

    await upsert_connector("openai", openai_in)
    await upsert_connector("anthropic", anthropic_in)

    # Tool-calling flag
    if "tool_calling" in agent_in:
        await cfg.set(
            "ai.agent.tool_calling",
            bool(agent_in.get("tool_calling")),
            is_sensitive=False,
            updated_by=actor,
            reason="update_ai_agent_tool_calling",
        )

    # Update gateway allowlist for ai-core based on configured providers
    allow: Dict[str, Any] = {}

    def host_from_base_url(u: Optional[str]) -> Optional[str]:
        try:
            from urllib.parse import urlparse

            if not u:
                return None
            return urlparse(u).netloc
        except Exception:
            return None

    o_base = (
        openai_in.get("base_url")
        or (await cfg.get("ai.connectors.openai") or {}).get("base_url")
        or "https://api.openai.com"
    )
    a_base = (
        anthropic_in.get("base_url")
        or (await cfg.get("ai.connectors.anthropic") or {}).get("base_url")
        or None
    )
    o_host = host_from_base_url(str(o_base))
    a_host = host_from_base_url(str(a_base) if a_base else None)
    if o_host:
        allow[o_host] = {"allowed_methods": ["POST"], "allowed_paths": ["/v1/"]}
    if a_host:
        allow[a_host] = {"allowed_methods": ["POST"], "allowed_paths": ["/v1/"]}
    if allow:
        await cfg.set(
            "gateway.allowlist.ai-core",
            allow,
            is_sensitive=False,
            updated_by=actor,
            reason="ai_connectors_allowlist_update",
        )
        # Ask gateway to reload (best-effort, may be no-op during tests)
        try:
            from core.main import gateway_service as _gw  # type: ignore

            if _gw is not None:
                await _gw.preload_allowlists(["ai-core"])  # type: ignore[attr-defined]
        except Exception:
            pass

    return {"ok": True}


@ai_router.post("/connectors/refresh-allowlist")
async def ai_connectors_refresh(_: Dict = Depends(require_auth(["admin"]))):
    try:
        from core.main import gateway_service as _gw  # type: ignore

        if _gw is not None:
            await _gw.preload_allowlists(["ai-core"])  # type: ignore[attr-defined]
    except Exception:
        pass
    return {"ok": True}
