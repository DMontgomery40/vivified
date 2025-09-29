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
    cfg = _get_cfg()
    model = await cfg.get("ai.llm.model")
    provider = await cfg.get("ai.llm.provider")
    base_url = await cfg.get("ai.llm.base_url")
    api_key_present = bool(await cfg.get("secrets.ai.openai.api_key"))
    safe = {
        "llm": {
            "provider": provider or "openai",
            "model": model
            or (os.getenv("AI_LLM_MODEL") or os.getenv("OPENAI_DEFAULT_MODEL") or "gpt-5-mini"),
            "base_url": base_url or os.getenv("OPENAI_BASE_URL"),
            "api_key_present": bool(api_key_present or os.getenv("OPENAI_API_KEY")),
        }
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
    agent_cfg = await cfg.get("ai.agent") or {}
    api_key_present = bool(await cfg.get("secrets.ai.openai.api_key"))
    ant_key_present = bool(await cfg.get("secrets.ai.anthropic.api_key"))
    return {
        "openai": {
            "base_url": openai_cfg.get("base_url") or await cfg.get("ai.llm.base_url"),
            "default_model": openai_cfg.get("default_model") or await cfg.get("ai.llm.model"),
            "api_key_present": api_key_present,
        },
        "anthropic": {
            "base_url": anthropic_cfg.get("base_url"),
            "default_model": anthropic_cfg.get("default_model"),
            "api_key_present": ant_key_present,
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
    if isinstance(op, dict):
        if op.get("base_url") is not None:
            await cfg.set(
                "ai.connectors.openai",
                {**(await cfg.get("ai.connectors.openai") or {}), "base_url": str(op.get("base_url"))},
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.openai.base_url")
        if op.get("default_model") is not None:
            await cfg.set(
                "ai.connectors.openai",
                {**(await cfg.get("ai.connectors.openai") or {}), "default_model": str(op.get("default_model"))},
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
                {**(await cfg.get("ai.connectors.anthropic") or {}), "base_url": str(ap.get("base_url"))},
                is_sensitive=False,
                updated_by=str(user.get("id")),
                reason="ai_connectors",
            )
            changed.append("ai.connectors.anthropic.base_url")
        if ap.get("default_model") is not None:
            await cfg.set(
                "ai.connectors.anthropic",
                {**(await cfg.get("ai.connectors.anthropic") or {}), "default_model": str(ap.get("default_model"))},
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
    return {"ok": True, "changed": changed}


# --- Connectors & Tool-Calling Configuration ---
