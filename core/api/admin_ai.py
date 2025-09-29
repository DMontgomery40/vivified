from __future__ import annotations

from typing import Any, Dict, Optional
import os
from fastapi import APIRouter, Depends, HTTPException

from core.api.dependencies import require_auth, get_current_user
from core.ai.service import RAGService, AgentService


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
    return {"docs_indexed": st.docs_indexed, "last_trained_ts": st.last_trained_ts}


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
        # Default to local docs, internal plans, and codebase
        sources = ["docs", "internal-plans", "core", "plugins", "sdk", "tools", "tests"]
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
    payload: Dict[str, Any], user: Dict = Depends(get_current_user), _: Dict = Depends(require_auth(["admin"]))
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
