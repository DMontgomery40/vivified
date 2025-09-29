from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime

from core.api.dependencies import get_current_user, require_auth
from core.audit.service import audit_log


admin_ai_router = APIRouter(prefix="/admin/ai", tags=["admin", "ai"])


@admin_ai_router.get("/status")
async def ai_status(_: Dict = Depends(require_auth(["admin", "ai_manager"]))):
    """Get AI service status."""
    return {
        "status": "active",
        "providers": ["openai", "anthropic"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@admin_ai_router.post("/query")
@audit_log("ai_query")
async def ai_query(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "ai_manager"])),
):
    """Submit AI query with audit logging."""
    query = payload.get("query", "")
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")

    # Mock response - in real implementation would call AI service
    response = {
        "query": query,
        "response": "This is a mock AI response",
        "user_id": user.get("id"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    return response


@admin_ai_router.get("/models")
async def list_ai_models(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    """List available AI models."""
    return {
        "models": [
            {"id": "gpt-4", "provider": "openai", "status": "active"},
            {"id": "claude-3", "provider": "anthropic", "status": "active"},
        ]
    }
