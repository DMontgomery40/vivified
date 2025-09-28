from fastapi import FastAPI
import httpx
import os
import logging

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(title="User Management Plugin")

CORE_URL = os.getenv("CORE_URL", "http://vivified-core:8000")
PLUGIN_ID = "user-management"

# Plugin manifest
MANIFEST = {
    "id": PLUGIN_ID,
    "name": "User Management Plugin",
    "version": "1.0.0",
    "description": "Manages user profiles and extended attributes",
    "contracts": ["IdentityPlugin"],
    "traits": ["handles_pii", "audit_required"],
    "dependencies": [],
    "allowed_domains": [],
    "endpoints": {"health": "/health", "user_info": "/api/users/{id}"},
    "security": {
        "authentication_required": True,
        "data_classification": ["pii", "internal"],
    },
    "compliance": {
        "hipaa_controls": ["164.312(a)", "164.312(d)"],
        "audit_level": "detailed",
    },
}


@app.on_event("startup")
async def register_with_core():
    """Register this plugin with the core on startup."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(f"{CORE_URL}/plugins/register", json=MANIFEST)
            if response.status_code == 200:
                data = response.json()
                # Store token for future use (in a real plugin we'd persist securely)
                os.environ["PLUGIN_TOKEN"] = data.get("token", "")
                logger.info("Successfully registered with core: %s", data)
            else:
                logger.error("Failed to register: %s", response.text)
        except Exception as e:  # noqa: BLE001
            logger.error("Registration error: %s", e)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "plugin": PLUGIN_ID}


@app.get("/api/users/{user_id}")
async def get_user_info(user_id: str):
    """Get extended user information (placeholder)."""
    return {
        "user_id": user_id,
        "department": "Engineering",
        "manager": "manager-123",
        "traits": ["handles_pii"],
    }

