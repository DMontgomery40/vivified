"""
Example User Management Plugin demonstrating core service integration.

This plugin shows how to:
- Register with the core platform
- Use messaging service for events
- Use canonical service for data transformation
- Use gateway service for external API calls
- Implement proper security and audit logging
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import httpx
import os

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Example User Management Plugin")

# Configuration
CORE_URL = os.getenv("CORE_URL", "http://localhost:8000")
PLUGIN_ID = "example-user-management"
PLUGIN_TOKEN = None

# Plugin manifest
MANIFEST = {
    "id": PLUGIN_ID,
    "name": "Example User Management Plugin",
    "version": "1.0.0",
    "description": "Demonstrates core service integration with user management",
    "contracts": ["IdentityPlugin"],
    "traits": ["handles_pii", "audit_required"],
    "dependencies": [],
    "allowed_domains": ["api.example.com", "jsonplaceholder.typicode.com"],
    "endpoints": {
        "health": "/health",
        "user_info": "/api/users/{user_id}",
        "create_user": "/api/users"
    },
    "security": {
        "authentication_required": True,
        "data_classification": ["pii", "internal"]
    },
    "compliance": {
        "hipaa_controls": ["164.312(a)", "164.312(d)"],
        "audit_level": "detailed"
    }
}


class UserCreateRequest(BaseModel):
    username: str
    email: str
    department: str
    manager: Optional[str] = None


class UserInfo(BaseModel):
    user_id: str
    username: str
    email: str
    department: str
    manager: Optional[str] = None
    traits: list[str] = []


@app.on_event("startup")
async def startup():
    """Initialize plugin and register with core."""
    global PLUGIN_TOKEN
    
    try:
        # Register with core
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{CORE_URL}/plugins/register",
                json=MANIFEST,
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                PLUGIN_TOKEN = data["token"]
                logger.info(f"Successfully registered with core: {data}")
                
                # Subscribe to user events
                await subscribe_to_events()
                
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                raise RuntimeError("Failed to register with core")
                
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise


async def subscribe_to_events():
    """Subscribe to relevant events from the core."""
    try:
        # In a real implementation, this would use the messaging service
        # For now, we'll just log that we would subscribe
        logger.info("Would subscribe to user events via messaging service")
    except Exception as e:
        logger.error(f"Failed to subscribe to events: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "plugin": PLUGIN_ID,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/users/{user_id}")
async def get_user_info(
    user_id: str,
    authorization: str = Header(None)
):
    """Get extended user information."""
    try:
        # Verify authorization (in real implementation, would validate JWT)
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization required")
        
        # Simulate user data
        user_data = {
            "id": user_id,
            "username": f"user_{user_id}",
            "email": f"user_{user_id}@example.com",
            "department": "Engineering",
            "manager": "manager-123",
            "traits": ["handles_pii"]
        }
        
        # In a real implementation, would use canonical service to normalize data
        logger.info(f"Retrieved user info for {user_id}")
        
        # Publish event via messaging service (simulated)
        await publish_user_event("user_accessed", {"user_id": user_id})
        
        return UserInfo(**user_data)
        
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/users")
async def create_user(
    user_data: UserCreateRequest,
    authorization: str = Header(None)
):
    """Create a new user with extended attributes."""
    try:
        # Verify authorization
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization required")
        
        # Simulate user creation
        new_user_id = f"user_{int(datetime.utcnow().timestamp())}"
        
        user_info = UserInfo(
            user_id=new_user_id,
            username=user_data.username,
            email=user_data.email,
            department=user_data.department,
            manager=user_data.manager,
            traits=["handles_pii"]
        )
        
        # Publish event via messaging service (simulated)
        await publish_user_event("user_created", {
            "user_id": new_user_id,
            "username": user_data.username,
            "department": user_data.department
        })
        
        logger.info(f"Created user {new_user_id}")
        return user_info
        
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/external-demo")
async def external_api_demo(authorization: str = Header(None)):
    """Demonstrate external API access via gateway service."""
    try:
        # Verify authorization
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization required")
        
        # In a real implementation, would use gateway service
        # For now, simulate external API call
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://jsonplaceholder.typicode.com/users/1",
                timeout=10.0
            )
            
            if response.status_code == 200:
                external_data = response.json()
                
                # In a real implementation, would use canonical service to normalize
                normalized_data = {
                    "id": external_data["id"],
                    "username": external_data["username"],
                    "email": external_data["email"],
                    "name": external_data["name"],
                    "company": external_data["company"]["name"]
                }
                
                # Publish event
                await publish_user_event("external_data_retrieved", {
                    "source": "jsonplaceholder",
                    "user_id": external_data["id"]
                })
                
                return normalized_data
            else:
                raise HTTPException(status_code=500, detail="External API failed")
                
    except Exception as e:
        logger.error(f"External API demo failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def publish_user_event(event_type: str, payload: Dict[str, Any]):
    """Publish an event via the messaging service."""
    try:
        # In a real implementation, would use the messaging service
        # For now, just log the event
        logger.info(f"Event: {event_type} - {payload}")
        
        # Simulate publishing to core
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{CORE_URL}/messaging/events",
                json={
                    "event_type": event_type,
                    "payload": payload,
                    "source_plugin": PLUGIN_ID,
                    "data_traits": ["pii"]
                },
                headers={"Authorization": f"Bearer {PLUGIN_TOKEN}"} if PLUGIN_TOKEN else {},
                timeout=5.0
            )
            
    except Exception as e:
        logger.error(f"Failed to publish event {event_type}: {e}")


@app.on_event("shutdown")
async def shutdown():
    """Clean shutdown of plugin."""
    logger.info("Example User Management Plugin shutting down")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
