from __future__ import annotations

import os
from core.plugins.contracts.integration import (
    IntegrationPluginBase,
    ConnectURL,
    IntegrationStatus,
    Result,
)
from core.plugins.external_host import ExternalPluginClient, IntegrationClientError
from fastapi import HTTPException


class Plugin(IntegrationPluginBase):
    def __init__(self, host: str | None = None, provider: str = "discord"):
        base = host or os.getenv("INTEGRATIONS_BASE_URL", "http://frigg:3001")
        self.client = ExternalPluginClient(host=base, provider=provider)

    async def connect(self, user_id: str, state: str) -> ConnectURL:
        try:
            data = await self.client.get_oauth_url(user_id, state)
            return ConnectURL(url=str(data.get("url") or ""))
        except IntegrationClientError as e:
            raise HTTPException(status_code=e.status_code, detail=e.public_code)

    async def callback(self, user_id: str, code: str, state: str) -> Result:
        try:
            await self.client.exchange_code(user_id, code, state)
            return Result(success=True)
        except IntegrationClientError as e:
            raise HTTPException(status_code=e.status_code, detail=e.public_code)

    async def status(self, user_id: str) -> IntegrationStatus:
        try:
            data = await self.client.status(user_id)
            connected = bool(data.get("connected"))
            account = None
            details = data.get("details") or {}
            if isinstance(details, dict):
                account = details.get("account_name")
            return IntegrationStatus(connected=connected, account=account)
        except IntegrationClientError as e:
            raise HTTPException(status_code=e.status_code, detail=e.public_code)

    async def revoke(self, user_id: str) -> Result:
        try:
            await self.client.revoke(user_id)
            return Result(success=True)
        except IntegrationClientError as e:
            raise HTTPException(status_code=e.status_code, detail=e.public_code)

