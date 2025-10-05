from __future__ import annotations

from typing import Dict, List, TypedDict


class ProviderInfo(TypedDict, total=False):
    key: str
    name: str
    icon: str
    category: str
    hipaa_allowed: bool
    outbound_domains: List[str]
    env_vars: List[str]


# Single source of truth for providers (Step-2 ready)
PROVIDER_REGISTRY: Dict[str, ProviderInfo] = {
    "hubspot": {
        "key": "hubspot",
        "name": "HubSpot CRM",
        "icon": "hub",
        "category": "crm",
        "hipaa_allowed": False,
        "outbound_domains": ["api.hubapi.com", "app.hubspot.com"],
        "env_vars": ["HUBSPOT_CLIENT_ID", "HUBSPOT_CLIENT_SECRET", "HUBSPOT_SCOPE"],
    },
    "gmail": {
        "key": "gmail",
        "name": "Gmail",
        "icon": "gmail",
        "category": "comm",
        "hipaa_allowed": False,  # allow only with Workspace+BAA in HIPAA mode
        "outbound_domains": [
            "accounts.google.com",
            "oauth2.googleapis.com",
            "openidconnect.googleapis.com",
            "www.googleapis.com",
            "gmail.googleapis.com",
        ],
        "env_vars": ["GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_SCOPE"],
    },
    "discord": {
        "key": "discord",
        "name": "Discord",
        "icon": "discord",
        "category": "comm",
        "hipaa_allowed": False,
        "outbound_domains": ["discord.com"],
        "env_vars": ["DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "DISCORD_SCOPE"],
    },
}
