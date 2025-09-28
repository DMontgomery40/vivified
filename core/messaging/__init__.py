"""
Messaging service for inter-plugin communication with HIPAA compliance.

This module provides:
- Event bus for canonical communication
- Message routing and filtering
- PHI/PII data protection
- Audit logging for all message flows
"""

from .service import MessagingService
from .models import Message, Event, MessageFilter
from .event_bus import EventBus

__all__ = [
    "MessagingService",
    "Message", 
    "Event",
    "MessageFilter",
    "EventBus",
]
