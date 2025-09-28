from enum import Enum


class AuditCategory(str, Enum):
    SYSTEM = "system"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    USER_ACTION = "user_action"
