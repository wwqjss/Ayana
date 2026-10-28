"""Compatibility imports for the retired per-operation permission model.

Runtime callers use account roles and agent_authority.resolve_authority. Stored
permissions and agent_ceiling rows are historical data and are never evaluated.
"""
from .access import AccessControl, PolicyDeny

Policy = AccessControl

__all__ = ["Policy", "PolicyDeny", "AccessControl"]
