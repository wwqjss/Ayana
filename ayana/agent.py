"""Import compatibility only: the old AgentLoop was retired in P4.4.

Use AutoInvestigator for read-only automatic investigation, ActionService for
explicit human actions, and NotificationObligations for delivery obligations.
"""
from .legacy_history import RetiredAutonomyError


class AgentLoop:
    def __init__(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def set_auto_enabled(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def ready_incident_ids(self, *args, **kwargs):
        raise RetiredAutonomyError()

    async def handle_incident(self, *args, **kwargs):
        raise RetiredAutonomyError()

    async def _auto_dispatch(self, *args, **kwargs):
        raise RetiredAutonomyError()
