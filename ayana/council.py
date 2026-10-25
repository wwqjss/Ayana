"""Import compatibility for the permanently retired council orchestrator.

P4.4 退役：双席编排、计划/投票/一次性 grant 执行全部移除。
历史数据由 legacy_history 只读提供；本模块不规划、不投票、不执行任何写操作。
"""
from __future__ import annotations

from .legacy_history import RetiredAutonomyError

REVIEW_ROLES = ("reviewer_kimi", "reviewer_deepseek")
REPAIR_GOAL = "restore_registered_object"

CouncilError = RetiredAutonomyError


class CouncilService:
    """Removed council service. Construction and every entry method fail closed."""

    def __init__(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def snapshot(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def begin_review(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def record_review(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def tally(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def create_plan(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def get_plan(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def execute_grant(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def request_manual_adjudication(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def release_manual_barrier(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def recover_inflight(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def finish_verification(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def steps_for_grant(self, *args, **kwargs):
        raise RetiredAutonomyError()
