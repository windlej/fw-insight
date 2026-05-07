"""Analysis engine orchestration."""

import logging

from core.models import AnalysisResult, Session
from core.analysis.registry import run_checks
from core.constants import SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Orchestrates analysis checks against a session."""

    def analyze(self, session: Session) -> AnalysisResult:
        """Run all checks and produce an AnalysisResult.

        Args:
            session: Canonical session to analyze

        Returns:
            AnalysisResult with findings, health score, and counts
        """
        findings = run_checks(session)

        result = AnalysisResult(
            session_id=session.id,
            findings=findings,
        )

        result.calculate_health_score()
        result.compute_finding_counts()

        logger.info(
            "Analysis complete for session %s: %d findings, health score %d",
            session.id,
            len(findings),
            result.health_score,
        )

        return result
