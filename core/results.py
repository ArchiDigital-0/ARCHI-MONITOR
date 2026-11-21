from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4
import json

from diagnostics.test_context import TestContext


class TestStatus(StrEnum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


class ReportConclusion(StrEnum):
    NOT_EVALUATED = "not_evaluated"
    COMPLETED = "completed"
    ISSUES_DETECTED = "issues_detected"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    INCOMPLETE = "incomplete"


@dataclass
class TestResult:
    name: str
    status: TestStatus = TestStatus.PENDING

    summary: str = ""
    details: str | None = None

    duration_ms: float | None = None

    error_code: str | None = None
    error_message: str | None = None

    evidence: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self):
        self.name = self.name.strip().lower()

        if not self.name:
            raise ValueError("Le nom du test ne peut pas être vide.")

        if self.duration_ms is not None and self.duration_ms < 0:
            raise ValueError("La durée ne peut pas être négative.")


@dataclass
class DiagnosticReport:
    target: str
    context: TestContext

    results: list[TestResult] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    report_id: str = field(
        default_factory=lambda: str(uuid4())
    )

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self):
        self.target = self.target.strip().lower()

        if not self.target:
            raise ValueError("La cible du diagnostic ne peut pas être vide.")

    @property
    def conclusion(self) -> ReportConclusion:
        if not self.results:
            return ReportConclusion.NOT_EVALUATED

        statuses = [result.status for result in self.results]

        if all(
            status in (TestStatus.PENDING, TestStatus.SKIPPED)
            for status in statuses
        ):
            return ReportConclusion.NOT_EVALUATED

        if TestStatus.ERROR in statuses:
            return ReportConclusion.COMPLETED_WITH_ERRORS

        if TestStatus.FAILED in statuses:
            return ReportConclusion.ISSUES_DETECTED

        if TestStatus.PENDING in statuses or TestStatus.SKIPPED in statuses:
            return ReportConclusion.INCOMPLETE

        if TestStatus.WARNING in statuses:
            return ReportConclusion.COMPLETED_WITH_WARNINGS

        return ReportConclusion.COMPLETED

    def add_result(self, result: TestResult):
        self.results.append(result)

    def to_dict(self):
        return {
            "product": "ARCHI MONITOR",
            "report_id": self.report_id,
            "target": self.target,
            "context": self.context.to_dict(),
            "results": [
                asdict(result) for result in self.results
            ],
            "conclusion": self.conclusion.value,
            "limitations": self.limitations,
            "created_at": self.created_at
        }

    def to_json(self):
        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False
        )
