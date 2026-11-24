"""Moteur de cotation des risques pour SERVER INTELLIGENCE.

Les trois indicateurs sont indépendants :
- Risk Score : gravité estimée des constats.
- Evidence Confidence : fiabilité des preuves.
- Analysis Coverage : couverture des contrôles prévus.

Aucune connexion réseau et aucune affirmation automatique de CVE.
"""

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class FindingAssessment:
    code: str
    severity: str
    risk_points: int
    confidence: int
    evidence_count: int
    classification: str


@dataclass(frozen=True)
class RiskAssessment:
    risk_score: int
    evidence_confidence: int
    analysis_coverage: int
    risk_level: str
    findings_count: int
    confirmed_findings: int
    potential_findings: int
    informational_findings: int
    assessments: tuple[FindingAssessment, ...]
    limitations: tuple[str, ...]


class RiskEngine:
    """Calcule des indicateurs distincts à partir des constats et contrôles."""

    SEVERITY_POINTS = {
        "critical": 100,
        "high": 75,
        "medium": 45,
        "low": 20,
        "info": 5,
        "informational": 5,
    }

    CONFIDENCE_DEFAULTS = {
        "confirmed": 90,
        "potential": 55,
        "informational": 80,
        "unknown": 25,
    }

    def __init__(self):
        pass

    @staticmethod
    def _get(item: Any, key: str, default=None):
        if isinstance(item, dict):
            return item.get(key, default)
        return getattr(item, key, default)

    @staticmethod
    def _bounded(value: Any, default: int = 0) -> int:
        try:
            return max(0, min(100, int(value)))
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _normalize(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    def _classify_finding(self, finding: Any) -> FindingAssessment:
        code = str(self._get(finding, "code", "UNKNOWN"))
        category = self._normalize(
            self._get(finding, "category", "")
        )
        status = self._normalize(
            self._get(finding, "status", "")
        )
        severity = self._normalize(
            self._get(finding, "severity", "")
        )

        if severity not in self.SEVERITY_POINTS:
            severity = "info"

        if status in ("confirmed", "verified"):
            classification = "confirmed"
        elif status in ("potential", "suspected", "possible"):
            classification = "potential"
        elif category in (
            "informational",
            "info",
            "disclosure",
            "information_disclosure",
            "security_reference",
            "default_page",
        ):
            classification = "informational"
        elif category in (
            "potential_vulnerability",
            "potential",
            "configuration",
            "security_header",
            "tls",
            "tls_certificate",
            "tls_configuration",
            "tls_validation",
            "directory_listing",
            "installation_exposure",
            "sensitive_resource_exposure",
            "exposure",
            "version",
        ):
            classification = "potential"
        else:
            classification = "unknown"

        explicit_confidence = self._get(
            finding, "confidence", None
        )

        if explicit_confidence is None:
            confidence = self.CONFIDENCE_DEFAULTS[classification]
        else:
            confidence = self._bounded(explicit_confidence, 25)

        evidence = self._get(finding, "evidence", ())
        if evidence is None:
            evidence_count = 0
        elif isinstance(evidence, (str, bytes)):
            evidence_count = 1 if evidence else 0
        else:
            try:
                evidence_count = len(evidence)
            except TypeError:
                evidence_count = 1

        # Une preuve absente limite la confiance.
        if evidence_count == 0:
            confidence = min(confidence, 35)

        # Une vulnérabilité potentielle ne devient jamais confirmée
        # par le seul calcul du score.
        if classification == "potential":
            confidence = min(confidence, 75)

        return FindingAssessment(
            code=code,
            severity=severity,
            risk_points=self.SEVERITY_POINTS[severity],
            confidence=confidence,
            evidence_count=evidence_count,
            classification=classification,
        )

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 15:
            return "low"
        return "minimal"

    def evaluate(
        self,
        findings: Iterable[Any],
        completed_checks: int,
        total_checks: int,
    ) -> RiskAssessment:
        """Évalue les constats et la couverture des contrôles."""

        if completed_checks < 0 or total_checks < 0:
            raise ValueError("Les nombres de contrôles doivent être positifs.")

        if completed_checks > total_checks:
            raise ValueError(
                "Les contrôles réalisés ne peuvent dépasser le total prévu."
            )

        items = tuple(findings or ())
        assessments = tuple(
            self._classify_finding(item) for item in items
        )

        # Agrégation plafonnée : plusieurs constats identiques
        # ne doivent pas faire dépasser 100.
        remaining = 1.0
        for item in assessments:
            contribution = item.risk_points / 100.0
            remaining *= (1.0 - contribution)

        risk_score = round((1.0 - remaining) * 100)

        if assessments:
            evidence_confidence = round(
                sum(item.confidence for item in assessments)
                / len(assessments)
            )
        else:
            evidence_confidence = 0

        analysis_coverage = (
            round(completed_checks / total_checks * 100)
            if total_checks
            else 0
        )

        classifications = tuple(
            self._classify_finding(item).classification
            for item in items
        )

        confirmed = classifications.count("confirmed")
        potential = classifications.count("potential")
        informational = classifications.count("informational")

        limitations = []
        if analysis_coverage < 100:
            limitations.append(
                "Analyse incomplète : certains contrôles n'ont pas été réalisés."
            )
        if not assessments:
            limitations.append(
                "Aucun constat disponible : le risque ne peut pas être "
                "interprété comme une absence de vulnérabilité."
            )

        return RiskAssessment(
            risk_score=risk_score,
            evidence_confidence=evidence_confidence,
            analysis_coverage=analysis_coverage,
            risk_level=self._risk_level(risk_score),
            findings_count=len(assessments),
            confirmed_findings=confirmed,
            potential_findings=potential,
            informational_findings=informational,
            assessments=assessments,
            limitations=tuple(limitations),
        )
