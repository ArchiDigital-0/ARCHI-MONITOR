"""Analyse prudente des versions technologiques divulguées par HTTP.

Ce module n'effectue aucune requête réseau et ne télécharge aucune
base CVE. Les avis de sécurité doivent être fournis comme références
externes vérifiables.

Une correspondance de version ne constitue pas, à elle seule,
une preuve de vulnérabilité exploitable.
"""

import re
from dataclasses import dataclass

from .http_client import HTTPAuditResponse


@dataclass(frozen=True)
class TechnologyObservation:
    """Technologie et version observées dans une réponse HTTP."""

    product: str
    version: str
    source_header: str
    raw_value: str


@dataclass(frozen=True)
class VulnerabilityReference:
    """Référence de sécurité fournie par une source externe."""

    advisory_id: str
    product: str
    affected_versions: tuple[str, ...]
    summary: str
    source: str
    fixed_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class VersionFinding:
    """Constat relatif à une technologie ou à une référence de sécurité."""

    code: str
    category: str
    severity: str
    confidence: int
    title: str
    description: str
    evidence: str
    recommendation: str
    advisory_id: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class VersionAnalysis:
    """Résultat de l'analyse des versions divulguées."""

    analyzed_url: str
    technologies: tuple[TechnologyObservation, ...]
    findings: tuple[VersionFinding, ...]
    advisory_references_checked: int


class VersionAnalyzer:
    """Identifie les versions exposées et compare les avis fournis."""

    _VERSION_PATTERN = re.compile(
        r"(?P<product>nginx|apache(?:/|\s+)?httpd|"
        r"microsoft-iis|iis|php|openssh|openresty)"
        r"(?:[/\s:-]+v?)?"
        r"(?P<version>\d+(?:\.\d+){0,4}(?:[-+~][A-Za-z0-9._-]+)?)",
        re.IGNORECASE,
    )

    _PRODUCT_ALIASES = {
        "apache": "apache http server",
        "apache/httpd": "apache http server",
        "apache httpd": "apache http server",
        "microsoft-iis": "microsoft iis",
        "iis": "microsoft iis",
        "nginx": "nginx",
        "php": "php",
        "openssh": "openssh",
        "openresty": "openresty",
    }

    @classmethod
    def _normalize_product(cls, product: str) -> str:
        normalized = re.sub(r"\s+", " ", product.strip().lower())
        return cls._PRODUCT_ALIASES.get(normalized, normalized)

    @staticmethod
    def _normalize_version(version: str) -> str:
        return version.strip().lower().lstrip("v")

    @staticmethod
    def _safe_text(value: str, limit: int = 500) -> str:
        return str(value).replace("\r", " ").replace("\n", " ")[:limit]

    def _extract_observations(
        self,
        response: HTTPAuditResponse,
    ) -> tuple[TechnologyObservation, ...]:
        observations = []
        seen = set()

        for header_name, header_value in response.headers:
            normalized_header = header_name.strip().lower()

            if normalized_header not in {"server", "x-powered-by"}:
                continue

            if not header_value:
                continue

            raw_value = self._safe_text(header_value)

            for match in self._VERSION_PATTERN.finditer(raw_value):
                product = self._normalize_product(match.group("product"))
                version = self._normalize_version(match.group("version"))

                key = (product, version, normalized_header)
                if key in seen:
                    continue

                seen.add(key)
                observations.append(TechnologyObservation(
                    product=product,
                    version=version,
                    source_header=normalized_header,
                    raw_value=raw_value,
                ))

        return tuple(observations)

    def analyze(
        self,
        response: HTTPAuditResponse,
        references: tuple[VulnerabilityReference, ...] = (),
    ) -> VersionAnalysis:
        if not isinstance(response, HTTPAuditResponse):
            raise ValueError("Une réponse HTTPAuditResponse est obligatoire.")

        if not isinstance(references, tuple):
            raise ValueError("Les références doivent être fournies sous forme de tuple.")

        for reference in references:
            if not isinstance(reference, VulnerabilityReference):
                raise ValueError(
                    "Chaque référence doit être un objet VulnerabilityReference."
                )

        observations = self._extract_observations(response)
        findings = []

        def add(
            code,
            category,
            severity,
            confidence,
            title,
            description,
            evidence,
            recommendation,
            advisory_id=None,
            source=None,
        ):
            findings.append(VersionFinding(
                code=code,
                category=category,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=self._safe_text(evidence),
                recommendation=recommendation,
                advisory_id=advisory_id,
                source=source,
            ))

        for observation in observations:
            add(
                "TECHNOLOGY_VERSION_DISCLOSED",
                "information_disclosure",
                "informational",
                100,
                f"Version technologique divulguée : {observation.product}",
                (
                    "Une version a été extraite d'un en-tête HTTP. "
                    "Cette divulgation ne prouve pas une vulnérabilité."
                ),
                (
                    f"{observation.source_header}: {observation.raw_value}; "
                    f"version détectée : {observation.version}"
                ),
                (
                    "Évaluer si cette information est nécessaire et "
                    "si sa réduction est compatible avec l'application."
                ),
            )

            matching_references = [
                reference
                for reference in references
                if self._normalize_product(reference.product)
                == observation.product
            ]

            for reference in matching_references:
                affected_versions = {
                    self._normalize_version(version)
                    for version in reference.affected_versions
                }

                fixed_versions = {
                    self._normalize_version(version)
                    for version in reference.fixed_versions
                }

                observed_version = self._normalize_version(
                    observation.version
                )

                if observed_version in affected_versions:
                    add(
                        "VERSION_MATCHES_ADVISORY",
                        "potential_vulnerability",
                        "medium",
                        90,
                        f"Correspondance avec l'avis {reference.advisory_id}",
                        (
                            "La version observée correspond exactement à une "
                            "version déclarée affectée dans la référence fournie. "
                            "Cela ne confirme pas que le correctif est absent "
                            "ni que les conditions d'exploitation sont réunies."
                        ),
                        (
                            f"Produit : {observation.product}; "
                            f"version observée : {observed_version}; "
                            f"versions affectées déclarées : "
                            f"{', '.join(sorted(affected_versions))}"
                        ),
                        (
                            "Vérifier l'avis officiel, la branche logicielle, "
                            "les correctifs rétroportés, la configuration "
                            "et les prérequis avant toute conclusion."
                        ),
                        advisory_id=reference.advisory_id,
                        source=reference.source,
                    )
                elif observed_version in fixed_versions:
                    add(
                        "VERSION_MATCHES_FIXED_REFERENCE",
                        "security_reference",
                        "informational",
                        90,
                        f"Version correspondant à une version corrigée : {reference.advisory_id}",
                        (
                            "La version observée figure dans les versions "
                            "corrigées déclarées par la référence fournie. "
                            "Cette correspondance ne prouve pas à elle seule "
                            "l'état complet de sécurité du système."
                        ),
                        (
                            f"Version observée : {observed_version}; "
                            f"référence : {reference.advisory_id}"
                        ),
                        "Vérifier la version effectivement déployée et les avis officiels.",
                        advisory_id=reference.advisory_id,
                        source=reference.source,
                    )

        return VersionAnalysis(
            analyzed_url=response.requested_url,
            technologies=observations,
            findings=tuple(findings),
            advisory_references_checked=len(references),
        )
