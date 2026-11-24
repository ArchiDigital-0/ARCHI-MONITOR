"""Orchestrateur principal de SERVER INTELLIGENCE."""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .scope import ScopePolicy, classify_ip
from .http_client import SafeHTTPClient, HTTPAuditResponse
from .redirect_analyzer import RedirectAnalyzer
from .headers_analyzer import HeadersAnalyzer
from .tls_analyzer import TLSAnalyzer, TLSCertificateInfo
from .exposure_analyzer import ExposureAnalyzer
from .version_analyzer import VersionAnalyzer
from .risk_engine import RiskEngine
from .report import ReportBuilder, ReportDocument


@dataclass(frozen=True)
class ServerIntelligenceResult:
    target: str
    initial_response: HTTPAuditResponse
    redirect_analysis: Any
    headers_analysis: Any
    tls_analysis: Any
    exposure_analysis: Any
    version_analysis: Any
    risk_assessment: Any
    report: ReportDocument
    findings: tuple
    limitations: tuple[str, ...]
    errors: tuple[str, ...]


class ServerIntelligenceOrchestrator:
    """Coordonne les neuf composants de l'audit Web."""

    TOTAL_CHECKS = 7

    def __init__(
        self,
        target_domain: str,
        authorized_domains: tuple[str, ...],
        *,
        connect_timeout: float = 8.0,
        max_response_bytes: int = 1_000_000,
        max_redirects: int = 5,
        vulnerability_references: tuple = (),
    ):
        self.scope = ScopePolicy(
            target_domain=target_domain,
            authorized_domains=tuple(authorized_domains),
        )

        self.client = SafeHTTPClient(
            self.scope,
            connect_timeout=connect_timeout,
            max_response_bytes=max_response_bytes,
        )

        self.redirect_analyzer = RedirectAnalyzer(
            self.client,
            max_redirects=max_redirects,
        )

        self.headers_analyzer = HeadersAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.exposure_analyzer = ExposureAnalyzer()
        self.version_analyzer = VersionAnalyzer()
        self.risk_engine = RiskEngine()
        self.report_builder = ReportBuilder()

        self.vulnerability_references = tuple(
            vulnerability_references
        )

    @staticmethod
    def _collect_findings(*analyses) -> tuple:
        findings = []

        for analysis in analyses:
            if analysis is None:
                continue

            findings.extend(
                getattr(analysis, "findings", ()) or ()
            )

        return tuple(findings)

    @staticmethod
    def _collect_ip_classifications(
        response: HTTPAuditResponse,
        redirect_analysis: Any = None,
    ) -> tuple:
        classifications = {}

        def add(item):
            if item is not None:
                classifications[item.address] = item

        add(response.ip_classification)

        for attempt in response.attempts:
            try:
                add(classify_ip(attempt.ip_address))
            except (ValueError, TypeError):
                continue

        if redirect_analysis is not None:
            for hop in redirect_analysis.hops:
                for item in hop.ip_classifications:
                    add(item)

            final_response = redirect_analysis.final_response
            add(final_response.ip_classification)

            for attempt in final_response.attempts:
                try:
                    add(classify_ip(attempt.ip_address))
                except (ValueError, TypeError):
                    continue

        return tuple(classifications.values())

    def run(
        self,
        target_url: str,
        *,
        method: str = "GET",
        tls_certificate: TLSCertificateInfo | None = None,
    ) -> ServerIntelligenceResult:
        """Exécute un audit passif sur une cible autorisée."""

        parsed = urlsplit(target_url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Seuls HTTP et HTTPS sont autorisés.")

        if not parsed.hostname:
            raise ValueError("Nom d'hôte absent de l'URL.")

        if method.upper() not in ("GET", "HEAD"):
            raise ValueError("Méthode HTTP non autorisée.")

        hostname = self.scope.require_authorized_host(
            parsed.hostname
        )

        limitations = []
        errors = []
        completed_checks = 1

        initial_response = self.client.request(
            target_url,
            method=method.upper(),
        )
        completed_checks += 1

        redirect_analysis = None
        final_response = initial_response

        try:
            redirect_analysis = self.redirect_analyzer.analyze(
                initial_response,
                method=method.upper(),
            )
            final_response = redirect_analysis.final_response
            completed_checks += 1
        except Exception as exc:
            errors.append(
                f"redirect_analysis: {type(exc).__name__}"
            )
            limitations.append(
                "L'analyse des redirections n'a pas pu aboutir."
            )

        analyses = {
            "headers": None,
            "tls": None,
            "exposure": None,
            "versions": None,
        }

        analyzers = (
            ("headers", self.headers_analyzer.analyze),
            ("exposure", self.exposure_analyzer.analyze),
            (
                "versions",
                lambda response: self.version_analyzer.analyze(
                    response,
                    references=self.vulnerability_references,
                ),
            ),
        )

        for name, analyze in analyzers:
            try:
                analyses[name] = analyze(final_response)
                completed_checks += 1
            except Exception as exc:
                errors.append(
                    f"{name}_analysis: {type(exc).__name__}"
                )
                limitations.append(
                    f"L'analyse {name} n'a pas pu aboutir."
                )

        try:
            analyses["tls"] = self.tls_analyzer.analyze(
                tls_certificate
            )

            if tls_certificate is not None:
                completed_checks += 1
            else:
                limitations.append(
                    "Aucun certificat TLS n'a été collecté. "
                    "La validation TLS réelle n'est donc pas confirmée."
                )
        except Exception as exc:
            errors.append(
                f"tls_analysis: {type(exc).__name__}"
            )
            limitations.append(
                "L'analyse du certificat TLS n'a pas pu aboutir."
            )

        findings = self._collect_findings(
            analyses["headers"],
            analyses["tls"],
            analyses["exposure"],
            analyses["versions"],
        )

        try:
            risk_assessment = self.risk_engine.evaluate(
                findings=findings,
                completed_checks=completed_checks,
                total_checks=self.TOTAL_CHECKS,
            )
        except Exception as exc:
            errors.append(
                f"risk_evaluation: {type(exc).__name__}"
            )
            raise RuntimeError(
                "Impossible de produire une évaluation fiable."
            ) from exc

        limitations.extend(risk_assessment.limitations)

        ip_classifications = self._collect_ip_classifications(
            initial_response,
            redirect_analysis,
        )

        report = self.report_builder.build(
            target=target_url,
            risk_assessment=risk_assessment,
            findings=findings,
            redirect_analysis=redirect_analysis,
            ip_classifications=ip_classifications,
            tls_analysis=analyses["tls"],
            headers_analysis=analyses["headers"],
            exposure_analysis=analyses["exposure"],
            version_analysis=analyses["versions"],
            limitations=tuple(dict.fromkeys(limitations)),
            metadata={
                "method": method.upper(),
                "completed_checks": completed_checks,
                "total_checks": self.TOTAL_CHECKS,
                "execution_errors": tuple(errors),
                "tls_certificate_supplied": (
                    tls_certificate is not None
                ),
            },
        )

        return ServerIntelligenceResult(
            target=target_url,
            initial_response=initial_response,
            redirect_analysis=redirect_analysis,
            headers_analysis=analyses["headers"],
            tls_analysis=analyses["tls"],
            exposure_analysis=analyses["exposure"],
            version_analysis=analyses["versions"],
            risk_assessment=risk_assessment,
            report=report,
            findings=findings,
            limitations=tuple(dict.fromkeys(limitations)),
            errors=tuple(errors),
        )

    def export_json(
        self,
        result: ServerIntelligenceResult,
        *,
        indent: int = 2,
    ) -> str:
        return self.report_builder.to_json(
            result.report,
            indent=indent,
        )

    def export_text(
        self,
        result: ServerIntelligenceResult,
    ) -> str:
        return self.report_builder.to_text(result.report)
