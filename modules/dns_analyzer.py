import socket
import time

from core.results import TestResult, TestStatus


class DNSAnalyzer:
    """
    Analyse DNS à partir du résolveur système.
    """

    def analyze(self, domain: str) -> TestResult:
        domain = domain.strip().lower()

        if not domain:
            return TestResult(
                name="dns",
                status=TestStatus.ERROR,
                summary="Aucun domaine fourni.",
                error_code="EMPTY_TARGET",
            )

        start = time.perf_counter()

        try:
            addresses = socket.getaddrinfo(
                domain,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )

            duration = (time.perf_counter() - start) * 1000

            ipv4 = sorted({
                item[4][0]
                for item in addresses
                if item[0] == socket.AF_INET
            })

            ipv6 = sorted({
                item[4][0]
                for item in addresses
                if item[0] == socket.AF_INET6
            })

            if not ipv4 and not ipv6:
                return TestResult(
                    name="dns",
                    status=TestStatus.WARNING,
                    summary="Aucune adresse IP exploitable trouvée.",
                    duration_ms=round(duration, 2),
                    evidence={"ipv4": [], "ipv6": []},
                )

            return TestResult(
                name="dns",
                status=TestStatus.PASSED,
                summary="Résolution DNS effectuée.",
                details="Des adresses IP ont été obtenues.",
                duration_ms=round(duration, 2),
                evidence={
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "resolver": "system",
                },
                limitations=[
                    "Résultat obtenu via le résolveur système.",
                    "Les enregistrements DNS ne sont pas tous interrogés.",
                    "Le délai maximal dépend du résolveur système.",
                ],
            )

        except socket.gaierror as exc:
            duration = (time.perf_counter() - start) * 1000

            return TestResult(
                name="dns",
                status=TestStatus.FAILED,
                summary="Échec de la résolution DNS.",
                duration_ms=round(duration, 2),
                error_code="DNS_RESOLUTION_FAILED",
                error_message=str(exc),
            )

        except OSError as exc:
            duration = (time.perf_counter() - start) * 1000

            return TestResult(
                name="dns",
                status=TestStatus.ERROR,
                summary="Erreur système pendant le test DNS.",
                duration_ms=round(duration, 2),
                error_code="DNS_SYSTEM_ERROR",
                error_message=str(exc),
            )
