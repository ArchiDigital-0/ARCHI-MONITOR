import socket
import time

from core.results import TestResult, TestStatus


class TCPAnalyzer:
    """Vérifie la possibilité d'établir une connexion TCP."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze(self, destination: str, port: int = 443) -> TestResult:
        start = time.perf_counter()

        if not destination:
            return TestResult(
                name="tcp",
                status=TestStatus.ERROR,
                summary="Destination TCP manquante.",
                error_code="INVALID_DESTINATION",
            )

        if not 1 <= port <= 65535:
            return TestResult(
                name="tcp",
                status=TestStatus.ERROR,
                summary="Port TCP invalide.",
                error_code="INVALID_PORT",
            )

        try:
            with socket.create_connection(
                (destination, port),
                timeout=self.timeout,
            ) as connection:
                peer = connection.getpeername()

            duration = (time.perf_counter() - start) * 1000

            return TestResult(
                name="tcp",
                status=TestStatus.PASSED,
                summary="Connexion TCP établie.",
                details="La destination a accepté la connexion.",
                duration_ms=round(duration, 2),
                evidence={
                    "destination": destination,
                    "destination_ip": peer[0],
                    "port": port,
                    "timeout": self.timeout,
                },
                limitations=[
                    "Une connexion réussie ne garantit pas le fonctionnement du service applicatif.",
                    "Test exécuté localement depuis le téléphone Android.",
                ],
            )

        except (socket.timeout, OSError) as exc:
            duration = (time.perf_counter() - start) * 1000

            return TestResult(
                name="tcp",
                status=TestStatus.FAILED,
                summary="Échec de la connexion TCP.",
                duration_ms=round(duration, 2),
                error_code="TCP_CONNECTION_FAILED",
                error_message=str(exc),
                evidence={
                    "destination": destination,
                    "port": port,
                },
            )
