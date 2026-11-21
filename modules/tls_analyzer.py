import ipaddress
import socket
import ssl
import time

from core.results import TestResult, TestStatus


class TLSAnalyzer:
    """
    Analyse TLS avec séparation entre destination IP et SNI.
    """

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze(
        self,
        domain: str,
        port: int = 443,
        server_hostname: str | None = None,
        destination_ip: str | None = None,
    ) -> TestResult:

        domain = domain.strip().lower()

        server_hostname = (
            server_hostname or domain
        ).strip().lower()

        if not domain or not server_hostname:
            return TestResult(
                name="tls",
                status=TestStatus.ERROR,
                summary="Nom de domaine ou SNI manquant.",
                error_code="INVALID_TLS_TARGET",
            )

        if not 1 <= port <= 65535:
            return TestResult(
                name="tls",
                status=TestStatus.ERROR,
                summary="Port TCP invalide.",
                error_code="INVALID_PORT",
            )

        if destination_ip:
            try:
                destination_ip = str(
                    ipaddress.ip_address(destination_ip)
                )
            except ValueError:
                return TestResult(
                    name="tls",
                    status=TestStatus.ERROR,
                    summary="Adresse IP de destination invalide.",
                    error_code="INVALID_DESTINATION_IP",
                )

        destination = destination_ip or domain

        start = time.perf_counter()

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (destination, port),
                timeout=self.timeout,
            ) as connection:

                with context.wrap_socket(
                    connection,
                    server_hostname=server_hostname,
                ) as tls_connection:

                    duration = (
                        time.perf_counter() - start
                    ) * 1000

                    certificate = tls_connection.getpeercert()

                    peer = tls_connection.getpeername()

                    return TestResult(
                        name="tls",
                        status=TestStatus.PASSED,
                        summary="Connexion TLS validée.",
                        details=(
                            "Le certificat et le nom d'hôte "
                            "ont été vérifiés."
                        ),
                        duration_ms=round(duration, 2),
                        evidence={
                            "destination": destination,
                            "destination_ip": peer[0],
                            "port": port,
                            "sni": server_hostname,
                            "tls_version": tls_connection.version(),
                            "cipher": tls_connection.cipher(),
                            "certificate": {
                                "subject": certificate.get("subject"),
                                "issuer": certificate.get("issuer"),
                                "not_before": certificate.get("notBefore"),
                                "not_after": certificate.get("notAfter"),
                                "subject_alt_name": certificate.get(
                                    "subjectAltName", []
                                ),
                            },
                            "verification": {
                                "certificate_validated": True,
                                "hostname_checked": True,
                            },
                        },
                        limitations=[
                            "Test exécuté localement depuis le téléphone Android.",
                            "La connexion TLS ne prouve pas la sécurité globale du site.",
                            "Une seule adresse IP est testée par exécution.",
                        ],
                    )

        except ssl.SSLCertVerificationError as exc:
            duration = (
                time.perf_counter() - start
            ) * 1000

            return TestResult(
                name="tls",
                status=TestStatus.FAILED,
                summary="Échec de validation du certificat TLS.",
                duration_ms=round(duration, 2),
                error_code="TLS_CERTIFICATE_INVALID",
                error_message=str(exc),
            )

        except (ssl.SSLError, socket.timeout, OSError) as exc:
            duration = (
                time.perf_counter() - start
            ) * 1000

            return TestResult(
                name="tls",
                status=TestStatus.FAILED,
                summary="Échec de la connexion TLS.",
                duration_ms=round(duration, 2),
                error_code="TLS_CONNECTION_FAILED",
                error_message=str(exc),
            )
