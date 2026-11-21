
import socket
import ssl
import time
import http.client
import ipaddress

from core.results import TestResult, TestStatus


class HTTPAnalyzer:
    """
    Analyse HTTP avec séparation entre :
    - IP de destination
    - SNI TLS
    - En-tête HTTP Host
    """

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze(
        self,
        domain: str,
        destination_ip: str | None = None,
        server_hostname: str | None = None,
        host_header: str | None = None,
        port: int = 443,
    ) -> TestResult:

        domain = domain.strip().lower()
        server_hostname = (
            server_hostname or domain
        ).strip().lower()
        host_header = (host_header or domain).strip()

        if not domain or not server_hostname or not host_header:
            return TestResult(
                name="http",
                status=TestStatus.ERROR,
                summary="Paramètres HTTP incomplets.",
                error_code="INVALID_HTTP_TARGET",
            )

        if not 1 <= port <= 65535:
            return TestResult(
                name="http",
                status=TestStatus.ERROR,
                summary="Port invalide.",
                error_code="INVALID_PORT",
            )

        if any(char in host_header for char in "\r\n"):
            return TestResult(
                name="http",
                status=TestStatus.ERROR,
                summary="En-tête Host invalide.",
                error_code="INVALID_HOST_HEADER",
            )

        if destination_ip:
            try:
                destination_ip = str(
                    ipaddress.ip_address(destination_ip)
                )
            except ValueError:
                return TestResult(
                    name="http",
                    status=TestStatus.ERROR,
                    summary="Adresse IP invalide.",
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

                    request = (
                        "HEAD / HTTP/1.1\r\n"
                        f"Host: {host_header}\r\n"
                        "User-Agent: ARCHI-MONITOR/1.0\r\n"
                        "Accept: */*\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    )

                    tls_connection.sendall(
                        request.encode("ascii")
                    )

                    response = http.client.HTTPResponse(
                        tls_connection
                    )
                    response.begin()

                    duration = (
                        time.perf_counter() - start
                    ) * 1000

                    headers = dict(response.getheaders())

                    return TestResult(
                        name="http",
                        status=TestStatus.PASSED,
                        summary=(
                            f"Réponse HTTP reçue : "
                            f"{response.status}"
                        ),
                        details=response.reason,
                        duration_ms=round(duration, 2),
                        evidence={
                            "destination": destination,
                            "destination_ip": destination_ip,
                            "port": port,
                            "sni": server_hostname,
                            "host_header": host_header,
                            "http_version": response.version,
                            "status_code": response.status,
                            "reason": response.reason,
                            "headers": headers,
                            "redirect_location": headers.get(
                                "Location"
                            ),
                            "redirect_followed": False,
                        },
                        limitations=[
                            "Test exécuté localement depuis le téléphone Android.",
                            "La requête HEAD ne télécharge pas le contenu complet.",
                            "Les redirections ne sont pas suivies.",
                            "Une réponse HTTP ne prouve pas un accès sans frais.",
                        ],
                    )

        except (ssl.SSLError, socket.timeout, OSError,
                http.client.HTTPException) as exc:

            duration = (
                time.perf_counter() - start
            ) * 1000

            return TestResult(
                name="http",
                status=TestStatus.FAILED,
                summary="Échec de l'analyse HTTP.",
                duration_ms=round(duration, 2),
                error_code="HTTP_ANALYSIS_FAILED",
                error_message=str(exc),
            )
