import http.client
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin

from core.results import TestResult, TestStatus


class MobileDataAnalyzer:
    """
    Mesure le trafic HTTP applicatif généré par ARCHI MONITOR.

    Les volumes réseau réels peuvent être supérieurs aux estimations :
    TLS, TCP, IP et retransmissions ne sont pas comptabilisés.
    """

    REDIRECT_CODES = (301, 302, 303, 307, 308)

    def __init__(
        self,
        timeout=10,
        max_download_bytes=65536,
        max_redirects=3
    ):
        self.timeout = timeout
        self.max_download_bytes = max_download_bytes
        self.max_redirects = max_redirects

    def analyze(self, url):
        start = time.perf_counter()

        total_request = 0
        total_headers = 0
        total_body = 0
        redirect_count = 0
        redirect_history = []
        truncated = False

        try:
            current_url = url.strip()

            if not current_url:
                raise ValueError("URL vide.")

            while True:
                parsed = urlsplit(current_url)

                if parsed.scheme not in ("http", "https"):
                    raise ValueError(
                        "Seules les URL HTTP et HTTPS sont acceptées."
                    )

                if not parsed.hostname:
                    raise ValueError("Nom de domaine manquant.")

                if parsed.username or parsed.password:
                    raise ValueError(
                        "Les identifiants dans l'URL sont interdits."
                    )

                if parsed.fragment:
                    current_url = current_url.split("#", 1)[0]
                    parsed = urlsplit(current_url)

                host = parsed.hostname
                port = parsed.port or (
                    443 if parsed.scheme == "https" else 80
                )

                path = parsed.path or "/"

                if parsed.query:
                    path += "?" + parsed.query

                default_port = (
                    443 if parsed.scheme == "https" else 80
                )
                host_header = host

                if port != default_port:
                    host_header = f"{host}:{port}"

                headers = {
                    "Host": host_header,
                    "User-Agent": "ARCHI-MONITOR/2.1",
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                }

                request_line = f"GET {path} HTTP/1.1\r\n"
                estimated_request = len(
                    request_line.encode("iso-8859-1")
                )

                for key, value in headers.items():
                    estimated_request += len(
                        f"{key}: {value}\r\n".encode("iso-8859-1")
                    )

                estimated_request += 2
                total_request += estimated_request

                if parsed.scheme == "https":
                    connection = http.client.HTTPSConnection(
                        host,
                        port,
                        timeout=self.timeout,
                        context=ssl.create_default_context()
                    )
                else:
                    connection = http.client.HTTPConnection(
                        host,
                        port,
                        timeout=self.timeout
                    )

                try:
                    connection.request(
                        "GET",
                        path,
                        headers=headers
                    )

                    response = connection.getresponse()

                    body = response.read(
                        self.max_download_bytes + 1
                    )

                    if len(body) > self.max_download_bytes:
                        truncated = True

                    total_body += len(body)

                    header_size = len(
                        str(response.headers).encode("iso-8859-1")
                    )
                    total_headers += header_size

                    status_code = response.status
                    reason = response.reason
                    location = response.getheader("Location")

                finally:
                    connection.close()

                if (
                    status_code in self.REDIRECT_CODES
                    and location
                ):
                    if redirect_count >= self.max_redirects:
                        break

                    next_url = urljoin(current_url, location)

                    redirect_history.append({
                        "from": current_url,
                        "to": next_url,
                        "status": status_code,
                    })

                    redirect_count += 1
                    current_url = next_url
                    continue

                break

            total_estimated = (
                total_request + total_headers + total_body
            )

            duration = (
                time.perf_counter() - start
            ) * 1000

            redirect_limit_reached = (
                status_code in self.REDIRECT_CODES
                and bool(location)
                and redirect_count >= self.max_redirects
            )

            status = (
                TestStatus.WARNING
                if truncated or redirect_limit_reached
                or not (200 <= status_code < 400)
                else TestStatus.PASSED
            )

            return TestResult(
                name="mobile_data_measurement",
                status=status,
                summary="Mesure HTTP terminée.",
                details=(
                    f"Réponse finale HTTP {status_code} {reason}"
                ),
                duration_ms=round(duration, 2),
                evidence={
                    "initial_url": url,
                    "final_url": current_url,
                    "final_host": urlsplit(current_url).hostname,
                    "http_status": status_code,
                    "redirect_count": redirect_count,
                    "redirect_history": redirect_history,
                    "request_bytes_estimated": total_request,
                    "response_body_bytes_observed": total_body,
                    "response_header_bytes_estimated": total_headers,
                    "estimated_application_bytes": total_estimated,
                    "estimated_application_kib": round(
                        total_estimated / 1024, 3
                    ),
                    "estimated_application_mib": round(
                        total_estimated / (1024 * 1024), 6
                    ),
                    "download_limit_bytes_per_response":
                        self.max_download_bytes,
                    "download_truncated": truncated,
                    "redirect_limit_reached": redirect_limit_reached,
                    "measurement_scope": "application_http",
                },
                limitations=[
                    "Les volumes des requêtes et des en-têtes sont estimés.",
                    "Les octets du corps correspondent aux données lues par le module.",
                    "Les échanges TLS, TCP, IP et les retransmissions ne sont pas comptabilisés.",
                    "La consommation totale du téléphone n'est pas mesurée.",
                    "Le réseau réellement utilisé doit être vérifié séparément.",
                    "Les résultats ne prouvent pas la facturation réelle de l'opérateur.",
                    "La lecture est limitée à la taille configurée par réponse.",
                ],
            )

        except (
            ValueError,
            OSError,
            socket.timeout,
            ssl.SSLError,
            http.client.HTTPException
        ) as exc:

            return TestResult(
                name="mobile_data_measurement",
                status=TestStatus.FAILED,
                summary="Échec de la mesure HTTP.",
                duration_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                error_code="MOBILE_DATA_MEASUREMENT_FAILED",
                error_message=str(exc),
                limitations=[
                    "Aucune mesure complète n'a pu être établie."
                ],
            )
