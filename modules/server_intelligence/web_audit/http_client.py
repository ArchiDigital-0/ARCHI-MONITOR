"""Client HTTP/HTTPS à connexion épinglée sur une IP publique validée.

Aucune redirection automatique, aucun proxy et aucun accès aux IP non
publiques. Le DNS est vérifié avant chaque connexion.
"""

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .scope import DNSResolution, IPClassification, ScopePolicy, classify_ip


_SECRET_NAME_PATTERN = re.compile(
    r"api[_-]?key|access[_-]?token|token|secret|password|passwd|"
    r"authorization|cookie|session|credential",
    re.IGNORECASE,
)


def _sanitize_response_header(name: str, value: str) -> tuple[str, str] | None:
    """Filtre les en-têtes sensibles et assainit les URL de redirection."""

    if _SECRET_NAME_PATTERN.search(name):
        return None

    if name.lower() in ("location", "content-location"):
        try:
            parts = urlsplit(value)
            netloc = parts.netloc.rsplit("@", 1)[-1]
            query = []

            for key, item in parse_qsl(parts.query, keep_blank_values=True):
                if _SECRET_NAME_PATTERN.search(key):
                    item = "[REDACTED]"
                query.append((key, item))

            value = urlunsplit((
                parts.scheme,
                netloc,
                parts.path,
                urlencode(query),
                "",
            ))
        except (TypeError, ValueError):
            value = "[REDACTED_INVALID_URL]"

    return name, value


@dataclass(frozen=True)
class ConnectionAttempt:
    """Résultat d'une tentative vers une IP publique."""

    ip_address: str
    success: bool
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class HTTPAuditResponse:
    """Réponse HTTP conservée sans suivre les redirections."""

    requested_url: str
    hostname: str
    port: int
    method: str
    status: int | None
    reason: str | None
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_truncated: bool
    connected_ip: str | None
    ip_classification: IPClassification | None
    attempts: tuple[ConnectionAttempt, ...]
    collected_at: datetime
    error_type: str | None = None
    error_message: str | None = None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connexion HTTP directe vers une IP déterminée."""

    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(host=hostname, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connexion TLS vers une IP déterminée avec SNI du domaine original."""

    def __init__(self, hostname, port, pinned_ip, timeout, context):
        super().__init__(
            host=hostname,
            port=port,
            timeout=timeout,
            context=context,
        )
        self._pinned_ip = pinned_ip
        self._server_hostname = hostname

    def connect(self):
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self._server_hostname,
            )
        except BaseException:
            raw_socket.close()
            raise


class SafeHTTPClient:
    """Client HTTP/HTTPS limité à un périmètre explicitement autorisé.

    Les redirections sont retournées comme des réponses HTTP ordinaires.
    Leur destination ne doit jamais être contactée par ce client sans
    une nouvelle validation du périmètre et une nouvelle résolution DNS.
    """

    def __init__(
        self,
        scope: ScopePolicy,
        *,
        connect_timeout: float = 8.0,
        max_response_bytes: int = 1_000_000,
        user_agent: str = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0",
    ):
        if not isinstance(scope, ScopePolicy):
            raise ValueError("Une politique ScopePolicy est obligatoire.")

        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, (int, float))
            or connect_timeout <= 0
        ):
            raise ValueError("Délai de connexion invalide.")

        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1
        ):
            raise ValueError("Limite de réponse invalide.")

        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or "\r" in user_agent
            or "\n" in user_agent
        ):
            raise ValueError("User-Agent invalide.")

        self.scope = scope
        self.connect_timeout = float(connect_timeout)
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent

        self._tls_context = ssl.create_default_context()
        self._tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    @staticmethod
    def _safe_url(parts, hostname: str, port: int) -> str:
        """Retourne une URL sans paramètres ni fragment potentiellement secrets."""

        default_port = 443 if parts.scheme.lower() == "https" else 80
        authority = hostname if port == default_port else f"{hostname}:{port}"
        path = parts.path or "/"
        return f"{parts.scheme.lower()}://{authority}{path}"

    def request(
        self,
        url: str,
        *,
        method: Literal["GET", "HEAD"] = "GET",
        dns_resolution: DNSResolution | None = None,
    ) -> HTTPAuditResponse:
        """Effectue une seule requête, sans suivre de redirection."""

        collected_at = datetime.now(timezone.utc)

        if method not in ("GET", "HEAD"):
            raise ValueError("Seules les méthodes GET et HEAD sont autorisées.")

        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL invalide.")

        try:
            parts = urlsplit(url.strip())
            scheme = parts.scheme.lower()

            if scheme not in ("http", "https"):
                raise ValueError("Seuls HTTP et HTTPS sont acceptés.")

            if parts.username is not None or parts.password is not None:
                raise ValueError("Les identifiants intégrés à l'URL sont interdits.")

            if parts.fragment:
                raise ValueError("Les fragments URL ne sont pas acceptés.")

            hostname = self.scope.require_authorized_host(parts.hostname or "")
            port = parts.port or (443 if scheme == "https" else 80)

            if not 1 <= port <= 65535:
                raise ValueError("Port invalide.")

            path = parts.path or "/"
            target = path
            if parts.query:
                target += "?" + parts.query

            if any(ord(char) < 32 or ord(char) == 127 for char in target):
                raise ValueError("Cible HTTP contenant des caractères de contrôle.")

        except PermissionError:
            raise
        except (TypeError, ValueError):
            raise ValueError("URL ou destination invalide.") from None

        safe_url = self._safe_url(parts, hostname, port)

        if dns_resolution is None:
            resolution = self.scope.resolve_host(hostname, port)
        else:
            if not isinstance(dns_resolution, DNSResolution):
                raise ValueError("Objet DNSResolution invalide.")

            if (
                dns_resolution.hostname != hostname
                or dns_resolution.port != port
            ):
                raise ValueError(
                    "La résolution DNS ne correspond pas à la destination."
                )

            # Vérifie chaque classification reçue avant de l'utiliser.
            for item in dns_resolution.addresses:
                if not isinstance(item, IPClassification):
                    raise ValueError("Classification IP invalide.")
                if classify_ip(item.address) != item:
                    raise ValueError("Classification IP incohérente.")

            resolution = dns_resolution

        attempts = []

        if not resolution.public_addresses:
            return HTTPAuditResponse(
                requested_url=safe_url,
                hostname=hostname,
                port=port,
                method=method,
                status=None,
                reason=None,
                headers=(),
                body=b"",
                body_truncated=False,
                connected_ip=None,
                ip_classification=None,
                attempts=(),
                collected_at=collected_at,
                error_type="NoPublicAddress",
                error_message=(
                    "Aucune adresse IP publique utilisable dans la résolution DNS."
                ),
            )

        for classification in resolution.public_addresses:
            if not classification.is_public:
                continue

            # Une IPv4-mapped IPv6 publique doit être utilisée sous sa forme
            # IPv4 canonique, jamais comme destination IPv6 mappée.
            if classification.is_ipv4_mapped:
                if not classification.mapped_ipv4:
                    continue
                candidate_ip = classification.mapped_ipv4
            else:
                candidate_ip = classification.address

            try:
                canonical = classify_ip(candidate_ip)
            except ValueError:
                continue

            if not canonical.is_public or not canonical.is_connectable:
                continue

            try:
                ipaddress.ip_address(candidate_ip)

                if scheme == "https":
                    connection = _PinnedHTTPSConnection(
                        hostname,
                        port,
                        candidate_ip,
                        self.connect_timeout,
                        self._tls_context,
                    )
                else:
                    connection = _PinnedHTTPConnection(
                        hostname,
                        port,
                        candidate_ip,
                        self.connect_timeout,
                    )

                try:
                    connection.request(
                        method,
                        target,
                        headers={
                            "Host": (
                                hostname
                                if port == (443 if scheme == "https" else 80)
                                else f"{hostname}:{port}"
                            ),
                            "User-Agent": self.user_agent,
                            "Accept": "*/*",
                            "Accept-Encoding": "identity",
                            "Connection": "close",
                        },
                    )

                    response = connection.getresponse()
                    response_headers = tuple(
                        sanitized
                        for key, value in response.getheaders()
                        if (
                            sanitized := _sanitize_response_header(key, value)
                        ) is not None
                    )

                    body = response.read(self.max_response_bytes + 1)
                    truncated = len(body) > self.max_response_bytes

                    if truncated:
                        body = body[:self.max_response_bytes]

                    attempts.append(
                        ConnectionAttempt(
                            ip_address=candidate_ip,
                            success=True,
                        )
                    )

                    return HTTPAuditResponse(
                        requested_url=safe_url,
                        hostname=hostname,
                        port=port,
                        method=method,
                        status=response.status,
                        reason=response.reason,
                        headers=response_headers,
                        body=body,
                        body_truncated=truncated,
                        connected_ip=candidate_ip,
                        ip_classification=canonical,
                        attempts=tuple(attempts),
                        collected_at=collected_at,
                    )

                finally:
                    connection.close()

            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as error:
                attempts.append(
                    ConnectionAttempt(
                        ip_address=candidate_ip,
                        success=False,
                        error_type=type(error).__name__,
                        error_message=str(error)[:500],
                    )
                )

        return HTTPAuditResponse(
            requested_url=safe_url,
            hostname=hostname,
            port=port,
            method=method,
            status=None,
            reason=None,
            headers=(),
            body=b"",
            body_truncated=False,
            connected_ip=None,
            ip_classification=None,
            attempts=tuple(attempts),
            collected_at=collected_at,
            error_type="AllPublicConnectionsFailed",
            error_message="Toutes les tentatives vers les IP publiques ont échoué.",
        )
