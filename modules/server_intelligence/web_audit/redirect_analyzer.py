"""Analyse sûre des redirections HTTP dans un périmètre autorisé.

Chaque destination est examinée avant toute nouvelle requête.
Aucune connexion n'est établie vers une IP non publique ou un hôte
extérieur au périmètre autorisé.
"""

import ipaddress
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

from .http_client import (
    HTTPAuditResponse,
    SafeHTTPClient,
    _sanitize_response_header,
)
from .scope import IPClassification, classify_ip


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class RedirectHop:
    """Destination et décision associées à une étape de redirection."""

    source_url: str
    status: int
    location: str
    destination_url: str | None
    destination_host: str | None
    destination_port: int | None
    in_scope: bool
    ip_classifications: tuple[IPClassification, ...] = ()
    followed: bool = False
    stop_reason: str | None = None


@dataclass(frozen=True)
class RedirectAnalysis:
    """Résultat complet de l'analyse d'une chaîne de redirections."""

    initial_response: HTTPAuditResponse
    final_response: HTTPAuditResponse
    hops: tuple[RedirectHop, ...]
    completed: bool
    stop_reason: str | None


class RedirectAnalyzer:
    """Analyse les redirections sans contourner SafeHTTPClient."""

    def __init__(
        self,
        client: SafeHTTPClient,
        *,
        max_redirects: int = 5,
    ):
        if not isinstance(client, SafeHTTPClient):
            raise ValueError("Un client SafeHTTPClient est obligatoire.")

        if (
            isinstance(max_redirects, bool)
            or not isinstance(max_redirects, int)
            or max_redirects < 0
        ):
            raise ValueError("La limite de redirections est invalide.")

        self.client = client
        self.max_redirects = max_redirects

    @staticmethod
    def _safe_destination(parts) -> str:
        """Retire les paramètres de requête et les fragments du rapport."""

        scheme = parts.scheme.lower()
        hostname = parts.hostname or ""
        port = parts.port
        default_port = 443 if scheme == "https" else 80

        try:
            ip = ipaddress.ip_address(hostname)
            authority = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
        except ValueError:
            authority = hostname.encode("idna").decode("ascii").lower()

        if port is not None and port != default_port:
            authority = f"{authority}:{port}"

        return urlunsplit((
            scheme,
            authority,
            parts.path or "/",
            "",
            "",
        ))

    def analyze(
        self,
        initial_response: HTTPAuditResponse,
        *,
        method: str = "GET",
    ) -> RedirectAnalysis:
        """Analyse et suit uniquement les redirections autorisées."""

        if not isinstance(initial_response, HTTPAuditResponse):
            raise ValueError("Une réponse HTTPAuditResponse est obligatoire.")

        if method not in ("GET", "HEAD"):
            raise ValueError("Seules les méthodes GET et HEAD sont autorisées.")

        current = initial_response
        hops = []
        visited = {initial_response.requested_url}
        completed = True
        stop_reason = None

        while current.status in REDIRECT_STATUSES:
            locations = [
                value
                for name, value in current.headers
                if name.lower() == "location"
            ]

            if not locations:
                stop_reason = "redirect_without_location"
                break

            raw_location = locations[0]
            sanitized = _sanitize_response_header("Location", raw_location)

            if sanitized is None:
                stop_reason = "invalid_location_header"
                break

            try:
                destination = urljoin(current.requested_url, raw_location)
                parts = urlsplit(destination)

                if parts.scheme.lower() not in ("http", "https"):
                    raise ValueError("Schéma non autorisé.")

                if parts.username is not None or parts.password is not None:
                    raise ValueError("Identifiants URL interdits.")

                hostname = parts.hostname
                if not hostname:
                    raise ValueError("Nom d'hôte absent.")

                port = parts.port or (
                    443 if parts.scheme.lower() == "https" else 80
                )

                if not 1 <= port <= 65535:
                    raise ValueError("Port invalide.")

                safe_url = self._safe_destination(parts)

            except (TypeError, ValueError, UnicodeError):
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=None,
                    destination_host=None,
                    destination_port=None,
                    in_scope=False,
                    stop_reason="invalid_redirect_destination",
                ))
                completed = False
                stop_reason = "invalid_redirect_destination"
                break

            if safe_url in visited:
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=safe_url,
                    destination_host=hostname,
                    destination_port=port,
                    in_scope=False,
                    stop_reason="redirect_loop_detected",
                ))
                completed = False
                stop_reason = "redirect_loop_detected"
                break

            # Les IP littérales sont classifiées, mais ne sont jamais
            # contactées directement par ce composant.
            try:
                literal_ip = ipaddress.ip_address(hostname)
            except ValueError:
                literal_ip = None

            if literal_ip is not None:
                classification = classify_ip(str(literal_ip))
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=safe_url,
                    destination_host=hostname,
                    destination_port=port,
                    in_scope=False,
                    ip_classifications=(classification,),
                    stop_reason="ip_literal_destination_not_authorized",
                ))
                completed = False
                stop_reason = "ip_literal_destination_not_authorized"
                break

            if not self.client.scope.is_authorized_host(hostname):
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=safe_url,
                    destination_host=hostname,
                    destination_port=port,
                    in_scope=False,
                    stop_reason="destination_out_of_scope",
                ))
                completed = False
                stop_reason = "destination_out_of_scope"
                break

            # Résolution et classification individuelles avant toute
            # nouvelle connexion. La réponse DNS peut contenir des IP
            # publiques et non publiques : chacune est conservée.
            resolution = self.client.scope.resolve_host(hostname, port)
            classifications = resolution.addresses

            if not resolution.public_addresses:
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=safe_url,
                    destination_host=hostname,
                    destination_port=port,
                    in_scope=True,
                    ip_classifications=classifications,
                    stop_reason=(
                        "dns_resolution_failed"
                        if resolution.error
                        else "no_public_address"
                    ),
                ))
                completed = False
                stop_reason = "no_public_address"
                break

            if len(hops) >= self.max_redirects:
                hops.append(RedirectHop(
                    source_url=current.requested_url,
                    status=current.status,
                    location=sanitized[1],
                    destination_url=safe_url,
                    destination_host=hostname,
                    destination_port=port,
                    in_scope=True,
                    ip_classifications=classifications,
                    stop_reason="maximum_redirects_reached",
                ))
                completed = False
                stop_reason = "maximum_redirects_reached"
                break

            visited.add(safe_url)

            # SafeHTTPClient effectue sa propre résolution DNS et
            # n'essaie de joindre que les IP publiques connectables.
            next_response = self.client.request(
                destination,
                method=method,
                dns_resolution=resolution,
            )

            hops.append(RedirectHop(
                source_url=current.requested_url,
                status=current.status,
                location=sanitized[1],
                destination_url=safe_url,
                destination_host=hostname,
                destination_port=port,
                in_scope=True,
                ip_classifications=classifications,
                followed=True,
            ))

            current = next_response

            if current.error_type:
                completed = False
                stop_reason = current.error_type
                break

        return RedirectAnalysis(
            initial_response=initial_response,
            final_response=current,
            hops=tuple(hops),
            completed=completed,
            stop_reason=stop_reason,
        )
