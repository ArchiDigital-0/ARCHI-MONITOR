"""Transport HTTPS sécurisé et dédié aux fournisseurs de renseignements."""

import http.client
import io
from email.message import Message
import ipaddress
import socket
import time
import ssl
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from .web_audit.scope import classify_ip


PROVIDER_HOSTS = frozenset({
    "otx.alienvault.com",
    "api.platform.censys.io",
    "api.certspotter.com",
    "crt.sh",
    "api.ctlogs.dev",
    "api.hackertarget.com",
    "api.merklemap.com",
    "rapiddns.io",
    "urlscan.io",
    "www.virustotal.com",
})

DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class ProviderHTTPResponse:
    """Réponse obtenue depuis une IP publique validée."""

    hostname: str
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_truncated: bool
    connected_ip: str


class ProviderHTTPError(OSError):
    """Échec du transport fournisseur."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connexion HTTPS directe vers une IP déterminée, avec SNI original."""

    def __init__(self, hostname, pinned_ip, timeout, context):
        super().__init__(
            host=hostname,
            port=443,
            timeout=timeout,
            context=context,
        )
        self.pinned_ip = pinned_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, 443),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except BaseException:
            raw_socket.close()
            raise


def _remaining_time(deadline):
    """Retourne le temps restant avant une échéance monotone."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderHTTPError(
            "Délai global du transport fournisseur dépassé."
        )
    return remaining


class ProviderHTTPClient:
    """Transport HTTPS limité aux hôtes fournisseurs explicitement autorisés."""

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        user_agent: str = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0",
    ):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
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

        self.timeout = float(timeout)
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent

        self._tls_context = ssl.create_default_context()
        self._tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    @staticmethod
    def _parse_url(url):
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL fournisseur invalide.")

        try:
            parts = urlsplit(url.strip())
            hostname = (parts.hostname or "").lower().rstrip(".")
            port = parts.port
        except ValueError:
            raise ValueError("URL fournisseur invalide.") from None

        if parts.scheme.lower() != "https":
            raise PermissionError("Seules les URL HTTPS sont autorisées.")

        if parts.username is not None or parts.password is not None:
            raise PermissionError("Identifiants intégrés à l'URL interdits.")

        if parts.fragment:
            raise ValueError("Fragment URL interdit.")

        if hostname not in PROVIDER_HOSTS:
            raise PermissionError("Hôte fournisseur non autorisé.")

        if port not in (None, 443):
            raise PermissionError("Port fournisseur non autorisé.")

        path = parts.path or "/"
        target = path
        if parts.query:
            target += "?" + parts.query

        if any(ord(char) < 32 or ord(char) == 127 for char in target):
            raise ValueError("Cible HTTP invalide.")

        return hostname, target

    @staticmethod
    def _resolve_public_addresses(hostname):
        try:
            records = socket.getaddrinfo(
                hostname,
                443,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, OSError) as error:
            raise ProviderHTTPError(
                f"Résolution DNS fournisseur impossible : {type(error).__name__}."
            ) from None

        addresses = {}
        for record in records:
            raw_ip = record[4][0]

            try:
                classification = classify_ip(raw_ip)
            except ValueError:
                continue

            if not classification.is_public:
                continue

            candidate = (
                classification.mapped_ipv4
                if classification.is_ipv4_mapped
                else classification.address
            )

            if not candidate:
                continue

            try:
                canonical = classify_ip(candidate)
                ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if canonical.is_public and canonical.is_connectable:
                addresses.setdefault(candidate, canonical)

        if not addresses:
            raise ProviderHTTPError(
                "Aucune adresse IP publique utilisable pour ce fournisseur."
            )

        return tuple(addresses.items())

    def request(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> ProviderHTTPResponse:
        """Effectue une requête GET unique, sans suivre les redirections."""

        deadline = time.monotonic() + self.timeout

        hostname, target = self._parse_url(url)
        addresses = self._resolve_public_addresses(hostname)
        _remaining_time(deadline)

        request_headers = {
            "Host": hostname,
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

        if headers is not None:
            if not isinstance(headers, Mapping):
                raise ValueError("En-têtes HTTP invalides.")

            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError("En-tête HTTP invalide.")

                if (
                    not name
                    or any(ord(c) < 33 or ord(c) > 126 for c in name)
                    or "\r" in value
                    or "\n" in value
                ):
                    raise ValueError("En-tête HTTP invalide.")

                if name.lower() in {
                    "host",
                    "connection",
                    "proxy-authorization",
                    "proxy-connection",
                }:
                    raise ValueError("En-tête HTTP réservé.")

                request_headers[name] = value

        failures = []

        for candidate_ip, _classification in addresses:
            remaining = _remaining_time(deadline)
            connection = _PinnedHTTPSConnection(
                hostname,
                candidate_ip,
                remaining,
                self._tls_context,
            )

            try:
                connection.request(
                    "GET",
                    target,
                    headers=request_headers,
                )

                remaining = _remaining_time(deadline)
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)

                response = connection.getresponse()

                chunks = []
                total = 0
                while total <= self.max_response_bytes:
                    remaining = _remaining_time(deadline)
                    if connection.sock is not None:
                        connection.sock.settimeout(remaining)

                    chunk = response.read1(
                        min(65536, self.max_response_bytes + 1 - total)
                    )
                    if not chunk:
                        break

                    chunks.append(chunk)
                    total += len(chunk)

                body = b"".join(chunks)
                truncated = len(body) > self.max_response_bytes

                if truncated:
                    body = body[:self.max_response_bytes]

                _remaining_time(deadline)

                return ProviderHTTPResponse(
                    hostname=hostname,
                    status=response.status,
                    reason=response.reason or "",
                    headers=tuple(response.getheaders()),
                    body=body,
                    body_truncated=truncated,
                    connected_ip=candidate_ip,
                )

            except ProviderHTTPError:
                raise

            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as error:
                failures.append(type(error).__name__)
                if time.monotonic() >= deadline:
                    raise ProviderHTTPError(
                        "Délai global du transport fournisseur dépassé."
                    ) from None

            finally:
                connection.close()

        raise ProviderHTTPError(
            "Toutes les connexions aux IP publiques du fournisseur ont échoué : "
            + ", ".join(failures)
        )


class _ProviderURLResponse:
    """Interface compatible avec les réponses attendues par les connecteurs."""

    def __init__(self, response):
        self.status = response.status
        self.headers = Message()
        for name, value in response.headers:
            self.headers.add_header(name, value)
        self._body = io.BytesIO(response.body)

    def read(self, amount=-1):
        return self._body.read(amount)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._body.close()
        return False


def provider_urlopen(request, *, timeout=15.0):
    """Remplacement sécurisé de urllib.request.urlopen pour les connecteurs GET.

    Les redirections ne sont jamais suivies. Les réponses HTTP 3xx et 4xx
    deviennent des HTTPError afin de préserver les traitements existants.
    """
    from urllib.error import HTTPError

    if not hasattr(request, "full_url") or not hasattr(request, "get_method"):
        raise ProviderHTTPError("Objet de requête fournisseur invalide.")

    if request.get_method().upper() != "GET":
        raise ProviderHTTPError("Seules les requêtes GET sont autorisées.")

    url = request.full_url
    headers = dict(request.header_items())

    client = ProviderHTTPClient(
        timeout=timeout,
        max_response_bytes=DEFAULT_MAX_RESPONSE_BYTES,
    )
    response = client.request(url, headers=headers)

    if response.body_truncated:
        raise ProviderHTTPError(
            "Réponse fournisseur tronquée : limite de lecture atteinte."
        )

    if 300 <= response.status < 400 or response.status >= 400:
        message = Message()
        for name, value in response.headers:
            message.add_header(name, value)

        raise HTTPError(
            url,
            response.status,
            response.reason,
            message,
            io.BytesIO(response.body),
        )

    return _ProviderURLResponse(response)
