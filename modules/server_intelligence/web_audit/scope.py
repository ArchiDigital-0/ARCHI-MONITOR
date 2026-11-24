"""Contrôle du périmètre autorisé et classification des adresses IP.

Ce module ne réalise aucune connexion HTTP ni aucun accès aux équipements
des adresses découvertes. La résolution DNS est exécutée uniquement
lorsqu'elle est explicitement demandée.
"""

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..config import normalize_domain, domain_is_in_scope


@dataclass(frozen=True)
class IPClassification:
    """Classification individuelle d'une adresse IP."""

    address: str
    version: int
    category: str
    is_public: bool
    is_connectable: bool
    is_ipv4_mapped: bool = False
    mapped_ipv4: str | None = None


@dataclass(frozen=True)
class DNSResolution:
    """Résultat d'une résolution DNS, sans connexion à ses adresses."""

    hostname: str
    port: int
    resolved_at: datetime
    addresses: tuple[IPClassification, ...]
    error: str | None = None

    @property
    def public_addresses(self) -> tuple[IPClassification, ...]:
        return tuple(item for item in self.addresses if item.is_public)

    @property
    def blocked_addresses(self) -> tuple[IPClassification, ...]:
        return tuple(item for item in self.addresses if not item.is_public)

    @property
    def has_public_address(self) -> bool:
        return bool(self.public_addresses)


def classify_ip(value: str) -> IPClassification:
    """Classe une IP sans effectuer de communication réseau."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Adresse IP invalide.")

    value = value.strip()

    if "%" in value:
        raise ValueError("Les identifiants de zone IPv6 ne sont pas acceptés.")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Adresse IP invalide.") from None

    mapped = getattr(address, "ipv4_mapped", None)

    if mapped is not None:
        underlying = classify_ip(str(mapped))
        return IPClassification(
            address=str(address),
            version=6,
            category=underlying.category,
            is_public=underlying.is_public,
            is_connectable=False,
            is_ipv4_mapped=True,
            mapped_ipv4=str(mapped),
        )

    if address.is_loopback:
        category = "loopback"
    elif address.is_link_local:
        category = "link_local"
    elif address.is_multicast:
        category = "multicast"
    elif address.is_unspecified:
        category = "unspecified"
    elif address.is_reserved:
        category = "reserved"
    elif address.is_private:
        category = "private"
    elif address.is_global:
        category = "public"
    else:
        category = "non_public_other"

    is_public = category == "public"

    return IPClassification(
        address=str(address),
        version=address.version,
        category=category,
        is_public=is_public,
        is_connectable=is_public,
    )


@dataclass(frozen=True)
class ScopePolicy:
    """Politique de périmètre pour un audit autorisé."""

    target_domain: str
    authorized_domains: tuple[str, ...]

    def __post_init__(self):
        target = normalize_domain(self.target_domain)

        if not isinstance(self.authorized_domains, tuple):
            raise ValueError("authorized_domains doit être un tuple.")

        normalized_domains = tuple(
            dict.fromkeys(
                normalize_domain(domain)
                for domain in self.authorized_domains
            )
        )

        if not normalized_domains:
            raise ValueError("Aucun domaine autorisé n'a été défini.")

        if not any(
            domain_is_in_scope(target, domain)
            for domain in normalized_domains
        ):
            raise ValueError(
                "Le domaine cible ne figure pas dans le périmètre autorisé."
            )

        object.__setattr__(self, "target_domain", target)
        object.__setattr__(self, "authorized_domains", normalized_domains)

    @classmethod
    def from_config(cls, config: Any) -> "ScopePolicy":
        """Construit la politique depuis ServerIntelligenceConfig."""

        if not getattr(config, "active_audit_enabled", False):
            raise ValueError("L'audit actif n'est pas activé.")

        if not getattr(config, "active_audit_authorized", False):
            raise ValueError("L'autorisation d'audit est absente.")

        return cls(
            target_domain=config.target_domain,
            authorized_domains=tuple(config.authorized_domains),
        )

    def is_authorized_host(self, hostname: str) -> bool:
        """Vérifie l'appartenance exacte ou en sous-domaine autorisé."""

        try:
            normalized = normalize_domain(hostname)
        except (TypeError, ValueError):
            return False

        return any(
            domain_is_in_scope(normalized, authorized)
            for authorized in self.authorized_domains
        )

    def require_authorized_host(self, hostname: str) -> str:
        """Normalise un hôte ou refuse son utilisation."""

        try:
            normalized = normalize_domain(hostname)
        except (TypeError, ValueError):
            raise ValueError("Nom d'hôte invalide.") from None

        if not self.is_authorized_host(normalized):
            raise PermissionError(
                "L'hôte ne figure pas dans le périmètre autorisé."
            )

        return normalized

    def resolve_host(
        self,
        hostname: str,
        port: int = 443,
    ) -> DNSResolution:
        """Résout un hôte autorisé et classe chaque IP retournée.

        Cette méthode effectue une résolution DNS, mais n'établit
        aucune connexion vers les adresses obtenues.
        """

        normalized = self.require_authorized_host(hostname)

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("Port invalide.")

        collected_at = datetime.now(timezone.utc)

        try:
            records = socket.getaddrinfo(
                normalized,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, OSError) as error:
            return DNSResolution(
                hostname=normalized,
                port=port,
                resolved_at=collected_at,
                addresses=(),
                error=f"{type(error).__name__}: {error}",
            )

        classifications = {}
        for record in records:
            sockaddr = record[4]
            ip_value = sockaddr[0]

            classification = classify_ip(ip_value)
            classifications.setdefault(
                classification.address,
                classification,
            )

        return DNSResolution(
            hostname=normalized,
            port=port,
            resolved_at=collected_at,
            addresses=tuple(classifications.values()),
            error=None if classifications else "no_addresses_returned",
        )
