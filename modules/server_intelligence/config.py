"""Configuration centrale et validations de SERVER INTELLIGENCE."""

import ipaddress
import math
import re
from dataclasses import dataclass, field


_DOMAIN_LABEL = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def normalize_domain(value: str) -> str:
    """Valide et normalise un nom de domaine DNS."""

    if not isinstance(value, str):
        raise ValueError("Le domaine doit être une chaîne de caractères.")

    domain = value.strip()

    if not domain:
        raise ValueError("Le domaine est obligatoire.")

    if domain.endswith("."):
        domain = domain[:-1]

    if not domain or domain.endswith("."):
        raise ValueError("Le domaine contient une partie vide.")

    if any(char.isspace() for char in domain):
        raise ValueError("Les espaces sont interdits dans un domaine.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Une adresse IP n'est pas un nom de domaine.")

    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ValueError("Nom de domaine internationalisé invalide.") from None

    if len(ascii_domain) > 253:
        raise ValueError("Le domaine dépasse 253 caractères.")

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        raise ValueError("Un nom de domaine complet est obligatoire.")

    for label in labels:
        if not 1 <= len(label) <= 63:
            raise ValueError("Longueur d'une partie du domaine invalide.")

        if not _DOMAIN_LABEL.fullmatch(label):
            raise ValueError(
                f"Partie du domaine invalide : {label}"
            )

    return ascii_domain


def domain_is_in_scope(domain: str, authorized_domain: str) -> bool:
    """Vérifie l'appartenance au périmètre avec frontière DNS."""

    return (
        domain == authorized_domain
        or domain.endswith("." + authorized_domain)
    )


def _require_positive_number(name: str, value) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"Valeur invalide : {name}")


def _require_non_negative_number(name: str, value) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"Valeur invalide : {name}")


def _require_positive_integer(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"Valeur invalide : {name}")


@dataclass(frozen=True)
class SourceConfig:
    """Paramètres individuels d'un fournisseur."""

    enabled: bool = True
    api_key_env: str | None = None
    timeout_seconds: float = 15.0
    requests_per_minute: int | None = None
    max_pages: int = 5

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise ValueError("L'état du fournisseur doit être booléen.")

        if self.api_key_env is not None:
            if (
                not isinstance(self.api_key_env, str)
                or not _ENV_NAME.fullmatch(self.api_key_env)
            ):
                raise ValueError("Nom de variable d'environnement invalide.")

        _require_positive_number(
            "timeout_seconds",
            self.timeout_seconds,
        )

        if self.requests_per_minute is not None:
            _require_positive_integer(
                "requests_per_minute",
                self.requests_per_minute,
            )

        _require_positive_integer("max_pages", self.max_pages)


@dataclass
class ServerIntelligenceConfig:
    """Configuration générale du moteur SERVER INTELLIGENCE."""

    target_domain: str

    # Périmètre explicitement déclaré comme autorisé.
    authorized_domains: tuple[str, ...] = ()

    # Capacités du moteur.
    passive_discovery_enabled: bool = True
    active_audit_enabled: bool = False
    active_audit_authorized: bool = False

    # Délais réseau.
    connect_timeout_seconds: float = 8.0
    read_timeout_seconds: float = 12.0

    # Limites de ressources.
    max_response_bytes: int = 5_000_000
    max_redirects: int = 5
    max_concurrent_sources: int = 5
    max_concurrent_hosts: int = 3
    max_requests_per_host: int = 10
    max_assets: int = 5000
    max_pages_per_source: int = 10
    request_interval_seconds: float = 1.0

    # Identification des requêtes.
    user_agent: str = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"

    # Stockage local.
    evidence_dir: str = "data/server_intelligence/evidence"
    report_dir: str = "reports/server_intelligence"

    # Configuration indépendante des fournisseurs.
    source_configs: dict[str, SourceConfig] = field(
        default_factory=dict
    )

    def __post_init__(self):
        self.target_domain = normalize_domain(self.target_domain)

        if not isinstance(self.authorized_domains, (tuple, list)):
            raise ValueError(
                "Les domaines autorisés doivent former une liste ou un tuple."
            )

        normalized_authorized = []

        for domain in self.authorized_domains:
            normalized = normalize_domain(domain)
            if normalized not in normalized_authorized:
                normalized_authorized.append(normalized)

        self.authorized_domains = tuple(normalized_authorized)

        for name in (
            "passive_discovery_enabled",
            "active_audit_enabled",
            "active_audit_authorized",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"Paramètre booléen invalide : {name}")

        _require_positive_number(
            "connect_timeout_seconds",
            self.connect_timeout_seconds,
        )
        _require_positive_number(
            "read_timeout_seconds",
            self.read_timeout_seconds,
        )

        positive_limits = {
            "max_response_bytes": self.max_response_bytes,
            "max_concurrent_sources": self.max_concurrent_sources,
            "max_concurrent_hosts": self.max_concurrent_hosts,
            "max_requests_per_host": self.max_requests_per_host,
            "max_assets": self.max_assets,
            "max_pages_per_source": self.max_pages_per_source,
        }

        for name, value in positive_limits.items():
            _require_positive_integer(name, value)

        if (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or self.max_redirects < 0
        ):
            raise ValueError("Nombre de redirections invalide.")

        _require_non_negative_number(
            "request_interval_seconds",
            self.request_interval_seconds,
        )

        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise ValueError("User-Agent obligatoire.")

        for name in ("evidence_dir", "report_dir"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Chemin de stockage invalide : {name}")

        if not isinstance(self.source_configs, dict):
            raise ValueError("La configuration des fournisseurs doit être un dictionnaire.")

        for source_id, source_config in self.source_configs.items():
            if not isinstance(source_id, str) or not source_id.strip():
                raise ValueError("Identifiant de fournisseur invalide.")

            if not isinstance(source_config, SourceConfig):
                raise ValueError(
                    f"Configuration invalide pour le fournisseur : {source_id}"
                )

        if self.active_audit_enabled:
            if not self.active_audit_authorized:
                raise ValueError(
                    "L'audit actif exige une autorisation explicite."
                )

            if not self.authorized_domains:
                raise ValueError(
                    "Un périmètre autorisé est obligatoire."
                )

            if not any(
                domain_is_in_scope(self.target_domain, authorized)
                for authorized in self.authorized_domains
            ):
                raise ValueError(
                    "Le domaine cible ne figure pas dans le périmètre autorisé."
                )
