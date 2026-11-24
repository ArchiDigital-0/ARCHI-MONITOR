"""Registre central des sources de SERVER INTELLIGENCE.

Ce registre décrit les fournisseurs sans effectuer de connexion réseau.
Les endpoints et quotas doivent être vérifiés avant l'implémentation
des connecteurs.
"""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class SourceDefinition:
    """Description immuable d'une source de renseignement."""

    source_id: str
    name: str
    category: str
    discovery_type: str
    access_requirement: str
    api_key_env: str | None
    api_key_requirement: str = "unknown"
    documentation_url: str = ""
    endpoint: str | None = None
    activation_policy: str = "manual_after_review"
    verification_status: str = "pending_official_review"
    pagination_supported: bool | None = None
    notes: str = ""


_SOURCE_LIST = (
    SourceDefinition(
        source_id="crt_sh",
        name="crt.sh",
        category="certificate_transparency",
        discovery_type="certificate_and_subdomain_discovery",
        access_requirement="public_no_key",
        api_key_env=None,
        api_key_requirement="none",
        documentation_url="https://crt.sh/",
        activation_policy="automatic_if_policy_allows",
        notes="Recherche publique de certificats. Service susceptible d’être indisponible ou ralenti. Prévoir des délais stricts, des erreurs isolées et des tentatives contrôlées. Les noms historiques ne prouvent pas une résolution DNS actuelle.",
    ),
    SourceDefinition(
        source_id="cert_spotter",
        name="Cert Spotter",
        category="certificate_transparency",
        discovery_type="certificate_and_subdomain_discovery",
        access_requirement="limited_or_api_key",
        api_key_env="CERTSPOTTER_API_KEY",
        api_key_requirement="optional",
        documentation_url="https://certspotter.com/",
        activation_policy="automatic_if_anonymous_access_is_permitted",
        notes="Accès anonyme limité. Respecter les quotas du fournisseur, la pagination et Retry-After. Authentification recommandée pour un usage en production.",
    ),
    SourceDefinition(
        source_id="merklemap",
        name="Merklemap",
        category="internet_asset_discovery",
        discovery_type="asset_and_domain_discovery",
        access_requirement="verify_access",
        api_key_env="MERKLEMAP_API_KEY",
        api_key_requirement="unknown",
        documentation_url="https://www.merklemap.com/",
        notes="Endpoint, authentification et conditions d'accès à confirmer.",
    ),
    SourceDefinition(
        source_id="ctlogs_dev",
        name="CTLogs.dev",
        category="certificate_transparency",
        discovery_type="certificate_and_subdomain_discovery",
        access_requirement="verify_access",
        api_key_env="CTLOGS_API_KEY",
        api_key_requirement="unknown",
        documentation_url="https://ctlogs.dev/",
        notes="Quotas, authentification et conditions commerciales à vérifier.",
    ),
    SourceDefinition(
        source_id="hackertarget",
        name="HackerTarget",
        category="dns_discovery",
        discovery_type="host_and_subdomain_discovery",
        access_requirement="limited_no_key",
        api_key_env=None,
        api_key_requirement="none",
        documentation_url="https://hackertarget.com/",
        activation_policy="automatic_if_policy_allows",
        notes="Accès gratuit sans clé soumis aux limites du fournisseur : maximum annoncé de 50 appels par jour et 500 lignes de résultats. Respecter également la limite de débit et les quotas retournés.",
    ),
    SourceDefinition(
        source_id="rapiddns",
        name="RapidDNS",
        category="dns_discovery",
        discovery_type="historical_and_observed_dns_discovery",
        access_requirement="paid_api_key_subscription",
        api_key_env="RAPIDDNS_API_KEY",
        api_key_requirement="required",
        documentation_url="https://rapiddns.io/help/api",
        notes="API réservée aux abonnements compatibles (Pro, Pro Plus ou Max). Clé API obligatoire ; activation manuelle.",
    ),
    SourceDefinition(
        source_id="alienvault_otx",
        name="AlienVault OTX",
        category="threat_intelligence",
        discovery_type="passive_dns_and_threat_intelligence",
        access_requirement="optional_api_key",
        api_key_env="OTX_API_KEY",
        api_key_requirement="optional",
        documentation_url="https://otx.alienvault.com/api",
        activation_policy="manual_after_review",
        notes="Source de renseignement sur les menaces et de données DNS passives. Clé API facultative. Accès anonyme à vérifier avant activation. Ne constitue pas une preuve d’activité DNS actuelle.",
    ),
    SourceDefinition(
        source_id="urlscan",
        name="URLScan.io",
        category="web_scan_intelligence",
        discovery_type="historical_scan_and_web_asset_discovery",
        access_requirement="optional_or_required_api_key",
        api_key_env="URLSCAN_API_KEY",
        api_key_requirement="optional",
        documentation_url="https://urlscan.io/",
        notes="Distinguer recherche de scans existants et soumission de nouveaux scans.",
    ),
    SourceDefinition(
        source_id="virustotal",
        name="VirusTotal",
        category="threat_intelligence",
        discovery_type="domain_relationship_and_subdomain_discovery",
        access_requirement="api_key",
        api_key_env="VIRUSTOTAL_API_KEY",
        api_key_requirement="required",
        documentation_url="https://www.virustotal.com/",
        notes="Les quotas dépendent du type de compte et des conditions d'utilisation.",
    ),
    SourceDefinition(
        source_id="censys",
        name="Censys",
        category="internet_asset_search",
        discovery_type="internet_exposed_asset_discovery",
        access_requirement="account_or_api_credentials",
        api_key_env="CENSYS_API_KEY",
        api_key_requirement="required",
        documentation_url="https://censys.com/",
        notes="Accès, crédits et capacités à vérifier selon l'offre et l'API utilisée.",
    ),
)


SOURCE_REGISTRY = MappingProxyType({
    source.source_id: source
    for source in _SOURCE_LIST
})


def list_sources() -> tuple[SourceDefinition, ...]:
    """Retourne toutes les sources dans leur ordre de déclaration."""

    return tuple(SOURCE_REGISTRY.values())


def get_source(source_id: str) -> SourceDefinition | None:
    """Recherche une source par identifiant."""

    if not isinstance(source_id, str):
        return None

    return SOURCE_REGISTRY.get(source_id.strip().lower())


def sources_requiring_api_key() -> tuple[SourceDefinition, ...]:
    """Retourne les sources exigeant obligatoirement une clé API."""

    return tuple(
        source
        for source in SOURCE_REGISTRY.values()
        if source.api_key_requirement == "required"
    )


def sources_with_optional_api_key() -> tuple[SourceDefinition, ...]:
    """Retourne les sources acceptant potentiellement un accès sans clé."""

    return tuple(
        source
        for source in SOURCE_REGISTRY.values()
        if source.api_key_requirement == "optional"
    )


def sources_without_api_key() -> tuple[SourceDefinition, ...]:
    """Retourne les sources ne déclarant pas de clé nécessaire."""

    return tuple(
        source
        for source in SOURCE_REGISTRY.values()
        if source.api_key_requirement == "none"
    )


def sources_with_unknown_authentication() -> tuple[SourceDefinition, ...]:
    """Retourne les sources dont les exigences d'authentification restent inconnues."""

    return tuple(
        source
        for source in SOURCE_REGISTRY.values()
        if source.api_key_requirement == "unknown"
    )


def sources_pending_review() -> tuple[SourceDefinition, ...]:
    """Retourne les sources dont les modalités restent à vérifier."""

    return tuple(
        source
        for source in SOURCE_REGISTRY.values()
        if source.verification_status != "verified"
    )
