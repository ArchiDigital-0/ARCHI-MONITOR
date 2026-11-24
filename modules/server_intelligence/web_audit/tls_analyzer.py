"""Analyse passive des métadonnées d'un certificat TLS.

Ce module n'effectue aucune connexion réseau et ne contourne jamais
la validation TLS. Il analyse uniquement les informations fournies
par un composant de connexion déjà exécuté.
"""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class TLSCertificateInfo:
    """Métadonnées extraites d'un certificat TLS."""

    hostname: str
    not_before: datetime | None
    not_after: datetime | None
    subject: str = ""
    issuer: str = ""
    san_dns_names: tuple[str, ...] = ()
    signature_algorithm: str = ""
    public_key_type: str = ""
    public_key_bits: int | None = None
    validation_error: str | None = None


@dataclass(frozen=True)
class TLSFinding:
    """Constat documenté concernant la configuration TLS."""

    code: str
    category: str
    severity: str
    confidence: int
    title: str
    description: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class TLSAnalysis:
    """Résultat de l'analyse d'un certificat TLS."""

    hostname: str
    certificate_available: bool
    certificate_valid_at_analysis: bool | None
    findings: tuple[TLSFinding, ...]
    subject: str
    issuer: str


class TLSAnalyzer:
    """Évalue les métadonnées d'un certificat sans connexion réseau."""

    @staticmethod
    def _normalize_hostname(value: str) -> str:
        return value.strip().lower().rstrip(".")

    @classmethod
    def _hostname_matches(cls, hostname: str, pattern: str) -> bool:
        hostname = cls._normalize_hostname(hostname)
        pattern = cls._normalize_hostname(pattern)

        if not hostname or not pattern:
            return False

        if pattern.startswith("*."):
            suffix = pattern[2:]

            if not suffix or not hostname.endswith("." + suffix):
                return False

            prefix = hostname[:-(len(suffix) + 1)]
            return bool(prefix) and "." not in prefix

        return hostname == pattern

    def analyze(
        self,
        certificate: TLSCertificateInfo | None,
        now: datetime | None = None,
    ) -> TLSAnalysis:
        if certificate is None:
            finding = TLSFinding(
                code="TLS_CERTIFICATE_UNAVAILABLE",
                category="tls",
                severity="medium",
                confidence=100,
                title="Informations du certificat TLS indisponibles",
                description=(
                    "Aucune métadonnée de certificat n'a été fournie. "
                    "Il est impossible de conclure sur sa validité."
                ),
                evidence="Certificat non fourni au module d'analyse",
                recommendation=(
                    "Vérifier que le composant de connexion transmet "
                    "les métadonnées du certificat après une connexion TLS validée."
                ),
            )
            return TLSAnalysis(
                hostname="",
                certificate_available=False,
                certificate_valid_at_analysis=None,
                findings=(finding,),
                subject="",
                issuer="",
            )

        if not isinstance(certificate, TLSCertificateInfo):
            raise ValueError("Un objet TLSCertificateInfo est obligatoire.")

        if now is None:
            now = datetime.now(timezone.utc)

        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("La date d'analyse doit inclure un fuseau horaire.")

        now = now.astimezone(timezone.utc)
        findings = []
        hostname = self._normalize_hostname(certificate.hostname)

        def add(
            code,
            category,
            severity,
            title,
            description,
            evidence,
            recommendation,
            confidence=100,
        ):
            findings.append(TLSFinding(
                code=code,
                category=category,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
            ))

        valid = None
        validation_failed = bool(certificate.validation_error)

        if certificate.validation_error:
            add(
                "TLS_VALIDATION_ERROR",
                "tls_validation",
                "high",
                "Échec de validation TLS",
                (
                    "Le composant de connexion a signalé une erreur "
                    "de validation du certificat. La connexion ne doit "
                    "pas être considérée comme fiable."
                ),
                certificate.validation_error[:500],
                (
                    "Examiner la chaîne de certification, les autorités "
                    "de confiance, le nom d'hôte et les dates du certificat. "
                    "Ne pas désactiver la validation TLS."
                ),
            )

        dates_available = (
            certificate.not_before is not None
            and certificate.not_after is not None
        )

        if dates_available:
            if (
                certificate.not_before.tzinfo is None
                or certificate.not_after.tzinfo is None
            ):
                raise ValueError(
                    "Les dates du certificat doivent inclure un fuseau horaire."
                )

            not_before = certificate.not_before.astimezone(timezone.utc)
            not_after = certificate.not_after.astimezone(timezone.utc)

            if not_before > not_after:
                valid = False
                add(
                    "TLS_INVALID_DATE_RANGE",
                    "tls_configuration",
                    "high",
                    "Période de validité du certificat incohérente",
                    "La date de début de validité est postérieure à la date d'expiration.",
                    (
                        f"not_before={not_before.isoformat()}, "
                        f"not_after={not_after.isoformat()}"
                    ),
                    "Vérifier le certificat présenté et sa chaîne de délivrance.",
                )
            elif now < not_before:
                add(
                    "TLS_CERTIFICATE_NOT_YET_VALID",
                    "tls_certificate",
                    "high",
                    "Certificat TLS pas encore valide",
                    "La date actuelle précède le début de validité du certificat.",
                    f"Début de validité : {not_before.isoformat()}",
                    "Vérifier l'horloge du système et obtenir un certificat valide.",
                )
                valid = False
            elif now > not_after:
                add(
                    "TLS_CERTIFICATE_EXPIRED",
                    "tls_certificate",
                    "high",
                    "Certificat TLS expiré",
                    "La date actuelle dépasse la date d'expiration du certificat.",
                    f"Expiration : {not_after.isoformat()}",
                    "Renouveler le certificat et vérifier son déploiement.",
                )
                valid = False
            else:
                valid = True
        else:
            add(
                "TLS_CERTIFICATE_DATES_UNAVAILABLE",
                "tls",
                "informational",
                "Dates de validité du certificat indisponibles",
                "Les deux dates nécessaires à l'évaluation ne sont pas disponibles.",
                "not_before ou not_after absent",
                "Collecter les dates de validité du certificat.",
            )

        if certificate.san_dns_names:
            hostname_matches = any(
                self._hostname_matches(hostname, name)
                for name in certificate.san_dns_names
            )

            if not hostname_matches:
                valid = False
                add(
                    "TLS_HOSTNAME_MISMATCH",
                    "tls_certificate",
                    "high",
                    "Nom d'hôte absent des noms DNS du certificat",
                    (
                        "Aucun nom DNS du champ Subject Alternative Name "
                        "ne correspond à l'hôte analysé."
                    ),
                    (
                        f"Hôte : {hostname}; "
                        f"SAN DNS : {', '.join(certificate.san_dns_names)[:400]}"
                    ),
                    "Déployer un certificat couvrant explicitement le nom d'hôte.",
                )
        else:
            if valid is True:
                valid = None
            add(
                "TLS_SAN_MISSING",
                "tls_certificate",
                "medium",
                "Noms DNS SAN indisponibles",
                (
                    "Aucun nom DNS Subject Alternative Name n'a été fourni. "
                    "La correspondance du nom d'hôte ne peut pas être confirmée."
                ),
                "Liste SAN DNS vide",
                "Vérifier les extensions du certificat et collecter les SAN DNS.",
            )

        signature = certificate.signature_algorithm.strip().lower()

        if signature and any(
            weak in signature for weak in ("md5", "sha1", "sha-1")
        ):
            add(
                "TLS_WEAK_SIGNATURE_ALGORITHM",
                "tls_configuration",
                "high",
                "Algorithme de signature cryptographique ancien",
                "L'algorithme de signature déclaré utilise MD5 ou SHA-1.",
                certificate.signature_algorithm[:200],
                "Remplacer le certificat par un certificat utilisant un algorithme moderne.",
            )

        key_type = certificate.public_key_type.strip().lower()
        key_bits = certificate.public_key_bits

        if key_bits is not None:
            if key_bits <= 0:
                add(
                    "TLS_INVALID_PUBLIC_KEY_SIZE",
                    "tls_configuration",
                    "medium",
                    "Taille de clé publique invalide",
                    "La taille de clé publique fournie n'est pas positive.",
                    f"Taille déclarée : {key_bits}",
                    "Vérifier les métadonnées cryptographiques du certificat.",
                )
            elif key_type in {"rsa", "rsassa"} and key_bits < 2048:
                add(
                    "TLS_WEAK_RSA_KEY",
                    "tls_configuration",
                    "high",
                    "Clé RSA trop courte",
                    "La clé RSA déclarée comporte moins de 2048 bits.",
                    f"RSA {key_bits} bits",
                    "Utiliser une clé RSA d'au moins 2048 bits ou une alternative moderne.",
                )
            elif key_type in {"ec", "ecdsa"} and key_bits < 224:
                add(
                    "TLS_WEAK_EC_KEY",
                    "tls_configuration",
                    "high",
                    "Clé elliptique de taille insuffisante",
                    "La taille de clé elliptique déclarée est inférieure à 224 bits.",
                    f"EC {key_bits} bits",
                    "Utiliser une courbe elliptique moderne et suffisamment robuste.",
                )

        if certificate.subject:
            subject = certificate.subject[:500]
        else:
            subject = ""

        return TLSAnalysis(
            hostname=hostname,
            certificate_available=True,
            certificate_valid_at_analysis=(False if validation_failed else valid),
            findings=tuple(findings),
            subject=subject,
            issuer=certificate.issuer[:500],
        )
