"""Analyse passive des en-têtes de sécurité HTTP.

Ce module observe uniquement les en-têtes déjà collectés.
Il ne réalise aucune requête réseau et ne déclare pas automatiquement
une vulnérabilité à partir d'une simple absence de protection.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from .http_client import HTTPAuditResponse


@dataclass(frozen=True)
class HeaderFinding:
    """Constat documenté concernant un en-tête HTTP."""

    code: str
    category: str
    severity: str
    confidence: int
    title: str
    description: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class HeaderAnalysis:
    """Résultat de l'analyse des en-têtes d'une réponse HTTP."""

    analyzed_url: str
    http_status: int | None
    findings: tuple[HeaderFinding, ...]
    headers_present: tuple[str, ...]


class HeadersAnalyzer:
    """Évalue les en-têtes de sécurité sans effectuer de connexion."""

    _REFERRER_POLICIES = frozenset({
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    })

    _XFO_VALUES = frozenset({
        "deny",
        "sameorigin",
    })

    def analyze(self, response: HTTPAuditResponse) -> HeaderAnalysis:
        if not isinstance(response, HTTPAuditResponse):
            raise ValueError("Une réponse HTTPAuditResponse est obligatoire.")

        headers = {}
        for name, value in response.headers:
            key = name.strip().lower()
            headers.setdefault(key, []).append(value.strip())

        findings = []

        def add(
            code,
            category,
            severity,
            confidence,
            title,
            description,
            evidence,
            recommendation,
        ):
            findings.append(HeaderFinding(
                code=code,
                category=category,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
            ))

        def values(name):
            return headers.get(name.lower(), [])

        def has(name):
            return bool(values(name))

        scheme = urlsplit(response.requested_url).scheme.lower()
        is_https = scheme == "https"

        # HSTS : applicable uniquement aux réponses HTTPS.
        hsts_values = values("strict-transport-security")

        if is_https:
            if not hsts_values:
                add(
                    "HSTS_MISSING",
                    "security_header",
                    "low",
                    100,
                    "En-tête HSTS absent",
                    "La réponse HTTPS ne contient pas Strict-Transport-Security.",
                    "Strict-Transport-Security absent",
                    "Envisager HSTS avec un max-age adapté après vérification "
                    "de la prise en charge HTTPS de tous les sous-domaines concernés.",
                )
            else:
                for value in hsts_values:
                    directives = {}
                    malformed = False

                    for item in value.split(";"):
                        item = item.strip()
                        if not item:
                            continue

                        if "=" in item:
                            key, directive_value = item.split("=", 1)
                            key = key.strip().lower()
                            directive_value = directive_value.strip().strip('"')
                            if key in directives:
                                malformed = True
                            directives[key] = directive_value
                        else:
                            key = item.lower()
                            if key in directives:
                                malformed = True
                            directives[key] = None

                    max_age = directives.get("max-age")

                    if (
                        max_age is None
                        or not max_age.isdigit()
                    ):
                        add(
                            "HSTS_INVALID_MAX_AGE",
                            "security_header",
                            "medium",
                            100,
                            "Directive HSTS max-age invalide ou absente",
                            "La durée HSTS ne peut pas être interprétée correctement.",
                            value[:500],
                            "Définir max-age avec une valeur entière positive "
                            "adaptée à la politique de sécurité du domaine.",
                        )
                    elif int(max_age) == 0:
                        add(
                            "HSTS_DISABLED",
                            "security_header",
                            "medium",
                            100,
                            "HSTS désactivé par max-age=0",
                            "La valeur max-age=0 demande au navigateur de supprimer "
                            "la politique HSTS mémorisée.",
                            value[:500],
                            "Configurer une durée HSTS positive si cette protection "
                            "est souhaitée.",
                        )
                    elif int(max_age) < 15_552_000:
                        add(
                            "HSTS_SHORT_MAX_AGE",
                            "security_header",
                            "low",
                            100,
                            "Durée HSTS relativement courte",
                            "La durée configurée est inférieure à six mois.",
                            f"max-age={max_age}",
                            "Évaluer une durée plus longue après validation "
                            "de la disponibilité HTTPS.",
                        )

                    if malformed:
                        add(
                            "HSTS_DUPLICATE_DIRECTIVE",
                            "configuration",
                            "medium",
                            90,
                            "Directives HSTS dupliquées",
                            "Au moins une directive HSTS apparaît plusieurs fois.",
                            value[:500],
                            "Supprimer les directives dupliquées et conserver "
                            "une politique HSTS non ambiguë.",
                        )

        # CSP : présence et protection contre l'encadrement.
        csp_values = values("content-security-policy")
        frame_ancestors_present = False

        for policy in csp_values:
            for directive in policy.split(";"):
                parts = directive.strip().split()
                if parts and parts[0].lower() == "frame-ancestors":
                    frame_ancestors_present = True

        if not csp_values:
            add(
                "CSP_MISSING",
                "security_header",
                "low",
                100,
                "Content-Security-Policy absent",
                "Aucune politique CSP n'est présente dans la réponse.",
                "Content-Security-Policy absent",
                "Évaluer une politique CSP adaptée aux ressources et fonctionnalités "
                "réellement utilisées par l'application.",
            )

        # X-Frame-Options et CSP frame-ancestors sont évalués ensemble.
        xfo_values = values("x-frame-options")
        xfo_protective = False
        xfo_invalid = []

        for value in xfo_values:
            normalized = value.strip().lower()

            if normalized in self._XFO_VALUES:
                xfo_protective = True
            elif normalized.startswith("allow-from "):
                xfo_invalid.append(value)
            else:
                xfo_invalid.append(value)

        if not frame_ancestors_present and not xfo_protective:
            add(
                "CLICKJACKING_PROTECTION_MISSING",
                "security_header",
                "low",
                100,
                "Protection contre le clickjacking non détectée",
                "Aucune directive CSP frame-ancestors ni valeur X-Frame-Options "
                "reconnue comme protectrice n'a été détectée.",
                "CSP frame-ancestors et X-Frame-Options absents ou non protecteurs",
                "Évaluer CSP frame-ancestors et, pour la compatibilité, "
                "X-Frame-Options selon les besoins de l'application.",
            )

        if xfo_invalid:
            add(
                "X_FRAME_OPTIONS_INVALID",
                "configuration",
                "medium",
                95,
                "X-Frame-Options non reconnu",
                "Une ou plusieurs valeurs X-Frame-Options ne correspondent pas "
                "aux valeurs protectrices DENY ou SAMEORIGIN.",
                "; ".join(xfo_invalid)[:500],
                "Utiliser DENY ou SAMEORIGIN, ou une directive CSP frame-ancestors "
                "correctement configurée.",
            )

        # Protection contre le MIME sniffing.
        nosniff_values = values("x-content-type-options")

        if not any(value.lower() == "nosniff" for value in nosniff_values):
            add(
                "NOSNIFF_MISSING",
                "security_header",
                "low",
                100,
                "X-Content-Type-Options absent ou incorrect",
                "La valeur nosniff n'a pas été détectée.",
                "; ".join(nosniff_values)[:500] if nosniff_values
                else "X-Content-Type-Options absent",
                "Configurer X-Content-Type-Options: nosniff lorsque cela "
                "est approprié pour les ressources servies.",
            )

        # Referrer-Policy.
        referrer_values = values("referrer-policy")
        valid_referrer = []

        for value in referrer_values:
            for policy in value.split(","):
                normalized = policy.strip().lower()
                if normalized in self._REFERRER_POLICIES:
                    valid_referrer.append(normalized)

        if not valid_referrer:
            add(
                "REFERRER_POLICY_MISSING_OR_INVALID",
                "security_header",
                "low",
                100,
                "Referrer-Policy absente ou non reconnue",
                "Aucune politique de référent reconnue n'a été détectée.",
                "; ".join(referrer_values)[:500] if referrer_values
                else "Referrer-Policy absente",
                "Évaluer strict-origin-when-cross-origin ou une politique "
                "plus restrictive selon les besoins de l'application.",
            )

        # Permissions-Policy : présence seulement, sans supposer
        # que chaque fonctionnalité doit être interdite.
        if not has("permissions-policy"):
            add(
                "PERMISSIONS_POLICY_MISSING",
                "security_header",
                "informational",
                100,
                "Permissions-Policy absente",
                "Aucune politique de permissions du navigateur n'a été détectée.",
                "Permissions-Policy absent",
                "Définir explicitement les fonctionnalités du navigateur "
                "autorisées si cette politique est nécessaire.",
            )

        # Divulgation de technologies : information, pas vulnérabilité.
        for header_name in ("server", "x-powered-by"):
            for value in values(header_name):
                if value:
                    add(
                        f"{header_name.upper().replace('-', '_')}_DISCLOSURE",
                        "information_disclosure",
                        "informational",
                        100,
                        f"Information technologique exposée : {header_name}",
                        "L'en-tête divulgue une information sur la technologie "
                        "ou le serveur utilisé. Cette observation ne prouve "
                        "pas à elle seule une vulnérabilité.",
                        f"{header_name}: {value[:300]}",
                        "Évaluer si cette information est nécessaire et si "
                        "sa réduction est compatible avec le fonctionnement "
                        "de l'application.",
                    )

        return HeaderAnalysis(
            analyzed_url=response.requested_url,
            http_status=response.status,
            findings=tuple(findings),
            headers_present=tuple(sorted(headers)),
        )
