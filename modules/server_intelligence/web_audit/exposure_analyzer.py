"""Détection passive des expositions web observables.

Ce module analyse uniquement les réponses HTTP déjà collectées.
Il n'effectue aucune requête réseau, aucun téléchargement supplémentaire
et aucune tentative d'exploitation.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .http_client import HTTPAuditResponse


@dataclass(frozen=True)
class ExposureFinding:
    """Constat documenté concernant une exposition web."""

    code: str
    category: str
    severity: str
    confidence: int
    title: str
    description: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class ExposureAnalysis:
    """Résultat de l'analyse passive d'une réponse HTTP."""

    analyzed_url: str
    http_status: int | None
    findings: tuple[ExposureFinding, ...]
    body_analyzed: bool
    body_bytes_analyzed: int


class ExposureAnalyzer:
    """Détecte des pages par défaut et expositions web évidentes."""

    MAX_ANALYZED_BODY_BYTES = 1_000_000

    _DEFAULT_PAGE_PATTERNS = (
        (
            "APACHE_DEFAULT_PAGE",
            re.compile(
                r"Apache2 Ubuntu Default Page|"
                r"It works!\s*</(?:h1|title)>",
                re.IGNORECASE,
            ),
            "Page par défaut Apache détectée",
        ),
        (
            "NGINX_DEFAULT_PAGE",
            re.compile(
                r"Welcome to nginx!",
                re.IGNORECASE,
            ),
            "Page d'accueil par défaut Nginx détectée",
        ),
        (
            "IIS_DEFAULT_PAGE",
            re.compile(
                r"IIS Windows Server|"
                r"Internet Information Services\s*</",
                re.IGNORECASE,
            ),
            "Page par défaut IIS détectée",
        ),
    )

    _INSTALLATION_PATTERNS = (
        re.compile(
            r"<title[^>]*>\s*(?:installation|install wizard|setup wizard)",
            re.IGNORECASE,
        ),
        re.compile(
            r"<h[1-3][^>]*>\s*(?:complete the installation|"
            r"finish installation|installation wizard)",
            re.IGNORECASE,
        ),
    )

    _SENSITIVE_PATH_PATTERNS = (
        (
            "ENV_FILE_EXPOSED",
            re.compile(r"(?:^|/)\.env(?:\.[a-z0-9_-]+)?$", re.IGNORECASE),
            "Fichier d'environnement potentiellement exposé",
        ),
        (
            "GIT_METADATA_EXPOSED",
            re.compile(r"(?:^|/)\.git/(?:config|head|index)$", re.IGNORECASE),
            "Métadonnées Git potentiellement exposées",
        ),
        (
            "BACKUP_FILE_EXPOSED",
            re.compile(
                r"(?:^|/)[^/]+\.(?:bak|backup|old|orig|save|swp)$",
                re.IGNORECASE,
            ),
            "Fichier de sauvegarde potentiellement exposé",
        ),
        (
            "DATABASE_DUMP_EXPOSED",
            re.compile(
                r"(?:^|/)[^/]+\.(?:sql|sqlite|sqlite3|dump)$",
                re.IGNORECASE,
            ),
            "Fichier de base de données potentiellement exposé",
        ),
    )

    @staticmethod
    def _decode_body(body: bytes) -> str:
        if not isinstance(body, bytes):
            return ""
        return body.decode("utf-8", errors="replace")

    @staticmethod
    def _is_success_status(status: int | None) -> bool:
        return status == 200

    def analyze(self, response: HTTPAuditResponse) -> ExposureAnalysis:
        if not isinstance(response, HTTPAuditResponse):
            raise ValueError("Une réponse HTTPAuditResponse est obligatoire.")

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
            findings.append(ExposureFinding(
                code=code,
                category=category,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence[:500],
                recommendation=recommendation,
            ))

        status = response.status
        parsed_url = urlsplit(response.requested_url)
        path = parsed_url.path or "/"

        # Un chemin sensible n'est considéré comme exposé que si
        # la réponse indique que la ressource a été trouvée.
        if self._is_success_status(status):
            for code, pattern, title in self._SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    add(
                        code,
                        "sensitive_resource_exposure",
                        "high",
                        90,
                        title,
                        (
                            "Le chemin de la ressource correspond à un type "
                            "de fichier pouvant contenir des informations "
                            "sensibles. Le contenu n'est pas automatiquement "
                            "considéré comme confidentiel sans vérification."
                        ),
                        f"Chemin HTTP : {path}",
                        (
                            "Vérifier que cette ressource ne doit pas être "
                            "publique et empêcher son accès non autorisé."
                        ),
                    )

        body = response.body
        if not isinstance(body, bytes):
            raise ValueError("Le corps de la réponse doit être de type bytes.")

        analyzed_body = body[:self.MAX_ANALYZED_BODY_BYTES]
        text_body = self._decode_body(analyzed_body)
        body_analyzed = bool(analyzed_body)

        if self._is_success_status(status) and text_body:
            # Indexation de répertoire : plusieurs indices sont exigés
            # pour éviter les détections fondées sur un simple titre.
            has_index_title = bool(re.search(
                r"<title[^>]*>\s*Index of\s+/",
                text_body,
                re.IGNORECASE,
            ))
            has_parent_link = bool(re.search(
                r"<a[^>]+href\s*=\s*['\"]\.\./['\"]",
                text_body,
                re.IGNORECASE,
            ))
            has_directory_table = bool(re.search(
                r"<(?:pre|table)[^>]*>",
                text_body,
                re.IGNORECASE,
            ))

            if has_index_title and (has_parent_link or has_directory_table):
                add(
                    "DIRECTORY_LISTING_ENABLED",
                    "directory_listing",
                    "medium",
                    95,
                    "Indexation de répertoire détectée",
                    (
                        "La réponse ressemble à une page d'indexation "
                        "de répertoire exposant potentiellement les noms "
                        "des fichiers et sous-répertoires."
                    ),
                    "Titre HTML de type « Index of / » et structure de listing détectés",
                    (
                        "Désactiver l'indexation des répertoires lorsque "
                        "l'accès public aux listes de fichiers n'est pas nécessaire."
                    ),
                )

            # Pages par défaut des serveurs web.
            for code, pattern, title in self._DEFAULT_PAGE_PATTERNS:
                match = pattern.search(text_body)
                if match:
                    add(
                        code,
                        "default_page",
                        "informational",
                        95,
                        title,
                        (
                            "La réponse contient une signature reconnue "
                            "d'une page d'accueil par défaut. Cela ne prouve "
                            "pas à lui seul une vulnérabilité."
                        ),
                        match.group(0),
                        (
                            "Remplacer ou retirer la page par défaut si elle "
                            "n'est pas destinée à être publiée."
                        ),
                    )

            # Pages d'installation : signal informatif à confirmer.
            for pattern in self._INSTALLATION_PATTERNS:
                match = pattern.search(text_body)
                if match:
                    add(
                        "INSTALLATION_PAGE_DETECTED",
                        "installation_exposure",
                        "medium",
                        80,
                        "Page d'installation potentiellement accessible",
                        (
                            "Une signature de page d'installation a été "
                            "détectée. Il faut vérifier si l'installation "
                            "est réellement en cours et si des opérations "
                            "sensibles sont accessibles."
                        ),
                        match.group(0),
                        (
                            "Restreindre l'accès à l'assistant d'installation "
                            "et supprimer les interfaces d'installation après "
                            "le déploiement."
                        ),
                    )
                    break

        return ExposureAnalysis(
            analyzed_url=response.requested_url,
            http_status=status,
            findings=tuple(findings),
            body_analyzed=body_analyzed,
            body_bytes_analyzed=len(analyzed_body),
        )
