"""Génération de rapports pour SERVER INTELLIGENCE.

Ce module transforme les résultats d'audit en rapports JSON et texte.
Il ne réalise aucune connexion réseau et ne lance aucun contrôle.
"""

import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SENSITIVE_KEY = re.compile(
    r"token|secret|password|passwd|authorization|api[_-]?key|"
    r"access[_-]?key|cookie|session|credential",
    re.IGNORECASE,
)

_SENSITIVE_QUERY = re.compile(
    r"token|secret|password|passwd|api[_-]?key|"
    r"access[_-]?key|authorization|session|credential",
    re.IGNORECASE,
)

_BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]+"
)


def _sanitize_string(value: str) -> str:
    """Masque les informations sensibles dans les chaînes."""
    value = _BEARER_PATTERN.sub(r"\1 [REDACTED]", value)

    try:
        parsed = urlsplit(value)

        if parsed.query or (parsed.scheme and parsed.netloc):
            query = [
                (
                    key,
                    "[REDACTED]"
                    if _SENSITIVE_QUERY.search(key)
                    else item,
                )
                for key, item in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            ]

            host = parsed.netloc
            if parsed.scheme and parsed.netloc:
                host = parsed.hostname or ""
                if parsed.port:
                    host = f"{host}:{parsed.port}"
                if parsed.username or parsed.password:
                    host = "[REDACTED]@" + host

            return urlunsplit((
                parsed.scheme,
                host,
                parsed.path,
                urlencode(query),
                "",
            ))
    except (ValueError, TypeError):
        pass

    return value


def _normalize(value: Any, key: str = "") -> Any:
    """Convertit les objets en valeurs JSON sûres."""
    if key and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _sanitize_string(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Enum):
        return _normalize(value.value)

    if isinstance(value, (IPv4Address, IPv6Address)):
        return str(value)

    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))

    if isinstance(value, dict):
        return {
            str(item_key): _normalize(item_value, str(item_key))
            for item_key, item_value in value.items()
        }

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize(item) for item in value]

    if hasattr(value, "__dict__"):
        return _normalize(vars(value))

    return _sanitize_string(str(value))


@dataclass(frozen=True)
class ReportDocument:
    """Rapport d'audit normalisé."""

    schema_version: str
    generated_at: str
    target: str
    risk: dict
    findings: tuple
    redirects: Any
    ip_classifications: Any
    tls: Any
    headers: Any
    exposures: Any
    versions: Any
    limitations: tuple
    metadata: dict


class ReportBuilder:
    """Construit et exporte les rapports d'audit."""

    def build(
        self,
        target: str,
        risk_assessment: Any,
        findings=(),
        redirect_analysis=None,
        ip_classifications=(),
        tls_analysis=None,
        headers_analysis=None,
        exposure_analysis=None,
        version_analysis=None,
        limitations=(),
        metadata=None,
    ) -> ReportDocument:
        """Construit un rapport à partir des résultats disponibles."""

        if not isinstance(target, str) or not target.strip():
            raise ValueError("La cible du rapport est obligatoire.")

        if risk_assessment is None:
            raise ValueError("L'évaluation du risque est obligatoire.")

        risk = _normalize(risk_assessment)
        required_scores = (
            "risk_score",
            "evidence_confidence",
            "analysis_coverage",
        )

        for field in required_scores:
            value = risk.get(field) if isinstance(risk, dict) else None
            if not isinstance(value, int) or not 0 <= value <= 100:
                raise ValueError(
                    f"Indicateur absent ou invalide : {field}"
                )

        normalized_findings = _normalize(tuple(findings or ()))
        normalized_limitations = list(
            _normalize(tuple(limitations or ()))
        )

        if isinstance(risk, dict):
            normalized_limitations.extend(
                risk.get("limitations", [])
            )

        return ReportDocument(
            schema_version="1.0",
            generated_at=datetime.now(timezone.utc).isoformat(),
            target=_sanitize_string(target.strip()),
            risk=risk,
            findings=tuple(normalized_findings),
            redirects=_normalize(redirect_analysis),
            ip_classifications=_normalize(ip_classifications),
            tls=_normalize(tls_analysis),
            headers=_normalize(headers_analysis),
            exposures=_normalize(exposure_analysis),
            versions=_normalize(version_analysis),
            limitations=tuple(dict.fromkeys(normalized_limitations)),
            metadata=_normalize(metadata or {}),
        )

    @staticmethod
    def to_dict(report: ReportDocument) -> dict:
        """Convertit le rapport en dictionnaire JSON-compatible."""
        if not isinstance(report, ReportDocument):
            raise TypeError("Un ReportDocument est requis.")
        return _normalize(report)

    def to_json(self, report: ReportDocument, indent: int = 2) -> str:
        """Produit le rapport au format JSON."""
        if indent < 0 or indent > 8:
            raise ValueError("Indentation JSON invalide.")

        return json.dumps(
            self.to_dict(report),
            ensure_ascii=False,
            indent=indent,
            allow_nan=False,
        )

    def to_text(self, report: ReportDocument) -> str:
        """Produit une synthèse textuelle lisible."""
        data = self.to_dict(report)
        risk = data["risk"]

        lines = [
            "ARCHI MONITOR — SERVER INTELLIGENCE",
            "=" * 42,
            f"Cible : {data['target']}",
            f"Généré le : {data['generated_at']}",
            "",
            "ÉVALUATION",
            f"Risk Score : {risk['risk_score']}/100",
            f"Evidence Confidence : {risk['evidence_confidence']}/100",
            f"Analysis Coverage : {risk['analysis_coverage']}/100",
            f"Niveau de risque : {risk.get('risk_level', 'unknown')}",
            "",
            f"Nombre de constats : {len(data['findings'])}",
            "",
            "CONSTATS",
        ]

        if data["findings"]:
            for index, finding in enumerate(data["findings"], 1):
                if isinstance(finding, dict):
                    code = finding.get("code", "UNKNOWN")
                    severity = finding.get("severity", "unknown")
                    lines.append(
                        f"{index}. {code} — Sévérité : {severity}"
                    )
                    description = finding.get("description")
                    if description:
                        lines.append(f"   {description}")
                else:
                    lines.append(f"{index}. {finding}")
        else:
            lines.append("Aucun constat disponible.")

        lines.extend([
            "",
            "REDIRECTIONS",
            json.dumps(data["redirects"], ensure_ascii=False),
            "",
            "CLASSIFICATIONS IP",
            json.dumps(
                data["ip_classifications"],
                ensure_ascii=False,
            ),
            "",
            "ANALYSES TLS, HEADERS, EXPOSITIONS ET VERSIONS",
        ])

        for label, key in (
            ("TLS", "tls"),
            ("Headers", "headers"),
            ("Expositions", "exposures"),
            ("Versions", "versions"),
        ):
            lines.append(
                f"{label} : "
                + json.dumps(data[key], ensure_ascii=False)
            )

        lines.extend(["", "LIMITATIONS"])
        if data["limitations"]:
            lines.extend(
                f"- {item}" for item in data["limitations"]
            )
        else:
            lines.append("Aucune limitation signalée.")

        return "\n".join(lines) + "\n"
