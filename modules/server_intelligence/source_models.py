"""Modèles de données communs de SERVER INTELLIGENCE."""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SECRET_PATTERN = re.compile(
    r"api[_-]?key|access[_-]?token|token|secret|password|passwd|"
    r"authorization|cookie|session|credential",
    re.IGNORECASE,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_datetime(name: str, value: datetime) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"Date invalide : {name}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"La date doit être horodatée : {name}")


def validate_non_negative_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Valeur invalide : {name}")


def validate_percentage(name: str, value: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= value <= 100
    ):
        raise ValueError(f"Pourcentage invalide : {name}")


def _freeze_and_redact(value: Any) -> Any:
    """Fige récursivement les données et masque les champs sensibles."""

    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Les clés de métadonnées doivent être textuelles.")
            result[key] = (
                "[REDACTED]"
                if _SECRET_PATTERN.search(key)
                else _freeze_and_redact(item)
            )
        return MappingProxyType(result)

    if isinstance(value, (list, tuple)):
        return tuple(_freeze_and_redact(item) for item in value)

    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_and_redact(item) for item in value)

    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value

    raise ValueError(
        f"Type de métadonnée non pris en charge : {type(value).__name__}"
    )


def _sanitize_url(url: str) -> str:
    """Masque les paramètres sensibles et retire les identifiants URL."""

    try:
        parts = urlsplit(url)

        # Élimine les éventuels identifiants placés avant le nom d'hôte.
        netloc = parts.netloc.rsplit("@", 1)[-1]

        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if _SECRET_PATTERN.search(key):
                value = "[REDACTED]"
            query.append((key, value))

        return urlunsplit((
            parts.scheme,
            netloc,
            parts.path,
            urlencode(query),
            "",  # Ne conserve pas un fragment susceptible de contenir un secret.
        ))
    except (ValueError, TypeError):
        raise ValueError("URL de preuve invalide.") from None


class SourceExecutionStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    RATE_LIMITED = "rate_limited"
    AUTH_REQUIRED = "auth_required"
    INVALID_CREDENTIALS = "invalid_credentials"
    PERMISSION_DENIED = "permission_denied"
    UNAVAILABLE = "unavailable"
    NETWORK_ERROR = "network_error"
    EMPTY = "empty"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass(frozen=True)
class SourceObservation:
    """Observation normalisée issue d'une ou plusieurs preuves."""

    observation_id: str
    value: str
    observation_type: str
    source_id: str
    collected_at: datetime = field(default_factory=utc_now)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_evidence_ids: tuple[str, ...] = ()
    is_wildcard: bool = False
    is_currently_resolved: bool | None = None
    resolution_checked_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for name in ("observation_id", "value", "observation_type", "source_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Champ obligatoire invalide : {name}")

        validate_datetime("collected_at", self.collected_at)

        for name in ("first_seen", "last_seen", "resolution_checked_at"):
            value = getattr(self, name)
            if value is not None:
                validate_datetime(name, value)

        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError("La première observation dépasse la dernière.")

        if not isinstance(self.is_wildcard, bool):
            raise ValueError("is_wildcard doit être booléen.")

        if (
            self.is_currently_resolved is not None
            and not isinstance(self.is_currently_resolved, bool)
        ):
            raise ValueError("État de résolution invalide.")

        if (
            self.is_currently_resolved is not None
            and self.resolution_checked_at is None
        ):
            raise ValueError("Date de vérification DNS obligatoire.")

        if not isinstance(self.raw_evidence_ids, tuple):
            raise ValueError("raw_evidence_ids doit être un tuple.")

        if any(
            not isinstance(item, str) or not item.strip()
            for item in self.raw_evidence_ids
        ):
            raise ValueError("Identifiant de preuve invalide.")

        if len(self.raw_evidence_ids) != len(set(self.raw_evidence_ids)):
            raise ValueError("Références de preuves dupliquées.")

        if not isinstance(self.metadata, Mapping):
            raise ValueError("Les métadonnées doivent former un dictionnaire.")

        object.__setattr__(
            self, "metadata", _freeze_and_redact(self.metadata)
        )


@dataclass(frozen=True)
class RawEvidence:
    """Preuve originale reçue d'un fournisseur.

    raw_payload contient les octets exacts de la réponse.
    Les connecteurs doivent éviter d'y inclure des secrets.
    """

    evidence_id: str
    source_id: str
    collected_at: datetime
    request_url: str
    raw_payload: bytes
    http_status: int | None = None
    safe_headers: Mapping[str, str] = field(default_factory=dict)
    page_number: int | None = None
    pagination_cursor: str | None = None
    content_type: str | None = None
    response_sha256: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for name in ("evidence_id", "source_id", "request_url"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Champ obligatoire invalide : {name}")

        validate_datetime("collected_at", self.collected_at)

        if not isinstance(self.raw_payload, bytes):
            raise ValueError("raw_payload doit contenir les octets originaux.")

        calculated_hash = self.calculate_sha256(self.raw_payload)

        if self.response_sha256 is not None:
            if (
                not isinstance(self.response_sha256, str)
                or self.response_sha256.lower() != calculated_hash
            ):
                raise ValueError(
                    "L'empreinte SHA-256 ne correspond pas à la preuve."
                )

        object.__setattr__(self, "response_sha256", calculated_hash)
        object.__setattr__(self, "request_url", _sanitize_url(self.request_url))

        if self.http_status is not None:
            if (
                isinstance(self.http_status, bool)
                or not isinstance(self.http_status, int)
                or not 100 <= self.http_status <= 599
            ):
                raise ValueError("Code HTTP invalide.")

        if self.page_number is not None:
            if (
                isinstance(self.page_number, bool)
                or not isinstance(self.page_number, int)
                or self.page_number < 1
            ):
                raise ValueError("Numéro de page invalide.")

        if (
            self.pagination_cursor is not None
            and not isinstance(self.pagination_cursor, str)
        ):
            raise ValueError("Curseur de pagination invalide.")

        if (
            self.content_type is not None
            and not isinstance(self.content_type, str)
        ):
            raise ValueError("Type de contenu invalide.")

        if not isinstance(self.safe_headers, Mapping):
            raise ValueError("Les en-têtes doivent former un dictionnaire.")

        filtered_headers = {}
        for key, value in self.safe_headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("En-tête HTTP invalide.")
            if not _SECRET_PATTERN.search(key):
                filtered_headers[key] = value

        object.__setattr__(
            self, "safe_headers", MappingProxyType(filtered_headers)
        )

        if not isinstance(self.metadata, Mapping):
            raise ValueError("Les métadonnées doivent former un dictionnaire.")

        object.__setattr__(
            self, "metadata", _freeze_and_redact(self.metadata)
        )

    @staticmethod
    def calculate_sha256(payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise ValueError("La réponse doit être fournie en octets.")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class PaginationMetadata:
    """État de pagination d'une source."""

    pages_requested: int = 0
    pages_received: int = 0
    has_next_page: bool = False
    next_cursor: str | None = None
    completed: bool = False
    interruption_reason: str | None = None

    def __post_init__(self):
        validate_non_negative_integer("pages_requested", self.pages_requested)
        validate_non_negative_integer("pages_received", self.pages_received)

        if self.pages_received > self.pages_requested:
            raise ValueError("Les pages reçues dépassent les pages demandées.")

        if not isinstance(self.has_next_page, bool):
            raise ValueError("has_next_page doit être booléen.")

        if not isinstance(self.completed, bool):
            raise ValueError("completed doit être booléen.")

        if self.completed and self.has_next_page:
            raise ValueError("Pagination terminée avec une page suivante annoncée.")

        if (
            self.next_cursor is not None
            and not isinstance(self.next_cursor, str)
        ):
            raise ValueError("Curseur invalide.")

        if (
            self.interruption_reason is not None
            and not isinstance(self.interruption_reason, str)
        ):
            raise ValueError("Motif d'interruption invalide.")


@dataclass(frozen=True)
class SourceExecution:
    """Résultat d'une exécution individuelle de fournisseur."""

    source_id: str
    status: SourceExecutionStatus
    started_at: datetime
    finished_at: datetime
    raw_record_count: int = 0
    observation_count: int = 0
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    pagination: PaginationMetadata = field(default_factory=PaginationMetadata)
    request_count: int = 0
    rate_limit_remaining: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("Identifiant de source obligatoire.")

        if not isinstance(self.status, SourceExecutionStatus):
            raise ValueError("Statut d'exécution invalide.")

        validate_datetime("started_at", self.started_at)
        validate_datetime("finished_at", self.finished_at)

        if self.finished_at < self.started_at:
            raise ValueError("La fin précède le début de l'exécution.")

        for name in ("raw_record_count", "observation_count", "request_count"):
            validate_non_negative_integer(name, getattr(self, name))

        if self.rate_limit_remaining is not None:
            validate_non_negative_integer(
                "rate_limit_remaining", self.rate_limit_remaining
            )

        if not isinstance(self.pagination, PaginationMetadata):
            raise ValueError("Métadonnées de pagination invalides.")

        if self.http_status is not None:
            if (
                isinstance(self.http_status, bool)
                or not isinstance(self.http_status, int)
                or not 100 <= self.http_status <= 599
            ):
                raise ValueError("Code HTTP invalide.")

        if not isinstance(self.metadata, Mapping):
            raise ValueError("Les métadonnées doivent former un dictionnaire.")

        object.__setattr__(
            self, "metadata", _freeze_and_redact(self.metadata)
        )

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


@dataclass(frozen=True)
class SourceReport:
    """Bilan individuel d'un fournisseur."""

    source_id: str
    execution: SourceExecution
    evidence_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    duplicate_count: int = 0
    exclusive_discovery_count: int = 0
    limitations: tuple[str, ...] = ()
    coverage_percentage: float | None = None

    def __post_init__(self):
        if self.source_id != self.execution.source_id:
            raise ValueError("La source du rapport ne correspond pas à l'exécution.")

        for name in ("duplicate_count", "exclusive_discovery_count"):
            validate_non_negative_integer(name, getattr(self, name))

        if self.coverage_percentage is not None:
            validate_percentage("coverage_percentage", self.coverage_percentage)

        for name in ("evidence_ids", "observation_ids", "limitations"):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                raise ValueError(f"{name} doit être un tuple.")

            if any(
                not isinstance(item, str) or not item.strip()
                for item in value
            ):
                raise ValueError(f"Élément invalide dans {name}.")

            if len(value) != len(set(value)):
                raise ValueError(f"Doublon détecté dans {name}.")


@dataclass(frozen=True)
class DiscoveryReport:
    """Rapport consolidé de découverte multi-sources."""

    report_id: str
    target_domain: str
    created_at: datetime = field(default_factory=utc_now)
    source_reports: tuple[SourceReport, ...] = ()
    raw_evidence: tuple[RawEvidence, ...] = ()
    observations: tuple[SourceObservation, ...] = ()
    limitations: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        for name in ("report_id", "target_domain"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Champ obligatoire invalide : {name}")

        validate_datetime("created_at", self.created_at)

        for name in (
            "source_reports", "raw_evidence", "observations", "limitations"
        ):
            if not isinstance(getattr(self, name), tuple):
                raise ValueError(f"{name} doit être un tuple.")

        evidence_by_id = {
            item.evidence_id: item for item in self.raw_evidence
        }
        observation_by_id = {
            item.observation_id: item for item in self.observations
        }

        if len(evidence_by_id) != len(self.raw_evidence):
            raise ValueError("Identifiants de preuves dupliqués.")

        if len(observation_by_id) != len(self.observations):
            raise ValueError("Identifiants d'observations dupliqués.")

        source_ids = [item.source_id for item in self.source_reports]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Rapports individuels dupliqués pour une source.")

        for observation in self.observations:
            for evidence_id in observation.raw_evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    raise ValueError("Une observation référence une preuve absente.")
                if evidence.source_id != observation.source_id:
                    raise ValueError(
                        "La provenance de la preuve ne correspond pas à l'observation."
                    )

        for source_report in self.source_reports:
            for evidence_id in source_report.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    raise ValueError("Un rapport référence une preuve absente.")
                if evidence.source_id != source_report.source_id:
                    raise ValueError("Une preuve est associée à la mauvaise source.")

            for observation_id in source_report.observation_ids:
                observation = observation_by_id.get(observation_id)
                if observation is None:
                    raise ValueError("Un rapport référence une observation absente.")
                if observation.source_id != source_report.source_id:
                    raise ValueError(
                        "Une observation est associée à la mauvaise source."
                    )

        if not isinstance(self.metadata, Mapping):
            raise ValueError("Les métadonnées doivent former un dictionnaire.")

        object.__setattr__(
            self, "metadata", _freeze_and_redact(self.metadata)
        )

    @property
    def source_count(self) -> int:
        return len(self.source_reports)

    @property
    def raw_evidence_count(self) -> int:
        return len(self.raw_evidence)

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    def execution_summary(self) -> dict[str, int]:
        summary = {status.value: 0 for status in SourceExecutionStatus}
        for report in self.source_reports:
            summary[report.execution.status.value] += 1
        return summary
