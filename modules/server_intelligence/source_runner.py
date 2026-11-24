"""Coordinateur indépendant des fournisseurs de SERVER INTELLIGENCE.

Ce module orchestre les connecteurs sans effectuer lui-même
de requêtes réseau.
"""

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field, replace
import time
from typing import Callable, Mapping

from .config import ServerIntelligenceConfig, SourceConfig
from .source_models import (
    DiscoveryReport,
    PaginationMetadata,
    RawEvidence,
    SourceExecution,
    SourceExecutionStatus,
    SourceObservation,
    SourceReport,
    utc_now,
)
from .sources_registry import SOURCE_REGISTRY, SourceDefinition


@dataclass(frozen=True)
class ConnectorResult:
    """Résultat normalisé retourné par un connecteur."""

    raw_evidence: tuple[RawEvidence, ...] = ()
    observations: tuple[SourceObservation, ...] = ()
    pagination: PaginationMetadata = field(
        default_factory=PaginationMetadata
    )
    request_count: int = 0
    rate_limit_remaining: int | None = None
    metadata: Mapping = field(default_factory=dict)


class ConnectorFailure(Exception):
    """Erreur contrôlée permettant de classifier un échec fournisseur."""

    def __init__(
        self,
        status: SourceExecutionStatus,
        message: str,
        error_code: str | None = None,
        http_status: int | None = None,
        raw_evidence: tuple[RawEvidence, ...] = (),
        observations: tuple[SourceObservation, ...] = (),
        pagination: PaginationMetadata | None = None,
        request_count: int = 0,
        rate_limit_remaining: int | None = None,
    ):
        if not isinstance(status, SourceExecutionStatus):
            raise ValueError("Statut d'erreur de connecteur invalide.")

        self.status = status
        self.message = str(message)
        self.error_code = error_code
        self.http_status = http_status
        self.raw_evidence = tuple(raw_evidence)
        self.observations = tuple(observations)
        self.pagination = pagination or PaginationMetadata()
        self.request_count = request_count
        self.rate_limit_remaining = rate_limit_remaining
        super().__init__(self.message)


Connector = Callable[
    [str, SourceDefinition, SourceConfig],
    ConnectorResult,
]


@dataclass(frozen=True)
class SourceRunResult:
    """Résultat complet d'une tentative d'exécution."""

    source_report: SourceReport
    raw_evidence: tuple[RawEvidence, ...]
    observations: tuple[SourceObservation, ...]


class SourceRunner:
    """Exécute et isole les connecteurs de découverte."""

    def __init__(
        self,
        config: ServerIntelligenceConfig,
        connectors: Mapping[str, Connector],
    ):
        if not isinstance(config, ServerIntelligenceConfig):
            raise ValueError("Configuration SERVER INTELLIGENCE invalide.")

        if not isinstance(connectors, Mapping):
            raise ValueError("Les connecteurs doivent former un dictionnaire.")

        self.config = config
        self.connectors = {}

        for source_id, connector in connectors.items():
            if source_id not in SOURCE_REGISTRY:
                raise ValueError(
                    f"Fournisseur absent du registre : {source_id}"
                )
            if not callable(connector):
                raise ValueError(
                    f"Connecteur non exécutable : {source_id}"
                )
            self.connectors[source_id] = connector

    def _source_config(self, source_id: str) -> SourceConfig:
        return self.config.source_configs.get(
            source_id,
            SourceConfig(),
        )

    def _is_eligible(
        self,
        definition: SourceDefinition,
        source_config: SourceConfig,
        explicitly_configured: bool,
    ) -> bool:
        if not source_config.enabled:
            return False

        # Une authentification inconnue interdit toute exécution.
        if (
            definition.api_key_requirement == "unknown"
            or definition.access_requirement == "verify_access"
        ):
            return False

        # Une source non vérifiée exige une activation explicite.
        if (
            definition.verification_status != "verified"
            and not explicitly_configured
        ):
            return False

        automatic_policies = {
            "automatic_if_policy_allows",
            "automatic_if_anonymous_access_is_permitted",
        }

        if definition.activation_policy in automatic_policies:
            return True

        return explicitly_configured

    def _run_one(
        self,
        source_id: str,
        connector: Connector,
    ) -> SourceRunResult:
        definition = SOURCE_REGISTRY[source_id]
        source_config = self._source_config(source_id)
        started_at = utc_now()

        def build_result(
            status: SourceExecutionStatus,
            evidence: tuple[RawEvidence, ...] = (),
            observations: tuple[SourceObservation, ...] = (),
            pagination: PaginationMetadata | None = None,
            request_count: int = 0,
            rate_limit_remaining: int | None = None,
            error_code: str | None = None,
            error_message: str | None = None,
            http_status: int | None = None,
            metadata: Mapping | None = None,
        ) -> SourceRunResult:
            finished_at = utc_now()

            execution = SourceExecution(
                source_id=source_id,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                raw_record_count=len(evidence),
                observation_count=len(observations),
                http_status=http_status,
                error_code=error_code,
                error_message=error_message,
                pagination=pagination or PaginationMetadata(),
                request_count=request_count,
                rate_limit_remaining=rate_limit_remaining,
                metadata=metadata or {},
            )

            report = SourceReport(
                source_id=source_id,
                execution=execution,
                evidence_ids=tuple(item.evidence_id for item in evidence),
                observation_ids=tuple(
                    item.observation_id for item in observations
                ),
            )

            return SourceRunResult(
                source_report=report,
                raw_evidence=evidence,
                observations=observations,
            )

        if not source_config.enabled:
            return build_result(
                SourceExecutionStatus.DISABLED,
                error_message="Fournisseur désactivé dans la configuration.",
            )

        if definition.api_key_requirement == "required":
            env_name = source_config.api_key_env or definition.api_key_env

            if not env_name:
                return build_result(
                    SourceExecutionStatus.AUTH_REQUIRED,
                    error_message="Variable d'API non configurée.",
                )

            import os

            if not os.environ.get(env_name):
                return build_result(
                    SourceExecutionStatus.AUTH_REQUIRED,
                    error_code="API_KEY_MISSING",
                    error_message=(
                        f"Clé API absente de la variable {env_name}."
                    ),
                )

        try:
            result = connector(
                self.config.target_domain,
                definition,
                source_config,
            )

            if not isinstance(result, ConnectorResult):
                raise TypeError(
                    "Le connecteur doit retourner ConnectorResult."
                )

            if not isinstance(result.raw_evidence, tuple):
                raise TypeError("raw_evidence doit être un tuple.")

            if not isinstance(result.observations, tuple):
                raise TypeError("observations doit être un tuple.")

            for item in result.raw_evidence:
                if not isinstance(item, RawEvidence):
                    raise TypeError("Preuve brute invalide.")
                if item.source_id != source_id:
                    raise ValueError(
                        "Une preuve appartient à un autre fournisseur."
                    )

            for item in result.observations:
                if not isinstance(item, SourceObservation):
                    raise TypeError("Observation invalide.")
                if item.source_id != source_id:
                    raise ValueError(
                        "Une observation appartient à un autre fournisseur."
                    )

            evidence_ids = {
                item.evidence_id for item in result.raw_evidence
            }

            if len(evidence_ids) != len(result.raw_evidence):
                raise ValueError("Identifiants de preuves dupliqués.")

            observation_ids = {
                item.observation_id for item in result.observations
            }

            if len(observation_ids) != len(result.observations):
                raise ValueError("Identifiants d'observations dupliqués.")

            for observation in result.observations:
                if not observation.raw_evidence_ids:
                    raise ValueError(
                        "Une observation ne référence aucune preuve brute."
                    )
                if not set(observation.raw_evidence_ids).issubset(
                    evidence_ids
                ):
                    raise ValueError(
                        "Une observation référence une preuve absente."
                    )

            pagination = result.pagination
            pagination_incomplete = (
                pagination.has_next_page
                or pagination.interruption_reason is not None
                or (
                    pagination.pages_requested > 0
                    and (
                        pagination.pages_received < pagination.pages_requested
                        or not pagination.completed
                    )
                )
            )

            execution_status = (
                SourceExecutionStatus.PARTIAL
                if pagination_incomplete
                else (
                    SourceExecutionStatus.SUCCESS
                    if result.observations or result.raw_evidence
                    else SourceExecutionStatus.EMPTY
                )
            )

            return build_result(
                execution_status,
                evidence=result.raw_evidence,
                observations=result.observations,
                pagination=result.pagination,
                request_count=result.request_count,
                rate_limit_remaining=result.rate_limit_remaining,
                metadata=result.metadata,
            )

        except ConnectorFailure as exc:
            evidence = exc.raw_evidence
            observations = exc.observations

            valid = (
                isinstance(evidence, tuple)
                and isinstance(observations, tuple)
                and all(
                    isinstance(item, RawEvidence)
                    and item.source_id == source_id
                    for item in evidence
                )
                and all(
                    isinstance(item, SourceObservation)
                    and item.source_id == source_id
                    for item in observations
                )
            )

            if valid:
                evidence_ids = [item.evidence_id for item in evidence]
                observation_ids = [
                    item.observation_id for item in observations
                ]

                valid = (
                    len(evidence_ids) == len(set(evidence_ids))
                    and len(observation_ids) == len(set(observation_ids))
                )

            if valid:
                valid_ids = set(evidence_ids)
                valid = all(
                    bool(item.raw_evidence_ids)
                    and set(item.raw_evidence_ids).issubset(valid_ids)
                    for item in observations
                )

            partial_status = exc.status
            partial_error_code = exc.error_code
            partial_error_message = exc.message

            if not valid:
                evidence = ()
                observations = ()
                partial_status = SourceExecutionStatus.ERROR
                partial_error_code = "INVALID_PARTIAL_RESULT"
                partial_error_message = (
                    f"{exc.message} "
                    "Les données partielles ont été rejetées "
                    "car leur traçabilité est invalide."
                )

            return build_result(
                partial_status,
                evidence=evidence,
                observations=observations,
                pagination=exc.pagination,
                request_count=exc.request_count,
                rate_limit_remaining=exc.rate_limit_remaining,
                error_code=partial_error_code,
                error_message=partial_error_message,
                http_status=exc.http_status,
            )

        except TimeoutError as exc:
            return build_result(
                SourceExecutionStatus.NETWORK_ERROR,
                error_code="CONNECTOR_TIMEOUT",
                error_message=str(exc) or "Délai du connecteur dépassé.",
            )

        except ConnectionError as exc:
            return build_result(
                SourceExecutionStatus.NETWORK_ERROR,
                error_code="CONNECTION_ERROR",
                error_message=str(exc),
            )

        except Exception as exc:
            return build_result(
                SourceExecutionStatus.ERROR,
                error_code=type(exc).__name__,
                error_message=str(exc),
            )

    def run(self) -> DiscoveryReport:
        """Exécute les fournisseurs avec échéances individuelles."""

        import os

        if not self.config.passive_discovery_enabled:
            raise ValueError(
                "La découverte passive est désactivée dans la configuration."
            )

        results = {}
        selected = {}
        blocked = {}

        for source_id, connector in self.connectors.items():
            definition = SOURCE_REGISTRY[source_id]
            source_config = self._source_config(source_id)
            explicitly_configured = (
                source_id in self.config.source_configs
            )

            if not source_config.enabled:
                blocked[source_id] = (
                    SourceExecutionStatus.DISABLED,
                    "Fournisseur désactivé.",
                    "SOURCE_DISABLED",
                )
                continue

            if (
                definition.api_key_requirement == "unknown"
                or definition.access_requirement == "verify_access"
            ):
                blocked[source_id] = (
                    SourceExecutionStatus.DISABLED,
                    "Authentification ou conditions d'accès à vérifier.",
                    "SOURCE_REVIEW_REQUIRED",
                )
                continue

            if definition.api_key_requirement == "required":
                env_name = source_config.api_key_env or definition.api_key_env
                if not env_name or not os.environ.get(env_name):
                    blocked[source_id] = (
                        SourceExecutionStatus.AUTH_REQUIRED,
                        "Clé API obligatoire absente.",
                        "API_KEY_MISSING",
                    )
                    continue

            if not self._is_eligible(
                definition,
                source_config,
                explicitly_configured,
            ):
                blocked[source_id] = (
                    SourceExecutionStatus.DISABLED,
                    "Activation manuelle requise ou fournisseur non admissible.",
                    "MANUAL_ACTIVATION_REQUIRED",
                )
                continue

            selected[source_id] = (
                connector,
                source_config.timeout_seconds,
            )

        executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_sources,
            thread_name_prefix="server-intelligence",
        )

        pending = {}
        deadlines = {}

        try:
            for source_id, (connector, timeout_seconds) in selected.items():
                future = executor.submit(
                    self._run_one,
                    source_id,
                    connector,
                )
                pending[future] = source_id
                deadlines[future] = time.monotonic() + timeout_seconds

            while pending:
                remaining = min(
                    deadlines[future] - time.monotonic()
                    for future in pending
                )

                done, _ = wait(
                    tuple(pending),
                    timeout=max(0.0, remaining),
                    return_when=FIRST_COMPLETED,
                )

                # Une tâche déjà terminée est traitée avant le contrôle
                # des échéances, même si les deux événements sont proches.
                for future in done:
                    source_id = pending.pop(future)
                    try:
                        results[source_id] = future.result()
                    except Exception as exc:
                        started_at = utc_now()
                        execution = SourceExecution(
                            source_id=source_id,
                            status=SourceExecutionStatus.ERROR,
                            started_at=started_at,
                            finished_at=utc_now(),
                            error_code=type(exc).__name__,
                            error_message=str(exc),
                        )
                        results[source_id] = SourceRunResult(
                            SourceReport(source_id, execution),
                            (),
                            (),
                        )

                now = time.monotonic()
                expired = [
                    future for future in pending
                    if deadlines[future] <= now
                ]

                for future in expired:
                    source_id = pending.pop(future)
                    future.cancel()

                    started_at = utc_now()
                    execution = SourceExecution(
                        source_id=source_id,
                        status=SourceExecutionStatus.NETWORK_ERROR,
                        started_at=started_at,
                        finished_at=utc_now(),
                        error_code="SOURCE_DEADLINE_EXCEEDED",
                        error_message=(
                            "Échéance du fournisseur dépassée. "
                            "Le connecteur doit appliquer ses propres délais réseau."
                        ),
                    )
                    results[source_id] = SourceRunResult(
                        SourceReport(source_id, execution),
                        (),
                        (),
                    )
        finally:
            # Les tâches déjà démarrées ne peuvent pas être interrompues
            # de force par Future.cancel(). Les connecteurs doivent donc
            # impérativement respecter leurs délais réseau.
            executor.shutdown(wait=False, cancel_futures=True)

        for source_id, (status, message, error_code) in blocked.items():
            started_at = utc_now()
            execution = SourceExecution(
                source_id=source_id,
                status=status,
                started_at=started_at,
                finished_at=utc_now(),
                error_code=error_code,
                error_message=message,
            )
            results[source_id] = SourceRunResult(
                SourceReport(source_id, execution),
                (),
                (),
            )

        ordered_results = tuple(
            results[source_id] for source_id in self.connectors
        )

        all_evidence = tuple(
            evidence
            for item in ordered_results
            for evidence in item.raw_evidence
        )
        all_observations = tuple(
            observation
            for item in ordered_results
            for observation in item.observations
        )

        # Regroupement logique sans supprimer les observations originales.
        asset_groups = {}

        for observation in all_observations:
            normalized_value = observation.value.strip().rstrip(".").casefold()
            key = (
                observation.observation_type,
                normalized_value,
                observation.is_wildcard,
            )

            group = asset_groups.setdefault(
                key,
                {
                    "observation_type": observation.observation_type,
                    "value": normalized_value,
                    "is_wildcard": observation.is_wildcard,
                    "source_ids": set(),
                    "observation_ids": [],
                    "raw_evidence_ids": set(),
                },
            )

            group["source_ids"].add(observation.source_id)
            group["observation_ids"].append(observation.observation_id)
            group["raw_evidence_ids"].update(observation.raw_evidence_ids)

        consolidated_assets = []
        source_statistics = {}

        for source_report in (
            item.source_report for item in ordered_results
        ):
            source_statistics[source_report.source_id] = {
                "duplicates": 0,
                "exclusive": 0,
            }

        for group in asset_groups.values():
            source_ids = sorted(group["source_ids"])

            consolidated_assets.append({
                "observation_type": group["observation_type"],
                "value": group["value"],
                "is_wildcard": group["is_wildcard"],
                "source_ids": tuple(source_ids),
                "source_count": len(source_ids),
                "observation_ids": tuple(group["observation_ids"]),
                "raw_evidence_ids": tuple(
                    sorted(group["raw_evidence_ids"])
                ),
            })

            for source_id in source_ids:
                if len(source_ids) > 1:
                    source_statistics[source_id]["duplicates"] += 1
                else:
                    source_statistics[source_id]["exclusive"] += 1

        consolidated_reports = tuple(
            replace(
                item.source_report,
                duplicate_count=source_statistics[
                    item.source_report.source_id
                ]["duplicates"],
                exclusive_discovery_count=source_statistics[
                    item.source_report.source_id
                ]["exclusive"],
            )
            for item in ordered_results
        )

        return DiscoveryReport(
            report_id=f"discovery-{utc_now().strftime('%Y%m%dT%H%M%S%fZ')}",
            target_domain=self.config.target_domain,
            source_reports=consolidated_reports,
            raw_evidence=all_evidence,
            observations=all_observations,
            limitations=(
                "Les échéances du coordinateur ne remplacent pas les délais réseau des connecteurs.",
                "Un thread déjà démarré ne peut pas être interrompu de force par Future.cancel().",
                "Les connecteurs doivent transmettre leurs preuves partielles avec ConnectorFailure lorsqu'une pagination est interrompue.",
                "Le regroupement logique repose sur le type d'observation, la valeur normalisée et le caractère générique.",
                "Le nombre de sources ayant observé un actif ne constitue pas une preuve de confirmation indépendante.",
                "duplicate_count représente les actifs uniques partagés avec d'autres fournisseurs, et non les répétitions internes d'un fournisseur.",
            ),
            metadata={
                "consolidation": {
                    "unique_asset_count": len(consolidated_assets),
                    "assets": tuple(consolidated_assets),
                    "method": "observation_type+normalized_value+is_wildcard",
                    "duplicate_count_semantics": (
                        "Nombre d'actifs uniques partagés avec au moins "
                        "un autre fournisseur, comptabilisés une fois "
                        "par fournisseur participant."
                    ),
                },
            },
        )
