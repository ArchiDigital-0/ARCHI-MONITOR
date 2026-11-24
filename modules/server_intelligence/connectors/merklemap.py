"""Connecteur Merklemap pour la découverte passive de sous-domaines."""

from ..provider_http import provider_urlopen
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ..config import SourceConfig, domain_is_in_scope, normalize_domain
from ..source_models import (
    PaginationMetadata,
    RawEvidence,
    SourceExecutionStatus,
    SourceObservation,
)
from ..source_runner import ConnectorFailure, ConnectorResult


BASE_URL = "https://api.merklemap.com/v1/search"
MAX_RESPONSE_BYTES = 5_000_000
USER_AGENT = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"


def _identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _make_evidence(
    source_id,
    request_url,
    payload,
    page_number,
    http_status,
    content_type=None,
    metadata=None,
):
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=_identifier(
            "merklemap-evidence",
            f"{page_number}:{digest}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        content_type=content_type,
        page_number=page_number,
        response_sha256=digest,
        metadata={
            "page_number": page_number,
            **(metadata or {}),
        },
    )


def _build_observations(source_id, target_domain, observed_names):
    observations = []
    collected_at = datetime.now(timezone.utc)

    for hostname, details in sorted(observed_names.items()):
        observations.append(
            SourceObservation(
                observation_id=_identifier(
                    "merklemap-observation",
                    hostname,
                ),
                value=hostname,
                observation_type=(
                    "domain"
                    if hostname == target_domain
                    else "subdomain"
                ),
                source_id=source_id,
                collected_at=collected_at,
                raw_evidence_ids=tuple(
                    sorted(details["evidence_ids"])
                ),
                is_wildcard=details["is_wildcard"],
                metadata={
                    "discovery_method": "internet_asset_discovery",
                    "provider": "merklemap",
                    "dns_currently_verified": False,
                    "certificate_common_names": tuple(
                        sorted(details["common_names"])
                    ),
                    "first_seen_values": tuple(
                        sorted(details["first_seen"])
                    ),
                },
            )
        )

    return tuple(observations)


def merklemap_connector(domain, definition, source_config):
    """Interroge Merklemap avec authentification et pagination bornée."""

    target_domain = normalize_domain(domain)

    api_key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "MERKLEMAP_API_KEY"
    )
    api_key = os.environ.get(api_key_env)

    if not api_key:
        raise ConnectorFailure(
            status=SourceExecutionStatus.AUTH_REQUIRED,
            message=(
                "Clé API Merklemap absente. "
                f"Configurer la variable {api_key_env}."
            ),
            error_code="MERKLEMAP_API_KEY_MISSING",
            pagination=PaginationMetadata(
                pages_requested=0,
                pages_received=0,
                completed=False,
                has_next_page=False,
                interruption_reason="authentication_required",
            ),
            request_count=0,
        )

    evidence_items = []
    observed_names = {}

    pages_requested = 0
    pages_received = 0
    total_count = None
    processed_count = 0

    def build_pagination(completed, has_next, reason=None):
        return PaginationMetadata(
            pages_requested=pages_requested,
            pages_received=pages_received,
            completed=completed,
            has_next_page=has_next,
            interruption_reason=reason,
        )

    def build_observations():
        return _build_observations(
            definition.source_id,
            target_domain,
            observed_names,
        )

    def fail(
        status,
        message,
        error_code,
        http_status=None,
        has_next=False,
        reason=None,
    ):
        raise ConnectorFailure(
            status=status,
            message=message,
            error_code=error_code,
            http_status=http_status,
            raw_evidence=tuple(evidence_items),
            observations=build_observations(),
            pagination=build_pagination(
                False,
                has_next,
                reason,
            ),
            request_count=pages_requested,
        )

    for page_number in range(source_config.max_pages):
        params = {
            "query": f"*.{target_domain}",
            "type": "wildcard",
            "page": page_number,
        }

        request_url = (
            BASE_URL
            + "?"
            + urllib.parse.urlencode(params)
        )

        request = urllib.request.Request(
            request_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="GET",
        )

        pages_requested += 1

        try:
            with provider_urlopen(
                request,
                timeout=source_config.timeout_seconds,
            ) as response:
                http_status = response.status
                content_type = response.headers.get("Content-Type")
                payload = response.read(MAX_RESPONSE_BYTES + 1)

        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_RESPONSE_BYTES + 1)

            evidence_items.append(
                _make_evidence(
                    definition.source_id,
                    request_url,
                    payload[:MAX_RESPONSE_BYTES],
                    page_number,
                    exc.code,
                    metadata={"response_type": "http_error"},
                )
            )
            pages_received += 1

            if exc.code == 401:
                status = SourceExecutionStatus.INVALID_CREDENTIALS
                code = "HTTP_401_INVALID_API_KEY"
            elif exc.code == 403:
                status = SourceExecutionStatus.PERMISSION_DENIED
                code = "HTTP_403_PLAN_OR_ACCESS_REQUIRED"
            elif exc.code == 429:
                status = SourceExecutionStatus.RATE_LIMITED
                code = "HTTP_429_RATE_LIMIT"
            elif exc.code >= 500:
                status = SourceExecutionStatus.UNAVAILABLE
                code = f"HTTP_{exc.code}"
            else:
                status = SourceExecutionStatus.ERROR
                code = f"HTTP_{exc.code}"

            fail(
                status,
                f"Merklemap a retourné HTTP {exc.code}.",
                code,
                exc.code,
                has_next=total_count is not None
                and processed_count < total_count,
                reason="http_error",
            )

        except (TimeoutError, OSError) as exc:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau Merklemap : {exc}",
                "MERKLEMAP_NETWORK_ERROR",
                has_next=total_count is not None
                and processed_count < total_count,
                reason="network_error",
            )

        evidence_items.append(
            _make_evidence(
                definition.source_id,
                request_url,
                payload[:MAX_RESPONSE_BYTES],
                page_number + 1,
                http_status,
                content_type,
                {
                    "query_domain": target_domain,
                    "response_truncated": (
                        len(payload) > MAX_RESPONSE_BYTES
                    ),
                },
            )
        )
        pages_received += 1

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Réponse Merklemap supérieure à la taille maximale.",
                "RESPONSE_SIZE_LIMIT",
                http_status,
                has_next=True,
                reason="response_size_limit",
            )

        try:
            document = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON invalide de Merklemap.",
                "INVALID_JSON",
                http_status,
                has_next=True,
                reason="invalid_json",
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Format Merklemap inattendu : objet JSON attendu.",
                "INVALID_RESPONSE_FORMAT",
                http_status,
                reason="invalid_response_format",
            )

        results = document.get("results")
        count = document.get("count")

        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ count absent ou invalide.",
                "INVALID_RESULT_COUNT",
                http_status,
                reason="invalid_result_count",
            )

        if not isinstance(results, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ results absent ou invalide.",
                "INVALID_RESULTS_FIELD",
                http_status,
                reason="invalid_results",
            )

        if total_count is None:
            total_count = count
        elif count != total_count:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Le nombre total de résultats a changé pendant la pagination.",
                "INCONSISTENT_RESULT_COUNT",
                http_status,
                has_next=True,
                reason="inconsistent_result_count",
            )

        if not results:
            if processed_count < total_count:
                fail(
                    SourceExecutionStatus.PARTIAL,
                    "Page vide avant la fin du nombre annoncé de résultats.",
                    "UNEXPECTED_EMPTY_PAGE",
                    http_status,
                    has_next=True,
                    reason="unexpected_empty_page",
                )

            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=build_pagination(True, False),
                request_count=pages_requested,
                metadata={
                    "provider": "Merklemap",
                    "total_results_reported": total_count,
                    "results_processed": processed_count,
                    "unique_names": len(observed_names),
                    "authentication_used": True,
                    "data_type": "internet_asset_discovery",
                    "dns_currently_verified": False,
                },
            )

        evidence_id = evidence_items[-1].evidence_id

        processed_count += len(results)

        for record in results:
            if not isinstance(record, dict):
                continue

            hostname_value = record.get("hostname")

            if not isinstance(hostname_value, str):
                continue

            hostname_value = hostname_value.strip().lower()
            hostname_is_wildcard = hostname_value.startswith("*.")
            hostname = (
                hostname_value[2:]
                if hostname_is_wildcard
                else hostname_value
            )

            common_name = record.get("subject_common_name")
            common_name = (
                common_name.strip().lower()
                if isinstance(common_name, str)
                else ""
            )

            common_name_is_wildcard = common_name.startswith("*.")
            wildcard = (
                hostname_is_wildcard
                or common_name_is_wildcard
            )

            try:
                hostname = normalize_domain(hostname)
            except ValueError:
                continue

            if not domain_is_in_scope(hostname, target_domain):
                continue

            details = observed_names.setdefault(
                hostname,
                {
                    "evidence_ids": set(),
                    "common_names": set(),
                    "first_seen": set(),
                    "is_wildcard": False,
                },
            )

            details["evidence_ids"].add(evidence_id)
            details["is_wildcard"] = (
                details["is_wildcard"] or wildcard
            )

            if common_name:
                details["common_names"].add(common_name)

            first_seen = record.get("first_seen")

            if isinstance(first_seen, str) and first_seen.strip():
                details["first_seen"].add(first_seen.strip())

        if processed_count >= total_count:
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=build_pagination(True, False),
                request_count=pages_requested,
                metadata={
                    "provider": "Merklemap",
                    "total_results_reported": total_count,
                    "results_processed": processed_count,
                    "unique_names": len(observed_names),
                    "authentication_used": True,
                    "data_type": "internet_asset_discovery",
                    "dns_currently_verified": False,
                },
            )

    return ConnectorResult(
        raw_evidence=tuple(evidence_items),
        observations=build_observations(),
        pagination=build_pagination(
            False,
            True,
            "max_pages_reached",
        ),
        request_count=pages_requested,
        metadata={
            "provider": "Merklemap",
            "total_results_reported": total_count,
            "results_processed": processed_count,
            "unique_names": len(observed_names),
            "authentication_used": True,
            "pagination_limit_reached": True,
            "data_type": "internet_asset_discovery",
            "dns_currently_verified": False,
        },
    )
