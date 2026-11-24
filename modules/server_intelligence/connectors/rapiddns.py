"""Connecteur passif RapidDNS pour SERVER INTELLIGENCE."""

from ..provider_http import provider_urlopen
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timezone

from modules.server_intelligence.config import (
    normalize_domain,
    domain_is_in_scope,
)
from modules.server_intelligence.source_models import (
    RawEvidence,
    SourceObservation,
    PaginationMetadata,
    SourceExecutionStatus,
)
from modules.server_intelligence.source_runner import (
    ConnectorResult,
    ConnectorFailure,
)


BASE_URL = "https://rapiddns.io/api/search/"
USER_AGENT = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"
MAX_RESPONSE_BYTES = 5_000_000
PAGE_SIZE = 100


def _identifier(prefix, value):
    digest = hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _make_evidence(
    source_id,
    request_url,
    payload,
    page_number,
    http_status,
    content_type,
):
    return RawEvidence(
        evidence_id=_identifier(
            "rapiddns",
            f"{request_url}|{hashlib.sha256(payload).hexdigest()}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        safe_headers={
            "content-type": content_type or "",
        },
        page_number=page_number,
        content_type=content_type,
        response_sha256=hashlib.sha256(payload).hexdigest(),
        metadata={
            "provider": "RapidDNS",
            "page_number": page_number,
        },
    )


def rapiddns_connector(domain, definition, source_config):
    """Recherche passive et paginée de noms associés à un domaine."""

    target_domain = normalize_domain(domain)

    key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "RAPIDDNS_API_KEY"
    )
    api_key = os.environ.get(key_env)

    if not api_key:
        raise ConnectorFailure(
            SourceExecutionStatus.AUTH_REQUIRED,
            "Clé API RapidDNS absente.",
            "RAPIDDNS_API_KEY_MISSING",
            request_count=0,
        )

    evidence_items = []
    observed_names = {}

    pages_requested = 0
    pages_received = 0
    processed_count = 0
    total_count = None

    def build_observations():
        collected_at = datetime.now(timezone.utc)
        observations = []

        for hostname, details in sorted(observed_names.items()):
            observations.append(
                SourceObservation(
                    observation_id=_identifier(
                        "rapiddns-observation",
                        hostname,
                    ),
                    value=hostname,
                    observation_type=(
                        "domain"
                        if hostname == target_domain
                        else "subdomain"
                    ),
                    source_id=definition.source_id,
                    collected_at=collected_at,
                    raw_evidence_ids=tuple(
                        sorted(details["evidence_ids"])
                    ),
                    is_wildcard=details["is_wildcard"],
                    metadata={
                        "provider": "RapidDNS",
                        "discovery_method": "historical_dns_index",
                        "dns_currently_verified": False,
                        "record_types": tuple(
                            sorted(details["record_types"])
                        ),
                        "observed_values": tuple(
                            sorted(details["values"])
                        ),
                        "observed_dates": tuple(
                            sorted(details["dates"])
                        ),
                    },
                )
            )

        return tuple(observations)

    def build_pagination(completed, has_next, reason=None):
        return PaginationMetadata(
            pages_requested=pages_requested,
            pages_received=pages_received,
            has_next_page=has_next,
            next_cursor=None,
            completed=completed,
            interruption_reason=reason,
        )

    def fail(
        status,
        message,
        error_code,
        http_status=None,
        reason=None,
    ):
        raise ConnectorFailure(
            status,
            message,
            error_code,
            http_status,
            raw_evidence=tuple(evidence_items),
            observations=build_observations(),
            pagination=build_pagination(
                False,
                total_count is not None
                and processed_count < total_count,
                reason,
            ),
            request_count=pages_requested,
        )

    for page_number in range(1, source_config.max_pages + 1):
        query = urllib.parse.urlencode({
            "search_type": "subdomain",
            "page": page_number,
            "pagesize": PAGE_SIZE,
        })

        request_url = (
            BASE_URL
            + urllib.parse.quote(target_domain, safe="")
            + "?"
            + query
        )

        request = urllib.request.Request(
            request_url,
            headers={
                "X-API-KEY": api_key,
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
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
                content_type = response.headers.get(
                    "Content-Type",
                    "",
                )
                payload = response.read(
                    MAX_RESPONSE_BYTES + 1
                )

        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_RESPONSE_BYTES + 1)
            content_type = exc.headers.get("Content-Type", "")
            http_status = exc.code

            evidence_items.append(
                _make_evidence(
                    definition.source_id,
                    request_url,
                    payload[:MAX_RESPONSE_BYTES],
                    page_number,
                    http_status,
                    content_type,
                )
            )
            pages_received += 1

            if exc.code == 401:
                status = SourceExecutionStatus.INVALID_CREDENTIALS
                code = "RAPIDDNS_INVALID_CREDENTIALS"
            elif exc.code == 403:
                status = SourceExecutionStatus.PERMISSION_DENIED
                code = "RAPIDDNS_ACCESS_DENIED"
            elif exc.code == 429:
                status = SourceExecutionStatus.RATE_LIMITED
                code = "RAPIDDNS_RATE_LIMITED"
            elif exc.code >= 500:
                status = SourceExecutionStatus.UNAVAILABLE
                code = "RAPIDDNS_SERVER_ERROR"
            else:
                status = SourceExecutionStatus.ERROR
                code = "RAPIDDNS_HTTP_ERROR"

            fail(
                status,
                f"RapidDNS a retourné HTTP {exc.code}.",
                code,
                exc.code,
                "http_error",
            )

        except (TimeoutError, OSError, urllib.error.URLError) as exc:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau RapidDNS : {exc}",
                "RAPIDDNS_NETWORK_ERROR",
                reason="network_error",
            )

        evidence_items.append(
            _make_evidence(
                definition.source_id,
                request_url,
                payload[:MAX_RESPONSE_BYTES],
                page_number,
                http_status,
                content_type,
            )
        )
        pages_received += 1

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Réponse RapidDNS supérieure à la taille maximale.",
                "RAPIDDNS_RESPONSE_TOO_LARGE",
                http_status,
                "response_too_large",
            )

        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON RapidDNS invalide.",
                "RAPIDDNS_INVALID_JSON",
                http_status,
                "invalid_json",
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Structure JSON RapidDNS invalide.",
                "RAPIDDNS_INVALID_RESPONSE",
                http_status,
                "invalid_response",
            )

        message = document.get("message")

        if not isinstance(message, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ message absent ou invalide.",
                "RAPIDDNS_INVALID_MESSAGE",
                http_status,
                "invalid_message",
            )

        nested_status = message.get("status")

        if nested_status != "ok":
            fail(
                SourceExecutionStatus.ERROR,
                f"Erreur interne RapidDNS : {nested_status}",
                "RAPIDDNS_PROVIDER_ERROR",
                http_status,
                "provider_error",
            )

        records = message.get("data")
        count = message.get("total")

        if (
            not isinstance(records, list)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            fail(
                SourceExecutionStatus.ERROR,
                "Résultats ou total RapidDNS invalides.",
                "RAPIDDNS_INVALID_RESULTS",
                http_status,
                "invalid_results",
            )

        if total_count is None:
            total_count = count
        elif count != total_count:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Le total RapidDNS a changé pendant la pagination.",
                "RAPIDDNS_INCONSISTENT_TOTAL",
                http_status,
                "inconsistent_total",
            )

        processed_count += len(records)

        for record in records:
            if not isinstance(record, dict):
                continue

            hostname_value = record.get("subdomain")

            if not isinstance(hostname_value, str):
                continue

            hostname_value = hostname_value.strip().lower()
            is_wildcard = hostname_value.startswith("*.")

            if is_wildcard:
                hostname_value = hostname_value[2:]

            try:
                hostname = normalize_domain(hostname_value)
            except ValueError:
                continue

            if not domain_is_in_scope(hostname, target_domain):
                continue

            details = observed_names.setdefault(
                hostname,
                {
                    "evidence_ids": set(),
                    "record_types": set(),
                    "values": set(),
                    "dates": set(),
                    "is_wildcard": False,
                },
            )

            details["evidence_ids"].add(
                evidence_items[-1].evidence_id
            )
            details["is_wildcard"] = (
                details["is_wildcard"] or is_wildcard
            )

            record_type = record.get("type")
            if isinstance(record_type, str) and record_type.strip():
                details["record_types"].add(record_type.strip())

            value = record.get("value")
            if isinstance(value, str) and value.strip():
                details["values"].add(value.strip())

            observed_date = record.get("date")
            if isinstance(observed_date, str) and observed_date.strip():
                details["dates"].add(observed_date.strip())

        if processed_count >= total_count:
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=build_pagination(True, False),
                request_count=pages_requested,
                metadata={
                    "provider": "RapidDNS",
                    "total_results_reported": total_count,
                    "results_processed": processed_count,
                    "unique_names": len(observed_names),
                    "data_type": "historical_dns_discovery",
                    "dns_currently_verified": False,
                    "authentication_used": True,
                },
            )

        if not records:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Page vide avant la fin du total annoncé.",
                "RAPIDDNS_UNEXPECTED_EMPTY_PAGE",
                http_status,
                "unexpected_empty_page",
            )

    raise ConnectorFailure(
        SourceExecutionStatus.PARTIAL,
        "Limite de pagination RapidDNS atteinte.",
        "RAPIDDNS_MAX_PAGES_REACHED",
        raw_evidence=tuple(evidence_items),
        observations=build_observations(),
        pagination=build_pagination(
            False,
            total_count is not None
            and processed_count < total_count,
            "max_pages_reached",
        ),
        request_count=pages_requested,
    )
