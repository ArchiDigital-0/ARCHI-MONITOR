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


BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/"
USER_AGENT = "ARCHI-MONITOR-Server-Intelligence/1.0"
MAX_RESPONSE_BYTES = 5_000_000
PAGE_SIZE = 100


def _identifier(prefix, value):
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


def _parse_date(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _make_evidence(source_id, request_url, payload, page, status, content_type):
    collected_at = datetime.now(timezone.utc)

    return RawEvidence(
        evidence_id=_identifier(
            "otx",
            f"{source_id}:{request_url}:{hashlib.sha256(payload).hexdigest()}",
        ),
        source_id=source_id,
        collected_at=collected_at,
        request_url=request_url,
        raw_payload=payload,
        http_status=status,
        safe_headers={
            "Content-Type": content_type or "application/json",
        },
        page_number=page,
        content_type=content_type or "application/json",
        response_sha256=hashlib.sha256(payload).hexdigest(),
        metadata={
            "provider": "AlienVault OTX",
            "endpoint_type": "passive_dns",
            "page": page,
        },
    )


def alienvault_otx_connector(domain, definition, source_config):
    normalized_domain = normalize_domain(domain)

    if not normalized_domain:
        raise ConnectorFailure(
            SourceExecutionStatus.ERROR,
            "Domaine cible invalide.",
            error_code="OTX_INVALID_DOMAIN",
        )

    key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "OTX_API_KEY"
    )
    api_key = os.environ.get(key_env)

    # OTX autorise une tentative anonyme lorsque aucune clé n'est configurée.
    # Le fournisseur reste seul responsable de l'autorisation et des quotas.

    source_id = definition.source_id
    evidence_items = []
    observations_by_hostname = {}
    request_count = 0
    processed_count = 0
    page = 1
    total_count = None
    has_next = False

    def build_observations():
        result = []

        for hostname, item in observations_by_hostname.items():
            result.append(
                SourceObservation(
                    observation_id=_identifier(
                        "otx_host",
                        f"{source_id}:{hostname}",
                    ),
                    value=hostname,
                    observation_type="subdomain",
                    source_id=source_id,
                    first_seen=item["first_seen"],
                    last_seen=item["last_seen"],
                    raw_evidence_ids=tuple(item["evidence_ids"]),
                    is_wildcard=item["is_wildcard"],
                    metadata={
                        "provider": "AlienVault OTX",
                        "discovery_method": "passive_dns",
                        "dns_currently_verified": False,
                        "record_types": sorted(item["record_types"]),
                        "addresses": sorted(item["addresses"]),
                        "asns": sorted(item["asns"]),
                        "historical_dates": sorted(item["dates"]),
                    },
                )
            )

        return tuple(result)

    def fail(status, message, code, http_status=None, pagination=None):
        raise ConnectorFailure(
            status,
            message,
            error_code=code,
            http_status=http_status,
            raw_evidence=tuple(evidence_items),
            observations=build_observations(),
            pagination=pagination or PaginationMetadata(
                pages_requested=request_count,
                pages_received=len(evidence_items),
                has_next_page=has_next,
                completed=False,
                interruption_reason=code,
            ),
            request_count=request_count,
        )

    for page in range(1, source_config.max_pages + 1):
        query = urllib.parse.urlencode({
            "page": page,
            "limit": PAGE_SIZE,
        })

        request_url = (
            f"{BASE_URL}{urllib.parse.quote(normalized_domain, safe='')}"
            f"/passive_dns?{query}"
        )

        request = urllib.request.Request(
            request_url,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                **({"X-OTX-API-KEY": api_key} if api_key else {}),
            },
            method="GET",
        )

        try:
            request_count += 1

            with provider_urlopen(
                request,
                timeout=source_config.timeout_seconds,
            ) as response:
                http_status = response.status
                content_type = response.headers.get("Content-Type", "")
                payload = response.read(MAX_RESPONSE_BYTES + 1)

        except urllib.error.HTTPError as error:
            status_map = {
                401: (
                    SourceExecutionStatus.INVALID_CREDENTIALS,
                    "OTX_INVALID_API_KEY",
                ),
                403: (
                    SourceExecutionStatus.PERMISSION_DENIED,
                    "OTX_ACCESS_DENIED",
                ),
                404: (
                    SourceExecutionStatus.UNAVAILABLE,
                    "OTX_ENDPOINT_NOT_FOUND",
                ),
                429: (
                    SourceExecutionStatus.RATE_LIMITED,
                    "OTX_RATE_LIMITED",
                ),
            }

            status, code = status_map.get(
                error.code,
                (
                    SourceExecutionStatus.UNAVAILABLE
                    if error.code >= 500
                    else SourceExecutionStatus.ERROR,
                    "OTX_HTTP_ERROR",
                ),
            )

            fail(
                status,
                f"Erreur HTTP OTX : {error.code}.",
                code,
                http_status=error.code,
            )

        except (TimeoutError, OSError, urllib.error.URLError) as error:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau OTX : {type(error).__name__}.",
                "OTX_NETWORK_ERROR",
            )

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse OTX supérieure à la limite autorisée.",
                "OTX_RESPONSE_TOO_LARGE",
                http_status=http_status,
            )

        evidence = _make_evidence(
            source_id,
            request_url,
            payload,
            page,
            http_status,
            content_type,
        )
        evidence_items.append(evidence)

        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON OTX invalide.",
                "OTX_INVALID_JSON",
                http_status=http_status,
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Structure de réponse OTX inattendue.",
                "OTX_INVALID_RESPONSE",
                http_status=http_status,
            )

        records = document.get("passive_dns")

        if not isinstance(records, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ passive_dns absent ou invalide.",
                "OTX_PASSIVE_DNS_MISSING",
                http_status=http_status,
            )

        raw_count = document.get("count")
        if isinstance(raw_count, int) and not isinstance(raw_count, bool):
            if raw_count < 0:
                fail(
                    SourceExecutionStatus.ERROR,
                    "Compteur OTX invalide.",
                    "OTX_INVALID_COUNT",
                    http_status=http_status,
                )
            total_count = raw_count

        processed_count += len(records)

        for record in records:
            if not isinstance(record, dict):
                continue

            raw_hostname = record.get("hostname")
            if not isinstance(raw_hostname, str):
                continue

            raw_hostname = raw_hostname.strip().lower()
            is_wildcard = raw_hostname.startswith("*.")

            if is_wildcard:
                raw_hostname = raw_hostname[2:]

            hostname = normalize_domain(raw_hostname)

            if not hostname:
                continue

            if not domain_is_in_scope(hostname, normalized_domain):
                continue

            item = observations_by_hostname.setdefault(
                hostname,
                {
                    "first_seen": None,
                    "last_seen": None,
                    "evidence_ids": set(),
                    "record_types": set(),
                    "addresses": set(),
                    "asns": set(),
                    "dates": set(),
                    "is_wildcard": is_wildcard,
                },
            )

            item["is_wildcard"] = (
                item["is_wildcard"] or is_wildcard
            )
            item["evidence_ids"].add(evidence.evidence_id)

            record_type = record.get("record_type")
            if isinstance(record_type, str) and record_type:
                item["record_types"].add(record_type)

            address = record.get("address")
            if isinstance(address, str) and address:
                item["addresses"].add(address)

            asn = record.get("asn")
            if isinstance(asn, (str, int)) and not isinstance(asn, bool):
                item["asns"].add(str(asn))

            first_seen = _parse_date(record.get("first"))
            last_seen = _parse_date(record.get("last"))

            if first_seen:
                item["dates"].add(first_seen.isoformat())
                if (
                    item["first_seen"] is None
                    or first_seen < item["first_seen"]
                ):
                    item["first_seen"] = first_seen

            if last_seen:
                item["dates"].add(last_seen.isoformat())
                if (
                    item["last_seen"] is None
                    or last_seen > item["last_seen"]
                ):
                    item["last_seen"] = last_seen

        provider_has_next = document.get("has_next")

        if isinstance(provider_has_next, bool):
            has_next = provider_has_next
        elif total_count is not None:
            has_next = processed_count < total_count
        else:
            has_next = len(records) >= PAGE_SIZE

        if not has_next:
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=PaginationMetadata(
                    pages_requested=request_count,
                    pages_received=len(evidence_items),
                    has_next_page=False,
                    completed=True,
                ),
                request_count=request_count,
                metadata={
                    "provider": "AlienVault OTX",
                    "endpoint_type": "passive_dns",
                    "records_processed": processed_count,
                    "total_records_reported": total_count,
                    "unique_hosts": len(observations_by_hostname),
                    "historical_data_only": True,
                },
            )

        if not records:
            fail(
                SourceExecutionStatus.PARTIAL,
                "OTX annonce des résultats supplémentaires mais renvoie une page vide.",
                "OTX_EMPTY_PAGE_WITH_MORE_RESULTS",
            )

    fail(
        SourceExecutionStatus.PARTIAL,
        "Nombre maximal de pages OTX atteint.",
        "OTX_MAX_PAGES_REACHED",
        pagination=PaginationMetadata(
            pages_requested=request_count,
            pages_received=len(evidence_items),
            has_next_page=has_next,
            completed=False,
            interruption_reason="max_pages_reached",
        ),
    )
