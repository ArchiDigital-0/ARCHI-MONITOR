from ..provider_http import provider_urlopen
import hashlib
import json
import os
import threading
import time
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


BASE_URL = "https://www.virustotal.com/api/v3"
USER_AGENT = "ARCHI-MONITOR-Server-Intelligence/1.0"
MAX_RESPONSE_BYTES = 5_000_000
PAGE_SIZE = 40

# API communautaire : maximum de 4 requêtes par minute.
# Le verrou et l'horodatage sont partagés entre les appels du processus.
_MIN_REQUEST_INTERVAL = 15.1
MAX_DAILY_REQUESTS = 500
_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT = None
_REQUESTS_TODAY = 0
_REQUESTS_UTC_DATE = None


def _identifier(prefix, value):
    digest = hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()

    return f"{prefix}_{digest[:24]}"


def _parse_timestamp(value):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        return None

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        )
    except (ValueError, OverflowError, OSError):
        return None


def _pace_request():
    global _LAST_REQUEST_AT
    global _REQUESTS_TODAY
    global _REQUESTS_UTC_DATE

    with _RATE_LOCK:
        today = datetime.now(timezone.utc).date()

        if _REQUESTS_UTC_DATE != today:
            _REQUESTS_TODAY = 0
            _REQUESTS_UTC_DATE = today

        if _REQUESTS_TODAY >= MAX_DAILY_REQUESTS:
            return False

        now = time.monotonic()

        if _LAST_REQUEST_AT is not None:
            elapsed = now - _LAST_REQUEST_AT
            remaining = _MIN_REQUEST_INTERVAL - elapsed

            if remaining > 0:
                time.sleep(remaining)

        _LAST_REQUEST_AT = time.monotonic()
        _REQUESTS_TODAY += 1

        return True


def _make_evidence(
    source_id,
    request_url,
    payload,
    page_number,
    status,
    content_type,
    endpoint_type,
    pagination_cursor=None,
):
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=_identifier(
            "virustotal",
            f"{source_id}:{request_url}:{digest}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=status,
        safe_headers={
            "Content-Type": content_type or "application/json",
        },
        page_number=page_number,
        pagination_cursor=pagination_cursor,
        content_type=content_type or "application/json",
        response_sha256=digest,
        metadata={
            "provider": "VirusTotal",
            "endpoint_type": endpoint_type,
            "page": page_number,
        },
    )


def virustotal_connector(domain, definition, source_config):
    normalized_domain = normalize_domain(domain)

    if not normalized_domain:
        raise ConnectorFailure(
            SourceExecutionStatus.ERROR,
            "Domaine cible invalide.",
            error_code="VIRUSTOTAL_INVALID_DOMAIN",
        )

    key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "VIRUSTOTAL_API_KEY"
    )

    api_key = os.environ.get(key_env)

    if not api_key:
        raise ConnectorFailure(
            SourceExecutionStatus.AUTH_REQUIRED,
            "Clé API VirusTotal absente.",
            error_code="VIRUSTOTAL_AUTH_REQUIRED",
        )

    source_id = definition.source_id

    evidence_items = []
    observations_by_hostname = {}

    request_count = 0
    subdomain_pages_requested = 0
    subdomain_pages_received = 0
    processed_count = 0

    next_cursor = None
    has_next = False
    seen_cursors = set()

    domain_report_metadata = {}

    def build_observations():
        result = []

        for hostname, item in observations_by_hostname.items():
            observation_type = (
                "domain"
                if hostname == normalized_domain
                else "subdomain"
            )

            result.append(
                SourceObservation(
                    observation_id=_identifier(
                        "virustotal_host",
                        f"{source_id}:{hostname}",
                    ),
                    value=hostname,
                    observation_type=observation_type,
                    source_id=source_id,
                    first_seen=item["first_seen"],
                    last_seen=None,
                    raw_evidence_ids=tuple(
                        sorted(item["evidence_ids"])
                    ),
                    is_wildcard=False,
                    is_currently_resolved=None,
                    metadata={
                        "provider": "VirusTotal",
                        "discovery_method": item["discovery_method"],
                        "dns_currently_verified": False,
                        "last_analysis_date": item["last_analysis_date"],
                        "reputation": item["reputation"],
                        "tags": sorted(item["tags"]),
                    },
                )
            )

        return tuple(result)

    def current_pagination(
        completed=False,
        interruption_reason=None,
    ):
        return PaginationMetadata(
            pages_requested=subdomain_pages_requested,
            pages_received=subdomain_pages_received,
            has_next_page=has_next,
            next_cursor=next_cursor,
            completed=completed,
            interruption_reason=interruption_reason,
        )

    def fail(
        status,
        message,
        code,
        http_status=None,
        pagination=None,
    ):
        raise ConnectorFailure(
            status,
            message,
            error_code=code,
            http_status=http_status,
            raw_evidence=tuple(evidence_items),
            observations=build_observations(),
            pagination=pagination or current_pagination(
                completed=False,
                interruption_reason=code,
            ),
            request_count=request_count,
        )

    def request_json(request_url, endpoint_type, page_number, cursor=None):
        nonlocal request_count

        request = urllib.request.Request(
            request_url,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "x-apikey": api_key,
            },
            method="GET",
        )

        try:
            if not _pace_request():
                fail(
                    SourceExecutionStatus.RATE_LIMITED,
                    "Limite quotidienne communautaire VirusTotal atteinte dans ce processus.",
                    "VIRUSTOTAL_DAILY_LIMIT_REACHED",
                )

            request_count += 1

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

        except urllib.error.HTTPError as error:
            status_map = {
                400: (
                    SourceExecutionStatus.ERROR,
                    "VIRUSTOTAL_BAD_REQUEST",
                    "Requête VirusTotal invalide.",
                ),
                401: (
                    SourceExecutionStatus.INVALID_CREDENTIALS,
                    "VIRUSTOTAL_INVALID_API_KEY",
                    "Clé API VirusTotal invalide ou refusée.",
                ),
                403: (
                    SourceExecutionStatus.PERMISSION_DENIED,
                    "VIRUSTOTAL_ACCESS_DENIED",
                    "Accès VirusTotal refusé.",
                ),
                404: (
                    SourceExecutionStatus.UNAVAILABLE,
                    "VIRUSTOTAL_NOT_FOUND",
                    "Ressource VirusTotal introuvable.",
                ),
                429: (
                    SourceExecutionStatus.RATE_LIMITED,
                    "VIRUSTOTAL_RATE_LIMITED",
                    "Quota ou limite de requêtes VirusTotal atteint.",
                ),
            }

            status, code, message = status_map.get(
                error.code,
                (
                    SourceExecutionStatus.UNAVAILABLE
                    if error.code >= 500
                    else SourceExecutionStatus.ERROR,
                    "VIRUSTOTAL_HTTP_ERROR",
                    f"Erreur HTTP VirusTotal : {error.code}.",
                ),
            )

            error_payload = error.read(
                MAX_RESPONSE_BYTES + 1
            )

            if error_payload and len(error_payload) <= MAX_RESPONSE_BYTES:
                evidence_items.append(
                    _make_evidence(
                        source_id,
                        request_url,
                        error_payload,
                        page_number,
                        error.code,
                        error.headers.get("Content-Type", ""),
                        endpoint_type,
                        cursor,
                    )
                )

            fail(
                status,
                message,
                code,
                http_status=error.code,
            )

        except (
            TimeoutError,
            OSError,
            urllib.error.URLError,
        ) as error:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau VirusTotal : {type(error).__name__}.",
                "VIRUSTOTAL_NETWORK_ERROR",
            )

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse VirusTotal supérieure à la limite autorisée.",
                "VIRUSTOTAL_RESPONSE_TOO_LARGE",
                http_status=http_status,
            )

        evidence = _make_evidence(
            source_id,
            request_url,
            payload,
            page_number,
            http_status,
            content_type,
            endpoint_type,
            cursor,
        )

        evidence_items.append(evidence)

        try:
            document = json.loads(payload.decode("utf-8"))

        except (UnicodeDecodeError, json.JSONDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON VirusTotal invalide.",
                "VIRUSTOTAL_INVALID_JSON",
                http_status=http_status,
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Structure de réponse VirusTotal inattendue.",
                "VIRUSTOTAL_INVALID_RESPONSE",
                http_status=http_status,
            )

        return document, evidence

    def add_observation(hostname, evidence, attributes, discovery_method):
        nonlocal processed_count

        try:
            normalized_hostname = normalize_domain(hostname)
        except (TypeError, ValueError):
            return

        if not normalized_hostname:
            return

        if not domain_is_in_scope(
            normalized_hostname,
            normalized_domain,
        ):
            return

        if normalized_hostname.endswith("."):
            return

        if normalized_hostname not in observations_by_hostname:
            observations_by_hostname[normalized_hostname] = {
                "first_seen": None,
                "last_analysis_date": None,
                "evidence_ids": set(),
                "discovery_method": discovery_method,
                "reputation": None,
                "tags": set(),
            }

        item = observations_by_hostname[normalized_hostname]

        item["evidence_ids"].add(evidence.evidence_id)

        first_seen = _parse_timestamp(
            attributes.get("first_seen_date")
        )

        if first_seen:
            if (
                item["first_seen"] is None
                or first_seen < item["first_seen"]
            ):
                item["first_seen"] = first_seen

        last_analysis = _parse_timestamp(
            attributes.get("last_analysis_date")
        )

        if last_analysis:
            item["last_analysis_date"] = last_analysis.isoformat()

        reputation = attributes.get("reputation")

        if (
            isinstance(reputation, int)
            and not isinstance(reputation, bool)
        ):
            item["reputation"] = reputation

        tags = attributes.get("tags")

        if isinstance(tags, list):
            item["tags"].update(
                value.strip()
                for value in tags
                if isinstance(value, str) and value.strip()
            )

        processed_count += 1

    # PHASE 1 : rapport du domaine racine.
    report_url = (
        f"{BASE_URL}/domains/"
        f"{urllib.parse.quote(normalized_domain, safe='')}"
    )

    report_document, report_evidence = request_json(
        report_url,
        "domain_report",
        1,
    )

    report_data = report_document.get("data")

    if not isinstance(report_data, dict):
        fail(
            SourceExecutionStatus.ERROR,
            "Objet data absent du rapport VirusTotal.",
            "VIRUSTOTAL_DOMAIN_REPORT_MISSING",
        )

    if report_data.get("type") != "domain":
        fail(
            SourceExecutionStatus.ERROR,
            "Type d'objet inattendu dans le rapport VirusTotal.",
            "VIRUSTOTAL_DOMAIN_REPORT_TYPE_INVALID",
        )

    report_id = report_data.get("id")

    if (
        not isinstance(report_id, str)
        or normalize_domain(report_id) != normalized_domain
    ):
        fail(
            SourceExecutionStatus.ERROR,
            "Identifiant du domaine incohérent dans le rapport VirusTotal.",
            "VIRUSTOTAL_DOMAIN_REPORT_ID_MISMATCH",
        )

    report_attributes = report_data.get("attributes")

    if not isinstance(report_attributes, dict):
        report_attributes = {}

    domain_report_metadata = {
        "creation_date": report_attributes.get("creation_date"),
        "last_analysis_date": report_attributes.get("last_analysis_date"),
        "last_dns_records_date": report_attributes.get("last_dns_records_date"),
        "reputation": report_attributes.get("reputation"),
    }

    add_observation(
        normalized_domain,
        report_evidence,
        report_attributes,
        "domain_report",
    )

    # PHASE 2 : découverte paginée des sous-domaines directs.
    subdomain_base_url = (
        f"{BASE_URL}/domains/"
        f"{urllib.parse.quote(normalized_domain, safe='')}"
        "/subdomains"
    )

    for page in range(1, source_config.max_pages + 1):
        subdomain_pages_requested += 1
        query = {"limit": PAGE_SIZE}

        if next_cursor:
            query["cursor"] = next_cursor

        request_url = (
            subdomain_base_url
            + "?"
            + urllib.parse.urlencode(query)
        )

        document, evidence = request_json(
            request_url,
            "direct_subdomains",
            page,
            next_cursor,
        )

        subdomain_pages_received += 1

        records = document.get("data")

        if not isinstance(records, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ data absent ou invalide dans la réponse des sous-domaines.",
                "VIRUSTOTAL_SUBDOMAINS_MISSING",
            )

        for record in records:
            if not isinstance(record, dict):
                continue

            if record.get("type") != "domain":
                continue

            hostname = record.get("id")

            if not isinstance(hostname, str):
                continue

            attributes = record.get("attributes")

            if not isinstance(attributes, dict):
                attributes = {}

            add_observation(
                hostname,
                evidence,
                attributes,
                "direct_subdomain_relationship",
            )

        links = document.get("links")
        if not isinstance(links, dict):
            links = {}

        meta = document.get("meta")
        if not isinstance(meta, dict):
            meta = {}

        provider_next = links.get("next")
        provider_cursor = meta.get("cursor")

        has_next = (
            isinstance(provider_next, str)
            and bool(provider_next.strip())
        )

        if not has_next:
            next_cursor = None

            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=PaginationMetadata(
                    pages_requested=subdomain_pages_requested,
                    pages_received=subdomain_pages_received,
                    has_next_page=False,
                    next_cursor=None,
                    completed=True,
                ),
                request_count=request_count,
                metadata={
                    "provider": "VirusTotal",
                    "domain": normalized_domain,
                    "endpoint_types": [
                        "domain_report",
                        "direct_subdomains",
                    ],
                    "subdomain_pages_requested": subdomain_pages_requested,
                    "subdomain_pages_received": subdomain_pages_received,
                    "records_processed": processed_count,
                    "unique_hosts": len(observations_by_hostname),
                    "domain_report": domain_report_metadata,
                    "historical_data_only": True,
                    "dns_currently_verified": False,
                    "new_scans_submitted": 0,
                    "community_api_rate_limit_per_minute": 4,
                    "minimum_request_interval_seconds": _MIN_REQUEST_INTERVAL,
                    "community_api_daily_limit": MAX_DAILY_REQUESTS,
                    "daily_limit_enforcement": "process_memory_only",
                    "daily_limit_resets_at": "UTC midnight",
                },
            )

        if (
            not isinstance(provider_cursor, str)
            or not provider_cursor.strip()
        ):
            fail(
                SourceExecutionStatus.PARTIAL,
                "VirusTotal annonce une page suivante sans curseur exploitable.",
                "VIRUSTOTAL_MISSING_CURSOR",
            )

        if provider_cursor in seen_cursors:
            fail(
                SourceExecutionStatus.PARTIAL,
                "VirusTotal a renvoyé un curseur déjà utilisé.",
                "VIRUSTOTAL_REPEATED_CURSOR",
            )

        seen_cursors.add(provider_cursor)
        next_cursor = provider_cursor

        if page >= source_config.max_pages:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Nombre maximal de pages VirusTotal atteint.",
                "VIRUSTOTAL_MAX_PAGES_REACHED",
                pagination=current_pagination(
                    completed=False,
                    interruption_reason="max_pages_reached",
                ),
            )

    fail(
        SourceExecutionStatus.PARTIAL,
        "Pagination VirusTotal interrompue.",
        "VIRUSTOTAL_PAGINATION_INTERRUPTED",
    )
