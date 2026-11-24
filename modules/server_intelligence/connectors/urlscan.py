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


BASE_URL = "https://urlscan.io/api/v1/search/"
USER_AGENT = "ARCHI-MONITOR-Server-Intelligence/1.0"
MAX_RESPONSE_BYTES = 5_000_000
PAGE_SIZE = 100


def _identifier(prefix, value):
    digest = hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()

    return f"{prefix}_{digest[:24]}"


def _parse_date(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, OverflowError):
        return None


def _extract_hostname(value):
    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip()

    try:
        parsed = urllib.parse.urlsplit(candidate)

        if not parsed.hostname:
            parsed = urllib.parse.urlsplit("//" + candidate)

        hostname = parsed.hostname

        if not hostname:
            return None

        return normalize_domain(hostname)

    except (ValueError, UnicodeError):
        return None


def _make_evidence(
    source_id,
    request_url,
    payload,
    page,
    http_status,
    content_type,
):
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=_identifier(
            "urlscan",
            f"{source_id}:{request_url}:{digest}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        safe_headers={
            "Content-Type": content_type or "application/json",
        },
        page_number=page,
        content_type=content_type or "application/json",
        response_sha256=digest,
        metadata={
            "provider": "URLScan.io",
            "endpoint_type": "historical_scan_search",
            "page": page,
        },
    )


def urlscan_connector(domain, definition, source_config):
    normalized_domain = normalize_domain(domain)

    if not normalized_domain:
        raise ConnectorFailure(
            SourceExecutionStatus.ERROR,
            "Domaine cible invalide.",
            error_code="URLSCAN_INVALID_DOMAIN",
        )

    key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "URLSCAN_API_KEY"
    )

    api_key = os.environ.get(key_env)

    source_id = definition.source_id

    evidence_items = []
    observations_by_hostname = {}

    request_count = 0
    processed_count = 0
    total_count = None
    search_date_limit_days = None

    has_next = False
    next_cursor = None
    seen_cursors = set()

    def build_observations():
        result = []

        for hostname, item in observations_by_hostname.items():
            result.append(
                SourceObservation(
                    observation_id=_identifier(
                        "urlscan_host",
                        f"{source_id}:{hostname}",
                    ),
                    value=hostname,
                    observation_type=(
                        "domain" if hostname == normalized_domain
                        else "subdomain"
                    ),
                    source_id=source_id,
                    first_seen=item["first_seen"],
                    last_seen=item["last_seen"],
                    raw_evidence_ids=tuple(
                        sorted(item["evidence_ids"])
                    ),
                    is_wildcard=False,
                    metadata={
                        "provider": "URLScan.io",
                        "discovery_method": "historical_scan_search",
                        "dns_currently_verified": False,
                        "historical_scan_count": item["scan_count"],
                        "observed_urls": sorted(item["urls"]),
                    },
                )
            )

        return tuple(result)

    def current_pagination(
        completed=False,
        interruption_reason=None,
    ):
        return PaginationMetadata(
            pages_requested=request_count,
            pages_received=len(evidence_items),
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

    for page in range(1, source_config.max_pages + 1):
        query_parameters = {
            "q": f"page.domain:{normalized_domain}",
            "size": PAGE_SIZE,
            "datasource": "scans",
        }

        if next_cursor:
            query_parameters["search_after"] = next_cursor

        request_url = (
            BASE_URL
            + "?"
            + urllib.parse.urlencode(query_parameters)
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

        if api_key:
            headers["API-Key"] = api_key

        request = urllib.request.Request(
            request_url,
            headers=headers,
            method="GET",
        )

        try:
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
            error_payload = error.read(
                MAX_RESPONSE_BYTES + 1
            )

            if error_payload:
                evidence_items.append(
                    _make_evidence(
                        source_id,
                        request_url,
                        error_payload[:MAX_RESPONSE_BYTES],
                        page,
                        error.code,
                        error.headers.get("Content-Type", ""),
                    )
                )

            if error.code == 401:
                if api_key:
                    status = SourceExecutionStatus.INVALID_CREDENTIALS
                    code = "URLSCAN_INVALID_API_KEY"
                    message = "Clé API URLScan invalide ou refusée."
                else:
                    status = SourceExecutionStatus.AUTH_REQUIRED
                    code = "URLSCAN_AUTH_REQUIRED"
                    message = "Authentification requise par URLScan."

            elif error.code == 403:
                status = SourceExecutionStatus.PERMISSION_DENIED
                code = "URLSCAN_ACCESS_DENIED"
                message = "Accès URLScan refusé."

            elif error.code == 429:
                status = SourceExecutionStatus.RATE_LIMITED
                code = "URLSCAN_RATE_LIMITED"
                message = "Quota ou limite de requêtes URLScan atteint."

            elif error.code >= 500:
                status = SourceExecutionStatus.UNAVAILABLE
                code = "URLSCAN_PROVIDER_UNAVAILABLE"
                message = "Service URLScan temporairement indisponible."

            else:
                status = SourceExecutionStatus.ERROR
                code = "URLSCAN_HTTP_ERROR"
                message = f"Erreur HTTP URLScan : {error.code}."

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
                f"Erreur réseau URLScan : {type(error).__name__}.",
                "URLSCAN_NETWORK_ERROR",
            )

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse URLScan supérieure à la limite autorisée.",
                "URLSCAN_RESPONSE_TOO_LARGE",
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
            document = json.loads(
                payload.decode("utf-8")
            )

        except (UnicodeDecodeError, json.JSONDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON URLScan invalide.",
                "URLSCAN_INVALID_JSON",
                http_status=http_status,
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Structure de réponse URLScan inattendue.",
                "URLSCAN_INVALID_RESPONSE",
                http_status=http_status,
            )

        records = document.get("results")

        if not isinstance(records, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ results absent ou invalide.",
                "URLSCAN_RESULTS_MISSING",
                http_status=http_status,
            )

        reported_total = document.get("total")

        if (
            isinstance(reported_total, int)
            and not isinstance(reported_total, bool)
            and reported_total >= 0
        ):
            total_count = reported_total

        date_limit = document.get("search_date_limit_days")

        if (
            isinstance(date_limit, int)
            and not isinstance(date_limit, bool)
            and date_limit >= 0
        ):
            search_date_limit_days = date_limit

        provider_has_more = document.get("has_more")

        if not isinstance(provider_has_more, bool):
            provider_has_more = False

        processed_count += len(records)

        for record in records:
            if not isinstance(record, dict):
                continue

            page_data = record.get("page")
            task_data = record.get("task")
            lists_data = record.get("lists")

            if not isinstance(page_data, dict):
                page_data = {}

            if not isinstance(task_data, dict):
                task_data = {}

            if not isinstance(lists_data, dict):
                lists_data = {}

            candidates = set()

            for value in (
                page_data.get("domain"),
                page_data.get("apexDomain"),
                task_data.get("domain"),
                page_data.get("url"),
                task_data.get("url"),
            ):
                hostname = _extract_hostname(value)

                if hostname:
                    candidates.add(hostname)

            listed_domains = lists_data.get("domains")

            if isinstance(listed_domains, list):
                for value in listed_domains:
                    hostname = _extract_hostname(value)

                    if hostname:
                        candidates.add(hostname)

            listed_urls = lists_data.get("urls")

            if isinstance(listed_urls, list):
                for value in listed_urls:
                    hostname = _extract_hostname(value)

                    if hostname:
                        candidates.add(hostname)

            scan_date = _parse_date(
                task_data.get("time")
            )

            for hostname in candidates:
                if not domain_is_in_scope(
                    hostname,
                    normalized_domain,
                ):
                    continue

                item = observations_by_hostname.setdefault(
                    hostname,
                    {
                        "first_seen": None,
                        "last_seen": None,
                        "evidence_ids": set(),
                        "scan_count": 0,
                        "urls": set(),
                    },
                )

                item["evidence_ids"].add(
                    evidence.evidence_id
                )

                item["scan_count"] += 1

                for url_value in (
                    page_data.get("url"),
                    task_data.get("url"),
                ):
                    if (
                        isinstance(url_value, str)
                        and url_value.strip()
                    ):
                        item["urls"].add(url_value.strip())

                if scan_date:
                    if (
                        item["first_seen"] is None
                        or scan_date < item["first_seen"]
                    ):
                        item["first_seen"] = scan_date

                    if (
                        item["last_seen"] is None
                        or scan_date > item["last_seen"]
                    ):
                        item["last_seen"] = scan_date

        if records:
            last_record = records[-1]

            if not isinstance(last_record, dict):
                fail(
                    SourceExecutionStatus.PARTIAL,
                    "Dernier résultat URLScan invalide pour la pagination.",
                    "URLSCAN_INVALID_LAST_RESULT",
                )

            raw_sort = last_record.get("sort")

            if isinstance(raw_sort, (list, tuple)):
                cursor = ",".join(
                    str(value) for value in raw_sort
                )

            elif isinstance(raw_sort, str):
                cursor = raw_sort

            else:
                cursor = None

            if cursor and cursor in seen_cursors:
                fail(
                    SourceExecutionStatus.PARTIAL,
                    "URLScan a renvoyé un curseur de pagination déjà utilisé.",
                    "URLSCAN_REPEATED_CURSOR",
                )

            if cursor:
                seen_cursors.add(cursor)

        else:
            cursor = None

        has_next = (
            provider_has_more
            or len(records) >= PAGE_SIZE
        )

        if not has_next:
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=PaginationMetadata(
                    pages_requested=request_count,
                    pages_received=len(evidence_items),
                    has_next_page=False,
                    next_cursor=None,
                    completed=True,
                ),
                request_count=request_count,
                metadata={
                    "provider": "URLScan.io",
                    "endpoint_type": "historical_scan_search",
                    "records_processed": processed_count,
                    "total_records_reported": total_count,
                    "unique_hosts": len(observations_by_hostname),
                    "search_date_limit_days": search_date_limit_days,
                    "historical_data_only": True,
                    "new_scans_submitted": 0,
                },
            )

        if not cursor:
            fail(
                SourceExecutionStatus.PARTIAL,
                "URLScan indique des résultats supplémentaires sans fournir de curseur exploitable.",
                "URLSCAN_MISSING_PAGINATION_CURSOR",
            )

        next_cursor = cursor

        if not records:
            fail(
                SourceExecutionStatus.PARTIAL,
                "URLScan annonce des résultats supplémentaires mais renvoie une page vide.",
                "URLSCAN_EMPTY_PAGE_WITH_MORE_RESULTS",
            )

    fail(
        SourceExecutionStatus.PARTIAL,
        "Nombre maximal de pages URLScan atteint.",
        "URLSCAN_MAX_PAGES_REACHED",
        pagination=PaginationMetadata(
            pages_requested=request_count,
            pages_received=len(evidence_items),
            has_next_page=has_next,
            next_cursor=next_cursor,
            completed=False,
            interruption_reason="max_pages_reached",
        ),
    )
