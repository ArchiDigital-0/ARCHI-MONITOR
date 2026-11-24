"""Connecteur CTLogs.dev pour la découverte passive de domaines."""

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


BASE_URL = "https://api.ctlogs.dev/v1/subdomains/"
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
    cursor=None,
    metadata=None,
):
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=_identifier(
            "ctlogs-evidence",
            f"{page_number}:{digest}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        content_type=content_type,
        page_number=page_number,
        pagination_cursor=cursor,
        response_sha256=digest,
        metadata={
            "page_number": page_number,
            **(metadata or {}),
        },
    )


def _build_observations(source_id, target_domain, observed_names):
    observations = []
    collected_at = datetime.now(timezone.utc)

    for (hostname, is_wildcard), evidence_ids in sorted(
        observed_names.items()
    ):
        observations.append(
            SourceObservation(
                observation_id=_identifier(
                    "ctlogs-observation",
                    f"{hostname}|{is_wildcard}",
                ),
                value=hostname,
                observation_type=(
                    "domain"
                    if hostname == target_domain
                    else "subdomain"
                ),
                source_id=source_id,
                collected_at=collected_at,
                raw_evidence_ids=tuple(sorted(evidence_ids)),
                is_wildcard=is_wildcard,
                metadata={
                    "discovery_method": "certificate_transparency",
                    "provider": "ctlogs.dev",
                    "dns_currently_verified": False,
                },
            )
        )

    return tuple(observations)


def ctlogs_dev_connector(domain, definition, source_config):
    """Interroge CTLogs.dev séquentiellement et conserve les preuves."""

    target_domain = normalize_domain(domain)

    api_key_env = (
        source_config.api_key_env
        or definition.api_key_env
    )
    api_key = os.environ.get(api_key_env) if api_key_env else None

    evidence_items = []
    observed_names = {}
    seen_cursors = set()

    pages_requested = 0
    pages_received = 0
    cursor = None
    history_truncated = False

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

    for page_number in range(1, source_config.max_pages + 1):
        encoded_domain = urllib.parse.quote(
            target_domain,
            safe=".-",
        )

        request_url = BASE_URL + encoded_domain

        if cursor is not None:
            request_url += "?" + urllib.parse.urlencode({
                "after": cursor,
            })

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }

        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        request = urllib.request.Request(
            request_url,
            headers=headers,
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
                retry_after = response.headers.get("Retry-After")

        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_RESPONSE_BYTES + 1)

            evidence_items.append(
                _make_evidence(
                    definition.source_id,
                    request_url,
                    payload[:MAX_RESPONSE_BYTES],
                    page_number,
                    exc.code,
                    cursor=cursor,
                    metadata={
                        "response_type": "http_error",
                        "retry_after": exc.headers.get("Retry-After"),
                    },
                )
            )
            pages_received += 1

            if exc.code == 400:
                status = SourceExecutionStatus.ERROR
                code = "HTTP_400_INVALID_REQUEST"
            elif exc.code == 401:
                status = SourceExecutionStatus.INVALID_CREDENTIALS
                code = "HTTP_401_INVALID_API_KEY"
            elif exc.code == 403:
                status = SourceExecutionStatus.PERMISSION_DENIED
                code = "HTTP_403_ACCESS_OR_PLAN_REQUIRED"
            elif exc.code == 404:
                status = SourceExecutionStatus.ERROR
                code = "HTTP_404_ENDPOINT_NOT_FOUND"
            elif exc.code == 422:
                status = SourceExecutionStatus.PARTIAL
                code = "HTTP_422_TOO_MANY_CERTIFICATES"
            elif exc.code == 429:
                status = SourceExecutionStatus.RATE_LIMITED
                code = "HTTP_429_QUOTA_OR_RATE_LIMIT"
            elif exc.code in (500, 503):
                status = SourceExecutionStatus.UNAVAILABLE
                code = f"HTTP_{exc.code}"
            else:
                status = SourceExecutionStatus.ERROR
                code = f"HTTP_{exc.code}"

            fail(
                status,
                f"CTLogs.dev a retourné HTTP {exc.code}.",
                code,
                exc.code,
                has_next=bool(cursor),
                reason="http_error",
            )

        except (TimeoutError, OSError) as exc:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau CTLogs.dev : {exc}",
                "CTLOGS_NETWORK_ERROR",
                has_next=bool(cursor),
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
                cursor,
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
                "Réponse CTLogs.dev supérieure à la taille maximale.",
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
                "Réponse JSON invalide de CTLogs.dev.",
                "INVALID_JSON",
                http_status,
                has_next=bool(cursor),
                reason="invalid_json",
            )

        if not isinstance(document, dict):
            fail(
                SourceExecutionStatus.ERROR,
                "Format CTLogs.dev inattendu : objet JSON attendu.",
                "INVALID_RESPONSE_FORMAT",
                http_status,
                reason="invalid_response_format",
            )

        rows = document.get("rows")

        if not isinstance(rows, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Champ rows absent ou invalide.",
                "INVALID_ROWS_FIELD",
                http_status,
                reason="invalid_rows",
            )

        history_truncated = (
            history_truncated
            or document.get("history_truncated") is True
        )

        current_evidence_id = evidence_items[-1].evidence_id

        for record in rows:
            if not isinstance(record, dict):
                continue

            matches = record.get("matches")

            if not isinstance(matches, list):
                match = record.get("match")
                matches = [match] if isinstance(match, str) else []

            for candidate in matches:
                if not isinstance(candidate, str):
                    continue

                candidate = candidate.strip().lower()
                is_wildcard = candidate.startswith("*.")
                hostname = candidate[2:] if is_wildcard else candidate

                try:
                    hostname = normalize_domain(hostname)
                except ValueError:
                    continue

                if not domain_is_in_scope(hostname, target_domain):
                    continue

                identity = (hostname, is_wildcard)

                observed_names.setdefault(identity, set()).add(
                    current_evidence_id
                )

        has_next = document.get("has_next")

        if not isinstance(has_next, bool):
            fail(
                SourceExecutionStatus.PARTIAL,
                "Indicateur de pagination absent ou invalide.",
                "INVALID_PAGINATION_STATE",
                http_status,
                reason="invalid_pagination_state",
            )

        if not has_next:
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=build_observations(),
                pagination=build_pagination(True, False),
                request_count=pages_requested,
                metadata={
                    "provider": "CTLogs.dev",
                    "pages_processed": pages_received,
                    "unique_names": len(observed_names),
                    "authentication_used": bool(api_key),
                    "history_truncated": history_truncated,
                    "data_type": "certificate_transparency",
                    "dns_currently_verified": False,
                    "commercial_access_policy": (
                        "paid_plan_required_for_commercial_use"
                    ),
                },
            )

        next_cursor = document.get("next_cursor")

        if not isinstance(next_cursor, str) or not next_cursor.strip():
            fail(
                SourceExecutionStatus.PARTIAL,
                "Curseur suivant absent malgré has_next=true.",
                "MISSING_PAGINATION_CURSOR",
                http_status,
                has_next=True,
                reason="missing_pagination_cursor",
            )

        if next_cursor in seen_cursors:
            fail(
                SourceExecutionStatus.PARTIAL,
                "CTLogs.dev a renvoyé un curseur déjà rencontré.",
                "REPEATED_PAGINATION_CURSOR",
                http_status,
                has_next=True,
                reason="repeated_pagination_cursor",
            )

        seen_cursors.add(next_cursor)
        cursor = next_cursor

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
            "provider": "CTLogs.dev",
            "pages_processed": pages_received,
            "unique_names": len(observed_names),
            "authentication_used": bool(api_key),
            "history_truncated": history_truncated,
            "pagination_limit_reached": True,
            "commercial_access_policy": (
                "paid_plan_required_for_commercial_use"
            ),
        },
    )
