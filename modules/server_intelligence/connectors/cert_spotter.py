"""Connecteur Cert Spotter / SSLMate pour la découverte passive CT."""

from ..provider_http import provider_urlopen
import hashlib
import json
import os
import threading
import time
import email.utils
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


BASE_URL = "https://api.certspotter.com/v1/issuances"
MAX_RESPONSE_BYTES = 5_000_000
USER_AGENT = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"

_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT = {}
_RETRY_NOT_BEFORE = {}


def _set_retry_after(source_id: str, delay_seconds: float | None) -> None:
    """Enregistre un blocage fournisseur partagé entre les exécutions."""
    if delay_seconds is None:
        return
    if delay_seconds <= 0:
        return

    with _RATE_LOCK:
        deadline = time.monotonic() + delay_seconds
        previous = _RETRY_NOT_BEFORE.get(source_id, 0.0)
        _RETRY_NOT_BEFORE[source_id] = max(previous, deadline)


def _wait_for_rate_slot(source_id: str, requests_per_minute: int | None) -> None:
    """Applique le débit configuré, de manière synchronisée dans le processus."""
    if requests_per_minute is None:
        return
    if (
        isinstance(requests_per_minute, bool)
        or not isinstance(requests_per_minute, int)
        or requests_per_minute <= 0
    ):
        raise ValueError("requests_per_minute doit être un entier positif.")

    interval = 60.0 / requests_per_minute
    with _RATE_LOCK:
        now = time.monotonic()
        retry_deadline = _RETRY_NOT_BEFORE.get(source_id, 0.0)
        retry_remaining = retry_deadline - now
        if retry_remaining > 0:
            time.sleep(retry_remaining)

        now = time.monotonic()
        _RETRY_NOT_BEFORE.pop(source_id, None)

        previous = _LAST_REQUEST_AT.get(source_id)
        if previous is not None:
            remaining = interval - (now - previous)
            if remaining > 0:
                time.sleep(remaining)

        _LAST_REQUEST_AT[source_id] = time.monotonic()


def _parse_retry_after(value: str | None) -> float | None:
    """Convertit Retry-After en secondes ou en date HTTP."""
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except (TypeError, ValueError):
        try:
            retry_date = email.utils.parsedate_to_datetime(value)
            if retry_date.tzinfo is None:
                retry_date = retry_date.replace(tzinfo=timezone.utc)
            return max(
                0.0,
                (retry_date - datetime.now(timezone.utc)).total_seconds(),
            )
        except (TypeError, ValueError, OverflowError):
            return None


def _identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _make_evidence(
    source_id: str,
    request_url: str,
    payload: bytes,
    page_number: int,
    http_status: int | None,
    content_type: str | None = None,
    metadata: dict | None = None,
) -> RawEvidence:
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=_identifier(
            "certspotter-evidence",
            f"{page_number}:{digest}",
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        content_type=content_type,
        response_sha256=digest,
        metadata={
            "page_number": page_number,
            **(metadata or {}),
        },
    )


def _build_observations(
    source_id: str,
    target_domain: str,
    observed_names: dict,
) -> tuple[SourceObservation, ...]:
    """Construit des observations avec leur provenance exacte."""

    observations = []
    collected_at = datetime.now(timezone.utc)

    for (hostname, is_wildcard), details in sorted(
        observed_names.items()
    ):
        evidence_ids = details["evidence_ids"]

        observations.append(
            SourceObservation(
                observation_id=_identifier(
                    "certspotter-observation",
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
                    "provider": "certspotter",
                    "dns_currently_verified": False,
                },
            )
        )

    return tuple(observations)


def cert_spotter_connector(
    domain: str,
    definition,
    source_config: SourceConfig,
) -> ConnectorResult:
    """Récupère les émissions CT et leurs noms DNS, avec pagination."""

    normalized_domain = normalize_domain(domain)

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
    after = None

    def pagination(
        completed: bool,
        has_next_page: bool,
        reason: str | None = None,
    ) -> PaginationMetadata:
        return PaginationMetadata(
            pages_requested=pages_requested,
            pages_received=pages_received,
            completed=completed,
            has_next_page=has_next_page,
            interruption_reason=reason,
        )

    def partial_observations():
        return _build_observations(
            definition.source_id,
            normalized_domain,
            observed_names,
        )

    def fail(
        status,
        message,
        error_code,
        http_status=None,
        completed=False,
        has_next_page=False,
        reason=None,
    ):
        raise ConnectorFailure(
            status=status,
            message=message,
            error_code=error_code,
            http_status=http_status,
            raw_evidence=tuple(evidence_items),
            observations=partial_observations(),
            pagination=pagination(
                completed,
                has_next_page,
                reason,
            ),
            request_count=pages_requested,
        )

    for page_number in range(1, source_config.max_pages + 1):
        params = [
            ("domain", normalized_domain),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
        ]

        if after is not None:
            params.append(("after", after))

        request_url = f"{BASE_URL}?{urllib.parse.urlencode(params)}"

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

        _wait_for_rate_slot(
            definition.source_id,
            source_config.requests_per_minute,
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
                    metadata={
                        "response_type": "http_error",
                        "retry_after_raw": (
                            exc.headers.get("Retry-After") if exc.headers else None
                        ),
                        "retry_after_seconds": _parse_retry_after(
                            exc.headers.get("Retry-After") if exc.headers else None
                        ),
                    },
                )
            )
            pages_received += 1

            if exc.code == 429:
                retry_value = (
                    exc.headers.get("Retry-After") if exc.headers else None
                )
                _set_retry_after(
                    definition.source_id,
                    _parse_retry_after(retry_value),
                )
                status = SourceExecutionStatus.RATE_LIMITED
                code = "HTTP_429"
            elif exc.code == 401:
                status = SourceExecutionStatus.INVALID_CREDENTIALS
                code = "HTTP_401"
            elif exc.code == 403:
                status = SourceExecutionStatus.PERMISSION_DENIED
                code = "HTTP_403"
            elif exc.code >= 500:
                status = SourceExecutionStatus.UNAVAILABLE
                code = f"HTTP_{exc.code}"
            else:
                status = SourceExecutionStatus.ERROR
                code = f"HTTP_{exc.code}"

            fail(
                status,
                f"Cert Spotter a retourné HTTP {exc.code}.",
                code,
                exc.code,
                has_next_page=bool(observed_names),
                reason="http_error",
            )

        except (TimeoutError, OSError) as exc:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau Cert Spotter : {exc}",
                "CERT_SPOTTER_NETWORK_ERROR",
                has_next_page=bool(observed_names),
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
                {
                    "query_domain": normalized_domain,
                    "response_truncated": (
                        len(payload) > MAX_RESPONSE_BYTES
                    ),
                    "retry_after_raw": response.headers.get("Retry-After"),
                    "retry_after_seconds": _parse_retry_after(
                        response.headers.get("Retry-After")
                    ),
                },
            )
        )
        pages_received += 1

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Réponse Cert Spotter supérieure à la taille maximale.",
                "RESPONSE_SIZE_LIMIT",
                http_status,
                has_next_page=True,
                reason="response_size_limit",
            )

        try:
            records = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON invalide de Cert Spotter.",
                "INVALID_JSON",
                http_status,
                has_next_page=bool(observed_names),
                reason="invalid_json",
            )

        if not isinstance(records, list):
            fail(
                SourceExecutionStatus.ERROR,
                "Format Cert Spotter inattendu : une liste était attendue.",
                "INVALID_RESPONSE_FORMAT",
                http_status,
                has_next_page=bool(observed_names),
                reason="invalid_response_format",
            )

        if not records:
            _set_retry_after(
                definition.source_id,
                _parse_retry_after(response.headers.get("Retry-After")),
            )
            return ConnectorResult(
                raw_evidence=tuple(evidence_items),
                observations=partial_observations(),
                pagination=pagination(True, False),
                request_count=pages_requested,
                metadata={
                    "provider": "Cert Spotter",
                    "pages_processed": pages_received,
                    "unique_names": len(observed_names),
                    "authentication_used": bool(api_key),
                    "retry_after_raw": response.headers.get("Retry-After"),
                    "retry_after_seconds": _parse_retry_after(
                        response.headers.get("Retry-After")
                    ),
                    "retry_after_purpose": "next_poll_after_empty_page",
                },
            )

        for record in records:
            if not isinstance(record, dict):
                continue

            dns_names = record.get("dns_names", [])

            if not isinstance(dns_names, list):
                continue

            for candidate in dns_names:
                if not isinstance(candidate, str):
                    continue

                candidate = candidate.strip().lower()
                is_wildcard = candidate.startswith("*.")
                hostname = candidate[2:] if is_wildcard else candidate

                try:
                    hostname = normalize_domain(hostname)
                except ValueError:
                    continue

                if not domain_is_in_scope(
                    hostname,
                    normalized_domain,
                ):
                    continue

                identity = (hostname, is_wildcard)

                if identity not in observed_names:
                    observed_names[identity] = {
                        "hostname": hostname,
                        "evidence_ids": set(),
                    }

                observed_names[identity]["evidence_ids"].add(
                    evidence_items[-1].evidence_id
                )

        # Le dernier identifiant est nécessaire pour demander la page suivante.
        last_record = records[-1]

        if not isinstance(last_record, dict):
            fail(
                SourceExecutionStatus.PARTIAL,
                "Dernière émission sans identifiant exploitable.",
                "MISSING_PAGINATION_CURSOR",
                http_status,
                has_next_page=True,
                reason="missing_pagination_cursor",
            )

        cursor = last_record.get("id")

        if cursor is None or not str(cursor).strip():
            fail(
                SourceExecutionStatus.PARTIAL,
                "Identifiant de pagination absent dans Cert Spotter.",
                "MISSING_PAGINATION_CURSOR",
                http_status,
                has_next_page=True,
                reason="missing_pagination_cursor",
            )

        cursor = str(cursor)

        if cursor in seen_cursors:
            fail(
                SourceExecutionStatus.PARTIAL,
                "Cert Spotter a renvoyé un curseur déjà rencontré.",
                "REPEATED_PAGINATION_CURSOR",
                http_status,
                has_next_page=True,
                reason="repeated_pagination_cursor",
            )

        seen_cursors.add(cursor)
        after = cursor

    return ConnectorResult(
        raw_evidence=tuple(evidence_items),
        observations=partial_observations(),
        pagination=pagination(
            False,
            True,
            "max_pages_reached",
        ),
        request_count=pages_requested,
        metadata={
            "provider": "Cert Spotter",
            "pages_processed": pages_received,
            "unique_names": len(observed_names),
            "authentication_used": bool(api_key),
            "pagination_limit_reached": True,
        },
    )
