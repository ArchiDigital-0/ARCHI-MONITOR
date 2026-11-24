"""Connecteur passif crt.sh pour la découverte par transparence des certificats."""

from ..provider_http import provider_urlopen
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ..config import SourceConfig, domain_is_in_scope, normalize_domain
from ..source_models import (
    PaginationMetadata,
    RawEvidence,
    SourceExecutionStatus,
    SourceObservation,
)
from ..source_runner import ConnectorFailure, ConnectorResult


BASE_URL = "https://crt.sh/"
MAX_RESPONSE_BYTES = 5_000_000
USER_AGENT = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"

_RATE_LOCK = threading.Lock()
_LAST_REQUEST_AT = {}
_RETRY_NOT_BEFORE = {}


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None

    try:
        return max(0.0, float(value.strip()))
    except (TypeError, ValueError):
        pass

    try:
        retry_date = parsedate_to_datetime(value)
        if retry_date.tzinfo is None:
            retry_date = retry_date.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_date - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def _set_retry_after(source_id: str, delay_seconds: float | None) -> None:
    if delay_seconds is None:
        return

    with _RATE_LOCK:
        deadline = time.monotonic() + delay_seconds
        _RETRY_NOT_BEFORE[source_id] = max(
            _RETRY_NOT_BEFORE.get(source_id, 0.0),
            deadline,
        )


def _wait_for_rate_slot(source_id: str, requests_per_minute: int | None) -> None:
    if requests_per_minute is not None:
        if (
            isinstance(requests_per_minute, bool)
            or not isinstance(requests_per_minute, int)
            or requests_per_minute <= 0
        ):
            raise ValueError("requests_per_minute doit être un entier positif ou None.")
        interval = 60.0 / requests_per_minute
    else:
        interval = 0.0

    # Le verrou garantit une cadence commune aux appels concurrents.
    with _RATE_LOCK:
        now = time.monotonic()
        retry_deadline = _RETRY_NOT_BEFORE.get(source_id, 0.0)
        last_request = _LAST_REQUEST_AT.get(source_id, 0.0)
        wait_seconds = max(
            0.0,
            retry_deadline - now,
            last_request + interval - now,
        )

        if wait_seconds:
            time.sleep(wait_seconds)

        _RETRY_NOT_BEFORE.pop(source_id, None)
        _LAST_REQUEST_AT[source_id] = time.monotonic()


def _identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _make_evidence(
    source_id: str,
    request_url: str,
    payload: bytes,
    http_status: int | None,
    content_type: str | None = None,
    metadata: dict | None = None,
) -> RawEvidence:
    now = datetime.now(timezone.utc)
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=f"crt-sh-{digest[:24]}",
        source_id=source_id,
        collected_at=now,
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        content_type=content_type,
        response_sha256=digest,
        metadata=metadata or {},
    )


def _extract_names(records: list) -> set[str]:
    names = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        value = record.get("name_value")
        if not isinstance(value, str):
            continue

        for candidate in value.splitlines():
            candidate = candidate.strip().lower()

            if candidate:
                names.add(candidate)

    return names


def crt_sh_connector(
    domain: str,
    definition,
    source_config: SourceConfig,
) -> ConnectorResult:
    """Interroge crt.sh et retourne les noms observés dans les certificats."""

    normalized_domain = normalize_domain(domain)

    query = f"%25.{normalized_domain}"
    request_url = f"{BASE_URL}?q={query}&output=json"

    request = urllib.request.Request(
        request_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
        method="GET",
    )

    _wait_for_rate_slot(
        definition.source_id,
        source_config.requests_per_minute,
    )

    try:
        with provider_urlopen(
            request,
            timeout=source_config.timeout_seconds,
        ) as response:
            status = response.status
            content_type = response.headers.get("Content-Type")
            payload = response.read(MAX_RESPONSE_BYTES + 1)

    except urllib.error.HTTPError as exc:
        error_payload = exc.read(MAX_RESPONSE_BYTES + 1)
        error_truncated = len(error_payload) > MAX_RESPONSE_BYTES
        retry_after_raw = exc.headers.get("Retry-After") if exc.headers else None
        retry_after_seconds = _parse_retry_after(retry_after_raw)

        if exc.code == 429:
            _set_retry_after(definition.source_id, retry_after_seconds)

        evidence = _make_evidence(
            definition.source_id,
            request_url,
            error_payload[:MAX_RESPONSE_BYTES],
            exc.code,
            exc.headers.get("Content-Type") if exc.headers else None,
            {
                "response_type": "http_error",
                "retry_after_raw": retry_after_raw,
                "retry_after_seconds": retry_after_seconds,
                "response_truncated": error_truncated,
                "response_size_limit": MAX_RESPONSE_BYTES if error_truncated else None,
            },
        )

        if exc.code == 429:
            status_type = SourceExecutionStatus.RATE_LIMITED
            error_code = "HTTP_429"
        elif exc.code in (401, 403):
            status_type = SourceExecutionStatus.PERMISSION_DENIED
            error_code = f"HTTP_{exc.code}"
        elif exc.code >= 500:
            status_type = SourceExecutionStatus.UNAVAILABLE
            error_code = f"HTTP_{exc.code}"
        else:
            status_type = SourceExecutionStatus.ERROR
            error_code = f"HTTP_{exc.code}"

        raise ConnectorFailure(
            status=status_type,
            message=f"Réponse HTTP inattendue de crt.sh : {exc.code}",
            error_code=error_code,
            http_status=exc.code,
            raw_evidence=(evidence,),
            request_count=1,
        ) from None

    except (TimeoutError, OSError) as exc:
        raise ConnectorFailure(
            status=SourceExecutionStatus.NETWORK_ERROR,
            message=f"Erreur réseau pendant l'accès à crt.sh : {exc}",
            error_code="CRT_SH_NETWORK_ERROR",
            request_count=1,
        ) from None

    evidence = _make_evidence(
        definition.source_id,
        request_url,
        payload[:MAX_RESPONSE_BYTES],
        status,
        content_type,
        {
            "response_truncated": len(payload) > MAX_RESPONSE_BYTES,
            "query_domain": normalized_domain,
        },
    )

    if len(payload) > MAX_RESPONSE_BYTES:
        raise ConnectorFailure(
            status=SourceExecutionStatus.PARTIAL,
            message="Réponse crt.sh supérieure à la taille maximale autorisée.",
            error_code="RESPONSE_SIZE_LIMIT",
            http_status=status,
            raw_evidence=(evidence,),
            pagination=PaginationMetadata(
                pages_requested=1,
                pages_received=1,
                completed=False,
                interruption_reason="response_size_limit",
            ),
            request_count=1,
        )

    try:
        records = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConnectorFailure(
            status=SourceExecutionStatus.ERROR,
            message="La réponse de crt.sh n'est pas un JSON valide.",
            error_code="INVALID_JSON",
            http_status=status,
            raw_evidence=(evidence,),
            request_count=1,
        ) from None

    if not isinstance(records, list):
        raise ConnectorFailure(
            status=SourceExecutionStatus.ERROR,
            message="Format JSON inattendu : une liste était attendue.",
            error_code="INVALID_RESPONSE_FORMAT",
            http_status=status,
            raw_evidence=(evidence,),
            request_count=1,
        )

    observations = []
    seen = set()
    now = datetime.now(timezone.utc)

    for candidate in sorted(_extract_names(records)):
        is_wildcard = candidate.startswith("*.")
        hostname = candidate[2:] if is_wildcard else candidate

        try:
            hostname = normalize_domain(hostname)
        except ValueError:
            continue

        if not domain_is_in_scope(hostname, normalized_domain):
            continue

        observation_type = (
            "domain" if hostname == normalized_domain else "subdomain"
        )

        identity = f"{hostname}|{is_wildcard}"

        if identity in seen:
            continue

        seen.add(identity)

        observations.append(
            SourceObservation(
                observation_id=_identifier("crt-observation", identity),
                value=hostname,
                observation_type=observation_type,
                source_id=definition.source_id,
                collected_at=now,
                raw_evidence_ids=(evidence.evidence_id,),
                is_wildcard=is_wildcard,
                metadata={
                    "discovery_method": "certificate_transparency",
                    "dns_currently_verified": False,
                },
            )
        )

    return ConnectorResult(
        raw_evidence=(evidence,),
        observations=tuple(observations),
        pagination=PaginationMetadata(
            pages_requested=1,
            pages_received=1,
            completed=True,
        ),
        request_count=1,
        metadata={
            "provider": "crt.sh",
            "records_received": len(records),
            "unique_names_in_scope": len(observations),
            "empty_result": len(records) == 0,
            "retry_after_raw": None,
            "retry_after_seconds": None,
            "rate_limit_state": "process_memory_only",
            "dns_resolution_performed": False,
        },
    )
