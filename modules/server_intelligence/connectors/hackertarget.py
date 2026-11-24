"""Connecteur passif HackerTarget HostSearch."""

from ..provider_http import provider_urlopen
import csv
import hashlib
import ipaddress
import threading
import time
import io
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


BASE_URL = "https://api.hackertarget.com/hostsearch/"
MAX_RESPONSE_BYTES = 5_000_000
USER_AGENT = "ARCHI-MONITOR-SERVER-INTELLIGENCE/1.0"

# Protection locale du quota HackerTarget.
MAX_DAILY_REQUESTS = 50
MIN_REQUEST_INTERVAL = 0.5

_QUOTA_LOCK = threading.Lock()
_REQUESTS_TODAY = 0
_REQUESTS_UTC_DATE = None
_LAST_REQUEST_AT = None
_PROVIDER_DAILY_QUOTA = None
_PROVIDER_DAILY_COUNT = None


def _quota_headers(headers):
    if headers is None:
        return {}

    allowed = {
        "x-api-quota",
        "x-api-count",
        "x-api-boost",
    }

    return {
        name.lower(): value
        for name, value in headers.items()
        if name.lower() in allowed
    }


def _record_quota_headers(headers):
    global _PROVIDER_DAILY_QUOTA, _PROVIDER_DAILY_COUNT

    values = _quota_headers(headers)

    with _QUOTA_LOCK:
        try:
            if "x-api-quota" in values:
                _PROVIDER_DAILY_QUOTA = int(values["x-api-quota"])
        except (TypeError, ValueError):
            pass

        try:
            if "x-api-count" in values:
                count = int(values["x-api-count"])
                _PROVIDER_DAILY_COUNT = max(
                    _PROVIDER_DAILY_COUNT or 0,
                    count,
                )
        except (TypeError, ValueError):
            pass


def _reserve_request_slot():
    global _REQUESTS_TODAY
    global _REQUESTS_UTC_DATE
    global _LAST_REQUEST_AT

    with _QUOTA_LOCK:
        today = datetime.now(timezone.utc).date()

        if _REQUESTS_UTC_DATE != today:
            _REQUESTS_TODAY = 0
            _REQUESTS_UTC_DATE = today
            _LAST_REQUEST_AT = None
            globals()["_PROVIDER_DAILY_QUOTA"] = None
            globals()["_PROVIDER_DAILY_COUNT"] = None

        provider_limit = _PROVIDER_DAILY_QUOTA
        effective_limit = min(
            MAX_DAILY_REQUESTS,
            provider_limit,
        ) if provider_limit is not None else MAX_DAILY_REQUESTS

        provider_count = _PROVIDER_DAILY_COUNT or 0
        effective_count = max(_REQUESTS_TODAY, provider_count)

        if effective_count >= effective_limit:
            raise ConnectorFailure(
                status=SourceExecutionStatus.RATE_LIMITED,
                message="Quota quotidien HackerTarget atteint.",
                error_code="DAILY_QUOTA_EXHAUSTED",
                request_count=0,
            )

        now = time.monotonic()

        if _LAST_REQUEST_AT is not None:
            remaining = MIN_REQUEST_INTERVAL - (
                now - _LAST_REQUEST_AT
            )
            if remaining > 0:
                time.sleep(remaining)

        _LAST_REQUEST_AT = time.monotonic()
        _REQUESTS_TODAY += 1


def _quota_snapshot():
    with _QUOTA_LOCK:
        return {
            "daily_limit_local": MAX_DAILY_REQUESTS,
            "provider_daily_quota": _PROVIDER_DAILY_QUOTA,
            "provider_daily_count": _PROVIDER_DAILY_COUNT,
            "local_requests_today": _REQUESTS_TODAY,
            "counter_scope": "process_memory_only",
            "paid_boost_credits_consumed_automatically": False,
        }


def _identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _classify_ip(value: str) -> dict:
    address = ipaddress.ip_address(value)

    return {
        "ip_version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_unspecified": address.is_unspecified,
        "connection_attempted": False,
    }


def _make_evidence(
    source_id: str,
    request_url: str,
    payload: bytes,
    http_status: int | None,
    safe_headers: dict | None = None,
    metadata: dict | None = None,
) -> RawEvidence:
    digest = hashlib.sha256(payload).hexdigest()

    return RawEvidence(
        evidence_id=f"hackertarget-{digest[:24]}",
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=http_status,
        safe_headers=safe_headers or {},
        content_type="text/plain",
        response_sha256=digest,
        metadata=metadata or {},
    )


def hackertarget_connector(
    domain: str,
    definition,
    source_config: SourceConfig,
) -> ConnectorResult:
    """Recherche les hôtes et adresses IP associés au domaine."""

    normalized_domain = normalize_domain(domain)

    query = urllib.parse.urlencode({"q": normalized_domain})
    request_url = f"{BASE_URL}?{query}"

    request = urllib.request.Request(
        request_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain",
        },
        method="GET",
    )

    _reserve_request_slot()

    try:
        with provider_urlopen(
            request,
            timeout=source_config.timeout_seconds,
        ) as response:
            http_status = response.status
            payload = response.read(MAX_RESPONSE_BYTES + 1)

            safe_headers = {
                name.lower(): value
                for name, value in response.headers.items()
                if name.lower() in {
                    "content-type",
                    "x-api-quota",
                    "x-api-count",
                    "x-api-boost",
                }
            }
            _record_quota_headers(response.headers)

    except urllib.error.HTTPError as exc:
        payload = exc.read(MAX_RESPONSE_BYTES + 1)
        error_truncated = len(payload) > MAX_RESPONSE_BYTES
        safe_headers = _quota_headers(exc.headers)
        _record_quota_headers(exc.headers)
        evidence = _make_evidence(
            definition.source_id,
            request_url,
            payload[:MAX_RESPONSE_BYTES],
            exc.code,
            safe_headers=safe_headers,
            metadata={
                "response_type": "http_error",
                "quota_state": _quota_snapshot(),
                "response_truncated": error_truncated,
                "response_size_limit": MAX_RESPONSE_BYTES if error_truncated else None,
            },
        )

        if exc.code == 429:
            status = SourceExecutionStatus.RATE_LIMITED
        elif exc.code in (401, 403):
            status = SourceExecutionStatus.PERMISSION_DENIED
        elif exc.code >= 500:
            status = SourceExecutionStatus.UNAVAILABLE
        else:
            status = SourceExecutionStatus.ERROR

        raise ConnectorFailure(
            status=status,
            message=f"HackerTarget a retourné HTTP {exc.code}.",
            error_code=f"HTTP_{exc.code}",
            http_status=exc.code,
            raw_evidence=(evidence,),
            request_count=1,
        ) from None

    except (TimeoutError, OSError) as exc:
        raise ConnectorFailure(
            status=SourceExecutionStatus.NETWORK_ERROR,
            message=f"Erreur réseau HackerTarget : {exc}",
            error_code="HACKERTARGET_NETWORK_ERROR",
            request_count=1,
        ) from None

    evidence = _make_evidence(
        definition.source_id,
        request_url,
        payload[:MAX_RESPONSE_BYTES],
        http_status,
        safe_headers=safe_headers,
        metadata={
            "query_domain": normalized_domain,
            "response_truncated": len(payload) > MAX_RESPONSE_BYTES,
            "quota_state": _quota_snapshot(),
        },
    )

    if len(payload) > MAX_RESPONSE_BYTES:
        raise ConnectorFailure(
            status=SourceExecutionStatus.PARTIAL,
            message="Réponse HackerTarget supérieure à la taille maximale.",
            error_code="RESPONSE_SIZE_LIMIT",
            http_status=http_status,
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
        content = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConnectorFailure(
            status=SourceExecutionStatus.ERROR,
            message="Encodage inattendu dans la réponse HackerTarget.",
            error_code="INVALID_RESPONSE_ENCODING",
            http_status=http_status,
            raw_evidence=(evidence,),
            request_count=1,
        ) from None

    lowered = content.strip().lower()

    if any(marker in lowered for marker in (
        "api count exceeded",
        "api count limit",
        "usage limit",
        "rate limit",
        "error:",
    )):
        raise ConnectorFailure(
            status=SourceExecutionStatus.RATE_LIMITED,
            message="HackerTarget a signalé une limite ou une erreur de service.",
            error_code="PROVIDER_LIMIT_OR_ERROR",
            http_status=http_status,
            raw_evidence=(evidence,),
            request_count=1,
        )

    if not content.strip():
        raise ConnectorFailure(
            status=SourceExecutionStatus.EMPTY,
            message="HackerTarget n'a retourné aucun résultat.",
            error_code="EMPTY_RESPONSE",
            http_status=http_status,
            raw_evidence=(evidence,),
            request_count=1,
        )

    observations = []
    seen_hosts = set()
    seen_ips = set()
    valid_rows = 0

    try:
        rows = csv.reader(io.StringIO(content))
        for row in rows:
            if not row or len(row) < 1:
                continue

            raw_host = row[0].strip().lower()
            raw_ip = row[1].strip() if len(row) > 1 else ""

            if not raw_host:
                continue

            try:
                hostname = normalize_domain(raw_host)
            except ValueError:
                continue

            if not domain_is_in_scope(hostname, normalized_domain):
                continue

            valid_rows += 1

            if hostname not in seen_hosts:
                seen_hosts.add(hostname)

                observations.append(
                    SourceObservation(
                        observation_id=_identifier(
                            "ht-host",
                            hostname,
                        ),
                        value=hostname,
                        observation_type=(
                            "domain"
                            if hostname == normalized_domain
                            else "subdomain"
                        ),
                        source_id=definition.source_id,
                        collected_at=datetime.now(timezone.utc),
                        raw_evidence_ids=(evidence.evidence_id,),
                        metadata={
                            "discovery_method": "hackertarget_hostsearch",
                            "dns_currently_verified": False,
                        },
                    )
                )

            if raw_ip:
                try:
                    classification = _classify_ip(raw_ip)
                except ValueError:
                    continue

                identity = f"{hostname}|{raw_ip}"

                if identity in seen_ips:
                    continue

                seen_ips.add(identity)

                observations.append(
                    SourceObservation(
                        observation_id=_identifier(
                            "ht-ip",
                            identity,
                        ),
                        value=raw_ip,
                        observation_type="ip_address",
                        source_id=definition.source_id,
                        collected_at=datetime.now(timezone.utc),
                        raw_evidence_ids=(evidence.evidence_id,),
                        metadata={
                            "associated_hostname": hostname,
                            "discovery_method": "hackertarget_hostsearch",
                            **classification,
                        },
                    )
                )

    except csv.Error:
        raise ConnectorFailure(
            status=SourceExecutionStatus.PARTIAL,
            message="Erreur pendant l'analyse CSV de HackerTarget.",
            error_code="CSV_PARSE_ERROR",
            http_status=http_status,
            raw_evidence=(evidence,),
            request_count=1,
        ) from None

    if valid_rows == 0:
        raise ConnectorFailure(
            status=SourceExecutionStatus.EMPTY,
            message="Aucun hôte valide dans le périmètre autorisé.",
            error_code="NO_IN_SCOPE_HOSTS",
            http_status=http_status,
            raw_evidence=(evidence,),
            request_count=1,
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
            "provider": "HackerTarget",
            "valid_rows": valid_rows,
            "unique_hosts": len(seen_hosts),
            "unique_host_ip_pairs": len(seen_ips),
            "network_connections_to_discovered_ips": 0,
            "quota_state": _quota_snapshot(),
        },
    )
