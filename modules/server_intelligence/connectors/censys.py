"""Connecteur Censys : consultations individuelles compatibles avec le compte Free."""

from ..provider_http import provider_urlopen
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from modules.server_intelligence.config import normalize_domain
from modules.server_intelligence.source_models import (
    PaginationMetadata,
    RawEvidence,
    SourceExecutionStatus,
    SourceObservation,
)
from modules.server_intelligence.source_runner import (
    ConnectorFailure,
    ConnectorResult,
)

BASE_URL = "https://api.platform.censys.io/v3/global/asset/webproperty/"
USER_AGENT = "ARCHI-MONITOR-Server-Intelligence/1.0"
MAX_RESPONSE_BYTES = 5_000_000
LOOKUP_PORTS = (80, 443)


def _identifier(prefix, value):
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


def _make_evidence(source_id, request_url, payload, status, content_type, port):
    digest = hashlib.sha256(payload).hexdigest()
    return RawEvidence(
        evidence_id=_identifier(
            "censys", f"{source_id}:{request_url}:{digest}"
        ),
        source_id=source_id,
        collected_at=datetime.now(timezone.utc),
        request_url=request_url,
        raw_payload=payload,
        http_status=status,
        safe_headers={"Content-Type": content_type or "application/json"},
        content_type=content_type or "application/json",
        response_sha256=digest,
        metadata={
            "provider": "Censys",
            "endpoint_type": "web_property_lookup",
            "port": port,
            "access_tier": "free_lookup",
        },
    )


def _extract_resource(payload):
    if not isinstance(payload, dict):
        return None

    result = payload.get("result")
    if isinstance(result, dict):
        resource = result.get("resource")
        return resource if isinstance(resource, dict) else result

    resource = payload.get("resource")
    return resource if isinstance(resource, dict) else None


def censys_connector(domain, definition, source_config):
    """Consulte le domaine racine sur les propriétés Web des ports 80 et 443."""

    try:
        normalized_domain = normalize_domain(domain)
    except (TypeError, ValueError):
        raise ConnectorFailure(
            SourceExecutionStatus.ERROR,
            "Domaine cible invalide.",
            error_code="CENSYS_INVALID_DOMAIN",
        ) from None

    key_env = (
        source_config.api_key_env
        or definition.api_key_env
        or "CENSYS_API_KEY"
    )
    pat = os.environ.get(key_env)

    if not pat:
        raise ConnectorFailure(
            SourceExecutionStatus.AUTH_REQUIRED,
            f"Jeton Censys absent de la variable {key_env}.",
            error_code="CENSYS_PAT_MISSING",
        )

    source_id = definition.source_id
    evidence_items = []
    observations = []
    request_count = 0
    completed_lookups = 0

    def fail(status, message, code, http_status=None):
        effective_status = (
            SourceExecutionStatus.PARTIAL
            if evidence_items or observations
            else status
        )
        raise ConnectorFailure(
            effective_status,
            message,
            error_code=code,
            http_status=http_status,
            raw_evidence=tuple(evidence_items),
            observations=tuple(observations),
            pagination=PaginationMetadata(
                completed=False,
                interruption_reason=code,
            ),
            request_count=request_count,
        )

    for port in LOOKUP_PORTS:
        asset_id = f"{normalized_domain}:{port}"
        encoded_id = urllib.parse.quote(asset_id, safe=":")
        request_url = BASE_URL + encoded_id

        request = urllib.request.Request(
            request_url,
            headers={
                "Accept": "application/vnd.censys.api.v3.webproperty.v1+json",
                "Authorization": f"Bearer {pat}",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        request_count += 1

        try:
            with provider_urlopen(
                request,
                timeout=source_config.timeout_seconds,
            ) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                http_status = response.status
                content_type = response.headers.get("Content-Type", "")

        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read(MAX_RESPONSE_BYTES + 1)
            except Exception:
                payload = b""

            content_type = (
                exc.headers.get("Content-Type", "")
                if exc.headers else ""
            )

            if len(payload) > MAX_RESPONSE_BYTES:
                fail(
                    SourceExecutionStatus.ERROR,
                    "Réponse Censys trop volumineuse.",
                    "CENSYS_RESPONSE_TOO_LARGE",
                    exc.code,
                )

            if payload:
                evidence_items.append(
                    _make_evidence(
                        source_id, request_url, payload,
                        exc.code, content_type, port,
                    )
                )

            if exc.code == 404:
                completed_lookups += 1
                continue
            if exc.code == 401:
                fail(
                    SourceExecutionStatus.INVALID_CREDENTIALS,
                    "Le jeton personnel Censys a été refusé.",
                    "CENSYS_INVALID_PAT",
                    exc.code,
                )
            if exc.code == 403:
                fail(
                    SourceExecutionStatus.PERMISSION_DENIED,
                    "Le compte Censys ne dispose pas du droit requis.",
                    "CENSYS_PERMISSION_DENIED",
                    exc.code,
                )
            if exc.code == 429:
                fail(
                    SourceExecutionStatus.RATE_LIMITED,
                    "Censys a limité la fréquence des requêtes.",
                    "CENSYS_RATE_LIMITED",
                    exc.code,
                )

            fail(
                SourceExecutionStatus.UNAVAILABLE
                if exc.code >= 500
                else SourceExecutionStatus.ERROR,
                f"Échec HTTP Censys ({exc.code}).",
                "CENSYS_HTTP_ERROR",
                exc.code,
            )

        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            fail(
                SourceExecutionStatus.NETWORK_ERROR,
                f"Erreur réseau Censys : {type(exc).__name__}.",
                "CENSYS_NETWORK_ERROR",
            )

        if len(payload) > MAX_RESPONSE_BYTES:
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse Censys trop volumineuse.",
                "CENSYS_RESPONSE_TOO_LARGE",
                http_status,
            )

        evidence = _make_evidence(
            source_id, request_url, payload,
            http_status, content_type, port,
        )
        evidence_items.append(evidence)

        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail(
                SourceExecutionStatus.ERROR,
                "Réponse JSON Censys invalide.",
                "CENSYS_INVALID_JSON",
                http_status,
            )

        resource = _extract_resource(decoded)
        if resource is None:
            fail(
                SourceExecutionStatus.ERROR,
                "La réponse Censys ne contient aucune ressource exploitable.",
                "CENSYS_RESOURCE_MISSING",
                http_status,
            )

        observations.append(
            SourceObservation(
                observation_id=_identifier(
                    "censys_webproperty",
                    f"{source_id}:{asset_id}",
                ),
                value=asset_id,
                observation_type="web_property",
                source_id=source_id,
                raw_evidence_ids=(evidence.evidence_id,),
                metadata={
                    "provider": "Censys",
                    "discovery_method": "targeted_web_property_lookup",
                    "hostname": normalized_domain,
                    "port": port,
                    "dns_currently_verified": False,
                    "is_subdomain_discovery": False,
                    "access_tier": "free_lookup",
                },
            )
        )
        completed_lookups += 1

    if not observations:
        raise ConnectorFailure(
            SourceExecutionStatus.EMPTY,
            "Aucune propriété Web trouvée sur les ports consultés.",
            error_code="CENSYS_NO_WEB_PROPERTIES",
            raw_evidence=tuple(evidence_items),
            pagination=PaginationMetadata(completed=True),
            request_count=request_count,
        )

    return ConnectorResult(
        raw_evidence=tuple(evidence_items),
        observations=tuple(observations),
        pagination=PaginationMetadata(completed=True),
        request_count=request_count,
        metadata={
            "provider": "Censys",
            "access_tier": "free_lookup",
            "lookup_type": "web_property_only",
            "lookup_ports": list(LOOKUP_PORTS),
            "completed_lookups": completed_lookups,
            "global_search_used": False,
            "subdomain_discovery_performed": False,
            "ip_resolution_performed": False,
            "estimated_credit_cost": request_count,
            "usage_restriction": (
                "Respecter les conditions Censys du compte gratuit, "
                "notamment les restrictions non commerciales et l'attribution."
            ),
        },
    )
