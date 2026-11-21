import ipaddress
import json
import time
import urllib.request
import urllib.error
from urllib.parse import urlencode

from core.results import TestResult, TestStatus


class ASNAnalyzer:
    """
    Recherche les ASN et le préfixe BGP associés à une IP
    à partir de l'API publique RIPEstat.
    """

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.base_url = (
            "https://stat.ripe.net/data/network-info/data.json"
        )

    def analyze(self, value: str) -> TestResult:

        start = time.perf_counter()

        try:
            address = ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError):
            return TestResult(
                name="asn",
                status=TestStatus.ERROR,
                summary="Adresse IP invalide.",
                error_code="INVALID_IP_ADDRESS",
            )

        if not address.is_global:
            return TestResult(
                name="asn",
                status=TestStatus.SKIPPED,
                summary="Recherche ASN ignorée.",
                details="Cette adresse n'est pas une IP globale.",
                evidence={"query_ip": str(address)},
            )

        params = urlencode({
            "resource": str(address),
            "sourceapp": "ARCHI-MONITOR",
        })

        url = f"{self.base_url}?{params}"

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ARCHI-MONITOR/1.0",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                raw_data = response.read(1_000_001)

                if len(raw_data) > 1_000_000:
                    raise ValueError(
                        "Réponse RIPEstat trop volumineuse."
                    )

                payload = json.loads(
                    raw_data.decode("utf-8")
                )

            duration = round(
                (time.perf_counter() - start) * 1000, 2
            )

            if payload.get("status") != "ok":
                return TestResult(
                    name="asn",
                    status=TestStatus.WARNING,
                    summary="RIPEstat n'a pas confirmé la requête.",
                    duration_ms=duration,
                    error_code="RIPESTAT_QUERY_NOT_OK",
                    evidence={
                        "query_ip": str(address),
                        "api_status": payload.get("status"),
                        "status_code": payload.get("status_code"),
                        "messages": payload.get("messages", []),
                    },
                )

            data = payload.get("data", {})

            asns = data.get("asns", [])
            prefix = data.get("prefix")

            if not isinstance(asns, list):
                asns = []

            asns = [
                str(asn)
                for asn in asns
                if str(asn).isdigit()
            ]

            if not prefix or not asns:
                return TestResult(
                    name="asn",
                    status=TestStatus.WARNING,
                    summary="Aucune annonce ASN exploitable trouvée.",
                    duration_ms=duration,
                    evidence={
                        "query_ip": str(address),
                        "prefix": prefix,
                        "origin_asns": asns,
                        "source": "RIPEstat",
                    },
                    limitations=[
                        "L'absence de résultat ne prouve pas que l'IP est inactive.",
                        "Les données dépendent de la visibilité du routage dans RIPE RIS.",
                    ],
                )

            return TestResult(
                name="asn",
                status=TestStatus.PASSED,
                summary="Informations de routage ASN récupérées.",
                details="Préfixe réseau et ASN annoncés identifiés.",
                duration_ms=duration,
                evidence={
                    "query_ip": str(address),
                    "prefix": prefix,
                    "origin_asns": asns,
                    "source": "RIPEstat",
                    "query_id": payload.get("query_id"),
                    "api_time": payload.get("time"),
                    "api_version": payload.get("version"),
                },
                limitations=[
                    "Les données proviennent de RIPE RIS et ne représentent pas nécessairement le routage en temps réel.",
                    "Plusieurs ASN peuvent annoncer le même préfixe.",
                    "Un ASN annoncé ne prouve pas à lui seul la propriété de l'adresse IP.",
                    "Une annonce BGP ne prouve pas que le service est joignable.",
                ],
            )

        except urllib.error.HTTPError as exc:
            error_code = f"RIPESTAT_HTTP_{exc.code}"
            message = str(exc)

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            error_code = "RIPESTAT_REQUEST_FAILED"
            message = str(exc)

        duration = round(
            (time.perf_counter() - start) * 1000, 2
        )

        return TestResult(
            name="asn",
            status=TestStatus.ERROR,
            summary="Impossible de récupérer les informations ASN.",
            duration_ms=duration,
            error_code=error_code,
            error_message=message,
            evidence={"query_ip": str(address)},
        )