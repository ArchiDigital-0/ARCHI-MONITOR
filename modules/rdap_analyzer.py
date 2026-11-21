
import ipaddress
import json
import time
import urllib.request
import urllib.error

from core.results import TestResult, TestStatus


class RDAPAnalyzer:
    """
    Recherche les informations d'attribution
    d'une adresse IP auprès des registres RDAP.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.base_url = "https://rdap.org/ip/"

    def analyze(self, value: str) -> TestResult:

        start = time.perf_counter()

        try:
            address = ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError):
            return TestResult(
                name="rdap",
                status=TestStatus.ERROR,
                summary="Adresse IP invalide.",
                error_code="INVALID_IP_ADDRESS",
            )

        if not address.is_global:
            return TestResult(
                name="rdap",
                status=TestStatus.SKIPPED,
                summary="Recherche RDAP ignorée.",
                details="Cette adresse n'est pas une adresse IP globale.",
                evidence={"address": str(address)},
            )

        url = self.base_url + str(address)

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "ARCHI-MONITOR/1.0",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                data = json.loads(
                    response.read().decode("utf-8")
                )

                duration = round(
                    (time.perf_counter() - start) * 1000,
                    2,
                )

                entities = []

                for entity in data.get("entities", []):
                    entities.append({
                        "handle": entity.get("handle"),
                        "roles": entity.get("roles", []),
                    })

                return TestResult(
                    name="rdap",
                    status=TestStatus.PASSED,
                    summary="Informations RDAP récupérées.",
                    details="Réponse reçue d'un registre RDAP.",
                    duration_ms=duration,
                    evidence={
                        "query_ip": str(address),
                        "source": "rdap.org",
                        "response_url": response.geturl(),
                        "network": {
                            "handle": data.get("handle"),
                            "name": data.get("name"),
                            "type": data.get("type"),
                            "country": data.get("country"),
                            "start_address": data.get("startAddress"),
                            "end_address": data.get("endAddress"),
                            "parent_handle": data.get("parentHandle"),
                            "cidr0_cidrs": data.get("cidr0_cidrs", []),
                        },
                        "entities": entities,
                    },
                    limitations=[
                        "Les informations dépendent du registre interrogé.",
                        "Les données d'attribution ne prouvent pas la joignabilité de l'adresse.",
                        "Le titulaire enregistré n'est pas nécessairement l'utilisateur final de l'adresse.",
                        "RDAP ne garantit pas l'identification de l'ASN d'origine.",
                    ],
                )

        except urllib.error.HTTPError as exc:
            error_code = f"RDAP_HTTP_{exc.code}"
            message = str(exc)

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            error_code = "RDAP_REQUEST_FAILED"
            message = str(exc)

        duration = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        return TestResult(
            name="rdap",
            status=TestStatus.ERROR,
            summary="Impossible de récupérer les informations RDAP.",
            duration_ms=duration,
            error_code=error_code,
            error_message=message,
            evidence={"query_ip": str(address)},
        )
