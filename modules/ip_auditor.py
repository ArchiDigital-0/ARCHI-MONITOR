
import ipaddress
import time

from core.results import TestResult, TestStatus


class IPAuditor:
    """
    Analyse et classifie les adresses IPv4 et IPv6.
    """

    def analyze(self, addresses: list[str]) -> TestResult:

        start = time.perf_counter()

        if not addresses:
            return TestResult(
                name="ip",
                status=TestStatus.WARNING,
                summary="Aucune adresse IP à analyser.",
                duration_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                limitations=[
                    "L'analyse IP nécessite des adresses préalablement obtenues."
                ],
            )

        analyzed = []
        invalid = []
        duplicates = []
        seen = set()

        for value in addresses:

            if not isinstance(value, str):
                invalid.append(str(value))
                continue

            try:
                address = ipaddress.ip_address(value.strip())
                normalized = str(address)

                if normalized in seen:
                    duplicates.append(normalized)
                    continue

                seen.add(normalized)

                analyzed.append({
                    "address": normalized,
                    "version": address.version,
                    "compressed": address.compressed,
                    "is_global": address.is_global,
                    "is_private": address.is_private,
                    "is_loopback": address.is_loopback,
                    "is_link_local": address.is_link_local,
                    "is_multicast": address.is_multicast,
                    "is_reserved": address.is_reserved,
                    "is_unspecified": address.is_unspecified,
                    "reverse_pointer": address.reverse_pointer,
                })

            except ValueError:
                invalid.append(value)

        duration = round(
            (time.perf_counter() - start) * 1000, 2
        )

        if not analyzed:
            return TestResult(
                name="ip",
                status=TestStatus.ERROR,
                summary="Aucune adresse IP valide.",
                duration_ms=duration,
                error_code="INVALID_IP_ADDRESSES",
                evidence={
                    "invalid_addresses": invalid,
                    "duplicates": duplicates,
                },
            )

        status = (
            TestStatus.WARNING
            if invalid or any(
                not item["is_global"] for item in analyzed
            )
            else TestStatus.PASSED
        )

        return TestResult(
            name="ip",
            status=status,
            summary=f"{len(analyzed)} adresse(s) IP analysée(s).",
            details="Classification IPv4 et IPv6 effectuée.",
            duration_ms=duration,
            evidence={
                "addresses": analyzed,
                "invalid_addresses": invalid,
                "duplicates": duplicates,
                "unique_count": len(analyzed),
            },
            limitations=[
                "La classification ne prouve pas que l'adresse est joignable.",
                "Le pointeur DNS inverse ne prouve pas l'existence d'un enregistrement PTR.",
                "L'identification du propriétaire nécessite des sources complémentaires.",
                "Une IP publique ne prouve pas qu'un service est sans frais de données.",
            ],
        )
