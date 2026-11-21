"""Mesure passive de la qualité d'une connexion réseau via TCP."""

import socket
import time
import statistics

from core.results import TestResult, TestStatus


class NetworkQualityMonitor:
    """
    Mesure la latence TCP, le taux d'échec et la stabilité.

    Les mesures portent sur l'établissement de connexions TCP,
    et non sur la perte réelle de paquets IP.
    """

    def __init__(
        self,
        attempts=5,
        timeout=3.0,
        interval=0.5,
    ):
        if not 3 <= attempts <= 10:
            raise ValueError("Le nombre de tentatives doit être entre 3 et 10.")

        if not 1 <= timeout <= 5:
            raise ValueError("Le délai doit être entre 1 et 5 secondes.")

        if not 0 <= interval <= 2:
            raise ValueError("L'intervalle doit être entre 0 et 2 secondes.")

        self.attempts = attempts
        self.timeout = timeout
        self.interval = interval

    def analyze(self, destination, port=443):
        start = time.perf_counter()

        if not destination:
            return TestResult(
                name="network_quality",
                status=TestStatus.ERROR,
                summary="Destination réseau manquante.",
                error_code="INVALID_DESTINATION",
            )

        if not 1 <= port <= 65535:
            return TestResult(
                name="network_quality",
                status=TestStatus.ERROR,
                summary="Port TCP invalide.",
                error_code="INVALID_PORT",
            )

        try:
            addresses = socket.getaddrinfo(
                destination,
                port,
                type=socket.SOCK_STREAM,
            )

            if not addresses:
                raise OSError("Aucune adresse IP disponible.")

            family, socktype, protocol, _, sockaddr = addresses[0]
            destination_ip = sockaddr[0]

        except (socket.gaierror, OSError) as exc:
            return TestResult(
                name="network_quality",
                status=TestStatus.FAILED,
                summary="Impossible de résoudre la destination.",
                duration_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                error_code="NETWORK_QUALITY_RESOLUTION_FAILED",
                error_message=str(exc),
                evidence={"destination": destination},
            )

        latencies = []
        failures = []

        for number in range(1, self.attempts + 1):
            probe_start = time.perf_counter()

            try:
                with socket.socket(
                    family, socktype, protocol
                ) as connection:
                    connection.settimeout(self.timeout)
                    connection.connect(sockaddr)

                latency = (
                    time.perf_counter() - probe_start
                ) * 1000

                latencies.append(round(latency, 2))

            except (socket.timeout, OSError) as exc:
                failures.append({
                    "attempt": number,
                    "error": str(exc),
                })

            if number < self.attempts and self.interval:
                time.sleep(self.interval)

        successful = len(latencies)
        failed = len(failures)

        failure_rate = round(
            (failed / self.attempts) * 100, 2
        )

        evidence = {
            "destination": destination,
            "destination_ip": destination_ip,
            "port": port,
            "attempts": self.attempts,
            "successful_attempts": successful,
            "failed_attempts": failed,
            "tcp_failure_rate_percent": failure_rate,
            "latencies_ms": latencies,
            "failures": failures,
            "timeout_seconds": self.timeout,
            "interval_seconds": self.interval,
        }

        limitations = [
            "Mesure du temps d'établissement TCP, pas du RTT ICMP.",
            "Le taux d'échec TCP ne représente pas la perte réelle de paquets IP.",
            "Les résultats dépendent du serveur et du port testés.",
            "La résolution DNS est effectuée avant les mesures de latence.",
            "Test exécuté localement depuis le téléphone.",
        ]

        if not latencies:
            return TestResult(
                name="network_quality",
                status=TestStatus.FAILED,
                summary="Aucune connexion TCP n'a abouti.",
                duration_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                error_code="ALL_TCP_PROBES_FAILED",
                evidence=evidence,
                limitations=limitations,
            )

        average = statistics.mean(latencies)
        minimum = min(latencies)
        maximum = max(latencies)
        median = statistics.median(latencies)

        jitter = (
            statistics.mean([
                abs(latencies[i] - latencies[i - 1])
                for i in range(1, len(latencies))
            ])
            if len(latencies) > 1
            else 0.0
        )

        evidence.update({
            "average_latency_ms": round(average, 2),
            "minimum_latency_ms": round(minimum, 2),
            "maximum_latency_ms": round(maximum, 2),
            "median_latency_ms": round(median, 2),
            "average_latency_variation_ms": round(jitter, 2),
        })

        status = (
            TestStatus.WARNING if failed else TestStatus.PASSED
        )

        summary = (
            "Mesure terminée avec des échecs de connexion."
            if failed
            else "Mesure de qualité TCP terminée."
        )

        return TestResult(
            name="network_quality",
            status=status,
            summary=summary,
            details=(
                f"Latence moyenne : {average:.2f} ms ; "
                f"échecs TCP : {failure_rate:.2f} %."
            ),
            duration_ms=round(
                (time.perf_counter() - start) * 1000, 2
            ),
            evidence=evidence,
            limitations=limitations,
        )
