from diagnostics.test_context import (
    TestContext,
    TestEnvironment,
    ConnectionType,
)

from core.results import (
    DiagnosticReport,
    TestResult,
    TestStatus,
)

from modules.dns_analyzer import DNSAnalyzer
from modules.tcp_analyzer import TCPAnalyzer
from modules.ip_auditor import IPAuditor
from modules.asn_analyzer import ASNAnalyzer
from modules.tls_analyzer import TLSAnalyzer
from modules.http_analyzer import HTTPAnalyzer
from modules.ct_monitor import CertificateTransparencyMonitor


class ServerDiagnosticEngine:
    """
    Orchestre les diagnostics exécutés depuis le serveur.
    """

    def __init__(
        self,
        target: str,
        server_hostname: str | None = None,
    ):
        self.target = target.strip().lower()

        if not self.target:
            raise ValueError(
                "La cible du diagnostic ne peut pas être vide."
            )

        if server_hostname is None:
            self.server_hostname = self.target
        else:
            self.server_hostname = server_hostname.strip().lower()

        if not self.server_hostname:
            raise ValueError(
                "Le nom SNI ne peut pas être vide."
            )

        self.context = TestContext(
            environment=TestEnvironment.SERVER,
            connection_type=ConnectionType.UNKNOWN,
            device_type="Server",
        )

        self.report = DiagnosticReport(
            target=self.target,
            context=self.context,
        )

        self.dns_analyzer = DNSAnalyzer()
        self.tcp_analyzer = TCPAnalyzer()
        self.ip_auditor = IPAuditor()
        self.asn_analyzer = ASNAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.ct_monitor = CertificateTransparencyMonitor()

    def run(self) -> DiagnosticReport:

        # 1. Analyse DNS
        dns_result = self.dns_analyzer.analyze(self.target)
        self.report.add_result(dns_result)

        ipv4 = dns_result.evidence.get("ipv4", [])
        ipv6 = dns_result.evidence.get("ipv6", [])

        addresses = ipv4 + ipv6

        # 2. Sélection de l'adresse IP
        selected_ip = (
            ipv4[0] if ipv4 else
            ipv6[0] if ipv6 else
            None
        )

        # 3. Analyse TCP
        if selected_ip:
            tcp_result = self.tcp_analyzer.analyze(
                destination=selected_ip,
                port=443,
            )
        else:
            tcp_result = TestResult(
                name="tcp",
                status=TestStatus.SKIPPED,
                summary="Analyse TCP ignorée.",
                details="Aucune adresse IP disponible après le DNS.",
            )

        self.report.add_result(tcp_result)

        # 4. Analyse IP
        if addresses:
            ip_result = self.ip_auditor.analyze(addresses)
        else:
            ip_result = TestResult(
                name="ip",
                status=TestStatus.SKIPPED,
                summary="Analyse IP ignorée.",
                details="Aucune adresse IP disponible après le DNS.",
            )

        self.report.add_result(ip_result)

        # 5. Analyse ASN
        if selected_ip:
            asn_result = self.asn_analyzer.analyze(selected_ip)
        else:
            asn_result = TestResult(
                name="asn",
                status=TestStatus.SKIPPED,
                summary="Analyse ASN ignorée.",
                details="Aucune adresse IP disponible.",
            )

        self.report.add_result(asn_result)

        # 6. Analyse TLS avec SNI personnalisable
        if selected_ip:
            tls_result = self.tls_analyzer.analyze(
                domain=self.target,
                port=443,
                destination_ip=selected_ip,
                server_hostname=self.server_hostname,
            )
        else:
            tls_result = TestResult(
                name="tls",
                status=TestStatus.SKIPPED,
                summary="Analyse TLS ignorée.",
                details="Aucune adresse IP disponible.",
            )

        self.report.add_result(tls_result)

        # 7. Analyse HTTP après validation TLS
        if tls_result.status == TestStatus.PASSED:
            http_result = self.http_analyzer.analyze(
                domain=self.target,
                destination_ip=selected_ip,
                server_hostname=self.server_hostname,
                host_header=self.target,
                port=443,
            )
        else:
            http_result = TestResult(
                name="http",
                status=TestStatus.SKIPPED,
                summary="Analyse HTTP ignorée.",
                details="La connexion TLS n'a pas été validée.",
            )

        self.report.add_result(http_result)

        # 8. Découverte passive des sous-domaines via CT
        try:
            ct_result = self.ct_monitor.analyze(self.target)
        except Exception as exc:
            ct_result = TestResult(
                name="subdomain_ct",
                status=TestStatus.ERROR,
                summary="La découverte Certificate Transparency a échoué.",
                error_code="CT_UNEXPECTED_ERROR",
                error_message=str(exc),
            )

        self.report.add_result(ct_result)

        return self.report
