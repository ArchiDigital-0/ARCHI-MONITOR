"""Outils de diagnostic indépendants d'ARCHI MONITOR."""

import ipaddress

from modules.dns_analyzer import DNSAnalyzer
from modules.tcp_analyzer import TCPAnalyzer
from modules.ip_auditor import IPAuditor
from modules.rdap_analyzer import RDAPAnalyzer
from modules.asn_analyzer import ASNAnalyzer
from modules.tls_analyzer import TLSAnalyzer
from modules.http_analyzer import HTTPAnalyzer
from modules.ct_monitor import CertificateTransparencyMonitor
from modules.mobile_data_analyzer import MobileDataAnalyzer
from modules.network_quality_monitor import NetworkQualityMonitor

from cli.server_diagnostic import (
    ask_domain,
    show_result,
    browse_ct_results,
    line,
)


def ask_ip():
    while True:
        value = input("\nAdresse IP à analyser : ").strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            print("[!] Adresse IP invalide. Exemple : 8.8.8.8")


def ask_port(default=443):
    while True:
        value = input(f"Port à tester [{default}] : ").strip()

        if not value:
            return default

        try:
            port = int(value)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass

        print("[!] Port invalide. Choisis un nombre entre 1 et 65535.")


def resolve_domain(domain, mode):
    result = DNSAnalyzer().analyze(domain)
    show_result(result, mode)

    ipv4 = result.evidence.get("ipv4", [])
    ipv6 = result.evidence.get("ipv6", [])
    addresses = ipv4 + ipv6

    if not addresses:
        raise ValueError(
            "Aucune adresse IP disponible pour ce domaine."
        )

    selected_ip = ipv4[0] if ipv4 else ipv6[0]

    print("\nAdresse IP sélectionnée :", selected_ip)
    return selected_ip


def run_mobile_measurement():
    url = input("\nURL HTTP/HTTPS à tester : ").strip()

    if not url:
        print("[!] URL vide.")
        return

    result = MobileDataAnalyzer().analyze(url)

    print("\n===== MOBILE DATA ANALYZER =====")
    print("Statut :", result.status.value)
    print("Résumé :", result.summary)
    print("Durée :", result.duration_ms, "ms")

    for key, value in result.evidence.items():
        print(f"{key} : {value}")

    if result.error_message:
        print("Erreur :", result.error_message)

    print("\nLIMITATIONS :")
    for item in result.limitations:
        print("-", item)


def run_network_quality_monitor():
    destination = ask_domain("\\nDomaine ou adresse IP à tester : ")
    port = ask_port()

    monitor = NetworkQualityMonitor()
    result = monitor.analyze(destination, port)

    print("\\n===== NETWORK QUALITY MONITOR =====")
    show_result(result, "2")

    print("\\nINDICATEURS :")
    for key, value in result.evidence.items():
        print(f"{key} : {value}")

    print("\\nLIMITATIONS :")
    for item in result.limitations:
        print("-", item)


def run_independent_tool(mode):
    while True:
        print("\n")
        line()
        print("          ARCHI MONITOR — OUTILS INDÉPENDANTS")
        line()

        print("[1] Analyse DNS")
        print("[2] Test TCP")
        print("[3] Analyse IP")
        print("[4] Recherche RDAP")
        print("[5] Analyse ASN")
        print("[6] Analyse TLS")
        print("[7] Analyse HTTP")
        print("[8] Certificate Transparency")
        print("[9] Mesure du trafic HTTP mobile")
        print("[10] Network Quality Monitor")
        print("[0] Retour au menu principal")

        choice = input("\nSélectionne un outil : ").strip()

        try:
            if choice == "0":
                return

            elif choice == "1":
                domain = ask_domain("\nDomaine à analyser : ")
                result = DNSAnalyzer().analyze(domain)
                show_result(result, mode)

            elif choice == "2":
                domain = ask_domain("\nDomaine à tester : ")
                port = ask_port()
                result = TCPAnalyzer().analyze(domain, port)
                show_result(result, mode)

            elif choice == "3":
                address = ask_ip()
                result = IPAuditor().analyze([address])
                show_result(result, mode)

            elif choice == "4":
                address = ask_ip()
                result = RDAPAnalyzer().analyze(address)
                show_result(result, mode)

            elif choice == "5":
                address = ask_ip()
                result = ASNAnalyzer().analyze(address)
                show_result(result, mode)

            elif choice == "6":
                domain = ask_domain("\nDomaine à analyser : ")
                port = ask_port()
                address = resolve_domain(domain, mode)

                result = TLSAnalyzer().analyze(
                    domain=domain,
                    port=port,
                    server_hostname=domain,
                    destination_ip=address,
                )
                show_result(result, mode)

            elif choice == "7":
                domain = ask_domain("\nDomaine à analyser : ")
                port = ask_port()
                address = resolve_domain(domain, mode)

                result = HTTPAnalyzer().analyze(
                    domain=domain,
                    destination_ip=address,
                    server_hostname=domain,
                    host_header=domain,
                    port=port,
                )
                show_result(result, mode)

            elif choice == "8":
                domain = ask_domain("\nDomaine à analyser : ")
                result = CertificateTransparencyMonitor().analyze(domain)
                show_result(result, mode)

                if mode == "2" and result.evidence:
                    browse_ct_results(result)

            elif choice == "9":
                run_mobile_measurement()

            elif choice == "10":
                run_network_quality_monitor()

            else:
                print("[!] Option invalide.")

        except KeyboardInterrupt:
            print("\n[!] Opération interrompue.")

        except Exception as error:
            print("\n[ERREUR] L'outil n'a pas pu terminer.")
            if mode == "2":
                print("Détail technique :", repr(error))
            else:
                print("Vérifie la cible et réessaie.")

        input("\nAppuie sur Entrée pour revenir aux outils...")
