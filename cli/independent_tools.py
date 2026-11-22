"""Outils de diagnostic indépendants d'ARCHI MONITOR."""

import ipaddress

from core.display import (
    Colors,
    colorize,
    heading,
    section,
    separator,
    message,
    profile_text,
    is_expert,
)

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
from cli.zero_rating_lab import run_zero_rating_lab

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
    expert = is_expert(mode)

    while True:
        print()
        heading(
            "ARCHI DIGITAL | DIAGNOSTIC LAB",
            profile_text(
                mode,
                "CENTRE DES OUTILS DE DIAGNOSTIC",
                "NETWORK DIAGNOSTICS CONSOLE",
            ),
        )

        message(
            profile_text(
                mode,
                "PROFIL ACTIF : DÉBUTANT",
                "ACTIVE PROFILE : EXPERT",
            ),
            Colors.GREEN if not expert else Colors.CYAN,
        )

        options = [
            (
                "1",
                "ANALYSE DNS",
                "DNS ANALYZER",
                "Examiner un nom de domaine et ses adresses réseau.",
                "DNS resolution and record inspection.",
            ),
            (
                "2",
                "TEST DE CONNEXION TCP",
                "TCP CONNECTIVITY TEST",
                "Vérifier si un serveur accepte une connexion sur un port.",
                "TCP connection establishment and port verification.",
            ),
            (
                "3",
                "ANALYSE D'ADRESSE IP",
                "IP ADDRESS AUDIT",
                "Examiner une adresse IP et ses caractéristiques.",
                "IP address inspection and classification.",
            ),
            (
                "4",
                "RECHERCHE RDAP",
                "RDAP REGISTRATION INTELLIGENCE",
                "Rechercher les informations d'enregistrement d'une IP.",
                "Registration data and network allocation lookup.",
            ),
            (
                "5",
                "IDENTIFICATION DU RÉSEAU ASN",
                "ASN NETWORK INTELLIGENCE",
                "Identifier le réseau et son opérateur.",
                "Autonomous System identification and network ownership.",
            ),
            (
                "6",
                "VÉRIFICATION DE LA SÉCURITÉ TLS",
                "TLS SECURITY INSPECTION",
                "Examiner la connexion sécurisée et son certificat.",
                "TLS handshake and certificate inspection.",
            ),
            (
                "7",
                "ANALYSE DU PROTOCOLE HTTP",
                "HTTP PROTOCOL ANALYSIS",
                "Examiner la réponse d'un serveur web.",
                "HTTP response and protocol behaviour analysis.",
            ),
            (
                "8",
                "TRANSPARENCE DES CERTIFICATS",
                "CERTIFICATE TRANSPARENCY",
                "Rechercher les certificats publiés pour un domaine.",
                "Public certificate discovery and CT log inspection.",
            ),
            (
                "9",
                "MESURE DU TRAFIC WEB MOBILE",
                "MOBILE HTTP TRAFFIC ANALYZER",
                "Estimer les données échangées avec un serveur web.",
                "HTTP application-level traffic measurement.",
            ),
            (
                "10",
                "QUALITÉ DE LA CONNEXION RÉSEAU",
                "NETWORK QUALITY MONITOR",
                "Mesurer les temps de connexion TCP et les échecs.",
                "TCP connection latency and failure-rate monitoring.",
            ),
            (
                "11",
                "LABORATOIRE ZERO-RATING",
                "ZERO-RATING LAB",
                "Examiner une connexion selon les paramètres SNI, IP, port et Host.",
                "Analyze target connectivity using SNI, IP, port and HTTP Host.",
            ),
        ]

        sections = [
            (
                profile_text(
                    mode,
                    "CONNECTIVITÉ ET ADRESSAGE",
                    "CONNECTIVITY & ADDRESSING",
                ),
                options[:3],
            ),
            (
                profile_text(
                    mode,
                    "RENSEIGNEMENT ET SÉCURITÉ",
                    "NETWORK INTELLIGENCE & SECURITY",
                ),
                options[3:8],
            ),
            (
                profile_text(
                    mode,
                    "PERFORMANCE ET TRAFIC",
                    "PERFORMANCE & TRAFFIC",
                ),
                options[8:10],
            ),
            (
                profile_text(
                    mode,
                    "ANALYSE AVANCÉE",
                    "ADVANCED NETWORK ANALYSIS",
                ),
                options[10:],
            ),
        ]

        for title, items in sections:
            section(title)

            for number, beginner_name, expert_name, beginner_desc, expert_desc in items:
                name = expert_name if expert else beginner_name
                description = expert_desc if expert else beginner_desc

                print(
                    f"  [{number.zfill(2)}] "
                    + colorize(name, Colors.WHITE + Colors.BOLD)
                )
                print(
                    "       "
                    + colorize(description, Colors.GREY)
                )

        separator(width=56)

        message(
            profile_text(
                mode,
                "[00] Retour au menu principal",
                "[00] RETURN TO CONTROL CENTER",
            ),
            Colors.YELLOW,
        )

        choice = input(
            profile_text(
                mode,
                "\nSélectionne un outil : ",
                "\nSelect a diagnostic module : ",
            )
        ).strip()

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

                if expert and result.evidence:
                    browse_ct_results(result)

            elif choice == "9":
                run_mobile_measurement()

            elif choice == "10":
                run_network_quality_monitor()

            elif choice == "11":
                run_zero_rating_lab(mode)

            else:
                message(
                    profile_text(
                        mode,
                        "[!] Option invalide. Réessaie.",
                        "[!] INVALID SELECTION.",
                    ),
                    Colors.YELLOW,
                )

        except KeyboardInterrupt:
            message(
                "\nOpération interrompue.",
                Colors.YELLOW,
            )

        except Exception as error:
            message(
                "\nUne erreur empêche le diagnostic de se terminer.",
                Colors.RED,
            )
            if expert:
                message(f"Détail technique : {error!r}", Colors.GREY)
            else:
                message("Vérifie la cible et réessaie.", Colors.YELLOW)

        input(
            profile_text(
                mode,
                "\nAppuie sur Entrée pour revenir aux outils...",
                "\nPress Enter to return to diagnostic modules...",
            )
        )
