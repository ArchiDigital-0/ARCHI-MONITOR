"""Menu principal d'ARCHI MONITOR."""

from cli.server_diagnostic import main as run_device_diagnostic
from cli.independent_tools import run_independent_tool

VERSION = "2.0"


def line():
    print("=" * 62)


def banner():
    line()
    print("                 ARCHI MONITOR v" + VERSION)
    print("                    ARCHI DIGITAL")
    print("          AFRICA MOBILE NETWORK INTELLIGENCE")
    line()


def choose_mode():
    print("\nCHOISIS TON MODE")
    print("[1] Débutant : explications simples")
    print("[2] Expert   : détails techniques")

    while True:
        choice = input("\nTon choix [1/2] : ").strip()
        if choice in ("1", "2"):
            return choice
        print("Choix invalide. Tape 1 ou 2.")


def show_capabilities():
    line()
    print("       FONCTIONNALITÉS DISPONIBLES")
    line()

    features = [
        "Résolution DNS IPv4 / IPv6",
        "Test de connexion TCP",
        "Classification des adresses IP",
        "Recherche RDAP des informations d'enregistrement IP",
        "Informations ASN et réseau",
        "Vérification TLS et certificats",
        "Inspection HTTP / HTTPS",
        "Découverte passive Certificate Transparency",
    ]

    for feature in features:
        print("[OK] " + feature)

    print("\nCes fonctions sont accessibles individuellement")
    print("dans le menu des outils indépendants.")
    input("\nAppuie sur Entrée pour revenir au menu...")


def main():
    banner()
    mode = choose_mode()

    while True:
        print("\n")
        line()
        print("                 MENU PRINCIPAL")
        line()

        profile = "DÉBUTANT" if mode == "1" else "EXPERT"
        print("PROFIL :", profile)
        print()
        print("[1] Analyse complète d'un domaine")
        print("[2] Fonctionnalités disponibles")
        print("[3] Changer de profil")
        print("[4] Mesure du trafic HTTP mobile")
        print("[5] Outils de diagnostic indépendants")
        print("[0] Quitter ARCHI MONITOR")

        choice = input("\nSélectionne une option : ").strip().lower()

        if choice == "1":
            try:
                run_device_diagnostic(mode=mode)
            except KeyboardInterrupt:
                print("\n[!] Analyse interrompue.")

            input("\nAppuie sur Entrée pour revenir au menu principal...")

        elif choice == "2":
            show_capabilities()

        elif choice == "3":
            mode = choose_mode()

        elif choice == "5":
            try:
                run_independent_tool(mode)
            except KeyboardInterrupt:
                print("\n[!] Opération interrompue.")

        elif choice == "4":
            try:
                from modules.mobile_data_analyzer import MobileDataAnalyzer

                url = input(
                    "\nURL HTTP/HTTPS à tester : "
                ).strip()

                if url:
                    analyzer = MobileDataAnalyzer()
                    result = analyzer.analyze(url)

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

            except KeyboardInterrupt:
                print("\n[!] Mesure interrompue.")

        elif choice in ("0", "q", "quit", "exit"):
            print("\nMerci d'avoir utilisé ARCHI MONITOR.")
            break

        else:
            print("Option invalide. Réessaie.")
