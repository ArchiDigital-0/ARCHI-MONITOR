"""Centre de contrôle principal d'ARCHI MONITOR."""

from cli.server_diagnostic import main as run_device_diagnostic
from cli.independent_tools import (
    run_independent_tool,
    run_mobile_measurement,
)

from core.display import (
    Colors,
    brand_logo,
    colorize,
    heading,
    section,
    message,
)

VERSION = "2.0"


def line():
    print(colorize("─" * 64, Colors.GREY))


def banner():
    brand_logo()
    print(
        colorize(
            f"                    VERSION {VERSION}",
            Colors.BLUE + Colors.BOLD,
        )
    )
    print(
        colorize(
            "       AFRICA MOBILE NETWORK INTELLIGENCE",
            Colors.CYAN,
        )
    )
    print()


def profile_name(mode):
    return "DÉBUTANT" if mode == "1" else "EXPERT"


def choose_mode():
    heading(
        "CONFIGURATION DU PROFIL",
        "Sélectionne ton niveau d'utilisation.",
    )

    section("PROFILS DISPONIBLES")

    print(colorize("[1] PROFIL DÉBUTANT", Colors.GREEN))
    print("    Comprendre les analyses grâce à des explications accessibles.")
    print()
    print(colorize("[2] PROFIL EXPERT", Colors.BLUE))
    print("    Examiner les résultats avec une terminologie technique.")

    while True:
        choice = input("\nSélection du profil [1/2] : ").strip()

        if choice in ("1", "2"):
            print()
            message(
                f"Profil activé : {profile_name(choice)}",
                Colors.GREEN,
            )
            return choice

        message("Sélection invalide. Choisis 1 ou 2.", Colors.YELLOW)


def show_capabilities(mode):
    heading(
        "INVENTAIRE DES CAPACITÉS",
        "Modules et fonctionnalités disponibles",
    )

    if mode == "1":
        categories = [
            (
                "ANALYSE ET CONNECTIVITÉ",
                [
                    ("DNS", "Trouver les adresses IP d'un domaine."),
                    ("TCP", "Vérifier l'accès à un port réseau."),
                    ("IP", "Examiner les adresses IP."),
                ],
            ),
            (
                "INFORMATIONS ET SÉCURITÉ",
                [
                    ("RDAP", "Consulter les informations d'enregistrement."),
                    ("ASN", "Identifier le réseau auquel appartient une IP."),
                    ("TLS", "Examiner la connexion sécurisée et son certificat."),
                    ("HTTP", "Observer la réponse d'un serveur web."),
                    (
                        "CERTIFICATE TRANSPARENCY",
                        "Rechercher des certificats et des sous-domaines publiés.",
                    ),
                ],
            ),
            (
                "PERFORMANCE ET TRAFIC",
                [
                    ("TRAFIC HTTP", "Estimer les données échangées avec un serveur."),
                    ("QUALITÉ RÉSEAU", "Mesurer la stabilité des connexions TCP."),
                ],
            ),
        ]
    else:
        categories = [
            (
                "ANALYSE ET CONNECTIVITÉ",
                [
                    ("DNS", "Résolution des enregistrements IPv4 et IPv6."),
                    ("TCP", "Vérification de l'établissement des connexions TCP."),
                    ("IP", "Classification et inspection des adresses IP."),
                ],
            ),
            (
                "RENSEIGNEMENT RÉSEAU ET SÉCURITÉ",
                [
                    ("RDAP", "Consultation des données d'enregistrement réseau."),
                    ("ASN", "Identification des systèmes autonomes et réseaux annoncés."),
                    ("TLS", "Inspection de la négociation TLS et des certificats."),
                    ("HTTP", "Analyse des réponses et métadonnées HTTP/HTTPS."),
                    (
                        "CERTIFICATE TRANSPARENCY",
                        "Exploration passive des certificats et noms DNS publiés.",
                    ),
                ],
            ),
            (
                "PERFORMANCE ET TRAFIC",
                [
                    ("TRAFIC HTTP", "Estimation des volumes de données applicatives."),
                    ("QUALITÉ RÉSEAU", "Mesure des temps d'établissement TCP et des échecs."),
                ],
            ),
        ]

    for category, features in categories:
        section(category)

        for name, description in features:
            print(colorize(f"  • {name}", Colors.CYAN))
            print(f"    {description}")

    print()
    input("Appuie sur Entrée pour revenir au centre de contrôle...")


def show_main_menu(mode):
    expert = mode == "2"

    heading(
        "CENTRE DE CONTRÔLE",
        "Gestion des opérations de diagnostic réseau",
    )

    print(
        colorize(
            f"PROFIL ACTIF : {profile_name(mode)}",
            Colors.GREEN if not expert else Colors.BLUE,
        )
    )

    if expert:
        options = [
            (
                "01",
                "Diagnostic multidimensionnel",
                "Exécuter les contrôles réseau sur une cible.",
            ),
            (
                "02",
                "Inventaire des capacités techniques",
                "Consulter les protocoles et modules disponibles.",
            ),
            (
                "03",
                "Analyse du trafic applicatif",
                "Évaluer les volumes d'échanges HTTP/HTTPS.",
            ),
            (
                "04",
                "Modules de diagnostic autonomes",
                "Exécuter individuellement les outils réseau.",
            ),
            (
                "05",
                "Configuration du profil d'exploitation",
                "Modifier le niveau de présentation technique.",
            ),
            (
                "06",
                "SERVER INTELLIGENCE",
                "Découverte passive et audit Web autorisé.",
            ),
            ("00", "Fermer la plateforme", "Terminer la session ARCHI MONITOR."),
        ]
    else:
        options = [
            (
                "01",
                "Analyser un domaine",
                "Examiner son fonctionnement et sa connectivité réseau.",
            ),
            (
                "02",
                "Découvrir les fonctionnalités",
                "Consulter les outils disponibles dans ARCHI MONITOR.",
            ),
            (
                "03",
                "Mesurer le trafic Internet",
                "Estimer les données échangées avec un serveur web.",
            ),
            (
                "04",
                "Utiliser un outil indépendant",
                "Lancer un contrôle réseau particulier.",
            ),
            (
                "05",
                "Changer de profil",
                "Passer du mode Débutant au mode Expert.",
            ),
            (
                "06",
                "SERVER INTELLIGENCE",
                "Découvrir les informations publiques et auditer un site autorisé.",
            ),
            ("00", "Quitter ARCHI MONITOR", "Fermer le programme."),
        ]

    section("OPÉRATIONS DISPONIBLES")

    for number, title, description in options:
        print(colorize(f"[{number}] {title}", Colors.CYAN))
        print(f"     {description}")
        print()


def main():
    banner()
    mode = choose_mode()

    while True:
        print()
        show_main_menu(mode)

        choice = input(
            colorize("Sélectionne une opération : ", Colors.GREEN)
        ).strip().lower()

        if choice in ("1", "01"):
            try:
                run_device_diagnostic(mode=mode)
            except KeyboardInterrupt:
                message("\nDiagnostic interrompu par l'utilisateur.", Colors.YELLOW)

            input("\nAppuie sur Entrée pour revenir au centre de contrôle...")

        elif choice in ("2", "02"):
            show_capabilities(mode)

        elif choice in ("3", "03"):
            try:
                run_mobile_measurement()
            except KeyboardInterrupt:
                message("\nMesure interrompue par l'utilisateur.", Colors.YELLOW)

            input("\nAppuie sur Entrée pour revenir au centre de contrôle...")

        elif choice in ("4", "04"):
            try:
                run_independent_tool(mode)
            except KeyboardInterrupt:
                message("\nOpération interrompue par l'utilisateur.", Colors.YELLOW)

        elif choice in ("5", "05"):
            mode = choose_mode()

        elif choice in ("6", "06"):
            try:
                from cli.server_intelligence import main as run_server_intelligence
                run_server_intelligence()
            except KeyboardInterrupt:
                message(
                    "\nSERVER INTELLIGENCE interrompu par l'utilisateur.",
                    Colors.YELLOW,
                )
            except Exception as exc:
                message(
                    f"Erreur SERVER INTELLIGENCE : {type(exc).__name__}: {exc}",
                    Colors.YELLOW,
                )
                input("\nAppuie sur Entrée pour revenir au centre de contrôle...")

        elif choice in ("0", "00", "q", "quit", "exit"):
            print()
            message("Fermeture d'ARCHI MONITOR.", Colors.CYAN)
            message("Merci d'avoir utilisé ARCHI MONITOR.", Colors.GREEN)
            break

        else:
            message(
                "Opération inconnue. Vérifie le numéro sélectionné.",
                Colors.YELLOW,
            )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        message("Session interrompue par l'utilisateur.", Colors.YELLOW)
