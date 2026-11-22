"""Interface indépendante du module ZERO-RATING LAB."""

import json
from copy import deepcopy

from core.display import (
    Colors,
    colorize,
    heading,
    section,
    separator,
    message,
    is_expert,
)
from modules.zero_rating_analyzer import ZeroRatingAnalyzer


AXIS_LABELS = {
    "domain_discovery": (
        "Découverte des domaines",
        "DOMAIN DISCOVERY",
    ),
    "dns_ip_analysis": (
        "Analyse DNS et IP",
        "DNS / IP ANALYSIS",
    ),
    "sni_tls_analysis": (
        "Connexion TCP et négociation TLS",
        "SNI / TLS ANALYSIS",
    ),
    "http_analysis": (
        "Analyse de la réponse HTTP",
        "HTTP ANALYSIS",
    ),
    "cross_operator_comparison": (
        "Comparaison entre opérateurs",
        "CROSS-OPERATOR COMPARISON",
    ),
}


STATUS_COLORS = {
    "passed": Colors.GREEN,
    "failed": Colors.RED,
    "error": Colors.RED,
    "warning": Colors.YELLOW,
    "skipped": Colors.GREY,
    "pending": Colors.BLUE,
}


STATUS_LABELS = {
    "passed": ("RÉUSSI", "PASSED"),
    "failed": ("ÉCHEC", "FAILED"),
    "error": ("ERREUR", "ERROR"),
    "warning": ("AVERTISSEMENT", "WARNING"),
    "skipped": ("IGNORÉ", "SKIPPED"),
    "pending": ("EN ATTENTE", "PENDING"),
}


CONCLUSION_LABELS = {
    "completed": ("DIAGNOSTIC TERMINÉ", "COMPLETED"),
    "completed_with_warnings": (
        "TERMINÉ AVEC AVERTISSEMENTS",
        "COMPLETED WITH WARNINGS",
    ),
    "completed_with_errors": (
        "TERMINÉ AVEC ERREURS",
        "COMPLETED WITH ERRORS",
    ),
    "incomplete": (
        "DIAGNOSTIC INCOMPLET",
        "INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED",
    ),
    "issues_detected": ("PROBLÈMES DÉTECTÉS", "ISSUES DETECTED"),
    "not_evaluated": ("NON ÉVALUÉ", "NOT EVALUATED"),
}


def collect_inputs(expert):
    """Recueille et valide les quatre champs avant tout diagnostic."""

    while True:
        section(
            "TARGET CONFIGURATION"
            if expert
            else "FORMULAIRE DE CONFIGURATION"
        )

        if expert:
            print("Enter all four target parameters.")
            sni = input("SNI          : ").strip()
            ip = input("DESTINATION IP: ").strip()
            port = input("PORT         : ").strip()
            host = input("HTTP HOST    : ").strip()
        else:
            print("Renseigne les quatre champs obligatoires.")
            sni = input("Nom SNI          : ").strip()
            ip = input("Adresse IP       : ").strip()
            port = input("Port             : ").strip()
            host = input("En-tête Host     : ").strip()

        try:
            target = ZeroRatingAnalyzer.validate_inputs(
                sni,
                ip,
                port,
                host,
            )
        except ValueError as error:
            message(
                "PARAMÈTRES INVALIDES — AUCUN TEST N'A ÉTÉ LANCÉ."
                if not expert
                else "INVALID PARAMETERS — NO DIAGNOSTIC WAS STARTED.",
                Colors.RED,
            )
            print(error)
            print()
            continue

        message(
            "Les quatre champs sont valides."
            if not expert
            else "All four parameters are valid.",
            Colors.GREEN,
        )
        return target



def localize_text(value, expert):
    """Traduit les messages connus pour le profil Expert."""

    if not expert or not isinstance(value, str):
        return value

    translations = {
        "Erreur pendant cette analyse.": "An error occurred during this analysis.",
        "Cette étape recense les noms saisis sans découvrir de nouveaux domaines ou sous-domaines.": (
            "This step records the supplied names without discovering new domains or subdomains."
        ),
        "La résolution utilise le résolveur système.": (
            "Name resolution uses the system resolver."
        ),
        "Une correspondance DNS ne prouve pas la joignabilité.": (
            "A DNS match does not prove network reachability."
        ),
        "Une IP publique ne prouve pas le zero-rating.": (
            "A public IP address does not prove zero-rating."
        ),
        "La connexion TCP est une étape préalable à TLS.": (
            "A TCP connection is a prerequisite for TLS."
        ),
        "Le protocole HTTP classique ne réalise pas de négociation TLS.": (
            "Standard HTTP does not perform a TLS handshake."
        ),
        "Une connexion TCP réussie ne prouve pas le zero-rating.": (
            "A successful TCP connection does not prove zero-rating."
        ),
        "Le protocole du port personnalisé doit être connu avant de lancer une analyse applicative.": (
            "The custom port protocol must be identified before application-layer analysis."
        ),
        "Le protocole du port personnalisé n'est pas déterminé automatiquement.": (
            "The protocol used by the custom port is not identified automatically."
        ),
        "Aucune requête applicative n'est envoyée sur un port dont le protocole est inconnu.": (
            "No application-layer request is sent to a port whose protocol is unknown."
        ),
        "Une erreur HTTP ne permet pas de conclure sur la facturation opérateur.": (
            "An HTTP error does not establish how the carrier bills the traffic."
        ),
        "Noms SNI et Host recensés.": "SNI and Host names recorded.",
        "Les noms fournis sont identifiés. Aucune énumération externe de domaines n'a été effectuée.": (
            "The supplied names have been identified. No external domain enumeration was performed."
        ),
        "Analyse DNS et IP terminée.": "DNS and IP analysis completed.",
        "Résolution des noms et classification des adresses.": (
            "Hostname resolution and address classification completed."
        ),
        "Connexion TCP impossible ou non vérifiée.": (
            "TCP connection failed or could not be verified."
        ),
        "L'analyse TLS n'a pas été lancée.": "TLS analysis was not started.",
        "Connexion TCP établie ; TLS non applicable.": (
            "TCP connection established; TLS is not applicable."
        ),
        "Le port 80 est traité comme une connexion HTTP classique. Aucune négociation TLS n'a été tentée.": (
            "Port 80 is treated as a standard HTTP connection. No TLS handshake was attempted."
        ),
        "Connexion TCP établie ; protocole indéterminé.": (
            "TCP connection established; protocol undetermined."
        ),
        "Contrôle TCP et négociation TLS exécutés.": (
            "TCP connectivity check and TLS handshake completed."
        ),
        "Connexion TLS validée.": "TLS connection successfully established.",
        "Le certificat et le nom d'hôte ont été vérifiés.": (
            "The certificate and hostname have been verified."
        ),
        "Échec de validation du certificat TLS.": (
            "TLS certificate validation failed."
        ),
        "Échec de la connexion TLS.": "TLS connection failed.",
        "Analyse HTTP non exécutée.": "HTTP analysis was not performed.",
        "Échec de l'analyse HTTP.": "HTTP analysis failed.",
        "La requête HTTP classique n'a pas abouti.": (
            "The standard HTTP request did not complete successfully."
        ),
        "Comparaison entre opérateurs non effectuée.": (
            "Cross-operator comparison was not performed."
        ),
        "Une seconde mesure sur un autre opérateur est nécessaire.": (
            "A second measurement on another carrier is required."
        ),
        "Test exécuté localement depuis le téléphone Android.": (
            "Test performed locally from the Android device."
        ),
        "La connexion TLS ne prouve pas la sécurité globale du site.": (
            "A successful TLS connection does not establish the overall security of the website."
        ),
        "Une seule adresse IP est testée par exécution.": (
            "Only one IP address is tested per execution."
        ),
        "La requête HEAD ne télécharge pas le contenu complet.": (
            "The HEAD request does not download the full response body."
        ),
        "Les redirections ne sont pas suivies.": "Redirects are not followed.",
        "Une réponse HTTP ne prouve pas un accès sans frais.": (
            "An HTTP response does not prove zero-rated access."
        ),
        "Une réponse HTTP ne confirme pas la gratuité des données.": (
            "An HTTP response does not confirm that data traffic is free."
        ),
        "Une négociation TLS réussie ne prouve pas le zero-rating.": (
            "A successful TLS handshake does not prove zero-rating."
        ),
        "Une seule connexion réseau ne permet pas une comparaison.": (
            "A single network connection is insufficient for comparison."
        ),
    }

    if value.startswith("Réponse HTTP reçue :"):
        return value.replace(
            "Réponse HTTP reçue :",
            "HTTP response received:",
            1,
        )

    return translations.get(value, value)


def localize_evidence(evidence, expert):
    """Traduit une copie des preuves sans modifier les données originales."""

    if not expert:
        return evidence

    localized = deepcopy(evidence)

    def translate(item):
        if isinstance(item, dict):
            return {
                key: translate(value)
                for key, value in item.items()
            }

        if isinstance(item, list):
            return [translate(value) for value in item]

        if isinstance(item, tuple):
            return tuple(translate(value) for value in item)

        if isinstance(item, str):
            return localize_text(item, True)

        return item

    return translate(localized)

def display_redirect_summary(evidence):
    """Affiche un résumé des redirections pour le profil Débutant."""

    if not evidence.get("redirect_detected"):
        print("  REDIRECTION : Aucune redirection détectée.")
        return

    history = evidence.get("redirect_history") or []
    destinations = evidence.get(
        "redirect_destinations_detected",
        len(history),
    )

    print("  REDIRECTION : Détectée")
    print(f"  Destinations identifiées : {destinations}")

    non_public = any(
        detail.get("category") != "public"
        for entry in history
        for detail in entry.get("address_details", [])
    )

    if non_public:
        print(
            "  SÉCURITÉ : Une destination non publique a été "
            "repérée ; aucune connexion n'a été effectuée vers elle."
        )
        print(
            "  INFORMATION : La suite éventuelle de cette chaîne "
            "de redirection n'a pas pu être observée."
        )
    elif evidence.get("redirect_requests_attempted", 0):
        print("  SUIVI : Requête(s) effectuée(s).")
        print(
            "  Réponses reçues : "
            f"{evidence.get('redirect_responses_received', 0)}"
        )
    else:
        print("  SUIVI : Non effectué.")

    final_host = evidence.get("final_destination_host")
    if final_host:
        print(f"  Destination finale connue : {final_host}")


def display_result(result, expert):
    """Présente un axe du rapport."""

    key = result.name
    beginner_label, expert_label = AXIS_LABELS.get(
        key,
        (key, key.upper()),
    )

    status_key = result.status.value.lower()
    beginner_status, expert_status = STATUS_LABELS.get(
        status_key,
        (status_key.upper(), status_key.upper()),
    )

    label = expert_label if expert else beginner_label
    status = expert_status if expert else beginner_status
    color = STATUS_COLORS.get(status_key, Colors.WHITE)

    print()
    print(colorize(f"[{status}] {label}", color))
    print(f"  {localize_text(result.summary, expert)}")

    if result.details:
        print(f"  {localize_text(result.details, expert)}")

    if key == "http_analysis":
        transport = result.evidence.get("transport_status")
        application = result.evidence.get("application_status")
        code = result.evidence.get("http_status_code") or result.evidence.get("status_code")
        reason = result.evidence.get("http_reason") or result.evidence.get("reason")
        server = result.evidence.get("server")

        if transport:
            print(
                f"  TRANSPORT STATUS : {transport}"
                if expert
                else f"  ÉTAT DU TRANSPORT : "
                f"{'RÉUSSI' if transport == 'PASSED' else transport}"
            )

        if application:
            print(
                f"  APPLICATION STATUS : {application}"
                if expert
                else f"  RÉSULTAT APPLICATIF : {application}"
            )

        if code is not None:
            print(f"  HTTP RESPONSE : {code} {reason or ''}".rstrip())

        if server:
            print(f"  SERVER : {server}" if expert else f"  SERVEUR : {server}")

        print(
            "  HTTP response does not prove zero-rated traffic."
            if expert
            else "  Une réponse HTTP ne prouve pas la gratuité des données."
        )

        if not expert:
            display_redirect_summary(result.evidence)

    if expert:
        if result.evidence:
            print("  EVIDENCE:")
            print(
                json.dumps(
                    localize_evidence(result.evidence, expert),
                    indent=4,
                    ensure_ascii=False,
                    default=str,
                )
            )

        if result.error_message:
            print(
                "  ERROR: "
                + localize_text(result.error_message, expert)
            )

        if result.limitations:
            print("  LIMITATIONS:")
            for limitation in result.limitations:
                print(
                    "    - "
                    + localize_text(limitation, expert)
                )

    elif result.error_message:
        print(f"  Détail : {result.error_message}")


def display_report(report, target, expert):
    """Affiche un rapport unique regroupant les cinq axes."""

    heading(
        "ZERO-RATING LAB | FINAL REPORT"
        if expert
        else "ZERO-RATING LAB | RAPPORT FINAL",
        "NETWORK BEHAVIOR ANALYSIS"
        if expert
        else "Analyse du comportement de la connexion",
    )

    section("TARGET SUMMARY" if expert else "CIBLE ANALYSÉE")

    print(f"SNI : {target['sni']}")
    print(f"IP  : {target['ip']}")
    print(f"PORT: {target['port']}")
    print(f"HOST: {target['host']}")

    section("FIVE DIAGNOSTIC AXES" if expert else "LES CINQ AXES")

    for result in report.results:
        display_result(result, expert)

    counts = {}
    for result in report.results:
        key = result.status.value.lower()
        counts[key] = counts.get(key, 0) + 1

    section("GLOBAL SUMMARY" if expert else "BILAN GÉNÉRAL")

    for key in (
        "passed",
        "failed",
        "error",
        "warning",
        "skipped",
    ):
        if counts.get(key, 0):
            beginner_status, expert_status = STATUS_LABELS[key]
            label = expert_status if expert else beginner_status
            print(f"{label:<18}: {counts[key]}")

    conclusion = getattr(report.conclusion, "value", report.conclusion)
    beginner_label, expert_label = CONCLUSION_LABELS.get(
        str(conclusion).lower(),
        ("CONCLUSION INCONNUE", "UNKNOWN CONCLUSION"),
    )
    conclusion_label = expert_label if expert else beginner_label

    print()
    print(
        "REPORT CONCLUSION"
        if expert
        else "CONCLUSION DU RAPPORT"
    )
    print(conclusion_label)

    separator()

    message(
        "IMPORTANT : les résultats techniques ne prouvent pas "
        "que l'opérateur ne facture pas ces données."
        if not expert
        else "IMPORTANT: technical results do not establish "
        "that the mobile operator is not billing this traffic.",
        Colors.YELLOW,
    )

    message(
        "Une vérification de la consommation réelle ou des données "
        "de facturation de l'opérateur reste nécessaire."
        if not expert
        else "Actual usage accounting or carrier billing data "
        "is still required for zero-rating confirmation.",
        Colors.YELLOW,
    )


def run_zero_rating_lab(mode="1"):
    """Point d'entrée indépendant du ZERO-RATING LAB."""

    expert = is_expert(mode)

    heading(
        "ARCHI DIGITAL | ZERO-RATING LAB",
        "ADVANCED NETWORK BEHAVIOR ANALYSIS"
        if expert
        else "Analyse avancée des connexions réseau",
    )

    message(
        "Les quatre paramètres seront validés avant tout diagnostic."
        if not expert
        else "All four parameters will be validated before diagnostics.",
        Colors.CYAN,
    )

    target = collect_inputs(expert)

    separator()
    message(
        "Démarrage des cinq axes de diagnostic..."
        if not expert
        else "Starting the five diagnostic axes...",
        Colors.BLUE,
    )

    analyzer = ZeroRatingAnalyzer(
        sni=target["sni"],
        ip=target["ip"],
        port=target["port"],
        host=target["host"],
    )

    report = analyzer.analyze()
    display_report(report, target, expert)

    input(
        "\nAppuie sur Entrée pour revenir au menu..."
        if not expert
        else "\nPress Enter to return to the menu..."
    )
