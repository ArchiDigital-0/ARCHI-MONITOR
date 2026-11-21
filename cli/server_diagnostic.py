import json
from datetime import datetime

from diagnostics.device_engine import DeviceDiagnosticEngine
from diagnostics.report_interpreter import ReportInterpreter
from core.results import TestStatus


VERSION = "2.0"

MODE_LABELS = {
    "dns": "DNS",
    "tcp": "TCP",
    "ip": "IP",
    "rdap": "RDAP",
    "asn": "ASN",
    "tls": "TLS",
    "http": "HTTP",
    "subdomain_ct": "CERTIFICATE TRANSPARENCY",
}

BEGINNER_EXPLANATIONS = {
    "dns": (
        "Recherche les adresses IP associées au domaine."
    ),
    "tcp": (
        "Vérifie si une connexion peut être établie avec le serveur."
    ),
    "ip": (
        "Examine et classe les adresses IP obtenues."
    ),
    "rdap": (
        "Recherche les informations d'enregistrement du réseau IP."
    ),
    "asn": (
        "Recherche le réseau auquel l'adresse IP est annoncée."
    ),
    "tls": (
        "Vérifie la connexion sécurisée et le certificat numérique."
    ),
    "http": (
        "Examine la réponse du serveur web."
    ),
    "subdomain_ct": (
        "Recherche passivement des noms de sous-domaines "
        "dans les journaux Certificate Transparency."
    ),
}


def line():
    print("=" * 62)


def banner():
    line()
    print("                 ARCHI MONITOR v" + VERSION)
    print("                    ARCHI DIGITAL")
    print("          AFRICA MOBILE NETWORK INTELLIGENCE")
    line()


def validate_domain(raw):
    raw = raw.strip()

    if not raw or any(c.isspace() for c in raw):
        raise ValueError("Saisie vide ou contenant des espaces.")

    if "://" not in raw:
        raw = "//" + raw

    from urllib.parse import urlsplit

    parsed = urlsplit(raw)

    if parsed.username or parsed.password or parsed.port:
        raise ValueError(
            "Ne saisis pas de port ou d'identifiants."
        )

    domain = parsed.hostname

    if not domain:
        raise ValueError("Nom de domaine introuvable.")

    domain = domain.rstrip(".").encode("idna").decode("ascii").lower()

    if len(domain) > 253:
        raise ValueError("Nom de domaine trop long.")

    for label in domain.split("."):
        if (
            not label
            or len(label) > 63
            or not __import__("re").fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError("Format de domaine incorrect.")

    return domain


def ask_domain(message):
    while True:
        raw = input(message)

        try:
            return validate_domain(raw)
        except (ValueError, UnicodeError) as error:
            print("[!] Saisie invalide :", error)
            print("    Exemple : example.com\n")


def choose_mode():
    print("\nCHOISIS TON MODE")
    print("[1] Débutant : explications simples")
    print("[2] Expert   : détails techniques")

    while True:
        choice = input("\nTon choix [1/2] : ").strip()

        if choice in ("1", "2"):
            return choice

        print("Choix invalide. Tape 1 ou 2.")


def status_label(status):
    labels = {
        TestStatus.PASSED: "RÉUSSI",
        TestStatus.FAILED: "ÉCHEC",
        TestStatus.WARNING: "AVERTISSEMENT",
        TestStatus.SKIPPED: "IGNORÉ",
        TestStatus.ERROR: "ERREUR",
        TestStatus.PENDING: "EN ATTENTE",
    }

    return labels.get(status, str(status))



def show_http_evidence(evidence):
    print("    Résumé HTTP :")

    fields = {
        "destination": "Destination",
        "destination_ip": "IP de destination",
        "port": "Port",
        "sni": "SNI TLS",
        "host_header": "Host HTTP",
        "status_code": "Code HTTP",
        "reason": "Raison",
    }

    for key, label in fields.items():
        value = evidence.get(key)
        if value is not None:
            print(f"      {label:<22}: {value}")

    version = evidence.get("http_version")
    if version is not None:
        version = {
            10: "HTTP/1.0",
            11: "HTTP/1.1",
        }.get(version, str(version))
        print(f"      {'Version HTTP':<22}: {version}")

    redirect = evidence.get("redirect_location")
    if redirect:
        print("      Redirection           :", redirect)

    headers = evidence.get("headers") or {}
    normalized = {
        str(key).lower(): value
        for key, value in headers.items()
    }

    print(f"      Nombre d'en-têtes     : {len(headers)}")
    print("      En-têtes sélectionnés :")

    selected_headers = [
        "server",
        "content-type",
        "content-length",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    for key in selected_headers:
        value = normalized.get(key)
        if value is not None:
            print(f"        {key}: {value}")

    csp = normalized.get("content-security-policy")
    if csp is not None:
        print(
            "        Content-Security-Policy : présente "
            f"({len(str(csp))} caractères)"
        )


def show_result(result, mode):
    name = MODE_LABELS.get(
        result.name,
        result.name.upper()
    )

    print(f"\n[{status_label(result.status)}] {name}")
    print("    " + result.summary)

    if mode == "1":
        explanation = BEGINNER_EXPLANATIONS.get(result.name)

        if explanation:
            print("    Comprendre :", explanation)

        if result.details:
            print("    Information :", result.details)

        if result.error_code:
            print("    Code de diagnostic :", result.error_code)

        if result.error_message:
            print("    Cause signalée :", result.error_message)

    else:
        if result.details:
            print("    Détails :", result.details)

        if result.duration_ms is not None:
            print(
                f"    Durée : {result.duration_ms:.2f} ms"
            )

        if result.evidence:
            if result.name == "http":
                show_http_evidence(result.evidence)
                print(
                    "    Note : les en-têtes complets restent "
                    "conservés dans les preuves du rapport."
                )

            elif result.name == "subdomain_ct":
                evidence = result.evidence

                print("    Résumé Certificate Transparency :")
                print("      Source             :", evidence.get("source"))
                print("      Sous-domaines      :", evidence.get("subdomain_count", 0))
                print("      Certificats       :", evidence.get("certificate_record_count", 0))
                print("      Jokers             :", evidence.get("wildcard_count", 0))
                print("      Pages récupérées   :", evidence.get("pages_requested", 0))
                print(
                    "      Pagination complète :",
                    "Non" if evidence.get("pagination_incomplete") else "Oui"
                )

                if evidence.get("source_error"):
                    print("      Erreur source      :", evidence["source_error"])

                print(
                    "    Note : consulte le menu CT pour parcourir "
                    "les noms et les certificats."
                )

            else:
                print("    Preuves techniques :")
                print(
                    json.dumps(
                        result.evidence,
                        indent=4,
                        ensure_ascii=False,
                        default=str,
                    )
                )

        if result.error_code:
            print("    Code erreur :", result.error_code)

        if result.error_message:
            print("    Message :", result.error_message)

        if result.limitations:
            print("    Limitations :")

            for limitation in result.limitations:
                print("      -", limitation)



def paginate_ct_items(items, title, formatter):
    page_size = 10
    page = 0
    total_pages = (len(items) + page_size - 1) // page_size

    if not items:
        print("\n    Aucun élément disponible.")
        return

    while True:
        start = page * page_size
        end = min(start + page_size, len(items))

        print("\n    " + title)
        print(
            f"    Page {page + 1}/{total_pages} "
            f"— éléments {start + 1} à {end} sur {len(items)}"
        )
        print("    " + "-" * 48)

        for index, item in enumerate(items[start:end], start=start + 1):
            print(formatter(index, item))

        print("\n    [n] Page suivante  [p] Page précédente  [q] Retour")
        choice = input("    Ton choix : ").strip().lower()

        if choice == "n" and page < total_pages - 1:
            page += 1
        elif choice == "p" and page > 0:
            page -= 1
        elif choice == "q":
            return
        else:
            print("    Choix invalide ou limite de pagination atteinte.")


def browse_ct_results(result):
    evidence = result.evidence

    subdomains = evidence.get("subdomains") or []
    certificates = evidence.get("certificate_records") or []

    while True:
        print("\n")
        line()
        print("             EXPLORATEUR CERTIFICATE TRANSPARENCY")
        line()
        print("    Domaine :", evidence.get("target_domain", "Inconnu"))
        print("    Source  :", evidence.get("source", "Inconnue"))
        print("    Sous-domaines :", len(subdomains))
        print("    Certificats   :", len(certificates))
        print("\n    [1] Consulter les sous-domaines")
        print("    [2] Consulter les certificats")
        print("    [3] Retour au rapport")

        choice = input("\n    Ton choix [1/2/3] : ").strip()

        if choice == "1":
            paginate_ct_items(
                subdomains,
                "LISTE DES SOUS-DOMAINES",
                lambda index, item: f"    {index:>3}. {item}",
            )

        elif choice == "2":
            def format_certificate(index, certificate):
                cert_id = certificate.get("id") or "Inconnu"
                sha256 = certificate.get("cert_sha256") or "Indisponible"
                dns_names = certificate.get("dns_names") or []
                revoked = certificate.get("revoked")

                if revoked is True:
                    revoked_label = "Oui"
                elif revoked is False:
                    revoked_label = "Non"
                else:
                    revoked_label = "Inconnu"

                lines = [
                    f"    {index:>3}. ID : {cert_id}",
                    f"         Début : {certificate.get('not_before') or 'Inconnu'}",
                    f"         Fin   : {certificate.get('not_after') or 'Inconnue'}",
                    f"         Révoqué : {revoked_label}",
                    f"         SHA-256 : {sha256}",
                    "         Noms DNS :",
                ]

                if dns_names:
                    for name in dns_names[:8]:
                        lines.append(f"           - {name}")

                    if len(dns_names) > 8:
                        lines.append(
                            f"           ... et {len(dns_names) - 8} autre(s)"
                        )
                else:
                    lines.append("           Aucun nom DNS disponible")

                return "\n".join(lines)

            paginate_ct_items(
                certificates,
                "REGISTRE DES CERTIFICATS",
                format_certificate,
            )

        elif choice == "3":
            return

        else:
            print("    Choix invalide. Tape 1, 2 ou 3.")



def final_report(report, mode):
    line()
    print("                    RAPPORT FINAL")
    line()

    counts = {
        status: 0 for status in TestStatus
    }

    for result in report.results:
        counts[result.status] += 1

        print(
            f"    {MODE_LABELS.get(result.name, result.name.upper()):<27}"
            f": {status_label(result.status)}"
        )

    total = len(report.results)

    print(f"\n    Nombre total d'analyses : {total}")
    print(f"    Réussies                : {counts[TestStatus.PASSED]}")
    print(f"    Échouées                : {counts[TestStatus.FAILED]}")
    print(f"    Avertissements          : {counts[TestStatus.WARNING]}")
    print(f"    Ignorées                : {counts[TestStatus.SKIPPED]}")
    print(f"    Erreurs                 : {counts[TestStatus.ERROR]}")

    print("\n    Conclusion :", report.conclusion.value)

    context = report.context

    print("\n    ENVIRONNEMENT DE MESURE")
    print("    Appareil       :", context.device_type or "Inconnu")
    print("    Connexion      :", context.connection_type.value)
    print("    Opérateur      :", context.operator_name or "Inconnu")
    print("    Code opérateur :", context.operator_code or "Inconnu")
    print("    Technologie    :", context.network_generation or "Inconnue")
    print("    Activité réseau:", context.data_activity or "Inconnue")
    print("    Confiance      :", context.connection_confidence or "Inconnue")

    print("\n    LIMITATIONS DU CONTEXTE")
    if report.limitations:
        for limitation in report.limitations:
            print("    -", limitation)
    else:
        print("    Aucune limitation signalée.")

    if mode == "2":
        print("\n    Identifiant du rapport :", report.report_id)
        print(
            "    Date du rapport :",
            report.created_at
        )

    print(
        "\n    IMPORTANT : les analyses réseau sont exécutées "
        "localement depuis ce téléphone Android via Termux."
    )
    print(
        "    Certaines données complémentaires proviennent "
        "de sources externes."
    )
    print(
        "    Une réponse HTTP ou une connexion TLS réussie "
        "ne prouve pas qu'un site est gratuit en données mobiles."
    )

    line()


def main(mode=None):
    banner()

    if mode is None:
        mode = choose_mode()

    domain = ask_domain(
        "\nDomaine ou URL à analyser : "
    )

    print("\nDomaine sélectionné :", domain)

    sni_input = input(
        "Nom SNI (Entrée pour utiliser le domaine) : "
    ).strip()

    if sni_input:
        try:
            sni = validate_domain(sni_input)
        except (ValueError, UnicodeError) as error:
            print("[!] SNI invalide :", error)
            print("    Utilisation du domaine principal.")
            sni = domain
    else:
        sni = domain

    print("SNI utilisé :", sni)

    print("\nInitialisation du moteur local du téléphone...")

    try:
        engine = DeviceDiagnosticEngine(
            target=domain,
            server_hostname=sni,
        )

        print("Moteur central : initialisé.")
        print("\nDébut du diagnostic...")

        report = engine.run()

        for result in report.results:
            show_result(result, mode)

        if mode == "2":
            ct_result = next(
                (
                    result for result in report.results
                    if result.name == "subdomain_ct"
                ),
                None,
            )

            if ct_result and ct_result.evidence:
                browse_ct_results(ct_result)

        print('\nInterprétation complémentaire du diagnostic...')
        ReportInterpreter(report).display(mode)

        final_report(report, mode)

    except KeyboardInterrupt:
        print("\n[!] Diagnostic interrompu par l'utilisateur.")

    except Exception as error:
        print("\n[ERREUR] Le diagnostic n'a pas pu être terminé.")

        if mode == "2":
            print("Détail technique :", repr(error))

        print(
            "Vérifie les modules et la connexion, "
            "puis réessaie."
        )


if __name__ == "__main__":
    main()
