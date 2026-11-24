"""Centre de contrôle du module SERVER INTELLIGENCE."""

from urllib.parse import urlsplit

from modules.server_intelligence.config import (
    ServerIntelligenceConfig,
    normalize_domain,
)
from modules.server_intelligence.connector_loader import run_discovery
from modules.server_intelligence.web_audit.orchestrator import (
    ServerIntelligenceOrchestrator,
)


def _pause():
    input("\nAppuie sur Entrée pour revenir au menu SERVER INTELLIGENCE...")


def _confirm_external_operation(description):
    print("\nAUTORISATION REQUISE")
    print(description)
    print("Cette opération peut communiquer avec des services externes.")
    return input("Pour continuer, saisis OUI : ").strip().upper() == "OUI"


def _read_domain():
    value = input("Domaine cible (ex. example.com) : ").strip()
    return normalize_domain(value)


def _run_passive_discovery():
    print("\n===== DÉCOUVERTE PASSIVE MULTI-SOURCES =====")
    domain = _read_domain()
    print(f"Cible : {domain}")

    if not _confirm_external_operation(
        "Les fournisseurs configurés seront interrogés pour rechercher "
        "des informations publiquement accessibles sur ce domaine."
    ):
        print("Opération annulée. Aucune source n'a été interrogée.")
        return

    config = ServerIntelligenceConfig(
        target_domain=domain,
        passive_discovery_enabled=True,
        active_audit_enabled=False,
        active_audit_authorized=False,
    )

    report = run_discovery(config)

    print("\n===== RÉSULTAT DE LA DÉCOUVERTE =====")
    print("Domaine :", report.target_domain)
    print("Fournisseurs :", report.source_count)
    print("Preuves brutes :", report.raw_evidence_count)
    print("Observations :", report.observation_count)
    print("Bilan des exécutions :")

    for status, count in report.execution_summary().items():
        print(f"  - {status} : {count}")

    if report.limitations:
        print("\nLimitations :")
        for limitation in report.limitations:
            print("  -", limitation)

    print("\nAucun fichier de rapport n'a été créé.")


def _run_web_audit():
    print("\n===== AUDIT DE SÉCURITÉ WEB =====")
    target_url = input("URL autorisée (http:// ou https://) : ").strip()

    parsed = urlsplit(target_url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "URL invalide : une adresse HTTP ou HTTPS complète est requise."
        )

    domain = normalize_domain(parsed.hostname)
    print("Domaine du périmètre :", domain)
    print("Méthodes disponibles : GET ou HEAD (aucune autre méthode).")

    method = (
        input("Méthode [GET/HEAD] (défaut : GET) : ").strip().upper()
        or "GET"
    )
    if method not in ("GET", "HEAD"):
        raise ValueError(
            "Méthode refusée : seules GET et HEAD sont autorisées."
        )

    print(
        "\nConfirme que tu possèdes cette cible "
        "ou que tu as reçu l'autorisation de l'auditer."
    )

    if not _confirm_external_operation(
        "L'audit enverra une requête HTTP(S) limitée à la cible et "
        "suivra uniquement les redirections autorisées par le périmètre."
    ):
        print("Audit annulé. Aucune requête n'a été envoyée.")
        return

    orchestrator = ServerIntelligenceOrchestrator(
        target_domain=domain,
        authorized_domains=(domain,),
    )
    result = orchestrator.run(target_url, method=method)

    print("\n===== RAPPORT D'AUDIT WEB =====")
    print(orchestrator.export_text(result))

    print("\nLIMITATION TLS")
    print(
        "L'orchestrateur actuel ne collecte pas encore lui-même "
        "le certificat TLS. La validation réelle du certificat "
        "doit donc être considérée comme non confirmée."
    )
    print("Aucun fichier de rapport n'a été créé.")


def show_menu():
    print("\n" + "=" * 58)
    print("             ARCHI MONITOR — SERVER INTELLIGENCE")
    print("=" * 58)
    print("[1] Découverte passive multi-sources")
    print("[2] Audit de sécurité Web autorisé")
    print("[0] Retour au centre de contrôle")


def main():
    while True:
        show_menu()
        choice = input("Sélectionne une opération : ").strip()

        if choice == "0":
            return

        if choice not in ("1", "2"):
            print("Sélection invalide.")
            continue

        try:
            if choice == "1":
                _run_passive_discovery()
            else:
                _run_web_audit()

        except KeyboardInterrupt:
            print("\nOpération interrompue par l'utilisateur.")

        except Exception as exc:
            print("\n[ERREUR] L'opération n'a pas pu aboutir.")
            print(f"Détail : {type(exc).__name__}: {exc}")

        _pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSERVER INTELLIGENCE interrompu par l'utilisateur.")
