import socket
import ssl
import time
import re
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

VERSION = "1.2"
PORT = 443
TIMEOUT = 12

RESULTS = {}


def line():
    print("=" * 58)


def banner():
    line()
    print("              ARCHI MONITOR v" + VERSION)
    print("                 ARCHI DIGITAL")
    print("          NETWORK DIAGNOSTICS & LEARNING")
    line()


def validate_domain(raw):
    raw = raw.strip()

    if not raw or any(c.isspace() for c in raw):
        raise ValueError("Saisie vide ou contenant des espaces.")

    if "://" not in raw:
        raw = "//" + raw

    parsed = urlsplit(raw)

    if parsed.username or parsed.password or parsed.port:
        raise ValueError("Ne saisis pas de port ou d'identifiants.")

    domain = parsed.hostname

    if not domain:
        raise ValueError("Nom de domaine introuvable.")

    domain = domain.rstrip(".").encode("idna").decode("ascii").lower()

    if len(domain) > 253:
        raise ValueError("Nom de domaine trop long.")

    labels = domain.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
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
            print("    Exemple : github.com\n")


def choose_mode():
    print("\nCHOISIS TON MODE")
    print("[1] Débutant : explications simples")
    print("[2] Expert   : détails techniques")

    while True:
        choice = input("\nTon choix [1/2] : ").strip()

        if choice in ("1", "2"):
            return choice

        print("Choix invalide. Tape 1 ou 2.")


def show_result(name, success, beginner_message, expert_message=None):
    RESULTS[name] = success

    if success:
        print("\n[OK] " + name + " : RÉUSSI")
    else:
        print("\n[!] " + name + " : ÉCHEC OU ANOMALIE")

    print("    " + beginner_message)

    if MODE == "2" and expert_message:
        print("    Détail technique :", expert_message)


def dns_analysis(domain):
    print("\n[1] ANALYSE DNS")
    start = time.perf_counter()

    try:
        records = socket.getaddrinfo(
            domain, PORT, type=socket.SOCK_STREAM
        )

        ipv4 = sorted(set(
            item[4][0] for item in records
            if item[0] == socket.AF_INET
        ))

        ipv6 = sorted(set(
            item[4][0] for item in records
            if item[0] == socket.AF_INET6
        ))

        elapsed = time.perf_counter() - start

        for ip in ipv4:
            print("    IPv4 :", ip)

        for ip in ipv6:
            print("    IPv6 :", ip)

        total = len(ipv4) + len(ipv6)

        show_result(
            "DNS",
            total > 0,
            (
                f"Le domaine a été traduit en {total} adresse(s) IP. "
                "Ton appareil a trouvé les adresses du serveur."
            ),
            f"IPv4={len(ipv4)}, IPv6={len(ipv6)}, durée={elapsed:.3f}s"
        )

        print(f"    Temps DNS : {elapsed:.3f} seconde(s)")
        return total > 0

    except socket.gaierror as error:
        show_result(
            "DNS", False,
            "Impossible de trouver une adresse IP pour ce domaine. "
            "Vérifie le nom ou ta connexion Internet.",
            str(error)
        )
        return False


def tcp_analysis(domain):
    print("\n[2] TEST DE CONNEXION TCP")
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (domain, PORT), timeout=TIMEOUT
        ):
            elapsed = time.perf_counter() - start

        show_result(
            "TCP", True,
            "Ton appareil a réussi à joindre le serveur sur le port "
            "443, utilisé habituellement pour HTTPS.",
            f"Port={PORT}, durée={elapsed:.3f}s"
        )

        print(f"    Temps de connexion : {elapsed:.3f} seconde(s)")
        return True

    except OSError as error:
        show_result(
            "TCP", False,
            "Ton appareil n'a pas réussi à établir la connexion. "
            "Le serveur peut être inaccessible ou le port bloqué.",
            str(error)
        )
        return False


def certificate_name(value):
    parts = []

    for group in value or ():
        for key, item in group:
            parts.append(f"{key}={item}")

    return ", ".join(parts) if parts else "Non disponible"


def tls_analysis(domain, sni):
    print("\n[3] ANALYSE TLS ET CERTIFICAT")
    start = time.perf_counter()

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, PORT), timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=sni
            ) as secure:

                elapsed = time.perf_counter() - start
                cert = secure.getpeercert()

                print("    Version TLS :", secure.version())
                print("    Chiffrement :", secure.cipher()[0])

                expiry = cert.get("notAfter")
                if expiry:
                    expiry_date = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expiry),
                        tz=timezone.utc
                    )
                    print(
                        "    Expiration du certificat :",
                        expiry_date.strftime("%d/%m/%Y %H:%M UTC")
                    )

                print("    Émetteur :", certificate_name(
                    cert.get("issuer")
                ))

                show_result(
                    "TLS",
                    True,
                    "La connexion sécurisée a été établie. "
                    "Le certificat a été vérifié et correspond au "
                    "nom SNI demandé.",
                    (
                        f"Version={secure.version()}, "
                        f"Cipher={secure.cipher()[0]}, SNI={sni}"
                    )
                )

                if MODE == "2":
                    print("    Sujet :", certificate_name(
                        cert.get("subject")
                    ))

                print(f"    Temps TLS : {elapsed:.3f} seconde(s)")
                return True

    except ssl.SSLCertVerificationError as error:
        show_result(
            "TLS", False,
            "Le certificat n'a pas pu être vérifié. "
            "L'identité du serveur n'est pas validée.",
            str(error)
        )
        return False

    except (ssl.SSLError, OSError) as error:
        show_result(
            "TLS", False,
            "La connexion sécurisée n'a pas pu être établie. "
            "Le serveur a peut-être interrompu la négociation TLS.",
            str(error)
        )
        return False


def http_explanation(status):
    if 200 <= status < 300:
        return (
            "Le serveur a accepté la demande. "
            "C'est généralement un bon signe."
        )

    if 300 <= status < 400:
        return (
            "Le serveur indique une redirection vers une autre adresse."
        )

    if 400 <= status < 500:
        return (
            "Le serveur a répondu, mais la demande n'a pas été acceptée "
            "ou nécessite une condition particulière."
        )

    if 500 <= status < 600:
        return (
            "Le serveur a répondu avec une erreur interne. "
            "Le problème peut venir de son fonctionnement."
        )

    return "Le serveur a renvoyé une réponse HTTP."


def http_analysis(domain):
    print("\n[4] ANALYSE HTTP")
    request = Request(
        "https://" + domain + "/",
        method="HEAD",
        headers={"User-Agent": "ARCHI-MONITOR/" + VERSION}
    )

    start = time.perf_counter()

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            status = response.status
            headers = response.headers
            final_url = response.url

    except HTTPError as error:
        status = error.code
        headers = error.headers
        final_url = error.url

    except (URLError, TimeoutError, OSError) as error:
        show_result(
            "HTTP", False,
            "Aucune réponse HTTP exploitable n'a été reçue. "
            "Vérifie la connexion, le serveur ou sa prise en charge de HTTPS.",
            str(error)
        )
        return False

    elapsed = time.perf_counter() - start

    print("    Code HTTP :", status)
    print("    Adresse finale :", final_url)
    print("    Type de contenu :", headers.get(
        "Content-Type", "Non communiqué"
    ))

    if MODE == "2":
        for key in ("Server", "Date", "Via"):
            if headers.get(key):
                print(f"    {key} : {headers.get(key)}")

    show_result(
        "HTTP",
        True,
        f"Le serveur a répondu avec le code {status}. "
        + http_explanation(status),
        f"HTTP status={status}, durée={elapsed:.3f}s"
    )

    print(f"    Temps total : {elapsed:.3f} seconde(s)")
    return True


def final_report():
    line()
    print("                 RAPPORT FINAL")
    line()

    for name, success in RESULTS.items():
        status = "RÉUSSI" if success else "À EXAMINER"
        print(f"    {name:<8} : {status}")

    successful = sum(RESULTS.values())
    total = len(RESULTS)

    print(f"\n    Résultats : {successful}/{total} tests réussis")

    if successful == total:
        print("\n    DIAGNOSTIC : Tous les tests ont réussi.")
    else:
        print(
            "\n    DIAGNOSTIC : Certains tests nécessitent "
            "une vérification."
        )

    print(
        "\n    Important : un test réussi ne garantit pas "
        "que toutes les fonctions du site sont opérationnelles."
    )
    line()


def main():
    global MODE

    banner()
    MODE = choose_mode()

    domain = ask_domain("\nDomaine ou URL à analyser : ")

    print("\nDomaine sélectionné :", domain)

    sni_input = input(
        "Nom SNI (Entrée pour utiliser le domaine) : "
    ).strip()

    if sni_input:
        sni = ask_domain("Nom SNI à vérifier : ") if sni_input else domain
        # Valide la saisie déjà fournie
        try:
            sni = validate_domain(sni_input)
        except (ValueError, UnicodeError):
            print("SNI invalide. Utilisation du domaine principal.")
            sni = domain
    else:
        sni = domain

    print("SNI utilisé :", sni)
    print("\nDébut du diagnostic...")

    RESULTS.clear()

    dns_analysis(domain)
    tcp_analysis(domain)
    tls_analysis(domain, sni)
    http_analysis(domain)

    final_report()


if __name__ == "__main__":
    MODE = "1"

    try:
        main()
    except KeyboardInterrupt:
        print("\nAnalyse interrompue par l'utilisateur.")
