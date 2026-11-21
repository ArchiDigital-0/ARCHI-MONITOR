"""Interprétation complémentaire des rapports ARCHI MONITOR."""

from core.results import TestStatus


class ReportInterpreter:
    """Interprète les résultats sans modifier le rapport original."""

    MODULES = (
        "dns", "tcp", "ip", "rdap",
        "asn", "tls", "http", "subdomain_ct",
    )

    def __init__(self, report):
        self.report = report

    def _get_result(self, name):
        return next(
            (r for r in self.report.results if r.name == name),
            None,
        )

    @staticmethod
    def _status(result):
        return getattr(result.status, "name", str(result.status)).upper()

    @staticmethod
    def _format(value):
        return ", ".join(map(str, value)) if value else "non disponible"

    def analyze(self):
        findings = []

        for name in self.MODULES:
            result = self._get_result(name)

            if result is None:
                findings.append(f"{name.upper()} : aucun résultat disponible.")
                continue

            status = self._status(result)
            evidence = result.evidence or {}

            if status == "SKIPPED":
                findings.append(
                    f"{name.upper()} : analyse ignorée. "
                    f"{result.summary}"
                )
                continue

            if status == "ERROR":
                findings.append(
                    f"{name.upper()} : erreur technique. "
                    f"{result.summary}"
                )
                continue

            if status == "FAILED":
                findings.append(
                    f"{name.upper()} : échec du test. "
                    f"{result.summary}"
                )
                continue

            if name == "dns":
                ipv4 = evidence.get("ipv4", [])
                ipv6 = evidence.get("ipv6", [])

                if status == "PASSED":
                    findings.append(
                        f"DNS : {len(ipv4)} IPv4 et "
                        f"{len(ipv6)} IPv6 obtenues."
                    )
                else:
                    findings.append(
                        f"DNS : aucune adresse exploitable. "
                        f"{result.summary}"
                    )

            elif name == "tcp":
                if status == "PASSED":
                    findings.append(
                        "TCP : connexion établie vers "
                        f"{evidence.get('destination_ip', 'destination inconnue')}"
                        f", port {evidence.get('port', '?')}."
                    )
                else:
                    findings.append(
                        f"TCP : résultat à examiner. {result.summary}"
                    )

            elif name == "ip":
                addresses = evidence.get("addresses", [])
                global_count = sum(
                    1 for item in addresses if item.get("is_global")
                )
                private_count = sum(
                    1 for item in addresses if item.get("is_private")
                )
                invalid = evidence.get("invalid_addresses", [])
                duplicates = evidence.get("duplicates", [])

                findings.append(
                    f"IP : {len(addresses)} adresse(s) valide(s), "
                    f"{global_count} globale(s), "
                    f"{private_count} privée(s), "
                    f"{len(invalid)} invalide(s), "
                    f"{len(duplicates)} doublon(s)."
                )

            elif name == "rdap":
                if status == "PASSED":
                    network = evidence.get("network", {})
                    findings.append(
                        "RDAP : attribution récupérée. "
                        f"Réseau : {network.get('name') or network.get('handle') or 'non précisé'} ; "
                        f"pays déclaré : {network.get('country') or 'non précisé'} ; "
                        f"plages : {self._format(network.get('cidr0_cidrs', []))}."
                    )
                else:
                    findings.append(
                        f"RDAP : résultat incomplet. {result.summary}"
                    )

            elif name == "asn":
                if status == "PASSED":
                    findings.append(
                        "ASN : préfixe "
                        f"{evidence.get('prefix') or 'non précisé'} ; "
                        f"ASN d'origine : "
                        f"{self._format(evidence.get('origin_asns', []))}."
                    )
                else:
                    findings.append(
                        f"ASN : aucune annonce exploitable confirmée. "
                        f"{result.summary}"
                    )

            elif name == "tls":
                if status == "PASSED":
                    findings.append(
                        "TLS : connexion validée ; version "
                        f"{evidence.get('tls_version', '?')} ; "
                        f"SNI {evidence.get('sni', '?')} ; "
                        f"certificat validé : "
                        f"{evidence.get('verification', {}).get('certificate_validated', False)}."
                    )
                else:
                    findings.append(
                        f"TLS : résultat à examiner. {result.summary}"
                    )

            elif name == "http":
                if status == "PASSED":
                    code = evidence.get("status_code")
                    if isinstance(code, int):
                        if 200 <= code < 300:
                            interpretation = "réponse HTTP réussie"
                        elif 300 <= code < 400:
                            interpretation = "redirection demandée"
                        elif 400 <= code < 500:
                            interpretation = "requête refusée ou ressource indisponible"
                        elif 500 <= code < 600:
                            interpretation = "erreur du serveur"
                        else:
                            interpretation = "code HTTP à examiner"
                    else:
                        interpretation = "réponse reçue"

                    findings.append(
                        f"HTTP : {interpretation} "
                        f"(code {code})."
                    )

                    if evidence.get("redirect_location"):
                        findings.append(
                            "HTTP : redirection annoncée vers "
                            f"{evidence['redirect_location']} ; "
                            "elle n'a pas été suivie."
                        )
                else:
                    findings.append(
                        f"HTTP : résultat à examiner. {result.summary}"
                    )

            elif name == "subdomain_ct":
                count = evidence.get("subdomain_count", 0)
                certificates = evidence.get(
                    "certificate_record_count", 0
                )
                wildcards = evidence.get("wildcard_count", 0)
                incomplete = evidence.get(
                    "pagination_incomplete", False
                )

                findings.append(
                    f"CT : {count} sous-domaine(s), "
                    f"{certificates} certificat(s), "
                    f"{wildcards} joker(s) recensés."
                )

                if incomplete:
                    findings.append(
                        "CT : pagination incomplète ; "
                        "d'autres résultats peuvent exister."
                    )

                if evidence.get("source_error"):
                    findings.append(
                        "CT : erreur de source : "
                        f"{evidence['source_error']}"
                    )

        # Interprétation croisée des dépendances
        dns = self._get_result("dns")
        tcp = self._get_result("tcp")
        tls = self._get_result("tls")
        http = self._get_result("http")

        if dns and self._status(dns) == "FAILED":
            findings.append(
                "DÉPENDANCE : l'échec DNS peut expliquer "
                "l'absence de certaines analyses réseau."
            )

        if tcp and tls:
            if (
                self._status(tcp) == "PASSED"
                and self._status(tls) == "FAILED"
            ):
                findings.append(
                    "CROISEMENT : TCP fonctionne, mais TLS échoue. "
                    "Le problème peut se situer au niveau TLS "
                    "ou de la validation du certificat."
                )

        if tls and http:
            if (
                self._status(tls) == "PASSED"
                and self._status(http) == "FAILED"
            ):
                findings.append(
                    "CROISEMENT : TLS est validé, mais la requête "
                    "HTTP échoue."
                )

        findings.append(
            "LIMITE : ces résultats ne prouvent ni la gratuité "
            "des données mobiles, ni la sécurité globale du réseau."
        )

        return findings

    def display(self, mode="1"):
        findings = self.analyze()

        print("\n" + "=" * 62)
        print("          INTERPRÉTATION DU DIAGNOSTIC")
        print("=" * 62)

        for finding in findings:
            print("-", finding)

        if mode == "2":
            print("\n===== INFORMATIONS EXPERT =====")
            for name in self.MODULES:
                result = self._get_result(name)
                if result is None:
                    continue

                print(f"\n[{name.upper()}]")
                print("Statut :", self._status(result))
                print("Résumé :", result.summary)

                if result.error_code:
                    print("Code erreur :", result.error_code)

                if result.evidence:
                    print("Preuves :", result.evidence)

                for limitation in result.limitations:
                    print("Limite :", limitation)

            print(
                "\nConclusion générale :",
                self.report.conclusion.value,
            )

        print("=" * 62)
