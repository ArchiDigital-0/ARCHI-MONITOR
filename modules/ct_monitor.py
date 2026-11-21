import json
import time
import http.client
import urllib.request
import urllib.error
from urllib.parse import urlencode

from core.results import TestResult, TestStatus


class CertificateTransparencyMonitor:
    """
    Découverte passive de sous-domaines via Cert Spotter.

    Les noms découverts sont filtrés pour ne conserver
    que ceux qui appartiennent réellement au domaine cible.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_pages: int = 3,
    ):
        self.timeout = timeout
        self.max_pages = max(1, max_pages)
        self.base_url = (
            "https://api.certspotter.com/v1/issuances"
        )

    @staticmethod
    def normalize_domain(domain: str) -> str:
        domain = domain.strip().lower().rstrip(".")

        if not domain:
            raise ValueError("Domaine vide.")

        domain = domain.encode("idna").decode("ascii")

        if len(domain) > 253:
            raise ValueError("Nom de domaine trop long.")

        labels = domain.split(".")

        if len(labels) < 2:
            raise ValueError("Nom de domaine incomplet.")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(
                    char.isalnum() or char == "-"
                    for char in label
                )
            ):
                raise ValueError("Format de domaine invalide.")

        return domain

    @staticmethod
    def normalize_dns_name(raw_name: str):
        name = raw_name.strip().lower().rstrip(".")

        if not name:
            return None, False

        is_wildcard = name.startswith("*.")

        if is_wildcard:
            name = name[2:]

        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None, is_wildcard

        return name, is_wildcard

    def _request_page(self, domain: str, after=None):

        params = {
            "domain": domain,
            "include_subdomains": "true",
            "match_wildcards": "true",
            "expand": "dns_names",
        }

        if after:
            params["after"] = str(after)

        url = self.base_url + "?" + urlencode(params)

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ARCHI-MONITOR/1.0",
            },
        )

        last_error = None

        for attempt in range(2):
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.timeout,
                ) as response:

                    raw_data = response.read(5_000_001)

                    if len(raw_data) > 5_000_000:
                        raise ValueError(
                            "Réponse Cert Spotter trop volumineuse."
                        )

                    records = json.loads(
                        raw_data.decode("utf-8")
                    )

                if not isinstance(records, list):
                    raise ValueError(
                        "Format de réponse Cert Spotter inattendu."
                    )

                return records, url

            except (
                http.client.IncompleteRead,
                urllib.error.URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
            ) as exc:
                last_error = exc

                if attempt == 0:
                    time.sleep(1)

        raise last_error

    def analyze(self, domain: str) -> TestResult:

        start = time.perf_counter()

        try:
            domain = self.normalize_domain(domain)

        except (ValueError, UnicodeError) as exc:
            return TestResult(
                name="subdomain_ct",
                status=TestStatus.ERROR,
                summary="Domaine invalide.",
                error_code="INVALID_DOMAIN",
                error_message=str(exc),
            )

        discovered = set()
        apex_domains = set()
        wildcard_patterns = set()
        certificate_records = []
        seen_certificate_ids = set()

        page_count = 0
        total_records = 0
        next_after = None
        pagination_incomplete = False
        last_url = self.base_url
        source_error = None

        try:
            for page_number in range(self.max_pages):

                try:
                    records, last_url = self._request_page(
                        domain,
                        after=next_after,
                    )

                except (
                    http.client.IncompleteRead,
                    urllib.error.HTTPError,
                    urllib.error.URLError,
                    TimeoutError,
                    OSError,
                    ValueError,
                ) as exc:
                    source_error = str(exc)
                    pagination_incomplete = True
                    break

                page_count += 1
                total_records += len(records)

                if not records:
                    break

                for record in records:

                    if not isinstance(record, dict):
                        continue

                    certificate_id = record.get("id")

                    if (
                        certificate_id is not None
                        and certificate_id in seen_certificate_ids
                    ):
                        continue

                    if certificate_id is not None:
                        seen_certificate_ids.add(certificate_id)

                    raw_names = record.get("dns_names") or []

                    if isinstance(raw_names, str):
                        raw_names = [raw_names]

                    certificate_dns_names = []

                    for raw_name in raw_names:

                        if not isinstance(raw_name, str):
                            continue

                        name, is_wildcard = (
                            self.normalize_dns_name(raw_name)
                        )

                        if not name:
                            continue

                        # Conserver les noms liés au domaine cible
                        # dans la fiche individuelle du certificat.
                        if name == domain or name.endswith("." + domain):
                            display_name = (
                                "*." + name if is_wildcard else name
                            )
                            certificate_dns_names.append(display_name)

                        # Le domaine racine est conservé séparément.
                        if name == domain:
                            if is_wildcard:
                                wildcard_patterns.add(
                                    "*." + name
                                )
                            else:
                                apex_domains.add(name)
                            continue

                        # Exclusion des domaines sans lien
                        # avec le domaine cible.
                        if not name.endswith("." + domain):
                            continue

                        if is_wildcard:
                            wildcard_patterns.add(
                                "*." + name
                            )
                        else:
                            discovered.add(name)

                    certificate_records.append({
                        "id": certificate_id,
                        "not_before": record.get("not_before"),
                        "not_after": record.get("not_after"),
                        "revoked": record.get("revoked"),
                        "cert_sha256": record.get("cert_sha256"),
                        "dns_names": sorted(set(certificate_dns_names)),
                    })

                # Continuer jusqu'à recevoir une page vide.
                last_id = records[-1].get("id")

                if not last_id:
                    pagination_incomplete = True
                    break

                next_after = last_id

                if page_number == self.max_pages - 1:
                    pagination_incomplete = True

            if page_count == 0 and source_error:
                raise OSError(source_error)

            duration = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            subdomains = sorted(discovered)

            limitations = [
                "Les certificats publics ne recensent pas tous les sous-domaines existants.",
                "Un nom découvert ne prouve pas que le sous-domaine est actuellement actif.",
                "Les noms peuvent correspondre à des environnements anciens ou de test.",
                "Les jokers sont conservés séparément et ne sont pas considérés comme des hôtes confirmés.",
                "Les résultats dépendent des certificats publiquement observés par la source.",
            ]

            if pagination_incomplete:
                limitations.append(
                    "La découverte est incomplète : des résultats "
                    "supplémentaires peuvent exister."
                )

            if source_error:
                limitations.append(
                    "Erreur pendant la récupération d'une page : "
                    + source_error
                )

            return TestResult(
                name="subdomain_ct",
                status=TestStatus.WARNING
                if pagination_incomplete
                else TestStatus.PASSED,
                summary=(
                    f"{len(subdomains)} sous-domaine(s) "
                    "découvert(s) via Cert Spotter."
                ),
                details=(
                    "Découverte passive dans les journaux "
                    "publics Certificate Transparency."
                ),
                duration_ms=duration,
                evidence={
                    "target_domain": domain,
                    "source": "Cert Spotter",
                    "source_url": last_url,
                    "subdomains": subdomains,
                    "subdomain_count": len(subdomains),
                    "apex_domains": sorted(apex_domains),
                    "wildcard_patterns": sorted(
                        wildcard_patterns
                    ),
                    "wildcard_count": len(wildcard_patterns),
                    "certificate_record_count": len(
                        certificate_records
                    ),
                    "certificate_records": certificate_records,
                    "pages_requested": page_count,
                    "pagination_incomplete": pagination_incomplete,
                    "source_error": source_error,
                },
                limitations=limitations,
            )

        except urllib.error.HTTPError as exc:
            error_code = f"CT_HTTP_{exc.code}"
            message = str(exc)

        except (
            http.client.IncompleteRead,
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            error_code = "CT_REQUEST_FAILED"
            message = str(exc)

        duration = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        return TestResult(
            name="subdomain_ct",
            status=TestStatus.ERROR,
            summary=(
                "La source Cert Spotter n'a pas pu "
                "fournir les résultats."
            ),
            duration_ms=duration,
            error_code=error_code,
            error_message=message,
            evidence={
                "target_domain": domain,
                "source": "Cert Spotter",
            },
            limitations=[
                "Une erreur réseau temporaire ne signifie pas que la source est hors service.",
                "La découverte devra éventuellement être relancée.",
            ],
        )
