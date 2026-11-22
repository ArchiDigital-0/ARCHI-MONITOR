"""Moteur indépendant du module ZERO-RATING LAB."""

import ipaddress
import re
import socket
import time
import http.client
import ssl
from urllib.parse import urljoin, urlsplit

from core.results import DiagnosticReport, TestResult, TestStatus
from diagnostics.test_context import (
    TestContext,
    TestEnvironment,
    ConnectionType,
)

from modules.dns_analyzer import DNSAnalyzer
from modules.ip_auditor import IPAuditor
from modules.tcp_analyzer import TCPAnalyzer
from modules.tls_analyzer import TLSAnalyzer
from modules.http_analyzer import HTTPAnalyzer


class ZeroRatingAnalyzer:
    """Analyse une cible à partir de SNI, IP, port et Host."""

    def __init__(self, sni, ip, port, host):
        self.target = self.validate_inputs(sni, ip, port, host)

    @staticmethod
    def valid_hostname(value):
        if not isinstance(value, str):
            return False

        value = value.strip()

        if not value or len(value) > 253:
            return False

        if any(char.isspace() for char in value):
            return False

        if any(char in value for char in "/\\:@?#"):
            return False

        try:
            value = value.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return False

        pattern = re.compile(
            r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$"
        )

        labels = value.split(".")

        return all(
            label and len(label) <= 63 and pattern.fullmatch(label)
            for label in labels
        )

    @classmethod
    def validate_inputs(cls, sni, ip, port, host):
        """Valide tous les champs sans effectuer de requête réseau."""

        errors = []
        normalized = {}

        if cls.valid_hostname(sni):
            normalized["sni"] = sni.strip().rstrip(".").lower()
        else:
            errors.append("SNI : nom de domaine invalide.")

        try:
            if not isinstance(ip, str) or not ip.strip():
                raise ValueError
            normalized["ip"] = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            errors.append("IP : adresse IPv4 ou IPv6 invalide.")

        try:
            if isinstance(port, bool):
                raise ValueError
            normalized_port = int(str(port).strip())
            if not 1 <= normalized_port <= 65535:
                raise ValueError
            normalized["port"] = normalized_port
        except (ValueError, TypeError):
            errors.append("PORT : nombre entier entre 1 et 65535 requis.")

        if isinstance(host, str) and host.strip():
            host_value = host.strip()
            try:
                normalized["host"] = str(ipaddress.ip_address(host_value))
            except ValueError:
                if cls.valid_hostname(host_value):
                    normalized["host"] = host_value.rstrip(".").lower()
                else:
                    errors.append("HOST : nom d'hôte ou adresse IP invalide.")
        else:
            errors.append("HOST : champ obligatoire.")

        if errors:
            raise ValueError("\n".join(errors))

        return normalized

    @staticmethod
    def _classify_ip(value):
        """Identifie la catégorie technique d'une adresse IPv4 ou IPv6."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return {
                "address": str(value),
                "version": None,
                "category": "invalid",
                "is_global": False,
            }

        if address.is_loopback:
            category = "loopback"
        elif address.is_link_local:
            category = "link_local"
        elif address.is_multicast:
            category = "multicast"
        elif address.is_unspecified:
            category = "unspecified"
        elif address.is_reserved:
            category = "reserved"
        elif address.is_private:
            category = "private"
        elif address.is_global:
            category = "public"
        else:
            category = "special"

        return {
            "address": str(address),
            "version": address.version,
            "category": category,
            "is_global": address.is_global,
        }

    @staticmethod
    def _is_safe_redirect_ip(value):
        """Accepte uniquement les adresses IP publiques et globales."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False

        return (
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
        )

    @classmethod
    def _resolve_redirect_host(cls, hostname, port):
        """Résout et classe les IP sans confondre résolution et autorisation."""
        try:
            results = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as error:
            return {
                "resolved": False,
                "addresses": [],
                "address_details": [],
                "connectable": False,
                "error": str(error),
            }

        addresses = sorted({
            item[4][0]
            for item in results
        })

        if not addresses:
            return {
                "resolved": False,
                "addresses": [],
                "address_details": [],
                "connectable": False,
                "error": "Aucune adresse IP obtenue.",
            }

        address_details = [
            cls._classify_ip(address)
            for address in addresses
        ]

        connectable = all(
            cls._is_safe_redirect_ip(address)
            for address in addresses
        )

        return {
            "resolved": True,
            "addresses": addresses,
            "address_details": address_details,
            "connectable": connectable,
            "error": None,
            "blocked_reason": (
                None if connectable
                else "Destination non publique détectée ; destination enregistrée ; aucune connexion effectuée."
            ),
        }

    @classmethod
    def _request_redirect_target(
        cls, hostname, destination_ip, port, scheme, path
    ):
        """Envoie une requête HEAD vers une IP publique déjà vérifiée."""
        if scheme not in ("http", "https"):
            raise ValueError("Protocole de redirection non autorisé.")

        host = hostname.encode("idna").decode("ascii")

        try:
            address = ipaddress.ip_address(hostname)
            if address.version == 6:
                host = f"[{host}]"
        except ValueError:
            pass

        default_port = 443 if scheme == "https" else 80
        host_header = host
        if port != default_port:
            host_header = f"{host_header}:{port}"

        request_path = path or "/"
        request = (
            f"HEAD {request_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: ARCHI-MONITOR/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        connection = socket.create_connection(
            (destination_ip, port),
            timeout=8.0,
        )

        try:
            if scheme == "https":
                context = ssl.create_default_context()
                connection = context.wrap_socket(
                    connection,
                    server_hostname=hostname,
                )

            connection.sendall(request.encode("ascii"))

            response = http.client.HTTPResponse(connection)
            response.begin()

            return {
                "status_code": response.status,
                "reason": response.reason,
                "headers": dict(response.getheaders()),
                "redirect_location": response.getheader("Location"),
                "http_version": response.version,
            }
        finally:
            connection.close()

    @classmethod
    def _follow_redirects(cls, initial_url, initial_location, max_redirects=5):
        """Suit prudemment une chaîne de redirections HTTP(S)."""
        history = []
        visited = {initial_url}
        current_url = initial_url
        location = initial_location
        stop_reason = None

        result = {
            "redirect_history": history,
            "redirect_hops": 0,
            "redirect_destinations_detected": 0,
            "redirect_requests_attempted": 0,
            "redirect_responses_received": 0,
            "redirect_followed": False,
            "final_url": initial_url,
            "final_destination_host": None,
            "final_destination_ip": None,
            "final_status_code": None,
            "final_reason": None,
            "final_headers": {},
            "redirect_stop_reason": None,
        }

        for hop in range(1, max_redirects + 1):
            if not location:
                stop_reason = "En-tête Location absent."
                break

            try:
                target_url = urljoin(current_url, location)
                parsed = urlsplit(target_url)
                scheme = parsed.scheme.lower()
                hostname = parsed.hostname
                port = parsed.port
            except ValueError:
                stop_reason = "URL de redirection invalide."
                break

            if scheme not in ("http", "https"):
                stop_reason = "Protocole de redirection non autorisé."
                break

            if not hostname or parsed.username is not None or parsed.password is not None:
                stop_reason = "Nom d'hôte absent ou identifiants interdits."
                break

            default_port = 443 if scheme == "https" else 80
            port = port or default_port

            if port != default_port:
                stop_reason = "Port de redirection non autorisé."
                break

            normalized_url = parsed._replace(fragment="").geturl()

            if normalized_url in visited:
                stop_reason = "Boucle de redirection détectée."
                break

            visited.add(normalized_url)
            result["redirect_destinations_detected"] += 1
            result["redirect_hops"] = result["redirect_destinations_detected"]

            request_path = parsed.path or "/"
            if parsed.query:
                request_path += "?" + parsed.query

            if "\\r" in request_path or "\\n" in request_path:
                stop_reason = "Chemin HTTP invalide."
                break

            try:
                address = ipaddress.ip_address(hostname)
                addresses = [str(address)]
                address_details = [cls._classify_ip(address)]
                connectable = cls._is_safe_redirect_ip(address)
                resolution = {
                    "resolved": True,
                    "addresses": addresses,
                    "address_details": address_details,
                    "connectable": connectable,
                    "error": None,
                    "blocked_reason": (
                        None if connectable
                        else "Destination non publique détectée ; destination enregistrée ; aucune connexion effectuée."
                    ),
                }
            except ValueError:
                resolution = cls._resolve_redirect_host(hostname, port)
                addresses = resolution["addresses"]
                address_details = resolution["address_details"]

            if not resolution["resolved"] or not resolution["connectable"]:
                reason = (
                    resolution.get("error")
                    or resolution.get("blocked_reason")
                    or "Suivi actif non autorisé."
                )
                history.append({
                    "url": normalized_url,
                    "hostname": hostname,
                    "port": port,
                    "scheme": scheme,
                    "resolved_ips": addresses,
                    "address_details": address_details,
                    "connectable": resolution["connectable"],
                    "connected_ip": None,
                    "error": reason,
                })
                stop_reason = reason
                break

            response_data = None
            connected_ip = None
            request_error = None

            for address in addresses:
                try:
                    result["redirect_requests_attempted"] += 1
                    response_data = cls._request_redirect_target(
                        hostname,
                        address,
                        port,
                        scheme,
                        request_path,
                    )
                    connected_ip = address
                    break
                except (OSError, ssl.SSLError, http.client.HTTPException,
                        UnicodeError) as error:
                    request_error = str(error)

            if response_data is None:
                history.append({
                    "url": normalized_url,
                    "hostname": hostname,
                    "port": port,
                    "scheme": scheme,
                    "resolved_ips": addresses,
                    "address_details": address_details,
                    "connectable": True,
                    "connected_ip": None,
                    "error": request_error or "Connexion impossible.",
                })
                stop_reason = "Aucune adresse résolue n'a répondu."
                break

            entry = {
                "url": normalized_url,
                "hostname": hostname,
                "port": port,
                "scheme": scheme,
                "resolved_ips": addresses,
                "address_details": address_details,
                "connectable": True,
                "connected_ip": connected_ip,
                **response_data,
            }
            history.append(entry)
            result["redirect_responses_received"] += 1

            result.update({
                "redirect_followed": True,
                "final_url": normalized_url,
                "final_destination_host": hostname,
                "final_destination_ip": connected_ip,
                "final_status_code": response_data["status_code"],
                "final_reason": response_data["reason"],
                "final_headers": response_data["headers"],
            })

            if not (
                300 <= response_data["status_code"] < 400
                and response_data["redirect_location"]
            ):
                stop_reason = "Réponse finale reçue."
                break

            current_url = normalized_url
            location = response_data["redirect_location"]
        else:
            stop_reason = "Limite maximale de redirections atteinte."

        result["redirect_stop_reason"] = stop_reason
        return result

    @staticmethod
    def error_result(name, error):
        return TestResult(
            name=name,
            status=TestStatus.ERROR,
            summary="Erreur pendant cette analyse.",
            error_code="ZERO_RATING_ANALYSIS_ERROR",
            error_message=str(error),
        )

    @staticmethod
    def classify_http_response(status_code, reason, headers):
        """Classe une réponse HTTP sans effectuer de connexion réseau."""

        if 200 <= status_code <= 299:
            application_status = "SUCCESS"
            overall_status = TestStatus.PASSED
        elif 300 <= status_code <= 399:
            application_status = "REDIRECT"
            overall_status = TestStatus.WARNING
        elif status_code == 403:
            application_status = "FORBIDDEN"
            overall_status = TestStatus.WARNING
        elif status_code == 404:
            application_status = "NOT_FOUND"
            overall_status = TestStatus.WARNING
        elif 500 <= status_code <= 599:
            application_status = "SERVER_ERROR"
            overall_status = TestStatus.WARNING
        else:
            application_status = "HTTP_RESPONSE"
            overall_status = TestStatus.WARNING

        return {
            "status": overall_status,
            "transport_status": "PASSED",
            "application_status": application_status,
            "http_status_code": status_code,
            "http_reason": reason,
            "server": headers.get("Server") or headers.get("server"),
        }

    def domain_discovery(self):
        names = list(dict.fromkeys([
            self.target["sni"],
            self.target["host"],
        ]))

        return TestResult(
            name="domain_discovery",
            status=TestStatus.WARNING,
            summary="Noms SNI et Host recensés.",
            details=(
                "Les noms fournis sont identifiés. "
                "Aucune énumération externe de domaines n'a été effectuée."
            ),
            evidence={
                "candidate_names": names,
                "source": "user_input",
                "external_discovery_performed": False,
            },
            limitations=[
                "Cette étape recense les noms saisis sans découvrir "
                "de nouveaux domaines ou sous-domaines."
            ],
        )

    def dns_ip_analysis(self):
        names = list(dict.fromkeys([
            self.target["sni"],
            self.target["host"],
        ]))

        dns_results = []
        addresses = []
        dns_statuses = []

        for name in names:
            try:
                result = DNSAnalyzer().analyze(name)
            except Exception as error:
                result = self.error_result("dns", error)

            dns_statuses.append(result.status)

            ipv4 = result.evidence.get("ipv4", [])
            ipv6 = result.evidence.get("ipv6", [])

            addresses.extend(ipv4 + ipv6)

            dns_results.append({
                "domain": name,
                "status": result.status.value,
                "summary": result.summary,
                "ipv4": ipv4,
                "ipv6": ipv6,
            })

        addresses = list(dict.fromkeys([self.target["ip"]] + addresses))

        try:
            ip_result = IPAuditor().analyze(addresses)
        except Exception as error:
            ip_result = self.error_result("ip", error)

        matching_names = [
            item["domain"]
            for item in dns_results
            if self.target["ip"] in item["ipv4"] + item["ipv6"]
        ]

        if all(status == TestStatus.FAILED for status in dns_statuses):
            dns_status = TestStatus.FAILED
        elif all(status == TestStatus.ERROR for status in dns_statuses):
            dns_status = TestStatus.ERROR
        elif any(
            status in (TestStatus.FAILED, TestStatus.ERROR)
            for status in dns_statuses
        ):
            dns_status = TestStatus.WARNING
        elif any(status == TestStatus.WARNING for status in dns_statuses):
            dns_status = TestStatus.WARNING
        else:
            dns_status = TestStatus.PASSED

        if TestStatus.ERROR in (dns_status, ip_result.status):
            status = TestStatus.ERROR
        elif TestStatus.FAILED in (dns_status, ip_result.status):
            status = TestStatus.FAILED
        elif (
            TestStatus.WARNING in (dns_status, ip_result.status)
            or (dns_status == TestStatus.PASSED and not matching_names)
        ):
            status = TestStatus.WARNING
        else:
            status = TestStatus.PASSED

        return TestResult(
            name="dns_ip_analysis",
            status=status,
            summary="Analyse DNS et IP terminée.",
            details="Résolution des noms et classification des adresses.",
            evidence={
                "dns_results": dns_results,
                "ip_analysis": ip_result.evidence,
                "target_ip": self.target["ip"],
                "resolved_addresses": addresses[1:],
                "target_ip_matches_names": matching_names,
            },
            limitations=[
                "La résolution utilise le résolveur système.",
                "Une correspondance DNS ne prouve pas la joignabilité.",
                "Une IP publique ne prouve pas le zero-rating.",
            ],
        )

    def sni_tls_analysis(self):
        """Contrôle TCP et TLS selon le protocole associé au port."""

        try:
            tcp = TCPAnalyzer().analyze(
                self.target["ip"],
                self.target["port"],
            )
        except Exception as error:
            tcp = self.error_result("tcp", error)

        if tcp.status != TestStatus.PASSED:
            return TestResult(
                name="sni_tls_analysis",
                status=tcp.status,
                summary="Connexion TCP impossible ou non vérifiée.",
                details="L'analyse TLS n'a pas été lancée.",
                evidence={
                    "tcp_status": tcp.status.value,
                    "tcp_summary": tcp.summary,
                    "destination_ip": self.target["ip"],
                    "port": self.target["port"],
                    "sni": self.target["sni"],
                    "tls_attempted": False,
                },
                error_code=tcp.error_code,
                error_message=tcp.error_message,
                limitations=[
                    "La connexion TCP est une étape préalable à TLS."
                ],
            )

        if self.target["port"] == 80:
            return TestResult(
                name="sni_tls_analysis",
                status=TestStatus.WARNING,
                summary="Connexion TCP établie ; TLS non applicable.",
                details=(
                    "Le port 80 est traité comme une connexion HTTP "
                    "classique. Aucune négociation TLS n'a été tentée."
                ),
                evidence={
                    "tcp_status": tcp.status.value,
                    "tcp_summary": tcp.summary,
                    "tls_status": "not_applicable",
                    "tls_attempted": False,
                    "destination_ip": self.target["ip"],
                    "port": 80,
                    "sni": self.target["sni"],
                },
                limitations=[
                    "Le protocole HTTP classique ne réalise pas de "
                    "négociation TLS.",
                    "Une connexion TCP réussie ne prouve pas le zero-rating.",
                ],
            )

        if self.target["port"] != 443:
            return TestResult(
                name="sni_tls_analysis",
                status=TestStatus.WARNING,
                summary="Connexion TCP établie ; protocole indéterminé.",
                details=(
                    "Le port utilisé est personnalisé. Le moteur ne "
                    "suppose pas qu'il utilise TLS."
                ),
                evidence={
                    "tcp_status": tcp.status.value,
                    "tls_status": "not_tested",
                    "tls_attempted": False,
                    "destination_ip": self.target["ip"],
                    "port": self.target["port"],
                    "sni": self.target["sni"],
                },
                limitations=[
                    "Le protocole du port personnalisé doit être connu "
                    "avant de lancer une analyse applicative."
                ],
            )

        try:
            tls = TLSAnalyzer().analyze(
                domain=self.target["sni"],
                port=443,
                server_hostname=self.target["sni"],
                destination_ip=self.target["ip"],
            )
        except Exception as error:
            tls = self.error_result("tls", error)

        return TestResult(
            name="sni_tls_analysis",
            status=tls.status,
            summary="Contrôle TCP et négociation TLS exécutés.",
            details=tls.summary,
            duration_ms=tls.duration_ms,
            evidence={
                "tcp_status": tcp.status.value,
                "tcp_summary": tcp.summary,
                "tls_status": tls.status.value,
                "tls_evidence": tls.evidence,
                "destination_ip": self.target["ip"],
                "port": 443,
                "sni": self.target["sni"],
            },
            error_code=tls.error_code,
            error_message=tls.error_message,
            limitations=tls.limitations + [
                "Une négociation TLS réussie ne prouve pas le zero-rating."
            ],
        )

    def http_analysis(self):
        """Analyse HTTP classique sur 80 et HTTPS sur 443."""

        port = self.target["port"]

        if port not in (80, 443):
            return TestResult(
                name="http_analysis",
                status=TestStatus.WARNING,
                summary="Analyse HTTP non exécutée.",
                details=(
                    "Le protocole du port personnalisé n'est pas "
                    "déterminé automatiquement."
                ),
                evidence={
                    "destination_ip": self.target["ip"],
                    "port": port,
                    "sni": self.target["sni"],
                    "host_header": self.target["host"],
                    "protocol": "unknown",
                },
                limitations=[
                    "Aucune requête applicative n'est envoyée sur un "
                    "port dont le protocole est inconnu."
                ],
            )

        if port == 443:
            try:
                result = HTTPAnalyzer().analyze(
                    domain=self.target["sni"],
                    destination_ip=self.target["ip"],
                    server_hostname=self.target["sni"],
                    host_header=self.target["host"],
                    port=443,
                )
            except Exception as error:
                return self.error_result("http_analysis", error)

            evidence = {
                **result.evidence,
                "destination_ip": self.target["ip"],
                "sni": self.target["sni"],
                "host_header": self.target["host"],
                "port": 443,
                "protocol": "HTTPS",
            }

            status_code = evidence.get("status_code")

            if status_code is not None:
                headers = evidence.get("headers") or {}
                classification = self.classify_http_response(
                    status_code,
                    evidence.get("reason", ""),
                    headers,
                )
                evidence.update({
                    "transport_status": classification["transport_status"],
                    "application_status": classification["application_status"],
                    "http_status_code": classification["http_status_code"],
                    "http_reason": classification["http_reason"],
                    "server": classification["server"],
                })
                overall_status = classification["status"]
            else:
                evidence.update({
                    "transport_status": "FAILED",
                    "application_status": "NOT_RECEIVED",
                })
                overall_status = result.status

            redirect_location = evidence.get("redirect_location")
            redirect_detected = (
                status_code is not None
                and 300 <= status_code < 400
                and bool(redirect_location)
            )

            initial_host = self.target["host"]
            try:
                initial_address = ipaddress.ip_address(initial_host)
                if initial_address.version == 6:
                    initial_host = f"[{initial_host}]"
            except ValueError:
                pass

            initial_url = f"https://{initial_host}/"

            redirect_trace = {
                "redirect_detected": redirect_detected,
                "redirect_history": [],
                "redirect_hops": 0,
                "redirect_destinations_detected": 0,
                "redirect_requests_attempted": 0,
                "redirect_responses_received": 0,
                "redirect_followed": False,
                "final_url": initial_url,
                "final_destination_host": None,
                "final_destination_ip": None,
                "final_status_code": None,
                "final_reason": None,
                "final_headers": {},
                "redirect_stop_reason": (
                    None if redirect_detected
                    else "Aucune redirection HTTP détectée."
                ),
            }

            if redirect_detected:
                redirect_trace = self._follow_redirects(
                    initial_url,
                    redirect_location,
                )
                redirect_trace["redirect_detected"] = True

            evidence.update(redirect_trace)

            return TestResult(
                name="http_analysis",
                status=overall_status,
                summary=result.summary,
                details=result.details,
                duration_ms=result.duration_ms,
                evidence=evidence,
                error_code=result.error_code,
                error_message=result.error_message,
                limitations=result.limitations + [
                    "Une réponse HTTP ne confirme pas la gratuité "
                    "des données."
                ],
            )

        start = time.perf_counter()

        try:
            with socket.create_connection(
                (self.target["ip"], 80),
                timeout=8.0,
            ) as connection:
                request = (
                    "HEAD / HTTP/1.1\r\n"
                    f"Host: {self.target['host']}\r\n"
                    "User-Agent: ARCHI-MONITOR/1.0\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )

                connection.sendall(request.encode("ascii"))

                response = http.client.HTTPResponse(connection)
                response.begin()

                duration = (time.perf_counter() - start) * 1000
                headers = dict(response.getheaders())

                classification = self.classify_http_response(
                    response.status,
                    response.reason,
                    headers,
                )

                evidence = {
                    "destination_ip": self.target["ip"],
                    "sni": self.target["sni"],
                    "host_header": self.target["host"],
                    "port": 80,
                    "protocol": "HTTP",
                    "http_version": response.version,
                    "status_code": response.status,
                    "reason": response.reason,
                    "headers": headers,
                    "redirect_location": headers.get("Location"),
                    "redirect_followed": False,
                    "transport_status": classification["transport_status"],
                    "application_status": classification["application_status"],
                    "http_status_code": classification["http_status_code"],
                    "http_reason": classification["http_reason"],
                    "server": classification["server"],
                }

                redirect_location = evidence.get("redirect_location")
                redirect_detected = (
                    300 <= response.status < 400
                    and bool(redirect_location)
                )

                initial_host = self.target["host"]
                try:
                    initial_address = ipaddress.ip_address(initial_host)
                    if initial_address.version == 6:
                        initial_host = f"[{initial_host}]"
                except ValueError:
                    pass

                initial_url = f"http://{initial_host}/"

                redirect_trace = {
                    "redirect_detected": redirect_detected,
                    "redirect_history": [],
                    "redirect_hops": 0,
                    "redirect_destinations_detected": 0,
                    "redirect_requests_attempted": 0,
                    "redirect_responses_received": 0,
                    "redirect_followed": False,
                    "final_url": initial_url,
                    "final_destination_host": None,
                    "final_destination_ip": None,
                    "final_status_code": None,
                    "final_reason": None,
                    "final_headers": {},
                    "redirect_stop_reason": (
                        None if redirect_detected
                        else "Aucune redirection HTTP détectée."
                    ),
                }

                if redirect_detected:
                    redirect_trace = self._follow_redirects(
                        initial_url,
                        redirect_location,
                    )
                    redirect_trace["redirect_detected"] = True

                evidence.update(redirect_trace)

                return TestResult(
                    name="http_analysis",
                    status=classification["status"],
                    summary=(
                        f"Réponse HTTP reçue : {response.status} "
                        f"{response.reason}"
                    ),
                    details=response.reason,
                    duration_ms=round(duration, 2),
                    evidence=evidence,
                    limitations=[
                        "Requête HEAD envoyée en HTTP non chiffré.",
                        "La réponse ne représente pas un téléchargement "
                        "complet de la page.",
                        "Les destinations publiques peuvent être suivies ; les destinations privées sont enregistrées sans connexion.",
                        "Une réponse HTTP ne prouve pas le zero-rating.",
                    ],
                )

        except (socket.timeout, OSError, http.client.HTTPException) as error:
            duration = (time.perf_counter() - start) * 1000

            return TestResult(
                name="http_analysis",
                status=TestStatus.FAILED,
                summary="Échec de l'analyse HTTP.",
                details="La requête HTTP classique n'a pas abouti.",
                duration_ms=round(duration, 2),
                error_code="HTTP_ANALYSIS_FAILED",
                error_message=str(error),
                evidence={
                    "destination_ip": self.target["ip"],
                    "sni": self.target["sni"],
                    "host_header": self.target["host"],
                    "port": 80,
                    "protocol": "HTTP",
                    "transport_status": "FAILED",
                    "application_status": "NOT_RECEIVED",
                },
                limitations=[
                    "Une erreur HTTP ne permet pas de conclure sur "
                    "la facturation opérateur."
                ],
            )

    def cross_operator_comparison(self):
        return TestResult(
            name="cross_operator_comparison",
            status=TestStatus.SKIPPED,
            summary="Comparaison entre opérateurs non effectuée.",
            details=(
                "Une seconde mesure sur un autre opérateur est nécessaire."
            ),
            evidence={
                "comparison_available": False,
                "additional_measurement_required": True,
            },
            limitations=[
                "Une seule connexion réseau ne permet pas une comparaison."
            ],
        )

    def analyze(self):
        """Exécute exactement les cinq axes du rapport."""

        report = DiagnosticReport(
            target=self.target["ip"],
            context=TestContext(
                environment=TestEnvironment.DEVICE,
                connection_type=ConnectionType.UNKNOWN,
            ),
            limitations=[
                "Les tests sont exécutés depuis l'appareil local.",
                "Le réseau utilisé est celui de la connexion active.",
                "Les résultats techniques ne prouvent pas la facturation "
                "réelle par l'opérateur.",
                "La confirmation du zero-rating nécessite des mesures "
                "de consommation ou des données opérateur.",
            ],
        )

        report.add_result(self.domain_discovery())
        report.add_result(self.dns_ip_analysis())
        report.add_result(self.sni_tls_analysis())
        report.add_result(self.http_analysis())
        report.add_result(self.cross_operator_comparison())

        return report
