# ARCHI MONITOR

### Network Diagnostics, Server Intelligence & Zero-Rating Research

**Developed by ARCHI DIGITAL**

ARCHI MONITOR is a modular Python network analysis and diagnostic platform designed to investigate network behavior, examine publicly observable infrastructure and analyze mobile network connectivity.

Built primarily for Android and Termux, it provides two operating modes:

- Beginner Mode: simplified explanations of diagnostic results and limitations.
- Expert Mode: technical evidence and detailed diagnostic information.

ARCHI MONITOR is an experimental project under active development.

---

## 1. CORE FEATURES

### Network Diagnostics

- DNS resolution and IP analysis
- TCP connectivity analysis
- RDAP registration information
- ASN and network infrastructure analysis
- TLS negotiation and certificate inspection
- HTTP and HTTPS analysis
- Certificate Transparency monitoring
- Mobile network diagnostics
- Network quality monitoring

### SERVER INTELLIGENCE

A multi-source infrastructure discovery and authorized web-audit module.

Discovery connectors include:

- crt.sh
- HackerTarget
- Cert Spotter
- CT Logs
- Merklemap
- RapidDNS
- AlienVault OTX
- urlscan.io
- VirusTotal
- Censys

Connector availability depends on provider access, rate limits and, where applicable, API credentials.

Sources requiring explicit configuration or activation are not automatically treated as available.

The authorized web-audit workflow uses GET and HEAD requests. Only examine systems for which you have permission.

### ZERO-RATING LAB

ZERO-RATING LAB is an experimental mobile-network diagnostic module designed to collect technical observations about connectivity through a mobile operator.

#### Experimental conditions

The intended test procedure uses:

- A SIM card belonging to the operator being studied.
- No active mobile Internet bundle.
- No active prepaid credit.
- The mobile network connection being examined.

The objective is to observe whether selected destinations can be reached under these conditions and collect technical evidence about network behavior.

IMPORTANT: A successful connection does not prove that traffic is free, zero-rated or exempt from billing. Independent consumption measurements and reliable operator billing records are necessary to investigate actual charging.

#### Five diagnostic axes

1. Domain and Host identification: records the supplied SNI and HTTP Host. No external domain or subdomain enumeration is performed.
2. DNS and IP analysis: examines name resolution and classifies relevant IP addresses.
3. SNI and TLS analysis: checks TCP connectivity and, when applicable, TLS negotiation using the supplied SNI.
4. HTTP analysis: examines HTTP or HTTPS responses and their technical status.
5. Cross-operator comparison: requires an additional measurement from another operator. It is currently skipped when that measurement is unavailable.

#### Required parameters

- SNI
- Destination IP address
- Port
- HTTP Host

The supplied values are validated before the diagnostic begins.

#### Redirect analysis

When an HTTP redirect is detected, the module can record redirect destinations, response information, connection attempts and the final observed destination.

Redirect tracking is controlled and limited to five hops. Non-public destinations, including private and reserved addresses, are recorded and classified but must not be contacted or used to access internal systems.

#### ZERO-RATING LAB limitations

- DNS resolution does not prove reachability.
- A successful TCP connection does not prove application availability.
- A successful TLS negotiation does not prove zero-rating.
- An HTTP response does not prove that traffic is free.
- HTTP HEAD requests do not download the complete response body.
- Port 80 is handled as conventional HTTP.
- TLS is attempted only when the selected port is 443.
- The protocol of a custom port is not automatically assumed.
- Cross-operator comparison requires separate measurements.
- Operator accounting may be delayed or not immediately visible.

For meaningful research, record the operator, SIM conditions, date, time, network type and observed consumption before and after each test. Do not draw billing conclusions from a single technical response.

---

## 2. OPERATING MODES

- Beginner Mode: simplified explanations and accessible descriptions.
- Expert Mode: detailed technical evidence, observations and limitations.

The available modes depend on the selected module.

---

## 3. SECURITY AND RESPONSIBLE USE

ARCHI MONITOR is intended for education, diagnostics and authorized security research.

- Test only systems and services you own or are explicitly authorized to examine.
- Respect external providers' terms, rate limits and access requirements.
- Protect API credentials and never publish private keys or tokens.
- Do not use the software to access private networks or internal devices.
- Do not contact non-public redirect destinations.
- Do not interpret technical connectivity as proof of a billing exemption.

The user is responsible for ensuring that each test is lawful and authorized.

---

## 4. INSTALLATION

### Requirements

- Python 3.11 or newer
- Git
- An Internet connection for network-dependent features
- Android with Termux recommended

The core CLI primarily uses Python standard-library modules. Some external intelligence providers may require API credentials.

### Clone and launch

```bash
git clone https://github.com/ArchiDigital-0/ARCHI-MONITOR.git
cd ARCHI-MONITOR
python archi_monitor.py
```
## 5. PROJECT STRUCTURE

The project follows a modular Python architecture.

- cli/ — interactive command-line interfaces
- core/ — shared diagnostic components and results
- modules/ — network analysis and intelligence modules
- diagnostics/ — diagnostic engines and test context
- database/ — data models
- public/ — public-facing documentation
- private/ — private workspace documentation
- config.py — project configuration

The structure may evolve during development.

---

## 6. TECHNICAL LIMITATIONS

Network observations depend on the device, operating system, active connection, DNS resolver, remote server and mobile operator.

A successful technical test does not automatically establish service availability, security, ownership, zero-rating or billing status.

Some external providers may be unavailable, rate-limited or require API credentials.

ARCHI MONITOR is experimental. Its results must be interpreted with these limitations in mind.

---

## 7. DEVELOPMENT STATUS

Version: 2.0 Alpha

Status: Experimental / Under Development

Platform: Python, Android and Termux

Features, connectors and diagnostic methods may evolve as development continues.

Technical feedback and reproducible bug reports are welcome.

---

## 8. SUGGESTED GITHUB TOPICS

network-diagnostics
zero-rating
termux
python
cybersecurity
network-intelligence
dns-analysis
mobile-networks
certificate-transparency

---

## 9. AUTHOR

ARCHI DIGITAL

GitHub: https://github.com/ArchiDigital-0

Repository: https://github.com/ArchiDigital-0/ARCHI-MONITOR

---

## 10. LICENSE

No open-source license has been selected yet. All rights are reserved by the author unless a license is added to this repository.

---

## PROJECT HASHTAGS

#ARCHIMONITOR #ARCHIDIGITAL #ZeroRatingLab #NetworkDiagnostics #ServerIntelligence #CyberSecurity #NetworkSecurity #Python #Termux #MobileNetworks #DNS #TLS #NetworkResearch


#SNI #Host #FindHost #HostOrange #SNIOrange #HostAirtel #HostAfricell #HostMTN #HostMoov #HostCamtel
