# ARCHI MONITOR

### Network Diagnostic & Intelligence Tool

**Developed by ARCHI DIGITAL**

ARCHI MONITOR is a modular Python-based network diagnostic tool designed to investigate network connectivity, DNS resolution, IP addressing, TCP connections, TLS certificates, HTTP responses, and network quality.

The project is primarily designed for Android devices running Termux.

## Features

- DNS Analysis
- TCP Connectivity
- IP Analysis
- RDAP Lookup
- ASN Analysis
- TLS Analysis
- HTTP Analysis
- Certificate Transparency
- Mobile Data Analyzer
- Network Quality Monitor

## Operating Modes

- **Beginner Mode:** Simplified explanations of diagnostic results.
- **Expert Mode:** Technical information and diagnostic evidence.

## Requirements

- Python 3.11 or newer.
- Git.
- Internet connection.
- Android with Termux recommended.

The CLI core uses Python standard-library modules. No third-party installation is currently required.

## Installation

Clone the repository using this single Git command:

`git clone https://github.com/ArchiDigital-0/ARCHI-MONITOR.git`

Enter the project directory:

`cd ARCHI-MONITOR`

Launch ARCHI MONITOR:

`python archi_monitor.py`

## Technical Limitations

- TCP connection success does not guarantee application availability.
- TCP failure rates are not equivalent to actual IP packet loss.
- TCP connection latency is not ICMP ping latency.
- RDAP information does not necessarily identify the end user.
- ASN information describes network allocation and routing context.
- Certificate Transparency findings do not prove that discovered hosts are active or vulnerable.
- HTTP traffic estimates are not mobile operator billing measurements.

## Project Status

**Version:** 2.0 Alpha

**Status:** Experimental / Under Development

## Author

**ARCHI DIGITAL**

GitHub: https://github.com/ArchiDigital-0

## License

No open-source license has been selected yet. All rights are reserved by the author unless a license is added.
