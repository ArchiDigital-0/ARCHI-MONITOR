ARCHI MONITOR

A network diagnostic and analysis tool by ARCHI DIGITAL.

ARCHI MONITOR is a Python-based network diagnostic tool designed to help users understand and analyze the connectivity, DNS resolution, TCP connection, TLS security and HTTP response of a domain.

It provides two operating modes:

- Beginner Mode: Simple explanations to help users understand each test result.
- Expert Mode: Technical information for users who want more detailed diagnostics.

Features

- DNS Analysis: Resolves domain names and displays available IPv4 and IPv6 addresses.
- TCP Connectivity: Tests connectivity to port 443.
- TLS Analysis: Checks TLS negotiation, protocol version, cipher suite and certificate validity.
- Certificate Verification: Checks the server certificate using the system's trusted certificate authorities and hostname verification.
- HTTP Analysis: Sends an HTTPS HEAD request and displays the response status and relevant headers.
- SNI Support: Allows users to specify a different Server Name Indication (SNI).
- Diagnostic Report: Provides a summary of the tests performed.

Requirements

- Python 3
- Internet connection
- Termux (Android) or another Python-compatible environment

Installation on Termux

Update Termux packages:

pkg update && pkg upgrade

Install Python and Git:

pkg install python git

Clone the repository:

git clone https://github.com/ArchiDigital-0/ARCHI-MONITOR.git

Enter the project directory:

cd ARCHI-MONITOR

Run the program:

python archi_monitor.py

How to Use

1. Launch ARCHI MONITOR.
2. Choose Beginner Mode or Expert Mode.
3. Enter the domain you want to analyze.
4. Enter an SNI hostname if needed, or press Enter to use the target domain.
5. Review the diagnostic results.

Security

ARCHI MONITOR uses Python's standard TLS certificate verification. It does not intentionally disable certificate validation.

A successful TCP connection does not necessarily mean that an application is functioning correctly. Interpret the results of each test separately.

Project Structure

ARCHI-MONITOR/
├── archi_monitor.py
├── .gitignore
└── README.md

Author

ARCHI DIGITAL

GitHub: https://github.com/ArchiDigital-0

License

No open-source license has been selected yet. All rights are reserved by the author unless a license is added to this repository.
