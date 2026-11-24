"""Chargeur central des connecteurs SERVER INTELLIGENCE."""

from modules.server_intelligence.source_runner import SourceRunner

from modules.server_intelligence.connectors.alienvault_otx import (
    alienvault_otx_connector,
)
from modules.server_intelligence.connectors.censys import (
    censys_connector,
)
from modules.server_intelligence.connectors.cert_spotter import (
    cert_spotter_connector,
)
from modules.server_intelligence.connectors.crt_sh import (
    crt_sh_connector,
)
from modules.server_intelligence.connectors.ctlogs_dev import (
    ctlogs_dev_connector,
)
from modules.server_intelligence.connectors.hackertarget import (
    hackertarget_connector,
)
from modules.server_intelligence.connectors.merklemap import (
    merklemap_connector,
)
from modules.server_intelligence.connectors.rapiddns import (
    rapiddns_connector,
)
from modules.server_intelligence.connectors.urlscan import (
    urlscan_connector,
)
from modules.server_intelligence.connectors.virustotal import (
    virustotal_connector,
)


def build_connectors():
    """Construit le registre explicite des dix connecteurs."""

    return {
        "crt_sh": crt_sh_connector,
        "cert_spotter": cert_spotter_connector,
        "merklemap": merklemap_connector,
        "ctlogs_dev": ctlogs_dev_connector,
        "hackertarget": hackertarget_connector,
        "rapiddns": rapiddns_connector,
        "alienvault_otx": alienvault_otx_connector,
        "urlscan": urlscan_connector,
        "virustotal": virustotal_connector,
        "censys": censys_connector,
    }


def run_discovery(config):
    """Exécute la découverte passive avec les connecteurs enregistrés."""

    return SourceRunner(
        config=config,
        connectors=build_connectors(),
    ).run()
