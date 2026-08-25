"""Port to service identification.

A scan report that says "27017" is data; one that says "MongoDB" is
intelligence. Knowing *what* an attacker was hunting for tells you what they
expected to find, and the category tells you how much it would have mattered
if they had found it.

This is a static local table -- no lookup service, no new dependency. It is
presentation-layer enrichment only and never influences whether an alert
fires.
"""

from __future__ import annotations

from typing import NamedTuple


class Service(NamedTuple):
    name: str
    category: str


# Categories drive the colour coding on the dashboard:
#   database  -- unauthenticated data stores, the highest-value find
#   remote    -- interactive access; a hit here is a foothold
#   file      -- file shares, often unauthenticated
#   web       -- application surface
#   mail      -- relay and credential targets
#   infra     -- management, orchestration, monitoring planes
CATEGORIES = ("database", "remote", "file", "web", "mail", "infra", "other")

PORT_SERVICES: dict[int, Service] = {
    21:    Service("FTP", "file"),
    22:    Service("SSH", "remote"),
    23:    Service("Telnet", "remote"),
    25:    Service("SMTP", "mail"),
    53:    Service("DNS", "infra"),
    80:    Service("HTTP", "web"),
    110:   Service("POP3", "mail"),
    111:   Service("RPCbind", "infra"),
    135:   Service("MSRPC", "infra"),
    137:   Service("NetBIOS-NS", "file"),
    138:   Service("NetBIOS-DGM", "file"),
    139:   Service("NetBIOS-SSN", "file"),
    143:   Service("IMAP", "mail"),
    161:   Service("SNMP", "infra"),
    389:   Service("LDAP", "infra"),
    554:   Service("RTSP", "other"),
    443:   Service("HTTPS", "web"),
    445:   Service("SMB", "file"),
    465:   Service("SMTPS", "mail"),
    587:   Service("SMTP submit", "mail"),
    636:   Service("LDAPS", "infra"),
    993:   Service("IMAPS", "mail"),
    995:   Service("POP3S", "mail"),
    1433:  Service("MSSQL", "database"),
    1521:  Service("Oracle DB", "database"),
    1080:  Service("SOCKS proxy", "web"),
    1723:  Service("PPTP", "remote"),
    1900:  Service("SSDP / UPnP", "infra"),
    2049:  Service("NFS", "file"),
    2323:  Service("Telnet alt", "remote"),
    2375:  Service("Docker API", "infra"),
    2376:  Service("Docker TLS", "infra"),
    3000:  Service("Node / Grafana", "web"),
    3128:  Service("Squid proxy", "web"),
    3306:  Service("MySQL", "database"),
    3389:  Service("RDP", "remote"),
    4444:  Service("Metasploit", "remote"),
    5000:  Service("Flask / UPnP", "web"),
    5060:  Service("SIP", "other"),
    5061:  Service("SIP-TLS", "other"),
    5432:  Service("PostgreSQL", "database"),
    5601:  Service("Kibana", "infra"),
    5555:  Service("Android ADB", "remote"),
    5900:  Service("VNC", "remote"),
    5985:  Service("WinRM", "remote"),
    6379:  Service("Redis", "database"),
    6667:  Service("IRC", "other"),
    7001:  Service("WebLogic", "web"),
    7547:  Service("TR-069 CWMP", "infra"),
    8000:  Service("HTTP alt", "web"),
    8080:  Service("HTTP proxy", "web"),
    8086:  Service("InfluxDB", "database"),
    8443:  Service("HTTPS alt", "web"),
    8291:  Service("MikroTik Winbox", "infra"),
    8888:  Service("Jupyter", "infra"),
    9000:  Service("PHP-FPM / SonarQube", "web"),
    9090:  Service("Prometheus", "infra"),
    9200:  Service("Elasticsearch", "database"),
    9300:  Service("Elasticsearch node", "database"),
    11211: Service("Memcached", "database"),
    15672: Service("RabbitMQ", "infra"),
    27017: Service("MongoDB", "database"),
    37777: Service("Dahua DVR", "other"),
    27018: Service("MongoDB shard", "database"),
}

_UNKNOWN = Service("unknown", "other")


def service_for(port: int) -> Service:
    """Identify a destination port, falling back to a generic descriptor."""
    known = PORT_SERVICES.get(port)
    if known is not None:
        return known
    if 49152 <= port <= 65535:
        return Service("ephemeral", "other")
    return _UNKNOWN
