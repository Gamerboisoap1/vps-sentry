"""Port identification. Presentation-layer only -- it never gates an alert."""
import pytest

from sentry.services import CATEGORIES, PORT_SERVICES, service_for


@pytest.mark.parametrize("port,name,category", [
    (3306, "MySQL", "database"),
    (27017, "MongoDB", "database"),
    (6379, "Redis", "database"),
    (22, "SSH", "remote"),
    (3389, "RDP", "remote"),
    (445, "SMB", "file"),
    (80, "HTTP", "web"),
])
def test_well_known_ports_are_identified(port, name, category):
    service = service_for(port)
    assert service.name == name
    assert service.category == category


def test_unmapped_low_port_falls_back_to_unknown():
    assert service_for(31337).name == "unknown"


def test_high_port_is_labelled_ephemeral():
    """A probe of an ephemeral port is different news from a probe of MySQL."""
    assert service_for(61000).name == "ephemeral"


def test_every_mapped_service_uses_a_known_category():
    """Categories drive dashboard colours; an unknown one would render blank."""
    for port, service in PORT_SERVICES.items():
        assert service.category in CATEGORIES, f"port {port} has category {service.category}"


def test_scanner_favourites_are_all_mapped():
    """Ports the seed data probes must not render as 'unknown' on the demo."""
    for port in (137, 161, 1900, 5060, 8080, 8443, 23, 443):
        assert service_for(port).name != "unknown", f"port {port} unmapped"
