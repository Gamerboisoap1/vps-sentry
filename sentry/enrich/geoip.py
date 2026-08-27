"""Offline attacker-IP geolocation via MaxMind GeoLite2.

Deliberately offline: the ``.mmdb`` file is read from local disk, so there are
no API calls, no rate limits, and no dependency on the VPS being able to reach
a threat-intel provider. Obtaining the file does require a free MaxMind
account and licence key -- see the README.

Every failure path degrades to ``None`` rather than raising. Geolocation is
decoration on an alert; it must never be able to stop one from being recorded.
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path

try:  # pragma: no cover - exercised by the import environment, not tests
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _GEOIP2_AVAILABLE = False


class GeoIPResolver:
    """Thread-safe lazy reader over a GeoLite2-Country database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._reader = None
        self._lock = threading.Lock()
        self._attempted = False
        self._cache: dict[str, tuple[str | None, str | None]] = {}

    @property
    def available(self) -> bool:
        return self._ensure_reader() is not None

    @property
    def status(self) -> str:
        if not _GEOIP2_AVAILABLE:
            return "geoip2 library not installed"
        if not self.db_path.exists():
            return f"database not found at {self.db_path}"
        return "ready" if self.available else "database unreadable"

    def _ensure_reader(self):
        if self._attempted:
            return self._reader
        with self._lock:
            if self._attempted:
                return self._reader
            self._attempted = True
            if not _GEOIP2_AVAILABLE or not self.db_path.exists():
                return None
            try:
                self._reader = geoip2.database.Reader(str(self.db_path))
            except (OSError, ValueError):
                self._reader = None
            return self._reader

    def lookup(self, ip: str) -> tuple[str | None, str | None]:
        """Return ``(country_name, iso_code)``; either may be ``None``."""
        if ip in self._cache:
            return self._cache[ip]

        result: tuple[str | None, str | None] = (None, None)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            self._cache[ip] = result
            return result

        # Private and reserved space never resolves; label it so the dashboard
        # can distinguish "internal source" from "lookup failed".
        if address.is_private or address.is_loopback or address.is_reserved:
            result = ("Private network", "LAN")
            self._cache[ip] = result
            return result

        reader = self._ensure_reader()
        if reader is not None:
            try:
                response = reader.country(ip)
                result = (response.country.name, response.country.iso_code)
            except Exception:
                # geoip2 raises AddressNotFoundError for unallocated space and
                # ValueError for malformed input; neither is worth surfacing.
                result = (None, None)

        self._cache[ip] = result
        return result

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
