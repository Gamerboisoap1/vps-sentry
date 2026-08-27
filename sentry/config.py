"""Runtime configuration for Sentry.

Every tunable lives here so the detection thresholds can be pointed at in a
review and justified in one place. Environment variables override defaults,
which keeps the demo mode and a real VPS deployment on the same code path.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SSHRule:
    """SSH brute-force detection thresholds.

    The defaults deliberately mirror fail2ban's stock sshd jail
    (maxretry=5, findtime=10m). Matching the enforcement layer means an alert
    here corresponds to a ban there, so the two views agree instead of
    disagreeing for reasons nobody can explain.
    """

    threshold: int = field(default_factory=lambda: _env_int("SENTRY_SSH_THRESHOLD", 5))
    window_seconds: int = field(default_factory=lambda: _env_int("SENTRY_SSH_WINDOW", 600))
    # Suppression window. Without this a sustained brute force emits one alert
    # per log line; instead the open alert escalates in place.
    cooldown_seconds: int = field(default_factory=lambda: _env_int("SENTRY_SSH_COOLDOWN", 600))


@dataclass(frozen=True)
class ScanRule:
    """Port-scan detection thresholds.

    Four distinct ports is a low bar on purpose. UFW rate-limits its own
    logging (roughly a burst of 10 then ~3/min), so a 1000-port sweep may only
    leave a handful of lines behind. We are counting a *sample* of the scan,
    not the scan itself, so the threshold has to sit below what a throttled
    log can show.
    """

    distinct_ports: int = field(default_factory=lambda: _env_int("SENTRY_SCAN_PORTS", 4))
    window_seconds: int = field(default_factory=lambda: _env_int("SENTRY_SCAN_WINDOW", 60))
    cooldown_seconds: int = field(default_factory=lambda: _env_int("SENTRY_SCAN_COOLDOWN", 300))


@dataclass(frozen=True)
class Config:
    # --- Inputs -----------------------------------------------------------
    auth_log: Path = field(
        default_factory=lambda: Path(_env_str("SENTRY_AUTH_LOG", "/var/log/auth.log"))
    )
    ufw_log: Path = field(
        default_factory=lambda: Path(_env_str("SENTRY_UFW_LOG", "/var/log/ufw.log"))
    )

    # --- Storage ----------------------------------------------------------
    db_path: Path = field(
        default_factory=lambda: Path(
            _env_str("SENTRY_DB", str(PROJECT_ROOT / "data" / "sentry.db"))
        )
    )

    # --- Detection --------------------------------------------------------
    ssh: SSHRule = field(default_factory=SSHRule)
    scan: ScanRule = field(default_factory=ScanRule)

    # --- Enrichment -------------------------------------------------------
    geoip_db: Path = field(
        default_factory=lambda: Path(
            _env_str("SENTRY_GEOIP_DB", str(PROJECT_ROOT / "data" / "GeoLite2-Country.mmdb"))
        )
    )
    fail2ban_jail: str = field(default_factory=lambda: _env_str("SENTRY_F2B_JAIL", "sshd"))
    fail2ban_enabled: bool = field(default_factory=lambda: _env_bool("SENTRY_F2B_ENABLED", True))

    # --- Ingest loop ------------------------------------------------------
    poll_seconds: int = field(default_factory=lambda: _env_int("SENTRY_POLL_SECONDS", 10))
    # A monitor that silently stops reading is worse than no monitor, so the
    # dashboard flags staleness past this many seconds.
    stale_after_seconds: int = field(
        default_factory=lambda: _env_int("SENTRY_STALE_AFTER", 60)
    )
    retention_days: int = field(default_factory=lambda: _env_int("SENTRY_RETENTION_DAYS", 30))

    # --- Server -----------------------------------------------------------
    # Loopback by default. Binding this to 0.0.0.0 would publish your log data
    # and an unauthenticated endpoint on the box you are trying to watch.
    host: str = field(default_factory=lambda: _env_str("SENTRY_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("SENTRY_PORT", 8787))


def load_config() -> Config:
    cfg = Config()
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    return cfg
