"""A rules-based posture score.

Deliberately not a model and not a percentage of anything. It is an arithmetic
sum of named deductions from a base of 100, and every deduction is returned
alongside the number so the dashboard can show its working. A score nobody can
explain is worse than no score, because it invites trust it has not earned.

Phrase it as "VPS Sentry Security Score: 87/100", never "your VPS is 87%
secure". The first is this tool's own indicator; the second is a claim about
reality that no rule set of this size could support.

A rule whose input is unavailable does not deduct. Punishing the operator for
something we could not measure would make the score drift down on hardened
boxes that merely deny us a reading.
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .db import iso, utcnow

BASE_SCORE = 100

# More than this many publicly-bound listeners reads as a broad surface.
PUBLIC_PORT_BUDGET = 6
DISK_PRESSURE_PERCENT = 90


@dataclass
class Deduction:
    rule: str
    points: int
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Score:
    value: int
    band: str
    deductions: list[Deduction] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "band": self.band,
            "base": BASE_SCORE,
            "deductions": [d.as_dict() for d in self.deductions],
            "unknowns": self.unknowns,
        }


def _band(value: int) -> str:
    if value >= 85:
        return "good"
    if value >= 65:
        return "fair"
    if value >= 40:
        return "weak"
    return "poor"


def compute(
    conn: sqlite3.Connection,
    *,
    listening_ports: list[Any] | None,
    ssh_policy: Any | None,
    host_sample: Any | None,
    firewall_active: bool | None,
    fail2ban_ready: bool,
) -> Score:
    deductions: list[Deduction] = []
    unknowns: list[str] = []

    hour_ago = iso(utcnow() - timedelta(hours=1))
    day_ago = iso(utcnow() - timedelta(days=1))

    # -- Firewall ---------------------------------------------------------
    if firewall_active is None:
        unknowns.append("firewall state could not be determined")
    elif not firewall_active:
        deductions.append(Deduction("firewall", 20, "UFW is not active"))

    # -- Live attack activity ---------------------------------------------
    active = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE last_seen >= ?", (hour_ago,)
    ).fetchone()["n"]
    if active:
        deductions.append(
            Deduction("active_attacks", 10, f"{active} alert(s) active in the last hour")
        )

    # A successful login from an address that was attacking outranks every
    # other signal here, so it carries the largest single deduction.
    breach = conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE kind = 'SSH_LOGIN_AFTER_ATTACK' AND ts >= ?",
        (day_ago,),
    ).fetchone()["n"]
    if breach:
        deductions.append(
            Deduction("login_after_attack", 25,
                      f"{breach} successful SSH login(s) from an attacking IP in 24h")
        )

    # -- Exposure ---------------------------------------------------------
    if listening_ports is None:
        unknowns.append("listening ports could not be enumerated")
    else:
        public = [p for p in listening_ports if getattr(p, "exposure", None) == "public"]
        if len(public) > PUBLIC_PORT_BUDGET:
            deductions.append(
                Deduction("open_ports", 10,
                          f"{len(public)} publicly bound ports (budget {PUBLIC_PORT_BUDGET})")
            )
        risky = [p for p in public if getattr(p, "category", None) == "database"]
        if risky:
            names = ", ".join(f"{p.service}:{p.port}" for p in risky[:4])
            deductions.append(
                Deduction("exposed_database", 15, f"database port(s) reachable publicly: {names}")
            )

    # -- SSH configuration -------------------------------------------------
    if ssh_policy is None or not getattr(ssh_policy, "readable", False):
        unknowns.append("sshd_config could not be read")
    else:
        if ssh_policy.permit_root_login == "yes":
            deductions.append(
                Deduction("root_login", 15, "PermitRootLogin yes (root may log in directly)")
            )
        if ssh_policy.password_authentication:
            deductions.append(
                Deduction("password_auth", 10,
                          "PasswordAuthentication enabled (brute force can succeed)")
            )

    # -- Existing defences -------------------------------------------------
    if not fail2ban_ready:
        deductions.append(
            Deduction("fail2ban", 10, "fail2ban is not answering; bans are not being applied")
        )

    # -- Operational -------------------------------------------------------
    if host_sample is None or getattr(host_sample, "disk_percent", None) is None:
        unknowns.append("disk usage could not be read")
    elif host_sample.disk_percent >= DISK_PRESSURE_PERCENT:
        deductions.append(
            Deduction("disk_pressure", 5,
                      f"disk {host_sample.disk_percent:.0f}% full; logging may stop")
        )

    value = max(0, min(BASE_SCORE, BASE_SCORE - sum(d.points for d in deductions)))
    return Score(value=value, band=_band(value), deductions=deductions, unknowns=unknowns)
