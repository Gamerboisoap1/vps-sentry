"""Generate realistic log fixtures so the dashboard can be demonstrated.

Timestamps are written relative to *now* rather than baked in, so the sliding
windows fire no matter when the demo is run. The traffic mix is modelled on
what a public VPS with port 22 exposed actually receives: a few persistent
brute-force sources hammering a small dictionary of usernames, one host
sweeping ports, and a background of ordinary system noise that must be
correctly ignored.

Usage:
    python -m tools.seed --reset
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "data" / "demo"

HOSTNAME = "vps-fra1"

# Source profiles. Usernames reflect real dictionary attacks: root dominates,
# with service accounts and vendor defaults filling the tail.
BRUTE_FORCE_SOURCES = [
    {"ip": "45.148.10.92",  "attempts": 61, "users": ["root"] * 9 + ["admin"], "span": 420},
    {"ip": "91.240.118.23", "attempts": 34, "users": ["root", "root", "ubuntu", "admin", "postgres"], "span": 540},
    {"ip": "103.94.108.7",  "attempts": 17, "users": ["root", "oracle", "test", "git"], "span": 300},
    {"ip": "2.57.122.184",  "attempts": 12, "users": ["root", "deploy"], "span": 260, "keyonly": True},
    {"ip": "185.220.101.44","attempts": 6,  "users": ["admin", "user"], "span": 180},
]

SCAN_SOURCES = [
    {"ip": "193.34.76.15", "ports": [3306, 6379, 27017, 5432, 9200, 8080, 23, 445, 1433, 5900], "span": 40},
    {"ip": "159.223.88.201", "ports": [21, 25, 110, 143, 993, 3389], "span": 35},
    {"ip": "20.106.44.19", "ports": [8000, 8443, 9000], "span": 50},  # under threshold on purpose
]


def stamp(when: datetime) -> str:
    """BSD syslog format: local time, no year, no offset."""
    return when.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if when.day < 10 \
        else when.strftime("%b %d %H:%M:%S")


def build_auth_log(now: datetime, rng: random.Random) -> list[tuple[datetime, str]]:
    lines: list[tuple[datetime, str]] = []

    for profile in BRUTE_FORCE_SOURCES:
        ip = profile["ip"]
        span = profile["span"]
        for i in range(profile["attempts"]):
            when = now - timedelta(seconds=span - int(i * span / profile["attempts"]))
            user = rng.choice(profile["users"])
            pid = rng.randint(20000, 39999)
            port = rng.randint(30000, 62000)

            if profile.get("keyonly"):
                # PasswordAuthentication=no: brute force shows up as preauth closes.
                body = (f"sshd[{pid}]: Connection closed by authenticating user "
                        f"{user} {ip} port {port} [preauth]")
            elif user not in {"root", "ubuntu", "postgres", "deploy", "git"}:
                # Non-existent account: sshd emits the precursor, then the failure.
                lines.append((when, f"{stamp(when)} {HOSTNAME} sshd[{pid}]: "
                                    f"Invalid user {user} from {ip} port {port}"))
                body = (f"sshd[{pid}]: Failed password for invalid user {user} "
                        f"from {ip} port {port} ssh2")
            else:
                body = f"sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

            lines.append((when, f"{stamp(when)} {HOSTNAME} {body}"))

    # Background probing across the preceding 24 hours. A public VPS with port
    # 22 open is touched continuously, so a timeline showing a single spike and
    # 23 empty hours would misrepresent what the logs actually look like.
    background_ips = [
        "212.70.149.83", "141.98.11.29", "61.177.173.52", "218.92.0.112",
        "92.63.197.61", "134.209.24.190", "159.65.13.24", "45.61.187.202",
    ]
    background_users = ["root"] * 6 + ["admin", "ubuntu", "test", "oracle", "user", "ftpuser"]
    for hour in range(2, 24):
        # Volume varies by hour; scanning botnets are not uniform.
        volume = rng.choice([0, 1, 2, 3, 4, 6, 9, 14, 22])
        for _ in range(volume):
            when = now - timedelta(seconds=hour * 3600 + rng.randint(0, 3599))
            ip = rng.choice(background_ips)
            user = rng.choice(background_users)
            pid = rng.randint(20000, 39999)
            port = rng.randint(30000, 62000)
            prefix = "invalid user " if user in {"test", "user", "ftpuser", "admin"} else ""
            lines.append((when, f"{stamp(when)} {HOSTNAME} sshd[{pid}]: "
                                f"Failed password for {prefix}{user} from {ip} port {port} ssh2"))

    # The sequence that matters most: the brute force against 45.148.10.92
    # stops because it succeeded. Seeding it means the demo shows the critical
    # event rather than only the routine ones.
    breach_at = now - timedelta(seconds=95)
    lines.append((
        breach_at,
        f"{stamp(breach_at)} {HOSTNAME} sshd[28903]: Accepted password for root "
        f"from 45.148.10.92 port 51890 ssh2",
    ))

    # Ordinary system noise the parsers must ignore.
    noise = [
        "CRON[4471]: pam_unix(cron:session): session opened for user root(uid=0)",
        "CRON[4471]: pam_unix(cron:session): session closed for user root",
        "sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
        "sshd[3312]: Accepted publickey for deploy from 82.14.203.66 port 49820 ssh2: ED25519 SHA256:9pQ2r",
        "sshd[3312]: pam_unix(sshd:session): session opened for user deploy(uid=1000)",
        "systemd-logind[812]: New session 214 of user deploy.",
    ]
    for i, body in enumerate(noise):
        when = now - timedelta(seconds=600 - i * 40)
        lines.append((when, f"{stamp(when)} {HOSTNAME} {body}"))

    return lines


def build_ufw_log(now: datetime, rng: random.Random) -> list[tuple[datetime, str]]:
    lines: list[tuple[datetime, str]] = []
    for profile in SCAN_SOURCES:
        ip = profile["ip"]
        span = profile["span"]
        for i, port in enumerate(profile["ports"]):
            when = now - timedelta(seconds=span - int(i * span / max(len(profile["ports"]), 1)))
            body = (
                f"kernel: [{rng.randint(200000, 900000)}.{rng.randint(100000, 999999)}] "
                f"[UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:2a:11:04 SRC={ip} DST=10.0.0.4 "
                f"LEN=44 TOS=0x00 PREC=0x00 TTL={rng.randint(40, 60)} ID={rng.randint(1000, 65000)} "
                f"PROTO=TCP SPT={rng.randint(40000, 60000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
            )
            lines.append((when, f"{stamp(when)} {HOSTNAME} {body}"))

    # Background blocked probes across the day, same reasoning as above.
    background_scanners = ["198.235.24.161", "87.236.176.14", "185.242.226.9", "167.94.138.34"]
    background_ports = [22, 23, 80, 443, 445, 3389, 8080, 8443, 5060, 1900, 137, 161]
    for hour in range(1, 24):
        for _ in range(rng.choice([0, 1, 2, 3, 5, 8])):
            when = now - timedelta(seconds=hour * 3600 + rng.randint(0, 3599))
            ip = rng.choice(background_scanners)
            port = rng.choice(background_ports)
            body = (
                f"kernel: [{rng.randint(200000, 900000)}.{rng.randint(100000, 999999)}] "
                f"[UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:2a:11:04 SRC={ip} DST=10.0.0.4 "
                f"LEN=44 TOS=0x00 PREC=0x00 TTL={rng.randint(40, 60)} ID={rng.randint(1000, 65000)} "
                f"PROTO=TCP SPT={rng.randint(40000, 60000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
            )
            lines.append((when, f"{stamp(when)} {HOSTNAME} {body}"))

    # A blocked ICMP probe: no destination port, must be skipped cleanly.
    when = now - timedelta(seconds=25)
    lines.append((when, f"{stamp(when)} {HOSTNAME} kernel: [284720.1] [UFW BLOCK] IN=eth0 "
                        f"OUT= SRC=193.34.76.15 DST=10.0.0.4 LEN=84 PROTO=ICMP TYPE=8 CODE=0"))
    return lines


def write_log(path: Path, entries: list[tuple[datetime, str]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    entries.sort(key=lambda pair: pair[0])
    path.write_text("\n".join(text for _, text in entries) + "\n")
    return len(entries)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Sentry with demo log data")
    parser.add_argument("--dir", type=Path, default=DEMO_DIR, help="where to write the logs")
    parser.add_argument("--reset", action="store_true", help="also delete the existing database")
    parser.add_argument("--seed", type=int, default=7, help="RNG seed for reproducible output")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    now = datetime.now().astimezone()

    auth_path = args.dir / "auth.log"
    ufw_path = args.dir / "ufw.log"
    auth_count = write_log(auth_path, build_auth_log(now, rng))
    ufw_count = write_log(ufw_path, build_ufw_log(now, rng))

    if args.reset:
        for suffix in ("", "-wal", "-shm"):
            db = ROOT / "data" / f"sentry.db{suffix}"
            if db.exists():
                db.unlink()
        print("  database reset")

    print(f"  {auth_path}: {auth_count} lines")
    print(f"  {ufw_path}: {ufw_count} lines")
    print()
    print("  Run the dashboard against them with:")
    print(f"    SENTRY_AUTH_LOG={auth_path} SENTRY_UFW_LOG={ufw_path} \\")
    print("      ./.venv/bin/python -m uvicorn sentry.api:app --port 8787")


if __name__ == "__main__":
    main()
