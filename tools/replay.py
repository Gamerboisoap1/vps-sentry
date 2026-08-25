"""Drip-feed new attack lines into a running demo.

Seeding produces a populated dashboard; this makes it visibly move. Lines are
appended at a controlled rate so alerts arrive, escalate, and flash while
someone is watching -- which is what a demo needs when no real attacker is
obliging.

Usage:
    python -m tools.replay --rate 2
"""

from __future__ import annotations

import argparse
import random
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "data" / "demo"
HOSTNAME = "vps-fra1"

# A fresh source, so the demo shows an alert being born rather than an
# existing one merely ticking upward.
NEW_ATTACKER = "77.83.36.219"
NEW_SCANNER = "45.135.232.90"
USERNAMES = ["root", "root", "root", "admin", "ubuntu", "jenkins", "www-data"]
SCAN_PORTS = [2375, 5601, 9200, 11211, 27017, 6379, 5432, 8086, 15672, 4444]


def now_stamp() -> str:
    return datetime.now().astimezone().strftime("%b %d %H:%M:%S")


def auth_line(rng: random.Random) -> str:
    user = rng.choice(USERNAMES)
    pid = rng.randint(20000, 39999)
    port = rng.randint(30000, 62000)
    return (f"{now_stamp()} {HOSTNAME} sshd[{pid}]: Failed password for "
            f"{'invalid user ' if user in {'jenkins', 'www-data'} else ''}{user} "
            f"from {NEW_ATTACKER} port {port} ssh2")


def ufw_line(rng: random.Random, port: int) -> str:
    return (
        f"{now_stamp()} {HOSTNAME} kernel: [{rng.randint(200000, 900000)}.{rng.randint(100000, 999999)}] "
        f"[UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:2a:11:04 SRC={NEW_SCANNER} DST=10.0.0.4 "
        f"LEN=44 TOS=0x00 PREC=0x00 TTL={rng.randint(40, 60)} ID={rng.randint(1000, 65000)} "
        f"PROTO=TCP SPT={rng.randint(40000, 60000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay live attack traffic into the demo logs")
    parser.add_argument("--dir", type=Path, default=DEMO_DIR)
    parser.add_argument("--rate", type=float, default=1.5, help="seconds between lines")
    parser.add_argument("--count", type=int, default=40, help="how many lines to emit")
    args = parser.parse_args()

    rng = random.Random()
    auth_path = args.dir / "auth.log"
    ufw_path = args.dir / "ufw.log"
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.touch()
    ufw_path.touch()

    print(f"  appending {args.count} lines, one every {args.rate}s (ctrl-c to stop)")
    try:
        for i in range(args.count):
            if i % 4 == 3:
                port = SCAN_PORTS[(i // 4) % len(SCAN_PORTS)]
                with ufw_path.open("a") as fh:
                    fh.write(ufw_line(rng, port) + "\n")
                print(f"  [{i + 1:>3}] scan probe  {NEW_SCANNER} -> :{port}")
            else:
                with auth_path.open("a") as fh:
                    fh.write(auth_line(rng) + "\n")
                print(f"  [{i + 1:>3}] failed auth {NEW_ATTACKER}")
            time.sleep(args.rate)
    except KeyboardInterrupt:
        print("\n  stopped")


if __name__ == "__main__":
    main()
