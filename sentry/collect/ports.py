"""Listening-socket inventory.

Answers one question: what is accepting connections on this box right now.
On Linux that is read from /proc/net/tcp[6] and /proc/net/udp[6] directly --
the same source `ss` and `netstat` use -- so no tool needs to be installed.

Process attribution is best effort. Mapping a socket to the process holding it
means resolving its inode through /proc/<pid>/fd, and a non-root process can
only see its own. Rather than pretend, an unattributed socket reports None and
the dashboard leaves the column blank.

Exposure matters more than the port number: a service bound to 127.0.0.1 is
not reachable from the internet, and calling it "open" would be alarming and
wrong. Each entry is therefore classified by the address it is bound to.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any

from ..services import service_for

IS_LINUX = platform.system() == "Linux"

# /proc/net/tcp connection states; 0A is TCP_LISTEN.
_TCP_LISTEN = "0A"

_LOOPBACK_V4 = {"127.0.0.1"}
_ANY_V4 = {"0.0.0.0"}
_ANY_V6 = {"::", "0000:0000:0000:0000:0000:0000:0000:0000"}


@dataclass
class ListeningPort:
    proto: str
    port: int
    address: str
    exposure: str        # "public" | "loopback" | "private"
    service: str
    category: str
    process: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _classify(address: str) -> str:
    if address in _LOOPBACK_V4 or address == "::1" or address.startswith("127."):
        return "loopback"
    if address in _ANY_V4 or address in _ANY_V6:
        return "public"
    if address.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
        return "private"
    return "public"


def _hex_to_ipv4(raw: str) -> str:
    """/proc encodes IPv4 little-endian, so the octets come out reversed."""
    value = int(raw, 16)
    return ".".join(str((value >> (8 * i)) & 0xFF) for i in range(4))


def _hex_to_ipv6(raw: str) -> str:
    groups = [raw[i:i + 8] for i in range(0, 32, 8)]
    words: list[str] = []
    for group in groups:
        value = int(group, 16)
        little = value.to_bytes(4, "big")[::-1]
        words.append(f"{little[0]:02x}{little[1]:02x}")
        words.append(f"{little[2]:02x}{little[3]:02x}")
    joined = ":".join(words)
    return "::" if set(joined.replace(":", "")) == {"0"} else joined


def _socket_inode_to_process() -> dict[str, str]:
    """Best-effort inode -> process name map. Silently partial without root."""
    mapping: dict[str, str] = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return mapping

    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue  # not ours to read
        name = None
        for fd in entries:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = target[8:-1]
                if name is None:
                    try:
                        with open(f"/proc/{pid}/comm", "r") as fh:
                            name = fh.read().strip()
                    except OSError:
                        name = f"pid {pid}"
                mapping[inode] = name
    return mapping


def _read_proc_net(path: str, proto: str, listen_only: bool) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    try:
        with open(path, "r") as fh:
            lines = fh.readlines()[1:]
    except OSError:
        return rows

    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, state, inode = parts[1], parts[3], parts[9]
        if listen_only and state != _TCP_LISTEN:
            continue
        addr_hex, _, port_hex = local.partition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        address = _hex_to_ipv6(addr_hex) if len(addr_hex) > 8 else _hex_to_ipv4(addr_hex)
        rows.append((address, port, inode))
    return rows


def _collect_linux() -> list[ListeningPort]:
    inode_map = _socket_inode_to_process()
    found: dict[tuple[str, int], ListeningPort] = {}

    sources = [
        ("/proc/net/tcp", "tcp", True),
        ("/proc/net/tcp6", "tcp", True),
        # A UDP socket has no LISTEN state; a bound one is simply present.
        ("/proc/net/udp", "udp", False),
        ("/proc/net/udp6", "udp", False),
    ]
    for path, proto, listen_only in sources:
        for address, port, inode in _read_proc_net(path, proto, listen_only):
            key = (proto, port)
            svc = service_for(port)
            entry = ListeningPort(
                proto=proto, port=port, address=address,
                exposure=_classify(address), service=svc.name, category=svc.category,
                process=inode_map.get(inode),
            )
            # A service bound on both v4 and v6 appears twice; keep the more
            # exposed of the two rather than whichever was read last.
            existing = found.get(key)
            if existing is None or (existing.exposure != "public" and entry.exposure == "public"):
                found[key] = entry
    return list(found.values())


def _collect_macos() -> list[ListeningPort]:
    binary = shutil.which("lsof")
    if binary is None:
        return []
    try:
        out = subprocess.run(
            [binary, "-nP", "-iTCP", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=8, check=False,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []

    found: dict[tuple[str, int], ListeningPort] = {}
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        process, name = cols[0], cols[8]
        m = re.match(r"^(.*):(\d+)$", name)
        if not m:
            continue
        address, port_raw = m.group(1), m.group(2)
        address = {"*": "0.0.0.0", "[::]": "::"}.get(address, address.strip("[]"))
        try:
            port = int(port_raw)
        except ValueError:
            continue
        svc = service_for(port)
        entry = ListeningPort(
            proto="tcp", port=port, address=address, exposure=_classify(address),
            service=svc.name, category=svc.category, process=process,
        )
        key = ("tcp", port)
        existing = found.get(key)
        if existing is None or (existing.exposure != "public" and entry.exposure == "public"):
            found[key] = entry
    return list(found.values())


def collect() -> list[ListeningPort]:
    """Current listening sockets, sorted by port."""
    ports = _collect_linux() if IS_LINUX else _collect_macos()
    return sorted(ports, key=lambda p: (p.port, p.proto))


def status() -> str:
    if IS_LINUX:
        return "ready" if os.path.exists("/proc/net/tcp") else "/proc/net/tcp not readable"
    if platform.system() == "Darwin":
        return "ready (macOS: lsof)" if shutil.which("lsof") else "lsof not installed"
    return f"unsupported platform: {platform.system()}"
