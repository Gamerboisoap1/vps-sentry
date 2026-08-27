"""Host metrics: CPU, memory, disk, network and uptime.

Read straight from what the kernel already publishes -- no agent, no metrics
library, no new dependency. On Linux that means /proc; the values are exactly
what `top` and `free` compute from the same files.

macOS support exists so the dashboard is demonstrable on a development
machine. It is honest about being second class: where a figure cannot be
obtained the same way, the collector says so in ``cpu_basis`` rather than
quietly presenting a different measurement as if it were the same one.

CPU percentage is inherently a *rate*, so the first cycle after start has no
previous sample to compare against and reports None. That is a real state, not
an error, and the dashboard renders it as such.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any

IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


@dataclass
class HostSample:
    cpu_percent: float | None = None
    cpu_basis: str = "unavailable"
    mem_percent: float | None = None
    mem_total: int | None = None
    mem_used: int | None = None
    disk_percent: float | None = None
    disk_total: int | None = None
    disk_used: int | None = None
    net_rx_bps: float | None = None
    net_tx_bps: float | None = None
    uptime_secs: int | None = None
    load1: float | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run(cmd: list[str], timeout: float = 3.0) -> str | None:
    binary = shutil.which(cmd[0])
    if binary is None:
        return None
    try:
        done = subprocess.run(
            [binary, *cmd[1:]], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return done.stdout if done.returncode == 0 else None


class HostCollector:
    """Samples host metrics, holding the previous reading for rate figures."""

    def __init__(self, disk_path: str = "/") -> None:
        self.disk_path = disk_path
        self._prev_cpu: tuple[int, int] | None = None       # (busy, total)
        self._prev_net: tuple[float, int, int] | None = None  # (monotonic, rx, tx)

    @property
    def platform_supported(self) -> bool:
        return IS_LINUX or IS_MACOS

    @property
    def status(self) -> str:
        if IS_LINUX:
            return "ready"
        if IS_MACOS:
            return "ready (macOS: CPU derived from load average)"
        return f"unsupported platform: {platform.system()}"

    # -- CPU ---------------------------------------------------------------
    def _cpu_linux(self, sample: HostSample) -> None:
        """Delta of busy vs total jiffies between consecutive /proc/stat reads."""
        try:
            with open("/proc/stat", "r") as fh:
                line = fh.readline()
        except OSError as exc:
            sample.errors.append(f"cpu: {exc}")
            return

        fields = line.split()
        if not fields or fields[0] != "cpu":
            sample.errors.append("cpu: unexpected /proc/stat format")
            return

        values = [int(v) for v in fields[1:] if v.isdigit()]
        if len(values) < 5:
            sample.errors.append("cpu: too few fields in /proc/stat")
            return

        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
        busy = total - idle

        if self._prev_cpu is not None:
            prev_busy, prev_total = self._prev_cpu
            busy_delta = busy - prev_busy
            total_delta = total - prev_total
            if total_delta > 0:
                sample.cpu_percent = round(max(0.0, min(100.0, busy_delta * 100.0 / total_delta)), 1)
                sample.cpu_basis = "/proc/stat delta"
        self._prev_cpu = (busy, total)

    def _cpu_macos(self, sample: HostSample) -> None:
        """No /proc; approximate from load average and say so."""
        cores = os.cpu_count() or 1
        if sample.load1 is not None:
            sample.cpu_percent = round(min(100.0, sample.load1 * 100.0 / cores), 1)
            sample.cpu_basis = f"load average / {cores} cores (approximate)"

    # -- Memory ------------------------------------------------------------
    def _mem_linux(self, sample: HostSample) -> None:
        wanted = {"MemTotal": 0, "MemAvailable": 0}
        try:
            with open("/proc/meminfo", "r") as fh:
                for line in fh:
                    key, _, rest = line.partition(":")
                    if key in wanted:
                        wanted[key] = int(rest.split()[0]) * 1024  # kB -> bytes
        except (OSError, ValueError, IndexError) as exc:
            sample.errors.append(f"memory: {exc}")
            return

        total, available = wanted["MemTotal"], wanted["MemAvailable"]
        if total > 0:
            # MemAvailable, not MemFree: cache is reclaimable, so counting it as
            # used is what makes naive memory monitors report 95% on idle boxes.
            sample.mem_total = total
            sample.mem_used = total - available
            sample.mem_percent = round((total - available) * 100.0 / total, 1)

    def _mem_macos(self, sample: HostSample) -> None:
        total_raw = _run(["sysctl", "-n", "hw.memsize"])
        stats = _run(["vm_stat"])
        if not total_raw or not stats:
            sample.errors.append("memory: sysctl/vm_stat unavailable")
            return
        try:
            total = int(total_raw.strip())
        except ValueError:
            sample.errors.append("memory: could not read hw.memsize")
            return

        page_match = re.search(r"page size of (\d+) bytes", stats)
        page = int(page_match.group(1)) if page_match else 4096

        def pages(name: str) -> int:
            m = re.search(rf"{name}:\s+(\d+)", stats)
            return int(m.group(1)) if m else 0

        # Free, inactive and speculative pages are all reclaimable, which is the
        # closest analogue to Linux's MemAvailable.
        available = (pages("Pages free") + pages("Pages inactive")
                     + pages("Pages speculative")) * page
        available = min(available, total)
        sample.mem_total = total
        sample.mem_used = total - available
        sample.mem_percent = round((total - available) * 100.0 / total, 1)

    # -- Disk --------------------------------------------------------------
    def _disk(self, sample: HostSample) -> None:
        try:
            st = os.statvfs(self.disk_path)
        except OSError as exc:
            sample.errors.append(f"disk: {exc}")
            return
        total = st.f_blocks * st.f_frsize
        # f_bavail is space available to unprivileged users; the gap to f_bfree
        # is the root reserve, which is not free space for practical purposes.
        available = st.f_bavail * st.f_frsize
        used = total - (st.f_bfree * st.f_frsize)
        if total > 0:
            sample.disk_total = total
            sample.disk_used = used
            sample.disk_percent = round(used * 100.0 / (used + available), 1) if (used + available) else None

    # -- Network -----------------------------------------------------------
    def _net_counters_linux(self) -> tuple[int, int] | None:
        rx = tx = 0
        try:
            with open("/proc/net/dev", "r") as fh:
                for line in fh.readlines()[2:]:
                    name, _, rest = line.partition(":")
                    if name.strip() == "lo":
                        continue
                    parts = rest.split()
                    if len(parts) >= 9:
                        rx += int(parts[0])
                        tx += int(parts[8])
        except (OSError, ValueError):
            return None
        return rx, tx

    def _net_counters_macos(self) -> tuple[int, int] | None:
        out = _run(["netstat", "-ib"])
        if not out:
            return None
        rx = tx = 0
        seen: set[str] = set()
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10 or cols[0].startswith("lo"):
                continue
            # netstat prints one row per address family; count each interface once.
            if cols[0] in seen:
                continue
            try:
                rx += int(cols[6])
                tx += int(cols[9])
                seen.add(cols[0])
            except (ValueError, IndexError):
                continue
        return rx, tx

    def _network(self, sample: HostSample) -> None:
        counters = self._net_counters_linux() if IS_LINUX else self._net_counters_macos()
        if counters is None:
            sample.errors.append("network: counters unavailable")
            return
        rx, tx = counters
        now = time.monotonic()
        if self._prev_net is not None:
            prev_t, prev_rx, prev_tx = self._prev_net
            elapsed = now - prev_t
            # Counters are 32/64-bit and wrap, and an interface reset can move
            # them backwards; a negative delta means "unknown", not "negative
            # throughput".
            if elapsed > 0 and rx >= prev_rx and tx >= prev_tx:
                sample.net_rx_bps = round((rx - prev_rx) / elapsed, 1)
                sample.net_tx_bps = round((tx - prev_tx) / elapsed, 1)
        self._prev_net = (now, rx, tx)

    # -- Uptime ------------------------------------------------------------
    def _uptime(self, sample: HostSample) -> None:
        if IS_LINUX:
            try:
                with open("/proc/uptime", "r") as fh:
                    sample.uptime_secs = int(float(fh.readline().split()[0]))
                return
            except (OSError, ValueError, IndexError) as exc:
                sample.errors.append(f"uptime: {exc}")
                return
        boot = _run(["sysctl", "-n", "kern.boottime"])
        if boot:
            m = re.search(r"sec\s*=\s*(\d+)", boot)
            if m:
                sample.uptime_secs = int(time.time()) - int(m.group(1))
                return
        sample.errors.append("uptime: unavailable")

    # -- Entry point -------------------------------------------------------
    def sample(self) -> HostSample:
        s = HostSample()
        if not self.platform_supported:
            s.errors.append(self.status)
            return s

        try:
            s.load1 = round(os.getloadavg()[0], 2)
        except (OSError, AttributeError):
            pass

        if IS_LINUX:
            self._cpu_linux(s)
            self._mem_linux(s)
        else:
            self._cpu_macos(s)
            self._mem_macos(s)

        self._disk(s)
        self._network(s)
        self._uptime(s)
        return s


def format_uptime(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
