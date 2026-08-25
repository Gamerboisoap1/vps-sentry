"""fail2ban cross-check.

Answers one question per alert: has the existing defence already handled this
IP, or is it still open? That converts a raw alert into an actionable one.

Two facts shape the implementation:

* The check shells out to ``fail2ban-client``, which needs access to the
  fail2ban socket -- normally root. Running an entire monitoring daemon as
  root to read one status line is a poor trade, so the installer grants a
  single narrow sudoers rule instead and this module falls back to ``sudo -n``
  when the direct call is refused. Every failure mode (not installed, no
  permission, jail missing, daemon stopped) resolves to ``None`` meaning
  *unknown*, which the dashboard renders distinctly from *not banned*.
* Bans expire (stock ``bantime`` is 10 minutes). A live query therefore
  answers "is this IP banned **right now**", which is not the same question as
  "was it banned when we detected it". Sentinel stores the answer at detection
  time and re-queries for the live view, and the dashboard shows both.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time

_BANNED_LIST_RE = re.compile(r"Banned IP list:\s*(?P<ips>.*)")
_CACHE_TTL_SECONDS = 5.0
_COMMAND_TIMEOUT_SECONDS = 5.0


class Fail2BanClient:
    """Cached wrapper around ``fail2ban-client status <jail>``."""

    def __init__(self, jail: str = "sshd", enabled: bool = True) -> None:
        self.jail = jail
        self.enabled = enabled
        self._lock = threading.Lock()
        self._banned: frozenset[str] = frozenset()
        self._fetched_at = 0.0
        self._last_error: str | None = None
        self._reachable = False

    @property
    def status(self) -> str:
        if not self.enabled:
            return "disabled"
        if self._fetched_at == 0.0:
            return "not yet queried"
        return "ready" if self._reachable else (self._last_error or "unavailable")

    def _refresh(self) -> None:
        if not self.enabled:
            self._reachable = False
            self._last_error = "disabled"
            return

        binary = shutil.which("fail2ban-client")
        if binary is None:
            self._banned = frozenset()
            self._reachable = False
            self._last_error = "fail2ban-client not installed"
            return

        # Direct call first; if the socket is refused, retry through the narrow
        # sudoers rule the installer writes. -n never prompts, so a missing
        # rule fails fast instead of hanging the ingest cycle.
        attempts = [[binary, "status", self.jail]]
        sudo = shutil.which("sudo")
        if sudo is not None:
            attempts.append([sudo, "-n", binary, "status", self.jail])

        completed = None
        for argv in attempts:
            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=_COMMAND_TIMEOUT_SECONDS,
                    check=False,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                self._reachable = False
                self._last_error = f"query failed: {exc.__class__.__name__}"
                return
            if completed.returncode == 0:
                break

        if completed is None or completed.returncode != 0:
            self._reachable = False
            detail = ((completed.stderr or completed.stdout) if completed else "").strip().splitlines()
            self._last_error = detail[0][:120] if detail else "non-zero exit"
            return

        match = _BANNED_LIST_RE.search(completed.stdout)
        self._banned = frozenset(match.group("ips").split()) if match else frozenset()
        self._reachable = True
        self._last_error = None

    def banned_ips(self) -> frozenset[str]:
        """Current ban list, cached briefly so alerts do not each fork a process."""
        with self._lock:
            if time.monotonic() - self._fetched_at > _CACHE_TTL_SECONDS:
                self._refresh()
                self._fetched_at = time.monotonic()
            return self._banned

    def is_banned(self, ip: str) -> bool | None:
        """``True``/``False`` when fail2ban answered, ``None`` when unknown."""
        banned = self.banned_ips()
        if not self._reachable:
            return None
        return ip in banned
