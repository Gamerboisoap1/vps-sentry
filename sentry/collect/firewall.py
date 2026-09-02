"""UFW active/inactive check.

`ufw status` needs root, so a plain failure is ambiguous: it may mean the
firewall is off, or merely that we are not allowed to ask. Those must not be
conflated -- the score deducts for a firewall that is off and abstains for one
it could not read. Hence a tri-state return.
"""

from __future__ import annotations

import platform
import shutil
import subprocess


def is_active() -> tuple[bool | None, str]:
    """Returns (active, explanation); active is None when undetermined."""
    if platform.system() != "Linux":
        return None, f"UFW is Linux-only (host is {platform.system()})"

    binary = shutil.which("ufw")
    if binary is None:
        return None, "ufw not installed"

    # `ufw status` requires root, and the service deliberately runs as an
    # unprivileged account. Direct call first, then the narrow sudoers rule the
    # installer writes -- the same two-step the fail2ban check uses. Without
    # this the rule could never fire on a real deployment: it would abstain
    # forever, and the score would read identically whether UFW was on or off.
    attempts = [[binary, "status"]]
    sudo = shutil.which("sudo")
    if sudo is not None:
        attempts.append([sudo, "-n", binary, "status"])

    done = None
    for argv in attempts:
        try:
            done = subprocess.run(
                argv, capture_output=True, text=True, timeout=5, check=False
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None, f"ufw status failed: {exc.__class__.__name__}"
        if done.returncode == 0:
            break

    if done is None or done.returncode != 0:
        detail = ((done.stderr or done.stdout) if done else "").strip().splitlines()
        first = detail[0][:80] if detail else "non-zero exit"
        return None, f"could not query ufw ({first})"

    text = done.stdout.lower()
    if "status: active" in text:
        return True, "UFW active"
    if "status: inactive" in text:
        return False, "UFW inactive"
    return None, "unrecognised ufw output"
