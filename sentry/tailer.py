"""Rotation-safe incremental log reading.

A monitor that re-reads a whole log every cycle double-counts; one that blindly
seeks to a saved byte offset goes permanently blind the first time logrotate
runs. This module handles the three transitions that actually happen in
production:

1. **Append** -- same inode, file grew. Read from the saved offset.
2. **Rename rotation** (logrotate default) -- the inode behind the path
   changed. The tail of the old file still holds unread lines, so we drain
   ``<path>.1`` from the saved offset *before* switching to the new inode.
3. **Copytruncate rotation** -- same inode, but the file shrank. The saved
   offset now points past EOF, so we restart at zero.

Lines are decoded with ``errors="replace"``: log content is partly
attacker-controlled and invalid UTF-8 must not be able to halt ingestion.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TailPosition:
    inode: int | None = None
    byte_offset: int = 0


@dataclass
class TailedLine:
    inode: int
    byte_offset: int
    text: str


@dataclass
class TailResult:
    lines: list[TailedLine] = field(default_factory=list)
    position: TailPosition = field(default_factory=TailPosition)
    rotated: bool = False


def _read_from(path: Path, inode: int, start: int) -> tuple[list[TailedLine], int]:
    """Read whole lines from ``start`` to EOF, returning them and the new offset.

    A trailing partial line (the writer was mid-append) is deliberately left
    unconsumed so it gets picked up complete on the next cycle.
    """
    collected: list[TailedLine] = []
    with path.open("rb") as fh:
        fh.seek(start)
        raw = fh.read()

    if not raw:
        return collected, start

    consumed = 0
    for chunk in raw.splitlines(keepends=True):
        if not chunk.endswith((b"\n", b"\r")):
            break  # partial line; leave it for next time
        offset = start + consumed
        consumed += len(chunk)
        text = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
        if text.strip():
            collected.append(TailedLine(inode=inode, byte_offset=offset, text=text))

    return collected, start + consumed


def read_new_lines(path: Path, previous: TailPosition) -> TailResult:
    """Collect unread lines from ``path`` given the previously saved position."""
    stat = path.stat()  # raises if unreadable; caller records the error
    current_inode = stat.st_ino
    result = TailResult()

    # --- Case 2: rename rotation -----------------------------------------
    if previous.inode is not None and previous.inode != current_inode:
        result.rotated = True
        rotated_path = path.with_name(path.name + ".1")
        try:
            if rotated_path.exists() and rotated_path.stat().st_ino == previous.inode:
                drained, _ = _read_from(rotated_path, previous.inode, previous.byte_offset)
                result.lines.extend(drained)
        except OSError:
            # The rotated file may be compressed or already gone. Losing its
            # tail is acceptable; failing to advance past it is not.
            pass
        start = 0

    # --- Case 3: copytruncate --------------------------------------------
    elif previous.inode == current_inode and stat.st_size < previous.byte_offset:
        result.rotated = True
        start = 0

    # --- Case 1: plain append (or first ever read) ------------------------
    else:
        start = previous.byte_offset

    fresh, new_offset = _read_from(path, current_inode, start)
    result.lines.extend(fresh)
    result.position = TailPosition(inode=current_inode, byte_offset=new_offset)
    return result
