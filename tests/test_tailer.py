"""Rotation safety. These are the cases that silently break naive tailers."""
import os

from sentry.tailer import TailPosition, read_new_lines


def test_first_read_returns_everything(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("line one\nline two\n")
    result = read_new_lines(log, TailPosition())
    assert [l.text for l in result.lines] == ["line one", "line two"]
    assert result.position.byte_offset == len("line one\nline two\n")


def test_second_read_returns_only_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("line one\n")
    first = read_new_lines(log, TailPosition())

    with log.open("a") as fh:
        fh.write("line two\n")
    second = read_new_lines(log, first.position)

    assert [l.text for l in second.lines] == ["line two"]
    assert not second.rotated


def test_no_new_data_yields_nothing(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("only line\n")
    first = read_new_lines(log, TailPosition())
    second = read_new_lines(log, first.position)
    assert second.lines == []
    assert second.position.byte_offset == first.position.byte_offset


def test_partial_trailing_line_is_left_for_next_cycle(tmp_path):
    """A half-written line must not be parsed as if it were complete."""
    log = tmp_path / "auth.log"
    log.write_text("complete line\npartial li")
    first = read_new_lines(log, TailPosition())
    assert [l.text for l in first.lines] == ["complete line"]

    with log.open("a") as fh:
        fh.write("ne here\n")
    second = read_new_lines(log, first.position)
    assert [l.text for l in second.lines] == ["partial line here"]


def test_rename_rotation_drains_old_file_then_reads_new(tmp_path):
    """logrotate's default: auth.log -> auth.log.1, then a fresh auth.log."""
    log = tmp_path / "auth.log"
    log.write_text("old one\n")
    first = read_new_lines(log, TailPosition())
    assert [l.text for l in first.lines] == ["old one"]

    # A line lands in the old file after our last read, then rotation happens.
    with log.open("a") as fh:
        fh.write("old two (unread at rotation)\n")
    log.rename(tmp_path / "auth.log.1")
    log.write_text("brand new line\n")

    second = read_new_lines(log, first.position)
    assert second.rotated is True
    texts = [l.text for l in second.lines]
    assert "old two (unread at rotation)" in texts, "tail of rotated file was lost"
    assert "brand new line" in texts
    assert second.position.inode == os.stat(log).st_ino


def test_copytruncate_rotation_restarts_at_zero(tmp_path):
    """Same inode, file shrank: the saved offset now points past EOF."""
    log = tmp_path / "auth.log"
    log.write_text("aaaa\nbbbb\ncccc\n")
    first = read_new_lines(log, TailPosition())
    assert len(first.lines) == 3

    log.write_text("short\n")  # truncate in place, same inode
    second = read_new_lines(log, first.position)
    assert second.rotated is True
    assert [l.text for l in second.lines] == ["short"]


def test_rotation_without_recoverable_old_file_still_advances(tmp_path):
    """If the rotated file is gone or compressed, we must not stall."""
    log = tmp_path / "auth.log"
    log.write_text("first gen\n")
    first = read_new_lines(log, TailPosition())

    log.unlink()
    log.write_text("second gen\n")
    second = read_new_lines(log, first.position)
    assert second.rotated is True
    assert [l.text for l in second.lines] == ["second gen"]


def test_invalid_utf8_does_not_halt_ingestion(tmp_path):
    """Log content is partly attacker-controlled; bad bytes must not raise."""
    log = tmp_path / "auth.log"
    log.write_bytes(b"good line\n\xff\xfe broken bytes\ngood again\n")
    result = read_new_lines(log, TailPosition())
    assert len(result.lines) == 3
    assert result.lines[0].text == "good line"
    assert result.lines[2].text == "good again"


def test_offsets_are_unique_per_line(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("a\nbb\nccc\n")
    result = read_new_lines(log, TailPosition())
    offsets = [l.byte_offset for l in result.lines]
    assert offsets == [0, 2, 5]
    assert len(set(offsets)) == len(offsets)


def test_blank_lines_are_skipped_but_offset_still_advances(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("real\n\n\nalso real\n")
    result = read_new_lines(log, TailPosition())
    assert [l.text for l in result.lines] == ["real", "also real"]
    assert result.position.byte_offset == len("real\n\n\nalso real\n")
