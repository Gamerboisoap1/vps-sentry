# VPS Sentry

**Lightweight VPS Security Monitor**

It reads two logs your server already
writes, applies two rule-based detectors, and shows what is happening on a
dashboard that refreshes itself.

A sentry watches and raises the alarm; it does not leave its post to fight.
VPS Sentry detects and reports — blocking stays a decision you (or fail2ban)
make.

No AI, no external threat-intel APIs, no SIEM stack, and no new service
listening on the box.

---

## What it detects

**SSH brute force** — five or more failed authentications from one IP inside a
ten-minute sliding window. Those defaults deliberately match fail2ban's stock
`sshd` jail (`maxretry=5`, `findtime=10m`) so an alert here corresponds to a
ban there instead of disagreeing for reasons nobody can explain.

**Port scanning** — four or more *distinct* destination ports from one IP
inside a sixty-second window, read from UFW's block log.

Both rules are threshold-plus-window arithmetic over rows in a SQLite table.
Every alert traces back to specific events and can be explained line by line.

## What it adds on top

| Feature | Cost |
| --- | --- |
| Username capture | An extra column parsed from lines already being read |
| GeoIP country | One local `.mmdb` file, read offline, no API calls |
| fail2ban cross-check | One `fail2ban-client` call, cached for five seconds |

All three reuse data already flowing through the pipeline. None adds a log
source, a daemon, or an inbound port.

## On the dashboard

- **Activity timeline** — 24 hourly buckets, failed authentications and blocked
  probes as separate series. Hourly rather than averaged, because a brute force
  is a burst and averaging is exactly what hides one.
- **Service identification** — probed ports are named and categorised, so a
  scan report reads `27017 MongoDB` rather than a bare number. Ports are tinted
  by what a hit would have cost: databases red, remote access amber, and so on.
- **Threat posture** — a plain count of alerts still moving in the last fifteen
  minutes, not a score. The number on screen always traces to specific rows.
- **Freshness** — time since the last successful log read, always visible.
- **Username breakdown** — which accounts attackers targeted, as shares.

---

## Quick start

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Run it against generated demo data:

```bash
./.venv/bin/python -m tools.seed --reset
./demo.sh
```

Then open <http://127.0.0.1:8787>.

To make the dashboard visibly move while someone is watching, in a second
terminal:

```bash
./.venv/bin/python -m tools.replay --rate 1.5
```

## Installing on a VPS

Upload the project directory to your server, then:

```bash
sudo ./install.sh
```

That single command installs the dependencies, creates an unprivileged
`sentry` service account, builds a virtualenv under `/opt/vps-sentry`,
writes a hardened systemd unit, and starts it on loopback. It is safe to
re-run — every step checks its own state first.

It also handles the two things that silently break this kind of tool:

- **Missing `auth.log`.** Newer Ubuntu cloud images ship without rsyslog and
  log authentication only to journald, so the file never exists. The installer
  detects that and installs rsyslog.
- **UFW logging off.** It enables `ufw logging low`, which is all the port-scan
  detector needs. Enabling logging does not enable the firewall itself.

To include country data, supply a free MaxMind licence key:

```bash
sudo MAXMIND_LICENSE_KEY=your_key_here ./install.sh
```

Afterwards:

```bash
systemctl status vps-sentry
journalctl -u vps-sentry -f
sudo ./install.sh --uninstall
```

### It does not run as root

A monitoring daemon holding root to read two log files is a poor trade, so the
installer creates a system account in the `adm` group — which is what grants
read access to `auth.log` and `ufw.log` — and grants exactly one sudoers rule:

```
sentry ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status sshd
```

That one command, and nothing else. The systemd unit adds `ProtectSystem=strict`,
`PrivateTmp`, `ProtectHome`, and `MemoryDenyWriteExecute`, with `ReadWritePaths`
limited to the data directory. `NoNewPrivileges` is deliberately left off,
because it would block that sudo rule.

## Running manually

```bash
SENTRY_AUTH_LOG=/var/log/auth.log \
SENTRY_UFW_LOG=/var/log/ufw.log \
  ./.venv/bin/python -m uvicorn sentry.api:app --host 127.0.0.1 --port 8787
```

Reach it from your laptop over an SSH tunnel:

```bash
ssh -N -L 8787:127.0.0.1:8787 you@your-vps
```

**Sentry binds to loopback on purpose.** Serving it on `0.0.0.0` would publish
your log data and an unauthenticated endpoint on the machine you are trying to
protect, which would undo the whole point.

### Check these three things first

1. **Does `/var/log/auth.log` exist?** On newer Ubuntu cloud images rsyslog is
   not installed and authentication goes only to journald. If the file is
   missing, Sentry says so on the dashboard rather than sitting silently at
   zero. Fix with `apt install rsyslog`, or export the journal to a file.
2. **Is UFW logging on?** `sudo ufw logging low` is enough — low already logs
   blocked packets.
3. **Can the process read the logs?** Both files are normally `root:adm`.
   Either run Sentry as a user in the `adm` group, or run it as root.

### Optional enrichment

**GeoIP.** Download `GeoLite2-Country.mmdb` from MaxMind (a free account and
licence key are required, though lookups afterwards are entirely offline) and
place it at `data/GeoLite2-Country.mmdb`. Without it, alerts simply show no
country.

**fail2ban.** If `fail2ban-client` is installed and reachable, Sentry shows
whether each attacker is currently banned. Querying it usually needs root.
Without it, every alert shows `ban unknown` — which is rendered distinctly
from `not banned`, because "we could not ask" and "we asked and it is not
banned" are different facts.

---

## Configuration

Every tunable is an environment variable, defined in `sentry/config.py`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTRY_AUTH_LOG` | `/var/log/auth.log` | SSH log to read |
| `SENTRY_UFW_LOG` | `/var/log/ufw.log` | Firewall log to read |
| `SENTRY_DB` | `data/sentry.db` | SQLite file |
| `SENTRY_SSH_THRESHOLD` | `5` | Failed auths to trip the rule |
| `SENTRY_SSH_WINDOW` | `600` | SSH window, seconds |
| `SENTRY_SSH_COOLDOWN` | `600` | Suppression window, seconds |
| `SENTRY_SCAN_PORTS` | `4` | Distinct ports to trip the rule |
| `SENTRY_SCAN_WINDOW` | `60` | Scan window, seconds |
| `SENTRY_POLL_SECONDS` | `10` | Ingest cycle interval |
| `SENTRY_STALE_AFTER` | `60` | Freshness alarm threshold |
| `SENTRY_RETENTION_DAYS` | `30` | Event retention horizon |
| `SENTRY_HOST` / `SENTRY_PORT` | `127.0.0.1` / `8787` | Bind address |
| `SENTRY_F2B_JAIL` | `sshd` | fail2ban jail to query |
| `SENTRY_F2B_ENABLED` | `1` | Set to `0` to skip fail2ban entirely |

---

## How it works

```
/var/log/auth.log ─┐
                   ├─► tailer (offset + inode, rotation-safe)
/var/log/ufw.log  ─┘        │
                            ▼
                   regex parsers ──► SQLite events
                                          │
                                          ▼
                            threshold + sliding window
                                          │
                                          ▼
                              alerts (+ geo, + ban status)
                                          │
                                          ▼
                                   FastAPI JSON
                                          │
                                          ▼
                                  dashboard (polls)
```

### Five decisions worth knowing

**Ingestion is idempotent.** Event inserts and the tail-offset advance commit
in one transaction, so a batch is either stored with the offset moved past it
or neither. Every event also carries `(inode, byte_offset)`, unique for a
physical line on disk, as a second guard.

**Rotation is handled explicitly.** When logrotate renames the file, the tail
of `auth.log.1` is drained from the saved offset before switching to the new
inode. Copytruncate is detected by the file shrinking below the saved offset.
Tests cover both.

**One attempt is not two events.** sshd logs `Invalid user admin` and then
`Failed password for invalid user admin` for a single attempt. Counting both
would halve the effective threshold, so the precursor is stored as evidence
but excluded from `COUNTING_KINDS`.

**Key-only servers are handled.** With `PasswordAuthentication no` there is no
`Failed password` line at all; brute force appears as
`Connection closed by authenticating user root ... [preauth]`. A parser that
only knows the password line reports zero during a live attack.

**Alerts escalate instead of multiplying.** Once an alert is open for an IP,
further activity within the cooldown updates it in place — with totals across
the whole incident, not just the current window. Otherwise a sustained attack
emits a fresh alert per log line.

---

## Known limitations

These are properties of the design, and stating them is part of the work.

- **UFW only logs what it blocked**, so scans of *closed* ports are visible
  and probes of open services (22, 80, 443) are not.
- **UFW rate-limits its own logging** (roughly a burst then a few lines a
  minute). A thousand-port sweep may leave only a handful of lines. The
  four-port threshold is low precisely because the evidence is throttled —
  Sentry sees a sample of a scan, not the scan.
- **A slow scan evades the window.** Paced wider than sixty seconds, a sweep
  stays under the rule. This is the standard trade-off of a fixed window and
  is covered by an explicit test.
- **Detection is per-IP**, so distributed attempts from many addresses do not
  pool into one alert.
- **fail2ban's answer is point-in-time.** Stock bans expire after ten minutes,
  so "not banned" can mean "was banned, already released". Sentry records the
  status at detection time and queries again live, and shows both.
- **The dashboard has no authentication.** It is protected by binding to
  loopback, nothing more. Do not expose it.

---

## Tests

```bash
./.venv/bin/python -m pytest -q
```

87 tests covering timestamp inference, every sshd line variant, UFW parsing,
all three rotation modes, threshold and window behaviour, alert escalation,
port identification, timeline bucketing, and the API contract — including that
stats exclude precursor lines and that the health endpoint reports staleness.

---

## Layout

```
sentry/
├── config.py         Thresholds, paths, bind address
├── timeparse.py      Syslog timestamps, including year inference
├── tailer.py         Rotation-safe incremental reads
├── parsers/          ssh.py, ufw.py — regex extraction
├── detect.py         Threshold + window rules
├── enrich/           geoip.py, fail2ban.py — both degrade gracefully
├── services.py       Port to service and category identification
├── db.py             Schema, event insert, alert upsert, retention
├── ingest.py         The cycle that ties it together
└── api.py            FastAPI endpoints + static dashboard
static/               index.html, style.css, app.js — no build step
tools/                seed.py, replay.py — demo data
tests/                87 tests
install.sh            One-command VPS install (systemd + hardened unit)
demo.sh               Run locally against generated demo logs
```
