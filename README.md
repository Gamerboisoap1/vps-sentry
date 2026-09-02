# VPS Sentry

**Lightweight VPS security monitor.** Reads the logs your server already writes,
applies rule-based detection, and shows what is happening — on one page, over an
SSH tunnel, with no agent and nothing new listening.

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-149-4c9a76)
![Dependencies](https://img.shields.io/badge/runtime%20deps-3-6a7280)
![Frontend](https://img.shields.io/badge/frontend-no%20build%20step-6a7280)
![License](https://img.shields.io/badge/license-MIT-6a7280)

No AI. No external threat-intel APIs. No SIEM stack. Two regex parsers, a
sliding window, and SQLite.

> A sentry watches and raises the alarm; it does not leave its post to fight.
> VPS Sentry detects and reports — blocking stays a decision you, or fail2ban,
> make.

---

## Why it might interest you

Most log monitors are a thin wrapper over `grep`. The interesting part of this
one is the set of traps it handles, each of which silently breaks the naive
version:

| Trap | What happens without handling it |
| --- | --- |
| **Key-only servers** | `PasswordAuthentication no` never writes `Failed password`. The monitor reports zero during a live attack. |
| **One attempt, two log lines** | sshd logs `Invalid user x` *and* `Failed password for invalid user x`. Counting both halves your threshold. |
| **Log rotation** | A saved byte offset points into a file that no longer exists. The monitor goes permanently blind. |
| **Year-less syslog stamps** | `Dec 31 23:58` parsed on Jan 1 lands twelve months in the future. |
| **UFW throttling its own logs** | A 1000-port sweep may leave ten lines. You are sampling a scan, not observing one. |
| **Going blind quietly** | A monitor that stopped reading looks exactly like a quiet network. |

Each one has a test. [The engineering section](#the-engineering) explains the
handling.

### The one signal worth waking up for

A successful SSH login is ordinarily routine `info`. A successful login **from
an address that tripped an alert within the last hour** is `SSH_LOGIN_AFTER_ATTACK`
at `critical`, and costs 25 points of score.

That is the brute force stopping *because it worked* — and it is the sequence
this whole tool exists to catch.

Classification deliberately runs **after** detection in the ingest cycle: on a
first ingest the alert that makes the login significant is created in that same
cycle, so running earlier files the breach as an ordinary login. There is a
regression test for exactly that ordering.

---

## Contents

- [What it detects](#what-it-detects)
- [Quick start](#quick-start)
- [Installing on a VPS](#installing-on-a-vps)
- [On the dashboard](#on-the-dashboard)
- [The engineering](#the-engineering)
- [Configuration](#configuration)
- [API](#api)
- [Known limitations](#known-limitations)
- [Tests](#tests)
- [Layout](#layout)

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

---

## Quick start

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements-dev.txt
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

### Reaching it without a tunnel

The tunnel is the default because the dashboard has **no authentication** —
the loopback bind is the entire access control. But `/api/score` returns a
ranked list of this host's weaknesses, `/api/users` lists who can log in over
SSH, and `/api/ports` lists everything listening. Served openly, that is a
reconnaissance report on the machine it is protecting, so simply setting
`SENTRY_HOST=0.0.0.0` is the one change you should not make.

To get a public URL safely, put nginx in front with a password and TLS. Sentry
keeps binding to loopback; nginx is the only public listener and proxies
inward, so the app cannot be reached by hitting the port directly.

```bash
sudo apt install -y nginx apache2-utils certbot python3-certbot-nginx
sudo htpasswd -c /etc/nginx/.htpasswd-sentry YOUR_USERNAME
sudo cp deploy/nginx-vps-sentry.conf /etc/nginx/sites-available/vps-sentry
sudo sed -i "s/sentry.example.com/YOUR_DOMAIN/g" /etc/nginx/sites-available/vps-sentry
sudo ln -sf /etc/nginx/sites-available/vps-sentry /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d YOUR_DOMAIN
sudo ufw allow 'Nginx Full'
```

[`deploy/nginx-vps-sentry.conf`](deploy/nginx-vps-sentry.conf) also sets
`noindex`, `DENY` framing and `no-referrer`, and carries a commented IP
allow-list if you want a second lock in front of the password.

### Check these three things first

1. **Does `/var/log/auth.log` exist?** On newer Ubuntu cloud images rsyslog is
   not installed and authentication goes only to journald. If the file is
   missing, Sentry says so on the dashboard rather than sitting silently at
   zero. Fix with `apt install rsyslog`, or export the journal to a file.
2. **Is UFW logging on?** `sudo ufw logging low` is enough — low already logs
   blocked packets.
3. **Can the process read the logs?** Both files are normally `root:adm`.
   Either run Sentry as a user in the `adm` group, or run it as root.

### A note on platform

The host, port and user collectors are written for Linux and read /proc
directly. They also run on macOS so the dashboard can be developed and
demonstrated on a laptop, with two honest downgrades: CPU is derived from load
average (and says so on screen), and listening sockets come from `lsof`.
Anywhere else, each collector reports itself unsupported and the log detectors
carry on unaffected.

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

## What else it shows

Everything below reuses data the host already publishes. No agent is
installed, nothing new listens, and each collector can be switched off
independently.

**Security Events and Activity Log** are two views of one table. The Activity
Log is everything observed; Security Events is the same rows filtered to
medium severity and above. Keeping one store means an event cannot appear in
one view and be missing from the other. The log filters by category
(SSH / Network / System) and searches across IP, username and description.

**VPS health** — CPU, memory, disk, network throughput and uptime, read from
`/proc/stat`, `/proc/meminfo`, `statvfs` and `/proc/net/dev`. Memory uses
`MemAvailable` rather than `MemFree`, which is why it does not report 95% on
an idle box with a warm page cache. CPU is a rate, so the first cycle after
startup reports nothing rather than a fabricated figure.

**Open ports** — listening sockets from `/proc/net/tcp[6]` and `/proc/net/udp[6]`,
named through the same service table the scan detector uses. Each is
classified by exposure, because a service bound to `127.0.0.1` is not
reachable from the internet and calling it "open" would be alarming and
wrong. A port that appears when it was not there before raises a `NEW_PORT`
event; the first run records a baseline instead of announcing every existing
listener at once.

**System users** — accounts from `/etc/passwd`, resolved against the effective
sshd policy: `AllowUsers`, `AllowGroups`, `DenyUsers`, `PermitRootLogin`,
`PasswordAuthentication` and the presence of `authorized_keys`. The question
answered is not "who exists" but "who can actually log in", which is a
different and smaller set. Strictly read-only.

**Security score** — a plain sum of named deductions from a base of 100,
returned together with every deduction so the dashboard can show its working.
A rule whose input is unavailable does not deduct; it is listed as not
assessed, because penalising the operator for something we could not measure
would drift the score down on hardened hosts that merely deny us a reading.

Phrase it as *VPS Sentry Security Score: 87/100*, never "your VPS is 87%
secure". The first is this tool's own indicator; the second is a claim about
reality that a rule set this size cannot support.

---

## The engineering

### The pipeline

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
| `SENTRY_COLLECT_HOST` | `1` | Sample CPU / memory / disk / network |
| `SENTRY_COLLECT_PORTS` | `1` | Enumerate listening sockets |
| `SENTRY_COLLECT_USERS` | `1` | Read account list and sshd policy |
| `SENTRY_DISK_PATH` | `/` | Filesystem to report usage for |
| `SENTRY_HOST_RETENTION_HOURS` | `48` | Host-sample retention |

Each collector can be switched off independently, so a host where `/proc` is
restricted or `lsof` is absent still runs the log detectors.

---

## API

All endpoints are read-only JSON. There are no write endpoints: the tool
observes and never acts.

| Endpoint | Returns |
| --- | --- |
| `GET /api/alerts` | Open incidents; `kind`, `limit` |
| `GET /api/stats` | Totals, username shares, countries, top ports |
| `GET /api/timeline` | Hourly buckets for the activity chart; `hours` |
| `GET /api/health` | Freshness per source, rule thresholds, enrichment status |
| `GET /api/events` | Unified feed; `category`, `min_severity`, `search`, `limit` |
| `GET /api/host` | Latest host sample plus a short trend |
| `GET /api/ports` | Live listening sockets with exposure |
| `GET /api/users` | Accounts and effective SSH policy |
| `GET /api/score` | Score, band, and every deduction |

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
  loopback, nothing more. Do not expose it directly — put a reverse proxy
  with a password in front instead, as described in
  [Reaching it without a tunnel](#reaching-it-without-a-tunnel).

---

## Tests

```bash
./.venv/bin/python -m pytest -q
```

149 tests covering timestamp inference, every sshd line variant, UFW parsing,
all three rotation modes, threshold and window behaviour, alert escalation,
port identification, timeline bucketing, event idempotency, score
arithmetic, /proc address decoding, sshd policy resolution, and the API
contract — including that
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
├── collect/          host.py, ports.py, users.py, firewall.py — host state
├── services.py       Port to service and category identification
├── events.py         The unified event stream (feed + activity log)
├── score.py          Rules-based posture score, deductions included
├── db.py             Schema, event insert, alert upsert, retention
├── ingest.py         The cycle that ties it together
└── api.py            FastAPI endpoints + static dashboard
static/               index.html, style.css, app.js — no build step
tools/                seed.py, replay.py — demo data
tests/                149 tests
deploy/               nginx reverse-proxy template for public access
install.sh            One-command VPS install (systemd + hardened unit)
demo.sh               Run locally against generated demo logs
```

---

## Licence

MIT — see [LICENSE](LICENSE).

## A note on the data

Every figure in a fresh checkout is **synthetic**, generated by `tools/seed.py`
so the dashboard is demonstrable without waiting for a real attack. The seeded
attacker addresses are real allocations belonging to third parties and must not
be presented as observed attackers. Point it at a real host to see real data.
