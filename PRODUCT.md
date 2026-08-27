# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: the operator, who is also the author.** One person running VPS Sentry
on a VPS they own, reaching the dashboard from a laptop over an SSH tunnel
(`ssh -N -L 8787:127.0.0.1:8787`). Not a team, no multi-tenancy, no roles.

They work in two distinct situations, and both are real:

- **Operating.** Checking whether the host is under attack right now, whether
  anything succeeded, and whether existing defences already handled it.
- **Defending the work.** Explaining any given alert, line by line, to an
  examiner in a cybersecurity subject assessment.

Where the two conflict, **real operational correctness wins.** The assessment is
a milestone; the tool is expected to keep running afterwards.

## Product Purpose

A passive host intrusion monitor for a single VPS. It reads logs the server
already writes, applies rule-based detectors, and reports what it found. It
does not act.

Success is that the operator can tell at a glance:

1. whether the host is under attack right now,
2. whether anything *succeeded*,
3. and whether the monitor itself is still reading.

The third is not a footnote. A monitor that has silently stopped reading is
indistinguishable from a quiet network, and is worse than no monitor at all,
because it is trusted.

## Positioning

Four mechanisms a neighbouring log monitor could not truthfully claim:

- **Its thresholds deliberately match the enforcement layer already on the
  box.** SSH defaults (5 failures / 10 minutes) mirror fail2ban's stock `sshd`
  jail, so an alert here corresponds to a ban there rather than the two
  disagreeing for reasons nobody can explain.
- **It cross-checks its own alerts against fail2ban** and reports *unknown*
  distinctly from *not banned* — "we could not ask" and "we asked and it is
  not banned" are different facts and are never merged.
- **It correlates success against attack.** A successful SSH login from an
  address that tripped an alert within the hour is raised as its own critical
  event: the brute force stopping because it worked.
- **It is built around the failure mode of looking fine while blind.**
  Freshness is the most prominent element on the page; unreadable log sources
  raise events; score rules abstain rather than deduct when their input could
  not be measured.

## Operating Context

- **Target host:** a single Debian/Ubuntu VPS with systemd. Reads
  `/var/log/auth.log` (rsyslog) and `/var/log/ufw.log` (UFW).
- **Permissions:** both logs are normally `root:adm`, so the process needs the
  `adm` group or root. `fail2ban-client` and `ufw status` normally need root.
- **Known deployment hazards:** newer Ubuntu cloud images ship without rsyslog,
  so `/var/log/auth.log` may not exist at all; UFW rate-limits its own logging;
  a key-only server never writes `Failed password`.
- **Deployment:** `install.sh` installs to `/opt/vps-sentry` under an
  unprivileged service account with a systemd unit. **Not yet exercised against
  a real host.**
- **Development happens on macOS**, where the host, port and user collectors
  run degraded on purpose (CPU derived from load average, `lsof` instead of
  `/proc`). This exists so the dashboard is demonstrable on a laptop and is
  openly labelled in the UI; it is not a supported deployment target.
- **Demo path:** `tools/seed.py` writes logs stamped relative to now;
  `tools/replay.py` drip-feeds live traffic so the dashboard visibly moves.
  Reseeding and clearing the database must happen together, or the saved tail
  offset sits past the new content and the dashboard shows nothing.

## Capabilities and Constraints

**Detectors** (threshold within a sliding window, per source IP):
SSH brute force — 5 failed authentications in 10 minutes. Port scan — 4
distinct blocked destination ports in 60 seconds.

**Collectors:** host metrics (CPU, memory, disk, network, uptime); listening
sockets with exposure classification and new-port detection; local accounts
resolved against effective sshd policy; UFW active state.

**Enrichment:** attempted usernames, offline GeoIP country, fail2ban ban
status, port-to-service naming.

**Derived:** a unified event stream feeding both the Security Events view and
the Activity Log; a rules-based posture score.

### Binding constraints — confirmed, future work may not violate

- **Detection stays rule-based and traceable.** Threshold-and-window
  arithmetic over rows a human can read. No models, no learned scoring.
- **Observe and report only.** Never auto-blocks, bans, or modifies the system.
  Blocking is a decision for the operator or for fail2ban. The users collector
  is read-only and gains no write path.

### Current implementation choices — NOT binding

These are how it works today and were explicitly *not* marked permanent. They
may be revisited, but changing either is a deliberate product decision, not a
default to drift out of:

- **Runs fully offline.** GeoIP is a local `.mmdb`; there are no threat-intel
  API calls. Future work *may* introduce outbound calls.
- **Adds no listening surface.** Binds to loopback and is reached over an SSH
  tunnel. Future work *may* expose a network surface — which would require
  authentication that does not exist today.

### Technical constraints

Python 3.13, FastAPI, uvicorn, SQLite. The dashboard is vanilla HTML, CSS and
JavaScript served by the same process, with **no build step and no
dependencies** — chosen so the tool adds no toolchain to the host.

Ingestion is idempotent: event inserts and the tail-offset advance commit in
one transaction, and every event carries `(inode, byte_offset)`. Log rotation
is handled explicitly for both rename and copytruncate.

### Terminology

**Alert** — an open incident for one IP, escalating in place. **Event** — one
entry in the unified feed. **Detector** — reads logs. **Collector** — reads
host state. **Exposure** — public / private / loopback. **Severity** —
critical, high, medium, low, info. **Counting kinds** — the SSH event types
that may move a threshold; precursor lines are stored but excluded.

### Explicitly undecided

- Whether the seeded attacker IPs move to RFC 5737 documentation ranges.
- Whether the project directory renames from `vps-sentinel` to `vps-sentry`.

## Brand Commitments

- **Name:** VPS Sentry. **Tagline:** Lightweight VPS Security Monitor. The
  header strapline is "VPS Sentry / security monitor" — the name already
  carries "VPS", so the strapline does not repeat it.
- **Known collision, accepted:** "Sentry" is also sentry.io, an established
  error-monitoring product. Unaffiliated. This was raised and the name was
  chosen anyway; any write-up should note the lack of affiliation.
- **Score phrasing is binding.** Always "VPS Sentry Security Score: 87/100";
  never "your VPS is 87% secure". The first is this tool's own indicator; the
  second is a claim about reality the rule set cannot support.
- **Voice:** states its limits inside the product. The README documents what
  the tool structurally cannot see, and the dashboard surfaces degraded
  enrichment rather than hiding it.

## Evidence on Hand

- **Everything currently shown on the dashboard is synthetic**, generated by
  `tools/seed.py`. It must be labelled as such wherever it is presented. No
  real attack has been observed yet.
- **The seeded attacker IPs are real allocations** — `185.220.101.44` (a Tor
  exit network), `20.106.44.19` (Microsoft), `159.223.88.201` (DigitalOcean),
  `45.148.10.92` (RIPE). Presenting them as observed attackers would be
  fabricated attribution against real operators. Unresolved; see Undecided.
- `fixtures/auth.log` and `fixtures/ufw.log` are genuine OpenSSH and UFW *line
  formats*, hand-written as parser reference. Real formats, not real captures.
- **146 passing tests**, covering timestamp year inference, every sshd line
  variant, all three log-rotation modes, threshold and window behaviour, alert
  escalation, event idempotency, score arithmetic, and the API contract.
- A VPS exists but Sentry is **not deployed to it**. Real log evidence is
  expected later and does not exist now.
- **No** benchmarks, users, uptime figures, detection rates, or false-positive
  rates exist. Future work must not invent them.

## Product Principles

1. **Blindness is reported as loudly as attack.** A monitor that has stopped
   reading must never resemble a quiet network.
2. **"Unknown" is a distinct answer from "no."** Where a fact could not be
   determined, say so rather than defaulting to the reassuring reading. This
   governs ban status, score deductions, and collector availability alike.
3. **Every detection traces to rows a human can read.** If it cannot be
   explained line by line, it does not ship.
4. **Observe, never act.** The tool informs a decision; it never takes one.
5. **State the limits inside the product.** What the tool cannot see — scans of
   open ports, slow scans below the window, distributed attempts — is part of
   what it reports, not an omission to be discovered later.

## Accessibility & Inclusion

- **Severity is encoded on three channels** — hue, an uppercase text label, and
  a left rule — so red/amber severity survives red-green colour blindness and a
  monochrome printout.
- `prefers-reduced-motion` is honoured; motion is reserved for state change
  rather than decoration.
- Read on a laptop over an SSH tunnel, so no large display is assumed: the
  layout collapses to a single column below 1040px and again below 680px, with
  no horizontal scroll.
