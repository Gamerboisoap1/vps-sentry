/* Sentry dashboard client.
 *
 * SECURITY NOTE: usernames, and to a lesser extent the rest of the alert
 * payload, originate in attacker-controlled log lines. An attacker who can
 * choose the username they try can choose text that lands on this page. Every
 * value below is inserted with textContent, never innerHTML -- otherwise the
 * security tool becomes the injection point, which is an embarrassing way to
 * get owned.
 */

(function () {
  'use strict';

  var POLL_MS = 5000;
  var seenAlerts = Object.create(null);   // id -> last_seen, for arrival flashes
  var firstPaintDone = false;

  // ---------------------------------------------------------------- helpers

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function relativeTime(iso) {
    if (!iso) { return '—'; }
    var seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    if (seconds < 60)    { return seconds + 's ago'; }
    if (seconds < 3600)  { return Math.floor(seconds / 60) + 'm ago'; }
    if (seconds < 86400) { return Math.floor(seconds / 3600) + 'h ago'; }
    return Math.floor(seconds / 86400) + 'd ago';
  }

  function severityFor(ratio) {
    if (ratio >= 5) { return { cls: 'high', label: 'high' }; }
    if (ratio >= 2) { return { cls: 'med',  label: 'med' }; }
    return { cls: 'low', label: 'low' };
  }

  function banBadge(alert) {
    // Three distinct answers. "Unknown" must never be rendered as "not banned":
    // one means fail2ban could not be queried, the other is a real negative.
    if (alert.banned_now === true || alert.banned_at_detection === true) {
      return el('span', 'badge badge-banned', 'banned');
    }
    if (alert.banned_now === false) {
      return el('span', 'badge badge-open', 'not banned');
    }
    return el('span', 'badge badge-unknown', 'ban unknown');
  }

  function topEntries(obj, limit) {
    return Object.keys(obj || {})
      .map(function (k) { return [k, obj[k]]; })
      .sort(function (a, b) { return b[1] - a[1]; })
      .slice(0, limit);
  }

  function geoLabel(alert) {
    var geo = el('span', 'country', alert.country);
    if (alert.country_code) {
      geo.appendChild(el('span', 'country-code', ' ' + alert.country_code));
    }
    return geo;
  }

  function isNewSince(alert) {
    return firstPaintDone && seenAlerts[alert.id] !== alert.last_seen;
  }

  // ------------------------------------------------------------- rendering

  function emptyState(title, text) {
    var wrap = el('div', 'empty');
    wrap.appendChild(el('div', 'empty-title', title));
    wrap.appendChild(el('div', 'empty-text', text));
    return wrap;
  }

  function skeleton(rows) {
    var wrap = el('div', 'skeleton');
    for (var i = 0; i < rows; i++) {
      var row = el('div', 'skel-row');
      var wide = el('div', 'skel-bar');
      wide.style.width = (55 + (i % 3) * 12) + '%';
      var thin = el('div', 'skel-bar');
      thin.style.width = (28 + (i % 4) * 8) + '%';
      row.appendChild(wide);
      row.appendChild(thin);
      wrap.appendChild(row);
    }
    return wrap;
  }

  function sshRow(alert) {
    var detail = alert.detail || {};
    var sev = severityFor(alert.event_count / (detail.threshold || 5));

    var row = el('div', 'row lvl-' + sev.cls);
    if (isNewSince(alert)) { row.classList.add('is-new'); }

    row.appendChild(el('div', 'row-ip', alert.ip));

    var count = el('div', 'row-count');
    count.appendChild(el('span', null, alert.event_count));
    count.appendChild(el('small', null, ' attempts'));
    row.appendChild(count);

    row.appendChild(el('div', 'row-when', relativeTime(alert.last_seen)));

    var meta = el('div', 'row-meta');
    meta.appendChild(el('span', 'sev sev-' + sev.cls, sev.label));
    if (alert.country) { meta.appendChild(geoLabel(alert)); }

    // Which accounts were tried is the intelligence here, so give each one
    // its own chip rather than burying them in a run-on string.
    topEntries(detail.usernames, 4).forEach(function (pair) {
      var chip = el('span', 'chip');
      chip.appendChild(el('b', null, pair[0]));
      chip.appendChild(el('span', 'chip-x', ' ×' + pair[1]));
      meta.appendChild(chip);
    });

    meta.appendChild(banBadge(alert));
    row.appendChild(meta);
    row.title = 'First seen ' + alert.first_seen + '\nLast seen ' + alert.last_seen;
    return row;
  }

  function scanRow(alert) {
    var detail = alert.detail || {};
    var portCount = detail.port_count || 0;
    var sev = severityFor(portCount / (detail.threshold || 4));

    var row = el('div', 'row lvl-' + sev.cls);
    if (isNewSince(alert)) { row.classList.add('is-new'); }

    row.appendChild(el('div', 'row-ip', alert.ip));

    var count = el('div', 'row-count');
    count.appendChild(el('span', null, portCount));
    count.appendChild(el('small', null, ' ports'));
    row.appendChild(count);

    row.appendChild(el('div', 'row-when', relativeTime(alert.last_seen)));

    var meta = el('div', 'row-meta');
    meta.appendChild(el('span', 'sev sev-' + sev.cls, sev.label));
    if (alert.country) { meta.appendChild(geoLabel(alert)); }

    // Ports tinted by what a hit would have cost: a MongoDB probe and an
    // ephemeral-port probe are not the same news.
    var services = detail.port_services || [];
    services.slice(0, 8).forEach(function (entry) {
      // Neutral in the row; the category is conveyed by the tooltip and,
      // with a legend, by the breakdown panel below.
      var chip = el('span', 'port-chip', entry.port);
      chip.title = entry.service + ' · ' + entry.category;
      meta.appendChild(chip);
    });
    if (portCount > services.slice(0, 8).length) {
      meta.appendChild(el('span', 'chip-x', '+' + (portCount - services.slice(0, 8).length)));
    }

    meta.appendChild(banBadge(alert));
    row.appendChild(meta);
    row.title = 'First seen ' + alert.first_seen + '\nLast seen ' + alert.last_seen;
    return row;
  }

  function renderPanel(containerId, countId, alerts, builder, empty) {
    var container = document.getElementById(containerId);
    clear(container);
    document.getElementById(countId).textContent = alerts.length ? alerts.length + ' active' : '';
    if (!alerts.length) { container.appendChild(empty); return; }
    alerts.forEach(function (alert) { container.appendChild(builder(alert)); });
  }

  function renderBreakdown(containerId, entries, fillClass) {
    var container = document.getElementById(containerId);
    clear(container);

    if (!entries.length) {
      container.appendChild(emptyState('No data yet', 'Nothing has been observed in this dimension.'));
      return;
    }

    var maxCount = Math.max.apply(null, entries.map(function (e) { return e.count; }));

    entries.forEach(function (entry) {
      var row = el('div', 'break-row');

      var name = el('div', 'break-name');
      name.appendChild(el('span', entry.nameClass || null, entry.name));
      if (entry.sub) { name.appendChild(el('span', 'break-sub', entry.sub)); }
      row.appendChild(name);

      var num = el('div', 'break-num');
      if (entry.share !== undefined) {
        num.appendChild(el('b', null, entry.share + '%'));
        num.appendChild(document.createTextNode(' · ' + entry.count));
      } else {
        num.appendChild(el('b', null, entry.count));
      }
      row.appendChild(num);

      // Bar width is share when we have one, otherwise relative to the row
      // with the highest count so the column still reads as a ranking.
      var pct = entry.share !== undefined
        ? entry.share
        : (maxCount ? (entry.count / maxCount) * 100 : 0);

      var track = el('div', 'share-track');
      var fill = el('div', 'share-fill ' + (entry.fillClass || fillClass || ''));
      fill.style.width = Math.max(2, Math.min(100, pct)) + '%';
      track.appendChild(fill);
      row.appendChild(track);

      container.appendChild(row);
    });
  }

  function renderTimeline(timeline) {
    var bars = document.getElementById('tl-bars');
    var axis = document.getElementById('tl-axis');
    clear(bars);
    clear(axis);

    var peak = timeline.peak || 0;
    document.getElementById('tl-peak').textContent =
      peak ? 'peak ' + peak + '/h' : 'no events in window';

    timeline.buckets.forEach(function (bucket) {
      var col = el('div', 'tl-col');
      var total = bucket.ssh + bucket.scan;
      col.title = bucket.label + ' — ' + bucket.ssh + ' failed auth, ' + bucket.scan + ' blocked probes';

      if (!total || !peak) {
        col.appendChild(el('div', 'tl-empty'));
      } else {
        // Scans stack above failed auth so the amber baseline stays readable.
        if (bucket.scan) {
          var scanSeg = el('div', 'tl-seg scan');
          scanSeg.style.height = ((bucket.scan / peak) * 100) + '%';
          col.appendChild(scanSeg);
        }
        if (bucket.ssh) {
          var sshSeg = el('div', 'tl-seg ssh');
          sshSeg.style.height = ((bucket.ssh / peak) * 100) + '%';
          col.appendChild(sshSeg);
        }
      }
      bars.appendChild(col);
      axis.appendChild(el('span', null, bucket.label));
    });
  }

  function renderPosture(threat) {
    if (!threat) { return; }
    var box = document.getElementById('posture');
    box.className = 'posture posture-' + threat.level;
    document.getElementById('posture-text').textContent = threat.label;
    box.title = threat.active_alerts_15m + ' ' +
      (threat.active_alerts_15m === 1 ? 'alert' : 'alerts') + ' — ' + threat.basis;

    var lamps = box.querySelectorAll('.bars i');
    for (var i = 0; i < lamps.length; i++) {
      lamps[i].classList.toggle('on', i < threat.level);
    }
  }

  function renderHealth(health) {
    var box = document.getElementById('freshness');
    var text = document.getElementById('freshness-text');

    var ages = health.sources
      .map(function (s) { return s.seconds_since_read; })
      .filter(function (v) { return v !== null && v !== undefined; });
    var freshest = ages.length ? Math.min.apply(null, ages) : null;

    box.classList.remove('live', 'stale', 'down');
    if (freshest === null) {
      box.classList.add('stale');
      text.textContent = 'no log read yet';
    } else if (health.healthy) {
      box.classList.add('live');
      text.textContent = 'reading · ' + freshest + 's ago';
    } else {
      box.classList.add('stale');
      text.textContent = 'degraded · ' + freshest + 's ago';
    }

    var rules = document.getElementById('rules');
    clear(rules);
    var ssh = health.rules.ssh;
    var scan = health.rules.port_scan;
    [
      ['SSH', ssh.threshold + ' fails / ' + Math.round(ssh.window_seconds / 60) + 'm', 'k-ssh'],
      ['SCAN', scan.distinct_ports + ' ports / ' + scan.window_seconds + 's', 'k-scan'],
      ['POLL', health.poll_seconds + 's', null]
    ].forEach(function (triple) {
      var item = el('span', null, null);
      item.appendChild(el('b', triple[2], triple[0] + ' '));
      item.appendChild(document.createTextNode(triple[1]));
      rules.appendChild(item);
    });

    document.getElementById('ssh-rule').textContent =
      '≥' + ssh.threshold + ' failed auth in ' + Math.round(ssh.window_seconds / 60) + ' min';
    document.getElementById('scan-rule').textContent =
      '≥' + scan.distinct_ports + ' distinct ports in ' + scan.window_seconds + 's';

    document.getElementById('foot-geo').textContent = 'GeoIP: ' + health.enrichment.geoip;
    document.getElementById('foot-f2b').textContent =
      'fail2ban (' + health.enrichment.fail2ban_jail + '): ' + health.enrichment.fail2ban;

    // Diagnostics: only rendered when something is actually wrong.
    var problems = [];
    health.sources.forEach(function (source) {
      if (source.error) {
        // The monitor is blind on this source: nothing is being detected.
        problems.push([source.source + ' parser', source.error, 'error']);
      } else if (source.stale) {
        problems.push([
          source.source + ' parser',
          'no read for ' + source.seconds_since_read + 's (expected every ' +
          health.poll_seconds + 's) — ingestion may have stopped',
          'error'
        ]);
      }
    });
    // Enrichment gaps degrade context but detection still works, so they are
    // reported at a lower level than a parser that has stopped.
    if (health.enrichment.geoip !== 'ready') {
      problems.push(['GeoIP', health.enrichment.geoip + ' — alerts will show no country', 'warn']);
    }
    if (health.enrichment.fail2ban !== 'ready') {
      problems.push(['fail2ban', health.enrichment.fail2ban + ' — ban status shows as unknown', 'warn']);
    }
    showDiagnostics(problems);
  }

  function showDiagnostics(problems) {
    var section = document.getElementById('diagnostics');
    var body = document.getElementById('diagnostics-body');
    clear(body);

    if (!problems.length) { section.hidden = true; return; }
    section.hidden = false;
    section.classList.toggle('has-error', problems.some(function (p) { return p[2] === 'error'; }));

    problems.forEach(function (pair) {
      var item = el('div', 'diag-item level-' + (pair[2] || 'warn'));
      item.appendChild(el('span', 'diag-label', pair[0]));
      item.appendChild(el('span', 'diag-text', pair[1]));
      body.appendChild(item);
    });
  }

  function renderStats(stats) {
    var t = stats.totals;
    document.getElementById('stat-attackers').textContent = t.unique_attackers;
    document.getElementById('stat-ssh').textContent = t.ssh_alerts;
    document.getElementById('stat-scan').textContent = t.scan_alerts;
    document.getElementById('stat-ssh24').textContent = t.ssh_events_24h;
    document.getElementById('stat-scan24').textContent = t.scan_events_24h;

    renderPosture(stats.threat);

    renderBreakdown('usernames', stats.usernames.map(function (u) {
      return { name: u.username, count: u.count, share: u.share };
    }), 'd-auth');

    renderBreakdown('countries', stats.countries.map(function (c) {
      return { name: c.country, sub: c.code || '', count: c.attackers };
    }), 'd-net');

    renderBreakdown('ports', stats.top_ports.map(function (p) {
      return {
        name: String(p.port),
        nameClass: 'cat-' + p.category,
        sub: p.service,
        count: p.hits,
        fillClass: 'fill-' + p.category
      };
    }));
  }


  // ======================================================================
  // Score, health, event feed, ports, users, activity log
  // ======================================================================

  var logFilter = 'all';
  var logSearch = '';
  var searchTimer = null;

  function bytes(n) {
    if (n === null || n === undefined) { return '--'; }
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }

  function rate(bps) {
    return bps === null || bps === undefined ? '--' : bytes(bps) + '/s';
  }

  function clockTime(iso) {
    if (!iso) { return '--:--'; }
    var d = new Date(iso);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  // -- score --------------------------------------------------------------
  function renderScore(score) {
    document.getElementById('score-value').textContent = score.value;
    var band = document.getElementById('score-band');
    band.textContent = score.band;
    band.className = 'score-band band-' + score.band;

    var box = document.getElementById('score-deductions');
    clear(box);

    if (!score.deductions.length && !score.unknowns.length) {
      box.appendChild(el('div', 'score-unknown', 'No deductions applied.'));
      return;
    }

    score.deductions.forEach(function (d) {
      var row = el('div', 'deduction');
      row.appendChild(el('div', 'deduction-pts', '-' + d.points));
      var text = el('div', 'deduction-text');
      text.appendChild(el('span', 'deduction-rule', d.rule.replace(/_/g, ' ')));
      text.appendChild(document.createTextNode(d.detail));
      row.appendChild(text);
      box.appendChild(row);
    });

    // Rules we could not evaluate are listed rather than silently skipped:
    // a score of 100 that simply failed to measure anything would mislead.
    score.unknowns.forEach(function (u) {
      var row = el('div', 'deduction');
      row.appendChild(el('div', 'deduction-pts', '--'));
      var text = el('div', 'deduction-text');
      text.appendChild(el('span', 'deduction-rule', 'not assessed'));
      text.appendChild(document.createTextNode(u));
      row.appendChild(text);
      box.appendChild(row);
    });
  }

  // -- host health --------------------------------------------------------
  function metric(label, valueText, subText, percent) {
    var wrap = el('div', 'metric');
    var head = el('div', 'metric-head');
    head.appendChild(el('span', 'metric-label', label));
    head.appendChild(el('span', 'metric-value', valueText));
    wrap.appendChild(head);

    if (subText) { wrap.appendChild(el('div', 'metric-sub', subText)); }

    if (percent !== null && percent !== undefined) {
      var track = el('div', 'metric-track');
      var fill = el('div', 'metric-fill' + (percent >= 90 ? ' hot' : percent >= 75 ? ' warn' : ''));
      fill.style.width = Math.max(0, Math.min(100, percent)) + '%';
      track.appendChild(fill);
      wrap.appendChild(track);
    }
    return wrap;
  }

  function renderHost(host) {
    var grid = document.getElementById('health-grid');
    var foot = document.getElementById('health-foot');
    clear(grid);

    if (!host.available) {
      grid.appendChild(emptyState('No sample yet', host.reason || 'The collector has not run.'));
      foot.textContent = host.status || '';
      return;
    }

    // CPU is a rate, so the first cycle after start genuinely has no value.
    grid.appendChild(metric(
      'CPU',
      host.cpu_percent === null ? 'measuring' : host.cpu_percent + '%',
      host.load1 !== null ? 'load ' + host.load1 : null,
      host.cpu_percent
    ));
    grid.appendChild(metric(
      'RAM',
      host.mem_percent === null ? '--' : host.mem_percent + '%',
      host.mem_used !== null ? bytes(host.mem_used) + ' of ' + bytes(host.mem_total) : null,
      host.mem_percent
    ));
    grid.appendChild(metric(
      'Disk',
      host.disk_percent === null ? '--' : host.disk_percent + '%',
      host.disk_used !== null ? bytes(host.disk_used) + ' of ' + bytes(host.disk_total) : null,
      host.disk_percent
    ));
    grid.appendChild(metric(
      'Network',
      rate(host.net_rx_bps),
      'up ' + rate(host.net_tx_bps),
      null
    ));
    grid.appendChild(metric('Uptime', host.uptime_human || '--', null, null));

    foot.textContent = host.status || '';
  }

  // -- event rows ---------------------------------------------------------
  function eventRow(event) {
    var row = el('div', 'event-row ev-' + event.severity);
    row.appendChild(el('div', 'event-time mono', clockTime(event.ts)));

    var label = el('div', 'event-label');
    label.appendChild(document.createTextNode(event.label + '  '));
    label.appendChild(el('span', 'ev-tag', event.severity));
    row.appendChild(label);

    row.appendChild(el('div', 'event-ip', event.ip || ''));
    row.appendChild(el('div', 'event-desc', event.description));
    row.title = event.ts;
    return row;
  }

  function renderFeed(body) {
    var rows = document.getElementById('feed-rows');
    clear(rows);
    var list = body.events || [];
    document.getElementById('feed-count').textContent = list.length ? list.length + ' events' : '';

    if (!list.length) {
      rows.appendChild(emptyState(
        'Nothing above routine',
        'No event has reached medium severity. Detections, new listening ports ' +
        'and logins from attacking addresses all surface here first.'
      ));
      return;
    }
    list.forEach(function (e) { rows.appendChild(eventRow(e)); });
  }

  // -- ports --------------------------------------------------------------
  function renderPorts(body) {
    var rows = document.getElementById('ports-rows');
    clear(rows);
    document.getElementById('ports-rule').textContent =
      body.count ? body.public_count + ' reachable from outside' : '';
    document.getElementById('ports-count').textContent = body.count ? body.count + ' listening' : '';

    if (!body.ports || !body.ports.length) {
      rows.appendChild(emptyState('No listening sockets found', body.status || ''));
      return;
    }

    body.ports.forEach(function (p) {
      var row = el('div', 'pu-row');
      row.appendChild(el('div', 'pu-port', p.port + '/' + p.proto));
      row.appendChild(el('div', 'pu-name', p.service));
      row.appendChild(el('span', 'tag tag-' + p.exposure, p.exposure));
      var meta = el('div', 'pu-meta');
      meta.textContent = p.address + (p.process ? '  ' + p.process : '');
      row.appendChild(meta);
      row.title = p.first_seen ? 'First seen ' + p.first_seen : 'Not yet recorded in port history';
      rows.appendChild(row);
    });
  }

  // -- users --------------------------------------------------------------
  function renderUsers(body) {
    var rows = document.getElementById('users-rows');
    clear(rows);
    document.getElementById('users-count').textContent =
      body.count ? body.ssh_capable + ' of ' + body.count + ' can SSH' : '';

    var list = (body.users || []).filter(function (u) { return u.ssh_access !== 'no'; });
    if (!list.length) {
      rows.appendChild(emptyState(
        'No account can log in over SSH',
        (body.users || []).length
          ? 'Every account has a nologin shell or is denied by sshd policy.'
          : (body.status || 'Account list unavailable.')
      ));
      return;
    }

    list.forEach(function (u) {
      var row = el('div', 'pu-row');
      row.appendChild(el('div', 'pu-port', 'uid ' + u.uid));
      row.appendChild(el('div', 'pu-name', u.username));
      row.appendChild(el('span', 'tag tag-' + u.ssh_access,
        u.ssh_access === 'yes' ? 'ssh' : u.ssh_access));
      var meta = el('div', 'pu-meta');
      meta.textContent = (u.kind === 'root' ? 'root  ' : '') + u.reasons.join('; ');
      row.appendChild(meta);
      rows.appendChild(row);
    });
  }

  // -- activity log -------------------------------------------------------
  function renderFilters(counts) {
    var box = document.getElementById('log-filters');
    clear(box);
    [['all', 'All'], ['ssh', 'SSH'], ['network', 'Network'], ['system', 'System']]
      .forEach(function (pair) {
        var key = pair[0];
        var btn = el('button', 'filter-btn', pair[1]);
        btn.type = 'button';
        btn.setAttribute('aria-pressed', String(logFilter === key));
        var n = counts[key];
        if (n !== undefined) { btn.appendChild(el('span', 'n', n)); }
        btn.addEventListener('click', function () {
          logFilter = key;
          refresh();
        });
        box.appendChild(btn);
      });
  }

  function renderLog(body) {
    var rows = document.getElementById('log-rows');
    clear(rows);
    var list = body.events || [];
    document.getElementById('log-count').textContent = list.length ? list.length + ' entries' : '';
    renderFilters(body.category_counts || {});

    if (!list.length) {
      rows.appendChild(emptyState(
        logSearch ? 'No entries match' : 'Nothing recorded yet',
        logSearch
          ? 'Nothing in the log matches that filter.'
          : 'The log fills as the monitor observes activity.'
      ));
      return;
    }
    list.forEach(function (e) { rows.appendChild(eventRow(e)); });
  }

  var searchBox = document.getElementById('log-search');
  if (searchBox) {
    searchBox.addEventListener('input', function () {
      // Debounced: refetching on every keystroke would hammer the API for a
      // query the user has not finished typing.
      window.clearTimeout(searchTimer);
      searchTimer = window.setTimeout(function () {
        logSearch = searchBox.value.trim();
        refresh();
      }, 250);
    });
  }

  // ------------------------------------------------------------------ poll

  function markUnreachable(error) {
    var box = document.getElementById('freshness');
    box.classList.remove('live', 'stale');
    box.classList.add('down');
    document.getElementById('freshness-text').textContent = 'API unreachable';
    showDiagnostics([[
      'dashboard',
      'Cannot reach the Sentry API (' + error + '). Figures below are the last ' +
      'values received and may be out of date.',
      'error'
    ]]);
  }

  var cycle = 0;
  var SLOW_EVERY = 6;   // ports/users/score refresh roughly every 30s

  function refresh() {
    var slow = (cycle % SLOW_EVERY) === 0;
    cycle++;

    var logQuery = '/api/events?limit=120'
      + (logFilter !== 'all' ? '&category=' + encodeURIComponent(logFilter) : '')
      + (logSearch ? '&search=' + encodeURIComponent(logSearch) : '');

    Promise.all([
      fetch('/api/health').then(function (r) { return r.json(); }),
      fetch('/api/alerts?limit=200').then(function (r) { return r.json(); }),
      fetch('/api/stats').then(function (r) { return r.json(); }),
      fetch('/api/timeline?hours=24').then(function (r) { return r.json(); }),
      fetch('/api/events?limit=60&min_severity=medium').then(function (r) { return r.json(); }),
      fetch(logQuery).then(function (r) { return r.json(); }),
      fetch('/api/host').then(function (r) { return r.json(); }),
      slow ? fetch('/api/score').then(function (r) { return r.json(); }) : Promise.resolve(null),
      slow ? fetch('/api/ports').then(function (r) { return r.json(); }) : Promise.resolve(null),
      slow ? fetch('/api/users').then(function (r) { return r.json(); }) : Promise.resolve(null)
    ]).then(function (results) {
      var health = results[0], alertBody = results[1], stats = results[2], timeline = results[3];
      var feed = results[4], log = results[5], host = results[6];
      var score = results[7], portsBody = results[8], usersBody = results[9];

      renderFeed(feed);
      renderLog(log);
      renderHost(host);
      if (score) { renderScore(score); }
      if (portsBody) { renderPorts(portsBody); }
      if (usersBody) { renderUsers(usersBody); }

      renderHealth(health);
      renderStats(stats);
      renderTimeline(timeline);

      var all = alertBody.alerts || [];
      var ssh = all.filter(function (a) { return a.kind === 'ssh_bruteforce'; });
      var scans = all.filter(function (a) { return a.kind === 'port_scan'; });

      renderPanel('ssh-rows', 'ssh-count', ssh, sshRow, emptyState(
        'No brute-force activity',
        'No source IP has reached the failed-authentication threshold. This is ' +
        'the expected state on a quiet host — check the freshness indicator ' +
        'above to confirm logs are still being read.'
      ));

      renderPanel('scan-rows', 'scan-count', scans, scanRow, emptyState(
        'No scans detected',
        'No source has probed enough distinct blocked ports to trip the rule. ' +
        'Note that UFW only logs what it blocked, so probes of open services ' +
        'do not appear here.'
      ));

      all.forEach(function (a) { seenAlerts[a.id] = a.last_seen; });
      firstPaintDone = true;
    }).catch(function (err) {
      markUnreachable(err && err.message ? err.message : 'network error');
      if (!firstPaintDone) {
        document.getElementById('ssh-rows').appendChild(emptyState(
          'Cannot load alerts', 'The dashboard could not reach the API on this host.'
        ));
      }
    });
  }

  // Loading skeletons, then poll on a fixed cadence.
  document.getElementById('ssh-rows').appendChild(skeleton(4));
  document.getElementById('scan-rows').appendChild(skeleton(3));
  refresh();
  setInterval(refresh, POLL_MS);
}());
