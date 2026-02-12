// =========================================================================
// Frontend Logic
// =========================================================================

var lastScanData = null;
var historyNextCursor = null;
var historySearchTimeout = null;

function esc(str) {
  var d = document.createElement('div');
  d.textContent = String(str || '');
  return d.innerHTML;
}

// =========================================================================
// Subdomain UI Helpers
// =========================================================================

function toggleSubFilter(level) {
  var btn = document.querySelector('[data-sub-filter="' + level + '"]');
  if (!btn) return;
  btn.classList.toggle('active');
  var isActive = btn.classList.contains('active');
  if (!isActive) {
    btn.style.opacity = '0.35';
  } else {
    btn.style.opacity = '';
  }
  // Show/hide category sections matching this interest level
  var sections = document.querySelectorAll('.sub-category-section[data-interest="' + level + '"]');
  for (var i = 0; i < sections.length; i++) {
    sections[i].style.display = isActive ? '' : 'none';
  }
}

function toggleSubCategory(btn) {
  var body = btn.parentElement.querySelector('.sub-category-body');
  var chevron = btn.querySelector('.sub-chevron');
  if (!body) return;
  body.classList.toggle('hidden');
  if (chevron) chevron.classList.toggle('rotate-90');
}

function toggleSubGroup(id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('hidden');
  var chevron = el.parentElement.querySelector('.sub-grp-chevron');
  if (chevron) chevron.classList.toggle('rotate-90');
}

function exportJSON() {
  if (!lastScanData) return;
  var blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (lastScanData.target || 'scan') + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportCSV() {
  if (!lastScanData) return;
  var d = lastScanData;
  var rows = [['Category', 'Key', 'Value']];
  rows.push(['Target', 'domain', d.target || '']);
  rows.push(['Target', 'scan_timestamp', d.scan_timestamp || '']);
  rows.push(['Target', 'duration_ms', String(d.duration_ms || 0)]);
  if (d.waf) {
    rows.push(['WAF', 'detected', String(d.waf.detected)]);
    rows.push(['WAF', 'provider', d.waf.provider || '']);
  }
  (d.technologies || []).forEach(function(t) {
    rows.push(['Technology', t.name, (t.version || '') + (t.category ? ' (' + t.category + ')' : '')]);
  });
  if (d.tls) {
    rows.push(['TLS', 'protocols', (d.tls.protocols || []).join('; ')]);
    rows.push(['TLS', 'cipher_suites', (d.tls.cipher_suites || []).join('; ')]);
    if (d.tls.certificate) {
      rows.push(['TLS', 'issuer', d.tls.certificate.issuer || '']);
      rows.push(['TLS', 'expiry', d.tls.certificate.expiry || '']);
      rows.push(['TLS', 'san', (d.tls.certificate.san || []).join('; ')]);
    }
  }
  if (d.dns) {
    rows.push(['DNS', 'a_records', (d.dns.a_records || []).join('; ')]);
    rows.push(['DNS', 'cname_records', (d.dns.cname_records || []).join('; ')]);
    rows.push(['DNS', 'ns_records', (d.dns.ns_records || []).join('; ')]);
    rows.push(['DNS', 'mx_records', (d.dns.mx_records || []).join('; ')]);
    rows.push(['DNS', 'cdn_detected', d.dns.cdn_detected || '']);
    rows.push(['DNS', 'hosting_provider', d.dns.hosting_provider || '']);
  }
  if (d.headers) {
    rows.push(['Headers', 'server', d.headers.server || '']);
    Object.keys(d.headers.security_headers || {}).forEach(function(k) {
      rows.push(['Headers', k, d.headers.security_headers[k]]);
    });
  }
  if (d.ip_info) {
    rows.push(['IP', 'ip', d.ip_info.ip || '']);
    rows.push(['IP', 'asn', d.ip_info.asn || '']);
    rows.push(['IP', 'org', d.ip_info.org || '']);
  }
  if (d.security_score) {
    rows.push(['Score', 'grade', d.security_score.grade || '']);
    rows.push(['Score', 'score', String(d.security_score.score || 0)]);
    (d.security_score.recommendations || []).forEach(function(r) {
      rows.push(['Score', 'recommendation', r]);
    });
  }
  // Subdomains — use classified data if available, else flat list
  var csvSubs = d.subdomains || {};
  var csvClassified = csvSubs.classified || [];
  if (csvClassified.length) {
    csvClassified.forEach(function(item) {
      rows.push(['Subdomain', item.subdomain, item.category + ' (' + item.interest + ') — ' + item.cf_opportunity]);
    });
  } else {
    (csvSubs.subdomains || []).forEach(function(sub) {
      rows.push(['Subdomain', sub, '']);
    });
  }
  var csv = rows.map(function(r) {
    return r.map(function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
  }).join('\n');
  var blob = new Blob([csv], { type: 'text/csv' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (d.target || 'scan') + '.csv';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function startScan() {
  var input = document.getElementById('target-input');
  var target = input.value.trim();
  if (!target) return;

  // Show loading, hide others
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('loading').classList.remove('hidden');
  document.getElementById('error').classList.add('hidden');
  document.getElementById('results').classList.add('hidden');

  try {
    var res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target }),
    });
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Scan failed');
    renderResults(data);
    loadHistory();
  } catch (err) {
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('error-msg').textContent = err.message;
  } finally {
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('loading').classList.add('hidden');
  }
}

// =========================================================================
// Security Score
// =========================================================================

function gradeColor(grade) {
  if (grade === 'A') return 'green';
  if (grade === 'B') return 'blue';
  if (grade === 'C') return 'yellow';
  if (grade === 'D') return 'orange';
  return 'red';
}

function renderSecurityScore(score) {
  var el = document.getElementById('score-content');
  if (!score) { el.innerHTML = '<span class="text-gray-500">N/A</span>'; return; }

  var gc = gradeColor(score.grade);
  var h = '<div class="flex items-center gap-4 mb-4">';
  h += '<div class="text-4xl font-bold text-' + gc + '-400">' + esc(score.grade) + '</div>';
  h += '<div><div class="text-2xl font-semibold text-white">' + score.score + '<span class="text-sm text-gray-500">/100</span></div>';
  h += '<div class="text-xs text-gray-500">Security Score</div></div>';
  h += '</div>';

  // Breakdown bars
  if (score.breakdown) {
    var cats = [
      { label: 'TLS', val: score.breakdown.tls, max: 25 },
      { label: 'Headers', val: score.breakdown.headers, max: 30 },
      { label: 'Certificate', val: score.breakdown.certificate, max: 20 },
      { label: 'WAF', val: score.breakdown.waf, max: 15 },
      { label: 'Server', val: score.breakdown.server_exposure, max: 10 },
    ];
    h += '<div class="space-y-2">';
    cats.forEach(function(c) {
      var pct = c.max > 0 ? Math.round((c.val / c.max) * 100) : 0;
      var barColor = pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-red-500';
      h += '<div class="flex items-center gap-2 text-xs">';
      h += '<span class="text-gray-500 w-20">' + esc(c.label) + '</span>';
      h += '<div class="flex-1 bg-gray-800 rounded-full h-1.5"><div class="' + barColor + ' h-1.5 rounded-full" style="width:' + pct + '%"></div></div>';
      h += '<span class="text-gray-400 w-10 text-right">' + c.val + '/' + c.max + '</span>';
      h += '</div>';
    });
    h += '</div>';
  }

  // Recommendations
  var recs = score.recommendations || [];
  if (recs.length) {
    h += '<div class="mt-4 space-y-1">';
    h += '<div class="text-xs text-gray-500 font-semibold mb-1">Recommendations</div>';
    recs.forEach(function(r) {
      h += '<div class="text-xs text-gray-400">&bull; ' + esc(r) + '</div>';
    });
    h += '</div>';
  }

  el.innerHTML = h;
}

// =========================================================================
// Render Results
// =========================================================================

function renderResults(data) {
  lastScanData = data;
  document.getElementById('results').classList.remove('hidden');

  // Summary
  var parts = [];
  parts.push(badge('Target', data.target, 'blue'));
  parts.push(badge('Duration', ((data.duration_ms || 0) / 1000).toFixed(1) + 's', 'gray'));
  if (data.security_score) {
    var gc = gradeColor(data.security_score.grade);
    parts.push(badge('Grade', data.security_score.grade + ' (' + data.security_score.score + '/100)', gc));
  }
  if (data.waf && data.waf.detected) parts.push(badge('WAF', data.waf.provider, 'yellow'));
  if (data.dns && data.dns.cdn_detected) parts.push(badge('CDN', data.dns.cdn_detected, 'green'));
  var protos = (data.tls && data.tls.protocols) ? data.tls.protocols.join(', ') : 'N/A';
  parts.push(badge('TLS', protos, 'purple'));
  document.getElementById('summary-bar').innerHTML = parts.join('');

  // Security Score
  renderSecurityScore(data.security_score);

  // WAF
  var waf = data.waf || {};
  document.getElementById('waf-content').innerHTML = waf.detected
    ? '<div class="flex items-center gap-2"><span class="w-2 h-2 bg-yellow-500 rounded-full"></span><span class="text-yellow-400 font-medium">' + esc(waf.provider) + '</span></div>'
      + (waf.details ? '<pre class="mt-2 text-xs text-gray-500 overflow-x-auto">' + esc(JSON.stringify(waf.details, null, 2)) + '</pre>' : '')
    : '<div class="flex items-center gap-2"><span class="w-2 h-2 bg-green-500 rounded-full"></span><span class="text-green-400">No WAF detected</span></div>';

  // Technologies
  var techs = data.technologies || [];
  document.getElementById('tech-content').innerHTML = techs.length
    ? techs.map(function(t) {
        var label = esc(t.name);
        if (t.version) label += ' <span class="text-gray-500">' + esc(t.version) + '</span>';
        if (t.category && t.category !== 'Unknown') label += ' <span class="text-gray-600 text-xs">(' + esc(t.category) + ')</span>';
        return '<span class="inline-block bg-gray-800 text-gray-300 text-xs px-2.5 py-1 rounded mr-1.5 mb-1.5">' + label + '</span>';
      }).join('')
    : '<span class="text-gray-500">No technologies detected</span>';

  // TLS
  var tls = data.tls || {};
  var tlsH = '<div class="space-y-2 text-sm">';
  tlsH += '<div><span class="text-gray-500">Protocols:</span> ' + esc((tls.protocols || []).join(', ') || 'N/A') + '</div>';
  var ciphers = (tls.cipher_suites || []).slice(0, 6);
  tlsH += '<div><span class="text-gray-500">Ciphers:</span> ' + esc(ciphers.join(', ') || 'N/A');
  if ((tls.cipher_suites || []).length > 6) tlsH += ' <span class="text-gray-600">+ ' + (tls.cipher_suites.length - 6) + ' more</span>';
  tlsH += '</div>';
  if (tls.certificate) {
    tlsH += '<div><span class="text-gray-500">Issuer:</span> ' + esc(tls.certificate.issuer || 'N/A') + '</div>';
    tlsH += '<div><span class="text-gray-500">Expiry:</span> ' + esc(tls.certificate.expiry || 'N/A') + '</div>';
    if (tls.certificate.san && tls.certificate.san.length) {
      tlsH += '<div><span class="text-gray-500">SANs:</span> ' + esc(tls.certificate.san.join(', ')) + '</div>';
    }
  }
  tlsH += '</div>';
  document.getElementById('tls-content').innerHTML = tlsH;

  // DNS
  var dns = data.dns || {};
  var dnsH = '<div class="space-y-2 text-sm">';
  dnsH += dnsRow('A Records', dns.a_records);
  dnsH += dnsRow('CNAME', dns.cname_records);
  dnsH += dnsRow('NS', dns.ns_records);
  dnsH += dnsRow('MX', dns.mx_records);
  if (dns.cdn_detected) dnsH += '<div><span class="text-gray-500">CDN:</span> <span class="text-green-400">' + esc(dns.cdn_detected) + '</span></div>';
  if (dns.hosting_provider) dnsH += '<div><span class="text-gray-500">Hosting:</span> ' + esc(dns.hosting_provider) + '</div>';
  dnsH += '</div>';
  document.getElementById('dns-content').innerHTML = dnsH;

  // Headers
  var hdrs = data.headers || {};
  var hH = '<div class="space-y-2 text-sm">';
  hH += '<div><span class="text-gray-500">Server:</span> ' + esc(hdrs.server || 'N/A') + '</div>';
  var sec = hdrs.security_headers || {};
  var secKeys = Object.keys(sec);
  if (secKeys.length) {
    hH += '<div class="mt-3 space-y-1.5">';
    secKeys.forEach(function(k) {
      var v = sec[k];
      var present = v && v !== 'missing' && v !== '';
      hH += '<div class="flex items-center gap-2">';
      hH += '<span class="w-1.5 h-1.5 rounded-full flex-shrink-0 ' + (present ? 'bg-green-500' : 'bg-red-500') + '"></span>';
      hH += '<span class="text-gray-400 font-mono text-xs">' + esc(k) + '</span>';
      hH += present
        ? '<span class="text-green-400 text-xs">Present</span>'
        : '<span class="text-red-400 text-xs">Missing</span>';
      hH += '</div>';
    });
    hH += '</div>';
  }
  hH += '</div>';
  document.getElementById('headers-content').innerHTML = hH;

  // IP Info
  var ip = data.ip_info || {};
  document.getElementById('ip-content').innerHTML =
    '<div class="space-y-2 text-sm">' +
    '<div><span class="text-gray-500">IP Address:</span> ' + esc(ip.ip || 'N/A') + '</div>' +
    '<div><span class="text-gray-500">ASN:</span> ' + esc(ip.asn || 'N/A') + '</div>' +
    '<div><span class="text-gray-500">Organization:</span> ' + esc(ip.org || 'N/A') + '</div>' +
    '</div>';

  // WHOIS
  var whois = data.whois || {};
  var wH = '<div class="space-y-2 text-sm">';
  if (whois.registrar) wH += '<div><span class="text-gray-500">Registrar:</span> ' + esc(whois.registrar) + '</div>';
  if (whois.registrant_org) wH += '<div><span class="text-gray-500">Organization:</span> ' + esc(whois.registrant_org) + '</div>';
  if (whois.creation_date) wH += '<div><span class="text-gray-500">Created:</span> ' + esc(whois.creation_date) + '</div>';
  if (whois.expiry_date) wH += '<div><span class="text-gray-500">Expires:</span> ' + esc(whois.expiry_date) + '</div>';
  if (whois.updated_date) wH += '<div><span class="text-gray-500">Updated:</span> ' + esc(whois.updated_date) + '</div>';
  if (whois.nameservers && whois.nameservers.length) wH += '<div><span class="text-gray-500">Nameservers:</span> ' + whois.nameservers.map(function(n) { return esc(n); }).join(', ') + '</div>';
  if (whois.status && whois.status.length) wH += '<div><span class="text-gray-500">Status:</span> ' + whois.status.map(function(s) { return '<span class="inline-block bg-gray-800 text-gray-300 text-xs px-2 py-0.5 rounded mr-1 mb-1">' + esc(s) + '</span>'; }).join('') + '</div>';
  if (wH === '<div class="space-y-2 text-sm">') wH += '<span class="text-gray-500">No WHOIS data available</span>';
  wH += '</div>';
  document.getElementById('whois-content').innerHTML = wH;

  // Subdomains
  var subs = data.subdomains || {};
  var subList = subs.subdomains || [];
  var classified = subs.classified || [];
  var sH = '';

  if (classified.length) {
    // --- Interest summary pills (double as filters) ---
    var stats = subs.stats || {};
    sH += '<div class="flex items-center gap-2 mb-3 flex-wrap">';
    sH += '<span class="text-gray-500 text-sm">' + subList.length + ' subdomain' + (subList.length !== 1 ? 's' : '') + '</span>';
    if (stats.high_interest) sH += '<button onclick="toggleSubFilter(\'high\')" data-sub-filter="high" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-red-900/40 text-red-400 border border-red-800 hover:bg-red-900/60 transition-colors">' + stats.high_interest + ' High</button>';
    if (stats.medium_interest) sH += '<button onclick="toggleSubFilter(\'medium\')" data-sub-filter="medium" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-yellow-900/40 text-yellow-400 border border-yellow-800 hover:bg-yellow-900/60 transition-colors">' + stats.medium_interest + ' Medium</button>';
    if (stats.low_interest) sH += '<button onclick="toggleSubFilter(\'low\')" data-sub-filter="low" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700 transition-colors">' + stats.low_interest + ' Low</button>';
    sH += '</div>';

    // --- Build category sections ordered by interest ---
    var interestOrder = { high: 0, medium: 1, low: 2 };
    var catColorDot = { high: 'bg-red-500', medium: 'bg-yellow-500', low: 'bg-gray-500' };
    var catTagBg = { high: 'bg-red-900/30 text-red-300 border border-red-900/50', medium: 'bg-yellow-900/30 text-yellow-300 border border-yellow-900/50', low: 'bg-gray-800 text-gray-300' };

    // Group classified items by category while preserving order
    var catGroups = [];
    var catSeen = {};
    classified.forEach(function(item) {
      if (!catSeen[item.category]) {
        catSeen[item.category] = { name: item.category, interest: item.interest, cf_opportunity: item.cf_opportunity, items: [] };
        catGroups.push(catSeen[item.category]);
      }
      catSeen[item.category].items.push(item);
    });
    catGroups.sort(function(a, b) { return (interestOrder[a.interest] || 9) - (interestOrder[b.interest] || 9); });

    // Build group lookup for prefix clusters
    var groupsByCategory = {};
    (subs.groups || []).forEach(function(g) {
      if (!groupsByCategory[g.category]) groupsByCategory[g.category] = [];
      groupsByCategory[g.category].push(g);
    });

    sH += '<div class="space-y-3">';
    catGroups.forEach(function(cat, catIdx) {
      var dotClass = catColorDot[cat.interest] || 'bg-gray-500';
      var tagClass = catTagBg[cat.interest] || 'bg-gray-800 text-gray-300';
      var defaultOpen = cat.interest === 'high';

      sH += '<div class="sub-category-section" data-interest="' + esc(cat.interest) + '">';
      // Header
      sH += '<button onclick="toggleSubCategory(this)" class="flex items-center gap-2 w-full text-left group">';
      sH += '<span class="w-2 h-2 rounded-full flex-shrink-0 ' + dotClass + '"></span>';
      sH += '<span class="text-sm font-medium text-gray-200">' + esc(cat.name) + '</span>';
      sH += '<span class="text-xs text-gray-500">(' + cat.items.length + ')</span>';
      sH += '<span class="text-xs text-gray-600 ml-1">' + esc(cat.cf_opportunity) + '</span>';
      sH += '<svg class="sub-chevron w-3.5 h-3.5 text-gray-600 ml-auto transition-transform ' + (defaultOpen ? 'rotate-90' : '') + '" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>';
      sH += '</button>';

      // Body
      sH += '<div class="sub-category-body mt-2 flex flex-wrap gap-1.5 pl-4' + (defaultOpen ? '' : ' hidden') + '">';

      // Check for prefix groups in this category
      var groups = groupsByCategory[cat.name] || [];
      var groupedSubs = {};
      groups.forEach(function(g) {
        g.members.forEach(function(m) { groupedSubs[m] = g.prefix; });
      });

      // Render groups first
      groups.forEach(function(g, gIdx) {
        var gId = 'subgrp-' + catIdx + '-' + gIdx;
        sH += '<div class="w-full">';
        sH += '<button onclick="toggleSubGroup(\'' + gId + '\')" class="text-xs text-gray-400 hover:text-gray-200 font-mono flex items-center gap-1">';
        sH += '<svg class="sub-grp-chevron w-3 h-3 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>';
        sH += esc(g.prefix) + ' <span class="text-gray-600">(' + g.count + ')</span>';
        sH += '</button>';
        sH += '<div id="' + gId + '" class="hidden mt-1 flex flex-wrap gap-1.5 pl-4">';
        g.members.forEach(function(m) {
          sH += '<span class="inline-block ' + tagClass + ' text-xs px-2 py-1 rounded font-mono">' + esc(m) + '</span>';
        });
        sH += '</div></div>';
      });

      // Render ungrouped subdomains
      cat.items.forEach(function(item) {
        if (!groupedSubs[item.subdomain]) {
          sH += '<span class="inline-block ' + tagClass + ' text-xs px-2 py-1 rounded font-mono">' + esc(item.subdomain) + '</span>';
        }
      });

      sH += '</div></div>';
    });
    sH += '</div>';

  } else if (subList.length) {
    // Fallback: old scan data without classification
    sH += '<div class="mb-2 text-sm"><span class="text-gray-500">Found:</span> <span class="text-blue-400 font-medium">' + subList.length + ' subdomain' + (subList.length !== 1 ? 's' : '') + '</span></div>';
    var shown = subList.slice(0, 20);
    sH += '<div class="flex flex-wrap gap-1.5">';
    shown.forEach(function(sub) {
      sH += '<span class="inline-block bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded font-mono">' + esc(sub) + '</span>';
    });
    if (subList.length > 20) sH += '<span class="text-gray-500 text-xs self-center">+ ' + (subList.length - 20) + ' more</span>';
    sH += '</div>';
  } else {
    sH = '<span class="text-gray-500 text-sm">No subdomains found</span>';
  }
  document.getElementById('subdomains-content').innerHTML = sH;

  // Errors
  var errors = data.errors || [];
  var errPanel = document.getElementById('scan-errors');
  if (errors.length > 0) {
    errPanel.classList.remove('hidden');
    document.getElementById('scan-errors-list').innerHTML = errors.map(function(e) {
      return '<li>' + esc(e) + '</li>';
    }).join('');
  } else {
    errPanel.classList.add('hidden');
  }
}

function dnsRow(label, records) {
  if (!records || !records.length) return '';
  return '<div><span class="text-gray-500">' + esc(label) + ':</span> ' + records.map(function(r) { return esc(r); }).join(', ') + '</div>';
}

function badge(label, value, color) {
  return '<div class="bg-gray-800 rounded px-3 py-1.5">'
    + '<span class="text-gray-500 text-xs">' + esc(label) + '</span> '
    + '<span class="text-' + color + '-400 text-sm font-medium">' + esc(value || 'N/A') + '</span>'
    + '</div>';
}

// =========================================================================
// History with search, filter, and pagination
// =========================================================================

function onHistorySearch() {
  clearTimeout(historySearchTimeout);
  historySearchTimeout = setTimeout(function() { loadHistory(); }, 300);
}

function onHistoryFilter() {
  loadHistory();
}

async function loadHistory(cursor) {
  try {
    var searchEl = document.getElementById('history-search');
    var filterEl = document.getElementById('history-filter');
    var q = searchEl ? searchEl.value.trim() : '';
    var status = filterEl ? filterEl.value : '';

    var params = new URLSearchParams();
    if (q) params.set('q', q);
    if (status) params.set('status', status);
    if (cursor) params.set('cursor', cursor);

    var res = await fetch('/api/history?' + params.toString());
    var data = await res.json();
    var el = document.getElementById('history-list');

    historyNextCursor = data.next_cursor || null;

    if (!data.scans || !data.scans.length) {
      el.innerHTML = '<p class="text-gray-600 text-sm">No scans found.</p>';
      document.getElementById('history-load-more').classList.add('hidden');
      return;
    }

    var html = data.scans.map(function(s) {
      var statusColors = { completed: 'green', running: 'blue', failed: 'red', pending: 'gray' };
      var c = statusColors[s.status] || 'gray';
      var dur = s.duration_ms ? ' (' + (s.duration_ms / 1000).toFixed(1) + 's)' : '';
      return '<div class="flex items-center justify-between bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-sm cursor-pointer hover:border-gray-600 transition-colors" data-scan-id="' + esc(s.id) + '">'
        + '<span class="text-gray-300 truncate max-w-md">' + esc(s.target) + '</span>'
        + '<div class="flex items-center gap-3 flex-shrink-0">'
        + '<span class="text-gray-600 text-xs">' + esc(new Date(s.created_at + 'Z').toLocaleString()) + esc(dur) + '</span>'
        + '<span class="text-xs px-2 py-0.5 rounded-full bg-' + c + '-900 text-' + c + '-400">' + esc(s.status) + '</span>'
        + '</div></div>';
    }).join('');

    if (cursor) {
      el.innerHTML += html;
    } else {
      el.innerHTML = html;
    }

    var loadMoreBtn = document.getElementById('history-load-more');
    if (historyNextCursor) {
      loadMoreBtn.classList.remove('hidden');
    } else {
      loadMoreBtn.classList.add('hidden');
    }
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

function loadMoreHistory() {
  if (historyNextCursor) loadHistory(historyNextCursor);
}

async function loadScan(id) {
  try {
    var res = await fetch('/api/scan/' + encodeURIComponent(id));
    var data = await res.json();
    if (data.results) {
      document.getElementById('target-input').value = data.target;
      var results = typeof data.results === 'string' ? JSON.parse(data.results) : data.results;
      renderResults(results);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  } catch (err) {
    console.error('Failed to load scan:', err);
  }
}

// Event delegation for history scan clicks
document.getElementById('history-list').addEventListener('click', function(e) {
  var el = e.target.closest('[data-scan-id]');
  if (el) loadScan(el.dataset.scanId);
});

// Load history on page load
loadHistory();
