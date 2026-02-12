// =========================================================================
// Theme Switching
// =========================================================================

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  updateThemeButtons();
}

function updateThemeButtons() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var btns = document.querySelectorAll('[data-theme-btn]');
  for (var i = 0; i < btns.length; i++) {
    var btn = btns[i];
    if (btn.getAttribute('data-theme-btn') === current) {
      btn.classList.add('bg-surface-card', 'text-content-accent');
      btn.classList.remove('text-content-muted');
    } else {
      btn.classList.remove('bg-surface-card', 'text-content-accent');
      btn.classList.add('text-content-muted');
    }
  }
}

document.addEventListener('DOMContentLoaded', updateThemeButtons);

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
    (d.headers.redirect_chain || []).forEach(function(hop, i) {
      rows.push(['Redirect', 'hop_' + i, hop.status_code + ' ' + (hop.url || '') + (hop.location ? ' -> ' + hop.location : '')]);
    });
    if (d.headers.final_url) {
      rows.push(['Redirect', 'final_url', d.headers.final_url]);
    }
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
  if (grade === 'A') return 'text-grade-a';
  if (grade === 'B') return 'text-grade-b';
  if (grade === 'C') return 'text-grade-c';
  if (grade === 'D') return 'text-grade-d';
  return 'text-grade-f';
}

function renderSecurityScore(score) {
  var el = document.getElementById('score-content');
  if (!score) { el.innerHTML = '<span class="text-content-muted">N/A</span>'; return; }

  var gc = gradeColor(score.grade);
  var h = '<div class="flex items-center gap-4 mb-4">';
  h += '<div class="text-4xl font-bold ' + gc + '">' + esc(score.grade) + '</div>';
  h += '<div><div class="text-2xl font-semibold text-content-heading">' + score.score + '<span class="text-sm text-content-muted">/100</span></div>';
  h += '<div class="text-xs text-content-muted">Security Score</div></div>';
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
      var barColor = pct >= 80 ? 'bg-bar-good' : pct >= 50 ? 'bg-bar-mid' : 'bg-bar-bad';
      h += '<div class="flex items-center gap-2 text-xs">';
      h += '<span class="text-content-muted w-20">' + esc(c.label) + '</span>';
      h += '<div class="flex-1 bg-bar-track rounded-full h-1.5"><div class="' + barColor + ' h-1.5 rounded-full" style="width:' + pct + '%"></div></div>';
      h += '<span class="text-content-secondary w-10 text-right">' + c.val + '/' + c.max + '</span>';
      h += '</div>';
    });
    h += '</div>';
  }

  // Recommendations
  var recs = score.recommendations || [];
  if (recs.length) {
    h += '<div class="mt-4 space-y-1">';
    h += '<div class="text-xs text-content-muted font-semibold mb-1">Recommendations</div>';
    recs.forEach(function(r) {
      h += '<div class="text-xs text-content-secondary">&bull; ' + esc(r) + '</div>';
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
  parts.push(badge('Target', data.target, 'text-content-accent'));
  parts.push(badge('Duration', ((data.duration_ms || 0) / 1000).toFixed(1) + 's', 'text-content-muted'));
  if (data.security_score) {
    var gc = gradeColor(data.security_score.grade);
    parts.push(badge('Grade', data.security_score.grade + ' (' + data.security_score.score + '/100)', gc));
  }
  if (data.waf && data.waf.detected) parts.push(badge('WAF', data.waf.provider, 'text-status-warning'));
  if (data.dns && data.dns.cdn_detected) parts.push(badge('CDN', data.dns.cdn_detected, 'text-status-success'));
  var protos = (data.tls && data.tls.protocols) ? data.tls.protocols.join(', ') : 'N/A';
  parts.push(badge('TLS', protos, 'text-content-accent'));
  var chain = (data.headers && data.headers.redirect_chain) || [];
  if (chain.length > 1) {
    var hopCount = chain.length - 1;
    parts.push(badge('Redirects', hopCount + ' hop' + (hopCount !== 1 ? 's' : ''), 'text-status-warning'));
  }
  document.getElementById('summary-bar').innerHTML = parts.join('');

  // Security Score
  renderSecurityScore(data.security_score);

  // WAF
  var waf = data.waf || {};
  document.getElementById('waf-content').innerHTML = waf.detected
    ? '<div class="flex items-center gap-2"><span class="w-2 h-2 bg-status-warning-muted rounded-full"></span><span class="text-status-warning font-medium">' + esc(waf.provider) + '</span></div>'
      + (waf.details ? '<pre class="mt-2 text-xs text-content-muted overflow-x-auto">' + esc(JSON.stringify(waf.details, null, 2)) + '</pre>' : '')
    : '<div class="flex items-center gap-2"><span class="w-2 h-2 bg-status-success-muted rounded-full"></span><span class="text-status-success">No WAF detected</span></div>';

  // Technologies
  var techs = data.technologies || [];
  document.getElementById('tech-content').innerHTML = techs.length
    ? techs.map(function(t) {
        var label = esc(t.name);
        if (t.version) label += ' <span class="text-content-muted">' + esc(t.version) + '</span>';
        if (t.category && t.category !== 'Unknown') label += ' <span class="text-content-faint text-xs">(' + esc(t.category) + ')</span>';
        return '<span class="inline-block bg-surface-elevated text-content-secondary text-xs px-2.5 py-1 rounded mr-1.5 mb-1.5">' + label + '</span>';
      }).join('')
    : '<span class="text-content-muted">No technologies detected</span>';

  // TLS
  var tls = data.tls || {};
  var tlsH = '<div class="space-y-2 text-sm">';
  tlsH += '<div><span class="text-content-muted">Protocols:</span> ' + esc((tls.protocols || []).join(', ') || 'N/A') + '</div>';
  var ciphers = (tls.cipher_suites || []).slice(0, 6);
  tlsH += '<div><span class="text-content-muted">Ciphers:</span> ' + esc(ciphers.join(', ') || 'N/A');
  if ((tls.cipher_suites || []).length > 6) tlsH += ' <span class="text-content-faint">+ ' + (tls.cipher_suites.length - 6) + ' more</span>';
  tlsH += '</div>';
  if (tls.certificate) {
    tlsH += '<div><span class="text-content-muted">Issuer:</span> ' + esc(tls.certificate.issuer || 'N/A') + '</div>';
    tlsH += '<div><span class="text-content-muted">Expiry:</span> ' + esc(tls.certificate.expiry || 'N/A') + '</div>';
    if (tls.certificate.san && tls.certificate.san.length) {
      tlsH += '<div><span class="text-content-muted">SANs:</span> ' + esc(tls.certificate.san.join(', ')) + '</div>';
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
  if (dns.cdn_detected) dnsH += '<div><span class="text-content-muted">CDN:</span> <span class="text-status-success">' + esc(dns.cdn_detected) + '</span></div>';
  if (dns.hosting_provider) dnsH += '<div><span class="text-content-muted">Hosting:</span> ' + esc(dns.hosting_provider) + '</div>';
  dnsH += '</div>';
  document.getElementById('dns-content').innerHTML = dnsH;

  // Headers
  var hdrs = data.headers || {};
  var hH = '<div class="space-y-2 text-sm">';
  hH += '<div><span class="text-content-muted">Server:</span> ' + esc(hdrs.server || 'N/A') + '</div>';
  var sec = hdrs.security_headers || {};
  var secKeys = Object.keys(sec);
  if (secKeys.length) {
    hH += '<div class="mt-3 space-y-1.5">';
    secKeys.forEach(function(k) {
      var v = sec[k];
      var present = v && v !== 'missing' && v !== '';
      hH += '<div class="flex items-center gap-2">';
      hH += '<span class="w-1.5 h-1.5 rounded-full flex-shrink-0 ' + (present ? 'bg-status-success-muted' : 'bg-status-danger-muted') + '"></span>';
      hH += '<span class="text-content-secondary font-mono text-xs">' + esc(k) + '</span>';
      hH += present
        ? '<span class="text-status-success text-xs">Present</span>'
        : '<span class="text-status-danger text-xs">Missing</span>';
      hH += '</div>';
    });
    hH += '</div>';
  }
  // Redirect chain
  var chain = hdrs.redirect_chain || [];
  if (chain.length > 1) {
    hH += '<div class="mt-4 pt-3 border-t border-line">';
    hH += '<div class="text-xs text-content-muted font-semibold mb-2">Redirect Chain</div>';
    hH += '<div class="space-y-1">';
    for (var ci = 0; ci < chain.length; ci++) {
      var hop = chain[ci];
      var isLast = ci === chain.length - 1;
      var scColor = 'text-content-muted';
      if (hop.status_code >= 200 && hop.status_code < 300) scColor = 'text-status-success';
      else if (hop.status_code >= 300 && hop.status_code < 400) scColor = 'text-status-warning';
      else if (hop.status_code >= 400) scColor = 'text-status-danger';
      hH += '<div class="flex items-center gap-2 text-xs">';
      hH += '<span class="flex-shrink-0 font-mono ' + scColor + '">' + hop.status_code + '</span>';
      hH += '<span class="text-content-faint">' + (isLast ? '&#x25CF;' : '&rarr;') + '</span>';
      hH += '<span class="font-mono text-content-secondary truncate">' + esc(hop.url || '(unknown)') + '</span>';
      hH += '</div>';
    }
    hH += '</div>';
    if (hdrs.final_url) {
      hH += '<div class="mt-2 text-xs text-content-muted">Final: <span class="text-content-secondary font-mono">' + esc(hdrs.final_url) + '</span></div>';
    }
    hH += '</div>';
  }
  hH += '</div>';
  document.getElementById('headers-content').innerHTML = hH;

  // IP Info
  var ip = data.ip_info || {};
  document.getElementById('ip-content').innerHTML =
    '<div class="space-y-2 text-sm">' +
    '<div><span class="text-content-muted">IP Address:</span> ' + esc(ip.ip || 'N/A') + '</div>' +
    '<div><span class="text-content-muted">ASN:</span> ' + esc(ip.asn || 'N/A') + '</div>' +
    '<div><span class="text-content-muted">Organization:</span> ' + esc(ip.org || 'N/A') + '</div>' +
    '</div>';

  // WHOIS
  var whois = data.whois || {};
  var wH = '<div class="space-y-2 text-sm">';
  if (whois.registrar) wH += '<div><span class="text-content-muted">Registrar:</span> ' + esc(whois.registrar) + '</div>';
  if (whois.registrant_org) wH += '<div><span class="text-content-muted">Organization:</span> ' + esc(whois.registrant_org) + '</div>';
  if (whois.creation_date) wH += '<div><span class="text-content-muted">Created:</span> ' + esc(whois.creation_date) + '</div>';
  if (whois.expiry_date) wH += '<div><span class="text-content-muted">Expires:</span> ' + esc(whois.expiry_date) + '</div>';
  if (whois.updated_date) wH += '<div><span class="text-content-muted">Updated:</span> ' + esc(whois.updated_date) + '</div>';
  if (whois.nameservers && whois.nameservers.length) wH += '<div><span class="text-content-muted">Nameservers:</span> ' + whois.nameservers.map(function(n) { return esc(n); }).join(', ') + '</div>';
  if (whois.status && whois.status.length) wH += '<div><span class="text-content-muted">Status:</span> ' + whois.status.map(function(s) { return '<span class="inline-block bg-surface-elevated text-content-secondary text-xs px-2 py-0.5 rounded mr-1 mb-1">' + esc(s) + '</span>'; }).join('') + '</div>';
  if (wH === '<div class="space-y-2 text-sm">') wH += '<span class="text-content-muted">No WHOIS data available</span>';
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
    sH += '<span class="text-content-muted text-sm">' + subList.length + ' subdomain' + (subList.length !== 1 ? 's' : '') + '</span>';
    if (stats.high_interest) sH += '<button onclick="toggleSubFilter(\'high\')" data-sub-filter="high" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-interest-high-bg text-interest-high border border-interest-high-border hover:opacity-80 transition-colors">' + stats.high_interest + ' High</button>';
    if (stats.medium_interest) sH += '<button onclick="toggleSubFilter(\'medium\')" data-sub-filter="medium" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-interest-medium-bg text-interest-medium border border-interest-medium-border hover:opacity-80 transition-colors">' + stats.medium_interest + ' Medium</button>';
    if (stats.low_interest) sH += '<button onclick="toggleSubFilter(\'low\')" data-sub-filter="low" class="sub-filter-pill active text-xs px-2.5 py-1 rounded-full bg-interest-low-bg text-interest-low border border-interest-low-border hover:opacity-80 transition-colors">' + stats.low_interest + ' Low</button>';
    sH += '</div>';

    // --- Build category sections ordered by interest ---
    var interestOrder = { high: 0, medium: 1, low: 2 };
    var catColorDot = { high: 'bg-status-danger-muted', medium: 'bg-status-warning-muted', low: 'bg-status-neutral' };
    var catTagBg = { high: 'bg-interest-high-bg text-interest-high border border-interest-high-border', medium: 'bg-interest-medium-bg text-interest-medium border border-interest-medium-border', low: 'bg-interest-low-bg text-interest-low' };

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
      var dotClass = catColorDot[cat.interest] || 'bg-status-neutral';
      var tagClass = catTagBg[cat.interest] || 'bg-interest-low-bg text-interest-low';
      var defaultOpen = cat.interest === 'high';

      sH += '<div class="sub-category-section" data-interest="' + esc(cat.interest) + '">';
      // Header
      sH += '<button onclick="toggleSubCategory(this)" class="flex items-center gap-2 w-full text-left group">';
      sH += '<span class="w-2 h-2 rounded-full flex-shrink-0 ' + dotClass + '"></span>';
      sH += '<span class="text-sm font-medium text-content">' + esc(cat.name) + '</span>';
      sH += '<span class="text-xs text-content-muted">(' + cat.items.length + ')</span>';
      sH += '<span class="text-xs text-content-faint ml-1">' + esc(cat.cf_opportunity) + '</span>';
      sH += '<svg class="sub-chevron w-3.5 h-3.5 text-content-faint ml-auto transition-transform ' + (defaultOpen ? 'rotate-90' : '') + '" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>';
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
        sH += '<button onclick="toggleSubGroup(\'' + gId + '\')" class="text-xs text-content-secondary hover:text-content font-mono flex items-center gap-1">';
        sH += '<svg class="sub-grp-chevron w-3 h-3 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>';
        sH += esc(g.prefix) + ' <span class="text-content-faint">(' + g.count + ')</span>';
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
    sH += '<div class="mb-2 text-sm"><span class="text-content-muted">Found:</span> <span class="text-content-accent font-medium">' + subList.length + ' subdomain' + (subList.length !== 1 ? 's' : '') + '</span></div>';
    var shown = subList.slice(0, 20);
    sH += '<div class="flex flex-wrap gap-1.5">';
    shown.forEach(function(sub) {
      sH += '<span class="inline-block bg-surface-elevated text-content-secondary text-xs px-2 py-1 rounded font-mono">' + esc(sub) + '</span>';
    });
    if (subList.length > 20) sH += '<span class="text-content-muted text-xs self-center">+ ' + (subList.length - 20) + ' more</span>';
    sH += '</div>';
  } else {
    sH = '<span class="text-content-muted text-sm">No subdomains found</span>';
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
  return '<div><span class="text-content-muted">' + esc(label) + ':</span> ' + records.map(function(r) { return esc(r); }).join(', ') + '</div>';
}

function badge(label, value, textClass) {
  return '<div class="bg-surface-elevated rounded px-3 py-1.5">'
    + '<span class="text-content-muted text-xs">' + esc(label) + '</span> '
    + '<span class="' + textClass + ' text-sm font-medium">' + esc(value || 'N/A') + '</span>'
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
      el.innerHTML = '<p class="text-content-faint text-sm">No scans found.</p>';
      document.getElementById('history-load-more').classList.add('hidden');
      return;
    }

    var statusStyles = {
      completed: 'bg-status-success/20 text-status-success',
      running: 'bg-status-info/20 text-status-info',
      failed: 'bg-status-danger/20 text-status-danger',
      pending: 'bg-surface-elevated text-content-muted'
    };
    var html = data.scans.map(function(s) {
      var sc = statusStyles[s.status] || statusStyles.pending;
      var dur = s.duration_ms ? ' (' + (s.duration_ms / 1000).toFixed(1) + 's)' : '';
      return '<div class="flex items-center justify-between bg-surface-card border border-line rounded-lg px-4 py-3 text-sm cursor-pointer hover:border-content-muted transition-colors" data-scan-id="' + esc(s.id) + '">'
        + '<span class="text-content-secondary truncate max-w-md">' + esc(s.target) + '</span>'
        + '<div class="flex items-center gap-3 flex-shrink-0">'
        + '<span class="text-content-faint text-xs">' + esc(new Date(s.created_at + 'Z').toLocaleString()) + esc(dur) + '</span>'
        + '<span class="text-xs px-2 py-0.5 rounded-full ' + sc + '">' + esc(s.status) + '</span>'
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
