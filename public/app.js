// HeatMap 360 dashboard. Plain DOM, no framework, no inline scripts (CSP: script-src 'self').
'use strict';
const $ = s => document.querySelector(s);
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter(k => k != null)); return e; };
const level = n => (n >= 60 ? 'hot' : n >= 30 ? 'warm' : n > 0 ? 'mild' : 'cool');
const cell = n => el('td', { className: `heat ${level(n)}`, textContent: String(n), title: `${n} of 100` });
const when = iso => (iso ? new Date(iso).toLocaleString() : 'never');

async function load() {
  const r = await fetch('api/machines');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function renderFeeds(f) {
  $('#feeds').textContent = f.kevCount
    ? `CISA KEV catalog ${f.kevVersion ?? ''}: ${f.kevCount} vulnerabilities exploited in the wild, fetched ${when(f.fetchedAt)}.${f.lastError ? ` Last refresh failed: ${f.lastError}` : ''}`
    : `CISA KEV catalog not loaded yet.${f.lastError ? ` ${f.lastError}` : ''}`;
}

function renderMap(data) {
  const body = $('#map tbody');
  body.replaceChildren(...data.machines.map(m => {
    const row = el('tr', { tabIndex: 0, className: m.heat.stale ? 'stale' : '' },
      el('th', { scope: 'row', textContent: m.host }),
      el('td', { textContent: m.os ? `${m.os.name ?? ''} ${m.os.build ?? ''}`.trim() : '' }),
      cell(m.heat.health), cell(m.heat.patching), cell(m.heat.exposure), cell(m.heat.overall),
      el('td', { textContent: when(m.collectedAt) }));
    const open = () => renderDetail(m);
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
    return row;
  }));
  $('#empty').hidden = data.machines.length > 0;
  $('#rejected').replaceChildren(...(data.rejected || []).map(x => el('p', { className: 'warn', textContent: `Ignored ${x.file}: ${x.error}` })));
}

function renderDetail(m) {
  const d = $('#detail');
  const checks = el('table', {}, el('thead', {}, el('tr', {}, el('th', { textContent: 'Check' }), el('th', { textContent: 'Status' }), el('th', { textContent: 'Detail' }))),
    el('tbody', {}, ...m.checks.map(c => el('tr', {}, el('td', { textContent: c.label }), el('td', { className: `status ${c.status}`, textContent: c.status }), el('td', { textContent: c.detail })))));
  const vulns = m.candidates.length
    ? el('table', {}, el('thead', {}, el('tr', {}, ...['CVE', 'Product', 'Why it may apply', 'Ransomware', 'EPSS', 'CISA due'].map(t => el('th', { textContent: t })))),
      el('tbody', {}, ...m.candidates.map(c => el('tr', {},
        el('td', {}, el('a', { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cveID)}`, target: '_blank', rel: 'noopener noreferrer', textContent: c.cveID })),
        el('td', { textContent: c.kind === 'software' ? `${c.software}${c.version ? ` ${c.version}` : ''}` : `${c.vendor} ${c.product}` }),
        el('td', { textContent: c.reason }),
        el('td', { textContent: c.ransomware ? 'Known' : '' }),
        el('td', { textContent: c.epss == null ? '' : `${(c.epss * 100).toFixed(1)}%` }),
        el('td', { textContent: c.dueDate ?? '' })))))
    : el('p', { className: 'muted', textContent: 'No KEV candidates for this machine.' });
  d.replaceChildren(el('h2', { textContent: m.host }),
    el('h3', { textContent: 'Health checks' }), checks,
    el('h3', { textContent: `Known exploited vulnerabilities that may apply (${m.candidates.length})` }),
    el('p', { className: 'muted', textContent: 'Candidates, not confirmed findings: CISA KEV lists products, not version ranges. Verify the installed version against the CVE.' }), vulns,
    ...(m.errors.length ? [el('h3', { textContent: 'Collector errors' }), el('ul', {}, ...m.errors.map(e => el('li', { textContent: e })))] : []));
  d.hidden = false;
  d.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

load().then(data => { renderFeeds(data.feeds); renderMap(data); })
  .catch(err => { $('#feeds').textContent = `Could not load machines: ${err.message}`; });
