/* Port Tools v2 - front end. No dependencies. */
(() => {
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};

const HISTORY_KEY = 'portools.history.v2';
const CONCURRENCY = 4;
const RISK_RANK = { high: 3, medium: 2, low: 1, none: 0 };

let policy = null;            // answer of GET scan.php
let demoMode = false;
let token = '';
let run = null;               // active scan: {ips, ports, hosts:Map, done, abort, cancelled, demo}
let view = null;              // what is displayed: same shape as run
let filter = 'all';
let history = store.get(HISTORY_KEY, []);

/* ------------------------------------------------------------ theme + tabs */

const themeBtn = $('#theme');
const savedTheme = store.get('portools.theme', null);
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
themeBtn.onclick = () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  store.set('portools.theme', next);
};

function showPanel(id) {
  $$('.tab').forEach(t => t.setAttribute('aria-selected', String(t.dataset.panel === id)));
  $$('.panel').forEach(p => p.classList.toggle('hidden', p.id !== id));
  if (id === 'history') renderHistory();
}
$$('.tab').forEach(t => t.onclick = () => showPanel(t.dataset.panel));
$('.tabs').addEventListener('keydown', e => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const tabs = $$('.tab'), i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  n.focus(); n.click();
});

/* ------------------------------------------------------------ parsing */

const ipToInt = s => {
  const p = s.split('.');
  if (p.length !== 4 || p.some(x => !/^\d{1,3}$/.test(x) || +x > 255)) return null;
  return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3];
};
const intToIp = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

function expandTarget(spec, limit) {
  let m;
  if (ipToInt(spec) !== null) return [ipToInt(spec)];
  if ((m = spec.match(/^([\d.]+)\/(\d{1,2})$/)) && ipToInt(m[1]) !== null && +m[2] <= 32) {
    const bits = +m[2], size = 2 ** (32 - bits);
    if (size > limit) throw Error(`${spec} has ${size} addresses; the limit is ${limit}.`);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const start = (ipToInt(m[1]) & mask) >>> 0;
    const from = bits <= 30 ? 1 : 0, to = bits <= 30 ? size - 2 : size - 1;
    return Array.from({ length: to - from + 1 }, (_, i) => start + from + i);
  }
  if ((m = spec.match(/^([\d.]+)-([\d.]+)$/)) && ipToInt(m[1]) !== null) {
    const first = ipToInt(m[1]);
    const last = ipToInt(m[2]) !== null ? ipToInt(m[2]) : (/^\d{1,3}$/.test(m[2]) && +m[2] <= 255 ? ((first & 0xFFFFFF00) >>> 0) + +m[2] : null);
    if (last === null) throw Error(`Invalid range: ${spec}`);
    if (last < first) throw Error(`${spec} ends before it starts.`);
    if (last - first + 1 > limit) throw Error(`${spec} has more than ${limit} addresses.`);
    return Array.from({ length: last - first + 1 }, (_, i) => first + i);
  }
  throw Error(`Not an IPv4 address, range or subnet: ${spec}`);
}

function parseTargets(text) {
  const limit = policy?.limits?.totalTargets ?? 256;
  const set = new Set();
  for (const spec of text.split(/[\s,;]+/).filter(Boolean)) {
    for (const n of expandTarget(spec, limit)) set.add(n);
    if (set.size > limit) throw Error(`More than ${limit} addresses. Split the scan into smaller parts.`);
  }
  return [...set].sort((a, b) => a - b).map(intToIp);
}

function parseCustomPorts(text) {
  const out = new Set();
  for (const item of text.split(/[\s,;]+/).filter(Boolean)) {
    const m = item.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m) throw Error(`Not a port or range: ${item}`);
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535 || b < a) throw Error(`Port out of range: ${item}`);
    if (b - a > 255) throw Error(`Range ${item} is too large.`);
    for (let p = a; p <= b; p++) out.add(p);
  }
  return [...out];
}

const checkedPorts = () => $$('input[name=port]:checked').map(x => +x.value);
function selectedPorts() {
  const s = new Set(checkedPorts());
  parseCustomPorts($('#custom').value).forEach(p => s.add(p));
  return [...s].sort((a, b) => a - b);
}

function setError(msg = '') {
  const e = $('#error');
  e.textContent = msg;
  e.classList.toggle('hidden', !msg);
}

/* ------------------------------------------------------------ setup form */

function updateInfo() {
  const maxPorts = policy?.limits?.ports ?? 64;
  let t = '', p = '', ok = true;
  try {
    const ips = parseTargets($('#targets').value);
    t = ips.length ? `${ips.length} host${ips.length === 1 ? '' : 's'} to scan.` : 'Addresses, ranges (10.0.0.1-20) and subnets (10.0.0.0/28) are accepted.';
    $('#targetInfo').classList.remove('bad');
  } catch (e) { t = e.message; ok = false; }
  $('#targetInfo').textContent = t;
  $('#targetInfo').style.color = ok ? '' : 'var(--high)';
  let n = 0;
  try { n = selectedPorts().length; p = `${n} port${n === 1 ? '' : 's'} selected`; if (n > maxPorts) { p += ` (limit ${maxPorts})`; ok = false; } }
  catch (e) { p = e.message; ok = false; }
  $('#portInfo').textContent = p;
  $('#portInfo').style.color = ok || n <= maxPorts ? '' : 'var(--high)';
  $$('#presets .chip').forEach(c => {
    const ports = policy.presets[c.dataset.id].ports, on = new Set(checkedPorts());
    c.setAttribute('aria-pressed', String(ports.every(x => on.has(x))));
  });
  syncRunButton();
}

function syncRunButton() {
  $('#scan').disabled = !($('#consent').checked && (policy || demoMode)) || !!run;
}

function buildCatalogue() {
  const presets = $('#presets');
  presets.innerHTML = '';
  for (const [id, p] of Object.entries(policy.presets)) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'chip'; b.dataset.id = id; b.textContent = p.label;
    b.setAttribute('aria-pressed', 'false');
    b.onclick = () => {
      const on = b.getAttribute('aria-pressed') !== 'true';
      p.ports.forEach(port => { const i = $(`#p${port}`); if (i) i.checked = on; });
      updateInfo();
    };
    presets.append(b);
  }
  const list = $('#ports');
  list.innerHTML = '';
  for (const [port, name] of Object.entries(policy.services)) {
    const risk = policy.risk?.[port] || '';
    const d = document.createElement('div');
    d.className = 'pt';
    d.innerHTML = `<input type="checkbox" name="port" id="p${port}" value="${port}"><label for="p${port}"><b>${port}</b><span>${esc(name)}</span>${risk ? `<i class="${risk}" title="Risky when exposed"></i>` : ''}</label>`;
    d.firstChild.onchange = updateInfo;
    list.append(d);
  }
}

$('#targets').addEventListener('input', updateInfo);
$('#custom').addEventListener('input', updateInfo);
$('#consent').addEventListener('change', syncRunButton);
$('#clear').onclick = () => { $$('input[name=port]').forEach(x => x.checked = false); $('#custom').value = ''; updateInfo(); };
$('#all').onclick = () => { $$('input[name=port]').forEach(x => x.checked = true); updateInfo(); };

/* ------------------------------------------------------------ backend */

async function init() {
  try {
    const r = await fetch('scan.php', { cache: 'no-store' });
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('json')) throw Error('not json');
    const j = await r.json();
    if (r.status === 401) { policy = { ...j, presets: {}, services: {}, limits: {} }; }
    if (!r.ok && r.status !== 401) throw Error(j.error || 'unavailable');
    if (j.ok) policy = j;
    if (j.tokenRequired) token = sessionStorage.getItem('portools.token') || '';
  } catch {
    policy = null;
  }
  if (!policy) {
    // No PHP behind this page (for example GitHub Pages): keep the UI usable with sample data.
    demoMode = true;
    policy = demoPolicy();
    const b = $('#banner');
    b.innerHTML = '<strong>The scanner service is not running here.</strong> Remote scans need PHP (<code>php -S localhost:8000</code> in this folder). Demo mode shows simulated results so you can try the interface.';
    b.classList.remove('hidden');
  }
  buildCatalogue();
  const q = new URLSearchParams(location.search);
  if (q.has('demo')) { demoMode = true; }
  presetDefaults();
  updateInfo();
  updateHistoryCount();
}

function presetDefaults() {
  const def = policy.presets.common?.ports || [22, 80, 443];
  def.forEach(p => { const i = $(`#p${p}`); if (i) i.checked = true; });
}

function demoPolicy() {
  return {
    ok: true, version: '2.0.0-demo',
    services: {22:'SSH',23:'Telnet',53:'DNS (TCP)',80:'HTTP',135:'MS RPC',139:'NetBIOS',443:'HTTPS',445:'SMB',1433:'Microsoft SQL Server',3000:'Dev server',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP Alternate',9200:'Elasticsearch'},
    presets: {
      common: { label: 'Common', ports: [22, 53, 80, 443, 445, 3389] },
      web: { label: 'Web', ports: [80, 443, 3000, 8080] },
      remote: { label: 'Remote access', ports: [22, 23, 3389, 5900] },
      windows: { label: 'Windows', ports: [135, 139, 445, 3389] },
      database: { label: 'Databases', ports: [1433, 3306, 5432, 6379] },
    },
    risk: { 23:'high', 135:'medium', 139:'medium', 445:'high', 1433:'medium', 3306:'medium', 3389:'high', 5432:'medium', 5900:'high', 6379:'high', 9200:'high' },
    limits: { totalTargets: 256, ports: 64 },
  };
}

const DEMO_NOTES = { 23:'Telnet sends everything in clear text.', 135:'Windows RPC should not be reachable from untrusted networks.', 139:'Legacy NetBIOS file sharing.', 445:'SMB exposed; frequent target of ransomware and worms.', 1433:'Database port reachable over the network.', 3306:'Database port reachable over the network.', 3389:'RDP exposed; common brute-force and ransomware entry point.', 5432:'Database port reachable over the network.', 5900:'VNC is often unauthenticated or weakly protected.', 6379:'Redis is usually unauthenticated by default.', 9200:'Elasticsearch is often exposed without authentication.' };

function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }

async function demoHost(ip, ports, signal) {
  await new Promise((res, rej) => {
    const t = setTimeout(res, 160 + (hash(ip) % 340));
    signal.addEventListener('abort', () => { clearTimeout(t); rej(new DOMException('aborted', 'AbortError')); });
  });
  const live = hash(ip + 'up') % 10 < 7;
  return ports.map(port => {
    const open = live && (hash(`${ip}:${port}`) % 100) < (port === 443 || port === 22 ? 55 : port === 80 ? 45 : 22);
    const level = open ? (policy.risk[port] || 'low') : 'none';
    return { port, service: policy.services[port] || 'Unknown', status: open ? 'open' : 'no_connection', ms: Math.round((1 + (hash(ip + port) % 90) / 3) * 10) / 10, risk: level, note: open ? (DEMO_NOTES[port] || '') : '' };
  });
}

async function scanHost(ip, ports, signal, demo) {
  if (demo) return demoHost(ip, ports, signal);
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['X-Access-Token'] = token;
  const r = await fetch('scan.php', { method: 'POST', headers, signal, body: JSON.stringify({ targets: [ip], ports }) });
  let j;
  try { j = await r.json(); } catch { throw Error('The scanner returned an unreadable answer.'); }
  if (r.status === 401) throw Error('The scanner needs an access token.');
  if (!r.ok || !j.ok) throw Error(j.error || 'Scan failed.');
  return j.results[0].ports;
}

/* ------------------------------------------------------------ run */

$('#form').addEventListener('submit', async e => {
  e.preventDefault();
  setError();
  let ips, ports;
  try { ips = parseTargets($('#targets').value); ports = selectedPorts(); }
  catch (err) { return setError(err.message); }
  if (!ips.length) return setError('Enter at least one IPv4 address.');
  if (!ports.length) return setError('Select at least one port.');
  if (ports.length > (policy.limits?.ports ?? 64)) return setError(`Select at most ${policy.limits.ports} ports.`);
  if (policy.tokenRequired && !token) {
    token = prompt('This scanner needs an access token:') || '';
    if (!token) return setError('An access token is required.');
    sessionStorage.setItem('portools.token', token);
  }
  await startScan(ips, ports, $('#targets').value.trim());
});

$('#cancel').onclick = () => { if (run) { run.cancelled = true; run.abort.abort(); } };

$('#demo').onclick = () => { demoMode = true; policy = policy || demoPolicy(); $('#consent').checked = true; $('#form').requestSubmit(); };

async function startScan(ips, ports, targetsText) {
  run = { ips, ports, targetsText, hosts: new Map(), done: 0, abort: new AbortController(), cancelled: false, demo: demoMode, started: Date.now(), ts: new Date().toISOString() };
  view = run;
  filter = 'all';
  $$('.seg button').forEach(b => b.classList.toggle('on', b.dataset.filter === 'all'));
  $('#diff').classList.add('hidden');
  $('#empty').classList.add('hidden');
  $('#results').classList.remove('hidden');
  $('#progress').classList.remove('hidden');
  $('#cancel').hidden = false;
  $('#scan').disabled = true;
  buildMatrix();
  renderStats(); renderFindings(); progress();
  if (matchMedia('(max-width:900px)').matches) $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });

  const queue = [...ips];
  let failure = null;
  const worker = async () => {
    while (queue.length && !run.cancelled && !failure) {
      const ip = queue.shift();
      try {
        const rows = await scanHost(ip, ports, run.abort.signal, run.demo);
        run.hosts.set(ip, rows);
        updateHost(ip);
      } catch (err) {
        if (err.name === 'AbortError') return;
        failure = err;
        run.abort.abort();
        return;
      }
      run.done++;
      progress();
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ips.length) }, worker));

  const finished = run;
  run = null;
  $('#cancel').hidden = true;
  $('#progress').classList.add('hidden');
  syncRunButton();
  if (failure) setError(failure.message);
  if (finished.hosts.size) {
    finished.durationMs = Date.now() - finished.started;
    finished.partial = finished.cancelled || !!failure || finished.hosts.size < ips.length;
    finished.prev = findPrevious(finished);
    saveHistory(finished);
    view = finished;
    renderStats(); renderFindings(); renderDiff(finished); renderMeta();
  } else { view = finished; }
}

function progress() {
  if (!run) return;
  const pct = Math.round(run.done / run.ips.length * 100);
  $('#barFill').style.width = pct + '%';
  $('#progressText').textContent = `${run.done} of ${run.ips.length} hosts checked`;
}

/* ------------------------------------------------------------ render */

const openRows = v => { const a = []; for (const [ip, rows] of v.hosts) for (const r of rows) if (r.status === 'open') a.push({ ip, ...r }); return a; };

function buildMatrix() {
  const v = view;
  const t = $('#matrix');
  const head = `<thead><tr><th class="host" scope="col">Host</th>${v.ports.map(p => `<th scope="col" title="${esc(policy?.services?.[p] || 'Port ' + p)}">${p}</th>`).join('')}</tr></thead>`;
  const body = v.ips.map(ip => `<tr data-ip="${ip}"><th class="host" scope="row">${ip}</th>${v.ports.map(p => `<td><button type="button" class="cell wait" data-p="${p}" tabindex="-1" aria-label="${ip} port ${p}: waiting">·</button></td>`).join('')}</tr>`).join('');
  t.innerHTML = head + `<tbody>${body}</tbody>`;
  v.ips.forEach(ip => v.hosts.has(ip) && paintHost(ip, false));
  applyFilter();
}

function paintHost(ip, animate = true) {
  const rows = view.hosts.get(ip); if (!rows) return;
  const tr = $(`#matrix tr[data-ip="${CSS.escape(ip)}"]`); if (!tr) return;
  const by = new Map(rows.map(r => [r.port, r]));
  $$('.cell', tr).forEach(c => {
    const r = by.get(+c.dataset.p); if (!r) return;
    const open = r.status === 'open';
    const lvl = open ? (r.risk === 'high' ? 'high' : r.risk === 'medium' ? 'medium' : 'open') : 'closed';
    c.className = `cell ${lvl}${animate ? ' fresh' : ''}`;
    c.textContent = open ? (r.risk === 'high' ? '!' : r.risk === 'medium' ? '?' : '●') : '–';
    c.title = `${ip}:${r.port} ${r.service} — ${open ? 'open' : 'no connection'} (${r.ms} ms)${r.note ? '. ' + r.note : ''}`;
    c.setAttribute('aria-label', `${ip} port ${r.port} ${r.service}: ${open ? 'open' : 'no connection'}${r.risk === 'high' ? ', exposed risk' : r.risk === 'medium' ? ', worth a look' : ''}`);
  });
  tr.dataset.open = rows.some(r => r.status === 'open') ? '1' : '0';
  tr.dataset.risky = rows.some(r => r.status === 'open' && RISK_RANK[r.risk] >= 2) ? '1' : '0';
}

function updateHost(ip) { paintHost(ip); applyFilter(); renderStats(); renderFindings(); }

function applyFilter() {
  $$('#matrix tbody tr').forEach(tr => {
    const done = view.hosts.has(tr.dataset.ip);
    const show = filter === 'all' || !done || (filter === 'open' ? tr.dataset.open === '1' : tr.dataset.risky === '1');
    tr.classList.toggle('hidden', !show);
  });
}

function summary(v) {
  let open = 0, flagged = 0, checks = 0;
  for (const rows of v.hosts.values()) for (const r of rows) { checks++; if (r.status === 'open') { open++; if (RISK_RANK[r.risk] >= 2) flagged++; } }
  return { hosts: v.hosts.size, total: v.ips.length, checks, open, closed: checks - open, flagged };
}

function renderStats() {
  const s = summary(view);
  $('#stats').innerHTML = [
    ['', `${s.hosts}${s.hosts < s.total ? ' / ' + s.total : ''}`, 'Hosts checked'],
    ['', s.checks, 'Checks'],
    ['sig', s.open, 'Open'],
    ['', s.closed, 'No connection'],
    ['warn', s.flagged, 'Need attention'],
  ].map(([c, n, l]) => `<div class="stat ${c}"><b>${n}</b><span>${l}</span></div>`).join('');
}

function renderFindings() {
  let rows = openRows(view);
  if (filter === 'risky') rows = rows.filter(r => RISK_RANK[r.risk] >= 2);
  rows.sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || a.ip.localeCompare(b.ip, undefined, { numeric: true }) || a.port - b.port);
  const box = $('#findings');
  if (!rows.length) {
    box.innerHTML = `<p class="none">${view.hosts.size ? (filter === 'risky' ? 'No open port needs attention.' : 'No open ports found on the hosts checked so far.') : 'Waiting for the first host to answer…'}</p>`;
    return;
  }
  box.innerHTML = rows.map(r => {
    const cls = r.risk === 'high' ? 'high' : r.risk === 'medium' ? 'medium' : 'open';
    const tag = cls === 'high' ? '<span class="tg high">Exposed risk</span>' : cls === 'medium' ? '<span class="tg medium">Worth a look</span>' : '';
    return `<div class="f ${cls}"><span class="ip">${esc(r.ip)}</span><span class="pn">${r.port}</span><span class="sv">${esc(r.service)}${tag}${r.note ? `<small>${esc(r.note)}</small>` : ''}</span><span class="ms">${Number(r.ms).toFixed(1)} ms</span></div>`;
  }).join('');
}

function renderMeta() {
  const v = view;
  const when = new Date(v.ts).toLocaleString();
  const dur = v.durationMs ? ` · ${(v.durationMs / 1000).toFixed(1)} s` : '';
  $('#resultMeta').textContent = `${when}${dur} · TCP${v.demo ? ' · simulated demo data' : ''}${v.partial ? ' · scan stopped before every host was checked' : ''}`;
}

$$('.seg button').forEach(b => b.onclick = () => {
  filter = b.dataset.filter;
  $$('.seg button').forEach(x => x.classList.toggle('on', x === b));
  applyFilter(); renderFindings();
});

/* ------------------------------------------------------------ history + diff */

const sig = v => v.ips.join(',') + '|' + v.ports.join(',');
const compact = v => ({ id: v.ts, ts: v.ts, ips: v.ips, ports: v.ports, targetsText: v.targetsText, demo: !!v.demo, partial: !!v.partial, durationMs: v.durationMs || 0, open: openRows(v).map(r => ({ ip: r.ip, port: r.port, service: r.service, ms: r.ms, risk: r.risk, note: r.note })), checked: [...v.hosts.keys()] });

function expand(h) {
  const hosts = new Map();
  for (const ip of h.checked) hosts.set(ip, h.ports.map(p => ({ port: p, service: policy?.services?.[p] || 'Unknown', status: 'no_connection', ms: 0, risk: 'none', note: '' })));
  for (const o of h.open) { const rows = hosts.get(o.ip); if (!rows) continue; const i = rows.findIndex(r => r.port === o.port); if (i >= 0) rows[i] = { ...o, status: 'open' }; }
  return { ...h, hosts };
}

function findPrevious(cur) { return history.map(expand).find(h => sig(h) === sig(cur) && h.ts !== cur.ts && !h.demo === !cur.demo) || null; }

function saveHistory(v) {
  history = [compact(v), ...history].slice(0, 12);
  store.set(HISTORY_KEY, history);
  updateHistoryCount();
}
function updateHistoryCount() { $('#histCount').textContent = history.length; }

function renderDiff(v) {
  const box = $('#diff');
  if (!v.prev) { box.classList.add('hidden'); return; }
  const key = r => `${r.ip}:${r.port}`;
  const before = new Set(openRows(v.prev).map(key)), now = new Set(openRows(v).map(key));
  const added = [...now].filter(k => !before.has(k)), gone = [...before].filter(k => !now.has(k));
  box.classList.remove('hidden');
  const when = new Date(v.prev.ts).toLocaleString();
  box.innerHTML = !added.length && !gone.length
    ? `Same open ports as the scan of ${esc(when)}.`
    : `Compared with ${esc(when)}: ${added.length ? `<b class="new">${added.length} newly open</b> (${esc(added.slice(0, 6).join(', '))}${added.length > 6 ? '…' : ''})` : ''}${added.length && gone.length ? ' and ' : ''}${gone.length ? `<b class="gone">${gone.length} no longer open</b> (${esc(gone.slice(0, 6).join(', '))}${gone.length > 6 ? '…' : ''})` : ''}.`;
}

function renderHistory() {
  const ul = $('#histList');
  if (!history.length) { ul.innerHTML = '<li class="none">No scans yet. Run one and it will be listed here.</li>'; return; }
  ul.innerHTML = history.map((h, i) => {
    const hosts = h.ips.length === 1 ? h.ips[0] : `${h.ips[0]} and ${h.ips.length - 1} more`;
    return `<li class="hi"><div><strong>${esc(hosts)}</strong><small>${esc(new Date(h.ts).toLocaleString())} · ${h.ports.length} ports · ${h.open.length} open${h.demo ? ' · demo' : ''}${h.partial ? ' · partial' : ''}</small></div><div class="row gap"><button class="btn sm" data-open="${i}" type="button">Open</button><button class="btn sm" data-again="${i}" type="button">Scan again</button></div></li>`;
  }).join('');
}

$('#histList').addEventListener('click', e => {
  const o = e.target.closest('[data-open]'), a = e.target.closest('[data-again]');
  if (o) {
    const h = expand(history[+o.dataset.open]);
    h.prev = null; view = h; filter = 'all';
    showPanel('remote');
    $('#empty').classList.add('hidden'); $('#results').classList.remove('hidden');
    $$('.seg button').forEach(b => b.classList.toggle('on', b.dataset.filter === 'all'));
    $('#diff').classList.add('hidden');
    buildMatrix(); renderStats(); renderFindings(); renderMeta();
  } else if (a) {
    const h = history[+a.dataset.again];
    showPanel('remote');
    $('#targets').value = h.targetsText || h.ips.join('\n');
    $$('input[name=port]').forEach(x => x.checked = h.ports.includes(+x.value));
    $('#custom').value = h.ports.filter(p => !policy.services[p]).join(', ');
    updateInfo(); $('#consent').focus();
  }
});
$('#histClear').onclick = () => { if (!history.length || confirm('Delete all saved scans from this browser?')) { history = []; store.set(HISTORY_KEY, history); updateHistoryCount(); renderHistory(); } };

/* ------------------------------------------------------------ export */

const stamp = () => new Date(view.ts).toISOString().replace(/[:T]/g, '-').slice(0, 19);
const allRows = () => { const a = []; for (const [ip, rows] of view.hosts) for (const r of rows) a.push({ ip, ...r }); return a; };

function asText() {
  const lines = [`Port Tools scan, ${new Date(view.ts).toLocaleString()}`, ''];
  for (const [ip, rows] of view.hosts) {
    const open = rows.filter(r => r.status === 'open');
    lines.push(`${ip}: ${open.length ? open.map(r => `${r.port} ${r.service}${r.risk === 'high' || r.risk === 'medium' ? ' (!)' : ''}`).join(', ') : 'no open ports'}`);
  }
  return lines.join('\n');
}
function asMarkdown() {
  const rows = openRows(view);
  const s = summary(view);
  let md = `# Port scan ${new Date(view.ts).toLocaleString()}\n\n- Hosts checked: ${s.hosts}\n- Ports per host: ${view.ports.join(', ')}\n- Open: ${s.open}, needing attention: ${s.flagged}\n\n`;
  md += '| Host | Port | Service | Attention | Note |\n|---|---|---|---|---|\n';
  md += rows.length ? rows.map(r => `| ${r.ip} | ${r.port} | ${r.service} | ${r.risk === 'high' ? 'Exposed risk' : r.risk === 'medium' ? 'Worth a look' : '-'} | ${(r.note || '').replace(/\|/g, '/')} |`).join('\n') : '| - | - | No open ports | - | - |';
  return md + '\n';
}
function asCsv() {
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  return ['host,port,service,status,latency_ms,risk,note', ...allRows().map(r => [r.ip, r.port, q(r.service), r.status, r.ms, r.risk, q(r.note)].join(','))].join('\r\n') + '\r\n';
}
function asJson() {
  return JSON.stringify({ tool: 'Port Tools', version: 2, timestamp: view.ts, demo: !!view.demo, ports: view.ports, summary: summary(view), results: allRows() }, null, 2);
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('#exMd').onclick = () => download(`port-scan-${stamp()}.md`, asMarkdown(), 'text/markdown');
$('#exCsv').onclick = () => download(`port-scan-${stamp()}.csv`, '﻿' + asCsv(), 'text/csv');
$('#exJson').onclick = () => download(`port-scan-${stamp()}.json`, asJson(), 'application/json');
$('#exCopy').onclick = async function () {
  try { await navigator.clipboard.writeText(asText()); }
  catch { const t = Object.assign(document.createElement('textarea'), { value: asText() }); document.body.append(t); t.select(); document.execCommand('copy'); t.remove(); }
  const old = this.textContent; this.textContent = 'Copied'; setTimeout(() => this.textContent = old, 1500);
};

/* ------------------------------------------------------------ boot */

init().then(() => {
  $('#demo').hidden = !(demoMode);
  if (demoMode) $('#scan').textContent = 'Scan (demo)';
});
})();
