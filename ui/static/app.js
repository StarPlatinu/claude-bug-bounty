/* claudebbp UI v2 — enhanced frontend */

// ── State ─────────────────────────────────────────────────────────────────────
let activeTarget   = null;
let allFindings    = [];
let activeFilter   = 'all';
let sortKey        = 'id';
let sortDir        = 1;
let runningJob     = null;
let eventSource    = null;
let selectedFinding = null;
let palSel          = 0;
let prevFindCount   = 0;

// ── Commands palette data ─────────────────────────────────────────────────────
const COMMANDS = [
  { cmd:'/recon',      desc:'Subdomain enum → live hosts → URL crawl → nuclei',    tag:'recon'   },
  { cmd:'/hunt',       desc:'Targeted vuln checks (IDOR, XSS, SSRF, CVE…)',         tag:'hunt'    },
  { cmd:'/validate',   desc:'7-Question Gate — scores 0–11, threshold 7 to submit', tag:'validate'},
  { cmd:'/report',     desc:'Generate H1 / Bugcrowd / Intigriti submission report',  tag:'report'  },
  { cmd:'/intel',      desc:'CVEs + HackerOne disclosed reports for target',         tag:'intel'   },
  { cmd:'/triage',     desc:'Quick 3-question go/no-go triage',                      tag:'triage'  },
  { cmd:'/chain',      desc:'Build A→B→C exploit chain, 17 known patterns',         tag:'chain'   },
  { cmd:'/scope',      desc:'Verify asset is in-scope before hunting',               tag:'scope'   },
  { cmd:'/surface',    desc:'Ranked attack surface from recon output',               tag:'surface' },
  { cmd:'/pickup',     desc:'Resume previous hunt — history + suggestions',          tag:'pickup'  },
  { cmd:'/autopilot',  desc:'Full autonomous loop (paranoid / normal / yolo)',       tag:'autopilot'},
  { cmd:'/web3-audit', desc:'Slither + Mythril + pattern scan on .sol file',        tag:'web3'    },
  { cmd:'/token-scan', desc:'Rug-pull / honeypot detection for EVM + Solana',       tag:'web3'    },
  { cmd:'/remember',   desc:'Log finding to persistent hunt journal',               tag:'memory'  },
];

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadTargets();
  loadReports();
  setInterval(loadTargets, 12000);
  setInterval(loadReports, 30000);

  // Input shortcuts
  $('newTarget').addEventListener('keydown', e => e.key === 'Enter' && addTarget());
  $('cmdTarget').addEventListener('keydown', e => e.key === 'Enter' && runCommand());

  // Global keyboard
  document.addEventListener('keydown', onGlobalKey);
});

function onGlobalKey(e) {
  // Ctrl+K — palette
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    openPalette();
    return;
  }
  // Ctrl+Enter — run
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    runCommand();
    return;
  }
  // Ctrl+L — clear terminal
  if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
    e.preventDefault();
    clearTerminal();
    return;
  }
  // Esc — close modals
  if (e.key === 'Escape') {
    closePalette();
    closeModal();
    return;
  }
  // Number keys 1-4 — switch tabs
  if (!e.ctrlKey && !e.metaKey && !e.altKey && !isInput(e.target)) {
    const tabs = ['terminal','findings','stats','reports'];
    const idx  = parseInt(e.key) - 1;
    if (idx >= 0 && idx < tabs.length) switchTab(tabs[idx]);
  }
}

function isInput(el) {
  return ['INPUT','TEXTAREA','SELECT'].includes(el.tagName);
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $('tab-' + name).classList.add('active');
  $('panel-' + name).classList.add('active');

  if (name === 'findings' && activeTarget) {
    loadFindings(activeTarget);
    $('dot-findings').classList.remove('show');
  }
  if (name === 'stats' && activeTarget) loadStats(activeTarget);
  if (name === 'reports') loadReports();
}

// ── Targets ───────────────────────────────────────────────────────────────────
async function loadTargets() {
  try {
    const data = await api('/api/targets');
    renderSidebar(data);
    const total = data.reduce((s,t) => s + t.findings, 0);
    $('headerStats').textContent = `${data.length} target${data.length!==1?'s':''} · ${total} finding${total!==1?'s':''}`;
    $('sbCount').textContent = data.length;
  } catch(_) {
    $('headerStats').textContent = 'Server offline';
    $('statusDot').style.background = 'var(--red)';
  }
}

function renderSidebar(targets) {
  const el = $('targetList');
  if (!targets.length) {
    el.innerHTML = `<div class="empty" style="padding:24px 0">
      <div class="e-icon">🎯</div>
      <div class="e-sub">Add your first target above</div>
    </div>`;
    return;
  }
  el.innerHTML = targets.map(t => {
    const total  = t.critical + t.high + t.medium + t.low;
    const active = activeTarget === t.target;
    const cls    = t.critical > 0 ? 'has-crits' : t.high > 0 ? 'has-highs' : t.findings > 0 ? 'has-findings' : '';
    const barW   = (n, tot) => tot ? Math.max(3, Math.round(n/tot*80)) : 0;

    return `
    <div class="target-item ${cls} ${active?'active':''}" onclick="selectTarget('${esc(t.target)}')">
      <div class="ti-top">
        <div class="ti-dot"></div>
        <div class="ti-name" title="${esc(t.target)}">${esc(t.target)}</div>
        <button class="ti-del" onclick="deleteTarget(event,'${esc(t.target)}')" title="Remove">✕</button>
      </div>
      ${total > 0 ? `
      <div class="ti-bars">
        ${t.critical ? `<div class="sev-pip pip-c" style="width:${barW(t.critical,total)}px"></div>` : ''}
        ${t.high     ? `<div class="sev-pip pip-h" style="width:${barW(t.high,total)}px"></div>` : ''}
        ${t.medium   ? `<div class="sev-pip pip-m" style="width:${barW(t.medium,total)}px"></div>` : ''}
        ${t.low      ? `<div class="sev-pip pip-l" style="width:${barW(t.low,total)}px"></div>` : ''}
        <span class="ti-total">${total}</span>
      </div>` : ''}
    </div>`;
  }).join('');
}

function addTarget() {
  const inp = $('newTarget');
  const val = inp.value.trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];
  if (!val) return;
  inp.value = '';
  selectTarget(val);
  toast(`Target: ${val}`, 'green');
}

async function deleteTarget(e, target) {
  e.stopPropagation();
  if (!confirm(`Remove ${target}?`)) return;
  await api(`/api/target/${encodeURIComponent(target)}`, 'DELETE');
  if (activeTarget === target) { activeTarget = null; allFindings = []; renderFindings(); }
  loadTargets();
  toast(`Removed ${target}`);
}

function selectTarget(target) {
  activeTarget = target;
  $('cmdTarget').value = target;
  loadTargets();
  const tab = document.querySelector('.tab.active')?.id?.replace('tab-','');
  if (tab === 'findings') loadFindings(target);
  if (tab === 'stats')    loadStats(target);
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function onCmdChange() {
  const cmd = $('cmdSelect').value;
  $('vcSelect').style.display    = cmd === '/hunt'      ? 'block' : 'none';
  $('platSelect').style.display  = cmd === '/report'    ? 'block' : 'none';
  $('modeSelect').style.display  = cmd === '/autopilot' ? 'block' : 'none';
}

async function runCommand() {
  const target  = $('cmdTarget').value.trim();
  const command = $('cmdSelect').value;

  const needsTarget = !['/validate','/triage','/chain'].includes(command);
  if (!target && needsTarget) {
    toast('Enter a target first', 'red');
    $('cmdTarget').focus();
    return;
  }

  const flags = {};
  if (command === '/hunt'     && $('vcSelect').value)   flags['vuln-class'] = $('vcSelect').value;
  if (command === '/report'   && $('platSelect').value) flags['platform']   = $('platSelect').value;
  if (command === '/autopilot') flags['mode'] = $('modeSelect').value;

  await startJob(command, target, flags);
}

function quickRun(cmd) {
  const target = activeTarget || $('cmdTarget').value.trim();
  if (!target) { toast('Select a target first', 'red'); return; }
  $('cmdSelect').value = cmd;
  onCmdChange();
  startJob(cmd, target, {});
}

async function startJob(command, target, flags) {
  if (runningJob) { toast('Already running…', 'yellow'); return; }
  if (eventSource) { eventSource.close(); eventSource = null; }

  switchTab('terminal');
  $('runBtn').disabled = true;
  $('cursor').style.display = 'inline-block';
  $('termTitle').textContent = `${command} ${target}`;
  startProgress();

  // Highlight active quick cmd
  document.querySelectorAll('.qcmd').forEach(b => {
    b.classList.toggle('active', b.textContent.trim() === command);
  });

  appendLine('', 'dim');
  appendLine(`▶  ${command}${target ? ' ' + target : ''}  ${Object.entries(flags).map(([k,v])=>`--${k} ${v}`).join(' ')}`, 'cmd');

  try {
    const { job_id } = await api('/api/run', 'POST', { command, target, flags });
    runningJob = job_id;
    listenJob(job_id);
  } catch(e) {
    appendLine(`Error: ${e.message}`, 'error');
    onJobDone();
  }
}

function listenJob(jobId) {
  eventSource = new EventSource(`/api/stream/${jobId}`);
  eventSource.onmessage = e => {
    const d = JSON.parse(e.data);
    if (d.type === 'done') {
      onJobDone();
      loadTargets();
      if (activeTarget) {
        const prevCount = allFindings.length;
        loadFindings(activeTarget).then(() => {
          if (allFindings.length > prevCount) {
            $('dot-findings').classList.add('show');
            toast(`${allFindings.length - prevCount} new finding(s)!`, 'green');
          }
        });
      }
      return;
    }
    appendLine(d.line || '', classify(d.line || ''));
  };
  eventSource.onerror = () => { appendLine('Connection lost', 'error'); onJobDone(); };
}

function onJobDone() {
  runningJob = null;
  if (eventSource) { eventSource.close(); eventSource = null; }
  $('runBtn').disabled = false;
  $('cursor').style.display = 'none';
  $('termTitle').textContent = 'claudebbp terminal';
  document.querySelectorAll('.qcmd').forEach(b => b.classList.remove('active'));
  stopProgress();
}

function appendLine(text, type = '') {
  const body = $('termBody');
  const now  = new Date().toTimeString().slice(0,8);
  const row  = document.createElement('div');
  row.className = `t-row t-${type||'out'}`;
  row.innerHTML = `<span class="t-ts">${now}</span><span class="t-txt">${escHtml(text)}</span>`;
  body.appendChild(row);
  const term = $('termBody').closest('.terminal');
  if(term) term.scrollTop = term.scrollHeight;
}

function classify(line) {
  const l = line.toLowerCase();
  if (l.startsWith('▶') || l.startsWith('$'))                        return 'cmd';
  if (l.startsWith('─') || l.startsWith('═'))                        return 'sep';
  if (l.includes('[finding]'))                                        return 'finding';
  if (l.includes('[+]'))                                              return 'success';
  if (l.includes('[!]') || l.includes('warn'))                        return 'warn';
  if (l.includes('[-]') || l.includes('error') || l.includes('✗'))   return 'error';
  if (l.includes('  >') || l.includes('[*]'))                         return 'info';
  if (l.includes('✓') || l.includes('done'))                          return 'done';
  if (!l.trim())                                                       return 'dim';
  return 'out';
}

function clearTerminal() {
  $('termBody').innerHTML = '';
  toast('Terminal cleared');
}

function copyTerminal() {
  const lines = [...document.querySelectorAll('#termBody .t-txt')].map(x => x.textContent).join('\n');
  navigator.clipboard.writeText(lines).then(() => toast('Copied to clipboard', 'green'));
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings(target) {
  try {
    allFindings = await api(`/api/findings/${encodeURIComponent(target)}`);
    renderFindings();
  } catch(_) { allFindings = []; renderFindings(); }
}

function filterSev(sev) {
  activeFilter = sev;
  document.querySelectorAll('.sev-filters .f-btn').forEach(b => b.classList.remove('active'));
  $('f-' + sev)?.classList.add('active');
  renderFindings();
}

function sortFindings(key) {
  if (sortKey === key) sortDir *= -1;
  else { sortKey = key; sortDir = 1; }
  renderFindings();
}

function renderFindings() {
  const q = ($('searchInput')?.value || '').toLowerCase();

  const SEV_RANK = { critical:4, high:3, medium:2, low:1, info:0 };

  let list = allFindings
    .filter(f => activeFilter === 'all' || (f.severity||'').toLowerCase() === activeFilter)
    .filter(f => !q || JSON.stringify(f).toLowerCase().includes(q));

  // Sort
  list.sort((a,b) => {
    let av = a[sortKey] ?? '', bv = b[sortKey] ?? '';
    if (sortKey === 'severity') { av = SEV_RANK[av.toLowerCase()]||0; bv = SEV_RANK[bv.toLowerCase()]||0; }
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });

  $('findCount').textContent = `${list.length} finding${list.length!==1?'s':''}`;

  const tbody = $('findTbody');
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:50px;color:var(--text3)">
      ${allFindings.length ? 'No matches for current filter' : 'No findings yet — run /hunt to start'}
    </td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(f => {
    const sev = (f.severity||'info').toLowerCase();
    const url = truncate(f.url||'—', 45);
    const vrd = f.gate_verdict || '—';
    return `
    <tr onclick="openFinding('${esc(f.id||'')}')">
      <td class="td-m">${esc(f.id||'—')}</td>
      <td><span class="badge b-${sev}">${sev}</span></td>
      <td class="td-t">${esc(f.title || f.vuln_class || '—')}</td>
      <td class="td-m">${esc(f.vuln_class||'—')}</td>
      <td class="td-m" title="${esc(f.url||'')}"><span style="color:var(--cyan)">${esc(url)}</span></td>
      <td class="td-m">${f.gate_score != null ? `${f.gate_score}/11` : '—'}</td>
      <td class="td-m ${vrd==='SUBMIT'?'v-submit':vrd==='CHAIN'?'v-chain':vrd==='KILL'?'v-kill':''}">${vrd}</td>
    </tr>`;
  }).join('');
}

function exportFindings(format) {
  if (!allFindings.length) { toast('No findings to export', 'yellow'); return; }
  let content, mime, ext;
  if (format === 'json') {
    content = JSON.stringify(allFindings, null, 2);
    mime = 'application/json'; ext = 'json';
  } else {
    const headers = ['id','severity','vuln_class','title','url','gate_score','gate_verdict','source'];
    const rows    = allFindings.map(f => headers.map(h => `"${(f[h]||'').toString().replace(/"/g,'""')}"`).join(','));
    content = [headers.join(','), ...rows].join('\n');
    mime = 'text/csv'; ext = 'csv';
  }
  const blob = new Blob([content], { type: mime });
  const a    = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `findings_${activeTarget||'export'}.${ext}` });
  a.click();
  toast(`Exported ${allFindings.length} findings as ${ext.toUpperCase()}`, 'green');
}

// ── Finding modal ─────────────────────────────────────────────────────────────
function openFinding(id) {
  const f = allFindings.find(x => x.id === id);
  if (!f) return;
  selectedFinding = f;

  const sev = (f.severity||'info').toLowerCase();
  $('modal-badge').outerHTML = `<span id="modal-badge" class="badge b-${sev}">${sev}</span>`;
  $('modal-title').textContent = f.title || f.vuln_class || 'Finding Detail';

  $('modal-body').innerHTML = `
    <div class="mf-grid">
      <div class="mf-cell"><label>ID</label><div class="val">${esc(f.id||'—')}</div></div>
      <div class="mf-cell"><label>Target</label><div class="val">${esc(f.target||'—')}</div></div>
      <div class="mf-cell"><label>Vuln Class</label><div class="val">${esc(f.vuln_class||'—')}</div></div>
      <div class="mf-cell"><label>Source</label><div class="val">${esc(f.source||'—')}</div></div>
      <div class="mf-cell" style="grid-column:1/-1"><label>URL</label><div class="val" style="word-break:break-all;color:var(--cyan)">${esc(f.url||'—')}</div></div>
      <div class="mf-cell"><label>Gate Score</label><div class="val">${f.gate_score != null ? `${f.gate_score} / 11` : '—'}</div></div>
      <div class="mf-cell"><label>Verdict</label>
        <div class="val ${f.gate_verdict==='SUBMIT'?'v-submit':f.gate_verdict==='CHAIN'?'v-chain':'v-kill'}">${f.gate_verdict||'—'}</div>
      </div>
      <div class="mf-cell"><label>Discovered</label><div class="val" style="font-size:11px">${esc(f.ts||'—')}</div></div>
      <div class="mf-cell"><label>CVSS</label><div class="val">${esc(f.cvss||'—')}</div></div>
    </div>
    <div class="mf-poc">
      <label>Proof of Concept</label>
      <pre>${esc(f.poc||'No PoC recorded — run /validate to add one')}</pre>
    </div>
    ${f.chain_suggestions?.length ? `
    <div class="mf-poc" style="margin-top:10px">
      <label>Chain Suggestions</label>
      <pre>${esc(f.chain_suggestions.map(c=>`[${c.severity.toUpperCase()}] ${c.desc}`).join('\n'))}</pre>
    </div>` : ''}
  `;

  $('modal-overlay').classList.add('open');
}

function closeModal(e) {
  if (e && e.target !== $('modal-overlay')) return;
  $('modal-overlay').classList.remove('open');
  selectedFinding = null;
}

function copyFinding() {
  if (!selectedFinding) return;
  navigator.clipboard.writeText(JSON.stringify(selectedFinding, null, 2))
    .then(() => toast('Finding JSON copied', 'green'));
}

function runReportForFinding() {
  if (!selectedFinding) return;
  closeModal();
  $('cmdSelect').value = '/report';
  $('cmdTarget').value = selectedFinding.target || activeTarget || '';
  onCmdChange();
  switchTab('terminal');
  toast('Running /report…');
  runCommand();
}

// ── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats(target) {
  try {
    const state = await api(`/api/state/${encodeURIComponent(target)}`);
    renderStats(state);
  } catch(_) {}
}

function renderStats(state) {
  const findings = state.findings || [];
  const recon    = state.recon   || {};
  const intel    = state.intel   || {};

  const sev = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => { const s = (f.severity||'info').toLowerCase(); sev[s] = (sev[s]||0)+1; });
  const total   = findings.length;
  const submit  = findings.filter(f => f.gate_verdict === 'SUBMIT').length;
  const pct = n => total ? Math.round(n/total*100) : 0;

  $('statsContent').innerHTML = `
    <div class="stats-grid">
      ${sc('Total Findings', total, '', submit + ' ready to submit')}
      ${sc('Critical', sev.critical, 'red',    pct(sev.critical) + '% of findings')}
      ${sc('High',     sev.high,     'orange',  pct(sev.high)     + '% of findings')}
      ${sc('Medium',   sev.medium,   'yellow',  pct(sev.medium)   + '% of findings')}
      ${sc('Low',      sev.low,      'blue',    pct(sev.low)      + '% of findings')}
      ${sc('Subdomains',  (recon.subdomains||[]).length, 'purple', (recon.live_hosts||[]).length + ' live hosts')}
      ${sc('URLs Found',  (recon.urls||[]).length, '',      (recon.nuclei||[]).length + ' nuclei hits')}
      ${sc('CVEs',        (intel.cves||[]).length, (intel.cves||[]).length > 0 ? 'red' : '', (intel.disclosed_reports||[]).length + ' disclosed reports')}
      ${sc('Gate Passed', submit, submit > 0 ? '' : '', `of ${total} total`)}
    </div>

    ${total > 0 ? `
    <div class="sev-bar-card">
      <div class="sev-bar-title">Severity Distribution</div>
      <div class="sev-bar">
        <div class="b-c" style="width:${pct(sev.critical)}%"></div>
        <div class="b-h" style="width:${pct(sev.high)}%"></div>
        <div class="b-m" style="width:${pct(sev.medium)}%"></div>
        <div class="b-l" style="width:${pct(sev.low)}%"></div>
      </div>
      <div class="sev-legend">
        <div class="sev-leg-item"><div class="leg-dot" style="background:var(--red)"></div>Critical ${sev.critical}</div>
        <div class="sev-leg-item"><div class="leg-dot" style="background:var(--orange)"></div>High ${sev.high}</div>
        <div class="sev-leg-item"><div class="leg-dot" style="background:var(--yellow)"></div>Medium ${sev.medium}</div>
        <div class="sev-leg-item"><div class="leg-dot" style="background:var(--blue)"></div>Low ${sev.low}</div>
      </div>
    </div>` : ''}

    ${(recon.nuclei||[]).length > 0 ? `
    <div class="sev-bar-card" style="margin-top:10px">
      <div class="sev-bar-title">Top Nuclei Findings</div>
      ${recon.nuclei.slice(0,5).map(n => `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
          <span class="badge b-${(n.severity||'info').toLowerCase()}">${n.severity||'?'}</span>
          <span style="font-size:12px;color:var(--text2);flex:1">${esc(n.name||n.template_id||'?')}</span>
          <span style="font-size:11px;color:var(--text3);font-family:var(--mono)">${esc(truncate(n.host||'',40))}</span>
        </div>`).join('')}
    </div>` : ''}

    <div class="sev-bar-card" style="margin-top:10px">
      <div class="sev-bar-title">Recon Summary</div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:10px">
        ${mini('Subdomains', (recon.subdomains||[]).length)}
        ${mini('Live Hosts', (recon.live_hosts||[]).length)}
        ${mini('URLs', (recon.urls||[]).length)}
        ${mini('Nuclei Hits', (recon.nuclei||[]).length)}
      </div>
    </div>
  `;
}

function sc(label, value, color, sub) {
  return `<div class="stat-card">
    <div class="sc-label">${label}</div>
    <div class="sc-val ${color}">${value}</div>
    <div class="sc-sub">${sub}</div>
  </div>`;
}

function mini(label, val) {
  return `<div style="text-align:center;padding:10px;background:var(--bg3);border-radius:var(--r)">
    <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--green)">${val}</div>
    <div style="font-size:10px;color:var(--text3);margin-top:3px;text-transform:uppercase;letter-spacing:.5px">${label}</div>
  </div>`;
}

// ── Reports ───────────────────────────────────────────────────────────────────
async function loadReports() {
  try {
    const data = await api('/api/reports');
    const el = $('repList');
    if (!data.length) {
      el.innerHTML = `<div class="empty" style="padding:30px 0">
        <div class="e-icon">📄</div><div class="e-sub">No reports yet</div>
        <div class="e-sub" style="margin-top:4px">Run /report to generate one</div>
      </div>`;
      return;
    }
    el.innerHTML = data.map(r => `
      <div class="rep-item" onclick="openReport('${esc(r.path)}',this)">
        <div class="ri-name">${esc(r.name)}</div>
        <div class="ri-meta"><span>${formatBytes(r.size)}</span></div>
      </div>`).join('');
  } catch(_) {}
}

async function openReport(path, el) {
  document.querySelectorAll('.rep-item').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  try {
    const { content } = await api(`/api/report-content?path=${encodeURIComponent(path)}`);
    $('repPreview').innerHTML = `<div class="md">${mdToHtml(content)}</div>`;
  } catch(_) {
    $('repPreview').innerHTML = '<div class="empty"><div class="e-msg">Failed to load report</div></div>';
  }
}

// ── Command Palette ───────────────────────────────────────────────────────────
function openPalette() {
  $('palette-overlay').classList.add('open');
  $('palInput').value = '';
  palSel = 0;
  renderPalette(COMMANDS);
  setTimeout(() => $('palInput').focus(), 50);
}

function closePalette(e) {
  if (e && e.target !== $('palette-overlay')) return;
  $('palette-overlay').classList.remove('open');
}

function filterPalette() {
  const q = $('palInput').value.toLowerCase();
  const filtered = q ? COMMANDS.filter(c => c.cmd.includes(q) || c.desc.toLowerCase().includes(q) || c.tag.includes(q)) : COMMANDS;
  palSel = 0;
  renderPalette(filtered);
}

function renderPalette(items) {
  $('palList').innerHTML = items.map((c,i) => `
    <div class="pal-item ${i===palSel?'selected':''}" onclick="runPalette('${esc(c.cmd)}')">
      <div class="pal-cmd">${esc(c.cmd)}</div>
      <div class="pal-desc">${esc(c.desc)}</div>
      <div class="pal-badge">${esc(c.tag)}</div>
    </div>`).join('');
}

function palKey(e) {
  const items = $('palList').querySelectorAll('.pal-item');
  if (e.key === 'ArrowDown') { palSel = Math.min(palSel+1, items.length-1); highlightPal(); e.preventDefault(); }
  if (e.key === 'ArrowUp')   { palSel = Math.max(palSel-1, 0); highlightPal(); e.preventDefault(); }
  if (e.key === 'Enter' && items[palSel]) items[palSel].click();
}

function highlightPal() {
  $('palList').querySelectorAll('.pal-item').forEach((el,i) => {
    el.classList.toggle('selected', i === palSel);
    if (i === palSel) el.scrollIntoView({ block:'nearest' });
  });
}

function runPalette(cmd) {
  $('palette-overlay').classList.remove('open');
  $('cmdSelect').value = cmd;
  onCmdChange();
  switchTab('terminal');
  const target = activeTarget || '';
  if (target) $('cmdTarget').value = target;
  $('cmdTarget').focus();
}

// ── Progress bar ──────────────────────────────────────────────────────────────
function startProgress() {
  const bar = $('progressBar');
  bar.style.width = '0';
  bar.classList.add('indeterminate');
}

function stopProgress() {
  const bar = $('progressBar');
  bar.classList.remove('indeterminate');
  bar.style.width = '100%';
  setTimeout(() => { bar.style.transition = 'width .4s ease'; bar.style.width = '0'; }, 500);
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let _toastId = 0;
function toast(msg, type = '') {
  const wrap = $('toast-wrap');
  const id   = ++_toastId;
  const el   = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  requestAnimationFrame(() => { requestAnimationFrame(() => el.classList.add('show')); });
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

// ── Markdown renderer ─────────────────────────────────────────────────────────
function mdToHtml(md) {
  return md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^#### (.+)$/gm,'<h3>$1</h3>')
    .replace(/^### (.+)$/gm,'<h3>$1</h3>')
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,'<em>$1</em>')
    .replace(/^\|(.+)\|$/gm, row => '<tr>' + row.split('|').slice(1,-1).map(c=>`<td>${c.trim()}</td>`).join('') + '</tr>')
    .replace(/(<tr>.*<\/tr>\n?)+/g, m => `<table>${m}</table>`)
    .replace(/^---+$/gm,'<hr>')
    .replace(/^\d+\. (.+)$/gm,'<li>$1</li>')
    .replace(/^[-*] (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, m => `<ul>${m}</ul>`)
    .replace(/^> (.+)$/gm,'<blockquote>$1</blockquote>')
    .replace(/\n\n+/g,'</p><p>')
    .replace(/^(?!<[hpuotlcbied])/gm, '')
    .replace(/^(.+)$/gm, l => l.startsWith('<') ? l : `<p>${l}</p>`);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function api(url, method = 'GET', body = null) {
  const opts = { method, headers: {} };
  if (body) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function $(id) { return document.getElementById(id); }

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escHtml(s) { return esc(s); }

function truncate(s, n) { return s.length > n ? s.slice(0,n) + '…' : s; }

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}
