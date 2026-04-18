/* claudebbp UI — frontend logic */

// ── State ─────────────────────────────────────────────────────────────────────
let activeTarget  = null;
let allFindings   = [];
let activeFilter  = 'all';
let runningJob    = null;
let eventSource   = null;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadTargets();
  loadReports();
  setInterval(loadTargets, 15000);
  setInterval(loadReports, 30000);

  // Enter key on new target input
  document.getElementById('newTarget').addEventListener('keydown', e => {
    if (e.key === 'Enter') addTarget();
  });

  // Enter key on cmd target
  document.getElementById('cmdTarget').addEventListener('keydown', e => {
    if (e.key === 'Enter') runCommand();
  });

  // Show/hide extra selects based on command
  document.getElementById('cmdSelect').addEventListener('change', updateCmdExtras);
});

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');

  if (name === 'findings' && activeTarget) loadFindings(activeTarget);
  if (name === 'stats'    && activeTarget) loadStats(activeTarget);
  if (name === 'reports')                  loadReports();
}

// ── Targets ───────────────────────────────────────────────────────────────────
async function loadTargets() {
  try {
    const res  = await fetch('/api/targets');
    const data = await res.json();
    renderTargetList(data);

    const totalFindings = data.reduce((s, t) => s + t.findings, 0);
    document.getElementById('headerStats').textContent =
      `${data.length} targets · ${totalFindings} findings`;
  } catch (_) {}
}

function renderTargetList(targets) {
  const el = document.getElementById('targetList');
  if (!targets.length) {
    el.innerHTML = '<div class="empty" style="padding:20px 0"><div class="empty-sub">No targets yet</div></div>';
    return;
  }
  el.innerHTML = targets.map(t => `
    <div class="target-item ${t.findings > 0 ? 'has-findings' : ''} ${activeTarget === t.target ? 'active' : ''}"
         onclick="selectTarget('${esc(t.target)}')">
      <div class="t-name" title="${esc(t.target)}">${esc(t.target)}</div>
      <div class="t-count">${t.findings}</div>
      <button class="t-del" onclick="deleteTarget(event,'${esc(t.target)}')" title="Remove">✕</button>
    </div>
  `).join('');
}

function addTarget() {
  const inp = document.getElementById('newTarget');
  const val = inp.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!val) return;
  inp.value = '';
  selectTarget(val);
  toast(`Target added: ${val}`, 'green');
  loadTargets();
}

async function deleteTarget(e, target) {
  e.stopPropagation();
  if (!confirm(`Remove ${target} from state?`)) return;
  await fetch(`/api/target/${encodeURIComponent(target)}`, { method: 'DELETE' });
  if (activeTarget === target) {
    activeTarget = null;
    clearFindings();
  }
  loadTargets();
  toast(`Removed ${target}`);
}

function selectTarget(target) {
  activeTarget = target;
  document.getElementById('cmdTarget').value = target;
  loadTargets();

  const activePanel = document.querySelector('.tab.active')?.id?.replace('tab-', '');
  if (activePanel === 'findings') loadFindings(target);
  if (activePanel === 'stats')    loadStats(target);
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function updateCmdExtras() {
  const cmd = document.getElementById('cmdSelect').value;
  document.getElementById('vulnClassSelect').style.display = (cmd === '/hunt') ? 'block' : 'none';
  document.getElementById('platformSelect').style.display  = (cmd === '/report') ? 'block' : 'none';
  document.getElementById('modeSelect').style.display      = (cmd === '/autopilot') ? 'block' : 'none';
}

async function runCommand() {
  const target  = document.getElementById('cmdTarget').value.trim();
  const command = document.getElementById('cmdSelect').value;

  if (!target && !['validate','triage','chain'].includes(command.replace('/',''))) {
    toast('Enter a target first', 'red');
    document.getElementById('cmdTarget').focus();
    return;
  }

  const flags = {};
  if (command === '/hunt') {
    const vc = document.getElementById('vulnClassSelect').value;
    if (vc) flags['vuln-class'] = vc;
  }
  if (command === '/report') {
    flags['platform'] = document.getElementById('platformSelect').value;
  }
  if (command === '/autopilot') {
    flags['mode'] = document.getElementById('modeSelect').value;
  }

  await startJob(command, target, flags);
}

function quickRun(cmd) {
  const target = activeTarget || document.getElementById('cmdTarget').value.trim();
  if (!target) { toast('Select a target first', 'red'); return; }
  startJob(cmd, target, {});
}

async function startJob(command, target, flags) {
  if (runningJob) {
    toast('A command is already running…', 'red');
    return;
  }

  // Cancel existing SSE
  if (eventSource) { eventSource.close(); eventSource = null; }

  document.getElementById('runBtn').disabled = true;
  document.getElementById('cursor').style.display = 'inline-block';
  document.getElementById('termTitle').textContent = `${command} ${target}`;

  // Switch to terminal tab
  switchTab('terminal');

  // Mark active quick cmd button
  document.querySelectorAll('.qcmd').forEach(b => {
    b.classList.toggle('running', b.textContent.trim() === command);
  });

  // Append separator in terminal
  appendLine('', 't-dim');
  appendLine(`▶ ${command} ${target}`, 't-cmd');

  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command, target, flags }),
    });
    const { job_id } = await res.json();
    runningJob = job_id;
    listenToJob(job_id);
  } catch (e) {
    appendLine(`Error: ${e.message}`, 't-error');
    onJobDone();
  }
}

function listenToJob(jobId) {
  eventSource = new EventSource(`/api/stream/${jobId}`);

  eventSource.onmessage = e => {
    const data = JSON.parse(e.data);
    if (data.type === 'done') {
      onJobDone();
      loadTargets();
      if (activeTarget) loadFindings(activeTarget);
      return;
    }
    appendLine(data.line || '', classifyLine(data.line || ''));
  };

  eventSource.onerror = () => {
    appendLine('Connection lost', 't-error');
    onJobDone();
  };
}

function onJobDone() {
  runningJob = null;
  if (eventSource) { eventSource.close(); eventSource = null; }
  document.getElementById('runBtn').disabled = false;
  document.getElementById('cursor').style.display = 'none';
  document.getElementById('termTitle').textContent = 'claudebbp terminal';
  document.querySelectorAll('.qcmd').forEach(b => b.classList.remove('running'));
}

function appendLine(text, cls = '') {
  const out = document.getElementById('termOutput');
  const div = document.createElement('div');
  div.className = `t-line ${cls}`;
  div.textContent = text;
  out.appendChild(div);

  const term = document.getElementById('terminal');
  term.scrollTop = term.scrollHeight;
}

function classifyLine(line) {
  const l = line.toLowerCase();
  if (l.startsWith('$') || l.startsWith('▶'))           return 't-cmd';
  if (l.startsWith('─') || l.startsWith('='))            return 't-sep';
  if (l.includes('[finding]') || l.includes('[+]') && l.includes('found'))   return 't-finding';
  if (l.includes('[+]'))                                  return 't-success';
  if (l.includes('[!]') || l.includes('warn'))            return 't-warn';
  if (l.includes('[-]') || l.includes('error') || l.includes('failed')) return 't-error';
  if (l.includes('[*]') || l.includes('  >'))             return 't-info';
  if (l.includes('done') || l.includes('✓'))             return 't-done';
  if (l.trim() === '' || l.startsWith('─'))               return 't-dim';
  return '';
}

function clearTerminal() {
  document.getElementById('termOutput').innerHTML = '';
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings(target) {
  try {
    const res = await fetch(`/api/findings/${encodeURIComponent(target)}`);
    allFindings = await res.json();
    renderFindings();
  } catch (_) {
    allFindings = [];
    renderFindings();
  }
}

function filterFindings(sev) {
  activeFilter = sev;
  document.querySelectorAll('#sevFilters .filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('f-' + sev)?.classList.add('active');
  renderFindings();
}

function renderFindings() {
  const filtered = activeFilter === 'all'
    ? allFindings
    : allFindings.filter(f => (f.severity||'').toLowerCase() === activeFilter);

  document.getElementById('findingsCount').textContent = `${filtered.length} finding${filtered.length !== 1 ? 's' : ''}`;

  const tbody = document.getElementById('findingsTbody');
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-dim)">
      ${allFindings.length ? 'No findings match this filter' : 'No findings yet — run /hunt to start'}
    </td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(f => {
    const sev     = (f.severity || 'info').toLowerCase();
    const verdict = f.gate_verdict || '';
    const url     = (f.url || '').substring(0, 50) + (f.url?.length > 50 ? '…' : '');
    return `
      <tr onclick="showFinding('${esc(f.id||'')}')">
        <td class="td-mono">${esc(f.id || '—')}</td>
        <td><span class="badge badge-${sev}">${sev}</span></td>
        <td class="td-title">${esc(f.title || f.vuln_class || '—')}</td>
        <td class="td-mono">${esc(f.vuln_class || '—')}</td>
        <td class="td-mono" title="${esc(f.url||'')}">${esc(url)}</td>
        <td class="td-mono ${verdictClass(verdict)}">${verdict || '—'}</td>
        <td class="td-mono">${esc(f.source || '—')}</td>
      </tr>`;
  }).join('');
}

function clearFindings() {
  allFindings = [];
  renderFindings();
  document.getElementById('findingsCount').textContent = '0 findings';
}

function showFinding(id) {
  const f = allFindings.find(x => x.id === id);
  if (!f) return;
  const detail = [
    `ID: ${f.id}`,
    `Title: ${f.title || '—'}`,
    `Severity: ${f.severity || '—'}`,
    `Vuln Class: ${f.vuln_class || '—'}`,
    `URL: ${f.url || '—'}`,
    `Gate Score: ${f.gate_score ?? '—'} / 11`,
    `Verdict: ${f.gate_verdict || '—'}`,
    '',
    'PoC:',
    f.poc || '—',
  ].join('\n');
  alert(detail);
}

function verdictClass(v) {
  if (!v) return '';
  return { SUBMIT: 'verdict-submit', CHAIN: 'verdict-chain', KILL: 'verdict-kill' }[v] || '';
}

// ── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats(target) {
  try {
    const res   = await fetch(`/api/state/${encodeURIComponent(target)}`);
    const state = await res.json();
    renderStats(target, state);
  } catch (_) {}
}

function renderStats(target, state) {
  const findings = state.findings || [];
  const recon    = state.recon   || {};
  const intel    = state.intel   || {};

  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { const s = (f.severity||'info').toLowerCase(); bySev[s] = (bySev[s]||0)+1; });

  const total = findings.length;
  const submitReady = findings.filter(f => f.gate_verdict === 'SUBMIT').length;

  const pct = (n) => total ? Math.round(n/total*100) : 0;

  document.getElementById('statsGrid').innerHTML = `
    <div class="stat-card">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value">${total}</div>
      <div class="stat-sub">${submitReady} ready to submit</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical</div>
      <div class="stat-value red">${bySev.critical}</div>
      <div class="stat-sub">${pct(bySev.critical)}% of findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High</div>
      <div class="stat-value orange">${bySev.high}</div>
      <div class="stat-sub">${pct(bySev.high)}% of findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium</div>
      <div class="stat-value yellow">${bySev.medium}</div>
      <div class="stat-sub">${pct(bySev.medium)}% of findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Subdomains</div>
      <div class="stat-value blue">${(recon.subdomains||[]).length}</div>
      <div class="stat-sub">${(recon.live_hosts||[]).length} live hosts</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">URLs Found</div>
      <div class="stat-value purple">${(recon.urls||[]).length}</div>
      <div class="stat-sub">${(recon.nuclei||[]).length} nuclei hits</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">CVEs Found</div>
      <div class="stat-value ${(intel.cves||[]).length > 0 ? 'red' : ''}">${(intel.cves||[]).length}</div>
      <div class="stat-sub">${(intel.disclosed_reports||[]).length} disclosed reports</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Gate Passed</div>
      <div class="stat-value">${submitReady}</div>
      <div class="stat-sub">out of ${total} findings</div>
    </div>

    ${total > 0 ? `
    <div class="stat-card sev-bar-wrap" style="grid-column:1/-1">
      <div class="stat-label">Severity Distribution</div>
      <div class="sev-bar">
        <div class="sev-c" style="width:${pct(bySev.critical)}%" title="Critical: ${bySev.critical}"></div>
        <div class="sev-h" style="width:${pct(bySev.high)}%"     title="High: ${bySev.high}"></div>
        <div class="sev-m" style="width:${pct(bySev.medium)}%"   title="Medium: ${bySev.medium}"></div>
        <div class="sev-l" style="width:${pct(bySev.low)}%"      title="Low: ${bySev.low}"></div>
      </div>
      <div style="display:flex;gap:16px;margin-top:8px;font-size:11px;color:var(--text-dim)">
        <span style="color:var(--red)">■ Critical ${bySev.critical}</span>
        <span style="color:var(--orange)">■ High ${bySev.high}</span>
        <span style="color:var(--yellow)">■ Medium ${bySev.medium}</span>
        <span style="color:var(--blue)">■ Low ${bySev.low}</span>
      </div>
    </div>` : ''}

    ${(state.updated) ? `
    <div class="stat-card" style="grid-column:1/-1">
      <div class="stat-label">Last Updated</div>
      <div style="font-family:var(--font-mono);font-size:12px;color:var(--text-mid)">${state.updated}</div>
    </div>` : ''}
  `;
}

// ── Reports ───────────────────────────────────────────────────────────────────
async function loadReports() {
  try {
    const res  = await fetch('/api/reports');
    const data = await res.json();
    renderReportList(data);
  } catch (_) {}
}

function renderReportList(reports) {
  const el = document.getElementById('reportList');
  if (!reports.length) {
    el.innerHTML = `<div class="empty" style="padding:20px 0">
      <div class="empty-sub">No reports yet</div>
      <div class="empty-sub" style="margin-top:4px">Run /report to generate one</div>
    </div>`;
    return;
  }
  el.innerHTML = reports.map(r => `
    <div class="report-item" onclick="openReport('${esc(r.path)}', this)">
      <div class="r-name">${esc(r.name)}</div>
      <div class="r-meta">${formatBytes(r.size)}</div>
    </div>
  `).join('');
}

async function openReport(path, el) {
  document.querySelectorAll('.report-item').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  try {
    const res  = await fetch(`/api/report-content?path=${encodeURIComponent(path)}`);
    const data = await res.json();
    document.getElementById('reportPreview').innerHTML =
      `<div class="md">${markdownToHtml(data.content)}</div>`;
  } catch (_) {
    document.getElementById('reportPreview').innerHTML =
      '<div class="empty"><div class="empty-msg">Failed to load report</div></div>';
  }
}

// ── Markdown renderer (minimal) ───────────────────────────────────────────────
function markdownToHtml(md) {
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^#### (.+)$/gm,   '<h3>$1</h3>')
    .replace(/^### (.+)$/gm,    '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,     '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,      '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g,  '<strong>$1</strong>')
    .replace(/`([^`]+)`/g,      '<code>$1</code>')
    .replace(/^```[\w]*\n?([\s\S]*?)```/gm, '<pre><code>$1</code></pre>')
    .replace(/^\|(.+)\|$/gm, (row) => {
      const cells = row.split('|').slice(1,-1).map(c => `<td>${c.trim()}</td>`).join('');
      return `<tr>${cells}</tr>`;
    })
    .replace(/(<tr>.*<\/tr>\n?)+/g, m => `<table>${m}</table>`)
    .replace(/^---+$/gm,        '<hr>')
    .replace(/^\d+\. (.+)$/gm,  '<li>$1</li>')
    .replace(/^[-*] (.+)$/gm,   '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, m => `<ul>${m}</ul>`)
    .replace(/\n\n/g,            '</p><p>')
    .replace(/^(?!<[h|p|u|o|t|l|h|c|b|i|d])/gm, '')
    .replace(/^(.+)$/gm, l => l.startsWith('<') ? l : `<p>${l}</p>`);
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let _toastTimer;
function toast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `show ${type}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.className = ''; }, 3000);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}
