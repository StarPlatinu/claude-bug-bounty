/* claudebbp Scanner Dashboard */

// ── State ─────────────────────────────────────────────────────────────────────
let activeTarget = null;
let allVulns     = [];
let activeFilter = 'all';
let runningJob   = null;
let eventSource  = null;
let selectedVuln = null;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadTargets();
  setInterval(loadTargets, 10000);
  $('newTarget').addEventListener('keydown', e => e.key === 'Enter' && addTarget());
  $('cmdTarget').addEventListener('keydown', e => e.key === 'Enter' && runCommand());
  document.addEventListener('keydown', onGlobalKey);
});

function onGlobalKey(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runCommand(); return; }
  if ((e.ctrlKey || e.metaKey) && e.key === 'l')     { e.preventDefault(); clearTerminal(); return; }
  if (e.key === 'Escape') { closeModal(); return; }
  if (!e.ctrlKey && !e.metaKey && !e.altKey && !isInput(e.target)) {
    const tabs = ['dashboard','recon','vulns','terminal'];
    const idx  = parseInt(e.key) - 1;
    if (idx >= 0 && idx < tabs.length) switchTab(tabs[idx]);
  }
}
function isInput(el) { return ['INPUT','TEXTAREA','SELECT'].includes(el.tagName); }

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t  => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  const t = $('tab-' + name), p = $('panel-' + name);
  if (!t || !p) return;
  t.classList.add('active');
  p.classList.add('active');
  if (name === 'recon'   && activeTarget) loadRecon(activeTarget);
  if (name === 'vulns'   && activeTarget) loadVulns(activeTarget);
  if (name === 'dashboard' && activeTarget) loadDashboard(activeTarget);
  if (name === 'recon' || name === 'vulns') {
    const dot = $('dot-' + name);
    if (dot) dot.classList.remove('show');
  }
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
      <div class="e-msg" style="font-size:11px">Add your first target</div>
    </div>`;
    return;
  }
  el.innerHTML = targets.map(t => {
    const total   = t.critical + t.high + t.medium + t.low;
    const active  = activeTarget === t.target;
    const cls     = t.scanning ? 'scanning' : t.critical > 0 ? 'has-crits' : t.high > 0 ? 'has-highs' : '';
    const barW    = (n, tot) => tot ? Math.max(3, Math.round(n/tot*80)) : 0;
    const scanLbl = t.scanning ? '⏳ Scanning' : '▶ Scan';
    return `
    <div class="target-item ${cls} ${active?'active':''}" onclick="selectTarget('${esc(t.target)}')">
      <div class="ti-top">
        <div class="ti-dot"></div>
        <div class="ti-name" title="${esc(t.target)}">${esc(t.target)}</div>
        <button class="ti-scan" onclick="scanTarget(event,'${esc(t.target)}')">${scanLbl}</button>
        <button class="ti-del"  onclick="deleteTarget(event,'${esc(t.target)}')" title="Remove">✕</button>
      </div>
      ${total > 0 ? `
      <div class="ti-bars">
        ${t.critical ? `<div class="sev-pip pip-c" style="width:${barW(t.critical,total)}px"></div>` : ''}
        ${t.high     ? `<div class="sev-pip pip-h" style="width:${barW(t.high,total)}px"></div>` : ''}
        ${t.medium   ? `<div class="sev-pip pip-m" style="width:${barW(t.medium,total)}px"></div>` : ''}
        ${t.low      ? `<div class="sev-pip pip-l" style="width:${barW(t.low,total)}px"></div>` : ''}
        <span class="ti-total">${total}</span>
      </div>` : `
      <div class="ti-stats">
        <span class="ti-stat">${t.subdomains} subs · ${t.live_hosts} live · ${t.urls} urls</span>
      </div>`}
    </div>`;
  }).join('');
}

function addTarget() {
  const inp = $('newTarget');
  const val = inp.value.trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0];
  if (!val) return;
  inp.value = '';
  selectTarget(val);
  toast(`Added ${val}`, 'green');
}

async function deleteTarget(e, target) {
  e.stopPropagation();
  if (!confirm(`Remove ${target}?`)) return;
  await api(`/api/targets/${encodeURIComponent(target)}`, 'DELETE');
  if (activeTarget === target) { activeTarget = null; allVulns = []; renderVulns(); }
  loadTargets();
  toast(`Removed ${target}`);
}

function selectTarget(target) {
  activeTarget = target;
  $('cmdTarget').value = target;
  loadTargets();
  const tab = document.querySelector('.tab.active')?.id?.replace('tab-','');
  if (tab === 'dashboard') loadDashboard(target);
  if (tab === 'recon')     loadRecon(target);
  if (tab === 'vulns')     loadVulns(target);
}

function scanTarget(e, target) {
  e.stopPropagation();
  selectTarget(target);
  startScan(target, 'full');
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function startScan(target, mode = 'full') {
  if (runningJob) { toast('Scan already running…', 'yellow'); return; }
  if (eventSource) { eventSource.close(); eventSource = null; }

  switchTab('terminal');
  $('runBtn').disabled = true;
  $('cursor').style.display = 'inline-block';
  $('termTitle').textContent = `Scanning ${target} [${mode}]`;
  startProgress();

  appendLine('', 'dim');
  appendLine(`▶  /scan ${target} --mode ${mode}`, 'cmd');

  try {
    const { job_id } = await api('/api/scan', 'POST', { target, mode });
    runningJob = job_id;
    listenJob(job_id, target);
  } catch(e) {
    appendLine(`Error: ${e.message}`, 'error');
    onJobDone();
  }
}

// ── Terminal commands ─────────────────────────────────────────────────────────
function onCmdChange() {
  const cmd = $('cmdSelect').value;
  $('vcSelect').style.display   = cmd === '/hunt'      ? 'block' : 'none';
  $('modeSelect').style.display = cmd === '/autopilot' ? 'block' : 'none';
}

async function runCommand() {
  const target  = $('cmdTarget').value.trim();
  const command = $('cmdSelect').value;
  const needsTarget = !['/validate','/triage','/chain'].includes(command);
  if (!target && needsTarget) { toast('Enter a target first', 'red'); $('cmdTarget').focus(); return; }

  const flags = {};
  if (command === '/hunt'      && $('vcSelect').value)   flags['vuln-class'] = $('vcSelect').value;
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

  document.querySelectorAll('.qcmd').forEach(b => {
    b.classList.toggle('active', b.textContent.trim() === command);
  });

  appendLine('', 'dim');
  appendLine(`▶  ${command}${target ? ' ' + target : ''}`, 'cmd');

  try {
    const { job_id } = await api('/api/run', 'POST', { command, target, flags });
    runningJob = job_id;
    listenJob(job_id, target);
  } catch(e) {
    appendLine(`Error: ${e.message}`, 'error');
    onJobDone();
  }
}

function listenJob(jobId, target) {
  eventSource = new EventSource(`/api/stream/${jobId}`);
  eventSource.onmessage = e => {
    const d = JSON.parse(e.data);
    if (d.type === 'done') {
      appendLine('── Scan complete ──', 'done');
      onJobDone();
      loadTargets();
      if (target || activeTarget) {
        const t = target || activeTarget;
        loadRecon(t);
        loadVulns(t).then(() => {
          if (allVulns.length > 0) {
            $('dot-vulns')?.classList.add('show');
            toast(`Found ${allVulns.length} vulnerabilities`, 'green');
          }
          $('dot-recon')?.classList.add('show');
        });
        if (document.querySelector('.tab.active')?.id === 'tab-dashboard') loadDashboard(t);
      }
      return;
    }
    if (d.type === 'error') { appendLine(d.line || 'Stream error', 'error'); onJobDone(); return; }
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
  body.scrollTop = body.scrollHeight;
}

function classify(line) {
  const l = line.toLowerCase();
  if (l.includes('[phase]'))                                       return 'phase';
  if (l.startsWith('▶') || l.startsWith('$'))                     return 'cmd';
  if (l.startsWith('─') || l.startsWith('═'))                     return 'sep';
  if (l.includes('[finding]'))                                     return 'finding';
  if (l.includes('[+]'))                                           return 'success';
  if (l.includes('[!]') || l.includes('warn'))                     return 'warn';
  if (l.includes('[-]') || l.includes('error') || l.includes('✗')) return 'error';
  if (l.includes('  >') || l.includes('[*]'))                      return 'info';
  if (l.includes('✓') || l.includes('done'))                       return 'done';
  if (!l.trim())                                                    return 'dim';
  return 'out';
}

function clearTerminal() { $('termBody').innerHTML = ''; toast('Terminal cleared'); }
function copyTerminal() {
  const lines = [...document.querySelectorAll('#termBody .t-txt')].map(x => x.textContent).join('\n');
  navigator.clipboard.writeText(lines).then(() => toast('Copied', 'green'));
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard(target) {
  if (!target) return;
  try {
    const [vulns, reconData] = await Promise.all([
      api(`/api/vulns/${encodeURIComponent(target)}`),
      api(`/api/recon/${encodeURIComponent(target)}`),
    ]);
    renderDashboard(vulns, reconData);
  } catch(e) { console.error(e); }
}

function renderDashboard(vulns, recon) {
  const sev = { critical:0, high:0, medium:0, low:0, info:0 };
  vulns.forEach(f => { const s = (f.severity||'info').toLowerCase(); sev[s] = (sev[s]||0)+1; });
  const total = vulns.length;
  const pct   = n => total ? Math.round(n/total*100) : 0;

  $('dashContent').innerHTML = `
    <div class="dash-summary">
      ${sc('Total Findings', total, '')}
      ${sc('Critical', sev.critical, 'red')}
      ${sc('High',     sev.high,     'orange')}
      ${sc('Medium',   sev.medium,   'yellow')}
      ${sc('Low',      sev.low,      'blue')}
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

    <div>
      <div class="sev-bar-title" style="margin-bottom:8px">Recon Coverage</div>
      <div class="dash-recon-mini">
        <div class="drm-card" onclick="switchTab('recon')">
          <div class="drm-val">${(recon.subdomains||[]).length}</div>
          <div class="drm-label">Subdomains</div>
        </div>
        <div class="drm-card" onclick="switchTab('recon')">
          <div class="drm-val">${(recon.live_hosts||[]).length}</div>
          <div class="drm-label">Live Hosts</div>
        </div>
        <div class="drm-card" onclick="switchTab('recon')">
          <div class="drm-val">${(recon.urls||[]).length}</div>
          <div class="drm-label">URLs</div>
        </div>
        <div class="drm-card" onclick="switchTab('recon')">
          <div class="drm-val">${(recon.nuclei||[]).length}</div>
          <div class="drm-label">Nuclei Hits</div>
        </div>
      </div>
    </div>
  `;
}

function sc(label, value, color) {
  return `<div class="stat-card">
    <div class="sc-label">${label}</div>
    <div class="sc-val ${color}">${value}</div>
  </div>`;
}

// ── Recon ─────────────────────────────────────────────────────────────────────
async function loadRecon(target) {
  if (!target) return;
  const el = $('reconContent');
  el.innerHTML = `<div class="empty" style="flex:1"><div class="e-icon">⏳</div><div class="e-msg">Loading recon data…</div></div>`;
  try {
    const data = await api(`/api/recon/${encodeURIComponent(target)}`);
    renderRecon(data);
  } catch(e) {
    el.innerHTML = `<div class="empty" style="flex:1"><div class="e-msg">Failed to load recon data</div></div>`;
  }
}

function renderRecon(data) {
  const subs  = data.subdomains  || [];
  const hosts = data.live_hosts  || [];
  const urls  = data.urls        || [];
  const nucs  = data.nuclei      || [];

  const el = $('reconContent');
  if (!subs.length && !hosts.length && !urls.length && !nucs.length) {
    el.innerHTML = `<div class="empty" style="flex:1">
      <div class="e-icon">🔍</div>
      <div class="e-msg">No recon data yet — click Scan to start</div>
    </div>`;
    return;
  }

  el.innerHTML = `
    <!-- Subdomains -->
    ${subs.length ? `
    <div class="recon-section">
      <div class="rs-head">
        <div class="rs-title">Subdomains <span class="rs-count">${subs.length}</span></div>
        <input class="rs-search" placeholder="Filter subdomains…" oninput="filterSubdomains(this.value)" id="subSearch"/>
      </div>
      <div class="rs-body">
        <table class="recon-table" id="subTable">
          <thead><tr><th>#</th><th>Subdomain</th></tr></thead>
          <tbody id="subTbody">${subs.map((s,i) => `
            <tr><td class="mono" style="color:var(--text3);width:40px">${i+1}</td>
            <td class="mono">${esc(s)}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- Live Hosts -->
    ${hosts.length ? `
    <div class="recon-section">
      <div class="rs-head">
        <div class="rs-title">Live Hosts <span class="rs-count">${hosts.length}</span></div>
        <input class="rs-search" placeholder="Filter hosts…" oninput="filterHosts(this.value)"/>
      </div>
      <div class="rs-body" id="hostsBody">
        <table class="recon-table" id="hostTable">
          <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
          <tbody id="hostTbody">${hosts.map(h => `
            <tr>
              <td class="url">${esc(typeof h === 'string' ? h : (h.url || h))}</td>
              <td>${statusBadge(typeof h === 'object' ? h.status : '')}</td>
              <td style="font-size:11px;color:var(--text2)">${esc(typeof h === 'object' ? (h.title||'') : '')}</td>
              <td>${typeof h === 'object' && h.tech?.length ? h.tech.map(t => `<span class="tech-badge">${esc(t)}</span>`).join('') : ''}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- Nuclei Findings -->
    ${nucs.length ? `
    <div class="recon-section">
      <div class="rs-head">
        <div class="rs-title">Nuclei Findings <span class="rs-count">${nucs.length}</span></div>
      </div>
      <div class="rs-body">
        <table class="recon-table">
          <thead><tr><th>Severity</th><th>Template</th><th>Host</th><th>Info</th></tr></thead>
          <tbody>${nucs.map(n => {
            const sev = (n.severity||'info').toLowerCase();
            return `<tr>
              <td><span class="nuclei-sev b-${sev}">${sev}</span></td>
              <td class="mono" style="color:var(--text)">${esc(n.name||n.template_id||'?')}</td>
              <td class="url">${esc(truncate(n.host||n.url||'',60))}</td>
              <td style="font-size:11px;color:var(--text3)">${esc(n.info||n.matcher_name||'')}</td>
            </tr>`;
          }).join('')}
          </tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- URLs -->
    ${urls.length ? `
    <div class="recon-section">
      <div class="rs-head">
        <div class="rs-title">Discovered URLs <span class="rs-count">${urls.length}</span></div>
        <input class="rs-search" placeholder="Filter URLs…" oninput="filterUrls(this.value)"/>
      </div>
      <div class="rs-body" style="max-height:350px">
        <ul class="url-list" id="urlList">${urls.map(u => renderUrlItem(u)).join('')}</ul>
      </div>
    </div>` : ''}
  `;

  // Store raw data for filtering
  window._reconSubs  = subs;
  window._reconHosts = hosts;
  window._reconUrls  = urls;
}

function renderUrlItem(u) {
  const str = typeof u === 'string' ? u : (u.url || String(u));
  const [base, qs] = str.split('?');
  const params = qs ? `?<span class="url-param">${esc(qs)}</span>` : '';
  return `<li class="url-item"><span class="url-path">${esc(base)}${params}</span></li>`;
}

function statusBadge(code) {
  if (!code) return `<span class="status-badge s-unk">—</span>`;
  const n = parseInt(code);
  const cls = n >= 500 ? 's-5xx' : n >= 400 ? 's-4xx' : n >= 300 ? 's-3xx' : n >= 200 ? 's-2xx' : 's-unk';
  return `<span class="status-badge ${cls}">${code}</span>`;
}

function filterSubdomains(q) {
  const subs = window._reconSubs || [];
  const filtered = q ? subs.filter(s => s.toLowerCase().includes(q.toLowerCase())) : subs;
  const tbody = $('subTbody');
  if (!tbody) return;
  tbody.innerHTML = filtered.map((s,i) => `
    <tr><td class="mono" style="color:var(--text3);width:40px">${i+1}</td>
    <td class="mono">${esc(s)}</td></tr>`).join('');
}

function filterHosts(q) {
  const hosts = window._reconHosts || [];
  const filtered = q ? hosts.filter(h => {
    const str = typeof h === 'string' ? h : JSON.stringify(h);
    return str.toLowerCase().includes(q.toLowerCase());
  }) : hosts;
  const tbody = $('hostTbody');
  if (!tbody) return;
  tbody.innerHTML = filtered.map(h => `
    <tr>
      <td class="url">${esc(typeof h === 'string' ? h : (h.url || h))}</td>
      <td>${statusBadge(typeof h === 'object' ? h.status : '')}</td>
      <td style="font-size:11px;color:var(--text2)">${esc(typeof h === 'object' ? (h.title||'') : '')}</td>
      <td>${typeof h === 'object' && h.tech?.length ? h.tech.map(t => `<span class="tech-badge">${esc(t)}</span>`).join('') : ''}</td>
    </tr>`).join('');
}

function filterUrls(q) {
  const urls = window._reconUrls || [];
  const filtered = q ? urls.filter(u => {
    const str = typeof u === 'string' ? u : (u.url || String(u));
    return str.toLowerCase().includes(q.toLowerCase());
  }) : urls;
  const el = $('urlList');
  if (!el) return;
  el.innerHTML = filtered.map(u => renderUrlItem(u)).join('');
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────
async function loadVulns(target) {
  if (!target) return;
  try {
    allVulns = await api(`/api/vulns/${encodeURIComponent(target)}`);
    renderVulns();
  } catch(_) { allVulns = []; renderVulns(); }
}

function filterSev(sev) {
  activeFilter = sev;
  document.querySelectorAll('.sev-filters .f-btn').forEach(b => b.classList.remove('active'));
  $('f-' + sev)?.classList.add('active');
  renderVulns();
}

function renderVulns() {
  const q   = ($('vulnSearch')?.value || '').toLowerCase();
  const SEV = { critical:4, high:3, medium:2, low:1, info:0 };

  let list = allVulns
    .filter(f => activeFilter === 'all' || (f.severity||'').toLowerCase() === activeFilter)
    .filter(f => !q || JSON.stringify(f).toLowerCase().includes(q));

  list.sort((a,b) => {
    const as = SEV[(a.severity||'info').toLowerCase()] || 0;
    const bs = SEV[(b.severity||'info').toLowerCase()] || 0;
    return bs - as;
  });

  $('vulnCount').textContent = `${list.length} finding${list.length!==1?'s':''}`;

  const el = $('vulnsList');
  if (!list.length) {
    el.innerHTML = `<div class="empty" style="flex:1">
      <div class="e-icon">🎯</div>
      <div class="e-msg">${allVulns.length ? 'No matches for current filter' : 'No findings yet — run a scan first'}</div>
    </div>`;
    return;
  }

  el.innerHTML = list.map(f => renderVulnCard(f)).join('');
}

function renderVulnCard(f) {
  const sev   = (f.severity||'info').toLowerCase();
  const steps = Array.isArray(f.steps) ? f.steps : [];
  const id    = esc(f.id || '');

  return `
  <div class="vuln-card sev-${sev}" id="vc-${id}">
    <div class="vc-header" onclick="toggleCard('${id}')">
      <span class="badge b-${sev}">${sev}</span>
      <span class="vc-title">${esc(f.title || f.vuln_class || 'Unknown')}</span>
      ${f.vuln_class ? `<span class="vc-class">${esc(f.vuln_class)}</span>` : ''}
      ${f.source     ? `<span class="vc-source">${esc(f.source)}</span>` : ''}
      <button class="vc-toggle">▶</button>
    </div>
    ${f.url ? `<div class="vc-url">${esc(f.url)}</div>` : ''}
    <div class="vc-body">

      ${f.description ? `
      <div class="vc-section">
        <div class="vc-section-title">Description</div>
        <p>${esc(f.description)}</p>
      </div>` : ''}

      ${steps.length ? `
      <div class="vc-section">
        <div class="vc-section-title">Steps to Reproduce</div>
        <ol class="vc-steps">${steps.map((s,i) => `
          <li><span class="step-num">${i+1}</span><span>${esc(s)}</span></li>`).join('')}
        </ol>
      </div>` : ''}

      ${f.poc ? `
      <div class="vc-section">
        <div class="vc-section-title">Proof of Concept</div>
        <div class="vc-poc"><pre>${esc(f.poc)}</pre></div>
      </div>` : ''}

      ${f.remediation ? `
      <div class="vc-section">
        <div class="vc-section-title">Remediation</div>
        <div class="vc-remediation">${esc(f.remediation)}</div>
      </div>` : ''}

    </div>
    <div class="vc-footer">
      ${f.cvss ? `<div class="vc-footer-item"><span class="vc-footer-label">CVSS:</span><span class="vc-footer-val">${esc(f.cvss)}</span></div>` : ''}
      ${f.gate_score != null ? `<div class="vc-footer-item"><span class="vc-footer-label">Gate:</span><span class="vc-footer-val">${f.gate_score}/11</span></div>` : ''}
      ${f.ts ? `<div class="vc-footer-item"><span class="vc-footer-label">Found:</span><span class="vc-footer-val">${esc(f.ts.slice(0,16))}</span></div>` : ''}
      <div style="flex:1"></div>
      <button class="btn btn-sm" onclick="copyVulnJson('${id}')">📋 Copy JSON</button>
    </div>
  </div>`;
}

function toggleCard(id) {
  const card = document.getElementById('vc-' + id);
  if (card) card.classList.toggle('expanded');
}

function copyVulnJson(id) {
  const f = allVulns.find(x => x.id === id || String(x.id) === id);
  if (!f) return;
  navigator.clipboard.writeText(JSON.stringify(f, null, 2))
    .then(() => toast('Copied JSON', 'green'));
}

function exportVulns(format) {
  if (!allVulns.length) { toast('No findings to export', 'yellow'); return; }
  let content, mime, ext;
  if (format === 'json') {
    content = JSON.stringify(allVulns, null, 2);
    mime = 'application/json'; ext = 'json';
  } else {
    const headers = ['id','severity','vuln_class','title','url','cvss','gate_score','source','ts'];
    const rows    = allVulns.map(f => headers.map(h => `"${(f[h]||'').toString().replace(/"/g,'""')}"`).join(','));
    content = [headers.join(','), ...rows].join('\n');
    mime = 'text/csv'; ext = 'csv';
  }
  const blob = new Blob([content], { type: mime });
  const a    = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob),
    download: `vulns_${activeTarget||'export'}.${ext}`
  });
  a.click();
  toast(`Exported ${allVulns.length} findings as ${ext.toUpperCase()}`, 'green');
}

// ── Modal (fallback detail view) ──────────────────────────────────────────────
function closeModal(e) {
  if (e && e.target !== $('modal-overlay')) return;
  $('modal-overlay').classList.remove('open');
  selectedVuln = null;
}
function copyFinding() {
  if (!selectedVuln) return;
  navigator.clipboard.writeText(JSON.stringify(selectedVuln, null, 2))
    .then(() => toast('Copied JSON', 'green'));
}

// ── Progress ──────────────────────────────────────────────────────────────────
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
  const el   = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('show')));
  setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 3000);
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
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escHtml(s) { return esc(s); }
function truncate(s, n) { return String(s).length > n ? String(s).slice(0,n) + '…' : String(s); }
