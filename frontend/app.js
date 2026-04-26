const API = '/api';

// ── Utilities ──────────────────────────────────────────────────────────────

async function apiFetch(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  if (res.status === 204) return null;
  return res.json();
}

function toast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `fixed bottom-6 right-6 text-white text-sm px-4 py-3 rounded-xl shadow-xl z-50 max-w-sm ${
    isError ? 'bg-red-700' : 'bg-slate-700'
  }`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 3500);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

function fmtDuration(start, end) {
  if (!start || !end) return '—';
  const s = Math.round((new Date(end) - new Date(start)) / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function badge(text, cls) {
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}">${text}</span>`;
}

function severityBadge(sev) {
  const map = {
    critical: 'severity-critical',
    high: 'severity-high',
    medium: 'severity-medium',
    low: 'severity-low',
  };
  return badge(sev, map[sev] || 'bg-slate-700 text-slate-300');
}

function statusBadge(status) {
  const map = {
    pending: 'status-pending',
    running: 'status-running',
    completed: 'status-completed',
    failed: 'status-failed',
  };
  const icon = status === 'running'
    ? `<svg class="w-3 h-3 spinner inline mr-1" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>`
    : '';
  return badge(icon + status, map[status] || 'bg-slate-700 text-slate-300');
}

// ── Tab routing ────────────────────────────────────────────────────────────

const TABS = ['repos', 'scans'];

function switchTab(name) {
  TABS.forEach(t => {
    document.getElementById(`pane-${t}`).classList.add('hidden');
    document.getElementById(`tab-${t}`).classList.remove('tab-active');
  });
  document.getElementById(`pane-${name}`).classList.remove('hidden');
  document.getElementById(`tab-${name}`).classList.add('tab-active');
  if (name === 'repos') loadRepos();
  if (name === 'scans') loadScans();
}

// ── Stats ──────────────────────────────────────────────────────────────────

async function loadStats() {
  try {
    const s = await apiFetch('/findings/stats');
    document.getElementById('stat-repos').textContent = `${s.total_repos} repo${s.total_repos !== 1 ? 's' : ''}`;
    document.getElementById('stat-scans').textContent = `${s.total_scans} scan${s.total_scans !== 1 ? 's' : ''}`;
    document.getElementById('stat-findings').textContent = `${s.total_findings} finding${s.total_findings !== 1 ? 's' : ''}`;
    document.getElementById('cnt-critical').textContent = s.critical_findings;
    document.getElementById('cnt-high').textContent = s.high_findings;
    document.getElementById('cnt-medium').textContent = s.medium_findings;
    document.getElementById('cnt-low').textContent = s.low_findings;
    if (s.total_findings > 0) {
      document.getElementById('stats-bar').classList.remove('hidden');
      document.getElementById('stats-bar').classList.add('flex');
    }
  } catch (e) {
    // silently ignore stats errors
  }
}

// ── Repos ──────────────────────────────────────────────────────────────────

async function loadRepos() {
  document.getElementById('repos-loading').classList.remove('hidden');
  document.getElementById('repos-table').classList.add('hidden');
  document.getElementById('repos-empty').classList.add('hidden');

  try {
    const repos = await apiFetch('/repos/');
    document.getElementById('repos-loading').classList.add('hidden');
    if (repos.length === 0) {
      document.getElementById('repos-empty').classList.remove('hidden');
      return;
    }
    document.getElementById('repos-table').classList.remove('hidden');
    const tbody = document.getElementById('repos-tbody');
    tbody.innerHTML = repos.map(r => `
      <tr class="border-b border-slate-800 hover:bg-slate-800/40 transition-colors" id="repo-row-${r.id}">
        <td class="py-3 pr-4 font-medium text-white">${esc(r.name)}</td>
        <td class="py-3 pr-4 max-w-xs truncate">
          ${r.remote_url
            ? `<a href="${esc(r.remote_url)}" target="_blank" class="text-sky-400 hover:underline text-xs mono">${esc(r.remote_url.replace('https://github.com/', ''))}</a>`
            : `<span class="text-slate-400 mono text-xs" title="${esc(r.path)}">${esc(r.path)}</span>`}
        </td>
        <td class="py-3 pr-4">
          <button onclick="toggleMonitor(${r.id}, ${r.monitor_enabled})"
            class="text-xs px-2 py-0.5 rounded border transition-colors ${r.monitor_enabled
              ? 'border-green-600 text-green-400 hover:bg-red-900 hover:border-red-600 hover:text-red-400'
              : 'border-slate-600 text-slate-500 hover:border-sky-500 hover:text-sky-400'}">
            ${r.monitor_enabled ? `● every ${r.monitor_interval_minutes}m` : 'off'}
          </button>
        </td>
        <td class="py-3 pr-4 mono text-slate-400 text-xs">
          ${r.last_scanned_commit ? r.last_scanned_commit.slice(0, 8) : '—'}
        </td>
        <td class="py-3 pr-4 text-slate-500 text-xs">${fmtDate(r.created_at)}</td>
        <td class="py-3 pr-4">
          <input id="branch-${r.id}" type="text" placeholder="HEAD" title="Branch name or 'all'"
            class="w-24 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300 px-2 py-1 mono focus:outline-none focus:border-sky-500" />
        </td>
        <td class="py-3 pr-4">
          <select id="depth-${r.id}" class="bg-slate-900 border border-slate-700 rounded text-xs text-slate-300 px-2 py-1 focus:outline-none focus:border-sky-500">
            <option value="latest">Latest commit</option>
            <option value="incremental">Since last scan</option>
            <option value="10">Last 10 commits</option>
            <option value="50">Last 50 commits</option>
            <option value="all">All commits</option>
          </select>
        </td>
        <td class="py-3">
          <div class="flex gap-2">
            <button onclick="triggerScan(${r.id})"
              class="text-xs bg-sky-700 hover:bg-sky-600 text-white px-3 py-1 rounded transition-colors">
              Scan now
            </button>
            <button onclick="deleteRepo(${r.id}, '${esc(r.name)}')"
              class="text-xs bg-slate-700 hover:bg-red-700 text-slate-300 hover:text-white px-3 py-1 rounded transition-colors">
              Delete
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    document.getElementById('repos-loading').classList.add('hidden');
    toast('Failed to load repositories: ' + e.message, true);
  }
}

function _isUrl(s) {
  return /^(https?:\/\/|git@|ssh:\/\/)/.test(s);
}

function _deriveName(source) {
  return source.replace(/\.git$/, '').split(/[/\\]/).filter(Boolean).pop() || source;
}

async function submitAddRepo() {
  const source = document.getElementById('repo-source').value.trim();
  const errEl  = document.getElementById('add-repo-error');

  if (!source) {
    errEl.textContent = 'Paste a local path or GitHub URL.';
    errEl.classList.remove('hidden');
    return;
  }
  errEl.classList.add('hidden');

  const name = _deriveName(source);
  const body = _isUrl(source)
    ? { name, remote_url: source }
    : { name, path: source };

  try {
    await apiFetch('/repos/', { method: 'POST', body: JSON.stringify(body) });
    document.getElementById('repo-source').value = '';
    toast(`Added "${name}".`);
    loadRepos();
    loadStats();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  }
}

async function triggerScan(repoId) {
  const depth  = document.getElementById(`depth-${repoId}`)?.value || 'latest';
  const branch = document.getElementById(`branch-${repoId}`)?.value.trim() || '';
  let qs = `?depth=${depth}`;
  if (branch) qs += `&branch=${encodeURIComponent(branch)}`;
  try {
    const { scan_id } = await apiFetch(`/repos/${repoId}/scan${qs}`, { method: 'POST' });
    toast(`Scan #${scan_id} started.`);
    setTimeout(() => switchTab('scans'), 800);
    loadStats();
  } catch (e) {
    toast('Failed to start scan: ' + e.message, true);
  }
}

async function toggleMonitor(repoId, currentlyEnabled) {
  try {
    await apiFetch(`/repos/${repoId}`, {
      method: 'PATCH',
      body: JSON.stringify({ monitor_enabled: !currentlyEnabled }),
    });
    loadRepos();
  } catch (e) {
    toast('Failed to update monitor: ' + e.message, true);
  }
}

async function deleteRepo(repoId, name) {
  if (!confirm(`Delete repository "${name}"? All scans and findings will be removed.`)) return;
  try {
    await apiFetch(`/repos/${repoId}`, { method: 'DELETE' });
    toast(`Deleted "${name}".`);
    loadRepos();
    loadStats();
  } catch (e) {
    toast('Failed to delete: ' + e.message, true);
  }
}

// ── Scans ──────────────────────────────────────────────────────────────────

async function loadScans() {
  document.getElementById('scans-loading').classList.remove('hidden');
  document.getElementById('scans-table').classList.add('hidden');
  document.getElementById('scans-empty').classList.add('hidden');

  try {
    const scans = await apiFetch('/scans/');
    document.getElementById('scans-loading').classList.add('hidden');
    if (scans.length === 0) {
      document.getElementById('scans-empty').classList.remove('hidden');
      return;
    }
    document.getElementById('scans-table').classList.remove('hidden');
    const tbody = document.getElementById('scans-tbody');
    tbody.innerHTML = scans.map(s => `
      <tr class="border-b border-slate-800 hover:bg-slate-800/40 transition-colors cursor-pointer"
          onclick="viewScanFindings(${s.id}, '${esc(s.repo_name || '')}')">
        <td class="py-3 pr-4 text-slate-400">#${s.id}</td>
        <td class="py-3 pr-4 font-medium">${esc(s.repo_name || '—')}</td>
        <td class="py-3 pr-4">${statusBadge(s.status)}</td>
        <td class="py-3 pr-4 text-slate-400">${s.commits_scanned}</td>
        <td class="py-3 pr-4">
          ${s.findings_count > 0
            ? `<span class="text-orange-400 font-semibold">${s.findings_count}</span>`
            : `<span class="text-slate-500">0</span>`}
        </td>
        <td class="py-3 pr-4 text-slate-500 text-xs">${fmtDate(s.started_at || s.created_at)}</td>
        <td class="py-3 text-slate-500 text-xs">${fmtDuration(s.started_at, s.completed_at)}</td>
      </tr>
      ${s.error_message ? `
      <tr class="border-b border-slate-800">
        <td colspan="7" class="pb-3 pr-4">
          <span class="text-red-400 text-xs mono">${esc(s.error_message)}</span>
        </td>
      </tr>` : ''}
    `).join('');
  } catch (e) {
    document.getElementById('scans-loading').classList.add('hidden');
    toast('Failed to load scans: ' + e.message, true);
  }
}

// ── Findings slide-over panel ──────────────────────────────────────────────

let _panelScanId = null;

function viewScanFindings(scanId, repoName) {
  _panelScanId = scanId;
  document.getElementById('panel-title').textContent = `Scan #${scanId}${repoName ? ' · ' + repoName : ''}`;
  document.getElementById('panel-subtitle').textContent = '';
  document.getElementById('panel-show-resolved').checked = false;
  const panel = document.getElementById('findings-panel');
  const inner = document.getElementById('findings-panel-inner');
  panel.classList.remove('hidden');
  requestAnimationFrame(() => { inner.style.transform = 'translateX(0)'; });
  loadPanelFindings();
}

function closeFindingsPanel() {
  const inner = document.getElementById('findings-panel-inner');
  inner.style.transform = 'translateX(100%)';
  setTimeout(() => document.getElementById('findings-panel').classList.add('hidden'), 210);
  _panelScanId = null;
}

function reloadPanel() {
  if (_panelScanId) loadPanelFindings();
}

async function loadPanelFindings() {
  document.getElementById('panel-loading').classList.remove('hidden');
  document.getElementById('panel-findings-list').innerHTML = '';
  document.getElementById('panel-empty').classList.add('hidden');

  const showResolved = document.getElementById('panel-show-resolved').checked;
  try {
    const findings = await apiFetch(`/scans/${_panelScanId}/findings?show_resolved=${showResolved}`);
    document.getElementById('panel-loading').classList.add('hidden');
    if (findings.length === 0) {
      document.getElementById('panel-empty').classList.remove('hidden');
      return;
    }
    document.getElementById('panel-findings-list').innerHTML = findings.map(f => renderFinding(f)).join('');
  } catch (e) {
    document.getElementById('panel-loading').classList.add('hidden');
    toast('Failed to load findings: ' + e.message, true);
  }
}

async function resolveFinding(findingId) {
  try {
    const updated = await apiFetch(`/findings/${findingId}/resolve`, { method: 'PATCH' });
    toast(updated.resolved ? 'Marked as resolved.' : 'Reopened.');
    loadPanelFindings();
    loadStats();
  } catch (e) {
    toast('Failed: ' + e.message, true);
  }
}

function renderFinding(f) {
  const resolveLabel = f.resolved ? 'Reopen' : 'Resolve';
  const resolveClass = f.resolved
    ? 'text-slate-500 hover:text-sky-400'
    : 'text-slate-400 hover:text-green-400';
  return `
    <div class="bg-slate-800 border ${f.resolved ? 'border-slate-700/50 opacity-60' : 'border-slate-700'} rounded-xl p-4 transition-colors">
      <div class="flex flex-wrap items-center gap-2 mb-2">
        ${severityBadge(f.severity)}
        <span class="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded mono">${esc(f.rule_name)}</span>
        <button onclick="resolveFinding(${f.id})" class="ml-auto text-xs ${resolveClass} transition-colors">${resolveLabel}</button>
      </div>
      <div class="text-sm text-slate-300 mb-1">
        <span class="text-slate-400">File:</span>
        <span class="mono text-sky-300">${esc(f.file_path)}</span>
        ${f.line_number ? `<span class="text-slate-500">:${f.line_number}</span>` : ''}
      </div>
      ${f.matched_value_masked ? `
      <div class="text-sm mb-1">
        <span class="text-slate-400">Matched:</span>
        <code class="bg-slate-900 text-orange-300 px-2 py-0.5 rounded mono">${esc(f.matched_value_masked)}</code>
      </div>` : ''}
      ${f.line_content_masked ? `
      <div class="mt-2 bg-slate-900 rounded-lg px-3 py-2 mono text-xs text-slate-300 overflow-x-auto whitespace-pre">${esc(f.line_content_masked)}</div>` : ''}
      <div class="mt-2 flex flex-wrap gap-3 text-xs text-slate-500">
        <span>Commit: <span class="mono text-slate-400">${f.commit_hash.slice(0, 8)}</span></span>
        ${f.author ? `<span>Author: <span class="text-slate-400">${esc(f.author)}</span></span>` : ''}
        ${f.commit_message ? `<span class="truncate max-w-xs" title="${esc(f.commit_message)}">${esc(f.commit_message.slice(0, 80))}</span>` : ''}
      </div>
    </div>`;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Boot ───────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  switchTab('repos');
  loadStats();
  // Refresh stats every 15 seconds (catches in-progress scans)
  setInterval(loadStats, 15000);
});
