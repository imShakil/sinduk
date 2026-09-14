/* ========================================================================
   Sinduk Web UI — app.js
   ======================================================================== */

const S = {
  secrets: [],
  vaults: [],
  currentVault: '',
  myVaultRole: null,
  myIdentity: null,
  filter: 'all',
  query: '',
  currentId: null,
  currentSecret: null,
  editingId: null,
  sshConnectionId: null,
  socket: null,
  backupFile: null,
  revealTimer: null,
  sshOutputPoller: null,
  envFile: null,
  theme: 'dark',
};

// ------------------------------------------------------------------
// Boot
// ------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  S.socket = io();
  bindSocketEvents();
  const res = await api('GET', '/api/auth/check');
  if (!res) return showLogin();
  if (!res.configured) return showSetup();
  if (res.authenticated) { showApp(); await loadVaults(); await loadSecrets(); }
  else showLogin();

  // Keyboard shortcuts
  document.addEventListener('keydown', handleGlobalKeydown);
});

// ------------------------------------------------------------------
// Theme
// ------------------------------------------------------------------
function initTheme() {
  let theme = localStorage.getItem('sinduk.theme') || localStorage.getItem('pacli.theme');
  if (!theme) {
    theme = globalThis.matchMedia?.('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark';
  }
  applyTheme(theme);
}

function applyTheme(theme) {
  const normalized = theme === 'light' ? 'light' : 'dark';
  const prevTheme = S.theme;
  S.theme = normalized;
  document.documentElement.dataset.theme = normalized;
  localStorage.setItem('sinduk.theme', normalized);
  updateThemeToggleButton(prevTheme !== normalized);
}

function toggleTheme() {
  applyTheme(S.theme === 'dark' ? 'light' : 'dark');
}

function updateThemeToggleButton(animateIcon = false) {
  const btn = document.getElementById('theme-toggle-btn');
  if (!btn) return;
  if (S.theme === 'dark') {
    btn.setAttribute('aria-label', 'Switch to light theme');
    btn.title = 'Switch to light theme';
  } else {
    btn.setAttribute('aria-label', 'Switch to dark theme');
    btn.title = 'Switch to dark theme';
  }
}

// Mobile menu drawer
function toggleMobileMenu() {
  const drawer = document.getElementById('mobile-drawer');
  const overlay = document.getElementById('mobile-drawer-overlay');
  if (!drawer) return;
  const isHidden = drawer.classList.contains('hidden');
  drawer.classList.toggle('hidden', !isHidden);
  overlay.classList.toggle('hidden', !isHidden);
  document.body.style.overflow = isHidden ? 'hidden' : '';
}

function closeMobileMenu() {
  const drawer = document.getElementById('mobile-drawer');
  const overlay = document.getElementById('mobile-drawer-overlay');
  if (!drawer) return;
  drawer.classList.add('hidden');
  overlay.classList.add('hidden');
  document.body.style.overflow = '';
}

// Mobile sidebar/filter sheet
function toggleMobileSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;
  sidebar.classList.toggle('mobile-open');
}

function closeMobileSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) sidebar.classList.remove('mobile-open');
}

function handleGlobalKeydown(e) {
  // Esc closes any open modal
  if (e.key === 'Escape') {
    if (!document.getElementById('view-backdrop').classList.contains('hidden')) { closeViewModal(); return; }
    if (!document.getElementById('edit-backdrop').classList.contains('hidden')) { closeEditModal(); return; }
    if (!document.getElementById('ssh-backdrop').classList.contains('hidden')) { closeSSHModal(); return; }
    if (!document.getElementById('backup-backdrop').classList.contains('hidden')) { closeBackupModal(); return; }
    if (!document.getElementById('env-backdrop').classList.contains('hidden')) { closeEnvModal(); return; }
  }
  // Ctrl/Cmd+K = search focus
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('search-input').focus();
  }
  // Ctrl/Cmd+N = add secret
  if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
    e.preventDefault();
    openAddModal();
  }
}

// ------------------------------------------------------------------
// Setup (first run)
// ------------------------------------------------------------------
function showSetup() {
  hide('login-overlay'); hide('app');
  show('setup-overlay');
  document.getElementById('setup-pw').focus();
}

async function doSetup() {
  const pw = val('setup-pw'), pw2 = val('setup-pw2');
  if (pw.length < 6) return showMsg('setup-error', 'error', 'Password must be at least 6 characters.');
  if (pw !== pw2) return showMsg('setup-error', 'error', 'Passwords do not match.');
  hide('setup-error');
  const res = await api('POST', '/api/setup/init', { password: pw, confirm: pw2 });
  if (res?.success) { hide('setup-overlay'); showApp(); await loadSecrets(); }
  else showMsg('setup-error', 'error', res?.error || 'Setup failed.');
}

// ------------------------------------------------------------------
// Login / Logout
// ------------------------------------------------------------------
function showLogin() {
  hide('setup-overlay'); hide('app');
  show('login-overlay');
  document.getElementById('login-pw').focus();
}

async function doLogin() {
  const pw = val('login-pw');
  if (!pw) return showMsg('login-error', 'error', 'Password required.');
  hide('login-error');
  const res = await api('POST', '/api/auth/login', { password: pw });
  if (res?.success) { hide('login-overlay'); showApp(); await loadSecrets(); }
  else showMsg('login-error', 'error', res?.error || 'Invalid password.');
}

async function doLogout() {
  await api('POST', '/api/auth/logout');
  hide('app'); showLogin();
  document.getElementById('login-pw').value = '';
}

function showApp() {
  show('app');
  // Show the mobile filter FAB (only visible on mobile via CSS)
  const fab = document.getElementById('mobile-sidebar-btn');
  if (fab) fab.classList.remove('hidden');
}

// ------------------------------------------------------------------
// Vaults (Phase 3)
// ------------------------------------------------------------------
async function loadVaults() {
  const res = await api('GET', '/api/vaults');
  S.vaults = res?.vaults || [];
  renderVaultSelect();
}

function renderVaultSelect() {
  const sel = document.getElementById('vault-select');
  if (!sel) return;
  sel.innerHTML = '<option value="">🔒 Personal Store</option>' +
    S.vaults.map(v => `<option value="${esc(v.name)}" ${S.currentVault === v.name ? 'selected' : ''}>🗄️ ${esc(v.name)} (${esc(v.role)})</option>`).join('');

  const badgeRow = document.getElementById('vault-badge-row');
  const roleBadge = document.getElementById('vault-role-badge');
  if (S.currentVault) {
    const current = S.vaults.find(v => v.name === S.currentVault);
    S.myVaultRole = current?.role || 'viewer';
    if (roleBadge) roleBadge.textContent = S.myVaultRole;
    badgeRow?.classList.remove('hidden');
  } else {
    S.myVaultRole = null;
    badgeRow?.classList.add('hidden');
  }
}

async function onVaultChange(vaultName) {
  S.currentVault = vaultName;
  renderVaultSelect();
  await loadSecrets();
}

// ------------------------------------------------------------------
// Secrets
// ------------------------------------------------------------------
async function loadSecrets() {
  const endpoint = S.currentVault ? `/api/vaults/${S.currentVault}/secrets` : '/api/secrets';
  const res = await api('GET', endpoint);
  S.secrets = res?.secrets || [];
  renderGrid();
  populateSSHDropdowns();
}

function renderGrid() {
  const grid = document.getElementById('secrets-grid');

  const counts = { all: S.secrets.length, password: 0, token: 0, ssh: 0 };
  S.secrets.forEach(s => { if (counts[s.type] !== undefined) counts[s.type]++; });
  Object.entries(counts).forEach(([k, v]) => {
    const el = document.getElementById('cnt-' + k);
    if (el) el.textContent = v;
  });
  document.getElementById('total-count').textContent = `${counts.all} secret${counts.all === 1 ? '' : 's'}`;

  const visible = S.secrets.filter(s => {
    const matchFilter = S.filter === 'all' || s.type === S.filter;
    const matchQuery = !S.query || s.label.toLowerCase().includes(S.query);
    return matchFilter && matchQuery;
  });

  if (!visible.length) {
    grid.innerHTML = `<div class="empty-state"><div class="es-icon">🔍</div><h3>${S.query ? 'No results found' : 'No secrets yet'}</h3><p>${S.query ? 'Try a different search.' : 'Click "+ Add Secret" to get started.'}</p></div>`;
    return;
  }

  grid.innerHTML = visible.map(s => {
    const typeIcon = { password: '🔑', token: '🪙', ssh: '🖥️' }[s.type] || '🔐';
    return `
    <div class="secret-card" onclick="openViewModal('${s.id}')">
      <div class="secret-card-top">
        <div class="secret-card-label">${esc(s.label)}</div>
        <span class="badge badge-${s.type}">${typeIcon} ${s.type}</span>
      </div>
      <div class="secret-card-meta">Updated ${s.update_date}</div>
      <div class="secret-card-actions" onclick="event.stopPropagation()">
        <button class="card-action-btn" title="Quick copy" onclick="quickCopy('${s.id}')">📋</button>
        ${s.type === 'ssh' ? `<button class="card-action-btn" title="Connect SSH" onclick="quickSSH('${s.id}')">⌨️</button>` : ''}
      </div>
    </div>
  `;
  }).join('');
}

function setFilter(f, btn) {
  S.filter = f;
  document.querySelectorAll('.filter-item').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderGrid();
}

function doSearch(q) { S.query = q.toLowerCase(); renderGrid(); }

// Quick copy from card (no modal needed)
async function quickCopy(id) {
  const res = await api('GET', `/api/secrets/${id}/reveal`);
  if (!res?.secret) return;
  let text = res.secret;
  // For SSH, copy just the connection string
  if (res.type === 'ssh' || (S.secrets.find(s => s.id === id)?.type === 'ssh')) {
    text = text.split('|')[0].replace(':', '@');
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast('📋 Copied!');
  } catch {
    showToast('❌ Clipboard denied', 'error');
  }
}

// Quick SSH connect from card
function quickSSH(id) {
  openSSHModal();
  // Switch to stored tab and pre-select
  const storedBtn = document.querySelector('[onclick*="stored"]');
  if (storedBtn) switchTab('ssh', 'stored', storedBtn);
  document.getElementById('ssh-stored-select').value = id;
}

// ------------------------------------------------------------------
// Add / Edit modal — TYPE-AWARE FORM
// ------------------------------------------------------------------
function openAddModal() {
  S.editingId = null;
  document.getElementById('edit-title').textContent = 'Add Secret';
  document.getElementById('edit-label').value = '';
  document.getElementById('edit-label').disabled = false;
  document.getElementById('edit-type').value = 'password';
  document.getElementById('edit-type').disabled = false;
  clearStrengthMeter();
  hide('edit-error');
  renderSecretTypeForm('password');
  show('edit-backdrop');
  document.getElementById('edit-label').focus();
}

function openEditFromView() {
  const s = S.secrets.find(x => x.id === S.currentId);
  if (!s) return;
  closeViewModal();
  S.editingId = s.id;
  document.getElementById('edit-title').textContent = 'Edit Secret';
  document.getElementById('edit-label').value = s.label;
  document.getElementById('edit-label').disabled = true;
  document.getElementById('edit-type').value = s.type;
  document.getElementById('edit-type').disabled = true;
  hide('edit-error');
  renderSecretTypeForm(s.type, S.currentSecret?.secret || '');
  show('edit-backdrop');
}

function closeEditModal() { hide('edit-backdrop'); }

function parsePasswordSecret(existingValue) {
  const parts = existingValue ? existingValue.split(':') : [];
  return {
    user: parts[0] || '',
    pass: parts.slice(1).join(':') || '',
  };
}

function parseSSHSecret(existingValue) {
  let user = '';
  let host = '';
  let port = '22';
  let keyPath = '';
  let opts = '';

  if (!existingValue) {
    return { user, host, port, keyPath, opts };
  }

  const parts = existingValue.split('|');
  const userHost = parts[0];
  if (userHost.includes(':')) {
    [user, host] = userHost.split(':', 2);
  }

  parts.slice(1).forEach((part) => {
    if (part.startsWith('key:')) keyPath = part.slice(4);
    else if (part.startsWith('port:')) port = part.slice(5);
    else if (part.startsWith('opts:')) opts = part.slice(5);
  });

  return { user, host, port, keyPath, opts };
}

function bindSSHPreviewListeners() {
  ['ssh-edit-user', 'ssh-edit-host', 'ssh-edit-port', 'ssh-edit-key'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', updateSSHPreview);
  });
}

function renderPasswordTypeForm(container, existingValue) {
  const { user, pass } = parsePasswordSecret(existingValue);
  container.innerHTML = `
      <div class="field">
        <label>Username</label>
        <input type="text" id="edit-username" placeholder="username" value="${esc(user)}" autocomplete="off" />
      </div>
      <div class="field">
        <label>Password</label>
        <div class="pw-input-wrap">
          <input type="password" id="edit-password" placeholder="password" value="${esc(pass)}"
            oninput="updateStrength(this.value)" autocomplete="new-password" />
          <button type="button" class="pw-toggle" onclick="togglePwVisibility('edit-password', this)">👁</button>
        </div>
        <div id="strength-bar-wrap" class="strength-wrap">
          <div id="strength-bar" class="strength-bar"></div>
        </div>
        <div id="strength-label" class="strength-label"></div>
      </div>
    `;
}

function renderTokenTypeForm(container, existingValue) {
  container.innerHTML = `
      <div class="field">
        <label>Token / API Key</label>
        <div class="pw-input-wrap">
          <textarea id="edit-token" rows="3" placeholder="Paste your token or API key here"
            oninput="updateStrength(this.value)">${esc(existingValue)}</textarea>
          <button type="button" class="pw-toggle textarea-toggle" onclick="toggleTokenVisibility()">👁</button>
        </div>
        <div id="strength-bar-wrap" class="strength-wrap">
          <div id="strength-bar" class="strength-bar"></div>
        </div>
        <div id="strength-label" class="strength-label"></div>
      </div>
    `;
}

function renderSSHTypeForm(container, existingValue) {
  const { user, host, port, keyPath, opts } = parseSSHSecret(existingValue);
  container.innerHTML = `
      <div class="ssh-form-grid">
        <div class="field">
          <label>Username</label>
          <input type="text" id="ssh-edit-user" placeholder="ubuntu" value="${esc(user)}" />
        </div>
        <div class="field">
          <label>Hostname / IP</label>
          <input type="text" id="ssh-edit-host" placeholder="192.168.1.100 or server.com" value="${esc(host)}" />
        </div>
        <div class="field">
          <label>Port</label>
          <input type="number" id="ssh-edit-port" placeholder="22" value="${esc(port)}" min="1" max="65535" />
        </div>
        <div class="field">
          <label>Key path <span class="optional-tag">optional</span></label>
          <input type="text" id="ssh-edit-key" placeholder="~/.ssh/id_rsa" value="${esc(keyPath)}" />
        </div>
      </div>
      <div class="field">
        <label>Extra SSH options <span class="optional-tag">optional</span></label>
        <input type="text" id="ssh-edit-opts" placeholder="-o StrictHostKeyChecking=no" value="${esc(opts)}" />
      </div>
      <div class="field">
        <label>Password <span class="optional-tag">optional — for password auth</span></label>
        <div class="pw-input-wrap">
          <input type="password" id="ssh-edit-password" placeholder="SSH password (leave blank for key auth)" autocomplete="new-password" />
          <button type="button" class="pw-toggle" onclick="togglePwVisibility('ssh-edit-password', this)">👁</button>
        </div>
      </div>
      <div class="ssh-edit-preview" id="ssh-preview">
        <span class="preview-label">Preview:</span>
        <code id="ssh-preview-cmd">ssh ${user ? user + '@' : ''}${host || '<host>'}${port && port !== '22' ? ' -p ' + port : ''}${keyPath ? ' -i ' + keyPath : ''}</code>
      </div>
    `;
  bindSSHPreviewListeners();
}

// Render the right input fields based on secret type
function renderSecretTypeForm(type, existingValue = '') {
  const container = document.getElementById('edit-fields-container');

  switch (type) {
    case 'password':
      renderPasswordTypeForm(container, existingValue);
      return;
    case 'token':
      renderTokenTypeForm(container, existingValue);
      return;
    case 'ssh':
      renderSSHTypeForm(container, existingValue);
      return;
    default:
      container.innerHTML = '';
  }
}

function updateSSHPreview() {
  const user = document.getElementById('ssh-edit-user')?.value || '';
  const host = document.getElementById('ssh-edit-host')?.value || '<host>';
  const port = document.getElementById('ssh-edit-port')?.value || '22';
  const key = document.getElementById('ssh-edit-key')?.value || '';
  const portPart = port && port !== '22' ? ` -p ${port}` : '';
  const keyPart = key ? ` -i ${key}` : '';
  const cmd = `ssh ${user ? user + '@' : ''}${host}${portPart}${keyPart}`;
  const el = document.getElementById('ssh-preview-cmd');
  if (el) el.textContent = cmd;
}

function onEditTypeChange() {
  const type = document.getElementById('edit-type').value;
  renderSecretTypeForm(type);
}

function togglePwVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === 'password') { input.type = 'text'; btn.textContent = '🙈'; }
  else { input.type = 'password'; btn.textContent = '👁'; }
}

function toggleTokenVisibility() {
  const ta = document.getElementById('edit-token');
  if (!ta) return;
  const btn = ta.parentElement.querySelector('.pw-toggle');
  if (ta.classList.contains('token-hidden')) {
    ta.classList.remove('token-hidden');
    if (btn) btn.textContent = '🙈';
  } else {
    ta.classList.add('token-hidden');
    if (btn) btn.textContent = '👁';
  }
}

// Password strength
function updateStrength(value) {
  const bar = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  if (!bar || !label) return;
  const score = calcStrength(value);
  const levels = [
    { cls: 'str-weak', text: 'Weak', color: '#f56565' },
    { cls: 'str-fair', text: 'Fair', color: '#f6ad55' },
    { cls: 'str-good', text: 'Good', color: '#68d391' },
    { cls: 'str-strong', text: 'Strong', color: '#3ecf8e' },
  ];
  const lvl = levels[Math.min(score, 3)];
  bar.style.width = `${(score + 1) * 25}%`;
  bar.style.background = lvl.color;
  label.textContent = value ? lvl.text : '';
  label.style.color = lvl.color;
}

function calcStrength(pw) {
  if (!pw || pw.length < 4) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(Math.floor(score * 0.75), 3);
}

function clearStrengthMeter() {
  const bar = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  if (bar) { bar.style.width = '0'; bar.style.background = ''; }
  if (label) label.textContent = '';
}

// Collect secret value from the type-specific form
function collectSecretValue(type) {
  if (type === 'password') {
    const user = document.getElementById('edit-username')?.value.trim() || '';
    const pass = document.getElementById('edit-password')?.value || '';
    if (!user || !pass) return null;
    return `${user}:${pass}`;
  } else if (type === 'token') {
    const token = document.getElementById('edit-token')?.value.trim() || '';
    return token || null;
  } else if (type === 'ssh') {
    const user = document.getElementById('ssh-edit-user')?.value.trim() || '';
    const host = document.getElementById('ssh-edit-host')?.value.trim() || '';
    const port = document.getElementById('ssh-edit-port')?.value.trim() || '22';
    const key = document.getElementById('ssh-edit-key')?.value.trim() || '';
    const opts = document.getElementById('ssh-edit-opts')?.value.trim() || '';
    if (!user || !host) return null;
    let val = `${user}:${host}`;
    if (key) val += `|key:${key}`;
    if (port && port !== '22') val += `|port:${port}`;
    if (opts) val += `|opts:${opts}`;
    return val;
  }
  return null;
}

async function saveSecret() {
  const label = document.getElementById('edit-label').value.trim();
  const type = document.getElementById('edit-type').value;
  const secret = collectSecretValue(type);

  if (!label) return showMsg('edit-error', 'error', 'Label is required.');
  if (!secret) {
    const fieldHints = { password: 'username and password', token: 'token value', ssh: 'username and hostname' };
    return showMsg('edit-error', 'error', `Please fill in ${fieldHints[type] || 'all required fields'}.`);
  }
  hide('edit-error');

  let res;
  if (S.currentVault) {
    if (S.editingId) {
      res = await api('PUT', `/api/vaults/${S.currentVault}/secrets/${S.editingId}`, { secret });
    } else {
      res = await api('POST', `/api/vaults/${S.currentVault}/secrets`, { label, type, secret });
    }
  } else if (S.editingId) {
    res = await api('PUT', `/api/secrets/${S.editingId}`, { secret });
  } else {
    res = await api('POST', '/api/secrets', { label, type, secret });
  }

  if (res?.success) { closeEditModal(); await loadSecrets(); showToast('✅ Secret saved!'); }
  else showMsg('edit-error', 'error', res?.error || 'Save failed.');
}

// ------------------------------------------------------------------
// View modal
// ------------------------------------------------------------------
async function openViewModal(id) {
  const s = S.secrets.find(x => x.id === id);
  if (!s) return;
  S.currentId = id;
  S.currentSecret = null;

  document.getElementById('view-title-text').textContent = s.label;
  document.getElementById('view-label-val').textContent = s.label;
  document.getElementById('view-type-val').innerHTML = `<span class="badge badge-${s.type}">${s.type}</span>`;
  document.getElementById('view-created-val').textContent = new Date(s.creation_time * 1000).toLocaleString();
  document.getElementById('view-updated-val').textContent = new Date(s.update_time * 1000).toLocaleString();

  // Created by row
  const createdByRow = document.getElementById('view-created-by-row');
  const createdByVal = document.getElementById('view-created-by-val');
  if (s.created_by) {
    if (createdByVal) createdByVal.textContent = s.created_by;
    createdByRow?.classList.remove('hidden');
  } else {
    createdByRow?.classList.add('hidden');
  }

  // Show SSH-specific connect button
  const sshBtn = document.getElementById('view-ssh-btn');
  if (sshBtn) sshBtn.style.display = s.type === 'ssh' ? 'inline-flex' : 'none';

  setRevealMasked();
  hide('view-msg');
  show('view-backdrop');
}

function setRevealMasked() {
  const el = document.getElementById('reveal-text');
  el.textContent = '••••••••••••••••';
  el.classList.add('masked');
  document.getElementById('reveal-toggle-btn').textContent = '👁 Show';
  clearTimeout(S.revealTimer);
}

function setRevealVisible(text, type) {
  const el = document.getElementById('reveal-text');
  // Pretty-print based on type
  if (type === 'ssh') {
    el.innerHTML = formatSSHDisplay(text);
  } else if (type === 'password') {
    const parts = text.split(':');
    if (parts.length >= 2) {
      el.innerHTML = `<span class="reveal-field-label">user:</span><span>${esc(parts[0])}</span>  <span class="reveal-field-label">pass:</span><span>${esc(parts.slice(1).join(':'))}</span>`;
    } else {
      el.textContent = text;
    }
  } else {
    el.textContent = text;
  }
  el.classList.remove('masked');
  document.getElementById('reveal-toggle-btn').textContent = '🙈 Hide';
  clearTimeout(S.revealTimer);
  S.revealTimer = setTimeout(setRevealMasked, 30000);
}

function formatSSHDisplay(raw) {
  const parts = raw.split('|');
  const userHost = parts[0];
  let html = `<span class="reveal-field-label">conn:</span><span>${esc(userHost.replace(':', '@'))}</span>`;
  parts.slice(1).forEach(p => {
    if (p.startsWith('key:')) html += `  <span class="reveal-field-label">key:</span><span>${esc(p.slice(4))}</span>`;
    else if (p.startsWith('port:')) html += `  <span class="reveal-field-label">port:</span><span>${esc(p.slice(5))}</span>`;
    else if (p.startsWith('opts:')) html += `  <span class="reveal-field-label">opts:</span><span>${esc(p.slice(5))}</span>`;
  });
  return html;
}

async function fetchSecret() {
  if (S.currentSecret) return S.currentSecret.secret;
  const endpoint = S.currentVault
    ? `/api/vaults/${S.currentVault}/secrets/${S.currentId}/reveal`
    : `/api/secrets/${S.currentId}/reveal`;
  const res = await api('GET', endpoint);
  if (res?.secret !== undefined) {
    S.currentSecret = res;
    return res.secret;
  }
  return null;
}

async function toggleReveal() {
  const el = document.getElementById('reveal-text');
  if (!el.classList.contains('masked')) { setRevealMasked(); return; }
  const text = await fetchSecret();
  if (text === null) return showMsg('view-msg', 'error', 'Failed to reveal secret.');
  const s = S.secrets.find(x => x.id === S.currentId);
  setRevealVisible(text, s?.type);
}

async function copySecret() {
  const text = await fetchSecret();
  if (text === null) return showMsg('view-msg', 'error', 'Failed to retrieve secret.');
  const s = S.secrets.find(x => x.id === S.currentId);
  let copyText = text;
  // For SSH copy the connection string (user@host)
  if (s?.type === 'ssh') copyText = text.split('|')[0].replace(':', '@');
  // For password, let user choose — default copy just password part
  if (s?.type === 'password') {
    const parts = text.split(':');
    copyText = parts.length >= 2 ? parts.slice(1).join(':') : text;
  }
  try {
    await navigator.clipboard.writeText(copyText);
    showMsg('view-msg', 'success', '📋 Copied to clipboard!');
    setTimeout(() => hide('view-msg'), 2500);
  } catch {
    showMsg('view-msg', 'error', 'Clipboard access denied.');
  }
}

// Copy full secret (for password: user:pass, for ssh: full string)
async function copyFullSecret() {
  const text = await fetchSecret();
  if (text === null) return showMsg('view-msg', 'error', 'Failed to retrieve secret.');
  try {
    await navigator.clipboard.writeText(text);
    showMsg('view-msg', 'success', '📋 Full secret copied!');
    setTimeout(() => hide('view-msg'), 2500);
  } catch {
    showMsg('view-msg', 'error', 'Clipboard access denied.');
  }
}

// Copy username specifically (for password type)
async function copyUsername() {
  const text = await fetchSecret();
  if (text === null) return;
  const s = S.secrets.find(x => x.id === S.currentId);
  if (s?.type !== 'password') return;
  const username = text.split(':')[0];
  try {
    await navigator.clipboard.writeText(username);
    showMsg('view-msg', 'success', '📋 Username copied!');
    setTimeout(() => hide('view-msg'), 2500);
  } catch { }
}

function closeViewModal() {
  hide('view-backdrop');
  setRevealMasked();
  S.currentSecret = null;
}

async function deleteSecret() {
  if (!S.currentId) return;
  const s = S.secrets.find(x => x.id === S.currentId);
  if (!confirm(`Delete "${s?.label}"? This cannot be undone.`)) return;
  const endpoint = S.currentVault
    ? `/api/vaults/${S.currentVault}/secrets/${S.currentId}`
    : `/api/secrets/${S.currentId}`;
  const res = await api('DELETE', endpoint);
  if (res?.success) { closeViewModal(); await loadSecrets(); showToast('🗑️ Deleted'); }
  else alert(res?.error || 'Delete failed.');
}

function openSSHFromView() {
  closeViewModal();
  openSSHModal();
  setTimeout(() => {
    const storedTab = document.querySelector('.tab-btn[onclick*="stored"]');
    if (storedTab) {
      switchTab('ssh', 'stored', storedTab);
      document.getElementById('ssh-stored-select').value = S.currentId || '';
    }
  }, 100);
}

// ------------------------------------------------------------------
// SSH Terminal — improved with output polling + reconnect
// ------------------------------------------------------------------
function openSSHModal() { show('ssh-backdrop'); }
function closeSSHModal() {
  if (S.sshConnectionId) {
    if (!confirm('You have an active SSH connection. Disconnect and close?')) return;
    sshDisconnect();
  }
  hide('ssh-backdrop');
}

function toggleSSHAuth() {
  const v = document.getElementById('ssh-auth').value;
  document.getElementById('ssh-pw-field').style.display = v === 'password' ? '' : 'none';
  document.getElementById('ssh-key-fields').style.display = v === 'key' ? '' : 'none';
}

function populateSSHDropdowns() {
  const sshSecrets = S.secrets.filter(s => s.type === 'ssh');

  const ks = document.getElementById('ssh-key-select');
  ks.innerHTML = '<option value="">— Choose stored key —</option>';
  sshSecrets.forEach(s => {
    const o = document.createElement('option');
    o.value = s.id; o.textContent = s.label;
    ks.appendChild(o);
  });

  const ss = document.getElementById('ssh-stored-select');
  ss.innerHTML = '<option value="">— Choose —</option>';
  sshSecrets.forEach(s => {
    const o = document.createElement('option');
    o.value = s.id; o.textContent = s.label;
    ss.appendChild(o);
  });
}

async function sshConnect(mode) {
  const errId = mode === 'manual' ? 'ssh-manual-error' : 'ssh-stored-error';
  hide(errId);
  clearSSHStatus();

  const payloadResult = mode === 'manual'
    ? await buildManualSSHPayload(errId)
    : buildStoredSSHPayload(errId);
  if (!payloadResult.ok) return;
  const payload = payloadResult.payload;

  setSSHStatus('connecting', 'Connecting…');

  if (S.socket?.connected) {
    S.socket.emit('ssh_connect', payload);
    return;
  }

  await connectSSHViaApi(errId, payload);
}

function buildStoredSSHPayload(errId) {
  const keyId = document.getElementById('ssh-stored-select').value;
  if (!keyId) {
    showMsg(errId, 'error', 'Select a stored SSH server.');
    return { ok: false, payload: null };
  }
  return { ok: true, payload: { key_id: keyId } };
}

async function buildManualSSHPayload(errId) {
  const host = val('ssh-host');
  const user = val('ssh-user');
  const port = Number.parseInt(document.getElementById('ssh-port').value, 10) || 22;
  const auth = document.getElementById('ssh-auth').value;

  if (!host || !user) {
    showMsg(errId, 'error', 'Hostname and username are required.');
    return { ok: false, payload: null };
  }

  const payload = { hostname: host, username: user, port };

  if (auth === 'password') {
    const pw = val('ssh-password');
    if (!pw) {
      showMsg(errId, 'error', 'Password is required.');
      return { ok: false, payload: null };
    }
    payload.password = pw;
    return { ok: true, payload };
  }

  const sshKey = await resolveSSHKeyFromInput(errId);
  if (!sshKey) return { ok: false, payload: null };
  payload.ssh_key = sshKey;
  return { ok: true, payload };
}

async function resolveSSHKeyFromInput(errId) {
  const keyId = document.getElementById('ssh-key-select').value;
  if (keyId) {
    const revealed = await api('GET', `/api/secrets/${keyId}/reveal`);
    if (!revealed?.secret) {
      showMsg(errId, 'error', 'Could not retrieve SSH key.');
      return null;
    }
    return revealed.secret;
  }

  const pasted = val('ssh-key-paste');
  if (!pasted) {
    showMsg(errId, 'error', 'Provide an SSH key.');
    return null;
  }
  return pasted;
}

async function connectSSHViaApi(errId, payload) {
  const r = await api('POST', '/api/ssh/connect', payload);
  if (!r?.success) {
    setSSHStatus('error', 'Failed');
    showMsg(errId, 'error', r?.error || 'Connection failed.');
    return;
  }

  S.sshConnectionId = r.connection_id;
  showSSHTerminal(`Connected: ${r.message}\n`);
  startSSHOutputPoller();
}

function setSSHStatus(state, text) {
  const el = document.getElementById('ssh-status');
  if (!el) return;
  el.className = `ssh-status ssh-status-${state}`;
  el.textContent = text;
  el.style.display = 'inline-flex';
}

function clearSSHStatus() {
  const el = document.getElementById('ssh-status');
  if (el) el.style.display = 'none';
}

function showSSHTerminal(welcomeMsg) {
  hide('ssh-connect-area');
  show('ssh-terminal-wrap');
  const cmd = document.getElementById('ssh-cmd');
  cmd.disabled = false;
  cmd.focus();
  if (welcomeMsg) appendSSH(welcomeMsg);
  setSSHStatus('connected', 'Connected');
}

function hideSSHTerminal() {
  show('ssh-connect-area');
  hide('ssh-terminal-wrap');
  document.getElementById('ssh-output').textContent = '';
  document.getElementById('ssh-cmd').disabled = true;
  document.getElementById('ssh-cmd').value = '';
  clearSSHStatus();
  stopSSHOutputPoller();
}

function appendSSH(text) {
  const out = document.getElementById('ssh-output');
  out.textContent += text;
  out.scrollTop = out.scrollHeight;
}

// Poll for output when using REST fallback
function startSSHOutputPoller() {
  stopSSHOutputPoller();
  S.sshOutputPoller = setInterval(async () => {
    if (!S.sshConnectionId) return stopSSHOutputPoller();
    const r = await api('GET', `/api/ssh/output/${S.sshConnectionId}`);
    if (r?.output) appendSSH(r.output);
    if (r?.disconnected) {
      appendSSH('\n[Connection closed]\n');
      S.sshConnectionId = null;
      stopSSHOutputPoller();
      setTimeout(hideSSHTerminal, 1500);
    }
  }, 300);
}

function stopSSHOutputPoller() {
  if (S.sshOutputPoller) { clearInterval(S.sshOutputPoller); S.sshOutputPoller = null; }
}

function sshKey(e) {
  if (e.key !== 'Enter') return;
  const cmd = document.getElementById('ssh-cmd');
  const command = cmd.value;
  if (!S.sshConnectionId) return;
  // Show command echo
  appendSSH(`\r\n`);
  cmd.value = '';

  if (S.socket?.connected) {
    S.socket.emit('ssh_command', { connection_id: S.sshConnectionId, command });
  } else {
    api('POST', '/api/ssh/execute', { connection_id: S.sshConnectionId, command })
      .then(r => { if (r?.output) appendSSH(r.output); });
  }
}

function sshDisconnect() {
  if (!S.sshConnectionId) return;
  stopSSHOutputPoller();
  if (S.socket?.connected) {
    S.socket.emit('ssh_disconnect', { connection_id: S.sshConnectionId });
  } else {
    api('POST', `/api/ssh/disconnect/${S.sshConnectionId}`);
    appendSSH('\n[Disconnected]\n');
    S.sshConnectionId = null;
    setTimeout(hideSSHTerminal, 1000);
  }
}

function clearSSHOutput() {
  document.getElementById('ssh-output').textContent = '';
}

function bindSocketEvents() {
  S.socket.on('ssh_connected', d => {
    S.sshConnectionId = d.connection_id;
    showSSHTerminal(`Connected: ${d.message}\n`);
  });
  S.socket.on('ssh_output', d => {
    if (d.output) appendSSH(d.output);
  });
  S.socket.on('ssh_disconnected', d => {
    appendSSH(`\n[${d.message}]\n`);
    S.sshConnectionId = null;
    setSSHStatus('disconnected', 'Disconnected');
    setTimeout(hideSSHTerminal, 1500);
  });
  S.socket.on('error', d => {
    setSSHStatus('error', 'Error');
    const errId = document.getElementById('ssh-panel-manual').classList.contains('active')
      ? 'ssh-manual-error' : 'ssh-stored-error';
    showMsg(errId, 'error', d.message || 'SSH error');
  });
}

// ------------------------------------------------------------------
// .env Import
// ------------------------------------------------------------------
function openEnvModal() { show('env-backdrop'); }
function closeEnvModal() { hide('env-backdrop'); S.envFile = null; }

async function onEnvFileSelected(input) {
  S.envFile = input.files[0];
  if (!S.envFile) return;
  const content = await S.envFile.text();
  previewEnvFile(content);
}

function stripWrappingQuotes(value) {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }
  if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1);
  }
  return value;
}

function previewEnvFile(content) {
  const preview = document.getElementById('env-preview');
  const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && l.includes('='));
  if (!lines.length) {
    preview.innerHTML = '<p class="env-no-items">No valid KEY=VALUE lines found.</p>';
    return;
  }
  preview.innerHTML = `
    <p class="env-preview-title">${lines.length} secret(s) found — select which to import:</p>
    <div class="env-select-all">
      <label><input type="checkbox" id="env-check-all" onchange="toggleAllEnvItems(this)" checked /> Select all</label>
    </div>
    ${lines.map((line, i) => {
    const eqIdx = line.indexOf('=');
    const key = line.slice(0, eqIdx).trim();
    const val = stripWrappingQuotes(line.slice(eqIdx + 1).trim());
    return `
        <div class="env-item">
          <label>
            <input type="checkbox" class="env-item-check" data-key="${esc(key)}" data-val="${esc(val)}" checked />
            <code class="env-key">${esc(key)}</code>
            <span class="env-val-preview">${val.length > 30 ? val.slice(0, 30) + '…' : esc(val)}</span>
          </label>
        </div>`;
  }).join('')}
  `;
  show('env-import-btn');
}

function toggleAllEnvItems(checkbox) {
  document.querySelectorAll('.env-item-check').forEach(cb => cb.checked = checkbox.checked);
}

async function doEnvImport() {
  const checks = document.querySelectorAll('.env-item-check:checked');
  if (!checks.length) return showMsg('env-msg', 'error', 'No items selected.');
  hide('env-msg');

  let imported = 0, errors = 0;
  for (const cb of checks) {
    const key = cb.dataset.key;
    const secretVal = cb.dataset.val;
    const res = await api('POST', '/api/secrets', { label: key, type: 'token', secret: secretVal });
    if (res?.success) imported++;
    else errors++;
  }

  const failText = errors ? `, ${errors} failed` : '';
  showMsg('env-msg', 'success', `✅ ${imported} imported${failText}.`);
  await loadSecrets();
  setTimeout(() => closeEnvModal(), 2000);
}

// ------------------------------------------------------------------
// Backup
// ------------------------------------------------------------------
function openBackupModal() { show('backup-backdrop'); }
function closeBackupModal() { hide('backup-backdrop'); }

async function doBackupExport() {
  const pw = val('backup-export-pw'), pw2 = val('backup-export-pw2');
  if (pw.length < 6) return showMsg('backup-export-msg', 'error', 'Password must be at least 6 characters.');
  if (pw !== pw2) return showMsg('backup-export-msg', 'error', 'Passwords do not match.');
  hide('backup-export-msg');

  try {
    const resp = await fetch('/api/backup/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ password: pw }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      return showMsg('backup-export-msg', 'error', err.error || 'Export failed.');
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sinduk_backup_${new Date().toISOString().slice(0, 10)}.sinduk`;
    a.click();
    URL.revokeObjectURL(url);
    showMsg('backup-export-msg', 'success', '✅ Backup downloaded! Store it somewhere safe.');
  } catch (e) {
    showMsg('backup-export-msg', 'error', 'Export failed: ' + e.message);
  }
}

function onFileSelected(input) {
  S.backupFile = input.files[0];
  document.getElementById('upload-zone-label').textContent = `📄 ${S.backupFile.name}`;
}

function handleFileDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('drag-over');
  S.backupFile = e.dataTransfer.files[0];
  if (S.backupFile) document.getElementById('upload-zone-label').textContent = `📄 ${S.backupFile.name}`;
}

async function doBackupImport() {
  if (!S.backupFile) return showMsg('backup-import-msg', 'error', 'Please select a backup file.');
  const pw = val('backup-import-pw');
  if (!pw) return showMsg('backup-import-msg', 'error', 'Backup password is required.');
  const overwrite = document.getElementById('import-overwrite').checked;
  hide('backup-import-msg');

  const fd = new FormData();
  fd.append('file', S.backupFile);
  fd.append('password', pw);
  fd.append('overwrite', overwrite ? 'true' : 'false');

  try {
    const resp = await fetch('/api/backup/import', { method: 'POST', credentials: 'include', body: fd });
    const data = await resp.json();
    if (!resp.ok) return showMsg('backup-import-msg', 'error', data.error || 'Import failed.');
    showMsg('backup-import-msg', 'success',
      `✅ Import done: ${data.imported} imported, ${data.skipped} skipped, ${data.errors} errors.`);
    await loadSecrets();
  } catch (e) {
    showMsg('backup-import-msg', 'error', 'Import failed: ' + e.message);
  }
}

// ------------------------------------------------------------------
// Tab switcher
// ------------------------------------------------------------------
function switchTab(group, panel, btn) {
  btn.closest('.tabs').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll(`[id^="${group}-panel-"]`).forEach(p => p.classList.remove('active'));
  document.getElementById(`${group}-panel-${panel}`).classList.add('active');
}

// ------------------------------------------------------------------
// Toast notifications
// ------------------------------------------------------------------
function showToast(msg, type = 'success') {
  let toast = document.getElementById('global-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'global-toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.className = `toast toast-${type} toast-show`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('toast-show'), 2500);
}

// ------------------------------------------------------------------
// Vault Creation (Phase 3)
// ------------------------------------------------------------------
function openNewVaultModal() {
  document.getElementById('new-vault-name').value = '';
  document.getElementById('new-vault-desc').value = '';
  hide('new-vault-error');
  show('new-vault-backdrop');
  document.getElementById('new-vault-name').focus();
}

function closeNewVaultModal() { hide('new-vault-backdrop'); }

async function doCreateVault() {
  const name = val('new-vault-name').toLowerCase();
  const description = val('new-vault-desc');
  if (!name) return showMsg('new-vault-error', 'error', 'Vault name is required.');
  hide('new-vault-error');

  const res = await api('POST', '/api/vaults', { name, description });
  if (res?.success) {
    closeNewVaultModal();
    await loadVaults();
    S.currentVault = name;
    renderVaultSelect();
    await loadSecrets();
    showToast(`✅ Vault '${name}' created!`);
  } else {
    showMsg('new-vault-error', 'error', res?.error || 'Failed to create vault.');
  }
}

// ------------------------------------------------------------------
// Team Management (Phase 3)
// ------------------------------------------------------------------
async function openTeamModal() {
  if (!S.currentVault) return;
  document.getElementById('team-modal-title').textContent = `👥 Team: ${S.currentVault}`;
  hide('add-member-form');
  hide('team-msg');
  show('team-backdrop');
  await loadTeamDetails();
}

function closeTeamModal() { hide('team-backdrop'); }

function toggleAddMemberForm() {
  const form = document.getElementById('add-member-form');
  const isHidden = form.classList.contains('hidden');
  form.classList.toggle('hidden', !isHidden);
  if (isHidden) {
    document.getElementById('new-member-id').value = '';
    document.getElementById('new-member-name').value = '';
    document.getElementById('new-member-role').value = 'viewer';
    hide('add-member-error');
    document.getElementById('new-member-id').focus();
  }
}

async function loadTeamDetails() {
  // Load identity info
  const idRes = await api('GET', `/api/vaults/${S.currentVault}/identity`);
  if (idRes && !idRes.error) {
    S.myIdentity = idRes;
    document.getElementById('my-identity-name').textContent = idRes.user_name || '—';
    document.getElementById('my-identity-id').textContent = idRes.user_id || '—';
    const roleBadge = document.getElementById('my-vault-role');
    if (roleBadge) roleBadge.textContent = idRes.role || '—';
  }

  // Load members
  const res = await api('GET', `/api/vaults/${S.currentVault}/members`);
  const members = res?.members || [];

  const isAdmin = S.myIdentity?.role === 'admin';
  const deleteBtn = document.getElementById('delete-vault-btn');
  if (deleteBtn) deleteBtn.style.display = isAdmin ? 'inline-flex' : 'none';
  const addBtn = document.getElementById('add-member-toggle-btn');
  if (addBtn) addBtn.style.display = isAdmin ? 'inline-flex' : 'none';

  renderTeamMembers(members);
}

function _renderMemberRoleOptions(currentRole) {
  const roles = [
    { value: 'viewer', label: 'Viewer' },
    { value: 'editor', label: 'Editor' },
    { value: 'admin', label: 'Admin' },
  ];
  return roles
    .map(r => {
      const isSelected = r.value === currentRole ? ' selected' : '';
      return `<option value="${r.value}"${isSelected}>${r.label}</option>`;
    })
    .join('');
}

function renderTeamMembers(members) {
  const listEl = document.getElementById('team-members-list');
  if (!listEl) return;
  const isAdmin = S.myIdentity?.role === 'admin';

  if (!members.length) {
    listEl.innerHTML = '<div class="empty-state"><p>No members found.</p></div>';
    return;
  }

  listEl.innerHTML = members.map(m => {
    const isSelf = m.user_id === S.myIdentity?.user_id;
    const dateStr = m.added_at ? new Date(m.added_at * 1000).toLocaleDateString() : '';
    const actionsHtml = isAdmin && !isSelf
      ? `<select class="member-role-select" onchange="doChangeMemberRole('${esc(m.user_id)}', this.value)">${_renderMemberRoleOptions(m.role)}</select>
         <button class="btn btn-danger btn-xs" onclick="doRemoveMember('${esc(m.user_id)}')">Remove</button>`
      : `<span class="badge badge-vault">${esc(m.role)}</span>`;

    return `
      <div class="team-member-card">
        <div class="member-info">
          <div class="member-name">${esc(m.user_name)} ${isSelf ? '<span class="tag-you">(You)</span>' : ''}</div>
          <div class="member-id">ID: <code class="inline-code">${esc(m.user_id)}</code> · Added ${dateStr}</div>
        </div>
        <div class="member-actions">
          ${actionsHtml}
        </div>
      </div>
    `;
  }).join('');
}

async function doAddMember() {
  const userId = val('new-member-id');
  const userName = val('new-member-name');
  const role = document.getElementById('new-member-role').value;

  if (!userId || !userName) return showMsg('add-member-error', 'error', 'User ID and Display Name are required.');
  hide('add-member-error');

  const res = await api('POST', `/api/vaults/${S.currentVault}/members`, {
    user_id: userId,
    user_name: userName,
    role: role,
  });

  if (res?.success) {
    toggleAddMemberForm();
    await loadTeamDetails();
    showToast(`✅ Added ${userName}!`);
  } else {
    showMsg('add-member-error', 'error', res?.error || 'Failed to add member.');
  }
}

async function doChangeMemberRole(userId, newRole) {
  const res = await api('PUT', `/api/vaults/${S.currentVault}/members/${userId}/role`, { role: newRole });
  if (res?.success) {
    showToast(`✅ Role updated to ${newRole}`);
    await loadTeamDetails();
  } else {
    alert(res?.error || 'Failed to update role.');
  }
}

async function doRemoveMember(userId) {
  if (!confirm(`Remove member with ID "${userId}" from this vault?`)) return;
  const res = await api('DELETE', `/api/vaults/${S.currentVault}/members/${userId}`);
  if (res?.success) {
    showToast('🗑️ Member removed');
    await loadTeamDetails();
  } else {
    alert(res?.error || 'Failed to remove member.');
  }
}

async function doDeleteCurrentVault() {
  if (!S.currentVault) return;
  if (!confirm(`Are you sure you want to permanently delete vault "${S.currentVault}" and ALL its secrets? This cannot be undone.`)) return;
  const res = await api('DELETE', `/api/vaults/${S.currentVault}`);
  if (res?.success) {
    closeTeamModal();
    S.currentVault = '';
    await loadVaults();
    await loadSecrets();
    showToast('🗑️ Vault deleted.');
  } else {
    alert(res?.error || 'Failed to delete vault.');
  }
}

// ------------------------------------------------------------------
// Audit Log (Phase 3)
// ------------------------------------------------------------------
async function openAuditModal() {
  if (!S.currentVault) return;
  document.getElementById('audit-modal-title').textContent = `📋 Audit Log: ${S.currentVault}`;
  show('audit-backdrop');
  await loadAuditLog();
}

function closeAuditModal() { hide('audit-backdrop'); }

async function loadAuditLog() {
  const container = document.getElementById('audit-log-container');
  container.innerHTML = '<div class="empty-state"><p>Loading audit log…</p></div>';

  const res = await api('GET', `/api/vaults/${S.currentVault}/audit?limit=50`);
  const entries = res?.entries || [];

  if (!entries.length) {
    container.innerHTML = '<div class="empty-state"><p>No audit entries for this vault yet.</p></div>';
    return;
  }

  container.innerHTML = `
    <table class="audit-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>User</th>
          <th>Action</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        ${entries.map(e => `
          <tr>
            <td class="audit-time">${esc(e.timestamp_formatted || '')}</td>
            <td><code class="inline-code">${esc(e.user_id || 'unknown')}</code></td>
            <td><span class="audit-action-tag audit-action-${esc(e.action)}">${esc(e.action)}</span></td>
            <td class="audit-details">${esc(e.details || '')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
async function api(method, url, body) {
  try {
    const opts = { method, credentials: 'include', headers: {} };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    if (r.status === 401) { showLogin(); return null; }
    return await r.json();
  } catch (e) {
    console.error('API error', url, e);
    return null;
  }
}

function val(id) { return document.getElementById(id)?.value?.trim() || ''; }
function show(id) { document.getElementById(id)?.classList.remove('hidden'); }
function hide(id) { document.getElementById(id)?.classList.add('hidden'); }
function esc(s) {
  if (s === null || s === undefined) return '';
  const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML;
}

function showMsg(id, type, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `alert alert-${type}`;
  el.textContent = text;
  el.classList.remove('hidden');
}
