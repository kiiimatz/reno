export interface Env {
  RENO_KV: KVNamespace;
  USERNAME: string;
  PASSWORD: string;
  JWT_SECRET: string;
  API_SECRET: string;
}

interface Edge {
  id: string;
  name: string;
  registeredAt: string;
  lastSeen: string;
  status: 'online' | 'offline';
}

interface Station {
  id: string;
  name: string;
  controlPort: number;
  certFingerprint: string;
  registeredAt: string;
  lastSeen: string;
  status: 'online' | 'offline';
}

interface Tunnel {
  id: string;
  edge_id: string;
  station_id: string;
  name: string;
  protocol: 'TCP' | 'UDP' | 'QUIC' | 'HTTP' | 'HTTPS';
  local_host: string;
  local_port: number;
  remote_port: number;
  status: 'active' | 'idle';
  created_at: string;
}

// --- Crypto utilities ---

async function deriveKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(secret));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptInfo(secret: string, plaintext: string): Promise<string> {
  const key = await deriveKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    enc.encode(plaintext)
  );
  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(nonce);
  combined.set(new Uint8Array(ciphertext), 12);
  return btoa(String.fromCharCode(...combined))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function decryptInfo(secret: string, encoded: string): Promise<string> {
  const key = await deriveKey(secret);
  const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '==='.slice((b64.length + 3) % 4);
  const data = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  const nonce = data.slice(0, 12);
  const ciphertext = data.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// --- JWT utilities ---

async function jwtSign(payload: object, secret: string): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const body = btoa(JSON.stringify(payload)).replace(/=/g, '');
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${data}.${sigB64}`;
}

async function jwtVerify(token: string, secret: string): Promise<object | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const data = `${parts[0]}.${parts[1]}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
    const sig = Uint8Array.from(atob(sigB64 + '==='.slice((sigB64.length + 3) % 4)), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1] + '==='.slice((parts[1].length + 3) % 4)));
    if (payload.exp && payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

// --- KV helpers ---

async function getEdges(kv: KVNamespace): Promise<Edge[]> {
  const data = await kv.get('edges');
  return data ? JSON.parse(data) : [];
}

async function saveEdges(kv: KVNamespace, edges: Edge[]): Promise<void> {
  await kv.put('edges', JSON.stringify(edges));
}

async function getStations(kv: KVNamespace): Promise<Station[]> {
  const data = await kv.get('stations');
  return data ? JSON.parse(data) : [];
}

async function saveStations(kv: KVNamespace, stations: Station[]): Promise<void> {
  await kv.put('stations', JSON.stringify(stations));
}

async function getTunnels(kv: KVNamespace): Promise<Tunnel[]> {
  const data = await kv.get('tunnels');
  return data ? JSON.parse(data) : [];
}

async function saveTunnels(kv: KVNamespace, tunnels: Tunnel[]): Promise<void> {
  await kv.put('tunnels', JSON.stringify(tunnels));
}

function generateId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

// --- Auth middleware ---

async function requireAuth(request: Request, env: Env): Promise<string | null> {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/token=([^;]+)/);
  if (!match) return null;
  const payload = await jwtVerify(match[1], env.JWT_SECRET);
  if (!payload) return null;
  return 'ok';
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function unauthorized(): Response {
  return json({ error: 'unauthorized' }, 401);
}

// --- Dashboard HTML ---

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>reno</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #1a1a1c;
    --surface:  #252528;
    --input:    #2e2e32;
    --border:   #3a3a3e;
    --text:     #e8e8ea;
    --muted:    #8a8a8e;
    --dim:      #5a5a5e;
    --green:    #22c55e;
    --green-bg: #14532d;
    --offline:  #52525b;
    --btn-bg:   #f4f4f5;
    --btn-text: #18181b;
    --blue:     #3b82f6;
  }

  body.light {
    --bg:       #f0f0f2;
    --surface:  #ffffff;
    --input:    #ebebed;
    --border:   #d4d4d8;
    --text:     #18181b;
    --muted:    #52525b;
    --dim:      #a1a1aa;
    --green:    #16a34a;
    --green-bg: #dcfce7;
    --offline:  #a1a1aa;
    --btn-bg:   #18181b;
    --btn-text: #f4f4f5;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    min-height: 100vh;
    transition: background 0.15s, color 0.15s;
  }

  /* ── Layout ── */
  .wrap {
    max-width: 680px;
    margin: 0 auto;
    padding: 40px 20px 60px;
  }

  /* ── Header ── */
  .hdr {
    display: flex;
    align-items: center;
    margin-bottom: 24px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .logo-icon {
    width: 36px; height: 36px;
    background: var(--blue);
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-size: 17px;
    flex-shrink: 0;
  }
  .logo-name {
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.4px;
  }
  .theme-btn {
    margin-left: auto;
    background: #f4f4f5;
    border: 1.5px solid #d4d4d8;
    border-radius: 20px;
    color: #18181b;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    padding: 7px 16px;
    transition: opacity 0.15s;
    white-space: nowrap;
  }
  body.light .theme-btn {
    background: #18181b;
    border-color: #3f3f46;
    color: #f4f4f5;
  }
  .theme-btn:hover { opacity: 0.85; }

  /* ── Card ── */
  .card {
    background: var(--surface);
    border-radius: 14px;
    padding: 22px 24px;
    margin-bottom: 10px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.35);
  }

  .section-title {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.5px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 16px;
  }

  /* ── Two column ── */
  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 10px;
  }

  /* ── Node rows (edges / stations) ── */
  .node-row {
    display: flex;
    align-items: center;
    padding: 9px 0;
    border-bottom: 1px solid var(--border);
    gap: 8px;
  }
  .node-row:last-child { border-bottom: none; }

  .node-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .node-dot.online  { background: var(--green); }
  .node-dot.offline { background: var(--offline); }

  .node-label {
    flex: 1;
    font-size: 13px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .node-status {
    font-size: 11px;
    flex-shrink: 0;
  }
  .node-status.online  { color: var(--green); }
  .node-status.offline { color: var(--offline); }

  .icon-btn {
    width: 28px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    background: var(--input);
    border: 1.5px solid var(--border);
    border-radius: 7px;
    color: var(--muted);
    cursor: pointer;
    font-size: 13px;
    flex-shrink: 0;
    transition: border-color 0.12s, color 0.12s;
  }
  .icon-btn:hover { border-color: #ef4444; color: #ef4444; }

  .empty-msg {
    color: var(--dim);
    font-size: 12px;
    padding: 4px 0;
  }

  /* ── Form ── */
  .form-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: flex-end;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
  }
  .field label {
    font-size: 11px;
    color: var(--muted);
  }

  .f-edge    { flex: 1.2; min-width: 100px; }
  .f-station { flex: 1.2; min-width: 100px; }
  .f-proto   { flex: 0.7; min-width: 72px; }
  .f-ip      { flex: 1.6; min-width: 110px; }
  .f-port    { flex: 0.8; min-width: 72px; }
  .f-rport   { flex: 0.8; min-width: 72px; }

  .form-row2 {
    display: flex;
    gap: 8px;
    align-items: flex-end;
    margin-top: 8px;
  }
  .f-name { flex: 1; }

  input, select {
    background: var(--input);
    border: 1.5px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-size: 13px;
    font-weight: 500;
    padding: 9px 11px;
    width: 100%;
    outline: none;
    transition: border-color 0.15s;
    -webkit-appearance: none;
    appearance: none;
  }
  select {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238a8a8e'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 10px center;
    padding-right: 28px;
  }
  input::placeholder { color: var(--dim); font-weight: 400; }
  input:focus, select:focus { border-color: var(--blue); }

  .btn {
    background: var(--btn-bg);
    color: var(--btn-text);
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    padding: 9px 22px;
    white-space: nowrap;
    flex-shrink: 0;
    transition: opacity 0.12s;
  }
  .btn:hover { opacity: 0.85; }

  /* ── Tunnel rows ── */
  .tunnel-row {
    display: flex;
    align-items: center;
    padding: 13px 0;
    border-bottom: 1px solid var(--border);
    gap: 12px;
  }
  .tunnel-row:last-child { border-bottom: none; }

  .tunnel-info { flex: 1; min-width: 0; }
  .tunnel-name {
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tunnel-addr {
    font-size: 12px;
    color: #6a6a6e;
    font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
    margin-top: 2px;
  }
  .tunnel-sub {
    font-size: 11px;
    color: var(--dim);
    margin-top: 2px;
  }

  .tunnel-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
  .proto-text {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    min-width: 34px;
    text-align: right;
  }
  .status-active {
    font-size: 11px;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 20px;
    background: var(--green-bg);
    color: var(--green);
  }
  .status-idle {
    font-size: 11px;
    color: var(--muted);
  }

  /* ── Login ── */
  .login-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .login-box {
    background: var(--surface);
    border-radius: 16px;
    padding: 40px 36px;
    width: 100%;
    max-width: 360px;
  }
  .login-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
  }
  .login-logo-icon {
    width: 36px; height: 36px;
    background: var(--blue);
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-size: 17px;
  }
  .login-logo-name { font-size: 20px; font-weight: 700; letter-spacing: -0.4px; }
  .login-field { margin-bottom: 12px; }
  .login-field label {
    display: block;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 0.5px;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .login-field input { width: 100%; }
  .login-btn {
    width: 100%;
    background: var(--btn-bg);
    color: var(--btn-text);
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
    padding: 12px;
    margin-top: 10px;
    transition: opacity 0.12s;
  }
  .login-btn:hover { opacity: 0.85; }
  .login-err { color: #ef4444; font-size: 12px; margin-top: 10px; text-align: center; }
</style>
</head>
<body>

<div id="login-view" class="login-page" style="display:none">
  <div class="login-box">
    <div class="login-logo">
      <div class="login-logo-icon">&#10052;</div>
      <span class="login-logo-name">reno</span>
    </div>
    <div class="login-field">
      <label>Username</label>
      <input type="text" id="login-user" autocomplete="username" />
    </div>
    <div class="login-field">
      <label>Password</label>
      <input type="password" id="login-pass" autocomplete="current-password" />
    </div>
    <button class="login-btn" onclick="doLogin()">Login</button>
    <div class="login-err" id="login-error"></div>
  </div>
</div>

<div id="app-view" style="display:none">
  <div class="wrap">

    <div class="hdr">
      <div class="logo">
        <div class="logo-icon">&#10052;</div>
        <span class="logo-name">reno</span>
      </div>
      <button class="theme-btn" onclick="toggleTheme()">&#x1F319; dark</button>
    </div>

    <div class="two-col">
      <div class="card" style="margin-bottom:0">
        <div class="section-title">Edges</div>
        <div id="edge-list"><div class="empty-msg">No edges</div></div>
      </div>
      <div class="card" style="margin-bottom:0">
        <div class="section-title">Stations</div>
        <div id="station-list"><div class="empty-msg">No stations</div></div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">Create Tunnel</div>
      <div class="form-row">
        <div class="field f-edge">
          <label>Edge</label>
          <select id="form-edge"><option value="">Select...</option></select>
        </div>
        <div class="field f-station">
          <label>Station</label>
          <select id="form-station"><option value="">Select...</option></select>
        </div>
        <div class="field f-proto">
          <label>Protocol</label>
          <select id="form-protocol">
            <option>TCP</option><option>UDP</option><option>QUIC</option>
            <option>HTTP</option><option>HTTPS</option>
          </select>
        </div>
        <div class="field f-ip">
          <label>IP</label>
          <input type="text" id="form-ip" placeholder="127.0.0.1" value="127.0.0.1" />
        </div>
        <div class="field f-port">
          <label>Port</label>
          <input type="number" id="form-port" placeholder="8080" />
        </div>
        <div class="field f-rport">
          <label>Remote Port</label>
          <input type="number" id="form-remote-port" placeholder="13000" />
        </div>
      </div>
      <div class="form-row2">
        <div class="field f-name">
          <label>Name</label>
          <input type="text" id="form-name" placeholder="my-service" />
        </div>
        <button class="btn" onclick="createTunnel()">Create</button>
      </div>
    </div>

    <div class="card">
      <div class="section-title">Tunnels</div>
      <div id="tunnel-list"><div class="empty-msg">No tunnels yet</div></div>
    </div>

  </div>
</div>

<script>
let edges = [];
let stations = [];
let tunnels = [];
let ws = null;
let lastMutation = 0;

async function init() {
  const res = await fetch('/api/stations');
  if (res.status === 401) { showLogin(); return; }
  showApp();
  connectWS();
}

function showLogin() {
  document.getElementById('login-view').style.display = 'flex';
  document.getElementById('app-view').style.display = 'none';
  if (ws) { ws.close(); ws = null; }
}

function showApp() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('app-view').style.display = 'block';
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/api/ws');
  ws.onmessage = function(e) {
    const data = JSON.parse(e.data);
    edges    = data.edges    || [];
    stations = data.stations || [];
    if (Date.now() - lastMutation > 3000) {
      tunnels = data.tunnels || [];
      renderTunnels();
    }
    renderEdges();
    renderStations();
    renderEdgeSelect();
    renderStationSelect();
  };
  ws.onclose = function() {
    ws = null;
    setTimeout(function() {
      if (document.getElementById('app-view').style.display !== 'none') connectWS();
    }, 3000);
  };
  ws.onerror = function() { ws && ws.close(); };
}

async function doLogin() {
  const username = document.getElementById('login-user').value;
  const password = document.getElementById('login-pass').value;
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (res.ok) { showApp(); connectWS(); }
  else document.getElementById('login-error').textContent = 'Invalid credentials';
}

async function refresh() {
  const [eRes, sRes, tRes] = await Promise.all([
    fetch('/api/edges'),
    fetch('/api/stations'),
    fetch('/api/tunnels')
  ]);
  if (sRes.status === 401) { showLogin(); return; }
  edges    = (await eRes.json()).edges    || [];
  stations = (await sRes.json()).stations || [];
  tunnels  = (await tRes.json()).tunnels  || [];
  renderEdges();
  renderStations();
  renderEdgeSelect();
  renderStationSelect();
  renderTunnels();
}

function renderEdges() {
  const el = document.getElementById('edge-list');
  if (!edges.length) { el.innerHTML = '<div class="empty-msg">No edges</div>'; return; }
  el.innerHTML = edges.map(e => {
    const cls = e.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-label">' + esc(e.name) + '</span>' +
      '<span class="node-status ' + cls + '">' + e.status + '</span>' +
      '<button class="icon-btn" data-edge-id="' + esc(e.id) + '">&#x2715;</button>' +
    '</div>';
  }).join('');
}

function renderStations() {
  const el = document.getElementById('station-list');
  if (!stations.length) { el.innerHTML = '<div class="empty-msg">No stations</div>'; return; }
  el.innerHTML = stations.map(s => {
    const cls = s.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-label">' + esc(s.name) + '</span>' +
      '<span class="node-status ' + cls + '">' + s.status + '</span>' +
      '<button class="icon-btn" data-station-id="' + esc(s.id) + '">&#x2715;</button>' +
    '</div>';
  }).join('');
}

function renderEdgeSelect() {
  const sel = document.getElementById('form-edge');
  const val = sel.value;
  sel.innerHTML = '<option value="">Select...</option>';
  for (const e of edges) {
    const opt = document.createElement('option');
    opt.value = e.id;
    opt.textContent = e.name + (e.status === 'offline' ? ' (offline)' : '');
    if (e.id === val) opt.selected = true;
    sel.appendChild(opt);
  }
}

function renderStationSelect() {
  const sel = document.getElementById('form-station');
  const val = sel.value;
  sel.innerHTML = '<option value="">Select...</option>';
  for (const s of stations) {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name + (s.status === 'offline' ? ' (offline)' : '');
    if (s.id === val) opt.selected = true;
    sel.appendChild(opt);
  }
}

function renderTunnels() {
  const list = document.getElementById('tunnel-list');
  if (!tunnels.length) { list.innerHTML = '<div class="empty-msg">No tunnels yet</div>'; return; }
  list.innerHTML = tunnels.map(t => {
    const edgeName    = (edges.find(e => e.id === t.edge_id) || {}).name || t.edge_id || '?';
    const stationName = (stations.find(s => s.id === t.station_id) || {}).name || t.station_id || '?';
    const statusHtml  = t.status === 'active'
      ? '<span class="status-active">active</span>'
      : '<span class="status-idle">idle</span>';
    return '<div class="tunnel-row">' +
      '<div class="tunnel-info">' +
        '<div class="tunnel-name">' + esc(t.name) + '</div>' +
        '<div class="tunnel-addr">' + esc(t.local_host) + ':' + t.local_port + ' \u2192 :' + t.remote_port + '</div>' +
        '<div class="tunnel-sub">' + esc(edgeName) + ' \u2192 ' + esc(stationName) + '</div>' +
      '</div>' +
      '<div class="tunnel-right">' +
        '<span class="proto-text">' + esc(t.protocol) + '</span>' +
        statusHtml +
        '<button class="icon-btn" data-tunnel-id="' + esc(t.id) + '">&#x2715;</button>' +
      '</div>' +
    '</div>';
  }).join('');
}

document.addEventListener('click', function(e) {
  const btn = e.target.closest('.icon-btn');
  if (!btn) return;
  if (btn.dataset.tunnelId)  deleteTunnel(btn.dataset.tunnelId);
  if (btn.dataset.edgeId)    deleteEdge(btn.dataset.edgeId);
  if (btn.dataset.stationId) deleteStation(btn.dataset.stationId);
});

async function createTunnel() {
  const edgeId     = document.getElementById('form-edge').value;
  const stationId  = document.getElementById('form-station').value;
  const protocol   = document.getElementById('form-protocol').value;
  const localHost  = document.getElementById('form-ip').value;
  const localPort  = parseInt(document.getElementById('form-port').value);
  const name       = document.getElementById('form-name').value;
  const remotePort = parseInt(document.getElementById('form-remote-port').value);

  if (!edgeId || !stationId || !localPort || !name || !remotePort) {
    alert('Please fill in all fields');
    return;
  }

  lastMutation = Date.now();
  const res = await fetch('/api/tunnels', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ edge_id: edgeId, station_id: stationId, protocol, local_host: localHost, local_port: localPort, name, remote_port: remotePort })
  });
  if (res.ok) {
    const data = await res.json();
    tunnels.push(data.tunnel);
    document.getElementById('form-port').value = '';
    document.getElementById('form-name').value = '';
    document.getElementById('form-remote-port').value = '';
    renderTunnels();
  }
}

function deleteTunnel(id) {
  lastMutation = Date.now();
  tunnels = tunnels.filter(t => t.id !== id);
  renderTunnels();
  fetch('/api/tunnels/' + id, { method: 'DELETE' });
}

function deleteEdge(id) {
  lastMutation = Date.now();
  edges = edges.filter(e => e.id !== id);
  renderEdges();
  renderEdgeSelect();
  fetch('/api/edges/' + id, { method: 'DELETE' });
}

function deleteStation(id) {
  lastMutation = Date.now();
  stations = stations.filter(s => s.id !== id);
  renderStations();
  renderStationSelect();
  fetch('/api/stations/' + id, { method: 'DELETE' });
}

function toggleTheme() {
  document.body.classList.toggle('light');
  document.querySelector('.theme-btn').textContent =
    document.body.classList.contains('light') ? '\u2600\uFE0F light' : '\uD83C\uDF19 dark';
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

init();
</script>
</body>
</html>`;

// --- Router ---

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Favicon — no auth needed
    if (method === 'GET' && path === '/favicon.ico') {
      return new Response(null, { status: 204 });
    }

    // Serve dashboard
    if (method === 'GET' && path === '/') {
      return new Response(DASHBOARD_HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // Auth routes
    if (path === '/api/auth/login' && method === 'POST') {
      const body = await request.json() as { username: string; password: string };
      if (body.username !== env.USERNAME || body.password !== env.PASSWORD) {
        return unauthorized();
      }
      const token = await jwtSign(
        { sub: body.username, exp: Math.floor(Date.now() / 1000) + 86400 * 30 },
        env.JWT_SECRET
      );
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${86400 * 30}`
        }
      });
    }

    if (path === '/api/auth/logout' && method === 'POST') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': 'token=; Path=/; HttpOnly; Max-Age=0'
        }
      });
    }

    // WebSocket for real-time dashboard updates
    if (path === '/api/ws' && request.headers.get('Upgrade') === 'websocket') {
      const authed = await requireAuth(request, env);
      if (!authed) return unauthorized();

      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];
      server.accept();

      const sendState = async () => {
        const [edgeList, stationList, tunnelList] = await Promise.all([
          getEdges(env.RENO_KV),
          getStations(env.RENO_KV),
          getTunnels(env.RENO_KV),
        ]);
        const now = Date.now();
        for (const e of edgeList) {
          if (now - new Date(e.lastSeen).getTime() > 60000) e.status = 'offline';
        }
        for (const s of stationList) {
          if (now - new Date(s.lastSeen).getTime() > 60000) s.status = 'offline';
        }
        try {
          server.send(JSON.stringify({ edges: edgeList, stations: stationList, tunnels: tunnelList }));
        } catch {}
      };

      await sendState();
      const timer = setInterval(sendState, 1000);
      server.addEventListener('close', () => clearInterval(timer));

      return new Response(null, { status: 101, webSocket: client } as ResponseInit);
    }

    // Edge register (uses API_SECRET)
    if (path === '/api/edges/register' && method === 'POST') {
      const body = await request.json() as { name: string; secret: string };
      if (body.secret !== env.API_SECRET) return unauthorized();

      const edges = await getEdges(env.RENO_KV);
      const existing = edges.find(e => e.name === body.name);

      let edgeId: string;
      if (existing) {
        edgeId = existing.id;
        existing.lastSeen = new Date().toISOString();
        existing.status = 'online';
        await saveEdges(env.RENO_KV, edges);
      } else {
        edgeId = generateId();
        edges.push({
          id: edgeId,
          name: body.name,
          registeredAt: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          status: 'online',
        });
        await saveEdges(env.RENO_KV, edges);
      }

      return json({ edge_id: edgeId });
    }

    // Edge offline (uses API_SECRET)
    const edgeOfflineMatch = path.match(/^\/api\/edges\/([^/]+)\/offline$/);
    if (edgeOfflineMatch && method === 'POST') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      const edgeId = edgeOfflineMatch[1];
      const edges = await getEdges(env.RENO_KV);
      const edge = edges.find(e => e.id === edgeId);
      if (edge) {
        edge.status = 'offline';
        await saveEdges(env.RENO_KV, edges);
      }
      return json({ ok: true });
    }

    // Edge heartbeat (uses API_SECRET)
    const edgeHeartbeatMatch = path.match(/^\/api\/edges\/([^/]+)\/heartbeat$/);
    if (edgeHeartbeatMatch && method === 'POST') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      const edgeId = edgeHeartbeatMatch[1];
      const edges = await getEdges(env.RENO_KV);
      const edge = edges.find(e => e.id === edgeId);
      if (edge) {
        edge.lastSeen = new Date().toISOString();
        edge.status = 'online';
        await saveEdges(env.RENO_KV, edges);
      }

      return json({ ok: true });
    }

    // Station register (uses API_SECRET, not JWT)
    if (path === '/api/stations/register' && method === 'POST') {
      const body = await request.json() as {
        name: string; control_port: number; cert_fingerprint: string; secret: string; ip: string;
      };
      if (body.secret !== env.API_SECRET) return unauthorized();

      const stations = await getStations(env.RENO_KV);
      const existing = stations.find(s => s.name === body.name);

      let stationId: string;
      if (existing) {
        stationId = existing.id;
        existing.controlPort = body.control_port;
        existing.certFingerprint = body.cert_fingerprint;
        existing.lastSeen = new Date().toISOString();
        existing.status = 'online';
        await saveStations(env.RENO_KV, stations);
      } else {
        stationId = generateId();
        stations.push({
          id: stationId,
          name: body.name,
          controlPort: body.control_port,
          certFingerprint: body.cert_fingerprint,
          registeredAt: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          status: 'online',
        });
        await saveStations(env.RENO_KV, stations);
      }

      const encryptedInfo = await encryptInfo(
        env.API_SECRET,
        `${body.ip}:${body.control_port}:${body.cert_fingerprint}`
      );
      await env.RENO_KV.put(`station_info:${stationId}`, encryptedInfo);

      return json({ station_id: stationId });
    }

    // Station connect info (for Edge, uses API_SECRET)
    const connectMatch = path.match(/^\/api\/stations\/([^/]+)\/connect$/);
    if (connectMatch && method === 'GET') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      let stationId = connectMatch[1];
      if (stationId === 'auto') {
        const stations = await getStations(env.RENO_KV);
        if (!stations.length) return json({ error: 'no stations registered' }, 404);
        stationId = stations[0].id;
      }

      const encryptedInfo = await env.RENO_KV.get(`station_info:${stationId}`);
      if (!encryptedInfo) return json({ error: 'station not found' }, 404);

      return json({ encrypted_info: encryptedInfo, station_id: stationId });
    }

    // Station tunnels (for Station polling, uses API_SECRET)
    const tunnelsForStationMatch = path.match(/^\/api\/stations\/([^/]+)\/tunnels$/);
    if (tunnelsForStationMatch && method === 'GET') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      const stationId = tunnelsForStationMatch[1];
      const allTunnels = await getTunnels(env.RENO_KV);
      const stationTunnels = allTunnels.filter(t => t.station_id === stationId);

      return json({ tunnels: stationTunnels });
    }

    // Station offline (uses API_SECRET)
    const stationOfflineMatch = path.match(/^\/api\/stations\/([^/]+)\/offline$/);
    if (stationOfflineMatch && method === 'POST') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      const stationId = stationOfflineMatch[1];
      const stations = await getStations(env.RENO_KV);
      const station = stations.find(s => s.id === stationId);
      if (station) {
        station.status = 'offline';
        await saveStations(env.RENO_KV, stations);
      }
      return json({ ok: true });
    }

    // Station heartbeat (uses API_SECRET)
    const heartbeatMatch = path.match(/^\/api\/stations\/([^/]+)\/heartbeat$/);
    if (heartbeatMatch && method === 'POST') {
      const secret = url.searchParams.get('secret');
      if (secret !== env.API_SECRET) return unauthorized();

      const stationId = heartbeatMatch[1];
      const stations = await getStations(env.RENO_KV);
      const station = stations.find(s => s.id === stationId);
      if (station) {
        station.lastSeen = new Date().toISOString();
        station.status = 'online';
        await saveStations(env.RENO_KV, stations);
      }

      return json({ ok: true });
    }

    // Require auth for remaining routes
    const authed = await requireAuth(request, env);
    if (!authed) return unauthorized();

    // GET /api/edges
    if (path === '/api/edges' && method === 'GET') {
      const edges = await getEdges(env.RENO_KV);
      const now = Date.now();
      for (const e of edges) {
        if (now - new Date(e.lastSeen).getTime() > 120000) {
          e.status = 'offline';
        }
      }
      return json({ edges });
    }

    // DELETE /api/edges/:id
    const deleteEdgeMatch = path.match(/^\/api\/edges\/([^/]+)$/);
    if (deleteEdgeMatch && method === 'DELETE') {
      const id = deleteEdgeMatch[1];
      const edges = await getEdges(env.RENO_KV);
      await saveEdges(env.RENO_KV, edges.filter(e => e.id !== id));
      return json({ ok: true });
    }

    // GET /api/stations
    if (path === '/api/stations' && method === 'GET') {
      const stations = await getStations(env.RENO_KV);
      const now = Date.now();
      for (const s of stations) {
        if (now - new Date(s.lastSeen).getTime() > 120000) {
          s.status = 'offline';
        }
      }
      return json({ stations });
    }

    // DELETE /api/stations/:id
    const deleteStationMatch = path.match(/^\/api\/stations\/([^/]+)$/);
    if (deleteStationMatch && method === 'DELETE') {
      const id = deleteStationMatch[1];
      const stations = await getStations(env.RENO_KV);
      await saveStations(env.RENO_KV, stations.filter(s => s.id !== id));
      await env.RENO_KV.delete(`station_info:${id}`);
      return json({ ok: true });
    }

    // GET /api/tunnels
    if (path === '/api/tunnels' && method === 'GET') {
      return json({ tunnels: await getTunnels(env.RENO_KV) });
    }

    // POST /api/tunnels
    if (path === '/api/tunnels' && method === 'POST') {
      const body = await request.json() as {
        edge_id: string; station_id: string; name: string;
        protocol: 'TCP' | 'UDP' | 'QUIC' | 'HTTP' | 'HTTPS';
        local_host: string; local_port: number; remote_port: number;
      };
      const tunnel: Tunnel = {
        id: generateId(),
        edge_id: body.edge_id,
        station_id: body.station_id,
        name: body.name,
        protocol: body.protocol || 'TCP',
        local_host: body.local_host || '127.0.0.1',
        local_port: body.local_port,
        remote_port: body.remote_port,
        status: 'idle',
        created_at: new Date().toISOString(),
      };
      const tunnels = await getTunnels(env.RENO_KV);
      tunnels.push(tunnel);
      await saveTunnels(env.RENO_KV, tunnels);
      return json({ tunnel });
    }

    // DELETE /api/tunnels/:id
    const deleteTunnelMatch = path.match(/^\/api\/tunnels\/([^/]+)$/);
    if (deleteTunnelMatch && method === 'DELETE') {
      const id = deleteTunnelMatch[1];
      const tunnels = await getTunnels(env.RENO_KV);
      await saveTunnels(env.RENO_KV, tunnels.filter(t => t.id !== id));
      return json({ ok: true });
    }

    return new Response('Not Found', { status: 404 });
  }
};
