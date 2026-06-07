export interface Env {
  RENO_R2: R2Bucket;
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
  host: string;
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

// --- AES-GCM encrypt (compatible with Go's cryptoDecrypt) ---

async function cryptoEncrypt(secret: string, plaintext: string): Promise<string> {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc);
  const buf = new Uint8Array(12 + ciphertext.byteLength);
  buf.set(iv, 0);
  buf.set(new Uint8Array(ciphertext), 12);
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// --- R2 state helpers ---
// R2 is strongly consistent globally and has generous free limits (1M writes/month).

const ONLINE_MS = 10 * 60 * 1000; // 10 minutes

interface State {
  edges: Edge[];
  stations: Station[];
  tunnels: Tunnel[];
}

async function getState(env: Env): Promise<State> {
  const obj = await env.RENO_R2.get('state');
  if (!obj) return { edges: [], stations: [], tunnels: [] };
  return await obj.json() as State;
}

async function saveState(env: Env, state: State): Promise<void> {
  await env.RENO_R2.put('state', JSON.stringify(state));
}

async function getEdges(env: Env): Promise<Edge[]> { return (await getState(env)).edges; }
async function getStations(env: Env): Promise<Station[]> { return (await getState(env)).stations; }
async function getTunnels(env: Env): Promise<Tunnel[]> { return (await getState(env)).tunnels; }

async function saveEdges(env: Env, edges: Edge[]): Promise<void> {
  const s = await getState(env); s.edges = edges; await saveState(env, s);
}
async function saveStations(env: Env, stations: Station[]): Promise<void> {
  const s = await getState(env); s.stations = stations; await saveState(env, s);
}
async function saveTunnels(env: Env, tunnels: Tunnel[]): Promise<void> {
  const s = await getState(env); s.tunnels = tunnels; await saveState(env, s);
}

function withStatus<T extends { lastSeen: string; status: 'online' | 'offline' }>(list: T[]): T[] {
  const now = Date.now();
  return list.map(item => ({
    ...item,
    status: (now - new Date(item.lastSeen).getTime()) < ONLINE_MS ? 'online' as const : 'offline' as const,
  }));
}

function generateId(): string {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Dashboard HTML ---

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>reno</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet" />
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg-primary: #ffffff;
  --bg-secondary: #f5f5f4;
  --bg-tertiary: #eeede9;
  --bg-input: #f5f5f4;
  --border: rgba(0,0,0,0.1);
  --border-hover: rgba(0,0,0,0.2);
  --text-primary: #1a1917;
  --text-secondary: #6b6a67;
  --text-tertiary: #9e9c98;
  --text-on-accent: #ffffff;
  --accent: #1a1917;
  --accent-hover: #2e2d2a;
  --badge-active-bg: #e8f5e9;
  --badge-active-text: #2d7a3a;
  --badge-idle-bg: #f0efeb;
  --badge-idle-text: #9e9c98;
  --proto-bg: #f0efeb;
  --proto-text: #6b6a67;
  --danger-text: #c0392b;
  --danger-bg: #fdf0ef;
  --scrollbar: rgba(0,0,0,0.12);
  --shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --font: 'DM Mono', monospace;
  --font-sans: 'DM Sans', sans-serif;
}

[data-theme="dark"] {
  --bg-primary: #1c1b19;
  --bg-secondary: #252421;
  --bg-tertiary: #2e2c29;
  --bg-input: #252421;
  --border: rgba(255,255,255,0.08);
  --border-hover: rgba(255,255,255,0.15);
  --text-primary: #f0ede8;
  --text-secondary: #9e9c98;
  --text-tertiary: #6b6a67;
  --text-on-accent: #1a1917;
  --accent: #e8e5e0;
  --accent-hover: #f0ede8;
  --badge-active-bg: #1a2e1c;
  --badge-active-text: #6abf74;
  --badge-idle-bg: #252421;
  --badge-idle-text: #6b6a67;
  --proto-bg: #2e2c29;
  --proto-text: #9e9c98;
  --danger-text: #e07060;
  --danger-bg: #2e1e1c;
  --scrollbar: rgba(255,255,255,0.1);
  --shadow: 0 1px 3px rgba(0,0,0,0.3);
}

html, body {
  height: 100%;
  font-family: var(--font-sans);
  background: var(--bg-secondary);
  color: var(--text-primary);
  -webkit-font-smoothing: antialiased;
  transition: background 0.2s, color 0.2s;
}

.page {
  min-height: 100vh;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 2.5rem 1rem;
}

.container {
  width: 100%;
  max-width: 540px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2px;
  margin-bottom: 0.5rem;
}

.logo { display: flex; align-items: center; gap: 10px; }

.logo-icon {
  width: 30px; height: 30px;
  background: var(--accent);
  border-radius: var(--radius-sm);
  display: flex; align-items: center; justify-content: center;
}

.logo-icon svg {
  width: 16px; height: 16px;
  stroke: var(--text-on-accent);
  fill: none;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.logo-text {
  font-family: var(--font);
  font-size: 20px;
  font-weight: 500;
  color: var(--text-primary);
  letter-spacing: -0.3px;
}

.theme-toggle {
  display: flex; align-items: center; gap: 6px;
  background: var(--bg-primary);
  border: 0.5px solid var(--border);
  border-radius: 20px;
  padding: 5px 12px;
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 12px;
  color: var(--text-secondary);
  transition: background 0.15s, border-color 0.15s, color 0.15s;
}

.theme-toggle:hover { background: var(--bg-tertiary); color: var(--text-primary); }

.theme-toggle svg {
  width: 14px; height: 14px;
  stroke: currentColor;
  fill: none;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
  flex-shrink: 0;
}

.card {
  background: var(--bg-primary);
  border: 0.5px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow);
  transition: background 0.2s, border-color 0.2s;
}

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

.node-card { padding: 1rem 1.25rem; }

.section-label {
  font-family: var(--font);
  font-size: 10px;
  font-weight: 500;
  color: var(--text-tertiary);
  letter-spacing: 0.8px;
  text-transform: uppercase;
  margin-bottom: 14px;
}

.node-row {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 0;
  border-bottom: 0.5px solid var(--border);
}
.node-row:last-child { border-bottom: none; }

.node-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.node-dot.online  { background: var(--badge-active-text); }
.node-dot.offline { background: var(--text-tertiary); }

.node-name {
  flex: 1;
  font-size: 12px; font-weight: 500;
  font-family: var(--font-sans);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.node-status { font-size: 11px; font-family: var(--font); flex-shrink: 0; }
.node-status.online  { color: var(--badge-active-text); }
.node-status.offline { color: var(--text-tertiary); }

.empty-sm { font-size: 11px; color: var(--text-tertiary); font-family: var(--font); padding: 2px 0; }

.create-card { padding: 1.25rem; }

.create-fields {
  display: grid;
  grid-template-columns: 1fr 1fr 80px 1fr;
  gap: 8px;
  margin-bottom: 8px;
}

.create-fields-2 {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.field { display: flex; flex-direction: column; }
.field-sm { width: 80px; flex-shrink: 0; display: flex; flex-direction: column; }
.field-grow { flex: 1; display: flex; flex-direction: column; }

.field label, .field-sm label, .field-grow label {
  font-size: 11px;
  color: var(--text-tertiary);
  margin-bottom: 5px;
  font-family: var(--font);
}

.field input, .field select,
.field-sm input, .field-sm select,
.field-grow input, .field-grow select {
  width: 100%;
  height: 34px;
  padding: 0 10px;
  font-size: 12px;
  font-family: var(--font);
  color: var(--text-primary);
  background: var(--bg-input);
  border: 0.5px solid var(--border);
  border-radius: var(--radius-sm);
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  transition: border-color 0.15s, background 0.15s;
}

.field input::placeholder, .field-sm input::placeholder, .field-grow input::placeholder {
  color: var(--text-tertiary);
}

.field input:focus, .field select:focus,
.field-sm input:focus, .field-sm select:focus,
.field-grow input:focus, .field-grow select:focus {
  border-color: var(--border-hover);
  background: var(--bg-primary);
}

.field select, .field-sm select, .field-grow select {
  cursor: pointer;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%239e9c98' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 8px center;
  padding-right: 28px;
}

.create-footer { display: flex; justify-content: flex-end; }

.btn-create {
  height: 34px;
  padding: 0 18px;
  background: var(--accent);
  color: var(--text-on-accent);
  border: none;
  border-radius: var(--radius-sm);
  font-family: var(--font);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s, transform 0.1s;
  white-space: nowrap;
}
.btn-create:hover { background: var(--accent-hover); }
.btn-create:active { transform: scale(0.97); }

.list-card { overflow: hidden; }

.list-header {
  padding: 12px 14px 0;
  font-family: var(--font);
  font-size: 10px;
  font-weight: 500;
  color: var(--text-tertiary);
  letter-spacing: 0.8px;
  text-transform: uppercase;
}

.tunnel-list {
  max-height: 400px;
  overflow-y: auto;
  padding: 8px 0 4px;
}

.tunnel-list::-webkit-scrollbar { width: 3px; }
.tunnel-list::-webkit-scrollbar-track { background: transparent; }
.tunnel-list::-webkit-scrollbar-thumb { background: var(--scrollbar); border-radius: 3px; }

.tunnel-item {
  display: grid;
  grid-template-columns: 1fr auto auto auto;
  gap: 10px;
  align-items: center;
  padding: 9px 14px;
  border-bottom: 0.5px solid var(--border);
  transition: background 0.1s;
}
.tunnel-item:last-child { border-bottom: none; }
.tunnel-item:hover { background: var(--bg-secondary); }

.t-name { font-size: 13px; font-weight: 500; color: var(--text-primary); font-family: var(--font-sans); }
.t-route { font-size: 11px; color: var(--text-secondary); font-family: var(--font-sans); margin-top: 1px; }
.t-addr { font-size: 11px; color: var(--text-tertiary); font-family: var(--font); margin-top: 1px; }

.t-proto {
  font-size: 10px;
  font-family: var(--font);
  font-weight: 500;
  color: var(--proto-text);
  background: var(--proto-bg);
  padding: 2px 7px;
  border-radius: 4px;
  white-space: nowrap;
}

.t-badge {
  font-size: 10px;
  font-family: var(--font);
  padding: 2px 8px;
  border-radius: 20px;
  white-space: nowrap;
}
.t-badge.active { background: var(--badge-active-bg); color: var(--badge-active-text); }
.t-badge.idle   { background: var(--badge-idle-bg);   color: var(--badge-idle-text); }

.t-del {
  background: transparent;
  border: none;
  cursor: pointer;
  color: var(--text-tertiary);
  display: flex; align-items: center; justify-content: center;
  width: 24px; height: 24px;
  border-radius: var(--radius-sm);
  transition: background 0.1s, color 0.1s;
  flex-shrink: 0;
}
.t-del:hover { background: var(--danger-bg); color: var(--danger-text); }
.t-del svg {
  width: 13px; height: 13px;
  stroke: currentColor; fill: none;
  stroke-width: 2; stroke-linecap: round;
}

.empty {
  text-align: center;
  padding: 2.5rem 1rem;
  color: var(--text-tertiary);
  font-size: 12px;
  font-family: var(--font);
}
.empty svg {
  width: 28px; height: 28px;
  stroke: var(--text-tertiary); fill: none;
  stroke-width: 1.4; stroke-linecap: round; stroke-linejoin: round;
  display: block; margin: 0 auto 10px; opacity: 0.4;
}

.login-page {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  background: var(--bg-secondary);
  padding: 1rem;
}
.login-box {
  background: var(--bg-primary);
  border: 0.5px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow);
  padding: 2rem;
  width: 100%; max-width: 320px;
}
.login-logo { display: flex; align-items: center; gap: 10px; margin-bottom: 1.5rem; }
.login-field { margin-bottom: 10px; }
.login-field label {
  display: block;
  font-size: 11px; color: var(--text-tertiary);
  margin-bottom: 5px; font-family: var(--font);
}
.login-field input {
  width: 100%; height: 34px; padding: 0 10px;
  font-size: 12px; font-family: var(--font);
  color: var(--text-primary); background: var(--bg-input);
  border: 0.5px solid var(--border); border-radius: var(--radius-sm);
  outline: none; transition: border-color 0.15s;
}
.login-field input:focus { border-color: var(--border-hover); }
.login-btn {
  width: 100%; height: 36px;
  background: var(--accent); color: var(--text-on-accent);
  border: none; border-radius: var(--radius-sm);
  font-family: var(--font); font-size: 13px; font-weight: 500;
  cursor: pointer; margin-top: 6px; transition: background 0.15s;
}
.login-btn:hover { background: var(--accent-hover); }
.login-err { color: var(--danger-text); font-size: 11px; font-family: var(--font); margin-top: 8px; text-align: center; }

@media (max-width: 480px) {
  .create-fields { grid-template-columns: 1fr 1fr; }
  .two-col { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<div id="login-view" class="login-page" style="display:none">
  <div class="login-box">
    <div class="login-logo">
      <div class="logo-icon">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/>
          <line x1="12" y1="7" x2="5" y2="17"/><line x1="12" y1="7" x2="19" y2="17"/><line x1="5" y1="19" x2="19" y2="19"/>
        </svg>
      </div>
      <span class="logo-text">reno</span>
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

<div id="app-view" class="page" style="display:none">
  <div class="container">

    <header class="header">
      <div class="logo">
        <div class="logo-icon">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/>
            <line x1="12" y1="7" x2="5" y2="17"/><line x1="12" y1="7" x2="19" y2="17"/><line x1="5" y1="19" x2="19" y2="19"/>
          </svg>
        </div>
        <span class="logo-text">reno</span>
      </div>
      <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
        <svg id="themeIcon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
        <span id="themeLabel">dark</span>
      </button>
    </header>

    <div class="two-col">
      <div class="card node-card">
        <div class="section-label">Edges</div>
        <div id="edge-list"><div class="empty-sm">No edges</div></div>
      </div>
      <div class="card node-card">
        <div class="section-label">Stations</div>
        <div id="station-list"><div class="empty-sm">No stations</div></div>
      </div>
    </div>

    <div class="card create-card">
      <div class="section-label">Create</div>
      <div class="create-fields">
        <div class="field">
          <label>Edge</label>
          <select id="form-edge"><option value="">Select...</option></select>
        </div>
        <div class="field">
          <label>Station</label>
          <select id="form-station"><option value="">Select...</option></select>
        </div>
        <div class="field">
          <label>Protocol</label>
          <select id="form-protocol">
            <option>TCP</option><option>UDP</option><option>QUIC</option><option>HTTP</option><option>HTTPS</option>
          </select>
        </div>
        <div class="field">
          <label>IP</label>
          <input id="form-ip" type="text" placeholder="127.0.0.1" value="127.0.0.1" />
        </div>
      </div>
      <div class="create-fields-2">
        <div class="field-sm">
          <label>Port</label>
          <input id="form-port" type="number" placeholder="8080" />
        </div>
        <div class="field-sm" style="width:96px">
          <label>Remote Port</label>
          <input id="form-remote-port" type="number" placeholder="13000" />
        </div>
        <div class="field-grow">
          <label>Name</label>
          <input id="form-name" type="text" placeholder="my-service" />
        </div>
      </div>
      <div class="create-footer">
        <button class="btn-create" onclick="createTunnel()">Create</button>
      </div>
    </div>

    <div class="card list-card">
      <div class="list-header">Tunnels</div>
      <div class="tunnel-list" id="tunnel-list"></div>
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
  document.getElementById('app-view').style.display = 'flex';
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/api/ws');
  ws.onmessage = function(e) {
    const data = JSON.parse(e.data);
    edges    = data.edges    || [];
    stations = data.stations || [];
    // Only overwrite tunnel list after 60s guard (prevents stale data from
    // wiping out tunnels we just created/deleted).
    if (Date.now() - lastMutation > 60000) {
      tunnels = data.tunnels || [];
    }
    // Always re-render tunnels so active/idle status updates in real-time
    // even while the tunnel list is guarded.
    renderTunnels();
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
    fetch('/api/edges'), fetch('/api/stations'), fetch('/api/tunnels')
  ]);
  if (sRes.status === 401) { showLogin(); return; }
  edges    = (await eRes.json()).edges    || [];
  stations = (await sRes.json()).stations || [];
  tunnels  = (await tRes.json()).tunnels  || [];
  renderEdges(); renderStations(); renderEdgeSelect(); renderStationSelect(); renderTunnels();
}

const DEL_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

function renderEdges() {
  const el = document.getElementById('edge-list');
  if (!edges.length) { el.innerHTML = '<div class="empty-sm">No edges</div>'; return; }
  el.innerHTML = edges.map(function(e) {
    const cls = e.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-name">' + esc(e.name) + '</span>' +
      '<span class="node-status ' + cls + '">' + e.status + '</span>' +
      '<button class="t-del" data-edge-id="' + esc(e.id) + '" aria-label="Delete">' + DEL_SVG + '</button>' +
    '</div>';
  }).join('');
}

function renderStations() {
  const el = document.getElementById('station-list');
  if (!stations.length) { el.innerHTML = '<div class="empty-sm">No stations</div>'; return; }
  el.innerHTML = stations.map(function(s) {
    const cls = s.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-name">' + esc(s.name) + '</span>' +
      '<span class="node-status ' + cls + '">' + s.status + '</span>' +
      '<button class="t-del" data-station-id="' + esc(s.id) + '" aria-label="Delete">' + DEL_SVG + '</button>' +
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
  if (!tunnels.length) {
    list.innerHTML = '<div class="empty"><svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><line x1="12" y1="7" x2="5" y2="17"/><line x1="12" y1="7" x2="19" y2="17"/><line x1="5" y1="19" x2="19" y2="19"/></svg>no tunnels yet</div>';
    return;
  }
  list.innerHTML = tunnels.map(function(t) {
    const edge    = edges.find(function(e)   { return e.id === t.edge_id; });
    const station = stations.find(function(s) { return s.id === t.station_id; });
    const edgeOnline    = edge    && edge.status    === 'online';
    const stationOnline = station && station.status === 'online';
    const badge = (edgeOnline && stationOnline)
      ? '<span class="t-badge active">active</span>'
      : '<span class="t-badge idle">idle</span>';
    const edgeName    = edge    ? esc(edge.name)    : '?';
    const stationName = station ? esc(station.name) : '?';
    return '<div class="tunnel-item">' +
      '<div>' +
        '<div class="t-name">' + esc(t.name) + '</div>' +
        '<div class="t-route">' + edgeName + ' \u2192 ' + stationName + '</div>' +
        '<div class="t-addr">' + esc(t.local_host) + ':' + t.local_port + ' \u2192 :' + t.remote_port + '</div>' +
      '</div>' +
      '<span class="t-proto">' + esc(t.protocol) + '</span>' +
      badge +
      '<button class="t-del" data-tunnel-id="' + esc(t.id) + '" aria-label="Delete">' + DEL_SVG + '</button>' +
    '</div>';
  }).join('');
}

document.addEventListener('click', function(e) {
  const btn = e.target.closest('.t-del');
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
  if (!edgeId || !stationId || !localPort || !name || !remotePort) { alert('Please fill in all fields'); return; }
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
  tunnels = tunnels.filter(function(t) { return t.id !== id; });
  renderTunnels();
  fetch('/api/tunnels/' + id, { method: 'DELETE' });
}

function deleteEdge(id) {
  lastMutation = Date.now();
  edges = edges.filter(function(e) { return e.id !== id; });
  renderEdges(); renderEdgeSelect();
  fetch('/api/edges/' + id, { method: 'DELETE' });
}

function deleteStation(id) {
  lastMutation = Date.now();
  stations = stations.filter(function(s) { return s.id !== id; });
  renderStations(); renderStationSelect();
  fetch('/api/stations/' + id, { method: 'DELETE' });
}

let dark = true;

function toggleTheme() {
  dark = !dark;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const icon = document.getElementById('themeIcon');
  const label = document.getElementById('themeLabel');
  if (dark) {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
    label.textContent = 'dark';
  } else {
    icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
    label.textContent = 'light';
  }
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
    try {
      return await handle(request, env);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.stack ?? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }
};

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const qs = url.searchParams.get('secret') || '';
  const hdr = request.headers.get('X-Reno-Secret') || '';
  const secretOk = env.API_SECRET !== '' && (qs === env.API_SECRET || hdr === env.API_SECRET);

  // favicon
  if (method === 'GET' && path === '/favicon.ico') {
    return new Response(null, { status: 204 });
  }

  // dashboard HTML
  if (method === 'GET' && path === '/') {
    return new Response(DASHBOARD_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  // login
  if (path === '/api/auth/login' && method === 'POST') {
    const body = await request.json() as { username: string; password: string };
    if (body.username !== env.USERNAME || body.password !== env.PASSWORD) return unauthorized();
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

  // logout
  if (path === '/api/auth/logout' && method === 'POST') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'token=; Path=/; HttpOnly; Max-Age=0' }
    });
  }

  // WebSocket — JWT required
  if (path === '/api/ws' && request.headers.get('Upgrade') === 'websocket') {
    if (!await requireAuth(request, env)) return unauthorized();
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();
    const sendState = async () => {
      try {
        const { edges, stations, tunnels } = await getState(env);
        server.send(JSON.stringify({
          edges: withStatus(edges),
          stations: withStatus(stations),
          tunnels,
        }));
      } catch {}
    };
    await sendState();
    const timer = setInterval(sendState, 5000);
    server.addEventListener('close', () => clearInterval(timer));
    return new Response(null, { status: 101, webSocket: client } as ResponseInit);
  }

  // All API routes require secret (station/edge) OR JWT (dashboard user)
  if (!path.startsWith('/api/')) return new Response('Not Found', { status: 404 });
  const jwtOk = secretOk || !!(await requireAuth(request, env));
  if (!jwtOk) return unauthorized();

  // ── Edges ──────────────────────────────────────────────────────────────────

  if (path === '/api/edges/register' && method === 'POST') {
    if (!secretOk) return unauthorized();
    const body = await request.json() as { name: string };
    const now = new Date().toISOString();
    const edges = await getEdges(env);
    let edge = edges.find(e => e.name === body.name);
    if (edge) {
      edge.lastSeen = now;
    } else {
      edge = { id: generateId(), name: body.name, registeredAt: now, lastSeen: now, status: 'online' };
      edges.push(edge);
    }
    await saveEdges(env, edges);
    return json({ edge_id: edge.id });
  }

  const edgeActionMatch = path.match(/^\/api\/edges\/([^/]+)\/(heartbeat|offline)$/);
  if (edgeActionMatch && method === 'POST') {
    if (!secretOk) return unauthorized();
    const [, edgeId, action] = edgeActionMatch;
    const edges = await getEdges(env);
    const edge = edges.find(e => e.id === edgeId);
    if (edge) {
      edge.lastSeen = action === 'heartbeat' ? new Date().toISOString() : new Date(0).toISOString();
      await saveEdges(env, edges);
    }
    return json({ ok: true });
  }

  if (path === '/api/edges' && method === 'GET') {
    return json({ edges: withStatus(await getEdges(env)) });
  }

  const edgeIdMatch = path.match(/^\/api\/edges\/([^/]+)$/);
  if (edgeIdMatch && method === 'DELETE') {
    const [, edgeId] = edgeIdMatch;
    await saveEdges(env, (await getEdges(env)).filter(e => e.id !== edgeId));
    await saveTunnels(env, (await getTunnels(env)).filter(t => t.edge_id !== edgeId));
    return json({ ok: true });
  }

  // ── Stations ────────────────────────────────────────────────────────────────

  if (path === '/api/stations/register' && method === 'POST') {
    if (!secretOk) return unauthorized();
    const body = await request.json() as { id: string; name: string; control_port: number; cert_fingerprint: string; host?: string };
    const now = new Date().toISOString();
    // Prefer the IPv4 address explicitly sent by the station; fall back to CF-Connecting-IP
    const host = body.host || request.headers.get('CF-Connecting-IP') || '';
    const stations = await getStations(env);
    let station = stations.find(s => s.id === body.id);
    if (station) {
      station.name = body.name;
      station.controlPort = body.control_port;
      station.certFingerprint = body.cert_fingerprint;
      station.host = host;
      station.lastSeen = now;
    } else {
      station = { id: body.id, name: body.name, controlPort: body.control_port, certFingerprint: body.cert_fingerprint, host, registeredAt: now, lastSeen: now, status: 'online' };
      stations.push(station);
    }
    await saveStations(env, stations);
    return json({ ok: true, station_id: body.id });
  }

  const stationHbMatch = path.match(/^\/api\/stations\/([^/]+)\/heartbeat$/);
  if (stationHbMatch && method === 'POST') {
    if (!secretOk) return unauthorized();
    const [, stationId] = stationHbMatch;
    const stations = await getStations(env);
    const station = stations.find(s => s.id === stationId);
    if (station) { station.lastSeen = new Date().toISOString(); await saveStations(env, stations); }
    return json({ ok: true });
  }

  const stationConnMatch = path.match(/^\/api\/stations\/([^/]+)\/connect$/);
  if (stationConnMatch && method === 'GET') {
    const [, stationId] = stationConnMatch;
    const stations = await getStations(env);
    // "auto" = connect to first available station
    const station = stationId === 'auto'
      ? withStatus(stations).find(s => s.status === 'online') ?? stations[0]
      : stations.find(s => s.id === stationId);
    if (!station) return json({ error: 'station not found' }, 404);
    const plain = `${station.host}|${station.controlPort}|${station.certFingerprint}`;
    const encrypted = await cryptoEncrypt(env.API_SECRET, plain);
    return json({ encrypted_info: encrypted, station_id: station.id });
  }

  if (path === '/api/stations' && method === 'GET') {
    return json({ stations: withStatus(await getStations(env)) });
  }

  const stationIdMatch = path.match(/^\/api\/stations\/([^/]+)$/);
  if (stationIdMatch && method === 'DELETE') {
    const [, stationId] = stationIdMatch;
    await saveStations(env, (await getStations(env)).filter(s => s.id !== stationId));
    return json({ ok: true });
  }

  // ── Tunnels ─────────────────────────────────────────────────────────────────

  if (path === '/api/tunnels' && method === 'GET') {
    const stationFilter = url.searchParams.get('station_id');
    const edgeFilter = url.searchParams.get('edge_id');
    let tunnels = await getTunnels(env);
    if (stationFilter) tunnels = tunnels.filter(t => t.station_id === stationFilter);
    if (edgeFilter) tunnels = tunnels.filter(t => t.edge_id === edgeFilter);
    return json({ tunnels });
  }

  if (path === '/api/tunnels' && method === 'POST') {
    const body = await request.json() as Partial<Tunnel>;
    const now = new Date().toISOString();
    const tunnel: Tunnel = {
      id: body.id || generateId(),
      edge_id: body.edge_id || '',
      station_id: body.station_id || '',
      name: body.name || '',
      protocol: body.protocol || 'TCP',
      local_host: body.local_host || '127.0.0.1',
      local_port: body.local_port || 0,
      remote_port: body.remote_port || 0,
      status: 'idle',
      created_at: body.created_at || now,
    };
    const tunnels = await getTunnels(env);
    tunnels.push(tunnel);
    await saveTunnels(env, tunnels);
    return json({ tunnel });
  }

  const tunnelIdMatch = path.match(/^\/api\/tunnels\/([^/]+)$/);
  if (tunnelIdMatch && method === 'DELETE') {
    const [, tunnelId] = tunnelIdMatch;
    await saveTunnels(env, (await getTunnels(env)).filter(t => t.id !== tunnelId));
    return json({ ok: true });
  }

  return new Response('Not Found', { status: 404 });
}
