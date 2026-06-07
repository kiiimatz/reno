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
  address: string; // custom hostname/IP; empty = use host
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
  enabled: boolean;
  created_at: string;
  bytes?: number;
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

async function getTraffic(env: Env): Promise<Record<string, number>> {
  const obj = await env.RENO_R2.get('traffic');
  if (!obj) return {};
  return await obj.json() as Record<string, number>;
}

async function saveTraffic(env: Env, traffic: Record<string, number>): Promise<void> {
  await env.RENO_R2.put('traffic', JSON.stringify(traffic));
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
  --bg-page:    #f5f4f0;
  --bg-primary: #ffffff;
  --bg-input:   #f0efeb;
  --border:        rgba(0,0,0,0.09);
  --border-input:  rgba(0,0,0,0.12);
  --border-hover:  rgba(0,0,0,0.25);
  --text-primary:  rgba(26,25,23,1);
  --text-secondary:rgba(90,88,84,1);
  --text-label:    rgba(130,128,124,1);
  --text-on-accent:rgba(255,255,255,1);
  --accent:        rgba(26,25,23,1);
  --accent-hover:  rgba(46,45,42,1);
  --accent-text:   rgba(255,255,255,1);
  --badge-active-bg:  #d4edda;
  --badge-active-text:#276235;
  --badge-idle-bg:    #ebebeb;
  --badge-idle-text:  #8a8880;
  --proto-bg:   #ebebeb;
  --proto-text: #6b6a67;
  --del-bg:     #ebebeb;
  --del-border: rgba(0,0,0,0.1);
  --del-text:   #9e9c98;
  --danger-text:#c0392b;
  --danger-bg:  #fdf0ef;
  --scrollbar:  rgba(0,0,0,0.1);
  --shadow:     none;
  --radius-sm:  6px;
  --radius-md:  8px;
  --radius-lg:  10px;
  --font:       'DM Mono', monospace;
  --font-sans:  'DM Sans', sans-serif;
}

[data-theme="dark"] {
  --bg-page:    rgba(30,29,27,1);
  --bg-primary: rgba(48,46,43,1);
  --bg-input:   rgba(55,53,50,1);
  --border:        rgba(255,255,255,0.08);
  --border-input:  rgba(255,255,255,0.10);
  --border-hover:  rgba(255,255,255,0.25);
  --text-primary:  rgba(240,237,232,1);
  --text-secondary:rgba(120,118,114,1);
  --text-label:    rgba(100,98,94,1);
  --text-on-accent:rgba(30,29,27,1);
  --accent:        rgba(240,237,232,1);
  --accent-hover:  rgba(255,255,255,1);
  --accent-text:   rgba(30,29,27,1);
  --badge-active-bg:  rgba(78,207,113,0.15);
  --badge-active-text:rgba(78,207,113,1);
  --badge-idle-bg:    rgba(60,58,55,1);
  --badge-idle-text:  rgba(130,128,124,1);
  --proto-bg:   rgba(60,58,55,1);
  --proto-text: rgba(160,158,154,1);
  --del-bg:     rgba(60,58,55,1);
  --del-border: rgba(255,255,255,0.10);
  --del-text:   rgba(160,158,154,1);
  --danger-text:#e07060;
  --danger-bg:  #3a2420;
  --scrollbar:  rgba(255,255,255,0.1);
  --shadow:     none;
  --radius-lg:  10px;
}

html {
  scrollbar-gutter: stable;
}
html, body {
  height: 100%;
  font-family: var(--font-sans);
  background: var(--bg-page);
  color: var(--text-primary);
  -webkit-font-smoothing: antialiased;
  transition: background 0.15s, color 0.15s;
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
  gap: 10px;
}

/* ── Header ── */
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2px;
  margin-bottom: 6px;
}

.logo { display: flex; align-items: center; gap: 10px; }

.logo-icon {
  width: 32px; height: 32px;
  background: #3d5a8a;
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}

.logo-icon svg {
  width: 17px; height: 17px;
  stroke: #ffffff; fill: none;
  stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round;
}

.logo-text {
  font-family: var(--font-sans);
  font-size: 22px;
  font-weight: 400;
  color: var(--text-primary);
  letter-spacing: -0.3px;
}

.theme-toggle {
  display: flex; align-items: center; gap: 6px;
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 5px 13px;
  cursor: pointer;
  font-family: var(--font-sans);
  font-size: 12px;
  color: var(--text-secondary);
  transition: background 0.15s, color 0.15s;
}

.theme-toggle:hover { color: var(--text-primary); }

.theme-toggle svg {
  width: 13px; height: 13px;
  stroke: currentColor; fill: none;
  stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round;
  flex-shrink: 0;
}

/* ── Card ── */
.card {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  transition: background 0.15s;
}

.section-label {
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  color: var(--text-label);
  letter-spacing: 0.7px;
  text-transform: uppercase;
}

/* ── Item drag & drop ── */
#cards-container {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.item-flying {
  position: fixed;
  z-index: 9999;
  pointer-events: none;
  box-shadow: 0 10px 32px rgba(0,0,0,0.4), 0 2px 8px rgba(0,0,0,0.25);
  opacity: 0.95;
  border-radius: 6px;
  background: var(--bg-primary);
  transform: scale(1.02);
  user-select: none;
}
.item-ghost {
  border: 1.5px dashed var(--border);
  border-radius: 6px;
  background: rgba(255,255,255,0.025);
  pointer-events: none;
  box-sizing: border-box;
}
/* Prevent text selection during drag */
.no-select, .no-select * { user-select: none !important; }

/* ── Nodes collapsible card ── */
.nodes-card { overflow: hidden; }

.nodes-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}
.nodes-header:hover { background: rgba(255,255,255,0.03); }

.nodes-arrow {
  width: 16px; height: 16px;
  stroke: var(--text-label); fill: none;
  stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;
  transition: transform 0.28s ease;
  flex-shrink: 0;
}
.nodes-arrow.open { transform: rotate(180deg); }

.nodes-body {
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.32s ease;
}
.nodes-body.open { max-height: 600px; }

.nodes-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  border-top: 1px solid var(--border);
}

.nodes-section { padding: 14px 18px; }
.nodes-section:first-child { border-right: 1px solid var(--border); }

.nodes-sublabel {
  font-family: var(--font-sans);
  font-size: 10px;
  font-weight: 500;
  color: var(--text-label);
  letter-spacing: 0.6px;
  text-transform: uppercase;
  margin-bottom: 10px;
}

/* ── Context menu ── */
.ctx-menu {
  position: fixed;
  z-index: 10000;
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 4px;
  min-width: 140px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  opacity: 0;
  transform: scale(0.95);
  transform-origin: top left;
  transition: opacity 0.1s ease, transform 0.1s ease;
  pointer-events: none;
}
.ctx-menu.open {
  opacity: 1;
  transform: scale(1);
  pointer-events: all;
}
.ctx-item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 10px;
  border-radius: 5px;
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 13px;
  font-family: var(--font-sans);
  cursor: pointer;
  text-align: left;
  transition: background 0.12s, color 0.12s;
}
.ctx-item:hover { background: rgba(255,255,255,0.07); color: var(--text-primary); }
.ctx-item.danger:hover { background: var(--danger-bg); color: var(--danger-text); }
.ctx-item svg { width: 13px; height: 13px; stroke: currentColor; fill: none; stroke-width: 2; stroke-linecap: round; flex-shrink: 0; }

/* ── Node rows ── */
.node-row {
  display: flex; align-items: center; gap: 8px;
  padding: 5px 0;
  border-bottom: 1px solid var(--border);
  cursor: grab;
}
.node-row:active { cursor: grabbing; }
.node-row:last-child { border-bottom: none; }

.node-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.node-dot.online  { background: var(--badge-active-text); }
.node-dot.offline { background: var(--text-label); }

.node-name {
  flex: 1;
  font-size: 13px; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.node-status { font-size: 12px; flex-shrink: 0; }
.node-status.online  { color: var(--badge-active-text); }
.node-status.offline { color: var(--text-label); }

.empty-sm { font-size: 12px; color: var(--text-label); padding: 2px 0; }

/* ── Modal ── */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.55);
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  z-index: 100;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.22s ease;
}
.modal-overlay.open {
  opacity: 1;
  pointer-events: all;
}
.modal {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 22px;
  width: 100%;
  max-width: 520px;
  transform: translateY(10px) scale(0.98);
  transition: transform 0.22s ease;
}
.modal-overlay.open .modal {
  transform: translateY(0) scale(1);
}
.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 18px;
}
.modal-close {
  background: var(--del-bg);
  border: 1px solid var(--del-border);
  color: var(--del-text);
  width: 28px; height: 28px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: background 0.15s, color 0.15s;
  flex-shrink: 0;
}
.modal-close:hover { background: var(--danger-bg); color: var(--danger-text); border-color: transparent; }
.add-btn { background: transparent !important; border-color: transparent !important; }
.add-btn:hover { background: var(--del-bg) !important; border-color: var(--del-border) !important; color: var(--del-text) !important; }
.modal-close svg { width: 13px; height: 13px; stroke: currentColor; fill: none; stroke-width: 2; stroke-linecap: round; }

/* ── Create form (inside modal) ── */

.create-fields {
  display: flex;
  gap: 10px;
  margin-bottom: 10px;
}
.create-fields .field:nth-child(1) { flex: 2; } /* Edge */
.create-fields .field:nth-child(2) { flex: 2; } /* Station */
.create-fields .field:nth-child(3) { flex: 1; } /* Protocol */
.create-fields .field:nth-child(4) { flex: 2; } /* IP */

.create-fields-2 {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}

.field { display: flex; flex-direction: column; min-width: 0; }
.field-sm { flex: 1; min-width: 70px; display: flex; flex-direction: column; }
.field-grow { flex: 3; display: flex; flex-direction: column; }

.field label, .field-sm label, .field-grow label {
  display: block;
  font-size: 12px;
  font-weight: 400;
  color: var(--text-secondary);
  margin-bottom: 6px;
  font-family: var(--font-sans);
}

.field input, .field select,
.field-sm input, .field-sm select,
.field-grow input, .field-grow select {
  width: 100%;
  height: 36px;
  padding: 0 10px;
  font-size: 13px;
  font-weight: 400;
  font-family: var(--font-sans);
  color: var(--text-primary);
  background: var(--bg-input);
  border: 1px solid var(--border-input);
  border-radius: var(--radius-sm);
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  transition: border-color 0.15s, background 0.15s;
}

.field input::placeholder, .field-sm input::placeholder, .field-grow input::placeholder {
  color: var(--text-label);
}

.field input:focus, .field select:focus,
.field-sm input:focus, .field-sm select:focus,
.field-grow input:focus, .field-grow select:focus {
  border-color: var(--border-hover);
}

.field select, .field-sm select, .field-grow select {
  cursor: pointer;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23a09e9a' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 8px center;
  padding-right: 28px;
}

.create-footer { display: flex; justify-content: flex-end; }

.btn-create {
  height: 36px;
  padding: 0 20px;
  background: var(--accent);
  color: var(--accent-text);
  border: none;
  border-radius: var(--radius-sm);
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s, transform 0.1s;
  white-space: nowrap;
}
.btn-create:hover { background: var(--accent-hover); }
.btn-create:active { transform: scale(0.97); }

/* ── Tunnel list ── */
.list-card { overflow: hidden; }

.list-header {
  padding: 16px 16px 0;
  font-family: var(--font-sans);
  font-size: 11px;
  font-weight: 500;
  color: var(--text-label);
  letter-spacing: 0.7px;
  text-transform: uppercase;
  margin-bottom: 4px;
}

.tunnel-list {
  max-height: 360px;
  overflow-y: auto;
  padding: 4px 0;
}

.tunnel-list::-webkit-scrollbar { width: 3px; }
.tunnel-list::-webkit-scrollbar-track { background: transparent; }
.tunnel-list::-webkit-scrollbar-thumb { background: var(--scrollbar); border-radius: 3px; }

.tunnel-item {
  display: grid;
  grid-template-columns: auto 1fr auto auto;
  gap: 12px;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  transition: background 0.15s;
  cursor: grab;
}

.t-bytes {
  font-size: 11px;
  font-weight: 500;
  color: var(--proto-text);
  background: var(--proto-bg);
  padding: 3px 8px;
  border-radius: 20px;
  white-space: nowrap;
  font-family: var(--font);
}
.tunnel-item:active { cursor: grabbing; }
.tunnel-item:last-child { border-bottom: none; }
.tunnel-item:hover { background: rgba(255,255,255,0.03); }

.t-name-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  overflow: hidden;
}
.t-name  { font-size: 14px; font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.t-route { font-size: 11px; color: var(--text-label); font-family: var(--font); white-space: nowrap; flex-shrink: 0; font-weight: 400; }
.t-addr  { font-size: 11px; font-weight: 400; color: var(--text-secondary); font-family: var(--font-sans); margin-top: 2px; }
.t-copy-addr {
  cursor: pointer;
  border-radius: 4px;
  padding: 1px 3px;
  margin: 0 -3px;
  transition: background 0.15s, color 0.15s;
  position: relative;
}
.t-copy-addr:hover { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.t-copy-addr.copied::after {
  content: 'copied!';
  position: absolute;
  left: 50%; top: -22px;
  transform: translateX(-50%);
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 6px;
  font-size: 10px;
  color: var(--text-primary);
  white-space: nowrap;
  pointer-events: none;
}

.t-proto {
  font-size: 11px;
  font-weight: 500;
  padding: 3px 8px;
  border-radius: 20px;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  transition: background 0.22s ease, color 0.22s ease, opacity 0.18s ease, transform 0.22s cubic-bezier(.22,1,.36,1);
}
.t-proto.proto-active { background: var(--badge-active-bg); color: var(--badge-active-text); }
.t-proto.proto-off    { background: var(--proto-bg);        color: var(--proto-text); }

.t-del {
  background: var(--del-bg);
  border: 1px solid var(--del-border);
  cursor: pointer;
  color: var(--del-text);
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px;
  border-radius: var(--radius-sm);
  transition: background 0.15s, color 0.15s;
  flex-shrink: 0;
}
.t-del:hover { background: var(--danger-bg); color: var(--danger-text); border-color: transparent; }
.t-del svg {
  width: 13px; height: 13px;
  stroke: currentColor; fill: none;
  stroke-width: 2; stroke-linecap: round;
}

.empty {
  text-align: center;
  padding: 2.5rem 1rem;
  color: var(--text-label);
  font-size: 12px;
}
.empty svg {
  width: 28px; height: 28px;
  stroke: var(--text-label); fill: none;
  stroke-width: 1.4; stroke-linecap: round; stroke-linejoin: round;
  display: block; margin: 0 auto 10px; opacity: 0.4;
}

/* ── Login ── */
.login-page {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  background: var(--bg-page);
  padding: 1rem;
}
.login-box {
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 2rem;
  width: 100%; max-width: 320px;
}
.login-logo { display: flex; align-items: center; gap: 10px; margin-bottom: 1.5rem; }
.login-field { margin-bottom: 10px; }
.login-field label {
  display: block;
  font-size: 12px; font-weight: 400; color: var(--text-secondary);
  margin-bottom: 6px; font-family: var(--font-sans);
}
.login-field input {
  width: 100%; height: 36px; padding: 0 10px;
  font-size: 13px; font-family: var(--font-sans);
  color: var(--text-primary); background: var(--bg-input);
  border: 1px solid var(--border-input); border-radius: var(--radius-sm);
  outline: none; transition: border-color 0.15s;
}
.login-field input:focus { border-color: var(--border-hover); }
.login-btn {
  width: 100%; height: 36px;
  background: var(--accent); color: var(--accent-text);
  border: none; border-radius: var(--radius-sm);
  font-family: var(--font-sans); font-size: 13px; font-weight: 500;
  cursor: pointer; margin-top: 6px; transition: background 0.15s;
}
.login-btn:hover { background: var(--accent-hover); }
.login-err { color: var(--danger-text); font-size: 11px; margin-top: 8px; text-align: center; }

@media (max-width: 480px) {
  .create-fields { flex-wrap: wrap; }
  .create-fields .field { flex: 1 1 calc(50% - 5px); }
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

    <div id="cards-container">

    <div id="card-nodes" class="card nodes-card">
      <div class="nodes-header" onclick="toggleNodes()">
        <span class="section-label">Edges &amp; Stations</span>
        <svg class="nodes-arrow" id="nodes-arrow" viewBox="0 0 24 24" aria-hidden="true">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </div>
      <div class="nodes-body" id="nodes-body">
        <div class="nodes-cols">
          <div class="nodes-section">
            <div class="nodes-sublabel">Edges</div>
            <div id="edge-list"><div class="empty-sm">No edges</div></div>
          </div>
          <div class="nodes-section">
            <div class="nodes-sublabel">Stations</div>
            <div id="station-list"><div class="empty-sm">No stations</div></div>
          </div>
        </div>
      </div>
    </div>

    <div id="card-tunnels" class="card list-card">
      <div class="list-header" style="display:flex;align-items:center;justify-content:space-between;padding-bottom:8px">
        <span>Tunnels</span>
        <button class="modal-close add-btn" onclick="openCreate()" aria-label="Create tunnel">
          <svg viewBox="0 0 24 24" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        </button>
      </div>
      <div class="tunnel-list" id="tunnel-list"></div>
    </div>

    </div>

    <div class="modal-overlay" id="create-overlay" onclick="handleOverlayClick(event)">
      <div class="modal">
        <div class="modal-header">
          <span class="section-label">Create Tunnel</span>
          <button class="modal-close" onclick="closeCreate()" aria-label="Close">
            <svg viewBox="0 0 24 24" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
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
    </div>

  </div>
</div>

<div id="ctx-menu" class="ctx-menu">
  <button class="ctx-item danger" id="ctx-delete" onclick="ctxDelete()">
    <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    Delete
  </button>
</div>

<script>
let edges = [];
let stations = [];
let tunnels = [];
let ws = null;
let lastMutation = 0;
let nodesOpen = false;

function toggleNodes() {
  nodesOpen = !nodesOpen;
  document.getElementById('nodes-body').classList.toggle('open', nodesOpen);
  document.getElementById('nodes-arrow').classList.toggle('open', nodesOpen);
}

/* ── Context menu ── */
let ctxTarget = null; // { type: 'edge'|'station', id: string }

function openCtxMenu(e, type, id) {
  e.preventDefault();
  ctxTarget = { type, id };
  const menu = document.getElementById('ctx-menu');
  menu.classList.add('open');
  // Position near cursor, keep within viewport
  const mw = 160, mh = 48;
  const x = Math.min(e.clientX, window.innerWidth  - mw - 8);
  const y = Math.min(e.clientY, window.innerHeight - mh - 8);
  menu.style.left = x + 'px';
  menu.style.top  = y + 'px';
}

function closeCtxMenu() {
  document.getElementById('ctx-menu').classList.remove('open');
  ctxTarget = null;
}

function ctxDelete() {
  if (!ctxTarget) return;
  if (ctxTarget.type === 'edge')    deleteEdge(ctxTarget.id);
  if (ctxTarget.type === 'station') deleteStation(ctxTarget.id);
  closeCtxMenu();
}

document.addEventListener('contextmenu', function(e) {
  const row = e.target.closest('[data-ctx-type]');
  if (row) {
    openCtxMenu(e, row.dataset.ctxType, row.dataset.ctxId);
  } else {
    closeCtxMenu();
  }
});
document.addEventListener('click',   function(e) { if (!e.target.closest('#ctx-menu')) closeCtxMenu(); });
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeCtxMenu(); });

function openCreate() {
  document.getElementById('create-overlay').classList.add('open');
}
function closeCreate() {
  document.getElementById('create-overlay').classList.remove('open');
}
function handleOverlayClick(e) {
  if (e.target === document.getElementById('create-overlay')) closeCreate();
}

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

/* ── Item drag-to-reorder (Trello style) ── */
let activeDragList = null; // set to listEl while a drag is in progress
let tunnelOrder   = [];
let edgeOrder     = [];
let stationOrder  = [];
(function loadOrders() {
  try { tunnelOrder  = JSON.parse(localStorage.getItem('tunnel-order')  || '[]'); } catch(e) {}
  try { edgeOrder    = JSON.parse(localStorage.getItem('edge-order')    || '[]'); } catch(e) {}
  try { stationOrder = JSON.parse(localStorage.getItem('station-order') || '[]'); } catch(e) {}
})();

function applyOrder(arr, order) {
  if (!order.length) return arr.slice();
  const out = order.map(function(id) { return arr.find(function(x) { return x.id === id; }); }).filter(Boolean);
  arr.forEach(function(x) { if (!order.includes(x.id)) out.push(x); });
  return out;
}

// Makes children of listEl sortable by pointer drag.
// idAttr: data attribute on each item holding its id.
// orderArr/orderKey: the persistent order array and its localStorage key.
function makeSortable(listEl, idAttr, orderArr, orderKey) {
  listEl.addEventListener('pointerdown', function startDrag(e) {
    const item = e.target.closest('[' + idAttr + ']');
    if (!item || item.parentNode !== listEl) return;
    // Don't drag when clicking buttons or toggle badges
    if (e.target.closest('button') || e.target.closest('.t-proto[data-toggle-id]')) return;

    const startX = e.clientX, startY = e.clientY;
    let started = false;
    let flyEl = null, ghostEl = null;
    let offX, offY, w, h;

    function onMove(ev) {
      if (!started) {
        if (Math.abs(ev.clientX - startX) < 5 && Math.abs(ev.clientY - startY) < 5) return;
        started = true;
        activeDragList = listEl;
        document.body.classList.add('no-select');
        const rect = item.getBoundingClientRect();
        w = rect.width; h = rect.height;
        offX = startX - rect.left; offY = startY - rect.top;

        // Ghost placeholder
        ghostEl = document.createElement('div');
        ghostEl.className = 'item-ghost';
        ghostEl.style.height = h + 'px';
        ghostEl.style.width  = w + 'px';
        listEl.insertBefore(ghostEl, item);
        item.remove();

        // Flying clone
        flyEl = item.cloneNode(true);
        flyEl.classList.add('item-flying');
        flyEl.style.width = w + 'px';
        flyEl.style.left  = (ev.clientX - offX) + 'px';
        flyEl.style.top   = (ev.clientY - offY) + 'px';
        document.body.appendChild(flyEl);
      }

      flyEl.style.left = (ev.clientX - offX) + 'px';
      flyEl.style.top  = (ev.clientY - offY) + 'px';

      // Move ghost to right slot
      const sibs = Array.from(listEl.children).filter(function(el) { return el !== ghostEl; });
      let before = null;
      for (let i = 0; i < sibs.length; i++) {
        const r = sibs[i].getBoundingClientRect();
        if (ev.clientY < r.top + r.height / 2) { before = sibs[i]; break; }
      }
      if (before) listEl.insertBefore(ghostEl, before);
      else listEl.appendChild(ghostEl);
    }

    function onUp() {
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup',   onUp);
      document.removeEventListener('pointercancel', onUp);
      document.body.classList.remove('no-select');
      activeDragList = null;
      if (!started) return;

      listEl.insertBefore(item, ghostEl);
      ghostEl.remove();
      flyEl.remove();

      // Landing pop
      item.style.transition = 'transform 0.18s cubic-bezier(.22,1,.36,1)';
      item.style.transform = 'scale(1.015)';
      requestAnimationFrame(function() { requestAnimationFrame(function() {
        item.style.transform = '';
        setTimeout(function() { item.style.transition = ''; }, 180);
      }); });

      // Persist new order
      const newOrder = Array.from(listEl.querySelectorAll('[' + idAttr + ']')).map(function(el) {
        return el.getAttribute(idAttr);
      });
      orderArr.length = 0;
      newOrder.forEach(function(id) { orderArr.push(id); });
      localStorage.setItem(orderKey, JSON.stringify(newOrder));
    }

    document.addEventListener('pointermove',   onMove);
    document.addEventListener('pointerup',     onUp);
    document.addEventListener('pointercancel', onUp);
  });
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
  if (activeDragList === el) return;
  const sorted = applyOrder(edges, edgeOrder);
  if (!sorted.length) { el.innerHTML = '<div class="empty-sm">No edges</div>'; return; }
  el.innerHTML = sorted.map(function(e) {
    const cls = e.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row" data-edge-sort-id="' + esc(e.id) + '" data-ctx-type="edge" data-ctx-id="' + esc(e.id) + '">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-name">' + esc(e.name) + '</span>' +
    '</div>';
  }).join('');
  makeSortable(el, 'data-edge-sort-id', edgeOrder, 'edge-order');
}

function renderStations() {
  const el = document.getElementById('station-list');
  if (activeDragList === el) return;
  const sorted = applyOrder(stations, stationOrder);
  if (!sorted.length) { el.innerHTML = '<div class="empty-sm">No stations</div>'; return; }
  el.innerHTML = sorted.map(function(s) {
    const cls = s.status === 'online' ? 'online' : 'offline';
    return '<div class="node-row" data-station-sort-id="' + esc(s.id) + '" data-ctx-type="station" data-ctx-id="' + esc(s.id) + '">' +
      '<span class="node-dot ' + cls + '"></span>' +
      '<span class="node-name">' + esc(s.name) + '</span>' +
    '</div>';
  }).join('');
  makeSortable(el, 'data-station-sort-id', stationOrder, 'station-order');
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
  if (activeDragList === list) return;
  const sorted = applyOrder(tunnels, tunnelOrder);
  if (!sorted.length) {
    list.innerHTML = '<div class="empty"><svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><line x1="12" y1="7" x2="5" y2="17"/><line x1="12" y1="7" x2="19" y2="17"/><line x1="5" y1="19" x2="19" y2="19"/></svg>no tunnels yet</div>';
    return;
  }
  list.innerHTML = sorted.map(function(t) {
    const edge    = edges.find(function(e)   { return e.id === t.edge_id; });
    const station = stations.find(function(s) { return s.id === t.station_id; });
    const edgeOnline    = edge    && edge.status    === 'online';
    const stationOnline = station && station.status === 'online';
    const enabled = t.enabled !== false;
    const badgeCls = (!enabled || !(edgeOnline && stationOnline)) ? 'idle' : 'active';
    const badgeTxt = !enabled ? 'off' : (edgeOnline && stationOnline) ? 'active' : 'idle';
    const edgeName    = edge    ? esc(edge.name)    : '?';
    const stationName = station ? esc(station.name) : '?';
    const stationAddr = station ? (station.address || station.host || '') : '';
    const remoteAddr  = stationAddr ? esc(stationAddr) + ':' + t.remote_port : ':' + t.remote_port;
    const protoCls = 'proto-' + (badgeCls === 'active' ? 'active' : 'off');
    return '<div class="tunnel-item" data-tunnel-sort-id="' + esc(t.id) + '">' +
      '<span class="t-proto ' + protoCls + '" data-toggle-id="' + esc(t.id) + '">' + esc(t.protocol) + '</span>' +
      '<div>' +
        '<div class="t-name-row">' +
          '<span class="t-name">' + esc(t.name) + '</span>' +
          '<span class="t-route">' + edgeName + ' \u2192 ' + stationName + '</span>' +
        '</div>' +
        '<div class="t-addr">' + esc(t.local_host) + ':' + t.local_port + ' \u2192 ' +
          '<span class="t-copy-addr" data-copy="' + remoteAddr + '" title="click to copy">' + remoteAddr + '</span>' +
        '</div>' +
      '</div>' +
      '<span class="t-bytes">' + formatBytes(t.bytes || 0) + '</span>' +
      '<button class="t-del" data-tunnel-id="' + esc(t.id) + '" aria-label="Delete">' + DEL_SVG + '</button>' +
    '</div>';
  }).join('');
  makeSortable(list, 'data-tunnel-sort-id', tunnelOrder, 'tunnel-order');
}

document.addEventListener('click', function(e) {
  const badge = e.target.closest('.t-proto[data-toggle-id]');
  if (badge) { toggleTunnel(badge.dataset.toggleId); return; }

  const copyEl = e.target.closest('.t-copy-addr[data-copy]');
  if (copyEl) {
    navigator.clipboard.writeText(copyEl.dataset.copy).then(function() {
      copyEl.classList.add('copied');
      setTimeout(function() { copyEl.classList.remove('copied'); }, 1500);
    });
    return;
  }

  const btn = e.target.closest('.t-del');
  if (!btn) return;
  if (btn.dataset.tunnelId)  deleteTunnel(btn.dataset.tunnelId);
  if (btn.dataset.edgeId)    deleteEdge(btn.dataset.edgeId);
  if (btn.dataset.stationId) deleteStation(btn.dataset.stationId);
});

function updateBadge(id) {
  const proto = document.querySelector('.t-proto[data-toggle-id="' + id + '"]');
  if (!proto) return;
  const t = tunnels.find(function(x) { return x.id === id; });
  if (!t) return;
  const edge    = edges.find(function(e) { return e.id === t.edge_id; });
  const station = stations.find(function(s) { return s.id === t.station_id; });
  const edgeOnline    = edge    && edge.status    === 'online';
  const stationOnline = station && station.status === 'online';
  const enabled  = t.enabled !== false;
  const isActive = enabled && edgeOnline && stationOnline;
  proto.className = 't-proto ' + (isActive ? 'proto-active' : 'proto-off');
}

async function toggleTunnel(id) {
  lastMutation = Date.now();
  const idx = tunnels.findIndex(function(t) { return t.id === id; });
  if (idx === -1) return;

  // Animate proto badge: shrink + fade out, swap, grow + fade in
  const proto = document.querySelector('.t-proto[data-toggle-id="' + id + '"]');
  if (proto) {
    proto.style.opacity = '0';
    proto.style.transform = 'scale(0.7)';
  }

  // Optimistic flip after short delay (mid-fade)
  setTimeout(function() {
    tunnels[idx] = Object.assign({}, tunnels[idx], { enabled: tunnels[idx].enabled === false });
    updateBadge(id);
    const p = document.querySelector('.t-proto[data-toggle-id="' + id + '"]');
    if (p) {
      p.style.opacity = '0';
      p.style.transform = 'scale(0.7)';
      requestAnimationFrame(function() { requestAnimationFrame(function() {
        p.style.opacity = '';
        p.style.transform = '';
      }); });
    }
  }, 120);

  const res = await fetch('/api/tunnels/' + id + '/toggle', { method: 'POST' });
  if (res.ok) {
    const data = await res.json();
    const i = tunnels.findIndex(function(t) { return t.id === id; });
    if (i !== -1) { tunnels[i] = data.tunnel; updateBadge(id); }
  }
}

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
    closeCreate();
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

function formatBytes(b) {
  if (b <= 0) return '0.0 MB';
  const mb = b / (1024 * 1024);
  if (mb < 1000) return mb.toFixed(1) + ' MB';
  const gb = b / (1024 * 1024 * 1024);
  if (gb < 1000) return gb.toFixed(1) + ' GB';
  const tb = b / (1024 * 1024 * 1024 * 1024);
  return tb.toFixed(1) + ' TB';
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
        const traffic = await getTraffic(env);
        server.send(JSON.stringify({
          edges: withStatus(edges),
          stations: withStatus(stations),
          tunnels: tunnels.map(t => ({ ...t, bytes: traffic[t.id] ?? 0 })),
        }));
      } catch {}
    };
    await sendState();
    const timer = setInterval(sendState, 2500);
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
    const body = await request.json() as { id: string; name: string; control_port: number; cert_fingerprint: string; host?: string; address?: string };
    const now = new Date().toISOString();
    // Prefer the IPv4 address explicitly sent by the station; fall back to CF-Connecting-IP
    const host = body.host || request.headers.get('CF-Connecting-IP') || '';
    const address = body.address || '';
    const stations = await getStations(env);
    let station = stations.find(s => s.id === body.id);
    if (station) {
      station.name = body.name;
      station.controlPort = body.control_port;
      station.certFingerprint = body.cert_fingerprint;
      station.host = host;
      station.address = address;
      station.lastSeen = now;
    } else {
      station = { id: body.id, name: body.name, controlPort: body.control_port, certFingerprint: body.cert_fingerprint, host, address, registeredAt: now, lastSeen: now, status: 'online' };
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
    // When polling for a specific station, exclude disabled tunnels so the station stops listening
    if (stationFilter) tunnels = tunnels.filter(t => t.station_id === stationFilter && t.enabled !== false);
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
      enabled: true,
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

  const tunnelToggleMatch = path.match(/^\/api\/tunnels\/([^/]+)\/toggle$/);
  if (tunnelToggleMatch && method === 'POST') {
    const [, tunnelId] = tunnelToggleMatch;
    const tunnels = await getTunnels(env);
    const tunnel = tunnels.find(t => t.id === tunnelId);
    if (!tunnel) return json({ error: 'not found' }, 404);
    tunnel.enabled = tunnel.enabled === false ? true : false;
    await saveTunnels(env, tunnels);
    return json({ tunnel });
  }

  if (path === '/api/traffic' && method === 'POST') {
    if (!secretOk) return unauthorized();
    const updates = await request.json() as Record<string, number>;
    const traffic = await getTraffic(env);
    for (const [id, bytes] of Object.entries(updates)) {
      traffic[id] = Math.max(traffic[id] || 0, bytes); // keep highest ever seen; never go backwards
    }
    await saveTraffic(env, traffic);
    return json({ ok: true });
  }

  return new Response('Not Found', { status: 404 });
}
