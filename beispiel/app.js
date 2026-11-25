'use strict';
// Beispiel-App für „Anmelden mit Alltag“ (OpenID Connect): zeigt, was eine fremde App beim Anmelden bekommt.
// Node ≥ 20, keine Pakete. Umgebung: ALLTAG_CLIENT_ID, ALLTAG_CLIENT_SECRET, optional ALLTAG_ISSUER, PUBLIC_URL, PORT.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ISSUER = (process.env.ALLTAG_ISSUER || 'https://accounts.alltag-app.de').replace(/\/+$/, '');
const CLIENT_ID = process.env.ALLTAG_CLIENT_ID || '';
const CLIENT_SECRET = process.env.ALLTAG_CLIENT_SECRET || '';
const KEY_FILE = path.join(__dirname, '.session-key'); // Sitzungen überstehen Neustarts
const KEY = (() => { try { return fs.readFileSync(KEY_FILE, 'utf8'); } catch { const k = crypto.randomBytes(32).toString('hex'); try { fs.writeFileSync(KEY_FILE, k, { mode: 0o600 }); } catch { /* nur im Speicher */ } return k; } })();

const b64u = (b) => Buffer.from(b).toString('base64url');
const sign = (v) => crypto.createHmac('sha256', KEY).update(v).digest('base64url');
const seal = (obj) => { const p = b64u(JSON.stringify(obj)); return `${p}.${sign(p)}`; };
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const open = (v) => { const [p, s] = String(v || '').split('.'); if (!p || !s || !crypto.timingSafeEqual(sha(sign(p)), sha(s))) return null; try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o : null; } catch { return null; } };
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter(([k]) => k));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Anbieter-Daten (Discovery, Schlüssel) zwischenspeichern
let meta = null, jwks = null;
const getJson = async (url, opts) => { const r = await fetch(url, { ...opts, signal: AbortSignal.timeout(8000) }); const j = await r.json().catch(() => ({})); if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), { body: j }); return j; };
const discovery = async () => (meta ||= await getJson(`${ISSUER}/.well-known/openid-configuration`));
async function keyFor(kid) {
  if (!jwks?.keys.some((k) => k.kid === kid)) jwks = await getJson((await discovery()).jwks_uri); // neuer Schlüssel → neu laden
  const k = jwks.keys.find((x) => x.kid === kid);
  if (!k) throw new Error('Signaturschlüssel unbekannt');
  return crypto.createPublicKey({ key: k, format: 'jwk' });
}
// id_token prüfen: Signatur (RS256), Aussteller, Empfänger, Ablauf, nonce
async function verifyIdToken(token, { nonce, issuer = ISSUER, audience = CLIENT_ID, key = keyFor }) {
  const [h, p, s] = String(token).split('.');
  const head = JSON.parse(Buffer.from(h, 'base64url')), claims = JSON.parse(Buffer.from(p, 'base64url'));
  if (head.alg !== 'RS256') throw new Error('falsches Verfahren');
  if (!crypto.verify('sha256', Buffer.from(`${h}.${p}`), await key(head.kid), Buffer.from(s, 'base64url'))) throw new Error('Signatur stimmt nicht');
  if (claims.iss !== issuer) throw new Error('falscher Aussteller');
  if (claims.aud !== audience) throw new Error('falscher Empfänger');
  if (!(claims.exp > Date.now() / 1000)) throw new Error('abgelaufen');
  if (claims.nonce !== nonce) throw new Error('nonce stimmt nicht');
  return { head, claims };
}

const ICON = `<svg viewBox="0 0 100 100" aria-hidden="true"><defs><linearGradient id="a" gradientUnits="userSpaceOnUse" x1="22" y1="0" x2="78" y2="0"><stop offset="0" stop-color="#5b8cff"/><stop offset=".55" stop-color="#ff5f86"/><stop offset="1" stop-color="#ffae57"/></linearGradient></defs><rect width="100" height="100" rx="22.5" fill="#1a2550"/><path d="M22 58A28 28 0 0 1 78 58" fill="none" stroke="#fff" stroke-opacity=".16" stroke-width="9" stroke-linecap="round"/><path d="M22 58A28 28 0 0 1 58.65 31.37" fill="none" stroke="url(#a)" stroke-width="9" stroke-linecap="round"/><line x1="18" y1="72" x2="82" y2="72" stroke="#fff" stroke-opacity=".3" stroke-width="5.5" stroke-linecap="round"/><circle cx="58.65" cy="31.37" r="7.2" fill="#fff" stroke="#ff6f86" stroke-width="3.4"/></svg>`;
const CSS = `*{box-sizing:border-box}body{margin:0;min-height:100vh;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#e8ecf7;background:radial-gradient(800px 500px at 90% 0,rgba(255,95,134,.18),transparent 60%),linear-gradient(#141c3d,#0c1229)}
main{max-width:640px;margin:0 auto;padding:48px 16px}h1{font-size:30px;margin:0 0 8px}p{color:#b7c0da}.tag{display:inline-block;padding:4px 12px;border-radius:99px;background:rgba(255,255,255,.08);font-size:13px;color:#cfd6ea;margin-bottom:18px}
.card{background:#1a2347;border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:22px;margin:20px 0}.alltag{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;padding:14px;border:0;border-radius:14px;background:#2e6bf0;color:#fff;font:600 17px system-ui,sans-serif;cursor:pointer;text-decoration:none}
.alltag svg{width:28px;height:28px}label{display:flex;gap:10px;align-items:center;margin:14px 0 0;color:#cfd6ea;font-size:15px}input{width:18px;height:18px;accent-color:#2e6bf0}
table{width:100%;border-collapse:collapse;font-size:15px}td{padding:8px 0;border-top:1px solid rgba(255,255,255,.08);vertical-align:top;overflow-wrap:anywhere}td:first-child{color:#8f9ab8;width:40%;padding-right:10px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}pre{white-space:pre-wrap;word-break:break-all;background:#10172f;border-radius:12px;padding:12px;color:#cdd6f0}ol{color:#b7c0da;padding-left:20px}li{margin:6px 0}
.ok{color:#5fd4b0}.err{color:#ff8aa6}.small{font-size:13px;color:#8f9ab8}.secondary{background:transparent;border:1px solid rgba(255,255,255,.2);color:#e8ecf7}a{color:#8fb0ff}`;
const CSP = `default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self' ${ISSUER}; frame-ancestors 'none'; base-uri 'none'`;
function page(res, body, { status = 200, cookies: set = [] } = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...(set.length ? { 'Set-Cookie': set } : {}) });
  res.end(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Test: Anmelden mit Alltag</title><style>${CSS}</style></head><body><main><span class="tag">Test-App</span>${body}</main></body></html>`);
}
const go = (res, to, set = []) => { res.writeHead(303, { Location: to, 'Set-Cookie': set, 'Cache-Control': 'no-store' }); res.end(); };
const secure = (req) => (process.env.PUBLIC_URL || '').startsWith('https:') || req.headers['x-forwarded-proto'] === 'https';
const cookie = (req, name, value, maxAge) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`;
const base = (req) => (process.env.PUBLIC_URL || `${secure(req) ? 'https' : 'http'}://${req.headers.host}`).replace(/\/+$/, '');

function home(req, res, s, note = '') {
  if (!CLIENT_ID || !CLIENT_SECRET) return page(res, `<h1>Noch nicht eingerichtet</h1><p>Trag die App in der Alltag-Verwaltung unter „Anmelden mit Alltag“ ein (Rücksprung-Adresse <code>${esc(base(req))}/callback</code>) und setz danach <code>ALLTAG_CLIENT_ID</code> und <code>ALLTAG_CLIENT_SECRET</code>.</p>`);
  if (!s) return page(res, `<h1>Anmelden mit Alltag</h1><p>Diese Seite ist eine kleine fremde App. Sie hat keine eigenen Konten, sondern lässt dich mit deinem Alltag-Konto anmelden, so wie andere Seiten „Anmelden mit Google“ anbieten.</p>${note}
    <div class="card"><form method="get" action="/login"><button class="alltag">${ICON}Anmelden mit Alltag</button><label><input type="checkbox" name="email" value="1"> E-Mail-Adresse mit anfragen</label></form></div>
    <ol><li>Du landest auf ${esc(new URL(ISSUER).host)} und meldest dich dort an. Dein Passwort sieht diese App nie.</li><li>Beim ersten Mal fragt Alltag, ob diese App deinen Namen (und die E-Mail) bekommen darf.</li><li>Alltag schickt dich mit einem Einmal-Code zurück. Diese App tauscht ihn gegen ein signiertes Ausweis-Token und zeigt dir, was drinsteht.</li></ol>`);
  const c = s.claims, u = s.userinfo || {};
  const rows = (o) => Object.entries(o).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(typeof v === 'number' && /^(iat|exp)$/.test(k) ? `${v} (${new Date(v * 1000).toLocaleString('de-DE')})` : v)}</td></tr>`).join('');
  page(res, `<h1>Hallo ${esc(c.name || c.preferred_username)}!</h1><p class="ok">Du bist mit Alltag angemeldet. Die Signatur des Ausweis-Tokens ist geprüft (RS256, Schlüssel von ${esc(ISSUER)}).</p>${note}
    <div class="card"><h2 style="margin-top:0;font-size:18px">Das weiß diese App über dich</h2><table>${rows({ sub: u.sub, name: u.name, preferred_username: u.preferred_username, ...(u.email ? { email: u.email, email_verified: String(u.email_verified) } : {}) })}</table>
      <p class="small"><code>sub</code> ist deine feste Kennung für genau diese App. Eine andere App bekommt eine andere. ${u.email ? '' : 'Die E-Mail fehlt, weil sie nicht angefragt wurde.'}</p></div>
    <div class="card"><h2 style="margin-top:0;font-size:18px">Inhalt des id_token</h2><table>${rows(c)}</table><p class="small">Kopf: <code>${esc(JSON.stringify(s.head))}</code></p></div>
    <form method="post" action="/logout"><button class="alltag secondary">Abmelden</button></form>
    <p class="small">Abmelden beendet nur die Sitzung hier. Bei Alltag bleibst du angemeldet. Den Zugriff dieser App entfernst du unter <a href="${esc(ISSUER)}/konto">Dein Konto</a> → „Verbundene Apps“.</p>`);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), ck = cookies(req);
  try {
    if (req.method === 'GET' && url.pathname === '/') return home(req, res, open(ck.s));
    if (req.method === 'GET' && url.pathname === '/login') {
      if (!CLIENT_ID) return go(res, '/');
      const m = await discovery(), tx = { state: b64u(crypto.randomBytes(16)), nonce: b64u(crypto.randomBytes(16)), verifier: b64u(crypto.randomBytes(32)), email: url.searchParams.get('email') === '1', exp: Date.now() + 10 * 60e3 };
      const q = new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID, redirect_uri: `${base(req)}/callback`, scope: tx.email ? 'openid profile email' : 'openid profile',
        state: tx.state, nonce: tx.nonce, code_challenge: crypto.createHash('sha256').update(tx.verifier).digest('base64url'), code_challenge_method: 'S256' });
      return go(res, `${m.authorization_endpoint}?${q}`, [cookie(req, 'tx', seal(tx), 600)]);
    }
    if (req.method === 'GET' && url.pathname === '/callback') {
      const tx = open(ck.tx), q = url.searchParams, clear = cookie(req, 'tx', '', 0);
      const fail = (msg) => { res.setHeader('Set-Cookie', clear); return home(req, res, null, `<p class="err">${esc(msg)}</p>`); };
      if (!tx || q.get('state') !== tx.state) return fail('Die Anmeldung ist abgelaufen oder gehört nicht zu diesem Browser. Bitte noch einmal.');
      if (q.get('iss') && q.get('iss') !== ISSUER) return fail('Die Antwort kam vom falschen Anbieter.');
      if (q.get('error')) return fail(q.get('error') === 'access_denied' ? 'Du hast die Anmeldung abgebrochen.' : `Alltag meldet: ${q.get('error')}`);
      const m = await discovery();
      const t = await getJson(m.token_endpoint, { method: 'POST', headers: { Authorization: `Basic ${Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: q.get('code') || '', redirect_uri: `${base(req)}/callback`, code_verifier: tx.verifier }) });
      const { head, claims } = await verifyIdToken(t.id_token, { nonce: tx.nonce });
      const userinfo = await getJson(m.userinfo_endpoint, { headers: { Authorization: `Bearer ${t.access_token}` } });
      if (userinfo.sub !== claims.sub) return fail('Nutzerdaten passen nicht zum Ausweis-Token.');
      return go(res, '/', [clear, cookie(req, 's', seal({ head, claims, userinfo, exp: Date.now() + 8 * 3600e3 }), 8 * 3600)]);
    }
    if (req.method === 'POST' && url.pathname === '/logout') {
      if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return page(res, '<p>Nicht erlaubt.</p>', { status: 403 });
      return go(res, '/', [cookie(req, 's', '', 0)]);
    }
    page(res, '<h1>Nicht gefunden</h1><p><a href="/">Zur Startseite</a></p>', { status: 404 });
  } catch (e) {
    console.error(e.message, e.body || '');
    page(res, `<h1>Das hat nicht geklappt</h1><p class="err">${esc(e.message)}</p><p><a href="/">Noch einmal</a></p>`, { status: 502 });
  }
});
// Plesk startet die App über eine eigene Startdatei, require.main hilft da nicht
if (process.env.ALLTAG_TEST !== '1') server.listen(process.env.PORT || 5000, () => console.log(`Test-App für Anmelden mit Alltag läuft (Anbieter ${ISSUER})`));
module.exports = { verifyIdToken };
