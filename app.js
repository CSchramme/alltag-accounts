'use strict';
// Alltag-Konten (accounts.alltag-app.de): eigene App neben alltag-app.de. Hier wird registriert (Einladungscode + E-Mail),
// die E-Mail bestätigt, angemeldet, das Passwort zurückgesetzt und das Konto verwaltet. Nach dem Anmelden bekommt die App
// einen Einmal-Code und tauscht ihn über die geschützte API (ACCOUNTS_SECRET) gegen die Kontodaten. Node ≥ 20, keine Pakete.
process.env.TZ ||= 'Europe/Berlin';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createMailer } = require('./mail');

// Einstellungen auch aus .env (NAME=Wert je Zeile); echte Umgebungsvariablen (Plesk) haben Vorrang
const ENV_FILE = process.env.ENV_FILE ?? path.join(__dirname, '.env');
if (ENV_FILE && fs.existsSync(ENV_FILE)) {
  for (const line of fs.readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^(["'])(.*)\1$/, '$2');
  }
}

const PORT = Number(process.env.PORT || 3002);
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const SELF = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/+$/, '');
const API_SECRET = process.env.ACCOUNTS_SECRET || '';
const START_CODE = process.env.START_CODE || '';
const CONTACT = process.env.LEGAL_EMAIL || '';
if (API_SECRET.length < 32) {
  console.error('ACCOUNTS_SECRET fehlt oder ist kürzer als 32 Zeichen. Derselbe Wert gehört auch in die App (alltag-app.de).');
  process.exit(1);
}
const SECURE = SELF.startsWith('https:');
const SCHOOLS = [['edupage', 'EduPage'], ['untis', 'WebUntis'], ['schulmanager', 'Schulmanager'], ['none', 'Keine']];

/* ------------------------------------------------------------------ Dateien */
fs.mkdirSync(DATA, { recursive: true, mode: 0o700 });
const file = (n) => path.join(DATA, n);
const load = (n, d) => { try { return JSON.parse(fs.readFileSync(file(n), 'utf8')); } catch { return d; } };
const save = (n, v) => { // atomar: ein Absturz beim Schreiben zerstört die alte Datei nicht
  const tmp = `${file(n)}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(v), { mode: 0o600 });
  fs.renameSync(tmp, file(n));
};
const SECRET = load('secret.json', null) || (() => { const s = crypto.randomBytes(32).toString('hex'); save('secret.json', s); return s; })();
const accounts = () => load('accounts.json', []);
const saveAccounts = (l) => save('accounts.json', l);
const invites = () => load('invites.json', []);
const saveInvites = (l) => save('invites.json', l);
const deleted = () => load('deleted.json', []); // gelöschte Konten (30 Tage): die App löscht dann deren Daten
const mail = createMailer({ dir: file('mails'), from: process.env.MAIL_FROM || 'Alltag <noreply@alltag-app.de>',
  host: process.env.SMTP_HOST, port: process.env.SMTP_PORT || 587, user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' });

/* ------------------------------------------------------------------ Hilfen */
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
const rand = () => crypto.randomBytes(24).toString('base64url');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(String(pw), salt, 64).toString('hex') });
const checkPw = (a, pw) => crypto.timingSafeEqual(Buffer.from(hashPw(pw, a.salt).hash, 'hex'), Buffer.from(a.hash, 'hex'));
const WEAK = /^(.)\1+$|^(0?123456789?0?|12345678|87654321|passwort\d*|password\d*|qwertz\w*|qwerty\w*|asdfghjk\w*|alltag\w*|schule\w*|edupage\w*)$/i;
const weakPw = (pw, name) => WEAK.test(pw) || (String(name).length >= 4 && pw.toLowerCase().includes(String(name).toLowerCase()));
const EMAIL_RE = /^[^\s@<>"(),;:]{1,64}@[a-z0-9.-]+\.[a-z]{2,}$/i;
const normEmail = (s) => String(s || '').trim().toLowerCase().slice(0, 120);
const mask = (e) => String(e).replace(/^(.)[^@]*(@.*)$/, '$1•••$2');
const supportId = (a) => a.id.replace(/-/g, '').slice(0, 8).toUpperCase().replace(/^(.{4})/, '$1-');
const when = (t) => new Date(t).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
const deviceName = (ua = '') => `${/iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Macintosh/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : 'Unbekanntes Gerät'}, ${
  /Edg\//.test(ua) ? 'Edge' : /Firefox\/|FxiOS/.test(ua) ? 'Firefox' : /Chrome\/|CriOS/.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser'}`;
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter(([k]) => k));
const clientIp = (req) => String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',').pop() || req.socket.remoteAddress || '').trim();
const findLogin = (login) => { const l = String(login || '').trim().toLowerCase(); return accounts().find((a) => a.name === l || (a.email && a.email === l)); };
const emailTaken = (e, exceptId) => accounts().some((a) => a.id !== exceptId && (a.email === e || a.pendingEmail === e));
const pub = (a) => ({ id: a.id, name: a.name, email: a.email || '', emailOk: !!a.emailOk, school: a.school, admin: !!a.admin, demo: !!a.demo, jury: !!a.jury, pro: !!a.pro,
  disabled: !!a.disabled, ver: a.ver || 0, created: a.created });
function update(id, fn) { // ein Konto ändern und sichern; gibt das geänderte Konto zurück
  const list = accounts(), a = list.find((x) => x.id === id);
  if (!a) return null;
  fn(a);
  saveAccounts(list);
  return a;
}

// Bremse gegen Raten und Mail-Fluten: je Schlüssel (IP, Konto) höchstens 10 Fehlversuche in 15 Minuten
const tries = new Map();
function throttled(...keys) {
  const since = Date.now() - 15 * 60e3;
  return keys.some((k) => { const l = (tries.get(k) || []).filter((t) => t > since); tries.set(k, l); return l.length >= 10; });
}
const strike = (...keys) => { if (tries.size > 20000) tries.clear(); for (const k of keys) tries.set(k, [...(tries.get(k) || []), Date.now()]); };
const pause = () => new Promise((r) => setTimeout(r, 600));

// Einladungscodes: 6 Ziffern, einzeln 7 Tage und einmal gültig; Sammelcode (Flyer) für `uses` Anmeldungen, 30–90 Tage
const inviteEnd = (x) => Date.parse(x.created) + (x.days || 7) * 864e5;
const usedCount = (x) => (x.uses ? (x.used || []).length : x.usedBy ? 1 : 0);
const inviteOpen = (x) => usedCount(x) < (x.uses || 1) && Date.now() < inviteEnd(x);
const pubInvites = () => invites().slice(-300).map(({ used, ...x }) => ({ ...x, usedCount: usedCount({ ...x, used }), open: inviteOpen({ ...x, used }), expires: new Date(inviteEnd(x)).toISOString() }));
function newInvite(list) { let c; do c = String(crypto.randomInt(0, 1e6)).padStart(6, '0'); while (list.some((x) => x.code === c && inviteOpen(x))); return c; }
const regFails = []; // falsche Einladungscodes, alle zusammen: nach 30 in einer Stunde pausiert das Registrieren

// Einmal-Links (Bestätigen, Passwort neu): gespeichert wird nur der Hash, jeder Link gilt einmal
function newLink(kind, id, hours, extra = {}) {
  const t = rand(), now = Date.now();
  save('links.json', [...load('links.json', []).filter((x) => x.exp > now && !(x.kind === kind && x.id === id)), { h: sha(t).toString('hex'), kind, id, exp: now + hours * 3600e3, ...extra }]);
  return t;
}
function link(kind, t, take) {
  const list = load('links.json', []), h = sha(t || '').toString('hex'), i = list.findIndex((x) => x.kind === kind && x.h === h && x.exp > Date.now());
  if (i < 0) return null;
  const [x] = take ? list.splice(i, 1) : [list[i]];
  if (take) save('links.json', list);
  return x;
}

// Einmal-Codes für die App: 60 Sekunden, nur im Speicher (Passenger hat einen Prozess)
const codes = new Map();
function appUrl(a, next) {
  const code = rand();
  codes.set(code, { id: a.id, exp: Date.now() + 60e3 });
  const n = /^\/(?!\/)[^\s\\]{0,300}$/.test(String(next || '')) ? next : '/'; // nur Pfade innerhalb der App, nie fremde Adressen
  return `${APP_URL}/auth/callback?code=${code}&next=${encodeURIComponent(n)}`;
}
// Die App neu laden lassen (Sperren, Passwort, Löschen wirken dort sofort); klappt es nicht, holt sie es sich selbst alle paar Minuten
const notifyApp = () => fetch(`${APP_URL}/api/accounts-hook`, { method: 'POST', headers: { Authorization: `Bearer ${API_SECRET}` }, signal: AbortSignal.timeout(5000) }).catch(() => {});

/* ------------------------------------------------------------------ Sitzungen */
// Anmeldung hier: „Konto.Ablauf.Signatur“ mit Version des Kontos (Passwort ändern, Sperren → alle Sitzungen enden)
const SESSION_DAYS = 180;
function sessionOf(req) {
  const [id, exp, sig] = String(cookies(req).as || '').split('.');
  const a = sig && Number(exp) > Date.now() && accounts().find((x) => x.id === id);
  return a && !a.disabled && a.emailOk && same(sig, sign(`${id}.${exp}.${a.ver || 0}`)) ? a : null;
}
const cookie = (name, value, maxAge) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE ? '; Secure' : ''}`;
const sessionCookie = (a) => { const exp = String(Date.now() + SESSION_DAYS * 864e5); return cookie('as', `${a.id}.${exp}.${sign(`${a.id}.${exp}.${a.ver || 0}`)}`, SESSION_DAYS * 86400); };
// Zwischenstand nach richtigem Passwort, aber noch ohne bestätigte E-Mail (30 Minuten): Mail neu senden, Adresse ändern
const pendingCookie = (a) => { const exp = String(Date.now() + 30 * 60e3); return cookie('ap', `${a.id}.${exp}.${sign(`p.${a.id}.${exp}`)}`, 1800); };
function pendingOf(req) {
  const [id, exp, sig] = String(cookies(req).ap || '').split('.');
  const a = sig && Number(exp) > Date.now() && same(sig, sign(`p.${id}.${exp}`)) && accounts().find((x) => x.id === id);
  return a && !a.disabled ? a : null;
}

/* ------------------------------------------------------------------ E-Mails */
function mailHtml(lines, button) {
  const p = (t) => `<p style="margin:0 0 14px">${esc(t).replace(/\n/g, '<br>')}</p>`;
  return `<!doctype html><html lang="de"><body style="margin:0;background:#f3f5fb;font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#131a30">
<div style="max-width:520px;margin:0 auto;padding:28px 20px"><div style="background:#fff;border-radius:18px;padding:28px;border:1px solid #dde3f0">
<p style="margin:0 0 18px;font-weight:700;font-size:20px;color:#2e6bf0">Alltag</p>${lines.map(p).join('')}
${button ? `<p style="margin:22px 0"><a href="${esc(button[1])}" style="background:#2e6bf0;color:#fff;text-decoration:none;padding:12px 20px;border-radius:12px;font-weight:600;display:inline-block">${esc(button[0])}</a></p>
<p style="margin:0;color:#5b6478;font-size:13px">Falls der Knopf nicht geht: ${esc(button[1])}</p>` : ''}</div>
<p style="color:#5b6478;font-size:12px;text-align:center;margin-top:16px">Alltag · Kalender, Stundenplan, Hausaufgaben. Alles in einer App.</p></div></body></html>`;
}
const sendMail = (to, subject, lines, button) => mail.send({ to, subject, text: [...lines, button ? `${button[0]}: ${button[1]}` : ''].join('\n\n').trim(), html: mailHtml(lines, button) })
  .catch((e) => console.error(`Mail an ${mask(to)} fehlgeschlagen:`, e.message));
const mailVerify = (a, email) => sendMail(email, 'Bitte bestätige deine E-Mail-Adresse', [`Hallo ${a.name},`,
  'bitte bestätige deine E-Mail-Adresse für Alltag. Der Link gilt 48 Stunden.', 'Wenn du kein Konto angelegt hast, kannst du diese Mail ignorieren.'],
['E-Mail bestätigen', `${SELF}/bestaetigen?t=${newLink('verify', a.id, 48, { email })}`]);
const mailWarn = `Warst du das nicht? Setz bitte sofort dein Passwort zurück, dann werden alle Geräte abgemeldet: ${SELF}/passwort-vergessen`;

/* ------------------------------------------------------------------ Seiten */
const CSP = `default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self' ${new URL(APP_URL).origin}; frame-ancestors 'none'; base-uri 'none'`;
function page(res, title, body, { status = 200, headers = {} } = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin', 'Cross-Origin-Opener-Policy': 'same-origin', // nicht no-referrer: dann schicken Browser bei Formularen „Origin: null“ ...(SECURE ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}), ...headers,
  });
  res.end(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Alltag</title><link rel="icon" href="/icon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css"></head>
<body><main><a class="brand" href="${esc(APP_URL)}/"><img src="/icon.svg" alt="" width="40" height="40"><span>Alltag</span></a>
<section class="card"><h1>${esc(title)}</h1>${body}</section>
<footer><a href="${esc(APP_URL)}/impressum.html">Impressum</a><a href="${esc(APP_URL)}/datenschutz.html">Datenschutz</a></footer></main></body></html>`);
}
const redirect = (res, to, setCookies = []) => { res.writeHead(303, { Location: to, 'Set-Cookie': setCookies, 'Cache-Control': 'no-store', 'Referrer-Policy': 'same-origin' }); res.end(); };
const field = (name, label, attrs = '') => `<label><span>${label}</span><input name="${name}" ${attrs}></label>`;
const hidden = (name, value) => `<input type="hidden" name="${name}" value="${esc(value)}">`;
const err = (m) => (m ? `<p class="error" role="alert">${esc(m)}</p>` : '');
const note = (m) => (m ? `<p class="note">${esc(m)}</p>` : '');
const NOTES = { pw: 'Dein Passwort ist geändert. Melde dich mit dem neuen an.', out: 'Du bist abgemeldet.', del: 'Dein Konto ist gelöscht.' };

function loginPage(res, { next = '', ziel = '', login = '', error = '', info = '', status } = {}) {
  page(res, 'Anmelden', `${note(info)}<form method="post" action="/anmelden">${hidden('next', next)}${hidden('ziel', ziel)}
    ${field('login', 'Benutzername oder E-Mail', `value="${esc(login)}" autocomplete="username" autocapitalize="off" spellcheck="false" required maxlength="120"`)}
    ${field('password', 'Passwort', 'type="password" autocomplete="current-password" required maxlength="200"')}
    ${err(error)}<button>Anmelden</button></form>
    <p class="links"><a href="/passwort-vergessen">Passwort vergessen?</a><a href="/registrieren">Neu hier? Registrieren</a></p>`, { status });
}
function registerPage(res, { v = {}, error = '', status } = {}) {
  const first = !accounts().length;
  page(res, first ? 'Erstes Konto anlegen' : 'Registrieren', `<form method="post" action="/registrieren">
    ${field('code', first ? 'Start-Code (START_CODE)' : 'Einladungscode (6 Ziffern)', `value="${esc(v.code)}" ${first ? '' : 'inputmode="numeric"'} autocomplete="one-time-code" required maxlength="40"`)}
    ${field('name', 'Benutzername', `value="${esc(v.name)}" autocomplete="username" autocapitalize="off" spellcheck="false" required minlength="3" maxlength="30" pattern="[A-Za-z0-9._\\-]+"`)}
    ${field('email', 'E-Mail-Adresse', `type="email" value="${esc(v.email)}" autocomplete="email" required maxlength="120"`)}
    ${field('password', 'Passwort (ab 8 Zeichen)', 'type="password" autocomplete="new-password" required minlength="8" maxlength="200"')}
    <fieldset><legend>Welche Schulsoftware nutzt deine Schule?</legend><div class="choice">${SCHOOLS.map(([k, l]) => `<label><input type="radio" name="school" value="${k}"${(v.school || 'edupage') === k ? ' checked' : ''}><span>${l}</span></label>`).join('')}</div></fieldset>
    <p class="small">Den Zugang zur Schulsoftware gibst du danach in der App ein. Bei „Keine“ trägst du deinen Stundenplan selbst ein. Was mit deinen Daten passiert, steht in der <a href="${esc(APP_URL)}/datenschutz.html">Datenschutzerklärung</a>.</p>
    ${err(error)}<button>Konto anlegen</button></form>
    <p class="links"><a href="/anmelden">Schon ein Konto? Anmelden</a></p>`, { status });
}
function pendingPage(res, a, { info = '', error = '', status } = {}) {
  const mailPart = a.email
    ? `<p>Wir haben eine Mail an <b>${esc(mask(a.email))}</b> geschickt. Klick auf den Link darin, dann geht es weiter.</p>${note(info)}
      <form method="post" action="/bestaetigung-senden"><button class="secondary">Mail noch einmal senden</button></form>
      <details><summary>Andere E-Mail-Adresse verwenden</summary>`
    : `<p>Für Passwort vergessen und Hinweise zur Sicherheit braucht dein Konto jetzt eine E-Mail-Adresse. Wir schicken dir einen Link zum Bestätigen.</p>${note(info)}<div>`;
  page(res, a.email ? 'Bestätige deine E-Mail' : 'E-Mail hinterlegen', `${mailPart}
    <form method="post" action="/email-setzen">${field('email', 'E-Mail-Adresse', 'type="email" autocomplete="email" required maxlength="120"')}${err(error)}<button${a.email ? ' class="secondary"' : ''}>Bestätigungs-Mail senden</button></form>
    ${a.email ? '</details>' : '</div>'}<p class="links"><a href="/anmelden">Zurück zur Anmeldung</a></p>`, { status });
}

// Nach erfolgreicher Anmeldung: Gerät merken (neues Gerät → Hinweis-Mail), Sitzung setzen, weiter zur App oder zum Konto
function finish(req, res, a, { next = '/', ziel = '', firstDevice = false } = {}) {
  const old = String(cookies(req).dev || ''), dev = /^[\w-]{30,40}$/.test(old) ? old : rand(), h = sha(dev).toString('hex').slice(0, 32), ua = deviceName(req.headers['user-agent']);
  const x = update(a.id, (y) => {
    y.devices ||= [];
    const known = y.devices.find((d) => d.h === h);
    if (known) { known.last = new Date().toISOString(); known.ua = ua; return; }
    if (y.devices.length && !firstDevice) sendMail(y.email, 'Neue Anmeldung bei Alltag', [`Hallo ${y.name},`, `dein Konto wurde gerade auf einem neuen Gerät angemeldet: ${ua}, ${when(Date.now())} Uhr.`, 'Warst du das? Dann musst du nichts tun.', mailWarn]);
    y.devices = [...y.devices, { h, ua, first: new Date().toISOString(), last: new Date().toISOString() }].slice(-20);
  });
  redirect(res, ziel === 'konto' ? '/konto' : appUrl(x, next), [sessionCookie(x), cookie('dev', dev, 2 * 365 * 86400), cookie('ap', '', 0)]);
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) { size += c.length; if (size > 20e3) throw Object.assign(new Error('zu groß'), { status: 413 }); chunks.push(c); }
  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
}

/* ------------------------------------------------------------------ Seiten-Routen */
const pages = {
  'GET /': (req, res) => redirect(res, sessionOf(req) ? '/konto' : '/anmelden'),
  // Einstieg aus der App: schon angemeldet → sofort zurück mit Code, sonst Anmeldeseite
  'GET /weiter': (req, res, q) => { const a = sessionOf(req); return a && !a.demo ? redirect(res, appUrl(a, q.get('next'))) : redirect(res, `/anmelden?next=${encodeURIComponent(q.get('next') || '/')}`); },
  'GET /anmelden': (req, res, q) => loginPage(res, { next: q.get('next') || '', ziel: q.get('ziel') || '', info: NOTES[q.get('msg')] || '' }),
  'POST /anmelden': async (req, res) => {
    const f = await readForm(req), login = String(f.login || '').trim().toLowerCase().slice(0, 120), ip = `ip:${clientIp(req)}`, keys = [ip, `login:${login}`];
    const again = (error, status = 401) => loginPage(res, { next: f.next, ziel: f.ziel, login: f.login, error, status });
    if (throttled(...keys)) return again('Zu viele Versuche. Bitte in 15 Minuten erneut.', 429);
    const a = findLogin(login);
    if (!a) { hashPw(String(f.password)); strike(ip); await pause(); return again('Benutzername, E-Mail oder Passwort stimmt nicht.'); } // gleiche Rechenzeit wie bei echtem Konto
    if (!checkPw(a, String(f.password || ''))) { strike(...keys); await pause(); return again('Benutzername, E-Mail oder Passwort stimmt nicht.'); }
    if (a.disabled) return again('Dieses Konto ist gesperrt.', 403);
    if (a.demo) return again('Das Demo-Konto öffnest du in der App über „Demo ansehen“.', 403);
    if (!a.emailOk) { res.setHeader('Set-Cookie', pendingCookie(a)); return pendingPage(res, a); }
    finish(req, res, a, { next: f.next, ziel: f.ziel });
  },
  'GET /registrieren': (req, res, q) => registerPage(res, { v: { code: q.get('code') || '' } }),
  'POST /registrieren': async (req, res) => {
    const f = await readForm(req), ip = `ip:${clientIp(req)}`, name = String(f.name || '').trim().toLowerCase(), email = normEmail(f.email), pw = String(f.password || '');
    const v = { code: f.code, name: f.name, email: f.email, school: f.school };
    const again = (error, status = 400) => registerPage(res, { v, error, status });
    if (throttled(ip)) return again('Zu viele Versuche. Bitte in 15 Minuten erneut.', 429);
    if (!/^[a-z0-9._-]{3,30}$/.test(name)) return again('Benutzername: 3 bis 30 Zeichen, nur Buchstaben, Ziffern, Punkt, Bindestrich und Unterstrich.');
    if (!EMAIL_RE.test(email)) return again('Bitte eine gültige E-Mail-Adresse eingeben.');
    if (pw.length < 8) return again('Das Passwort braucht mindestens 8 Zeichen.');
    if (weakPw(pw, name)) return again('Dieses Passwort ist zu leicht zu erraten. Nimm zum Beispiel drei Wörter, die nichts miteinander zu tun haben.');
    if (!SCHOOLS.some(([k]) => k === f.school)) return again('Bitte wähle aus, welche Schulsoftware deine Schule nutzt.');
    const list = accounts(), inv = invites(), first = !list.length, code = String(f.code || '').trim();
    if (!first) {
      while (regFails.length && regFails[0] < Date.now() - 3600e3) regFails.shift();
      if (regFails.length >= 30) return again('Registrieren ist gerade kurz pausiert. Bitte versuch es in einer Stunde noch einmal.', 429);
    }
    const hit = first ? null : inv.find((x) => inviteOpen(x) && same(x.code, code.replace(/\D/g, '')));
    if (first ? !START_CODE || !same(code.replace(/\s/g, ''), START_CODE.replace(/\s/g, '')) : !hit) {
      if (!first) regFails.push(Date.now());
      strike(ip); await pause();
      return again('Dieser Einladungscode passt nicht, ist abgelaufen oder wurde schon benutzt.', 403);
    }
    if (list.some((x) => x.name === name)) return again('Diesen Benutzernamen gibt es schon.');
    if (emailTaken(email)) return again('Mit dieser E-Mail-Adresse gibt es schon ein Konto. Passwort vergessen? Dann setz es auf der Anmeldeseite zurück.');
    const a = { id: crypto.randomUUID(), name, email, emailOk: false, ...hashPw(pw), school: f.school, admin: first, created: new Date().toISOString(), ver: 0, devices: [] };
    saveAccounts([...list, a]);
    if (hit?.uses) hit.used = [...(hit.used || []), a.id]; else if (hit) Object.assign(hit, { usedBy: a.id, usedAt: a.created });
    if (hit) saveInvites(inv);
    mailVerify(a, email);
    res.setHeader('Set-Cookie', pendingCookie(a));
    pendingPage(res, a, { info: 'Konto angelegt. Jetzt nur noch die E-Mail bestätigen.' });
  },
  'POST /bestaetigung-senden': async (req, res) => {
    const a = pendingOf(req);
    if (!a?.email) return redirect(res, '/anmelden');
    if (throttled(`mail:${a.id}`)) return pendingPage(res, a, { error: 'Es wurden schon viele Mails geschickt. Bitte warte 15 Minuten.', status: 429 });
    strike(`mail:${a.id}`); // jede Mail zählt
    mailVerify(a, a.email);
    pendingPage(res, a, { info: 'Wir haben die Mail noch einmal geschickt. Schau auch im Spam-Ordner nach.' });
  },
  'POST /email-setzen': async (req, res) => {
    const a = pendingOf(req), f = await readForm(req), email = normEmail(f.email);
    if (!a) return redirect(res, '/anmelden');
    if (!EMAIL_RE.test(email)) return pendingPage(res, a, { error: 'Bitte eine gültige E-Mail-Adresse eingeben.', status: 400 });
    if (emailTaken(email, a.id)) return pendingPage(res, a, { error: 'Diese E-Mail-Adresse gehört schon zu einem anderen Konto.', status: 400 });
    if (throttled(`mail:${a.id}`)) return pendingPage(res, a, { error: 'Es wurden schon viele Mails geschickt. Bitte warte 15 Minuten.', status: 429 });
    strike(`mail:${a.id}`);
    const x = update(a.id, (y) => { y.email = email; y.emailOk = false; });
    mailVerify(x, email);
    pendingPage(res, x, { info: 'Wir haben dir eine Mail geschickt.' });
  },
  // Link aus der Mail: Adresse bestätigt → angemeldet und weiter in die App
  'GET /bestaetigen': (req, res, q) => {
    const t = link('verify', q.get('t'), true), a = t && accounts().find((x) => x.id === t.id);
    if (!a || (t.email !== a.email && t.email !== a.pendingEmail)) {
      return page(res, 'Link ungültig', '<p>Dieser Link ist abgelaufen oder wurde schon benutzt. Melde dich an, dann kannst du eine neue Mail anfordern.</p><p class="links"><a href="/anmelden">Zur Anmeldung</a></p>', { status: 400 });
    }
    const before = a.email, changed = a.emailOk && t.email === a.pendingEmail && before !== t.email;
    const x = update(a.id, (y) => { y.email = t.email; y.emailOk = true; delete y.pendingEmail; delete y.legacy; });
    if (changed) sendMail(before, 'Deine E-Mail-Adresse wurde geändert', [`Hallo ${x.name},`, `die E-Mail-Adresse deines Alltag-Kontos ist jetzt ${t.email}.`, `Warst du das nicht? ${CONTACT ? `Schreib bitte an ${CONTACT}.` : 'Melde dich bitte beim Betreiber.'}`]);
    notifyApp();
    if (x.disabled) return page(res, 'Konto gesperrt', '<p>Die E-Mail ist bestätigt, aber dieses Konto ist gesperrt.</p>', { status: 403 });
    finish(req, res, x, { firstDevice: !before || !a.emailOk });
  },
  'GET /passwort-vergessen': (req, res) => page(res, 'Passwort vergessen', `<p>Gib deinen Benutzernamen oder deine E-Mail-Adresse ein. Wir schicken dir einen Link, mit dem du ein neues Passwort festlegst.</p>
    <form method="post" action="/passwort-vergessen">${field('login', 'Benutzername oder E-Mail', 'autocomplete="username" autocapitalize="off" spellcheck="false" required maxlength="120"')}<button>Link senden</button></form>
    <p class="links"><a href="/anmelden">Zurück zur Anmeldung</a></p>`),
  'POST /passwort-vergessen': async (req, res) => {
    const f = await readForm(req), ip = `reset:${clientIp(req)}`, a = findLogin(f.login);
    const done = () => page(res, 'Schau in dein Postfach', '<p>Wenn es zu dieser Angabe ein Konto mit bestätigter E-Mail gibt, kommt gleich eine Mail mit einem Link. Er gilt eine Stunde. Schau auch im Spam-Ordner nach.</p><p class="links"><a href="/anmelden">Zurück zur Anmeldung</a></p>');
    if (throttled(ip) || (a && throttled(`mail:${a.id}`))) { await pause(); return done(); } // immer dieselbe Antwort: verrät nicht, ob es das Konto gibt
    strike(ip);
    if (a && a.email && a.emailOk && !a.disabled && !a.demo) {
      strike(`mail:${a.id}`);
      sendMail(a.email, 'Neues Passwort für Alltag', [`Hallo ${a.name},`, 'jemand (hoffentlich du) möchte das Passwort für dein Alltag-Konto zurücksetzen. Der Link gilt eine Stunde.',
        'Wenn du das nicht warst, ignorier die Mail einfach. Dein Passwort bleibt dann gleich.'], ['Neues Passwort festlegen', `${SELF}/passwort-neu?t=${newLink('reset', a.id, 1)}`]);
    }
    await pause();
    done();
  },
  'GET /passwort-neu': (req, res, q) => {
    if (!link('reset', q.get('t'), false)) return page(res, 'Link ungültig', '<p>Dieser Link ist abgelaufen oder wurde schon benutzt.</p><p class="links"><a href="/passwort-vergessen">Neuen Link anfordern</a></p>', { status: 400 });
    newPasswordPage(res, q.get('t'));
  },
  'POST /passwort-neu': async (req, res) => {
    const f = await readForm(req), t = link('reset', f.t, false), a = t && accounts().find((x) => x.id === t.id), pw = String(f.password || '');
    if (!a) return page(res, 'Link ungültig', '<p>Dieser Link ist abgelaufen oder wurde schon benutzt.</p><p class="links"><a href="/passwort-vergessen">Neuen Link anfordern</a></p>', { status: 400 });
    if (pw.length < 8) return newPasswordPage(res, f.t, 'Das Passwort braucht mindestens 8 Zeichen.');
    if (pw !== f.password2) return newPasswordPage(res, f.t, 'Die beiden Passwörter sind nicht gleich.');
    if (weakPw(pw, a.name)) return newPasswordPage(res, f.t, 'Dieses Passwort ist zu leicht zu erraten.');
    link('reset', f.t, true);
    passwordChanged(a.id, pw);
    redirect(res, '/anmelden?msg=pw', [cookie('as', '', 0)]);
  },
  'GET /konto': (req, res, q) => {
    const a = sessionOf(req);
    if (!a) return redirect(res, '/anmelden?ziel=konto');
    accountPage(res, a, { info: { email: 'Wir haben eine Mail an die neue Adresse geschickt. Erst nach dem Klick auf den Link gilt sie.', pw: 'Dein Passwort ist geändert. Alle anderen Geräte sind abgemeldet.', out: 'Alle anderen Geräte sind abgemeldet.' }[q.get('ok')] || '' });
  },
  'POST /konto/email': async (req, res) => {
    const a = sessionOf(req), f = await readForm(req), email = normEmail(f.email);
    if (!a) return redirect(res, '/anmelden?ziel=konto');
    if (throttled(`acc:${a.id}`)) return accountPage(res, a, { error: 'Zu viele Versuche. Bitte in 15 Minuten erneut.', status: 429 });
    if (!checkPw(a, String(f.password || ''))) { strike(`acc:${a.id}`); await pause(); return accountPage(res, a, { error: 'Das Passwort stimmt nicht.', status: 400 }); }
    if (!EMAIL_RE.test(email)) return accountPage(res, a, { error: 'Bitte eine gültige E-Mail-Adresse eingeben.', status: 400 });
    if (email === a.email) return accountPage(res, a, { error: 'Das ist schon deine Adresse.', status: 400 });
    if (emailTaken(email, a.id)) return accountPage(res, a, { error: 'Diese E-Mail-Adresse gehört schon zu einem anderen Konto.', status: 400 });
    const x = update(a.id, (y) => { y.pendingEmail = email; });
    mailVerify(x, email);
    redirect(res, '/konto?ok=email');
  },
  'POST /konto/passwort': async (req, res) => {
    const a = sessionOf(req), f = await readForm(req), pw = String(f.password || '');
    if (!a) return redirect(res, '/anmelden?ziel=konto');
    if (throttled(`acc:${a.id}`)) return accountPage(res, a, { error: 'Zu viele Versuche. Bitte in 15 Minuten erneut.', status: 429 });
    if (!checkPw(a, String(f.old || ''))) { strike(`acc:${a.id}`); await pause(); return accountPage(res, a, { error: 'Das bisherige Passwort stimmt nicht.', status: 400 }); }
    if (pw.length < 8 || weakPw(pw, a.name)) return accountPage(res, a, { error: 'Das neue Passwort braucht mindestens 8 Zeichen und darf nicht zu leicht sein.', status: 400 });
    const x = passwordChanged(a.id, pw);
    redirect(res, '/konto?ok=pw', [sessionCookie(x)]); // dieses Gerät bleibt angemeldet
  },
  'POST /konto/abmelden-ueberall': (req, res) => {
    const a = sessionOf(req);
    if (!a) return redirect(res, '/anmelden?ziel=konto');
    const x = update(a.id, (y) => { y.ver = (y.ver || 0) + 1; });
    notifyApp();
    redirect(res, '/konto?ok=out', [sessionCookie(x)]);
  },
  'POST /konto/loeschen': async (req, res) => {
    const a = sessionOf(req), f = await readForm(req);
    if (!a) return redirect(res, '/anmelden?ziel=konto');
    if (throttled(`acc:${a.id}`)) return accountPage(res, a, { error: 'Zu viele Versuche. Bitte in 15 Minuten erneut.', status: 429 });
    if (!checkPw(a, String(f.password || ''))) { strike(`acc:${a.id}`); await pause(); return accountPage(res, a, { error: 'Das Passwort stimmt nicht.', status: 400 }); }
    if (f.sure !== 'ja') return accountPage(res, a, { error: 'Bitte bestätige, dass alles gelöscht werden soll.', status: 400 });
    if (a.admin && !accounts().some((x) => x.admin && x.id !== a.id && !x.disabled)) return accountPage(res, a, { error: 'Du bist der einzige Admin. Mach vorher ein anderes Konto zum Admin.', status: 400 });
    removeAccount(a.id);
    redirect(res, '/anmelden?msg=del', [cookie('as', '', 0)]);
  },
  'GET /abmelden': (req, res) => redirect(res, `${APP_URL}/`, [cookie('as', '', 0)]), // die App hat ihre Sitzung schon beendet
};

function newPasswordPage(res, t, error = '') {
  page(res, 'Neues Passwort', `<form method="post" action="/passwort-neu">${hidden('t', t)}
    ${field('password', 'Neues Passwort (ab 8 Zeichen)', 'type="password" autocomplete="new-password" required minlength="8" maxlength="200"')}
    ${field('password2', 'Noch einmal', 'type="password" autocomplete="new-password" required minlength="8" maxlength="200"')}
    ${err(error)}<button>Passwort speichern</button></form><p class="small">Danach sind alle Geräte abgemeldet.</p>`, { status: error ? 400 : 200 });
}
function passwordChanged(id, pw) {
  const x = update(id, (y) => { Object.assign(y, hashPw(pw)); y.ver = (y.ver || 0) + 1; });
  if (x.email) sendMail(x.email, 'Dein Passwort wurde geändert', [`Hallo ${x.name},`, `das Passwort deines Alltag-Kontos wurde am ${when(Date.now())} Uhr geändert. Alle Geräte wurden abgemeldet.`, mailWarn]);
  notifyApp();
  return x;
}
function removeAccount(id) {
  saveAccounts(accounts().filter((x) => x.id !== id));
  save('deleted.json', [...deleted().filter((d) => Date.now() - Date.parse(d.at) < 30 * 864e5), { id, at: new Date().toISOString() }]);
  notifyApp();
}
function accountPage(res, a, { info = '', error = '', status } = {}) {
  page(res, 'Dein Konto', `${note(info)}${err(error)}
    <dl class="facts"><dt>Benutzername</dt><dd>${esc(a.name)}</dd><dt>E-Mail</dt><dd>${esc(a.email)}${a.pendingEmail ? `<br><small>wartet auf Bestätigung: ${esc(a.pendingEmail)}</small>` : ''}</dd><dt>Support-ID</dt><dd class="code">${esc(supportId(a))}</dd></dl>
    <a class="button" href="${esc(APP_URL)}/">Zur App</a>
    <details><summary>E-Mail-Adresse ändern</summary><form method="post" action="/konto/email">
      ${field('email', 'Neue E-Mail-Adresse', 'type="email" autocomplete="email" required maxlength="120"')}${field('password', 'Dein Passwort', 'type="password" autocomplete="current-password" required')}<button class="secondary">Bestätigungs-Mail senden</button></form></details>
    <details><summary>Passwort ändern</summary><form method="post" action="/konto/passwort">
      ${field('old', 'Bisheriges Passwort', 'type="password" autocomplete="current-password" required')}${field('password', 'Neues Passwort (ab 8 Zeichen)', 'type="password" autocomplete="new-password" required minlength="8"')}<button class="secondary">Passwort ändern</button></form></details>
    <details><summary>Geräte (${(a.devices || []).length})</summary><ul class="devices">${(a.devices || []).slice().reverse().map((d) => `<li><b>${esc(d.ua)}</b><span>zuletzt ${esc(when(d.last))}</span></li>`).join('')}</ul>
      <form method="post" action="/konto/abmelden-ueberall"><button class="secondary">Auf allen anderen Geräten abmelden</button></form></details>
    <details><summary>Konto löschen</summary><p class="small">Löscht dein Konto und alle Daten in der App sofort. Das lässt sich nicht rückgängig machen.</p><form method="post" action="/konto/loeschen">
      ${field('password', 'Dein Passwort', 'type="password" autocomplete="current-password" required')}<label class="check"><input type="checkbox" name="sure" value="ja" required> Ja, alles löschen</label><button class="danger">Konto löschen</button></form></details>
    <p class="links"><a href="/abmelden">Abmelden</a></p>`, { status });
}

/* ------------------------------------------------------------------ API für die App (Bearer ACCOUNTS_SECRET) */
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); };
async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}; } catch { return {}; }
}
const api = {
  // Einmal-Code aus der Weiterleitung → Kontodaten (Code gilt 60 Sekunden und genau einmal)
  'POST /api/exchange': async (req, res) => {
    const { code } = await readJson(req), c = codes.get(String(code || ''));
    codes.delete(String(code || ''));
    const a = c && c.exp > Date.now() && accounts().find((x) => x.id === c.id);
    if (!a || a.disabled || !a.emailOk) return json(res, 400, { error: 'Code ungültig oder abgelaufen' });
    json(res, 200, { account: pub(a) });
  },
  'GET /api/accounts': (req, res) => json(res, 200, { accounts: accounts().map(pub), deleted: deleted() }),
  'PATCH /api/accounts/:id': async (req, res, id) => {
    const b = await readJson(req), list = accounts(), a = list.find((x) => x.id === id);
    if (!a) return json(res, 404, { error: 'nicht gefunden' });
    let password = null;
    if (b.school !== undefined) { if (!SCHOOLS.some(([k]) => k === b.school)) return json(res, 400, { error: 'Unbekannte Schulsoftware' }); a.school = b.school; }
    if (b.reset === true) { // gut abzutippen: ohne 0/o, 1/i/l
      const abc = 'abcdefghjkmnpqrstuvwxyz23456789', r = crypto.randomBytes(8);
      password = `${[...r.subarray(0, 4)].map((x) => abc[x % abc.length]).join('')}-${[...r.subarray(4)].map((x) => abc[x % abc.length]).join('')}`;
      Object.assign(a, hashPw(password)); a.ver = (a.ver || 0) + 1;
    }
    if (typeof b.disabled === 'boolean') { a.disabled = b.disabled; a.ver = (a.ver || 0) + 1; }
    if (typeof b.admin === 'boolean') { if (b.admin && a.demo) return json(res, 400, { error: 'Ein Demo-Konto kann kein Admin sein.' }); a.admin = b.admin; }
    if (typeof b.demo === 'boolean' && b.demo !== !!a.demo) {
      if (b.demo && a.admin) return json(res, 400, { error: 'Ein Admin-Konto kann kein Demo-Konto sein.' });
      a.demo = b.demo; a.ver = (a.ver || 0) + 1;
      if (a.demo) a.emailOk = true; else delete a.jury; // Demo-Konten melden sich über die App an, ohne Mail
    }
    if (typeof b.jury === 'boolean') { if (!a.demo) return json(res, 400, { error: 'Erst als Demo-Konto einrichten.' }); a.jury = b.jury; }
    if (typeof b.pro === 'boolean') a.pro = b.pro; // Pro-Funktionen, schaltet der Admin frei
    saveAccounts(list);
    notifyApp();
    json(res, 200, { account: pub(a), password }); // neues Passwort nur in dieser einen Antwort
  },
  'DELETE /api/accounts/:id': (req, res, id) => {
    if (!accounts().some((x) => x.id === id)) return json(res, 404, { error: 'nicht gefunden' });
    removeAccount(id);
    json(res, 200, { ok: true });
  },
  'GET /api/invites': (req, res) => json(res, 200, { invites: pubInvites() }),
  'POST /api/invites': async (req, res) => {
    const b = await readJson(req), list = invites();
    const days = [30, 60, 90].includes(b.days) ? b.days : 7, uses = Math.min(1000, Math.max(0, Math.trunc(Number(b.uses)) || 0));
    const count = uses ? 1 : Math.min(40, Math.max(1, Math.trunc(Number(b.count)) || 1));
    if (list.filter(inviteOpen).length + count > 200) return json(res, 400, { error: 'Es gibt schon zu viele offene Codes. Lösch erst ein paar.' });
    const created = [];
    for (let i = 0; i < count; i++) {
      const code = newInvite(list);
      list.push({ code, note: String(b.note || '').trim().slice(0, 80), days, ...(uses ? { uses, used: [] } : {}), created: new Date().toISOString(), usedBy: null, usedAt: null });
      created.push(code);
    }
    saveInvites(list);
    // Beta-Test: Einladung gleich per Mail, mit Tester-ID und Link, der den Code schon einträgt
    const email = normEmail(b.email);
    let mailed = false;
    if (email && EMAIL_RE.test(email) && count === 1) {
      const name = String(b.name || '').trim().slice(0, 60), beta = /^BETA-\d{4}$/.test(String(b.betaId || '')) ? b.betaId : '';
      const code = created[0], shown = code.replace(/^(\d{3})(\d{3})$/, '$1 $2');
      sendMail(email, 'Deine Einladung zum Beta-Test von Alltag', [`Hallo${name ? ` ${name}` : ''},`,
        `schön, dass du beim Beta-Test von Alltag mitmachst!${beta ? ` Deine Tester-ID ist ${beta}.` : ''}`,
        `Dein Einladungscode: ${shown}. Er gilt ${days} Tage. Über den Knopf ist er beim Registrieren schon eingetragen.`,
        'Fehler und Ideen meldest du später direkt in der App unter Profil → Beta-Test. Danke fürs Mitmachen!'],
      ['Jetzt registrieren', `${SELF}/registrieren?code=${code}`]);
      mailed = true;
    }
    json(res, 200, { invites: pubInvites(), created, mailed });
  },
  'DELETE /api/invites/:code': (req, res, code) => { saveInvites(invites().filter((x) => x.code !== code || x.usedBy)); json(res, 200, { invites: pubInvites() }); },
  // Umzug: Konten und Codes der bisherigen App einmalig übernehmen (nur solange es hier noch keine gibt)
  'POST /api/import': async (req, res) => {
    if (accounts().length) return json(res, 409, { error: 'Es gibt hier schon Konten.' });
    const b = await readJson(req), list = (Array.isArray(b.accounts) ? b.accounts : []).filter((a) => a?.id && a.name && a.salt && a.hash);
    saveAccounts(list.map((a) => ({ id: a.id, name: a.name, email: '', emailOk: !!a.demo, legacy: true, salt: a.salt, hash: a.hash, school: a.school || 'edupage',
      admin: !!a.admin, demo: !!a.demo, jury: !!a.jury, disabled: !!a.disabled, ver: a.ver || 0, created: a.created || new Date().toISOString(), devices: [] })));
    if (Array.isArray(b.invites)) saveInvites(b.invites);
    json(res, 200, { imported: list.length });
  },
  'GET /api/health': async (req, res) => json(res, 200, { mail: await mail.check(), accounts: accounts().length, unconfirmed: accounts().filter((a) => !a.emailOk).length }),
};

// Aufräumen: unbestätigte neue Konten nach 7 Tagen, alte Links und Codes
setInterval(() => {
  const old = accounts().filter((a) => !a.emailOk && !a.legacy && Date.now() - Date.parse(a.created) > 7 * 864e5);
  for (const a of old) removeAccount(a.id);
  for (const [k, c] of codes) if (c.exp < Date.now()) codes.delete(k);
  save('links.json', load('links.json', []).filter((x) => x.exp > Date.now()));
}, 3600e3).unref();

/* ------------------------------------------------------------------ Server */
const STATIC = { '/style.css': ['style.css', 'text/css; charset=utf-8'], '/icon.svg': ['icon.svg', 'image/svg+xml'] };
function match(table, method, pathname) {
  for (const [key, fn] of Object.entries(table)) {
    const [m, p] = key.split(' ');
    if (m !== method) continue;
    const a = p.split('/'), b = pathname.split('/');
    if (a.length !== b.length) continue;
    const params = [];
    if (a.every((s, i) => (s.startsWith(':') ? (params.push(decodeURIComponent(b[i])), true) : s === b[i]))) return [fn, params];
  }
  return [null, []];
}
// Formulare nur von der eigenen Seite (Browser schicken Origin bzw. Referer mit)
const ownOrigin = (req) => { const o = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : ''); return o === new URL(SELF).origin; };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, SELF);
  try {
    if (url.pathname.startsWith('/api/')) {
      const h = String(req.headers.authorization || '');
      if (!h.startsWith('Bearer ') || !same(h.slice(7), API_SECRET)) { await pause(); return json(res, 401, { error: 'Schlüssel fehlt oder falsch' }); }
      const [fn, params] = match(api, req.method, url.pathname);
      return fn ? await fn(req, res, ...params) : json(res, 404, { error: 'unbekannt' });
    }
    if (STATIC[url.pathname] && req.method === 'GET') {
      const [name, type] = STATIC[url.pathname];
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', name)));
    }
    if (req.method === 'POST' && !ownOrigin(req)) return page(res, 'Nicht erlaubt', '<p>Diese Anfrage kam nicht von dieser Seite.</p>', { status: 403 });
    const [fn] = match(pages, req.method === 'HEAD' ? 'GET' : req.method, url.pathname); // HEAD wie GET, Node lässt den Inhalt weg
    if (!fn) return page(res, 'Nicht gefunden', '<p class="links"><a href="/anmelden">Zur Anmeldung</a></p>', { status: 404 });
    await fn(req, res, url.searchParams);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) page(res, 'Fehler', '<p>Da ist etwas schiefgegangen. Bitte versuch es gleich noch einmal.</p>', { status: e.status || 500 });
  }
});
server.listen(PORT, () => console.log(`Alltag-Konten läuft auf ${SELF} (Port ${PORT}), App: ${APP_URL}, Mail: ${mail.configured ? 'SMTP' : 'Ordner data/mails'}`));
