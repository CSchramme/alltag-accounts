'use strict';
// Selbsttest: node test.js – startet den Konto-Dienst mit Testdaten, Mails landen im Ordner, die „App“ ist nachgebaut
const assert = require('assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');
const { smtp, build, readEml } = require('./mail');

(async () => {
  // 1. SMTP: Gespräch mit einem nachgebauten Mailserver; ohne Verschlüsselung wird kein Passwort gesendet
  const seen = [];
  const fake = net.createServer((s) => {
    s.write('220 test\r\n');
    let buf = '', data = false;
    s.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (data) { if (line === '.') { data = false; s.write('250 ok\r\n'); } else seen.push(line); continue; }
        seen.push(line);
        if (/^EHLO/.test(line)) s.write('250-test\r\n250 SIZE 1000000\r\n');
        else if (line === 'DATA') { data = true; s.write('354 go\r\n'); } else if (line === 'QUIT') s.end('221 bye\r\n'); else s.write('250 ok\r\n');
      }
    });
  }).listen(0);
  const sp = fake.address().port;
  await smtp({ host: '127.0.0.1', port: sp }, 'Alltag <noreply@alltag-app.de>', 'max@example.org', build({ from: 'Alltag <noreply@alltag-app.de>', to: 'max@example.org', subject: 'Grüße', text: 'Hallo äöü', html: '<p>Hallo</p>' }));
  assert.ok(seen.includes('MAIL FROM:<noreply@alltag-app.de>') && seen.includes('RCPT TO:<max@example.org>'));
  assert.ok(seen.some((l) => l === 'Subject: =?UTF-8?B?R3LDvMOfZQ==?='));
  assert.equal(readEml(`${seen.join('\r\n')}\r\n`), 'Hallo äöü');
  await assert.rejects(smtp({ host: '127.0.0.1', port: sp, user: 'u', pass: 'geheim' }, 'a@b.de', 'c@d.de', 'x'), /keine Verschlüsselung/);
  assert.ok(!seen.some((l) => l.startsWith('AUTH')));
  fake.close();

  // 2. nachgebaute App: zählt die Benachrichtigungen
  let hooks = 0;
  const appSrv = http.createServer((req, res) => { if (req.url === '/api/accounts-hook') hooks++; res.end('ok'); }).listen(0);
  const APP = `http://localhost:${appSrv.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'alltag-accounts-')), port = 4100 + Math.floor(Math.random() * 400), B = `http://localhost:${port}`;
  const SECRET = 's'.repeat(40);
  const srv = spawn(process.execPath, ['app.js'], { cwd: __dirname, stdio: 'pipe',
    env: { ...process.env, ENV_FILE: '', PORT: String(port), DATA_DIR: dir, PUBLIC_URL: B, APP_URL: APP, ACCOUNTS_SECRET: SECRET, START_CODE: 'start-123', SMTP_HOST: '' } });
  try {
    await new Promise((resolve, reject) => { srv.stdout.on('data', (b) => String(b).includes('läuft') && resolve()); srv.on('exit', reject); });
    // ein „Browser“ mit eigenem Cookie-Speicher
    const browser = (ua = 'Mozilla/5.0 (Windows NT 10.0) Chrome/130') => {
      const jar = {};
      const go = async (p, form) => {
        const r = await fetch(p.startsWith('http') ? p : B + p, { method: form ? 'POST' : 'GET', redirect: 'manual',
          headers: { 'User-Agent': ua, Cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '), ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded', Origin: B } : {}) },
          body: form ? new URLSearchParams(form) : undefined });
        for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const [k, v] = kv.split('='); if (v) jar[k] = v; else delete jar[k]; }
        return { status: r.status, location: r.headers.get('location') || '', csp: r.headers.get('content-security-policy') || '', text: await r.text() };
      };
      return { go, jar };
    };
    const api = (p, method = 'GET', body, key = SECRET) => fetch(B + p, { method, headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) }).then(async (r) => ({ status: r.status, ...(await r.json()) }));
    const mails = () => { const d = path.join(dir, 'mails'); return fs.existsSync(d) ? fs.readdirSync(d).sort().map((f) => fs.readFileSync(path.join(d, f), 'utf8')) : []; };
    const lastMail = (to) => { const m = mails().filter((x) => x.includes(`To: ${to}`)).at(-1); return m && { subject: /^Subject: (.*)$/m.exec(m)[1], text: readEml(m) }; };
    const linkIn = (text) => /(http\S+)/.exec(text)[1].replace(B, '');
    const exchange = async (location) => api('/api/exchange', 'POST', { code: new URL(location).searchParams.get('code') });

    // API nur mit Schlüssel
    assert.equal((await api('/api/accounts', 'GET', null, 'falsch')).status, 401);
    // erstes Konto mit Start-Code → Admin; erst nach Bestätigung angemeldet
    const chef = browser();
    assert.equal((await chef.go('/registrieren', { code: 'falsch', name: 'chef', email: 'chef@example.org', password: 'lange-geheime-worte', school: 'edupage' })).status, 403);
    const reg = await chef.go('/registrieren', { code: 'start-123', name: 'Chef', email: 'Chef@Example.org', password: 'lange-geheime-worte', school: 'edupage' });
    assert.ok(reg.text.includes('Bestätige deine E-Mail') && reg.text.includes('c•••@example.org'));
    assert.equal((await chef.go('/anmelden', { login: 'chef', password: 'lange-geheime-worte' })).status, 200); // noch unbestätigt → Hinweis statt Weiterleitung
    const vm = lastMail('chef@example.org');
    assert.equal(vm.subject, '=?UTF-8?B?Qml0dGUgYmVzdMOkdGlnZSBkZWluZSBFLU1haWwtQWRyZXNzZQ==?='); // „Bitte bestätige deine E-Mail-Adresse“
    const ok = await chef.go(linkIn(vm.text));
    assert.equal(ok.status, 303);
    assert.ok(ok.location.startsWith(`${APP}/auth/callback?code=`));
    const ex = await exchange(ok.location);
    assert.deepEqual([ex.account.name, ex.account.email, ex.account.emailOk, ex.account.admin], ['chef', 'chef@example.org', true, true]);
    assert.equal((await exchange(ok.location)).status, 400); // Code nur einmal
    assert.equal((await chef.go(linkIn(vm.text))).status, 400); // Link nur einmal
    // schon angemeldet: /weiter führt sofort zurück in die App; fremde Ziele werden zu „/“
    const w = await chef.go('/weiter?next=https://boese.example/x');
    assert.ok(w.location.startsWith(`${APP}/auth/callback?code=`) && w.location.endsWith('next=%2F'));
    assert.ok((await chef.go('/weiter?next=/kalender')).location.endsWith('next=%2Fkalender'));

    // Anmelden mit Alltag (OpenID Connect): nur eingetragene Apps, Zustimmung einmal, id_token mit RS256, E-Mail nur mit Scope
    const crypto = require('crypto');
    assert.equal((await api('/api/clients', 'POST', { name: 'Spiel', redirects: 'http://boese.example/cb' })).status, 400); // nur https oder localhost
    const cl = await api('/api/clients', 'POST', { name: 'Gameserver', redirects: 'https://spiel.example/cb http://localhost:5000/cb' });
    assert.ok(cl.secret && cl.created && !JSON.stringify(cl.clients).includes('secretHash'));
    const disc = await (await fetch(`${B}/.well-known/openid-configuration`)).json(), jwks = await (await fetch(disc.jwks_uri)).json();
    assert.deepEqual([disc.issuer, disc.token_endpoint, jwks.keys[0].alg, 'd' in jwks.keys[0]], [B, `${B}/oauth/token`, 'RS256', false]); // nur der öffentliche Schlüssel
    const verifier = 'v'.repeat(50), challenge = crypto.createHash('sha256').update(verifier).digest('base64url'), CB = 'https://spiel.example/cb';
    const authQ = (extra = {}) => `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: cl.created, redirect_uri: CB, scope: 'openid email', state: 'xyz', nonce: 'n-1', code_challenge: challenge, code_challenge_method: 'S256', ...extra })}`;
    const bad1 = await chef.go(authQ({ redirect_uri: 'https://boese.example/cb' }));
    assert.deepEqual([bad1.status, bad1.location], [400, '']); // fremde Adresse: Fehlerseite statt Weiterleitung
    assert.ok((await chef.go(authQ({ scope: 'email' }))).location.startsWith(`${CB}?error=invalid_scope&state=xyz`));
    assert.ok((await browser().go(authQ({ prompt: 'none' }))).location.includes('error=login_required'));
    const dev = browser(), toLogin = await dev.go(authQ());
    const ziel = new URL(B + toLogin.location).searchParams.get('ziel');
    const lp = await dev.go(toLogin.location);
    assert.ok(lp.text.includes('bei Gameserver weiterzumachen') && lp.csp.includes("form-action 'self' https://spiel.example"));
    const back1 = await dev.go('/anmelden', { login: 'chef', password: 'lange-geheime-worte', ziel });
    assert.equal(back1.location, ziel);
    const cons = await dev.go(back1.location);
    assert.ok(cons.text.includes('<b>Gameserver</b> möchte') && cons.text.includes('E-Mail-Adresse') && cons.csp.includes('https://spiel.example'));
    const q = new URL(B + ziel).searchParams.toString();
    assert.ok((await dev.go('/oauth/authorize', { q, ok: '0' })).location.startsWith(`${CB}?error=access_denied`));
    const ok1 = await dev.go('/oauth/authorize', { q, ok: '1' }), got = new URL(ok1.location);
    assert.deepEqual([got.origin + got.pathname, got.searchParams.get('state'), got.searchParams.get('iss')], [CB, 'xyz', B]);
    const token = (body, auth = `Basic ${Buffer.from(`${cl.created}:${cl.secret}`).toString('base64')}`) => fetch(`${B}/oauth/token`, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(auth ? { Authorization: auth } : {}) }, body: new URLSearchParams(body) }).then(async (r) => ({ status: r.status, ...(await r.json()) }));
    const code1 = got.searchParams.get('code'), tb = { grant_type: 'authorization_code', code: code1, redirect_uri: CB, code_verifier: verifier };
    assert.equal((await token(tb, `Basic ${Buffer.from(`${cl.created}:falsch`).toString('base64')}`)).status, 401);
    const tk = await token(tb);
    assert.equal(tk.token_type, 'Bearer');
    assert.equal((await token(tb)).status, 400); // Code nur einmal
    const [h, pl, sig] = tk.id_token.split('.'), idt = JSON.parse(Buffer.from(pl, 'base64url'));
    assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${pl}`), crypto.createPublicKey({ key: jwks.keys[0], format: 'jwk' }), Buffer.from(sig, 'base64url')));
    assert.deepEqual([idt.iss, idt.aud, idt.nonce, idt.name, idt.email, idt.email_verified, idt.sub.length], [B, cl.created, 'n-1', 'chef', 'chef@example.org', true, 32]);
    const ui = async (t) => fetch(`${B}/oauth/userinfo`, { headers: { Authorization: `Bearer ${t}` } }).then(async (r) => ({ status: r.status, ...(await r.json()) }));
    assert.deepEqual(await ui(tk.access_token), { status: 200, sub: idt.sub, name: 'chef', preferred_username: 'chef', email: 'chef@example.org', email_verified: true });
    assert.equal((await ui(`${tk.access_token}x`)).status, 401);
    // schon zugestimmt: sofort zurück; ohne Scope email keine E-Mail; falscher PKCE-Schlüssel und Schlüssel im Formular
    const ok2 = new URL((await dev.go(authQ({ scope: 'openid' }))).location);
    assert.equal((await token({ ...tb, code: ok2.searchParams.get('code'), code_verifier: 'w'.repeat(50) })).status, 400);
    const ok3 = new URL((await dev.go(authQ({ scope: 'openid' }))).location);
    const tk3 = await token({ ...tb, code: ok3.searchParams.get('code'), client_id: cl.created, client_secret: cl.secret }, '');
    const idt3 = JSON.parse(Buffer.from(tk3.id_token.split('.')[1], 'base64url'));
    assert.deepEqual([idt3.sub, idt3.name, 'email' in idt3], [idt.sub, 'chef', false]);
    // Zugriff in „Dein Konto“ entfernen → Zugangs-Schlüssel gilt nicht mehr; App löschen → Anfrage abgelehnt
    assert.ok((await dev.go('/konto')).text.includes('Verbundene Apps (1)'));
    assert.equal((await dev.go('/konto/apps', { app: cl.created })).location, '/konto?ok=app');
    assert.equal((await ui(tk.access_token)).status, 401);
    await api(`/api/clients/${cl.created}`, 'DELETE');
    assert.equal((await dev.go(authQ())).status, 400);

    // Einladung → zweites Konto, Anmelden mit E-Mail, neues Gerät meldet sich per Mail
    const inv = await api('/api/invites', 'POST', { note: 'Ben' });
    const ben = browser('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Safari/604.1');
    assert.ok((await ben.go('/registrieren', { code: inv.created[0], name: 'ben', email: 'chef@example.org', password: 'ben-hat-ein-passwort', school: 'untis' })).text.includes('schon ein Konto'));
    await ben.go('/registrieren', { code: inv.created[0], name: 'ben', email: 'ben@example.org', password: 'ben-hat-ein-passwort', school: 'untis' });
    await ben.go(linkIn(lastMail('ben@example.org').text));
    assert.equal((await api('/api/invites')).invites.find((i) => i.code === inv.created[0]).usedBy !== null, true);
    const mailsBefore = mails().length;
    const pc = browser('Mozilla/5.0 (Windows NT 10.0) Edg/130');
    assert.equal((await pc.go('/anmelden', { login: 'ben@example.org', password: 'falsch-falsch' })).status, 401);
    const li = await pc.go('/anmelden', { login: 'BEN@example.org', password: 'ben-hat-ein-passwort', next: '/schule' });
    assert.ok(li.location.includes('next=%2Fschule'));
    assert.equal((await exchange(li.location)).account.school, 'untis');
    const dm = lastMail('ben@example.org');
    assert.ok(mails().length === mailsBefore + 1 && dm.text.includes('Windows, Edge'));

    // Passwort vergessen: gleiche Antwort für unbekannte Konten, Link gilt einmal, danach neue Version (alle Sitzungen enden)
    const anon = browser();
    assert.ok((await anon.go('/passwort-vergessen', { login: 'gibtsnicht' })).text.includes('Schau in dein Postfach'));
    await anon.go('/passwort-vergessen', { login: 'ben' });
    const rl = linkIn(lastMail('ben@example.org').text), t = new URL(B + rl).searchParams.get('t');
    assert.equal((await anon.go(rl)).status, 200);
    assert.equal((await anon.go('/passwort-neu', { t, password: 'neues-langes-wort', password2: 'anders-langes-wort' })).status, 400);
    const verBefore = (await api('/api/accounts')).accounts.find((a) => a.name === 'ben').ver;
    assert.equal((await anon.go('/passwort-neu', { t, password: 'neues-langes-wort', password2: 'neues-langes-wort' })).status, 303);
    assert.equal((await anon.go('/passwort-neu', { t, password: 'noch-ein-wort-x', password2: 'noch-ein-wort-x' })).status, 400);
    assert.equal((await api('/api/accounts')).accounts.find((a) => a.name === 'ben').ver, verBefore + 1);
    assert.ok(lastMail('ben@example.org').text.includes('wurde am'));
    assert.equal((await pc.go('/konto')).status, 303); // alte Sitzung beendet
    assert.equal((await pc.go('/anmelden', { login: 'ben', password: 'ben-hat-ein-passwort' })).status, 401);
    assert.equal((await pc.go('/anmelden', { login: 'ben', password: 'neues-langes-wort' })).status, 303);

    // Formulare nur von dieser Seite (no-referrer würde Browser „Origin: null“ schicken lassen und eigene Formulare sperren)
    assert.equal((await fetch(`${B}/anmelden`)).headers.get('referrer-policy'), 'same-origin');
    assert.equal((await fetch(`${B}/anmelden`, { method: 'HEAD' })).status, 200);
    assert.equal((await fetch(`${B}/anmelden`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://boese.example' }, body: 'login=ben&password=x' })).status, 403);
    // Admin über die API: sperren beendet Sitzungen, App wird benachrichtigt; Löschen hinterlässt eine Notiz für die App
    const benId = (await api('/api/accounts')).accounts.find((a) => a.name === 'ben').id, hooksBefore = hooks;
    assert.equal((await api(`/api/accounts/${benId}`, 'PATCH', { pro: true })).account.pro, true);
    const fam = (await api(`/api/accounts/${benId}`, 'PATCH', { plan: 'familie' })).account;
    assert.deepEqual([fam.plan, fam.pro], ['familie', true]);
    assert.equal((await api(`/api/accounts/${benId}`, 'PATCH', { plan: 'gold' })).account.plan, 'familie'); // unbekannt: bleibt
    await api(`/api/accounts/${benId}`, 'PATCH', { disabled: true });
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(hooks > hooksBefore);
    assert.equal((await pc.go('/konto')).status, 303);
    assert.equal((await api(`/api/accounts/${benId}`, 'PATCH', { school: 'quatsch' })).status, 400);
    await api(`/api/accounts/${benId}`, 'DELETE');
    const after = await api('/api/accounts');
    assert.ok(!after.accounts.some((a) => a.id === benId) && after.deleted.some((d) => d.id === benId));
    assert.equal((await api('/api/import', 'POST', { accounts: [] })).status, 409); // Umzug nur in einen leeren Dienst
    assert.match((await api('/api/health')).mail, /nicht eingerichtet/);
    // Beta-Einladung: Code gleich per Mail, mit Tester-ID und Link, der den Code einträgt
    const bi = await api('/api/invites', 'POST', { note: 'BETA-0007 Mia', days: 30, email: 'mia@example.org', name: 'Mia', betaId: 'BETA-0007' });
    const bm = lastMail('mia@example.org');
    assert.ok(bi.mailed && bm.text.includes('BETA-0007') && bm.text.includes(`/registrieren?code=${bi.created[0]}`));
    assert.ok((await browser().go(`/registrieren?code=${bi.created[0]}`)).text.includes(`value="${bi.created[0]}"`)); // Code schon eingetragen
    // Einladungscodes: Flyer 30–90 Tage, Sammelcode für mehrere Anmeldungen, alte Codes laufen ab, zu leichte Passwörter gibt es nicht
    const fl = await api('/api/invites', 'POST', { count: 3, days: 30 });
    assert.equal(fl.created.length, 3);
    const flDays = (Date.parse(fl.invites.find((i) => i.code === fl.created[0]).expires) - Date.now()) / 864e5;
    assert.ok(flDays > 29.9 && flDays <= 30);
    assert.ok((Date.parse((await api('/api/invites', 'POST', { days: 999 })).invites.at(-1).expires) - Date.now()) / 864e5 <= 7); // unbekannte Dauer → 7 Tage
    const sc = (await api('/api/invites', 'POST', { uses: 2, days: 90 })).created[0];
    for (const n of ['flyer-a', 'flyer-b']) assert.ok((await browser().go('/registrieren', { code: sc, name: n, email: `${n}@example.org`, password: 'gruene-wiese-9', school: 'none' })).text.includes('Bestätige'));
    assert.equal((await browser().go('/registrieren', { code: sc, name: 'flyer-c', email: 'flyer-c@example.org', password: 'gruene-wiese-9', school: 'none' })).status, 403);
    // ohne Ablaufdatum und ohne Höchstzahl: bleibt offen, auch nach vielen Anmeldungen und langer Zeit
    const fc = (await api('/api/invites', 'POST', { forever: true, unlimited: true, uses: 5 })).created[0];
    for (const n of ['frei-a', 'frei-b', 'frei-c']) assert.ok((await browser().go('/registrieren', { code: fc, name: n, email: `${n}@example.org`, password: 'gruene-wiese-9', school: 'none' })).text.includes('Bestätige'));
    const fInv = (await api('/api/invites')).invites.find((i) => i.code === fc);
    assert.deepEqual([fInv.usedCount, fInv.open, fInv.expires, fInv.unlimited, fInv.forever], [3, true, null, true, true]);
    const invFileF = path.join(dir, 'invites.json');
    fs.writeFileSync(invFileF, JSON.stringify(JSON.parse(fs.readFileSync(invFileF, 'utf8')).map((i) => (i.code === fc ? { ...i, created: '2020-01-01T00:00:00.000Z' } : i))));
    assert.equal((await api('/api/invites')).invites.find((i) => i.code === fc).open, true);
    const scInv = (await api('/api/invites')).invites.find((i) => i.code === sc);
    assert.deepEqual([scInv.usedCount, scInv.open, 'used' in scInv], [2, false, false]); // Liste der Konten bleibt auf dem Server
    assert.equal((await browser().go('/registrieren', { code: fl.created[1], name: 'lea', email: 'lea@example.org', password: '12345678', school: 'none' })).status, 400);
    const oldCode = (await api('/api/invites', 'POST', { note: 'alt' })).created[0], invFile = path.join(dir, 'invites.json');
    fs.writeFileSync(invFile, JSON.stringify(JSON.parse(fs.readFileSync(invFile, 'utf8')).map((i) => (i.code === oldCode ? { ...i, created: new Date(Date.now() - 8 * 864e5).toISOString() } : i))));
    assert.equal((await browser().go('/registrieren', { code: oldCode, name: 'zu-spaet', email: 'z@example.org', password: 'gruene-wiese-8', school: 'none' })).status, 403);
    // Konto-Seite: Passwort ändern hält dieses Gerät angemeldet
    const k = await chef.go('/konto/passwort', { old: 'lange-geheime-worte', password: 'ganz-neue-worte-hier' });
    assert.equal(k.location, '/konto?ok=pw');
    assert.equal((await chef.go('/konto')).status, 200);
  } finally {
    srv.kill();
    appSrv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // 3. Umzug: Konten der bisherigen App übernehmen; beim ersten Anmelden wird die E-Mail nachgetragen
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'alltag-accounts-')), port2 = 4600 + Math.floor(Math.random() * 300), B2 = `http://localhost:${port2}`;
  const srv2 = spawn(process.execPath, ['app.js'], { cwd: __dirname, stdio: 'pipe', env: { ...process.env, ENV_FILE: '', PORT: String(port2), DATA_DIR: dir2, PUBLIC_URL: B2, APP_URL: 'http://localhost:9', ACCOUNTS_SECRET: 'x'.repeat(32), SMTP_HOST: '' } });
  try {
    await new Promise((resolve, reject) => { srv2.stdout.on('data', (b) => String(b).includes('läuft') && resolve()); srv2.on('exit', reject); });
    const crypto = require('crypto'), salt = 'abc', hash = crypto.scryptSync('altes-passwort-1', salt, 64).toString('hex');
    const imp = await (await fetch(`${B2}/api/import`, { method: 'POST', headers: { Authorization: `Bearer ${'x'.repeat(32)}` }, body: JSON.stringify({ accounts: [{ id: 'a1', name: 'alt', salt, hash, school: 'edupage', admin: true, ver: 2 }], invites: [] }) })).json();
    assert.equal(imp.imported, 1);
    const r = await fetch(`${B2}/anmelden`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: B2 }, body: 'login=alt&password=altes-passwort-1' });
    assert.ok((await r.text()).includes('E-Mail hinterlegen'));
  } finally {
    srv2.kill();
    fs.rmSync(dir2, { recursive: true, force: true });
  }
  console.log('alle Tests ok');
})().catch((e) => { console.error(e); process.exit(1); });
