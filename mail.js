'use strict';
// E-Mails ohne fremde Pakete: SMTP mit STARTTLS (Port 587) oder TLS (Port 465) und Anmeldung (AUTH PLAIN),
// wie es ein Plesk-Postfach anbietet. Ohne SMTP_HOST landen die Mails als .eml-Datei im Ordner `dir`
// (zum Ausprobieren am PC und für die Tests).
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const b64 = (s) => Buffer.from(String(s), 'utf8').toString('base64');
const lines76 = (s) => s.replace(/.{1,76}/g, '$&\r\n');
const header = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`);
const address = (s) => (/<([^>]+)>/.exec(s) || [null, s])[1].trim();

function build({ from, to, subject, text, html }) {
  const id = crypto.randomBytes(12).toString('hex'), b = `alltag-${id}`, domain = address(from).split('@')[1] || 'localhost';
  return [
    `From: ${from}`, `To: ${to}`, `Subject: ${header(subject)}`, `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${id}@${domain}>`, 'MIME-Version: 1.0', `Content-Type: multipart/alternative; boundary="${b}"`, '',
    `--${b}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', lines76(b64(text)),
    `--${b}`, 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', lines76(b64(html)),
    `--${b}--`, '',
  ].join('\r\n');
}

// Ein SMTP-Gespräch: jede Antwort des Servers abwarten (mehrzeilig „250-…“ bis „250 …“), Befehl für Befehl
async function smtp({ host, port, user, pass, helo = 'alltag' }, from, to, data) {
  let sock, buf = '', waiting = null, err = null;
  const got = [];
  const check = () => {
    if (!waiting) return;
    const end = got.findIndex((l) => /^\d{3}(?: |$)/.test(l));
    if (end < 0) { if (err) { const w = waiting; waiting = null; w.reject(err); } return; }
    const part = got.splice(0, end + 1), w = waiting;
    waiting = null;
    w.resolve({ code: Number(part.at(-1).slice(0, 3)), text: part.join('\n') });
  };
  const onData = (d) => { buf += d; let i; while ((i = buf.indexOf('\r\n')) >= 0) { got.push(buf.slice(0, i)); buf = buf.slice(i + 2); } check(); };
  const attach = (s) => {
    s.setEncoding('utf8');
    s.on('data', onData);
    s.on('error', (e) => { err = e; check(); });
    s.on('close', () => { err ||= new Error('SMTP: Verbindung beendet'); check(); });
    s.setTimeout(20000, () => s.destroy(new Error('SMTP: Zeitüberschreitung')));
  };
  const reply = () => new Promise((resolve, reject) => { waiting = { resolve, reject }; check(); });
  const cmd = async (line, ok, label = line.split(' ')[0]) => { // label: nie das Passwort in eine Fehlermeldung
    sock.write(`${line}\r\n`);
    const r = await reply();
    if (!ok.includes(r.code)) throw new Error(`SMTP ${label}: ${r.text}`);
    return r;
  };
  sock = port === 465 ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
  attach(sock);
  try {
    if ((await reply()).code !== 220) throw new Error('SMTP: Server begrüßt nicht');
    let r = await cmd(`EHLO ${helo}`, [250]);
    if (port !== 465) {
      if (/STARTTLS/i.test(r.text)) {
        await cmd('STARTTLS', [220]);
        sock.removeListener('data', onData);
        const plain = sock;
        sock = tls.connect({ socket: plain, servername: host });
        await new Promise((resolve, reject) => { sock.once('secureConnect', resolve); sock.once('error', reject); });
        attach(sock);
        r = await cmd(`EHLO ${helo}`, [250]);
      } else if (user) throw new Error('SMTP: Der Server bietet keine Verschlüsselung an, das Passwort wird nicht gesendet.');
    }
    if (user) await cmd(`AUTH PLAIN ${b64(`\0${user}\0${pass}`)}`, [235], 'AUTH');
    if (data == null) { sock.write('QUIT\r\n'); return; } // nur Verbindung und Anmeldung prüfen
    await cmd(`MAIL FROM:<${address(from)}>`, [250]);
    await cmd(`RCPT TO:<${to}>`, [250, 251]);
    await cmd('DATA', [354]);
    await cmd(`${data.replace(/^\./gm, '..')}\r\n.`, [250], 'Nachricht');
    sock.write('QUIT\r\n');
  } finally { sock.end(); }
}

function createMailer({ dir, from = 'Alltag <noreply@alltag-app.de>', host, port = 587, user = '', pass = '' }) {
  const cfg = { host, port: Number(port), user, pass };
  return {
    configured: !!host,
    async send({ to, subject, text, html }) {
      const data = build({ from, to, subject, text, html });
      if (!host) { // ohne Mailserver: in den Ordner schreiben
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, `${Date.now()}-${crypto.randomBytes(3).toString('hex')}.eml`), data);
        console.log(`Mail an ${to}: ${subject} (gespeichert in ${dir})`);
        return;
      }
      await smtp(cfg, from, to, data);
    },
    // Verbindung und Anmeldung prüfen, ohne etwas zu senden (für die Verwaltung)
    async check() {
      if (!host) return 'nicht eingerichtet (Mails landen im Ordner)';
      try { await smtp(cfg, from, '', null); return 'ok'; } catch (e) { return e.message; }
    },
  };
}

// Text einer .eml-Datei (für Tests und zum Nachsehen): Teil text/plain entpacken
function readEml(raw) {
  const m = /Content-Type: text\/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n([\s\S]*?)\r\n--/.exec(raw);
  return m ? Buffer.from(m[1].replace(/\s/g, ''), 'base64').toString('utf8') : '';
}

module.exports = { createMailer, build, smtp, readEml };
