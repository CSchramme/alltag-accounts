'use strict';
// Selbsttest der Beispiel-App: id_token-Prüfung (node beispiel/test.js)
process.env.ALLTAG_TEST = '1';
const assert = require('assert/strict');
const crypto = require('crypto');
const { verifyIdToken } = require('./app');

(async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const make = (claims, head = { alg: 'RS256', kid: 'k1' }) => { const hp = `${b64(head)}.${b64(claims)}`; return `${hp}.${crypto.sign('sha256', Buffer.from(hp), privateKey).toString('base64url')}`; };
  const now = Math.floor(Date.now() / 1000), good = { iss: 'https://acc.example', aud: 'app-1', sub: 'abc', exp: now + 60, iat: now, nonce: 'n1', name: 'chef' };
  const opts = { nonce: 'n1', issuer: 'https://acc.example', audience: 'app-1', key: async () => publicKey };
  assert.equal((await verifyIdToken(make(good), opts)).claims.name, 'chef');
  for (const [bad, msg] of [[{ ...good, aud: 'app-2' }, /Empfänger/], [{ ...good, iss: 'https://boese.example' }, /Aussteller/], [{ ...good, exp: now - 1 }, /abgelaufen/], [{ ...good, nonce: 'x' }, /nonce/]]) {
    await assert.rejects(verifyIdToken(make(bad), opts), msg);
  }
  const [h, , s] = make(good).split('.');
  await assert.rejects(verifyIdToken(`${h}.${b64({ ...good, name: 'admin' })}.${s}`, opts), /Signatur/); // verändert
  await assert.rejects(verifyIdToken(make(good, { alg: 'none' }), opts), /Verfahren/);
  console.log('Beispiel-App: alle Tests ok');
})().catch((e) => { console.error(e); process.exit(1); });
