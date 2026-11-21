# Alltag-Konten

Der Konto-Dienst von [Alltag](https://alltag-app.de) unter **accounts.alltag-app.de**: Registrieren mit Einladungscode und E-Mail-Adresse, E-Mail bestätigen, Anmelden mit Benutzername oder E-Mail, Passwort vergessen, Konto verwalten (E-Mail, Passwort, Geräte, Löschen) und Hinweis-Mails bei neuen Geräten.

Die App (alltag-app.de, eigenes Repository `alltag-app_de`) speichert keine Passwörter. Sie schickt Besucher zum Anmelden hierher und bekommt danach einen Einmal-Code zurück, den sie über die geschützte API gegen die Kontodaten tauscht.

```
app.js        Server, Seiten und API (Node.js ≥ 20, keine npm-Pakete)
mail.js       E-Mails per SMTP (STARTTLS/TLS, AUTH PLAIN); ohne SMTP_HOST als .eml-Datei in data/mails
public/       style.css, icon.svg
test.js       Selbsttest (node test.js)
data/         wird beim Start angelegt: Konten, Einladungscodes, Einmal-Links – geheim, nie veröffentlichen
```

## So reden die beiden Apps miteinander

```
Browser ── „Anmelden“ ──▶ accounts.alltag-app.de/weiter?next=/…
                           (Anmeldeseite, oder sofort weiter, wenn schon angemeldet)
Browser ◀── 303 ── alltag-app.de/auth/callback?code=<Einmal-Code, 60 s>
App ── POST /api/exchange {code} + Bearer ACCOUNTS_SECRET ──▶ Konto-Dienst ──▶ {account}
App setzt ihre eigene Sitzung (Cookie „sid“)

Konto-Dienst ── POST alltag-app.de/api/accounts-hook (Bearer) ──▶ App lädt die Kontenliste neu
                (nach Sperren, Passwort ändern, Löschen; sonst alle 3 Minuten)
```

API (alle mit `Authorization: Bearer <ACCOUNTS_SECRET>`): `POST /api/exchange`, `GET /api/accounts` (mit Löschnotizen), `PATCH /api/accounts/:id` (school, admin, demo, jury, disabled, reset), `DELETE /api/accounts/:id`, `GET/POST /api/invites`, `DELETE /api/invites/:code`, `POST /api/import` (Umzug, nur in einen leeren Dienst), `GET /api/health` (prüft den Mailversand).

## Auf Plesk einrichten

1. **Subdomain** `accounts.alltag-app.de` anlegen, Let's Encrypt aktivieren, HTTP → HTTPS umleiten.
2. **Postfach** `noreply@alltag-app.de` unter *E-Mail* anlegen (Passwort im Passwort-Manager). Unter *Mail-Einstellungen* der Domain DKIM einschalten, damit die Mails nicht im Spam landen.
3. **Git:** dieses Repository, Zweig `main`, Bereitstellungspfad = Ordner der Subdomain (z. B. `/accounts.alltag-app.de`), **nicht** `public`.
4. **Node.js:** Anwendungsstamm = Ordner mit `app.js`, Dokumentenstamm = `public`, Startdatei `app.js`.
5. **Umgebungsvariablen:**

   | Variable | Wert |
   |---|---|
   | `PUBLIC_URL` | `https://accounts.alltag-app.de` |
   | `APP_URL` | `https://alltag-app.de` |
   | `ACCOUNTS_SECRET` | zufällig, mindestens 32 Zeichen, **derselbe Wert wie in der App** |
   | `SMTP_HOST` | Mailserver des Hosters (z. B. der Servername aus Plesk) |
   | `SMTP_PORT` | `587` (STARTTLS) oder `465` (TLS) |
   | `SMTP_USER`, `SMTP_PASS` | Postfach `noreply@alltag-app.de` und sein Passwort |
   | `MAIL_FROM` | `Alltag <noreply@alltag-app.de>` |
   | `LEGAL_EMAIL` | Kontakt, steht in Hinweis-Mails |
   | `START_CODE` | nur nötig, wenn es noch gar keine Konten gibt (erstes Konto wird Admin) |

6. **App neu starten.** Danach in der App (alltag-app.de) `ACCOUNTS_URL` und `ACCOUNTS_SECRET` eintragen und sie neu starten. Beim ersten Start übergibt sie die bisherigen Konten hierher; jedes Konto trägt beim nächsten Anmelden seine E-Mail-Adresse nach.

Ohne `SMTP_HOST` werden keine Mails verschickt, sondern als Datei in `data/mails` abgelegt. Ob der Versand klappt, zeigt die Verwaltung der App unter „Mailversand“.

## Lokal ausprobieren

```powershell
$env:ACCOUNTS_SECRET="lokaler-test-schluessel-mindestens-32-zeichen"; $env:START_CODE="start"; node app.js
```

Läuft auf http://localhost:3002, die App erwartet ihn dort mit `ACCOUNTS_URL=http://localhost:3002`. Mails liegen in `data/mails`.

## Test

```powershell
npm test
```
