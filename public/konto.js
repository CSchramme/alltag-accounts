// Passwort anzeigen oder verbergen. Ohne Skript bleiben die Felder einfach verdeckt (die Knöpfe sind dann unsichtbar).
document.documentElement.classList.add('js');
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-pw]');
  if (!b) return;
  const input = b.parentElement.querySelector('input'), show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  b.textContent = show ? 'Verbergen' : 'Anzeigen';
  b.setAttribute('aria-pressed', String(show));
  b.setAttribute('aria-label', show ? 'Passwort verbergen' : 'Passwort anzeigen');
  input.focus();
});
