// Page de réveil du nœud sentinelle.
//
// Elle est servie par le service de réveil lui-même, et non par l'agent : quand
// on veut réveiller la station, l'agent est précisément éteint. Même origine que
// l'API, donc ni CORS ni contenu mixte.
//
// Les noms de machines viennent du serveur ; ils sont insérés par `textContent`,
// jamais par `innerHTML`, pour qu'aucune configuration ne puisse injecter de
// balisage dans la page.

'use strict';

const STORAGE_KEY = 'sidgate-wol-token';

const form = document.getElementById('unlock');
const tokenInput = document.getElementById('token');
const hostsBox = document.getElementById('hosts');
const statusLine = document.getElementById('status');

function setStatus(text, kind = '') {
  statusLine.textContent = text;
  statusLine.className = kind;
}

function readToken() {
  try {
    return localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

function storeToken(value) {
  try {
    if (value) localStorage.setItem(STORAGE_KEY, value);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Stockage indisponible (navigation privée) : le jeton restera à ressaisir.
  }
}

async function call(path, method, token) {
  const response = await fetch(path, {
    method,
    headers: { 'X-Sidgate-Token': token },
    cache: 'no-store',
  });
  if (response.status === 401) {
    const error = new Error('Jeton refusé.');
    error.unauthorized = true;
    throw error;
  }
  if (!response.ok) throw new Error(`Réponse inattendue du service (${response.status}).`);
  return response.json();
}

async function showHosts(token) {
  setStatus('Chargement…');
  let hosts;
  try {
    ({ hosts } = await call('/hosts', 'GET', token));
  } catch (error) {
    if (error.unauthorized) {
      storeToken('');
      form.hidden = false;
      hostsBox.hidden = true;
    }
    setStatus(error.message, 'error');
    return;
  }

  storeToken(token);
  form.hidden = true;
  hostsBox.replaceChildren();

  for (const name of hosts) {
    const button = document.createElement('button');
    button.type = 'button';
    const label = document.createElement('span');
    label.textContent = name;
    const action = document.createElement('span');
    action.textContent = 'Réveiller';
    button.append(label, action);
    button.addEventListener('click', () => wake(name, token, button, action));
    hostsBox.append(button);
  }

  const forget = document.createElement('button');
  forget.type = 'button';
  forget.textContent = 'Oublier le jeton sur cet appareil';
  forget.addEventListener('click', () => {
    storeToken('');
    hostsBox.hidden = true;
    form.hidden = false;
    tokenInput.value = '';
    setStatus('Jeton oublié.');
  });
  hostsBox.append(forget);

  hostsBox.hidden = false;
  setStatus(hosts.length ? '' : 'Aucune machine déclarée dans la configuration.');
}

async function wake(name, token, button, action) {
  button.disabled = true;
  action.textContent = 'Envoi…';
  try {
    await call(`/wake/${encodeURIComponent(name)}`, 'POST', token);
    // Le paquet n'est jamais acquitté : on sait qu'il est parti, pas qu'il est
    // arrivé. Le dire autrement serait mentir.
    setStatus(`Paquet envoyé à « ${name} ». Le démarrage prend en général 20 à 60 secondes.`, 'ok');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    action.textContent = 'Réveiller';
    // Un délai avant réactivation évite les rafales de broadcast sur double clic.
    setTimeout(() => { button.disabled = false; }, 3000);
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const token = tokenInput.value.trim();
  if (token) showHosts(token);
});

const saved = readToken();
if (saved) showHosts(saved);
