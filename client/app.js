// Client sidgate.
//
// Trois responsabilités : prouver son identité à l'agent, négocier la session
// WebRTC, puis traduire les gestes et les frappes en trames binaires.
//
// L'identité du client est une paire ECDSA P-256 **non extractible**, gardée par
// le navigateur dans IndexedDB. La clé privée ne quitte jamais le magasin de
// clés — même du code exécuté sur cette page ne peut pas la lire, seulement
// demander une signature. C'est ce qui rend le vol d'identité par script
// impossible sans vol de l'appareil.

import { toScancode, SHORTCUTS } from '/keymap.js';

const PROTOCOL = 1;
const NONCE_LEN = 32;

const DOMAIN_AUTH = 'sidgate/auth/client/v1';
const DOMAIN_PAIR = 'sidgate/pair/client/v1';
const DOMAIN_AGENT = 'sidgate/auth/agent/v1';

// --- Éléments ---------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const ui = {
  gate: $('gate'), status: $('status'), fingerprint: $('fingerprint'),
  connect: $('connect'), unlock: $('unlock'),
  pairing: $('pairing'), code: $('code'), pair: $('pair'),
  stage: $('stage'), video: $('screen'), cursor: $('cursor'),
  hud: $('hud'), grip: $('grip'), shortcuts: $('shortcuts'),
  mode: $('mode'), keyboard: $('keyboard'), fullscreen: $('fullscreen'),
  lock: $('lock'), telemetry: $('telemetry'), toast: $('toast'), ime: $('ime'),
};

// --- Magasin local ----------------------------------------------------------

const DB_NAME = 'sidgate';
const STORE = 'identity';

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbPut(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// --- Encodage ---------------------------------------------------------------

const toHex = (bytes) =>
  Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');

const fromHex = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

/**
 * Reconstruit exactement la transcription que l'agent signe et vérifie.
 *
 * Chaque champ est préfixé de sa longueur sur 32 bits en petit-boutiste. Sans
 * ce préfixe, deux découpages différents des mêmes octets donneraient la même
 * transcription et une signature vaudrait pour les deux.
 */
function transcript(domain, serverNonce, clientNonce, clientKey) {
  const parts = [new TextEncoder().encode(domain), serverNonce, clientNonce, clientKey];
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, true);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// --- Identité ---------------------------------------------------------------

async function loadIdentity() {
  let keys = await dbGet('keys');
  if (!keys) {
    // `extractable: false` ne s'applique qu'à la clé privée ; la publique reste
    // exportable, ce qu'il nous faut pour l'annoncer à l'agent.
    keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'],
    );
    await dbPut('keys', keys);
  }
  const raw = await crypto.subtle.exportKey('raw', keys.publicKey);
  return { keys, publicKey: new Uint8Array(raw), publicKeyHex: toHex(raw) };
}

const sign = async (privateKey, data) =>
  toHex(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data));

/**
 * Vérifie la signature Ed25519 de l'agent.
 *
 * Renvoie `null` si le navigateur ne connaît pas Ed25519 dans WebCrypto : on le
 * signale alors à l'utilisateur au lieu de faire semblant d'avoir vérifié.
 */
async function verifyAgent(agentKeyHex, signatureHex, data) {
  try {
    const key = await crypto.subtle.importKey(
      'raw', fromHex(agentKeyHex), { name: 'Ed25519' }, false, ['verify'],
    );
    return crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(signatureHex), data);
  } catch {
    return null;
  }
}

const randomNonce = () => crypto.getRandomValues(new Uint8Array(NONCE_LEN));

// --- Déverrouillage biométrique --------------------------------------------

/**
 * Exige une vérification de l'utilisateur avant d'ouvrir la session.
 *
 * S'appuie sur l'authentificateur de la plateforme : Face ID, empreinte, ou
 * Windows Hello. Indisponible lorsque la page est servie sous un certificat
 * auto-signé que le navigateur a signalé — dans ce cas on le dit franchement
 * plutôt que de laisser croire à une protection qui n'existe pas.
 */
async function requireUserPresence() {
  const credentialId = await dbGet('webauthn');
  if (!credentialId) return { ok: true, reason: 'non configuré' };
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomNonce(),
        allowCredentials: [{ id: credentialId, type: 'public-key' }],
        userVerification: 'required',
        timeout: 60000,
      },
    });
    return { ok: Boolean(assertion), reason: 'vérifié' };
  } catch (e) {
    return { ok: false, reason: e.name === 'NotAllowedError' ? 'refusé' : String(e.message) };
  }
}

async function enrollBiometrics(publicKeyHex) {
  if (!window.PublicKeyCredential) return;
  try {
    const available =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) return;
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: randomNonce(),
        rp: { name: 'sidgate', id: location.hostname },
        user: {
          id: fromHex(publicKeyHex.slice(0, 32)),
          name: 'sidgate',
          displayName: 'Accès distant sidgate',
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'discouraged',
        },
        timeout: 60000,
      },
    });
    if (credential) {
      await dbPut('webauthn', credential.rawId);
      toast('Déverrouillage biométrique activé');
    }
  } catch {
    // Facultatif par nature : un échec ne doit pas bloquer l'appairage.
  }
}

// --- Session ----------------------------------------------------------------

const state = {
  socket: null,
  peer: null,
  input: null,
  control: null,
  identity: null,
  serverNonce: null,
  clientNonce: null,
  absolute: false,
  live: false,
  cursor: { x: 0.5, y: 0.5 },
  desktop: { width: 1920, height: 1080 },
  seq: 0,
  pending: [],
  flushScheduled: false,
};

function setStatus(text, isError = false) {
  ui.status.textContent = text;
  ui.status.classList.toggle('error', isError);
}

let toastTimer;
function toast(text) {
  ui.toast.textContent = text;
  ui.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ui.toast.classList.remove('show'), 2200);
}

async function connect() {
  setStatus('Connexion…');
  ui.connect.hidden = true;

  const presence = await requireUserPresence();
  if (!presence.ok) {
    setStatus(`Déverrouillage ${presence.reason}.`, true);
    ui.connect.hidden = false;
    return;
  }

  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const socket = new WebSocket(`${scheme}://${location.host}/ws`);
  socket.binaryType = 'arraybuffer';
  state.socket = socket;

  socket.onerror = () => setStatus('Connexion impossible.', true);
  socket.onclose = () => endSession('Connexion fermée.');
  socket.onmessage = (event) => handleServerMessage(JSON.parse(event.data));
}

function send(type, payload) {
  state.socket?.send(JSON.stringify(payload === undefined ? { type } : { type, payload }));
}

async function handleServerMessage({ type, payload }) {
  switch (type) {
    case 'challenge': return onChallenge(payload);
    case 'auth_ok': return onAuthOk(payload);
    case 'auth_failed': return onAuthFailed(payload);
    case 'answer': return state.peer?.setRemoteDescription({ type: 'answer', sdp: payload.sdp });
    case 'candidate':
      return state.peer?.addIceCandidate({
        candidate: payload.candidate,
        sdpMid: payload.sdp_mid,
        sdpMLineIndex: payload.sdp_mline_index,
      }).catch(() => {});
    case 'error': return setStatus(payload.message, true);
    default: return undefined;
  }
}

async function onChallenge(payload) {
  if (payload.protocol !== PROTOCOL) {
    setStatus('Version de protocole incompatible avec l’agent.', true);
    return;
  }

  state.serverNonce = fromHex(payload.server_nonce);
  state.clientNonce = randomNonce();

  const pinned = await dbGet('agent');
  if (pinned && pinned !== payload.agent_key) {
    // L'agent auquel nous avons été appairés n'est pas celui qui répond.
    setStatus(
      'L’identité de l’hôte a changé. Connexion interrompue par précaution.',
      true,
    );
    state.socket.close();
    return;
  }

  ui.fingerprint.textContent = `hôte ${groupHex(payload.agent_key)}`;
  state.agentKey = payload.agent_key;

  if (pinned) {
    const data = transcript(
      DOMAIN_AUTH, state.serverNonce, state.clientNonce, state.identity.publicKey,
    );
    send('authenticate', {
      protocol: PROTOCOL,
      client_key: state.identity.publicKeyHex,
      client_nonce: toHex(state.clientNonce),
      signature: await sign(state.identity.keys.privateKey, data),
    });
    setStatus('Authentification…');
  } else if (payload.pairing_open) {
    setStatus('Cet appareil n’est pas encore appairé.');
    ui.pairing.hidden = false;
    ui.code.focus();
  } else {
    setStatus('Aucun appairage ouvert. Tapez « p » sur la console de l’hôte.', true);
  }
}

async function submitPairing() {
  const code = ui.code.value.trim();
  if (code.replace(/[^a-z0-9]/gi, '').length !== 8) {
    setStatus('Le code compte huit caractères.', true);
    return;
  }
  ui.pair.disabled = true;

  const data = transcript(
    DOMAIN_PAIR, state.serverNonce, state.clientNonce, state.identity.publicKey,
  );
  send('pair', {
    protocol: PROTOCOL,
    code,
    client_key: state.identity.publicKeyHex,
    client_nonce: toHex(state.clientNonce),
    signature: await sign(state.identity.keys.privateKey, data),
    label: deviceLabel(),
  });
  setStatus('Appairage…');
}

async function onAuthOk(payload) {
  const data = transcript(
    DOMAIN_AGENT, state.serverNonce, state.clientNonce, state.identity.publicKey,
  );
  const verified = await verifyAgent(state.agentKey, payload.agent_signature, data);

  if (verified === false) {
    setStatus('L’hôte n’a pas prouvé son identité. Connexion abandonnée.', true);
    state.socket.close();
    return;
  }
  if (verified === null) {
    toast('Ce navigateur ne sait pas vérifier la signature de l’hôte');
  }

  const firstTime = !(await dbGet('agent'));
  await dbPut('agent', state.agentKey);
  if (firstTime) await enrollBiometrics(state.identity.publicKeyHex);

  ui.pairing.hidden = true;
  setStatus('Négociation du flux…');
  await startWebrtc();
}

function onAuthFailed({ reason }) {
  const messages = {
    rejected: 'Identité ou code refusé.',
    pairing_closed: 'Aucun appairage ouvert sur l’hôte.',
    rate_limited: 'Trop de tentatives. Patientez une minute.',
    protocol_mismatch: 'Version de protocole incompatible.',
    unexpected_message: 'Échange inattendu.',
  };
  setStatus(messages[reason] ?? 'Authentification refusée.', true);
  ui.pair.disabled = false;
}

// --- WebRTC -----------------------------------------------------------------

async function startWebrtc() {
  const peer = new RTCPeerConnection({ iceServers: [], bundlePolicy: 'max-bundle' });
  state.peer = peer;

  peer.addTransceiver('video', { direction: 'recvonly' });

  // Temps réel : ni ordre ni retransmission. Une trame d'entrée perdue vaut
  // mieux qu'une trame en retard — la suivante corrige déjà la position.
  state.input = peer.createDataChannel('input-raw', { ordered: false, maxRetransmits: 0 });
  state.control = peer.createDataChannel('control-secure', { ordered: true });
  state.control.onmessage = (event) => handleControlEvent(JSON.parse(event.data));

  peer.ontrack = (event) => {
    ui.video.srcObject = event.streams[0] ?? new MediaStream([event.track]);
  };
  peer.onicecandidate = ({ candidate }) => {
    if (!candidate) return;
    send('candidate', {
      candidate: candidate.candidate,
      sdp_mid: candidate.sdpMid,
      sdp_mline_index: candidate.sdpMLineIndex,
    });
  };
  peer.onconnectionstatechange = () => {
    if (peer.connectionState === 'connected') beginSession();
    if (['failed', 'disconnected', 'closed'].includes(peer.connectionState)) {
      endSession('Transport perdu.');
    }
  };

  const offer = await peer.createOffer();
  await peer.setLocalDescription(offer);
  send('offer', { sdp: offer.sdp });
}

function beginSession() {
  state.live = true;
  ui.gate.hidden = true;
  ui.stage.classList.add('live');
  ui.cursor.classList.add('on');
  ui.hud.classList.add('open');
  setTimeout(() => ui.hud.classList.remove('open'), 2600);
  drawCursor();
}

function endSession(message) {
  if (!state.live && ui.gate.hidden === false) setStatus(message, true);
  state.live = false;
  ui.stage.classList.remove('live');
  ui.cursor.classList.remove('on');
  ui.gate.hidden = false;
  ui.connect.hidden = false;
  ui.pair.disabled = false;
  setStatus(message, true);
  state.peer?.close();
  state.peer = null;
}

// --- Canal de contrôle ------------------------------------------------------

function command(cmd, args) {
  if (state.control?.readyState !== 'open') return;
  state.control.send(JSON.stringify(args === undefined ? { cmd } : { cmd, args }));
}

function handleControlEvent(event) {
  switch (event.evt) {
    case 'hello':
      state.desktop = {
        width: event.capabilities.width,
        height: event.capabilities.height,
      };
      ui.lock.hidden = false;
      break;
    case 'stats':
      renderTelemetry(event);
      break;
    case 'command_rejected':
      toast(`« ${event.command} » refusé (${event.reason})`);
      break;
    case 'capture_unavailable':
      // La session reste ouverte : seule la vidéo manque, et elle revient
      // d'elle-même. Fermer la connexion obligerait à tout renégocier.
      toast(event.message);
      ui.telemetry.textContent = event.message;
      break;
    case 'capture_resumed':
      toast('Capture reprise');
      ui.telemetry.textContent = '';
      break;
    case 'display_changed':
      state.desktop = { width: event.width, height: event.height };
      break;
    case 'ping':
      command('pong', { seq: event.seq });
      break;
    default:
      break;
  }
}

function renderTelemetry(stats) {
  const mbps = (stats.bitrate_bps / 1e6).toFixed(1);
  ui.telemetry.innerHTML = [
    `<b>${stats.fps.toFixed(0)}</b> i/s`,
    `<b>${mbps}</b> Mbit/s`,
    `<b>${stats.encode_ms.toFixed(1)}</b> ms enc.`,
    `<b>${stats.frames_captured}</b> capt.`,
    stats.frames_dropped ? `<b>${stats.frames_dropped}</b> écartées` : '',
  ].filter(Boolean).join('');
}

// --- Entrées ----------------------------------------------------------------

const EVENT = {
  MOVE_REL: 0x01, MOVE_ABS: 0x02, BUTTON: 0x03, SCROLL: 0x04, KEY: 0x05,
};

function queue(bytes) {
  if (state.input?.readyState !== 'open') return;
  state.pending.push(bytes);
  if (state.flushScheduled) return;
  state.flushScheduled = true;
  // Regrouper sur une trame d'affichage : un geste continu produit une seule
  // trame de plusieurs événements au lieu de dizaines de datagrammes.
  requestAnimationFrame(flush);
}

function flush() {
  state.flushScheduled = false;
  const events = state.pending.splice(0, 64);
  if (!events.length) return;

  const size = 6 + events.reduce((n, e) => n + e.length, 0);
  const frame = new Uint8Array(size);
  const view = new DataView(frame.buffer);
  frame[0] = 1;
  view.setUint32(1, state.seq, true);
  frame[5] = events.length;
  let offset = 6;
  for (const event of events) {
    frame.set(event, offset);
    offset += event.length;
  }
  state.seq = (state.seq + 1) >>> 0;

  try {
    state.input.send(frame);
  } catch {
    // Canal saturé : la trame suivante portera la position à jour.
  }
  if (state.pending.length) queue([]);
}

const moveRelative = (dx, dy) => {
  const bytes = new Uint8Array(5);
  const view = new DataView(bytes.buffer);
  bytes[0] = EVENT.MOVE_REL;
  view.setInt16(1, clamp(dx, -32768, 32767), true);
  view.setInt16(3, clamp(dy, -32768, 32767), true);
  queue(bytes);
};

const moveAbsolute = (x, y) => {
  const bytes = new Uint8Array(5);
  const view = new DataView(bytes.buffer);
  bytes[0] = EVENT.MOVE_ABS;
  view.setUint16(1, clamp(Math.round(x * 65535), 0, 65535), true);
  view.setUint16(3, clamp(Math.round(y * 65535), 0, 65535), true);
  queue(bytes);
};

const button = (index, pressed) =>
  queue(new Uint8Array([EVENT.BUTTON, index, pressed ? 1 : 0]));

const scroll = (dx, dy) => {
  const bytes = new Uint8Array(5);
  const view = new DataView(bytes.buffer);
  bytes[0] = EVENT.SCROLL;
  view.setInt16(1, clamp(dx, -32768, 32767), true);
  view.setInt16(3, clamp(dy, -32768, 32767), true);
  queue(bytes);
};

const key = (code, pressed) => {
  const mapped = toScancode(code);
  if (!mapped) return false;
  const bytes = new Uint8Array(4);
  const view = new DataView(bytes.buffer);
  bytes[0] = EVENT.KEY;
  view.setUint16(1, mapped.scancode, true);
  bytes[3] = (pressed ? 1 : 0) | (mapped.extended ? 2 : 0);
  queue(bytes);
  return true;
};

const clamp = (value, min, max) => Math.min(max, Math.max(min, Math.round(value)));

// --- Curseur local ----------------------------------------------------------

/**
 * Le bureau capturé ne contient jamais le curseur : Desktop Duplication le
 * livre séparément. Le dessiner localement le rend immédiat, sans attendre
 * l'aller-retour réseau.
 */
function drawCursor() {
  const rect = videoContentRect();
  ui.cursor.style.left = `${rect.x + state.cursor.x * rect.width}px`;
  ui.cursor.style.top = `${rect.y + state.cursor.y * rect.height}px`;
}

/** Rectangle réellement occupé par l'image dans l'élément vidéo. */
function videoContentRect() {
  const box = ui.video.getBoundingClientRect();
  const videoRatio = (ui.video.videoWidth || state.desktop.width)
    / (ui.video.videoHeight || state.desktop.height);
  const boxRatio = box.width / box.height;
  if (videoRatio > boxRatio) {
    const height = box.width / videoRatio;
    return { x: box.x, y: box.y + (box.height - height) / 2, width: box.width, height };
  }
  const width = box.height * videoRatio;
  return { x: box.x + (box.width - width) / 2, y: box.y, width, height: box.height };
}

function moveCursorBy(dx, dy) {
  const rect = videoContentRect();
  state.cursor.x = Math.min(1, Math.max(0, state.cursor.x + dx / rect.width));
  state.cursor.y = Math.min(1, Math.max(0, state.cursor.y + dy / rect.height));
  drawCursor();
}

// --- Gestes -----------------------------------------------------------------

let pointerDown = false;
let lastPointer = null;
let touchStart = null;
let pinchDistance = null;

ui.video.addEventListener('pointerdown', (event) => {
  if (!state.live) return;
  ui.video.setPointerCapture(event.pointerId);
  pointerDown = true;
  lastPointer = { x: event.clientX, y: event.clientY };
  touchStart = { time: performance.now(), x: event.clientX, y: event.clientY };

  if (event.pointerType === 'mouse') {
    if (state.absolute) sendAbsoluteFrom(event);
    button(mouseButton(event.button), true);
  }
});

ui.video.addEventListener('pointermove', (event) => {
  if (!state.live) return;

  if (event.pointerType === 'mouse') {
    if (state.absolute) {
      sendAbsoluteFrom(event);
    } else if (document.pointerLockElement === ui.video) {
      moveRelative(event.movementX, event.movementY);
      moveCursorBy(event.movementX, event.movementY);
    } else if (pointerDown) {
      const dx = event.clientX - lastPointer.x;
      const dy = event.clientY - lastPointer.y;
      moveRelative(dx, dy);
      moveCursorBy(dx, dy);
    }
    lastPointer = { x: event.clientX, y: event.clientY };
    return;
  }

  if (!pointerDown) return;
  const dx = event.clientX - lastPointer.x;
  const dy = event.clientY - lastPointer.y;
  lastPointer = { x: event.clientX, y: event.clientY };

  if (state.absolute) {
    sendAbsoluteFrom(event);
  } else {
    // Gain progressif : les petits gestes gagnent en précision, les grands en
    // portée, comme sur un trackpad matériel.
    const speed = Math.hypot(dx, dy);
    const gain = 1 + Math.min(1.6, speed / 14);
    moveRelative(dx * gain, dy * gain);
    moveCursorBy(dx * gain, dy * gain);
  }
});

ui.video.addEventListener('pointerup', (event) => {
  if (!state.live) return;
  pointerDown = false;

  if (event.pointerType === 'mouse') {
    button(mouseButton(event.button), false);
    return;
  }
  // Toucher bref et immobile : clic gauche à la position courante.
  const moved = Math.hypot(event.clientX - touchStart.x, event.clientY - touchStart.y);
  if (performance.now() - touchStart.time < 250 && moved < 12) {
    button(0, true);
    button(0, false);
  }
});

ui.video.addEventListener('wheel', (event) => {
  if (!state.live) return;
  event.preventDefault();
  // Un cran de molette vaut 120 unités côté Windows.
  scroll(-Math.sign(event.deltaX) * 120, -Math.sign(event.deltaY) * 120);
}, { passive: false });

ui.video.addEventListener('touchmove', (event) => {
  if (!state.live || event.touches.length !== 2) return;
  event.preventDefault();
  const [a, b] = event.touches;
  const distance = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
  const midY = (a.clientY + b.clientY) / 2;
  if (pinchDistance !== null && Math.abs(distance - pinchDistance) < 8) {
    scroll(0, Math.sign(touchStart.y - midY) * -120);
  }
  pinchDistance = distance;
  touchStart = { ...touchStart, y: midY };
}, { passive: false });

ui.video.addEventListener('touchend', () => { pinchDistance = null; });
ui.video.addEventListener('contextmenu', (event) => event.preventDefault());

ui.video.addEventListener('dblclick', () => {
  if (state.live && !state.absolute && document.pointerLockElement !== ui.video) {
    ui.video.requestPointerLock?.();
  }
});

function sendAbsoluteFrom(event) {
  const rect = videoContentRect();
  const x = (event.clientX - rect.x) / rect.width;
  const y = (event.clientY - rect.y) / rect.height;
  if (x < 0 || x > 1 || y < 0 || y > 1) return;
  state.cursor = { x, y };
  drawCursor();
  moveAbsolute(x, y);
}

const mouseButton = (index) => ({ 0: 0, 2: 1, 1: 2, 3: 3, 4: 4 })[index] ?? 0;

// --- Clavier ----------------------------------------------------------------

window.addEventListener('keydown', (event) => {
  if (!state.live) return;
  if (key(event.code, true)) event.preventDefault();
});

window.addEventListener('keyup', (event) => {
  if (!state.live) return;
  if (key(event.code, false)) event.preventDefault();
});

// Un onglet qui perd le focus ne reçoit plus les relâchements : sans ce filet,
// une modificatrice resterait enfoncée sur l'hôte.
window.addEventListener('blur', () => {
  if (!state.live) return;
  for (const code of ['ControlLeft', 'ControlRight', 'ShiftLeft', 'ShiftRight',
    'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight']) {
    key(code, false);
  }
});

async function pressCombo(codes) {
  for (const code of codes) key(code, true);
  await new Promise((resolve) => setTimeout(resolve, 40));
  for (const code of [...codes].reverse()) key(code, false);
}

// --- Interface --------------------------------------------------------------

for (const shortcut of SHORTCUTS) {
  const element = document.createElement('button');
  element.textContent = shortcut.label;
  element.onclick = () => pressCombo(shortcut.keys);
  ui.shortcuts.append(element);
}

ui.grip.parentElement.addEventListener('click', (event) => {
  if (event.target === ui.grip || event.target === ui.hud) {
    ui.hud.classList.toggle('open');
  }
});

for (const element of document.querySelectorAll('[data-quality]')) {
  element.onclick = () => {
    command('set_quality', { preset: element.dataset.quality });
    document.querySelectorAll('[data-quality]').forEach((b) => b.classList.remove('on'));
    element.classList.add('on');
  };
}

ui.mode.onclick = () => {
  state.absolute = !state.absolute;
  ui.mode.textContent = state.absolute ? 'Direct' : 'Trackpad';
  ui.mode.classList.toggle('on', state.absolute);
  command('set_cursor_mode', { mode: state.absolute ? 'absolute' : 'relative' });
  if (document.pointerLockElement === ui.video) document.exitPointerLock();
};

ui.keyboard.onclick = () => {
  ui.ime.focus();
  ui.ime.click();
};

ui.fullscreen.onclick = () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen?.().catch(() => {});
};

ui.lock.onclick = () => command('lock');
ui.unlock.onclick = connect;
ui.pair.onclick = submitPairing;
ui.code.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') submitPairing();
});

window.addEventListener('resize', () => { if (state.live) drawCursor(); });

const groupHex = (hex) => (hex.slice(0, 16).match(/.{4}/g) ?? []).join('-').toUpperCase();

function deviceLabel() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return 'iOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  return 'Navigateur';
}

// --- Démarrage --------------------------------------------------------------

(async function boot() {
  if (!window.isSecureContext) {
    setStatus('Contexte non sécurisé : WebRTC et WebCrypto sont indisponibles.', true);
    return;
  }
  try {
    state.identity = await loadIdentity();
    ui.fingerprint.textContent = `cet appareil ${groupHex(state.identity.publicKeyHex.slice(2))}`;
    setStatus('Prêt.');
    ui.connect.hidden = false;
    navigator.serviceWorker?.register('/sw.js').catch(() => {});
  } catch (e) {
    setStatus(`Identité locale indisponible : ${e.message}`, true);
  }
})();
