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
//
// Les calculs et les codecs vivent dans `core.js`, sans DOM, pour être testés
// hors navigateur. Ce fichier-ci ne fait que relier la page à cette logique.

import { scancodeOf, toScancode, SHORTCUTS, MODIFIERS } from '/keymap.js';
import {
  PROTOCOL, NONCE_LEN, DOMAIN_AUTH, DOMAIN_PAIR, DOMAIN_AGENT, MAX_EVENTS_PER_FRAME,
  toHex, fromHex, fromBase64, groupHex, transcript,
  event as input, encodeFrame, coalesce, chunk, textToEvents, textDelta, wheelUnits,
  buttonDelta,
  decodePointer, SeqTracker, contentRect,
  perUnitDelta, lossPercentDelta, estimateLatency, isStalled, reconnectDelay,
} from '/core.js';

// --- Éléments ---------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const ui = {
  gate: $('gate'), status: $('status'), unlock: $('unlock'), cancel: $('cancel'),
  pairing: $('pairing'), code: $('code'), pair: $('pair'),
  trust: $('trust'), trustText: $('trust-text'), forget: $('forget'),
  deviceFingerprint: $('device-fingerprint'), hostFingerprint: $('host-fingerprint'),
  options: $('options'), biometrics: $('biometrics'),
  stage: $('stage'), video: $('screen'), cursor: $('cursor'),
  notice: $('notice'), details: $('details'),
  hud: $('hud'), grip: $('grip'), badge: $('badge'), shortcuts: $('shortcuts'),
  displays: $('displays'), mode: $('mode'), keyboard: $('keyboard'),
  paste: $('paste'), copy: $('copy'), stats: $('stats'), fullscreen: $('fullscreen'),
  lock: $('lock'), disconnect: $('disconnect'), telemetry: $('telemetry'),
  confirm: $('confirm'), confirmTitle: $('confirm-title'), confirmText: $('confirm-text'),
  confirmYes: $('confirm-yes'), confirmNo: $('confirm-no'),
  clip: $('clip'), clipTitle: $('clip-title'), clipText: $('clip-text'),
  clipArea: $('clip-area'), clipAction: $('clip-action'), clipClose: $('clip-close'),
  toast: $('toast'), ime: $('ime'),
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

async function dbDelete(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
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
 * Windows Hello. C'est une protection de l'appareil, pas de l'hôte : elle
 * empêche quelqu'un qui tient le téléphone déverrouillé d'ouvrir la session.
 * Elle ne s'active que sur demande, depuis l'écran d'accueil.
 */
async function requireUserPresence() {
  const credentialId = await dbGet('webauthn');
  if (!credentialId) return { ok: true };
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomNonce(),
        allowCredentials: [{ id: credentialId, type: 'public-key' }],
        userVerification: 'required',
        timeout: 60000,
      },
    });
    return { ok: Boolean(assertion) };
  } catch (e) {
    return { ok: false, reason: e.name === 'NotAllowedError' ? 'refusée' : 'indisponible' };
  }
}

async function biometricsAvailable() {
  try {
    return Boolean(window.PublicKeyCredential)
      && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

async function enrollBiometrics() {
  try {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: randomNonce(),
        rp: { name: 'sidgate', id: location.hostname },
        user: {
          id: fromHex(state.identity.publicKeyHex.slice(0, 32)),
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
    if (!credential) return;
    await dbPut('webauthn', credential.rawId);
    toast('La biométrie sera demandée à chaque connexion');
  } catch (e) {
    // Une adresse IP ne peut pas servir d'identifiant de site à WebAuthn : la
    // biométrie n'existe que derrière un nom de domaine.
    toast(e.name === 'SecurityError'
      ? 'Biométrie indisponible à cette adresse : il faut un nom de domaine'
      : 'Biométrie non activée');
  }
  refreshOptions();
}

async function refreshOptions() {
  const paired = Boolean(await dbGet('agent'));
  const enrolled = Boolean(await dbGet('webauthn'));
  const available = await biometricsAvailable();
  ui.biometrics.hidden = !(paired && (available || enrolled));
  ui.biometrics.textContent = enrolled
    ? 'Ne plus exiger la biométrie à la connexion'
    : 'Exiger la biométrie à la connexion';
  ui.options.hidden = ui.biometrics.hidden;
}

// --- État -------------------------------------------------------------------

const state = {
  identity: null,
  /** Incrémenté à chaque tentative : un rappel d'une tentative passée s'ignore. */
  run: 0,
  socket: null,
  peer: null,
  input: null,
  control: null,
  serverNonce: null,
  clientNonce: null,
  agentKey: null,
  live: false,
  /** La session a-t-elle été établie depuis le dernier geste de l'utilisateur ? */
  wasLive: false,
  attempt: 0,
  retryTimer: null,
  /** Motif de fin annoncé par l'agent ou choisi par l'utilisateur. */
  cause: null,
  /** Cette tentative a-t-elle présenté une identité déjà appairée ? */
  presentedIdentity: false,
  caps: null,
  desktop: { width: 1920, height: 1080 },
  absolute: matchMedia('(pointer: fine)').matches,
  quality: null,
  // Curseur : position en pixels du bureau, coin haut-gauche de l'image.
  pointer: { x: 0, y: 0, visible: false, known: false },
  shape: { width: 12, height: 18, hotX: 0, hotY: 0, blank: false, custom: false },
  cursorUrl: null,
  pointerSeq: new SeqTracker(),
  seqLossy: 0,
  seqReliable: 0,
  pending: [],
  flushScheduled: false,
  held: new Set(),
  sticky: new Set(),
  statsTimer: null,
  rtcPrevious: null,
  rtc: null,
  agentStats: null,
  stalls: 0,
  showDetails: false,
  /** L'utilisateur a-t-il manipulé le panneau ? Il ne se replie alors plus seul. */
  hudTouched: false,
  wakeLock: null,
};

function setStatus(text, { error = false, busy = false } = {}) {
  ui.status.textContent = text;
  ui.status.classList.toggle('error', error);
  ui.status.classList.toggle('busy', busy);
}

let toastTimer;
function toast(text) {
  ui.toast.textContent = text;
  ui.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ui.toast.classList.remove('show'), 2600);
}

/** Demande une confirmation et renvoie la réponse. */
function confirmAction(title, text, action) {
  ui.confirmTitle.textContent = title;
  ui.confirmText.textContent = text;
  ui.confirmYes.textContent = action;
  ui.confirm.showModal();
  return new Promise((resolve) => {
    const done = (answer) => {
      ui.confirm.close();
      ui.confirmYes.onclick = null;
      ui.confirmNo.onclick = null;
      ui.confirm.oncancel = null;
      resolve(answer);
    };
    ui.confirmYes.onclick = () => done(true);
    ui.confirmNo.onclick = () => done(false);
    ui.confirm.oncancel = () => done(false);
  });
}

// --- Connexion --------------------------------------------------------------

async function connect() {
  clearTimeout(state.retryTimer);
  state.retryTimer = null;
  const run = ++state.run;
  state.cause = null;
  state.presentedIdentity = false;
  ui.unlock.hidden = true;
  ui.cancel.hidden = false;
  ui.pairing.hidden = true;
  ui.trust.hidden = true;
  setStatus('Connexion…', { busy: true });

  const presence = await requireUserPresence();
  if (run !== state.run) return;
  if (!presence.ok) {
    finish('refused', `Vérification biométrique ${presence.reason}.`);
    return;
  }

  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const socket = new WebSocket(`${scheme}://${location.host}/ws`);
  state.socket = socket;

  socket.onmessage = (message) => {
    if (run !== state.run) return;
    let parsed;
    try {
      parsed = JSON.parse(message.data);
    } catch {
      return;
    }
    handleServerMessage(parsed).catch((e) => finish('error', `Erreur : ${e.message}`));
  };
  socket.onclose = () => {
    if (run !== state.run) return;
    finish(state.cause ?? 'lost', state.wasLive ? 'Connexion perdue.' : 'Hôte injoignable.');
  };
}

function send(type, payload) {
  if (state.socket?.readyState !== WebSocket.OPEN) return;
  state.socket.send(JSON.stringify(payload === undefined ? { type } : { type, payload }));
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
    case 'closed': return onClosed(payload);
    case 'error': return finish('error', payload.message);
    default: return undefined;
  }
}

async function onChallenge(payload) {
  if (payload.protocol !== PROTOCOL) {
    finish('refused', 'Cette page ne correspond pas à la version de l’hôte. Rechargez-la.');
    return;
  }

  state.serverNonce = fromHex(payload.server_nonce);
  state.clientNonce = randomNonce();
  state.agentKey = payload.agent_key;
  ui.hostFingerprint.textContent = groupHex(payload.agent_key);

  const pinned = await dbGet('agent');
  if (pinned && pinned !== payload.agent_key) {
    // L'agent auquel nous avons été appairés n'est pas celui qui répond.
    finish('refused', 'L’identité de l’hôte a changé. Connexion interrompue par précaution.');
    offerToForget('Si l’hôte a été réinstallé, oubliez son ancienne identité puis appairez de '
      + 'nouveau. Dans le doute, n’en faites rien : c’est aussi ce que verrait la victime '
      + 'd’une interception.');
    return;
  }

  if (pinned) {
    const data = transcript(
      DOMAIN_AUTH, state.serverNonce, state.clientNonce, state.identity.publicKey,
    );
    state.presentedIdentity = true;
    send('authenticate', {
      protocol: PROTOCOL,
      client_key: state.identity.publicKeyHex,
      client_nonce: toHex(state.clientNonce),
      signature: await sign(state.identity.keys.privateKey, data),
    });
    setStatus('Authentification…', { busy: true });
  } else if (payload.pairing_open) {
    setStatus('Cet appareil n’est pas encore appairé.');
    ui.pairing.hidden = false;
    ui.pair.disabled = false;
    ui.code.value = '';
    ui.code.focus();
  } else {
    finish('refused',
      'Aucun appairage ouvert. Lancez « sidgate pair » sur l’hôte, puis reconnectez-vous.');
  }
}

async function submitPairing() {
  const code = ui.code.value.trim();
  if (code.replace(/[^a-z0-9]/gi, '').length !== 8) {
    setStatus('Le code compte huit caractères.', { error: true });
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
  setStatus('Appairage…', { busy: true });
}

async function onAuthOk(payload) {
  const data = transcript(
    DOMAIN_AGENT, state.serverNonce, state.clientNonce, state.identity.publicKey,
  );
  const verified = await verifyAgent(state.agentKey, payload.agent_signature, data);

  if (verified === false) {
    finish('refused', 'L’hôte n’a pas prouvé son identité. Connexion abandonnée.');
    return;
  }
  if (verified === null) {
    toast('Ce navigateur ne sait pas vérifier la signature de l’hôte');
  }

  await dbPut('agent', state.agentKey);
  ui.pairing.hidden = true;
  setStatus('Négociation du flux…', { busy: true });
  await startWebrtc();
}

function onAuthFailed({ reason }) {
  const messages = {
    rejected: 'Identité ou code refusé.',
    pairing_closed: 'Aucun appairage ouvert sur l’hôte.',
    rate_limited: 'Trop de tentatives. Patientez une minute.',
    protocol_mismatch: 'Cette page ne correspond pas à la version de l’hôte. Rechargez-la.',
    unexpected_message: 'Échange inattendu.',
  };
  // Refusé alors que nous présentions une identité déjà appairée : l'hôte ne
  // nous connaît plus. Tant que cet appareil garde l'hôte en mémoire, il ne
  // se verra jamais proposer d'appairage — il faut lui offrir d'en sortir.
  const forgotten = reason === 'rejected' && state.presentedIdentity;
  finish('refused', forgotten
    ? 'L’hôte ne reconnaît plus cet appareil.'
    : messages[reason] ?? 'Authentification refusée.');
  if (forgotten) {
    offerToForget('Il a pu être révoqué. Pour l’appairer de nouveau, oubliez l’hôte, puis '
      + 'reconnectez-vous pendant qu’un appairage y est ouvert.');
  }
}

/** Propose d'oublier l'hôte épinglé, avec l'explication qui convient au cas. */
function offerToForget(explanation) {
  ui.trustText.textContent = explanation;
  ui.trust.hidden = false;
}

function onClosed({ reason }) {
  const messages = {
    replaced: 'Session reprise par un autre de vos appareils.',
    busy: 'L’hôte reçoit trop de connexions. Réessayez dans un instant.',
  };
  finish(reason, messages[reason] ?? 'Session fermée par l’hôte.');
}

// --- WebRTC -----------------------------------------------------------------

async function startWebrtc() {
  const run = state.run;
  const peer = new RTCPeerConnection({ iceServers: [], bundlePolicy: 'max-bundle' });
  state.peer = peer;

  peer.addTransceiver('video', { direction: 'recvonly' });

  // Temps réel : ni ordre ni retransmission. Un mouvement perdu vaut mieux
  // qu'un mouvement en retard — le suivant corrige déjà la position. L'agent
  // y renvoie la position réelle du curseur, sous les mêmes garanties.
  state.input = peer.createDataChannel('input-raw', { ordered: false, maxRetransmits: 0 });
  state.input.binaryType = 'arraybuffer';
  state.input.onmessage = (message) => onPointerUpdate(message.data);

  // Fiable et ordonné : commandes en texte, appuis et saisie en binaire.
  state.control = peer.createDataChannel('control-secure', { ordered: true });
  state.control.binaryType = 'arraybuffer';
  state.control.onmessage = (message) => {
    if (typeof message.data !== 'string') return;
    try {
      handleControlEvent(JSON.parse(message.data));
    } catch {
      // Un événement illisible ne doit pas interrompre la session.
    }
  };

  peer.ontrack = (track) => {
    ui.video.srcObject = track.streams[0] ?? new MediaStream([track.track]);

    // Par défaut le navigateur retient les images dans un tampon de gigue pour
    // lisser la lecture — le bon choix pour une visioconférence, le mauvais
    // pour piloter un bureau. Mesuré avant ce réglage : 94 à 175 ms de tampon,
    // soit l'essentiel de la latence. `jitterBufferTarget` est l'API standard ;
    // `playoutDelayHint` est l'ancienne forme propre à Chrome.
    const receiver = track.receiver;
    if (receiver && 'jitterBufferTarget' in receiver) {
      receiver.jitterBufferTarget = 0;
    } else if (receiver && 'playoutDelayHint' in receiver) {
      receiver.playoutDelayHint = 0;
    }
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
    if (run !== state.run) return;
    if (peer.connectionState === 'connected') beginSession();
    if (['failed', 'disconnected', 'closed'].includes(peer.connectionState)) {
      finish(state.cause ?? 'lost', 'Transport perdu.');
    }
  };

  const offer = await peer.createOffer();
  await peer.setLocalDescription(offer);
  send('offer', { sdp: offer.sdp });
}

function beginSession() {
  if (state.live) return;
  state.live = true;
  state.wasLive = true;
  state.attempt = 0;
  state.rtcPrevious = null;
  state.rtc = null;
  state.agentStats = null;
  state.stalls = 0;
  state.pointerSeq = new SeqTracker();
  state.pointer.known = false;
  state.hudTouched = false;
  resetShape();

  clearInterval(state.statsTimer);
  state.statsTimer = setInterval(sampleRtcStats, 2000);

  ui.gate.hidden = true;
  ui.stage.classList.add('live');
  ui.hud.classList.add('on');
  setHud(true);
  setTimeout(() => { if (state.live && !state.hudTouched) setHud(false); }, 3200);
  renderMode();
  renderCursor();
  acquireWakeLock();
}

/**
 * Termine la tentative ou la session en cours et revient à l'écran d'accueil.
 *
 * @param {string} cause  `lost` pour une coupure subie, qui peut se retenter ;
 *   tout autre motif rend la main à l'utilisateur.
 * @param {string} message  Texte à afficher.
 */
function finish(cause, message) {
  const wasLive = state.live;
  // Tant que la session est encore tenue pour ouverte : après, plus rien ne
  // part. Si le canal est déjà tombé, l'agent relâche de son côté.
  releaseEverything();
  state.run += 1;
  state.live = false;
  clearInterval(state.statsTimer);
  state.statsTimer = null;

  const socket = state.socket;
  state.socket = null;
  if (socket && socket.readyState <= WebSocket.OPEN) socket.close();
  state.peer?.close();
  state.peer = null;
  state.input = null;
  state.control = null;
  state.caps = null;
  state.pending = [];

  resetPointers();
  if (document.pointerLockElement) document.exitPointerLock();
  state.wakeLock?.release().catch(() => {});
  state.wakeLock = null;
  ui.video.srcObject = null;
  ui.stage.classList.remove('live');
  ui.hud.classList.remove('on', 'open');
  ui.notice.hidden = true;
  ui.gate.hidden = false;
  ui.pairing.hidden = true;
  ui.cancel.hidden = true;
  for (const dialog of [ui.confirm, ui.clip]) if (dialog.open) dialog.close();
  refreshOptions();

  // Une coupure subie en pleine session se retente toute seule ; avec la
  // biométrie activée, chaque tentative ouvrirait une invite : on s'abstient.
  const delay = wasLive || state.attempt > 0 ? reconnectDelay(cause, state.attempt) : null;
  if (delay !== null) {
    dbGet('webauthn').then((credential) => {
      if (credential || state.live || state.socket) {
        idle(message);
        return;
      }
      state.attempt += 1;
      setStatus(`${message} Nouvelle tentative…`, { busy: true });
      ui.unlock.hidden = true;
      ui.cancel.hidden = false;
      state.retryTimer = setTimeout(connect, delay);
    });
    return;
  }
  idle(message, cause !== 'left');
}

/** Rend la main à l'utilisateur, bouton de connexion affiché. */
function idle(message, error = true) {
  state.attempt = 0;
  state.wasLive = false;
  setStatus(message, { error });
  ui.unlock.hidden = false;
  ui.cancel.hidden = true;
}

function cancel() {
  clearTimeout(state.retryTimer);
  state.retryTimer = null;
  state.cause = 'left';
  finish('left', 'Prêt.');
}

function disconnect() {
  state.cause = 'left';
  send('bye');
  finish('left', 'Déconnecté.');
}

async function acquireWakeLock() {
  // Un téléphone qui s'éteint au bout de trente secondes sans toucher l'écran
  // couperait la session en plein visionnage.
  try {
    state.wakeLock = await navigator.wakeLock?.request('screen');
  } catch {
    // Refusé en économie d'énergie : sans conséquence.
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && state.live) acquireWakeLock();
});

// --- Télémétrie -------------------------------------------------------------

/**
 * Relève les statistiques WebRTC du récepteur vidéo.
 *
 * Les compteurs du navigateur sont cumulés depuis le début de la session : on
 * travaille sur la différence entre deux relevés, sans quoi un pic de gigue
 * survenu à la première seconde pèserait encore sur la moyenne une heure plus
 * tard.
 */
async function sampleRtcStats() {
  if (!state.peer) return;
  let report;
  try {
    report = await state.peer.getStats();
  } catch {
    return;
  }

  let inbound = null;
  let rttSeconds = null;
  report.forEach((entry) => {
    if (entry.type === 'inbound-rtp' && entry.kind === 'video') inbound = entry;
    if (entry.type === 'candidate-pair' && entry.state === 'succeeded'
        && (entry.nominated || entry.selected)
        && typeof entry.currentRoundTripTime === 'number') {
      rttSeconds = entry.currentRoundTripTime;
    }
  });
  if (!inbound) return;

  // Un champ que le navigateur n'expose pas vaut `null`, jamais 0 : afficher
  // « 0 ms de décodage » là où rien n'est mesuré serait inventer une mesure.
  const numeric = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
  const current = {
    jitterDelay: numeric(inbound.jitterBufferDelay),
    jitterCount: numeric(inbound.jitterBufferEmittedCount),
    decodeTime: numeric(inbound.totalDecodeTime),
    decoded: numeric(inbound.framesDecoded),
    lost: numeric(inbound.packetsLost),
    received: numeric(inbound.packetsReceived),
  };
  const previous = state.rtcPrevious;
  state.rtcPrevious = current;
  if (!previous) return;

  state.rtc = {
    jitterMs: perUnitDelta(current.jitterDelay, previous.jitterDelay,
      current.jitterCount, previous.jitterCount, 1000),
    decodeMs: perUnitDelta(current.decodeTime, previous.decodeTime,
      current.decoded, previous.decoded, 1000),
    rttMs: rttSeconds === null ? null : rttSeconds * 1000,
    lossPercent: lossPercentDelta(current, previous),
  };

  // Filet : le décodeur attend une image clé que personne ne lui envoie.
  state.stalls = isStalled(current, previous) ? state.stalls + 1 : 0;
  if (state.stalls >= 2) {
    state.stalls = 0;
    command('request_keyframe');
  }
}

function renderTelemetry(stats) {
  state.agentStats = stats;
  const latency = estimateLatency(stats.encode_ms, state.rtc, stats.rtt_ms);
  const mbps = (stats.bitrate_bps / 1e6).toFixed(1);
  // Uniquement des nombres formatés : aucune chaîne venue du réseau n'est
  // insérée ici, d'où l'usage acceptable d'innerHTML pour la mise en forme.
  ui.telemetry.innerHTML = [
    latency ? `<span><b>≥${latency.total.toFixed(0)}</b> ms${latency.complete ? '' : '*'}</span>` : '',
    `<span><b>${Number(stats.fps).toFixed(0)}</b> i/s</span>`,
    `<span><b>${mbps}</b> Mbit/s</span>`,
    latency && latency.lossPercent !== null && latency.lossPercent >= 0.1
      ? `<span><b>${latency.lossPercent.toFixed(1)}</b> % pertes</span>` : '',
  ].filter(Boolean).join('');
  renderDetails(latency);
}

function renderDetails(latency) {
  ui.details.hidden = !state.showDetails;
  if (!state.showDetails) return;
  const stats = state.agentStats;
  const ms = (value) => (value === null || value === undefined ? 'n/d' : `${value.toFixed(1)} ms`);
  const lines = [
    `bureau      ${state.desktop.width}×${state.desktop.height}`,
    `encodage    ${ms(latency?.encodeMs)}`,
    `réseau      ${ms(latency?.networkMs)}`,
    `gigue       ${ms(latency?.jitterMs)}`,
    `décodage    ${ms(latency?.decodeMs)}`,
    `latence     ${latency ? `≥ ${latency.total.toFixed(0)} ms` : 'n/d'}${latency && !latency.complete ? ' (incomplète)' : ''}`,
    '            hors présentation et synchro verticale',
  ];
  if (stats) {
    const optional = (value, digits, unit) =>
      (typeof value === 'number' ? `${value.toFixed(digits)} ${unit}` : 'n/d');
    lines.push(
      `cadence     ${Number(stats.fps).toFixed(0)} i/s, ${stats.frames_dropped} écartées`,
      `débit       ${(stats.bitrate_bps / 1e6).toFixed(2)} Mbit/s`,
      `pertes      ${latency?.lossPercent === null || latency?.lossPercent === undefined ? 'n/d' : `${latency.lossPercent.toFixed(1)} %`}`,
      `hôte        ${optional(stats.cpu_percent, 1, '% CPU')}, ${optional(stats.rss_mb, 0, 'Mo')}`,
    );
  }
  ui.details.textContent = lines.join('\n');
}

// --- Canal de contrôle ------------------------------------------------------

function command(cmd, args) {
  if (state.control?.readyState !== 'open') return;
  try {
    state.control.send(JSON.stringify(args === undefined ? { cmd } : { cmd, args }));
  } catch {
    // Canal en cours de fermeture : la commande n'a plus de destinataire.
  }
}

function handleControlEvent(message) {
  switch (message.evt) {
    case 'hello':
      onHello(message.capabilities);
      break;
    case 'stats':
      renderTelemetry(message);
      break;
    case 'command_rejected':
      toast(rejection(message.command, message.reason));
      break;
    case 'capture_unavailable': {
      // La session reste ouverte : seule la vidéo manque. Si la cause est
      // passagère — poste verrouillé — elle revient d'elle-même, et fermer la
      // connexion obligerait à tout renégocier.
      const reason = String(message.message);
      const sentence = `${reason.charAt(0).toUpperCase()}${reason.slice(1)}.`;
      ui.notice.textContent = message.transient
        ? `${sentence} La vidéo reprendra d’elle-même.` : sentence;
      ui.notice.hidden = false;
      break;
    }
    case 'capture_resumed':
      ui.notice.hidden = true;
      break;
    case 'display_changed':
      state.desktop = { width: message.width, height: message.height };
      renderCursor();
      break;
    case 'pointer_shape':
      onPointerShape(message);
      break;
    case 'clipboard':
      onHostClipboard(message);
      break;
    case 'ping':
      command('pong', { seq: message.seq });
      break;
    default:
      break;
  }
}

function rejection(name, reason) {
  const names = {
    lock: 'Verrouillage', sleep: 'Mise en veille', reboot: 'Redémarrage', shutdown: 'Extinction',
    set_quality: 'Changement de qualité', select_display: 'Changement d’écran',
    request_clipboard: 'Lecture du presse-papiers', request_keyframe: 'Rafraîchissement',
  };
  const reasons = {
    not_permitted: 'refusé par la configuration de l’hôte',
    rate_limited: 'trop de commandes, patientez',
    wrong_state: 'impossible pour l’instant',
    failed: 'échec sur l’hôte',
    malformed: 'commande non reconnue',
  };
  return `${names[name] ?? 'Commande'} : ${reasons[reason] ?? 'refusé'}`;
}

function onHello(caps) {
  state.caps = caps;
  state.desktop = { width: caps.width, height: caps.height };
  state.quality = caps.quality;
  ui.notice.hidden = true;
  renderMode();

  ui.badge.hidden = caps.input_injection;
  ui.copy.hidden = !caps.clipboard;
  for (const element of document.querySelectorAll('[data-power]')) {
    element.hidden = !caps.power_actions;
  }

  ui.displays.hidden = caps.displays.length < 2;
  ui.displays.replaceChildren(...caps.displays.map((display, position) => {
    const element = document.createElement('button');
    element.textContent = `Écran ${position + 1}${display.primary ? ' ★' : ''}`;
    element.title = `${display.width}×${display.height}`;
    element.classList.toggle('on', display.index === caps.display);
    element.onclick = () => command('select_display', { index: display.index });
    return element;
  }));
  renderCursor();
}

// --- Presse-papiers ---------------------------------------------------------

async function onHostClipboard({ text, truncated }) {
  if (!text) {
    toast('Le presse-papiers de l’hôte ne contient pas de texte');
    return;
  }
  const suffix = truncated ? ' (tronqué)' : '';
  try {
    await navigator.clipboard.writeText(text);
    toast(`Presse-papiers de l’hôte copié${suffix}`);
  } catch {
    // Le navigateur exige un geste récent pour écrire dans le presse-papiers ;
    // la réponse de l'hôte est arrivée trop tard pour compter comme tel.
    openClipDialog({
      title: `Presse-papiers de l’hôte${suffix}`,
      text: 'Votre navigateur demande une confirmation pour copier ce texte.',
      value: text,
      action: 'Copier',
      onAction: async (value) => {
        await navigator.clipboard.writeText(value).catch(() => {});
        toast('Copié');
      },
    });
  }
}

async function pasteToHost() {
  let text = null;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    // Lecture refusée ou non proposée par ce navigateur : saisie manuelle.
  }
  if (text) {
    typeText(text);
    return;
  }
  openClipDialog({
    title: 'Coller sur l’hôte',
    text: 'Collez ici le texte à saisir sur l’hôte.',
    value: '',
    action: 'Envoyer',
    onAction: (value) => typeText(value),
  });
}

function openClipDialog({ title, text, value, action, onAction }) {
  ui.clipTitle.textContent = title;
  ui.clipText.textContent = text;
  ui.clipArea.value = value;
  ui.clipAction.textContent = action;
  ui.clipAction.onclick = async () => {
    await onAction(ui.clipArea.value);
    ui.clip.close();
  };
  ui.clip.showModal();
  ui.clipArea.focus();
  ui.clipArea.select();
}

/** Longueur maximale d'un texte tapé d'un coup sur l'hôte. */
const MAX_TYPED_CHARS = 20000;

/**
 * Tape un texte sur l'hôte, par paquets espacés.
 *
 * L'application qui a le focus traite les frappes à son rythme ; lui en livrer
 * vingt mille d'un bloc en ferait perdre une partie à certaines.
 */
function typeText(text) {
  if (text.length > MAX_TYPED_CHARS) {
    toast(`Texte coupé à ${MAX_TYPED_CHARS} caractères`);
  }
  const frames = chunk(textToEvents(text.slice(0, MAX_TYPED_CHARS)), 32);
  const run = state.run;
  const next = () => {
    if (run !== state.run || !frames.length) return;
    sendReliable(frames.shift());
    setTimeout(next, 8);
  };
  next();
}

// --- Émission des entrées ---------------------------------------------------

const canSend = () => state.live && state.caps?.input_injection !== false;

/** Met en file un événement que le suivant rattrape, pour le canal non fiable. */
function queueLossy(bytes) {
  if (!canSend() || state.input?.readyState !== 'open') return;
  state.pending.push(bytes);
  if (state.flushScheduled) return;
  state.flushScheduled = true;
  // Regrouper sur une trame d'affichage : un geste continu produit une seule
  // trame au lieu de dizaines de datagrammes.
  requestAnimationFrame(flushLossy);
}

function flushLossy() {
  state.flushScheduled = false;
  if (!state.pending.length || state.input?.readyState !== 'open') {
    state.pending = [];
    return;
  }
  const events = coalesce(state.pending.splice(0));
  for (const part of chunk(events, MAX_EVENTS_PER_FRAME)) {
    try {
      state.input.send(encodeFrame(state.seqLossy, part));
    } catch {
      // Canal saturé : la trame suivante portera la position à jour.
    }
    state.seqLossy = (state.seqLossy + 1) >>> 0;
  }
}

/**
 * Envoie tout de suite des événements qui ne doivent pas se perdre.
 *
 * Les mouvements en attente partent d'abord : un clic doit suivre le dernier
 * déplacement, pas le précéder.
 */
function sendReliable(events) {
  if (!canSend() || state.control?.readyState !== 'open') return;
  flushLossy();
  for (const part of chunk(events, MAX_EVENTS_PER_FRAME)) {
    try {
      state.control.send(encodeFrame(state.seqReliable, part));
    } catch {
      // Canal en cours de fermeture : l'agent relâche tout à la fin de session.
      return;
    }
    state.seqReliable = (state.seqReliable + 1) >>> 0;
  }
}

/** Traduit une touche décrite par position ou par caractère. */
const keyEvent = (key, pressed) => {
  if (key.char) return input.keyChar(key.char, pressed);
  const mapped = toScancode(key.code);
  return mapped ? input.key(mapped.scancode, pressed, mapped.extended) : null;
};

async function pressCombo(keys) {
  sendReliable(keys.map((key) => keyEvent(key, true)).filter(Boolean));
  await new Promise((resolve) => setTimeout(resolve, 40));
  sendReliable([...keys].reverse().map((key) => keyEvent(key, false)).filter(Boolean));
  releaseSticky();
}

/** Relâche tout ce que ce client tient enfoncé sur l'hôte. */
function releaseEverything() {
  const events = [];
  for (const code of state.held) {
    const mapped = toScancode(code);
    if (mapped) events.push(input.key(mapped.scancode, false, mapped.extended));
  }
  state.held.clear();
  for (const code of state.sticky) {
    const mapped = toScancode(code);
    if (mapped) events.push(input.key(mapped.scancode, false, mapped.extended));
  }
  state.sticky.clear();
  renderSticky();
  if (gesture?.dragging) {
    gesture.dragging = false;
    events.push(input.button(0, false));
  }
  for (const index of mouseButtons) events.push(input.button(index, false));
  mouseButtons.clear();
  if (events.length) sendReliable(events);
}

// --- Curseur ----------------------------------------------------------------

/**
 * Le bureau capturé ne contient jamais le curseur : le compositeur le livre à
 * part. L'agent en transmet la forme et la position réelle, et c'est ici
 * qu'il est dessiné.
 */
function resetShape() {
  // Flèche par défaut, affichée tant que l'hôte n'a pas donné la sienne.
  const canvas = ui.cursor;
  canvas.width = 12;
  canvas.height = 18;
  const context = canvas.getContext('2d');
  context.clearRect(0, 0, 12, 18);
  const arrow = new Path2D('M1 1l10 9.5H6.2l2.6 5.6-2.1 1-2.6-5.7L1 14.6z');
  context.fillStyle = '#fff';
  context.strokeStyle = '#000';
  context.lineWidth = 1.1;
  context.lineJoin = 'round';
  context.fill(arrow);
  context.stroke(arrow);
  state.shape = { width: 12, height: 18, hotX: 1, hotY: 1, blank: false, custom: false };
  state.cursorUrl = null;
}

function onPointerShape({ width, height, hot_x: hotX, hot_y: hotY, rgba }) {
  const pixels = fromBase64(rgba);
  if (width < 1 || height < 1 || width > 256 || height > 256
      || pixels.length !== width * height * 4) {
    return;
  }
  const canvas = ui.cursor;
  canvas.width = width;
  canvas.height = height;
  canvas.getContext('2d').putImageData(
    new ImageData(new Uint8ClampedArray(pixels.buffer), width, height), 0, 0,
  );
  let blank = true;
  for (let i = 3; i < pixels.length; i += 4) {
    if (pixels[i] !== 0) {
      blank = false;
      break;
    }
  }
  state.shape = { width, height, hotX, hotY, blank, custom: true };
  state.cursorUrl = null;
  renderCursor();
}

function onPointerUpdate(buffer) {
  const update = decodePointer(buffer);
  if (!update || !state.pointerSeq.accept(update.seq)) return;
  state.pointer = { x: update.x, y: update.y, visible: update.visible, known: true };
  renderCursor();
}

/** Rectangle réellement occupé par l'image dans l'élément vidéo. */
function videoContentRect() {
  const box = ui.video.getBoundingClientRect();
  const ratio = (ui.video.videoWidth || state.desktop.width)
    / (ui.video.videoHeight || state.desktop.height);
  return contentRect(box, ratio, portrait.matches ? 0 : 0.5);
}

// Téléphone tenu debout : l'image est calée en haut de l'écran, pour que le
// panneau de commandes s'ouvre sous elle plutôt que par-dessus. La feuille de
// style applique la même règle à `object-position`.
const portrait = matchMedia('(orientation: portrait)');
portrait.addEventListener('change', () => renderCursor());

/**
 * Le curseur du système local tient-il lieu de curseur distant ?
 *
 * Avec une souris en pointage direct, oui : il est déjà à l'endroit visé, sans
 * le moindre délai. Il lui suffit de prendre la forme de celui de l'hôte.
 */
const usesNativeCursor = () => state.absolute && lastPointerType !== 'touch';

function renderCursor() {
  if (!state.live) return;
  const rect = videoContentRect();
  const scale = rect.width / state.desktop.width;
  const shape = state.shape;

  if (usesNativeCursor()) {
    ui.cursor.classList.remove('on');
    ui.video.style.cursor = shape.blank ? 'none' : nativeCursor(scale);
    return;
  }

  ui.video.style.cursor = 'none';
  const visible = state.pointer.known && state.pointer.visible && !shape.blank;
  ui.cursor.classList.toggle('on', visible);
  if (!visible) return;
  const stage = ui.stage.getBoundingClientRect();
  const left = rect.x - stage.x + state.pointer.x * scale;
  const top = rect.y - stage.y + state.pointer.y * scale;
  ui.cursor.style.transform = `translate(${left}px, ${top}px) scale(${scale})`;
}

/** Valeur CSS `cursor` reproduisant le curseur de l'hôte à l'échelle de l'image. */
function nativeCursor(scale) {
  const shape = state.shape;
  if (!shape.custom) return 'default';
  const key = scale.toFixed(3);
  if (state.cursorUrl?.key === key) return state.cursorUrl.value;

  // Les navigateurs ignorent une image de curseur de plus de 128 pixels.
  const factor = Math.min(scale, 128 / Math.max(shape.width, shape.height));
  const width = Math.max(1, Math.round(shape.width * factor));
  const height = Math.max(1, Math.round(shape.height * factor));
  const scaled = document.createElement('canvas');
  scaled.width = width;
  scaled.height = height;
  scaled.getContext('2d').drawImage(ui.cursor, 0, 0, width, height);
  const hotX = Math.min(width - 1, Math.round(shape.hotX * factor));
  const hotY = Math.min(height - 1, Math.round(shape.hotY * factor));
  const value = `url(${scaled.toDataURL('image/png')}) ${hotX} ${hotY}, default`;
  state.cursorUrl = { key, value };
  return value;
}

// --- Pointeur ---------------------------------------------------------------

let lastPointerType = matchMedia('(pointer: fine)').matches ? 'mouse' : 'touch';
const mouseButtons = new Set();
const wheelCarry = { x: 0, y: 0 };

/** Position normalisée d'un événement dans l'image du bureau, ou `null` hors image. */
function normalized(pointerEvent) {
  const rect = videoContentRect();
  const x = (pointerEvent.clientX - rect.x) / rect.width;
  const y = (pointerEvent.clientY - rect.y) / rect.height;
  if (x < 0 || x > 1 || y < 0 || y > 1) return null;
  return { x, y };
}

const pointerLocked = () => document.pointerLockElement === ui.video;

function notePointerType(type) {
  if (type === lastPointerType) return;
  lastPointerType = type;
  renderCursor();
}

// Souris et stylet.
//
// Un seul traitement pour l'appui, le mouvement et le relâchement : les
// boutons se lisent dans le masque de chaque événement, pas dans son type.

/** Le clic en cours a servi à capturer la souris : il ne va pas à l'hôte. */
let swallowClick = false;

/**
 * Aligne les boutons tenus sur l'hôte sur ceux que rapporte le navigateur.
 * @param {boolean} allowPress  Faux hors de l'image : on y relâche, on n'y
 *   appuie pas.
 */
function buttonEvents(pointerEvent, allowPress) {
  const { press, release } = buttonDelta(pointerEvent.buttons, mouseButtons);
  const events = [];
  for (const index of release) {
    mouseButtons.delete(index);
    events.push(input.button(index, false));
  }
  if (allowPress) {
    for (const index of press) {
      mouseButtons.add(index);
      events.push(input.button(index, true));
    }
  }
  return events;
}

function onMouse(pointerEvent) {
  if (state.absolute) {
    if (pointerEvent.type === 'pointerdown') {
      // Garde les événements quand le pointeur sort de l'image, bouton tenu.
      try {
        ui.video.setPointerCapture(pointerEvent.pointerId);
      } catch {
        // Refusé si le pointeur est déjà capturé autrement : sans conséquence.
      }
    }
    const at = normalized(pointerEvent);
    const move = at ? input.moveAbsolute(at.x, at.y) : null;
    const buttons = buttonEvents(pointerEvent, at !== null);
    if (buttons.length) {
      // La position accompagne le clic sur le canal fiable : il doit tomber
      // là où il a été fait, même si le dernier mouvement s'est perdu.
      sendReliable(move ? [move, ...buttons] : buttons);
    } else if (move) {
      queueLossy(move);
    }
    return;
  }

  // Mode trackpad à la souris : il faut capturer le pointeur pour recevoir des
  // déplacements sans borne. Le premier clic sert à cela, et à rien d'autre.
  if (!pointerLocked()) {
    if (pointerEvent.type === 'pointerdown') {
      swallowClick = true;
      ui.video.requestPointerLock?.();
    }
    return;
  }
  if (pointerEvent.type === 'pointermove'
      && (pointerEvent.movementX || pointerEvent.movementY)) {
    queueLossy(input.moveRelative(pointerEvent.movementX, pointerEvent.movementY));
  }
  if (swallowClick) {
    if (pointerEvent.buttons === 0) swallowClick = false;
    return;
  }
  const buttons = buttonEvents(pointerEvent, true);
  if (buttons.length) sendReliable(buttons);
}

// Tactile.
//
// Un doigt déplace le pointeur, un toucher bref clique. Deux doigts défilent,
// ou font un clic droit s'ils ne bougent pas. Un appui long fait aussi un clic
// droit. Un double toucher dont le second se prolonge fait glisser, comme sur
// le pavé tactile d'un ordinateur portable.

const TAP_MS = 280;
const TAP_SLOP = 10;
const LONG_PRESS_MS = 550;
const DOUBLE_TAP_MS = 320;

const touches = new Map();
let gesture = null;
let lastTapAt = 0;

function centroid() {
  let x = 0;
  let y = 0;
  for (const touch of touches.values()) {
    x += touch.x;
    y += touch.y;
  }
  return { x: x / touches.size, y: y / touches.size };
}

function onTouchDown(pointerEvent) {
  touches.set(pointerEvent.pointerId, { x: pointerEvent.clientX, y: pointerEvent.clientY });
  const now = performance.now();

  if (touches.size === 1) {
    gesture = {
      start: now, fingers: 1, moved: false, consumed: false,
      dragging: now - lastTapAt < DOUBLE_TAP_MS,
      last: { x: pointerEvent.clientX, y: pointerEvent.clientY },
      travel: 0, carry: { x: 0, y: 0 }, timer: null,
    };
    const at = state.absolute ? normalized(pointerEvent) : null;
    const events = at ? [input.moveAbsolute(at.x, at.y)] : [];
    if (gesture.dragging) events.push(input.button(0, true));
    if (events.length) sendReliable(events);

    if (!gesture.dragging) {
      const current = gesture;
      current.timer = setTimeout(() => {
        if (gesture !== current || current.moved || current.fingers !== 1) return;
        current.consumed = true;
        navigator.vibrate?.(15);
        sendReliable([input.button(1, true), input.button(1, false)]);
      }, LONG_PRESS_MS);
    }
    return;
  }

  if (!gesture) return;
  clearTimeout(gesture.timer);
  gesture.fingers = Math.max(gesture.fingers, touches.size);
  if (gesture.dragging) {
    gesture.dragging = false;
    sendReliable([input.button(0, false)]);
  }
  gesture.last = centroid();
}

function onTouchMove(pointerEvent) {
  const touch = touches.get(pointerEvent.pointerId);
  if (!touch || !gesture) return;
  touch.x = pointerEvent.clientX;
  touch.y = pointerEvent.clientY;

  const at = centroid();
  const dx = at.x - gesture.last.x;
  const dy = at.y - gesture.last.y;
  gesture.last = at;
  gesture.travel += Math.hypot(dx, dy);
  if (!gesture.moved && gesture.travel > TAP_SLOP) {
    gesture.moved = true;
    clearTimeout(gesture.timer);
  }
  if (!gesture.moved) return;

  if (touches.size >= 2) {
    // Défilement « naturel » : le contenu suit les doigts.
    const x = gesture.carry.x - dx * 3;
    const y = gesture.carry.y + dy * 3;
    const units = { x: Math.trunc(x), y: Math.trunc(y) };
    gesture.carry = { x: x - units.x, y: y - units.y };
    if (units.x || units.y) queueLossy(input.scroll(units.x, units.y));
    return;
  }
  if (gesture.fingers > 1) return;

  if (state.absolute) {
    const target = normalized(pointerEvent);
    if (target) queueLossy(input.moveAbsolute(target.x, target.y));
  } else {
    // Gain progressif : les petits gestes gagnent en précision, les grands en
    // portée, comme sur un pavé tactile matériel.
    const gain = 1 + Math.min(1.6, Math.hypot(dx, dy) / 14);
    queueLossy(input.moveRelative(dx * gain, dy * gain));
  }
}

function onTouchUp(pointerEvent) {
  if (!touches.delete(pointerEvent.pointerId) || !gesture) return;
  if (touches.size > 0) {
    gesture.last = centroid();
    return;
  }

  const finished = gesture;
  gesture = null;
  clearTimeout(finished.timer);
  const brief = performance.now() - finished.start < TAP_MS;

  if (finished.dragging) {
    sendReliable([input.button(0, false)]);
  } else if (!finished.consumed && !finished.moved && brief) {
    const index = finished.fingers >= 2 ? 1 : 0;
    sendReliable([input.button(index, true), input.button(index, false)]);
    if (index === 0) lastTapAt = performance.now();
  }
}

ui.video.addEventListener('pointerdown', (pointerEvent) => {
  if (!state.live) return;
  notePointerType(pointerEvent.pointerType);
  if (pointerEvent.pointerType === 'touch') onTouchDown(pointerEvent);
  else onMouse(pointerEvent);
});

ui.video.addEventListener('pointermove', (pointerEvent) => {
  if (!state.live) return;
  notePointerType(pointerEvent.pointerType);
  if (pointerEvent.pointerType === 'touch') onTouchMove(pointerEvent);
  else onMouse(pointerEvent);
});

for (const type of ['pointerup', 'pointercancel']) {
  ui.video.addEventListener(type, (pointerEvent) => {
    if (!state.live) return;
    if (pointerEvent.pointerType === 'touch') onTouchUp(pointerEvent);
    else onMouse(pointerEvent);
  });
}

/** Oublie tout geste en cours : à la fin d'une session, plus rien n'est tenu. */
function resetPointers() {
  clearTimeout(gesture?.timer);
  gesture = null;
  touches.clear();
  mouseButtons.clear();
  swallowClick = false;
  wheelCarry.x = 0;
  wheelCarry.y = 0;
}

ui.video.addEventListener('wheel', (wheelEvent) => {
  if (!state.live) return;
  wheelEvent.preventDefault();
  const vertical = wheelUnits(wheelEvent.deltaY, wheelEvent.deltaMode, wheelCarry.y);
  // Horizontalement, navigateur et Windows comptent dans le même sens.
  const horizontal = wheelUnits(-wheelEvent.deltaX, wheelEvent.deltaMode, wheelCarry.x);
  wheelCarry.x = horizontal.carry;
  wheelCarry.y = vertical.carry;
  if (horizontal.units || vertical.units) {
    queueLossy(input.scroll(horizontal.units, vertical.units));
  }
}, { passive: false });

// Empêche le navigateur de retirer le focus au champ de saisie — donc de
// replier le clavier virtuel — à chaque toucher sur l'image.
ui.video.addEventListener('touchstart', (touchEvent) => touchEvent.preventDefault(),
  { passive: false });
ui.video.addEventListener('contextmenu', (mouseEvent) => mouseEvent.preventDefault());
document.addEventListener('pointerlockchange', () => {
  if (pointerLocked()) return;
  // Capture perdue — Échap, changement de fenêtre — boutons encore tenus.
  const released = [...mouseButtons].map((index) => input.button(index, false));
  mouseButtons.clear();
  swallowClick = false;
  if (released.length) sendReliable(released);
});

// --- Clavier ----------------------------------------------------------------

/** L'utilisateur tape-t-il pour la page elle-même, et non pour l'hôte ? */
const typingLocally = (target) =>
  target === ui.code || target === ui.clipArea || ui.confirm.open || ui.clip.open;

window.addEventListener('keydown', (keyboardEvent) => {
  if (!state.live || typingLocally(keyboardEvent.target)) return;
  // Composition en cours : c'est du texte, il passera par le champ de saisie.
  if (keyboardEvent.isComposing || keyboardEvent.keyCode === 229) return;
  const mapped = scancodeOf(keyboardEvent);
  if (!mapped) return;
  keyboardEvent.preventDefault();
  // Une touche n'est « tenue » que si son relâchement saura la retrouver,
  // c'est-à-dire si son code physique se traduit. Un clavier virtuel donne un
  // code vide ou « Unidentified » : la touche est alors frappée d'un coup.
  if (toScancode(keyboardEvent.code)) {
    state.held.add(keyboardEvent.code);
    sendReliable([input.key(mapped.scancode, true, mapped.extended)]);
  } else {
    sendReliable([
      input.key(mapped.scancode, true, mapped.extended),
      input.key(mapped.scancode, false, mapped.extended),
    ]);
    releaseSticky();
  }
});

window.addEventListener('keyup', (keyboardEvent) => {
  if (!state.live || typingLocally(keyboardEvent.target)) return;
  const mapped = toScancode(keyboardEvent.code);
  if (!mapped) return;
  keyboardEvent.preventDefault();
  state.held.delete(keyboardEvent.code);
  sendReliable([input.key(mapped.scancode, false, mapped.extended)]);
  if (!MODIFIER_CODES.has(keyboardEvent.code)) releaseSticky();
});

const MODIFIER_CODES = new Set(['ControlLeft', 'ControlRight', 'ShiftLeft', 'ShiftRight',
  'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight']);

// Un onglet qui perd le focus ne reçoit plus les relâchements : sans ce filet,
// une touche resterait enfoncée sur l'hôte.
window.addEventListener('blur', () => {
  if (state.live) releaseEverything();
});

// Saisie de texte : claviers virtuels et méthodes de saisie.
//
// Ces claviers ne produisent pas de touches mais du texte, souvent par
// composition : le mot en cours est réécrit à chaque frappe. Le champ caché
// sert de brouillon ; à chaque changement, la différence avec ce qui a déjà
// été envoyé part vers l'hôte — des retours arrière pour ce qui a disparu, des
// caractères pour ce qui est apparu.

/** Caractère gardé en tête du champ : sans lui, un retour arrière sur un champ
 *  vide ne déclencherait aucun événement. */
const SENTINEL = '​';
let typed = '';
let composing = false;

function resetIme() {
  typed = '';
  ui.ime.value = SENTINEL;
}

function onImeInput() {
  const value = ui.ime.value;
  if (!value.startsWith(SENTINEL)) {
    // La sentinelle a été effacée : retour arrière au-delà de ce brouillon.
    sendReliable([...backspaces(1)]);
    resetIme();
    return;
  }
  const current = value.slice(SENTINEL.length);
  const { backspaces: removed, added } = textDelta(typed, current);
  typed = current;

  const events = [...backspaces(removed)];
  if (added) {
    const modified = [...state.sticky].some((code) => code !== 'ShiftLeft');
    if (modified && added.length === 1) {
      // Modificatrice à bascule active : c'est un raccourci, pas du texte.
      const char = added.toLowerCase();
      events.push(input.keyChar(char, true), input.keyChar(char, false));
    } else {
      events.push(...textToEvents(added));
    }
  }
  if (events.length) sendReliable(events);
  if (added) releaseSticky();
  if (!composing && current.length > 48) resetIme();
}

function backspaces(count) {
  const mapped = toScancode('Backspace');
  const events = [];
  for (let i = 0; i < count; i += 1) {
    events.push(input.key(mapped.scancode, true, false), input.key(mapped.scancode, false, false));
  }
  return events;
}

ui.ime.addEventListener('input', onImeInput);
ui.ime.addEventListener('compositionstart', () => { composing = true; });
ui.ime.addEventListener('compositionend', () => {
  composing = false;
  onImeInput();
  resetIme();
});
ui.ime.addEventListener('focus', resetIme);
ui.ime.addEventListener('blur', () => ui.keyboard.classList.remove('on'));

// Modificatrices à bascule.

function toggleSticky(code) {
  const mapped = toScancode(code);
  if (state.sticky.has(code)) {
    state.sticky.delete(code);
    sendReliable([input.key(mapped.scancode, false, mapped.extended)]);
  } else {
    state.sticky.add(code);
    sendReliable([input.key(mapped.scancode, true, mapped.extended)]);
  }
  renderSticky();
}

function releaseSticky() {
  if (!state.sticky.size) return;
  const events = [...state.sticky].map((code) => {
    const mapped = toScancode(code);
    return input.key(mapped.scancode, false, mapped.extended);
  });
  state.sticky.clear();
  sendReliable(events);
  renderSticky();
}

function renderSticky() {
  for (const element of ui.shortcuts.querySelectorAll('[data-sticky]')) {
    element.classList.toggle('on', state.sticky.has(element.dataset.sticky));
  }
}

// --- Interface --------------------------------------------------------------

function setHud(open) {
  ui.hud.classList.toggle('open', open);
  ui.grip.setAttribute('aria-expanded', String(open));
}

function renderMode() {
  ui.mode.textContent = state.absolute ? 'Pointage direct' : 'Trackpad';
  ui.mode.title = state.absolute
    ? 'Le pointeur va là où vous pointez. Appuyez pour passer en trackpad.'
    : 'Vos gestes déplacent le pointeur. Appuyez pour passer en pointage direct.';
  for (const element of document.querySelectorAll('[data-quality]')) {
    element.classList.toggle('on', element.dataset.quality === state.quality);
  }
}

for (const modifier of MODIFIERS) {
  const element = document.createElement('button');
  element.textContent = modifier.label;
  element.dataset.sticky = modifier.code;
  element.onclick = () => toggleSticky(modifier.code);
  ui.shortcuts.append(element);
}
{
  const separator = document.createElement('span');
  separator.className = 'sep';
  ui.shortcuts.append(separator);
}
for (const shortcut of SHORTCUTS) {
  const element = document.createElement('button');
  element.textContent = shortcut.label;
  element.onclick = () => pressCombo(shortcut.keys);
  ui.shortcuts.append(element);
}

// Les boutons du panneau ne prennent pas le focus : il doit rester au champ de
// saisie, faute de quoi chaque raccourci replierait le clavier virtuel.
for (const type of ['pointerdown', 'mousedown']) {
  ui.hud.addEventListener(type, (pointerEvent) => {
    if (pointerEvent.target.closest('button')) pointerEvent.preventDefault();
  });
}

ui.grip.onclick = () => {
  state.hudTouched = true;
  setHud(!ui.hud.classList.contains('open'));
};

for (const element of document.querySelectorAll('[data-quality]')) {
  element.onclick = () => {
    state.quality = element.dataset.quality;
    command('set_quality', { preset: state.quality });
    renderMode();
  };
}

ui.mode.onclick = () => {
  state.absolute = !state.absolute;
  if (pointerLocked()) document.exitPointerLock();
  renderMode();
  renderCursor();
  if (!state.absolute && lastPointerType !== 'touch') {
    toast('Cliquez sur l’image pour capturer la souris, Échap pour la libérer');
  }
};

ui.keyboard.onclick = () => {
  if (document.activeElement === ui.ime) {
    ui.ime.blur();
    return;
  }
  ui.ime.focus({ preventScroll: true });
  ui.keyboard.classList.add('on');
};

ui.paste.onclick = pasteToHost;
ui.copy.onclick = () => command('request_clipboard');

ui.stats.onclick = () => {
  state.showDetails = !state.showDetails;
  ui.stats.classList.toggle('on', state.showDetails);
  renderDetails(state.agentStats
    ? estimateLatency(state.agentStats.encode_ms, state.rtc, state.agentStats.rtt_ms) : null);
};

ui.fullscreen.onclick = async () => {
  if (document.fullscreenElement) {
    await document.exitFullscreen().catch(() => {});
    return;
  }
  await document.documentElement.requestFullscreen?.().catch(() => {});
  // En plein écran, le navigateur peut nous céder les touches qu'il garde
  // d'ordinaire pour lui : Échap, Alt+Tab, la touche Windows.
  navigator.keyboard?.lock?.().catch(() => {});
};
document.addEventListener('fullscreenchange', () => {
  ui.fullscreen.classList.toggle('on', Boolean(document.fullscreenElement));
  if (!document.fullscreenElement) navigator.keyboard?.unlock?.();
  renderCursor();
});

ui.lock.onclick = () => command('lock');

const POWER = {
  sleep: ['Mettre l’hôte en veille ?', 'La session se fermera. Un réveil réseau sera nécessaire pour y revenir.', 'Mettre en veille'],
  reboot: ['Redémarrer l’hôte ?', 'Les applications ouvertes seront fermées.', 'Redémarrer'],
  shutdown: ['Éteindre l’hôte ?', 'Il faudra le rallumer, sur place ou par réveil réseau.', 'Éteindre'],
};
for (const [name, [title, text, action]] of Object.entries(POWER)) {
  $(name).onclick = async () => {
    if (await confirmAction(title, text, action)) command(name);
  };
}

ui.disconnect.onclick = disconnect;
ui.unlock.onclick = () => {
  state.attempt = 0;
  state.wasLive = false;
  connect();
};
ui.cancel.onclick = cancel;
ui.pair.onclick = submitPairing;
ui.code.addEventListener('keydown', (keyboardEvent) => {
  if (keyboardEvent.key === 'Enter') submitPairing();
});
ui.clipClose.onclick = () => ui.clip.close();

ui.forget.onclick = async () => {
  const confirmed = await confirmAction(
    'Oublier cet hôte ?',
    'Cet appareil devra être appairé de nouveau, avec un code lu sur l’hôte.',
    'Oublier',
  );
  if (!confirmed) return;
  await dbDelete('agent');
  ui.trust.hidden = true;
  ui.hostFingerprint.textContent = '—';
  setStatus('Hôte oublié. Reconnectez-vous pour appairer.');
  refreshOptions();
};

ui.biometrics.onclick = async () => {
  if (await dbGet('webauthn')) {
    await dbDelete('webauthn');
    toast('La biométrie n’est plus demandée');
    refreshOptions();
  } else {
    await enrollBiometrics();
  }
};

window.addEventListener('resize', renderCursor);
ui.video.addEventListener('resize', renderCursor);

function deviceLabel() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return 'iOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Navigateur';
}

// --- Démarrage --------------------------------------------------------------

(async function boot() {
  if (!window.isSecureContext) {
    setStatus('Contexte non sécurisé : WebRTC et WebCrypto sont indisponibles.', { error: true });
    return;
  }
  try {
    state.identity = await loadIdentity();
    // Le premier octet d'une clé SEC1 non compressée est toujours 0x04.
    ui.deviceFingerprint.textContent = groupHex(state.identity.publicKeyHex.slice(2));
    const pinned = await dbGet('agent');
    if (pinned) ui.hostFingerprint.textContent = groupHex(pinned);
    setStatus('Prêt.');
    ui.unlock.hidden = false;
    refreshOptions();
    navigator.serviceWorker?.register('/sw.js').catch(() => {});
  } catch (e) {
    setStatus(`Identité locale indisponible : ${e.message}`, { error: true });
  }
})();
