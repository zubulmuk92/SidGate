// Logique pure du client sidgate : codecs, calculs, décisions.
//
// Rien ici ne touche au DOM, au réseau ou à une horloge. C'est ce qui permet de
// tester ces fonctions sous Node telles que le navigateur les exécute, sans
// simuler de page :
//
//   node --test "client/tests/*.test.mjs"

/** Version du protocole applicatif. Doit égaler `PROTOCOL_VERSION` de l'agent. */
export const PROTOCOL = 2;
export const NONCE_LEN = 32;

export const DOMAIN_AUTH = 'sidgate/auth/client/v1';
export const DOMAIN_PAIR = 'sidgate/pair/client/v1';
export const DOMAIN_AGENT = 'sidgate/auth/agent/v1';

// --- Encodage ---------------------------------------------------------------

export const toHex = (bytes) =>
  Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

/** Décode du base64 standard en octets. */
export function fromBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/** Empreinte lisible : les seize premiers chiffres hexadécimaux, par groupes. */
export const groupHex = (hex) =>
  (hex.slice(0, 16).match(/.{4}/g) ?? []).join('-').toUpperCase();

/**
 * Reconstruit exactement la transcription que l'agent signe et vérifie.
 *
 * Chaque champ est préfixé de sa longueur sur 32 bits en petit-boutiste. Sans
 * ce préfixe, deux découpages différents des mêmes octets donneraient la même
 * transcription et une signature vaudrait pour les deux.
 */
export function transcript(domain, serverNonce, clientNonce, clientKey) {
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

// --- Entrées ----------------------------------------------------------------

export const FRAME_VERSION = 1;
export const MAX_EVENTS_PER_FRAME = 64;

const KIND = {
  MOVE_REL: 0x01, MOVE_ABS: 0x02, BUTTON: 0x03, SCROLL: 0x04,
  KEY: 0x05, TEXT: 0x06, KEY_CHAR: 0x07,
};

const clampInt = (value, min, max) => Math.min(max, Math.max(min, Math.round(value)));

function pair16(kind, a, b, signed) {
  const bytes = new Uint8Array(5);
  const view = new DataView(bytes.buffer);
  bytes[0] = kind;
  if (signed) {
    view.setInt16(1, clampInt(a, -32768, 32767), true);
    view.setInt16(3, clampInt(b, -32768, 32767), true);
  } else {
    view.setUint16(1, clampInt(a, 0, 65535), true);
    view.setUint16(3, clampInt(b, 0, 65535), true);
  }
  return bytes;
}

/** Constructeurs d'événements, au format binaire de `sidgate-proto::input`. */
export const event = {
  moveRelative: (dx, dy) => pair16(KIND.MOVE_REL, dx, dy, true),
  /** Position normalisée sur `0..1` dans l'image du bureau. */
  moveAbsolute: (x, y) => pair16(KIND.MOVE_ABS, x * 65535, y * 65535, false),
  button: (index, pressed) => new Uint8Array([KIND.BUTTON, index, pressed ? 1 : 0]),
  /** Défilement en unités de molette : 120 par cran. */
  scroll: (dx, dy) => pair16(KIND.SCROLL, dx, dy, true),
  key: (scancode, pressed, extended) => new Uint8Array([
    KIND.KEY, scancode & 0xff, scancode >> 8, (pressed ? 1 : 0) | (extended ? 2 : 0),
  ]),
  /** Une unité de code UTF-16, tapée telle quelle sur l'hôte. */
  text: (unit) => new Uint8Array([KIND.TEXT, unit & 0xff, unit >> 8]),
  /** La touche qui produit ce caractère sur la disposition de l'hôte. */
  keyChar: (char, pressed) => {
    const unit = char.charCodeAt(0);
    return new Uint8Array([KIND.KEY_CHAR, unit & 0xff, unit >> 8, pressed ? 1 : 0]);
  },
};

/**
 * L'événement tolère-t-il d'être perdu ?
 *
 * Vrai pour ce que l'événement suivant rattrape : un mouvement, un défilement.
 * Tout le reste — appui, relâchement, texte — doit arriver, et dans l'ordre.
 */
export const isLossy = (bytes) =>
  bytes[0] === KIND.MOVE_REL || bytes[0] === KIND.MOVE_ABS || bytes[0] === KIND.SCROLL;

/** Assemble une trame à partir d'au plus `MAX_EVENTS_PER_FRAME` événements. */
export function encodeFrame(seq, events) {
  const size = 6 + events.reduce((n, e) => n + e.length, 0);
  const frame = new Uint8Array(size);
  frame[0] = FRAME_VERSION;
  new DataView(frame.buffer).setUint32(1, seq >>> 0, true);
  frame[5] = events.length;
  let offset = 6;
  for (const bytes of events) {
    frame.set(bytes, offset);
    offset += bytes.length;
  }
  return frame;
}

/**
 * Fusionne les mouvements relatifs et les défilements consécutifs.
 *
 * Un geste rapide produit plusieurs événements par image affichée ; l'hôte n'a
 * besoin que de leur somme. Les positions absolues se résument à la dernière.
 * L'ordre relatif des autres événements est conservé.
 */
export function coalesce(events) {
  const out = [];
  for (const bytes of events) {
    const last = out[out.length - 1];
    const kind = bytes[0];
    if (last && last[0] === kind && (kind === KIND.MOVE_REL || kind === KIND.SCROLL)) {
      const a = new DataView(last.buffer);
      const b = new DataView(bytes.buffer, bytes.byteOffset);
      out[out.length - 1] = pair16(kind, a.getInt16(1, true) + b.getInt16(1, true),
        a.getInt16(3, true) + b.getInt16(3, true), true);
    } else if (last && last[0] === kind && kind === KIND.MOVE_ABS) {
      out[out.length - 1] = bytes;
    } else {
      out.push(bytes);
    }
  }
  return out;
}

/** Découpe une liste en tranches d'au plus `size` éléments. */
export function chunk(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** Scancodes des touches que le texte tapé emprunte plutôt qu'un caractère. */
const SCANCODE_ENTER = 0x1c;
const SCANCODE_TAB = 0x0f;

/**
 * Traduit un texte en événements de saisie.
 *
 * Les caractères voyagent tels quels, hors de toute disposition clavier. Les
 * fins de ligne et les tabulations deviennent de vraies touches : un saut de
 * ligne « tapé » comme caractère n'est pas une touche Entrée, et la plupart des
 * applications ne valideraient rien.
 */
export function textToEvents(text) {
  const events = [];
  const normalized = text.replace(/\r\n?/g, '\n');
  for (let i = 0; i < normalized.length; i += 1) {
    const unit = normalized.charCodeAt(i);
    if (unit === 0x0a) {
      events.push(event.key(SCANCODE_ENTER, true, false), event.key(SCANCODE_ENTER, false, false));
    } else if (unit === 0x09) {
      events.push(event.key(SCANCODE_TAB, true, false), event.key(SCANCODE_TAB, false, false));
    } else if (unit >= 0x20 && unit !== 0x7f) {
      events.push(event.text(unit));
    }
    // Les autres caractères de contrôle n'ont pas de sens tapés au clavier.
  }
  return events;
}

/**
 * Compare le brouillon de saisie à ce qui a déjà été envoyé à l'hôte.
 *
 * Un clavier virtuel ne produit pas des touches mais du texte, et réécrit
 * volontiers le mot en cours à chaque frappe : correction automatique,
 * composition, saisie par glissement. Plutôt que de deviner l'intention, on
 * envoie la différence — tant de retours arrière pour ce qui a disparu, puis ce
 * qui est apparu.
 *
 * @param {string} sent     Texte du brouillon déjà reproduit sur l'hôte.
 * @param {string} current  Texte actuel du brouillon.
 * @returns {{backspaces: number, added: string}} Les retours arrière se
 *   comptent en caractères, pas en unités UTF-16 : l'hôte efface un émoji d'une
 *   seule frappe.
 */
export function textDelta(sent, current) {
  const before = [...sent];
  const after = [...current];
  let common = 0;
  while (common < before.length && common < after.length && before[common] === after[common]) {
    common += 1;
  }
  return { backspaces: before.length - common, added: after.slice(common).join('') };
}

/**
 * Convertit un défilement de molette en unités Windows, en gardant le reste.
 *
 * Un pavé tactile émet des dizaines de petits événements par geste : arrondir
 * chacun à un cran entier ferait défiler dix fois trop vite, et les ignorer
 * tous ferait disparaître le geste. Le reste fractionnaire est donc reporté sur
 * l'appel suivant.
 *
 * @param {number} delta   `deltaX` ou `deltaY` de l'événement.
 * @param {number} mode    `deltaMode` : 0 pixels, 1 lignes, 2 pages.
 * @param {number} carry   Reste laissé par l'appel précédent.
 * @returns {{units: number, carry: number}} Unités à envoyer et nouveau reste.
 */
export function wheelUnits(delta, mode, carry) {
  // Un cran de molette vaut 120 unités, et un navigateur le traduit par une
  // centaine de pixels, trois lignes, ou une page.
  const perUnit = [120 / 100, 120 / 3, 120][mode] ?? 120 / 100;
  // Signe inversé : `deltaY` positif veut dire « vers le bas », une molette
  // Windows compte positivement vers le haut.
  const exact = -delta * perUnit + carry;
  const units = Math.trunc(exact);
  return { units, carry: exact - units };
}

// --- Retour de pointeur -----------------------------------------------------

export const POINTER_LEN = 10;

/**
 * Décode une position de curseur émise par l'agent.
 * @returns {{seq:number,x:number,y:number,visible:boolean}|null} `null` si le
 *   message n'a pas la forme attendue.
 */
export function decodePointer(buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length !== POINTER_LEN || bytes[0] !== 1) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  return {
    seq: view.getUint32(1, true),
    x: view.getInt16(5, true),
    y: view.getInt16(7, true),
    visible: (bytes[9] & 1) !== 0,
  };
}

/**
 * Fenêtre d'acceptation des numéros de séquence, sur un canal non ordonné.
 *
 * N'accepte que ce qui est strictement plus récent, en comparaison cyclique :
 * correct au rebouclage sur 32 bits.
 */
export class SeqTracker {
  constructor() { this.last = null; }

  accept(seq) {
    if (this.last === null) {
      this.last = seq;
      return true;
    }
    const delta = (seq - this.last) >>> 0;
    if (delta !== 0 && delta < 0x7fffffff) {
      this.last = seq;
      return true;
    }
    return false;
  }
}

// --- Géométrie --------------------------------------------------------------

/**
 * Rectangle réellement occupé par l'image dans un élément `object-fit: contain`.
 * @param {{x:number,y:number,width:number,height:number}} box  Boîte de l'élément.
 * @param {number} ratio  Largeur sur hauteur de l'image.
 * @param {number} [anchorY]  Position verticale de l'image dans l'espace
 *   libre : 0 en haut, 0,5 au centre. Doit refléter `object-position`.
 */
export function contentRect(box, ratio, anchorY = 0.5) {
  if (!(ratio > 0) || !(box.width > 0) || !(box.height > 0)) {
    return { x: box.x, y: box.y, width: box.width, height: box.height };
  }
  if (ratio > box.width / box.height) {
    const height = box.width / ratio;
    return { x: box.x, y: box.y + (box.height - height) * anchorY, width: box.width, height };
  }
  const width = box.height * ratio;
  return { x: box.x + (box.width - width) / 2, y: box.y, width, height: box.height };
}

// --- Latence ----------------------------------------------------------------

/**
 * Moyenne par unité sur l'intervalle, mise à l'échelle.
 *
 * Renvoie `null` si une valeur manque ou si aucune unité n'est passée dans
 * l'intervalle. La multiplication se fait ici, après ce test, et non sur le
 * résultat : en JavaScript `null * 1000` vaut 0, et c'est exactement par là
 * qu'une absence de mesure devenait un « 0,0 ms » affiché.
 */
export function perUnitDelta(valueNow, valueBefore, countNow, countBefore, scale) {
  if ([valueNow, valueBefore, countNow, countBefore].includes(null)) return null;
  const count = countNow - countBefore;
  if (count <= 0) return null;
  return ((valueNow - valueBefore) / count) * scale;
}

/** Part de paquets perdus sur l'intervalle, en pourcentage, ou `null`. */
export function lossPercentDelta(current, previous) {
  if ([current.lost, previous.lost, current.received, previous.received].includes(null)) {
    return null;
  }
  const lost = Math.max(0, current.lost - previous.lost);
  const total = lost + (current.received - previous.received);
  return total > 0 ? (lost / total) * 100 : null;
}

/**
 * Latence estimée du pipeline, en millisecondes.
 *
 * Somme de ce que l'on sait mesurer : capture et encodage côté hôte, trajet
 * aller (la moitié de l'aller-retour), attente dans le tampon de gigue, et
 * décodage. N'y figurent pas l'attente de présentation du compositeur de l'hôte
 * ni la synchronisation verticale de l'écran client — jusqu'à une image chacune
 * à 60 Hz. C'est donc une borne basse, et elle est affichée comme telle.
 *
 * @param {number|null} encodeMs  Durée d'encodage annoncée par l'agent.
 * @param {{rttMs:number|null,jitterMs:number|null,decodeMs:number|null,
 *   lossPercent:number|null}|null} rtc  Relevé WebRTC du navigateur.
 * @param {number|null} agentRttMs  Aller-retour applicatif mesuré par l'agent,
 *   utilisé quand le navigateur n'expose pas celui du transport.
 * @returns `null` si rien n'est mesuré.
 */
export function estimateLatency(encodeMs, rtc, agentRttMs) {
  const number = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
  const rtt = number(rtc?.rttMs) ?? number(agentRttMs);
  const terms = {
    encodeMs: number(encodeMs) !== null && encodeMs > 0 ? encodeMs : null,
    networkMs: rtt === null ? null : rtt / 2,
    jitterMs: number(rtc?.jitterMs),
    decodeMs: number(rtc?.decodeMs),
  };
  const known = Object.values(terms).filter((value) => value !== null);
  if (known.length === 0) return null;
  return {
    ...terms,
    // Somme des seuls termes mesurés : une borne basse, d'autant plus basse
    // qu'il en manque. `complete` le signale à l'affichage.
    total: known.reduce((sum, value) => sum + value, 0),
    complete: known.length === Object.keys(terms).length,
    lossPercent: number(rtc?.lossPercent),
  };
}

/**
 * Le décodeur est-il à l'arrêt alors que le flux arrive ?
 *
 * Des paquets reçus sans qu'aucune image ne soit décodée : le décodeur attend
 * une image clé qu'il n'a pas. Le navigateur la réclame de lui-même ; ce test
 * sert de filet si sa demande s'est perdue.
 */
export function isStalled(current, previous) {
  if ([current.decoded, previous.decoded, current.received, previous.received].includes(null)) {
    return false;
  }
  return current.decoded === previous.decoded && current.received - previous.received > 5;
}

// --- Reconnexion ------------------------------------------------------------

/** Délais successifs entre deux tentatives de reconnexion, en millisecondes. */
export const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000, 15000];

/**
 * Faut-il retenter après la fin d'une session, et dans combien de temps ?
 *
 * @param {string} cause  Pourquoi la session s'est terminée.
 * @param {number} attempt  Tentatives déjà faites depuis la dernière session établie.
 * @returns {number|null} Délai avant la prochaine tentative, ou `null` pour
 *   s'arrêter et rendre la main à l'utilisateur.
 */
export function reconnectDelay(cause, attempt) {
  // Seule une coupure subie se retente. Un départ volontaire, un remplacement
  // par un autre appareil ou un refus de l'hôte sont des réponses, pas des
  // pannes : insister ferait se disputer la session ou marteler l'hôte.
  if (cause !== 'lost') return null;
  return RECONNECT_DELAYS_MS[attempt] ?? null;
}
