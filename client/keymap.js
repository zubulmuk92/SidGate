// Correspondance `KeyboardEvent.code` → scancode PS/2 jeu 1.
//
// La conversion a lieu ici, et non sur l'hôte, pour une raison précise :
// `code` décrit la *position physique* de la touche, indépendamment de la
// disposition du client. En transmettant un scancode, l'hôte applique sa propre
// disposition clavier — un AZERTY distant reste un AZERTY — et les applications
// qui lisent le clavier au plus bas niveau voient un vrai clavier.
//
// Les touches marquées « étendues » portent le préfixe 0xE0 d'un clavier
// 101 touches : sans ce drapeau, la flèche haut serait prise pour un 8 du pavé
// numérique.

/** Touches du bloc principal. */
const BASE = {
  Escape: 0x01,
  Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
  Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0a, Digit0: 0x0b,
  Minus: 0x0c, Equal: 0x0d, Backspace: 0x0e, Tab: 0x0f,
  KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12, KeyR: 0x13, KeyT: 0x14,
  KeyY: 0x15, KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
  BracketLeft: 0x1a, BracketRight: 0x1b, Enter: 0x1c, ControlLeft: 0x1d,
  KeyA: 0x1e, KeyS: 0x1f, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22,
  KeyH: 0x23, KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26,
  Semicolon: 0x27, Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2a, Backslash: 0x2b,
  KeyZ: 0x2c, KeyX: 0x2d, KeyC: 0x2e, KeyV: 0x2f, KeyB: 0x30,
  KeyN: 0x31, KeyM: 0x32,
  Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
  NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3a,
  F1: 0x3b, F2: 0x3c, F3: 0x3d, F4: 0x3e, F5: 0x3f,
  F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44,
  NumLock: 0x45, ScrollLock: 0x46,
  Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49, NumpadSubtract: 0x4a,
  Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, NumpadAdd: 0x4e,
  Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52, NumpadDecimal: 0x53,
  IntlBackslash: 0x56, F11: 0x57, F12: 0x58,
  IntlRo: 0x73, IntlYen: 0x7d,
};

/** Touches précédées du préfixe 0xE0. */
const EXTENDED = {
  NumpadEnter: 0x1c, ControlRight: 0x1d, NumpadDivide: 0x35,
  PrintScreen: 0x37, AltRight: 0x38,
  Home: 0x47, ArrowUp: 0x48, PageUp: 0x49,
  ArrowLeft: 0x4b, ArrowRight: 0x4d,
  End: 0x4f, ArrowDown: 0x50, PageDown: 0x51,
  Insert: 0x52, Delete: 0x53,
  MetaLeft: 0x5b, MetaRight: 0x5c, ContextMenu: 0x5d,
};

/**
 * Traduit un `KeyboardEvent.code`.
 * @param {string} code
 * @returns {{scancode: number, extended: boolean} | null} `null` si la touche
 *   n'a pas d'équivalent : elle est alors ignorée plutôt qu'envoyée à tout
 *   hasard, ce qui produirait une frappe fantaisiste sur l'hôte.
 */
export function toScancode(code) {
  if (code in BASE) return { scancode: BASE[code], extended: false };
  if (code in EXTENDED) return { scancode: EXTENDED[code], extended: true };
  return null;
}

/**
 * Repli pour les claviers virtuels, qui renseignent `key` mais laissent `code`
 * vide : seules les touches sans caractère y figurent, les caractères passant
 * par la saisie de texte.
 */
const BY_KEY = {
  Enter: 'Enter', Backspace: 'Backspace', Tab: 'Tab', Escape: 'Escape', Delete: 'Delete',
  ArrowUp: 'ArrowUp', ArrowDown: 'ArrowDown', ArrowLeft: 'ArrowLeft', ArrowRight: 'ArrowRight',
  Home: 'Home', End: 'End', PageUp: 'PageUp', PageDown: 'PageDown',
};

/**
 * Traduit un événement clavier, en se rabattant sur `key` quand `code` manque.
 * @param {{code: string, key: string}} event
 * @returns {{scancode: number, extended: boolean} | null}
 */
export function scancodeOf(event) {
  return toScancode(event.code) ?? toScancode(BY_KEY[event.key] ?? '');
}

/**
 * Raccourcis proposés par le panneau d'actions rapides.
 *
 * Une touche s'écrit de deux façons. Par position — `code` — pour celles qui
 * sont au même endroit sur tous les claviers : Échap, Tab, les modificatrices.
 * Par caractère — `char` — pour les lettres : « Ctrl+C » désigne la touche
 * gravée C, que seul l'hôte sait situer sur sa propre disposition. L'écrire par
 * position enverrait Ctrl+Q à un hôte AZERTY à la place de Ctrl+A.
 *
 * Ctrl+Alt+Suppr n'y figure pas : Windows réserve cette séquence au clavier
 * physique et ignore celle qu'un programme injecte.
 */
export const SHORTCUTS = [
  { label: 'Échap', keys: [{ code: 'Escape' }] },
  { label: 'Tab', keys: [{ code: 'Tab' }] },
  { label: 'Alt+Tab', keys: [{ code: 'AltLeft' }, { code: 'Tab' }] },
  { label: 'Win', keys: [{ code: 'MetaLeft' }] },
  { label: 'Gest. tâches', keys: [{ code: 'ControlLeft' }, { code: 'ShiftLeft' }, { code: 'Escape' }] },
  { label: 'Ctrl+C', keys: [{ code: 'ControlLeft' }, { char: 'c' }] },
  { label: 'Ctrl+V', keys: [{ code: 'ControlLeft' }, { char: 'v' }] },
  { label: 'Ctrl+Z', keys: [{ code: 'ControlLeft' }, { char: 'z' }] },
  { label: 'Impr. écran', keys: [{ code: 'PrintScreen' }] },
];

/**
 * Modificatrices à bascule, pour les écrans tactiles : un appui les enfonce,
 * la frappe suivante les relâche.
 */
export const MODIFIERS = [
  { label: 'Ctrl', code: 'ControlLeft' },
  { label: 'Alt', code: 'AltLeft' },
  { label: 'Maj', code: 'ShiftLeft' },
];
