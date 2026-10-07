// Tests de la logique pure du client.
//
//   node --test "client/tests/*.test.mjs"
//
// `core.js` n'a aucune dépendance au DOM : il s'importe ici tel que le
// navigateur le charge.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  PROTOCOL, toHex, fromHex, fromBase64, groupHex, transcript,
  event, isLossy, encodeFrame, coalesce, chunk, textToEvents, textDelta, wheelUnits,
  decodePointer, SeqTracker, contentRect, pointInRect, buttonDelta,
  perUnitDelta, lossPercentDelta, estimateLatency, isStalled,
  reconnectDelay, RECONNECT_DELAYS_MS, MAX_EVENTS_PER_FRAME,
} from '../core.js';
import { toScancode, scancodeOf, SHORTCUTS, MODIFIERS } from '../keymap.js';

const bytes = (...values) => Uint8Array.from(values);

// --- Encodage ---------------------------------------------------------------

test('l’hexadécimal fait l’aller-retour', () => {
  const data = bytes(0x00, 0x7f, 0x80, 0xff);
  assert.equal(toHex(data), '007f80ff');
  assert.deepEqual(fromHex('007f80ff'), data);
});

test('le base64 est décodé en octets', () => {
  assert.deepEqual(fromBase64('AAAA/w=='), bytes(0, 0, 0, 255));
});

test('une empreinte groupe les seize premiers chiffres', () => {
  assert.equal(groupHex('91292d5158dbe340aabbccdd'), '9129-2D51-58DB-E340');
});

test('la transcription préfixe chaque champ de sa longueur', () => {
  // Référence : `sidgate_proto::signaling::transcript`, mêmes entrées.
  const out = transcript('ab', bytes(1), bytes(2, 3), bytes());
  assert.deepEqual(out, bytes(
    2, 0, 0, 0, 0x61, 0x62,
    1, 0, 0, 0, 1,
    2, 0, 0, 0, 2, 3,
    0, 0, 0, 0,
  ));
});

test('deux découpages des mêmes octets donnent deux transcriptions', () => {
  const a = transcript('d', bytes(1, 2), bytes(3), bytes());
  const b = transcript('d', bytes(1), bytes(2, 3), bytes());
  assert.notDeepEqual(a, b);
});

// --- Entrées ----------------------------------------------------------------

test('les événements ont le format binaire attendu par l’agent', () => {
  // Mêmes octets que `sidgate_proto::input`, petit-boutiste.
  assert.deepEqual(event.moveRelative(-3, 12), bytes(0x01, 0xfd, 0xff, 12, 0));
  assert.deepEqual(event.moveAbsolute(0, 1), bytes(0x02, 0, 0, 0xff, 0xff));
  assert.deepEqual(event.button(4, true), bytes(0x03, 4, 1));
  assert.deepEqual(event.scroll(0, -120), bytes(0x04, 0, 0, 0x88, 0xff));
  assert.deepEqual(event.key(0x4b, false, true), bytes(0x05, 0x4b, 0, 2));
  assert.deepEqual(event.key(0x1e, true, false), bytes(0x05, 0x1e, 0, 1));
  assert.deepEqual(event.text(0x00e9), bytes(0x06, 0xe9, 0));
  assert.deepEqual(event.keyChar('w', true), bytes(0x07, 0x77, 0, 1));
});

test('les valeurs hors bornes sont écrêtées, pas repliées', () => {
  assert.deepEqual(event.moveRelative(1e6, -1e6), bytes(0x01, 0xff, 0x7f, 0x00, 0x80));
  assert.deepEqual(event.moveAbsolute(2, -1), bytes(0x02, 0xff, 0xff, 0, 0));
});

test('une trame porte version, séquence et nombre d’événements', () => {
  const frame = encodeFrame(0xdeadbeef, [event.button(0, true), event.text(0x41)]);
  assert.deepEqual(frame, bytes(1, 0xef, 0xbe, 0xad, 0xde, 2, 0x03, 0, 1, 0x06, 0x41, 0));
});

test('une trame vide reste valide', () => {
  assert.deepEqual(encodeFrame(7, []), bytes(1, 7, 0, 0, 0, 0));
});

test('seuls mouvements et défilements tolèrent la perte', () => {
  assert.ok(isLossy(event.moveRelative(1, 1)));
  assert.ok(isLossy(event.moveAbsolute(0.5, 0.5)));
  assert.ok(isLossy(event.scroll(0, 120)));
  // Un relâchement perdu laisse une touche enfoncée sur l'hôte.
  assert.ok(!isLossy(event.key(0x1e, false, false)));
  assert.ok(!isLossy(event.button(0, false)));
  assert.ok(!isLossy(event.text(0x41)));
  assert.ok(!isLossy(event.keyChar('c', true)));
});

test('les mouvements relatifs consécutifs sont sommés', () => {
  const merged = coalesce([
    event.moveRelative(3, -1), event.moveRelative(4, -2), event.moveRelative(-1, 0),
  ]);
  assert.deepEqual(merged, [event.moveRelative(6, -3)]);
});

test('les positions absolues consécutives se résument à la dernière', () => {
  const merged = coalesce([event.moveAbsolute(0.1, 0.1), event.moveAbsolute(0.9, 0.2)]);
  assert.deepEqual(merged, [event.moveAbsolute(0.9, 0.2)]);
});

test('la fusion ne franchit pas un événement d’une autre nature', () => {
  const merged = coalesce([
    event.moveRelative(1, 1), event.scroll(0, 60), event.scroll(0, 60), event.moveRelative(2, 2),
  ]);
  assert.deepEqual(merged, [
    event.moveRelative(1, 1), event.scroll(0, 120), event.moveRelative(2, 2),
  ]);
});

test('la fusion ne déborde pas sur un geste très ample', () => {
  const merged = coalesce([event.moveRelative(30000, 0), event.moveRelative(30000, 0)]);
  assert.deepEqual(merged, [event.moveRelative(32767, 0)]);
});

test('le découpage respecte la taille maximale d’une trame', () => {
  const parts = chunk(Array.from({ length: 150 }, (_, i) => i), MAX_EVENTS_PER_FRAME);
  assert.deepEqual(parts.map((p) => p.length), [64, 64, 22]);
  assert.deepEqual(chunk([], 8), []);
});

test('le texte voyage par caractère, les fins de ligne par touche', () => {
  const enter = [event.key(0x1c, true, false), event.key(0x1c, false, false)];
  const tab = [event.key(0x0f, true, false), event.key(0x0f, false, false)];
  assert.deepEqual(textToEvents('aé'), [event.text(0x61), event.text(0xe9)]);
  assert.deepEqual(textToEvents('a\nb'), [event.text(0x61), ...enter, event.text(0x62)]);
  assert.deepEqual(textToEvents('\t'), tab);
});

test('les trois conventions de fin de ligne donnent une seule touche Entrée', () => {
  for (const text of ['a\nb', 'a\r\nb', 'a\rb']) {
    assert.equal(textToEvents(text).length, 4, JSON.stringify(text));
  }
});

test('un caractère hors du plan de base voyage en deux unités', () => {
  assert.deepEqual(textToEvents('😀'), [event.text(0xd83d), event.text(0xde00)]);
});

test('les caractères de contrôle ne sont pas tapés', () => {
  assert.deepEqual(textToEvents('\u0000\u0007\u001b\u007f'), []);
});

test('une frappe ajoutée au brouillon part seule', () => {
  assert.deepEqual(textDelta('bonjou', 'bonjour'), { backspaces: 0, added: 'r' });
  assert.deepEqual(textDelta('', 'a'), { backspaces: 0, added: 'a' });
});

test('un retour arrière se traduit par un retour arrière', () => {
  assert.deepEqual(textDelta('bonjour', 'bonjou'), { backspaces: 1, added: '' });
  assert.deepEqual(textDelta('a', ''), { backspaces: 1, added: '' });
});

test('une correction automatique efface puis réécrit la fin du mot', () => {
  // « bonjuor » corrigé en « bonjour » par le clavier.
  assert.deepEqual(textDelta('bonjuor', 'bonjour'), { backspaces: 3, added: 'our' });
  // Un accent posé après coup sur la dernière lettre.
  assert.deepEqual(textDelta('cafe', 'café'), { backspaces: 1, added: 'é' });
});

test('un brouillon inchangé n’envoie rien', () => {
  assert.deepEqual(textDelta('abc', 'abc'), { backspaces: 0, added: '' });
});

test('un émoji compte pour un seul retour arrière', () => {
  assert.deepEqual(textDelta('a\u{1F600}', 'a'), { backspaces: 1, added: '' });
  assert.deepEqual(textDelta('\u{1F600}', '\u{1F601}'), { backspaces: 1, added: '\u{1F601}' });
});

test('le masque du navigateur donne les boutons à enfoncer et à relâcher', () => {
  // Bits : 1 gauche, 2 droit, 4 milieu. Protocole : 0 gauche, 1 droit, 2 milieu.
  assert.deepEqual(buttonDelta(1, new Set()), { press: [0], release: [] });
  assert.deepEqual(buttonDelta(2, new Set()), { press: [1], release: [] });
  assert.deepEqual(buttonDelta(4, new Set()), { press: [2], release: [] });
  assert.deepEqual(buttonDelta(0, new Set([0])), { press: [], release: [0] });
  assert.deepEqual(buttonDelta(1, new Set([0])), { press: [], release: [] });
});

test('des boutons combinés ne laissent rien d’enfoncé sur l’hôte', () => {
  // Gauche, puis droit, puis gauche relâché, puis droit relâché. Le
  // navigateur n'émet `pointerdown` que pour le premier et `pointerup` que
  // pour le dernier ; les deux étapes du milieu n'existent que dans le masque.
  const held = new Set();
  const apply = (mask) => {
    const { press, release } = buttonDelta(mask, held);
    release.forEach((index) => held.delete(index));
    press.forEach((index) => held.add(index));
    return { press, release };
  };
  assert.deepEqual(apply(1), { press: [0], release: [] });
  assert.deepEqual(apply(3), { press: [1], release: [] });
  assert.deepEqual(apply(2), { press: [], release: [0] });
  assert.deepEqual(apply(0), { press: [], release: [1] });
  assert.equal(held.size, 0);
});

test('les boutons latéraux sont transmis', () => {
  assert.deepEqual(buttonDelta(8 | 16, new Set()), { press: [3, 4], release: [] });
});

test('un cran de molette vaut 120 unités, vers le haut en positif', () => {
  assert.deepEqual(wheelUnits(100, 0, 0), { units: -120, carry: 0 });
  assert.deepEqual(wheelUnits(-100, 0, 0), { units: 120, carry: 0 });
  assert.deepEqual(wheelUnits(3, 1, 0), { units: -120, carry: 0 });
  assert.deepEqual(wheelUnits(1, 2, 0), { units: -120, carry: 0 });
});

test('les petits défilements s’accumulent au lieu de se perdre ou de s’amplifier', () => {
  // Un pavé tactile : cent événements d'un pixel font un cran, pas cent.
  let carry = 0;
  let total = 0;
  for (let i = 0; i < 100; i += 1) {
    const step = wheelUnits(1, 0, carry);
    carry = step.carry;
    total += step.units;
  }
  assert.ok(Math.abs(total + 120) <= 1, `total ${total}`);
});

// --- Clavier ----------------------------------------------------------------

test('les touches étendues portent leur drapeau', () => {
  assert.deepEqual(toScancode('KeyA'), { scancode: 0x1e, extended: false });
  assert.deepEqual(toScancode('ArrowUp'), { scancode: 0x48, extended: true });
  assert.deepEqual(toScancode('Numpad8'), { scancode: 0x48, extended: false });
  assert.equal(toScancode('AudioVolumeUp'), null);
});

test('un clavier virtuel sans code se rabat sur le nom de la touche', () => {
  assert.deepEqual(scancodeOf({ code: '', key: 'Enter' }), { scancode: 0x1c, extended: false });
  assert.deepEqual(scancodeOf({ code: '', key: 'ArrowLeft' }), { scancode: 0x4b, extended: true });
  // Un caractère n'est pas une touche : il passera par la saisie de texte.
  assert.equal(scancodeOf({ code: '', key: 'a' }), null);
  assert.equal(scancodeOf({ code: '', key: 'Unidentified' }), null);
});

test('le code physique l’emporte sur le nom de la touche', () => {
  // AZERTY : la touche en position Q produit « a ». C'est la position qui part.
  assert.deepEqual(scancodeOf({ code: 'KeyQ', key: 'a' }), { scancode: 0x10, extended: false });
});

test('chaque raccourci proposé est traduisible', () => {
  for (const shortcut of SHORTCUTS) {
    assert.ok(shortcut.keys.length > 0, shortcut.label);
    for (const key of shortcut.keys) {
      if (key.char) {
        assert.equal(key.char.length, 1, shortcut.label);
      } else {
        assert.ok(toScancode(key.code), `${shortcut.label}: ${key.code}`);
      }
    }
  }
  for (const modifier of MODIFIERS) assert.ok(toScancode(modifier.code), modifier.label);
});

test('les lettres des raccourcis sont désignées par caractère, pas par position', () => {
  // Par position, « Ctrl+C » deviendrait une autre lettre sur un hôte dont la
  // disposition diffère de celle qu'on avait en tête en écrivant la table.
  for (const shortcut of SHORTCUTS) {
    for (const key of shortcut.keys) {
      assert.ok(!/^Key[A-Z]$/.test(key.code ?? ''), `${shortcut.label} désigne une lettre par position`);
    }
  }
});

// --- Retour de pointeur -----------------------------------------------------

test('une position de curseur est décodée, coordonnées négatives comprises', () => {
  // Mêmes octets que le test `wire_layout_is_stable` de `sidgate-proto`.
  const update = decodePointer(bytes(1, 1, 0, 0, 0, 2, 0, 0xff, 0xff, 1).buffer);
  assert.deepEqual(update, { seq: 1, x: 2, y: -1, visible: true });
});

test('un message de pointeur mal formé est ignoré', () => {
  assert.equal(decodePointer(bytes(1, 0, 0, 0, 0, 0, 0, 0, 0).buffer), null);
  assert.equal(decodePointer(bytes(2, 0, 0, 0, 0, 0, 0, 0, 0, 1).buffer), null);
  assert.equal(decodePointer(new ArrayBuffer(0)), null);
});

test('le suivi de séquence écarte doublons et retardataires', () => {
  const tracker = new SeqTracker();
  assert.ok(tracker.accept(10));
  assert.ok(tracker.accept(11));
  assert.ok(!tracker.accept(11), 'doublon');
  assert.ok(!tracker.accept(9), 'périmée');
  assert.ok(tracker.accept(12));
});

test('le suivi de séquence survit au rebouclage sur 32 bits', () => {
  const tracker = new SeqTracker();
  assert.ok(tracker.accept(0xfffffffe));
  assert.ok(tracker.accept(0xffffffff));
  assert.ok(tracker.accept(0), 'rebouclage accepté');
  assert.ok(tracker.accept(1));
  assert.ok(!tracker.accept(0xffffffff), 'pré-rebouclage rejeté');
});

// --- Géométrie --------------------------------------------------------------

test('une image plus large que sa boîte laisse des bandes en haut et en bas', () => {
  const rect = contentRect({ x: 0, y: 0, width: 1000, height: 1000 }, 2);
  assert.deepEqual(rect, { x: 0, y: 250, width: 1000, height: 500 });
});

test('une image plus haute que sa boîte laisse des bandes sur les côtés', () => {
  const rect = contentRect({ x: 10, y: 20, width: 1000, height: 500 }, 1);
  assert.deepEqual(rect, { x: 260, y: 20, width: 500, height: 500 });
});

test('une image calée en haut ne laisse de bande qu’en bas', () => {
  const rect = contentRect({ x: 0, y: 40, width: 400, height: 800 }, 2, 0);
  assert.deepEqual(rect, { x: 0, y: 40, width: 400, height: 200 });
  // L'ancrage vertical ne joue pas quand les bandes sont sur les côtés.
  assert.deepEqual(contentRect({ x: 0, y: 0, width: 1000, height: 500 }, 1, 0),
    contentRect({ x: 0, y: 0, width: 1000, height: 500 }, 1, 0.5));
});

test('un point se normalise dans son rectangle', () => {
  const rect = { x: 100, y: 50, width: 200, height: 100 };
  assert.deepEqual(pointInRect(100, 50, rect), { x: 0, y: 0 });
  assert.deepEqual(pointInRect(300, 150, rect), { x: 1, y: 1 });
  assert.deepEqual(pointInRect(200, 100, rect), { x: 0.5, y: 0.5 });
  assert.equal(pointInRect(99, 100, rect), null);
  assert.equal(pointInRect(200, 151, rect), null);
});

test('un rectangle sans surface ne désigne aucun point', () => {
  // Régression : page masquée, zone vidéo de zéro pixel. La division donnait
  // « pas un nombre », le test « hors bornes » ne le voyait pas, et le clic
  // partait en (0, 0) sur l'écran de l'hôte.
  const empty = { x: 0, y: 0, width: 0, height: 0 };
  assert.equal(pointInRect(0, 0, empty), null);
  assert.equal(pointInRect(10, 10, empty), null);
  assert.equal(pointInRect(10, 10, { x: 0, y: 0, width: 100, height: 0 }), null);
  assert.equal(pointInRect(NaN, 10, { x: 0, y: 0, width: 100, height: 100 }), null);
});

test('une valeur qui n’est pas un nombre ne produit jamais une trame à son image', () => {
  assert.deepEqual(event.moveRelative(NaN, 5), bytes(0x01, 0, 0, 5, 0));
  assert.deepEqual(event.scroll(Infinity, -Infinity), bytes(0x04, 0, 0, 0, 0));
});

test('une géométrie dégénérée rend la boîte telle quelle', () => {
  const box = { x: 1, y: 2, width: 0, height: 0 };
  assert.deepEqual(contentRect(box, 16 / 9), box);
  assert.deepEqual(contentRect({ x: 0, y: 0, width: 10, height: 10 }, NaN),
    { x: 0, y: 0, width: 10, height: 10 });
});

// --- Latence ----------------------------------------------------------------

test('une valeur absente ne devient jamais zéro', () => {
  // Régression : `null * 1000` vaut 0 en JavaScript, et c'est ainsi qu'une
  // statistique non exposée par le navigateur s'affichait « 0,0 ms ».
  assert.equal(perUnitDelta(null, 0, 10, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, null, 10, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, 0.1, null, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, 0.1, 10, null, 1000), null);
});

test('un intervalle sans unité ne donne pas de moyenne', () => {
  assert.equal(perUnitDelta(0.5, 0.1, 5, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, 0.1, 4, 5, 1000), null);
});

test('la moyenne porte sur l’intervalle, pas sur le cumul', () => {
  assert.equal(perUnitDelta(0.75, 0.25, 110, 100, 1000), 50);
});

test('les pertes sont inconnues si un compteur manque', () => {
  const full = { lost: 0, received: 100 };
  assert.equal(lossPercentDelta({ lost: null, received: 200 }, full), null);
  assert.equal(lossPercentDelta({ lost: 1, received: 200 }, { lost: 0, received: null }), null);
});

test('les pertes sont exprimées en pourcentage de l’intervalle', () => {
  const loss = lossPercentDelta({ lost: 10, received: 190 }, { lost: 0, received: 100 });
  assert.equal(loss, 10);
});

test('une baisse du compteur de pertes est bornée à zéro', () => {
  // Un paquet dupliqué fait reculer `packetsLost`.
  const loss = lossPercentDelta({ lost: 3, received: 200 }, { lost: 5, received: 100 });
  assert.equal(loss, 0);
});

test('la latence est la somme des termes mesurés', () => {
  const rtc = { rttMs: 10, jitterMs: 20, decodeMs: 3, lossPercent: 0 };
  const latency = estimateLatency(4, rtc, null);
  assert.equal(latency.total, 4 + 5 + 20 + 3);
  assert.ok(latency.complete);
});

test('un terme manquant rend la somme incomplète sans la fausser', () => {
  const rtc = { rttMs: null, jitterMs: 20, decodeMs: null, lossPercent: null };
  const latency = estimateLatency(4, rtc, null);
  assert.equal(latency.total, 24);
  assert.equal(latency.networkMs, null);
  assert.equal(latency.decodeMs, null);
  assert.ok(!latency.complete);
});

test('l’aller-retour de l’agent supplée celui que le navigateur n’expose pas', () => {
  const rtc = { rttMs: null, jitterMs: 20, decodeMs: 3, lossPercent: null };
  const latency = estimateLatency(4, rtc, 30);
  assert.equal(latency.networkMs, 15);
  assert.ok(latency.complete);
  // Quand les deux existent, celui du transport fait foi.
  assert.equal(estimateLatency(4, { ...rtc, rttMs: 10 }, 30).networkMs, 5);
});

test('rien de mesuré ne donne pas de latence', () => {
  assert.equal(estimateLatency(0, null, null), null);
  assert.equal(estimateLatency(null, null, undefined), null);
});

test('un décodeur à l’arrêt sous un flux qui arrive est détecté', () => {
  assert.ok(isStalled({ decoded: 50, received: 400 }, { decoded: 50, received: 300 }));
  // Bureau immobile : rien n'est décodé parce que rien n'arrive.
  assert.ok(!isStalled({ decoded: 50, received: 301 }, { decoded: 50, received: 300 }));
  assert.ok(!isStalled({ decoded: 60, received: 400 }, { decoded: 50, received: 300 }));
  assert.ok(!isStalled({ decoded: null, received: 400 }, { decoded: 50, received: 300 }));
});

// --- Reconnexion ------------------------------------------------------------

test('seule une coupure subie se retente', () => {
  assert.equal(reconnectDelay('lost', 0), RECONNECT_DELAYS_MS[0]);
  for (const cause of ['left', 'replaced', 'busy', 'refused', 'error']) {
    assert.equal(reconnectDelay(cause, 0), null, cause);
  }
});

test('les tentatives s’espacent puis s’arrêtent', () => {
  const delays = RECONNECT_DELAYS_MS.map((_, attempt) => reconnectDelay('lost', attempt));
  assert.deepEqual(delays, RECONNECT_DELAYS_MS);
  assert.ok(delays.every((delay, i) => i === 0 || delay > delays[i - 1]));
  assert.equal(reconnectDelay('lost', RECONNECT_DELAYS_MS.length), null);
});

test('le protocole du client est celui de l’agent', async () => {
  const { readFile } = await import('node:fs/promises');
  const source = await readFile(new URL('../../crates/sidgate-proto/src/lib.rs', import.meta.url), 'utf8');
  const version = Number(/PROTOCOL_VERSION: u16 = (\d+);/.exec(source)[1]);
  assert.equal(PROTOCOL, version);
});
