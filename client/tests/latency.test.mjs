// Tests des calculs de latence du client.
//
//   node client/tests/latency.test.mjs
//
// `app.js` manipule le DOM dès son chargement et ne peut pas être importé tel
// quel hors navigateur. Les fonctions de calcul, elles, sont pures : on extrait
// leur source et on les évalue isolément.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const source = readFileSync(fileURLToPath(new URL('../app.js', import.meta.url)), 'utf8');

// Extrait une fonction de premier niveau, de sa signature jusqu'à la première
// accolade fermante en début de ligne.
function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `fonction ${name} introuvable dans app.js`);
  const end = source.indexOf('\n}', start);
  assert.ok(end > start, `fin de ${name} introuvable`);
  return source.slice(start, end + 2);
}

const perUnitDelta = new Function(`${extract('perUnitDelta')}\nreturn perUnitDelta;`)();
const lossPercentDelta = new Function(`${extract('lossPercentDelta')}\nreturn lossPercentDelta;`)();

let passed = 0;
function check(label, body) {
  body();
  passed += 1;
  console.log(`  ok  ${label}`);
}

check('une valeur absente ne devient jamais zéro', () => {
  // Régression : `null * 1000` vaut 0 en JavaScript, et c'est ainsi qu'une
  // statistique non exposée par le navigateur s'affichait « 0,0 ms ».
  assert.equal(perUnitDelta(null, 0, 10, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, null, 10, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, 0.1, null, 5, 1000), null);
  assert.equal(perUnitDelta(0.5, 0.1, 10, null, 1000), null);
});

check('un intervalle sans échantillon est inconnu, pas nul', () => {
  assert.equal(perUnitDelta(0.2, 0.2, 7, 7, 1000), null);
});

check('la moyenne par unité est calculée sur l’intervalle', () => {
  assert.ok(Math.abs(perUnitDelta(0.03, 0.01, 12, 10, 1000) - 10) < 1e-9);
});

check('un zéro réellement mesuré reste un zéro', () => {
  assert.equal(perUnitDelta(0.01, 0.01, 12, 10, 1000), 0);
});

check('les pertes sont inconnues si un compteur manque', () => {
  assert.equal(lossPercentDelta({ lost: null, received: 10 }, { lost: 0, received: 0 }), null);
  assert.equal(lossPercentDelta({ lost: 0, received: 0 }, { lost: 0, received: 0 }), null);
});

check('les pertes sont exprimées en pourcentage', () => {
  assert.equal(lossPercentDelta({ lost: 1, received: 99 }, { lost: 0, received: 0 }), 1);
});

check('une baisse de packetsLost (paquets dupliqués) est bornée à zéro', () => {
  assert.equal(lossPercentDelta({ lost: 2, received: 200 }, { lost: 5, received: 100 }), 0);
});

console.log(`\n${passed} tests passés`);
