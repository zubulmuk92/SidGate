// Service worker minimal.
//
// Il ne met en cache que la coque de l'application, jamais de données de
// session : le flux vidéo et les entrées ne doivent laisser aucune trace sur
// l'appareil client, et un écran de bureau mis en cache serait exactement ce
// qu'on cherche à éviter.

const CACHE = 'sidgate-v1';
const SHELL = ['/', '/app.js', '/keymap.js', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))),
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.pathname === '/ws') return;

  // Réseau d'abord : l'agent sert toujours la version du binaire en cours
  // d'exécution, et un cache périmé afficherait une interface incompatible
  // avec le protocole. Le cache n'est qu'un filet hors ligne.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request)),
  );
});
