/*
 * sw.js — the offline service worker.
 *
 * A workshop room usually shares one conference access point, and that access
 * point is usually the first thing to fall over. Open Door Range is entirely
 * static — HTML, CSS, ES modules and one wasm binary — so once a browser has
 * loaded it, there is no reason it should stop working when the network does.
 * This worker makes that true: it caches the app shell and the wasm the first
 * time they load, and serves them from the cache afterwards.
 *
 * PRIVACY — THIS IS LOAD-BEARING, DO NOT LOOSEN IT.
 * The site's promise is that nothing leaves the browser. This worker upholds it:
 *
 *   - It only ever handles SAME-ORIGIN GET requests. A cross-origin request (of
 *     which the site makes none) is ignored entirely — passed to the network
 *     untouched, never inspected, never cached. So the worker can never turn
 *     into a channel that phones home.
 *   - It originates NO requests of its own. It caches only responses to requests
 *     the page was already making. There is no prefetch of anything off-origin.
 *
 * If you add an asset to the site, it is picked up automatically the first time
 * a page requests it (runtime caching below). The PRECACHE list is only the
 * handful of files needed to boot with the network already gone.
 */

const CACHE = 'odr-offline-v1';

// The minimum needed to boot cold with no network. Everything else (ui/*.js,
// the wasm, etc.) is cached at runtime as the page requests it. Paths are
// relative to the worker's scope, so this works at any base path.
const PRECACHE = [
  './',
  './index.html',
  './css/tokens.css',
  './css/app.css',
  './js/app.js',
  './js/util.js',
  './js/store.js',
  './js/share.js',
  './js/engine-wasm.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      // addAll is atomic and would fail the whole install if one file 404s
      // (e.g. a renamed module), so add them individually and tolerate misses:
      // a precache gap just means that file is fetched on first use instead.
      .then((cache) => Promise.all(
        PRECACHE.map((url) => cache.add(url).catch(() => undefined)),
      ))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only GET, and only our own origin. Anything else is none of this worker's
  // business — hand it straight to the network so the worker can never be a
  // conduit for an off-origin request.
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== self.location.origin) return;

  // Cache-first: offline is the priority, and the assets are versioned by the
  // deploy, not mutated in place. On a cache miss we fetch AND store, so the
  // next load works offline; a genuine network failure with nothing cached
  // falls through to the browser's own error, which is the honest outcome.
  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req).then((res) => {
        // Only cache full, basic (same-origin) 200s. Opaque/partial responses
        // are left uncached rather than poisoning the cache.
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put(req, copy)).catch(() => {});
        }
        return res;
      });
    }),
  );
});
