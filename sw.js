/* sw.js — service worker Relais v0.3.
   Strategie : pre-cache a l'installation (app + bibliotheques CDN), puis
   cache-first. Apres le PREMIER chargement en ligne, l'application entiere
   fonctionne sans aucun reseau. */

const CACHE = "relais-v0.3";
const LOCAL = [
  "./", "./index.html", "./relais_core.js",
  "./manifest.webmanifest", "./icon-192.png", "./icon-512.png",
];
const CDN = [
  "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js",
  "https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(LOCAL);
    // Les reponses cross-origin peuvent etre opaques : fetch no-cors + put
    // manuel, en tolerant l'echec (l'app reste utilisable en ligne).
    for (const url of CDN) {
      try {
        const resp = await fetch(url, { mode: "no-cors" });
        await cache.put(url, resp);
      } catch (err) { /* hors ligne a l'installation : reessaye au runtime */ }
    }
    self.skipWaiting();
  })());
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys())
      if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  e.respondWith((async () => {
    const cached = await caches.match(e.request, { ignoreSearch: true });
    if (cached) return cached;
    try {
      const resp = await fetch(e.request);
      if (resp && (resp.ok || resp.type === "opaque")) {
        const cache = await caches.open(CACHE);
        cache.put(e.request, resp.clone());
      }
      return resp;
    } catch (err) {
      return cached || Response.error();
    }
  })());
});
