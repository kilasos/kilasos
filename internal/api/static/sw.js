// KilasOS Service Worker — stub
// M406: PWA service worker, stub only (no offline API caching per PLAN.md)
const CACHE_NAME = 'kilasos-v1';

self.addEventListener('fetch', (event) => {
  // No offline caching of API responses — keeps live data fresh
  // Static assets could be cached in future but keep it simple for now
});

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});