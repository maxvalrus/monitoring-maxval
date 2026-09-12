const CACHE_NAME = "monitoring-maxval-0.8.5-ui1";
// Cache only immutable presentation assets. Authenticated HTML and API data are never cached.
const STATIC_ASSETS = [
  "/static/app.css?v=0.8.5&r=aca92c3cc480",
  "/static/app.js?v=0.8.5&r=d710c7aefed",
  "/static/wallboard.css?v=0.8.5&r=7942e90ad9b",
  "/static/favicon.svg",
  "/static/icon-192.png",
  "/static/icon-512.png",
  "/static/manifest.webmanifest",
  "/static/offline-theme.js",
  "/static/offline.html"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(
    keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
  )));
  self.clients.claim();
});

// iOS fullscreen chat geometry is managed by CSS; navigations remain network-first.
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/static/")) {
    event.respondWith(caches.match(event.request).then((cached) => cached || fetch(event.request)));
    return;
  }
  // Only navigations receive the offline document. A failed private API request must
  // remain failed rather than masquerading as stale monitoring data.
  if (event.request.mode === "navigate") {
    event.respondWith(fetch(event.request).catch(() => caches.match("/static/offline.html")));
  }
});

self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (_error) { payload = { body: event.data?.text() || "" }; }
  const title = payload.title || "Мониторинг Maxval";
  const options = {
    body: payload.body || "Новое оповещение",
    icon: "/static/favicon.svg",
    badge: "/static/favicon.svg",
    data: { url: payload.url || "/notifications" }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL(event.notification.data?.url || "/notifications", self.location.origin).href;
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(async (clients) => {
    for (const client of clients) {
      if (new URL(client.url).origin === self.location.origin) {
        if ("navigate" in client) await client.navigate(url);
        return client.focus();
      }
    }
    return self.clients.openWindow ? self.clients.openWindow(url) : undefined;
  }));
});
