// Service worker SmartNutri Eats
const VERSION = 'v1'; // đổi số này mỗi lần cập nhật giao diện để khách nhận bản mới
const STATIC = 'static-' + VERSION;
const MUST_CACHE = ['/offline.html', '/manifest.json'];
const OPTIONAL_CACHE = ['/tailwind.css', '/lucide.min.js']; // chỉ lưu nếu file đã tồn tại

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(STATIC)
      .then(async c => {
        await c.addAll(MUST_CACHE);
        await Promise.all(OPTIONAL_CACHE.map(u => c.add(u).catch(() => {})));
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== STATIC).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);

  if (req.method !== 'GET' || url.origin !== location.origin) return; // bỏ qua POST và CDN bên ngoài
  if (url.pathname.startsWith('/api/')) return;                      // KHÔNG cache API (đơn hàng, token, AI)
  if (url.pathname === '/sw.js') return;

  // Trang HTML: ưu tiên mạng, mất mạng thì dùng bản đã lưu, không có nữa thì hiện trang offline
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then(res => {
          if (res.ok) { const copy = res.clone(); caches.open(STATIC).then(c => c.put(req, copy)); }
          return res;
        })
        .catch(() => caches.match(req).then(r => r || caches.match('/offline.html')))
    );
    return;
  }

  // CSS, JS, ảnh món ăn: dùng bản đã lưu ngay, đồng thời tải bản mới ở nền
  e.respondWith(
    caches.match(req).then(cached => {
      const fresh = fetch(req).then(res => {
        if (res.ok) { const copy = res.clone(); caches.open(STATIC).then(c => c.put(req, copy)); }
        return res;
      }).catch(() => cached);
      return cached || fresh;
    })
  );
});
