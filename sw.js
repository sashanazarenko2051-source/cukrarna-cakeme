self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(
    self.registration.showNotification(data.title || 'CakeMe Admin', {
      body: data.body || 'Nová objednávka!',
      icon: '/favicon.svg',
      badge: '/favicon.svg',
      tag: 'cakeme-order',
      requireInteraction: true,
      data: { url: data.url || '/admin.html' }
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('/admin.html') && 'focus' in c) return c.focus();
      }
      return clients.openWindow(event.notification.data?.url || '/admin.html');
    })
  );
});
