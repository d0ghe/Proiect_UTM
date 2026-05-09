/**
 * WebSocket Live Alert Broadcaster
 *
 * Singleton care permite oricărui modul backend să publice evenimente
 * push către toți clienții conectați (dashboard live, alerts).
 *
 * Server-ul îl atașează la un HTTP server în server.js.
 */

const { WebSocketServer } = require('ws');

let wss = null;
const buffer = []; // ultimele 50 alerte (replay pentru clienți noi)

function attach(httpServer) {
  if (wss) return wss;
  wss = new WebSocketServer({ server: httpServer, path: '/ws/alerts' });

  wss.on('connection', (ws) => {
    // Trimite buffer-ul la conectare
    try {
      ws.send(JSON.stringify({ type: 'replay', events: buffer }));
    } catch { /* ignore */ }
  });

  console.log('[+] WebSocket server attached on /ws/alerts');
  return wss;
}

function broadcast(event) {
  const payload = JSON.stringify({
    type: 'alert',
    at: new Date().toISOString(),
    ...event,
  });

  buffer.push({ at: new Date().toISOString(), ...event });
  if (buffer.length > 50) buffer.shift();

  if (!wss) return 0;
  let count = 0;
  for (const client of wss.clients) {
    if (client.readyState === 1) { // OPEN
      try {
        client.send(payload);
        count++;
      } catch { /* ignore client errors */ }
    }
  }
  return count;
}

module.exports = { attach, broadcast };
