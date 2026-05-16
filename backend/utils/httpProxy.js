'use strict';

const http = require('http');
const net = require('net');
const { URL } = require('url');

const PROXY_PORT = 8877;
const PROTECTED_WEB_PORTS = new Set([53, 80, 443]);
let proxyServer = null;

function getRules() {
  try { return require('../store/runtimeState').getFirewallRules(); }
  catch { return []; }
}

function isPortBlocked(port) {
  const p = Number(port);
  if (PROTECTED_WEB_PORTS.has(p)) return false;

  return getRules().some(
    (rule) =>
      String(rule.action).toUpperCase() === 'BLOCK' &&
      String(rule.status).toLowerCase() === 'active' &&
      Number(rule.port) === p,
  );
}

function isDomainBlocked(hostname) {
  try { return require('../store/contentFilterStore').isDomainBlocked(hostname); }
  catch { return false; }
}

async function isGeoBlocked(hostname) {
  try { return await require('../utils/geoFilter').isGeoBlocked(hostname); }
  catch (err) {
    console.error('[proxy] geo check failed:', err.message);
    return { blocked: false };
  }
}

function logContentBlock(hostname) {
  try { require('../utils/geoFilter').addContentBlock(hostname); } catch { /* ignore */ }
}

async function getBlockDecision(hostname, port) {
  const normalizedPort = Number(port);

  if (isPortBlocked(normalizedPort)) {
    return {
      blocked: true,
      label: 'An active Firewall rule is blocking TCP port',
      detail: `port ${normalizedPort}`,
    };
  }

  if (isDomainBlocked(hostname)) {
    logContentBlock(hostname);
    return {
      blocked: true,
      label: 'This domain is blocked by the Content Filter policy.',
      detail: hostname,
    };
  }

  const geo = await isGeoBlocked(hostname);
  if (geo.blocked) {
    return {
      blocked: true,
      label: 'This destination is blocked by the Geo-Filter policy.',
      detail: `${hostname} - ${geo.country}`,
      geo,
    };
  }

  return { blocked: false };
}

const BLOCK_HTML = (reason, detail) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Blocked - UTM Firewall</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    background:#0a0a0a;color:#e8e8e8;display:flex;align-items:center;
    justify-content:center;min-height:100vh;margin:0}
  .card{background:#141414;border:1px solid #2a2a2a;border-radius:12px;
    padding:2.5rem 3rem;max-width:480px;text-align:center}
  h1{font-size:1.4rem;margin:0 0 .5rem;color:#ff453a}
  p{opacity:.65;font-size:.9rem;line-height:1.6;margin:.5rem 0}
  code{background:#1e1e1e;border-radius:4px;padding:.15em .4em;font-size:.85em}
</style></head>
<body><div class="card">
  <div style="font-size:2rem;margin-bottom:1rem">&#128274;</div>
  <h1>Connection Blocked</h1>
  <p>${reason}</p>
  <p><code>${detail}</code></p>
  <p>Modify the rule in <strong>Argus</strong> to restore access.</p>
</div></body></html>`;

function sendBlockHtml(res, label, detail) {
  const body = BLOCK_HTML(label, detail);
  res.writeHead(403, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-UTM-Block': detail,
    Connection: 'close',
  });
  res.end(body);
}

function sendBlockSocket(socket, label, detail) {
  const body = BLOCK_HTML(label, detail);
  socket.write(
    'HTTP/1.1 403 Forbidden\r\n' +
    'Content-Type: text/html; charset=utf-8\r\n' +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `X-UTM-Block: ${detail}\r\n` +
    'Connection: close\r\n\r\n' +
    body,
  );
  socket.destroy();
}

function safeWrite(socket, data) {
  try { if (socket.writable) socket.write(data); } catch { /* ignore */ }
}

function safeDestroy(socket) {
  try { if (!socket.destroyed) socket.destroy(); } catch { /* ignore */ }
}

function pipeWithErrors(src, dst) {
  src.on('error', () => safeDestroy(dst));
  dst.on('error', () => safeDestroy(src));
  src.pipe(dst, { end: true });
}

function parseConnectTarget(target) {
  const value = String(target || '');
  const ipv6Match = value.match(/^\[([^\]]+)\]:(\d+)$/);
  if (ipv6Match) {
    return { host: ipv6Match[1], port: Number(ipv6Match[2]) || 443 };
  }

  const separator = value.lastIndexOf(':');
  if (separator === -1) {
    return { host: value, port: 443 };
  }

  return {
    host: value.slice(0, separator),
    port: Number(value.slice(separator + 1)) || 443,
  };
}

async function handleHttp(req, res) {
  try {
    let targetUrl;
    try {
      targetUrl = new URL(req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`);
    } catch {
      res.writeHead(400);
      res.end('Bad Request');
      return;
    }

    const port = Number(targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80));
    const block = await getBlockDecision(targetUrl.hostname, port);
    if (block.blocked) {
      sendBlockHtml(res, block.label, block.detail);
      return;
    }

    const headers = { ...req.headers, host: targetUrl.host };
    delete headers['proxy-connection'];

    const upstream = http.request({
      hostname: targetUrl.hostname,
      port,
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers,
    }, (upstreamRes) => {
      try {
        if (!res.headersSent) res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
        pipeWithErrors(upstreamRes, res);
      } catch {
        safeDestroy(res);
      }
    });

    upstream.on('error', () => {
      try {
        if (!res.headersSent) res.writeHead(502);
        res.end();
      } catch { /* ignore */ }
    });

    req.on('error', () => safeDestroy(upstream));
    pipeWithErrors(req, upstream);
  } catch (err) {
    console.error('[proxy] handleHttp unhandled:', err.message);
    try {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    } catch { /* ignore */ }
  }
}

async function handleConnect(req, clientSocket, head) {
  try {
    const { host, port } = parseConnectTarget(req.url);
    const block = await getBlockDecision(host, port);
    if (block.blocked) {
      sendBlockSocket(clientSocket, block.label, block.detail);
      return;
    }

    const serverSocket = net.connect(port, host, () => {
      try {
        safeWrite(clientSocket, 'HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) safeWrite(serverSocket, head);
        pipeWithErrors(serverSocket, clientSocket);
        pipeWithErrors(clientSocket, serverSocket);
      } catch {
        safeDestroy(clientSocket);
        safeDestroy(serverSocket);
      }
    });

    serverSocket.on('error', () => {
      safeWrite(clientSocket, 'HTTP/1.1 502 Bad Gateway\r\n\r\n');
      safeDestroy(clientSocket);
    });
    clientSocket.on('error', () => safeDestroy(serverSocket));
  } catch (err) {
    console.error('[proxy] handleConnect unhandled:', err.message);
    safeDestroy(clientSocket);
  }
}

function startProxy() {
  if (proxyServer) return PROXY_PORT;

  proxyServer = http.createServer(handleHttp);
  proxyServer.on('connect', handleConnect);

  proxyServer.on('clientError', (_err, socket) => {
    if (socket.writable) socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
  });

  proxyServer.listen(PROXY_PORT, '127.0.0.1', () => {
    console.log(`[+] UTM HTTP Proxy listening on http://127.0.0.1:${PROXY_PORT}`);
  });

  return PROXY_PORT;
}

function stopProxy(cb) {
  if (proxyServer) {
    proxyServer.close(cb);
    proxyServer = null;
  } else if (cb) {
    cb();
  }
}

function isRunning() {
  return proxyServer !== null;
}

module.exports = { startProxy, stopProxy, isRunning, PROXY_PORT, getBlockDecision };
