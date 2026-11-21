'use strict';
/*
 * OTC - One Time Communication
 * Server di segnalazione + relay di riserva. Zero dipendenze (serve solo Node >= 18).
 *
 * Il server NON vede mai il contenuto delle chat: inoltra soltanto blob cifrati
 * (AES-GCM, chiave derivata dal codice nel browser) e non scrive nulla su disco.
 * Tutto lo stato vive in memoria e sparisce quando la stanza si chiude.
 *
 * Trasporto: Server-Sent Events (GET /events) per ricevere, POST /send per inviare.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 8080;
const WAIT_MS = Number(process.env.OTC_WAIT_MS) || 3 * 60 * 1000;   // attesa del secondo partecipante
const GRACE_MS = Number(process.env.OTC_GRACE_MS) || 30 * 1000;     // tolleranza a una disconnessione breve
const MAX_LIFE_MS = 6 * 60 * 60 * 1000;                             // durata massima di una stanza
const BURN_MS = 60 * 60 * 1000;                                     // un codice usato non si riusa per 1 ora
const MAX_ROOMS = 200;
const MAX_BODY = 64 * 1024;
const JOINS_PER_MIN = Number(process.env.OTC_JOINS_PER_MIN) || 30;

const ROOM_RE = /^[a-f0-9]{32}$/;
const CID_RE = /^[a-z0-9]{8,32}$/;
const B64_RE = /^[A-Za-z0-9+/=]+$/;

const FILES = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/app.js': 'app.js',
  '/otc-lib.js': 'otc-lib.js',
};

const rooms = new Map();   // roomId -> { clients: Map(cid -> {cid,res,role,leaveTimer}), everFull, waitTimer, lifeTimer }
const burned = new Map();  // roomId -> scadenza (ms)
const hits = new Map();    // ip -> timestamp dei tentativi di accesso

// ---------- utilità ----------
function clientIp(req) {
  const addr = req.socket.remoteAddress || '';
  const loopback = addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
  const xff = req.headers['x-forwarded-for'];
  // Dietro un tunnel (ngrok, cloudflared) la connessione arriva da localhost:
  // l'IP reale è l'ultimo valore aggiunto dal proxy.
  if (loopback && xff) {
    const parts = String(xff).split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return addr;
}

function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > JOINS_PER_MIN;
}

function send(res, name, data) {
  try { res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`); } catch (_) { /* connessione chiusa */ }
}

function reject(res) {
  // Messaggio volutamente generico: non si deve capire se un codice esiste, è pieno o è stato usato.
  send(res, 'unavailable', {});
  res.end();
}

function createRoom(id) {
  const room = { id, clients: new Map(), everFull: false, waitTimer: null, lifeTimer: null };
  room.waitTimer = setTimeout(() => closeRoom(id, 'expired'), WAIT_MS);
  room.lifeTimer = setTimeout(() => closeRoom(id, 'expired'), MAX_LIFE_MS);
  rooms.set(id, room);
  return room;
}

function closeRoom(id, notice) {
  const room = rooms.get(id);
  if (!room) return;
  rooms.delete(id);
  clearTimeout(room.waitTimer);
  clearTimeout(room.lifeTimer);
  for (const c of room.clients.values()) {
    clearTimeout(c.leaveTimer);
    if (notice) send(c.res, notice, {});
    try { c.res.end(); } catch (_) { /* già chiusa */ }
  }
  if (room.everFull) burned.set(id, Date.now() + BURN_MS); // codice monouso
}

// ---------- GET /events : ingresso in una stanza + flusso di eventi ----------
function handleEvents(req, res, url) {
  const roomId = url.searchParams.get('room') || '';
  const cid = url.searchParams.get('cid') || '';
  if (!ROOM_RE.test(roomId) || !CID_RE.test(cid)) { res.writeHead(400); return res.end(); }
  if (rateLimited(clientIp(req))) { res.writeHead(429, { 'Retry-After': '60' }); return res.end(); }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');

  const burnedUntil = burned.get(roomId);
  if (burnedUntil && burnedUntil > Date.now()) return reject(res);

  let room = rooms.get(roomId);
  let me = room && room.clients.get(cid);
  let reconnect = false;

  if (me) {
    // Stesso dispositivo che si ricollega entro il periodo di tolleranza
    reconnect = true;
    clearTimeout(me.leaveTimer);
    me.leaveTimer = null;
    const old = me.res;
    me.res = res;
    try { old.end(); } catch (_) { /* già chiusa */ }
  } else {
    if (!room) {
      if (rooms.size >= MAX_ROOMS) return reject(res);
      room = createRoom(roomId);
    }
    if (room.clients.size >= 2) return reject(res);
    me = { cid, res, role: room.clients.size === 0 ? 'host' : 'guest', leaveTimer: null };
    room.clients.set(cid, me);
    if (room.clients.size === 2) {
      room.everFull = true;
      clearTimeout(room.waitTimer);
      room.waitTimer = null;
    }
  }

  send(res, 'joined', { role: me.role, peer: room.clients.size === 2 });
  if (!reconnect && room.clients.size === 2) {
    for (const o of room.clients.values()) if (o !== me) send(o.res, 'peer', {});
  }

  res.on('close', () => {
    if (me.res !== res) return; // sostituita da una riconnessione
    const r = rooms.get(roomId);
    if (!r || r.clients.get(cid) !== me) return;
    me.leaveTimer = setTimeout(() => {
      const cur = rooms.get(roomId);
      if (!cur || cur.clients.get(cid) !== me) return;
      cur.clients.delete(cid);
      for (const o of cur.clients.values()) send(o.res, 'peer-left', {});
      closeRoom(roomId);
    }, r.everFull ? GRACE_MS : Math.min(5000, GRACE_MS));
  });
}

// ---------- POST /send : inoltro di un blob cifrato all'altro partecipante ----------
function handleSend(req, res, url) {
  const roomId = url.searchParams.get('room') || '';
  const cid = url.searchParams.get('cid') || '';
  if (!ROOM_RE.test(roomId) || !CID_RE.test(cid)) { res.writeHead(400); return res.end(); }
  const room = rooms.get(roomId);
  const me = room && room.clients.get(cid);
  if (!me) { res.writeHead(403); return res.end(); }

  let size = 0;
  const chunks = [];
  req.on('data', (c) => {
    size += c.length;
    if (size > MAX_BODY) {
      if (!res.headersSent) { res.writeHead(413); res.end(); }
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (res.writableEnded) return;
    const body = Buffer.concat(chunks).toString('utf8');
    if (!body || !B64_RE.test(body)) { res.writeHead(400); return res.end(); }
    let delivered = 0;
    for (const o of room.clients.values()) {
      if (o !== me) { send(o.res, 'm', body); delivered++; }
    }
    res.writeHead(delivered ? 204 : 409);
    res.end();
  });
}

// ---------- server HTTP ----------
function serveFile(res, name) {
  fs.readFile(path.join(__dirname, 'public', name), (err, buf) => {
    if (err) { res.writeHead(500); return res.end('File mancante'); }
    res.writeHead(200, {
      'Content-Type': name.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8',
    });
    res.end(buf);
  });
}

const server = http.createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch (_) { res.writeHead(400); return res.end(); }

  if (req.method === 'GET' && url.pathname === '/events') return handleEvents(req, res, url);
  if (req.method === 'POST' && url.pathname === '/send') return handleSend(req, res, url);
  if (req.method === 'GET' && FILES[url.pathname]) return serveFile(res, FILES[url.pathname]);
  res.writeHead(404);
  res.end('Not found');
});

// Heartbeat: tiene aperte le connessioni SSE attraverso proxy e tunnel
setInterval(() => {
  for (const room of rooms.values()) {
    for (const c of room.clients.values()) { try { c.res.write(': ping\n\n'); } catch (_) { /* ignora */ } }
  }
}, 20000).unref();

// Pulizia periodica delle tabelle in memoria
setInterval(() => {
  const now = Date.now();
  for (const [id, until] of burned) if (until <= now) burned.delete(id);
  for (const [ip, arr] of hits) {
    const fresh = arr.filter((t) => now - t < 60000);
    if (fresh.length) hits.set(ip, fresh); else hits.delete(ip);
  }
}, 60000).unref();

server.listen(PORT, () => {
  console.log(`OTC in ascolto su http://localhost:${PORT}`);
  console.log('Il server inoltra solo dati cifrati e non salva nulla.');
  console.log('Per farlo raggiungere da fuori: cloudflared tunnel --url http://localhost:' + PORT + '   (oppure: ngrok http ' + PORT + ')');
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { console.log('\nChiuso. Tutte le stanze in memoria sono state eliminate.'); process.exit(0); });
}
