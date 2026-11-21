'use strict';
// Test senza dipendenze: node test/test.js
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const OTC = require('../public/otc-lib.js');

let passed = 0;
async function t(name, fn) {
  try { await fn(); passed++; console.log('  ok  ' + name); }
  catch (e) { console.log('  KO  ' + name + '\n      ' + (e && e.stack || e)); process.exitCode = 1; }
}

// ---------- libreria ----------
async function libTests() {
  console.log('Libreria (crypto, trascrizione, PDF)');
  await t('codice generato: formato XXXX-XXXX, alfabeto senza 0/O/1/I', () => {
    for (let i = 0; i < 200; i++) assert.match(OTC.generateCode(), /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
  });
  await t('normalizeCode ignora trattini, spazi e maiuscole', () => {
    assert.strictEqual(OTC.normalizeCode(' ab12-cd34 '), 'AB12CD34');
  });
  await t('stesso codice -> stessa stanza; codice diverso -> stanza diversa', async () => {
    const a = await OTC.deriveSession('K7X2-9MQA', 1000);
    const b = await OTC.deriveSession('k7x2 9mqa', 1000);
    const c = await OTC.deriveSession('K7X2-9MQB', 1000);
    assert.strictEqual(a.room, b.room);
    assert.notStrictEqual(a.room, c.room);
    assert.match(a.room, /^[a-f0-9]{32}$/);
  });
  await t('cifra/decifra; chiave sbagliata e manomissione falliscono', async () => {
    const a = await OTC.deriveSession('K7X2-9MQA', 1000);
    const c = await OTC.deriveSession('K7X2-9MQB', 1000);
    const blob = await OTC.encrypt(a.key, { t: 'msg', x: 'ciao è perché' });
    assert.match(blob, /^[A-Za-z0-9+/=]+$/);
    assert.deepStrictEqual(await OTC.decrypt(a.key, blob), { t: 'msg', x: 'ciao è perché' });
    await assert.rejects(OTC.decrypt(c.key, blob));
    const bytes = Buffer.from(blob, 'base64'); bytes[bytes.length - 1] ^= 1;
    await assert.rejects(OTC.decrypt(a.key, bytes.toString('base64')));
  });
  await t('due cifrature dello stesso testo sono diverse (IV casuale)', async () => {
    const a = await OTC.deriveSession('K7X2-9MQA', 1000);
    assert.notStrictEqual(await OTC.encrypt(a.key, { x: 1 }), await OTC.encrypt(a.key, { x: 1 }));
  });
  await t('impronta della trascrizione indipendente dall\'ordine di arrivo', async () => {
    const m1 = { id: 'a-1', n: 'A', x: 'uno', ts: 1000 };
    const m2 = { id: 'b-1', n: 'B', x: 'due', ts: 2000 };
    assert.strictEqual(await OTC.transcriptHash([m1, m2]), await OTC.transcriptHash([m2, m1]));
    assert.notStrictEqual(await OTC.transcriptHash([m1, m2]), await OTC.transcriptHash([m1]));
  });

  function pdfCheck(bytes) {
    const s = Buffer.from(bytes).toString('latin1');
    assert.ok(s.startsWith('%PDF-1.4'));
    assert.ok(s.trimEnd().endsWith('%%EOF'));
    const startxref = Number(/startxref\n(\d+)\n%%EOF/.exec(s)[1]);
    assert.ok(s.slice(startxref).startsWith('xref'));
    const lines = s.slice(startxref).split('\n');
    const n = Number(lines[1].split(' ')[1]);
    for (let i = 1; i < n; i++) {
      const off = Number(lines[2 + i].slice(0, 10));
      assert.ok(s.slice(off).startsWith(i + ' 0 obj'), 'offset xref oggetto ' + i);
    }
    return s;
  }
  const parts = [{ n: 'Mario', r: 'host' }, { n: 'Luca', r: 'guest' }];
  await t('PDF: struttura valida (offset xref esatti)', async () => {
    const msgs = [{ id: 'a-1', n: 'Mario', x: 'Ciao! Perché è così? (test) \\ ok', ts: Date.now(), r: 'host' }];
    const bytes = OTC.buildPdf({ participants: parts, messages: msgs, hash: await OTC.transcriptHash(msgs), verified: true });
    pdfCheck(bytes);
  });
  await t('PDF: tante pagine, parole lunghissime, emoji', async () => {
    const msgs = [];
    for (let i = 0; i < 300; i++) msgs.push({ id: 'a-' + i, n: i % 2 ? 'Luca' : 'Mario', r: i % 2 ? 'guest' : 'host', ts: 1700000000000 + i * 60000, x: i === 5 ? 'x'.repeat(400) : 'Messaggio numero ' + i + ' con 😀 emoji e testo abbastanza lungo da andare a capo più di una volta nella pagina A4.' });
    const bytes = OTC.buildPdf({ participants: parts, messages: msgs, hash: await OTC.transcriptHash(msgs), verified: null });
    const s = pdfCheck(bytes);
    assert.ok(Number(/\/Count (\d+)/.exec(s)[1]) > 5);
  });
}

// ---------- server ----------
const PORT = 18000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
let ipn = 0;
const nextIp = () => '10.9.' + Math.floor(++ipn / 250) + '.' + (ipn % 250);

async function sse(room, cid, ip) {
  const ac = new AbortController();
  const res = await fetch(`${BASE}/events?room=${room}&cid=${cid}`, { headers: { 'x-forwarded-for': ip || nextIp() }, signal: ac.signal });
  const out = { status: res.status, events: [], waiters: [], close: () => ac.abort() };
  if (res.status !== 200) return out;
  (async () => {
    const rd = res.body.getReader(); const td = new TextDecoder(); let buf = '';
    try {
      for (;;) {
        const { value, done } = await rd.read(); if (done) break;
        buf += td.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, i); buf = buf.slice(i + 2);
          let name = null, data = '';
          for (const l of block.split('\n')) { if (l.startsWith('event: ')) name = l.slice(7); else if (l.startsWith('data: ')) data += l.slice(6); }
          if (!name) continue;
          const ev = { name, data: data ? JSON.parse(data) : null };
          const w = out.waiters.findIndex((x) => x.name === name);
          if (w >= 0) out.waiters.splice(w, 1)[0].resolve(ev); else out.events.push(ev);
        }
      }
    } catch (_) { /* chiusa */ }
  })();
  out.next = (name, ms = 3000) => {
    const k = out.events.findIndex((e) => e.name === name);
    if (k >= 0) return Promise.resolve(out.events.splice(k, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { name, resolve };
      out.waiters.push(w);
      setTimeout(() => { const j = out.waiters.indexOf(w); if (j >= 0) { out.waiters.splice(j, 1); reject(new Error('timeout in attesa di "' + name + '"')); } }, ms);
    });
  };
  return out;
}
const post = (room, cid, body) => fetch(`${BASE}/send?room=${room}&cid=${cid}`, { method: 'POST', body, headers: { 'Content-Type': 'text/plain' } });
const rid = () => Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');

async function serverTests() {
  console.log('Server (stanze, relay, monouso, scadenza)');
  const srv = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), OTC_WAIT_MS: '700', OTC_GRACE_MS: '400', OTC_JOINS_PER_MIN: '30' },
  });
  await new Promise((resolve, reject) => {
    srv.stdout.on('data', (d) => { if (String(d).includes('in ascolto')) resolve(); });
    srv.on('error', reject);
    setTimeout(() => reject(new Error('server non partito')), 4000);
  });
  try {
    await t('serve pagina e script con intestazioni di sicurezza', async () => {
      for (const p of ['/', '/app.js', '/otc-lib.js']) {
        const r = await fetch(BASE + p);
        assert.strictEqual(r.status, 200, p);
        assert.ok(r.headers.get('content-security-policy').includes("script-src 'self'"));
        assert.strictEqual(r.headers.get('cache-control'), 'no-store');
      }
      assert.strictEqual((await fetch(BASE + '/server.js')).status, 404);
      assert.strictEqual((await fetch(BASE + '/../server.js')).status, 404);
    });

    await t('due client si accoppiano: host/guest, evento peer, relay in entrambe le direzioni', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0001');
      const ja = await a.next('joined');
      assert.deepStrictEqual(ja.data, { role: 'host', peer: false });
      const b = await sse(room, 'clientb0001');
      assert.deepStrictEqual((await b.next('joined')).data, { role: 'guest', peer: true });
      await a.next('peer');
      assert.strictEqual((await post(room, 'clienta0001', 'QUJDRA==')).status, 204);
      assert.strictEqual((await b.next('m')).data, 'QUJDRA==');
      assert.strictEqual((await post(room, 'clientb0001', 'WFla')).status, 204);
      assert.strictEqual((await a.next('m')).data, 'WFla');
      a.close(); b.close();
    });

    await t('un terzo client viene respinto; non si capisce se il codice esiste', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0002'); await a.next('joined');
      const b = await sse(room, 'clientb0002'); await b.next('joined');
      const c = await sse(room, 'clientc0002');
      assert.strictEqual((await c.next('unavailable')).name, 'unavailable');
      a.close(); b.close();
    });

    await t('invio rifiutato: non membro (403), corpo non base64 (400), troppo grande (413)', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0003'); await a.next('joined');
      const b = await sse(room, 'clientb0003'); await b.next('joined');
      assert.strictEqual((await post(room, 'intruso0001', 'QUJD')).status, 403);
      assert.strictEqual((await post(room, 'clienta0003', 'ciao\nevent: x')).status, 400);
      assert.strictEqual((await post(room, 'clienta0003', 'A'.repeat(70 * 1024))).status, 413);
      a.close(); b.close();
    });

    await t('invio senza l\'altro partecipante -> 409', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0004'); await a.next('joined');
      assert.strictEqual((await post(room, 'clienta0004', 'QUJD')).status, 409);
      a.close();
    });

    await t('se uno esce, l\'altro riceve peer-left e il codice è bruciato', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0005'); await a.next('joined');
      const b = await sse(room, 'clientb0005'); await b.next('joined');
      a.close();
      await b.next('peer-left', 2500);
      await new Promise((r) => setTimeout(r, 100));
      const again = await sse(room, 'clientc0005');
      await again.next('unavailable');
      b.close();
    });

    await t('ricollegamento entro la tolleranza: nessun peer-left, stessa stanza', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0006'); await a.next('joined');
      const b = await sse(room, 'clientb0006'); await b.next('joined');
      a.close();
      await new Promise((r) => setTimeout(r, 150));
      const a2 = await sse(room, 'clienta0006');
      assert.deepStrictEqual((await a2.next('joined')).data, { role: 'host', peer: true });
      await new Promise((r) => setTimeout(r, 700));
      assert.ok(!b.events.some((e) => e.name === 'peer-left'));
      assert.strictEqual((await post(room, 'clienta0006', 'QUJD')).status, 204);
      a2.close(); b.close();
    });

    await t('stanza in attesa: scade, il codice non viene bruciato', async () => {
      const room = rid();
      const a = await sse(room, 'clienta0007'); await a.next('joined');
      await a.next('expired', 2500);
      const again = await sse(room, 'clienta0008');
      assert.deepStrictEqual((await again.next('joined')).data, { role: 'host', peer: false });
      again.close();
    });

    await t('limite di tentativi per IP (429)', async () => {
      const ip = '203.0.113.77';
      let last = 200;
      const open = [];
      for (let i = 0; i < 35 && last !== 429; i++) {
        const s = await sse(rid(), 'spam' + String(i).padStart(6, '0'), ip);
        last = s.status; open.push(s);
      }
      open.forEach((s) => s.close());
      assert.strictEqual(last, 429);
    });
  } finally {
    srv.kill();
  }
}

(async () => {
  await libTests();
  await serverTests();
  console.log(`\n${passed} test superati` + (process.exitCode ? ' - CI SONO FALLIMENTI' : ''));
})();
