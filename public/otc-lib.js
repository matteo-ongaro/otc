/*
 * OTC - libreria condivisa (browser + Node): crittografia, trascrizione, generatore PDF.
 * Nessuna dipendenza esterna.
 */
(function (root) {
  'use strict';

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const cr = root.crypto;
  const subtle = cr && cr.subtle;

  // ---------- utilità ----------
  function hex(buf) {
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  function b64(buf) {
    const a = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) {
    const bin = atob(s);
    const a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }
  function concat(a, b) {
    const o = new Uint8Array(a.length + b.length);
    o.set(a);
    o.set(b, a.length);
    return o;
  }
  function hasCrypto() { return !!subtle; } // false su pagine http non sicure (tranne localhost)

  // ---------- codice ----------
  const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 simboli, senza 0/O e 1/I
  function normalizeCode(c) { return String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
  function formatCode(c) { return normalizeCode(c).replace(/(.{4})(?=.)/g, '$1-'); }
  function generateCode() {
    const r = cr.getRandomValues(new Uint8Array(8)); // 256 % 32 == 0: nessun bias
    let s = '';
    for (const b of r) s += ALPHABET[b % 32];
    return s.slice(0, 4) + '-' + s.slice(4); // 40 bit di entropia
  }

  // ---------- crittografia ----------
  const PBKDF2_ITER = 200000;

  // Dal codice si ricavano (con PBKDF2) un segreto "master", da cui derivano:
  //  - l'id della stanza (l'unica cosa che il server vede: non permette di risalire al codice senza un PBKDF2 per tentativo)
  //  - la chiave AES-GCM che cifra tutto (il server non la conosce)
  async function deriveSession(code, iterations) {
    if (!subtle) throw new Error('Crittografia non disponibile in questo contesto');
    const norm = normalizeCode(code);
    const base = await subtle.importKey('raw', enc.encode(norm), 'PBKDF2', false, ['deriveBits']);
    const master = new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('otc/v1/salt'), iterations: iterations || PBKDF2_ITER }, base, 256));
    const roomHash = await subtle.digest('SHA-256', concat(enc.encode('otc/room|'), master));
    const keyHash = await subtle.digest('SHA-256', concat(enc.encode('otc/key|'), master));
    const key = await subtle.importKey('raw', keyHash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { room: hex(roomHash).slice(0, 32), key };
  }

  async function encrypt(key, obj) {
    const iv = cr.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return b64(concat(iv, new Uint8Array(ct)));
  }
  async function decrypt(key, s) {
    const a = unb64(s);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: a.subarray(0, 12) }, key, a.subarray(12));
    return JSON.parse(dec.decode(pt));
  }

  // ---------- trascrizione ----------
  function sortMessages(msgs) {
    return msgs.slice().sort((a, b) => (a.ts - b.ts) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }
  // Impronta SHA-256 della trascrizione in ordine canonico: i due dispositivi la confrontano
  // alla chiusura per verificare che abbiano ricevuto esattamente gli stessi messaggi.
  async function transcriptHash(msgs) {
    const canon = JSON.stringify(sortMessages(msgs).map((m) => [m.id, m.n, m.x, m.ts]));
    return hex(await subtle.digest('SHA-256', enc.encode(canon)));
  }
  function fingerprint(h) { return String(h).slice(0, 16).toUpperCase().replace(/(.{4})(?=.)/g, '$1 '); }

  // ---------- PDF (scritto a mano: Helvetica, testo selezionabile) ----------
  // Larghezze Helvetica per i caratteri 32..126 (unità di 1/1000 del corpo)
  const HELV = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
    278, 278, 584, 584, 584, 556, 1015,
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
    278, 278, 278, 469, 556, 333,
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500,
    334, 260, 334, 584,
  ];
  // Caratteri WinAnsi fuori da ASCII/Latin-1
  const WIN = {
    '€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87,
    'ˆ': 0x88, '‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E, '‘': 0x91,
    '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98,
    '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F,
  };

  function toWin(ch) {
    const c = ch.codePointAt(0);
    if (c >= 0x20 && c <= 0x7E) return c;
    if (c >= 0xA0 && c <= 0xFF) return c;
    return WIN[ch] !== undefined ? WIN[ch] : null;
  }
  function charWidth(ch) {
    const c = ch.codePointAt(0);
    if (c >= 32 && c <= 126) return HELV[c - 32];
    const base = ch.normalize('NFD').charCodeAt(0);
    if (base >= 32 && base <= 126) return Math.max(HELV[base - 32], 278); // lettere accentate
    return 556;
  }

  // Tiene solo i caratteri rappresentabili con Helvetica/WinAnsi (emoji e alfabeti non latini -> "?")
  function sanitize(str, stats) {
    const out = [];
    let lastLost = false;
    for (const ch of String(str).normalize('NFC')) {
      const c = ch.codePointAt(0);
      if (c === 0xFE0E || c === 0xFE0F || c === 0x200D || c === 0x200B) continue; // selettori emoji, ZWJ
      if (ch === '\t') { out.push(' '); lastLost = false; continue; }
      if (c < 0x20 || c === 0x7F) continue;
      if (toWin(ch) !== null) { out.push(ch); lastLost = false; }
      else { if (!lastLost) { out.push('?'); stats.lost++; } lastLost = true; }
    }
    return out.join('');
  }
  function sanitizeMultiline(str, stats) {
    return String(str).split(/\r?\n/).map((l) => sanitize(l, stats)).join('\n');
  }

  function wrap(text, size, maxW) {
    const k = size / 1000;
    const strW = (s) => { let w = 0; for (const ch of s) w += charWidth(ch) * k; return w; };
    function breakWord(word) {
      const pieces = [];
      let cur = '', w = 0;
      for (const ch of word) {
        const cw = charWidth(ch) * k;
        if (w + cw > maxW && cur) { pieces.push(cur); cur = ''; w = 0; }
        cur += ch; w += cw;
      }
      if (cur) pieces.push(cur);
      return pieces;
    }
    const lines = [];
    for (const para of text.split('\n')) {
      let cur = '';
      for (const word of para.split(' ')) {
        const pieces = strW(word) > maxW ? breakWord(word) : [word];
        pieces.forEach((p, i) => {
          if (i > 0) { lines.push(cur); cur = ''; }
          const cand = cur === '' ? p : cur + ' ' + p;
          if (cur === '' || strW(cand) <= maxW) cur = cand;
          else { lines.push(cur); cur = p; }
        });
      }
      lines.push(cur);
    }
    return lines;
  }

  const pad2 = (n) => String(n).padStart(2, '0');
  const fmtDate = (ts) => { const d = new Date(ts); return pad2(d.getDate()) + '/' + pad2(d.getMonth() + 1) + '/' + d.getFullYear(); };
  const fmtTime = (ts) => { const d = new Date(ts); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()); };

  /*
   * opts: { participants:[{n,r}], messages:[{id,n,x,ts,r}], hash, startedAt, endedAt, verified: true|false|null }
   * Restituisce un Uint8Array con il PDF.
   */
  function buildPdf(opts) {
    const stats = { lost: 0 };
    const PW = 595.28, PH = 841.89, MX = 54, TOP = PH - 64, BOT = 64;
    const maxW = PW - 2 * MX;
    const msgs = sortMessages(opts.messages || []);
    const parts = opts.participants || [];
    const sameNick = parts.length === 2 && parts[0].n.trim().toLowerCase() === parts[1].n.trim().toLowerCase();
    const label = (m) => sanitize(sameNick ? m.n + ' (' + (m.r === 'host' ? 1 : 2) + ')' : m.n, stats);

    // Pre-passo: pulizia dei testi (serve a sapere quanti caratteri sono stati sostituiti)
    const prepared = msgs.map((m) => ({
      ts: m.ts,
      who: label(m),
      lines: wrap(sanitizeMultiline(m.x, stats), 10.5, maxW - 14),
    }));
    const names = parts.map((p) => sanitize(p.n, stats)).join(', ');

    const pages = [[]];
    let y = TOP;
    const cur = () => pages[pages.length - 1];
    const newPage = () => { pages.push([]); y = TOP; };
    const need = (h) => { if (y - h < BOT) newPage(); };
    const line = (s, o) => {
      o = o || {};
      const lead = o.lead || 14;
      need(lead);
      y -= lead;
      cur().push({ s, x: o.x === undefined ? MX : o.x, y, size: o.size || 10, bold: !!o.bold, gray: o.gray === undefined ? 0 : o.gray });
    };
    const gap = (h) => { y -= h; };
    const rule = () => { need(6); y -= 4; cur().push({ rule: true, x1: MX, x2: PW - MX, y, gray: 0.75 }); y -= 4; };

    // Intestazione
    line('Conversazione OTC', { size: 20, bold: true, lead: 26 });
    rule();
    gap(4);
    const s = opts.startedAt || Date.now(), e = opts.endedAt || Date.now();
    const when = 'Data: ' + fmtDate(s) + ', ' + fmtTime(s) + ' - ' + (fmtDate(s) === fmtDate(e) ? '' : fmtDate(e) + ', ') + fmtTime(e);
    const meta = [when, 'Partecipanti: ' + names, 'Messaggi: ' + msgs.length, 'Impronta SHA-256 della trascrizione: ' + fingerprint(opts.hash || '')];
    if (opts.verified === true) meta.push('Verifica: anche l\'altro dispositivo ha calcolato la stessa impronta.');
    else if (opts.verified === false) meta.push('ATTENZIONE: l\'impronta dell\'altro dispositivo è diversa, le due trascrizioni potrebbero non coincidere.');
    else meta.push('Verifica non completata (l\'altro dispositivo non ha risposto).');
    if (stats.lost) meta.push('Nota: ' + stats.lost + ' sequenze di caratteri non rappresentabili nel PDF (emoji, alfabeti non latini) sono state sostituite con "?".');
    for (const m of meta) {
      for (const l of wrap(m, 9.5, maxW)) line(l, { size: 9.5, gray: 0.35, lead: 13 });
    }
    gap(4);
    rule();
    gap(6);

    // Messaggi
    let lastDay = '';
    for (const m of prepared) {
      const day = fmtDate(m.ts);
      if (day !== lastDay) {
        need(40);
        gap(8);
        line(day, { size: 9.5, bold: true, gray: 0.4, lead: 16 });
        lastDay = day;
      }
      need(13 + 14.5);
      line(fmtTime(m.ts) + '   ' + m.who, { size: 9, bold: true, gray: 0.35, lead: 13 });
      for (const l of m.lines) line(l, { x: MX + 14, size: 10.5, lead: 14.5 });
      gap(7);
    }

    // Piè di pagina
    const N = pages.length;
    pages.forEach((ops, i) => {
      ops.push({ s: 'OTC - Pagina ' + (i + 1) + ' di ' + N + ' - Impronta ' + fingerprint(opts.hash || ''), x: MX, y: 34, size: 8, bold: false, gray: 0.5 });
    });

    // Serializzazione
    const hexStr = (str) => {
      let h = '';
      for (const ch of str) { const b = toWin(ch); h += (b === null ? 63 : b).toString(16).padStart(2, '0'); }
      return '<' + h + '>';
    };
    const n2 = (v) => v.toFixed(2);
    const stream = (ops) => ops.map((op) => op.rule
      ? `${op.gray} G 0.6 w ${n2(op.x1)} ${n2(op.y)} m ${n2(op.x2)} ${n2(op.y)} l S`
      : `BT /${op.bold ? 'F2' : 'F1'} ${op.size} Tf ${op.gray} g ${n2(op.x)} ${n2(op.y)} Td ${hexStr(op.s)} Tj ET`).join('\n');

    const objs = [];
    objs.push('<</Type/Catalog/Pages 2 0 R>>');
    objs.push(`<</Type/Pages/Kids[${pages.map((_, i) => (6 + 2 * i) + ' 0 R').join(' ')}]/Count ${N}>>`);
    objs.push('<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>');
    objs.push('<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold/Encoding/WinAnsiEncoding>>');
    objs.push('<</Title(OTC - conversazione)/Creator(OTC)/Producer(OTC)>>');
    pages.forEach((ops, i) => {
      const st = stream(ops);
      objs.push(`<</Type/Page/Parent 2 0 R/MediaBox[0 0 ${PW} ${PH}]/Resources<</Font<</F1 3 0 R/F2 4 0 R>>>>/Contents ${7 + 2 * i} 0 R>>`);
      objs.push(`<</Length ${st.length}>>\nstream\n${st}\nendstream`);
    });

    let out = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
    const offs = [];
    objs.forEach((body, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${body}\nendobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
    offs.forEach((o) => { out += String(o).padStart(10, '0') + ' 00000 n \n'; });
    out += `trailer\n<</Size ${objs.length + 1}/Root 1 0 R/Info 5 0 R>>\nstartxref\n${xref}\n%%EOF\n`;

    const bytes = new Uint8Array(out.length);
    for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 255;
    return bytes;
  }

  const api = {
    hasCrypto, generateCode, normalizeCode, formatCode, deriveSession, encrypt, decrypt,
    transcriptHash, fingerprint, buildPdf, PBKDF2_ITER,
  };
  root.OTC = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
