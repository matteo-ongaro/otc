/* OTC - logica del client: stanza, WebRTC con ripiego su relay cifrato, chat, chiusura a doppia conferma, PDF, cancellazione. */
(() => {
  'use strict';
  const OTC = window.OTC;
  const $ = (s) => document.querySelector(s);
  const params = new URLSearchParams(location.search);
  const FORCE_RELAY = params.get('transport') === 'relay'; // solo per prove: disattiva WebRTC
  const ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }] };
  const coarse = !!(window.matchMedia && matchMedia('(pointer: coarse)').matches);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function fresh() {
    return {
      nick: '', code: '', key: null, room: '', cid: '', sid: '', role: '',
      peerSid: '', peerNick: '', es: null, pc: null, dc: null,
      msgs: [], seen: new Set(), seq: 0, q: Promise.resolve(),
      hs: false, inChat: false, startedAt: 0,
      end: 'none', myHash: '', finalSent: false, peerFinal: null, completed: false, peerFinalTimer: null,
      pdfUrl: '',
    };
  }
  let S = fresh();

  function randomId(n) {
    const a = crypto.getRandomValues(new Uint8Array(n));
    const abc = 'abcdefghjkmnpqrstuvwxyz23456789';
    return Array.from(a).map((b) => abc[b % abc.length]).join('');
  }

  // ---------- interfaccia ----------
  function show(name) {
    document.querySelectorAll('.screen').forEach((el) => { el.hidden = el.id !== 'screen-' + name; });
  }
  function banner(text) {
    const el = $('#banner');
    el.hidden = !text;
    el.textContent = text || '';
  }
  function setStatus(t) { $('#wait-status').textContent = t; }

  function overlay(title, text, buttons) {
    $('#ov-title').textContent = title;
    $('#ov-text').textContent = text;
    const box = $('#ov-actions');
    box.replaceChildren();
    for (const b of buttons) {
      const el = document.createElement('button');
      el.className = b.kind;
      el.type = 'button';
      el.textContent = b.label;
      el.onclick = b.fn;
      box.append(el);
    }
    $('#overlay').hidden = false;
  }
  function closeOverlay() { $('#overlay').hidden = true; }

  function lock(on) {
    $('#msg').disabled = on;
    $('#send').disabled = on;
    $('#end-btn').disabled = on;
    if (!on && !coarse) $('#msg').focus();
  }

  function scrollDown() { const l = $('#log'); l.scrollTop = l.scrollHeight; }
  function addNote(text) {
    const el = document.createElement('div');
    el.className = 'note';
    el.textContent = text;
    $('#log').append(el);
    scrollDown();
  }
  function addBubble(m) {
    const el = document.createElement('div');
    el.className = 'bubble ' + (m.me ? 'me' : 'them');
    const t = document.createElement('div');
    t.className = 'text';
    t.textContent = m.x; // textContent: nessun HTML dai messaggi altrui
    const meta = document.createElement('div');
    meta.className = 'meta';
    const time = new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.textContent = (m.me ? '' : m.n + ' · ') + time;
    el.append(t, meta);
    $('#log').append(el);
    scrollDown();
    return el;
  }

  function updateTransport() {
    const p2p = !!(S.dc && S.dc.readyState === 'open');
    const el = $('#transport');
    el.textContent = p2p ? 'P2P diretto' : 'Relay cifrato';
    el.dataset.mode = p2p ? 'p2p' : 'relay';
    el.title = p2p ? 'Connessione diretta tra i due dispositivi: il server non vede nemmeno il traffico.'
      : 'I messaggi passano dal server ma sono cifrati end-to-end: il server non può leggerli.';
  }

  // ---------- avvio ----------
  $('#gen').onclick = () => { $('#code').value = OTC.generateCode(); $('#code').focus(); };
  $('#join-form').addEventListener('submit', (e) => { e.preventDefault(); start(); });
  $('#cancel').onclick = () => location.reload();
  $('#again').onclick = () => location.reload();
  $('#copy').onclick = async () => {
    try { await navigator.clipboard.writeText(OTC.formatCode(S.code)); $('#copy').textContent = 'Copiato ✓'; } catch (_) { /* ignora */ }
  };

  async function start() {
    const err = $('#home-error');
    err.textContent = '';
    if (!OTC.hasCrypto()) {
      err.textContent = 'Il browser blocca la crittografia su connessioni non sicure. Apri la pagina tramite HTTPS (tunnel) oppure da localhost.';
      return;
    }
    const code = OTC.normalizeCode($('#code').value);
    if (code.length < 6) { err.textContent = 'Il codice deve avere almeno 6 caratteri (meglio usare "Genera").'; return; }
    S.nick = ($('#nick').value.trim() || 'Anonimo').slice(0, 24);
    S.code = code;
    $('#join-btn').disabled = true;
    $('#wait-code').textContent = OTC.formatCode(code);
    $('#copy').textContent = 'Copia codice';
    show('wait');
    setStatus('Derivo la chiave dal codice…');
    try {
      const { room, key } = await OTC.deriveSession(code);
      S.room = room;
      S.key = key;
    } catch (e) { return fatal('Errore di crittografia: ' + e.message); }
    S.cid = randomId(16);
    S.sid = randomId(12);
    openEvents();
  }

  function closeLinks() {
    try { if (S.dc) S.dc.close(); } catch (_) { /* ignora */ }
    try { if (S.pc) S.pc.close(); } catch (_) { /* ignora */ }
    try { if (S.es) S.es.close(); } catch (_) { /* ignora */ }
    S.dc = null; S.pc = null; S.es = null;
  }

  function fatal(msg) {
    wipe();
    S = fresh();
    banner('');
    closeOverlay();
    show('home');
    $('#join-btn').disabled = false;
    $('#home-error').textContent = msg;
  }

  // ---------- segnalazione (SSE) ----------
  function openEvents() {
    const es = new EventSource(`/events?room=${S.room}&cid=${S.cid}`);
    S.es = es;
    es.addEventListener('joined', (e) => {
      const d = JSON.parse(e.data);
      banner('');
      S.role = d.role;
      if (d.peer) startHandshake();
      else setStatus('In attesa che l\'altro dispositivo inserisca lo stesso codice (valido 3 minuti)…');
    });
    es.addEventListener('peer', () => startHandshake());
    es.addEventListener('m', (e) => enqueue(JSON.parse(e.data)));
    es.addEventListener('peer-left', () => onPeerLeft('L\'altro dispositivo si è disconnesso.'));
    es.addEventListener('unavailable', () => fatal('Codice non disponibile: è già in uso, scaduto o è già stato usato per un\'altra chat.'));
    es.addEventListener('expired', () => { if (S.inChat) onPeerLeft('La stanza è scaduta.'); else fatal('Tempo scaduto: nessuno si è collegato con questo codice.'); });
    es.onerror = () => {
      if (S.completed) return;
      if (es.readyState === EventSource.CLOSED) {
        if (S.inChat) onPeerLeft('Connessione al server persa.');
        else fatal('Impossibile collegarsi al server (troppi tentativi o server non raggiungibile). Riprova tra poco.');
      } else banner('Riconnessione al server…');
    };
  }

  // ---------- invio / ricezione cifrati ----------
  async function sendRaw(raw) {
    if (S.dc && S.dc.readyState === 'open') {
      try { S.dc.send(raw); return true; } catch (_) { /* ripiego su relay */ }
    }
    try {
      const r = await fetch(`/send?room=${S.room}&cid=${S.cid}`, {
        method: 'POST', body: raw, cache: 'no-store',
        headers: { 'Content-Type': 'text/plain', 'ngrok-skip-browser-warning': '1' },
      });
      return r.ok;
    } catch (_) { return false; }
  }
  async function sendControl(o) {
    if (!S.key) return false;
    o.f = S.sid;
    return sendRaw(await OTC.encrypt(S.key, o));
  }
  function enqueue(raw) { S.q = S.q.then(() => onRaw(raw)).catch(() => {}); }

  async function onRaw(raw) {
    if (S.completed || !S.key) return;
    let o;
    try { o = await OTC.decrypt(S.key, raw); } catch (_) { return; }
    if (!o || typeof o !== 'object' || typeof o.f !== 'string' || o.f === S.sid) return;
    if (!S.peerSid) S.peerSid = o.f; else if (o.f !== S.peerSid) return;

    switch (o.t) {
      case 'hello':
        S.peerNick = String(o.n || 'Anonimo').slice(0, 24);
        if (!S.hs) startHandshake();
        enterChat();
        break;

      case 'sdp': {
        const d = o.d;
        if (!d || FORCE_RELAY) break;
        if (d.type === 'offer' && !S.pc) startRtc(false, { type: 'offer', sdp: String(d.sdp) });
        else if (d.type === 'answer' && S.pc) S.pc.setRemoteDescription({ type: 'answer', sdp: String(d.sdp) }).catch(() => {});
        break;
      }

      case 'msg': {
        if (S.end === 'finalizing' && S.myHash) break; // trascrizione già congelata
        const id = String(o.id || '').slice(0, 40);
        if (!id || S.seen.has(id)) break;
        S.seen.add(id);
        const m = {
          id, n: String(o.n || 'Anonimo').slice(0, 24), x: String(o.x || '').slice(0, 4000),
          ts: Math.floor(Number(o.ts)) || Date.now(), r: o.r === 'host' ? 'host' : 'guest', me: false,
        };
        S.msgs.push(m);
        addBubble(m);
        break;
      }

      case 'end-req':
        if (S.end === 'asking') { S.end = 'agreed'; doFinal(); } // richieste incrociate = accordo
        else if (S.end === 'none') {
          S.end = 'asked';
          lock(true);
          overlay(S.peerNick + ' vuole concludere',
            'Se confermi, la chat viene salvata come PDF su entrambi i dispositivi e poi cancellata completamente dall\'app.',
            [{ label: 'Conferma e salva PDF', kind: 'primary', fn: confirmEnd },
              { label: 'Continua a chattare', kind: 'ghost', fn: declineEnd }]);
        }
        break;

      case 'end-ack':
        if (S.end === 'asking') { S.end = 'agreed'; doFinal(); }
        break;

      case 'end-cancel':
        if (S.end === 'asked' || S.end === 'asking') {
          S.end = 'none';
          closeOverlay();
          lock(false);
          addNote(S.peerNick + ' ha preferito continuare la chat.');
        }
        break;

      case 'final':
        S.peerFinal = { h: String(o.h || '') };
        if (S.end === 'asking') { S.end = 'agreed'; doFinal(); } // il "final" ha superato l'"ack" per strada
        else maybeComplete();
        break;

      default: break;
    }
  }

  // ---------- handshake e WebRTC ----------
  async function startHandshake() {
    if (S.hs) return;
    S.hs = true;
    setStatus('Dispositivo trovato. Stabilisco il collegamento sicuro…');
    await sendControl({ t: 'hello', n: S.nick });
    if (S.role === 'host' && !FORCE_RELAY) startRtc(true);
  }

  function enterChat() {
    if (S.inChat) return;
    S.inChat = true;
    S.startedAt = Date.now();
    $('#peer-name').textContent = S.peerNick;
    updateTransport();
    show('chat');
    addNote('Connessione cifrata end-to-end con ' + S.peerNick + '. Chiave e messaggi esistono solo su questi due dispositivi.');
    if (!coarse) $('#msg').focus();
  }

  function setupDc(dc) {
    dc.onopen = () => { S.dc = dc; updateTransport(); };
    dc.onclose = () => { if (S.dc === dc) { S.dc = null; updateTransport(); } };
    dc.onmessage = (e) => enqueue(e.data);
  }
  function createPc(offerer) {
    const pc = new RTCPeerConnection(ICE);
    S.pc = pc;
    pc.ondatachannel = (e) => setupDc(e.channel);
    pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed') updateTransport(); };
    if (offerer) setupDc(pc.createDataChannel('otc'));
    return pc;
  }
  function iceDone(pc, ms) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') return resolve();
      const t = setTimeout(done, ms || 4000);
      function check() { if (pc.iceGatheringState === 'complete') done(); }
      function done() { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', check); resolve(); }
      pc.addEventListener('icegatheringstatechange', check);
    });
  }
  // La chat parte subito sul relay cifrato; se il collegamento diretto riesce, si passa a P2P.
  async function startRtc(offerer, remote) {
    try {
      const pc = S.pc || createPc(offerer);
      if (offerer) await pc.setLocalDescription(await pc.createOffer());
      else { await pc.setRemoteDescription(remote); await pc.setLocalDescription(await pc.createAnswer()); }
      await iceDone(pc);
      await sendControl({ t: 'sdp', d: { type: pc.localDescription.type, sdp: pc.localDescription.sdp } });
    } catch (_) { /* si resta sul relay */ }
  }

  // ---------- messaggi ----------
  $('#composer').addEventListener('submit', (e) => { e.preventDefault(); sendMessage(); });
  $('#msg').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !coarse) { e.preventDefault(); sendMessage(); }
  });
  $('#msg').addEventListener('input', (e) => {
    const t = e.target;
    t.style.height = 'auto';
    t.style.height = Math.min(t.scrollHeight, 120) + 'px';
  });

  function sendMessage() {
    if (S.end !== 'none' || !S.inChat) return;
    const ta = $('#msg');
    const x = ta.value.trim();
    if (!x) return;
    const m = { id: S.sid.slice(0, 6) + '-' + (++S.seq), n: S.nick, x, ts: Date.now(), r: S.role, me: true };
    S.msgs.push(m);
    S.seen.add(m.id);
    const el = addBubble(m);
    ta.value = '';
    ta.style.height = 'auto';
    sendControl({ t: 'msg', id: m.id, n: m.n, x: m.x, ts: m.ts, r: m.r }).then((ok) => {
      if (!ok) { el.classList.add('failed'); el.querySelector('.meta').textContent += ' · non consegnato'; }
    });
    ta.focus();
  }

  // ---------- chiusura a doppia conferma ----------
  $('#end-btn').onclick = requestEnd;

  function requestEnd() {
    if (S.end !== 'none' || !S.inChat) return;
    S.end = 'asking';
    lock(true);
    overlay('In attesa di conferma',
      'Hai chiesto di concludere. Se ' + S.peerNick + ' conferma, la chat viene salvata come PDF su entrambi i dispositivi e poi cancellata.',
      [{ label: 'Annulla richiesta', kind: 'ghost', fn: cancelEnd }]);
    sendControl({ t: 'end-req' }).then((ok) => { if (!ok && S.end === 'asking') { cancelEnd(); addNote('Richiesta non consegnata, riprova.'); } });
  }
  function cancelEnd() {
    S.end = 'none';
    closeOverlay();
    lock(false);
    sendControl({ t: 'end-cancel' });
  }
  async function confirmEnd() {
    S.end = 'agreed';
    await sendControl({ t: 'end-ack' });
    doFinal();
  }
  function declineEnd() {
    S.end = 'none';
    closeOverlay();
    lock(false);
    sendControl({ t: 'end-cancel' });
  }

  async function doFinal() {
    S.end = 'finalizing';
    lock(true);
    overlay('Preparo il PDF…', 'Aspetto gli ultimi messaggi in arrivo e verifico che le due trascrizioni coincidano.', []);
    await sleep(600); // lascia arrivare i messaggi ancora in volo
    if (S.completed) return;
    S.myHash = await OTC.transcriptHash(S.msgs);
    S.finalSent = true;
    S.peerFinalTimer = setTimeout(() => finishAndWipe(null, true), 12000);
    await sendControl({ t: 'final', h: S.myHash, c: S.msgs.length });
    maybeComplete();
  }
  function maybeComplete() {
    if (S.completed || !S.finalSent || !S.peerFinal) return;
    finishAndWipe(S.peerFinal.h === S.myHash, true);
  }

  function onPeerLeft(reason) {
    if (S.completed) return;
    closeLinks();
    if (S.end === 'finalizing') {
      if (S.finalSent) finishAndWipe(S.peerFinal ? S.peerFinal.h === S.myHash : null, true);
      return;
    }
    if (!S.inChat) return fatal('L\'altro dispositivo si è scollegato prima dell\'inizio. Riprova con un nuovo codice.');
    lock(true);
    overlay('Chat interrotta', reason + ' Non si può continuare: puoi salvare il PDF di quanto scritto (poi la chat viene cancellata) oppure cancellare tutto subito.', [
      { label: 'Salva PDF e cancella', kind: 'primary', fn: async () => { S.end = 'finalizing'; S.myHash = await OTC.transcriptHash(S.msgs); finishAndWipe(null, true); } },
      { label: 'Cancella senza salvare', kind: 'ghost', fn: () => finishAndWipe(null, false) },
    ]);
  }

  // ---------- PDF + cancellazione ----------
  function download(url, name) {
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
  }

  function wipe() {
    closeLinks();
    clearTimeout(S.peerFinalTimer);
    S.msgs.length = 0;
    S.seen.clear();
    S.key = null;
    S.code = '';
    S.room = '';
    $('#log').replaceChildren();
    $('#msg').value = '';
    $('#code').value = '';
    $('#wait-code').textContent = '';
  }

  async function finishAndWipe(verified, save) {
    if (S.completed) return;
    S.completed = true;
    clearTimeout(S.peerFinalTimer);
    let fp = '';
    if (save) {
      if (!S.myHash) S.myHash = await OTC.transcriptHash(S.msgs);
      const peerRole = S.role === 'host' ? 'guest' : 'host';
      const parts = [{ n: S.nick, r: S.role }, { n: S.peerNick, r: peerRole }].sort((a, b) => (a.r === 'host' ? -1 : 1) - (b.r === 'host' ? -1 : 1));
      const bytes = OTC.buildPdf({
        participants: parts, messages: S.msgs, hash: S.myHash,
        startedAt: S.startedAt, endedAt: Date.now(), verified,
      });
      S.pdfUrl = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
      const d = new Date();
      const p = (n) => String(n).padStart(2, '0');
      const name = `OTC-chat-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.pdf`;
      download(S.pdfUrl, name);
      fp = OTC.fingerprint(S.myHash);
      $('#done-dl').href = S.pdfUrl;
      $('#done-dl').download = name;
    }
    wipe();
    closeOverlay();
    banner('');

    $('#done-dl').hidden = !save;
    if (save) {
      $('#done-title').textContent = 'Chat conclusa';
      let t = 'Il PDF è stato scaricato. Nell\'app non resta più nulla della conversazione: messaggi, chiave e connessione sono stati eliminati.';
      if (verified === true) t += ' Le due trascrizioni coincidono.';
      else if (verified === false) t += ' Attenzione: le impronte dei due dispositivi non coincidono, la trascrizione potrebbe differire.';
      else t += ' Non è stato possibile verificare la trascrizione con l\'altro dispositivo.';
      t += ' Il PDF resta scaricabile qui solo finché non chiudi questa pagina.';
      $('#done-text').textContent = t;
      $('#done-fp').textContent = 'Impronta ' + fp;
    } else {
      $('#done-title').textContent = 'Chat cancellata';
      $('#done-text').textContent = 'Nessuna copia è stata salvata. Messaggi, chiave e connessione sono stati eliminati.';
      $('#done-fp').textContent = '';
    }
    show('done');
  }

  window.addEventListener('beforeunload', (e) => {
    if (S.inChat && !S.completed) { e.preventDefault(); e.returnValue = ''; }
  });
})();
