# OTC - One Time Communication

Chat a due, cifrata end-to-end, senza account. Si entra con un codice, si chatta, e quando **entrambi** premono "Concludi" ognuno scarica un PDF della conversazione e la chat viene cancellata dall'app.

## Avvio (serve solo Node 18+, nessun `npm install`)

```bash
node server.js                                  # server su http://localhost:8080
cloudflared tunnel --url http://localhost:8080  # in un altro terminale (oppure: ngrok http 8080)
```

Il tunnel stampa un indirizzo `https://...`: aprilo sul tuo telefono e mandalo all'amico. Funziona anche con il PC collegato all'hotspot del telefono, perché il tunnel usa solo connessioni in uscita.

1. Uno tocca **Genera**, poi **Entra**, e comunica il codice all'altro (a voce o su un altro canale).
2. L'altro scrive lo stesso codice e preme **Entra**.
3. Si chatta. **Concludi** -> l'altro conferma -> si scarica un PDF a testa e la chat sparisce.

Test: `node test/test.js` (libreria, PDF e server; nessuna dipendenza).

## Come funziona

- **Codice -> chiavi.** Nel browser il codice passa da PBKDF2 (200.000 iterazioni) e ne escono due cose: l'id della stanza (l'unica cosa che il server vede) e la chiave AES-GCM che cifra tutto. Il server non conosce né il codice né la chiave.
- **Connessione.** I due browser provano a collegarsi direttamente con WebRTC (P2P). Nel frattempo la chat funziona già tramite il server, che inoltra solo blob cifrati. Se il P2P riesce, il badge in alto passa da "Relay cifrato" a "P2P diretto".
- **Codice monouso.** Una stanza ha al massimo 2 persone, scade dopo 3 minuti se nessuno entra, e un codice già usato viene bloccato per 1 ora. Tentativi di accesso limitati per IP.
- **Chiusura.** "Concludi" richiede la conferma dell'altro. Poi i due dispositivi confrontano l'impronta SHA-256 della trascrizione (compare anche nel PDF) per verificare di avere gli stessi messaggi, generano il PDF in locale, lo scaricano e azzerano messaggi, chiave e connessioni.

## Limiti da conoscere

- **HTTPS obbligatorio sui telefoni**: la crittografia del browser funziona solo su HTTPS o localhost. Per questo serve il tunnel. Con ngrok gratuito la prima visita mostra una pagina di avviso da confermare; Cloudflare Tunnel no.
- **"Cancellata" vuol dire dall'app.** Non si possono impedire screenshot, copie o il PDF dell'altro. Il PDF scaricato resta nei file di ciascuno, e dalla schermata finale si può riscaricare finché non si chiude la pagina.
- **Il codice è il segreto.** Quelli generati hanno 40 bit di entropia e bastano. Codici scelti a mano e corti sono indovinabili. Chi ha il codice può entrare.
- **Nel P2P i due dispositivi vedono l'IP l'uno dell'altro** (è il funzionamento di WebRTC). Sul relay no, ma passa dal tuo server.
- **PDF:** usa Helvetica, quindi emoji e alfabeti non latini diventano `?` (il PDF lo dichiara). Per supportarli si può incorporare un font TTF.
- **Tieni l'app in primo piano.** Se il telefono sospende la pagina per più di ~30 secondi, l'altro vede la chat interrotta e può salvare il PDF di quanto scritto.
- È un prototipo: nessun login, nessuna verifica dell'identità dell'interlocutore oltre al possesso del codice.

## File

- `server.js` - server di segnalazione e relay (zero dipendenze)
- `public/index.html`, `public/app.js` - interfaccia e logica
- `public/otc-lib.js` - crittografia, impronta della trascrizione, generatore PDF
- `test/test.js` - test
