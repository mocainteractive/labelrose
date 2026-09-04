# Guida — Sito statico privato su Netlify con login a password

Ricetta completa e **riutilizzabile** per pubblicare su Netlify un sito/report statico
proteggendolo con una **password condivisa**, verificata **lato server** (nessun rischio
data breach: il contenuto non è mai scaricabile senza autenticazione).

> Testato su `mocainteractive/randstad` (report `social-listening.html`).
> Per riusarla su un altro repository, vedi la sezione **“Adattamenti per una nuova repo”**.

---

## 1. Come funziona (architettura)

- Su Netlify viene aggiunta una **Edge Function** che gira su **ogni** richiesta (`path = "/*"`).
- Se l’utente **non è autenticato** → viene servita **solo** una schermata di login.
  Il file con i dati reali **non viene mai restituito** finché non si supera il login
  (a differenza di una password fatta in JavaScript nel browser, che è aggirabile
  scaricando il sorgente).
- Inserita la password corretta → viene impostato un **cookie firmato (HMAC‑SHA256)**,
  `HttpOnly` + `Secure` + `SameSite=Lax`, valido 12 ore.
- La password **non sta nel codice**: è una **variabile d’ambiente** su Netlify
  (`SITE_PASSWORD`), modificabile in qualsiasi momento.

**Costo:** 0 € — funziona sul piano gratuito di Netlify (Edge Functions incluse).

---

## 2. Prerequisiti

- Un repository su GitHub con dentro il/i file statici (es. un `.html`).
- Un account Netlify (anche gratuito; ci si registra con GitHub).
- L’app **Netlify** deve avere **accesso al repository** su GitHub (vedi sezione 6, è il
  punto dove ci si blocca più spesso).

---

## 3. File da aggiungere al repository

Struttura finale:

```
<repo>/
├── social-listening.html            ← il tuo contenuto statico (nome a piacere)
├── netlify.toml                     ← configurazione Netlify
└── netlify/
    └── edge-functions/
        └── auth.js                  ← login/logout + verifica sessione
```

### 3.1 `netlify.toml` (nella root del repo)

```toml
# Configurazione Netlify — sito statico protetto da password (vedi netlify/edge-functions/auth.js).

[build]
  # Nessun processo di build: sito statico servito dalla root del repository.
  publish = "."
  command = ""

# La home ("/") mostra direttamente il file principale, senza digitarne il nome.
# Riscrittura interna (status 200): l'URL resta "/" ma viene servito il file indicato.
# ⚠️ Adatta il nome del file "to" a quello della TUA repo (o rimuovi il blocco se hai index.html).
[[redirects]]
  from = "/"
  to = "/social-listening.html"
  status = 200

# Header di sicurezza di base su tutte le risposte.
[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "SAMEORIGIN"
    X-Content-Type-Options = "nosniff"
    Referrer-Policy = "strict-origin-when-cross-origin"
```

### 3.2 `netlify/edge-functions/auth.js`

> Le voci da personalizzare per progetto sono indicate con `⚙️` (vedi anche sezione 5).

```js
// Protezione con password condivisa per un sito statico.
// Gira su OGNI richiesta (config.path = "/*"): finché non ci si autentica,
// il contenuto reale non viene mai servito, viene mostrata la pagina di login.
//
// La password NON è nel codice: va impostata su Netlify come variabile
// d'ambiente SITE_PASSWORD (Site settings → Environment variables).

const COOKIE_NAME = "rnd_session";                 // ⚙️ nome cookie (cambialo per progetto)
const SESSION_TTL = 60 * 60 * 12;                  // ⚙️ durata sessione: 12 ore (in secondi)
const TOKEN_MSG = "randstad-social-listening";     // ⚙️ "dominio" della firma (stringa unica per progetto)

// ── Firma HMAC-SHA256 (usa la password come chiave: se cambi password, le sessioni scadono) ──
async function hmac(key, msg) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// Confronto a tempo costante per non esporre informazioni tramite i tempi di risposta.
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function now() {
  return Math.floor(Date.now() / 1000);
}

async function makeToken(password) {
  const exp = now() + SESSION_TTL;
  const sig = await hmac(password, `${TOKEN_MSG}:${exp}`);
  return `${exp}.${sig}`;
}

async function verifyToken(token, password) {
  if (!token) return false;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return false;
  const exp = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp)) return false;
  if (parseInt(exp, 10) < now()) return false; // sessione scaduta
  const expected = await hmac(password, `${TOKEN_MSG}:${exp}`);
  return safeEqual(sig, expected);
}

function readCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

function loginPage(error) {
  const errorHtml = error
    ? `<p class="err">${error}</p>`
    : "";
  // ⚙️ Personalizza testi/colori qui sotto per il tuo progetto.
  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Accesso riservato</title>
<link rel="preconnect" href="https://fonts.googleapis.com/">
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Figtree',system-ui,sans-serif;background:#191919;color:#191919;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{background:#fff;border-radius:12px;width:100%;max-width:380px;padding:40px 36px;
        box-shadow:0 20px 60px rgba(0,0,0,.35);border-top:4px solid #E52217}
  .eyebrow{font-size:10px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;
           color:#E52217;margin-bottom:10px}
  h1{font-size:22px;font-weight:800;color:#191919;line-height:1.2;margin-bottom:6px}
  p.sub{font-size:13px;color:#595959;margin-bottom:26px;line-height:1.5}
  label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;
        letter-spacing:.06em;color:#595959;margin-bottom:8px}
  input{width:100%;padding:13px 14px;font-size:15px;font-family:inherit;
        border:1px solid #d9dbde;border-radius:8px;background:#f7f8f9;transition:border .15s,background .15s}
  input:focus{outline:none;border-color:#E52217;background:#fff}
  button{width:100%;margin-top:18px;padding:13px;font-size:14px;font-weight:700;
         font-family:inherit;color:#fff;background:#E52217;border:none;border-radius:8px;
         cursor:pointer;text-transform:uppercase;letter-spacing:.04em;transition:background .15s}
  button:hover{background:#c41c12}
  .err{background:#FFE7E6;color:#c41c12;font-size:12.5px;font-weight:600;
       padding:10px 12px;border-radius:8px;margin-bottom:18px}
  .foot{margin-top:22px;font-size:11px;color:#9aa0a6;text-align:center;line-height:1.5}
</style>
</head>
<body>
  <form class="card" method="POST" action="/__login" autocomplete="off">
    <div class="eyebrow">Area riservata</div>
    <h1>Accesso riservato</h1>
    <p class="sub">Questo contenuto è privato. Inserisci la password per accedere.</p>
    ${errorHtml}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required autofocus placeholder="••••••••">
    <button type="submit">Accedi</button>
    <div class="foot">Accesso protetto · dati riservati</div>
  </form>
</body>
</html>`;
}

function htmlResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export default async (request, context) => {
  const password = Deno.env.get("SITE_PASSWORD");
  const url = new URL(request.url);

  // Password non ancora configurata: messaggio esplicito (nessun accesso possibile).
  if (!password) {
    return htmlResponse(
      loginPage(
        "Configurazione incompleta: la variabile d'ambiente SITE_PASSWORD non è impostata su Netlify.",
      ),
      500,
    );
  }

  // ── Logout ──
  if (url.pathname === "/__logout") {
    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      },
    });
  }

  // ── Invio del form di login ──
  if (request.method === "POST" && url.pathname === "/__login") {
    let submitted = "";
    try {
      const form = await request.formData();
      submitted = String(form.get("password") || "");
    } catch (_) {
      submitted = "";
    }
    if (safeEqual(submitted, password)) {
      const token = await makeToken(password);
      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/",
          "Set-Cookie": `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}`,
        },
      });
    }
    return htmlResponse(loginPage("Password errata. Riprova."), 401);
  }

  // ── Sessione già valida → mostra il contenuto reale ──
  const token = readCookie(request, COOKIE_NAME);
  if (await verifyToken(token, password)) {
    return context.next();
  }

  // ── Non autenticato → schermata di login ──
  return htmlResponse(loginPage(), 401);
};

export const config = { path: "/*" };
```

---

## 4. Deploy su Netlify (passo per passo)

1. Netlify → **Add new site → Import an existing project → Deploy with GitHub**.
2. Seleziona il repository desiderato.
3. **Branch to deploy** → scegli il branch (es. `main`).
4. **Base directory** → **vuoto**. **Build command** → **vuoto**. **Publish directory** → `.`
   (di norma già compilati da `netlify.toml`).
5. Clicca **Deploy**.
   👉 Al primo deploy vedrai l’avviso *“SITE_PASSWORD non impostata”*: è **normale**, manca la password.
6. **Site configuration → Environment variables → Add a variable**
   - **Key**: `SITE_PASSWORD`
   - **Value**: *(la password che scegli tu, robusta)*
   - **Scopes**: *All scopes / All contexts*
7. **Deploys → Trigger deploy → Clear cache and deploy site**.
8. Apri l’URL del sito: comparirà la **schermata di login**; con la password corretta → il contenuto. ✅

Da qui in poi ogni `git push` sul branch collegato aggiorna il sito **automaticamente**.

---

## 5. Adattamenti per una nuova repo (checklist)

Copia i due file (`netlify.toml`, `netlify/edge-functions/auth.js`) nella nuova repo e modifica:

- [ ] **`netlify.toml` → blocco `[[redirects]]`**: cambia `to = "/il-tuo-file.html"` con il nome del
      tuo file principale. **Se hai già un `index.html` nella root**, puoi **eliminare l’intero blocco
      `[[redirects]]`** (Netlify serve `index.html` da solo).
- [ ] **`auth.js → COOKIE_NAME`**: metti un nome diverso (es. `"acme_session"`), così progetti diversi
      non si sovrappongono se ospitati sullo stesso dominio.
- [ ] **`auth.js → TOKEN_MSG`**: stringa unica per progetto (es. `"acme-report-2026"`).
- [ ] **`auth.js → SESSION_TTL`**: durata sessione (es. `60 * 60 * 24 * 7` = 7 giorni).
- [ ] **`auth.js → loginPage()`**: testi, titolo e colori (`#E52217` ecc.) per il brand del progetto.
- [ ] Su Netlify: imposta **`SITE_PASSWORD`** (per ogni sito la sua) + **redeploy**.

Se la repo ha **più file/sottocartelle**, non serve altro: `path = "/*"` protegge tutto.

---

## 6. ⚠️ Problema frequente: “No results found” nel menu Branch

Se nel passo di import il menu **“Branch to deploy”** è vuoto / mostra *“No results found”*,
**non è un problema del codice**: l’app Netlify non ha accesso al repository su GitHub
(tipico con repo di **organizzazioni**). Fix:

1. GitHub → **foto profilo → Settings**
2. **Applications → Installed GitHub Apps → Netlify → Configure**
3. Se l’app è su più account, scegli **l’organizzazione** proprietaria del repo
4. **Repository access** → **All repositories**, oppure **Only select repositories** e aggiungi il repo
5. **Save** (se non sei owner dell’organizzazione, GitHub crea una **richiesta** da far approvare a un admin)
6. Torna su Netlify, **ricarica**: i branch ora compaiono.

---

## 7. Gestione ordinaria

- **Cambiare password**: aggiorna `SITE_PASSWORD` su Netlify → **redeploy**.
  (Cambiando la password, tutte le sessioni attive vengono invalidate.)
- **Logout**: visita `/__logout`.
- **Aggiornare il contenuto**: modifica i file → `git push` sul branch collegato → deploy automatico.
- **Durata sessione**: costante `SESSION_TTL` in `auth.js`.

---

## 8. Verifica di sicurezza (test rapido)

1. In finestra anonima, apri l’URL → deve comparire **il login**, non il contenuto.
2. Prova ad aprire direttamente il file (es. `.../social-listening.html`) → deve comparire **il login**
   (il contenuto NON deve essere restituito).
3. Inserisci la password → vedi il contenuto.
4. Vai su `/__logout` → torni al login.

Se tutti e 4 i punti passano, la protezione è attiva correttamente.

---

## 9. Note e limiti

- È una **password condivisa** (uguale per tutti): niente utenti/tracciamento individuale.
  Se in futuro serve chi‑ha‑fatto‑cosa, valutare **Netlify Identity** o un IdP (Google/Microsoft SSO).
- Il cookie di sessione, se sottratto, è riutilizzabile fino alla scadenza (come ogni sessione web):
  mitigato da `HttpOnly` + `Secure` + `SameSite=Lax`.
- La protezione nativa di Netlify (password a livello di sito, zero codice) esiste ma richiede un
  **piano a pagamento**; questa ricetta ottiene lo stesso risultato **gratis**.
