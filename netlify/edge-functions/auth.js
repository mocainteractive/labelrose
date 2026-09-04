// Protezione con password condivisa per il report statico "Label Rose Deep-Dive".
// Gira su OGNI richiesta (config.path = "/*"): finché non ci si autentica,
// il contenuto reale non viene mai servito, viene mostrata la pagina di login.
//
// La password NON è nel codice: va impostata su Netlify come variabile
// d'ambiente SITE_PASSWORD (Site configuration → Environment variables).

const COOKIE_NAME = "labelrose_session";            // nome cookie (specifico di questo progetto)
const SESSION_TTL = 60 * 60 * 24 * 7;               // durata sessione: 7 giorni (in secondi)
const TOKEN_MSG = "label-rose-deepdive-mag-lug-2026"; // "dominio" della firma (stringa unica per progetto)

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
  const errorHtml = error ? `<p class="err">${error}</p>` : "";
  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Label Rose Deep-Dive · Accesso riservato</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Figtree',system-ui,-apple-system,sans-serif;background:#191919;color:#191919;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{background:#FFFFFF;border-radius:12px;width:100%;max-width:380px;padding:40px 36px;
        box-shadow:0 20px 60px rgba(0,0,0,.35);border-top:4px solid #FF2619}
  .eyebrow{font-size:10px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;
           color:#FF2619;margin-bottom:10px}
  h1{font-size:22px;font-weight:800;letter-spacing:-.03em;color:#191919;line-height:1.15;margin-bottom:6px}
  p.sub{font-size:13px;color:#757575;margin-bottom:26px;line-height:1.5}
  label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;
        letter-spacing:.06em;color:#757575;margin-bottom:8px}
  input{width:100%;padding:13px 14px;font-size:15px;font-family:inherit;color:#191919;
        border:1px solid #DBDBDB;border-radius:8px;background:#F4F5F6;transition:border .15s,background .15s}
  input:focus{outline:none;border-color:#FF2619;background:#FFFFFF}
  button{width:100%;margin-top:18px;padding:13px;font-size:14px;font-weight:700;
         font-family:inherit;color:#FFFFFF;background:#FF2619;border:none;border-radius:8px;
         cursor:pointer;text-transform:uppercase;letter-spacing:.04em;transition:background .15s}
  button:hover{background:#C21A10}
  .err{background:#FFE7E6;color:#C21A10;font-size:12.5px;font-weight:600;
       padding:10px 12px;border-radius:8px;margin-bottom:18px}
  .foot{margin-top:22px;font-size:11px;color:#8A8A8A;text-align:center;line-height:1.5}
</style>
</head>
<body>
  <form class="card" method="POST" action="/__login" autocomplete="off">
    <div class="eyebrow">Area riservata</div>
    <h1>Label Rose Deep-Dive<span style="color:#FF2619">.</span></h1>
    <p class="sub">Report riservato Mag–Lug 2026. Inserisci la password per accedere.</p>
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
