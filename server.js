// FiveM Item List - backend s autentizací.
// Žádné externí npm závislosti kromě "pg" (jen když se použije Postgres/Neon
// pro trvalé úložiště - viz níže). Jinak čistý Node.js (18+).
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const { loadEnv } = require("./lib/env");
const { verifyPassword } = require("./lib/password");

loadEnv();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

// ---------------------------------------------------------------------------
// Úložiště itemů - dva možné režimy:
//
// 1) DATABASE_URL nastavená (Postgres, např. free Neon databáze) - itemy se
//    ukládají do tabulky "items". Tohle přežije restart/redeploy/uspání
//    Render služby i na free plánu, protože data nejsou na disku Renderu.
//
// 2) DATABASE_URL nenastavená - itemy se ukládají do JSON souboru na disku
//    (DATA_DIR, výchozí "data/items.json"). Lokálně to funguje normálně, ale
//    na Renderu free plánu tahle složka NENÍ trvalá - při každém
//    redeployi/restartu/uspání služby se smaže a nahradí verzí z GitHubu.
//    Aby data přežila restart bez databáze, je potřeba na Renderu připojit
//    Persistent Disk (vyžaduje placený plán) a nastavit DATA_DIR na jeho
//    mount path (např. /var/data).
// ---------------------------------------------------------------------------
const DATABASE_URL = process.env.DATABASE_URL;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "items.json");

let pool = null;
if (DATABASE_URL) {
  const { Pool } = require("pg");
  pool = new Pool({ connectionString: DATABASE_URL });
  pool.on("error", (err) => {
    // Chyba na nečinném klientovi v poolu (např. výpadek spojení při
    // uspání Neon databáze) - jen zalogovat, ne shodit celý server.
    console.error("Neočekávaná chyba PostgreSQL připojení:", err);
  });
}

// Když DATA_DIR ukazuje na čerstvý/prázdný Persistent Disk (žádný items.json
// tam ještě není), naplníme ho počátečními daty z repozitáře, ať appka
// nezačíná s prázdnou databází. Používá se jen v režimu souborového úložiště.
function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    const seedFile = path.join(__dirname, "data", "items.json");
    if (fs.existsSync(seedFile) && seedFile !== DATA_FILE) {
      fs.copyFileSync(seedFile, DATA_FILE);
    } else {
      fs.writeFileSync(DATA_FILE, "[]\n", "utf-8");
    }
  }
}

// Vytvoří tabulku "items" v Postgresu, pokud ještě neexistuje, a při prvním
// spuštění (prázdná tabulka) ji naplní stejnými počátečními daty jako
// souborový režim. Používá se jen v režimu Postgres.
async function ensureDbSchema() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      code TEXT NOT NULL,
      category TEXT NOT NULL
    )
  `);
  const { rows } = await pool.query("SELECT COUNT(*)::int AS count FROM items");
  if (rows[0].count === 0) {
    const seedFile = path.join(__dirname, "data", "items.json");
    if (fs.existsSync(seedFile)) {
      const seedItems = JSON.parse(fs.readFileSync(seedFile, "utf-8"));
      for (const item of seedItems) {
        await pool.query(
          "INSERT INTO items (id, name, code, category) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
          [item.id, item.name, item.code, item.category]
        );
      }
    }
  }
}

if (!pool) ensureDataFile();

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const DEVELOPER_USERNAME = process.env.DEVELOPER_USERNAME;
const DEVELOPER_PASSWORD_HASH = process.env.DEVELOPER_PASSWORD_HASH;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !DEVELOPER_USERNAME || !DEVELOPER_PASSWORD_HASH) {
  console.error(
    "Chybí ADMIN_USERNAME/ADMIN_PASSWORD_HASH nebo DEVELOPER_USERNAME/DEVELOPER_PASSWORD_HASH v .env souboru.\n" +
    "Zkopíruj .env.example na .env, případně si vygeneruj vlastní hash heslem:\n" +
    "  npm run hash-password -- \"tvoje_heslo\"\n"
  );
  process.exit(1);
}

// Dva účty se dvěma úrovněmi oprávnění:
//  - "viewer" (ADMIN_USERNAME/ADMIN_PASSWORD_HASH) - jen prohlížení, žádné úpravy.
//  - "admin"  (DEVELOPER_USERNAME/DEVELOPER_PASSWORD_HASH) - plná práva (přidávat/mazat/importovat).
const ACCOUNTS = {
  [ADMIN_USERNAME]: { passwordHash: ADMIN_PASSWORD_HASH, role: "viewer" },
  [DEVELOPER_USERNAME]: { passwordHash: DEVELOPER_PASSWORD_HASH, role: "admin" },
};

const VALID_CATEGORIES = ["auta", "drogy", "zbrane", "itemy", "jidlo", "obleceni", "joby", "ostatni"];

// ---------------------------------------------------------------------------
// In-memory session store: sid -> { username, expiresAt }
// ---------------------------------------------------------------------------
const sessions = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hodin

function createSession(username, role) {
  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, { username, role, expiresAt: Date.now() + SESSION_TTL_MS });
  return sid;
}

function getSession(sid) {
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return session;
}

function destroySession(sid) {
  if (sid) sessions.delete(sid);
}

// Průběžný úklid expirovaných session
setInterval(() => {
  const now = Date.now();
  for (const [sid, session] of sessions.entries()) {
    if (session.expiresAt < now) sessions.delete(sid);
  }
}, 60 * 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Rate limiting pro login (jednoduché in-memory sliding window per IP)
// ---------------------------------------------------------------------------
const loginAttempts = new Map(); // ip -> [timestamps]
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 20;

function isRateLimited(ip) {
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  attempts.push(now);
  loginAttempts.set(ip, attempts);
  return attempts.length > RATE_LIMIT_MAX;
}

// ---------------------------------------------------------------------------
// Item storage (Postgres, pokud je nastavená DATABASE_URL, jinak JSON soubor)
// ---------------------------------------------------------------------------
async function readItems() {
  if (pool) {
    const { rows } = await pool.query("SELECT id, name, code, category FROM items ORDER BY name");
    return rows;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  } catch (err) {
    return [];
  }
}

async function writeItems(items) {
  if (pool) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM items");
      for (const item of items) {
        await client.query(
          "INSERT INTO items (id, name, code, category) VALUES ($1, $2, $3, $4)",
          [item.id, item.name, item.code, item.category]
        );
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
    return;
  }
  fs.writeFileSync(DATA_FILE, JSON.stringify(items, null, 2), "utf-8");
}

function newId() {
  return crypto.randomBytes(6).toString("hex");
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    out[key] = decodeURIComponent(val);
  });
  return out;
}

function setSessionCookie(res, sid) {
  const parts = [
    `fivem_sid=${sid}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (IS_PRODUCTION) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = ["fivem_sid=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (IS_PRODUCTION) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

// ---------------------------------------------------------------------------
// Request body parsing
// ---------------------------------------------------------------------------
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let size = 0;
    const LIMIT = 1024 * 1024; // 1MB
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > LIMIT) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function getClientIp(req) {
  return req.socket.remoteAddress || "unknown";
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  return getSession(cookies.fivem_sid);
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function serveStatic(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === "/" ? "index.html" : pathname);

  // Zabránit path traversal mimo public/
  if (!filePath.startsWith(PUBLIC_DIR)) {
    filePath = path.join(PUBLIC_DIR, "index.html");
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      // SPA fallback -> index.html
      fs.readFile(path.join(PUBLIC_DIR, "index.html"), (err2, indexContent) => {
        if (err2) {
          res.writeHead(404);
          res.end("Not found");
          return;
        }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(indexContent);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
    res.end(content);
  });
}

// ---------------------------------------------------------------------------
// API route handlers
// ---------------------------------------------------------------------------
async function handleLogin(req, res) {
  const ip = getClientIp(req);
  if (isRateLimited(ip)) {
    return sendJson(res, 429, { error: "Příliš mnoho pokusů o přihlášení. Zkus to znovu za chvíli." });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }

  const { username, password } = body || {};
  if (!username || !password) {
    return sendJson(res, 400, { error: "Chybí uživatelské jméno nebo heslo." });
  }

  const account = ACCOUNTS[username];
  const passwordMatches = account ? verifyPassword(password, account.passwordHash) : false;

  if (!account || !passwordMatches) {
    return sendJson(res, 401, { error: "Nesprávné uživatelské jméno nebo heslo." });
  }

  const sid = createSession(username, account.role);
  setSessionCookie(res, sid);
  sendJson(res, 200, { ok: true, username, role: account.role });
}

function handleLogout(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  destroySession(cookies.fivem_sid);
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

function handleSession(req, res) {
  const session = getSessionFromRequest(req);
  if (session) {
    return sendJson(res, 200, { authenticated: true, username: session.username, role: session.role });
  }
  sendJson(res, 200, { authenticated: false });
}

function requireAuth(req, res) {
  const session = getSessionFromRequest(req);
  if (!session) {
    sendJson(res, 401, { error: "Nepřihlášen." });
    return null;
  }
  return session;
}

// Stejné jako requireAuth, navíc vyžaduje roli "admin" (plná práva).
// Účet "viewer" projde requireAuth (může si prohlížet), ale požadavky na
// úpravu dat (přidání/mazání/import) skrz tohle projdou jen s rolí "admin".
function requireWriteAuth(req, res) {
  const session = requireAuth(req, res);
  if (!session) return null;
  if (session.role !== "admin") {
    sendJson(res, 403, { error: "Tento účet má jen oprávnění k prohlížení." });
    return null;
  }
  return session;
}

async function handleGetItems(req, res) {
  if (!requireAuth(req, res)) return;
  sendJson(res, 200, await readItems());
}

async function handlePostItem(req, res) {
  if (!requireWriteAuth(req, res)) return;
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }
  const { name, code, category } = body || {};
  if (!name || typeof name !== "string" || !name.trim()) {
    return sendJson(res, 400, { error: "Chybí název." });
  }
  if (!code || typeof code !== "string" || !code.trim()) {
    return sendJson(res, 400, { error: "Chybí spawn kód." });
  }
  const cat = VALID_CATEGORIES.includes(category) ? category : "ostatni";

  const items = await readItems();
  const item = { id: newId(), name: name.trim(), code: code.trim(), category: cat };
  items.push(item);
  await writeItems(items);
  sendJson(res, 201, item);
}

async function handlePutItem(req, res, id) {
  if (!requireWriteAuth(req, res)) return;
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }
  const items = await readItems();
  const idx = items.findIndex((i) => i.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Item nenalezen." });

  const { name, code, category } = body || {};
  if (name && typeof name === "string" && name.trim()) items[idx].name = name.trim();
  if (code && typeof code === "string" && code.trim()) items[idx].code = code.trim();
  if (category && VALID_CATEGORIES.includes(category)) items[idx].category = category;

  await writeItems(items);
  sendJson(res, 200, items[idx]);
}

async function handleBulkDeleteItems(req, res) {
  if (!requireWriteAuth(req, res)) return;
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }
  const { ids } = body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return sendJson(res, 400, { error: "Chybí seznam ID ke smazání." });
  }
  const idSet = new Set(ids.map(String));
  const items = await readItems();
  const remaining = items.filter((i) => !idSet.has(i.id));
  const deleted = items.length - remaining.length;
  if (deleted > 0) await writeItems(remaining);
  sendJson(res, 200, { deleted });
}

async function handleDeleteItem(req, res, id) {
  if (!requireWriteAuth(req, res)) return;
  const items = await readItems();
  const idx = items.findIndex((i) => i.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Item nenalezen." });
  const [removed] = items.splice(idx, 1);
  await writeItems(items);
  sendJson(res, 200, removed);
}

// Rozpozná dva běžné formáty Lua tabulek s itemy/vozidly:
//
// Formát A - klíčovaný objekt (typicky qb-core/esx/ox_inventory shared items):
//   ["iron_pipe"] = { label = "Železná trubka", weight = 500 },
//
// Formát B - pole plochých objektů (typicky seznamy vozidel):
//   { name = "Asbo", brand = "Maxwell", model = "asbo", price = 8500, hash = `asbo` },
//
// Obě varianty hledáme jen v "plochých" blocích {...} bez vnořených složených
// závorek - díky tomu se korektně přeskočí obalové/kategorické tabulky jako
// Customize.Vehicles = { ['compacts'] = { ...vnořené vozy... }, ['coupes'] = {...} },
// které by jinak omylem vypadaly jako jeden item.
function parseLuaItems(lua) {
  const results = [];
  const seenCodes = new Set();

  function addResult(code, name) {
    if (!code) return;
    const key = String(code).toLowerCase();
    if (seenCodes.has(key)) return;
    seenCodes.add(key);
    results.push({ name: name ? String(name) : String(code), code: String(code) });
  }

  // Formát A
  const reA = /\[["']([a-zA-Z0-9_\-]+)["']\]\s*=\s*\{([^{}]*)\}/g;
  let m;
  while ((m = reA.exec(lua)) !== null) {
    const code = m[1];
    const body = m[2];
    const labelMatch = body.match(/(?:label|name)\s*=\s*["']([^"']+)["']/);
    addResult(code, labelMatch ? labelMatch[1] : code);
  }

  // Formát B
  const reB = /\{([^{}]*)\}/g;
  const fieldRe = /(\w+)\s*=\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`|(-?\d+\.?\d*))/g;
  while ((m = reB.exec(lua)) !== null) {
    const body = m[1];
    const fields = {};
    let f;
    fieldRe.lastIndex = 0;
    while ((f = fieldRe.exec(body)) !== null) {
      const key = f[1].toLowerCase();
      const value = f[2] !== undefined ? f[2] : f[3] !== undefined ? f[3] : f[4] !== undefined ? f[4] : f[5];
      fields[key] = value;
    }
    const code =
      fields.model || fields.spawn || fields.spawnname || fields.spawn_name ||
      fields.spawncode || fields.spawn_code || fields.code;
    if (!code) continue;
    const name = fields.label || fields.name || code;
    addResult(code, name);
  }

  return results;
}

async function handleImport(req, res) {
  if (!requireWriteAuth(req, res)) return;
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }
  const { lua, category } = body || {};
  if (!lua || typeof lua !== "string") {
    return sendJson(res, 400, { error: "Chybí Lua obsah." });
  }
  const cat = VALID_CATEGORIES.includes(category) ? category : "ostatni";

  const parsed = parseLuaItems(lua);
  const items = await readItems();
  const existingCodes = new Set(items.map((i) => i.code.toLowerCase()));
  let added = 0;
  let skippedDuplicates = 0;
  for (const p of parsed) {
    const key = p.code.toLowerCase();
    if (existingCodes.has(key)) {
      skippedDuplicates++;
      continue;
    }
    items.push({ id: newId(), name: p.name, code: p.code, category: cat });
    existingCodes.add(key);
    added++;
  }

  if (added > 0) await writeItems(items);
  sendJson(res, 200, { added, skippedDuplicates });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  try {
    if (pathname === "/api/login" && req.method === "POST") {
      return await handleLogin(req, res);
    }
    if (pathname === "/api/logout" && req.method === "POST") {
      return handleLogout(req, res);
    }
    if (pathname === "/api/session" && req.method === "GET") {
      return handleSession(req, res);
    }
    if (pathname === "/api/items" && req.method === "GET") {
      return await handleGetItems(req, res);
    }
    if (pathname === "/api/items" && req.method === "POST") {
      return await handlePostItem(req, res);
    }
    if (pathname === "/api/items/import" && req.method === "POST") {
      return await handleImport(req, res);
    }
    if (pathname === "/api/items/bulk-delete" && req.method === "POST") {
      return await handleBulkDeleteItems(req, res);
    }
    const itemMatch = pathname.match(/^\/api\/items\/([a-f0-9]+)$/);
    if (itemMatch && req.method === "PUT") {
      return await handlePutItem(req, res, itemMatch[1]);
    }
    if (itemMatch && req.method === "DELETE") {
      return await handleDeleteItem(req, res, itemMatch[1]);
    }
    if (pathname.startsWith("/api/")) {
      return sendJson(res, 404, { error: "Endpoint nenalezen." });
    }

    // Vše ostatní -> statické soubory frontendu
    return serveStatic(req, res, pathname);
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: "Interní chyba serveru." });
  }
});

ensureDbSchema()
  .then(() => {
    server.listen(PORT, () => {
      console.log(
        `FiveM Item List backend běží na http://localhost:${PORT}` +
        (pool ? " (úložiště: Postgres)" : " (úložiště: soubor)")
      );
    });
  })
  .catch((err) => {
    console.error("Nepodařilo se připravit databázi:", err);
    process.exit(1);
  });
