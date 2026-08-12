// FiveM Item List - backend s autentizací.
// Záměrně bez externích npm závislostí - běží na čistém Node.js (18+).
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const { loadEnv } = require("./lib/env");
const { verifyPassword } = require("./lib/password");

loadEnv();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const DATA_FILE = path.join(__dirname, "data", "items.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
  console.error(
    "Chybí ADMIN_USERNAME nebo ADMIN_PASSWORD_HASH v .env souboru.\n" +
    "Zkopíruj .env.example na .env, případně si vygeneruj vlastní hash heslem:\n" +
    "  npm run hash-password -- \"tvoje_heslo\"\n"
  );
  process.exit(1);
}

const VALID_CATEGORIES = ["auta", "drogy", "zbrane", "itemy", "jidlo", "obleceni", "ostatni"];

// ---------------------------------------------------------------------------
// In-memory session store: sid -> { username, expiresAt }
// ---------------------------------------------------------------------------
const sessions = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hodin

function createSession(username) {
  const sid = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, { username, expiresAt: Date.now() + SESSION_TTL_MS });
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
// Item storage (JSON soubor)
// ---------------------------------------------------------------------------
function readItems() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  } catch (err) {
    return [];
  }
}

function writeItems(items) {
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

  const usernameMatches = username === ADMIN_USERNAME;
  const passwordMatches = verifyPassword(password, ADMIN_PASSWORD_HASH);

  if (!usernameMatches || !passwordMatches) {
    return sendJson(res, 401, { error: "Nesprávné uživatelské jméno nebo heslo." });
  }

  const sid = createSession(username);
  setSessionCookie(res, sid);
  sendJson(res, 200, { ok: true, username });
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
    return sendJson(res, 200, { authenticated: true, username: session.username });
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

function handleGetItems(req, res) {
  if (!requireAuth(req, res)) return;
  sendJson(res, 200, readItems());
}

async function handlePostItem(req, res) {
  if (!requireAuth(req, res)) return;
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

  const items = readItems();
  const item = { id: newId(), name: name.trim(), code: code.trim(), category: cat };
  items.push(item);
  writeItems(items);
  sendJson(res, 201, item);
}

async function handlePutItem(req, res, id) {
  if (!requireAuth(req, res)) return;
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: "Neplatný požadavek." });
  }
  const items = readItems();
  const idx = items.findIndex((i) => i.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Item nenalezen." });

  const { name, code, category } = body || {};
  if (name && typeof name === "string" && name.trim()) items[idx].name = name.trim();
  if (code && typeof code === "string" && code.trim()) items[idx].code = code.trim();
  if (category && VALID_CATEGORIES.includes(category)) items[idx].category = category;

  writeItems(items);
  sendJson(res, 200, items[idx]);
}

function handleDeleteItem(req, res, id) {
  if (!requireAuth(req, res)) return;
  const items = readItems();
  const idx = items.findIndex((i) => i.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Item nenalezen." });
  const [removed] = items.splice(idx, 1);
  writeItems(items);
  sendJson(res, 200, removed);
}

async function handleImport(req, res) {
  if (!requireAuth(req, res)) return;
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

  const regex = /\[["']([a-zA-Z0-9_\-]+)["']\]\s*=\s*\{([^}]*)\}/g;
  const items = readItems();
  let added = 0;
  let match;
  while ((match = regex.exec(lua)) !== null) {
    const code = match[1];
    const bodyMatch = match[2];
    const labelMatch = bodyMatch.match(/label\s*=\s*["']([^"']+)["']/);
    const name = labelMatch ? labelMatch[1] : code;
    items.push({ id: newId(), name, code, category: cat });
    added++;
  }

  if (added > 0) writeItems(items);
  sendJson(res, 200, { added });
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
      return handleGetItems(req, res);
    }
    if (pathname === "/api/items" && req.method === "POST") {
      return await handlePostItem(req, res);
    }
    if (pathname === "/api/items/import" && req.method === "POST") {
      return await handleImport(req, res);
    }
    const itemMatch = pathname.match(/^\/api\/items\/([a-f0-9]+)$/);
    if (itemMatch && req.method === "PUT") {
      return await handlePutItem(req, res, itemMatch[1]);
    }
    if (itemMatch && req.method === "DELETE") {
      return handleDeleteItem(req, res, itemMatch[1]);
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

server.listen(PORT, () => {
  console.log(`FiveM Item List backend běží na http://localhost:${PORT}`);
});
