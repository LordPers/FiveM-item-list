# FiveM Item List — backend s autentizací

Samostatný web (FiveM item katalog) s reálným backendem: přihlášení chráněné
heslem, session cookie, a itemy uložené na serveru (přežijí refresh i restart
prohlížeče). Žádné externí npm závislosti — běží na čistém Node.js.

## Spuštění

Vyžaduje Node.js 18 nebo novější (žádné `npm install` není potřeba).

```bash
node server.js
```

Server poběží na `http://localhost:3000`. Přihlašovací údaje jsou
předvyplněné v `.env`:

- Uživatelské jméno: `admin`
- Heslo: `admin1234`

## Změna hesla

Heslo se nikde neukládá v čitelné podobě — v `.env` je jen jeho hash
(scrypt, vestavěný Node modul `crypto`). Pro změnu hesla vygeneruj nový hash:

```bash
node scripts/hash-password.js "nove_heslo"
```

Výstup (`ADMIN_PASSWORD_HASH=...`) zkopíruj do `.env` a restartuj server.
Uživatelské jméno změníš přímo úpravou `ADMIN_USERNAME` v `.env`.

## Jak to funguje

- **Přihlášení** (`POST /api/login`) ověří jméno a heslo (scrypt hash +
  `timingSafeEqual`), vytvoří session a pošle ji jako `HttpOnly` cookie.
  Session žije 24 hodin a je uložená v paměti serveru (viz Omezení níže).
- **Middleware** kontroluje session cookie na všech `/api/items*` routách —
  bez přihlášení dostaneš `401`.
- **Rate limiting** na `/api/login` (max 20 pokusů / 15 minut na IP) proti
  hrubému forcování hesla.
- **Itemy** se ukládají do `data/items.json` na disku — přidávání, mazání
  i import z Lua tabulky (`["code"] = { label = "Název" }`) rovnou zapisují
  do souboru.
- **Frontend** (`public/index.html`) je stejný vzhled jako předchozí
  statická verze, ale místo dat v paměti prohlížeče volá tohle API přes
  `fetch`.

## Nasazení mimo localhost

Tenhle server je "vanilla" Node http server, takže půjde nasadit prakticky
kamkoli, kde běží Node.js — např. Render, Railway, Fly.io, VPS, nebo za
reverzní proxy (nginx/Caddy). Před ostrým nasazením:

1. V `.env` nastav `NODE_ENV=production` — zapne se `Secure` flag na cookie
   (vyžaduje HTTPS).
2. Vygeneruj si vlastní silné heslo (viz výše) — needěl bys nechávat
   `admin1234` na veřejně dostupném serveru.
3. Zvaž reálnou databázi (Postgres/SQLite) místo `data/items.json`, pokud
   očekáváš víc současných zápisů nebo běh na více instancích zároveň.

## Omezení této verze (co říct, než to nasadíš "na ostro")

- **Session store je jen v paměti procesu.** Restart serveru odhlásí
  všechny uživatele. Pro provoz na víc instancích (load balancing) by bylo
  potřeba sdílené úložiště session (Redis apod.).
- **Jeden uživatelský účet** (`admin`). Není tu registrace ani víc účtů —
  pokud to budeš chtít, dá se to doplnit.
- **`data/items.json` jako úložiště** je v pořádku pro tenhle rozsah dat,
  ale u vyššího provozu / souběžných zápisů je lepší přejít na databázi.
- Frontend pořád obsahuje jen ukázková data z tvého screenshotu (20 itemů),
  zbytek doplníš přes „Přidat item“ nebo „Import .lua“.

## Struktura projektu

```
fivem-backend/
  server.js           # HTTP server + routování + API
  lib/
    env.js             # jednoduchý .env loader
    password.js         # hashování hesel (scrypt)
  scripts/
    hash-password.js    # CLI pro vygenerování nového hashe hesla
  data/
    items.json           # uložené itemy (čte/zapisuje server)
  public/
    index.html            # frontend (přihlášení + katalog)
  .env                    # přihlašovací údaje a konfigurace (lokální)
  .env.example            # šablona pro .env
```
