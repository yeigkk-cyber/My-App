const encoder = new TextEncoder();
const ITERATIONS = 20000;
const SESSION_SECONDS = 12 * 60 * 60;

function b64(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary);
}
function unb64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
function b64url(bytes) {
  return b64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function fromB64url(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  return unb64(base64 + "=".repeat((4 - base64.length % 4) % 4));
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
function cookie(request, value, maxAge) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `fabric_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}
async function derive(code, salt, iterations = ITERATIONS) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations }, key, 256);
}
function supabaseConfigured(env) {
  const hasUrl = !!env.SUPABASE_URL;
  const hasKey = !!(env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY);
  if (hasUrl !== hasKey) throw new Error("Set both SUPABASE_URL and SUPABASE_SECRET_KEY.");
  return hasUrl;
}
async function supabaseRequest(env, table, query = "", { method = "GET", body, prefer } = {}) {
  const key = env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY;
  const headers = { apikey: key, Accept: "application/json" };
  // New sb_secret keys are API keys, not JWTs. Legacy service_role keys are JWTs.
  if (!key.startsWith("sb_secret_")) headers.Authorization = `Bearer ${key}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (prefer) headers.Prefer = prefer;
  const response = await fetch(`${env.SUPABASE_URL.replace(/\/+$/, "")}/rest/v1/${table}${query ? `?${query}` : ""}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    console.error("Supabase database request failed", table, response.status);
    throw new Error(`supabase_http_${response.status}`);
  }
  if (response.status === 204) return null;
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}
function sbQuery(values) { return new URLSearchParams(values).toString(); }
async function supabaseUpsert(env, table, rows, conflict = "id", resolution = "merge-duplicates") {
  if (!rows.length) return;
  await supabaseRequest(env, table, sbQuery({ on_conflict: conflict }), {
    method: "POST", body: rows, prefer: `resolution=${resolution},return=minimal`,
  });
}
async function loadAuth(env) {
  if (supabaseConfigured(env)) {
    const query = sbQuery({ select: "value", key: "eq.auth", limit: "1" });
    let rows = await supabaseRequest(env, "app_settings", query);
    if (rows.length) return rows[0].value;
    const code = env.FABRIC_LOGIN_CODE || "";
    if (code.length < 6 || code.length > 128) throw new Error("Set FABRIC_LOGIN_CODE to a code of 6-128 characters.");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const auth = { salt: b64(salt), hash: b64(await derive(code, b64(salt))), iterations: ITERATIONS, signingKey: b64(crypto.getRandomValues(new Uint8Array(32))) };
    await supabaseUpsert(env, "app_settings", [{ key: "auth", value: auth }], "key", "ignore-duplicates");
    rows = await supabaseRequest(env, "app_settings", query);
    if (!rows.length) throw new Error("Supabase auth settings were not created.");
    return rows[0].value;
  }
  let row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'auth'").first();
  if (row) return JSON.parse(row.value);
  const code = env.FABRIC_LOGIN_CODE || "";
  if (code.length < 6 || code.length > 128) throw new Error("Set FABRIC_LOGIN_CODE to a code of 6-128 characters.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const auth = {
    salt: b64(salt),
    hash: b64(await derive(code, b64(salt))),
    iterations: ITERATIONS,
    signingKey: b64(crypto.getRandomValues(new Uint8Array(32))),
  };
  await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('auth', ?)").bind(JSON.stringify(auth)).run();
  row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'auth'").first();
  return JSON.parse(row.value);
}
async function writeAuth(env, auth) {
  if (supabaseConfigured(env)) return supabaseUpsert(env, "app_settings", [{ key: "auth", value: auth }], "key");
  return env.DB.prepare("UPDATE settings SET value = ? WHERE key = 'auth'").bind(JSON.stringify(auth)).run();
}
async function sign(value, auth) {
  const key = await crypto.subtle.importKey("raw", unb64(auth.signingKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}
async function session(request, env, auth) {
  const raw = (request.headers.get("Cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith("fabric_session="))?.slice(15);
  if (!raw) return false;
  const [body, signature] = raw.split(".");
  if (!body || !signature) return false;
  const expected = await sign(body, auth);
  if (signature !== expected) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(body)));
    return payload.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
async function issueSession(request, auth) {
  const body = b64url(encoder.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS, nonce: b64url(crypto.getRandomValues(new Uint8Array(18))) })));
  return cookie(request, `${body}.${await sign(body, auth)}`, SESSION_SECONDS);
}
async function readBody(request, limit = 25_000_000) {
  const text = await request.text();
  if (text.length > limit) throw new Error("request_too_large");
  return JSON.parse(text);
}
async function readData(env) {
  if (supabaseConfigured(env)) {
    const [itemRows, historyRows, deletedRows] = await Promise.all([
      supabaseRequest(env, "app_items", "select=payload"),
      supabaseRequest(env, "app_history", "select=payload"),
      supabaseRequest(env, "app_deleted_ids", "select=id"),
    ]);
    const deletedIds = deletedRows.map(x => x.id);
    const deleted = new Set(deletedIds);
    return {
      items: itemRows.map(x => x.payload).filter(x => x && !deleted.has(String(x.id))),
      history: historyRows.map(x => x.payload).filter(Boolean),
      deletedIds,
    };
  }
  const [itemRows, historyRows, deletedRows] = await Promise.all([
    env.DB.prepare("SELECT payload FROM items").all(),
    env.DB.prepare("SELECT payload FROM history").all(),
    env.DB.prepare("SELECT id FROM deleted_ids").all(),
  ]);
  return {
    items: itemRows.results.map(x => JSON.parse(x.payload)),
    history: historyRows.results.map(x => JSON.parse(x.payload)),
    deletedIds: deletedRows.results.map(x => x.id),
  };
}
async function batchChunks(env, statements, size = 80) {
  for (let i = 0; i < statements.length; i += size) await env.DB.batch(statements.slice(i, i + size));
}
async function mergeData(env, incoming) {
  if (supabaseConfigured(env)) {
    const current = await readData(env);
    const tombstones = [...new Set([...current.deletedIds, ...(Array.isArray(incoming.deletedIds) ? incoming.deletedIds : [])].map(String))];
    const deleted = new Set(tombstones);
    const items = new Map(current.items.map(x => [String(x.id), x]));
    for (const item of Array.isArray(incoming.items) ? incoming.items : []) {
      if (item?.id != null && !deleted.has(String(item.id))) items.set(String(item.id), item);
    }
    const history = new Map(current.history.map(x => [String(x.id), x]));
    for (const entry of Array.isArray(incoming.history) ? incoming.history : []) {
      if (entry?.id != null) history.set(String(entry.id), entry);
    }
    const itemRows = [...items.values()].map(payload => ({ id: String(payload.id), payload }));
    const historyRows = [...history.values()].map(payload => ({ id: String(payload.id), payload }));
    // Save incoming rows first. If a later request fails during a replacement,
    // the previous catalog remains visible until all new rows have been stored.
    for (let i = 0; i < itemRows.length; i += 100) await supabaseUpsert(env, "app_items", itemRows.slice(i, i + 100));
    for (let i = 0; i < historyRows.length; i += 100) await supabaseUpsert(env, "app_history", historyRows.slice(i, i + 100));
    for (let i = 0; i < tombstones.length; i += 200) {
      await supabaseUpsert(env, "app_deleted_ids", tombstones.slice(i, i + 200).map(id => ({ id })), "id");
    }
    return readData(env);
  }
  const tombstones = [...new Set((Array.isArray(incoming.deletedIds) ? incoming.deletedIds : []).map(String))];
  const statements = [];
  for (const item of Array.isArray(incoming.items) ? incoming.items : []) {
    if (!item || item.id == null || tombstones.includes(String(item.id))) continue;
    statements.push(env.DB.prepare("INSERT INTO items (id, payload) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET payload = excluded.payload").bind(String(item.id), JSON.stringify(item)));
  }
  for (const entry of Array.isArray(incoming.history) ? incoming.history : []) {
    if (!entry || entry.id == null) continue;
    statements.push(env.DB.prepare("INSERT INTO history (id, payload) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET payload = excluded.payload").bind(String(entry.id), JSON.stringify(entry)));
  }
  // In replacement mode, write new item/history rows before hiding old ids.
  for (const id of tombstones) statements.push(env.DB.prepare("INSERT OR IGNORE INTO deleted_ids (id) VALUES (?)").bind(id));
  for (const id of tombstones) statements.push(env.DB.prepare("DELETE FROM items WHERE id = ?").bind(id));
  await batchChunks(env, statements);
  return readData(env);
}
async function clearExpiredAttempts(env, cutoff) {
  if (supabaseConfigured(env)) {
    return supabaseRequest(env, "app_login_attempts", sbQuery({ created_at: `lt.${cutoff}` }), { method: "DELETE", prefer: "return=minimal" });
  }
  return env.DB.prepare("DELETE FROM login_attempts WHERE created_at < ?").bind(cutoff).run();
}
async function countAttempts(env, ip, cutoff) {
  if (supabaseConfigured(env)) {
    const rows = await supabaseRequest(env, "app_login_attempts", sbQuery({ select: "id", ip: `eq.${ip}`, created_at: `gte.${cutoff}` }));
    return rows.length;
  }
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND created_at >= ?").bind(ip, cutoff).first();
  return row.n;
}
async function recordAttempt(env, ip) {
  if (supabaseConfigured(env)) return supabaseRequest(env, "app_login_attempts", "", { method: "POST", body: { ip, created_at: Math.floor(Date.now() / 1000) }, prefer: "return=minimal" });
  return env.DB.prepare("INSERT INTO login_attempts (ip, created_at) VALUES (?, ?)").bind(ip, Math.floor(Date.now() / 1000)).run();
}
async function clearAttempts(env, ip) {
  if (supabaseConfigured(env)) return supabaseRequest(env, "app_login_attempts", sbQuery({ ip: `eq.${ip}` }), { method: "DELETE", prefer: "return=minimal" });
  return env.DB.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(ip).run();
}
async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (path === "/api/health" && request.method === "GET") return json({ ok: true });
  let auth;
  try { auth = await loadAuth(env); }
  catch (error) { return json({ error: "login_not_configured" }, 503); }
  const authenticated = await session(request, env, auth);
  if (path === "/api/auth/status" && request.method === "GET") return json({ authenticated });
  if (path === "/api/auth/login" && request.method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const cutoff = Math.floor(Date.now() / 1000) - 900;
    await clearExpiredAttempts(env, cutoff);
    if (await countAttempts(env, ip, cutoff) >= 8) return json({ error: "too_many_attempts" }, 429, { "Retry-After": "900" });
    let code;
    try { code = String((await readBody(request, 4096)).code || ""); } catch { return json({ error: "invalid_request" }, 400); }
    if (code.length > 128) return json({ error: "invalid_code" }, 401);
    const candidate = await derive(code, auth.salt, auth.iterations);
    // Use a constant-time byte comparison for the PBKDF2 result.
    let same = candidate.byteLength === unb64(auth.hash).byteLength;
    if (same) { const a = new Uint8Array(candidate), b = unb64(auth.hash); let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]; same = diff === 0; }
    if (!same) {
      await recordAttempt(env, ip);
      return json({ error: "invalid_code" }, 401);
    }
    await clearAttempts(env, ip);
    return json({ ok: true }, 200, { "Set-Cookie": await issueSession(request, auth) });
  }
  if (path === "/api/auth/logout" && request.method === "POST") return json({ ok: true }, 200, { "Set-Cookie": cookie(request, "", 0) });
  if (path === "/api/auth/change-code" && request.method === "POST") {
    if (!authenticated) return json({ error: "unauthorized" }, 401);
    let code;
    try { code = String((await readBody(request, 4096)).newCode || ""); } catch { return json({ error: "invalid_request" }, 400); }
    if (code.length < 6 || code.length > 128) return json({ error: "code_length" }, 400);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    auth.salt = b64(salt);
    auth.hash = b64(await derive(code, auth.salt));
    auth.iterations = ITERATIONS;
    auth.signingKey = b64(crypto.getRandomValues(new Uint8Array(32)));
    await writeAuth(env, auth);
    return json({ ok: true }, 200, { "Set-Cookie": await issueSession(request, auth) });
  }
  if (path === "/api/data" && request.method === "GET") return authenticated ? json(await readData(env)) : json({ error: "unauthorized" }, 401);
  if (path === "/api/data" && request.method === "POST") {
    if (!authenticated) return json({ error: "unauthorized" }, 401);
    try {
      const data = await readBody(request);
      if (!data || typeof data !== "object" || Array.isArray(data)) return json({ error: "invalid_data" }, 400);
      return json(await mergeData(env, data));
    } catch (error) { return json({ error: "invalid_request" }, 400); }
  }
  return json({ error: "not_found" }, 404);
}
export default { fetch: handle };
