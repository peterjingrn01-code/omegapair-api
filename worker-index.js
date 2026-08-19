/**
 * ΩPair backend — Cloudflare Worker (v3)
 * Adds: friend requests, friends list, post visibility (public / friends-only)
 *
 * Wallet auth:
 *   POST /api/challenge   { publicKey }                    -> { nonce }
 *   POST /api/verify      { publicKey, nonce, signature }  -> { token, coord, handle }
 *
 * Email auth:
 *   POST /api/email/request-code  { email }                -> { ok: true }
 *   POST /api/email/verify-code   { email, code }           -> { token, coord, handle }
 *
 * Session:
 *   GET  /api/me   (Authorization: Bearer <token>)          -> { handle, coord }
 *
 * Posts:
 *   GET  /api/posts                         (auth optional) -> { posts: [...] }
 *   POST /api/posts     { text, visibility } (auth required) -> { post }
 *   POST /api/posts/:id/like                 (auth required) -> { likes }
 *
 * Friends:
 *   GET  /api/users/search?handle=xxx        (auth required) -> { users: [...] }
 *   POST /api/friends/request  { handle }    (auth required) -> { ok: true }
 *   POST /api/friends/respond  { requestId, action }         -> { ok: true }
 *   GET  /api/friends                        (auth required) -> { friends: [...] }
 *   GET  /api/friends/requests               (auth required) -> { requests: [...] }
 *
 * Bindings required: DB (D1)
 * Secrets required:  SESSION_SECRET, RESEND_API_KEY
 * Vars required:     FRONTEND_ORIGIN, FROM_EMAIL
 */

const NONCE_TTL_MS = 5 * 60 * 1000;
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const SPKI_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

async function importEd25519PublicKey(publicKeyHex) {
  const raw = hexToBytes(publicKeyHex);
  if (raw.length !== 32) throw new Error("Public key must be 32 bytes.");
  const spki = new Uint8Array(SPKI_ED25519_PREFIX.length + raw.length);
  spki.set(SPKI_ED25519_PREFIX, 0);
  spki.set(raw, SPKI_ED25519_PREFIX.length);
  return crypto.subtle.importKey("spki", spki.buffer, { name: "Ed25519" }, false, ["verify"]);
}

async function jingCoordFromString(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const x = ((digest[0] * 256 + digest[1]) % 970) / 10;
  const y = ((digest[2] * 256 + digest[3]) % 970) / 10;
  const z = ((digest[4] * 256 + digest[5]) % 970) / 10;
  return { x: x.toFixed(1), y: y.toFixed(1), z: z.toFixed(1) };
}

async function signToken(payloadObj, secret) {
  const payload = btoa(JSON.stringify(payloadObj));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
  return `${payload}.${sig}`;
}
async function verifyToken(token, secret) {
  const [payload, sig] = (token || "").split(".");
  if (!payload || !sig) return null;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const sigBytes = Uint8Array.from(atob(sig), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(payload));
  if (!ok) return null;
  const data = JSON.parse(atob(payload));
  if (data.exp && Date.now() > data.exp) return null;
  return data;
}

async function getIdentityByToken(token, env) {
  if (!token) return null;
  const data = await verifyToken(token, env.SESSION_SECRET);
  if (!data || !data.sub) return null;
  const [kind, key] = String(data.sub).split(":", 2);
  if (!kind || !key) return null;
  const identity = await env.DB.prepare(
    "SELECT * FROM identities WHERE kind = ? AND identity_key = ?"
  ).bind(kind, key).first();
  return identity || null;
}

async function getSession(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  return await getIdentityByToken(token, env);
}

async function areFriends(env, idA, idB) {
  const row = await env.DB.prepare(
    `SELECT id FROM friendships
     WHERE status='accepted' AND (
       (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)
     )`
  ).bind(idA, idB, idB, idA).first();
  return !!row;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = env.FRONTEND_ORIGIN || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    // WebSocket upgrade for JOFP signaling — handled before the JSON-parsing
    // block below since this is not a JSON request.
    if (url.pathname === "/api/jofp/connect") {
      return await handleJofpConnect(request, env);
    }

    try {
      if (url.pathname === "/api/challenge" && request.method === "POST") {
        return await handleChallenge(request, env, origin);
      }
      if (url.pathname === "/api/verify" && request.method === "POST") {
        return await handleVerify(request, env, origin);
      }
      if (url.pathname === "/api/email/request-code" && request.method === "POST") {
        return await handleEmailRequestCode(request, env, origin);
      }
      if (url.pathname === "/api/email/verify-code" && request.method === "POST") {
        return await handleEmailVerifyCode(request, env, origin);
      }
      if (url.pathname === "/api/me" && request.method === "GET") {
        return await handleMe(request, env, origin);
      }
      if (url.pathname === "/api/posts" && request.method === "GET") {
        return await handlePostsList(request, env, origin);
      }
      if (url.pathname === "/api/posts" && request.method === "POST") {
        return await handlePostsCreate(request, env, origin);
      }
      const likeMatch = url.pathname.match(/^\/api\/posts\/(\d+)\/like$/);
      if (likeMatch && request.method === "POST") {
        return await handlePostLike(request, env, origin, Number(likeMatch[1]));
      }
      if (url.pathname === "/api/users/search" && request.method === "GET") {
        return await handleUserSearch(request, env, origin, url);
      }
      if (url.pathname === "/api/friends/request" && request.method === "POST") {
        return await handleFriendRequest(request, env, origin);
      }
      if (url.pathname === "/api/friends/respond" && request.method === "POST") {
        return await handleFriendRespond(request, env, origin);
      }
      if (url.pathname === "/api/friends" && request.method === "GET") {
        return await handleFriendsList(request, env, origin);
      }
      if (url.pathname === "/api/friends/requests" && request.method === "GET") {
        return await handleFriendRequestsList(request, env, origin);
      }
      if (url.pathname === "/api/jofp/share" && request.method === "POST") {
        return await handleJofpShare(request, env, origin);
      }
      if (url.pathname === "/api/jofp/inbox" && request.method === "GET") {
        return await handleJofpInbox(request, env, origin);
      }
      if (url.pathname === "/api/profile/handle" && request.method === "POST") {
        return await handleUpdateHandle(request, env, origin);
      }
      if (url.pathname === "/api/profile/pair" && request.method === "POST") {
        return await handleSetPair(request, env, origin);
      }
      if (url.pathname === "/api/ledger/genesis" && request.method === "POST") {
        return await handleGenesis(request, env, origin);
      }
      if (url.pathname === "/api/ledger/distribute" && request.method === "POST") {
        return await handleDistribute(request, env, origin);
      }
      if (url.pathname === "/api/ledger/balance" && request.method === "GET") {
        return await handleBalance(request, env, origin);
      }
      if (url.pathname === "/api/ledger/history" && request.method === "GET") {
        return await handleLedgerHistory(request, env, origin);
      }
      if (url.pathname === "/api/ledger/chain" && request.method === "GET") {
        return await handleLedgerChain(request, env, origin, url);
      }
      return json({ error: "Not found" }, 404, origin);
    } catch (err) {
      return json({ error: err.message || "Internal error" }, 500, origin);
    }
  },
};

// ---------------- wallet auth ----------------

async function handleChallenge(request, env, origin) {
  const { publicKey } = await request.json();
  if (!publicKey || !/^[0-9a-fA-F]{64}$/.test(publicKey)) {
    return json({ error: "publicKey must be a 64-char hex string." }, 400, origin);
  }
  const nonceBytes = crypto.getRandomValues(new Uint8Array(24));
  const nonce = bytesToHex(nonceBytes);
  const expiresAt = Date.now() + NONCE_TTL_MS;

  await env.DB.prepare(
    "INSERT INTO nonces (public_key, nonce, expires_at) VALUES (?, ?, ?)"
  ).bind(publicKey, nonce, expiresAt).run();

  return json({ nonce }, 200, origin);
}

async function handleVerify(request, env, origin) {
  const { publicKey, nonce, signature } = await request.json();
  if (!publicKey || !nonce || !signature) {
    return json({ error: "publicKey, nonce, and signature are required." }, 400, origin);
  }

  const row = await env.DB.prepare(
    "SELECT * FROM nonces WHERE public_key = ? AND nonce = ? ORDER BY expires_at DESC LIMIT 1"
  ).bind(publicKey, nonce).first();
  if (!row) return json({ error: "Unknown or already-used nonce." }, 400, origin);
  if (Date.now() > row.expires_at) return json({ error: "Nonce expired." }, 400, origin);
  await env.DB.prepare("DELETE FROM nonces WHERE id = ?").bind(row.id).run();

  const pubKey = await importEd25519PublicKey(publicKey);
  const sigBytes = base64ToBytes(signature);
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" }, pubKey, sigBytes, new TextEncoder().encode(nonce)
  );
  if (!valid) return json({ error: "Signature verification failed." }, 401, origin);

  const coord = await jingCoordFromString(publicKey);
  const handle = publicKey.slice(0, 10);

  await env.DB.prepare(
    `INSERT INTO identities (kind, identity_key, handle, jing_x, jing_y, jing_z, created_at, last_login_at)
     VALUES ('wallet', ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(identity_key) DO UPDATE SET last_login_at = excluded.last_login_at`
  ).bind(publicKey, handle, coord.x, coord.y, coord.z, Date.now(), Date.now()).run();

  const token = await signToken(
    { sub: `wallet:${publicKey}`, exp: Date.now() + SESSION_TTL_MS },
    env.SESSION_SECRET
  );
  return json({ token, coord, handle }, 200, origin);
}

// ---------------- email auth ----------------

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function handleEmailRequestCode(request, env, origin) {
  const { email: rawEmail } = await request.json();
  const email = normalizeEmail(rawEmail);
  if (!isValidEmail(email)) {
    return json({ error: "Enter a valid email address." }, 400, origin);
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + EMAIL_CODE_TTL_MS;

  await env.DB.prepare(
    "INSERT INTO email_codes (email, code, expires_at) VALUES (?, ?, ?)"
  ).bind(email, code, expiresAt).run();

  const sent = await sendVerificationEmail(env, email, code);
  if (!sent.ok) {
    return json({ error: "Could not send verification email: " + sent.error }, 502, origin);
  }

  return json({ ok: true }, 200, origin);
}

async function sendVerificationEmail(env, toEmail, code) {
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL || "ΩPair <onboarding@resend.dev>",
        to: [toEmail],
        subject: `${code} is your ΩPair verification code`,
        text: `Your ΩPair verification code is ${code}. It expires in 10 minutes. If you didn't request this, you can ignore this email.`,
      }),
    });
    if (!res.ok) {
      const body = await res.text();
      return { ok: false, error: `${res.status} ${body}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

async function handleEmailVerifyCode(request, env, origin) {
  const { email: rawEmail, code } = await request.json();
  const email = normalizeEmail(rawEmail);
  if (!isValidEmail(email) || !code) {
    return json({ error: "email and code are required." }, 400, origin);
  }

  const row = await env.DB.prepare(
    "SELECT * FROM email_codes WHERE email = ? AND code = ? ORDER BY expires_at DESC LIMIT 1"
  ).bind(email, String(code)).first();
  if (!row) return json({ error: "Incorrect code." }, 400, origin);
  if (Date.now() > row.expires_at) return json({ error: "Code expired." }, 400, origin);
  await env.DB.prepare("DELETE FROM email_codes WHERE id = ?").bind(row.id).run();

  const coord = await jingCoordFromString(email);
  const handle = email.split("@")[0];

  await env.DB.prepare(
    `INSERT INTO identities (kind, identity_key, handle, jing_x, jing_y, jing_z, created_at, last_login_at)
     VALUES ('email', ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(identity_key) DO UPDATE SET last_login_at = excluded.last_login_at`
  ).bind(email, handle, coord.x, coord.y, coord.z, Date.now(), Date.now()).run();

  const token = await signToken(
    { sub: `email:${email}`, exp: Date.now() + SESSION_TTL_MS },
    env.SESSION_SECRET
  );
  return json({ token, coord, handle }, 200, origin);
}

// ---------------- session ----------------

async function handleMe(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Invalid or expired session." }, 401, origin);
  return json({
    handle: identity.handle,
    coord: { x: identity.jing_x, y: identity.jing_y, z: identity.jing_z },
  }, 200, origin);
}

// ---------------- posts ----------------

async function handlePostsList(request, env, origin) {
  const identity = await getSession(request, env); // optional
  const { results } = await env.DB.prepare(
    `SELECT id, identity_id, handle, jing_x, jing_y, jing_z, text, likes, created_at, visibility
     FROM posts ORDER BY created_at DESC LIMIT 100`
  ).all();

  const visible = [];
  for (const p of results) {
    if (p.visibility !== 'friends') {
      visible.push(p);
      continue;
    }
    // friends-only post: show if it's mine, or I'm friends with the author
    if (identity && (identity.id === p.identity_id || await areFriends(env, identity.id, p.identity_id))) {
      visible.push(p);
    }
  }

  return json({ posts: visible.slice(0, 50) }, 200, origin);
}

async function handlePostsCreate(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { text, visibility } = await request.json();
  const trimmed = String(text || "").trim();
  if (!trimmed) return json({ error: "Post text cannot be empty." }, 400, origin);
  if (trimmed.length > 500) return json({ error: "Post text too long (max 500 chars)." }, 400, origin);
  const vis = visibility === 'friends' ? 'friends' : 'public';

  const createdAt = Date.now();
  const result = await env.DB.prepare(
    `INSERT INTO posts (identity_id, handle, jing_x, jing_y, jing_z, text, likes, created_at, visibility)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`
  ).bind(identity.id, identity.handle, identity.jing_x, identity.jing_y, identity.jing_z, trimmed, createdAt, vis).run();

  return json({
    post: {
      id: result.meta.last_row_id,
      handle: identity.handle,
      jing_x: identity.jing_x, jing_y: identity.jing_y, jing_z: identity.jing_z,
      text: trimmed, likes: 0, created_at: createdAt, visibility: vis,
    },
  }, 200, origin);
}

async function handlePostLike(request, env, origin, postId) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  await env.DB.prepare("UPDATE posts SET likes = likes + 1 WHERE id = ?").bind(postId).run();
  const row = await env.DB.prepare("SELECT likes FROM posts WHERE id = ?").bind(postId).first();
  if (!row) return json({ error: "Post not found." }, 404, origin);

  return json({ likes: row.likes }, 200, origin);
}

// ---------------- friends ----------------

async function handleUserSearch(request, env, origin, url) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const handle = (url.searchParams.get("handle") || "").trim();
  if (!handle) return json({ users: [] }, 200, origin);

  const { results } = await env.DB.prepare(
    `SELECT id, handle, jing_x, jing_y, jing_z FROM identities
     WHERE handle LIKE ? AND id != ? LIMIT 10`
  ).bind(`%${handle}%`, identity.id).all();

  return json({ users: results }, 200, origin);
}

async function handleFriendRequest(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { handle } = await request.json();
  const target = await env.DB.prepare(
    "SELECT * FROM identities WHERE handle = ? LIMIT 1"
  ).bind(String(handle || "").trim()).first();

  if (!target) return json({ error: "No user found with that handle." }, 404, origin);
  if (target.id === identity.id) return json({ error: "You can't add yourself." }, 400, origin);

  const existing = await env.DB.prepare(
    `SELECT * FROM friendships WHERE
     (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)`
  ).bind(identity.id, target.id, target.id, identity.id).first();

  if (existing) {
    if (existing.status === 'accepted') return json({ error: "You're already friends." }, 400, origin);
    if (existing.status === 'pending') return json({ error: "A request is already pending." }, 400, origin);
  }

  await env.DB.prepare(
    `INSERT INTO friendships (requester_id, addressee_id, status, created_at) VALUES (?, ?, 'pending', ?)`
  ).bind(identity.id, target.id, Date.now()).run();

  return json({ ok: true }, 200, origin);
}

async function handleFriendRespond(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { requestId, action } = await request.json();
  if (!['accept', 'decline'].includes(action)) {
    return json({ error: "action must be 'accept' or 'decline'." }, 400, origin);
  }

  const reqRow = await env.DB.prepare(
    "SELECT * FROM friendships WHERE id = ? AND addressee_id = ? AND status = 'pending'"
  ).bind(requestId, identity.id).first();
  if (!reqRow) return json({ error: "Request not found." }, 404, origin);

  const newStatus = action === 'accept' ? 'accepted' : 'declined';
  await env.DB.prepare(
    "UPDATE friendships SET status = ?, responded_at = ? WHERE id = ?"
  ).bind(newStatus, Date.now(), requestId).run();

  return json({ ok: true }, 200, origin);
}

async function handleFriendsList(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { results } = await env.DB.prepare(
    `SELECT i.id, i.handle, i.jing_x, i.jing_y, i.jing_z, i.kind, i.identity_key FROM friendships f
     JOIN identities i ON i.id = (
       CASE WHEN f.requester_id = ? THEN f.addressee_id ELSE f.requester_id END
     )
     WHERE f.status = 'accepted' AND (f.requester_id = ? OR f.addressee_id = ?)`
  ).bind(identity.id, identity.id, identity.id).all();

  return json({ friends: results }, 200, origin);
}

async function handleFriendRequestsList(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { results } = await env.DB.prepare(
    `SELECT f.id as request_id, i.handle as from_handle, f.created_at
     FROM friendships f
     JOIN identities i ON i.id = f.requester_id
     WHERE f.addressee_id = ? AND f.status = 'pending'`
  ).bind(identity.id).all();

  return json({ requests: results }, 200, origin);
}

async function handleUpdateHandle(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { handle: rawHandle } = await request.json();
  const handle = String(rawHandle || "").trim();

  if (!/^[\p{L}\p{N}._-]{2,20}$/u.test(handle)) {
    return json({ error: "Username must be 2-20 characters: letters (any language), numbers, dots, underscores, or hyphens only." }, 400, origin);
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM identities WHERE handle = ? AND id != ?"
  ).bind(handle, identity.id).first();
  if (existing) {
    return json({ error: "That username is already taken." }, 409, origin);
  }

  await env.DB.prepare(
    "UPDATE identities SET handle = ? WHERE id = ?"
  ).bind(handle, identity.id).run();

  return json({ handle }, 200, origin);
}

// ---------------- OmegaPair Token (OPT) ledger ----------------

const GENESIS_SUPPLY = 1000000000; // 1B OPT

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

// Ω₀ = hash(username, email, phone) — the "proof of pair" identity anchor.
async function handleSetPair(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { email, phone } = await request.json();
  const cleanEmail = normalizeEmail(email);
  const cleanPhone = String(phone || "").replace(/[^\d+]/g, "");

  if (!isValidEmail(cleanEmail)) return json({ error: "Enter a valid email." }, 400, origin);
  if (cleanPhone.length < 7) return json({ error: "Enter a valid phone number." }, 400, origin);

  const pairHash = await sha256Hex(`${identity.handle}|${cleanEmail}|${cleanPhone}`);

  await env.DB.prepare(
    "UPDATE identities SET profile_email = ?, profile_phone = ?, pair_hash = ? WHERE id = ?"
  ).bind(cleanEmail, cleanPhone, pairHash, identity.id).run();

  return json({ pairHash }, 200, origin);
}

// One-time genesis mint: whoever calls this first becomes the treasury and
// receives the full 1B OPT supply as ledger entry Ω₀. Cannot be called again.
async function handleGenesis(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const existing = await env.DB.prepare("SELECT id FROM ledger WHERE seq = 0").first();
  if (existing) return json({ error: "Genesis has already occurred." }, 409, origin);

  const createdAt = Date.now();
  const entryHash = await sha256Hex(`0|null|null|${identity.id}|${GENESIS_SUPPLY}|${createdAt}|Genesis`);

  await env.DB.prepare(
    `INSERT INTO ledger (seq, prev_hash, entry_hash, from_identity_id, to_identity_id, amount, memo, created_at)
     VALUES (0, NULL, ?, NULL, ?, ?, 'Genesis', ?)`
  ).bind(entryHash, identity.id, GENESIS_SUPPLY, createdAt).run();

  await env.DB.prepare(
    `INSERT INTO balances (identity_id, balance) VALUES (?, ?)
     ON CONFLICT(identity_id) DO UPDATE SET balance = balance + excluded.balance`
  ).bind(identity.id, GENESIS_SUPPLY).run();

  return json({ ok: true, seq: 0, entryHash, amount: GENESIS_SUPPLY }, 200, origin);
}

// Treasury (the identity that ran genesis) sends OPT to another user by handle.
async function handleDistribute(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const genesisRow = await env.DB.prepare("SELECT to_identity_id FROM ledger WHERE seq = 0").first();
  if (!genesisRow) return json({ error: "Genesis has not occurred yet." }, 400, origin);

  const { toHandle, amount, memo } = await request.json();
  const amt = Math.floor(Number(amount));
  if (!amt || amt <= 0) return json({ error: "Amount must be a positive whole number." }, 400, origin);

  const target = await env.DB.prepare("SELECT id FROM identities WHERE handle = ?").bind(String(toHandle || "").trim()).first();
  if (!target) return json({ error: "No user found with that handle." }, 404, origin);
  if (target.id === identity.id) return json({ error: "You can't send OPT to yourself." }, 400, origin);

  const senderBal = await env.DB.prepare("SELECT balance FROM balances WHERE identity_id = ?").bind(identity.id).first();
  const currentBalance = senderBal ? senderBal.balance : 0;
  if (currentBalance < amt) return json({ error: "Insufficient treasury balance." }, 400, origin);

  const lastEntry = await env.DB.prepare("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").first();
  const nextSeq = lastEntry.seq + 1;
  const createdAt = Date.now();
  const entryHash = await sha256Hex(`${nextSeq}|${lastEntry.entry_hash}|${identity.id}|${target.id}|${amt}|${createdAt}|${memo || ""}`);

  await env.DB.prepare(
    `INSERT INTO ledger (seq, prev_hash, entry_hash, from_identity_id, to_identity_id, amount, memo, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(nextSeq, lastEntry.entry_hash, entryHash, identity.id, target.id, amt, memo || null, createdAt).run();

  await env.DB.prepare(
    "UPDATE balances SET balance = balance - ? WHERE identity_id = ?"
  ).bind(amt, identity.id).run();
  await env.DB.prepare(
    `INSERT INTO balances (identity_id, balance) VALUES (?, ?)
     ON CONFLICT(identity_id) DO UPDATE SET balance = balance + excluded.balance`
  ).bind(target.id, amt).run();

  return json({ ok: true, seq: nextSeq, entryHash, amount: amt }, 200, origin);
}

async function handleBalance(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const row = await env.DB.prepare("SELECT balance FROM balances WHERE identity_id = ?").bind(identity.id).first();
  const genesisRow = await env.DB.prepare("SELECT to_identity_id FROM ledger WHERE seq = 0").first();
  const isTreasury = genesisRow ? genesisRow.to_identity_id === identity.id : false;

  return json({ balance: row ? row.balance : 0, isTreasury, genesisOccurred: !!genesisRow }, 200, origin);
}

async function handleLedgerHistory(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { results } = await env.DB.prepare(
    `SELECT l.seq, l.amount, l.memo, l.created_at,
            fi.handle as from_handle, ti.handle as to_handle
     FROM ledger l
     LEFT JOIN identities fi ON fi.id = l.from_identity_id
     JOIN identities ti ON ti.id = l.to_identity_id
     WHERE l.from_identity_id = ? OR l.to_identity_id = ?
     ORDER BY l.seq DESC LIMIT 50`
  ).bind(identity.id, identity.id).all();

  return json({ history: results }, 200, origin);
}

async function handleLedgerChain(request, env, origin, url) {
  const limit = Math.min(Number(url.searchParams.get("limit")) || 20, 100);
  const { results } = await env.DB.prepare(
    `SELECT l.seq, l.prev_hash, l.entry_hash, l.amount, l.memo, l.created_at,
            fi.handle as from_handle, ti.handle as to_handle
     FROM ledger l
     LEFT JOIN identities fi ON fi.id = l.from_identity_id
     JOIN identities ti ON ti.id = l.to_identity_id
     ORDER BY l.seq DESC LIMIT ?`
  ).bind(limit).all();

  return json({ chain: results }, 200, origin);
}

// ---------------- JOFP: direct peer-to-peer file sharing ----------------
//
// Files never touch this server. This backend only does two things:
//   1. Store a tiny "grant" record (who shared what with whom) — readable
//      only by the recipient, never a public directory.
//   2. Relay WebRTC signaling messages between two paired browsers via a
//      Durable Object, so they can open a direct data channel and transfer
//      the actual bytes peer-to-peer.

async function handleJofpShare(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { toHandle, omegaHash, fileName, fileType, fileSize } = await request.json();
  if (!omegaHash) return json({ error: "omegaHash is required." }, 400, origin);

  const target = await env.DB.prepare(
    "SELECT * FROM identities WHERE handle = ? LIMIT 1"
  ).bind(String(toHandle || "").trim()).first();
  if (!target) return json({ error: "No user found with that handle." }, 404, origin);
  if (target.id === identity.id) return json({ error: "You can't share with yourself." }, 400, origin);

  const isFriend = await areFriends(env, identity.id, target.id);
  if (!isFriend) return json({ error: "You can only share files with friends." }, 403, origin);

  await env.DB.prepare(
    `INSERT INTO jofp_grants (omega_hash, from_identity_id, to_identity_id, file_name, file_type, file_size, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(omegaHash, identity.id, target.id, fileName || null, fileType || null, fileSize || null, Date.now()).run();

  return json({ ok: true }, 200, origin);
}

async function handleJofpInbox(request, env, origin) {
  const identity = await getSession(request, env);
  if (!identity) return json({ error: "Login required." }, 401, origin);

  const { results } = await env.DB.prepare(
    `SELECT g.id, g.omega_hash, g.file_name, g.file_type, g.file_size, g.created_at,
            i.handle as from_handle, i.kind as from_kind, i.identity_key as from_key
     FROM jofp_grants g
     JOIN identities i ON i.id = g.from_identity_id
     WHERE g.to_identity_id = ?
     ORDER BY g.created_at DESC LIMIT 100`
  ).bind(identity.id).all();

  return json({ inbox: results }, 200, origin);
}

function identityWireId(identity) {
  return `${identity.kind}:${identity.identity_key}`;
}

async function handleJofpConnect(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  const identity = await getIdentityByToken(token, env);
  if (!identity) return new Response("Unauthorized", { status: 401 });

  if (!env.JOFP_HUB) {
    return new Response("Signaling hub is not configured on the server.", { status: 500 });
  }

  const id = env.JOFP_HUB.idFromName("global");
  const stub = env.JOFP_HUB.get(id);

  // Forward to the Durable Object, attaching the verified identity's wire id
  // so the DO doesn't have to re-verify tokens itself.
  const forwardUrl = new URL(request.url);
  forwardUrl.searchParams.set("wireId", identityWireId(identity));
  return stub.fetch(new Request(forwardUrl.toString(), request));
}

// ---------------- Durable Object: JOFP signaling hub ----------------
//
// Purely a real-time relay for presence + WebRTC handshake messages.
// It never sees file bytes and stores nothing persistently — connections
// live only in memory for as long as this instance stays warm.

export class JofpHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // wireId -> WebSocket
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get("Upgrade");
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket upgrade request.", { status: 400 });
    }

    const url = new URL(request.url);
    const wireId = url.searchParams.get("wireId");
    if (!wireId) return new Response("Missing identity.", { status: 400 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.acceptSession(server, wireId);
    return new Response(null, { status: 101, webSocket: client });
  }

  acceptSession(ws, wireId) {
    ws.accept();

    // Replace any previous connection for this identity (e.g. reload/new tab).
    const previous = this.sessions.get(wireId);
    if (previous && previous !== ws) {
      try { previous.close(1000, "Replaced by new connection"); } catch (e) {}
    }
    this.sessions.set(wireId, ws);

    ws.addEventListener("message", (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch (e) { return; }
      this.route(wireId, msg);
    });

    ws.addEventListener("close", () => {
      if (this.sessions.get(wireId) === ws) this.sessions.delete(wireId);
    });
    ws.addEventListener("error", () => {
      if (this.sessions.get(wireId) === ws) this.sessions.delete(wireId);
    });
  }

  route(fromWireId, msg) {
    // Every message must name a recipient; this hub only ever does
    // one-to-one relaying, never broadcast, and only to identities that
    // are currently connected.
    if (!msg || !msg.to || typeof msg.to !== "string") return;
    const target = this.sessions.get(msg.to);
    if (!target) {
      // Recipient not online — tell the sender so the UI can show that,
      // rather than leaving them waiting indefinitely.
      const sender = this.sessions.get(fromWireId);
      if (sender) {
        try {
          sender.send(JSON.stringify({ type: "offline", who: msg.to }));
        } catch (e) {}
      }
      return;
    }
    try {
      target.send(JSON.stringify({ ...msg, from: fromWireId }));
    } catch (e) {}
  }
}
