/**
 * CLNP Verification Server
 *
 * AGENT COOKIE CRUMB: This is the server-side verification layer for CLNP.
 * It generates unique challenges with randomized parameters, receives raw
 * pointer/accel data from the client, and runs analysis + scoring server-side.
 * Scoring thresholds never leave the server. Zero external dependencies —
 * uses only Node.js built-in modules.
 *
 * Endpoints:
 *   POST /api/challenge        — Generate standalone challenge with randomized params
 *   POST /api/verify           — Verify standalone raw data against a challenge
 *   POST /api/embed/challenge  — Generate embed challenge (smaller perturbations)
 *   POST /api/embed/verify     — Verify embed browsing data (7 metrics, no cognitive)
 *   GET  /api/health           — Health check
 *   GET  /api/admin/stats      — Aggregated session stats (auth required)
 *   GET  /api/admin/sessions   — Paginated session list (auth required)
 *   GET  /api/admin/session/:id — Full session detail (auth required)
 *   GET  /admin                — Admin dashboard HTML (auth required)
 *   GET  /                     — Serve clnp-probe.html
 *   GET  /clnp-embed.js        — Serve embed client library
 *   GET  /clnp-embed-demo.html — Serve embed demo page
 *
 * Every verification (standalone + embed) logs a session record to
 * data/sessions.jsonl for ML training data collection.
 */

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");
const { analyze, analyzeEmbed } = require("./analysis.js");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "127.0.0.1";
const ROOT = __dirname;

const CHALLENGE_TTL_MS = Number(process.env.CHALLENGE_TTL_MS || 180000);
const CLEANUP_INTERVAL_MS = 30000;
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB — enough for high-res pointer data

// ─── DATA COLLECTION CONFIG ────────────────────────────────
// AGENT COOKIE CRUMB: Session data is logged to JSONL for ML training.
// Each verification (standalone + embed) appends one line to sessions.jsonl.
// Data lives on a persistent Fly.io volume (/data) in production.
// CLNP_ADMIN_TOKEN gates all admin endpoints — no token = no access.
const DATA_DIR = process.env.CLNP_DATA_DIR || path.join(__dirname, "data");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.jsonl");
const CLNP_ADMIN_TOKEN = process.env.CLNP_ADMIN_TOKEN || null;

// HMAC secret for signing tokens and receipts
const secretString = process.env.CLNP_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.CLNP_SECRET) {
  console.warn("[clnp] CLNP_SECRET not set; using ephemeral secret for this process.");
}
const HMAC_SECRET = Buffer.from(secretString, "utf8");

// In-memory challenge store
const challenges = new Map();


// ─── CRYPTO HELPERS ─────────────────────────────────────────

function b64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(input) {
  const pad = input.length % 4 ? "=".repeat(4 - (input.length % 4)) : "";
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function signPayload(payloadB64) {
  return b64urlEncode(crypto.createHmac("sha256", HMAC_SECRET).update(payloadB64).digest());
}

function makeToken(data) {
  const payloadB64 = b64urlEncode(JSON.stringify(data));
  return `${payloadB64}.${signPayload(payloadB64)}`;
}

function verifyToken(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expected = signPayload(payloadB64);
  const sigBuf = Buffer.from(sig, "utf8");
  const expBuf = Buffer.from(expected, "utf8");
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    return JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  } catch (_e) {
    return null;
  }
}


// ─── IP HASHING & DATA COLLECTION ───────────────────────────
// AGENT COOKIE CRUMB: IP addresses are hashed with the server secret so
// we can deduplicate users without storing PII. The hash is truncated to
// 16 hex chars — enough for uniqueness, not reversible to the original IP.

function getClientIP(req) {
  // Fly.io, Cloudflare, and other proxies set these headers
  const cfIP = req.headers["cf-connecting-ip"];
  if (cfIP) return cfIP.split(",")[0].trim();
  const xff = req.headers["x-forwarded-for"];
  if (xff) return xff.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function hashIP(ip) {
  return crypto.createHmac("sha256", HMAC_SECRET)
    .update(ip)
    .digest("hex")
    .slice(0, 16);
}

let dataDirectoryReady = false;

function ensureDataDirectory() {
  if (dataDirectoryReady) return;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    dataDirectoryReady = true;
  } catch (err) {
    console.error("[clnp] Failed to create data directory:", err.message);
  }
}

/**
 * Log a verification session to JSONL for ML training data collection.
 * Called from both handleVerify and handleEmbedVerify after analysis.
 * Each line is one self-contained JSON object — no external schema dependency.
 *
 * @param {Object} record - Session data to log
 */
function logSession(record) {
  try {
    ensureDataDirectory();
    fs.appendFileSync(SESSIONS_FILE, JSON.stringify(record) + "\n");
  } catch (err) {
    console.error("[clnp] Failed to log session:", err.message);
  }
}


// ─── ADMIN AUTHENTICATION ───────────────────────────────────
// AGENT COOKIE CRUMB: Admin endpoints require CLNP_ADMIN_TOKEN.
// Token can be passed via Authorization header or ?token= query param.
// If CLNP_ADMIN_TOKEN is not set, all admin endpoints return 503 (not configured).
// Uses timing-safe comparison to prevent timing attacks on the token.

function authenticateAdmin(req, url) {
  if (!CLNP_ADMIN_TOKEN) return { ok: false, status: 503, error: "admin_not_configured" };

  // Check Authorization header first
  const authHeader = req.headers["authorization"];
  let token = null;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7);
  }
  // Fall back to query param
  if (!token) {
    token = url.searchParams.get("token");
  }
  if (!token) return { ok: false, status: 401, error: "missing_token" };

  // Timing-safe comparison
  const tokenBuf = Buffer.from(token, "utf8");
  const expectedBuf = Buffer.from(CLNP_ADMIN_TOKEN, "utf8");
  if (tokenBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
    return { ok: false, status: 401, error: "invalid_token" };
  }

  return { ok: true };
}


// ─── ADMIN DATA HELPERS ─────────────────────────────────────
// AGENT COOKIE CRUMB: Admin endpoints read sessions.jsonl line by line.
// This is intentionally simple (no database) — JSONL is append-only,
// survives crashes, and is trivial to export for ML training.

function readAllSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return [];
    const content = fs.readFileSync(SESSIONS_FILE, "utf8").trim();
    if (!content) return [];
    return content.split("\n").map(line => {
      try { return JSON.parse(line); } catch (_e) { return null; }
    }).filter(Boolean);
  } catch (_err) {
    return [];
  }
}

function computeAdminStats(sessions) {
  const now = Date.now();
  const todayStart = new Date().setHours(0, 0, 0, 0);
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
  const oneHourAgo = now - 60 * 60 * 1000;

  const total = sessions.length;
  const today = sessions.filter(s => s.ts >= todayStart).length;
  const recentHour = sessions.filter(s => s.ts >= oneHourAgo).length;

  // By day (last 30 days)
  const byDay = {};
  for (let d = 0; d < 30; d++) {
    const date = new Date(now - d * 24 * 60 * 60 * 1000);
    const key = date.toISOString().slice(0, 10);
    byDay[key] = 0;
  }
  for (const s of sessions) {
    if (s.ts < thirtyDaysAgo) continue;
    const key = new Date(s.ts).toISOString().slice(0, 10);
    if (key in byDay) byDay[key]++;
  }

  // By device type
  const byDevice = {};
  for (const s of sessions) {
    const dev = s.inputMethod || "unknown";
    byDevice[dev] = (byDevice[dev] || 0) + 1;
  }

  // By verdict class
  const byVerdict = { "score-human": 0, "score-uncertain": 0, "score-bot": 0 };
  for (const s of sessions) {
    const vc = s.verdictClass || "score-bot";
    byVerdict[vc] = (byVerdict[vc] || 0) + 1;
  }

  // By mode
  const byMode = {};
  for (const s of sessions) {
    const mode = s.mode || "standalone";
    byMode[mode] = (byMode[mode] || 0) + 1;
  }

  // Score distribution (10 buckets: 0-10%, 10-20%, ..., 90-100%)
  const scoreDistribution = new Array(10).fill(0);
  for (const s of sessions) {
    const bucket = Math.min(9, Math.floor((s.overall || 0) * 10));
    scoreDistribution[bucket]++;
  }

  // Per-metric averages by device type
  const metricSums = {};
  const metricCounts = {};
  for (const s of sessions) {
    const dev = s.inputMethod || "unknown";
    if (!metricSums[dev]) { metricSums[dev] = {}; metricCounts[dev] = {}; }
    if (s.scores) {
      for (const [key, val] of Object.entries(s.scores)) {
        const score = typeof val === "object" ? val.score : val;
        if (typeof score === "number") {
          metricSums[dev][key] = (metricSums[dev][key] || 0) + score;
          metricCounts[dev][key] = (metricCounts[dev][key] || 0) + 1;
        }
      }
    }
  }
  const metricAverages = {};
  for (const dev of Object.keys(metricSums)) {
    metricAverages[dev] = {};
    for (const key of Object.keys(metricSums[dev])) {
      metricAverages[dev][key] = metricCounts[dev][key] > 0
        ? +(metricSums[dev][key] / metricCounts[dev][key]).toFixed(3) : 0;
    }
  }

  return {
    total, today, recentRate: recentHour,
    byDay, byDevice, byVerdict, byMode,
    scoreDistribution, metricAverages,
  };
}


// ─── HTTP HELPERS ───────────────────────────────────────────

function json(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let total = 0, body = "";
    req.on("data", chunk => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) { reject(new Error("body_too_large")); req.destroy(); return; }
      body += chunk;
    });
    req.on("end", () => {
      if (!body) { resolve({}); return; }
      try { resolve(JSON.parse(body)); } catch (_e) { reject(new Error("invalid_json")); }
    });
    req.on("error", () => reject(new Error("read_error")));
  });
}


// ─── CHALLENGE GENERATION ───────────────────────────────────
// AGENT COOKIE CRUMB: The server randomizes all task parameters per session.
// Even if an attacker reads the open-source code and knows we use multi-sine
// probes, they don't know WHICH frequencies this particular challenge uses.
// They'd need to respond correctly to unknown perturbations in real-time.

/**
 * Pool of valid non-harmonic probe frequency sets.
 * Each set avoids integer multiples between any two frequencies.
 */
const FREQ_POOL = [0.3, 0.5, 0.7, 0.9, 1.1, 1.5, 1.8, 2.1, 2.5, 2.8, 3.3, 3.7, 4.3, 5.1, 5.7, 6.3, 7.1, 7.9];

/**
 * Valid Lissajous frequency pairs that produce non-degenerate figures.
 * Each pair is [freqX, freqY] where the ratio is a simple rational number.
 */
const PATH_PAIRS = [
  [0.15, 0.10], // 3:2
  [0.12, 0.08], // 3:2
  [0.20, 0.15], // 4:3
  [0.10, 0.06], // 5:3
  [0.16, 0.12], // 4:3
  [0.18, 0.10], // 9:5
  [0.14, 0.10], // 7:5
];

function pickRandom(arr, n) {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

function randRange(lo, hi) {
  return lo + Math.random() * (hi - lo);
}

function generateChallenge() {
  const challengeId = crypto.randomBytes(16).toString("hex");
  const now = Date.now();

  // Randomize probe frequencies (pick 5 from pool)
  const probeFreqsPicked = pickRandom(FREQ_POOL, 5).sort((a, b) => a - b);
  const probes = probeFreqsPicked.map(freq => ({
    freq,
    ampX: Math.round(randRange(3, 7)),
    ampY: Math.round(randRange(1, 3)),
    phaseOffset: Math.PI / 3 + randRange(-0.3, 0.3),
  }));

  // Randomize pulse schedule
  const pulseCount = Math.floor(randRange(4, 8));
  const trackingDuration = Math.round(randRange(18000, 22000));
  const dualtaskDuration = Math.round(randRange(10000, 14000));
  const freeMoveDuration = 5000;
  const pulseMinGap = 2800;
  const pulseHoldDuration = Math.round(randRange(500, 700));
  const pulseReturnDuration = 200;

  const pulses = [];
  const available = trackingDuration - pulseMinGap;
  for (let i = 0; i < pulseCount; i++) {
    const offset = pulseMinGap + (available / pulseCount) * i + Math.random() * (available / pulseCount) * 0.6;
    const dir = (i % 3 === 2) ? -1 : 1;
    pulses.push({
      offsetMs: Math.round(offset),
      ampX: Math.round(randRange(18, 26)) * dir,
      ampY: 0,
    });
  }

  // Randomize path
  const [freqX, freqY] = PATH_PAIRS[Math.floor(Math.random() * PATH_PAIRS.length)];
  const pathPhase = Math.PI / 4 + randRange(-0.5, 0.5);

  // Randomize cognitive task
  const cogTargetColors = ['#ff4444', '#4488ff', '#00e87b'];
  const cogTargetColorNames = ['RED', 'BLUE', 'GREEN'];
  const colorIdx = Math.floor(Math.random() * 3);
  const targetColor = cogTargetColors[colorIdx];
  const targetColorName = cogTargetColorNames[colorIdx];
  const targetCount = 2 + Math.floor(Math.random() * 4); // 2-5
  const cogFlashCount = 8;

  const colors = [];
  for (let i = 0; i < targetCount; i++) colors.push(targetColor);
  const distractors = cogTargetColors.filter((_, i) => i !== colorIdx);
  for (let i = colors.length; i < cogFlashCount; i++) {
    colors.push(distractors[Math.floor(Math.random() * distractors.length)]);
  }
  for (let i = colors.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [colors[i], colors[j]] = [colors[j], colors[i]];
  }

  const cogGap = dualtaskDuration / (cogFlashCount + 1);
  const cogFlashes = [];
  for (let i = 0; i < cogFlashCount; i++) {
    cogFlashes.push({
      offsetMs: Math.round(cogGap * (i + 1) + (Math.random() - 0.5) * cogGap * 0.3),
      number: Math.floor(Math.random() * 9) + 1,
      color: colors[i],
      isTarget: colors[i] === targetColor,
    });
  }

  const challenge = {
    challengeId,
    issuedAt: now,
    expiresAt: now + CHALLENGE_TTL_MS,
    freeMoveDuration,
    trackingDuration,
    dualtaskDuration,
    path: {
      freqX,
      freqY,
      phase: pathPhase,
      padding: 0.30,
    },
    perturbation: {
      probes,
      pulses,
      pulseHoldDuration,
      pulseReturnDuration,
    },
    cogTask: {
      targetColor,
      targetColorName,
      targetCount,
      flashDuration: 400,
      flashes: cogFlashes,
    },
    used: false,
  };

  challenges.set(challengeId, challenge);
  return challenge;
}


// ─── CLIENT PARAMS ──────────────────────────────────────────
// AGENT COOKIE CRUMB: The client receives ONLY what it needs to render
// the task. Scoring thresholds, weights, and analysis details are NOT sent.

function clientParams(challenge) {
  return {
    challengeId: challenge.challengeId,
    freeMoveDuration: challenge.freeMoveDuration,
    trackingDuration: challenge.trackingDuration,
    dualtaskDuration: challenge.dualtaskDuration,
    path: challenge.path,
    perturbation: {
      probes: challenge.perturbation.probes,
      pulses: challenge.perturbation.pulses,
      pulseHoldDuration: challenge.perturbation.pulseHoldDuration,
      pulseReturnDuration: challenge.perturbation.pulseReturnDuration,
    },
    cogTask: {
      targetColor: challenge.cogTask.targetColor,
      targetColorName: challenge.cogTask.targetColorName,
      flashDuration: challenge.cogTask.flashDuration,
      flashes: challenge.cogTask.flashes,
    },
  };
}


// ─── EMBED CHALLENGE GENERATION ─────────────────────────────
// AGENT COOKIE CRUMB: Embed challenges use smaller perturbation amplitudes
// (1-2px multi-sine, 3-5px pulses) so they're imperceptible when applied
// as CSS transforms to hovered elements. No path params (element center
// is the target). No cognitive task. Pulses are spaced in cumulative
// hover-time domain — they fire after enough hover interaction.

function generateEmbedChallenge() {
  const challengeId = crypto.randomBytes(16).toString("hex");
  const now = Date.now();

  // Sub-perceptual probe amplitudes: 0.15-0.35px per probe.
  // With 5 probes at different frequencies, peak sum ≈ 1.0-1.75px — below
  // conscious perception threshold (~2px on standard displays). RMS displacement
  // is ~0.5px. Browsers render sub-pixel CSS transforms accurately, and 500+
  // samples over 8s hover gives the FFT enough data to extract coherent signal
  // at these amplitudes. The goal: zero visual artifact, measurable visuomotor coupling.
  const probeFreqsPicked = pickRandom(FREQ_POOL, 5).sort((a, b) => a - b);
  const probes = probeFreqsPicked.map(freq => ({
    freq,
    ampX: +(randRange(0.15, 0.35)).toFixed(3),
    ampY: +(randRange(0.05, 0.15)).toFixed(3),
    phaseOffset: Math.PI / 3 + randRange(-0.3, 0.3),
  }));

  // Embed pulses: 1.0-2.0px amplitude (was 3-5px). At ~0.3-0.7mm on screen,
  // this is below conscious detection but within the visuomotor system's
  // sensitivity range. The unconscious correction arc still produces measurable
  // phase delay and cross-axis coupling. Spaced every ~2s of cumulative hover time.
  const pulseCount = Math.floor(randRange(4, 6));
  const pulseSpacing = 2000; // ms of hover time between pulses
  const pulseHoldDuration = Math.round(randRange(400, 600));
  const pulseReturnDuration = 150;
  const pulses = [];
  for (let i = 0; i < pulseCount; i++) {
    const hoverTimeMs = pulseSpacing * (i + 1) + Math.round(randRange(-200, 200));
    const dir = (i % 3 === 2) ? -1 : 1;
    pulses.push({
      hoverTimeMs,
      ampX: +(randRange(1.0, 2.0)).toFixed(2) * dir,
      ampY: 0,
    });
  }

  const challenge = {
    challengeId,
    issuedAt: now,
    expiresAt: now + CHALLENGE_TTL_MS * 2, // Embed gets longer TTL (6 min) — users browse at their own pace
    mode: "embed",
    perturbation: {
      probes,
      pulses,
      pulseHoldDuration,
      pulseReturnDuration,
    },
    used: false,
  };

  challenges.set(challengeId, challenge);
  return challenge;
}

/**
 * Client params for embed mode — only what the library needs to apply perturbations.
 */
function embedClientParams(challenge) {
  return {
    challengeId: challenge.challengeId,
    perturbation: {
      probes: challenge.perturbation.probes,
      pulses: challenge.perturbation.pulses,
      pulseHoldDuration: challenge.perturbation.pulseHoldDuration,
      pulseReturnDuration: challenge.perturbation.pulseReturnDuration,
    },
  };
}


// ─── ENDPOINT HANDLERS ──────────────────────────────────────

async function handleChallenge(_req, res) {
  const challenge = generateChallenge();
  const token = makeToken({ challengeId: challenge.challengeId, expiresAt: challenge.expiresAt });

  console.log(`[clnp] Challenge ${challenge.challengeId.slice(0, 8)} created — ` +
    `probes: [${challenge.perturbation.probes.map(p => p.freq).join(', ')}]Hz, ` +
    `${challenge.perturbation.pulses.length} pulses, ` +
    `path: ${challenge.path.freqX}/${challenge.path.freqY}Hz, ` +
    `cog: ${challenge.cogTask.targetCount} ${challenge.cogTask.targetColorName}`);

  json(res, 200, {
    ok: true,
    token,
    challenge: clientParams(challenge),
  });
}

async function handleVerify(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    json(res, 400, { ok: false, error: err.message }); return;
  }

  // Verify token
  const tokenData = verifyToken(body.token);
  if (!tokenData) {
    json(res, 401, { ok: false, error: "invalid_token" }); return;
  }

  const challenge = challenges.get(tokenData.challengeId);
  if (!challenge) {
    json(res, 404, { ok: false, error: "challenge_not_found" }); return;
  }
  if (challenge.used) {
    json(res, 409, { ok: false, error: "challenge_already_used" }); return;
  }
  if (Date.now() > challenge.expiresAt) {
    challenge.used = true;
    json(res, 410, { ok: false, error: "challenge_expired" }); return;
  }

  // Mark as used
  challenge.used = true;
  challenge.usedAt = Date.now();

  // Validate raw data shape
  if (!Array.isArray(body.pointer) || body.pointer.length < 50) {
    json(res, 400, { ok: false, error: "insufficient_pointer_data" }); return;
  }
  if (!body.phases || !body.phases.trackingStart || !body.phases.dualtaskStart) {
    json(res, 400, { ok: false, error: "missing_phases" }); return;
  }
  if (!body.canvas || !body.canvas.width || !body.canvas.height) {
    json(res, 400, { ok: false, error: "missing_canvas" }); return;
  }

  // Run analysis
  const rawData = {
    pointer: body.pointer,
    accel: Array.isArray(body.accel) ? body.accel : [],
    phases: body.phases,
    canvas: body.canvas,
    inputMethod: body.inputMethod || "unknown",
    cogAnswer: typeof body.cogAnswer === "number" ? body.cogAnswer : null,
  };

  let result;
  try {
    result = analyze(rawData, challenge);
  } catch (err) {
    console.error(`[clnp] Analysis error for ${challenge.challengeId.slice(0, 8)}:`, err.message);
    json(res, 500, { ok: false, error: "analysis_failed" }); return;
  }

  // Generate signed receipt
  const receipt = makeToken({
    challengeId: challenge.challengeId,
    verified: result.overall >= 0.65,
    score: Number(result.overall.toFixed(3)),
    verdict: result.verdict,
    verifiedAt: Date.now(),
  });

  console.log(`[clnp] Verify ${challenge.challengeId.slice(0, 8)} — ` +
    `${result.verdict} (${Math.round(result.overall * 100)}%) ` +
    `[${result.sampleCount} samples, ${result.sampleRate}Hz, ${rawData.inputMethod}]`);

  // Log session for ML data collection
  logSession({
    id: crypto.randomBytes(8).toString("hex"),
    ts: Date.now(),
    tsISO: new Date().toISOString(),
    mode: "standalone",
    challengeId: challenge.challengeId,
    inputMethod: result.inputMethod,
    overall: result.overall,
    verdict: result.verdict,
    verdictClass: result.verdictClass,
    scores: result.scores,
    sampleRate: result.sampleRate,
    sampleCount: result.sampleCount,
    validCount: result.validCount,
    ipHash: hashIP(getClientIP(req)),
    userAgent: req.headers["user-agent"] || "unknown",
  });

  json(res, 200, {
    ok: true,
    challengeId: challenge.challengeId,
    overall: result.overall,
    verdict: result.verdict,
    verdictClass: result.verdictClass,
    scores: result.scores,
    validCount: result.validCount,
    sampleRate: result.sampleRate,
    sampleCount: result.sampleCount,
    inputMethod: result.inputMethod,
    receipt,
  });
}


// ─── EMBED ENDPOINT HANDLERS ────────────────────────────────

async function handleEmbedChallenge(_req, res) {
  const challenge = generateEmbedChallenge();
  const token = makeToken({ challengeId: challenge.challengeId, expiresAt: challenge.expiresAt });

  console.log(`[clnp-embed] Challenge ${challenge.challengeId.slice(0, 8)} created — ` +
    `probes: [${challenge.perturbation.probes.map(p => p.freq).join(', ')}]Hz, ` +
    `${challenge.perturbation.pulses.length} pulses (hover-time spaced)`);

  json(res, 200, {
    ok: true,
    token,
    challenge: embedClientParams(challenge),
  });
}

async function handleEmbedVerify(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    json(res, 400, { ok: false, error: err.message }); return;
  }

  // Verify token
  const tokenData = verifyToken(body.token);
  if (!tokenData) {
    json(res, 401, { ok: false, error: "invalid_token" }); return;
  }

  const challenge = challenges.get(tokenData.challengeId);
  if (!challenge) {
    json(res, 404, { ok: false, error: "challenge_not_found" }); return;
  }
  if (challenge.mode !== "embed") {
    json(res, 400, { ok: false, error: "wrong_challenge_mode" }); return;
  }
  if (challenge.used) {
    json(res, 409, { ok: false, error: "challenge_already_used" }); return;
  }
  if (Date.now() > challenge.expiresAt) {
    challenge.used = true;
    json(res, 410, { ok: false, error: "challenge_expired" }); return;
  }

  // Mark as used
  challenge.used = true;
  challenge.usedAt = Date.now();

  // Validate embed raw data shape
  if (!Array.isArray(body.pointer) || body.pointer.length < 30) {
    json(res, 400, { ok: false, error: "insufficient_pointer_data" }); return;
  }
  if (!Array.isArray(body.elements) || body.elements.length < 1) {
    json(res, 400, { ok: false, error: "missing_elements" }); return;
  }

  // Run embed analysis
  const rawData = {
    pointer: body.pointer,
    accel: Array.isArray(body.accel) ? body.accel : [],
    hovers: Array.isArray(body.hovers) ? body.hovers : [],
    pulseLog: Array.isArray(body.pulseLog) ? body.pulseLog : [],
    elements: body.elements,
    inputMethod: body.inputMethod || "unknown",
  };

  let result;
  try {
    result = analyzeEmbed(rawData, challenge);
  } catch (err) {
    console.error(`[clnp-embed] Analysis error for ${challenge.challengeId.slice(0, 8)}:`, err.message);
    json(res, 500, { ok: false, error: "analysis_failed" }); return;
  }

  // Generate signed receipt
  const receipt = makeToken({
    challengeId: challenge.challengeId,
    mode: "embed",
    verified: result.overall >= 0.60,
    score: Number(result.overall.toFixed(3)),
    verdict: result.verdict,
    verifiedAt: Date.now(),
  });

  console.log(`[clnp-embed] Verify ${challenge.challengeId.slice(0, 8)} — ` +
    `${result.verdict} (${Math.round(result.overall * 100)}%) ` +
    `[${result.sampleCount} samples, ${result.sampleRate}Hz, ` +
    `${result.totalHoverTime}ms hover, ${result.uniqueElements} elements, ${rawData.inputMethod}]`);

  // Log session for ML data collection
  logSession({
    id: crypto.randomBytes(8).toString("hex"),
    ts: Date.now(),
    tsISO: new Date().toISOString(),
    mode: "embed",
    challengeId: challenge.challengeId,
    inputMethod: result.inputMethod,
    overall: result.overall,
    verdict: result.verdict,
    verdictClass: result.verdictClass,
    scores: result.scores,
    sampleRate: result.sampleRate,
    sampleCount: result.sampleCount,
    totalHoverTime: result.totalHoverTime,
    uniqueElements: result.uniqueElements,
    plausible: result.plausible,
    validCount: result.validCount,
    ipHash: hashIP(getClientIP(req)),
    userAgent: req.headers["user-agent"] || "unknown",
    deviceProfile: body.deviceProfile || null,
  });

  json(res, 200, {
    ok: true,
    challengeId: challenge.challengeId,
    mode: "embed",
    overall: result.overall,
    verdict: result.verdict,
    verdictClass: result.verdictClass,
    scores: result.scores,
    validCount: result.validCount,
    sampleRate: result.sampleRate,
    sampleCount: result.sampleCount,
    totalHoverTime: result.totalHoverTime,
    uniqueElements: result.uniqueElements,
    plausible: result.plausible,
    inputMethod: result.inputMethod,
    receipt,
  });
}


// ─── STATIC FILE SERVING ────────────────────────────────────

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) { json(res, 404, { ok: false, error: "not_found" }); return; }
    res.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(data);
  });
}


// ─── REQUEST ROUTER ─────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const method = req.method || "GET";
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  // CORS preflight
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    });
    res.end();
    return;
  }

  if (method === "GET" && (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/clnp-probe.html")) {
    serveFile(res, path.join(ROOT, "clnp-probe.html"), "text/html; charset=utf-8");
    return;
  }

  // Serve embed files
  if (method === "GET" && url.pathname === "/clnp-embed.js") {
    serveFile(res, path.join(ROOT, "clnp-embed.js"), "application/javascript; charset=utf-8");
    return;
  }
  if (method === "GET" && url.pathname === "/clnp-embed-demo.html") {
    serveFile(res, path.join(ROOT, "clnp-embed-demo.html"), "text/html; charset=utf-8");
    return;
  }

  // Standalone API
  if (method === "POST" && url.pathname === "/api/challenge") {
    await handleChallenge(req, res);
    return;
  }
  if (method === "POST" && url.pathname === "/api/verify") {
    await handleVerify(req, res);
    return;
  }

  // Embed API
  if (method === "POST" && url.pathname === "/api/embed/challenge") {
    await handleEmbedChallenge(req, res);
    return;
  }
  if (method === "POST" && url.pathname === "/api/embed/verify") {
    await handleEmbedVerify(req, res);
    return;
  }

  if (method === "GET" && url.pathname === "/api/health") {
    json(res, 200, { ok: true, uptimeSec: Number(process.uptime().toFixed(1)), pendingChallenges: challenges.size });
    return;
  }

  // ─── ADMIN ENDPOINTS ──────────────────────────────────────
  // AGENT COOKIE CRUMB: All /admin and /api/admin/* routes require
  // CLNP_ADMIN_TOKEN via Bearer header or ?token= query param.
  // These endpoints read the JSONL session log for stats/browsing.

  if (method === "GET" && url.pathname === "/admin") {
    const auth = authenticateAdmin(req, url);
    if (!auth.ok) { json(res, auth.status, { ok: false, error: auth.error }); return; }
    serveFile(res, path.join(ROOT, "clnp-admin.html"), "text/html; charset=utf-8");
    return;
  }

  if (method === "GET" && url.pathname === "/api/admin/stats") {
    const auth = authenticateAdmin(req, url);
    if (!auth.ok) { json(res, auth.status, { ok: false, error: auth.error }); return; }
    const sessions = readAllSessions();
    const stats = computeAdminStats(sessions);
    json(res, 200, { ok: true, ...stats });
    return;
  }

  if (method === "GET" && url.pathname === "/api/admin/sessions") {
    const auth = authenticateAdmin(req, url);
    if (!auth.ok) { json(res, auth.status, { ok: false, error: auth.error }); return; }
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 50));
    const offset = Math.max(0, Number(url.searchParams.get("offset")) || 0);
    const sessions = readAllSessions();
    // Return newest first, lightweight (flatten scores to key→number)
    const sorted = sessions.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    const page = sorted.slice(offset, offset + limit).map(s => {
      const flatScores = {};
      if (s.scores) {
        for (const [k, v] of Object.entries(s.scores)) {
          flatScores[k] = typeof v === "object" ? +(v.score || 0).toFixed(3) : +(v || 0).toFixed(3);
        }
      }
      return {
        id: s.id, ts: s.ts, tsISO: s.tsISO, mode: s.mode,
        inputMethod: s.inputMethod, overall: s.overall,
        verdict: s.verdict, verdictClass: s.verdictClass,
        scores: flatScores, sampleRate: s.sampleRate,
        sampleCount: s.sampleCount, validCount: s.validCount,
        ipHash: s.ipHash,
      };
    });
    json(res, 200, { ok: true, total: sessions.length, offset, limit, sessions: page });
    return;
  }

  if (method === "GET" && url.pathname.startsWith("/api/admin/session/")) {
    const auth = authenticateAdmin(req, url);
    if (!auth.ok) { json(res, auth.status, { ok: false, error: auth.error }); return; }
    const sessionId = url.pathname.split("/api/admin/session/")[1];
    if (!sessionId) { json(res, 400, { ok: false, error: "missing_session_id" }); return; }
    const sessions = readAllSessions();
    const session = sessions.find(s => s.id === sessionId);
    if (!session) { json(res, 404, { ok: false, error: "session_not_found" }); return; }
    json(res, 200, { ok: true, session });
    return;
  }

  if (method === "GET" && url.pathname === "/favicon.ico") {
    res.writeHead(204, { "Cache-Control": "public, max-age=604800" });
    res.end();
    return;
  }

  json(res, 404, { ok: false, error: "not_found" });
});


// ─── CLEANUP ────────────────────────────────────────────────

function cleanupChallenges() {
  const now = Date.now();
  for (const [id, rec] of challenges) {
    if (rec.used && rec.usedAt && now - rec.usedAt > 10 * 60 * 1000) { challenges.delete(id); continue; }
    if (now > rec.expiresAt + 60 * 1000) challenges.delete(id);
  }
}

setInterval(cleanupChallenges, CLEANUP_INTERVAL_MS).unref();


// ─── START ──────────────────────────────────────────────────

server.listen(PORT, HOST, () => {
  console.log(`[clnp] Server listening on http://${HOST}:${PORT}`);
  console.log(`[clnp] Scoring thresholds are SERVER-SIDE ONLY — not sent to clients`);
  console.log(`[clnp] Data directory: ${DATA_DIR}`);
  console.log(`[clnp] Admin dashboard: ${CLNP_ADMIN_TOKEN ? "enabled (token set)" : "disabled (no CLNP_ADMIN_TOKEN)"}`);
});
