const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "127.0.0.1";
const ROOT = __dirname;
const INDEX_PATH = path.join(ROOT, "index.html");

const CHALLENGE_TTL_MS = Number(process.env.CHALLENGE_TTL_MS || 120000);
const CLEANUP_INTERVAL_MS = 30000;
const MAX_BODY_BYTES = 1024 * 1024;

const secretString = process.env.LIVENESS_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.LIVENESS_SECRET) {
  console.warn("[liveness] LIVENESS_SECRET not set; using ephemeral secret for this process only.");
}
const HMAC_SECRET = Buffer.from(secretString, "utf8");

const challenges = new Map();

function b64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(input) {
  const pad = input.length % 4 ? "=".repeat(4 - (input.length % 4)) : "";
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function signPayload(payloadB64) {
  const sig = crypto.createHmac("sha256", HMAC_SECRET).update(payloadB64).digest();
  return b64urlEncode(sig);
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function json(res, statusCode, body, cacheControl = "no-store") {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": cacheControl,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer"
  });
  res.end(JSON.stringify(body));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    let body = "";
    req.on("data", chunk => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (_err) {
        reject(new Error("invalid_json"));
      }
    });
    req.on("error", () => reject(new Error("read_error")));
  });
}

function createChallenge() {
  const now = Date.now();
  const expiresAt = now + CHALLENGE_TTL_MS;
  const challengeId = crypto.randomBytes(12).toString("hex");
  const nonce = crypto.randomBytes(8).toString("hex");
  const seed = crypto.randomBytes(4).readUInt32BE(0);

  const payload = {
    v: 1,
    challengeId,
    seed,
    nonce,
    issuedAt: now,
    expiresAt
  };

  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  const token = `${payloadB64}.${signPayload(payloadB64)}`;

  challenges.set(challengeId, {
    challengeId,
    issuedAt: now,
    expiresAt,
    seed,
    tokenHash: sha256Hex(token),
    used: false,
    usedAt: 0
  });

  return { payload, token };
}

function parseAndVerifyToken(token) {
  if (typeof token !== "string") return { ok: false, reason: "token_missing" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "token_format" };

  const [payloadB64, signature] = parts;
  const expected = signPayload(payloadB64);

  const sigBuf = Buffer.from(signature, "utf8");
  const expBuf = Buffer.from(expected, "utf8");
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { ok: false, reason: "token_signature" };
  }

  try {
    const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
    if (!payload || !payload.challengeId || !Number.isFinite(payload.seed)) {
      return { ok: false, reason: "token_payload" };
    }
    return { ok: true, payload };
  } catch (_err) {
    return { ok: false, reason: "token_decode" };
  }
}

function assessReport(report) {
  const hardFails = [];
  const warnings = [];

  if (!report || typeof report !== "object") {
    return { verified: false, reason: "report_missing", hardFails: ["missing_report"], warnings: [] };
  }

  const score = Number(report.score);
  const digest = typeof report.digest === "string" ? report.digest : "";
  const perturbationCount = Array.isArray(report.perturbations)
    ? report.perturbations.length
    : Number(report?.summary?.perturbationCount || 0);
  const correctionCount = Array.isArray(report.corrections)
    ? report.corrections.filter(c => Number.isFinite(c?.latencyMs)).length
    : Number(report?.summary?.correctionCount || 0);
  const meanSampleHz = Number(report?.summary?.meanSampleHz || 0);

  if (!digest || digest.length < 10) hardFails.push("digest_missing");
  if (!Number.isFinite(score) || score < 0 || score > 100) hardFails.push("score_invalid");
  if (perturbationCount < 5) hardFails.push("too_few_perturbations");
  if (correctionCount < 2) hardFails.push("too_few_corrections");
  if (meanSampleHz < 8 || meanSampleHz > 300) hardFails.push("sample_rate_out_of_bounds");

  if (score < 48) warnings.push("score_low");
  if (correctionCount / Math.max(1, perturbationCount) < 0.35) warnings.push("weak_correction_ratio");

  const verified = hardFails.length === 0 && score >= 35;
  let reason = "ok";
  if (!verified) reason = hardFails[0] || (score < 35 ? "score_very_low" : "unverified");
  else if (warnings.length) reason = warnings[0];

  return {
    verified,
    reason,
    hardFails,
    warnings,
    score,
    digest,
    perturbationCount,
    correctionCount,
    meanSampleHz
  };
}

function makeReceipt(data) {
  const payload = {
    v: 1,
    challengeId: data.challengeId,
    verified: data.verified,
    reason: data.reason,
    score: Number.isFinite(data.score) ? Number(data.score.toFixed(2)) : null,
    digest: data.digest || null,
    verifiedAt: Date.now()
  };
  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  return `${payloadB64}.${signPayload(payloadB64)}`;
}

function cleanupChallenges() {
  const now = Date.now();
  for (const [id, rec] of challenges) {
    if (rec.used && rec.usedAt && now - rec.usedAt > 10 * 60 * 1000) {
      challenges.delete(id);
      continue;
    }
    if (now > rec.expiresAt + 60 * 1000) challenges.delete(id);
  }
}

function serveIndex(res) {
  fs.readFile(INDEX_PATH, (err, data) => {
    if (err) {
      json(res, 500, { ok: false, error: "index_read_failed" });
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;"
    });
    res.end(data);
  });
}

async function handleChallenge(_req, res) {
  const c = createChallenge();
  json(res, 200, { ok: true, challenge: c.payload, token: c.token });
}

async function handleVerify(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    json(res, 400, { ok: false, error: err.message || "bad_request" });
    return;
  }

  const parsed = parseAndVerifyToken(body.token);
  if (!parsed.ok) {
    json(res, 401, { ok: false, error: parsed.reason });
    return;
  }

  const payload = parsed.payload;
  const rec = challenges.get(payload.challengeId);
  if (!rec) {
    json(res, 404, { ok: false, error: "challenge_not_found" });
    return;
  }

  if (rec.used) {
    json(res, 409, { ok: false, error: "challenge_already_used" });
    return;
  }

  if (Date.now() > rec.expiresAt) {
    rec.used = true;
    rec.usedAt = Date.now();
    json(res, 410, { ok: false, error: "challenge_expired" });
    return;
  }

  if (sha256Hex(body.token) !== rec.tokenHash) {
    rec.used = true;
    rec.usedAt = Date.now();
    json(res, 401, { ok: false, error: "challenge_token_mismatch" });
    return;
  }

  const assessed = assessReport(body.report);
  rec.used = true;
  rec.usedAt = Date.now();

  const receipt = makeReceipt({
    challengeId: payload.challengeId,
    verified: assessed.verified,
    reason: assessed.reason,
    score: assessed.score,
    digest: assessed.digest
  });

  json(res, 200, {
    ok: true,
    challengeId: payload.challengeId,
    verified: assessed.verified,
    reason: assessed.reason,
    hardFails: assessed.hardFails,
    warnings: assessed.warnings,
    receipt
  });
}

const server = http.createServer(async (req, res) => {
  const method = req.method || "GET";
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    serveIndex(res);
    return;
  }

  if (method === "GET" && url.pathname === "/api/challenge") {
    await handleChallenge(req, res);
    return;
  }

  if (method === "POST" && url.pathname === "/api/verify") {
    await handleVerify(req, res);
    return;
  }

  if (method === "GET" && url.pathname === "/healthz") {
    json(res, 200, {
      ok: true,
      uptimeSec: Number(process.uptime().toFixed(1)),
      pendingChallenges: challenges.size
    });
    return;
  }

  if (method === "GET" && url.pathname === "/favicon.ico") {
    res.writeHead(204, { "Cache-Control": "public, max-age=604800" });
    res.end();
    return;
  }

  json(res, 404, { ok: false, error: "not_found" });
});

setInterval(cleanupChallenges, CLEANUP_INTERVAL_MS).unref();

server.listen(PORT, HOST, () => {
  console.log(`[liveness] listening on http://${HOST}:${PORT}`);
});
