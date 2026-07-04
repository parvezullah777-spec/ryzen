// api/admin.js
// Core admin backend: login, session tokens, and dashboard summary.
// Products, Pages, and Face ID logic will live in their own files
// (products.js, pages.js, faceMatch.js) and get wired in as we build them.

const crypto = require('crypto');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_SECRET = process.env.ADMIN_SECRET; // used to sign session tokens

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

// ---------- Token helpers (no external deps, just Node's crypto) ----------

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', ADMIN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', ADMIN_SECRET).update(body).digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer (.+)$/);
  return match ? match[1] : null;
}

// ---------- GitHub helper (used for read-only dashboard stats here) ----------

async function githubGetFile(path) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}?ref=${GITHUB_BRANCH}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
    },
  });
  if (!res.ok) return null;
  const data = await res.json();
  const content = Buffer.from(data.content, 'base64').toString('utf8');
  return content;
}

// ---------- Route handlers ----------

async function handleLogin(req, res) {
  const { password } = req.body || {};

  if (!ADMIN_PASSWORD || !ADMIN_SECRET) {
    return res.status(500).json({
      error: 'Server not configured. Set ADMIN_PASSWORD and ADMIN_SECRET environment variables in Vercel.',
    });
  }

  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  const token = signToken({ role: 'admin', exp: Date.now() + TOKEN_TTL_MS });
  return res.status(200).json({ token, expiresInMs: TOKEN_TTL_MS });
}

async function handleDashboard(req, res) {
  const token = getBearerToken(req);
  const session = verifyToken(token);
  if (!session) {
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }

  let productCount = 0;
  try {
    const raw = await githubGetFile('products.json');
    if (raw) {
      const products = JSON.parse(raw);
      productCount = Array.isArray(products) ? products.length : 0;
    }
  } catch {
    // Non-fatal — dashboard still loads, just shows 0
  }

  return res.status(200).json({
    stats: {
      products: productCount,
      pages: 0, // wired up once pages.js exists
      orders: 0, // wired up once create-order.js is reconnected
    },
  });
}

// ---------- Entry point ----------

module.exports = async function handler(req, res) {
  // Basic CORS (same-origin in production, but keeps local testing easy)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'POST' && action === 'login') {
      return await handleLogin(req, res);
    }

    if (req.method === 'GET' && action === 'dashboard') {
      return await handleDashboard(req, res);
    }

    return res.status(400).json({ error: 'Unknown action.' });
  } catch (err) {
    console.error('admin.js error:', err);
    return res.status(500).json({ error: 'Unexpected server error.' });
  }
};
