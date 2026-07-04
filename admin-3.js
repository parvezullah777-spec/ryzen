// api/admin.js
// Login + dashboard summary. Products, Pages, and the AI Assistant each
// live in their own file (products.js, pages.js, assistant.js) and share
// the auth/github helpers in api/_lib/.

const { signToken, requireAuth, TOKEN_TTL_MS } = require('./_lib/auth');
const { getJSON } = require('./_lib/github');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

async function handleLogin(req, res) {
  const { password } = req.body || {};

  if (!ADMIN_PASSWORD || !ADMIN_SECRET) {
    return res.status(500).json({
      error: 'Server not configured: ADMIN_PASSWORD and/or ADMIN_SECRET missing in Vercel environment variables.',
    });
  }

  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  const token = signToken({ role: 'admin', exp: Date.now() + TOKEN_TTL_MS });
  return res.status(200).json({ token, expiresInMs: TOKEN_TTL_MS });
}

async function handleDashboard(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  let productCount = 0;
  let pageCount = 0;

  try {
    const { data: products } = await getJSON('products.json');
    productCount = Array.isArray(products) ? products.length : 0;
  } catch (err) {
    console.error('dashboard: products.json read failed:', err.message);
  }

  try {
    const { data: pages } = await getJSON('pages.json');
    pageCount = Array.isArray(pages) ? pages.length : 0;
  } catch (err) {
    console.error('dashboard: pages.json read failed:', err.message);
  }

  return res.status(200).json({
    stats: { products: productCount, pages: pageCount, orders: 0 },
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'POST' && action === 'login') return await handleLogin(req, res);
    if (req.method === 'GET' && action === 'dashboard') return await handleDashboard(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('admin.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
