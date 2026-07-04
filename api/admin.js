// api/admin.js
// Login + dashboard summary.

const { signToken, requireAuth, TOKEN_TTL_MS } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');
const { verifyPassword } = require('./_lib/passwords');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; // bootstrap fallback only
const ADMIN_SECRET = process.env.ADMIN_SECRET;

const FULL_PERMISSIONS = {
  products: { view: true, edit: true, delete: true },
  pages: { view: true, edit: true, delete: true },
  orders: { view: true, edit: true },
  traffic: { view: true },
  admins: { view: true, edit: true, delete: true },
};

async function handleLogin(req, res) {
  const { username, password } = req.body || {};

  if (!ADMIN_SECRET) {
    return res.status(500).json({
      error: 'Server not configured: ADMIN_SECRET missing in Vercel environment variables.',
    });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password is required.' });
  }

  if (username) {
    const { data: admin, error } = await supabase
      .from('admins')
      .select('*')
      .eq('username', username)
      .maybeSingle();

    if (error) throw error;
    if (!admin || !verifyPassword(password, admin.password_hash)) {
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }

    const token = signToken({
      role: admin.role,
      username: admin.username,
      permissions: admin.role === 'super_admin' ? FULL_PERMISSIONS : (admin.permissions || {}),
      exp: Date.now() + TOKEN_TTL_MS,
    });
    return res.status(200).json({ token, expiresInMs: TOKEN_TTL_MS, role: admin.role });
  }

  if (!ADMIN_PASSWORD) {
    return res.status(500).json({
      error: 'Server not configured: ADMIN_PASSWORD missing in Vercel environment variables.',
    });
  }
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  const token = signToken({
    role: 'super_admin',
    username: 'owner',
    permissions: FULL_PERMISSIONS,
    exp: Date.now() + TOKEN_TTL_MS,
  });
  return res.status(200).json({ token, expiresInMs: TOKEN_TTL_MS, role: 'super_admin' });
}

async function handleDashboard(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  let productCount = 0;
  let pageCount = 0;

  try {
    const { count } = await supabase.from('products').select('*', { count: 'exact', head: true });
    productCount = count || 0;
  } catch (err) {
    console.error('dashboard: products count failed:', err.message);
  }

  try {
    const { count } = await supabase.from('pages').select('*', { count: 'exact', head: true });
    pageCount = count || 0;
  } catch (err) {
    console.error('dashboard: pages count failed:', err.message);
  }

  return res.status(200).json({
    stats: { products: productCount, pages: pageCount, orders: 0 },
    role: session.role,
    permissions: session.permissions || {},
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
