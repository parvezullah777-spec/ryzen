// api/admin.js
// Login + dashboard summary + login history.

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

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : null;
}

async function logAttempt(req, { username, role, success, reason }) {
  try {
    await supabase.from('login_logs').insert([{
      username: username || null,
      role: role || null,
      ip_address: getClientIp(req),
      user_agent: req.headers['user-agent'] || null,
      success: !!success,
      reason: reason || null,
    }]);
  } catch (err) {
    console.error('login_logs insert failed:', err.message);
  }
}

async function handleLogin(req, res) {
  const { username, password } = req.body || {};

  if (!ADMIN_SECRET) {
    return res.status(500).json({
      error: 'Server not configured: ADMIN_SECRET missing in Vercel environment variables.',
    });
  }

  if (!password) {
    await logAttempt(req, { username, success: false, reason: 'missing_password' });
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
      await logAttempt(req, { username, success: false, reason: 'bad_credentials' });
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }

    const token = signToken({
      role: admin.role,
      username: admin.username,
      permissions: admin.role === 'super_admin' ? FULL_PERMISSIONS : (admin.permissions || {}),
      exp: Date.now() + TOKEN_TTL_MS,
    });
    await logAttempt(req, { username: admin.username, role: admin.role, success: true });
    return res.status(200).json({ token, expiresInMs: TOKEN_TTL_MS, role: admin.role });
  }

  if (!ADMIN_PASSWORD) {
    return res.status(500).json({
      error: 'Server not configured: ADMIN_PASSWORD missing in Vercel environment variables.',
    });
  }
  if (password !== ADMIN_PASSWORD) {
    await logAttempt(req, { username: 'owner', success: false, reason: 'bad_bootstrap_password' });
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  const token = signToken({
    role: 'super_admin',
    username: 'owner',
    permissions: FULL_PERMISSIONS,
    exp: Date.now() + TOKEN_TTL_MS,
  });
  await logAttempt(req, { username: 'owner', role: 'super_admin', success: true });
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

async function handleLoginLogs(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the super admin can view login history.' });
  }

  const { data, error } = await supabase
    .from('login_logs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) throw error;
  return res.status(200).json({ logs: data });
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
    if (req.method === 'GET' && action === 'login-logs') return await handleLoginLogs(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('admin.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
