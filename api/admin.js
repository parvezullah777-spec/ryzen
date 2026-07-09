// api/admin.js
// Login + dashboard summary.

const { signToken, requireAuth, TOKEN_TTL_MS } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');
const { verifyPassword } = require('./_lib/password');

const FULL_PERMISSIONS = {
  products: { view: true, edit: true, delete: true },
  pages: { view: true, edit: true, delete: true },
  orders: { view: true, edit: true },
  traffic: { view: true },
  admins: { view: true, edit: true, delete: true },
};

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

async function logLogin(adminId, req) {
  try {
    await supabase.from('admin_logins').insert({
      admin_id: adminId,
      ip_address: getClientIp(req),
      user_agent: req.headers['user-agent'] || 'unknown',
    });
  } catch (err) {
    console.error('logLogin failed:', err.message);
  }
}

async function sendTelegramAlert(admin, req, faceStatus) {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!token || !chatId) return;

    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    const time = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    const faceLine = faceStatus === 'mismatch'
      ? '\n⚠️ FACE MISMATCH'
      : faceStatus === 'verified'
      ? '\n✅ Face verified'
      : '';

    const message =
      `🔐 Ryzen Admin Login\n` +
      `User: ${admin.username} (${admin.role})\n` +
      `IP: ${ip}\n` +
      `Device: ${userAgent}\n` +
      `Time: ${time}${faceLine}`;

    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message }),
    });
  } catch (err) {
    console.error('sendTelegramAlert failed:', err.message);
  }
}

async function handleLogin(req, res) {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const { data: admin, error } = await supabase
    .from('admins')
    .select('*')
    .eq('username', username)
    .maybeSingle();

  if (error) throw error;

  if (!admin || !verifyPassword(password, admin.password_hash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  if (admin.deactivated_at) {
    return res.status(401).json({ error: 'This account has been deactivated.' });
  }

  await logLogin(admin.id, req);
  await sendTelegramAlert(admin, req);

  const token = signToken({
    sub: admin.id,
    role: admin.role,
    username: admin.username,
    permissions: admin.role === 'super_admin' ? FULL_PERMISSIONS : (admin.permissions || {}),
    exp: Date.now() + TOKEN_TTL_MS,
  });

  return res.status(200).json({
    token,
    expiresInMs: TOKEN_TTL_MS,
    role: admin.role,
    mustChangePassword: !!admin.must_change_password,
  });
}

async function handleDashboard(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { data: admin } = await supabase
    .from('admins')
    .select('deactivated_at')
    .eq('id', session.sub)
    .maybeSingle();

  if (admin?.deactivated_at) {
    return res.status(401).json({ error: 'This account has been deactivated.' });
  }

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
