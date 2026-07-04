// api/_lib/auth.js
// Shared session-token helpers. Vercel ignores folders starting with "_",
// so this file is NOT its own endpoint — it's imported by admin.js,
// products.js, pages.js, and assistant.js.

const crypto = require('crypto');

const ADMIN_SECRET = process.env.ADMIN_SECRET;
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

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

// Call at the top of any protected handler. Returns the session payload
// if valid, or sends a 401 and returns null if not (caller should then
// just `return` without sending anything else).
function requireAuth(req, res) {
  const token = getBearerToken(req);
  const session = verifyToken(token);
  if (!session) {
    res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
    return null;
  }
  return session;
}

module.exports = { signToken, verifyToken, getBearerToken, requireAuth, TOKEN_TTL_MS };
