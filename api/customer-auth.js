// api/_lib/customer-auth.js
// Mirrors the admin auth.js pattern but with its own secret, so a customer
// session token can never be confused with (or misused as) an admin token.

const crypto = require('crypto');

const CUSTOMER_SECRET = process.env.CUSTOMER_SECRET;
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — customers shouldn't have to re-login constantly

function signCustomerToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', CUSTOMER_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyCustomerToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', CUSTOMER_SECRET).update(body).digest('base64url');

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

function requireCustomerAuth(req, res) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  const payload = verifyCustomerToken(token);
  if (!payload) {
    res.status(401).json({ error: 'Session expired, please sign in again.' });
    return null;
  }
  return payload;
}

module.exports = { signCustomerToken, verifyCustomerToken, requireCustomerAuth, TOKEN_TTL_MS };
