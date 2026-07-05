const crypto = require('crypto');

const PHONE_TOKEN_SECRET = process.env.CUSTOMER_SECRET; // reuse existing secret, no new env var needed
const PHONE_TOKEN_TTL_MS = 15 * 60 * 1000; // proof of phone verification is valid for 15 min

function signPhoneToken(phone) {
  const payload = { phone, exp: Date.now() + PHONE_TOKEN_TTL_MS };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', PHONE_TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyPhoneToken(token, expectedPhone) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [body, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', PHONE_TOKEN_SECRET).update(body).digest('base64url');
  if (sig !== expectedSig) return false;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return false;
  }
  if (!payload.exp || Date.now() > payload.exp) return false;
  if (payload.phone !== expectedPhone) return false;
  return true;
}

/* Decode (not verify -- MSG91's API call below is what actually verifies
   authenticity) the JWT payload just to read which identifier it covers. */
function decodeJwtPayload(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    return null;
  }
}

/* Exported so customers.js can gate signup on a verified phone. */
function requirePhoneVerification(req, phone) {
  const token = req.headers['x-phone-verify-token'];
  return verifyPhoneToken(token, phone);
}

async function handleVerifyWidgetToken(req, res) {
  const { accessToken, phone } = req.body || {};
  if (!accessToken || !/^[6-9]\d{9}$/.test(phone || '')) {
    return res.status(400).json({ error: 'accessToken and a valid phone are required' });
  }

  const payload = decodeJwtPayload(accessToken);
  const identifier = payload && (payload.identifier || payload.mobile || payload.phone);
  if (identifier && !String(identifier).includes(phone)) {
    return res.status(400).json({ error: 'Token does not match this phone number' });
  }

  try {
    const r = await fetch('https://control.msg91.com/api/v5/widget/verifyAccessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        authkey: process.env.MSG91_AUTH_KEY,
        'access-token': accessToken,
      }),
    });
    const data = await r.json();
    if (data.type !== 'success') {
      return res.status(400).json({ error: data.message || 'Phone verification failed' });
    }
    const token = signPhoneToken(phone);
    return res.status(200).json({ verified: true, token });
  } catch (e) {
    return res.status(502).json({ error: 'MSG91 unreachable, please try again' });
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  if (req.query.action === 'verify-widget-token') {
    return handleVerifyWidgetToken(req, res);
  }
  return res.status(400).json({ error: 'Unknown action' });
};

module.exports.requirePhoneVerification = requirePhoneVerification;
