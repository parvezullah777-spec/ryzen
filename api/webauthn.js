// api/webauthn.js
// WebAuthn (Face ID / Touch ID) registration and login.

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const { signToken, requireAuth, TOKEN_TTL_MS } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');
const { RP_NAME, getRpID, getOrigin } = require('./_lib/webauthn');

const FULL_PERMISSIONS = {
  products: { view: true, edit: true, delete: true },
  pages: { view: true, edit: true, delete: true },
  orders: { view: true, edit: true },
  traffic: { view: true },
  admins: { view: true, edit: true, delete: true },
};

// In-memory challenge store (fine for single-instance serverless with short TTL use)
const challenges = new Map();
function storeChallenge(key, challenge) {
  challenges.set(key, { challenge, expires: Date.now() + 5 * 60 * 1000 });
}
function takeChallenge(key) {
  const entry = challenges.get(key);
  challenges.delete(key);
  if (!entry || entry.expires < Date.now()) return null;
  return entry.challenge;
}

async function handleRegisterOptions(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { data: existing } = await supabase
    .from('admin_webauthn_credentials')
    .select('credential_id')
    .eq('admin_id', session.sub);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: getRpID(req),
    userID: Buffer.from(session.sub),
    userName: session.username,
    attestationType: 'none',
    excludeCredentials: (existing || []).map((c) => ({
      id: Buffer.from(c.credential_id, 'base64url'),
      type: 'public-key',
    })),
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // built-in Face ID/Touch ID, not USB keys
      userVerification: 'required',
    },
  });

  storeChallenge('reg:' + session.sub, options.challenge);
  return res.status(200).json(options);
}

async function handleRegisterVerify(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;

  const { response, deviceName } = req.body || {};
  const expectedChallenge = takeChallenge('reg:' + session.sub);
  if (!expectedChallenge) {
    return res.status(400).json({ error: 'Registration session expired. Try again.' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
    });
  } catch (err) {
    return res.status(400).json({ error: 'Verification failed: ' + err.message });
  }

  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ error: 'Could not verify device.' });
  }

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

  await supabase.from('admin_webauthn_credentials').insert({
    admin_id: session.sub,
    credential_id: Buffer.from(credentialID).toString('base64url'),
    public_key: Buffer.from(credentialPublicKey).toString('base64url'),
    counter,
    device_name: deviceName || 'Unnamed device',
  });

  return res.status(200).json({ ok: true });
}

async function handleLoginOptions(req, res) {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Username is required.' });

  const { data: admin } = await supabase
    .from('admins')
    .select('id, deactivated_at')
    .eq('username', username)
    .maybeSingle();

  if (!admin || admin.deactivated_at) {
    return res.status(401).json({ error: 'No Face ID set up for this account.' });
  }

  const { data: creds } = await supabase
    .from('admin_webauthn_credentials')
    .select('credential_id')
    .eq('admin_id', admin.id);

  if (!creds || !creds.length) {
    return res.status(404).json({ error: 'No Face ID registered for this account yet.' });
  }

  const options = await generateAuthenticationOptions({
    rpID: getRpID(req),
    userVerification: 'required',
    allowCredentials: creds.map((c) => ({
      id: Buffer.from(c.credential_id, 'base64url'),
      type: 'public-key',
    })),
  });

  storeChallenge('login:' + admin.id, options.challenge);
  storeChallenge('login-admin:' + options.challenge, admin.id); // reverse lookup for verify step

  return res.status(200).json({ options, adminId: admin.id });
}

async function handleLoginVerify(req, res) {
  const { response, adminId } = req.body || {};
  if (!response || !adminId) return res.status(400).json({ error: 'Missing verification data.' });

  const expectedChallenge = takeChallenge('login:' + adminId);
  if (!expectedChallenge) {
    return res.status(400).json({ error: 'Login session expired. Try again.' });
  }

  const { data: admin } = await supabase
    .from('admins')
    .select('*')
    .eq('id', adminId)
    .maybeSingle();

  if (!admin || admin.deactivated_at) {
    return res.status(401).json({ error: 'This account is unavailable.' });
  }

  const credentialIdB64 = Buffer.isBuffer(response.rawId)
    ? response.rawId.toString('base64url')
    : response.id;

  const { data: cred } = await supabase
    .from('admin_webauthn_credentials')
    .select('*')
    .eq('admin_id', adminId)
    .eq('credential_id', credentialIdB64)
    .maybeSingle();

  if (!cred) return res.status(400).json({ error: 'Unrecognized device.' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
      authenticator: {
        credentialID: Buffer.from(cred.credential_id, 'base64url'),
        credentialPublicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.counter,
      },
    });
  } catch (err) {
    return res.status(400).json({ error: 'Verification failed: ' + err.message });
  }

  if (!verification.verified) {
    return res.status(401).json({ error: 'Face ID verification failed.' });
  }

  await supabase
    .from('admin_webauthn_credentials')
    .update({ counter: verification.authenticationInfo.newCounter })
    .eq('id', cred.id);

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

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'POST' && action === 'register-options') return await handleRegisterOptions(req, res);
    if (req.method === 'POST' && action === 'register-verify') return await handleRegisterVerify(req, res);
    if (req.method === 'POST' && action === 'login-options') return await handleLoginOptions(req, res);
    if (req.method === 'POST' && action === 'login-verify') return await handleLoginVerify(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('webauthn.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
