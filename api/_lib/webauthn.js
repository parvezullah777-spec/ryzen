// api/_lib/webauthn.js
// Shared WebAuthn config and helpers.

const RP_NAME = 'Ryzen Admin Panel';

// This MUST match the domain admins actually use to log in.
// Update this if your custom domain differs from the vercel.app one.
function getRpID(req) {
  const host = req.headers.host || '';
  return host.split(':')[0]; // strips port if present
}

function getOrigin(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return `${proto}://${req.headers.host}`;
}

module.exports = { RP_NAME, getRpID, getOrigin };
