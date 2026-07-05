// api/debug-agent.js
// Debug AI — Monitor -> Analyze -> Report. Read-only detection only.
// It never edits files, never redeploys, never touches products/pages/prices.
// It only writes to its own tables (client_errors, debug_findings) and reports
// findings for the Super Admin to review and resolve manually.

const crypto = require('crypto');
const { requireAuth } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');

function fingerprint(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);
}

async function upsertFinding({ fp, category, title, message, source, severity, meta }) {
  const { data: existing } = await supabase
    .from('debug_findings')
    .select('id, occurrences, status')
    .eq('fingerprint', fp)
    .maybeSingle();

  if (existing) {
    // If it had been resolved and is happening again, reopen it.
    const nextStatus = existing.status === 'resolved' ? 'open' : existing.status;
    await supabase
      .from('debug_findings')
      .update({
        occurrences: existing.occurrences + 1,
        last_seen: new Date().toISOString(),
        status: nextStatus,
      })
      .eq('id', existing.id);
    return;
  }

  await supabase.from('debug_findings').insert([{
    fingerprint: fp,
    category,
    title,
    message,
    source,
    severity,
    meta: meta || null,
  }]);
}

// ---------- Public: frontend error capture ----------
// No auth — this runs on the live storefront for anonymous visitors too.
async function handleReportError(req, res) {
  const { message, stack, page, url } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message is required.' });

  const safeMessage = String(message).slice(0, 500);
  const safePage = page === 'admin' ? 'admin' : 'storefront';
  const fp = fingerprint(['frontend_error', safePage, safeMessage]);

  try {
    await supabase.from('client_errors').insert([{
      fingerprint: fp,
      message: safeMessage,
      stack: stack ? String(stack).slice(0, 4000) : null,
      page: safePage,
      source_url: url ? String(url).slice(0, 500) : null,
      user_agent: req.headers['user-agent'] || null,
    }]);

    const severity = /payment|checkout|charge/i.test(safeMessage)
      ? 'high'
      : safePage === 'admin' ? 'medium' : 'low';

    await upsertFinding({
      fp,
      category: 'frontend_error',
      title: safeMessage,
      message: safeMessage,
      source: safePage,
      severity,
      meta: { url },
    });
  } catch (err) {
    // Never let error reporting itself break the page for a real user.
    console.error('debug-agent report-error failed:', err.message);
  }

  return res.status(200).json({ ok: true });
}

// ---------- Auth-only: run a health scan ----------
async function handleScan(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can run a Debug AI scan.' });
  }

  const results = [];

  // 1. Required config present?
  const requiredEnv = ['ADMIN_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
  for (const key of requiredEnv) {
    if (!process.env[key]) {
      const fp = fingerprint(['config', key]);
      await upsertFinding({
        fp, category: 'config', title: `Missing environment variable: ${key}`,
        message: `${key} is not set in the deployment environment.`,
        source: 'env', severity: 'critical',
      });
      results.push({ check: `env:${key}`, ok: false });
    } else {
      results.push({ check: `env:${key}`, ok: true });
    }
  }

  // 2. Core tables reachable? (read-only count queries)
  const tables = ['products', 'pages', 'admins', 'login_logs'];
  for (const table of tables) {
    const start = Date.now();
    try {
      const { error } = await supabase.from(table).select('*', { count: 'exact', head: true });
      const ms = Date.now() - start;
      if (error) throw error;
      results.push({ check: `db:${table}`, ok: true, ms });
      if (ms > 2000) {
        const fp = fingerprint(['db_health', table, 'slow']);
        await upsertFinding({
          fp, category: 'db_health', title: `Slow response from "${table}" table`,
          message: `Query took ${ms}ms.`, source: table, severity: 'medium', meta: { ms },
        });
      }
    } catch (err) {
      results.push({ check: `db:${table}`, ok: false, error: err.message });
      const fp = fingerprint(['db_health', table, 'error']);
      await upsertFinding({
        fp, category: 'db_health', title: `"${table}" table unreachable`,
        message: err.message, source: table, severity: 'high',
      });
    }
  }

  // 3. Sibling API endpoints respond? (best-effort — needs a resolvable host)
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if (host) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const base = `${proto}://${host}`;
    const endpoints = ['/api/admin?action=dashboard', '/api/products?action=list', '/api/pages?action=list'];
    for (const ep of endpoints) {
      const start = Date.now();
      try {
        const r = await fetch(base + ep, { headers: { Authorization: req.headers.authorization || '' } });
        const ms = Date.now() - start;
        results.push({ check: `api:${ep}`, ok: r.status < 500, status: r.status, ms });
        if (r.status >= 500) {
          const fp = fingerprint(['api_health', ep]);
          await upsertFinding({
            fp, category: 'api_health', title: `${ep} returned ${r.status}`,
            message: `Endpoint responded with status ${r.status}.`, source: ep, severity: 'high',
          });
        }
      } catch (err) {
        results.push({ check: `api:${ep}`, ok: false, error: err.message });
      }
    }
  }

  return res.status(200).json({ ranAt: new Date().toISOString(), results });
}

// ---------- Auth-only: list findings ----------
async function handleFindings(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can view Debug AI findings.' });
  }

  const status = req.query.status; // optional filter: open | acknowledged | resolved
  let query = supabase.from('debug_findings').select('*').order('severity', { ascending: true }).order('last_seen', { ascending: false });
  if (status) query = query.eq('status', status);

  const { data, error } = await query;
  if (error) throw error;
  return res.status(200).json({ findings: data });
}

// ---------- Auth-only: acknowledge / resolve a finding ----------
async function handleResolve(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can update Debug AI findings.' });
  }

  const { id, status } = req.body || {};
  if (!id || !['acknowledged', 'resolved', 'open'].includes(status)) {
    return res.status(400).json({ error: 'id and a valid status are required.' });
  }

  const update = { status };
  if (status === 'resolved') update.resolved_at = new Date().toISOString();

  const { error } = await supabase.from('debug_findings').update(update).eq('id', id);
  if (error) throw error;
  return res.status(200).json({ ok: true });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'POST' && action === 'report-error') return await handleReportError(req, res);
    if (req.method === 'GET' && action === 'scan') return await handleScan(req, res);
    if (req.method === 'GET' && action === 'findings') return await handleFindings(req, res);
    if (req.method === 'POST' && action === 'resolve') return await handleResolve(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('debug-agent.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
