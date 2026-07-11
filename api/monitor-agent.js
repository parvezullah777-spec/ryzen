// api/monitor-agent.js
// Ryzen AI Monitor — the five sub-agents from the architecture doc (Debug, Security,
// Performance, Analytics, Developer) merged into one endpoint.
//
// Hard rule: report-only. This file NEVER edits products/pages/prices, never
// redeploys, never restarts anything, never touches a live user's session.
// It only writes to its own tables (client_errors, page_views, debug_findings)
// and surfaces findings for the Super Admin to review and resolve by hand.
//
// Each domain check is isolated (its own try/catch, run via Promise.allSettled)
// so a slow or failing check in one domain never blocks or delays the others.

const crypto = require('crypto');
const { requireAuth } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');

function fingerprint(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);
}

// mode 'count'   -> repeated occurrences of the same problem (bugs, errors): bump a counter
// mode 'replace' -> a living summary (e.g. "today's traffic"): overwrite with the latest value
async function upsertFinding({ fp, domain, title, message, source, severity, meta, mode = 'count' }) {
  const { data: existing } = await supabase
    .from('debug_findings')
    .select('id, occurrences, status')
    .eq('fingerprint', fp)
    .maybeSingle();

  if (existing) {
    const nextStatus = existing.status === 'resolved' ? 'open' : existing.status;
    const update = { last_seen: new Date().toISOString(), status: nextStatus };
    if (mode === 'count') update.occurrences = existing.occurrences + 1;
    if (mode === 'replace') { update.title = title; update.message = message; update.meta = meta || null; }
    await supabase.from('debug_findings').update(update).eq('id', existing.id);
    return;
  }

  await supabase.from('debug_findings').insert([{
    fingerprint: fp, category: domain, title, message, source, severity, meta: meta || null,
  }]);
}

// Run a labeled check without letting it throw past this point — a broken
// check becomes a result row, not a crash that stops the other domains.
async function safe(domain, checkName, fn, results) {
  try {
    await fn();
  } catch (err) {
    results.push({ domain, check: checkName, ok: false, error: err.message });
  }
}

// ================= DEBUG =================
async function runDebugChecks(req, results) {
  const tables = ['products', 'pages', 'admins', 'admin_logins'];
  for (const table of tables) {
    await safe('debug', `db:${table}`, async () => {
      const start = Date.now();
      const { error } = await supabase.from(table).select('*', { count: 'exact', head: true });
      const ms = Date.now() - start;
      if (error) {
        results.push({ domain: 'debug', check: `db:${table}`, ok: false, error: error.message });
        await upsertFinding({
          fp: fingerprint(['debug', table, 'unreachable']), domain: 'debug',
          title: `"${table}" table unreachable`, message: error.message, source: table, severity: 'high',
        });
        return;
      }
      results.push({ domain: 'debug', check: `db:${table}`, ok: true, ms });
    }, results);
  }

  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if (host) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const base = `${proto}://${host}`;
    const endpoints = ['/api/admin?action=dashboard', '/api/products?action=list', '/api/pages?action=list'];
    for (const ep of endpoints) {
      await safe('debug', `api:${ep}`, async () => {
        const start = Date.now();
        const r = await fetch(base + ep, { headers: { Authorization: req.headers.authorization || '' } });
        const ms = Date.now() - start;
        results.push({ domain: 'debug', check: `api:${ep}`, ok: r.status < 500, status: r.status, ms });
        if (r.status >= 500) {
          await upsertFinding({
            fp: fingerprint(['debug', ep]), domain: 'debug',
            title: `${ep} returned ${r.status}`, message: `Endpoint responded with status ${r.status}.`,
            source: ep, severity: 'high',
          });
        }
      }, results);
    }
  }
}

// ================= PERFORMANCE =================
async function runPerformanceChecks(results) {
  const tables = ['products', 'pages', 'admins', 'admin_logins'];
  for (const table of tables) {
    await safe('performance', `latency:${table}`, async () => {
      const start = Date.now();
      const { error } = await supabase.from(table).select('*', { count: 'exact', head: true });
      const ms = Date.now() - start;
      if (error) return; // already reported under debug
      results.push({ domain: 'performance', check: `latency:${table}`, ok: ms <= 2000, ms });
      if (ms > 2000) {
        await upsertFinding({
          fp: fingerprint(['performance', table, 'slow']), domain: 'performance',
          title: `Slow response from "${table}" table`, message: `Query took ${ms}ms.`,
          source: table, severity: 'medium', meta: { ms },
        });
      }
    }, results);
  }
}

// ================= SECURITY =================
async function runSecurityChecks(results) {
  const requiredEnv = ['ADMIN_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
  for (const key of requiredEnv) {
    await safe('security', `env:${key}`, async () => {
      if (!process.env[key]) {
        results.push({ domain: 'security', check: `env:${key}`, ok: false });
        await upsertFinding({
          fp: fingerprint(['security', key, 'missing']), domain: 'security',
          title: `Missing environment variable: ${key}`, message: `${key} is not set in the deployment environment.`,
          source: 'env', severity: 'critical',
        });
        return;
      }
      results.push({ domain: 'security', check: `env:${key}`, ok: true });
      if (key === 'ADMIN_SECRET' && process.env.ADMIN_SECRET.length < 32) {
        await upsertFinding({
          fp: fingerprint(['security', 'admin_secret', 'weak']), domain: 'security',
          title: 'ADMIN_SECRET is short', message: 'Use a longer, random secret (32+ characters) to sign tokens.',
          source: 'env', severity: 'medium',
        });
      }
    }, results);
  }

  // Repeated failed logins in the last 15 minutes (possible brute force)
  await safe('security', 'failed-login-spike', async () => {
    const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { data, error } = await supabase
      .from('admin_logins')
      .select('ip_address, attempted_username, created_at')
      .eq('success', false)
      .gte('created_at', since);
    if (error) throw error;

    const byIp = {};
    (data || []).forEach((l) => {
      const key = l.ip_address || 'unknown';
      byIp[key] = (byIp[key] || 0) + 1;
    });

    const hourBucket = new Date().toISOString().slice(0, 13); // dedupe per hour per IP
    for (const [ip, count] of Object.entries(byIp)) {
      if (count >= 5) {
        await upsertFinding({
          fp: fingerprint(['security', 'login-spike', ip, hourBucket]), domain: 'security',
          title: `${count} failed logins from ${ip} in 15 minutes`,
          message: 'Possible brute-force attempt. Consider blocking this IP or reviewing admin credentials.',
          source: ip, severity: 'high', mode: 'replace', meta: { count },
        });
      }
    }
    results.push({ domain: 'security', check: 'failed-login-spike', ok: true, flagged: Object.values(byIp).filter((c) => c >= 5).length });
  }, results);

  // Sub-admins with no permissions granted (likely misconfigured)
  await safe('security', 'sub-admin-permissions', async () => {
    const { data, error } = await supabase.from('admins').select('id, username, permissions').eq('role', 'sub_admin');
    if (error) throw error;
    const empty = (data || []).filter((a) => {
      const p = a.permissions || {};
      return !Object.values(p).some((section) => section && Object.values(section).some(Boolean));
    });
    if (empty.length) {
      await upsertFinding({
        fp: fingerprint(['security', 'sub-admin-empty-permissions']), domain: 'security',
        title: `${empty.length} sub-admin account(s) with no permissions granted`,
        message: empty.map((a) => a.username).join(', '),
        source: 'admins', severity: 'low', mode: 'replace', meta: { usernames: empty.map((a) => a.username) },
      });
    }
    results.push({ domain: 'security', check: 'sub-admin-permissions', ok: true, flagged: empty.length });
  }, results);
}

// ================= ANALYTICS =================
async function runAnalyticsChecks(results) {
  await safe('analytics', 'daily-traffic', async () => {
    const now = Date.now();
    const today0 = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const yest0 = new Date(now - 48 * 60 * 60 * 1000).toISOString();

    const { count: todayCount, error: e1 } = await supabase
      .from('page_views').select('*', { count: 'exact', head: true }).gte('created_at', today0);
    if (e1) throw e1;
    const { count: yestCount, error: e2 } = await supabase
      .from('page_views').select('*', { count: 'exact', head: true }).gte('created_at', yest0).lt('created_at', today0);
    if (e2) throw e2;

    const today = todayCount || 0;
    const yesterday = yestCount || 0;
    const deltaPct = yesterday > 0 ? Math.round(((today - yesterday) / yesterday) * 100) : null;
    const deltaText = deltaPct === null ? '' : ` (${deltaPct >= 0 ? '+' : ''}${deltaPct}% vs. previous 24h)`;

    await upsertFinding({
      fp: fingerprint(['analytics', 'daily-traffic']), domain: 'analytics',
      title: `Traffic — last 24h: ${today} views${deltaText}`,
      message: `Previous 24h: ${yesterday} views.`, source: 'page_views', severity: 'low',
      mode: 'replace', meta: { today, yesterday, deltaPct },
    });
    results.push({ domain: 'analytics', check: 'daily-traffic', ok: true, today, yesterday });
  }, results);
}

// ================= DEVELOPER (content/SEO quality, read-only) =================
async function runDeveloperChecks(results) {
  await safe('developer', 'pages-content-quality', async () => {
    const { data, error } = await supabase.from('pages').select('title, slug, type, html, blocks');
    if (error) throw error;
    const issues = (data || []).filter((p) => {
      if (!p.title || !p.title.trim()) return true;
      if (p.type === 'static') return !p.html || p.html.trim().length < 40;
      if (p.type === 'dynamic') return !Array.isArray(p.blocks) || p.blocks.length === 0;
      return false;
    });
    if (issues.length) {
      await upsertFinding({
        fp: fingerprint(['developer', 'pages-content-quality']), domain: 'developer',
        title: `${issues.length} page(s) with thin content or missing titles`,
        message: issues.map((p) => p.slug || p.title || 'untitled').join(', '),
        source: 'pages', severity: 'low', mode: 'replace',
        meta: { slugs: issues.map((p) => p.slug) },
      });
    }
    results.push({ domain: 'developer', check: 'pages-content-quality', ok: true, flagged: issues.length });
  }, results);

  await safe('developer', 'products-content-quality', async () => {
    const { data, error } = await supabase.from('products').select('id, name, image, description');
    if (error) throw error;
    const issues = (data || []).filter((p) => !p.image || !p.description || !p.description.trim());
    if (issues.length) {
      await upsertFinding({
        fp: fingerprint(['developer', 'products-content-quality']), domain: 'developer',
        title: `${issues.length} product(s) missing an image or description`,
        message: issues.map((p) => p.name).join(', '),
        source: 'products', severity: 'low', mode: 'replace',
        meta: { productIds: issues.map((p) => p.id) },
      });
    }
    results.push({ domain: 'developer', check: 'products-content-quality', ok: true, flagged: issues.length });
  }, results);
}

// ---------- Public: frontend error capture (storefront + admin) ----------
async function handleReportError(req, res) {
  const { message, stack, page, url } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message is required.' });

  const safeMessage = String(message).slice(0, 500);
  const safePage = page === 'admin' ? 'admin' : 'storefront';
  const fp = fingerprint(['debug', safePage, safeMessage]);

  try {
    await supabase.from('client_errors').insert([{
      fingerprint: fp, message: safeMessage,
      stack: stack ? String(stack).slice(0, 4000) : null,
      page: safePage, source_url: url ? String(url).slice(0, 500) : null,
      user_agent: req.headers['user-agent'] || null,
    }]);

    const severity = /payment|checkout|charge/i.test(safeMessage) ? 'high' : safePage === 'admin' ? 'medium' : 'low';
    await upsertFinding({ fp, domain: 'debug', title: safeMessage, message: safeMessage, source: safePage, severity, meta: { url } });
  } catch (err) {
    console.error('monitor-agent report-error failed:', err.message);
  }
  return res.status(200).json({ ok: true });
}

// ---------- Public: lightweight pageview beacon (storefront only, feeds Analytics) ----------
async function handleReportView(req, res) {
  const { path } = req.body || {};
  try {
    await supabase.from('page_views').insert([{
      path: path ? String(path).slice(0, 300) : null,
      user_agent: req.headers['user-agent'] || null,
    }]);
  } catch (err) {
    console.error('monitor-agent report-view failed:', err.message);
  }
  return res.status(200).json({ ok: true });
}

// ---------- Auth-only: run the full scan across all five domains ----------
async function handleScan(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can run a scan.' });
  }

  const results = [];
  // Promise.allSettled: each domain runs independently. One failing or slow
  // domain never blocks, delays, or cancels the others.
  await Promise.allSettled([
    runDebugChecks(req, results),
    runPerformanceChecks(results),
    runSecurityChecks(results),
    runAnalyticsChecks(results),
    runDeveloperChecks(results),
  ]);

  return res.status(200).json({ ranAt: new Date().toISOString(), results });
}

// ---------- Auth-only: list findings (optionally filter by domain/status) ----------
async function handleFindings(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can view findings.' });
  }

  const { status, domain } = req.query;
  let query = supabase.from('debug_findings').select('*').order('severity', { ascending: true }).order('last_seen', { ascending: false });
  if (status) query = query.eq('status', status);
  if (domain) query = query.eq('category', domain);

  const { data, error } = await query;
  if (error) throw error;
  return res.status(200).json({ findings: data });
}

// ---------- Auth-only: acknowledge / resolve a finding ----------
async function handleResolve(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can update findings.' });
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
    if (req.method === 'POST' && action === 'report-view') return await handleReportView(req, res);
    if (req.method === 'GET' && action === 'scan') return await handleScan(req, res);
    if (req.method === 'GET' && action === 'findings') return await handleFindings(req, res);
    if (req.method === 'POST' && action === 'resolve') return await handleResolve(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('monitor-agent.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
