// api/developer-agent.js
// Developer AI — the one agent that actually touches code, and only ever via
// a Pull Request. It NEVER pushes to main and NEVER merges. Opening the PR is
// the "Generate execution plan" + "Send report" step from the architecture doc;
// you reviewing and merging it on GitHub IS the Super Admin approval gate.
//
// Provider: Groq (free tier, llama-3.3-70b-versatile by default — no card,
// no expiry, 1,000 requests/day). Connection is OFF by default and can only
// be switched on/off by the Super Admin from the admin panel (app_settings.
// developer_ai_enabled). Every propose request checks this switch first and
// refuses to call Groq at all while it's off — the connection itself is
// under Super Admin control, not just who can trigger a proposal.
//
// Hard safety rules baked in, not configurable at request time:
// - Only ever commits to a freshly created branch, never main.
// - Refuses to touch anything under api/, package.json / package-lock.json,
//   or any .env* file — so it can't propose changes to auth/secrets logic.
// - No merge endpoint exists in this file at all.

const { requireAuth } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const SETTINGS_KEY = 'developer_ai_enabled';

const BLOCKED_PATH_PATTERNS = [
  /^api\//i,          // server logic, including auth — never touched by this agent
  /package(-lock)?\.json$/i,
  /^\.env/i,
  /^\.git/i,
];

function isBlockedPath(path) {
  return BLOCKED_PATH_PATTERNS.some((re) => re.test(path));
}

function slugify(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40) || 'fix';
}

async function githubRequest(path, opts = {}) {
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    throw new Error('GITHUB_TOKEN, GITHUB_OWNER, or GITHUB_REPO is not configured.');
  }
  const res = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || `GitHub API error (${res.status})`);
  return data;
}

async function askGroq(prompt) {
  if (!GROQ_API_KEY) throw new Error('GROQ_API_KEY is not configured.');
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 8000,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error?.message || `Groq API error (${res.status})`);
  const text = data.choices?.[0]?.message?.content || '';
  if (!text.trim()) throw new Error('Groq returned an empty response.');
  return text;
}

// ---------- Settings: the Super-Admin-controlled on/off switch ----------
// Developer AI refuses to call any AI provider at all while this is off,
// regardless of who calls the endpoint or what instructions they send.
async function isDeveloperAiEnabled() {
  const { data, error } = await supabase.from('app_settings').select('value').eq('key', SETTINGS_KEY).maybeSingle();
  if (error) throw error;
  return data ? data.value === true : false; // default OFF if the row is somehow missing
}

async function handleGetSettings(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can view Developer AI settings.' });
  }
  const enabled = await isDeveloperAiEnabled();
  return res.status(200).json({ enabled });
}

// ---------- Auth-only: flip the switch ----------
async function handleSetSettings(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can change Developer AI settings.' });
  }
  const { enabled } = req.body || {};
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be true or false.' });
  }
  const { error } = await supabase.from('app_settings').upsert(
    { key: SETTINGS_KEY, value: enabled, updated_at: new Date().toISOString(), updated_by: session.username || null },
    { onConflict: 'key' }
  );
  if (error) throw error;
  return res.status(200).json({ enabled });
}

function stripCodeFences(text) {
  const fenced = text.match(/```[a-z]*\n([\s\S]*?)```/i);
  return (fenced ? fenced[1] : text).trim();
}

// ---------- Auth-only: propose a fix as a PR ----------
async function handlePropose(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can request a Developer AI proposal.' });
  }

  const enabled = await isDeveloperAiEnabled();
  if (!enabled) {
    return res.status(403).json({ error: 'Developer AI is currently switched off. Turn it on from the admin panel to request a proposal.' });
  }

  const { filePath, instructions, findingId } = req.body || {};
  if (!filePath || !instructions) {
    return res.status(400).json({ error: 'filePath and instructions are required.' });
  }
  if (isBlockedPath(filePath)) {
    return res.status(403).json({ error: `Developer AI is not permitted to touch "${filePath}". Server logic, dependencies, and env files are off-limits.` });
  }

  // 1. Fetch current file content + sha from GitHub
  const fileData = await githubRequest(`/contents/${encodeURIComponent(filePath).replace(/%2F/g, '/')}`);
  if (Array.isArray(fileData) || !fileData.content) {
    return res.status(400).json({ error: `"${filePath}" is not a readable file in this repo.` });
  }
  const originalContent = Buffer.from(fileData.content, 'base64').toString('utf8');

  // 2. Ask Groq to produce the full updated file — nothing else
  const prompt = [
    'You are editing one file in a live production website. Make the smallest possible change that satisfies the instruction.',
    'Return ONLY the complete, updated file content. No explanation, no markdown code fences, no commentary.',
    '',
    `Instruction: ${instructions}`,
    '',
    `--- Current content of ${filePath} ---`,
    originalContent,
  ].join('\n');

  const raw = await askGroq(prompt);
  const updatedContent = stripCodeFences(raw);

  if (!updatedContent || updatedContent === originalContent) {
    return res.status(422).json({ error: 'Developer AI did not produce a meaningful change. No PR was opened.' });
  }

  // 3. Branch off main
  const mainRef = await githubRequest('/git/ref/heads/main');
  const branch = `devai/${slugify(instructions)}-${Date.now().toString(36)}`;
  await githubRequest('/git/refs', {
    method: 'POST',
    body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: mainRef.object.sha }),
  });

  // 4. Commit the change to the new branch only
  await githubRequest(`/contents/${encodeURIComponent(filePath).replace(/%2F/g, '/')}`, {
    method: 'PUT',
    body: JSON.stringify({
      message: `Developer AI: ${instructions.slice(0, 60)}`,
      content: Buffer.from(updatedContent, 'utf8').toString('base64'),
      sha: fileData.sha,
      branch,
    }),
  });

  // 5. Open the PR — this is the approval gate. Nothing merges automatically.
  const pr = await githubRequest('/pulls', {
    method: 'POST',
    body: JSON.stringify({
      title: `[Developer AI] ${instructions.slice(0, 70)}`,
      head: branch,
      base: 'main',
      body: [
        '_Opened automatically by Ryzen Developer AI. Nothing is live until you review and merge this._',
        '',
        `**File:** \`${filePath}\``,
        `**Instruction:** ${instructions}`,
        findingId ? `**Linked finding:** ${findingId}` : '',
      ].filter(Boolean).join('\n'),
    }),
  });

  // 6. Log it, and if this came from a finding, acknowledge (not resolve — resolve happens on merge)
  await supabase.from('dev_proposals').insert([{
    finding_id: findingId || null, file_path: filePath, instructions,
    branch, pr_number: pr.number, pr_url: pr.html_url, status: 'open',
  }]);
  if (findingId) {
    await supabase.from('debug_findings').update({ status: 'acknowledged' }).eq('id', findingId);
  }

  return res.status(200).json({ prUrl: pr.html_url, prNumber: pr.number, branch });
}

// ---------- Auth-only: list past proposals ----------
async function handleProposals(req, res) {
  const session = requireAuth(req, res);
  if (!session) return;
  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the Super Admin can view Developer AI proposals.' });
  }
  const { data, error } = await supabase.from('dev_proposals').select('*').order('created_at', { ascending: false }).limit(50);
  if (error) throw error;
  return res.status(200).json({ proposals: data });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'POST' && action === 'propose') return await handlePropose(req, res);
    if (req.method === 'GET' && action === 'proposals') return await handleProposals(req, res);
    if (req.method === 'GET' && action === 'settings') return await handleGetSettings(req, res);
    if (req.method === 'POST' && action === 'settings') return await handleSetSettings(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('developer-agent.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
