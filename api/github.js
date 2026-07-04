// api/_lib/github.js
// Thin wrapper around the GitHub Contents API. Every write needs the file's
// current "sha" if it already exists (GitHub uses this for optimistic
// concurrency), so getFile() always returns { content, sha } together.

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';

function assertConfigured() {
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    throw new Error(
      'GitHub is not configured. Set GITHUB_TOKEN, GITHUB_OWNER, and GITHUB_REPO in Vercel.'
    );
  }
}

function apiUrl(path) {
  return `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
}

function headers() {
  return {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
  };
}

// Returns { content: string, sha: string } or null if the file doesn't exist.
async function getFile(path) {
  assertConfigured();
  const res = await fetch(`${apiUrl(path)}?ref=${GITHUB_BRANCH}`, { headers: headers() });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub read failed for ${path}: ${res.status}`);

  const data = await res.json();
  const content = Buffer.from(data.content, 'base64').toString('utf8');
  return { content, sha: data.sha };
}

// Creates or updates a file. Pass `sha` when updating an existing file
// (omit it, or pass null, when creating a brand new one).
async function putFile(path, content, message, sha) {
  assertConfigured();
  const body = {
    message,
    content: Buffer.from(content, 'utf8').toString('base64'),
    branch: GITHUB_BRANCH,
  };
  if (sha) body.sha = sha;

  const res = await fetch(apiUrl(path), {
    method: 'PUT',
    headers: { ...headers(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub write failed for ${path}: ${res.status} ${errText}`);
  }
  return res.json();
}

async function deleteFile(path, sha, message) {
  assertConfigured();
  const res = await fetch(apiUrl(path), {
    method: 'DELETE',
    headers: { ...headers(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, sha, branch: GITHUB_BRANCH }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub delete failed for ${path}: ${res.status} ${errText}`);
  }
  return res.json();
}

// Convenience: read + JSON.parse a data file, returning [] if missing.
async function getJSON(path) {
  const file = await getFile(path);
  if (!file) return { data: [], sha: null };
  try {
    return { data: JSON.parse(file.content), sha: file.sha };
  } catch {
    throw new Error(`${path} contains invalid JSON.`);
  }
}

// Convenience: write a JS value as pretty-printed JSON.
async function putJSON(path, value, sha, message) {
  return putFile(path, JSON.stringify(value, null, 2), message, sha);
}

module.exports = { getFile, putFile, deleteFile, getJSON, putJSON };
