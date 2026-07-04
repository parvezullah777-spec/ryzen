// api/pages.js
// Page management. Two page types:
//   - "static": raw HTML, committed as its own file (e.g. about.html)
//   - "dynamic": content stored as JSON blocks, rendered by page.html at
//     runtime via ?slug=... (page.html/template not built yet — this
//     endpoint just manages the data side)
//
// pages.json is the index of every page (both types) so the admin panel
// can list them without scanning the whole repo.

const { requireAuth } = require('./_lib/auth');
const { getJSON, putJSON, getFile, putFile, deleteFile } = require('./_lib/github');

const INDEX_PATH = 'pages.json';

function slugify(s) {
  return String(s || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function htmlFilePath(slug) {
  return `${slug}.html`;
}

async function handleList(req, res) {
  const { data } = await getJSON(INDEX_PATH);
  return res.status(200).json({ pages: data });
}

async function handleGet(req, res) {
  const slug = req.query.slug;
  if (!slug) return res.status(400).json({ error: 'Missing "slug" query parameter.' });

  const { data: pages } = await getJSON(INDEX_PATH);
  const meta = (pages || []).find((p) => p.slug === slug);
  if (!meta) return res.status(404).json({ error: 'Page not found.' });

  if (meta.type === 'static') {
    const file = await getFile(htmlFilePath(slug));
    return res.status(200).json({ page: { ...meta, html: file ? file.content : '' } });
  }

  return res.status(200).json({ page: meta });
}

async function handleCreate(req, res) {
  const { title, type, html, blocks } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Missing "title".' });
  if (type !== 'static' && type !== 'dynamic') {
    return res.status(400).json({ error: '"type" must be "static" or "dynamic".' });
  }

  const slug = slugify(title);
  if (!slug) return res.status(400).json({ error: 'Could not derive a URL slug from that title.' });

  const { data, sha: indexSha } = await getJSON(INDEX_PATH);
  const pages = Array.isArray(data) ? data : [];
  if (pages.some((p) => p.slug === slug)) {
    return res.status(409).json({ error: `A page with slug "${slug}" already exists.` });
  }

  const meta = {
    slug,
    title,
    type,
    updatedAt: new Date().toISOString(),
  };

  if (type === 'static') {
    await putFile(htmlFilePath(slug), html || `<!doctype html>\n<html><head><title>${title}</title></head><body></body></html>`, `Create page: ${title}`);
  } else {
    meta.blocks = Array.isArray(blocks) ? blocks : [];
  }

  pages.push(meta);
  await putJSON(INDEX_PATH, pages, indexSha, `Add page: ${title}`);
  return res.status(200).json({ page: meta });
}

async function handleUpdate(req, res) {
  const { slug, title, html, blocks } = req.body || {};
  if (!slug) return res.status(400).json({ error: 'Missing "slug".' });

  const { data, sha: indexSha } = await getJSON(INDEX_PATH);
  const pages = Array.isArray(data) ? data : [];
  const idx = pages.findIndex((p) => p.slug === slug);
  if (idx === -1) return res.status(404).json({ error: 'Page not found.' });

  const meta = pages[idx];
  if (title) meta.title = title;
  meta.updatedAt = new Date().toISOString();

  if (meta.type === 'static' && typeof html === 'string') {
    const existing = await getFile(htmlFilePath(slug));
    await putFile(htmlFilePath(slug), html, `Update page: ${meta.title}`, existing ? existing.sha : null);
  }
  if (meta.type === 'dynamic' && Array.isArray(blocks)) {
    meta.blocks = blocks;
  }

  pages[idx] = meta;
  await putJSON(INDEX_PATH, pages, indexSha, `Update page: ${meta.title}`);
  return res.status(200).json({ page: meta });
}

async function handleDelete(req, res) {
  const { slug } = req.body || {};
  if (!slug) return res.status(400).json({ error: 'Missing "slug".' });

  const { data, sha: indexSha } = await getJSON(INDEX_PATH);
  const pages = Array.isArray(data) ? data : [];
  const idx = pages.findIndex((p) => p.slug === slug);
  if (idx === -1) return res.status(404).json({ error: 'Page not found.' });

  const [removed] = pages.splice(idx, 1);

  if (removed.type === 'static') {
    const existing = await getFile(htmlFilePath(slug));
    if (existing) await deleteFile(htmlFilePath(slug), existing.sha, `Delete page: ${removed.title}`);
  }

  await putJSON(INDEX_PATH, pages, indexSha, `Delete page: ${removed.title}`);
  return res.status(200).json({ removed });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const session = requireAuth(req, res);
  if (!session) return;

  const action = req.query.action || (req.body && req.body.action);

  try {
    if (req.method === 'GET' && action === 'list') return await handleList(req, res);
    if (req.method === 'GET' && action === 'get') return await handleGet(req, res);
    if (req.method === 'POST' && action === 'create') return await handleCreate(req, res);
    if (req.method === 'POST' && action === 'update') return await handleUpdate(req, res);
    if (req.method === 'POST' && action === 'delete') return await handleDelete(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('pages.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
