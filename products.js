// api/products.js
// Full CRUD for products.json, which the storefront (index.html) reads
// directly to render the product grid. Fields match what index.html
// expects: cat, catLabel, name, price, originalPrice, badge, sizes,
// image, label, description.

const { requireAuth } = require('./_lib/auth');
const { getJSON, putJSON } = require('./_lib/github');

const PATH = 'products.json';

function validateProduct(p) {
  const errors = [];
  if (!p.name || typeof p.name !== 'string') errors.push('name is required');
  if (typeof p.price !== 'number' || p.price < 0) errors.push('price must be a positive number');
  if (!p.cat || typeof p.cat !== 'string') errors.push('cat is required');
  if (!p.catLabel || typeof p.catLabel !== 'string') errors.push('catLabel is required');
  if (!Array.isArray(p.sizes) || !p.sizes.length) errors.push('sizes must be a non-empty array');
  if (!p.image || typeof p.image !== 'string') errors.push('image is required');
  return errors;
}

function makeId() {
  return 'p_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

async function handleList(req, res) {
  const { data } = await getJSON(PATH);
  return res.status(200).json({ products: data });
}

async function handleCreate(req, res) {
  const incoming = req.body && req.body.product;
  if (!incoming) return res.status(400).json({ error: 'Missing "product" in request body.' });

  const errors = validateProduct(incoming);
  if (errors.length) return res.status(400).json({ error: 'Invalid product: ' + errors.join(', ') });

  const { data, sha } = await getJSON(PATH);
  const products = Array.isArray(data) ? data : [];

  const product = { id: makeId(), label: incoming.label || incoming.cat, ...incoming };
  products.push(product);

  await putJSON(PATH, products, sha, `Add product: ${product.name}`);
  return res.status(200).json({ product });
}

async function handleUpdate(req, res) {
  const { id, updates } = req.body || {};
  if (!id || !updates) return res.status(400).json({ error: 'Missing "id" or "updates" in request body.' });

  const { data, sha } = await getJSON(PATH);
  const products = Array.isArray(data) ? data : [];
  const idx = products.findIndex((p) => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found.' });

  const merged = { ...products[idx], ...updates, id };
  const errors = validateProduct(merged);
  if (errors.length) return res.status(400).json({ error: 'Invalid product: ' + errors.join(', ') });

  products[idx] = merged;
  await putJSON(PATH, products, sha, `Update product: ${merged.name}`);
  return res.status(200).json({ product: merged });
}

async function handleDelete(req, res) {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: 'Missing "id" in request body.' });

  const { data, sha } = await getJSON(PATH);
  const products = Array.isArray(data) ? data : [];
  const idx = products.findIndex((p) => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found.' });

  const [removed] = products.splice(idx, 1);
  await putJSON(PATH, products, sha, `Remove product: ${removed.name}`);
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
    if (req.method === 'POST' && action === 'create') return await handleCreate(req, res);
    if (req.method === 'POST' && action === 'update') return await handleUpdate(req, res);
    if (req.method === 'POST' && action === 'delete') return await handleDelete(req, res);
    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('products.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
