const crypto = require('crypto');

const GITHUB_API = 'https://api.github.com';
const PRODUCTS_PATH = 'products.json';
const BRANCH = 'main';

function ghHeaders() {
  return {
    Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
  };
}

function repoUrl(path) {
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  return `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`;
}

function signToken() {
  const secret = process.env.RAZORPAY_KEY_SECRET;
  const expiry = Date.now() + 1000 * 60 * 60 * 6; // 6 hours
  const sig = crypto.createHmac('sha256', secret).update(String(expiry)).digest('hex');
  return `${expiry}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [expiry, sig] = token.split('.');
  const secret = process.env.RAZORPAY_KEY_SECRET;
  const expected = crypto.createHmac('sha256', secret).update(expiry).digest('hex');
  if (expected !== sig) return false;
  if (Date.now() > Number(expiry)) return false;
  return true;
}

async function getProductsFile() {
  const r = await fetch(repoUrl(PRODUCTS_PATH) + `?ref=${BRANCH}`, { headers: ghHeaders() });
  if (!r.ok) throw new Error('Could not read products.json');
  const data = await r.json();
  const content = Buffer.from(data.content, 'base64').toString('utf-8');
  return { products: JSON.parse(content), sha: data.sha };
}

async function putProductsFile(products, sha, message) {
  const content = Buffer.from(JSON.stringify(products, null, 2)).toString('base64');
  const r = await fetch(repoUrl(PRODUCTS_PATH), {
    method: 'PUT',
    headers: ghHeaders(),
    body: JSON.stringify({ message, content, sha, branch: BRANCH }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('Could not write products.json: ' + err);
  }
  return r.json();
}

async function uploadImage(base64Data, filename) {
  const cleanBase64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
  const safeName = filename.replace(/[^a-zA-Z0-9.\-_]/g, '_');
  const path = `images/${Date.now()}-${safeName}`;
  const r = await fetch(repoUrl(path), {
    method: 'PUT',
    headers: ghHeaders(),
    body: JSON.stringify({
      message: `Upload product image ${safeName}`,
      content: cleanBase64,
      branch: BRANCH,
    }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('Image upload failed: ' + err);
  }
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  return `https://raw.githubusercontent.com/${owner}/${repo}/${BRANCH}/${path}`;
}

function slugify(name) {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

module.exports = async (req, res) => {
  try {
    const body = req.body || {};
    const action = req.query.action || body.action;

    // ── LOGIN ──
    if (action === 'login') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
      const adminPassword = process.env.ADMIN_PASSWORD;
      if (!adminPassword) return res.status(500).json({ error: 'Admin password not configured.' });
      if (!body.password || body.password !== adminPassword) {
        return res.status(401).json({ error: 'Incorrect password.' });
      }
      return res.status(200).json({ token: signToken() });
    }

    // ── EVERYTHING BELOW REQUIRES A VALID TOKEN ──
    const token = req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : body.token;
    if (!verifyToken(token)) {
      return res.status(401).json({ error: 'Not authorized. Please log in again.' });
    }

    if (req.method === 'GET') {
      const { products } = await getProductsFile();
      return res.status(200).json({ products });
    }

    if (req.method === 'POST') {
      const { product, imageBase64, imageName } = body;
      if (!product || !product.name || !product.price) {
        return res.status(400).json({ error: 'Product name and price are required.' });
      }

      const { products, sha } = await getProductsFile();

      let imageUrl = product.image || '';
      if (imageBase64 && imageName) {
        imageUrl = await uploadImage(imageBase64, imageName);
      }
      if (!imageUrl) {
        return res.status(400).json({ error: 'Please provide an image URL or upload a file.' });
      }

      let id = slugify(product.name);
      let suffix = 1;
      const existingIds = new Set(products.map((p) => p.id));
      while (existingIds.has(id)) {
        id = `${slugify(product.name)}-${suffix}`;
        suffix++;
      }

      const newProduct = {
        id,
        cat: product.cat || 'tshirt',
        catLabel: product.catLabel || 'T-Shirts',
        name: product.name,
        label: product.label || product.name,
        price: Number(product.price),
        originalPrice: product.originalPrice ? Number(product.originalPrice) : null,
        badge: product.badge || null,
        image: imageUrl,
        sizes: Array.isArray(product.sizes) && product.sizes.length ? product.sizes : ['S', 'M', 'L', 'XL'],
      };

      products.push(newProduct);
      await putProductsFile(products, sha, `Add product: ${newProduct.name}`);
      return res.status(200).json({ success: true, product: newProduct });
    }

    if (req.method === 'PUT') {
      const { id, updates, imageBase64, imageName } = body;
      if (!id || !updates) {
        return res.status(400).json({ error: 'Product id and updates are required.' });
      }

      const { products, sha } = await getProductsFile();
      const idx = products.findIndex((p) => p.id === id);
      if (idx === -1) {
        return res.status(404).json({ error: 'Product not found.' });
      }

      if (imageBase64 && imageName) {
        updates.image = await uploadImage(imageBase64, imageName);
      }

      products[idx] = { ...products[idx], ...updates };
      await putProductsFile(products, sha, `Update product: ${products[idx].name}`);
      return res.status(200).json({ success: true, product: products[idx] });
    }

    if (req.method === 'DELETE') {
      const { id } = body;
      if (!id) {
        return res.status(400).json({ error: 'Product id is required.' });
      }

      const { products, sha } = await getProductsFile();
      const filtered = products.filter((p) => p.id !== id);
      if (filtered.length === products.length) {
        return res.status(404).json({ error: 'Product not found.' });
      }

      await putProductsFile(filtered, sha, `Remove product: ${id}`);
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('admin error:', err);
    return res.status(500).json({ error: err.message || 'Something went wrong.' });
  }
};
