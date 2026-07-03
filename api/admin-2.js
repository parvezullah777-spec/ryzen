const crypto = require('crypto');

const GITHUB_API = 'https://api.github.com';
const PRODUCTS_PATH = 'products.json';
const FACE_PATH = 'face.json';
const BRANCH = 'main';

// Strips anything that looks like base64 image data out of a string before it is
// logged or sent back to a client. External APIs sometimes echo request payloads
// back in error bodies — this makes sure a photo never leaks that way.
function redact(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[A-Za-z0-9+/]{200,}={0,2}/g, '[image data redacted]');
}

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
    throw new Error('Could not write products.json: ' + redact(err));
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
    throw new Error('Image upload failed: ' + redact(err));
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

/* ── FACE ID storage (same GitHub-as-datastore pattern as products.json) ── */
async function getFaceFile() {
  const r = await fetch(repoUrl(FACE_PATH) + `?ref=${BRANCH}`, { headers: ghHeaders() });
  if (r.status === 404) return { referenceImage: null, sha: null };
  if (!r.ok) throw new Error('Could not read face.json');
  const data = await r.json();
  const content = Buffer.from(data.content, 'base64').toString('utf-8');
  const parsed = JSON.parse(content);
  return { referenceImage: parsed.referenceImage || null, sha: data.sha };
}

async function putFaceFile(referenceImage, sha, message) {
  const content = Buffer.from(JSON.stringify({ referenceImage }, null, 2)).toString('base64');
  const payload = { message, content, branch: BRANCH };
  if (sha) payload.sha = sha;
  const r = await fetch(repoUrl(FACE_PATH), {
    method: 'PUT',
    headers: ghHeaders(),
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('Could not write face.json: ' + redact(err));
  }
  return r.json();
}

/* ── Anthropic AI agent: compares the login snapshot against the enrolled photo ── */
function cleanImage(base64Data) {
  return base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
}

function guessMediaType(base64Data) {
  if (base64Data.startsWith('data:')) {
    const match = base64Data.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,/);
    if (match) return match[1];
  }
  return 'image/jpeg';
}

async function verifyFaceWithClaude(referenceImage, capturedImage) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('Anthropic AI agent is not configured (missing ANTHROPIC_API_KEY).');

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-5',
      max_tokens: 200,
      system:
        'You are a strict face-verification agent guarding an admin login. ' +
        'You will be shown a reference photo of the authorized admin and a new snapshot taken at login. ' +
        'Decide whether the snapshot shows the same person as the reference photo. ' +
        'Respond with ONLY raw JSON, no markdown, no preamble, in exactly this shape: ' +
        '{"match": true or false, "confidence": 0-100, "reason": "short explanation"}',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Reference photo (enrolled admin):' },
            {
              type: 'image',
              source: { type: 'base64', media_type: guessMediaType(referenceImage), data: cleanImage(referenceImage) },
            },
            { type: 'text', text: 'Login snapshot (just captured):' },
            {
              type: 'image',
              source: { type: 'base64', media_type: guessMediaType(capturedImage), data: cleanImage(capturedImage) },
            },
            { type: 'text', text: 'Is this the same person? Respond with the JSON object only.' },
          ],
        },
      ],
    }),
  });

  if (!r.ok) {
    const err = await r.text();
    throw new Error('Anthropic AI agent request failed: ' + redact(err));
  }

  const data = await r.json();
  const text = (data.content || [])
    .map((block) => (block.type === 'text' ? block.text : ''))
    .join('')
    .trim();

  const clean = text.replace(/```json|```/g, '').trim();
  try {
    const parsed = JSON.parse(clean);
    return {
      match: parsed.match === true,
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : null,
      reason: parsed.reason || '',
    };
  } catch (e) {
    throw new Error('Anthropic AI agent returned an unparsable response: ' + redact(text));
  }
}

/* ── Telegram photo alert (used for face mismatch AND every login) ── */
async function sendTelegramPhoto(imageBase64, caption) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) throw new Error('Telegram is not configured (missing bot token or chat id).');

  const cleanBase64 = imageBase64.includes(',') ? imageBase64.split(',')[1] : imageBase64;
  const buffer = Buffer.from(cleanBase64, 'base64');

  const form = new FormData();
  form.append('chat_id', chatId);
  form.append('caption', caption);
  form.append('photo', new Blob([buffer], { type: 'image/jpeg' }), 'alert.jpg');

  const r = await fetch(`https://api.telegram.org/bot${token}/sendPhoto`, {
    method: 'POST',
    body: form,
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('Telegram send failed: ' + redact(err));
  }
  return r.json();
}

function sendTelegramAlert(imageBase64, timestamp) {
  return sendTelegramPhoto(
    imageBase64,
    `⚠️ Unrecognized face attempted to access Ryzen Admin\n${timestamp || new Date().toISOString()}`
  );
}

function sendLoginPhoto(imageBase64, timestamp) {
  return sendTelegramPhoto(
    imageBase64,
    `🔐 Admin login to Ryzen Admin\n${timestamp || new Date().toISOString()}`
  );
}

function sendFaceMatchPhoto(imageBase64, timestamp) {
  return sendTelegramPhoto(
    imageBase64,
    `✅ Face ID verified — Admin access granted\n${timestamp || new Date().toISOString()}`
  );
}

function sendFaceEnrollPhoto(imageBase64, timestamp) {
  return sendTelegramPhoto(
    imageBase64,
    `🆕 Face ID (re-)enrolled on Ryzen Admin\n${timestamp || new Date().toISOString()}`
  );
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

      // Best-effort snapshot on every login. Awaited so the serverless function
      // doesn't exit/freeze before the Telegram request completes — but any
      // failure here is swallowed so it never blocks or fails the login itself.
      if (body.imageBase64) {
        try {
          await sendLoginPhoto(body.imageBase64, body.timestamp);
        } catch (err) {
          console.error('login photo send failed:', redact(err.message));
        }
      }

      return res.status(200).json({ token: signToken() });
    }

    // ── EVERYTHING BELOW REQUIRES A VALID TOKEN ──
    const token = req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : body.token;
    if (!verifyToken(token)) {
      return res.status(401).json({ error: 'Not authorized. Please log in again.' });
    }

    // ── FACE ID: status ──
    if (action === 'face-status') {
      if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
      const { referenceImage } = await getFaceFile();
      return res.status(200).json({ enrolled: !!referenceImage });
    }

    // ── FACE ID: enroll / re-enroll (stores a reference photo, never returned to the client) ──
    if (action === 'face-enroll') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
      const { imageBase64 } = body;
      if (!imageBase64) return res.status(400).json({ error: 'Reference photo is required.' });
      const existing = await getFaceFile();
      await putFaceFile(imageBase64, existing.sha, 'Update admin Face ID reference photo');

      try {
        await sendFaceEnrollPhoto(imageBase64, body.timestamp);
      } catch (err) {
        console.error('enroll photo send failed:', redact(err.message));
      }

      return res.status(200).json({ success: true });
    }

    // ── FACE ID: verify via the Anthropic AI agent. Runs entirely server-side — ──
    // ── the reference photo never leaves the server, and the result (match/reason) ──
    // ── is the only thing sent back to the browser. ──
    if (action === 'face-verify') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
      const { imageBase64, timestamp } = body;
      if (!imageBase64) return res.status(400).json({ error: 'Missing snapshot.' });

      const { referenceImage } = await getFaceFile();
      if (!referenceImage) return res.status(400).json({ error: 'No Face ID enrolled yet.' });

      let result;
      try {
        result = await verifyFaceWithClaude(referenceImage, imageBase64);
      } catch (err) {
        console.error('face verification failed:', redact(err.message));
        return res.status(500).json({ error: 'Face verification could not be completed.' });
      }

      // Photo goes only to your own Telegram chat (TELEGRAM_CHAT_ID env var) — nowhere else.
      // Awaited so the serverless function doesn't exit before the send completes.
      try {
        if (result.match) {
          await sendFaceMatchPhoto(imageBase64, timestamp);
        } else {
          await sendTelegramAlert(imageBase64, timestamp);
        }
      } catch (err) {
        console.error('face photo send failed:', redact(err.message));
      }

      return res.status(200).json({ match: result.match, confidence: result.confidence });
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
        description: product.description || '',
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
    console.error('admin error:', redact(err.message));
    return res.status(500).json({ error: redact(err.message) || 'Something went wrong.' });
  }
};
