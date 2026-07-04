const { supabase } = require('./_lib/supabase');
const { verifyToken } = require('./_lib/auth');

const BUCKET = 'product-images';

// Vercel's default body parser doesn't handle multipart/form-data well,
// so we disable it and parse the raw body ourselves.
module.exports.config = {
  api: {
    bodyParser: false,
  },
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Minimal multipart/form-data parser for a single file field named "file"
function parseMultipart(buffer, boundary) {
  const boundaryStr = `--${boundary}`;
  const parts = buffer
    .toString('binary')
    .split(boundaryStr)
    .filter((p) => p.trim() && p.trim() !== '--');

  for (const part of parts) {
    if (part.includes('name="file"')) {
      const headerEndIndex = part.indexOf('\r\n\r\n');
      if (headerEndIndex === -1) continue;

      const headers = part.slice(0, headerEndIndex);
      const filenameMatch = headers.match(/filename="(.+?)"/);
      const contentTypeMatch = headers.match(/Content-Type:\s*(.+)/i);

      if (!filenameMatch) continue;

      const filename = filenameMatch[1];
      const contentType = contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream';

      // Body is everything after the header block, minus the trailing \r\n
      let body = part.slice(headerEndIndex + 4);
      if (body.endsWith('\r\n')) body = body.slice(0, -2);

      const fileBuffer = Buffer.from(body, 'binary');
      return { filename, contentType, fileBuffer };
    }
  }
  return null;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)$/);
    if (!boundaryMatch) {
      return res.status(400).json({ error: 'Expected multipart/form-data with a file field' });
    }

    const rawBody = await readRawBody(req);
    const parsed = parseMultipart(rawBody, boundaryMatch[1]);

    if (!parsed) {
      return res.status(400).json({ error: 'No file found in upload' });
    }

    const { filename, contentType: fileContentType, fileBuffer } = parsed;
    const ext = filename.includes('.') ? filename.split('.').pop() : 'jpg';
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from(BUCKET)
      .upload(uniqueName, fileBuffer, {
        contentType: fileContentType,
        upsert: false,
      });

    if (uploadError) throw uploadError;

    const { data: publicUrlData } = supabase.storage.from(BUCKET).getPublicUrl(uniqueName);

    return res.status(200).json({ url: publicUrlData.publicUrl });
  } catch (err) {
    console.error('upload.js error:', err);
    return res.status(500).json({ error: err.message || 'Upload failed' });
  }
};
