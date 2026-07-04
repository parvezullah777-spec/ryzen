const { supabase } = require('./_lib/supabase');
const { requireAuth } = require('./_lib/auth');

const BUCKET = 'login-photos';

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

function parseMultipart(buffer, boundary) {
  const boundaryStr = `--${boundary}`;
  const parts = buffer.toString('binary').split(boundaryStr).filter((p) => p.trim() && p.trim() !== '--');
  const result = {};

  for (const part of parts) {
    const headerEndIndex = part.indexOf('\r\n\r\n');
    if (headerEndIndex === -1) continue;
    const headers = part.slice(0, headerEndIndex);
    let body = part.slice(headerEndIndex + 4);
    if (body.endsWith('\r\n')) body = body.slice(0, -2);

    const nameMatch = headers.match(/name="([^"]+)"/);
    if (!nameMatch) continue;
    const fieldName = nameMatch[1];

    if (headers.includes('filename=')) {
      result[fieldName] = { isFile: true, buffer: Buffer.from(body, 'binary') };
    } else {
      result[fieldName] = body.toString();
    }
  }
  return result;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const session = requireAuth(req, res);
  if (!session) return;

  try {
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)$/);
    if (!boundaryMatch) {
      return res.status(400).json({ error: 'Expected multipart/form-data' });
    }

    const rawBody = await readRawBody(req);
    const fields = parseMultipart(rawBody, boundaryMatch[1]);

    const loginLogId = fields.loginLogId;
    const file = fields.file;

    if (!loginLogId || !file || !file.isFile) {
      return res.status(400).json({ error: 'loginLogId and file are required' });
    }

    const path = `${loginLogId}.jpg`;

    const { error: uploadError } = await supabase.storage
      .from(BUCKET)
      .upload(path, file.buffer, { contentType: 'image/jpeg', upsert: true });

    if (uploadError) throw uploadError;

    const { error: updateError } = await supabase
      .from('login_logs')
      .update({ photo_path: path })
      .eq('id', loginLogId);

    if (updateError) throw updateError;

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('login-photo.js error:', err);
    return res.status(500).json({ error: err.message || 'Failed to save login photo' });
  }
};
