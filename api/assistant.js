// api/assistant.js
// Chat endpoint for the in-panel AI assistant. Uses Google Gemini's free
// tier (gemini-2.5-flash-lite has the most generous free daily quota).
// The assistant is READ-ONLY by design: it's given a summary of current
// products/pages for context, but this endpoint has no write path — it
// can only ever return text. Any actual change still has to go through
// the admin clicking Save on products.js / pages.js.

const { supabase } = require('./_lib/supabase');
const { requireAuth } = require('./_lib/auth');
const { getJSON } = require('./_lib/github');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const MODEL = 'gemini-2.5-flash-lite';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;

async function buildContext() {
  let productsSummary = 'No products loaded.';
  let pagesSummary = 'No pages loaded.';

  try {
    const { data: products } = await getJSON('public/products.json');
    if (Array.isArray(products) && products.length) {
      productsSummary = products
        .slice(0, 50)
        .map((p) => `- ${p.name} (${p.catLabel || p.cat}), ₹${p.price}${p.badge ? ', badge: ' + p.badge : ''}`)
        .join('\n');
    }
  } catch (err) {
    console.error('assistant: failed to load products.json context:', err.message);
  }

  try {
    const { data: pages, error } = await supabase
      .from('pages')
      .select('slug, title, type')
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    if (Array.isArray(pages) && pages.length) {
      pagesSummary = pages.map((p) => `- ${p.title} (${p.type}, /${p.slug})`).join('\n');
    }
  } catch (err) {
    console.error('assistant: failed to load pages context:', err.message);
  }

  return `Current products in the store:\n${productsSummary}\n\nCurrent pages:\n${pagesSummary}`;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const session = requireAuth(req, res);
  if (!session) return;

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Use POST.' });
  }

  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: 'GEMINI_API_KEY is not set in Vercel environment variables.' });
  }

  const { message, history } = req.body || {};
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Missing "message" in request body.' });
  }

  try {
    const context = await buildContext();

    const systemInstruction = {
      parts: [
        {
          text:
            'You are the admin assistant inside the Ryzen store\'s admin panel. ' +
            'Ryzen is a premium men\'s fashion brand (T-shirts, cargo pants, joggers, co-ords) sold via pre-order. ' +
            'You help the admin manage products and pages, write product descriptions, and answer questions about their store data. ' +
            'You have READ-ONLY access to the data below — you cannot create, edit, or delete anything yourself. ' +
            'If asked to make a change, clearly explain what you\'d suggest and tell the admin to apply it themselves in the Products or Pages tab. ' +
            'Be concise and practical.\n\n' + context,
        },
      ],
    };

    const contents = [
      ...(Array.isArray(history) ? history : []).map((h) => ({
        role: h.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: h.text }],
      })),
      { role: 'user', parts: [{ text: message }] },
    ];

    const geminiRes = await fetch(`${GEMINI_URL}?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ system_instruction: systemInstruction, contents }),
    });

    if (!geminiRes.ok) {
      const errText = await geminiRes.text();
      console.error('Gemini API error:', geminiRes.status, errText);
      return res.status(502).json({ error: `AI service error (${geminiRes.status}). Try again in a moment.` });
    }

    const data = await geminiRes.json();
    const reply =
      data.candidates &&
      data.candidates[0] &&
      data.candidates[0].content &&
      data.candidates[0].content.parts &&
      data.candidates[0].content.parts.map((p) => p.text || '').join('');

    return res.status(200).json({ reply: reply || 'No response generated.' });
  } catch (err) {
    console.error('assistant.js error:', err);
    return res.status(500).json({ error: err.message || 'Unexpected server error.' });
  }
};
