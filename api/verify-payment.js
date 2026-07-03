const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, shipping, items, total } = req.body || {};

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ error: 'Missing required payment fields.' });
  }

  const body = `${razorpay_order_id}|${razorpay_payment_id}`;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest('hex');

  const isValid = expectedSignature === razorpay_signature;

  if (!isValid) {
    return res.status(400).json({ success: false, error: 'Payment verification failed.' });
  }

  // Payment is genuine — send a Telegram alert. Failures here must never
  // block the customer's success response, so this is best-effort only.
  try {
    await sendTelegramOrderAlert({ razorpay_order_id, razorpay_payment_id, shipping, items, total });
  } catch (err) {
    console.error('telegram-alert error:', err);
  }

  return res.status(200).json({ success: true });
};

async function sendTelegramOrderAlert({ razorpay_order_id, razorpay_payment_id, shipping, items, total }) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  const lines = [];
  lines.push('🛍️ *New Ryzen Order*');
  lines.push('');

  if (Array.isArray(items) && items.length) {
    items.forEach((i) => {
      const qty = i.qty || 1;
      const lineTotal = (i.price || 0) * qty;
      lines.push(`• ${i.name} (Size: ${i.size || '-'}) x${qty} — ₹${lineTotal.toLocaleString('en-IN')}`);
    });
    lines.push('');
  }

  if (typeof total === 'number') {
    lines.push(`*Total: ₹${total.toLocaleString('en-IN')}*`);
    lines.push('');
  }

  if (shipping) {
    lines.push('*Deliver To:*');
    lines.push(`${shipping.name || ''} | ${shipping.phone || ''}`);
    if (shipping.email) lines.push(shipping.email);
    const addrLine = [shipping.line1, shipping.line2, shipping.city, shipping.state, shipping.pincode, shipping.country]
      .filter(Boolean)
      .join(', ');
    lines.push(addrLine);
    lines.push('');
  }

  lines.push(`Order ID: ${razorpay_order_id}`);
  lines.push(`Payment ID: ${razorpay_payment_id}`);

  const text = lines.join('\n');

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: text,
      parse_mode: 'Markdown',
    }),
  });
}
