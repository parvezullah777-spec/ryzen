// api/order.js
// Orders CRUD/stats (admin-only, requires auth) PLUS the Razorpay webhook
// (action=webhook, no auth — Razorpay calls this directly) in one file, to
// avoid adding a 14th serverless function on top of an already-full
// Vercel Hobby deployment (12 function limit).
//
// Because the webhook needs the RAW request body to verify Razorpay's
// signature, this file disables Vercel's automatic body parsing for ALL
// actions and parses JSON manually for the admin actions instead. See
// readRawBody() below.

const crypto = require('crypto');
const { supabase } = require('./_lib/supabase');
const { requireAuth } = require('./_lib/auth');

/* ─────────────────────────────────────────────────────────────────────────
   ASSUMED SCHEMA — matches the standard Razorpay + Supabase pattern.
   >>> BEFORE RELYING ON THIS: run `select * from orders limit 1;` in
   >>> Supabase and compare column names below. One-line fix if different.
   ───────────────────────────────────────────────────────────────────────── */
const COLS = {
  id: 'id',
  customerId: 'customer_id',
  items: 'items',
  amount: 'total_amount',           // ADJUST HERE if your column is named "amount"
  status: 'status',
  razorpayOrderId: 'razorpay_order_id',
  razorpayPaymentId: 'razorpay_payment_id',
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  trackingNumber: 'tracking_number',       // from order-details-migration.sql
  courier: 'courier',
  paymentStatus: 'payment_status',
  customerNotes: 'customer_notes',
  adminNotes: 'admin_notes',
  timeline: 'timeline',
};

const VALID_STATUSES = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];
const STATUS_LABELS = { pending: 'Pending', paid: 'Paid', shipped: 'Shipped', delivered: 'Delivered', cancelled: 'Cancelled' };

module.exports.config = {
  api: { bodyParser: false },
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function checkPerm(session, action) {
  if (session.role === 'super_admin') return true;
  const perm = (session.permissions && session.permissions.orders) || {};
  if (['update-status', 'update-tracking', 'add-note'].includes(action)) return !!perm.edit;
  return !!perm.view;
}

function toApi(row) {
  return {
    id: row[COLS.id],
    customerId: row[COLS.customerId] || null,
    customerName: row.customer_name || undefined,
    customerEmail: row.customer_email || undefined,
    customerPhone: row.customer_phone || undefined,
    items: row[COLS.items] || [],
    amount: Number(row[COLS.amount] || 0),
    status: row[COLS.status] || 'pending',
    razorpayOrderId: row[COLS.razorpayOrderId] || null,
    razorpayPaymentId: row[COLS.razorpayPaymentId] || null,
    trackingNumber: row[COLS.trackingNumber] || null,
    courier: row[COLS.courier] || null,
    paymentStatus: row[COLS.paymentStatus] || (row[COLS.razorpayPaymentId] ? 'paid' : 'pending'),
    customerNotes: row[COLS.customerNotes] || '',
    adminNotes: row[COLS.adminNotes] || '',
    timeline: row[COLS.timeline] || [],
    createdAt: row[COLS.createdAt],
    updatedAt: row[COLS.updatedAt],
  };
}

/* ───────────────────────── Razorpay webhook (no auth) ───────────────────────── */
function verifyWebhookSignature(rawBody, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || '');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function handleWebhook(rawBody, req, res) {
  const signature = req.headers['x-razorpay-signature'] || '';
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

  if (!secret) {
    console.error('order.js webhook: RAZORPAY_WEBHOOK_SECRET is not set');
    return res.status(500).json({ error: 'Webhook not configured' });
  }
  if (!verifyWebhookSignature(rawBody, signature, secret)) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const event = payload.event;
  const paymentEntity = payload.payload && payload.payload.payment && payload.payload.payment.entity;
  if (!paymentEntity) return res.status(200).json({ received: true });

  try {
    if (event === 'payment.captured') {
      const razorpayOrderId = paymentEntity.order_id;
      const razorpayPaymentId = paymentEntity.id;
      const amount = paymentEntity.amount / 100; // Razorpay sends paise
      const notes = paymentEntity.notes || {};

      const { data: existing } = await supabase
        .from('orders').select('id, ' + COLS.timeline).eq(COLS.razorpayOrderId, razorpayOrderId).maybeSingle();

      if (existing) {
        const timeline = Array.isArray(existing[COLS.timeline]) ? existing[COLS.timeline] : [];
        timeline.push({ status: 'paid', note: 'Payment captured via Razorpay webhook', at: new Date().toISOString(), by: 'razorpay-webhook' });
        const { error } = await supabase
          .from('orders')
          .update({ [COLS.status]: 'paid', [COLS.razorpayPaymentId]: razorpayPaymentId, [COLS.timeline]: timeline, [COLS.updatedAt]: new Date().toISOString() })
          .eq('id', existing.id);
        if (error) throw error;
      } else {
        const { error } = await supabase.from('orders').insert([{
          [COLS.amount]: amount,
          [COLS.status]: 'paid',
          [COLS.razorpayOrderId]: razorpayOrderId,
          [COLS.razorpayPaymentId]: razorpayPaymentId,
          [COLS.items]: notes.items ? JSON.parse(notes.items) : [],
          [COLS.timeline]: [{ status: 'paid', note: 'Order created from Razorpay webhook (no matching pending order found)', at: new Date().toISOString(), by: 'razorpay-webhook' }],
        }]);
        if (error) throw error;
      }
    }

    if (event === 'payment.failed') {
      const razorpayOrderId = paymentEntity.order_id;
      await supabase.from('orders')
        .update({ [COLS.status]: 'cancelled', [COLS.updatedAt]: new Date().toISOString() })
        .eq(COLS.razorpayOrderId, razorpayOrderId);
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('order.js webhook error:', err);
    // Still 200 so Razorpay doesn't hammer retries — check Vercel logs.
    return res.status(200).json({ received: true, warning: 'logged error, see server logs' });
  }
}

/* ───────────────────────── Admin-facing order actions ───────────────────────── */
async function handleList(req, res) {
  const status = req.query.status;
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const offset = Number(req.query.offset) || 0;

  let query = supabase
    .from('orders')
    .select(`*, customers ( name, email )`, { count: 'exact' })
    .order(COLS.createdAt, { ascending: false })
    .range(offset, offset + limit - 1);

  if (status && VALID_STATUSES.includes(status)) query = query.eq(COLS.status, status);

  const { data, error, count } = await query;
  if (error) throw error;

  const orders = data.map((row) => {
    const flat = { ...row };
    if (row.customers) { flat.customer_name = row.customers.name; flat.customer_email = row.customers.email; }
    return toApi(flat);
  });
  return res.status(200).json({ orders, total: count });
}

async function handleGet(req, res) {
  const { id } = req.query;
  if (!id) return res.status(400).json({ error: 'Order id is required' });

  const { data, error } = await supabase
    .from('orders').select(`*, customers ( name, email, phone )`).eq(COLS.id, id).single();
  if (error) throw error;

  const flat = { ...data };
  if (data.customers) { flat.customer_name = data.customers.name; flat.customer_email = data.customers.email; flat.customer_phone = data.customers.phone; }
  return res.status(200).json({ order: toApi(flat) });
}

async function handleUpdateStatus(body, session, res) {
  const { id, status, note } = body;
  if (!id || !status) return res.status(400).json({ error: 'Order id and status are required' });
  if (!VALID_STATUSES.includes(status)) return res.status(400).json({ error: `Status must be one of: ${VALID_STATUSES.join(', ')}` });

  const { data: current, error: fetchErr } = await supabase.from('orders').select(COLS.timeline).eq(COLS.id, id).single();
  if (fetchErr) throw fetchErr;

  const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
  timeline.push({ status, note: note || `Marked ${STATUS_LABELS[status] || status}`, at: new Date().toISOString(), by: session.username || session.role });

  const { data, error } = await supabase
    .from('orders')
    .update({ [COLS.status]: status, [COLS.updatedAt]: new Date().toISOString(), [COLS.timeline]: timeline })
    .eq(COLS.id, id).select().single();
  if (error) throw error;
  return res.status(200).json({ order: toApi(data) });
}

async function handleUpdateTracking(body, session, res) {
  const { id, trackingNumber, courier } = body;
  if (!id) return res.status(400).json({ error: 'Order id is required' });

  const { data: current, error: fetchErr } = await supabase.from('orders').select(COLS.timeline).eq(COLS.id, id).single();
  if (fetchErr) throw fetchErr;
  const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
  timeline.push({ status: null, note: `Tracking updated: ${courier || 'courier'} — ${trackingNumber || 'no number'}`, at: new Date().toISOString(), by: session.username || session.role });

  const { data, error } = await supabase
    .from('orders')
    .update({ [COLS.trackingNumber]: trackingNumber || null, [COLS.courier]: courier || null, [COLS.updatedAt]: new Date().toISOString(), [COLS.timeline]: timeline })
    .eq(COLS.id, id).select().single();
  if (error) throw error;
  return res.status(200).json({ order: toApi(data) });
}

async function handleAddNote(body, session, res) {
  const { id, note } = body;
  if (!id || !note) return res.status(400).json({ error: 'Order id and note text are required' });

  const { data: current, error: fetchErr } = await supabase.from('orders').select(`${COLS.adminNotes}, ${COLS.timeline}`).eq(COLS.id, id).single();
  if (fetchErr) throw fetchErr;

  const stamp = `[${new Date().toLocaleString()} · ${session.username || session.role}] ${note}`;
  const combinedNotes = current[COLS.adminNotes] ? `${current[COLS.adminNotes]}\n${stamp}` : stamp;
  const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
  timeline.push({ status: null, note: `Note added: ${note}`, at: new Date().toISOString(), by: session.username || session.role });

  const { data, error } = await supabase
    .from('orders')
    .update({ [COLS.adminNotes]: combinedNotes, [COLS.timeline]: timeline, [COLS.updatedAt]: new Date().toISOString() })
    .eq(COLS.id, id).select().single();
  if (error) throw error;
  return res.status(200).json({ order: toApi(data) });
}

async function handleStats(req, res) {
  const { data: orderRows, error: ordersErr } = await supabase
    .from('orders').select(`${COLS.amount}, ${COLS.status}, ${COLS.createdAt}, ${COLS.customerId}`);
  if (ordersErr) throw ordersErr;

  const paidStatuses = ['paid', 'shipped', 'delivered'];
  const paidOrders = orderRows.filter((o) => paidStatuses.includes(o[COLS.status]));
  const totalRevenue = paidOrders.reduce((sum, o) => sum + Number(o[COLS.amount] || 0), 0);
  const totalOrders = orderRows.length;

  const { count: totalCustomers } = await supabase.from('customers').select('id', { count: 'exact', head: true });

  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const recentPaid = paidOrders.filter((o) => new Date(o[COLS.createdAt]) >= thirtyDaysAgo);
  const byDay = {};
  recentPaid.forEach((o) => {
    const day = new Date(o[COLS.createdAt]).toISOString().slice(0, 10);
    byDay[day] = (byDay[day] || 0) + Number(o[COLS.amount] || 0);
  });
  const revenueTrend = Object.entries(byDay).sort(([a], [b]) => (a < b ? -1 : 1)).map(([date, amount]) => ({ date, amount }));

  return res.status(200).json({ totalRevenue, totalOrders, totalCustomers: totalCustomers ?? 0, revenueTrend });
}

/* ───────────────────────── Router ───────────────────────── */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-razorpay-signature');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;
  const rawBody = req.method === 'POST' ? await readRawBody(req) : '';

  // Webhook path — no admin auth, Razorpay calls this directly.
  if (action === 'webhook') {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    return handleWebhook(rawBody, req, res);
  }

  // Every other action is admin-only. Manually parse JSON since bodyParser
  // is disabled for this whole file (needed for the webhook above).
  let body = {};
  if (rawBody) {
    try { body = JSON.parse(rawBody); }
    catch (e) { return res.status(400).json({ error: 'Invalid JSON body' }); }
  }
  req.body = body; // so requireAuth or anything else expecting req.body still works

  try {
    const session = requireAuth(req, res);
    if (!session) return;
    if (!checkPerm(session, action)) {
      return res.status(403).json({ error: 'You do not have permission to do that.' });
    }

    if (req.method === 'GET' && action === 'list') return await handleList(req, res);
    if (req.method === 'GET' && action === 'get') return await handleGet(req, res);
    if (req.method === 'GET' && action === 'stats') return await handleStats(req, res);
    if (req.method === 'POST' && action === 'update-status') return await handleUpdateStatus(body, session, res);
    if (req.method === 'POST' && action === 'update-tracking') return await handleUpdateTracking(body, session, res);
    if (req.method === 'POST' && action === 'add-note') return await handleAddNote(body, session, res);

    return res.status(400).json({ error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('order.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
