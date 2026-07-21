const { supabase } = require('./_lib/supabase');
const { requireAuth } = require('./_lib/auth');

/* ─────────────────────────────────────────────────────────────────────────
   ASSUMED SCHEMA — I don't have your real `orders` table columns yet, so
   this is written against the most common Razorpay + Supabase pattern:

     orders
       id                  uuid, pk
       customer_id         uuid, fk -> customers.id (nullable for guest checkout)
       items               jsonb   (array of { productId, name, price, qty, size })
       total_amount        numeric
       status              text    ('pending' | 'paid' | 'shipped' | 'delivered' | 'cancelled')
       razorpay_order_id   text
       razorpay_payment_id text    (nullable until paid)
       created_at          timestamptz
       updated_at          timestamptz

   >>> BEFORE DEPLOYING: run `select * from orders limit 1;` in Supabase
   >>> and compare column names below (marked with "ADJUST HERE" comments).
   >>> If a column name differs, it's a one-line fix in COLS below — nothing
   >>> else in this file needs to change.
   ───────────────────────────────────────────────────────────────────────── */
const COLS = {
  id: 'id',
  customerId: 'customer_id',       // ADJUST HERE if different
  items: 'items',                  // ADJUST HERE if different
  amount: 'total_amount',          // ADJUST HERE if different (e.g. "amount")
  status: 'status',                // ADJUST HERE if different
  razorpayOrderId: 'razorpay_order_id',
  razorpayPaymentId: 'razorpay_payment_id',
  createdAt: 'created_at',
  updatedAt: 'updated_at',
  // Order-details columns — added by order-details-migration.sql. If that
  // migration hasn't been run yet, these reads just come back null/empty,
  // which the API and UI both handle gracefully (nothing breaks).
  trackingNumber: 'tracking_number',
  courier: 'courier',
  paymentStatus: 'payment_status',
  customerNotes: 'customer_notes',
  adminNotes: 'admin_notes',
  timeline: 'timeline',
};

const STATUS_LABELS = {
  pending: 'Pending', paid: 'Paid', shipped: 'Shipped',
  delivered: 'Delivered', cancelled: 'Cancelled',
};

const VALID_STATUSES = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];

function checkPerm(session, action) {
  if (session.role === 'super_admin') return true;
  const perm = (session.permissions && session.permissions.orders) || {};
  if (['update-status', 'update-tracking', 'add-note'].includes(action)) return !!perm.edit;
  return !!perm.view; // list/get/stats
}

function toApi(row) {
  return {
    id: row[COLS.id],
    customerId: row[COLS.customerId] || null,
    customerName: row.customer_name || undefined,  // present only when joined
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

module.exports = async (req, res) => {
  const action = req.query.action;

  try {
    const session = requireAuth(req, res);
    if (!session) return;
    if (!checkPerm(session, action)) {
      return res.status(403).json({ error: 'You do not have permission to do that.' });
    }

    /* ---- list: paginated orders, newest first, optional status filter ---- */
    if (req.method === 'GET' && action === 'list') {
      const status = req.query.status;
      const limit = Math.min(Number(req.query.limit) || 50, 200);
      const offset = Number(req.query.offset) || 0;

      let query = supabase
        .from('orders')
        .select(`*, customers ( name, email )`, { count: 'exact' })
        .order(COLS.createdAt, { ascending: false })
        .range(offset, offset + limit - 1);

      if (status && VALID_STATUSES.includes(status)) {
        query = query.eq(COLS.status, status);
      }

      const { data, error, count } = await query;
      if (error) throw error;

      const orders = data.map((row) => {
        const flat = { ...row };
        if (row.customers) {
          flat.customer_name = row.customers.name;
          flat.customer_email = row.customers.email;
        }
        return toApi(flat);
      });

      return res.status(200).json({ orders, total: count });
    }

    /* ---- get: single order by id ---- */
    if (req.method === 'GET' && action === 'get') {
      const { id } = req.query;
      if (!id) return res.status(400).json({ error: 'Order id is required' });

      const { data, error } = await supabase
        .from('orders')
        .select(`*, customers ( name, email, phone )`)
        .eq(COLS.id, id)
        .single();

      if (error) throw error;
      const flat = { ...data };
      if (data.customers) {
        flat.customer_name = data.customers.name;
        flat.customer_email = data.customers.email;
        flat.customer_phone = data.customers.phone;
      }
      return res.status(200).json({ order: toApi(flat) });
    }

    /* ---- update-status: move an order through its lifecycle ---- */
    if (req.method === 'POST' && action === 'update-status') {
      const { id, status, note } = req.body;
      if (!id || !status) return res.status(400).json({ error: 'Order id and status are required' });
      if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({ error: `Status must be one of: ${VALID_STATUSES.join(', ')}` });
      }

      const { data: current, error: fetchErr } = await supabase
        .from('orders').select(COLS.timeline).eq(COLS.id, id).single();
      if (fetchErr) throw fetchErr;

      const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
      timeline.push({
        status,
        note: note || `Marked ${STATUS_LABELS[status] || status}`,
        at: new Date().toISOString(),
        by: session.username || session.role,
      });

      const { data, error } = await supabase
        .from('orders')
        .update({ [COLS.status]: status, [COLS.updatedAt]: new Date().toISOString(), [COLS.timeline]: timeline })
        .eq(COLS.id, id)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json({ order: toApi(data) });
    }

    /* ---- update-tracking: courier + tracking number ---- */
    if (req.method === 'POST' && action === 'update-tracking') {
      const { id, trackingNumber, courier } = req.body;
      if (!id) return res.status(400).json({ error: 'Order id is required' });

      const { data: current, error: fetchErr } = await supabase
        .from('orders').select(COLS.timeline).eq(COLS.id, id).single();
      if (fetchErr) throw fetchErr;
      const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
      timeline.push({
        status: null,
        note: `Tracking updated: ${courier || 'courier'} — ${trackingNumber || 'no number'}`,
        at: new Date().toISOString(),
        by: session.username || session.role,
      });

      const { data, error } = await supabase
        .from('orders')
        .update({
          [COLS.trackingNumber]: trackingNumber || null,
          [COLS.courier]: courier || null,
          [COLS.updatedAt]: new Date().toISOString(),
          [COLS.timeline]: timeline,
        })
        .eq(COLS.id, id)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json({ order: toApi(data) });
    }

    /* ---- add-note: append an admin note (kept separate from customer notes) ---- */
    if (req.method === 'POST' && action === 'add-note') {
      const { id, note } = req.body;
      if (!id || !note) return res.status(400).json({ error: 'Order id and note text are required' });

      const { data: current, error: fetchErr } = await supabase
        .from('orders').select(`${COLS.adminNotes}, ${COLS.timeline}`).eq(COLS.id, id).single();
      if (fetchErr) throw fetchErr;

      const stamp = `[${new Date().toLocaleString()} · ${session.username || session.role}] ${note}`;
      const combinedNotes = current[COLS.adminNotes] ? `${current[COLS.adminNotes]}\n${stamp}` : stamp;
      const timeline = Array.isArray(current[COLS.timeline]) ? current[COLS.timeline] : [];
      timeline.push({ status: null, note: `Note added: ${note}`, at: new Date().toISOString(), by: session.username || session.role });

      const { data, error } = await supabase
        .from('orders')
        .update({ [COLS.adminNotes]: combinedNotes, [COLS.timeline]: timeline, [COLS.updatedAt]: new Date().toISOString() })
        .eq(COLS.id, id)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json({ order: toApi(data) });
    }

    /* ---- stats: powers the Dashboard Revenue/Orders/Customers cards ---- */
    if (req.method === 'GET' && action === 'stats') {
      const { data: orderRows, error: ordersErr } = await supabase
        .from('orders')
        .select(`${COLS.amount}, ${COLS.status}, ${COLS.createdAt}, ${COLS.customerId}`);
      if (ordersErr) throw ordersErr;

      const paidStatuses = ['paid', 'shipped', 'delivered'];
      const paidOrders = orderRows.filter((o) => paidStatuses.includes(o[COLS.status]));

      const totalRevenue = paidOrders.reduce((sum, o) => sum + Number(o[COLS.amount] || 0), 0);
      const totalOrders = orderRows.length;

      const uniqueCustomerIds = new Set(orderRows.map((o) => o[COLS.customerId]).filter(Boolean));
      const { count: totalCustomers } = await supabase
        .from('customers')
        .select('id', { count: 'exact', head: true });

      // last 30 days revenue trend, bucketed by day, for the Revenue Overview chart
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const recentPaid = paidOrders.filter((o) => new Date(o[COLS.createdAt]) >= thirtyDaysAgo);
      const byDay = {};
      recentPaid.forEach((o) => {
        const day = new Date(o[COLS.createdAt]).toISOString().slice(0, 10);
        byDay[day] = (byDay[day] || 0) + Number(o[COLS.amount] || 0);
      });
      const revenueTrend = Object.entries(byDay)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([date, amount]) => ({ date, amount }));

      return res.status(200).json({
        totalRevenue,
        totalOrders,
        totalCustomers: totalCustomers ?? uniqueCustomerIds.size,
        revenueTrend,
      });
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    console.error('orders.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
