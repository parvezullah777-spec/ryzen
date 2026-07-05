const { supabase } = require('./_lib/supabase');
const { hashPassword, verifyPassword } = require('./_lib/passwords');
const { signCustomerToken, requireCustomerAuth, TOKEN_TTL_MS } = require('./_lib/customer-auth');
const { requirePhoneVerification } = require('./otp');

async function getSavedState(customerId) {
  const [{ data: cartRows }, { data: wlRows }, { data: address }] = await Promise.all([
    supabase.from('customer_cart_items').select('*').eq('customer_id', customerId),
    supabase.from('customer_wishlist_items').select('*').eq('customer_id', customerId),
    supabase.from('customer_addresses').select('*').eq('customer_id', customerId).maybeSingle(),
  ]);

  return {
    cart: (cartRows || []).map((r) => ({ name: r.name, price: r.price, size: r.size, qty: r.qty })),
    wishlist: (wlRows || []).map((r) => ({ name: r.name, price: r.price })),
    address: address || null,
  };
}

async function handleSignup(req, res) {
  const { name, email, phone, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  // If a phone number is supplied, it must have been verified via OTP first.
  // The frontend attaches the proof token in this header after a successful
  // /api/otp?action=verify-widget-token call. Skipping this check would let
  // someone create accounts with unverified/fake phone numbers.
  if (phone && !requirePhoneVerification(req, phone)) {
    return res.status(400).json({ error: 'Phone number not verified. Please verify your phone before continuing.' });
  }

  const { data: existing } = await supabase.from('customers').select('id').eq('email', email).maybeSingle();
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists. Try signing in instead.' });
  }

  const { data: customer, error } = await supabase
    .from('customers')
    .insert([{ name: name || null, email, phone: phone || null, password_hash: hashPassword(password) }])
    .select()
    .single();

  if (error) throw error;

  const token = signCustomerToken({ customerId: customer.id, email: customer.email, exp: Date.now() + TOKEN_TTL_MS });
  return res.status(201).json({ token, customer: { id: customer.id, name: customer.name, email: customer.email } });
}

async function handleLogin(req, res) {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const { data: customer, error } = await supabase.from('customers').select('*').eq('email', email).maybeSingle();
  if (error) throw error;
  if (!customer || !verifyPassword(password, customer.password_hash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  const token = signCustomerToken({ customerId: customer.id, email: customer.email, exp: Date.now() + TOKEN_TTL_MS });
  const saved = await getSavedState(customer.id);

  return res.status(200).json({
    token,
    customer: { id: customer.id, name: customer.name, email: customer.email },
    ...saved,
  });
}

async function handleMerge(req, res) {
  const session = requireCustomerAuth(req, res);
  if (!session) return;

  const { cart, wishlist } = req.body || {};

  if (Array.isArray(cart)) {
    for (const item of cart) {
      if (!item.name || !item.size) continue;
      const { data: existingRow } = await supabase
        .from('customer_cart_items')
        .select('*')
        .eq('customer_id', session.customerId)
        .eq('name', item.name)
        .eq('size', item.size)
        .maybeSingle();

      if (existingRow) {
        await supabase
          .from('customer_cart_items')
          .update({ qty: existingRow.qty + (item.qty || 1) })
          .eq('id', existingRow.id);
      } else {
        await supabase.from('customer_cart_items').insert([{
          customer_id: session.customerId,
          name: item.name,
          price: item.price,
          size: item.size,
          qty: item.qty || 1,
        }]);
      }
    }
  }

  if (Array.isArray(wishlist)) {
    for (const item of wishlist) {
      if (!item.name) continue;
      await supabase.from('customer_wishlist_items')
        .insert([{ customer_id: session.customerId, name: item.name, price: item.price }])
        .select()
        .maybeSingle()
        .then(() => {}, () => {}); // unique constraint silently skips duplicates
    }
  }

  const saved = await getSavedState(session.customerId);
  return res.status(200).json(saved);
}

async function handleSaveAddress(req, res) {
  const session = requireCustomerAuth(req, res);
  if (!session) return;

  const { name, phone, email, country, state, city, pincode, line1, line2 } = req.body || {};

  const { data, error } = await supabase
    .from('customer_addresses')
    .upsert(
      { customer_id: session.customerId, name, phone, email, country, state, city, pincode, line1, line2, updated_at: new Date().toISOString() },
      { onConflict: 'customer_id' }
    )
    .select()
    .single();

  if (error) throw error;
  return res.status(200).json({ address: data });
}

async function handleGetState(req, res) {
  const session = requireCustomerAuth(req, res);
  if (!session) return;

  const saved = await getSavedState(session.customerId);
  return res.status(200).json(saved);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Phone-Verify-Token');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;

  try {
    if (req.method === 'POST' && action === 'signup') return await handleSignup(req, res);
    if (req.method === 'POST' && action === 'login') return await handleLogin(req, res);
    if (req.method === 'POST' && action === 'merge') return await handleMerge(req, res);
    if (req.method === 'POST' && action === 'save-address') return await handleSaveAddress(req, res);
    if (req.method === 'GET' && action === 'state') return await handleGetState(req, res);
    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    console.error('customers.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
