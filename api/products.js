const { supabase } = require('./_lib/supabase');
const { verifyToken } = require('./_lib/auth');

module.exports = async (req, res) => {
  // --- Auth check for write operations ---
  // GET is public (storefront reads products), everything else requires admin session
  if (req.method !== 'GET') {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('products')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.status(200).json(data);
    }

    if (req.method === 'POST') {
      const { name, description, price, image_url, category, in_stock } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'Product name is required' });
      }

      const { data, error } = await supabase
        .from('products')
        .insert([{ name, description, price, image_url, category, in_stock }])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json(data);
    }

    if (req.method === 'PUT' || req.method === 'PATCH') {
      const { id, ...updates } = req.body;

      if (!id) {
        return res.status(400).json({ error: 'Product id is required' });
      }

      updates.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('products')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json(data);
    }

    if (req.method === 'DELETE') {
      const { id } = req.query.id ? req.query : req.body;

      if (!id) {
        return res.status(400).json({ error: 'Product id is required' });
      }

      const { error } = await supabase.from('products').delete().eq('id', id);

      if (error) throw error;
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('products.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
