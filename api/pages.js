const { supabase } = require('./_lib/supabase');
const { verifyToken } = require('./_lib/auth');

module.exports = async (req, res) => {
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
      const { slug } = req.query;

      if (slug) {
        const { data, error } = await supabase
          .from('pages')
          .select('*')
          .eq('slug', slug)
          .single();

        if (error) throw error;
        return res.status(200).json(data);
      }

      const { data, error } = await supabase
        .from('pages')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.status(200).json(data);
    }

    if (req.method === 'POST') {
      const { slug, title, content, meta } = req.body;

      if (!slug) {
        return res.status(400).json({ error: 'Page slug is required' });
      }

      const { data, error } = await supabase
        .from('pages')
        .insert([{ slug, title, content, meta: meta || {} }])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json(data);
    }

    if (req.method === 'PUT' || req.method === 'PATCH') {
      const { id, ...updates } = req.body;

      if (!id) {
        return res.status(400).json({ error: 'Page id is required' });
      }

      updates.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('pages')
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
        return res.status(400).json({ error: 'Page id is required' });
      }

      const { error } = await supabase.from('pages').delete().eq('id', id);

      if (error) throw error;
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('pages.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
