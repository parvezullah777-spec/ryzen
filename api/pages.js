const { supabase } = require('./_lib/supabase');
const { requireAuth } = require('./_lib/auth');

function checkPerm(session, action) {
  if (session.role === 'super_admin') return true;
  const perm = (session.permissions && session.permissions.pages) || {};
  if (action === 'delete') return !!perm.delete;
  return !!perm.edit; // create/update
}

function toApi(row) {
  return {
    slug: row.slug,
    title: row.title,
    type: row.type || 'static',
    html: row.html || '',
    blocks: row.blocks || [],
  };
}

function slugify(title) {
  return String(title)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

module.exports = async (req, res) => {
  const action = req.query.action;

  try {
    let session = null;
    if (action !== 'list' && action !== 'get') {
      session = requireAuth(req, res);
      if (!session) return;
      if (!checkPerm(session, action)) {
        return res.status(403).json({ error: 'You do not have permission to do that.' });
      }
    }

    if (req.method === 'GET' && action === 'list') {
      const { data, error } = await supabase
        .from('pages')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.status(200).json({ pages: data.map(toApi) });
    }

    if (req.method === 'GET' && action === 'get') {
      const { slug } = req.query;
      if (!slug) return res.status(400).json({ error: 'slug is required' });

      const { data, error } = await supabase
        .from('pages')
        .select('*')
        .eq('slug', slug)
        .single();

      if (error) throw error;
      return res.status(200).json({ page: toApi(data) });
    }

    if (req.method === 'POST' && action === 'create') {
      const { title, type, html, blocks } = req.body;
      if (!title) return res.status(400).json({ error: 'Title is required' });

      let slug = slugify(title);
      const { data: existing } = await supabase.from('pages').select('slug').eq('slug', slug).maybeSingle();
      if (existing) slug = `${slug}-${Date.now().toString(36)}`;

      const { data, error } = await supabase
        .from('pages')
        .insert([{ slug, title, type: type || 'static', html: html || '', blocks: blocks || [] }])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json({ page: toApi(data) });
    }

    if (req.method === 'POST' && action === 'update') {
      const { slug, title, html, blocks } = req.body;
      if (!slug) return res.status(400).json({ error: 'slug is required' });

      const updates = { title, updated_at: new Date().toISOString() };
      if (html !== undefined) updates.html = html;
      if (blocks !== undefined) updates.blocks = blocks;

      const { data, error } = await supabase
        .from('pages')
        .update(updates)
        .eq('slug', slug)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json({ page: toApi(data) });
    }

    if (req.method === 'POST' && action === 'delete') {
      const { slug } = req.body;
      if (!slug) return res.status(400).json({ error: 'slug is required' });

      const { error } = await supabase.from('pages').delete().eq('slug', slug);
      if (error) throw error;
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    console.error('pages.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
