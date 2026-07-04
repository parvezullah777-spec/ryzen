const { requireAuth } = require('./_lib/auth');
const { supabase } = require('./_lib/supabase');
const { hashPassword } = require('./_lib/passwords');

function toApi(row) {
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    permissions: row.permissions || {},
    createdAt: row.created_at,
    deactivatedAt: row.deactivated_at,
    mustChangePassword: row.must_change_password,
  };
}

async function logAction(actorId, action, targetId, details = {}) {
  try {
    await supabase.from('admin_logs').insert({
      actor_id: actorId,
      action,
      target_id: targetId,
      details,
    });
  } catch (err) {
    console.error('logAction failed:', err.message);
  }
}

module.exports = async (req, res) => {
  const session = requireAuth(req, res);
  if (!session) return;

  if (session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only the super admin can manage admins.' });
  }

  const action = req.query.action;

  try {
    if (req.method === 'GET' && action === 'list') {
      const { data, error } = await supabase
        .from('admins')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.status(200).json({ admins: data.map(toApi) });
    }

    if (req.method === 'POST' && action === 'create') {
      const { username, password, permissions } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
      }

      const { data, error } = await supabase
        .from('admins')
        .insert([{
          username,
          password_hash: hashPassword(password),
          role: 'sub_admin',
          permissions: permissions || {},
          must_change_password: true,
        }])
        .select()
        .single();

      if (error) throw error;
      await logAction(session.sub, 'create_admin', data.id, { username });
      return res.status(201).json({ admin: toApi(data) });
    }

    if (req.method === 'POST' && action === 'update') {
      const { id, permissions, password } = req.body;
      if (!id) return res.status(400).json({ error: 'Admin id is required.' });

      const updates = { updated_at: new Date().toISOString() };
      if (permissions !== undefined) updates.permissions = permissions;
      if (password) {
        updates.password_hash = hashPassword(password);
        updates.must_change_password = true;
      }

      const { data, error } = await supabase
        .from('admins')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;
      await logAction(session.sub, password ? 'reset_password' : 'update_permissions', id);
      return res.status(200).json({ admin: toApi(data) });
    }

    if (req.method === 'POST' && action === 'delete') {
      const { id } = req.body;
      if (!id) return res.status(400).json({ error: 'Admin id is required.' });

      const { data: target } = await supabase.from('admins').select('role').eq('id', id).single();
      if (target?.role === 'super_admin') {
        return res.status(403).json({ error: 'Cannot deactivate the super admin.' });
      }

      const { error } = await supabase
        .from('admins')
        .update({ deactivated_at: new Date().toISOString() })
        .eq('id', id);

      if (error) throw error;
      await logAction(session.sub, 'deactivate_admin', id);
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    console.error('admins.js error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
};
