import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.103.0';
import { getCorsHeaders } from '../_shared/cors.ts';

function jsonResponse(body: unknown, status = 200, origin: string | null = null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...getCorsHeaders(origin),
      'Content-Type': 'application/json',
    },
  });
}

// Inline auth utilities
const CRM_AUTH_DOMAIN = 'crm.local';

function normalizeUsername(username: string) {
  return username
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
}

function getInternalAuthEmail(username: string) {
  return `${normalizeUsername(username)}@${CRM_AUTH_DOMAIN}`;
}

function validatePassword(password: unknown) {
  if (typeof password !== 'string' || password.length === 0) {
    return 'Informe uma senha.';
  }

  if (password.length < 6) {
    return 'A senha deve ter pelo menos 6 caracteres.';
  }

  if (!/\d/.test(password)) {
    return 'A senha deve conter pelo menos 1 numero.';
  }

  return null;
}

function getSupabaseClients() {
  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    throw new Error('Supabase environment variables are not configured.');
  }

  return {
    authClient: createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    }),
    adminClient: createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    }),
  };
}

async function requireAdmin(adminClient: ReturnType<typeof createClient>, authHeader: string | null) {
  const token = authHeader?.replace(/^Bearer\s+/i, '');
  if (!token) {
    return { error: 'Unauthorized', status: 401 };
  }

  const { authClient } = getSupabaseClients();
  const { data: authData, error: authError } = await authClient.auth.getUser(token);
  const authUserId = authData?.user?.id;

  if (authError || !authUserId) {
    return { error: 'Invalid token', status: 401 };
  }

  const { data: profile, error: profileError } = await adminClient
    .from('crm_mkt_users')
    .select('id, role, active, auth_user_id')
    .eq('auth_user_id', authUserId)
    .maybeSingle();

  if (profileError || !profile || profile.role !== 'admin' || profile.active === false) {
    return { error: 'Forbidden', status: 403 };
  }

  return { profile, authUser: { id: authUserId } };
}

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: getCorsHeaders(origin) });
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405, origin);
  }

  try {
    const { adminClient } = getSupabaseClients();

    const adminCheck = await requireAdmin(adminClient, req.headers.get('Authorization'));
    if ('error' in adminCheck) {
      return jsonResponse({ error: adminCheck.error }, adminCheck.status, origin);
    }

    const body = await req.json();
    const { action } = body;

    // ─── CREATE ───────────────────────────────────────────────────────────────
    if (action === 'create') {
      const { username: rawUsername, password, name, email, role, clientId, clientName, client_ids, phone, bio, photoUrl } = body;

      if (!rawUsername || !password || !name || !role) {
        return jsonResponse({ error: 'Campos obrigatórios: username, password, name, role.' }, 400, origin);
      }

      const passwordError = validatePassword(password);
      if (passwordError) {
        return jsonResponse({ error: passwordError }, 400, origin);
      }

      const username = normalizeUsername(String(rawUsername));
      const authEmail = getInternalAuthEmail(username);
      const normalizedClientIds = Array.isArray(client_ids)
        ? client_ids.filter(Boolean)
        : (clientId ? [clientId] : []);
      const primaryClientId = normalizedClientIds[0] || clientId || null;

      // Cria usuário no Supabase Auth
      const { data: authData, error: authError } = await adminClient.auth.admin.createUser({
        email: authEmail,
        password,
        email_confirm: true,
        user_metadata: { username, name, role },
      });

      if (authError || !authData?.user) {
        return jsonResponse({ error: authError?.message || 'Erro ao criar usuário no Auth.' }, 400, origin);
      }

      const authUserId = authData.user.id;

      // Insere perfil na tabela users
      const { data: profile, error: profileError } = await adminClient
        .from('crm_mkt_users')
        .insert({
          auth_user_id: authUserId,
          username,
          name,
          email: email || null,
          role,
          clientId: primaryClientId,
          clientName: clientName || null,
          client_ids: normalizedClientIds,
          phone: phone || null,
          bio: bio || null,
          photoUrl: photoUrl || null,
          active: true,
        })
        .select()
        .single();

      if (profileError || !profile) {
        // Rollback: remove usuário do Auth se o perfil falhou
        await adminClient.auth.admin.deleteUser(authUserId);
        return jsonResponse({ error: profileError?.message || 'Erro ao criar perfil do usuário.' }, 500, origin);
      }

      return jsonResponse({ user: profile }, 200, origin);
    }

    // ─── UPDATE ───────────────────────────────────────────────────────────────
    if (action === 'update') {
      const { userId, password, ...updateFields } = body;
      delete updateFields.action;

      if (!userId) {
        return jsonResponse({ error: 'userId é obrigatório para update.' }, 400, origin);
      }

      // Busca auth_user_id do perfil
      const { data: existing, error: fetchError } = await adminClient
        .from('crm_mkt_users')
        .select('auth_user_id')
        .eq('id', userId)
        .maybeSingle();

      if (fetchError || !existing) {
        return jsonResponse({ error: 'Usuário não encontrado.' }, 404, origin);
      }

      // Atualiza senha no Auth se fornecida
      if (password && existing.auth_user_id) {
        const passwordError = validatePassword(password);
        if (passwordError) {
          return jsonResponse({ error: passwordError }, 400, origin);
        }

        const { error: pwError } = await adminClient.auth.admin.updateUserById(
          existing.auth_user_id,
          { password },
        );
        if (pwError) {
          return jsonResponse({ error: 'Erro ao atualizar senha: ' + pwError.message }, 400, origin);
        }
      }

      // Remove campos que não devem ir para a tabela users
      if (updateFields.password !== undefined) delete updateFields.password;

      const { data: profile, error: profileError } = await adminClient
        .from('crm_mkt_users')
        .update(updateFields)
        .eq('id', userId)
        .select()
        .single();

      if (profileError || !profile) {
        return jsonResponse({ error: profileError?.message || 'Erro ao atualizar perfil.' }, 500, origin);
      }

      return jsonResponse({ user: profile }, 200, origin);
    }

    // ─── DELETE ───────────────────────────────────────────────────────────────
    if (action === 'delete') {
      const { userId } = body;

      if (!userId) {
        return jsonResponse({ error: 'userId é obrigatório para delete.' }, 400, origin);
      }

      const { data: existing, error: fetchError } = await adminClient
        .from('crm_mkt_users')
        .select('id, auth_user_id, username')
        .eq('id', userId)
        .maybeSingle();

      if (fetchError || !existing) {
        return jsonResponse({ error: 'Usuário não encontrado.' }, 404, origin);
      }

      // Remove o login no Auth e desativa o perfil CRM sem apagar historico vinculado.
      if (existing.auth_user_id) {
        await adminClient.auth.admin.deleteUser(existing.auth_user_id);
      }

      const { data: profile, error: deactivateProfileError } = await adminClient
        .from('crm_mkt_users')
        .update({
          active: false,
          auth_user_id: null,
          username: `${existing.username || 'deleted'}__deleted__${Date.now()}`,
        })
        .eq('id', userId)
        .select()
        .single();

      if (deactivateProfileError || !profile) {
        return jsonResponse({ error: deactivateProfileError?.message || 'Erro ao desativar perfil.' }, 500, origin);
      }

      return jsonResponse({ success: true }, 200, origin);
    }

    // ─── RESET PASSWORD ───────────────────────────────────────────────────────
    if (action === 'reset_password') {
      const { userId, password } = body;

      if (!userId || !password) {
        return jsonResponse({ error: 'userId e password são obrigatórios.' }, 400, origin);
      }

      const passwordError = validatePassword(password);
      if (passwordError) {
        return jsonResponse({ error: passwordError }, 400, origin);
      }

      const { data: existing, error: fetchError } = await adminClient
        .from('crm_mkt_users')
        .select('auth_user_id')
        .eq('id', userId)
        .maybeSingle();

      if (fetchError || !existing?.auth_user_id) {
        return jsonResponse({ error: 'Usuário não encontrado ou sem conta Auth.' }, 404, origin);
      }

      const { error: pwError } = await adminClient.auth.admin.updateUserById(
        existing.auth_user_id,
        { password },
      );

      if (pwError) {
        return jsonResponse({ error: 'Erro ao redefinir senha: ' + pwError.message }, 400, origin);
      }

      return jsonResponse({ success: true }, 200, origin);
    }

    return jsonResponse({ error: 'Ação inválida. Use: create, update, delete, reset_password.' }, 400, origin);
  } catch (error) {
    console.error('admin-manage-user error:', error);
    return jsonResponse({ error: 'Erro interno.' }, 500, origin);
  }
});
