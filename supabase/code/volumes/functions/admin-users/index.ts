import { getCorsHeaders, jsonResponse } from '../_shared/cors.ts';
import { getInternalAuthEmail, getSupabaseClients, normalizeUsername, requireAdmin } from '../_shared/auth.ts';

const PROFILE_COLUMNS = 'id, auth_user_id, username, name, email, role, clientId, clientName, client_ids, active, photoUrl, phone, bio';
const ALLOWED_ROLES = new Set(['admin', 'designer', 'creator', 'partner']);

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error || 'Erro desconhecido');
}

function cleanProfilePayload(input: Record<string, unknown>) {
  const role = String(input.role || 'designer') === 'client' ? 'partner' : String(input.role || 'designer');
  if (!ALLOWED_ROLES.has(role)) {
    throw new Error('Nível de acesso inválido.');
  }

  return {
    name: String(input.name || '').trim(),
    email: String(input.email || input.username || '').trim(),
    role,
    clientId: role === 'partner' ? String(input.clientId || '') : null,
    client_ids: role === 'partner'
      ? Array.isArray(input.client_ids)
        ? input.client_ids.filter(Boolean).map(String)
        : (input.clientId ? [String(input.clientId)] : [])
      : [],
    clientName: input.clientName ? String(input.clientName) : role === 'partner' ? input.clientName : '-',
    active: input.active !== false,
    photoUrl: input.photoUrl || null,
    phone: input.phone || null,
    bio: input.bio || null,
  };
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
      const message = adminCheck.status === 403
        ? 'Seu usuario precisa estar vinculado ao Supabase Auth e ter cargo admin ativo.'
        : adminCheck.error;
      return jsonResponse({ error: message }, adminCheck.status, origin);
    }

    const body = await req.json();
    const action = String(body.action || '');

    if (action === 'create') {
      const userInput = body.user || {};
      const username = normalizeUsername(String(userInput.username || ''));
      const password = String(userInput.password || '');
      const payload = cleanProfilePayload({ ...userInput, username });

      if (!username || username.length < 3) {
        return jsonResponse({ error: 'Usuário deve ter pelo menos 3 caracteres.' }, 400, origin);
      }
      if (!payload.name) {
        return jsonResponse({ error: 'Nome é obrigatório.' }, 400, origin);
      }
      if (!password) {
        return jsonResponse({ error: 'Senha é obrigatória.' }, 400, origin);
      }
      if (payload.role === 'partner' && (!payload.clientId || payload.client_ids.length === 0)) {
        return jsonResponse({ error: 'Empresa parceira vinculada e obrigatoria.' }, 400, origin);
      }

      const { data: existingProfile } = await adminClient
        .from('crm_mkt_users')
        .select('id')
        .eq('username', username)
        .maybeSingle();

      if (existingProfile) {
        return jsonResponse({ error: 'Este usuário já existe.' }, 409, origin);
      }

      const { data: authData, error: authError } = await adminClient.auth.admin.createUser({
        email: getInternalAuthEmail(username),
        password,
        email_confirm: true,
        user_metadata: {
          username,
          name: payload.name,
          role: payload.role,
        },
      });

      if (authError || !authData.user) {
        return jsonResponse({ error: authError?.message || 'Não foi possível criar o login.' }, 400, origin);
      }

      const { data: profile, error: profileError } = await adminClient
        .from('crm_mkt_users')
        .insert([{ ...payload, username, auth_user_id: authData.user.id }])
        .select(PROFILE_COLUMNS)
        .single();

      if (profileError) {
        await adminClient.auth.admin.deleteUser(authData.user.id);
        return jsonResponse({ error: profileError.message }, 400, origin);
      }

      return jsonResponse({ user: profile }, 200, origin);
    }

    if (action === 'update') {
      const userId = String(body.userId || '');
      const userInput = body.user || {};
      const payload = cleanProfilePayload(userInput);
      const password = String(userInput.password || '').trim();
      delete payload.clientName;

      if (!userId) {
        return jsonResponse({ error: 'Usuário não informado.' }, 400, origin);
      }
      if (!payload.name) {
        return jsonResponse({ error: 'Nome é obrigatório.' }, 400, origin);
      }
      if (payload.role === 'partner' && (!payload.clientId || payload.client_ids.length === 0)) {
        return jsonResponse({ error: 'Empresa parceira vinculada e obrigatoria.' }, 400, origin);
      }

      const { data: profile, error: profileError } = await adminClient
        .from('crm_mkt_users')
        .update(payload)
        .eq('id', userId)
        .select(PROFILE_COLUMNS)
        .single();

      if (profileError) {
        return jsonResponse({ error: profileError.message }, 400, origin);
      }

      if (profile.auth_user_id) {
        const { error: authError } = await adminClient.auth.admin.updateUserById(profile.auth_user_id, {
          ...(password ? { password } : {}),
          user_metadata: {
            username: profile.username,
            name: profile.name,
            role: profile.role,
          },
        });

        if (authError) {
          return jsonResponse({ error: authError.message }, 400, origin);
        }
      }

      return jsonResponse({ user: profile }, 200, origin);
    }

    if (action === 'reset-password') {
      const userId = String(body.userId || '');
      const password = String(body.password || '');

      if (!userId || !password) {
        return jsonResponse({ error: 'Informe uma nova senha.' }, 400, origin);
      }

      const { data: profile, error: profileError } = await adminClient
        .from('crm_mkt_users')
        .select('id, auth_user_id')
        .eq('id', userId)
        .single();

      if (profileError || !profile?.auth_user_id) {
        return jsonResponse({ error: 'Usuário não encontrado no Auth.' }, 404, origin);
      }

      const { error: authError } = await adminClient.auth.admin.updateUserById(profile.auth_user_id, {
        password,
      });

      if (authError) {
        return jsonResponse({ error: authError.message }, 400, origin);
      }

      return jsonResponse({ ok: true }, 200, origin);
    }

    return jsonResponse({ error: 'Ação inválida.' }, 400, origin);
  } catch (error) {
    console.error('admin-users error:', error);
    return jsonResponse({ error: `Nao foi possivel concluir a operacao: ${getErrorMessage(error)}` }, 500, origin);
  }
});
