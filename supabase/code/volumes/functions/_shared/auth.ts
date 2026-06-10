import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.103.0';

export const CRM_AUTH_DOMAIN = 'crm.local';

export function normalizeUsername(username: string) {
  return username
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
}

export function getInternalAuthEmail(username: string) {
  return `${normalizeUsername(username)}@${CRM_AUTH_DOMAIN}`;
}

export function getSupabaseClients() {
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

export async function requireAdmin(adminClient: ReturnType<typeof createClient>, authHeader: string | null) {
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
