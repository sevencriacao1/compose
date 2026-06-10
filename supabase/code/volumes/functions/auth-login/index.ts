import { getCorsHeaders, jsonResponse } from '../_shared/cors.ts';
import { getInternalAuthEmail, getSupabaseClients, normalizeUsername } from '../_shared/auth.ts';

const RETENTION_DAYS = 60;

function getClientIp(req: Request) {
  const forwardedFor = req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim();
  return req.headers.get('CF-Connecting-IP') || forwardedFor || req.headers.get('X-Real-IP') || null;
}

async function closeOpenSessions(
  adminClient: ReturnType<typeof getSupabaseClients>['adminClient'],
  userId: string,
  now: Date,
  expiresAt: string,
) {
  const { data: openSessions, error } = await adminClient
    .from('crm_mkt_user_sessions')
    .select('id, started_at')
    .eq('user_id', userId)
    .is('ended_at', null);

  if (error || !openSessions?.length) return;

  await Promise.all(openSessions.map(async (openSession) => {
    const durationSeconds = Math.max(
      0,
      Math.round((now.getTime() - new Date(openSession.started_at).getTime()) / 1000),
    );

    await adminClient
      .from('crm_mkt_user_sessions')
      .update({
        ended_at: now.toISOString(),
        last_seen_at: now.toISOString(),
        end_reason: 'timeout',
        duration_seconds: durationSeconds,
      })
      .eq('id', openSession.id);

    await adminClient.from('crm_mkt_user_activity_events').insert({
      session_id: openSession.id,
      user_id: userId,
      event_type: 'logout',
      action_name: 'auto_end_previous_session',
      duration_seconds: durationSeconds,
      metadata: { reason: 'timeout' },
      created_at: now.toISOString(),
      expires_at: expiresAt,
    });
  }));
}

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin');

  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: getCorsHeaders(origin) });
  }

  try {
    const { adminClient, authClient } = getSupabaseClients();

    if (req.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405, origin);
    }

    const { username, password } = await req.json();

    if (!username || !password) {
      return jsonResponse({ error: 'Usuario ou senha incorretos.' }, 400, origin);
    }

    const normalizedUsername = normalizeUsername(String(username));

    const { data: user, error: userError } = await adminClient
      .from('crm_mkt_users')
      .select('*')
      .eq('username', normalizedUsername)
      .eq('active', true)
      .maybeSingle();

    if (userError || !user || !user.auth_user_id) {
      return jsonResponse({ error: 'Usuario ou senha incorretos.' }, 401, origin);
    }

    const authEmail = getInternalAuthEmail(normalizedUsername);

    const { data: signInData, error: signInError } = await authClient.auth.signInWithPassword({
      email: authEmail,
      password,
    });

    if (signInError || !signInData.session) {
      return jsonResponse({ error: 'Usuario ou senha incorretos.' }, 401, origin);
    }

    let activitySessionId: string | null = null;
    try {
      const now = new Date();
      const expiresAt = new Date(now.getTime() + RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
      await closeOpenSessions(adminClient, user.id, now, expiresAt);

      const { data: activitySession, error: activitySessionError } = await adminClient
        .from('crm_mkt_user_sessions')
        .insert({
          user_id: user.id,
          auth_user_id: user.auth_user_id,
          role: user.role,
          started_at: now.toISOString(),
          last_seen_at: now.toISOString(),
          ip: getClientIp(req),
          user_agent: req.headers.get('User-Agent'),
          metadata: { source: 'auth-login' },
          expires_at: expiresAt,
        })
        .select('id')
        .single();

      if (!activitySessionError && activitySession?.id) {
        activitySessionId = activitySession.id;
        await adminClient.from('crm_mkt_user_activity_events').insert({
          session_id: activitySession.id,
          user_id: user.id,
          event_type: 'login',
          action_name: 'login',
          metadata: { source: 'auth-login' },
          created_at: now.toISOString(),
          expires_at: expiresAt,
        });
      }
    } catch (auditError) {
      console.warn('Auth login audit skipped:', auditError);
    }

    const clientIds = Array.isArray(user.client_ids)
      ? user.client_ids.filter(Boolean)
      : (user.clientId ? [user.clientId] : []);
    const primaryClientId = user.clientId ?? user.client_id ?? clientIds[0] ?? null;
    const clientName = user.clientName ?? user.client_name ?? null;
    const photoUrl = user.photoUrl ?? user.photo_url ?? null;

    return jsonResponse({
      session: signInData.session,
      user: {
        id: user.id,
        auth_user_id: user.auth_user_id,
        username: user.username,
        name: user.name,
        email: user.email,
        role: user.role,
        clientId: primaryClientId,
        client_id: primaryClientId,
        clientIds,
        client_ids: clientIds,
        clientName,
        client_name: clientName,
        active: user.active,
        photoUrl,
        photo_url: photoUrl,
        phone: user.phone,
        bio: user.bio,
      },
      activitySessionId,
    }, 200, origin);
  } catch (error) {
    console.error('Auth login error:', error);
    return jsonResponse({ error: 'Nao foi possivel realizar o login agora.' }, 500, origin);
  }
});
