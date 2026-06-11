import { getCorsHeaders, jsonResponse } from '../_shared/cors.ts';
import { getSupabaseClients } from '../_shared/auth.ts';

const RETENTION_DAYS = 60;
const ALLOWED_ACTIONS = new Set(['start_session', 'track_route', 'track_action', 'heartbeat', 'end_session']);

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error || 'Erro desconhecido');
}

function toIsoDate(value: unknown, fallback = new Date()) {
  if (typeof value !== 'string') return fallback.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? fallback.toISOString() : parsed.toISOString();
}

function toPositiveInteger(value: unknown) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.round(numeric) : null;
}

function sanitizeText(value: unknown, maxLength = 500) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

function sanitizeMetadata(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};

  const safe: Record<string, unknown> = {};
  for (const [key, rawValue] of Object.entries(value as Record<string, unknown>)) {
    if (/password|token|secret|credential|authorization|file|content|payload/i.test(key)) continue;
    if (rawValue === null || ['string', 'number', 'boolean'].includes(typeof rawValue)) {
      safe[key] = typeof rawValue === 'string' ? rawValue.slice(0, 500) : rawValue;
    }
  }
  return safe;
}

function getClientIp(req: Request) {
  const forwardedFor = req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim();
  return req.headers.get('CF-Connecting-IP') || forwardedFor || req.headers.get('X-Real-IP') || null;
}

async function closeOpenSessions(
  adminClient: ReturnType<typeof getSupabaseClients>['adminClient'],
  userId: string,
  now: Date,
  expiresAt: string,
  endReason = 'timeout',
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
        end_reason: endReason,
        duration_seconds: durationSeconds,
      })
      .eq('id', openSession.id);

    await adminClient.from('crm_mkt_user_activity_events').insert({
      session_id: openSession.id,
      user_id: userId,
      event_type: 'logout',
      action_name: 'auto_end_previous_session',
      duration_seconds: durationSeconds,
      metadata: { reason: endReason },
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

  if (req.method === 'GET') {
    return jsonResponse({
      ok: true,
      service: 'user-activity',
      methods: ['GET', 'POST', 'OPTIONS'],
    }, 200, origin);
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405, origin);
  }

  try {
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || '');

    if (!ALLOWED_ACTIONS.has(action)) {
      return jsonResponse({ error: 'Acao invalida.' }, 400, origin);
    }

    const { adminClient, authClient } = getSupabaseClients();
    const requestUrl = new URL(req.url);
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '')
      || requestUrl.searchParams.get('authorization');

    if (!token) {
      return jsonResponse({ error: 'Unauthorized' }, 401, origin);
    }

    const { data: authData, error: authError } = await authClient.auth.getUser(token);
    const authUserId = authData?.user?.id;

    if (authError || !authUserId) {
      return jsonResponse({ error: 'Invalid token' }, 401, origin);
    }

    const { data: profile, error: profileError } = await adminClient
      .from('crm_mkt_users')
      .select('id, auth_user_id, username, name, email, role, active')
      .eq('auth_user_id', authUserId)
      .maybeSingle();

    if (profileError || !profile || profile.active === false) {
      return jsonResponse({ error: 'Perfil nao encontrado.' }, 403, origin);
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const sessionId = sanitizeText(body.sessionId, 80);
    const metadata = sanitizeMetadata(body.metadata);

    if (action === 'start_session') {
      await closeOpenSessions(adminClient, profile.id, now, expiresAt);

      const { data: session, error: sessionError } = await adminClient
        .from('crm_mkt_user_sessions')
        .insert({
          user_id: profile.id,
          auth_user_id: authUserId,
          role: profile.role,
          started_at: now.toISOString(),
          last_seen_at: now.toISOString(),
          ip: getClientIp(req),
          user_agent: req.headers.get('User-Agent'),
          metadata,
          expires_at: expiresAt,
        })
        .select('id')
        .single();

      if (sessionError || !session) throw sessionError || new Error('Sessao nao criada.');

      await adminClient.from('crm_mkt_user_activity_events').insert({
        session_id: session.id,
        user_id: profile.id,
        event_type: 'login',
        action_name: 'login',
        metadata,
        created_at: now.toISOString(),
        expires_at: expiresAt,
      });

      return jsonResponse({ sessionId: session.id }, 200, origin);
    }

    if (!sessionId) {
      return jsonResponse({ error: 'Sessao nao informada.' }, 400, origin);
    }

    const { data: session, error: sessionError } = await adminClient
      .from('crm_mkt_user_sessions')
      .select('id, user_id, started_at, ended_at')
      .eq('id', sessionId)
      .eq('user_id', profile.id)
      .maybeSingle();

    if (sessionError || !session) {
      return jsonResponse({ error: 'Sessao invalida.' }, 403, origin);
    }

    if (session.ended_at) {
      if (action === 'end_session') {
        return jsonResponse({ ok: true }, 200, origin);
      }
      if (action === 'heartbeat') {
        return jsonResponse({ ok: false, code: 'session_ended' }, 200, origin);
      }
      return jsonResponse({ error: 'Sessao encerrada.', code: 'session_ended' }, 409, origin);
    }

    await adminClient
      .from('crm_mkt_user_sessions')
      .update({ last_seen_at: now.toISOString() })
      .eq('id', sessionId);

    if (action === 'heartbeat') {
      return jsonResponse({ ok: true }, 200, origin);
    }

    if (action === 'track_route') {
      const startedAt = toIsoDate(body.startedAt, now);
      const endedAt = body.endedAt ? toIsoDate(body.endedAt, now) : null;
      const durationSeconds = toPositiveInteger(body.durationSeconds);

      await adminClient.from('crm_mkt_user_activity_events').insert({
        session_id: sessionId,
        user_id: profile.id,
        event_type: 'route',
        route_path: sanitizeText(body.routePath, 1000),
        route_title: sanitizeText(body.routeTitle, 500),
        started_at: startedAt,
        ended_at: endedAt,
        duration_seconds: durationSeconds,
        metadata,
        created_at: now.toISOString(),
        expires_at: expiresAt,
      });

      return jsonResponse({ ok: true }, 200, origin);
    }

    if (action === 'track_action') {
      await adminClient.from('crm_mkt_user_activity_events').insert({
        session_id: sessionId,
        user_id: profile.id,
        event_type: 'action',
        action_name: sanitizeText(body.actionName, 200),
        route_path: sanitizeText(body.routePath, 1000),
        route_title: sanitizeText(body.routeTitle, 500),
        metadata,
        created_at: now.toISOString(),
        expires_at: expiresAt,
      });

      return jsonResponse({ ok: true }, 200, origin);
    }

    if (action === 'end_session') {
      const endReason = sanitizeText(body.endReason, 40) || 'unknown';
      const durationSeconds = toPositiveInteger(body.durationSeconds)
        ?? Math.max(0, Math.round((now.getTime() - new Date(session.started_at).getTime()) / 1000));

      await adminClient
        .from('crm_mkt_user_sessions')
        .update({
          ended_at: now.toISOString(),
          last_seen_at: now.toISOString(),
          end_reason: ['logout', 'pagehide', 'timeout', 'invalid_session', 'unknown'].includes(endReason) ? endReason : 'unknown',
          duration_seconds: durationSeconds,
        })
        .eq('id', sessionId)
        .eq('user_id', profile.id);

      await adminClient.from('crm_mkt_user_activity_events').insert({
        session_id: sessionId,
        user_id: profile.id,
        event_type: 'logout',
        action_name: 'logout',
        duration_seconds: durationSeconds,
        metadata,
        created_at: now.toISOString(),
        expires_at: expiresAt,
      });

      return jsonResponse({ ok: true }, 200, origin);
    }

    return jsonResponse({ error: 'Acao invalida.' }, 400, origin);
  } catch (error) {
    console.error('user-activity error:', error);
    return jsonResponse({ error: `Nao foi possivel registrar auditoria: ${getErrorMessage(error)}` }, 500, origin);
  }
});
