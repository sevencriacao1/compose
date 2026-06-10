import { getCorsHeaders, jsonResponse } from '../_shared/cors.ts';
import { getSupabaseClients } from '../_shared/auth.ts';

const ALLOWED_UPDATE_FIELDS = new Set([
  'title',
  'publishDate',
  'deadline',
  'copy',
  'caption',
  'notes',
  'editReason',
]);

function cleanText(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
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
    const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
    if (!token) {
      return jsonResponse({ error: 'Unauthorized' }, 401, origin);
    }

    const { authClient, adminClient } = getSupabaseClients();
    const { data: authData, error: authError } = await authClient.auth.getUser(token);
    const authUserId = authData?.user?.id;

    if (authError || !authUserId) {
      return jsonResponse({ error: 'Invalid token' }, 401, origin);
    }

    const { data: profile, error: profileError } = await adminClient
      .from('crm_mkt_users')
      .select('id, name, role, active')
      .eq('auth_user_id', authUserId)
      .maybeSingle();

    if (profileError || !profile || profile.role !== 'creator' || profile.active === false) {
      return jsonResponse({ error: 'Forbidden' }, 403, origin);
    }

    const body = await req.json();
    const action = String(body.action || '');

    if (action !== 'update' && action !== 'archive') {
      return jsonResponse({ error: 'Acao invalida.' }, 400, origin);
    }

    const demandId = String(body.demandId || '');
    if (!demandId) {
      return jsonResponse({ error: 'Demanda nao informada.' }, 400, origin);
    }

    const { data: demand, error: demandError } = await adminClient
      .from('crm_mkt_demands')
      .select('*')
      .eq('id', demandId)
      .maybeSingle();

    if (demandError || !demand) {
      return jsonResponse({ error: 'Demanda nao encontrada.' }, 404, origin);
    }

    if (action === 'archive') {
      if (demand.status !== 'Aprovada') {
        return jsonResponse({ error: 'Somente demandas aprovadas podem ser arquivadas.' }, 403, origin);
      }

      const previousHistory = Array.isArray(demand.history) ? demand.history : [];
      const archivePayload = {
        status: 'Arquivado',
        creatorArchived: true,
        creatorArchivedAt: new Date().toISOString(),
        creatorArchivedBy: profile.id,
        history: [
          ...previousHistory,
          {
            id: `hist-${Date.now()}-${crypto.randomUUID()}`,
            description: 'CREATOR ARQUIVOU A DEMANDA COMO POSTADA',
            author: profile.name || 'Creator',
            authorRole: 'creator',
            icon: 'Archive',
            color: 'text-primary',
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const { data: archivedDemand, error: archiveError } = await adminClient
        .from('crm_mkt_demands')
        .update(archivePayload)
        .eq('id', demandId)
        .eq('status', 'Aprovada')
        .select()
        .single();

      if (archiveError || !archivedDemand) {
        return jsonResponse({ error: archiveError?.message || 'Nao foi possivel arquivar a demanda.' }, 400, origin);
      }

      return jsonResponse({ demand: archivedDemand }, 200, origin);
    }

    const editReason = cleanText(body.editReason);
    if (!editReason) {
      return jsonResponse({ error: 'Motivo da alteracao e obrigatorio.' }, 400, origin);
    }

    if (demand.status !== 'Pendente') {
      return jsonResponse({ error: 'Creators so podem editar demandas pendentes.' }, 403, origin);
    }

    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(body)) {
      if (!ALLOWED_UPDATE_FIELDS.has(key) || key === 'editReason') continue;
      payload[key] = value;
    }

    const previousHistory = Array.isArray(demand.history) ? demand.history : [];
    payload.creator_edit_reason = editReason;
    payload.creator_edited_at = new Date().toISOString();
    payload.creator_edited_by = profile.id;
    payload.history = [
      ...previousHistory,
      {
        id: `hist-${Date.now()}-${crypto.randomUUID()}`,
        description: `CREATOR ALTEROU A DEMANDA: ${editReason}`,
        author: profile.name || 'Creator',
        authorRole: 'creator',
        icon: 'Edit',
        color: 'text-blue-accent',
        timestamp: new Date().toISOString(),
        editReason,
      },
    ];
    payload.updatedAt = new Date().toISOString();

    const { data: updatedDemand, error: updateError } = await adminClient
      .from('crm_mkt_demands')
      .update(payload)
      .eq('id', demandId)
      .eq('status', 'Pendente')
      .select()
      .single();

    if (updateError || !updatedDemand) {
      return jsonResponse({ error: updateError?.message || 'Nao foi possivel atualizar a demanda.' }, 400, origin);
    }

    return jsonResponse({ demand: updatedDemand }, 200, origin);
  } catch (error) {
    console.error('creator-demand error:', error);
    return jsonResponse({ error: 'Erro interno.' }, 500, origin);
  }
});
