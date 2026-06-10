import { getCorsHeaders, jsonResponse } from '../_shared/cors.ts';
import { getSupabaseClients, requireAdmin } from '../_shared/auth.ts';

const PROFILE_COLUMNS = 'id, auth_user_id, username, name, email, role, clientId, clientName, client_ids, active, photoUrl, phone, bio';
const PARTNER_ROLES = ['partner', 'client'];

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error || 'Erro desconhecido');
}

async function getLinkedPartners(adminClient: ReturnType<typeof getSupabaseClients>['adminClient'], adminUserId: string) {
  const { data, error } = await adminClient
    .from('crm_mkt_admin_partner_links')
    .select('id, partner_user_id, is_active')
    .eq('admin_user_id', adminUserId)
    .eq('is_active', true)
    .order('created_at', { ascending: true });

  if (error) throw error;

  const partnerIds = (data || []).map((link) => link.partner_user_id).filter(Boolean);
  if (partnerIds.length === 0) return [];

  const { data: partners, error: partnersError } = await adminClient
    .from('crm_mkt_users')
    .select(PROFILE_COLUMNS)
    .in('id', partnerIds);

  if (partnersError) throw partnersError;

  const linkByPartnerId = new Map((data || []).map((link) => [link.partner_user_id, link.id]));

  return (partners || [])
    .filter((partner) => partner?.id && partner.active !== false && PARTNER_ROLES.includes(partner.role))
    .map((partner) => ({ linkId: linkByPartnerId.get(partner.id), ...partner }));
}

async function replaceAdminPartnerLinks(
  adminClient: ReturnType<typeof getSupabaseClients>['adminClient'],
  adminUserId: string,
  partnerUserIds: string[],
  createdBy: string,
) {
  const uniquePartnerIds = Array.from(new Set(partnerUserIds.filter(Boolean)));

  if (uniquePartnerIds.length > 0) {
    const { data: partners, error: partnerError } = await adminClient
      .from('crm_mkt_users')
      .select('id, role, active')
      .in('id', uniquePartnerIds);

    if (partnerError) throw partnerError;

    const validPartnerIds = new Set(
      (partners || [])
        .filter((partner) => partner.active !== false && PARTNER_ROLES.includes(partner.role))
        .map((partner) => partner.id),
    );

    if (validPartnerIds.size !== uniquePartnerIds.length) {
      throw new Error('Um ou mais partners vinculados sao invalidos.');
    }
  }

  const { error: deactivateError } = await adminClient
    .from('crm_mkt_admin_partner_links')
    .update({ is_active: false })
    .eq('admin_user_id', adminUserId)
    .eq('is_active', true);

  if (deactivateError) throw deactivateError;

  if (uniquePartnerIds.length === 0) return;

  const rows = uniquePartnerIds.map((partnerUserId) => ({
    admin_user_id: adminUserId,
    partner_user_id: partnerUserId,
    created_by: createdBy,
    is_active: true,
  }));

  const { error: insertError } = await adminClient
    .from('crm_mkt_admin_partner_links')
    .insert(rows);

  if (insertError) throw insertError;
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
    const action = String(body.action || '');
    const adminUserId = adminCheck.profile.id;

    if (action === 'list-linked-partners') {
      const partners = await getLinkedPartners(adminClient, adminUserId);
      return jsonResponse({ partners }, 200, origin);
    }

    if (action === 'replace-links') {
      const targetAdminUserId = String(body.adminUserId || '');
      const partnerUserIds = Array.isArray(body.partnerUserIds) ? body.partnerUserIds.map(String) : [];

      if (!targetAdminUserId) {
        return jsonResponse({ error: 'Admin nao informado.' }, 400, origin);
      }

      const { data: targetAdmin, error: targetError } = await adminClient
        .from('crm_mkt_users')
        .select('id, role, active')
        .eq('id', targetAdminUserId)
        .maybeSingle();

      if (targetError || !targetAdmin || targetAdmin.role !== 'admin' || targetAdmin.active === false) {
        return jsonResponse({ error: 'Admin invalido para vinculos.' }, 400, origin);
      }

      await replaceAdminPartnerLinks(adminClient, targetAdminUserId, partnerUserIds, adminUserId);
      const partners = await getLinkedPartners(adminClient, targetAdminUserId);
      return jsonResponse({ partners }, 200, origin);
    }

    if (action === 'start' || action === 'validate') {
      const partnerUserId = String(body.partnerUserId || '');
      if (!partnerUserId) {
        return jsonResponse({ error: 'Partner nao informado.' }, 400, origin);
      }

      const { data: link, error: linkError } = await adminClient
        .from('crm_mkt_admin_partner_links')
        .select('id, partner_user_id')
        .eq('admin_user_id', adminUserId)
        .eq('partner_user_id', partnerUserId)
        .eq('is_active', true)
        .maybeSingle();

      const { data: partner, error: partnerError } = link
        ? await adminClient
          .from('crm_mkt_users')
          .select(PROFILE_COLUMNS)
          .eq('id', partnerUserId)
          .maybeSingle()
        : { data: null, error: null };

      if (linkError || partnerError || !link || !partner || partner.active === false || !PARTNER_ROLES.includes(partner.role)) {
        return jsonResponse({ error: 'Vinculo ativo nao encontrado para este partner.' }, 403, origin);
      }

      if (action === 'start') {
        await adminClient.from('crm_mkt_impersonation_logs').insert({
          admin_user_id: adminUserId,
          partner_user_id: partnerUserId,
          action: 'start',
          metadata: {
            linkId: link.id,
            userAgent: req.headers.get('User-Agent'),
          },
        });
      }

      return jsonResponse({ partner, originalAdminId: adminUserId, actingAsPartnerId: partnerUserId }, 200, origin);
    }

    if (action === 'stop') {
      const partnerUserId = String(body.partnerUserId || '');

      await adminClient.from('crm_mkt_impersonation_logs').insert({
        admin_user_id: adminUserId,
        partner_user_id: partnerUserId || null,
        action: 'stop',
        metadata: {
          userAgent: req.headers.get('User-Agent'),
        },
      });

      return jsonResponse({ ok: true }, 200, origin);
    }

    return jsonResponse({ error: 'Acao invalida.' }, 400, origin);
  } catch (error) {
    console.error('admin-impersonation error:', error);
    return jsonResponse({ error: `Nao foi possivel concluir a operacao: ${getErrorMessage(error)}` }, 500, origin);
  }
});
