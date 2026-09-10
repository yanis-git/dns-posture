// Anti-spoofing hardening policy for dormant domains.
// Goal: the domain can no longer send mail, and nothing is left lying around.

// OVH types that carry text (OVH has dedicated fieldTypes on top of TXT).
export const TEXTUAL_TYPES = ['TXT', 'SPF', 'DKIM', 'DMARC'];

export const DEFAULT_CNAMES_TO_DROP = ['ftp'];

export function buildPolicy({ rua = null, nullMx = false, ttl = 3600 } = {}) {
  const dmarc = ['v=DMARC1', 'p=reject', 'sp=reject', 'adkim=s', 'aspf=s'];
  if (rua) dmarc.push(`rua=${rua}`);

  const records = [
    { subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all', ttl, why: 'SPF: no authorised sender' },
    { subDomain: '_dmarc', fieldType: 'TXT', target: dmarc.join('; '), ttl, why: 'DMARC: strict reject, subdomains included' },
    { subDomain: '*._domainkey', fieldType: 'TXT', target: 'v=DKIM1; p=', ttl, why: 'DKIM: every key revoked' },
  ];
  if (nullMx) {
    records.push({ subDomain: '', fieldType: 'MX', target: '0 .', ttl, why: 'Null MX (RFC 7505): the domain receives no mail' });
  }
  return records;
}

/**
 * Display form of a record. OVH returns TXT targets already wrapped in quotes,
 * so quoting the raw value would print ""v=spf1 -all"".
 */
export function recordLabel({ subDomain, fieldType, target }) {
  const value = String(target ?? '').replace(/^"([\s\S]*)"$/, '$1');
  return `${subDomain || '@'} ${fieldType} "${value}"`;
}

function sameRecord(existing, wanted) {
  // OVH has dedicated SPF/DKIM/DMARC fieldTypes, but they come out as TXT in
  // the zone: a record already at the right value is compliant whatever its type.
  const sameType = existing.fieldType === wanted.fieldType
    || (wanted.fieldType === 'TXT' && TEXTUAL_TYPES.includes(existing.fieldType));
  return sameType
    && (existing.subDomain || '') === wanted.subDomain
    && normalize(existing.target) === normalize(wanted.target);
}

function normalize(target) {
  return String(target ?? '').trim().replace(/^"|"$/g, '').replace(/"\s+"/g, '').replace(/\s+/g, ' ');
}

/**
 * Fetch every relevant record of a zone.
 */
export async function fetchRecords(ovh, zone) {
  const types = [...TEXTUAL_TYPES, 'MX', 'CNAME'];
  const records = [];
  for (const fieldType of types) {
    let ids;
    try {
      ids = await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record?fieldType=${fieldType}`);
    } catch (err) {
      if (err.status === 404) continue;
      throw err;
    }
    for (const id of ids) {
      records.push(await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record/${id}`));
    }
  }
  return records;
}

/**
 * Build the plan: what we delete, what we create, what we leave alone.
 */
export function planZone(records, { policy, keepPatterns = [], cnamesToDrop = DEFAULT_CNAMES_TO_DROP, dropRedirect = false }) {
  const del = [];
  const keep = [];

  for (const rec of records) {
    const sub = rec.subDomain || '@';
    const label = recordLabel(rec);

    if (keepPatterns.some((re) => re.test(rec.target) || re.test(sub))) {
      keep.push({ ...rec, reason: 'protected by --keep' });
      continue;
    }

    if (rec.fieldType === 'MX') {
      del.push({ ...rec, label, reason: 'MX on a dormant domain' });
      continue;
    }
    if (TEXTUAL_TYPES.includes(rec.fieldType)) {
      // "1|www.example.com": plumbing of the OVH web redirection service, with
      // nothing to do with mail. Deleting it breaks the redirect: explicit opt-in.
      if (/^"?\d+\|/.test(String(rec.target))) {
        if (!dropRedirect) {
          keep.push({ ...rec, reason: 'OVH redirection marker' });
          continue;
        }
        del.push({ ...rec, label, reason: 'OVH redirection marker (--drop-redirect: the web redirect will break)' });
        continue;
      }
      del.push({ ...rec, label, reason: 'superfluous TXT/SPF/DKIM/DMARC (replaced by the policy)' });
      continue;
    }
    if (rec.fieldType === 'CNAME' && cnamesToDrop.includes((rec.subDomain || '').toLowerCase())) {
      del.push({ ...rec, label, reason: `useless ${rec.subDomain} CNAME` });
      continue;
    }
    keep.push({ ...rec, reason: 'out of scope' });
  }

  // A record already compliant is neither deleted nor recreated.
  const create = [];
  for (const wanted of policy) {
    const already = del.find((r) => sameRecord(r, wanted));
    if (already) {
      already.skip = true;
      keep.push({ ...already, reason: 'already compliant' });
      continue;
    }
    create.push(wanted);
  }

  return { delete: del.filter((r) => !r.skip), create, keep };
}

/**
 * Apply the plan. Individual failures are collected, not fatal.
 */
export async function applyPlan(ovh, zone, plan) {
  const z = encodeURIComponent(zone);
  const done = { deleted: [], created: [], errors: [] };

  for (const rec of plan.delete) {
    try {
      await ovh.delete(`/domain/zone/${z}/record/${rec.id}`);
      done.deleted.push(rec.label);
    } catch (err) {
      done.errors.push(`DELETE ${rec.label}: ${err.message}`);
    }
  }

  for (const rec of plan.create) {
    try {
      const created = await ovh.post(`/domain/zone/${z}/record`, {
        subDomain: rec.subDomain,
        fieldType: rec.fieldType,
        target: rec.target,
        ttl: rec.ttl,
      });
      done.created.push(recordLabel({ ...rec, target: created.target }));
    } catch (err) {
      done.errors.push(`CREATE ${recordLabel(rec)}: ${err.message}`);
    }
  }

  try {
    await ovh.post(`/domain/zone/${z}/refresh`);
  } catch (err) {
    done.errors.push(`REFRESH: ${err.message}`);
  }

  return done;
}
