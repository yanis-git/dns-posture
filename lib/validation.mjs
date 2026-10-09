import { domainToASCII } from 'node:url';

export function domainName(value) {
  const raw = String(value ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (/[\\/\s:]/.test(raw) || [...raw].some((c) => c.charCodeAt(0) < 32)) throw new Error(`Invalid domain: ${value}`);
  const domain = domainToASCII(raw);
  if (!domain || domain.length > 253 || !domain.includes('.')
    || domain.split('.').some((s) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))) {
    throw new Error(`Invalid domain: ${value}`);
  }
  return domain;
}

export function validTtl(value) {
  if (!Number.isInteger(value) || value < 1 || value > 2147483647) {
    throw new Error('TTL must be an integer between 1 and 2147483647');
  }
  return value;
}

export function validateRecords(records) {
  for (const r of records) {
    if (typeof r.subDomain !== 'string' || /[\s/\\]/.test(r.subDomain)
      || typeof r.target !== 'string' || !Number.isInteger(r.ttl) || r.ttl < 0
      || typeof r.fieldType !== 'string') throw new Error('Incomplete or ambiguous DNS record');
    if (r.fieldType === 'MX' && !/^\d+\s+\S+$/.test(r.target)) throw new Error('Ambiguous MX record; refusing classification');
  }
  return records;
}
