import { request } from '../http.mjs';
import { domainName, validateRecords } from '../validation.mjs';
import { parseCaa, txtValue } from '../zone.mjs';

const WRITABLE = ['type', 'name', 'content', 'ttl', 'priority', 'data', 'proxied', 'comment', 'tags', 'settings'];
export class CloudflareProvider {
  constructor({ token = process.env.CLOUDFLARE_API_TOKEN, account = null } = {}) {
    if (!token) throw new Error('Missing Cloudflare credentials: CLOUDFLARE_API_TOKEN');
    this.name = 'cloudflare';
    this.token = token;
    this.account = account;
  }
  async init() {} // Account identity comes from the exact zone, not from a token fingerprint.
  async call(method, path, body) {
    const { response, body: text } = await request(`https://api.cloudflare.com/client/v4${path}`, {
      method, headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data;
    try { data = JSON.parse(text); } catch { throw new Error(`Cloudflare ${response.status}: invalid JSON`); }
    if (!response.ok || data.success !== true) throw new Error(`Cloudflare ${response.status}: ${data.errors?.map((e) => e.message).join('; ') || 'unsuccessful response'}`);
    return data;
  }
  async pages(path) {
    const all = [];
    let expected;
    for (let page = 1; page <= 100000; page++) {
      const data = await this.call('GET', `${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      const info = data.result_info;
      if (!Array.isArray(data.result) || !info || info.page !== page || !Number.isInteger(info.total_count)
        || !Number.isInteger(info.total_pages) || info.total_pages < 0 || info.count !== data.result.length
        || (expected !== undefined && expected !== info.total_count)) throw new Error('Incomplete or changing Cloudflare pagination');
      expected = info.total_count;
      all.push(...data.result);
      if (page >= info.total_pages) {
        if (all.length !== expected || new Set(all.map((r) => r.id)).size !== all.length) throw new Error('Incomplete or duplicate Cloudflare results');
        return all;
      }
    }
    throw new Error('Cloudflare pagination limit exceeded');
  }
  async zones() {
    return (await this.pages(`/zones${this.account ? `?account.id=${encodeURIComponent(this.account)}` : ''}`))
      .map((z) => this.zoneInfo(z));
  }
  zoneInfo(z) {
    if (!z?.id || !z.account?.id) throw new Error('Cloudflare zone identity missing');
    return { name: domainName(z.name), id: z.id, account: z.account.id, provider: this.name };
  }
  async zone(name) {
    name = domainName(name);
    const matches = (await this.pages(`/zones?name=${encodeURIComponent(name)}${this.account ? `&account.id=${encodeURIComponent(this.account)}` : ''}`))
      .filter((z) => z.name.toLowerCase() === name);
    if (matches.length !== 1) throw new Error('Cloudflare zone must resolve to exactly one accessible zone');
    return this.zoneInfo(matches[0]);
  }
  path(zone) { return `/zones/${encodeURIComponent(zone.id)}/dns_records`; }
  normalize(r, zone) {
    const name = String(r.name).toLowerCase().replace(/\.$/, '');
    if (name !== zone.name && !name.endsWith(`.${zone.name}`)) throw new Error('Record outside Cloudflare zone');
    if (!r.id || typeof r.type !== 'string' || typeof r.content !== 'string' || !Number.isInteger(r.ttl)) throw new Error('Incomplete Cloudflare record');
    let target = r.content;
    if (r.type === 'MX') {
      if (!Number.isInteger(r.priority)) throw new Error('Cloudflare MX priority missing');
      target = `${r.priority} ${r.content}`;
    }
    if (r.type === 'CAA') {
      if (!r.data || !Number.isInteger(r.data.flags) || !r.data.tag || typeof r.data.value !== 'string') throw new Error('Cloudflare CAA data missing');
      target = `${r.data.flags} ${r.data.tag} ${JSON.stringify(r.data.value)}`;
    }
    return { id: r.id, subDomain: name === zone.name ? '' : name.slice(0, -zone.name.length - 1), fieldType: r.type, target, ttl: r.ttl, native: r };
  }
  async read(zone) { return validateRecords((await this.pages(this.path(zone))).map((r) => this.normalize(r, zone))); }
  async export(zone, records) {
    return `$ORIGIN ${zone.name}.\n` + records.map((r) => `${r.subDomain || '@'} ${r.ttl} IN ${r.fieldType} ${r.fieldType === 'TXT' ? JSON.stringify(txtValue(r.target)) : r.target}`).join('\n') + '\n';
  }
  payload(r, zone) {
    const body = Object.fromEntries(WRITABLE.filter((k) => r.native?.[k] !== undefined).map((k) => [k, r.native[k]]));
    Object.assign(body, { type: r.fieldType, name: r.subDomain ? `${r.subDomain}.${zone.name}` : zone.name, ttl: r.ttl, content: r.target });
    if (r.fieldType === 'TXT') body.content = r.native?.content === r.target ? r.native.content : txtValue(r.target);
    if (r.fieldType === 'MX') {
      const m = r.target.match(/^(\d+)\s+(\S+)$/);
      if (!m) throw new Error('Invalid MX target');
      body.priority = Number(m[1]); body.content = m[2];
    }
    if (r.fieldType === 'CAA') {
      const caa = parseCaa(r.target);
      if (!caa) throw new Error('Invalid CAA target');
      body.data = { flags: Number(caa.flags), tag: caa.tag, value: caa.value };
      delete body.content;
    }
    return body;
  }
  validate(operations, zone) {
    for (const op of operations) {
      const r = op.record;
      if (!['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'HTTPS', 'SVCB', 'NAPTR', 'URI', 'TLSA', 'SSHFP', 'CERT', 'DNSKEY', 'DS', 'LOC', 'SMIMEA'].includes(r.fieldType)) throw new Error(`Unmanageable Cloudflare type: ${r.fieldType}`);
      if (r.ttl !== 1 && (r.ttl < 60 || r.ttl > 86400)) throw new Error('Cloudflare TTL must be 1 (automatic) or 60–86400');
      this.payload(r, zone);
    }
  }
  async create(zone, r) { return (await this.call('POST', this.path(zone), this.payload(r, zone))).result; }
  async update(zone, old, r) { return (await this.call('PUT', `${this.path(zone)}/${encodeURIComponent(old.id)}`, this.payload(r, zone))).result; }
  async delete(zone, r) { return (await this.call('DELETE', `${this.path(zone)}/${encodeURIComponent(r.id)}`)).result; }
  async finalize() {} // API completion is not a promise of atomic DNS propagation.
}
