import { OvhClient } from '../ovh-client.mjs';
import { requireCredentials } from '../config.mjs';
import { domainName, validateRecords } from '../validation.mjs';

export class OvhProvider {
  constructor(client = null) {
    this.name = 'ovh';
    if (!client) requireCredentials();
    this.client = client || new OvhClient({
      endpoint: process.env.OVH_ENDPOINT || 'ovh-eu', appKey: process.env.APP_KEY,
      appSecret: process.env.APP_SECRET, consumerKey: process.env.OVH_CONSUMER_KEY,
    });
  }
  async init() {
    await this.client.syncTime();
    const me = await this.client.get('/me');
    if (!me?.nichandle) throw new Error('OVH account identity missing');
    this.account = `${process.env.OVH_ENDPOINT || 'ovh-eu'}-${me.nichandle}`;
  }
  async zones() {
    const names = await this.client.get('/domain/zone');
    if (!Array.isArray(names)) throw new Error('Incomplete zone list');
    return names.map((name) => ({ name: domainName(name), account: this.account }));
  }
  async zone(name) { return { name: domainName(name), id: domainName(name), account: this.account, provider: this.name }; }
  path(zone) { return `/domain/zone/${encodeURIComponent(zone.id)}`; }
  async read(zone) {
    const base = this.path(zone);
    const ids = await this.client.get(`${base}/record`);
    if (!Array.isArray(ids) || new Set(ids).size !== ids.length) throw new Error('Incomplete or duplicate OVH record list');
    const records = [];
    for (const id of ids) {
      const r = await this.client.get(`${base}/record/${encodeURIComponent(id)}`);
      if (r?.id !== id || typeof r.fieldType !== 'string' || typeof r.target !== 'string'
        || typeof r.subDomain !== 'string' || !Number.isInteger(r.ttl)) throw new Error('Incomplete OVH record');
      records.push({ ...r, native: { ...r } });
    }
    return validateRecords(records);
  }
  async export(zone) { return this.client.get(`${this.path(zone)}/export`); }
  payload(r) { return { fieldType: r.fieldType, subDomain: r.subDomain, target: r.target, ttl: r.ttl }; }
  validate(operations) {
    for (const op of operations) {
      if (op.record.fieldType === 'SOA') throw new Error('SOA is provider-managed');
      if (op.record.fieldType === 'CAA') throw new Error('OVH CAA writes blocked: target encoding has not been verified');
    }
  }
  async create(zone, r) { return this.client.post(`${this.path(zone)}/record`, this.payload(r)); }
  async update(zone, old, r) {
    const body = this.payload(r);
    delete body.fieldType;
    return this.client.put(`${this.path(zone)}/record/${encodeURIComponent(old.id)}`, body);
  }
  async delete(zone, r) { return this.client.delete(`${this.path(zone)}/record/${encodeURIComponent(r.id)}`); }
  async finalize(zone) { return this.client.post(`${this.path(zone)}/refresh`); }
}
