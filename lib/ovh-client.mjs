import { createHash } from 'node:crypto';

export const ENDPOINTS = {
  'ovh-eu': 'https://eu.api.ovh.com/1.0',
  'ovh-ca': 'https://ca.api.ovh.com/1.0',
  'ovh-us': 'https://api.us.ovhcloud.com/1.0',
};

export class OvhError extends Error {
  constructor(status, message, path) {
    super(`OVH ${status} on ${path}: ${message}`);
    this.status = status;
    this.path = path;
  }
}

/**
 * Minimal client for the OVH v1 API.
 *
 * Auth is OVH's application-key / consumer-key scheme: every call carries an
 * `$1$<sha1>` signature over secret + consumer key + method + url + body +
 * timestamp. SHA-1 is not a choice — it is what the v1 API mandates.
 */
export class OvhClient {
  constructor({ endpoint = 'ovh-eu', appKey, appSecret, consumerKey }) {
    this.base = ENDPOINTS[endpoint];
    if (!this.base) throw new Error(`Unknown endpoint: ${endpoint} (expected one of ${Object.keys(ENDPOINTS).join(', ')})`);
    this.appKey = appKey;
    this.appSecret = appSecret;
    this.consumerKey = consumerKey;
    this.delta = 0;
  }

  /** Align on the server clock: a skewed signature is rejected. */
  async syncTime() {
    const res = await fetch(`${this.base}/auth/time`);
    const serverTime = Number(await res.text());
    this.delta = serverTime - Math.round(Date.now() / 1000);
    return this.delta;
  }

  sign(method, url, payload, ts) {
    const raw = [this.appSecret, this.consumerKey, method, url, payload, ts].join('+');
    return '$1$' + createHash('sha1').update(raw).digest('hex');
  }

  async call(method, path, body = null, { unsigned = false } = {}) {
    const url = `${this.base}${path}`;
    const payload = body === null ? '' : JSON.stringify(body);
    const headers = {
      'Content-Type': 'application/json',
      'X-Ovh-Application': this.appKey,
    };

    if (!unsigned) {
      if (!this.consumerKey) throw new Error('OVH_CONSUMER_KEY is missing — run `node ovh.mjs auth`');
      const ts = String(Math.round(Date.now() / 1000) + this.delta);
      headers['X-Ovh-Consumer'] = this.consumerKey;
      headers['X-Ovh-Timestamp'] = ts;
      headers['X-Ovh-Signature'] = this.sign(method, url, payload, ts);
    }

    const res = await fetch(url, {
      method,
      headers,
      body: payload === '' ? undefined : payload,
    });

    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }

    if (!res.ok) {
      const msg = (data && (data.message || data.class)) || text || res.statusText;
      throw new OvhError(res.status, msg, path);
    }
    return data;
  }

  get(path) { return this.call('GET', path); }
  post(path, body) { return this.call('POST', path, body ?? {}); }
  put(path, body) { return this.call('PUT', path, body); }
  delete(path) { return this.call('DELETE', path); }

  requestCredentials(accessRules, redirection) {
    return this.call('POST', '/auth/credential', { accessRules, redirection }, { unsigned: true });
  }
}
