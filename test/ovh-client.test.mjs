// The signed client. The signature is the one thing that cannot be "mostly
// right": a change in the formula fails every call with an opaque 403, so it is
// pinned to a frozen vector.

import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { OvhClient, OvhError, ENDPOINTS } from '../lib/ovh-client.mjs';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

/** Records the outgoing request and replies with whatever is asked for. */
function stubFetch({ status = 200, body = '{}' } = {}) {
  const seen = [];
  globalThis.fetch = async (url, init = {}) => {
    seen.push({ url, ...init });
    return { ok: status >= 200 && status < 300, status, statusText: 'x', text: async () => body };
  };
  return seen;
}

const client = (over = {}) => new OvhClient({
  appKey: 'ak', appSecret: 'as', consumerKey: 'ck', ...over,
});

describe('endpoints', () => {
  test('the three OVH regions resolve', () => {
    assert.equal(client().base, ENDPOINTS['ovh-eu']);
    assert.equal(client({ endpoint: 'ovh-ca' }).base, ENDPOINTS['ovh-ca']);
    assert.equal(client({ endpoint: 'ovh-us' }).base, ENDPOINTS['ovh-us']);
  });

  test('an unknown endpoint fails at construction, listing the valid ones', () => {
    assert.throws(() => client({ endpoint: 'ovh-mars' }), /Unknown endpoint: ovh-mars.*ovh-eu/s);
  });
});

describe('signature', () => {
  // Frozen vector. If this changes, every OVH call starts returning 403.
  test('matches $1$sha1(secret+ck+method+url+body+ts)', () => {
    const c = client();
    const url = 'https://eu.api.ovh.com/1.0/me';
    const expected = '$1$' + createHash('sha1').update('as+ck+GET+' + url + '++1700000000').digest('hex');
    assert.equal(c.sign('GET', url, '', '1700000000'), expected);
    assert.equal(c.sign('GET', url, '', '1700000000'), '$1$212ae9d571c1dbc085f3630b6c2b68d5b3fdc482');
  });

  test('the body is part of the signature', () => {
    const c = client();
    const a = c.sign('POST', 'https://x/1.0/y', '{"a":1}', '1700000000');
    const b = c.sign('POST', 'https://x/1.0/y', '{"a":2}', '1700000000');
    assert.notEqual(a, b);
  });

  test('signed calls carry the three OVH headers', async () => {
    const seen = stubFetch();
    await client().get('/me');
    const { headers } = seen[0];
    assert.equal(headers['X-Ovh-Application'], 'ak');
    assert.equal(headers['X-Ovh-Consumer'], 'ck');
    assert.match(headers['X-Ovh-Signature'], /^\$1\$[0-9a-f]{40}$/);
    assert.match(headers['X-Ovh-Timestamp'], /^\d+$/);
  });

  test('a missing consumer key is reported before any request', async () => {
    globalThis.fetch = () => { throw new Error('should not be called'); };
    await assert.rejects(client({ consumerKey: undefined }).get('/me'), /OVH_CONSUMER_KEY is missing.*auth/s);
  });

  test('syncTime shifts the timestamp by the server delta', async () => {
    const c = client();
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => String(Math.round(Date.now() / 1000) + 120) });
    await c.syncTime();
    assert.ok(Math.abs(c.delta - 120) <= 1, `delta was ${c.delta}`);

    const seen = stubFetch();
    await c.get('/me');
    const sent = Number(seen[0].headers['X-Ovh-Timestamp']);
    assert.ok(Math.abs(sent - (Math.round(Date.now() / 1000) + 120)) <= 1);
  });
});

describe('credential request', () => {
  test('is unsigned — it is what mints the consumer key in the first place', async () => {
    const seen = stubFetch({ body: '{"consumerKey":"new","validationUrl":"https://ovh/validate"}' });
    const res = await new OvhClient({ appKey: 'ak', appSecret: 'as' })
      .requestCredentials([{ method: 'GET', path: '/me' }], 'https://ovh.com/manager/');

    assert.equal(seen[0].headers['X-Ovh-Consumer'], undefined);
    assert.equal(seen[0].headers['X-Ovh-Signature'], undefined);
    assert.equal(seen[0].headers['X-Ovh-Application'], 'ak');
    assert.equal(res.consumerKey, 'new');
  });
});

describe('errors', () => {
  test('OvhError carries status and path — the 404 branches depend on it', async () => {
    stubFetch({ status: 404, body: '{"message":"This service does not exist"}' });
    await assert.rejects(client().get('/domain/zone/nope.com/export'), (err) => {
      assert.ok(err instanceof OvhError);
      assert.equal(err.status, 404);
      assert.equal(err.path, '/domain/zone/nope.com/export');
      assert.match(err.message, /This service does not exist/);
      return true;
    });
  });

  test('a non-JSON error body is still surfaced', async () => {
    stubFetch({ status: 502, body: '<html>gateway</html>' });
    await assert.rejects(client().get('/me'), /OVH 502 on \/me: <html>gateway<\/html>/);
  });

  test('an empty 200 body yields null, not a parse error', async () => {
    stubFetch({ body: '' });
    assert.equal(await client().delete('/domain/zone/example.com/record/1'), null);
  });
});

describe('verbs', () => {
  test('GET sends no body; POST defaults to {}', async () => {
    const seen = stubFetch();
    await client().get('/me');
    assert.equal(seen[0].body, undefined);

    const seen2 = stubFetch();
    await client().post('/domain/zone/example.com/refresh');
    assert.equal(seen2[0].body, '{}');
    assert.equal(seen2[0].method, 'POST');
  });
});
