import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { CloudflareProvider } from '../lib/providers/cloudflare.mjs';
import { OvhProvider } from '../lib/providers/ovh.mjs';
import { request } from '../lib/http.mjs';
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const zone = { name: 'example.com', id: 'zone1', account: 'account1' };
const cf = () => new CloudflareProvider({ token: 'fake-test-token' });
const reply = (result, result_info) => new Response(JSON.stringify({ success: true, result, result_info }));

test('Cloudflare consumes every page and refuses a changing total', async () => {
  const pages = [];
  globalThis.fetch = async (url) => {
    const page = Number(new URL(url).searchParams.get('page'));
    pages.push(page);
    return reply([{ id: String(page) }], { page, count: 1, total_pages: 2, total_count: 2 });
  };
  assert.equal((await cf().pages('/zones')).length, 2);
  assert.deepEqual(pages, [1, 2]);
  globalThis.fetch = async (url) => {
    const page = Number(new URL(url).searchParams.get('page'));
    return reply([{ id: String(page) }], { page, count: 1, total_pages: 2, total_count: page + 1 });
  };
  await assert.rejects(cf().pages('/zones'), /changing/);
});

test('Cloudflare rejects ambiguous zone identities and incomplete pagination', async () => {
  globalThis.fetch = async () => reply([{ id: '1', name: 'example.com' }, { id: '2', name: 'example.com' }], { page: 1, count: 2, total_count: 2, total_pages: 1 });
  await assert.rejects(cf().zone('example.com'), /exactly one/);
  globalThis.fetch = async () => reply([]);
  await assert.rejects(cf().pages('/zones'), /Incomplete/);
});

test('Cloudflare faithfully converts TXT, MX, CAA, automatic TTL and metadata', () => {
  const provider = cf();
  for (const item of [
    { type: 'TXT', content: '"v=spf1 -all"' },
    { type: 'MX', content: '.', priority: 0 },
    { type: 'CAA', content: '0 issue ";"', data: { flags: 0, tag: 'issue', value: ';' } },
  ]) {
    const native = { id: 'r1', name: 'example.com', ttl: 1, proxied: false, comment: 'example', tags: ['scope:example'], settings: {}, ...item };
    const normalized = provider.normalize(native, zone);
    const payload = provider.payload(normalized, zone);
    assert.equal(payload.ttl, 1);
    assert.equal(payload.comment, native.comment);
    assert.deepEqual(payload.tags, native.tags);
    assert.deepEqual(payload.settings, native.settings);
    if (item.type === 'MX') assert.equal(payload.priority, 0);
    if (item.type === 'CAA') assert.deepEqual(payload.data, item.data);
  }
  assert.throws(() => provider.normalize({ id: 'r', name: 'other.example', type: 'TXT', content: '', ttl: 1 }, zone), /outside/);
});

test('OVH refuses incomplete reads and all CAA mutations', async () => {
  const provider = new OvhProvider({ async get(path) { return path.endsWith('/record') ? [1] : { id: 1 }; } });
  await assert.rejects(provider.read(zone), /Incomplete/);
  assert.throws(() => provider.validate([{ action: 'create', record: { fieldType: 'CAA' } }]), /CAA writes blocked/);
});

test('transient reads respect Retry-After and writes are never replayed', async () => {
  let calls = 0;
  const waits = [];
  globalThis.fetch = async () => { calls++; return new Response('{}', { status: calls === 1 ? 429 : 200, headers: { 'Retry-After': '2' } }); };
  assert.equal((await request('https://example.invalid', {}, { sleep: async (ms) => waits.push(ms) })).response.status, 200);
  assert.deepEqual(waits, [2000]);
  calls = 0;
  await request('https://example.invalid', { method: 'POST' });
  assert.equal(calls, 1);
});

test('timeouts are bounded and an uncertain write is not retried', async () => {
  let calls = 0;
  globalThis.fetch = async (_url, { signal }) => {
    calls++;
    return new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('test deadline exceeded')), 1000);
      signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
    });
  };
  await assert.rejects(request('https://example.invalid', { method: 'POST' }, { timeout: 5 }), /timeout/i);
  assert.equal(calls, 1);
});

test('restoring a native Cloudflare TXT never strips embedded quotes', () => {
  const provider = cf();
  const r = provider.normalize({ id: 'txt1', name: 'example.com', type: 'TXT', content: 'example="literal text" other=value', ttl: 3600 }, zone);
  assert.equal(provider.payload(r, zone).content, 'example="literal text" other=value');
});
